// From gcp.zig src/core/rpc.zig at eae944c: its request loop and tests, made neutral. Google's error body, RetryInfo and quota project are gcp.zig's hook's.
//! One API call, from URL to body: attach credentials, send it through the
//! transport, map a failure to an error, retry the transient ones with
//! jittered backoff, and keep `Diagnostics` and the log current.
//!
//! Every module of a cloud's library runs this same loop.
//! `Engine(log_scope, Cloud)` binds it to the module's log scope and to the
//! cloud's hook; the struct it returns holds the settings the loop reads,
//! and a client fills one in for each call it makes.
//!
//! `Cloud` is a namespace that says what is the cloud's own:
//!
//! - `pub const RefusalError`: the errors a refused (non-2xx) response
//!   maps to, such as gcp.zig's `NotFound` and `Unavailable`. A named set,
//!   with no name but `OutOfMemory` that the transport or the token
//!   provider returns too, which the loop would take the refusal for.
//! - `pub fn refusal(scratch: Allocator, res: transport.Response,
//!   diagnostics: ?*Diagnostics) (RefusalError || Allocator.Error)`: reads
//!   a refused response into `diagnostics` (`set`, then `setRequestId` when
//!   the cloud names one) and returns its error, or `OutOfMemory` when
//!   reading the body ran out, which ends the call as `bodyDelayMs` running
//!   out does. (Zig has no error union whose payload is an
//!   error set, so the two are one set.) Google's body is JSON, or
//!   XML from Cloud Storage's XML API; ARM's is JSON with `error.code`, and
//!   Blob Storage's XML with the code in `x-ms-error-code`.
//! - `pub fn retryable(err: anyerror, http_status: u16) bool`: whether a
//!   failed attempt is worth another, by default. `http_status` is 0 when
//!   the attempt got no response; `retry.isRetryable` covers the
//!   transport's failures.
//! - `pub fn bodyDelayMs(scratch: Allocator, body: []const u8)
//!   Allocator.Error!?u32`: a retry delay a refused response's body
//!   carries, as Google's `google.rpc.RetryInfo`, or null. The loop waits
//!   the larger of it and what the headers ask (`retry_after`).
//!
//! `Engine` checks these when it binds `Cloud`: a hook that breaks one
//! fails to compile there, with a message that says which.
//!
//! Headers a cloud sends on every call, as gcp.zig's `x-goog-user-project`,
//! go in the engine's `headers`.

const std = @import("std");
const Allocator = std.mem.Allocator;

const Diagnostics = @import("Diagnostics.zig");
const WipingAllocator = @import("WipingAllocator.zig");
const logging = @import("logging.zig");
const retry = @import("retry.zig");
const retry_after = @import("retry_after.zig");
const transport = @import("transport.zig");
const Response = transport.Response;
const RetryPolicy = retry.RetryPolicy;
const TokenProvider = @import("TokenProvider.zig");
const Transport = transport.Transport;
const isRetryable = retry.isRetryable;

/// Decides whether a failed attempt is worth another: the error, and the
/// response's HTTP status or 0 when the attempt got none.
pub const RetryableFn = *const fn (err: anyerror, http_status: u16) bool;

/// One request, as a module describes it.
pub const Call = struct {
    method: transport.Method,
    /// Path and query, starting with `/`. Appended to the base URL.
    path: []const u8,
    body: ?[]const u8 = null,
    /// How `body` is encoded, sent as its Content-Type.
    content_type: transport.ContentType = .json,
    /// Extra request headers, such as the `Content-Encoding` of a compressed
    /// body. The engine's own go after them.
    headers: []const transport.Header = &.{},
    /// Pointed at each attempt's response status and headers, a success's
    /// or a refusal's, for a caller that reads more of an answer than its
    /// body: a long-running write's 202 and the `Location` or
    /// `Azure-AsyncOperation` it names, or a poll told apart by its
    /// status. Null when the latest attempt got no response. The headers
    /// stay in `response` until the caller resets it; always null from
    /// `executeDiscard`, which frees the response as it returns.
    head_out: ?*?transport.StreamRequest.Head = null,
    /// False where the caller opted out of retries, as a publish does.
    retry: bool = true,
    /// Whether a failed attempt is worth another; null: the cloud's
    /// `retryable`. A call can widen it, as a publish does, or narrow it, as
    /// `unsentOnly` does for a write that must not be repeated. A canceled
    /// attempt is never retried, whatever it says.
    retryable: ?RetryableFn = null,
    /// This call carries secrets. What the loop allocates for it, the URL
    /// and the bearer token, is wiped when the call returns, and a failed
    /// attempt's response memory is freed at once rather than kept for the
    /// next attempt, so an arena over a `WipingAllocator` wipes it then.
    /// `HttpTransport` zeroes the `Bearer` header it writes into the
    /// response arena once the request is sent, wipe or not. Out of reach:
    /// std's HTTP client keeps the request head, the header in it, in its
    /// pooled connection's write buffer for the connection's life, and
    /// frees it without wiping.
    wipe: bool = false,
    /// When the call fails with a response, pointed at that response's
    /// body, which stays in `response` until the caller resets it, for a
    /// caller that reads more of an error than `Diagnostics` keeps. Null
    /// when the call succeeds or its last attempt got no response, and
    /// always null from `executeDiscard`, which frees the response as it
    /// returns.
    error_body_out: ?*?[]const u8 = null,
    /// No retry begins later than this many milliseconds after the first
    /// attempt began, for a call whose repeats are safe only for so long,
    /// as a write the server recognises by an idempotency token is. Null:
    /// no limit but the attempts. The fresh-token retry after a 401 is not
    /// held to it: the server refused that request before acting on it.
    retry_window_ms: ?u32 = null,
};

/// One streaming request, as a module describes it: the body from replayable
/// segments, the response buffered or streamed into a writer, response
/// headers included in the result. A body read from a stream cannot be
/// replayed for a retry; `executeStreamBody` sends one once.
pub const StreamCall = struct {
    method: transport.Method,
    /// Path and query, appended to the base URL.
    path: []const u8,
    /// The Content-Type sent with the body, verbatim.
    content_type: ?[]const u8 = null,
    headers: []const transport.Header = &.{},
    body: Body = .none,
    sink: transport.StreamRequest.Sink = .buffer,
    accept_encoding: transport.StreamRequest.AcceptEncoding = .identity,
    /// A writer sink narrows what a retry may repeat: a non-2xx response is
    /// buffered and leaves the writer untouched, so it retries as usual,
    /// but a transport failure may have delivered part of the body, which
    /// cannot be taken back, so it is returned instead. Resuming is the
    /// caller's business.
    retry: bool = true,
    retryable: ?RetryableFn = null,
    /// A writer sink that can take the body again from its first byte:
    /// after a transport failure mid-body, once the engine has decided to
    /// retry it as it would a buffered body, it asks the sink to start over,
    /// and retries when it has. A failure that is not retried leaves the
    /// sink alone, holding what arrived. Null: such a failure is returned.
    restart: ?Restart = null,
    /// Filled with the response head as soon as it arrives, even when the
    /// body then fails; see `transport.StreamRequest.head_out`. With
    /// engine-level retries the head is the latest attempt's, and null when
    /// that attempt got none.
    head_out: ?*?transport.StreamRequest.Head = null,
    /// How long one attempt may take, instead of the engine's
    /// `request_timeout_ms`, for a request that is slow by nature. 0 removes
    /// the limit.
    timeout_ms: ?u32 = null,
    /// As `Call.retry_window_ms`.
    retry_window_ms: ?u32 = null,

    pub const Body = union(enum) {
        none,
        /// Sent back to back with an exact Content-Length; replayable.
        segments: []const []const u8,
    };

    pub const Restart = struct {
        ptr: *anyopaque,
        /// Whether the sink has made itself ready for the body again.
        restart: *const fn (ptr: *anyopaque) bool,
    };
};

/// A request body read from a stream: exactly `len` bytes from `reader`.
pub const StreamBody = struct {
    reader: *std.Io.Reader,
    len: u64,
};

pub fn Engine(comptime log_scope: @EnumLiteral(), comptime Cloud: type) type {
    comptime checkCloud(Cloud);
    return struct {
        gpa: Allocator,
        io: std.Io,
        transport: Transport,
        /// Scheme, host and port, with no trailing slash.
        base_url: []const u8,
        /// The scope asked of the token provider.
        auth_scope: []const u8,
        /// Null where there is nothing to ask.
        token_provider: ?TokenProvider = null,
        /// This endpoint must never receive credentials: an emulator speaks
        /// plain HTTP and needs none.
        unauthenticated: bool = false,
        /// Sent on every call, after the call's own and the credential's
        /// (`TokenProvider.headers`); a header the call or the credential
        /// names already is not sent again.
        headers: []const transport.Header = &.{},
        /// Whether the credential's own headers go with its token. Off, as
        /// gcp.zig's clients offer with `send_quota_project = false`, the
        /// token still goes; an `unauthenticated` engine sends neither.
        send_credential_headers: bool = true,
        retry: RetryPolicy = .{},
        request_timeout_ms: u32 = 0,
        diagnostics: ?*Diagnostics = null,
        /// Set before each attempt to the delay its response asked for,
        /// or null: for a module's own retry loop, which makes its calls
        /// with `retry` off and waits with `RetryPolicy.waitMs`. A module
        /// points it at its client, which one task uses at a time.
        server_delay_out: ?*?u32 = null,
        /// In place of the cloud's `refusal`, for a service whose refusals
        /// name their kind in the body more truly than in the status, as
        /// BigQuery's `errors[].reason` does (it may send a rate limit as
        /// 403). What it returns is the call's error, and decides the retry
        /// as any refusal's error does.
        refusal: ?RefusalFn = null,

        const Self = @This();
        const log = logging.Scoped(log_scope);

        /// Every error the loop itself returns. A module's error set adds
        /// what its own validation and decoding raise.
        pub const Error = Cloud.RefusalError || transport.Error || TokenProvider.Error;

        /// `Error`, plus the caller's sink writer failing, with the detail
        /// wherever that concrete writer keeps it.
        pub const StreamCallError = Error || error{WriteFailed};

        /// `StreamCallError`, plus a streamed body's reader failing
        /// (`ReadFailed`, the detail wherever that reader keeps it) or
        /// ending before its declared length (`EndOfStream`).
        pub const StreamBodyError = StreamCallError || error{ ReadFailed, EndOfStream };

        /// A cloud's `refusal`, or an engine's own in its place.
        pub const RefusalFn = *const fn (scratch: Allocator, res: Response, diagnostics: ?*Diagnostics) (Cloud.RefusalError || Allocator.Error);

        /// Starts a public call: `Diagnostics` describe only the latest one.
        pub fn begin(self: Self) void {
            if (self.diagnostics) |d| d.clear();
        }

        /// Sends `call`, retrying transient failures, and returns the body of
        /// the first 2xx response. The body lives in `response`, which is
        /// reset between attempts and so must hold nothing else.
        pub fn execute(self: Self, response: *std.heap.ArenaAllocator, call: Call) Error![]const u8 {
            var wiping: WipingAllocator = .init(self.gpa);
            var scratch: std.heap.ArenaAllocator = .init(if (call.wipe) wiping.allocator() else self.gpa);
            defer scratch.deinit();
            const url = try self.callUrl(scratch.allocator(), call.path);
            const headers = try self.allHeaders(scratch.allocator(), call.headers);
            var attempts: Attempts = .{
                .method = call.method,
                .log_path = logPath(call.path),
                .max = if (call.retry) self.retry.max_attempts else 1,
                .retryable = call.retryable orelse Cloud.retryable,
                .window_ms = call.retry_window_ms,
                .first_started = std.Io.Clock.awake.now(self.io),
                .wipe = call.wipe,
                .error_body_out = call.error_body_out,
                .head_out = call.head_out,
            };
            attempts.clearOuts();
            while (true) : (attempts.number += 1) {
                const bearer = try self.beginAttempt(scratch.allocator());
                const started = std.Io.Clock.awake.now(self.io);
                const outcome = self.transport.send(.{
                    .method = call.method,
                    .url = url,
                    .bearer = bearer,
                    .body = call.body,
                    .content_type = call.content_type,
                    .headers = headers,
                    .timeout_ms = self.request_timeout_ms,
                }, response.allocator());
                const failed: Failed = if (outcome) |res| f: {
                    const refused = try self.answered(scratch.allocator(), &attempts, res, started) orelse return res.body;
                    if (call.error_body_out) |out| out.* = res.body;
                    break :f refused;
                } else |err| f: {
                    self.unanswered(&attempts, err, started);
                    break :f .{ .err = err };
                };
                try self.again(&attempts, response, failed);
            }
        }

        /// Sends `call` through the transport's streaming entry, retrying
        /// transient failures, and returns the first 2xx response whole:
        /// status, headers, and the body, buffered or already delivered to
        /// the sink writer. Everything returned lives in `response`, which
        /// is reset between attempts and so must hold nothing else.
        pub fn executeStream(
            self: Self,
            response: *std.heap.ArenaAllocator,
            call: StreamCall,
        ) StreamCallError!transport.StreamResponse {
            return self.stream(response, call, null) catch |err| switch (err) {
                // Only a streamed body's reader fails as itself; with none,
                // `streamFailure` has named the transport's.
                error.ReadFailed, error.EndOfStream => error.ConnectionResetByPeer,
                else => |e| e,
            };
        }

        /// `executeStream` with the body read from `body`, which cannot go
        /// back: the request is sent once, whatever `call.retry` says, and a
        /// transient failure comes back for the caller to try again with a
        /// fresh reader. A 401 drops the cached token, so that next attempt
        /// gets a new one. `call.body` must be `.none`.
        pub fn executeStreamBody(
            self: Self,
            response: *std.heap.ArenaAllocator,
            call: StreamCall,
            body: StreamBody,
        ) StreamBodyError!transport.StreamResponse {
            std.debug.assert(call.body == .none);
            return self.stream(response, call, body);
        }

        fn stream(
            self: Self,
            response: *std.heap.ArenaAllocator,
            call: StreamCall,
            streamed: ?StreamBody,
        ) StreamBodyError!transport.StreamResponse {
            var scratch: std.heap.ArenaAllocator = .init(self.gpa);
            defer scratch.deinit();
            const url = try self.callUrl(scratch.allocator(), call.path);
            const headers = try self.allHeaders(scratch.allocator(), call.headers);
            var attempts: Attempts = .{
                .method = call.method,
                .log_path = logPath(call.path),
                // A streamed body is spent by its first attempt.
                .max = if (call.retry and streamed == null) self.retry.max_attempts else 1,
                .retryable = call.retryable orelse Cloud.retryable,
                .window_ms = call.retry_window_ms,
                .first_started = std.Io.Clock.awake.now(self.io),
                .head_out = call.head_out,
                .restart = call.restart,
            };
            attempts.clearOuts();
            const body = requestBody(call.body, streamed);
            while (true) : (attempts.number += 1) {
                const bearer = try self.beginAttempt(scratch.allocator());
                const started = std.Io.Clock.awake.now(self.io);
                const outcome = self.transport.sendStream(.{
                    .method = call.method,
                    .url = url,
                    .bearer = bearer,
                    .content_type = call.content_type,
                    .headers = headers,
                    .body = body,
                    .sink = call.sink,
                    .accept_encoding = call.accept_encoding,
                    .timeout_ms = call.timeout_ms orelse self.request_timeout_ms,
                    .head_out = call.head_out,
                }, response.allocator());
                const failed: Failed = if (outcome) |res| f: {
                    const buffered: Response = .{ .status = res.status, .body = res.body, .headers = res.headers };
                    break :f try self.answered(scratch.allocator(), &attempts, buffered, started) orelse return res;
                } else |err| f: {
                    self.unanswered(&attempts, err, started);
                    break :f try streamFailure(err, call, streamed != null);
                };

                // A 401 response is buffered whatever the sink, so `again`
                // retries it once with a fresh token even there. A streamed
                // body is spent, so it only gets the token dropped, for the
                // caller's next attempt.
                if (failed.http_status == 401 and streamed != null) {
                    _ = self.dropCachedToken();
                    return failed.err;
                }
                try self.again(&attempts, response, failed);
            }
        }

        /// A streaming attempt that got no response: the caller's own
        /// stream failing, returned, or the transport's failure.
        fn streamFailure(err: transport.StreamError, call: StreamCall, streamed: bool) StreamBodyError!Failed {
            return switch (err) {
                // The caller's sink writer failed; nothing to retry.
                error.WriteFailed => error.WriteFailed,
                // The caller's body reader failed or ran short, and a
                // streamed body is never retried. With no body of the
                // caller's to read, they are the transport's own reader
                // failing on the response (not HttpTransport's, which maps
                // them; another Transport's may): a short body, as
                // HttpTransport names one.
                error.ReadFailed, error.EndOfStream => |e| if (streamed) e else .{
                    .err = error.ConnectionResetByPeer,
                    .sink_dirty = call.sink == .writer,
                },
                // A transport failure may have delivered part of the body to
                // a writer sink already, which only a sink that can start
                // over takes back, asked once a retry is decided.
                else => |e| .{ .err = e, .sink_dirty = call.sink == .writer },
            };
        }

        /// `execute` for calls whose response body is not needed.
        pub fn executeDiscard(self: Self, call: Call) Error!void {
            var wiping: WipingAllocator = .init(self.gpa);
            var response: std.heap.ArenaAllocator = .init(if (call.wipe) wiping.allocator() else self.gpa);
            defer response.deinit();
            // The response goes before this returns, and with it a failed
            // body and any head.
            var discarding = call;
            if (discarding.error_body_out) |out| out.* = null;
            if (discarding.head_out) |out| out.* = null;
            discarding.error_body_out = null;
            discarding.head_out = null;
            _ = try self.execute(&response, discarding);
        }

        /// The URL a call goes to: the base URL and the call's path, which
        /// must start with `/`. A path that does not would change the host
        /// the token goes to (`.evil.example`, `:8443`, `@evil.example`
        /// after `https://service.example.com`), so it is
        /// `error.InvalidEndpoint` before anything is sent.
        fn callUrl(self: Self, scratch: Allocator, path: []const u8) Error![]const u8 {
            if (path.len == 0 or path[0] != '/') {
                if (self.diagnostics) |d| d.print("a call's path must start with '/'", .{});
                return error.InvalidEndpoint;
            }
            return std.mem.concat(scratch, u8, &.{ self.base_url, path });
        }

        /// The call's headers, then the credential's, then the engine's,
        /// each only where no earlier one has its name: a call that names
        /// the project it bills sends that one alone, not the credential's
        /// beside it. The credential's go only where its token goes. The
        /// transport then holds all of them to the rules any header meets.
        fn allHeaders(self: Self, scratch: Allocator, call_headers: []const transport.Header) Allocator.Error![]const transport.Header {
            const credential: []const transport.Header = if (self.unauthenticated or !self.send_credential_headers)
                &.{}
            else if (self.token_provider) |p| p.headers() else &.{};
            if (credential.len == 0 and self.headers.len == 0) return call_headers;
            var all: std.ArrayList(transport.Header) = .empty;
            try all.appendSlice(scratch, call_headers);
            try appendNew(scratch, &all, credential);
            try appendNew(scratch, &all, self.headers);
            return all.items;
        }

        /// The delay a refused response asked for, in its headers or, as the
        /// cloud reads it, its body: the larger. Kept in `Diagnostics`
        /// whether or not the call is retried.
        fn serverDelay(self: Self, scratch: Allocator, res: Response) Allocator.Error!?u32 {
            const from_headers = retry_after.serverDelayMs(transport.Header, res.headers, std.Io.Clock.real.now(self.io));
            const ms = retry_after.larger(from_headers, try Cloud.bodyDelayMs(scratch, hookBody(res.body)));
            if (self.diagnostics) |d| d.retry_after_ms = ms;
            if (self.server_delay_out) |out| out.* = ms;
            return ms;
        }

        /// What the loop keeps across one call's attempts, the buffered
        /// entry's and the streamed entry's alike.
        const Attempts = struct {
            method: transport.Method,
            /// The path without its query, for the log.
            log_path: []const u8,
            /// One more after a 401's fresh token.
            max: u32,
            retryable: RetryableFn,
            /// `Call.retry_window_ms`.
            window_ms: ?u32,
            first_started: std.Io.Timestamp,
            /// `Call.wipe`: a failed attempt's response memory goes back at
            /// once, to be wiped, rather than kept for the next.
            wipe: bool = false,
            /// `Call.error_body_out`, cleared with the response it points into.
            error_body_out: ?*?[]const u8 = null,
            /// The call's `head_out`, cleared as `error_body_out` is.
            head_out: ?*?transport.StreamRequest.Head = null,
            /// `StreamCall.restart`, asked only once a retry is decided.
            restart: ?StreamCall.Restart = null,
            /// The attempt under way, from 1.
            number: u32 = 1,
            /// Whether the fresh-token retry after a 401 has been spent.
            reauthenticated: bool = false,

            /// Nulls what points into the response: before the first
            /// attempt, and whenever the response is reset, so an attempt
            /// that gets no response leaves none of an earlier one's.
            fn clearOuts(a: *const Attempts) void {
                if (a.error_body_out) |out| out.* = null;
                if (a.head_out) |out| out.* = null;
            }

            /// Clears a failed attempt's response for the next. A call that
            /// carries secrets gives the memory back, so the wrapping
            /// allocator wipes it now; every other call keeps it for the
            /// next attempt.
            fn reset(a: *const Attempts, response: *std.heap.ArenaAllocator) void {
                a.clearOuts();
                _ = response.reset(if (a.wipe) .free_all else .retain_capacity);
            }
        };

        /// An attempt that failed: its error, its response's status (0 with
        /// none), the delay the response asked for, and whether part of its
        /// body may be in the caller's sink.
        const Failed = struct {
            err: Error,
            http_status: u16 = 0,
            server_delay: ?u32 = null,
            /// Part of a body may have gone to a writer sink: another attempt
            /// follows only if the sink starts over.
            sink_dirty: bool = false,
        };

        /// What follows a failed attempt.
        const Next = union(enum) {
            /// None: the call returns the attempt's error.
            stop,
            /// Another at once, with a fresh token.
            now,
            /// Another after this many milliseconds.
            after_ms: u32,
        };

        /// What every attempt starts with: no delay asked for yet, and the
        /// token to send, or null for none.
        fn beginAttempt(self: Self, scratch: Allocator) Error!?[]const u8 {
            if (self.server_delay_out) |out| out.* = null;
            return self.bearerToken(scratch);
        }

        /// An attempt's response, logged and its head handed out: null for
        /// a 2xx, which clears `Diagnostics`; else the failure as the hook
        /// maps it, with the delay the response asked for.
        fn answered(self: Self, scratch: Allocator, a: *const Attempts, res: Response, started: std.Io.Timestamp) Allocator.Error!?Failed {
            self.logAttempt(a, "{d}", res.status, started);
            // A streaming transport has set it already, to the same; one
            // that buffers has nowhere to.
            if (a.head_out) |out| out.* = .{ .status = res.status, .headers = res.headers };
            if (res.status >= 200 and res.status < 300) {
                if (self.diagnostics) |d| d.clear();
                return null;
            }
            const err = self.failure(scratch, res);
            // The hook could not read the server's answer: the call's end,
            // as when reading the delay its body asks for runs out, and no
            // answer to retry on.
            if (err == error.OutOfMemory) return error.OutOfMemory;
            return .{ .err = err, .http_status = res.status, .server_delay = try self.serverDelay(scratch, res) };
        }

        /// An attempt that got no response: logged, and named in
        /// `Diagnostics`.
        fn unanswered(self: Self, a: *const Attempts, err: anyerror, started: std.Io.Timestamp) void {
            self.logAttempt(a, "{t}", err, started);
            if (self.diagnostics) |d| d.print("{t}", .{err});
        }

        /// One attempt's outcome, `what` a status or an error, with the
        /// time it took. Never a token, a header or the query.
        fn logAttempt(self: Self, a: *const Attempts, comptime what_fmt: []const u8, what: anytype, started: std.Io.Timestamp) void {
            const elapsed_ms = started.durationTo(std.Io.Clock.awake.now(self.io)).toMilliseconds();
            log.debug("{t} {s} -> " ++ what_fmt ++ " in {d} ms (attempt {d} of {d})", .{
                a.method, a.log_path, what, elapsed_ms, a.number, a.max,
            });
        }

        /// After a failed attempt: its error when none follows; else the
        /// response cleared for the next, once the wait before it is over.
        fn again(self: Self, a: *Attempts, response: *std.heap.ArenaAllocator, failed: Failed) Error!void {
            switch (self.next(a, failed)) {
                .stop => return failed.err,
                .now => a.reset(response),
                .after_ms => |ms| {
                    a.reset(response);
                    try self.io.sleep(.fromMilliseconds(ms), .awake);
                },
            }
        }

        /// What follows a failed attempt, logged when it is another.
        fn next(self: Self, a: *Attempts, failed: Failed) Next {
            // A cancel is the caller's, whatever `retryable` says of it. Its
            // request was spent when Canceled came back, so neither a retry's
            // sleep nor its send could be canceled again.
            if (failed.err == error.Canceled) return .stop;
            // A 401 usually means the token died between being fetched and
            // being used. The server refused the request before acting on
            // it, so trying again with a fresh token is safe even for a call
            // that otherwise never retries.
            if (failed.http_status == 401 and !a.reauthenticated and self.dropCachedToken()) {
                a.reauthenticated = true;
                a.max += 1;
                log.warn("{t} {s} was refused as unauthenticated; retrying once with a fresh token", .{ a.method, a.log_path });
                return .now;
            }
            if (a.number >= a.max or !a.retryable(failed.err, failed.http_status)) return .stop;
            const delay_ms = self.waitMs(a, failed) orelse return .stop;
            if (self.pastWindow(a, delay_ms, failed.err)) return .stop;
            // Last, since asking takes back what the sink holds: with no
            // retry to follow, that part of the body is the caller's.
            if (failed.sink_dirty and !restarted(a.restart)) return .stop;
            log.warn("{t} {s} failed with {t}; retrying in {d} ms (attempt {d} of {d})", .{
                a.method, a.log_path, failed.err, delay_ms, a.number + 1, a.max,
            });
            return .{ .after_ms = delay_ms };
        }

        /// The wait before the next attempt, or null, logged, when the
        /// server asked for longer than the policy waits.
        fn waitMs(self: Self, a: *const Attempts, failed: Failed) ?u32 {
            if (self.retry.waitMs(a.number, entropy(self.io), failed.server_delay)) |ms| return ms;
            log.warn("{t} {s} failed with {t}; not retried: the server asked to wait {d} ms, longer than max_backoff_ms ({d} ms)", .{
                a.method, a.log_path, failed.err, failed.server_delay.?, self.retry.max_backoff_ms,
            });
            return null;
        }

        /// Whether a retry `delay_ms` from now would begin past the call's
        /// window, counted from its first attempt; logged when it would.
        fn pastWindow(self: Self, a: *const Attempts, delay_ms: u32, err: anyerror) bool {
            const window = a.window_ms orelse return false;
            const elapsed = a.first_started.durationTo(std.Io.Clock.awake.now(self.io)).toMilliseconds();
            if (elapsed + delay_ms <= window) return false;
            log.warn("{t} {s} failed with {t}; not retried: {d} ms after its first attempt, past its {d} ms window", .{
                a.method, a.log_path, err, elapsed + delay_ms, window,
            });
            return true;
        }

        /// Maps a non-2xx response, with the cloud's hook or the engine's
        /// own, which also records its details.
        fn failure(self: Self, scratch: Allocator, res: Response) Error {
            const refusal = self.refusal orelse Cloud.refusal;
            var bounded = res;
            bounded.body = hookBody(res.body);
            return refusal(scratch, bounded, self.diagnostics);
        }

        /// The token for one attempt, copied into `scratch`, which outlives
        /// the request and is freed when the call returns.
        fn bearerToken(self: Self, scratch: Allocator) Error!?[]const u8 {
            // Never send credentials to an endpoint that speaks plain HTTP.
            if (self.unauthenticated) return null;
            const provider = self.token_provider orelse return null;
            // A provider given these same diagnostics explains its own
            // failures better than this loop can, such as which role an
            // impersonation lacks. Start clean, so that if it fails, what
            // is left is what it said about this attempt.
            if (self.diagnostics) |d| d.clear();
            const token = provider.getToken(self.io, scratch, &.{self.auth_scope}) catch |err| {
                if (self.diagnostics) |d| if (d.message().len == 0) d.print("the token provider failed: {t}", .{err});
                return err;
            };
            if (!TokenProvider.isValidToken(token)) {
                if (self.diagnostics) |d| d.print("the token provider returned an empty token, or one with spaces, newlines or non-ASCII bytes", .{});
                return error.TokenUnavailable;
            }
            return token;
        }

        /// Drops the cached token after a 401, so the next attempt fetches a
        /// new one. False when there is no provider to ask, which makes a
        /// second attempt pointless.
        fn dropCachedToken(self: Self) bool {
            if (self.unauthenticated) return false;
            const provider = self.token_provider orelse return false;
            provider.invalidate();
            return true;
        }
    };
}

/// The most of a refused response's body a cloud's hook reads: error bodies
/// are a few kilobytes, and a hook parses what it is given, often with
/// std.json, whose maps hash every key with a fixed seed, so keys a server
/// chose to collide would make the parse quadratic. Bounded, a server
/// cannot make the client parse megabytes of error. `error_body_out` still
/// holds all of it.
pub const max_hook_body = 64 * 1024;

fn hookBody(body: []const u8) []const u8 {
    return body[0..@min(body.len, max_hook_body)];
}

/// The path of `url` when it is on `base_url`'s origin, for a module that
/// follows a URL a server gave it (a next page, an upload session, an
/// operation to poll) through the loop: the loop sends a path only to its
/// own base URL, so the bearer token cannot go where a server points it.
/// Null when `url` names another scheme, host or port, or adds userinfo.
/// Origins compare as RFC 3986 6.2.3 normalizes them: the scheme and host
/// without regard to case, and the port as a number, the scheme's default
/// when none is written. So `https://h:443/x` is on `https://h`'s origin,
/// as Azure's Retail Prices API writes its next pages. An empty port
/// (`https://h:/x`) is refused, as std.Uri refuses it.
pub fn pathOnOrigin(base_url: []const u8, url: []const u8) ?[]const u8 {
    const base = Origin.split(base_url) orelse return null;
    const other = Origin.split(url) orelse return null;
    if (!base.same(other)) return null;
    // A path the base URL holds after its origin goes before every call's.
    if (!std.mem.startsWith(u8, other.rest, base.rest)) return null;
    const path = other.rest[base.rest.len..];
    if (path.len == 0 or path[0] != '/') return null;
    return path;
}

/// A URL's origin, as `pathOnOrigin` compares it, and what follows it.
const Origin = struct {
    scheme: []const u8,
    host: []const u8,
    /// As written, or the scheme's default; 0 for a scheme with none.
    port: u16,
    /// The path, query and fragment.
    rest: []const u8,

    /// Null for a URL with no `scheme://` or no host, with userinfo (an
    /// `@`, which would let `https://h@evil.example` pass for `h`), or with
    /// a port that is not a number that fits.
    fn split(url: []const u8) ?Origin {
        const sep = std.mem.indexOf(u8, url, "://") orelse return null;
        const scheme = url[0..sep];
        const after = url[sep + 3 ..];
        const end = std.mem.indexOfAny(u8, after, "/?#") orelse after.len;
        const authority = after[0..end];
        if (std.mem.indexOfScalar(u8, authority, '@') != null) return null;
        const host_end = hostEnd(authority) orelse return null;
        if (host_end == 0) return null;
        return .{
            .scheme = scheme,
            .host = authority[0..host_end],
            .port = portAfterHost(scheme, authority[host_end..]) orelse return null,
            .rest = after[end..],
        };
    }

    fn same(a: Origin, b: Origin) bool {
        return a.port == b.port and std.ascii.eqlIgnoreCase(a.scheme, b.scheme) and std.ascii.eqlIgnoreCase(a.host, b.host);
    }
};

/// Where an authority's host ends: after an IPv6 literal's `]`, else at its
/// last `:`. Null for a `[` never closed.
fn hostEnd(authority: []const u8) ?usize {
    if (std.mem.startsWith(u8, authority, "[")) {
        const close = std.mem.indexOfScalar(u8, authority, ']') orelse return null;
        return close + 1;
    }
    return std.mem.lastIndexOfScalar(u8, authority, ':') orelse authority.len;
}

/// The port `text`, what follows the host, names: `:443` is 443, and none
/// the scheme's default. Null for anything else, an empty `:` included.
fn portAfterHost(scheme: []const u8, text: []const u8) ?u16 {
    if (text.len == 0) return defaultPort(scheme);
    if (text.len == 1 or text[0] != ':') return null;
    const digits = text[1..];
    for (digits) |c| if (!std.ascii.isDigit(c)) return null;
    return std.fmt.parseInt(u16, digits, 10) catch null;
}

fn defaultPort(scheme: []const u8) u16 {
    if (std.ascii.eqlIgnoreCase(scheme, "https")) return 443;
    if (std.ascii.eqlIgnoreCase(scheme, "http")) return 80;
    return 0;
}

/// Appends each of `more` whose name no header in `all` has yet.
fn appendNew(scratch: Allocator, all: *std.ArrayList(transport.Header), more: []const transport.Header) Allocator.Error!void {
    for (more) |h| {
        const taken = for (all.items) |kept| {
            if (std.ascii.eqlIgnoreCase(kept.name, h.name)) break true;
        } else false;
        if (!taken) try all.append(scratch, h);
    }
}

/// The path to log: query strings carry page tokens, filters and object
/// names, so they stay out of it.
fn logPath(path: []const u8) []const u8 {
    return path[0 .. std.mem.indexOfScalar(u8, path, '?') orelse path.len];
}

/// What a streaming call sends: the reader's bytes when it has them, else
/// its replayable body.
fn requestBody(body: StreamCall.Body, streamed: ?StreamBody) transport.StreamRequest.Body {
    if (streamed) |s| return .{ .stream = .{ .reader = s.reader, .len = s.len } };
    return switch (body) {
        .none => .none,
        .segments => |segments| .{ .segments = segments },
    };
}

/// Holds `Cloud` to the hook this file's doc describes where `Engine` binds
/// it, rather than at a use site deep in the loop, or not at all.
fn checkCloud(comptime Cloud: type) void {
    const name = @typeName(Cloud);
    for ([_][]const u8{ "RefusalError", "refusal", "retryable", "bodyDelayMs" }) |decl| {
        if (!@hasDecl(Cloud, decl)) @compileError(name ++ " has no pub " ++ decl ++
            ": a Cloud hook declares RefusalError, refusal, retryable and bodyDelayMs, each pub (see loop.zig's doc)");
    }
    const refusals = switch (@typeInfo(Cloud.RefusalError)) {
        .error_set => |set| set.error_names orelse @compileError(name ++
            ".RefusalError is anyerror, which would make every consumer's error set anyerror: name the refusals"),
        else => @compileError(name ++ ".RefusalError is not an error set"),
    };
    // A refusal that shares a name with a failure below HTTP is taken for
    // it: a 408's TimedOut retried as the transport's, a CANCELLED's
    // Canceled as a cancel. OutOfMemory means the same either way.
    const below = @typeInfo(transport.Error || TokenProvider.Error).error_set.error_names.?;
    @setEvalBranchQuota(100 * (refusals.len + 1) * below.len);
    for (refusals) |refusal| {
        if (std.mem.eql(u8, refusal, "OutOfMemory")) continue;
        for (below) |failure| if (std.mem.eql(u8, refusal, failure)) @compileError(name ++ ".RefusalError has " ++ refusal ++
            ", which the transport or the token provider returns too, so the loop would take the refusal for that failure: give it a name of its own, as gcp.zig's ServerCancelled");
    }
}

/// Whether a writer sink has taken back what a failed attempt delivered and
/// is ready for the body again. False with no way to ask.
fn restarted(restart: ?StreamCall.Restart) bool {
    const r = restart orelse return false;
    return r.restart(r.ptr);
}

/// Whether a failed attempt may be tried again when a repeat would act
/// again, as a create makes something new or a run dispatches a job once
/// more: only a failure raised before the request left, a refused
/// connection or a name lookup that failed. A TLS failure or an
/// unreachable network can also come after the request went, on a
/// connection already open. For `Call.retryable`.
pub fn unsentOnly(err: anyerror, http_status: u16) bool {
    _ = http_status;
    return switch (err) {
        error.ConnectionRefused, error.NameServerFailure => true,
        else => false,
    };
}

/// Randomness for a jittered backoff. Public so a module that retries a call
/// of its own waits the same way the loop does.
pub fn entropy(io: std.Io) u64 {
    var bytes: [8]u8 = undefined;
    io.random(&bytes);
    return std.mem.readInt(u64, &bytes, .little);
}

test {
    _ = @import("loop_test.zig");
}
