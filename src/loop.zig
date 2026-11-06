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
//!   maps to, such as gcp.zig's `NotFound` and `Unavailable`.
//! - `pub fn refusal(scratch: Allocator, res: transport.Response,
//!   diagnostics: ?*Diagnostics) (RefusalError || Allocator.Error)`: reads
//!   a refused response into `diagnostics` (`set`, then `setRequestId` when
//!   the cloud names one) and returns its error, or `OutOfMemory` when
//!   reading the body ran out. (Zig has no error union whose payload is an
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
    /// Extra request headers, such as the `Content-Encoding` of a compressed
    /// body. The engine's own go after them.
    headers: []const transport.Header = &.{},
    /// False where the caller opted out of retries, as a publish does.
    retry: bool = true,
    /// Whether a failed attempt is worth another; null: the cloud's
    /// `retryable`. A call can widen it, as a publish does, or narrow it, as
    /// `unsentOnly` does for a write that must not be repeated.
    retryable: ?RetryableFn = null,
    /// This call carries secrets. What the loop allocates for it, the URL
    /// and the bearer token, is wiped when the call returns, and a failed
    /// attempt's response memory is freed at once rather than kept for the
    /// next attempt, so an arena over a `WipingAllocator` wipes it then.
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
    /// after a transport failure mid-body the engine asks it to start over,
    /// and when it has, retries as it would a buffered body. Null: such a
    /// failure is returned.
    restart: ?Restart = null,
    /// Filled with the response head as soon as it arrives, even when the
    /// body then fails; see `transport.StreamRequest.head_out`. With
    /// engine-level retries the head is the latest attempt's.
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
            const log_path = logPath(call.path);
            var max_attempts: u32 = if (call.retry) self.retry.max_attempts else 1;
            const headers = try self.allHeaders(scratch.allocator(), call.headers);
            const retryable = call.retryable orelse Cloud.retryable;

            var reauthenticated = false;
            const first_started = std.Io.Clock.awake.now(self.io);
            var attempt: u32 = 1;
            while (true) : (attempt += 1) {
                // Each attempt starts over: a reset arena no longer holds
                // the previous attempt's body.
                if (call.error_body_out) |out| out.* = null;
                if (self.server_delay_out) |out| out.* = null;
                const bearer = try self.bearerToken(scratch.allocator());
                const started = std.Io.Clock.awake.now(self.io);
                const outcome = self.transport.send(.{
                    .method = call.method,
                    .url = url,
                    .bearer = bearer,
                    .body = call.body,
                    .headers = headers,
                    .timeout_ms = self.request_timeout_ms,
                }, response.allocator());
                const elapsed_ms = started.durationTo(std.Io.Clock.awake.now(self.io)).toMilliseconds();

                var http_status: u16 = 0;
                var server_delay: ?u32 = null;
                const err: Error = if (outcome) |res| e: {
                    http_status = res.status;
                    log.debug("{t} {s} -> {d} in {d} ms (attempt {d} of {d})", .{
                        call.method, log_path, res.status, elapsed_ms, attempt, max_attempts,
                    });
                    if (res.status >= 200 and res.status < 300) {
                        if (self.diagnostics) |d| d.clear();
                        return res.body;
                    }
                    if (call.error_body_out) |out| out.* = res.body;
                    const failed = self.failure(scratch.allocator(), res);
                    server_delay = try self.serverDelay(scratch.allocator(), res);
                    break :e failed;
                } else |err| e: {
                    log.debug("{t} {s} -> {t} in {d} ms (attempt {d} of {d})", .{
                        call.method, log_path, err, elapsed_ms, attempt, max_attempts,
                    });
                    if (self.diagnostics) |d| d.print("{t}", .{err});
                    break :e err;
                };

                // A 401 usually means the token died between being fetched
                // and being used. The server refused the request before
                // acting on it, so trying again with a fresh token is safe
                // even for a call that otherwise never retries.
                if (http_status == 401 and !reauthenticated and self.dropCachedToken()) {
                    reauthenticated = true;
                    max_attempts += 1;
                    log.warn("{t} {s} was refused as unauthenticated; retrying once with a fresh token", .{ call.method, log_path });
                    resetResponse(response, call.wipe, call.error_body_out);
                    continue;
                }

                if (attempt >= max_attempts or !retryable(err, http_status)) return err;
                const delay_ms = self.waitMs(attempt, server_delay, call.method, log_path, err) orelse return err;
                if (self.pastWindow(call.retry_window_ms, first_started, delay_ms, call.method, log_path, err)) return err;
                log.warn("{t} {s} failed with {t}; retrying in {d} ms (attempt {d} of {d})", .{
                    call.method, log_path, err, delay_ms, attempt + 1, max_attempts,
                });
                resetResponse(response, call.wipe, call.error_body_out);
                try self.io.sleep(.fromMilliseconds(delay_ms), .awake);
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
                // Only a streamed body reads.
                error.ReadFailed, error.EndOfStream => unreachable,
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
            const log_path = logPath(call.path);
            // A streamed body is spent by its first attempt.
            var max_attempts: u32 = if (call.retry and streamed == null) self.retry.max_attempts else 1;
            const headers = try self.allHeaders(scratch.allocator(), call.headers);
            const retryable = call.retryable orelse Cloud.retryable;

            var reauthenticated = false;
            const first_started = std.Io.Clock.awake.now(self.io);
            var attempt: u32 = 1;
            while (true) : (attempt += 1) {
                if (self.server_delay_out) |out| out.* = null;
                const bearer = try self.bearerToken(scratch.allocator());
                const started = std.Io.Clock.awake.now(self.io);
                const outcome = self.transport.sendStream(.{
                    .method = call.method,
                    .url = url,
                    .bearer = bearer,
                    .content_type = call.content_type,
                    .headers = headers,
                    .body = if (streamed) |s| .{ .stream = .{ .reader = s.reader, .len = s.len } } else switch (call.body) {
                        .none => .none,
                        .segments => |segments| .{ .segments = segments },
                    },
                    .sink = call.sink,
                    .accept_encoding = call.accept_encoding,
                    .timeout_ms = call.timeout_ms orelse self.request_timeout_ms,
                    .head_out = call.head_out,
                }, response.allocator());
                const elapsed_ms = started.durationTo(std.Io.Clock.awake.now(self.io)).toMilliseconds();

                var http_status: u16 = 0;
                var server_delay: ?u32 = null;
                var mid_body = false;
                const err: StreamBodyError = if (outcome) |res| e: {
                    http_status = res.status;
                    log.debug("{t} {s} -> {d} in {d} ms (attempt {d} of {d})", .{
                        call.method, log_path, res.status, elapsed_ms, attempt, max_attempts,
                    });
                    if (res.status >= 200 and res.status < 300) {
                        if (self.diagnostics) |d| d.clear();
                        return res;
                    }
                    const buffered: Response = .{ .status = res.status, .body = res.body, .headers = res.headers };
                    const failed = self.failure(scratch.allocator(), buffered);
                    server_delay = try self.serverDelay(scratch.allocator(), buffered);
                    break :e failed;
                } else |err| e: {
                    log.debug("{t} {s} -> {t} in {d} ms (attempt {d} of {d})", .{
                        call.method, log_path, err, elapsed_ms, attempt, max_attempts,
                    });
                    if (self.diagnostics) |d| d.print("{t}", .{err});
                    break :e switch (err) {
                        // The caller's sink writer failed; nothing to retry.
                        error.WriteFailed => return error.WriteFailed,
                        // The caller's body reader failed or ran short. Only
                        // a streamed body reads, and it is never retried.
                        error.ReadFailed, error.EndOfStream => |e| if (streamed != null) return e else unreachable,
                        else => |e| b: {
                            // A transport failure may have delivered part of
                            // the body to a writer sink already, which only a
                            // sink that can start over takes back.
                            if (call.sink == .writer) {
                                mid_body = if (call.restart) |r| !r.restart(r.ptr) else true;
                            }
                            break :b e;
                        },
                    };
                };

                // A 401 response is buffered whatever the sink, so retrying
                // it once with a fresh token is safe even there. A streamed
                // body is spent, so it only gets the token dropped, for the
                // caller's next attempt.
                if (http_status == 401 and streamed != null) {
                    _ = self.dropCachedToken();
                    return err;
                }
                if (http_status == 401 and !reauthenticated and self.dropCachedToken()) {
                    reauthenticated = true;
                    max_attempts += 1;
                    log.warn("{t} {s} was refused as unauthenticated; retrying once with a fresh token", .{ call.method, log_path });
                    _ = response.reset(.retain_capacity);
                    continue;
                }

                if (mid_body or attempt >= max_attempts or !retryable(err, http_status)) return err;
                const delay_ms = self.waitMs(attempt, server_delay, call.method, log_path, err) orelse return err;
                if (self.pastWindow(call.retry_window_ms, first_started, delay_ms, call.method, log_path, err)) return err;
                log.warn("{t} {s} failed with {t}; retrying in {d} ms (attempt {d} of {d})", .{
                    call.method, log_path, err, delay_ms, attempt + 1, max_attempts,
                });
                _ = response.reset(.retain_capacity);
                try self.io.sleep(.fromMilliseconds(delay_ms), .awake);
            }
        }

        /// `execute` for calls whose response body is not needed.
        pub fn executeDiscard(self: Self, call: Call) Error!void {
            var wiping: WipingAllocator = .init(self.gpa);
            var response: std.heap.ArenaAllocator = .init(if (call.wipe) wiping.allocator() else self.gpa);
            defer response.deinit();
            // The response goes before this returns, and a failed body with it.
            var discarding = call;
            if (discarding.error_body_out) |out| out.* = null;
            discarding.error_body_out = null;
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

        /// The wait before the next attempt, or null, logged, when the
        /// server asked for longer than the policy waits.
        fn waitMs(self: Self, attempt: u32, server_delay: ?u32, method: transport.Method, log_path: []const u8, err: anyerror) ?u32 {
            if (self.retry.waitMs(attempt, entropy(self.io), server_delay)) |ms| return ms;
            log.warn("{t} {s} failed with {t}; not retried: the server asked to wait {d} ms, longer than max_backoff_ms ({d} ms)", .{
                method, log_path, err, server_delay.?, self.retry.max_backoff_ms,
            });
            return null;
        }

        /// Whether a retry `delay_ms` from now would begin past the call's
        /// window, counted from its first attempt; logged when it would.
        fn pastWindow(
            self: Self,
            window_ms: ?u32,
            first_started: std.Io.Timestamp,
            delay_ms: u32,
            method: transport.Method,
            log_path: []const u8,
            err: anyerror,
        ) bool {
            const window = window_ms orelse return false;
            const elapsed = first_started.durationTo(std.Io.Clock.awake.now(self.io)).toMilliseconds();
            if (elapsed + delay_ms <= window) return false;
            log.warn("{t} {s} failed with {t}; not retried: {d} ms after its first attempt, past its {d} ms window", .{
                method, log_path, err, elapsed + delay_ms, window,
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
pub fn pathOnOrigin(base_url: []const u8, url: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, url, base_url)) return null;
    const path = url[base_url.len..];
    if (path.len == 0 or path[0] != '/') return null;
    return path;
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

/// Clears the failed attempt's body. A call that carries secrets gives the
/// memory back, so the wrapping allocator wipes it now; every other call
/// keeps it for the next attempt.
fn resetResponse(response: *std.heap.ArenaAllocator, wipe: bool, error_body_out: ?*?[]const u8) void {
    // The body it pointed at goes with the reset.
    if (error_body_out) |out| out.* = null;
    _ = response.reset(if (wipe) .free_all else .retain_capacity);
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
