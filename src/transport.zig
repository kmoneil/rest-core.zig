// Ported from gcp.zig src/core/transport.zig at eae944c. gcp.zig has built on this copy since its 5aa9ba8.
//! The HTTP seam. Every request goes through a `Transport`, so the standard
//! library's HTTP churn stays in this file and tests can substitute a fake.
//! `HttpTransport` is the implementation over std's HTTP client, carried
//! as `HttpClient` with a patched TLS client beneath it (deps/zig-tls).

const std = @import("std");
const builtin = @import("builtin");
const flate = std.compress.flate;
const Crc32 = @import("Crc32.zig");
const Allocator = std.mem.Allocator;
const http = std.http;
/// std.http.Client, its TLS client the copy in deps/zig-tls: each signer
/// in a server's chain checked to be a CA, each certificate held to the
/// limits it states and checked before std parses it, and an RSA
/// signature held to its key's length (t78; CONN-10 to CONN-13).
/// Everything else in it is std's, from the Zig that builds rest-core.
const HttpClient = @import("http_client");

/// HEAD is answered with a head alone: whatever Content-Length or
/// Transfer-Encoding the answer carries describes the body a GET would
/// get, and none is read (RFC 9110 9.3.2). Its status and headers are the
/// answer, a refusal's included, as Blob Storage's `x-ms-error-code` is.
pub const Method = enum { GET, PUT, POST, DELETE, PATCH, HEAD };

/// One request for `Transport.send`, its response buffered. A value.
pub const Request = struct {
    method: Method,
    /// Absolute URL.
    url: []const u8,
    /// Token for `Authorization: Bearer <token>`; null sends no Authorization header.
    bearer: ?[]const u8 = null,
    /// Sent with the `Content-Type` that `content_type` names. GET, HEAD
    /// and DELETE never carry a body.
    body: ?[]const u8 = null,
    content_type: ContentType = .json,
    /// Sent after the headers above, in order. A name or value that could
    /// end the header line is `error.InvalidRequestHeader`, never a second
    /// request smuggled into this one.
    headers: []const Header = &.{},
    /// How long this request may take before it is `error.TimedOut`, or 0
    /// for no limit. std.http has no timeout of its own, so without one a
    /// server that accepts the connection and then says nothing stalls the
    /// caller until its `std.Io` task is canceled. The limit needs a second
    /// task to run the timer; where the `Io` cannot start one, the request
    /// is `error.ConcurrencyUnavailable`, never sent untimed.
    timeout_ms: u32 = 0,

    /// The Content-Type it goes with: `content_type`'s for a method that
    /// carries a body, none for GET, HEAD and DELETE.
    pub fn sentContentType(req: Request) ?[]const u8 {
        return switch (req.method) {
            .GET, .HEAD, .DELETE => null,
            .PUT, .POST, .PATCH => req.content_type.mediaType(),
        };
    }
};

/// Refuses, as `HttpTransport` does before it connects, a request it would
/// not send: a URL that would go out other than as written
/// (`error.InvalidEndpoint`), and a header HTTP cannot carry or the
/// transport writes itself (`error.InvalidRequestHeader`). `content_type`
/// is the one the request carries, or null: a `Request`'s is
/// `sentContentType`. For a `Transport` of one's own, and a fake, so that
/// what production refuses never passes in a test.
pub fn checkRequest(url: []const u8, bearer: ?[]const u8, content_type: ?[]const u8, headers: []const Header) Error!void {
    _ = try HttpTransport.target(url);
    try HttpTransport.checkHeaders(bearer, content_type, headers);
}

/// One header, as `std.http` writes it.
pub const Header = http.Header;

/// The value of the first header named `name`, matched as HTTP matches
/// names (without regard to case), or null. Where a name comes twice, the
/// first wins. (std.http keeps the last of Content-Type, Location and
/// Connection for the headers it reads itself, and refuses two Content-
/// Lengths or Content-Encodings that differ.)
pub fn findHeader(headers: []const Header, name: []const u8) ?[]const u8 {
    for (headers) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    return null;
}

test "findHeader: the first of a name, in any case, or null" {
    const headers: []const Header = &.{
        .{ .name = "Content-Type", .value = "application/json" },
        .{ .name = "x-ms-request-id", .value = "r-1" },
        .{ .name = "content-type", .value = "text/plain" },
    };
    try std.testing.expectEqualStrings("application/json", findHeader(headers, "CONTENT-TYPE").?);
    try std.testing.expectEqualStrings("r-1", findHeader(headers, "X-MS-Request-Id").?);
    try std.testing.expectEqual(null, findHeader(headers, "location"));
}

/// RFC 9110 field names: at least one character, all of them token
/// characters, so the name cannot carry a separator or end the line.
pub fn isValidHeaderName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |c| {
        if (std.ascii.isAlphanumeric(c)) continue;
        if (std.mem.findScalar(u8, "!#$%&'*+-.^_`|~", c) == null) return false;
    }
    return true;
}

/// RFC 9110 field values: visible ASCII, space and tab, with no space or
/// tab at either end, where the receiver would strip it anyway. An empty
/// value is legal.
pub fn isValidHeaderValue(value: []const u8) bool {
    for (value) |c| if (c != '\t' and (c < ' ' or c >= 0x7f)) return false;
    if (value.len == 0) return true;
    return !isSpaceOrTab(value[0]) and !isSpaceOrTab(value[value.len - 1]);
}

fn isSpaceOrTab(c: u8) bool {
    return c == ' ' or c == '\t';
}

/// How a request body is encoded.
pub const ContentType = enum {
    json,
    /// `application/x-www-form-urlencoded`, as OAuth token endpoints take.
    form,

    /// The Content-Type value sent for it.
    pub fn mediaType(ct: ContentType) []const u8 {
        return switch (ct) {
            .json => "application/json",
            .form => "application/x-www-form-urlencoded",
        };
    }
};

/// What `Transport.send` returns. Its body and headers live in the arena
/// given to `send`, and go with it.
pub const Response = struct {
    /// HTTP status code. Non-2xx statuses are responses, not transport errors.
    status: u16,
    /// The complete body, allocated in the arena passed to `send`.
    body: []const u8,
    /// Every header the response carried, in order, allocated in the same
    /// arena. A server that sends the same name twice appears twice.
    headers: []const Header = &.{},

    /// The value sent for `name`, as `findHeader` finds it.
    pub fn header(self: Response, name: []const u8) ?[]const u8 {
        return findHeader(self.headers, name);
    }
};

/// A request whose bodies can stream. `Request` covers small bodies held in
/// memory; this covers uploads read from a caller's reader, multipart bodies
/// sent as segments without copying, and downloads written straight into a
/// caller's writer. Cloud Storage objects reach 5 TiB, so neither body may
/// ever be held whole.
pub const StreamRequest = struct {
    method: Method,
    /// Absolute URL.
    url: []const u8,
    /// Token for `Authorization: Bearer <token>`; null sends no Authorization header.
    bearer: ?[]const u8 = null,
    /// The `Content-Type` value sent verbatim when there is a body, such as
    /// `multipart/related; boundary=...`. Null sends no Content-Type.
    content_type: ?[]const u8 = null,
    /// Sent after the transport's own headers, in order, validated as
    /// `Request.headers` is.
    headers: []const Header = &.{},
    body: Body = .none,
    /// Where a successful response body goes.
    sink: Sink = .buffer,
    /// What `Accept-Encoding` offers the server, and whether a compressed
    /// response body is decompressed on its way to the sink.
    accept_encoding: AcceptEncoding = .identity,
    /// As `Request.timeout_ms`. While the clock runs the request runs on
    /// another task, so the body reader and sink writer must not be touched
    /// until the call returns.
    timeout_ms: u32 = 0,
    /// Filled with the response's status and headers as soon as the head
    /// arrives, before any body byte moves, and left null when no head
    /// arrived at all. A download that fails mid-body reads here what it
    /// was reading, such as the object generation a resume must pin. The
    /// headers live in the arena passed to the send.
    head_out: ?*?Head = null,

    /// A response's status and headers, as `head_out` hands them out.
    pub const Head = struct {
        status: u16,
        headers: []const Header,

        /// The value sent for `name`, as `findHeader` finds it.
        pub fn header(self: Head, name: []const u8) ?[]const u8 {
            return findHeader(self.headers, name);
        }
    };

    /// The request body: none, segments, or a reader of a known length.
    pub const Body = union(enum) {
        /// No body and no Content-Length, as GET, HEAD and DELETE send.
        /// POST, PUT and PATCH send an empty one, `Content-Length: 0`, since
        /// Google's front ends refuse a POST that gives no length (411).
        none,
        /// Sent back to back with an exact Content-Length, without being
        /// copied into one buffer. A multipart body is framing, caller data,
        /// closing framing. Empty segments send `Content-Length: 0`, which a
        /// resumable-upload status query needs where `.none` would send no
        /// length at all.
        segments: []const []const u8,
        /// Exactly `len` bytes read from `reader`, sent as the
        /// Content-Length. A reader that ends before `len` bytes is
        /// `error.EndOfStream`, and the connection is closed.
        stream: struct { reader: *std.Io.Reader, len: u64 },
    };

    /// Where a success's body goes.
    pub const Sink = union(enum) {
        /// Buffer the body into the arena, bounded by the transport's
        /// response limit.
        buffer,
        /// Stream a 2xx body into this writer, unbounded. Error bodies are
        /// still buffered. The transport never flushes it: the writer and
        /// its buffer belong to the caller.
        writer: *std.Io.Writer,
    };

    /// What Accept-Encoding offers, and whether a compressed body is
    /// decoded.
    pub const AcceptEncoding = enum {
        /// Ask for plain bytes, as a download whose bytes must match a
        /// checksum wants.
        identity,
        /// Offer gzip and deflate, as `send` does for JSON responses, and
        /// decompress what comes back.
        compressed,
        /// Offer gzip, and deliver the body as it arrived: a gzip body stays
        /// gzip, for a caller that must hash the bytes the server stored.
        /// The head's `Content-Encoding` says which arrived.
        gzip_as_sent,
    };
};

/// What `Transport.sendStream` returns. Its body, when buffered, and its
/// headers live in the arena given to `sendStream`, and go with it.
pub const StreamResponse = struct {
    /// HTTP status code. Non-2xx statuses are responses, not transport
    /// errors; 308 is how a resumable upload answers a chunk, so it must
    /// come back untouched, never followed as a redirect.
    status: u16,
    /// Every header the response carried, in order, allocated in the arena.
    headers: []const Header = &.{},
    /// The buffered body: always set for non-2xx, and for 2xx when the sink
    /// is `.buffer`. Empty when the body went to the sink writer.
    body: []const u8 = "",
    /// Bytes handed to the sink writer, buffered there or not.
    bytes_streamed: u64 = 0,

    /// The value sent for `name`, as `findHeader` finds it.
    pub fn header(self: StreamResponse, name: []const u8) ?[]const u8 {
        return findHeader(self.headers, name);
    }
};

/// `Error`, plus the caller's own streams failing. `ReadFailed` is the body
/// reader and `WriteFailed` the sink writer; each records its detail
/// wherever that concrete reader or writer keeps it. `EndOfStream` is a body
/// reader that ended before the declared length.
pub const StreamError = Error || error{ ReadFailed, WriteFailed, EndOfStream };

/// Failures below HTTP: no response arrived, or none that can be used.
pub const Error = error{
    /// Nothing is listening at the endpoint.
    ConnectionRefused,
    /// The connection dropped before a complete response arrived.
    ConnectionResetByPeer,
    ConnectionTimedOut,
    /// No route to the network or host.
    NetworkUnreachable,
    /// DNS has no such host.
    UnknownHostName,
    /// The DNS lookup itself failed, possibly temporarily.
    NameServerFailure,
    /// The TLS handshake or certificate validation failed.
    TlsFailure,
    /// The response broke HTTP framing rules.
    HttpProtocolError,
    /// The response body exceeded the read limit.
    ResponseTooLarge,
    /// The URL has an unsupported scheme or no host, or is one the
    /// transport will not send: see `HttpTransport`'s `checkUrl`.
    InvalidEndpoint,
    /// A header on the request has a name or value that HTTP cannot carry.
    InvalidRequestHeader,
    /// The request did not finish within `Request.timeout_ms`.
    TimedOut,
    /// The request asked for a time limit, and the `Io` could not start the
    /// task that runs it: a single-threaded `Io`, or its `concurrent_limit`
    /// spent. It was not sent untimed.
    ConcurrencyUnavailable,
    /// Any other operating-system network failure.
    NetworkFailure,
    /// The surrounding `std.Io` task was canceled.
    Canceled,
    OutOfMemory,
};

/// A way to send one HTTP request, in the `std.mem.Allocator` interface shape.
/// Thread-safety is the implementation's: `HttpTransport` is not
/// thread-safe, nor are `testing`'s fakes.
pub const Transport = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    /// What a transport implements.
    pub const VTable = struct {
        /// Sends `req` and reads the whole response. The response body is
        /// allocated in `arena`.
        send: *const fn (ptr: *anyopaque, req: Request, arena: Allocator) Error!Response,
        /// Sends a request with streaming bodies, or null for a transport
        /// that cannot stream. Fakes that only ever see `send` leave it out.
        sendStream: ?*const fn (ptr: *anyopaque, req: StreamRequest, arena: Allocator) StreamError!StreamResponse = null,
    };

    /// Sends `req` and reads its whole response into `arena`.
    pub fn send(self: Transport, req: Request, arena: Allocator) Error!Response {
        return self.vtable.send(self.ptr, req, arena);
    }

    /// Sends a streaming request. Calling this through a transport whose
    /// vtable has no `sendStream` (a fake that only ever sees `send`) is a
    /// programmer bug, and panics in every build mode.
    pub fn sendStream(self: Transport, req: StreamRequest, arena: Allocator) StreamError!StreamResponse {
        const stream = self.vtable.sendStream orelse @panic("this Transport cannot stream: its vtable has no sendStream");
        return stream(self.ptr, req, arena);
    }
};

/// The largest response body read. A 10 MB pull response grows by a third as
/// base64, plus JSON framing, so this leaves headroom above 10 MB.
pub const default_max_response_bytes = 32 * 1024 * 1024;

/// How long std.http's TLS clock reading is trusted before it is reloaded.
pub const tls_clock_max_age: std.Io.Duration = .fromSeconds(60 * 60);

/// A `Transport` over std's HTTP client (`HttpClient`, its TLS patched):
/// HTTP/1.1, keep-alive, one connection pool. Not thread-safe: one task
/// sends through it at a time. What a send returns lives in the arena it
/// was given.
pub const HttpTransport = struct {
    client: HttpClient,
    /// Borrowed; must outlive the transport.
    user_agent: []const u8,
    max_response_bytes: usize = default_max_response_bytes,

    /// A transport whose connections and TLS state live in `gpa`.
    pub fn init(gpa: Allocator, io: std.Io, user_agent: []const u8) HttpTransport {
        return .{ .client = .{ .allocator = gpa, .io = io }, .user_agent = user_agent };
    }

    /// Closes its connections and frees its pool.
    pub fn deinit(self: *HttpTransport) void {
        self.client.deinit();
        self.* = undefined;
    }

    /// The transport; it points at this struct, which must not move while
    /// in use.
    pub fn transport(self: *HttpTransport) Transport {
        return .{ .ptr = self, .vtable = &.{ .send = send, .sendStream = sendStream } };
    }

    /// `send` is the streaming path with the body as one segment and the
    /// response buffered, so both entries share one implementation.
    fn send(ptr: *anyopaque, req: Request, arena: Allocator) Error!Response {
        const self: *HttpTransport = @ptrCast(@alignCast(ptr));
        const content_type = req.sentContentType();
        const segments = [_][]const u8{req.body orelse ""};
        const res = self.sendStreamNow(.{
            .method = req.method,
            .url = req.url,
            .bearer = req.bearer,
            .content_type = content_type,
            .headers = req.headers,
            .body = if (content_type != null) .{ .segments = &segments } else .none,
            .sink = .buffer,
            .accept_encoding = .compressed,
            .timeout_ms = req.timeout_ms,
        }, arena) catch |err| switch (err) {
            // No caller streams here: a slice body cannot fail or end early,
            // and buffering into the arena cannot fail the sink.
            error.ReadFailed, error.WriteFailed, error.EndOfStream => unreachable,
            else => |e| return e,
        };
        return .{ .status = res.status, .body = res.body, .headers = res.headers };
    }

    fn sendStream(ptr: *anyopaque, req: StreamRequest, arena: Allocator) StreamError!StreamResponse {
        const self: *HttpTransport = @ptrCast(@alignCast(ptr));
        return self.sendStreamNow(req, arena);
    }

    fn sendStreamNow(self: *HttpTransport, req: StreamRequest, arena: Allocator) StreamError!StreamResponse {
        if (req.timeout_ms == 0) return self.sendNow(req, arena);

        // The request runs elsewhere, so a server that accepts the
        // connection and then says nothing costs `timeout_ms` rather than
        // the rest of the program's life. Canceling it interrupts the
        // blocked read, and the connection it was using is not reused.
        const Winner = union(enum) { sent: StreamError!StreamResponse, expired: void };
        var slots: [2]Winner = undefined;
        var race: std.Io.Select(Winner) = .init(self.client.io, &slots);
        // Without a second task there is no timeout to be had. gcp.zig sent
        // the request untimed then, and said nothing; a caller who asked for
        // a limit gets an error instead, and one who wants none passes 0.
        // The timer starts first, so when the request's task is the one
        // that cannot start, nothing has been sent: only a sleep is
        // canceled on the way out.
        race.concurrent(.expired, expire, .{ self.client.io, req.timeout_ms }) catch return error.ConcurrencyUnavailable;
        defer race.cancelDiscard();
        race.concurrent(.sent, sendNow, .{ self, req, arena }) catch return error.ConcurrencyUnavailable;
        return switch (race.await() catch |err| return err) {
            .sent => |result| result,
            .expired => error.TimedOut,
        };
    }

    fn expire(io: std.Io, ms: u32) void {
        io.sleep(.fromMilliseconds(ms), .awake) catch {};
    }

    fn sendNow(self: *HttpTransport, req: StreamRequest, arena: Allocator) StreamError!StreamResponse {
        const uri, const protocol = try target(req.url);
        try checkHeaders(req.bearer, req.content_type, req.headers);
        if (protocol == .tls) self.expireTlsClock(.when_stale);
        return self.exchange(uri, protocol, req, arena) catch |err| {
            // A handshake can fail on a stale clock or CA bundle; the next
            // attempt reloads both.
            if (err == error.TlsFailure) self.expireTlsClock(.now);
            return err;
        };
    }

    /// std.http reads the clock once, at the first HTTPS request, and checks
    /// every later certificate against that reading. Forgetting the reading
    /// makes the next HTTPS request reload the clock and the CA bundle, so a
    /// long-lived client accepts rotated certificates and rejects expired ones.
    fn expireTlsClock(self: *HttpTransport, when: enum { now, when_stale }) void {
        if (HttpClient.disable_tls) return;
        const io = self.client.io;
        self.client.ca_bundle_lock.lockUncancelable(io);
        defer self.client.ca_bundle_lock.unlock(io);
        const then = self.client.now orelse return;
        const age = then.durationTo(std.Io.Clock.real.now(io)).nanoseconds;
        if (when == .now or age < 0 or age > tls_clock_max_age.nanoseconds) self.client.now = null;
    }

    fn exchange(
        self: *HttpTransport,
        uri: std.Uri,
        protocol: HttpClient.Protocol,
        req: StreamRequest,
        arena: Allocator,
    ) StreamError!StreamResponse {
        const authorization: ?[]u8 = if (req.bearer) |token|
            try arena.print("Bearer {s}", .{token})
        else
            null;
        // The header is in the caller's arena, which may outlive the call by
        // far (the loop hands its response arena here): gone once the head
        // is written, which it is by the time this returns. std's copy in
        // the connection's write buffer is out of reach.
        defer if (authorization) |v| std.crypto.secureZero(u8, v);
        var request = self.client.request(httpMethod(req.method), uri, .{
            .connection = try self.preconnect(uri, protocol),
            .redirect_behavior = .unhandled,
            .headers = .{
                .user_agent = .{ .override = self.user_agent },
                .content_type = if (req.content_type) |ct| .{ .override = ct } else .omit,
                .authorization = if (authorization) |v| .{ .override = v } else .omit,
                .accept_encoding = acceptEncoding(req.accept_encoding),
            },
            .extra_headers = req.headers,
        }) catch |err| return mapConnectError(err);
        defer request.deinit();
        const connection = request.connection.?;
        // Any failure from here on closes the connection, the one place it
        // is done: a write that failed leaves it in an unknown state, and a
        // refused head, a body refused or cut short, or an arena that ran
        // out leaves the rest of the response unread. Kept, std would reuse
        // it, or have `request.deinit` drain it with std's chunked decoder
        // (see `Dechunker`), unbounded.
        errdefer connection.closing = true;

        sendBody(&request, req.body) catch |err| return switch (err) {
            // The caller's reader failed, or ended before the declared
            // length; the response, if any, is not read.
            error.ReadFailed, error.EndOfStream => |e| e,
            error.WriteFailed => mapError(err, connection),
        };

        const response = request.receiveHead(&.{}) catch |err| return mapError(err, connection);
        return self.readResponse(&request, response.head, req, arena);
    }

    /// std.http hands an IPv6 literal to the resolver with its brackets
    /// ("[::1]"), which finds nothing. An emulator binds [::1] by default,
    /// so connect to the bare address and let the request use that
    /// connection. Plain HTTP only: std's TLS setup expects its own path.
    fn preconnect(self: *HttpTransport, uri: std.Uri, protocol: HttpClient.Protocol) Error!?*HttpClient.Connection {
        const address = ipv6Literal(uri) orelse return null;
        if (protocol != .plain) return null;
        return self.client.connectTcp(.{ .bytes = address }, uri.port orelse 80, .plain) catch |err| return mapConnectError(err);
    }

    /// What follows a response's head: its framing checked, the responses
    /// that end at the head returned, and otherwise its body read.
    fn readResponse(
        self: *HttpTransport,
        request: *HttpClient.Request,
        head: HttpClient.Response.Head,
        req: StreamRequest,
        arena: Allocator,
    ) StreamError!StreamResponse {
        const connection = request.connection.?;
        // std reads the code with wrapping arithmetic, so bytes that are
        // not digits make a status (`1;0` is 210): refused, as checkFraming
        // refuses a Content-Length that is not digits.
        if (!isDigits(head.bytes[9..12])) return error.HttpProtocolError;
        const status: u16 = @backingInt(head.status);
        // The head lives in the connection's read buffer, which reading the
        // body overwrites, so copy the headers out first.
        const headers = try collectHeaders(head, arena);
        try checkFraming(headers);
        if (req.head_out) |out| out.* = .{ .status = status, .headers = headers };
        if (status < 200) {
            // An informational response precedes the real one, which this
            // client does not wait for. The connection cannot be reused.
            connection.closing = true;
            return .{ .status = status, .headers = headers };
        }
        if (req.method == .HEAD or status == 204 or status == 304) {
            // These end at the head, whatever its framing headers say (RFC
            // 9112 6.3): a HEAD's describe the body a GET would get. Reading
            // that body would wait on bytes that never come, or take the
            // next response's for it. The connection is ready for the next
            // request.
            request.reader.state = .ready;
            return .{ .status = status, .headers = headers };
        }
        // Only a success streams to the sink writer; an error body is
        // buffered, so the caller can always read what the server said.
        const to_writer: ?*std.Io.Writer = switch (req.sink) {
            .buffer => null,
            .writer => |w| if (status < 300) w else null,
        };
        const read = try self.readBody(request, head, req.accept_encoding, to_writer, arena);
        return .{ .status = status, .body = read.body, .headers = headers, .bytes_streamed = read.streamed };
    }

    /// A response's body: framed by its length or its chunks, decoded when
    /// compressed, and delivered into `to_writer` when there is one, else
    /// into `arena` up to `max_response_bytes`. A compressed body is held to
    /// its own trailer, which std's decoder reads and never checks.
    fn readBody(
        self: *HttpTransport,
        request: *HttpClient.Request,
        head: HttpClient.Response.Head,
        accept: StreamRequest.AcceptEncoding,
        to_writer: ?*std.Io.Writer,
        arena: Allocator,
    ) StreamError!ReadBody {
        // A body wanted as sent is not decoded, whatever it says it is.
        const encoding: http.ContentEncoding = if (accept == .gzip_as_sent) .identity else head.content_encoding;
        var transfer_buffer: [64]u8 = undefined;
        var dechunker: Dechunker = undefined;
        const chunked = head.transfer_encoding == .chunked;
        // A streamed body has no size limit: it goes to the caller, not the
        // arena. The chunk-size bound only guards the buffered path's memory.
        const max_chunk: u64 = if (to_writer == null) self.max_response_bytes *| 2 +| 1024 else std.math.maxInt(u64);
        const transfer: *std.Io.Reader = if (chunked) t: {
            dechunker = .init(request.reader.in, &transfer_buffer, max_chunk);
            break :t &dechunker.interface;
        } else request.reader.bodyReader(&transfer_buffer, head.transfer_encoding, head.content_length);
        // Decompressed here, from the transport's own dechunker, rather than
        // by std.http's reader, which would decode the chunks with std's
        // decoder (see `Dechunker`).
        var inflate: flate.Decompress = undefined;
        const reader: *std.Io.Reader = switch (encoding) {
            .identity => transfer,
            .gzip, .deflate => r: {
                // The window the decoder needs, in the caller's arena.
                const window = try arena.alloc(u8, flate.max_window_len);
                inflate = .init(transfer, if (encoding == .gzip) .gzip else .zlib, window);
                break :r &inflate.reader;
            },
            // std refuses an encoding the request did not accept, and it
            // accepts only gzip and deflate, so these arrive only if std
            // changes. zstd would need a larger window than std's own table
            // gives, and a smaller one fails an assertion.
            .zstd, .compress => return error.HttpProtocolError,
        };
        const source: BodySource = .{
            .request = request,
            .dechunker = if (chunked) &dechunker else null,
            .transfer = transfer,
            .encoding = encoding,
            .max_drain = self.max_response_bytes,
        };
        var check: TrailerCheck = .of(encoding);
        const read: ReadBody = if (to_writer) |w|
            .{ .streamed = try streamBody(reader, w, &check, source) }
        else
            .{ .body = try bufferBody(reader, self.max_response_bytes, &check, source, arena) };
        try finishFraming(source, head.content_length);
        if (encoding != .identity) try check.against(inflate.container_metadata);
        return read;
    }

    /// Refuses a URL that would go out other than as written, or that two
    /// parsers would read apart, before anything connects: a control byte,
    /// a space or a backslash anywhere in it (std.http writes the path as it
    /// is given, so a CR and LF in it split the request: CWE-93, the class
    /// of Python urllib's CVE-2019-9740), userinfo (`user:pw@`, which std
    /// silently drops), and a percent-encoded host, which std sends in Host
    /// as written. A URL comes from the program, but parts of it often come
    /// from input; `query` encodes them.
    /// `url` parsed and checked, with the protocol it is sent over. The
    /// host must be one std will name (RFC 1123), as `client.request`
    /// refuses any other, except an IPv6 literal over plain HTTP, which
    /// the transport connects to itself (`preconnect`).
    fn target(url: []const u8) Error!struct { std.Uri, HttpClient.Protocol } {
        const uri = std.Uri.parse(url) catch return error.InvalidEndpoint;
        try checkUrl(url, uri);
        const protocol = HttpClient.Protocol.fromUri(uri) orelse return error.InvalidEndpoint;
        if (ipv6Literal(uri) == null or protocol != .plain) {
            var host_buf: [std.Io.net.HostName.max_len]u8 = undefined;
            _ = std.Io.net.HostName.fromUri(uri, &host_buf) catch return error.InvalidEndpoint;
        }
        return .{ uri, protocol };
    }

    fn checkUrl(text: []const u8, uri: std.Uri) Error!void {
        for (text) |c| if (c <= ' ' or c == 0x7f or c == '\\') return error.InvalidEndpoint;
        if (uri.user != null or uri.password != null) return error.InvalidEndpoint;
        const host = uri.host orelse return error.InvalidEndpoint;
        const host_text = switch (host) {
            .raw => |raw| raw,
            .percent_encoded => |encoded| encoded,
        };
        if (std.mem.findScalar(u8, host_text, '%') != null) return error.InvalidEndpoint;
    }

    /// Refuses, before anything is sent, a header HTTP cannot carry, and one
    /// the transport writes itself: the framing and connection headers
    /// (`isOwnedHeader`), a second Authorization beside `bearer`, and a
    /// second Content-Type beside `content_type`. With two, a server or a
    /// proxy before it picks one, and two lengths is request smuggling
    /// (CWE-444).
    fn checkHeaders(bearer: ?[]const u8, content_type: ?[]const u8, headers: []const Header) Error!void {
        if (bearer) |token| if (!isValidBearerToken(token)) return error.InvalidRequestHeader;
        for (headers) |h| if (!isAllowedHeader(h, bearer != null, content_type != null)) return error.InvalidRequestHeader;
        if (content_type) |ct| if (!isValidHeaderValue(ct)) return error.InvalidRequestHeader;
    }

    /// Whether `h` goes out as asked: a name and value HTTP can carry, and
    /// not a header the transport writes itself.
    fn isAllowedHeader(h: Header, has_bearer: bool, has_content_type: bool) bool {
        if (!isValidHeaderName(h.name) or !isValidHeaderValue(h.value)) return false;
        if (isOwnedHeader(h.name)) return false;
        if (has_bearer and std.ascii.eqlIgnoreCase(h.name, "authorization")) return false;
        return !(has_content_type and std.ascii.eqlIgnoreCase(h.name, "content-type"));
    }

    /// Refuses a response whose body is framed two ways or whose length is
    /// not plain digits: Transfer-Encoding beside Content-Length, which
    /// RFC 9112 6.3 says ought to be handled as an error, and a length such
    /// as `+2`, which std reads as 2 and another parser need not (the class
    /// of hyper's CVE-2021-32715). Either can put the next response on this
    /// connection out of step, so the connection is closed.
    fn checkFraming(headers: []const Header) Error!void {
        var length = false;
        var encoding = false;
        for (headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "transfer-encoding")) encoding = true;
            if (!std.ascii.eqlIgnoreCase(h.name, "content-length")) continue;
            length = true;
            if (!isDigits(std.mem.trim(u8, h.value, " \t"))) return error.HttpProtocolError;
        }
        if (length and encoding) return error.HttpProtocolError;
    }

    /// Every header of `head`, in `arena`: one copy of the head, the names
    /// and values sliced from it (about 160 ns less per response than a
    /// copy of each, by `zig build bench`). std.http bounds the head by the
    /// connection's read buffer, so this copy is bounded too.
    fn collectHeaders(head: HttpClient.Response.Head, arena: Allocator) Allocator.Error![]const Header {
        const copy = try arena.dupe(u8, head.bytes);
        var headers: std.ArrayList(Header) = .empty;
        var it: http.HeaderIterator = .init(copy);
        while (it.next()) |h| try headers.append(arena, h);
        return headers.items;
    }
};

/// The headers a caller may not set, since the transport writes them or
/// they govern the connection: the message's framing and the hop-by-hop
/// headers of RFC 9110 7.6.1, and Accept-Encoding, which says what the
/// transport decodes.
const owned_headers = [_][]const u8{ "host", "content-length", "transfer-encoding", "connection", "keep-alive", "te", "trailer", "upgrade", "proxy-connection", "accept-encoding" };

/// Whether `name` is one of the headers the transport owns: a caller that
/// sets one gets `error.InvalidRequestHeader`.
pub fn isOwnedHeader(name: []const u8) bool {
    for (owned_headers) |owned| if (std.ascii.eqlIgnoreCase(name, owned)) return true;
    return false;
}

/// Whether `token` can follow `Bearer ` in Authorization: non-empty, every
/// byte visible ASCII. std.http writes the header as it is given, so a
/// token with CR and LF in it, from a hostile or broken token endpoint,
/// would add a header of its own to the request.
pub fn isValidBearerToken(token: []const u8) bool {
    if (token.len == 0) return false;
    for (token) |c| if (c <= ' ' or c >= 0x7f) return false;
    return true;
}

fn isDigits(text: []const u8) bool {
    if (text.len == 0) return false;
    for (text) |c| if (!std.ascii.isDigit(c)) return false;
    return true;
}

/// A buffered pass-through to another writer. Everything drains straight
/// on; the buffer only gives the readers upstream somewhere to put bytes,
/// which they require and which the destination may not have.
const ForwardWriter = struct {
    out: *std.Io.Writer,
    writer: std.Io.Writer,
    /// When set, sees every byte forwarded, as a compressed body's decoded
    /// bytes are held to its trailer.
    check: ?*TrailerCheck = null,

    fn init(out: *std.Io.Writer, buffer: []u8) ForwardWriter {
        return .{ .out = out, .writer = .{ .buffer = buffer, .vtable = &.{ .drain = drain } } };
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *ForwardWriter = @alignCast(@fieldParentPtr("writer", w));
        const buffered = w.buffered();
        if (buffered.len > 0) try self.forward(buffered);
        w.end = 0;
        var consumed: usize = 0;
        for (data[0 .. data.len - 1]) |slice| {
            try self.forward(slice);
            consumed += slice.len;
        }
        const pattern = data[data.len - 1];
        for (0..splat) |_| {
            try self.forward(pattern);
            consumed += pattern.len;
        }
        return consumed;
    }

    fn forward(self: *ForwardWriter, bytes: []const u8) std.Io.Writer.Error!void {
        try self.out.writeAll(bytes);
        if (self.check) |c| c.update(bytes);
    }
};

/// std.http's name for a method.
fn httpMethod(method: Method) http.Method {
    return switch (method) {
        .GET => .GET,
        .PUT => .PUT,
        .POST => .POST,
        .DELETE => .DELETE,
        .PATCH => .PATCH,
        .HEAD => .HEAD,
    };
}

/// What `Accept-Encoding` says for `accept`.
fn acceptEncoding(accept: StreamRequest.AcceptEncoding) HttpClient.Request.Headers.Value {
    return switch (accept) {
        .compressed => .default,
        .identity => .{ .override = "identity" },
        .gzip_as_sent => .{ .override = "gzip" },
    };
}

/// A response body as read: in `body` when buffered, counted in `streamed`
/// when it went to the caller's writer.
const ReadBody = struct {
    body: []const u8 = "",
    streamed: u64 = 0,
};

/// Where a response body is read from, for the functions that read it, and
/// for `bodyError`, which says why a read failed.
const BodySource = struct {
    request: *HttpClient.Request,
    dechunker: ?*Dechunker,
    transfer: *std.Io.Reader,
    encoding: http.ContentEncoding,
    /// How much of the framing a failed decode drains to tell a dropped
    /// connection from a bad body: the response limit.
    max_drain: usize,

    fn fail(s: BodySource) Error {
        return bodyError(s.request, s.dechunker, s.transfer, s.encoding, s.max_drain);
    }
};

/// A body streamed into `w` as it arrives, through a buffer of the
/// transport's own: the readers in the chain need somewhere writable, and a
/// caller's unbuffered writer has nowhere. Returns the bytes delivered.
fn streamBody(reader: *std.Io.Reader, w: *std.Io.Writer, check: *TrailerCheck, source: BodySource) StreamError!u64 {
    var forward_buffer: [4096]u8 = undefined;
    var forward: ForwardWriter = .init(w, &forward_buffer);
    if (source.encoding != .identity) forward.check = check;
    var streamed: u64 = 0;
    while (true) {
        const n = reader.stream(&forward.writer, .unlimited) catch |err| switch (err) {
            error.EndOfStream => break,
            // The caller's writer failed; the rest of the body is abandoned.
            error.WriteFailed => return error.WriteFailed,
            error.ReadFailed => {
                // What arrived before the failure still belongs to the
                // caller; a resume counts on having it.
                forward.writer.flush() catch return error.WriteFailed;
                return source.fail();
            },
        };
        streamed += n;
        // What arrived goes on now, not when the buffer fills: a streamed
        // answer's next message may be a while coming.
        try forward.writer.flush();
    }
    try forward.writer.flush();
    return streamed;
}

/// A body read whole into `arena`, up to `max` bytes after decoding.
fn bufferBody(reader: *std.Io.Reader, max: usize, check: *TrailerCheck, source: BodySource, arena: Allocator) StreamError![]const u8 {
    // `allocRemaining` takes up to the limit and fails past it.
    const body = reader.allocRemaining(arena, .limited(max)) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.StreamTooLong => error.ResponseTooLarge,
        error.ReadFailed => source.fail(),
    };
    if (source.encoding != .identity) check.update(body);
    return body;
}

/// The end of a body's framing, once its last byte is read. What a decoder
/// left of the framing is consumed, so the connection can be reused and a
/// cut still shows; chunked framing must have reached its last chunk; and
/// a body short of its Content-Length is a dropped connection, which std
/// reports as a normal end.
fn finishFraming(source: BodySource, content_length: ?u64) Error!void {
    const request = source.request;
    // A decompressor stops at the end of its own stream, which can leave
    // the last chunk unread (Google's front end sends gzip in chunks).
    if (source.encoding != .identity) {
        // One byte is the verdict: anything at all after the stream is
        // content. Read on, endless chunks would hold an untimed caller.
        const extra = source.transfer.discardShort(1) catch
            return bodyError(request, source.dechunker, source.transfer, .identity, 0);
        // What the framing held past the compressed stream is content, not
        // framing: a second gzip member, or bytes after a zlib stream. std's
        // decoder reads one member; refused rather than dropped, so a body is
        // never cut short in silence.
        if (extra > 0) return error.HttpProtocolError;
    }
    if (source.dechunker) |d| {
        if (!d.done()) return error.ConnectionResetByPeer;
        // Framing ended exactly at the terminating chunk; the next response
        // starts here.
        request.reader.state = .ready;
    } else if (content_length != null and request.reader.state != .ready) {
        return error.ConnectionResetByPeer;
    }
}

/// A compressed body's decoded bytes, hashed and counted to hold them to
/// the trailer std's decoder reads and never checks: gzip's CRC-32 and
/// length (mod 2^32), zlib's Adler-32. A body that does not match its own
/// trailer is a bad body, `error.HttpProtocolError`, whatever it decoded to.
/// Only the container's own hash is computed: hashing a gzip body with
/// Adler-32 too cost about 250 us a MiB, and a zlib body with CRC-32 too
/// about 1.7 ms, more than the decode (`zig build bench`).
const TrailerCheck = struct {
    container: flate.Container,
    crc: Crc32 = .init(),
    adler: std.hash.Adler32 = .{},
    count: u64 = 0,

    /// The check for a body in `encoding`: gzip's trailer holds a CRC-32,
    /// deflate's (a zlib stream) an Adler-32, and any other body none.
    fn of(encoding: http.ContentEncoding) TrailerCheck {
        return .{ .container = switch (encoding) {
            .gzip => .gzip,
            .deflate => .zlib,
            else => .raw,
        } };
    }

    fn update(c: *TrailerCheck, bytes: []const u8) void {
        switch (c.container) {
            .gzip => c.crc.update(bytes),
            .zlib => c.adler.update(bytes),
            .raw => {},
        }
        c.count += bytes.len;
    }

    fn against(c: *TrailerCheck, metadata: flate.Container.Metadata) Error!void {
        const ok = switch (metadata) {
            .gzip => |g| g.crc == c.crc.final() and g.count == @as(u32, @truncate(c.count)),
            .zlib => |z| z.adler == c.adler.adler,
            .raw => true,
        };
        if (!ok) return error.HttpProtocolError;
    }
};

/// The address inside `[...]` when the URI's host is an IPv6 literal.
fn ipv6Literal(uri: std.Uri) ?[]const u8 {
    const host = switch (uri.host orelse return null) {
        .raw, .percent_encoded => |h| h,
    };
    if (host.len < 3 or host[0] != '[' or host[host.len - 1] != ']') return null;
    return host[1 .. host.len - 1];
}

/// Sends the request head and body. `ReadFailed` is the caller's body
/// reader, `EndOfStream` a body reader that ended before its declared
/// length, and `WriteFailed` the connection, whose detail `mapError` reads.
fn sendBody(
    request: *HttpClient.Request,
    body: StreamRequest.Body,
) error{ ReadFailed, WriteFailed, EndOfStream }!void {
    // The body writer needs a buffer of its own: a reader-backed source
    // streams into it, and readers require a writable destination.
    var body_buffer: [4096]u8 = undefined;
    switch (body) {
        // A method that takes a body sends an empty one, with its length.
        // (Zig 0.17.0's std asserted that it did; 0.17.1's sends none.)
        .none => return if (request.method.requestHasBody()) sendBody(request, .{ .segments = &.{} }) else request.sendBodiless(),
        .segments => |segments| {
            var total: u64 = 0;
            for (segments) |s| total += s.len;
            request.transfer_encoding = .{ .content_length = total };
            var body_writer = try request.sendBodyUnflushed(&body_buffer);
            for (segments) |s| try body_writer.writer.writeAll(s);
            try bodyEnd(request, &body_writer);
        },
        .stream => |source| {
            request.transfer_encoding = .{ .content_length = source.len };
            var body_writer = try request.sendBodyUnflushed(&body_buffer);
            try source.reader.streamExact64(&body_writer.writer, source.len);
            try bodyEnd(request, &body_writer);
        },
    }
}

/// Ends a body sent with its length, all of it written, and flushes it.
/// std's BodyWriter tells the request so itself, clearing
/// `payload_pending`, but its link to the request is typed for std's
/// Request, not `HttpClient`'s, so the copy leaves it null
/// (tools/zig_tls.zig) and this does what `end` would have. The flag
/// matters only to a request freed with its response's body unread (the
/// transport marks the connection ready once it has read one): std then
/// drains that body and keeps the connection, unless a body sent was
/// never ended.
fn bodyEnd(request: *HttpClient.Request, body_writer: *http.BodyWriter) http.BodyWriter.Error!void {
    try body_writer.end();
    request.payload_pending = false;
    try request.connection.?.flush();
}

/// Maps a failed body read. A body cut short by a dropped connection is
/// retryable; one that arrived whole but would not decode is not.
fn bodyError(
    request: *HttpClient.Request,
    dechunker: ?*Dechunker,
    transfer: *std.Io.Reader,
    encoding: http.ContentEncoding,
    max_drain: usize,
) Error {
    const connection = request.connection.?;
    if (dechunker) |d| if (d.err) |err| return err;
    if (connection.stream_reader.err) |err| return mapError(err, null);
    if (encoding == .identity) return socketOk(connection);
    // The decoder failed. If the framing ends early too, the connection
    // dropped mid-body; if the framing is whole, the body itself is bad.
    // Read no further than the response limit to tell: past it, the body
    // is bad whatever its framing, on the buffered path and the streamed.
    const drained = transfer.discardShort(max_drain +| 1) catch d: {
        // A socket error in the drain is the answer, a cancel among them:
        // the framing's state would call it a dropped connection, retried.
        if (connection.stream_reader.err) |err| return mapError(err, null);
        break :d 0;
    };
    if (drained > max_drain) return error.HttpProtocolError;
    const framing_complete = if (dechunker) |d|
        d.done()
    else
        request.reader.state == .ready or request.reader.state == .body_none;
    return if (framing_complete) error.HttpProtocolError else error.ConnectionResetByPeer;
}

/// Decodes `Transfer-Encoding: chunked` straight from the connection. It
/// replaces std.http's decoder, which panics with an integer overflow on a
/// chunk size near 2^64 and reads any letter as a hex digit. Sizes are
/// bounded before use, and reading stops exactly after the terminating chunk
/// and trailers, where the next response on the connection begins. Not
/// thread-safe: one task reads through it.
pub const Dechunker = struct {
    in: *std.Io.Reader,
    interface: std.Io.Reader,
    /// Larger chunks fail with `error.ResponseTooLarge`.
    max_chunk: u64,
    state: union(enum) {
        size,
        /// Chunk bytes still to read.
        data: u64,
        data_end,
        /// Trailer bytes read so far.
        trailers: usize,
        done,
    } = .size,
    /// Why reading failed, when the framing was at fault. Socket failures are
    /// recorded on the connection instead.
    err: ?Error = null,

    const max_trailer_bytes = 16 * 1024;

    /// `in` must start at the first chunk. `buffer` backs `interface`.
    pub fn init(in: *std.Io.Reader, buffer: []u8, max_chunk: u64) Dechunker {
        return .{
            .in = in,
            .max_chunk = max_chunk,
            .interface = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
        };
    }

    /// Whether the terminating chunk and trailers were read.
    pub fn done(d: *const Dechunker) bool {
        return d.state == .done;
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const d: *Dechunker = @alignCast(@fieldParentPtr("interface", r));
        while (true) switch (d.state) {
            .size => try d.readSize(),
            .data => |left| {
                const n = d.in.stream(w, limit.min(.limited64(left))) catch |err| switch (err) {
                    error.EndOfStream => return d.fail(error.ConnectionResetByPeer),
                    error.ReadFailed, error.WriteFailed => |e| return e,
                };
                d.state = if (n == left) .data_end else .{ .data = left - n };
                return n;
            },
            .data_end => {
                const crlf = d.in.takeArray(2) catch |err| return d.readError(err);
                if (!std.mem.eql(u8, crlf, "\r\n")) return d.fail(error.HttpProtocolError);
                d.state = .size;
            },
            .trailers => |seen| try d.readTrailer(seen),
            .done => return error.EndOfStream,
        };
    }

    /// `chunk-size [ chunk-ext ] CRLF`
    fn readSize(d: *Dechunker) error{ReadFailed}!void {
        const line = d.in.takeDelimiterInclusive('\n') catch |err| return d.readError(err);
        var size: u64 = 0;
        var digits: usize = 0;
        for (line) |c| {
            const digit = std.fmt.charToDigit(c, 16) catch break;
            const shifted = std.math.mul(u64, size, 16) catch return d.fail(error.ResponseTooLarge);
            size = shifted + digit;
            if (size > d.max_chunk) return d.fail(error.ResponseTooLarge);
            digits += 1;
        }
        // The line ends in '\n', which is not a digit, so `rest` is not empty.
        const rest = line[digits..];
        if (digits == 0) return d.fail(error.HttpProtocolError);
        switch (rest[0]) {
            ';', ' ', '\t', '\r', '\n' => {},
            else => return d.fail(error.HttpProtocolError),
        }
        d.state = if (size == 0) .{ .trailers = 0 } else .{ .data = size };
    }

    fn readTrailer(d: *Dechunker, seen: usize) error{ReadFailed}!void {
        const line = d.in.takeDelimiterInclusive('\n') catch |err| return d.readError(err);
        if (std.mem.eql(u8, line, "\r\n") or std.mem.eql(u8, line, "\n")) {
            d.state = .done;
            return;
        }
        if (seen + line.len > max_trailer_bytes) return d.fail(error.HttpProtocolError);
        d.state = .{ .trailers = seen + line.len };
    }

    fn readError(d: *Dechunker, err: anyerror) error{ReadFailed} {
        return switch (err) {
            // The socket's own error is on the connection.
            error.ReadFailed => error.ReadFailed,
            error.EndOfStream => d.fail(error.ConnectionResetByPeer),
            // A line longer than the connection's buffer.
            else => d.fail(error.HttpProtocolError),
        };
    }

    fn fail(d: *Dechunker, err: Error) error{ReadFailed} {
        d.err = err;
        return error.ReadFailed;
    }
};

/// Maps a `std.http` or `std.Io.net` failure to `Error`. `ReadFailed` and
/// `WriteFailed` carry no detail, so the connection's recorded error is used.
fn mapError(err: anyerror, connection: ?*HttpClient.Connection) Error {
    return switch (err) {
        error.ReadFailed => if (connection) |c|
            if (c.stream_reader.err) |e| mapError(e, null) else socketOk(c)
        else
            error.ConnectionResetByPeer,
        error.WriteFailed => if (connection) |c|
            if (c.stream_writer.err) |e| mapError(e, null) else socketOk(c)
        else
            error.ConnectionResetByPeer,

        error.Canceled => error.Canceled,
        error.OutOfMemory => error.OutOfMemory,

        error.ConnectionRefused => error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.SocketUnconnected,
        error.BrokenPipe,
        error.EndOfStream,
        error.HttpConnectionClosing,
        error.HttpRequestTruncated,
        error.HttpChunkTruncated,
        => error.ConnectionResetByPeer,
        error.Timeout, error.ConnectionTimedOut => error.ConnectionTimedOut,
        error.NetworkUnreachable,
        error.HostUnreachable,
        error.NetworkDown,
        error.AddressUnavailable,
        => error.NetworkUnreachable,

        error.UnknownHostName, error.NoAddressReturned => error.UnknownHostName,
        error.NameServerFailure,
        error.ResolvConfParseFailed,
        error.DetectingNetworkConfigurationFailed,
        error.InvalidDnsARecord,
        error.InvalidDnsAAAARecord,
        error.InvalidDnsCnameRecord,
        => error.NameServerFailure,

        error.TlsInitializationFailed,
        error.CertificateBundleLoadFailure,
        => error.TlsFailure,

        error.UnsupportedUriScheme, error.UriMissingHost, error.InvalidHostName => error.InvalidEndpoint,

        // std on Windows returns Unexpected for socket statuses it does not
        // map. Zig 0.16 left a refused connection among them, and 0.17.0 a
        // peer that hangs up mid-read or write (STATUS_LOCAL_DISCONNECT),
        // which 0.17.1 maps. Which status it was is lost by now, and a
        // hang-up is worth retrying, so call it a dropped connection.
        // Elsewhere std maps every socket error it expects once a request
        // is under way; making the connection is `mapConnectError`'s.
        error.Unexpected => if (builtin.target.os.tag == .windows) error.ConnectionResetByPeer else error.NetworkFailure,

        error.HttpHeadersOversize,
        error.HttpHeadersInvalid,
        error.HttpChunkInvalid,
        error.HttpContentEncodingUnsupported,
        error.HttpTransferEncodingUnsupported,
        error.HttpConnectionHeaderUnsupported,
        error.HttpHeaderContinuationsUnsupported,
        error.InvalidContentLength,
        error.TooManyHttpRedirects,
        error.RedirectRequiresResend,
        error.HttpRedirectLocationMissing,
        error.HttpRedirectLocationOversize,
        error.HttpRedirectLocationInvalid,
        => error.HttpProtocolError,

        else => error.NetworkFailure,
    };
}

/// `mapError` for a failure in making the connection: std's
/// `Client.request` connects, TLS handshake and all, and sends nothing.
/// There `error.Unexpected` is a dropped connection on every platform.
/// std's connect calls `connect()` again when a signal interrupts it, and
/// on macOS the second call answers EISCONN at once while the first goes
/// on in the kernel; std takes that for a programmer's bug (Codeberg
/// ziglang/zig#31391), which a release build returns as `error.Unexpected`,
/// the socket closed. The signal can be `Io.Threaded`'s own cancel, late:
/// `HostName.connect` cancels the addresses that lose its race. Nothing
/// was sent, so another attempt is safe; an errno that is a real bug fails
/// each attempt the same way, until the retries run out.
fn mapConnectError(err: anyerror) Error {
    return if (err == error.Unexpected) error.ConnectionResetByPeer else mapError(err, null);
}

/// A read or write failed but the socket recorded no error, so the TLS layer
/// (or a peer that closed cleanly) caused it.
fn socketOk(connection: *const HttpClient.Connection) Error {
    return if (connection.protocol == .tls) error.TlsFailure else error.ConnectionResetByPeer;
}

// Tests use a real `HttpClient` against a scripted server on the loopback
// interface. Nothing leaves the machine.

const testing = std.testing;
const net = std.Io.net;
const test_util = @import("testing.zig");
const BodyHash = std.hash.Crc32;

const ScriptedServer = test_util.ScriptedServer;

fn expectHeader(raw: []const u8, header_line: []const u8) !void {
    if (std.mem.find(u8, raw, header_line) == null) {
        std.debug.print("missing header {s} in request:\n{s}\n", .{ header_line, raw });
        return error.TestExpectedHeader;
    }
}

test "HttpTransport sends headers and body and reads the response" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"messageIds\":[]}",
        "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found",
    });
    defer server.deinit(io);
    server.per_connection = 2;
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "rest-core-test/1");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;

    const first = try ht.transport().send(.{
        .method = .POST,
        .url = server.url(&buf, "/v1/projects/p/topics/t:publish"),
        .bearer = "tok-123",
        .body = "{\"messages\":[]}",
    }, arena.allocator());
    try testing.expectEqual(200, first.status);
    try testing.expectEqualStrings("{\"messageIds\":[]}", first.body);

    // The second request reuses the kept-alive connection.
    const second = try ht.transport().send(.{
        .method = .GET,
        .url = server.url(&buf, "/v1/projects/p/topics/t"),
    }, arena.allocator());
    try testing.expectEqual(404, second.status);
    try testing.expectEqualStrings("Not Found", second.body);

    try serving.await(io);
    try testing.expectEqual(1, server.connections);

    const post = server.request(0);
    try testing.expect(std.mem.startsWith(u8, post, "POST /v1/projects/p/topics/t:publish HTTP/1.1\r\n"));
    try expectHeader(post, "user-agent: rest-core-test/1\r\n");
    try expectHeader(post, "content-type: application/json\r\n");
    try expectHeader(post, "authorization: Bearer tok-123\r\n");
    try expectHeader(post, "content-length: 15\r\n");
    try testing.expect(std.mem.endsWith(u8, post, "\r\n\r\n{\"messages\":[]}"));

    const get = server.request(1);
    try testing.expect(std.mem.startsWith(u8, get, "GET /v1/projects/p/topics/t HTTP/1.1\r\n"));
    try testing.expect(std.mem.find(u8, get, "authorization") == null);
    try testing.expect(std.mem.find(u8, get, "content-type") == null);
}

test "HttpTransport sends a form body with its content type" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
    });
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    _ = try ht.transport().send(.{
        .method = .POST,
        .url = server.url(&buf, "/token"),
        .body = "grant_type=refresh_token&refresh_token=1%2F%2Fabc",
        .content_type = .form,
    }, arena.allocator());
    try serving.await(io);

    const post = server.request(0);
    try expectHeader(post, "content-type: application/x-www-form-urlencoded\r\n");
    try testing.expect(std.mem.endsWith(u8, post, "\r\n\r\ngrant_type=refresh_token&refresh_token=1%2F%2Fabc"));
}

test "HttpTransport: a server that accepts and then says nothing is TimedOut" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"});
    defer server.deinit(io);
    server.hang = true;
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    const started = std.Io.Clock.awake.now(io);
    const outcome = ht.transport().send(.{
        .method = .GET,
        .url = server.url(&buf, "/v1/slow"),
        .timeout_ms = 150,
    }, arena.allocator());
    const elapsed_ms = started.durationTo(std.Io.Clock.awake.now(io)).toMilliseconds();
    // Windows sometimes tears the idle connection down before the timeout
    // (STATUS_LOCAL_DISCONNECT, which `mapError` reads as a dropped
    // connection). The request still ended promptly, but it is not the
    // timeout under test, so bow out. The outcome says which it was; the
    // time cannot, since a Windows timer can fire a hair before this clock
    // says it is due, and a real timeout then measures 149 ms.
    if (builtin.target.os.tag == .windows) {
        if (outcome) |_| {} else |err| if (err == error.ConnectionResetByPeer) return error.SkipZigTest;
    }
    try testing.expectError(error.TimedOut, outcome);
    // It waited for the timeout, and not much longer. Windows gets a timer
    // tick of slack.
    const slack_ms: i64 = if (builtin.target.os.tag == .windows) 16 else 0;
    try testing.expect(elapsed_ms >= 150 - slack_ms);
    try testing.expect(elapsed_ms < 5_000);
}

test "HttpTransport: a timed-out request leaves the transport usable" {
    const io = testing.io;
    var slow: ScriptedServer = try .start(io, &.{"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"});
    defer slow.deinit(io);
    slow.hang = true;
    var serving_slow = try io.concurrent(ScriptedServer.run, .{ &slow, io });
    defer _ = serving_slow.cancel(io) catch {};
    var quick: ScriptedServer = try .start(io, &.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"});
    defer quick.deinit(io);
    var serving_quick = try io.concurrent(ScriptedServer.run, .{ &quick, io });
    defer _ = serving_quick.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    try testing.expectError(error.TimedOut, ht.transport().send(.{
        .method = .GET,
        .url = slow.url(&buf, "/v1/slow"),
        .timeout_ms = 150,
    }, arena.allocator()));

    // The canceled request took its connection with it; the next one works.
    var next_buf: [128]u8 = undefined;
    const res = try ht.transport().send(.{
        .method = .GET,
        .url = quick.url(&next_buf, "/v1/quick"),
        .timeout_ms = 30_000,
    }, arena.allocator());
    try testing.expectEqual(200, res.status);
    try testing.expectEqualStrings("hi", res.body);
    try serving_quick.await(io);
}

test "HttpTransport hands back the response headers, still readable after the body" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 200 OK\r\nMetadata-Flavor: Google\r\nContent-Length: 12\r\n" ++
            "X-Twice: first\r\nX-Twice: second\r\n\r\nhello world!",
    });
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    const res = try ht.transport().send(.{
        .method = .GET,
        .url = server.url(&buf, "/computeMetadata/v1/"),
    }, arena.allocator());
    try serving.await(io);

    // The head lives in the read buffer that the body overwrites, so these
    // are copies, not views of whatever is there now.
    try testing.expectEqualStrings("hello world!", res.body);
    try testing.expectEqualStrings("Google", res.header("metadata-flavor").?);
    try testing.expectEqualStrings("12", res.header("Content-Length").?);
    try testing.expectEqual(null, res.header("X-Absent"));
    // A name sent twice keeps its first value, as std.http does.
    try testing.expectEqualStrings("first", res.header("x-twice").?);
    try testing.expectEqual(4, res.headers.len);
}

test "a response without headers answers every lookup with null" {
    const empty: Response = .{ .status = 200, .body = "" };
    try testing.expectEqual(null, empty.header("Metadata-Flavor"));
}

test "HttpTransport sends extra headers, in order, after its own" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
    });
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    _ = try ht.transport().send(.{
        .method = .GET,
        .url = server.url(&buf, "/computeMetadata/v1/"),
        .headers = &.{
            .{ .name = "Metadata-Flavor", .value = "Google" },
            .{ .name = "x-goog-user-project", .value = "billing-project" },
        },
    }, arena.allocator());
    try serving.await(io);

    const get = server.request(0);
    try expectHeader(get, "Metadata-Flavor: Google\r\n");
    try expectHeader(get, "x-goog-user-project: billing-project\r\n");
    // After the ones the transport writes itself, so neither can be replaced.
    try testing.expect(std.mem.find(u8, get, "user-agent: t\r\n").? < std.mem.find(u8, get, "Metadata-Flavor").?);
}

test "HttpTransport refuses a header that would end the line, before it connects" {
    var ht: HttpTransport = .init(testing.allocator, testing.io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    for ([_]Header{
        .{ .name = "X-Evil", .value = "1\r\nX-Injected: 2" },
        .{ .name = "X-Evil", .value = "1\n" },
        .{ .name = "X-Evil", .value = " 1" },
        .{ .name = "X-Evil", .value = "1\t" },
        .{ .name = "X-Evil", .value = "caf\xc3\xa9" },
        .{ .name = "X-Evil\r\nX-Injected", .value = "1" },
        .{ .name = "X Evil", .value = "1" },
        .{ .name = "", .value = "1" },
    }) |h| {
        // Nothing listens on port 1: a connection attempt would be refused,
        // so InvalidRequestHeader proves the check runs first.
        try testing.expectError(error.InvalidRequestHeader, ht.transport().send(.{
            .method = .GET,
            .url = "http://127.0.0.1:1/",
            .headers = &.{h},
        }, arena.allocator()));
    }
}

test "header names and values follow RFC 9110" {
    try testing.expect(isValidHeaderName("Metadata-Flavor"));
    try testing.expect(isValidHeaderName("x-goog-user-project"));
    try testing.expect(!isValidHeaderName("X:Y"));
    try testing.expect(!isValidHeaderName("X Y"));
    try testing.expect(!isValidHeaderName(""));
    try testing.expect(isValidHeaderValue("Google"));
    try testing.expect(isValidHeaderValue("a b"));
    try testing.expect(isValidHeaderValue(""));
    try testing.expect(!isValidHeaderValue("a\x00b"));
    try testing.expect(!isValidHeaderValue("a\r\nb"));
    try testing.expect(!isValidHeaderValue(" a"));
    try testing.expect(!isValidHeaderValue("a "));
}

fn headerProperty(_: void, input: []const u8) !void {
    // An accepted header can never end its line or start another one.
    if (isValidHeaderName(input)) {
        try testing.expect(std.mem.findAny(u8, input, "\r\n\x00 \t:") == null);
        try testing.expect(input.len > 0);
    }
    if (isValidHeaderValue(input)) {
        try testing.expect(std.mem.findAny(u8, input, "\r\n\x00") == null);
        if (input.len > 0) try testing.expect(input[0] != ' ' and input[input.len - 1] != ' ');
    }
}

test "fuzz headers: nothing accepted can break the request" {
    try test_util.fuzzBytes({}, headerProperty, .{ .corpus = &.{
        "Metadata-Flavor",
        "Google",
        "a\r\nX-Injected: 1",
        " lead",
        "trail\t",
        "caf\xc3\xa9",
        "",
    } });
}

test "HttpTransport reaches IPv6 literal hosts, as an emulator at [::1]:8085" {
    const io = testing.io;
    // Regression: std.http looked up "[::1]" by name and failed.
    var server = ScriptedServer.startOn(io, .{ .ip6 = .loopback(0) }, &.{
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]",
    }) catch return error.SkipZigTest; // No IPv6 loopback here.
    defer server.deinit(io);
    server.per_connection = 2;
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [64]u8 = undefined;
    // ScriptedServer.url writes the address it is bound to, brackets and all.
    const url = server.url(&buf, "/v1/x");
    var want: [64]u8 = undefined;
    try testing.expectEqualStrings(try std.fmt.bufPrint(&want, "http://[::1]:{d}/v1/x", .{server.port}), url);
    try testing.expectEqualStrings("{}", (try ht.transport().send(.{ .method = .GET, .url = url }, arena.allocator())).body);
    try testing.expectEqualStrings("[]", (try ht.transport().send(.{ .method = .GET, .url = url }, arena.allocator())).body);
    try serving.await(io);
    // The pooled connection was reused, and the Host header keeps the brackets.
    try testing.expectEqual(1, server.connections);
    var host_line: [64]u8 = undefined;
    try expectHeader(server.request(0), try std.fmt.bufPrint(&host_line, "host: [::1]:{d}\r\n", .{server.port}));
}

test "ipv6Literal" {
    try testing.expectEqualStrings("::1", ipv6Literal(try std.Uri.parse("http://[::1]:8085")).?);
    try testing.expectEqualStrings("fe80::1", ipv6Literal(try std.Uri.parse("http://[fe80::1]/v1")).?);
    try testing.expectEqual(null, ipv6Literal(try std.Uri.parse("http://localhost:8085")));
    try testing.expectEqual(null, ipv6Literal(try std.Uri.parse("http://127.0.0.1:8085")));
}

test "HttpTransport reports a truncated body as a dropped connection" {
    const io = testing.io;
    // Regression: std.http returns a short Content-Length body as success.
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{\"receivedMessages\":[",
    });
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;

    try testing.expectError(error.ConnectionResetByPeer, ht.transport().send(.{
        .method = .POST,
        .url = server.url(&buf, "/v1/projects/p/subscriptions/s:pull"),
        .body = "{}",
    }, arena.allocator()));
}

test "HttpTransport refuses a status that is not three digits" {
    // std reads the three bytes with wrapping arithmetic, so "1;0" was
    // 210 and "abc" 331: garbage became a status, a 2xx among them.
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 1;0 OK\r\nContent-Length: 2\r\n\r\n{}",
        "HTTP/1.1 abc OK\r\nContent-Length: 2\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
    });
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};
    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    for (0..2) |_| try testing.expectError(error.HttpProtocolError, ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/a") }, arena.allocator()));
    try testing.expectEqual(200, (try ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/b") }, arena.allocator())).status);
}

test "HttpTransport reads chunked bodies and rejects bad chunk framing" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n",
        // Chunk data must end in CRLF. (std.http accepts any letter as a size
        // digit, so a size like "zz" is not a framing error to it.)
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXY0\r\n\r\n",
    });
    defer server.deinit(io);
    server.per_connection = 2;
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;

    const ok = try ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/a") }, arena.allocator());
    try testing.expectEqualStrings("{\"a\":1}", ok.body);
    try testing.expectError(
        error.HttpProtocolError,
        ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/b") }, arena.allocator()),
    );
}

test "HttpTransport reports a truncated chunked body as a dropped connection" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n{\"receivedMe",
    });
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    try testing.expectError(
        error.ConnectionResetByPeer,
        ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/a") }, arena.allocator()),
    );
}

/// Sends a GET whose answer, `head` and then a chunk size near 2^64, is
/// read through `arena`, which runs out after the head; then a GET that
/// works. The connection must close: kept, std drains the body with its own
/// chunked decoder (see `Dechunker`), which panics on that size in a safe
/// build and reads any body to its end in every build. The server holds the
/// connection open until the first call returns, so a drain waits out its
/// pause even where nothing panics.
fn expectOutOfMemoryAfterHeadCloses(comptime head: []const u8, arena: Allocator) !void {
    const io = testing.io;
    const reply = head ++ "ffffffffffffffff\r\n";
    var open: std.atomic.Value(bool) = .init(false);
    var server: ScriptedServer = try .start(io, &.{ reply, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}" });
    defer server.deinit(io);
    server.pause = .{ .after = reply.len, .open = &open };
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var buf: [128]u8 = undefined;
    try testing.expectError(
        error.OutOfMemory,
        ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/a") }, arena),
    );
    open.store(true, .release);
    var ok_arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer ok_arena.deinit();
    const ok = try ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/b") }, ok_arena.allocator());
    try testing.expectEqualStrings("{}", ok.body);
    try serving.await(io);
    try testing.expect(!server.pause_timed_out);
    try testing.expectEqual(2, server.connections);
}

test "HttpTransport: an arena that fails on the headers closes the connection, never draining it" {
    try expectOutOfMemoryAfterHeadCloses(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        testing.failing_allocator,
    );
}

test "HttpTransport: an arena that fails on the gzip window closes the connection, never draining it" {
    // Room for the headers, not for the decoder's 64 KiB window.
    var room: [4096]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&room);
    try expectOutOfMemoryAfterHeadCloses(
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n",
        fixed.allocator(),
    );
}

test "HttpTransport decodes gzip in chunks and keeps the connection" {
    const io = testing.io;
    // Regression: the gzip decoder stops before the final chunk, which once
    // made every production response look truncated.
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n" ++
            "14\x0d\x0a\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\xabV*\xc9/\xc8L.V\xb2\x0d\x0a2c\x0d\x0a\x8a\xaeV\xcaK\xccMU\xb2R*(\xca\xcfJM.)\xd6/\xd0\x87H\xeaWe\x16\x14\xa4\xa6(\xd5\xc6\xd6\x02\x00\x80\xdd\xe810\x00\x00\x00\x0d\x0a0\x0d\x0a\x0d\x0a",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
    });
    defer server.deinit(io);
    server.per_connection = 2;
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;

    const zipped = try ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/a") }, arena.allocator());
    try testing.expectEqualStrings("{\"topics\":[{\"name\":\"projects/p/topics/zipped\"}]}", zipped.body);
    const plain = try ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/b") }, arena.allocator());
    try testing.expectEqualStrings("{}", plain.body);
    try serving.await(io);
    // Both requests went over one connection.
    try testing.expectEqual(1, server.connections);
    try expectHeader(server.request(0), "accept-encoding: gzip, deflate\r\n");
}

test "HttpTransport rejects a gzip stream cut short" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n" ++
            "1e\x0d\x0a\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\xabV*\xc9/\xc8L.V\xb2\x8a\xaeV\xcaK\xccMU\xb2R\x0d\x0a0\x0d\x0a\x0d\x0a",
    });
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    try testing.expectError(
        error.HttpProtocolError,
        ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/a") }, arena.allocator()),
    );
}

test "Dechunker: a chunk size near 2^64 is an error, not a panic" {
    const io = testing.io;
    // Regression: std.http's decoder overflows on `chunk_len + 2` and panics.
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\nx",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n00000000000000000000000000000002\r\n{}\r\n0\r\n\r\n",
    });
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    try testing.expectError(
        error.ResponseTooLarge,
        ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/a") }, arena.allocator()),
    );
    // Leading zeros are fine however many there are.
    const ok = try ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/b") }, arena.allocator());
    try testing.expectEqualStrings("{}", ok.body);
}

test "HttpTransport: 204 ends at the head instead of waiting for the connection to close" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{"HTTP/1.1 204 No Content\r\n\r\n"});
    defer server.deinit(io);
    server.linger_ms = 3000;
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    const started = std.Io.Clock.awake.now(io);
    const res = try ht.transport().send(.{ .method = .DELETE, .url = server.url(&buf, "/a") }, arena.allocator());
    try testing.expectEqual(204, res.status);
    try testing.expectEqualStrings("", res.body);
    try testing.expect(started.untilNow(io, .awake).toMilliseconds() < 1500);
}

test "HttpTransport: a HEAD answer ends at its head, whatever its framing says, and keeps the connection" {
    const io = testing.io;
    // Each HEAD answer names a body it does not send, as Blob Storage's
    // Get Blob Properties does. Read as a GET's, the first would wait for a
    // megabyte, or take the next answers for its body. All four come on
    // one connection, so the GET's answer arrives intact only if every HEAD
    // ended at its blank line.
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\nContent-Type: application/octet-stream\r\nx-ms-meta-token: w1\r\n\r\n",
        "HTTP/1.1 404 The specified blob does not exist.\r\nContent-Length: 215\r\nx-ms-error-code: BlobNotFound\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
    });
    defer server.deinit(io);
    server.per_connection = 4;
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    // A limit, so a transport that waits for the body fails the test
    // rather than hanging it.
    const props = try ht.transport().send(.{ .method = .HEAD, .url = server.url(&buf, "/c/b"), .timeout_ms = 5000 }, arena.allocator());
    try testing.expectEqual(200, props.status);
    try testing.expectEqualStrings("", props.body);
    try testing.expectEqualStrings("1048576", props.header("content-length").?);
    try testing.expectEqualStrings("w1", props.header("x-ms-meta-token").?);

    const missing = try ht.transport().send(.{ .method = .HEAD, .url = server.url(&buf, "/c/gone"), .timeout_ms = 5000 }, arena.allocator());
    try testing.expectEqual(404, missing.status);
    try testing.expectEqualStrings("", missing.body);
    try testing.expectEqualStrings("BlobNotFound", missing.header("x-ms-error-code").?);

    // Through the streaming entry, with a writer sink: nothing reaches it,
    // and the head is still handed out.
    var sink_buf: [16]u8 = undefined;
    var sink: std.Io.Writer = .fixed(&sink_buf);
    var head: ?StreamRequest.Head = null;
    const streamed = try ht.transport().sendStream(.{
        .method = .HEAD,
        .url = server.url(&buf, "/c/b"),
        .sink = .{ .writer = &sink },
        .accept_encoding = .compressed,
        .head_out = &head,
        .timeout_ms = 5000,
    }, arena.allocator());
    try testing.expectEqual(200, streamed.status);
    try testing.expectEqual(0, streamed.bytes_streamed);
    try testing.expectEqual(0, sink.end);
    try testing.expectEqualStrings("gzip", head.?.header("content-encoding").?);

    const next = try ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/c/x"), .timeout_ms = 5000 }, arena.allocator());
    try testing.expectEqualStrings("{}", next.body);
    try serving.await(io);
    try testing.expectEqual(1, server.connections);

    // A HEAD goes with no body, so with no Content-Length or Content-Type
    // (std writes both names in lower case).
    try testing.expect(std.mem.startsWith(u8, server.request(0), "HEAD /c/b HTTP/1.1\r\n"));
    try testing.expect(std.mem.find(u8, server.request(0), "content-length:") == null);
    try testing.expect(std.mem.find(u8, server.request(0), "content-type:") == null);
    try testing.expect(std.mem.startsWith(u8, server.request(2), "HEAD /c/b HTTP/1.1\r\n"));
}

test "HttpTransport: a rejected response head returns at once" {
    const io = testing.io;
    // Regression: std.http read the rest of the stream before giving the
    // connection back, blocking until the server closed it.
    var server: ScriptedServer = try .start(io, &.{"HTTP/1.1 200 OK\r\nContent-Encoding: br\r\n\r\nbrotli..."});
    defer server.deinit(io);
    server.linger_ms = 3000;
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    const started = std.Io.Clock.awake.now(io);
    try testing.expectError(
        error.HttpProtocolError,
        ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/a") }, arena.allocator()),
    );
    try testing.expect(started.untilNow(io, .awake).toMilliseconds() < 1500);
}

/// `data` compressed in `container`'s framing, in `arena`.
fn compressedForTest(arena: Allocator, container: flate.Container, data: []const u8) ![]u8 {
    // std's compressor needs a writer with a buffer of its own.
    var out: std.Io.Writer.Allocating = try .initCapacity(arena, 64);
    var window: [flate.max_window_len]u8 = undefined;
    var c: flate.Compress = try .init(&out.writer, &window, container, .default);
    try c.writer.writeAll(data);
    try c.finish();
    return out.toOwnedSlice();
}

test "HttpTransport refuses a compressed body that does not match its trailer, buffered or streamed" {
    const io = testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const data = "{\"name\":\"projects/p/topics/t\",\"labels\":{}}";
    const gzip = try compressedForTest(arena, .gzip, data);
    const zlib = try compressedForTest(arena, .zlib, data);
    // The gzip trailer is its CRC-32, then its length; zlib's is Adler-32.
    const Spoil = struct { body: []const u8, encoding: []const u8, at: usize };
    const spoils = [_]Spoil{
        .{ .body = gzip, .encoding = "gzip", .at = gzip.len - 8 },
        .{ .body = gzip, .encoding = "gzip", .at = gzip.len - 4 },
        .{ .body = zlib, .encoding = "deflate", .at = zlib.len - 1 },
    };
    for (spoils) |spoil| {
        const bad = try arena.dupe(u8, spoil.body);
        bad[spoil.at] ^= 0xff;
        for ([_]bool{ false, true }) |streamed| {
            const reply = try std.fmt.allocPrint(arena, "HTTP/1.1 200 OK\r\nContent-Encoding: {s}\r\nContent-Length: {d}\r\n\r\n{s}", .{ spoil.encoding, bad.len, bad });
            var server: ScriptedServer = try .start(io, &.{reply});
            defer server.deinit(io);
            var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
            defer _ = serving.cancel(io) catch {};
            var ht: HttpTransport = .init(testing.allocator, io, "t");
            defer ht.deinit();
            var buf: [128]u8 = undefined;
            var out_buf: [256]u8 = undefined;
            var out: std.Io.Writer = .fixed(&out_buf);
            const outcome = ht.transport().sendStream(.{
                .method = .GET,
                .url = server.url(&buf, "/p"),
                .accept_encoding = .compressed,
                .sink = if (streamed) StreamRequest.Sink{ .writer = &out } else .buffer,
            }, arena);
            try testing.expectError(error.HttpProtocolError, outcome);
        }
    }
    // Unspoiled, both decode, buffered and streamed.
    for ([_][2][]const u8{ .{ gzip, "gzip" }, .{ zlib, "deflate" } }) |good| {
        for ([_]bool{ false, true }) |streamed| {
            const reply = try std.fmt.allocPrint(arena, "HTTP/1.1 200 OK\r\nContent-Encoding: {s}\r\nContent-Length: {d}\r\n\r\n{s}", .{ good[1], good[0].len, good[0] });
            var server: ScriptedServer = try .start(io, &.{reply});
            defer server.deinit(io);
            var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
            defer _ = serving.cancel(io) catch {};
            var ht: HttpTransport = .init(testing.allocator, io, "t");
            defer ht.deinit();
            var buf: [128]u8 = undefined;
            var out_buf: [256]u8 = undefined;
            var out: std.Io.Writer = .fixed(&out_buf);
            const res = try ht.transport().sendStream(.{
                .method = .GET,
                .url = server.url(&buf, "/p"),
                .accept_encoding = .compressed,
                .sink = if (streamed) StreamRequest.Sink{ .writer = &out } else .buffer,
            }, arena);
            try testing.expectEqualStrings(data, if (streamed) out.buffered() else res.body);
        }
    }
}

test "HttpTransport refuses a compressed body with content after its stream, never cutting it short" {
    const io = testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const first = try compressedForTest(arena, .gzip, "first member, ");
    const second = try compressedForTest(arena, .gzip, "second member");
    const two_members = try std.mem.concat(arena, u8, &.{ first, second });
    const zlib = try compressedForTest(arena, .zlib, "one stream");
    const trailing = try std.mem.concat(arena, u8, &.{ zlib, "garbage" });
    for ([_][2][]const u8{ .{ two_members, "gzip" }, .{ trailing, "deflate" } }) |case| {
        for ([_]bool{ false, true }) |chunked| {
            for ([_]bool{ false, true }) |streamed| {
                const reply = if (chunked)
                    try std.fmt.allocPrint(arena, "HTTP/1.1 200 OK\r\nContent-Encoding: {s}\r\nTransfer-Encoding: chunked\r\n\r\n{x}\r\n{s}\r\n0\r\n\r\n", .{ case[1], case[0].len, case[0] })
                else
                    try std.fmt.allocPrint(arena, "HTTP/1.1 200 OK\r\nContent-Encoding: {s}\r\nContent-Length: {d}\r\n\r\n{s}", .{ case[1], case[0].len, case[0] });
                var server: ScriptedServer = try .start(io, &.{reply});
                defer server.deinit(io);
                var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
                defer _ = serving.cancel(io) catch {};
                var ht: HttpTransport = .init(testing.allocator, io, "t");
                defer ht.deinit();
                var buf: [128]u8 = undefined;
                var out_buf: [256]u8 = undefined;
                var out: std.Io.Writer = .fixed(&out_buf);
                try testing.expectError(error.HttpProtocolError, ht.transport().sendStream(.{
                    .method = .GET,
                    .url = server.url(&buf, "/p"),
                    .accept_encoding = .compressed,
                    .sink = if (streamed) StreamRequest.Sink{ .writer = &out } else .buffer,
                }, arena));
            }
        }
    }
}

test "HttpTransport: a gzip body cut short is a dropped connection; a corrupt one is not" {
    const io = testing.io;
    const gzip_head = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\xabV*\xc9/\xc8L.V\xb2\x8a\xaeV\xcaK\xccMU\xb2R";
    var server: ScriptedServer = try .start(io, &.{
        // Content-Length promises more than arrives before the close.
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 200\r\n\r\n" ++ gzip_head,
        // Complete framing, but not a gzip stream.
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 10\r\n\r\nnot gzip!!",
    });
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    try testing.expectError(
        error.ConnectionResetByPeer,
        ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/a") }, arena.allocator()),
    );
    try testing.expectError(
        error.HttpProtocolError,
        ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/b") }, arena.allocator()),
    );
}

test "HttpTransport: an informational response is returned as it is" {
    const io = testing.io;
    // A 1xx precedes the real response. This client does not wait for it,
    // and does not reuse the connection; the next request still works.
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
    });
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    const early = try ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/a") }, arena.allocator());
    try testing.expectEqual(103, early.status);
    try testing.expectEqualStrings("", early.body);
    const next = try ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/b") }, arena.allocator());
    try testing.expectEqual(200, next.status);
    try testing.expectEqualStrings("{}", next.body);
    try serving.await(io);
}

test "HttpTransport decodes deflate, and refuses encodings it did not ask for" {
    const io = testing.io;
    // std sends `accept-encoding: gzip, deflate`, but a proxy may send
    // anything. HTTP's deflate is zlib-wrapped.
    const deflate = "\x78\xda\xab\x56\xca\xcf\x56\xb2\x2a\x29\x2a\x4d\xad\x05\x00\x16\xe3\x04\x11";
    const zstd = "\x28\xb5\x2f\xfd\x20\x0b\x59\x00\x00\x7b\x22\x6f\x6b\x22\x3a\x74\x72\x75\x65\x7d";
    var server: ScriptedServer = try .start(io, &.{
        std.fmt.comptimePrint("HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\nContent-Length: {d}\r\n\r\n", .{deflate.len}) ++ deflate,
        std.fmt.comptimePrint("HTTP/1.1 200 OK\r\nContent-Encoding: zstd\r\nContent-Length: {d}\r\n\r\n", .{zstd.len}) ++ zstd,
        "HTTP/1.1 200 OK\r\nContent-Encoding: compress\r\nContent-Length: 4\r\n\r\nabcd",
    });
    // deflate and zstd share the first connection, which the client keeps
    // after a whole body. A refused encoding leaves its body unread, so the
    // client closes that connection and compress needs a new one.
    server.per_connection = 2;
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    const res = try ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/deflate") }, arena.allocator());
    try testing.expectEqualStrings("{\"ok\":true}", res.body);
    for ([_][]const u8{ "/zstd", "/compress" }) |path| {
        try testing.expectError(
            error.HttpProtocolError,
            ht.transport().send(.{ .method = .GET, .url = server.url(&buf, path) }, arena.allocator()),
        );
    }
    try serving.await(io);
}

test "HttpTransport: chunked framing cut after a whole gzip stream is a dropped connection" {
    const io = testing.io;
    // The gzip stream decodes completely, but the terminating chunk never
    // arrives: the body cannot be known to be whole.
    const gzip = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x03\xab\x56\xca\xcf\x56\xb2\x2a\x29\x2a\x4d\xad\x05\x00\x90\x5f\xd4\xa7\x0b\x00\x00\x00";
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n1f\r\n" ++ gzip ++ "\r\n",
    });
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    try testing.expectError(
        error.ConnectionResetByPeer,
        ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/") }, arena.allocator()),
    );
    try serving.await(io);
}

test "HttpTransport: a chunk-size line longer than the read buffer is a protocol error" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;" ++ test_util.repeat("x", 16384) ++ "\r\nhello\r\n0\r\n\r\n",
    });
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    try testing.expectError(
        error.HttpProtocolError,
        ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/") }, arena.allocator()),
    );
}

test "HttpTransport: a failed TLS handshake forgets the TLS clock" {
    if (HttpClient.disable_tls) return error.SkipZigTest;
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{});
    defer server.deinit(io);
    server.close_on_accept = true;
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    // A fresh clock reading, so the request skips the CA bundle scan.
    ht.client.now = std.Io.Clock.real.now(io);
    var buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&buf, "https://127.0.0.1:{d}/v1/x", .{server.port});
    // The server hangs up mid-handshake: a TLS failure, which is retried,
    // and which forgets the clock. On every platform since Zig 0.17.1:
    // 0.17.0 on Windows left the hang-up's status (STATUS_LOCAL_DISCONNECT)
    // unmapped, and std's TLS connect passes error.Unexpected through
    // rather than calling it a TLS failure.
    try testing.expectError(error.TlsFailure, ht.transport().send(.{ .method = .GET, .url = url }, arena.allocator()));
    try testing.expectEqual(null, ht.client.now);
}

test "HttpTransport: a TLS clock older than an hour is reloaded" {
    if (HttpClient.disable_tls) return error.SkipZigTest;
    var ht: HttpTransport = .init(testing.allocator, testing.io, "t");
    defer ht.deinit();
    const now = std.Io.Clock.real.now(testing.io);
    ht.client.now = now;
    ht.expireTlsClock(.when_stale);
    try testing.expectEqual(now, ht.client.now.?);
    ht.client.now = now.subDuration(.fromSeconds(2 * 60 * 60));
    ht.expireTlsClock(.when_stale);
    try testing.expectEqual(null, ht.client.now);
    // A clock that ran backwards is not trusted either.
    ht.client.now = now.addDuration(.fromSeconds(60));
    ht.expireTlsClock(.when_stale);
    try testing.expectEqual(null, ht.client.now);
}

fn dechunk(gpa: Allocator, input: []const u8, max_chunk: u64) !struct { []u8, []const u8 } {
    var in: std.Io.Reader = .fixed(input);
    var buffer: [64]u8 = undefined;
    var d: Dechunker = .init(&in, &buffer, max_chunk);
    const out = d.interface.allocRemaining(gpa, .unlimited) catch |err| switch (err) {
        error.ReadFailed => return d.err orelse error.TestUnexpectedReadFailure,
        else => |e| return e,
    };
    if (!d.done()) {
        gpa.free(out);
        return error.TestNotDone;
    }
    return .{ out, in.buffered() };
}

test "Dechunker: chunks, extensions, trailers, and nothing read past the end" {
    const gpa = testing.allocator;
    const out, const rest = try dechunk(gpa, "4;name=value\r\nWiki\r\n5 \r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\nExpires: never\r\n\r\nHTTP/1.1 200 OK", 1024);
    defer gpa.free(out);
    try testing.expectEqualStrings("Wikipedia in\r\n\r\nchunks.", out);
    // The next response on the connection is untouched.
    try testing.expectEqualStrings("HTTP/1.1 200 OK", rest);

    const empty, _ = try dechunk(gpa, "0\r\n\r\n", 1024);
    defer gpa.free(empty);
    try testing.expectEqualStrings("", empty);
    const bare_lf, _ = try dechunk(gpa, "2\nhi\r\n0\n\n", 1024);
    defer gpa.free(bare_lf);
    try testing.expectEqualStrings("hi", bare_lf);
}

test "Dechunker: framing errors" {
    const gpa = testing.allocator;
    const cases = [_]struct { []const u8, anyerror }{
        .{ "zz\r\nnope", error.HttpProtocolError },
        .{ "\r\n", error.HttpProtocolError },
        .{ "-1\r\n", error.HttpProtocolError },
        .{ "4x\r\nabcd\r\n0\r\n\r\n", error.HttpProtocolError },
        .{ "3\r\nabcXY0\r\n\r\n", error.HttpProtocolError },
        .{ "401\r\n", error.ResponseTooLarge },
        .{ "ffffffffffffffff\r\nx", error.ResponseTooLarge },
        .{ "fffffffffffffffffffff\r\n", error.ResponseTooLarge },
        .{ "", error.ConnectionResetByPeer },
        .{ "5\r\nab", error.ConnectionResetByPeer },
        .{ "2\r\nab", error.ConnectionResetByPeer },
        .{ "2\r\nab\r\n0\r\n", error.ConnectionResetByPeer },
        .{ "2\r\nab\r\n0\r\nTrailer: x\r\n", error.ConnectionResetByPeer },
    };
    for (cases) |c| {
        if (dechunk(gpa, c[0], 1024)) |result| {
            gpa.free(result[0]);
            std.debug.print("accepted {s}\n", .{c[0]});
            return error.TestUnexpectedSuccess;
        } else |err| try testing.expectEqual(c[1], err);
    }
    // Endless trailers are cut off.
    const trailers = "0\r\n" ++ test_util.repeat("X-Trailer: yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy\r\n", 400) ++ "\r\n";
    try testing.expectError(error.HttpProtocolError, dechunk(gpa, trailers, 1024));
}

fn dechunkRoundTrip(_: void, input: []const u8) !void {
    const gpa = testing.allocator;
    var g: test_util.ByteGen = .init(input);
    const data = g.slice(600);
    // Encode `data` in random-sized chunks with random extensions, hex case,
    // leading zeros and trailers, followed by the next response's bytes.
    var encoded: std.Io.Writer.Allocating = .init(gpa);
    defer encoded.deinit();
    const w = &encoded.writer;
    var pos: usize = 0;
    while (pos < data.len) {
        const n = @min(data.len - pos, g.intRange(usize, 1, 64));
        for (0..g.intRange(usize, 0, 2)) |_| try w.writeByte('0');
        if (g.boolean()) try w.print("{x}", .{n}) else try w.print("{X}", .{n});
        if (g.boolean()) try w.writeAll(";ext=\"v\"");
        try w.writeAll("\r\n");
        try w.writeAll(data[pos..][0..n]);
        try w.writeAll("\r\n");
        pos += n;
    }
    try w.writeAll("0\r\n");
    if (g.boolean()) try w.writeAll("Trailer: value\r\n");
    try w.writeAll("\r\n");
    const whole = encoded.written().len;
    try w.writeAll("NEXT");

    const out, const rest = try dechunk(gpa, encoded.written(), 1024);
    defer gpa.free(out);
    try testing.expectEqualSlices(u8, data, out);
    try testing.expectEqualStrings("NEXT", rest);

    // Every strict prefix is a dropped connection, never a short success.
    const cut = g.intRange(usize, 0, whole - 1);
    try testing.expectError(error.ConnectionResetByPeer, dechunk(gpa, encoded.written()[0..cut], 1024));
}

test "Dechunker: the destination failing is WriteFailed, not a framing error" {
    var in: std.Io.Reader = .fixed("5\r\nhello\r\n0\r\n\r\n");
    var buffer: [64]u8 = undefined;
    var d: Dechunker = .init(&in, &buffer, 1024);
    const Failing = struct {
        fn drain(_: *std.Io.Writer, _: []const []const u8, _: usize) std.Io.Writer.Error!usize {
            return error.WriteFailed;
        }
    };
    var out: std.Io.Writer = .{ .buffer = &.{}, .vtable = &.{ .drain = Failing.drain } };
    try testing.expectError(error.WriteFailed, d.interface.stream(&out, .unlimited));
    // The caller's side failed, not the connection: nothing recorded.
    try testing.expectEqual(null, d.err);
}

test "ForwardWriter forwards every slice of a vectored write" {
    var list: std.Io.Writer.Allocating = .init(testing.allocator);
    defer list.deinit();
    var forward: ForwardWriter = .init(&list.writer, &.{});
    var pieces = [_][]const u8{ "one,", "two,", "three" };
    try forward.writer.writeVecAll(&pieces);
    try forward.writer.flush();
    try testing.expectEqualStrings("one,two,three", list.written());
}

test "fuzz Dechunker: encoded data decodes exactly; every prefix is a dropped connection" {
    try test_util.fuzzBytes({}, dechunkRoundTrip, .{ .corpus = &.{
        "\x00\x05hello\x00\x03\x01",
        "",
        "\x00\x40" ++ test_util.repeat("0123456789abcdef", 4) ++ "\x07\x01\x00\x01",
    } });
}

fn dechunkArbitrary(_: void, input: []const u8) !void {
    const gpa = testing.allocator;
    const out, _ = dechunk(gpa, input, 256) catch |err| switch (err) {
        error.HttpProtocolError, error.ResponseTooLarge, error.ConnectionResetByPeer => return,
        else => return err,
    };
    gpa.free(out);
}

test "fuzz Dechunker: arbitrary input never crashes" {
    try test_util.fuzzBytes({}, dechunkArbitrary, .{ .corpus = &.{
        "ffffffffffffffff\r\nx",
        "1;\r\na\r\n0\r\n\r\n",
        "10\r\n0123456789abcdef\r\n0\r\nA: b\r\n\r\n",
        "0\n\n",
    } });
}

test "HttpTransport does not follow redirects" {
    const io = testing.io;
    // A redirect could carry the request, Authorization header and all, to
    // another host. The response comes back as it is and nothing follows it.
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 302 Found\r\nLocation: http://attacker.invalid/steal\r\nContent-Length: 0\r\n\r\n",
    });
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    const res = try ht.transport().send(.{
        .method = .GET,
        .url = server.url(&buf, "/v1/projects/p/topics/t"),
        .bearer = "secret-token",
    }, arena.allocator());
    try testing.expectEqual(302, res.status);
    try serving.await(io);
    try testing.expectEqual(1, server.connections);
}

test "HttpTransport enforces the response size limit" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789",
        "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n0123456789A",
    });
    defer server.deinit(io);
    server.per_connection = 2;
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    ht.max_response_bytes = 10;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;

    const at_limit = try ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/a") }, arena.allocator());
    try testing.expectEqualStrings("0123456789", at_limit.body);
    try testing.expectError(
        error.ResponseTooLarge,
        ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/b") }, arena.allocator()),
    );
}

test "HttpTransport maps a refused connection" {
    const io = testing.io;
    // Bind a port, then close it so nothing listens there.
    var server: ScriptedServer = try .start(io, &.{});
    const port = server.port;
    server.deinit(io);

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&buf, "http://127.0.0.1:{d}/v1/x", .{port});
    // Zig 0.16 on Windows reported this as error.Unexpected, which mapError
    // calls a dropped connection; Zig 0.17 maps it everywhere.
    try testing.expectError(error.ConnectionRefused, ht.transport().send(.{ .method = .GET, .url = url }, arena.allocator()));
}

test "mapError: an unmapped socket status is a dropped connection on Windows, and anywhere while connecting" {
    // Regression: CI on Windows showed a refused connection and a hang-up
    // arriving as error.Unexpected, which was a permanent NetworkFailure, so
    // neither was retried.
    const expected: Error = if (builtin.target.os.tag == .windows) error.ConnectionResetByPeer else error.NetworkFailure;
    try testing.expectEqual(expected, mapError(error.Unexpected, null));
    // Regression (t79): on macOS a signal in a blocking connect makes std
    // try again and get EISCONN, error.Unexpected in a release build (seen
    // on Zig 0.17.1, Codeberg ziglang/zig#31391), which was a permanent
    // NetworkFailure off Windows though nothing had been sent.
    try testing.expectEqual(error.ConnectionResetByPeer, mapConnectError(error.Unexpected));
    // Every other failure in connecting maps as it does after.
    try testing.expectEqual(error.ConnectionRefused, mapConnectError(error.ConnectionRefused));
    try testing.expectEqual(error.NameServerFailure, mapConnectError(error.ResolvConfParseFailed));
    try testing.expectEqual(error.NetworkFailure, mapConnectError(error.SystemResources));
}

test "HttpTransport refuses, before connecting, a URL that would go out other than as written" {
    var ht: HttpTransport = .init(testing.allocator, testing.io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const t = ht.transport();
    // Port 9 (discard) on loopback: nothing connects in these tests, since
    // each URL is refused first.
    for ([_][]const u8{
        "http://127.0.0.1:9/a\r\nX-Injected: y",
        "http://127.0.0.1:9/a\nb",
        "http://127.0.0.1:9/a b",
        "http://127.0.0.1:9/a\tb",
        "http://127.0.0.1:9/a\\b",
        "http://127.0.0.1:9/a\x00b",
        "http://127.0.0.1:9/a\x7fb",
        "http://user:pw@127.0.0.1:9/p",
        "http://user@127.0.0.1:9/p",
        "http://127.0.0.%31:9/p",
        "http://[::1%25lo0]:9/p",
    }) |url| {
        try testing.expectError(error.InvalidEndpoint, t.send(.{ .method = .GET, .url = url }, arena.allocator()));
    }
}

test "HttpTransport refuses, before connecting, a header the transport owns" {
    var ht: HttpTransport = .init(testing.allocator, testing.io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const t = ht.transport();
    const url = "http://127.0.0.1:9/p";
    for ([_][]const u8{ "Host", "content-length", "Transfer-Encoding", "Connection", "Keep-Alive", "TE", "Trailer", "Upgrade", "Proxy-Connection", "Accept-Encoding" }) |name| {
        try testing.expectError(error.InvalidRequestHeader, t.send(.{ .method = .POST, .url = url, .body = "{}", .headers = &.{.{ .name = name, .value = "x" }} }, arena.allocator()));
    }
    // A second Authorization beside the bearer token, and a second
    // Content-Type beside the body's.
    try testing.expectError(error.InvalidRequestHeader, t.send(.{ .method = .GET, .url = url, .bearer = "tok", .headers = &.{.{ .name = "Authorization", .value = "Bearer other" }} }, arena.allocator()));
    try testing.expectError(error.InvalidRequestHeader, t.send(.{ .method = .POST, .url = url, .body = "{}", .headers = &.{.{ .name = "content-type", .value = "text/plain" }} }, arena.allocator()));
}

test "HttpTransport refuses, before connecting, a bearer token that would end the line" {
    var ht: HttpTransport = .init(testing.allocator, testing.io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    // std.http wrote `authorization: Bearer tok`, then `X-Injected: y`, as
    // a header of its own (probed on Zig 0.17.1).
    for ([_][]const u8{ "tok\r\nX-Injected: y", "tok\n", "", "a b", "t\xc3\xa9" }) |token| {
        try testing.expectError(error.InvalidRequestHeader, ht.transport().send(.{ .method = .GET, .url = "http://127.0.0.1:9/p", .bearer = token }, arena.allocator()));
    }
}

test "HttpTransport sends an Authorization of the caller's own when there is no bearer token" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"});
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};
    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    // A scheme other than Bearer, as Azure Storage's SharedKey is.
    _ = try ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/c/b"), .headers = &.{.{ .name = "Authorization", .value = "SharedKey account:c2ln" }} }, arena.allocator());
    try expectHeader(server.seen[0][0..server.seen_len[0]], "Authorization: SharedKey account:c2ln\r\n");
}

test "HttpTransport refuses a response framed two ways, or with a length that is not digits, and drops the connection" {
    const io = testing.io;
    for ([_][]const u8{
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n2\r\nhi\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\nhi",
        "HTTP/1.1 200 OK\r\nContent-Length: 0x2\r\n\r\nhi",
    }) |reply| {
        // The refused response, then one the next request would read on a
        // reused connection.
        var server: ScriptedServer = try .start(io, &.{ reply, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" });
        defer server.deinit(io);
        server.per_connection = 2;
        var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
        defer _ = serving.cancel(io) catch {};
        var ht: HttpTransport = .init(testing.allocator, io, "t");
        defer ht.deinit();
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        var buf: [128]u8 = undefined;
        try testing.expectError(error.HttpProtocolError, ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/p") }, arena.allocator()));
    }
    // Two equal lengths are one length (RFC 9110 8.6), and plain digits with
    // the spaces a field value may carry are read as ever.
    for ([_][]const u8{ "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nhi", "HTTP/1.1 200 OK\r\nContent-Length:  2 \r\n\r\nhi" }) |reply| {
        var server: ScriptedServer = try .start(io, &.{reply});
        defer server.deinit(io);
        var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
        defer _ = serving.cancel(io) catch {};
        var ht: HttpTransport = .init(testing.allocator, io, "t");
        defer ht.deinit();
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        var buf: [128]u8 = undefined;
        try testing.expectEqualStrings("hi", (try ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/p") }, arena.allocator())).body);
    }
}

test "HttpTransport rejects unusable URLs without panicking" {
    var ht: HttpTransport = .init(testing.allocator, testing.io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const t = ht.transport();
    try testing.expectError(error.InvalidEndpoint, t.send(.{ .method = .GET, .url = "not a url" }, arena.allocator()));
    try testing.expectError(error.InvalidEndpoint, t.send(.{ .method = .GET, .url = "ftp://h/x" }, arena.allocator()));
    // A PUT with no body still sends a well-formed request line; it fails at connect here.
    try testing.expectError(error.InvalidEndpoint, t.send(.{ .method = .PUT, .url = "gopher://h" }, arena.allocator()));
}

test "sendStream uploads from a reader with an exact Content-Length" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
    });
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;

    // Larger than the server's record slot: the body is checked by checksum.
    var data: [8000]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i % 251);
    var reader: std.Io.Reader = .fixed(&data);
    const res = try ht.transport().sendStream(.{
        .method = .PUT,
        .url = server.url(&buf, "/upload/storage/v1/b/b/o"),
        .bearer = "tok-stream",
        .content_type = "application/octet-stream",
        .body = .{ .stream = .{ .reader = &reader, .len = data.len } },
    }, arena.allocator());
    try testing.expectEqual(200, res.status);
    try testing.expectEqualStrings("{}", res.body);
    try testing.expectEqual(0, res.bytes_streamed);
    try serving.await(io);

    const put = server.request(0);
    try testing.expect(std.mem.startsWith(u8, put, "PUT /upload/storage/v1/b/b/o HTTP/1.1\r\n"));
    try expectHeader(put, "content-length: 8000\r\n");
    try expectHeader(put, "content-type: application/octet-stream\r\n");
    try expectHeader(put, "authorization: Bearer tok-stream\r\n");
    try testing.expectEqual(8000, server.seen_body_len[0]);
    try testing.expectEqual(BodyHash.hash(&data), server.seen_body_crc[0]);
}

test "sendStream sends segments back to back as one body" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
    });
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;

    // A multipart/related shape: framing, caller data, closing framing.
    const framing = "--b\r\nContent-Type: application/json\r\n\r\n{\"name\":\"x\"}\r\n--b\r\nContent-Type: text/plain\r\n\r\n";
    const data = "hello world\n";
    const closing = "\r\n--b--\r\n";
    const res = try ht.transport().sendStream(.{
        .method = .POST,
        .url = server.url(&buf, "/upload/storage/v1/b/b/o?uploadType=multipart"),
        .content_type = "multipart/related; boundary=b",
        .body = .{ .segments = &.{ framing, data, closing } },
    }, arena.allocator());
    try testing.expectEqual(200, res.status);
    try serving.await(io);

    const post = server.request(0);
    var length_line: [64]u8 = undefined;
    try expectHeader(post, try std.fmt.bufPrint(&length_line, "content-length: {d}\r\n", .{framing.len + data.len + closing.len}));
    try expectHeader(post, "content-type: multipart/related; boundary=b\r\n");
    try testing.expect(std.mem.endsWith(u8, post, "\r\n\r\n" ++ framing ++ data ++ closing));
}

test "sendStream: empty segments send Content-Length: 0, as a status query needs" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 308 Permanent Redirect\r\nRange: bytes=0-1023\r\nContent-Length: 0\r\n\r\n",
    });
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    const res = try ht.transport().sendStream(.{
        .method = .PUT,
        .url = server.url(&buf, "/session"),
        .headers = &.{.{ .name = "Content-Range", .value = "bytes */20000000" }},
        .body = .{ .segments = &.{} },
    }, arena.allocator());
    // 308 is how a resumable upload answers: returned untouched, never
    // followed as a redirect, with its headers readable.
    try testing.expectEqual(308, res.status);
    try testing.expectEqualStrings("bytes=0-1023", res.header("Range").?);
    try serving.await(io);
    try testing.expectEqual(1, server.connections);
    try expectHeader(server.request(0), "content-length: 0\r\n");
    try expectHeader(server.request(0), "Content-Range: bytes */20000000\r\n");
}

test "sendStream: a reader that ends before its declared length is EndOfStream" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
    });
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    var reader: std.Io.Reader = .fixed("only ten b");
    try testing.expectError(error.EndOfStream, ht.transport().sendStream(.{
        .method = .PUT,
        .url = server.url(&buf, "/session"),
        .body = .{ .stream = .{ .reader = &reader, .len = 100 } },
    }, arena.allocator()));
}

test "sendStream downloads into a writer, with headers readable" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 200 OK\r\nx-goog-hash: crc32c=8P9ykg==\r\nx-goog-generation: 175\r\n" ++
            "Content-Length: 12\r\n\r\nhello world\n",
    });
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    var out_buf: [64]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    const res = try ht.transport().sendStream(.{
        .method = .GET,
        .url = server.url(&buf, "/storage/v1/b/b/o/x?alt=media"),
        .sink = .{ .writer = &out },
    }, arena.allocator());
    try testing.expectEqual(200, res.status);
    // The body went to the writer, not the arena.
    try testing.expectEqualStrings("", res.body);
    try testing.expectEqual(12, res.bytes_streamed);
    try testing.expectEqualStrings("hello world\n", out.buffered());
    try testing.expectEqualStrings("crc32c=8P9ykg==", res.header("x-goog-hash").?);
    try testing.expectEqualStrings("175", res.header("x-goog-generation").?);
    try serving.await(io);
    // The plain-bytes request asked for plain bytes.
    try expectHeader(server.request(0), "accept-encoding: identity\r\n");
}

test "sendStream streams a chunked body and keeps the connection" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
    });
    defer server.deinit(io);
    server.per_connection = 2;
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    var out_buf: [64]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    const res = try ht.transport().sendStream(.{
        .method = .GET,
        .url = server.url(&buf, "/a"),
        .sink = .{ .writer = &out },
    }, arena.allocator());
    try testing.expectEqualStrings("{\"a\":1}", out.buffered());
    try testing.expectEqual(7, res.bytes_streamed);

    const next = try ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/b") }, arena.allocator());
    try testing.expectEqualStrings("{}", next.body);
    try serving.await(io);
    try testing.expectEqual(1, server.connections);
}

test "sendStream: a POST with no body sends an empty one" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"});
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};
    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    const res = try ht.transport().sendStream(.{ .method = .POST, .url = server.url(&buf, "/v1/x:run") }, arena.allocator());
    try testing.expectEqualStrings("{}", res.body);
    try serving.await(io);
    try expectHeader(server.request(0), "content-length: 0\r\n");
}

test "sendStream hands each piece to the writer as it arrives, not when more comes" {
    // A streamed answer's messages are handed on as they arrive, as
    // Firestore's are: a short one must not wait in a buffer for the next.
    const io = testing.io;
    var open: std.atomic.Value(bool) = .init(false);
    const head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n[{}\n\r\n";
    var server: ScriptedServer = try .start(io, &.{head ++ "2\r\n]\n\r\n0\r\n\r\n"});
    defer server.deinit(io);
    server.pause = .{ .after = head.len, .open = &open };
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    // Opens the server's pause once the first piece has arrived.
    const Watch = struct {
        open: *std.atomic.Value(bool),
        got: std.ArrayList(u8) = .empty,
        writer: std.Io.Writer = .{ .buffer = &.{}, .vtable = &.{ .drain = drain } },

        fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
            const self: *@This() = @alignCast(@fieldParentPtr("writer", w));
            var n: usize = 0;
            for (data[0 .. data.len - 1]) |d| {
                self.got.appendSlice(testing.allocator, d) catch return error.WriteFailed;
                n += d.len;
            }
            for (0..splat) |_| {
                self.got.appendSlice(testing.allocator, data[data.len - 1]) catch return error.WriteFailed;
                n += data[data.len - 1].len;
            }
            if (std.mem.find(u8, self.got.items, "[{}") != null) self.open.store(true, .release);
            return n;
        }
    };
    var watch: Watch = .{ .open = &open };
    defer watch.got.deinit(testing.allocator);
    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    _ = try ht.transport().sendStream(.{
        .method = .GET,
        .url = server.url(&buf, "/v1/o?alt=media"),
        .sink = .{ .writer = &watch.writer },
    }, arena.allocator());
    try serving.await(io);
    try testing.expectEqualStrings("[{}\n]\n", watch.got.items);
    try testing.expect(!server.pause_timed_out);
}

test "sendStream decompresses a gzip body on its way to the writer" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n" ++
            "14\x0d\x0a\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\xabV*\xc9/\xc8L.V\xb2\x0d\x0a2c\x0d\x0a\x8a\xaeV\xcaK\xccMU\xb2R*(\xca\xcfJM.)\xd6/\xd0\x87H\xeaWe\x16\x14\xa4\xa6(\xd5\xc6\xd6\x02\x00\x80\xdd\xe810\x00\x00\x00\x0d\x0a0\x0d\x0a\x0d\x0a",
    });
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    var out_buf: [128]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    const res = try ht.transport().sendStream(.{
        .method = .GET,
        .url = server.url(&buf, "/a"),
        .sink = .{ .writer = &out },
        .accept_encoding = .compressed,
    }, arena.allocator());
    const expected = "{\"topics\":[{\"name\":\"projects/p/topics/zipped\"}]}";
    try testing.expectEqualStrings(expected, out.buffered());
    try testing.expectEqual(expected.len, res.bytes_streamed);
    try serving.await(io);
    try expectHeader(server.request(0), "accept-encoding: gzip, deflate\r\n");
}

test "sendStream delivers a gzip body as sent when asked, and a plain one as it is" {
    const io = testing.io;
    const gzip_body = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\xabV*\xc9/\xc8L.V\xb2" ++
        "\x8a\xaeV\xcaK\xccMU\xb2R*(\xca\xcfJM.)\xd6/\xd0\x87H\xeaWe\x16\x14\xa4\xa6(\xd5\xc6\xd6\x02\x00\x80\xdd\xe810\x00\x00\x00";
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n" ++
            "14\x0d\x0a" ++ gzip_body[0..20] ++ "\x0d\x0a2c\x0d\x0a" ++ gzip_body[20..] ++ "\x0d\x0a0\x0d\x0a\x0d\x0a",
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nplain",
    });
    server.per_connection = 2;
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    var out_buf: [128]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    const res = try ht.transport().sendStream(.{
        .method = .GET,
        .url = server.url(&buf, "/a"),
        .sink = .{ .writer = &out },
        .accept_encoding = .gzip_as_sent,
    }, arena.allocator());
    // The bytes the server sent, gzip and all, and they are the JSON.
    try testing.expectEqualSlices(u8, gzip_body, out.buffered());
    try testing.expectEqual(gzip_body.len, res.bytes_streamed);
    try testing.expectEqualStrings("gzip", res.header("content-encoding").?);
    var in: std.Io.Reader = .fixed(out.buffered());
    var window: [flate.max_window_len]u8 = undefined;
    var inflate: flate.Decompress = .init(&in, .gzip, &window);
    var json_buf: [128]u8 = undefined;
    const json = json_buf[0..try inflate.reader.readSliceShort(&json_buf)];
    try testing.expectEqualStrings("{\"topics\":[{\"name\":\"projects/p/topics/zipped\"}]}", json);

    // A body that was never compressed comes as it is, on the same
    // connection.
    var plain_buf: [16]u8 = undefined;
    var plain: std.Io.Writer = .fixed(&plain_buf);
    _ = try ht.transport().sendStream(.{
        .method = .GET,
        .url = server.url(&buf, "/b"),
        .sink = .{ .writer = &plain },
        .accept_encoding = .gzip_as_sent,
    }, arena.allocator());
    try testing.expectEqualStrings("plain", plain.buffered());
    try serving.await(io);
    try expectHeader(server.request(0), "accept-encoding: gzip\r\n");
    try testing.expectEqual(1, server.connections);
}

test "a gzip body that ends partway is refused, never a panic: whole framing is a bad body, cut framing a drop" {
    const io = testing.io;
    // Nineteen bytes of gzip that end partway through a code, which Zig
    // 0.16's decompressor panicked on (nightly run 36230092734).
    const cut_gzip = "\x1f\x8b\x08\x00\x00\x00\x00\xb5\x33\x8e\x2d\x00\x02\x29\xbd\xfb\x54\x0f\xcc";
    var server: ScriptedServer = try .start(io, &.{
        // All the body the length promised: the body itself is bad.
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 19\r\n\r\n" ++ cut_gzip,
        // A length the connection never delivers: it dropped mid-body.
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 400\r\n\r\n" ++ cut_gzip,
    });
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    try testing.expectError(error.HttpProtocolError, ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/a") }, arena.allocator()));
    try testing.expectError(error.ConnectionResetByPeer, ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/b") }, arena.allocator()));
    try serving.await(io);
}

test "sendStream buffers an error body even when a writer was given" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 404 Not Found\r\nContent-Length: 44\r\n\r\n{\"error\":{\"code\":404,\"message\":\"no object\"}}",
    });
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    var out_buf: [64]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    const res = try ht.transport().sendStream(.{
        .method = .GET,
        .url = server.url(&buf, "/a"),
        .sink = .{ .writer = &out },
    }, arena.allocator());
    try testing.expectEqual(404, res.status);
    try testing.expectEqualStrings("{\"error\":{\"code\":404,\"message\":\"no object\"}}", res.body);
    // The caller's writer saw nothing of it.
    try testing.expectEqualStrings("", out.buffered());
    try testing.expectEqual(0, res.bytes_streamed);
}

test "sendStream: a streamed body cut short is a dropped connection, and the writer keeps what arrived" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial data",
    });
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    var out_buf: [128]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    try testing.expectError(error.ConnectionResetByPeer, ht.transport().sendStream(.{
        .method = .GET,
        .url = server.url(&buf, "/a"),
        .sink = .{ .writer = &out },
    }, arena.allocator()));
    // Delivered bytes stay delivered; a resuming download counts them
    // through its own counting writer.
    try testing.expectEqualStrings("partial data", out.buffered());
}

test "sendStream: a chunked body cut mid-chunk still flushes what arrived to the writer" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab",
    });
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    var out_buf: [64]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    // Unlike a Content-Length body, whose truncation shows as a quiet end
    // of stream after the loop, a cut inside a chunk fails the read
    // itself, and that arm must still hand over what the loop forwarded.
    try testing.expectError(error.ConnectionResetByPeer, ht.transport().sendStream(.{
        .method = .GET,
        .url = server.url(&buf, "/a"),
        .sink = .{ .writer = &out },
    }, arena.allocator()));
    try testing.expectEqualStrings("ab", out.buffered());
}

test "sendStream: the server hanging up mid-upload is a dropped connection" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{});
    defer server.deinit(io);
    server.close_on_accept = true;
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    // Big enough that the kernel cannot hold it all: the write itself has
    // to fail, not the read of an answer that never comes.
    const big = try testing.allocator.alloc(u8, 8 << 20);
    defer testing.allocator.free(big);
    @memset(big, 'x');
    var buf: [128]u8 = undefined;
    try testing.expectError(error.ConnectionResetByPeer, ht.transport().sendStream(.{
        .method = .POST,
        .url = server.url(&buf, "/up"),
        .body = .{ .segments = &.{big} },
    }, arena.allocator()));
}

test "sendStream: the head is readable even when the body is cut short" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 200 OK\r\nx-goog-generation: 42\r\nContent-Length: 100\r\n\r\npartial",
    });
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    var out_buf: [64]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var head: ?StreamRequest.Head = null;
    try testing.expectError(error.ConnectionResetByPeer, ht.transport().sendStream(.{
        .method = .GET,
        .url = server.url(&buf, "/a"),
        .sink = .{ .writer = &out },
        .head_out = &head,
    }, arena.allocator()));
    // The body failed, but the head had already been delivered whole.
    try testing.expectEqual(200, head.?.status);
    try testing.expectEqualStrings("42", head.?.header("x-goog-generation").?);
    try testing.expectEqualStrings("partial", out.buffered());

    // A connection that never answers leaves it null.
    var refused: ?StreamRequest.Head = null;
    var closed: ScriptedServer = try .start(io, &.{});
    const port = closed.port;
    closed.deinit(io);
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/a", .{port});
    _ = ht.transport().sendStream(.{
        .method = .GET,
        .url = url,
        .head_out = &refused,
    }, arena.allocator()) catch {};
    try testing.expectEqual(null, refused);
}

test "sendStream: the caller's writer failing mid-body is WriteFailed" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{
        "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nhello world\n",
    });
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    var out_buf: [4]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    try testing.expectError(error.WriteFailed, ht.transport().sendStream(.{
        .method = .GET,
        .url = server.url(&buf, "/a"),
        .sink = .{ .writer = &out },
    }, arena.allocator()));
}

test "sendStream: a large body streams into an unbuffered writer" {
    const io = testing.io;
    // Regression: a body too large for the connection's read buffer goes
    // through the readers' streaming path, which requires a writable
    // destination; a caller's unbuffered writer panicked in std.
    const gpa = testing.allocator;
    const body_len = 300 * 1024;
    const reply = try gpa.alloc(u8, 64 + body_len);
    defer gpa.free(reply);
    const head = try std.fmt.bufPrint(reply, "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\n\r\n", .{body_len});
    const payload = reply[head.len .. head.len + body_len];
    for (payload, 0..) |*b, i| b.* = @intCast(i % 251);

    var server: ScriptedServer = try .start(io, &.{reply[0 .. head.len + body_len]});
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(gpa, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    var buf: [128]u8 = undefined;

    // A writer with no buffer at all: a hasher that discards the bytes.
    var hashing: std.Io.Writer.Hashing(BodyHash) = .initHasher(.init(), &.{});
    const res = try ht.transport().sendStream(.{
        .method = .GET,
        .url = server.url(&buf, "/big"),
        .sink = .{ .writer = &hashing.writer },
    }, arena.allocator());
    try testing.expectEqual(body_len, res.bytes_streamed);
    try testing.expectEqual(BodyHash.hash(payload), hashing.hasher.final());
}

test "sendStream: a server that says nothing is TimedOut" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"});
    defer server.deinit(io);
    server.hang = true;
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    var out_buf: [64]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    const outcome = ht.transport().sendStream(.{
        .method = .GET,
        .url = server.url(&buf, "/slow"),
        .sink = .{ .writer = &out },
        .timeout_ms = 150,
    }, arena.allocator());
    // Windows may tear the idle connection down first; see the send test.
    if (builtin.target.os.tag == .windows) {
        if (outcome) |_| {} else |err| if (err == error.ConnectionResetByPeer) return error.SkipZigTest;
    }
    try testing.expectError(error.TimedOut, outcome);
}

test "a time limit the Io cannot run is ConcurrencyUnavailable, and nothing is sent" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"});
    defer server.deinit(io);
    server.hang = true;
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    // The transport's own Io can start no second task, as a single-threaded
    // one cannot.
    var threaded: std.Io.Threaded = .init(testing.allocator, .{ .concurrent_limit = .nothing });
    defer threaded.deinit();
    var ht: HttpTransport = .init(testing.allocator, threaded.io(), "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    const url = server.url(&buf, "/v1/slow");
    try testing.expectError(error.ConcurrencyUnavailable, ht.transport().send(.{ .method = .GET, .url = url, .timeout_ms = 150 }, arena.allocator()));
    var out_buf: [64]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    try testing.expectError(error.ConcurrencyUnavailable, ht.transport().sendStream(.{
        .method = .GET,
        .url = url,
        .sink = .{ .writer = &out },
        .timeout_ms = 150,
    }, arena.allocator()));
    // Neither went out untimed: the hanging server saw no request.
    try testing.expectEqual(0, server.seen_count);
}

test "with no time limit asked for, a request needs no second task" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"});
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var threaded: std.Io.Threaded = .init(testing.allocator, .{ .concurrent_limit = .nothing });
    defer threaded.deinit();
    var ht: HttpTransport = .init(testing.allocator, threaded.io(), "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    const res = try ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/v1/x") }, arena.allocator());
    try testing.expectEqual(200, res.status);
    try testing.expectEqualStrings("ok", res.body);
}

test "HttpTransport returns error.Canceled when its task is canceled" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{});
    defer server.deinit(io);
    server.hang = true;
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    const url = server.url(&buf, "/v1/projects/p/subscriptions/s:pull");

    const Call = struct {
        fn run(t: Transport, u: []const u8, a: Allocator) Error!Response {
            return t.send(.{ .method = .POST, .url = u, .body = "{}" }, a);
        }
    };
    var pending = try io.concurrent(Call.run, .{ ht.transport(), url, arena.allocator() });
    // Give the request time to reach the server, then cancel it.
    try io.sleep(.fromMilliseconds(100), .awake);
    try testing.expectError(error.Canceled, pending.cancel(io));
}

/// Sends an untimed GET whose gzip body is not gzip, with the server holding
/// the framing open before its last chunk, and cancels the call while
/// `bodyError` drains that framing. The cancel must come back as itself: as
/// the dropped connection the drain's read fails with, it would be retried.
fn expectCanceledInBodyDrain(sink: enum { buffer, writer }) !void {
    const io = testing.io;
    const head = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "20\r\n" ++ "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" ++ "\r\n";
    var open: std.atomic.Value(bool) = .init(false);
    var server: ScriptedServer = try .start(io, &.{head ++ "0\r\n\r\n"});
    defer server.deinit(io);
    server.pause = .{ .after = head.len, .open = &open };
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var discarding: std.Io.Writer.Discarding = .init(&.{});
    var buf: [128]u8 = undefined;
    const req: StreamRequest = .{
        .method = .GET,
        .url = server.url(&buf, "/v1/o?alt=media"),
        .accept_encoding = .compressed,
        .sink = switch (sink) {
            .buffer => .buffer,
            .writer => .{ .writer = &discarding.writer },
        },
    };
    const Call = struct {
        fn run(t: Transport, r: StreamRequest, a: Allocator) StreamError!StreamResponse {
            return t.sendStream(r, a);
        }
    };
    var pending = try io.concurrent(Call.run, .{ ht.transport(), req, arena.allocator() });
    // Time for the decoder to fail on the first chunk and the drain to wait.
    try io.sleep(.fromMilliseconds(300), .awake);
    const result = pending.cancel(io);
    open.store(true, .release);
    try testing.expectError(error.Canceled, result);
}

test "HttpTransport: a cancel while a bad gzip body's framing drains is Canceled, buffered" {
    try expectCanceledInBodyDrain(.buffer);
}

test "HttpTransport: a cancel while a bad gzip body's framing drains is Canceled, to a writer" {
    try expectCanceledInBodyDrain(.writer);
}

/// A gzip body in two chunks, decoding to `zipped_json`.
const zipped_head = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n";
const zipped_chunks = "14\x0d\x0a\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\xabV*\xc9/\xc8L.V\xb2\x0d\x0a2c\x0d\x0a\x8a\xaeV\xcaK\xccMU\xb2R*(\xca\xcfJM.)\xd6/\xd0\x87H\xeaWe\x16\x14\xa4\xa6(\xd5\xc6\xd6\x02\x00\x80\xdd\xe810\x00\x00\x00\x0d\x0a0\x0d\x0a\x0d\x0a";
const zipped_json = "{\"topics\":[{\"name\":\"projects/p/topics/zipped\"}]}";

/// Sends an untimed GET whose answer the server stops after `cut` bytes,
/// holding the connection open, and cancels the call while it waits for
/// the rest: it must come back Canceled, which is never retried.
fn expectCanceledMidBody(reply: []const u8, cut: usize, sink: enum { buffer, writer }) !void {
    const io = testing.io;
    var open: std.atomic.Value(bool) = .init(false);
    var server: ScriptedServer = try .start(io, &.{reply});
    defer server.deinit(io);
    server.pause = .{ .after = cut, .open = &open };
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};
    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var out_buf: [256]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var buf: [128]u8 = undefined;
    const req: StreamRequest = .{
        .method = .GET,
        .url = server.url(&buf, "/v1/o?alt=media"),
        .accept_encoding = .compressed,
        .sink = switch (sink) {
            .buffer => .buffer,
            .writer => .{ .writer = &out },
        },
    };
    const Call = struct {
        fn run(t: Transport, r: StreamRequest, a: Allocator) StreamError!StreamResponse {
            return t.sendStream(r, a);
        }
    };
    var pending = try io.concurrent(Call.run, .{ ht.transport(), req, arena.allocator() });
    try io.sleep(.fromMilliseconds(300), .awake);
    const result = pending.cancel(io);
    open.store(true, .release);
    try testing.expectError(error.Canceled, result);
}

/// Sends a GET whose answer is `reply`, the server then holding the
/// connection open for more, and expects `want` before the server's pause
/// runs out: a drain that read on would wait it out.
fn expectPromptAfterDecode(reply: []const u8, max_response_bytes: usize, want: Error) !void {
    const io = testing.io;
    var open: std.atomic.Value(bool) = .init(false);
    var server: ScriptedServer = try .start(io, &.{reply});
    defer server.deinit(io);
    server.pause = .{ .after = reply.len, .open = &open };
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};
    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    ht.max_response_bytes = max_response_bytes;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    const result = ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/v1/o") }, arena.allocator());
    open.store(true, .release);
    try testing.expectError(want, result);
    try serving.await(io);
    try testing.expect(!server.pause_timed_out);
}

test "HttpTransport: content after a gzip stream is refused at its first byte, not read to its end" {
    // A valid member, then chunks that go on: one byte is the verdict.
    const without_end = zipped_chunks[0 .. zipped_chunks.len - "0\r\n\r\n".len];
    try expectPromptAfterDecode(zipped_head ++ without_end ++ "4\r\njunk\r\n", default_max_response_bytes, error.HttpProtocolError);
}

test "HttpTransport: a body that will not decode is drained no further than the response limit" {
    const junk: [1024]u8 = @splat('y');
    const chunk = "400\r\n" ++ junk ++ "\r\n";
    const reply = zipped_head ++ "20\r\n" ++ "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" ++ "\r\n" ++ chunk ++ chunk;
    try expectPromptAfterDecode(reply, 1024, error.HttpProtocolError);
}

test "HttpTransport: a cancel mid-body is Canceled, plain or gzip, buffered or to a writer" {
    const plain = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789";
    const zipped = zipped_head ++ zipped_chunks;
    // After the first chunk of each: the head and some body are in.
    const plain_cut = plain.len - 6;
    const zipped_cut = zipped_head.len + 4 + 0x14 + 2;
    inline for (.{ .buffer, .writer }) |sink| {
        try expectCanceledMidBody(plain, plain_cut, sink);
        try expectCanceledMidBody(zipped, zipped_cut, sink);
    }
}

test "HttpTransport: a timed request whose task is canceled is Canceled, not TimedOut" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{});
    defer server.deinit(io);
    server.hang = true;
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};
    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    const Call = struct {
        fn run(t: Transport, u: []const u8, a: Allocator) Error!Response {
            return t.send(.{ .method = .GET, .url = u, .timeout_ms = 10_000 }, a);
        }
    };
    var pending = try io.concurrent(Call.run, .{ ht.transport(), server.url(&buf, "/v1/slow"), arena.allocator() });
    try io.sleep(.fromMilliseconds(100), .awake);
    try testing.expectError(error.Canceled, pending.cancel(io));
}

test "HttpTransport: memory running out anywhere in a response is OutOfMemory, and the next request works" {
    const io = testing.io;
    var fail_index: usize = 0;
    while (true) : (fail_index += 1) {
        try testing.expect(fail_index < 64);
        var server: ScriptedServer = try .start(io, &.{ zipped_head ++ zipped_chunks, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}" });
        defer server.deinit(io);
        var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
        defer _ = serving.cancel(io) catch {};
        var ht: HttpTransport = .init(testing.allocator, io, "t");
        defer ht.deinit();
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        var failing: std.testing.FailingAllocator = .init(arena.allocator(), .{ .fail_index = fail_index });
        var buf: [128]u8 = undefined;
        const first = ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/a") }, failing.allocator());
        if (!failing.has_induced_failure) {
            try testing.expectEqualStrings(zipped_json, (try first).body);
            break;
        }
        try testing.expectError(error.OutOfMemory, first);
        const next = try ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/b"), .timeout_ms = 10_000 }, arena.allocator());
        try testing.expectEqualStrings("{}", next.body);
    }
    // At least the headers, the gzip window and the body were tried.
    try testing.expect(fail_index >= 3);
}

test "HttpTransport: an Io with room for one task is ConcurrencyUnavailable, and nothing is sent" {
    // The request's task may start where the timer's cannot: it must not
    // go out then, untimed or canceled on the way.
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"});
    defer server.deinit(io);
    server.hang = true;
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};
    var threaded: std.Io.Threaded = .init(testing.allocator, .{ .concurrent_limit = .limited(1) });
    defer threaded.deinit();
    var ht: HttpTransport = .init(testing.allocator, threaded.io(), "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    try testing.expectError(error.ConcurrencyUnavailable, ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/v1/slow"), .timeout_ms = 150 }, arena.allocator()));
    try io.sleep(.fromMilliseconds(200), .awake);
    try testing.expectEqual(0, server.seen_count);
    try testing.expectEqual(0, server.connections);
}

test "HttpTransport: a body reader that fails is ReadFailed, and the next request works" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"});
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};
    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    var reader: std.Io.Reader = .failing;
    try testing.expectError(error.ReadFailed, ht.transport().sendStream(.{
        .method = .PUT,
        .url = server.url(&buf, "/v1/upload"),
        .body = .{ .stream = .{ .reader = &reader, .len = 10 } },
    }, arena.allocator()));
    const next = try ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/v1/a"), .timeout_ms = 10_000 }, arena.allocator());
    try testing.expectEqualStrings("{}", next.body);
    try serving.await(io);
    // The failed upload never reached the server as a request.
    try testing.expectEqual(1, server.seen_count);
}
