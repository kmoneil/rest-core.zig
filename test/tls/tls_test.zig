//! TLS against a real server, `openssl s_server` with certificates made for
//! the run: what the transport refuses, what a head past a TLS record does,
//! and what std's TLS client gets wrong. Each test of the last holds std to
//! its bug, so it fails once std fixes it. It needs `openssl` on the PATH
//! and a machine where a test may listen on a port: CI runs it (`zig build
//! test-tls`); `zig build test` only compiles it.

const std = @import("std");
const rest_core = @import("rest_core");
const HttpTransport = rest_core.transport.HttpTransport;
const Io = std.Io;
const testing = std.testing;

/// Runs `argv` in `dir`; a command that fails fails the test, with its
/// output.
fn run(io: Io, dir: Io.Dir, argv: []const []const u8) !void {
    const result = try std.process.run(testing.allocator, io, .{ .argv = argv, .cwd = .{ .dir = dir } });
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);
    switch (result.term) {
        .exited => |code| if (code == 0) return,
        else => {},
    }
    std.debug.print("openssl {s} failed: {s}\n", .{ argv[1], result.stderr });
    return error.CommandFailed;
}

fn fileName(buf: []u8, name: []const u8, ext: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}.{s}", .{ name, ext });
}

/// A certificate to make: `name.pem`, its key in `name.key`, signed by
/// `by` (`by.pem` and `by.key`) with the extensions in the file `ext`.
const Issue = struct {
    name: []const u8,
    subject: []const u8,
    ext: []const u8,
    by: []const u8 = "ca",
    rsa: bool = false,
};

fn issue(io: Io, dir: Io.Dir, o: Issue) !void {
    var key: [32]u8 = undefined;
    var csr: [32]u8 = undefined;
    var pem: [32]u8 = undefined;
    var by_pem: [32]u8 = undefined;
    var by_key: [32]u8 = undefined;
    const k = try fileName(&key, o.name, "key");
    const c = try fileName(&csr, o.name, "csr");
    if (o.rsa) {
        try run(io, dir, &.{ "openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", k });
    } else {
        try run(io, dir, &.{ "openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", k });
    }
    try run(io, dir, &.{ "openssl", "req", "-new", "-key", k, "-out", c, "-subj", o.subject });
    try run(io, dir, &.{ "openssl", "x509", "-req", "-in", c, "-CA", try fileName(&by_pem, o.by, "pem"), "-CAkey", try fileName(&by_key, o.by, "key"), "-CAcreateserial", "-out", try fileName(&pem, o.name, "pem"), "-days", "2", "-extfile", o.ext });
}

/// The run's certificates, each `NAME.pem` with its key in `NAME.key`:
///
/// - `ca`, the root the tests trust, for 30 days;
/// - `server`, P-256, for localhost, signed by `ca`;
/// - `rsa`, RSA 2048, for localhost, signed by `ca`: a key std's TLS 1.2
///   can use;
/// - `leaf`, P-256, for attacker.example, signed by `ca`: CA:FALSE, a key
///   that may only sign data, such as anyone can have for a domain of
///   their own;
/// - `forged`, P-256, for localhost, signed by `leaf`.
///
/// All but `ca` last 2 days.
fn makeCertificates(io: Io, dir: Io.Dir) !void {
    try dir.writeFile(io, .{ .sub_path = "localhost.cnf", .data = "subjectAltName=DNS:localhost\n" });
    try dir.writeFile(io, .{ .sub_path = "leaf.cnf", .data = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectAltName=DNS:attacker.example\n" });
    try run(io, dir, &.{ "openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "ca.key" });
    try run(io, dir, &.{ "openssl", "req", "-x509", "-new", "-key", "ca.key", "-out", "ca.pem", "-days", "30", "-subj", "/CN=rest-core test CA" });
    try issue(io, dir, .{ .name = "server", .subject = "/CN=localhost", .ext = "localhost.cnf" });
    try issue(io, dir, .{ .name = "rsa", .subject = "/CN=localhost", .ext = "localhost.cnf", .rsa = true });
    try issue(io, dir, .{ .name = "leaf", .subject = "/CN=attacker.example", .ext = "leaf.cnf" });
    try issue(io, dir, .{ .name = "forged", .subject = "/CN=localhost", .ext = "localhost.cnf", .by = "leaf" });
}

/// A port nothing listens on now.
fn freePort(io: Io) !u16 {
    const address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    return server.socket.address.getPort();
}

/// `openssl s_server` in `dir`, serving each file there as a whole raw HTTP
/// response (`-HTTP`): `GET /ok.txt` answers ok.txt's bytes. What it writes
/// to stderr goes to s_server-PORT.log there, which `printLog` shows.
const Server = struct {
    child: std.process.Child,
    port: u16,

    const Options = struct {
        /// `NAME.pem`, with its key in `NAME.key`.
        cert: []const u8 = "server",
        /// A PEM file of the certificates sent after it.
        chain: ?[]const u8 = null,
        /// More of s_server's options.
        extra: []const []const u8 = &.{},
    };

    fn start(io: Io, dir: Io.Dir, o: Options) !Server {
        const gpa = testing.allocator;
        const port = try freePort(io);
        var port_text: [8]u8 = undefined;
        var pem: [32]u8 = undefined;
        var key: [32]u8 = undefined;
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(gpa);
        try argv.appendSlice(gpa, &.{ "openssl", "s_server", "-accept", try std.fmt.bufPrint(&port_text, "{d}", .{port}), "-cert", try fileName(&pem, o.cert, "pem"), "-key", try fileName(&key, o.cert, "key"), "-HTTP", "-quiet" });
        if (o.chain) |chain| try argv.appendSlice(gpa, &.{ "-cert_chain", chain });
        try argv.appendSlice(gpa, o.extra);
        var name: [32]u8 = undefined;
        const log = try dir.createFile(io, try logName(&name, port), .{});
        defer log.close(io);
        const child = try std.process.spawn(io, .{
            .argv = argv.items,
            .cwd = .{ .dir = dir },
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .{ .file = log },
        });
        return .{ .child = child, .port = port };
    }

    fn stop(s: *Server, io: Io) void {
        s.child.kill(io);
    }

    fn logName(buf: []u8, port: u16) ![]const u8 {
        return std.fmt.bufPrint(buf, "s_server-{d}.log", .{port});
    }

    /// What s_server wrote to stderr, for a test that failed.
    fn printLog(s: *const Server, io: Io, dir: Io.Dir) void {
        var name: [32]u8 = undefined;
        const text = dir.readFileAlloc(io, logName(&name, s.port) catch return, testing.allocator, .limited(64 << 10)) catch |err| {
            std.debug.print("s_server's log: {t}\n", .{err});
            return;
        };
        defer testing.allocator.free(text);
        std.debug.print("s_server on {d} wrote:\n{s}\n", .{ s.port, text });
    }

    fn url(s: *const Server, buf: []u8, host: []const u8, path: []const u8) []const u8 {
        return std.fmt.bufPrint(buf, "https://{s}:{d}{s}", .{ host, s.port, path }) catch unreachable;
    }
};

/// For a step a test needs to succeed: says what failed, and what s_server
/// wrote, and returns the error.
fn failed(err: anyerror, server: *const Server, io: Io, dir: Io.Dir) anyerror {
    std.debug.print("{t}\n", .{err});
    server.printLog(io, dir);
    return err;
}

/// A transport that trusts the run's CA alone, not the system's roots.
fn trustRunCa(ht: *HttpTransport, io: Io, dir: Io.Dir) !void {
    const now = Io.Clock.real.now(io);
    try ht.client.ca_bundle.addCertsFromFilePath(testing.allocator, io, now, dir, "ca.pem");
    // Set, so std does not rescan the system roots on the first request.
    ht.client.now = now;
}

/// GETs `url` through a transport that trusts the run's CA, waiting for the
/// server to come up.
fn getTrusted(io: Io, dir: Io.Dir, arena: std.mem.Allocator, url: []const u8) !rest_core.transport.Response {
    var attempt: usize = 0;
    while (true) : (attempt += 1) {
        var ht: HttpTransport = .init(testing.allocator, io, "rest-core-tls-test");
        defer ht.deinit();
        try trustRunCa(&ht, io, dir);
        if (ht.transport().send(.{ .method = .GET, .url = url, .timeout_ms = 10_000 }, arena)) |res| {
            return res;
        } else |err| {
            // s_server takes a moment to listen.
            if (err != error.ConnectionRefused or attempt >= 50) return err;
            try io.sleep(.fromMilliseconds(100), .awake);
        }
    }
}

/// std's own TLS handshake with the server on `port`, for localhost,
/// trusting the run's CA, its clock at `now`: the error
/// `std.crypto.tls.Client.init` returns, which the transport reports only
/// as `error.TlsFailure`. Waits for the server to come up.
fn handshake(io: Io, dir: Io.Dir, port: u16, now: Io.Timestamp) !void {
    var attempt: usize = 0;
    while (true) : (attempt += 1) {
        handshakeOnce(io, dir, port, now) catch |err| {
            if (err != error.ConnectionRefused or attempt >= 50) return err;
            try io.sleep(.fromMilliseconds(100), .awake);
            continue;
        };
        return;
    }
}

fn handshakeOnce(io: Io, dir: Io.Dir, port: u16, now: Io.Timestamp) !void {
    const gpa = testing.allocator;
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(gpa);
    try bundle.addCertsFromFilePath(gpa, io, Io.Clock.real.now(io), dir, "ca.pem");
    var lock: Io.RwLock = .init;
    const address: Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    const stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    // As std.http.Client lays them out, each a whole record long.
    const len = std.crypto.tls.Client.min_buffer_len;
    const bufs = try gpa.alloc(u8, 4 * len);
    defer gpa.free(bufs);
    var reader = stream.reader(io, bufs[0..len]);
    var writer = stream.writer(io, bufs[len..][0..len]);
    var entropy: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
    io.random(&entropy);
    _ = try std.crypto.tls.Client.init(&reader.interface, &writer.interface, .{
        .host = .{ .explicit = "localhost" },
        .ca = .{ .bundle = .{ .gpa = gpa, .io = io, .lock = &lock, .bundle = &bundle } },
        .read_buffer = bufs[2 * len ..][0..len],
        .write_buffer = bufs[3 * len ..][0..len],
        .entropy = &entropy,
        .realtime_now = now,
    });
}

const ok_reply = "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok";

/// A 200 whose head has one header line of `n` bytes, then the body "ok".
fn longHeadReply(n: usize) ![]u8 {
    var reply: std.ArrayList(u8) = .empty;
    errdefer reply.deinit(testing.allocator);
    try reply.appendSlice(testing.allocator, "HTTP/1.0 200 OK\r\nX-Long: ");
    try reply.appendNTimes(testing.allocator, 'a', n);
    try reply.appendSlice(testing.allocator, "\r\nContent-Length: 2\r\n\r\nok");
    return reply.toOwnedSlice(testing.allocator);
}

test "security: CWE-295 https takes a certificate only from a root it trusts, for its host, and in its time" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try makeCertificates(io, tmp.dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "ok.txt", .data = ok_reply });
    var server: Server = try .start(io, tmp.dir, .{});
    defer server.stop(io);
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;

    // The control: the CA that signed it, for the host it names.
    const res = getTrusted(io, tmp.dir, arena.allocator(), server.url(&buf, "localhost", "/ok.txt")) catch |err| return failed(err, &server, io, tmp.dir);
    try testing.expectEqual(200, res.status);
    try testing.expectEqualStrings("ok", res.body);

    // The system's roots alone: no root signed it, as for a self-signed
    // certificate or one a stranger's CA signed.
    {
        var ht: HttpTransport = .init(testing.allocator, io, "rest-core-tls-test");
        defer ht.deinit();
        try testing.expectError(error.TlsFailure, ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "localhost", "/ok.txt"), .timeout_ms = 10_000 }, arena.allocator()));
    }
    // The right CA, and another name: the certificate names localhost only.
    {
        var ht: HttpTransport = .init(testing.allocator, io, "rest-core-tls-test");
        defer ht.deinit();
        try trustRunCa(&ht, io, tmp.dir);
        try testing.expectError(error.TlsFailure, ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "127.0.0.1", "/ok.txt"), .timeout_ms = 10_000 }, arena.allocator()));
    }
    // Three days on, the certificate has expired and its CA has not. The
    // transport resets a TLS clock that runs ahead of the real one, so this
    // drives std's handshake, the check the transport relies on, with the
    // clock moved.
    const now = Io.Clock.real.now(io);
    handshake(io, tmp.dir, server.port, now) catch |err| return failed(err, &server, io, tmp.dir);
    try testing.expectError(error.CertificateExpired, handshake(io, tmp.dir, server.port, now.addDuration(.fromSeconds(3 * 24 * 60 * 60))));
}

test "security: CWE-617 a head under std's 8 KiB is read, and one past a TLS record refused, never a crash" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try makeCertificates(io, tmp.dir);
    // A head read past a 16 KiB TLS record made std's TLS reader assert in
    // ekur's client, which read heads of up to 64 KiB (its FETCH-08). std's
    // own head limit, `read_buffer_size`, is 8 KiB, under a record.
    const near = try longHeadReply(7_000);
    defer testing.allocator.free(near);
    const long = try longHeadReply(20_000);
    defer testing.allocator.free(long);
    try tmp.dir.writeFile(io, .{ .sub_path = "near.txt", .data = near });
    try tmp.dir.writeFile(io, .{ .sub_path = "long.txt", .data = long });
    var server: Server = try .start(io, tmp.dir, .{});
    defer server.stop(io);
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;

    // Under the limit: read whole.
    const res = getTrusted(io, tmp.dir, arena.allocator(), server.url(&buf, "localhost", "/near.txt")) catch |err| return failed(err, &server, io, tmp.dir);
    try testing.expectEqual(200, res.status);
    try testing.expectEqualStrings("ok", res.body);
    // Past a record and the limit: refused, cleanly.
    try testing.expectError(error.HttpProtocolError, getTrusted(io, tmp.dir, arena.allocator(), server.url(&buf, "localhost", "/long.txt")));
}

test "security: CWE-296 std takes a certificate signed by one that is not a CA (Codeberg ziglang/zig#35877)" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try makeCertificates(io, tmp.dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "ok.txt", .data = ok_reply });
    // forged.pem for localhost, signed by leaf.pem, which the CA signed for
    // attacker.example with CA:FALSE: a client must refuse the chain (RFC
    // 5280 4.2.1.9). Zig 0.17.1's takes it, so a man in the middle with any
    // certificate a trusted root signed is taken for any host. This test
    // holds std to the bug. Once it fails, std refuses the chain: expect
    // error.TlsFailure here, and set CONN-10 covered (t31).
    var server: Server = try .start(io, tmp.dir, .{ .cert = "forged", .chain = "leaf.pem" });
    defer server.stop(io);
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    const res = getTrusted(io, tmp.dir, arena.allocator(), server.url(&buf, "localhost", "/ok.txt")) catch |err| return failed(err, &server, io, tmp.dir);
    try testing.expectEqual(200, res.status);
}

test "std's TLS client cannot reach a server that splits its handshake into small records, or a TLS 1.2 one with an ECDSA key" {
    // Each holds std to what it cannot do, and fails once std can.
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try makeCertificates(io, tmp.dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "ok.txt", .data = ok_reply });
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    const now = Io.Clock.real.now(io);

    // The controls: TLS 1.3, its records whole, and TLS 1.2 with an RSA key.
    {
        var server: Server = try .start(io, tmp.dir, .{});
        defer server.stop(io);
        handshake(io, tmp.dir, server.port, now) catch |err| return failed(err, &server, io, tmp.dir);
    }
    {
        var server: Server = try .start(io, tmp.dir, .{ .cert = "rsa", .extra = &.{"-tls1_2"} });
        defer server.stop(io);
        handshake(io, tmp.dir, server.port, now) catch |err| return failed(err, &server, io, tmp.dir);
    }
    // TLS 1.3 in records of 512 bytes, which RFC 8446 5.1 allows: once the
    // Certificate message is read, std reads the next record into its other
    // buffer, away from the start of the message that record ends, and takes
    // bytes never written there for the rest of it.
    {
        var server: Server = try .start(io, tmp.dir, .{ .extra = &.{ "-max_send_frag", "512" } });
        defer server.stop(io);
        try testing.expectError(error.TlsUnexpectedMessage, handshake(io, tmp.dir, server.port, now));
    }
    // TLS 1.2 in records of 512 bytes: std reads a cleartext handshake
    // record by record, so a message split between two is never joined.
    // Through the transport, whose time limit ends a handshake left waiting.
    {
        var server: Server = try .start(io, tmp.dir, .{ .cert = "rsa", .extra = &.{ "-tls1_2", "-max_send_frag", "512" } });
        defer server.stop(io);
        if (getTrusted(io, tmp.dir, arena.allocator(), server.url(&buf, "localhost", "/ok.txt"))) |_| {
            std.debug.print("TLS 1.2 in records of 512 bytes was taken\n", .{});
            return error.TestUnexpectedResult;
        } else |err| switch (err) {
            error.TlsFailure, error.TimedOut => {},
            else => return failed(err, &server, io, tmp.dir),
        }
    }
    // TLS 1.2 with an ECDSA key: std offers TLS 1.2's ECDHE_RSA suites
    // alone, so the server has none it can use, and says so.
    {
        var server: Server = try .start(io, tmp.dir, .{ .extra = &.{"-tls1_2"} });
        defer server.stop(io);
        try testing.expectError(error.TlsAlert, handshake(io, tmp.dir, server.port, now));
    }
}
