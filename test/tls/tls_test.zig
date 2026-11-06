//! TLS against a real server: certificates refused as they must be, and a
//! response head line longer than a TLS record. It makes a CA and a server
//! certificate for the run and starts `openssl s_server`, so it needs
//! `openssl` on the PATH and a machine where a test may listen on a port:
//! CI runs it (`zig build test-tls`); `zig build test` does not.

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

/// A CA, and a server certificate it signed for `localhost` alone.
fn makeCertificates(io: Io, dir: Io.Dir) !void {
    try run(io, dir, &.{ "openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "ca.key" });
    try run(io, dir, &.{ "openssl", "req", "-x509", "-new", "-key", "ca.key", "-out", "ca.pem", "-days", "2", "-subj", "/CN=rest-core test CA" });
    try run(io, dir, &.{ "openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "server.key" });
    try run(io, dir, &.{ "openssl", "req", "-new", "-key", "server.key", "-out", "server.csr", "-subj", "/CN=localhost" });
    try dir.writeFile(io, .{ .sub_path = "san.cnf", .data = "subjectAltName=DNS:localhost\n" });
    try run(io, dir, &.{ "openssl", "x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "server.pem", "-days", "2", "-extfile", "san.cnf" });
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

    /// With `extra`, up to four more of s_server's options.
    fn start(io: Io, dir: Io.Dir, extra: []const []const u8) !Server {
        const port = try freePort(io);
        var port_text: [8]u8 = undefined;
        const base = [_][]const u8{ "openssl", "s_server", "-accept", try std.fmt.bufPrint(&port_text, "{d}", .{port}), "-cert", "server.pem", "-key", "server.key", "-HTTP", "-quiet" };
        var argv: [base.len + 4][]const u8 = undefined;
        @memcpy(argv[0..base.len], &base);
        @memcpy(argv[base.len..][0..extra.len], extra);
        var name: [32]u8 = undefined;
        const log = try dir.createFile(io, try logName(&name, port), .{});
        defer log.close(io);
        const child = try std.process.spawn(io, .{
            .argv = argv[0 .. base.len + extra.len],
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
            if (err != error.ConnectionRefused or attempt >= 50) {
                std.debug.print("GET {s}: {t}\n", .{ url, err });
                return err;
            }
            try io.sleep(.fromMilliseconds(100), .awake);
        }
    }
}

/// std's own TLS handshake with the server on `port`, trusting the run's
/// CA: the error `std.crypto.tls.Client.init` returns, which the transport
/// reports only as `error.TlsFailure`. Waits for the server to come up.
fn handshake(io: Io, dir: Io.Dir, port: u16) !void {
    var attempt: usize = 0;
    while (true) : (attempt += 1) {
        handshakeOnce(io, dir, port) catch |err| {
            if (err != error.ConnectionRefused or attempt >= 50) return err;
            try io.sleep(.fromMilliseconds(100), .awake);
            continue;
        };
        return;
    }
}

fn handshakeOnce(io: Io, dir: Io.Dir, port: u16) !void {
    const gpa = testing.allocator;
    const now = Io.Clock.real.now(io);
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(gpa);
    try bundle.addCertsFromFilePath(gpa, io, now, dir, "ca.pem");
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

test "security: CWE-295 https takes a certificate only from a root it trusts, and only for its host" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try makeCertificates(io, tmp.dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "ok.txt", .data = ok_reply });
    var server: Server = try .start(io, tmp.dir, &.{});
    defer server.stop(io);
    errdefer server.printLog(io, tmp.dir);
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;

    // The control: the CA that signed it, for the host it names.
    const res = try getTrusted(io, tmp.dir, arena.allocator(), server.url(&buf, "localhost", "/ok.txt"));
    try testing.expectEqual(200, res.status);
    try testing.expectEqualStrings("ok", res.body);

    // The system's roots alone: no root signed it, as for a self-signed or
    // forged certificate.
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
    var server: Server = try .start(io, tmp.dir, &.{});
    defer server.stop(io);
    errdefer server.printLog(io, tmp.dir);
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;

    // Under the limit: read whole.
    const res = try getTrusted(io, tmp.dir, arena.allocator(), server.url(&buf, "localhost", "/near.txt"));
    try testing.expectEqual(200, res.status);
    try testing.expectEqualStrings("ok", res.body);
    // Past a record and the limit: refused, cleanly.
    try testing.expectError(error.HttpProtocolError, getTrusted(io, tmp.dir, arena.allocator(), server.url(&buf, "localhost", "/long.txt")));
}

// For now a probe: with s_server's records cut to 512 bytes, the head
// test's first request failed at once (CI run 42292877349), and std's
// handshake looks unable to join a message split across records.
test "std's TLS handshake, with the server's records whole and cut to 512 bytes" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try makeCertificates(io, tmp.dir);
    const cases = [_]struct { name: []const u8, extra: []const []const u8 }{
        .{ .name = "TLS 1.3, whole records", .extra = &.{} },
        .{ .name = "TLS 1.3, 512-byte records", .extra = &.{ "-max_send_frag", "512" } },
        .{ .name = "TLS 1.2, whole records", .extra = &.{"-tls1_2"} },
        .{ .name = "TLS 1.2, 512-byte records", .extra = &.{ "-tls1_2", "-max_send_frag", "512" } },
    };
    var failed = false;
    for (cases) |c| {
        var server: Server = try .start(io, tmp.dir, c.extra);
        defer server.stop(io);
        if (handshake(io, tmp.dir, server.port)) |_| {
            std.debug.print("{s}: ok\n", .{c.name});
        } else |err| {
            std.debug.print("{s}: {t}\n", .{ c.name, err });
            server.printLog(io, tmp.dir);
            failed = true;
        }
    }
    if (failed) return error.TestUnexpectedResult;
}
