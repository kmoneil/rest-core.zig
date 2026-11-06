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
/// response (`-HTTP`): `GET /ok.txt` answers ok.txt's bytes.
const Server = struct {
    child: std.process.Child,
    port: u16,

    fn start(io: Io, dir: Io.Dir) !Server {
        const port = try freePort(io);
        var port_text: [8]u8 = undefined;
        const child = try std.process.spawn(io, .{
            .argv = &.{ "openssl", "s_server", "-accept", try std.fmt.bufPrint(&port_text, "{d}", .{port}), "-cert", "server.pem", "-key", "server.key", "-HTTP", "-quiet" },
            .cwd = .{ .dir = dir },
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        });
        return .{ .child = child, .port = port };
    }

    fn stop(s: *Server, io: Io) void {
        s.child.kill(io);
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
            if (err != error.ConnectionRefused or attempt >= 50) return err;
            try io.sleep(.fromMilliseconds(100), .awake);
        }
    }
}

const ok_reply = "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok";

test "security: CWE-295 https takes a certificate only from a root it trusts, and only for its host" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try makeCertificates(io, tmp.dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "ok.txt", .data = ok_reply });
    var server: Server = try .start(io, tmp.dir);
    defer server.stop(io);
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

test "security: CWE-617 a head line longer than a TLS record is read or refused, never a crash" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try makeCertificates(io, tmp.dir);
    // One header line of 20,000 bytes: past a 16 KiB TLS record, which made
    // std's TLS reader assert in ekur's client (its FETCH-08).
    var reply: std.ArrayList(u8) = .empty;
    defer reply.deinit(testing.allocator);
    try reply.appendSlice(testing.allocator, "HTTP/1.0 200 OK\r\nX-Long: ");
    try reply.appendNTimes(testing.allocator, 'a', 20_000);
    try reply.appendSlice(testing.allocator, "\r\nContent-Length: 2\r\n\r\nok");
    try tmp.dir.writeFile(io, .{ .sub_path = "long.txt", .data = reply.items });
    try tmp.dir.writeFile(io, .{ .sub_path = "ok.txt", .data = ok_reply });
    var server: Server = try .start(io, tmp.dir);
    defer server.stop(io);
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    // Up first, then the long head.
    _ = try getTrusted(io, tmp.dir, arena.allocator(), server.url(&buf, "localhost", "/ok.txt"));
    if (getTrusted(io, tmp.dir, arena.allocator(), server.url(&buf, "localhost", "/long.txt"))) |res| {
        try testing.expectEqualStrings("ok", res.body);
    } else |err| {
        // A head too long for the read buffer is refused, cleanly.
        try testing.expectEqual(error.HttpProtocolError, err);
    }
}
