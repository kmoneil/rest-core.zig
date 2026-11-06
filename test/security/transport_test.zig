//! The transport against a hostile server, and against a caller whose input
//! reaches the request.

const std = @import("std");
const builtin = @import("builtin");
const rest_core = @import("rest_core");
const HttpTransport = rest_core.transport.HttpTransport;
const ScriptedServer = rest_core.testing.ScriptedServer;
const testing = std.testing;

/// Sends one GET to a server that answers `reply`, with the transport's body
/// limit `max`, and returns what came back; `seen` is how many requests the
/// server read.
fn getOnce(reply: []const u8, max: usize, seen: *usize) !void {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{reply});
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};
    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    ht.max_response_bytes = max;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    defer seen.* = server.seen_count;
    _ = try ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/p") }, arena.allocator());
}

test "security: CWE-93 a URL carrying CR and LF is refused before anything is sent" {
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
    // A name from input pasted into the path unencoded: std.http would write
    // it into the request line as it is, and the server would read a header
    // the caller never set.
    for ([_][]const u8{ "/a\r\nX-Injected: y", "/a b", "/a\\b" }) |path| {
        try testing.expectError(error.InvalidEndpoint, ht.transport().send(.{ .method = .GET, .url = server.url(&buf, path) }, arena.allocator()));
    }
    try testing.expectEqual(0, server.seen_count);
}

test "security: CWE-444 a caller cannot set the request's framing or its host" {
    var ht: HttpTransport = .init(testing.allocator, testing.io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    // Each would be sent beside the transport's own: two lengths is request
    // smuggling, two hosts a request the server routes by the wrong one.
    for ([_][2][]const u8{ .{ "Content-Length", "0" }, .{ "Transfer-Encoding", "chunked" }, .{ "Host", "evil.example" }, .{ "Connection", "close" } }) |h| {
        try testing.expectError(error.InvalidRequestHeader, ht.transport().send(.{
            .method = .POST,
            .url = "http://127.0.0.1:9/p",
            .body = "{}",
            .headers = &.{.{ .name = h[0], .value = h[1] }},
        }, arena.allocator()));
    }
}

test "security: CWE-444 a response framed two ways, or with a length that is not digits, is refused" {
    var seen: usize = 0;
    try testing.expectError(error.HttpProtocolError, getOnce("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n", 1 << 20, &seen));
    try testing.expectError(error.HttpProtocolError, getOnce("HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\nhi", 1 << 20, &seen));
    try testing.expectError(error.HttpProtocolError, getOnce("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nhix", 1 << 20, &seen));
}

test "security: CWE-444 a response head with bare line feeds or a folded line is refused" {
    var seen: usize = 0;
    // A head of bare LFs never ends, so the response is never taken: the
    // server's close reads as a dropped connection.
    if (getOnce("HTTP/1.1 200 OK\nContent-Length: 2\n\nhi", 1 << 20, &seen)) |_| return error.TestUnexpectedResult else |_| {}
    try testing.expectError(error.HttpProtocolError, getOnce("HTTP/1.1 200 OK\r\nX-A: 1\r\n folded\r\nContent-Length: 2\r\n\r\nhi", 1 << 20, &seen));
}

test "security: CWE-770 a head too long for the read buffer is refused" {
    var head: std.ArrayList(u8) = .empty;
    defer head.deinit(testing.allocator);
    try head.appendSlice(testing.allocator, "HTTP/1.1 200 OK\r\n");
    for (0..20_000) |_| try head.appendSlice(testing.allocator, "X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
    try head.appendSlice(testing.allocator, "Content-Length: 2\r\n\r\nhi");
    var seen: usize = 0;
    try testing.expectError(error.HttpProtocolError, getOnce(head.items, 1 << 20, &seen));
}

test "security: CWE-409 a gzip body that expands past the limit is refused" {
    const zeros = try testing.allocator.alloc(u8, 8 << 20);
    defer testing.allocator.free(zeros);
    @memset(zeros, 0);
    // std's compressor needs a writer with a buffer of its own.
    var compressed: std.Io.Writer.Allocating = try .initCapacity(testing.allocator, 64);
    defer compressed.deinit();
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var gzip: std.compress.flate.Compress = try .init(&compressed.writer, &window, .gzip, .default);
    try gzip.writer.writeAll(zeros);
    try gzip.finish();
    const bomb = compressed.written();
    // 8 MiB of zeros is a few kilobytes on the wire.
    try testing.expect(bomb.len < 64 << 10);
    const reply = try std.fmt.allocPrint(testing.allocator, "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {d}\r\n\r\n{s}", .{ bomb.len, bomb });
    defer testing.allocator.free(reply);
    var seen: usize = 0;
    // The limit counts the decoded bytes, not the bytes on the wire.
    try testing.expectError(error.ResponseTooLarge, getOnce(reply, 1 << 20, &seen));
}

test "security: CWE-354 a compressed body that does not match its own trailer is refused" {
    var compressed: std.Io.Writer.Allocating = try .initCapacity(testing.allocator, 64);
    defer compressed.deinit();
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var gzip: std.compress.flate.Compress = try .init(&compressed.writer, &window, .gzip, .default);
    try gzip.writer.writeAll("{\"balance\":100}");
    try gzip.finish();
    // A body corrupted on the way, its trailer's CRC-32 no longer its own:
    // std's decoder reads the trailer and checks nothing, so it came back
    // as a good body.
    const body = compressed.written();
    body[body.len - 8] ^= 0x01;
    const reply = try std.fmt.allocPrint(testing.allocator, "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {d}\r\n\r\n{s}", .{ body.len, body });
    defer testing.allocator.free(reply);
    var seen: usize = 0;
    try testing.expectError(error.HttpProtocolError, getOnce(reply, 1 << 20, &seen));
}

test "security: CWE-400 a stalling server is cut off at the time limit, and a limit that cannot run is refused" {
    const io = testing.io;
    var server: ScriptedServer = try .start(io, &.{"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"});
    defer server.deinit(io);
    server.hang = true;
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    const url = server.url(&buf, "/p");

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    const outcome = ht.transport().send(.{ .method = .GET, .url = url, .timeout_ms = 150 }, arena.allocator());
    // Windows may tear the idle connection down first; the transport's own
    // test explains it.
    if (builtin.target.os.tag == .windows) {
        if (outcome) |_| {} else |err| if (err == error.ConnectionResetByPeer) return error.SkipZigTest;
    }
    try testing.expectError(error.TimedOut, outcome);
    const seen = server.seen_count;

    // Where the Io cannot start the timer, the request is refused, not sent
    // with no limit at all.
    var threaded: std.Io.Threaded = .init(testing.allocator, .{ .concurrent_limit = .nothing });
    defer threaded.deinit();
    var untimed: HttpTransport = .init(testing.allocator, threaded.io(), "t");
    defer untimed.deinit();
    try testing.expectError(error.ConcurrencyUnavailable, untimed.transport().send(.{ .method = .GET, .url = url, .timeout_ms = 150 }, arena.allocator()));
    try testing.expectEqual(seen, server.seen_count);
}

test "security: CWE-400 std's Group.async drops a cancel when it runs a task inline (Codeberg ziglang/zig#37192)" {
    // This test holds std to its bug. When it fails, std has fixed it:
    // catalog row CONN-08 can then be covered, and this test inverted.
    var threaded: std.Io.Threaded = .init(testing.allocator, .{ .async_limit = .nothing });
    defer threaded.deinit();
    const io = threaded.io();
    const Job = struct {
        fn sleepFor(job_io: std.Io, ms: i64) std.Io.Cancelable!void {
            try job_io.sleep(.fromMilliseconds(ms), .awake);
        }
        // Two tasks in a group, as std's HostName.connect starts one per
        // address. With no async capacity left, each runs inline.
        fn run(job_io: std.Io) std.Io.Cancelable!void {
            var group: std.Io.Group = .init;
            group.async(job_io, sleepFor, .{ job_io, 300 });
            group.async(job_io, sleepFor, .{ job_io, 300 });
            try group.await(job_io);
        }
    };
    const started = std.Io.Clock.awake.now(io);
    var job = try io.concurrent(Job.run, .{io});
    try io.sleep(.fromMilliseconds(50), .awake);
    const outcome = job.cancel(io);
    const elapsed = started.durationTo(std.Io.Clock.awake.now(io)).toMilliseconds();
    if (outcome) |_| {
        // The bug: the first task's cancel was dropped, the second slept its
        // whole time with no cancel pending, and the job succeeded.
        try testing.expect(elapsed >= 300);
    } else |err| {
        std.debug.print("std now returns {t} after {d} ms: Codeberg #37192 looks fixed; cover CONN-08\n", .{ err, elapsed });
        return error.TestUnexpectedResult;
    }
}

test "security: CWE-200 a redirect is never followed, so the token stays with its host" {
    const io = testing.io;
    var elsewhere: ScriptedServer = try .start(io, &.{"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"});
    defer elsewhere.deinit(io);
    var serving_elsewhere = try io.concurrent(ScriptedServer.run, .{ &elsewhere, io });
    defer _ = serving_elsewhere.cancel(io) catch {};
    var target_buf: [128]u8 = undefined;
    const reply = try std.fmt.allocPrint(testing.allocator, "HTTP/1.1 302 Found\r\nLocation: {s}\r\nContent-Length: 0\r\n\r\n", .{elsewhere.url(&target_buf, "/steal")});
    defer testing.allocator.free(reply);
    var server: ScriptedServer = try .start(io, &.{reply});
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    const res = try ht.transport().send(.{ .method = .GET, .url = server.url(&buf, "/p"), .bearer = "ya29.secret" }, arena.allocator());
    try testing.expectEqual(302, res.status);
    try testing.expectEqual(0, elsewhere.seen_count);
}

test "security: CWE-319 the transport sets no proxy and reads none from the environment" {
    var seen: usize = 0;
    try getOnce("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 1 << 20, &seen);
    var ht: HttpTransport = .init(testing.allocator, testing.io, "t");
    defer ht.deinit();
    // std.http.Client reads HTTP_PROXY and HTTPS_PROXY only when asked
    // (`initDefaultProxies`), and HTTPS through its proxies goes in cleartext
    // (Codeberg ziglang/zig#35294). The transport never asks.
    try testing.expectEqual(null, ht.client.http_proxy);
    try testing.expectEqual(null, ht.client.https_proxy);
}
