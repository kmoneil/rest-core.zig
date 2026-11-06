//! A request through the HTTP transport: one call with a time limit, the
//! body read whole. The test answers it from a loopback server, so it runs
//! anywhere.

const std = @import("std");
const rest_core = @import("rest_core");
const Transport = rest_core.transport.Transport;

/// GETs `url` with a 10-second limit; the body lives in `arena`.
fn fetch(t: Transport, arena: std.mem.Allocator, url: []const u8) ![]const u8 {
    const res = try t.send(.{ .method = .GET, .url = url, .timeout_ms = 10_000 }, arena);
    if (res.status != 200) return error.UnexpectedStatus;
    return res.body;
}

test "fetch reads a body through HttpTransport" {
    const io = std.testing.io;
    const ScriptedServer = rest_core.testing.ScriptedServer;
    var server: ScriptedServer = try .start(io, &.{"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"});
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var http: rest_core.transport.HttpTransport = .init(std.testing.allocator, io, "my-client/1.0");
    defer http.deinit();
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("hello", try fetch(http.transport(), arena.allocator(), server.url(&buf, "/greeting")));
}
