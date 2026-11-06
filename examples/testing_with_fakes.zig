//! Testing a client with rest-core's fakes: the client sends through a
//! `Transport`, and the test hands it a `FakeTransport` that answers from a
//! script and records every request. README.md shows this file.

const std = @import("std");
const rest_core = @import("rest_core");
const Transport = rest_core.transport.Transport;

/// A client call: GET /v1/widgets/{id} with a bearer token. The id may come
/// from input, so it goes through a checked segment writer.
fn getWidget(t: Transport, arena: std.mem.Allocator, token: []const u8, id: []const u8) ![]const u8 {
    var url: std.Io.Writer.Allocating = .init(arena);
    try url.writer.writeAll("https://api.example.com/v1/widgets/");
    try rest_core.query.writeCheckedSegment(&url.writer, id);
    const res = try t.send(.{ .method = .GET, .url = url.written(), .bearer = token, .timeout_ms = 30_000 }, arena);
    if (res.status != 200) return error.NotFound;
    return res.body;
}

test "getWidget sends one GET with the token and reads the answer" {
    var fake: rest_core.testing.FakeTransport = .init(std.testing.allocator, &.{
        .{ .respond = .{ .status = 404, .body = "{\"error\":\"no such widget\"}" } },
        .{ .respond = .{ .status = 200, .body = "{\"name\":\"sprocket\"}" } },
    });
    defer fake.deinit();
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const t = fake.transport();

    try std.testing.expectError(error.NotFound, getWidget(t, arena.allocator(), "tok", "missing"));
    try std.testing.expectEqualStrings("{\"name\":\"sprocket\"}", try getWidget(t, arena.allocator(), "tok", "a/b"));

    // What the client sent, as the server would have seen it.
    const sent = try fake.request(1);
    try std.testing.expectEqual(.GET, sent.method);
    try std.testing.expectEqualStrings("https://api.example.com/v1/widgets/a%2Fb", sent.url);
    try std.testing.expectEqualStrings("tok", sent.bearer.?);
    try std.testing.expectEqual(30_000, sent.timeout_ms);
}
