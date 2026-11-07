// Ported from gcp.zig src/core/PreparedRequest.zig at eae944c. gcp.zig has built on this copy since its 5aa9ba8.
//! A request as a client would send it, built without sending it: to show
//! before the call, as a console's confirmation does, or to record after
//! it. A module builds one from the same `loop.Call` its write sends, so the
//! URL and the body are byte for byte what the call sends. Credentials and
//! other headers are not part of it, so a preview shown or logged carries no
//! token.
//!
//! A value: once built, any task may read it. Its URL and body live in the
//! arena `fromCall` was given, and go with it.

const PreparedRequest = @This();

const std = @import("std");
const Allocator = std.mem.Allocator;
const loop = @import("loop.zig");
const transport = @import("transport.zig");

method: transport.Method,
/// The whole URL, the client's endpoint included.
url: []const u8,
/// The body as sent; empty for a request that sends none.
body: []const u8,

/// What `loop.Engine.execute` sends for `call` against `base_url`, the
/// engine's own base URL. Allocates the URL in `arena`; the body is
/// copied there too, so the result outlives the call's own memory. A path
/// the loop refuses, one that does not start with `/`, is refused here too.
/// A library that wraps `loop.Call` in its own type passes the `loop.Call`
/// it builds for the engine, or one holding only `method`, `path` and
/// `body`: nothing else here is read.
pub fn fromCall(arena: Allocator, base_url: []const u8, call: loop.Call) (Allocator.Error || error{InvalidEndpoint})!PreparedRequest {
    if (call.path.len == 0 or call.path[0] != '/') return error.InvalidEndpoint;
    return .{
        .method = call.method,
        .url = try std.mem.concat(arena, u8, &.{ base_url, call.path }),
        .body = if (call.body) |b| try arena.dupe(u8, b) else "",
    };
}

const testing = std.testing;

test "fromCall: the whole URL, the body copied, none as empty" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var body = "{}".*;
    const r = try fromCall(arena.allocator(), "https://service.googleapis.com", .{ .method = .POST, .path = "/v1/things/a:run", .body = &body });
    body[0] = 'x';
    try testing.expectEqual(.POST, r.method);
    try testing.expectEqualStrings("https://service.googleapis.com/v1/things/a:run", r.url);
    try testing.expectEqualStrings("{}", r.body);
    const none = try fromCall(arena.allocator(), "https://service.googleapis.com", .{ .method = .GET, .path = "/v1/things" });
    try testing.expectEqualStrings("", none.body);
    try testing.expectError(error.InvalidEndpoint, fromCall(arena.allocator(), "https://service.googleapis.com", .{ .method = .GET, .path = ".evil.example/x" }));
}
