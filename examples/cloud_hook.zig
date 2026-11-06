//! How a cloud's library plugs into rest-core: its hook, and the request
//! loop over it. This cloud's errors read `{"error":{"code","message"}}`;
//! it retries 429 and 5xx, and its bodies carry no retry delay. The tests
//! drive the loop with a fake transport and a fake clock.

const std = @import("std");
const rest_core = @import("rest_core");
const Allocator = std.mem.Allocator;

const ExampleCloud = struct {
    pub const RefusalError = error{ NotFound, Throttled, ServerError, Refused };

    /// A refused response, read into `diagnostics`, and the error it is.
    pub fn refusal(scratch: Allocator, res: rest_core.transport.Response, diagnostics: ?*rest_core.Diagnostics) (RefusalError || Allocator.Error) {
        const Body = struct { @"error": struct { code: []const u8 = "", message: []const u8 = "" } };
        const body: ?Body = std.json.parseFromSliceLeaky(Body, scratch, res.body, .{ .ignore_unknown_fields = true }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => null,
        };
        if (diagnostics) |d| {
            d.set(res.status, if (body) |b| b.@"error".code else "", if (body) |b| b.@"error".message else res.body);
        }
        return switch (res.status) {
            404 => error.NotFound,
            429 => error.Throttled,
            500...599 => error.ServerError,
            else => error.Refused,
        };
    }

    /// Which failures are worth another attempt.
    pub fn retryable(err: anyerror, http_status: u16) bool {
        _ = http_status;
        return rest_core.isRetryable(err) or err == error.Throttled or err == error.ServerError;
    }

    /// A retry delay the body carries: none, in this cloud.
    pub fn bodyDelayMs(scratch: Allocator, body: []const u8) Allocator.Error!?u32 {
        _ = scratch;
        _ = body;
        return null;
    }
};

const Engine = rest_core.Engine(.example_cloud, ExampleCloud);

const Rig = struct {
    fake: rest_core.testing.FakeTransport,
    clock: rest_core.testing.FakeClock = .{},
    token: rest_core.StaticToken = .{ .token = "token-1" },
    diag: rest_core.Diagnostics = .{},

    fn engine(rig: *Rig) Engine {
        return .{
            .gpa = std.testing.allocator,
            .io = rig.clock.io(),
            .transport = rig.fake.transport(),
            .base_url = "https://api.example.com",
            .auth_scope = "https://api.example.com/.default",
            .token_provider = rig.token.provider(),
            .diagnostics = &rig.diag,
        };
    }
};

test "a throttled call waits what the server asked, then succeeds" {
    var rig: Rig = .{ .fake = .init(std.testing.allocator, &.{
        .{ .respond = .{ .status = 429, .headers = &.{.{ .name = "Retry-After", .value = "2" }}, .body = "{\"error\":{\"code\":\"Throttled\",\"message\":\"slow down\"}}" } },
        .{ .respond = .{ .body = "{\"id\":\"w-1\"}" } },
    }) };
    defer rig.fake.deinit();
    var response: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer response.deinit();

    const engine = rig.engine();
    engine.begin();
    const body = try engine.execute(&response, .{ .method = .GET, .path = "/v1/widgets/w-1" });
    try std.testing.expectEqualStrings("{\"id\":\"w-1\"}", body);
    // It slept the two seconds the 429 asked for, then tried again.
    try std.testing.expectEqual(2_000, rig.clock.sleepMs(0));
    try std.testing.expectEqual(2, rig.fake.requests.items.len);
}

test "a refusal not worth retrying comes back at once, with what the server said" {
    var rig: Rig = .{ .fake = .init(std.testing.allocator, &.{
        .{ .respond = .{ .status = 404, .body = "{\"error\":{\"code\":\"WidgetNotFound\",\"message\":\"no widget w-2\"}}" } },
    }) };
    defer rig.fake.deinit();
    var response: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer response.deinit();

    const engine = rig.engine();
    engine.begin();
    try std.testing.expectError(error.NotFound, engine.execute(&response, .{ .method = .GET, .path = "/v1/widgets/w-2" }));
    try std.testing.expectEqual(1, rig.fake.requests.items.len);
    try std.testing.expectEqualStrings("WidgetNotFound", rig.diag.code());
    try std.testing.expectEqualStrings("no widget w-2", rig.diag.message());
}
