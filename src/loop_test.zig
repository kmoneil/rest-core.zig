// From gcp.zig src/core/rpc.zig at eae944c: its loop tests, run against two clouds' hooks, Google's and Azure ARM's, written here as tests.
//! The request loop's contract, driven through a fake transport, a fake
//! clock and a fake token provider, under two clouds' hooks: one in Google's
//! shape (a JSON `error.status`, `google.rpc.RetryInfo` in the body) and one
//! in Azure Resource Manager's (a JSON `error.code`, `x-ms-request-id`,
//! `x-ms-retry-after-ms`, 408, 429 and 5xx retried). Neither ships here:
//! each lives in its cloud's library.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const loop = @import("loop.zig");
const Diagnostics = @import("Diagnostics.zig");
const WipingAllocator = @import("WipingAllocator.zig");
const RetryPolicy = @import("retry.zig").RetryPolicy;
const isRetryable = @import("retry.zig").isRetryable;
const TokenProvider = @import("TokenProvider.zig");
const transport = @import("transport.zig");
const test_util = @import("testing.zig");
const FakeTransport = test_util.FakeTransport;
const Reply = FakeTransport.Reply;
const Call = loop.Call;
const StreamCall = loop.StreamCall;

/// A hook in Google's shape, as gcp.zig's will be.
const GoogleShaped = struct {
    pub const RefusalError = error{
        InvalidArgument,
        FailedPrecondition,
        Unauthenticated,
        PermissionDenied,
        NotFound,
        AlreadyExists,
        Aborted,
        ResourceExhausted,
        Internal,
        Unavailable,
        DeadlineExceeded,
        Unknown,
    };

    pub fn refusal(scratch: Allocator, res: transport.Response, diagnostics: ?*Diagnostics) (RefusalError || Allocator.Error) {
        const Body = struct { @"error": struct { status: []const u8 = "", message: []const u8 = "" } };
        const parsed: ?Body = std.json.parseFromSliceLeaky(Body, scratch, res.body, .{ .ignore_unknown_fields = true }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => null,
        };
        const status = if (parsed) |p| p.@"error".status else "";
        // A body that is not the standard error shape, such as a proxy's
        // page, is the best message there is.
        const message = if (parsed) |p| p.@"error".message else res.body;
        if (diagnostics) |d| d.set(res.status, status, message);
        return fromStatus(res.status, status);
    }

    fn fromStatus(http_status: u16, status: []const u8) RefusalError {
        const named = [_]struct { []const u8, RefusalError }{
            .{ "INVALID_ARGUMENT", error.InvalidArgument },   .{ "FAILED_PRECONDITION", error.FailedPrecondition },
            .{ "UNAUTHENTICATED", error.Unauthenticated },    .{ "PERMISSION_DENIED", error.PermissionDenied },
            .{ "NOT_FOUND", error.NotFound },                 .{ "ALREADY_EXISTS", error.AlreadyExists },
            .{ "ABORTED", error.Aborted },                    .{ "RESOURCE_EXHAUSTED", error.ResourceExhausted },
            .{ "INTERNAL", error.Internal },                  .{ "UNAVAILABLE", error.Unavailable },
            .{ "DEADLINE_EXCEEDED", error.DeadlineExceeded },
        };
        for (named) |n| if (std.mem.eql(u8, n[0], status)) return n[1];
        return switch (http_status) {
            400 => error.InvalidArgument,
            401 => error.Unauthenticated,
            403 => error.PermissionDenied,
            404 => error.NotFound,
            409 => error.Aborted,
            429 => error.ResourceExhausted,
            500 => error.Internal,
            502, 503 => error.Unavailable,
            504 => error.DeadlineExceeded,
            else => error.Unknown,
        };
    }

    pub fn retryable(err: anyerror, http_status: u16) bool {
        _ = http_status;
        return isRetryable(err) or switch (err) {
            error.ResourceExhausted, error.Internal, error.Unavailable, error.DeadlineExceeded => true,
            else => false,
        };
    }

    /// `google.rpc.RetryInfo` in `error.details`: "1.250s" is 1,250 ms.
    pub fn bodyDelayMs(scratch: Allocator, body: []const u8) Allocator.Error!?u32 {
        const root = std.json.parseFromSliceLeaky(std.json.Value, scratch, body, .{}) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return null,
        };
        const err_value = if (root == .object) root.object.get("error") orelse return null else return null;
        const details = if (err_value == .object) err_value.object.get("details") orelse return null else return null;
        if (details != .array) return null;
        for (details.array.items) |detail| {
            if (detail != .object) continue;
            const kind = detail.object.get("@type") orelse continue;
            if (kind != .string or !std.mem.endsWith(u8, kind.string, "google.rpc.RetryInfo")) continue;
            const delay = detail.object.get("retryDelay") orelse continue;
            if (delay == .string) return durationMs(delay.string);
        }
        return null;
    }

    fn durationMs(text: []const u8) ?u32 {
        if (!std.mem.endsWith(u8, text, "s")) return null;
        const number = text[0 .. text.len - 1];
        const dot = std.mem.indexOfScalar(u8, number, '.') orelse number.len;
        const whole = std.fmt.parseInt(u32, number[0..dot], 10) catch return null;
        var ms: u32 = 0;
        if (dot < number.len) {
            const fraction = number[dot + 1 ..];
            for (fraction[0..@min(3, fraction.len)], 0..) |c, i| {
                if (!std.ascii.isDigit(c)) return null;
                ms += (c - '0') * std.math.pow(u32, 10, @intCast(2 - i));
            }
        }
        return whole * 1000 + ms;
    }
};

/// A hook in Azure Resource Manager's shape, as azure.zig's will be.
const ArmShaped = struct {
    pub const RefusalError = error{
        BadRequest,
        Unauthorized,
        Forbidden,
        NotFound,
        Conflict,
        PreconditionFailed,
        TooManyRequests,
        ServerError,
        ServiceUnavailable,
        GatewayTimeout,
        Unexpected,
    };

    pub fn refusal(scratch: Allocator, res: transport.Response, diagnostics: ?*Diagnostics) (RefusalError || Allocator.Error) {
        const Body = struct { @"error": struct { code: []const u8 = "", message: []const u8 = "" } };
        const parsed: ?Body = std.json.parseFromSliceLeaky(Body, scratch, res.body, .{ .ignore_unknown_fields = true }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => null,
        };
        // ARM puts the code in the body; Blob Storage's XML errors in a
        // header as well, which is the only place a HEAD's can be.
        const code = if (parsed) |p| p.@"error".code else header(res.headers, "x-ms-error-code") orelse "";
        const message = if (parsed) |p| p.@"error".message else res.body;
        if (diagnostics) |d| {
            d.set(res.status, code, message);
            if (header(res.headers, "x-ms-request-id")) |id| d.setRequestId(id);
            // ARM's own id for the operation, which its support asks for.
            if (header(res.headers, "x-ms-correlation-request-id")) |id| d.setCorrelationId(id);
        }
        return switch (res.status) {
            400 => error.BadRequest,
            401 => error.Unauthorized,
            403 => error.Forbidden,
            404 => error.NotFound,
            409 => error.Conflict,
            412 => error.PreconditionFailed,
            429 => error.TooManyRequests,
            500 => error.ServerError,
            503 => error.ServiceUnavailable,
            504 => error.GatewayTimeout,
            else => error.Unexpected,
        };
    }

    fn header(headers: []const transport.Header, name: []const u8) ?[]const u8 {
        for (headers) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        return null;
    }

    pub fn retryable(err: anyerror, http_status: u16) bool {
        if (isRetryable(err)) return true;
        return switch (http_status) {
            408, 429, 500, 502, 503, 504 => true,
            else => false,
        };
    }

    /// ARM asks for its delays in headers alone.
    pub fn bodyDelayMs(scratch: Allocator, body: []const u8) Allocator.Error!?u32 {
        _ = scratch;
        _ = body;
        return null;
    }
};

const GoogleEngine = loop.Engine(.rest_core_loop_test, GoogleShaped);
const ArmEngine = loop.Engine(.rest_core_loop_arm_test, ArmShaped);

const unavailable: Reply = .{ .respond = .{
    .status = 503,
    .body = "{\"error\":{\"code\":503,\"message\":\"The service is currently unavailable.\",\"status\":\"UNAVAILABLE\"}}",
} };
const unauthorized: Reply = .{ .respond = .{
    .status = 401,
    .body = "{\"error\":{\"code\":401,\"message\":\"Invalid Credentials\",\"status\":\"UNAUTHENTICATED\"}}",
} };
const ok: Reply = .{ .respond = .{ .body = "{\"name\":\"projects/p/things/1\"}" } };

/// A fake transport, clock and token provider, with an engine on them.
fn Harness(comptime E: type) type {
    return struct {
        fake: FakeTransport,
        clock: test_util.FakeClock = .{},
        token: test_util.FakeTokenProvider = .{},
        diag: Diagnostics = .{},
        arena: std.heap.ArenaAllocator = undefined,

        fn init(h: *@This(), script: []const Reply) void {
            h.* = .{ .fake = .init(testing.allocator, script) };
            h.arena = .init(testing.allocator);
        }

        fn deinit(h: *@This()) void {
            h.arena.deinit();
            h.fake.deinit();
        }

        fn engine(h: *@This()) E {
            return .{
                .gpa = testing.allocator,
                .io = h.clock.io(),
                .transport = h.fake.transport(),
                .base_url = "https://service.example.com",
                .auth_scope = "https://service.example.com/.default",
                .token_provider = h.token.provider(),
                .diagnostics = &h.diag,
            };
        }

        /// `GET /v1/things` through the engine.
        fn get(h: *@This()) E.Error![]const u8 {
            const e = h.engine();
            e.begin();
            return e.execute(&h.arena, .{ .method = .GET, .path = "/v1/things" });
        }
    };
}

const H = Harness(GoogleEngine);

test "PreparedRequest.fromCall names what execute sends, byte for byte, and no token" {
    const PreparedRequest = @import("PreparedRequest.zig");
    var h: H = undefined;
    h.init(&.{ok});
    defer h.deinit();
    const call: Call = .{ .method = .POST, .path = "/v1/things/1:run?x=%2F", .body = "{\"a\":\"\\u00e9\"}" };
    const e = h.engine();
    e.begin();
    _ = try e.execute(&h.arena, call);
    const prepared = try PreparedRequest.fromCall(h.arena.allocator(), e.base_url, call);
    const sent = try h.fake.request(0);
    try testing.expectEqual(sent.method, prepared.method);
    try testing.expectEqualStrings(sent.url, prepared.url);
    try testing.expectEqualStrings(sent.body.?, prepared.body);
    // The request carried a token; the preview has nowhere to hold one.
    try testing.expect(sent.bearer != null);
    try testing.expectEqual(3, @typeInfo(PreparedRequest).@"struct".field_names.len);
}

test "unsentOnly: a refused connection and a failed lookup, nothing after a send" {
    try testing.expect(loop.unsentOnly(error.ConnectionRefused, 0));
    try testing.expect(loop.unsentOnly(error.NameServerFailure, 0));
    for ([_]anyerror{ error.ConnectionResetByPeer, error.TimedOut, error.Unavailable, error.Internal, error.TlsFailure, error.NetworkUnreachable, error.ResourceExhausted }) |err| {
        try testing.expect(!loop.unsentOnly(err, 503));
    }
}

test "a success returns the body and clears the diagnostics" {
    var h: H = undefined;
    h.init(&.{ok});
    defer h.deinit();
    h.diag.set(500, "INTERNAL", "an earlier call failed");

    try testing.expectEqualStrings("{\"name\":\"projects/p/things/1\"}", try h.get());
    const sent = try h.fake.request(0);
    try testing.expectEqualStrings("https://service.example.com/v1/things", sent.url);
    try testing.expectEqualStrings("ya29.fake-token", sent.bearer.?);
    try testing.expectEqual(.GET, sent.method);
    try testing.expectEqual(0, h.diag.http_status);
    try testing.expectEqualStrings("", h.diag.message());
    try testing.expectEqualStrings("https://service.example.com/.default", h.token.firstScope());
}

test "retry: 503, 503, 200 succeeds on the third attempt within the backoff bounds" {
    var h: H = undefined;
    h.init(&.{ unavailable, unavailable, ok });
    defer h.deinit();

    _ = try h.get();
    try testing.expectEqual(3, h.fake.requests.items.len);
    try testing.expectEqual(2, h.clock.sleep_count);
    try testing.expect(h.clock.sleepMs(0) <= 100);
    try testing.expect(h.clock.sleepMs(1) <= 200);
    // Every attempt asked for a token; none of them invalidated one.
    try testing.expectEqual(3, h.token.calls);
    try testing.expectEqual(0, h.token.invalidations);
}

test "an engine's own refusal replaces the cloud's, and its error decides the retry" {
    const rate_limited: Reply = .{ .respond = .{
        .status = 403,
        .body = "{\"error\":{\"code\":403,\"message\":\"Exceeded rate limits\",\"errors\":[{\"reason\":\"rateLimitExceeded\"}],\"status\":\"PERMISSION_DENIED\"}}",
    } };
    const Classify = struct {
        fn refusal(scratch: Allocator, res: transport.Response, d: ?*Diagnostics) (GoogleShaped.RefusalError || Allocator.Error) {
            const err = GoogleShaped.refusal(scratch, res, d);
            if (err == error.OutOfMemory) return err;
            return if (std.mem.indexOf(u8, res.body, "rateLimitExceeded") != null) error.ResourceExhausted else err;
        }
    };
    var h: H = undefined;
    h.init(&.{ rate_limited, ok });
    defer h.deinit();
    var e = h.engine();
    e.refusal = Classify.refusal;
    _ = try e.execute(&h.arena, .{ .method = .GET, .path = "/v1/things" });
    try testing.expectEqual(2, h.fake.requests.items.len);
}

test "retry: gives up after max_attempts and reports the last failure" {
    var h: H = undefined;
    h.init(&.{ unavailable, unavailable, unavailable, unavailable, unavailable });
    defer h.deinit();
    var e = h.engine();
    e.retry = .{ .max_attempts = 3 };
    try testing.expectError(error.Unavailable, e.execute(&h.arena, .{ .method = .GET, .path = "/v1/things" }));
    try testing.expectEqual(3, h.fake.requests.items.len);
    try testing.expectEqual(2, h.clock.sleep_count);
    try testing.expectEqual(503, h.diag.http_status);
    try testing.expectEqualStrings("UNAVAILABLE", h.diag.code());
    try testing.expectEqualStrings("The service is currently unavailable.", h.diag.message());
}

test "retry window: no retry begins past it, on either entry" {
    var h: H = undefined;
    h.init(&.{ unavailable, unavailable, unavailable, unavailable, unavailable, unavailable, unavailable, unavailable });
    defer h.deinit();
    // Every byte 0xff, and a cap of 1023 ms: each full-jitter wait is the
    // whole cap, since 1024 divides 2^64.
    h.clock.random_byte = 0xff;
    var e = h.engine();
    e.retry = .{ .max_attempts = 4, .initial_backoff_ms = 1023, .max_backoff_ms = 1023, .multiplier = 1 };

    // Retries begin at 1023 and 2046 ms; the third would begin at 3069,
    // past 2500.
    try testing.expectError(error.Unavailable, e.execute(&h.arena, .{ .method = .POST, .path = "/v1/things", .retry_window_ms = 2500 }));
    try testing.expectEqual(3, h.fake.requests.items.len);
    try testing.expectEqual(2, h.clock.sleep_count);
    try testing.expectEqual(1023, h.clock.sleepMs(0));

    // The streaming entry, the same.
    _ = h.arena.reset(.retain_capacity);
    try testing.expectError(error.Unavailable, e.executeStream(&h.arena, .{ .method = .POST, .path = "/v1/things", .retry_window_ms = 2500 }));
    try testing.expectEqual(3, h.fake.stream_requests.items.len);
}

test "retry window: a window of 0 allows no retry that waits, and the 401 retry is not held to it" {
    var h: H = undefined;
    h.init(&.{ unavailable, unauthorized, ok });
    defer h.deinit();
    h.clock.random_byte = 0xff;
    var e = h.engine();
    e.retry = .{ .max_attempts = 4, .initial_backoff_ms = 1023, .max_backoff_ms = 1023, .multiplier = 1 };
    try testing.expectError(error.Unavailable, e.execute(&h.arena, .{ .method = .POST, .path = "/v1/things", .retry_window_ms = 0 }));
    try testing.expectEqual(1, h.fake.requests.items.len);
    // A refused token is retried once with a fresh one, window or not.
    _ = try e.execute(&h.arena, .{ .method = .POST, .path = "/v1/things", .retry_window_ms = 0 });
    try testing.expectEqual(3, h.fake.requests.items.len);
}

test "retry: a non-retryable status returns at once, and an opted-out call never retries" {
    var h: H = undefined;
    h.init(&.{
        .{ .respond = .{ .status = 404, .body = "{\"error\":{\"status\":\"NOT_FOUND\",\"message\":\"no such thing\"}}" } },
        unavailable,
    });
    defer h.deinit();
    try testing.expectError(error.NotFound, h.get());
    try testing.expectEqual(1, h.fake.requests.items.len);
    try testing.expectEqualStrings("no such thing", h.diag.message());

    const e = h.engine();
    try testing.expectError(error.Unavailable, e.execute(&h.arena, .{ .method = .POST, .path = "/v1/things", .retry = false }));
    try testing.expectEqual(2, h.fake.requests.items.len);
    try testing.expectEqual(0, h.clock.sleep_count);
}

test "retry: a call can widen what is retried, and sees the HTTP status it decides on" {
    const Widened = struct {
        var seen: [4]u16 = undefined;
        var calls: usize = 0;

        fn retryable(err: anyerror, http_status: u16) bool {
            seen[calls] = http_status;
            calls += 1;
            return err == error.Aborted or isRetryable(err);
        }
    };
    var h: H = undefined;
    h.init(&.{
        .{ .respond = .{ .status = 409, .body = "{\"error\":{\"status\":\"ABORTED\"}}" } },
        .{ .fail = error.ConnectionResetByPeer },
        ok,
        .{ .respond = .{ .status = 409, .body = "{\"error\":{\"status\":\"ABORTED\"}}" } },
    });
    defer h.deinit();
    const e = h.engine();
    Widened.calls = 0;
    _ = try e.execute(&h.arena, .{ .method = .POST, .path = "/v1/things", .retryable = Widened.retryable });
    try testing.expectEqual(3, h.fake.requests.items.len);
    // A response's status, and 0 for an attempt that got none.
    try testing.expectEqualSlices(u16, &.{ 409, 0 }, Widened.seen[0..Widened.calls]);

    // The cloud's default leaves ABORTED alone.
    try testing.expectError(error.Aborted, h.get());
    try testing.expectEqual(4, h.fake.requests.items.len);
}

const too_many_wait_2: Reply = .{ .respond = .{
    .status = 429,
    .headers = &.{.{ .name = "Retry-After", .value = "2" }},
    .body = "{\"error\":{\"code\":429,\"message\":\"Quota exceeded.\",\"status\":\"RESOURCE_EXHAUSTED\"}}",
} };

test "server delay: Retry-After is waited in full, kept in Diagnostics, and cleared by the success" {
    var h: H = undefined;
    h.init(&.{ too_many_wait_2, ok });
    defer h.deinit();
    _ = try h.get();
    try testing.expectEqual(2, h.fake.requests.items.len);
    try testing.expectEqual(1, h.clock.sleep_count);
    // At least the two seconds asked for, past the 100 ms backoff.
    try testing.expectEqual(2_000, h.clock.sleepMs(0));
    try testing.expectEqual(null, h.diag.retry_after_ms);
}

test "server delay: longer than max_backoff_ms, the call returns at once with the delay" {
    // A policy with no backoff, and a 429 asking for 30 s: once, gcp.zig made
    // all four attempts at once (its issue #208).
    var h: H = undefined;
    const wait_30: Reply = .{ .respond = .{
        .status = 429,
        .headers = &.{.{ .name = "retry-after", .value = "30" }},
        .body = "{\"error\":{\"code\":429,\"message\":\"Quota exceeded ...\",\"status\":\"RESOURCE_EXHAUSTED\"}}",
    } };
    h.init(&.{ wait_30, wait_30, wait_30, wait_30 });
    defer h.deinit();
    var e = h.engine();
    e.retry = .{ .max_attempts = 4, .initial_backoff_ms = 0, .max_backoff_ms = 0 };
    e.begin();
    try testing.expectError(error.ResourceExhausted, e.execute(&h.arena, .{ .method = .GET, .path = "/v1/things" }));
    try testing.expectEqual(1, h.fake.requests.items.len);
    try testing.expectEqual(0, h.clock.sleep_count);
    try testing.expectEqual(429, h.diag.http_status);
    try testing.expectEqualStrings("RESOURCE_EXHAUSTED", h.diag.code());
    try testing.expectEqual(30_000, h.diag.retry_after_ms.?);
}

test "server delay: the body's, as the cloud reads it, and the largest of all" {
    var h: H = undefined;
    h.init(&.{
        .{ .respond = .{ .status = 503, .body =
        \\{"error":{"code":503,"message":"try later","status":"UNAVAILABLE","details":[{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"1.250s"}]}}
        } },
        .{ .respond = .{ .status = 503, .headers = &.{ .{ .name = "Retry-After", .value = "1" }, .{ .name = "retry-after-ms", .value = "3500" } }, .body =
        \\{"error":{"code":503,"message":"try later","status":"UNAVAILABLE","details":[{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"2s"}]}}
        } },
        ok,
    });
    defer h.deinit();
    _ = try h.get();
    try testing.expectEqual(3, h.fake.requests.items.len);
    try testing.expectEqual(1_250, h.clock.sleepMs(0));
    try testing.expectEqual(3_500, h.clock.sleepMs(1));
}

test "server delay: a status not retried keeps its delay, and is still not retried" {
    var h: H = undefined;
    h.init(&.{ .{ .respond = .{
        .status = 400,
        .headers = &.{.{ .name = "Retry-After", .value = "5" }},
        .body = "{\"error\":{\"code\":400,\"message\":\"bad\",\"status\":\"INVALID_ARGUMENT\"}}",
    } }, ok });
    defer h.deinit();
    try testing.expectError(error.InvalidArgument, h.get());
    try testing.expectEqual(1, h.fake.requests.items.len);
    try testing.expectEqual(5_000, h.diag.retry_after_ms.?);
}

test "server delay: each attempt reads its own; one without a delay goes back to the backoff" {
    var h: H = undefined;
    h.init(&.{ too_many_wait_2, unavailable, ok });
    defer h.deinit();
    h.clock.random_byte = 0;
    _ = try h.get();
    try testing.expectEqual(2_000, h.clock.sleepMs(0));
    try testing.expectEqual(0, h.clock.sleepMs(1));
}

test "server delay: server_delay_out holds each attempt's own, for a module's loop" {
    var h: H = undefined;
    h.init(&.{ too_many_wait_2, unavailable, too_many_wait_2, ok });
    defer h.deinit();
    var delay: ?u32 = 12345;
    var e = h.engine();
    e.server_delay_out = &delay;
    const call: Call = .{ .method = .GET, .path = "/v1/things", .retry = false };
    try testing.expectError(error.ResourceExhausted, e.execute(&h.arena, call));
    try testing.expectEqual(2_000, delay.?);
    try testing.expectError(error.Unavailable, e.execute(&h.arena, call));
    try testing.expectEqual(null, delay);
    const stream: StreamCall = .{ .method = .GET, .path = "/v1/things", .retry = false };
    try testing.expectError(error.ResourceExhausted, e.executeStream(&h.arena, stream));
    try testing.expectEqual(2_000, delay.?);
    _ = try e.executeStream(&h.arena, stream);
    try testing.expectEqual(null, delay);
}

test "a body that is not the cloud's error shape maps by HTTP status and keeps its text" {
    var h: H = undefined;
    h.init(&.{.{ .respond = .{ .status = 502, .body = "<html>Bad Gateway</html>" } }});
    defer h.deinit();
    var e = h.engine();
    e.retry = .{ .max_attempts = 1 };
    try testing.expectError(error.Unavailable, e.execute(&h.arena, .{ .method = .GET, .path = "/v1/things" }));
    try testing.expectEqual(502, h.diag.http_status);
    try testing.expectEqualStrings("", h.diag.code());
    try testing.expectEqualStrings("<html>Bad Gateway</html>", h.diag.message());
}

test "401: the cached token is dropped and the call retried once with a fresh one" {
    var h: H = undefined;
    h.init(&.{ unauthorized, ok });
    defer h.deinit();
    h.token.next_token = "ya29.fresh";

    _ = try h.get();
    try testing.expectEqual(2, h.fake.requests.items.len);
    try testing.expectEqual(1, h.token.invalidations);
    try testing.expectEqualStrings("ya29.fake-token", (try h.fake.request(0)).bearer.?);
    try testing.expectEqualStrings("ya29.fresh", (try h.fake.request(1)).bearer.?);
    // Re-authentication is not a retry: no backoff was waited.
    try testing.expectEqual(0, h.clock.sleep_count);
}

test "401: a second one is returned, with no third attempt" {
    var h: H = undefined;
    h.init(&.{ unauthorized, unauthorized, ok });
    defer h.deinit();
    try testing.expectError(error.Unauthenticated, h.get());
    try testing.expectEqual(2, h.fake.requests.items.len);
    try testing.expectEqual(1, h.token.invalidations);
    try testing.expectEqualStrings("Invalid Credentials", h.diag.message());
}

test "401: an opted-out call still retries once, because the server refused before acting" {
    var h: H = undefined;
    h.init(&.{ unauthorized, ok });
    defer h.deinit();
    const e = h.engine();
    _ = try e.execute(&h.arena, .{ .method = .POST, .path = "/v1/things:publish", .retry = false });
    try testing.expectEqual(2, h.fake.requests.items.len);
}

test "credentials: an unauthenticated endpoint gets no token and nothing to invalidate" {
    var h: H = undefined;
    h.init(&.{ unauthorized, ok });
    defer h.deinit();
    var e = h.engine();
    e.unauthenticated = true;
    try testing.expectError(error.Unauthenticated, e.execute(&h.arena, .{ .method = .GET, .path = "/v1/things" }));
    try testing.expectEqual(1, h.fake.requests.items.len);
    try testing.expectEqual(null, (try h.fake.request(0)).bearer);
    try testing.expectEqual(0, h.token.calls);
    try testing.expectEqual(0, h.token.invalidations);
}

test "credentials: a token that cannot go in a header fails before sending" {
    var h: H = undefined;
    h.init(&.{ok});
    defer h.deinit();
    h.token.token = "ya29.trailing-newline\n";
    try testing.expectError(error.TokenUnavailable, h.get());
    try testing.expectEqual(0, h.fake.requests.items.len);
    try testing.expect(std.mem.indexOf(u8, h.diag.message(), "newlines") != null);
}

test "credentials: a provider's own explanation survives in shared diagnostics" {
    const Explaining = struct {
        diag: *Diagnostics,

        fn provider(self: *@This()) TokenProvider {
            return .{ .ptr = self, .vtable = &.{ .getToken = getTokenFn, .invalidate = invalidateFn } };
        }
        fn getTokenFn(ptr: *anyopaque, io: std.Io, arena: Allocator, scopes: []const []const u8) TokenProvider.Error![]const u8 {
            _ = io;
            _ = arena;
            _ = scopes;
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.diag.set(403, "PERMISSION_DENIED", "impersonation was refused: grant the role");
            return error.TokenEndpointRejected;
        }
        fn invalidateFn(_: *anyopaque) void {}
    };
    var h: H = undefined;
    h.init(&.{ok});
    defer h.deinit();
    // What an application does: one Diagnostics, given to the credentials
    // and to the client alike.
    var explaining: Explaining = .{ .diag = &h.diag };
    var e = h.engine();
    e.token_provider = explaining.provider();
    try testing.expectError(error.TokenEndpointRejected, e.execute(&h.arena, .{ .method = .GET, .path = "/v1/things" }));
    try testing.expectEqualStrings("impersonation was refused: grant the role", h.diag.message());
    try testing.expectEqual(403, h.diag.http_status);
}

test "credentials: the provider's own failure is returned, not retried" {
    var h: H = undefined;
    h.init(&.{ok});
    defer h.deinit();
    h.token.fail = error.ReauthenticationRequired;
    try testing.expectError(error.ReauthenticationRequired, h.get());
    try testing.expectEqual(0, h.fake.requests.items.len);
    try testing.expect(std.mem.indexOf(u8, h.diag.message(), "token provider failed") != null);
}

test "timeouts: every attempt carries the engine's limit, and a stream's own replaces it" {
    var h: H = undefined;
    h.init(&.{ unavailable, ok, ok, ok });
    defer h.deinit();
    var e = h.engine();
    e.request_timeout_ms = 4_500;
    _ = try e.execute(&h.arena, .{ .method = .GET, .path = "/v1/things" });
    try testing.expectEqual(4_500, (try h.fake.request(0)).timeout_ms);
    try testing.expectEqual(4_500, (try h.fake.request(1)).timeout_ms);
    _ = try e.executeStream(&h.arena, .{ .method = .GET, .path = "/v1/slow", .timeout_ms = 60_000 });
    _ = try e.executeStream(&h.arena, .{ .method = .GET, .path = "/v1/endless", .timeout_ms = 0 });
    try testing.expectEqual(60_000, (try h.fake.streamRequest(0)).timeout_ms);
    try testing.expectEqual(0, (try h.fake.streamRequest(1)).timeout_ms);
}

test "headers: a call's own go first, then the engine's" {
    var h: H = undefined;
    h.init(&.{ ok, ok });
    defer h.deinit();
    var e = h.engine();
    e.headers = &.{.{ .name = "x-goog-user-project", .value = "billing-project" }};
    _ = try e.execute(&h.arena, .{ .method = .GET, .path = "/v1/things", .headers = &.{.{ .name = "Content-Encoding", .value = "gzip" }} });
    const sent = try h.fake.request(0);
    try testing.expectEqual(2, sent.headers.len);
    try testing.expectEqualStrings("Content-Encoding", sent.headers[0].name);
    try testing.expectEqualStrings("billing-project", sent.header("x-goog-user-project").?);
    _ = try e.executeStream(&h.arena, .{ .method = .GET, .path = "/v1/things" });
    try testing.expectEqualStrings("billing-project", (try h.fake.streamRequest(0)).header("x-goog-user-project").?);
}

test "a path that does not start with '/' is refused, since it would change the host" {
    var h: H = undefined;
    h.init(&.{ ok, ok });
    defer h.deinit();
    const e = h.engine();
    for ([_][]const u8{ ".evil.example/v1/x", ":8443/v1/x", "@evil.example/v1/x", "", "v1/x" }) |path| {
        try testing.expectError(error.InvalidEndpoint, e.execute(&h.arena, .{ .method = .GET, .path = path }));
        try testing.expectError(error.InvalidEndpoint, e.executeStream(&h.arena, .{ .method = .GET, .path = path }));
    }
    try testing.expectEqual(0, h.fake.requests.items.len);
    try testing.expectEqual(0, h.fake.stream_requests.items.len);
    try testing.expectEqual(0, h.token.calls);
}

test "pathOnOrigin: a server's URL is followed only on the engine's own origin" {
    const base = "https://management.azure.com";
    try testing.expectEqualStrings("/subscriptions?api-version=2022-12-01&$skiptoken=x", loop.pathOnOrigin(base, "https://management.azure.com/subscriptions?api-version=2022-12-01&$skiptoken=x").?);
    for ([_][]const u8{
        "http://management.azure.com/subscriptions",
        "https://management.azure.com.evil.example/subscriptions",
        "https://management.azure.com:8443/subscriptions",
        "https://management.azure.com@evil.example/subscriptions",
        "https://evil.example/https://management.azure.com/subscriptions",
        "https://management.azure.com",
        "/subscriptions",
        "https://management.azure.com:80/subscriptions",
        "https://management.azure.com:443@evil.example/subscriptions",
        "https://management.azure.com:443.evil.example/subscriptions",
        "https://management.azure.com:4430/subscriptions",
        "https://management.azure.com:+443/subscriptions",
        "https://management.azure.com:65979/subscriptions",
        "https://management.azure.com:443:443/subscriptions",
        "https://management.azure.com:/subscriptions",
        "https://management.azure.com?subscriptions",
        "https://[::1/subscriptions",
        "https:///subscriptions",
    }) |url| {
        try testing.expectEqual(null, loop.pathOnOrigin(base, url));
    }
}

test "pathOnOrigin: an explicit default port and a host in another case are the same origin" {
    // As Azure's Retail Prices API writes every NextPageLink.
    const prices = "https://prices.azure.com";
    try testing.expectEqualStrings(
        "/api/retail/prices?api-version=2023-01-01-preview&$skip=1000",
        loop.pathOnOrigin(prices, "https://prices.azure.com:443/api/retail/prices?api-version=2023-01-01-preview&$skip=1000").?,
    );
    try testing.expectEqualStrings("/x", loop.pathOnOrigin(prices, "https://Prices.Azure.COM/x").?);
    try testing.expectEqualStrings("/x", loop.pathOnOrigin(prices, "HTTPS://prices.azure.com/x").?);
    try testing.expectEqualStrings("/x", loop.pathOnOrigin(prices, "https://prices.azure.com:0443/x").?);
    // And the other way: a base URL that writes its default port.
    try testing.expectEqualStrings("/x", loop.pathOnOrigin("https://prices.azure.com:443", "https://prices.azure.com/x").?);
    // An emulator's base: an IPv6 literal and a port of its own.
    try testing.expectEqualStrings("/v1/x", loop.pathOnOrigin("http://[::1]:8085", "http://[::1]:8085/v1/x").?);
    try testing.expectEqual(null, loop.pathOnOrigin("http://[::1]:8085", "http://[::1]/v1/x"));
    try testing.expectEqual(null, loop.pathOnOrigin("http://localhost:8080", "http://localhost/v1/x"));
    // A base URL with a path still prefixes it, as callUrl does.
    try testing.expectEqualStrings("/x", loop.pathOnOrigin("https://h.example/v1", "https://h.example:443/v1/x").?);
    try testing.expectEqual(null, loop.pathOnOrigin("https://h.example/v1", "https://h.example/v2/x"));
}

test "pathOnOrigin: agrees with std.Uri on every combination of scheme, host, userinfo, port and path" {
    const base = "https://management.azure.com";
    const schemes = [_][]const u8{ "https", "HTTPS", "http" };
    const hosts = [_][]const u8{ "management.azure.com", "Management.Azure.Com", "evil.example", "management.azure.com.evil.example" };
    const users = [_][]const u8{ "", "u@", "management.azure.com@" };
    const ports = [_][]const u8{ "", ":", ":443", ":0443", ":80", ":8443", ":65536", ":44x" };
    const paths = [_][]const u8{ "", "/", "/subscriptions?x=1", "?q", "#f" };
    var buf: [128]u8 = undefined;
    var accepted: usize = 0;
    for (schemes) |scheme| for (hosts) |host| for (users) |user| for (ports) |port| for (paths) |path| {
        const url = try std.fmt.bufPrint(&buf, "{s}://{s}{s}{s}{s}", .{ scheme, user, host, port, path });
        if (try agreesWithUri(base, url, path)) accepted += 1;
    };
    // https or HTTPS, either host case, no userinfo, the three spellings of
    // 443 std.Uri takes, and the two paths that start with '/'.
    try testing.expectEqual(2 * 2 * 3 * 2, accepted);
}

/// Whether `pathOnOrigin` and `uriOracle` agree on `url`, failing the test
/// when they do not; true when both accept it.
fn agreesWithUri(base: []const u8, url: []const u8, path: []const u8) !bool {
    const want = uriOracle(base, url, path);
    const got = loop.pathOnOrigin(base, url);
    if (want == null) {
        if (got != null) std.debug.print("accepted {s}\n", .{url});
        try testing.expectEqual(null, got);
        return false;
    }
    if (got == null) std.debug.print("refused {s}\n", .{url});
    try testing.expectEqualStrings(want.?, got orelse return error.TestExpectedEqual);
    return true;
}

/// What `pathOnOrigin` should return for `url`, built with `path` last, as
/// std.Uri reads the URL: the path when its scheme and host match the
/// base's without regard to case, its port is 443 written or not, it has no
/// userinfo, and the path starts with '/'.
fn uriOracle(base: []const u8, url: []const u8, path: []const u8) ?[]const u8 {
    const b = std.Uri.parse(base) catch unreachable;
    const u = std.Uri.parse(url) catch return null;
    if (u.user != null or u.password != null) return null;
    if (!std.ascii.eqlIgnoreCase(u.scheme, b.scheme)) return null;
    const host = switch (u.host orelse return null) {
        .raw, .percent_encoded => |h| h,
    };
    const base_host = switch (b.host.?) {
        .raw, .percent_encoded => |h| h,
    };
    if (!std.ascii.eqlIgnoreCase(host, base_host)) return null;
    if ((u.port orelse 443) != 443) return null;
    if (path.len == 0 or path[0] != '/') return null;
    return path;
}

test "a refused body the hook reads is bounded; error_body_out keeps it whole" {
    const Seen = struct {
        var longest: usize = 0;
        fn refusal(scratch: Allocator, res: transport.Response, d: ?*Diagnostics) (GoogleShaped.RefusalError || Allocator.Error) {
            longest = @max(longest, res.body.len);
            return GoogleShaped.refusal(scratch, res, d);
        }
    };
    const huge = try testing.allocator.alloc(u8, 1 << 20);
    defer testing.allocator.free(huge);
    @memset(huge, '{');
    var h: H = undefined;
    h.init(&.{.{ .respond = .{ .status = 400, .body = huge } }});
    defer h.deinit();
    var e = h.engine();
    e.refusal = Seen.refusal;
    var body: ?[]const u8 = null;
    Seen.longest = 0;
    try testing.expectError(error.InvalidArgument, e.execute(&h.arena, .{ .method = .GET, .path = "/v1/things", .error_body_out = &body }));
    try testing.expectEqual(loop.max_hook_body, Seen.longest);
    try testing.expectEqual(huge.len, body.?.len);
}

test "the log names the method, the path without its query, statuses and timings, never a token" {
    const log = @import("logging.zig").Scoped(.rest_core_loop_test);
    log.capture.reset();
    var h: H = undefined;
    h.init(&.{ unavailable, ok });
    defer h.deinit();
    h.token.token = "ya29.secret-token-for-the-log-test";
    const e = h.engine();
    _ = try e.execute(&h.arena, .{ .method = .GET, .path = "/v1/things?pageToken=secret-page-token&filter=x" });
    const text = log.capture.text();
    try testing.expect(std.mem.indexOf(u8, text, "GET /v1/things ") != null);
    try testing.expect(std.mem.indexOf(u8, text, "503") != null);
    for ([_][]const u8{ "secret-page-token", "pageToken", "ya29.secret", "?" }) |never| {
        try testing.expect(std.mem.indexOf(u8, text, never) == null);
    }
}

test "unsentOnly: a write that must not repeat is not resent after its request may have gone" {
    var h: H = undefined;
    h.init(&.{ .{ .fail = error.ConnectionResetByPeer }, .{ .fail = error.ConnectionRefused }, ok });
    defer h.deinit();
    const e = h.engine();
    // A connection that dropped after the request went: the server may have
    // acted, so a create is not sent again.
    try testing.expectError(error.ConnectionResetByPeer, e.execute(&h.arena, .{ .method = .POST, .path = "/v1/things", .retryable = loop.unsentOnly }));
    try testing.expectEqual(1, h.fake.requests.items.len);
    // A refused connection never reached the server: that is retried.
    _ = try e.execute(&h.arena, .{ .method = .POST, .path = "/v1/things", .retryable = loop.unsentOnly });
    try testing.expectEqual(3, h.fake.requests.items.len);
}

test "credential headers: they go with the token, on every attempt and both entries" {
    var h: H = undefined;
    h.init(&.{ unavailable, ok, ok });
    defer h.deinit();
    h.token.credential_headers = &.{.{ .name = "x-goog-user-project", .value = "billing-project" }};
    const e = h.engine();
    _ = try e.execute(&h.arena, .{ .method = .GET, .path = "/v1/things" });
    try testing.expectEqualStrings("billing-project", (try h.fake.request(0)).header("x-goog-user-project").?);
    try testing.expectEqualStrings("billing-project", (try h.fake.request(1)).header("x-goog-user-project").?);
    _ = try e.executeStream(&h.arena, .{ .method = .GET, .path = "/v1/things" });
    try testing.expectEqualStrings("billing-project", (try h.fake.streamRequest(0)).header("x-goog-user-project").?);
}

test "credential headers: a call's own wins over the credential's, and the credential's over the engine's" {
    var h: H = undefined;
    h.init(&.{ ok, ok });
    defer h.deinit();
    h.token.credential_headers = &.{.{ .name = "x-goog-user-project", .value = "credential-project" }};
    var e = h.engine();
    e.headers = &.{ .{ .name = "X-Goog-User-Project", .value = "engine-project" }, .{ .name = "x-engine", .value = "1" } };
    // A requester-pays call names the project it bills: only that one goes.
    _ = try e.execute(&h.arena, .{ .method = .GET, .path = "/v1/b", .headers = &.{.{ .name = "x-goog-user-project", .value = "requester" }} });
    const named = try h.fake.request(0);
    try testing.expectEqual(2, named.headers.len);
    try testing.expectEqualStrings("requester", named.header("x-goog-user-project").?);
    try testing.expectEqualStrings("1", named.header("x-engine").?);
    // Without it, the credential's, and the engine's same-named one is not sent beside it.
    _ = try e.execute(&h.arena, .{ .method = .GET, .path = "/v1/b" });
    const plain = try h.fake.request(1);
    try testing.expectEqual(2, plain.headers.len);
    try testing.expectEqualStrings("credential-project", plain.header("x-goog-user-project").?);
}

test "credential headers: none to an unauthenticated engine, none when turned off, the token still going" {
    var h: H = undefined;
    h.init(&.{ ok, ok });
    defer h.deinit();
    h.token.credential_headers = &.{.{ .name = "x-goog-user-project", .value = "billing-project" }};
    var e = h.engine();
    e.send_credential_headers = false;
    _ = try e.execute(&h.arena, .{ .method = .GET, .path = "/v1/things" });
    const off = try h.fake.request(0);
    try testing.expectEqual(null, off.header("x-goog-user-project"));
    try testing.expectEqualStrings("ya29.fake-token", off.bearer.?);
    e.send_credential_headers = true;
    e.unauthenticated = true;
    _ = try e.execute(&h.arena, .{ .method = .GET, .path = "/v1/things" });
    const emulator = try h.fake.request(1);
    try testing.expectEqual(null, emulator.header("x-goog-user-project"));
    try testing.expectEqual(null, emulator.bearer);
}

test "credential headers: the transport holds them to the rules any header meets" {
    var h: H = undefined;
    h.init(&.{});
    defer h.deinit();
    var http: transport.HttpTransport = .init(testing.allocator, testing.io, "t");
    defer http.deinit();
    var e = h.engine();
    e.transport = http.transport();
    e.base_url = "http://127.0.0.1:9";
    e.retry = .{ .max_attempts = 1 };
    // A credential that would set a header the transport owns, or one std
    // would write other than as given, is refused before anything connects.
    for ([_][]const transport.Header{
        &.{.{ .name = "Host", .value = "evil.example" }},
        &.{.{ .name = "Content-Length", .value = "0" }},
        &.{.{ .name = "x-goog-user-project", .value = "p\r\nX-Injected: y" }},
    }) |bad| {
        h.token.credential_headers = bad;
        try testing.expectError(error.InvalidRequestHeader, e.execute(&h.arena, .{ .method = .GET, .path = "/v1/things" }));
    }
}

test "executeDiscard sends the call and keeps nothing" {
    var h: H = undefined;
    h.init(&.{ unavailable, .{ .respond = .{ .body = "{}" } } });
    defer h.deinit();
    const e = h.engine();
    try e.executeDiscard(.{ .method = .DELETE, .path = "/v1/things/1" });
    try testing.expectEqual(2, h.fake.requests.items.len);
    try testing.expectEqual(.DELETE, (try h.fake.request(0)).method);
}

/// Runs a retry through an arena over a wiping allocator on a fixed buffer,
/// and reports whether the failed attempt's body is still readable after.
fn failedBodySurvives(wipe: bool) !bool {
    const marker = test_util.repeat("S3CR3T", 40);
    var h: H = undefined;
    h.init(&.{
        .{ .respond = .{ .status = 503, .body = "{\"error\":{\"status\":\"UNAVAILABLE\",\"message\":\"" ++ marker ++ "\"}}" } },
        .{ .respond = .{ .body = "{}" } },
    });
    defer h.deinit();

    var backing: [64 * 1024]u8 = @splat(0);
    var fba: std.heap.FixedBufferAllocator = .init(&backing);
    var wiping: WipingAllocator = .init(fba.allocator());
    var arena: std.heap.ArenaAllocator = .init(wiping.allocator());
    defer arena.deinit();
    const e = h.engine();
    _ = try e.execute(&arena, .{ .method = .GET, .path = "/v1/things", .wipe = wipe });
    return std.mem.indexOf(u8, &backing, marker) != null;
}

test "wipe: a failed attempt's body is wiped before the next attempt" {
    try testing.expect(!try failedBodySurvives(true));
    // Without the flag the failed body is kept for the next attempt to write
    // over, and what the shorter body does not cover stays readable. That is
    // the leak the flag closes, and it is what makes the check above real.
    try testing.expect(try failedBodySurvives(false));
}

test "wipe: the bearer token does not outlive the call" {
    const token = "ya29.a0-wiped-token-0123456789";
    var h: H = undefined;
    h.init(&.{ok});
    defer h.deinit();
    h.token.token = token;

    // The engine's own scratch memory comes from this allocator.
    var backing: [64 * 1024]u8 = @splat(0);
    var fba: std.heap.FixedBufferAllocator = .init(&backing);
    var e = h.engine();
    e.gpa = fba.allocator();
    _ = try e.execute(&h.arena, .{ .method = .GET, .path = "/v1/things", .wipe = true });
    try testing.expectEqual(null, std.mem.indexOf(u8, &backing, token));
    // The request really did carry it.
    try testing.expectEqualStrings(token, (try h.fake.request(0)).bearer.?);
}

test "error_body_out: the last failed response's body, null on success and with no response" {
    var h: H = undefined;
    h.init(&.{ .{ .respond = .{ .status = 404, .body = "{\"error\":{\"status\":\"NOT_FOUND\",\"details\":[1]}}" } }, ok, .{ .fail = error.ConnectionRefused } });
    defer h.deinit();
    var body: ?[]const u8 = "stale";
    var e = h.engine();
    e.retry = .{ .max_attempts = 1 };
    try testing.expectError(error.NotFound, e.execute(&h.arena, .{ .method = .GET, .path = "/v1/things", .error_body_out = &body }));
    try testing.expectEqualStrings("{\"error\":{\"status\":\"NOT_FOUND\",\"details\":[1]}}", body.?);
    _ = try e.execute(&h.arena, .{ .method = .GET, .path = "/v1/things", .error_body_out = &body });
    try testing.expectEqual(null, body);
    try testing.expectError(error.ConnectionRefused, e.execute(&h.arena, .{ .method = .GET, .path = "/v1/things", .error_body_out = &body }));
    try testing.expectEqual(null, body);
}

fn retryPolicyProperty(_: void, input: []const u8) !void {
    var g: test_util.ByteGen = .init(input);
    const policy: RetryPolicy = .{
        .max_attempts = g.intRange(u8, 1, 6),
        .initial_backoff_ms = g.intRange(u32, 0, 1_000),
        .max_backoff_ms = g.intRange(u32, 0, 10_000),
    };
    var script: [8]Reply = undefined;
    // The delay each reply asks for, as `Retry-After` seconds.
    var delays: [8]?u32 = @splat(null);
    var texts: [8][4]u8 = undefined;
    var headers: [8][1]transport.Header = undefined;
    for (&script, 0..) |*reply, i| reply.* = switch (g.intRange(u8, 0, 4)) {
        0 => ok,
        1 => unavailable,
        2 => .{ .respond = .{ .status = 404, .body = "{}" } },
        3 => r: {
            const seconds = g.intRange(u8, 0, 12);
            delays[i] = @as(u32, seconds) * 1000;
            headers[i] = .{.{ .name = "Retry-After", .value = std.fmt.bufPrint(&texts[i], "{d}", .{seconds}) catch unreachable }};
            break :r .{ .respond = .{ .status = g.pick(u16, &.{ 429, 503 }), .headers = &headers[i], .body = "{}" } };
        },
        else => .{ .fail = error.ConnectionResetByPeer },
    };

    var h: H = undefined;
    h.init(&script);
    defer h.deinit();
    var e = h.engine();
    e.retry = policy;
    const outcome = e.execute(&h.arena, .{ .method = .GET, .path = "/v1/things" });

    const requests = h.fake.requests.items.len;
    try testing.expect(requests >= 1 and requests <= policy.max_attempts);
    // One wait between attempts, none before the first or after the last.
    try testing.expectEqual(requests - 1, h.clock.sleep_count);
    for (0..h.clock.sleep_count) |i| {
        const slept: u32 = @intCast(h.clock.sleepMs(i));
        if (delays[i]) |d| {
            // Never shorter than the server asked, and only ever within
            // the cap, since a longer delay is never waited.
            try testing.expect(slept >= d);
            try testing.expect(d <= policy.max_backoff_ms);
            try testing.expect(slept <= @max(policy.backoffCapMs(@intCast(i + 1)), d));
        } else {
            try testing.expect(slept <= policy.backoffCapMs(@intCast(i + 1)));
        }
    }
    // A run stops at the first reply that is not retryable, or that asks
    // for longer than the cap, and a success is always the last thing that
    // happened.
    const last = requests - 1;
    if (outcome) |_| {
        try testing.expectEqual(Reply.respond, std.meta.activeTag(script[last]));
        try testing.expectEqual(200, script[last].respond.status);
    } else |err| {
        const too_long = if (delays[last]) |d| d > policy.max_backoff_ms else false;
        if (requests < policy.max_attempts) try testing.expect(!GoogleShaped.retryable(err, 0) or too_long);
        try testing.expectEqual(delays[last], h.diag.retry_after_ms);
    }
}

test "fuzz retry: attempts and waits follow the policy for any sequence of failures" {
    try test_util.fuzzBytes({}, retryPolicyProperty, .{ .corpus = &.{
        "\x05\x00\x00\x00\x64\x00\x00\x27\x10\x01\x01\x01\x00\x00\x00\x00",
        "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x03\x03\x03\x03\x03\x03\x03\x03",
        "\x06\x00\x00\x03\xe8\x00\x00\x27\x10\x02\x00\x01\x02\x03\x00\x01",
    } });
}

test "executeStream: a success returns status, headers and body, and sends segments" {
    var h: H = undefined;
    h.init(&.{.{ .respond = .{ .status = 201, .body = "{\"id\":7}", .headers = &.{.{ .name = "ETag", .value = "\"v1\"" }} } }});
    defer h.deinit();
    const e = h.engine();
    const res = try e.executeStream(&h.arena, .{
        .method = .PUT,
        .path = "/v1/objects/a",
        .content_type = "application/octet-stream",
        .body = .{ .segments = &.{ "hel", "lo" } },
    });
    try testing.expectEqual(201, res.status);
    try testing.expectEqualStrings("{\"id\":7}", res.body);
    try testing.expectEqualStrings("\"v1\"", res.header("etag").?);
    const sent = try h.fake.streamRequest(0);
    try testing.expectEqual(5, sent.body_len);
    try testing.expectEqualStrings("hello", sent.body_prefix);
}

test "head_out: the latest attempt's head, null when it got no response, on both entries" {
    // A 503's head, then a dropped connection: the 503's head lived in the
    // response the retry reset, so nothing may point at it after.
    const script = [_]Reply{ unavailable, .{ .fail = error.ConnectionResetByPeer } };
    var h: H = undefined;
    h.init(&script);
    defer h.deinit();
    var e = h.engine();
    e.retry = .{ .max_attempts = 2 };
    var head: ?transport.StreamRequest.Head = null;
    try testing.expectError(error.ConnectionResetByPeer, e.executeStream(&h.arena, .{ .method = .GET, .path = "/v1/things", .head_out = &head }));
    try testing.expectEqual(null, head);

    var hb: H = undefined;
    hb.init(&script);
    defer hb.deinit();
    var eb = hb.engine();
    eb.retry = .{ .max_attempts = 2 };
    var buffered_head: ?transport.StreamRequest.Head = null;
    try testing.expectError(error.ConnectionResetByPeer, eb.execute(&hb.arena, .{ .method = .GET, .path = "/v1/things", .head_out = &buffered_head }));
    try testing.expectEqual(null, buffered_head);
}

test "head_out: execute hands out a success's status and headers, and a refusal's" {
    var h: H = undefined;
    // An accepted long-running write names where to poll, and how long to
    // wait first, beside an empty body.
    h.init(&.{
        .{ .respond = .{ .status = 202, .body = "", .headers = &.{
            .{ .name = "Location", .value = "https://service.example.com/v1/operations/7" },
            .{ .name = "Retry-After", .value = "10" },
        } } },
        .{ .respond = .{ .status = 404, .body = "{\"error\":{\"status\":\"NOT_FOUND\"}}", .headers = &.{.{ .name = "x-request-id", .value = "r-9" }} } },
    });
    defer h.deinit();
    const e = h.engine();
    var head: ?transport.StreamRequest.Head = .{ .status = 1, .headers = &.{} };
    const body = try e.execute(&h.arena, .{ .method = .PUT, .path = "/v1/things/a", .body = "{}", .head_out = &head });
    try testing.expectEqualStrings("", body);
    try testing.expectEqual(202, head.?.status);
    try testing.expectEqualStrings("https://service.example.com/v1/operations/7", head.?.header("location").?);
    try testing.expectEqualStrings("10", head.?.header("retry-after").?);

    try testing.expectError(error.NotFound, e.execute(&h.arena, .{ .method = .GET, .path = "/v1/things/b", .head_out = &head }));
    try testing.expectEqual(404, head.?.status);
    try testing.expectEqualStrings("r-9", head.?.header("x-request-id").?);
}

test "head_out: executeDiscard leaves it null, as it frees the response" {
    var h: H = undefined;
    h.init(&.{.{ .respond = .{ .status = 202, .body = "", .headers = &.{.{ .name = "Location", .value = "/v1/operations/7" }} } }});
    defer h.deinit();
    var head: ?transport.StreamRequest.Head = .{ .status = 1, .headers = &.{} };
    try h.engine().executeDiscard(.{ .method = .DELETE, .path = "/v1/things/1", .head_out = &head });
    try testing.expectEqual(null, head);
}

test "content_type: a call's body goes as the type it names, JSON unless it says" {
    var h: H = undefined;
    h.init(&.{ ok, ok });
    defer h.deinit();
    const e = h.engine();
    _ = try e.execute(&h.arena, .{ .method = .POST, .path = "/token", .body = "grant_type=client_credentials", .content_type = .form });
    _ = try e.execute(&h.arena, .{ .method = .POST, .path = "/v1/things", .body = "{}" });
    try testing.expectEqual(.form, (try h.fake.request(0)).content_type);
    try testing.expectEqual(.json, (try h.fake.request(1)).content_type);
}

test "executeStream: a buffered sink retries statuses and transport failures alike" {
    var h: H = undefined;
    h.init(&.{ unavailable, .{ .fail = error.ConnectionResetByPeer }, ok });
    defer h.deinit();
    _ = try h.engine().executeStream(&h.arena, .{ .method = .GET, .path = "/v1/things" });
    try testing.expectEqual(3, h.fake.stream_requests.items.len);
}

test "executeStream: a writer sink retries a status but never a mid-body failure" {
    var h: H = undefined;
    h.init(&.{
        unavailable,
        .{ .respond = .{ .body = "0123456789", .cut_after = 4 } },
        ok,
    });
    defer h.deinit();
    var out_buf: [64]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    try testing.expectError(error.ConnectionResetByPeer, h.engine().executeStream(&h.arena, .{ .method = .GET, .path = "/v1/o", .sink = .{ .writer = &out } }));
    // The 503 was retried; the cut was not, since part of the body was out.
    try testing.expectEqual(2, h.fake.stream_requests.items.len);
    try testing.expectEqualStrings("0123", out.buffered());
}

test "executeStream: a mid-body failure retries when the sink starts over, and not once it cannot" {
    const Sink = struct {
        out: *std.Io.Writer,
        allowed: usize,

        fn restart(ptr: *anyopaque) bool {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (self.allowed == 0) return false;
            self.allowed -= 1;
            self.out.end = 0;
            return true;
        }
    };
    var h: H = undefined;
    h.init(&.{
        .{ .respond = .{ .body = "0123456789", .cut_after = 4 } },
        .{ .respond = .{ .body = "0123456789" } },
        .{ .respond = .{ .body = "0123456789", .cut_after = 2 } },
        .{ .respond = .{ .body = "0123456789", .cut_after = 3 } },
    });
    defer h.deinit();
    var out_buf: [64]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var sink: Sink = .{ .out = &out, .allowed = 1 };
    const call: StreamCall = .{ .method = .GET, .path = "/v1/o", .sink = .{ .writer = &out }, .restart = .{ .ptr = &sink, .restart = Sink.restart } };
    _ = try h.engine().executeStream(&h.arena, call);
    try testing.expectEqualStrings("0123456789", out.buffered());
    // The sink has spent its one start-over: the next cut is returned.
    out.end = 0;
    try testing.expectError(error.ConnectionResetByPeer, h.engine().executeStream(&h.arena, call));
    try testing.expectEqual(3, h.fake.stream_requests.items.len);
}

test "executeStream: a 401 is retried once with a fresh token, whatever the sink" {
    var h: H = undefined;
    h.init(&.{ unauthorized, ok });
    defer h.deinit();
    var out_buf: [64]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    _ = try h.engine().executeStream(&h.arena, .{ .method = .GET, .path = "/v1/o", .sink = .{ .writer = &out } });
    try testing.expectEqual(2, h.fake.stream_requests.items.len);
    try testing.expectEqual(1, h.token.invalidations);
}

test "executeStreamBody: the reader's bytes go once; a transient failure and a 401 come back" {
    var h: H = undefined;
    h.init(&.{ ok, unavailable, unauthorized, ok });
    defer h.deinit();
    const e = h.engine();
    for (0..3) |i| {
        var reader: std.Io.Reader = .fixed("payload");
        const outcome = e.executeStreamBody(&h.arena, .{ .method = .PUT, .path = "/v1/o" }, .{ .reader = &reader, .len = 7 });
        switch (i) {
            0 => _ = try outcome,
            1 => try testing.expectError(error.Unavailable, outcome),
            else => try testing.expectError(error.Unauthenticated, outcome),
        }
    }
    // One request each: a streamed body is never sent twice.
    try testing.expectEqual(3, h.fake.stream_requests.items.len);
    try testing.expectEqual(7, (try h.fake.streamRequest(0)).body_len);
    // The 401 dropped the token, for the caller's next try.
    try testing.expectEqual(1, h.token.invalidations);
}

// Azure Resource Manager's shape, through the same loop.

const ArmH = Harness(ArmEngine);

test "ARM: x-ms-retry-after-ms is waited, and the code and both ids are kept" {
    var h: ArmH = undefined;
    const throttled: Reply = .{ .respond = .{
        .status = 429,
        .headers = &.{
            .{ .name = "x-ms-retry-after-ms", .value = "1500" },
            .{ .name = "x-ms-request-id", .value = "0d3f4c11-7b2a-4e9b-a1e0-5c6d7e8f9a0b" },
            .{ .name = "x-ms-correlation-request-id", .value = "7a9b8c6d-5e4f-4a3b-9c2d-1e0f2a3b4c5d" },
        },
        .body = "{\"error\":{\"code\":\"TooManyRequests\",\"message\":\"The request is being throttled.\"}}",
    } };
    h.init(&.{ throttled, .{ .respond = .{ .body = "{\"id\":\"/subscriptions/s\"}" } } });
    defer h.deinit();
    _ = try h.get();
    try testing.expectEqual(2, h.fake.requests.items.len);
    try testing.expectEqual(1_500, h.clock.sleepMs(0));

    var lone: ArmH = undefined;
    lone.init(&.{throttled});
    defer lone.deinit();
    var e = lone.engine();
    e.retry = .{ .max_attempts = 1 };
    try testing.expectError(error.TooManyRequests, e.execute(&lone.arena, .{ .method = .GET, .path = "/subscriptions" }));
    try testing.expectEqualStrings("TooManyRequests", lone.diag.code());
    try testing.expectEqualStrings("The request is being throttled.", lone.diag.message());
    try testing.expectEqualStrings("0d3f4c11-7b2a-4e9b-a1e0-5c6d7e8f9a0b", lone.diag.requestId());
    try testing.expectEqualStrings("7a9b8c6d-5e4f-4a3b-9c2d-1e0f2a3b4c5d", lone.diag.correlationId());
    try testing.expectEqual(1_500, lone.diag.retry_after_ms.?);
}

test "ARM: 408, 429 and 5xx are retried; 404 and 409 are not" {
    for ([_]u16{ 408, 429, 500, 502, 503, 504 }) |status| {
        var h: ArmH = undefined;
        h.init(&.{ .{ .respond = .{ .status = status, .body = "{}" } }, ok });
        defer h.deinit();
        _ = try h.get();
        try testing.expectEqual(2, h.fake.requests.items.len);
    }
    for ([_]u16{ 404, 409 }) |status| {
        var h: ArmH = undefined;
        h.init(&.{ .{ .respond = .{ .status = status, .body = "{\"error\":{\"code\":\"ResourceNotFound\",\"message\":\"gone\"}}" } }, ok });
        defer h.deinit();
        if (h.get()) |_| return error.TestUnexpectedResult else |_| {}
        try testing.expectEqual(1, h.fake.requests.items.len);
    }
}

test "ARM: a Blob Storage error's code comes from x-ms-error-code" {
    var h: ArmH = undefined;
    h.init(&.{.{ .respond = .{
        .status = 412,
        .headers = &.{.{ .name = "x-ms-error-code", .value = "ConditionNotMet" }},
        .body = "<?xml version=\"1.0\" encoding=\"utf-8\"?><Error><Code>ConditionNotMet</Code><Message>The condition specified using HTTP conditional header(s) is not met.</Message></Error>",
    } }});
    defer h.deinit();
    try testing.expectError(error.PreconditionFailed, h.get());
    try testing.expectEqualStrings("ConditionNotMet", h.diag.code());
}

test "ARM: a HEAD through executeStream: a blob's properties in its headers, a refusal's code too" {
    var h: ArmH = undefined;
    // The scripted bodies are never delivered: a HEAD's answer has none.
    h.init(&.{
        .{ .respond = .{ .status = 404, .body = "not sent", .headers = &.{
            .{ .name = "x-ms-error-code", .value = "BlobNotFound" },
            .{ .name = "x-ms-request-id", .value = "req-1" },
        } } },
        .{ .respond = .{ .body = "not sent", .headers = &.{
            .{ .name = "Content-Length", .value = "1048576" },
            .{ .name = "x-ms-meta-token", .value = "w1" },
        } } },
    });
    defer h.deinit();
    const e = h.engine();

    e.begin();
    try testing.expectError(error.NotFound, e.executeStream(&h.arena, .{ .method = .HEAD, .path = "/c/gone" }));
    try testing.expectEqualStrings("BlobNotFound", h.diag.code());
    try testing.expectEqualStrings("", h.diag.message());
    try testing.expectEqualStrings("req-1", h.diag.requestId());

    e.begin();
    const res = try e.executeStream(&h.arena, .{ .method = .HEAD, .path = "/c/b" });
    try testing.expectEqual(200, res.status);
    try testing.expectEqualStrings("", res.body);
    try testing.expectEqualStrings("1048576", res.header("content-length").?);
    try testing.expectEqualStrings("w1", res.header("x-ms-meta-token").?);
    const sent = try h.fake.streamRequest(1);
    try testing.expectEqual(.HEAD, sent.method);
    try testing.expectEqual(.none, sent.body_tag);
}

test "ARM: a 401 refreshes the token once, as it does for any cloud" {
    var h: ArmH = undefined;
    h.init(&.{ .{ .respond = .{ .status = 401, .body = "{\"error\":{\"code\":\"InvalidAuthenticationToken\"}}" } }, ok });
    defer h.deinit();
    _ = try h.get();
    try testing.expectEqual(1, h.token.invalidations);
    try testing.expectEqual(2, h.fake.requests.items.len);
}
