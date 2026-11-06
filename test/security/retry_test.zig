//! Retries against a server that asks for a delay built to stall or
//! overflow the client.

const std = @import("std");
const rest_core = @import("rest_core");
const retry_after = rest_core.retry_after;
const RetryPolicy = rest_core.RetryPolicy;
const testing = std.testing;

test "security: CWE-400 a Retry-After built to stall or overflow neither sleeps for ever nor wraps" {
    const now: std.Io.Timestamp = .{ .nanoseconds = 1_792_255_951 * std.time.ns_per_s };
    const max = std.math.maxInt(u32);
    // Huge values saturate at maxInt(u32) milliseconds, never wrap to a short
    // wait; a date in year 9999 does the same.
    for ([_][2][]const u8{
        .{ "Retry-After", "99999999999999999999999999999999999999999" },
        .{ "retry-after-ms", "18446744073709551616" },
        .{ "x-ms-retry-after-ms", "99999999999999999999" },
        .{ "Retry-After", "Fri, 31 Dec 9999 23:59:59 GMT" },
    }) |h| {
        try testing.expectEqual(max, retry_after.serverDelayMs(std.http.Header, &.{.{ .name = h[0], .value = h[1] }}, now).?);
    }
    // Negative, fractional, signed, malformed and empty values are ignored:
    // the server asked for nothing.
    for ([_][]const u8{ "-1", "1.5", "+5", "1e9", "soon", "" }) |value| {
        try testing.expectEqual(null, retry_after.serverDelayMs(std.http.Header, &.{.{ .name = "Retry-After", .value = value }}, now));
    }
    // A date in the past waits nothing, the year 0000 included.
    try testing.expectEqual(0, retry_after.serverDelayMs(std.http.Header, &.{.{ .name = "Retry-After", .value = "Thu, 01 Jan 1970 00:00:00 GMT" }}, now).?);
    try testing.expectEqual(0, retry_after.serverDelayMs(std.http.Header, &.{.{ .name = "Retry-After", .value = "Sat, 01 Jan 0000 00:00:00 GMT" }}, now).?);

    // And a delay past the policy's cap is no wait at all: the failure goes
    // back to the caller, rather than a task asleep for 49 days.
    const policy: RetryPolicy = .{};
    try testing.expectEqual(null, policy.waitMs(1, 0, max));
    try testing.expectEqual(null, policy.waitMs(1, 0, policy.max_backoff_ms + 1));
    try testing.expectEqual(policy.max_backoff_ms, policy.waitMs(1, 0, policy.max_backoff_ms).?);
}
