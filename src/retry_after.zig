// From gcp.zig src/core/retry_after.zig at eae944c: its header readers and their tests. google.rpc.RetryInfo stays Google's, read by the cloud's hook; the HTTP-date parser moved to http_date.zig; x-ms-retry-after-ms is new.
//! A server's retry delay: how long a refused response's headers asked its
//! client to wait before trying again. Three headers are read, and the
//! largest valid delay kept, since each means "at least this long":
//!
//! - `Retry-After`, RFC 9110 section 10.2.3: delay-seconds, or an HTTP-date
//!   in any of the three formats a recipient must accept, read against the
//!   response's own `Date` when it has one (RFC 9111 measures a server's
//!   dates that way, to cancel clock skew), else against when the response
//!   arrived;
//! - `retry-after-ms`, milliseconds, which Google's front end sends beside
//!   `Retry-After` and Azure defines;
//! - `x-ms-retry-after-ms`, milliseconds, Azure's.
//!
//! A delay a body carries (Google's `google.rpc.RetryInfo` in an error's
//! `details`) is the cloud's to read, through the request loop's hook; the
//! loop keeps the larger of the two (`larger`).
//!
//! A malformed, negative or empty value is ignored, never an error, and a
//! delay past `maxInt(u32)` milliseconds (49.7 days) saturates there with no
//! overflow on the way. `RetryPolicy.waitMs` then returns a failure to the
//! caller rather than sleeping on a delay past its `max_backoff_ms`.
//!
//! `Asked` writes a delay in any of the headers, for the fakes, whose
//! scripted refusals stand in for a server that asks.

const std = @import("std");
const Allocator = std.mem.Allocator;
const http_date = @import("http_date.zig");
const transport = @import("transport.zig");

const max_ms = std.math.maxInt(u32);

/// The delay a refused response's headers asked for, in milliseconds, or
/// null when they asked for none. `received_at` is the wall clock when it
/// arrived.
pub fn serverDelayMs(headers: []const transport.Header, received_at: std.Io.Timestamp) ?u32 {
    var best: ?u32 = null;
    const date = header(headers, "date");
    for (headers) |h| best = larger(best, headerDelayMs(h, date, received_at));
    return best;
}

/// The delay one header asks for, if it is one of the three.
fn headerDelayMs(h: transport.Header, date: ?[]const u8, received_at: std.Io.Timestamp) ?u32 {
    if (std.ascii.eqlIgnoreCase(h.name, "retry-after")) return retryAfterMs(h.value, date, received_at);
    if (std.ascii.eqlIgnoreCase(h.name, "retry-after-ms")) return millisecondsMs(h.value);
    if (std.ascii.eqlIgnoreCase(h.name, "x-ms-retry-after-ms")) return millisecondsMs(h.value);
    return null;
}

/// The larger of two delays, either of which may be missing: how the request
/// loop joins the headers' delay with the one a cloud's hook reads from the
/// body.
pub fn larger(a: ?u32, b: ?u32) ?u32 {
    const x = a orelse return b;
    const y = b orelse return x;
    return @max(x, y);
}

fn header(headers: []const transport.Header, name: []const u8) ?[]const u8 {
    for (headers) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    return null;
}

const ows = " \t";

/// A `Retry-After` value: delay-seconds, or an HTTP-date measured from the
/// response's `Date` (`date`, when present and valid) or else from
/// `received_at`. A date in the past is 0.
pub fn retryAfterMs(value: []const u8, date: ?[]const u8, received_at: std.Io.Timestamp) ?u32 {
    const text = std.mem.trim(u8, value, ows);
    if (digitsMs(text, 1000)) |ms| return ms;
    const target = http_date.unixSeconds(text) orelse return null;
    const base: i64 = if (date) |d| http_date.unixSeconds(std.mem.trim(u8, d, ows)) orelse nowSeconds(received_at) else nowSeconds(received_at);
    if (target <= base) return 0;
    const seconds: u64 = @intCast(target - base);
    return saturate(@as(u128, seconds) * 1000);
}

fn nowSeconds(t: std.Io.Timestamp) i64 {
    return @intCast(@divFloor(t.nanoseconds, std.time.ns_per_s));
}

/// A `retry-after-ms` or `x-ms-retry-after-ms` value: a non-negative integer
/// of milliseconds.
pub fn millisecondsMs(value: []const u8) ?u32 {
    return digitsMs(std.mem.trim(u8, value, ows), 1);
}

/// `1*DIGIT` times `unit_ms`, saturating; null for anything else.
fn digitsMs(text: []const u8, unit_ms: u32) ?u32 {
    if (text.len == 0) return null;
    var n: u128 = 0;
    for (text) |c| {
        if (!std.ascii.isDigit(c)) return null;
        // Past this the result saturates whatever digits follow.
        if (n <= max_ms) n = n * 10 + (c - '0');
    }
    return saturate(n * unit_ms);
}

fn saturate(n: u128) u32 {
    return if (n > max_ms) max_ms else @intCast(n);
}

/// A delay a server asks for, and the header or headers it asks in: what
/// the fakes script on the refusals they inject, so that a caller's offline
/// checks can drive its own scheduling.
pub const Asked = struct {
    ms: u32,
    form: Form = .all,

    pub const Form = enum {
        /// `Retry-After`, in whole seconds, rounded up.
        retry_after,
        /// `retry-after-ms`.
        retry_after_ms,
        /// `x-ms-retry-after-ms`.
        x_ms_retry_after_ms,
        /// `Retry-After` and `retry-after-ms` at once, as Google's front end
        /// sends them.
        all,
    };

    /// The headers that carry it, in `arena`.
    pub fn headers(a: Asked, arena: Allocator) Allocator.Error![]const transport.Header {
        var list: std.ArrayList(transport.Header) = .empty;
        if (a.form == .retry_after or a.form == .all) {
            try list.append(arena, .{ .name = "Retry-After", .value = try arena.print("{d}", .{a.seconds()}) });
        }
        if (a.form == .retry_after_ms or a.form == .all) {
            try list.append(arena, .{ .name = "retry-after-ms", .value = try arena.print("{d}", .{a.ms}) });
        }
        if (a.form == .x_ms_retry_after_ms) {
            try list.append(arena, .{ .name = "x-ms-retry-after-ms", .value = try arena.print("{d}", .{a.ms}) });
        }
        return list.items;
    }

    /// What a client that reads every header, as `serverDelayMs` does, takes
    /// it for: `Retry-After`'s seconds are rounded up, and the largest wins.
    pub fn readMs(a: Asked) u32 {
        return switch (a.form) {
            .retry_after, .all => saturate(@as(u128, a.seconds()) * std.time.ms_per_s),
            .retry_after_ms, .x_ms_retry_after_ms => a.ms,
        };
    }

    fn seconds(a: Asked) u32 {
        return a.ms / std.time.ms_per_s + @intFromBool(a.ms % std.time.ms_per_s != 0);
    }
};

const testing = std.testing;
const test_util = @import("testing.zig");

fn at(seconds: i64) std.Io.Timestamp {
    return .{ .nanoseconds = @as(i96, seconds) * std.time.ns_per_s };
}

/// 1994-11-06T08:49:37Z, RFC 9110's example.
const example: i64 = 784111777;

test "retryAfterMs: seconds, saturating; a date against the response's Date, else the clock" {
    const now = at(example);
    try testing.expectEqual(120_000, retryAfterMs("120", null, now).?);
    try testing.expectEqual(0, retryAfterMs("0", null, now).?);
    try testing.expectEqual(1_000, retryAfterMs(" 1\t", null, now).?);
    try testing.expectEqual(5_000, retryAfterMs("0005", null, now).?);
    // GoDaddy's, and far past it: saturated, never wrapped.
    try testing.expectEqual(std.math.maxInt(u32), retryAfterMs("9223372037", null, now).?);
    try testing.expectEqual(std.math.maxInt(u32), retryAfterMs("99999999999999999999999999999999999999999", null, now).?);
    try testing.expectEqual(4_294_967_000, retryAfterMs("4294967", null, now).?);
    try testing.expectEqual(std.math.maxInt(u32), retryAfterMs("4294968", null, now).?);
    for ([_][]const u8{ "", " ", "-1", "1.5", "+1", "1e3", "1 2", "soon" }) |bad| try testing.expectEqual(null, retryAfterMs(bad, null, now));

    // A date: from the response's Date when it has one, which cancels a
    // client clock that is an hour fast.
    const date = "Sun, 06 Nov 1994 08:49:37 GMT";
    const later = "Sun, 06 Nov 1994 08:50:07 GMT";
    try testing.expectEqual(30_000, retryAfterMs(later, date, at(example + 3600)).?);
    try testing.expectEqual(30_000, retryAfterMs(later, null, now).?);
    // A broken Date falls back to the clock; a date in the past is now.
    try testing.expectEqual(30_000, retryAfterMs(later, "yesterday", now).?);
    try testing.expectEqual(0, retryAfterMs(date, null, at(example + 1)).?);
    try testing.expectEqual(0, retryAfterMs(date, later, now).?);
    try testing.expectEqual(std.math.maxInt(u32), retryAfterMs("Fri, 31 Dec 9999 23:59:59 GMT", null, now).?);
}

test "millisecondsMs" {
    try testing.expectEqual(831, millisecondsMs("831").?);
    try testing.expectEqual(0, millisecondsMs("0").?);
    try testing.expectEqual(std.math.maxInt(u32), millisecondsMs("4294967296").?);
    for ([_][]const u8{ "", "-1", "1.5", "831ms" }) |bad| try testing.expectEqual(null, millisecondsMs(bad));
}

test "serverDelayMs: the largest of the headers, as Google's front end and Azure send them" {
    const now = at(1_792_255_951);
    // jenslys/opencode-gemini-auth#48: one 429 from ESF with both headers
    // (and a RetryInfo in its body, which is the cloud's hook's to read).
    try testing.expectEqual(1_000, serverDelayMs(&.{
        .{ .name = "date", .value = "Sat, 07 Feb 2026 15:08:40 GMT" },
        .{ .name = "retry-after", .value = "1" },
        .{ .name = "retry-after-ms", .value = "831" },
        .{ .name = "server", .value = "ESF" },
    }, now).?);
    try testing.expectEqual(831, serverDelayMs(&.{.{ .name = "Retry-After-Ms", .value = "831" }}, now).?);
    // Azure's own header, alone and beside Retry-After.
    try testing.expectEqual(2_500, serverDelayMs(&.{.{ .name = "x-ms-retry-after-ms", .value = "2500" }}, now).?);
    try testing.expectEqual(3_000, serverDelayMs(&.{ .{ .name = "Retry-After", .value = "3" }, .{ .name = "x-ms-retry-after-ms", .value = "2500" } }, now).?);
    // Two Retry-After headers: the larger.
    try testing.expectEqual(7_000, serverDelayMs(&.{ .{ .name = "Retry-After", .value = "7" }, .{ .name = "Retry-After", .value = "2" } }, now).?);
    // An invalid one beside a valid one is ignored.
    try testing.expectEqual(2_000, serverDelayMs(&.{ .{ .name = "Retry-After", .value = "soon" }, .{ .name = "Retry-After", .value = "2" } }, now).?);
}

test "serverDelayMs: what Google's production sent on 2026-10-16 and 17 asks for nothing" {
    const now = at(1_792_255_951);
    // Logging's quota 429, from ESF, with every header it carried.
    try testing.expectEqual(null, serverDelayMs(&.{
        .{ .name = "Vary", .value = "X-Origin" },
        .{ .name = "Content-Type", .value = "application/json; charset=UTF-8" },
        .{ .name = "Date", .value = "Sat, 17 Oct 2026 16:53:10 GMT" },
        .{ .name = "Server", .value = "ESF" },
        .{ .name = "Server-Timing", .value = "gfet4t7; dur=19" },
    }, now));
    // Cloud Storage's XML 429.
    try testing.expectEqual(null, serverDelayMs(&.{
        .{ .name = "Content-Type", .value = "application/xml; charset=UTF-8" },
        .{ .name = "Date", .value = "Sat, 17 Oct 2026 16:52:31 GMT" },
        .{ .name = "Server", .value = "UploadServer" },
    }, now));
}

test "larger: either may be missing" {
    try testing.expectEqual(null, larger(null, null));
    try testing.expectEqual(5, larger(5, null).?);
    try testing.expectEqual(5, larger(null, 5).?);
    try testing.expectEqual(9, larger(9, 5).?);
}

test "Asked: each form, written as servers write it, and read back" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const header_only: Asked = .{ .ms = 1_500, .form = .retry_after };
    const sent = try header_only.headers(a);
    try testing.expectEqual(1, sent.len);
    try testing.expectEqualStrings("Retry-After", sent[0].name);
    try testing.expectEqualStrings("2", sent[0].value);
    try testing.expectEqual(2_000, header_only.readMs());

    const ms_only: Asked = .{ .ms = 1_500, .form = .retry_after_ms };
    try testing.expectEqualStrings("retry-after-ms", (try ms_only.headers(a))[0].name);
    try testing.expectEqualStrings("1500", (try ms_only.headers(a))[0].value);
    try testing.expectEqual(1_500, ms_only.readMs());

    const azure: Asked = .{ .ms = 1_500, .form = .x_ms_retry_after_ms };
    try testing.expectEqualStrings("x-ms-retry-after-ms", (try azure.headers(a))[0].name);
    try testing.expectEqual(1_500, azure.readMs());
    try testing.expectEqual(1_500, serverDelayMs(try azure.headers(a), at(0)).?);

    const all: Asked = .{ .ms = 1_500 };
    try testing.expectEqual(2, (try all.headers(a)).len);
    try testing.expectEqual(2_000, all.readMs());
    try testing.expectEqual(2_000, serverDelayMs(try all.headers(a), at(0)).?);
    // The longest delay there is: the header's seconds saturate.
    try testing.expectEqual(max_ms, (Asked{ .ms = max_ms }).readMs());
    try testing.expectEqual(0, (Asked{ .ms = 0 }).readMs());
}

test "Asked: every allocation failure is OutOfMemory without leaks" {
    const Run = struct {
        fn run(gpa: Allocator) !void {
            var arena: std.heap.ArenaAllocator = .init(gpa);
            defer arena.deinit();
            const a: Asked = .{ .ms = 2_250 };
            _ = try a.headers(arena.allocator());
        }
    };
    try testing.checkAllAllocationFailures(std.testing.allocator, Run.run, .{});
}

fn askedProperty(_: void, input: []const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(std.heap.smp_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var g: test_util.ByteGen = .init(input);
    // Whatever is asked, in whatever header, is read back as `readMs`.
    const asked: Asked = .{ .ms = g.int(u32), .form = g.pick(Asked.Form, &.{ .retry_after, .retry_after_ms, .x_ms_retry_after_ms, .all }) };
    try testing.expectEqual(asked.readMs(), serverDelayMs(try asked.headers(a), at(1_792_255_951)).?);
}

test "fuzz Asked: any delay in any form reads back as readMs says" {
    try test_util.fuzzBytes({}, askedProperty, .{ .corpus = &.{ "", "\xff\xff\xff\xff\x03", "\xdc\x05\x00\x00\x02\x00" } });
}

fn delayProperty(_: void, input: []const u8) !void {
    var g: test_util.ByteGen = .init(input);
    // Arbitrary headers: never a crash, and the answer is the largest each
    // header gives alone.
    var headers: [4]transport.Header = undefined;
    const n = g.intRange(usize, 0, headers.len);
    for (headers[0..n]) |*h| h.* = .{
        .name = g.pick([]const u8, &.{ "Retry-After", "retry-after-ms", "x-ms-retry-after-ms", "Date", "X-Other" }),
        .value = g.slice(40),
    };
    const now = at(1_792_255_951);
    const got = serverDelayMs(headers[0..n], now);
    var want: ?u32 = null;
    const date = header(headers[0..n], "date");
    for (headers[0..n]) |h| {
        const one = if (std.mem.eql(u8, h.name, "Retry-After"))
            retryAfterMs(h.value, date, now)
        else if (std.mem.eql(u8, h.name, "retry-after-ms") or std.mem.eql(u8, h.name, "x-ms-retry-after-ms"))
            millisecondsMs(h.value)
        else
            null;
        want = larger(want, one);
    }
    try testing.expectEqual(want, got);
}

test "fuzz serverDelayMs: arbitrary headers, the largest of each alone" {
    try test_util.fuzzBytes({}, delayProperty, .{ .corpus = &.{ "", "\x02\x00\x033\x00\x00", "\x01\x02\x0580000" } });
}
