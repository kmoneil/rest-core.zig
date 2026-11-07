// From gcp.zig src/core/retry_after.zig at eae944c: its HTTP-date parser and tests, moved here. `parse` and `format` are new.
//! HTTP dates (RFC 9110 5.6.7): read in any of RFC 9110's three formats,
//! written as IMF-fixdate, the RFC 1123 form servers send
//! (`Sun, 06 Nov 1994 08:49:37 GMT`). Retry-After and Date carry them, as do
//! Azure's `x-ms-date` and Scheduled Events' `NotBefore`. RFC 9110 says a
//! recipient must accept all three formats, so this one does.

const std = @import("std");
const timestamp = @import("timestamp.zig");
const test_util = @import("testing.zig");

/// `parse`'s one error: text in none of RFC 9110's three formats, or an
/// instant outside `timestamp`'s range.
pub const ParseError = error{InvalidHttpDate};

/// The length of an IMF-fixdate, the text `format` writes.
pub const len = 29;

const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
const day_names = [_][]const u8{ "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun" };
const long_day_names = [_][]const u8{ "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday" };

/// An HTTP-date as an instant, as `unixSeconds` reads it. A text that is
/// not an HTTP-date, or one outside what `timestamp` can write (the year
/// 0000), is `error.InvalidHttpDate`, so whatever this returns, `format` and
/// `timestamp.format` can write.
pub fn parse(text: []const u8) ParseError!std.Io.Timestamp {
    const seconds = unixSeconds(text) orelse return error.InvalidHttpDate;
    const ts: std.Io.Timestamp = .{ .nanoseconds = @as(i96, seconds) * std.time.ns_per_s };
    if (!timestamp.inRange(ts)) return error.InvalidHttpDate;
    return ts;
}

/// Writes `ts` as an IMF-fixdate, to the second: its fraction is dropped,
/// so an instant is written as the second it falls in, before the epoch
/// too. An instant past `timestamp.min` or `timestamp.max` is written as
/// that end.
pub fn format(buf: *[len]u8, ts: std.Io.Timestamp) []const u8 {
    const ns = std.math.clamp(ts.nanoseconds, timestamp.min.nanoseconds, timestamp.max.nanoseconds);
    const seconds: i64 = @intCast(@divFloor(ns, std.time.ns_per_s));
    const days = @divFloor(seconds, std.time.s_per_day);
    const secs_of_day = @mod(seconds, std.time.s_per_day);
    const date = timestamp.civilFromDays(days);
    // 1970-01-01 was a Thursday.
    const weekday: usize = @intCast(@mod(days + 3, 7));
    var w: std.Io.Writer = .fixed(buf);
    // Fits: a clamped year has four digits, so the text is `len` long.
    w.print("{s}, {d:0>2} {s} {d:0>4} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
        day_names[weekday],
        @as(u64, @intCast(date.day)),
        months[@intCast(date.month - 1)],
        @as(u64, @intCast(date.year)),
        @as(u64, @intCast(@divFloor(secs_of_day, 3600))),
        @as(u64, @intCast(@mod(@divFloor(secs_of_day, 60), 60))),
        @as(u64, @intCast(@mod(secs_of_day, 60))),
    }) catch unreachable;
    return w.buffered();
}

/// An HTTP-date in Unix seconds, in any of RFC 9110's three formats:
/// IMF-fixdate "Sun, 06 Nov 1994 08:49:37 GMT", rfc850-date
/// "Sunday, 06-Nov-94 08:49:37 GMT", and asctime-date
/// "Sun Nov  6 08:49:37 1994". Case-sensitive, as RFC 9110 says. The
/// weekday is not checked against the date. A two-digit year is read in
/// 1950 to 2049, which is RFC 9110's rule ("more than 50 years in the
/// future" is the past) for any year this library will run in.
pub fn unixSeconds(text: []const u8) ?i64 {
    if (imfFixdate(text)) |t| return t;
    if (rfc850Date(text)) |t| return t;
    return asctimeDate(text);
}

fn imfFixdate(t: []const u8) ?i64 {
    // "Sun, 06 Nov 1994 08:49:37 GMT"
    if (t.len != 29 or !isOneOf(t[0..3], &day_names) or !std.mem.eql(u8, t[3..5], ", ") or t[7] != ' ' or t[11] != ' ' or t[16] != ' ' or !std.mem.eql(u8, t[25..], " GMT")) return null;
    const day = number(t[5..7]) orelse return null;
    const month = monthOf(t[8..11]) orelse return null;
    const year = number(t[12..16]) orelse return null;
    return civil(year, month, day, t[17..25]);
}

fn rfc850Date(t: []const u8) ?i64 {
    // "Sunday, 06-Nov-94 08:49:37 GMT"
    const comma = std.mem.indexOfScalar(u8, t, ',') orelse return null;
    if (!isOneOf(t[0..comma], &long_day_names)) return null;
    const rest = t[comma..];
    if (rest.len != 24 or rest[1] != ' ' or rest[4] != '-' or rest[8] != '-' or rest[11] != ' ' or !std.mem.eql(u8, rest[20..], " GMT")) return null;
    const day = number(rest[2..4]) orelse return null;
    const month = monthOf(rest[5..8]) orelse return null;
    const yy = number(rest[9..11]) orelse return null;
    const year = if (yy < 50) 2000 + yy else 1900 + yy;
    return civil(year, month, day, rest[12..20]);
}

fn asctimeDate(t: []const u8) ?i64 {
    // "Sun Nov  6 08:49:37 1994"
    if (t.len != 24 or !isOneOf(t[0..3], &day_names) or t[3] != ' ' or t[7] != ' ' or t[10] != ' ' or t[19] != ' ') return null;
    const month = monthOf(t[4..7]) orelse return null;
    const day = if (t[8] == ' ') number(t[9..10]) orelse return null else number(t[8..10]) orelse return null;
    const year = number(t[20..24]) orelse return null;
    return civil(year, month, day, t[11..19]);
}

fn isOneOf(text: []const u8, names: []const []const u8) bool {
    for (names) |n| if (std.mem.eql(u8, text, n)) return true;
    return false;
}

fn monthOf(text: []const u8) ?i64 {
    for (months, 1..) |m, i| if (std.mem.eql(u8, text, m)) return @intCast(i);
    return null;
}

fn number(text: []const u8) ?i64 {
    var n: i64 = 0;
    for (text) |c| {
        if (!std.ascii.isDigit(c)) return null;
        n = n * 10 + (c - '0');
    }
    return n;
}

/// "08:49:37" on a date, in Unix seconds; a leap second (60) is read as 59.
fn civil(year: i64, month: i64, day: i64, time: []const u8) ?i64 {
    if (time.len != 8 or time[2] != ':' or time[5] != ':') return null;
    const hour = number(time[0..2]) orelse return null;
    const minute = number(time[3..5]) orelse return null;
    const second = number(time[6..8]) orelse return null;
    if (hour > 23 or minute > 59 or second > 60) return null;
    if (day < 1 or day > daysIn(year, month)) return null;
    return timestamp.daysFromCivil(year, month, day) * std.time.s_per_day + hour * 3600 + minute * 60 + @min(second, 59);
}

fn daysIn(year: i64, month: i64) i64 {
    return switch (month) {
        2 => if (@mod(year, 4) == 0 and (@mod(year, 100) != 0 or @mod(year, 400) == 0)) 29 else 28,
        4, 6, 9, 11 => 30,
        else => 31,
    };
}

const testing = std.testing;

/// 1994-11-06T08:49:37Z, RFC 9110's example.
const example: i64 = 784111777;

fn at(seconds: i64) std.Io.Timestamp {
    return .{ .nanoseconds = @as(i96, seconds) * std.time.ns_per_s };
}

test "unixSeconds: RFC 9110's three formats, its example, and what is not one" {
    try testing.expectEqual(example, unixSeconds("Sun, 06 Nov 1994 08:49:37 GMT").?);
    try testing.expectEqual(example, unixSeconds("Sunday, 06-Nov-94 08:49:37 GMT").?);
    try testing.expectEqual(example, unixSeconds("Sun Nov  6 08:49:37 1994").?);
    try testing.expectEqual(example, unixSeconds("Sun Nov 06 08:49:37 1994").?);
    // Two-digit years: 49 is 2049, 50 is 1950.
    try testing.expectEqual(unixSeconds("Wed, 01 Jan 2049 00:00:00 GMT").?, unixSeconds("Wednesday, 01-Jan-49 00:00:00 GMT").?);
    try testing.expectEqual(unixSeconds("Sun, 01 Jan 1950 00:00:00 GMT").?, unixSeconds("Sunday, 01-Jan-50 00:00:00 GMT").?);
    try testing.expectEqual(@as(i64, 0), unixSeconds("Thu, 01 Jan 1970 00:00:00 GMT").?);
    // Leap days, century years by the Gregorian rule, and a leap second
    // read as the second before.
    try testing.expect(unixSeconds("Thu, 29 Feb 2024 12:00:00 GMT") != null);
    try testing.expect(unixSeconds("Tue, 29 Feb 2000 12:00:00 GMT") != null);
    try testing.expectEqual(null, unixSeconds("Thu, 29 Feb 2100 12:00:00 GMT"));
    try testing.expectEqual(null, unixSeconds("Thu, 29 Feb 1900 12:00:00 GMT"));
    try testing.expectEqual(unixSeconds("Wed, 31 Dec 2025 23:59:59 GMT").?, unixSeconds("Wed, 31 Dec 2025 23:59:60 GMT").?);
    for ([_][]const u8{
        "",                                 "Sun, 06 Nov 1994 08:49:37 UTC",  "sun, 06 Nov 1994 08:49:37 GMT",
        "Sun, 06 nov 1994 08:49:37 GMT",    "Sun, 6 Nov 1994 08:49:37 GMT",   "Sun, 06 Nov 1994 8:49:37 GMT",
        "Sun, 31 Feb 1994 08:49:37 GMT",    "Sun, 29 Feb 2023 08:49:37 GMT",  "Sun, 06 Nov 1994 24:00:00 GMT",
        "Sun, 06 Nov 1994 08:60:00 GMT",    "Sun, 06 Nov 1994 08:49:61 GMT",  "Sun, 00 Nov 1994 08:49:37 GMT",
        "Sunday, 06-Nov-1994 08:49:37 GMT", "Sun, 06-Nov-94 08:49:37 GMT",    "Sun Nov 6 08:49:37 1994",
        "Sun Nov  6 08:49:37 94",           "Sun, 06 Nov 1994 08:49:37 GMT ", "Sun, 06 Nov 1994 08:49:37 GMTX",
        "120",                              "Funday, 06-Nov-94 08:49:37 GMT", "Sun, 06 Nov 19x4 08:49:37 GMT",
    }) |bad| {
        if (unixSeconds(bad) != null) {
            std.debug.print("read: {s}\n", .{bad});
            return error.TestExpectedNull;
        }
    }
}

test "parse: an instant timestamp can write, or InvalidHttpDate" {
    try testing.expectEqual(at(example), try parse("Sun, 06 Nov 1994 08:49:37 GMT"));
    try testing.expectEqual(timestamp.max.nanoseconds - 999_999_999, (try parse("Fri, 31 Dec 9999 23:59:59 GMT")).nanoseconds);
    try testing.expectEqual(timestamp.min, try parse("Mon, 01 Jan 0001 00:00:00 GMT"));
    // The year 0000 reads as an HTTP-date, and is before what can be written.
    try testing.expect(unixSeconds("Sat, 01 Jan 0000 00:00:00 GMT") != null);
    try testing.expectError(error.InvalidHttpDate, parse("Sat, 01 Jan 0000 00:00:00 GMT"));
    try testing.expectError(error.InvalidHttpDate, parse("120"));
}

test "format writes IMF-fixdate: RFC 9110's example, the epoch, the range's ends" {
    var buf: [len]u8 = undefined;
    try testing.expectEqualStrings("Sun, 06 Nov 1994 08:49:37 GMT", format(&buf, at(example)));
    try testing.expectEqualStrings("Thu, 01 Jan 1970 00:00:00 GMT", format(&buf, at(0)));
    try testing.expectEqualStrings("Mon, 01 Jan 0001 00:00:00 GMT", format(&buf, timestamp.min));
    try testing.expectEqualStrings("Fri, 31 Dec 9999 23:59:59 GMT", format(&buf, timestamp.max));
    // A fraction is dropped, before the epoch as after it.
    try testing.expectEqualStrings("Sun, 06 Nov 1994 08:49:37 GMT", format(&buf, .{ .nanoseconds = @as(i96, example) * std.time.ns_per_s + 999_999_999 }));
    try testing.expectEqualStrings("Wed, 31 Dec 1969 23:59:59 GMT", format(&buf, .{ .nanoseconds = -1 }));
    try testing.expectEqualStrings("Thu, 29 Feb 2024 12:00:00 GMT", format(&buf, at(1709208000)));
}

fn dateProperty(_: void, input: []const u8) !void {
    var g: test_util.ByteGen = .init(input);
    // Any second from 1950 to 2049, written in each format, reads back.
    const t: i64 = -631152000 + @as(i64, @intCast(g.intRange(u32, 0, 3155759999)));
    const days = @divFloor(t, std.time.s_per_day);
    const secs = @mod(t, std.time.s_per_day);
    const c = timestamp.civilFromDays(days);
    const weekday: usize = @intCast(@mod(days + 3, 7)); // 1970-01-01 was a Thursday.
    var buf: [64]u8 = undefined;
    const hh = @divFloor(secs, 3600);
    const mm = @divFloor(@mod(secs, 3600), 60);
    const ss = @mod(secs, 60);
    const imf = std.fmt.bufPrint(&buf, "{s}, {d:0>2} {s} {d:0>4} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{ day_names[weekday], @as(u64, @intCast(c.day)), months[@intCast(c.month - 1)], @as(u64, @intCast(c.year)), @as(u64, @intCast(hh)), @as(u64, @intCast(mm)), @as(u64, @intCast(ss)) }) catch unreachable;
    try testing.expectEqual(t, unixSeconds(imf).?);
    var buf2: [64]u8 = undefined;
    const rfc850 = std.fmt.bufPrint(&buf2, "{s}, {d:0>2}-{s}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{ long_day_names[weekday], @as(u64, @intCast(c.day)), months[@intCast(c.month - 1)], @as(u64, @intCast(@mod(c.year, 100))), @as(u64, @intCast(hh)), @as(u64, @intCast(mm)), @as(u64, @intCast(ss)) }) catch unreachable;
    try testing.expectEqual(t, unixSeconds(rfc850).?);
    var buf3: [64]u8 = undefined;
    const asc = std.fmt.bufPrint(&buf3, "{s} {s} {d: >2} {d:0>2}:{d:0>2}:{d:0>2} {d:0>4}", .{ day_names[weekday], months[@intCast(c.month - 1)], @as(u64, @intCast(c.day)), @as(u64, @intCast(hh)), @as(u64, @intCast(mm)), @as(u64, @intCast(ss)), @as(u64, @intCast(c.year)) }) catch unreachable;
    try testing.expectEqual(t, unixSeconds(asc).?);
    _ = unixSeconds(g.rest());
}

test "format clamps an instant past timestamp's range to its end" {
    var buf: [len]u8 = undefined;
    var want: [len]u8 = undefined;
    try testing.expectEqualStrings(format(&want, timestamp.max), format(&buf, .{ .nanoseconds = std.math.maxInt(i96) }));
    try testing.expectEqualStrings(format(&want, timestamp.min), format(&buf, .{ .nanoseconds = std.math.minInt(i96) }));
}

test "fuzz unixSeconds: any second from 1950 to 2049 reads back in all three formats" {
    try test_util.fuzzBytes({}, dateProperty, .{ .corpus = &.{ "", "\xff\xff\xff\xff", "\x00\x00\x00\x00" } });
}

fn formatProperty(_: void, input: []const u8) !void {
    var g: test_util.ByteGen = .init(input);
    // Any instant timestamp can write is written as an IMF-fixdate that
    // parses back to its second; arbitrary text never crashes parse.
    const span: u128 = @intCast(timestamp.max.nanoseconds - timestamp.min.nanoseconds);
    const ts: std.Io.Timestamp = .{ .nanoseconds = timestamp.min.nanoseconds + @as(i96, @intCast(@as(u128, g.int(u128)) % (span + 1))) };
    var buf: [len]u8 = undefined;
    const text = format(&buf, ts);
    try testing.expectEqual(len, text.len);
    const back = try parse(text);
    try testing.expectEqual(@divFloor(ts.nanoseconds, std.time.ns_per_s) * std.time.ns_per_s, back.nanoseconds);
    if (parse(g.rest())) |any| {
        var again: [len]u8 = undefined;
        _ = format(&again, any);
    } else |_| {}
}

test "fuzz format: every instant in range writes and reads back to its second" {
    try test_util.fuzzBytes({}, formatProperty, .{ .corpus = &.{ "", test_util.repeat("\xff", 16), "Sat, 01 Jan 0000 00:00:00 GMT" } });
}
