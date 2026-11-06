//! Time read from a server: what a hostile timestamp can do.

const std = @import("std");
const rest_core = @import("rest_core");
const timestamp = rest_core.timestamp;
const http_date = rest_core.http_date;

test "security: CWE-20 a timestamp at the edges is read exactly or refused, and what is read always writes back" {
    // Well formed, and outside what can be written: refused, never handed on
    // to a formatter that asserts its range.
    for ([_][]const u8{ "0000-01-01T00:00:00Z", "0001-01-01T00:00:00+00:01", "9999-12-31T23:59:59-00:01", "9999-12-31T23:59:59.999999999-23:59" }) |text| {
        try std.testing.expectError(error.InvalidTimestamp, timestamp.parse(text));
    }
    // Ten fractional digits, an offset past its limits, a 60th second.
    for ([_][]const u8{ "2026-11-06T12:00:00.1234567890Z", "2026-11-06T12:00:00+24:00", "2026-11-06T12:00:00-00:60", "2026-12-31T23:59:60Z" }) |text| {
        try std.testing.expectError(error.InvalidTimestamp, timestamp.parse(text));
    }
    // The range's ends are read exactly, and write back.
    var buf: [timestamp.max_len]u8 = undefined;
    try std.testing.expectEqualStrings("0001-01-01T00:00:00Z", timestamp.format(&buf, try timestamp.parse("0001-01-01T00:00:00Z")));
    try std.testing.expectEqualStrings("9999-12-31T23:59:59.999999999Z", timestamp.format(&buf, try timestamp.parse("9999-12-31T23:59:59.999999999Z")));

    // An HTTP-date in the year 0000 is refused; one in 9999 writes back
    // both ways; a 60th second reads as the 59th, never into the next minute.
    try std.testing.expectError(error.InvalidHttpDate, http_date.parse("Sat, 01 Jan 0000 00:00:00 GMT"));
    const latest = try http_date.parse("Fri, 31 Dec 9999 23:59:59 GMT");
    var date_buf: [http_date.len]u8 = undefined;
    try std.testing.expectEqualStrings("Fri, 31 Dec 9999 23:59:59 GMT", http_date.format(&date_buf, latest));
    _ = timestamp.format(&buf, latest);
    try std.testing.expectEqual(try http_date.parse("Wed, 31 Dec 2025 23:59:59 GMT"), try http_date.parse("Wed, 31 Dec 2025 23:59:60 GMT"));
}
