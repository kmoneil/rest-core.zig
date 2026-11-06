//! Requests rest-core helps build: what a name from input can do to the URL.

const std = @import("std");
const query = @import("rest_core").query;
const Writer = std.Io.Writer;

test "security: CWE-22 a resource name cannot leave its segment of the URL" {
    var buf: [256]u8 = undefined;
    // Every character that would end the segment, start a query or a
    // fragment, or forge an escape is encoded, by both segment writers.
    const names = [_][]const u8{ "a/b", "../x", "a?b=c", "a#frag", "100%", "%2F", "%2e%2e", "a\\b", "a b", "a\r\nHost: evil", "\x00" };
    for (names) |name| {
        inline for (.{ query.writeCheckedSegment, query.writeCheckedStrictSegment }) |write| {
            var w: Writer = .fixed(&buf);
            try write(&w, name);
            const out = w.buffered();
            for (out, 0..) |c, i| {
                try std.testing.expect(c != '/' and c != '?' and c != '#' and c != '\\');
                try std.testing.expect(c > ' ' and c < 0x7f);
                // A `%` in the output is always one this writer made.
                if (c == '%') try std.testing.expect(i + 2 < out.len and std.ascii.isHex(out[i + 1]) and std.ascii.isHex(out[i + 2]));
            }
        }
    }
    // `@` and `:` are legal in a path segment and mean nothing there; only an
    // authority, which no segment writer writes, gives them a meaning.
    var w: Writer = .fixed(&buf);
    try query.writeCheckedSegment(&w, "user@host:1");
    try std.testing.expectEqualStrings("user@host:1", w.buffered());
}

test "security: CWE-22 a dot-segment from input is refused, not sent" {
    var buf: [64]u8 = undefined;
    for ([_][]const u8{ ".", ".." }) |name| {
        var w: Writer = .fixed(&buf);
        try std.testing.expectError(error.DotSegment, query.writeCheckedSegment(&w, name));
        try std.testing.expectError(error.DotSegment, query.writeCheckedStrictSegment(&w, name));
    }
    var w: Writer = .fixed(&buf);
    try std.testing.expectError(error.DotSegment, query.writeCheckedPath(&w, "logs/../../admin"));
    try std.testing.expectEqual(0, w.buffered().len);
}

test "security: CWE-74 a query value cannot add a parameter or end the query" {
    var buf: [256]u8 = undefined;
    var w: Writer = .fixed(&buf);
    w.writeAll("/v1/items") catch unreachable;
    var params: query.Params = .init(&w);
    try params.add("filter", "a&admin=true#x");
    try params.add("page", "1");
    try std.testing.expectEqualStrings("/v1/items?filter=a%26admin%3Dtrue%23x&page=1", w.buffered());
}
