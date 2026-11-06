// From gcp.zig src/core/errors.zig at eae944c: its Diagnostics and truncateUtf8, with their tests. `status` is `code`, and the request id is new.
//! Details of the most recent failed call. Zig errors carry no payload, so
//! pass `&diagnostics` in a client's options and read it after a call fails.
//! A call that succeeds clears it. Not safe to share across concurrent
//! tasks.
//!
//! What a refusal says is the cloud's to read (the request loop's hook
//! does): a code such as Google's "NOT_FOUND" or Azure's
//! "ResourceNotFound", the server's message, and the id the server gave the
//! request, as Azure's `x-ms-request-id`, for a support ticket.

const Diagnostics = @This();

const std = @import("std");
const test_util = @import("testing.zig");

/// HTTP status of the failed response, or 0 when the call failed without
/// one: client-side validation, a connection error, cancellation.
http_status: u16 = 0,
/// How long the failed response asked its client to wait before trying
/// again, in milliseconds: the largest of what its headers ask
/// (`retry_after`) and what its body carries, as the cloud's hook reads it,
/// saturating at `maxInt(u32)`; null when it asked for nothing, or the call
/// failed without a response. Kept whether or not the call was retried,
/// for a caller that schedules its own next try.
retry_after_ms: ?u32 = null,
code_len: u8 = 0,
message_len: u16 = 0,
request_id_len: u8 = 0,
buffer: [512]u8 = undefined,
request_id_buffer: [max_request_id_len]u8 = undefined,

/// Longest code kept. Real codes are short, like "FAILED_PRECONDITION" or
/// "AuthorizationFailed".
pub const max_code_len = 64;
/// Longest request id kept. Azure's are GUIDs, 36 bytes.
pub const max_request_id_len = 64;

/// The cloud's code for the failure, such as "NOT_FOUND", or "" when there
/// is none.
pub fn code(d: *const Diagnostics) []const u8 {
    return d.buffer[0..d.code_len];
}

/// The server's message, or a client-side description of the failure,
/// truncated to the buffer at a UTF-8 boundary.
pub fn message(d: *const Diagnostics) []const u8 {
    return d.buffer[d.code_len..][0..d.message_len];
}

/// The id the server gave the failed request, or "".
pub fn requestId(d: *const Diagnostics) []const u8 {
    return d.request_id_buffer[0..d.request_id_len];
}

pub fn clear(d: *Diagnostics) void {
    d.* = .{};
}

/// Records a failure, copying `code_text` and `message_text`, which must not
/// point into `d.buffer`. The request id and the delay are cleared: a
/// cloud's hook sets them after, from the same response.
pub fn set(d: *Diagnostics, http_status: u16, code_text: []const u8, message_text: []const u8) void {
    d.http_status = http_status;
    d.retry_after_ms = null;
    d.request_id_len = 0;
    const c = truncateUtf8(code_text, max_code_len);
    @memcpy(d.buffer[0..c.len], c);
    d.code_len = @intCast(c.len);
    const m = truncateUtf8(message_text, d.buffer.len - c.len);
    @memcpy(d.buffer[c.len..][0..m.len], m);
    d.message_len = @intCast(m.len);
}

/// Records the id the server gave the request, after `set`.
pub fn setRequestId(d: *Diagnostics, id: []const u8) void {
    const r = truncateUtf8(id, max_request_id_len);
    @memcpy(d.request_id_buffer[0..r.len], r);
    d.request_id_len = @intCast(r.len);
}

/// Records a failure that has no HTTP response, with a formatted message.
pub fn print(d: *Diagnostics, comptime fmt: []const u8, args: anytype) void {
    d.http_status = 0;
    d.retry_after_ms = null;
    d.code_len = 0;
    d.request_id_len = 0;
    var w: std.Io.Writer = .fixed(&d.buffer);
    w.print(fmt, args) catch {}; // Keeps whatever fit.
    d.message_len = @intCast(truncateUtf8(w.buffered(), d.buffer.len).len);
}

/// Writes the failure for a log or a terminal: the status, the code, the
/// request id and the message, with every control byte in what the server
/// sent (an escape sequence, a line break that would forge a log line)
/// written as `\xNN`. `message()` and `code()` hand the server's bytes as
/// they came.
pub fn format(d: *const Diagnostics, w: *std.Io.Writer) std.Io.Writer.Error!void {
    if (d.http_status != 0) try w.print("HTTP {d}", .{d.http_status});
    if (d.code_len > 0) {
        if (d.http_status != 0) try w.writeByte(' ');
        try writeEscaped(w, d.code());
    }
    if (d.request_id_len > 0) {
        try w.writeAll(" (request ");
        try writeEscaped(w, d.requestId());
        try w.writeByte(')');
    }
    if (d.message_len > 0) {
        if (d.http_status != 0 or d.code_len > 0) try w.writeAll(": ");
        try writeEscaped(w, d.message());
    }
}

fn writeEscaped(w: *std.Io.Writer, text: []const u8) std.Io.Writer.Error!void {
    for (text) |c| {
        if (c < 0x20 or c == 0x7f) try w.print("\\x{x:0>2}", .{c}) else try w.writeByte(c);
    }
}

/// The longest prefix of `text` that fits in `max` bytes without splitting a
/// UTF-8 sequence. Invalid UTF-8 is cut at `max` bytes or up to 3 before it.
pub fn truncateUtf8(text: []const u8, max: usize) []const u8 {
    if (text.len <= max) return text;
    var cut = max;
    var steps: usize = 0;
    // A continuation byte at the cut means a sequence started before it.
    while (cut > 0 and steps < 3 and text[cut] & 0xC0 == 0x80) : (steps += 1) cut -= 1;
    return text[0..cut];
}

const testing = std.testing;

test "Diagnostics.set copies and truncates" {
    var d: Diagnostics = .{};
    try testing.expectEqualStrings("", d.code());
    try testing.expectEqualStrings("", d.message());
    try testing.expectEqualStrings("", d.requestId());

    d.set(404, "NOT_FOUND", "Resource not found (resource=orders).");
    d.setRequestId("8e6f8a35-5c1e-4b6c-9f2b-3a1d2c4e5f60");
    try testing.expectEqual(404, d.http_status);
    try testing.expectEqualStrings("NOT_FOUND", d.code());
    try testing.expectEqualStrings("Resource not found (resource=orders).", d.message());
    try testing.expectEqualStrings("8e6f8a35-5c1e-4b6c-9f2b-3a1d2c4e5f60", d.requestId());

    // A copy stays valid: accessors index the copy's own buffer.
    const copy = d;
    d.clear();
    try testing.expectEqualStrings("NOT_FOUND", copy.code());
    try testing.expectEqualStrings("", d.code());
    try testing.expectEqualStrings("", d.requestId());

    const long: [2000]u8 = @splat('m');
    d.set(500, &@as([100]u8, @splat('S')), &long);
    d.setRequestId(&long);
    try testing.expectEqual(Diagnostics.max_code_len, d.code().len);
    try testing.expectEqual(d.buffer.len - Diagnostics.max_code_len, d.message().len);
    try testing.expectEqual(Diagnostics.max_request_id_len, d.requestId().len);
}

test "Diagnostics.set never splits a UTF-8 sequence" {
    var d: Diagnostics = .{};
    // 170 three-byte characters are 510 bytes; the 171st straddles the end.
    const text = test_util.repeat("€", 171);
    d.set(400, "", text);
    try testing.expect(std.unicode.utf8ValidateSlice(d.message()));
    try testing.expectEqual(510, d.message().len);
}

test "Diagnostics.print formats client-side failures, and clears the code and request id" {
    var d: Diagnostics = .{};
    d.set(503, "UNAVAILABLE", "x");
    d.setRequestId("r-1");
    d.print("message {d}: attribute key is {d} bytes", .{ 3, 300 });
    try testing.expectEqual(0, d.http_status);
    try testing.expectEqualStrings("", d.code());
    try testing.expectEqualStrings("", d.requestId());
    try testing.expectEqualStrings("message 3: attribute key is 300 bytes", d.message());

    const long: [600]u8 = @splat('x');
    d.print("{s}", .{&long});
    try testing.expectEqual(d.buffer.len, d.message().len);
}

test "Diagnostics.format writes the failure on one line, the server's control bytes escaped" {
    var d: Diagnostics = .{};
    d.set(404, "NOT_FOUND", "no such bucket");
    d.setRequestId("r-1");
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try d.format(&w);
    try testing.expectEqualStrings("HTTP 404 NOT_FOUND (request r-1): no such bucket", w.buffered());

    d.set(500, "X\x1b[2J", "line one\nINFO forged line\r\x07");
    w = .fixed(&buf);
    try d.format(&w);
    try testing.expectEqualStrings("HTTP 500 X\\x1b[2J: line one\\x0aINFO forged line\\x0d\\x07", w.buffered());

    d.print("the token provider failed: {t}", .{error.TokenUnavailable});
    w = .fixed(&buf);
    try d.format(&w);
    try testing.expectEqualStrings("the token provider failed: TokenUnavailable", w.buffered());
}

test "Diagnostics: set, print and clear clear an earlier delay" {
    var d: Diagnostics = .{};
    d.retry_after_ms = 7;
    d.set(500, "INTERNAL", "x");
    try testing.expectEqual(null, d.retry_after_ms);
    d.retry_after_ms = 7;
    d.print("y", .{});
    try testing.expectEqual(null, d.retry_after_ms);
    d.retry_after_ms = 7;
    d.clear();
    try testing.expectEqual(null, d.retry_after_ms);
}

fn truncateProperty(_: void, input: []const u8) !void {
    var g: test_util.ByteGen = .init(input);
    const max = g.intRange(usize, 0, 64);
    const text = g.rest();
    const out = truncateUtf8(text, max);
    try testing.expect(out.len <= max or out.len == text.len);
    try testing.expect(std.mem.startsWith(u8, text, out));
    if (text.len > max) try testing.expect(out.len + 3 >= max);
    if (std.unicode.utf8ValidateSlice(text)) try testing.expect(std.unicode.utf8ValidateSlice(out));
}

test "fuzz truncateUtf8: prefix, bounded, keeps valid UTF-8 valid" {
    try test_util.fuzzBytes({}, truncateProperty, .{ .corpus = &.{
        "\x05€€€€",
        "\x04\xf0\x9f\x98\x80\xf0\x9f\x98\x80",
        "\x02\x80\x80\x80\x80\x80",
        "\x00abc",
    } });
}
