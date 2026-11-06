// From gcp.zig src/core/logging.zig at eae944c.
//! Logging for the modules. Each logs through `std.log` under its own scope,
//! such as `.gcp_pubsub` or `.azure_storage`, so applications can filter or silence each with
//! `std_options.log_scope_levels`. Callers pass only methods, paths,
//! statuses, counts, sizes and timings: never tokens, secrets, message data
//! or attribute values. What a server sent, such as a request id, goes
//! through `escaped`, so it cannot forge a line or drive the terminal.
//!
//! In test builds, lines are captured in memory instead of printed, so tests
//! stay quiet and can assert on exactly what would have been logged.

const std = @import("std");
const builtin = @import("builtin");

/// `text`, for a `{f}` in a log line or any other format: printed with
/// every control byte (below 0x20, and 0x7f) written as `\xNN`, so a
/// server's line break cannot start a forged log line (CWE-117), nor an
/// escape sequence reach the terminal (CWE-150). Other bytes go as they are.
pub fn escaped(text: []const u8) Escaped {
    return .{ .text = text };
}

pub const Escaped = struct {
    text: []const u8,

    pub fn format(e: Escaped, w: *std.Io.Writer) std.Io.Writer.Error!void {
        var start: usize = 0;
        for (e.text, 0..) |c, i| {
            if (c >= 0x20 and c != 0x7f) continue;
            try w.writeAll(e.text[start..i]);
            try w.print("\\x{x:0>2}", .{c});
            start = i + 1;
        }
        try w.writeAll(e.text[start..]);
    }
};

/// The logging functions for one module's scope.
pub fn Scoped(comptime scope: @EnumLiteral()) type {
    return struct {
        const log = std.log.scoped(scope);

        pub fn debug(comptime format: []const u8, args: anytype) void {
            if (builtin.is_test) return capture.record("debug", format, args);
            log.debug(format, args);
        }

        pub fn warn(comptime format: []const u8, args: anytype) void {
            if (builtin.is_test) return capture.record("warn", format, args);
            log.warn(format, args);
        }

        /// The in-memory sink used in test builds, one per scope. Tasks on
        /// other threads may record at the same time.
        pub const capture = if (builtin.is_test) struct {
            // A type that captures no comptime value is shared by every
            // instantiation; naming the scope gives each scope its own buffer.
            const owner = scope;
            var buffer: [64 * 1024]u8 = undefined;
            var len: usize = 0;
            /// Lines recorded since the last reset, including any that did not fit.
            pub var lines: usize = 0;

            fn record(comptime level: []const u8, comptime format: []const u8, args: anytype) void {
                var line_buffer: [1024]u8 = undefined;
                var w: std.Io.Writer = .fixed(&line_buffer);
                w.print(level ++ ": " ++ format ++ "\n", args) catch {};
                const line = w.buffered();
                const at = @atomicRmw(usize, &len, .Add, line.len, .monotonic);
                if (at + line.len <= buffer.len) @memcpy(buffer[at..][0..line.len], line);
                _ = @atomicRmw(usize, &lines, .Add, 1, .monotonic);
            }

            pub fn reset() void {
                len = 0;
                lines = 0;
            }

            pub fn text() []const u8 {
                return buffer[0..@min(len, buffer.len)];
            }
        } else struct {};
    };
}

test "capture records formatted lines" {
    const scoped = Scoped(.rest_core_test);
    scoped.capture.reset();
    scoped.debug("{s} {s} -> {d}", .{ "GET", "/v1/x", 200 });
    scoped.warn("retrying in {d} ms", .{150});
    try std.testing.expectEqualStrings("debug: GET /v1/x -> 200\nwarn: retrying in 150 ms\n", scoped.capture.text());
    try std.testing.expectEqual(2, scoped.capture.lines);
    scoped.capture.reset();
    try std.testing.expectEqualStrings("", scoped.capture.text());
}

test "escaped: a server's text goes into a log line with its control bytes written out" {
    const scoped = Scoped(.rest_core_test_escaped);
    scoped.capture.reset();
    scoped.debug("request {f}", .{escaped("r-1\nINFO forged line\r\x1b[2J\x7f")});
    scoped.debug("request {f}", .{escaped("0d3f4c11-7b2a-4e9b-a1e0-5c6d7e8f9a0b")});
    scoped.debug("[{f}]", .{escaped("")});
    try std.testing.expectEqualStrings(
        "debug: request r-1\\x0aINFO forged line\\x0d\\x1b[2J\\x7f\n" ++
            "debug: request 0d3f4c11-7b2a-4e9b-a1e0-5c6d7e8f9a0b\n" ++
            "debug: []\n",
        scoped.capture.text(),
    );
    // Bytes above 0x7f, UTF-8's, go as they are; a tab is a control byte.
    var buf: [32]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.print("{f}", .{escaped("é\tx")});
    try std.testing.expectEqualStrings("é\\x09x", w.buffered());
}

test "capture keeps scopes apart" {
    const a = Scoped(.rest_core_test_a);
    const b = Scoped(.rest_core_test_b);
    a.capture.reset();
    b.capture.reset();
    a.warn("only in a", .{});
    try std.testing.expectEqualStrings("warn: only in a\n", a.capture.text());
    try std.testing.expectEqualStrings("", b.capture.text());
}
