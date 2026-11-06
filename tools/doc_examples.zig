// From yaml.zig tools/doc_examples.zig at aad9a5e, with a check of the documents' relative links added, and its arguments read so Windows compiles it.
//! Keeps the examples in README.md and docs/*.md true. A code block
//! marked with a comment naming a file, at the start of a line,
//!
//!     <!-- example: examples/quick_start.zig -->
//!     ```zig
//!     ...
//!     ```
//!
//! must equal that file byte for byte, and every examples/*.zig file
//! must be shown somewhere and imported by examples/all.zig, which
//! `zig build test` compiles and runs. So no document can show code
//! that does not compile, or an answer the code does not give.
//!
//! Every relative link in those documents must name a file or directory
//! that exists, an anchor after `#` aside.
//!
//! Quiet when everything agrees; each problem prints on stderr and the
//! exit code says so. With --fix it rewrites each marked block from its
//! file instead (`zig build doc-examples -- --fix`). Run from the
//! repository root.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const marker = "<!-- example: ";
const marker_end = " -->\n```";

/// One marked block: the file it names, and where its body (the lines
/// between the fences) starts and ends in the document.
const Block = struct { path: []const u8, body_start: usize, body_end: usize };

/// The first marked block at or after `from`, or null when there is
/// none. A marker counts only at the start of a line, so a document can
/// show one, indented, without it being checked. The closing fence is
/// the first line after the opening one that starts with ```, so an
/// example must not hold such a line itself.
fn nextBlock(doc: []const u8, from: usize) error{Malformed}!?Block {
    var at = std.mem.findPos(u8, doc, from, marker) orelse return null;
    while (at > 0 and doc[at - 1] != '\n') {
        at = std.mem.findPos(u8, doc, at + 1, marker) orelse return null;
    }
    const path_start = at + marker.len;
    const path_end = std.mem.findScalarPos(u8, doc, path_start, ' ') orelse return error.Malformed;
    if (!std.mem.startsWith(u8, doc[path_end..], marker_end)) return error.Malformed;
    const fence_end = std.mem.findScalarPos(u8, doc, path_end + marker_end.len, '\n') orelse return error.Malformed;
    const body_start = fence_end + 1;
    var line = body_start;
    while (!std.mem.startsWith(u8, doc[line..], "```")) {
        const nl = std.mem.findScalarPos(u8, doc, line, '\n') orelse return error.Malformed;
        line = nl + 1;
    }
    return .{ .path = doc[path_start..path_end], .body_start = body_start, .body_end = line };
}

const Check = struct {
    arena: Allocator,
    io: Io,
    dir: Io.Dir,
    fix: bool,
    /// The example files some document shows.
    shown: std.StringHashMapUnmanaged(void) = .empty,
    problems: usize = 0,

    fn problem(c: *Check, comptime fmt: []const u8, args: anytype) void {
        std.debug.print(fmt ++ "\n", args);
        c.problems += 1;
    }

    /// Compares each marked block in one document with its file, and
    /// under --fix writes the document back with the files' text.
    fn doc(c: *Check, path: []const u8) !void {
        const text = try c.dir.readFileAlloc(c.io, path, c.arena, .unlimited);
        try c.links(path, text);
        var out: std.ArrayList(u8) = .empty;
        var copied: usize = 0;
        var from: usize = 0;
        while (nextBlock(text, from) catch {
            c.problem("{s}: an example marker with no closed code block after it", .{path});
            return;
        }) |block| : (from = block.body_end) {
            try c.shown.put(c.arena, block.path, {});
            const want = c.dir.readFileAlloc(c.io, block.path, c.arena, .unlimited) catch |err| switch (err) {
                error.FileNotFound => {
                    c.problem("{s}: {s} does not exist", .{ path, block.path });
                    continue;
                },
                else => return err,
            };
            if (std.mem.eql(u8, want, text[block.body_start..block.body_end])) continue;
            if (!c.fix) {
                c.problem("{s}: the block for {s} differs from the file (zig build doc-examples -- --fix)", .{ path, block.path });
                continue;
            }
            try out.appendSlice(c.arena, text[copied..block.body_start]);
            try out.appendSlice(c.arena, want);
            copied = block.body_end;
        }
        if (copied == 0) return;
        try out.appendSlice(c.arena, text[copied..]);
        try c.dir.writeFile(c.io, .{ .sub_path = path, .data = out.items });
        std.debug.print("{s}: rewrote its examples from their files\n", .{path});
    }

    /// Every relative link in `text`, the document at `path`, names a file
    /// or directory that exists.
    fn links(c: *Check, path: []const u8, text: []const u8) !void {
        const base = std.fs.path.dirname(path) orelse ".";
        var at: usize = 0;
        while (std.mem.findPos(u8, text, at, "](")) |i| {
            const start = i + 2;
            const end = std.mem.findScalarPos(u8, text, start, ')') orelse break;
            at = end;
            const file = linkedFile(text[start..end]) orelse continue;
            const resolved = try std.fs.path.join(c.arena, &.{ base, file });
            c.dir.access(c.io, resolved, .{}) catch c.problem("{s}: links to {s}, which does not exist", .{ path, text[start..end] });
        }
    }

    /// Every example file is shown in a document and run by all.zig.
    fn examples(c: *Check) !void {
        const all = try c.dir.readFileAlloc(c.io, "examples/all.zig", c.arena, .unlimited);
        var dir = try c.dir.openDir(c.io, "examples", .{ .iterate = true });
        defer dir.close(c.io);
        var it = dir.iterate();
        while (try it.next(c.io)) |entry| {
            if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".zig")) continue;
            if (std.mem.eql(u8, entry.name, "all.zig")) continue;
            const rel = try c.arena.print("examples/{s}", .{entry.name});
            if (!c.shown.contains(rel)) c.problem("{s} is not shown in README.md or docs/", .{rel});
            const import = try c.arena.print("@import(\"{s}\")", .{entry.name});
            if (std.mem.find(u8, all, import) == null) c.problem("{s} is not imported by examples/all.zig, so it never runs", .{rel});
        }
    }
};

/// The file a link names, without its anchor, or null for a link that
/// names no file here: a URL, an e-mail address, an anchor alone.
fn linkedFile(target: []const u8) ?[]const u8 {
    for ([_][]const u8{ "http://", "https://", "mailto:" }) |scheme| if (std.mem.startsWith(u8, target, scheme)) return null;
    const file = target[0 .. std.mem.indexOfScalar(u8, target, '#') orelse target.len];
    return if (file.len == 0) null else file;
}

test "linkedFile: a file here, its anchor dropped; nothing for a URL or an anchor alone" {
    try std.testing.expectEqualStrings("docs/essentials.md", linkedFile("docs/essentials.md#retries").?);
    try std.testing.expectEqualStrings("../README.md", linkedFile("../README.md").?);
    for ([_][]const u8{ "https://github.com/kmoneil/gcp.zig", "http://x", "mailto:a@b", "#retries", "" }) |t| {
        try std.testing.expectEqual(null, linkedFile(t));
    }
}

/// README.md, then docs/*.md in name order.
fn documents(arena: Allocator, io: Io, cwd: Io.Dir) ![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    try list.append(arena, "README.md");
    var dir = cwd.openDir(io, "docs", .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return list.items,
        else => return err,
    };
    defer dir.close(io);
    var it = dir.iterate();
    const first_doc = list.items.len;
    while (try it.next(io)) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".md")) continue;
        try list.append(arena, try arena.print("docs/{s}", .{entry.name}));
    }
    std.mem.sort([]const u8, list.items[first_doc..], {}, lessThan);
    return list.items;
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;

    var c: Check = .{ .arena = arena, .io = io, .dir = Io.Dir.cwd(), .fix = false };
    // toSlice, not an Args.Iterator: Windows has no allocation-free one.
    const args = try init.minimal.args.toSlice(arena);
    for (args[1..]) |arg| {
        if (!std.mem.eql(u8, arg, "--fix")) {
            std.debug.print("usage: doc-examples [--fix]   (from the repository root)\n", .{});
            std.process.exit(2);
        }
        c.fix = true;
    }
    for (try documents(arena, io, c.dir)) |path| try c.doc(path);
    try c.examples();
    if (c.problems > 0) std.process.exit(1);
}

test "a marked block's body is the lines between its fences" {
    const doc = "Intro.\n\n<!-- example: examples/a.zig -->\n```zig\nconst x = 1;\n```\n\nAfter.\n";
    const block = (try nextBlock(doc, 0)).?;
    try std.testing.expectEqualStrings("examples/a.zig", block.path);
    try std.testing.expectEqualStrings("const x = 1;\n", doc[block.body_start..block.body_end]);
    try std.testing.expectEqual(null, try nextBlock(doc, block.body_end));
}

test "an empty block, and two in a row" {
    const doc = "<!-- example: a.zig -->\n```zig\n```\n<!-- example: b.zig -->\n```zig\nb\n```\n";
    const a = (try nextBlock(doc, 0)).?;
    try std.testing.expectEqual(a.body_start, a.body_end);
    const b = (try nextBlock(doc, a.body_end)).?;
    try std.testing.expectEqualStrings("b.zig", b.path);
    try std.testing.expectEqualStrings("b\n", doc[b.body_start..b.body_end]);
}

test "a marker not at the start of its line is only shown, not checked" {
    const doc = "    <!-- example: shown.zig -->\n    ```zig\n    ```\n<!-- example: real.zig -->\n```zig\nx\n```\n";
    const block = (try nextBlock(doc, 0)).?;
    try std.testing.expectEqualStrings("real.zig", block.path);
    try std.testing.expectEqual(null, try nextBlock("say <!-- example: a.zig --> inline\n", 0));
}

test "a marker with no fence, or a fence never closed, is malformed" {
    try std.testing.expectError(error.Malformed, nextBlock("<!-- example: a.zig -->\ntext\n", 0));
    try std.testing.expectError(error.Malformed, nextBlock("<!-- example: a.zig -->\n```zig\nno end\n", 0));
}
