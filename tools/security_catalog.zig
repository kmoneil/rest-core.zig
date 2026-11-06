// From yaml.zig tools/security_catalog.zig at 9fe87e9 (itself after ekur's, ekur t65); here its paths are joined with '/' on every OS.
//! `security-catalog CATALOG.md DIR`: checks the security catalog against
//! the tests, so the two cannot drift apart. After ekur's, less its
//! compile-error fixtures.
//!
//! The catalog is Markdown tables whose rows read
//!
//!     | ID | Attack | Source | Defense | Test | Status |
//!
//! Test is `path: test name`, several separated by ` ; `, or `-`. Status
//! is `covered` (every named test must exist: its file holds `test
//! "name"`), `gap tNN` or `later tNN` (a card), or `n/a: reason`. Every
//! `test "security: ..."` under DIR must be named by some row, and IDs
//! must be unique.

const std = @import("std");

const Io = std.Io;

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 3) {
        std.debug.print("usage: security-catalog CATALOG.md DIR\n", .{});
        return 2;
    }
    const cwd = Io.Dir.cwd();
    const catalog = try cwd.readFileAlloc(io, args[1], arena, .limited(4 << 20));
    var buf: [4096]u8 = undefined;
    var stderr = Io.File.stderr().writerStreaming(io, &buf);
    const w = &stderr.interface;
    const problems = try check(io, arena, cwd, .{ .name = args[1], .text = catalog }, args[2], w);
    if (problems > 0) try w.print("security-catalog: {d} problem(s)\n", .{problems});
    try w.flush();
    return if (problems > 0) 1 else 0;
}

/// Checks `catalog` against the tests under `dir_path`, paths taken from
/// `root`; each problem is a line on `w`, and the count is returned.
fn check(io: Io, arena: std.mem.Allocator, root: Io.Dir, catalog: struct { name: []const u8, text: []const u8 }, dir_path: []const u8, w: *Io.Writer) !usize {
    var c: Checker = .{ .io = io, .arena = arena, .root = root, .file = catalog.name, .w = w };
    var lines = std.mem.splitScalar(u8, catalog.text, '\n');
    var line_no: usize = 0;
    while (lines.next()) |line| {
        line_no += 1;
        try c.row(line_no, std.mem.trim(u8, line, " \r"));
    }
    try c.unnamedTests(dir_path);
    if (c.rows == 0) try c.report("{s} has no rows\n", .{c.file});
    return c.problems;
}

/// What a check has seen so far, and where its problems go.
const Checker = struct {
    io: Io,
    arena: std.mem.Allocator,
    root: Io.Dir,
    file: []const u8,
    w: *Io.Writer,
    problems: usize = 0,
    rows: usize = 0,
    /// Every test a row names, as `path\x00name`.
    named: std.StringHashMapUnmanaged(void) = .empty,
    /// Each ID's line.
    ids: std.StringHashMapUnmanaged(usize) = .empty,

    fn report(c: *Checker, comptime format: []const u8, args: anytype) !void {
        try c.w.print(format, args);
        c.problems += 1;
    }

    /// Checks a line of the catalog, if it is a table's row.
    fn row(c: *Checker, line_no: usize, text: []const u8) !void {
        if (text.len < 2 or text[0] != '|') return;
        var cells: std.ArrayList([]const u8) = .empty;
        var it = std.mem.splitScalar(u8, text[1 .. text.len - 1], '|');
        while (it.next()) |cell| try cells.append(c.arena, std.mem.trim(u8, cell, " "));
        // A row of another shape would otherwise be skipped, its tests and
        // status never checked (ekur t210).
        if (cells.items.len != 6) {
            return c.report("{s}:{d}: a row of {d} cells; the catalog's rows have 6 (ID, Attack, Source, Defense, Test, Status), and a `|` inside a cell splits it\n", .{ c.file, line_no, cells.items.len });
        }
        const id = cells.items[0];
        // The header row and the separator under it.
        if (std.mem.eql(u8, id, "ID") or std.mem.startsWith(u8, id, "---")) return;
        c.rows += 1;
        if (try c.ids.fetchPut(c.arena, id, line_no)) |prev| {
            try c.report("{s}:{d}: {s} is also the ID of line {d}\n", .{ c.file, line_no, id, prev.value });
        }
        const covered = try c.status(line_no, id, cells.items[5]);
        const test_cell = cells.items[4];
        if (std.mem.eql(u8, test_cell, "-")) {
            if (covered) try c.report("{s}:{d}: {s} is covered but names no test\n", .{ c.file, line_no, id });
            return;
        }
        var tests = std.mem.splitSequence(u8, test_cell, " ; ");
        while (tests.next()) |ref| try c.testRef(line_no, id, ref);
    }

    /// Checks a row's status, and returns whether it is `covered`.
    fn status(c: *Checker, line_no: usize, id: []const u8, text: []const u8) !bool {
        const covered = std.mem.eql(u8, text, "covered");
        const card = (std.mem.startsWith(u8, text, "gap t") or std.mem.startsWith(u8, text, "later t")) and
            isCard(text[std.mem.findScalar(u8, text, ' ').? + 1 ..]);
        const na = std.mem.startsWith(u8, text, "n/a: ") and text.len > 5;
        if (!covered and !card and !na) {
            try c.report("{s}:{d}: {s}: status \"{s}\" is not covered, gap tNN, later tNN or n/a: reason\n", .{ c.file, line_no, id, text });
        }
        return covered;
    }

    /// Checks a row's `path: test name`: the file holds that test.
    fn testRef(c: *Checker, line_no: usize, id: []const u8, ref: []const u8) !void {
        const colon = std.mem.find(u8, ref, ": ") orelse {
            return c.report("{s}:{d}: {s}: \"{s}\" is not `path: test name`\n", .{ c.file, line_no, id, ref });
        };
        const path = ref[0..colon];
        const name = ref[colon + 2 ..];
        try c.named.put(c.arena, try c.arena.print("{s}\x00{s}", .{ path, name }), {});
        const src = c.root.readFileAlloc(c.io, path, c.arena, .limited(16 << 20)) catch |err| {
            return c.report("{s}:{d}: {s}: cannot read {s}: {t}\n", .{ c.file, line_no, id, path, err });
        };
        if (std.mem.find(u8, src, try c.arena.print("test \"{s}\"", .{name})) == null) {
            try c.report("{s}:{d}: {s}: {s} has no test \"{s}\"\n", .{ c.file, line_no, id, path, name });
        }
    }

    /// Reports each `security: ...` test under `dir_path` no row names.
    fn unnamedTests(c: *Checker, dir_path: []const u8) !void {
        var dir = try c.root.openDir(c.io, dir_path, .{ .iterate = true });
        defer dir.close(c.io);
        var walker = try dir.walk(c.arena);
        while (try walker.next(c.io)) |entry| {
            if (entry.kind != .file or !std.mem.endsWith(u8, entry.path, ".zig")) continue;
            // With `/`, as the catalog names files, whatever the OS joins
            // with: on Windows the walker's own paths use `\`.
            const path = try c.arena.print("{s}/{s}", .{ dir_path, entry.path });
            std.mem.replaceScalar(u8, path, '\\', '/');
            const src = try c.root.readFileAlloc(c.io, path, c.arena, .limited(16 << 20));
            var at: usize = 0;
            while (std.mem.findPos(u8, src, at, "test \"security: ")) |i| {
                const start = i + "test \"".len;
                const end = std.mem.findScalarPos(u8, src, start, '"') orelse break;
                at = end;
                if (!c.named.contains(try c.arena.print("{s}\x00{s}", .{ path, src[start..end] }))) {
                    try c.report("{s}: test \"{s}\" is in no row of {s}\n", .{ path, src[start..end], c.file });
                }
            }
        }
    }
};

fn isCard(s: []const u8) bool {
    if (s.len < 2 or s[0] != 't') return false;
    for (s[1..]) |c| if (!std.ascii.isDigit(c)) return false;
    return true;
}

/// `check` over a catalog and tests written into a fresh directory: the
/// problems it reports, one a line.
fn checked(catalog: []const u8, files: []const [2][]const u8) ![]const u8 {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    for (files) |f| {
        if (std.fs.path.dirname(f[0])) |d| try tmp.dir.createDirPath(io, d);
        try tmp.dir.writeFile(io, .{ .sub_path = f[0], .data = f[1] });
    }
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var out: Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    const n = try check(io, arena.allocator(), tmp.dir, .{ .name = "CATALOG.md", .text = catalog }, "sec", &out.writer);
    try std.testing.expectEqual(n, std.mem.count(u8, out.written(), "\n"));
    return std.testing.allocator.dupe(u8, out.written());
}

const header =
    \\| ID | Attack | Source | Defense | Test | Status |
    \\| --- | --- | --- | --- | --- | --- |
    \\
;
const tests_file: [2][]const u8 = .{ "sec/a_test.zig", "test \"security: one\" {}\ntest \"security: two\" {}\n" };

test "a catalog that names every security test, each of which exists, is clean" {
    const got = try checked(header ++
        \\| A-1 | x | y | z | sec/a_test.zig: security: one | covered |
        \\| A-2 | x | y | z | sec/a_test.zig: security: two ; src/b_test.zig: plain | covered |
        \\| A-3 | x | y | z | - | gap t12 |
        \\| A-4 | x | y | z | - | n/a: not a server |
        \\
    , &.{ tests_file, .{ "src/b_test.zig", "test \"plain\" {}\n" } });
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings("", got);
}

test "every way a catalog row can be wrong is reported, a row of another shape too" {
    const got = try checked(header ++
        \\| A-1 | x | y | z | sec/a_test.zig: security: one | covered |
        \\| A-1 | x | y | z | sec/a_test.zig: security: three | covered |
        \\| A-2 | x | y | z | - | covered |
        \\| A-3 | x | y | z | - | gap soon |
        \\| A-4 | x | y | sec/a_test.zig: security: two | covered |
        \\| A-5 | x | y | z | src/gone.zig: a test | covered |
        \\| A-6 | x | y | z | sec/a_test.zig security two | covered |
        \\
    , &.{tests_file});
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings(
        \\CATALOG.md:4: A-1 is also the ID of line 3
        \\CATALOG.md:4: A-1: sec/a_test.zig has no test "security: three"
        \\CATALOG.md:5: A-2 is covered but names no test
        \\CATALOG.md:6: A-3: status "gap soon" is not covered, gap tNN, later tNN or n/a: reason
        \\CATALOG.md:7: a row of 5 cells; the catalog's rows have 6 (ID, Attack, Source, Defense, Test, Status), and a `|` inside a cell splits it
        \\CATALOG.md:8: A-5: cannot read src/gone.zig: FileNotFound
        \\CATALOG.md:9: A-6: "sec/a_test.zig security two" is not `path: test name`
        \\sec/a_test.zig: test "security: two" is in no row of CATALOG.md
        \\
    , got);
}

test "a catalog with no rows is a problem" {
    const got = try checked(header, &.{tests_file});
    defer std.testing.allocator.free(got);
    try std.testing.expect(std.mem.find(u8, got, "CATALOG.md has no rows") != null);
}
