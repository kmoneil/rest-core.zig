//! `provenance [--checkout REPO=DIR]...`: for each file under src/, test/,
//! tools/ and examples/ whose first line says where it came from
//! (`// From gcp.zig src/core/transport.zig at eae944c.`), what that
//! repository has changed in that file since the recorded commit, read with
//! `git log` in its checkout. A fix made there is then carried here.
//!
//! The checkouts are found beside this one: gcp.zig at ../zig-gcp-pubsub,
//! yaml.zig at ../yaml.zig; `--checkout` names another. Exit status: 0 when
//! no source changed a file since its commit, 1 when one did (each listed,
//! with its commits), 2 when a checkout is missing, a provenance line cannot
//! be read, or git does not know a recorded commit. It never passes in
//! silence over what it could not check.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

/// Where a ported file came from.
pub const Source = struct {
    repo: []const u8,
    path: []const u8,
    commit: []const u8,
};

/// Reads a provenance line, `// From <repo> <path> at <commit>` and anything
/// after the commit (`.`, `,`, `:`, `;` or ` (`), or null for any other line.
/// A commit is at least 7 hex digits.
pub fn parse(line: []const u8) ?Source {
    const prefix = "// From ";
    if (!std.mem.startsWith(u8, line, prefix)) return null;
    var words = std.mem.splitScalar(u8, line[prefix.len..], ' ');
    const repo = words.next() orelse return null;
    const path = words.next() orelse return null;
    const at = words.next() orelse return null;
    if (!std.mem.eql(u8, at, "at")) return null;
    const rest = words.rest();
    var n: usize = 0;
    while (n < rest.len and std.ascii.isHex(rest[n])) n += 1;
    if (n < 7 or repo.len == 0 or path.len == 0) return null;
    return .{ .repo = repo, .path = path, .commit = rest[0..n] };
}

test "parse: the shapes the ported files use, and what is not one" {
    const cases = [_]struct { []const u8, Source }{
        .{ "// From gcp.zig src/core/owned.zig at eae944c.", .{ .repo = "gcp.zig", .path = "src/core/owned.zig", .commit = "eae944c" } },
        .{ "// From gcp.zig src/core/testing.zig at eae944c, less FakeSigner and retryInfoBody.", .{ .repo = "gcp.zig", .path = "src/core/testing.zig", .commit = "eae944c" } },
        .{ "// From gcp.zig tools/test_runner.zig at eae944c; carried unchanged below this line.", .{ .repo = "gcp.zig", .path = "tools/test_runner.zig", .commit = "eae944c" } },
        .{ "// From yaml.zig tools/security_catalog.zig at 9fe87e9 (itself after ekur's).", .{ .repo = "yaml.zig", .path = "tools/security_catalog.zig", .commit = "9fe87e9" } },
        .{ "// From gcp.zig src/core/rpc.zig at eae944c: its request loop.", .{ .repo = "gcp.zig", .path = "src/core/rpc.zig", .commit = "eae944c" } },
    };
    for (cases) |c| {
        const got = parse(c[0]).?;
        try std.testing.expectEqualStrings(c[1].repo, got.repo);
        try std.testing.expectEqualStrings(c[1].path, got.path);
        try std.testing.expectEqualStrings(c[1].commit, got.commit);
    }
    for ([_][]const u8{ "//! A doc comment.", "// From gcp.zig src/x.zig at abc.", "// From gcp.zig src/x.zig on eae944c.", "const std = @import(\"std\");", "" }) |line| {
        try std.testing.expectEqual(null, parse(line));
    }
}

/// Runs `git log` for one file: the commits in `checkout` that touched
/// `path` after `commit`, one a line, or `error.UnknownCommit` when git
/// does not know `commit`. Tests replace it.
pub const LogFn = *const fn (ctx: *anyopaque, arena: Allocator, checkout: []const u8, commit: []const u8, path: []const u8) anyerror![]const u8;

pub const Checkout = struct { repo: []const u8, dir: []const u8 };

/// The default checkouts, beside this repository.
pub const default_checkouts = [_]Checkout{
    .{ .repo = "gcp.zig", .dir = "../zig-gcp-pubsub" },
    .{ .repo = "yaml.zig", .dir = "../yaml.zig" },
};

const Outcome = enum(u8) { unchanged = 0, changed = 1, unchecked = 2 };

/// Checks one file's provenance, reporting on `w`.
fn checkFile(
    arena: Allocator,
    file: []const u8,
    source: Source,
    checkouts: []const Checkout,
    log: LogFn,
    ctx: *anyopaque,
    w: *Io.Writer,
) !Outcome {
    const checkout = for (checkouts) |c| {
        if (std.mem.eql(u8, c.repo, source.repo)) break c.dir;
    } else {
        try w.print("{s}: from {s}, which has no checkout here (--checkout {s}=DIR)\n", .{ file, source.repo, source.repo });
        return .unchecked;
    };
    const commits = log(ctx, arena, checkout, source.commit, source.path) catch |err| {
        try w.print("{s}: {s} {s} at {s}: cannot be checked in {s}: {t}\n", .{ file, source.repo, source.path, source.commit, checkout, err });
        return .unchecked;
    };
    const trimmed = std.mem.trim(u8, commits, "\n");
    if (trimmed.len == 0) return .unchanged;
    try w.print("{s}: {s} {s} changed since {s}:\n", .{ file, source.repo, source.path, source.commit });
    var lines = std.mem.splitScalar(u8, trimmed, '\n');
    while (lines.next()) |line| try w.print("    {s}\n", .{line});
    return .changed;
}

fn worse(a: Outcome, b: Outcome) Outcome {
    return if (@backingInt(b) > @backingInt(a)) b else a;
}

/// Every file under `dirs` whose first line is a provenance line, checked;
/// the worst outcome. Files without one are skipped: they were written here.
fn checkTree(io: Io, arena: Allocator, root: Io.Dir, dirs: []const []const u8, checkouts: []const Checkout, log: LogFn, ctx: *anyopaque, w: *Io.Writer) !Outcome {
    var outcome: Outcome = .unchanged;
    var checked: usize = 0;
    for (dirs) |dir_path| {
        var dir = root.openDir(io, dir_path, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => |e| return e,
        };
        defer dir.close(io);
        var walker = try dir.walk(arena);
        while (try walker.next(io)) |entry| {
            if (entry.kind != .file or !std.mem.endsWith(u8, entry.path, ".zig")) continue;
            const path = try std.fs.path.join(arena, &.{ dir_path, entry.path });
            const text = try root.readFileAlloc(io, path, arena, .limited(16 << 20));
            const first = text[0 .. std.mem.indexOfScalar(u8, text, '\n') orelse text.len];
            const source = parse(first) orelse continue;
            checked += 1;
            outcome = worse(outcome, try checkFile(arena, path, source, checkouts, log, ctx, w));
        }
    }
    try w.print("provenance: {d} ported files checked: {s}\n", .{ checked, switch (outcome) {
        .unchanged => "none changed at its source since its commit",
        .changed => "some changed at their source; carry the fix, then record the new commit",
        .unchecked => "some could not be checked",
    } });
    return outcome;
}

/// `git log` in a real checkout.
fn gitLog(ctx: *anyopaque, arena: Allocator, checkout: []const u8, commit: []const u8, path: []const u8) anyerror![]const u8 {
    const io: *const Io = @ptrCast(@alignCast(ctx));
    // A missing checkout would read as a commit git does not know.
    var dir = Io.Dir.cwd().openDir(io.*, checkout, .{}) catch return error.NoCheckout;
    dir.close(io.*);
    const range = try std.fmt.allocPrint(arena, "{s}..HEAD", .{commit});
    const result = try std.process.run(arena, io.*, .{ .argv = &.{ "git", "-C", checkout, "log", "--oneline", range, "--", path } });
    switch (result.term) {
        .exited => |code| if (code != 0) return error.UnknownCommit,
        else => return error.GitFailed,
    }
    return result.stdout;
}

pub fn main(init: std.process.Init) !u8 {
    var io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    var checkouts: std.ArrayList(Checkout) = .empty;
    try checkouts.appendSlice(arena, &default_checkouts);
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--checkout") and i + 1 < args.len) {
            i += 1;
            const eq = std.mem.indexOfScalar(u8, args[i], '=') orelse return usage();
            try checkouts.insert(arena, 0, .{ .repo = args[i][0..eq], .dir = args[i][eq + 1 ..] });
        } else return usage();
    }
    var buf: [4096]u8 = undefined;
    var out = Io.File.stdout().writerStreaming(io, &buf);
    const outcome = try checkTree(io, arena, Io.Dir.cwd(), &.{ "src", "test", "tools", "examples" }, checkouts.items, gitLog, @ptrCast(&io), &out.interface);
    try out.interface.flush();
    return @backingInt(outcome);
}

fn usage() u8 {
    std.debug.print("usage: provenance [--checkout REPO=DIR]...\n", .{});
    return 2;
}

/// A `LogFn` that answers from a table: the commits after `commit` for each
/// path, or an unknown commit.
const FakeLog = struct {
    changed: []const struct { []const u8, []const u8 },
    unknown_commit: []const u8 = "",

    fn log(ctx: *anyopaque, arena: Allocator, checkout: []const u8, commit: []const u8, path: []const u8) anyerror![]const u8 {
        _ = arena;
        _ = checkout;
        const self: *FakeLog = @ptrCast(@alignCast(ctx));
        if (std.mem.eql(u8, commit, self.unknown_commit)) return error.UnknownCommit;
        for (self.changed) |c| if (std.mem.eql(u8, c[0], path)) return c[1];
        return "";
    }
};

fn checkedTree(files: []const [2][]const u8, fake: *FakeLog, checkouts: []const Checkout) !struct { Outcome, []const u8 } {
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
    const outcome = try checkTree(io, arena.allocator(), tmp.dir, &.{ "src", "tools" }, checkouts, FakeLog.log, fake, &out.writer);
    return .{ outcome, try std.testing.allocator.dupe(u8, out.written()) };
}

test "a ported file changed at its source since its commit is listed with the commits" {
    var fake: FakeLog = .{ .changed = &.{.{ "src/core/transport.zig", "1a2b3c4 Fix the chunked decoder\n5d6e7f8 Read the TLS clock again\n" }} };
    const got = try checkedTree(&.{
        .{ "src/transport.zig", "// From gcp.zig src/core/transport.zig at eae944c.\nconst std = @import(\"std\");\n" },
        .{ "src/retry.zig", "// From gcp.zig src/core/retry.zig at eae944c.\n" },
        .{ "src/own.zig", "//! Written here.\n" },
    }, &fake, &default_checkouts);
    defer std.testing.allocator.free(got[1]);
    try std.testing.expectEqual(.changed, got[0]);
    try std.testing.expect(std.mem.indexOf(u8, got[1], "src/transport.zig: gcp.zig src/core/transport.zig changed since eae944c:\n    1a2b3c4 Fix the chunked decoder\n    5d6e7f8 Read the TLS clock again\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, got[1], "retry.zig:") == null);
    try std.testing.expect(std.mem.indexOf(u8, got[1], "2 ported files checked") != null);
}

test "nothing changed is a pass; an unknown commit or a repo with no checkout is never one" {
    var quiet: FakeLog = .{ .changed = &.{} };
    const pass = try checkedTree(&.{.{ "src/a.zig", "// From gcp.zig src/core/a.zig at eae944c.\n" }}, &quiet, &default_checkouts);
    defer std.testing.allocator.free(pass[1]);
    try std.testing.expectEqual(.unchanged, pass[0]);

    var unknown: FakeLog = .{ .changed = &.{}, .unknown_commit = "deadbee" };
    const bad = try checkedTree(&.{.{ "src/a.zig", "// From gcp.zig src/core/a.zig at deadbee.\n" }}, &unknown, &default_checkouts);
    defer std.testing.allocator.free(bad[1]);
    try std.testing.expectEqual(.unchecked, bad[0]);
    try std.testing.expect(std.mem.indexOf(u8, bad[1], "UnknownCommit") != null);

    const nowhere = try checkedTree(&.{.{ "tools/x.zig", "// From ekur tools/x.zig at abcdef0.\n" }}, &quiet, &default_checkouts);
    defer std.testing.allocator.free(nowhere[1]);
    try std.testing.expectEqual(.unchecked, nowhere[0]);
    try std.testing.expect(std.mem.indexOf(u8, nowhere[1], "--checkout ekur=DIR") != null);
}
