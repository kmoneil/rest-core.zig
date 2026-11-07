//! `zig build bench`: what two per-response costs in the transport come to,
//! built ReleaseFast and measured in this process (t70). Each case runs
//! several times; a run's figure is its time per operation, and the spread
//! between runs is the noise floor a change has to clear.
//!
//! The functions measured are private to transport.zig, so each is
//! replicated here in both forms. Both are thin over std, so the replica
//! does the same work.

const std = @import("std");
const http = std.http;
const flate = std.compress.flate;

const runs = 7;

/// A JSON response's head as Cloud Storage sends one: 21 headers.
const head_bytes = "HTTP/1.1 200 OK\r\n" ++
    "X-GUploader-UploadID: ADPycdtW1Mb5bRrUwzGQ7b4V5nHq8yKkO3n0x7c2qkzLrT0m9Q4z1ZcVvYbHnJmKlPoIuYtReWq\r\n" ++
    "Content-Type: application/json; charset=UTF-8\r\n" ++
    "Date: Sat, 07 Nov 2026 15:00:00 GMT\r\n" ++
    "Vary: Origin\r\n" ++
    "Vary: X-Origin\r\n" ++
    "Cache-Control: no-cache, no-store, max-age=0, must-revalidate\r\n" ++
    "Expires: Mon, 01 Jan 1990 00:00:00 GMT\r\n" ++
    "Pragma: no-cache\r\n" ++
    "ETag: CKih16GjyIkDEAE=\r\n" ++
    "Content-Length: 1234\r\n" ++
    "Server: UploadServer\r\n" ++
    "Alt-Svc: h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000\r\n" ++
    "x-goog-generation: 1700000000000000\r\n" ++
    "x-goog-metageneration: 1\r\n" ++
    "x-goog-stored-content-encoding: identity\r\n" ++
    "x-goog-stored-content-length: 1234\r\n" ++
    "x-goog-hash: crc32c=n03x6A==\r\n" ++
    "x-goog-hash: md5=Ojk9c3dhfxgoKVVHYwFbHQ==\r\n" ++
    "x-goog-storage-class: STANDARD\r\n" ++
    "Accept-Ranges: bytes\r\n" ++
    "\r\n";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    var out_buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &out_buf);
    const w = &stdout.interface;

    // Headers: one response's, each copied out, against one copy of the
    // head with names and values sliced from it, as collectHeaders does.
    const head = try http.Client.Response.Head.parse(head_bytes);
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const per_header = try measure(io, 200_000, struct {
        fn run(a: *std.heap.ArenaAllocator, h: http.Client.Response.Head) !void {
            _ = a.reset(.retain_capacity);
            std.mem.doNotOptimizeAway(try copyEach(a.allocator(), h));
        }
    }.run, .{ &arena, head });
    const one_copy = try measure(io, 200_000, struct {
        fn run(a: *std.heap.ArenaAllocator, h: http.Client.Response.Head) !void {
            _ = a.reset(.retain_capacity);
            std.mem.doNotOptimizeAway(try copyOnce(a.allocator(), h));
        }
    }.run, .{ &arena, head });
    const parse = try measure(io, 200_000, struct {
        fn run(bytes: []const u8) !void {
            std.mem.doNotOptimizeAway(try http.Client.Response.Head.parse(bytes));
        }
    }.run, .{head_bytes});
    try w.print("Headers, ns per response (21 headers), {d} runs: min median max\n", .{runs});
    try report(w, "  each copied (before t70)", per_header);
    try report(w, "  one copy, sliced (since t70)", one_copy);
    try report(w, "  std's head parse, for scale", parse);

    // Trailer hashes over a gzip body's decoded bytes, against the decode.
    const body = try jsonish(gpa, 1 << 20);
    defer gpa.free(body);
    const zipped = try gzip(gpa, body);
    defer gpa.free(zipped);
    const window = try gpa.alloc(u8, flate.max_window_len);
    defer gpa.free(window);
    const inflate = try measure(io, 20, struct {
        fn run(z: []const u8, win: []u8) !void {
            var in: std.Io.Reader = .fixed(z);
            var d: flate.Decompress = .init(&in, .gzip, win);
            var sink_buf: [64 * 1024]u8 = undefined;
            var sink: std.Io.Writer.Discarding = .init(&sink_buf);
            std.mem.doNotOptimizeAway(try d.reader.streamRemaining(&sink.writer));
        }
    }.run, .{ zipped, window });
    const both = try measure(io, 20, hashBoth, .{body});
    const crc_only = try measure(io, 20, hashCrc, .{body});
    const adler_only = try measure(io, 20, hashAdler, .{body});
    try w.print("\nOne MiB decoded from gzip ({d} bytes zipped), us per MiB, {d} runs: min median max\n", .{ zipped.len, runs });
    try reportUs(w, "  inflate", inflate);
    try reportUs(w, "  CRC-32 and Adler-32 (before t70)", both);
    try reportUs(w, "  CRC-32 only (gzip's, since t70)", crc_only);
    try reportUs(w, "  Adler-32 only (zlib's, since t70)", adler_only);
    try w.flush();
}

fn copyEach(arena: std.mem.Allocator, head: http.Client.Response.Head) ![]const http.Header {
    var headers: std.ArrayList(http.Header) = .empty;
    var it = head.iterateHeaders();
    while (it.next()) |h| try headers.append(arena, .{
        .name = try arena.dupe(u8, h.name),
        .value = try arena.dupe(u8, h.value),
    });
    return headers.items;
}

fn copyOnce(arena: std.mem.Allocator, head: http.Client.Response.Head) ![]const http.Header {
    const copy = try arena.dupe(u8, head.bytes);
    var headers: std.ArrayList(http.Header) = .empty;
    var it: http.HeaderIterator = .init(copy);
    while (it.next()) |h| try headers.append(arena, h);
    return headers.items;
}

fn hashBoth(bytes: []const u8) !void {
    var crc: std.hash.Crc32 = .init();
    var adler: std.hash.Adler32 = .{};
    crc.update(bytes);
    adler.update(bytes);
    std.mem.doNotOptimizeAway(crc.final());
    std.mem.doNotOptimizeAway(adler.adler);
}

fn hashCrc(bytes: []const u8) !void {
    var crc: std.hash.Crc32 = .init();
    crc.update(bytes);
    std.mem.doNotOptimizeAway(crc.final());
}

fn hashAdler(bytes: []const u8) !void {
    var adler: std.hash.Adler32 = .{};
    adler.update(bytes);
    std.mem.doNotOptimizeAway(adler.adler);
}

/// Text shaped like a JSON listing, `len` bytes: compressible, not trivially.
fn jsonish(gpa: std.mem.Allocator, len: usize) ![]u8 {
    const out = try gpa.alloc(u8, len);
    var w: std.Io.Writer = .fixed(out);
    var i: u64 = 0;
    while (true) : (i += 1) {
        w.print("{{\"name\":\"projects/p/topics/t{d}\",\"generation\":\"{d}\",\"size\":\"{d}\"}},", .{ i, i *% 2654435761, i % 977 }) catch break;
    }
    @memset(out[w.end..], ' ');
    return out;
}

fn gzip(gpa: std.mem.Allocator, data: []const u8) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    const window = try gpa.alloc(u8, flate.max_window_len);
    defer gpa.free(window);
    var c: flate.Compress = try .init(&out.writer, window, .gzip, .level_6);
    try c.writer.writeAll(data);
    try c.finish();
    return out.toOwnedSlice();
}

/// Runs `func` `iters` times per run, `runs` times, and returns each run's
/// nanoseconds per call, sorted.
fn measure(io: std.Io, iters: u64, comptime func: anytype, args: anytype) ![runs]u64 {
    var per_call: [runs]u64 = undefined;
    // One warm-up run first, not counted.
    for (0..runs + 1) |r| {
        const start = std.Io.Clock.awake.now(io);
        for (0..iters) |_| try @call(.never_inline, func, args);
        const ns: u64 = @intCast(start.durationTo(std.Io.Clock.awake.now(io)).nanoseconds);
        if (r > 0) per_call[r - 1] = ns / iters;
    }
    std.mem.sort(u64, &per_call, {}, std.sort.asc(u64));
    return per_call;
}

fn report(w: *std.Io.Writer, label: []const u8, t: [runs]u64) !void {
    try w.print("{s:<34} {d:>8} {d:>8} {d:>8}\n", .{ label, t[0], t[runs / 2], t[runs - 1] });
}

fn reportUs(w: *std.Io.Writer, label: []const u8, t: [runs]u64) !void {
    try w.print("{s:<34} {d:>8} {d:>8} {d:>8}\n", .{ label, t[0] / 1000, t[runs / 2] / 1000, t[runs - 1] / 1000 });
}
