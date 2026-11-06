// From gcp.zig src/core/testing.zig at eae944c: the helpers that need no transport. The fakes arrive with the transport and the token seam.
//! Test helpers: a fake clock, allocators that check wiping and refuse
//! large blocks, and a runner for byte-driven property tests that also
//! feeds `zig build test --fuzz`. rest-core's own tests use them, and so can
//! tests of code that uses rest-core. Nothing here is referenced by a
//! normal build.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;

test "FakeClock: cancel protection is kept, and a blocked sleep is not canceled" {
    var clock: FakeClock = .{ .cancel_sleep = true };
    const io = clock.io();
    try std.testing.expectError(error.Canceled, io.sleep(.fromMilliseconds(1), .awake));
    const before = io.swapCancelProtection(.blocked);
    try std.testing.expectEqual(.unblocked, before);
    try io.sleep(.fromMilliseconds(1), .awake);
    try std.testing.expectEqual(.blocked, io.swapCancelProtection(before));
    try std.testing.expectError(error.Canceled, io.sleep(.fromMilliseconds(1), .awake));
}

/// An allocator that counts the blocks that were not all zeros when freed,
/// to test code that must wipe secrets. Such code should free with `rawFree`
/// after wiping: `Allocator.free` overwrites memory with a debug pattern in
/// safe builds, which would hide a missing wipe.
pub const WipeChecker = struct {
    child: Allocator,
    frees: usize = 0,
    unwiped: usize = 0,

    pub fn allocator(self: *WipeChecker) Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }

    fn fromPtr(ptr: *anyopaque) *WipeChecker {
        return @ptrCast(@alignCast(ptr));
    }

    fn alloc(ptr: *anyopaque, len: usize, alignment: Alignment, ret_addr: usize) ?[*]u8 {
        return fromPtr(ptr).child.rawAlloc(len, alignment, ret_addr);
    }

    fn resize(ptr: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) bool {
        return fromPtr(ptr).child.rawResize(memory, alignment, new_len, ret_addr);
    }

    fn remap(ptr: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        return fromPtr(ptr).child.rawRemap(memory, alignment, new_len, ret_addr);
    }

    fn free(ptr: *anyopaque, memory: []u8, alignment: Alignment, ret_addr: usize) void {
        const self = fromPtr(ptr);
        self.frees += 1;
        if (!std.mem.allEqual(u8, memory, 0)) self.unwiped += 1;
        self.child.rawFree(memory, alignment, ret_addr);
    }
};

/// An allocator that refuses any block over `limit` bytes and passes the
/// rest to `child`. `std.testing.checkAllAllocationFailures` fails every
/// allocation after the first one it fails, so a later allocation always
/// reports `OutOfMemory`, and code that swallows the first failure passes
/// the sweep. This fails only the large blocks, such as a compressor's
/// state, and lets everything else through.
pub const RefuseOver = struct {
    child: Allocator,
    limit: usize,
    /// Allocations refused so far.
    refused: usize = 0,

    pub fn allocator(self: *RefuseOver) Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }

    fn fromPtr(ptr: *anyopaque) *RefuseOver {
        return @ptrCast(@alignCast(ptr));
    }

    fn alloc(ptr: *anyopaque, len: usize, alignment: Alignment, ret_addr: usize) ?[*]u8 {
        const self = fromPtr(ptr);
        if (len > self.limit) {
            self.refused += 1;
            return null;
        }
        return self.child.rawAlloc(len, alignment, ret_addr);
    }

    // Growing past the limit is refused too; the caller then allocates,
    // and that is counted.
    fn resize(ptr: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) bool {
        const self = fromPtr(ptr);
        if (new_len > self.limit) return false;
        return self.child.rawResize(memory, alignment, new_len, ret_addr);
    }

    fn remap(ptr: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self = fromPtr(ptr);
        if (new_len > self.limit) return null;
        return self.child.rawRemap(memory, alignment, new_len, ret_addr);
    }

    fn free(ptr: *anyopaque, memory: []u8, alignment: Alignment, ret_addr: usize) void {
        fromPtr(ptr).child.rawFree(memory, alignment, ret_addr);
    }
};

test "RefuseOver: refuses blocks over the limit, and only those" {
    var refuse: RefuseOver = .{ .child = std.testing.allocator, .limit = 64 };
    const a = refuse.allocator();
    const small = try a.alloc(u8, 64);
    defer a.free(small);
    try std.testing.expectError(error.OutOfMemory, a.alloc(u8, 65));
    // Growing past it is refused as well, and small blocks still come.
    const block = try a.alloc(u8, 32);
    defer a.free(block);
    try std.testing.expect(!a.resize(block, 65));
    try std.testing.expectEqual(null, a.remap(block, 65));
    try std.testing.expectEqual(1, refuse.refused);
}

/// An `Io` whose clock, sleep and randomness are simulated. Every other
/// operation fails, as in `std.Io.failing`, so a test cannot touch the network.
pub const FakeClock = struct {
    now_ns: i96 = 0,
    /// Every sleep requested, in nanoseconds, up to the array length.
    sleeps: [64]i96 = undefined,
    sleep_count: usize = 0,
    /// When set, `random` fills every byte with this value instead of the PRNG.
    random_byte: ?u8 = null,
    prng: std.Random.DefaultPrng = .init(0x9e37_79b9_7f4a_7c15),
    /// When set, `sleep` reports cancellation, as a canceled task would see
    /// it, unless the task has blocked cancellation.
    cancel_sleep: bool = false,
    /// What `swapCancelProtection` last set: code that must finish a
    /// cleanup after a cancel blocks it, and a blocked sleep is not canceled.
    cancel_protection: std.Io.CancelProtection = .unblocked,

    pub fn io(self: *FakeClock) std.Io {
        return .{ .userdata = self, .vtable = &vtable };
    }

    /// The recorded sleeps, in milliseconds.
    pub fn sleepMs(self: *const FakeClock, index: usize) i64 {
        return @intCast(@divTrunc(self.sleeps[index], std.time.ns_per_ms));
    }

    const vtable: std.Io.VTable = v: {
        var v = std.Io.failing.vtable.*;
        v.now = now;
        v.sleep = sleep;
        v.random = random;
        v.swapCancelProtection = swapCancelProtection;
        break :v v;
    };

    fn fromUserdata(userdata: ?*anyopaque) *FakeClock {
        return @ptrCast(@alignCast(userdata.?));
    }

    fn now(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
        _ = clock;
        return .{ .nanoseconds = fromUserdata(userdata).now_ns };
    }

    fn sleep(userdata: ?*anyopaque, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = fromUserdata(userdata);
        if (self.cancel_sleep and self.cancel_protection == .unblocked) return error.Canceled;
        const ns: i96 = switch (timeout) {
            .none => 0,
            .duration => |d| d.raw.nanoseconds,
            .deadline => |d| d.raw.nanoseconds - self.now_ns,
        };
        if (self.sleep_count < self.sleeps.len) self.sleeps[self.sleep_count] = ns;
        self.sleep_count += 1;
        self.now_ns += ns;
    }

    fn swapCancelProtection(userdata: ?*anyopaque, new: std.Io.CancelProtection) std.Io.CancelProtection {
        const self = fromUserdata(userdata);
        defer self.cancel_protection = new;
        return self.cancel_protection;
    }

    fn random(userdata: ?*anyopaque, buffer: []u8) void {
        const self = fromUserdata(userdata);
        if (self.random_byte) |b| {
            @memset(buffer, b);
        } else {
            self.prng.random().bytes(buffer);
        }
    }
};

/// Derives structured values from arbitrary bytes. Reads past the end yield
/// zeros, so every input, including the empty one, is valid.
pub const ByteGen = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn init(bytes: []const u8) ByteGen {
        return .{ .bytes = bytes };
    }

    pub fn byte(g: *ByteGen) u8 {
        if (g.pos >= g.bytes.len) return 0;
        defer g.pos += 1;
        return g.bytes[g.pos];
    }

    pub fn boolean(g: *ByteGen) bool {
        return g.byte() & 1 == 1;
    }

    /// An unsigned integer built from the next `@sizeOf(T)` bytes.
    pub fn int(g: *ByteGen, comptime T: type) T {
        comptime std.debug.assert(@typeInfo(T).int.signedness == .unsigned);
        var v: u128 = 0;
        for (0..@sizeOf(T)) |_| v = (v << 8) | g.byte();
        return @truncate(v);
    }

    /// An unsigned integer in `[lo, hi]`.
    pub fn intRange(g: *ByteGen, comptime T: type, lo: T, hi: T) T {
        std.debug.assert(lo <= hi);
        const span: u128 = @as(u128, hi - lo) + 1;
        return lo + @as(T, @intCast(@as(u128, g.int(T)) % span));
    }

    /// Up to `n` of the remaining bytes, fewer at the end of input.
    pub fn take(g: *ByteGen, n: usize) []const u8 {
        const start = @min(g.pos, g.bytes.len);
        const end = start + @min(n, g.bytes.len - start);
        g.pos = end;
        return g.bytes[start..end];
    }

    /// A slice whose length is drawn from `[0, max_len]`.
    pub fn slice(g: *ByteGen, max_len: usize) []const u8 {
        return g.take(g.intRange(usize, 0, max_len));
    }

    /// One of `options`.
    pub fn pick(g: *ByteGen, comptime T: type, options: []const T) T {
        return options[g.intRange(usize, 0, options.len - 1)];
    }

    pub fn rest(g: *ByteGen) []const u8 {
        return g.take(g.bytes.len);
    }

    /// Valid UTF-8 of at most `@min(max_len, out.len)` bytes, weighted toward
    /// what JSON must escape and toward every sequence length.
    pub fn utf8(g: *ByteGen, out: []u8, max_len: usize) []const u8 {
        const target = g.intRange(usize, 0, @min(max_len, out.len));
        var len: usize = 0;
        while (len < target) {
            const cp: u21 = switch (g.intRange(u8, 0, 7)) {
                0 => g.intRange(u21, 0, 0x1f),
                1 => g.pick(u21, &.{ '"', '\\', '/', 0x7f }),
                2, 3 => g.intRange(u21, 0x20, 0x7e),
                4 => g.intRange(u21, 0x80, 0x7ff),
                5 => g.intRange(u21, 0x800, 0xd7ff),
                6 => g.intRange(u21, 0xe000, 0xffff),
                else => g.intRange(u21, 0x10000, 0x10ffff),
            };
            const n = std.unicode.utf8CodepointSequenceLength(cp) catch unreachable;
            if (len + n > target) break;
            _ = std.unicode.utf8Encode(cp, out[len..]) catch unreachable;
            len += n;
        }
        return out[0..len];
    }
};

/// `s` written `n` times over, as a comptime constant that `++` accepts.
/// It stands in for `s ** n`, which Zig 0.17 removed from the language.
pub inline fn repeat(comptime s: []const u8, comptime n: usize) *const [s.len * n]u8 {
    return comptime repeated: {
        const copies: [n][s.len]u8 = @splat(s[0..s.len].*);
        break :repeated @ptrCast(&copies);
    };
}

/// The longest input a property sees under the coverage-guided fuzzer.
pub const max_fuzz_input = 4096;

pub const FuzzOptions = struct {
    /// Inputs that always run. Add every input the fuzzer finds a bug with,
    /// so the fix stays covered.
    corpus: []const []const u8 = &.{},
    /// Pseudo-random inputs per run, from a fixed seed mixed with `--seed`.
    random_runs: u32 = 300,
    /// Longest pseudo-random input.
    max_len: u32 = 512,
};

/// Checks `property` against the corpus, then pseudo-random inputs, then hands
/// it to `std.testing.fuzz`. Under `zig build test --fuzz` that last step is
/// coverage-guided fuzzing; under `zig build test` it is one more smoke run.
pub fn fuzzBytes(
    context: anytype,
    comptime property: fn (@TypeOf(context), []const u8) anyerror!void,
    comptime options: FuzzOptions,
) !void {
    for (options.corpus) |input| {
        property(context, input) catch |err| {
            std.debug.print("property failed on corpus input {x}\n", .{input});
            return err;
        };
    }

    var prng: std.Random.DefaultPrng = .init(0x7075_6273_7562 ^ @as(u64, std.testing.random_seed));
    const random = prng.random();
    var buf: [max_fuzz_input]u8 = undefined;
    for (0..options.random_runs) |_| {
        const input = buf[0..random.uintAtMost(usize, @min(options.max_len, buf.len))];
        random.bytes(input);
        property(context, input) catch |err| {
            std.debug.print("property failed on input {x}\n", .{input});
            return err;
        };
    }

    const Adapter = struct {
        fn testOne(ctx: @TypeOf(context), smith: *std.testing.Smith) anyerror!void {
            var input: [max_fuzz_input]u8 = undefined;
            const n = smith.slice(&input);
            try property(ctx, input[0..n]);
        }
    };
    // The fuzzer reads slices as a little-endian u32 length and then the bytes.
    const seeds = comptime s: {
        var list: [options.corpus.len][]const u8 = undefined;
        for (options.corpus, &list) |input, *seed| {
            const len_le = std.mem.toBytes(std.mem.nativeToLittle(u32, input.len));
            const joined = len_le ++ input[0..input.len].*;
            seed.* = &joined;
        }
        const final = list;
        break :s final;
    };
    try std.testing.fuzz(context, Adapter.testOne, .{ .corpus = &seeds });
}

test "FakeClock records sleeps and advances time" {
    var clock: FakeClock = .{};
    const io = clock.io();
    try io.sleep(.fromMilliseconds(150), .awake);
    try io.sleep(.fromMilliseconds(20), .awake);
    try std.testing.expectEqual(2, clock.sleep_count);
    try std.testing.expectEqual(150, clock.sleepMs(0));
    try std.testing.expectEqual(170 * std.time.ns_per_ms, std.Io.Clock.awake.now(io).nanoseconds);

    // A deadline sleeps the gap between it and now.
    const deadline: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .{ .nanoseconds = 200 * std.time.ns_per_ms } };
    try deadline.wait(io);
    try std.testing.expectEqual(30, clock.sleepMs(2));
    try std.testing.expectEqual(200 * std.time.ns_per_ms, std.Io.Clock.awake.now(io).nanoseconds);

    clock.cancel_sleep = true;
    try std.testing.expectError(error.Canceled, io.sleep(.fromMilliseconds(1), .awake));
}

test "FakeClock random is deterministic or pinned" {
    var a: FakeClock = .{};
    var b: FakeClock = .{};
    var x: [16]u8 = undefined;
    var y: [16]u8 = undefined;
    a.io().random(&x);
    b.io().random(&y);
    try std.testing.expectEqualSlices(u8, &x, &y);

    a.random_byte = 0xff;
    a.io().random(&x);
    try std.testing.expectEqualSlices(u8, &@as([16]u8, @splat(0xff)), &x);
}

test "WipeChecker passes a remap through to its child" {
    var checker: WipeChecker = .{ .child = std.testing.allocator };
    const a = checker.allocator();
    var block = try a.alloc(u8, 16);
    if (a.remap(block, 8)) |smaller| block = smaller;
    // Wipe and free raw, as code under a WipeChecker does: `free` would
    // paint the block with the debug pattern first and look unwiped.
    @memset(block, 0);
    a.rawFree(block, .of(u8), @returnAddress());
    try std.testing.expectEqual(1, checker.frees);
    try std.testing.expectEqual(0, checker.unwiped);
}

fn growMany(gpa: Allocator) !void {
    var list: std.ArrayList(u64) = .empty;
    defer list.deinit(gpa);
    for (0..5_000) |i| try list.append(gpa, i);
    var text: std.Io.Writer.Allocating = .init(gpa);
    defer text.deinit();
    // An allocating writer reports a failed allocation as WriteFailed.
    for (0..2_000) |i| text.writer.print("{d},", .{i}) catch return error.OutOfMemory;
}

// Zig 0.17.1's sweep refuses every resize itself, so code that grows its
// blocks makes the same allocations on every run. On 0.17.0, seven of the
// modules' sweeps failed without the old `no_grow_allocator`
// (docs/zig-std-workarounds.md names them); this one did not.
test "a sweep of code that grows its blocks sees the same allocations every run" {
    for (0..3) |_| try std.testing.checkAllAllocationFailures(std.testing.allocator, growMany, .{});
}

test "repeat writes the text n times, at comptime" {
    try std.testing.expectEqualStrings("abababab", repeat("ab", 4));
    try std.testing.expectEqualStrings("x", repeat("x", 1));
    try std.testing.expectEqualStrings("", repeat("ab", 0));
    try std.testing.expectEqualStrings("", repeat("", 5));
    // Several bytes to a character stay whole, and `++` takes the result.
    try std.testing.expectEqualStrings("<日日日>", "<" ++ repeat("日", 3) ++ ">");
    comptime std.debug.assert(repeat("ab", 4).len == 8);
}

test "ByteGen is total and in range" {
    var g: ByteGen = .init(&.{ 0xff, 0x01, 7 });
    try std.testing.expect(g.intRange(u8, 3, 5) >= 3);
    try std.testing.expectEqual(@as(u16, 0x0107), g.int(u16));
    try std.testing.expectEqual(@as(u32, 0), g.int(u32));
    try std.testing.expectEqualStrings("", g.slice(10));
    try std.testing.expectEqual(@as(u64, 9), g.intRange(u64, 9, 9));

    var full: ByteGen = .init(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    _ = full.intRange(u64, 0, std.math.maxInt(u64));
}

fn utf8Property(_: void, input: []const u8) !void {
    var g: ByteGen = .init(input);
    var buf: [64]u8 = undefined;
    const max = g.intRange(usize, 0, 80);
    const s = g.utf8(&buf, max);
    try std.testing.expect(s.len <= @min(max, buf.len));
    try std.testing.expect(std.unicode.utf8ValidateSlice(s));
}

test "fuzz ByteGen.utf8 always yields valid UTF-8" {
    try fuzzBytes({}, utf8Property, .{ .corpus = &.{ "\x40\x07\xff\xff\xff\xff", "" } });
}
