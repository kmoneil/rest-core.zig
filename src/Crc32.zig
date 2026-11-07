//! CRC-32/ISO-HDLC, the checksum a gzip member's trailer holds, eight bytes
//! a step (slicing-by-8). `std.hash.Crc32` computes the same, a byte a
//! step: about 1.85 ms a MiB on an Apple M5 Max in ReleaseFast, more than
//! the inflate it checks; this takes about 0.35 ms (`zig build bench`,
//! t76). The same interface as std's: `init`, `update`, `final`, `hash`.
//!
//! A value: thread-safe to copy, one task updates each.

const Crc32 = @This();
const std = @import("std");
const test_util = @import("testing.zig");

/// The register, inverted: what `final` inverts back.
state: u32 = 0xffffffff,

/// Eight 256-entry tables, the first the usual byte-a-step table for the
/// reflected polynomial 0xEDB88320, each next one a byte further on.
const tables = blk: {
    @setEvalBranchQuota(20_000);
    var t: [8][256]u32 = undefined;
    for (0..256) |i| {
        var c: u32 = @intCast(i);
        for (0..8) |_| c = if (c & 1 != 0) (c >> 1) ^ 0xEDB88320 else c >> 1;
        t[0][i] = c;
    }
    for (0..256) |i| {
        for (1..8) |k| t[k][i] = (t[k - 1][i] >> 8) ^ t[0][t[k - 1][i] & 0xff];
    }
    break :blk t;
};

/// A checksum of no bytes yet.
pub fn init() Crc32 {
    return .{};
}

/// Adds `bytes`, in order, after those already added.
pub fn update(c: *Crc32, bytes: []const u8) void {
    var crc = c.state;
    var i: usize = 0;
    while (i + 8 <= bytes.len) : (i += 8) {
        const lo = std.mem.readInt(u32, bytes[i..][0..4], .little) ^ crc;
        const hi = std.mem.readInt(u32, bytes[i + 4 ..][0..4], .little);
        crc = tables[7][lo & 0xff] ^ tables[6][(lo >> 8) & 0xff] ^
            tables[5][(lo >> 16) & 0xff] ^ tables[4][lo >> 24] ^
            tables[3][hi & 0xff] ^ tables[2][(hi >> 8) & 0xff] ^
            tables[1][(hi >> 16) & 0xff] ^ tables[0][hi >> 24];
    }
    while (i < bytes.len) : (i += 1) crc = (crc >> 8) ^ tables[0][(crc ^ bytes[i]) & 0xff];
    c.state = crc;
}

/// The checksum of every byte added.
pub fn final(c: Crc32) u32 {
    return ~c.state;
}

/// The checksum of `bytes`.
pub fn hash(bytes: []const u8) u32 {
    var c: Crc32 = .init();
    c.update(bytes);
    return c.final();
}

const testing = std.testing;

test "Crc32: the catalogue's check value, and none of the empty input" {
    // CRC-32/ISO-HDLC's check value: the CRC of "123456789".
    try testing.expectEqual(0xCBF43926, hash("123456789"));
    try testing.expectEqual(0, hash(""));
    try testing.expectEqual(std.hash.Crc32.hash("The quick brown fox jumps over the lazy dog"), hash("The quick brown fox jumps over the lazy dog"));
}

fn agreesWithStd(_: void, input: []const u8) !void {
    try testing.expectEqual(std.hash.Crc32.hash(input), hash(input));
    // In pieces, as a body is hashed while it streams: split where the
    // input's first byte says, so pieces fall on and off eight-byte steps.
    const at = if (input.len == 0) 0 else input[0] % (input.len + 1);
    var c: Crc32 = .init();
    c.update(input[0..at]);
    c.update(input[at..]);
    try testing.expectEqual(std.hash.Crc32.hash(input), c.final());
}

test "fuzz Crc32: agrees with std's, whole and in two pieces" {
    try test_util.fuzzBytes({}, agreesWithStd, .{ .corpus = &.{
        "",
        "a",
        "1234567",
        "12345678",
        "123456789",
        "\xff\x00\xff\x00\xff\x00\xff\x00\xff\x00\xff\x00\xff\x00\xff\x00\xff",
    } });
}
