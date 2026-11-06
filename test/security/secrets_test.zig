//! Secrets in memory: what WipingAllocator leaves behind.

const std = @import("std");
const rest_core = @import("rest_core");
const WipingAllocator = rest_core.WipingAllocator;
const WipeChecker = rest_core.testing.WipeChecker;

test "security: CWE-226 a secret is wiped before its block is freed" {
    var checker: WipeChecker = .{ .child = std.testing.allocator };
    var wiping: WipingAllocator = .init(checker.allocator());
    const a = wiping.allocator();
    const secret = try a.alloc(u8, 64);
    @memcpy(secret, "ya29.a-bearer-token-that-must-not-outlive-its-use-in-freed-memory"[0..64]);
    // Freed raw: `Allocator.free` paints the block first in safe builds,
    // which would hide a missing wipe.
    a.rawFree(secret, .of(u8), @returnAddress());
    try std.testing.expectEqual(1, checker.frees);
    try std.testing.expectEqual(0, checker.unwiped);
}

test "security: CWE-244 a secret's block is never shrunk or moved, which would leave bytes behind unwiped" {
    var checker: WipeChecker = .{ .child = std.testing.allocator };
    var wiping: WipingAllocator = .init(checker.allocator());
    const a = wiping.allocator();
    var secret = try a.alloc(u8, 64);
    @memset(secret, 0x5a);
    // A shrink would hand the tail back unwiped; a move would leave the old
    // copy behind. Both are refused, so the caller copies and frees, and the
    // free wipes.
    try std.testing.expect(!a.resize(secret, 16));
    try std.testing.expectEqual(null, a.remap(secret, 16));
    if (a.remap(secret, 1 << 20)) |grown| {
        // Only growth in place is allowed: the same block, longer.
        try std.testing.expectEqual(secret.ptr, grown.ptr);
        secret = grown;
    }
    a.rawFree(secret, .of(u8), @returnAddress());
    try std.testing.expectEqual(0, checker.unwiped);
}
