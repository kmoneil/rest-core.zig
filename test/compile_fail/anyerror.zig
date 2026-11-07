//! Must not compile: a Cloud hook whose `RefusalError` is `anyerror`, which
//! would make every consumer's error set `anyerror`. build.zig checks the
//! message.

const std = @import("std");
const rest_core = @import("rest_core");

const Hook = struct {
    pub const RefusalError = anyerror;

    pub fn refusal(_: std.mem.Allocator, _: rest_core.transport.Response, _: ?*rest_core.Diagnostics) (RefusalError || std.mem.Allocator.Error) {
        return error.NotFound;
    }

    pub fn retryable(_: anyerror, _: u16) bool {
        return false;
    }

    pub fn bodyDelayMs(_: std.mem.Allocator, _: []const u8) std.mem.Allocator.Error!?u32 {
        return null;
    }
};

comptime {
    _ = rest_core.Engine(.compile_fail, Hook);
}
