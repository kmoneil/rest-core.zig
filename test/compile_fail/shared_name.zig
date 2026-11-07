//! Must not compile: a Cloud hook that names a 408 `TimedOut`, the
//! transport's own name for a request past its time limit, which the loop
//! would retry as the transport's. build.zig checks the message.

const std = @import("std");
const rest_core = @import("rest_core");

const Hook = struct {
    pub const RefusalError = error{ NotFound, TimedOut };

    pub fn refusal(_: std.mem.Allocator, res: rest_core.transport.Response, _: ?*rest_core.Diagnostics) (RefusalError || std.mem.Allocator.Error) {
        return if (res.status == 408) error.TimedOut else error.NotFound;
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
