//! Must not compile: a Cloud hook with no `bodyDelayMs` is refused where
//! `Engine` binds it, not at a use site, or never. build.zig checks the
//! message.

const std = @import("std");
const rest_core = @import("rest_core");

const Hook = struct {
    pub const RefusalError = error{NotFound};

    pub fn refusal(_: std.mem.Allocator, _: rest_core.transport.Response, _: ?*rest_core.Diagnostics) (RefusalError || std.mem.Allocator.Error) {
        return error.NotFound;
    }

    pub fn retryable(_: anyerror, _: u16) bool {
        return false;
    }
};

comptime {
    _ = rest_core.Engine(.compile_fail, Hook);
}
