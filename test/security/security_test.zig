//! The security suite: a test per known attack on an HTTP and REST client,
//! each a row of CATALOG.md, through the public API only, as a hostile
//! server or caller reaches it. tools/security_catalog.zig, run by `zig
//! build test`, fails a row whose test is gone and a test no row names.
//! Each port adds its files here as its rows turn covered.

const std = @import("std");

// Not an attack. This module compiles rest_core as a dependency, as a
// consumer's test binary does, so it shows that logging's test-build capture
// works there too: a consumer's tests stay quiet and can read what was logged.
test "rest_core as a dependency: its logging is captured in a consumer's test build" {
    const log = @import("rest_core").logging.Scoped(.rest_core_consumer_test);
    log.capture.reset();
    log.warn("seen {d}", .{1});
    try std.testing.expectEqualStrings("warn: seen 1\n", log.capture.text());
}

test {
    _ = @import("rest_core");
    _ = @import("requests_test.zig");
    _ = @import("retry_test.zig");
    _ = @import("rsa_test.zig");
    _ = @import("secrets_test.zig");
    // Below the public API: the transport's TLS client (deps/zig-tls),
    // over canned flights (CONN-10 to CONN-13), and std's, held to the
    // bugs the copy's patches are there for.
    _ = @import("tls_client_test.zig");
    _ = @import("std_tls_test.zig");
    _ = @import("time_test.zig");
    _ = @import("transport_test.zig");
}
