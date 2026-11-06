//! The security suite: a test per known attack on an HTTP and REST client,
//! each a row of CATALOG.md, through the public API only, as a hostile
//! server or caller reaches it. tools/security_catalog.zig, run by `zig
//! build test`, fails a row whose test is gone and a test no row names.
//! Each port adds its files here as its rows turn covered.

test {
    _ = @import("rest_core");
}
