//! The certificates beside this file, by name, for
//! test/security/tls_client_test.zig: a module of its own (`tls_chain_certs`
//! in build.zig), since a test outside src/ cannot embed them.

/// `name.der`, as tools/tls_chain_certs.sh wrote it.
pub fn der(comptime name: []const u8) []const u8 {
    return @embedFile(name ++ ".der");
}
