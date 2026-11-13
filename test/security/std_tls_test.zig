//! std's TLS client against a hostile server's first flight (CONN-11 and
//! CONN-12, t78). Each case runs in std_tls_probe.zig's process, since on
//! Zig 0.17.1 std panics on every one in a safe build (in ReleaseFast it
//! reads or writes out of bounds instead), and std.http.Client, beneath the
//! transport, hands every certificate a server sends to the same code. The
//! tests hold std to its bugs: once one fails, std refuses those bytes with
//! an error, which is what the test should then expect, and its row turns
//! covered.

const std = @import("std");
const testing = std.testing;
const probe = @import("std_tls_probe.zig");
const probe_path = @import("std_tls_probe_bin").path;

/// Runs the probe on `case`: its exit status (null when a signal ended it)
/// and what it printed. Free both.
fn run(case: probe.Case) !struct { code: ?u8, stdout: []u8, stderr: []u8 } {
    const result = try std.process.run(testing.allocator, testing.io, .{ .argv = &.{ probe_path, @tagName(case) } });
    return .{
        .code = switch (result.term) {
            .exited => |code| code,
            else => null,
        },
        .stdout = result.stdout,
        .stderr = result.stderr,
    };
}

/// That std returns `err` for `case`.
fn expectReturns(case: probe.Case, comptime err: anyerror) !void {
    const r = try run(case);
    defer testing.allocator.free(r.stdout);
    defer testing.allocator.free(r.stderr);
    const want = "returned error." ++ @errorName(err) ++ "\n";
    if (r.code == 0 and std.mem.eql(u8, r.stdout, want)) return;
    std.debug.print("std-tls-probe {t}: expected {s}it exited {?d} and printed:\n{s}{s}\n", .{ case, want, r.code, r.stdout, r.stderr });
    return error.TestUnexpectedResult;
}

/// That std panics on `case` with `message`, the bug held to; when std
/// returns an error instead, it says so.
fn expectPanics(case: probe.Case, message: []const u8) !void {
    const r = try run(case);
    defer testing.allocator.free(r.stdout);
    defer testing.allocator.free(r.stderr);
    const first_line = std.mem.sliceTo(r.stderr, '\n');
    if (r.code == probe.panic_exit and std.mem.startsWith(u8, first_line, "panic: ") and std.mem.eql(u8, first_line["panic: ".len..], message)) return;
    if (r.code == 0) {
        std.debug.print("std-tls-probe {t}: std {s}, where Zig 0.17.1 panicked ({s}). Expect that error here, and turn the catalog row covered (t78).\n", .{ case, std.mem.trimEnd(u8, r.stdout, "\n"), message });
    } else {
        std.debug.print("std-tls-probe {t}: expected std's panic \"{s}\"; it exited {?d} and printed:\n{s}{s}\n", .{ case, message, r.code, r.stdout, r.stderr });
    }
    return error.TestUnexpectedResult;
}

test "security: CWE-125 std's TLS client reads past a certificate a server sends, before checking anything (Zig 0.17.1)" {
    // The control: a chain the root signed, for the host, gets as far as
    // the server's signature, which is wrong.
    try expectReturns(.control, error.InvalidSignature);
    // Each runs before any signature or name is checked, so a man in the
    // middle with no certificate at all can send it. A four-byte
    // certificate that claims 65535 (std's der.Element.parse,
    // Certificate.zig:973, reads past it):
    try expectPanics(.short_certificate, "index out of bounds: index 4, len 4");
    // One claiming 4 GiB, its end past a u32 (:1002):
    try expectPanics(.huge_length, "integer overflow");
    // GeneralNames claiming more than their subjectAltName holds, read by
    // the host check once a name does not match (verifyHostName, :331):
    try expectPanics(.subject_alt_name, "index out of bounds: index 13, len 13");
    // A signature BIT STRING of no bytes, last in the certificate
    // (parseBitString, :621):
    try expectPanics(.empty_signature, "index out of bounds: index 220, len 220");
    // An RSA key claiming more than it holds, in the chain's second
    // certificate, read to check the first's signature before anything
    // checks the second's (rsa.PublicKey.parseDer, :1350):
    try expectPanics(.rsa_key, "index out of bounds: index 131, len 8");
}

test "security: CWE-787 std's TLS client copies an RSA signature longer than the key past its buffer (PR ziglang/zig#36695)" {
    // The control: a signature as long as the key, the wrong bytes, is
    // refused.
    try expectReturns(.control, error.InvalidSignature);
    // 300 bytes from a 2048-bit key: PKCS1v1_5Signature.fromBytes
    // (Certificate.zig:1186) copies them into its 256 on the stack. Any
    // server with a certificate for the host can send it, in TLS 1.2's
    // ServerKeyExchange or TLS 1.3's CertificateVerify; in ReleaseFast it
    // writes past the buffer.
    try expectPanics(.long_signature, "index out of bounds: index 300, len 256");
}
