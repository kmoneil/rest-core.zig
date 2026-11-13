// From ekur src/runtime/tls_test.zig at ba2c6c7 (its t380, t382, t383), on rest-core's copy of the client, which offers no TLS 1.2 ECDSA suite.
//! The transport's TLS client (deps/zig-tls: std's, patched, t78) against
//! a server's first flight, canned: in TLS 1.2 the ServerHello and the
//! Certificate message travel in the clear, so the chain checks run on
//! bytes a test can write, with no server and no network. The chains are
//! src/testdata/tls_chain (tools/tls_chain_certs.sh; its README says what
//! each is). TLS 1.3 sends the same message encrypted, through the same
//! loop in the client.
//!
//! A hostile server's bytes must never crash the client: certificates no
//! CA would sign, built here by `testCert`, and a fuzz target over the
//! whole flight. The last test sends one through `HttpTransport`, so the
//! transport is shown to be on this client.

const std = @import("std");
const rest_core = @import("rest_core");
const Client = @import("zig_tls");
const certs = @import("tls_chain_certs");

const Io = std.Io;
const Certificate = std.crypto.Certificate;
const testing = std.testing;

fn der(comptime name: []const u8) []const u8 {
    return certs.der(name);
}

/// 2026-05-28, inside every test certificate's validity (2026 to 2126).
const now: Io.Timestamp = .fromNanoseconds(1_780_000_000 * std.time.ns_per_s);

/// The ServerKeyExchange the canned server sends after its certificates,
/// with curve type 0 where a server says 3 (named_curve): a client that
/// took the chain reads it and stops with `error.TlsIllegalParameter`.
const trusted = error.TlsIllegalParameter;

/// What the client makes of a TLS 1.2 server for localhost that sends
/// `chain`, the server's certificate first, when it trusts the test roots
/// alone: the error the handshake stops with. `trusted` means the chain
/// was taken; a chain no root vouches for is `TlsCertificateNotVerified`.
fn handshake(chain: []const []const u8) anyerror!void {
    return handshakeWith(.{ .chain = chain });
}

/// A canned server's first flight, in one handshake record.
const Flight = struct {
    /// The server's certificate first.
    chain: []const []const u8,
    /// The suite the ServerHello picks: ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    /// which std offers. Nothing the client does with a certificate looks
    /// at it before the ServerKeyExchange.
    suite: u16 = 0xC02F,
    /// The ServerKeyExchange: by default the one `trusted` describes.
    key_exchange: []const u8 = &.{ 0x00, 0x00, 0x17, 0x41 },
    /// The host the client asks for.
    host: []const u8 = "localhost",
};

fn handshakeWith(f: Flight) anyerror!void {
    const flight = try serverFlight(testing.allocator, f);
    defer testing.allocator.free(flight);
    return handshakeBytes(flight, f.host);
}

/// The roots the client trusts: `root`, which signed most chains, and
/// others whose own limits are under test, each with a name of its own.
const roots = .{ "root", "nc-root", "len-root", "eku-root", "crit-root", "pinned" };

/// The client against `flight`, the server's bytes as they are: what the
/// fuzz target hands it.
fn handshakeBytes(flight: []const u8, host: []const u8) anyerror!void {
    const gpa = testing.allocator;
    var bundle: Certificate.Bundle = .empty;
    defer bundle.deinit(gpa);
    inline for (roots) |name| {
        const start: u32 = @intCast(bundle.bytes.items.len);
        try bundle.bytes.appendSlice(gpa, der(name));
        try bundle.parseCert(gpa, start, now.toSeconds());
    }
    var lock: Io.RwLock = .init;

    // The client asks for a reader buffer of a whole record; the flight
    // is its first bytes, and there is nothing after it.
    const in_buf = try gpa.alloc(u8, Client.min_buffer_len);
    defer gpa.free(in_buf);
    if (flight.len > in_buf.len) return error.FlightTooLong;
    @memcpy(in_buf[0..flight.len], flight);
    var in: Io.Reader = .fixed(in_buf);
    in.end = flight.len;
    var out_buf: [4096]u8 = undefined;
    var out: Io.Writer = .fixed(&out_buf);
    const read_buf = try gpa.alloc(u8, Client.min_buffer_len);
    defer gpa.free(read_buf);
    const write_buf = try gpa.alloc(u8, Client.min_buffer_len);
    defer gpa.free(write_buf);
    const entropy: [Client.Options.entropy_len]u8 = @splat(7);

    _ = try Client.init(&in, &out, .{
        .host = .{ .explicit = host },
        .ca = .{ .bundle = .{ .gpa = gpa, .io = testing.io, .lock = &lock, .bundle = &bundle } },
        .read_buffer = read_buf,
        .write_buffer = write_buf,
        .entropy = &entropy,
        .realtime_now = now,
    });
    return error.TestUnexpectedResult; // the canned flight never finishes a handshake
}

/// One handshake record: a TLS 1.2 ServerHello choosing `f.suite`, the
/// Certificate message with `f.chain`, and `f.key_exchange`.
fn serverFlight(gpa: std.mem.Allocator, f: Flight) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    // ServerHello: version, random, no session id, the suite, no compression.
    const random: [32]u8 = @splat(0x11);
    const hello = [_]u8{ 0x03, 0x03 } ++ random ++ [_]u8{ 0x00, @intCast(f.suite >> 8), @truncate(f.suite), 0x00 };
    try message(gpa, &body, 2, &hello);
    var chain: std.ArrayList(u8) = .empty;
    defer chain.deinit(gpa);
    var size: usize = 0;
    for (f.chain) |c| size += 3 + c.len;
    try putU24(gpa, &chain, size);
    for (f.chain) |c| {
        try putU24(gpa, &chain, c.len);
        try chain.appendSlice(gpa, c);
    }
    try message(gpa, &body, 11, chain.items);
    try message(gpa, &body, 12, f.key_exchange);

    var record: std.ArrayList(u8) = .empty;
    errdefer record.deinit(gpa);
    try record.appendSlice(gpa, &.{ 0x16, 0x03, 0x03 });
    try record.appendSlice(gpa, &std.mem.toBytes(std.mem.nativeToBig(u16, @intCast(body.items.len))));
    try record.appendSlice(gpa, body.items);
    return record.toOwnedSlice(gpa);
}

fn message(gpa: std.mem.Allocator, to: *std.ArrayList(u8), kind: u8, payload: []const u8) !void {
    try to.append(gpa, kind);
    try putU24(gpa, to, payload.len);
    try to.appendSlice(gpa, payload);
}

fn putU24(gpa: std.mem.Allocator, to: *std.ArrayList(u8), n: usize) !void {
    try to.appendSlice(gpa, &.{ @intCast(n >> 16 & 0xFF), @intCast(n >> 8 & 0xFF), @intCast(n & 0xFF) });
}

test "security: CWE-296 a certificate signed by one that is not a CA is refused" {
    // The attack: the root signed attacker.example's certificate, which is
    // no CA, and its key signed one for localhost. std's client alone
    // takes it (Codeberg ziglang/zig#35877).
    try testing.expectError(error.CertificateIssuerNotCa, handshake(&.{ der("forged"), der("attacker") }));
    // A signer with no basicConstraints is no CA either, nor one with no
    // extensions at all.
    try testing.expectError(error.CertificateIssuerNotCa, handshake(&.{ der("bare-leaf"), der("bare") }));
    try testing.expectError(error.CertificateIssuerNotCa, handshake(&.{ der("plain-leaf"), der("plain") }));
}

test "security: CWE-296 a CA whose keyUsage leaves out keyCertSign signs no certificate" {
    try testing.expectError(error.CertificateIssuerKeyUsage, handshake(&.{ der("no-sign-leaf"), der("no-sign") }));
}

test "security: CWE-296 a CA under one whose pathLenConstraint is 0 is refused" {
    try testing.expectError(error.CertificatePathLenExceeded, handshake(&.{ der("deep-leaf"), der("deep"), der("inter0") }));
}

test "tls: chains through intermediate CAs are taken, and one no root signed is not" {
    try testing.expectError(trusted, handshake(&.{ der("good"), der("inter0") }));
    // A self-issued intermediate (a new key under the old name) does not
    // count against pathLenConstraint 0.
    try testing.expectError(trusted, handshake(&.{ der("rollover-leaf"), der("rollover"), der("inter0") }));
    try testing.expectError(trusted, handshake(&.{ der("open-leaf"), der("open-sub"), der("open") }));
    // Without its intermediate, nothing in the bundle signed it: so
    // `trusted` above is the chain taken, not any chain.
    try testing.expectError(error.TlsCertificateNotVerified, handshake(&.{der("good")}));
}

// The limits a certificate states about itself (CONN-13). std reads none
// of them; each test's chain is one std's client alone would take.

test "security: CWE-295 a CA that nameConstraints hold to other names signs nothing for this host" {
    const refused = error.CertificateNameConstraints;
    // Held to example.com, it signed one for localhost.
    try testing.expectError(refused, handshake(&.{ der("nc-dns-leaf"), der("nc-dns") }));
    // With no subjectAltName, so a common name of localhost, which std's
    // host check falls back to.
    try testing.expectError(refused, handshake(&.{ der("nc-cn-leaf"), der("nc-dns") }));
    // Through a CA of its own under it, which states no constraints.
    try testing.expectError(refused, handshake(&.{ der("nc-mid-leaf"), der("nc-mid"), der("nc-dns") }));
    // A leaf for www.example.com is in it, but not through a CA under it
    // whose own subjectAltName is localhost: every certificate under a
    // constrained one is held to it.
    try testing.expectError(trusted, handshakeWith(.{ .chain = &.{ der("nc-www-leaf"), der("nc-dns") }, .host = "www.example.com" }));
    try testing.expectError(refused, handshakeWith(.{ .chain = &.{ der("nc-san-leaf"), der("nc-san-mid"), der("nc-dns") }, .host = "www.example.com" }));
    // Held to every name but localhost.
    try testing.expectError(refused, handshake(&.{ der("nc-excl-leaf"), der("nc-excl") }));
    // Held to 10.0.0.0/8, it signed one for 127.0.0.1.
    try testing.expectError(refused, handshakeWith(.{ .chain = &.{ der("nc-ip-leaf"), der("nc-ip") }, .host = "127.0.0.1" }));
    // Held to localhost, it signs for localhost.
    try testing.expectError(trusted, handshake(&.{ der("nc-ok-leaf"), der("nc-ok") }));
}

test "security: CWE-295 nameConstraints of a form rest-core does not check refuse the chain" {
    // Email addresses: a limit the client does not read could be one that
    // keeps this certificate out, so it is not passed over.
    try testing.expectError(error.CertificateNameConstraints, handshake(&.{ der("nc-email-leaf"), der("nc-email") }));
}

test "security: CWE-295 a certificate whose extended key usage leaves out serverAuth is no server's" {
    const refused = error.CertificateExtKeyUsage;
    // A certificate for client logins, which a CA may issue on less proof
    // of the name than a server's needs.
    try testing.expectError(refused, handshake(&.{der("client-leaf")}));
    try testing.expectError(refused, handshake(&.{der("any-leaf")}));
    // A CA for mail and client logins signed a server's.
    try testing.expectError(refused, handshake(&.{ der("smime-leaf"), der("smime") }));
    // No extended key usage at all limits nothing; a CA's that lists
    // serverAuth allows it.
    try testing.expectError(trusted, handshake(&.{der("noeku-leaf")}));
    try testing.expectError(trusted, handshake(&.{ der("tls-ca-leaf"), der("tls-ca") }));
}

test "security: CWE-295 a certificate with a critical extension rest-core does not process is refused" {
    const refused = error.CertificateUnhandledCriticalExtension;
    try testing.expectError(refused, handshake(&.{der("crit-leaf")}));
    // A precertificate: Certificate Transparency's poison is there to make
    // every client refuse it.
    try testing.expectError(refused, handshake(&.{der("poison-leaf")}));
    // policyConstraints: the client does no policy processing.
    try testing.expectError(refused, handshake(&.{ der("policy-leaf"), der("policy") }));
    // The same unknown extension, not critical, is passed over.
    try testing.expectError(trusted, handshake(&.{der("note-leaf")}));
}

test "security: CWE-296 a root's own limits hold for the chain under it" {
    try testing.expectError(error.CertificateNameConstraints, handshake(&.{der("nc-root-leaf")}));
    try testing.expectError(error.CertificatePathLenExceeded, handshake(&.{ der("len-leaf"), der("len-inter") }));
    try testing.expectError(error.CertificateExtKeyUsage, handshake(&.{der("eku-root-leaf")}));
    try testing.expectError(error.CertificateUnhandledCriticalExtension, handshake(&.{der("crit-root-leaf")}));
    // A root is a signer by being trusted: a server's own self-signed
    // certificate, no CA, pinned as the one root.
    try testing.expectError(trusted, handshake(&.{der("pinned")}));
}

// Certificates no CA would sign, for the crash tests (CONN-11, CONN-12).
// The client reads a server's certificate before it checks any signature,
// so what a hostile server sends needs no CA at all.

const oid_ecdsa_sha256 = "\x2A\x86\x48\xCE\x3D\x04\x03\x02";
const oid_rsa_sha256 = "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0B";
/// AlgorithmIdentifier contents: id-ecPublicKey with prime256v1.
const alg_ec_p256 = "\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07";
/// AlgorithmIdentifier contents: rsaEncryption, NULL parameters.
const alg_rsa = "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00";

/// A BIT STRING's contents: no unused bits, then an uncompressed P-256
/// point (not on the curve: nothing here gets as far as using it).
const p256_bits = [_]u8{ 0x00, 0x04 } ++ @as([64]u8, @splat(0x11));

const CertSpec = struct {
    sig_alg: []const u8 = oid_ecdsa_sha256,
    /// The fixtures' root, whose name the certificates were made under.
    issuer: []const u8 = "ekur test root",
    subject: []const u8 = "localhost",
    key_alg: []const u8 = alg_ec_p256,
    /// The subjectPublicKey BIT STRING's whole contents, its unused-bits
    /// byte first: a P-256 point by default.
    key_bits: []const u8 = &p256_bits,
    /// Each a whole Extension's DER; none at all when null.
    extensions: ?[]const []const u8 = null,
    signature: []const u8 = "\x30\x06\x02\x01\x01\x02\x01\x01",
    /// The signature BIT STRING's whole contents, in place of an
    /// unused-bits byte and `signature`.
    signature_bits: ?[]const u8 = null,
};

/// A DER element: `tag`, its length (long form past 127), then `parts`.
fn tlvOf(a: std.mem.Allocator, tag: u8, parts: []const []const u8) ![]const u8 {
    const body = try std.mem.concat(a, u8, parts);
    var head: [4]u8 = undefined;
    head[0] = tag;
    const n: usize = if (body.len < 0x80) blk: {
        head[1] = @intCast(body.len);
        break :blk 2;
    } else if (body.len < 0x100) blk: {
        head[1] = 0x81;
        head[2] = @intCast(body.len);
        break :blk 3;
    } else blk: {
        head[1] = 0x82;
        head[2] = @intCast(body.len >> 8);
        head[3] = @truncate(body.len);
        break :blk 4;
    };
    return std.mem.concat(a, u8, &.{ head[0..n], body });
}

/// A Name with one common name.
fn testName(a: std.mem.Allocator, cn: []const u8) ![]const u8 {
    const atav = try tlvOf(a, 0x30, &.{ "\x06\x03\x55\x04\x03", try tlvOf(a, 0x0C, &.{cn}) });
    return tlvOf(a, 0x30, &.{try tlvOf(a, 0x31, &.{atav})});
}

fn testCert(a: std.mem.Allocator, s: CertSpec) ![]const u8 {
    const alg = try tlvOf(a, 0x30, &.{try tlvOf(a, 0x06, &.{s.sig_alg})});
    const validity = try tlvOf(a, 0x30, &.{ try tlvOf(a, 0x17, &.{"260101000000Z"}), try tlvOf(a, 0x18, &.{"21260101000000Z"}) });
    const spki = try tlvOf(a, 0x30, &.{ try tlvOf(a, 0x30, &.{s.key_alg}), try tlvOf(a, 0x03, &.{s.key_bits}) });
    const exts: []const u8 = if (s.extensions) |e| try tlvOf(a, 0xA3, &.{try tlvOf(a, 0x30, e)}) else "";
    const tbs = try tlvOf(a, 0x30, &.{ "\xA0\x03\x02\x01\x02", "\x02\x01\x01", alg, try testName(a, s.issuer), validity, try testName(a, s.subject), spki, exts });
    const sig = s.signature_bits orelse try std.mem.concat(a, u8, &.{ "\x00", s.signature });
    return tlvOf(a, 0x30, &.{ tbs, alg, try tlvOf(a, 0x03, &.{sig}) });
}

/// A subjectAltName extension whose contents are `names`, as written.
fn sanExt(a: std.mem.Allocator, names: []const u8) ![]const u8 {
    return tlvOf(a, 0x30, &.{ "\x06\x03\x55\x1D\x11", try tlvOf(a, 0x04, &.{names}) });
}

test "tls: a certificate testCert builds for localhost is read as one" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Unsigned, so no root vouches for it: it gets as far as the root's
    // signature check, which a certificate std cannot read never reaches.
    try testing.expectError(error.CertificateSignatureInvalid, handshake(&.{try testCert(a, .{})}));
    const san = try sanExt(a, "\x30\x0B\x82\x09localhost");
    try testing.expectError(error.CertificateSignatureInvalid, handshake(&.{try testCert(a, .{ .subject = "x", .extensions = &.{san} })}));
}

test "security: CWE-125 a certificate whose DER runs past its bytes is refused, never read past" {
    // A SEQUENCE that claims 65535 bytes, in four: std's parser reads
    // past it (test/security/std_tls_test.zig holds std to that).
    try testing.expectError(error.CertificateFieldHasInvalidLength, handshake(&.{"\x30\x82\xFF\xFF"}));
    // One that claims 4 GB: std adds that to its place in a u32.
    try testing.expectError(error.CertificateFieldHasInvalidLength, handshake(&.{"\x30\x84\xFF\xFF\xFF\xFF"}));
}

test "security: CWE-125 a subjectAltName that runs past its bytes is refused, never read past" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // GeneralNames claiming 127 bytes inside an extension of 13, its one
    // name not the host, so the check reads on for the next.
    const san = try sanExt(a, "\x30\x7F\x82\x09otherhost");
    try testing.expectError(error.CertificateFieldHasInvalidLength, handshake(&.{try testCert(a, .{ .extensions = &.{san} })}));
}

test "security: CWE-125 a BIT STRING with no bits is refused, never read past" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Not even its unused-bits byte: std reads the byte after it for that,
    // which for the signature, last in the certificate, is past the end.
    try testing.expectError(error.CertificateFieldHasInvalidLength, handshake(&.{try testCert(a, .{ .signature_bits = "" })}));
    try testing.expectError(error.CertificateFieldHasInvalidLength, handshake(&.{try testCert(a, .{ .key_bits = "" })}));
}

test "security: CWE-125 an RSA key that runs past its bytes is refused, never read past" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // The server's certificate says an RSA key signed it, and the next
    // names that key's holder: std reads that key to check the first
    // signature before anything has checked the second certificate's.
    const leaf = try testCert(a, .{ .sig_alg = oid_rsa_sha256, .issuer = "ekur hostile" });
    // RSAPublicKey whose modulus claims 127 bytes of 6.
    const key = try testCert(a, .{ .subject = "ekur hostile", .key_alg = alg_rsa, .key_bits = "\x00\x30\x06\x02\x7F\x01\x02\x03\x04" });
    try testing.expectError(error.CertificateFieldHasInvalidLength, handshake(&.{ leaf, key }));
}

/// A ServerKeyExchange for x25519 signed rsa_pkcs1_sha256 with `sig_len`
/// bytes that are no signature.
fn rsaKeyExchange(a: std.mem.Allocator, comptime sig_len: u16) ![]const u8 {
    const sig: [sig_len]u8 = @splat(0x5A);
    const share: [32]u8 = @splat(9);
    return std.mem.concat(a, u8, &.{
        "\x03\x00\x1D\x20", &share, // named_curve, x25519, its key
        "\x04\x01", &.{ sig_len >> 8, sig_len & 0xFF }, &sig, // rsa_pkcs1_sha256
    });
}

test "security: CWE-787 an RSA signature longer than its key is refused, never copied past its buffer" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // The root signed this RSA leaf, so the chain is taken; then the
    // server signs its key share with 300 bytes, where a 2048-bit key's
    // signature is 256. Any server with an RSA certificate can send it.
    try testing.expectError(error.InvalidSignature, handshakeWith(.{ .chain = &.{der("rsa-leaf")}, .key_exchange = try rsaKeyExchange(a, 300) }));
    // As long as the key, it reaches the check of the signature itself.
    try testing.expectError(error.InvalidSignature, handshakeWith(.{ .chain = &.{der("rsa-leaf")}, .key_exchange = try rsaKeyExchange(a, 256) }));
}

// The fuzz target: a server's first flight, near ones the client reads far
// into, changed. Nothing it sends may crash the client; any error is fine.

/// Flights the fuzz target starts from: chains std reads all of, an RSA
/// one signing its key share, built ones that reach the host check's
/// name list and an RSA key read before its holder is checked, and ones
/// whose nameConstraints and critical extensions tls_chain reads.
const FuzzCorpus = struct {
    flights: []const Flight,
    /// Where each flight as it is stops: `trusted` for one taken, or the
    /// error it is refused with.
    ends: []const anyerror,
};

fn fuzzCorpus(a: std.mem.Allocator) !FuzzCorpus {
    // Another host, an address, then this one: the check reads them all.
    const names = try sanExt(a, "\x30\x1C\x82\x09otherhost\x87\x04\x7F\x00\x00\x01\x82\x09localhost");
    const rsa_key = "\x00\x30\x0D\x02\x08\xC1\x02\x03\x04\x05\x06\x07\x08\x02\x01\x03";
    // Each chain in the arena: a literal of runtime values would be on
    // this function's stack.
    const flights = try a.dupe(Flight, &.{
        .{ .chain = try a.dupe([]const u8, &.{ der("good"), der("inter0") }) },
        .{ .chain = try a.dupe([]const u8, &.{ der("rollover-leaf"), der("rollover"), der("inter0") }) },
        .{ .chain = try a.dupe([]const u8, &.{ der("open-leaf"), der("open-sub"), der("open") }) },
        .{ .chain = try a.dupe([]const u8, &.{ der("forged"), der("attacker") }) },
        .{ .chain = try a.dupe([]const u8, &.{ der("plain-leaf"), der("plain") }) },
        .{ .chain = try a.dupe([]const u8, &.{der("rsa-leaf")}), .key_exchange = try rsaKeyExchange(a, 256) },
        .{ .chain = try a.dupe([]const u8, &.{try testCert(a, .{ .extensions = &.{names} })}) },
        .{ .chain = try a.dupe([]const u8, &.{
            try testCert(a, .{ .sig_alg = oid_rsa_sha256, .issuer = "ekur hostile" }),
            try testCert(a, .{ .subject = "ekur hostile", .key_alg = alg_rsa, .key_bits = rsa_key }),
        }) },
        // What CONN-13 reads: nameConstraints taken and refused, under a
        // CA and the root, and a critical extension.
        .{ .chain = try a.dupe([]const u8, &.{ der("nc-ok-leaf"), der("nc-ok") }) },
        .{ .chain = try a.dupe([]const u8, &.{ der("nc-mid-leaf"), der("nc-mid"), der("nc-dns") }) },
        .{ .chain = try a.dupe([]const u8, &.{ der("nc-ip-leaf"), der("nc-ip") }), .host = "127.0.0.1" },
        .{ .chain = try a.dupe([]const u8, &.{der("nc-root-leaf")}) },
        .{ .chain = try a.dupe([]const u8, &.{ der("policy-leaf"), der("policy") }) },
    });
    const ends = try a.dupe(anyerror, &.{
        trusted,
        trusted,
        trusted,
        error.CertificateIssuerNotCa,
        error.CertificateIssuerNotCa,
        error.InvalidSignature, // the key share's signature, checked with the key
        error.CertificateSignatureInvalid, // unsigned: no root signed it
        error.CertificateSignatureUnsupportedBitCount, // the second's RSA key read, too small
        trusted,
        error.CertificateNameConstraints,
        error.CertificateNameConstraints,
        error.CertificateNameConstraints,
        error.CertificateUnhandledCriticalExtension,
    });
    return .{ .flights = flights, .ends = ends };
}

/// The fuzzer's bytes read as decisions, a byte or two each, as ekur's
/// `Draw` draws them; 0 once they run out.
const Draw = struct {
    bytes: []const u8,

    fn byte(d: *Draw) u8 {
        if (d.bytes.len == 0) return 0;
        defer d.bytes = d.bytes[1..];
        return d.bytes[0];
    }

    /// A number below `len`, which must not be 0.
    fn index(d: *Draw, len: usize) usize {
        const hi: usize = d.byte();
        return (hi << 8 | d.byte()) % len;
    }

    fn atMost(d: *Draw, at_least: u8, at_most: u8) u8 {
        return at_least + d.byte() % (at_most - at_least + 1);
    }

    fn boolean(d: *Draw) bool {
        return d.byte() & 1 == 1;
    }

    fn pick(d: *Draw, comptime T: type, items: []const T) T {
        return items[d.index(items.len)];
    }
};

/// Bytes that mean something in DER: tags, lengths short and long.
const der_bytes = "\x00\x01\x02\x03\x04\x05\x06\x0C\x17\x18\x30\x31\x7F\x80\x81\x82\x83\x84\x85\xA0\xA3\xFF";

/// `bytes`, in `buf`, changed by one to four edits: a byte set (to one
/// that means something in DER, or any), nudged by a little (a length
/// one off), put in, taken out, or the rest cut off.
fn mutateDer(d: *Draw, buf: []u8, bytes: []const u8) []u8 {
    var len = @min(bytes.len, buf.len);
    @memcpy(buf[0..len], bytes[0..len]);
    for (0..d.atMost(1, 4)) |_| {
        if (len == 0) break;
        const at = d.index(len);
        switch (d.index(5)) {
            0 => buf[at] = if (d.boolean()) d.pick(u8, der_bytes) else d.byte(),
            1 => buf[at] = if (d.boolean()) buf[at] +% d.atMost(1, 3) else buf[at] -% d.atMost(1, 3),
            2 => if (len < buf.len) {
                std.mem.copyBackwards(u8, buf[at + 1 .. len + 1], buf[at..len]);
                buf[at] = d.pick(u8, der_bytes);
                len += 1;
            },
            3 => {
                std.mem.copyForwards(u8, buf[at .. len - 1], buf[at + 1 .. len]);
                len -= 1;
            },
            else => len = at,
        }
    }
    return buf[0..len];
}

fn fuzzFlight(corpus: FuzzCorpus, input: []const u8) anyerror!void {
    var d: Draw = .{ .bytes = input };
    const base = d.pick(Flight, corpus.flights);
    var bufs: [4][2048]u8 = undefined;
    var chain: [4][]const u8 = undefined;
    for (base.chain, 0..) |c, i| chain[i] = c;
    var f = base;
    // One certificate changed, or the key exchange.
    const which = d.index(base.chain.len + 1);
    if (which < base.chain.len) {
        chain[which] = mutateDer(&d, &bufs[which], base.chain[which]);
    } else {
        f.key_exchange = mutateDer(&d, &bufs[3], base.key_exchange);
    }
    f.chain = chain[0..base.chain.len];
    handshakeWith(f) catch {};
}

test "fuzz: no flight a TLS server sends crashes the transport's TLS client" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const corpus = try fuzzCorpus(arena.allocator());
    for (corpus.flights, corpus.ends) |f, end| try testing.expectError(end, handshakeWith(f));
    try rest_core.testing.fuzzBytes(corpus, fuzzFlight, .{ .max_len = 64 });
}

// Through the transport: a server that answers the ClientHello with a
// flight, so what the client does with it is what `HttpTransport` does.

/// A server on loopback that reads a ClientHello's record, answers with
/// `flight`, and holds the connection until the client closes it.
const FlightServer = struct {
    server: Io.net.Server,
    flight: []const u8,

    fn start(io: Io, flight: []const u8) !FlightServer {
        const address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        return .{ .server = try address.listen(io, .{ .reuse_address = true }), .flight = flight };
    }

    fn run(s: *FlightServer, io: Io) !void {
        const stream = try s.server.accept(io);
        defer stream.close(io);
        var read_buf: [1024]u8 = undefined;
        var reader = stream.reader(io, &read_buf);
        const head = try reader.interface.takeArray(5);
        try reader.interface.discardAll(std.mem.readInt(u16, head[3..5], .big));
        var write_buf: [1024]u8 = undefined;
        var writer = stream.writer(io, &write_buf);
        try writer.interface.writeAll(s.flight);
        try writer.interface.flush();
        // Until the client sends an alert and hangs up.
        _ = reader.interface.discardRemaining() catch {};
    }

    fn url(s: *const FlightServer, buf: []u8, host: []const u8) []const u8 {
        return std.fmt.bufPrint(buf, "https://{s}:{d}/", .{ host, s.server.socket.address.getPort() }) catch unreachable;
    }
};

/// What `HttpTransport` makes of a server that answers with `f`, trusting
/// the fixtures' root alone.
fn sendThrough(f: Flight, host: []const u8) !rest_core.transport.Response {
    const io = testing.io;
    const flight = try serverFlight(testing.allocator, f);
    defer testing.allocator.free(flight);
    var server: FlightServer = try .start(io, flight);
    defer server.server.deinit(io);
    var serving = try io.concurrent(FlightServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var ht: rest_core.transport.HttpTransport = .init(testing.allocator, io, "t");
    defer ht.deinit();
    const bundle = &ht.client.ca_bundle;
    try bundle.bytes.appendSlice(testing.allocator, der("root"));
    try bundle.parseCert(testing.allocator, 0, Io.Clock.real.now(io).toSeconds());
    // Set, so std does not rescan the system roots first.
    ht.client.now = Io.Clock.real.now(io);
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buf: [64]u8 = undefined;
    return ht.transport().send(.{ .method = .GET, .url = server.url(&buf, host), .timeout_ms = 10_000 }, arena.allocator());
}

test "security: CWE-125 the transport takes a malformed certificate, or a signature longer than the key, as a TLS failure" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    // On std's TLS client each of these panics a safe build, and reads or
    // writes out of bounds in ReleaseFast.
    try testing.expectError(error.TlsFailure, sendThrough(.{ .chain = &.{"\x30\x82\xFF\xFF"} }, "127.0.0.1"));
    try testing.expectError(error.TlsFailure, sendThrough(.{ .chain = &.{der("rsa-leaf")}, .key_exchange = try rsaKeyExchange(arena.allocator(), 300) }, "localhost"));
}
