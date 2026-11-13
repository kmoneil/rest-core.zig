//! std's own TLS client handed a hostile server's first flight, canned:
//! the bugs behind test/security/CATALOG.md's CONN-11 and CONN-12 (t78),
//! which deps/zig-tls's copy of the client is patched against.
//! `std-tls-probe CASE` builds the flight CASE names, hands it to
//! `std.crypto.tls.Client.init` with no socket under it, and prints what
//! init returned. On Zig 0.17.1 init never returns for any case but
//! `control`: std reads past a certificate, or copies a signature past its
//! buffer, and a safe build panics. So std_tls_test.zig runs each case in
//! a process of its own, this one, built Debug whatever the suite's mode:
//! in ReleaseFast the same bytes go out of bounds without a word.
//!
//! In TLS 1.2 a server's ServerHello, Certificate and ServerKeyExchange
//! travel in the clear, so its first flight is bytes a program can write.
//! After ekur's src/runtime/tls_test.zig (its t382), which drives its own
//! copy of std's client over the same flights.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const tls = std.crypto.tls;
const Certificate = std.crypto.Certificate;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const Case = enum {
    /// What every other case changes, taken as far as std's last check: a
    /// certificate for localhost with an RSA key, which the root signed,
    /// and a ServerKeyExchange signed with as many bytes as the key has,
    /// the wrong ones. std returns `error.InvalidSignature`.
    control,
    /// CONN-11. A certificate that is a SEQUENCE claiming 65535 bytes, in
    /// four.
    short_certificate,
    /// One claiming 4 GiB: std adds the length to its place in a u32.
    huge_length,
    /// A subjectAltName whose GeneralNames claim 127 bytes of the 11 there,
    /// its one name not the host, so std reads on for another.
    subject_alt_name,
    /// A signature BIT STRING with no bytes, last in the certificate: std
    /// reads the byte after it for the count of unused bits.
    empty_signature,
    /// A chain whose second certificate holds an RSA key whose modulus
    /// claims 127 bytes of the 4 there, which std reads to check the first
    /// certificate's signature before anything checks the second's.
    rsa_key,
    /// CONN-12. The control's chain, trusted, and a ServerKeyExchange
    /// signed with 300 bytes, where the key's signature is 256: std copies
    /// the 300 into a buffer of 256 on its stack.
    long_signature,
};

/// std's panic, printed with where it came from, and then an exit with
/// `panic_exit` where std would abort: no core dump or crash report for
/// each run of the suite, and the same status on every platform.
pub const panic = std.debug.FullPanic(probePanic);

/// The exit status of a run std panicked in.
pub const panic_exit = 70;

fn probePanic(msg: []const u8, first_trace_addr: ?usize) noreturn {
    std.debug.print("panic: {s}\n", .{msg});
    std.debug.dumpCurrentStackTrace(.{ .first_address = first_trace_addr orelse @returnAddress() });
    std.process.exit(panic_exit);
}

pub fn main(init: std.process.Init) !u8 {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    const case = if (args.len == 2) std.meta.stringToEnum(Case, args[1]) else null;
    var buf: [256]u8 = undefined;
    var stdout = Io.File.stdout().writerStreaming(init.io, &buf);
    const out = &stdout.interface;
    const c = case orelse {
        try out.writeAll("usage: std-tls-probe CASE, one of");
        for (std.meta.fieldNames(Case)) |name| try out.print(" {s}", .{name});
        try out.writeAll("\n");
        try out.flush();
        return 2;
    };
    const root: Root = try .make(a);
    const flight = try serverFlight(a, try caseFlight(a, root, c));
    if (handshake(init.io, a, root, flight)) |_| {
        try out.writeAll("returned\n");
    } else |err| {
        try out.print("returned error.{t}\n", .{err});
    }
    try out.flush();
    return 0;
}

/// 2026-05-28, inside the validity of every certificate here (2026 to
/// 2126).
const now: Io.Timestamp = .fromNanoseconds(1_780_000_000 * std.time.ns_per_s);

/// std's client, for localhost, trusting `root` alone, against `flight`:
/// the server's bytes, and nothing after them.
fn handshake(io: Io, a: Allocator, root: Root, flight: []const u8) !void {
    var bundle: Certificate.Bundle = .empty;
    try bundle.bytes.appendSlice(a, root.der);
    try bundle.parseCert(a, 0, now.toSeconds());
    var lock: Io.RwLock = .init;
    // The client asks for a reader buffer of a whole record.
    const in_buf = try a.alloc(u8, tls.Client.min_buffer_len);
    @memcpy(in_buf[0..flight.len], flight);
    var in: Io.Reader = .fixed(in_buf);
    in.end = flight.len;
    // Where the ClientHello goes.
    const out_buf = try a.alloc(u8, tls.Client.min_buffer_len);
    var out: Io.Writer = .fixed(out_buf);
    const entropy: [tls.Client.Options.entropy_len]u8 = @splat(7);
    _ = try tls.Client.init(&in, &out, .{
        .host = .{ .explicit = "localhost" },
        .ca = .{ .bundle = .{ .gpa = a, .io = io, .lock = &lock, .bundle = &bundle } },
        .read_buffer = try a.alloc(u8, tls.Client.min_buffer_len),
        .write_buffer = try a.alloc(u8, tls.Client.min_buffer_len),
        .entropy = &entropy,
        .realtime_now = now,
    });
}

/// What the server sends after its ServerHello.
const Flight = struct {
    /// The server's certificate first.
    chain: []const []const u8,
    /// The ServerKeyExchange's body. By default one a client that took the
    /// chain refuses at its first byte (curve type 0, not named_curve).
    key_exchange: []const u8 = &.{ 0x00, 0x00, 0x17, 0x41 },
};

fn caseFlight(a: Allocator, root: Root, case: Case) !Flight {
    return switch (case) {
        .control => .{ .chain = try chain(a, &.{try root.rsaLeaf(a)}), .key_exchange = try keyExchange(a, 256) },
        .short_certificate => .{ .chain = &.{"\x30\x82\xFF\xFF"} },
        .huge_length => .{ .chain = &.{"\x30\x84\xFF\xFF\xFF\xFF"} },
        .subject_alt_name => .{ .chain = try chain(a, &.{try certOf(a, .{
            .key = try root.spki(a),
            .extensions = &.{try tlv(a, 0x30, &.{ oid_subject_alt_name, try tlv(a, 0x04, &.{"\x30\x7F\x82\x09otherhost"}) })},
        }, unsigned)}) },
        .empty_signature => .{ .chain = try chain(a, &.{try certOf(a, .{ .key = try root.spki(a) }, "")}) },
        .rsa_key => .{
            .chain = try chain(a, &.{
                // Says the holder of the next certificate's key signed it.
                try certOf(a, .{ .sig_alg = oid_rsa_sha256, .issuer = "hostile", .key = try root.spki(a) }, unsigned),
                try certOf(a, .{ .subject = "hostile", .key = try rsaSpki(a, "\x30\x06\x02\x7F\x01\x02\x03\x04") }, unsigned),
            }),
        },
        .long_signature => .{ .chain = try chain(a, &.{try root.rsaLeaf(a)}), .key_exchange = try keyExchange(a, 300) },
    };
}

/// `certs` copied into `a`: an array literal of values made at run time
/// lives in this frame, gone once `caseFlight` returns.
fn chain(a: Allocator, certs: []const []const u8) ![]const []const u8 {
    return a.dupe([]const u8, certs);
}

/// A ServerKeyExchange for x25519, signed rsa_pkcs1_sha256 with
/// `sig_len` bytes that are no signature.
fn keyExchange(a: Allocator, comptime sig_len: u16) ![]const u8 {
    const share: [32]u8 = @splat(9);
    const sig: [sig_len]u8 = @splat(0x5A);
    return std.mem.concat(a, u8, &.{ "\x03\x00\x1D\x20", &share, "\x04\x01", &.{ sig_len >> 8, sig_len & 0xFF }, &sig });
}

/// The root the client trusts, a P-256 key from a fixed seed.
const Root = struct {
    key: Ecdsa.KeyPair,
    der: []const u8,

    const name = "rest-core probe root";

    fn make(a: Allocator) !Root {
        const key: Ecdsa.KeyPair = try .generateDeterministic(@splat(0x42));
        var root: Root = .{ .key = key, .der = &.{} };
        root.der = try root.sign(a, .{ .subject = name, .key = try root.spki(a) });
        return root;
    }

    /// Its own public key as a SubjectPublicKeyInfo, which serves any
    /// certificate here whose key nothing uses.
    fn spki(r: Root, a: Allocator) ![]const u8 {
        const point = r.key.public_key.toUncompressedSec1();
        return tlv(a, 0x30, &.{ try tlv(a, 0x30, &.{ oid_ec_public_key, oid_prime256v1 }), try tlv(a, 0x03, &.{ "\x00", &point }) });
    }

    /// The certificate `t` describes, signed with the root's key.
    fn sign(r: Root, a: Allocator, t: Tbs) ![]const u8 {
        const tbs = try tbsOf(a, t);
        const sig = try r.key.sign(tbs, null);
        var der_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
        return wrap(a, tbs, t.sig_alg, try std.mem.concat(a, u8, &.{ "\x00", sig.toDer(&der_buf) }));
    }

    /// A certificate for localhost the root signed, whose key is a 2048-bit
    /// RSA modulus no one holds the private key of: no check here gets as
    /// far as needing it.
    fn rsaLeaf(r: Root, a: Allocator) ![]const u8 {
        var n: [256]u8 = @splat(0x5A);
        n[0] = 0xC5;
        n[255] = 0x5B;
        const modulus = try tlv(a, 0x02, &.{ "\x00", &n });
        const key = try tlv(a, 0x30, &.{ modulus, "\x02\x03\x01\x00\x01" });
        return r.sign(a, .{ .key = try rsaSpki(a, key) });
    }
};

/// The signature BIT STRING's contents in a certificate nothing signed:
/// std reads none before the bug.
const unsigned = "\x00\x01";

/// The parts of a TBSCertificate a case sets.
const Tbs = struct {
    /// The signature algorithm, an OID element, written in the
    /// TBSCertificate and after it.
    sig_alg: []const u8 = oid_ecdsa_sha256,
    issuer: []const u8 = Root.name,
    subject: []const u8 = "localhost",
    /// The SubjectPublicKeyInfo's DER.
    key: []const u8,
    /// Each a whole Extension's DER; none at all when null.
    extensions: ?[]const []const u8 = null,
};

/// A version 3 TBSCertificate, from 2026 to 2126.
fn tbsOf(a: Allocator, t: Tbs) ![]const u8 {
    const validity = try tlv(a, 0x30, &.{ try tlv(a, 0x17, &.{"260101000000Z"}), try tlv(a, 0x18, &.{"21260101000000Z"}) });
    const exts: []const u8 = if (t.extensions) |e| try tlv(a, 0xA3, &.{try tlv(a, 0x30, e)}) else "";
    return tlv(a, 0x30, &.{ "\xA0\x03\x02\x01\x02", "\x02\x01\x01", try algorithm(a, t.sig_alg), try nameOf(a, t.issuer), validity, try nameOf(a, t.subject), t.key, exts });
}

/// The certificate `t` describes, with `sig_bits` for its signature BIT
/// STRING's whole contents, its unused-bits byte first.
fn certOf(a: Allocator, t: Tbs, sig_bits: []const u8) ![]const u8 {
    return wrap(a, try tbsOf(a, t), t.sig_alg, sig_bits);
}

/// A Certificate: `tbs`, the signature algorithm `sig_alg`, and the
/// signature BIT STRING's contents.
fn wrap(a: Allocator, tbs: []const u8, sig_alg: []const u8, sig_bits: []const u8) ![]const u8 {
    return tlv(a, 0x30, &.{ tbs, try algorithm(a, sig_alg), try tlv(a, 0x03, &.{sig_bits}) });
}

fn algorithm(a: Allocator, oid: []const u8) ![]const u8 {
    return tlv(a, 0x30, &.{oid});
}

/// A SubjectPublicKeyInfo for an RSA key: `key`, an RSAPublicKey's DER.
fn rsaSpki(a: Allocator, key: []const u8) ![]const u8 {
    return tlv(a, 0x30, &.{ try tlv(a, 0x30, &.{ oid_rsa_encryption, "\x05\x00" }), try tlv(a, 0x03, &.{ "\x00", key }) });
}

/// A Name with one common name.
fn nameOf(a: Allocator, cn: []const u8) ![]const u8 {
    const atav = try tlv(a, 0x30, &.{ "\x06\x03\x55\x04\x03", try tlv(a, 0x0C, &.{cn}) });
    return tlv(a, 0x30, &.{try tlv(a, 0x31, &.{atav})});
}

const oid_ecdsa_sha256 = "\x06\x08\x2A\x86\x48\xCE\x3D\x04\x03\x02";
const oid_rsa_sha256 = "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0B";
const oid_rsa_encryption = "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01";
const oid_ec_public_key = "\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01";
const oid_prime256v1 = "\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07";
const oid_subject_alt_name = "\x06\x03\x55\x1D\x11";

/// A DER element: `tag`, its length (long form past 127), then `parts`.
fn tlv(a: Allocator, tag: u8, parts: []const []const u8) ![]const u8 {
    const body = try std.mem.concat(a, u8, parts);
    var head: [4]u8 = .{ tag, 0, 0, 0 };
    const head_len: usize = if (body.len < 0x80) blk: {
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
    return std.mem.concat(a, u8, &.{ head[0..head_len], body });
}

/// One handshake record: a TLS 1.2 ServerHello choosing
/// ECDHE_RSA_WITH_AES_128_GCM_SHA256, which std offers, the Certificate
/// message with `f.chain`, and the ServerKeyExchange.
fn serverFlight(a: Allocator, f: Flight) ![]const u8 {
    var body: std.ArrayList(u8) = .empty;
    // Version, random, no session id, the suite, no compression.
    const random: [32]u8 = @splat(0x11);
    try message(a, &body, 2, &([_]u8{ 0x03, 0x03 } ++ random ++ [_]u8{ 0x00, 0xC0, 0x2F, 0x00 }));
    var certs: std.ArrayList(u8) = .empty;
    var size: usize = 0;
    for (f.chain) |c| size += 3 + c.len;
    try putU24(a, &certs, size);
    for (f.chain) |c| {
        try putU24(a, &certs, c.len);
        try certs.appendSlice(a, c);
    }
    try message(a, &body, 11, certs.items);
    try message(a, &body, 12, f.key_exchange);
    const len: u16 = @intCast(body.items.len);
    return std.mem.concat(a, u8, &.{ "\x16\x03\x03", &.{ @intCast(len >> 8), @truncate(len) }, body.items });
}

fn message(a: Allocator, to: *std.ArrayList(u8), kind: u8, payload: []const u8) !void {
    try to.append(a, kind);
    try putU24(a, to, payload.len);
    try to.appendSlice(a, payload);
}

fn putU24(a: Allocator, to: *std.ArrayList(u8), n: usize) !void {
    try to.appendSlice(a, &.{ @intCast(n >> 16 & 0xFF), @intCast(n >> 8 & 0xFF), @intCast(n & 0xFF) });
}
