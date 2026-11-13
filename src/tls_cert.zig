// From ekur src/runtime/tls_cert.zig at fff1ad3 (its t382); what it says of ekur said of rest-core.
//! What std's certificate parser takes for granted, checked before it
//! runs (ekur t382). Zig 0.17.1's std/crypto/Certificate.zig reads DER
//! with `der.Element.parse`, which never holds a length to the bytes it
//! was given, and its TLS client runs `parse` on every certificate a
//! server sends, before anything about it is trusted: four bytes that
//! claim 64 KB crash the process in a safe build and read past the buffer
//! in a fast one. std reads two slices that `parse` leaves again later,
//! the same way: the subjectAltName when the host is checked, and an RSA
//! key when a signature is.
//!
//! `parse` walks the certificate first, every element std's `parse` will
//! read, each held to the element around it; then lets std parse it; then
//! checks those two slices. A certificate that fails is refused as std
//! refuses a length it cannot read, `error.CertificateFieldHasInvalidLength`.
//! tools/zig_tls.zig puts the call in place of std's `subject_cert.parse()`
//! in rest-core's copy of the TLS client, beside tls_chain.zig's CA check.

const std = @import("std");

const Certificate = std.crypto.Certificate;

/// `cert` parsed by std, once nothing std will read in it, then or
/// later, runs past the bytes it is in.
pub fn parse(cert: Certificate) Certificate.ParseError!Certificate.Parsed {
    const bad = error.CertificateFieldHasInvalidLength;
    if (cert.index >= cert.buffer.len) return bad;
    shape(cert.buffer[cert.index..]) catch return bad;
    const p = try cert.parse();
    if (p.subjectAltName().len > 0) generalNames(p.subjectAltName()) catch return bad;
    switch (p.pub_key_algo) {
        .rsaEncryption, .rsassa_pss => rsaKey(p.pubKey()) catch return bad,
        else => {},
    }
    return p;
}

pub const Malformed = error{Malformed};

pub const tag_boolean = 0x01;
pub const tag_integer = 0x02;
pub const tag_bit_string = 0x03;
pub const tag_octet_string = 0x04;
pub const tag_oid = 0x06;
pub const tag_sequence = 0x30;
/// TBSCertificate's `version [0] EXPLICIT`.
pub const tag_version = 0xA0;
/// TBSCertificate's `extensions [3] EXPLICIT`.
pub const tag_extensions = 0xA3;

pub const Tlv = struct { tag: u8, body: []const u8, rest: []const u8 };

/// The DER element at the front of `bytes`: its tag, its contents and
/// what follows it. Every length is held to `bytes`, so one that runs
/// past it is `Malformed`, never a read past the end. Where it reads a
/// length std reads the same one: one byte, or 0x81 to 0x84 and that
/// many more.
pub fn tlv(bytes: []const u8) Malformed!Tlv {
    if (bytes.len < 2) return error.Malformed;
    const tag = bytes[0];
    // A tag number past 30 takes more bytes; a certificate has none.
    if (tag & 0x1F == 0x1F) return error.Malformed;
    var len: usize = bytes[1];
    var at: usize = 2;
    if (len & 0x80 != 0) {
        const n = len & 0x7F;
        // 0 is BER's indefinite length; more than 4 bytes of length is
        // more than a TLS message holds.
        if (n == 0 or n > 4 or bytes.len - at < n) return error.Malformed;
        len = 0;
        for (bytes[at..][0..n]) |byte| len = (len << 8) | byte;
        at += n;
    }
    if (bytes.len - at < len) return error.Malformed;
    return .{ .tag = tag, .body = bytes[at..][0..len], .rest = bytes[at + len ..] };
}

/// The elements of a constructed element's contents, one after another.
const Elements = struct {
    rest: []const u8,

    fn of(body: []const u8) Elements {
        return .{ .rest = body };
    }

    fn next(e: *Elements) Malformed!Tlv {
        const t = try tlv(e.rest);
        e.rest = t.rest;
        return t;
    }

    /// The next, which must be a `tag`.
    fn expect(e: *Elements, tag: u8) Malformed!Tlv {
        const t = try e.next();
        if (t.tag != tag) return error.Malformed;
        return t;
    }

    /// The rest read to the end, every one whole: how many there were.
    fn count(e: *Elements) Malformed!usize {
        var n: usize = 0;
        while (e.rest.len > 0) : (n += 1) _ = try e.next();
        return n;
    }

    fn end(e: Elements) Malformed!void {
        if (e.rest.len != 0) return error.Malformed;
    }
};

/// `body` holds exactly `n` elements.
fn exactly(n: usize, body: []const u8) Malformed!void {
    var e: Elements = .of(body);
    if (try e.count() != n) return error.Malformed;
}

/// `Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
/// signatureValue }`.
fn shape(bytes: []const u8) Malformed!void {
    const certificate = try tlv(bytes);
    if (certificate.tag != tag_sequence) return error.Malformed;
    var c: Elements = .of(certificate.body);
    const tbs = try c.expect(tag_sequence);
    try algorithm((try c.expect(tag_sequence)).body);
    try bitString((try c.expect(tag_bit_string)).body);
    try c.end();
    try toBeSigned(tbs.body);
}

/// TBSCertificate: version, serial, signature, issuer, validity,
/// subject, subjectPublicKeyInfo, then issuerUniqueID, subjectUniqueID
/// and extensions, each optional.
fn toBeSigned(body: []const u8) Malformed!void {
    var t: Elements = .of(body);
    const first = try t.next();
    if (first.tag == tag_version) _ = try t.next(); // then the serial
    _ = try t.next(); // signature: std reads past it, not into it
    _ = try t.next(); // issuer: std keeps it whole
    try exactly(2, (try t.next()).body); // validity: notBefore, notAfter
    try name((try t.next()).body); // subject: std reads each attribute
    try publicKeyInfo((try t.expect(tag_sequence)).body);
    // std takes the element after the key for the extensions when its
    // tag number is 3, whatever its class.
    if (t.rest.len > 0 and t.rest[0] & 0x1F == 3) try extensions(try t.next());
    _ = try t.count();
}

/// A Name: RDNs, each attributes, each a type and a value.
fn name(body: []const u8) Malformed!void {
    var rdns: Elements = .of(body);
    while (rdns.rest.len > 0) {
        var attributes: Elements = .of((try rdns.next()).body);
        while (attributes.rest.len > 0) try exactly(2, (try attributes.next()).body);
    }
}

/// `SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT
/// STRING }`.
fn publicKeyInfo(body: []const u8) Malformed!void {
    var k: Elements = .of(body);
    try algorithm((try k.expect(tag_sequence)).body);
    try bitString((try k.expect(tag_bit_string)).body);
    try k.end();
}

/// AlgorithmIdentifier: an OID, and parameters or not.
fn algorithm(body: []const u8) Malformed!void {
    var a: Elements = .of(body);
    _ = try a.expect(tag_oid);
    if (try a.count() > 1) return error.Malformed;
}

/// A BIT STRING has at least its unused-bits byte, which std reads.
fn bitString(body: []const u8) Malformed!void {
    if (body.len == 0) return error.Malformed;
}

/// `[3] { SEQUENCE OF Extension }`, each an OID, critical or not, and a
/// value: std reads the second element, and the third when the second
/// is the BOOLEAN.
fn extensions(outer: Tlv) Malformed!void {
    if (outer.tag != tag_extensions) return error.Malformed;
    var o: Elements = .of(outer.body);
    const list = try o.expect(tag_sequence);
    try o.end();
    var exts: Elements = .of(list.body);
    while (exts.rest.len > 0) {
        var ext: Elements = .of((try exts.expect(tag_sequence)).body);
        const n = try ext.count();
        if (n < 2 or n > 3) return error.Malformed;
    }
}

/// subjectAltName's contents, `GeneralNames ::= SEQUENCE OF
/// GeneralName`, which std reads name by name to check the host.
fn generalNames(san: []const u8) Malformed!void {
    const names = try tlv(san);
    if (names.tag != tag_sequence or names.rest.len != 0) return error.Malformed;
    var each: Elements = .of(names.body);
    _ = try each.count();
}

/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER
/// }`, which std reads to check a signature with it.
fn rsaKey(key: []const u8) Malformed!void {
    const seq = try tlv(key);
    if (seq.tag != tag_sequence or seq.rest.len != 0) return error.Malformed;
    var parts: Elements = .of(seq.body);
    _ = try parts.expect(tag_integer);
    _ = try parts.expect(tag_integer);
    try parts.end();
}

const testing = std.testing;

fn fixture(comptime name_: []const u8) []const u8 {
    return @embedFile("testdata/tls_chain/" ++ name_ ++ ".der");
}

test "tls_cert: every certificate OpenSSL made is read whole" {
    inline for (.{ "root", "attacker", "forged", "bare", "bare-leaf", "plain", "plain-leaf", "no-sign", "no-sign-leaf", "inter0", "good", "deep", "deep-leaf", "rollover", "rollover-leaf", "open", "open-sub", "open-leaf", "rsa-leaf" }) |n| {
        const p = try parse(.{ .buffer = fixture(n), .index = 0 });
        try testing.expectEqual(Certificate.Version.v3, p.version);
    }
}

test "tls_cert: a certificate cut short anywhere is refused, never a crash" {
    // Every length but the whole: std's own parse would read past most.
    for ([_][]const u8{ fixture("good"), fixture("rsa-leaf") }) |whole| {
        for (0..whole.len) |n| try testing.expectError(error.CertificateFieldHasInvalidLength, parse(.{ .buffer = whole[0..n], .index = 0 }));
    }
}

test "tls_cert: the elements std reads must be there and fit" {
    const ok = [_][]const u8{
        &.{ 0x06, 0x01, 0x2A }, // an OID alone
        &.{ 0x06, 0x01, 0x2A, 0x05, 0x00 }, // and parameters
    };
    for (ok) |b| try algorithm(b);
    const bad = [_][]const u8{
        "", // no OID
        &.{ 0x05, 0x00 }, // not an OID
        &.{ 0x06, 0x01, 0x2A, 0x05, 0x00, 0x05, 0x00 }, // more than parameters
        &.{ 0x06, 0x05, 0x2A }, // an OID past its bytes
    };
    for (bad) |b| try testing.expectError(error.Malformed, algorithm(b));
    try testing.expectError(error.Malformed, bitString(""));
    try exactly(2, &.{ 0x17, 0x00, 0x18, 0x00 });
    try testing.expectError(error.Malformed, exactly(2, &.{ 0x17, 0x00 }));
    // An attribute with a type and no value: std reads the value anyway.
    try testing.expectError(error.Malformed, name(&.{ 0x31, 0x07, 0x30, 0x05, 0x06, 0x03, 0x55, 0x04, 0x03 }));
    try generalNames(&.{ 0x30, 0x04, 0x82, 0x02, 'a', 'b' });
    try testing.expectError(error.Malformed, generalNames(&.{ 0x30, 0x04, 0x82, 0x05, 'a', 'b' }));
    try testing.expectError(error.Malformed, generalNames(&.{ 0x04, 0x04, 0x82, 0x02, 'a', 'b' }));
    try rsaKey(&.{ 0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x03 });
    try testing.expectError(error.Malformed, rsaKey(&.{ 0x30, 0x03, 0x02, 0x01, 0x05 }));
    try testing.expectError(error.Malformed, rsaKey(&.{ 0x30, 0x06, 0x02, 0x7F, 0x05, 0x02, 0x01, 0x03 }));
}

test "tls_cert: an extension std would read past is refused" {
    // [3] { SEQUENCE { SEQUENCE { OID } } }: a known OID with no value,
    // which std reads anyway, from whatever follows.
    const no_value = [_]u8{ 0xA3, 0x09, 0x30, 0x07, 0x30, 0x05, 0x06, 0x03, 0x55, 0x1D, 0x11 };
    try testing.expectError(error.Malformed, extensions(try tlv(&no_value)));
    // A constructed universal BIT STRING where [3] goes, holding a list
    // that would read: std would take it for the extensions, which no
    // certificate may hold there.
    const not_explicit = [_]u8{ 0x23, 0x0C, 0x30, 0x0A, 0x30, 0x08, 0x06, 0x03, 0x55, 0x1D, 0x11, 0x04, 0x01, 0x00 };
    try testing.expectError(error.Malformed, extensions(try tlv(&not_explicit)));
    const one = [_]u8{ 0xA3, 0x0C, 0x30, 0x0A, 0x30, 0x08, 0x06, 0x03, 0x55, 0x1D, 0x11, 0x04, 0x01, 0x00 };
    try extensions(try tlv(&one));
}
