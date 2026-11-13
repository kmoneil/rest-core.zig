// From ekur src/runtime/tls_chain.zig at ba2c6c7 (its t380 and t383); what it says of ekur said of rest-core.
//! What std's TLS client leaves out when it walks a server's certificate
//! chain. Zig 0.17.1's client checks each link by signature and names
//! alone (Codeberg ziglang/zig#35877 and #37353; the fix for the first,
//! PR #37354, is not merged), and reads no extension but the
//! subjectAltName.
//!
//! tools/zig_tls.zig puts three calls into rest-core's copy of that client
//! (deps/zig-tls): `Path.leaf` on the server's certificate, `Path.issued`
//! after std's own check of each link, and `Path.anchored` in place of
//! std's look in the root bundle, so that the root it finds is read too.
//! As RFC 5280 asks:
//!
//! - Each certificate that signed another is a version 3 CA whose
//!   keyUsage, if it has one, allows keyCertSign, and whose
//!   pathLenConstraint, if it has one, allows the intermediates under it,
//!   self-issued ones not counted (4.2.1.3, 4.2.1.9, 6.1.4 (k) to (n);
//!   ekur t380).
//! - No certificate in the path, the root included, marks critical an
//!   extension rest-core does not process (4.2): it says "refuse me unless you
//!   honour this", and rest-core cannot (ekur t383).
//! - Each one that has an extended key usage lists serverAuth (4.2.1.12):
//!   a certificate for client logins, mail or code signing is no
//!   server's, and a CA limited to those signs none. anyExtendedKeyUsage
//!   alone is not enough, as OpenSSL holds for the server's certificate:
//!   the CA/Browser Forum's rules keep it out of TLS certificates, and no
//!   public intermediate has it (ekur t383).
//! - A CA's or the root's nameConstraints hold for every certificate
//!   under it (4.2.1.10, 6.1.4 (g)): its DNS names and IP addresses, and
//!   the server's common name when it has no subjectAltName, since std's
//!   host check falls back to it. A constraint of another form, or with a
//!   minimum or maximum, is refused rather than passed over (ekur t383).
//!
//! A root is a signer by being in the bundle, so it need not say cA or
//! keyCertSign: an app's `.ca` may hold a server's own self-signed
//! certificate. What a root says about its own limits (pathLenConstraint,
//! nameConstraints, extended key usage, a critical extension) holds: Go's
//! verifier holds a root to its pathLenConstraint and critical
//! extensions as it does an intermediate.
//!
//! A module of its own, imported by name by deps/zig-tls/Client.zig;
//! rest-core's own code does not import it.

const std = @import("std");

const Certificate = std.crypto.Certificate;
const Parsed = Certificate.Parsed;
const Bundle = Certificate.Bundle;

pub const Error = error{
    /// A certificate in the chain signed the next one down without being
    /// a CA: no basicConstraints, cA not set, not version 3, or the
    /// extensions do not read.
    CertificateIssuerNotCa,
    /// A CA whose keyUsage leaves out keyCertSign signed a certificate.
    CertificateIssuerKeyUsage,
    /// More intermediates under a CA, or under the root, than its
    /// pathLenConstraint allows; or more than `max_below` in all.
    CertificatePathLenExceeded,
    /// A certificate in the chain, or its root, marks critical an
    /// extension rest-core does not process (RFC 5280 4.2).
    CertificateUnhandledCriticalExtension,
    /// A certificate in the chain, or its root, whose extended key usage
    /// leaves out serverAuth.
    CertificateExtKeyUsage,
    /// A name in a certificate outside the nameConstraints of a CA above
    /// it, or constraints rest-core does not check: a form other than DNS
    /// names and IP addresses, a minimum or a maximum, or more than
    /// `max_comparisons` to check.
    CertificateNameConstraints,
    /// The server's certificate's or the root's extensions do not read:
    /// cut short, a value not of its kind, or one extension twice.
    CertificateExtensionsInvalid,
};

/// The most certificates a chain may have under any one signer whose
/// names a nameConstraints is checked against: the server's, and each
/// intermediate that is not self-issued. Real chains have one to three.
pub const max_below = 8;

/// The most subtrees one chain may have its names compared with. A CA
/// may list many, and a certificate many names, both a hostile server's
/// to choose before any root has vouched for them (Go's verifier caps
/// its comparisons for the same reason, VerifyOptions.MaxConstraintComparisions).
pub const max_comparisons = 1 << 16;

/// The chain read so far, from the server's certificate up.
pub const Path = struct {
    /// Certificates between the server's and the next signer that are
    /// not self-issued: what that signer's pathLenConstraint limits.
    intermediates: u32 = 0,
    /// Links checked so far: the first is the server's certificate's.
    links: u32 = 0,
    /// The names of each certificate under the next signer that its
    /// nameConstraints would hold: the server's first, then each
    /// intermediate not self-issued (RFC 5280 6.1.4 (b)).
    below: [max_below]Names = undefined,
    below_len: u8 = 0,
    /// Subtrees compared so far, held to `max_comparisons`.
    comparisons: u32 = 0,

    /// The server's certificate, before any link is checked: nothing
    /// critical that rest-core does not process, an extended key usage, if
    /// any, that allows a TLS server, and its names kept for the
    /// constraints of the CAs above it.
    pub fn leaf(p: *Path, cert: Parsed) Error!void {
        const exts = readExtensions(cert) catch return error.CertificateExtensionsInvalid;
        try exts.usable();
        const san = cert.subjectAltName();
        p.below[0] = .{ .san = san, .cn = if (san.len == 0) cert.commonName() else "" };
        p.below_len = 1;
    }

    /// `issuer` signed `subject`, the certificate before it in the chain:
    /// std has checked the signature and that the names match. `issuer`
    /// must be allowed to sign it.
    pub fn issued(p: *Path, subject: Parsed, issuer: Parsed) Error!void {
        try p.under(subject);
        if (issuer.version != .v3) return error.CertificateIssuerNotCa;
        const exts = readExtensions(issuer) catch return error.CertificateIssuerNotCa;
        const basic = exts.basicConstraints() catch return error.CertificateIssuerNotCa;
        if (!basic.ca) return error.CertificateIssuerNotCa;
        if (exts.key_usage) |v| if (!(keyCertSign(v) catch return error.CertificateIssuerNotCa)) return error.CertificateIssuerKeyUsage;
        try p.limits(exts, basic);
    }

    /// What std's client asks of the bundle, `bundle.verify(subject,
    /// now_sec)`: whether a root in it signed `subject`
    /// (`CertificateIssuerNotFound` when none did, and the walk goes on
    /// up the chain). When one did, that root's own limits must allow
    /// the chain under it.
    pub fn anchored(p: *Path, bundle: *const Bundle, subject: Parsed, now_sec: i64) (Bundle.VerifyError || Error)!void {
        try bundle.verify(subject, now_sec);
        // The root `verify` found, by the same name under the same lock.
        // Neither of the two errors can be: every certificate in a bundle
        // was parsed when it went in.
        const index = bundle.find(subject.issuer()) orelse return error.CertificateExtensionsInvalid;
        const cert: Certificate = .{ .buffer = bundle.bytes.items, .index = index };
        const root = cert.parse() catch return error.CertificateExtensionsInvalid;
        try p.under(subject);
        const exts = readExtensions(root) catch return error.CertificateExtensionsInvalid;
        const basic = exts.basicConstraints() catch return error.CertificateExtensionsInvalid;
        try p.limits(exts, basic);
    }

    /// `cert` was signed by the signer being checked: counted, and its
    /// names kept, unless it is the server's (which `leaf` keeps) or
    /// self-issued (RFC 5280 6.1.4 (l), 6.1.3 (b)).
    fn under(p: *Path, cert: Parsed) Error!void {
        const first = p.links == 0;
        p.links += 1;
        if (first or selfIssued(cert)) return;
        p.intermediates +|= 1;
        if (p.below_len == max_below) return error.CertificatePathLenExceeded;
        p.below[p.below_len] = .{ .san = cert.subjectAltName() };
        p.below_len += 1;
    }

    /// What a signer, a CA or the root, says about its own limits: how
    /// many intermediates it allows under it, its extended key usage and
    /// critical extensions, and the names it may sign for.
    fn limits(p: *Path, exts: Extensions, basic: Basic) Error!void {
        if (basic.path_len) |most| if (p.intermediates > most) return error.CertificatePathLenExceeded;
        try exts.usable();
        if (exts.name_constraints) |v| try p.constrain(v);
    }

    /// `value`, a signer's nameConstraints, held to every certificate
    /// under it.
    fn constrain(p: *Path, value: []const u8) Error!void {
        const subtrees = readNameConstraints(value) catch return error.CertificateNameConstraints;
        for (p.below[0..p.below_len]) |names| try p.constrainNames(subtrees, names);
    }

    fn constrainNames(p: *Path, s: Subtrees, names: Names) Error!void {
        const bad = error.CertificateNameConstraints;
        if (names.san.len == 0) {
            if (names.cn.len > 0) try p.check(s, .{ .form = .dns, .name = names.cn });
            return;
        }
        const seq = tlv(names.san) catch return bad;
        if (seq.tag != tag_sequence) return bad;
        var rest = seq.body;
        while (rest.len > 0) {
            const name = tlv(rest) catch return bad;
            rest = name.rest;
            const form = formOf(name.tag) orelse continue; // a form no constraint here can hold
            try p.check(s, .{ .form = form, .name = name.body });
        }
    }

    /// `name` inside one of the permitted subtrees of its form, when
    /// there are any, and outside every excluded one.
    fn check(p: *Path, s: Subtrees, name: GeneralName) Error!void {
        if (s.permits.contains(name.form) and !try p.anyMatch(s.permitted, name, .within)) return error.CertificateNameConstraints;
        if (try p.anyMatch(s.excluded, name, .overlaps)) return error.CertificateNameConstraints;
    }

    fn anyMatch(p: *Path, list: []const u8, name: GeneralName, how: Match) Error!bool {
        const bad = error.CertificateNameConstraints;
        var rest = list;
        while (rest.len > 0) {
            p.comparisons += 1;
            if (p.comparisons > max_comparisons) return bad;
            const base = nextSubtree(&rest) catch return bad;
            if (base.form != name.form) continue;
            if (matches(name, base, how) catch return bad) return true;
        }
        return false;
    }
};

/// The names a certificate under a constrained signer answers to.
const Names = struct {
    /// Its subjectAltName's GeneralNames, as std reads them for the host
    /// check: empty when it has none.
    san: []const u8 = "",
    /// The server's common name when it has no subjectAltName: std's
    /// host check takes it as a DNS name then.
    cn: []const u8 = "",
};

/// Issued by a CA to itself: the same name as issuer and subject, as a
/// new key for an old name is (RFC 5280 6.1, "self-issued").
fn selfIssued(cert: Parsed) bool {
    return std.mem.eql(u8, cert.issuer(), cert.subject());
}

const der = @import("tls_cert.zig");
const Malformed = der.Malformed;
const tlv = der.tlv;
const tag_boolean = der.tag_boolean;
const tag_integer = der.tag_integer;
const tag_bit_string = der.tag_bit_string;
const tag_octet_string = der.tag_octet_string;
const tag_oid = der.tag_oid;
const tag_sequence = der.tag_sequence;
const tag_extensions = der.tag_extensions;
const tag_version = der.tag_version;

/// A server's certificate, parsed by std once nothing std will read in
/// it runs past its bytes (tls_cert.zig, ekur t382): the client calls
/// this in place of std's `parse`.
pub const parse = der.parse;

// The extensions

/// What a certificate's extensions say that rest-core reads, each extension's
/// value (its OCTET STRING's contents) when it has one.
const Extensions = struct {
    basic: ?[]const u8 = null,
    key_usage: ?[]const u8 = null,
    ext_key_usage: ?[]const u8 = null,
    name_constraints: ?[]const u8 = null,
    /// It has a critical extension not on `known`.
    unhandled_critical: bool = false,

    /// Where the value of an extension of `kind` goes: null for one
    /// passed over.
    fn slot(e: *Extensions, kind: Kind) ?*?[]const u8 {
        return switch (kind) {
            .basic_constraints => &e.basic,
            .key_usage => &e.key_usage,
            .ext_key_usage => &e.ext_key_usage,
            .name_constraints => &e.name_constraints,
            .passed_over => null,
        };
    }

    /// Its basicConstraints; with none, not a CA.
    fn basicConstraints(e: Extensions) Malformed!Basic {
        return if (e.basic) |v| basicConstraintsOf(v) else .{ .ca = false, .path_len = null };
    }

    /// Nothing critical that rest-core does not process, and an extended key
    /// usage, if any, that allows a TLS server.
    fn usable(e: Extensions) Error!void {
        if (e.unhandled_critical) return error.CertificateUnhandledCriticalExtension;
        if (e.ext_key_usage) |v| if (!(serverAuth(v) catch false)) return error.CertificateExtKeyUsage;
    }
};

const Kind = enum { basic_constraints, key_usage, ext_key_usage, name_constraints, passed_over };

/// The extensions rest-core processes, and those it may pass over even when
/// one is marked critical. Any other critical one refuses the chain.
const known = [_]struct { oid: []const u8, kind: Kind }{
    .{ .oid = &.{ 0x55, 0x1D, 0x13 }, .kind = .basic_constraints }, // 2.5.29.19
    .{ .oid = &.{ 0x55, 0x1D, 0x0F }, .kind = .key_usage }, // 2.5.29.15
    .{ .oid = &.{ 0x55, 0x1D, 0x25 }, .kind = .ext_key_usage }, // 2.5.29.37
    .{ .oid = &.{ 0x55, 0x1D, 0x1E }, .kind = .name_constraints }, // 2.5.29.30
    // subjectAltName (2.5.29.17): std's host check reads it, and the
    // nameConstraints check here.
    .{ .oid = &.{ 0x55, 0x1D, 0x11 }, .kind = .passed_over },
    // subjectKeyIdentifier, authorityKeyIdentifier (2.5.29.14, 2.5.29.35):
    // hints for finding an issuer, which std finds by name.
    .{ .oid = &.{ 0x55, 0x1D, 0x0E }, .kind = .passed_over },
    .{ .oid = &.{ 0x55, 0x1D, 0x23 }, .kind = .passed_over },
    // certificatePolicies (2.5.29.32): rest-core asks for no policy, as RFC
    // 5280 6.1.1 does with any-policy and no explicit policy required.
    .{ .oid = &.{ 0x55, 0x1D, 0x20 }, .kind = .passed_over },
    // cRLDistributionPoints (2.5.29.31) and authorityInfoAccess
    // (1.3.6.1.5.5.7.1.1): where to ask about revocation, which rest-core
    // does not.
    .{ .oid = &.{ 0x55, 0x1D, 0x1F }, .kind = .passed_over },
    .{ .oid = &.{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01 }, .kind = .passed_over },
    // Certificate Transparency's signed timestamps (1.3.6.1.4.1.11129.2.4.2).
    .{ .oid = &.{ 0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x04, 0x02 }, .kind = .passed_over },
};

fn knownIndex(oid: []const u8) ?usize {
    for (known, 0..) |k, i| if (std.mem.eql(u8, k.oid, oid)) return i;
    return null;
}

/// `cert`'s extensions, each on `known` at most once (RFC 5280 4.2: a
/// certificate has no extension twice, and a second could say what the
/// first does not). None is no extensions; extensions in a certificate
/// that is not version 3 is `Malformed`.
fn readExtensions(cert: Parsed) Malformed!Extensions {
    var out: Extensions = .{};
    var list = (try extensionList(cert)) orelse return out;
    var seen: std.bit_set.IntegerBitSet(known.len) = .empty;
    while (list.len > 0) {
        const ext = try nextExtension(&list);
        const i = knownIndex(ext.oid) orelse {
            out.unhandled_critical = out.unhandled_critical or ext.critical;
            continue;
        };
        if (seen.isSet(i)) return error.Malformed;
        seen.set(i);
        if (out.slot(known[i].kind)) |s| s.* = ext.value;
    }
    return out;
}

const Extension = struct { oid: []const u8, critical: bool, value: []const u8 };

/// The extension at the front of `exts`, which then starts after it:
/// `Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN
/// DEFAULT FALSE, extnValue OCTET STRING }`.
fn nextExtension(exts: *[]const u8) Malformed!Extension {
    const ext = try tlv(exts.*);
    exts.* = ext.rest;
    if (ext.tag != tag_sequence) return error.Malformed;
    const oid = try tlv(ext.body);
    if (oid.tag != tag_oid) return error.Malformed;
    var value = try tlv(oid.rest);
    var critical = false;
    if (value.tag == tag_boolean) {
        if (value.body.len != 1) return error.Malformed;
        critical = value.body[0] != 0;
        value = try tlv(value.rest);
    }
    if (value.tag != tag_octet_string or value.rest.len != 0) return error.Malformed;
    return .{ .oid = oid.body, .critical = critical, .value = value.body };
}

/// The contents of `cert`'s extensions SEQUENCE, or null when it has
/// none.
fn extensionList(cert: Parsed) Malformed!?[]const u8 {
    var rest = try afterKey(cert);
    // issuerUniqueID [1] and subjectUniqueID [2], each optional, then
    // extensions [3].
    while (rest.len > 0) {
        const next = try tlv(rest);
        rest = next.rest;
        if (next.tag == tag_extensions) return try extensionsOf(cert, next.body);
    }
    return null;
}

/// What follows the subjectPublicKeyInfo in `cert`'s TBSCertificate.
fn afterKey(cert: Parsed) Malformed![]const u8 {
    const whole = cert.certificate.buffer;
    if (cert.certificate.index >= whole.len) return error.Malformed;
    const certificate = try tlv(whole[cert.certificate.index..]);
    const tbs = try tlv(certificate.body);
    if (tbs.tag != tag_sequence) return error.Malformed;
    var field = try tlv(tbs.body);
    if (field.tag == tag_version) field = try tlv(field.rest); // now the serial number
    var rest = field.rest;
    // signature, issuer, validity, subject, subjectPublicKeyInfo
    for (0..5) |_| rest = (try tlv(rest)).rest;
    return rest;
}

/// The list inside `extensions [3] EXPLICIT Extensions`, which only a
/// version 3 certificate may have.
fn extensionsOf(cert: Parsed, field: []const u8) Malformed![]const u8 {
    if (cert.version != .v3) return error.Malformed;
    const list = try tlv(field);
    if (list.tag != tag_sequence or list.rest.len != 0) return error.Malformed;
    return list.body;
}

const Basic = struct { ca: bool, path_len: ?u32 };

/// `BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE,
/// pathLenConstraint INTEGER (0..MAX) OPTIONAL }`, from the extension's
/// OCTET STRING.
fn basicConstraintsOf(value: []const u8) Malformed!Basic {
    const seq = try tlv(value);
    if (seq.tag != tag_sequence or seq.rest.len != 0) return error.Malformed;
    var out: Basic = .{ .ca = false, .path_len = null };
    if (seq.body.len == 0) return out;
    var field = try tlv(seq.body);
    if (field.tag == tag_boolean) {
        if (field.body.len != 1) return error.Malformed;
        out.ca = field.body[0] != 0;
        if (field.rest.len == 0) return out;
        field = try tlv(field.rest);
    }
    if (field.tag != tag_integer or field.rest.len != 0) return error.Malformed;
    out.path_len = try nonNegative(field.body);
    return out;
}

/// A DER INTEGER's contents as a count, a huge one as the most a u32
/// holds (no chain is that long); a negative one is `Malformed`.
fn nonNegative(int: []const u8) Malformed!u32 {
    if (int.len == 0 or int[0] & 0x80 != 0) return error.Malformed;
    var n: u64 = 0;
    for (int) |byte| {
        n = (n << 8) | byte;
        if (n > std.math.maxInt(u32)) return std.math.maxInt(u32);
    }
    return @intCast(n);
}

/// Whether `KeyUsage ::= BIT STRING` (from the extension's OCTET STRING)
/// sets keyCertSign, bit 5: 0x04 of the first byte of bits.
fn keyCertSign(value: []const u8) Malformed!bool {
    const bits = try tlv(value);
    if (bits.tag != tag_bit_string or bits.rest.len != 0) return error.Malformed;
    if (bits.body.len == 0) return error.Malformed;
    const unused = bits.body[0];
    if (unused > 7) return error.Malformed;
    if (bits.body.len < 2) return false;
    // A bit in the last byte's unused tail is not set, whatever it holds.
    const mask: u8 = if (bits.body.len == 2) @as(u8, 0xFF) << @intCast(unused) else 0xFF;
    return bits.body[1] & mask & 0x04 != 0;
}

const oid_server_auth = [_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 }; // 1.3.6.1.5.5.7.3.1

/// Whether `ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF
/// KeyPurposeId` (from the extension's OCTET STRING) lists serverAuth.
fn serverAuth(value: []const u8) Malformed!bool {
    const seq = try tlv(value);
    if (seq.tag != tag_sequence or seq.rest.len != 0 or seq.body.len == 0) return error.Malformed;
    var rest = seq.body;
    var found = false;
    while (rest.len > 0) {
        const purpose = try tlv(rest);
        rest = purpose.rest;
        if (purpose.tag != tag_oid) return error.Malformed;
        if (std.mem.eql(u8, purpose.body, &oid_server_auth)) found = true;
    }
    return found;
}

// Name constraints

const tag_permitted = 0xA0;
const tag_excluded = 0xA1;
const tag_minimum = 0x80;
const tag_dns_name = 0x82;
const tag_ip_address = 0x87;

/// The two forms of GeneralName rest-core holds to a constraint.
const Form = enum { dns, ip };

fn formOf(tag: u8) ?Form {
    return switch (tag) {
        tag_dns_name => .dns,
        tag_ip_address => .ip,
        else => null,
    };
}

const GeneralName = struct { form: Form, name: []const u8 };

/// A signer's nameConstraints, read: the contents of each list of
/// GeneralSubtrees (empty when it has none), each subtree in them one
/// that `nextSubtree` reads.
const Subtrees = struct {
    permitted: []const u8 = "",
    excluded: []const u8 = "",
    /// The forms `permitted` has a subtree of: a form it has none of, it
    /// does not limit.
    permits: std.EnumSet(Form) = .empty,
};

/// `NameConstraints ::= SEQUENCE { permittedSubtrees [0] GeneralSubtrees
/// OPTIONAL, excludedSubtrees [1] GeneralSubtrees OPTIONAL }`, one of the
/// two at least, `GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF
/// GeneralSubtree`.
fn readNameConstraints(value: []const u8) Malformed!Subtrees {
    const seq = try tlv(value);
    if (seq.tag != tag_sequence or seq.rest.len != 0 or seq.body.len == 0) return error.Malformed;
    var out: Subtrees = .{};
    var field = try tlv(seq.body);
    if (field.tag == tag_permitted) {
        out.permitted = field.body;
        out.permits = try subtreeForms(field.body);
        if (field.rest.len == 0) return out;
        field = try tlv(field.rest);
    }
    if (field.tag != tag_excluded or field.rest.len != 0) return error.Malformed;
    out.excluded = field.body;
    _ = try subtreeForms(field.body);
    return out;
}

/// The forms of the subtrees in `list`, one at least, each read whole.
fn subtreeForms(list: []const u8) Malformed!std.EnumSet(Form) {
    if (list.len == 0) return error.Malformed;
    var forms: std.EnumSet(Form) = .empty;
    var rest = list;
    while (rest.len > 0) forms.insert((try nextSubtree(&rest)).form);
    return forms;
}

/// `GeneralSubtree ::= SEQUENCE { base GeneralName, minimum [0]
/// BaseDistance DEFAULT 0, maximum [1] BaseDistance OPTIONAL }` at the
/// front of `list`: its base. RFC 5280 has minimum 0 and no maximum for
/// every form. A minimum other than 0, a maximum, or a base other than a
/// DNS name or an IP range (a directory name, an email address, a URI)
/// is `Malformed`, refused rather than passed over: a limit not read
/// would let through what it is there to keep out.
fn nextSubtree(list: *[]const u8) Malformed!GeneralName {
    const subtree = try tlv(list.*);
    list.* = subtree.rest;
    if (subtree.tag != tag_sequence) return error.Malformed;
    const base = try tlv(subtree.body);
    if (base.rest.len != 0) {
        const minimum = try tlv(base.rest);
        if (minimum.tag != tag_minimum or minimum.rest.len != 0 or !std.mem.eql(u8, minimum.body, &.{0})) return error.Malformed;
    }
    const form = formOf(base.tag) orelse return error.Malformed;
    switch (form) {
        .dns => try validDnsBase(base.body),
        .ip => try validIpRange(base.body),
    }
    return .{ .form = form, .name = base.body };
}

const Match = enum {
    /// Every name `name` stands for is in the subtree: what a permitted
    /// subtree asks.
    within,
    /// Some name `name` stands for is in the subtree: what an excluded
    /// one refuses.
    overlaps,
};

/// `name`, a certificate's, against `base`, a subtree of the same form.
/// A name that is not one (a DNS name with an empty label, an address
/// neither 4 nor 16 bytes) is `Malformed`.
fn matches(name: GeneralName, base: GeneralName, how: Match) Malformed!bool {
    switch (name.form) {
        .dns => {
            try validDnsName(name.name);
            return switch (how) {
                .within => dnsWithin(name.name, base.name),
                .overlaps => dnsOverlaps(name.name, base.name),
            };
        },
        // An address is one point: in the range, or not.
        .ip => return ipWithin(name.name, base.name),
    }
}

/// A DNS name as a certificate names one: labels of letters, digits,
/// hyphens and underscores, the first of two or more may be a `*`
/// alone. No empty label, so no trailing dot: std's host check compares
/// names as they are, and `example.com.` would be outside every subtree
/// it means to be in.
fn validDnsName(name: []const u8) Malformed!void {
    if (name.len == 0 or name.len > 253) return error.Malformed;
    var labels = std.mem.splitScalar(u8, name, '.');
    var first = true;
    while (labels.next()) |label| : (first = false) {
        if (first and std.mem.eql(u8, label, "*") and labels.peek() != null) continue;
        try validLabel(label);
    }
}

/// A DNS subtree: empty (every name), or a name with no `*`, which may
/// start with a `.` for names under it and not the name itself (as Go,
/// NSS and OpenSSL read one).
fn validDnsBase(base: []const u8) Malformed!void {
    if (base.len == 0) return;
    const name = if (base[0] == '.') base[1..] else base;
    if (name.len == 0 or name.len > 253) return error.Malformed;
    var labels = std.mem.splitScalar(u8, name, '.');
    while (labels.next()) |label| try validLabel(label);
}

fn validLabel(label: []const u8) Malformed!void {
    if (label.len == 0 or label.len > 63) return error.Malformed;
    for (label) |c| switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9', '-', '_' => {},
        else => return error.Malformed,
    };
}

/// RFC 5280 4.2.1.10: a name is in a DNS subtree when it is the base
/// with zero or more labels added on the left. A wildcard name is a name
/// with `*` as its first label, so `*.example.com` is within
/// `example.com`, and not within `a.example.com`, whose subtree holds
/// only some of the names it stands for. Neither case nor a `*` in the
/// base is special. Both have been through `validDnsName` and
/// `validDnsBase`.
fn dnsWithin(name: []const u8, base: []const u8) bool {
    if (base.len == 0) return true;
    const under_only = base[0] == '.';
    const b = if (under_only) base[1..] else base;
    if (name.len < b.len or !std.ascii.eqlIgnoreCase(name[name.len - b.len ..], b)) return false;
    if (name.len == b.len) return !under_only;
    return name[name.len - b.len - 1] == '.';
}

/// Whether any name `name` stands for is in `base`'s subtree. A wildcard
/// stands for each name with one label in place of its `*`, so
/// `*.example.com` overlaps `bad.example.com` (std's host check would
/// take it for that host), but not `a.bad.example.com`.
fn dnsOverlaps(name: []const u8, base: []const u8) bool {
    if (dnsWithin(name, base)) return true;
    if (!std.mem.startsWith(u8, name, "*.") or base.len == 0 or base[0] == '.') return false;
    const rest = name[1..]; // ".example.com"
    if (base.len <= rest.len or !std.ascii.eqlIgnoreCase(base[base.len - rest.len ..], rest)) return false;
    return std.mem.findScalar(u8, base[0 .. base.len - rest.len], '.') == null;
}

/// An IP range as nameConstraints writes one: an IPv4 address and its
/// mask (8 bytes), or an IPv6 one's (32), the mask ones then zeros.
fn validIpRange(range: []const u8) Malformed!void {
    if (range.len != 8 and range.len != 32) return error.Malformed;
    var past = false; // past the mask's last one
    for (range[range.len / 2 ..]) |byte| {
        if (past and byte != 0) return error.Malformed;
        const inverse = ~byte;
        if (inverse & (inverse +% 1) != 0) return error.Malformed; // a one after a zero
        past = byte != 0xFF;
    }
}

/// Whether `address`, a certificate's (4 or 16 bytes), is in `range`. An
/// IPv4 address written as IPv6 (::ffff:a.b.c.d) is `Malformed`: it is
/// both forms, and a range of either could be dodged by the other.
fn ipWithin(address: []const u8, range: []const u8) Malformed!bool {
    if (address.len != 4 and address.len != 16) return error.Malformed;
    const v4_mapped = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF };
    if (address.len == 16 and std.mem.startsWith(u8, address, &v4_mapped)) return error.Malformed;
    if (range.len != 2 * address.len) return false;
    const net = range[0..address.len];
    const mask = range[address.len..];
    for (address, net, mask) |a, n, m| if (a & m != n & m) return false;
    return true;
}

const testing = std.testing;

test {
    _ = der;
}

test "tls_chain: basicConstraints reads cA and pathLenConstraint, and refuses what does not read" {
    // SEQUENCE {}: cA left at its default, false.
    try testing.expectEqual(Basic{ .ca = false, .path_len = null }, try basicConstraintsOf(&.{ 0x30, 0x00 }));
    try testing.expectEqual(Basic{ .ca = true, .path_len = null }, try basicConstraintsOf(&.{ 0x30, 0x03, 0x01, 0x01, 0xFF }));
    try testing.expectEqual(Basic{ .ca = true, .path_len = 0 }, try basicConstraintsOf(&.{ 0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00 }));
    try testing.expectEqual(Basic{ .ca = false, .path_len = 3 }, try basicConstraintsOf(&.{ 0x30, 0x03, 0x02, 0x01, 0x03 }));
    // A pathLenConstraint past u32 is as good as none.
    try testing.expectEqual(Basic{ .ca = true, .path_len = std.math.maxInt(u32) }, try basicConstraintsOf(&.{ 0x30, 0x0A, 0x01, 0x01, 0xFF, 0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00 }));
    const bad = [_][]const u8{
        &.{},
        &.{ 0x31, 0x00 }, // a SET
        &.{ 0x30, 0x03, 0x01, 0x01 }, // cut short
        &.{ 0x30, 0x04, 0x01, 0x02, 0xFF, 0xFF }, // a two-byte BOOLEAN
        &.{ 0x30, 0x03, 0x02, 0x01, 0xFF }, // pathLenConstraint -1
        &.{ 0x30, 0x02, 0x02, 0x00 }, // an empty INTEGER
        &.{ 0x30, 0x03, 0x01, 0x01, 0xFF, 0x00 }, // a byte after the SEQUENCE
        &.{ 0x30, 0x05, 0x01, 0x01, 0xFF, 0x05, 0x00 }, // NULL where the INTEGER goes
        &.{ 0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF }, // a length past the bytes
        &.{ 0x30, 0x80, 0x00, 0x00 }, // BER's indefinite length
    };
    for (bad) |b| try testing.expectError(error.Malformed, basicConstraintsOf(b));
}

test "tls_chain: keyUsage's keyCertSign is bit 5, and an unused bit is not set" {
    // keyCertSign and cRLSign (bits 5 and 6), one unused bit.
    try testing.expect(try keyCertSign(&.{ 0x03, 0x02, 0x01, 0x06 }));
    // digitalSignature (bit 0) alone.
    try testing.expect(!try keyCertSign(&.{ 0x03, 0x02, 0x07, 0x80 }));
    // No bits at all.
    try testing.expect(!try keyCertSign(&.{ 0x03, 0x01, 0x00 }));
    // 0x04 set but said to be unused padding: not keyCertSign.
    try testing.expect(!try keyCertSign(&.{ 0x03, 0x02, 0x03, 0x04 }));
    // Two bytes of bits (decipherOnly is bit 8): bit 5 in the first.
    try testing.expect(try keyCertSign(&.{ 0x03, 0x03, 0x07, 0x04, 0x80 }));
    try testing.expectError(error.Malformed, keyCertSign(&.{ 0x03, 0x00 }));
    try testing.expectError(error.Malformed, keyCertSign(&.{ 0x03, 0x02, 0x08, 0x04 }));
    try testing.expectError(error.Malformed, keyCertSign(&.{ 0x04, 0x02, 0x01, 0x06 }));
}

/// A DER element: `tag`, its length, then `parts` one after another.
fn testDer(a: std.mem.Allocator, tag: u8, parts: []const []const u8) ![]const u8 {
    const body = try std.mem.concat(a, u8, parts);
    std.debug.assert(body.len < 0x10000);
    const head: []const u8 = if (body.len < 0x80)
        &.{ tag, @intCast(body.len) }
    else if (body.len < 0x100)
        &.{ tag, 0x81, @intCast(body.len) }
    else
        &.{ tag, 0x82, @intCast(body.len >> 8), @truncate(body.len) };
    return std.mem.concat(a, u8, &.{ head, body });
}

fn testExt(a: std.mem.Allocator, oid: []const u8, critical: bool, value: []const u8) ![]const u8 {
    const flag: []const u8 = if (critical) &.{ tag_boolean, 0x01, 0xFF } else "";
    return testDer(a, tag_sequence, &.{ try testDer(a, tag_oid, &.{oid}), flag, try testDer(a, tag_octet_string, &.{value}) });
}

/// A certificate with only what `readExtensions` reads filled in: its
/// version (`.v1` written with no version field) and `exts`, the
/// extensions (null for none), after an issuerUniqueID when `unique_id`.
fn testCert(a: std.mem.Allocator, version: Certificate.Version, exts: ?[]const []const u8, unique_id: bool) !Parsed {
    const empty: []const u8 = &.{ tag_sequence, 0x00 };
    const v: []const u8 = switch (version) {
        .v1 => "",
        .v2 => try testDer(a, tag_version, &.{&.{ tag_integer, 0x01, 0x01 }}),
        .v3 => try testDer(a, tag_version, &.{&.{ tag_integer, 0x01, 0x02 }}),
    };
    const uid: []const u8 = if (unique_id) &.{ 0x81, 0x01, 0x00 } else "";
    const ext_field: []const u8 = if (exts) |e| try testDer(a, tag_extensions, &.{try testDer(a, tag_sequence, e)}) else "";
    // serial, then signature, issuer, validity, subject and key, empty
    const tbs = try testDer(a, tag_sequence, &.{ v, &.{ tag_integer, 0x01, 0x01 }, empty, empty, empty, empty, empty, uid, ext_field });
    var p: Parsed = undefined;
    p.version = version;
    p.certificate = .{ .buffer = try testDer(a, tag_sequence, &.{ tbs, empty, &.{ tag_bit_string, 0x01, 0x00 } }), .index = 0 };
    return p;
}

const oid_basic_constraints = known[0].oid;
const oid_key_usage = known[1].oid;
const oid_ext_key_usage = known[2].oid;
const oid_name_constraints = known[3].oid;
const oid_subject_alt_name = known[4].oid;

test "tls_chain: the extensions read once each; none, or not version 3, is no CA" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const ca_true: []const u8 = &.{ 0x30, 0x03, 0x01, 0x01, 0xFF };
    const cert_sign: []const u8 = &.{ 0x03, 0x02, 0x01, 0x06 };
    const basic = try testExt(a, oid_basic_constraints, true, ca_true);
    const usage = try testExt(a, oid_key_usage, true, cert_sign);
    const other = try testExt(a, known[5].oid, false, &.{ 0x04, 0x01, 0x00 });

    const ca = try readExtensions(try testCert(a, .v3, &.{ other, basic, usage }, false));
    try testing.expectEqual(Basic{ .ca = true, .path_len = null }, try ca.basicConstraints());
    try testing.expect(try keyCertSign(ca.key_usage.?));
    // After an issuerUniqueID, the extensions are still found.
    try testing.expect((try (try readExtensions(try testCert(a, .v3, &.{ basic, usage }, true))).basicConstraints()).ca);
    // Without keyUsage, nothing is said about keyCertSign.
    try testing.expect((try readExtensions(try testCert(a, .v3, &.{basic}, false))).key_usage == null);
    // The obsolete basicConstraints (2.5.29.10) is not the one.
    const obsolete = try testExt(a, &.{ 0x55, 0x1D, 0x0A }, false, ca_true);
    try testing.expect(!(try (try readExtensions(try testCert(a, .v3, &.{obsolete}, false))).basicConstraints()).ca);
    // No extensions: nothing said, so no CA.
    try testing.expect(!(try (try readExtensions(try testCert(a, .v3, null, false))).basicConstraints()).ca);
    try testing.expect(!(try (try readExtensions(try testCert(a, .v1, null, false))).basicConstraints()).ca);

    // Any extension rest-core knows, twice: the second could say what the first does not.
    try testing.expectError(error.Malformed, readExtensions(try testCert(a, .v3, &.{ basic, usage, basic }, false)));
    try testing.expectError(error.Malformed, readExtensions(try testCert(a, .v3, &.{ usage, basic, usage }, false)));
    const san = try testExt(a, oid_subject_alt_name, false, &.{ 0x30, 0x00 });
    try testing.expectError(error.Malformed, readExtensions(try testCert(a, .v3, &.{ san, basic, san }, false)));
    // Extensions in a version 2 certificate.
    try testing.expectError(error.Malformed, readExtensions(try testCert(a, .v2, &.{ basic, usage }, false)));
    // A critical flag of two bytes.
    const two_byte_flag = try testDer(a, tag_sequence, &.{ try testDer(a, tag_oid, &.{oid_basic_constraints}), &.{ tag_boolean, 0x02, 0xFF, 0xFF }, try testDer(a, tag_octet_string, &.{ca_true}) });
    try testing.expectError(error.Malformed, readExtensions(try testCert(a, .v3, &.{two_byte_flag}, false)));
}

test "tls_chain: an unknown extension is passed over unless critical; a known critical one is fine" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const unknown_oid: []const u8 = &.{ 0x2A, 0x03, 0x04 }; // 1.2.3.4
    const quiet = try testExt(a, unknown_oid, false, &.{ 0x05, 0x00 });
    const loud = try testExt(a, unknown_oid, true, &.{ 0x05, 0x00 });
    const policies = try testExt(a, known[7].oid, true, &.{ 0x30, 0x00 });
    try (try readExtensions(try testCert(a, .v3, &.{ quiet, policies }, false))).usable();
    try testing.expectError(error.CertificateUnhandledCriticalExtension, (try readExtensions(try testCert(a, .v3, &.{loud}, false))).usable());
    // policyConstraints, inhibitAnyPolicy and policyMappings, which RFC
    // 5280 has always critical: rest-core does no policy processing.
    for ([_][]const u8{ &.{ 0x55, 0x1D, 0x24 }, &.{ 0x55, 0x1D, 0x36 }, &.{ 0x55, 0x1D, 0x21 } }) |oid| {
        const ext = try testExt(a, oid, true, &.{ 0x30, 0x00 });
        try testing.expectError(error.CertificateUnhandledCriticalExtension, (try readExtensions(try testCert(a, .v3, &.{ext}, false))).usable());
    }
}

test "tls_chain: an extended key usage must list serverAuth" {
    const server = [_]u8{ 0x30, 0x0A, 0x06, 0x08 } ++ oid_server_auth;
    const client = [_]u8{ 0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02 };
    const any = [_]u8{ 0x30, 0x06, 0x06, 0x04, 0x55, 0x1D, 0x25, 0x00 }; // anyExtendedKeyUsage
    const client_then_server = [_]u8{ 0x30, 0x14 } ++ client[2..] ++ server[2..];
    try testing.expect(try serverAuth(&server));
    try testing.expect(try serverAuth(client_then_server));
    try testing.expect(!try serverAuth(&client));
    try testing.expect(!try serverAuth(&any));
    try testing.expectError(error.Malformed, serverAuth(&.{ 0x30, 0x00 })); // SIZE (1..MAX)
    try testing.expectError(error.Malformed, serverAuth(&.{ 0x30, 0x02, 0x05, 0x00 })); // NULL, not an OID
    try testing.expectError(error.Malformed, serverAuth(&(server ++ [_]u8{0x00})));
    // One that does not read allows nothing.
    const e: Extensions = .{ .ext_key_usage = &.{ 0x30, 0x02, 0x05, 0x00 } };
    try testing.expectError(error.CertificateExtKeyUsage, e.usable());
}

test "tls_chain: a DNS name is in a subtree when the subtree's name ends it on a label" {
    const yes = [_][2][]const u8{
        .{ "example.com", "example.com" },
        .{ "a.example.com", "example.com" },
        .{ "A.EXAMPLE.com", "example.COM" },
        .{ "a.b.example.com", "example.com" },
        .{ "*.example.com", "example.com" },
        .{ "a.example.com", ".example.com" },
        .{ "*.example.com", ".example.com" },
        .{ "anything.at.all", "" },
    };
    for (yes) |c| try testing.expect(dnsWithin(c[0], c[1]));
    const no = [_][2][]const u8{
        .{ "badexample.com", "example.com" },
        .{ "example.com", ".example.com" },
        .{ "example.com", "a.example.com" },
        .{ "*.example.com", "a.example.com" },
        .{ "com", "example.com" },
        .{ "example.org", "example.com" },
    };
    for (no) |c| try testing.expect(!dnsWithin(c[0], c[1]));
}

test "tls_chain: a wildcard overlaps the subtree of each name it stands for" {
    // Itself within: overlaps.
    try testing.expect(dnsOverlaps("a.example.com", "example.com"));
    try testing.expect(dnsOverlaps("*.example.com", "example.com"));
    // `*` stands for `bad`, so the wildcard covers bad.example.com.
    try testing.expect(dnsOverlaps("*.example.com", "bad.example.com"));
    try testing.expect(dnsOverlaps("*.EXAMPLE.com", "Bad.example.COM"));
    // One label only: not a.bad.example.com, nor only the names under bad.example.com.
    try testing.expect(!dnsOverlaps("*.example.com", "a.bad.example.com"));
    try testing.expect(!dnsOverlaps("*.example.com", ".bad.example.com"));
    try testing.expect(!dnsOverlaps("*.example.com", "bad.example.org"));
    try testing.expect(!dnsOverlaps("good.example.com", "bad.example.com"));
}

test "tls_chain: names and subtrees that are not DNS names are refused" {
    for ([_][]const u8{ "localhost", "a.example.com", "*.example.com", "x-1_y.example" }) |n| try validDnsName(n);
    const bad_names = [_][]const u8{ "", "example.com.", ".example.com", "a..example.com", "*", "a.*.example.com", "f*.example.com", "*.*.example.com", "exa mple.com", "\xC3\xA9.com", "a/b" };
    for (bad_names) |n| try testing.expectError(error.Malformed, validDnsName(n));
    for ([_][]const u8{ "", "example.com", ".example.com", "localhost" }) |b| try validDnsBase(b);
    for ([_][]const u8{ ".", "*.example.com", "example.com.", "a..b", " example.com" }) |b| try testing.expectError(error.Malformed, validDnsBase(b));
}

test "tls_chain: an address is in an IP range when it agrees under the mask" {
    const ten: []const u8 = &.{ 10, 0, 0, 0, 255, 0, 0, 0 };
    try testing.expect(try ipWithin(&.{ 10, 1, 2, 3 }, ten));
    try testing.expect(!try ipWithin(&.{ 127, 0, 0, 1 }, ten));
    // An IPv4 address against an IPv6 range: not in it.
    var v6_range: [32]u8 = @splat(0);
    v6_range[0] = 0x20;
    v6_range[1] = 0x01;
    @memset(v6_range[16..20], 0xFF);
    try testing.expect(!try ipWithin(&.{ 10, 1, 2, 3 }, &v6_range));
    var v6: [16]u8 = @splat(0);
    v6[0] = 0x20;
    v6[1] = 0x01;
    v6[15] = 1;
    try testing.expect(try ipWithin(&v6, &v6_range));
    // An IPv4 address written as IPv6.
    const mapped = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 10, 1, 2, 3 };
    try testing.expectError(error.Malformed, ipWithin(&mapped, ten));
    try testing.expectError(error.Malformed, ipWithin(&.{ 10, 1, 2 }, ten));

    try validIpRange(ten);
    try validIpRange(&.{ 192, 168, 0, 0, 255, 255, 240, 0 });
    try validIpRange(&.{ 0, 0, 0, 0, 0, 0, 0, 0 });
    try validIpRange(&v6_range);
    try testing.expectError(error.Malformed, validIpRange(&.{ 10, 0, 0, 0, 255, 0, 255, 0 }));
    try testing.expectError(error.Malformed, validIpRange(&.{ 10, 0, 0, 0, 0xF7, 0, 0, 0 }));
    try testing.expectError(error.Malformed, validIpRange(&.{ 10, 0, 0, 0 }));
}

/// A GeneralSubtree whose base is `tag` and `name`, then `tail`.
fn testSubtree(a: std.mem.Allocator, tag: u8, name: []const u8, tail: []const u8) ![]const u8 {
    return testDer(a, tag_sequence, &.{ try testDer(a, tag, &.{name}), tail });
}

test "tls_chain: nameConstraints read DNS and IP subtrees, and refuse every other form" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const dns = try testSubtree(a, tag_dns_name, "example.com", "");
    const ip = try testSubtree(a, tag_ip_address, &.{ 10, 0, 0, 0, 255, 0, 0, 0 }, "");
    const both = try testDer(a, tag_sequence, &.{ try testDer(a, tag_permitted, &.{dns}), try testDer(a, tag_excluded, &.{ip}) });
    const s = try readNameConstraints(both);
    try testing.expect(s.permits.contains(.dns) and !s.permits.contains(.ip));
    try testing.expectEqual(ip.len, s.excluded.len);
    // Excluded alone, and a minimum of 0 written out.
    const zero_min = try testSubtree(a, tag_dns_name, "example.com", &.{ tag_minimum, 0x01, 0x00 });
    _ = try readNameConstraints(try testDer(a, tag_sequence, &.{try testDer(a, tag_excluded, &.{zero_min})}));

    const bad_subtrees = [_][]const u8{
        try testSubtree(a, 0x81, "example.com", ""), // rfc822Name
        try testSubtree(a, 0x86, "https://example.com", ""), // URI
        try testSubtree(a, 0xA4, &.{ 0x30, 0x00 }, ""), // directoryName
        try testSubtree(a, 0xA0, &.{ 0x06, 0x01, 0x2A }, ""), // otherName
        try testSubtree(a, tag_dns_name, "example.com", &.{ tag_minimum, 0x01, 0x01 }), // minimum 1
        try testSubtree(a, tag_dns_name, "example.com", &.{ 0x81, 0x01, 0x02 }), // a maximum
        try testSubtree(a, tag_dns_name, "*.example.com", ""),
        try testSubtree(a, tag_ip_address, &.{ 10, 0, 0, 0 }, ""),
    };
    for (bad_subtrees) |sub| {
        try testing.expectError(error.Malformed, readNameConstraints(try testDer(a, tag_sequence, &.{try testDer(a, tag_permitted, &.{sub})})));
        // Excluded too: one rest-core cannot read might have kept out the name.
        try testing.expectError(error.Malformed, readNameConstraints(try testDer(a, tag_sequence, &.{try testDer(a, tag_excluded, &.{ dns, sub })})));
    }
    const bad_shapes = [_][]const u8{
        &.{ 0x30, 0x00 }, // neither list
        &.{ 0x30, 0x02, tag_permitted, 0x00 }, // an empty list
        try testDer(a, tag_sequence, &.{ try testDer(a, tag_excluded, &.{dns}), try testDer(a, tag_permitted, &.{dns}) }), // out of order
        try testDer(a, tag_sequence, &.{ try testDer(a, tag_permitted, &.{dns}), &.{ 0x05, 0x00 } }),
    };
    for (bad_shapes) |b| try testing.expectError(error.Malformed, readNameConstraints(b));
}

/// A Path whose server's certificate has `san` (GeneralNames) and `cn`.
fn testPath(san: []const u8, cn: []const u8) Path {
    var p: Path = .{};
    p.below[0] = .{ .san = san, .cn = cn };
    p.below_len = 1;
    return p;
}

test "tls_chain: a name outside the permitted subtrees, or inside an excluded one, is refused" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const nc = struct {
        fn of(al: std.mem.Allocator, tag: u8, subtrees: []const []const u8) ![]const u8 {
            return testDer(al, tag_sequence, &.{try testDer(al, tag, subtrees)});
        }
    }.of;
    const example = try testSubtree(a, tag_dns_name, "example.com", "");
    const ten = try testSubtree(a, tag_ip_address, &.{ 10, 0, 0, 0, 255, 0, 0, 0 }, "");
    const names = try testDer(a, tag_sequence, &.{ try testDer(a, tag_dns_name, &.{"www.example.com"}), try testDer(a, tag_ip_address, &.{&.{ 127, 0, 0, 1 }}) });

    var p = testPath(names, "");
    // DNS names held to example.com: www.example.com is in it. No IP
    // subtree is permitted, so the address is not limited.
    try p.constrain(try nc(a, tag_permitted, &.{example}));
    // IP addresses held to 10/8: 127.0.0.1 is not in it.
    try testing.expectError(error.CertificateNameConstraints, p.constrain(try nc(a, tag_permitted, &.{ example, ten })));
    // Excluded: www.example.com is under example.com.
    try testing.expectError(error.CertificateNameConstraints, p.constrain(try nc(a, tag_excluded, &.{example})));
    // A common name stands in only when there is no subjectAltName.
    var q = testPath("", "localhost");
    try testing.expectError(error.CertificateNameConstraints, q.constrain(try nc(a, tag_permitted, &.{example})));
    var r = testPath("", "www.example.com");
    try r.constrain(try nc(a, tag_permitted, &.{example}));
    // A common name that is no DNS name, under a DNS constraint.
    var s = testPath("", "ekur test leaf");
    try testing.expectError(error.CertificateNameConstraints, s.constrain(try nc(a, tag_permitted, &.{example})));
    // A trailing dot is no way around an excluded subtree: std's host
    // check would take `localhost.` for a client that asks for it.
    var dot = testPath(try testDer(a, tag_sequence, &.{try testDer(a, tag_dns_name, &.{"localhost."})}), "");
    try testing.expectError(error.CertificateNameConstraints, dot.constrain(try nc(a, tag_excluded, &.{try testSubtree(a, tag_dns_name, "localhost", "")})));
    // A name of a form no subtree holds (a URI) passes.
    var t = testPath(try testDer(a, tag_sequence, &.{try testDer(a, 0x86, &.{"https://localhost/"})}), "");
    try t.constrain(try nc(a, tag_permitted, &.{example}));
}

test "security: CWE-400 a chain whose names and nameConstraints would take millions of comparisons is refused (ekur t383)" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // 300 names against 300 excluded subtrees, none matching: 90,000
    // comparisons, more than the cap. Each is cheap; a few thousand of
    // each, which a certificate message holds, would be millions.
    var names: std.ArrayList(u8) = .empty;
    var subtrees: std.ArrayList(u8) = .empty;
    for (0..300) |i| {
        try names.appendSlice(a, try testDer(a, tag_dns_name, &.{try std.fmt.allocPrint(a, "n{d}.example.com", .{i})}));
        try subtrees.appendSlice(a, try testSubtree(a, tag_dns_name, try std.fmt.allocPrint(a, "s{d}.example.org", .{i}), ""));
    }
    const nc = try testDer(a, tag_sequence, &.{try testDer(a, tag_excluded, &.{subtrees.items})});
    var p = testPath(try testDer(a, tag_sequence, &.{names.items}), "");
    try testing.expectError(error.CertificateNameConstraints, p.constrain(nc));
    try testing.expectEqual(max_comparisons + 1, p.comparisons);
    // 200 by 200 is 40,000: checked in full, and nothing in it is refused.
    var few: std.ArrayList(u8) = .empty;
    for (0..200) |i| try few.appendSlice(a, try testDer(a, tag_dns_name, &.{try std.fmt.allocPrint(a, "n{d}.example.com", .{i})}));
    var q = testPath(try testDer(a, tag_sequence, &.{few.items}), "");
    var some: std.ArrayList(u8) = .empty;
    for (0..200) |i| try some.appendSlice(a, try testSubtree(a, tag_dns_name, try std.fmt.allocPrint(a, "s{d}.example.org", .{i}), ""));
    try q.constrain(try testDer(a, tag_sequence, &.{try testDer(a, tag_excluded, &.{some.items})}));
}
