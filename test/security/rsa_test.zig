//! RSA signing and verifying against a hostile signature, a faulty key, and
//! a salt that repeats.

const std = @import("std");
const rsa = @import("rest_core").rsa;
const testing = std.testing;

test "security: a fault while signing never hands out the signature it made" {
    var key = try rsa.parsePem(rsa.test_key_2048);
    defer key.deinit();
    // A private exponent one bit wrong, as a fault in memory or in the
    // arithmetic would leave it: the signature it makes would let anyone
    // factor the modulus from it, so it must never leave.
    key.d[key.d_len - 1] ^= 0x01;
    var out: [rsa.max_modulus_bytes]u8 = undefined;
    try testing.expectError(error.SignatureFailed, key.sign(rsa.test_message, &out));
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(rsa.test_message, &digest, .{});
    const salt: [32]u8 = @splat(7);
    try testing.expectError(error.SignatureFailed, key.signPss(.sha256, &digest, &salt, &out));
}

test "security: CWE-347 a signature is held to the whole expected encoding" {
    var key = try rsa.parsePem(rsa.test_key_2048);
    defer key.deinit();
    const public = key.publicKey();
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(rsa.test_message, &digest, .{});
    var out: [rsa.max_modulus_bytes]u8 = undefined;
    const signature = try key.signDigest(.sha256, &digest, &out);
    try public.verifyPkcs1(.sha256, &digest, signature);
    // Any byte of the signature changed, or another digest, or a digest of
    // another length, is refused: the decrypted block is compared whole with
    // the encoding it must be, never parsed for the digest inside it.
    for (0..signature.len) |i| {
        var spoiled: [rsa.max_modulus_bytes]u8 = undefined;
        @memcpy(spoiled[0..signature.len], signature);
        spoiled[i] ^= 0x80;
        try testing.expectError(error.SignatureInvalid, public.verifyPkcs1(.sha256, &digest, spoiled[0..signature.len]));
    }
    var other = digest;
    other[0] ^= 1;
    try testing.expectError(error.SignatureInvalid, public.verifyPkcs1(.sha256, &other, signature));
    try testing.expectError(error.SignatureInvalid, public.verifyPkcs1(.sha256, digest[0..20], signature));
}

test "security: CWE-330 PSS signatures of one digest differ with their salts, and each verifies" {
    var key = try rsa.parsePem(rsa.test_key_2048);
    defer key.deinit();
    const public = key.publicKey();
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(rsa.test_message, &digest, .{});
    // The salt is the caller's, from a cryptographic source.
    var salt_a: [32]u8 = undefined;
    var salt_b: [32]u8 = undefined;
    testing.io.random(&salt_a);
    testing.io.random(&salt_b);
    var a: [rsa.max_modulus_bytes]u8 = undefined;
    var b: [rsa.max_modulus_bytes]u8 = undefined;
    const sig_a = try key.signPss(.sha256, &digest, &salt_a, &a);
    const sig_b = try key.signPss(.sha256, &digest, &salt_b, &b);
    try testing.expect(!std.mem.eql(u8, sig_a, sig_b));
    try public.verifyPss(.sha256, &digest, sig_a);
    try public.verifyPss(.sha256, &digest, sig_b);
}
