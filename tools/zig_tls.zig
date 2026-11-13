// From ekur tools/zig_tls.zig at ba2c6c7, less its TLS 1.2 ECDSA suites, with std's HTTP client beside the TLS one.
//! `zig-tls --write|--check STD_TLS_CLIENT STD_HTTP_CLIENT DIR`:
//! deps/zig-tls holds two of std's files from the Zig that builds
//! rest-core, patched (t78, t31):
//!
//! - Client.zig, std's crypto/tls/Client.zig, with three patches after
//!   ekur's copy of it (ekur t380, t382, t383):
//!   - Each certificate that signed the one before it in the server's
//!     chain checked to be a CA (src/tls_chain.zig; CONN-10). Zig 0.17's
//!     client checks signatures and names alone (Codeberg
//!     ziglang/zig#35877), so a certificate a trusted root signed for any
//!     domain could sign one for every other.
//!   - Each certificate in the chain, and the root std finds for it, held
//!     to the limits it states: no critical extension rest-core does not
//!     process, an extended key usage that allows a TLS server, and the
//!     nameConstraints of each CA above it (CONN-13). std reads none of
//!     it.
//!   - A server's bytes kept from crashing the client: each certificate
//!     it sends checked before std parses it (src/tls_cert.zig, by way of
//!     tls_chain; CONN-11), as std's DER reader trusts every length, and
//!     an RSA signature held to its key's length before std copies it
//!     into a buffer of that length (CONN-12; PR ziglang/zig#36695).
//! - HttpClient.zig, std's http/Client.zig with Client.zig for its TLS
//!   client. std.http.Client builds its TLS client itself, in a private
//!   function, so the transport could not reach std's otherwise. The
//!   BodyWriter a request returns is left without its link back to the
//!   request, since std.http.BodyWriter types it as std's Request: the
//!   transport clears `payload_pending` when the body ends, as BodyWriter
//!   would.
//!
//! Both import std as a package. `--write` makes the copies (`zig build
//! zig-tls`); `--check` fails when a copy is not exactly that (`zig build
//! test` runs it), so a Zig upgrade, or an edit by hand, is caught rather
//! than shipped. When a Zig release changes the lines a patch finds, the
//! tool says which patch, and why it is there: drop that patch once std
//! does its work itself, and deps/zig-tls with the last of them
//! (deps/zig-tls/VENDORED.md says how).

const std = @import("std");
const builtin = @import("builtin");

const Io = std.Io;

/// A line of std's, exactly `line` once its indent is trimmed, found
/// exactly `count` times: put `before` on the line before it, `replace`
/// in its place, and `after` on the line after it, each at its indent.
const Edit = struct {
    line: []const u8,
    before: ?[]const u8 = null,
    replace: ?[]const u8 = null,
    after: ?[]const u8 = null,
    count: usize = 1,
    /// Which patch it belongs to, for the message when it is not found.
    why: []const u8,
};

const why_import = "std imported as a package";
const why_chain = "each signer in the chain checked to be a CA (src/tls_chain.zig, CONN-10; Codeberg ziglang/zig#35877)";
const why_limits = "each certificate in the chain, the root included, held to the limits it states: extended key usage, nameConstraints, critical extensions (src/tls_chain.zig, CONN-13)";
const why_parse = "a server's certificate checked before std parses it, whose DER reader trusts every length (src/tls_cert.zig, CONN-11)";
const why_rsa = "an RSA signature held to its key's length before std copies it into a buffer of that length (CONN-12; PR ziglang/zig#36695)";
const why_http = "std's HTTP client on the patched TLS client, Client.zig beside it";
const why_body = "std.http.BodyWriter typed for std's Request, which this copy's is not";

const tls_edits = [_]Edit{
    .{ .line = "const std = @import(\"../../std.zig\");", .replace = "const std = @import(\"std\");", .why = why_import },
    .{ .line = "const Certificate = std.crypto.Certificate;", .after = "const tls_chain = @import(\"tls_chain\");", .why = why_chain },
    .{ .line = "var prev_cert: Certificate.Parsed = undefined;", .after = "var cert_path: tls_chain.Path = .{};", .why = why_chain },
    .{ .line = "try prev_cert.verify(subject, now_sec);", .after = "try cert_path.issued(prev_cert, subject);", .why = why_chain },
    .{ .line = "try main_cert_pub_key.init(subject.pub_key_algo, subject.pubKey());", .after = "try cert_path.leaf(subject);", .why = why_limits },
    .{
        .line = "break :verify ca.bundle.verify(subject, now_sec);",
        .replace = "break :verify cert_path.anchored(ca.bundle, subject, now_sec);",
        .why = why_limits,
    },
    .{ .line = "const subject = try subject_cert.parse();", .replace = "const subject = try tls_chain.parse(subject_cert);", .why = why_parse },
    .{
        .line = "const sig = RsaSignature.fromBytes(modulus_len, encoded_sig);",
        .before = "if (encoded_sig.len != modulus_len) return error.InvalidSignature;",
        .why = why_rsa,
    },
    .{
        .line = "} || std.Io.Writer.Error || std.Io.Reader.ShortError || std.Io.Cancelable;",
        .replace = "} || tls_chain.Error || std.Io.Writer.Error || std.Io.Reader.ShortError || std.Io.Cancelable;",
        .why = why_chain,
    },
};

const http_edits = [_]Edit{
    .{ .line = "const std = @import(\"../std.zig\");", .replace = "const std = @import(\"std\");", .after = "const TlsClient = @import(\"zig_tls\");", .why = why_import },
    .{
        .line = "tls_buffer_size: if (disable_tls) u0 else usize = if (disable_tls) 0 else std.crypto.tls.Client.min_buffer_len,",
        .replace = "tls_buffer_size: if (disable_tls) u0 else usize = if (disable_tls) 0 else TlsClient.min_buffer_len,",
        .why = why_http,
    },
    .{ .line = "ssl_key_log: ?*std.crypto.tls.Client.SslKeyLog = null,", .replace = "ssl_key_log: ?*TlsClient.SslKeyLog = null,", .why = why_http },
    .{ .line = "client: std.crypto.tls.Client,", .replace = "client: TlsClient,", .why = why_http },
    .{
        .line = "var random_buffer: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;",
        .replace = "var random_buffer: [TlsClient.Options.entropy_len]u8 = undefined;",
        .why = why_http,
    },
    .{ .line = ".client = std.crypto.tls.Client.init(", .replace = ".client = TlsClient.init(", .why = why_http },
    .{
        .line = "pub const ReadError = std.crypto.tls.Client.ReadError || Io.net.Stream.Reader.Error;",
        .replace = "pub const ReadError = TlsClient.ReadError || Io.net.Stream.Reader.Error;",
        .why = why_http,
    },
    // std.http.BodyWriter's `client_request` is a `*std.http.Client.Request`,
    // not this copy's, so it is left null: the caller clears
    // `payload_pending` once `end` returns, as BodyWriter would have.
    .{
        .line = ".client_request = r,",
        .replace = "// .client_request = r: std's Request, not this copy's; the caller clears r.payload_pending after end() (tools/zig_tls.zig)",
        .count = 3,
        .why = why_body,
    },
};

/// A file of deps/zig-tls: its name there, std's file it is made from,
/// its header and its edits.
const File = struct {
    name: []const u8,
    std_path: []const u8,
    header: []const u8,
    edits: []const Edit,
};

const files = [_]File{
    .{ .name = "Client.zig", .std_path = "crypto/tls/Client.zig", .header = tls_header, .edits = &tls_edits },
    .{ .name = "HttpClient.zig", .std_path = "http/Client.zig", .header = http_header, .edits = &http_edits },
};

const tls_header =
    \\//! Vendored by tools/zig_tls.zig, not edited by hand: std's
    \\//! crypto/tls/Client.zig from Zig {s}, with each certificate that
    \\//! signed another in the server's chain checked to be a CA (tls_chain,
    \\//! src/tls_chain.zig; CONN-10), each certificate in the chain and its
    \\//! root held to the limits it states (extended key usage,
    \\//! nameConstraints, critical extensions; CONN-13), each certificate a
    \\//! server sends checked before std parses it (src/tls_cert.zig;
    \\//! CONN-11), an RSA signature held to its key's length (CONN-12), and
    \\//! std imported as a package. After ekur's copy (its t380, t382, t383).
    \\//! `zig build zig-tls` writes it again. Zig's MIT license is LICENSE
    \\//! beside it.
    \\
;

const http_header =
    \\//! Vendored by tools/zig_tls.zig, not edited by hand: std's
    \\//! http/Client.zig from Zig {s}, with Client.zig beside it (zig_tls)
    \\//! for its TLS client in place of std's, std imported as a package, and
    \\//! the BodyWriter a request returns not pointed back at the request,
    \\//! as std.http.BodyWriter is typed for std's: whoever ends the body
    \\//! clears `payload_pending` itself, as rest-core's transport does.
    \\//! Nothing else differs. `zig build zig-tls` writes it again. Zig's MIT
    \\//! license is LICENSE beside it.
    \\
;

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 5 or !(std.mem.eql(u8, args[1], "--write") or std.mem.eql(u8, args[1], "--check"))) {
        std.debug.print("usage: zig-tls --write|--check STD_TLS_CLIENT STD_HTTP_CLIENT DIR\n", .{});
        return 2;
    }
    var ok = true;
    inline for (files, 2..) |file, arg| {
        if (!try writeOrCheck(io, arena, file, std.mem.eql(u8, args[1], "--write"), args[arg], args[4])) ok = false;
    }
    return if (ok) 0 else 1;
}

/// `file` made from `std_file`, std's, and written into `dir`, or checked
/// against the copy there; false, said why, when it cannot be.
fn writeOrCheck(io: Io, arena: std.mem.Allocator, comptime file: File, write: bool, std_file: []const u8, dir: []const u8) !bool {
    const cwd = Io.Dir.cwd();
    const original = try cwd.readFileAlloc(io, std_file, arena, .limited(1 << 20));
    var missed: Missed = undefined;
    const want = patch(arena, file, original, &missed) catch |err| switch (err) {
        error.PatchFound => {
            std.debug.print("zig-tls: std's {s} in Zig {s} has the line `{s}` {d} times, not {d}, so the patch for {s} has no place: see whether std does that itself now, and if so drop it\n", .{ file.std_path, builtin.zig_version_string, missed.edit.line, missed.found, missed.edit.count, missed.edit.why });
            return false;
        },
        error.OutOfMemory => |e| return e,
    };
    const path = try std.fs.path.join(arena, &.{ dir, file.name });
    if (write) {
        try cwd.writeFile(io, .{ .sub_path = path, .data = want });
        std.debug.print("zig-tls: wrote {s} from Zig {s}\n", .{ path, builtin.zig_version_string });
        return true;
    }
    const have = cwd.readFileAlloc(io, path, arena, .limited(1 << 20)) catch |err| {
        std.debug.print("zig-tls: cannot read {s}: {t}; `zig build zig-tls` writes it\n", .{ path, err });
        return false;
    };
    if (std.mem.eql(u8, have, want)) return true;
    std.debug.print("zig-tls: {s} is not std's {s} from Zig {s} with rest-core's patches (t78): Zig was upgraded, or the copy was edited. `zig build zig-tls` writes it again; read the diff first.\n", .{ path, file.std_path, builtin.zig_version_string });
    return false;
}

/// Which edit found no place, or more than one, when `patch` says
/// `PatchFound`.
const Missed = struct { edit: Edit, found: usize };

/// `original`, std's file, as deps/zig-tls holds `file`.
fn patch(arena: std.mem.Allocator, comptime file: File, original: []const u8, missed: *Missed) error{ OutOfMemory, PatchFound }![]u8 {
    var out: std.Io.Writer.Allocating = .init(arena);
    const counts = try arena.alloc(usize, file.edits.len);
    @memset(counts, 0);
    patchLines(&out.writer, file, original, counts) catch return error.OutOfMemory;
    for (file.edits, counts) |e, n| if (n != e.count) {
        missed.* = .{ .edit = e, .found = n };
        return error.PatchFound;
    };
    return out.written();
}

/// The edit for `line`, counted in `counts`, if one is for it.
fn editFor(edits: []const Edit, counts: []usize, line: []const u8) ?Edit {
    const trimmed = std.mem.trim(u8, line, " ");
    for (edits, counts) |e, *n| if (std.mem.eql(u8, trimmed, e.line)) {
        n.* += 1;
        return e;
    };
    return null;
}

fn patchLines(w: *std.Io.Writer, comptime file: File, original: []const u8, counts: []usize) std.Io.Writer.Error!void {
    try w.print(file.header, .{builtin.zig_version_string});
    var lines = std.mem.splitScalar(u8, original, '\n');
    while (lines.next()) |line| {
        const indent = line[0 .. line.len - std.mem.trimStart(u8, line, " ").len];
        const edit = editFor(file.edits, counts, line);
        const before: ?[]const u8 = if (edit) |e| e.before else null;
        const replace: ?[]const u8 = if (edit) |e| e.replace else null;
        const after: ?[]const u8 = if (edit) |e| e.after else null;
        if (before) |b| try w.print("{s}{s}\n", .{ indent, b });
        if (replace) |r| try w.print("{s}{s}", .{ indent, r }) else try w.writeAll(line);
        if (lines.peek() != null) try w.writeByte('\n');
        if (after) |a| try w.print("{s}{s}\n", .{ indent, a });
    }
}

/// A stand-in for std's `file` with each line its patches look for, as often as they look for it.
fn fakeStd(arena: std.mem.Allocator, file: File) ![]const u8 {
    var src: std.ArrayList(u8) = .empty;
    for (file.edits) |e| for (0..e.count) |_| try src.print(arena, "    {s}\n", .{e.line});
    try src.appendSlice(arena, "// end");
    return src.items;
}

/// That `got` holds each of `in_order`, in that order.
fn expectInOrder(got: []const u8, in_order: []const []const u8) !void {
    var from: usize = 0;
    for (in_order) |want| {
        const at = std.mem.findPos(u8, got, from, want) orelse {
            std.debug.print("not found in order: {s}\n", .{want});
            return error.TestExpectedEqual;
        };
        from = at + want.len;
    }
}

test "the TLS client's patch checks each signer after std's own check of the link, and adds its errors" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var missed: Missed = undefined;
    const got = try patch(a, files[0], try fakeStd(a, files[0]), &missed);
    try expectInOrder(got, &.{
        "    const std = @import(\"std\");\n",
        "    const Certificate = std.crypto.Certificate;\n    const tls_chain = @import(\"tls_chain\");\n",
        "    var prev_cert: Certificate.Parsed = undefined;\n    var cert_path: tls_chain.Path = .{};\n",
        "    try prev_cert.verify(subject, now_sec);\n    try cert_path.issued(prev_cert, subject);\n",
        "    try main_cert_pub_key.init(subject.pub_key_algo, subject.pubKey());\n    try cert_path.leaf(subject);\n",
        "    break :verify cert_path.anchored(ca.bundle, subject, now_sec);\n",
        "    const subject = try tls_chain.parse(subject_cert);\n",
        "    if (encoded_sig.len != modulus_len) return error.InvalidSignature;\n    const sig = RsaSignature.fromBytes(modulus_len, encoded_sig);\n",
        "    } || tls_chain.Error || std.Io.Writer.Error || std.Io.Reader.ShortError || std.Io.Cancelable;\n",
    });
    try std.testing.expect(std.mem.find(u8, got, "ca.bundle.verify(") == null);
    try std.testing.expect(std.mem.find(u8, got, "subject_cert.parse()") == null);
    try std.testing.expect(std.mem.endsWith(u8, got, "// end"));
}

test "the HTTP client's patch puts every use of std's TLS client on the copy" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var missed: Missed = undefined;
    const got = try patch(a, files[1], try fakeStd(a, files[1]), &missed);
    try expectInOrder(got, &.{
        "    const std = @import(\"std\");\n    const TlsClient = @import(\"zig_tls\");\n",
        "    client: TlsClient,\n",
        "    .client = TlsClient.init(\n",
    });
    try std.testing.expect(std.mem.find(u8, got, "std.crypto.tls.Client") == null);
    // BodyWriter cannot point back at this copy's Request.
    try std.testing.expect(std.mem.find(u8, got, "    .client_request = r,") == null);
    try std.testing.expectEqual(3, std.mem.count(u8, got, "    // .client_request = r: "));
}

test "a line a patch needs, gone from std or there twice, is said so by name" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const verify = "try prev_cert.verify(subject, now_sec);";
    const src = try fakeStd(a, files[0]);
    var missed: Missed = undefined;
    // Gone, as when std moves the chain walk into a function of its own.
    const gone = try std.mem.replaceOwned(u8, a, src, verify, "try verifyChain(subject);");
    try std.testing.expectError(error.PatchFound, patch(a, files[0], gone, &missed));
    try std.testing.expectEqualStrings(verify, missed.edit.line);
    try std.testing.expectEqual(0, missed.found);
    try std.testing.expectEqualStrings(why_chain, missed.edit.why);
    // Twice: the patch would check one place and not the other.
    const twice = try std.mem.concat(a, u8, &.{ src, "\n    ", verify, "\n" });
    try std.testing.expectError(error.PatchFound, patch(a, files[0], twice, &missed));
    try std.testing.expectEqual(2, missed.found);
    // Any other file of std's is not this one.
    try std.testing.expectError(error.PatchFound, patch(a, files[1], "const x = 1;\n", &missed));
}
