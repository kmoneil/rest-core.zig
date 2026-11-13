//! rest-core: the cloud-neutral half of a REST client for Zig 0.17.
//!
//! An HTTP transport over std's HTTP client, its TLS client patched, with a
//! per-request timeout, retries with full-jitter backoff that honour a
//! server's own delay, `Owned` results, a token-provider seam, RFC 3339
//! and RFC 1123 time, RSA signing, a wiping allocator, and fakes for
//! tests. Each cloud's library adds its endpoints, error bodies, retry
//! classes and credentials.
//!
//! Most of it began in gcp.zig's `core`; docs/development.md says what
//! came from where, and what changed on the way.

/// The HTTP seam: implement `transport.Transport` to send requests another
/// way, or to fake the server in tests. `transport.HttpTransport` is the
/// one over std's HTTP client, with a per-request time limit and the TLS
/// checks std leaves out.
pub const transport = @import("transport.zig");

/// The request loop every module of a cloud runs: credentials, retries,
/// the server's delay, and its refusal read by the cloud's hook.
pub const loop = @import("loop.zig");
/// `loop.Engine`.
pub const Engine = loop.Engine;

/// Details of the most recent failed call: status, the cloud's code, the
/// server's message, its request id and delay.
pub const Diagnostics = @import("Diagnostics.zig");

/// The seam through which a cloud's modules get bearer tokens.
pub const TokenProvider = @import("TokenProvider.zig");
/// A provider of one fixed token, such as a CLI prints.
pub const StaticToken = @import("StaticToken.zig");

/// How many attempts a call makes, and the backoff between them.
pub const RetryPolicy = @import("retry.zig").RetryPolicy;
/// Whether a transport failure is worth another attempt.
pub const isRetryable = @import("retry.zig").isRetryable;

/// A refused response's own retry delay: `Retry-After`, `retry-after-ms`
/// and `x-ms-retry-after-ms`, read into milliseconds. Like `RetryPolicy`
/// and `http_date`, it needs neither the transport nor the loop.
pub const retry_after = @import("retry_after.zig");

/// A request as a client would send it, built without sending it, for a
/// caller that shows a write before making it.
pub const PreparedRequest = @import("PreparedRequest.zig");

/// RSA with a private key held here: PKCS#1 v1.5 and PSS signatures from a
/// digest, and public keys read and written as SubjectPublicKeyInfo.
pub const rsa = @import("rsa.zig");

/// Base64, as JSON APIs carry bytes fields.
pub const base64 = @import("base64.zig");

/// A result and the arena that holds it, freed by one `deinit`.
pub const Owned = @import("owned.zig").Owned;

/// What an update does to a setting that can be taken away: `.keep`,
/// `.set`, or `.clear`.
pub const Change = @import("change.zig").Change;

/// An allocator that wipes memory before freeing it, for secrets.
pub const WipingAllocator = @import("WipingAllocator.zig");

/// A writer that counts what passes through it to another writer.
pub const CountingWriter = @import("CountingWriter.zig");

/// Percent-encoding for request paths, and a query-string builder.
pub const query = @import("query.zig");

/// RFC 3339 timestamps, as JSON APIs send them.
pub const timestamp = @import("timestamp.zig");

/// HTTP dates (RFC 9110): read in all three formats, written as IMF-fixdate.
pub const http_date = @import("http_date.zig");

/// Logging under each module's own scope, captured in test builds.
pub const logging = @import("logging.zig");

/// Fakes and property-test helpers, for tests only.
pub const testing = @import("testing.zig");

/// References every pub declaration, down into the namespaces that hold
/// them, to `depth`. `std.testing.refAllDecls` is shallow, so a pub fn
/// inside `HttpTransport`, `query` or `rsa` was compiled only when some
/// test happened to reach it. Generic functions (`Engine`, `Owned`) are
/// referenced, not instantiated.
fn refAllDeclsDeep(comptime T: type, comptime depth: u32) void {
    inline for (comptime @import("std").meta.declarations(T)) |name| {
        if (@TypeOf(@field(T, name)) == type) {
            const Inner = @field(T, name);
            if (depth > 1) switch (@typeInfo(Inner)) {
                .@"struct", .@"enum", .@"union", .@"opaque" => refAllDeclsDeep(Inner, depth - 1),
                else => {},
            };
        } else {
            _ = &@field(T, name);
        }
    }
}

test "every pub declaration compiles, namespaces' too" {
    refAllDeclsDeep(@This(), 4);
}

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("CountingWriter.zig");
    _ = @import("Crc32.zig");
    _ = @import("Diagnostics.zig");
    _ = @import("PreparedRequest.zig");
    _ = @import("loop.zig");
    _ = @import("StaticToken.zig");
    _ = @import("TokenProvider.zig");
    _ = @import("WipingAllocator.zig");
    _ = @import("base64.zig");
    _ = @import("change.zig");
    _ = @import("http_date.zig");
    _ = @import("logging.zig");
    _ = @import("owned.zig");
    _ = @import("query.zig");
    _ = @import("retry.zig");
    _ = @import("retry_after.zig");
    _ = @import("rsa.zig");
    _ = @import("testing.zig");
    _ = @import("timestamp.zig");
    _ = @import("transport.zig");
}
