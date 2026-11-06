//! rest-core: the cloud-neutral half of a REST client for Zig 0.17.
//!
//! An HTTP transport over `std.http.Client` with a per-request timeout,
//! retries with full-jitter backoff that honour a server's own delay,
//! `Owned` results, a token-provider seam, RFC 3339 and RFC 1123 time, RSA
//! signing, a wiping allocator, and fakes for tests. Each cloud's library
//! adds its endpoints, error bodies, retry classes and credentials.
//!
//! The parts arrive one by one, ported from gcp.zig's `core`.

/// The HTTP seam: implement `transport.Transport` to send requests another
/// way, or to fake the server in tests. `transport.HttpTransport` is the
/// `std.http.Client` one, with a per-request time limit.
pub const transport = @import("transport.zig");

/// The request loop every module of a cloud runs: credentials, retries,
/// the server's delay, and its refusal read by the cloud's hook.
pub const loop = @import("loop.zig");
pub const Engine = loop.Engine;

/// Details of the most recent failed call: status, the cloud's code, the
/// server's message, its request id and delay.
pub const Diagnostics = @import("Diagnostics.zig");

/// The seam through which a cloud's modules get bearer tokens.
pub const TokenProvider = @import("TokenProvider.zig");
pub const StaticToken = @import("StaticToken.zig");

pub const RetryPolicy = @import("retry.zig").RetryPolicy;
pub const isRetryable = @import("retry.zig").isRetryable;

/// A refused response's own retry delay: `Retry-After`, `retry-after-ms`
/// and `x-ms-retry-after-ms`, read into milliseconds.
pub const retry_after = @import("retry_after.zig");

/// Base64, as JSON APIs carry bytes fields.
pub const base64 = @import("base64.zig");

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

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("CountingWriter.zig");
    _ = @import("Diagnostics.zig");
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
    _ = @import("testing.zig");
    _ = @import("timestamp.zig");
    _ = @import("transport.zig");
}
