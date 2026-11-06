//! rest-core: the cloud-neutral half of a REST client for Zig 0.17.
//!
//! An HTTP transport over `std.http.Client` with a per-request timeout,
//! retries with full-jitter backoff that honour a server's own delay,
//! `Owned` results, a token-provider seam, RFC 3339 and RFC 1123 time, RSA
//! signing, a wiping allocator, and fakes for tests. Each cloud's library
//! adds its endpoints, error bodies, retry classes and credentials.
//!
//! Nothing is here yet: the parts arrive one by one, ported from gcp.zig's
//! `core`.

test {
    @import("std").testing.refAllDecls(@This());
}
