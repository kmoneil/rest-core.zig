[Docs](README.md) › Zig 0.17 workarounds

# Zig 0.17 standard library issues handled here

Each of these is worked around here, and covered by a regression test in
`src/transport.zig` unless it says otherwise. Most came from gcp.zig's
transport, which met them first (its docs/zig-std-workarounds.md); the
last group was found while porting it. Each was checked against Zig
0.17.1's source.

## From gcp.zig

- A chunk size near 2^64 overflows `std.http`'s chunked decoder (a panic
  in a safe build), so the transport decodes chunked bodies itself.
- A body that ends before its `Content-Length` is reported as complete;
  the transport checks, and reports a dropped connection.
- The gzip decoder stops before the last chunk, which kept connections
  from being reused and made complete bodies look truncated.
- `[::1]` is not a host name to std's HTTP client, so an emulator at
  `[::1]:8085` could not be reached; the transport connects to an IPv6
  literal itself.
- The TLS certificate clock is read once per client; the transport
  reloads it hourly and after a TLS failure.
- Streaming a body larger than the connection's read buffer into a writer
  with no buffer of its own trips an assertion in std's readers, which
  need somewhere writable; the transport passes bodies through a small
  buffer of its own.
- On Windows, std maps only the socket statuses it expects, and any other
  arrives as `error.Unexpected`. The transport reads that as a dropped
  connection and retries; on other platforms `error.Unexpected` stays a
  permanent `NetworkFailure`.
- `std.Io.Writer.Hashing.init` passes an argument to its hasher's `init`,
  which a CRC hasher's does not take; the tests call `initHasher`.
- `std.testing.allocator` records a stack trace for every allocation, and
  on macOS capturing one can swallow a task's pending cancel, after which
  the task can never be canceled. Every test build uses
  `tools/test_runner.zig`, std's runner with `std.debug` waiting
  uncancelably; see the top of that file.

## Found here

- `std.http.Client.ConnectTcpOptions.timeout` is declared and never read,
  and there is no per-request deadline at all. The transport races each
  request against a timer; where the `Io` cannot start the timer's task,
  the request is `error.ConcurrencyUnavailable` rather than sent with no
  limit (gcp.zig sends it untimed).
- `std.http.Client` writes a request's path as it is given, so a CR and LF
  in it split the request line and add a header the caller never set (the
  class of Python urllib's CVE-2019-9740). It also drops userinfo silently
  and sends a percent-encoded host in Host as written. The transport
  refuses such URLs before connecting (`checkUrl`).
- `std.http.Client` sends a caller's extra Host, Content-Length,
  Transfer-Encoding or Connection beside its own; two lengths is request
  smuggling. The transport refuses the headers it owns (`isOwnedHeader`).
- `std.http.Client` takes a response with both Content-Length and
  Transfer-Encoding (as chunked), and reads `Content-Length: +2` as 2. The
  transport refuses both and closes the connection (`checkFraming`).
- `std.compress.flate.Decompress` reads a gzip member's CRC-32 and length,
  and a zlib stream's Adler-32, and checks none of them, so a corrupted
  compressed body decodes to wrong bytes without complaint. Not yet worked
  around in the transport: the check comes when its body path is broken up
  (test/security/CATALOG.md, RESP-08).
- `std.http.Client` reads `HTTP_PROXY` and `HTTPS_PROXY` only when asked,
  and HTTPS through its proxies goes in cleartext (Codeberg
  ziglang/zig#35294). The transport never asks for proxies.
- `std.crypto.ff`'s constant-time selects compile to branches on the
  secret exponent in ReleaseFast and ReleaseSafe on x86_64 (Codeberg
  ziglang/zig#37023, fixed for 0.18 only). This concerns RSA signing, which
  is not ported yet.
