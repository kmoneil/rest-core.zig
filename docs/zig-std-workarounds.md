[Docs](README.md) › Zig 0.17 workarounds

# Zig 0.17 standard library issues handled here

Each of these is worked around here, and covered by a regression test in
`src/transport.zig` unless it says otherwise. Most came from gcp.zig's
transport, which met them first (its docs/zig-std-workarounds.md); the
last group was found while porting it. Each was checked against Zig
0.17.1's source.

## From gcp.zig

- A chunk size near 2^64 overflows `std.http`'s chunked decoder (a panic
  in a safe build), so the transport decodes chunked bodies itself. It
  also closes a connection it gives up on after the head, since
  releasing the request would drain the rest with std's decoder.
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
- `std.http.Client` writes an Authorization value as it is given, so a
  bearer token with CR and LF in it, from a hostile or broken token
  endpoint, adds a header to the request. The transport holds every token
  to non-empty visible ASCII (`isValidBearerToken`).
- `std.http.Client` sends a caller's extra Host, Content-Length,
  Transfer-Encoding or Connection beside its own; two lengths is request
  smuggling. The transport refuses the headers it owns (`isOwnedHeader`).
- `std.http.Client` takes a response with both Content-Length and
  Transfer-Encoding (as chunked), and reads `Content-Length: +2` as 2. The
  transport refuses both and closes the connection (`checkFraming`).
- `std.compress.flate.Decompress` reads a gzip member's CRC-32 and length,
  and a zlib stream's Adler-32, and checks none of them, so a corrupted
  compressed body decodes to wrong bytes without complaint. The transport
  hashes and counts what it decodes, on the buffered and the streamed path
  alike, and refuses a body that does not match its trailer
  (`TrailerCheck`).
- `std.Io.Group.async` runs a task inline once an `Io.Threaded`'s
  `async_limit` is spent, and then drops the `error.Canceled` it returns
  (Codeberg ziglang/zig#37192, open; reproduced on 0.17.1). std's
  `HostName.connect`, which `std.http.Client` connects through, starts a
  group task per address, so a cancel sent during a connect can be lost,
  and the next address is tried with none pending. The transport's own
  time-limit race uses `concurrent`, which never runs inline, but a
  stalled connect can still outlive `timeout_ms` while the `Io`'s async
  capacity is spent. Not worked around: test/security/CATALOG.md, CONN-08.
- `std.http.Client` reads `HTTP_PROXY` and `HTTPS_PROXY` only when asked,
  and HTTPS through its proxies goes in cleartext (Codeberg
  ziglang/zig#35294). The transport never asks for proxies.
- `std.crypto.ff`'s constant-time selects compile to branches on the
  secret exponent in ReleaseFast and ReleaseSafe on x86_64 (Codeberg
  ziglang/zig#37023, fixed for 0.18 only). `rsa` blinds its exponent:
  each signature raises to `d + k * phi(n)` for a fresh random `k`, so the
  branches see another exponent every time.
- `std.crypto.tls.Client` takes a certificate signed by one that is not a
  CA (Codeberg ziglang/zig#35877 and #37353, open; the fix, PR #37354,
  not merged; reproduced on 0.17.1). It checks each certificate against
  the next by signature and issuer alone, never basicConstraints' cA flag
  or path length, nor keyUsage. So anyone holding a certificate a trusted
  root signed, for a domain of their own, can sign one for any host, and a
  man in the middle that presents the two is trusted, and is sent the
  bearer token. `std.http.Client` builds the TLS client and verifies the
  chain itself, out of the transport's reach. Not worked around:
  test/security/CATALOG.md, CONN-10, and card t31.
- `std.crypto.tls.Client` cannot join a handshake message split across
  records, which RFC 8446 5.1 allows a server to send. Under TLS 1.3 it
  reads the record after the Certificate message into its other buffer,
  away from the start of the message that record ends, and reads bytes
  never written there (`error.TlsUnexpectedMessage`); under TLS 1.2 it
  reads each cleartext record alone. A server whose records hold whole
  handshake messages, as one of 16 KiB holds a whole flight, is reached;
  one that cuts its records small (OpenSSL's `max_send_fragment`) is not.
  No issue found upstream. Not worked around; test/tls/tls_test.zig holds
  std to it.
- `std.crypto.tls.Client` offers TLS 1.2's ECDHE_RSA suites alone, so a
  server that speaks TLS 1.2 and no later, with an ECDSA key, refuses the
  handshake (`error.TlsAlert`, handshake_failure). Google's and Azure's
  endpoints speak TLS 1.3. Not worked around; test/tls/tls_test.zig holds
  std to it.
