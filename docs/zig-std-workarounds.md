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
  permanent `NetworkFailure` once a request is under way (making the
  connection is below, under "Found here").
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
  capacity is spent, until the OS's TCP connect timeout ends it.
  `Io.Threaded`'s default `async_limit` is the CPU count less one (none on
  a one-CPU machine), so docs/essentials.md tells a client to set it.
  Connecting around std is not done: `Connection.Tls.create` is private
  in 0.17.1, so it would mean carrying std's TLS connection setup.
  Documented, not worked around: test/security/CATALOG.md, CONN-08.
- `std.Io.Threaded`'s connect calls `connect()` again when a signal
  interrupts it, and on macOS the second call answers EISCONN at once
  while the first goes on in the kernel. std takes that for a programmer's
  bug (Codeberg ziglang/zig#31391, open): a Debug build panics ("programmer
  bug caused syscall error: ISCONN"), and a release build closes the socket,
  which was fine, and returns `error.Unexpected`. The signal can be
  `Io.Threaded`'s own cancel, arriving late, since `HostName.connect`
  cancels the addresses that lose its race. Reproduced on 0.17.1 under
  ReleaseSafe, every run: a connect to an address that never answers, sent
  one SIGIO after 200 ms. The transport reads `error.Unexpected` from
  making a connection, where nothing has been sent, as a dropped
  connection, so it is retried. The panic is out of its reach: a program
  that talks to a network for long on a Mac should not be a Debug build.
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
  bearer token. It also reads no extension but the subjectAltName, so a
  certificate's extended key usage, the nameConstraints of a CA above it
  and a critical extension it does not process go unheeded.
- `std.crypto.Certificate`'s DER reader checks no length against the
  bytes it is given, and `std.crypto.tls.Client` parses every certificate
  a server sends before it checks any. A certificate that claims more
  bytes than it holds, a subjectAltName whose names do, an empty BIT
  STRING last in a certificate, or an issuer's RSA key that runs past
  itself is read out of bounds: a panic in a safe build. No upstream
  issue found. The client also copies an RSA signature into a buffer the
  size of the server's key without checking its length
  (`PKCS1v1_5Signature.fromBytes` and `PSSSignature.fromBytes`; PR
  ziglang/zig#36695, open), so a longer one writes past a buffer on the
  stack in ReleaseFast. Found by ekur; reproduced on 0.17.1, and master is
  the same.
- Both are worked around the only way open, as ekur does: `std.http.Client`
  builds its TLS client in a private function, so the transport carries
  std's TLS and HTTP clients in deps/zig-tls, patched, each signer held
  to being a CA and each certificate to its stated limits
  (src/tls_chain.zig), each certificate checked before std parses it
  (src/tls_cert.zig), and an RSA signature held to its key's length.
  tools/zig_tls.zig writes the copies from the installed Zig and `zig
  build test` fails when they differ from that, so a Zig upgrade shows
  which patch std has made unneeded (deps/zig-tls/VENDORED.md).
  test/security/CATALOG.md, CONN-10 to CONN-13, and cards t31 and t78;
  test/security/std_tls_test.zig holds std's own client to the crashes.
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
