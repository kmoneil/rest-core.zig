# Changelog

Until 1.0, minor versions may break the API; each entry says how.

## Unreleased

- `rsa.parsePemInto(pem, key: *PrivateKey)`: parses into the caller's
  key, writing its secret parts straight there, never into a copy on the
  way, and wipes it on any error. `parsePem`, which returns the key by
  value, can leave a copy in the stack it used (seen in ReleaseFast);
  it stays, and its doc points here (security catalog SECRET-04).
- docs/essentials.md: a stalled connect can outlive a request's time
  limit while the `Io`'s `async_limit` is spent (std's ziglang/zig#37192),
  and `std.Io.Threaded`'s default is the CPU count less one, none on a
  one-CPU machine; set `async_limit` when making the `Io` (security
  catalog CONN-08, now with a test that a cancel holds given room).

## 0.3.0 (2026-11-07)

The fixes from an audit of the whole library (2026-11-06), each with a
test that failed before it. Breaks, each marked below: a cloud's hook
that broke one of `Engine`'s rules no longer compiles; `FakeTransport`
refuses what `HttpTransport` refuses, and answers a 204, 304 or 1xx
with no body; and a wrapper that copies `Call`'s or `StreamCall`'s
fields across has three more to copy. gcp.zig's and azure.zig's suites
pass against it but for that last.

- `Engine` checks a cloud's hook when it binds it: each of the four
  declarations `pub`, `RefusalError` a named set rather than `anyerror`
  (which made every consumer's error set `anyerror`), and none of its
  names but `OutOfMemory` one the transport or the token provider
  returns too (a 408 called `TimedOut` was retried as the transport's).
  A hook that breaks one fails to compile there, with a message saying
  which, where it failed at a use site deep in the loop, or not at all.
  `OutOfMemory` from `refusal` now ends the call, as it did from
  `bodyDelayMs`; it went to `retryable` before. Breaks: a hook that broke
  a rule. gcp.zig's and azure.zig's keep them.
- `testing.FakeTransport` refuses what `HttpTransport` refuses before it
  connects: a URL that would go out other than as written
  (`error.InvalidEndpoint`), and a header HTTP cannot carry or the
  transport writes itself, such as Content-Length, Host or
  Accept-Encoding (`error.InvalidRequestHeader`). It took them before, so
  a test passed on a request production refused. A refused request is
  not recorded and does not use a scripted reply. The check is public,
  `transport.checkRequest`, for a `Transport` of one's own. Breaks: a
  test that sent such a request through the fake now gets the error.
- Fixed: `testing.FakeTransport` answered unlike `HttpTransport` in three
  ways. A 204, 304 or 1xx came back with the canned body (`"{}"` by
  default) and streamed it into a writer sink; such an answer ends at
  its head, so no body now, buffered or to a sink. A GET, HEAD or DELETE
  was recorded with the body it held, which is never sent; it is
  recorded with none. And `send` ignored `cut_after`, though `Canned`
  says a buffered reply cut short fails; it returns `cut_error` now.
  Breaks: a test that read a 204's or 304's body from the fake.
- `Call.timeout_ms`, and `StreamCall.wipe` and `StreamCall.error_body_out`:
  each entry had a field the other lacked for no reason the streaming
  path gives, so a buffered call could not set its own time limit, a
  streaming one could not wipe its token and URL, nor read a refused
  body (which is buffered whatever the sink). A test now holds the two
  to the same field under the same name, and lists what only one has and
  why. A wrapper that copies `Call`'s fields across gets one more;
  docs/essentials.md's test for one now compares types as well as names.
- Fixed: when the caller's arena ran out after a response's head (copying
  its headers, or the 64 KiB window a gzip or deflate body needs),
  `HttpTransport` kept the connection, and releasing the request had
  std drain the rest of the body with its own chunked decoder: with no
  bound, and on a chunk size near 2^64 a panic in a safe build and
  undefined in ReleaseFast. The connection is closed now, as on every
  other failure after the head (security catalog RESP-02).
- Fixed: a canceled call could be retried, and its canceler wait out
  every retry. `HttpTransport` reported a cancel that landed while it
  drained a compressed body that would not decode as a dropped
  connection, which is retried, and the loop asked `retryable` about
  `error.Canceled` too, so a widened one sent the call again. The
  transport returns `error.Canceled` there now, and the loop never
  retries it, whatever `retryable` says (security catalog RETRY-04).
- Fixed: a call canceled during the wait before a retry left
  `Diagnostics` describing the failure before it (an HTTP 503, say),
  though the call returned `error.Canceled` and `Diagnostics` says a
  cancellation has no status. It says Canceled now.
- Fixed: `Call.wipe` left the bearer token readable after the call.
  `HttpTransport` formats `Bearer <token>` into the arena it is given,
  which `execute` passes as the caller's response arena, so the token
  sat beside the result for as long as the caller kept it. The transport
  zeroes that header once the request is sent. std's own copy, in its
  pooled connection's write buffer, is out of reach; `wipe`'s doc says
  so (security catalog SECRET-05).
- Fixed: `StreamCall.restart` was asked on every transport failure with
  a writer sink, before the engine had decided to retry, so on a last
  attempt, a failure not retried, or any `executeStreamBody` failure the
  sink was emptied and the part of the body a resume counts on was lost.
  It is asked only once a retry is decided.
- Fixed: two slips in a `Transport` of your own were undefined in
  ReleaseFast. `executeStream` took `error.ReadFailed` and
  `error.EndOfStream` as unreachable when no streamed body was given,
  though `StreamError` allows them on any request; they are now the
  transport's own short body, `error.ConnectionResetByPeer`, retried as
  one. `Transport.sendStream` through a vtable with no `sendStream` (a
  fake that sets `send` only) panics in every mode, where it unwrapped a
  null.
- Fixed: `loop.pathOnOrigin` passed a path with a dot-segment, so
  `https://h.example/v1/../admin` (or `%2e%2e`) under a base of
  `https://h.example/v1` came back as `/../admin`, which a normalizing
  server serves outside `/v1`. Such a path, its dots written or encoded,
  is refused now. `Engine.base_url`'s doc says a path may follow the
  origin, as the loop has always taken one.
- Fixed: `Diagnostics.print` could end a message that overflowed its
  buffer in half a UTF-8 sequence, though `message()` promises a
  boundary, and formatting a message from `d.message()` aliased the
  buffer it was writing (a panic in a safe build, undefined in
  ReleaseFast). It formats apart from the buffer, then cuts and copies.
- Fixed: `rsa.parsePem` took a private key whose public exponent ran
  past 32 bits, which `PublicKey.fromSpki` refuses, and `writeSpki` sizes
  its output for. A 4096-bit key with a 22-byte or longer exponent then
  made `publicKey().writeSpki` panic in a safe build and spin for ever in
  ReleaseFast. Such a key is `error.UnsupportedKey` now (security catalog
  RSA-04).
- Fixed: `rsa.parsePem` called a key too big for it (an 8192-bit one)
  `InvalidPrivateKey`, which a caller reports as a file that is not a
  PEM key at all; it is `UnsupportedKey`, as `ParseError` says. And
  `base64.decode` kept what it allocated when the text was not base64,
  which leaked under any allocator but an arena; it frees it now.
- Fixed: three stack buffers that held an RSA secret were never wiped: a
  refused key's `d` (`parsePem` copied it, then failed on the primes),
  the columns of (p - 1)(q - 1) before their carries, and the signing
  blind. Each is zeroed when its function returns. `parsePem` returns
  its key by value, and in ReleaseFast a copy is left in the stack it
  used, which nothing here can reach; its doc and security catalog
  SECRET-04 now say so.
- Fixed: an RSA signature that failed its own check (`SignatureFailed`,
  as a fault in the key or the arithmetic makes) was already written into
  the caller's `out`: the faulty signature a fault attack wants. It is
  written only once it verifies (security catalog RSA-02).
- Fixed: `rsa.PrivateKey.signDigest` and `signPss` asserted that the
  digest was the hash's length, and signing asserted that `out` held the
  key's length. In ReleaseFast a message passed in place of its digest
  wrapped the encoding's offset and wrote past its buffer. Each is
  `error.SignatureFailed` now, as the verify side already returned an
  error for the same mismatch.
- Fixed: `timestamp.format` and `http_date.format` held their instant to
  the years 1 to 9999 with an assert alone, so a caller's far-future
  sentinel overflowed the fixed buffer into `unreachable` in ReleaseFast.
  An instant past either end is written as that end now.
- Fixed: `testing.FakeClock.sleepMs` read a sleep never made from
  memory never set, so `expectEqual(0, clock.sleepMs(1))` could pass
  after the code stopped sleeping; it panics now. A deadline already
  past moved the clock back and recorded a negative sleep; it returns at
  once and records none, as a real `Io` does.
- Fixed: `testing.ScriptedServer` copied a request's head into its
  2 KiB slot with no bound, so a long bearer token (an Entra ID JWT runs
  past 2 KiB) panicked in a safe build and wrote past the slot in
  ReleaseFast; the head is kept to the slot like the body, and a head
  line may run to 16 KiB. It never hangs a test: a cancel while it
  lingers ends the run (the linger swallowed it, and the run went back
  to accept for good), and a client that closes before its next request
  ends that connection, not the run, so the next connection is served.
  `request()` and `url()` panic with a message where they read out of
  bounds or reached `unreachable`.
- Fixed: in a test build, `logging.Scoped(...).capture.text()` past its
  64 KiB returned the whole buffer, its tail bytes never written in that
  test, so a "never contains" check could fail, or a "contains" one
  pass, on stale bytes. A line that does not fit now takes no room, and
  `capture.dropped` counts such lines.

## 0.2.1 (2026-11-06)

- Fixed: `loop.pathOnOrigin` compared bytes, so a URL with its scheme's
  default port written out (`https://prices.azure.com:443/...`, as
  Azure's Retail Prices API writes every next page) or a host in another
  case was refused as another origin, and a list followed through the
  loop stopped at its first page. It compares origins now, as RFC 3986
  6.2.3 normalizes them; userinfo, another port and an empty port are
  still refused, and the reading agrees with std.Uri's.

## 0.2.0 (2026-11-06)

From the trials azure.zig and gcp.zig ran on 0.1.0. One break, the HEAD
method's below.

- `transport.Method.HEAD`, for Blob Storage's Get Blob Properties and
  the like. `HttpTransport` sends it with no body and reads none back,
  whatever the answer's Content-Length or Transfer-Encoding says, and the
  connection stays in step for the next request (security catalog
  RESP-14). `testing.FakeTransport` answers a HEAD with its scripted
  status and headers and drops the body. Breaks: a `switch` over
  `transport.Method` with no `else` needs a `.HEAD` prong.
- `loop.Call.head_out`: each attempt's status and headers, a success's
  too, so `execute` reads a long-running write's 202 and the poll URL it
  names without the streaming entry. `loop.Call.content_type`: a body
  other than JSON, such as a form, through the loop.
- Fixed: with retries, `StreamCall.head_out` kept an earlier attempt's
  head, pointing into the response the retry had reset, when the latest
  attempt got no response. It is null then, as documented.
- `Diagnostics.setCorrelationId` and `correlationId`: a second id beside
  the request id, for ARM's `x-ms-correlation-request-id`; `format` writes
  `(request r-1, correlation c-1)`. `logging.escaped(text)`, a `{f}` that
  writes a server's text into a log line with its control bytes as `\xNN`,
  as `Diagnostics.format` does.
- `Engine.execute` and `Engine.stream` share one attempt and one retry
  decision, so the two entries cannot drift; behaviour is otherwise
  unchanged.

## 0.1.0 (2026-11-06)

- The repository: build, test runner, and the empty `rest_core` module.
- `zig build test` runs zigvet and gnarl (0.7.0, named in
  `complexity.zon`): a zigvet finding, or a function newly over its
  complexity limit or worse than `complexity.baseline`, fails it.
- `Owned`, `WipingAllocator`, `Change`, `base64`, `CountingWriter`,
  `query` and `logging`, from gcp.zig's core, and in `testing` the
  property-test runner `fuzzBytes`, `ByteGen`, `repeat`, `FakeClock`,
  `WipeChecker` and `RefuseOver`.
- `query.isDotSegment`, `hasDotSegment`, `writeCheckedSegment`,
  `writeCheckedStrictSegment` and `writeCheckedPath`: a resource name or
  path from input that is, or holds, `.` or `..` is `error.DotSegment`
  rather than a request a normalizing server sends to the parent resource.
- `timestamp`: RFC 3339, from gcp.zig. `parse` refuses a well-formed
  instant outside 0001 to 9999 in UTC (the year 0000, or an offset that
  carries the time past either end), so whatever it returns, `format` can
  write; gcp.zig's took such text, and its `format` then asserted.
- `http_date`: HTTP dates (RFC 9110 5.6.7), read in all three of its
  formats and written as IMF-fixdate, for Retry-After, Date and
  `x-ms-date`.
- `transport`: the `Transport` seam and `HttpTransport` over
  `std.http.Client`, from gcp.zig, with a per-request time limit, streamed
  bodies, and the std workarounds in docs/zig-std-workarounds.md. Unlike
  gcp.zig's:
  - a time limit the `Io` cannot run (no second task) is
    `error.ConcurrencyUnavailable`, never an untimed request;
  - a URL with a control byte, space or backslash, userinfo, or a
    percent-encoded host is `error.InvalidEndpoint`, since std would send
    a CR and LF in the path into the request line;
  - a caller's Host, Content-Length, Transfer-Encoding, Connection, the
    other hop-by-hop headers and Accept-Encoding, and a second
    Authorization or Content-Type, are `error.InvalidRequestHeader`;
  - a response with Transfer-Encoding beside Content-Length, or a
    Content-Length that is not digits, is `error.HttpProtocolError` and
    its connection is closed.
- `TokenProvider`, `StaticToken` and `testing.FakeTokenProvider`, from
  gcp.zig, without `quotaProject`. Breaking against gcp.zig:
  `RefreshTokenInvalid` is `ReauthenticationRequired`, and
  `MetadataUnavailable` is `CredentialSourceUnavailable`. The transport
  refuses a bearer token that is not non-empty visible ASCII
  (`error.InvalidRequestHeader`), since std would write CR and LF in one
  into the request.
- The transport refuses a compressed body with content after its stream (a
  second gzip member, bytes after a zlib stream), `error.HttpProtocolError`:
  gcp.zig's decoded the first member and dropped the rest in silence.
- The transport holds a gzip or deflate body to its own trailer (gzip's
  CRC-32 and length, zlib's Adler-32), which std's decoder reads and never
  checks: a body that does not match is `error.HttpProtocolError`.
- `Engine(log_scope, Cloud)`, the request loop, from gcp.zig's `rpc`: a
  token per attempt and a fresh one after a 401, retries with full-jitter
  backoff and the server's delay as a floor (headers and, through the
  cloud's hook, the body), a retry window, wiping, and logs without the
  query. A cloud supplies `RefusalError`, `refusal`, `retryable` and
  `bodyDelayMs`. Unlike gcp.zig's: no quota project (the engine's
  `headers`), a path that does not start with `/` is
  `error.InvalidEndpoint`, a hook reads at most 64 KiB of a refused body,
  and `loop.pathOnOrigin` follows a server's URL only on the engine's
  origin.
- `PreparedRequest.fromCall`, from gcp.zig: what a `loop.Call` would send,
  method, URL and body, for a preview; it refuses a path the loop refuses.
- `Diagnostics`: status, the cloud's `code` (gcp.zig's `status`), the
  message, a request id, the server's delay, and `format`, which escapes
  the server's control bytes.
- `rsa`, from gcp.zig: PKCS#1 v1.5 and PSS signatures from a digest, PEM
  private keys (PKCS#8 and PKCS#1) parsed without allocating, and public
  keys as SubjectPublicKeyInfo. On Zig 0.17.1 std.crypto.ff's
  exponentiation branches on its exponent in ReleaseFast and ReleaseSafe
  (Codeberg ziglang/zig#37023), so signing blinds it: each signature raises
  to `d + k * phi(n)` for a fresh random `k`. Breaking against gcp.zig:
  `sign`, `signDigest` and `signPss` take an `Io` (for `k`) after the key;
  a key keeps its totient, checked against its modulus when parsed; and
  `wipe` zeroes the private exponent and the totient.
- `testing.FakeTransport` (answers from a script, records every request)
  and `testing.FaultTransport` (wraps a transport and injects faults), from
  gcp.zig. A recorded streamed body's checksum is `body_crc32`, std's
  CRC-32, where gcp.zig's was `body_crc32c`. examples/testing_with_fakes.zig
  shows them, and `zig build test` runs it.
- `RetryPolicy`, `isRetryable` and `retry_after`, from gcp.zig. Unlike
  gcp.zig's, `isRetryable` covers only the transport's failures, a
  server's statuses being each cloud's to judge; `retry_after` reads
  `x-ms-retry-after-ms` too, and only headers: `serverDelayMs(H, headers,
  received_at)` takes no body, since a delay in one (Google's `RetryInfo`)
  is the cloud's to read. `retry_after.larger` joins the two. `H` is the
  header type, std's or a client's own, so `retry`, `retry_after` and
  `http_date` serve a client with its own HTTP stack (ekur asked).
- `TokenProvider` gains an optional `headers`: what a credential adds to
  each request it authorizes, as gcp.zig's quota project. The loop sends
  them with the token only, merged by name (the call's own, then the
  credential's, then the engine's), and `Engine.send_credential_headers`
  turns them off. A call's header no longer goes out beside an engine
  header of the same name.
- `testing.ScriptedServer`: a loopback server that answers with scripted
  bytes and records what it was sent.
- The README, docs/essentials.md and three examples (the transport, a
  cloud's hook driving the loop, and testing with the fakes), each run by
  `zig build test`, which also holds the documents' copies of them to the
  files and checks every relative link.
- A security catalog, test/security/CATALOG.md: every known attack on an
  HTTP and REST client, each with its defence and the work that will
  prove it, checked against the tests by `zig build test`. SECURITY.md
  says how to report a vulnerability.
- `zig build test-tls`, run in CI: TLS against `openssl s_server` with a
  CA made for the run. A certificate no trusted root signed, one for
  another name, and one expired are refused; a head under std's 8 KiB is
  read, and one past a TLS record is refused, never a crash. It holds std
  to three faults of its TLS client, each test failing once std fixes
  it: a certificate signed by one that is not a CA is taken (SECURITY.md,
  Known gaps), and neither a handshake cut into small records nor TLS
  1.2 with an ECDSA key gets through.
