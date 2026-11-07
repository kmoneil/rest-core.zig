# Changelog

Until 1.0, minor versions may break the API; each entry says how.

## Unreleased

- Fixed: when the caller's arena ran out after a response's head (copying
  its headers, or the 64 KiB window a gzip or deflate body needs),
  `HttpTransport` kept the connection, and releasing the request had
  std drain the rest of the body with its own chunked decoder: with no
  bound, and on a chunk size near 2^64 a panic in a safe build and
  undefined in ReleaseFast. The connection is closed now, as on every
  other failure after the head (security catalog RESP-02).

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
