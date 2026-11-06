# Changelog

Until 1.0, minor versions may break the API; each entry says how.

## 0.1.0 (unreleased)

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
- `testing.FakeTransport` (answers from a script, records every request)
  and `testing.FaultTransport` (wraps a transport and injects faults), from
  gcp.zig. A recorded streamed body's checksum is `body_crc32`, std's
  CRC-32, where gcp.zig's was `body_crc32c`. examples/testing_with_fakes.zig
  shows them, and `zig build test` runs it.
- `RetryPolicy`, `isRetryable` and `retry_after`, from gcp.zig. Unlike
  gcp.zig's, `isRetryable` covers only the transport's failures, a
  server's statuses being each cloud's to judge; `retry_after` reads
  `x-ms-retry-after-ms` too, and only headers: `serverDelayMs(headers,
  received_at)` takes no body, since a delay in one (Google's `RetryInfo`)
  is the cloud's to read. `retry_after.larger` joins the two.
- `testing.ScriptedServer`: a loopback server that answers with scripted
  bytes and records what it was sent.
- A security catalog, test/security/CATALOG.md: every known attack on an
  HTTP and REST client, each with its defence and the work that will
  prove it, checked against the tests by `zig build test`. SECURITY.md
  says how to report a vulnerability.
