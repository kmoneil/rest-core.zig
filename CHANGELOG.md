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
- A security catalog, test/security/CATALOG.md: every known attack on an
  HTTP and REST client, each with its defence and the work that will
  prove it, checked against the tests by `zig build test`. SECURITY.md
  says how to report a vulnerability.
