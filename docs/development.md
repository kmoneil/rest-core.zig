[Docs](README.md) › Development

# Development

## Build steps

```sh
zig build test                          # unit, property and fuzz-corpus tests, zig fmt --check, lint and complexity
zig build test --seed=0x1234            # the same, with other pseudo-random inputs
zig build test-unit                     # the tests alone, compiling nothing else
zig build test-release                  # the unit tests, the library built ReleaseSafe and ReleaseFast
zig build test -Dfuzz-runner --fuzz     # coverage-guided fuzzing, LLVM backend
zig build test -Dtest-filter=fuzz       # only the fuzz properties
zig build fmt                           # format the Zig
zig build docs                          # the API reference, into zig-out/docs
zig build lint                          # zigvet: code that compiles but is wrong
zig build complexity                    # gnarl --check: complexity against complexity.baseline
zig build security                      # the security suite, and its catalog checked against it
```

`lint` and `complexity` run programs from the PATH (CONTRIBUTING.md says
how to install them). Both print nothing on a clean tree. gnarl reads
`complexity.zon`, which names its classes and the gnarl release the code
is judged by, and `complexity.baseline`, which holds the functions over a
critical limit today at their numbers: two in `tools/test_runner.zig`,
std's runner carried unchanged. A ported file joins `complexity.zon`'s hot
list in the change that ports it, and a baselined function it brings comes
with its gcp.zig numbers.

## The security catalog

[test/security/CATALOG.md](../test/security/CATALOG.md) lists every known
attack on an HTTP and REST client, with its source, the defence, the test
that proves it and a status. `zig build test` runs
`tools/security_catalog.zig` over it: a covered row whose test is gone, or
a test named `security: ...` under test/security that no row names, fails
the build. A change that adds a defence turns its row covered with the
test; one that finds a defence missing adds a `gap` row.

Every test build runs under `tools/test_runner.zig`: Zig 0.17's test
runner with `std.debug` waiting uncancelably, carried from gcp.zig, whose
docs/zig-std-workarounds.md says why.

## Where the code came from

Most of this library is gcp.zig's `src/core`, moved here. Each file that
came from there starts with a line naming the gcp.zig file and commit, so a
fix made in either can be carried to the other.

| File here | From gcp.zig | At |
| --- | --- | --- |
| tools/test_runner.zig | tools/test_runner.zig | eae944c |
| src/owned.zig | src/core/owned.zig | eae944c |
| src/WipingAllocator.zig | src/core/WipingAllocator.zig | eae944c |
| src/change.zig | src/core/change.zig | eae944c |
| src/base64.zig | src/core/base64.zig | eae944c |
| src/CountingWriter.zig | src/core/CountingWriter.zig | eae944c |
| src/query.zig | src/core/query.zig | eae944c |
| src/logging.zig | src/core/logging.zig | eae944c |
| src/testing.zig | src/core/testing.zig (less FakeSigner and retryInfoBody) | eae944c |
| src/timestamp.zig | src/core/timestamp.zig | eae944c |
| src/http_date.zig | src/core/retry_after.zig (its HTTP-date parser and tests) | eae944c |
| src/transport.zig | src/core/transport.zig | eae944c |
| src/TokenProvider.zig | src/core/TokenProvider.zig | eae944c |
| src/StaticToken.zig | src/core/StaticToken.zig | eae944c |
| src/retry.zig | src/core/retry.zig | eae944c |
| src/retry_after.zig | src/core/retry_after.zig (its header readers and tests) | eae944c |
| src/loop.zig, src/loop_test.zig | src/core/rpc.zig | eae944c |
| src/Diagnostics.zig | src/core/errors.zig (its Diagnostics and truncateUtf8) | eae944c |
| src/PreparedRequest.zig | src/core/PreparedRequest.zig | eae944c |

Changed on the way: base64's and logging's headers no longer assume
Google; query.zig gained `isDotSegment`, `hasDotSegment` and the checked
writers, which refuse a dot-segment from input; testing.zig holds only
ByteGen, `repeat`, `fuzzBytes`, FakeClock, WipeChecker and RefuseOver, the
fakes arriving with the transport and the token seam. timestamp.zig's
`parse` refuses a well-formed instant outside 0001 to 9999 in UTC, which
gcp.zig's returns and its `format` then asserts on. http_date.zig is
retry_after.zig's HTTP-date parser in a file of its own, with `parse` and
`format` added. transport.zig uses `std.compress.flate` directly (gcp.zig's
flate.zig was a re-export); a time limit the `Io` cannot run is
`error.ConcurrencyUnavailable` rather than an untimed request; and
`checkUrl`, `checkRequestHeaders` and `checkFraming` refuse a URL std would
send other than as written, a header the transport owns, and a response
framed two ways (docs/zig-std-workarounds.md). Its tests' CRC-32C became
std's CRC-32, and testing.zig gained `ScriptedServer`, whose body hash
changed the same way. TokenProvider.zig drops `quotaProject` (gcp.zig's
`x-goog-user-project` goes through the request loop's hook instead) and
renames two errors, `RefreshTokenInvalid` to `ReauthenticationRequired`
and `MetadataUnavailable` to `CredentialSourceUnavailable`; its
`isValidToken` is the transport's `isValidBearerToken`, which the
transport now holds every bearer token to. testing.zig gained
`FakeTokenProvider`, without `quota_project`, and then `FakeTransport` and
`FaultTransport`, whose `body_crc32c` became `body_crc32`, std's CRC-32.
retry.zig's `isRetryable` covers the transport's failures only; the
statuses gcp.zig retries (RESOURCE_EXHAUSTED, INTERNAL, UNAVAILABLE,
DEADLINE_EXCEEDED) are its hook's. retry_after.zig reads only headers,
`x-ms-retry-after-ms` added: `serverDelayMs` takes no body or arena, the
`google.rpc.RetryInfo` delay and its `durationMs` stay Google's, and
`Asked` lost its `retry_info` form. loop.zig is rpc.zig's engine made
generic over a cloud's hook (`Engine(log_scope, Cloud)`): Google's error
body, RetryInfo and the gRPC statuses it retries are gcp.zig's hook's, the
quota project became the engine's `headers`, a 401 is known by its status
rather than by Google's error name, and the per-call `decode_error` and
engine `classify_refusal` became one engine `refusal`. Its tests run under
two hooks written in the tests, Google's shape and Azure ARM's. It also
refuses a path that does not start with `/`, bounds the body a hook reads,
and adds `pathOnOrigin`. Diagnostics.zig is errors.zig's with `status`
named `code`, a request id, and `format`, which escapes control bytes.

tools/security_catalog.zig came from yaml.zig (9fe87e9), not gcp.zig.
