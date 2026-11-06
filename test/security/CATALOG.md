# Security catalog

Every known attack on an HTTP and REST client, and where rest-core stands
on it: a test that proves the defence (covered), a card that will add it
(gap when the surface exists today, later when it does not yet), or the
reason it does not apply (n/a). `zig build test` checks this file against
the code (tools/security_catalog.zig): a covered row whose test is gone
fails the build, and so does a test in test/security that no row names.
After ekur's catalog and yaml.zig's.

The catalog came before the code. Each row starts `later`, naming the card
that ports or builds its surface, and that card turns it `covered` with its
tests. A defence the port finds missing becomes a `gap` row with a card.

Sources: the CWE entries that reach a client; RFC 9110 and RFC 9112; the
Zig standard library's own issues on Codeberg (ziglang/zig); and the
advisory history of comparable clients by class: libcurl, Go's net/http
and crypto/rsa, Python's requests and urllib3, Node's undici, Rust's hyper
and reqwest. CVE ids are added only once checked against NVD, GitHub's
advisory database, RustSec or the Go vulnerability database.

Test cells read `path: test name`, several joined by ` ; `. The tests under
test/security use the public API only, as a hostile server or caller
reaches it: raw bytes from a scripted server over a socket where the attack
is on the wire, in process where it is not. They run with `zig build test`
and, in ReleaseSafe and ReleaseFast, `zig build test-release`. A row may
cite a test in src/ where the defence is internal. Status is `covered`,
`gap tNN`, `later tNN` or `n/a: why`.

## Responses from a server

| ID | Attack | Source | Defense | Test | Status |
|---|---|---|---|---|---|
| RESP-01 | A body framed two ways (Content-Length with Transfer-Encoding), two Content-Lengths, or one that is malformed or does not fit | CWE-444, CWE-190; RFC 9112 6.3 | A response whose framing is ambiguous or whose length is not digits that fit is refused, not guessed at | - | later t10 |
| RESP-02 | Chunk sizes near 2^64, negative or malformed, or past the body's limit | CWE-130, CWE-190 | The transport decodes chunked bodies itself, since std's decoder panics on a size near 2^64 in a safe build (a gcp.zig workaround); a size is bounded by the body's limit before anything is buffered | - | later t10 |
| RESP-03 | A body that ends before its Content-Length, taken as complete | CWE-130, CWE-20 | A short body is a dropped connection, never a short success; std reports it complete (a gcp.zig workaround) | - | later t10 |
| RESP-04 | Bare LF, bare CR and obsolete line folding in a response's head | CWE-444; RFC 9112 2.2 and 5.2 | What std.http.Client accepts is checked in the port, and anything ambiguous refused | - | later t10 |
| RESP-05 | A head that never ends, or 1xx heads without end before the response | CWE-400, CWE-770 | A cap on the head with any 1xx heads counted in, and the request's timeout | - | later t10 |
| RESP-06 | A body too big for memory, by Content-Length, by chunks, or a connection that never closes | CWE-400, CWE-770 | `max_response_bytes` (32 MiB in gcp.zig), then `error.ResponseTooLarge`; a streamed body goes to the caller's writer | - | later t10 |
| RESP-07 | A gzip or deflate body that expands into a bomb | CWE-409 | The body's limit counts decoded bytes, not bytes on the wire | - | later t10 |
| RESP-08 | A corrupted gzip member taken as good data | CWE-354 | std's flate leaves each member's CRC-32 and length unchecked (gcp.zig's docs/zig-std-workarounds.md); the transport checks them, or asks for no compression | - | later t10 |
| RESP-09 | A head line longer than a TLS record, which makes std's TLS reader assert and takes the process down | CWE-617, CWE-400 | The response is read through a buffer of the transport's own, as ekur's client does (its FETCH-08), once std.http.Client is shown to have the same fault | - | later t10 |
| RESP-10 | A server's error text with escape sequences or line breaks, written raw to a log or a terminal through `Diagnostics` | CWE-117, CWE-150 | `Diagnostics` escapes control bytes when it is formatted | - | later t22 |
| RESP-11 | Keys a server chose to collide in a hash map keyed by its text: header names, an error body's object keys | CWE-407 | No std hash map is keyed by a server's text without a seed; an error body is bounded before the cloud's hook parses it | - | later t22 |
| RESP-12 | Parser bugs found by fuzzing: the head, chunked, gzip and Retry-After readers | CWE-20 | Fuzz targets with seed corpora, run by `zig build test` and fuzzed with `-Dfuzz-runner --fuzz` | - | later t10 |

## Requests rest-core sends

| ID | Attack | Source | Defense | Test | Status |
|---|---|---|---|---|---|
| REQ-01 | CR, LF or NUL in a header's name or value: header injection and request splitting | CWE-113, CWE-93 | `isValidHeaderName` and `isValidHeaderValue` refuse it before anything is sent | - | later t10 |
| REQ-02 | A caller setting a header the transport owns: Host, Content-Length, Transfer-Encoding, Connection | CWE-444 | Refused before anything is sent | - | later t10 |
| REQ-03 | A resource name from input that escapes its place in the URL: `../`, `%2F`, `?`, `#`, `@` | CWE-74, CWE-22 | `query` percent-encodes path segments and query values, with a test for each character that could move the request elsewhere | - | later t8 |
| REQ-04 | A URL two parsers read differently, or one carrying CR or LF into the request line: userinfo, a backslash, whitespace, control bytes, a percent-encoded host | CWE-436, CWE-93, CWE-20 | Refused before anything is sent | - | later t10 |

## The connection

| ID | Attack | Source | Defense | Test | Status |
|---|---|---|---|---|---|
| CONN-01 | A server that accepts the connection and then stalls or trickles, holding the caller | CWE-400 | `timeout_ms` races each request against a timer; a race that cannot start is `error.ConcurrencyUnavailable`, never an untimed request | - | later t10 |
| CONN-02 | A forged, self-signed, expired or misnamed certificate | CWE-295, CWE-297 | std's TLS checks the chain against the system's roots and the name against the host, and nothing turns it off; the TLS clock is read again hourly and after a failure (a gcp.zig workaround) | - | later t10 |
| CONN-03 | Plain http where https was meant | CWE-319 | https unless the call names plain http, as an emulator needs | - | later t10 |
| CONN-04 | A redirect that carries the Authorization header to another host | CWE-200, CWE-522 | The transport follows no redirect (`redirect_behavior = .unhandled`): a 3xx comes back to the caller | - | later t10 |
| CONN-05 | A bearer token sent to a URL a server gave (a Location, a next-page link, an upload session) on another origin | CWE-522, CWE-200 | The loop attaches the token only to the origin it was set up for | - | later t22 |
| CONN-06 | A request resent on a stale pooled connection after the server may have acted on it | CWE-837; Codeberg ziglang/zig#37195 | A dropped connection is retried, and resent only when the cloud's hook says the request is idempotent | - | later t22 |
| CONN-07 | HTTPS through a proxy sent in cleartext, and proxies taken from the environment | CWE-319, CWE-200; Codeberg ziglang/zig#35294 | The transport sets no proxy and reads no proxy variable | - | later t10 |
| CONN-08 | A cancel lost by `Io.Threaded`, taking a request's timeout with it | CWE-400; Codeberg ziglang/zig#37192 | Reproduced first; then a test, and a timer that does not depend on a single cancel | - | later t10 |
| CONN-09 | Server-side request forgery: a URL from untrusted input that reaches this machine, the private network or a metadata service | CWE-918 | n/a | - | n/a: endpoints are set by the program, never taken from a request's input, and the metadata services at 169.254.169.254 must stay reachable; a program that fetches a user's URL needs a guard of its own, as ekur's client has |

## Retries

| ID | Attack | Source | Defense | Test | Status |
|---|---|---|---|---|---|
| RETRY-01 | A Retry-After built to stall or overflow: huge, negative, malformed, an HTTP-date in year 9999, a `retry-after-ms` past u64 | CWE-400, CWE-190 | Read saturating at maxInt(u32) milliseconds, a malformed one ignored; a delay past `max_backoff_ms` returns the failure to the caller, the delay in `Diagnostics`, rather than sleeping on it | - | later t13 |
| RETRY-02 | A write retried after the server may already have applied it: a duplicate POST | CWE-837 | The cloud's hook says what may be retried, and a non-idempotent request is not sent again once its bytes went out, unless the server's answer says it did nothing | - | later t22 |
| RETRY-03 | Retries with no bound on their total time | CWE-400 | `max_attempts` caps the attempts and each has its timeout; the docs show how to bound the whole call | - | later t13 |

## Secrets

| ID | Attack | Source | Defense | Test | Status |
|---|---|---|---|---|---|
| SECRET-01 | A token, the Authorization header or a URL's query written to a log | CWE-532 | Log lines carry methods, hosts, paths, statuses, counts, sizes and timings, never a token or the query | - | later t8 |
| SECRET-02 | A token in an error, in `Diagnostics` or in a request preview | CWE-200, CWE-532 | `Diagnostics` holds no request header; `PreparedRequest` shows Authorization redacted | - | later t15 |
| SECRET-03 | A secret left in memory after it is freed, or in the old copy of a block that moved | CWE-226, CWE-244 | `WipingAllocator` zeroes a block before freeing it, and refuses to shrink or move one; `testing.WipeChecker` catches a block freed unwiped | - | later t8 |
| SECRET-04 | An RSA private key left on the stack or in a buffer after signing | CWE-226 | The key is decoded on the stack, without allocating, and wiped | - | later t14 |

## RSA

| ID | Attack | Source | Defense | Test | Status |
|---|---|---|---|---|---|
| RSA-01 | The secret exponent's timing, in release builds | CWE-208, CWE-385; Codeberg ziglang/zig#37023 | On Zig 0.17.1, LLVM compiles std.crypto.ff's masked selects into branches on the exponent in ReleaseFast and ReleaseSafe; fixed for 0.18 (PR #37025), not backported. The port carries the fix, blinds, or records the gap, proven with a Valgrind taint test on a ReleaseFast build | - | later t14 |
| RSA-02 | A fault during signing that leaks the key through one bad signature | Boneh, DeMillo and Lipton (1997); Lenstra's attack on CRT | Signing uses d without CRT, and every signature is verified against the public key before it is returned | - | later t14 |
| RSA-03 | A forged PKCS#1 v1.5 signature accepted by a loose parse of its encoding (the exponent-3 class) | CWE-347 | Verification compares the whole expected encoding and parses nothing out of it | - | later t14 |
| RSA-04 | Hostile bytes in a PEM, PKCS#8, PKCS#1 or SubjectPublicKeyInfo key | CWE-125, CWE-787, CWE-190 | DER is read with every length checked against what holds it, and fuzzed | - | later t14 |
| RSA-05 | A PSS salt that repeats or can be predicted | CWE-330 | The salt comes from a cryptographic source; two signatures of one digest differ | - | later t14 |
| RSA-06 | Timing attacks on decryption (Bleichenbacher's 1998 oracle, Marvin) | CWE-208 | n/a | - | n/a: rest-core signs and verifies, and never decrypts |

## Time

| ID | Attack | Source | Defense | Test | Status |
|---|---|---|---|---|---|
| TIME-01 | Timestamps at the edges: years 0000 and 9999, long fractions, offsets past their limits, a 60th second | CWE-190, CWE-20 | Parsers refuse what does not fit, fuzzed with inputs drawn at the edges | - | later t9 |

## Supply chain

| ID | Attack | Source | Defense | Test | Status |
|---|---|---|---|---|---|
| SUPPLY-01 | A compromised dependency | CWE-1357 | n/a | - | n/a: there is no dependency beyond std, and a consumer pins this package by its hash |
