[Docs](README.md) › Essentials

# Essentials

What each part of rest-core does, and how a cloud's library plugs in. The
examples in the [README](../README.md) run as tests.

## The transport

Every request goes through a `transport.Transport`: `send` for a body held
in memory, `sendStream` for a body read from a stream or a response written
to the caller's writer. `HttpTransport` is the `std.http.Client` one; a test
hands a client `testing.FakeTransport` instead.

- **A time limit.** `Request.timeout_ms` bounds one request; 0 is no limit.
  The limit runs on a second task, a timer raced against the request.
  Where the `Io` cannot start one (a single-threaded `Io`, or one whose
  `concurrent_limit` is spent), the request is
  `error.ConcurrencyUnavailable`, never sent untimed. One known limit: while
  the `Io`'s `async_limit` is spent, a connect that stalls can outlive the
  time limit, since std's connect loses the cancel then (Codeberg
  ziglang/zig#37192); give the `Io` async capacity to spare.
- **What it refuses before sending.** A URL with a control byte, a space or
  a backslash, userinfo, or a percent-encoded host
  (`error.InvalidEndpoint`): std would write a CR and LF in the path into
  the request line. A header HTTP cannot carry, one the transport writes
  itself (Host, Content-Length, Transfer-Encoding, Connection, the other
  hop-by-hop headers, Accept-Encoding), a second Authorization beside the
  bearer token, and a bearer token that is not visible ASCII
  (`error.InvalidRequestHeader`). A caller's own Authorization scheme, with
  no bearer token, goes as given.
- **What it refuses in a response.** One framed two ways, or with a
  Content-Length that is not digits (`error.HttpProtocolError`, the
  connection closed); a head too long; a buffered body past
  `max_response_bytes` (32 MiB, after decoding, so a gzip bomb stops
  there); a compressed body that does not match its own trailer; a body
  short of its length (`error.ConnectionResetByPeer`).
- **Redirects** are never followed: a 3xx comes back to the caller, and the
  token stays with its host. **Proxies** are never used.

## The request loop

`Engine(log_scope, Cloud)` is the loop every module of a cloud runs. A
client fills in an engine (allocator, `Io`, transport, base URL, the scope
to ask tokens for, the token provider, retry policy, time limit,
`Diagnostics`) and calls `execute` with a `Call` (method, path, body,
headers), `executeStream` with a `StreamCall`, or `executeDiscard` when the
body is not needed. Each call:

1. gets a token from the provider, and refuses one that cannot go in a
   header;
2. sends to the base URL and the call's path, which must start with `/`;
3. on a 2xx, returns the body and clears `Diagnostics`;
4. on a refusal, asks the cloud's hook what it is, and keeps what the
   server said in `Diagnostics`;
5. after a 401, drops the cached token and tries once more with a fresh
   one, even for a call that never retries, since the server refused before
   acting;
6. retries what the hook (or the call's own `retryable`) says may be
   retried, up to `RetryPolicy.max_attempts`, waiting a full-jitter backoff
   or the delay the server asked for, whichever is longer. A server delay
   past `max_backoff_ms` is not waited: the call returns with the delay in
   `Diagnostics`, for a caller that schedules its own next try.

A call that must not be repeated once it may have reached the server, as a
create, passes `retryable = loop.unsentOnly`. `retry_window_ms` bounds how
late a retry may begin; `wipe` wipes the call's memory, the token included,
when it returns; `error_body_out` keeps a refused body for a caller that
reads more of it than `Diagnostics` does. The loop logs the method, the
path without its query, the status and the time, never a token.

A URL a server gives (a next page, an upload session, an operation to
poll) is followed through `loop.pathOnOrigin(engine.base_url, url)`, which
returns its path only when it is on the engine's own origin, so the token
cannot go where a server points it.

## A cloud's hook

The `Cloud` an engine is made with is a namespace of four declarations,
the cloud's own part of the loop. [examples/cloud_hook.zig](../examples/cloud_hook.zig)
is a whole one.

- `RefusalError`: the errors a refused response maps to.
- `refusal(scratch, res, diagnostics)`: reads a refused response into
  `diagnostics` (`set`, then `setRequestId` when the cloud names a request
  id) and returns its error, or `error.OutOfMemory`. It sees at most
  `loop.max_hook_body` (64 KiB) of the body. An engine's own `refusal` can
  take its place, for a service whose refusals name their kind in the body.
- `retryable(err, http_status)`: whether a failure is worth another
  attempt. `isRetryable` covers the transport's failures; the statuses are
  the cloud's (Google retries RESOURCE_EXHAUSTED, INTERNAL, UNAVAILABLE and
  DEADLINE_EXCEEDED; Azure 408, 429 and 5xx).
- `bodyDelayMs(scratch, body)`: a retry delay the body carries (Google's
  `google.rpc.RetryInfo`), or null. The loop reads the headers' delay
  itself.

Headers a cloud sends on every call go in the engine's `headers`; headers
that belong to a credential, such as gcp.zig's `x-goog-user-project`, come
from the token provider's `headers`.

## Diagnostics

Zig errors carry no payload, so a client takes `&diagnostics` and fills it
when a call fails: the HTTP status, the cloud's code ("NOT_FOUND",
"ResourceNotFound"), the server's message, its request id, and the delay it
asked for. `format` writes it on one line with the server's control bytes
escaped, safe for a log or a terminal; `message()` and `code()` hand the
bytes as they came.

## Credentials

`TokenProvider` is a pointer and a table of functions: `getToken` returns a
token copied into the caller's arena, valid for the next request, and
`invalidate` drops a cached one after a 401. Where tokens come from is the
provider's business; `StaticToken` returns one it was given. Its errors
include `ReauthenticationRequired` (only signing in again fixes it) and
`CredentialSourceUnavailable` (no metadata service answered).

A credential may also add headers to every request it authorizes (the
vtable's optional `headers`), as Google's user credentials name the project
billed for quota in `x-goog-user-project`. The loop sends them only where
it sends the token, after the call's own headers and before the engine's,
a header the call names already winning; `send_credential_headers = false`
leaves them off and keeps the token. The transport holds them to the rules
any header meets.

## Time

`timestamp.parse` and `format` read and write RFC 3339, from 0001 to 9999
in UTC; whatever `parse` returns, `format` can write. `http_date` reads all
three of RFC 9110's date formats, as a recipient must, and writes
IMF-fixdate. `retry_after.serverDelayMs` reads a refused response's
`Retry-After` (seconds, or a date against the response's own `Date`),
`retry-after-ms` and `x-ms-retry-after-ms`, saturating at `maxInt(u32)`
milliseconds.

## Memory

A call's result comes back as `Owned(T)`, the value with the arena that
holds it; one `deinit` frees both, and `initWiping` makes an arena that
zeroes what it held. `WipingAllocator` zeroes every block before freeing
it, and never shrinks or moves one, which would leave a copy behind.

## Paths and queries

`query` percent-encodes path segments and query values. A name that comes
from input goes through `writeCheckedSegment`, `writeCheckedStrictSegment`
or `writeCheckedPath`, which refuse a dot-segment (`.` or `..`): a server
that normalizes the path would send it to the parent resource.

## Testing

`testing.FakeTransport` answers from a script (a status, headers and body,
or a transport error) and records every request, headers and body
included. `FaultTransport` wraps another transport and cuts a body, stops a
download, or loses a response. `FakeTokenProvider`, `FakeClock` (whose
sleeps are recorded, so a test of retries takes no time), `ScriptedServer`
(a loopback server for code that needs a socket), `WipeChecker` and
`RefuseOver` (allocators for testing wiping and large allocations), and
`fuzzBytes` (the property-test runner, which also feeds
`zig build test --fuzz`) are there for a client's tests too.
