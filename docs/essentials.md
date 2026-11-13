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
  ziglang/zig#37192), until the OS's TCP connect timeout ends it (about
  75 s on macOS, about 2 minutes on Linux). `std.Io.Threaded`'s default
  `async_limit` is the CPU count less one, which is none at all on a
  one-CPU machine, so set it when you make the `Io`:
  `std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited })`, or a limit
  with room for a DNS lookup and a connect per address the host returns
  (std takes up to 32 at a time) beyond your program's own `async` tasks.
- **TLS** is std's: the chain checked against the system's roots, the
  name against the host, the dates against the clock, with no option to
  turn any of it off. Known holes, std's: Zig 0.17.1 takes a certificate
  signed by one that is not a CA (Codeberg ziglang/zig#35877), so a man in
  the middle holding any publicly trusted certificate can pass for any
  host; and a malformed certificate or an RSA signature longer than the
  server's key makes it read or write out of bounds, a panic in a safe
  build. So build a program that talks to a network ReleaseSafe, not
  ReleaseFast, until std fixes them. SECURITY.md says more.
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
  connection closed); a head past 8 KiB (std's `read_buffer_size`); a
  buffered body past `max_response_bytes` (32 MiB, after decoding, so a
  gzip bomb stops there); a compressed body that does not match its own
  trailer; a body short of its length (`error.ConnectionResetByPeer`).
- **HEAD** is answered with a status and headers and no body: the
  Content-Length or Transfer-Encoding on the answer describes the body a
  GET would get, and none is read, so a blob's size is its
  `header("content-length")`. A refusal is headers alone too, as Blob
  Storage's `x-ms-error-code`. Through the loop, `Call.head_out` (or
  `executeStream`'s result) has the headers; `execute` returns only the
  body, which for a HEAD is empty.
- **Redirects** are never followed: a 3xx comes back to the caller, and the
  token stays with its host. **Proxies** are never used.

## The request loop

`Engine(log_scope, Cloud)` is the loop every module of a cloud runs. A
client fills in an engine (allocator, `Io`, transport, base URL, the scope
to ask tokens for, the token provider, retry policy, time limit,
`Diagnostics`) and calls `execute` with a `Call` (method, path, body and
its content type, headers), `executeStream` with a `StreamCall`, or
`executeDiscard` when the body is not needed. Each call:

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
   `Diagnostics`, for a caller that schedules its own next try. A canceled
   call returns `error.Canceled`, never retried, whatever `retryable` says.

A call that must not be repeated once it may have reached the server, as a
create, passes `retryable = loop.unsentOnly`. `retry_window_ms` bounds how
late a retry may begin; `wipe` wipes the call's memory, the token included,
when it returns (std's HTTP client keeps its own copy of the request head,
the token in it, in its pooled connection's buffer, out of the loop's
reach); `error_body_out` keeps a refused body for a caller that
reads more of it than `Diagnostics` does; `head_out` hands out each
attempt's status and headers, a success's too, as a long-running write's
202 and the `Location` or `Azure-AsyncOperation` it names (null when the
latest attempt got no response, and from `executeDiscard`); `timeout_ms`
sets one attempt's time limit in place of the engine's, 0 none. A
`StreamCall` has each of these too, and adds `sink`, `accept_encoding` and
`restart` for a body that goes to a writer. The loop logs
the method, the path without its query, the status and the time, never a
token.

A library may wrap `Call` and `StreamCall` in types of its own, as gcp.zig
does for its per-call quota project, and copy their fields across. A field
a later release adds (0.2.0's `head_out` and `content_type`) then never
reaches its modules until it copies that too, and nothing fails. A test
beside the wrapper catches it on the bump, a field's type as well as its
name. A wrapper may narrow an optional to a default of its own, as
gcp.zig's `retryable` is never null but Google's rule, so the test takes
`T` where rest-core has `?T`:

```zig
test "every rest_core.loop.Call field has a counterpart in Call" {
    inline for (@typeInfo(rest_core.loop.Call).@"struct".field_names) |name| {
        try std.testing.expect(@hasField(Call, name));
        const Ours = @FieldType(Call, name);
        const Theirs = @FieldType(rest_core.loop.Call, name);
        try std.testing.expect(Ours == Theirs or ?Ours == Theirs);
    }
}
```

It sees a field the wrapper lacks, not one it has and does not copy
across. Beside it, a test that builds the wrapper's `Call` with every field
set off its default, converts it, and checks each field arrived, as
gcp.zig's does for its `neutralCall`, catches that.

`PreparedRequest.fromCall` takes the `loop.Call` such a wrapper builds, so
a preview stays byte for byte what the call sends.

A URL a server gives (a next page, an upload session, an operation to
poll) is followed through `loop.pathOnOrigin(engine.base_url, url)`, which
returns its path only when it is on the engine's own origin, so the token
cannot go where a server points it. Origins compare as RFC 3986
normalizes them: the scheme and host in any case, and the scheme's default
port written out (`https://prices.azure.com:443/...`, as Azure's Retail
Prices API writes its next pages) the same as none. Userinfo, another
port, and an empty port are refused.

## Signing each attempt

An engine can sign each attempt in place of sending a bearer token, as
Azure Storage's Shared Key and AWS's SigV4 do: set `engine.signer` to a
`loop.Signer`. The loop calls it once an attempt's headers are final, on
every attempt afresh, so a retry's date and signature are its own, and
sends the headers it returns, each in place of any header of the same
name. It is given a `loop.Signable`: the method, the whole URL, the
headers, the Content-Type and Content-Length the transport will send, and
the body's bytes to hash when the loop holds them (a body streamed from a
reader comes by its length alone). With a signer the token provider is
not asked and its headers are not sent, and an `unauthenticated` engine
never signs.

## A cloud's hook

The `Cloud` an engine is made with is a namespace of four declarations,
the cloud's own part of the loop. [examples/cloud_hook.zig](../examples/cloud_hook.zig)
is a whole one.

- `RefusalError`: the errors a refused response maps to. A named set, not
  `anyerror`, and none of them (`OutOfMemory` aside) a name the transport
  or the token provider returns too: a 408 called `TimedOut` would be
  retried as the transport's, a CANCELLED called `Canceled` taken for a
  cancel. gcp.zig names the latter `ServerCancelled`.
- `refusal(scratch, res, diagnostics)`: reads a refused response into
  `diagnostics` (`set`, then `setRequestId` when the cloud names a request
  id) and returns its error, or `error.OutOfMemory`, which ends the call
  as `bodyDelayMs` running out does. It sees at most
  `loop.max_hook_body` (64 KiB) of the body. An engine's own `refusal` can
  take its place, for a service whose refusals name their kind in the body.
- `retryable(err, http_status)`: whether a failure is worth another
  attempt. `isRetryable` covers the transport's failures; the statuses are
  the cloud's (Google retries RESOURCE_EXHAUSTED, INTERNAL, UNAVAILABLE and
  DEADLINE_EXCEEDED; Azure 408, 429 and 5xx).
- `bodyDelayMs(scratch, body)`: a retry delay the body carries (Google's
  `google.rpc.RetryInfo`), or null. The loop reads the headers' delay
  itself.

Each must be `pub`. `Engine` checks all of this when it is made, so a hook
that breaks a rule fails to compile there, with a message saying which.

Headers a cloud sends on every call go in the engine's `headers`; headers
that belong to a credential, such as gcp.zig's `x-goog-user-project`, come
from the token provider's `headers`.

## Diagnostics

Zig errors carry no payload, so a client takes `&diagnostics` and fills it
when a call fails: the HTTP status, the cloud's code ("NOT_FOUND",
"ResourceNotFound"), the server's message, its request id and correlation
id (ARM sends both: `x-ms-request-id` and `x-ms-correlation-request-id`,
which its support asks for first), and the delay it asked for. `format`
writes it on one line with the server's control bytes escaped, safe for a
log or a terminal; `message()`, `code()` and the ids hand the bytes as they
came. A module that logs a server's text itself, a request id at debug
level say, writes it through `logging.escaped` (`{f}`), which escapes the
same way.

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
IMF-fixdate. `retry_after.serverDelayMs(H, headers, received_at)` reads
a refused response's `Retry-After` (seconds, or a date against the
response's own `Date`), `retry-after-ms` and `x-ms-retry-after-ms`,
saturating at `maxInt(u32)` milliseconds. `H` is the header type, std's
or a client's own: `RetryPolicy`, `retry_after` and `http_date` need
neither the transport nor the loop, for a client with an HTTP stack of
its own.

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
included. It refuses what `HttpTransport` refuses before connecting, a URL
or a header it would not send, with the same error, so a test cannot pass
on a request production refuses. A `Transport` of one's own can do the
same through `transport.checkRequest`. `FaultTransport` wraps another transport and cuts a body, stops a
download, or loses a response. `FakeTokenProvider`, `FakeClock` (whose
sleeps are recorded, so a test of retries takes no time), `ScriptedServer`
(a loopback server for code that needs a socket), `WipeChecker` and
`RefuseOver` (allocators for testing wiping and large allocations), and
`fuzzBytes` (the property-test runner, which also feeds
`zig build test --fuzz`) are there for a client's tests too.
