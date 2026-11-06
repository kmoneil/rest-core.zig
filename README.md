# rest-core.zig

The cloud-neutral half of a REST client, for Zig 0.17.1, with no
dependencies beyond std. Each cloud's library supplies its own endpoints,
error bodies, retry classes and credentials; everything else is here, so
two such libraries do not carry two copies that drift apart.

**Status: pre-release, nothing usable yet.** The parts are being moved here
from [gcp.zig](https://github.com/kmoneil/gcp.zig)'s `core`, one at a time,
each with its tests.

## What will be inside

- **Transport**: an HTTP transport over `std.http.Client`, with a
  per-request timeout (std has none in Zig 0.17), streamed request bodies,
  and header checks.
- **Retries**: full-jitter exponential backoff, where a delay the server
  asks for (`Retry-After` in seconds or as an HTTP date, `retry-after-ms`)
  is the least it waits.
- **Owned results**, previews of a request built without sending it, and a
  token-provider seam for credentials.
- **Time**: RFC 3339 and RFC 1123 timestamps.
- **RSA signing**, PKCS#1 v1.5 and PSS, and an allocator that wipes memory
  before freeing it, for secrets.
- **Fakes for tests**: a transport that answers from a script and records
  every request, and a fake token provider.

## Install

Not released yet. Once it is, a consumer pins it in `build.zig.zon` and
imports the `rest_core` module:

```zig
const rest_core = b.dependency("rest_core", .{}).module("rest_core");
```

## License

MIT; see [LICENSE](LICENSE).
