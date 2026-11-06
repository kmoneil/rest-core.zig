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

## Testing a client

A client sends through a `Transport`, so its tests hand it a
`testing.FakeTransport`: it answers from a script and records every
request. From [examples/testing_with_fakes.zig](examples/testing_with_fakes.zig),
which `zig build test` runs:

```zig
fn getWidget(t: Transport, arena: std.mem.Allocator, token: []const u8, id: []const u8) ![]const u8 {
    var url: std.Io.Writer.Allocating = .init(arena);
    try url.writer.writeAll("https://api.example.com/v1/widgets/");
    try rest_core.query.writeCheckedSegment(&url.writer, id);
    const res = try t.send(.{ .method = .GET, .url = url.written(), .bearer = token, .timeout_ms = 30_000 }, arena);
    if (res.status != 200) return error.NotFound;
    return res.body;
}

test "getWidget sends one GET with the token and reads the answer" {
    var fake: rest_core.testing.FakeTransport = .init(std.testing.allocator, &.{
        .{ .respond = .{ .status = 404, .body = "{\"error\":\"no such widget\"}" } },
        .{ .respond = .{ .status = 200, .body = "{\"name\":\"sprocket\"}" } },
    });
    defer fake.deinit();
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const t = fake.transport();

    try std.testing.expectError(error.NotFound, getWidget(t, arena.allocator(), "tok", "missing"));
    try std.testing.expectEqualStrings("{\"name\":\"sprocket\"}", try getWidget(t, arena.allocator(), "tok", "a/b"));

    // What the client sent, as the server would have seen it.
    const sent = try fake.request(1);
    try std.testing.expectEqual(.GET, sent.method);
    try std.testing.expectEqualStrings("https://api.example.com/v1/widgets/a%2Fb", sent.url);
    try std.testing.expectEqualStrings("tok", sent.bearer.?);
    try std.testing.expectEqual(30_000, sent.timeout_ms);
}
```

`testing.FaultTransport` wraps another transport and injects faults: a
request body cut partway, a download that stops, a response lost after the
server acted on it. `testing.ScriptedServer` is a loopback server that
answers with scripted bytes, for code that needs a real socket.

## License

MIT; see [LICENSE](LICENSE).
