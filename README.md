# rest-core.zig

The cloud-neutral half of a REST client, for Zig 0.17.1, with no
dependencies beyond std. Each cloud's library supplies its own endpoints,
error bodies, retry classes and credentials; everything else is here, so
two such libraries do not carry two copies that drift apart.

**Status: pre-release.** Most of it has moved here from
[gcp.zig](https://github.com/kmoneil/gcp.zig)'s `core`, with its tests, and
is being tried by gcp.zig and azure.zig before a first release. RSA signing
has not moved yet.

## What is inside

- **`transport`**: the `Transport` seam, and `HttpTransport` over
  `std.http.Client`: a time limit on every request (std has none in Zig
  0.17), streamed request and response bodies, gzip and deflate checked
  against their trailers, and the refusals std leaves out: a URL with a
  control byte, a header the transport owns, a response framed two ways.
  Its TLS client is std's, carried with patches in deps/zig-tls, so a
  certificate a non-CA signed, one outside the limits its chain states,
  and a server's bytes that crash std's are refused.
  [Zig 0.17 workarounds](docs/zig-std-workarounds.md) lists each.
- **`Engine`**, the request loop: a token on every attempt and a fresh one
  after a 401, retries with full-jitter backoff where the delay a server
  asks for is the least it waits, a retry window, and `Diagnostics` for
  what went wrong. A cloud plugs in its hook: how its refusals read, which
  of them retry, and what delay its bodies carry.
- **`retry_after`** (`Retry-After`, `retry-after-ms`, `x-ms-retry-after-ms`),
  **`timestamp`** (RFC 3339) and **`http_date`** (RFC 9110's three
  formats, written as IMF-fixdate).
- **`TokenProvider`**, the seam credentials come through, and
  `StaticToken`.
- **`Owned(T)`** results, **`PreparedRequest`** previews, **`query`**
  encoding that refuses a dot-segment from input, `base64`, `Change`,
  `CountingWriter`, `logging`, and **`WipingAllocator`** for secrets.
- **`testing`**: `FakeTransport`, which answers from a script and records
  every request; `FaultTransport`, which injects faults; `FakeTokenProvider`;
  `ScriptedServer`, a loopback server; `FakeClock`; and the property-test
  runner the library's own tests use.

[Essentials](docs/essentials.md) explains each part.

## Install

Pin a release by its tag, which goes after `#`:

```sh
zig fetch --save=rest_core "git+https://github.com/kmoneil/rest-core.zig#v0.5.0"
```

It should print `resolved ref "v0.5.0"`, and the hash it saves should
name the version (`rest_core-0.5.0-...`). A tag given as `?ref=v0.5.0`
instead fetches the default branch and still saves the `?ref=`, so the
pin looks right and is not.

Then import the module in `build.zig`:

```zig
const rest_core = b.dependency("rest_core", .{}).module("rest_core");
```

## A request through the transport

<!-- example: examples/http_transport.zig -->
```zig
//! A request through the HTTP transport: one call with a time limit, the
//! body read whole. The test answers it from a loopback server, so it runs
//! anywhere.

const std = @import("std");
const rest_core = @import("rest_core");
const Transport = rest_core.transport.Transport;

/// GETs `url` with a 10-second limit; the body lives in `arena`.
fn fetch(t: Transport, arena: std.mem.Allocator, url: []const u8) ![]const u8 {
    const res = try t.send(.{ .method = .GET, .url = url, .timeout_ms = 10_000 }, arena);
    if (res.status != 200) return error.UnexpectedStatus;
    return res.body;
}

test "fetch reads a body through HttpTransport" {
    const io = std.testing.io;
    const ScriptedServer = rest_core.testing.ScriptedServer;
    var server: ScriptedServer = try .start(io, &.{"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"});
    defer server.deinit(io);
    var serving = try io.concurrent(ScriptedServer.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};

    var http: rest_core.transport.HttpTransport = .init(std.testing.allocator, io, "my-client/1.0");
    defer http.deinit();
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("hello", try fetch(http.transport(), arena.allocator(), server.url(&buf, "/greeting")));
}
```

## A cloud's hook, and the request loop over it

<!-- example: examples/cloud_hook.zig -->
```zig
//! How a cloud's library plugs into rest-core: its hook, and the request
//! loop over it. This cloud's errors read `{"error":{"code","message"}}`;
//! it retries 429 and 5xx, and its bodies carry no retry delay. The tests
//! drive the loop with a fake transport and a fake clock.

const std = @import("std");
const rest_core = @import("rest_core");
const Allocator = std.mem.Allocator;

const ExampleCloud = struct {
    pub const RefusalError = error{ NotFound, Throttled, ServerError, Refused };

    /// A refused response, read into `diagnostics`, and the error it is.
    pub fn refusal(scratch: Allocator, res: rest_core.transport.Response, diagnostics: ?*rest_core.Diagnostics) (RefusalError || Allocator.Error) {
        const Body = struct { @"error": struct { code: []const u8 = "", message: []const u8 = "" } };
        const body: ?Body = std.json.parseFromSliceLeaky(Body, scratch, res.body, .{ .ignore_unknown_fields = true }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => null,
        };
        if (diagnostics) |d| {
            d.set(res.status, if (body) |b| b.@"error".code else "", if (body) |b| b.@"error".message else res.body);
        }
        return switch (res.status) {
            404 => error.NotFound,
            429 => error.Throttled,
            500...599 => error.ServerError,
            else => error.Refused,
        };
    }

    /// Which failures are worth another attempt.
    pub fn retryable(err: anyerror, http_status: u16) bool {
        _ = http_status;
        return rest_core.isRetryable(err) or err == error.Throttled or err == error.ServerError;
    }

    /// A retry delay the body carries: none, in this cloud.
    pub fn bodyDelayMs(scratch: Allocator, body: []const u8) Allocator.Error!?u32 {
        _ = scratch;
        _ = body;
        return null;
    }
};

const Engine = rest_core.Engine(.example_cloud, ExampleCloud);

const Rig = struct {
    fake: rest_core.testing.FakeTransport,
    clock: rest_core.testing.FakeClock = .{},
    token: rest_core.StaticToken = .{ .token = "token-1" },
    diag: rest_core.Diagnostics = .{},

    fn engine(rig: *Rig) Engine {
        return .{
            .gpa = std.testing.allocator,
            .io = rig.clock.io(),
            .transport = rig.fake.transport(),
            .base_url = "https://api.example.com",
            .auth_scope = "https://api.example.com/.default",
            .token_provider = rig.token.provider(),
            .diagnostics = &rig.diag,
        };
    }
};

test "a throttled call waits what the server asked, then succeeds" {
    var rig: Rig = .{ .fake = .init(std.testing.allocator, &.{
        .{ .respond = .{ .status = 429, .headers = &.{.{ .name = "Retry-After", .value = "2" }}, .body = "{\"error\":{\"code\":\"Throttled\",\"message\":\"slow down\"}}" } },
        .{ .respond = .{ .body = "{\"id\":\"w-1\"}" } },
    }) };
    defer rig.fake.deinit();
    var response: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer response.deinit();

    const engine = rig.engine();
    engine.begin();
    const body = try engine.execute(&response, .{ .method = .GET, .path = "/v1/widgets/w-1" });
    try std.testing.expectEqualStrings("{\"id\":\"w-1\"}", body);
    // It slept the two seconds the 429 asked for, then tried again.
    try std.testing.expectEqual(2_000, rig.clock.sleepMs(0));
    try std.testing.expectEqual(2, rig.fake.requests.items.len);
}

test "a refusal not worth retrying comes back at once, with what the server said" {
    var rig: Rig = .{ .fake = .init(std.testing.allocator, &.{
        .{ .respond = .{ .status = 404, .body = "{\"error\":{\"code\":\"WidgetNotFound\",\"message\":\"no widget w-2\"}}" } },
    }) };
    defer rig.fake.deinit();
    var response: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer response.deinit();

    const engine = rig.engine();
    engine.begin();
    try std.testing.expectError(error.NotFound, engine.execute(&response, .{ .method = .GET, .path = "/v1/widgets/w-2" }));
    try std.testing.expectEqual(1, rig.fake.requests.items.len);
    try std.testing.expectEqualStrings("WidgetNotFound", rig.diag.code());
    try std.testing.expectEqualStrings("no widget w-2", rig.diag.message());
}
```

## Testing a client

A client sends through a `Transport`, so its tests hand it a
`testing.FakeTransport`:

<!-- example: examples/testing_with_fakes.zig -->
```zig
//! Testing a client with rest-core's fakes: the client sends through a
//! `Transport`, and the test hands it a `FakeTransport` that answers from a
//! script and records every request. README.md shows this file.

const std = @import("std");
const rest_core = @import("rest_core");
const Transport = rest_core.transport.Transport;

/// A client call: GET /v1/widgets/{id} with a bearer token. The id may come
/// from input, so it goes through a checked segment writer.
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
server acted on it.

## Security

[SECURITY.md](SECURITY.md) says how to report a vulnerability.
[test/security/CATALOG.md](test/security/CATALOG.md) lists every known
attack on an HTTP and REST client, each with the test that proves the
defence, the work that will add it, or the reason it does not apply, and
`zig build test` holds the catalog to the tests.

## Documentation

- [Essentials](docs/essentials.md): each part, and how a cloud plugs in.
- [Development](docs/development.md): building, testing, fuzzing, and
  where each file came from.
- [Zig 0.17 workarounds](docs/zig-std-workarounds.md): what std gets wrong,
  and what the transport does about it.
- [CHANGELOG.md](CHANGELOG.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT; see [LICENSE](LICENSE).
