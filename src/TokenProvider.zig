// From gcp.zig src/core/TokenProvider.zig at eae944c.
//! Supplies OAuth bearer tokens, in the `std.mem.Allocator` interface shape:
//! a pointer plus a table of functions. A service module asks for a token
//! before each request. Where the token comes from (a pasted string, a
//! metadata service, a CLI's login, a client secret) is the provider's
//! business.
//!
//! Thread-safety is the implementation's. One provider is often shared by
//! several clients, so `getToken` and `invalidate` can be called from
//! several tasks at once: a provider shared that way must be thread-safe,
//! and its doc should say so. `StaticToken` is. A token is handed out as a
//! copy in the caller's arena, and goes with it.

const TokenProvider = @This();

const std = @import("std");
const Allocator = std.mem.Allocator;
const transport = @import("transport.zig");
const test_util = @import("testing.zig");

ptr: *anyopaque,
vtable: *const VTable,

/// Every way getting a token can fail. Closed, so that a service's own error
/// set can include it and callers can still switch on every case.
pub const Error = error{
    /// The provider could not produce a usable token, for a reason not
    /// listed here.
    TokenUnavailable,
    /// The credential was revoked or has expired, and nothing but signing
    /// in again fixes it: a dead refresh token, as after
    /// `gcloud auth application-default login` lapses or `az login` must be
    /// run again. gcp.zig's `RefreshTokenInvalid`.
    ReauthenticationRequired,
    /// The token endpoint refused the request for a reason other than a
    /// credential that needs signing in again.
    TokenEndpointRejected,
    /// The source of credentials on this machine did not answer: no metadata
    /// service (GCE's metadata server, Azure's IMDS), or no identity attached
    /// to the workload. gcp.zig's `MetadataUnavailable`.
    CredentialSourceUnavailable,
    /// A token response lacked a usable token or lifetime.
    InvalidTokenResponse,
} || transport.Error;

/// What a provider implements.
pub const VTable = struct {
    /// Returns a bearer token valid for at least the next request, copied
    /// into `arena`: the copy cannot change under the caller, even when the
    /// provider replaces its cached token. The provider owns caching and
    /// refresh. `scopes` is advisory: most credentials fix their scopes when
    /// they are issued.
    getToken: *const fn (
        ptr: *anyopaque,
        io: std.Io,
        arena: Allocator,
        scopes: []const []const u8,
    ) Error![]const u8,
    /// Drops any cached token, so the next `getToken` fetches a new one.
    /// Services call this after an HTTP 401.
    invalidate: *const fn (ptr: *anyopaque) void,
    /// Headers this credential adds to each request it authorizes, such as
    /// the project Google bills a user credential's quota to
    /// (`x-goog-user-project`), or null: none. They go only where the token
    /// goes, after the call's own and before the engine's, a call's header
    /// of the same name winning. Checked when the credential is made, so
    /// asking cannot fail; valid as long as the provider is.
    headers: ?*const fn (ptr: *anyopaque) []const transport.Header = null,
};

/// A token valid for at least the next request, copied into `arena`.
pub fn getToken(self: TokenProvider, io: std.Io, arena: Allocator, scopes: []const []const u8) Error![]const u8 {
    return self.vtable.getToken(self.ptr, io, arena, scopes);
}

/// Drops a cached token, after a 401 says it died early, so the next
/// `getToken` fetches a fresh one.
pub fn invalidate(self: TokenProvider) void {
    self.vtable.invalidate(self.ptr);
}

/// The headers this credential adds to each request it authorizes, or none.
pub fn headers(self: TokenProvider) []const transport.Header {
    const f = self.vtable.headers orelse return &.{};
    return f(self.ptr);
}

/// Whether `token` can go into an HTTP header: non-empty, visible ASCII.
/// A token read from a command's output often ends in a newline. The
/// transport refuses any other (`error.InvalidRequestHeader`), so a token
/// from a hostile token endpoint cannot add a header to the request.
pub fn isValidToken(token: []const u8) bool {
    return transport.isValidBearerToken(token);
}

test "isValidToken rejects what would break the header" {
    try std.testing.expect(isValidToken("ya29.a0AfB_byC-9x"));
    try std.testing.expect(!isValidToken(""));
    try std.testing.expect(!isValidToken("ya29.abc\n"));
    try std.testing.expect(!isValidToken("a b"));
    try std.testing.expect(!isValidToken("abc\r\nX-Injected: 1"));
    try std.testing.expect(!isValidToken("t\xc3\xa9"));
}

fn isValidTokenProperty(_: void, input: []const u8) !void {
    // The rule, stated independently: non-empty, every byte visible ASCII.
    var visible = input.len > 0;
    for (input) |c| visible = visible and c >= '!' and c <= '~';
    try std.testing.expectEqual(visible, isValidToken(input));
    // So an accepted token can never end the header line or start another.
    if (isValidToken(input)) try std.testing.expect(std.mem.indexOfAny(u8, input, "\r\n\x00 \t") == null);
}

test "fuzz isValidToken: accepts exactly non-empty visible ASCII" {
    try test_util.fuzzBytes({}, isValidTokenProperty, .{ .corpus = &.{
        "ya29.a0AfB_byC-9x",
        "",
        " ",
        "!",
        "~",
        "\x7f",
        "abc\r\nX-Injected: 1",
        "t\xc3\xa9",
        "tok\x00en",
    } });
}

test "the wrappers pass their arguments through" {
    const Recording = struct {
        arena_seen: ?Allocator = null,
        scopes_seen: []const []const u8 = &.{},
        invalidated: usize = 0,

        fn provider(self: *@This()) TokenProvider {
            return .{ .ptr = self, .vtable = &.{
                .getToken = getTokenFn,
                .invalidate = invalidateFn,
            } };
        }
        fn getTokenFn(ptr: *anyopaque, io: std.Io, arena: Allocator, scopes: []const []const u8) Error![]const u8 {
            _ = io;
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.arena_seen = arena;
            self.scopes_seen = scopes;
            return arena.dupe(u8, "ya29.recorded");
        }
        fn invalidateFn(ptr: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.invalidated += 1;
        }
    };

    var recording: Recording = .{};
    const p = recording.provider();
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const scopes: []const []const u8 = &.{"https://www.googleapis.com/auth/cloud-platform"};

    try std.testing.expectEqualStrings("ya29.recorded", try p.getToken(std.testing.io, arena.allocator(), scopes));
    try std.testing.expectEqual(arena.allocator().ptr, recording.arena_seen.?.ptr);
    try std.testing.expectEqual(scopes.ptr, recording.scopes_seen.ptr);
    p.invalidate();
    p.invalidate();
    try std.testing.expectEqual(2, recording.invalidated);
}
