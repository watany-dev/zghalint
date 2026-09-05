//! A single `std.http.Client` is kept for the whole process so its internal
//! connection pool reuses TLS/TCP connections to `api.github.com`; this
//! amortizes the ~200ms TLS handshake to a single occurrence.

const std = @import("std");
const engine = @import("engine.zig");

const Allocator = std.mem.Allocator;

var client_storage: std.http.Client = undefined;
var client_initialized: bool = false;
var client_mutex: std.Thread.Mutex = .{};

/// `allocator` must remain valid until `deinit()` returns — `std.http.Client`
/// retains it for connection pool allocations. init/deinit/fetch share a mutex
/// so the initialization flag and storage are never observed half-built.
pub fn init(allocator: Allocator) void {
    client_mutex.lock();
    defer client_mutex.unlock();
    if (client_initialized) return;
    client_storage = .{ .allocator = allocator };
    client_initialized = true;
}

pub fn deinit() void {
    client_mutex.lock();
    defer client_mutex.unlock();
    if (!client_initialized) return;
    client_storage.deinit();
    client_initialized = false;
}

pub const user_agent: []const u8 = "zghalint/0.1.0";
pub const accept_github_json: []const u8 = "application/vnd.github+json";
pub const api_version: []const u8 = "2022-11-28";

pub fn getAuthHeader(allocator: Allocator) ?[]const u8 {
    const token = std.process.getEnvVarOwned(allocator, "GITHUB_TOKEN") catch return null;
    defer allocator.free(token);
    return std.fmt.allocPrint(allocator, "Bearer {s}", .{token}) catch null;
}

pub fn writeStandardHeaders(buf: []std.http.Header, auth_value: ?[]const u8) usize {
    std.debug.assert(buf.len >= 3);
    buf[0] = .{ .name = "Accept", .value = accept_github_json };
    buf[1] = .{ .name = "X-GitHub-Api-Version", .value = api_version };
    if (auth_value) |auth| {
        buf[2] = .{ .name = "Authorization", .value = auth };
        return 3;
    }
    return 2;
}

pub const FetchError = error{
    NotInitialized,
    FetchFailed,
    NetworkDeadlineExceeded,
};

/// The client mutex is held for the duration of the call so the shared
/// `std.http.Client` remains safe even if callers are later parallelized.
pub fn fetch(
    opts: std.http.Client.FetchOptions,
) FetchError!std.http.Client.FetchResult {
    if (engine.isNetworkDeadlineExceeded()) return error.NetworkDeadlineExceeded;
    if (!client_initialized) return error.NotInitialized;
    client_mutex.lock();
    defer client_mutex.unlock();
    return client_storage.fetch(opts) catch return error.FetchFailed;
}

pub const FetchedError = FetchError || error{OutOfMemory};

pub const FetchedBody = struct {
    status: std.http.Status,
    body: []u8,
    allocator: Allocator,

    pub fn deinit(self: *FetchedBody) void {
        self.allocator.free(self.body);
        self.body = &.{};
    }
};

/// The status is left untouched rather than mapped to errors so callers keep
/// their existing branching semantics (e.g. `.ok` vs `.not_found`).
pub fn fetchAuthenticatedJson(
    allocator: Allocator,
    url: []const u8,
) FetchedError!FetchedBody {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();

    const auth_value = getAuthHeader(allocator);
    defer if (auth_value) |auth| allocator.free(auth);

    var headers_buf: [3]std.http.Header = undefined;
    const header_count = writeStandardHeaders(&headers_buf, auth_value);

    const result = try fetch(.{
        .location = .{ .url = url },
        .response_writer = &aw.writer,
        .headers = .{ .user_agent = .{ .override = user_agent } },
        .extra_headers = headers_buf[0..header_count],
    });

    const body = try aw.toOwnedSlice();
    return .{ .status = result.status, .body = body, .allocator = allocator };
}

const test_support = @import("../test_support.zig");
const testing = std.testing;

test "writeStandardHeaders without auth yields 2 entries" {
    var buf: [4]std.http.Header = undefined;
    const count = writeStandardHeaders(&buf, null);
    try testing.expectEqual(@as(usize, 2), count);
    try testing.expectEqualStrings("Accept", buf[0].name);
    try testing.expectEqualStrings(accept_github_json, buf[0].value);
    try testing.expectEqualStrings("X-GitHub-Api-Version", buf[1].name);
    try testing.expectEqualStrings(api_version, buf[1].value);
}

test "writeStandardHeaders with auth yields 3 entries" {
    var buf: [4]std.http.Header = undefined;
    const count = writeStandardHeaders(&buf, "Bearer ghp_abc");
    try testing.expectEqual(@as(usize, 3), count);
    try testing.expectEqualStrings("Authorization", buf[2].name);
    try testing.expectEqualStrings("Bearer ghp_abc", buf[2].value);
}

test "fetch returns NotInitialized when client not started" {
    if (client_initialized) return error.SkipZigTest;
    const result = fetch(.{ .location = .{ .url = "http://localhost/does-not-matter" } });
    try testing.expectError(error.NotInitialized, result);
}

test "init is idempotent and deinit resets state" {
    if (client_initialized) return error.SkipZigTest;

    init(testing.allocator);
    try testing.expect(client_initialized);
    init(testing.allocator);
    try testing.expect(client_initialized);

    deinit();
    try testing.expect(!client_initialized);
    deinit();
    try testing.expect(!client_initialized);
}

test "getAuthHeader: returns Bearer <token> when GITHUB_TOKEN set" {
    var env = try test_support.EnvGuard.set(testing.allocator, "GITHUB_TOKEN", "ghp_mock_token");
    defer env.deinit();

    const header = getAuthHeader(testing.allocator) orelse return error.TestExpectedNonNull;
    defer testing.allocator.free(header);
    try testing.expectEqualStrings("Bearer ghp_mock_token", header);
}

test "getAuthHeader: returns null when GITHUB_TOKEN unset" {
    var env = try test_support.EnvGuard.set(testing.allocator, "GITHUB_TOKEN", null);
    defer env.deinit();

    try testing.expect(getAuthHeader(testing.allocator) == null);
}

test "fetch: returns NetworkDeadlineExceeded when deadline has passed" {
    // The deadline check must short-circuit before any TCP / TLS work is
    // attempted, so the client is deliberately left uninitialized.
    engine.network_deadline_ns = std.time.nanoTimestamp() - 1;
    defer engine.clearNetworkDeadline();

    const result = fetch(.{ .location = .{ .url = "http://127.0.0.1:1/irrelevant" } });
    try testing.expectError(error.NetworkDeadlineExceeded, result);
}

test "fetchAuthenticatedJson: returns NotInitialized when client not started" {
    if (client_initialized) return error.SkipZigTest;
    const result = fetchAuthenticatedJson(testing.allocator, "http://localhost/does-not-matter");
    try testing.expectError(error.NotInitialized, result);
}

test "fetchAuthenticatedJson: short-circuits on expired deadline" {
    engine.network_deadline_ns = std.time.nanoTimestamp() - 1;
    defer engine.clearNetworkDeadline();

    const result = fetchAuthenticatedJson(testing.allocator, "http://127.0.0.1:1/irrelevant");
    try testing.expectError(error.NetworkDeadlineExceeded, result);
}
