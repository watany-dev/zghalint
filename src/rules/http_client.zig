//! Shared HTTP client for GitHub API access.
//!
//! Owns a single `std.http.Client` instance across the process so that
//! TLS/TCP connections to `api.github.com` are reused between rule fetches.
//! Each `std.http.Client` maintains an internal connection pool; reusing one
//! client amortizes the ~200ms TLS handshake to a single occurrence.

const std = @import("std");
const engine = @import("engine.zig");

const Allocator = std.mem.Allocator;

// ============================================================
// Singleton state
// ============================================================

var client_storage: std.http.Client = undefined;
var client_initialized: bool = false;
var client_mutex: std.Thread.Mutex = .{};

/// Initialize the shared HTTP client.
/// No-op if already initialized. `deinit()` must be called to free resources.
/// The provided `allocator` must remain valid until `deinit()` returns —
/// `std.http.Client` retains it for connection pool allocations.
/// Safe to call from multiple threads; init/deinit/fetch share a mutex so
/// the initialization flag and storage are never observed half-built.
pub fn init(allocator: Allocator) void {
    client_mutex.lock();
    defer client_mutex.unlock();
    if (client_initialized) return;
    client_storage = .{ .allocator = allocator };
    client_initialized = true;
}

/// Release the shared HTTP client and any pooled connections.
/// Safe to call multiple times; safe to call concurrently with `fetch()`
/// (the mutex serializes with in-flight requests).
pub fn deinit() void {
    client_mutex.lock();
    defer client_mutex.unlock();
    if (!client_initialized) return;
    client_storage.deinit();
    client_initialized = false;
}

// ============================================================
// Header helpers
// ============================================================

pub const user_agent: []const u8 = "zghalint/0.1.0";
pub const accept_github_json: []const u8 = "application/vnd.github+json";
pub const api_version: []const u8 = "2022-11-28";

/// Allocate a "Bearer <token>" string from the `GITHUB_TOKEN` env var.
/// Returns `null` if the variable is unset or allocation fails. The caller
/// owns the returned slice and must free it with `allocator`.
pub fn getAuthHeader(allocator: Allocator) ?[]const u8 {
    const token = std.process.getEnvVarOwned(allocator, "GITHUB_TOKEN") catch return null;
    defer allocator.free(token);
    return std.fmt.allocPrint(allocator, "Bearer {s}", .{token}) catch null;
}

/// Fill the provided header buffer with the standard GitHub REST headers:
/// Accept, X-GitHub-Api-Version, and (optionally) Authorization.
/// Returns the number of headers written. `buf` must hold at least 3 entries.
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

// ============================================================
// Fetch
// ============================================================

pub const FetchError = error{
    NotInitialized,
    FetchFailed,
    NetworkDeadlineExceeded,
};

/// Perform an HTTP fetch through the shared client.
///
/// The client mutex is held for the duration of the call so the shared
/// `std.http.Client` remains safe even if callers are later parallelized.
/// Callers are responsible for constructing `opts.extra_headers` using
/// `writeStandardHeaders()` plus any endpoint-specific entries.
pub fn fetch(
    opts: std.http.Client.FetchOptions,
) FetchError!std.http.Client.FetchResult {
    if (engine.isNetworkDeadlineExceeded()) return error.NetworkDeadlineExceeded;
    if (!client_initialized) return error.NotInitialized;
    client_mutex.lock();
    defer client_mutex.unlock();
    return client_storage.fetch(opts) catch return error.FetchFailed;
}

// ============================================================
// High-level GET helper
// ============================================================

pub const FetchedError = FetchError || error{OutOfMemory};

/// Owned response body together with the HTTP status returned by GitHub.
/// Callers must invoke `deinit()` to free the body slice.
pub const FetchedBody = struct {
    status: std.http.Status,
    body: []u8,
    allocator: Allocator,

    pub fn deinit(self: *FetchedBody) void {
        self.allocator.free(self.body);
        self.body = &.{};
    }
};

/// Issue a GET against `url` with the standard GitHub REST headers and the
/// optional `Authorization` header derived from `GITHUB_TOKEN`. The response
/// body is returned as an owned slice; the status is left untouched so callers
/// retain their existing branching semantics (e.g. `.ok` vs `.not_found`).
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

// ============================================================
// Tests
// ============================================================

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
    // Ensure a clean slate for this test even if another test initialized the client
    if (client_initialized) return error.SkipZigTest;
    const result = fetch(.{ .location = .{ .url = "http://localhost/does-not-matter" } });
    try testing.expectError(error.NotInitialized, result);
}

test "init is idempotent and deinit resets state" {
    // Work on a clean slate. If a parent test left the client up, we bail.
    if (client_initialized) return error.SkipZigTest;

    init(testing.allocator);
    try testing.expect(client_initialized);
    // Second init must not re-allocate or leak.
    init(testing.allocator);
    try testing.expect(client_initialized);

    deinit();
    try testing.expect(!client_initialized);
    // Second deinit is a no-op and must not crash.
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
    // Force an already-expired deadline. This must short-circuit before any
    // TCP / TLS work is attempted, so the client doesn't even need to be init'd.
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
