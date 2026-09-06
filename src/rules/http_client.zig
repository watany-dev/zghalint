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

pub fn writeStandardHeaders(buf: []std.http.Header) usize {
    std.debug.assert(buf.len >= 2);
    buf[0] = .{ .name = "Accept", .value = accept_github_json };
    buf[1] = .{ .name = "X-GitHub-Api-Version", .value = api_version };
    return 2;
}

/// The Authorization header goes in `privileged_headers`, which
/// `std.http.Client` drops when a redirect leaves the original host, so a
/// token is never forwarded to a third-party origin.
pub fn authHeaders(buf: *[1]std.http.Header, auth_value: ?[]const u8) []const std.http.Header {
    const auth = auth_value orelse return &.{};
    buf[0] = .{ .name = "Authorization", .value = auth };
    return buf[0..1];
}

/// Upper bound on a single API response body. GitHub's largest documented
/// payloads here (100 advisories, a page of refs) are well under 1 MiB;
/// the cap bounds memory when a misbehaving or redirected server streams
/// an unbounded body.
pub const max_response_bytes: usize = 16 * 1024 * 1024;

/// A `std.Io.Writer` that accumulates into an owned buffer and fails the
/// write (and therefore the fetch) once `limit` bytes would be exceeded.
pub const BoundedBody = struct {
    list: std.ArrayListUnmanaged(u8) = .empty,
    allocator: Allocator,
    limit: usize,
    overflowed: bool = false,
    writer: std.Io.Writer,

    pub fn init(allocator: Allocator, limit: usize) BoundedBody {
        return .{
            .allocator = allocator,
            .limit = limit,
            .writer = .{ .vtable = &.{ .drain = drain }, .buffer = &.{} },
        };
    }

    pub fn deinit(self: *BoundedBody) void {
        self.list.deinit(self.allocator);
    }

    pub fn written(self: *BoundedBody) []u8 {
        return self.list.items;
    }

    pub fn toOwnedSlice(self: *BoundedBody) error{OutOfMemory}![]u8 {
        return self.list.toOwnedSlice(self.allocator);
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *BoundedBody = @fieldParentPtr("writer", w);
        var consumed: usize = 0;
        for (data[0 .. data.len - 1]) |chunk| {
            try self.append(chunk);
            consumed += chunk.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| {
            try self.append(last);
            consumed += last.len;
        }
        return consumed;
    }

    fn append(self: *BoundedBody, chunk: []const u8) std.Io.Writer.Error!void {
        if (chunk.len > self.limit - self.list.items.len) {
            self.overflowed = true;
            return error.WriteFailed;
        }
        self.list.appendSlice(self.allocator, chunk) catch return error.WriteFailed;
    }
};

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
    var body_sink = BoundedBody.init(allocator, max_response_bytes);
    errdefer body_sink.deinit();

    const auth_value = getAuthHeader(allocator);
    defer if (auth_value) |auth| allocator.free(auth);

    var headers_buf: [2]std.http.Header = undefined;
    const header_count = writeStandardHeaders(&headers_buf);
    var auth_buf: [1]std.http.Header = undefined;

    const result = try fetch(.{
        .location = .{ .url = url },
        .response_writer = &body_sink.writer,
        .headers = .{ .user_agent = .{ .override = user_agent } },
        .extra_headers = headers_buf[0..header_count],
        .privileged_headers = authHeaders(&auth_buf, auth_value),
    });

    const body = try body_sink.toOwnedSlice();
    return .{ .status = result.status, .body = body, .allocator = allocator };
}

const test_support = @import("../test_support.zig");
const testing = std.testing;

test "writeStandardHeaders yields the 2 unprivileged entries" {
    var buf: [4]std.http.Header = undefined;
    const count = writeStandardHeaders(&buf);
    try testing.expectEqual(@as(usize, 2), count);
    try testing.expectEqualStrings("Accept", buf[0].name);
    try testing.expectEqualStrings(accept_github_json, buf[0].value);
    try testing.expectEqualStrings("X-GitHub-Api-Version", buf[1].name);
    try testing.expectEqualStrings(api_version, buf[1].value);
}

test "authHeaders: empty without a token, Authorization with one" {
    var buf: [1]std.http.Header = undefined;
    try testing.expectEqual(@as(usize, 0), authHeaders(&buf, null).len);

    const with_auth = authHeaders(&buf, "Bearer ghp_abc");
    try testing.expectEqual(@as(usize, 1), with_auth.len);
    try testing.expectEqualStrings("Authorization", with_auth[0].name);
    try testing.expectEqualStrings("Bearer ghp_abc", with_auth[0].value);
}

test "BoundedBody: accepts up to the limit and fails beyond it" {
    var sink = BoundedBody.init(testing.allocator, 8);
    defer sink.deinit();

    try sink.writer.writeAll("abcd");
    try sink.writer.writeAll("efgh");
    try testing.expectEqualStrings("abcdefgh", sink.written());
    try testing.expect(!sink.overflowed);

    try testing.expectError(error.WriteFailed, sink.writer.writeAll("i"));
    try testing.expect(sink.overflowed);
    try testing.expectEqualStrings("abcdefgh", sink.written());
}

test "BoundedBody: splat writes are counted against the limit" {
    var sink = BoundedBody.init(testing.allocator, 5);
    defer sink.deinit();

    try sink.writer.splatByteAll('x', 5);
    try testing.expectEqualStrings("xxxxx", sink.written());
    try testing.expectError(error.WriteFailed, sink.writer.splatByteAll('y', 1));
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
