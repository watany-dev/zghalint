//! A single `std.http.Client` is kept for the whole process so its internal
//! connection pool reuses TLS/TCP connections to `api.github.com`; this
//! amortizes the ~200ms TLS handshake to a single occurrence.

const std = @import("std");
const runtime = @import("../runtime.zig");
const engine = @import("engine.zig");

const Allocator = std.mem.Allocator;

var client_storage: std.http.Client = undefined;
var client_initialized: bool = false;
var client_mutex: std.Io.Mutex = .init;

/// Set by `init`, cleared by the first `fetch`, which is where the CA bundle
/// scan actually runs. A run that never touches the network (`--offline`, or
/// every lookup served from the disk cache) then never pays for reading and
/// parsing the certificate files, which dominated small offline runs.
var custom_ca_pending: bool = false;

/// Owns the `Proxy` structs `initDefaultProxies` allocates. `Client.deinit`
/// does not free those, so they live in this arena until we tear down.
var proxy_arena: std.heap.ArenaAllocator = undefined;

/// `allocator` must remain valid until `deinit()` returns — `std.http.Client`
/// retains it for connection pool allocations. init/deinit/fetch share a mutex
/// so the initialization flag and storage are never observed half-built.
pub fn init(allocator: Allocator) void {
    client_mutex.lockUncancelable(runtime.io());
    defer client_mutex.unlock(runtime.io());
    if (client_initialized) return;
    client_storage = .{ .allocator = allocator, .io = runtime.io() };
    proxy_arena = .init(allocator);
    if (runtime.environ) |environ| client_storage.initDefaultProxies(proxy_arena.allocator(), environ) catch {};
    custom_ca_pending = true;
    resetNetworkState();
    client_initialized = true;
}

pub fn deinit() void {
    client_mutex.lockUncancelable(runtime.io());
    defer client_mutex.unlock(runtime.io());
    if (!client_initialized) return;
    client_storage.deinit();
    proxy_arena.deinit();
    resetNetworkState();
    client_initialized = false;
}

/// The caller holds `client_mutex`.
fn applyPendingCustomCa() void {
    if (!custom_ca_pending) return;
    custom_ca_pending = false;
    applyCustomCa(client_storage.allocator);
}

/// Zig's default CA scan uses hardcoded system paths and ignores
/// `SSL_CERT_FILE`. A TLS-intercepting proxy needs that file. Loading it
/// freezes the bundle so the next-request rescan cannot wipe the extra CA.
fn applyCustomCa(allocator: Allocator) void {
    const path = runtime.getEnv(allocator, "SSL_CERT_FILE") catch return;
    defer allocator.free(path);
    if (path.len == 0) return;
    // Zig's addCertsFromFilePathAbsolute asserts an absolute path; a relative
    // SSL_CERT_FILE would panic in Debug rather than skip the extra CA.
    if (!std.Io.Dir.path.isAbsolute(path)) return;
    const now = std.Io.Clock.real.now(runtime.io());
    client_storage.ca_bundle.rescan(allocator, runtime.io(), now) catch {};
    client_storage.ca_bundle.addCertsFromFilePathAbsolute(allocator, runtime.io(), now, path) catch return;
    client_storage.now = now;
}

pub const user_agent: []const u8 = "zghalint/0.1.0";
pub const accept_github_json: []const u8 = "application/vnd.github+json";
pub const api_version: []const u8 = "2022-11-28";

pub fn getAuthHeader(allocator: Allocator) ?[]const u8 {
    const token = runtime.getEnv(allocator, "GITHUB_TOKEN") catch return null;
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
    list: std.ArrayList(u8) = .empty,
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
    /// A request failed at the transport layer (name resolution, connect,
    /// TLS, send / receive, or the per-request budget). Sticky: every later
    /// `fetch` in this process returns it without connecting (ADR 0016).
    NetworkUnreachable,
};

/// Set by the first transport failure, cleared by `init` / `deinit` like
/// `rest_fallback.rate_limited`. It lives here rather than in prefetch so the
/// lazy fetches that run after prefetch (archived, stale_refs, refconfusion)
/// are short-circuited as well.
var network_unreachable: bool = false;

/// Whether the previous request got an HTTP response. `std.http.Client` does
/// not resend when a pooled keep-alive connection turns out to be closed by
/// the server, so one `HttpConnectionClosing` / `HttpRequestTruncated` right
/// after a success is forgiven and the next request reconnects. Two in a row
/// mean the network is gone.
var last_fetch_succeeded: bool = false;

pub fn isNetworkUnreachable() bool {
    return network_unreachable;
}

/// Records a transport failure observed outside `fetch`, e.g. by a test
/// that must not open a connection.
pub fn markNetworkUnreachable() void {
    network_unreachable = true;
}

pub fn resetNetworkState() void {
    network_unreachable = false;
    last_fetch_succeeded = false;
}

/// Transport failures cannot recover within one run, so they become the
/// sticky `NetworkUnreachable`; everything else (URL, HTTP protocol, local
/// resources) is `FetchFailed` and the next request is still attempted.
fn classify(err: std.http.Client.FetchError) FetchError {
    return switch (err) {
        // Name resolution.
        error.UnknownHostName,
        error.NameServerFailure,
        error.NoAddressReturned,
        error.ResolvConfParseFailed,
        error.DetectingNetworkConfigurationFailed,
        error.InvalidDnsARecord,
        error.InvalidDnsAAAARecord,
        error.InvalidDnsCnameRecord,
        // Connect.
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.HostUnreachable,
        error.NetworkUnreachable,
        error.NetworkDown,
        error.AddressUnavailable,
        error.Timeout,
        error.TlsInitializationFailed,
        // Send / receive. A request cancelled by the budget surfaces as
        // `ReadFailed` (interrupted readv) or `Canceled` (interrupted connect).
        error.ReadFailed,
        error.WriteFailed,
        error.Canceled,
        error.HttpConnectionClosing,
        error.HttpRequestTruncated,
        // An OS error std has no mapping for. Every such error inside a fetch
        // comes from a socket, resolver or TLS syscall, so it is a transport
        // failure. Windows relies on this: `netConnectIpWindows` and
        // `netReadWindows` pass every AFD status but `INSUFFICIENT_RESOURCES`
        // through `unexpectedStatus`, so even a refused connection arrives here.
        error.Unexpected,
        => error.NetworkUnreachable,
        else => error.FetchFailed,
    };
}

fn isStaleKeepAlive(err: std.http.Client.FetchError) bool {
    return last_fetch_succeeded and switch (err) {
        error.HttpConnectionClosing, error.HttpRequestTruncated => true,
        else => false,
    };
}

/// Maps a std failure to `FetchError` and remembers a dead network. The
/// caller holds `client_mutex`.
fn recordFailure(err: std.http.Client.FetchError) FetchError {
    const stale = isStaleKeepAlive(err);
    last_fetch_succeeded = false;
    if (stale) return error.FetchFailed;
    const mapped = classify(err);
    if (mapped == error.NetworkUnreachable) network_unreachable = true;
    return mapped;
}

const BudgetedFetch = struct {
    opts: std.http.Client.FetchOptions,
    done: std.Io.Event = .unset,
    result: std.http.Client.FetchError!std.http.Client.FetchResult = error.Canceled,

    fn run(self: *BudgetedFetch, io: std.Io) void {
        self.result = client_storage.fetch(self.opts);
        self.done.set(io);
    }
};

/// Runs the request on a concurrent task and cuts it off once `budget` has
/// elapsed. std offers no usable connect or receive timeout, so this is the
/// only per-request cutoff available. Without a budget, or on an `Io` that
/// cannot run concurrent tasks, the request runs inline and waits as long as
/// std does. The caller holds `client_mutex`.
fn fetchWithBudget(
    opts: std.http.Client.FetchOptions,
    budget: std.Io.Timeout,
) std.http.Client.FetchError!std.http.Client.FetchResult {
    const io = runtime.io();
    const deadline = budget.toDeadline(io);
    if (deadline == .none) return client_storage.fetch(opts);

    var task: BudgetedFetch = .{ .opts = opts };
    var future = io.concurrent(BudgetedFetch.run, .{ &task, io }) catch return client_storage.fetch(opts);
    while (!task.done.isSet()) {
        task.done.waitTimeout(io, deadline) catch |err| switch (err) {
            // `waitTimeout` may wake early; only a spent deadline is a timeout.
            error.Timeout => if (deadline.deadline.durationFromNow(io).raw.nanoseconds <= 0) {
                abortFetch(io, &future, &task);
                return task.result catch error.Timeout;
            },
            error.Canceled => {
                abortFetch(io, &future, &task);
                return error.Canceled;
            },
        };
    }
    future.await(io);
    return task.result;
}

/// Stops a request that is still in flight and waits for its task to return.
///
/// `Future.cancel` makes `Io.Threaded` interrupt the blocked name lookup,
/// connect, or read with `error.Canceled`, but the signal is delivered once:
/// a task that swallows it can no longer be interrupted. `std.http.Client`
/// does exactly that while waiting for a proxy's CONNECT reply (it treats the
/// failure as "tunnel unsupported" and reconnects as a plain proxy), which
/// would leave the fresh connection blocked and `cancel` waiting forever. So
/// alongside the cancel a reaper keeps shutting down every socket the client
/// has in use, which turns each blocked read into an EOF, until the task
/// reports back. Both fallbacks are cheap: the reaper only runs on a spent
/// budget.
fn abortFetch(io: std.Io, future: *std.Io.Future(void), task: *BudgetedFetch) void {
    var reaper: SocketReaper = .{ .done = &task.done };
    var reaper_future = io.concurrent(SocketReaper.run, .{ &reaper, io }) catch null;
    future.cancel(io);
    if (reaper_future) |*f| f.await(io);
}

const SocketReaper = struct {
    done: *std.Io.Event,

    const interval: std.Io.Timeout = .{
        .duration = .{ .raw = .fromMilliseconds(10), .clock = .awake },
    };

    fn run(self: *SocketReaper, io: std.Io) void {
        while (!self.done.isSet()) {
            shutdownUsedConnections(io);
            self.done.waitTimeout(io, interval) catch {};
        }
    }
};

/// Shuts down every connection the client currently has in use. A read that
/// is blocked on one returns EOF, and std never hands a shut-down socket
/// back to the pool. Runs under the pool's own mutex, so a connection seen
/// here is not being destroyed at the same time.
fn shutdownUsedConnections(io: std.Io) void {
    const pool = &client_storage.connection_pool;
    pool.mutex.lockUncancelable(io);
    defer pool.mutex.unlock(io);
    var it = pool.used.first;
    while (it) |node| : (it = node.next) {
        const connection: *std.http.Client.Connection = @alignCast(@fieldParentPtr("pool_node", node));
        connection.stream_reader.stream.shutdown(io, .both) catch {};
    }
}

/// `sink` is the response writer when one is used, so a body that exceeded
/// its limit (which std reports as `WriteFailed`, indistinguishable from a
/// failed send) is not mistaken for a dead network.
fn fetchRecorded(
    opts: std.http.Client.FetchOptions,
    sink: ?*const BoundedBody,
) FetchError!std.http.Client.FetchResult {
    if (network_unreachable) return error.NetworkUnreachable;
    if (engine.isNetworkDeadlineExceeded()) return error.NetworkDeadlineExceeded;
    if (!client_initialized) return error.NotInitialized;
    client_mutex.lockUncancelable(runtime.io());
    defer client_mutex.unlock(runtime.io());
    applyPendingCustomCa();
    const result = fetchWithBudget(opts, engine.requestBudget()) catch |err| {
        if (sink) |s| if (s.overflowed) {
            last_fetch_succeeded = true;
            return error.FetchFailed;
        };
        return recordFailure(err);
    };
    last_fetch_succeeded = true;
    return result;
}

/// The client mutex is held for the duration of the call so the shared
/// `std.http.Client` remains safe even if callers are later parallelized.
/// Each request is bounded by `engine.requestBudget()`, and a transport
/// failure makes every later call fail fast with `NetworkUnreachable`.
pub fn fetch(
    opts: std.http.Client.FetchOptions,
) FetchError!std.http.Client.FetchResult {
    return fetchRecorded(opts, null);
}

/// `fetch` with the response body streamed into `sink`; overrides
/// `opts.response_writer`. An overflowed body is `FetchFailed` and does not
/// mark the network unreachable.
pub fn fetchBounded(
    opts: std.http.Client.FetchOptions,
    sink: *BoundedBody,
) FetchError!std.http.Client.FetchResult {
    var bounded = opts;
    bounded.response_writer = &sink.writer;
    return fetchRecorded(bounded, sink);
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

    const result = try fetchBounded(.{
        .location = .{ .url = url },
        .headers = .{ .user_agent = .{ .override = user_agent } },
        .extra_headers = headers_buf[0..header_count],
        .privileged_headers = authHeaders(&auth_buf, auth_value),
    }, &body_sink);

    const body = try body_sink.toOwnedSlice();
    return .{ .status = result.status, .body = body, .allocator = allocator };
}

const test_support = @import("../test_support.zig");
const testing = std.testing;

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

test "classify: transport failures are NetworkUnreachable, the rest FetchFailed" {
    const transport = .{
        error.UnknownHostName,         error.NoAddressReturned,     error.InvalidDnsARecord,
        error.ConnectionRefused,       error.ConnectionResetByPeer, error.HostUnreachable,
        error.NetworkUnreachable,      error.NetworkDown,           error.Timeout,
        error.TlsInitializationFailed, error.ReadFailed,            error.WriteFailed,
        error.Canceled,                error.HttpConnectionClosing, error.HttpRequestTruncated,
        error.Unexpected,
    };
    inline for (transport) |err| {
        try testing.expectEqual(@as(FetchError, error.NetworkUnreachable), classify(err));
    }

    const local = .{
        error.InvalidFormat,                error.UriMissingHost,   error.UnsupportedUriScheme,
        error.OutOfMemory,                  error.SystemResources,  error.HttpHeadersInvalid,
        error.TooManyHttpRedirects,         error.HttpChunkInvalid, error.StreamTooLong,
        error.UnsupportedCompressionMethod,
    };
    inline for (local) |err| {
        try testing.expectEqual(@as(FetchError, error.FetchFailed), classify(err));
    }
}

test "recordFailure: a transport failure is sticky until reset" {
    resetNetworkState();
    defer resetNetworkState();

    try testing.expectEqual(@as(FetchError, error.NetworkUnreachable), recordFailure(error.ConnectionRefused));
    try testing.expect(isNetworkUnreachable());

    // The flag short-circuits ahead of every other check, so even an
    // uninitialized client answers NetworkUnreachable.
    if (!client_initialized) {
        try testing.expectError(error.NetworkUnreachable, fetch(.{ .location = .{ .url = "http://127.0.0.1:1/x" } }));
    }

    resetNetworkState();
    try testing.expect(!isNetworkUnreachable());
}

test "recordFailure: a non-transport failure leaves the network reachable" {
    resetNetworkState();
    defer resetNetworkState();

    try testing.expectEqual(@as(FetchError, error.FetchFailed), recordFailure(error.HttpHeadersInvalid));
    try testing.expect(!isNetworkUnreachable());
}

test "recordFailure: one stale keep-alive after a success is forgiven, two are not" {
    resetNetworkState();
    defer resetNetworkState();

    last_fetch_succeeded = true;
    try testing.expectEqual(@as(FetchError, error.FetchFailed), recordFailure(error.HttpConnectionClosing));
    try testing.expect(!isNetworkUnreachable());

    try testing.expectEqual(@as(FetchError, error.NetworkUnreachable), recordFailure(error.HttpConnectionClosing));
    try testing.expect(isNetworkUnreachable());
}

test "recordFailure: a stale keep-alive shape without a preceding success is sticky" {
    resetNetworkState();
    defer resetNetworkState();

    try testing.expectEqual(@as(FetchError, error.NetworkUnreachable), recordFailure(error.HttpRequestTruncated));
    try testing.expect(isNetworkUnreachable());
}

test "init and deinit reset the network state" {
    if (client_initialized) return error.SkipZigTest;

    network_unreachable = true;
    init(testing.allocator);
    try testing.expect(!isNetworkUnreachable());

    network_unreachable = true;
    deinit();
    try testing.expect(!isNetworkUnreachable());
}

/// A loopback HTTP server for exercising the transport path without the
/// network: `.hang` accepts and never answers, `.reply` answers every
/// request with a fixed 64-byte body.
const TestServer = struct {
    const Mode = enum { hang, reply };
    const reply_body = "x" ** 64;
    const reply_head = "HTTP/1.1 200 OK\r\nContent-Length: 64\r\nConnection: close\r\n\r\n";

    listener: std.Io.net.Server,
    mode: Mode,
    accepted: std.atomic.Value(u32) = .init(0),
    future: ?std.Io.Future(void) = null,

    fn listen(mode: Mode) !TestServer {
        const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
        return .{ .listener = try addr.listen(runtime.io(), .{}), .mode = mode };
    }

    /// `self` must not move after this: the task holds its address.
    fn spawn(self: *TestServer) !void {
        self.future = try runtime.io().concurrent(run, .{ self, runtime.io() });
    }

    fn deinit(self: *TestServer) void {
        const io = runtime.io();
        if (self.future) |*f| f.cancel(io);
        self.listener.deinit(io);
    }

    fn url(self: *const TestServer, buf: []u8, path: []const u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "http://127.0.0.1:{d}{s}", .{ self.listener.socket.address.getPort(), path });
    }

    fn run(self: *TestServer, io: std.Io) void {
        // Hung connections stay open until the task ends; closing one would
        // hand the client an EOF instead of the stall under test.
        var held: [4]std.Io.net.Stream = undefined;
        var held_len: usize = 0;
        defer for (held[0..held_len]) |stream| stream.close(io);

        while (true) {
            const stream = self.listener.accept(io) catch return;
            _ = self.accepted.fetchAdd(1, .monotonic);
            switch (self.mode) {
                .hang => if (held_len < held.len) {
                    held[held_len] = stream;
                    held_len += 1;
                } else stream.close(io),
                .reply => {
                    respond(io, stream);
                    stream.close(io);
                },
            }
        }
    }

    fn respond(io: std.Io, stream: std.Io.net.Stream) void {
        var read_buf: [4096]u8 = undefined;
        var reader = stream.reader(io, &read_buf);
        while (true) {
            const line = reader.interface.takeDelimiterInclusive('\n') catch return;
            if (std.mem.eql(u8, line, "\r\n")) break;
        }
        var write_buf: [256]u8 = undefined;
        var writer = stream.writer(io, &write_buf);
        writer.interface.writeAll(reply_head ++ reply_body) catch return;
        writer.interface.flush() catch return;
    }
};

fn elapsedSince(t0: std.Io.Timestamp) i128 {
    return std.Io.Clock.awake.now(runtime.io()).nanoseconds - t0.nanoseconds;
}

test "fetch: a server that never answers is cut off by the budget and marks the network unreachable" {
    if (client_initialized) return error.SkipZigTest;
    var server = try TestServer.listen(.hang);
    defer server.deinit();
    try server.spawn();

    init(testing.allocator);
    defer deinit();
    // The request must reach the loopback server, not a proxy from the environment.
    client_storage.http_proxy = null;

    var url_buf: [64]u8 = undefined;
    const url = try server.url(&url_buf, "/hang");

    engine.setNetworkDeadline(200 * std.time.ns_per_ms);
    defer engine.clearNetworkDeadline();
    const t0 = std.Io.Clock.awake.now(runtime.io());
    try testing.expectError(error.NetworkUnreachable, fetch(.{ .location = .{ .url = url } }));
    const first = elapsedSince(t0);
    try testing.expect(first >= 150 * std.time.ns_per_ms);
    try testing.expect(first < 2 * std.time.ns_per_s);
    try testing.expect(isNetworkUnreachable());
    try testing.expectEqual(@as(u32, 1), server.accepted.load(.monotonic));

    // The second request is refused before connecting, whatever the budget.
    engine.setNetworkDeadline(10 * std.time.ns_per_s);
    const t1 = std.Io.Clock.awake.now(runtime.io());
    try testing.expectError(error.NetworkUnreachable, fetch(.{ .location = .{ .url = url } }));
    try testing.expect(elapsedSince(t1) < 50 * std.time.ns_per_ms);
    try testing.expectEqual(@as(u32, 1), server.accepted.load(.monotonic));
}

test "fetch: a CONNECT proxy that never answers is cut off by the budget" {
    if (client_initialized) return error.SkipZigTest;
    var server = try TestServer.listen(.hang);
    defer server.deinit();
    try server.spawn();

    var url_buf: [64]u8 = undefined;
    const proxy_url = try server.url(&url_buf, "");
    var https = try test_support.EnvGuard.set(testing.allocator, "HTTPS_PROXY", proxy_url);
    defer https.deinit();
    var https_lc = try test_support.EnvGuard.set(testing.allocator, "https_proxy", proxy_url);
    defer https_lc.deinit();

    init(testing.allocator);
    defer deinit();
    try testing.expect(client_storage.https_proxy != null);

    // std answers a failed CONNECT by reconnecting to the proxy as a plain
    // HTTP proxy, so the request has to be cut off twice.
    engine.setNetworkDeadline(200 * std.time.ns_per_ms);
    defer engine.clearNetworkDeadline();
    const t0 = std.Io.Clock.awake.now(runtime.io());
    try testing.expectError(error.NetworkUnreachable, fetch(.{ .location = .{ .url = "https://api.github.invalid/" } }));
    try testing.expect(elapsedSince(t0) < 2 * std.time.ns_per_s);
    try testing.expect(isNetworkUnreachable());
    try testing.expect(server.accepted.load(.monotonic) >= 1);
}

test "fetch: a refused connection fails at once instead of waiting out the budget" {
    if (client_initialized) return error.SkipZigTest;
    // Bind and release a port so nothing listens on it.
    var probe = try TestServer.listen(.hang);
    var url_buf: [64]u8 = undefined;
    const url = try probe.url(&url_buf, "/refused");
    probe.deinit();

    init(testing.allocator);
    defer deinit();
    client_storage.http_proxy = null;

    engine.setNetworkDeadline(5 * std.time.ns_per_s);
    defer engine.clearNetworkDeadline();
    const t0 = std.Io.Clock.awake.now(runtime.io());
    try testing.expectError(error.NetworkUnreachable, fetch(.{ .location = .{ .url = url } }));
    try testing.expect(elapsedSince(t0) < std.time.ns_per_s);
    try testing.expect(isNetworkUnreachable());
}

test "fetchBounded: an oversized body is FetchFailed and leaves the network reachable" {
    if (client_initialized) return error.SkipZigTest;
    var server = try TestServer.listen(.reply);
    defer server.deinit();
    try server.spawn();

    init(testing.allocator);
    defer deinit();
    client_storage.http_proxy = null;

    var url_buf: [64]u8 = undefined;
    const url = try server.url(&url_buf, "/body");

    engine.setNetworkDeadline(5 * std.time.ns_per_s);
    defer engine.clearNetworkDeadline();

    var small = BoundedBody.init(testing.allocator, 8);
    defer small.deinit();
    try testing.expectError(error.FetchFailed, fetchBounded(.{ .location = .{ .url = url } }, &small));
    try testing.expect(small.overflowed);
    try testing.expect(!isNetworkUnreachable());

    var roomy = BoundedBody.init(testing.allocator, max_response_bytes);
    defer roomy.deinit();
    const result = try fetchBounded(.{ .location = .{ .url = url } }, &roomy);
    try testing.expectEqual(std.http.Status.ok, result.status);
    try testing.expectEqualStrings(TestServer.reply_body, roomy.written());
    try testing.expect(!isNetworkUnreachable());
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

test "init honors HTTPS_PROXY (#336)" {
    if (client_initialized) return error.SkipZigTest;
    var https = try test_support.EnvGuard.set(testing.allocator, "HTTPS_PROXY", "http://127.0.0.1:8080");
    defer https.deinit();
    var https_lc = try test_support.EnvGuard.set(testing.allocator, "https_proxy", "http://127.0.0.1:8080");
    defer https_lc.deinit();

    init(testing.allocator);
    defer deinit();
    const proxy = client_storage.https_proxy orelse return error.TestExpectedNonNull;
    try testing.expectEqualStrings("127.0.0.1", proxy.host.bytes);
    try testing.expectEqual(@as(u16, 8080), proxy.port);
}

test "init defers the CA bundle scan until the first fetch" {
    if (client_initialized) return error.SkipZigTest;
    init(testing.allocator);
    defer deinit();
    try testing.expect(custom_ca_pending);

    applyPendingCustomCa();
    try testing.expect(!custom_ca_pending);
}

test "fetch ignores a missing SSL_CERT_FILE without failing (#336)" {
    if (client_initialized) return error.SkipZigTest;
    var env = try test_support.EnvGuard.set(testing.allocator, "SSL_CERT_FILE", "/no/such/ca.pem");
    defer env.deinit();
    init(testing.allocator);
    defer deinit();
    applyPendingCustomCa();
    try testing.expect(client_initialized);
}

test "fetch ignores a relative SSL_CERT_FILE without panicking (#336)" {
    if (client_initialized) return error.SkipZigTest;
    var env = try test_support.EnvGuard.set(testing.allocator, "SSL_CERT_FILE", "not-absolute.pem");
    defer env.deinit();
    init(testing.allocator);
    defer deinit();
    applyPendingCustomCa();
    try testing.expect(client_initialized);
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
    engine.network_deadline_ns = std.Io.Clock.awake.now(runtime.io()).nanoseconds - 1;
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
    engine.network_deadline_ns = std.Io.Clock.awake.now(runtime.io()).nanoseconds - 1;
    defer engine.clearNetworkDeadline();

    const result = fetchAuthenticatedJson(testing.allocator, "http://127.0.0.1:1/irrelevant");
    try testing.expectError(error.NetworkDeadlineExceeded, result);
}
