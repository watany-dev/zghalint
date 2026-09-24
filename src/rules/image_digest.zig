//! Tag → registry digest, populated on `--fix`, plus the image rewrite SC001
//! uses. Lives outside `prefetch.zig` so a rule can read it without importing
//! the GitHub orchestrator (ADR 0017).
//!
//! Only positive facts are stored. A miss is never evidence that the tag
//! does not exist — the run may be offline, the registry unsupported, or
//! the fetch a 4xx — so callers degrade to "no fix".

const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const workflow_types = @import("../workflow/types.zig");
const runtime = @import("../runtime.zig");
const http_client = @import("http_client.zig");
const cache_dir = @import("cache_dir.zig");
const json_util = @import("json_util.zig");

const Allocator = std.mem.Allocator;
const DiagnosticList = diagnostics.DiagnosticList;
const Edit = diagnostics.Edit;
const Fix = diagnostics.Fix;
const ScalarValueMeta = workflow_types.ScalarValueMeta;
const Workflow = workflow_types.Workflow;

const docker_prefix = "docker://";
const cache_ttl_s: i64 = 24 * 60 * 60;
const cache_subdir = "zghalint/images";

const accept_manifest =
    "application/vnd.oci.image.index.v1+json, " ++
    "application/vnd.docker.distribution.manifest.list.v2+json, " ++
    "application/vnd.oci.image.manifest.v1+json, " ++
    "application/vnd.docker.distribution.manifest.v2+json";

const manifest_headers = [_]std.http.Header{
    .{ .name = "Accept", .value = accept_manifest },
};

pub const Registry = enum { docker_hub, ghcr };

pub const ImageRef = struct {
    host: []const u8,
    name: []const u8,
    tag: []const u8,
    /// Empty when the source had no `:tag` (implicit `latest`).
    written_tag: []const u8,
    registry: Registry,
};

const DigestMap = std.StringHashMapUnmanaged([]const u8);

var digest_cache: DigestMap = .{};
var digest_arena: ?std.heap.ArenaAllocator = null;
var docker_hub_rate_limited = false;
var ghcr_rate_limited = false;

pub fn initDigests(backing_allocator: Allocator, offline: bool, wanted: bool) void {
    if (offline or !wanted) return;
    digest_arena = std.heap.ArenaAllocator.init(backing_allocator);
    docker_hub_rate_limited = false;
    ghcr_rate_limited = false;
}

pub fn deinitDigests() void {
    if (digest_arena) |*arena| {
        digest_cache = .{};
        arena.deinit();
        digest_arena = null;
    }
    docker_hub_rate_limited = false;
    ghcr_rate_limited = false;
}

pub fn isActive() bool {
    return digest_arena != null;
}

fn isHexLower(s: []const u8) bool {
    if (s.len != 64) return false;
    for (s) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        if (!ok) return false;
    }
    return true;
}

pub fn isValidDigest(digest: []const u8) bool {
    return std.mem.startsWith(u8, digest, "sha256:") and isHexLower(digest["sha256:".len..]);
}

fn cacheKey(alloc: Allocator, host: []const u8, name: []const u8, tag: []const u8) ?[]const u8 {
    return std.fmt.allocPrint(alloc, "{s}/{s}:{s}", .{ host, name, tag }) catch null;
}

pub fn setCachedDigest(host: []const u8, name: []const u8, tag: []const u8, digest: []const u8) void {
    const alloc = if (digest_arena) |*arena| arena.allocator() else return;
    if (!isValidDigest(digest)) return;
    const key = cacheKey(alloc, host, name, tag) orelse return;
    const value = alloc.dupe(u8, digest) catch return;
    digest_cache.put(alloc, key, value) catch return;
}

pub fn lookupDigest(host: []const u8, name: []const u8, tag: []const u8) ?[]const u8 {
    if (digest_arena == null) return null;
    var key_buf: [512]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "{s}/{s}:{s}", .{ host, name, tag }) catch return null;
    return digest_cache.get(key);
}

const docker_hub_hosts = [_][]const u8{ "docker.io", "index.docker.io", "registry-1.docker.io" };

fn isDockerHubHost(host: []const u8) bool {
    for (docker_hub_hosts) |h| {
        if (std.ascii.eqlIgnoreCase(host, h)) return true;
    }
    return false;
}

/// Strip `docker://` and split host / name / tag. Null for a digest pin, an
/// expression, or a registry this run will not fetch. Official Docker Hub
/// images keep their one-component spelling here; `library/` is a fetch-only
/// prefix.
pub fn parseImageRef(raw: []const u8) ?ImageRef {
    const body = if (std.mem.startsWith(u8, raw, docker_prefix))
        raw[docker_prefix.len..]
    else
        raw;
    if (body.len == 0) return null;
    if (std.mem.find(u8, body, "@sha256:") != null) return null;
    if (std.mem.find(u8, body, "${{") != null) return null;

    const slash = std.mem.findScalar(u8, body, '/');
    const first = if (slash) |s| body[0..s] else body;
    // A colon in `alpine:3.19` is the tag. A colon is a host:port only when
    // a `/` follows (`localhost:5000/foo`).
    const has_host = slash != null and (std.mem.findScalar(u8, first, '.') != null or
        std.mem.findScalar(u8, first, ':') != null);

    const registry: Registry, const host: []const u8, const rest: []const u8 = blk: {
        if (!has_host) break :blk .{ .docker_hub, "docker.io", body };
        const path = body[slash.? + 1 ..];
        if (path.len == 0) return null;
        if (std.ascii.eqlIgnoreCase(first, "ghcr.io")) break :blk .{ .ghcr, "ghcr.io", path };
        if (isDockerHubHost(first)) break :blk .{ .docker_hub, "docker.io", path };
        return null;
    };

    const last_slash = std.mem.findScalarLast(u8, rest, '/');
    const last_comp = if (last_slash) |s| rest[s + 1 ..] else rest;
    const colon = std.mem.findScalar(u8, last_comp, ':');
    const written_tag = if (colon) |c| last_comp[c + 1 ..] else "";
    if (written_tag.len == 0 and colon != null) return null;
    if (std.mem.findScalar(u8, written_tag, ':') != null) return null;
    const tag: []const u8 = if (written_tag.len == 0) "latest" else written_tag;
    const name = if (colon != null) rest[0 .. rest.len - written_tag.len - 1] else rest;
    if (name.len == 0) return null;

    return .{
        .host = host,
        .name = name,
        .tag = tag,
        .written_tag = written_tag,
        .registry = registry,
    };
}

/// Official Docker Hub images are a single path component; the registry
/// API wants `library/<name>`.
fn dockerHubName(alloc: Allocator, name: []const u8) ?[]const u8 {
    if (std.mem.findScalar(u8, name, '/') != null) return name;
    return std.fmt.allocPrint(alloc, "library/{s}", .{name}) catch null;
}

fn fetchName(alloc: Allocator, ref: ImageRef) []const u8 {
    if (ref.registry != .docker_hub) return ref.name;
    return dockerHubName(alloc, ref.name) orelse ref.name;
}

fn digestOfBody(alloc: Allocator, body: []const u8) ?[]const u8 {
    if (body.len == 0) return null;
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &hash, .{});
    const hex = std.fmt.bytesToHex(hash, .lower);
    return std.fmt.allocPrint(alloc, "sha256:{s}", .{hex}) catch null;
}

fn bearerFromTokenJson(alloc: Allocator, body: []const u8) ?[]const u8 {
    var parse_arena = std.heap.ArenaAllocator.init(alloc);
    defer parse_arena.deinit();
    const root = std.json.parseFromSliceLeaky(std.json.Value, parse_arena.allocator(), body, .{}) catch return null;
    const obj = json_util.asObject(root) orelse return null;
    const token = json_util.stringField(obj, "token") orelse json_util.stringField(obj, "access_token") orelse return null;
    if (token.len == 0) return null;
    return std.fmt.allocPrint(alloc, "Bearer {s}", .{token}) catch null;
}

const FetchOutcome = enum { ok, rate_limited, miss };

fn markRateLimited(registry: Registry) void {
    switch (registry) {
        .docker_hub => docker_hub_rate_limited = true,
        .ghcr => ghcr_rate_limited = true,
    }
}

fn isRateLimited(registry: Registry) bool {
    return switch (registry) {
        .docker_hub => docker_hub_rate_limited,
        .ghcr => ghcr_rate_limited,
    };
}

fn classifyStatus(status: std.http.Status) FetchOutcome {
    return switch (status) {
        .ok => .ok,
        .too_many_requests => .rate_limited,
        else => .miss,
    };
}

fn storeDigest(host: []const u8, written_name: []const u8, fetch_name: []const u8, tag: []const u8, digest: []const u8) void {
    setCachedDigest(host, written_name, tag, digest);
    if (!std.mem.eql(u8, written_name, fetch_name)) {
        setCachedDigest(host, fetch_name, tag, digest);
    }
}

fn fetchDockerHubManifest(alloc: Allocator, name: []const u8, tag: []const u8) FetchOutcome {
    const repo = dockerHubName(alloc, name) orelse return .miss;
    const token_url = std.fmt.allocPrint(
        alloc,
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{s}:pull",
        .{repo},
    ) catch return .miss;
    var token_body = http_client.fetchBodyIsolated(alloc, token_url, &.{}, &.{}) catch return .miss;
    defer token_body.deinit();
    if (classifyStatus(token_body.status) != .ok) return classifyStatus(token_body.status);
    const auth = bearerFromTokenJson(alloc, token_body.body) orelse return .miss;
    defer alloc.free(auth);

    const manifest_url = std.fmt.allocPrint(
        alloc,
        "https://registry-1.docker.io/v2/{s}/manifests/{s}",
        .{ repo, tag },
    ) catch return .miss;
    var auth_buf: [1]std.http.Header = undefined;
    var body = http_client.fetchBodyIsolated(
        alloc,
        manifest_url,
        &manifest_headers,
        http_client.authHeaders(&auth_buf, auth),
    ) catch return .miss;
    defer body.deinit();
    const outcome = classifyStatus(body.status);
    if (outcome != .ok) return outcome;
    const digest = digestOfBody(alloc, body.body) orelse return .miss;
    storeDigest("docker.io", name, repo, tag, digest);
    return .ok;
}

fn fetchGhcrManifest(alloc: Allocator, name: []const u8, tag: []const u8) FetchOutcome {
    const url = std.fmt.allocPrint(alloc, "https://ghcr.io/v2/{s}/manifests/{s}", .{ name, tag }) catch return .miss;
    var body = http_client.fetchBodyIsolated(alloc, url, &manifest_headers, &.{}) catch return .miss;
    if (body.status == .unauthorized) {
        body.deinit();
        const auth_value = http_client.getAuthHeader(alloc);
        defer if (auth_value) |a| alloc.free(a);
        var auth_buf: [1]std.http.Header = undefined;
        body = http_client.fetchBodyIsolated(
            alloc,
            url,
            &manifest_headers,
            http_client.authHeaders(&auth_buf, auth_value),
        ) catch return .miss;
    }
    defer body.deinit();

    const outcome = classifyStatus(body.status);
    if (outcome != .ok) return outcome;
    const digest = digestOfBody(alloc, body.body) orelse return .miss;
    setCachedDigest("ghcr.io", name, tag, digest);
    return .ok;
}

fn fetchIntoStore(alloc: Allocator, ref: ImageRef, no_cache: bool) void {
    if (lookupFor(ref) != null) return;
    const stored_name = fetchName(alloc, ref);
    if (!no_cache) {
        if (loadDisk(alloc, ref.host, stored_name, ref.tag) orelse loadDisk(alloc, ref.host, ref.name, ref.tag)) |d| {
            storeDigest(ref.host, ref.name, stored_name, ref.tag, d);
            return;
        }
    }
    if (isRateLimited(ref.registry)) return;

    const outcome: FetchOutcome = switch (ref.registry) {
        .docker_hub => fetchDockerHubManifest(alloc, ref.name, ref.tag),
        .ghcr => fetchGhcrManifest(alloc, ref.name, ref.tag),
    };
    switch (outcome) {
        .ok => {
            if (!no_cache) {
                if (lookupFor(ref)) |d| saveDisk(alloc, ref.host, stored_name, ref.tag, d);
            }
        },
        .rate_limited => markRateLimited(ref.registry),
        .miss => {},
    }
}

fn sanitizeFilePart(alloc: Allocator, s: []const u8) ?[]const u8 {
    var buf = std.ArrayList(u8).empty;
    buf.ensureTotalCapacity(alloc, s.len) catch return null;
    for (s) |c| {
        const ok = std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.';
        buf.appendAssumeCapacity(if (ok) c else '_');
    }
    return buf.toOwnedSlice(alloc) catch null;
}

fn cacheFilename(alloc: Allocator, host: []const u8, name: []const u8, tag: []const u8) ?[]const u8 {
    const h = sanitizeFilePart(alloc, host) orelse return null;
    const n = sanitizeFilePart(alloc, name) orelse return null;
    const t = sanitizeFilePart(alloc, tag) orelse return null;
    return std.fmt.allocPrint(alloc, "{s}_{s}_{s}.json", .{ h, n, t }) catch null;
}

fn isFresh(cached_at: i64) bool {
    const now = std.Io.Clock.real.now(runtime.io()).toSeconds();
    if (cached_at > now) return false;
    const floor = std.math.sub(i64, now, cache_ttl_s) catch return false;
    return cached_at >= floor;
}

fn loadDisk(alloc: Allocator, host: []const u8, name: []const u8, tag: []const u8) ?[]const u8 {
    var dir = cache_dir.open(alloc, cache_subdir) orelse return null;
    defer dir.close(runtime.io());
    const file_name = cacheFilename(alloc, host, name, tag) orelse return null;
    const file = dir.openFile(runtime.io(), file_name, .{}) catch return null;
    defer file.close(runtime.io());
    var file_reader = file.reader(runtime.io(), &.{});
    const body = file_reader.interface.allocRemaining(alloc, .limited(4096)) catch return null;
    defer alloc.free(body);

    var parse_arena = std.heap.ArenaAllocator.init(alloc);
    defer parse_arena.deinit();
    const root = std.json.parseFromSliceLeaky(std.json.Value, parse_arena.allocator(), body, .{}) catch return null;
    const obj = json_util.asObject(root) orelse return null;
    const cached_at: i64 = blk: {
        const v = obj.get("cached_at") orelse break :blk 0;
        break :blk switch (v) {
            .integer => |i| @intCast(i),
            else => 0,
        };
    };
    if (!isFresh(cached_at)) return null;
    const digest = json_util.stringField(obj, "digest") orelse return null;
    if (!isValidDigest(digest)) return null;
    const arena_alloc = (digest_arena orelse return null).allocator();
    return arena_alloc.dupe(u8, digest) catch null;
}

fn saveDisk(alloc: Allocator, host: []const u8, name: []const u8, tag: []const u8, digest: []const u8) void {
    var dir = cache_dir.open(alloc, cache_subdir) orelse return;
    defer dir.close(runtime.io());
    const file_name = cacheFilename(alloc, host, name, tag) orelse return;
    const now = std.Io.Clock.real.now(runtime.io()).toSeconds();
    const doc = std.fmt.allocPrint(alloc, "{{\"cached_at\":{d},\"digest\":\"{s}\"}}", .{ now, digest }) catch return;
    cache_dir.writeFileAtomic(dir, file_name, doc) catch return;
}

fn consider(alloc: Allocator, raw: []const u8, seen: *std.StringHashMapUnmanaged(void), no_cache: bool) void {
    const ref = parseImageRef(raw) orelse return;
    const key = cacheKey(alloc, ref.host, ref.name, ref.tag) orelse return;
    const gop = seen.getOrPut(alloc, key) catch return;
    if (gop.found_existing) return;
    fetchIntoStore(alloc, ref, no_cache);
}

/// Unique unpinned Docker Hub / GHCR refs, fetched before the lint pass.
pub fn prefetch(allocator: Allocator, workflows: []const Workflow, no_cache: bool) void {
    if (!isActive()) return;
    var seen: std.StringHashMapUnmanaged(void) = .{};
    defer seen.deinit(allocator);

    for (workflows) |wf| {
        for (wf.jobs) |job| {
            if (job.container) |c| {
                if (c.image) |img| consider(allocator, img, &seen, no_cache);
            }
            for (job.services) |svc| {
                if (svc.image) |img| consider(allocator, img, &seen, no_cache);
            }
            const Ctx = struct {
                alloc: Allocator,
                seen: *std.StringHashMapUnmanaged(void),
                no_cache: bool,
                pub fn visit(self: @This(), step: *const workflow_types.Step) void {
                    const uses = step.uses orelse return;
                    if (!uses.is_docker) return;
                    consider(self.alloc, uses.raw, self.seen, self.no_cache);
                }
            };
            workflow_types.walkSteps(job.steps, Ctx{ .alloc = allocator, .seen = &seen, .no_cache = no_cache });
        }
    }
}

const pin_description = "pin the image to the digest the tag resolved to when fetched";

fn lookupFor(ref: ImageRef) ?[]const u8 {
    if (lookupDigest(ref.host, ref.name, ref.tag)) |d| return d;
    if (ref.registry == .docker_hub) {
        // Official images are stored as library/<name> after fetch.
        var buf: [256]u8 = undefined;
        if (std.mem.findScalar(u8, ref.name, '/') == null) {
            const n = std.fmt.bufPrint(&buf, "library/{s}", .{ref.name}) catch return null;
            return lookupDigest(ref.host, n, ref.tag);
        }
    }
    return null;
}

/// Rewrites `image:tag` (or `docker://image:tag`) to `image@sha256:…`, and
/// appends `# <tag>` when the value ends the line.
pub fn buildPinFix(
    list: *DiagnosticList,
    written: []const u8,
    meta: ?ScalarValueMeta,
    ends_line: bool,
) ?Fix {
    if (!ends_line) return null;
    const m = meta orelse return null;
    switch (m.style) {
        .plain, .single_quoted, .double_quoted => {},
        .literal, .folded => return null,
    }
    const ref = parseImageRef(written) orelse return null;
    const digest = lookupFor(ref) orelse return null;

    const quote_offset: usize = switch (m.style) {
        .plain => 0,
        .single_quoted, .double_quoted => 1,
        .literal, .folded => return null,
    };
    const end_byte = m.value_span.end_byte;
    if (end_byte < quote_offset) return null;

    const alloc = list.fixAllocator();
    const comment_tag: []const u8 = if (ref.written_tag.len == 0) "latest" else ref.written_tag;
    const comment = std.fmt.allocPrint(alloc, " # {s}", .{comment_tag}) catch return null;
    const replacement = alloc.dupe(u8, digest) catch return null;

    const tag_suffix_len: usize = if (ref.written_tag.len == 0) 0 else ref.written_tag.len + 1;
    if (end_byte < quote_offset + tag_suffix_len) return null;
    const replace_end = end_byte - quote_offset;
    const replace_start = if (tag_suffix_len == 0)
        replace_end
    else
        replace_end - tag_suffix_len;

    const pin = std.fmt.allocPrint(alloc, "@{s}", .{replacement}) catch return null;
    const edits = alloc.alloc(Edit, 2) catch return null;
    edits[0] = .{ .start_byte = replace_start, .end_byte = replace_end, .replacement = pin };
    edits[1] = .{ .start_byte = end_byte, .end_byte = end_byte, .replacement = comment };
    return .{ .description = pin_description, .safety = .safe, .edits = edits };
}

const testing = std.testing;

const valid_digest = "sha256:1c4eef651f65e2f7daee7ea7320b2504cd83545e8f5da6c45b8c4911eb1aea61";

test "parseImageRef: official image, docker.io, ghcr, implicit latest" {
    const alpine = parseImageRef("alpine:3.19").?;
    try testing.expectEqual(Registry.docker_hub, alpine.registry);
    try testing.expectEqualStrings("docker.io", alpine.host);
    try testing.expectEqualStrings("alpine", alpine.name);
    try testing.expectEqualStrings("3.19", alpine.tag);
    try testing.expectEqualStrings("3.19", alpine.written_tag);

    const official = parseImageRef("library/alpine:3.19").?;
    try testing.expectEqualStrings("library/alpine", official.name);

    const docker_io = parseImageRef("docker.io/library/alpine:3.19").?;
    try testing.expectEqual(Registry.docker_hub, docker_io.registry);
    try testing.expectEqualStrings("library/alpine", docker_io.name);

    const ghcr = parseImageRef("ghcr.io/owner/image:tag").?;
    try testing.expectEqual(Registry.ghcr, ghcr.registry);
    try testing.expectEqualStrings("owner/image", ghcr.name);
    try testing.expectEqualStrings("tag", ghcr.tag);

    const latest = parseImageRef("alpine").?;
    try testing.expectEqualStrings("latest", latest.tag);
    try testing.expectEqualStrings("", latest.written_tag);

    const docker_uses = parseImageRef("docker://alpine:3.19").?;
    try testing.expectEqualStrings("alpine", docker_uses.name);
    try testing.expectEqualStrings("3.19", docker_uses.tag);
}

test "parseImageRef: pinned, expression, and unsupported host are skipped" {
    try testing.expect(parseImageRef("alpine@sha256:abc") == null);
    try testing.expect(parseImageRef("alpine:${{ env.TAG }}") == null);
    try testing.expect(parseImageRef("quay.io/foo/bar:1") == null);
    try testing.expect(parseImageRef("gcr.io/proj/img:v1") == null);
    try testing.expect(parseImageRef("docker://") == null);
}

test "digests: inactive lookup returns null" {
    deinitDigests();
    setCachedDigest("docker.io", "alpine", "3.19", valid_digest);
    try testing.expect(lookupDigest("docker.io", "alpine", "3.19") == null);
    try testing.expect(!isActive());
}

test "digests: offline init leaves the store inactive" {
    initDigests(testing.allocator, true, true);
    defer deinitDigests();
    try testing.expect(!isActive());
}

test "digests: unwanted init leaves the store inactive" {
    initDigests(testing.allocator, false, false);
    defer deinitDigests();
    try testing.expect(!isActive());
}

test "digests: round-trips a stored digest" {
    initDigests(testing.allocator, false, true);
    defer deinitDigests();
    setCachedDigest("docker.io", "alpine", "3.19", valid_digest);
    try testing.expectEqualStrings(valid_digest, lookupDigest("docker.io", "alpine", "3.19").?);
}

test "digests: rejects a malformed digest" {
    initDigests(testing.allocator, false, true);
    defer deinitDigests();
    setCachedDigest("docker.io", "alpine", "3.19", "not-a-digest");
    setCachedDigest("docker.io", "alpine", "3.18", "sha256:ABCDEF");
    try testing.expect(lookupDigest("docker.io", "alpine", "3.19") == null);
    try testing.expect(lookupDigest("docker.io", "alpine", "3.18") == null);
}

test "digestOfBody: SHA-256 of the decoded body, lowercase hex" {
    const got = digestOfBody(testing.allocator, "hello").?;
    defer testing.allocator.free(got);
    try testing.expect(isValidDigest(got));
    try testing.expectEqualStrings(
        "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        got,
    );
}

test "bearerFromTokenJson: token or access_token" {
    const a = bearerFromTokenJson(testing.allocator, "{\"token\":\"abc\"}").?;
    defer testing.allocator.free(a);
    try testing.expectEqualStrings("Bearer abc", a);

    const b = bearerFromTokenJson(testing.allocator, "{\"access_token\":\"xyz\"}").?;
    defer testing.allocator.free(b);
    try testing.expectEqualStrings("Bearer xyz", b);

    try testing.expect(bearerFromTokenJson(testing.allocator, "{}") == null);
    try testing.expect(bearerFromTokenJson(testing.allocator, "not json") == null);
}
