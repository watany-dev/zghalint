//! When the GraphQL batch path is unavailable (no `GITHUB_TOKEN`, transport
//! error, etc.) the prefetch orchestrator and the lazy per-step rule paths
//! fall back to single REST calls. Those calls are collected here so each
//! rule file only contains domain logic, not HTTP plumbing.

const std = @import("std");

const rules_engine = @import("engine.zig");
const http_client = @import("http_client.zig");
const json_util = @import("json_util.zig");

const Allocator = std.mem.Allocator;

/// Built on top of `http_client.FetchedError` so that transport-level
/// failures propagate to callers without being collapsed into the
/// REST-specific ones.
pub const RestError = http_client.FetchedError || error{
    HttpError,
    JsonParseError,
    UnexpectedFormat,
    MissingField,
};

pub const TagResolution = enum {
    has_tag,
    no_tag,
    unknown,
};

pub const RefStatus = enum {
    ambiguous,
    not_ambiguous,
    fetch_failed,
};

/// Once GitHub returns 403 / 429 we stop issuing further REST ref-existence
/// queries for the lifetime of the process. This flag lives here, not in
/// `refconfusion.zig`, because it is owned by the REST transport layer.
var rate_limited: bool = false;

pub fn resetRateLimit() void {
    rate_limited = false;
}

pub fn fetchArchiveStatus(allocator: Allocator, owner: []const u8, repo: []const u8) RestError!bool {
    const url = try std.fmt.allocPrint(allocator, "https://api.github.com/repos/{s}/{s}", .{ owner, repo });
    defer allocator.free(url);

    var resp = try http_client.fetchAuthenticatedJson(allocator, url);
    defer resp.deinit();

    if (resp.status != .ok) return error.HttpError;

    return parseArchivedField(allocator, resp.body);
}

fn parseArchivedField(allocator: Allocator, body: []const u8) RestError!bool {
    const root = std.json.parseFromSliceLeaky(std.json.Value, allocator, body, .{}) catch return error.JsonParseError;

    const obj = json_util.asObject(root) orelse return error.UnexpectedFormat;
    const archived_val = obj.get("archived") orelse return error.MissingField;
    return json_util.asBool(archived_val) orelse error.UnexpectedFormat;
}

/// Returns `unknown` for any HTTP failure so the rule can fail open instead
/// of misfiring.
pub fn resolveTagForSha(
    allocator: Allocator,
    owner: []const u8,
    repo: []const u8,
    sha: []const u8,
) RestError!TagResolution {
    var out: [1]TagResolution = undefined;
    try resolveTagsForShas(allocator, owner, repo, &.{sha}, &out);
    return out[0];
}

/// Resolves every SHA pinned to one repository against a single tag listing.
/// The listing is per-repo, not per-SHA, so a workflow pinning N actions from
/// the same repository costs one request instead of N.
///
/// `out` must be the same length as `shas`; results are written positionally
/// and every entry is initialized, so a caller reads valid data even when the
/// request fails.
pub fn resolveTagsForShas(
    allocator: Allocator,
    owner: []const u8,
    repo: []const u8,
    shas: []const []const u8,
    out: []TagResolution,
) RestError!void {
    std.debug.assert(out.len == shas.len);
    @memset(out, .unknown);
    if (shas.len == 0) return;

    const url = try std.fmt.allocPrint(
        allocator,
        "https://api.github.com/repos/{s}/{s}/git/matching-refs/tags/?per_page=100",
        .{ owner, repo },
    );
    defer allocator.free(url);

    var resp = try http_client.fetchAuthenticatedJson(allocator, url);
    defer resp.deinit();

    if (resp.status != .ok) return;

    matchShasInRefs(allocator, resp.body, shas, out, owner, repo);
}

fn matchShasInRefs(
    allocator: Allocator,
    body: []const u8,
    targets: []const []const u8,
    out: []TagResolution,
    owner: []const u8,
    repo: []const u8,
) void {
    @memset(out, .unknown);

    const root = std.json.parseFromSliceLeaky(std.json.Value, allocator, body, .{}) catch return;

    const items = switch (root) {
        .array => |arr| arr.items,
        else => return,
    };

    if (items.len == 0) return;

    var annotated_shas: [64][]const u8 = undefined;
    var annotated_count: usize = 0;

    var unresolved = targets.len;

    for (items) |item| {
        const obj = json_util.asObject(item) orelse continue;
        const ref_obj = json_util.objField(obj, "object") orelse continue;

        const obj_sha = json_util.stringField(ref_obj, "sha") orelse continue;
        const obj_type = json_util.stringField(ref_obj, "type") orelse continue;

        if (std.mem.eql(u8, obj_type, "commit")) {
            unresolved -= markMatches(obj_sha, targets, out);
        } else if (std.mem.eql(u8, obj_type, "tag")) {
            if (annotated_count < annotated_shas.len) {
                annotated_shas[annotated_count] = obj_sha;
                annotated_count += 1;
            }
        }
    }

    // Each annotated tag is dereferenced once and compared against every
    // still-unresolved target, rather than once per target.
    for (annotated_shas[0..annotated_count]) |tag_sha| {
        if (unresolved == 0) break;
        const commit_sha = dereferenceAnnotatedTag(allocator, owner, repo, tag_sha) catch continue;
        unresolved -= markMatches(commit_sha, targets, out);
    }

    // A full page means the listing may be truncated, so an absent SHA cannot
    // be distinguished from one on a page we never fetched.
    if (items.len >= 100) return;

    for (out) |*res| {
        if (res.* != .has_tag) res.* = .no_tag;
    }
}

/// Single-target convenience over `matchShasInRefs`, kept because the
/// one-SHA shape is what most call sites and tests reason about.
fn matchShaInRefs(allocator: Allocator, body: []const u8, target_sha: []const u8, owner: []const u8, repo: []const u8) TagResolution {
    var out: [1]TagResolution = undefined;
    matchShasInRefs(allocator, body, &.{target_sha}, &out, owner, repo);
    return out[0];
}

/// Returns how many entries flipped to `has_tag`, so the caller can stop
/// dereferencing annotated tags once every target is resolved.
fn markMatches(candidate_sha: []const u8, targets: []const []const u8, out: []TagResolution) usize {
    var newly: usize = 0;
    for (targets, out) |target, *res| {
        if (res.* == .has_tag) continue;
        if (!std.mem.eql(u8, candidate_sha, target)) continue;
        res.* = .has_tag;
        newly += 1;
    }
    return newly;
}

fn dereferenceAnnotatedTag(allocator: Allocator, owner: []const u8, repo: []const u8, tag_sha: []const u8) RestError![]const u8 {
    const url = try std.fmt.allocPrint(
        allocator,
        "https://api.github.com/repos/{s}/{s}/git/tags/{s}",
        .{ owner, repo, tag_sha },
    );
    defer allocator.free(url);

    var resp = try http_client.fetchAuthenticatedJson(allocator, url);
    defer resp.deinit();

    if (resp.status != .ok) return error.HttpError;

    return parseTagObject(resp.body);
}

fn parseTagObject(body: []const u8) RestError![]const u8 {
    var buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);

    const root = std.json.parseFromSliceLeaky(std.json.Value, fba.allocator(), body, .{}) catch return error.JsonParseError;

    const obj = json_util.asObject(root) orelse return error.UnexpectedFormat;
    const inner = json_util.objField(obj, "object") orelse return error.UnexpectedFormat;

    const obj_type = json_util.stringField(inner, "type") orelse return error.UnexpectedFormat;
    if (!std.mem.eql(u8, obj_type, "commit")) return error.UnexpectedFormat;

    return json_util.stringField(inner, "sha") orelse error.UnexpectedFormat;
}

pub fn queryRefStatus(allocator: Allocator, owner: []const u8, repo: []const u8, ref: []const u8) RefStatus {
    if (rate_limited) return .fetch_failed;

    const tag_exists = checkRefExists(allocator, owner, repo, ref, "tags") orelse return .fetch_failed;
    const branch_exists = checkRefExists(allocator, owner, repo, ref, "heads") orelse return .fetch_failed;

    if (tag_exists and branch_exists) return .ambiguous;
    return .not_ambiguous;
}

pub const CompareStatus = enum { reachable, unreachable_, unknown };

/// Any non-200 response or parse failure returns `.unknown` so SC008
/// fail-closes on uncertainty.
pub fn compareRest(
    scratch: Allocator,
    owner: []const u8,
    repo: []const u8,
    base: []const u8,
    head: []const u8,
) CompareStatus {
    if (!rules_engine.isValidGitHubComponent(owner)) return .unknown;
    if (!rules_engine.isValidGitHubComponent(repo)) return .unknown;
    if (!rules_engine.isValidGitRef(base)) return .unknown;
    if (!rules_engine.isValidSha(head)) return .unknown;

    // Branch/tag names can contain '/' (e.g. "release/v1.0"). Percent-encode
    // the base segment so the compare endpoint doesn't route those characters
    // as extra path components and force us into a fail-closed unknown.
    const base_encoded = percentEncodePathSegment(scratch, base) orelse return .unknown;

    const url = std.fmt.allocPrint(
        scratch,
        "https://api.github.com/repos/{s}/{s}/compare/{s}...{s}",
        .{ owner, repo, base_encoded, head },
    ) catch return .unknown;

    var resp = http_client.fetchAuthenticatedJson(scratch, url) catch return .unknown;
    defer resp.deinit();

    if (resp.status != .ok) return .unknown;

    return parseCompareStatus(scratch, resp.body);
}

fn parseCompareStatus(scratch: Allocator, body: []const u8) CompareStatus {
    const root = std.json.parseFromSliceLeaky(std.json.Value, scratch, body, .{}) catch return .unknown;
    const obj = json_util.asObject(root) orelse return .unknown;
    const status = json_util.stringField(obj, "status") orelse return .unknown;
    if (std.mem.eql(u8, status, "identical") or std.mem.eql(u8, status, "behind")) {
        return .reachable;
    }
    if (std.mem.eql(u8, status, "ahead") or std.mem.eql(u8, status, "diverged")) {
        return .unreachable_;
    }
    return .unknown;
}

fn percentEncodePathSegment(scratch: Allocator, s: []const u8) ?[]const u8 {
    for (s) |c| {
        if (!isUnreserved(c)) break;
    } else return s;

    var out: std.Io.Writer.Allocating = .init(scratch);
    std.Uri.Component.percentEncode(&out.writer, s, isUnreserved) catch return null;
    return out.written();
}

fn isUnreserved(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => true,
        else => false,
    };
}

fn checkRefExists(allocator: Allocator, owner: []const u8, repo: []const u8, ref: []const u8, ref_type: []const u8) ?bool {
    const url = std.fmt.allocPrint(allocator, "https://api.github.com/repos/{s}/{s}/git/ref/{s}/{s}", .{ owner, repo, ref_type, ref }) catch return null;
    defer allocator.free(url);

    var resp = http_client.fetchAuthenticatedJson(allocator, url) catch return null;
    defer resp.deinit();

    if (resp.status == .ok) return true;
    if (resp.status == .not_found) return false;

    if (resp.status == .forbidden or resp.status == .too_many_requests) {
        rate_limited = true;
    }
    return null;
}

const testing = std.testing;

test "parseArchivedField: archived true" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body = "{\"archived\": true, \"name\": \"repo\"}";
    try testing.expect(try parseArchivedField(arena.allocator(), body));
}

test "parseArchivedField: archived false" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body = "{\"archived\": false}";
    try testing.expect(!(try parseArchivedField(arena.allocator(), body)));
}

test "parseArchivedField: missing field" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body = "{\"name\": \"repo\"}";
    try testing.expectError(error.MissingField, parseArchivedField(arena.allocator(), body));
}

test "parseArchivedField: non-object" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body = "[1, 2, 3]";
    try testing.expectError(error.UnexpectedFormat, parseArchivedField(arena.allocator(), body));
}

test "parseArchivedField: malformed JSON" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body = "{not json";
    try testing.expectError(error.JsonParseError, parseArchivedField(arena.allocator(), body));
}

test "parseTagObject: extracts inner commit sha" {
    const body = "{\"object\": {\"sha\": \"abc123\", \"type\": \"commit\"}}";
    const sha = try parseTagObject(body);
    try testing.expectEqualStrings("abc123", sha);
}

test "parseTagObject: rejects nested tag" {
    const body = "{\"object\": {\"sha\": \"abc\", \"type\": \"tag\"}}";
    try testing.expectError(error.UnexpectedFormat, parseTagObject(body));
}

test "matchShaInRefs: lightweight tag match" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body =
        \\[{"ref":"refs/tags/v1","object":{"sha":"abc","type":"commit"}}]
    ;
    const result = matchShaInRefs(arena.allocator(), body, "abc", "o", "r");
    try testing.expectEqual(TagResolution.has_tag, result);
}

test "matchShaInRefs: no match → no_tag (under page limit)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body =
        \\[{"ref":"refs/tags/v1","object":{"sha":"def","type":"commit"}}]
    ;
    const result = matchShaInRefs(arena.allocator(), body, "abc", "o", "r");
    try testing.expectEqual(TagResolution.no_tag, result);
}

test "matchShaInRefs: empty array → unknown" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const result = matchShaInRefs(arena.allocator(), "[]", "abc", "o", "r");
    try testing.expectEqual(TagResolution.unknown, result);
}

test "parseArchivedField: non-bool archived returns UnexpectedFormat" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body =
        \\{"archived":"yes"}
    ;
    try testing.expectError(
        error.UnexpectedFormat,
        parseArchivedField(arena.allocator(), body),
    );
}

test "parseTagObject: malformed JSON returns error" {
    try testing.expectError(error.JsonParseError, parseTagObject("not json"));
}

test "parseTagObject: missing object field returns error" {
    const body =
        \\{"tag":"v1.0.0"}
    ;
    try testing.expectError(error.UnexpectedFormat, parseTagObject(body));
}

test "parseTagObject: non-object inner 'object' returns error" {
    const body =
        \\{"tag":"v1","object":"not-an-object"}
    ;
    try testing.expectError(error.UnexpectedFormat, parseTagObject(body));
}

test "parseTagObject: inner missing sha returns error" {
    const body =
        \\{"tag":"v1","object":{"type":"commit"}}
    ;
    try testing.expectError(error.UnexpectedFormat, parseTagObject(body));
}

test "matchShaInRefs: invalid JSON returns unknown" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const result = matchShaInRefs(arena.allocator(), "not json", "abc", "o", "r");
    try testing.expectEqual(TagResolution.unknown, result);
}

test "matchShaInRefs: non-array JSON returns unknown" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body =
        \\{"message":"Not Found"}
    ;
    const result = matchShaInRefs(arena.allocator(), body, "abc", "o", "r");
    try testing.expectEqual(TagResolution.unknown, result);
}

test "matchShaInRefs: multiple lightweight tags, one matches" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body =
        \\[
        \\  {"ref":"refs/tags/v1.0.0","object":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","type":"commit"}},
        \\  {"ref":"refs/tags/v2.0.0","object":{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","type":"commit"}}
        \\]
    ;
    const result = matchShaInRefs(arena.allocator(), body, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "o", "r");
    try testing.expectEqual(TagResolution.has_tag, result);
}

test "matchShasInRefs: resolves several SHAs from one listing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body =
        \\[
        \\  {"ref":"refs/tags/v1","object":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","type":"commit"}},
        \\  {"ref":"refs/tags/v2","object":{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","type":"commit"}}
        \\]
    ;
    const targets = [_][]const u8{
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "cccccccccccccccccccccccccccccccccccccccc",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    };
    var out: [3]TagResolution = undefined;
    matchShasInRefs(arena.allocator(), body, &targets, &out, "o", "r");

    try testing.expectEqual(TagResolution.has_tag, out[0]);
    try testing.expectEqual(TagResolution.no_tag, out[1]);
    try testing.expectEqual(TagResolution.has_tag, out[2]);
}

test "matchShasInRefs: pagination guard leaves unmatched targets unknown" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(testing.allocator);
    try buf.append(testing.allocator, '[');
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        if (i != 0) try buf.append(testing.allocator, ',');
        try buf.writer(testing.allocator).print(
            "{{\"ref\":\"refs/tags/v{d}\",\"object\":{{\"sha\":\"{x:0>40}\",\"type\":\"commit\"}}}}",
            .{ i, i },
        );
    }
    try buf.append(testing.allocator, ']');

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const targets = [_][]const u8{
        "0000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffffffffffff",
    };
    var out: [2]TagResolution = undefined;
    matchShasInRefs(arena.allocator(), buf.items, &targets, &out, "o", "r");

    try testing.expectEqual(TagResolution.has_tag, out[0]);
    try testing.expectEqual(TagResolution.unknown, out[1]);
}

test "resolveTagsForShas: empty input is a no-op that issues no request" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    // An expired deadline would make any real request fail, so reaching the
    // early return proves nothing was fetched.
    rules_engine.network_deadline_ns = std.time.nanoTimestamp() - 1;
    defer rules_engine.clearNetworkDeadline();

    var out: [0]TagResolution = undefined;
    try resolveTagsForShas(arena.allocator(), "o", "r", &.{}, &out);
}

test "matchShaInRefs: annotated tags fail to dereference offline -> no_tag" {
    rules_engine.network_deadline_ns = std.time.nanoTimestamp() - 1;
    defer rules_engine.clearNetworkDeadline();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body =
        \\[
        \\  {"ref":"refs/tags/v1","object":{"sha":"tagsha111111111111111111111111111111111","type":"tag"}},
        \\  {"ref":"refs/tags/v2","object":{"sha":"tagsha222222222222222222222222222222222","type":"tag"}}
        \\]
    ;
    const result = matchShaInRefs(arena.allocator(), body, "ffffffffffffffffffffffffffffffffffffffff", "o", "r");
    try testing.expectEqual(TagResolution.no_tag, result);
}

test "matchShaInRefs: >= 100 items with no match -> unknown (pagination guard)" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(testing.allocator);
    try buf.append(testing.allocator, '[');
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        if (i != 0) try buf.append(testing.allocator, ',');
        try buf.writer(testing.allocator).print(
            "{{\"ref\":\"refs/tags/v{d}\",\"object\":{{\"sha\":\"{x:0>40}\",\"type\":\"commit\"}}}}",
            .{ i, i },
        );
    }
    try buf.append(testing.allocator, ']');

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const result = matchShaInRefs(arena.allocator(), buf.items, "ffffffffffffffffffffffffffffffffffffffff", "o", "r");
    try testing.expectEqual(TagResolution.unknown, result);
}

test "matchShaInRefs: non-object items and missing object/type are skipped" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const body =
        \\[
        \\  42,
        \\  {"ref":"refs/tags/v0"},
        \\  {"ref":"refs/tags/v1","object":"not-an-object"},
        \\  {"ref":"refs/tags/v2","object":{"type":"commit"}},
        \\  {"ref":"refs/tags/v3","object":{"sha":"abc"}},
        \\  {"ref":"refs/tags/v4","object":{"sha":"hit","type":"commit"}}
        \\]
    ;
    const result = matchShaInRefs(arena.allocator(), body, "hit", "o", "r");
    try testing.expectEqual(TagResolution.has_tag, result);
}

test "parseCompareStatus: identical and behind are reachable" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqual(CompareStatus.reachable, parseCompareStatus(arena.allocator(), "{\"status\":\"identical\"}"));
    try testing.expectEqual(CompareStatus.reachable, parseCompareStatus(arena.allocator(), "{\"status\":\"behind\"}"));
}

test "parseCompareStatus: ahead and diverged are unreachable" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqual(CompareStatus.unreachable_, parseCompareStatus(arena.allocator(), "{\"status\":\"ahead\"}"));
    try testing.expectEqual(CompareStatus.unreachable_, parseCompareStatus(arena.allocator(), "{\"status\":\"diverged\"}"));
}

test "parseCompareStatus: unknown / malformed inputs map to unknown" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqual(CompareStatus.unknown, parseCompareStatus(arena.allocator(), "{\"status\":\"weird\"}"));
    try testing.expectEqual(CompareStatus.unknown, parseCompareStatus(arena.allocator(), "{}"));
    try testing.expectEqual(CompareStatus.unknown, parseCompareStatus(arena.allocator(), "not-json"));
    try testing.expectEqual(CompareStatus.unknown, parseCompareStatus(arena.allocator(), "[\"array\"]"));
}

test "compareRest: invalid component arguments fail closed to unknown without network" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    try testing.expectEqual(CompareStatus.unknown, compareRest(alloc, "..", "r", "main", "0000000000000000000000000000000000000000"));
    try testing.expectEqual(CompareStatus.unknown, compareRest(alloc, "o", "..", "main", "0000000000000000000000000000000000000000"));
    try testing.expectEqual(CompareStatus.unknown, compareRest(alloc, "o", "r", "../evil", "0000000000000000000000000000000000000000"));
    try testing.expectEqual(CompareStatus.unknown, compareRest(alloc, "o", "r", "main", "not-a-sha"));
}

test "percentEncodePathSegment: refs with slashes are encoded" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const out = percentEncodePathSegment(alloc, "release/v1.0").?;
    try testing.expectEqualStrings("release%2Fv1.0", out);
}

test "percentEncodePathSegment: plain ref passes through unchanged" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const s = "main";
    const out = percentEncodePathSegment(alloc, s).?;
    // Unchanged inputs return the original slice without allocation.
    try testing.expectEqual(s.ptr, out.ptr);
    try testing.expectEqualStrings("main", out);
}

test "percentEncodePathSegment: nested slashes and dots encode correctly" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const out = percentEncodePathSegment(alloc, "feature/foo/bar-1.2_3").?;
    try testing.expectEqualStrings("feature%2Ffoo%2Fbar-1.2_3", out);
}
