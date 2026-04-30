//! REST fallback for GitHub repository metadata.
//!
//! When the GraphQL batch path is unavailable (no `GITHUB_TOKEN`, transport
//! error, etc.) the prefetch orchestrator and the lazy per-step rule paths
//! fall back to single REST calls. This module collects those calls in one
//! place so each rule file only contains domain logic, not HTTP plumbing.
//!
//! The eight-step fetch ritual (URL alloc, allocating writer, auth header,
//! standard headers, fetch, status branch, body parse) used to live in five
//! callsites across `archived.zig`, `stale_refs.zig`, `refconfusion.zig`, and
//! `impostor_compare.zig`. This module replaces four of them; the
//! `compareRest` callsite is left for a follow-up tidy.

const std = @import("std");

const http_client = @import("http_client.zig");

const Allocator = std.mem.Allocator;

// ============================================================
// Public types
// ============================================================

pub const RestError = error{
    FetchFailed,
    HttpError,
    JsonParseError,
    UnexpectedFormat,
    MissingField,
    OutOfMemory,
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

// ============================================================
// Module-level rate-limit flag for SC006
// ============================================================

/// Once GitHub returns 403 / 429 we stop issuing further REST ref-existence
/// queries for the lifetime of the process. This flag lives here, not in
/// `refconfusion.zig`, because it is owned by the REST transport layer.
var rate_limited: bool = false;

pub fn resetRateLimit() void {
    rate_limited = false;
}

pub fn isRateLimited() bool {
    return rate_limited;
}

// ============================================================
// SC004: archived repository
// ============================================================

/// Fetch the `archived` flag for `owner/repo` via the REST endpoint
/// `GET /repos/{owner}/{repo}`.
pub fn fetchArchiveStatus(allocator: Allocator, owner: []const u8, repo: []const u8) RestError!bool {
    const url = std.fmt.allocPrint(allocator, "https://api.github.com/repos/{s}/{s}", .{ owner, repo }) catch return error.OutOfMemory;
    defer allocator.free(url);

    var resp = http_client.fetchAuthenticatedJson(allocator, url) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.FetchFailed,
    };
    defer resp.deinit();

    if (resp.status != .ok) return error.HttpError;

    return parseArchivedField(allocator, resp.body);
}

fn parseArchivedField(allocator: Allocator, body: []const u8) RestError!bool {
    const root = std.json.parseFromSliceLeaky(std.json.Value, allocator, body, .{}) catch return error.JsonParseError;

    const obj = switch (root) {
        .object => |o| o,
        else => return error.UnexpectedFormat,
    };

    const archived_val = obj.get("archived") orelse return error.MissingField;
    return switch (archived_val) {
        .bool => |b| b,
        else => error.UnexpectedFormat,
    };
}

// ============================================================
// SC005: stale SHA → tag resolution
// ============================================================

/// Resolve the tag relationship for `sha` by listing matching tag refs and
/// (where necessary) dereferencing annotated tags. Returns `unknown` for any
/// HTTP failure so the rule can fail open instead of misfiring.
pub fn resolveTagForSha(
    allocator: Allocator,
    owner: []const u8,
    repo: []const u8,
    sha: []const u8,
) RestError!TagResolution {
    const url = std.fmt.allocPrint(
        allocator,
        "https://api.github.com/repos/{s}/{s}/git/matching-refs/tags/?per_page=100",
        .{ owner, repo },
    ) catch return error.OutOfMemory;
    defer allocator.free(url);

    var resp = http_client.fetchAuthenticatedJson(allocator, url) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.FetchFailed,
    };
    defer resp.deinit();

    if (resp.status != .ok) return TagResolution.unknown;

    return matchShaInRefs(allocator, resp.body, sha, owner, repo);
}

fn matchShaInRefs(allocator: Allocator, body: []const u8, target_sha: []const u8, owner: []const u8, repo: []const u8) TagResolution {
    const root = std.json.parseFromSliceLeaky(std.json.Value, allocator, body, .{}) catch return .unknown;

    const items = switch (root) {
        .array => |arr| arr.items,
        else => return .unknown,
    };

    if (items.len == 0) return .unknown;

    var annotated_shas: [64][]const u8 = undefined;
    var annotated_count: usize = 0;

    for (items) |item| {
        const obj = switch (item) {
            .object => |o| o,
            else => continue,
        };
        const ref_obj_val = obj.get("object") orelse continue;
        const ref_obj = switch (ref_obj_val) {
            .object => |o| o,
            else => continue,
        };

        const obj_sha = getJsonString(ref_obj, "sha") orelse continue;
        const obj_type = getJsonString(ref_obj, "type") orelse continue;

        if (std.mem.eql(u8, obj_type, "commit")) {
            if (std.mem.eql(u8, obj_sha, target_sha)) return .has_tag;
        } else if (std.mem.eql(u8, obj_type, "tag")) {
            if (annotated_count < annotated_shas.len) {
                annotated_shas[annotated_count] = obj_sha;
                annotated_count += 1;
            }
        }
    }

    for (annotated_shas[0..annotated_count]) |tag_sha| {
        const commit_sha = dereferenceAnnotatedTag(allocator, owner, repo, tag_sha) catch continue;
        if (std.mem.eql(u8, commit_sha, target_sha)) return .has_tag;
    }

    if (items.len >= 100) return .unknown;

    return .no_tag;
}

fn dereferenceAnnotatedTag(allocator: Allocator, owner: []const u8, repo: []const u8, tag_sha: []const u8) RestError![]const u8 {
    const url = std.fmt.allocPrint(
        allocator,
        "https://api.github.com/repos/{s}/{s}/git/tags/{s}",
        .{ owner, repo, tag_sha },
    ) catch return error.OutOfMemory;
    defer allocator.free(url);

    var resp = http_client.fetchAuthenticatedJson(allocator, url) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.FetchFailed,
    };
    defer resp.deinit();

    if (resp.status != .ok) return error.HttpError;

    return parseTagObject(resp.body);
}

/// Parse a Git tag object response and extract the target commit SHA.
/// Response format: { "object": { "sha": "...", "type": "commit" } }
fn parseTagObject(body: []const u8) RestError![]const u8 {
    var buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);

    const root = std.json.parseFromSliceLeaky(std.json.Value, fba.allocator(), body, .{}) catch return error.JsonParseError;

    const obj = switch (root) {
        .object => |o| o,
        else => return error.UnexpectedFormat,
    };

    const inner_val = obj.get("object") orelse return error.UnexpectedFormat;
    const inner = switch (inner_val) {
        .object => |o| o,
        else => return error.UnexpectedFormat,
    };

    const obj_type = getJsonString(inner, "type") orelse return error.UnexpectedFormat;
    if (!std.mem.eql(u8, obj_type, "commit")) return error.UnexpectedFormat;

    return getJsonString(inner, "sha") orelse error.UnexpectedFormat;
}

fn getJsonString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const val = obj.get(key) orelse return null;
    return switch (val) {
        .string => |s| s,
        else => null,
    };
}

// ============================================================
// SC006: tag/branch ref existence
// ============================================================

/// Probe whether `ref` exists as a tag, a branch, or both. Sets the module
/// rate-limit flag on 403 / 429 and returns `fetch_failed` for the lifetime
/// of the process once tripped.
pub fn queryRefStatus(allocator: Allocator, owner: []const u8, repo: []const u8, ref: []const u8) RefStatus {
    if (rate_limited) return .fetch_failed;

    const tag_exists = checkRefExists(allocator, owner, repo, ref, "tags") orelse return .fetch_failed;
    const branch_exists = checkRefExists(allocator, owner, repo, ref, "heads") orelse return .fetch_failed;

    if (tag_exists and branch_exists) return .ambiguous;
    return .not_ambiguous;
}

/// Returns true on HTTP 200, false on HTTP 404, null on any other status
/// (rate-limited responses also flip the module flag).
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

// ============================================================
// Tests
// ============================================================

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

test "rate_limited flag round-trip" {
    resetRateLimit();
    try testing.expect(!isRateLimited());
    rate_limited = true;
    try testing.expect(isRateLimited());
    resetRateLimit();
    try testing.expect(!isRateLimited());
}
