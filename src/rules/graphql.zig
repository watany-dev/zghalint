//! GitHub GraphQL batching for SC004/SC005/SC006.
//!
//! When a `GITHUB_TOKEN` is available, the prefetch orchestrator can
//! collapse many REST requests into one GraphQL POST. Each repository's
//! archive status, SHA-to-tag resolutions, and ambiguous-ref checks are
//! folded into a single query using alias namespacing (`r0`, `r1`, ...).
//!
//! Annotated tag dereferencing, which the REST path performs with N extra
//! requests per repository, is done inline here via the
//! `... on Tag { target { oid } }` fragment.

const std = @import("std");
const http_client = @import("http_client.zig");

const Allocator = std.mem.Allocator;

// ============================================================
// Public types
// ============================================================

pub const GraphQlError = error{
    RequestFailed,
    ParseFailed,
    RateLimited,
    OutOfMemory,
    NoToken,
};

pub const RepoInput = struct {
    owner: []const u8,
    repo: []const u8,
    /// SHAs for SC005 (stale action refs): "does this SHA map to a tag?"
    sha_refs: []const []const u8 = &.{},
    /// Non-SHA refs for SC006 (ref confusion): "is this name both tag + branch?"
    named_refs: []const []const u8 = &.{},
};

pub const ShaTagResolution = enum { has_tag, no_tag, unknown };

pub const ShaTagResult = struct {
    sha: []const u8,
    resolution: ShaTagResolution,
};

pub const NamedRefResult = struct {
    ref: []const u8,
    is_tag: bool,
    is_branch: bool,
};

pub const RepoResult = struct {
    owner: []const u8,
    repo: []const u8,
    archived: ?bool = null,
    sha_results: []const ShaTagResult = &.{},
    named_results: []const NamedRefResult = &.{},
    /// True if the API returned the repo as missing / permission-denied.
    missing: bool = false,
};

// ============================================================
// Query building
// ============================================================

/// Maximum repos per batch. Each repo can add ~1 + 2*named_refs fields; 30
/// keeps us well below GraphQL's default node limit of 500k.
pub const max_repos_per_batch: usize = 30;

/// Build a GraphQL query body for the given repo inputs. Caller owns the
/// returned slice.
pub fn buildQuery(allocator: Allocator, repos: []const RepoInput) ![]const u8 {
    var buf = std.ArrayList(u8){};
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "query {");

    for (repos, 0..) |repo, idx| {
        try buf.writer(allocator).print(
            " r{d}: repository(owner:\"{s}\", name:\"{s}\") {{ isArchived",
            .{ idx, repo.owner, repo.repo },
        );

        for (repo.named_refs, 0..) |named, j| {
            try buf.writer(allocator).print(
                " tag_{d}: ref(qualifiedName:\"refs/tags/{s}\") {{ name }} branch_{d}: ref(qualifiedName:\"refs/heads/{s}\") {{ name }}",
                .{ j, named, j, named },
            );
        }

        if (repo.sha_refs.len > 0) {
            // Fetch up to 100 tags; inline-dereference annotated tags so we
            // see the underlying commit oid in a single round trip.
            try buf.appendSlice(
                allocator,
                " tagNodes: refs(refPrefix:\"refs/tags/\", first:100) { nodes { name target { oid ... on Tag { target { oid } } } } }",
            );
        }

        try buf.appendSlice(allocator, " }");
    }

    try buf.appendSlice(allocator, " }");
    return buf.toOwnedSlice(allocator);
}

// ============================================================
// POST driver
// ============================================================

const endpoint: []const u8 = "https://api.github.com/graphql";

/// Execute a GraphQL batch. Requires `GITHUB_TOKEN`. Caller owns the
/// returned `RepoResult` slice; its inner slices are allocated from the
/// same allocator.
pub fn batchQuery(
    allocator: Allocator,
    repos: []const RepoInput,
) GraphQlError![]const RepoResult {
    if (repos.len == 0) return &[_]RepoResult{};

    const auth_value = http_client.getAuthHeader(allocator) orelse return error.NoToken;
    defer allocator.free(auth_value);

    const query = buildQuery(allocator, repos) catch return error.OutOfMemory;
    defer allocator.free(query);

    const body = encodeRequestBody(allocator, query) catch return error.OutOfMemory;
    defer allocator.free(body);

    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();

    var headers_buf: [4]std.http.Header = undefined;
    var header_count = http_client.writeStandardHeaders(&headers_buf, auth_value);
    headers_buf[header_count] = .{ .name = "Content-Type", .value = "application/json" };
    header_count += 1;

    const result = http_client.fetch(.{
        .location = .{ .url = endpoint },
        .method = .POST,
        .payload = body,
        .response_writer = &aw.writer,
        .headers = .{ .user_agent = .{ .override = http_client.user_agent } },
        .extra_headers = headers_buf[0..header_count],
    }) catch return error.RequestFailed;

    if (result.status == .forbidden or result.status == .too_many_requests) {
        return error.RateLimited;
    }
    if (result.status != .ok) return error.RequestFailed;

    var response_list = aw.toArrayList();
    defer response_list.deinit(allocator);

    return parseResponse(allocator, response_list.items, repos) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.ParseFailed,
    };
}

fn encodeRequestBody(allocator: Allocator, query: []const u8) ![]const u8 {
    // Manual encoding is sufficient: the query we build never contains
    // control characters, backslashes, or double quotes (GitHub component
    // validation already filters those), so escaping is trivial.
    var buf = std.ArrayList(u8){};
    errdefer buf.deinit(allocator);
    try buf.appendSlice(allocator, "{\"query\":\"");
    for (query) |c| {
        switch (c) {
            '"' => try buf.appendSlice(allocator, "\\\""),
            '\\' => try buf.appendSlice(allocator, "\\\\"),
            '\n' => try buf.appendSlice(allocator, "\\n"),
            else => try buf.append(allocator, c),
        }
    }
    try buf.appendSlice(allocator, "\"}");
    return buf.toOwnedSlice(allocator);
}

// ============================================================
// Response parsing
// ============================================================

fn parseResponse(
    allocator: Allocator,
    body: []const u8,
    repos: []const RepoInput,
) ![]const RepoResult {
    const root = std.json.parseFromSliceLeaky(std.json.Value, allocator, body, .{}) catch return error.ParseFailed;

    const root_obj = switch (root) {
        .object => |o| o,
        else => return error.ParseFailed,
    };

    // If "errors" is present without "data" we treat it as a rate limit.
    if (root_obj.get("data") == null) {
        if (root_obj.get("errors")) |_| return error.ParseFailed;
        return error.ParseFailed;
    }

    const data = switch (root_obj.get("data").?) {
        .object => |o| o,
        .null => return try defaultMissingResults(allocator, repos),
        else => return error.ParseFailed,
    };

    var results = try allocator.alloc(RepoResult, repos.len);

    for (repos, 0..) |repo, idx| {
        var alias_buf: [16]u8 = undefined;
        const alias = std.fmt.bufPrint(&alias_buf, "r{d}", .{idx}) catch unreachable;

        const entry = data.get(alias) orelse {
            results[idx] = .{ .owner = repo.owner, .repo = repo.repo, .missing = true };
            continue;
        };

        results[idx] = switch (entry) {
            .null => .{ .owner = repo.owner, .repo = repo.repo, .missing = true },
            .object => |obj| try parseRepoObject(allocator, repo, obj),
            else => .{ .owner = repo.owner, .repo = repo.repo, .missing = true },
        };
    }

    return results;
}

fn defaultMissingResults(allocator: Allocator, repos: []const RepoInput) ![]const RepoResult {
    var results = try allocator.alloc(RepoResult, repos.len);
    for (repos, 0..) |repo, idx| {
        results[idx] = .{ .owner = repo.owner, .repo = repo.repo, .missing = true };
    }
    return results;
}

fn parseRepoObject(
    allocator: Allocator,
    repo: RepoInput,
    obj: std.json.ObjectMap,
) !RepoResult {
    var result: RepoResult = .{ .owner = repo.owner, .repo = repo.repo };

    if (obj.get("isArchived")) |v| {
        result.archived = switch (v) {
            .bool => |b| b,
            else => null,
        };
    }

    if (repo.named_refs.len > 0) {
        var named = try allocator.alloc(NamedRefResult, repo.named_refs.len);
        for (repo.named_refs, 0..) |ref_name, j| {
            var tag_buf: [24]u8 = undefined;
            var branch_buf: [24]u8 = undefined;
            const tag_alias = std.fmt.bufPrint(&tag_buf, "tag_{d}", .{j}) catch unreachable;
            const branch_alias = std.fmt.bufPrint(&branch_buf, "branch_{d}", .{j}) catch unreachable;

            const is_tag = refAliasExists(obj, tag_alias);
            const is_branch = refAliasExists(obj, branch_alias);
            named[j] = .{ .ref = ref_name, .is_tag = is_tag, .is_branch = is_branch };
        }
        result.named_results = named;
    }

    if (repo.sha_refs.len > 0) {
        // Collect all commit oids reachable from tag refs.
        var resolutions = try allocator.alloc(ShaTagResult, repo.sha_refs.len);
        const tag_shas = collectTagCommitShas(allocator, obj) catch &[_][]const u8{};
        defer if (tag_shas.len > 0) allocator.free(tag_shas);

        const tag_nodes_val = obj.get("tagNodes");
        const hit_page_limit = switch (tag_nodes_val orelse std.json.Value{ .null = {} }) {
            .object => |nodes_obj| blk: {
                const nodes_val = nodes_obj.get("nodes") orelse break :blk false;
                break :blk switch (nodes_val) {
                    .array => |arr| arr.items.len >= 100,
                    else => false,
                };
            },
            else => false,
        };

        for (repo.sha_refs, 0..) |sha, j| {
            var found = false;
            for (tag_shas) |oid| {
                if (std.mem.eql(u8, oid, sha)) {
                    found = true;
                    break;
                }
            }
            const resolution: ShaTagResolution = if (found) .has_tag else if (hit_page_limit) .unknown else .no_tag;
            resolutions[j] = .{ .sha = sha, .resolution = resolution };
        }
        result.sha_results = resolutions;
    }

    return result;
}

fn refAliasExists(obj: std.json.ObjectMap, alias: []const u8) bool {
    const val = obj.get(alias) orelse return false;
    return switch (val) {
        .object => true,
        else => false,
    };
}

fn collectTagCommitShas(
    allocator: Allocator,
    obj: std.json.ObjectMap,
) ![]const []const u8 {
    const tag_nodes_val = obj.get("tagNodes") orelse return &[_][]const u8{};
    const tag_nodes_obj = switch (tag_nodes_val) {
        .object => |o| o,
        else => return &[_][]const u8{},
    };
    const nodes_val = tag_nodes_obj.get("nodes") orelse return &[_][]const u8{};
    const nodes = switch (nodes_val) {
        .array => |a| a.items,
        else => return &[_][]const u8{},
    };

    var shas = std.ArrayList([]const u8){};
    errdefer shas.deinit(allocator);

    for (nodes) |node_val| {
        const node = switch (node_val) {
            .object => |o| o,
            else => continue,
        };
        const target_val = node.get("target") orelse continue;
        const target = switch (target_val) {
            .object => |o| o,
            else => continue,
        };

        // Direct oid (lightweight tag points at commit, or Tag.target.oid
        // for annotated tags sits one level deeper).
        if (target.get("oid")) |oid_val| {
            if (oid_val == .string) try shas.append(allocator, oid_val.string);
        }
        if (target.get("target")) |inner_val| {
            if (inner_val == .object) {
                if (inner_val.object.get("oid")) |oid2| {
                    if (oid2 == .string) try shas.append(allocator, oid2.string);
                }
            }
        }
    }

    return shas.toOwnedSlice(allocator);
}

// ============================================================
// Tests
// ============================================================

const testing = std.testing;

test "buildQuery: empty repos produces wrapper only" {
    const q = try buildQuery(testing.allocator, &.{});
    defer testing.allocator.free(q);
    try testing.expectEqualStrings("query { }", q);
}

test "buildQuery: single repo with no refs" {
    const repos = [_]RepoInput{.{ .owner = "actions", .repo = "checkout" }};
    const q = try buildQuery(testing.allocator, &repos);
    defer testing.allocator.free(q);
    try testing.expect(std.mem.indexOf(u8, q, "r0: repository(owner:\"actions\", name:\"checkout\")") != null);
    try testing.expect(std.mem.indexOf(u8, q, "isArchived") != null);
    try testing.expect(std.mem.indexOf(u8, q, "tagNodes") == null); // no SHAs → no tag fetch
}

test "buildQuery: named refs produce tag_ and branch_ aliases" {
    const named = [_][]const u8{ "main", "v4" };
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r", .named_refs = &named }};
    const q = try buildQuery(testing.allocator, &repos);
    defer testing.allocator.free(q);
    try testing.expect(std.mem.indexOf(u8, q, "tag_0: ref(qualifiedName:\"refs/tags/main\")") != null);
    try testing.expect(std.mem.indexOf(u8, q, "branch_0: ref(qualifiedName:\"refs/heads/main\")") != null);
    try testing.expect(std.mem.indexOf(u8, q, "tag_1: ref(qualifiedName:\"refs/tags/v4\")") != null);
}

test "buildQuery: sha refs pull in tagNodes subquery" {
    const shas = [_][]const u8{"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"};
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r", .sha_refs = &shas }};
    const q = try buildQuery(testing.allocator, &repos);
    defer testing.allocator.free(q);
    try testing.expect(std.mem.indexOf(u8, q, "tagNodes: refs(refPrefix:\"refs/tags/\", first:100)") != null);
    try testing.expect(std.mem.indexOf(u8, q, "... on Tag { target { oid } }") != null);
}

test "parseResponse: archived + named ref results" {
    const body =
        \\{"data":{"r0":{"isArchived":true,"tag_0":{"name":"main"},"branch_0":null}}}
    ;
    const named = [_][]const u8{"main"};
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r", .named_refs = &named }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const results = try parseResponse(arena.allocator(), body, &repos);
    try testing.expectEqual(@as(usize, 1), results.len);
    try testing.expect(results[0].archived.?);
    try testing.expectEqual(@as(usize, 1), results[0].named_results.len);
    try testing.expect(results[0].named_results[0].is_tag);
    try testing.expect(!results[0].named_results[0].is_branch);
}

test "parseResponse: sha match resolves to has_tag" {
    const body =
        \\{"data":{"r0":{"isArchived":false,"tagNodes":{"nodes":[{"name":"v1","target":{"oid":"aa"}},{"name":"v2","target":{"oid":"bb"}}]}}}}
    ;
    const shas = [_][]const u8{ "aa", "cc" };
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r", .sha_refs = &shas }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const results = try parseResponse(arena.allocator(), body, &repos);
    try testing.expectEqual(ShaTagResolution.has_tag, results[0].sha_results[0].resolution);
    try testing.expectEqual(ShaTagResolution.no_tag, results[0].sha_results[1].resolution);
}

test "parseResponse: annotated tag inner oid matched" {
    const body =
        \\{"data":{"r0":{"isArchived":false,"tagNodes":{"nodes":[{"name":"v1","target":{"oid":"tagobj","target":{"oid":"commitoid"}}}]}}}}
    ;
    const shas = [_][]const u8{"commitoid"};
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r", .sha_refs = &shas }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const results = try parseResponse(arena.allocator(), body, &repos);
    try testing.expectEqual(ShaTagResolution.has_tag, results[0].sha_results[0].resolution);
}

test "parseResponse: missing repo reported as missing=true" {
    const body =
        \\{"data":{"r0":null}}
    ;
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r" }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const results = try parseResponse(arena.allocator(), body, &repos);
    try testing.expect(results[0].missing);
}
