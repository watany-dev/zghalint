//! With a `GITHUB_TOKEN`, the prefetch orchestrator collapses many REST
//! requests into one GraphQL POST per batch. Annotated tag dereferencing,
//! which the REST path performs with N extra requests per repository, is
//! done inline here via the `... on Tag { target { oid } }` fragment.

const std = @import("std");
const http_client = @import("http_client.zig");
const json_util = @import("json_util.zig");

const Allocator = std.mem.Allocator;

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
    sha_refs: []const []const u8 = &.{},
    named_refs: []const []const u8 = &.{},
    /// With an empty `sha_refs` only `defaultBranchRef` is fetched;
    /// `branchNodes` would have no SHA to reach, so it is skipped.
    needs_impostor: bool = false,
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

pub const NamedOid = struct {
    name: []const u8,
    oid: []const u8,
};

pub const RepoResult = struct {
    owner: []const u8,
    repo: []const u8,
    archived: ?bool = null,
    sha_results: []const ShaTagResult = &.{},
    named_results: []const NamedRefResult = &.{},
    missing: bool = false,
    /// Callers that need to know every tag SHA must consult this before
    /// trusting a negative match: more tag pages may exist beyond the fetched one.
    tag_oids_complete: bool = true,
    tag_oids: []const NamedOid = &.{},
    branch_oids: []const NamedOid = &.{},
    branch_oids_complete: bool = true,
    default_branch: ?NamedOid = null,
};

/// Maximum repos per batch for non-SC008 queries. SC004/SC005/SC006-only
/// runs keep this throughput because their node cost per repo is small.
pub const max_repos_per_batch: usize = 30;

/// Reduced batch size for batches that include at least one SC008 lookup.
/// branchNodes + defaultBranchRef roughly doubles the node count per repo,
/// so we lower this so the query stays well below GraphQL's default node
/// limit of 500k.
pub const max_repos_per_batch_with_impostor: usize = 20;

/// A single SC008 request drops the whole batch to the impostor-aware limit
/// so it can't push the query over the node ceiling.
pub fn maxReposPerBatch(repos: []const RepoInput) usize {
    for (repos) |r| {
        if (r.needs_impostor) return max_repos_per_batch_with_impostor;
    }
    return max_repos_per_batch;
}

pub fn buildQuery(allocator: Allocator, repos: []const RepoInput) ![]const u8 {
    var buf = std.ArrayList(u8){};
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "query {");

    for (repos, 0..) |repo, idx| {
        try buf.writer(allocator).print(
            " r{d}: repository(owner:\"{s}\", name:\"{s}\") {{ isArchived",
            .{ idx, repo.owner, repo.repo },
        );

        if (repo.needs_impostor) {
            try buf.appendSlice(
                allocator,
                " defaultBranchRef { name target { oid } }",
            );
        }

        for (repo.named_refs, 0..) |named, j| {
            try buf.writer(allocator).print(
                " tag_{d}: ref(qualifiedName:\"refs/tags/{s}\") {{ name }} branch_{d}: ref(qualifiedName:\"refs/heads/{s}\") {{ name }}",
                .{ j, named, j, named },
            );
        }

        if (repo.sha_refs.len > 0) {
            // pageInfo lets the caller detect when more pages exist and mark
            // affected SHA lookups as unknown rather than falsely claiming
            // no_tag; annotated tags are dereferenced inline to avoid a
            // second round trip.
            try buf.appendSlice(
                allocator,
                " tagNodes: refs(refPrefix:\"refs/tags/\", first:100) { pageInfo { hasNextPage } nodes { name target { oid ... on Tag { target { oid } } } } }",
            );
        }

        if (repo.needs_impostor and repo.sha_refs.len > 0) {
            // Branches always point at commits, so no annotated-ref
            // dereferencing is needed here.
            try buf.appendSlice(
                allocator,
                " branchNodes: refs(refPrefix:\"refs/heads/\", first:100) { pageInfo { hasNextPage } nodes { name target { oid } } }",
            );
        }

        try buf.appendSlice(allocator, " }");
    }

    try buf.appendSlice(allocator, " }");
    return buf.toOwnedSlice(allocator);
}

const endpoint: []const u8 = "https://api.github.com/graphql";

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

    var body_sink = http_client.BoundedBody.init(allocator, http_client.max_response_bytes);
    defer body_sink.deinit();

    var headers_buf: [3]std.http.Header = undefined;
    var header_count = http_client.writeStandardHeaders(&headers_buf);
    headers_buf[header_count] = .{ .name = "Content-Type", .value = "application/json" };
    header_count += 1;
    var auth_buf: [1]std.http.Header = undefined;

    const result = http_client.fetch(.{
        .location = .{ .url = endpoint },
        .method = .POST,
        .payload = body,
        .response_writer = &body_sink.writer,
        .headers = .{ .user_agent = .{ .override = http_client.user_agent } },
        .extra_headers = headers_buf[0..header_count],
        .privileged_headers = http_client.authHeaders(&auth_buf, auth_value),
    }) catch return error.RequestFailed;

    if (result.status == .forbidden or result.status == .too_many_requests) {
        return error.RateLimited;
    }
    if (result.status != .ok) return error.RequestFailed;

    return parseResponse(allocator, body_sink.written(), repos) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.RateLimited => error.RateLimited,
        else => error.ParseFailed,
    };
}

fn encodeRequestBody(allocator: Allocator, query: []const u8) ![]const u8 {
    return std.json.Stringify.valueAlloc(allocator, .{ .query = query }, .{});
}

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

    // GitHub signals secondary rate limits via HTTP 200 + errors[].type ==
    // "RATE_LIMITED" (primary limits come back as 403/429 and are caught by
    // the caller before we get here). Surface that explicitly so the
    // orchestrator can stop making requests.
    if (root_obj.get("errors")) |errors_value| {
        if (isRateLimitedErrors(errors_value)) return error.RateLimited;
    }
    if (root_obj.get("data") == null) return error.ParseFailed;

    const data: ?std.json.ObjectMap = switch (root_obj.get("data").?) {
        .object => |o| o,
        .null => null,
        else => return error.ParseFailed,
    };

    var results = try allocator.alloc(RepoResult, repos.len);

    for (repos, 0..) |repo, idx| {
        results[idx] = .{ .owner = repo.owner, .repo = repo.repo, .missing = true };

        var alias_buf: [16]u8 = undefined;
        const alias = std.fmt.bufPrint(&alias_buf, "r{d}", .{idx}) catch unreachable;

        const entry = (data orelse continue).get(alias) orelse continue;
        switch (entry) {
            .object => |obj| results[idx] = try parseRepoObject(allocator, repo, obj),
            else => continue,
        }
    }

    return results;
}

fn isRateLimitedErrors(value: std.json.Value) bool {
    const arr = switch (value) {
        .array => |a| a,
        else => return false,
    };
    for (arr.items) |entry| {
        const obj = switch (entry) {
            .object => |o| o,
            else => continue,
        };
        const type_value = obj.get("type") orelse continue;
        const type_str = switch (type_value) {
            .string => |s| s,
            else => continue,
        };
        if (std.mem.eql(u8, type_str, "RATE_LIMITED")) return true;
    }
    return false;
}

fn parseRepoObject(
    allocator: Allocator,
    repo: RepoInput,
    obj: std.json.ObjectMap,
) !RepoResult {
    var result: RepoResult = .{ .owner = repo.owner, .repo = repo.repo };

    if (obj.get("isArchived")) |v| {
        result.archived = json_util.asBool(v);
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

    result.tag_oids_complete = refsListingComplete(obj, "tagNodes");

    if (repo.sha_refs.len > 0) {
        // Names are kept so SC008 fix_hint can list candidate tag pins.
        const tag_oids = collectRefOids(allocator, obj, "tagNodes", true) catch &[_]NamedOid{};
        result.tag_oids = tag_oids;

        var resolutions = try allocator.alloc(ShaTagResult, repo.sha_refs.len);
        for (repo.sha_refs, 0..) |sha, j| {
            var found = false;
            for (tag_oids) |entry| {
                if (std.mem.eql(u8, entry.oid, sha)) {
                    found = true;
                    break;
                }
            }
            const resolution: ShaTagResolution = if (found) .has_tag else if (!result.tag_oids_complete) .unknown else .no_tag;
            resolutions[j] = .{ .sha = sha, .resolution = resolution };
        }
        result.sha_results = resolutions;
    }

    if (repo.needs_impostor) {
        result.branch_oids_complete = refsListingComplete(obj, "branchNodes");
        result.branch_oids = collectRefOids(allocator, obj, "branchNodes", false) catch &[_]NamedOid{};
        result.default_branch = parseDefaultBranchRef(obj);
    }

    return result;
}

fn parseDefaultBranchRef(obj: std.json.ObjectMap) ?NamedOid {
    const ref_obj = json_util.objField(obj, "defaultBranchRef") orelse return null;
    const name = json_util.stringField(ref_obj, "name") orelse return null;
    const target = json_util.objField(ref_obj, "target") orelse return null;
    const oid = json_util.stringField(target, "oid") orelse return null;
    return .{ .name = name, .oid = oid };
}

/// pageInfo.hasNextPage is authoritative when present; otherwise the
/// legacy heuristic (full 100-node page = "could have more") preserves
/// behaviour for pre-pageInfo fixtures.
fn refsListingComplete(obj: std.json.ObjectMap, listing_name: []const u8) bool {
    const listing_obj = json_util.objField(obj, listing_name) orelse return true;
    if (listing_obj.get("pageInfo")) |pi_val| {
        if (pi_val == .object) {
            if (pi_val.object.get("hasNextPage")) |hnp_val| {
                if (hnp_val == .bool) return !hnp_val.bool;
            }
        }
    }
    const nodes_val = listing_obj.get("nodes") orelse return true;
    const count = switch (nodes_val) {
        .array => |arr| arr.items.len,
        else => return true,
    };
    return count < 100;
}

fn refAliasExists(obj: std.json.ObjectMap, alias: []const u8) bool {
    const val = obj.get(alias) orelse return false;
    return switch (val) {
        .object => true,
        else => false,
    };
}

/// For annotated tags only the dereferenced commit oid is recorded, never
/// the tag object oid, so a SHA pinned to the tag object is still judged
/// against the *commit*.
fn collectRefOids(
    allocator: Allocator,
    obj: std.json.ObjectMap,
    listing_name: []const u8,
    follow_inner_target: bool,
) ![]const NamedOid {
    const listing_obj = json_util.objField(obj, listing_name) orelse return &[_]NamedOid{};
    const nodes = json_util.arrayField(listing_obj, "nodes") orelse return &[_]NamedOid{};

    var entries = std.ArrayList(NamedOid){};
    errdefer entries.deinit(allocator);

    for (nodes) |node_val| {
        const node = json_util.asObject(node_val) orelse continue;
        const name = json_util.stringField(node, "name") orelse continue;
        const target_val = node.get("target") orelse continue;
        const target = switch (target_val) {
            .object => |o| o,
            else => continue,
        };

        if (follow_inner_target) {
            if (target.get("target")) |inner_val| {
                if (inner_val == .object) {
                    if (inner_val.object.get("oid")) |oid_inner| {
                        if (oid_inner == .string) {
                            try entries.append(allocator, .{ .name = name, .oid = oid_inner.string });
                            continue;
                        }
                    }
                }
            }
        }
        if (target.get("oid")) |oid_val| {
            if (oid_val == .string) {
                try entries.append(allocator, .{ .name = name, .oid = oid_val.string });
            }
        }
    }

    return entries.toOwnedSlice(allocator);
}

const test_support = @import("../test_support.zig");
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
    try testing.expect(std.mem.indexOf(u8, q, "tagNodes") == null);
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

test "buildQuery: sha refs pull in tagNodes subquery with pageInfo" {
    const shas = [_][]const u8{"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"};
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r", .sha_refs = &shas }};
    const q = try buildQuery(testing.allocator, &repos);
    defer testing.allocator.free(q);
    try testing.expect(std.mem.indexOf(u8, q, "tagNodes: refs(refPrefix:\"refs/tags/\", first:100)") != null);
    try testing.expect(std.mem.indexOf(u8, q, "pageInfo { hasNextPage }") != null);
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

test "parseResponse: null data marks every repo missing" {
    const body = "{\"data\":null}";
    const repos = [_]RepoInput{
        .{ .owner = "a", .repo = "x" },
        .{ .owner = "b", .repo = "y" },
    };
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const results = try parseResponse(arena.allocator(), body, &repos);
    try testing.expectEqual(@as(usize, 2), results.len);
    try testing.expect(results[0].missing);
    try testing.expect(results[1].missing);
}

test "parseResponse: errors without data surfaces ParseFailed" {
    const body = "{\"errors\":[{\"message\":\"boom\"}]}";
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r" }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    try testing.expectError(error.ParseFailed, parseResponse(arena.allocator(), body, &repos));
}

test "parseResponse: errors[].type RATE_LIMITED surfaces RateLimited" {
    const body = "{\"errors\":[{\"type\":\"RATE_LIMITED\",\"message\":\"API rate limit exceeded\"}]}";
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r" }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    try testing.expectError(error.RateLimited, parseResponse(arena.allocator(), body, &repos));
}

test "parseResponse: errors[].type RATE_LIMITED wins even if data is also present" {
    // GitHub may return a partial data payload alongside the rate-limit
    // error. Detecting the sentinel should still short-circuit the caller.
    const body = "{\"data\":{\"r0\":null},\"errors\":[{\"type\":\"RATE_LIMITED\"}]}";
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r" }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    try testing.expectError(error.RateLimited, parseResponse(arena.allocator(), body, &repos));
}

test "parseResponse: pageInfo.hasNextPage=true marks non-match unknown even under 100 nodes" {
    const body =
        \\{"data":{"r0":{"isArchived":false,"tagNodes":{"pageInfo":{"hasNextPage":true,"endCursor":"c1"},"nodes":[{"name":"v1","target":{"oid":"aa"}},{"name":"v2","target":{"oid":"bb"}}]}}}}
    ;
    const shas = [_][]const u8{ "aa", "cc" };
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r", .sha_refs = &shas }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const results = try parseResponse(arena.allocator(), body, &repos);
    try testing.expectEqual(ShaTagResolution.has_tag, results[0].sha_results[0].resolution);
    try testing.expectEqual(ShaTagResolution.unknown, results[0].sha_results[1].resolution);
    try testing.expect(!results[0].tag_oids_complete);
}

test "parseResponse: pageInfo.hasNextPage=false keeps no_tag for non-match" {
    const body =
        \\{"data":{"r0":{"isArchived":false,"tagNodes":{"pageInfo":{"hasNextPage":false,"endCursor":"c1"},"nodes":[{"name":"v1","target":{"oid":"aa"}},{"name":"v2","target":{"oid":"bb"}}]}}}}
    ;
    const shas = [_][]const u8{ "aa", "cc" };
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r", .sha_refs = &shas }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const results = try parseResponse(arena.allocator(), body, &repos);
    try testing.expectEqual(ShaTagResolution.has_tag, results[0].sha_results[0].resolution);
    try testing.expectEqual(ShaTagResolution.no_tag, results[0].sha_results[1].resolution);
    try testing.expect(results[0].tag_oids_complete);
}

test "parseResponse: 100 tag nodes without match yields unknown (legacy heuristic)" {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(testing.allocator);
    try buf.appendSlice(testing.allocator, "{\"data\":{\"r0\":{\"isArchived\":false,\"tagNodes\":{\"nodes\":[");
    for (0..100) |i| {
        if (i != 0) try buf.append(testing.allocator, ',');
        try buf.writer(testing.allocator).print("{{\"name\":\"v{d}\",\"target\":{{\"oid\":\"oid{d}\"}}}}", .{ i, i });
    }
    try buf.appendSlice(testing.allocator, "]}}}}");

    const shas = [_][]const u8{"sha-not-present"};
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r", .sha_refs = &shas }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const results = try parseResponse(arena.allocator(), buf.items, &repos);
    try testing.expectEqual(ShaTagResolution.unknown, results[0].sha_results[0].resolution);
}

test "parseResponse: non-bool isArchived leaves archived = null" {
    const body = "{\"data\":{\"r0\":{\"isArchived\":null}}}";
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r" }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const results = try parseResponse(arena.allocator(), body, &repos);
    try testing.expect(results[0].archived == null);
    try testing.expect(!results[0].missing);
}

test "parseResponse: malformed root JSON returns ParseFailed" {
    const body = "not-json-at-all";
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r" }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    try testing.expectError(error.ParseFailed, parseResponse(arena.allocator(), body, &repos));
}

test "encodeRequestBody escapes quotes, backslashes, and newlines" {
    const q = "query { a \"b\" \\c\nd }";
    const body = try encodeRequestBody(testing.allocator, q);
    defer testing.allocator.free(body);
    try testing.expect(std.mem.startsWith(u8, body, "{\"query\":\""));
    try testing.expect(std.mem.endsWith(u8, body, "\"}"));
    try testing.expect(std.mem.indexOf(u8, body, "\\\"b\\\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\\\\c") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\\n") != null);
}

test "batchQuery: empty repo slice short-circuits" {
    const results = try batchQuery(testing.allocator, &.{});
    try testing.expectEqual(@as(usize, 0), results.len);
}

test "parseResponse: non-object data (string) surfaces ParseFailed" {
    const body = "{\"data\":\"not-an-object\"}";
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r" }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.ParseFailed, parseResponse(arena.allocator(), body, &repos));
}

test "parseResponse: alias missing from data marks repo missing" {
    const body = "{\"data\":{\"r0\":{\"isArchived\":false}}}";
    const repos = [_]RepoInput{
        .{ .owner = "a", .repo = "x" },
        .{ .owner = "b", .repo = "y" },
    };
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const results = try parseResponse(arena.allocator(), body, &repos);
    try testing.expect(!results[0].missing);
    try testing.expect(results[1].missing);
}

test "parseResponse: alias is primitive (not object, not null) -> missing" {
    const body = "{\"data\":{\"r0\":42}}";
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r" }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const results = try parseResponse(arena.allocator(), body, &repos);
    try testing.expect(results[0].missing);
}

test "parseResponse: repo without isArchived field keeps archived = null" {
    const body = "{\"data\":{\"r0\":{}}}";
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r" }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const results = try parseResponse(arena.allocator(), body, &repos);
    try testing.expect(results[0].archived == null);
    try testing.expect(!results[0].missing);
}

test "parseResponse: sha_refs but no tagNodes -> no_tag for every sha" {
    const body = "{\"data\":{\"r0\":{\"isArchived\":false}}}";
    const shas = [_][]const u8{ "deadbeef", "cafebabe" };
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r", .sha_refs = &shas }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const results = try parseResponse(arena.allocator(), body, &repos);
    try testing.expectEqual(@as(usize, 2), results[0].sha_results.len);
    try testing.expectEqual(ShaTagResolution.no_tag, results[0].sha_results[0].resolution);
    try testing.expectEqual(ShaTagResolution.no_tag, results[0].sha_results[1].resolution);
}

test "parseResponse: tagNodes non-object is tolerated" {
    const body = "{\"data\":{\"r0\":{\"isArchived\":false,\"tagNodes\":\"oops\"}}}";
    const shas = [_][]const u8{"any"};
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r", .sha_refs = &shas }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const results = try parseResponse(arena.allocator(), body, &repos);
    try testing.expectEqual(ShaTagResolution.no_tag, results[0].sha_results[0].resolution);
}

test "parseResponse: tagNodes.nodes is non-array is tolerated" {
    const body = "{\"data\":{\"r0\":{\"isArchived\":false,\"tagNodes\":{\"nodes\":\"oops\"}}}}";
    const shas = [_][]const u8{"any"};
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r", .sha_refs = &shas }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const results = try parseResponse(arena.allocator(), body, &repos);
    try testing.expectEqual(ShaTagResolution.no_tag, results[0].sha_results[0].resolution);
}

test "parseResponse: tag node malformed entries are skipped" {
    const body =
        \\{"data":{"r0":{"isArchived":false,"tagNodes":{"nodes":[
        \\  "not-an-object",
        \\  {"name":"bad1","target":"not-an-object"},
        \\  {"name":"bad2","target":{"oid":123}},
        \\  {"name":"bad3","target":{"oid":"outer","target":"not-an-object"}},
        \\  {"name":"bad4","target":{"oid":"outer2","target":{"oid":42}}},
        \\  {"name":"good","target":{"oid":"the-commit"}}
        \\]}}}}
    ;
    const shas = [_][]const u8{"the-commit"};
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r", .sha_refs = &shas }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const results = try parseResponse(arena.allocator(), body, &repos);
    try testing.expectEqual(ShaTagResolution.has_tag, results[0].sha_results[0].resolution);
}

test "parseResponse: named ref alias with non-object value reads as false" {
    const body = "{\"data\":{\"r0\":{\"isArchived\":true,\"tag_0\":null,\"branch_0\":{\"name\":\"main\"}}}}";
    const named = [_][]const u8{"main"};
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r", .named_refs = &named }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const results = try parseResponse(arena.allocator(), body, &repos);
    try testing.expect(!results[0].named_results[0].is_tag);
    try testing.expect(results[0].named_results[0].is_branch);
}

test "parseResponse: non-object root returns ParseFailed" {
    const body = "[]";
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r" }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.ParseFailed, parseResponse(arena.allocator(), body, &repos));
}

test "buildQuery: branchNodes only appears when needs_impostor=true" {
    const shas = [_][]const u8{"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"};

    const repos_off = [_]RepoInput{.{ .owner = "o", .repo = "r", .sha_refs = &shas }};
    const q_off = try buildQuery(testing.allocator, &repos_off);
    defer testing.allocator.free(q_off);
    try testing.expect(std.mem.indexOf(u8, q_off, "tagNodes:") != null);
    try testing.expect(std.mem.indexOf(u8, q_off, "branchNodes:") == null);
    try testing.expect(std.mem.indexOf(u8, q_off, "defaultBranchRef") == null);

    const repos_on = [_]RepoInput{.{
        .owner = "o",
        .repo = "r",
        .sha_refs = &shas,
        .needs_impostor = true,
    }};
    const q_on = try buildQuery(testing.allocator, &repos_on);
    defer testing.allocator.free(q_on);
    try testing.expect(std.mem.indexOf(u8, q_on, "branchNodes: refs(refPrefix:\"refs/heads/\", first:100)") != null);
    try testing.expect(std.mem.indexOf(u8, q_on, "defaultBranchRef { name target { oid } }") != null);
}

test "buildQuery: needs_impostor without sha_refs still skips branchNodes" {
    // branchNodes is only useful when we have SHAs to reach. defaultBranchRef
    // however is cheap and always emitted with needs_impostor.
    const repos = [_]RepoInput{.{
        .owner = "o",
        .repo = "r",
        .needs_impostor = true,
    }};
    const q = try buildQuery(testing.allocator, &repos);
    defer testing.allocator.free(q);
    try testing.expect(std.mem.indexOf(u8, q, "branchNodes:") == null);
    try testing.expect(std.mem.indexOf(u8, q, "defaultBranchRef") != null);
}

test "maxReposPerBatch: impostor-free batches keep the larger limit" {
    // Deliberate constant assertion: SC004/SC005/SC006-only queries stay
    // cheap, so they shouldn't pay the SC008 batch-size penalty.
    try testing.expectEqual(@as(usize, 30), max_repos_per_batch);
    try testing.expectEqual(@as(usize, 20), max_repos_per_batch_with_impostor);
    const inputs = [_]RepoInput{
        .{ .owner = "a", .repo = "a" },
        .{ .owner = "b", .repo = "b" },
    };
    try testing.expectEqual(@as(usize, 30), maxReposPerBatch(&inputs));
}

test "maxReposPerBatch: any impostor need shrinks the batch to 20" {
    const inputs = [_]RepoInput{
        .{ .owner = "a", .repo = "a" },
        .{ .owner = "b", .repo = "b", .needs_impostor = true },
    };
    try testing.expectEqual(@as(usize, 20), maxReposPerBatch(&inputs));
}

test "parseResponse: branchNodes populates branch_oids" {
    const body =
        \\{"data":{"r0":{"isArchived":false,"tagNodes":{"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[]},"branchNodes":{"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[{"name":"main","target":{"oid":"mainoid"}},{"name":"dev","target":{"oid":"devoid"}}]}}}}
    ;
    const shas = [_][]const u8{"any"};
    const repos = [_]RepoInput{.{
        .owner = "o",
        .repo = "r",
        .sha_refs = &shas,
        .needs_impostor = true,
    }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const results = try parseResponse(arena.allocator(), body, &repos);
    try testing.expectEqual(@as(usize, 2), results[0].branch_oids.len);
    try testing.expectEqualStrings("main", results[0].branch_oids[0].name);
    try testing.expectEqualStrings("mainoid", results[0].branch_oids[0].oid);
    try testing.expectEqualStrings("dev", results[0].branch_oids[1].name);
    try testing.expectEqualStrings("devoid", results[0].branch_oids[1].oid);
    try testing.expect(results[0].branch_oids_complete);
}

test "parseResponse: branchNodes hasNextPage=true sets branch_oids_complete=false" {
    const body =
        \\{"data":{"r0":{"isArchived":false,"tagNodes":{"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[]},"branchNodes":{"pageInfo":{"hasNextPage":true,"endCursor":"BCUR=="},"nodes":[{"name":"main","target":{"oid":"mainoid"}}]}}}}
    ;
    const shas = [_][]const u8{"any"};
    const repos = [_]RepoInput{.{
        .owner = "o",
        .repo = "r",
        .sha_refs = &shas,
        .needs_impostor = true,
    }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const results = try parseResponse(arena.allocator(), body, &repos);
    try testing.expect(!results[0].branch_oids_complete);
}

test "parseResponse: defaultBranchRef populates default_branch" {
    const body =
        \\{"data":{"r0":{"isArchived":false,"defaultBranchRef":{"name":"main","target":{"oid":"defaultoid"}}}}}
    ;
    const repos = [_]RepoInput{.{
        .owner = "o",
        .repo = "r",
        .needs_impostor = true,
    }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const results = try parseResponse(arena.allocator(), body, &repos);
    try testing.expect(results[0].default_branch != null);
    try testing.expectEqualStrings("main", results[0].default_branch.?.name);
    try testing.expectEqualStrings("defaultoid", results[0].default_branch.?.oid);
}

test "parseResponse: missing defaultBranchRef leaves default_branch null" {
    const body =
        \\{"data":{"r0":{"isArchived":false}}}
    ;
    const repos = [_]RepoInput{.{
        .owner = "o",
        .repo = "r",
        .needs_impostor = true,
    }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const results = try parseResponse(arena.allocator(), body, &repos);
    try testing.expect(results[0].default_branch == null);
}

test "parseResponse: needs_impostor + branch HEAD oid match (used downstream by SC008 step2)" {
    // The graphql layer only surfaces branch_oids; prefetch does the
    // "branch HEAD = pinned SHA" step2 check. This pins the data path it
    // relies on.
    const body =
        \\{"data":{"r0":{"isArchived":false,"tagNodes":{"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[]},"branchNodes":{"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[{"name":"feature","target":{"oid":"sha-of-pinned"}}]}}}}
    ;
    const shas = [_][]const u8{"sha-of-pinned"};
    const repos = [_]RepoInput{.{
        .owner = "o",
        .repo = "r",
        .sha_refs = &shas,
        .needs_impostor = true,
    }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const results = try parseResponse(arena.allocator(), body, &repos);
    var found = false;
    for (results[0].branch_oids) |b| {
        if (std.mem.eql(u8, b.oid, "sha-of-pinned")) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

test "batchQuery: no GITHUB_TOKEN in env returns NoToken" {
    var env = try test_support.EnvGuard.set(testing.allocator, "GITHUB_TOKEN", null);
    defer env.deinit();

    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r" }};
    const result = batchQuery(testing.allocator, &repos);
    try testing.expectError(error.NoToken, result);
}
