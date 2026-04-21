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
    /// SC008: also fetch branch HEAD oids and the default branch so prefetch
    /// can decide reachability for `sha_refs`. Implies `sha_refs.len > 0`.
    needs_impostor: bool = false,
    /// Continuation cursor for tagNodes pagination (per-repo). When set,
    /// emitted as `after:"<cursor>"` in the refs(refPrefix:"refs/tags/")
    /// argument list. null on the first page.
    tags_cursor: ?[]const u8 = null,
    /// Continuation cursor for branchNodes pagination. Same semantics.
    branches_cursor: ?[]const u8 = null,
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

/// A ref name paired with its target commit OID. Used for both branch HEAD
/// listings (SC008 step2 reachability) and the suggested-tag listings that
/// SC008 surfaces in fix_hint.
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
    /// True if the API returned the repo as missing / permission-denied.
    missing: bool = false,
    /// False when more tag pages exist beyond what we fetched (pageInfo.hasNextPage=true
    /// or the legacy 100-node heuristic fired). Callers that need to know every tag SHA
    /// must consult this flag before trusting a negative match.
    tag_oids_complete: bool = true,
    /// All tag (name, commit oid) pairs from the fetched page, with
    /// annotated tags resolved to their underlying commit oid. Populated
    /// whenever tagNodes was requested.
    tag_oids: []const NamedOid = &.{},
    /// All branch (name, head oid) pairs from the fetched page. Populated
    /// only when `needs_impostor` was set on the request.
    branch_oids: []const NamedOid = &.{},
    /// Mirror of tag_oids_complete for the branches listing.
    branch_oids_complete: bool = true,
    /// Default branch (name + head oid). Populated when `needs_impostor`.
    default_branch: ?NamedOid = null,
    /// pageInfo.endCursor for tagNodes when more pages exist; null when
    /// the fetch is complete.
    tags_next_cursor: ?[]const u8 = null,
    /// pageInfo.endCursor for branchNodes when more pages exist; null when
    /// the fetch is complete.
    branches_next_cursor: ?[]const u8 = null,
};

// ============================================================
// Query building
// ============================================================

/// Maximum repos per batch for non-SC008 queries. SC004/SC005/SC006-only
/// runs keep this throughput because their node cost per repo is small.
pub const max_repos_per_batch: usize = 30;

/// Reduced batch size for batches that include at least one SC008 lookup.
/// branchNodes + defaultBranchRef roughly doubles the node count per repo,
/// so we lower this so the query stays well below GraphQL's default node
/// limit of 500k.
pub const max_repos_per_batch_with_impostor: usize = 20;

/// Pick the batch size appropriate for `repos`: fall back to the
/// impostor-aware limit whenever any repo needs SC008 data, so a single
/// SC008 request doesn't push the whole batch over the node ceiling.
pub fn maxReposPerBatch(repos: []const RepoInput) usize {
    for (repos) |r| {
        if (r.needs_impostor) return max_repos_per_batch_with_impostor;
    }
    return max_repos_per_batch;
}

/// Append the `, first:100[, after:"<cursor>"]` argument tail to a
/// `refs(refPrefix:"...")` call. Cursor strings come from GitHub's
/// pageInfo.endCursor and are opaque base64 — we trust them as-is.
fn writePagedRefArgs(
    allocator: Allocator,
    buf: *std.ArrayList(u8),
    cursor: ?[]const u8,
) !void {
    try buf.appendSlice(allocator, ", first:100");
    if (cursor) |c| {
        try buf.writer(allocator).print(", after:\"{s}\"", .{c});
    }
}

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

        if (repo.needs_impostor) {
            // SC008 step3 / fix_hint candidate. Default branch resolves to a
            // single ref; we always have it for a non-archived public repo.
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
            // Fetch up to 100 tags; inline-dereference annotated tags so we
            // see the underlying commit oid in a single round trip. pageInfo
            // lets the caller detect when more pages exist and mark affected
            // SHA lookups as unknown rather than falsely claiming no_tag.
            try buf.appendSlice(allocator, " tagNodes: refs(refPrefix:\"refs/tags/\"");
            try writePagedRefArgs(allocator, &buf, repo.tags_cursor);
            try buf.appendSlice(
                allocator,
                ") { pageInfo { hasNextPage endCursor } nodes { name target { oid ... on Tag { target { oid } } } } }",
            );
        }

        if (repo.needs_impostor and repo.sha_refs.len > 0) {
            // SC008 step2: enumerate branch HEAD oids. Each branch's
            // target.oid is the head commit; no annotated-ref dereferencing
            // is needed because branches always point at commits.
            try buf.appendSlice(allocator, " branchNodes: refs(refPrefix:\"refs/heads/\"");
            try writePagedRefArgs(allocator, &buf, repo.branches_cursor);
            try buf.appendSlice(
                allocator,
                ") { pageInfo { hasNextPage endCursor } nodes { name target { oid } } }",
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
        error.RateLimited => error.RateLimited,
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

    // GitHub signals secondary rate limits via HTTP 200 + errors[].type ==
    // "RATE_LIMITED" (primary limits come back as 403/429 and are caught by
    // the caller before we get here). Surface that explicitly so the
    // orchestrator can stop making requests.
    if (root_obj.get("errors")) |errors_value| {
        if (isRateLimitedErrors(errors_value)) return error.RateLimited;
    }
    if (root_obj.get("data") == null) return error.ParseFailed;

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

    // Detect pagination state for tagNodes. pageInfo.hasNextPage is
    // authoritative when present; otherwise fall back to the legacy
    // heuristic that treats a full 100-node page as "could have more"
    // so pre-pageInfo test fixtures keep the same unknown/no_tag split.
    result.tag_oids_complete = refsListingComplete(obj, "tagNodes");
    result.tags_next_cursor = refsListingNextCursor(obj, "tagNodes");

    if (repo.sha_refs.len > 0) {
        // Collect all (name, commit oid) pairs reachable from tag refs.
        // Names are kept so SC008 fix_hint can list candidate tag pins.
        const tag_oids = collectTagOids(allocator, obj) catch &[_]NamedOid{};
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
        result.branches_next_cursor = refsListingNextCursor(obj, "branchNodes");
        result.branch_oids = collectBranchOids(allocator, obj) catch &[_]NamedOid{};
        result.default_branch = parseDefaultBranchRef(obj);
    }

    return result;
}

fn parseDefaultBranchRef(obj: std.json.ObjectMap) ?NamedOid {
    const ref_val = obj.get("defaultBranchRef") orelse return null;
    const ref_obj = switch (ref_val) {
        .object => |o| o,
        else => return null,
    };
    const name_val = ref_obj.get("name") orelse return null;
    const name = switch (name_val) {
        .string => |s| s,
        else => return null,
    };
    const target_val = ref_obj.get("target") orelse return null;
    const target = switch (target_val) {
        .object => |o| o,
        else => return null,
    };
    const oid_val = target.get("oid") orelse return null;
    const oid = switch (oid_val) {
        .string => |s| s,
        else => return null,
    };
    return .{ .name = name, .oid = oid };
}

/// True iff every page of the named refs(...) listing has been fetched.
/// pageInfo.hasNextPage is authoritative when present; otherwise the
/// legacy heuristic (full 100-node page = "could have more") preserves
/// behaviour for pre-pageInfo fixtures.
fn refsListingComplete(obj: std.json.ObjectMap, listing_name: []const u8) bool {
    const listing_val = obj.get(listing_name) orelse return true;
    const listing_obj = switch (listing_val) {
        .object => |o| o,
        else => return true,
    };
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

/// Return pageInfo.endCursor when `hasNextPage` is true; null otherwise.
/// Caller owns nothing — the slice points into the parsed JSON arena.
fn refsListingNextCursor(obj: std.json.ObjectMap, listing_name: []const u8) ?[]const u8 {
    const listing_val = obj.get(listing_name) orelse return null;
    const listing_obj = switch (listing_val) {
        .object => |o| o,
        else => return null,
    };
    const pi_val = listing_obj.get("pageInfo") orelse return null;
    const pi = switch (pi_val) {
        .object => |o| o,
        else => return null,
    };
    const hnp_val = pi.get("hasNextPage") orelse return null;
    const has_next = switch (hnp_val) {
        .bool => |b| b,
        else => return null,
    };
    if (!has_next) return null;
    const cursor_val = pi.get("endCursor") orelse return null;
    return switch (cursor_val) {
        .string => |s| s,
        else => null,
    };
}

fn refAliasExists(obj: std.json.ObjectMap, alias: []const u8) bool {
    const val = obj.get(alias) orelse return false;
    return switch (val) {
        .object => true,
        else => false,
    };
}

/// Collect (tag name, commit oid) pairs from tagNodes. For lightweight
/// tags, oid == target.oid (the commit). For annotated tags, oid ==
/// target.target.oid (the dereferenced commit). When both are present
/// (annotated tag schema), only the inner commit oid is recorded so a
/// SHA-pin matched against the tag object oid is correctly detected as
/// an impostor on the *commit*.
fn collectTagOids(
    allocator: Allocator,
    obj: std.json.ObjectMap,
) ![]const NamedOid {
    return collectRefOids(allocator, obj, "tagNodes", true);
}

fn collectBranchOids(
    allocator: Allocator,
    obj: std.json.ObjectMap,
) ![]const NamedOid {
    return collectRefOids(allocator, obj, "branchNodes", false);
}

fn collectRefOids(
    allocator: Allocator,
    obj: std.json.ObjectMap,
    listing_name: []const u8,
    follow_inner_target: bool,
) ![]const NamedOid {
    const listing_val = obj.get(listing_name) orelse return &[_]NamedOid{};
    const listing_obj = switch (listing_val) {
        .object => |o| o,
        else => return &[_]NamedOid{},
    };
    const nodes_val = listing_obj.get("nodes") orelse return &[_]NamedOid{};
    const nodes = switch (nodes_val) {
        .array => |a| a.items,
        else => return &[_]NamedOid{},
    };

    var entries = std.ArrayList(NamedOid){};
    errdefer entries.deinit(allocator);

    for (nodes) |node_val| {
        const node = switch (node_val) {
            .object => |o| o,
            else => continue,
        };
        const name = switch (node.get("name") orelse continue) {
            .string => |s| s,
            else => continue,
        };
        const target_val = node.get("target") orelse continue;
        const target = switch (target_val) {
            .object => |o| o,
            else => continue,
        };

        // Annotated tag: prefer the inner commit oid. Fall back to the
        // outer oid (lightweight tag / branch HEAD).
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

test "buildQuery: sha refs pull in tagNodes subquery with pageInfo" {
    const shas = [_][]const u8{"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"};
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r", .sha_refs = &shas }};
    const q = try buildQuery(testing.allocator, &repos);
    defer testing.allocator.free(q);
    try testing.expect(std.mem.indexOf(u8, q, "tagNodes: refs(refPrefix:\"refs/tags/\", first:100)") != null);
    try testing.expect(std.mem.indexOf(u8, q, "pageInfo { hasNextPage endCursor }") != null);
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
    // Authoritative pagination: 2 nodes is well below 100, but hasNextPage=true
    // tells us more pages exist → any non-matching SHA must stay unknown.
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
    // Authoritative pagination with hasNextPage=false: 2 known tags, cc not
    // among them → no_tag even though <100 nodes.
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
    // Build a "data":{"r0":{...}} body with exactly 100 tagNodes entries.
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
    // Double-quoted wrapper with escaped characters inside.
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
    // data has r0 but we query two repos → r1 absent should be reported missing.
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
    // No tagNodes field means hit_page_limit=false AND empty tag_shas,
    // so every SHA resolves to no_tag.
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
    // tagNodes is a string, not an object. collectTagCommitShas / page-limit
    // detection both must handle this without crashing.
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
    // Non-object node, object-with-non-object-target, oid non-string:
    // the loop must skip each without adding to tag_shas. A clean oid in
    // the last node still produces a has_tag match.
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
    // tag_0 present but set to null (branch_0 to an object).
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

    // Without needs_impostor: tagNodes present, branchNodes absent.
    const repos_off = [_]RepoInput{.{ .owner = "o", .repo = "r", .sha_refs = &shas }};
    const q_off = try buildQuery(testing.allocator, &repos_off);
    defer testing.allocator.free(q_off);
    try testing.expect(std.mem.indexOf(u8, q_off, "tagNodes:") != null);
    try testing.expect(std.mem.indexOf(u8, q_off, "branchNodes:") == null);
    try testing.expect(std.mem.indexOf(u8, q_off, "defaultBranchRef") == null);

    // With needs_impostor: branchNodes + defaultBranchRef appear.
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

test "buildQuery: tags_cursor and branches_cursor emit after: arguments" {
    const shas = [_][]const u8{"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"};
    const repos = [_]RepoInput{.{
        .owner = "o",
        .repo = "r",
        .sha_refs = &shas,
        .needs_impostor = true,
        .tags_cursor = "TAGCURSOR==",
        .branches_cursor = "BRANCHCURSOR==",
    }};
    const q = try buildQuery(testing.allocator, &repos);
    defer testing.allocator.free(q);
    try testing.expect(std.mem.indexOf(u8, q, "tagNodes: refs(refPrefix:\"refs/tags/\", first:100, after:\"TAGCURSOR==\")") != null);
    try testing.expect(std.mem.indexOf(u8, q, "branchNodes: refs(refPrefix:\"refs/heads/\", first:100, after:\"BRANCHCURSOR==\")") != null);
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
    // branchNodes + defaultBranchRef roughly doubles the per-repo node cost,
    // so even one SC008 request must drop the whole batch below 500k nodes.
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
    try testing.expect(results[0].branches_next_cursor == null);
}

test "parseResponse: branchNodes hasNextPage=true sets branch_oids_complete=false and surfaces cursor" {
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
    try testing.expect(results[0].branches_next_cursor != null);
    try testing.expectEqualStrings("BCUR==", results[0].branches_next_cursor.?);
}

test "parseResponse: tagNodes hasNextPage=true also surfaces tags_next_cursor" {
    const body =
        \\{"data":{"r0":{"isArchived":false,"tagNodes":{"pageInfo":{"hasNextPage":true,"endCursor":"TCUR=="},"nodes":[{"name":"v1","target":{"oid":"aa"}}]}}}}
    ;
    const shas = [_][]const u8{"aa"};
    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r", .sha_refs = &shas }};
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const results = try parseResponse(arena.allocator(), body, &repos);
    try testing.expect(!results[0].tag_oids_complete);
    try testing.expect(results[0].tags_next_cursor != null);
    try testing.expectEqualStrings("TCUR==", results[0].tags_next_cursor.?);
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
    // The graphql layer doesn't itself decide impostor status; it just
    // surfaces branch_oids so prefetch can short-circuit step2 without an
    // extra REST call. This test pins the data path: the (name,oid) pair
    // we expect to use as the "branch HEAD = pinned SHA" check is present.
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
    // Save current token value so we can restore it after the test.
    const saved = std.process.getEnvVarOwned(testing.allocator, "GITHUB_TOKEN") catch null;
    defer if (saved) |s| testing.allocator.free(s);
    const saved_z: ?[:0]u8 = if (saved) |s| testing.allocator.dupeZ(u8, s) catch null else null;
    defer if (saved_z) |z| testing.allocator.free(z);

    _ = libc_unsetenv("GITHUB_TOKEN");
    defer if (saved_z) |z| {
        _ = libc_setenv("GITHUB_TOKEN", z.ptr, 1);
    };

    const repos = [_]RepoInput{.{ .owner = "o", .repo = "r" }};
    const result = batchQuery(testing.allocator, &repos);
    try testing.expectError(error.NoToken, result);
}

const libc_setenv = @extern(*const fn ([*:0]const u8, [*:0]const u8, c_int) callconv(.c) c_int, .{ .name = "setenv" });
const libc_unsetenv = @extern(*const fn ([*:0]const u8) callconv(.c) c_int, .{ .name = "unsetenv" });
