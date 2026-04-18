//! Pre-fetch network-dependent rule data before the engine runs.
//!
//! Walks every parsed workflow, collects unique `(owner, repo)`,
//! `(owner, repo, sha)`, and `(owner, repo, ref)` triples, then issues
//! sequential REST fetches through the shared HTTP client to populate each
//! rule's cache. Sharing the client keeps the TLS handshake cost to one
//! occurrence even when many actions are referenced.
//!
//! GraphQL batching (`graphql.zig`) and ETag disk cache (`disk_cache.zig`)
//! sit on top of this orchestrator as future layers; the REST path stays
//! available as a fallback for unauthenticated users.

const std = @import("std");
const workflow_types = @import("../workflow/types.zig");
const engine = @import("engine.zig");

const advisory = @import("advisory.zig");
const archived = @import("archived.zig");
const stale_refs = @import("stale_refs.zig");
const refconfusion = @import("refconfusion.zig");
const graphql = @import("graphql.zig");

const Allocator = std.mem.Allocator;
const Workflow = workflow_types.Workflow;

// ============================================================
// Stats
// ============================================================

pub const Stats = struct {
    unique_repos: usize = 0,
    unique_sha_refs: usize = 0,
    unique_tag_or_branch_refs: usize = 0,
};

// ============================================================
// Driver
// ============================================================

/// Orchestrate all network-rule prefetch work for `workflows`.
/// Safe to call with an empty slice, in offline mode, or with any rule
/// module left uninitialized (each rule self-gates on `isActive()`).
pub fn prefetchAll(allocator: Allocator, workflows: []const Workflow) !Stats {
    // Advisory is a single batched fetch regardless of workflow content.
    advisory.prefetch();

    const archived_active = archived.isActive();
    const stale_active = stale_refs.isActive();
    const refconf_active = refconfusion.isActive();

    if (!archived_active and !stale_active and !refconf_active) {
        return .{};
    }

    // Scratch arena keyed off of the caller's allocator; freed on return.
    var scratch_arena = std.heap.ArenaAllocator.init(allocator);
    defer scratch_arena.deinit();
    const scratch = scratch_arena.allocator();

    const ref_sets = try collectRefs(scratch, workflows);

    // Try the GraphQL batch path first (folds archived + SHA + named ref
    // lookups into 1-2 POSTs). Falls back to REST on no-token, parse
    // failure, or rate-limit.
    const used_graphql = tryGraphQlBatch(scratch, ref_sets, archived_active, stale_active, refconf_active);

    if (!used_graphql) {
        if (archived_active) fetchRepos(scratch, ref_sets.repos);
        if (stale_active) fetchShaRefs(scratch, ref_sets.sha_refs);
        if (refconf_active) fetchNamedRefs(scratch, ref_sets.named_refs);
    }

    return .{
        .unique_repos = ref_sets.repos.count(),
        .unique_sha_refs = ref_sets.sha_refs.count(),
        .unique_tag_or_branch_refs = ref_sets.named_refs.count(),
    };
}

// ============================================================
// Ref collection
// ============================================================

const RepoKey = struct {
    owner: []const u8,
    repo: []const u8,
};

const ShaKey = struct {
    owner: []const u8,
    repo: []const u8,
    sha: []const u8,
};

const NamedKey = struct {
    owner: []const u8,
    repo: []const u8,
    ref: []const u8,
};

const RepoSet = std.StringHashMapUnmanaged(RepoKey);
const ShaSet = std.StringHashMapUnmanaged(ShaKey);
const NamedSet = std.StringHashMapUnmanaged(NamedKey);

const RefSets = struct {
    repos: RepoSet,
    sha_refs: ShaSet,
    named_refs: NamedSet,
};

fn collectRefs(allocator: Allocator, workflows: []const Workflow) !RefSets {
    var repos: RepoSet = .{};
    var sha_refs: ShaSet = .{};
    var named_refs: NamedSet = .{};

    for (workflows) |wf| {
        for (wf.jobs) |job| {
            for (job.steps) |step| {
                const action_ref = step.uses orelse continue;
                if (action_ref.is_local or action_ref.is_docker) continue;
                const owner = action_ref.owner orelse continue;
                const repo = action_ref.repo orelse continue;
                if (!engine.isValidGitHubComponent(owner)) continue;
                if (!engine.isValidGitHubComponent(repo)) continue;

                const repo_key = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ owner, repo });
                if (!repos.contains(repo_key)) {
                    try repos.put(allocator, repo_key, .{ .owner = owner, .repo = repo });
                }

                const ref = action_ref.ref orelse continue;
                if (action_ref.is_pinned) {
                    // SHA-pinned → SC005 candidate.
                    const sha_key = try std.fmt.allocPrint(allocator, "{s}/{s}@{s}", .{ owner, repo, ref });
                    if (!sha_refs.contains(sha_key)) {
                        try sha_refs.put(allocator, sha_key, .{ .owner = owner, .repo = repo, .sha = ref });
                    }
                } else {
                    // Tag/branch ref → SC006 candidate.
                    if (!engine.isValidGitRef(ref)) continue;
                    const named_key = try std.fmt.allocPrint(allocator, "{s}/{s}@{s}", .{ owner, repo, ref });
                    if (!named_refs.contains(named_key)) {
                        try named_refs.put(allocator, named_key, .{ .owner = owner, .repo = repo, .ref = ref });
                    }
                }
            }
        }
    }

    return .{ .repos = repos, .sha_refs = sha_refs, .named_refs = named_refs };
}

// ============================================================
// GraphQL batch path
// ============================================================

/// Group refs per repo and issue GraphQL batches. Returns `true` if the
/// batch completed and caches were populated; `false` if the caller
/// should fall back to REST.
fn tryGraphQlBatch(
    scratch: Allocator,
    sets: RefSets,
    archived_active: bool,
    stale_active: bool,
    refconf_active: bool,
) bool {
    if (sets.repos.count() == 0) return false;

    const inputs = buildRepoInputs(
        scratch,
        sets,
        stale_active,
        refconf_active,
    ) catch return false;

    var idx: usize = 0;
    while (idx < inputs.len) {
        if (engine.isNetworkDeadlineExceeded()) return idx > 0;
        const end = @min(idx + graphql.max_repos_per_batch, inputs.len);
        const chunk = inputs[idx..end];

        const results = graphql.batchQuery(scratch, chunk) catch |err| switch (err) {
            error.NoToken => return false, // fall back to REST
            error.RateLimited => return idx > 0, // give up; keep what we have
            else => return false,
        };

        applyResults(results, archived_active, stale_active, refconf_active);
        idx = end;
    }

    return true;
}

fn buildRepoInputs(
    scratch: Allocator,
    sets: RefSets,
    stale_active: bool,
    refconf_active: bool,
) ![]graphql.RepoInput {
    var inputs = try scratch.alloc(graphql.RepoInput, sets.repos.count());
    var shas_by_repo = std.StringHashMapUnmanaged(std.ArrayListUnmanaged([]const u8)){};
    var named_by_repo = std.StringHashMapUnmanaged(std.ArrayListUnmanaged([]const u8)){};

    if (stale_active) {
        var it = sets.sha_refs.valueIterator();
        while (it.next()) |sha_key| {
            const repo_key = try std.fmt.allocPrint(scratch, "{s}/{s}", .{ sha_key.owner, sha_key.repo });
            const gop = try shas_by_repo.getOrPut(scratch, repo_key);
            if (!gop.found_existing) gop.value_ptr.* = .{};
            try gop.value_ptr.append(scratch, sha_key.sha);
        }
    }
    if (refconf_active) {
        var it = sets.named_refs.valueIterator();
        while (it.next()) |named_key| {
            const repo_key = try std.fmt.allocPrint(scratch, "{s}/{s}", .{ named_key.owner, named_key.repo });
            const gop = try named_by_repo.getOrPut(scratch, repo_key);
            if (!gop.found_existing) gop.value_ptr.* = .{};
            try gop.value_ptr.append(scratch, named_key.ref);
        }
    }

    var i: usize = 0;
    var repo_it = sets.repos.iterator();
    while (repo_it.next()) |entry| : (i += 1) {
        const repo_key = entry.key_ptr.*;
        const val = entry.value_ptr.*;

        const sha_slice: []const []const u8 = if (shas_by_repo.getPtr(repo_key)) |list|
            list.items
        else
            &.{};
        const named_slice: []const []const u8 = if (named_by_repo.getPtr(repo_key)) |list|
            list.items
        else
            &.{};

        inputs[i] = .{
            .owner = val.owner,
            .repo = val.repo,
            .sha_refs = sha_slice,
            .named_refs = named_slice,
        };
    }

    return inputs;
}

fn applyResults(
    results: []const graphql.RepoResult,
    archived_active: bool,
    stale_active: bool,
    refconf_active: bool,
) void {
    for (results) |res| {
        if (res.missing) continue;
        if (archived_active) {
            if (res.archived) |b| archived.setCachedResult(res.owner, res.repo, b);
        }
        if (stale_active) {
            for (res.sha_results) |sr| {
                const mapped: stale_refs.TagResolution = switch (sr.resolution) {
                    .has_tag => .has_tag,
                    .no_tag => .no_tag,
                    .unknown => .unknown,
                };
                stale_refs.setCachedTagResult(res.owner, res.repo, sr.sha, mapped);
            }
        }
        if (refconf_active) {
            for (res.named_results) |nr| {
                const status: refconfusion.RefStatus = if (nr.is_tag and nr.is_branch)
                    .ambiguous
                else
                    .not_ambiguous;
                refconfusion.setCachedRefResult(res.owner, res.repo, nr.ref, status);
            }
        }
    }
}

// ============================================================
// Per-rule fetchers
// ============================================================

fn fetchRepos(scratch: Allocator, set: RepoSet) void {
    var it = set.valueIterator();
    while (it.next()) |key| {
        if (engine.isNetworkDeadlineExceeded()) return;
        const is_archived = archived.fetchArchiveStatusPub(scratch, key.owner, key.repo) catch continue;
        archived.setCachedResult(key.owner, key.repo, is_archived);
    }
}

fn fetchShaRefs(scratch: Allocator, set: ShaSet) void {
    var it = set.valueIterator();
    while (it.next()) |key| {
        if (engine.isNetworkDeadlineExceeded()) return;
        const resolution = stale_refs.resolveTagForShaPub(scratch, key.owner, key.repo, key.sha) catch stale_refs.TagResolution.unknown;
        stale_refs.setCachedTagResult(key.owner, key.repo, key.sha, resolution);
    }
}

fn fetchNamedRefs(scratch: Allocator, set: NamedSet) void {
    var it = set.valueIterator();
    while (it.next()) |key| {
        if (engine.isNetworkDeadlineExceeded()) return;
        const status = refconfusion.queryRefStatusPub(scratch, key.owner, key.repo, key.ref);
        refconfusion.setCachedRefResult(key.owner, key.repo, key.ref, status);
    }
}

// ============================================================
// Tests
// ============================================================

const testing = std.testing;
const ActionRef = workflow_types.ActionRef;
const Step = workflow_types.Step;
const Job = workflow_types.Job;

test "prefetchAll: offline-only no-op returns empty stats" {
    // All rule modules left uninitialized (isActive → false).
    const wf = Workflow{ .on = .{ .events = &.{} }, .jobs = &.{} };
    const wfs = [_]Workflow{wf};
    const stats = try prefetchAll(testing.allocator, &wfs);
    try testing.expectEqual(@as(usize, 0), stats.unique_repos);
    try testing.expectEqual(@as(usize, 0), stats.unique_sha_refs);
    try testing.expectEqual(@as(usize, 0), stats.unique_tag_or_branch_refs);
}

test "collectRefs: deduplicates repeated action refs" {
    const step_a = Step{ .uses = ActionRef.parse("actions/checkout@v4") };
    const step_b = Step{ .uses = ActionRef.parse("actions/checkout@v4") };
    const step_c = Step{ .uses = ActionRef.parse("actions/setup-node@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0") };
    const steps = [_]Step{ step_a, step_b, step_c };
    const jobs = [_]Job{.{ .id = "build", .steps = &steps }};
    const wf = Workflow{ .on = .{ .events = &.{} }, .jobs = &jobs };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const sets = try collectRefs(arena.allocator(), &[_]Workflow{wf});

    try testing.expectEqual(@as(usize, 2), sets.repos.count()); // checkout + setup-node
    try testing.expectEqual(@as(usize, 1), sets.sha_refs.count()); // setup-node@SHA
    try testing.expectEqual(@as(usize, 1), sets.named_refs.count()); // checkout@v4
}

test "collectRefs: skips local and docker actions" {
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("./local-action") },
        .{ .uses = ActionRef.parse("docker://alpine:3.18") },
        .{ .run = "echo hi" },
    };
    const jobs = [_]Job{.{ .id = "build", .steps = &steps }};
    const wf = Workflow{ .on = .{ .events = &.{} }, .jobs = &jobs };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const sets = try collectRefs(arena.allocator(), &[_]Workflow{wf});

    try testing.expectEqual(@as(usize, 0), sets.repos.count());
    try testing.expectEqual(@as(usize, 0), sets.sha_refs.count());
    try testing.expectEqual(@as(usize, 0), sets.named_refs.count());
}

test "collectRefs: rejects invalid owner/repo characters" {
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("evil?org/repo@main") },
        .{ .uses = ActionRef.parse("org/evil#repo@main") },
    };
    const jobs = [_]Job{.{ .id = "build", .steps = &steps }};
    const wf = Workflow{ .on = .{ .events = &.{} }, .jobs = &jobs };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const sets = try collectRefs(arena.allocator(), &[_]Workflow{wf});
    try testing.expectEqual(@as(usize, 0), sets.repos.count());
}
