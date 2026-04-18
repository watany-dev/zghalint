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
const disk_cache = @import("disk_cache.zig");

const Allocator = std.mem.Allocator;
const Workflow = workflow_types.Workflow;

// ============================================================
// Stats
// ============================================================

pub const Stats = struct {
    unique_repos: usize = 0,
    unique_sha_refs: usize = 0,
    unique_tag_or_branch_refs: usize = 0,
    cache_hits: usize = 0,
    cache_misses: usize = 0,
};

pub const Options = struct {
    /// When true, ignore existing disk cache entries and refetch everything.
    no_cache: bool = false,
};

// ============================================================
// Driver
// ============================================================

/// Orchestrate all network-rule prefetch work for `workflows`.
/// Safe to call with an empty slice, in offline mode, or with any rule
/// module left uninitialized (each rule self-gates on `isActive()`).
pub fn prefetchAll(allocator: Allocator, workflows: []const Workflow) !Stats {
    return prefetchAllWithOptions(allocator, workflows, .{});
}

/// Like `prefetchAll`, but accepts runtime options such as `no_cache`.
pub fn prefetchAllWithOptions(
    allocator: Allocator,
    workflows: []const Workflow,
    opts: Options,
) !Stats {
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

    var ref_sets = try collectRefs(scratch, workflows);

    var cache_hits: usize = 0;
    if (!opts.no_cache) {
        cache_hits = applyDiskCache(scratch, &ref_sets, archived_active, stale_active, refconf_active);
    }

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
        .cache_hits = cache_hits,
        .cache_misses = ref_sets.repos.count() + ref_sets.sha_refs.count() + ref_sets.named_refs.count(),
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
// Disk cache path (front of the pipeline)
// ============================================================

/// For each unique repo, load any fresh cache entry and populate the rule
/// caches directly. Remove satisfied entries from `sets` so the GraphQL /
/// REST phase only fetches what the disk cache could not supply.
///
/// Returns the number of cache entries applied (for diagnostics).
fn applyDiskCache(
    scratch: Allocator,
    sets: *RefSets,
    archived_active: bool,
    stale_active: bool,
    refconf_active: bool,
) usize {
    var hits: usize = 0;

    // Collect the repos we want to consult, then iterate over a stable
    // snapshot (we mutate `sets` while iterating).
    var repo_keys = std.ArrayList([]const u8){};
    defer repo_keys.deinit(scratch);
    var rk_it = sets.repos.keyIterator();
    while (rk_it.next()) |k| repo_keys.append(scratch, k.*) catch return hits;

    for (repo_keys.items) |repo_key| {
        const val_ptr = sets.repos.getPtr(repo_key) orelse continue;
        const owner = val_ptr.owner;
        const repo = val_ptr.repo;

        const entry = disk_cache.load(scratch, owner, repo) orelse continue;
        hits += applyCacheEntry(scratch, sets, repo_key, owner, repo, entry, archived_active, stale_active, refconf_active);
    }

    return hits;
}

/// Apply a single cached repo entry to the shared rule caches and drop any
/// refs it covered from `sets`. Factored out of `applyDiskCache` so tests
/// can drive the mutation logic without staging files on disk.
fn applyCacheEntry(
    scratch: Allocator,
    sets: *RefSets,
    repo_key: []const u8,
    owner: []const u8,
    repo: []const u8,
    entry: disk_cache.CachedRepo,
    archived_active: bool,
    stale_active: bool,
    refconf_active: bool,
) usize {
    var hits: usize = 0;

    if (archived_active) {
        if (entry.archived) |b| {
            archived.setCachedResult(owner, repo, b);
            _ = sets.repos.remove(repo_key);
            hits += 1;
        }
    }

    if (stale_active) {
        for (entry.shas) |s| {
            var sha_buf = std.ArrayList(u8){};
            defer sha_buf.deinit(scratch);
            sha_buf.writer(scratch).print("{s}/{s}@{s}", .{ owner, repo, s.sha }) catch continue;
            if (sets.sha_refs.getPtr(sha_buf.items)) |_| {
                const mapped: stale_refs.TagResolution = switch (s.resolution) {
                    .has_tag => .has_tag,
                    .no_tag => .no_tag,
                    .unknown => .unknown,
                };
                stale_refs.setCachedTagResult(owner, repo, s.sha, mapped);
                _ = sets.sha_refs.remove(sha_buf.items);
                hits += 1;
            }
        }
    }

    if (refconf_active) {
        for (entry.named) |n| {
            var ref_buf = std.ArrayList(u8){};
            defer ref_buf.deinit(scratch);
            ref_buf.writer(scratch).print("{s}/{s}@{s}", .{ owner, repo, n.ref }) catch continue;
            if (sets.named_refs.getPtr(ref_buf.items)) |_| {
                const status: refconfusion.RefStatus = if (n.is_tag and n.is_branch)
                    .ambiguous
                else
                    .not_ambiguous;
                refconfusion.setCachedRefResult(owner, repo, n.ref, status);
                _ = sets.named_refs.remove(ref_buf.items);
                hits += 1;
            }
        }
    }

    return hits;
}

/// Persist freshly-fetched results for a single repo. Non-fatal: failures
/// are ignored so that a missing cache dir or permission error never
/// blocks the lint run. `dir_override` lets tests redirect the write to a
/// `std.testing.tmpDir`; in production callers pass null to route through
/// the XDG-resolved cache dir.
fn persistRepoResult(
    scratch: Allocator,
    res: graphql.RepoResult,
    dir_override: ?std.fs.Dir,
) void {
    if (res.missing) return;
    const entry: disk_cache.CachedRepo = .{
        .cached_at = std.time.timestamp(),
        .archived = res.archived,
        .shas = blk: {
            var list = scratch.alloc(disk_cache.ShaEntry, res.sha_results.len) catch return;
            for (res.sha_results, 0..) |sr, i| {
                list[i] = .{ .sha = sr.sha, .resolution = sr.resolution };
            }
            break :blk list;
        },
        .named = blk: {
            var list = scratch.alloc(disk_cache.NamedEntry, res.named_results.len) catch return;
            for (res.named_results, 0..) |nr, i| {
                list[i] = .{ .ref = nr.ref, .is_tag = nr.is_tag, .is_branch = nr.is_branch };
            }
            break :blk list;
        },
    };
    if (dir_override) |dir| {
        disk_cache.saveToDir(dir, scratch, res.owner, res.repo, entry) catch return;
    } else {
        disk_cache.save(scratch, res.owner, res.repo, entry) catch return;
    }
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

        applyResults(scratch, results, archived_active, stale_active, refconf_active, null);
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
    scratch: Allocator,
    results: []const graphql.RepoResult,
    archived_active: bool,
    stale_active: bool,
    refconf_active: bool,
    persist_dir: ?std.fs.Dir,
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
        persistRepoResult(scratch, res, persist_dir);
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

test "buildRepoInputs groups sha and named refs by repo" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var repos: RepoSet = .{};
    try repos.put(alloc, "actions/checkout", .{ .owner = "actions", .repo = "checkout" });
    try repos.put(alloc, "actions/setup-node", .{ .owner = "actions", .repo = "setup-node" });

    var sha_refs: ShaSet = .{};
    try sha_refs.put(alloc, "actions/checkout@aa", .{ .owner = "actions", .repo = "checkout", .sha = "aa" });
    try sha_refs.put(alloc, "actions/checkout@bb", .{ .owner = "actions", .repo = "checkout", .sha = "bb" });
    try sha_refs.put(alloc, "actions/setup-node@cc", .{ .owner = "actions", .repo = "setup-node", .sha = "cc" });

    var named_refs: NamedSet = .{};
    try named_refs.put(alloc, "actions/checkout@v4", .{ .owner = "actions", .repo = "checkout", .ref = "v4" });

    const sets = RefSets{ .repos = repos, .sha_refs = sha_refs, .named_refs = named_refs };
    const inputs = try buildRepoInputs(alloc, sets, true, true);

    try testing.expectEqual(@as(usize, 2), inputs.len);

    // Order is hash-map dependent; locate by owner/repo.
    var checkout_idx: usize = 0;
    var setup_idx: usize = 0;
    for (inputs, 0..) |input, i| {
        if (std.mem.eql(u8, input.repo, "checkout")) checkout_idx = i;
        if (std.mem.eql(u8, input.repo, "setup-node")) setup_idx = i;
    }

    try testing.expectEqual(@as(usize, 2), inputs[checkout_idx].sha_refs.len);
    try testing.expectEqual(@as(usize, 1), inputs[checkout_idx].named_refs.len);
    try testing.expectEqualStrings("v4", inputs[checkout_idx].named_refs[0]);
    try testing.expectEqual(@as(usize, 1), inputs[setup_idx].sha_refs.len);
    try testing.expectEqual(@as(usize, 0), inputs[setup_idx].named_refs.len);
}

test "buildRepoInputs: inactive rules leave slices empty" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var repos: RepoSet = .{};
    try repos.put(alloc, "o/r", .{ .owner = "o", .repo = "r" });
    var sha_refs: ShaSet = .{};
    try sha_refs.put(alloc, "o/r@ff", .{ .owner = "o", .repo = "r", .sha = "ff" });
    var named_refs: NamedSet = .{};
    try named_refs.put(alloc, "o/r@v1", .{ .owner = "o", .repo = "r", .ref = "v1" });

    const sets = RefSets{ .repos = repos, .sha_refs = sha_refs, .named_refs = named_refs };
    const inputs = try buildRepoInputs(alloc, sets, false, false);
    try testing.expectEqual(@as(usize, 1), inputs.len);
    try testing.expectEqual(@as(usize, 0), inputs[0].sha_refs.len);
    try testing.expectEqual(@as(usize, 0), inputs[0].named_refs.len);
}

test "applyCacheEntry: fresh hit drops repo/shas/named from sets and counts hits" {
    archived.initForTesting(testing.allocator);
    defer archived.deinitArchived();
    stale_refs.initStaleRefs(testing.allocator, false);
    defer stale_refs.deinitStaleRefs();
    refconfusion.initRefConfusion(testing.allocator, false);
    defer refconfusion.deinitRefConfusion();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const repo_key = "o/r";
    var repos: RepoSet = .{};
    try repos.put(alloc, repo_key, .{ .owner = "o", .repo = "r" });
    var sha_refs: ShaSet = .{};
    const sha_key = "o/r@deadbeef";
    try sha_refs.put(alloc, sha_key, .{ .owner = "o", .repo = "r", .sha = "deadbeef" });
    var named_refs: NamedSet = .{};
    const named_key = "o/r@main";
    try named_refs.put(alloc, named_key, .{ .owner = "o", .repo = "r", .ref = "main" });
    var sets = RefSets{ .repos = repos, .sha_refs = sha_refs, .named_refs = named_refs };

    const shas = [_]disk_cache.ShaEntry{.{ .sha = "deadbeef", .resolution = .no_tag }};
    const named = [_]disk_cache.NamedEntry{.{ .ref = "main", .is_tag = true, .is_branch = true }};
    const entry = disk_cache.CachedRepo{
        .cached_at = std.time.timestamp(),
        .archived = true,
        .shas = @constCast(&shas),
        .named = @constCast(&named),
    };

    const hits = applyCacheEntry(alloc, &sets, repo_key, "o", "r", entry, true, true, true);
    try testing.expectEqual(@as(usize, 3), hits);
    try testing.expectEqual(@as(usize, 0), sets.repos.count());
    try testing.expectEqual(@as(usize, 0), sets.sha_refs.count());
    try testing.expectEqual(@as(usize, 0), sets.named_refs.count());
}

test "applyCacheEntry: inactive rules skip corresponding categories" {
    archived.initForTesting(testing.allocator);
    defer archived.deinitArchived();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var repos: RepoSet = .{};
    try repos.put(alloc, "o/r", .{ .owner = "o", .repo = "r" });
    var sha_refs: ShaSet = .{};
    try sha_refs.put(alloc, "o/r@ff", .{ .owner = "o", .repo = "r", .sha = "ff" });
    var named_refs: NamedSet = .{};
    try named_refs.put(alloc, "o/r@main", .{ .owner = "o", .repo = "r", .ref = "main" });
    var sets = RefSets{ .repos = repos, .sha_refs = sha_refs, .named_refs = named_refs };

    const shas = [_]disk_cache.ShaEntry{.{ .sha = "ff", .resolution = .has_tag }};
    const named = [_]disk_cache.NamedEntry{.{ .ref = "main", .is_tag = true, .is_branch = false }};
    const entry = disk_cache.CachedRepo{
        .cached_at = std.time.timestamp(),
        .archived = false,
        .shas = @constCast(&shas),
        .named = @constCast(&named),
    };

    // archived_active=true, stale_active=false, refconf_active=false
    const hits = applyCacheEntry(alloc, &sets, "o/r", "o", "r", entry, true, false, false);
    try testing.expectEqual(@as(usize, 1), hits);
    try testing.expectEqual(@as(usize, 0), sets.repos.count());
    try testing.expectEqual(@as(usize, 1), sets.sha_refs.count()); // untouched
    try testing.expectEqual(@as(usize, 1), sets.named_refs.count()); // untouched
}

test "applyResults: missing entries are skipped (no rule init required)" {
    // All rule modules left uninitialized; setCached* is a no-op when their
    // arenas are null, so this primarily exercises the missing-guard branch.
    const results = [_]graphql.RepoResult{
        .{ .owner = "o", .repo = "r", .missing = true },
    };
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    applyResults(arena.allocator(), &results, true, true, true, null);
}

test "prefetchAllWithOptions: deadline-expired short-circuits but still counts refs" {
    // Route all network fetches to the deadline-exceeded path so the test
    // never touches the network, yet still exercises the orchestrator's
    // GraphQL-fallback + per-rule REST loops.
    archived.initForTesting(testing.allocator);
    defer archived.deinitArchived();
    stale_refs.initStaleRefs(testing.allocator, false);
    defer stale_refs.deinitStaleRefs();
    refconfusion.initRefConfusion(testing.allocator, false);
    defer refconfusion.deinitRefConfusion();

    engine.network_deadline_ns = std.time.nanoTimestamp() - 1;
    defer engine.clearNetworkDeadline();

    const sha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@" ++ sha) },
        .{ .uses = ActionRef.parse("actions/setup-node@v4") },
    };
    const jobs = [_]Job{.{ .id = "build", .steps = &steps }};
    const wf = Workflow{ .on = .{ .events = &.{} }, .jobs = &jobs };
    const wfs = [_]Workflow{wf};

    const stats = try prefetchAllWithOptions(testing.allocator, &wfs, .{ .no_cache = true });
    try testing.expectEqual(@as(usize, 2), stats.unique_repos);
    try testing.expectEqual(@as(usize, 1), stats.unique_sha_refs);
    try testing.expectEqual(@as(usize, 1), stats.unique_tag_or_branch_refs);
    try testing.expectEqual(@as(usize, 0), stats.cache_hits);
}

test "applyDiskCache: reads entries from XDG_CACHE_HOME and drops them from sets" {
    archived.initForTesting(testing.allocator);
    defer archived.deinitArchived();
    stale_refs.initStaleRefs(testing.allocator, false);
    defer stale_refs.deinitStaleRefs();
    refconfusion.initRefConfusion(testing.allocator, false);
    defer refconfusion.deinitRefConfusion();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_path = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(tmp_path);
    const tmp_path_z = try testing.allocator.dupeZ(u8, tmp_path);
    defer testing.allocator.free(tmp_path_z);

    const saved = std.process.getEnvVarOwned(testing.allocator, "XDG_CACHE_HOME") catch null;
    defer if (saved) |s| testing.allocator.free(s);
    const saved_z: ?[:0]u8 = if (saved) |s| (testing.allocator.dupeZ(u8, s) catch null) else null;
    defer if (saved_z) |z| testing.allocator.free(z);

    _ = libc_setenv("XDG_CACHE_HOME", tmp_path_z.ptr, 1);
    defer {
        if (saved_z) |z| {
            _ = libc_setenv("XDG_CACHE_HOME", z.ptr, 1);
        } else {
            _ = libc_unsetenv("XDG_CACHE_HOME");
        }
    }

    // Stage a fresh entry at the real on-disk cache location so that
    // `disk_cache.load` (via XDG resolution) finds it.
    const now = std.time.timestamp();
    const shas = [_]disk_cache.ShaEntry{.{ .sha = "abc123", .resolution = .no_tag }};
    const named = [_]disk_cache.NamedEntry{.{ .ref = "main", .is_tag = true, .is_branch = true }};
    try disk_cache.save(testing.allocator, "acme", "tool", .{
        .cached_at = now,
        .archived = false,
        .shas = @constCast(&shas),
        .named = @constCast(&named),
    });

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const repo_key = "acme/tool";
    var repos: RepoSet = .{};
    try repos.put(alloc, repo_key, .{ .owner = "acme", .repo = "tool" });
    var sha_refs: ShaSet = .{};
    try sha_refs.put(alloc, "acme/tool@abc123", .{ .owner = "acme", .repo = "tool", .sha = "abc123" });
    var named_refs: NamedSet = .{};
    try named_refs.put(alloc, "acme/tool@main", .{ .owner = "acme", .repo = "tool", .ref = "main" });
    var sets = RefSets{ .repos = repos, .sha_refs = sha_refs, .named_refs = named_refs };

    const hits = applyDiskCache(alloc, &sets, true, true, true);
    try testing.expectEqual(@as(usize, 3), hits);
    try testing.expectEqual(@as(usize, 0), sets.repos.count());
    try testing.expectEqual(@as(usize, 0), sets.sha_refs.count());
    try testing.expectEqual(@as(usize, 0), sets.named_refs.count());
}

const libc_setenv = @extern(*const fn ([*:0]const u8, [*:0]const u8, c_int) callconv(.c) c_int, .{ .name = "setenv" });
const libc_unsetenv = @extern(*const fn ([*:0]const u8) callconv(.c) c_int, .{ .name = "unsetenv" });

test "applyResults: persists repo state to the provided cache dir" {
    archived.initForTesting(testing.allocator);
    defer archived.deinitArchived();
    stale_refs.initStaleRefs(testing.allocator, false);
    defer stale_refs.deinitStaleRefs();
    refconfusion.initRefConfusion(testing.allocator, false);
    defer refconfusion.deinitRefConfusion();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const sha_res = [_]graphql.ShaTagResult{.{ .sha = "abcd", .resolution = .has_tag }};
    const named_res = [_]graphql.NamedRefResult{.{ .ref = "main", .is_tag = true, .is_branch = true }};
    const results = [_]graphql.RepoResult{
        .{
            .owner = "o",
            .repo = "r",
            .archived = false,
            .sha_results = &sha_res,
            .named_results = &named_res,
        },
    };

    applyResults(alloc, &results, true, true, true, tmp.dir);

    // The cache file should exist and reload cleanly.
    const loaded = disk_cache.loadFromDir(tmp.dir, testing.allocator, "o", "r") orelse
        return error.TestExpectedNonNull;
    defer {
        for (loaded.shas) |s| testing.allocator.free(s.sha);
        testing.allocator.free(loaded.shas);
        for (loaded.named) |n| testing.allocator.free(n.ref);
        testing.allocator.free(loaded.named);
    }
    try testing.expect(!loaded.archived.?);
    try testing.expectEqual(@as(usize, 1), loaded.shas.len);
    try testing.expectEqualStrings("abcd", loaded.shas[0].sha);
    try testing.expectEqual(graphql.ShaTagResolution.has_tag, loaded.shas[0].resolution);
    try testing.expectEqual(@as(usize, 1), loaded.named.len);
    try testing.expect(loaded.named[0].is_tag);
    try testing.expect(loaded.named[0].is_branch);
}
