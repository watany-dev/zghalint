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
const impostor = @import("impostor.zig");
const graphql = @import("graphql.zig");
const disk_cache = @import("disk_cache.zig");
const http_client = @import("http_client.zig");

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
    const impostor_active = impostor.isActive();

    if (!archived_active and !stale_active and !refconf_active and !impostor_active) {
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
    // failure, or rate-limit. SC008's REST compare phase rides on top of
    // the same GraphQL data so it shares whatever batches succeeded.
    var pending_compares = std.ArrayList(PendingCompare){};
    defer pending_compares.deinit(scratch);

    const used_graphql = tryGraphQlBatch(
        scratch,
        ref_sets,
        archived_active,
        stale_active,
        refconf_active,
        impostor_active,
        &pending_compares,
    );

    if (!used_graphql) {
        if (archived_active) fetchRepos(scratch, ref_sets.repos);
        if (stale_active) fetchShaRefs(scratch, ref_sets.sha_refs);
        if (refconf_active) fetchNamedRefs(scratch, ref_sets.named_refs);
    }

    // SC008 step3/4: compare REST against default branch and remaining refs
    // for any SHAs the GraphQL data couldn't classify directly.
    if (impostor_active and pending_compares.items.len > 0) {
        runImpostorCompares(scratch, pending_compares.items);
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
///
/// `pending` collects SC008 SHAs that need a follow-up REST compare phase
/// because the GraphQL data alone couldn't classify them as legitimate.
/// When `impostor_active` is false the slot is unused.
fn tryGraphQlBatch(
    scratch: Allocator,
    sets: RefSets,
    archived_active: bool,
    stale_active: bool,
    refconf_active: bool,
    impostor_active: bool,
    pending: *std.ArrayList(PendingCompare),
) bool {
    if (sets.repos.count() == 0) return false;

    const inputs = buildRepoInputs(
        scratch,
        sets,
        stale_active,
        refconf_active,
        impostor_active,
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

        applyResults(
            scratch,
            results,
            archived_active,
            stale_active,
            refconf_active,
            impostor_active,
            pending,
            null,
        );
        idx = end;
    }

    return true;
}

fn buildRepoInputs(
    scratch: Allocator,
    sets: RefSets,
    stale_active: bool,
    refconf_active: bool,
    impostor_active: bool,
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
            // SC008 only needs the extra branch + default fetch when there
            // are SHA-pinned refs to evaluate against. Without SHAs there's
            // nothing to classify even if impostor checking is on.
            .needs_impostor = impostor_active and sha_slice.len > 0,
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
    impostor_active: bool,
    pending: ?*std.ArrayList(PendingCompare),
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
        if (impostor_active) {
            classifyImpostorFromGraphql(scratch, res, pending);
        }
        persistRepoResult(scratch, res, persist_dir);
    }
}

// ============================================================
// SC008 impostor classification
// ============================================================

/// Deferred work for SC008's compare REST phase: SHAs that the GraphQL
/// data alone could not classify as legitimate.
const PendingCompare = struct {
    owner: []const u8,
    repo: []const u8,
    sha: []const u8,
    /// Default branch + HEAD oid; null if GraphQL didn't surface it.
    default_branch: ?graphql.NamedOid,
    /// Tag refs to use as compare bases in step4 if step3 fails.
    tag_oids: []const graphql.NamedOid,
    /// Branch refs to use as compare bases in step4 if step3 fails.
    branch_oids: []const graphql.NamedOid,
};

/// Run steps 1+2 (in-memory tag/branch oid match) for every SHA the
/// GraphQL response surfaced. Legitimate / unknown verdicts are committed
/// straight into the impostor cache here. SHAs that survive both steps
/// are appended to `pending` for the compare REST phase.
fn classifyImpostorFromGraphql(
    scratch: Allocator,
    res: graphql.RepoResult,
    pending: ?*std.ArrayList(PendingCompare),
) void {
    if (res.sha_results.len == 0) return;

    // Pagination incomplete on either listing means step1/step2 negative
    // verdicts can't be trusted; fail-closed to unknown for the whole
    // repo to avoid false-positive impostor flags.
    const refs_complete = res.tag_oids_complete and res.branch_oids_complete;

    for (res.sha_results) |sr| {
        if (!refs_complete) {
            impostor.setCachedImpostorResult(res.owner, res.repo, sr.sha, .{ .status = .unknown });
            continue;
        }

        // step1: SHA matches a tag's commit oid.
        if (oidIn(res.tag_oids, sr.sha)) {
            impostor.setCachedImpostorResult(res.owner, res.repo, sr.sha, .{ .status = .legitimate });
            continue;
        }

        // step2: SHA matches a branch HEAD oid.
        if (oidIn(res.branch_oids, sr.sha)) {
            impostor.setCachedImpostorResult(res.owner, res.repo, sr.sha, .{ .status = .legitimate });
            continue;
        }

        // step3/4 require REST. Defer.
        if (pending) |list| {
            list.append(scratch, .{
                .owner = res.owner,
                .repo = res.repo,
                .sha = sr.sha,
                .default_branch = res.default_branch,
                .tag_oids = res.tag_oids,
                .branch_oids = res.branch_oids,
            }) catch {
                // Allocator failure: degrade to unknown so SC008 stays silent.
                impostor.setCachedImpostorResult(res.owner, res.repo, sr.sha, .{ .status = .unknown });
            };
        } else {
            impostor.setCachedImpostorResult(res.owner, res.repo, sr.sha, .{ .status = .unknown });
        }
    }
}

fn oidIn(refs: []const graphql.NamedOid, target: []const u8) bool {
    for (refs) |r| {
        if (std.mem.eql(u8, r.oid, target)) return true;
    }
    return false;
}

/// Outcome of a `/compare/{base}...{head}` REST call.
const CompareStatus = enum { reachable, unreachable_, unknown };

/// Run SC008 step3 + step4 for every pending SHA. Each pending entry is
/// resolved into a final ImpostorStatus and committed to the impostor
/// cache (with suggested candidates when the verdict is impostor).
fn runImpostorCompares(scratch: Allocator, pending: []const PendingCompare) void {
    for (pending) |pc| {
        if (engine.isNetworkDeadlineExceeded()) {
            impostor.setCachedImpostorResult(pc.owner, pc.repo, pc.sha, .{ .status = .unknown });
            continue;
        }

        const verdict = classifyImpostorViaCompare(scratch, pc);
        impostor.setCachedImpostorResult(pc.owner, pc.repo, pc.sha, verdict);
    }
}

/// Decide impostor status by issuing compare REST calls. Returns the
/// final cached result (status + suggested candidates for fix_hint).
fn classifyImpostorViaCompare(
    scratch: Allocator,
    pc: PendingCompare,
) impostor.CachedResult {
    // step3: compare against the default branch HEAD if known.
    if (pc.default_branch) |def| {
        switch (compareRest(scratch, pc.owner, pc.repo, def.name, pc.sha)) {
            .reachable => return .{
                .status = .legitimate,
            },
            .unknown => {
                // Network/auth failure on the default-branch compare leaves
                // the verdict ambiguous; fail-closed.
                return .{ .status = .unknown };
            },
            .unreachable_ => {},
        }
    }

    // step4: try every other ref as a compare base. Branches first, then
    // tags — branches change more often, so an ahead/diverged sha is more
    // likely to surface there. Any reachable hit short-circuits to
    // legitimate.
    var saw_unknown = false;
    if (compareAllRefs(scratch, pc, pc.branch_oids, pc.default_branch)) |found_legit| {
        if (found_legit == .legit) return .{ .status = .legitimate };
        if (found_legit == .unknown) saw_unknown = true;
    }
    if (compareAllRefs(scratch, pc, pc.tag_oids, null)) |found_legit| {
        if (found_legit == .legit) return .{ .status = .legitimate };
        if (found_legit == .unknown) saw_unknown = true;
    }

    if (saw_unknown) return .{ .status = .unknown };

    // Every ref came back ahead/diverged. Surface impostor with up to 3
    // tag candidates and the default branch in the fix_hint.
    return .{
        .status = .impostor,
        .suggested_tags = bridgeOids(scratch, pc.tag_oids),
        .suggested_default = if (pc.default_branch) |def|
            bridgeSingle(def)
        else
            null,
    };
}

const RefSweepResult = enum { legit, all_unreachable, unknown };

/// Iterate through `refs`, issuing a compare for each one. Returns
/// `.legit` on the first reachable ref, `.unknown` if at least one
/// compare came back unknown (and none reachable), `.all_unreachable`
/// when every compare was decisively ahead/diverged. `skip` lets the
/// caller avoid re-checking a ref already tried (the default branch).
fn compareAllRefs(
    scratch: Allocator,
    pc: PendingCompare,
    refs: []const graphql.NamedOid,
    skip: ?graphql.NamedOid,
) ?RefSweepResult {
    if (refs.len == 0) return null;
    var saw_unknown = false;
    for (refs) |r| {
        if (engine.isNetworkDeadlineExceeded()) return .unknown;
        if (skip) |s| {
            if (std.mem.eql(u8, s.name, r.name)) continue;
        }
        switch (compareRest(scratch, pc.owner, pc.repo, r.name, pc.sha)) {
            .reachable => return .legit,
            .unknown => saw_unknown = true,
            .unreachable_ => {},
        }
    }
    if (saw_unknown) return .unknown;
    return .all_unreachable;
}

/// Issue `GET /repos/{owner}/{repo}/compare/{base}...{head}` and translate
/// the returned `status` field. Any non-200 response or parse failure
/// returns `.unknown` so SC008 fail-closes on uncertainty.
fn compareRest(
    scratch: Allocator,
    owner: []const u8,
    repo: []const u8,
    base: []const u8,
    head: []const u8,
) CompareStatus {
    if (!engine.isValidGitHubComponent(owner)) return .unknown;
    if (!engine.isValidGitHubComponent(repo)) return .unknown;
    if (!engine.isValidGitRef(base)) return .unknown;
    if (!engine.isValidSha(head)) return .unknown;

    const url = std.fmt.allocPrint(
        scratch,
        "https://api.github.com/repos/{s}/{s}/compare/{s}...{s}",
        .{ owner, repo, base, head },
    ) catch return .unknown;

    var aw: std.Io.Writer.Allocating = .init(scratch);
    defer aw.deinit();

    const auth_value = http_client.getAuthHeader(scratch);
    defer if (auth_value) |a| scratch.free(a);

    var headers_buf: [3]std.http.Header = undefined;
    const header_count = http_client.writeStandardHeaders(&headers_buf, auth_value);

    const result = http_client.fetch(.{
        .location = .{ .url = url },
        .response_writer = &aw.writer,
        .headers = .{ .user_agent = .{ .override = http_client.user_agent } },
        .extra_headers = headers_buf[0..header_count],
    }) catch return .unknown;

    if (result.status != .ok) return .unknown;

    var response_list = aw.toArrayList();
    defer response_list.deinit(scratch);

    return parseCompareStatus(scratch, response_list.items);
}

fn parseCompareStatus(scratch: Allocator, body: []const u8) CompareStatus {
    const root = std.json.parseFromSliceLeaky(std.json.Value, scratch, body, .{}) catch return .unknown;
    const obj = switch (root) {
        .object => |o| o,
        else => return .unknown,
    };
    const status_val = obj.get("status") orelse return .unknown;
    const status = switch (status_val) {
        .string => |s| s,
        else => return .unknown,
    };
    if (std.mem.eql(u8, status, "identical") or std.mem.eql(u8, status, "behind")) {
        return .reachable;
    }
    if (std.mem.eql(u8, status, "ahead") or std.mem.eql(u8, status, "diverged")) {
        return .unreachable_;
    }
    return .unknown;
}

/// Convert graphql.NamedOid slices into the impostor.NamedOid layout.
/// Both structs are field-compatible but live in different modules to
/// avoid a circular import.
fn bridgeOids(scratch: Allocator, src: []const graphql.NamedOid) []const impostor.NamedOid {
    if (src.len == 0) return &.{};
    var out = scratch.alloc(impostor.NamedOid, src.len) catch return &.{};
    for (src, 0..) |s, i| {
        out[i] = .{ .name = s.name, .oid = s.oid };
    }
    return out;
}

fn bridgeSingle(src: graphql.NamedOid) impostor.NamedOid {
    return .{ .name = src.name, .oid = src.oid };
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
    const inputs = try buildRepoInputs(alloc, sets, true, true, false);

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
    const inputs = try buildRepoInputs(alloc, sets, false, false, false);
    try testing.expectEqual(@as(usize, 1), inputs.len);
    try testing.expectEqual(@as(usize, 0), inputs[0].sha_refs.len);
    try testing.expectEqual(@as(usize, 0), inputs[0].named_refs.len);
    try testing.expect(!inputs[0].needs_impostor);
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
    applyResults(arena.allocator(), &results, true, true, true, false, null, null);
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
    const fake_sha = "abc1230000000000000000000000000000000000";
    const shas = [_]disk_cache.ShaEntry{.{ .sha = fake_sha, .resolution = .no_tag }};
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
    try sha_refs.put(alloc, "acme/tool@" ++ fake_sha, .{ .owner = "acme", .repo = "tool", .sha = fake_sha });
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

    const fake_sha = "abcd000000000000000000000000000000000000";
    const sha_res = [_]graphql.ShaTagResult{.{ .sha = fake_sha, .resolution = .has_tag }};
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

    applyResults(alloc, &results, true, true, true, false, null, tmp.dir);

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
    try testing.expectEqualStrings(fake_sha, loaded.shas[0].sha);
    try testing.expectEqual(graphql.ShaTagResolution.has_tag, loaded.shas[0].resolution);
    try testing.expectEqual(@as(usize, 1), loaded.named.len);
    try testing.expect(loaded.named[0].is_tag);
    try testing.expect(loaded.named[0].is_branch);
}

// ============================================================
// SC008 prefetch tests
// ============================================================

test "buildRepoInputs: impostor_active sets needs_impostor only when SHAs exist" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var repos: RepoSet = .{};
    try repos.put(alloc, "o/has", .{ .owner = "o", .repo = "has" });
    try repos.put(alloc, "o/none", .{ .owner = "o", .repo = "none" });

    var sha_refs: ShaSet = .{};
    try sha_refs.put(alloc, "o/has@aa", .{ .owner = "o", .repo = "has", .sha = "aa" });

    const named_refs: NamedSet = .{};

    const sets = RefSets{ .repos = repos, .sha_refs = sha_refs, .named_refs = named_refs };
    const inputs = try buildRepoInputs(alloc, sets, true, false, true);

    try testing.expectEqual(@as(usize, 2), inputs.len);
    var has_idx: usize = 0;
    var none_idx: usize = 0;
    for (inputs, 0..) |input, i| {
        if (std.mem.eql(u8, input.repo, "has")) has_idx = i;
        if (std.mem.eql(u8, input.repo, "none")) none_idx = i;
    }
    try testing.expect(inputs[has_idx].needs_impostor);
    try testing.expect(!inputs[none_idx].needs_impostor);
}

test "classifyImpostorFromGraphql: tag oid match yields legitimate (no pending)" {
    impostor.initImpostor(testing.allocator, false);
    defer impostor.deinitImpostor();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const sha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    const tag_oids = [_]graphql.NamedOid{.{ .name = "v1", .oid = sha }};
    const sha_results = [_]graphql.ShaTagResult{.{ .sha = sha, .resolution = .has_tag }};
    const res = graphql.RepoResult{
        .owner = "o",
        .repo = "r",
        .sha_results = &sha_results,
        .tag_oids = &tag_oids,
    };

    var pending = std.ArrayList(PendingCompare){};
    defer pending.deinit(alloc);
    classifyImpostorFromGraphql(alloc, res, &pending);

    try testing.expectEqual(@as(usize, 0), pending.items.len);
    const cached = impostor.lookupCachedImpostorResult("o", "r", sha) orelse return error.TestExpectedNonNull;
    try testing.expectEqual(impostor.ImpostorStatus.legitimate, cached.status);
}

test "classifyImpostorFromGraphql: branch HEAD match yields legitimate" {
    impostor.initImpostor(testing.allocator, false);
    defer impostor.deinitImpostor();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const sha = "0123456789abcdef0123456789abcdef01234567";
    const branch_oids = [_]graphql.NamedOid{.{ .name = "main", .oid = sha }};
    const sha_results = [_]graphql.ShaTagResult{.{ .sha = sha, .resolution = .no_tag }};
    const res = graphql.RepoResult{
        .owner = "o",
        .repo = "r",
        .sha_results = &sha_results,
        .branch_oids = &branch_oids,
    };

    var pending = std.ArrayList(PendingCompare){};
    defer pending.deinit(alloc);
    classifyImpostorFromGraphql(alloc, res, &pending);

    try testing.expectEqual(@as(usize, 0), pending.items.len);
    const cached = impostor.lookupCachedImpostorResult("o", "r", sha) orelse return error.TestExpectedNonNull;
    try testing.expectEqual(impostor.ImpostorStatus.legitimate, cached.status);
}

test "classifyImpostorFromGraphql: pagination incomplete fails closed to unknown" {
    impostor.initImpostor(testing.allocator, false);
    defer impostor.deinitImpostor();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const sha = "0011223344556677889900112233445566778899";
    const sha_results = [_]graphql.ShaTagResult{.{ .sha = sha, .resolution = .unknown }};
    const res = graphql.RepoResult{
        .owner = "o",
        .repo = "r",
        .sha_results = &sha_results,
        .tag_oids_complete = false,
    };

    var pending = std.ArrayList(PendingCompare){};
    defer pending.deinit(alloc);
    classifyImpostorFromGraphql(alloc, res, &pending);

    try testing.expectEqual(@as(usize, 0), pending.items.len);
    const cached = impostor.lookupCachedImpostorResult("o", "r", sha) orelse return error.TestExpectedNonNull;
    try testing.expectEqual(impostor.ImpostorStatus.unknown, cached.status);
}

test "classifyImpostorFromGraphql: no match queues pending compare entry" {
    impostor.initImpostor(testing.allocator, false);
    defer impostor.deinitImpostor();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const sha = "ffffffffffffffffffffffffffffffffffffffff";
    const tag_oids = [_]graphql.NamedOid{.{ .name = "v1", .oid = "aaaaaaaa" }};
    const branch_oids = [_]graphql.NamedOid{.{ .name = "main", .oid = "bbbbbbbb" }};
    const sha_results = [_]graphql.ShaTagResult{.{ .sha = sha, .resolution = .no_tag }};
    const default_branch = graphql.NamedOid{ .name = "main", .oid = "bbbbbbbb" };
    const res = graphql.RepoResult{
        .owner = "o",
        .repo = "r",
        .sha_results = &sha_results,
        .tag_oids = &tag_oids,
        .branch_oids = &branch_oids,
        .default_branch = default_branch,
    };

    var pending = std.ArrayList(PendingCompare){};
    defer pending.deinit(alloc);
    classifyImpostorFromGraphql(alloc, res, &pending);

    try testing.expectEqual(@as(usize, 1), pending.items.len);
    try testing.expectEqualStrings(sha, pending.items[0].sha);
    try testing.expect(pending.items[0].default_branch != null);
    try testing.expectEqualStrings("main", pending.items[0].default_branch.?.name);

    // No verdict cached yet; the compare phase will commit it.
    try testing.expect(impostor.lookupCachedImpostorResult("o", "r", sha) == null);
}

test "classifyImpostorFromGraphql: null pending forces unknown" {
    impostor.initImpostor(testing.allocator, false);
    defer impostor.deinitImpostor();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    _ = alloc;

    const sha = "1111111111111111111111111111111111111111";
    const sha_results = [_]graphql.ShaTagResult{.{ .sha = sha, .resolution = .no_tag }};
    const res = graphql.RepoResult{
        .owner = "o",
        .repo = "r",
        .sha_results = &sha_results,
    };

    classifyImpostorFromGraphql(testing.allocator, res, null);

    const cached = impostor.lookupCachedImpostorResult("o", "r", sha) orelse return error.TestExpectedNonNull;
    try testing.expectEqual(impostor.ImpostorStatus.unknown, cached.status);
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

test "runImpostorCompares: deadline-expired entries all map to unknown" {
    impostor.initImpostor(testing.allocator, false);
    defer impostor.deinitImpostor();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    engine.network_deadline_ns = std.time.nanoTimestamp() - 1;
    defer engine.clearNetworkDeadline();

    const pending = [_]PendingCompare{
        .{
            .owner = "o",
            .repo = "r",
            .sha = "2222222222222222222222222222222222222222",
            .default_branch = null,
            .tag_oids = &.{},
            .branch_oids = &.{},
        },
    };

    runImpostorCompares(alloc, &pending);

    const cached = impostor.lookupCachedImpostorResult("o", "r", "2222222222222222222222222222222222222222") orelse
        return error.TestExpectedNonNull;
    try testing.expectEqual(impostor.ImpostorStatus.unknown, cached.status);
}

test "compareRest: invalid component arguments fail closed to unknown without network" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Bad owner (path traversal), bad sha (not hex), bad ref (slash + dot dot).
    try testing.expectEqual(CompareStatus.unknown, compareRest(alloc, "..", "r", "main", "0000000000000000000000000000000000000000"));
    try testing.expectEqual(CompareStatus.unknown, compareRest(alloc, "o", "..", "main", "0000000000000000000000000000000000000000"));
    try testing.expectEqual(CompareStatus.unknown, compareRest(alloc, "o", "r", "../evil", "0000000000000000000000000000000000000000"));
    try testing.expectEqual(CompareStatus.unknown, compareRest(alloc, "o", "r", "main", "not-a-sha"));
}
