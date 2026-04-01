const std = @import("std");
const workflow_types = @import("../workflow/types.zig");
const engine = @import("engine.zig");
const advisory = @import("advisory.zig");
const archived = @import("archived.zig");
const stale_refs = @import("stale_refs.zig");
const refconfusion = @import("refconfusion.zig");

const Allocator = std.mem.Allocator;
const Workflow = workflow_types.Workflow;
const ActionRef = workflow_types.ActionRef;
const isValidGitHubComponent = engine.isValidGitHubComponent;
const isValidGitRef = engine.isValidGitRef;

// ============================================================
// Result types for pre-allocated slots
// ============================================================

const ArchivedResult = struct {
    owner: []const u8,
    repo: []const u8,
    value: ?bool = null,
};

const StaleRefResult = struct {
    owner: []const u8,
    repo: []const u8,
    sha: []const u8,
    value: stale_refs.TagResolution = .unknown,
};

const RefResult = struct {
    owner: []const u8,
    repo: []const u8,
    ref: []const u8,
    value: refconfusion.RefStatus = .fetch_failed,
};

// ============================================================
// Public API
// ============================================================

/// Pre-fetch all network-dependent rule data in parallel using a thread pool.
/// Results are populated into each rule module's cache so that rule execution
/// hits only cached data. Fails open: network errors are silently ignored.
pub fn prefetchAll(backing_allocator: Allocator, workflows: []const Workflow) void {
    // Skip if offline
    if (std.process.hasEnvVar(backing_allocator, "ZGHALINT_OFFLINE") catch false) return;
    if (engine.isNetworkDeadlineExceeded()) return;

    var arena = std.heap.ArenaAllocator.init(backing_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // -- Collect unique action references --
    var has_actions = false;
    var unique_repos = std.StringArrayHashMap(void).init(alloc);
    var unique_sha_pins = std.StringArrayHashMap(void).init(alloc);
    var unique_tag_refs = std.StringArrayHashMap(void).init(alloc);

    collectActionRefs(alloc, workflows, &has_actions, &unique_repos, &unique_sha_pins, &unique_tag_refs);

    const advisory_tasks: usize = if (has_actions) 1 else 0;
    const total = advisory_tasks + unique_repos.count() + unique_sha_pins.count() + unique_tag_refs.count();
    if (total == 0) return;

    // -- Allocate result slots --
    var advisory_result: ?[]const advisory.Advisory = null;

    const archived_results = alloc.alloc(ArchivedResult, unique_repos.count()) catch return;
    for (archived_results, 0..) |*r, i| {
        const key = unique_repos.keys()[i];
        const sep = std.mem.indexOf(u8, key, "/") orelse continue;
        r.* = .{ .owner = key[0..sep], .repo = key[sep + 1 ..] };
    }

    const stale_results = alloc.alloc(StaleRefResult, unique_sha_pins.count()) catch return;
    for (stale_results, 0..) |*r, i| {
        const key = unique_sha_pins.keys()[i];
        const at = std.mem.indexOf(u8, key, "@") orelse continue;
        const sep = std.mem.indexOf(u8, key[0..at], "/") orelse continue;
        r.* = .{ .owner = key[0..sep], .repo = key[sep + 1 .. at], .sha = key[at + 1 ..] };
    }

    const ref_results = alloc.alloc(RefResult, unique_tag_refs.count()) catch return;
    for (ref_results, 0..) |*r, i| {
        const key = unique_tag_refs.keys()[i];
        const at = std.mem.indexOf(u8, key, "@") orelse continue;
        const sep = std.mem.indexOf(u8, key[0..at], "/") orelse continue;
        r.* = .{ .owner = key[0..sep], .repo = key[sep + 1 .. at], .ref = key[at + 1 ..] };
    }

    // -- ThreadSafeAllocator for advisory (needs arena allocation from workers) --
    var advisory_ts: std.heap.ThreadSafeAllocator = .{
        .child_allocator = if (advisory.getArenaAllocator()) |a| a else backing_allocator,
    };

    // -- Thread pool --
    const cpu_count = std.Thread.getCpuCount() catch 1;
    const n_jobs = @min(cpu_count, total, 8);

    var pool: std.Thread.Pool = undefined;
    pool.init(.{ .allocator = backing_allocator, .n_jobs = n_jobs }) catch return;
    defer pool.deinit();

    var wg: std.Thread.WaitGroup = .{};

    // SC003: advisory bulk fetch
    if (has_actions) {
        pool.spawnWg(&wg, fetchAdvisoryTask, .{ &advisory_result, advisory_ts.allocator() });
    }

    // SC004: archived repo checks
    for (archived_results) |*r| {
        pool.spawnWg(&wg, fetchArchivedTask, .{r});
    }

    // SC005: stale ref checks
    for (stale_results) |*r| {
        pool.spawnWg(&wg, fetchStaleRefTask, .{r});
    }

    // SC006: ref confusion checks
    for (ref_results) |*r| {
        pool.spawnWg(&wg, fetchRefTask, .{r});
    }

    pool.waitAndWork(&wg);

    // -- Populate caches (main thread, no contention) --
    if (advisory_result) |adv| {
        advisory.setAdvisoryCache(adv);
    }

    for (archived_results) |r| {
        if (r.value) |v| {
            archived.setCachedResult(r.owner, r.repo, v);
        }
    }

    for (stale_results) |r| {
        if (r.value != .unknown) {
            const key = std.fmt.allocPrint(alloc, "{s}/{s}@{s}", .{ r.owner, r.repo, r.sha }) catch continue;
            stale_refs.setCachedTagResult(key, r.value);
        }
    }

    for (ref_results) |r| {
        if (r.value != .fetch_failed) {
            const key = std.fmt.allocPrint(alloc, "{s}/{s}@{s}", .{ r.owner, r.repo, r.ref }) catch continue;
            refconfusion.setCachedRefResult(key, r.value);
        }
    }
}

// ============================================================
// Collection
// ============================================================

fn collectActionRefs(
    alloc: Allocator,
    workflows: []const Workflow,
    has_actions: *bool,
    unique_repos: *std.StringArrayHashMap(void),
    unique_sha_pins: *std.StringArrayHashMap(void),
    unique_tag_refs: *std.StringArrayHashMap(void),
) void {
    for (workflows) |wf| {
        for (wf.jobs) |job| {
            for (job.steps) |step| {
                const action_ref = step.uses orelse continue;
                if (action_ref.is_local or action_ref.is_docker) continue;
                const owner = action_ref.owner orelse continue;
                const repo = action_ref.repo orelse continue;
                if (!isValidGitHubComponent(owner) or !isValidGitHubComponent(repo)) continue;

                has_actions.* = true;

                // SC004: unique owner/repo
                const repo_key = std.fmt.allocPrint(alloc, "{s}/{s}", .{ owner, repo }) catch continue;
                unique_repos.put(repo_key, {}) catch continue;

                const ref = action_ref.ref orelse continue;

                if (action_ref.is_pinned) {
                    // SC005: unique owner/repo@sha
                    const sha_key = std.fmt.allocPrint(alloc, "{s}/{s}@{s}", .{ owner, repo, ref }) catch continue;
                    unique_sha_pins.put(sha_key, {}) catch continue;
                } else if (isValidGitRef(ref)) {
                    // SC006: unique owner/repo@ref
                    const ref_key = std.fmt.allocPrint(alloc, "{s}/{s}@{s}", .{ owner, repo, ref }) catch continue;
                    unique_tag_refs.put(ref_key, {}) catch continue;
                }
            }
        }
    }
}

// ============================================================
// Worker functions
// ============================================================

fn fetchAdvisoryTask(result: *?[]const advisory.Advisory, ts_alloc: Allocator) void {
    result.* = advisory.fetchAndParse(ts_alloc) catch null;
}

fn fetchArchivedTask(result: *ArchivedResult) void {
    result.value = archived.fetchArchiveStatus(std.heap.page_allocator, result.owner, result.repo) catch null;
}

fn fetchStaleRefTask(result: *StaleRefResult) void {
    result.value = stale_refs.resolveTagForSha(std.heap.page_allocator, result.owner, result.repo, result.sha) catch .unknown;
}

fn fetchRefTask(result: *RefResult) void {
    result.value = refconfusion.queryRefStatus(std.heap.page_allocator, result.owner, result.repo, result.ref);
}

// ============================================================
// Tests
// ============================================================

const testing = std.testing;
const Step = workflow_types.Step;
const Job = workflow_types.Job;

test "collectActionRefs: classifies action references correctly" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const alloc = arena_inst.allocator();

    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") }, // tag ref
        .{ .uses = ActionRef.parse("actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11") }, // pinned
        .{ .uses = ActionRef.parse("./local-action") }, // local, skipped
        .{ .uses = ActionRef.parse("docker://alpine:3.18") }, // docker, skipped
        .{ .run = "echo hello" }, // no uses, skipped
        .{ .uses = ActionRef.parse("owner/repo@main") }, // tag ref
        .{ .uses = ActionRef.parse("owner/repo@v1") }, // tag ref (same owner/repo)
    };
    const jobs = [_]Job{.{ .id = "build", .steps = &steps }};
    const workflows = [_]Workflow{.{ .on = .{ .events = &.{} }, .jobs = &jobs }};

    var has_actions = false;
    var unique_repos = std.StringArrayHashMap(void).init(alloc);
    var unique_sha_pins = std.StringArrayHashMap(void).init(alloc);
    var unique_tag_refs = std.StringArrayHashMap(void).init(alloc);

    collectActionRefs(alloc, &workflows, &has_actions, &unique_repos, &unique_sha_pins, &unique_tag_refs);

    try testing.expect(has_actions);
    try testing.expectEqual(@as(usize, 2), unique_repos.count()); // actions/checkout, owner/repo
    try testing.expectEqual(@as(usize, 1), unique_sha_pins.count()); // actions/checkout@sha
    try testing.expectEqual(@as(usize, 3), unique_tag_refs.count()); // actions/checkout@v4, owner/repo@main, owner/repo@v1
}

test "collectActionRefs: empty workflow produces no tasks" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const alloc = arena_inst.allocator();

    const workflows = [_]Workflow{};

    var has_actions = false;
    var unique_repos = std.StringArrayHashMap(void).init(alloc);
    var unique_sha_pins = std.StringArrayHashMap(void).init(alloc);
    var unique_tag_refs = std.StringArrayHashMap(void).init(alloc);

    collectActionRefs(alloc, &workflows, &has_actions, &unique_repos, &unique_sha_pins, &unique_tag_refs);

    try testing.expect(!has_actions);
    try testing.expectEqual(@as(usize, 0), unique_repos.count());
    try testing.expectEqual(@as(usize, 0), unique_sha_pins.count());
    try testing.expectEqual(@as(usize, 0), unique_tag_refs.count());
}

test "collectActionRefs: invalid owner/repo characters rejected" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const alloc = arena_inst.allocator();

    const steps = [_]Step{
        .{ .uses = ActionRef.parse("evil?org/repo@v1") },
        .{ .uses = ActionRef.parse("org/repo#bad@v1") },
    };
    const jobs = [_]Job{.{ .id = "build", .steps = &steps }};
    const workflows = [_]Workflow{.{ .on = .{ .events = &.{} }, .jobs = &jobs }};

    var has_actions = false;
    var unique_repos = std.StringArrayHashMap(void).init(alloc);
    var unique_sha_pins = std.StringArrayHashMap(void).init(alloc);
    var unique_tag_refs = std.StringArrayHashMap(void).init(alloc);

    collectActionRefs(alloc, &workflows, &has_actions, &unique_repos, &unique_sha_pins, &unique_tag_refs);

    try testing.expect(!has_actions);
    try testing.expectEqual(@as(usize, 0), unique_repos.count());
}
