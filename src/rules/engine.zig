const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const workflow_types = @import("../workflow/types.zig");

pub const Diagnostic = diagnostics.Diagnostic;
pub const DiagnosticList = diagnostics.DiagnosticList;
pub const Severity = diagnostics.Severity;
pub const Category = diagnostics.Category;
pub const Workflow = workflow_types.Workflow;
pub const Job = workflow_types.Job;
pub const Step = workflow_types.Step;

/// A lint rule that can inspect workflows, jobs, and/or steps.
pub const Rule = struct {
    id: []const u8,
    name: []const u8,
    description: []const u8,
    severity: Severity,
    category: Category,
    check_workflow: ?*const fn (*const Workflow, *DiagnosticList) void = null,
    check_job: ?*const fn (*const Job, *DiagnosticList) void = null,
    check_step: ?*const fn (*const Step, *DiagnosticList) void = null,
};

/// The rule engine: holds a set of rules and runs them against workflows.
pub const Engine = struct {
    rules: []const Rule,

    pub fn init(rules: []const Rule) Engine {
        return .{ .rules = rules };
    }

    /// Run all rules against a workflow, returning collected diagnostics.
    pub fn run(self: Engine, allocator: std.mem.Allocator, workflow: *const Workflow) DiagnosticList {
        var list = DiagnosticList.init(allocator);

        for (self.rules) |rule| {
            // Workflow-level checks
            if (rule.check_workflow) |check_fn| {
                check_fn(workflow, &list);
            }

            // Job-level checks
            for (workflow.jobs) |*job| {
                if (rule.check_job) |check_fn| {
                    check_fn(job, &list);
                }

                // Step-level checks
                for (job.steps) |*step| {
                    if (rule.check_step) |check_fn| {
                        check_fn(step, &list);
                    }
                }
            }
        }

        return list;
    }
};

// ============================================================
// Post-processing: dedupe overlapping SC005/SC008 diagnostics
// ============================================================

const stale_refs = @import("stale_refs.zig");
const impostor = @import("impostor.zig");

/// Walk `workflow` and drop any SC005 diagnostic whose underlying step
/// also fired SC008-impostor. Both rules visit steps in identical order
/// (engine.run iterates `rules` outer, `steps` inner), so the K-th SC005
/// diagnostic in `list` corresponds to the K-th step that satisfied
/// SC005's emission condition. We rebuild the same K-th counter here by
/// re-querying the cached tag resolution + impostor verdict for each
/// step, then strike the matching SC005 entries from the list.
///
/// SC008 is structurally a stricter version of SC005 (impostor implies
/// no_tag), so this hides the SC005 noise without affecting the case
/// where SC005 fires alone on a no_tag-but-legitimate SHA.
pub fn postProcess(
    allocator: std.mem.Allocator,
    workflow: *const Workflow,
    list: *DiagnosticList,
) void {
    var drop = std.ArrayList(usize){};
    defer drop.deinit(allocator);

    var k_sc005: usize = 0;
    for (workflow.jobs) |*job| {
        for (job.steps) |*step| {
            const action_ref = step.uses orelse continue;
            if (!action_ref.is_pinned) continue;
            if (action_ref.is_local or action_ref.is_docker) continue;
            const owner = action_ref.owner orelse continue;
            const repo = action_ref.repo orelse continue;
            const sha = action_ref.ref orelse continue;
            if (!isValidGitHubComponent(owner) or !isValidGitHubComponent(repo)) continue;
            if (!isValidSha(sha)) continue;

            // Did SC005 actually fire for this step?
            const tag_res = stale_refs.lookupCachedTagResult(owner, repo, sha) orelse continue;
            if (tag_res != .no_tag) continue;
            defer k_sc005 += 1;

            // Same step also flagged as impostor → drop the K-th SC005.
            if (impostor.shaIsCachedImpostor(owner, repo, sha)) {
                drop.append(allocator, k_sc005) catch return;
            }
        }
    }

    if (drop.items.len == 0) return;

    // `drop` is built in ascending k_sc005 order by the outer loop above,
    // so a single forward cursor into it is enough to answer
    // "should the next SC005 be dropped?" in O(1). This replaces the
    // per-diagnostic scan over `drop` with a single linear pass, so the
    // whole post-process is O(n) in the number of diagnostics.
    var seen_sc005: usize = 0;
    var drop_cursor: usize = 0;
    var write: usize = 0;
    var read: usize = 0;
    while (read < list.items.items.len) : (read += 1) {
        const d = list.items.items[read];
        const is_sc005 = std.mem.eql(u8, d.rule_id, "SC005");
        if (is_sc005) {
            const should_drop = drop_cursor < drop.items.len and
                drop.items[drop_cursor] == seen_sc005;
            seen_sc005 += 1;
            if (should_drop) {
                drop_cursor += 1;
                continue;
            }
        }
        if (write != read) list.items.items[write] = d;
        write += 1;
    }
    list.items.shrinkRetainingCapacity(write);
}

// ============================================================
// Network deadline
// ============================================================

pub var network_deadline_ns: ?i128 = null;

/// Set a deadline for network operations using a timeout duration in nanoseconds.
pub fn setNetworkDeadline(timeout_ns: i128) void {
    network_deadline_ns = std.time.nanoTimestamp() + timeout_ns;
}

/// Check if the network deadline has been exceeded.
pub fn isNetworkDeadlineExceeded() bool {
    const deadline = network_deadline_ns orelse return false;
    return std.time.nanoTimestamp() >= deadline;
}

/// Clear the network deadline.
pub fn clearNetworkDeadline() void {
    network_deadline_ns = null;
}

// ============================================================
// URL component validation
// ============================================================

/// Validate that a string is safe for use in GitHub API URL path segments.
/// Allows: [a-zA-Z0-9._-] (GitHub naming rules for owners, repos, and refs).
/// Rejects: /, ?, #, \, spaces, control characters, etc.
pub fn isValidGitHubComponent(s: []const u8) bool {
    if (s.len == 0 or s.len > 255) return false;
    for (s) |c| {
        switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '.', '_', '-' => {},
            else => return false,
        }
    }
    // Reject "." and any ".." subsequence (path traversal)
    if (std.mem.eql(u8, s, ".") or std.mem.indexOf(u8, s, "..") != null) return false;
    return true;
}

/// Validate a Git ref for safe use in GitHub API URL path segments.
/// Like isValidGitHubComponent but additionally allows '/' for branch refs
/// (e.g. "feature/foo") and '.' for dot-prefixed components.
/// Rejects ".." to prevent path traversal (e.g. "../", "foo/../bar").
pub fn isValidGitRef(s: []const u8) bool {
    if (s.len == 0 or s.len > 255) return false;
    for (s) |c| {
        switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '.', '_', '-', '/' => {},
            else => return false,
        }
    }
    // ".." is the only dot pattern that enables path traversal
    if (std.mem.indexOf(u8, s, "..") != null) return false;
    return true;
}

/// Validate that a string is a valid hex SHA (40 chars, [0-9a-f]).
pub fn isValidSha(s: []const u8) bool {
    if (s.len != 40) return false;
    for (s) |c| {
        switch (c) {
            '0'...'9', 'a'...'f' => {},
            else => return false,
        }
    }
    return true;
}

// ============================================================
// Tests
// ============================================================

const Span = @import("../yaml/types.zig").Span;
const EventConfig = workflow_types.EventConfig;
const Trigger = workflow_types.Trigger;
const ActionRef = workflow_types.ActionRef;

fn makeEmptyTrigger() Trigger {
    return .{ .events = &.{} };
}

// --- Test rule check functions ---

fn warnMissingName(wf: *const Workflow, list: *DiagnosticList) void {
    if (wf.name == null) {
        list.append(.{
            .rule_id = "BP001",
            .severity = .warning,
            .message = "workflow is missing a name",
            .span = Span.point(1, 1, 0),
        }) catch return;
    }
}

fn warnMissingJobName(job: *const Job, list: *DiagnosticList) void {
    if (job.name == null) {
        list.append(.{
            .rule_id = "BP002",
            .severity = .info,
            .message = "job is missing a display name",
            .span = job.span,
        }) catch return;
    }
}

fn checkUnpinnedAction(step: *const Step, list: *DiagnosticList) void {
    if (step.uses) |action_ref| {
        if (!action_ref.is_local and !action_ref.is_docker and !action_ref.is_pinned) {
            list.append(.{
                .rule_id = "SEC001",
                .severity = .warning,
                .message = "action reference is not pinned to a SHA",
                .span = step.uses_value_span orelse step.span,
                .fix_hint = "pin to a full commit SHA",
            }) catch return;
        }
    }
}

const test_rules = [_]Rule{
    .{
        .id = "BP001",
        .name = "workflow-name",
        .description = "Workflows should have a name",
        .severity = .warning,
        .category = .best_practice,
        .check_workflow = &warnMissingName,
    },
    .{
        .id = "BP002",
        .name = "job-name",
        .description = "Jobs should have a display name",
        .severity = .info,
        .category = .best_practice,
        .check_job = &warnMissingJobName,
    },
    .{
        .id = "SEC001",
        .name = "pinned-action",
        .description = "Actions should be pinned to a SHA",
        .severity = .warning,
        .category = .security,
        .check_step = &checkUnpinnedAction,
    },
};

test "engine runs workflow-level rule" {
    const engine = Engine.init(&test_rules);
    const wf = Workflow{ .on = makeEmptyTrigger(), .jobs = &.{} };
    var list = engine.run(std.testing.allocator, &wf);
    defer list.deinit();

    var found = false;
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "BP001")) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

test "engine runs job-level rule" {
    const engine = Engine.init(&test_rules);
    const jobs = [_]Job{
        .{ .id = "build" },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs };
    var list = engine.run(std.testing.allocator, &wf);
    defer list.deinit();

    var found = false;
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "BP002")) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

test "engine runs step-level rule" {
    const engine = Engine.init(&test_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .name = "Build", .steps = &steps },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs };
    var list = engine.run(std.testing.allocator, &wf);
    defer list.deinit();

    var found = false;
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "SEC001")) {
            found = true;
            try std.testing.expect(d.fix_hint != null);
            break;
        }
    }
    try std.testing.expect(found);
}

test "engine no false positive for pinned action" {
    const engine = Engine.init(&test_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .name = "Build", .steps = &steps },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs };
    var list = engine.run(std.testing.allocator, &wf);
    defer list.deinit();

    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "SEC001")) {
            try std.testing.expect(false);
        }
    }
}

test "engine no false positive for local action" {
    const engine = Engine.init(&test_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("./my-action") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .name = "Build", .steps = &steps },
    };
    const wf = Workflow{ .name = "CI", .on = makeEmptyTrigger(), .jobs = &jobs };
    var list = engine.run(std.testing.allocator, &wf);
    defer list.deinit();

    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "SEC001")) {
            try std.testing.expect(false);
        }
    }
}

test "engine returns all expected diagnostics" {
    const engine = Engine.init(&test_rules);

    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
    };
    const jobs = [_]Job{
        .{ .id = "test", .steps = &steps },
    };
    const wf = Workflow{ .on = makeEmptyTrigger(), .jobs = &jobs };
    var list = engine.run(std.testing.allocator, &wf);
    defer list.deinit();

    // Should have BP001, BP002, SEC001
    try std.testing.expect(list.len() >= 3);
}

test "engine with empty rules" {
    const empty_rules = [_]Rule{};
    const engine = Engine.init(&empty_rules);
    const wf = Workflow{ .on = makeEmptyTrigger(), .jobs = &.{} };
    var list = engine.run(std.testing.allocator, &wf);
    defer list.deinit();

    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "engine with empty workflow" {
    const engine = Engine.init(&test_rules);
    const wf = Workflow{ .name = "Empty", .on = makeEmptyTrigger(), .jobs = &.{} };
    var list = engine.run(std.testing.allocator, &wf);
    defer list.deinit();

    // Only BP001 should NOT fire (name is present), no jobs/steps to check
    for (list.items.items) |d| {
        try std.testing.expect(!std.mem.eql(u8, d.rule_id, "BP002"));
        try std.testing.expect(!std.mem.eql(u8, d.rule_id, "SEC001"));
    }
}

test "rule struct field access" {
    const rule = test_rules[0];
    try std.testing.expectEqualStrings("BP001", rule.id);
    try std.testing.expectEqualStrings("workflow-name", rule.name);
    try std.testing.expect(rule.severity == .warning);
    try std.testing.expect(rule.category == .best_practice);
    try std.testing.expect(rule.check_workflow != null);
    try std.testing.expect(rule.check_job == null);
    try std.testing.expect(rule.check_step == null);
}

// --- isValidGitHubComponent tests ---

test "isValidGitHubComponent: valid names" {
    try std.testing.expect(isValidGitHubComponent("actions"));
    try std.testing.expect(isValidGitHubComponent("checkout"));
    try std.testing.expect(isValidGitHubComponent("setup-node"));
    try std.testing.expect(isValidGitHubComponent("my_action.v2"));
    try std.testing.expect(isValidGitHubComponent("Owner-123"));
}

test "isValidGitHubComponent: rejects empty" {
    try std.testing.expect(!isValidGitHubComponent(""));
}

test "isValidGitHubComponent: rejects slash" {
    try std.testing.expect(!isValidGitHubComponent("owner/repo"));
}

test "isValidGitHubComponent: rejects query chars" {
    try std.testing.expect(!isValidGitHubComponent("repo?foo"));
    try std.testing.expect(!isValidGitHubComponent("repo#bar"));
}

test "isValidGitHubComponent: rejects backslash and spaces" {
    try std.testing.expect(!isValidGitHubComponent("repo\\path"));
    try std.testing.expect(!isValidGitHubComponent("repo name"));
}

test "isValidGitHubComponent: rejects control characters" {
    try std.testing.expect(!isValidGitHubComponent("repo\x00name"));
    try std.testing.expect(!isValidGitHubComponent("repo\nname"));
}

test "isValidGitHubComponent: rejects oversized input" {
    const long = "a" ** 256;
    try std.testing.expect(!isValidGitHubComponent(long));
}

test "isValidGitHubComponent: rejects dot segments" {
    try std.testing.expect(!isValidGitHubComponent("."));
    try std.testing.expect(!isValidGitHubComponent(".."));
    try std.testing.expect(!isValidGitHubComponent("foo..bar"));
    try std.testing.expect(!isValidGitHubComponent("..."));
    // Single dot within a name is still valid
    try std.testing.expect(isValidGitHubComponent("my.action"));
}

test "isValidGitHubComponent: allows dot-prefixed names" {
    // .github is a legitimate repo name used widely
    try std.testing.expect(isValidGitHubComponent(".github"));
    try std.testing.expect(isValidGitHubComponent(".hidden"));
    try std.testing.expect(isValidGitHubComponent(".gitignore"));
    try std.testing.expect(isValidGitHubComponent("a.b.c"));
}

test "isValidGitHubComponent: rejects path traversal with separators" {
    // / and \ are rejected by character check
    try std.testing.expect(!isValidGitHubComponent("./"));
    try std.testing.expect(!isValidGitHubComponent("../"));
    // Windows separators
    try std.testing.expect(!isValidGitHubComponent(".\\"));
    try std.testing.expect(!isValidGitHubComponent("..\\"));
    try std.testing.expect(!isValidGitHubComponent("foo\\bar"));
}

// --- isValidGitRef tests ---

test "isValidGitRef: allows slashes" {
    try std.testing.expect(isValidGitRef("feature/foo"));
    try std.testing.expect(isValidGitRef("v1"));
    try std.testing.expect(isValidGitRef("main"));
    try std.testing.expect(isValidGitRef("release/v1.0"));
}

test "isValidGitRef: rejects double dot" {
    try std.testing.expect(!isValidGitRef("main..HEAD"));
}

test "isValidGitRef: allows single-dot patterns (harmless)" {
    try std.testing.expect(isValidGitRef("."));
    try std.testing.expect(isValidGitRef("./"));
    try std.testing.expect(isValidGitRef("./foo"));
    try std.testing.expect(isValidGitRef("foo/./bar"));
    try std.testing.expect(isValidGitRef("foo/."));
    try std.testing.expect(isValidGitRef("foo/.hidden"));
}

test "isValidGitRef: rejects double-dot traversal" {
    try std.testing.expect(!isValidGitRef("../"));
    try std.testing.expect(!isValidGitRef("../foo"));
    try std.testing.expect(!isValidGitRef("foo/../bar"));
}

test "isValidGitRef: rejects unsafe chars" {
    try std.testing.expect(!isValidGitRef("ref?query"));
    try std.testing.expect(!isValidGitRef("ref#fragment"));
    try std.testing.expect(!isValidGitRef("ref name"));
    // Windows separators
    try std.testing.expect(!isValidGitRef("ref\\path"));
    try std.testing.expect(!isValidGitRef(".\\foo"));
    try std.testing.expect(!isValidGitRef("..\\foo"));
}

// --- isValidSha tests ---

test "isValidSha: valid 40-char hex" {
    try std.testing.expect(isValidSha("a5ac7e51b41094c92402da3b24376905380afc29"));
}

test "isValidSha: rejects short string" {
    try std.testing.expect(!isValidSha("a5ac7e"));
}

test "isValidSha: rejects uppercase hex" {
    try std.testing.expect(!isValidSha("A5AC7E51B41094C92402DA3B24376905380AFC29"));
}

test "isValidSha: rejects non-hex chars" {
    try std.testing.expect(!isValidSha("g5ac7e51b41094c92402da3b24376905380afc29"));
}

// --- Network deadline tests ---

test "isNetworkDeadlineExceeded: no deadline set returns false" {
    clearNetworkDeadline();
    try std.testing.expect(!isNetworkDeadlineExceeded());
}

test "isNetworkDeadlineExceeded: future deadline returns false" {
    setNetworkDeadline(60 * std.time.ns_per_s); // 60 seconds
    defer clearNetworkDeadline();
    try std.testing.expect(!isNetworkDeadlineExceeded());
}

test "isNetworkDeadlineExceeded: past deadline returns true" {
    // Set a deadline in the past by using a negative timeout
    network_deadline_ns = std.time.nanoTimestamp() - 1;
    defer clearNetworkDeadline();
    try std.testing.expect(isNetworkDeadlineExceeded());
}

// ============================================================
// postProcess tests
// ============================================================

test "postProcess: drops SC005 when same step is impostor" {
    stale_refs.initStaleRefs(std.testing.allocator, false);
    defer stale_refs.deinitStaleRefs();
    impostor.initImpostor(std.testing.allocator, false);
    defer impostor.deinitImpostor();

    const owner = "evil";
    const repo = "action";
    const sha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    stale_refs.setCachedTagResult(owner, repo, sha, .no_tag);
    impostor.setCachedImpostorResult(owner, repo, sha, .{ .status = .impostor });

    const steps = [_]Step{.{ .uses = ActionRef.parse("evil/action@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef") }};
    const jobs = [_]Job{.{ .id = "j", .steps = &steps }};
    const wf = Workflow{ .on = makeEmptyTrigger(), .jobs = &jobs };

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();
    try list.append(.{
        .rule_id = "SC005",
        .severity = .info,
        .message = "stale",
        .span = Span.point(1, 1, 0),
    });
    try list.append(.{
        .rule_id = "SC008",
        .severity = .warning,
        .message = "impostor",
        .span = Span.point(1, 1, 0),
    });

    postProcess(std.testing.allocator, &wf, &list);

    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("SC008", list.get(0).rule_id);
}

test "postProcess: keeps SC005 when impostor is legitimate" {
    stale_refs.initStaleRefs(std.testing.allocator, false);
    defer stale_refs.deinitStaleRefs();
    impostor.initImpostor(std.testing.allocator, false);
    defer impostor.deinitImpostor();

    const owner = "ok";
    const repo = "lib";
    const sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    stale_refs.setCachedTagResult(owner, repo, sha, .no_tag);
    impostor.setCachedImpostorResult(owner, repo, sha, .{ .status = .legitimate });

    const steps = [_]Step{.{ .uses = ActionRef.parse("ok/lib@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") }};
    const jobs = [_]Job{.{ .id = "j", .steps = &steps }};
    const wf = Workflow{ .on = makeEmptyTrigger(), .jobs = &jobs };

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();
    try list.append(.{
        .rule_id = "SC005",
        .severity = .info,
        .message = "stale",
        .span = Span.point(1, 1, 0),
    });

    postProcess(std.testing.allocator, &wf, &list);

    // legitimate verdict → SC005 stays (SC008 wouldn't have fired anyway).
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("SC005", list.get(0).rule_id);
}

test "postProcess: drops only the matching SC005 entry, not unrelated ones" {
    stale_refs.initStaleRefs(std.testing.allocator, false);
    defer stale_refs.deinitStaleRefs();
    impostor.initImpostor(std.testing.allocator, false);
    defer impostor.deinitImpostor();

    // Two no_tag SHAs: A is impostor, B is legitimate. Engine emits one
    // SC005 per step in step order. We must drop only the SC005 for A.
    const sha_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const sha_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    stale_refs.setCachedTagResult("o", "a", sha_a, .no_tag);
    stale_refs.setCachedTagResult("o", "b", sha_b, .no_tag);
    impostor.setCachedImpostorResult("o", "a", sha_a, .{ .status = .impostor });
    impostor.setCachedImpostorResult("o", "b", sha_b, .{ .status = .legitimate });

    const steps = [_]Step{
        .{ .uses = ActionRef.parse("o/a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") },
        .{ .uses = ActionRef.parse("o/b@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") },
    };
    const jobs = [_]Job{.{ .id = "j", .steps = &steps }};
    const wf = Workflow{ .on = makeEmptyTrigger(), .jobs = &jobs };

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();
    try list.append(.{
        .rule_id = "SC005",
        .severity = .info,
        .message = "stale-A",
        .span = Span.point(1, 1, 0),
    });
    try list.append(.{
        .rule_id = "SC005",
        .severity = .info,
        .message = "stale-B",
        .span = Span.point(1, 1, 0),
    });
    try list.append(.{
        .rule_id = "SC008",
        .severity = .warning,
        .message = "impostor-A",
        .span = Span.point(1, 1, 0),
    });

    postProcess(std.testing.allocator, &wf, &list);

    try std.testing.expectEqual(@as(usize, 2), list.len());
    // The remaining SC005 must be the B one (we dropped index 0).
    try std.testing.expectEqualStrings("SC005", list.get(0).rule_id);
    try std.testing.expectEqualStrings("stale-B", list.get(0).message);
    try std.testing.expectEqualStrings("SC008", list.get(1).rule_id);
}

test "postProcess: no-op when impostor module offline" {
    // stale_refs offline → lookupCachedTagResult returns null → no drops.
    const steps = [_]Step{.{ .uses = ActionRef.parse("o/r@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") }};
    const jobs = [_]Job{.{ .id = "j", .steps = &steps }};
    const wf = Workflow{ .on = makeEmptyTrigger(), .jobs = &jobs };

    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();
    try list.append(.{
        .rule_id = "SC005",
        .severity = .info,
        .message = "stale",
        .span = Span.point(1, 1, 0),
    });

    postProcess(std.testing.allocator, &wf, &list);

    try std.testing.expectEqual(@as(usize, 1), list.len());
}
