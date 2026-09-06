const std = @import("std");
const test_support = @import("../test_support.zig");
const diagnostics = @import("../diagnostics.zig");
const workflow_types = @import("../workflow/types.zig");

pub const Diagnostic = diagnostics.Diagnostic;
pub const DiagnosticList = diagnostics.DiagnosticList;
pub const Severity = diagnostics.Severity;
pub const Category = diagnostics.Category;
pub const Workflow = workflow_types.Workflow;
pub const Job = workflow_types.Job;
pub const Step = workflow_types.Step;

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

pub const Engine = struct {
    rules: []const Rule,

    pub fn init(rules: []const Rule) Engine {
        return .{ .rules = rules };
    }

    pub fn run(self: Engine, allocator: std.mem.Allocator, workflow: *const Workflow) DiagnosticList {
        var list = DiagnosticList.init(allocator);

        for (self.rules) |rule| {
            if (rule.check_workflow) |check_fn| {
                check_fn(workflow, &list);
            }

            for (workflow.jobs) |*job| {
                if (rule.check_job) |check_fn| {
                    check_fn(job, &list);
                }

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

const stale_refs = @import("stale_refs.zig");
const impostor = @import("impostor.zig");

/// Both rules visit steps in identical order (engine.run iterates `rules`
/// outer, `steps` inner), so the K-th SC005 diagnostic in `list` corresponds
/// to the K-th step that satisfied SC005's emission condition. The same K-th
/// counter is rebuilt here by re-querying the cached tag resolution +
/// impostor verdict for each step, then the matching SC005 entries are
/// struck from the list.
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

pub var network_deadline_ns: ?i128 = null;

pub fn setNetworkDeadline(timeout_ns: i128) void {
    network_deadline_ns = std.time.nanoTimestamp() + timeout_ns;
}

pub fn isNetworkDeadlineExceeded() bool {
    const deadline = network_deadline_ns orelse return false;
    return std.time.nanoTimestamp() >= deadline;
}

pub fn clearNetworkDeadline() void {
    network_deadline_ns = null;
}

/// Guards GitHub API URL path segments; the allowed character set is
/// GitHub's naming rules for owners, repos, and refs.
pub fn isValidGitHubComponent(s: []const u8) bool {
    if (s.len == 0 or s.len > 255) return false;
    for (s) |c| {
        switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '.', '_', '-' => {},
            else => return false,
        }
    }
    // "." and ".." would enable path traversal in the URL.
    if (std.mem.eql(u8, s, ".") or std.mem.indexOf(u8, s, "..") != null) return false;
    return true;
}

/// Like isValidGitHubComponent but also allows '/' because branch refs
/// (e.g. "feature/foo") contain it.
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

const Span = @import("../yaml/types.zig").Span;
const EventConfig = workflow_types.EventConfig;
const Trigger = workflow_types.Trigger;
const ActionRef = workflow_types.ActionRef;

// The engine only needs to know that each hook is reached, so these stubs fire
// unconditionally instead of re-implementing real rules; the actual BP/SEC
// logic is covered where those rules live.

fn markWorkflow(wf: *const Workflow, list: *DiagnosticList) void {
    _ = wf;
    list.append(.{
        .rule_id = "TEST-WF",
        .severity = .warning,
        .message = "workflow hook ran",
        .span = Span.point(1, 1, 0),
    }) catch return;
}

fn markJob(job: *const Job, list: *DiagnosticList) void {
    list.append(.{
        .rule_id = "TEST-JOB",
        .severity = .info,
        .message = "job hook ran",
        .span = job.span,
    }) catch return;
}

fn markStep(step: *const Step, list: *DiagnosticList) void {
    list.append(.{
        .rule_id = "TEST-STEP",
        .severity = .warning,
        .message = "step hook ran",
        .span = step.uses_value_span orelse step.span,
        .fix_hint = "step hook fix hint",
    }) catch return;
}

const test_rules = [_]Rule{
    .{
        .id = "TEST-WF",
        .name = "workflow-hook",
        .description = "Fires once per workflow",
        .severity = .warning,
        .category = .best_practice,
        .check_workflow = &markWorkflow,
    },
    .{
        .id = "TEST-JOB",
        .name = "job-hook",
        .description = "Fires once per job",
        .severity = .info,
        .category = .best_practice,
        .check_job = &markJob,
    },
    .{
        .id = "TEST-STEP",
        .name = "step-hook",
        .description = "Fires once per step",
        .severity = .warning,
        .category = .security,
        .check_step = &markStep,
    },
};

test "engine runs workflow-level rule" {
    const engine = Engine.init(&test_rules);
    const wf = Workflow{ .on = test_support.empty_trigger, .jobs = &.{} };
    var list = engine.run(std.testing.allocator, &wf);
    defer list.deinit();

    try std.testing.expect(test_support.hasDiagnostic(&list, "TEST-WF"));
}

test "engine runs job-level rule" {
    const engine = Engine.init(&test_rules);
    const jobs = [_]Job{
        .{ .id = "build" },
    };
    const wf = Workflow{ .name = "CI", .on = test_support.empty_trigger, .jobs = &jobs };
    var list = engine.run(std.testing.allocator, &wf);
    defer list.deinit();

    try std.testing.expect(test_support.hasDiagnostic(&list, "TEST-JOB"));
}

test "engine runs step-level rule" {
    const engine = Engine.init(&test_rules);
    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
    };
    const jobs = [_]Job{
        .{ .id = "build", .name = "Build", .steps = &steps },
    };
    const wf = Workflow{ .name = "CI", .on = test_support.empty_trigger, .jobs = &jobs };
    var list = engine.run(std.testing.allocator, &wf);
    defer list.deinit();

    const d = test_support.findDiagnostic(&list, "TEST-STEP") orelse return error.TestUnexpectedResult;
    try std.testing.expect(d.fix_hint != null);
}

test "engine returns all expected diagnostics" {
    const engine = Engine.init(&test_rules);

    const steps = [_]Step{
        .{ .uses = ActionRef.parse("actions/checkout@v4") },
    };
    const jobs = [_]Job{
        .{ .id = "test", .steps = &steps },
    };
    const wf = Workflow{ .on = test_support.empty_trigger, .jobs = &jobs };
    var list = engine.run(std.testing.allocator, &wf);
    defer list.deinit();

    try std.testing.expectEqual(@as(usize, 3), list.len());
}

test "engine with empty rules" {
    const empty_rules = [_]Rule{};
    const engine = Engine.init(&empty_rules);
    const wf = Workflow{ .on = test_support.empty_trigger, .jobs = &.{} };
    var list = engine.run(std.testing.allocator, &wf);
    defer list.deinit();

    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "engine with empty workflow" {
    const engine = Engine.init(&test_rules);
    const wf = Workflow{ .name = "Empty", .on = test_support.empty_trigger, .jobs = &.{} };
    var list = engine.run(std.testing.allocator, &wf);
    defer list.deinit();

    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expect(test_support.hasDiagnostic(&list, "TEST-WF"));
}

test "rule struct field access" {
    const rule = test_rules[0];
    try std.testing.expectEqualStrings("TEST-WF", rule.id);
    try std.testing.expectEqualStrings("workflow-hook", rule.name);
    try std.testing.expect(rule.severity == .warning);
    try std.testing.expect(rule.category == .best_practice);
    try std.testing.expect(rule.check_workflow != null);
    try std.testing.expect(rule.check_job == null);
    try std.testing.expect(rule.check_step == null);
}

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
    try std.testing.expect(!isValidGitHubComponent("./"));
    try std.testing.expect(!isValidGitHubComponent("../"));
    try std.testing.expect(!isValidGitHubComponent(".\\"));
    try std.testing.expect(!isValidGitHubComponent("..\\"));
    try std.testing.expect(!isValidGitHubComponent("foo\\bar"));
}

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
    try std.testing.expect(!isValidGitRef("ref\\path"));
    try std.testing.expect(!isValidGitRef(".\\foo"));
    try std.testing.expect(!isValidGitRef("..\\foo"));
}

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

test "isNetworkDeadlineExceeded: no deadline set returns false" {
    clearNetworkDeadline();
    try std.testing.expect(!isNetworkDeadlineExceeded());
}

test "isNetworkDeadlineExceeded: future deadline returns false" {
    setNetworkDeadline(60 * std.time.ns_per_s);
    defer clearNetworkDeadline();
    try std.testing.expect(!isNetworkDeadlineExceeded());
}

test "isNetworkDeadlineExceeded: past deadline returns true" {
    network_deadline_ns = std.time.nanoTimestamp() - 1;
    defer clearNetworkDeadline();
    try std.testing.expect(isNetworkDeadlineExceeded());
}

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
    const wf = Workflow{ .on = test_support.empty_trigger, .jobs = &jobs };

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
    const wf = Workflow{ .on = test_support.empty_trigger, .jobs = &jobs };

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
    const wf = Workflow{ .on = test_support.empty_trigger, .jobs = &jobs };

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
    try std.testing.expectEqualStrings("SC005", list.get(0).rule_id);
    try std.testing.expectEqualStrings("stale-B", list.get(0).message);
    try std.testing.expectEqualStrings("SC008", list.get(1).rule_id);
}

test "postProcess: no-op when impostor module offline" {
    const steps = [_]Step{.{ .uses = ActionRef.parse("o/r@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") }};
    const jobs = [_]Job{.{ .id = "j", .steps = &steps }};
    const wf = Workflow{ .on = test_support.empty_trigger, .jobs = &jobs };

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
