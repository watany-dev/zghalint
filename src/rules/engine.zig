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

        list.sort();
        return list;
    }
};

// ============================================================
// Network deadline
// ============================================================

var network_deadline_ns: ?i128 = null;

/// Set a deadline for network operations (absolute timestamp in nanoseconds).
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
            .span = Span.point(0, 0, 0),
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
                .span = Span.point(0, 0, 0),
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

test "engine returns sorted diagnostics" {
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
    // Verify sorted order (by line, then col)
    var prev_line: u32 = 0;
    for (list.items.items) |d| {
        try std.testing.expect(d.span.start_line >= prev_line);
        prev_line = d.span.start_line;
    }
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
