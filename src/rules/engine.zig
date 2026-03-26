const std = @import("std");
const types = @import("../workflow/types.zig");
const diag = @import("../diagnostics.zig");

pub const Workflow = types.Workflow;
pub const Job = types.Job;
pub const Step = types.Step;
pub const DiagnosticList = diag.DiagnosticList;
pub const Severity = diag.Severity;
pub const Diagnostic = diag.Diagnostic;

pub const Category = enum {
    syntax,
    security,
    performance,
    best_practice,
    expression,
    dependency,
    permissions,
    runner,
    reusable_workflow,
};

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
        var diagnostics = DiagnosticList.init(allocator);

        for (self.rules) |rule| {
            if (rule.check_workflow) |check_fn| {
                check_fn(workflow, &diagnostics);
            }

            for (workflow.jobs) |*job| {
                if (rule.check_job) |check_fn| {
                    check_fn(job, &diagnostics);
                }

                for (job.steps) |*step| {
                    if (rule.check_step) |check_fn| {
                        check_fn(step, &diagnostics);
                    }
                }
            }
        }

        return diagnostics;
    }
};

test "engine runs rules" {
    const allocator = std.testing.allocator;

    const test_rule = Rule{
        .id = "TEST001",
        .name = "test-rule",
        .description = "A test rule",
        .severity = .warning,
        .category = .best_practice,
        .check_workflow = struct {
            fn check(wf: *const Workflow, diagnostics: *DiagnosticList) void {
                if (wf.name == null) {
                    diagnostics.append(.{
                        .rule_id = "TEST001",
                        .severity = .warning,
                        .message = "Workflow has no name",
                    });
                }
            }
        }.check,
    };

    const engine = Engine.init(&.{test_rule});
    const workflow = Workflow{
        .on = .{ .events = &.{} },
    };

    var results = engine.run(allocator, &workflow);
    defer results.deinit();

    try std.testing.expectEqual(@as(usize, 1), results.len());
    try std.testing.expectEqualStrings("TEST001", results.get(0).rule_id);
}
