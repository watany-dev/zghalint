const std = @import("std");
const workflow_types = @import("workflow/types.zig");
const validator = @import("workflow/validator.zig");
const engine_mod = @import("rules/engine.zig");
const security = @import("rules/security.zig");
const best_practices = @import("rules/best_practices.zig");
const perf_rules = @import("rules/performance.zig");
const permissions = @import("rules/permissions.zig");
const expressions = @import("rules/expressions.zig");
const diagnostics = @import("diagnostics.zig");
const yaml_parser = @import("yaml/parser.zig");
const workflow_parser = @import("workflow/parser.zig");

const Workflow = workflow_types.Workflow;
const Job = workflow_types.Job;
const Step = workflow_types.Step;
const EventConfig = workflow_types.EventConfig;
const ActionRef = workflow_types.ActionRef;
const DiagnosticList = diagnostics.DiagnosticList;
const Engine = engine_mod.Engine;
const Rule = engine_mod.Rule;

const all_rules = security.security_rules ++
    best_practices.rules ++
    perf_rules.rules ++
    permissions.rules ++
    [_]Rule{expressions.expression_rule};

// ── Helpers to build large synthetic workflows ──

fn makeSteps(allocator: std.mem.Allocator, count: usize) ![]Step {
    const steps = try allocator.alloc(Step, count);
    for (steps, 0..) |*s, i| {
        s.* = if (i % 3 == 0)
            Step{ .name = "checkout", .uses = ActionRef.parse("actions/checkout@v4"), .run = null }
        else if (i % 3 == 1)
            Step{ .name = "run", .run = "echo hello ${{ github.event.issue.title }}", .uses = null }
        else
            Step{ .name = "setup", .uses = ActionRef.parse("actions/setup-node@v4"), .run = null };
    }
    return steps;
}

fn makeJobs(allocator: std.mem.Allocator, job_count: usize, steps_per_job: usize) ![]Job {
    const jobs = try allocator.alloc(Job, job_count);
    for (jobs, 0..) |*j, i| {
        const id = try std.fmt.allocPrint(allocator, "job_{d}", .{i});
        const steps = try makeSteps(allocator, steps_per_job);
        j.* = Job{
            .id = id,
            .name = id,
            .runs_on = "ubuntu-latest",
            .steps = steps,
        };
    }
    return jobs;
}

fn makeChainedJobs(allocator: std.mem.Allocator, count: usize) ![]Job {
    const jobs = try allocator.alloc(Job, count);
    const steps = try allocator.alloc(Step, 1);
    steps[0] = Step{ .run = "echo ok" };

    for (jobs, 0..) |*j, i| {
        const id = try std.fmt.allocPrint(allocator, "job_{d}", .{i});
        j.* = Job{
            .id = id,
            .runs_on = "ubuntu-latest",
            .steps = steps,
        };
        if (i > 0) {
            const needs = try allocator.alloc([]const u8, 1);
            const prev_id = try std.fmt.allocPrint(allocator, "job_{d}", .{i - 1});
            needs[0] = prev_id;
            j.*.needs = needs;
        }
    }
    return jobs;
}

fn makeWorkflow(jobs: []Job) Workflow {
    return Workflow{
        .name = "bench",
        .on = .{ .events = &.{.{ .event = .push, .name = "push" }} },
        .jobs = jobs,
    };
}

// ── Benchmark: engine.run with large workflow ──

test "bench: engine.run 50 jobs x 20 steps" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const jobs = try makeJobs(allocator, 50, 20);
    const wf = makeWorkflow(jobs);
    const engine = Engine.init(&all_rules);

    const iterations: usize = 100;
    var timer = try std.time.Timer.start();

    for (0..iterations) |_| {
        var list = engine.run(allocator, &wf);
        list.deinit();
    }

    const elapsed_ns = timer.read();
    const avg_us = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(iterations)) / 1000.0;
    std.debug.print("\n[bench] engine.run (50 jobs x 20 steps): {d:.1} us/iter ({d} iters)\n", .{ avg_us, iterations });
}

// ── Benchmark: checkCyclicNeeds with 50-job chain ──

test "bench: checkCyclicNeeds 50-job chain" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const jobs = try makeChainedJobs(allocator, 50);
    const wf = makeWorkflow(jobs);

    const iterations: usize = 1000;
    var timer = try std.time.Timer.start();

    for (0..iterations) |_| {
        const result = try validator.validate(allocator, wf);
        _ = result;
    }

    const elapsed_ns = timer.read();
    const avg_us = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(iterations)) / 1000.0;
    std.debug.print("\n[bench] checkCyclicNeeds (50-job chain): {d:.1} us/iter ({d} iters)\n", .{ avg_us, iterations });
}

// ── Benchmark: YAML parse + workflow parse + lint pipeline ──

test "bench: full pipeline (YAML parse + workflow parse + engine)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Generate a realistic workflow YAML string
    var buf = std.ArrayList(u8).init(allocator);
    const w = buf.writer();
    try w.writeAll("name: bench\non:\n  push:\njobs:\n");
    for (0..10) |i| {
        try w.print("  job_{d}:\n    runs-on: ubuntu-latest\n    steps:\n", .{i});
        for (0..10) |s| {
            try w.print("      - name: step_{d}\n        run: echo hello\n", .{s});
        }
    }
    const source = try buf.toOwnedSlice();

    const engine = Engine.init(&all_rules);
    const iterations: usize = 100;
    var timer = try std.time.Timer.start();

    for (0..iterations) |_| {
        var parser = yaml_parser.Parser.init(allocator, source);
        defer parser.deinit();
        const yaml_node = parser.parse() catch continue;
        const wf = workflow_parser.parseWorkflow(allocator, yaml_node) catch continue;
        var list = engine.run(allocator, &wf);
        list.deinit();
    }

    const elapsed_ns = timer.read();
    const avg_us = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(iterations)) / 1000.0;
    std.debug.print("\n[bench] full pipeline (10 jobs x 10 steps): {d:.1} us/iter ({d} iters)\n", .{ avg_us, iterations });
}
