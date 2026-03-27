const std = @import("std");
const types = @import("types.zig");

pub const ValidationError = struct {
    message: []const u8,
    context: ?[]const u8 = null,
};

pub const ValidationResult = struct {
    errors: []const ValidationError,

    pub fn ok(self: ValidationResult) bool {
        return self.errors.len == 0;
    }
};

/// Validate a parsed Workflow for structural correctness
pub fn validate(allocator: std.mem.Allocator, workflow: types.Workflow) !ValidationResult {
    var errors: std.ArrayList(ValidationError) = .{};

    // on field is required (enforced by parser, but check events non-empty)
    if (workflow.on.events.len == 0) {
        try errors.append(allocator, .{ .message = "'on' must specify at least one event" });
    }

    // jobs must be non-empty
    if (workflow.jobs.len == 0) {
        try errors.append(allocator, .{ .message = "'jobs' must contain at least one job" });
    }

    // Validate each job
    for (workflow.jobs) |job| {
        try validateJob(allocator, &errors, job);
    }

    // Check for circular dependencies in needs
    try checkCyclicNeeds(allocator, &errors, workflow.jobs);

    return .{ .errors = try errors.toOwnedSlice(allocator) };
}

fn validateJob(allocator: std.mem.Allocator, errors: *std.ArrayList(ValidationError), job: types.Job) !void {
    const has_steps = job.steps.len > 0;
    const has_uses = job.uses != null;

    // Each job must have steps or uses, but not both
    if (has_steps and has_uses) {
        const msg = try std.fmt.allocPrint(allocator, "job '{s}' must not have both 'steps' and 'uses'", .{job.id});
        try errors.append(allocator, .{ .message = msg, .context = job.id });
    } else if (!has_steps and !has_uses) {
        const msg = try std.fmt.allocPrint(allocator, "job '{s}' must have either 'steps' or 'uses'", .{job.id});
        try errors.append(allocator, .{ .message = msg, .context = job.id });
    }

    // runs-on is required for non-reusable workflow jobs
    if (!has_uses and job.runs_on == null) {
        const msg = try std.fmt.allocPrint(allocator, "job '{s}' requires 'runs-on'", .{job.id});
        try errors.append(allocator, .{ .message = msg, .context = job.id });
    }

    // Validate each step
    for (job.steps, 0..) |step, i| {
        try validateStep(allocator, errors, job.id, step, i);
    }
}

fn validateStep(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList(ValidationError),
    job_id: []const u8,
    step: types.Step,
    step_index: usize,
) !void {
    const has_uses = step.uses != null;
    const has_run = step.run != null;

    // Each step must have uses or run, but not both
    if (has_uses and has_run) {
        const msg = try std.fmt.allocPrint(allocator, "job '{s}' step {d} must not have both 'uses' and 'run'", .{ job_id, step_index });
        try errors.append(allocator, .{ .message = msg, .context = job_id });
    } else if (!has_uses and !has_run) {
        const msg = try std.fmt.allocPrint(allocator, "job '{s}' step {d} must have either 'uses' or 'run'", .{ job_id, step_index });
        try errors.append(allocator, .{ .message = msg, .context = job_id });
    }
}

/// Check for circular dependencies in job `needs` using topological sort (Kahn's algorithm)
fn checkCyclicNeeds(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList(ValidationError),
    jobs: []const types.Job,
) !void {
    // Build adjacency list and in-degree map
    var job_indices = std.StringHashMap(usize).init(allocator);
    defer job_indices.deinit();

    for (jobs, 0..) |job, i| {
        try job_indices.put(job.id, i);
    }

    // in_degree[i] = number of jobs that job i depends on
    const in_degree = try allocator.alloc(usize, jobs.len);
    defer allocator.free(in_degree);
    @memset(in_degree, 0);

    // Validate needs references exist and count in-degrees
    for (jobs, 0..) |job, i| {
        for (job.needs) |dep| {
            if (job_indices.get(dep)) |_| {
                in_degree[i] += 1;
            } else {
                const msg = try std.fmt.allocPrint(allocator, "job '{s}' depends on unknown job '{s}'", .{ job.id, dep });
                try errors.append(allocator, .{ .message = msg, .context = job.id });
            }
        }
    }

    // Kahn's algorithm: start with jobs that have no dependencies
    var queue: std.ArrayList(usize) = .{};
    defer queue.deinit(allocator);

    for (in_degree, 0..) |deg, i| {
        if (deg == 0) try queue.append(allocator, i);
    }

    var visited: usize = 0;
    while (queue.items.len > 0) {
        const current = queue.orderedRemove(0);
        visited += 1;

        // For each job that depends on current, decrease in-degree
        for (jobs, 0..) |job, i| {
            for (job.needs) |dep| {
                if (job_indices.get(dep)) |dep_idx| {
                    if (dep_idx == current) {
                        in_degree[i] -= 1;
                        if (in_degree[i] == 0) {
                            try queue.append(allocator, i);
                        }
                    }
                }
            }
        }
    }

    if (visited != jobs.len) {
        try errors.append(allocator, .{ .message = "circular dependency detected in job 'needs'" });
    }
}

// ============================================================
// Tests
// ============================================================

const testing = std.testing;

test "validate minimal valid workflow" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var events = [_]types.EventConfig{
        .{ .event = .push, .name = "push" },
    };
    var steps = [_]types.Step{
        .{ .run = "echo hello" },
    };
    var jobs = [_]types.Job{
        .{ .id = "build", .runs_on = "ubuntu-latest", .steps = &steps },
    };

    const wf = types.Workflow{
        .on = .{ .events = &events },
        .jobs = &jobs,
    };

    const result = try validate(alloc, wf);
    try testing.expect(result.ok());
}

test "validate empty events" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var steps = [_]types.Step{.{ .run = "echo" }};
    var jobs = [_]types.Job{
        .{ .id = "build", .runs_on = "ubuntu-latest", .steps = &steps },
    };

    const wf = types.Workflow{
        .on = .{ .events = &.{} },
        .jobs = &jobs,
    };

    const result = try validate(alloc, wf);
    try testing.expect(!result.ok());
    try testing.expect(std.mem.indexOf(u8, result.errors[0].message, "'on'") != null);
}

test "validate empty jobs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var events = [_]types.EventConfig{
        .{ .event = .push, .name = "push" },
    };

    const wf = types.Workflow{
        .on = .{ .events = &events },
        .jobs = &.{},
    };

    const result = try validate(alloc, wf);
    try testing.expect(!result.ok());
    try testing.expect(std.mem.indexOf(u8, result.errors[0].message, "'jobs'") != null);
}

test "validate job must have steps or uses" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var events = [_]types.EventConfig{.{ .event = .push, .name = "push" }};
    var jobs = [_]types.Job{
        .{ .id = "empty-job", .runs_on = "ubuntu-latest" },
    };

    const wf = types.Workflow{
        .on = .{ .events = &events },
        .jobs = &jobs,
    };

    const result = try validate(alloc, wf);
    try testing.expect(!result.ok());
    try testing.expect(std.mem.indexOf(u8, result.errors[0].message, "either 'steps' or 'uses'") != null);
}

test "validate job must not have both steps and uses" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var events = [_]types.EventConfig{.{ .event = .push, .name = "push" }};
    var steps = [_]types.Step{.{ .run = "echo" }};
    var jobs = [_]types.Job{
        .{ .id = "both", .runs_on = "ubuntu-latest", .steps = &steps, .uses = "org/repo/.github/workflows/x.yml@v1" },
    };

    const wf = types.Workflow{
        .on = .{ .events = &events },
        .jobs = &jobs,
    };

    const result = try validate(alloc, wf);
    try testing.expect(!result.ok());
    try testing.expect(std.mem.indexOf(u8, result.errors[0].message, "must not have both") != null);
}

test "validate step must have uses or run" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var events = [_]types.EventConfig{.{ .event = .push, .name = "push" }};
    var steps = [_]types.Step{
        .{ .name = "empty step" },
    };
    var jobs = [_]types.Job{
        .{ .id = "test", .runs_on = "ubuntu-latest", .steps = &steps },
    };

    const wf = types.Workflow{
        .on = .{ .events = &events },
        .jobs = &jobs,
    };

    const result = try validate(alloc, wf);
    try testing.expect(!result.ok());
    try testing.expect(std.mem.indexOf(u8, result.errors[0].message, "step 0") != null);
}

test "validate step must not have both uses and run" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var events = [_]types.EventConfig{.{ .event = .push, .name = "push" }};
    var steps = [_]types.Step{
        .{ .uses = types.ActionRef.parse("actions/checkout@v4"), .run = "echo" },
    };
    var jobs = [_]types.Job{
        .{ .id = "test", .runs_on = "ubuntu-latest", .steps = &steps },
    };

    const wf = types.Workflow{
        .on = .{ .events = &events },
        .jobs = &jobs,
    };

    const result = try validate(alloc, wf);
    try testing.expect(!result.ok());
    try testing.expect(std.mem.indexOf(u8, result.errors[0].message, "must not have both 'uses' and 'run'") != null);
}

test "validate runs-on required for non-reusable job" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var events = [_]types.EventConfig{.{ .event = .push, .name = "push" }};
    var steps = [_]types.Step{.{ .run = "echo" }};
    var jobs = [_]types.Job{
        .{ .id = "no-runner", .steps = &steps },
    };

    const wf = types.Workflow{
        .on = .{ .events = &events },
        .jobs = &jobs,
    };

    const result = try validate(alloc, wf);
    try testing.expect(!result.ok());
    try testing.expect(std.mem.indexOf(u8, result.errors[0].message, "requires 'runs-on'") != null);
}

test "validate runs-on not required for reusable workflow job" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var events = [_]types.EventConfig{.{ .event = .push, .name = "push" }};
    var jobs = [_]types.Job{
        .{ .id = "reusable", .uses = "org/repo/.github/workflows/x.yml@v1" },
    };

    const wf = types.Workflow{
        .on = .{ .events = &events },
        .jobs = &jobs,
    };

    const result = try validate(alloc, wf);
    try testing.expect(result.ok());
}

test "validate circular dependency detection" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var events = [_]types.EventConfig{.{ .event = .push, .name = "push" }};
    var steps_a = [_]types.Step{.{ .run = "echo a" }};
    var steps_b = [_]types.Step{.{ .run = "echo b" }};
    var needs_a = [_][]const u8{"b"};
    var needs_b = [_][]const u8{"a"};
    var jobs = [_]types.Job{
        .{ .id = "a", .runs_on = "ubuntu-latest", .steps = &steps_a, .needs = &needs_a },
        .{ .id = "b", .runs_on = "ubuntu-latest", .steps = &steps_b, .needs = &needs_b },
    };

    const wf = types.Workflow{
        .on = .{ .events = &events },
        .jobs = &jobs,
    };

    const result = try validate(alloc, wf);
    try testing.expect(!result.ok());
    var found_cycle = false;
    for (result.errors) |e| {
        if (std.mem.indexOf(u8, e.message, "circular") != null) {
            found_cycle = true;
            break;
        }
    }
    try testing.expect(found_cycle);
}

test "validate no circular dependency in linear chain" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var events = [_]types.EventConfig{.{ .event = .push, .name = "push" }};
    var steps_a = [_]types.Step{.{ .run = "echo a" }};
    var steps_b = [_]types.Step{.{ .run = "echo b" }};
    var steps_c = [_]types.Step{.{ .run = "echo c" }};
    var needs_b = [_][]const u8{"a"};
    var needs_c = [_][]const u8{"b"};
    var jobs = [_]types.Job{
        .{ .id = "a", .runs_on = "ubuntu-latest", .steps = &steps_a },
        .{ .id = "b", .runs_on = "ubuntu-latest", .steps = &steps_b, .needs = &needs_b },
        .{ .id = "c", .runs_on = "ubuntu-latest", .steps = &steps_c, .needs = &needs_c },
    };

    const wf = types.Workflow{
        .on = .{ .events = &events },
        .jobs = &jobs,
    };

    const result = try validate(alloc, wf);
    try testing.expect(result.ok());
}

test "validate unknown needs reference" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var events = [_]types.EventConfig{.{ .event = .push, .name = "push" }};
    var steps = [_]types.Step{.{ .run = "echo" }};
    var needs = [_][]const u8{"nonexistent"};
    var jobs = [_]types.Job{
        .{ .id = "build", .runs_on = "ubuntu-latest", .steps = &steps, .needs = &needs },
    };

    const wf = types.Workflow{
        .on = .{ .events = &events },
        .jobs = &jobs,
    };

    const result = try validate(alloc, wf);
    try testing.expect(!result.ok());
    try testing.expect(std.mem.indexOf(u8, result.errors[0].message, "unknown job") != null);
}

test "ValidationResult.ok" {
    const ok_result = ValidationResult{ .errors = &.{} };
    try testing.expect(ok_result.ok());

    var errs = [_]ValidationError{.{ .message = "error" }};
    const bad_result = ValidationResult{ .errors = &errs };
    try testing.expect(!bad_result.ok());
}
