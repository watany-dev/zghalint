const std = @import("std");
const engine = @import("engine.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml_types = @import("../yaml/types.zig");

const Rule = engine.Rule;
const Workflow = engine.Workflow;
const Job = engine.Job;
const Step = engine.Step;
const DiagnosticList = engine.DiagnosticList;
const Span = yaml_types.Span;
const Node = yaml_types.Node;
const Mapping = yaml_types.Mapping;

// ── SYN002: Case-insensitive duplicate YAML keys ──

fn checkDuplicateKeys(wf: *const Workflow, list: *DiagnosticList) void {
    const root = wf.yaml_root orelse return;
    walkDuplicateKeys(root, "workflow", null, list);
}

fn sectionForMappingChild(parent_section: []const u8, key: []const u8, value: Node) []const u8 {
    // Job IDs are arbitrary. A job named `env` is still a job, not an env map.
    if (std.mem.eql(u8, parent_section, "jobs")) return "job";
    return switch (value) {
        .mapping => key,
        else => parent_section,
    };
}

fn walkDuplicateKeys(node: Node, section: []const u8, parent_key: ?[]const u8, list: *DiagnosticList) void {
    switch (node) {
        .mapping => |m| checkMapping(m, section, list),
        .sequence => |s| {
            const item_section = if (parent_key) |pk|
                (if (std.ascii.eqlIgnoreCase(pk, "steps")) "step" else section)
            else
                section;
            for (s.items) |item| {
                walkDuplicateKeys(item, item_section, parent_key, list);
            }
        },
        else => {},
    }
}

fn checkMapping(mapping: Mapping, section: []const u8, list: *DiagnosticList) void {
    for (mapping.entries, 0..) |entry, i| {
        for (mapping.entries[0..i]) |earlier| {
            if (!std.ascii.eqlIgnoreCase(earlier.key.value, entry.key.value)) continue;
            const message = std.fmt.allocPrint(
                list.fixAllocator(),
                "key \"{s}\" is duplicated in \"{s}\" section. previously defined at line:{d},col:{d}. note that this key is case insensitive",
                .{ entry.key.value, section, earlier.key.span.start_line, earlier.key.span.start_col },
            ) catch return;

            list.append(.{
                .rule_id = "SYN002",
                .severity = .@"error",
                .message = message,
                .span = entry.key.span,
                .fix_hint = "remove the duplicate key or rename it so keys are unique within the section",
            }) catch return;
            break;
        }

        const child_section = sectionForMappingChild(section, entry.key.value, entry.value);
        walkDuplicateKeys(entry.value, child_section, entry.key.value, list);
    }
}

// ── SYN005: Duplicated job ID / step ID (case-insensitive) ──

fn spanOrFallback(primary: ?Span, fallback: Span) Span {
    return primary orelse fallback;
}

fn reportDuplicateId(
    list: *DiagnosticList,
    id: []const u8,
    prior_line: u32,
    span: Span,
    comptime message_fmt: []const u8,
    fix_hint: []const u8,
) void {
    const alloc = list.fixAllocator();
    const message = std.fmt.allocPrint(alloc, message_fmt, .{ id, prior_line }) catch return;
    list.append(.{
        .rule_id = "SYN005",
        .severity = .@"error",
        .message = message,
        .span = span,
        .fix_hint = fix_hint,
    }) catch return;
}

const job_id_dup_fmt =
    "job ID \"{s}\" duplicates. previously defined at line {d}. note that job ID is case insensitive";
const step_id_dup_fmt =
    "step ID \"{s}\" duplicates. previously defined at line {d}. step ID must be unique within a job. note that step ID is case insensitive";

fn checkDuplicateJobIds(wf: *const Workflow, list: *DiagnosticList) void {
    for (wf.jobs, 0..) |*job, i| {
        for (wf.jobs[0..i]) |*prior| {
            if (!std.ascii.eqlIgnoreCase(prior.id, job.id)) continue;
            reportDuplicateId(
                list,
                job.id,
                spanOrFallback(prior.id_span, prior.span).start_line,
                spanOrFallback(job.id_span, job.span),
                job_id_dup_fmt,
                "use a unique job ID within the workflow",
            );
            break;
        }
    }
}

fn checkDuplicateStepIds(job: *const Job, list: *DiagnosticList) void {
    for (job.steps, 0..) |*step, i| {
        const step_id = step.id orelse continue;
        for (job.steps[0..i]) |*prior_step| {
            const prior_id = prior_step.id orelse continue;
            if (!std.ascii.eqlIgnoreCase(prior_id, step_id)) continue;
            reportDuplicateId(
                list,
                step_id,
                spanOrFallback(prior_step.id_value_span, prior_step.span).start_line,
                spanOrFallback(step.id_value_span, step.span),
                step_id_dup_fmt,
                "use a unique step ID within the job",
            );
            break;
        }
    }
}

// ── SYN008: Duplicated job ID in `needs` ──

fn checkDuplicateNeeds(job: *const Job, diag_list: *DiagnosticList) void {
    for (job.needs, 0..) |dep, i| {
        // Job IDs are case-insensitive in GitHub Actions. Report on the second
        // occurrence only, so an ID repeated three or more times still yields
        // a single diagnostic.
        var prior: usize = 0;
        for (job.needs[0..i]) |earlier| {
            if (std.ascii.eqlIgnoreCase(earlier, dep)) prior += 1;
        }
        if (prior != 1) continue;

        diag_list.append(.{
            .rule_id = "SYN008",
            .severity = .warning,
            .message = "job ID is duplicated in 'needs'",
            .span = job.span,
            .fix_hint = "remove the repeated job ID from 'needs'",
        }) catch return;
    }
}

// ── SYN012: Mutually exclusive event filters ──

/// One `<filter>` / `<filter>-ignore` pair as it appears in a single event.
/// GitHub Actions rejects a workflow that specifies both halves of a pair.
const ExclusivePair = struct {
    include: ?Span,
    exclude: ?Span,
    message: []const u8,
    fix_hint: []const u8,
};

fn checkExclusiveFilters(wf: *const Workflow, list: *DiagnosticList) void {
    for (wf.on.events) |event| {
        const s = (event.filter orelse continue).spans;
        const pairs = [_]ExclusivePair{
            .{
                .include = s.branches,
                .exclude = s.branches_ignore,
                .message = "both \"branches\" and \"branches-ignore\" filters cannot be used for the same event",
                .fix_hint = "keep only one of 'branches' or 'branches-ignore'; a negated pattern such as '!wip/**' can be listed under 'branches'",
            },
            .{
                .include = s.tags,
                .exclude = s.tags_ignore,
                .message = "both \"tags\" and \"tags-ignore\" filters cannot be used for the same event",
                .fix_hint = "keep only one of 'tags' or 'tags-ignore'; a negated pattern such as '!v0.*' can be listed under 'tags'",
            },
            .{
                .include = s.paths,
                .exclude = s.paths_ignore,
                .message = "both \"paths\" and \"paths-ignore\" filters cannot be used for the same event",
                .fix_hint = "keep only one of 'paths' or 'paths-ignore'; a negated pattern such as '!docs/**' can be listed under 'paths'",
            },
        };

        for (pairs) |pair| {
            const include = pair.include orelse continue;
            const exclude = pair.exclude orelse continue;

            // Report on whichever key comes second in the source so the
            // diagnostic points at the offending addition, not the first
            // filter the author wrote.
            const span = if (exclude.start_byte >= include.start_byte) exclude else include;

            list.append(.{
                .rule_id = "SYN012",
                .severity = .@"error",
                .message = pair.message,
                .span = span,
                .fix_hint = pair.fix_hint,
            }) catch return;
        }
    }
}

pub const rules = [_]Rule{
    .{
        .id = "SYN002",
        .name = "duplicate-key",
        .description = "the same mapping key appears more than once (case-insensitive)",
        .severity = .@"error",
        .category = .syntax,
        .check_workflow = &checkDuplicateKeys,
    },
    .{
        .id = "SYN005",
        .name = "duplicate-id",
        .description = "job IDs and step IDs must be unique within a workflow or job (case-insensitive)",
        .severity = .@"error",
        .category = .syntax,
        .check_workflow = &checkDuplicateJobIds,
        .check_job = &checkDuplicateStepIds,
    },
    .{
        .id = "SYN008",
        .name = "duplicate-needs",
        .description = "the same job ID is listed more than once in 'needs'",
        .severity = .warning,
        .category = .syntax,
        .check_job = &checkDuplicateNeeds,
    },
    .{
        .id = "SYN012",
        .name = "exclusive-event-filters",
        .description = "Mutually exclusive event filters (branches/tags/paths and their -ignore forms) are specified together",
        .severity = .@"error",
        .category = .syntax,
        .check_workflow = &checkExclusiveFilters,
    },
};

// ============================================================
// Tests
// ============================================================

const testing = std.testing;
const yaml_parser = @import("../yaml/parser.zig");
const workflow_parser = @import("../workflow/parser.zig");
const EventConfig = workflow_types.EventConfig;
const Trigger = workflow_types.Trigger;

fn runOn(events: []const EventConfig, list: *DiagnosticList) void {
    const wf = Workflow{ .on = .{ .events = events }, .jobs = &.{} };
    checkExclusiveFilters(&wf, list);
}

fn runOnNeeds(needs: []const []const u8, diags: *DiagnosticList) void {
    const job = Job{ .id = "test", .runs_on = "ubuntu-latest", .needs = needs };
    checkDuplicateNeeds(&job, diags);
}

fn collectDuplicateKeyDiagnostics(source: []const u8, diags: *DiagnosticList) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var parser = yaml_parser.Parser.init(arena.allocator(), source);
    defer parser.deinit();
    const node = try parser.parse();
    walkDuplicateKeys(node, "workflow", null, diags);
}

test "SYN002: duplicated steps key is reported" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo first
        \\    STEPS:
        \\      - run: echo second
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    try collectDuplicateKeyDiagnostics(source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expectEqualStrings("SYN002", diag.rule_id);
    try testing.expect(diag.severity == .@"error");
    try testing.expect(std.mem.indexOf(u8, diag.message, "STEPS") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "job") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "previously defined at line:5,col:5") != null);
    try testing.expectEqual(@as(u32, 7), diag.span.start_line);
    try testing.expectEqual(@as(u32, 5), diag.span.start_col);
}

test "SYN002: duplicate detection is case-insensitive in matrix" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix:
        \\        version_name: [v1, v2]
        \\        VERSION_NAME: [V1, V2]
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    try collectDuplicateKeyDiagnostics(source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "matrix") != null);
}

test "SYN002: distinct env keys are not reported" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    env:
        \\      FOO: 1
        \\      foo_bar: 2
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    try collectDuplicateKeyDiagnostics(source, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN002: a key repeated three times reports each extra occurrence" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    env:
        \\      FOO: 1
        \\      foo: 2
        \\      Foo: 3
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    try collectDuplicateKeyDiagnostics(source, &diags);

    try testing.expectEqual(@as(usize, 2), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "foo") != null);
    try testing.expect(std.mem.indexOf(u8, diags.get(1).message, "Foo") != null);
}

test "SYN002: with mapping duplicates are reported" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/checkout@v4
        \\        with:
        \\          fetch-depth: 1
        \\          FETCH-DEPTH: 0
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    try collectDuplicateKeyDiagnostics(source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "with") != null);
}

test "SYN002: flow mapping duplicates are reported" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    env: {FOO: 1, foo: 2}
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    try collectDuplicateKeyDiagnostics(source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "env") != null);
}

test "SYN002: duplicate job IDs are reported in jobs section" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo a
        \\  BUILD:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo b
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    try collectDuplicateKeyDiagnostics(source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "jobs") != null);
}

test "SYN002: a job named env is still a job section" {
    const source =
        \\on: push
        \\jobs:
        \\  env:
        \\    runs-on: ubuntu-latest
        \\    RUNS-ON: windows-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    try collectDuplicateKeyDiagnostics(source, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "job") != null);
}

test "SYN002: engine.run emits via yaml_root" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo first
        \\    STEPS:
        \\      - run: echo second
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var parser = yaml_parser.Parser.init(arena.allocator(), source);
    defer parser.deinit();
    const node = try parser.parse();
    const wf = try workflow_parser.parseWorkflow(arena.allocator(), node);

    const engine_inst = engine.Engine.init(&rules);
    var diags = engine_inst.run(testing.allocator, &wf);
    defer diags.deinit();

    var found = false;
    for (0..diags.len()) |i| {
        if (std.mem.eql(u8, diags.get(i).rule_id, "SYN002")) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

fn runOnDuplicateJobIds(jobs: []const Job, diags: *DiagnosticList) void {
    const wf = Workflow{ .on = .{ .events = &.{} }, .jobs = jobs };
    checkDuplicateJobIds(&wf, diags);
}

fn runOnDuplicateStepIds(steps: []const Step, diags: *DiagnosticList) void {
    const job = Job{ .id = "build", .runs_on = "ubuntu-latest", .steps = steps };
    checkDuplicateStepIds(&job, diags);
}

test "SYN005: duplicate job IDs" {
    const cases = [_]struct {
        jobs: [2]Job,
        message: []const u8,
        span_line: u32,
    }{
        .{
            .jobs = .{
                .{ .id = "build", .id_span = Span.point(3, 3, 20), .runs_on = "ubuntu-latest" },
                .{ .id = "build", .id_span = Span.point(6, 3, 50), .runs_on = "ubuntu-latest" },
            },
            .message = "job ID \"build\" duplicates. previously defined at line 3. note that job ID is case insensitive",
            .span_line = 6,
        },
        .{
            .jobs = .{
                .{ .id = "build", .id_span = Span.point(5, 3, 40), .runs_on = "ubuntu-latest" },
                .{ .id = "Build", .id_span = Span.point(8, 3, 80), .runs_on = "ubuntu-latest" },
            },
            .message = "job ID \"Build\" duplicates. previously defined at line 5. note that job ID is case insensitive",
            .span_line = 8,
        },
    };

    for (cases) |c| {
        var diags = DiagnosticList.init(testing.allocator);
        defer diags.deinit();

        runOnDuplicateJobIds(&c.jobs, &diags);

        try testing.expectEqual(@as(usize, 1), diags.len());
        const diag = diags.get(0);
        try testing.expectEqualStrings("SYN005", diag.rule_id);
        try testing.expect(diag.severity == .@"error");
        try testing.expectEqualStrings(c.message, diag.message);
        try testing.expectEqual(c.span_line, diag.span.start_line);
    }
}

test "SYN005: job ID repeated three times reports on each subsequent occurrence" {
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    const jobs = [_]Job{
        .{ .id = "build", .id_span = Span.point(3, 3, 20) },
        .{ .id = "Build", .id_span = Span.point(6, 3, 50) },
        .{ .id = "BUILD", .id_span = Span.point(9, 3, 80) },
    };
    runOnDuplicateJobIds(&jobs, &diags);

    try testing.expectEqual(@as(usize, 2), diags.len());
    try testing.expectEqualStrings(
        "job ID \"Build\" duplicates. previously defined at line 3. note that job ID is case insensitive",
        diags.get(0).message,
    );
    try testing.expectEqualStrings(
        "job ID \"BUILD\" duplicates. previously defined at line 3. note that job ID is case insensitive",
        diags.get(1).message,
    );
}

test "SYN005: distinct job IDs produce no diagnostic" {
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    const jobs = [_]Job{
        .{ .id = "build", .id_span = Span.point(3, 3, 20) },
        .{ .id = "test", .id_span = Span.point(6, 3, 50) },
    };
    runOnDuplicateJobIds(&jobs, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN005: duplicate step IDs within a job" {
    const cases = [_]struct {
        steps: [2]Step,
        message: []const u8,
        span_line: u32,
    }{
        .{
            .steps = .{
                .{ .id = "setup", .id_value_span = Span.point(7, 11, 100), .run = "echo hi" },
                .{ .id = "setup", .id_value_span = Span.point(9, 11, 140), .run = "echo hi" },
            },
            .message = "step ID \"setup\" duplicates. previously defined at line 7. step ID must be unique within a job. note that step ID is case insensitive",
            .span_line = 9,
        },
        .{
            .steps = .{
                .{ .id = "setup", .id_value_span = Span.point(7, 11, 100), .run = "echo hi" },
                .{ .id = "SETUP", .id_value_span = Span.point(9, 11, 140), .run = "echo hi" },
            },
            .message = "step ID \"SETUP\" duplicates. previously defined at line 7. step ID must be unique within a job. note that step ID is case insensitive",
            .span_line = 9,
        },
    };

    for (cases) |c| {
        var diags = DiagnosticList.init(testing.allocator);
        defer diags.deinit();

        runOnDuplicateStepIds(&c.steps, &diags);

        try testing.expectEqual(@as(usize, 1), diags.len());
        const diag = diags.get(0);
        try testing.expectEqualStrings("SYN005", diag.rule_id);
        try testing.expect(diag.severity == .@"error");
        try testing.expectEqualStrings(c.message, diag.message);
        try testing.expectEqual(c.span_line, diag.span.start_line);
    }
}

test "SYN005: step ID repeated three times reports on each subsequent occurrence" {
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    const steps = [_]Step{
        .{ .id = "setup", .id_value_span = Span.point(7, 11, 100), .run = "echo hi" },
        .{ .id = "Setup", .id_value_span = Span.point(9, 11, 140), .run = "echo hi" },
        .{ .id = "SETUP", .id_value_span = Span.point(11, 11, 180), .run = "echo hi" },
    };
    runOnDuplicateStepIds(&steps, &diags);

    try testing.expectEqual(@as(usize, 2), diags.len());
    try testing.expectEqualStrings(
        "step ID \"Setup\" duplicates. previously defined at line 7. step ID must be unique within a job. note that step ID is case insensitive",
        diags.get(0).message,
    );
    try testing.expectEqualStrings(
        "step ID \"SETUP\" duplicates. previously defined at line 7. step ID must be unique within a job. note that step ID is case insensitive",
        diags.get(1).message,
    );
}

test "SYN005: same step ID in different jobs is allowed" {
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    const steps_a = [_]Step{
        .{ .id = "setup", .id_value_span = Span.point(7, 11, 100), .run = "echo hi" },
    };
    const steps_b = [_]Step{
        .{ .id = "setup", .id_value_span = Span.point(12, 11, 200), .run = "echo hi" },
    };
    const jobs = [_]Job{
        .{ .id = "build", .runs_on = "ubuntu-latest", .steps = &steps_a },
        .{ .id = "test", .runs_on = "ubuntu-latest", .steps = &steps_b },
    };

    const wf = Workflow{ .on = .{ .events = &.{} }, .jobs = &jobs };
    const eng = engine.Engine.init(&rules);
    var list = eng.run(testing.allocator, &wf);
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.len());
}

test "SYN005: steps without id are ignored" {
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    const steps = [_]Step{
        .{ .run = "echo hi" },
        .{ .run = "echo bye" },
    };
    runOnDuplicateStepIds(&steps, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN005: end-to-end duplicate job and step IDs from YAML source" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: setup
        \\        run: echo hi
        \\      - id: setup
        \\        run: echo hi
        \\      - id: SETUP
        \\        run: echo hi
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\  Build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    var yp = yaml_parser.Parser.init(alloc, source);
    defer yp.deinit();
    const yaml_node = try yp.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_node);

    const eng = engine.Engine.init(&rules);
    var diags = eng.run(alloc, &wf);
    defer diags.deinit();

    var syn005_count: usize = 0;
    var step_exact = false;
    var step_case = false;
    var job_exact = false;
    var job_case = false;
    for (diags.items.items) |d| {
        if (!std.mem.eql(u8, d.rule_id, "SYN005")) continue;
        syn005_count += 1;
        if (std.mem.eql(u8, d.message, "step ID \"setup\" duplicates. previously defined at line 6. step ID must be unique within a job. note that step ID is case insensitive")) {
            step_exact = true;
            try testing.expectEqual(@as(u32, 8), d.span.start_line);
        }
        if (std.mem.eql(u8, d.message, "step ID \"SETUP\" duplicates. previously defined at line 6. step ID must be unique within a job. note that step ID is case insensitive")) {
            step_case = true;
            try testing.expectEqual(@as(u32, 10), d.span.start_line);
        }
        if (std.mem.eql(u8, d.message, "job ID \"build\" duplicates. previously defined at line 3. note that job ID is case insensitive")) {
            job_exact = true;
            try testing.expectEqual(@as(u32, 12), d.span.start_line);
        }
        if (std.mem.eql(u8, d.message, "job ID \"Build\" duplicates. previously defined at line 3. note that job ID is case insensitive")) {
            job_case = true;
            try testing.expectEqual(@as(u32, 16), d.span.start_line);
        }
    }
    try testing.expectEqual(@as(usize, 4), syn005_count);
    try testing.expect(step_exact);
    try testing.expect(step_case);
    try testing.expect(job_exact);
    try testing.expect(job_case);
}

test "SYN008: duplicated job ID is reported" {
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    runOnNeeds(&.{ "build", "build" }, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expectEqualStrings("SYN008", diag.rule_id);
    try testing.expect(diag.severity == .warning);
}

test "SYN008: duplicate detection is case-insensitive" {
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    runOnNeeds(&.{ "Build", "bUILD" }, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
}

test "SYN008: a job ID repeated three times reports once" {
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    runOnNeeds(&.{ "build", "build", "build" }, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
}

test "SYN008: distinct job IDs produce no diagnostic" {
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    runOnNeeds(&.{ "build", "lint" }, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN012: branches with branches-ignore is an error" {
    const events = [_]EventConfig{.{
        .event = .push,
        .name = "push",
        .filter = .{ .spans = .{ .branches = Span.point(1, 1, 10), .branches_ignore = Span.point(1, 1, 30) } },
    }};
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    runOn(&events, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expectEqualStrings("SYN012", diag.rule_id);
    try testing.expect(diag.severity == .@"error");
    try testing.expectEqualStrings(
        "both \"branches\" and \"branches-ignore\" filters cannot be used for the same event",
        diag.message,
    );
    try testing.expectEqual(@as(usize, 30), diag.span.start_byte);
}

test "SYN012: tags with tags-ignore is an error" {
    const events = [_]EventConfig{.{
        .event = .push,
        .name = "push",
        .filter = .{ .spans = .{ .tags = Span.point(1, 1, 10), .tags_ignore = Span.point(1, 1, 30) } },
    }};
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    runOn(&events, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expectEqualStrings(
        "both \"tags\" and \"tags-ignore\" filters cannot be used for the same event",
        diags.get(0).message,
    );
}

test "SYN012: paths with paths-ignore is an error" {
    const events = [_]EventConfig{.{
        .event = .push,
        .name = "push",
        .filter = .{ .spans = .{ .paths = Span.point(1, 1, 10), .paths_ignore = Span.point(1, 1, 30) } },
    }};
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    runOn(&events, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expectEqualStrings(
        "both \"paths\" and \"paths-ignore\" filters cannot be used for the same event",
        diags.get(0).message,
    );
}

test "SYN012: all three conflicting pairs are reported separately" {
    const events = [_]EventConfig{.{
        .event = .push,
        .name = "push",
        .filter = .{ .spans = .{
            .branches = Span.point(1, 1, 10),
            .branches_ignore = Span.point(1, 1, 20),
            .tags = Span.point(1, 1, 30),
            .tags_ignore = Span.point(1, 1, 40),
            .paths = Span.point(1, 1, 50),
            .paths_ignore = Span.point(1, 1, 60),
        } },
    }};
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    runOn(&events, &diags);

    try testing.expectEqual(@as(usize, 3), diags.len());
}

test "SYN012: filters from different pairs may coexist" {
    const events = [_]EventConfig{.{
        .event = .push,
        .name = "push",
        .filter = .{ .spans = .{ .branches = Span.point(1, 1, 10), .paths_ignore = Span.point(1, 1, 30) } },
    }};
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    runOn(&events, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN012: an empty filter value still counts as present" {
    // `branches: []` parses to an empty array but the key is there, so the
    // conflict with `branches-ignore` must still be reported.
    const events = [_]EventConfig{.{
        .event = .push,
        .name = "push",
        .filter = .{
            .branches = &.{},
            .branches_ignore = &.{"wip/**"},
            .spans = .{ .branches = Span.point(1, 1, 10), .branches_ignore = Span.point(1, 1, 30) },
        },
    }};
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    runOn(&events, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
}

test "SYN012: separate events using opposite halves are fine" {
    const events = [_]EventConfig{
        .{
            .event = .push,
            .name = "push",
            .filter = .{ .spans = .{ .branches = Span.point(1, 1, 10) } },
        },
        .{
            .event = .pull_request,
            .name = "pull_request",
            .filter = .{ .spans = .{ .branches_ignore = Span.point(1, 1, 40) } },
        },
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    runOn(&events, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN012: event without a filter is ignored" {
    const events = [_]EventConfig{.{ .event = .push, .name = "push" }};
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    runOn(&events, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN012: diagnostic points at the first key when the ignore form comes first" {
    const events = [_]EventConfig{.{
        .event = .push,
        .name = "push",
        .filter = .{ .spans = .{ .branches = Span.point(1, 1, 40), .branches_ignore = Span.point(1, 1, 10) } },
    }};
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    runOn(&events, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expectEqual(@as(usize, 40), diags.get(0).span.start_byte);
}
