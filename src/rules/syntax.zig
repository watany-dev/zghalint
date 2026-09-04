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

// ── SYN003: Empty mapping / sequence sections ──

fn emptySectionMessage(section: []const u8) []const u8 {
    if (std.mem.eql(u8, section, "on")) return "\"on\" section should not be empty";
    if (std.mem.eql(u8, section, "jobs")) return "\"jobs\" section should not be empty";
    if (std.mem.eql(u8, section, "steps")) return "\"steps\" section should not be empty";
    if (std.mem.eql(u8, section, "with")) return "\"with\" section should not be empty";
    if (std.mem.eql(u8, section, "env")) return "\"env\" section should not be empty";
    if (std.mem.eql(u8, section, "strategy")) return "\"strategy\" section should not be empty";
    if (std.mem.eql(u8, section, "matrix")) return "\"matrix\" section should not be empty";
    if (std.mem.eql(u8, section, "defaults")) return "\"defaults\" section should not be empty";
    if (std.mem.eql(u8, section, "container")) return "\"container\" section should not be empty";
    if (std.mem.eql(u8, section, "services")) return "\"services\" section should not be empty";
    if (std.mem.eql(u8, section, "outputs")) return "\"outputs\" section should not be empty";
    if (std.mem.eql(u8, section, "inputs")) return "\"inputs\" section should not be empty";
    if (std.mem.eql(u8, section, "secrets")) return "\"secrets\" section should not be empty";
    return "\"section\" section should not be empty";
}

fn reportEmptySection(section: []const u8, span: Span, list: *DiagnosticList) void {
    list.append(.{
        .rule_id = "SYN003",
        .severity = .@"error",
        .message = emptySectionMessage(section),
        .span = span,
        .fix_hint = "remove this section if it is unnecessary",
    }) catch return;
}

fn checkEmptySections(sections: []const workflow_types.EmptySection, list: *DiagnosticList) void {
    for (sections) |section| {
        reportEmptySection(section.name, section.span, list);
    }
}

fn checkWorkflowEmptySections(wf: *const Workflow, list: *DiagnosticList) void {
    checkEmptySections(wf.empty_sections, list);
}

fn checkJobEmptySections(job: *const Job, list: *DiagnosticList) void {
    checkEmptySections(job.empty_sections, list);
}

fn checkStepEmptySections(step: *const Step, list: *DiagnosticList) void {
    checkEmptySections(step.empty_sections, list);
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
        .id = "SYN003",
        .name = "empty-section",
        .description = "Required workflow sections must not be empty mappings or sequences",
        .severity = .@"error",
        .category = .syntax,
        .check_workflow = &checkWorkflowEmptySections,
        .check_job = &checkJobEmptySections,
        .check_step = &checkStepEmptySections,
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

const workflow_parser = @import("../workflow/parser.zig");
const yaml_parser_mod = @import("../yaml/parser.zig");

fn runEngineOnWorkflow(wf: Workflow, diags: *DiagnosticList) void {
    const rule_engine = engine.Engine.init(&rules);
    var list = rule_engine.run(testing.allocator, &wf);
    defer list.deinit();
    for (list.items.items) |diag| {
        diags.append(diag) catch return;
    }
}

fn lintYaml(source: []const u8, diags: *DiagnosticList) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var parser = yaml_parser_mod.Parser.init(alloc, source);
    defer parser.deinit();
    const node = try parser.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, node);
    runEngineOnWorkflow(wf, diags);
}

test "SYN003: empty strategy and with are reported" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    strategy: {}
        \\    steps:
        \\      - uses: actions/checkout@v4
        \\        with: {}
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try lintYaml(source, &diags);

    try testing.expectEqual(@as(usize, 2), diags.len());
    try testing.expectEqualStrings("SYN003", diags.get(0).rule_id);
    try testing.expectEqualStrings("\"strategy\" section should not be empty", diags.get(0).message);
    try testing.expectEqualStrings("SYN003", diags.get(1).rule_id);
    try testing.expectEqualStrings("\"with\" section should not be empty", diags.get(1).message);
}

test "SYN003: valid workflow without empty sections is clean" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/checkout@v4
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try lintYaml(source, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN003: permissions mapping is allowed to be empty" {
    const source =
        \\on: push
        \\permissions: {}
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    permissions: {}
        \\    steps:
        \\      - run: echo ok
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try lintYaml(source, &diags);

    for (0..diags.len()) |i| {
        try testing.expect(!std.mem.eql(u8, diags.get(i).rule_id, "SYN003"));
    }
}

test "SYN003: empty jobs mapping is reported" {
    const source =
        \\on: push
        \\jobs: {}
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try lintYaml(source, &diags);

    var found_jobs = false;
    for (0..diags.len()) |i| {
        const diag = diags.get(i);
        if (std.mem.eql(u8, diag.rule_id, "SYN003") and
            std.mem.eql(u8, diag.message, "\"jobs\" section should not be empty"))
        {
            found_jobs = true;
        }
    }
    try testing.expect(found_jobs);
}

test "SYN003: empty steps sequence is reported" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps: []
    ;

    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();
    try lintYaml(source, &diags);

    var found_steps = false;
    for (0..diags.len()) |i| {
        const diag = diags.get(i);
        if (std.mem.eql(u8, diag.rule_id, "SYN003") and
            std.mem.eql(u8, diag.message, "\"steps\" section should not be empty"))
        {
            found_steps = true;
        }
    }
    try testing.expect(found_steps);
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
