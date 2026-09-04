const std = @import("std");
const engine = @import("engine.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml_types = @import("../yaml/types.zig");

const Rule = engine.Rule;
const Workflow = engine.Workflow;
const Job = engine.Job;
const DiagnosticList = engine.DiagnosticList;
const Span = yaml_types.Span;
const Node = yaml_types.Node;
const Mapping = yaml_types.Mapping;
const Scalar = yaml_types.Scalar;

// ── SYN002: Case-insensitive duplicate YAML keys ──

pub fn emitDuplicateKeyDiagnostics(node: Node, list: *DiagnosticList) void {
    walkDuplicateKeys(node, "workflow", null, list);
}

fn checkDuplicateKeys(wf: *const Workflow, list: *DiagnosticList) void {
    const root = wf.yaml_root orelse return;
    emitDuplicateKeyDiagnostics(root, list);
}

fn sectionForMappingChild(parent_section: []const u8, key: []const u8) []const u8 {
    // Job IDs are arbitrary. A job named `env` is still a job, not an env map.
    if (std.mem.eql(u8, parent_section, "jobs")) return "job";

    if (std.ascii.eqlIgnoreCase(key, "jobs")) return "jobs";
    if (std.ascii.eqlIgnoreCase(key, "env")) return "env";
    if (std.ascii.eqlIgnoreCase(key, "with")) return "with";
    if (std.ascii.eqlIgnoreCase(key, "matrix")) return "matrix";
    if (std.ascii.eqlIgnoreCase(key, "secrets")) return "secrets";
    if (std.ascii.eqlIgnoreCase(key, "permissions")) return "permissions";
    if (std.ascii.eqlIgnoreCase(key, "outputs")) return "outputs";
    if (std.ascii.eqlIgnoreCase(key, "strategy")) return "strategy";
    if (std.ascii.eqlIgnoreCase(key, "inputs")) return "inputs";
    if (std.ascii.eqlIgnoreCase(key, "services")) return "services";
    if (std.ascii.eqlIgnoreCase(key, "container")) return "container";
    if (std.ascii.eqlIgnoreCase(key, "defaults")) return "defaults";
    if (std.ascii.eqlIgnoreCase(key, "concurrency")) return "concurrency";
    if (std.ascii.eqlIgnoreCase(key, "on")) return "on";

    if (std.mem.eql(u8, parent_section, "job")) return "job";
    if (std.mem.eql(u8, parent_section, "strategy")) return "strategy";
    if (std.mem.eql(u8, parent_section, "step")) return "step";
    if (std.mem.eql(u8, parent_section, "services")) return "services";
    if (std.mem.eql(u8, parent_section, "container")) return "container";

    return parent_section;
}

fn walkDuplicateKeys(node: Node, section: []const u8, parent_key: ?[]const u8, list: *DiagnosticList) void {
    switch (node) {
        .mapping => |m| checkMapping(m, section, list),
        .sequence => |s| {
            const item_section = blk: {
                if (parent_key) |pk| {
                    if (std.ascii.eqlIgnoreCase(pk, "steps")) break :blk "step";
                }
                break :blk section;
            };
            for (s.items) |item| {
                walkDuplicateKeys(item, item_section, parent_key, list);
            }
        },
        else => {},
    }
}

fn checkMapping(mapping: Mapping, section: []const u8, list: *DiagnosticList) void {
    for (mapping.entries, 0..) |entry, i| {
        var first: ?Scalar = null;
        for (mapping.entries[0..i]) |earlier| {
            if (!std.ascii.eqlIgnoreCase(earlier.key.value, entry.key.value)) continue;
            if (first == null) first = earlier.key;
        }
        if (first) |prior| {
            const message = std.fmt.allocPrint(
                list.fixAllocator(),
                "key \"{s}\" is duplicated in \"{s}\" section. previously defined at line:{d},col:{d}. note that this key is case insensitive",
                .{ entry.key.value, section, prior.span.start_line, prior.span.start_col },
            ) catch return;

            list.append(.{
                .rule_id = "SYN002",
                .severity = .@"error",
                .message = message,
                .span = entry.key.span,
                .fix_hint = "remove the duplicate key or rename it so keys are unique within the section",
            }) catch return;
        }

        const child_section = sectionForMappingChild(section, entry.key.value);
        walkDuplicateKeys(entry.value, child_section, entry.key.value, list);
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
    emitDuplicateKeyDiagnostics(node, diags);
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
