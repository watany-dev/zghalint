const std = @import("std");
const engine = @import("engine.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml_types = @import("../yaml/types.zig");
const util = @import("../util.zig");

const Rule = engine.Rule;
const Workflow = engine.Workflow;
const Job = engine.Job;
const DiagnosticList = engine.DiagnosticList;
const Span = yaml_types.Span;
const UnknownKey = workflow_types.UnknownKey;

// ── SYN001: Unknown mapping keys ──

fn findDidYouMean(key: []const u8, expected: []const []const u8) ?[]const u8 {
    const max_dist: usize = 2;
    var best: ?[]const u8 = null;
    var best_dist: usize = std.math.maxInt(usize);
    var ties: usize = 0;

    for (expected) |candidate| {
        const dist = util.levenshteinDistance(key, candidate);
        if (dist == 0 or dist > max_dist) continue;
        if (dist < best_dist) {
            best = candidate;
            best_dist = dist;
            ties = 1;
        } else if (dist == best_dist) {
            ties += 1;
        }
    }

    if (ties != 1) return null;
    return best;
}

fn lessThanKey(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn formatUnexpectedKeyMessage(
    alloc: std.mem.Allocator,
    uk: UnknownKey,
    suggestion: ?[]const u8,
) ![]const u8 {
    const sorted = try alloc.alloc([]const u8, uk.expected.len);
    defer alloc.free(sorted);
    @memcpy(sorted, uk.expected);
    std.mem.sort([]const u8, sorted, {}, lessThanKey);

    var expected_buf = std.ArrayList(u8){};
    defer expected_buf.deinit(alloc);
    for (sorted, 0..) |key, i| {
        if (i > 0) try expected_buf.appendSlice(alloc, ", ");
        try expected_buf.writer(alloc).print("\"{s}\"", .{key});
    }

    var message = std.ArrayList(u8){};
    defer message.deinit(alloc);
    const writer = message.writer(alloc);
    try writer.print(
        "unexpected key \"{s}\" for \"{s}\" section. expected one of {s}",
        .{ uk.key, uk.section, expected_buf.items },
    );

    if (suggestion) |s| {
        try writer.print("; did you mean \"{s}\"?", .{s});
    }

    return try message.toOwnedSlice(alloc);
}

fn checkUnknownKeys(wf: *const Workflow, list: *DiagnosticList) void {
    const alloc = list.fixAllocator();
    for (wf.unknown_keys) |uk| {
        const suggestion = findDidYouMean(uk.key, uk.expected);
        const message = formatUnexpectedKeyMessage(alloc, uk, suggestion) catch continue;
        const fix_hint = if (suggestion) |s|
            std.fmt.allocPrint(alloc, "did you mean \"{s}\"?", .{s}) catch null
        else
            null;

        list.append(.{
            .rule_id = "SYN001",
            .severity = .@"error",
            .message = message,
            .span = uk.span,
            .fix_hint = fix_hint,
        }) catch continue;
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
        .id = "SYN001",
        .name = "unknown-key",
        .description = "mapping contains a key that is not defined in the GitHub Actions workflow schema",
        .severity = .@"error",
        .category = .syntax,
        .check_workflow = &checkUnknownKeys,
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
const workflow_parser = @import("../workflow/parser.zig");
const yaml_parser_mod = @import("../yaml/parser.zig");

fn parseWorkflowYaml(arena: *std.heap.ArenaAllocator, source: []const u8) !Workflow {
    const alloc = arena.allocator();

    var parser = yaml_parser_mod.Parser.init(alloc, source);
    defer parser.deinit();
    const yaml_node = try parser.parse();
    return try workflow_parser.parseWorkflow(alloc, yaml_node);
}

fn lintUnknownKeys(wf: *const Workflow, list: *DiagnosticList) void {
    checkUnknownKeys(wf, list);
}

test "SYN001: unknown job key is reported" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    timeout-minute: 10
        \\    steps:
        \\      - run: echo hi
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try parseWorkflowYaml(&arena, source);
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    lintUnknownKeys(&wf, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expectEqualStrings("SYN001", diag.rule_id);
    try testing.expect(diag.severity == .@"error");
    try testing.expect(std.mem.indexOf(u8, diag.message, "timeout-minute") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "\"job\"") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "did you mean \"timeout-minutes\"") != null);
}

test "SYN001: unknown step key is reported" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - runs: echo hi
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try parseWorkflowYaml(&arena, source);
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    lintUnknownKeys(&wf, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expect(std.mem.indexOf(u8, diag.message, "runs") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "\"step\"") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "did you mean \"run\"") != null);
}

test "SYN001: valid workflow produces no diagnostic" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    timeout-minutes: 10
        \\    steps:
        \\      - run: echo hi
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try parseWorkflowYaml(&arena, source);
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    lintUnknownKeys(&wf, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN001: matrix keys are not validated" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest]
        \\        custom-key: [value]
        \\    steps:
        \\      - run: echo hi
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try parseWorkflowYaml(&arena, source);
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    lintUnknownKeys(&wf, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN001: with and env keys are not validated" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/checkout@v4
        \\        with:
        \\          fetch-depth: 1
        \\        env:
        \\          CUSTOM: value
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try parseWorkflowYaml(&arena, source);
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    lintUnknownKeys(&wf, &diags);

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN001: unknown workflow key is reported" {
    const source =
        \\on: push
        \\default:
        \\  run:
        \\    shell: bash
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try parseWorkflowYaml(&arena, source);
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    lintUnknownKeys(&wf, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expect(std.mem.indexOf(u8, diag.message, "default") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "\"workflow\"") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "did you mean \"defaults\"") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "\"true\"") == null);
}

test "SYN001: expected keys are sorted" {
    const source =
        \\on: push
        \\foo: bar
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try parseWorkflowYaml(&arena, source);
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    lintUnknownKeys(&wf, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "\"concurrency\", \"defaults\", \"env\", \"jobs\"") != null);
}

test "SYN001: unknown strategy key is reported" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      fail_fast: false
        \\      matrix:
        \\        os: [ubuntu-latest]
        \\    steps:
        \\      - run: echo hi
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try parseWorkflowYaml(&arena, source);
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    lintUnknownKeys(&wf, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expect(std.mem.indexOf(u8, diag.message, "fail_fast") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "\"strategy\"") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "did you mean \"fail-fast\"") != null);
}

test "SYN001: unknown container key is reported" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    container:
        \\      image: node:20
        \\      imagen: node:20
        \\    steps:
        \\      - run: echo hi
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try parseWorkflowYaml(&arena, source);
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    lintUnknownKeys(&wf, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expect(std.mem.indexOf(u8, diag.message, "imagen") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "\"container\"") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "did you mean \"image\"") != null);
}

test "SYN001: unknown services key is reported" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    services:
        \\      redis:
        \\        image: redis
        \\        imagen: redis
        \\    steps:
        \\      - run: echo hi
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try parseWorkflowYaml(&arena, source);
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    lintUnknownKeys(&wf, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expect(std.mem.indexOf(u8, diag.message, "imagen") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "\"services\"") != null);
}

test "SYN001: unknown defaults.run key is reported" {
    const source =
        \\on: push
        \\defaults:
        \\  run:
        \\    shel: bash
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try parseWorkflowYaml(&arena, source);
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    lintUnknownKeys(&wf, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expect(std.mem.indexOf(u8, diag.message, "shel") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "\"run\"") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "did you mean \"shell\"") != null);
}

test "SYN001: step keys are case-sensitive" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\        Shell: bash
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try parseWorkflowYaml(&arena, source);
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    lintUnknownKeys(&wf, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expect(std.mem.indexOf(u8, diag.message, "Shell") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "did you mean \"shell\"") != null);
}

test "SYN001: action step rejects shell" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/checkout@v4
        \\        shell: bash
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try parseWorkflowYaml(&arena, source);
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    lintUnknownKeys(&wf, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    const diag = diags.get(0);
    try testing.expect(std.mem.indexOf(u8, diag.message, "shell") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message, "\"step\"") != null);
}

test "SYN001: distant key has no did-you-mean" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    totally-unrelated: 1
        \\    steps:
        \\      - run: echo hi
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try parseWorkflowYaml(&arena, source);
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    lintUnknownKeys(&wf, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "totally-unrelated") != null);
    try testing.expect(std.mem.indexOf(u8, diags.get(0).message, "did you mean") == null);
}

test "SYN001: message survives appendOwning after source list deinit" {
    const source =
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    timeout-minute: 10
        \\    steps:
        \\      - run: echo hi
    ;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try parseWorkflowYaml(&arena, source);

    var dst = DiagnosticList.init(testing.allocator);
    defer dst.deinit();

    {
        var src = DiagnosticList.init(testing.allocator);
        defer src.deinit();
        lintUnknownKeys(&wf, &src);
        try testing.expectEqual(@as(usize, 1), src.len());
        try dst.appendOwning(src.get(0));
    }

    try testing.expectEqualStrings("SYN001", dst.get(0).rule_id);
    try testing.expect(std.mem.indexOf(u8, dst.get(0).message, "timeout-minute") != null);
    const hint = dst.get(0).fix_hint orelse return error.TestExpectedNonNull;
    try testing.expect(std.mem.indexOf(u8, hint, "timeout-minutes") != null);
}

fn runOn(events: []const EventConfig, list: *DiagnosticList) void {
    const wf = Workflow{ .on = .{ .events = events }, .jobs = &.{} };
    checkExclusiveFilters(&wf, list);
}

fn runOnNeeds(needs: []const []const u8, diags: *DiagnosticList) void {
    const job = Job{ .id = "test", .runs_on = "ubuntu-latest", .needs = needs };
    checkDuplicateNeeds(&job, diags);
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
