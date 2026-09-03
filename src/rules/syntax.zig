const std = @import("std");
const engine = @import("engine.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml_types = @import("../yaml/types.zig");

const Rule = engine.Rule;
const Workflow = engine.Workflow;
const DiagnosticList = engine.DiagnosticList;
const EventFilterSpans = workflow_types.EventFilterSpans;
const Span = yaml_types.Span;

// ── SYN012: Mutually exclusive event filters ──

/// One `<filter>` / `<filter>-ignore` pair. GitHub Actions rejects a workflow
/// that specifies both halves of a pair for the same event.
const ExclusivePair = struct {
    /// Reads the key span of the positive filter (e.g. `branches`).
    include: *const fn (EventFilterSpans) ?Span,
    /// Reads the key span of the negative filter (e.g. `branches-ignore`).
    exclude: *const fn (EventFilterSpans) ?Span,
    message: []const u8,
    fix_hint: []const u8,
};

const exclusive_pairs = [_]ExclusivePair{
    .{
        .include = struct {
            fn f(s: EventFilterSpans) ?Span {
                return s.branches;
            }
        }.f,
        .exclude = struct {
            fn f(s: EventFilterSpans) ?Span {
                return s.branches_ignore;
            }
        }.f,
        .message = "both \"branches\" and \"branches-ignore\" filters cannot be used for the same event",
        .fix_hint = "keep only one of 'branches' or 'branches-ignore'; a negated pattern such as '!wip/**' can be listed under 'branches'",
    },
    .{
        .include = struct {
            fn f(s: EventFilterSpans) ?Span {
                return s.tags;
            }
        }.f,
        .exclude = struct {
            fn f(s: EventFilterSpans) ?Span {
                return s.tags_ignore;
            }
        }.f,
        .message = "both \"tags\" and \"tags-ignore\" filters cannot be used for the same event",
        .fix_hint = "keep only one of 'tags' or 'tags-ignore'; a negated pattern such as '!v0.*' can be listed under 'tags'",
    },
    .{
        .include = struct {
            fn f(s: EventFilterSpans) ?Span {
                return s.paths;
            }
        }.f,
        .exclude = struct {
            fn f(s: EventFilterSpans) ?Span {
                return s.paths_ignore;
            }
        }.f,
        .message = "both \"paths\" and \"paths-ignore\" filters cannot be used for the same event",
        .fix_hint = "keep only one of 'paths' or 'paths-ignore'; a negated pattern such as '!docs/**' can be listed under 'paths'",
    },
};

fn checkExclusiveFilters(wf: *const Workflow, list: *DiagnosticList) void {
    for (wf.on.events) |event| {
        const filter = event.filter orelse continue;
        for (exclusive_pairs) |pair| {
            const include_span = pair.include(filter.spans) orelse continue;
            const exclude_span = pair.exclude(filter.spans) orelse continue;

            // Report on whichever key comes second in the source so the
            // diagnostic points at the offending addition, not the first
            // filter the author wrote.
            const span = if (exclude_span.start_byte >= include_span.start_byte)
                exclude_span
            else
                include_span;

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

fn keySpan(start_byte: usize) Span {
    return .{
        .start_line = 1,
        .start_col = 1,
        .end_line = 1,
        .end_col = 1,
        .start_byte = start_byte,
        .end_byte = start_byte + 1,
    };
}

fn runOn(events: []const EventConfig, list: *DiagnosticList) void {
    const wf = Workflow{ .on = .{ .events = events }, .jobs = &.{} };
    checkExclusiveFilters(&wf, list);
}

test "SYN012: branches with branches-ignore is an error" {
    const events = [_]EventConfig{.{
        .event = .push,
        .name = "push",
        .filter = .{ .spans = .{ .branches = keySpan(10), .branches_ignore = keySpan(30) } },
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
        .filter = .{ .spans = .{ .tags = keySpan(10), .tags_ignore = keySpan(30) } },
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
        .filter = .{ .spans = .{ .paths = keySpan(10), .paths_ignore = keySpan(30) } },
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
            .branches = keySpan(10),
            .branches_ignore = keySpan(20),
            .tags = keySpan(30),
            .tags_ignore = keySpan(40),
            .paths = keySpan(50),
            .paths_ignore = keySpan(60),
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
        .filter = .{ .spans = .{ .branches = keySpan(10), .paths_ignore = keySpan(30) } },
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
            .spans = .{ .branches = keySpan(10), .branches_ignore = keySpan(30) },
        },
    }};
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    runOn(&events, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
}

test "SYN012: conflicts are reported per event" {
    const events = [_]EventConfig{
        .{
            .event = .push,
            .name = "push",
            .filter = .{ .spans = .{ .branches = keySpan(10), .branches_ignore = keySpan(20) } },
        },
        .{
            .event = .pull_request,
            .name = "pull_request",
            .filter = .{ .spans = .{ .paths = keySpan(40), .paths_ignore = keySpan(50) } },
        },
    };
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    runOn(&events, &diags);

    try testing.expectEqual(@as(usize, 2), diags.len());
}

test "SYN012: separate events using opposite halves are fine" {
    const events = [_]EventConfig{
        .{
            .event = .push,
            .name = "push",
            .filter = .{ .spans = .{ .branches = keySpan(10) } },
        },
        .{
            .event = .pull_request,
            .name = "pull_request",
            .filter = .{ .spans = .{ .branches_ignore = keySpan(40) } },
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
        .filter = .{ .spans = .{ .branches = keySpan(40), .branches_ignore = keySpan(10) } },
    }};
    var diags = DiagnosticList.init(testing.allocator);
    defer diags.deinit();

    runOn(&events, &diags);

    try testing.expectEqual(@as(usize, 1), diags.len());
    try testing.expectEqual(@as(usize, 40), diags.get(0).span.start_byte);
}
