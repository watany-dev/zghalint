//! SYN026 — GitHub Actions does not accept YAML merge key `<<` (issue #439).
//!
//! The YAML parser still folds `<<:` so the rest of the linter can see the
//! merged keys.

const std = @import("std");
const engine = @import("engine.zig");
const yaml = @import("../yaml/types.zig");
const test_support = @import("../test_support.zig");

const Rule = engine.Rule;
const Workflow = engine.Workflow;
const DiagnosticList = engine.DiagnosticList;

fn checkMergeKeys(wf: *const Workflow, list: *DiagnosticList) void {
    const root = wf.yaml_root orelse return;
    const mapping = switch (root) {
        .mapping => |m| m,
        else => return,
    };
    for (mapping.merge_key_spans) |span| {
        list.append(.{
            .rule_id = "SYN026",
            .severity = .@"error",
            .message = "GitHub Actions does not support YAML merge key \"<<\"",
            .span = span,
            .fix_hint = "inline the mapping, or use an alias without <<",
        }) catch return;
    }
}

pub const rules = [_]Rule{
    .{
        .id = "SYN026",
        .name = "unsupported-yaml-merge",
        .description = "GitHub Actions does not support the YAML merge key <<",
        .severity = .@"error",
        .category = .syntax,
        .check_workflow = &checkMergeKeys,
    },
};

const testing = std.testing;

fn runSyn026(source: []const u8) !DiagnosticList {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const wf = try test_support.parseWorkflowSource(arena.allocator(), source);
    var list = DiagnosticList.init(testing.allocator);
    checkMergeKeys(&wf, &list);
    return list;
}

test "SYN026: a merge key is reported" {
    const source =
        \\on: push
        \\jobs:
        \\  a:
        \\    <<: &defaults
        \\      timeout-minutes: 5
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\  b:
        \\    <<: *defaults
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn026(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 2), test_support.countDiagnostics(&diags, "SYN026"));
    try testing.expectEqual(@as(usize, 4), diags.get(0).span.start_line);
    try testing.expectEqual(@as(usize, 10), diags.get(1).span.start_line);
}

test "SYN026: an alias without a merge key is clean" {
    const source =
        \\on: push
        \\defaults: &defaults
        \\  run:
        \\    shell: bash
        \\jobs:
        \\  a:
        \\    defaults: *defaults
        \\    runs-on: ubuntu-latest
        \\    timeout-minutes: 5
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn026(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 0), diags.len());
}

test "SYN026: a flow merge key is reported" {
    const source =
        \\on: push
        \\jobs:
        \\  a: {<<: {timeout-minutes: 5}, runs-on: ubuntu-latest, steps: [{run: echo}]}
    ;

    var diags = try runSyn026(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 1), test_support.countDiagnostics(&diags, "SYN026"));
}

test "SYN026: nested merge under an anchored mapping is reported once" {
    const source =
        \\x-common: &common
        \\  env:
        \\    <<: {FOO: bar}
        \\on: push
        \\jobs:
        \\  a:
        \\    <<: *common
        \\    runs-on: ubuntu-latest
        \\    timeout-minutes: 5
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn026(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 2), test_support.countDiagnostics(&diags, "SYN026"));
}

test "SYN026: nested merge used only as a merge source is reported" {
    const source =
        \\on: push
        \\jobs:
        \\  a:
        \\    <<:
        \\      <<: {timeout-minutes: 5}
        \\      runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ;

    var diags = try runSyn026(source);
    defer diags.deinit();

    try testing.expectEqual(@as(usize, 2), test_support.countDiagnostics(&diags, "SYN026"));
}
