//! The `with:` half of DEP004 and DEP005: compare a step's `with:` keys
//! against the `inputs:` an action declares.
//!
//! The two rules read their metadata from different places — DEP004 parses a
//! local `action.yml`, DEP005 looks the action up in the embedded table — but
//! say the same three things about it, so the comparison lives here and the
//! callers only supply the inputs and the wording.

const std = @import("std");
const engine = @import("engine.zig");
const spans = @import("spans.zig");
const util = @import("../util.zig");
const rename = @import("rename.zig");
const diagnostics = @import("../diagnostics.zig");

const DiagnosticList = engine.DiagnosticList;
const Step = engine.Step;

/// How the diagnostics of one rule are worded. Everything else about the two
/// rules is identical.
pub const Wording = struct {
    rule_id: []const u8,
    /// Names the target in the message: `action` or `local action`.
    noun: []const u8,
    /// Fix hint for a key the action does not declare, used when no close
    /// enough input name exists to suggest.
    unknown_hint: []const u8,
};

/// The declared input whose name matches `name`, or null.
///
/// The runner matches a `with:` key to an `inputs:` entry without regard to
/// case, so this does too. `Input` is any struct with a `name` field, which
/// lets each caller keep its own representation.
pub fn find(comptime Input: type, inputs: []const Input, name: []const u8) ?Input {
    for (inputs) |input| {
        if (std.ascii.eqlIgnoreCase(input.name, name)) return input;
    }
    return null;
}

/// Report every `with:` key the action does not declare and every required
/// input the step leaves out.
///
/// `Input` needs a `name: []const u8` and a `required: bool`; an input that
/// carries a `default:` must already be marked as not required, because a
/// default satisfies it whether or not the caller passes anything.
pub fn check(
    comptime Input: type,
    step: *const Step,
    inputs: []const Input,
    /// `runs.using` of the referenced action, when it is known.
    using: ?[]const u8,
    wording: Wording,
    list: *DiagnosticList,
) void {
    const raw = (step.uses orelse return).raw;
    const alloc = list.fixAllocator();

    if (step.with) |with| {
        for (with.keys()) |key| {
            if (find(Input, inputs, key) != null) continue;
            if (isDockerOverride(using, key)) continue;

            const message = std.fmt.allocPrint(
                alloc,
                "input \"{s}\" is not declared by {s} \"{s}\"",
                .{ key, wording.noun, raw },
            ) catch return;
            const suggestion = nearestInput(alloc, Input, inputs, key);
            const hint = if (suggestion) |near|
                std.fmt.allocPrint(alloc, "did you mean \"{s}\"?", .{near}) catch wording.unknown_hint
            else
                wording.unknown_hint;

            report(
                list,
                wording.rule_id,
                message,
                keySpan(step, key),
                hint,
                if (suggestion) |near| renameKeyFix(list, step, key, near) else null,
            );
        }
    }

    for (inputs) |input| {
        if (!input.required) continue;
        if (step.with) |with| {
            if (containsIgnoreCase(with.keys(), input.name)) continue;
        }

        const message = std.fmt.allocPrint(
            alloc,
            "required input \"{s}\" of {s} \"{s}\" is not provided",
            .{ input.name, wording.noun, raw },
        ) catch return;
        const hint = std.fmt.allocPrint(alloc, "add `{s}:` under `with:`", .{input.name}) catch return;

        report(list, wording.rule_id, message, spans.usesSpan(step), hint, null);
    }
}

fn containsIgnoreCase(names: []const []const u8, name: []const u8) bool {
    for (names) |candidate| {
        if (std.ascii.eqlIgnoreCase(candidate, name)) return true;
    }
    return false;
}

fn nearestInput(
    alloc: std.mem.Allocator,
    comptime Input: type,
    inputs: []const Input,
    key: []const u8,
) ?[]const u8 {
    const names = alloc.alloc([]const u8, inputs.len) catch return null;
    for (inputs, 0..) |input, i| names[i] = input.name;

    return util.didYouMean(key, names);
}

/// The `with:` key itself, not the value `keySpan` points the caret at. Absent
/// when the parser captured no meta for the entry (a non-scalar value).
fn renameKeyFix(list: *DiagnosticList, step: *const Step, key: []const u8, suggestion: []const u8) ?diagnostics.Fix {
    const meta = (step.with_meta orelse return null).get(key) orelse return null;
    const key_span = meta.key_span orelse return null;
    return rename.tokenFix(list, key_span, key, suggestion);
}

/// `args:` and `entrypoint:` override the Dockerfile rather than naming an
/// input, so a docker action accepts them without declaring them.
fn isDockerOverride(using: ?[]const u8, key: []const u8) bool {
    if (!std.mem.eql(u8, using orelse return false, "docker")) return false;
    return std.mem.eql(u8, key, "args") or std.mem.eql(u8, key, "entrypoint");
}

/// The `with:` entry's value span when the parser captured it, so the caret
/// lands on the offending entry rather than on `uses:`.
pub fn keySpan(step: *const Step, key: []const u8) spans.Span {
    if (step.with_meta) |meta| {
        if (meta.get(key)) |m| return m.value_span;
    }
    return spans.usesSpan(step);
}

fn report(
    list: *DiagnosticList,
    rule_id: []const u8,
    message: []const u8,
    span: spans.Span,
    hint: []const u8,
    fix: ?diagnostics.Fix,
) void {
    list.append(.{
        .rule_id = rule_id,
        .severity = .@"error",
        .message = message,
        .span = span,
        .fix_hint = hint,
        .fix = fix,
    }) catch return;
}

const testing = std.testing;
const workflow_types = @import("../workflow/types.zig");
const ActionRef = workflow_types.ActionRef;

const TestInput = struct { name: []const u8, required: bool = false };

const test_wording = Wording{
    .rule_id = "TEST001",
    .noun = "action",
    .unknown_hint = "remove the input",
};

fn runCheck(step: *const Step, inputs: []const TestInput, using: ?[]const u8) DiagnosticList {
    var list = DiagnosticList.init(testing.allocator);
    check(TestInput, step, inputs, using, test_wording, &list);
    return list;
}

test "find matches an input name without regard to case" {
    const inputs = [_]TestInput{ .{ .name = "fetch-depth" }, .{ .name = "Token" } };

    try testing.expectEqualStrings("fetch-depth", find(TestInput, &inputs, "FETCH-DEPTH").?.name);
    try testing.expectEqualStrings("Token", find(TestInput, &inputs, "token").?.name);
    try testing.expect(find(TestInput, &inputs, "depth") == null);
}

test "a with key matching an input under a different case is accepted" {
    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);
    try with.put(testing.allocator, "FETCH-DEPTH", "1");

    const step = Step{ .uses = ActionRef.parse("actions/checkout@v4"), .with = with };
    var list = runCheck(&step, &.{.{ .name = "fetch-depth" }}, "node24");
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.len());
}

test "a required input is satisfied by a with key under a different case" {
    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);
    try with.put(testing.allocator, "Path", "src");

    const step = Step{ .uses = ActionRef.parse("actions/cache@v4"), .with = with };
    var list = runCheck(&step, &.{.{ .name = "path", .required = true }}, "node24");
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.len());
}

test "docker args and entrypoint are accepted only by a docker action" {
    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);
    try with.put(testing.allocator, "args", "--help");
    try with.put(testing.allocator, "entrypoint", "/bin/sh");

    const step = Step{ .uses = ActionRef.parse("some/action@v1"), .with = with };

    var docker = runCheck(&step, &.{}, "docker");
    defer docker.deinit();
    try testing.expectEqual(@as(usize, 0), docker.len());

    var node = runCheck(&step, &.{}, "node24");
    defer node.deinit();
    try testing.expectEqual(@as(usize, 2), node.len());
}

test "an unknown key points at its own value, a missing input at uses" {
    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);
    try with.put(testing.allocator, "versoin", "1");

    var meta: workflow_types.ScalarValueMetaMap = .empty;
    defer meta.deinit(testing.allocator);
    try meta.put(testing.allocator, "versoin", .{
        .value_span = .{ .start_line = 9, .start_col = 18, .end_line = 9, .end_col = 19, .start_byte = 40, .end_byte = 41 },
        .style = .plain,
    });

    const step = Step{
        .uses = ActionRef.parse("actions/setup-node@v4"),
        .with = with,
        .with_meta = meta,
        .uses_value_span = .{ .start_line = 7, .start_col = 14, .end_line = 7, .end_col = 35, .start_byte = 10, .end_byte = 31 },
    };
    var list = runCheck(&step, &.{
        .{ .name = "version" },
        .{ .name = "path", .required = true },
    }, "node24");
    defer list.deinit();

    try testing.expectEqual(@as(usize, 2), list.len());
    try testing.expectEqual(@as(usize, 9), list.get(0).span.start_line);
    try testing.expect(std.mem.find(u8, list.get(0).fix_hint.?, "version") != null);
    try testing.expectEqual(@as(usize, 7), list.get(1).span.start_line);
    try testing.expect(std.mem.find(u8, list.get(1).message, "required input") != null);
}

test "an unknown key with a captured key span renames the key" {
    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);
    try with.put(testing.allocator, "versoin", "1");

    var meta: workflow_types.ScalarValueMetaMap = .empty;
    defer meta.deinit(testing.allocator);
    try meta.put(testing.allocator, "versoin", .{
        .value_span = .{ .start_line = 9, .start_col = 18, .end_line = 9, .end_col = 19, .start_byte = 40, .end_byte = 41 },
        .key_span = .{ .start_line = 9, .start_col = 9, .end_line = 9, .end_col = 16, .start_byte = 31, .end_byte = 38 },
        .style = .plain,
    });

    const step = Step{
        .uses = ActionRef.parse("actions/setup-node@v4"),
        .with = with,
        .with_meta = meta,
        .uses_value_span = .{ .start_line = 7, .start_col = 14, .end_line = 7, .end_col = 35, .start_byte = 10, .end_byte = 31 },
    };
    var list = runCheck(&step, &.{.{ .name = "version" }}, "node24");
    defer list.deinit();

    try testing.expectEqual(@as(usize, 1), list.len());
    const fix = list.get(0).fix.?;
    try testing.expectEqual(diagnostics.FixSafety.safe, fix.safety);
    try testing.expectEqual(@as(usize, 1), fix.edits.len);
    // The key, not the value the caret points at.
    try testing.expectEqual(@as(usize, 31), fix.edits[0].start_byte);
    try testing.expectEqual(@as(usize, 38), fix.edits[0].end_byte);
    try testing.expectEqualStrings("version", fix.edits[0].replacement);
}

test "an unknown key without a close name carries no fix" {
    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);
    try with.put(testing.allocator, "completely-different", "1");

    var meta: workflow_types.ScalarValueMetaMap = .empty;
    defer meta.deinit(testing.allocator);
    try meta.put(testing.allocator, "completely-different", .{
        .value_span = .{ .start_line = 9, .start_col = 31, .end_line = 9, .end_col = 32, .start_byte = 60, .end_byte = 61 },
        .key_span = .{ .start_line = 9, .start_col = 9, .end_line = 9, .end_col = 29, .start_byte = 31, .end_byte = 51 },
        .style = .plain,
    });

    const step = Step{
        .uses = ActionRef.parse("actions/setup-node@v4"),
        .with = with,
        .with_meta = meta,
        .uses_value_span = .{ .start_line = 7, .start_col = 14, .end_line = 7, .end_col = 35, .start_byte = 10, .end_byte = 31 },
    };
    var list = runCheck(&step, &.{.{ .name = "version" }}, "node24");
    defer list.deinit();

    try testing.expectEqual(@as(usize, 1), list.len());
    try testing.expect(list.get(0).fix == null);
}

test "without with_meta an unknown key falls back to the uses span" {
    var with: workflow_types.StringMap = .empty;
    defer with.deinit(testing.allocator);
    try with.put(testing.allocator, "nope", "1");

    const step = Step{
        .uses = ActionRef.parse("actions/setup-node@v4"),
        .with = with,
        .uses_value_span = .{ .start_line = 7, .start_col = 14, .end_line = 7, .end_col = 35, .start_byte = 10, .end_byte = 31 },
    };
    var list = runCheck(&step, &.{}, "node24");
    defer list.deinit();

    try testing.expectEqual(@as(usize, 1), list.len());
    try testing.expectEqual(@as(usize, 7), list.get(0).span.start_line);
    try testing.expectEqualStrings("remove the input", list.get(0).fix_hint.?);
}

test "a step without uses is left alone" {
    const step = Step{ .run = "echo hi" };
    var list = runCheck(&step, &.{.{ .name = "path", .required = true }}, "node24");
    defer list.deinit();

    try testing.expectEqual(@as(usize, 0), list.len());
}
