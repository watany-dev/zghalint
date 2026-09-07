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
            const hint = didYouMean(alloc, Input, inputs, key) orelse wording.unknown_hint;

            report(list, wording.rule_id, message, keySpan(step, key), hint);
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

        report(list, wording.rule_id, message, spans.usesSpan(step), hint);
    }
}

fn containsIgnoreCase(names: []const []const u8, name: []const u8) bool {
    for (names) |candidate| {
        if (std.ascii.eqlIgnoreCase(candidate, name)) return true;
    }
    return false;
}

fn didYouMean(
    alloc: std.mem.Allocator,
    comptime Input: type,
    inputs: []const Input,
    key: []const u8,
) ?[]const u8 {
    const names = alloc.alloc([]const u8, inputs.len) catch return null;
    for (inputs, 0..) |input, i| names[i] = input.name;

    const suggestion = util.didYouMean(key, names) orelse return null;
    return std.fmt.allocPrint(alloc, "did you mean \"{s}\"?", .{suggestion}) catch null;
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
) void {
    list.append(.{
        .rule_id = rule_id,
        .severity = .@"error",
        .message = message,
        .span = span,
        .fix_hint = hint,
    }) catch return;
}
