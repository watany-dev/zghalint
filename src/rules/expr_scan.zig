//! Shared traversal for the contextual-typing rules (EXPR010-EXPR014).
//!
//! Each of those rules answers the same question in a different context: walk
//! every `${{ }}` expression reachable from a step or a job, and resolve the
//! context paths inside it against workflow data. Only the resolution differs,
//! so the walk lives here and the caller supplies a visitor with a
//! `checkPath(path, span)` method and an `alloc` field backing the expression
//! parse trees.
//!
//! Spans are node-precise: a path is reported at its own byte range inside the
//! scalar, not at the whole step.

const std = @import("std");
const expressions = @import("expressions.zig");
const spans = @import("spans.zig");
const workflow_types = @import("../workflow/types.zig");

const Job = workflow_types.Job;
const Step = workflow_types.Step;
const Span = spans.Span;
const Anchor = spans.Anchor;
const ExprNode = expressions.ExprNode;

fn Walk(comptime Visitor: type) type {
    return struct {
        visitor: Visitor,
        text: []const u8,
        anchor: Anchor,
        /// Offset of the expression source inside `text`, so a node's
        /// expression-relative byte range maps back to a file position.
        expr_offset: usize,

        const Self = @This();

        fn spanOf(self: Self, node: *const ExprNode) Span {
            const start = self.expr_offset + node.start_byte;
            const len = if (node.end_byte > node.start_byte) node.end_byte - node.start_byte else 0;
            return self.anchor.at(self.text, start, len);
        }

        fn walk(self: Self, node: *const ExprNode) void {
            if (node.kind == .context_access) {
                self.visitor.checkPath(node.value, self.spanOf(node));
                return;
            }
            for (node.children) |*child| self.walk(child);
        }
    };
}

/// A parse failure is EXPR001's finding; the contextual rules stay silent on it.
fn scanExpression(visitor: anytype, text: []const u8, anchor: Anchor, expr_offset: usize, expr: []const u8) void {
    var parser = expressions.ExprParser.init(visitor.alloc, expr);
    const node = parser.parse() catch return;
    const walk = Walk(@TypeOf(visitor)){
        .visitor = visitor,
        .text = text,
        .anchor = anchor,
        .expr_offset = expr_offset,
    };
    walk.walk(&node);
}

/// Scans every `${{ }}` block embedded in `text`.
pub fn scanText(visitor: anytype, text: []const u8, anchor: Anchor) void {
    var pos: usize = 0;
    while (pos + 2 < text.len) {
        if (!(text[pos] == '$' and text[pos + 1] == '{' and text[pos + 2] == '{')) {
            pos += 1;
            continue;
        }
        const expr_start = pos + 3;
        const end_offset = std.mem.indexOf(u8, text[expr_start..], "}}") orelse return;
        const content = text[expr_start .. expr_start + end_offset];
        pos = expr_start + end_offset + 2;

        const leading = std.mem.indexOfNone(u8, content, " \t\n\r") orelse continue;
        const trimmed = std.mem.trim(u8, content, " \t\n\r");
        scanExpression(visitor, text, anchor, expr_start + leading, trimmed);
    }
}

/// `if:` may omit the `${{ }}` wrapper, in which case the whole scalar is one
/// expression.
pub fn scanCondition(
    visitor: anytype,
    condition: ?[]const u8,
    meta: ?workflow_types.ScalarValueMeta,
    fallback: Span,
) void {
    const value = condition orelse return;
    const anchor = Anchor.fromMeta(meta, fallback);
    if (std.mem.indexOf(u8, value, "${{") != null) {
        scanText(visitor, value, anchor);
        return;
    }
    const trimmed = std.mem.trim(u8, value, " \t\n\r");
    if (trimmed.len == 0) return;
    const leading: usize = @intFromPtr(trimmed.ptr) - @intFromPtr(value.ptr);
    scanExpression(visitor, value, anchor, leading, trimmed);
}

pub fn scanScalarMap(
    visitor: anytype,
    map: ?workflow_types.StringMap,
    meta_map: ?workflow_types.ScalarValueMetaMap,
    fallback: Span,
) void {
    const values = map orelse return;
    for (values.keys(), values.values()) |key, value| {
        const entry_meta = if (meta_map) |m| m.get(key) else null;
        scanText(visitor, value, Anchor.fromMeta(entry_meta, fallback));
    }
}

/// `run:`, `if:`, `with:` and `env:` — every step field that carries a scalar
/// an expression can hide in.
pub fn scanStep(visitor: anytype, step: *const Step) void {
    if (step.run) |run_val| {
        scanText(visitor, run_val, spans.runAnchor(step));
    }
    scanCondition(visitor, step.if_condition, step.if_condition_meta, step.span);
    scanScalarMap(visitor, step.with, step.with_meta, step.span);
    scanScalarMap(visitor, step.env, step.env_meta, step.span);
}

/// The job's own scalars, excluding its steps. `runs-on` is included because
/// `runs-on: ${{ matrix.os }}` is the canonical matrix reference; job-level
/// `with:` feeds a reusable workflow call and has no per-entry spans, so the
/// job span anchors it.
pub fn scanJobFields(visitor: anytype, job: *const Job) void {
    scanCondition(visitor, job.if_condition, job.if_condition_meta, job.span);
    scanScalarMap(visitor, job.env, job.env_meta, job.span);
    scanScalarMap(visitor, job.with, null, job.span);
    if (job.runs_on) |runs_on| {
        scanText(visitor, runs_on, Anchor.fromMeta(runsOnMeta(job), job.span));
    }
}

fn runsOnMeta(job: *const Job) ?workflow_types.ScalarValueMeta {
    const span = job.runs_on_value_span orelse return null;
    return .{ .value_span = span, .style = job.runs_on_value_style };
}

/// Every scalar of a job: its own fields and those of each step.
pub fn scanJob(visitor: anytype, job: *const Job) void {
    scanJobFields(visitor, job);
    for (job.steps) |*step| scanStep(visitor, step);
}
