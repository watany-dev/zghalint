//! Shared traversal for the contextual rules (EXPR010-EXPR016).
//!
//! Each of those rules answers the same question in a different context: walk
//! every `${{ }}` expression reachable from a step or a job, and resolve the
//! context paths inside it against workflow data. Only the resolution differs,
//! so the walk lives here and the caller supplies a visitor with an `alloc`
//! field backing the expression parse trees and either or both of
//! `checkPath(path, loc)` and `checkCall(name, loc)`.
//!
//! `Loc` is unresolved: `Anchor.at` only runs when the visitor emits a
//! diagnostic (#527). Paths are node-precise: a finding points at the path's
//! own byte range inside the scalar, not at the whole step.

const std = @import("std");
const expressions = @import("expressions.zig");
const spans = @import("spans.zig");
const workflow_types = @import("../workflow/types.zig");

const Job = workflow_types.Job;
const Step = workflow_types.Step;
const Span = spans.Span;
const Anchor = spans.Anchor;
const ExprNode = expressions.ExprNode;

/// Byte range of a path or call inside a scalar. `resolve` runs `Anchor.at`
/// only for a finding (#527).
pub const Loc = struct {
    anchor: Anchor,
    text: []const u8,
    offset: usize,
    len: usize,

    pub fn resolve(self: Loc) Span {
        return self.anchor.at(self.text, self.offset, self.len);
    }
};

fn Walk(comptime Visitor: type) type {
    return struct {
        visitor: Visitor,
        text: []const u8,
        anchor: Anchor,
        /// Offset of the expression source inside `text`, so a node's
        /// expression-relative byte range maps back to a file position.
        expr_offset: usize,

        const Self = @This();

        comptime {
            // A visitor whose hook is misspelled or not `pub` would walk every
            // expression and report nothing, silently disabling its rule.
            if (!@hasDecl(Visitor, "checkPath") and !@hasDecl(Visitor, "checkCall")) {
                @compileError(@typeName(Visitor) ++ " declares neither a pub checkPath nor a pub checkCall");
            }
        }

        fn locOf(self: Self, node: *const ExprNode) Loc {
            const start = self.expr_offset + node.start_byte;
            const len = if (node.end_byte > node.start_byte) node.end_byte - node.start_byte else 0;
            return .{
                .anchor = self.anchor,
                .text = self.text,
                .offset = start,
                .len = len,
            };
        }

        fn walk(self: Self, node: *const ExprNode) void {
            switch (node.kind) {
                .context_access => {
                    if (@hasDecl(Visitor, "checkPath")) {
                        self.visitor.checkPath(node.value, self.locOf(node));
                    }
                    return;
                },
                .function_call => {
                    if (@hasDecl(Visitor, "checkCall")) {
                        self.visitor.checkCall(node.value, self.locOf(node));
                    }
                },
                else => {},
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
    while (std.mem.find(u8, text[pos..], "${{")) |rel| {
        const expr_start = pos + rel + 3;
        const end_offset = std.mem.find(u8, text[expr_start..], "}}") orelse return;
        const content = text[expr_start .. expr_start + end_offset];
        pos = expr_start + end_offset + 2;

        const leading = std.mem.findNone(u8, content, " \t\n\r") orelse continue;
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
    if (std.mem.find(u8, value, "${{") != null) {
        scanText(visitor, value, anchor);
        return;
    }
    const leading = std.mem.findNone(u8, value, " \t\n\r") orelse return;
    const trimmed = std.mem.trim(u8, value, " \t\n\r");
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
fn scanJobFields(visitor: anytype, job: *const Job) void {
    scanCondition(visitor, job.if_condition, job.if_condition_meta, job.span);
    scanScalarMap(visitor, job.env, job.env_meta, job.span);
    scanScalarMap(visitor, job.with, null, job.span);
    if (job.runs_on) |runs_on| {
        scanText(visitor, runs_on, runsOnAnchor(job));
    }
}

/// `runs-on` keeps its span and style in two separate fields rather than a
/// `ScalarValueMeta`. The span is set whenever `job.runs_on` is, so the
/// fallback only satisfies `Anchor`'s shape.
pub fn runsOnAnchor(job: *const Job) Anchor {
    const span = job.runs_on_value_span orelse return Anchor{ .fallback = job.span };
    return Anchor.fromMeta(.{ .value_span = span, .style = job.runs_on_value_style }, job.span);
}

/// Every scalar of a job: its own fields and those of each step, including
/// nested `parallel:` children.
pub fn scanJob(visitor: anytype, job: *const Job) void {
    scanJobFields(visitor, job);
    scanStepTree(visitor, job.steps);
}

fn scanStepTree(visitor: anytype, steps: []const Step) void {
    for (steps) |*step| {
        scanStep(visitor, step);
        scanStepTree(visitor, step.nestedSteps());
    }
}

test "Loc.resolve matches Anchor.at" {
    const token = Span{
        .start_line = 3,
        .start_col = 9,
        .end_line = 3,
        .end_col = 24,
        .start_byte = 100,
        .end_byte = 115,
    };
    const value = "github.head_ref";
    const loc = Loc{
        .anchor = Anchor.fromMeta(.{ .value_span = token, .style = .plain }, Span.point(1, 1, 0)),
        .text = value,
        .offset = 7,
        .len = 8,
    };
    const s = loc.resolve();
    try std.testing.expectEqual(@as(u32, 3), s.start_line);
    try std.testing.expectEqual(@as(u32, 16), s.start_col);
    try std.testing.expectEqual(@as(usize, 107), s.start_byte);
}
