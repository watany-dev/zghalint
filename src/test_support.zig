//! Helpers shared by the inline test blocks across the codebase.
//!
//! Nothing here is used by the linter at runtime; the module exists so the
//! same fixture-building and assertion code isn't re-typed in every rules file.

const std = @import("std");

const yaml = @import("yaml/types.zig");
const yaml_parser = @import("yaml/parser.zig");
const workflow_types = @import("workflow/types.zig");
const workflow_parser = @import("workflow/parser.zig");
const diagnostics = @import("diagnostics.zig");
const rule_engine = @import("rules/engine.zig");
const fix_engine = @import("fix/engine.zig");

const Span = yaml.Span;
const Node = yaml.Node;
const DiagnosticList = diagnostics.DiagnosticList;
const Diagnostic = diagnostics.Diagnostic;
const EventConfig = workflow_types.EventConfig;
const EventType = workflow_types.EventType;
const Trigger = workflow_types.Trigger;
const Rule = rule_engine.Rule;

// ── Diagnostic assertions ──

pub fn hasDiagnostic(list: *const DiagnosticList, rule_id: []const u8) bool {
    return findDiagnostic(list, rule_id) != null;
}

pub fn countDiagnostics(list: *const DiagnosticList, rule_id: []const u8) usize {
    var count: usize = 0;
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, rule_id)) count += 1;
    }
    return count;
}

pub fn findDiagnostic(list: *const DiagnosticList, rule_id: []const u8) ?Diagnostic {
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, rule_id)) return d;
    }
    return null;
}

// ── Workflow fixtures ──

/// A workflow with no `on:` events at all.
pub const empty_trigger = Trigger{ .events = &.{} };

/// A single-event `on:` trigger. `name` is the key as it would appear in YAML,
/// which is `@tagName(ev)` for every event GitHub currently defines.
pub fn makeTrigger(comptime ev: EventType, comptime name: []const u8) Trigger {
    const events = &[_]EventConfig{.{ .event = ev, .name = name }};
    return .{ .events = events };
}

// ── Span / node fixtures ──

/// A span whose line/column are meaningless but whose byte range is real —
/// enough for rules that only look at byte offsets.
pub fn dummySpan(start_byte: usize, end_byte: usize) Span {
    return .{
        .start_line = 1,
        .start_col = 1,
        .end_line = 1,
        .end_col = 1,
        .start_byte = start_byte,
        .end_byte = end_byte,
    };
}

/// A plain scalar node at the start of the document.
pub fn mkScalar(value: []const u8) Node {
    return .{ .scalar = .{ .value = value, .style = .plain, .span = Span.point(1, 1, 0) } };
}

// ── Autofix harness ──

/// Parse `source` as a workflow, run `rules` over it, apply the fixes they
/// produce and hand back the rewritten source. `unsafe` also applies fixes
/// marked `.unsafe`. The caller owns the result.
pub fn lintAndFix(
    allocator: std.mem.Allocator,
    rules: []const Rule,
    source: []const u8,
    unsafe: bool,
) !fix_engine.ApplyResult {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var yp = yaml_parser.Parser.init(alloc, source);
    defer yp.deinit();
    const wf = try workflow_parser.parseWorkflow(alloc, try yp.parse());

    var diags = rule_engine.Engine.init(rules).run(alloc, &wf);
    defer diags.deinit();

    const fixes = try fix_engine.collectFixes(alloc, diags.items.items, unsafe);
    // Copy out of the arena before it goes away.
    const result = try fix_engine.applyFixes(alloc, source, fixes);
    return .{
        .content = try allocator.dupe(u8, result.content),
        .edits_applied = result.edits_applied,
    };
}

/// The single rule with `id`, as a slice, so a test can fix one rule at a time
/// without the rest of the file's rules editing the same source.
pub fn only(comptime rules: []const Rule, comptime id: []const u8) []const Rule {
    comptime {
        for (rules) |r| {
            if (std.mem.eql(u8, r.id, id)) return &[_]Rule{r};
        }
        @compileError("no rule with id " ++ id);
    }
}

// ── Environment ──

const libc_setenv = @extern(*const fn ([*:0]const u8, [*:0]const u8, c_int) callconv(.c) c_int, .{ .name = "setenv" });
const libc_unsetenv = @extern(*const fn ([*:0]const u8) callconv(.c) c_int, .{ .name = "unsetenv" });

/// Overrides one environment variable for the duration of a test and restores
/// whatever the process had before, so tests leave process state untouched.
/// Requires libc, which the test binaries link.
pub const EnvGuard = struct {
    allocator: std.mem.Allocator,
    name: [:0]const u8,
    saved: ?[:0]u8,

    /// Set `name` to `value`, or unset it when `value` is null.
    pub fn set(allocator: std.mem.Allocator, name: [:0]const u8, value: ?[:0]const u8) !EnvGuard {
        const previous = std.process.getEnvVarOwned(allocator, name) catch null;
        defer if (previous) |p| allocator.free(p);
        const saved: ?[:0]u8 = if (previous) |p| try allocator.dupeZ(u8, p) else null;

        if (value) |v| {
            _ = libc_setenv(name.ptr, v.ptr, 1);
        } else {
            _ = libc_unsetenv(name.ptr);
        }
        return .{ .allocator = allocator, .name = name, .saved = saved };
    }

    pub fn deinit(self: *EnvGuard) void {
        if (self.saved) |s| {
            _ = libc_setenv(self.name.ptr, s.ptr, 1);
            self.allocator.free(s);
        } else {
            _ = libc_unsetenv(self.name.ptr);
        }
    }
};
