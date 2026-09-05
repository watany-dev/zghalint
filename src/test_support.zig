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

const Span = yaml.Span;
const Node = yaml.Node;
const DiagnosticList = diagnostics.DiagnosticList;
const Diagnostic = diagnostics.Diagnostic;
const EventConfig = workflow_types.EventConfig;
const EventType = workflow_types.EventType;
const Trigger = workflow_types.Trigger;

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

/// A single-event `on:` trigger.
pub fn makeTrigger(comptime ev: EventType) Trigger {
    const events = &[_]EventConfig{.{ .event = ev }};
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

// ── Workflow parsing ──

/// Parse `source` into a `Workflow` allocated from `allocator` — which must
/// outlive the result, so tests pass an arena's allocator.
pub fn parseWorkflowSource(allocator: std.mem.Allocator, source: []const u8) !workflow_types.Workflow {
    var yp = yaml_parser.Parser.init(allocator, source);
    return workflow_parser.parseWorkflow(allocator, try yp.parse());
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

    /// Point `name` at `dir`'s real path for the lifetime of the guard.
    /// `setenv` copies the value, so the temporary path buffers can go away here.
    pub fn setDir(allocator: std.mem.Allocator, name: [:0]const u8, dir: std.fs.Dir) !EnvGuard {
        const path = try dir.realpathAlloc(allocator, ".");
        defer allocator.free(path);
        const path_z = try allocator.dupeZ(u8, path);
        defer allocator.free(path_z);
        return set(allocator, name, path_z);
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
