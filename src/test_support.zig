//! Nothing here is used by the linter at runtime; the module exists so the
//! same fixture-building and assertion code isn't re-typed in every rules file.

const std = @import("std");
const runtime = @import("runtime.zig");

const yaml = @import("yaml/types.zig");
const yaml_parser = @import("yaml/parser.zig");
const workflow_types = @import("workflow/types.zig");
const workflow_parser = @import("workflow/parser.zig");
const diagnostics = @import("diagnostics.zig");
const fix_engine = @import("fix/engine.zig");

const Span = yaml.Span;
const Node = yaml.Node;
const DiagnosticList = diagnostics.DiagnosticList;
const Diagnostic = diagnostics.Diagnostic;
const EventConfig = workflow_types.EventConfig;
const EventType = workflow_types.EventType;
const Trigger = workflow_types.Trigger;

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

pub const empty_trigger = Trigger{ .events = &.{} };

pub fn makeTrigger(comptime ev: EventType) Trigger {
    const events = &[_]EventConfig{.{ .event = ev }};
    return .{ .events = events };
}

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

pub fn mkScalar(value: []const u8) Node {
    return .{ .scalar = .{ .value = value, .style = .plain, .span = Span.point(1, 1, 0) } };
}

/// `allocator` must outlive the result, so tests pass an arena's allocator.
pub fn parseWorkflowSource(allocator: std.mem.Allocator, source: []const u8) !workflow_types.Workflow {
    var yp = yaml_parser.Parser.init(allocator, source);
    return workflow_parser.parseWorkflow(allocator, try yp.parse());
}

pub fn lintSourceAlloc(
    alloc: std.mem.Allocator,
    source: []const u8,
    check: Check,
    list: *DiagnosticList,
) !void {
    switch (check) {
        .document => |f| {
            var yp = yaml_parser.Parser.init(alloc, source);
            f(try yp.parse(), list);
        },
        else => {
            const wf = try parseWorkflowSource(alloc, source);
            switch (check) {
                .workflow => |f| f(&wf, list),
                .job => |f| for (wf.jobs) |*job| f(job, list),
                .step => |f| for (wf.jobs) |*job| workflow_types.walkSteps(job.steps, struct {
                    f: *const fn (*const workflow_types.Step, *DiagnosticList) void,
                    diags: *DiagnosticList,
                    pub fn visit(self: @This(), step: *const workflow_types.Step) void {
                        self.f(step, self.diags);
                    }
                }{ .f = f, .diags = list }),
                .document => unreachable,
            }
        },
    }
}

/// Parse `source` and run `check`. The workflow tree lives in a test arena
/// that dies before return; diagnostics must copy what they keep into `list`.
pub fn lintSource(source: []const u8, check: Check, list: *DiagnosticList) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try lintSourceAlloc(arena.allocator(), source, check, list);
}

pub fn expectNoDiagnostics(source: []const u8, check: Check) !void {
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();
    try lintSource(source, check, &list);
    if (list.len() != 0) {
        std.debug.print("unexpected diagnostic: {s}\n", .{list.get(0).message});
    }
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

pub fn expectMessage(source: []const u8, check: Check, rule_id: []const u8, needle: []const u8) !void {
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();
    try lintSource(source, check, &list);
    for (list.items.items) |diag| {
        if (std.mem.eql(u8, diag.rule_id, rule_id) and std.mem.find(u8, diag.message, needle) != null) {
            return;
        }
    }
    if (list.len() != 0) {
        std.debug.print("messages did not contain \"{s}\"; first: {s}\n", .{ needle, list.get(0).message });
    }
    return error.MessageNotFound;
}

pub const Check = union(enum) {
    workflow: *const fn (*const workflow_types.Workflow, *DiagnosticList) void,
    job: *const fn (*const workflow_types.Job, *DiagnosticList) void,
    step: *const fn (*const workflow_types.Step, *DiagnosticList) void,
    /// A check over a raw YAML document, for configs that are not workflows.
    document: *const fn (Node, *DiagnosticList) void,
};

pub const FixOutcome = struct {
    content: []const u8,
    edits_applied: usize,
    diagnostic_count: usize,
    fix_count: usize,
    first_safety: ?diagnostics.FixSafety,

    pub fn deinit(self: FixOutcome, allocator: std.mem.Allocator) void {
        allocator.free(self.content);
    }
};

/// Diagnostics and their fix strings live in an arena that dies here; the fix
/// engine copies what it needs into the returned `content`.
pub fn lintAndFix(
    allocator: std.mem.Allocator,
    source: []const u8,
    check: Check,
    include_unsafe: bool,
) !FixOutcome {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var diags = DiagnosticList.init(alloc);
    try lintSourceAlloc(alloc, source, check, &diags);

    const fixes = try fix_engine.collectFixes(alloc, diags.items.items, include_unsafe);
    const result = try fix_engine.applyFixes(allocator, source, fixes);
    return .{
        .content = result.content,
        .edits_applied = result.edits_applied,
        .diagnostic_count = diags.len(),
        .fix_count = fixes.len,
        .first_safety = if (fixes.len > 0) fixes[0].safety else null,
    };
}

/// Installs an isolated environment map and restores the previous one in LIFO order.
pub const EnvGuard = struct {
    allocator: std.mem.Allocator,
    saved: ?*std.process.Environ.Map,
    map: *std.process.Environ.Map,

    pub fn set(allocator: std.mem.Allocator, name: []const u8, value: ?[]const u8) !EnvGuard {
        const map = try allocator.create(std.process.Environ.Map);
        errdefer allocator.destroy(map);
        map.* = if (runtime.environ) |previous|
            try previous.clone(allocator)
        else
            try std.testing.environ.createMap(allocator);
        errdefer map.deinit();
        if (value) |v| try map.put(name, v) else _ = map.swapRemove(name);
        const saved = runtime.environ;
        runtime.environ = map;
        return .{ .allocator = allocator, .saved = saved, .map = map };
    }

    pub fn setDir(allocator: std.mem.Allocator, name: []const u8, dir: std.Io.Dir) !EnvGuard {
        const path = try dir.realPathFileAlloc(runtime.io(), ".", allocator);
        defer allocator.free(path);
        return set(allocator, name, path);
    }

    pub fn deinit(self: *EnvGuard) void {
        std.debug.assert(runtime.environ == self.map);
        runtime.environ = self.saved;
        self.map.deinit();
        self.allocator.destroy(self.map);
    }
};
