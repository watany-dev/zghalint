//! EXPR011 — contextual typing of the `matrix` context (issue #87).
//!
//! `matrix.<key>` may only name an axis of the job's `strategy.matrix`, or a
//! key an `include:` entry adds. A job without `strategy.matrix` has no
//! `matrix` context at all. Both need the job, not just the step, so this
//! hangs off `check_job` next to EXPR010.
//!
//! A dynamic matrix (`matrix: ${{ fromJSON(...) }}`) carries keys that are
//! only known at run time, so nothing is reported for such a job.

const std = @import("std");
const engine = @import("engine.zig");
const expr_check = @import("expr_check.zig");
const expr_scan = @import("expr_scan.zig");
const spans = @import("spans.zig");
const util = @import("../util.zig");
const test_support = @import("../test_support.zig");

const Rule = engine.Rule;
const Job = engine.Job;
const DiagnosticList = engine.DiagnosticList;
const Span = spans.Span;

/// `include` and `exclude` are matrix keys in the YAML but not axes: the names
/// they carry live one level down, inside each entry.
fn isMetaAxis(name: []const u8) bool {
    return std.mem.eql(u8, name, "include") or std.mem.eql(u8, name, "exclude");
}

/// Context keys resolve case-insensitively on the runner, so `matrix.OS`
/// reaches an axis declared as `os`.
fn keyEql(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

/// Axis names plus every key an `include:` entry adds, deduplicated in source
/// order. `exclude:` entries can only narrow existing axes (SYN019 checks
/// that), so they contribute no names.
fn collectKeys(job: *const Job, alloc: std.mem.Allocator) ?[]const []const u8 {
    const strategy = job.strategy orelse return null;
    if (!strategy.matrix_key_present) return null;
    const matrix = strategy.matrix orelse return null;

    var keys: std.ArrayList([]const u8) = .empty;
    for (matrix.axes) |axis| {
        if (!isMetaAxis(axis.name)) {
            appendUnique(&keys, alloc, axis.name);
            continue;
        }
        if (!std.mem.eql(u8, axis.name, "include")) continue;
        for (axis.values) |value| {
            const entry = switch (value) {
                .mapping => |m| m,
                else => continue,
            };
            for (entry.entries) |kv| appendUnique(&keys, alloc, kv.key.value);
        }
    }
    return keys.toOwnedSlice(alloc) catch null;
}

fn appendUnique(keys: *std.ArrayList([]const u8), alloc: std.mem.Allocator, name: []const u8) void {
    for (keys.items) |seen| {
        if (keyEql(seen, name)) return;
    }
    keys.append(alloc, name) catch return;
}

const Resolver = struct {
    /// Declared matrix keys, or null when the job has no `matrix:` at all.
    keys: ?[]const []const u8,
    /// Backs the expression parse trees; diagnostic messages are allocated
    /// from the list's own arena instead.
    alloc: std.mem.Allocator,
    list: *DiagnosticList,

    pub fn checkPath(self: Resolver, path: []const u8, span: Span) void {
        var iter = expr_check.SegmentIter{ .path = path };
        const root = identSegment(iter.next()) orelse return;
        if (!keyEql(root, "matrix")) return;

        const declared = self.keys orelse {
            self.reportUnavailable(span);
            return;
        };

        // `matrix` alone (`toJSON(matrix)`) and computed keys
        // (`matrix[github.ref]`) carry no name to resolve.
        const key = identSegment(iter.next()) orelse return;
        for (declared) |name| {
            if (keyEql(name, key)) return;
        }
        self.reportUnknownKey(key, declared, span);
    }

    fn reportUnavailable(self: Resolver, span: Span) void {
        self.list.append(.{
            .rule_id = "EXPR011",
            .severity = .@"error",
            .message = "\"matrix\" is not available: this job has no \"strategy.matrix\"",
            .span = span,
            .fix_hint = "add a `strategy.matrix:` to the job, or drop the reference",
        }) catch return;
    }

    fn reportUnknownKey(self: Resolver, key: []const u8, declared: []const []const u8, span: Span) void {
        const alloc = self.list.fixAllocator();
        const suffix = if (util.didYouMean(key, declared)) |s|
            std.fmt.allocPrint(alloc, ". did you mean \"{s}\"?", .{s}) catch ""
        else
            "";
        const message = std.fmt.allocPrint(
            alloc,
            "\"{s}\" is not defined in the matrix of this job{s}",
            .{ key, suffix },
        ) catch return;

        self.list.append(.{
            .rule_id = "EXPR011",
            .severity = .@"error",
            .message = message,
            .span = span,
            .fix_hint = "declare the key under `strategy.matrix:` or one of its `include:` entries",
        }) catch return;
    }
};

/// Only plain identifiers are resolved: a globbed or computed segment
/// (`matrix.*`, `matrix['os']` built at run time) has no literal name.
fn identSegment(segment: ?expr_check.Segment) ?[]const u8 {
    const seg = segment orelse return null;
    return switch (seg) {
        .ident => |name| name,
        .index_string => |name| name,
        .star => null,
    };
}

pub fn checkJob(job: *const Job, list: *DiagnosticList) void {
    // The engine hands rules no arena (#159), so this one owns the memory the
    // expression parser needs and frees it as soon as the job is scanned.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // A dynamic matrix has a `matrix:` key but no readable axes: its keys are
    // unknowable here, so the job is skipped entirely rather than guessed at.
    if (job.strategy) |strategy| {
        if (strategy.matrix_key_present and strategy.matrix == null) return;
    }

    expr_scan.scanJob(Resolver{
        .keys = collectKeys(job, alloc),
        .alloc = alloc,
        .list = list,
    }, job);
}

pub const rules = [_]Rule{
    .{
        .id = "EXPR011",
        .name = "matrix-context",
        .description = "`matrix.<key>` must name a key declared in the job's `strategy.matrix`",
        .severity = .@"error",
        .category = .expression,
        .check_job = &checkJob,
    },
};

const testing = std.testing;

fn diagnose(arena: std.mem.Allocator, source: []const u8, list: *DiagnosticList) !void {
    const wf = try test_support.parseWorkflowSource(arena, source);
    for (wf.jobs) |*job| checkJob(job, list);
}

fn expectNoDiagnostics(source: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();

    try diagnose(arena.allocator(), source, &list);
    if (list.len() != 0) {
        std.debug.print("unexpected diagnostic: {s}\n", .{list.get(0).message});
    }
    try testing.expectEqual(@as(usize, 0), list.len());
}

fn expectMessage(source: []const u8, needle: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();

    try diagnose(arena.allocator(), source, &list);
    for (list.items.items) |diag| {
        if (std.mem.indexOf(u8, diag.message, needle) != null) {
            try testing.expectEqualStrings("EXPR011", diag.rule_id);
            return;
        }
    }
    if (list.len() != 0) {
        std.debug.print("messages did not contain \"{s}\"; first: {s}\n", .{ needle, list.get(0).message });
    }
    return error.MessageNotFound;
}

test "EXPR011: a misspelled axis is reported with a suggestion" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  test:
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest, macos-latest]
        \\    runs-on: ${{ matrix.so }}
        \\    steps:
        \\      - run: echo hi
    , "\"so\" is not defined in the matrix of this job. did you mean \"os\"?");
}

test "EXPR011: an axis absent from the matrix is reported" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix:
        \\        node: [18, 20]
        \\    steps:
        \\      - run: echo "${{ matrix.python }}"
    , "\"python\" is not defined in the matrix of this job");
}

test "EXPR011: a job without a strategy has no matrix context" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ matrix.os }}"
    , "\"matrix\" is not available");
}

test "EXPR011: a strategy without a matrix has no matrix context" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      fail-fast: false
        \\    steps:
        \\      - run: echo "${{ matrix.os }}"
    , "\"matrix\" is not available");
}

test "EXPR011: declared axes and include keys are accepted" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  test:
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest]
        \\        include:
        \\          - os: ubuntu-latest
        \\            experimental: true
        \\    runs-on: ${{ matrix.os }}
        \\    steps:
        \\      - if: matrix.experimental
        \\        run: echo hi
    );
}

test "EXPR011: a dynamic matrix silences the rule" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix: ${{ fromJSON(needs.setup.outputs.matrix) }}
        \\    steps:
        \\      - run: echo "${{ matrix.anything }}"
    );
}

test "EXPR011: matrix keys resolve case-insensitively" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest]
        \\    steps:
        \\      - run: echo "${{ matrix.OS }}"
    );
}

test "EXPR011: a bare matrix reference needs no key but still needs a matrix" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest]
        \\    steps:
        \\      - run: echo "${{ toJSON(matrix) }}"
    );
}

test "EXPR011: env and with values are scanned too" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest]
        \\    steps:
        \\      - uses: actions/setup-node@v4
        \\        with:
        \\          node-version: ${{ matrix.node }}
    , "\"node\" is not defined in the matrix of this job");
}
