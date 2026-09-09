//! EXPR011 — contextual typing of the `matrix` context (issue #87).
//!
//! `matrix.<key>` may only name an axis of the job's `strategy.matrix`, or a
//! key an `include:` entry adds. A job without `strategy.matrix` has no
//! `matrix` context at all. Both need the job, not just the step, so this
//! hangs off `check_job` next to EXPR010.
//!
//! A dynamic matrix (`matrix: ${{ fromJSON(...) }}`) carries keys that are
//! only known at run time, so nothing is reported for such a job.
//!
//! When an axis takes mapping values, the property behind the axis name
//! (`matrix.platform.image`) is resolved too, against the union of the keys its
//! cells — and any `include:` entry for that axis — carry (issue #382).

const std = @import("std");
const engine = @import("engine.zig");
const expr_check = @import("expr_check.zig");
const expr_overlay = @import("expr_overlay.zig");
const expr_scan = @import("expr_scan.zig");
const spans = @import("spans.zig");
const util = @import("../util.zig");
const rename = @import("rename.zig");
const yaml_types = @import("../yaml/types.zig");
const type_validation = @import("../workflow/type_validation.zig");
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

/// One declared matrix key, with what is known about the values behind it.
const Key = struct {
    name: []const u8,
    /// Property names the key's values carry, as the union over every cell.
    props: std.ArrayList([]const u8) = .empty,
    /// True once a value is seen that is not an inspectable mapping — a scalar
    /// axis, an axis built at run time, an expression key. The properties then
    /// cannot be enumerated, so `matrix.<key>.<prop>` stays unchecked.
    unknowable: bool = false,
};

const Keys = struct {
    entries: []Key,
    /// The same names as a flat slice, for `util.didYouMean`.
    names: []const []const u8,

    fn find(self: Keys, name: []const u8) ?*const Key {
        for (self.entries) |*key| {
            if (keyEql(key.name, name)) return key;
        }
        return null;
    }
};

/// Axis names plus every key an `include:` entry adds, deduplicated in source
/// order. `exclude:` entries can only narrow existing axes (SYN019 checks
/// that), so they contribute no names.
fn collectKeys(job: *const Job, alloc: std.mem.Allocator) ?Keys {
    const strategy = job.strategy orelse return null;
    if (!strategy.matrix_key_present) return null;
    const matrix = strategy.matrix orelse return null;

    var keys: std.ArrayList(Key) = .empty;
    for (matrix.axes) |axis| {
        if (!isMetaAxis(axis.name)) {
            const key = upsert(&keys, alloc, axis.name) orelse continue;
            // An axis whose values the parser could not inspect
            // (`os: ${{ fromJSON(...) }}`) still declares its name.
            if (axis.dynamic or axis.values.len == 0) key.unknowable = true;
            for (axis.values) |value| absorb(key, alloc, value);
            continue;
        }
        if (!std.mem.eql(u8, axis.name, "include")) continue;
        for (axis.values) |value| {
            const entry = switch (value) {
                .mapping => |m| m,
                else => continue,
            };
            for (entry.entries) |kv| {
                const key = upsert(&keys, alloc, kv.key.value) orelse continue;
                absorb(key, alloc, kv.value);
            }
        }
    }

    var names: std.ArrayList([]const u8) = .empty;
    for (keys.items) |key| names.append(alloc, key.name) catch return null;
    return .{
        .entries = keys.toOwnedSlice(alloc) catch return null,
        .names = names.toOwnedSlice(alloc) catch return null,
    };
}

/// The existing entry for `name`, or a fresh one appended in source order.
/// Null only when the entry could not be allocated.
fn upsert(keys: *std.ArrayList(Key), alloc: std.mem.Allocator, name: []const u8) ?*Key {
    for (keys.items) |*key| {
        if (keyEql(key.name, name)) return key;
    }
    keys.append(alloc, .{ .name = name }) catch return null;
    return &keys.items[keys.items.len - 1];
}

/// Folds one cell of a key into what is known about its properties. Anything
/// but a mapping — or a mapping whose key is itself an expression — leaves the
/// property set unenumerable.
fn absorb(key: *Key, alloc: std.mem.Allocator, value: yaml_types.Node) void {
    const mapping = switch (value) {
        .mapping => |m| m,
        else => {
            key.unknowable = true;
            return;
        },
    };
    for (mapping.entries) |kv| {
        if (type_validation.containsExpression(kv.key.value)) {
            key.unknowable = true;
            continue;
        }
        appendUnique(&key.props, alloc, kv.key.value);
    }
}

fn appendUnique(keys: *std.ArrayList([]const u8), alloc: std.mem.Allocator, name: []const u8) void {
    for (keys.items) |seen| {
        if (keyEql(seen, name)) return;
    }
    keys.append(alloc, name) catch return;
}

const Resolver = struct {
    /// Declared matrix keys, or null when the job has no `matrix:` at all.
    keys: ?Keys,
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
        const entry = declared.find(key) orelse {
            self.reportUnknownKey(path, key, declared.names, span);
            return;
        };

        // The axis is declared; a property behind it only resolves when every
        // cell is a mapping, so the key set is the union of what they carry.
        if (entry.unknowable or entry.props.items.len == 0) return;
        const prop = identSegment(iter.next()) orelse return;
        for (entry.props.items) |name| {
            if (keyEql(name, prop)) return;
        }
        self.reportUnknownProperty(path, entry, prop, span);
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

    fn reportUnknownKey(
        self: Resolver,
        path: []const u8,
        key: []const u8,
        declared: []const []const u8,
        span: Span,
    ) void {
        const alloc = self.list.fixAllocator();
        const suggestion = util.didYouMean(key, declared);
        const suffix = if (suggestion) |s|
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
            .fix = if (suggestion) |s| rename.pathSegmentFix(self.list, span, path, 1, s) else null,
        }) catch return;
    }

    fn reportUnknownProperty(
        self: Resolver,
        path: []const u8,
        entry: *const Key,
        prop: []const u8,
        span: Span,
    ) void {
        const alloc = self.list.fixAllocator();
        const suggestion = util.didYouMean(prop, entry.props.items);
        const suffix = if (suggestion) |s|
            std.fmt.allocPrint(alloc, ". did you mean \"{s}\"?", .{s}) catch ""
        else
            "";
        const message = std.fmt.allocPrint(
            alloc,
            "\"{s}\" is not defined in the values of matrix key \"{s}\"{s}",
            .{ prop, entry.name, suffix },
        ) catch return;

        self.list.append(.{
            .rule_id = "EXPR011",
            .severity = .@"error",
            .message = message,
            .span = span,
            .fix_hint = "declare the property in every value of the axis, or in one of its `include:` entries",
            .fix = if (suggestion) |s| rename.pathSegmentFix(self.list, span, path, 2, s) else null,
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
    // Scratch for the expression parser: no diagnostic points at it, and
    // the list's allocator keeps it under the run's leak detection (#159).
    var arena = std.heap.ArenaAllocator.init(list.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // A dynamic matrix carries keys that only exist at run time, so the job is
    // skipped entirely rather than guessed at.
    if (expr_overlay.hasUnknowableKeys(job)) return;

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
        if (std.mem.find(u8, diag.message, needle) != null) {
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

test "EXPR011: a dynamic include silences the rule for the whole job" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest]
        \\        include: ${{ fromJSON(needs.setup.outputs.matrix) }}
        \\    steps:
        \\      - run: echo "${{ matrix.runner }}"
    );
}

test "EXPR011: an include entry built by an expression silences the rule" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest]
        \\        include:
        \\          - ${{ fromJSON(needs.setup.outputs.entry) }}
        \\    steps:
        \\      - run: echo "${{ matrix.runner }}"
    );
}

test "EXPR011: a dynamic exclude leaves the declared keys checkable" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest]
        \\        exclude: ${{ fromJSON(needs.setup.outputs.skip) }}
        \\    steps:
        \\      - run: echo "${{ matrix.arch }}"
    ,
        "\"arch\" is not defined in the matrix of this job",
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

test "EXPR011: a property missing from every cell of an object axis is reported" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix:
        \\        platform:
        \\          - target: x86_64-unknown-linux-gnu
        \\            arch: x64
        \\    steps:
        \\      - run: echo "${{ matrix.platform.image }}"
    , "\"image\" is not defined in the values of matrix key \"platform\"");
}

test "EXPR011: a misspelled property is reported with a suggestion" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix:
        \\        platform:
        \\          - target: x86_64-unknown-linux-gnu
        \\            arch: x64
        \\    steps:
        \\      - run: echo "${{ matrix.platform.ach }}"
    , "\"ach\" is not defined in the values of matrix key \"platform\". did you mean \"arch\"?");
}

test "EXPR011: object-axis properties are the union over the cells and include" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix:
        \\        platform:
        \\          - target: x86_64-unknown-linux-gnu
        \\            arch: x64
        \\          - target: aarch64-apple-darwin
        \\            sdk: macosx
        \\        include:
        \\          - platform:
        \\              target: wasm32
        \\              image: scratch
        \\    steps:
        \\      - run: echo "${{ matrix.platform.arch }} ${{ matrix.platform.sdk }} ${{ matrix.platform.image }}"
    );
}

test "EXPR011: a scalar axis leaves its properties unchecked" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest]
        \\    steps:
        \\      - run: echo "${{ matrix.os.anything }}"
    );
}

test "EXPR011: an axis with a cell built by an expression stays silent" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix:
        \\        platform:
        \\          - target: x86_64-unknown-linux-gnu
        \\            arch: x64
        \\          - ${{ fromJSON(vars.EXTRA_PLATFORM) }}
        \\    steps:
        \\      - run: echo "${{ matrix.platform.image }}"
    );
}

test "EXPR011: a nested property one level deeper is not resolved" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix:
        \\        platform:
        \\          - toolchain:
        \\              rust: stable
        \\    steps:
        \\      - run: echo "${{ matrix.platform.toolchain.cargo }}"
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
