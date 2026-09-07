//! T4 (#129): builds the per-workflow contextual overlays that `expr_check`
//! layers over the builtin catalog, so `typeOf` sees the workflow's own
//! `steps` / `matrix` / `needs` / `inputs` / `secrets` instead of a loose
//! object. See `docs/design/expr-static-typecheck-design.md` §4.
//!
//! Every overlay is built `strict`, which is what makes property types
//! resolve. Existence is deliberately *not* this module's business: an unknown
//! key under an overlay stays silent in the walker and is reported by
//! EXPR010-EXPR014, which own those diagnostics and their spans.
//!
//! Allocation failure is never fatal: a builder that cannot allocate returns
//! null, and the context falls back to the loose catalog entry.

const std = @import("std");
const t = @import("expr_type.zig");
const yaml_types = @import("../yaml/types.zig");
const workflow_types = @import("../workflow/types.zig");

const Type = t.Type;
const TypeRef = t.TypeRef;
const Prop = t.Prop;
const Job = workflow_types.Job;
const Step = workflow_types.Step;
const Workflow = workflow_types.Workflow;

const string = &t.type_string;
const any = &t.type_any;

/// Every step exposes the same three properties, so the shape is a shared
/// constant and only the id list is built per job. `outputs` is loose because
/// an action's output names are not knowable from the workflow file.
const step_result: Type = .{
    .kind = .object,
    .shape = .strict,
    .props = &.{
        .{ .name = "conclusion", .ty = string },
        .{ .name = "outcome", .ty = string },
        .{ .name = "outputs", .ty = &t.type_loose_object },
    },
};

/// A job whose `outputs:` this workflow cannot see: `result` is still known.
const opaque_need: Type = .{
    .kind = .object,
    .shape = .strict,
    .props = &.{
        .{ .name = "outputs", .ty = &t.type_loose_object },
        .{ .name = "result", .ty = string },
    },
};

fn strictObject(alloc: std.mem.Allocator, props: []const Prop) ?TypeRef {
    const ty = alloc.create(Type) catch return null;
    ty.* = .{ .kind = .object, .shape = .strict, .props = props };
    return ty;
}

/// Later duplicates lose: a repeated key keeps the first type seen, matching
/// the source-order dedup the EXPR010-EXPR014 collectors already do.
const PropList = struct {
    items: std.ArrayList(Prop) = .empty,
    alloc: std.mem.Allocator,

    fn put(self: *PropList, name: []const u8, ty: TypeRef) void {
        for (self.items.items) |existing| {
            if (std.ascii.eqlIgnoreCase(existing.name, name)) return;
        }
        self.items.append(self.alloc, .{ .name = name, .ty = ty }) catch return;
    }

    /// Merges into an existing key instead of dropping it, for overlays whose
    /// value type is a union over several declarations (`matrix`).
    fn merge(self: *PropList, name: []const u8, ty: TypeRef) void {
        for (self.items.items) |*existing| {
            if (std.ascii.eqlIgnoreCase(existing.name, name)) {
                existing.ty = t.merge(existing.ty, ty);
                return;
            }
        }
        self.items.append(self.alloc, .{ .name = name, .ty = ty }) catch return;
    }

    fn finish(self: *PropList) ?[]const Prop {
        return self.items.toOwnedSlice(self.alloc) catch null;
    }
};

/// `steps` as seen from `steps[index]`: only ids declared earlier in the same
/// job are in scope, which is what EXPR010 checks too.
pub fn buildSteps(alloc: std.mem.Allocator, steps: []const Step, index: usize) ?TypeRef {
    var props = PropList{ .alloc = alloc };
    for (steps[0..@min(index, steps.len)]) |step| {
        const id = step.id orelse continue;
        if (id.len == 0) continue;
        props.put(id, &step_result);
    }
    return strictObject(alloc, props.finish() orelse return null);
}

/// `include` and `exclude` are matrix keys in the YAML but not axes: the names
/// they carry live one level down, inside each entry.
fn isMetaAxis(name: []const u8) bool {
    return std.mem.eql(u8, name, "include") or std.mem.eql(u8, name, "exclude");
}

/// Null when the job has no usable `strategy.matrix`, including the dynamic
/// form (`matrix: ${{ fromJSON(...) }}`) whose keys are unknowable here.
pub fn buildMatrix(alloc: std.mem.Allocator, job: *const Job) ?TypeRef {
    const strategy = job.strategy orelse return null;
    if (!strategy.matrix_key_present) return null;
    const matrix = strategy.matrix orelse return null;

    var props = PropList{ .alloc = alloc };
    for (matrix.axes) |axis| {
        if (!isMetaAxis(axis.name)) {
            props.merge(axis.name, elementType(axis.values));
            continue;
        }
        // `exclude:` can only narrow existing axes, so it contributes no keys.
        if (!std.mem.eql(u8, axis.name, "include")) continue;
        for (axis.values) |value| {
            const entry = switch (value) {
                .mapping => |m| m,
                else => continue,
            };
            for (entry.entries) |kv| props.merge(kv.key.value, nodeType(kv.value));
        }
    }
    return strictObject(alloc, props.finish() orelse return null);
}

/// The union of the values an axis can take. An axis with no inspectable
/// values (`os: ${{ fromJSON(...) }}`) is `any`.
fn elementType(values: []const yaml_types.Node) TypeRef {
    var merged: ?TypeRef = null;
    for (values) |value| {
        const ty = nodeType(value);
        merged = if (merged) |m| t.merge(m, ty) else ty;
    }
    return merged orelse any;
}

/// A quoted scalar is a string whatever it spells; a plain one takes the type
/// its literal form implies, the same way YAML resolves it.
fn nodeType(node: yaml_types.Node) TypeRef {
    return switch (node) {
        .null_value => &t.type_null,
        .sequence => |seq| blk: {
            var merged: ?TypeRef = null;
            for (seq.items) |item| {
                const ty = nodeType(item);
                merged = if (merged) |m| t.merge(m, ty) else ty;
            }
            const elem = merged orelse any;
            if (elem == string) break :blk &t.type_array_string;
            break :blk &t.type_array_any;
        },
        // Matrix values that are mappings expose keys zghalint does not model.
        .mapping => &t.type_loose_object,
        .scalar => |scalar| switch (scalar.style) {
            .single_quoted, .double_quoted => string,
            else => scalarType(scalar.value),
        },
    };
}

fn scalarType(text: []const u8) TypeRef {
    if (text.len == 0) return &t.type_null;
    if (std.mem.eql(u8, text, "null") or std.mem.eql(u8, text, "~")) return &t.type_null;
    if (std.mem.eql(u8, text, "true") or std.mem.eql(u8, text, "false")) return &t.type_bool;
    // An expression is whatever it evaluates to at run time.
    if (std.mem.indexOf(u8, text, "${{") != null) return any;
    if (std.fmt.parseFloat(f64, text)) |_| return &t.type_number else |_| {}
    return string;
}

/// `needs` as seen from one job: only the jobs it declares, each with the
/// outputs that job's `outputs:` mapping names.
pub fn buildNeeds(alloc: std.mem.Allocator, wf: *const Workflow, job: *const Job) ?TypeRef {
    if (job.needs.len == 0) return null;

    var props = PropList{ .alloc = alloc };
    for (job.needs) |need| {
        props.put(need, needType(alloc, wf, need) orelse &opaque_need);
    }
    return strictObject(alloc, props.finish() orelse return null);
}

/// Null when the named job is absent (EXPR012's finding) or declares no
/// outputs, so `<job>.outputs.<name>` keeps resolving to `any`.
fn needType(alloc: std.mem.Allocator, wf: *const Workflow, name: []const u8) ?TypeRef {
    for (wf.jobs) |*candidate| {
        if (!std.mem.eql(u8, candidate.id, name)) continue;
        if (candidate.outputs.len == 0) return null;

        var outputs = PropList{ .alloc = alloc };
        for (candidate.outputs) |output| outputs.put(output.name, string);
        const outputs_ty = strictObject(alloc, outputs.finish() orelse return null) orelse return null;

        // The prop slice outlives this frame, so it has to come from the arena
        // rather than from an anonymous array literal.
        var props = PropList{ .alloc = alloc };
        props.put("outputs", outputs_ty);
        props.put("result", string);
        return strictObject(alloc, props.finish() orelse return null);
    }
    return null;
}

/// The union of `workflow_dispatch` and `workflow_call` inputs, which is the
/// same set EXPR013 resolves against.
pub fn buildInputs(alloc: std.mem.Allocator, wf: *const Workflow) ?TypeRef {
    var props = PropList{ .alloc = alloc };
    var declared = false;

    for (wf.on.events) |event| {
        switch (event.event) {
            .workflow_call => {
                if (event.workflow_call_inputs.len == 0) continue;
                declared = true;
                for (event.workflow_call_inputs) |input| {
                    props.merge(input.name, callableInputType(input.input_type));
                }
            },
            .workflow_dispatch => {
                if (event.workflow_dispatch_inputs.len == 0) continue;
                declared = true;
                for (event.workflow_dispatch_inputs) |input| {
                    props.merge(input.name, dispatchInputType(input.input_type));
                }
            },
            else => {},
        }
    }
    if (!declared) return null;
    return strictObject(alloc, props.finish() orelse return null);
}

/// An absent `type:` defaults to string on `workflow_call`.
fn callableInputType(kind: ?workflow_types.CallableInputType) TypeRef {
    return switch (kind orelse return string) {
        .string => string,
        .number => &t.type_number,
        .boolean => &t.type_bool,
    };
}

/// `choice` and `environment` both hand the job a string; an absent `type:`
/// defaults to string as well.
fn dispatchInputType(kind: ?workflow_types.DispatchInputType) TypeRef {
    return switch (kind orelse return string) {
        .string, .choice, .environment => string,
        .number => &t.type_number,
        .boolean => &t.type_bool,
    };
}

/// Always present, whatever `workflow_call.secrets` declares.
const builtin_secrets = [_][]const u8{"GITHUB_TOKEN"};

/// Only a reusable workflow that declares `on.workflow_call.secrets` has a
/// closed secret set; everywhere else the repository or organization can
/// supply any name, so the context stays the catalog's string map. That is the
/// same restriction EXPR014 applies.
pub fn buildSecrets(alloc: std.mem.Allocator, wf: *const Workflow) ?TypeRef {
    var props = PropList{ .alloc = alloc };
    var declared = false;

    for (wf.on.events) |event| {
        if (event.event != .workflow_call) continue;
        if (event.workflow_call_secrets.len == 0) continue;
        declared = true;
        for (event.workflow_call_secrets) |secret| props.put(secret.name, string);
    }
    if (!declared) return null;

    for (builtin_secrets) |name| props.put(name, string);
    return strictObject(alloc, props.finish() orelse return null);
}

const testing = std.testing;
const test_support = @import("../test_support.zig");
const expr_check = @import("expr_check.zig");

fn parse(arena: std.mem.Allocator, source: []const u8) !Workflow {
    return test_support.parseWorkflowSource(arena, source);
}

fn expectKind(env: *const expr_check.TypeEnv, path: []const u8, kind: t.TypeKind) !void {
    const result = expr_check.walkPath(path, env);
    try testing.expectEqual(@as(?expr_check.Problem, null), result.problem);
    try testing.expectEqual(kind, result.ty.kind);
}

test "overlay: steps sees only ids declared earlier" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const wf = try parse(alloc,
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - id: setup
        \\        run: echo hi
        \\      - id: later
        \\        run: echo hi
    );
    const steps = wf.jobs[0].steps;

    const at_first = expr_check.TypeEnv{ .steps = buildSteps(alloc, steps, 0) };
    try testing.expectEqual(@as(usize, 0), at_first.steps.?.props.len);

    const at_second = expr_check.TypeEnv{ .steps = buildSteps(alloc, steps, 1) };
    try testing.expectEqual(@as(usize, 1), at_second.steps.?.props.len);
    try expectKind(&at_second, "steps.setup.outcome", .string);
    try expectKind(&at_second, "steps.setup.outputs.anything", .any);
    // A step declared later is EXPR010's finding, not a type problem.
    try expectKind(&at_second, "steps.later.outcome", .any);
}

test "overlay: matrix axis values decide the key type" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const wf = try parse(alloc,
        \\on: push
        \\jobs:
        \\  test:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix:
        \\        os: [ubuntu-latest, macos-latest]
        \\        node: [18, 20]
        \\        mixed: [1, two]
        \\        include:
        \\          - os: ubuntu-latest
        \\            experimental: true
        \\    steps:
        \\      - run: echo hi
    );
    const env = expr_check.TypeEnv{ .matrix = buildMatrix(alloc, &wf.jobs[0]) };

    try expectKind(&env, "matrix.os", .string);
    try expectKind(&env, "matrix.node", .number);
    try expectKind(&env, "matrix.mixed", .any);
    try expectKind(&env, "matrix.experimental", .bool);
    // Keys resolve case-insensitively, like every other context.
    try expectKind(&env, "matrix.OS", .string);
    // An undeclared key is EXPR011's finding.
    try expectKind(&env, "matrix.python", .any);
}

test "overlay: a job without a usable matrix gets none" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const wf = try parse(alloc,
        \\on: push
        \\jobs:
        \\  plain:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\  dynamic:
        \\    runs-on: ubuntu-latest
        \\    strategy:
        \\      matrix: ${{ fromJSON(needs.setup.outputs.matrix) }}
        \\    steps:
        \\      - run: echo hi
    );
    try testing.expectEqual(@as(?TypeRef, null), buildMatrix(alloc, &wf.jobs[0]));
    try testing.expectEqual(@as(?TypeRef, null), buildMatrix(alloc, &wf.jobs[1]));
}

test "overlay: needs carries the target job's outputs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const wf = try parse(alloc,
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    outputs:
        \\      version: ${{ steps.v.outputs.value }}
        \\    steps:
        \\      - id: v
        \\        run: echo hi
        \\  deploy:
        \\    runs-on: ubuntu-latest
        \\    needs: build
        \\    steps:
        \\      - run: echo hi
    );
    const env = expr_check.TypeEnv{ .needs = buildNeeds(alloc, &wf, &wf.jobs[1]) };

    try expectKind(&env, "needs.build.result", .string);
    try expectKind(&env, "needs.build.outputs.version", .string);
    // Undeclared names are EXPR012's finding.
    try expectKind(&env, "needs.build.outputs.missing", .any);
    try expectKind(&env, "needs.other.result", .any);
    try testing.expectEqual(@as(?TypeRef, null), buildNeeds(alloc, &wf, &wf.jobs[0]));
}

test "overlay: inputs reflect the declared type" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const wf = try parse(alloc,
        \\on:
        \\  workflow_call:
        \\    inputs:
        \\      version:
        \\        type: string
        \\      retries:
        \\        type: number
        \\  workflow_dispatch:
        \\    inputs:
        \\      dry_run:
        \\        type: boolean
        \\      environment:
        \\        type: choice
        \\        options: [staging, prod]
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    );
    const env = expr_check.TypeEnv{ .inputs = buildInputs(alloc, &wf) };

    try expectKind(&env, "inputs.version", .string);
    try expectKind(&env, "inputs.retries", .number);
    try expectKind(&env, "inputs.dry_run", .bool);
    try expectKind(&env, "inputs.environment", .string);
    // Undeclared names are EXPR013's finding.
    try expectKind(&env, "inputs.nope", .any);
}

test "overlay: inputs are absent without a declaration" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const wf = try parse(alloc,
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    );
    try testing.expectEqual(@as(?TypeRef, null), buildInputs(alloc, &wf));
    try testing.expectEqual(@as(?TypeRef, null), buildSecrets(alloc, &wf));
}

test "overlay: secrets only close over a workflow_call declaration" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const wf = try parse(alloc,
        \\on:
        \\  workflow_call:
        \\    secrets:
        \\      npm_token:
        \\        required: true
        \\jobs:
        \\  publish:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    );
    const env = expr_check.TypeEnv{ .secrets = buildSecrets(alloc, &wf) };

    try expectKind(&env, "secrets.npm_token", .string);
    try expectKind(&env, "secrets.GITHUB_TOKEN", .string);
    // Undeclared names are EXPR014's finding.
    try expectKind(&env, "secrets.OTHER", .any);
}
