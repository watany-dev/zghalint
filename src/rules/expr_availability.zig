//! EXPR015 / EXPR016 — where a context or a special function may be used
//! (#91, #92).
//!
//! GitHub evaluates each workflow key at a different point of a run, so each
//! key exposes a different set of contexts: `runs-on` is resolved before any
//! secret is available, a job-level `if:` before the matrix is expanded into a
//! `strategy`, and the status functions have no job status to report outside
//! an `if:`. The other expression rules ask whether a *reference* resolves;
//! this one asks whether the key it sits under offers it at all.
//!
//! The tables below follow the "Contexts and available contexts" and "Special
//! functions" sections of the GitHub Actions expression docs, which are also
//! actionlint's source. Only keys whose scalars the parser already models are
//! listed — `on.*`, `environment.url` and `container.*` carry no expression
//! spans yet, so they are simply not scanned.

const std = @import("std");
const engine = @import("engine.zig");
const catalog = @import("expr_catalog.zig");
const expr_check = @import("expr_check.zig");
const expr_scan = @import("expr_scan.zig");
const spans = @import("spans.zig");
const test_support = @import("../test_support.zig");

const Rule = engine.Rule;
const Workflow = engine.Workflow;
const Step = engine.Step;
const DiagnosticList = engine.DiagnosticList;
const Anchor = spans.Anchor;
const Span = spans.Span;

/// Everything a step sees: by the time a step runs, the job, the runner and
/// the earlier steps all exist.
const step_contexts: []const []const u8 = &.{
    "github", "needs", "strategy", "matrix", "job",    "runner",
    "env",    "vars",  "secrets",  "steps",  "inputs",
};

/// Job-level keys evaluated once the matrix is expanded but before the job
/// starts, so `job`, `runner`, `env` and `steps` are still empty.
const job_expanded_contexts: []const []const u8 = &.{
    "github", "needs", "strategy", "matrix", "vars", "inputs",
};

/// A workflow key that can hold a `${{ }}` expression. Which contexts and
/// special functions the expression may use depends only on this.
const Key = enum {
    workflow_env,
    workflow_concurrency,
    job_if,
    job_env,
    job_runs_on,
    job_concurrency,
    job_with,
    step_if,
    step_name,
    step_run,
    step_with,
    step_env,

    fn label(self: Key) []const u8 {
        return switch (self) {
            .workflow_env => "env",
            .workflow_concurrency => "concurrency",
            .job_if => "jobs.<job_id>.if",
            .job_env => "jobs.<job_id>.env",
            .job_runs_on => "jobs.<job_id>.runs-on",
            .job_concurrency => "jobs.<job_id>.concurrency",
            .job_with => "jobs.<job_id>.with",
            .step_if => "jobs.<job_id>.steps.*.if",
            .step_name => "jobs.<job_id>.steps.*.name",
            .step_run => "jobs.<job_id>.steps.*.run",
            .step_with => "jobs.<job_id>.steps.*.with",
            .step_env => "jobs.<job_id>.steps.*.env",
        };
    }

    fn contexts(self: Key) []const []const u8 {
        return switch (self) {
            // The workflow's own `env:` is resolved before any job, so nothing
            // job-shaped exists yet.
            .workflow_env => &.{ "github", "secrets", "vars", "inputs" },
            .workflow_concurrency => &.{ "github", "vars", "inputs" },
            // A job's `if:` decides whether the job is expanded at all, so the
            // matrix it would be expanded with is not available to it.
            .job_if => &.{ "github", "needs", "vars", "inputs" },
            .job_env => &.{ "github", "needs", "strategy", "matrix", "secrets", "vars", "inputs" },
            .job_runs_on, .job_concurrency, .job_with => job_expanded_contexts,
            .step_if, .step_name, .step_run, .step_with, .step_env => step_contexts,
        };
    }

    /// `success()` / `failure()` / `always()` / `cancelled()` report the status
    /// of what has run so far, which only a condition can act on.
    fn allowsStatusFunctions(self: Key) bool {
        return self == .job_if or self == .step_if;
    }

    fn allowsHashFiles(self: Key) bool {
        return switch (self) {
            .job_env, .step_if, .step_name, .step_run, .step_with, .step_env => true,
            else => false,
        };
    }
};

fn isStatusFunction(name: []const u8) bool {
    for ([_][]const u8{ "success", "failure", "always", "cancelled" }) |candidate| {
        if (std.ascii.eqlIgnoreCase(name, candidate)) return true;
    }
    return false;
}

/// `"github", "needs", "vars"` — the tail of a message listing what is allowed.
fn quotedList(alloc: std.mem.Allocator, names: []const []const u8) []const u8 {
    var buf: std.ArrayList(u8) = .empty;
    for (names, 0..) |name, i| {
        if (i != 0) buf.appendSlice(alloc, ", ") catch return "";
        buf.append(alloc, '"') catch return "";
        buf.appendSlice(alloc, name) catch return "";
        buf.append(alloc, '"') catch return "";
    }
    return buf.items;
}

const ContextVisitor = struct {
    key: Key,
    /// Backs the expression parse trees; diagnostic messages are allocated
    /// from the list's own arena instead.
    alloc: std.mem.Allocator,
    list: *DiagnosticList,

    pub fn checkPath(self: ContextVisitor, path: []const u8, span: Span) void {
        var iter = expr_check.SegmentIter{ .path = path };
        const root = switch (iter.next() orelse return) {
            .ident => |name| name,
            .star, .index_string => return,
        };
        // A context nobody knows is EXPR002's finding, not this rule's.
        // Context names are case-insensitive on GitHub, and `lookupContext` is
        // not, so the name is normalized before either comparison.
        const known = catalog.contextName(root) orelse return;

        const allowed = self.key.contexts();
        for (allowed) |name| {
            if (std.mem.eql(u8, name, known)) return;
        }

        const alloc = self.list.fixAllocator();
        const message = std.fmt.allocPrint(
            alloc,
            "context \"{s}\" is not available in \"{s}\". available contexts are {s}",
            .{ known, self.key.label(), quotedList(alloc, allowed) },
        ) catch return;
        self.list.append(.{
            .rule_id = "EXPR015",
            .severity = .@"error",
            .message = message,
            .span = span,
            .fix_hint = "move the expression to a key that provides this context",
        }) catch return;
    }
};

const FunctionVisitor = struct {
    key: Key,
    alloc: std.mem.Allocator,
    list: *DiagnosticList,

    pub fn checkCall(self: FunctionVisitor, name: []const u8, span: Span) void {
        const hint = if (isStatusFunction(name)) blk: {
            if (self.key.allowsStatusFunctions()) return;
            break :blk "status functions are only available in `if:`";
        } else if (std.ascii.eqlIgnoreCase(name, "hashFiles")) blk: {
            if (self.key.allowsHashFiles()) return;
            break :blk "hashFiles() is available in a job's `env:` and in a step's `if:`, `name:`, `run:`, `with:` and `env:`";
        } else return;

        const alloc = self.list.fixAllocator();
        const message = std.fmt.allocPrint(
            alloc,
            "function \"{s}()\" is not available in \"{s}\"",
            .{ name, self.key.label() },
        ) catch return;
        self.list.append(.{
            .rule_id = "EXPR016",
            .severity = .@"error",
            .message = message,
            .span = span,
            .fix_hint = hint,
        }) catch return;
    }
};

fn visitor(comptime Visitor: type, key: Key, alloc: std.mem.Allocator, list: *DiagnosticList) Visitor {
    return .{ .key = key, .alloc = alloc, .list = list };
}

/// One traversal per rule: EXPR015 and EXPR016 are registered separately, and
/// a visitor without the matching hook walks the same tree for free.
fn scanWorkflow(comptime Visitor: type, wf: *const Workflow, list: *DiagnosticList) void {
    // Scratch for the expression parser: no diagnostic points at it, and
    // the list's allocator keeps it under the run's leak detection (#159).
    var arena = std.heap.ArenaAllocator.init(list.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const head = spans.workflow_head;
    expr_scan.scanScalarMap(visitor(Visitor, .workflow_env, alloc, list), wf.env, wf.env_meta, head);
    if (wf.concurrency) |c| {
        const v = visitor(Visitor, .workflow_concurrency, alloc, list);
        expr_scan.scanText(v, c.group, Anchor.fromMeta(c.group_meta, head));
    }

    for (wf.jobs) |*job| {
        expr_scan.scanCondition(
            visitor(Visitor, .job_if, alloc, list),
            job.if_condition,
            job.if_condition_meta,
            job.span,
        );
        expr_scan.scanScalarMap(visitor(Visitor, .job_env, alloc, list), job.env, job.env_meta, job.span);
        // A job-level `with:` feeds a reusable workflow call; the parser keeps
        // no per-entry spans for it, so the job span anchors those findings.
        expr_scan.scanScalarMap(visitor(Visitor, .job_with, alloc, list), job.with, null, job.span);
        if (job.runs_on) |runs_on| {
            const v = visitor(Visitor, .job_runs_on, alloc, list);
            expr_scan.scanText(v, runs_on, expr_scan.runsOnAnchor(job));
        } else {
            // A sequence `runs-on:` or a runner-group mapping leaves the
            // scalar unset, and each label carries its own span.
            const v = visitor(Visitor, .job_runs_on, alloc, list);
            for (job.runs_on_labels, job.runs_on_label_spans) |label, span| {
                expr_scan.scanText(v, label, Anchor{ .fallback = span });
            }
        }
        if (job.concurrency) |c| {
            const v = visitor(Visitor, .job_concurrency, alloc, list);
            expr_scan.scanText(v, c.group, Anchor.fromMeta(c.group_meta, job.span));
        }

        for (job.steps) |*step| {
            scanStepAvailability(Visitor, alloc, list, step);
        }
    }
}

fn scanStepAvailability(comptime Visitor: type, alloc: std.mem.Allocator, list: *DiagnosticList, step: *const Step) void {
    expr_scan.scanCondition(
        visitor(Visitor, .step_if, alloc, list),
        step.if_condition,
        step.if_condition_meta,
        step.span,
    );
    if (step.run) |run_val| {
        const v = visitor(Visitor, .step_run, alloc, list);
        expr_scan.scanText(v, run_val, spans.runAnchor(step));
    }
    if (step.name) |name| {
        const v = visitor(Visitor, .step_name, alloc, list);
        expr_scan.scanText(v, name, Anchor.fromMeta(step.name_meta, step.span));
    }
    expr_scan.scanScalarMap(visitor(Visitor, .step_with, alloc, list), step.with, step.with_meta, step.span);
    expr_scan.scanScalarMap(visitor(Visitor, .step_env, alloc, list), step.env, step.env_meta, step.span);
    for (step.nestedSteps()) |*child| scanStepAvailability(Visitor, alloc, list, child);
}

fn checkContexts(wf: *const Workflow, list: *DiagnosticList) void {
    scanWorkflow(ContextVisitor, wf, list);
}

fn checkFunctions(wf: *const Workflow, list: *DiagnosticList) void {
    scanWorkflow(FunctionVisitor, wf, list);
}

pub const rules = [_]Rule{
    .{
        .id = "EXPR015",
        .name = "context-availability",
        .description = "A context must be one the workflow key it appears under provides",
        .severity = .@"error",
        .category = .expression,
        .check_workflow = &checkContexts,
    },
    .{
        .id = "EXPR016",
        .name = "function-availability",
        .description = "Status functions are only available in `if:`, and `hashFiles()` only in step and job keys",
        .severity = .@"error",
        .category = .expression,
        .check_workflow = &checkFunctions,
    },
};

const testing = std.testing;

fn checkAvailability(wf: *const Workflow, list: *DiagnosticList) void {
    checkContexts(wf, list);
    checkFunctions(wf, list);
}

const availability_check: test_support.Check = .{ .workflow = &checkAvailability };

fn expectMessage(source: []const u8, rule_id: []const u8, needle: []const u8) !void {
    try test_support.expectMessage(source, availability_check, rule_id, needle);
}

fn expectNoDiagnostics(source: []const u8) !void {
    try test_support.expectNoDiagnostics(source, availability_check);
}

test "EXPR015: secrets is not available in runs-on" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ${{ secrets.RUNNER_LABEL }}
        \\    steps:
        \\      - run: echo hi
    ,
        "EXPR015",
        "context \"secrets\" is not available in \"jobs.<job_id>.runs-on\"",
    );
}

test "EXPR015: the message lists the contexts the key does provide" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    if: steps.setup.outcome == 'success'
        \\    steps:
        \\      - run: echo hi
    ,
        "EXPR015",
        "available contexts are \"github\", \"needs\", \"vars\", \"inputs\"",
    );
}

test "EXPR015: steps is not available in a workflow-level concurrency group" {
    try expectMessage(
        \\on: push
        \\concurrency: ${{ github.ref }}-${{ steps.foo.outputs.x }}
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    ,
        "EXPR015",
        "context \"steps\" is not available in \"concurrency\"",
    );
}

test "EXPR015: secrets is available in the workflow-level env" {
    try expectNoDiagnostics(
        \\on: push
        \\env:
        \\  TOKEN: ${{ secrets.GITHUB_TOKEN }}
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
    );
}

test "EXPR015: the job contexts a matrix job legitimately uses stay silent" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ${{ matrix.os }}
        \\    if: github.event_name == 'push'
        \\    steps:
        \\      - if: steps.setup.outcome == 'success'
        \\        run: echo "${{ runner.os }} ${{ job.status }}"
    );
}

test "EXPR015: an unknown context is left to EXPR002" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ${{ nonsense.value }}
        \\    steps:
        \\      - run: echo hi
    );
}

test "EXPR016: a status function outside if: is reported" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ success() }}"
    ,
        "EXPR016",
        "function \"success()\" is not available in \"jobs.<job_id>.steps.*.run\"",
    );
}

test "EXPR016: a status function in a step name is reported" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - name: "${{ always() }}"
        \\        run: echo hi
    ,
        "EXPR016",
        "function \"always()\" is not available in \"jobs.<job_id>.steps.*.name\"",
    );
}

test "EXPR016: hashFiles is not available in a concurrency group" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    concurrency: ${{ hashFiles('**/*.zig') }}
        \\    steps:
        \\      - run: echo hi
    ,
        "EXPR016",
        "function \"hashFiles()\" is not available in \"jobs.<job_id>.concurrency\"",
    );
}

test "EXPR016: status functions and hashFiles in the keys that offer them" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    if: success()
        \\    steps:
        \\      - if: always() && steps.setup.outcome == 'success'
        \\        run: echo hi
        \\      - uses: actions/cache@v4
        \\        with:
        \\          key: ${{ runner.os }}-${{ hashFiles('**/build.zig.zon') }}
    );
}

test "EXPR016: a status function nested in a condition is still located" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo "${{ format('{0}', cancelled()) }}"
    ,
        "EXPR016",
        "function \"cancelled()\" is not available",
    );
}

test "EXPR016: an ordinary function is available everywhere" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ${{ format('{0}-latest', 'ubuntu') }}
        \\    steps:
        \\      - run: echo hi
    );
}

test "EXPR015: an uppercase context name resolves to the same rule" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ${{ SECRETS.RUNNER_LABEL }}
        \\    steps:
        \\      - run: echo hi
    ,
        "EXPR015",
        "context \"secrets\" is not available in \"jobs.<job_id>.runs-on\"",
    );
}

test "EXPR015: a sequence runs-on is scanned label by label" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: [self-hosted, "${{ secrets.RUNNER_LABEL }}"]
        \\    steps:
        \\      - run: echo hi
    ,
        "EXPR015",
        "context \"secrets\" is not available in \"jobs.<job_id>.runs-on\"",
    );
}

test "EXPR015: a job env may read secrets but not steps" {
    try expectNoDiagnostics(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    env:
        \\      TOKEN: ${{ secrets.GITHUB_TOKEN }}
        \\      LOCK: ${{ hashFiles('**/build.zig.zon') }}
        \\    steps:
        \\      - run: echo hi
    );
    try expectMessage(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    env:
        \\      READY: ${{ steps.setup.outputs.ready }}
        \\    steps:
        \\      - run: echo hi
    ,
        "EXPR015",
        "context \"steps\" is not available in \"jobs.<job_id>.env\"",
    );
}

test "EXPR016: a status function in a step env is reported" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  build:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo hi
        \\        env:
        \\          OK: ${{ success() }}
    ,
        "EXPR016",
        "function \"success()\" is not available in \"jobs.<job_id>.steps.*.env\"",
    );
}

test "EXPR015: a reusable workflow call's with: is a job-level key" {
    try expectMessage(
        \\on: push
        \\jobs:
        \\  call:
        \\    uses: ./.github/workflows/reusable.yml
        \\    with:
        \\      token: ${{ secrets.NPM_TOKEN }}
    ,
        "EXPR015",
        "context \"secrets\" is not available in \"jobs.<job_id>.with\"",
    );
}
