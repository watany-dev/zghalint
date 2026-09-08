//! #254: run the workflow step rules over a composite action's `runs.steps`.
//!
//! `action_metadata.zig` checks the shape of `runs:`; the steps underneath it
//! are ordinary GitHub Actions steps and deserve the same scrutiny as the ones
//! in a workflow. They never pass through `parseWorkflow`, so each mapping is
//! parsed on its own (`parser.parseStandaloneStep`) and handed to a selected
//! set of `check_step` functions.
//!
//! Two things make a composite step different from a workflow step, and both
//! are handled here rather than inside the shared rules:
//!
//!   * `shell:` is mandatory on `run:` — there is no runner default and no
//!     `defaults.run` to fall back on.
//!   * the context set is narrower. `inputs` means the action's own `inputs:`,
//!     and `matrix` / `needs` / `secrets` / `strategy` do not exist at all.
//!     ACT005 reports both halves of that.

const std = @import("std");
const engine = @import("engine.zig");
const best_practices = @import("best_practices.zig");
const security = @import("security.zig");
const uses_rules = @import("uses.zig");
const local_action = @import("local_action.zig");
const popular_actions = @import("popular_actions.zig");
const expressions = @import("expressions.zig");
const expr_check = @import("expr_check.zig");
const expr_overlay = @import("expr_overlay.zig");
const expr_scan = @import("expr_scan.zig");
const parser = @import("../workflow/parser.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml_types = @import("../yaml/types.zig");
const util = @import("../util.zig");
const rename = @import("rename.zig");

const Rule = engine.Rule;
const DiagnosticList = engine.DiagnosticList;
const Step = workflow_types.Step;
const Node = yaml_types.Node;
const Mapping = yaml_types.Mapping;
const Span = yaml_types.Span;

const StepCheck = *const fn (*const Step, *DiagnosticList) void;

/// Selecting by ID keeps this list honest: a renamed or removed rule, or one
/// that loses its `check_step`, is a compile error instead of a silent gap.
fn stepCheck(comptime candidates: []const Rule, comptime id: []const u8) StepCheck {
    for (candidates) |rule| {
        if (!std.mem.eql(u8, rule.id, id)) continue;
        return rule.check_step orelse @compileError("rule " ++ id ++ " has no check_step");
    }
    @compileError("no rule with id " ++ id);
}

/// The same guarantee for a rule wired in through an exported entry point
/// instead of its `check_step` field.
fn requireRule(comptime candidates: []const Rule, comptime id: []const u8) void {
    for (candidates) |rule| {
        if (std.mem.eql(u8, rule.id, id)) return;
    }
    @compileError("no rule with id " ++ id);
}

/// The step rules that still hold with no workflow and no job around them.
/// Every entry reads nothing but the step itself and on-disk data. The
/// omissions are deliberate:
///
///   * workflow- or job-scoped rules (SEC004, SEC005, BP001, BP004, ...) have
///     nothing here to judge.
///   * `secrets`-based rules (SEC011, SEC012, SEC019) would report a context a
///     composite action cannot use at all; ACT005 covers that case instead.
///   * network-backed rules (SC003-SC006, SC008) never get their prefetch on
///     the document lint path, so they would be inert.
///   * BP002 (`name:`) is about workflow log readability, which a composite
///     step does not control.
const composite_step_checks = [_]StepCheck{
    stepCheck(&security.security_rules, "SEC001"),
    // SEC002 is workflow-scoped (its taint sources include the triggers and the
    // sibling steps), so it exports a step-level entry point of its own.
    blk: {
        requireRule(&security.security_rules, "SEC002");
        break :blk &security.checkStandaloneStepScriptInjection;
    },
    stepCheck(&security.security_rules, "SEC003"),
    stepCheck(&security.security_rules, "SEC006"),
    // SEC008 is workflow-scoped for the same reason as SEC002.
    blk: {
        requireRule(&security.security_rules, "SEC008");
        break :blk &security.checkStandaloneGithubEnvInjection;
    },
    stepCheck(&security.security_rules, "SEC014"),
    stepCheck(&security.security_rules, "SEC017"),
    stepCheck(&security.security_rules, "SEC018"),
    stepCheck(&security.security_rules, "SC002"),
    stepCheck(&security.security_rules, "SC007"),
    stepCheck(&security.security_rules, "BP007"),
    stepCheck(&best_practices.rules, "BP003"),
    stepCheck(&best_practices.rules, "BP008"),
    stepCheck(&uses_rules.rules, "DEP003"),
    // DEP004 needs the sibling steps (an earlier `actions/checkout` with a
    // `path:` creates its directory at run time), so it is called from the
    // loop below with the step list in hand.
    stepCheck(&popular_actions.rules, "DEP005"),
    stepCheck(&popular_actions.rules, "DEP006"),
};

comptime {
    // DEP004 is invoked directly rather than through the table above; keep the
    // same "a renamed or removed rule is a compile error" guarantee.
    requireRule(&local_action.rules, "DEP004");
}

/// Contexts a composite action step cannot resolve. They are all valid
/// elsewhere, so the expression checker accepts them and only this rule knows
/// they are out of scope here.
const unavailable_contexts = [_][]const u8{ "matrix", "needs", "secrets", "strategy" };

pub fn checkCompositeSteps(root: Mapping, steps_node: Node, list: *DiagnosticList) void {
    const seq = switch (steps_node) {
        .sequence => |s| s,
        else => return,
    };

    // Scratch for the parsed steps and the overlays: diagnostic messages come
    // from the list's own arena and outlive it, and the list's allocator keeps
    // this under the run's leak detection (#159).
    var arena = std.heap.ArenaAllocator.init(list.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const buffer = alloc.alloc(Step, seq.items.len) catch return;
    var count: usize = 0;
    for (seq.items) |item| {
        // A step that is not a mapping is ACT004's finding, not this module's.
        buffer[count] = parser.parseStandaloneStep(alloc, item) catch continue;
        count += 1;
    }
    const steps = buffer[0..count];

    const declared_inputs = declaredInputs(alloc, root);
    var env = expr_check.TypeEnv{
        .inputs = if (declared_inputs) |names| expr_overlay.buildStringInputs(alloc, names) else null,
    };
    const resolver = ContextResolver{ .alloc = alloc, .list = list, .declared_inputs = declared_inputs };

    for (steps, 0..) |*step, index| {
        for (composite_step_checks) |check| check(step, list);
        local_action.checkStepAmongSteps(steps, index, list);
        checkShell(step, list);

        env.steps = expr_overlay.buildSteps(alloc, steps, index);
        expressions.checkStepEnv(step, list, &env);
        expr_scan.scanStep(resolver, step);
    }
}

/// The names declared under `inputs:`, or null when the section is malformed
/// and nothing can be resolved against it. An action with no `inputs:` at all
/// declares the empty set, so `inputs.anything` is undeclared there.
fn declaredInputs(alloc: std.mem.Allocator, root: Mapping) ?[]const []const u8 {
    const node = root.get("inputs") orelse return &.{};
    const mapping = switch (node) {
        .mapping => |m| m,
        else => return null,
    };
    const names = alloc.alloc([]const u8, mapping.entries.len) catch return null;
    for (mapping.entries, 0..) |entry, i| names[i] = entry.key.value;
    return names;
}

/// A composite `run:` step has no default shell: GitHub fails the run outright
/// when `shell:` is absent, which makes this a missing required key (ACT001)
/// rather than a style warning.
fn checkShell(step: *const Step, list: *DiagnosticList) void {
    if (step.shell) |shell| {
        best_practices.checkShellName(shell, step.shell_value_span orelse step.span, list);
        return;
    }
    if (step.run == null) return;

    list.append(.{
        .rule_id = "ACT001",
        .severity = .@"error",
        .message = "\"shell\" is required on a composite action step that uses \"run\"",
        .span = step.span,
        .fix_hint = "add `shell: bash` to the step",
    }) catch return;
}

/// Only plain identifiers carry a name to resolve; a globbed or computed
/// segment (`inputs[github.event_name]`) does not.
fn identSegment(segment: ?expr_check.Segment) ?[]const u8 {
    const seg = segment orelse return null;
    return switch (seg) {
        .ident => |name| name,
        .index_string => |name| name,
        .star => null,
    };
}

const ContextResolver = struct {
    /// Backs the expression parse trees; diagnostic text comes from the list's
    /// own arena instead.
    alloc: std.mem.Allocator,
    list: *DiagnosticList,
    declared_inputs: ?[]const []const u8,

    pub fn checkPath(self: ContextResolver, path: []const u8, span: Span) void {
        var iter = expr_check.SegmentIter{ .path = path };
        const root = identSegment(iter.next()) orelse return;

        for (unavailable_contexts) |name| {
            if (std.ascii.eqlIgnoreCase(root, name)) return self.reportContext(name, span);
        }

        if (!std.ascii.eqlIgnoreCase(root, "inputs")) return;
        const declared = self.declared_inputs orelse return;
        const input = identSegment(iter.next()) orelse return;
        for (declared) |name| {
            if (std.ascii.eqlIgnoreCase(name, input)) return;
        }
        self.reportInput(path, input, declared, span);
    }

    fn reportContext(self: ContextResolver, name: []const u8, span: Span) void {
        const alloc = self.list.fixAllocator();
        const message = std.fmt.allocPrint(
            alloc,
            "the \"{s}\" context is not available inside a composite action",
            .{name},
        ) catch return;

        self.list.append(.{
            .rule_id = "ACT005",
            .severity = .@"error",
            .message = message,
            .span = span,
            .fix_hint = "pass the value in as an action input and read it through `inputs.<name>`",
        }) catch return;
    }

    fn reportInput(
        self: ContextResolver,
        path: []const u8,
        name: []const u8,
        declared: []const []const u8,
        span: Span,
    ) void {
        const alloc = self.list.fixAllocator();
        const suggestion = util.didYouMean(name, declared);
        const suffix = if (suggestion) |s|
            std.fmt.allocPrint(alloc, ". did you mean \"{s}\"?", .{s}) catch ""
        else
            "";
        const message = std.fmt.allocPrint(
            alloc,
            "input \"{s}\" is not declared by this action{s}",
            .{ name, suffix },
        ) catch return;

        self.list.append(.{
            .rule_id = "ACT005",
            .severity = .@"error",
            .message = message,
            .span = span,
            .fix_hint = "declare the input under the action's `inputs:` section",
            .fix = if (suggestion) |s| rename.pathSegmentFix(self.list, span, path, 1, s) else null,
        }) catch return;
    }
};

pub const rules = [_]Rule{
    .{
        .id = "ACT005",
        .name = "action-invalid-context",
        .description = "Composite step expression uses a context unavailable in an action, or an input the action does not declare",
        .severity = .@"error",
        .category = .action,
    },
};

const testing = std.testing;
const yaml_parser_mod = @import("../yaml/parser.zig");
const test_support = @import("../test_support.zig");

const Lint = struct {
    arena: std.heap.ArenaAllocator,
    diags: DiagnosticList,

    /// `source` is a whole `action.yml`; only `runs.steps` is checked, since
    /// the surrounding metadata belongs to `action_metadata.zig` (which cannot
    /// be imported here: it is this module's caller).
    fn run(source: []const u8) !Lint {
        var self = Lint{
            .arena = std.heap.ArenaAllocator.init(testing.allocator),
            .diags = DiagnosticList.init(testing.allocator),
        };
        errdefer self.deinit();

        var yaml = yaml_parser_mod.Parser.init(self.arena.allocator(), source);
        const node = try yaml.parse();
        const root = switch (node) {
            .mapping => |m| m,
            else => return error.NotAMapping,
        };
        const runs = switch (root.get("runs") orelse return error.NoRuns) {
            .mapping => |m| m,
            else => return error.NoRuns,
        };
        checkCompositeSteps(root, runs.get("steps") orelse return error.NoSteps, &self.diags);
        return self;
    }

    fn deinit(self: *Lint) void {
        self.diags.deinit();
        self.arena.deinit();
    }

    fn has(self: *const Lint, rule_id: []const u8) bool {
        return test_support.hasDiagnostic(&self.diags, rule_id);
    }

    fn message(self: *const Lint, rule_id: []const u8) []const u8 {
        const d = test_support.findDiagnostic(&self.diags, rule_id) orelse return "";
        return d.message;
    }
};

test "a clean composite action reports nothing" {
    var lint = try Lint.run(
        \\name: Build
        \\description: builds
        \\inputs:
        \\  target:
        \\    description: what to build
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020
        \\    - name: Build
        \\      run: make ${{ inputs.target }}
        \\      shell: bash
    );
    defer lint.deinit();

    try testing.expectEqual(@as(usize, 0), lint.diags.len());
}

test "SEC001: an unpinned action inside a composite step is reported" {
    var lint = try Lint.run(
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - uses: actions/checkout@v4
    );
    defer lint.deinit();

    try testing.expect(lint.has("SEC001"));
}

test "SC007: a typosquat action inside a composite step is reported" {
    var lint = try Lint.run(
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - uses: actions/chekout@v4
    );
    defer lint.deinit();

    try testing.expect(lint.has("SC007"));
}

test "SEC002: script injection inside a composite step is reported" {
    var lint = try Lint.run(
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - run: echo "${{ github.event.issue.title }}"
        \\      shell: bash
    );
    defer lint.deinit();

    try testing.expect(lint.has("SEC002"));
}

test "DEP003: a malformed uses inside a composite step is reported" {
    var lint = try Lint.run(
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - uses: actions/checkout
    );
    defer lint.deinit();

    try testing.expect(lint.has("DEP003"));
}

test "DEP005: an undeclared with: key inside a composite step is reported" {
    var lint = try Lint.run(
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - uses: actions/checkout@v4
        \\      with:
        \\        fetch-dept: 0
    );
    defer lint.deinit();

    try testing.expect(lint.has("DEP005"));
}

test "DEP006: a deprecated input inside a composite step is reported" {
    var lint = try Lint.run(
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - uses: actions/setup-node@v2
        \\      with:
        \\        version: 16
    );
    defer lint.deinit();

    try testing.expect(lint.has("DEP006"));
}

test "BP003: a composite step on an action with a retired runtime is reported" {
    // The runtime half of BP003 reads the embedded table rather than an
    // `action.yml` on disk, so it has to reach composite steps too.
    var lint = try Lint.run(
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - uses: actions/create-release@v1
    );
    defer lint.deinit();

    try testing.expect(lint.has("BP003"));
}

test "BP008: a deprecated workflow command inside a composite step is reported" {
    var lint = try Lint.run(
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - run: echo "::set-output name=v::1"
        \\      shell: bash
    );
    defer lint.deinit();

    try testing.expect(lint.has("BP008"));
}

test "ACT001: a composite run step without shell is an error" {
    var lint = try Lint.run(
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - run: make build
    );
    defer lint.deinit();

    try testing.expect(lint.has("ACT001"));
    try testing.expect(std.mem.indexOf(u8, lint.message("ACT001"), "shell") != null);
}

test "ACT001: a uses step needs no shell" {
    var lint = try Lint.run(
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
    );
    defer lint.deinit();

    try testing.expect(!lint.has("ACT001"));
}

test "BP004: an unknown shell name on a composite step is reported" {
    var lint = try Lint.run(
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - run: make build
        \\      shell: bash4
    );
    defer lint.deinit();

    try testing.expect(lint.has("BP004"));
}

test "ACT005: matrix is not available inside a composite action" {
    var lint = try Lint.run(
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - run: echo ${{ matrix.os }}
        \\      shell: bash
    );
    defer lint.deinit();

    try testing.expect(lint.has("ACT005"));
    try testing.expect(std.mem.indexOf(u8, lint.message("ACT005"), "matrix") != null);
}

test "ACT005: secrets is not available inside a composite action" {
    var lint = try Lint.run(
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - run: echo ${{ secrets.TOKEN }}
        \\      shell: bash
    );
    defer lint.deinit();

    try testing.expect(lint.has("ACT005"));
}

test "ACT005: an undeclared input is reported with a suggestion" {
    var lint = try Lint.run(
        \\inputs:
        \\  target:
        \\    description: what to build
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - run: make ${{ inputs.targt }}
        \\      shell: bash
    );
    defer lint.deinit();

    try testing.expect(lint.has("ACT005"));
    try testing.expect(std.mem.indexOf(u8, lint.message("ACT005"), "\"target\"") != null);
}

test "ACT005: an action with no inputs section declares no inputs" {
    var lint = try Lint.run(
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - run: make ${{ inputs.target }}
        \\      shell: bash
    );
    defer lint.deinit();

    try testing.expect(lint.has("ACT005"));
}

test "ACT005: a malformed inputs section suppresses the input check" {
    var lint = try Lint.run(
        \\inputs: not-a-mapping
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - run: make ${{ inputs.target }}
        \\      shell: bash
    );
    defer lint.deinit();

    try testing.expect(!lint.has("ACT005"));
}

test "ACT005: github and inputs stay silent" {
    var lint = try Lint.run(
        \\inputs:
        \\  target:
        \\    description: what to build
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - run: echo ${{ github.repository }} ${{ inputs.target }} ${{ runner.os }}
        \\      shell: bash
    );
    defer lint.deinit();

    try testing.expect(!lint.has("ACT005"));
}

test "EXPR: an unknown context inside a composite step is still reported" {
    var lint = try Lint.run(
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - run: echo ${{ nonexistent.value }}
        \\      shell: bash
    );
    defer lint.deinit();

    try testing.expect(lint.has("EXPR002"));
}

test "steps context resolves against earlier composite steps" {
    var lint = try Lint.run(
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - id: build
        \\      run: echo hi
        \\      shell: bash
        \\    - run: echo ${{ steps.build.outputs.name }}
        \\      shell: bash
    );
    defer lint.deinit();

    try testing.expectEqual(@as(usize, 0), lint.diags.len());
}

test "a non-sequence steps value is left to the metadata checks" {
    var lint = try Lint.run(
        \\runs:
        \\  using: composite
        \\  steps: nope
    );
    defer lint.deinit();

    try testing.expectEqual(@as(usize, 0), lint.diags.len());
}
