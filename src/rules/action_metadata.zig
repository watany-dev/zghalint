//! ACT001-ACT004: validate `action.yml` / `action.yaml` metadata.
//!
//! Action metadata is not a workflow, so — like `dependabot.zig` — these
//! checks run over the raw YAML document instead of the workflow rule engine.
//! Composite `runs.steps` are checked for their shape here and then handed to
//! `composite_steps.zig`, which runs the workflow step rules over them (#254).

const std = @import("std");
const engine = @import("engine.zig");
const yaml_types = @import("../yaml/types.zig");
const diagnostics_mod = @import("../diagnostics.zig");
const composite_steps = @import("composite_steps.zig");
const local_action = @import("local_action.zig");
const util = @import("../util.zig");
const rename = @import("rename.zig");
const fix_builder = @import("../fix/builder.zig");

const Rule = engine.Rule;
const DiagnosticList = engine.DiagnosticList;
const Node = yaml_types.Node;
const Mapping = yaml_types.Mapping;
const MappingEntry = yaml_types.MappingEntry;
const Span = yaml_types.Span;

const action_keys = [_][]const u8{
    "author",
    "branding",
    "description",
    "inputs",
    "name",
    "outputs",
    "runs",
};

const node_runs_keys = [_][]const u8{
    "main",
    "post",
    "post-if",
    "pre",
    "pre-if",
    "using",
};

const docker_runs_keys = [_][]const u8{
    "args",
    "entrypoint",
    "env",
    "image",
    "post-entrypoint",
    "post-if",
    "pre-entrypoint",
    "pre-if",
    "using",
};

const composite_runs_keys = [_][]const u8{
    "steps",
    "using",
};

const input_keys = [_][]const u8{
    "default",
    "deprecationMessage",
    "description",
    "required",
};

const output_keys = [_][]const u8{
    "description",
    "value",
};

/// The `using` values GitHub still accepts. `node20` stays here until
/// 2026-09-23 so ACT003 does not call a still-runnable runtime unknown.
const supported_using = [_][]const u8{ "composite", "docker", "node20", "node24" };
const node_using = [_][]const u8{ "node12", "node16", "node20", "node24" };
/// Shared with BP003, which reports retired and ending runtimes from the
/// caller's side (`uses: ./path`). The table lives in `local_action.zig`
/// because this module sits above the step rules in the import graph.
const deprecated_node_using = &local_action.deprecated_runtimes;

const using_expected = "\"node20\", \"node24\", \"docker\", \"composite\"";

const yaml_booleans = [_][]const u8{ "FALSE", "False", "TRUE", "True", "false", "true" };

const Runtime = enum { node, docker, composite };

fn contains(haystack: []const []const u8, needle: []const u8) bool {
    for (haystack) |candidate| {
        if (std.mem.eql(u8, candidate, needle)) return true;
    }
    return false;
}

fn findEntry(m: Mapping, key: []const u8) ?MappingEntry {
    for (m.entries) |entry| {
        if (std.mem.eql(u8, entry.key.value, key)) return entry;
    }
    return null;
}

/// A key written with nothing after the colon (`main:`) reaches the runner as
/// no value at all, so it counts as missing rather than present-but-empty.
fn hasValue(m: Mapping, key: []const u8) bool {
    const entry = findEntry(m, key) orelse return false;
    return switch (entry.value) {
        .null_value => false,
        .scalar => |sc| sc.value.len > 0,
        else => true,
    };
}

fn missingKey(list: *DiagnosticList, key: []const u8, context: []const u8, span: Span) void {
    missingKeyWithFix(list, key, context, span, null);
}

fn missingKeyWithFix(
    list: *DiagnosticList,
    key: []const u8,
    context: []const u8,
    span: Span,
    fix: ?diagnostics_mod.Fix,
) void {
    const alloc = list.fixAllocator();
    const message = std.fmt.allocPrint(
        alloc,
        "required key \"{s}\" is missing in {s}",
        .{ key, context },
    ) catch return;
    const hint = std.fmt.allocPrint(alloc, "add `{s}:` to {s}", .{ key, context }) catch return;

    list.append(.{
        .rule_id = "ACT001",
        .severity = .@"error",
        .message = message,
        .span = span,
        .fix_hint = hint,
        .fix = fix,
    }) catch return;
}

/// Placeholder body for the key each runtime requires. The values cannot be
/// derived from the file — nothing in it says which script or image the action
/// runs — so the fix writes a stub the author still has to fill in. That is
/// what makes it `unsafe`: applying it turns a metadata error into a file that
/// parses but does not do the right thing yet.
const runtime_placeholders = std.StaticStringMap([]const u8).initComptime(.{
    .{ "main", "index.js" },
    .{ "image", "Dockerfile" },
});

const placeholder_composite_step = [_]fix_builder.SubEntry{
    .{ .key = "run", .value = "echo TODO" },
    .{ .key = "shell", .value = "bash" },
};

/// Anchors the insertion at `runs.using`, the one key a classified runtime is
/// guaranteed to have. Returns null when its column is unknown, which leaves
/// the diagnostic without a fix rather than guessing an indent.
fn buildMissingRunsKeyFix(
    list: *DiagnosticList,
    using_span: Span,
    key: []const u8,
) ?diagnostics_mod.Fix {
    if (using_span.start_col == 0) return null;
    const alloc = list.fixAllocator();
    const pos = fix_builder.InsertPos{
        .byte = using_span.start_byte,
        .indent = using_span.start_col - 1,
    };

    const edits = if (std.mem.eql(u8, key, "steps"))
        fix_builder.insertSequenceItemEntryBefore(alloc, pos, key, &placeholder_composite_step, 2) orelse return null
    else
        fix_builder.insertMappingEntryBefore(
            alloc,
            pos,
            key,
            runtime_placeholders.get(key) orelse return null,
        ) orelse return null;

    const description = std.fmt.allocPrint(alloc, "Add a placeholder `{s}:`", .{key}) catch return null;
    return .{ .description = description, .safety = .unsafe, .edits = edits };
}

fn missingRunsKey(
    list: *DiagnosticList,
    key: []const u8,
    context: []const u8,
    runs_span: Span,
    using_span: Span,
) void {
    missingKeyWithFix(list, key, context, runs_span, buildMissingRunsKeyFix(list, using_span, key));
}

fn reportInvalid(list: *DiagnosticList, message: []const u8, span: Span, hint: []const u8) void {
    list.append(.{
        .rule_id = "ACT004",
        .severity = .@"error",
        .message = message,
        .span = span,
        .fix_hint = hint,
    }) catch return;
}

fn checkUnknownKeys(
    list: *DiagnosticList,
    m: Mapping,
    allowed: []const []const u8,
    context: []const u8,
) void {
    for (m.entries) |entry| {
        const key = entry.key.value;
        if (contains(allowed, key)) continue;

        const alloc = list.fixAllocator();
        const suggestion = util.didYouMean(key, allowed);
        const suffix = util.suggestionSuffix(alloc, suggestion);
        const message = std.fmt.allocPrint(
            alloc,
            "unknown key \"{s}\" in {s}{s}",
            .{ key, context, suffix },
        ) catch return;

        list.append(.{
            .rule_id = "ACT003",
            .severity = .@"error",
            .message = message,
            .span = entry.key.span,
            .fix_hint = "remove the key or correct its spelling",
            .fix = if (suggestion) |s| rename.tokenFix(list, entry.key.span, key, s) else null,
        }) catch return;
    }
}

fn classifyUsing(using: []const u8) ?Runtime {
    if (std.mem.eql(u8, using, "docker")) return .docker;
    if (std.mem.eql(u8, using, "composite")) return .composite;
    if (contains(&node_using, using)) return .node;
    return null;
}

fn reportUnknownUsing(list: *DiagnosticList, using: []const u8, span: Span) void {
    const alloc = list.fixAllocator();
    const suggestion = util.didYouMean(using, &supported_using);
    const suffix = util.suggestionSuffix(alloc, suggestion);
    const message = std.fmt.allocPrint(
        alloc,
        "invalid value \"{s}\" for \"using\". expected one of " ++ using_expected ++ "{s}",
        .{ using, suffix },
    ) catch return;

    list.append(.{
        .rule_id = "ACT002",
        .severity = .@"error",
        .message = message,
        .span = span,
        .fix_hint = "set `using:` to " ++ using_expected,
        .fix = if (suggestion) |s| rename.tokenFix(list, span, using, s) else null,
    }) catch return;
}

fn reportDeprecatedUsing(list: *DiagnosticList, using: []const u8, span: Span) void {
    const alloc = list.fixAllocator();
    const message = std.fmt.allocPrint(
        alloc,
        "\"{s}\" runtime is deprecated by GitHub Actions and will stop running",
        .{using},
    ) catch return;

    list.append(.{
        .rule_id = "ACT002",
        .severity = .warning,
        .message = message,
        .span = span,
        .fix_hint = "migrate the action to `using: node24`",
    }) catch return;
}

/// Returns the runtime when it could be determined; the outputs check needs it
/// because `value` is composite-only.
fn checkRuns(root: Mapping, list: *DiagnosticList) ?Runtime {
    const runs_node = root.get("runs") orelse {
        missingKey(list, "runs", "action metadata", root.span);
        return null;
    };
    const runs_span = root.getKeySpan("runs") orelse root.span;

    const runs = switch (runs_node) {
        .mapping => |m| m,
        else => {
            reportInvalid(
                list,
                "\"runs\" must be a mapping",
                runs_span,
                "declare `using:` and the keys that runtime requires under `runs:`",
            );
            return null;
        },
    };

    const using_entry = findEntry(runs, "using") orelse {
        missingKey(list, "using", "the \"runs\" section", runs_span);
        return null;
    };
    const using = switch (using_entry.value) {
        .scalar => |s| s.value,
        else => {
            reportInvalid(
                list,
                "\"using\" must be a string",
                using_entry.key.span,
                "set `using:` to " ++ using_expected,
            );
            return null;
        },
    };

    const runtime = classifyUsing(using) orelse {
        reportUnknownUsing(list, using, using_entry.value.getSpan());
        return null;
    };
    if (contains(deprecated_node_using, using)) {
        reportDeprecatedUsing(list, using, using_entry.value.getSpan());
    }

    const alloc = list.fixAllocator();
    const context = std.fmt.allocPrint(
        alloc,
        "the \"runs\" section of a \"{s}\" action",
        .{using},
    ) catch "the \"runs\" section";

    const using_span = using_entry.key.span;
    switch (runtime) {
        .node => {
            checkUnknownKeys(list, runs, &node_runs_keys, context);
            if (!hasValue(runs, "main")) missingRunsKey(list, "main", context, runs_span, using_span);
        },
        .docker => {
            checkUnknownKeys(list, runs, &docker_runs_keys, context);
            if (!hasValue(runs, "image")) missingRunsKey(list, "image", context, runs_span, using_span);
        },
        .composite => {
            checkUnknownKeys(list, runs, &composite_runs_keys, context);
            if (runs.get("steps")) |steps| {
                switch (steps) {
                    .sequence => composite_steps.checkCompositeSteps(root, steps, list),
                    else => reportInvalid(
                        list,
                        "\"steps\" must be a sequence of steps",
                        runs.getKeySpan("steps") orelse runs_span,
                        "write each step as a `- ` list item under `steps:`",
                    ),
                }
            } else {
                missingRunsKey(list, "steps", context, runs_span, using_span);
            }
        },
    }

    return runtime;
}

/// GitHub reads these as YAML 1.2 booleans. The core schema spells them in
/// three cases and nothing else, so `yes` / `on` are strings and would
/// silently make the input optional.
fn checkBoolean(list: *DiagnosticList, def: Mapping, key: []const u8, context: []const u8) void {
    const entry = findEntry(def, key) orelse return;
    const value = switch (entry.value) {
        .scalar => |s| s.value,
        else => "",
    };
    if (contains(&yaml_booleans, value)) return;

    const alloc = list.fixAllocator();
    const message = std.fmt.allocPrint(
        alloc,
        "\"{s}\" of {s} must be `true` or `false`",
        .{ key, context },
    ) catch return;
    reportInvalid(list, message, entry.value.getSpan(), "use the boolean literal `true` or `false`");
}

const Section = struct {
    plural: []const u8,
    singular: []const u8,
};

const inputs_section = Section{ .plural = "inputs", .singular = "input" };
const outputs_section = Section{ .plural = "outputs", .singular = "output" };

/// `inputs:` / `outputs:` are both a mapping of name to definition mapping;
/// only their key sets differ, so the shape checks are shared.
fn definitionsOf(root: Mapping, section: Section, list: *DiagnosticList) ?Mapping {
    const node = root.get(section.plural) orelse return null;
    const key_span = root.getKeySpan(section.plural) orelse root.span;

    return switch (node) {
        .mapping => |m| m,
        else => {
            const alloc = list.fixAllocator();
            const message = std.fmt.allocPrint(
                alloc,
                "\"{s}\" must be a mapping of {s} name to definition",
                .{ section.plural, section.singular },
            ) catch return null;
            reportInvalid(
                list,
                message,
                key_span,
                "define each entry as `<name>:` with its keys nested under it",
            );
            return null;
        },
    };
}

const Definition = struct {
    body: Mapping,
    /// Human-readable location used in every message about this entry,
    /// e.g. `input "version"`.
    context: []const u8,
};

fn definitionOf(list: *DiagnosticList, section: Section, entry: MappingEntry) ?Definition {
    const alloc = list.fixAllocator();
    const context = std.fmt.allocPrint(
        alloc,
        "{s} \"{s}\"",
        .{ section.singular, entry.key.value },
    ) catch return null;

    const body = switch (entry.value) {
        .mapping => |m| m,
        else => {
            const message = std.fmt.allocPrint(alloc, "{s} must be a mapping", .{context}) catch return null;
            reportInvalid(list, message, entry.key.span, "nest the definition keys under the name");
            return null;
        },
    };

    return .{ .body = body, .context = context };
}

fn checkInputs(root: Mapping, list: *DiagnosticList) void {
    const defs = definitionsOf(root, inputs_section, list) orelse return;
    for (defs.entries) |entry| {
        const def = definitionOf(list, inputs_section, entry) orelse continue;
        checkUnknownKeys(list, def.body, &input_keys, def.context);
        checkBoolean(list, def.body, "required", def.context);
    }
}

/// `value` is required for composite actions and rejected everywhere else, so
/// the outputs pass needs the runtime `runs.using` declared.
fn checkOutputs(root: Mapping, runtime: ?Runtime, list: *DiagnosticList) void {
    const defs = definitionsOf(root, outputs_section, list) orelse return;
    for (defs.entries) |entry| {
        const def = definitionOf(list, outputs_section, entry) orelse continue;
        checkUnknownKeys(list, def.body, &output_keys, def.context);

        const rt = runtime orelse continue;
        if (rt == .composite) {
            if (!hasValue(def.body, "value")) missingKey(list, "value", def.context, entry.key.span);
            continue;
        }
        const span = def.body.getKeySpan("value") orelse continue;
        const alloc = list.fixAllocator();
        const message = std.fmt.allocPrint(
            alloc,
            "\"value\" of {s} is only valid in a composite action",
            .{def.context},
        ) catch continue;
        reportInvalid(
            list,
            message,
            span,
            "remove `value:`; JavaScript and Docker actions set outputs at runtime",
        );
    }
}

pub fn lintActionMetadata(root: Node, diag_list: *DiagnosticList) void {
    const mapping = switch (root) {
        .mapping => |m| m,
        // An empty file or a document that opens with a list is not action
        // metadata at all; staying silent would report it as clean.
        else => return reportInvalid(
            diag_list,
            "action metadata must be a mapping of keys such as `name:` and `runs:`",
            root.getSpan(),
            "write the file as `key: value` pairs at the top level",
        ),
    };

    checkUnknownKeys(diag_list, mapping, &action_keys, "action metadata");
    if (!hasValue(mapping, "name")) {
        missingKey(diag_list, "name", "action metadata", mapping.span);
    }

    const runtime = checkRuns(mapping, diag_list);

    checkInputs(mapping, diag_list);
    checkOutputs(mapping, runtime, diag_list);
}

pub const rules = [_]Rule{
    .{
        .id = "ACT001",
        .name = "action-missing-required-key",
        .description = "Action metadata is missing a key its runtime requires",
        .severity = .@"error",
        .category = .action,
    },
    .{
        .id = "ACT002",
        .name = "action-invalid-runs-using",
        .description = "runs.using names an unsupported or deprecated action runtime",
        .severity = .@"error",
        .category = .action,
    },
    .{
        .id = "ACT003",
        .name = "action-unknown-key",
        .description = "Action metadata contains a key that is not part of the schema",
        .severity = .@"error",
        .category = .action,
    },
    .{
        .id = "ACT004",
        .name = "action-invalid-definition",
        .description = "Action metadata section or entry has the wrong shape or value type",
        .severity = .@"error",
        .category = .action,
    },
};

const yaml_parser_mod = @import("../yaml/parser.zig");
const test_support = @import("../test_support.zig");

const hasDiagnostic = test_support.hasDiagnostic;
const findDiagnostic = test_support.findDiagnostic;

fn parseYamlWithArena(arena: *std.heap.ArenaAllocator, source: []const u8) !Node {
    const alloc = arena.allocator();
    var parser = yaml_parser_mod.Parser.init(alloc, source);
    return parser.parse();
}

const Lint = struct {
    arena: std.heap.ArenaAllocator,
    diags: DiagnosticList,

    fn run(source: []const u8) !Lint {
        var self = Lint{
            .arena = std.heap.ArenaAllocator.init(std.testing.allocator),
            .diags = DiagnosticList.init(std.testing.allocator),
        };
        const node = try parseYamlWithArena(&self.arena, source);
        lintActionMetadata(node, &self.diags);
        return self;
    }

    fn deinit(self: *Lint) void {
        self.diags.deinit();
        self.arena.deinit();
    }

    fn has(self: *const Lint, rule_id: []const u8) bool {
        return hasDiagnostic(&self.diags, rule_id);
    }

    fn message(self: *const Lint, rule_id: []const u8) []const u8 {
        const d = findDiagnostic(&self.diags, rule_id) orelse return "";
        return d.message;
    }
};

test "clean node action produces no diagnostics" {
    var lint = try Lint.run(
        \\name: My Action
        \\description: Does something
        \\runs:
        \\  using: node24
        \\  main: dist/index.js
        \\inputs:
        \\  version:
        \\    description: Version to use
        \\    required: true
        \\    default: "1.0"
    );
    defer lint.deinit();

    try std.testing.expectEqual(@as(usize, 0), lint.diags.len());
}

test "clean composite action produces no diagnostics" {
    var lint = try Lint.run(
        \\name: Composite
        \\description: Runs steps
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - run: echo hi
        \\      shell: bash
        \\outputs:
        \\  result:
        \\    description: The result
        \\    value: ${{ steps.build.outputs.result }}
    );
    defer lint.deinit();

    try std.testing.expectEqual(@as(usize, 0), lint.diags.len());
}

test "clean docker action produces no diagnostics" {
    var lint = try Lint.run(
        \\name: Docker
        \\description: Runs a container
        \\runs:
        \\  using: docker
        \\  image: Dockerfile
        \\  args:
        \\    - hello
    );
    defer lint.deinit();

    try std.testing.expectEqual(@as(usize, 0), lint.diags.len());
}

test "ACT001: missing name and runs" {
    var lint = try Lint.run(
        \\description: Does something
    );
    defer lint.deinit();

    try std.testing.expectEqual(@as(usize, 2), test_support.countDiagnostics(&lint.diags, "ACT001"));
}

test "ACT001: node runtime without main" {
    var lint = try Lint.run(
        \\name: My Action
        \\runs:
        \\  using: node16
    );
    defer lint.deinit();

    try std.testing.expect(std.mem.find(
        u8,
        lint.message("ACT001"),
        "required key \"main\" is missing in the \"runs\" section of a \"node16\" action",
    ) != null);
}

test "ACT001: docker runtime without image" {
    var lint = try Lint.run(
        \\name: My Action
        \\runs:
        \\  using: docker
    );
    defer lint.deinit();

    try std.testing.expect(std.mem.find(u8, lint.message("ACT001"), "\"image\"") != null);
}

test "ACT001: composite runtime without steps" {
    var lint = try Lint.run(
        \\name: My Action
        \\runs:
        \\  using: composite
    );
    defer lint.deinit();

    try std.testing.expect(std.mem.find(u8, lint.message("ACT001"), "\"steps\"") != null);
}

test "ACT001: runs section without using" {
    var lint = try Lint.run(
        \\name: My Action
        \\runs:
        \\  main: dist/index.js
    );
    defer lint.deinit();

    try std.testing.expectEqualStrings(
        "required key \"using\" is missing in the \"runs\" section",
        lint.message("ACT001"),
    );
}

test "ACT001: composite output without value" {
    var lint = try Lint.run(
        \\name: My Action
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - run: echo hi
        \\      shell: bash
        \\outputs:
        \\  result:
        \\    description: The result
    );
    defer lint.deinit();

    try std.testing.expectEqualStrings(
        "required key \"value\" is missing in output \"result\"",
        lint.message("ACT001"),
    );
}

test "ACT002: unknown using value suggests the nearest runtime" {
    var lint = try Lint.run(
        \\name: My Action
        \\runs:
        \\  using: compsite
        \\  steps: []
    );
    defer lint.deinit();

    try std.testing.expect(std.mem.find(
        u8,
        lint.message("ACT002"),
        "did you mean \"composite\"?",
    ) != null);
}

test "ACT002: unknown using value without a near candidate" {
    var lint = try Lint.run(
        \\name: My Action
        \\runs:
        \\  using: python
        \\  main: main.py
    );
    defer lint.deinit();

    const msg = lint.message("ACT002");
    try std.testing.expect(std.mem.find(u8, msg, "invalid value \"python\" for \"using\"") != null);
    try std.testing.expect(std.mem.find(u8, msg, "did you mean") == null);
}

test "ACT002: deprecated node runtimes are a warning, not an error" {
    for ([_][]const u8{ "node12", "node16", "node20" }) |using| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const source = try std.fmt.allocPrint(
            arena.allocator(),
            "name: My Action\nruns:\n  using: {s}\n  main: dist/index.js\n",
            .{using},
        );
        const node = try parseYamlWithArena(&arena, source);

        var diags = DiagnosticList.init(std.testing.allocator);
        defer diags.deinit();
        lintActionMetadata(node, &diags);

        const d = findDiagnostic(&diags, "ACT002") orelse return error.TestUnexpectedResult;
        try std.testing.expect(d.severity == .warning);
        try std.testing.expect(std.mem.find(u8, d.message, "deprecated") != null);
    }
}

test "ACT002: supported runtimes are not reported" {
    var lint = try Lint.run(
        \\name: My Action
        \\runs:
        \\  using: node24
        \\  main: dist/index.js
    );
    defer lint.deinit();

    try std.testing.expect(!lint.has("ACT002"));
}

test "ACT003: unknown top-level key" {
    var lint = try Lint.run(
        \\name: My Action
        \\descriptions: Does something
        \\runs:
        \\  using: node24
        \\  main: dist/index.js
    );
    defer lint.deinit();

    try std.testing.expectEqualStrings(
        "unknown key \"descriptions\" in action metadata. did you mean \"description\"?",
        lint.message("ACT003"),
    );
}

test "ACT003: unknown key inside an input definition" {
    var lint = try Lint.run(
        \\name: My Action
        \\runs:
        \\  using: node24
        \\  main: dist/index.js
        \\inputs:
        \\  version:
        \\    requried: true
    );
    defer lint.deinit();

    try std.testing.expectEqualStrings(
        "unknown key \"requried\" in input \"version\". did you mean \"required\"?",
        lint.message("ACT003"),
    );
}

test "ACT003: runs key belonging to another runtime" {
    var lint = try Lint.run(
        \\name: My Action
        \\runs:
        \\  using: node24
        \\  main: dist/index.js
        \\  image: Dockerfile
    );
    defer lint.deinit();

    try std.testing.expect(std.mem.find(
        u8,
        lint.message("ACT003"),
        "unknown key \"image\" in the \"runs\" section of a \"node24\" action",
    ) != null);
}

test "ACT003: unknown key inside an output definition" {
    var lint = try Lint.run(
        \\name: My Action
        \\runs:
        \\  using: node24
        \\  main: dist/index.js
        \\outputs:
        \\  result:
        \\    descriptions: The result
    );
    defer lint.deinit();

    try std.testing.expect(std.mem.find(u8, lint.message("ACT003"), "output \"result\"") != null);
}

test "ACT004: runs is not a mapping" {
    var lint = try Lint.run(
        \\name: My Action
        \\runs: node24
    );
    defer lint.deinit();

    try std.testing.expectEqualStrings("\"runs\" must be a mapping", lint.message("ACT004"));
}

test "ACT004: composite steps is not a sequence" {
    var lint = try Lint.run(
        \\name: My Action
        \\runs:
        \\  using: composite
        \\  steps: echo hi
    );
    defer lint.deinit();

    try std.testing.expectEqualStrings(
        "\"steps\" must be a sequence of steps",
        lint.message("ACT004"),
    );
}

test "ACT004: required is not a boolean" {
    var lint = try Lint.run(
        \\name: My Action
        \\runs:
        \\  using: node24
        \\  main: dist/index.js
        \\inputs:
        \\  version:
        \\    description: Version
        \\    required: yes
    );
    defer lint.deinit();

    try std.testing.expectEqualStrings(
        "\"required\" of input \"version\" must be `true` or `false`",
        lint.message("ACT004"),
    );
}

test "ACT004: input definition is not a mapping" {
    var lint = try Lint.run(
        \\name: My Action
        \\runs:
        \\  using: node24
        \\  main: dist/index.js
        \\inputs:
        \\  version: "1.0"
    );
    defer lint.deinit();

    try std.testing.expectEqualStrings("input \"version\" must be a mapping", lint.message("ACT004"));
}

test "ACT004: inputs is not a mapping" {
    var lint = try Lint.run(
        \\name: My Action
        \\runs:
        \\  using: node24
        \\  main: dist/index.js
        \\inputs:
        \\  - version
    );
    defer lint.deinit();

    try std.testing.expectEqualStrings(
        "\"inputs\" must be a mapping of input name to definition",
        lint.message("ACT004"),
    );
}

test "ACT004: value outside a composite action" {
    var lint = try Lint.run(
        \\name: My Action
        \\runs:
        \\  using: node24
        \\  main: dist/index.js
        \\outputs:
        \\  result:
        \\    description: The result
        \\    value: ${{ steps.x.outputs.y }}
    );
    defer lint.deinit();

    try std.testing.expectEqualStrings(
        "\"value\" of output \"result\" is only valid in a composite action",
        lint.message("ACT004"),
    );
}

test "outputs are not judged when the runtime is unknown" {
    var lint = try Lint.run(
        \\name: My Action
        \\runs:
        \\  using: python
        \\  main: main.py
        \\outputs:
        \\  result:
        \\    description: The result
        \\    value: x
    );
    defer lint.deinit();

    try std.testing.expect(!lint.has("ACT004"));
    try std.testing.expect(!lint.has("ACT001"));
}

test "ACT001: a key written with no value counts as missing" {
    var lint = try Lint.run(
        \\name:
        \\description: Does something
        \\runs:
        \\  using: docker
        \\  image:
    );
    defer lint.deinit();

    try std.testing.expectEqual(@as(usize, 2), lint.diags.len());
    try std.testing.expectEqualStrings(
        "required key \"name\" is missing in action metadata",
        lint.diags.get(0).message,
    );
    try std.testing.expectEqualStrings("ACT001", lint.diags.get(1).rule_id);
    try std.testing.expectEqualStrings(
        "required key \"image\" is missing in the \"runs\" section of a \"docker\" action",
        lint.diags.get(1).message,
    );
}

test "ACT001: an empty composite output value counts as missing" {
    var lint = try Lint.run(
        \\name: My Action
        \\description: Does something
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - run: echo hi
        \\      shell: bash
        \\outputs:
        \\  result:
        \\    description: The result
        \\    value:
    );
    defer lint.deinit();

    try std.testing.expect(lint.has("ACT001"));
    try std.testing.expectEqualStrings(
        "required key \"value\" is missing in output \"result\"",
        lint.message("ACT001"),
    );
}

test "ACT004: every YAML 1.2 boolean spelling is accepted for required" {
    var lint = try Lint.run(
        \\name: My Action
        \\description: Does something
        \\runs:
        \\  using: node24
        \\  main: dist/index.js
        \\inputs:
        \\  a:
        \\    description: a
        \\    required: True
        \\  b:
        \\    description: b
        \\    required: FALSE
    );
    defer lint.deinit();

    try std.testing.expectEqual(@as(usize, 0), lint.diags.len());
}

test "ACT004: yes is a string, not a boolean" {
    var lint = try Lint.run(
        \\name: My Action
        \\description: Does something
        \\runs:
        \\  using: node24
        \\  main: dist/index.js
        \\inputs:
        \\  a:
        \\    description: a
        \\    required: yes
    );
    defer lint.deinit();

    try std.testing.expect(lint.has("ACT004"));
}

test "ACT004: a document that is not a mapping is reported, not skipped" {
    var lint = try Lint.run(
        \\- not an action
    );
    defer lint.deinit();

    try std.testing.expectEqual(@as(usize, 1), lint.diags.len());
    try std.testing.expectEqualStrings("ACT004", lint.diags.get(0).rule_id);
    try std.testing.expectEqualStrings(
        "action metadata must be a mapping of keys such as `name:` and `runs:`",
        lint.diags.get(0).message,
    );
}

test "ACT004: an empty document is reported" {
    var lint = try Lint.run("");
    defer lint.deinit();

    try std.testing.expectEqual(@as(usize, 1), lint.diags.len());
    try std.testing.expectEqualStrings("ACT004", lint.diags.get(0).rule_id);
}

test "diagnostics point at the offending line" {
    var lint = try Lint.run(
        \\name: My Action
        \\runs:
        \\  using: node16
        \\inputs:
        \\  version:
        \\    requried: true
    );
    defer lint.deinit();

    const deprecated = findDiagnostic(&lint.diags, "ACT002") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 3), deprecated.span.start_line);

    const unknown = findDiagnostic(&lint.diags, "ACT003") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 6), unknown.span.start_line);
}

fn actionFix(source: []const u8) !test_support.FixOutcome {
    return test_support.lintAndFix(
        std.testing.allocator,
        source,
        .{ .document = &lintActionMetadata },
        true,
    );
}

test "ACT001: fix inserts a placeholder main: for a node action" {
    const result = try actionFix(
        \\name: My Action
        \\description: Does something
        \\runs:
        \\  using: node24
        \\
    );
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(diagnostics_mod.FixSafety.unsafe, result.first_safety.?);
    try std.testing.expectEqualStrings(
        \\name: My Action
        \\description: Does something
        \\runs:
        \\  main: index.js
        \\  using: node24
        \\
    ,
        result.content,
    );
}

test "ACT001: fix inserts a placeholder image: for a docker action" {
    const result = try actionFix(
        \\name: My Action
        \\description: Does something
        \\runs:
        \\  using: docker
        \\
    );
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings(
        \\name: My Action
        \\description: Does something
        \\runs:
        \\  image: Dockerfile
        \\  using: docker
        \\
    ,
        result.content,
    );
}

test "ACT001: fix inserts a placeholder steps: item for a composite action" {
    const result = try actionFix(
        \\name: My Action
        \\description: Does something
        \\runs:
        \\  using: composite
        \\
    );
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings(
        \\name: My Action
        \\description: Does something
        \\runs:
        \\  steps:
        \\    - run: echo TODO
        \\      shell: bash
        \\  using: composite
        \\
    ,
        result.content,
    );
}

test "ACT001: a missing using: gets no fix, because the runtime is unknown" {
    var lint = try Lint.run(
        \\name: My Action
        \\description: Does something
        \\runs:
        \\  main: dist/index.js
    );
    defer lint.deinit();

    const d = findDiagnostic(&lint.diags, "ACT001") orelse return error.TestExpectedNonNull;
    try std.testing.expect(d.fix == null);
}
