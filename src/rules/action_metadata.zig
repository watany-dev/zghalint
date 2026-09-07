//! ACT001-ACT004: validate `action.yml` / `action.yaml` metadata.
//!
//! Action metadata is not a workflow, so — like `dependabot.zig` — these
//! checks run over the raw YAML document instead of the workflow rule engine.
//! Composite `runs.steps` are only checked for their shape here; applying the
//! existing step rules to them is #254.

const std = @import("std");
const engine = @import("engine.zig");
const yaml_types = @import("../yaml/types.zig");
const diagnostics_mod = @import("../diagnostics.zig");
const util = @import("../util.zig");

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

/// The `using` values GitHub still accepts. Deprecated Node runtimes are kept
/// out of this list so they are never suggested, but they are recognised (see
/// `node_using`) and reported as deprecated rather than invalid.
const supported_using = [_][]const u8{ "composite", "docker", "node20", "node24" };
const node_using = [_][]const u8{ "node12", "node16", "node20", "node24" };
const deprecated_node_using = [_][]const u8{ "node12", "node16" };

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
    }) catch return;
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
        const suffix = if (util.didYouMean(key, allowed)) |s|
            std.fmt.allocPrint(alloc, ". did you mean \"{s}\"?", .{s}) catch ""
        else
            "";
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
    const suffix = if (util.didYouMean(using, &supported_using)) |s|
        std.fmt.allocPrint(alloc, ". did you mean \"{s}\"?", .{s}) catch ""
    else
        "";
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
    if (contains(&deprecated_node_using, using)) {
        reportDeprecatedUsing(list, using, using_entry.value.getSpan());
    }

    const alloc = list.fixAllocator();
    const context = std.fmt.allocPrint(
        alloc,
        "the \"runs\" section of a \"{s}\" action",
        .{using},
    ) catch "the \"runs\" section";

    switch (runtime) {
        .node => {
            checkUnknownKeys(list, runs, &node_runs_keys, context);
            if (!hasValue(runs, "main")) missingKey(list, "main", context, runs_span);
        },
        .docker => {
            checkUnknownKeys(list, runs, &docker_runs_keys, context);
            if (!hasValue(runs, "image")) missingKey(list, "image", context, runs_span);
        },
        .composite => {
            checkUnknownKeys(list, runs, &composite_runs_keys, context);
            if (runs.get("steps")) |steps| {
                switch (steps) {
                    .sequence => {},
                    else => reportInvalid(
                        list,
                        "\"steps\" must be a sequence of steps",
                        runs.getKeySpan("steps") orelse runs_span,
                        "write each step as a `- ` list item under `steps:`",
                    ),
                }
            } else {
                missingKey(list, "steps", context, runs_span);
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

    try std.testing.expect(std.mem.indexOf(
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

    try std.testing.expect(std.mem.indexOf(u8, lint.message("ACT001"), "\"image\"") != null);
}

test "ACT001: composite runtime without steps" {
    var lint = try Lint.run(
        \\name: My Action
        \\runs:
        \\  using: composite
    );
    defer lint.deinit();

    try std.testing.expect(std.mem.indexOf(u8, lint.message("ACT001"), "\"steps\"") != null);
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

    try std.testing.expect(std.mem.indexOf(
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
    try std.testing.expect(std.mem.indexOf(u8, msg, "invalid value \"python\" for \"using\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "did you mean") == null);
}

test "ACT002: deprecated node runtimes are a warning, not an error" {
    for ([_][]const u8{ "node12", "node16" }) |using| {
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
        try std.testing.expect(std.mem.indexOf(u8, d.message, "deprecated") != null);
    }
}

test "ACT002: supported runtimes are not reported" {
    var lint = try Lint.run(
        \\name: My Action
        \\runs:
        \\  using: node20
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

    try std.testing.expect(std.mem.indexOf(
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

    try std.testing.expect(std.mem.indexOf(u8, lint.message("ACT003"), "output \"result\"") != null);
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

test "rule descriptors are valid" {
    try std.testing.expectEqual(@as(usize, 4), rules.len);
    for (rules) |rule| {
        try std.testing.expect(rule.category == .action);
        try std.testing.expect(rule.check_workflow == null);
        try std.testing.expect(rule.check_job == null);
        try std.testing.expect(rule.check_step == null);
        try std.testing.expect(std.mem.startsWith(u8, rule.id, "ACT"));
    }
    try std.testing.expectEqualStrings("ACT001", rules[0].id);
    try std.testing.expectEqualStrings("action-missing-required-key", rules[0].name);
    try std.testing.expectEqualStrings("ACT004", rules[3].id);
}
