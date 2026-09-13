//! Fixture-driven end-to-end tests.
//!
//! Every case in `tests/fixtures/e2e/` is a real workflow file that runs
//! through the production pipeline — YAML tokenizer → YAML parser → workflow
//! parser → rule engine — instead of hand-built `Workflow` values. That is the
//! path a user's file takes, so a parser-layer regression (see #131, where
//! plain scalars were truncated and SEC002 stopped firing on unquoted `run:`)
//! shows up here even while every inline rule test stays green.
//!
//! Each fixture declares its own expectations in leading comments:
//!
//!     # zghalint:expect SEC002 EXPR
//!     # zghalint:expect BP001@7      (optional `@line`: 1-based start line)
//!     # zghalint:forbid SEC001
//!
//! `expect` entries must fire at least once, `forbid` entries must not fire at
//! all. Directives are additive across lines, so a fixture can group them.

const std = @import("std");
const runtime = @import("runtime.zig");
const yaml_parser = @import("yaml/parser.zig");
const tokenizer = @import("yaml/tokenizer.zig");
const workflow_parser = @import("workflow/parser.zig");
const registry = @import("rules/registry.zig");
const local_action = @import("rules/local_action.zig");
const workspace = @import("workspace.zig");
const action_metadata = @import("rules/action_metadata.zig");
const rule_engine = @import("rules/engine.zig");
const diagnostics = @import("diagnostics.zig");
const fix_engine = @import("fix/engine.zig");

const fixture_dir = "tests/fixtures/e2e";
const action_fixture_dir = "tests/fixtures/e2e-action";

const Expectation = struct {
    rule_id: []const u8,
    line: ?u32 = null,

    /// A malformed `@line` is an error: silently dropping it would turn the
    /// expectation into a line-agnostic one and hide line regressions.
    fn parse(token: []const u8) !Expectation {
        const at = std.mem.findScalar(u8, token, '@') orelse
            return .{ .rule_id = token };
        return .{
            .rule_id = token[0..at],
            .line = try std.fmt.parseInt(u32, token[at + 1 ..], 10),
        };
    }
};

const Directives = struct {
    expect: std.ArrayList(Expectation) = .empty,
    forbid: std.ArrayList(Expectation) = .empty,

    fn parse(alloc: std.mem.Allocator, source: []const u8) !Directives {
        var self = Directives{};
        // A fixture may carry a UTF-8 BOM (see `bom-prefixed.yml`); the
        // linter skips it, so the directive scan has to as well or the
        // first `#` line would not be recognised as a comment.
        const bom = tokenizer.Tokenizer.utf8_bom;
        const body_source = if (std.mem.startsWith(u8, source, bom)) source[bom.len..] else source;
        var lines = std.mem.splitScalar(u8, body_source, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0) continue;
            if (line[0] != '#') break;

            const body = std.mem.trim(u8, line[1..], " \t");
            const target: *std.ArrayList(Expectation) =
                if (std.mem.startsWith(u8, body, "zghalint:expect"))
                    &self.expect
                else if (std.mem.startsWith(u8, body, "zghalint:forbid"))
                    &self.forbid
                else
                    continue;

            // Both directive names are the same length, so one slice works.
            const rest = body["zghalint:expect".len..];
            var tokens = std.mem.tokenizeAny(u8, rest, " \t");
            while (tokens.next()) |token| {
                try target.append(alloc, try Expectation.parse(token));
            }
        }
        return self;
    }
};

/// Network-backed rules (SC003–SC006, SC008) stay offline by default, so the
/// fixtures only ever exercise local analysis.
fn lintSource(
    alloc: std.mem.Allocator,
    source: []const u8,
) !diagnostics.DiagnosticList {
    var yp = yaml_parser.Parser.init(alloc, source);

    const yaml_node = try yp.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_node);

    const engine = rule_engine.Engine.init(&registry.all_rules);
    var list = engine.run(alloc, &wf);
    rule_engine.postProcess(alloc, &wf, &list, .{});
    return list;
}

/// Action metadata is not a workflow, so its fixtures stop at the YAML
/// document and run the document-level check the CLI uses for `action.yml`.
fn lintActionSource(
    alloc: std.mem.Allocator,
    source: []const u8,
) !diagnostics.DiagnosticList {
    var yp = yaml_parser.Parser.init(alloc, source);

    var list = diagnostics.DiagnosticList.init(alloc);
    action_metadata.lintActionMetadata(try yp.parse(), &list);
    return list;
}

/// Expected result of `--fix` for a fixture, held in a sibling `<name>.fixed`
/// file, and of `--fix-unsafe`, held in `<name>.fixed-unsafe`. Either sibling
/// is optional; a fixture with neither is only checked for its diagnostics.
///
/// The diagnostic directives pin where a rule fires; this pins what its fix
/// rewrites, which is the half a wrong byte range would silently get wrong.
fn checkFixedOutputs(
    alloc: std.mem.Allocator,
    dir: std.Io.Dir,
    name: []const u8,
    source: []const u8,
    diags: []const diagnostics.Diagnostic,
) !void {
    try checkFixedOutput(alloc, dir, name, source, diags, false);
    try checkFixedOutput(alloc, dir, name, source, diags, true);
}

fn checkFixedOutput(
    alloc: std.mem.Allocator,
    dir: std.Io.Dir,
    name: []const u8,
    source: []const u8,
    diags: []const diagnostics.Diagnostic,
    include_unsafe: bool,
) !void {
    const suffix = if (include_unsafe) ".fixed-unsafe" else ".fixed";
    const expected_name = try std.fmt.allocPrint(alloc, "{s}{s}", .{ name, suffix });
    const expected = dir.readFileAlloc(runtime.io(), expected_name, alloc, .limited(256 * 1024)) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };

    const fixes = try fix_engine.collectFixes(alloc, diags, include_unsafe);
    const result = try fix_engine.applyFixes(alloc, source, fixes);

    if (!std.mem.eql(u8, result.content, expected)) {
        std.debug.print("fixture '{s}': fix output does not match {s}\n--- got ---\n{s}\n--- want ---\n{s}\n", .{
            name, expected_name, result.content, expected,
        });
        return error.FixedOutputMismatch;
    }
}

/// Every diagnostic must describe a forward range. A reversed one makes SARIF
/// regions and terminal underlines nonsense, and it is easy to produce by
/// accident: a mapping built from a merge key ended before it began (#367).
fn checkSpanOrdering(name: []const u8, diags: []const diagnostics.Diagnostic) !void {
    for (diags) |diag| {
        const span = diag.span;
        const ordered = span.start_byte <= span.end_byte and
            (span.start_line < span.end_line or
                (span.start_line == span.end_line and span.start_col <= span.end_col));
        if (ordered) continue;
        std.debug.print(
            "fixture '{s}': {s} span runs backwards: {d}:{d} (byte {d}) -> {d}:{d} (byte {d})\n",
            .{
                name,            diag.rule_id,  span.start_line, span.start_col,
                span.start_byte, span.end_line, span.end_col,    span.end_byte,
            },
        );
        return error.SpanRunsBackwards;
    }
}

/// `--fix` must reach a fixed point: re-running it on its own output has to
/// leave the file alone. A fix whose rewrite is not read back the way it was
/// meant re-fires forever and grows the file on every round (#369, #370).
fn checkFixConverges(
    alloc: std.mem.Allocator,
    name: []const u8,
    source: []const u8,
    lint: LintFn,
    include_unsafe: bool,
) !void {
    var content = source;
    // One round applies the fixes, the second proves nothing is left. The
    // extras absorb a fix that legitimately uncovers another one.
    for (0..5) |_| {
        var list = try lint(alloc, content);
        defer list.deinit();

        const fixes = try fix_engine.collectFixes(alloc, list.items.items, include_unsafe);
        const result = try fix_engine.applyFixes(alloc, content, fixes);
        if (std.mem.eql(u8, result.content, content)) return;
        content = result.content;
    }

    std.debug.print("fixture '{s}': --fix{s} does not converge\n--- after 5 rounds ---\n{s}\n", .{
        name, if (include_unsafe) "-unsafe" else "", content,
    });
    return error.FixDidNotConverge;
}

fn matches(diag: diagnostics.Diagnostic, exp: Expectation) bool {
    if (!std.mem.eql(u8, diag.rule_id, exp.rule_id)) return false;
    const want_line = exp.line orelse return true;
    // Spans carry 1-based line numbers, same as the terminal/JSON output.
    return diag.span.start_line == want_line;
}

const LintFn = *const fn (std.mem.Allocator, []const u8) anyerror!diagnostics.DiagnosticList;

/// Fixture paths are relative to the repo root; `zig build test` and the
/// local wrapper both run with cwd = repo root (same assumption as the
/// PERF001 fixture harness).
fn runFixtures(
    alloc: std.mem.Allocator,
    dir_path: []const u8,
    lint: LintFn,
    /// Rule IDs seen across every fixture, for the coverage check.
    covered: *std.StringHashMapUnmanaged(void),
) !void {
    var dir = try std.Io.Dir.cwd().openDir(runtime.io(), dir_path, .{ .iterate = true });
    defer dir.close(runtime.io());

    var it = dir.iterate();
    while (try it.next(runtime.io())) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".yml")) continue;

        const source = try dir.readFileAlloc(runtime.io(), entry.name, alloc, .limited(256 * 1024));
        const directives = try Directives.parse(alloc, source);
        if (directives.expect.items.len == 0 and directives.forbid.items.len == 0) {
            std.debug.print("fixture '{s}': no zghalint:expect/forbid directives\n", .{entry.name});
            return error.FixtureWithoutExpectations;
        }

        var list = try lint(alloc, source);
        defer list.deinit();

        for (list.items.items) |diag| {
            try covered.put(alloc, diag.rule_id, {});
        }

        for (directives.expect.items) |exp| {
            const found = for (list.items.items) |diag| {
                if (matches(diag, exp)) break true;
            } else false;
            if (!found) {
                std.debug.print("fixture '{s}': expected {s} to fire, got:\n", .{ entry.name, exp.rule_id });
                for (list.items.items) |diag| {
                    std.debug.print("  {s} at line {d}: {s}\n", .{ diag.rule_id, diag.span.start_line, diag.message });
                }
                return error.ExpectedDiagnosticMissing;
            }
        }

        for (directives.forbid.items) |exp| {
            for (list.items.items) |diag| {
                if (!matches(diag, exp)) continue;
                std.debug.print("fixture '{s}': forbidden {s} fired: {s}\n", .{
                    entry.name, exp.rule_id, diag.message,
                });
                return error.ForbiddenDiagnosticFired;
            }
        }

        try checkSpanOrdering(entry.name, list.items.items);
        try checkFixedOutputs(alloc, dir, entry.name, source, list.items.items);
        try checkFixConverges(alloc, entry.name, source, lint, false);
        try checkFixConverges(alloc, entry.name, source, lint, true);
    }
}

test "E2E: fixtures produce the declared diagnostics" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // The CLI points the local-action store at the repository root, and so
    // does this: without it every `uses: ./x` resolves to `.unavailable` and
    // a `forbid DEP004` directive could never fail (#305).
    local_action.init(std.testing.allocator, ".");
    defer local_action.deinit();

    // Same root the CLI sets before rules run. BP009 and the RW checks stay
    // quiet when it is missing (fail-closed), so fixtures that name an
    // on-disk `./.github/workflows/…` would otherwise never fire.
    workspace.setRepoRoot(".");
    defer workspace.clear();

    var covered: std.StringHashMapUnmanaged(void) = .{};
    try runFixtures(alloc, fixture_dir, lintSource, &covered);

    // Minimum coverage: every rule family must fire at least once through a
    // real file, so a parser regression cannot silence a whole category.
    const must_cover = [_][]const u8{
        "SEC001",  "SEC002",  "SEC003",    "SEC004",    "SEC005",  "SEC006",
        "SEC007",  "SEC008",  "SEC015",    "SEC018",    "SEC019",  "SC001",
        "SC002",   "EXPR001", "EXPR002",   "SYN001",    "SYN004",  "SYN005",
        "BP001",   "BP002",   "BP005",     "PERF001",   "PERF002", "PERM001",
        "PERM002", "PERM003", "RUNNER001", "RUNNER002", "DEP003",  "RW001",
    };
    for (must_cover) |rule_id| {
        if (covered.get(rule_id) == null) {
            std.debug.print("no e2e fixture exercises rule {s}\n", .{rule_id});
            return error.RuleNotCoveredByFixtures;
        }
    }
}

test "E2E: action metadata fixtures produce the declared diagnostics" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var covered: std.StringHashMapUnmanaged(void) = .{};
    try runFixtures(alloc, action_fixture_dir, lintActionSource, &covered);

    for ([_][]const u8{ "ACT001", "ACT002", "ACT003", "ACT004" }) |rule_id| {
        if (covered.get(rule_id) == null) {
            std.debug.print("no e2e fixture exercises rule {s}\n", .{rule_id});
            return error.RuleNotCoveredByFixtures;
        }
    }
}
