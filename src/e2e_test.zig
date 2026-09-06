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
const yaml_parser = @import("yaml/parser.zig");
const workflow_parser = @import("workflow/parser.zig");
const registry = @import("rules/registry.zig");
const rule_engine = @import("rules/engine.zig");
const diagnostics = @import("diagnostics.zig");

const fixture_dir = "tests/fixtures/e2e";

const Expectation = struct {
    rule_id: []const u8,
    line: ?u32 = null,

    /// A malformed `@line` is an error: silently dropping it would turn the
    /// expectation into a line-agnostic one and hide line regressions.
    fn parse(token: []const u8) !Expectation {
        const at = std.mem.indexOfScalar(u8, token, '@') orelse
            return .{ .rule_id = token };
        return .{
            .rule_id = token[0..at],
            .line = try std.fmt.parseInt(u32, token[at + 1 ..], 10),
        };
    }
};

const Directives = struct {
    expect: std.ArrayList(Expectation) = .{},
    forbid: std.ArrayList(Expectation) = .{},

    fn parse(alloc: std.mem.Allocator, source: []const u8) !Directives {
        var self = Directives{};
        var lines = std.mem.splitScalar(u8, source, '\n');
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
    rule_engine.postProcess(alloc, &wf, &list);
    return list;
}

fn matches(diag: diagnostics.Diagnostic, exp: Expectation) bool {
    if (!std.mem.eql(u8, diag.rule_id, exp.rule_id)) return false;
    const want_line = exp.line orelse return true;
    // Spans carry 1-based line numbers, same as the terminal/JSON output.
    return diag.span.start_line == want_line;
}

test "E2E: fixtures produce the declared diagnostics" {
    // Fixture paths are relative to the repo root; `zig build test` and the
    // local wrapper both run with cwd = repo root (same assumption as the
    // PERF001 fixture harness).
    var dir = try std.fs.cwd().openDir(fixture_dir, .{ .iterate = true });
    defer dir.close();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Rule IDs seen across every fixture, for the coverage test below.
    var covered: std.StringHashMapUnmanaged(void) = .{};

    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".yml")) continue;

        const source = try dir.readFileAlloc(alloc, entry.name, 256 * 1024);
        const directives = try Directives.parse(alloc, source);
        if (directives.expect.items.len == 0 and directives.forbid.items.len == 0) {
            std.debug.print("fixture '{s}': no zghalint:expect/forbid directives\n", .{entry.name});
            return error.FixtureWithoutExpectations;
        }

        var list = try lintSource(alloc, source);
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
    }

    // Minimum coverage: every rule family must fire at least once through a
    // real file, so a parser regression cannot silence a whole category.
    const must_cover = [_][]const u8{
        "SEC001",    "SEC002",  "SEC003",  "SEC004",  "SEC005",  "SEC006",
        "SEC007",    "SEC008",  "SEC018",  "SC001",   "SC002",   "EXPR001",
        "EXPR002",   "SYN001",  "SYN004",  "SYN005",  "BP001",   "BP002",
        "BP005",     "PERF001", "PERF002", "PERM001", "PERM002", "PERM003",
        "RUNNER001", "DEP003",
    };
    for (must_cover) |rule_id| {
        if (covered.get(rule_id) == null) {
            std.debug.print("no e2e fixture exercises rule {s}\n", .{rule_id});
            return error.RuleNotCoveredByFixtures;
        }
    }
}
