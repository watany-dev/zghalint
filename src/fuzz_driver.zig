//! Standalone fuzz driver.
//!
//! `zig build fuzz --fuzz` cannot run on Zig 0.15.2 (see
//! `docs/design/pbt-strategy.md` §6-4), so long campaigns run through this
//! driver instead: it owns the corpus, the mutator and the properties, and
//! needs nothing from the compiler beyond a normal executable.
//!
//! Every iteration derives its input from a single u64 seed, so a violation is
//! reproduced with `zig build fuzz-driver -- --seed <n> --iterations 1`.
//!
//! Usage:
//!   zig build fuzz-driver -- [--iterations N] [--seed S] [--quiet]
//!   zig build fuzz-driver -- --file PATH

const std = @import("std");
const runtime = @import("runtime.zig");

const tokenizer = @import("yaml/tokenizer.zig");
const yaml_parser = @import("yaml/parser.zig");
const workflow_parser = @import("workflow/parser.zig");
const registry = @import("rules/registry.zig");
const rule_engine = @import("rules/engine.zig");
const diagnostics = @import("diagnostics.zig");
const fix_engine = @import("fix/engine.zig");
const expressions = @import("rules/expressions.zig");
const json_out = @import("output/json.zig");
const sarif_out = @import("output/sarif.zig");
const terminal_out = @import("output/terminal.zig");
const action_metadata = @import("rules/action_metadata.zig");

const max_input = 64 * 1024;

/// A property the driver checks. Kept as an error set so a failure names the
/// invariant rather than the line that noticed it.
const Violation = error{
    DiagnosticEmptyRuleId,
    DiagnosticEmptyMessage,
    DiagnosticSpanOutOfRange,
    DiagnosticSpanReversed,
    DiagnosticZeroLine,
    DiagnosticZeroColumn,
    JsonOutputNotValid,
    SarifOutputNotValid,
    LintNotDeterministic,
    FixBrokeParse,
    FixDidNotConverge,
    FixGrewUnboundedly,
    TokenizerDidNotReachEof,
    TokenizerSpanOutOfRange,
};

/// Seeds are the checked-in e2e fixtures: real workflow files that already
/// reach deep into the rules, so a mutation lands somewhere interesting far
/// more often than a mutation of a hand-written snippet would.
fn loadCorpus(alloc: std.mem.Allocator) ![]const []const u8 {
    var list = std.ArrayList([]const u8).empty;
    for ([_][]const u8{ "tests/fixtures/e2e", "tests/fixtures/e2e-action" }) |path| {
        var dir = std.Io.Dir.cwd().openDir(runtime.io(), path, .{ .iterate = true }) catch continue;
        defer dir.close(runtime.io());
        var it = dir.iterate();
        while (try it.next(runtime.io())) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".yml")) continue;
            const body = dir.readFileAlloc(runtime.io(), entry.name, alloc, .limited(max_input)) catch continue;
            try list.append(alloc, body);
        }
    }
    for (builtin_seeds) |seed| try list.append(alloc, seed);
    return list.toOwnedSlice(alloc);
}

/// Shapes the fixtures do not carry: degenerate documents, flow collections,
/// anchors, and the indicators that drive the tokenizer's state machine.
const builtin_seeds: []const []const u8 = &.{
    "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n",
    "a: {b: [1, 2], c: 'x'}\n",
    "a: |\n  one\n  two\n",
    "a: >-\n  folded\n  scalar\n",
    "- - - nested\n",
    "---\na: 1\n...\n",
    "key: \"unterminated\n",
    "\t: tab indent\n",
    "#\n",
    ":\n",
    "x: &c\n  runs-on: ubuntu-latest\njob:\n  <<: *c\n",
    "a: &a\n  b: *a\n",
    "job:\n  <<: *missing\n",
    "on:\n  pull_request_target:\njobs:\n  j:\n    runs-on: ubuntu-latest\n    permissions: write-all\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: npm publish\n",
    "on: workflow_call\njobs:\n  j:\n    uses: ./.github/workflows/x.yml\n    secrets: inherit\n",
};

/// Tokens spliced in by the mutator. Anything a rule or the fix builder keys
/// off belongs here: a purely byte-level mutator almost never rediscovers
/// `pull_request_target` on its own.
const dictionary: []const []const u8 = &.{
    "on:",                 "jobs:",                           "steps:",                          "runs-on:",
    "uses:",               "run:",                            "with:",                           "env:",
    "if:",                 "needs:",                          "permissions:",                    "strategy:",
    "matrix:",             "container:",                      "services:",                       "outputs:",
    "secrets:",            "concurrency:",                    "timeout-minutes:",                "continue-on-error:",
    "shell:",              "working-directory:",              "defaults:",                       "name:",
    "pull_request_target", "workflow_run",                    "issue_comment",                   "workflow_dispatch",
    "ubuntu-latest",       "self-hosted",                     "actions/checkout@v4",             "actions/checkout@main",
    "docker://alpine",     "./local-action",                  "write-all",                       "contents: write",
    "id-token: write",     "${{ github.event.issue.title }}", "${{ github.head_ref }}",          "${{ secrets.GITHUB_TOKEN }}",
    "${{ matrix.os }}",    "${{ needs.a.outputs.b }}",        "${{ fromJSON(inputs.x)[0] }}",    "${{ }}",
    "${{",                 "}}",                              "${{ toJSON(github) }}",           "&anchor",
    "*anchor",             "<<:",                             "- ",                              "  ",
    "\t",                  "\r\n",                            "\n\n",                            "'",
    "\"",                  "|",                               "|-",                              ">",
    ">-",                  "---",                             "...",                             "#",
    "[",                   "]",                               "{",                               "}",
    ",",                   ": ",                              "@",                               "\xef\xbb\xbf",
    "\xc3\xa9",            "\xed\xa0\x80",                    "\x00",                            "0123456789abcdef0123456789abcdef01234567",
    "npm publish",         "curl | bash",                     "echo \"::set-output name=x::y\"",
};

const Mutator = struct {
    rng: std.Random,
    corpus: []const []const u8,

    fn pick(self: Mutator, slice: []const []const u8) []const u8 {
        return slice[self.rng.uintLessThan(usize, slice.len)];
    }

    /// Builds one input: a corpus entry (or a splice of two) put through a
    /// handful of mutations. About one input in thirty-two is unstructured
    /// noise, which keeps the tokenizer's error paths exercised.
    fn generate(self: Mutator, alloc: std.mem.Allocator) ![]u8 {
        var buf = std.ArrayList(u8).empty;

        if (self.rng.uintLessThan(u8, 32) == 0) {
            const len = self.rng.uintLessThan(usize, 512);
            try buf.resize(alloc, len);
            self.rng.bytes(buf.items);
            return buf.toOwnedSlice(alloc);
        }

        const base = self.pick(self.corpus);
        try buf.appendSlice(alloc, base);

        if (self.rng.boolean()) {
            const other = self.pick(self.corpus);
            const cut = self.rng.uintAtMost(usize, buf.items.len);
            const take = self.rng.uintAtMost(usize, other.len);
            try buf.replaceRange(alloc, cut, buf.items.len - cut, other[0..take]);
        }

        const rounds = 1 + self.rng.uintLessThan(usize, 8);
        for (0..rounds) |_| try self.mutateOnce(alloc, &buf);

        if (buf.items.len > max_input) buf.shrinkRetainingCapacity(max_input);
        return buf.toOwnedSlice(alloc);
    }

    fn mutateOnce(self: Mutator, alloc: std.mem.Allocator, buf: *std.ArrayList(u8)) !void {
        const len = buf.items.len;
        switch (self.rng.uintLessThan(u8, 10)) {
            0, 1, 2 => {
                const token = self.pick(dictionary);
                try buf.insertSlice(alloc, self.rng.uintAtMost(usize, len), token);
            },
            3 => {
                if (len == 0) return;
                buf.items[self.rng.uintLessThan(usize, len)] = self.rng.int(u8);
            },
            4 => {
                if (len == 0) return;
                const start = self.rng.uintLessThan(usize, len);
                const count = self.rng.uintAtMost(usize, len - start);
                buf.replaceRangeAssumeCapacity(start, count, &.{});
            },
            // Duplicate a line: the cheapest way to reach duplicate-key and
            // repeated-step paths.
            5 => {
                if (len == 0) return;
                const at = self.rng.uintLessThan(usize, len);
                const start = if (std.mem.findScalarLast(u8, buf.items[0..at], '\n')) |i| i + 1 else 0;
                const end = (std.mem.findScalarPos(u8, buf.items, at, '\n') orelse len - 1) + 1;
                const line = try alloc.dupe(u8, buf.items[start..end]);
                defer alloc.free(line);
                try buf.insertSlice(alloc, end, line);
            },
            // Perturb indentation, which is what the YAML block parser keys on.
            6 => {
                if (len == 0) return;
                const at = self.rng.uintLessThan(usize, len);
                const start = if (std.mem.findScalarLast(u8, buf.items[0..at], '\n')) |i| i + 1 else 0;
                if (self.rng.boolean()) {
                    try buf.insertSlice(alloc, start, "  ");
                } else if (start < len and (buf.items[start] == ' ' or buf.items[start] == '\t')) {
                    buf.replaceRangeAssumeCapacity(start, 1, &.{});
                }
            },
            // Repeat a byte run: deep nesting, long scalars, unclosed quotes.
            7 => {
                const count = 1 + self.rng.uintLessThan(usize, 64);
                const token = self.pick(dictionary);
                const at = self.rng.uintAtMost(usize, len);
                for (0..count) |_| try buf.insertSlice(alloc, at, token);
            },
            // Truncate: the classic way to reach an unterminated construct.
            8 => {
                if (len == 0) return;
                buf.shrinkRetainingCapacity(self.rng.uintLessThan(usize, len));
            },
            9 => {
                if (len < 4) return;
                const a = self.rng.uintLessThan(usize, len);
                const b = self.rng.uintLessThan(usize, len);
                std.mem.swap(u8, &buf.items[a], &buf.items[b]);
            },
            else => unreachable,
        }
    }
};

fn checkDiagnostics(list: diagnostics.DiagnosticList, source: []const u8) Violation!void {
    for (list.items.items) |d| {
        if (d.rule_id.len == 0) return Violation.DiagnosticEmptyRuleId;
        if (d.message.len == 0) return Violation.DiagnosticEmptyMessage;
        if (d.span.start_line == 0 or d.span.end_line == 0) return Violation.DiagnosticZeroLine;
        if (d.span.start_col == 0 or d.span.end_col == 0) return Violation.DiagnosticZeroColumn;
        if (d.span.start_byte > d.span.end_byte) return Violation.DiagnosticSpanReversed;
        if (d.span.end_byte > source.len) return Violation.DiagnosticSpanOutOfRange;
    }
}

/// The JSON and SARIF writers hand their bytes to CI systems, so "it rendered"
/// is not the property -- "a parser accepts it" is.
fn checkSerializers(
    alloc: std.mem.Allocator,
    list: diagnostics.DiagnosticList,
) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);

    {
        var w = std.Io.Writer.Allocating.fromArrayList(alloc, &buf);
        json_out.renderJson(&w.writer, list, 1) catch return;
        buf = w.toArrayList();
        var parsed = std.json.parseFromSlice(std.json.Value, alloc, buf.items, .{}) catch
            return Violation.JsonOutputNotValid;
        parsed.deinit();
    }

    buf.clearRetainingCapacity();
    {
        var w = std.Io.Writer.Allocating.fromArrayList(alloc, &buf);
        sarif_out.renderSarif(&w.writer, list, &registry.all_rules) catch return;
        buf = w.toArrayList();
        var parsed = std.json.parseFromSlice(std.json.Value, alloc, buf.items, .{}) catch
            return Violation.SarifOutputNotValid;
        parsed.deinit();
    }

    buf.clearRetainingCapacity();
    {
        var w = std.Io.Writer.Allocating.fromArrayList(alloc, &buf);
        terminal_out.renderDiagnostics(&w.writer, list, false) catch {};
        buf = w.toArrayList();
    }
}

fn tokenizeProperty(input: []const u8) Violation!void {
    var tok = tokenizer.Tokenizer.init(input);
    var budget = input.len + 3;
    while (budget > 0) : (budget -= 1) {
        const token = tok.next();
        if (token.start > token.end or token.end > input.len) return Violation.TokenizerSpanOutOfRange;
        if (token.line == 0 or token.column == 0) return Violation.TokenizerSpanOutOfRange;
        if (token.kind == .eof) return;
    }
    return Violation.TokenizerDidNotReachEof;
}

const Lint = struct {
    list: diagnostics.DiagnosticList,
    parsed: bool,
};

fn lint(alloc: std.mem.Allocator, source: []const u8) !Lint {
    var yp = yaml_parser.Parser.init(alloc, source);
    const node = yp.parse() catch return .{ .list = diagnostics.DiagnosticList.init(alloc), .parsed = false };
    const wf = workflow_parser.parseWorkflow(alloc, node) catch
        return .{ .list = diagnostics.DiagnosticList.init(alloc), .parsed = false };

    const engine = rule_engine.Engine.init(&registry.all_rules);
    var list = engine.run(alloc, &wf);
    rule_engine.postProcess(alloc, &wf, &list, .{});
    return .{ .list = list, .parsed = true };
}

/// A rendering of the diagnostics stable enough to compare two runs by.
fn digest(alloc: std.mem.Allocator, list: diagnostics.DiagnosticList) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    for (list.items.items) |d| {
        try buf.print(alloc, "{s}|{d}|{d}|{s}\n", .{ d.rule_id, d.span.start_line, d.span.start_col, d.message });
    }
    return buf.toOwnedSlice(alloc);
}

/// `--fix` must reach a fixpoint. The engine drops a fix whose edits collide
/// with a winner and reports it as skipped, so a second pass is expected to do
/// work; an input that still changes after `max_rounds` is either an
/// oscillation or a rule fighting its own fix.
const max_rounds = 8;

fn checkFixLoop(
    alloc: std.mem.Allocator,
    original: []const u8,
    include_unsafe: bool,
) !void {
    var current: []const u8 = original;
    var first_parsed: ?bool = null;

    for (0..max_rounds) |round| {
        var res = try lint(alloc, current);
        defer res.list.deinit();
        if (first_parsed == null) first_parsed = res.parsed;

        // A file the parser accepted must not become unparseable because of a
        // fix the linter itself proposed.
        if (first_parsed.? and !res.parsed and round > 0) return Violation.FixBrokeParse;

        try checkDiagnostics(res.list, current);

        const fixes = try fix_engine.collectFixes(alloc, res.list.items.items, include_unsafe);
        const applied = try fix_engine.applyFixes(alloc, current, fixes);
        if (applied.content.len > original.len * 4 + 4096) return Violation.FixGrewUnboundedly;
        if (std.mem.eql(u8, applied.content, current)) return;
        current = applied.content;
    }
    return Violation.FixDidNotConverge;
}

fn runOne(alloc: std.mem.Allocator, input: []const u8) !void {
    try tokenizeProperty(input);

    var first = try lint(alloc, input);
    defer first.list.deinit();
    try checkDiagnostics(first.list, input);
    try checkSerializers(alloc, first.list);

    // Determinism: the rules cache lookups across a run, so a second lint of
    // the same bytes returning different diagnostics is a state leak.
    {
        var second = try lint(alloc, input);
        defer second.list.deinit();
        const a = try digest(alloc, first.list);
        const b = try digest(alloc, second.list);
        if (!std.mem.eql(u8, a, b)) return Violation.LintNotDeterministic;
    }

    try checkFixLoop(alloc, input, false);
    try checkFixLoop(alloc, input, true);

    // The expression parser also runs on fragments the workflow parser never
    // reaches, so feed it the raw input too.
    {
        var list = diagnostics.DiagnosticList.init(alloc);
        defer list.deinit();
        expressions.validateExpression(alloc, input, diagnostics.Span.point(1, 1, 0), &list, 0);
        try checkDiagnostics(list, input);
    }

    // `action.yml` takes the same untrusted bytes down a different path.
    {
        var yp = yaml_parser.Parser.init(alloc, input);
        if (yp.parse()) |node| {
            var list = diagnostics.DiagnosticList.init(alloc);
            defer list.deinit();
            action_metadata.lintActionMetadata(node, &list);
            try checkDiagnostics(list, input);
        } else |_| {}
    }
}

pub fn main(init: std.process.Init) !void {
    runtime.init(init);
    const base = init.gpa;

    var args = try init.minimal.args.iterateAllocator(base);
    defer args.deinit();
    _ = args.next();

    var iterations: usize = 100_000;
    var seed: u64 = 0;
    var quiet = false;
    var file: ?[]const u8 = null;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--file")) {
            file = args.next();
        } else if (std.mem.eql(u8, arg, "--iterations")) {
            iterations = try std.fmt.parseInt(usize, args.next() orelse "0", 10);
        } else if (std.mem.eql(u8, arg, "--seed")) {
            seed = try std.fmt.parseInt(u64, args.next() orelse "0", 10);
        } else if (std.mem.eql(u8, arg, "--quiet")) {
            quiet = true;
        }
    }

    // The corpus lives for the whole campaign; an arena keeps the leak
    // checker focused on the code under test rather than the driver.
    var corpus_arena = std.heap.ArenaAllocator.init(base);
    defer corpus_arena.deinit();
    const corpus = try loadCorpus(corpus_arena.allocator());

    // Replay mode: run the properties over one file, which is what a
    // minimizer drives and how a reported crash is confirmed fixed.
    if (file) |path| {
        var arena = std.heap.ArenaAllocator.init(base);
        defer arena.deinit();
        const alloc = arena.allocator();
        const input = try std.Io.Dir.cwd().readFileAlloc(runtime.io(), path, alloc, .limited(max_input));
        runOne(alloc, input) catch |err| {
            var buf: [256]u8 = undefined;
            var errw = std.Io.File.stderr().writerStreaming(init.io, &buf);
            try errw.interface.print("FAIL file={s} err={s}\n", .{ path, @errorName(err) });
            try errw.interface.flush();
            std.process.exit(1);
        };
        return;
    }
    var stderr_buf: [4096]u8 = undefined;
    var stderr = std.Io.File.stderr().writerStreaming(init.io, &stderr_buf);
    const w = &stderr.interface;

    if (!quiet) {
        try w.print("corpus: {d} seeds, iterations: {d}, base seed: {d}\n", .{ corpus.len, iterations, seed });
        try w.flush();
    }

    // A campaign is triaged by class, not by transcript: the input is dumped
    // for the first few of each violation and only the seed is recorded after
    // that, so a 100k run stays readable and still reproduces every case.
    var failures: usize = 0;
    var seen = std.AutoHashMap(anyerror, usize).init(base);
    defer seen.deinit();

    for (0..iterations) |i| {
        const iter_seed = seed +% i;
        var prng = std.Random.DefaultPrng.init(iter_seed);

        var arena = std.heap.ArenaAllocator.init(base);
        defer arena.deinit();
        const alloc = arena.allocator();

        const mutator = Mutator{ .rng = prng.random(), .corpus = corpus };
        const input = try mutator.generate(alloc);

        runOne(alloc, input) catch |err| {
            failures += 1;
            const gop = try seen.getOrPut(err);
            if (!gop.found_existing) gop.value_ptr.* = 0;
            gop.value_ptr.* += 1;
            try w.print("FAIL seed={d} err={s} len={d}\n", .{ iter_seed, @errorName(err), input.len });
            if (gop.value_ptr.* <= 3) {
                try w.print("--- input ---\n{s}\n--- end ---\n", .{input});
            }
            try w.flush();
        };

        if (!quiet and i % 10_000 == 0 and i > 0) {
            try w.print("  {d} iterations, {d} failures\n", .{ i, failures });
            try w.flush();
        }
    }

    try w.print("done: {d} iterations, {d} failures\n", .{ iterations, failures });
    var it = seen.iterator();
    while (it.next()) |e| {
        try w.print("  {s}: {d}\n", .{ @errorName(e.key_ptr.*), e.value_ptr.* });
    }
    try w.flush();
    if (failures > 0) std.process.exit(1);
}
