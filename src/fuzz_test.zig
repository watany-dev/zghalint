//! Fuzz targets for the three hand-written parsers zghalint feeds untrusted
//! bytes into: the YAML tokenizer, the YAML parser, and the `${{ }}`
//! expression parser.
//!
//! Each target is written so that `zig build test` (no `--fuzz`) still runs it
//! once per corpus entry — that keeps the seeds working as ordinary regression
//! tests. Continuous fuzzing is `zig build fuzz --fuzz`.
//!
//! Corpus / regression policy: the seed corpus lives inline below, next to the
//! target it seeds. A crash found by fuzzing is fixed with a *named unit test*
//! in the module that owns the bug (`src/yaml/parser.zig` etc.) carrying the
//! minimized input; only inputs that also open up new territory for the fuzzer
//! are added here as seeds. No binary corpus directory is checked in — the
//! cache under `.zig-cache/v/` is disposable and must never be a prerequisite
//! for reproducing a fixed bug.

const std = @import("std");

const tokenizer = @import("yaml/tokenizer.zig");
const yaml_parser = @import("yaml/parser.zig");
const expressions = @import("rules/expressions.zig");
const diagnostics = @import("diagnostics.zig");

/// Seeds shared by the YAML targets: the shapes a workflow file is made of,
/// plus the indicators that drive the tokenizer's flow/block state machine.
const yaml_corpus: []const []const u8 = &.{
    "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
    "a: {b: [1, 2], c: 'x'}\n",
    "a: |\n  line one\n  line two\n",
    "a: >-\n  folded\n  scalar\n",
    "- - - nested\n",
    "---\na: 1\n...\n",
    "key: \"unterminated\n",
    "run: echo ${{ github.event.head_commit.message }}\n",
    "run: echo ${{ unclosed\n",
    "\t: tab indent\n",
    "# comment only\n",
    ":\n",
    "x: &c\n  runs-on: ubuntu-latest\njob:\n  <<: *c\n",
    "a: &a\n  b: *a\n",
    "a: &a\n  x: *b\nb: &b\n  y: *a\n",
    "a: &a [1, 2]\nb: &b [*a, *a]\nc: [*b, *b]\n",
    "job:\n  <<: *missing\n",
    "run: rm *.log && echo *\n",
};

test "fuzz: yaml tokenizer never leaves the source buffer" {
    const Context = struct {
        fn testOne(_: @This(), input: []const u8) anyerror!void {
            var tok = tokenizer.Tokenizer.init(input);
            // A tokenizer that stops making progress would hang the fuzzer
            // instead of failing it, so the loop is bounded: every token must
            // consume at least one byte, apart from the zero-width markers
            // (stream_start / eof), which is at most len + 2 tokens.
            var budget = input.len + 3;
            while (budget > 0) : (budget -= 1) {
                const token = tok.next();
                try std.testing.expect(token.start <= token.end);
                try std.testing.expect(token.end <= input.len);
                try std.testing.expect(token.line >= 1);
                try std.testing.expect(token.column >= 1);
                if (token.kind == .eof) return;
            }
            return error.TokenizerDidNotReachEof;
        }
    };
    try std.testing.fuzz(Context{}, Context.testOne, .{ .corpus = yaml_corpus });
}

test "fuzz: yaml parser survives arbitrary input" {
    const Context = struct {
        fn testOne(_: @This(), input: []const u8) anyerror!void {
            var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
            defer arena.deinit();

            var parser = yaml_parser.Parser.init(arena.allocator(), input);
            // `parse` declares its failures as `ParseError`, so any error it
            // returns here is by definition expected. What this target looks
            // for is the undeclared kind: a panic, an `unreachable`, an
            // out-of-bounds slice, or a hang.
            _ = parser.parse() catch return;
        }
    };
    try std.testing.fuzz(Context{}, Context.testOne, .{ .corpus = yaml_corpus });
}

test "fuzz: expression parser survives arbitrary input" {
    const Context = struct {
        fn testOne(_: @This(), input: []const u8) anyerror!void {
            var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
            defer arena.deinit();

            var list = diagnostics.DiagnosticList.init(arena.allocator());
            defer list.deinit();

            // validateExpression cannot fail: it reports through `list`. The
            // property is that every diagnostic it produces is well-formed,
            // since these flow straight into the JSON and SARIF writers.
            expressions.validateExpression(
                arena.allocator(),
                input,
                diagnostics.Span.point(1, 1, 0),
                &list,
                0,
            );
            var i: usize = 0;
            while (i < list.len()) : (i += 1) {
                const diag = list.get(i);
                try std.testing.expect(diag.rule_id.len > 0);
                try std.testing.expect(diag.message.len > 0);
            }
        }
    };
    try std.testing.fuzz(Context{}, Context.testOne, .{ .corpus = &.{
        "github.event.head_commit.message",
        "contains(github.ref, 'main') && !cancelled()",
        "fromJSON(inputs.matrix)[0].name",
        "((((((((((a))))))))))",
        "a ==",
        "'unterminated",
        "steps.x.outputs['k']",
        "matrix.*.name",
        "1 > 2 || 3 <= 4",
        "",
    } });
}
