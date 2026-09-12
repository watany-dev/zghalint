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
const config_mod = @import("config.zig");
const dependabot = @import("rules/dependabot.zig");

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
    SerializerCountMismatch,
    ConfigNotDeterministic,
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
    "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.event.issue.title\n          }}\n",
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
    // Layouts the campaign proved the insertion anchors turn on: a root
    // mapping written indented, a mapping opened on its key's own line, a
    // `with:` block off the usual grid, and a job body sharing the id's line.
    "  on: push\n  jobs:\n    b:\n      runs-on: ubuntu-latest\n      steps:\n        - run: echo hi\n",
    "on: push:\njobs:\n  b: runs-on: ubuntu-latest\n",
    "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n         node-version: 20\n",
    // `.zghalint.yml`: the config parser and the glob matcher.
    "rules:\n  SEC001:\n    enabled: false\n  BP001:\n    severity: warning\nignore:\n  - \"**/generated/*.yml\"\noutput:\n  format: sarif\n  color: never\nrunner:\n  labels:\n    - my-runner\n",
    // `dependabot.yml`: its own linter, reached by no other property here.
    "version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: \"/\"\n    schedule:\n      interval: weekly\n",
    // A composite action and a reusable workflow's input surface.
    "name: a\ndescription: d\ninputs:\n  x:\n    required: true\nruns:\n  using: composite\n  steps:\n    - run: echo ${{ inputs.x }}\n      shell: bash\n",
    "on:\n  workflow_call:\n    inputs:\n      x:\n        type: string\n        required: true\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ inputs.y }}\n",
    // Block scalars whose indentation the campaign proved the fix anchors turn
    // on: an explicit indentation indicator, chomping, and content that starts
    // further left than its own key.
    "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |2\n         echo hi\n",
    "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |+\n\n\n      - run: >-\n          echo hi\n",
    // Job sections no seed reaches: a matrix with include / exclude, an
    // environment, a service container and job-level defaults and outputs.
    "on: push\njobs:\n  b:\n    runs-on: ${{ matrix.os }}\n    environment:\n      name: prod\n      url: https://x\n    defaults:\n      run:\n        shell: bash\n        working-directory: ./sub\n    outputs:\n      o: ${{ steps.s.outputs.v }}\n    strategy:\n      fail-fast: false\n      max-parallel: 2\n      matrix:\n        os: [ubuntu-latest, macos-latest]\n        include:\n          - os: ubuntu-latest\n            n: 20\n        exclude:\n          - os: macos-latest\n    services:\n      db:\n        image: postgres:16\n        ports:\n          - 5432:5432\n        options: --health-cmd pg_isready\n    container:\n      image: node:20\n      credentials:\n        username: u\n        password: ${{ secrets.P }}\n    steps:\n      - id: s\n        run: echo v=1 >> $GITHUB_OUTPUT\n",
    // Background / wait / parallel step control flow (GA5).
    "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - id: s\n        background: true\n        run: echo v=1 >> $GITHUB_OUTPUT\n      - wait: s\n      - wait-all:\n      - cancel: s\n      - parallel:\n          - run: echo a\n          - run: echo b\n",
    // Unsynchronized background outputs (GA6 / EXPR019).
    "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - id: s\n        background: true\n        run: echo v=1 >> $GITHUB_OUTPUT\n      - run: echo ${{ steps.s.outputs.v }}\n      - wait: s\n",
    // Shapes the YAML layer alone decides: a tag, an explicit key, a directive,
    // a quoted key, and a second document after the workflow.
    "%YAML 1.2\n---\n!!map\non: !!str push\n? jobs\n: b:\n    runs-on: ubuntu-latest\n---\nsecond: doc\n",
    "\"on\": push\n'jobs':\n  \"b\":\n    runs-on: ubuntu-latest\n",
    // CRLF throughout: every span the rules report is a byte offset into this.
    "on: push\r\njobs:\r\n  b:\r\n    runs-on: ubuntu-latest\r\n    steps:\r\n      - run: echo hi\r\n",
    // The trigger surface below `on:`: event filters, a cron schedule, and the
    // `workflow_run` / `workflow_dispatch` inputs no other seed writes out.
    "on:\n  push:\n    branches: [main]\n    paths-ignore:\n      - \"docs/**\"\n  pull_request:\n    types: [opened, synchronize]\n    branches-ignore:\n      - wip/**\n  schedule:\n    - cron: \"0 * * * *\"\n  workflow_run:\n    workflows: [\"CI\"]\n    types: [completed]\n  workflow_dispatch:\n    inputs:\n      env:\n        type: choice\n        options: [dev, prod]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
    // `runs-on:` as a mapping, workflow-level `env` and `concurrency`, and the
    // status / hash expression functions the `if:` checker keys off.
    "name: w\nconcurrency:\n  group: ${{ github.workflow }}-${{ github.ref }}\n  cancel-in-progress: true\nenv:\n  A: 1\non: push\njobs:\n  b:\n    runs-on:\n      group: my-group\n      labels: [self-hosted, linux]\n    if: always() && contains(github.event.head_commit.message, 'x')\n    steps:\n      - uses: actions/cache@v4\n        with:\n          key: ${{ runner.os }}-${{ hashFiles('**/lock') }}\n          path: |\n            a\n            b\n",
    // A reusable workflow called with `with:` and named secrets, plus the job
    // `needs` / `outputs` wiring between the two.
    "on: push\njobs:\n  a:\n    uses: o/r/.github/workflows/w.yml@v1\n    with:\n      x: 1\n    secrets:\n      T: ${{ secrets.T }}\n  b:\n    needs: [a]\n    if: ${{ failure() || needs.a.result == 'success' }}\n    runs-on: ubuntu-latest\n    steps:\n      - uses: docker://alpine:3\n        with:\n          entrypoint: /bin/sh\n          args: -c echo\n",
    // `action.yml` shapes the composite seed misses: a node runner with pre /
    // post hooks, a docker runner, outputs and branding.
    "name: a\ndescription: d\nbranding:\n  icon: activity\n  color: blue\ninputs:\n  x:\n    description: d\n    default: \"1\"\noutputs:\n  o:\n    description: d\n    value: ${{ steps.s.outputs.v }}\nruns:\n  using: node20\n  main: dist/index.js\n  pre: dist/pre.js\n  post: dist/post.js\n",
    "name: a\ndescription: d\nruns:\n  using: docker\n  image: Dockerfile\n  args:\n    - ${{ inputs.x }}\n  env:\n    A: 1\n",
    // `permissions:` as a mapping of scopes, which no seed writes: the only
    // ones here are `write-all` and the absent form.
    "on: push\npermissions:\n  contents: read\n  id-token: write\njobs:\n  b:\n    permissions: {}\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n  c:\n    permissions:\n      contents: write\n      pull-requests: write\n      actions: none\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
    // A whole workflow in flow style. Every span the fix engine anchors on
    // then sits inside `{}` / `[]` rather than on a line of its own.
    "{on: push, jobs: {b: {runs-on: ubuntu-latest, steps: [{run: 'echo hi'}, {uses: actions/checkout@v4, with: {ref: main}}]}}}\n",
    // The expression surface beyond the status functions: indexing, nesting a
    // call inside a string, and the JSON helpers the matrix form uses.
    "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix: ${{ fromJSON(needs.a.outputs.m) }}\n    steps:\n      - run: echo \"${{ format('{0}-{1}', github.event.inputs['x'], toJSON(matrix)) }}\"\n        if: ${{ !cancelled() && join(github.event.commits.*.id, ',') != '' }}\n        env:\n          E: ${{ github.event['pull_request']['title'] }}\n",
    // Multibyte text in keys, values and comments. Every span a rule reports
    // and every byte the fix engine inserts at is an offset into these bytes.
    "name: ワークフロー \u{1F600}\non: push\njobs:\n  ジョブ:\n    runs-on: ubuntu-latest\n    steps:\n      - name: ステップ\n        run: echo \"日本語 ${{ github.event.issue.title }}\" # コメント\n",
    // A comment on every line, including between a key and its block. An
    // insertion anchored on the block's first entry lands after them.
    "# top\non: push # trailing\n# before jobs\njobs: # on the key\n  # before the id\n  b:\n    # before runs-on\n    runs-on: ubuntu-latest # trailing\n    steps:\n      # before the step\n      - run: echo hi # trailing\n",
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
    // `.zghalint.yml`, `dependabot.yml` and the composite / reusable shapes.
    "rules:",
    "ignore:",             "severity:",                       "enabled:",                        "output:",
    "format:",             "color:",                          "runner:",                         "labels:",
    "visibility:",         "version: 2",                      "updates:",                        "package-ecosystem:",
    "directory:",          "schedule:",                       "interval:",                       "github-actions",
    "using: composite",    "description:",                    "inputs:",                         "required:",
    "type:",               "default:",                        "**/*.yml",                        "*",
    "?",                   "**",
    // The block scalar header, which decides where the content starts and
    // therefore where an inserted key lands.
                                 "|2",                              "|-2",
    "|+",                  ">2",                              ">+",                              "|1",
    // Shapes only the YAML layer sees: tags, directives, explicit keys, a lone
    // carriage return, and a colon with no space after it.
    "!!str",               "!!map",                           "!tag",                            "%YAML 1.2",
    "? ",                  "\r",                              ":x",                              " \n",
    // The trigger filters, the `runs-on:` mapping form and the expression
    // functions the new seeds introduce.
    "branches:",           "branches-ignore:",                "paths:",                          "paths-ignore:",
    "tags:",               "types:",                          "schedule:",                       "cron:",
    "workflows:",          "group:",                          "labels:",                         "cancel-in-progress:",
    "always()",            "failure()",                       "success()",                       "cancelled()",
    "hashFiles(",          "contains(",                       "startsWith(",                     "runner.os",
    "github.workflow",
    // `action.yml` runners and their hooks.
        "using: node20",                   "using: docker",                   "main:",
    "pre:",                "post:",                           "image:",                          "args:",
    "entrypoint:",         "branding:",
    // The permission scopes, the JSON and formatting helpers, and a multibyte
    // run of bytes the span math has to carry through unchanged.
                          "id-token:",                       "contents:",
    "pull-requests:",      "write-all",                       "fromJSON(",                       "toJSON(",
    "format(",             "join(",                           "['x']",                           ".*",
    "!cancelled()",
    "日本語",
    "\u{1F600}",
};

const Mutator = struct {
    rng: std.Random,
    corpus: []const []const u8,

    fn pick(self: Mutator, slice: []const []const u8) []const u8 {
        return slice[self.rng.uintLessThan(usize, slice.len)];
    }

    fn lineStart(_: Mutator, s: []const u8, at: usize) usize {
        return if (std.mem.lastIndexOfScalar(u8, s[0..at], '\n')) |i| i + 1 else 0;
    }

    fn lineEnd(_: Mutator, s: []const u8, at: usize) usize {
        return if (std.mem.indexOfScalarPos(u8, s, at, '\n')) |i| i + 1 else s.len;
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
        switch (self.rng.uintLessThan(u8, 24)) {
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
            // Re-indent a whole line to an arbitrary width. Stepping by two
            // keeps a line on the grid the surrounding block already uses; the
            // bugs live off it, where a line is deeper than its parent but
            // shallower than its sibling.
            10 => {
                if (len == 0) return;
                const at = self.rng.uintLessThan(usize, len);
                const start = if (std.mem.lastIndexOfScalar(u8, buf.items[0..at], '\n')) |i| i + 1 else 0;
                var old: usize = 0;
                while (start + old < len and (buf.items[start + old] == ' ' or buf.items[start + old] == '\t')) {
                    old += 1;
                }
                const spaces = "                ";
                const want = self.rng.uintAtMost(usize, spaces.len);
                try buf.replaceRange(alloc, start, old, spaces[0..want]);
            },
            // Join two lines by dropping the newline between them, so several
            // keys share one line (`b: strategy: fail-fast: false`). An entry
            // whose extent is read off its own line gets that shape wrong in
            // both directions, and reaching it by chance alone is rare.
            11 => {
                if (len == 0) return;
                const at = self.rng.uintLessThan(usize, len);
                const nl = std.mem.indexOfScalarPos(u8, buf.items, at, '\n') orelse return;
                var end = nl + 1;
                // Take the next line's indentation with the newline, otherwise
                // the join only moves the gap rather than closing it.
                while (end < buf.items.len and (buf.items[end] == ' ' or buf.items[end] == '\t')) end += 1;
                buf.replaceRangeAssumeCapacity(nl, end - nl, &.{});
            },
            // Reopen a line's value as a flow collection that closes below it.
            // A collection written across lines ends past the key's own line,
            // which is where an insertion anchored on that line lands wrong.
            12 => {
                if (len == 0) return;
                const at = self.rng.uintLessThan(usize, len);
                const nl = std.mem.indexOfScalarPos(u8, buf.items, at, '\n') orelse len;
                const open: []const u8 = if (self.rng.boolean()) "[\n" else "{\n";
                const close: []const u8 = if (open[0] == '[') "\n]" else "\n}";
                try buf.insertSlice(alloc, nl, close);
                const start = if (std.mem.lastIndexOfScalar(u8, buf.items[0..at], '\n')) |i| i + 1 else 0;
                const colon = std.mem.indexOfScalarPos(u8, buf.items, start, ':') orelse start;
                try buf.insertSlice(alloc, @min(colon + 1, buf.items.len), open);
            },
            // Open a quoted scalar without closing it. The scalar then runs to
            // the end of the file, so the entry has no boundary after it.
            13 => {
                const quote: []const u8 = if (self.rng.boolean()) "\"" else "'";
                try buf.insertSlice(alloc, self.rng.uintAtMost(usize, len), quote);
            },
            // Put a comment at the end of a line. A comment sits exactly where
            // an insertion anchored on the line's end lands, and a `#` dropped
            // at a random offset almost always lands mid-token instead.
            14 => {
                if (len == 0) return;
                const at = self.rng.uintLessThan(usize, len);
                const nl = std.mem.indexOfScalarPos(u8, buf.items, at, '\n') orelse len;
                const comment: []const u8 = if (self.rng.boolean()) " # c" else "  #";
                try buf.insertSlice(alloc, nl, comment);
            },
            // Wrap a line's value in `${{ }}`. The expression rules and the
            // fix builder both key off the whole value being one expression,
            // and splicing `${{` and `}}` in separately rarely brackets one.
            15 => {
                if (len == 0) return;
                const at = self.rng.uintLessThan(usize, len);
                const start = if (std.mem.lastIndexOfScalar(u8, buf.items[0..at], '\n')) |i| i + 1 else 0;
                const nl = std.mem.indexOfScalarPos(u8, buf.items, start, '\n') orelse len;
                const colon = std.mem.indexOfScalarPos(u8, buf.items, start, ':') orelse return;
                if (colon >= nl) return;
                try buf.insertSlice(alloc, nl, " }}");
                try buf.insertSlice(alloc, colon + 1, " ${{");
            },
            // Graft a line from another corpus entry into the middle of this
            // one. The splice in `generate` replaces everything after its cut,
            // so a foreign job body never lands under an existing `jobs:`;
            // grafted at a line boundary it does.
            16 => {
                const other = self.pick(self.corpus);
                if (other.len == 0) return;
                const from = self.lineStart(other, self.rng.uintLessThan(usize, other.len));
                const at = if (len == 0) 0 else self.lineStart(buf.items, self.rng.uintLessThan(usize, len));
                try buf.insertSlice(alloc, at, other[from..self.lineEnd(other, from)]);
            },
            // Move a line to another line boundary, so keys appear out of the
            // order they are written in (`steps:` above `runs-on:`, a sequence
            // entry away from its parent). No edit in place produces that.
            17 => {
                if (len == 0) return;
                const start = self.lineStart(buf.items, self.rng.uintLessThan(usize, len));
                const end = self.lineEnd(buf.items, start);
                const line = try alloc.dupe(u8, buf.items[start..end]);
                defer alloc.free(line);
                buf.replaceRangeAssumeCapacity(start, end - start, &.{});
                const rest = buf.items.len;
                const at = if (rest == 0) 0 else self.lineStart(buf.items, self.rng.uintLessThan(usize, rest));
                try buf.insertSlice(alloc, at, line);
            },
            // Rewrite a line's value as a block scalar with a body under it.
            // The header alone is in the dictionary, but content indented past
            // the key is what decides where the scalar ends, and splicing a
            // header in at random almost never leaves any.
            18 => {
                if (len == 0) return;
                const at = self.rng.uintLessThan(usize, len);
                const start = self.lineStart(buf.items, at);
                const nl = std.mem.indexOfScalarPos(u8, buf.items, start, '\n') orelse len;
                const colon = std.mem.indexOfScalarPos(u8, buf.items, start, ':') orelse return;
                if (colon + 1 >= nl) return;
                var indent: usize = 0;
                while (start + indent < nl and buf.items[start + indent] == ' ') indent += 1;
                const header = self.pick(&.{ "|", "|-", "|+", ">", ">-", "|2", ">1" });
                const body = try alloc.dupe(u8, buf.items[colon + 1 .. nl]);
                defer alloc.free(body);
                // Two past the key's own indent, the width a block scalar with
                // no indicator takes from its first line.
                const pad = "                                ";
                const want = @min(indent + 2, pad.len);
                try buf.replaceRange(alloc, colon + 1, body.len, header);
                try buf.insertSlice(alloc, colon + 1 + header.len, "\n");
                try buf.insertSlice(alloc, colon + 1 + header.len + 1, pad[0..want]);
                try buf.insertSlice(alloc, colon + 1 + header.len + 1 + want, body);
            },
            // Rewrite the file's line endings as CRLF. The tokenizer carries
            // the carriage return through spans and scalar values, and a lone
            // "\r\n" spliced mid-line reaches none of that.
            19 => {
                if (len == 0) return;
                var out: std.ArrayList(u8) = .empty;
                defer out.deinit(alloc);
                for (buf.items) |c| {
                    if (c == '\n') try out.append(alloc, '\r');
                    try out.append(alloc, c);
                }
                buf.clearRetainingCapacity();
                try buf.appendSlice(alloc, out.items);
            },
            // A decoded value is shorter than the source token it came from, so
            // an offset into the value is not an offset into the file -- the
            // same shape aliases have. Splicing `\n` in at random lands it
            // outside quotes, where it is only two plain characters.
            20 => {
                if (len == 0) return;
                const at = self.rng.uintLessThan(usize, len);
                const start = self.lineStart(buf.items, at);
                const nl = std.mem.indexOfScalarPos(u8, buf.items, start, '\n') orelse len;
                const colon = std.mem.indexOfScalarPos(u8, buf.items, start, ':') orelse return;
                if (colon + 1 >= nl) return;
                var quoted: std.ArrayList(u8) = .empty;
                defer quoted.deinit(alloc);
                try quoted.appendSlice(alloc, " \"");
                for (buf.items[colon + 1 .. nl]) |c| {
                    if (c == '"' or c == '\\') try quoted.append(alloc, '\\');
                    try quoted.append(alloc, c);
                }
                try quoted.appendSlice(alloc, self.pick(&.{
                    "\\n",     "\\t",     "\\\"", "\\\\",
                    "\\u00e9", "\\x41",   "\\0",  "\\N",
                    "\\ ",     "\\u{1F}", "\\",
                }));
                try quoted.append(alloc, '"');
                try buf.replaceRange(alloc, colon + 1, nl - (colon + 1), quoted.items);
            },
            // Anchor one line's value and alias it from another. An alias node
            // carries the spans of the value that defined it, so an offset in
            // it points at a line elsewhere in the file. `&anchor` and
            // `*anchor` are in the dictionary, but two random splices almost
            // never name the same anchor, and an unresolved alias is a
            // different path from a resolved one.
            21 => {
                if (len == 0) return;
                const name = self.pick(&.{ "a", "b", "c" });
                var mark: [8]u8 = undefined;

                const def = self.lineStart(buf.items, self.rng.uintLessThan(usize, len));
                const def_nl = std.mem.indexOfScalarPos(u8, buf.items, def, '\n') orelse len;
                const def_colon = std.mem.indexOfScalarPos(u8, buf.items, def, ':') orelse return;
                if (def_colon >= def_nl) return;
                try buf.insertSlice(alloc, def_colon + 1, std.fmt.bufPrint(&mark, " &{s}", .{name}) catch return);

                const use = self.lineStart(buf.items, self.rng.uintLessThan(usize, buf.items.len));
                const use_nl = std.mem.indexOfScalarPos(u8, buf.items, use, '\n') orelse buf.items.len;
                const use_colon = std.mem.indexOfScalarPos(u8, buf.items, use, ':') orelse return;
                if (use_colon >= use_nl) return;
                const alias = std.fmt.bufPrint(&mark, " *{s}", .{name}) catch return;
                try buf.replaceRange(alloc, use_colon + 1, use_nl - (use_colon + 1), alias);
            },
            // Fold one mapping into another with a merge key. The entries a
            // merge brings in are spanned where they were written, so a fix
            // that edits or removes one lands in a block other than the one
            // the diagnostic names. `<<:` is in the dictionary, but a merge
            // only happens when its value resolves to a mapping.
            22 => {
                if (len == 0) return;
                const name = self.pick(&.{ "a", "b", "c" });
                var mark: [8]u8 = undefined;

                const def = self.lineStart(buf.items, self.rng.uintLessThan(usize, len));
                const def_nl = std.mem.indexOfScalarPos(u8, buf.items, def, '\n') orelse len;
                const def_colon = std.mem.indexOfScalarPos(u8, buf.items, def, ':') orelse return;
                if (def_colon >= def_nl) return;
                try buf.insertSlice(alloc, def_colon + 1, std.fmt.bufPrint(&mark, " &{s}", .{name}) catch return);

                const at = self.lineStart(buf.items, self.rng.uintLessThan(usize, buf.items.len));
                var indent: usize = 0;
                while (at + indent < buf.items.len and buf.items[at + indent] == ' ') indent += 1;
                var line: std.ArrayList(u8) = .empty;
                defer line.deinit(alloc);
                try line.appendNTimes(alloc, ' ', indent);
                try line.appendSlice(alloc, "<<: *");
                try line.appendSlice(alloc, name);
                try line.append(alloc, '\n');
                try buf.insertSlice(alloc, at, line.items);
            },
            // Rewrite a line's `k: v` as an explicit key (`? k` over `: v`).
            // The key and its value then sit on different lines and the key's
            // own line carries no colon, so an anchor taken from the key line
            // is nowhere near the value. `? ` is in the dictionary, but spliced
            // at a random offset it is two plain characters.
            23 => {
                if (len == 0) return;
                const start = self.lineStart(buf.items, self.rng.uintLessThan(usize, len));
                const nl = std.mem.indexOfScalarPos(u8, buf.items, start, '\n') orelse len;
                const colon = std.mem.indexOfScalarPos(u8, buf.items, start, ':') orelse return;
                if (colon >= nl) return;
                var indent: usize = 0;
                while (start + indent < nl and buf.items[start + indent] == ' ') indent += 1;

                var line: std.ArrayList(u8) = .empty;
                defer line.deinit(alloc);
                try line.append(alloc, '\n');
                try line.appendNTimes(alloc, ' ', indent);
                try line.append(alloc, ':');
                try buf.replaceRange(alloc, colon, 1, line.items);
                try buf.insertSlice(alloc, start + indent, "? ");
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

/// Length of the array reached by walking `path` through JSON objects, or null
/// when the path does not lead to one.
fn arrayLen(value: std.json.Value, path: []const []const u8) ?usize {
    var current = value;
    for (path) |key| {
        current = switch (current) {
            .object => |o| o.get(key) orelse return null,
            else => return null,
        };
    }
    return switch (current) {
        .array => |a| a.items.len,
        else => null,
    };
}

/// The JSON and SARIF writers hand their bytes to CI systems, so "it rendered"
/// is not the property -- "a parser accepts it" is.
fn checkSerializers(
    alloc: std.mem.Allocator,
    list: diagnostics.DiagnosticList,
) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);

    var json_count: ?usize = null;
    {
        var w = std.Io.Writer.Allocating.fromArrayList(alloc, &buf);
        json_out.renderJson(&w.writer, list, 1) catch return;
        buf = w.toArrayList();
        var parsed = std.json.parseFromSlice(std.json.Value, alloc, buf.items, .{}) catch
            return Violation.JsonOutputNotValid;
        defer parsed.deinit();
        json_count = arrayLen(parsed.value, &.{"diagnostics"});
    }

    buf.clearRetainingCapacity();
    {
        var w = std.Io.Writer.Allocating.fromArrayList(alloc, &buf);
        sarif_out.renderSarif(&w.writer, list, &registry.all_rules) catch return;
        buf = w.toArrayList();
        var parsed = std.json.parseFromSlice(std.json.Value, alloc, buf.items, .{}) catch
            return Violation.SarifOutputNotValid;
        defer parsed.deinit();
        const runs = switch (parsed.value) {
            .object => |o| o.get("runs") orelse return Violation.SarifOutputNotValid,
            else => return Violation.SarifOutputNotValid,
        };
        const first_run = switch (runs) {
            .array => |a| if (a.items.len == 1) a.items[0] else return Violation.SarifOutputNotValid,
            else => return Violation.SarifOutputNotValid,
        };
        // Two reports of the same run must agree on how many findings there
        // were: a formatter that drops one silently hides it from CI.
        const sarif_count = arrayLen(first_run, &.{"results"}) orelse return Violation.SarifOutputNotValid;
        if (json_count) |n| {
            if (n != sarif_count) return Violation.SerializerCountMismatch;
        }
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

/// `.zghalint.yml` is a second untrusted file the tool parses, and one that
/// changes what every rule reports. The queries are part of the surface: an
/// override table or a glob is only useful if it can be asked about.
fn checkConfigPath(alloc: std.mem.Allocator, input: []const u8) !void {
    var cfg = config_mod.parseConfig(alloc, input) catch return;
    defer cfg.deinit();

    var digest_a: u64 = 0;
    for (registry.all_rules) |rule| {
        digest_a = digest_a *% 31 +% @intFromBool(cfg.isRuleEnabled(rule.id));
        digest_a = digest_a *% 31 +% @intFromEnum(cfg.getEffectiveSeverity(rule.id, rule.severity));
    }
    for (config_query_paths) |path| {
        digest_a = digest_a *% 31 +% @intFromBool(cfg.isIgnored(path));
    }

    // The config outlives the source buffer it was parsed from, so a second
    // parse answering differently means a string escaped the arena.
    var again = config_mod.parseConfig(alloc, input) catch return Violation.ConfigNotDeterministic;
    defer again.deinit();

    var digest_b: u64 = 0;
    for (registry.all_rules) |rule| {
        digest_b = digest_b *% 31 +% @intFromBool(again.isRuleEnabled(rule.id));
        digest_b = digest_b *% 31 +% @intFromEnum(again.getEffectiveSeverity(rule.id, rule.severity));
    }
    for (config_query_paths) |path| {
        digest_b = digest_b *% 31 +% @intFromBool(again.isIgnored(path));
    }

    if (digest_a != digest_b) return Violation.ConfigNotDeterministic;
}

/// Paths fed to `isIgnored`, which is where the glob matcher runs. The shapes
/// matter more than the names: a bare file, nested directories, a dotfile
/// directory and a path with no separator at all.
const config_query_paths: []const []const u8 = &.{
    ".github/workflows/ci.yml",
    ".github/workflows/nested/deploy.yaml",
    "ci.yml",
    "",
    "a/b/c/d/e/f/g.yml",
};

/// `dependabot.yml` takes untrusted bytes down a path of its own: it never
/// reaches the workflow parser, so nothing else in this driver covers it.
fn checkDependabotPath(alloc: std.mem.Allocator, input: []const u8) !void {
    var yp = yaml_parser.Parser.init(alloc, input);
    const node = yp.parse() catch return;
    var list = diagnostics.DiagnosticList.init(alloc);
    defer list.deinit();
    dependabot.lintDependabot(node, &list);
    try checkDiagnostics(list, input);
    try checkSerializers(alloc, list);
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

    try checkConfigPath(alloc, input);
    try checkDependabotPath(alloc, input);

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
