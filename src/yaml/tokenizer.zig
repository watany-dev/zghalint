const std = @import("std");

pub const TokenKind = enum {
    stream_start,
    document_start,
    document_end,
    mapping_key,
    mapping_value,
    sequence_entry,
    scalar,
    anchor,
    alias,
    flow_mapping_start,
    flow_mapping_end,
    flow_sequence_start,
    flow_sequence_end,
    flow_entry,
    comment,
    newline,
    eof,
};

pub const Token = struct {
    kind: TokenKind,
    start: usize,
    end: usize,
    line: u32,
    column: u32,

    pub fn slice(self: Token, source: []const u8) []const u8 {
        return source[self.start..self.end];
    }
};

pub const Tokenizer = struct {
    source: []const u8,
    pos: usize,
    line: u32,
    column: u32,
    started: bool,
    /// Nesting depth of `[` / `{` flow collections. `,` `]` `}` are YAML
    /// indicators only inside a flow context; in block context they are
    /// ordinary plain-scalar characters (e.g. a `run:` command line).
    flow_depth: u32,
    /// End of the line on which a `${{` was last found to have no closing
    /// `}}`. Every later `${{` on that line shares the same (empty) search
    /// range, so it is skipped without rescanning.
    expr_unclosed_line_end: usize,

    /// UTF-8 byte order mark. Windows editors prepend it; it carries no
    /// YAML meaning, so the tokenizer starts past it. The bytes stay in
    /// `source` so every span keeps pointing at real file offsets.
    pub const utf8_bom = "\xEF\xBB\xBF";

    pub fn init(source: []const u8) Tokenizer {
        const start: usize = if (std.mem.startsWith(u8, source, utf8_bom)) utf8_bom.len else 0;
        return .{
            .source = source,
            .pos = start,
            .line = 1,
            .column = 1,
            .started = false,
            .flow_depth = 0,
            .expr_unclosed_line_end = 0,
        };
    }

    pub fn next(self: *Tokenizer) Token {
        if (!self.started) {
            self.started = true;
            return .{
                .kind = .stream_start,
                .start = 0,
                .end = 0,
                .line = 1,
                .column = 1,
            };
        }

        if (self.pos >= self.source.len) {
            return .{
                .kind = .eof,
                .start = self.pos,
                .end = self.pos,
                .line = self.line,
                .column = self.column,
            };
        }

        const c = self.source[self.pos];

        if (c == '#') {
            return self.scanComment();
        }

        if (self.atBreak()) {
            return self.scanNewline();
        }

        if (c == ' ' or c == '\t') {
            self.skipWhitespace();
            if (self.pos >= self.source.len) {
                return .{
                    .kind = .eof,
                    .start = self.pos,
                    .end = self.pos,
                    .line = self.line,
                    .column = self.column,
                };
            }
            return self.next();
        }

        if (self.column == 1) {
            if (self.matchStr("---")) {
                self.flow_depth = 0;
                return self.emitSimple(.document_start, 3);
            }
            if (self.matchStr("...")) {
                self.flow_depth = 0;
                return self.emitSimple(.document_end, 3);
            }
        }

        // A `-` ending its line also opens an entry: `-\n  name: x` puts the
        // entry's mapping on the following lines, which every docker/*
        // workflow is written in (#293).
        if (c == '-' and self.isBlockSequenceIndicator()) {
            return self.emitSimple(.sequence_entry, 1);
        }

        // A plain scalar can never start with `{` or `[`, so those always open a
        // flow collection; the closing and separating indicators only count
        // while one is open.
        if (c == '{') {
            self.flow_depth += 1;
            return self.emitSimple(.flow_mapping_start, 1);
        }
        if (c == '[') {
            self.flow_depth += 1;
            return self.emitSimple(.flow_sequence_start, 1);
        }
        if (self.flow_depth > 0) {
            if (c == '}') {
                self.flow_depth -= 1;
                return self.emitSimple(.flow_mapping_end, 1);
            }
            if (c == ']') {
                self.flow_depth -= 1;
                return self.emitSimple(.flow_sequence_end, 1);
            }
            if (c == ',') return self.emitSimple(.flow_entry, 1);
        }

        if (c == ':' and self.colonStartsMappingValue(self.pos)) {
            return self.emitSimple(.mapping_value, 1);
        }

        if (c == '&' or c == '*') {
            if (self.scanAnchorOrAlias(if (c == '&') .anchor else .alias)) |token| return token;
        }

        if (c == '\'' or c == '"') {
            return self.scanQuotedScalar(c);
        }

        if (c == '|' or c == '>') {
            return self.scanBlockScalar();
        }

        return self.scanPlainScalar();
    }

    fn scanComment(self: *Tokenizer) Token {
        const start = self.pos;
        const line = self.line;
        const col = self.column;
        while (self.pos < self.source.len and !self.atBreak()) {
            self.advance();
        }
        return .{
            .kind = .comment,
            .start = start,
            .end = self.pos,
            .line = line,
            .column = col,
        };
    }

    fn scanNewline(self: *Tokenizer) Token {
        const start = self.pos;
        const line = self.line;
        const col = self.column;
        self.consumeNewline();
        return .{
            .kind = .newline,
            .start = start,
            .end = self.pos,
            .line = line,
            .column = col,
        };
    }

    /// `&` and `*` are YAML indicators only at the head of a node, and only
    /// when a name follows. Shell text puts both characters in the same
    /// position (`run: *.log`, `run: && make`), so the name is deliberately
    /// restricted to the identifier shape anchors actually take in workflows —
    /// letters, digits, `_`, `-` — and must be followed by a token boundary.
    /// Anything else stays ordinary plain-scalar text.
    fn scanAnchorOrAlias(self: *Tokenizer, kind: TokenKind) ?Token {
        var len: usize = 1;
        while (self.pos + len < self.source.len and isAnchorNameChar(self.source[self.pos + len])) {
            len += 1;
        }
        if (len == 1) return null;

        const after = self.pos + len;
        if (after < self.source.len) {
            const next_char = self.source[after];
            const boundary = next_char == ' ' or next_char == '\t' or
                next_char == ',' or next_char == ']' or next_char == '}' or
                self.isBreakAt(after);
            if (!boundary) return null;
        }

        return self.emitSimple(kind, len);
    }

    fn isAnchorNameChar(c: u8) bool {
        return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or c == '_' or c == '-';
    }

    fn scanQuotedScalar(self: *Tokenizer, quote: u8) Token {
        const start = self.pos;
        const line = self.line;
        const col = self.column;
        self.advance();
        while (self.pos < self.source.len) {
            if (self.source[self.pos] == quote) {
                if (quote == '\'' and self.pos + 1 < self.source.len and self.source[self.pos + 1] == '\'') {
                    self.advance();
                    self.advance();
                    continue;
                }
                self.advance();
                break;
            }
            if (quote == '"' and self.source[self.pos] == '\\') {
                self.advance();
                if (self.pos < self.source.len) {
                    // `\` + 改行は YAML の行継続。改行ごと食べるので行カウンタも進める。
                    if (self.atBreak()) self.consumeNewline() else self.advance();
                }
                continue;
            }
            if (self.atBreak()) {
                self.consumeNewline();
                continue;
            }
            self.advance();
        }
        return .{
            .kind = .scalar,
            .start = start,
            .end = self.pos,
            .line = line,
            .column = col,
        };
    }

    fn scanBlockScalar(self: *Tokenizer) Token {
        const start = self.pos;
        const line = self.line;
        const col = self.column;
        self.advance();

        while (self.pos < self.source.len and !self.atBreak()) {
            self.advance();
        }

        var base_indent: u32 = 0;
        if (self.pos < self.source.len) {
            const saved_pos = self.pos;
            const saved_line = self.line;
            const saved_col = self.column;
            self.consumeNewline();

            while (self.pos < self.source.len) {
                if (self.atBreak()) {
                    self.consumeNewline();
                    continue;
                }
                if (self.source[self.pos] == ' ') {
                    var indent: u32 = 0;
                    while (self.pos + indent < self.source.len and self.source[self.pos + indent] == ' ') {
                        indent += 1;
                    }
                    base_indent = indent;
                    break;
                }
                break;
            }
            self.pos = saved_pos;
            self.line = saved_line;
            self.column = saved_col;
        }

        while (self.atBreak()) {
            self.consumeNewline();

            var indent: u32 = 0;
            while (self.pos + indent < self.source.len and self.source[self.pos + indent] == ' ') {
                indent += 1;
            }

            if (self.pos + indent < self.source.len and !self.isBreakAt(self.pos + indent) and indent < base_indent) {
                break;
            }

            while (self.pos < self.source.len and !self.atBreak()) {
                self.advance();
            }
        }

        return .{
            .kind = .scalar,
            .start = start,
            .end = self.pos,
            .line = line,
            .column = col,
        };
    }

    /// A `${{ ... }}` expression is opaque to YAML scanning: `}` and `,` inside
    /// it are not flow indicators, and neither `#` nor `: ` inside it ends the
    /// scalar.
    fn skipExpressionInterpolation(self: *Tokenizer) bool {
        if (self.pos + 2 >= self.source.len) return false;
        if (self.source[self.pos] != '$') return false;
        if (self.source[self.pos + 1] != '{' or self.source[self.pos + 2] != '{') return false;

        // Unterminated, or closed only on a later line: fall back to normal
        // plain-scalar scanning. The search is confined to the current line
        // and its negative result is remembered, so a line full of `${{`
        // costs one pass rather than one pass per occurrence.
        if (self.pos < self.expr_unclosed_line_end) return false;
        const line_end = std.mem.indexOfScalarPos(u8, self.source, self.pos + 3, '\n') orelse self.source.len;
        const close = std.mem.indexOfPos(u8, self.source[0..line_end], self.pos + 3, "}}") orelse {
            self.expr_unclosed_line_end = line_end;
            return false;
        };
        while (self.pos < close + 2) self.advance();
        return true;
    }

    fn scanPlainScalar(self: *Tokenizer) Token {
        const start = self.pos;
        const line = self.line;
        const col = self.column;
        while (self.pos < self.source.len) {
            const ch = self.source[self.pos];
            if (self.skipExpressionInterpolation()) continue;
            if (self.atBreak() or ch == '#') break;
            if (self.flow_depth > 0 and (ch == ',' or ch == '{' or ch == '}' or ch == '[' or ch == ']')) {
                break;
            }
            if (ch == ':' and self.colonStartsMappingValue(self.pos)) {
                break;
            }
            self.advance();
        }
        var end = self.pos;
        while (end > start and self.source[end - 1] == ' ') {
            end -= 1;
        }
        return .{
            .kind = .scalar,
            .start = start,
            .end = end,
            .line = line,
            .column = col,
        };
    }

    fn advance(self: *Tokenizer) void {
        self.pos += 1;
        self.column += 1;
    }

    fn consumeNewline(self: *Tokenizer) void {
        if (self.pos < self.source.len and self.source[self.pos] == '\r') self.pos += 1;
        self.pos += 1;
        self.line += 1;
        self.column = 1;
    }

    /// Windows checkouts hand the linter CRLF files, so a `\r` that precedes a
    /// `\n` belongs to the line break and never to the token before it. A lone
    /// `\r` is ordinary scalar content, as in YAML.
    fn isBreakAt(self: *const Tokenizer, i: usize) bool {
        if (i >= self.source.len) return false;
        if (self.source[i] == '\n') return true;
        return self.source[i] == '\r' and i + 1 < self.source.len and self.source[i + 1] == '\n';
    }

    fn atBreak(self: *const Tokenizer) bool {
        return self.isBreakAt(self.pos);
    }

    fn skipWhitespace(self: *Tokenizer) void {
        while (self.pos < self.source.len and (self.source[self.pos] == ' ' or self.source[self.pos] == '\t')) {
            self.advance();
        }
    }

    /// YAML `s-white` is space or tab. A `:` is a mapping indicator only when
    /// the next character is s-white, a line break, or EOF (`ns-plain-safe`).
    fn isSWhiteAt(self: *const Tokenizer, i: usize) bool {
        if (i >= self.source.len) return false;
        const ch = self.source[i];
        return ch == ' ' or ch == '\t';
    }

    /// True when the `:` at `colon_pos` starts a mapping value rather than
    /// belonging to a plain scalar such as `http://example.com`.
    fn colonStartsMappingValue(self: *const Tokenizer, colon_pos: usize) bool {
        const after = colon_pos + 1;
        if (after >= self.source.len) return true;
        return self.isSWhiteAt(after) or self.isBreakAt(after);
    }

    /// True when the `-` at `pos` is a block sequence indicator rather than
    /// the first character of a plain scalar such as `-1` or `--flag`.
    fn isBlockSequenceIndicator(self: *const Tokenizer) bool {
        if (self.pos + 1 >= self.source.len) return self.flow_depth == 0;
        if (self.isSWhiteAt(self.pos + 1)) return true;
        return self.flow_depth == 0 and self.isBreakAt(self.pos + 1);
    }

    fn matchStr(self: *Tokenizer, str: []const u8) bool {
        if (self.pos + str.len > self.source.len) return false;
        if (self.pos + str.len < self.source.len) {
            const after = self.source[self.pos + str.len];
            if (after != '\n' and after != '\r' and after != ' ' and after != '\t') return false;
        }
        return std.mem.startsWith(u8, self.source[self.pos..], str);
    }

    fn emitSimple(self: *Tokenizer, kind: TokenKind, len: usize) Token {
        const start = self.pos;
        const line = self.line;
        const col = self.column;
        // Simple tokens never span a newline, so the cursor advances flat.
        self.pos += len;
        self.column += @intCast(len);
        return .{
            .kind = kind,
            .start = start,
            .end = self.pos,
            .line = line,
            .column = col,
        };
    }
};

test "tokenizer init" {
    const tokenizer = Tokenizer.init("name: CI");
    try std.testing.expectEqual(@as(usize, 0), tokenizer.pos);
    try std.testing.expectEqual(@as(u32, 1), tokenizer.line);
    try std.testing.expectEqual(@as(u32, 1), tokenizer.column);
    try std.testing.expectEqual(false, tokenizer.started);
}

test "tokenizer skips a leading UTF-8 BOM" {
    var tokenizer = Tokenizer.init("\xEF\xBB\xBFname: CI");
    try std.testing.expectEqual(@as(usize, 3), tokenizer.pos);
    _ = tokenizer.next();
    const key = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, key.kind);
    try std.testing.expectEqualStrings("name", key.slice(tokenizer.source));
    try std.testing.expectEqual(@as(u32, 1), key.line);
    try std.testing.expectEqual(@as(u32, 1), key.column);
}

test "tokenizer keeps a BOM appearing mid-stream" {
    var tokenizer = Tokenizer.init("a: \xEF\xBB\xBFb");
    try std.testing.expectEqual(@as(usize, 0), tokenizer.pos);
    _ = tokenizer.next();
    _ = tokenizer.next();
    _ = tokenizer.next();
    const value = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, value.kind);
    try std.testing.expectEqualStrings("\xEF\xBB\xBFb", value.slice(tokenizer.source));
}

test "tokenizer eof on empty input" {
    var tokenizer = Tokenizer.init("");
    const stream_start = tokenizer.next();
    try std.testing.expectEqual(TokenKind.stream_start, stream_start.kind);
    const eof = tokenizer.next();
    try std.testing.expectEqual(TokenKind.eof, eof.kind);
}

test "tokenizer stream_start" {
    var tokenizer = Tokenizer.init("hello");
    const token = tokenizer.next();
    try std.testing.expectEqual(TokenKind.stream_start, token.kind);
}

test "tokenizer plain scalar" {
    var tokenizer = Tokenizer.init("hello");
    _ = tokenizer.next();
    const token = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, token.kind);
    try std.testing.expectEqualStrings("hello", token.slice(tokenizer.source));
}

test "tokenizer plain scalar keeps a ${{ }} interpolation" {
    var tokenizer = Tokenizer.init("echo \"${{ github.event.issue.body }}\"");
    _ = tokenizer.next();
    const token = tokenizer.next();
    try std.testing.expectEqualStrings("echo \"${{ github.event.issue.body }}\"", token.slice(tokenizer.source));
}

test "tokenizer plain scalar keeps commas inside an interpolation" {
    var tokenizer = Tokenizer.init("echo \"${{ join(github.event.commits.*.message, ' ') }}\"");
    _ = tokenizer.next();
    const token = tokenizer.next();
    try std.testing.expectEqualStrings("echo \"${{ join(github.event.commits.*.message, ' ') }}\"", token.slice(tokenizer.source));
}

test "tokenizer plain scalar keeps an unterminated interpolation in block context" {
    var tokenizer = Tokenizer.init("echo ${{ oops");
    _ = tokenizer.next();
    const token = tokenizer.next();
    try std.testing.expectEqualStrings("echo ${{ oops", token.slice(tokenizer.source));
}

test "tokenizer: a line of unterminated ${{ is scanned in a single pass" {
    // Each `${{` used to search to end of input for `}}`; with 40k of them on
    // one line that was quadratic. The whole line must still be one scalar.
    const body = "run " ++ ("${{" ** 40000);
    var tokenizer = Tokenizer.init(body);
    _ = tokenizer.next();
    const token = tokenizer.next();
    try std.testing.expectEqualStrings(body, token.slice(tokenizer.source));
}

test "tokenizer: unterminated ${{ on one line does not disable skipping on the next" {
    var tokenizer = Tokenizer.init("a: ${{ oops\nb: [${{ x, y }}]");
    var saw_expr_scalar = false;
    while (true) {
        const tok = tokenizer.next();
        if (tok.kind == .eof) break;
        if (tok.kind == .scalar and std.mem.eql(u8, tok.slice(tokenizer.source), "${{ x, y }}")) saw_expr_scalar = true;
    }
    try std.testing.expect(saw_expr_scalar);
}

test "tokenizer plain scalar stops at an unterminated interpolation in flow context" {
    var tokenizer = Tokenizer.init("[echo ${{ oops]");
    _ = tokenizer.next();
    try std.testing.expectEqual(TokenKind.flow_sequence_start, tokenizer.next().kind);
    const token = tokenizer.next();
    try std.testing.expectEqualStrings("echo $", token.slice(tokenizer.source));
}

fn expectFirstScalar(source: []const u8, expected: []const u8) !void {
    var tokenizer = Tokenizer.init(source);
    while (true) {
        const token = tokenizer.next();
        switch (token.kind) {
            .scalar => return std.testing.expectEqualStrings(expected, token.slice(source)),
            .eof => return error.NoScalarFound,
            else => {},
        }
    }
}

test "tokenizer plain scalar keeps commas in block context" {
    try expectFirstScalar(
        "contains(github.event.issue.title, 'x')",
        "contains(github.event.issue.title, 'x')",
    );
}

test "tokenizer plain scalar keeps a quoted argument after a comma" {
    try expectFirstScalar(
        "startsWith(github.event.pull_request.head.ref, 'release/')",
        "startsWith(github.event.pull_request.head.ref, 'release/')",
    );
}

test "tokenizer plain scalar keeps brackets in block context" {
    try expectFirstScalar(
        "npm run build -- --flag [x]",
        "npm run build -- --flag [x]",
    );
}

test "tokenizer plain scalar keeps braces in block context" {
    try expectFirstScalar(
        "awk '{print $1}' file, other",
        "awk '{print $1}' file, other",
    );
}

test "tokenizer run: value is read to end of line" {
    var tokenizer = Tokenizer.init("run: echo a, b [c] {d}\nnext: 1\n");
    _ = tokenizer.next();
    try std.testing.expectEqualStrings("run", tokenizer.next().slice(tokenizer.source));
    try std.testing.expectEqual(TokenKind.mapping_value, tokenizer.next().kind);
    const value = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, value.kind);
    try std.testing.expectEqualStrings("echo a, b [c] {d}", value.slice(tokenizer.source));
    try std.testing.expectEqual(TokenKind.newline, tokenizer.next().kind);
}

// `: ` inside a plain scalar is invalid YAML, but a workflow that ships it is
// exactly the one worth linting, so the expression is scanned whole anyway.
test "tokenizer plain scalar keeps a colon inside an interpolation" {
    try expectFirstScalar(
        "echo ${{ format('{0}: {1}', github.event.issue.title, 'x') }}",
        "echo ${{ format('{0}: {1}', github.event.issue.title, 'x') }}",
    );
}

test "tokenizer plain scalar keeps a hash inside an interpolation" {
    try expectFirstScalar(
        "echo ${{ format('#{0}', github.event.issue.title) }} # trailing",
        "echo ${{ format('#{0}', github.event.issue.title) }}",
    );
}

test "tokenizer plain scalar still stops at a comment in block context" {
    try expectFirstScalar("echo a, b # trailing", "echo a, b");
}

test "tokenizer flow depth tracks nesting" {
    var tokenizer = Tokenizer.init("{a: [1, 2]}");
    _ = tokenizer.next();
    try std.testing.expectEqual(TokenKind.flow_mapping_start, tokenizer.next().kind);
    try std.testing.expectEqualStrings("a", tokenizer.next().slice(tokenizer.source));
    try std.testing.expectEqual(TokenKind.mapping_value, tokenizer.next().kind);
    try std.testing.expectEqual(TokenKind.flow_sequence_start, tokenizer.next().kind);
    try std.testing.expectEqualStrings("1", tokenizer.next().slice(tokenizer.source));
    try std.testing.expectEqual(TokenKind.flow_entry, tokenizer.next().kind);
    try std.testing.expectEqualStrings("2", tokenizer.next().slice(tokenizer.source));
    try std.testing.expectEqual(TokenKind.flow_sequence_end, tokenizer.next().kind);
    try std.testing.expectEqual(TokenKind.flow_mapping_end, tokenizer.next().kind);
    try std.testing.expectEqual(@as(u32, 0), tokenizer.flow_depth);
    try std.testing.expectEqual(TokenKind.eof, tokenizer.next().kind);
}

test "tokenizer stray closing bracket in block context is scalar text" {
    try expectFirstScalar("echo ]done}", "echo ]done}");
}

test "tokenizer document start resets flow depth" {
    var tokenizer = Tokenizer.init("on: [push\n---\nrun: echo a, b\n");
    _ = tokenizer.next();
    while (true) {
        const token = tokenizer.next();
        if (token.kind == .document_start) break;
        if (token.kind == .eof) return error.NoDocumentStart;
    }
    try std.testing.expectEqual(@as(u32, 0), tokenizer.flow_depth);
    try std.testing.expectEqual(TokenKind.newline, tokenizer.next().kind);
    try std.testing.expectEqualStrings("run", tokenizer.next().slice(tokenizer.source));
    try std.testing.expectEqual(TokenKind.mapping_value, tokenizer.next().kind);
    try std.testing.expectEqualStrings("echo a, b", tokenizer.next().slice(tokenizer.source));
}

test "tokenizer plain scalar keeps expression with index access" {
    var tokenizer = Tokenizer.init("echo ${{ github.event.commits[0].message }}");
    _ = tokenizer.next();
    const token = tokenizer.next();
    try std.testing.expectEqualStrings(
        "echo ${{ github.event.commits[0].message }}",
        token.slice(tokenizer.source),
    );
}

test "tokenizer mapping key-value" {
    var tokenizer = Tokenizer.init("name: CI");
    _ = tokenizer.next();
    const key = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, key.kind);
    try std.testing.expectEqualStrings("name", key.slice(tokenizer.source));

    const colon = tokenizer.next();
    try std.testing.expectEqual(TokenKind.mapping_value, colon.kind);

    const value = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, value.kind);
    try std.testing.expectEqualStrings("CI", value.slice(tokenizer.source));
}

test "tokenizer mapping key-value with tab after colon" {
    var tokenizer = Tokenizer.init("key:\tvalue");
    _ = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, tokenizer.next().kind);
    try std.testing.expectEqual(TokenKind.mapping_value, tokenizer.next().kind);
    const value = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, value.kind);
    try std.testing.expectEqualStrings("value", value.slice(tokenizer.source));
}

test "tokenizer comment" {
    var tokenizer = Tokenizer.init("# this is a comment");
    _ = tokenizer.next();
    const token = tokenizer.next();
    try std.testing.expectEqual(TokenKind.comment, token.kind);
    try std.testing.expectEqualStrings("# this is a comment", token.slice(tokenizer.source));
}

test "tokenizer newline tracking" {
    var tokenizer = Tokenizer.init("a\nb");
    _ = tokenizer.next();
    const a = tokenizer.next();
    try std.testing.expectEqual(@as(u32, 1), a.line);
    const nl = tokenizer.next();
    try std.testing.expectEqual(TokenKind.newline, nl.kind);
    const b = tokenizer.next();
    try std.testing.expectEqual(@as(u32, 2), b.line);
    try std.testing.expectEqual(@as(u32, 1), b.column);
}

test "tokenizer sequence entry" {
    var tokenizer = Tokenizer.init("- item");
    _ = tokenizer.next();
    const dash = tokenizer.next();
    try std.testing.expectEqual(TokenKind.sequence_entry, dash.kind);
    const item = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, item.kind);
    try std.testing.expectEqualStrings("item", item.slice(tokenizer.source));
}

test "tokenizer sequence entry with tab after dash" {
    var tokenizer = Tokenizer.init("-\titem");
    _ = tokenizer.next();
    try std.testing.expectEqual(TokenKind.sequence_entry, tokenizer.next().kind);
    const item = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, item.kind);
    try std.testing.expectEqualStrings("item", item.slice(tokenizer.source));
}

// #293: `-` ending its line opens a sequence entry whose content is on the
// lines below; it used to tokenize as the plain scalar "-".
test "tokenizer sequence entry ending its line" {
    var tokenizer = Tokenizer.init("-\n  a: b");
    _ = tokenizer.next();
    try std.testing.expectEqual(TokenKind.sequence_entry, tokenizer.next().kind);
    try std.testing.expectEqual(TokenKind.newline, tokenizer.next().kind);
}

test "tokenizer sequence entry at end of input" {
    var tokenizer = Tokenizer.init("-");
    _ = tokenizer.next();
    try std.testing.expectEqual(TokenKind.sequence_entry, tokenizer.next().kind);
}

test "tokenizer keeps a leading `-` that starts a plain scalar" {
    var tokenizer = Tokenizer.init("-1");
    _ = tokenizer.next();
    const token = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, token.kind);
    try std.testing.expectEqualStrings("-1", token.slice(tokenizer.source));
}

test "tokenizer flow mapping" {
    var tokenizer = Tokenizer.init("{a: b}");
    _ = tokenizer.next();
    try std.testing.expectEqual(TokenKind.flow_mapping_start, tokenizer.next().kind);
    const a = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, a.kind);
    try std.testing.expectEqualStrings("a", a.slice(tokenizer.source));
    try std.testing.expectEqual(TokenKind.mapping_value, tokenizer.next().kind);
    const b = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, b.kind);
    try std.testing.expectEqualStrings("b", b.slice(tokenizer.source));
    try std.testing.expectEqual(TokenKind.flow_mapping_end, tokenizer.next().kind);
}

test "tokenizer flow sequence" {
    var tokenizer = Tokenizer.init("[1, 2, 3]");
    _ = tokenizer.next();
    try std.testing.expectEqual(TokenKind.flow_sequence_start, tokenizer.next().kind);
    try std.testing.expectEqual(TokenKind.scalar, tokenizer.next().kind);
    try std.testing.expectEqual(TokenKind.flow_entry, tokenizer.next().kind);
    try std.testing.expectEqual(TokenKind.scalar, tokenizer.next().kind);
    try std.testing.expectEqual(TokenKind.flow_entry, tokenizer.next().kind);
    try std.testing.expectEqual(TokenKind.scalar, tokenizer.next().kind);
    try std.testing.expectEqual(TokenKind.flow_sequence_end, tokenizer.next().kind);
}

test "tokenizer quoted string single" {
    var tokenizer = Tokenizer.init("'hello world'");
    _ = tokenizer.next();
    const token = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, token.kind);
    try std.testing.expectEqualStrings("'hello world'", token.slice(tokenizer.source));
}

test "tokenizer quoted string double" {
    var tokenizer = Tokenizer.init("\"hello world\"");
    _ = tokenizer.next();
    const token = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, token.kind);
    try std.testing.expectEqualStrings("\"hello world\"", token.slice(tokenizer.source));
}

test "tokenizer document start" {
    var tokenizer = Tokenizer.init("---\nname: CI");
    _ = tokenizer.next();
    const doc = tokenizer.next();
    try std.testing.expectEqual(TokenKind.document_start, doc.kind);
}

test "tokenizer double eof" {
    var tokenizer = Tokenizer.init("");
    _ = tokenizer.next();
    const eof1 = tokenizer.next();
    try std.testing.expectEqual(TokenKind.eof, eof1.kind);
    const eof2 = tokenizer.next();
    try std.testing.expectEqual(TokenKind.eof, eof2.kind);
}

test "tokenizer multiline mapping" {
    var tokenizer = Tokenizer.init("name: CI\non: push");
    _ = tokenizer.next();
    try std.testing.expectEqualStrings("name", tokenizer.next().slice(tokenizer.source));
    try std.testing.expectEqual(TokenKind.mapping_value, tokenizer.next().kind);
    try std.testing.expectEqualStrings("CI", tokenizer.next().slice(tokenizer.source));
    try std.testing.expectEqual(TokenKind.newline, tokenizer.next().kind);
    try std.testing.expectEqualStrings("on", tokenizer.next().slice(tokenizer.source));
    try std.testing.expectEqual(TokenKind.mapping_value, tokenizer.next().kind);
    try std.testing.expectEqualStrings("push", tokenizer.next().slice(tokenizer.source));
}

test "tokenizer block scalar literal" {
    var tokenizer = Tokenizer.init("run: |\n  echo hello\n  echo world\nname: CI");
    _ = tokenizer.next();
    try std.testing.expectEqualStrings("run", tokenizer.next().slice(tokenizer.source));
    try std.testing.expectEqual(TokenKind.mapping_value, tokenizer.next().kind);
    const block = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, block.kind);
    const block_text = block.slice(tokenizer.source);
    try std.testing.expect(block_text[0] == '|');
}

test "token slice" {
    const source = "hello: world";
    var tokenizer = Tokenizer.init(source);
    _ = tokenizer.next();
    const token = tokenizer.next();
    try std.testing.expectEqualStrings("hello", token.slice(source));
}

test "tokenizer escaped double quote" {
    var tokenizer = Tokenizer.init("\"hello \\\"world\\\"\"");
    _ = tokenizer.next();
    const token = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, token.kind);
    try std.testing.expectEqualStrings("\"hello \\\"world\\\"\"", token.slice(tokenizer.source));
}

test "tokenizer escaped single quote" {
    var tokenizer = Tokenizer.init("'it''s'");
    _ = tokenizer.next();
    const token = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, token.kind);
    try std.testing.expectEqualStrings("'it''s'", token.slice(tokenizer.source));
}

test "tokenizer flow entry comma" {
    var tokenizer = Tokenizer.init("[a, b]");
    _ = tokenizer.next();
    _ = tokenizer.next();
    _ = tokenizer.next();
    const comma = tokenizer.next();
    try std.testing.expectEqual(TokenKind.flow_entry, comma.kind);
}
test "tokenizer counts the line after a `\\` line continuation inside a double-quoted scalar" {
    var tokenizer = Tokenizer.init("\"a \\\nb\"\nx");
    _ = tokenizer.next();
    const scalar = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, scalar.kind);
    try std.testing.expectEqualStrings("\"a \\\nb\"", scalar.slice(tokenizer.source));
    _ = tokenizer.next();
    const after = tokenizer.next();
    try std.testing.expectEqualStrings("x", after.slice(tokenizer.source));
    try std.testing.expectEqual(@as(u32, 3), after.line);
}
test "tokenizer counts an escaped backslash followed by a newline only once" {
    var tokenizer = Tokenizer.init("\"a\\\\\nb\"\nx");
    _ = tokenizer.next();
    _ = tokenizer.next();
    _ = tokenizer.next();
    const after = tokenizer.next();
    try std.testing.expectEqualStrings("x", after.slice(tokenizer.source));
    try std.testing.expectEqual(@as(u32, 3), after.line);
}

test "tokenizer: CRLF ends a line without leaking into the token" {
    var tokenizer = Tokenizer.init("name: ci\r\non:\r\n  push:\r\n");
    var kinds = std.ArrayList(TokenKind){};
    defer kinds.deinit(std.testing.allocator);
    var scalars = std.ArrayList([]const u8){};
    defer scalars.deinit(std.testing.allocator);
    while (true) {
        const tok = tokenizer.next();
        if (tok.kind == .eof) break;
        try kinds.append(std.testing.allocator, tok.kind);
        if (tok.kind == .scalar) try scalars.append(std.testing.allocator, tok.slice(tokenizer.source));
    }

    try std.testing.expectEqualStrings("name", scalars.items[0]);
    try std.testing.expectEqualStrings("ci", scalars.items[1]);
    // `on:` only becomes a key if the `\r` after the colon reads as a break.
    try std.testing.expectEqualStrings("on", scalars.items[2]);
    try std.testing.expectEqual(TokenKind.mapping_value, kinds.items[6]);
}

test "tokenizer emits anchor and alias tokens" {
    var tokenizer = Tokenizer.init("x: &common\ny: *common\n");
    _ = tokenizer.next();
    try std.testing.expectEqualStrings("x", tokenizer.next().slice(tokenizer.source));
    try std.testing.expectEqual(TokenKind.mapping_value, tokenizer.next().kind);
    const anchor = tokenizer.next();
    try std.testing.expectEqual(TokenKind.anchor, anchor.kind);
    try std.testing.expectEqualStrings("&common", anchor.slice(tokenizer.source));
    try std.testing.expectEqual(TokenKind.newline, tokenizer.next().kind);
    try std.testing.expectEqualStrings("y", tokenizer.next().slice(tokenizer.source));
    try std.testing.expectEqual(TokenKind.mapping_value, tokenizer.next().kind);
    const alias = tokenizer.next();
    try std.testing.expectEqual(TokenKind.alias, alias.kind);
    try std.testing.expectEqualStrings("*common", alias.slice(tokenizer.source));
}

test "tokenizer treats an alias inside a flow collection as an alias" {
    var tokenizer = Tokenizer.init("[*a, *b]");
    _ = tokenizer.next();
    try std.testing.expectEqual(TokenKind.flow_sequence_start, tokenizer.next().kind);
    try std.testing.expectEqual(TokenKind.alias, tokenizer.next().kind);
    try std.testing.expectEqual(TokenKind.flow_entry, tokenizer.next().kind);
    const b = tokenizer.next();
    try std.testing.expectEqual(TokenKind.alias, b.kind);
    try std.testing.expectEqualStrings("*b", b.slice(tokenizer.source));
    try std.testing.expectEqual(TokenKind.flow_sequence_end, tokenizer.next().kind);
}

// Shell one-liners put `*` and `&` exactly where a YAML indicator would sit,
// so the anchor scan must hand these back as ordinary scalar text.
test "tokenizer keeps shell globs and operators out of anchor tokens" {
    try expectFirstScalar("*.log", "*.log");
    try expectFirstScalar("**/*.ts", "**/*.ts");
    try expectFirstScalar("&& make", "&& make");
    try expectFirstScalar("*", "*");
    try expectFirstScalar("*cache*", "*cache*");
}

test "tokenizer: a lone CR stays inside a scalar" {
    var tokenizer = Tokenizer.init("a\rb");
    _ = tokenizer.next();
    try std.testing.expectEqualStrings("a\rb", tokenizer.next().slice(tokenizer.source));
}

test "tokenizer: a CRLF comment does not carry the CR" {
    var tokenizer = Tokenizer.init("# hi\r\nname: ci\r\n");
    _ = tokenizer.next();
    try std.testing.expectEqualStrings("# hi", tokenizer.next().slice(tokenizer.source));
}
