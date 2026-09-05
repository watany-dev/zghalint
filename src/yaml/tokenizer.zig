const std = @import("std");

pub const TokenKind = enum {
    stream_start,
    document_start,
    document_end,
    mapping_key,
    mapping_value,
    sequence_entry,
    scalar,
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

    pub fn init(source: []const u8) Tokenizer {
        return .{
            .source = source,
            .pos = 0,
            .line = 1,
            .column = 1,
            .started = false,
            .flow_depth = 0,
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

        // Comment
        if (c == '#') {
            return self.scanComment();
        }

        // Newline
        if (c == '\n') {
            return self.scanNewline();
        }

        // Skip spaces (but track them)
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

        // Document markers
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

        // Sequence entry
        if (c == '-' and self.peekNext() == ' ') {
            return self.emitSimple(.sequence_entry, 1);
        }

        // Flow indicators. A plain scalar can never start with `{` or `[`,
        // so those always open a flow collection; the closing and separating
        // indicators only count while one is open.
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

        // Colon followed by space or end -> mapping value indicator
        if (c == ':' and (self.peekNext() == ' ' or self.peekNext() == '\n' or self.pos + 1 >= self.source.len)) {
            return self.emitSimple(.mapping_value, 1);
        }

        // Quoted strings
        if (c == '\'' or c == '"') {
            return self.scanQuotedScalar(c);
        }

        // Block scalar indicators
        if (c == '|' or c == '>') {
            return self.scanBlockScalar();
        }

        // Plain scalar
        return self.scanPlainScalar();
    }

    fn scanComment(self: *Tokenizer) Token {
        const start = self.pos;
        const line = self.line;
        const col = self.column;
        while (self.pos < self.source.len and self.source[self.pos] != '\n') {
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
        self.pos += 1;
        self.line += 1;
        self.column = 1;
        return .{
            .kind = .newline,
            .start = start,
            .end = self.pos,
            .line = line,
            .column = col,
        };
    }

    fn scanQuotedScalar(self: *Tokenizer, quote: u8) Token {
        const start = self.pos;
        const line = self.line;
        const col = self.column;
        self.advance(); // skip opening quote
        while (self.pos < self.source.len) {
            if (self.source[self.pos] == quote) {
                if (quote == '\'' and self.pos + 1 < self.source.len and self.source[self.pos + 1] == '\'') {
                    // Escaped single quote
                    self.advance();
                    self.advance();
                    continue;
                }
                self.advance(); // skip closing quote
                break;
            }
            if (quote == '"' and self.source[self.pos] == '\\') {
                self.advance(); // skip backslash
                if (self.pos < self.source.len) {
                    self.advance(); // skip escaped char
                }
                continue;
            }
            if (self.source[self.pos] == '\n') {
                self.pos += 1;
                self.line += 1;
                self.column = 1;
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
        self.advance(); // skip | or >

        // Skip chomping/indent indicators and rest of line
        while (self.pos < self.source.len and self.source[self.pos] != '\n') {
            self.advance();
        }

        // Determine base indent from next non-empty line
        var base_indent: u32 = 0;
        if (self.pos < self.source.len) {
            const saved_pos = self.pos;
            const saved_line = self.line;
            const saved_col = self.column;
            self.pos += 1; // skip newline
            self.line += 1;
            self.column = 1;

            // Find first non-empty line to determine indent
            while (self.pos < self.source.len) {
                if (self.source[self.pos] == '\n') {
                    self.pos += 1;
                    self.line += 1;
                    self.column = 1;
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
            // Reset
            self.pos = saved_pos;
            self.line = saved_line;
            self.column = saved_col;
        }

        // Consume block content
        while (self.pos < self.source.len and self.source[self.pos] == '\n') {
            self.pos += 1;
            self.line += 1;
            self.column = 1;

            // Check indent of this line
            var indent: u32 = 0;
            while (self.pos + indent < self.source.len and self.source[self.pos + indent] == ' ') {
                indent += 1;
            }

            // If non-empty line with less indent, block ends
            if (self.pos + indent < self.source.len and self.source[self.pos + indent] != '\n' and indent < base_indent) {
                break;
            }

            // Consume the line
            while (self.pos < self.source.len and self.source[self.pos] != '\n') {
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

    /// Consume a `${{ ... }}` interpolation starting at the current position.
    /// Returns false (leaving the position untouched) when one does not start
    /// here, or when it is not closed before the end of the line.
    ///
    /// An expression is opaque to YAML scanning: `}` and `,` inside it are not
    /// flow indicators, and neither `#` nor `: ` inside it ends the scalar.
    fn skipExpressionInterpolation(self: *Tokenizer) bool {
        if (self.pos + 2 >= self.source.len) return false;
        if (self.source[self.pos] != '$') return false;
        if (self.source[self.pos + 1] != '{' or self.source[self.pos + 2] != '{') return false;

        // Unterminated, or closed only on a later line: fall back to normal
        // plain-scalar scanning.
        const close = std.mem.indexOfPos(u8, self.source, self.pos + 3, "}}") orelse return false;
        if (std.mem.indexOfScalarPos(u8, self.source, self.pos + 3, '\n')) |nl| {
            if (nl < close) return false;
        }
        while (self.pos < close + 2) self.advance();
        return true;
    }

    fn scanPlainScalar(self: *Tokenizer) Token {
        const start = self.pos;
        const line = self.line;
        const col = self.column;
        while (self.pos < self.source.len) {
            const ch = self.source[self.pos];
            // A GitHub Actions expression is scanned whole: its braces,
            // commas, `#` and `: ` all belong to the scalar.
            if (self.skipExpressionInterpolation()) continue;
            if (ch == '\n' or ch == '#') break;
            // `,` `[` `]` `{` `}` are indicators only inside a flow collection.
            if (self.flow_depth > 0 and (ch == ',' or ch == '{' or ch == '}' or ch == '[' or ch == ']')) {
                break;
            }
            // Colon followed by space is a mapping value indicator
            if (ch == ':' and (self.pos + 1 >= self.source.len or self.source[self.pos + 1] == ' ' or self.source[self.pos + 1] == '\n')) {
                break;
            }
            self.advance();
        }
        // Trim trailing whitespace
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

    fn skipWhitespace(self: *Tokenizer) void {
        while (self.pos < self.source.len and (self.source[self.pos] == ' ' or self.source[self.pos] == '\t')) {
            self.advance();
        }
    }

    fn peekNext(self: *Tokenizer) ?u8 {
        if (self.pos + 1 < self.source.len) {
            return self.source[self.pos + 1];
        }
        return null;
    }

    fn matchStr(self: *Tokenizer, str: []const u8) bool {
        if (self.pos + str.len > self.source.len) return false;
        // After the match, must be EOF, newline, or space
        if (self.pos + str.len < self.source.len) {
            const after = self.source[self.pos + str.len];
            if (after != '\n' and after != ' ' and after != '\t') return false;
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

// ============================================================
// Tests
// ============================================================

test "tokenizer init" {
    const tokenizer = Tokenizer.init("name: CI");
    try std.testing.expectEqual(@as(usize, 0), tokenizer.pos);
    try std.testing.expectEqual(@as(u32, 1), tokenizer.line);
    try std.testing.expectEqual(@as(u32, 1), tokenizer.column);
    try std.testing.expectEqual(false, tokenizer.started);
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
    _ = tokenizer.next(); // stream_start
    const token = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, token.kind);
    try std.testing.expectEqualStrings("hello", token.slice(tokenizer.source));
}

test "tokenizer plain scalar keeps a ${{ }} interpolation" {
    var tokenizer = Tokenizer.init("echo \"${{ github.event.issue.body }}\"");
    _ = tokenizer.next(); // stream_start
    const token = tokenizer.next();
    try std.testing.expectEqualStrings("echo \"${{ github.event.issue.body }}\"", token.slice(tokenizer.source));
}

test "tokenizer plain scalar keeps commas inside an interpolation" {
    var tokenizer = Tokenizer.init("echo \"${{ join(github.event.commits.*.message, ' ') }}\"");
    _ = tokenizer.next(); // stream_start
    const token = tokenizer.next();
    try std.testing.expectEqualStrings("echo \"${{ join(github.event.commits.*.message, ' ') }}\"", token.slice(tokenizer.source));
}

test "tokenizer plain scalar keeps an unterminated interpolation in block context" {
    var tokenizer = Tokenizer.init("echo ${{ oops");
    _ = tokenizer.next(); // stream_start
    const token = tokenizer.next();
    try std.testing.expectEqualStrings("echo ${{ oops", token.slice(tokenizer.source));
}

test "tokenizer plain scalar stops at an unterminated interpolation in flow context" {
    var tokenizer = Tokenizer.init("[echo ${{ oops]");
    _ = tokenizer.next(); // stream_start
    try std.testing.expectEqual(TokenKind.flow_sequence_start, tokenizer.next().kind);
    const token = tokenizer.next();
    try std.testing.expectEqualStrings("echo $", token.slice(tokenizer.source));
}

// ============================================================
// Flow depth: `,` `[` `]` `{` `}` are indicators only in flow context
// ============================================================

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
    _ = tokenizer.next(); // stream_start
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
    _ = tokenizer.next(); // stream_start
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
    _ = tokenizer.next(); // stream_start
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
    _ = tokenizer.next(); // stream_start
    const token = tokenizer.next();
    try std.testing.expectEqualStrings(
        "echo ${{ github.event.commits[0].message }}",
        token.slice(tokenizer.source),
    );
}

test "tokenizer mapping key-value" {
    var tokenizer = Tokenizer.init("name: CI");
    _ = tokenizer.next(); // stream_start
    const key = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, key.kind);
    try std.testing.expectEqualStrings("name", key.slice(tokenizer.source));

    const colon = tokenizer.next();
    try std.testing.expectEqual(TokenKind.mapping_value, colon.kind);

    const value = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, value.kind);
    try std.testing.expectEqualStrings("CI", value.slice(tokenizer.source));
}

test "tokenizer comment" {
    var tokenizer = Tokenizer.init("# this is a comment");
    _ = tokenizer.next(); // stream_start
    const token = tokenizer.next();
    try std.testing.expectEqual(TokenKind.comment, token.kind);
    try std.testing.expectEqualStrings("# this is a comment", token.slice(tokenizer.source));
}

test "tokenizer newline tracking" {
    var tokenizer = Tokenizer.init("a\nb");
    _ = tokenizer.next(); // stream_start
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
    _ = tokenizer.next(); // stream_start
    const dash = tokenizer.next();
    try std.testing.expectEqual(TokenKind.sequence_entry, dash.kind);
    const item = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, item.kind);
    try std.testing.expectEqualStrings("item", item.slice(tokenizer.source));
}

test "tokenizer flow mapping" {
    var tokenizer = Tokenizer.init("{a: b}");
    _ = tokenizer.next(); // stream_start
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
    _ = tokenizer.next(); // stream_start
    try std.testing.expectEqual(TokenKind.flow_sequence_start, tokenizer.next().kind);
    try std.testing.expectEqual(TokenKind.scalar, tokenizer.next().kind); // 1
    try std.testing.expectEqual(TokenKind.flow_entry, tokenizer.next().kind);
    try std.testing.expectEqual(TokenKind.scalar, tokenizer.next().kind); // 2
    try std.testing.expectEqual(TokenKind.flow_entry, tokenizer.next().kind);
    try std.testing.expectEqual(TokenKind.scalar, tokenizer.next().kind); // 3
    try std.testing.expectEqual(TokenKind.flow_sequence_end, tokenizer.next().kind);
}

test "tokenizer quoted string single" {
    var tokenizer = Tokenizer.init("'hello world'");
    _ = tokenizer.next(); // stream_start
    const token = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, token.kind);
    try std.testing.expectEqualStrings("'hello world'", token.slice(tokenizer.source));
}

test "tokenizer quoted string double" {
    var tokenizer = Tokenizer.init("\"hello world\"");
    _ = tokenizer.next(); // stream_start
    const token = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, token.kind);
    try std.testing.expectEqualStrings("\"hello world\"", token.slice(tokenizer.source));
}

test "tokenizer document start" {
    var tokenizer = Tokenizer.init("---\nname: CI");
    _ = tokenizer.next(); // stream_start
    const doc = tokenizer.next();
    try std.testing.expectEqual(TokenKind.document_start, doc.kind);
}

test "tokenizer double eof" {
    var tokenizer = Tokenizer.init("");
    _ = tokenizer.next(); // stream_start
    const eof1 = tokenizer.next();
    try std.testing.expectEqual(TokenKind.eof, eof1.kind);
    const eof2 = tokenizer.next();
    try std.testing.expectEqual(TokenKind.eof, eof2.kind);
}

test "tokenizer multiline mapping" {
    var tokenizer = Tokenizer.init("name: CI\non: push");
    _ = tokenizer.next(); // stream_start
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
    _ = tokenizer.next(); // stream_start
    try std.testing.expectEqualStrings("run", tokenizer.next().slice(tokenizer.source));
    try std.testing.expectEqual(TokenKind.mapping_value, tokenizer.next().kind);
    const block = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, block.kind);
    // Block scalar should capture the | and content
    const block_text = block.slice(tokenizer.source);
    try std.testing.expect(block_text[0] == '|');
}

test "token slice" {
    const source = "hello: world";
    var tokenizer = Tokenizer.init(source);
    _ = tokenizer.next(); // stream_start
    const token = tokenizer.next();
    try std.testing.expectEqualStrings("hello", token.slice(source));
}

test "tokenizer escaped double quote" {
    var tokenizer = Tokenizer.init("\"hello \\\"world\\\"\"");
    _ = tokenizer.next(); // stream_start
    const token = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, token.kind);
    try std.testing.expectEqualStrings("\"hello \\\"world\\\"\"", token.slice(tokenizer.source));
}

test "tokenizer escaped single quote" {
    var tokenizer = Tokenizer.init("'it''s'");
    _ = tokenizer.next(); // stream_start
    const token = tokenizer.next();
    try std.testing.expectEqual(TokenKind.scalar, token.kind);
    try std.testing.expectEqualStrings("'it''s'", token.slice(tokenizer.source));
}

test "tokenizer flow entry comma" {
    var tokenizer = Tokenizer.init("[a, b]");
    _ = tokenizer.next(); // stream_start
    _ = tokenizer.next(); // [
    _ = tokenizer.next(); // a
    const comma = tokenizer.next();
    try std.testing.expectEqual(TokenKind.flow_entry, comma.kind);
}
