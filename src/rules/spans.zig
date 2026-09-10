const std = @import("std");
const yaml = @import("../yaml/types.zig");
const workflow_types = @import("../workflow/types.zig");

pub const Span = yaml.Span;
pub const ScalarStyle = yaml.ScalarStyle;
pub const ScalarValueMeta = workflow_types.ScalarValueMeta;

/// Workflow-level findings ("this workflow is missing X") have no single
/// offending token; they point at the head of the file.
pub const workflow_head = Span.point(1, 1, 0);

/// Falls back to the step span because the parser leaves `uses_value_span`
/// unset for a non-scalar `uses:`.
pub fn usesSpan(step: *const workflow_types.Step) Span {
    return step.uses_value_span orelse step.span;
}

pub fn runAnchor(step: *const workflow_types.Step) Anchor {
    return Anchor.fromMeta(step.run_meta, step.span);
}

/// The YAML parser stores the *token* span on every scalar, but `value` is a
/// sub-slice of that token: quoted scalars drop the surrounding quotes and
/// block scalars (`|` / `>`) drop the indicator line. Mirrors
/// `contentOrigin`, which resolves the same position as line / column.
fn contentStartByte(token: Span, style: ScalarStyle, value: []const u8) usize {
    return switch (style) {
        // The token span covers the indicator line too, and the value runs to
        // the end of the token, so count back from there.
        .literal, .folded => if (token.end_byte < value.len)
            token.start_byte
        else
            token.end_byte - value.len,
        // The value starts right after the opening quote. Counting back from
        // the end would land on the closing quote, and escapes make the value
        // shorter than the quoted text anyway.
        .single_quoted, .double_quoted => token.start_byte + 1,
        .plain => token.start_byte,
    };
}

const Pos = struct { line: u32, col: u32 };

/// Block scalars start on the line after the `|` / `>` indicator at column 1
/// because the leading indentation is part of `value`, so the value's first
/// byte is the first byte of that line.
fn contentOrigin(token: Span, style: ScalarStyle) Pos {
    return switch (style) {
        .literal, .folded => .{ .line = token.start_line + 1, .col = 1 },
        .single_quoted, .double_quoted => .{ .line = token.start_line, .col = token.start_col + 1 },
        .plain => .{ .line = token.start_line, .col = token.start_col },
    };
}

/// `scalar` is the scalar's token span when the parser captured it; `fallback`
/// is the enclosing step / job span used when it did not, so a diagnostic
/// always carries a usable position instead of `0:0`.
pub const Anchor = struct {
    fallback: Span,
    scalar: ?Span = null,
    style: ScalarStyle = .plain,

    pub fn fromMeta(meta: ?ScalarValueMeta, fallback: Span) Anchor {
        if (meta) |m| return .{ .fallback = fallback, .scalar = m.value_span, .style = m.style };
        return .{ .fallback = fallback };
    }

    pub fn whole(self: Anchor) Span {
        return self.scalar orelse self.fallback;
    }

    /// One-off resolution of `value[offset..][0..len]`. A loop that reports
    /// several positions in the same scalar should go through `cursor`, which
    /// does not re-walk the value from its first byte for each of them.
    pub fn at(self: Anchor, value: []const u8, offset: usize, len: usize) Span {
        var c = self.cursor(value);
        return c.at(offset, len);
    }

    pub fn cursor(self: Anchor, value: []const u8) Cursor {
        return .{ .anchor = self, .value = value };
    }
};

/// Resolves offsets in one scalar to spans, remembering the last position so
/// a front-to-back scan advances from there. A scan that reports every match
/// in a `run:` block would otherwise re-count the newlines before each one,
/// making the block cost O(matches × length).
pub const Cursor = struct {
    anchor: Anchor,
    value: []const u8,
    /// Offset into `value` that `pos` describes.
    offset: usize = 0,
    /// Null until the first resolution, which is when the origin is needed.
    pos: ?Pos = null,

    pub fn at(self: *Cursor, offset: usize, len: usize) Span {
        const token = self.anchor.scalar orelse return self.anchor.fallback;
        const value = self.value;
        const start_off = @min(offset, value.len);
        const end_off = @min(start_off + len, value.len);

        const content_start_byte = contentStartByte(token, self.anchor.style, value);
        // An alias (`*name`) carries the anchored node's text under the alias's
        // own two-byte token, so an offset into the value is not an offset into
        // the source. Report the token whole rather than a position past the end
        // of the file (fuzz). A token with no extent records no such claim, so
        // there is nothing to contradict and the offsets stand.
        const token_has_extent = token.end_byte > token.start_byte;
        if (token_has_extent and content_start_byte + value.len > token.end_byte) return token;

        const start = self.positionAt(start_off);
        const end = advance(start.line, start.col, value[start_off..end_off]);

        return .{
            .start_line = start.line,
            .start_col = start.col,
            .end_line = end.line,
            .end_col = end.col,
            .start_byte = content_start_byte + start_off,
            .end_byte = content_start_byte + end_off,
        };
    }

    /// Walks forward from the remembered position when `offset` is at or past
    /// it, and from the origin otherwise, so an out-of-order request is merely
    /// slower, never wrong.
    fn positionAt(self: *Cursor, offset: usize) Pos {
        const from: Pos, const from_off: usize = if (self.pos) |pos|
            if (self.offset <= offset) .{ pos, self.offset } else .{ self.origin(), 0 }
        else
            .{ self.origin(), 0 };
        const pos = advance(from.line, from.col, self.value[from_off..offset]);
        self.pos = pos;
        self.offset = offset;
        return pos;
    }

    fn origin(self: *const Cursor) Pos {
        return contentOrigin(self.anchor.scalar.?, self.anchor.style);
    }
};

fn advance(line: u32, col: u32, text: []const u8) Pos {
    var l = line;
    var c = col;
    for (text) |ch| {
        if (ch == '\n') {
            l += 1;
            c = 1;
        } else {
            c += 1;
        }
    }
    return .{ .line = l, .col = c };
}

test "Cursor resolves the same spans as Anchor.at, in any order" {
    const value = "  echo one\n  echo ${{ a }}\n  echo ${{ b }} ${{ c }}\n";
    const token = Span{
        .start_line = 6,
        .start_col = 12,
        .end_line = 9,
        .end_col = 1,
        .start_byte = 50,
        .end_byte = 50 + 6 + value.len,
    };
    const a = Anchor.fromMeta(.{ .value_span = token, .style = .literal }, Span.point(1, 1, 0));
    var cursor = a.cursor(value);

    const offsets = [_]usize{ 0, 18, 32, 41, 41, 18, value.len };
    for (offsets) |offset| {
        const expected = a.at(value, offset, 3);
        const got = cursor.at(offset, 3);
        try std.testing.expectEqual(expected.start_line, got.start_line);
        try std.testing.expectEqual(expected.start_col, got.start_col);
        try std.testing.expectEqual(expected.end_line, got.end_line);
        try std.testing.expectEqual(expected.end_col, got.end_col);
        try std.testing.expectEqual(expected.start_byte, got.start_byte);
        try std.testing.expectEqual(expected.end_byte, got.end_byte);
    }
    // The cursor followed the last request rather than starting over.
    try std.testing.expectEqual(@as(usize, value.len), cursor.offset);
    try std.testing.expectEqual(@as(u32, 10), cursor.pos.?.line);
}

test "Cursor without a scalar span falls back like Anchor.at" {
    var cursor = (Anchor{ .fallback = Span.point(4, 7, 30) }).cursor("echo hi");
    const s = cursor.at(5, 2);
    try std.testing.expectEqual(@as(u32, 4), s.start_line);
    try std.testing.expectEqual(@as(usize, 30), s.start_byte);
    try std.testing.expectEqual(@as(?Pos, null), cursor.pos);
}

test "Anchor.at without a scalar span falls back to the step span" {
    const fallback = Span.point(4, 7, 30);
    const a = Anchor{ .fallback = fallback };
    const s = a.at("echo hi", 5, 2);
    try std.testing.expectEqual(@as(u32, 4), s.start_line);
    try std.testing.expectEqual(@as(u32, 7), s.start_col);
}

test "Anchor.at on a plain scalar offsets from the token column" {
    // `if: github.head_ref` — value starts at line 3, column 9.
    const token = Span{
        .start_line = 3,
        .start_col = 9,
        .end_line = 3,
        .end_col = 24,
        .start_byte = 100,
        .end_byte = 115,
    };
    const value = "github.head_ref";
    const a = Anchor.fromMeta(.{ .value_span = token, .style = .plain }, Span.point(1, 1, 0));
    const s = a.at(value, 7, 8);
    try std.testing.expectEqual(@as(u32, 3), s.start_line);
    try std.testing.expectEqual(@as(u32, 16), s.start_col);
    try std.testing.expectEqual(@as(usize, 107), s.start_byte);
    try std.testing.expectEqual(@as(usize, 115), s.end_byte);
}

test "Anchor.at reports the whole token when the value does not fit it (fuzz)" {
    // `*c` is two bytes of source carrying the anchored node's longer text, so
    // an offset into the value would run past the end of the file.
    const token = Span{
        .start_line = 4,
        .start_col = 6,
        .end_line = 4,
        .end_col = 8,
        .start_byte = 33,
        .end_byte = 35,
    };
    const a = Anchor.fromMeta(.{ .value_span = token, .style = .plain }, Span.point(1, 1, 0));
    const s = a.at("${{a}}", 0, 6);
    try std.testing.expectEqual(@as(usize, 33), s.start_byte);
    try std.testing.expectEqual(@as(usize, 35), s.end_byte);
    try std.testing.expectEqual(@as(u32, 8), s.end_col);
}

test "Anchor.at on a quoted scalar skips the opening quote" {
    const token = Span{
        .start_line = 2,
        .start_col = 5,
        .end_line = 2,
        .end_col = 10,
        .start_byte = 10,
        .end_byte = 15,
    };
    const value = "abc";
    const a = Anchor.fromMeta(.{ .value_span = token, .style = .double_quoted }, Span.point(1, 1, 0));
    const s = a.at(value, 0, 3);
    try std.testing.expectEqual(@as(u32, 6), s.start_col);
    // Token bytes 10..15 are `"abc"`, so the value itself is 11..14.
    try std.testing.expectEqual(@as(usize, 11), s.start_byte);
    try std.testing.expectEqual(@as(usize, 14), s.end_byte);
}

test "Anchor.at on a block scalar resolves the matching content line" {
    // run: |
    //   echo one
    //   echo two
    const value = "  echo one\n  echo two\n";
    const token = Span{
        .start_line = 6,
        .start_col = 12,
        .end_line = 8,
        .end_col = 1,
        .start_byte = 50,
        .end_byte = 50 + 6 + value.len,
    };
    const a = Anchor.fromMeta(.{ .value_span = token, .style = .literal }, Span.point(1, 1, 0));
    const offset = std.mem.find(u8, value, "two").?;
    const s = a.at(value, offset, 3);
    try std.testing.expectEqual(@as(u32, 8), s.start_line);
    try std.testing.expectEqual(@as(u32, 8), s.start_col);
    try std.testing.expectEqual(@as(usize, 56 + offset), s.start_byte);
}

test "contentStartByte handles a block value longer than the token" {
    const token = Span.point(1, 1, 0);
    try std.testing.expectEqual(@as(usize, 0), contentStartByte(token, .literal, "too long"));
}

test "contentStartByte skips the opening quote of a quoted scalar" {
    const token = Span{
        .start_line = 1,
        .start_col = 1,
        .end_line = 1,
        .end_col = 6,
        .start_byte = 10,
        .end_byte = 15,
    };
    try std.testing.expectEqual(@as(usize, 11), contentStartByte(token, .double_quoted, "abc"));
    try std.testing.expectEqual(@as(usize, 11), contentStartByte(token, .single_quoted, "abc"));
    try std.testing.expectEqual(@as(usize, 10), contentStartByte(token, .plain, "abc"));
}

test "Anchor.at clamps out-of-range offsets" {
    const token = Span{
        .start_line = 1,
        .start_col = 1,
        .end_line = 1,
        .end_col = 4,
        .start_byte = 0,
        .end_byte = 3,
    };
    const a = Anchor.fromMeta(.{ .value_span = token, .style = .plain }, Span.point(9, 9, 9));
    const s = a.at("abc", 99, 10);
    try std.testing.expectEqual(@as(usize, 3), s.start_byte);
    try std.testing.expectEqual(@as(usize, 3), s.end_byte);
}
