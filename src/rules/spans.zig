const std = @import("std");
const yaml = @import("../yaml/types.zig");
const workflow_types = @import("../workflow/types.zig");

pub const Span = yaml.Span;
pub const ScalarStyle = yaml.ScalarStyle;
pub const ScalarValueMeta = workflow_types.ScalarValueMeta;

/// Workflow-level findings ("this workflow is missing X") have no single
/// offending token; they point at the head of the file.
pub const workflow_head = Span.point(1, 1, 0);

/// Span of a step's `uses:` value, or the step itself when the parser did not
/// capture it (e.g. a non-scalar `uses:`). Shared by every rule that reports a
/// finding about the referenced action.
pub fn usesSpan(step: *const workflow_types.Step) Span {
    return step.uses_value_span orelse step.span;
}

/// Anchor for text scanned out of a step's `run:` body.
pub fn runAnchor(step: *const workflow_types.Step) Anchor {
    return Anchor.fromMeta(step.run_meta, step.span);
}

/// Byte offset of the first character of a scalar's parsed `value` within the
/// source, derived from the scalar's token span.
///
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

/// Source position of the first character of a scalar's parsed `value`.
/// Block scalars start on the line after the `|` / `>` indicator, at column 1
/// (the leading indentation is part of `value`, so the value's first byte is
/// the first byte of that line). Quoted scalars start one column after the
/// opening quote; plain scalars start at the token itself.
fn contentOrigin(token: Span, style: ScalarStyle) Pos {
    return switch (style) {
        .literal, .folded => .{ .line = token.start_line + 1, .col = 1 },
        .single_quoted, .double_quoted => .{ .line = token.start_line, .col = token.start_col + 1 },
        .plain => .{ .line = token.start_line, .col = token.start_col },
    };
}

/// Anchor for diagnostics raised while scanning the text of a single YAML
/// scalar (a `run:` body, an `if:` condition, a `with:` value, …).
///
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

    /// Span covering the whole scalar (or the fallback when it is unknown).
    pub fn whole(self: Anchor) Span {
        return self.scalar orelse self.fallback;
    }

    /// Span of `value[offset .. offset + len]` in the source.
    pub fn at(self: Anchor, value: []const u8, offset: usize, len: usize) Span {
        const token = self.scalar orelse return self.fallback;
        const start_off = @min(offset, value.len);
        const end_off = @min(start_off + len, value.len);

        const origin = contentOrigin(token, self.style);
        const start = advance(origin.line, origin.col, value[0..start_off]);
        const end = advance(start.line, start.col, value[start_off..end_off]);

        const content_start = contentStartByte(token, self.style, value);
        return .{
            .start_line = start.line,
            .start_col = start.col,
            .end_line = end.line,
            .end_col = end.col,
            .start_byte = content_start + start_off,
            .end_byte = content_start + end_off,
        };
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

// ============================================================
// Tests
// ============================================================

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
    //   echo ${{ github.head_ref }}
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
    const offset = std.mem.indexOf(u8, value, "two").?;
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
