//! Turns a `util.didYouMean` suggestion into a `Fix`.
//!
//! The suggestion is only ever produced for a name the reporting rule has
//! already found meaningless in the workflow -- an undefined step id, an
//! undeclared matrix key, a permission scope GitHub does not know -- and
//! `didYouMean` returns it only when a single candidate sits within edit
//! distance 2. Swapping the typo for that candidate therefore cannot change
//! what the workflow means, so every fix here is `safe`.

const std = @import("std");
const expr_check = @import("expr_check.zig");
const fix_builder = @import("../fix/builder.zig");
const diagnostics = @import("../diagnostics.zig");
const spans = @import("spans.zig");

const DiagnosticList = diagnostics.DiagnosticList;
const Fix = diagnostics.Fix;
const Span = spans.Span;

/// `span` must cover exactly `old_text` (optionally quoted); see
/// `fix_builder.renameToken`.
pub fn tokenFix(
    list: *DiagnosticList,
    span: Span,
    old_text: []const u8,
    new_text: []const u8,
) ?Fix {
    const alloc = list.fixAllocator();
    const edits = fix_builder.renameToken(alloc, span, old_text, new_text) orelse return null;
    const description = std.fmt.allocPrint(alloc, "rename to \"{s}\"", .{new_text}) catch return null;
    return .{ .description = description, .safety = .safe, .edits = edits };
}

/// The contextual expression rules (EXPR010-EXPR014, ACT005) report a whole
/// `a.b.c` path, but only one of its segments is the typo. `segment_index` is
/// 0-based over the segments `expr_check.SegmentIter` yields.
///
/// Returns null unless `path_span` covers exactly `path`: inside a quoted
/// scalar an escape makes the source wider than the value, and the segment's
/// offset within `path` no longer maps to a file offset.
pub fn pathSegmentFix(
    list: *DiagnosticList,
    path_span: Span,
    path: []const u8,
    segment_index: usize,
    new_segment: []const u8,
) ?Fix {
    const segment = segmentSpan(path_span, path, segment_index) orelse return null;
    return tokenFix(list, segment.span, segment.text, new_segment);
}

const SegmentSpan = struct {
    text: []const u8,
    span: Span,
};

/// Only a plain identifier segment has a literal span to rewrite; a computed
/// one (`inputs['name']`, `needs.*`) is left alone.
fn segmentSpan(path_span: Span, path: []const u8, segment_index: usize) ?SegmentSpan {
    if (path_span.end_byte < path_span.start_byte) return null;
    if (path_span.end_byte - path_span.start_byte != path.len) return null;

    var iter = expr_check.SegmentIter{ .path = path };
    var i: usize = 0;
    while (iter.next()) |segment| : (i += 1) {
        if (i != segment_index) continue;
        const text = switch (segment) {
            .ident => |name| name,
            else => return null,
        };
        const start = path_span.start_byte + iter.prev_end - text.len;
        return .{
            .text = text,
            .span = .{
                .start_line = path_span.start_line,
                .start_col = path_span.start_col,
                .end_line = path_span.start_line,
                .end_col = path_span.start_col,
                .start_byte = start,
                .end_byte = start + text.len,
            },
        };
    }
    return null;
}

const testing = std.testing;

fn pathSpan(start_byte: usize, len: usize) Span {
    return .{
        .start_line = 3,
        .start_col = 9,
        .end_line = 3,
        .end_col = @intCast(9 + len),
        .start_byte = start_byte,
        .end_byte = start_byte + len,
    };
}

test "segmentSpan locates each identifier segment" {
    const path = "steps.chekout.outputs.sha";
    const span = pathSpan(100, path.len);

    const root = segmentSpan(span, path, 0) orelse return error.TestExpectedNonNull;
    try testing.expectEqualStrings("steps", root.text);
    try testing.expectEqual(@as(usize, 100), root.span.start_byte);
    try testing.expectEqual(@as(usize, 105), root.span.end_byte);

    const id = segmentSpan(span, path, 1) orelse return error.TestExpectedNonNull;
    try testing.expectEqualStrings("chekout", id.text);
    try testing.expectEqual(@as(usize, 106), id.span.start_byte);
    try testing.expectEqual(@as(usize, 113), id.span.end_byte);

    const prop = segmentSpan(span, path, 3) orelse return error.TestExpectedNonNull;
    try testing.expectEqualStrings("sha", prop.text);
    try testing.expectEqual(@as(usize, 122), prop.span.start_byte);
}

test "segmentSpan rejects a computed segment and an out-of-range index" {
    const path = "secrets['TOKEM']";
    const span = pathSpan(10, path.len);
    try testing.expect(segmentSpan(span, path, 1) == null);
    try testing.expect(segmentSpan(span, path, 9) == null);
}

test "segmentSpan rejects a span that does not cover the path" {
    const path = "matrix.oss";
    // A quoted scalar whose escapes widened the source.
    try testing.expect(segmentSpan(pathSpan(10, path.len + 2), path, 1) == null);
}

test "pathSegmentFix rewrites only the offending segment" {
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();

    const path = "matrix.oss";
    const fix = pathSegmentFix(&list, pathSpan(40, path.len), path, 1, "os") orelse
        return error.TestExpectedNonNull;
    try testing.expectEqual(diagnostics.FixSafety.safe, fix.safety);
    try testing.expectEqualStrings("rename to \"os\"", fix.description);
    try testing.expectEqual(@as(usize, 1), fix.edits.len);
    try testing.expectEqual(@as(usize, 47), fix.edits[0].start_byte);
    try testing.expectEqual(@as(usize, 50), fix.edits[0].end_byte);
    try testing.expectEqualStrings("os", fix.edits[0].replacement);
}

test "tokenFix returns null for a span that is not the token" {
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();

    try testing.expect(tokenFix(&list, pathSpan(0, 40), "pusg", "push") == null);
}
