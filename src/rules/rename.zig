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

/// `span` must cover exactly `old_text`, optionally quoted; see
/// `fix_builder.renameToken`, which pins the bytes the edit may replace.
pub fn tokenFix(
    list: *DiagnosticList,
    span: Span,
    old_text: []const u8,
    new_text: []const u8,
) ?Fix {
    const alloc = list.fixAllocator();
    // Both slices can point into a per-rule arena that dies before the
    // diagnostic does -- RW003/RW004 parse the called workflow into one, and an
    // expression path lives only for the walk -- while the edit stores them
    // verbatim. They have to be ours.
    const owned_new = alloc.dupe(u8, new_text) catch return null;
    const owned_old = alloc.dupe(u8, old_text) catch return null;
    const edits = fix_builder.renameToken(alloc, span, owned_old, owned_new) orelse return null;
    const description = std.fmt.allocPrint(alloc, "rename to \"{s}\"", .{owned_new}) catch return null;
    return .{ .description = description, .safety = .safe, .edits = edits };
}

/// The contextual expression rules (EXPR010-EXPR014, ACT005) report a whole
/// `a.b.c` path, but only one of its segments is the typo. `segment_index` is
/// 0-based over the segments `expr_check.SegmentIter` yields.
///
/// Returns null unless `path_span` covers exactly `path`. A wider span means
/// the offsets inside `path` do not map to file offsets -- `parseContextAccess`
/// reconstructs the path, so `needs . buld` arrives shorter than its source --
/// and a fallback span standing in for one the parser never captured can be any
/// width at all. `renameToken` re-checks the bytes on top of that.
pub fn pathSegmentFix(
    list: *DiagnosticList,
    path_span: Span,
    path: []const u8,
    segment_index: usize,
    new_segment: []const u8,
) ?Fix {
    const segment = segmentSpan(path_span, path, segment_index) orelse return null;
    // The replacement is written back into an expression, so it has to survive
    // being lexed as a path segment. A candidate carrying anything else -- a
    // step id such as `a>b` -- would be read back as a shorter path plus a
    // remainder, the same diagnostic would fire again with a fresh candidate,
    // and every `--fix` round would grow the expression (#369).
    if (!isPathIdentifier(new_segment)) return null;
    return tokenFix(list, segment.span, segment.text, new_segment);
}

/// The identifier grammar an expression path segment accepts: a leading letter
/// or underscore, then letters, digits, `_` or `-`.
fn isPathIdentifier(name: []const u8) bool {
    if (name.len == 0) return false;
    if (!std.ascii.isAlphabetic(name[0]) and name[0] != '_') return false;
    for (name[1..]) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-') return false;
    }
    return true;
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
        // Only the byte range decides what gets rewritten; the line/column of
        // the whole path stays as the caret the diagnostic already points at.
        var span = path_span;
        span.start_byte = path_span.start_byte + iter.prev_end - text.len;
        span.end_byte = span.start_byte + text.len;
        return .{ .text = text, .span = span };
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
    // A span that covers more than the path -- a fallback span, say.
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

test "isPathIdentifier accepts only expression-safe segments" {
    try testing.expect(isPathIdentifier("build"));
    try testing.expect(isPathIdentifier("_build-2"));
    try testing.expect(!isPathIdentifier(""));
    try testing.expect(!isPathIdentifier("2build"));
    try testing.expect(!isPathIdentifier("a>b"));
    try testing.expect(!isPathIdentifier("a b"));
    try testing.expect(!isPathIdentifier("a.b"));
}

test "pathSegmentFix declines a candidate that is not a path identifier" {
    var list = DiagnosticList.init(testing.allocator);
    defer list.deinit();

    const path = "steps.b";
    try testing.expect(pathSegmentFix(&list, pathSpan(40, path.len), path, 1, "a>b") == null);
}
