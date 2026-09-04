const std = @import("std");
const yaml_types = @import("../yaml/types.zig");

const Node = yaml_types.Node;
const Span = yaml_types.Span;

/// Expected scalar type for a GitHub Actions workflow field.
pub const ExpectedType = enum {
    bool,
    number,

    pub fn label(self: ExpectedType) []const u8 {
        return switch (self) {
            .bool => "bool",
            .number => "number",
        };
    }
};

/// A value whose YAML node kind does not match the schema for its key.
pub const TypeMismatch = struct {
    field: []const u8,
    expected: ExpectedType,
    actual: []const u8,
    span: Span,
};

pub const Collector = struct {
    allocator: std.mem.Allocator,
    list: *std.ArrayList(TypeMismatch),

    pub fn report(self: *Collector, mismatch: TypeMismatch) void {
        self.list.append(self.allocator, mismatch) catch {};
    }
};

/// Return true when `value` contains a GitHub Actions expression.
/// Expression values are skipped because their runtime type is unknown.
///
/// Unquoted `${{ ... }}` scalars are often truncated to `$` by the YAML parser
/// because `{` starts a flow mapping.
pub fn containsExpression(value: []const u8) bool {
    if (std.mem.indexOf(u8, value, "${{") != null) return true;
    return value.len == 1 and value[0] == '$';
}

fn invalidNumberKind(value: []const u8) []const u8 {
    if (value.len > 0 and value[0] == '-') return "negative number";
    for (value) |c| {
        if (c < '0' or c > '9') return "string";
    }
    return "number out of range";
}

fn nodeKindLabel(node: Node) []const u8 {
    return switch (node) {
        .scalar => "string",
        .mapping => "mapping",
        .sequence => "sequence",
        .null_value => "null",
    };
}

/// Validate a bool field (`true` / `false` only). Returns the parsed value, or
/// null when the value is an expression or invalid.
pub fn checkBool(node: Node, field: []const u8, collector: *Collector) ?bool {
    switch (node) {
        .scalar => |s| {
            if (containsExpression(s.value)) return null;
            if (std.mem.eql(u8, s.value, "true")) return true;
            if (std.mem.eql(u8, s.value, "false")) return false;
            collector.report(.{
                .field = field,
                .expected = .bool,
                .actual = "string",
                .span = s.span,
            });
            return null;
        },
        else => {
            collector.report(.{
                .field = field,
                .expected = .bool,
                .actual = nodeKindLabel(node),
                .span = node.getSpan(),
            });
            return null;
        },
    }
}

/// Validate a non-negative integer field. Returns the parsed value, or null
/// when the value is an expression or invalid.
pub fn checkNumber(node: Node, field: []const u8, collector: *Collector) ?u32 {
    switch (node) {
        .scalar => |s| {
            if (containsExpression(s.value)) return null;
            if (std.fmt.parseInt(u32, s.value, 10)) |n| {
                return n;
            } else |_| {}
            collector.report(.{
                .field = field,
                .expected = .number,
                .actual = invalidNumberKind(s.value),
                .span = s.span,
            });
            return null;
        },
        else => {
            collector.report(.{
                .field = field,
                .expected = .number,
                .actual = nodeKindLabel(node),
                .span = node.getSpan(),
            });
            return null;
        },
    }
}

pub fn formatMessage(allocator: std.mem.Allocator, mismatch: TypeMismatch) ![]const u8 {
    return std.fmt.allocPrint(
        allocator,
        "expected {s} for \"{s}\", but found {s}",
        .{ mismatch.expected.label(), mismatch.field, mismatch.actual },
    );
}

// ============================================================
// Tests
// ============================================================

const testing = std.testing;

fn mkSpan(byte: usize) Span {
    return Span.point(1, 1, byte);
}

fn mkScalar(value: []const u8) Node {
    return .{ .scalar = .{ .value = value, .style = .plain, .span = mkSpan(0) } };
}

test "checkBool accepts true and false" {
    var list = std.ArrayList(TypeMismatch){};
    var collector = Collector{ .allocator = testing.allocator, .list = &list };

    try testing.expectEqual(true, checkBool(mkScalar("true"), "continue-on-error", &collector).?);
    try testing.expectEqual(false, checkBool(mkScalar("false"), "continue-on-error", &collector).?);
    try testing.expectEqual(@as(usize, 0), list.items.len);
}

test "checkBool rejects non-bool scalars" {
    var list = std.ArrayList(TypeMismatch){};
    defer list.deinit(testing.allocator);
    var collector = Collector{ .allocator = testing.allocator, .list = &list };
    _ = checkBool(mkScalar("maybe"), "continue-on-error", &collector);
    try testing.expectEqual(@as(usize, 1), list.items.len);
    try testing.expectEqualStrings("continue-on-error", list.items[0].field);
    try testing.expectEqualStrings("string", list.items[0].actual);
}

test "checkBool rejects YAML truthy aliases" {
    var list = std.ArrayList(TypeMismatch){};
    defer list.deinit(testing.allocator);
    var collector = Collector{ .allocator = testing.allocator, .list = &list };
    _ = checkBool(mkScalar("yes"), "continue-on-error", &collector);
    try testing.expectEqual(@as(usize, 1), list.items.len);
    list.clearRetainingCapacity();
    _ = checkBool(mkScalar("True"), "continue-on-error", &collector);
    try testing.expectEqual(@as(usize, 1), list.items.len);
}

test "checkBool skips truncated expression scalars" {
    var list = std.ArrayList(TypeMismatch){};
    defer list.deinit(testing.allocator);
    var collector = Collector{ .allocator = testing.allocator, .list = &list };
    try testing.expect(checkBool(mkScalar("$"), "continue-on-error", &collector) == null);
    try testing.expectEqual(@as(usize, 0), list.items.len);
}

test "checkBool does not skip dollar-prefixed non-expressions" {
    var list = std.ArrayList(TypeMismatch){};
    defer list.deinit(testing.allocator);
    var collector = Collector{ .allocator = testing.allocator, .list = &list };
    _ = checkBool(mkScalar("$maybe"), "continue-on-error", &collector);
    try testing.expectEqual(@as(usize, 1), list.items.len);
}

test "checkNumber rejects negative numbers" {
    var list = std.ArrayList(TypeMismatch){};
    defer list.deinit(testing.allocator);
    var collector = Collector{ .allocator = testing.allocator, .list = &list };
    _ = checkNumber(mkScalar("-1"), "timeout-minutes", &collector);
    try testing.expectEqual(@as(usize, 1), list.items.len);
    try testing.expectEqualStrings("negative number", list.items[0].actual);
}

test "checkNumber rejects overflow" {
    var list = std.ArrayList(TypeMismatch){};
    defer list.deinit(testing.allocator);
    var collector = Collector{ .allocator = testing.allocator, .list = &list };
    _ = checkNumber(mkScalar("99999999999"), "timeout-minutes", &collector);
    try testing.expectEqual(@as(usize, 1), list.items.len);
    try testing.expectEqualStrings("number out of range", list.items[0].actual);
}

test "checkNumber rejects non-scalar nodes" {
    var list = std.ArrayList(TypeMismatch){};
    defer list.deinit(testing.allocator);
    var collector = Collector{ .allocator = testing.allocator, .list = &list };
    var items = [_]Node{mkScalar("1")};
    const seq = Node{ .sequence = .{ .items = &items, .span = mkSpan(0) } };
    _ = checkNumber(seq, "timeout-minutes", &collector);
    try testing.expectEqual(@as(usize, 1), list.items.len);
    try testing.expectEqualStrings("sequence", list.items[0].actual);
}

test "checkNumber accepts integer scalars" {
    var list = std.ArrayList(TypeMismatch){};
    var collector = Collector{ .allocator = testing.allocator, .list = &list };
    try testing.expectEqual(@as(u32, 10), checkNumber(mkScalar("10"), "timeout-minutes", &collector).?);
    try testing.expectEqual(@as(usize, 0), list.items.len);
}

test "checkNumber rejects non-numeric strings" {
    var list = std.ArrayList(TypeMismatch){};
    defer list.deinit(testing.allocator);
    var collector = Collector{ .allocator = testing.allocator, .list = &list };
    _ = checkNumber(mkScalar("ten"), "timeout-minutes", &collector);
    try testing.expectEqual(@as(usize, 1), list.items.len);
    try testing.expectEqualStrings("timeout-minutes", list.items[0].field);
    try testing.expectEqualStrings("string", list.items[0].actual);
}

test "checkNumber skips expressions" {
    var list = std.ArrayList(TypeMismatch){};
    var collector = Collector{ .allocator = testing.allocator, .list = &list };
    try testing.expect(checkNumber(mkScalar("${{ matrix.timeout }}"), "timeout-minutes", &collector) == null);
    try testing.expectEqual(@as(usize, 0), list.items.len);
}

test "formatMessage" {
    const msg = try formatMessage(testing.allocator, .{
        .field = "max-parallel",
        .expected = .number,
        .actual = "string",
        .span = mkSpan(0),
    });
    defer testing.allocator.free(msg);
    try testing.expectEqualStrings("expected number for \"max-parallel\", but found string", msg);
}
