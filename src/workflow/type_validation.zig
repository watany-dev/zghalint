const std = @import("std");
const yaml_types = @import("../yaml/types.zig");

const Node = yaml_types.Node;
const Span = yaml_types.Span;

pub const TypeMismatch = struct {
    field: []const u8,
    expected: []const u8,
    actual: []const u8,
    span: Span,
};

fn report(
    mismatches: ?*std.ArrayList(TypeMismatch),
    allocator: std.mem.Allocator,
    mismatch: TypeMismatch,
) void {
    if (mismatches) |list| list.append(allocator, mismatch) catch {};
}

/// Expression values are skipped because their runtime type is unknown.
///
/// Unquoted `${{ ... }}` scalars are often truncated to `$` by the YAML parser
/// because `{` starts a flow mapping.
pub fn containsExpression(value: []const u8) bool {
    if (std.mem.indexOf(u8, value, "${{") != null) return true;
    return value.len == 1 and value[0] == '$';
}

fn nodeKindLabel(node: Node) []const u8 {
    return switch (node) {
        .scalar => "string",
        .mapping => "mapping",
        .sequence => "sequence",
        .null_value => "null",
    };
}

fn checkScalar(
    comptime T: type,
    comptime expected: []const u8,
    comptime parse: fn ([]const u8) ?T,
    node: Node,
    field: []const u8,
    mismatches: ?*std.ArrayList(TypeMismatch),
    allocator: std.mem.Allocator,
) ?T {
    switch (node) {
        .scalar => |s| {
            if (containsExpression(s.value)) return null;
            if (parse(s.value)) |v| return v;
            report(mismatches, allocator, .{
                .field = field,
                .expected = expected,
                .actual = "string",
                .span = s.span,
            });
            return null;
        },
        else => {
            report(mismatches, allocator, .{
                .field = field,
                .expected = expected,
                .actual = nodeKindLabel(node),
                .span = node.getSpan(),
            });
            return null;
        },
    }
}

fn parseBoolValue(value: []const u8) ?bool {
    if (std.mem.eql(u8, value, "true")) return true;
    if (std.mem.eql(u8, value, "false")) return false;
    return null;
}

fn parseU32Value(value: []const u8) ?u32 {
    return std.fmt.parseInt(u32, value, 10) catch null;
}

pub fn checkBool(
    node: Node,
    field: []const u8,
    mismatches: ?*std.ArrayList(TypeMismatch),
    allocator: std.mem.Allocator,
) ?bool {
    return checkScalar(bool, "bool", parseBoolValue, node, field, mismatches, allocator);
}

pub fn checkNumber(
    node: Node,
    field: []const u8,
    mismatches: ?*std.ArrayList(TypeMismatch),
    allocator: std.mem.Allocator,
) ?u32 {
    return checkScalar(u32, "number", parseU32Value, node, field, mismatches, allocator);
}

const testing = std.testing;
const test_support = @import("../test_support.zig");

fn mkSpan(byte: usize) Span {
    return Span.point(1, 1, byte);
}

const mkScalar = test_support.mkScalar;

test "checkBool accepts true and false" {
    var list = std.ArrayList(TypeMismatch){};
    try testing.expectEqual(true, checkBool(mkScalar("true"), "continue-on-error", &list, testing.allocator).?);
    try testing.expectEqual(false, checkBool(mkScalar("false"), "continue-on-error", &list, testing.allocator).?);
    try testing.expectEqual(@as(usize, 0), list.items.len);
}

test "checkBool rejects non-bool scalars and YAML truthy aliases" {
    var list = std.ArrayList(TypeMismatch){};
    defer list.deinit(testing.allocator);
    for ([_][]const u8{ "maybe", "yes", "True" }) |value| {
        _ = checkBool(mkScalar(value), "continue-on-error", &list, testing.allocator);
        try testing.expectEqual(@as(usize, 1), list.items.len);
        try testing.expectEqualStrings("continue-on-error", list.items[0].field);
        try testing.expectEqualStrings("string", list.items[0].actual);
        list.clearRetainingCapacity();
    }
}

test "checkBool skips truncated expression scalars" {
    var list = std.ArrayList(TypeMismatch){};
    defer list.deinit(testing.allocator);
    try testing.expect(checkBool(mkScalar("$"), "continue-on-error", &list, testing.allocator) == null);
    try testing.expectEqual(@as(usize, 0), list.items.len);
}

test "checkBool does not skip dollar-prefixed non-expressions" {
    var list = std.ArrayList(TypeMismatch){};
    defer list.deinit(testing.allocator);
    _ = checkBool(mkScalar("$maybe"), "continue-on-error", &list, testing.allocator);
    try testing.expectEqual(@as(usize, 1), list.items.len);
}

test "checkNumber accepts and rejects scalars" {
    var list = std.ArrayList(TypeMismatch){};
    defer list.deinit(testing.allocator);
    try testing.expectEqual(@as(u32, 10), checkNumber(mkScalar("10"), "timeout-minutes", &list, testing.allocator).?);
    try testing.expectEqual(@as(usize, 0), list.items.len);
    _ = checkNumber(mkScalar("ten"), "timeout-minutes", &list, testing.allocator);
    try testing.expectEqual(@as(usize, 1), list.items.len);
    try testing.expectEqualStrings("string", list.items[0].actual);
}

test "checkNumber rejects non-scalar nodes" {
    var list = std.ArrayList(TypeMismatch){};
    defer list.deinit(testing.allocator);
    var items = [_]Node{mkScalar("1")};
    const seq = Node{ .sequence = .{ .items = &items, .span = mkSpan(0) } };
    _ = checkNumber(seq, "timeout-minutes", &list, testing.allocator);
    try testing.expectEqualStrings("sequence", list.items[0].actual);
}

test "checkNumber skips expressions" {
    var list = std.ArrayList(TypeMismatch){};
    try testing.expect(checkNumber(mkScalar("${{ matrix.timeout }}"), "timeout-minutes", &list, testing.allocator) == null);
    try testing.expectEqual(@as(usize, 0), list.items.len);
}
