const std = @import("std");
const yaml = @import("yaml/types.zig");

pub const Span = yaml.Span;

/// Severity levels for diagnostics, ordered from most to least severe.
pub const Severity = enum {
    @"error",
    warning,
    info,
    hint,

    pub fn toString(self: Severity) []const u8 {
        return switch (self) {
            .@"error" => "error",
            .warning => "warning",
            .info => "info",
            .hint => "hint",
        };
    }
};

/// Category of lint rule.
pub const Category = enum {
    syntax,
    security,
    performance,
    best_practice,
    expression,
    dependency,
    permissions,
    runner,
    reusable_workflow,

    pub fn toString(self: Category) []const u8 {
        return switch (self) {
            .syntax => "syntax",
            .security => "security",
            .performance => "performance",
            .best_practice => "best_practice",
            .expression => "expression",
            .dependency => "dependency",
            .permissions => "permissions",
            .runner => "runner",
            .reusable_workflow => "reusable_workflow",
        };
    }
};

/// A single diagnostic message produced by a lint rule.
pub const Diagnostic = struct {
    rule_id: []const u8,
    severity: Severity,
    message: []const u8,
    file: ?[]const u8 = null,
    span: Span,
    fix_hint: ?[]const u8 = null,

    /// Format as "file:line:col: severity [rule_id]: message"
    pub fn format(self: Diagnostic, allocator: std.mem.Allocator) ![]const u8 {
        const file_str = self.file orelse "<unknown>";

        if (self.fix_hint) |hint| {
            return std.fmt.allocPrint(allocator, "{s}:{d}:{d}: {s} [{s}]: {s}\n  hint: {s}", .{
                file_str,
                self.span.start_line,
                self.span.start_col,
                self.severity.toString(),
                self.rule_id,
                self.message,
                hint,
            });
        }

        return std.fmt.allocPrint(allocator, "{s}:{d}:{d}: {s} [{s}]: {s}", .{
            file_str,
            self.span.start_line,
            self.span.start_col,
            self.severity.toString(),
            self.rule_id,
            self.message,
        });
    }
};

/// Collects diagnostics and provides sorting/access.
pub const DiagnosticList = struct {
    items: std.ArrayList(Diagnostic),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) DiagnosticList {
        return .{ .items = .{}, .allocator = allocator };
    }

    pub fn deinit(self: *DiagnosticList) void {
        self.items.deinit(self.allocator);
    }

    pub fn append(self: *DiagnosticList, diag: Diagnostic) void {
        self.items.append(self.allocator, diag) catch {};
    }

    /// Sort diagnostics by file, then line, then column.
    pub fn sort(self: *DiagnosticList) void {
        std.mem.sort(Diagnostic, self.items.items, {}, lessThan);
    }

    pub fn toOwnedSlice(self: *DiagnosticList) ![]Diagnostic {
        return self.items.toOwnedSlice(self.allocator);
    }

    pub fn len(self: DiagnosticList) usize {
        return self.items.items.len;
    }

    pub fn get(self: DiagnosticList, index: usize) Diagnostic {
        return self.items.items[index];
    }

    fn lessThan(_: void, a: Diagnostic, b: Diagnostic) bool {
        // Sort by file name first
        const file_a = a.file orelse "";
        const file_b = b.file orelse "";
        const file_cmp = std.mem.order(u8, file_a, file_b);
        if (file_cmp == .lt) return true;
        if (file_cmp == .gt) return false;

        // Then by line
        if (a.span.start_line < b.span.start_line) return true;
        if (a.span.start_line > b.span.start_line) return false;

        // Then by column
        return a.span.start_col < b.span.start_col;
    }
};

// ============================================================
// Tests
// ============================================================

test "severity toString" {
    try std.testing.expectEqualStrings("error", Severity.@"error".toString());
    try std.testing.expectEqualStrings("warning", Severity.warning.toString());
    try std.testing.expectEqualStrings("info", Severity.info.toString());
    try std.testing.expectEqualStrings("hint", Severity.hint.toString());
}

test "category toString" {
    try std.testing.expectEqualStrings("syntax", Category.syntax.toString());
    try std.testing.expectEqualStrings("security", Category.security.toString());
    try std.testing.expectEqualStrings("performance", Category.performance.toString());
    try std.testing.expectEqualStrings("best_practice", Category.best_practice.toString());
    try std.testing.expectEqualStrings("expression", Category.expression.toString());
    try std.testing.expectEqualStrings("dependency", Category.dependency.toString());
    try std.testing.expectEqualStrings("permissions", Category.permissions.toString());
    try std.testing.expectEqualStrings("runner", Category.runner.toString());
    try std.testing.expectEqualStrings("reusable_workflow", Category.reusable_workflow.toString());
}

test "diagnostic format without fix hint" {
    const allocator = std.testing.allocator;
    const diag = Diagnostic{
        .rule_id = "SEC001",
        .severity = .warning,
        .message = "unpinned action reference",
        .file = ".github/workflows/ci.yml",
        .span = Span.point(10, 5, 100),
    };
    const formatted = try diag.format(allocator);
    defer allocator.free(formatted);
    try std.testing.expectEqualStrings(
        ".github/workflows/ci.yml:10:5: warning [SEC001]: unpinned action reference",
        formatted,
    );
}

test "diagnostic format with fix hint" {
    const allocator = std.testing.allocator;
    const diag = Diagnostic{
        .rule_id = "SEC001",
        .severity = .@"error",
        .message = "script injection risk",
        .file = "ci.yml",
        .span = Span.point(3, 1, 20),
        .fix_hint = "use an intermediate env variable",
    };
    const formatted = try diag.format(allocator);
    defer allocator.free(formatted);
    try std.testing.expectEqualStrings(
        "ci.yml:3:1: error [SEC001]: script injection risk\n  hint: use an intermediate env variable",
        formatted,
    );
}

test "diagnostic format with no file" {
    const allocator = std.testing.allocator;
    const diag = Diagnostic{
        .rule_id = "BP001",
        .severity = .info,
        .message = "consider adding a timeout",
        .span = Span.point(1, 1, 0),
    };
    const formatted = try diag.format(allocator);
    defer allocator.free(formatted);
    try std.testing.expectEqualStrings(
        "<unknown>:1:1: info [BP001]: consider adding a timeout",
        formatted,
    );
}

test "diagnostic list append and len" {
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    list.append(.{
        .rule_id = "T001",
        .severity = .warning,
        .message = "test",
        .span = Span.point(1, 1, 0),
    });
    list.append(.{
        .rule_id = "T002",
        .severity = .@"error",
        .message = "test2",
        .span = Span.point(2, 1, 10),
    });

    try std.testing.expectEqual(@as(usize, 2), list.len());
    try std.testing.expectEqualStrings("T001", list.get(0).rule_id);
}

test "diagnostic list sort by file then line then col" {
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    // Add in unsorted order
    list.append(.{
        .rule_id = "R3",
        .severity = .info,
        .message = "third",
        .file = "b.yml",
        .span = Span.point(1, 1, 0),
    });
    list.append(.{
        .rule_id = "R1",
        .severity = .@"error",
        .message = "first",
        .file = "a.yml",
        .span = Span.point(5, 3, 50),
    });
    list.append(.{
        .rule_id = "R2",
        .severity = .warning,
        .message = "second",
        .file = "a.yml",
        .span = Span.point(5, 1, 40),
    });
    list.append(.{
        .rule_id = "R0",
        .severity = .hint,
        .message = "zeroth",
        .file = "a.yml",
        .span = Span.point(2, 1, 10),
    });

    list.sort();

    // a.yml:2:1, a.yml:5:1, a.yml:5:3, b.yml:1:1
    try std.testing.expectEqualStrings("R0", list.get(0).rule_id);
    try std.testing.expectEqualStrings("R2", list.get(1).rule_id);
    try std.testing.expectEqualStrings("R1", list.get(2).rule_id);
    try std.testing.expectEqualStrings("R3", list.get(3).rule_id);
}

test "diagnostic list toOwnedSlice" {
    var list = DiagnosticList.init(std.testing.allocator);
    // Don't defer deinit — toOwnedSlice transfers ownership

    list.append(.{
        .rule_id = "T001",
        .severity = .warning,
        .message = "test",
        .span = Span.point(1, 1, 0),
    });

    const slice = try list.toOwnedSlice();
    defer std.testing.allocator.free(slice);

    try std.testing.expectEqual(@as(usize, 1), slice.len);
    try std.testing.expectEqualStrings("T001", slice[0].rule_id);
}
