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

/// Safety classification for automatic fixes.
pub const FixSafety = enum {
    /// Semantics-preserving mechanical fix (e.g. SHA pinning, quote style).
    safe,
    /// Fix that may change behavior (e.g. permission changes).
    unsafe,

    pub fn toString(self: FixSafety) []const u8 {
        return switch (self) {
            .safe => "safe",
            .unsafe => "unsafe",
        };
    }
};

/// A single text edit: replace bytes [start_byte..end_byte) with replacement.
/// - start_byte == end_byte → insertion
/// - replacement.len == 0  → deletion
pub const Edit = struct {
    start_byte: usize,
    end_byte: usize,
    replacement: []const u8,
};

/// An automatic fix composed of one or more edits.
pub const Fix = struct {
    description: []const u8,
    safety: FixSafety,
    edits: []const Edit,
};

/// A single diagnostic message produced by a lint rule.
pub const Diagnostic = struct {
    rule_id: []const u8,
    severity: Severity,
    message: []const u8,
    file: ?[]const u8 = null,
    span: Span,
    fix_hint: ?[]const u8 = null,
    fix: ?Fix = null,

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
    /// Arena for Fix-related heap allocations (Edit slices, replacement strings).
    fix_arena: std.heap.ArenaAllocator,

    pub fn init(allocator: std.mem.Allocator) DiagnosticList {
        return .{
            .items = .{},
            .allocator = allocator,
            .fix_arena = std.heap.ArenaAllocator.init(allocator),
        };
    }

    pub fn deinit(self: *DiagnosticList) void {
        self.fix_arena.deinit();
        self.items.deinit(self.allocator);
    }

    /// Returns an allocator for Fix edits/strings. Lifetime matches DiagnosticList.
    pub fn fixAllocator(self: *DiagnosticList) std.mem.Allocator {
        return self.fix_arena.allocator();
    }

    pub fn append(self: *DiagnosticList, diag: Diagnostic) std.mem.Allocator.Error!void {
        try self.items.append(self.allocator, diag);
    }

    /// Allocate a single Edit on the heap, tracked for cleanup on deinit.
    /// Returns a slice suitable for use in Fix.edits, or null on OOM.
    pub fn allocEdit(self: *DiagnosticList, edit: Edit) ?[]const Edit {
        const alloc = self.fix_arena.allocator();
        const edits = alloc.alloc(Edit, 1) catch return null;
        edits[0] = edit;
        return edits;
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

    try list.append(.{
        .rule_id = "T001",
        .severity = .warning,
        .message = "test",
        .span = Span.point(1, 1, 0),
    });
    try list.append(.{
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
    try list.append(.{
        .rule_id = "R3",
        .severity = .info,
        .message = "third",
        .file = "b.yml",
        .span = Span.point(1, 1, 0),
    });
    try list.append(.{
        .rule_id = "R1",
        .severity = .@"error",
        .message = "first",
        .file = "a.yml",
        .span = Span.point(5, 3, 50),
    });
    try list.append(.{
        .rule_id = "R2",
        .severity = .warning,
        .message = "second",
        .file = "a.yml",
        .span = Span.point(5, 1, 40),
    });
    try list.append(.{
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

test "fixSafety toString" {
    try std.testing.expectEqualStrings("safe", FixSafety.safe.toString());
    try std.testing.expectEqualStrings("unsafe", FixSafety.unsafe.toString());
}

test "allocEdit returns valid slice" {
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    const edits = list.allocEdit(.{
        .start_byte = 10,
        .end_byte = 20,
        .replacement = "replacement text",
    });
    try std.testing.expect(edits != null);
    try std.testing.expectEqual(@as(usize, 1), edits.?.len);
    try std.testing.expectEqual(@as(usize, 10), edits.?[0].start_byte);
    try std.testing.expectEqual(@as(usize, 20), edits.?[0].end_byte);
    try std.testing.expectEqualStrings("replacement text", edits.?[0].replacement);
}

test "fixAllocator returns valid allocator" {
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    const alloc = list.fixAllocator();
    // Allocate something to verify it works
    const mem = try alloc.alloc(u8, 16);
    defer alloc.free(mem);
    try std.testing.expectEqual(@as(usize, 16), mem.len);
}

test "diagnostic with fix" {
    const edits = [_]Edit{
        .{ .start_byte = 0, .end_byte = 5, .replacement = "hello" },
    };
    const diag = Diagnostic{
        .rule_id = "T1",
        .severity = .warning,
        .message = "test",
        .span = Span.point(1, 1, 0),
        .fix = .{
            .description = "Fix it",
            .safety = .safe,
            .edits = &edits,
        },
    };
    try std.testing.expect(diag.fix != null);
    try std.testing.expectEqualStrings("Fix it", diag.fix.?.description);
    try std.testing.expect(diag.fix.?.safety == .safe);
    try std.testing.expectEqual(@as(usize, 1), diag.fix.?.edits.len);
}

test "diagnostic list toOwnedSlice" {
    var list = DiagnosticList.init(std.testing.allocator);
    // Don't defer deinit — toOwnedSlice transfers ownership

    try list.append(.{
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
