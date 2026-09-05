const std = @import("std");
const yaml = @import("yaml/types.zig");

pub const Span = yaml.Span;

/// Severity levels for diagnostics, ordered from most to least severe.
pub const Severity = enum {
    @"error",
    warning,
    info,
    hint,
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
};

/// Safety classification for automatic fixes.
pub const FixSafety = enum {
    /// Semantics-preserving mechanical fix (e.g. SHA pinning, quote style).
    safe,
    /// Fix that may change behavior (e.g. permission changes).
    unsafe,
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

    /// Append a Diagnostic, deep-cloning any embedded Fix and any
    /// heap-allocated `message` / `fix_hint` into this list's fix_arena. Use
    /// this when bringing diagnostics across DiagnosticList boundaries; plain
    /// `append` keeps those strings borrowed from the source list's arena,
    /// which dangles once that list is deinitialized.
    pub fn appendOwning(self: *DiagnosticList, diag: Diagnostic) !void {
        const alloc = self.fix_arena.allocator();
        var d = diag;
        d.message = try alloc.dupe(u8, diag.message);
        if (diag.fix) |f| d.fix = try cloneFix(alloc, f);
        if (diag.fix_hint) |hint| d.fix_hint = try alloc.dupe(u8, hint);
        try self.items.append(self.allocator, d);
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

    pub fn len(self: DiagnosticList) usize {
        return self.items.items.len;
    }

    /// Number of diagnostics per severity, indexed by the `Severity` tag.
    pub const SeverityCounts = std.enums.EnumFieldStruct(Severity, usize, 0);

    pub fn countBySeverity(self: DiagnosticList) SeverityCounts {
        var counts: SeverityCounts = .{};
        for (self.items.items) |diag| {
            switch (diag.severity) {
                inline else => |tag| @field(counts, @tagName(tag)) += 1,
            }
        }
        return counts;
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

fn cloneFix(alloc: std.mem.Allocator, src: Fix) !Fix {
    const edits = try alloc.alloc(Edit, src.edits.len);
    for (src.edits, 0..) |e, i| edits[i] = .{
        .start_byte = e.start_byte,
        .end_byte = e.end_byte,
        .replacement = try alloc.dupe(u8, e.replacement),
    };
    return .{
        .description = try alloc.dupe(u8, src.description),
        .safety = src.safety,
        .edits = edits,
    };
}

// ============================================================
// Tests
// ============================================================

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

test "appendOwning deep-clones fix across lists" {
    var dst = DiagnosticList.init(std.testing.allocator);
    defer dst.deinit();

    {
        var src = DiagnosticList.init(std.testing.allocator);
        defer src.deinit();

        const replacement = try src.fixAllocator().dupe(u8, "replacement-text");
        const edits = src.allocEdit(.{
            .start_byte = 10,
            .end_byte = 20,
            .replacement = replacement,
        }) orelse return error.OutOfMemory;

        const description = try src.fixAllocator().dupe(u8, "description-text");
        try src.append(.{
            .rule_id = "T1",
            .severity = .warning,
            .message = "msg",
            .span = Span.point(1, 1, 0),
            .fix = .{
                .description = description,
                .safety = .safe,
                .edits = edits,
            },
        });

        try dst.appendOwning(src.get(0));
    }
    // src.deinit() ran — arena backing the original Fix is gone.

    const got = dst.get(0);
    try std.testing.expect(got.fix != null);
    try std.testing.expectEqualStrings("description-text", got.fix.?.description);
    try std.testing.expectEqual(@as(usize, 1), got.fix.?.edits.len);
    try std.testing.expectEqual(@as(usize, 10), got.fix.?.edits[0].start_byte);
    try std.testing.expectEqual(@as(usize, 20), got.fix.?.edits[0].end_byte);
    try std.testing.expectEqualStrings("replacement-text", got.fix.?.edits[0].replacement);
}

test "appendOwning without fix skips clone" {
    var dst = DiagnosticList.init(std.testing.allocator);
    defer dst.deinit();

    try dst.appendOwning(.{
        .rule_id = "T2",
        .severity = .info,
        .message = "msg",
        .span = Span.point(2, 2, 0),
    });

    try std.testing.expectEqual(@as(usize, 1), dst.len());
    try std.testing.expect(dst.get(0).fix == null);
}

test "appendOwning deep-clones heap-allocated fix_hint" {
    var dst = DiagnosticList.init(std.testing.allocator);
    defer dst.deinit();

    {
        var src = DiagnosticList.init(std.testing.allocator);
        defer src.deinit();

        const hint = try src.fixAllocator().dupe(u8, "heap-hint-text");
        try src.append(.{
            .rule_id = "T3",
            .severity = .warning,
            .message = "msg",
            .span = Span.point(1, 1, 0),
            .fix_hint = hint,
        });

        try dst.appendOwning(src.get(0));
    }
    // src.deinit() ran — the original hint backing is gone.

    const got = dst.get(0);
    const hint = got.fix_hint orelse return error.TestExpectedNonNull;
    try std.testing.expectEqualStrings("heap-hint-text", hint);
}

test "appendOwning deep-clones heap-allocated message" {
    var dst = DiagnosticList.init(std.testing.allocator);
    defer dst.deinit();

    {
        var src = DiagnosticList.init(std.testing.allocator);
        defer src.deinit();

        const message = try src.fixAllocator().dupe(u8, "heap-message-text");
        try src.append(.{
            .rule_id = "T4",
            .severity = .@"error",
            .message = message,
            .span = Span.point(1, 1, 0),
        });

        try dst.appendOwning(src.get(0));
    }
    const got = dst.get(0);
    try std.testing.expectEqualStrings("heap-message-text", got.message);
}
