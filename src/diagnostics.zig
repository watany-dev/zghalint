const std = @import("std");

pub const Severity = enum {
    err,
    warning,
    info,
    hint,

    pub fn toString(self: Severity) []const u8 {
        return switch (self) {
            .err => "error",
            .warning => "warning",
            .info => "info",
            .hint => "hint",
        };
    }
};

pub const Span = struct {
    start_line: u32 = 0,
    start_col: u32 = 0,
    end_line: u32 = 0,
    end_col: u32 = 0,
};

pub const Diagnostic = struct {
    rule_id: []const u8,
    severity: Severity,
    message: []const u8,
    file: ?[]const u8 = null,
    span: Span = .{},
    fix_hint: ?[]const u8 = null,
};

pub const DiagnosticList = struct {
    items: std.ArrayList(Diagnostic),

    pub fn init(allocator: std.mem.Allocator) DiagnosticList {
        return .{ .items = std.ArrayList(Diagnostic).init(allocator) };
    }

    pub fn deinit(self: *DiagnosticList) void {
        self.items.deinit();
    }

    pub fn append(self: *DiagnosticList, diag: Diagnostic) void {
        self.items.append(diag) catch {};
    }

    pub fn len(self: *const DiagnosticList) usize {
        return self.items.items.len;
    }

    pub fn get(self: *const DiagnosticList, index: usize) Diagnostic {
        return self.items.items[index];
    }

    pub fn slice(self: *const DiagnosticList) []const Diagnostic {
        return self.items.items;
    }
};
