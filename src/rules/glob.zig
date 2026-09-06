//! GitHub Actions filter-pattern glob validation.
//!
//! Ported from actionlint's glob.go (MIT License, rhysd/actionlint).

const std = @import("std");

pub const InvalidGlobPattern = struct {
    message: []const u8,
    /// 1-based column in the pattern. Zero means the error is at the start or
    /// spans the whole pattern (e.g. empty pattern, newline).
    column: usize,
};

const GlobValidator = struct {
    is_ref: bool,
    prec: bool,
    pat: []const u8,
    pos: usize,
    errs: std.ArrayList(InvalidGlobPattern),
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator, pat: []const u8, is_ref: bool) GlobValidator {
        return .{
            .is_ref = is_ref,
            .prec = false,
            .pat = pat,
            .pos = 0,
            .errs = .{},
            .allocator = allocator,
        };
    }

    fn deinit(self: *GlobValidator) void {
        self.errs.deinit(self.allocator);
    }

    fn finish(self: *GlobValidator, out_allocator: std.mem.Allocator) []const InvalidGlobPattern {
        const out = out_allocator.alloc(InvalidGlobPattern, self.errs.items.len) catch return &.{};
        for (self.errs.items, 0..) |err, i| {
            out[i] = .{
                .message = out_allocator.dupe(u8, err.message) catch err.message,
                .column = err.column,
            };
        }
        return out;
    }

    fn atEof(self: *const GlobValidator) bool {
        return self.pos >= self.pat.len;
    }

    fn peek(self: *const GlobValidator) ?u8 {
        if (self.atEof()) return null;
        return self.pat[self.pos];
    }

    fn next(self: *GlobValidator) ?u8 {
        if (self.atEof()) return null;
        const c = self.pat[self.pos];
        self.pos += 1;
        return c;
    }

    fn columnAt(self: *const GlobValidator) usize {
        if (self.pos == 0) return 0;
        return self.pos;
    }

    fn addError(self: *GlobValidator, msg: []const u8) void {
        self.errs.append(self.allocator, .{
            .message = msg,
            .column = self.columnAt(),
        }) catch return;
    }

    fn unexpected(self: *GlobValidator, char: ?u8, what: []const u8, why: []const u8) void {
        const unexpected_msg: []const u8 = if (char == null)
            "unexpected EOF"
        else
            "unexpected character";

        const while_part: []const u8 = if (what.len == 0) "" else " while checking ";
        const msg = std.fmt.allocPrint(
            self.allocator,
            "invalid glob pattern. {s}{s}{s}. {s}",
            .{ unexpected_msg, while_part, what, why },
        ) catch {
            self.addError("invalid glob pattern");
            return;
        };
        self.errs.append(self.allocator, .{ .message = msg, .column = self.columnAt() }) catch {
            self.allocator.free(msg);
            return;
        };
    }

    fn invalidRefChar(self: *GlobValidator, c: u8, why: []const u8) void {
        const msg = std.fmt.allocPrint(
            self.allocator,
            "character '{c}' is invalid for branch and tag names. {s}. see `man git-check-ref-format` for more details. note that regular expression is unavailable",
            .{ c, why },
        ) catch {
            self.addError("character is invalid for branch and tag names");
            return;
        };
        self.errs.append(self.allocator, .{ .message = msg, .column = self.columnAt() }) catch {
            self.allocator.free(msg);
            return;
        };
    }

    fn validateNext(self: *GlobValidator) bool {
        const c = self.next() orelse return false;
        var prec: bool = true;

        switch (c) {
            '\\' => {
                if (self.peek()) |peek_c| {
                    switch (peek_c) {
                        '[', '?', '*' => {
                            _ = self.next();
                            if (self.is_ref) {
                                self.invalidRefChar(self.peek() orelse 0, "ref name cannot contain spaces, ~, ^, :, [, ?, *");
                            }
                        },
                        '+', '\\', '!' => _ = self.next(),
                        else => {
                            if (self.is_ref) {
                                self.invalidRefChar('\\', "only special characters [, ?, +, *, \\, ! can be escaped with \\");
                                _ = self.next();
                            }
                        },
                    }
                }
            },
            '?' => {
                if (!self.prec) {
                    self.unexpected('?', "special character ? (zero or one)", "the preceding character must not be special character");
                }
                prec = false;
            },
            '+' => {
                if (!self.prec) {
                    self.unexpected('+', "special character + (one or more)", "the preceding character must not be special character");
                }
                prec = false;
            },
            '*' => prec = false,
            '[' => {
                if (self.peek() == ']') {
                    _ = self.next();
                    self.unexpected(']', "content of character match []", "character match must not be empty");
                } else {
                    var chars: usize = 0;
                    bracket_loop: while (true) {
                        const inner = self.next();
                        if (inner == null) {
                            self.unexpected(null, "end of character match []", "missing ]");
                            return false;
                        }
                        if (inner == ']') break :bracket_loop;

                        if (self.peek() != '-') {
                            chars += 1;
                            continue;
                        }
                        chars += 2;
                        const start: u8 = inner.?;
                        _ = self.next(); // eat '-'
                        const end_peek = self.peek();
                        if (end_peek == ']') {
                            _ = self.next();
                            self.unexpected(']', "character range in []", "end of range is missing");
                            break :bracket_loop;
                        }
                        if (end_peek != null) {
                            const end = self.next().?;
                            if (start > end) {
                                const msg = std.fmt.allocPrint(
                                    self.allocator,
                                    "invalid glob pattern. unexpected character while checking character range in []. start of range '{c}' ({d}) is larger than end of range '{c}' ({d})",
                                    .{ start, start, end, end },
                                ) catch {
                                    self.addError("invalid character range in []");
                                    continue;
                                };
                                self.errs.append(self.allocator, .{ .message = msg, .column = self.columnAt() }) catch {
                                    self.allocator.free(msg);
                                };
                            }
                        }
                    }

                    if (chars == 1) {
                        self.unexpected(c, "character match []", "character match with single character is useless. simply use x instead of [x]");
                    }
                }
            },
            '\r' => {
                if (self.peek() == '\n') _ = self.next();
                self.unexpected('\r', "", "newline cannot be contained");
            },
            '\n' => self.unexpected('\n', "", "newline cannot be contained"),
            ' ', '\t', '~', '^', ':' => {
                if (self.is_ref) {
                    self.invalidRefChar(c, "ref name cannot contain spaces, ~, ^, :, [, ?, *");
                }
            },
            else => {},
        }

        self.prec = prec;

        if (self.atEof()) {
            if (self.is_ref and (c == '/' or c == '.')) {
                self.invalidRefChar(c, "ref name must not end with / and .");
            }
            return false;
        }

        return true;
    }

    fn validate(self: *GlobValidator) void {
        if (self.pat.len == 0) {
            self.addError("glob pattern cannot be empty");
            return;
        }

        if (self.peek() == '/') {
            if (self.is_ref) {
                _ = self.next();
                self.invalidRefChar('/', "ref name must not start with /");
                self.prec = true;
            }
        } else if (self.peek() == '!') {
            _ = self.next();
            if (self.atEof()) {
                self.unexpected('!', "! at first character (negate pattern)", "at least one character must follow !");
                return;
            }
            self.prec = false;
        }

        while (self.validateNext()) {}
    }
};

fn validateGlob(allocator: std.mem.Allocator, pat: []const u8, is_ref: bool) []const InvalidGlobPattern {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var v = GlobValidator.init(arena.allocator(), pat, is_ref);
    defer v.deinit();
    v.validate();
    return v.finish(allocator);
}

/// Validate a glob pattern for branch or tag filter values.
pub fn validateRefGlob(allocator: std.mem.Allocator, pat: []const u8) []const InvalidGlobPattern {
    return validateGlob(allocator, pat, true);
}

/// Validate a glob pattern for path filter values.
pub fn validatePathGlob(allocator: std.mem.Allocator, pat: []const u8) []const InvalidGlobPattern {
    const trimmed = std.mem.trim(u8, pat, " \t");
    if (!std.mem.eql(u8, pat, trimmed)) {
        const msg = "leading and trailing spaces are not allowed in glob path";
        const slice = allocator.alloc(InvalidGlobPattern, 1) catch return &.{};
        slice[0] = .{ .message = allocator.dupe(u8, msg) catch msg, .column = 0 };
        return slice;
    }

    var body = pat;
    if (std.mem.startsWith(u8, body, "!")) {
        body = body[1..];
    }
    if (body.len == 0 or std.mem.eql(u8, body, ".") or std.mem.eql(u8, body, "..") or
        std.mem.startsWith(u8, body, "./") or std.mem.startsWith(u8, body, "../"))
    {
        const msg = "'.' and '..' are not allowed in glob path";
        const slice = allocator.alloc(InvalidGlobPattern, 1) catch return &.{};
        slice[0] = .{ .message = allocator.dupe(u8, msg) catch msg, .column = 0 };
        return slice;
    }

    return validateGlob(allocator, pat, false);
}

const testing = std.testing;

fn freeGlobErrors(allocator: std.mem.Allocator, errs: []const InvalidGlobPattern) void {
    for (errs) |err| allocator.free(err.message);
    allocator.free(errs);
}

test "validateRefGlob: valid patterns" {
    const ok = [_][]const u8{
        "main", "feature/*", "v[12].[0-9]+.[0-9]+", "!main", "a+", "a?", "*", "**",
    };
    for (ok) |pat| {
        const errs = validateRefGlob(testing.allocator, pat);
        defer freeGlobErrors(testing.allocator, errs);
        try testing.expectEqual(@as(usize, 0), errs.len);
    }
}

test "validatePathGlob: valid patterns" {
    const ok = [_][]const u8{
        "src/**", "!src/vendor/**", "docs/**/*.md", "**/README.md", "/foo/bar",
    };
    for (ok) |pat| {
        const errs = validatePathGlob(testing.allocator, pat);
        defer freeGlobErrors(testing.allocator, errs);
        try testing.expectEqual(@as(usize, 0), errs.len);
    }
}

test "validateRefGlob: unclosed character class" {
    const errs = validateRefGlob(testing.allocator, "v[1.*");
    defer freeGlobErrors(testing.allocator, errs);
    try testing.expect(errs.len > 0);
    try testing.expect(std.mem.indexOf(u8, errs[0].message, "missing ]") != null);
}

test "validateRefGlob: + at start" {
    const errs = validateRefGlob(testing.allocator, "+foo");
    defer freeGlobErrors(testing.allocator, errs);
    try testing.expect(errs.len > 0);
    try testing.expect(std.mem.indexOf(u8, errs[0].message, "the preceding character must not be special character") != null);
}

test "validatePathGlob: rejects ./ prefix" {
    const errs = validatePathGlob(testing.allocator, "./src/**");
    defer freeGlobErrors(testing.allocator, errs);
    try testing.expectEqual(@as(usize, 1), errs.len);
    try testing.expect(std.mem.indexOf(u8, errs[0].message, "'.' and '..' are not allowed") != null);
}

test "validateRefGlob: empty pattern" {
    const errs = validateRefGlob(testing.allocator, "");
    defer freeGlobErrors(testing.allocator, errs);
    try testing.expectEqual(@as(usize, 1), errs.len);
    try testing.expectEqualStrings("glob pattern cannot be empty", errs[0].message);
}
