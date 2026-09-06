const std = @import("std");
const test_support = @import("../test_support.zig");
const diagnostics = @import("../diagnostics.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml = @import("../yaml/types.zig");
const expr_type = @import("expr_type.zig");
const catalog = @import("expr_catalog.zig");
const expr_check = @import("expr_check.zig");
const spans = @import("spans.zig");

pub const Diagnostic = diagnostics.Diagnostic;
pub const DiagnosticList = diagnostics.DiagnosticList;
pub const Severity = diagnostics.Severity;
pub const Fix = diagnostics.Fix;
pub const Edit = diagnostics.Edit;
pub const Span = yaml.Span;
pub const Anchor = spans.Anchor;
pub const Step = workflow_types.Step;
pub const Job = workflow_types.Job;
pub const StringMap = workflow_types.StringMap;

pub const TokenKind = enum {
    identifier,
    dot,
    open_paren,
    close_paren,
    string_literal,
    number,
    comparison_op,
    logical_op,
    not_op,
    comma,
    star,
    open_bracket,
    close_bracket,
    eof,
    @"error",
};

pub const ExprToken = struct {
    kind: TokenKind,
    value: []const u8,
    pos: usize,
};

pub const ExprTokenizer = struct {
    source: []const u8,
    pos: usize,

    pub fn init(source: []const u8) ExprTokenizer {
        return .{ .source = source, .pos = 0 };
    }

    fn skipWhitespace(self: *ExprTokenizer) void {
        while (self.pos < self.source.len and
            (self.source[self.pos] == ' ' or self.source[self.pos] == '\t' or
                self.source[self.pos] == '\n' or self.source[self.pos] == '\r'))
        {
            self.pos += 1;
        }
    }

    fn emitSimple(self: *ExprTokenizer, kind: TokenKind, comptime text: []const u8) ExprToken {
        const start = self.pos;
        self.pos += text.len;
        return .{ .kind = kind, .value = text, .pos = start };
    }

    fn peekIs(self: *const ExprTokenizer, c: u8) bool {
        return self.pos + 1 < self.source.len and self.source[self.pos + 1] == c;
    }

    pub fn next(self: *ExprTokenizer) ExprToken {
        self.skipWhitespace();
        if (self.pos >= self.source.len) {
            return .{ .kind = .eof, .value = "", .pos = self.pos };
        }

        const start = self.pos;
        const c = self.source[self.pos];

        switch (c) {
            '.' => return self.emitSimple(.dot, "."),
            '(' => return self.emitSimple(.open_paren, "("),
            ')' => return self.emitSimple(.close_paren, ")"),
            '[' => return self.emitSimple(.open_bracket, "["),
            ']' => return self.emitSimple(.close_bracket, "]"),
            ',' => return self.emitSimple(.comma, ","),
            '*' => return self.emitSimple(.star, "*"),
            '!' => {
                if (self.peekIs('=')) return self.emitSimple(.comparison_op, "!=");
                return self.emitSimple(.not_op, "!");
            },
            '=' => {
                if (self.peekIs('=')) return self.emitSimple(.comparison_op, "==");
                return self.emitSimple(.@"error", "=");
            },
            '<' => {
                if (self.peekIs('=')) return self.emitSimple(.comparison_op, "<=");
                return self.emitSimple(.comparison_op, "<");
            },
            '>' => {
                if (self.peekIs('=')) return self.emitSimple(.comparison_op, ">=");
                return self.emitSimple(.comparison_op, ">");
            },
            '&' => {
                if (self.peekIs('&')) return self.emitSimple(.logical_op, "&&");
                return self.emitSimple(.@"error", "&");
            },
            '|' => {
                if (self.peekIs('|')) return self.emitSimple(.logical_op, "||");
                return self.emitSimple(.@"error", "|");
            },
            '\'' => return self.readString(),
            else => {
                if (std.ascii.isDigit(c) or
                    (c == '-' and self.pos + 1 < self.source.len and std.ascii.isDigit(self.source[self.pos + 1])))
                {
                    return self.readNumber();
                }
                if (std.ascii.isAlphabetic(c) or c == '_') {
                    return self.readIdentifier();
                }
                self.pos += 1;
                return .{ .kind = .@"error", .value = self.source[start .. start + 1], .pos = start };
            },
        }
    }

    fn readString(self: *ExprTokenizer) ExprToken {
        const start = self.pos;
        self.pos += 1;
        while (self.pos < self.source.len) {
            if (self.source[self.pos] == '\'') {
                // `''` is an escaped quote.
                if (self.pos + 1 < self.source.len and self.source[self.pos + 1] == '\'') {
                    self.pos += 2;
                    continue;
                }
                self.pos += 1;
                return .{ .kind = .string_literal, .value = self.source[start..self.pos], .pos = start };
            }
            self.pos += 1;
        }
        return .{ .kind = .@"error", .value = self.source[start..self.pos], .pos = start };
    }

    fn readNumber(self: *ExprTokenizer) ExprToken {
        const start = self.pos;
        if (self.source[self.pos] == '-') self.pos += 1;
        while (self.pos < self.source.len and
            (std.ascii.isDigit(self.source[self.pos]) or self.source[self.pos] == '.'))
        {
            self.pos += 1;
        }
        if (self.pos < self.source.len and
            (self.source[self.pos] == 'e' or self.source[self.pos] == 'E'))
        {
            self.pos += 1;
            if (self.pos < self.source.len and
                (self.source[self.pos] == '+' or self.source[self.pos] == '-'))
            {
                self.pos += 1;
            }
            while (self.pos < self.source.len and std.ascii.isDigit(self.source[self.pos])) {
                self.pos += 1;
            }
        }
        return .{ .kind = .number, .value = self.source[start..self.pos], .pos = start };
    }

    fn readIdentifier(self: *ExprTokenizer) ExprToken {
        const start = self.pos;
        while (self.pos < self.source.len and
            (std.ascii.isAlphanumeric(self.source[self.pos]) or
                self.source[self.pos] == '_' or self.source[self.pos] == '-'))
        {
            self.pos += 1;
        }
        const value = self.source[start..self.pos];
        return .{ .kind = .identifier, .value = value, .pos = start };
    }
};

pub const NodeKind = enum {
    context_access,
    function_call,
    binary_op,
    unary_op,
    string_literal,
    number_literal,
    boolean_literal,
    null_literal,
};

pub const ExprNode = struct {
    kind: NodeKind,
    /// For context_access: "github.sha"; for function_call: "contains";
    /// for literals: the value; for ops: the operator
    value: []const u8,
    children: []const ExprNode,
    /// Relative to the expression source, not the workflow file.
    start_byte: u32 = 0,
    end_byte: u32 = 0,
};

pub const ParseError = error{
    UnexpectedToken,
    EmptyExpression,
    UnclosedParen,
    OutOfMemory,
};

fn isOrOp(tok: ExprToken) bool {
    return tok.kind == .logical_op and std.mem.eql(u8, tok.value, "||");
}

fn isAndOp(tok: ExprToken) bool {
    return tok.kind == .logical_op and std.mem.eql(u8, tok.value, "&&");
}

fn isComparisonOp(tok: ExprToken) bool {
    return tok.kind == .comparison_op;
}

pub const ExprParser = struct {
    tokenizer: ExprTokenizer,
    current: ExprToken,
    allocator: std.mem.Allocator,
    error_message: ?[]const u8 = null,

    pub fn init(allocator: std.mem.Allocator, source: []const u8) ExprParser {
        var tokenizer = ExprTokenizer.init(source);
        const first = tokenizer.next();
        return .{
            .tokenizer = tokenizer,
            .current = first,
            .allocator = allocator,
        };
    }

    fn advance(self: *ExprParser) void {
        self.current = self.tokenizer.next();
    }

    pub fn parse(self: *ExprParser) ParseError!ExprNode {
        if (self.current.kind == .eof) {
            self.error_message = "empty expression";
            return ParseError.EmptyExpression;
        }
        const node = try self.parseOr();
        if (self.current.kind != .eof) {
            self.error_message = "unexpected token after expression";
            return ParseError.UnexpectedToken;
        }
        return node;
    }

    fn parseOr(self: *ExprParser) ParseError!ExprNode {
        return self.parseBinary(parseAnd, isOrOp);
    }

    fn parseAnd(self: *ExprParser) ParseError!ExprNode {
        return self.parseBinary(parseComparison, isAndOp);
    }

    fn parseComparison(self: *ExprParser) ParseError!ExprNode {
        return self.parseBinary(parseUnary, isComparisonOp);
    }

    fn parseBinary(
        self: *ExprParser,
        comptime next: fn (*ExprParser) ParseError!ExprNode,
        comptime matches: fn (ExprToken) bool,
    ) ParseError!ExprNode {
        var left = try next(self);
        while (matches(self.current)) {
            const op = self.current.value;
            self.advance();
            const right = try next(self);
            const children = try self.allocator.alloc(ExprNode, 2);
            children[0] = left;
            children[1] = right;
            left = ExprNode{
                .kind = .binary_op,
                .value = op,
                .children = children,
                .start_byte = children[0].start_byte,
                .end_byte = children[1].end_byte,
            };
        }
        return left;
    }

    fn parseUnary(self: *ExprParser) ParseError!ExprNode {
        if (self.current.kind == .not_op) {
            const op = self.current.value;
            const op_start = self.current.pos;
            self.advance();
            const operand = try self.parseUnary();
            const children = try self.allocator.alloc(ExprNode, 1);
            children[0] = operand;
            return ExprNode{
                .kind = .unary_op,
                .value = op,
                .children = children,
                .start_byte = @intCast(op_start),
                .end_byte = operand.end_byte,
            };
        }
        return self.parsePrimary();
    }

    fn leaf(kind: NodeKind, tok: ExprToken) ExprNode {
        return .{
            .kind = kind,
            .value = tok.value,
            .children = &.{},
            .start_byte = @intCast(tok.pos),
            .end_byte = @intCast(tok.pos + tok.value.len),
        };
    }

    fn parsePrimary(self: *ExprParser) ParseError!ExprNode {
        switch (self.current.kind) {
            .string_literal, .number => {
                const kind: NodeKind = if (self.current.kind == .string_literal)
                    .string_literal
                else
                    .number_literal;
                const node = leaf(kind, self.current);
                self.advance();
                return node;
            },
            .open_paren => {
                self.advance();
                const inner = try self.parseOr();
                if (self.current.kind != .close_paren) {
                    self.error_message = "missing closing parenthesis";
                    return ParseError.UnclosedParen;
                }
                self.advance();
                return inner;
            },
            .identifier => {
                const tok = self.current;
                const name = tok.value;
                const name_start = tok.pos;
                self.advance();

                if (std.mem.eql(u8, name, "true") or std.mem.eql(u8, name, "false")) {
                    return leaf(.boolean_literal, tok);
                }
                if (std.mem.eql(u8, name, "null")) {
                    return leaf(.null_literal, tok);
                }

                if (self.current.kind == .open_paren) {
                    return self.parseFunctionCall(name, name_start);
                }

                return self.parseContextAccess(name, name_start);
            },
            .@"error" => {
                self.error_message = "invalid token in expression";
                return ParseError.UnexpectedToken;
            },
            else => {
                self.error_message = "unexpected token in expression";
                return ParseError.UnexpectedToken;
            },
        }
    }

    fn parseFunctionCall(self: *ExprParser, name: []const u8, name_start: usize) ParseError!ExprNode {
        self.advance();
        var args = std.ArrayList(ExprNode){};

        if (self.current.kind != .close_paren) {
            const first_arg = try self.parseOr();
            args.append(self.allocator, first_arg) catch return ParseError.OutOfMemory;
            while (self.current.kind == .comma) {
                self.advance();
                const arg = try self.parseOr();
                args.append(self.allocator, arg) catch return ParseError.OutOfMemory;
            }
        }

        if (self.current.kind != .close_paren) {
            self.error_message = "missing closing parenthesis in function call";
            return ParseError.UnclosedParen;
        }
        const close_paren_pos = self.current.pos;
        self.advance();

        const children = args.toOwnedSlice(self.allocator) catch return ParseError.OutOfMemory;
        return ExprNode{
            .kind = .function_call,
            .value = name,
            .children = children,
            .start_byte = @intCast(name_start),
            .end_byte = @intCast(close_paren_pos + 1),
        };
    }

    fn parseContextAccess(self: *ExprParser, first: []const u8, first_start: usize) ParseError!ExprNode {
        var parts = std.ArrayList(u8){};
        parts.appendSlice(self.allocator, first) catch return ParseError.OutOfMemory;
        var last_end: usize = first_start + first.len;

        while (self.current.kind == .dot) {
            last_end = self.current.pos + 1;
            parts.append(self.allocator, '.') catch return ParseError.OutOfMemory;
            self.advance();
            if (self.current.kind == .identifier) {
                last_end = self.current.pos + self.current.value.len;
                parts.appendSlice(self.allocator, self.current.value) catch return ParseError.OutOfMemory;
                self.advance();
            } else if (self.current.kind == .star) {
                last_end = self.current.pos + 1;
                parts.append(self.allocator, '*') catch return ParseError.OutOfMemory;
                self.advance();
            } else {
                self.error_message = "expected property name after '.'";
                return ParseError.UnexpectedToken;
            }
        }

        while (self.current.kind == .open_bracket) {
            self.advance();
            if (self.current.kind == .string_literal) {
                parts.append(self.allocator, '[') catch return ParseError.OutOfMemory;
                parts.appendSlice(self.allocator, self.current.value) catch return ParseError.OutOfMemory;
                parts.append(self.allocator, ']') catch return ParseError.OutOfMemory;
                self.advance();
            } else {
                self.error_message = "expected string in bracket access";
                return ParseError.UnexpectedToken;
            }
            if (self.current.kind != .close_bracket) {
                self.error_message = "missing closing bracket";
                return ParseError.UnexpectedToken;
            }
            last_end = self.current.pos + 1;
            self.advance();
        }

        const path = parts.toOwnedSlice(self.allocator) catch return ParseError.OutOfMemory;
        return ExprNode{
            .kind = .context_access,
            .value = path,
            .children = &.{},
            .start_byte = @intCast(first_start),
            .end_byte = @intCast(last_end),
        };
    }
};

/// `expr_base_byte` is the absolute file offset of `expr`, used only for
/// autofix Edit ranges; diagnostics keep reporting through `base_span`.
/// Pass `null` when it cannot be determined reliably: autofix is skipped
/// while diagnostics are still emitted.
pub fn validateExpression(
    allocator: std.mem.Allocator,
    expr: []const u8,
    base_span: Span,
    list: *DiagnosticList,
    expr_base_byte: ?usize,
) void {
    var parser = ExprParser.init(allocator, expr);
    const node = parser.parse() catch |err| {
        const msg = switch (err) {
            ParseError.EmptyExpression => "empty expression in ${{ }}",
            ParseError.UnclosedParen => parser.error_message orelse "unclosed parenthesis",
            ParseError.UnexpectedToken => parser.error_message orelse "invalid expression syntax",
            ParseError.OutOfMemory => "out of memory parsing expression",
        };
        list.append(.{
            .rule_id = "EXPR001",
            .severity = .@"error",
            .message = msg,
            .span = base_span,
        }) catch return;
        return;
    };
    validateNode(allocator, &node, base_span, list, expr_base_byte, null);
}

fn validateNode(
    allocator: std.mem.Allocator,
    node: *const ExprNode,
    span: Span,
    list: *DiagnosticList,
    expr_base_byte: ?usize,
    parent: ?*const ExprNode,
) void {
    switch (node.kind) {
        .context_access => validateContextAccess(allocator, node.value, span, list),
        .function_call => validateFunctionCall(allocator, node, span, list, expr_base_byte, parent),
        .binary_op, .unary_op => {
            if (node.kind == .binary_op) {
                checkUnsoundCondition(allocator, node, span, list, expr_base_byte);
                checkComparison(allocator, node, span, list);
            }
            for (node.children) |*child| {
                validateNode(allocator, child, span, list, expr_base_byte, node);
            }
        },
        .string_literal, .number_literal, .boolean_literal, .null_literal => {},
    }
}

fn validateContextAccess(allocator: std.mem.Allocator, path: []const u8, span: Span, list: *DiagnosticList) void {
    const result = expr_check.walkPath(path);
    const problem = result.problem orelse return;

    var buf: [96]u8 = undefined;
    const rule_id: []const u8, const severity: Severity, const message: []const u8 = switch (problem) {
        .unknown_context => |name| .{
            "EXPR002",
            .@"error",
            std.fmt.allocPrint(allocator, "unknown context: '{s}'", .{name}) catch "unknown context",
        },
        // Depth-1 accesses keep the historical wording
        // ("unknown github context property: 'x'").
        .unknown_property => |info| .{
            "EXPR003",
            .warning,
            if (std.mem.indexOfAny(u8, info.receiver_path, ".[") == null)
                std.fmt.allocPrint(allocator, "unknown {s} context property: '{s}'", .{ info.receiver_path, info.name }) catch "unknown context property"
            else
                std.fmt.allocPrint(allocator, "unknown property '{s}' on '{s}'", .{ info.name, info.receiver_path }) catch "unknown context property",
        },
        .not_an_object => |info| .{
            "EXPR003",
            .warning,
            std.fmt.allocPrint(
                allocator,
                "property '{s}' accessed on '{s}' which is {s}, not an object",
                .{ info.name, info.receiver_path, expr_type.display(info.receiver, &buf) },
            ) catch "property access on a non-object value",
        },
    };

    list.append(.{
        .rule_id = rule_id,
        .severity = severity,
        .message = message,
        .span = span,
    }) catch return;
}

fn checkComparison(allocator: std.mem.Allocator, node: *const ExprNode, span: Span, list: *DiagnosticList) void {
    if (node.children.len != 2) return;
    const op = node.value;
    if (!expr_check.isCompareOp(op)) return;

    const lhs = expr_check.typeOf(&node.children[0]);
    const rhs = expr_check.typeOf(&node.children[1]);
    if (expr_check.checkCompare(op, lhs, rhs)) return;

    var lhs_buf: [96]u8 = undefined;
    var rhs_buf: [96]u8 = undefined;
    const msg = std.fmt.allocPrint(
        allocator,
        "\"{s}\" value cannot be compared to \"{s}\" value with \"{s}\" operator",
        .{
            expr_type.display(lhs, &lhs_buf),
            expr_type.display(rhs, &rhs_buf),
            op,
        },
    ) catch "operands of this comparison have incompatible types";
    list.append(.{
        .rule_id = "EXPR017",
        .severity = .warning,
        .message = msg,
        .span = span,
        .fix_hint = "compare values of comparable types, or drop the comparison",
    }) catch return;
}

fn validateFunctionCall(
    allocator: std.mem.Allocator,
    node: *const ExprNode,
    span: Span,
    list: *DiagnosticList,
    expr_base_byte: ?usize,
    parent: ?*const ExprNode,
) void {
    const name = node.value;
    const arg_count: u8 = @intCast(node.children.len);

    if (catalog.lookupFunction(name)) |sig| {
        if (arg_count < sig.min_args or arg_count > sig.max_args) {
            const msg = if (sig.min_args == sig.max_args)
                std.fmt.allocPrint(allocator, "function '{s}' expects {d} argument(s), got {d}", .{ name, sig.min_args, arg_count }) catch "wrong number of arguments"
            else
                std.fmt.allocPrint(allocator, "function '{s}' expects {d}-{d} arguments, got {d}", .{ name, sig.min_args, sig.max_args, arg_count }) catch "wrong number of arguments";
            list.append(.{
                .rule_id = "EXPR005",
                .severity = .@"error",
                .message = msg,
                .span = span,
            }) catch return;
        }
    } else {
        const msg = std.fmt.allocPrint(allocator, "unknown function: '{s}'", .{name}) catch "unknown function";
        list.append(.{
            .rule_id = "EXPR004",
            .severity = .@"error",
            .message = msg,
            .span = span,
        }) catch return;
    }

    if (std.mem.eql(u8, name, "contains") and node.children.len == 2) {
        if (node.children[1].kind == .string_literal) {
            const fix = buildContainsEqFix(list, node, expr_base_byte, parent);
            list.append(.{
                .rule_id = "EXPR006",
                .severity = .warning,
                .message = "contains() uses substring matching which may match unintended values",
                .span = span,
                .fix_hint = "use exact comparison (== ) or startsWith()/endsWith() for precise matching",
                .fix = fix,
            }) catch return;
        }
    }

    for (node.children) |*child| {
        validateNode(allocator, child, span, list, expr_base_byte, node);
    }
}

fn buildContainsEqFix(
    list: *DiagnosticList,
    node: *const ExprNode,
    expr_base_byte: ?usize,
    parent: ?*const ExprNode,
) ?Fix {
    // Without a reliable byte base an Edit could land anywhere; diagnostic only.
    const base = expr_base_byte orelse return null;

    const ctx = &node.children[0];
    const lit = &node.children[1];

    if (ctx.kind != .context_access) return null;
    if (lit.kind != .string_literal) return null;

    if (std.mem.indexOf(u8, ctx.value, ".*") != null) return null;
    if (std.mem.indexOfScalar(u8, ctx.value, '[') != null) return null;

    if (lit.value.len >= 2) {
        const interior = lit.value[1 .. lit.value.len - 1];
        if (std.mem.indexOfScalar(u8, interior, '\'') != null) return null;
    }

    const is_negated = blk: {
        const p = parent orelse break :blk false;
        if (p.kind != .unary_op) break :blk false;
        break :blk std.mem.eql(u8, p.value, "!");
    };

    const alloc = list.fixAllocator();
    const op: []const u8 = if (is_negated) "!=" else "==";
    const replacement = std.fmt.allocPrint(alloc, "{s} {s} {s}", .{ ctx.value, op, lit.value }) catch return null;
    const edits = alloc.alloc(Edit, 1) catch return null;
    const start: usize = if (is_negated) base + parent.?.start_byte else base + node.start_byte;
    edits[0] = .{
        .start_byte = start,
        .end_byte = base + node.end_byte,
        .replacement = replacement,
    };
    return .{
        .description = if (is_negated) "replace !contains() with exact inequality" else "replace contains() with exact equality",
        .safety = .unsafe,
        .edits = edits,
    };
}

fn checkUnsoundCondition(
    allocator: std.mem.Allocator,
    node: *const ExprNode,
    span: Span,
    list: *DiagnosticList,
    expr_base_byte: ?usize,
) void {
    if (!std.mem.eql(u8, node.value, "||") and !std.mem.eql(u8, node.value, "&&")) return;

    for (node.children) |*child| {
        if (child.kind == .string_literal or child.kind == .number_literal) {
            const msg = std.fmt.allocPrint(
                allocator,
                "unsound condition: bare literal {s} as operand of '{s}' is always truthy",
                .{ child.value, node.value },
            ) catch "unsound condition: bare literal in logical operator";
            const fix = buildExpr007Fix(list, node, child, expr_base_byte);
            list.append(.{
                .rule_id = "EXPR007",
                .severity = .warning,
                .message = msg,
                .span = span,
                .fix_hint = if (std.mem.eql(u8, node.value, "||"))
                    "use an explicit comparison, e.g. github.event_name == 'push' || github.event_name == 'pull_request'"
                else
                    "use an explicit comparison, e.g. github.event_name != 'push' && github.event_name != 'pull_request'",
                .fix = fix,
            }) catch return;
        }
    }
}

/// Unsafe Edit that expands a bare string literal operand of `||` / `&&`
/// into a comparison borrowed from its sibling (`a == 'x' || 'y'` →
/// `a == 'x' || a == 'y'`). Only `==` under `||` and `!=` under `&&` pair
/// up; a bare number_literal is not handled yet (#158).
fn buildExpr007Fix(
    list: *DiagnosticList,
    node: *const ExprNode,
    bare: *const ExprNode,
    expr_base_byte: ?usize,
) ?Fix {
    const base = expr_base_byte orelse return null;

    if (bare.kind != .string_literal) return null;
    if (node.children.len != 2) return null;

    const op: []const u8 = if (std.mem.eql(u8, node.value, "||"))
        "=="
    else if (std.mem.eql(u8, node.value, "&&"))
        "!="
    else
        return null;

    const sibling: *const ExprNode = blk: {
        if (&node.children[0] == bare) break :blk &node.children[1];
        if (&node.children[1] == bare) break :blk &node.children[0];
        return null;
    };

    if (sibling.kind != .binary_op) return null;
    if (!std.mem.eql(u8, sibling.value, op)) return null;
    if (sibling.children.len != 2) return null;

    const lhs = &sibling.children[0];
    const rhs = &sibling.children[1];
    if (lhs.kind != .context_access) return null;
    if (rhs.kind != .string_literal) return null;

    if (std.mem.indexOf(u8, lhs.value, ".*") != null) return null;
    if (std.mem.indexOfScalar(u8, lhs.value, '[') != null) return null;

    if (!literalInteriorIsClean(bare.value)) return null;
    if (!literalInteriorIsClean(rhs.value)) return null;

    const alloc = list.fixAllocator();
    const replacement = std.fmt.allocPrint(alloc, "{s} {s} {s}", .{ lhs.value, op, bare.value }) catch return null;
    const edits = alloc.alloc(Edit, 1) catch return null;
    edits[0] = .{
        .start_byte = base + bare.start_byte,
        .end_byte = base + bare.end_byte,
        .replacement = replacement,
    };
    return .{
        .description = "expand bare literal into explicit comparison",
        .safety = .unsafe,
        .edits = edits,
    };
}

fn literalInteriorIsClean(lit_value: []const u8) bool {
    if (lit_value.len < 2) return true;
    const interior = lit_value[1 .. lit_value.len - 1];
    return std.mem.indexOfScalar(u8, interior, '\'') == null;
}

/// `anchor` maps offsets inside `text` back to source positions so each
/// expression is reported where it appears, not at the start of the
/// enclosing scalar. `text_base_byte` follows the `validateExpression`
/// contract: `null` suppresses autofix Edits but not diagnostics.
pub fn findAndValidateExpressions(
    allocator: std.mem.Allocator,
    text: []const u8,
    anchor: Anchor,
    list: *DiagnosticList,
    text_base_byte: ?usize,
) void {
    var pos: usize = 0;
    while (pos + 2 < text.len) {
        if (text[pos] == '$' and text[pos + 1] == '{' and text[pos + 2] == '{') {
            const expr_start = pos + 3;
            if (std.mem.indexOf(u8, text[expr_start..], "}}")) |end_offset| {
                const expr_content = text[expr_start .. expr_start + end_offset];
                const trimmed = std.mem.trim(u8, expr_content, " \t\n\r");
                const leading_trim = std.mem.indexOfNone(u8, expr_content, " \t\n\r") orelse 0;
                const expr_base_byte: ?usize = if (text_base_byte) |t| t + expr_start + leading_trim else null;
                const expr_span = anchor.at(text, pos, expr_start + end_offset + 2 - pos);
                validateExpression(allocator, trimmed, expr_span, list, expr_base_byte);
                pos = expr_start + end_offset + 2;
            } else {
                list.append(.{
                    .rule_id = "EXPR001",
                    .severity = .@"error",
                    .message = "unclosed expression: missing }}",
                    .span = anchor.at(text, pos, text.len - pos),
                }) catch return;
                return;
            }
        } else {
            pos += 1;
        }
    }
}

fn getArenaAllocator() std.mem.Allocator {
    // Leaks on purpose: diagnostic messages must outlive the call and the
    // engine provides no arena (#159).
    return std.heap.page_allocator;
}

/// For quoted scalars the parser's `value_span` starts at the opening quote,
/// so the content begins one byte later. For block scalars (`|` / `>`) the
/// span points at the indicator and the content-start byte is not preserved,
/// so no fix byte range can be derived: `null`.
fn scalarValueStartByte(meta: workflow_types.ScalarValueMeta) ?usize {
    return switch (meta.style) {
        .plain => meta.value_span.start_byte,
        .single_quoted, .double_quoted => meta.value_span.start_byte + 1,
        .literal, .folded => null,
    };
}

const IfConditionShape = enum {
    bare_expression,
    single_wrapped_expression,
    mixed_expression_string,
};

fn classifyIfConditionShape(if_val: []const u8) IfConditionShape {
    const trimmed = std.mem.trim(u8, if_val, " \t\n\r");
    if (std.mem.indexOf(u8, trimmed, "${{") == null) return .bare_expression;
    if (isSingleWrappedExpression(trimmed)) return .single_wrapped_expression;
    return .mixed_expression_string;
}

fn singleWrappedExpressionInner(s: []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, s, " \t\n\r");
    if (!std.mem.startsWith(u8, trimmed, "${{")) return null;
    const after_open = trimmed[3..];
    const close = std.mem.indexOf(u8, after_open, "}}") orelse return null;
    if (std.mem.trim(u8, after_open[close + 2 ..], " \t\n\r").len != 0) return null;
    const inner = std.mem.trim(u8, after_open[0..close], " \t\n\r");
    if (inner.len == 0) return null;
    return inner;
}

fn isSingleWrappedExpression(s: []const u8) bool {
    return singleWrappedExpressionInner(s) != null;
}

fn isConstantBooleanExpression(expr: []const u8) ?bool {
    var parser = ExprParser.init(std.heap.page_allocator, expr);
    const node = parser.parse() catch return null;
    if (node.kind != .boolean_literal) return null;
    return std.mem.eql(u8, node.value, "true");
}

fn checkIfConstantBoolean(
    expr: []const u8,
    span: Span,
    list: *DiagnosticList,
) void {
    const value = isConstantBooleanExpression(expr) orelse return;
    const msg = if (value)
        "if condition is always true"
    else
        "if condition is always false; this step or job will never run";
    list.append(.{
        .rule_id = "EXPR007",
        .severity = .warning,
        .message = msg,
        .span = span,
        .fix_hint = if (value)
            "remove the redundant `if:` or use a meaningful condition"
        else
            "remove the step or job, or fix the condition",
    }) catch return;
}

fn gapIsMergeable(gap: []const u8) bool {
    for (gap) |c| {
        switch (c) {
            ' ', '\t', '\n', '\r', '&', '|', '"', '\'' => {},
            else => return false,
        }
    }
    return true;
}

const IfExprBlock = struct {
    open: usize,
    close_end: usize,
    inner: []const u8,
};

fn findIfExprBlocks(if_val: []const u8) ?[]const IfExprBlock {
    var blocks: std.ArrayList(IfExprBlock) = .empty;
    var pos: usize = 0;
    while (pos + 2 < if_val.len) {
        if (!(if_val[pos] == '$' and if_val[pos + 1] == '{' and if_val[pos + 2] == '{')) {
            pos += 1;
            continue;
        }
        const inner_start = pos + 3;
        const close_rel = std.mem.indexOf(u8, if_val[inner_start..], "}}") orelse return null;
        const inner_end = inner_start + close_rel;
        const close_end = inner_end + 2;
        const inner = std.mem.trim(u8, if_val[inner_start..inner_end], " \t\n\r");
        if (inner.len == 0) return null;
        blocks.append(std.heap.page_allocator, .{
            .open = pos,
            .close_end = close_end,
            .inner = inner,
        }) catch return null;
        pos = close_end;
    }
    if (blocks.items.len == 0) return null;
    return blocks.toOwnedSlice(std.heap.page_allocator) catch null;
}

fn buildIfConditionMergeFix(
    list: *DiagnosticList,
    if_val: []const u8,
    base: ?usize,
) ?Fix {
    const base_byte = base orelse return null;
    const blocks = findIfExprBlocks(if_val) orelse return null;
    if (blocks.len < 2) return null;

    var prev_end: usize = 0;
    var combined: std.ArrayList(u8) = .empty;
    const alloc = list.fixAllocator();

    for (blocks, 0..) |block, i| {
        if (!gapIsMergeable(if_val[prev_end..block.open])) return null;
        if (i > 0) {
            const gap = if_val[prev_end..block.open];
            if (gap.len == 0) return null;
            combined.appendSlice(alloc, gap) catch return null;
        }
        combined.appendSlice(alloc, block.inner) catch return null;
        prev_end = block.close_end;
    }
    if (!gapIsMergeable(if_val[prev_end..])) return null;

    const replacement = std.fmt.allocPrint(alloc, "${{{{ {s} }}}}", .{combined.items}) catch return null;
    const edits = alloc.alloc(Edit, 1) catch return null;
    edits[0] = .{
        .start_byte = base_byte + blocks[0].open,
        .end_byte = base_byte + blocks[blocks.len - 1].close_end,
        .replacement = replacement,
    };
    return .{
        .description = "merge multiple ${{ }} expressions into a single expression",
        .safety = .unsafe,
        .edits = edits,
    };
}

fn checkMixedIfCondition(
    if_val: []const u8,
    span: Span,
    list: *DiagnosticList,
    base: ?usize,
) void {
    const msg = "if condition mixes text with ${{ }} expressions; GitHub stringifies the whole value so it is always truthy";
    const fix = buildIfConditionMergeFix(list, if_val, base);
    list.append(.{
        .rule_id = "EXPR007",
        .severity = .warning,
        .message = msg,
        .span = span,
        .fix_hint = "use a single ${{ }} expression, e.g. ${{ A && B }} instead of \"${{ A }} && ${{ B }}\"",
        .fix = fix,
    }) catch return;
}

/// GitHub allows the `${{ }}` wrapper to be omitted from `if:`, so a
/// condition without one is itself a single expression.
fn checkIfCondition(
    allocator: std.mem.Allocator,
    if_condition: ?[]const u8,
    meta: ?workflow_types.ScalarValueMeta,
    fallback: Span,
    list: *DiagnosticList,
) void {
    const if_val = if_condition orelse return;
    const anchor = Anchor.fromMeta(meta, fallback);
    const base: ?usize = if (meta) |m| scalarValueStartByte(m) else null;
    const span = anchor.at(if_val, 0, if_val.len);

    switch (classifyIfConditionShape(if_val)) {
        .mixed_expression_string => {
            checkMixedIfCondition(if_val, span, list, base);
            findAndValidateExpressions(allocator, if_val, anchor, list, base);
        },
        .single_wrapped_expression => {
            findAndValidateExpressions(allocator, if_val, anchor, list, base);
            const inner = singleWrappedExpressionInner(if_val) orelse return;
            checkIfConstantBoolean(inner, span, list);
        },
        .bare_expression => {
            const trimmed = std.mem.trim(u8, if_val, " \t\n\r");
            if (trimmed.len == 0) return;
            const leading: usize = @intFromPtr(trimmed.ptr) - @intFromPtr(if_val.ptr);
            const abs: ?usize = if (base) |b| b + leading else null;
            validateExpression(allocator, trimmed, anchor.at(if_val, leading, trimmed.len), list, abs);
            checkIfConstantBoolean(trimmed, span, list);
        },
    }
}

const ByteTracking = enum { track_bytes, no_bytes };

fn checkScalarMap(
    allocator: std.mem.Allocator,
    map: ?workflow_types.StringMap,
    meta_map: ?workflow_types.ScalarValueMetaMap,
    fallback: Span,
    list: *DiagnosticList,
    tracking: ByteTracking,
) void {
    const values = map orelse return;
    for (values.keys(), values.values()) |key, value| {
        const entry_meta = if (meta_map) |m| m.get(key) else null;
        const base: ?usize = switch (tracking) {
            .track_bytes => if (entry_meta) |m| scalarValueStartByte(m) else null,
            .no_bytes => null,
        };
        findAndValidateExpressions(allocator, value, Anchor.fromMeta(entry_meta, fallback), list, base);
    }
}

pub fn checkStep(step: *const Step, list: *DiagnosticList) void {
    const allocator = getArenaAllocator();

    // `run:` scalar style is not tracked and it is usually a block scalar,
    // whose content-start byte cannot be recovered; never derive fix ranges
    // from it.
    if (step.run) |run_val| {
        const run_anchor = spans.runAnchor(step);
        findAndValidateExpressions(allocator, run_val, run_anchor, list, null);
    }

    checkIfCondition(allocator, step.if_condition, step.if_condition_meta, step.span, list);

    // Per-entry scalar spans for `with:` are not captured, so the byte base
    // is unknown.
    checkScalarMap(allocator, step.with, step.with_meta, step.span, list, .no_bytes);

    checkScalarMap(allocator, step.env, step.env_meta, step.span, list, .track_bytes);
}

pub fn checkJob(job: *const Job, list: *DiagnosticList) void {
    const allocator = getArenaAllocator();

    checkIfCondition(allocator, job.if_condition, job.if_condition_meta, job.span, list);

    checkScalarMap(allocator, job.env, job.env_meta, job.span, list, .track_bytes);
}

pub const expression_rule = @import("engine.zig").Rule{
    .id = "EXPR",
    .name = "expression-validator",
    .description = "Validates GitHub Actions ${{ }} expressions",
    .severity = .@"error",
    .category = .expression,
    .check_step = &checkStep,
    .check_job = &checkJob,
};

fn expectNoDiagnostics(expr: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), expr, Span.point(1, 1, 0), &list, 0);
    if (list.len() != 0) {
        std.debug.print("unexpected diagnostic for '{s}': {s}\n", .{ expr, list.get(0).message });
        return error.UnexpectedDiagnostic;
    }
}

fn expectSingleRule(expr: []const u8, rule_id: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), expr, Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings(rule_id, list.get(0).rule_id);
}

test "tokenizer: simple identifier" {
    var t = ExprTokenizer.init("github");
    const tok = t.next();
    try std.testing.expectEqual(TokenKind.identifier, tok.kind);
    try std.testing.expectEqualStrings("github", tok.value);
    try std.testing.expectEqual(TokenKind.eof, t.next().kind);
}

test "tokenizer: dotted access" {
    var t = ExprTokenizer.init("github.sha");
    try std.testing.expectEqual(TokenKind.identifier, t.next().kind);
    try std.testing.expectEqual(TokenKind.dot, t.next().kind);
    try std.testing.expectEqual(TokenKind.identifier, t.next().kind);
    try std.testing.expectEqual(TokenKind.eof, t.next().kind);
}

test "tokenizer: comparison operators" {
    const ops = [_][]const u8{ "==", "!=", "<", ">", "<=", ">=" };
    for (ops) |op| {
        var t = ExprTokenizer.init(op);
        const tok = t.next();
        try std.testing.expectEqual(TokenKind.comparison_op, tok.kind);
        try std.testing.expectEqualStrings(op, tok.value);
    }
}

test "tokenizer: logical operators" {
    var t1 = ExprTokenizer.init("&&");
    try std.testing.expectEqual(TokenKind.logical_op, t1.next().kind);

    var t2 = ExprTokenizer.init("||");
    try std.testing.expectEqual(TokenKind.logical_op, t2.next().kind);
}

test "tokenizer: not operator" {
    var t = ExprTokenizer.init("!");
    const tok = t.next();
    try std.testing.expectEqual(TokenKind.not_op, tok.kind);
}

test "tokenizer: string literal" {
    var t = ExprTokenizer.init("'hello world'");
    const tok = t.next();
    try std.testing.expectEqual(TokenKind.string_literal, tok.kind);
    try std.testing.expectEqualStrings("'hello world'", tok.value);
}

test "tokenizer: unterminated string" {
    var t = ExprTokenizer.init("'hello");
    const tok = t.next();
    try std.testing.expectEqual(TokenKind.@"error", tok.kind);
}

test "tokenizer: number" {
    var t = ExprTokenizer.init("42");
    const tok = t.next();
    try std.testing.expectEqual(TokenKind.number, tok.kind);
    try std.testing.expectEqualStrings("42", tok.value);
}

test "tokenizer: function call tokens" {
    var t = ExprTokenizer.init("contains(github.event_name, 'push')");
    try std.testing.expectEqual(TokenKind.identifier, t.next().kind);
    try std.testing.expectEqual(TokenKind.open_paren, t.next().kind);
    try std.testing.expectEqual(TokenKind.identifier, t.next().kind);
    try std.testing.expectEqual(TokenKind.dot, t.next().kind);
    try std.testing.expectEqual(TokenKind.identifier, t.next().kind);
    try std.testing.expectEqual(TokenKind.comma, t.next().kind);
    try std.testing.expectEqual(TokenKind.string_literal, t.next().kind);
    try std.testing.expectEqual(TokenKind.close_paren, t.next().kind);
    try std.testing.expectEqual(TokenKind.eof, t.next().kind);
}

test "tokenizer: invalid single ampersand" {
    var t = ExprTokenizer.init("&");
    try std.testing.expectEqual(TokenKind.@"error", t.next().kind);
}

test "tokenizer: invalid single pipe" {
    var t = ExprTokenizer.init("|");
    try std.testing.expectEqual(TokenKind.@"error", t.next().kind);
}

test "parser: simple context access" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = ExprParser.init(arena.allocator(), "github.sha");
    const node = try parser.parse();
    try std.testing.expectEqual(NodeKind.context_access, node.kind);
    try std.testing.expectEqualStrings("github.sha", node.value);
}

test "parser: deep context access" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = ExprParser.init(arena.allocator(), "steps.build.outputs.result");
    const node = try parser.parse();
    try std.testing.expectEqual(NodeKind.context_access, node.kind);
    try std.testing.expectEqualStrings("steps.build.outputs.result", node.value);
}

test "parser: function call no args" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = ExprParser.init(arena.allocator(), "success()");
    const node = try parser.parse();
    try std.testing.expectEqual(NodeKind.function_call, node.kind);
    try std.testing.expectEqualStrings("success", node.value);
    try std.testing.expectEqual(@as(usize, 0), node.children.len);
}

test "parser: function call with args" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = ExprParser.init(arena.allocator(), "contains(github.event_name, 'push')");
    const node = try parser.parse();
    try std.testing.expectEqual(NodeKind.function_call, node.kind);
    try std.testing.expectEqualStrings("contains", node.value);
    try std.testing.expectEqual(@as(usize, 2), node.children.len);
    try std.testing.expectEqual(NodeKind.context_access, node.children[0].kind);
    try std.testing.expectEqual(NodeKind.string_literal, node.children[1].kind);
}

test "parser: binary comparison" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = ExprParser.init(arena.allocator(), "github.ref == 'refs/heads/main'");
    const node = try parser.parse();
    try std.testing.expectEqual(NodeKind.binary_op, node.kind);
    try std.testing.expectEqualStrings("==", node.value);
    try std.testing.expectEqual(@as(usize, 2), node.children.len);
}

test "parser: logical and" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = ExprParser.init(arena.allocator(), "github.ref == 'refs/heads/main' && github.event_name == 'push'");
    const node = try parser.parse();
    try std.testing.expectEqual(NodeKind.binary_op, node.kind);
    try std.testing.expectEqualStrings("&&", node.value);
}

test "parser: logical or" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = ExprParser.init(arena.allocator(), "success() || failure()");
    const node = try parser.parse();
    try std.testing.expectEqual(NodeKind.binary_op, node.kind);
    try std.testing.expectEqualStrings("||", node.value);
}

test "parser: unary not" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = ExprParser.init(arena.allocator(), "!cancelled()");
    const node = try parser.parse();
    try std.testing.expectEqual(NodeKind.unary_op, node.kind);
    try std.testing.expectEqualStrings("!", node.value);
    try std.testing.expectEqual(@as(usize, 1), node.children.len);
}

test "parser: boolean literal" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = ExprParser.init(arena.allocator(), "true");
    const node = try parser.parse();
    try std.testing.expectEqual(NodeKind.boolean_literal, node.kind);
    try std.testing.expectEqualStrings("true", node.value);
}

test "parser: null literal" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = ExprParser.init(arena.allocator(), "null");
    const node = try parser.parse();
    try std.testing.expectEqual(NodeKind.null_literal, node.kind);
}

test "parser: parenthesized expression" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = ExprParser.init(arena.allocator(), "(github.ref == 'refs/heads/main')");
    const node = try parser.parse();
    try std.testing.expectEqual(NodeKind.binary_op, node.kind);
}

test "parser: empty expression error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = ExprParser.init(arena.allocator(), "");
    const result = parser.parse();
    try std.testing.expectError(ParseError.EmptyExpression, result);
}

test "parser: unclosed paren error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = ExprParser.init(arena.allocator(), "(github.sha");
    const result = parser.parse();
    try std.testing.expectError(ParseError.UnclosedParen, result);
}

test "parser: unclosed function call error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = ExprParser.init(arena.allocator(), "contains(github.ref");
    const result = parser.parse();
    try std.testing.expectError(ParseError.UnclosedParen, result);
}

test "parser: byte offsets for string literal" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src = "'hello'";
    var parser = ExprParser.init(arena.allocator(), src);
    const node = try parser.parse();
    try std.testing.expectEqual(NodeKind.string_literal, node.kind);
    try std.testing.expectEqual(@as(u32, 0), node.start_byte);
    try std.testing.expectEqual(@as(u32, @intCast(src.len)), node.end_byte);
}

test "parser: byte offsets for context access" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src = "github.ref";
    var parser = ExprParser.init(arena.allocator(), src);
    const node = try parser.parse();
    try std.testing.expectEqual(NodeKind.context_access, node.kind);
    try std.testing.expectEqual(@as(u32, 0), node.start_byte);
    try std.testing.expectEqual(@as(u32, @intCast(src.len)), node.end_byte);
}

test "parser: byte offsets for function call" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src = "contains(github.ref, 'main')";
    var parser = ExprParser.init(arena.allocator(), src);
    const node = try parser.parse();
    try std.testing.expectEqual(NodeKind.function_call, node.kind);
    try std.testing.expectEqual(@as(u32, 0), node.start_byte);
    try std.testing.expectEqual(@as(u32, @intCast(src.len)), node.end_byte);

    // First arg: github.ref at [9, 19)
    const arg0 = node.children[0];
    try std.testing.expectEqual(NodeKind.context_access, arg0.kind);
    try std.testing.expectEqual(@as(u32, 9), arg0.start_byte);
    try std.testing.expectEqual(@as(u32, 19), arg0.end_byte);

    // Second arg: 'main' at [21, 27)
    const arg1 = node.children[1];
    try std.testing.expectEqual(NodeKind.string_literal, arg1.kind);
    try std.testing.expectEqual(@as(u32, 21), arg1.start_byte);
    try std.testing.expectEqual(@as(u32, 27), arg1.end_byte);
}

test "parser: byte offsets for unary not" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src = "!cancelled()";
    var parser = ExprParser.init(arena.allocator(), src);
    const node = try parser.parse();
    try std.testing.expectEqual(NodeKind.unary_op, node.kind);
    try std.testing.expectEqual(@as(u32, 0), node.start_byte);
    try std.testing.expectEqual(@as(u32, @intCast(src.len)), node.end_byte);
}

test "parser: byte offsets for binary op" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src = "github.ref == 'main'";
    var parser = ExprParser.init(arena.allocator(), src);
    const node = try parser.parse();
    try std.testing.expectEqual(NodeKind.binary_op, node.kind);
    try std.testing.expectEqual(@as(u32, 0), node.start_byte);
    try std.testing.expectEqual(@as(u32, @intCast(src.len)), node.end_byte);
}

test "parser: byte offsets for star context access" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const src = "github.event.commits.*.message";
    var parser = ExprParser.init(arena.allocator(), src);
    const node = try parser.parse();
    try std.testing.expectEqual(NodeKind.context_access, node.kind);
    try std.testing.expectEqual(@as(u32, 0), node.start_byte);
    try std.testing.expectEqual(@as(u32, @intCast(src.len)), node.end_byte);
}

test "validate: valid expression github.sha" {
    try expectNoDiagnostics("github.sha");
}

test "validate: valid expression github.ref" {
    try expectNoDiagnostics("github.ref == 'refs/heads/main'");
}

test "validate: valid function contains" {
    try expectSingleRule("contains(github.event_name, 'push')", "EXPR006");
}

test "validate: valid function success" {
    try expectNoDiagnostics("success()");
}

test "validate: valid expression with runner.os" {
    try expectNoDiagnostics("runner.os == 'Linux'");
}

test "validate: valid complex expression" {
    try expectSingleRule("github.event_name == 'push' && contains(github.ref, 'main')", "EXPR006");
}

test "validate: valid contexts env, secrets, matrix, steps, needs, inputs, vars, strategy, job, jobs" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();
    const span = Span.point(1, 1, 0);

    const contexts = [_][]const u8{
        "env.MY_VAR",                  "secrets.TOKEN",
        "matrix.os",                   "steps.build.outputs.result",
        "needs.setup.outputs.version", "inputs.debug",
        "vars.DEPLOY_ENV",             "strategy.job-index",
        "job.status",                  "jobs.build.result",
    };
    for (contexts) |ctx| {
        validateExpression(arena.allocator(), ctx, span, &list, 0);
    }
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "validate: unknown context" {
    try expectSingleRule("unknown.property", "EXPR002");
}

test "validate: unknown github property" {
    try expectSingleRule("github.nonexistent_prop", "EXPR003");
}

test "validate: known github properties are not reported" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const props = [_][]const u8{
        "github.actor_id",
        "github.artifact_cache_size_limit",
        "github.event_path",
        "github.ref_protected",
        "github.repository_id",
        "github.repository_owner_id",
        "github.repository_visibility",
        "github.secret_source",
        "github.state",
    };
    for (props) |expr| {
        var list = DiagnosticList.init(std.testing.allocator);
        defer list.deinit();

        validateExpression(arena.allocator(), expr, Span.point(1, 1, 0), &list, 0);
        try std.testing.expectEqual(@as(usize, 0), list.len());
    }
}

test "validate: unknown runner property" {
    try expectSingleRule("runner.nonexistent", "EXPR003");
}

test "validate: unknown function" {
    try expectSingleRule("unknownFunc()", "EXPR004");
}

test "validate: case() is a known function" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    // With a trailing default, and at the 3-argument minimum without one.
    validateExpression(arena.allocator(), "case(github.ref_name, 'main', 'prod', 'staging')", Span.point(1, 1, 0), &list, 0);
    validateExpression(arena.allocator(), "case(github.ref_name, 'main', 'prod')", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "validate: case() with too few arguments" {
    try expectSingleRule("case(github.ref_name, 'main')", "EXPR005");
}

test "validate: wrong arg count for contains" {
    try expectSingleRule("contains(github.ref)", "EXPR005");
}

test "validate: wrong arg count for success" {
    try expectSingleRule("success('unexpected')", "EXPR005");
}

test "validate: empty expression" {
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(std.testing.allocator, "", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR001", list.get(0).rule_id);
}

test "validate: syntax error unclosed paren" {
    try expectSingleRule("(github.sha", "EXPR001");
}

test "find expressions: single expression in string" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    findAndValidateExpressions(arena.allocator(), "echo ${{ github.sha }}", Anchor{ .fallback = Span.point(1, 1, 0) }, &list, 0);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "find expressions: multiple expressions" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    findAndValidateExpressions(arena.allocator(), "${{ github.sha }} and ${{ github.ref }}", Anchor{ .fallback = Span.point(1, 1, 0) }, &list, 0);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "find expressions: unclosed expression" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    findAndValidateExpressions(arena.allocator(), "echo ${{ github.sha", Anchor{ .fallback = Span.point(1, 1, 0) }, &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR001", list.get(0).rule_id);
}

test "find expressions: no expressions in plain text" {
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    findAndValidateExpressions(std.testing.allocator, "echo hello world", Anchor{ .fallback = Span.point(1, 1, 0) }, &list, 0);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "find expressions: expression with unknown context" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    findAndValidateExpressions(arena.allocator(), "${{ badcontext.value }}", Anchor{ .fallback = Span.point(1, 1, 0) }, &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR002", list.get(0).rule_id);
}

test "checkStep: valid run expression" {
    const step = Step{
        .run = "echo ${{ github.sha }}",
    };
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    checkStep(&step, &list);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "checkStep: invalid run expression with unknown context" {
    const step = Step{
        .run = "echo ${{ badctx.val }}",
    };
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    checkStep(&step, &list);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR002", list.get(0).rule_id);
}

test "checkStep: if expression validated" {
    const step = Step{
        .if_condition = "github.event_name == 'push'",
        .run = "echo hello",
    };
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    checkStep(&step, &list);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "checkStep: if with ${{ }} expression" {
    const step = Step{
        .if_condition = "${{ github.ref == 'refs/heads/main' }}",
        .run = "echo hello",
    };
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    checkStep(&step, &list);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "checkJob: if expression validated" {
    const job = Job{
        .id = "deploy",
        .if_condition = "github.ref == 'refs/heads/main'",
    };
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    checkJob(&job, &list);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "checkJob: invalid if expression" {
    const job = Job{
        .id = "deploy",
        .if_condition = "badcontext.ref == 'main'",
    };
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    checkJob(&job, &list);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR002", list.get(0).rule_id);
}

test "validate: all valid functions with correct args" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();
    const span = Span.point(1, 1, 0);

    const exprs = [_][]const u8{
        "contains('hello', 'ell')",
        "startsWith('hello', 'hel')",
        "endsWith('hello', 'llo')",
        "format('Hello {0}', 'world')",
        "join(github.event, ', ')",
        "toJSON(github.event)",
        "fromJSON('{}')",
        "hashFiles('**/package-lock.json')",
        "success()",
        "always()",
        "cancelled()",
        "failure()",
    };
    for (exprs) |expr| {
        validateExpression(arena.allocator(), expr, span, &list, 0);
    }
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR006", list.get(0).rule_id);
}

test "validate: all valid github properties" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();
    const span = Span.point(1, 1, 0);

    const props = [_][]const u8{
        "github.sha",        "github.ref",        "github.actor",
        "github.repository", "github.event_name", "github.workspace",
        "github.run_id",     "github.run_number", "github.token",
    };
    for (props) |prop| {
        validateExpression(arena.allocator(), prop, span, &list, 0);
    }
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "validate: all valid runner properties" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();
    const span = Span.point(1, 1, 0);

    const props = [_][]const u8{
        "runner.os",   "runner.arch",       "runner.name",
        "runner.temp", "runner.tool_cache", "runner.debug",
    };
    for (props) |prop| {
        validateExpression(arena.allocator(), prop, span, &list, 0);
    }
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "validate: hashFiles with multiple args" {
    try expectNoDiagnostics("hashFiles('**/package-lock.json', '**/yarn.lock')");
}

test "validate: format with multiple args" {
    try expectNoDiagnostics("format('{0}-{1}', github.ref, github.sha)");
}

test "validate: nested function calls" {
    try expectSingleRule("contains(toJSON(github.event), 'push')", "EXPR006");
}

test "validate: complex logical expression" {
    try expectNoDiagnostics("!cancelled() && (success() || failure())");
}

test "validate: toJSON wrong args" {
    try expectSingleRule("toJSON(github.event, 'extra')", "EXPR005");
}

test "EXPR006: contains with string literal second arg" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "contains(github.ref, 'main')", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR006", list.get(0).rule_id);
    try std.testing.expectEqual(Severity.warning, list.get(0).severity);
    try std.testing.expect(list.get(0).fix_hint != null);
}

test "EXPR006: contains in complex expression" {
    try expectSingleRule("contains(github.ref, 'main') && github.event_name == 'push'", "EXPR006");
}

test "EXPR006: contains nested in not" {
    try expectSingleRule("!contains(github.ref, 'release')", "EXPR006");
}

test "EXPR006: multiple contains calls" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "contains(github.ref, 'main') || contains(github.actor, 'bot')", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 2), list.len());
    try std.testing.expectEqualStrings("EXPR006", list.get(0).rule_id);
    try std.testing.expectEqualStrings("EXPR006", list.get(1).rule_id);
}

test "EXPR006: no warning for startsWith" {
    try expectNoDiagnostics("startsWith(github.ref, 'refs/heads/main')");
}

test "EXPR006: no warning for exact comparison" {
    try expectNoDiagnostics("github.ref == 'refs/heads/main'");
}

test "EXPR006: no warning for non-literal second arg" {
    try expectNoDiagnostics("contains(github.ref, github.base_ref)");
}

test "EXPR006: checkStep contains in if condition" {
    const step = Step{
        .if_condition = "contains(github.ref, 'main')",
    };
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    checkStep(&step, &list);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR006", list.get(0).rule_id);
}

test "EXPR006: checkJob contains in if condition" {
    const job = Job{
        .id = "deploy",
        .if_condition = "contains(github.ref, 'main')",
    };
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    checkJob(&job, &list);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR006", list.get(0).rule_id);
}

test "EXPR006 fix: replaces contains(ctx, 'lit') with ctx == 'lit'" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "contains(github.ref, 'main')", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    const diag = list.get(0);
    try std.testing.expectEqualStrings("EXPR006", diag.rule_id);
    try std.testing.expect(diag.fix != null);
    const fix = diag.fix.?;
    try std.testing.expectEqual(diagnostics.FixSafety.unsafe, fix.safety);
    try std.testing.expectEqual(@as(usize, 1), fix.edits.len);
    const edit = fix.edits[0];
    try std.testing.expectEqual(@as(usize, 0), edit.start_byte);
    try std.testing.expectEqual(@as(usize, 28), edit.end_byte);
    try std.testing.expectEqualStrings("github.ref == 'main'", edit.replacement);
}

test "EXPR006 fix: honors expr_base_byte offset" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "contains(github.ref, 'main')", Span.point(1, 1, 0), &list, 100);
    const edit = list.get(0).fix.?.edits[0];
    try std.testing.expectEqual(@as(usize, 100), edit.start_byte);
    try std.testing.expectEqual(@as(usize, 128), edit.end_byte);
}

test "EXPR006 fix V2: rewrites !contains(ctx, 'lit') to ctx != 'lit'" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    const src = "!contains(github.ref, 'release')";
    validateExpression(arena.allocator(), src, Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    const diag = list.get(0);
    try std.testing.expectEqualStrings("EXPR006", diag.rule_id);
    try std.testing.expect(diag.fix != null);
    const fix = diag.fix.?;
    try std.testing.expectEqual(diagnostics.FixSafety.unsafe, fix.safety);
    try std.testing.expectEqual(@as(usize, 1), fix.edits.len);
    const edit = fix.edits[0];
    // The replacement spans the entire !contains(...) including the leading '!'.
    try std.testing.expectEqual(@as(usize, 0), edit.start_byte);
    try std.testing.expectEqual(@as(usize, src.len), edit.end_byte);
    try std.testing.expectEqualStrings("github.ref != 'release'", edit.replacement);
}

test "EXPR006 fix: no fix when first arg is function_call" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "contains(toJSON(github.event), 'push')", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR006", list.get(0).rule_id);
    try std.testing.expect(list.get(0).fix == null);
}

test "EXPR006 fix: no fix when first arg is literal" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "contains('hello', 'ell')", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR006", list.get(0).rule_id);
    try std.testing.expect(list.get(0).fix == null);
}

test "EXPR006 fix: no fix when context path contains .* (array access)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "contains(github.event.commits.*.message, 'wip')", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expect(list.get(0).fix == null);
}

test "EXPR006 fix: no fix when context path contains [ (bracket access)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "contains(github.event['ref'], 'main')", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expect(list.get(0).fix == null);
}

test "EXPR006 fix: no fix when literal contains '' escape" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "contains(github.ref, 'it''s')", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expect(list.get(0).fix == null);
}

test "validate EXPR007: bare string literal right of ||" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.event_name == 'push' || 'pull_request'", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR007", list.get(0).rule_id);
    try std.testing.expectEqual(Severity.warning, list.get(0).severity);
}

test "validate EXPR007: bare string literal right of &&" {
    try expectSingleRule("github.event_name != 'push' && 'pull_request'", "EXPR007");
}

test "validate EXPR007: bare string literal left of ||" {
    try expectSingleRule("'push' || github.event_name == 'pull_request'", "EXPR007");
}

test "validate EXPR007: bare number literal right of ||" {
    try expectSingleRule("github.run_attempt == 1 || 2", "EXPR007");
}

test "validate EXPR007: no false positive for proper comparison" {
    try expectNoDiagnostics("github.event_name == 'push' || github.event_name == 'pull_request'");
}

test "validate EXPR007: no false positive for function call operands" {
    try expectNoDiagnostics("success() || failure()");
}

test "validate EXPR007: no false positive for boolean literal" {
    try expectNoDiagnostics("true || github.event_name == 'push'");
}

test "validate EXPR007: multiple bare literals in chained ||" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.event_name == 'push' || 'pull_request' || 'workflow_dispatch'", Span.point(1, 1, 0), &list, 0);
    var expr007_count: usize = 0;
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "EXPR007")) expr007_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), expr007_count);
}

test "checkStep EXPR007: if condition with bare literal" {
    const step = Step{
        .if_condition = "github.event_name == 'push' || 'pull_request'",
        .run = "echo deploy",
    };
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    checkStep(&step, &list);
    try std.testing.expect(test_support.hasDiagnostic(&list, "EXPR007"));
}

test "checkJob EXPR007: if condition with bare literal" {
    const job = Job{
        .id = "deploy",
        .if_condition = "github.event_name == 'push' || 'pull_request'",
    };
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    checkJob(&job, &list);
    try std.testing.expect(test_support.hasDiagnostic(&list, "EXPR007"));
}

test "checkStep EXPR007: if condition always false (bare)" {
    const step = Step{
        .if_condition = "false",
        .run = "echo never",
    };
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    checkStep(&step, &list);
    try std.testing.expect(test_support.hasDiagnostic(&list, "EXPR007"));
}

test "checkStep EXPR007: if condition always false (wrapped)" {
    const step = Step{
        .if_condition = "${{ false }}",
        .run = "echo never",
    };
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    checkStep(&step, &list);
    try std.testing.expect(test_support.hasDiagnostic(&list, "EXPR007"));
}

test "checkJob EXPR007: if condition always false" {
    const job = Job{
        .id = "deploy",
        .if_condition = "false",
    };
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    checkJob(&job, &list);
    try std.testing.expect(test_support.hasDiagnostic(&list, "EXPR007"));
}

test "checkStep EXPR007: if condition always true (bare)" {
    const step = Step{
        .if_condition = "true",
        .run = "echo always",
    };
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    checkStep(&step, &list);
    try std.testing.expect(test_support.hasDiagnostic(&list, "EXPR007"));
}

test "checkStep EXPR007: mixed expression string is always truthy" {
    const step = Step{
        .if_condition = "${{ github.event_name == 'push' }} && ${{ github.ref == 'refs/heads/main' }}",
        .run = "echo always",
    };
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    checkStep(&step, &list);
    try std.testing.expect(test_support.hasDiagnostic(&list, "EXPR007"));
}

test "checkStep EXPR007: prefix text with expression is always truthy" {
    const step = Step{
        .if_condition = "foo ${{ github.event_name == 'push' }}",
        .run = "echo always",
    };
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    checkStep(&step, &list);
    try std.testing.expect(test_support.hasDiagnostic(&list, "EXPR007"));
}

test "checkStep EXPR007: no false positive for single wrapped expression" {
    const step = Step{
        .if_condition = "${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}",
        .run = "echo hi",
    };
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    checkStep(&step, &list);
    try std.testing.expect(!test_support.hasDiagnostic(&list, "EXPR007"));
}

test "checkStep EXPR007: no false positive for bare expression" {
    const step = Step{
        .if_condition = "github.event_name == 'push'",
        .run = "echo hi",
    };
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    checkStep(&step, &list);
    try std.testing.expect(!test_support.hasDiagnostic(&list, "EXPR007"));
}

test "EXPR007 fix: merges multiple ${{ }} expressions in if condition" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    const step = Step{
        .if_condition = "${{ github.event_name == 'push' }} && ${{ github.ref == 'refs/heads/main' }}",
        .if_condition_meta = .{
            .value_span = .{
                .start_line = 1,
                .start_col = 5,
                .end_line = 1,
                .end_col = 81,
                .start_byte = 4,
                .end_byte = 80,
            },
            .style = .plain,
        },
        .run = "echo always",
    };
    checkStep(&step, &list);

    const fix = firstFix(list, "EXPR007") orelse return error.TestExpectedFix;
    try std.testing.expectEqualStrings(
        "${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}",
        fix.edits[0].replacement,
    );
}

test "EXPR007 fix: no fix when mixed if condition has non-operator text" {
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    const step = Step{
        .if_condition = "foo ${{ github.event_name == 'push' }}",
        .run = "echo always",
    };
    checkStep(&step, &list);
    try std.testing.expect(firstFix(list, "EXPR007") == null);
}

test "EXPR006 autofix: applied end-to-end on bare (double-quoted) `if:` scalar" {
    const fix_engine = @import("../fix/engine.zig");

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\name: t
        \\on: push
        \\jobs:
        \\  deploy:
        \\    runs-on: ubuntu-latest
        \\    if: "contains(github.ref, 'main')"
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    const wf = try test_support.parseWorkflowSource(alloc, source);

    var diags = DiagnosticList.init(alloc);
    checkJob(&wf.jobs[0], &diags);

    var fix_list = std.ArrayList(Fix){};
    defer fix_list.deinit(std.testing.allocator);
    for (diags.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "EXPR006")) {
            if (d.fix) |f| try fix_list.append(std.testing.allocator, f);
        }
    }
    try std.testing.expectEqual(@as(usize, 1), fix_list.items.len);

    const result = try fix_engine.applyFixes(std.testing.allocator, source, fix_list.items);
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), result.edits_applied);
    try std.testing.expect(std.mem.indexOf(u8, result.content, "if: \"github.ref == 'main'\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.content, "contains(") == null);
}

test "EXPR006 autofix: applied end-to-end on `${{ }}` inside double-quoted `if:`" {
    const fix_engine = @import("../fix/engine.zig");

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\name: t
        \\on: push
        \\jobs:
        \\  deploy:
        \\    runs-on: ubuntu-latest
        \\    if: "${{ contains(github.event_name, 'push') }}"
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    const wf = try test_support.parseWorkflowSource(alloc, source);

    var diags = DiagnosticList.init(alloc);
    checkJob(&wf.jobs[0], &diags);

    var fix_list = std.ArrayList(Fix){};
    defer fix_list.deinit(std.testing.allocator);
    for (diags.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "EXPR006")) {
            if (d.fix) |f| try fix_list.append(std.testing.allocator, f);
        }
    }
    try std.testing.expectEqual(@as(usize, 1), fix_list.items.len);

    const result = try fix_engine.applyFixes(std.testing.allocator, source, fix_list.items);
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(std.mem.indexOf(u8, result.content, "${{ github.event_name == 'push' }}") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.content, "contains(") == null);
}

test "EXPR006 autofix: --fix (safe only) does not apply EXPR006 fixes" {
    const fix_engine = @import("../fix/engine.zig");

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\name: t
        \\on: push
        \\jobs:
        \\  deploy:
        \\    runs-on: ubuntu-latest
        \\    if: "contains(github.ref, 'main')"
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    const wf = try test_support.parseWorkflowSource(alloc, source);

    var diags = DiagnosticList.init(alloc);
    checkJob(&wf.jobs[0], &diags);

    const safe_only = try fix_engine.collectFixes(std.testing.allocator, diags.items.items, false);
    defer std.testing.allocator.free(safe_only);
    for (safe_only) |f| {
        try std.testing.expect(!std.mem.eql(u8, f.description, "replace contains() with exact equality"));
    }

    const unsafe_too = try fix_engine.collectFixes(std.testing.allocator, diags.items.items, true);
    defer std.testing.allocator.free(unsafe_too);
    var saw_contains_fix = false;
    for (unsafe_too) |f| {
        if (std.mem.eql(u8, f.description, "replace contains() with exact equality")) saw_contains_fix = true;
    }
    try std.testing.expect(saw_contains_fix);
}

test "EXPR006 autofix V2: rewrites !contains(ctx, 'lit') to ctx != 'lit' end-to-end" {
    const fix_engine = @import("../fix/engine.zig");

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\name: t
        \\on: push
        \\jobs:
        \\  deploy:
        \\    runs-on: ubuntu-latest
        \\    if: "!contains(github.ref, 'release')"
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    const wf = try test_support.parseWorkflowSource(alloc, source);

    var diags = DiagnosticList.init(alloc);
    checkJob(&wf.jobs[0], &diags);

    var fix_list = std.ArrayList(Fix){};
    defer fix_list.deinit(std.testing.allocator);
    for (diags.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "EXPR006")) {
            if (d.fix) |f| try fix_list.append(std.testing.allocator, f);
        }
    }
    try std.testing.expectEqual(@as(usize, 1), fix_list.items.len);
    try std.testing.expectEqualStrings(
        "replace !contains() with exact inequality",
        fix_list.items[0].description,
    );

    const result = try fix_engine.applyFixes(std.testing.allocator, source, fix_list.items);
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), result.edits_applied);
    try std.testing.expect(std.mem.indexOf(u8, result.content, "if: \"github.ref != 'release'\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.content, "contains(") == null);
}

test "EXPR006 fix: suppressed when expr_base_byte is null" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "contains(github.ref, 'main')", Span.point(1, 1, 0), &list, null);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    const diag = list.get(0);
    try std.testing.expectEqualStrings("EXPR006", diag.rule_id);
    try std.testing.expect(diag.fix == null);
}

test "EXPR006 autofix: suppressed for `with:` values" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\name: t
        \\on: push
        \\jobs:
        \\  deploy:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - uses: actions/checkout@v4
        \\        with:
        \\          condition: ${{ contains(github.ref, 'main') }}
        \\
    ;

    const wf = try test_support.parseWorkflowSource(alloc, source);

    var diags = DiagnosticList.init(alloc);
    checkStep(&wf.jobs[0].steps[0], &diags);

    // If EXPR006 fires for this path, it must not carry a fix. Whether the
    // diagnostic fires at all for `with:` values is a separate concern handled
    // by other rules/tests.
    for (diags.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "EXPR006")) {
            try std.testing.expect(d.fix == null);
        }
    }
}

test "EXPR006 autofix: suppressed for `run:` values" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\name: t
        \\on: push
        \\jobs:
        \\  deploy:
        \\    runs-on: ubuntu-latest
        \\    steps:
        \\      - run: echo ${{ contains(github.ref, 'main') }}
        \\
    ;

    const wf = try test_support.parseWorkflowSource(alloc, source);

    var diags = DiagnosticList.init(alloc);
    checkStep(&wf.jobs[0].steps[0], &diags);

    // If EXPR006 fires for this path, it must not carry a fix.
    for (diags.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "EXPR006")) {
            try std.testing.expect(d.fix == null);
        }
    }
}

test "EXPR006 autofix: suppressed for block-scalar `if:` value" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Folded block scalar for `if:`. The YAML parser's value_span starts at
    // `>` while the .value slice starts after the newline, so the absolute
    // byte base cannot be recovered and fix emission must be suppressed.
    const source =
        \\name: t
        \\on: push
        \\jobs:
        \\  deploy:
        \\    runs-on: ubuntu-latest
        \\    if: >
        \\      contains(github.ref, 'main')
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    const wf = try test_support.parseWorkflowSource(alloc, source);

    var diags = DiagnosticList.init(alloc);
    checkJob(&wf.jobs[0], &diags);

    var saw_diag = false;
    for (diags.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "EXPR006")) {
            saw_diag = true;
            try std.testing.expect(d.fix == null);
        }
    }
    try std.testing.expect(saw_diag);
}

fn firstFix(list: DiagnosticList, rule_id: []const u8) ?Fix {
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, rule_id)) {
            if (d.fix) |f| return f;
        }
    }
    return null;
}

test "EXPR007 fix: rewrites bare string right of ||" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    const src = "github.event_name == 'push' || 'pull_request'";
    validateExpression(arena.allocator(), src, Span.point(1, 1, 0), &list, 0);
    const fix = firstFix(list, "EXPR007") orelse return error.TestExpectedFix;
    try std.testing.expectEqual(diagnostics.FixSafety.unsafe, fix.safety);
    try std.testing.expectEqual(@as(usize, 1), fix.edits.len);
    const edit = fix.edits[0];
    // The replacement covers the bare literal exactly, including its quotes.
    try std.testing.expectEqual(@as(usize, std.mem.indexOf(u8, src, "'pull_request'").?), edit.start_byte);
    try std.testing.expectEqual(@as(usize, src.len), edit.end_byte);
    try std.testing.expectEqualStrings("github.event_name == 'pull_request'", edit.replacement);
}

test "EXPR007 fix: rewrites bare string left of ||" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    const src = "'pull_request' || github.event_name == 'push'";
    validateExpression(arena.allocator(), src, Span.point(1, 1, 0), &list, 0);
    const fix = firstFix(list, "EXPR007") orelse return error.TestExpectedFix;
    try std.testing.expectEqual(@as(usize, 1), fix.edits.len);
    const edit = fix.edits[0];
    try std.testing.expectEqual(@as(usize, 0), edit.start_byte);
    try std.testing.expectEqual(@as(usize, "'pull_request'".len), edit.end_byte);
    try std.testing.expectEqualStrings("github.event_name == 'pull_request'", edit.replacement);
}

test "EXPR007 fix: rewrites bare string with && and !=" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    const src = "github.event_name != 'push' && 'pull_request'";
    validateExpression(arena.allocator(), src, Span.point(1, 1, 0), &list, 0);
    const fix = firstFix(list, "EXPR007") orelse return error.TestExpectedFix;
    try std.testing.expectEqualStrings("github.event_name != 'pull_request'", fix.edits[0].replacement);
}

test "EXPR007 fix: honors expr_base_byte offset" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    const src = "github.event_name == 'push' || 'pull_request'";
    const base: usize = 100;
    validateExpression(arena.allocator(), src, Span.point(1, 1, 0), &list, base);
    const fix = firstFix(list, "EXPR007") orelse return error.TestExpectedFix;
    const lit_offset = std.mem.indexOf(u8, src, "'pull_request'").?;
    try std.testing.expectEqual(@as(usize, base + lit_offset), fix.edits[0].start_byte);
    try std.testing.expectEqual(@as(usize, base + src.len), fix.edits[0].end_byte);
}

test "EXPR007 fix: no fix when sibling is function_call" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "success() || 'pull_request'", Span.point(1, 1, 0), &list, 0);
    var saw_diag = false;
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "EXPR007")) {
            saw_diag = true;
            try std.testing.expect(d.fix == null);
        }
    }
    try std.testing.expect(saw_diag);
}

test "EXPR007 fix: no fix when LHS is not context_access" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "'a' == 'push' || 'pull_request'", Span.point(1, 1, 0), &list, 0);
    try std.testing.expect(firstFix(list, "EXPR007") == null);
}

test "EXPR007 fix: no fix when LHS path contains .* (array access)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.event.commits.*.message == 'wip' || 'fixup'", Span.point(1, 1, 0), &list, 0);
    try std.testing.expect(firstFix(list, "EXPR007") == null);
}

test "EXPR007 fix: no fix when LHS path contains [ (bracket access)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.event['ref'] == 'main' || 'release'", Span.point(1, 1, 0), &list, 0);
    try std.testing.expect(firstFix(list, "EXPR007") == null);
}

test "EXPR007 fix: no fix when bare literal contains '' escape" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.ref == 'main' || 'it''s'", Span.point(1, 1, 0), &list, 0);
    try std.testing.expect(firstFix(list, "EXPR007") == null);
}

test "EXPR007 fix: no fix when sibling literal contains '' escape" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.ref == 'it''s' || 'main'", Span.point(1, 1, 0), &list, 0);
    try std.testing.expect(firstFix(list, "EXPR007") == null);
}

test "EXPR007 fix: no fix for || with != mismatch (tautology)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.ref != 'main' || 'release'", Span.point(1, 1, 0), &list, 0);
    try std.testing.expect(firstFix(list, "EXPR007") == null);
}

test "EXPR007 fix: no fix for && with == mismatch (always false)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.ref == 'main' && 'release'", Span.point(1, 1, 0), &list, 0);
    try std.testing.expect(firstFix(list, "EXPR007") == null);
}

test "EXPR007 fix: no fix for bare number literal in V1" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.run_attempt == 1 || 2", Span.point(1, 1, 0), &list, 0);
    try std.testing.expect(firstFix(list, "EXPR007") == null);
}

test "EXPR007 fix: no fix at outer || when sibling is itself a chain" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    // Tree: ((github.event_name == 'push') || 'pull_request') || 'workflow_dispatch'
    // Inner || matches V1 and gets a fix; outer || sibling is a binary_op '||' (not '==')
    // and must not produce a fix.
    const src = "github.event_name == 'push' || 'pull_request' || 'workflow_dispatch'";
    validateExpression(arena.allocator(), src, Span.point(1, 1, 0), &list, 0);

    var fix_count: usize = 0;
    var diag_count: usize = 0;
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "EXPR007")) {
            diag_count += 1;
            if (d.fix != null) fix_count += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 2), diag_count);
    try std.testing.expectEqual(@as(usize, 1), fix_count);
}

test "EXPR007 fix: suppressed when expr_base_byte is null" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.event_name == 'push' || 'pull_request'", Span.point(1, 1, 0), &list, null);
    var saw_diag = false;
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "EXPR007")) {
            saw_diag = true;
            try std.testing.expect(d.fix == null);
        }
    }
    try std.testing.expect(saw_diag);
}

test "EXPR007 autofix: applied end-to-end on bare `if:` scalar" {
    const fix_engine = @import("../fix/engine.zig");

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\name: t
        \\on: push
        \\jobs:
        \\  deploy:
        \\    runs-on: ubuntu-latest
        \\    if: github.event_name == 'push' || 'pull_request'
        \\    steps:
        \\      - run: echo hi
        \\
    ;

    const wf = try test_support.parseWorkflowSource(alloc, source);

    var diags = DiagnosticList.init(alloc);
    checkJob(&wf.jobs[0], &diags);

    var fix_list = std.ArrayList(Fix){};
    defer fix_list.deinit(std.testing.allocator);
    for (diags.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "EXPR007")) {
            if (d.fix) |f| try fix_list.append(std.testing.allocator, f);
        }
    }
    try std.testing.expectEqual(@as(usize, 1), fix_list.items.len);

    const result = try fix_engine.applyFixes(std.testing.allocator, source, fix_list.items);
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), result.edits_applied);
    try std.testing.expect(std.mem.indexOf(
        u8,
        result.content,
        "if: github.event_name == 'push' || github.event_name == 'pull_request'",
    ) != null);
}

test "EXPR003: property access on a string context value" {
    try expectSingleRule("github.repository.permissions.admin", "EXPR003");
}

test "EXPR003: job context is strict" {
    try expectSingleRule("job.unknown", "EXPR003");
    try expectNoDiagnostics("job.status");
    try expectNoDiagnostics("job.container.id");
    try expectNoDiagnostics("job.services.redis.ports['6379']");
}

test "EXPR003: nested unknown property message names the receiver" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "job.container.unknown", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR003", list.get(0).rule_id);
    try std.testing.expectEqualStrings(
        "unknown property 'unknown' on 'job.container'",
        list.get(0).message,
    );
}

test "EXPR003: github.event stays silent at any depth" {
    try expectNoDiagnostics("github.event.pull_request.head.sha");
    try expectNoDiagnostics("github.event.inputs.anything");
}

test "EXPR003: contexts awaiting overlay stay silent" {
    try expectNoDiagnostics("steps.setup.outputs.version");
    try expectNoDiagnostics("matrix.os");
    try expectNoDiagnostics("needs.build.outputs.artifact");
    try expectNoDiagnostics("inputs.name");
    try expectNoDiagnostics("env.MY_VAR");
    try expectNoDiagnostics("secrets.GITHUB_TOKEN");
    try expectNoDiagnostics("strategy.anything");
}

test "EXPR017: object compared to number" {
    try expectSingleRule("github.event > 3", "EXPR017");
}

test "EXPR017: string compared to number with a relational operator is allowed" {
    try expectNoDiagnostics("github.run_number > 3");
}

test "EXPR017: bool is not orderable" {
    try expectSingleRule("github.ref_protected > 1", "EXPR017");
}

// ADR D6 mirrors actionlint: mixing number/bool/string in an equality is a
// documented implicit conversion, so it is not reported. Only object/array
// operands (and non-orderable operands for < > <= >=) are.
test "EXPR017: array compared to a scalar" {
    try expectSingleRule("fromJSON('[1,2]') == 'x'", "EXPR017");
}

test "EXPR017: map value compared to number is allowed" {
    try expectNoDiagnostics("secrets.FOO == 1");
}

test "EXPR017: message follows the actionlint wording" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.event == 1", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings(
        "\"object\" value cannot be compared to \"number\" value with \"==\" operator",
        list.get(0).message,
    );
    try std.testing.expectEqual(Severity.warning, list.get(0).severity);
}

test "EXPR017: unknown types short-circuit to no diagnostic" {
    try expectNoDiagnostics("github.event.issue.number == 'foo'");
    try expectNoDiagnostics("steps.build.outputs.count > 3");
    try expectNoDiagnostics("matrix.os == 'ubuntu-latest'");
    try expectNoDiagnostics("github.event_name == 'push'");
    try expectNoDiagnostics("github.event.head_commit == null");
}

test "EXPR017: scalar mixing in equality is not reported" {
    try expectNoDiagnostics("github.event_name == 1");
    try expectNoDiagnostics("github.ref_protected == 'true'");
}

test "EXPR017: comparison inside a logical expression" {
    try expectSingleRule("success() && github.event > 3", "EXPR017");
}

test "typeOf: function return types" {
    const cases = [_]struct { expr: []const u8, kind: expr_type.TypeKind }{
        .{ .expr = "startsWith(github.sha, 'a')", .kind = .bool },
        .{ .expr = "startsWith(github.event, 'a')", .kind = .bool },
        .{ .expr = "toJSON(github.event)", .kind = .string },
        .{ .expr = "join(matrix.values, ',')", .kind = .string },
        .{ .expr = "hashFiles('**/*.lock')", .kind = .string },
        .{ .expr = "success()", .kind = .bool },
        .{ .expr = "case(true, 1, 2)", .kind = .any },
        .{ .expr = "fromJSON('[1,2]')", .kind = .array },
        .{ .expr = "fromJSON('{\"a\":1}')", .kind = .object },
        .{ .expr = "fromJSON('true')", .kind = .bool },
        .{ .expr = "fromJSON(env.RAW)", .kind = .any },
        .{ .expr = "unknownFunc()", .kind = .any },
    };
    for (cases) |c| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var parser = ExprParser.init(arena.allocator(), c.expr);
        const node = try parser.parse();
        try std.testing.expectEqual(c.kind, expr_check.typeOf(&node).kind);
    }
}

test "typeOf: logical operators merge operand types" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = ExprParser.init(arena.allocator(), "github.sha || github.ref");
    const node = try parser.parse();
    try std.testing.expectEqual(expr_type.TypeKind.string, expr_check.typeOf(&node).kind);
}
