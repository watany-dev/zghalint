const std = @import("std");
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

// ============================================================
// Expression Tokenizer
// ============================================================

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

    pub fn next(self: *ExprTokenizer) ExprToken {
        self.skipWhitespace();
        if (self.pos >= self.source.len) {
            return .{ .kind = .eof, .value = "", .pos = self.pos };
        }

        const start = self.pos;
        const c = self.source[self.pos];

        switch (c) {
            '.' => {
                self.pos += 1;
                return .{ .kind = .dot, .value = ".", .pos = start };
            },
            '(' => {
                self.pos += 1;
                return .{ .kind = .open_paren, .value = "(", .pos = start };
            },
            ')' => {
                self.pos += 1;
                return .{ .kind = .close_paren, .value = ")", .pos = start };
            },
            '[' => {
                self.pos += 1;
                return .{ .kind = .open_bracket, .value = "[", .pos = start };
            },
            ']' => {
                self.pos += 1;
                return .{ .kind = .close_bracket, .value = "]", .pos = start };
            },
            ',' => {
                self.pos += 1;
                return .{ .kind = .comma, .value = ",", .pos = start };
            },
            '*' => {
                self.pos += 1;
                return .{ .kind = .star, .value = "*", .pos = start };
            },
            '!' => {
                if (self.pos + 1 < self.source.len and self.source[self.pos + 1] == '=') {
                    self.pos += 2;
                    return .{ .kind = .comparison_op, .value = "!=", .pos = start };
                }
                self.pos += 1;
                return .{ .kind = .not_op, .value = "!", .pos = start };
            },
            '=' => {
                if (self.pos + 1 < self.source.len and self.source[self.pos + 1] == '=') {
                    self.pos += 2;
                    return .{ .kind = .comparison_op, .value = "==", .pos = start };
                }
                self.pos += 1;
                return .{ .kind = .@"error", .value = self.source[start .. start + 1], .pos = start };
            },
            '<' => {
                if (self.pos + 1 < self.source.len and self.source[self.pos + 1] == '=') {
                    self.pos += 2;
                    return .{ .kind = .comparison_op, .value = "<=", .pos = start };
                }
                self.pos += 1;
                return .{ .kind = .comparison_op, .value = "<", .pos = start };
            },
            '>' => {
                if (self.pos + 1 < self.source.len and self.source[self.pos + 1] == '=') {
                    self.pos += 2;
                    return .{ .kind = .comparison_op, .value = ">=", .pos = start };
                }
                self.pos += 1;
                return .{ .kind = .comparison_op, .value = ">", .pos = start };
            },
            '&' => {
                if (self.pos + 1 < self.source.len and self.source[self.pos + 1] == '&') {
                    self.pos += 2;
                    return .{ .kind = .logical_op, .value = "&&", .pos = start };
                }
                self.pos += 1;
                return .{ .kind = .@"error", .value = self.source[start .. start + 1], .pos = start };
            },
            '|' => {
                if (self.pos + 1 < self.source.len and self.source[self.pos + 1] == '|') {
                    self.pos += 2;
                    return .{ .kind = .logical_op, .value = "||", .pos = start };
                }
                self.pos += 1;
                return .{ .kind = .@"error", .value = self.source[start .. start + 1], .pos = start };
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
        self.pos += 1; // skip opening quote
        while (self.pos < self.source.len) {
            if (self.source[self.pos] == '\'') {
                // Check for escaped quote ('')
                if (self.pos + 1 < self.source.len and self.source[self.pos + 1] == '\'') {
                    self.pos += 2;
                    continue;
                }
                self.pos += 1; // skip closing quote
                return .{ .kind = .string_literal, .value = self.source[start..self.pos], .pos = start };
            }
            self.pos += 1;
        }
        // Unterminated string
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
        // Handle e/E notation
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

// ============================================================
// Expression AST
// ============================================================

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
    /// Byte offset of the node's first token within the expression source string
    start_byte: u32 = 0,
    /// Byte offset one past the node's last token within the expression source string
    end_byte: u32 = 0,
};

// ============================================================
// Expression Parser (recursive descent)
// ============================================================

pub const ParseError = error{
    UnexpectedToken,
    EmptyExpression,
    UnclosedParen,
    OutOfMemory,
};

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

    /// Parse a full expression
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
        var left = try self.parseAnd();
        while (self.current.kind == .logical_op and std.mem.eql(u8, self.current.value, "||")) {
            const op = self.current.value;
            self.advance();
            const right = try self.parseAnd();
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

    fn parseAnd(self: *ExprParser) ParseError!ExprNode {
        var left = try self.parseComparison();
        while (self.current.kind == .logical_op and std.mem.eql(u8, self.current.value, "&&")) {
            const op = self.current.value;
            self.advance();
            const right = try self.parseComparison();
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

    fn parseComparison(self: *ExprParser) ParseError!ExprNode {
        var left = try self.parseUnary();
        while (self.current.kind == .comparison_op) {
            const op = self.current.value;
            self.advance();
            const right = try self.parseUnary();
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

    fn parsePrimary(self: *ExprParser) ParseError!ExprNode {
        switch (self.current.kind) {
            .string_literal => {
                const val = self.current.value;
                const start = self.current.pos;
                self.advance();
                return ExprNode{
                    .kind = .string_literal,
                    .value = val,
                    .children = &.{},
                    .start_byte = @intCast(start),
                    .end_byte = @intCast(start + val.len),
                };
            },
            .number => {
                const val = self.current.value;
                const start = self.current.pos;
                self.advance();
                return ExprNode{
                    .kind = .number_literal,
                    .value = val,
                    .children = &.{},
                    .start_byte = @intCast(start),
                    .end_byte = @intCast(start + val.len),
                };
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
                const name = self.current.value;
                const name_start = self.current.pos;
                self.advance();

                // Check for boolean/null literals
                if (std.mem.eql(u8, name, "true") or std.mem.eql(u8, name, "false")) {
                    return ExprNode{
                        .kind = .boolean_literal,
                        .value = name,
                        .children = &.{},
                        .start_byte = @intCast(name_start),
                        .end_byte = @intCast(name_start + name.len),
                    };
                }
                if (std.mem.eql(u8, name, "null")) {
                    return ExprNode{
                        .kind = .null_literal,
                        .value = name,
                        .children = &.{},
                        .start_byte = @intCast(name_start),
                        .end_byte = @intCast(name_start + name.len),
                    };
                }

                // Function call: identifier followed by (
                if (self.current.kind == .open_paren) {
                    return self.parseFunctionCall(name, name_start);
                }

                // Context access: identifier possibly followed by dots
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
        self.advance(); // skip '('
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

        // Handle bracket access: context['key']
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

// ============================================================
// Expression Validator
// ============================================================

/// Empty type environment. Contextual overlays (steps / matrix / needs /
/// inputs / secrets) are wired in a later iteration; until then every context
/// resolves through the builtin catalog.
const base_env = expr_check.TypeEnv{};

/// Validate an expression.
///
/// `expr_base_byte` is the absolute byte offset in the source file at which
/// `expr` begins. It is used when constructing autofix Edit byte ranges;
/// diagnostics themselves continue to use `base_span` for reporting.
/// Pass `null` when the base byte cannot be determined reliably (e.g.
/// values whose scalar style makes the byte math ambiguous): autofix
/// generation is skipped in that case while diagnostics remain emitted.
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
    const result = expr_check.walkPath(path, &base_env);
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

/// EXPR017: operands of a comparison whose types can never be compared.
fn checkComparison(allocator: std.mem.Allocator, node: *const ExprNode, span: Span, list: *DiagnosticList) void {
    if (node.children.len != 2) return;
    const op = node.value;
    if (!expr_check.isCompareOp(op)) return;

    const lhs = expr_check.typeOf(&node.children[0], &base_env);
    const rhs = expr_check.typeOf(&node.children[1], &base_env);
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

    // EXPR006: contains() with string literal may cause unsound substring matching
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

    // Validate arguments recursively
    for (node.children) |*child| {
        validateNode(allocator, child, span, list, expr_base_byte, node);
    }
}

// ============================================================
// EXPR006 autofix: contains(ctx, 'lit') → ctx == 'lit'
//                  !contains(ctx, 'lit') → ctx != 'lit'   (V2)
// ============================================================

/// Build an unsafe Edit for one of:
///   * `contains(context.path, 'literal')` → `context.path == 'literal'` (V1)
///   * `!contains(context.path, 'literal')` → `context.path != 'literal'` (V2)
///
/// When `parent` is a unary `!` wrapping this `contains()` call, the Edit
/// range is widened to span the leading `!` and an inequality operator is
/// emitted. Otherwise a V1 equality Edit is produced.
///
/// Returns null when any of the following exclusions apply:
///   * first arg is not a bare `context_access` (function calls / literals rejected)
///   * context path contains `.*` or `[` (array / bracket access rejected)
///   * literal has a `''` escape in its interior (kept byte-identical)
fn buildContainsEqFix(
    list: *DiagnosticList,
    node: *const ExprNode,
    expr_base_byte: ?usize,
    parent: ?*const ExprNode,
) ?Fix {
    // If the caller could not determine a reliable absolute byte base, we
    // cannot produce a well-targeted Edit. Emit the diagnostic only.
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

// ============================================================
// EXPR007: unsound-condition — bare literal in logical operator
// ============================================================

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

// ============================================================
// EXPR007 autofix: a == 'x' || 'y'  →  a == 'x' || a == 'y'
//                  a != 'x' && 'y'  →  a != 'x' && a != 'y'
// ============================================================

/// Build an unsafe Edit that expands a bare string literal operand of `||` /
/// `&&` into an explicit comparison borrowed from its sibling.
///
/// Eligibility (V1):
///   * the parent logical op pairs with the sibling comparator:
///       - `||` requires sibling op `==`
///       - `&&` requires sibling op `!=`
///   * the sibling is a direct `binary_op` whose left child is `context_access`
///     and whose right child is a `string_literal`
///   * the bare literal is a `string_literal` (number_literal is V2 / not handled)
///   * neither literal contains a `''` escape in its interior
///   * the LHS context path contains neither `.*` nor `[`
///   * `expr_base_byte` is non-null (otherwise byte math is unreliable)
///
/// Returns null when any condition fails. The Edit replaces the bare
/// literal's byte range with `"{ctx_path} {op} {literal_value}"`.
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

// ============================================================
// Expression extraction from strings
// ============================================================

/// Find all ${{ ... }} expressions in a string and validate each.
///
/// `text_base_byte` is the absolute byte offset in the source file at which
/// `text` begins. For each inner `${{ ... }}` the trimmed expression's
/// absolute offset is forwarded to `validateExpression` so EXPR006 autofix
/// can emit byte-accurate Edits. Pass `null` when the base byte cannot be
/// determined reliably; in that case diagnostics are still emitted but the
/// autofix Edit is suppressed (see `validateExpression`).
/// Validate every `${{ ... }}` expression in `text`.
///
/// `anchor` maps an offset inside `text` back to a source position, so each
/// expression is reported where it actually appears instead of at the start of
/// the enclosing scalar.
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
                // Compute leading trim offset so `trimmed`'s absolute byte is accurate.
                const leading_trim = blk: {
                    var i: usize = 0;
                    while (i < expr_content.len) : (i += 1) {
                        const c = expr_content[i];
                        if (c != ' ' and c != '\t' and c != '\n' and c != '\r') break;
                    }
                    break :blk i;
                };
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

// ============================================================
// Rule check functions (for engine integration)
// ============================================================

fn getArenaAllocator() std.mem.Allocator {
    // Use a GPA for allocations needed during validation.
    // In real usage the engine would provide an arena; here we use a GPA
    // that leaks since diagnostic messages must outlive the call.
    return std.heap.page_allocator;
}

/// Return the absolute byte offset of the first character of the scalar's
/// `value` (the content, not the raw token). For quoted scalars the YAML
/// parser's `value_span.start_byte` points at the opening quote and `value`
/// begins one byte later; for plain scalars they coincide. For block
/// scalars (`|` / `>`) the parser's span points at the indicator while
/// `value` begins after the first newline — the exact content-start byte
/// is not preserved, so this function returns `null` to signal that fix
/// byte ranges cannot be derived from this meta.
fn scalarValueStartByte(meta: workflow_types.ScalarValueMeta) ?usize {
    return switch (meta.style) {
        .plain => meta.value_span.start_byte,
        .single_quoted, .double_quoted => meta.value_span.start_byte + 1,
        .literal, .folded => null,
    };
}

pub fn checkStep(step: *const Step, list: *DiagnosticList) void {
    const allocator = getArenaAllocator();

    // Check 'run' field — the scalar style is not tracked, and `run:` is
    // very commonly a block scalar (`|` / `>`) whose content-start byte
    // cannot be recovered from `value_span`. Pass null so autofix byte
    // ranges are never computed from an unreliable base.
    if (step.run) |run_val| {
        const run_anchor = spans.runAnchor(step);
        findAndValidateExpressions(allocator, run_val, run_anchor, list, null);
    }

    // Check 'if' field
    if (step.if_condition) |if_val| {
        const if_anchor = Anchor.fromMeta(step.if_condition_meta, step.span);
        const if_base: ?usize = if (step.if_condition_meta) |m| scalarValueStartByte(m) else null;
        if (std.mem.indexOf(u8, if_val, "${{") != null) {
            findAndValidateExpressions(allocator, if_val, if_anchor, list, if_base);
        } else {
            const trimmed = std.mem.trim(u8, if_val, " \t\n\r");
            if (trimmed.len > 0) {
                const leading: usize = @intFromPtr(trimmed.ptr) - @intFromPtr(if_val.ptr);
                const abs: ?usize = if (if_base) |b| b + leading else null;
                validateExpression(allocator, trimmed, if_anchor.at(if_val, leading, trimmed.len), list, abs);
            }
        }
    }

    // Check 'with' values — per-entry scalar spans are not captured, so the
    // absolute byte base is unknown. Suppress fix generation.
    if (step.with) |with_map| {
        for (with_map.keys(), with_map.values()) |key, value| {
            const with_meta = if (step.with_meta) |m| m.get(key) else null;
            findAndValidateExpressions(allocator, value, Anchor.fromMeta(with_meta, step.span), list, null);
        }
    }

    // Check 'env' values — use env_meta when available for accurate byte tracking.
    if (step.env) |env_map| {
        for (env_map.keys(), env_map.values()) |key, value| {
            const entry_meta = if (step.env_meta) |meta| meta.get(key) else null;
            const base: ?usize = if (entry_meta) |m| scalarValueStartByte(m) else null;
            findAndValidateExpressions(allocator, value, Anchor.fromMeta(entry_meta, step.span), list, base);
        }
    }
}

pub fn checkJob(job: *const Job, list: *DiagnosticList) void {
    const allocator = getArenaAllocator();

    // Check 'if' field
    if (job.if_condition) |if_val| {
        const if_anchor = Anchor.fromMeta(job.if_condition_meta, job.span);
        const if_base: ?usize = if (job.if_condition_meta) |m| scalarValueStartByte(m) else null;
        if (std.mem.indexOf(u8, if_val, "${{") != null) {
            findAndValidateExpressions(allocator, if_val, if_anchor, list, if_base);
        } else {
            const trimmed = std.mem.trim(u8, if_val, " \t\n\r");
            if (trimmed.len > 0) {
                const leading: usize = @intFromPtr(trimmed.ptr) - @intFromPtr(if_val.ptr);
                const abs: ?usize = if (if_base) |b| b + leading else null;
                validateExpression(allocator, trimmed, if_anchor.at(if_val, leading, trimmed.len), list, abs);
            }
        }
    }

    // Check 'env' values
    if (job.env) |env_map| {
        for (env_map.keys(), env_map.values()) |key, value| {
            const entry_meta = if (job.env_meta) |meta| meta.get(key) else null;
            const base: ?usize = if (entry_meta) |m| scalarValueStartByte(m) else null;
            findAndValidateExpressions(allocator, value, Anchor.fromMeta(entry_meta, job.span), list, base);
        }
    }
}

/// Pre-built rule for use with the Engine
pub const expression_rule = @import("engine.zig").Rule{
    .id = "EXPR",
    .name = "expression-validator",
    .description = "Validates GitHub Actions ${{ }} expressions",
    .severity = .@"error",
    .category = .expression,
    .check_step = &checkStep,
    .check_job = &checkJob,
};

// ============================================================
// Tests
// ============================================================

// --- Tokenizer Tests ---

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
    try std.testing.expectEqual(TokenKind.identifier, t.next().kind); // contains
    try std.testing.expectEqual(TokenKind.open_paren, t.next().kind);
    try std.testing.expectEqual(TokenKind.identifier, t.next().kind); // github
    try std.testing.expectEqual(TokenKind.dot, t.next().kind);
    try std.testing.expectEqual(TokenKind.identifier, t.next().kind); // event_name
    try std.testing.expectEqual(TokenKind.comma, t.next().kind);
    try std.testing.expectEqual(TokenKind.string_literal, t.next().kind); // 'push'
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

// --- Parser Tests ---

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

// --- Byte offset tests ---

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

// --- Validator Tests ---

test "validate: valid expression github.sha" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.sha", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "validate: valid expression github.ref" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.ref == 'refs/heads/main'", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "validate: valid function contains" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "contains(github.event_name, 'push')", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR006", list.get(0).rule_id);
}

test "validate: valid function success" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "success()", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "validate: valid expression with runner.os" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "runner.os == 'Linux'", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "validate: valid complex expression" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.event_name == 'push' && contains(github.ref, 'main')", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR006", list.get(0).rule_id);
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
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "unknown.property", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR002", list.get(0).rule_id);
}

test "validate: unknown github property" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.nonexistent_prop", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR003", list.get(0).rule_id);
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
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "runner.nonexistent", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR003", list.get(0).rule_id);
}

test "validate: unknown function" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "unknownFunc()", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR004", list.get(0).rule_id);
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
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "case(github.ref_name, 'main')", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR005", list.get(0).rule_id);
}

test "validate: wrong arg count for contains" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "contains(github.ref)", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR005", list.get(0).rule_id);
}

test "validate: wrong arg count for success" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "success('unexpected')", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR005", list.get(0).rule_id);
}

test "validate: empty expression" {
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(std.testing.allocator, "", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR001", list.get(0).rule_id);
}

test "validate: syntax error unclosed paren" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "(github.sha", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR001", list.get(0).rule_id);
}

// --- findAndValidateExpressions Tests ---

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

// --- checkStep / checkJob integration tests ---

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

// --- All valid functions test ---

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
    // contains('hello', 'ell') triggers EXPR006
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

// --- Edge cases ---

test "validate: hashFiles with multiple args" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "hashFiles('**/package-lock.json', '**/yarn.lock')", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "validate: format with multiple args" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "format('{0}-{1}', github.ref, github.sha)", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "validate: nested function calls" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "contains(toJSON(github.event), 'push')", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR006", list.get(0).rule_id);
}

test "validate: complex logical expression" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "!cancelled() && (success() || failure())", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "validate: toJSON wrong args" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "toJSON(github.event, 'extra')", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR005", list.get(0).rule_id);
}

// --- EXPR006: unsound-contains tests ---

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
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "contains(github.ref, 'main') && github.event_name == 'push'", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR006", list.get(0).rule_id);
}

test "EXPR006: contains nested in not" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "!contains(github.ref, 'release')", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR006", list.get(0).rule_id);
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
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "startsWith(github.ref, 'refs/heads/main')", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "EXPR006: no warning for exact comparison" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.ref == 'refs/heads/main'", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "EXPR006: no warning for non-literal second arg" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "contains(github.ref, github.base_ref)", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 0), list.len());
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

// --- EXPR006 V1 autofix tests ---

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

// --- EXPR007: unsound-condition tests ---

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
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.event_name != 'push' && 'pull_request'", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR007", list.get(0).rule_id);
}

test "validate EXPR007: bare string literal left of ||" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "'push' || github.event_name == 'pull_request'", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR007", list.get(0).rule_id);
}

test "validate EXPR007: bare number literal right of ||" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.run_attempt == 1 || 2", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR007", list.get(0).rule_id);
}

test "validate EXPR007: no false positive for proper comparison" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.event_name == 'push' || github.event_name == 'pull_request'", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "validate EXPR007: no false positive for function call operands" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "success() || failure()", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "validate EXPR007: no false positive for boolean literal" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "true || github.event_name == 'push'", Span.point(1, 1, 0), &list, 0);
    try std.testing.expectEqual(@as(usize, 0), list.len());
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
    var found = false;
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "EXPR007")) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

test "checkJob EXPR007: if condition with bare literal" {
    const job = Job{
        .id = "deploy",
        .if_condition = "github.event_name == 'push' || 'pull_request'",
    };
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    checkJob(&job, &list);
    var found = false;
    for (list.items.items) |d| {
        if (std.mem.eql(u8, d.rule_id, "EXPR007")) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

// ============================================================
// EXPR006 V1 autofix integration tests
// ============================================================

test "EXPR006 autofix: applied end-to-end on bare (double-quoted) `if:` scalar" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    const workflow_parser = @import("../workflow/parser.zig");
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

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    defer yp.deinit();
    const yaml_node = try yp.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_node);

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
    // The YAML double-quoted wrapper is preserved around the new expression.
    try std.testing.expect(std.mem.indexOf(u8, result.content, "if: \"github.ref == 'main'\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.content, "contains(") == null);
}

test "EXPR006 autofix: applied end-to-end on `${{ }}` inside double-quoted `if:`" {
    const yaml_parser_mod = @import("../yaml/parser.zig");
    const workflow_parser = @import("../workflow/parser.zig");
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

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    defer yp.deinit();
    const yaml_node = try yp.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_node);

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
    const yaml_parser_mod = @import("../yaml/parser.zig");
    const workflow_parser = @import("../workflow/parser.zig");
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

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    defer yp.deinit();
    const yaml_node = try yp.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_node);

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
    const yaml_parser_mod = @import("../yaml/parser.zig");
    const workflow_parser = @import("../workflow/parser.zig");
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

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    defer yp.deinit();
    const yaml_node = try yp.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_node);

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

// --- EXPR006 autofix suppression: byte base unreliable ---

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
    const yaml_parser_mod = @import("../yaml/parser.zig");
    const workflow_parser = @import("../workflow/parser.zig");

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

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    defer yp.deinit();
    const yaml_node = try yp.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_node);

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
    const yaml_parser_mod = @import("../yaml/parser.zig");
    const workflow_parser = @import("../workflow/parser.zig");

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

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    defer yp.deinit();
    const yaml_node = try yp.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_node);

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
    const yaml_parser_mod = @import("../yaml/parser.zig");
    const workflow_parser = @import("../workflow/parser.zig");

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

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    defer yp.deinit();
    const yaml_node = try yp.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_node);

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

// --- EXPR007 V1 autofix tests ---

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
    const yaml_parser_mod = @import("../yaml/parser.zig");
    const workflow_parser = @import("../workflow/parser.zig");
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

    var yp = yaml_parser_mod.Parser.init(alloc, source);
    defer yp.deinit();
    const yaml_node = try yp.parse();
    const wf = try workflow_parser.parseWorkflow(alloc, yaml_node);

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

// --- Type engine integration (EXPR003 deep walk / EXPR017) ---

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
    const env = expr_check.TypeEnv{};
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
        try std.testing.expectEqual(c.kind, expr_check.typeOf(&node, &env).kind);
    }
}

test "typeOf: logical operators merge operand types" {
    const env = expr_check.TypeEnv{};
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser = ExprParser.init(arena.allocator(), "github.sha || github.ref");
    const node = try parser.parse();
    try std.testing.expectEqual(expr_type.TypeKind.string, expr_check.typeOf(&node, &env).kind);
}
