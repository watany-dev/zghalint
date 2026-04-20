const std = @import("std");
const diagnostics = @import("../diagnostics.zig");
const workflow_types = @import("../workflow/types.zig");
const yaml = @import("../yaml/types.zig");

pub const Diagnostic = diagnostics.Diagnostic;
pub const DiagnosticList = diagnostics.DiagnosticList;
pub const Severity = diagnostics.Severity;
pub const Span = yaml.Span;
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

const valid_contexts = [_][]const u8{
    "github",   "env",    "vars",   "job",
    "jobs",     "steps",  "runner", "secrets",
    "strategy", "matrix", "needs",  "inputs",
};

const github_properties = [_][]const u8{
    "sha",              "ref",               "ref_name",
    "ref_type",         "actor",             "repository",
    "repository_owner", "event_name",        "event",
    "workspace",        "action",            "action_path",
    "action_ref",       "action_repository", "action_status",
    "workflow",         "workflow_ref",      "workflow_sha",
    "job",              "run_id",            "run_number",
    "run_attempt",      "server_url",        "api_url",
    "graphql_url",      "head_ref",          "base_ref",
    "token",            "path",              "env",
    "output",           "step_summary",      "repositoryUrl",
    "triggering_actor", "retention_days",
};

const runner_properties = [_][]const u8{
    "os", "arch", "name", "temp", "tool_cache", "debug", "environment",
};

const FuncSpec = struct { name: []const u8, min_args: u8, max_args: u8 };
const valid_functions = [_]FuncSpec{
    .{ .name = "contains", .min_args = 2, .max_args = 2 },
    .{ .name = "startsWith", .min_args = 2, .max_args = 2 },
    .{ .name = "endsWith", .min_args = 2, .max_args = 2 },
    .{ .name = "format", .min_args = 1, .max_args = 255 },
    .{ .name = "join", .min_args = 1, .max_args = 2 },
    .{ .name = "toJSON", .min_args = 1, .max_args = 1 },
    .{ .name = "fromJSON", .min_args = 1, .max_args = 1 },
    .{ .name = "hashFiles", .min_args = 1, .max_args = 255 },
    .{ .name = "success", .min_args = 0, .max_args = 0 },
    .{ .name = "always", .min_args = 0, .max_args = 0 },
    .{ .name = "cancelled", .min_args = 0, .max_args = 0 },
    .{ .name = "failure", .min_args = 0, .max_args = 0 },
};

pub fn validateExpression(allocator: std.mem.Allocator, expr: []const u8, base_span: Span, list: *DiagnosticList) void {
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
    validateNode(allocator, &node, base_span, list);
}

fn validateNode(allocator: std.mem.Allocator, node: *const ExprNode, span: Span, list: *DiagnosticList) void {
    switch (node.kind) {
        .context_access => validateContextAccess(allocator, node.value, span, list),
        .function_call => validateFunctionCall(allocator, node, span, list),
        .binary_op, .unary_op => {
            if (node.kind == .binary_op) {
                checkUnsoundCondition(allocator, node, span, list);
            }
            for (node.children) |*child| {
                validateNode(allocator, child, span, list);
            }
        },
        .string_literal, .number_literal, .boolean_literal, .null_literal => {},
    }
}

fn validateContextAccess(allocator: std.mem.Allocator, path: []const u8, span: Span, list: *DiagnosticList) void {
    // Extract top-level context name (before first '.' or '[')
    var end: usize = 0;
    while (end < path.len and path[end] != '.' and path[end] != '[') : (end += 1) {}
    const top_level = path[0..end];

    var valid = false;
    for (valid_contexts) |ctx| {
        if (std.mem.eql(u8, top_level, ctx)) {
            valid = true;
            break;
        }
    }

    if (!valid) {
        const msg = std.fmt.allocPrint(allocator, "unknown context: '{s}'", .{top_level}) catch "unknown context";
        list.append(.{
            .rule_id = "EXPR002",
            .severity = .@"error",
            .message = msg,
            .span = span,
        }) catch return;
        return;
    }

    // Validate known properties for github and runner
    if (end < path.len and path[end] == '.') {
        var prop_end = end + 1;
        while (prop_end < path.len and path[prop_end] != '.' and path[prop_end] != '[') : (prop_end += 1) {}
        const property = path[end + 1 .. prop_end];

        if (std.mem.eql(u8, top_level, "github")) {
            var known = false;
            for (github_properties) |p| {
                if (std.mem.eql(u8, property, p)) {
                    known = true;
                    break;
                }
            }
            if (!known and property.len > 0) {
                const msg = std.fmt.allocPrint(allocator, "unknown github context property: '{s}'", .{property}) catch "unknown github property";
                list.append(.{
                    .rule_id = "EXPR003",
                    .severity = .warning,
                    .message = msg,
                    .span = span,
                }) catch return;
            }
        } else if (std.mem.eql(u8, top_level, "runner")) {
            var known = false;
            for (runner_properties) |p| {
                if (std.mem.eql(u8, property, p)) {
                    known = true;
                    break;
                }
            }
            if (!known and property.len > 0) {
                const msg = std.fmt.allocPrint(allocator, "unknown runner context property: '{s}'", .{property}) catch "unknown runner property";
                list.append(.{
                    .rule_id = "EXPR003",
                    .severity = .warning,
                    .message = msg,
                    .span = span,
                }) catch return;
            }
        }
    }
}

fn validateFunctionCall(allocator: std.mem.Allocator, node: *const ExprNode, span: Span, list: *DiagnosticList) void {
    const name = node.value;
    const arg_count: u8 = @intCast(node.children.len);

    var found: ?FuncSpec = null;
    for (valid_functions) |f| {
        if (std.mem.eql(u8, f.name, name)) {
            found = f;
            break;
        }
    }

    if (found == null) {
        const msg = std.fmt.allocPrint(allocator, "unknown function: '{s}'", .{name}) catch "unknown function";
        list.append(.{
            .rule_id = "EXPR004",
            .severity = .@"error",
            .message = msg,
            .span = span,
        }) catch return;
    } else {
        const f = found.?;
        if (arg_count < f.min_args or arg_count > f.max_args) {
            const msg = if (f.min_args == f.max_args)
                std.fmt.allocPrint(allocator, "function '{s}' expects {d} argument(s), got {d}", .{ name, f.min_args, arg_count }) catch "wrong number of arguments"
            else
                std.fmt.allocPrint(allocator, "function '{s}' expects {d}-{d} arguments, got {d}", .{ name, f.min_args, f.max_args, arg_count }) catch "wrong number of arguments";
            list.append(.{
                .rule_id = "EXPR005",
                .severity = .@"error",
                .message = msg,
                .span = span,
            }) catch return;
        }
    }

    // EXPR006: contains() with string literal may cause unsound substring matching
    if (std.mem.eql(u8, name, "contains") and node.children.len == 2) {
        if (node.children[1].kind == .string_literal) {
            list.append(.{
                .rule_id = "EXPR006",
                .severity = .warning,
                .message = "contains() uses substring matching which may match unintended values",
                .span = span,
                .fix_hint = "use exact comparison (== ) or startsWith()/endsWith() for precise matching",
            }) catch return;
        }
    }

    // Validate arguments recursively
    for (node.children) |*child| {
        validateNode(allocator, child, span, list);
    }
}

// ============================================================
// EXPR007: unsound-condition — bare literal in logical operator
// ============================================================

fn checkUnsoundCondition(allocator: std.mem.Allocator, node: *const ExprNode, span: Span, list: *DiagnosticList) void {
    if (!std.mem.eql(u8, node.value, "||") and !std.mem.eql(u8, node.value, "&&")) return;

    for (node.children) |*child| {
        if (child.kind == .string_literal or child.kind == .number_literal) {
            const msg = std.fmt.allocPrint(
                allocator,
                "unsound condition: bare literal {s} as operand of '{s}' is always truthy",
                .{ child.value, node.value },
            ) catch "unsound condition: bare literal in logical operator";
            list.append(.{
                .rule_id = "EXPR007",
                .severity = .warning,
                .message = msg,
                .span = span,
                .fix_hint = "use an explicit comparison, e.g. github.event_name == 'push' || github.event_name == 'pull_request'",
            }) catch return;
        }
    }
}

// ============================================================
// Expression extraction from strings
// ============================================================

/// Find all ${{ ... }} expressions in a string and validate each.
pub fn findAndValidateExpressions(allocator: std.mem.Allocator, text: []const u8, base_span: Span, list: *DiagnosticList) void {
    var pos: usize = 0;
    while (pos + 2 < text.len) {
        if (text[pos] == '$' and text[pos + 1] == '{' and text[pos + 2] == '{') {
            const expr_start = pos + 3;
            if (std.mem.indexOf(u8, text[expr_start..], "}}")) |end_offset| {
                const expr_content = text[expr_start .. expr_start + end_offset];
                const trimmed = std.mem.trim(u8, expr_content, " \t\n\r");
                validateExpression(allocator, trimmed, base_span, list);
                pos = expr_start + end_offset + 2;
            } else {
                list.append(.{
                    .rule_id = "EXPR001",
                    .severity = .@"error",
                    .message = "unclosed expression: missing }}",
                    .span = base_span,
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

pub fn checkStep(step: *const Step, list: *DiagnosticList) void {
    const allocator = getArenaAllocator();
    const span = Span.point(0, 0, 0);

    // Check 'run' field
    if (step.run) |run_val| {
        findAndValidateExpressions(allocator, run_val, span, list);
    }

    // Check 'if' field
    if (step.if_condition) |if_val| {
        if (std.mem.indexOf(u8, if_val, "${{") != null) {
            findAndValidateExpressions(allocator, if_val, span, list);
        } else {
            const trimmed = std.mem.trim(u8, if_val, " \t\n\r");
            if (trimmed.len > 0) {
                validateExpression(allocator, trimmed, span, list);
            }
        }
    }

    // Check 'with' values
    if (step.with) |with_map| {
        for (with_map.values()) |value| {
            findAndValidateExpressions(allocator, value, span, list);
        }
    }

    // Check 'env' values
    if (step.env) |env_map| {
        for (env_map.values()) |value| {
            findAndValidateExpressions(allocator, value, span, list);
        }
    }
}

pub fn checkJob(job: *const Job, list: *DiagnosticList) void {
    const allocator = getArenaAllocator();
    const span = Span.point(0, 0, 0);

    // Check 'if' field
    if (job.if_condition) |if_val| {
        if (std.mem.indexOf(u8, if_val, "${{") != null) {
            findAndValidateExpressions(allocator, if_val, span, list);
        } else {
            const trimmed = std.mem.trim(u8, if_val, " \t\n\r");
            if (trimmed.len > 0) {
                validateExpression(allocator, trimmed, span, list);
            }
        }
    }

    // Check 'env' values
    if (job.env) |env_map| {
        for (env_map.values()) |value| {
            findAndValidateExpressions(allocator, value, span, list);
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

    validateExpression(arena.allocator(), "github.sha", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "validate: valid expression github.ref" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.ref == 'refs/heads/main'", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "validate: valid function contains" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "contains(github.event_name, 'push')", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR006", list.get(0).rule_id);
}

test "validate: valid function success" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "success()", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "validate: valid expression with runner.os" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "runner.os == 'Linux'", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "validate: valid complex expression" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.event_name == 'push' && contains(github.ref, 'main')", Span.point(1, 1, 0), &list);
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
        validateExpression(arena.allocator(), ctx, span, &list);
    }
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "validate: unknown context" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "unknown.property", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR002", list.get(0).rule_id);
}

test "validate: unknown github property" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.nonexistent_prop", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR003", list.get(0).rule_id);
}

test "validate: unknown runner property" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "runner.nonexistent", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR003", list.get(0).rule_id);
}

test "validate: unknown function" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "unknownFunc()", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR004", list.get(0).rule_id);
}

test "validate: wrong arg count for contains" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "contains(github.ref)", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR005", list.get(0).rule_id);
}

test "validate: wrong arg count for success" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "success('unexpected')", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR005", list.get(0).rule_id);
}

test "validate: empty expression" {
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(std.testing.allocator, "", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR001", list.get(0).rule_id);
}

test "validate: syntax error unclosed paren" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "(github.sha", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR001", list.get(0).rule_id);
}

// --- findAndValidateExpressions Tests ---

test "find expressions: single expression in string" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    findAndValidateExpressions(arena.allocator(), "echo ${{ github.sha }}", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "find expressions: multiple expressions" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    findAndValidateExpressions(arena.allocator(), "${{ github.sha }} and ${{ github.ref }}", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "find expressions: unclosed expression" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    findAndValidateExpressions(arena.allocator(), "echo ${{ github.sha", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR001", list.get(0).rule_id);
}

test "find expressions: no expressions in plain text" {
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    findAndValidateExpressions(std.testing.allocator, "echo hello world", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "find expressions: expression with unknown context" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    findAndValidateExpressions(arena.allocator(), "${{ badcontext.value }}", Span.point(1, 1, 0), &list);
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
        validateExpression(arena.allocator(), expr, span, &list);
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
        validateExpression(arena.allocator(), prop, span, &list);
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
        validateExpression(arena.allocator(), prop, span, &list);
    }
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

// --- Edge cases ---

test "validate: hashFiles with multiple args" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "hashFiles('**/package-lock.json', '**/yarn.lock')", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "validate: format with multiple args" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "format('{0}-{1}', github.ref, github.sha)", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "validate: nested function calls" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "contains(toJSON(github.event), 'push')", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR006", list.get(0).rule_id);
}

test "validate: complex logical expression" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "!cancelled() && (success() || failure())", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "validate: toJSON wrong args" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "toJSON(github.event, 'extra')", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR005", list.get(0).rule_id);
}

// --- EXPR006: unsound-contains tests ---

test "EXPR006: contains with string literal second arg" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "contains(github.ref, 'main')", Span.point(1, 1, 0), &list);
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

    validateExpression(arena.allocator(), "contains(github.ref, 'main') && github.event_name == 'push'", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR006", list.get(0).rule_id);
}

test "EXPR006: contains nested in not" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "!contains(github.ref, 'release')", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR006", list.get(0).rule_id);
}

test "EXPR006: multiple contains calls" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "contains(github.ref, 'main') || contains(github.actor, 'bot')", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 2), list.len());
    try std.testing.expectEqualStrings("EXPR006", list.get(0).rule_id);
    try std.testing.expectEqualStrings("EXPR006", list.get(1).rule_id);
}

test "EXPR006: no warning for startsWith" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "startsWith(github.ref, 'refs/heads/main')", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "EXPR006: no warning for exact comparison" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.ref == 'refs/heads/main'", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "EXPR006: no warning for non-literal second arg" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "contains(github.ref, github.base_ref)", Span.point(1, 1, 0), &list);
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

// --- EXPR007: unsound-condition tests ---

test "validate EXPR007: bare string literal right of ||" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.event_name == 'push' || 'pull_request'", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR007", list.get(0).rule_id);
    try std.testing.expectEqual(Severity.warning, list.get(0).severity);
}

test "validate EXPR007: bare string literal right of &&" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.event_name != 'push' && 'pull_request'", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR007", list.get(0).rule_id);
}

test "validate EXPR007: bare string literal left of ||" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "'push' || github.event_name == 'pull_request'", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR007", list.get(0).rule_id);
}

test "validate EXPR007: bare number literal right of ||" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.run_attempt == 1 || 2", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 1), list.len());
    try std.testing.expectEqualStrings("EXPR007", list.get(0).rule_id);
}

test "validate EXPR007: no false positive for proper comparison" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.event_name == 'push' || github.event_name == 'pull_request'", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "validate EXPR007: no false positive for function call operands" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "success() || failure()", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "validate EXPR007: no false positive for boolean literal" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "true || github.event_name == 'push'", Span.point(1, 1, 0), &list);
    try std.testing.expectEqual(@as(usize, 0), list.len());
}

test "validate EXPR007: multiple bare literals in chained ||" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var list = DiagnosticList.init(std.testing.allocator);
    defer list.deinit();

    validateExpression(arena.allocator(), "github.event_name == 'push' || 'pull_request' || 'workflow_dispatch'", Span.point(1, 1, 0), &list);
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
