pub const yaml = struct {
    pub const Tokenizer = @import("yaml/tokenizer.zig").Tokenizer;
    pub const Token = @import("yaml/tokenizer.zig").Token;
    pub const TokenKind = @import("yaml/tokenizer.zig").TokenKind;
    pub const Parser = @import("yaml/parser.zig").Parser;
    pub const types = @import("yaml/types.zig");
    pub const Node = types.Node;
    pub const Span = types.Span;
};

pub const workflow = struct {
    pub const types = @import("workflow/types.zig");
    pub const Workflow = types.Workflow;
    pub const Job = types.Job;
    pub const Step = types.Step;
    pub const Trigger = types.Trigger;
    pub const EventConfig = types.EventConfig;
    pub const EventType = types.EventType;
    pub const ActionRef = types.ActionRef;
    pub const Permissions = types.Permissions;
    pub const parser = @import("workflow/parser.zig");
    pub const parseWorkflow = parser.parseWorkflow;
    pub const validator = @import("workflow/validator.zig");
    pub const validate = validator.validate;
};

pub const diagnostics = @import("diagnostics.zig");
pub const Diagnostic = diagnostics.Diagnostic;
pub const DiagnosticList = diagnostics.DiagnosticList;
pub const Severity = diagnostics.Severity;
pub const Category = diagnostics.Category;

pub const output = struct {
    pub const terminal = @import("output/terminal.zig");
    pub const renderDiagnostic = terminal.renderDiagnostic;
    pub const renderDiagnostics = terminal.renderDiagnostics;
    pub const renderSummary = terminal.renderSummary;
    pub const json = @import("output/json.zig");
    pub const renderJson = json.renderJson;
    pub const sarif = @import("output/sarif.zig");
    pub const renderSarif = sarif.renderSarif;
};

pub const rules = struct {
    pub const engine = @import("rules/engine.zig");
    pub const Engine = engine.Engine;
    pub const Rule = engine.Rule;
    pub const expressions = @import("rules/expressions.zig");
    pub const security = @import("rules/security.zig");
    pub const performance = @import("rules/performance.zig");
    pub const best_practices = @import("rules/best_practices.zig");
    pub const permissions = @import("rules/permissions.zig");
};

pub const config = @import("config.zig");
pub const Config = config.Config;
pub const OutputFormat = config.OutputFormat;
pub const ColorMode = config.ColorMode;

test {
    _ = @import("yaml/tokenizer.zig");
    _ = @import("yaml/types.zig");
    _ = @import("yaml/parser.zig");
    _ = @import("workflow/types.zig");
    _ = @import("workflow/parser.zig");
    _ = @import("workflow/validator.zig");
    _ = @import("diagnostics.zig");
    _ = @import("rules/engine.zig");
    _ = @import("rules/expressions.zig");
    _ = @import("rules/security.zig");
    _ = @import("rules/performance.zig");
    _ = @import("rules/best_practices.zig");
    _ = @import("rules/permissions.zig");
    _ = @import("output/terminal.zig");
    _ = @import("output/json.zig");
    _ = @import("output/sarif.zig");
    _ = @import("config.zig");
}
