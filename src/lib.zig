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
    pub const expr_type = @import("rules/expr_type.zig");
    pub const expr_catalog = @import("rules/expr_catalog.zig");
    pub const expr_check = @import("rules/expr_check.zig");
    pub const security = @import("rules/security.zig");
    pub const performance = @import("rules/performance.zig");
    pub const best_practices = @import("rules/best_practices.zig");
    pub const permissions = @import("rules/permissions.zig");
    pub const advisory = @import("rules/advisory.zig");
    pub const refconfusion = @import("rules/refconfusion.zig");
    pub const dependabot = @import("rules/dependabot.zig");
    pub const archived = @import("rules/archived.zig");
    pub const stale_refs = @import("rules/stale_refs.zig");
    pub const impostor = @import("rules/impostor.zig");
    pub const impostor_compare = @import("rules/impostor_compare.zig");
    pub const runner = @import("rules/runner.zig");
    pub const syntax = @import("rules/syntax.zig");
    pub const http_client = @import("rules/http_client.zig");
    pub const prefetch = @import("rules/prefetch.zig");
    pub const graphql = @import("rules/graphql.zig");
    pub const disk_cache = @import("rules/disk_cache.zig");
    pub const rest_fallback = @import("rules/rest_fallback.zig");
};

pub const fix = struct {
    pub const engine = @import("fix/engine.zig");
    pub const applyFixes = engine.applyFixes;
    pub const ApplyResult = engine.ApplyResult;
    pub const collectFixes = engine.collectFixes;
    pub const builder = @import("fix/builder.zig");
};

pub const config = @import("config.zig");
pub const Config = config.Config;
pub const OutputFormat = config.OutputFormat;
pub const ColorMode = config.ColorMode;

pub const workspace = @import("workspace.zig");

test {
    _ = @import("yaml/tokenizer.zig");
    _ = @import("yaml/types.zig");
    _ = @import("yaml/parser.zig");
    _ = @import("workflow/types.zig");
    _ = @import("workflow/parser.zig");
    _ = @import("workflow/schema.zig");
    _ = @import("workflow/type_validation.zig");
    _ = @import("workflow/validator.zig");
    _ = @import("diagnostics.zig");
    _ = @import("rules/engine.zig");
    _ = @import("rules/expressions.zig");
    _ = @import("rules/expr_type.zig");
    _ = @import("rules/expr_catalog.zig");
    _ = @import("rules/expr_check.zig");
    _ = @import("rules/security.zig");
    _ = @import("rules/performance.zig");
    _ = @import("rules/best_practices.zig");
    _ = @import("rules/permissions.zig");
    _ = @import("rules/advisory.zig");
    _ = @import("rules/refconfusion.zig");
    _ = @import("rules/dependabot.zig");
    _ = @import("rules/archived.zig");
    _ = @import("rules/stale_refs.zig");
    _ = @import("rules/impostor.zig");
    _ = @import("rules/impostor_compare.zig");
    _ = @import("rules/runner.zig");
    _ = @import("rules/syntax.zig");
    _ = @import("rules/http_client.zig");
    _ = @import("rules/prefetch.zig");
    _ = @import("rules/graphql.zig");
    _ = @import("rules/disk_cache.zig");
    _ = @import("rules/rest_fallback.zig");
    _ = @import("rules/data/compromised_actions.zig");
    _ = @import("output/terminal.zig");
    _ = @import("output/json.zig");
    _ = @import("output/sarif.zig");
    _ = @import("fix/engine.zig");
    _ = @import("fix/builder.zig");
    _ = @import("config.zig");
    _ = @import("util.zig");
    _ = @import("workspace.zig");
}
