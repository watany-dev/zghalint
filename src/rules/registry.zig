//! The CLI, the SARIF renderer, and the fixture-driven E2E tests all run the
//! same rule set, so it lives here instead of in `main.zig`.

const std = @import("std");
const engine = @import("engine.zig");
const security = @import("security.zig");
const best_practices = @import("best_practices.zig");
const performance = @import("performance.zig");
const permissions = @import("permissions.zig");
const expressions = @import("expressions.zig");
const inputs_context = @import("inputs_context.zig");
const matrix_context = @import("matrix_context.zig");
const secrets_context = @import("secrets_context.zig");
const needs_context = @import("needs_context.zig");
const dependabot = @import("dependabot.zig");
const action_metadata = @import("action_metadata.zig");
const runner = @import("runner.zig");
const syntax = @import("syntax.zig");
const uses = @import("uses.zig");
const local_action = @import("local_action.zig");
const reusable_workflow = @import("reusable_workflow.zig");
const steps_ref = @import("steps_ref.zig");

pub const all_rules = security.security_rules ++
    best_practices.rules ++
    performance.rules ++
    permissions.rules ++
    [_]engine.Rule{expressions.expression_rule} ++
    needs_context.rules ++
    matrix_context.rules ++
    inputs_context.rules ++
    secrets_context.rules ++
    steps_ref.rules ++
    dependabot.rules ++
    action_metadata.rules ++
    runner.rules ++
    syntax.rules ++
    uses.rules ++
    local_action.rules ++
    reusable_workflow.rules;

/// Every rule ID that can appear in a diagnostic, and therefore every ID that
/// `docs/rules.md` must document. This is `all_rules` with the umbrella `EXPR`
/// entry expanded into the IDs it actually emits.
pub const documented_rule_ids: []const []const u8 = blk: {
    var ids: [all_rules.len + expressions.sub_rule_ids.len]([]const u8) = undefined;
    var n: usize = 0;
    for (all_rules) |rule| {
        if (std.mem.eql(u8, rule.id, expressions.expression_rule.id)) {
            for (expressions.sub_rule_ids) |sub_id| {
                ids[n] = sub_id;
                n += 1;
            }
            continue;
        }
        ids[n] = rule.id;
        n += 1;
    }
    const final = ids[0..n].*;
    break :blk &final;
};
