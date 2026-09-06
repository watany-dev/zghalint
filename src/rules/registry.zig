//! The CLI, the SARIF renderer, and the fixture-driven E2E tests all run the
//! same rule set, so it lives here instead of in `main.zig`.

const engine = @import("engine.zig");
const security = @import("security.zig");
const best_practices = @import("best_practices.zig");
const performance = @import("performance.zig");
const permissions = @import("permissions.zig");
const expressions = @import("expressions.zig");
const dependabot = @import("dependabot.zig");
const runner = @import("runner.zig");
const syntax = @import("syntax.zig");
const uses = @import("uses.zig");

pub const all_rules = security.security_rules ++
    best_practices.rules ++
    performance.rules ++
    permissions.rules ++
    [_]engine.Rule{expressions.expression_rule} ++
    dependabot.rules ++
    runner.rules ++
    syntax.rules ++
    uses.rules;
