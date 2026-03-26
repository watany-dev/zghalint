pub const diagnostics = @import("diagnostics.zig");
pub const workflow = struct {
    pub const types = @import("workflow/types.zig");
};
pub const rules = struct {
    pub const engine = @import("rules/engine.zig");
    pub const performance = @import("rules/performance.zig");
    pub const best_practices = @import("rules/best_practices.zig");
    pub const permissions = @import("rules/permissions.zig");
};

test {
    _ = diagnostics;
    _ = workflow.types;
    _ = rules.engine;
    _ = rules.performance;
    _ = rules.best_practices;
    _ = rules.permissions;
}
