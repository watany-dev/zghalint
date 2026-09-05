const std = @import("std");

/// Single source of truth for the CLI version: build.zig.zon.
const version = @import("build.zig.zon").version;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", version);

    // Strip debug info from Release-mode distribution binaries.
    // Debug keeps symbols for local development; tests retain debug info for stack traces / kcov.
    const strip_release: ?bool = if (optimize == .Debug) null else true;

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .strip = strip_release,
    });

    // Both the CLI module and its test module need the same dependencies.
    const cli_imports: []const std.Build.Module.Import = &.{
        .{ .name = "zghalint", .module = lib_mod },
        .{ .name = "build_options", .module = build_options.createModule() },
    };

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .strip = strip_release,
        .imports = cli_imports,
    });

    const exe = b.addExecutable(.{
        .name = "zghalint",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the zghalint linter");
    run_step.dependOn(&run_cmd.step);

    // Tests link libc so env-mutating helpers (setenv/unsetenv) are resolved.
    const lib_test_mod = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const lib_unit_tests = b.addTest(.{ .root_module = lib_test_mod });
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    // LLVM backend for kcov compatibility.
    const cov_unit_tests = b.addTest(.{
        .root_module = lib_test_mod,
        .use_llvm = true,
    });
    const install_cov_tests = b.addInstallArtifact(cov_unit_tests, .{});
    const test_bin_step = b.step("test-bin", "Install test binary for coverage measurement");
    test_bin_step.dependOn(&install_cov_tests.step);

    // link_libc is required because the imported lib_mod includes tests that
    // call setenv/unsetenv via @extern; those symbols must resolve when the
    // exe test binary is linked.
    const exe_unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = cli_imports,
        }),
    });
    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_exe_unit_tests.step);
}
