const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // --- Library module ---
    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    // --- Library artifact ---
    const lib = b.addLibrary(.{
        .name = "zghalint",
        .root_module = lib_mod,
    });
    b.installArtifact(lib);

    // --- CLI executable ---
    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zghalint", .module = lib_mod },
        },
    });

    const exe = b.addExecutable(.{
        .name = "zghalint",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    // --- Run step ---
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the zghalint linter");
    run_step.dependOn(&run_cmd.step);

    // --- Library tests ---
    // Tests link libc so env-mutating helpers (setenv/unsetenv) are resolved.
    const lib_unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/lib.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    // --- Coverage support: install test binary (LLVM backend for kcov compatibility) ---
    const cov_unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/lib.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
        .use_llvm = true,
    });
    const install_cov_tests = b.addInstallArtifact(cov_unit_tests, .{});
    const test_bin_step = b.step("test-bin", "Install test binary for coverage measurement");
    test_bin_step.dependOn(&install_cov_tests.step);

    // --- Executable tests ---
    // link_libc is required because the imported lib_mod includes tests that
    // call setenv/unsetenv via @extern; those symbols must resolve when the
    // exe test binary is linked.
    const exe_unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "zghalint", .module = lib_mod },
            },
        }),
    });
    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_exe_unit_tests.step);

    // --- Format check step ---
    const fmt_step = b.step("fmt", "Check source formatting");
    const fmt = b.addFmt(.{
        .paths = &.{ "src", "build.zig" },
        .check = true,
    });
    fmt_step.dependOn(&fmt.step);
}
