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
    addDocsRules(b, lib_mod);

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
    addDocsRules(b, lib_test_mod);
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

    // Fuzzing gets its own artifact: `zig build fuzz --fuzz` instruments only
    // these targets, and a plain `zig build fuzz` runs each one over its seed
    // corpus, which is also how they run inside `zig build test`.
    // Rooted at the fuzz file rather than src/lib.zig: only the parsers under
    // test get coverage instrumentation, instead of the whole 1400-test suite.
    const fuzz_mod = b.createModule(.{
        .root_source_file = b.path("src/fuzz_test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const fuzz_tests = b.addTest(.{
        .root_module = fuzz_mod,
        // The imported modules bring their own inline tests along; only the
        // fuzz targets belong to this step.
        .filters = &.{"fuzz:"},
        // The self-hosted x86_64 backend emits no `-fsanitize-coverage` PCs,
        // so `--fuzz` panics in std.Build.Fuzz.addEntryPoint with an empty PC
        // list. The LLVM backend produces the coverage the fuzzer needs.
        .use_llvm = true,
    });
    const run_fuzz_tests = b.addRunArtifact(fuzz_tests);
    const fuzz_step = b.step("fuzz", "Run fuzz targets (add --fuzz for continuous fuzzing)");
    fuzz_step.dependOn(&run_fuzz_tests.step);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_exe_unit_tests.step);
}

/// `docs/rules.md` lives outside the module root (`src/`), so it cannot be
/// reached with a relative `@embedFile`. Expose it under a stable name for
/// src/docs_sync_test.zig instead.
fn addDocsRules(b: *std.Build, module: *std.Build.Module) void {
    module.addAnonymousImport("docs_rules_md", .{
        .root_source_file = b.path("docs/rules.md"),
    });
}
