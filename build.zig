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
    addRepoFiles(b, lib_mod);

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
    addRepoFiles(b, lib_test_mod);
    const lib_unit_tests = b.addTest(.{ .root_module = lib_test_mod });
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    // LLVM backend for kcov compatibility.
    const cov_lib_tests = b.addTest(.{
        .root_module = lib_test_mod,
        .use_llvm = true,
        .name = "cov-lib-test",
    });
    const install_cov_lib_tests = b.addInstallArtifact(cov_lib_tests, .{});
    const test_bin_step = b.step("test-bin", "Install test binaries for coverage measurement");
    test_bin_step.dependOn(&install_cov_lib_tests.step);

    // The library dependency is `lib_test_mod`, not the distribution `lib_mod`:
    // the latter is stripped in Release modes, and a stripped import next to an
    // unstripped root makes LLVM reject the mixed debug info ("local variable
    // requires a valid scope") when the tests are built with -Doptimize=ReleaseFast.
    //
    // link_libc is required because the imported library includes tests that
    // call setenv/unsetenv via @extern; those symbols must resolve when the
    // CLI test binaries are linked.
    const test_imports: []const std.Build.Module.Import = &.{
        .{ .name = "zghalint", .module = lib_test_mod },
        .{ .name = "build_options", .module = build_options.createModule() },
    };

    const exe_unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = test_imports,
        }),
    });
    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    // Fuzzing gets its own artifact, rooted at the fuzz file rather than
    // src/lib.zig so that coverage instrumentation covers only the parsers
    // under test instead of the whole suite. A plain `zig build fuzz` replays
    // the seed corpus, which is also how these run inside `zig build test`.
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

    // Long fuzzing campaigns (100k+ inputs) run through a plain executable:
    // `zig build fuzz --fuzz` is unusable on Zig 0.15.2, and the driver owns
    // its own corpus, mutator and properties.
    const fuzz_driver_mod = b.createModule(.{
        .root_source_file = b.path("src/fuzz_driver.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    addRepoFiles(b, fuzz_driver_mod);
    const fuzz_driver = b.addExecutable(.{
        .name = "fuzz-driver",
        .root_module = fuzz_driver_mod,
    });
    const run_fuzz_driver = b.addRunArtifact(fuzz_driver);
    if (b.args) |args| run_fuzz_driver.addArgs(args);
    const fuzz_driver_step = b.step("fuzz-driver", "Run the standalone fuzz driver (--iterations N --seed S)");
    fuzz_driver_step.dependOn(&run_fuzz_driver.step);

    // The CLI test binary is measured too, so coverage covers argument
    // parsing, exit codes and `--fix` write-back, not just the library.
    const cov_exe_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = test_imports,
        }),
        .use_llvm = true,
        .name = "cov-exe-test",
    });
    const install_cov_exe_tests = b.addInstallArtifact(cov_exe_tests, .{});
    test_bin_step.dependOn(&install_cov_exe_tests.step);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_exe_unit_tests.step);
}

/// Repository files that tests read but that live outside the module root
/// (`src/`), so a relative `@embedFile` cannot reach them. Expose them under
/// stable names instead.
fn addRepoFiles(b: *std.Build, module: *std.Build.Module) void {
    // src/docs_sync_test.zig
    module.addAnonymousImport("docs_rules_md", .{
        .root_source_file = b.path("docs/rules.md"),
    });
    // src/rules/popular_actions.zig
    module.addAnonymousImport("popular_actions_manifest", .{
        .root_source_file = b.path("scripts/popular-actions.txt"),
    });
}
