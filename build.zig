const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The module a consumer imports: `b.dependency("rest_core", .{})
    // .module("rest_core")`.
    const mod = b.addModule("rest_core", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const test_filters = b.option(
        []const []const u8,
        "test-filter",
        "Skip tests whose names do not match any filter",
    ) orelse &.{};
    // Fuzzing needs the LLVM backend. The self-hosted x86_64 backend, the
    // Debug default there, emits no coverage instrumentation, so the fuzzer
    // would run blind. `zig build test -Dfuzz-runner --fuzz` fuzzes the
    // properties; `-Dtest-filter=fuzz` skips the tests that are not one.
    const fuzz_runner = b.option(
        bool,
        "fuzz-runner",
        "Build the tests for `zig build test --fuzz`: LLVM backend",
    ) orelse false;
    // Every test build runs under std's test runner with one fix, which
    // keeps std.debug from swallowing a task's cancel (see the top of
    // tools/test_runner.zig).
    const test_runner: std.Build.Step.Compile.TestRunner = .{ .path = b.path("tools/test_runner.zig"), .mode = .server };

    const test_step = b.step("test", "Run the unit, property and fuzz-corpus tests, zig fmt --check, zigvet and gnarl");
    // The same tests and nothing else beside them, for CI's optimized jobs.
    const unit_step = b.step("test-unit", "Run the unit, property and fuzz-corpus tests, and nothing else");
    test_step.dependOn(unit_step);
    unit_step.dependOn(&b.addRunArtifact(b.addTest(.{
        .root_module = mod,
        .filters = test_filters,
        .test_runner = test_runner,
        .use_llvm = if (fuzz_runner) true else null,
    })).step);
    // The security suite (test/security): a test per known attack, through
    // the public API only. Each is a row of test/security/CATALOG.md.
    const security_tests = b.addTest(.{
        .name = "security",
        .root_module = securityModule(b, target, optimize, mod),
        .filters = test_filters,
        .test_runner = test_runner,
        .use_llvm = if (fuzz_runner) true else null,
    });
    unit_step.dependOn(&b.addRunArtifact(security_tests).step);

    // The same tests with the library built ReleaseSafe and ReleaseFast. A
    // consumer builds this library in the mode it ships, and in ReleaseFast
    // `unreachable`, overflow and a cast out of range are undefined rather
    // than a panic. `zig build test test-release` runs all three.
    const release_step = b.step("test-release", "Run the unit tests with the library built ReleaseSafe and ReleaseFast");
    for ([_]std.builtin.Optimize{ .safe, .fast }) |mode| {
        const release_mod = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = mode,
        });
        release_step.dependOn(&b.addRunArtifact(b.addTest(.{
            .name = @tagName(mode),
            .root_module = release_mod,
            .filters = test_filters,
            .test_runner = test_runner,
        })).step);
        release_step.dependOn(&b.addRunArtifact(b.addTest(.{
            .name = b.fmt("security-{t}", .{mode}),
            .root_module = securityModule(b, target, mode, release_mod),
            .filters = test_filters,
            .test_runner = test_runner,
        })).step);
    }

    // tools/security_catalog.zig holds the catalog to the tests: a covered
    // row whose test is gone, or a `security: ...` test no row names, fails
    // `zig build test`. It reads files the build does not track, so it
    // always runs (it takes milliseconds).
    const catalog_tool = b.addExecutable(.{ .name = "security-catalog", .root_module = b.createModule(.{
        .root_source_file = b.path("tools/security_catalog.zig"),
        .target = b.graph.host,
        .optimize = .safe,
    }) });
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = catalog_tool.root_module, .test_runner = test_runner })).step);
    const check_catalog = b.addRunArtifact(catalog_tool);
    check_catalog.setCwd(b.path("."));
    check_catalog.addArgs(&.{ "test/security/CATALOG.md", "test/security" });
    check_catalog.has_side_effects = true;
    test_step.dependOn(&check_catalog.step);
    const security_step = b.step("security", "Run the security suite and check its catalog (test/security)");
    security_step.dependOn(&b.addRunArtifact(security_tests).step);
    security_step.dependOn(&check_catalog.step);

    // zigvet (github.com/kmoneil/zigvet) reports code the compiler accepts
    // that is almost certainly wrong. A program on the PATH, not a package;
    // `zig build test` runs it, so no change is tested without it. Add
    // examples/ here when it exists. It skips zig-pkg and hidden directories
    // by itself.
    const lint = b.addSystemCommand(&.{ "zigvet", "build.zig", "src", "test", "tools" });
    lint.setCwd(b.path("."));
    b.step("lint", "Report code that compiles but is wrong (zigvet, from the PATH)").dependOn(&lint.step);
    test_step.dependOn(&lint.step);

    // gnarl (github.com/kmoneil/gnarl) holds each function to the complexity
    // limits of its class in complexity.zon, which also names the gnarl
    // release the code is judged by; complexity.baseline holds what is over
    // a limit today, so `--check` fails only what is new or worse. A pass
    // prints nothing. Always run: the build does not know what gnarl reads,
    // and a cached step would pass a regression unseen.
    const complexity = b.addSystemCommand(&.{ "gnarl", "--check", "." });
    complexity.setCwd(b.path("."));
    complexity.has_side_effects = true;
    b.step("complexity", "Fail a function newly over its complexity limit (gnarl, from the PATH)").dependOn(&complexity.step);
    test_step.dependOn(&complexity.step);

    const fmt_paths: []const std.Build.LazyPath = &.{ b.path("build.zig"), b.path("build.zig.zon"), b.path("src"), b.path("test"), b.path("tools") };
    test_step.dependOn(&b.addFmt(.{ .paths = fmt_paths, .check = true }).step);
    b.step("fmt", "Format the Zig in build.zig, src/, test/ and tools/").dependOn(&b.addFmt(.{ .paths = fmt_paths }).step);

    // The API reference, from the doc comments: zig-out/docs/index.html.
    const lib = b.addLibrary(.{ .name = "rest_core", .root_module = mod });
    const docs = b.addInstallDirectory(.{ .source_dir = lib.getEmittedDocs(), .install_dir = .prefix, .install_subdir = "docs" });
    b.step("docs", "Build the API reference into zig-out/docs").dependOn(&docs.step);
}

/// The security suite's module, over `rest_core` built as `mod` is.
fn securityModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.Optimize, mod: *std.Build.Module) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("test/security/security_test.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "rest_core", .module = mod }},
    });
}
