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

    const test_step = b.step("test", "Run the unit, property and fuzz-corpus tests, and check formatting");
    // The same tests and nothing else beside them, for CI's optimized jobs.
    const unit_step = b.step("test-unit", "Run the unit, property and fuzz-corpus tests, and nothing else");
    test_step.dependOn(unit_step);
    unit_step.dependOn(&b.addRunArtifact(b.addTest(.{
        .root_module = mod,
        .filters = test_filters,
        .test_runner = test_runner,
        .use_llvm = if (fuzz_runner) true else null,
    })).step);

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
    }

    const fmt_paths: []const std.Build.LazyPath = &.{ b.path("build.zig"), b.path("build.zig.zon"), b.path("src"), b.path("tools") };
    test_step.dependOn(&b.addFmt(.{ .paths = fmt_paths, .check = true }).step);
    b.step("fmt", "Format the Zig in build.zig, src/ and tools/").dependOn(&b.addFmt(.{ .paths = fmt_paths }).step);

    // The API reference, from the doc comments: zig-out/docs/index.html.
    const lib = b.addLibrary(.{ .name = "rest_core", .root_module = mod });
    const docs = b.addInstallDirectory(.{ .source_dir = lib.getEmittedDocs(), .install_dir = .prefix, .install_subdir = "docs" });
    b.step("docs", "Build the API reference into zig-out/docs").dependOn(&docs.step);
}
