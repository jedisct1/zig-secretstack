const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The self-hosted x86_64 backend can't assemble the AVX register wipe.
    const use_llvm = if (target.result.cpu.arch == .x86_64) true else null;

    const mod = b.addModule("secretstack", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });

    const example = b.addExecutable(.{
        .name = "example",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "secretstack", .module = mod }},
        }),
        .use_llvm = use_llvm,
    });
    b.installArtifact(example);

    const run_step = b.step("run", "Run the example");
    run_step.dependOn(&b.addRunArtifact(example).step);

    const lib_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .use_llvm = use_llvm,
    });
    const example_tests = b.addTest(.{
        .root_module = example.root_module,
        .use_llvm = use_llvm,
    });
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&b.addRunArtifact(lib_tests).step);
    test_step.dependOn(&b.addRunArtifact(example_tests).step);
}
