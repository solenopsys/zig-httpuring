const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseFast });

    const picozig_mod = b.dependency("picozig", .{
        .target = target,
        .optimize = optimize,
    });

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "httpuring",
        .root_module = lib_mod,
    });

    // Change this line - use "udp_uring" instead of "picozig"
    const picozig_artifact = picozig_mod.artifact("picozig");

    lib.root_module.addImport("picozig", picozig_artifact.root_module);

    lib.linkSystemLibrary("ssl");
    lib.linkSystemLibrary("crypto");

    lib.linkLibCpp();
    lib.linkLibC();

    b.installArtifact(lib);
}
