const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseFast });

    const exe = b.addExecutable(.{
        .name = "ingress",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Напрямую создаем модуль вместо использования зависимости
    const picozig_mod = b.createModule(.{
        .root_source_file = b.path("../zig-pico/src/main.zig"),
    });

    // Добавляем модуль к исполняемому файлу
    exe.root_module.addImport("picozig", picozig_mod);

    exe.linkSystemLibrary("ssl");
    exe.linkSystemLibrary("crypto");

    exe.linkLibCpp();
    exe.linkLibC();

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the SSL test");
    run_step.dependOn(&run_cmd.step);
}
