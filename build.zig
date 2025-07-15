const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const smtp_client = b.addModule("smtp_client", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/smtp.zig"),
    });

    {
        // example
        const exe = b.addExecutable(.{
            .name = "smtp_client_demo",
            .root_module = smtp_client,
        });
        exe.linkLibC();
        exe.root_module.addImport("smtp_client", smtp_client);
        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        const run_step = b.step("run", "Run the example");
        run_step.dependOn(&run_cmd.step);
    }

    {
        // tests
        const lib_test = b.addTest(.{
            .root_module = smtp_client,
            .test_runner = .{ .path = b.path("test_runner.zig"), .mode = .simple },
        });
        const run_test = b.addRunArtifact(lib_test);
        run_test.has_side_effects = true;

        const test_step = b.step("test", "Run tests");
        test_step.dependOn(&run_test.step);
    }
}
