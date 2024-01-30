const std = @import("std");
const FileSource = @import("std").build.FileSource;

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const smtp_client = b.addModule("smtp_client", .{ .source_file = FileSource.relative("src/smtp.zig") });

    {
        // example
        const exe = b.addExecutable(.{
            .name = "smtp_client_demo",
            .root_source_file = .{ .path = "example/main.zig" },
            .target = target,
            .optimize = optimize,
        });
        exe.addModule("smtp_client", smtp_client);
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
            .root_source_file = .{ .path = "src/smtp.zig" },
            .target = target,
            .optimize = optimize,
        });
        const run_test = b.addRunArtifact(lib_test);
        run_test.has_side_effects = true;

        const test_step = b.step("test", "Run tests");
        test_step.dependOn(&run_test.step);
    }
}
