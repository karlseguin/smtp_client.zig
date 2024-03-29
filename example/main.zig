const std = @import("std");
const smtp = @import("smtp_client");
const Allocator = std.mem.Allocator;

pub fn main() !void {
	var gpa = std.heap.GeneralPurposeAllocator(.{}){};
	const allocator = gpa.allocator();

	const config = smtp.Config{
		.port = 1025,
		.host = "localhost",
		.encryption = .none,
		.allocator = allocator,
	};

	try smtp.send(.{
		.from = "admin@localhost",
		.to = &.{"user@localhost"},
		.data = "From: Admin <admin@localhost>\r\nTo: User <user@localhost>\r\nSuject: Test\r\n\r\nThis is karl, I'm testing a SMTP client for Zig\r\n.\r\n",
	}, config);
}
