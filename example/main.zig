const std = @import("std");
const Mailer = @import("smtp_client").Client;
const Allocator = std.mem.Allocator;

pub fn main() !void {
	const address = try std.net.Address.parseIp("127.0.0.1", 1025);
	const stream = try std.net.tcpConnectToAddress(address);
	defer stream.close();

	var client = try Mailer.init(stream, .{
		.username = "username1",
		.password = "password1",
	});
	defer client.quit() catch {};

	try client.hello();
	try client.auth();
	try client.from("admin@localhost");
	try client.to(&.{"user@localhost"});
	try client.data("Suject: Test\r\n\r\nThis is a test\r\n.\r\n");
	// This example starts 3 separate servers
}
