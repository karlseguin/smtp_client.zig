const std = @import("std");
const builtin = @import("builtin");
const client = @import("client.zig");

pub const Client = client.Client;

pub const Config = struct {
	timeout: i32 = 10_000,
	username: ?[]const u8 = null,
	password: ?[]const u8 = null,
	local_name: []const u8 = "localhost",
};

pub const Message = struct {
	to: []const []const u8,
	from: []const u8,
	subject: []const u8,
	body: []const u8,
};

pub const AuthMode = enum {
	PLAIN,
	LOGIN,
	CRAM_MD5,
};

// pub fn send(message: Message, config: Config) !void {
// 	if (comptime builtin.is_test) {
// 		// TODO...
// 	} else {
// 		const address = try std.net.Address.parseIp(config.host, config.port);
// 		const stream = try std.net.tcpConnectToAddress(address);
// 		return client.sendToStream(stream, message, config);
// 	}
// }

test {
	std.testing.refAllDecls(@This());
}
