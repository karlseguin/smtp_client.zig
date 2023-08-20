const std = @import("std");

const Allocator = std.mem.Allocator;
const Bundle = std.crypto.Certificate.Bundle;

pub const Stream = @import("stream.zig").Stream;
pub const Client = @import("client.zig").Client(*Stream);

pub const Encryption = enum {
	insecure,
	none,
	tls,
	start_tls,
};

pub const Config = struct {
	port: u16,
	host: []const u8,
	timeout: i32 = 10_000,
	encryption: Encryption = .tls,
	username: ?[]const u8 = null,
	password: ?[]const u8 = null,
	local_name: []const u8 = "localhost",
	ca_bundle: ?Bundle = null,
};

pub const Message = struct {
	to: []const []const u8,
	from: []const u8,
	data: []const u8,
};

pub fn send(allocator: Allocator, message: Message, config: Config) !void {
	const encryption = config.encryption;

	const net_stream = try std.net.tcpConnectToHost(allocator, config.host, config.port);

	var stream = Stream.init(allocator, net_stream);
	defer stream.deinit();
	if (encryption == .tls) {
		try stream.toTLS(config.host, config.ca_bundle);
	}

	var client = try Client.init(&stream, config);
	defer client.quit() catch {};

	try client.hello();
	if (encryption == .start_tls) {
		try client.startTLS();
	}
	try client.auth();
	try client.from(message.from);
	try client.to(message.to);
	try client.data(message.data);
}
