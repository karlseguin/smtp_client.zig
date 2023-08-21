const std = @import("std");

const Allocator = std.mem.Allocator;
const Bundle = std.crypto.Certificate.Bundle;

pub const client = @import("client.zig");
pub const Client = client.Client(*Stream);
pub const Stream = @import("stream.zig").Stream;

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
	const net_stream = try std.net.tcpConnectToHost(allocator, config.host, config.port);
	var stream = Stream.init(allocator, net_stream);
	defer stream.deinit();

	if (config.encryption == .tls) {
		try stream.toTLS(config.host, config.ca_bundle);
	}

	return sendT(*Stream, &stream, message, config);
}

// done this way do we can call sendT in test and inject a mock stream object
fn sendT(comptime S: type, stream: S, message: Message, config: Config) !void {
	var c = try client.Client(S).init(stream, config);
	defer c.quit() catch {};

	try c.hello();
	if (config.encryption == .start_tls) {
		try c.startTLS();
	}
	try c.auth();
	try c.from(message.from);
	try c.to(message.to);
	try c.data(message.data);
}

const t = @import("t.zig");

test {
	std.testing.refAllDecls(@This());
}

test "send: unencrypted single to" {
	var ms = t.MockServer.init(&.{
		.{.req = "EHLO localhost\r\n", .res = "250\r\n"},
		.{.req = "MAIL FROM:<from-user@localhost.local>\r\n", .res = "250\r\n"},
		.{.req = "RCPT TO:<to-user@localhost.local>\r\n", .res = "250\r\n"},
		.{.req = "DATA\r\n", .res = "354\r\n"},
		.{.req = "This is the data\r\n.\r\n", .res = "250\r\n"},
		.{.req = "QUIT\r\n", .res = null},
	});

	try sendT(*t.MockServer, &ms, .{
		.from = "from-user@localhost.local",
		.to = &.{"to-user@localhost.local"},
		.data = "This is the data\r\n.\r\n",
	}, .{
		.port = 0,
		.host = "localhost",
	});
}

test "send: scram-md5 + multiple to" {
	var ms = t.MockServer.init(&.{
		.{.req = "EHLO localhost\r\n", .res = "250-Ok\r\n250 AUTH Plain cram-MD5\r\n"},
		.{.req = "AUTH CRAM-MD5\r\n", .res = "235 my secret\r\n"},
		.{.req = "leto 9103a6f589ce8c5a3b775dd878b5ac3a\r\n", .res = "235 my secret\r\n"},
		.{.req = "MAIL FROM:<from-user@localhost.local>\r\n", .res = "250\r\n"},
		.{.req = "RCPT TO:<to-user1@localhost.local>\r\n", .res = "250\r\n"},
		.{.req = "RCPT TO:<to-user2@localhost.local>\r\n", .res = "250\r\n"},
		.{.req = "DATA\r\n", .res = "354\r\n"},
		.{.req = "hi\r\n", .res = "250\r\n"},
		.{.req = "QUIT\r\n", .res = null},
	});

	try sendT(*t.MockServer, &ms, .{
		.from = "from-user@localhost.local",
		.to = &.{"to-user1@localhost.local", "to-user2@localhost.local"},
		.data =  "hi\r\n",
	}, .{
		.port = 0,
		.host = "localhost",
		.username = "leto",
		.password =  "ghanima",
	});
}
