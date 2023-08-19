const std = @import("std");
const client = @import("client.zig");
const stream = @import("stream.zig");

const Allocator = std.mem.Allocator;
const Bundle = std.crypto.Certificate.Bundle;

pub const Client = client.Client(stream.Plain);
pub const TlsClient = client.Client(*stream.Tls);

pub const Config = struct {
	tls: bool,
	port: u16,
	host: []const u8,
	timeout: i32 = 10_000,
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
	defer net_stream.close();
	if (!config.tls) {
		const s = stream.Plain.init(net_stream);
		var c = try Client.init(s, config);
		return sendToClient(message, &c);
	}

	var own_bundle = false;
	var ca_bundle = config.ca_bundle orelse blk: {
		var b = Bundle{};
		try b.rescan(allocator);
		own_bundle = true;
		break :blk b;
	};

	defer if (own_bundle) ca_bundle.deinit(allocator);

	var s = try stream.Tls.init(net_stream, config.host, ca_bundle);
	defer s.end();
	var c = try TlsClient.init(&s, config);
	return sendToClient(message, &c);
}

// c can be a Client(Stream) or a client(TLSStream)
fn sendToClient(m: Message, c: anytype) !void {
	defer c.quit() catch {};

	try c.hello();
	try c.auth();
	try c.from(m.from);
	try c.to(m.to);
	try c.data(m.data);
}
