const std = @import("std");

const os = std.os;
const net = std.net;
const tls = std.crypto.tls;

const Allocator = std.mem.Allocator;
const Bundle = std.crypto.Certificate.Bundle;

pub const Stream = struct {
	// kept around just for ca_bundle
	allocator: Allocator,
	// not null if we own this and have to manage/release it
	ca_bundle: ?Bundle,

	pfd: [1]os.pollfd,
	stream: net.Stream,
	tls_client: ?tls.Client,

	pub fn init(allocator: Allocator, stream: net.Stream) Stream {
		return .{
			.ca_bundle = null,
			.tls_client = null,
			.stream = stream,
			.allocator = allocator,
			.pfd = [1]os.pollfd{os.pollfd{
				.fd = stream.handle,
				.events = os.POLL.IN,
				.revents = undefined,
			}},
		};
	}

	pub fn deinit(self: *Stream) void {
		if (self.tls_client) |*tls_client| {
			_ = tls_client.writeEnd(self.stream, "", true) catch {};
		}
		if (self.ca_bundle) |*ca_bundle| {
			ca_bundle.deinit(self.allocator);
		}
		self.stream.close();
	}

	pub fn toTLS(self: *Stream, host: []const u8, ca_bundle: ?Bundle) !void {
		const bundle = ca_bundle orelse blk: {
			var b = Bundle{};
			try b.rescan(self.allocator);
			self.ca_bundle = b;
			break :blk b;
		};
		self.tls_client = try tls.Client.init(self.stream, bundle, host);
	}

	pub fn poll(self: *Stream, timeout: i32) !usize {
		return os.poll(&self.pfd, timeout);
	}

	pub fn read(self: *Stream, buf: []u8) !usize {
		if (self.tls_client) |*tls_client| {
			return tls_client.read(self.stream, buf);
		}
		return self.stream.read(buf);
	}

	pub fn writeAll(self: *Stream, data: []const u8) !void {
		if (self.tls_client) |*tls_client| {
			return tls_client.writeAll(self.stream, data);
		}
		return self.stream.writeAll(data);
	}
};
