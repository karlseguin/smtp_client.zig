const std = @import("std");

const os = std.os;
const net = std.net;
const tls = std.crypto.tls;
const Bundle = std.crypto.Certificate.Bundle;

// Wrap a net.Stream to provide a consistent interface between with a TLS client
pub const Plain = struct {
	pfd: [1]os.pollfd,
	stream: net.Stream,

	pub fn init(stream: net.Stream) Plain {
		return .{
			.stream = stream,
			.pfd = [1]os.pollfd{os.pollfd{
				.fd = stream.handle,
				.events = os.POLL.IN,
				.revents = undefined,
			}},
		};
	}

	pub fn close(self: Plain) void {
		self.stream.close();
	}

	pub fn poll(self: *Plain, timeout: i32) !usize {
		return os.poll(&self.pfd, timeout);
	}

	pub fn read(self: Plain, buf: []u8) !usize {
		return self.stream.read(buf);
	}

	pub fn writeAll(self: Plain, data: []const u8) !void {
		return self.stream.writeAll(data);
	}
};

// wrap an tls_client + net.stream
pub const Tls = struct {
	pfd: [1]os.pollfd,
	stream: net.Stream,
	tls_client: tls.Client,

	pub fn init(stream: net.Stream, host: []const u8, ca_bundle: Bundle) !Tls {
		return .{
			.stream = stream,
			.pfd = [1]os.pollfd{os.pollfd{
				.fd = stream.handle,
				.events = os.POLL.IN,
				.revents = undefined,
			}},
			.tls_client = try tls.Client.init(stream, ca_bundle, host),
		};
	}

	pub fn close(self: Tls) void {
		self.end();
		self.stream.close();
	}

	pub fn end(self: *Tls) void {
		_ = self.tls_client.writeEnd(self.stream, "", true) catch {};
	}

	pub fn poll(self: *Tls, timeout: i32) !usize {
		return os.poll(&self.pfd, timeout);
	}

	pub fn read(self: *Tls, buf: []u8) !usize {
		return self.tls_client.read(self.stream, buf);
	}

	pub fn writeAll(self: *Tls, data: []const u8) !void {
		return self.tls_client.writeAll(self.stream, data);
	}
};
