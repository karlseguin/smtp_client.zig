// Internal helpers used by this library
// If you're looking for helpers to help you mock/test
const std = @import("std");
const lib = @import("lib.zig");

const mem = std.mem;
const ArrayList = std.ArrayList;

pub const allocator = std.testing.allocator;

// std.testing.expectEqual won't coerce expected to actual, which is a problem
// when expected is frequently a comptime.
// https://github.com/ziglang/zig/issues/4437
pub fn expectEqual(expected: anytype, actual: anytype) !void {
	try std.testing.expectEqual(@as(@TypeOf(actual), expected), actual);
}

pub const expectError = std.testing.expectError;
pub const expectString = std.testing.expectEqualStrings;

// Dummy net.Stream, lets us setup data to be read and capture data that is written.
pub const Stream = struct {
	closed: bool,
	handle: c_int = 0,
	_read_index: usize,
	_random: std.rand.DefaultPrng,
	_to_read: std.ArrayList(u8),
	_received: std.ArrayList(u8),

	pub fn init() *Stream {
		var seed: u64 = undefined;
		std.os.getrandom(std.mem.asBytes(&seed)) catch unreachable;

		const s = allocator.create(Stream) catch unreachable;
		s.* = .{
			.closed = false,
			._read_index = 0,
			._random = std.rand.DefaultPrng.init(seed),
			._to_read = std.ArrayList(u8).init(allocator),
			._received = std.ArrayList(u8).init(allocator),
		};
		return s;
	}

	pub fn deinit(self: *Stream) void {
		self._to_read.deinit();
		self._received.deinit();
		allocator.destroy(self);
	}

	pub fn reset(self: *Stream) void {
		self._read_index = 0;
		self._to_read.clearRetainingCapacity();
		self._received.clearRetainingCapacity();
	}

	pub fn received(self: *Stream) []const u8 {
		return self._received.items;
	}

	pub fn poll(_: Stream, _: i32) !usize {
		return 1;
	}

	pub fn add(self: *Stream, value: []const u8) void {
		self._to_read.appendSlice(value) catch unreachable;
	}

	pub fn read(self: *Stream, buf: []u8) !usize {
		std.debug.assert(!self.closed);

		const read_index = self._read_index;
		const items = self._to_read.items;

		if (read_index == items.len) {
			return 0;
		}
		if (buf.len == 0) {
			return 0;
		}

		// let's fragment this message
		const left_to_read = items.len - read_index;
		const max_can_read = if (buf.len < left_to_read) buf.len else left_to_read;
		var r = self._random.random();
		const to_read = r.uintAtMost(usize, max_can_read - 1) + 1;

		var data = items[read_index..(read_index+to_read)];
		if (data.len > buf.len) {
			// we have more data than we have space in buf (our target)
			// we'll give it when it can take
			data = data[0..buf.len];
		}
		self._read_index = read_index + data.len;

		for (data, 0..) |b, i| {
			buf[i] = b;
		}

		return data.len;
	}

	// store messages that are written to the stream
	pub fn writeAll(self: *Stream, data: []const u8) !void {
		self._received.appendSlice(data) catch unreachable;
	}

	pub fn close(self: *Stream) void {
		self.closed = true;
	}
};


pub const MockServer = struct {
	index: ?usize,
	req_res: []const ReqRes,

	pub fn init(req_res: []const ReqRes) MockServer {
		return .{
			.index = null,
			.req_res = req_res,
		};
	}

	pub fn toTLS(_: *MockServer, _: *const lib.Config) !void {
		// noop
	}

	pub fn poll(_: MockServer, _: i32) !usize {
		return 1;
	}

	pub fn read(self: *MockServer, buf: []u8) !usize {
		const index = self.index orelse {
			// in SMTP, the server sends the initial data.
			@memcpy(buf[0..5], "220\r\n");
			self.index = 0;
			return 5;
		};

		const rr = self.req_res[index];
		if (rr.res) |res| {
			@memcpy(buf[0..res.len], res);
			self.index = index + 1;
			return res.len;
		}
		@panic("unexpected read");
	}

	// store messages that are written to the stream
	pub fn writeAll(self: *MockServer, data: []const u8) !void {
		const index = self.index orelse {
			@panic("received data before server initiated connection");
		};

		try expectString(data, self.req_res[index].req);
	}

	const ReqRes = struct {
		req: []const u8,
		res: ?[]const u8,
	};
};
