const std = @import("std");
const lib = @import("lib.zig");

const os = std.os;

// Tracks state across multiple socket reads
pub fn Reader(comptime S: type) type {
	return struct {
		// 512 is the largest reply we can get, but we can get multiline replies.
		buf: [1024]u8 = undefined,

		// start in buf of the next message
		start: usize = 0,

		// position in buf that we have valid data up to
		pos: usize = 0,

		timeout: i32,

		stream: S,

		const Self = @This();

		pub fn init(stream: S, timeout: i32) Self {
			return .{
				.stream = stream,
				.timeout = timeout,
			};
		}

		pub fn read(self: *Self) !Reply {
			if (self.buffered()) |reply| {
				return reply;
			}

			var stream = self.stream;
			const timeout = self.timeout;
			const deadline = std.time.milliTimestamp() + timeout;

			var pos = self.pos;
			var buf = &self.buf;

			while (true) {
				if (pos == buf.len) {
					const start = self.start;
					if (start == 0) {
						// our buffer is full
						return error.MessageTooLarge;
					}
					// our buffer is "full", but our start isn't at 0. Move our data back at
					// the start of the buffer. start will become 0, and pos will become the
					// length of the data.

					@memcpy(buf[0..pos - start], buf[start..pos]);
					pos = pos - start;
					self.start = 0;
				}

				if ((try stream.poll(timeout)) == 0) {
					return error.Timeout;
				}

				const n = try stream.read(buf[pos..]);
				if (n == 0) {
					return error.Closed;
				}

				pos += n;
				self.pos = pos;
				if (self.buffered()) |reply| {
					return reply;
				}

				if (std.time.milliTimestamp() > deadline) {
					return error.Timeout;
				}
			}
		}

		// checks (and returns) if we alrady have a reply buffered
		fn buffered(self: *Self) ?Reply {
			const pos = self.pos;
			const start = self.start;
			if (pos == start) return null;

			const buf = self.buf;
			if (std.mem.indexOfScalar(u8, buf[start..pos], '\n')) |index| {
				const message_end = start + index;
				const new_start = message_end + 1;
				if (new_start == pos) {
					// we have no more data in the buffer, reset everything to the start
					// so that we have the full buffer for future messages
					self.pos = 0;
					self.start = 0;
				} else {
					self.start = new_start;
				}
				return Reply.parse(buf[start..message_end-1]);
			}
			return null;
		}
	};
}

// The reply doesn't own raw, and thus its lifetime is only as long as the
// next reply sequence.
pub const Reply = struct {
	code: u16,
	more: bool,
	raw: []const u8,
	data: []const u8,

	// our caller made sure that data.len >= 3
	fn parse(raw: []const u8) Reply {
		return .{
			.raw = raw,
			.more = raw.len > 3 and raw[3] == '-',
			.data = if (raw.len > 4) raw[4..] else "",
			.code = ((@as(u16, raw[0]) - '0') * 100) + ((@as(u16, raw[1]) - '0') * 10) + (raw[2] - '0'),
		};
	}
};

const t = lib.testing;
test "reader: buffered" {
	{
		// empty
		var reader = Reader(*t.Stream).init(undefined, 0);
		try t.expectEqual(null, reader.buffered());
		try t.expectEqual(0, reader.pos);
		try t.expectEqual(0, reader.start);
	}

	{
		// small data, no message
		var reader = Reader(*t.Stream).init(undefined, 0);
		reader.buf[0] = 'a';
		reader.pos = 1;
		try t.expectEqual(null, reader.buffered());
	}

	{
		// more data, still no message
		var reader = Reader(*t.Stream).init(undefined, 0);
		@memcpy(reader.buf[0..11], "200 abc123!");
		reader.pos = 11;
		try t.expectEqual(null, reader.buffered());
	}

	{
		// single message at 0 start
		var reader = Reader(*t.Stream).init(undefined, 0);
		@memcpy(reader.buf[0..5], "253\r\n");
		reader.pos = 5;
		try expectReply(try reader.read(), 253, false, "");
		// the buffer only had this exact message, it should reset everything to
		// 0 in the name of efficiency (so that we have the full buffer available again)
		try t.expectEqual(0, reader.pos);
		try t.expectEqual(0, reader.start);
	}

	{
		// message at 0 start with data
		var reader = Reader(*t.Stream).init(undefined, 0);
		@memcpy(reader.buf[0..15], "500 Go Away\r\n20");
		reader.pos = 15;
		try expectReply(try reader.read(), 500, false, "Go Away");
		try t.expectEqual(15, reader.pos);
		try t.expectEqual(13, reader.start);
	}

	{
		// incomplete multiline messages
		var reader = Reader(*t.Stream).init(undefined, 0);
		@memcpy(reader.buf[0..21], "100-\r\n100-Hello\r\n100\r");
		reader.pos = 21;
		try expectReply(try reader.read(), 100, true, "");
		try expectReply(try reader.read(), 100, true, "Hello");

		try t.expectEqual(21, reader.pos);
		try t.expectEqual(17, reader.start);
	}

	{
		// complete multiline messsage
		var reader = Reader(*t.Stream).init(undefined, 0);
		@memcpy(reader.buf[0..22], "101-\r\n101-He1lo\r\n101\r\n");
		reader.pos = 22;
		try expectReply(try reader.read(), 101, true, "");
		try expectReply(try reader.read(), 101, true, "He1lo");
		try expectReply(try reader.read(), 101, false, "");
		try t.expectEqual(0, reader.pos);
		try t.expectEqual(0, reader.start);
	}
}

test "reader: read fuzz" {
	// stream randomly fragments the data into N reads
	for (0..100) |_| {
		const stream = t.Stream.init();
		defer stream.deinit();

		stream.add("100\r\n");
		stream.add("101 a\r\n");
		stream.add("200 this is a bit longer\r\n");
		stream.add("300-\r\n");
		stream.add("300\r\n");
		stream.add("301-hello\r\n");
		stream.add("301-\r\n");
		stream.add("301-even more data\r\n");
		stream.add("301\r\n");

		var reader = Reader(*t.Stream).init(stream, 0);
		try expectReply(try reader.read(), 100, false, "");
		try expectReply(try reader.read(), 101, false, "a");
		try expectReply(try reader.read(), 200, false, "this is a bit longer");
		try expectReply(try reader.read(), 300, true, "");
		try expectReply(try reader.read(), 300, false, "");
		try expectReply(try reader.read(), 301, true, "hello");
		try expectReply(try reader.read(), 301, true, "");
		try expectReply(try reader.read(), 301, true, "even more data");
		try expectReply(try reader.read(), 301, false, "");
	}
}

fn expectReply(reply: Reply, expected_code: u16, expected_more: bool, expected_data: []const u8) !void {
	try t.expectEqual(expected_code, reply.code);
	try t.expectEqual(expected_more, reply.more);
	try t.expectString(expected_data, reply.data);
}
