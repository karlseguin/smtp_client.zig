const std = @import("std");

const lib = @import("lib.zig");
const Config = lib.Config;
const Reader = lib.Reader;

pub const AuthMode = enum {
	PLAIN,
	LOGIN,
	CRAM_MD5,
};

pub fn Client(comptime S: type) type {
	return struct {
		stream: S,

		reader: Reader(S),

		// maximum reply length is 512
		buf: [512]u8 = undefined,

		config: Config,

		// whether the server supports the 8BITMIME, SMTPUTF8 and AUTH extensions
		ext_8_bit_mine: bool = false,
		ext_smtp_utf8: bool = false,
		ext_auth: ?AuthMode = null,

		const Self = @This();

		pub fn init(stream: S, config: Config) !Self {
			var client = Self{
				.stream = stream,
				.config = config,
				.reader = Reader(S).init(stream, config.timeout),
			};

			const code = (try client.reader.read()).code;
			if (code != 220) {
				return errorFromCode(code);
			}
			return client;
		}

		pub fn hello(self: *Self) !void {
			var buf = &self.buf;
			var reader = &self.reader;

			const msg = try std.fmt.bufPrint(buf, "EHLO {s}\r\n", .{self.config.local_name});
			try self.stream.writeAll(msg);

			while (true) {
				const reply = try reader.read();
				const code = reply.code;
				if (code != 250) {
					return errorFromCode(code);
				}

				const reply_data = reply.data;
				if (std.ascii.eqlIgnoreCase(reply_data, "8BITMIME")) {
					self.ext_8_bit_mine = true;
				} else if (std.ascii.eqlIgnoreCase(reply_data, "SMTPUTF8")) {
					self.ext_smtp_utf8 = true;
				} else {
					if (reply_data.len > 4 and std.ascii.eqlIgnoreCase(reply_data[0..4], "AUTH")) {
						self.ext_auth = findSupportedAuth(reply_data[5..]);
					}
				}
				if (reply.more == false) {
					return;
				}
			}
		}

		pub fn auth(self: *Self) !void {
			if (self.config.username == null) {
				return;
			}

			const auth_mode = self.ext_auth orelse return error.NoSupportedAuth;
			switch (auth_mode) {
				.PLAIN => try self.authPlain(),
				.LOGIN => try self.authLogin(),
				.CRAM_MD5 => try self.authCRAMMD5(),
			}
		}

		pub fn from(self: *Self, frm: []const u8) !void {
			var buf = &self.buf;

			@memcpy(buf[0..11], "MAIL FROM:<");
			var pos: usize = 11;
			var end = pos + frm.len;
			@memcpy(buf[pos..end], frm);

			buf[end] = '>';
			pos = end + 1;

			if (self.ext_8_bit_mine) {
				end = pos + 14;
				@memcpy(buf[pos..end], " BODY=8BITMIME");
				pos = end;
			}

			if (self.ext_smtp_utf8) {
				end = pos + 13;
				@memcpy(buf[pos..end], " SMTPUTF8\r\n");
			} else {
				buf[pos] = '\r';
				buf[pos+1] = '\n';
				end = pos + 2;
			}

			try self.stream.writeAll(buf[0..end]);
			const code = (try self.reader.read()).code;
			if (code != 250) {
				return errorFromCode(code);
			}
		}

		pub fn to(self: *Self, recepients: []const []const u8) !void {
			var buf = &self.buf;
			var reader = &self.reader;
			const stream = self.stream;

			@memcpy(buf[0..9], "RCPT TO:<");
			for (recepients) |recepient| {
				const recepient_end = 9 + recepient.len;
				@memcpy(buf[9..recepient_end], recepient);

				const end = recepient_end + 3;
				@memcpy(buf[recepient_end..end], ">\r\n");
				try stream.writeAll(buf[0..end]);

				const code = (try reader.read()).code;
				if (code != 250 and code != 251) {
					return errorFromCode(code);
				}
			}
		}

		pub fn data(self: *Self, d: []const u8) !void {
			var reader = &self.reader;
			const stream = self.stream;

			{
				try stream.writeAll("DATA\r\n");
				const code = (try self.reader.read()).code;
				if (code != 354) {
					return errorFromCode(code);
				}
			}

			{
				try stream.writeAll(d);
				const code = (try reader.read()).code;
				if (code != 250) {
					return errorFromCode(code);
				}
			}
		}

		pub fn quit(self: *Self) !void {
			try self.stream.writeAll("QUIT\r\n");
		}

		fn authPlain(self: *Self) !void {
			const config = &self.config;
			const encoder = std.base64.standard.Encoder;

			// our final result has to fit in our 512 byte buffer + some command overhead
			// (+ a big of extra padding, incase...)
			var temp: [366]u8 = undefined;
			const plain = try std.fmt.bufPrint(&temp, "\x00{s}\x00{s}", .{config.username.?, config.password.?});
			const encoded_length = encoder.calcSize(plain.len);

			// "AUTH PLAIN " + \r + \n
			// 11            + 1  + 1   == 13
			var buf = self.buf[0..encoded_length + 13];
			@memcpy(buf[0..11], "AUTH PLAIN ");
			_ = encoder.encode(buf[11..], plain);

			buf[buf.len-2] = '\r';
			buf[buf.len-1] = '\n';

			try self.stream.writeAll(buf);
			const code = (try self.reader.read()).code;
			if (code != 235) {
				return errorFromCode(code);
			}
		}

		fn authLogin(self: *Self) !void {
			var buf = &self.buf;
			var reader = &self.reader;
			const config = &self.config;
			const encoder = std.base64.standard.Encoder;

			{
				@memcpy(buf[0..11], "AUTH LOGIN ");
				const encoded = encoder.encode(buf[11..], config.username.?);
				const end = 11 + encoded.len + 2;

				buf[end-2] = '\r';
				buf[end-1] = '\n';

				try self.stream.writeAll(buf);
				const reply = try reader.read();
				const code = reply.code;
				if (code != 334) {
					return errorFromCode(code);
				}

				// base64 encoded "Password"
				if (std.mem.eql(u8, reply.data, "TXktVXNlcm5hbWU=") == false) {
					return error.UnexpectedServerResponse;
				}
			}

			{
				const password = encoder.encode(buf, config.password.?);
				try self.stream.writeAll(password);

				const code = (try reader.read()).code;
				if (code != 334) {
					return errorFromCode(code);
				}
			}
		}

		fn authCRAMMD5(self: *Self) !void {
			const config = &self.config;

			try self.stream.writeAll("AUTH CRAM-MD5\r\n");

			const secret = blk: {
				const reply = try self.reader.read();
				const code = reply.code;
				if (code != 235) {
					return errorFromCode(code);
				}
				break :blk reply.data;
			};

			var temp: [16]u8 = undefined;
			std.crypto.auth.hmac.HmacMd5.create(&temp, config.password.?, secret);
			const hex = std.fmt.fmtSliceHexLower(&temp);

			const answer = try std.fmt.bufPrint(&self.buf, "{s} {s}\r\n", .{config.username.?, hex});
			try self.stream.writeAll(answer);
			const code = (try self.reader.read()).code;
			if (code != 235) {
				return errorFromCode(code);
			}
		}
	};
}

fn findSupportedAuth(data: []const u8) ?AuthMode {
	var it = std.mem.splitScalar(u8, data, ' ');
	while (it.next()) |value| {
		if (std.ascii.eqlIgnoreCase(value, "CRAM-MD5")) {
			return .CRAM_MD5;
		}
		if (std.ascii.eqlIgnoreCase(value, "PLAIN")) {
			return .PLAIN;
		}
		if (std.ascii.eqlIgnoreCase(value, "LOGIN")) {
			return .LOGIN;
		}
	}

	return null;
}

fn errorFromCode(code: u16) anyerror {
	return switch (code) {
		421 => error.ServiceNotAvailable,
		454 => error.TemporaryAuthFailure,
		450 => error.TemporaryMailboxNotAvailable,
		451 => error.ErrorInProcessing,
		452 => error.InsufficientStorage,
		455 => error.UnableToAccomodateParameter,
		500 => error.SyntaxErrorOrCommandNotFound,
		501 => error.InvalidParameter,
		502 => error.CommandNotImplemented,
		503 => error.InvalidCommandSequence,
		504 => error.ParameterNotImplemented,
		530 => error.AuthenticationRequired,
		534 => error.AuthMethodTooWeak,
		535 => error.InvalidCredentials,
		538 => error.EncryptionRequiredForAuthMethod,
		550 => error.MailboxNotAvailable,
		551 => error.UserNotLocal,
		552 => error.ExceededStorageAllocation,
		553 => error.MailboxNotAllowed,
		554 => error.TransactionFailed,
		555 => error.InvalidFromOrRecptParameter,
		else => if (code < 400) error.UnexpectedServerResponse else error.UnknownServerResponse,
	};
}

// const t = @import("t.zig");
