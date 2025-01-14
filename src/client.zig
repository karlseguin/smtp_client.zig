const std = @import("std");

const Config = @import("smtp.zig").Config;
const Reader = @import("reader.zig").Reader;
const Message = @import("message.zig").Message;

pub const AuthMode = enum {
    PLAIN,
    LOGIN,
    CRAM_MD5,
};

pub fn Client(comptime S: type) type {
    return struct {
        stream: S,

        reader: Reader(*S),

        // maximum reply length is 512
        buf: [512]u8 = undefined,

        random: std.Random.DefaultPrng,

        config: Config,

        // whether the server supports the 8BITMIME, SMTPUTF8 and AUTH extensions
        ext_8_bit_mine: bool = false,
        ext_smtp_utf8: bool = false,
        ext_auth: ?AuthMode = null,

        const Self = @This();

        pub fn init(stream: S, config: Config) !Self {
            var seed: u64 = undefined;
            try std.posix.getrandom(std.mem.asBytes(&seed));
            return .{
                .stream = stream,
                .config = config,
                .reader = undefined,
                .random = std.Random.DefaultPrng.init(seed),
            };
        }

        pub fn deinit(self: *Self) void {
            self.stream.deinit();
        }

        pub fn hello(self: *Self) !void {
            const config = &self.config;
            if (config.encryption == .tls) {
                try self.stream.toTLS(config);
            }

            self.reader = try Reader(*S).init(&self.stream, config.timeout);


            // server should send the first message
            const code = (try self.reader.read()).code;
            if (code != 220) {
                return errorFromCode(code);
            }
            return self._hello();
        }

        // When StartSSL is used, we send 2 hellos - one after we've upgraded
        // to TLS. This 2nd hello doesn't have to setup things (like the reader)
        // like the first one.
        fn _hello(self: *Self) !void {
            const buf = &self.buf;
            var reader = &self.reader;

            const msg = try std.fmt.bufPrint(buf, "EHLO {s}\r\n", .{self.config.local_name});
            try self.stream.directWrite(msg);

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

        pub fn startTLS(self: *Self) !void {
            var buf = &self.buf;
            @memcpy(buf[0..10], "STARTTLS\r\n");
            try self.stream.directWrite(buf[0..10]);
            const code = (try self.reader.read()).code;
            if (code != 220) {
                return errorFromCode(code);
            }
            try self.stream.toTLS(&self.config);
            return self._hello();
        }

        pub fn auth(self: *Self) !void {
            if (self.config.encryption == .start_tls) {
                try self.startTLS();
            }

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

        pub fn from(self: *Self, frm: Message.Address) !void {
            var buf = &self.buf;
            const address = frm.address;

            @memcpy(buf[0..11], "MAIL FROM:<");
            var pos: usize = 11;
            var end = pos + address.len;
            @memcpy(buf[pos..end], address);

            buf[end] = '>';
            pos = end + 1;

            if (self.ext_8_bit_mine) {
                end = pos + 14;
                @memcpy(buf[pos..end], " BODY=8BITMIME");
                pos = end;
            }

            if (self.ext_smtp_utf8) {
                end = pos + 11;
                @memcpy(buf[pos..end], " SMTPUTF8\r\n");
            } else {
                buf[pos] = '\r';
                buf[pos + 1] = '\n';
                end = pos + 2;
            }

            try self.stream.directWrite(buf[0..end]);
            const code = (try self.reader.read()).code;
            if (code != 250) {
                return errorFromCode(code);
            }
        }

        pub fn to(self: *Self, recepients: []const Message.Address) !void {
            var buf = &self.buf;
            var reader = &self.reader;
            const stream = &self.stream;

            @memcpy(buf[0..9], "RCPT TO:<");
            for (recepients) |recepient| {
                const address = recepient.address;
                const recepient_end = 9 + address.len;
                @memcpy(buf[9..recepient_end], address);

                const end = recepient_end + 3;
                @memcpy(buf[recepient_end..end], ">\r\n");
                try stream.directWrite(buf[0..end]);

                const code = (try reader.read()).code;
                if (code != 250 and code != 251) {
                    return errorFromCode(code);
                }
            }
        }

        pub fn data(self: *Self, d: []const u8) !void {
            try self.prepareFordata();
            try self.stream.directWrite(d);
            try self.verifyData();
        }

        pub fn sendMessage(self: *Self, message: Message) !void {
            try self.from(message.from);
            if (message.to) |message_to| {
                try self.to(message_to);
            }

            if (message.data) |d| {
                return self.data(d);
            }

            try self.prepareFordata();

            try message.write(&self.stream, self.random.random(), .{
                .message_id_host = self.config.message_id_host,
            });
            try self.stream.writeAll(".\r\n");
            try self.stream.flush();
            try self.verifyData();
        }

        pub fn quit(self: *Self) !void {
            try self.stream.directWrite("QUIT\r\n");
        }

        fn prepareFordata(self: *Self) !void {
            try self.stream.directWrite("DATA\r\n");
            const code = (try self.reader.read()).code;
            if (code != 354) {
                return errorFromCode(code);
            }
        }

        fn verifyData(self: *Self) !void {
            const code = (try self.reader.read()).code;
            if (code != 250) {
                return errorFromCode(code);
            }
        }

        fn authPlain(self: *Self) !void {
            if (self.config.encryption == .none) {
                return error.InsecureAuth;
            }

            const config = &self.config;
            const encoder = std.base64.standard.Encoder;

            // our final result has to fit in our 512 byte buffer + some command overhead
            // (+ a big of extra padding, incase...)
            var temp: [366]u8 = undefined;
            const plain = try std.fmt.bufPrint(&temp, "\x00{s}\x00{s}", .{ config.username.?, config.password.? });
            const encoded_length = encoder.calcSize(plain.len);

            // "AUTH PLAIN " + \r + \n
            // 11            + 1  + 1   == 13
            var buf = self.buf[0 .. encoded_length + 13];
            @memcpy(buf[0..11], "AUTH PLAIN ");
            _ = encoder.encode(buf[11..], plain);

            buf[buf.len - 2] = '\r';
            buf[buf.len - 1] = '\n';

            try self.stream.directWrite(buf);
            const code = (try self.reader.read()).code;
            if (code != 235) {
                return errorFromCode(code);
            }
        }

        fn authLogin(self: *Self) !void {
            if (self.config.encryption == .none) {
                return error.InsecureAuth;
            }

            var buf = &self.buf;
            var reader = &self.reader;
            const config = &self.config;
            const encoder = std.base64.standard.Encoder;

            {
                @memcpy(buf[0..11], "AUTH LOGIN ");
                const encoded = encoder.encode(buf[11..], config.username.?);
                const end = 11 + encoded.len + 2;

                buf[end - 2] = '\r';
                buf[end - 1] = '\n';

                try self.stream.directWrite(buf[0..end]);
            }

            {
                const reply = try reader.read();
                const code = reply.code;
                if (code != 334) {
                    return errorFromCode(code);
                }

                // base64 encoded "Password:"
                if (std.mem.eql(u8, reply.data, "UGFzc3dvcmQ6") == false) {
                    return error.UnexpectedServerResponse;
                }

                const password = config.password orelse return error.PasswordRequired;
                const encoded = encoder.encode(buf[0..], password);
                const end = encoded.len + 2;
                buf[end - 2] = '\r';
                buf[end - 1] = '\n';
                try self.stream.directWrite(buf[0..end]);
            }

            const code = (try reader.read()).code;
            if (code != 235) {
                return errorFromCode(code);
            }
        }

        fn authCRAMMD5(self: *Self) !void {
            const config = &self.config;

            try self.stream.directWrite("AUTH CRAM-MD5\r\n");

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

            const answer = try std.fmt.bufPrint(&self.buf, "{s} {s}\r\n", .{ config.username.?, hex });
            try self.stream.directWrite(answer);
            const code = (try self.reader.read()).code;
            if (code != 235) {
                return errorFromCode(code);
            }
        }
    };
}

fn findSupportedAuth(data: []const u8) ?AuthMode {
    var maybe_auth: ?AuthMode = null;
    var it = std.mem.splitScalar(u8, data, ' ');

    while (it.next()) |value| {
        if (std.ascii.eqlIgnoreCase(value, "CRAM-MD5")) {
            return .CRAM_MD5;
        }

        if (std.ascii.eqlIgnoreCase(value, "PLAIN") and maybe_auth == null) {
            maybe_auth = .PLAIN;
        }
        if (std.ascii.eqlIgnoreCase(value, "LOGIN")) {
            maybe_auth = .LOGIN;
        }
    }

    return maybe_auth;
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

const t = @import("t.zig");
test "client: helo" {
    const config = testConfig(.{});

    {
        // wrong server init reply
        var stream = t.Stream.init();
        stream.add("421 go away\r\n");
        var client = try TestClient.init(stream, config);
        defer client.deinit();

        try t.expectError(error.ServiceNotAvailable, client.hello());
    }

    {
        // wrong server reply
        var stream = t.Stream.init();
        stream.add("220\r\n502 nope\r\n");
        var client = try TestClient.init(stream, config);
        defer client.deinit();

        try t.expectError(error.CommandNotImplemented, client.hello());
    }

    {
        // no exstensions
        var stream = t.Stream.init();
        stream.add("220\r\n250\r\n");
        var client = try TestClient.init(stream, config);
        defer client.deinit();

        try client.hello();
        try t.expectEqual(false, client.ext_smtp_utf8);
        try t.expectEqual(false, client.ext_8_bit_mine);
        try t.expectEqual(null, client.ext_auth);
    }

    {
        // SMTPUTF8
        var stream = t.Stream.init();
        stream.add("220\r\n250-\r\n250 SMTPUTF8\r\n");
        var client = try TestClient.init(stream, config);
        defer client.deinit();

        try client.hello();
        try t.expectEqual(true, client.ext_smtp_utf8);
        try t.expectEqual(false, client.ext_8_bit_mine);
        try t.expectEqual(null, client.ext_auth);
    }

    {
        // 8BITMIME
        var stream = t.Stream.init();
        stream.add("220\r\n250-\r\n250 8BITMIME\r\n");
        var client = try TestClient.init(stream, config);
        defer client.deinit();

        try client.hello();
        try t.expectEqual(false, client.ext_smtp_utf8);
        try t.expectEqual(true, client.ext_8_bit_mine);
        try t.expectEqual(null, client.ext_auth);
    }

    {
        // CRAM-MD5
        var stream = t.Stream.init();
        stream.add("220\r\n250-\r\n250 AUTH LOGIN PLAIN CRAM-MD5\r\n");
        var client = try TestClient.init(stream, config);
        defer client.deinit();

        try client.hello();
        try t.expectEqual(false, client.ext_smtp_utf8);
        try t.expectEqual(false, client.ext_8_bit_mine);
        try t.expectEqual(.CRAM_MD5, client.ext_auth);
    }

    {
        // Login
        var stream = t.Stream.init();
        stream.add("220\r\n250-\r\n250 AUTH LOGIN PLAIN\r\n");
        var client = try TestClient.init(stream, config);
        defer client.deinit();

        try client.hello();
        try t.expectEqual(.LOGIN, client.ext_auth);
    }

    {
        // Plain
        var stream = t.Stream.init();
        stream.add("220\r\n250 Auth PlAIN\r\n");
        var client = try TestClient.init(stream, config);
        defer client.deinit();

        try client.hello();
        try t.expectEqual(.PLAIN, client.ext_auth);
    }
}

test "client: auth" {
    {
        // cannot use PLAIN auth with unencrypted connection
        var stream = t.Stream.init();
        stream.add("220\r\n250 AUTH PLAIN\r\n");
        var client = try TestClient.init(stream, testConfig(.{ .encryption = .none, .username = "leto" }));
        defer client.deinit();

        try client.hello();
        try t.expectError(error.InsecureAuth, client.auth());
    }

    {
        // cannot use LOGIN auth with unencrypted connection
        var stream = t.Stream.init();
        stream.add("220\r\n250 AUTH LOGIN\r\n");
        var client = try TestClient.init(stream, testConfig(.{ .encryption = .none, .username = "leto" }));
        defer client.deinit();

        try client.hello();
        try t.expectError(error.InsecureAuth, client.auth());
    }

    {
        // cannot use LOGIN auth with unencrypted connection
        var stream = t.Stream.init();
        stream.add("220\r\n250 AUTH LOGIN\r\n");
        stream.add("334 UGFzc3dvcmQ6\r\n");
        stream.add("235 Auth Successful\r\n");
        var client = try TestClient.init(stream, testConfig(.{ .username = "leto", .password = "ghanima", .encryption = .tls }));
        defer client.deinit();

        try client.hello();
        try client.auth();
        try client.quit();

        const received = client.stream.received();
        try t.expectEqual(4, received.len);
        try t.expectString("EHLO localhost\r\n", received[0]);
        try t.expectString("AUTH LOGIN bGV0bw==\r\n", received[1]);
        try t.expectString("Z2hhbmltYQ==\r\n", received[2]);
        try t.expectString("QUIT\r\n", received[3]);
    }

    {
        // wrong command
        var stream = t.Stream.init();
        stream.add("invalid data\r\n");
        var client = try TestClient.init(stream, testConfig(.{}));
        defer client.deinit();

        try t.expectError(error.SyntaxErrorOrCommandNotFound, client.hello());
    }
}

const TestClient = Client(t.Stream);
fn testConfig(config: anytype) Config {
    const T = @TypeOf(config);
    return .{
        .port = 1025,
        .host = "127.0.0.1",
        .encryption = if (@hasField(T, "encryption")) config.encryption else .none,
        .username = if (@hasField(T, "username")) config.username else null,
        .password = if (@hasField(T, "password")) config.password else null,
    };
}
