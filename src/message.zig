const std = @import("std");
const date = @import("date.zig");

pub const Message = struct {
    from: Address,
    to: ?[]const Address = null,
    cc: ?[]const Address = null,
    bcc: ?[]const Address = null,
    subject: ?[]const u8 = null,
    text_body: ?[]const u8 = null,
    html_body: ?[]const u8 = null,
    data: ?[]const u8 = null,
    timestamp: ?i64 = null,

    const WriteOpts = struct {
        message_id_host: ?[]const u8 = null,
    };

    pub fn write(self: *const Message, writer: anytype, random: std.Random, opts: WriteOpts) !void {
        {
            try writer.writeAll("From:");
            var line_length: usize = 5;
            try self.from.write(writer, &line_length);
            try writer.writeAll("\r\n");
        }

        try writeAddressList(writer, "To:", self.to);
        try writeAddressList(writer, "Cc:", self.cc);
        try writeAddressList(writer, "Bcc:", self.bcc);

        if (self.subject) |subject| {
            try writer.writeAll("Subject:");
            const ve = ValueEncoder.init(subject, false);
            try ve.write(writer);
            try writer.writeAll("\r\n");
        }

        try writer.writeAll("Date: ");
        try date.write(writer, self.timestamp orelse std.time.timestamp());
        try writer.writeAll("\r\nMIME-Version: 1.0\r\n");
        try writer.writeAll("Message-ID: <");
        try writeMessageId(writer, opts.message_id_host, self.from.address, random);
        try writer.writeAll(">\r\n");

        if (self.html_body) |html_body| {
            if (self.text_body) |text_body| {
                const boundary = createBoundary(random);
                try writer.writeAll("Content-Type: multipart/alternative;\r\n boundary=\"");
                try writer.writeAll(boundary[2..]);
                try writer.writeAll("\"\r\n\r\n");

                try writer.writeAll(&boundary);
                try writer.writeAll("\r\nContent-Type: text/plain; charset=utf-8\r\n");
                try writeBody(writer, text_body);

                try writer.writeAll(&boundary);
                try writer.writeAll("\r\nContent-Type: text/html; charset=utf-8\r\n");
                try writeBody(writer, html_body);
                try writer.writeAll(&boundary);
                try writer.writeAll("--\r\n");
                return;
            }

            try writer.writeAll("Content-Type: text/html; charset=utf-8\r\n");
            try writeBody(writer, html_body);
            return;
        }
        try writer.writeAll("Content-Type: text/plain; charset=utf-8\r\n");
        if (self.text_body) |text_body| {
            try writeBody(writer, text_body);
        }
    }

    pub const Address = struct {
        name: ?[]const u8 = null,
        address: []const u8,

        pub fn write(self: *const Address, writer: anytype, line_length: *usize) !void {
            // +2 for the <> around the address and +1 for the the leading space
            var to_write_length = self.address.len + 3;

            var name_encoder: ?ValueEncoder = null;
            if (self.name) |name| {
                name_encoder = ValueEncoder.init(name, true);
                // +1 for the space before the <
                to_write_length += name_encoder.?.encoded_len + 1;
            }

            const current_line_length = line_length.*;
            if (to_write_length + current_line_length > 76) {
                try writer.writeAll("\r\n");
                line_length.* = to_write_length;
            } else {
                line_length.* = current_line_length + to_write_length;
            }

            if (name_encoder) |ne| {
                try ne.write(writer);
            }
            try writer.writeAll(" <");
            try writer.writeAll(self.address);
            try writer.writeByte('>');
        }
    };
};

fn writeAddressList(writer: anytype, comptime field_name: []const u8, address_list: ?[]const Message.Address) !void {
    const list = address_list orelse return;
    if (list.len == 0) {
        return;
    }

    try writer.writeAll(field_name);
    var line_length: usize = field_name.len;
    try list[0].write(writer, &line_length);
    for (list[1..]) |to| {
        line_length += 1;
        try writer.writeByte(',');
        try to.write(writer, &line_length);
    }
    try writer.writeAll("\r\n");
}

fn createBoundary(random: std.Random) [36]u8 {
    var boundary: [36]u8 = undefined;
    @memcpy(boundary[0..4], "----");
    randomHex(16, boundary[4..], random);
    return boundary;
}

fn writeMessageId(writer: anytype, configured_host: ?[]const u8, from: []const u8, random: std.Random) !void {
    const host = configured_host orelse blk: {
        const i = std.mem.indexOfScalar(u8, from, '@') orelse break :blk "localhost";
        break :blk from[i + 1 ..];
    };
    var id: [32]u8 = undefined;
    randomHex(16, &id, random);
    try writer.writeAll(&id);
    try writer.writeByte('@');
    return writer.writeAll(host);
}

fn randomHex(size: comptime_int, into: []u8, random: std.Random) void {
    std.debug.assert(into.len == size * 2);

    var buf: [size]u8 = undefined;
    random.bytes(&buf);

    const charset = "0123456789abcdef";
    for (buf, 0..) |b, i| {
        into[i * 2] = charset[b >> 4];
        into[i * 2 + 1] = charset[b & 15];
    }
}

fn writeBody(writer: anytype, data: []const u8) !void {
    var encoding_writer = Writer(@TypeOf(writer), 76).from(writer, data);
    try encoding_writer.writeTransferEncodingHeader();
    try encoding_writer.write(data);
    return writer.writeAll("\r\n");
}

fn Writer(comptime T: type, comptime max_line_length: usize) type {
    return union(enum) {
        b64: Base64Writer(T, max_line_length),
        qp: QuotedPrintableWriter(T, max_line_length),

        const Self = @This();
        fn from(writer: T, data: []const u8) Self {
            if (hasHighBit(data)) {
                return .{ .b64 = Base64Writer(T, max_line_length){ .w = writer } };
            }
            return .{ .qp = QuotedPrintableWriter(T, max_line_length){ .w = writer } };
        }

        fn write(self: *Self, data: []const u8) !void {
            switch (self.*) {
                .b64 => |*w| return w.write(data),
                .qp => |*w| return w.write(data),
            }
        }

        fn writeTransferEncodingHeader(self: Self) !void {
            switch (self) {
                .b64 => |w| return w.w.writeAll("Content-Transfer-Encoding: base64\r\n\r\n"),
                .qp => |w| return w.w.writeAll("Content-Transfer-Encoding: quoted-printable\r\n\r\n"),
            }
        }
    };
}

fn Base64Writer(comptime T: type, comptime max_line_length: usize) type {
    return struct {
        w: T,
        line_length: usize = 0,

        const Self = @This();

        fn write(self: *Self, data: []const u8) !void {
            try std.base64.standard.Encoder.encodeWriter(self, data);
        }

        // called by std.base64
        pub fn writeAll(self: *Self, data: []const u8) !void {
            const w = self.w;

            const line_length = self.line_length;
            const line_space = max_line_length - line_length;
            if (line_space >= data.len) {
                self.line_length = line_length + data.len;
                return w.writeAll(data);
            }

            try w.writeAll(data[0..line_space]);
            try w.writeAll("\r\n");
            try w.writeAll(data[line_space..]);
            self.line_length = data.len - line_space;
        }
    };
}

fn QuotedPrintableWriter(comptime T: type, comptime max_line_length: usize) type {
    const end_column = max_line_length - 1;
    return struct {
        w: T,
        line_length: usize = 0,

        const Self = @This();

        fn write(self: *Self, data: []const u8) !void {
            const w = self.w;
            const charset = "0123456789ABCDEF";

            var line_length = self.line_length;
            defer self.line_length = line_length;

            for (data) |b| {
                if (b != '=' and b != '.' and ((b >= 33 and b <= 126) or b == ' ' or b == '\t')) {
                    if (line_length == end_column) {
                        try w.writeAll("=\r\n");
                        line_length = 1;
                    } else {
                        line_length += 1;
                    }
                    try w.writeByte(b);
                } else {
                    const remaining = max_line_length - line_length;
                    const encoded = [_]u8{ '=', charset[b >> 4], charset[b & 15] };
                    if (remaining < 4) {
                        try w.writeAll("=\r\n");
                        line_length = 3;
                    } else {
                        line_length += 3;
                    }
                    try w.writeAll(&encoded);
                }
            }
        }
    };
}

const ValueEncoder = struct {
    value: []const u8,
    encoder: Encoder,
    encoded_len: usize,

    const Encoder = enum {
        none,
        base64,
        quoted,
    };

    // 10 bytes of overhead for the =?UTF-8?B? prefix
    // 2 bytes overhead for the ?= suffix
    const ENCODING_OVERHEAD = 12;

    fn init(value: []const u8, allow_quoted: bool) ValueEncoder {
        var base64 = false;
        var needs_quote = false;
        var double_quote_count: usize = 0;

        for (value) |b| {
            switch (b) {
                0...31, 127...255 => {
                    base64 = true;
                    break;
                },
                'a'...'z', 'A'...'Z', '0'...'9', ' ' => {},
                '"' => {
                    if (allow_quoted == false) {
                        base64 = true;
                        break;
                    }
                    needs_quote = true;
                    double_quote_count += 1;
                },
                else => {
                    if (allow_quoted == false) {
                        base64 = true;
                        break;
                    }
                    needs_quote = true;
                },
            }
        }

        if (base64) {
            return .{
                .value = value,
                .encoder = .base64,
                .encoded_len = ENCODING_OVERHEAD + std.base64.standard.Encoder.calcSize(value.len),
            };
        }

        var encoded_len = value.len + double_quote_count;
        if (needs_quote) {
            encoded_len += 2;
        }

        return .{
            .value = value,
            .encoded_len = encoded_len,
            .encoder = if (needs_quote) .quoted else .none,
        };
    }

    fn write(self: *const ValueEncoder, writer: anytype) !void {
        const value = self.value;
        switch (self.encoder) {
            .none => {
                try writer.writeByte(' ');
                return writer.writeAll(value);
            },
            .base64 => {
                try writer.writeAll(" =?UTF-8?B?");
                try std.base64.standard.Encoder.encodeWriter(writer, value);
                return writer.writeAll("?=");
            },
            .quoted => {
                try writer.writeAll(" \"");
                if (self.encoded_len == value.len + 2) {
                    // if this is true, then all we need to do is write the value
                    // as-is, between quotes.
                    try writer.writeAll(value);
                } else {
                    for (value) |b| {
                        if (b == '"') {
                            try writer.writeByte('\\');
                        }
                        try writer.writeByte(b);
                    }
                }
                return writer.writeByte('"');
            },
        }
    }
};

// TODO: surely zig's std should expose something like this?
const backend_supports_vectors = switch (@import("builtin").zig_backend) {
    .stage2_llvm, .stage2_c => true,
    else => false,
};

// I know, I know, this results in base64 being used in cases where quoted
// printable would be more efficient.
fn hasHighBit(value: []const u8) bool {
    var remaining = value;
    if (comptime backend_supports_vectors) {
        if (comptime std.simd.suggestVectorLength(u8)) |vector_len| {
            while (remaining.len > vector_len) {
                const block: @Vector(vector_len, u8) = remaining[0..vector_len].*;
                if (@reduce(.Max, block) > 127) {
                    return true;
                }
                remaining = remaining[vector_len..];
            }
        }
    }

    if (std.mem.max(u8, remaining) > 127) {
        return true;
    }

    return false;
}

const t = @import("t.zig");

test "Message: address simple" {
    try testWriteMessage(.{
        .from = .{ .address = "leto@example.com" },
        .to = &.{.{ .address = "ghanima@example.com" }},
    }, "From: <leto@example.com>\r\n" ++
        "To: <ghanima@example.com>\r\n" ++
        "Date: 13 Jan 2025 03:00:38 +0000\r\n" ++
        "MIME-Version: 1.0\r\n" ++
        "Message-ID: <00000000000000000000000000000000@example.com>\r\n" ++
        "Content-Type: text/plain; charset=utf-8\r\n", .{});

    try testWriteMessage(.{
        .from = .{ .address = "leto@example.com", .name = "Leto" },
        .to = &.{.{ .address = "ghanima@example.com", .name = "Ghanima" }},
    }, "From: Leto <leto@example.com>\r\n" ++
        "To: Ghanima <ghanima@example.com>\r\n" ++
        "Date: 13 Jan 2025 03:00:38 +0000\r\n" ++
        "MIME-Version: 1.0\r\n" ++
        "Message-ID: <00000000000000000000000000000000@example.com>\r\n" ++
        "Content-Type: text/plain; charset=utf-8\r\n", .{});

    try testWriteMessage(.{
        .from = .{ .address = "from@example.org", .name = "Leto" },
        .to = &.{ .{ .address = "ghanima@example.com", .name = "Ghanima" }, .{ .address = "paul@example.com" } },
    }, "From: Leto <from@example.org>\r\n" ++
        "To: Ghanima <ghanima@example.com>, <paul@example.com>\r\n" ++
        "Date: 13 Jan 2025 03:00:38 +0000\r\n" ++
        "MIME-Version: 1.0\r\n" ++
        "Message-ID: <00000000000000000000000000000000@example.org>\r\n" ++
        "Content-Type: text/plain; charset=utf-8\r\n", .{});

    try testWriteMessage(.{
        .from = .{ .address = "from@example.com", .name = "Leto" },
        .to = &.{ .{ .address = "ghanima@example.com", .name = "Ghanima" }, .{ .address = "paul@example.com", .name = "Paul" } },
    }, "From: Leto <from@example.com>\r\n" ++
        "To: Ghanima <ghanima@example.com>, Paul <paul@example.com>\r\n" ++
        "Date: 13 Jan 2025 03:00:38 +0000\r\n" ++
        "MIME-Version: 1.0\r\n" ++
        "Message-ID: <00000000000000000000000000000000@example.com>\r\n" ++
        "Content-Type: text/plain; charset=utf-8\r\n", .{});
}

test "Message: address encoding" {
    try testWriteMessage(.{
        .from = .{ .address = "leto@example.com", .name = "Mr. Leto" },
        .to = &.{.{ .address = "ghanima@example.com" }},
    }, "From: \"Mr. Leto\" <leto@example.com>\r\n" ++
        "To: <ghanima@example.com>\r\n" ++
        "Date: 13 Jan 2025 03:00:38 +0000\r\n" ++
        "MIME-Version: 1.0\r\n" ++
        "Message-ID: <00000000000000000000000000000000@example.com>\r\n" ++
        "Content-Type: text/plain; charset=utf-8\r\n", .{});

    try testWriteMessage(.{
        .from = .{ .address = "leto@example.com", .name = "Mr. \"Leto\"" },
        .to = &.{.{ .address = "ghanima@example.com" }},
    }, "From: \"Mr. \\\"Leto\\\"\" <leto@example.com>\r\n" ++
        "To: <ghanima@example.com>\r\n" ++
        "Date: 13 Jan 2025 03:00:38 +0000\r\n" ++
        "MIME-Version: 1.0\r\n" ++
        "Message-ID: <00000000000000000000000000000000@example.com>\r\n" ++
        "Content-Type: text/plain; charset=utf-8\r\n", .{});

    try testWriteMessage(.{
        .from = .{ .address = "c@example.com", .name = "✔" },
        .to = &.{.{ .address = "ghost@example.com", .name = "Mr. 👻" }},
    }, "From: =?UTF-8?B?4pyU?= <c@example.com>\r\n" ++
        "To: =?UTF-8?B?TXIuIPCfkbs=?= <ghost@example.com>\r\n" ++
        "Date: 13 Jan 2025 03:00:38 +0000\r\n" ++
        "MIME-Version: 1.0\r\n" ++
        "Message-ID: <00000000000000000000000000000000@example.com>\r\n" ++
        "Content-Type: text/plain; charset=utf-8\r\n", .{});
}

test "Message: address folding" {
    try testWriteMessage(.{
        .from = .{ .address = "leto@example.com" },
        .to = &.{.{ .address = "a" ** 100 ++ "@example.com" }},
    }, "From: <leto@example.com>\r\n" ++
        "To:\r\n <" ++ "a" ** 100 ++ "@example.com>\r\n" ++
        "Date: 13 Jan 2025 03:00:38 +0000\r\n" ++
        "MIME-Version: 1.0\r\n" ++
        "Message-ID: <00000000000000000000000000000000@example.com>\r\n" ++
        "Content-Type: text/plain; charset=utf-8\r\n", .{});

    try testWriteMessage(.{
        .from = .{ .address = "leto@example.com" },
        .to = &.{ .{ .address = "ghanima@example.com" }, .{ .address = "a" ** 100 ++ "@example.com", .name = "Mr A" } },
    }, "From: <leto@example.com>\r\n" ++
        "To: <ghanima@example.com>,\r\n Mr A <" ++ "a" ** 100 ++ "@example.com>\r\n" ++
        "Date: 13 Jan 2025 03:00:38 +0000\r\n" ++
        "MIME-Version: 1.0\r\n" ++
        "Message-ID: <00000000000000000000000000000000@example.com>\r\n" ++
        "Content-Type: text/plain; charset=utf-8\r\n", .{});
}

test "Message: subject" {
    try testWriteMessage(.{ .from = .{ .address = "a" }, .to = &.{.{ .address = "b" }}, .subject = "Hello" }, "From: <a>\r\n" ++
        "To: <b>\r\n" ++
        "Subject: Hello\r\n" ++
        "Date: 13 Jan 2025 03:00:38 +0000\r\n" ++
        "MIME-Version: 1.0\r\n" ++
        "Message-ID: <00000000000000000000000000000000@localhost>\r\n" ++
        "Content-Type: text/plain; charset=utf-8\r\n", .{});

    try testWriteMessage(.{ .from = .{ .address = "a" }, .to = &.{.{ .address = "b" }}, .subject = "Hello.You" }, "From: <a>\r\n" ++
        "To: <b>\r\n" ++
        "Subject: =?UTF-8?B?SGVsbG8uWW91?=\r\n" ++
        "Date: 13 Jan 2025 03:00:38 +0000\r\n" ++
        "MIME-Version: 1.0\r\n" ++
        "Message-ID: <00000000000000000000000000000000@localhost>\r\n" ++
        "Content-Type: text/plain; charset=utf-8\r\n", .{});

    try testWriteMessage(.{ .from = .{ .address = "a" }, .to = &.{.{ .address = "b" }}, .subject = "Enjoy Better Performance ✔✔✔" }, "From: <a>\r\n" ++
        "To: <b>\r\n" ++
        "Subject: =?UTF-8?B?RW5qb3kgQmV0dGVyIFBlcmZvcm1hbmNlIOKclOKclOKclA==?=\r\n" ++
        "Date: 13 Jan 2025 03:00:38 +0000\r\n" ++
        "MIME-Version: 1.0\r\n" ++
        "Message-ID: <00000000000000000000000000000000@localhost>\r\n" ++
        "Content-Type: text/plain; charset=utf-8\r\n", .{});
}

test "Message: body quoted-printable" {
    const common_qp_prefix = "From: <a>\r\n" ++
        "To: <b>\r\n" ++
        "Date: 13 Jan 2025 03:00:38 +0000\r\n" ++
        "MIME-Version: 1.0\r\n" ++
        "Message-ID: <00000000000000000000000000000000@localhost>\r\n" ++
        "Content-Type: text/plain; charset=utf-8\r\n" ++
        "Content-Transfer-Encoding: quoted-printable\r\n\r\n";

    try testWriteMessage(.{ .from = .{ .address = "a" }, .to = &.{.{ .address = "b" }}, .text_body = "Hello\r\n." }, common_qp_prefix ++ "Hello=0D=0A=2E\r\n", .{});

    try testWriteMessage(.{ .from = .{ .address = "a" }, .to = &.{.{ .address = "b" }}, .text_body = "a" ** 76 }, common_qp_prefix ++ "a" ** 75 ++ "=\r\na\r\n", .{});

    try testWriteMessage(.{
        .from = .{ .address = "a" },
        .to = &.{.{ .address = "b" }},
        .text_body = "Hello==World",
    }, common_qp_prefix ++ "Hello=3D=3DWorld\r\n", .{});

    try testWriteMessage(.{ .from = .{ .address = "a" }, .to = &.{.{ .address = "b" }}, .text_body = "a" ** 75 ++ "\tb" }, common_qp_prefix ++ "a" ** 75 ++ "=\r\n\tb\r\n", .{});

    try testWriteMessage(.{
        .from = .{ .address = "a" },
        .to = &.{.{ .address = "b" }},
        .text_body = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  12313    \x14 999",
    }, common_qp_prefix ++ "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  12313    =14 =\r\n999\r\n", .{});

    try testWriteMessage(.{
        .from = .{ .address = "a" },
        .to = &.{.{ .address = "b" }},
        .text_body = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  12313     \x14 999",
    }, common_qp_prefix ++ "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  12313     =14=\r\n 999\r\n", .{});

    try testWriteMessage(.{
        .from = .{ .address = "a" },
        .to = &.{.{ .address = "b" }},
        .text_body = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  12313      \x14 999",
    }, common_qp_prefix ++ "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  12313      =\r\n=14 999\r\n", .{});

    try testWriteMessage(.{ .from = .{ .address = "a" }, .to = &.{.{ .address = "b" }}, .text_body = "a" ** 300 }, common_qp_prefix ++ "a" ** 75 ++ "=\r\n" ++ "a" ** 75 ++ "=\r\n" ++ "a" ** 75 ++ "=\r\n" ++ "a" ** 75 ++ "\r\n", .{});
}

test "Message: body base64" {
    const common_b64_prefix = "From: <a>\r\n" ++
        "To: <b>\r\n" ++
        "Date: 13 Jan 2025 03:00:38 +0000\r\n" ++
        "MIME-Version: 1.0\r\n" ++
        "Message-ID: <00000000000000000000000000000000@localhost>\r\n" ++
        "Content-Type: text/plain; charset=utf-8\r\n" ++
        "Content-Transfer-Encoding: base64\r\n\r\n";

    try testWriteMessage(.{
        .from = .{ .address = "a" },
        .to = &.{.{ .address = "b" }},
        .text_body = "ƒ",
    }, common_b64_prefix ++ "xpI=\r\n", .{});

    try testWriteMessage(.{
        .from = .{ .address = "a" },
        .to = &.{.{ .address = "b" }},
        .text_body = "ƒ" ** 28,
    }, common_b64_prefix ++ "xpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpI=\r\n", .{});

    try testWriteMessage(.{
        .from = .{ .address = "a" },
        .to = &.{.{ .address = "b" }},
        .text_body = "ƒ" ** 29,
    }, common_b64_prefix ++ "xpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLG\r\nkg==\r\n", .{});

    try testWriteMessage(.{
        .from = .{ .address = "a" },
        .to = &.{.{ .address = "b" }},
        .text_body = "ƒ" ** 200,
    }, common_b64_prefix ++
        "xpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLG\r\n" ++
        "ksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaS\r\n" ++
        "xpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLG\r\n" ++
        "ksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaS\r\n" ++
        "xpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLG\r\n" ++
        "ksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaS\r\n" ++
        "xpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLGksaSxpLG\r\n" ++
        "kg==\r\n", .{});
}

test "Message: body html" {
    try testWriteMessage(.{
        .from = .{ .address = "a" },
        .to = &.{.{ .address = "b" }},
        .html_body = "<b>ƒ</b>",
    }, "From: <a>\r\n" ++
        "To: <b>\r\n" ++
        "Date: 13 Jan 2025 03:00:38 +0000\r\n" ++
        "MIME-Version: 1.0\r\n" ++
        "Message-ID: <00000000000000000000000000000000@localhost>\r\n" ++
        "Content-Type: text/html; charset=utf-8\r\n" ++
        "Content-Transfer-Encoding: base64\r\n\r\n" ++
        "PGI+xpI8L2I+\r\n", .{});

    try testWriteMessage(.{
        .from = .{ .address = "a" },
        .to = &.{.{ .address = "b" }},
        .html_body = "<b>h=i</b>",
    }, "From: <a>\r\n" ++
        "To: <b>\r\n" ++
        "Date: 13 Jan 2025 03:00:38 +0000\r\n" ++
        "MIME-Version: 1.0\r\n" ++
        "Message-ID: <00000000000000000000000000000000@localhost>\r\n" ++
        "Content-Type: text/html; charset=utf-8\r\n" ++
        "Content-Transfer-Encoding: quoted-printable\r\n\r\n" ++
        "<b>h=3Di</b>\r\n", .{});
}

test "Message: body multipart" {
    try testWriteMessage(.{
        .from = .{ .address = "a" },
        .to = &.{.{ .address = "b" }},
        .text_body = "hello world!",
        .html_body = "<b>ƒ</b>",
    }, "From: <a>\r\n" ++
        "To: <b>\r\n" ++
        "Date: 13 Jan 2025 03:00:38 +0000\r\n" ++
        "MIME-Version: 1.0\r\n" ++
        "Message-ID: <00000000000000000000000000000000@localhost>\r\n" ++
        "Content-Type: multipart/alternative;\r\n" ++
        " boundary=\"--00000000000000000000000000000000\"\r\n" ++
        "\r\n" ++
        "----00000000000000000000000000000000\r\n" ++
        "Content-Type: text/plain; charset=utf-8\r\n" ++
        "Content-Transfer-Encoding: quoted-printable\r\n" ++
        "\r\n" ++
        "hello world!\r\n" ++
        "----00000000000000000000000000000000\r\n" ++
        "Content-Type: text/html; charset=utf-8\r\n" ++
        "Content-Transfer-Encoding: base64\r\n" ++
        "\r\n" ++
        "PGI+xpI8L2I+\r\n" ++
        "----00000000000000000000000000000000--\r\n", .{});
}

test "Message: message-id" {
    try testWriteMessageContains(.{
        .from = .{ .address = "leto@example.com" },
        .to = &.{.{ .address = "b" }},
    }, "\r\nMessage-ID: <00000000000000000000000000000000@fixed.example.org>\r\n", .{ .message_id_host = "fixed.example.org" });

    try testWriteMessageContains(.{
        .from = .{ .address = "leto@example.com" },
        .to = &.{.{ .address = "b" }},
    }, "\r\nMessage-ID: <00000000000000000000000000000000@example.com>\r\n", .{});
}

fn testWriteMessage(m: Message, expected: []const u8, opts: Message.WriteOpts) !void {
    var aw: std.Io.Writer.Allocating = .init(t.allocator);
    defer aw.deinit();

    var message_copy = m;
    if (m.timestamp == null) {
        message_copy.timestamp = 1736737238;
    }
    try message_copy.write(&aw.writer, t.random(), opts);
    const output = try aw.toOwnedSlice();
    defer t.allocator.free(output);
    try t.expectString(expected, output);
}

fn testWriteMessageContains(m: Message, contains: []const u8, opts: Message.WriteOpts) !void {
    var aw: std.Io.Writer.Allocating = .init(t.allocator);
    defer aw.deinit();

    try m.write(&aw.writer, t.random(), opts);
    const output = try aw.toOwnedSlice();
    defer t.allocator.free(output);
    if (std.mem.indexOf(u8, output, contains) == null) {
        std.debug.print("Expected the message to contain: '{s}'.\n\nThe Full message is\n============\n{s}\n============\n", .{ contains, output });
        return error.NotContained;
    }
}
