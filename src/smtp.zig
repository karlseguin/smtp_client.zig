const std = @import("std");

const Allocator = std.mem.Allocator;
const Bundle = std.crypto.Certificate.Bundle;

pub const client = @import("client.zig");
pub const Client = client.Client(Stream);
pub const Stream = @import("stream.zig").Stream;

pub const Encryption = enum {
    insecure,
    none,
    tls,
    start_tls,
};

pub const Config = struct {
    port: u16 = 25,
    host: []const u8,
    ca_bundle: ?Bundle = null,
    timeout: i32 = 10_000,
    encryption: Encryption = .tls,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
    local_name: []const u8 = "localhost",
    allocator: ?Allocator = null,
};

pub const Message = struct {
    to: []const []const u8,
    from: []const u8,
    data: []const u8,
};

pub fn connect(config: Config) !Client {
    const allocator = config.allocator orelse return error.AllocatorRequired;
    const stream = Stream.init(try std.net.tcpConnectToHost(allocator, config.host, config.port));
    return Client.init(stream, config);
}

pub fn connectTo(address: std.net.Address, config: Config) !Client {
    const stream = Stream.init(try std.net.tcpConnectToAddress(address));
    return Client.init(stream, config);
}

pub fn send(message: Message, config: Config) !void {
    var sent: usize = 0;
    return sendAll(&[_]Message{message}, config, &sent);
}

pub fn sendAll(messages: []const Message, config: Config, sent: *usize) !void {
    var c = try connect(config);
    defer c.deinit();
    try oneShot(&c, messages, sent);
}

pub fn sendTo(address: std.net.Address, message: Message, config: Config) !void {
    var sent: usize = 0;
    return sendAllTo(address, &[_]Message{message}, config, &sent);
}

pub fn sendAllTo(address: std.net.Address, messages: []const Message, config: Config, sent: *usize) !void {
    var c = try connectTo(address, config);
    defer c.deinit();
    try oneShot(&c, messages, sent);
}

// client is anytype for testing. It's a client.Client(net.Stream) during normal
// execution, but a client.Client(*t.MockServer) during tests.
fn oneShot(c: anytype, messages: []const Message, sent: *usize) !void {
    defer c.quit() catch {};

    try c.hello();
    try c.auth();

    for (messages) |message| {
        try c.from(message.from);
        try c.to(message.to);
        try c.data(message.data);
        sent.* += 1;
    }
}

const t = @import("t.zig");

test {
    std.testing.refAllDecls(@This());
}

test "send: unencrypted single to" {
    const ms = t.MockServer.init(&.{
        .{ .req = "EHLO localhost\r\n", .res = "250\r\n" },
        .{ .req = "MAIL FROM:<from-user@localhost.local>\r\n", .res = "250\r\n" },
        .{ .req = "RCPT TO:<to-user@localhost.local>\r\n", .res = "250\r\n" },
        .{ .req = "DATA\r\n", .res = "354\r\n" },
        .{ .req = "This is the data\r\n.\r\n", .res = "250\r\n" },
        .{ .req = "QUIT\r\n", .res = null },
    });

    var sent: usize = 0;
    var c = client.Client(t.MockServer).init(ms, .{
        .port = 0,
        .host = "localhost",
    });

    try oneShot(&c, &.{.{
        .from = "from-user@localhost.local",
        .to = &.{"to-user@localhost.local"},
        .data = "This is the data\r\n.\r\n",
    }}, &sent);
    try t.expectEqual(1, sent);
}

test "send: scram-md5 + multiple to" {
    const ms = t.MockServer.init(&.{
        .{ .req = "EHLO localhost\r\n", .res = "250-Ok\r\n250 AUTH Plain cram-MD5\r\n" },
        .{ .req = "AUTH CRAM-MD5\r\n", .res = "235 my secret\r\n" },
        .{ .req = "leto 9103a6f589ce8c5a3b775dd878b5ac3a\r\n", .res = "235 my secret\r\n" },
        .{ .req = "MAIL FROM:<from-user@localhost.local>\r\n", .res = "250\r\n" },
        .{ .req = "RCPT TO:<to-user1@localhost.local>\r\n", .res = "250\r\n" },
        .{ .req = "RCPT TO:<to-user2@localhost.local>\r\n", .res = "250\r\n" },
        .{ .req = "DATA\r\n", .res = "354\r\n" },
        .{ .req = "hi\r\n", .res = "250\r\n" },
        .{ .req = "QUIT\r\n", .res = null },
    });

    var sent: usize = 0;
    var c = client.Client(t.MockServer).init(ms, .{
        .port = 0,
        .host = "localhost",
        .username = "leto",
        .password = "ghanima",
    });

    try oneShot(&c, &.{.{
        .from = "from-user@localhost.local",
        .to = &.{ "to-user1@localhost.local", "to-user2@localhost.local" },
        .data = "hi\r\n",
    }}, &sent);
    try t.expectEqual(1, sent);
}

test "sendAll: success" {
    const ms = t.MockServer.init(&.{
        .{ .req = "EHLO localhost\r\n", .res = "250 Ok\r\n" },
        .{ .req = "MAIL FROM:<from-user1@localhost.local>\r\n", .res = "250\r\n" },
        .{ .req = "RCPT TO:<to-user1@localhost.local>\r\n", .res = "250\r\n" },
        .{ .req = "DATA\r\n", .res = "354\r\n" },
        .{ .req = "hi1\r\n", .res = "250\r\n" },
        .{ .req = "MAIL FROM:<from-user2@localhost.local>\r\n", .res = "250\r\n" },
        .{ .req = "RCPT TO:<to-user2@localhost.local>\r\n", .res = "250\r\n" },
        .{ .req = "DATA\r\n", .res = "354\r\n" },
        .{ .req = "hi2\r\n", .res = "250\r\n" },
        .{ .req = "QUIT\r\n", .res = null },
    });

    var sent: usize = 0;
    var c = client.Client(t.MockServer).init(ms, .{
        .port = 0,
        .host = "localhost",
    });

    try oneShot(&c, &.{
        .{
            .from = "from-user1@localhost.local",
            .to = &.{"to-user1@localhost.local"},
            .data = "hi1\r\n",
        },
        .{
            .from = "from-user2@localhost.local",
            .to = &.{"to-user2@localhost.local"},
            .data = "hi2\r\n",
        },
    }, &sent);

    try t.expectEqual(2, sent);
}

test "sendAll: partial" {
    const ms = t.MockServer.init(&.{
        .{ .req = "EHLO localhost\r\n", .res = "250 Ok\r\n" },
        .{ .req = "MAIL FROM:<from-user1@localhost.local>\r\n", .res = "250\r\n" },
        .{ .req = "RCPT TO:<to-user1@localhost.local>\r\n", .res = "250\r\n" },
        .{ .req = "DATA\r\n", .res = "354\r\n" },
        .{ .req = "hi1\r\n", .res = "250\r\n" },
        .{ .req = "MAIL FROM:<from-user2@localhost.local>\r\n", .res = "550\r\n" },
        .{ .req = "QUIT\r\n", .res = null },
    });

    var sent: usize = 0;
    var c = client.Client(t.MockServer).init(ms, .{
        .port = 0,
        .host = "localhost",
    });
    const err = oneShot(&c, &.{
        .{
            .from = "from-user1@localhost.local",
            .to = &.{"to-user1@localhost.local"},
            .data = "hi1\r\n",
        },
        .{
            .from = "from-user2@localhost.local",
            .to = &.{"to-user2@localhost.local"},
            .data = "hi2\r\n",
        },
    }, &sent);

    try t.expectEqual(error.MailboxNotAvailable, err);
    try t.expectEqual(1, sent);
}
