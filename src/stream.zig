const std = @import("std");

const net = std.net;
const posix = std.posix;
const tls = std.crypto.tls;

const Config = @import("smtp.zig").Config;
const Allocator = std.mem.Allocator;
const Bundle = std.crypto.Certificate.Bundle;

pub const Stream = struct {
    // not null if we own ca_bundle
    allocator: ?Allocator,

    // not null if we own this and have to manage/release it
    ca_bundle: ?Bundle,

    stream: net.Stream,
    tls_client: ?tls.Client,

    pub fn init(stream: net.Stream) Stream {
        return .{
            .ca_bundle = null,
            .allocator = null,
            .tls_client = null,
            .stream = stream,
        };
    }

    pub fn deinit(self: *Stream) void {
        if (self.tls_client) |*tls_client| {
            _ = tls_client.writeEnd(self.stream, "", true) catch {};
        }
        if (self.ca_bundle) |*ca_bundle| {
            ca_bundle.deinit(self.allocator.?);
        }
        self.stream.close();
    }

    pub fn toTLS(self: *Stream, config: *const Config) !void {
        const bundle = config.ca_bundle orelse blk: {
            const allocator = config.allocator orelse return error.AllocatorRequired;
            var b = Bundle{};
            try b.rescan(allocator);
            self.ca_bundle = b;
            self.allocator = allocator;
            break :blk b;
        };
        self.tls_client = try tls.Client.init(
            self.stream,
            .{ .ca = .{ .bundle = bundle }, .host = .{ .explicit = config.host } },
        );
    }

    pub fn readTimeout(self: *Stream, timeval: []const u8) !void {
        try posix.setsockopt(self.stream.handle, posix.SOL.SOCKET, posix.SO.RCVTIMEO, timeval);
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
