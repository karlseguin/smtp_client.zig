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

    end: usize = 0,
    buf: [4096]u8 = undefined,

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
        var end = self.end;

        if (end + data.len > self.buf.len) {
            try self.flush();
            end = 0;
            if (data.len > self.buf.len) {
                return self.directWrite(data);
            }
        }

        const new_end = end + data.len;
        @memcpy(self.buf[end..new_end], data);
        self.end = new_end;
    }

    pub fn writeByte(self: *Stream, data: u8) !void {
        var end = self.end;

        if (end == self.buf.len) {
            try self.flush();
            end = 0;
        }
        self.buf[end] = data;
        self.end = end + 1;
    }

    pub fn flush(self: *Stream) !void {
        const data = self.buf[0..self.end];
        self.end = 0;
        return self.directWrite(data);
    }

    pub fn directWrite(self: *Stream, data: []const u8) !void {
        if (self.tls_client) |*tls_client| {
                return tls_client.writeAll(self.stream, data);
        }
        return self.stream.writeAll(data);
    }
};
