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

    stream: net.Stream,
    tls_client: ?*TLSClient,

    end: usize = 0,
    buf: [4096]u8 = undefined,

    pub fn init(stream: net.Stream) Stream {
        return .{
            .allocator = null,
            .tls_client = null,
            .stream = stream,
        };
    }

    pub fn deinit(self: *Stream) void {
        if (self.tls_client) |tls_client| {
            tls_client.deinit();
        }
        self.stream.close();
    }

    pub fn toTLS(self: *Stream, config: *const Config) !void {
        self.tls_client = try TLSClient.init(self.stream, config);
    }

    pub fn readTimeout(self: *Stream, timeval: []const u8) !void {
        try posix.setsockopt(self.stream.handle, posix.SOL.SOCKET, posix.SO.RCVTIMEO, timeval);
    }

    pub fn read(self: *Stream, buf: []u8) !usize {
        if (self.tls_client) |tls_client| {
            var w: std.Io.Writer = .fixed(buf);
            while (true) {
                const n = try tls_client.client.reader.stream(&w, .limited(buf.len));
                if (n != 0) {
                    return n;
                }
            }
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
        if (self.tls_client) |tls_client| {
            try tls_client.client.writer.writeAll(data);
            // I know this looks silly, but as far as I can tell, this is what
            // we need to do.
            try tls_client.client.writer.flush();
            try tls_client.stream_writer.interface.flush();
            return;
        }
        return self.stream.writeAll(data);
    }

    const TLSClient = struct {
        client: tls.Client,
        stream: net.Stream,
        stream_writer: net.Stream.Writer,
        stream_reader: net.Stream.Reader,
        arena: std.heap.ArenaAllocator,

        fn init(stream: net.Stream, config: *const Config) !*TLSClient {
            const allocator = config.allocator orelse return error.AllocatorRequired;

            var arena = std.heap.ArenaAllocator.init(allocator);
            errdefer arena.deinit();

            const aa = arena.allocator();

            const bundle = config.ca_bundle orelse blk: {
                var b = Bundle{};
                try b.rescan(aa);
                break :blk b;
            };

            // The TLS input and output have to be max_ciphertext_record_len each.
            // It isn't clear to me how big the un-encrypted reader and writer
            // need to be. I would think 0, but that will fail an assertion. I
            // don't think that it's right that we need 4 buffers, but apparently
            // we do. Until i figure this out, using 4 x max_ciphertext_record_len
            // seems like the only safe choice.
            const buf_len = std.crypto.tls.max_ciphertext_record_len;
            var buf = try aa.alloc(u8, buf_len * 4);

            const self = try aa.create(TLSClient);
            self.* = .{
                .stream = stream,
                .arena = arena,
                .client = undefined,
                .stream_writer = stream.writer(buf.ptr[0..buf_len][0..buf_len]),
                .stream_reader = stream.reader(buf.ptr[buf_len..2*buf_len][0..buf_len]),
            };

            self.client = try tls.Client.init(
                self.stream_reader.interface(),
                &self.stream_writer.interface,
                .{
                    .ca = .{ .bundle = bundle },
                    .host = .{ .explicit = config.host } ,
                    .read_buffer = buf.ptr[2*buf_len..3*buf_len][0..buf_len],
                    .write_buffer = buf.ptr[3*buf_len..4*buf_len][0..buf_len],
                },
            );

            return self;
        }

        fn deinit(self: *TLSClient) void {
            _ = self.client.end() catch {};
            self.arena.deinit();
        }
    };
};
