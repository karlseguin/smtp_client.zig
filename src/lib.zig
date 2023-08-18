// This file is only internally referenced.
// Modules don't need to know where all the other modules are, they just need
// to know about this one (which I think works much better for these small libs).
const std = @import("std");

const smtp = @import("smtp.zig");
pub const Config = smtp.Config;
pub const Message = smtp.Message;
pub const AuthMode = smtp.AuthMode;

const reader = @import("reader.zig");
pub const Reply = reader.Reply;
pub const Reader = reader.Reader;

pub const Client = @import("client.zig").Client;

pub const testing = @import("t.zig");
pub const is_test = @import("builtin").is_test;
pub const Stream = if (is_test) *testing.Stream else std.net.Stream;

test {
	std.testing.refAllDecls(@This());
}
