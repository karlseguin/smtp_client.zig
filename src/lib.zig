// This file is only internally referenced.
// Modules don't need to know where all the other modules are, they just need
// to know about this one (which I think works much better for these small libs).
const std = @import("std");

const smtp = @import("smtp.zig");
pub const Config = smtp.Config;
pub const Message = smtp.Message;

const reader = @import("reader.zig");
pub const Reply = reader.Reply;
pub const Reader = reader.Reader;

pub const Stream = @import("stream.zig");

pub const testing = @import("t.zig");
