SMTP Client for Zig

This library currently does not support StartTLS. Furthermore, Zig currently only supports TLS 1.3, so this library will not work with all providers. It does support the `PLAIN`, `LOGIN` and `CRAM-MD5` mechanisms of the `AUTH` extension.

This library does not currently work with Amazon SES (it very weirdly only supports TLS 1.3 with StartTLS))

If you're only sending occasional emails, using `smtp.send` as shown should be sufficient. The `Mailer` provides a more efficient mechanism for sending multiple mails.

```zig
const std = @import("std");
const smtp = @import("smtp_client");
const Allocator = std.mem.Allocator;

pub fn main() !void {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  const allocator = gpa.allocator();

  var config = smtp.Config{
    .tls = false,
    .port = 25,
    .host = "localhost",
    // .username="username",
    // .password="password",
  };

  try smtp.send(allocator, .{
    .from = "admin@localhsot",
    .to = &.{"user@localhost"},
    .data = "From: Admin <admin@localhost>\r\nTo: User <user@localhsot>\r\nSuject: Test\r\n\r\nThis is karl, I'm testing a SMTP client for Zig\r\n.\r\n",
  }, config);
}
```

This library is still a work in progress, but it is working and should be relatively stable.

Note that the `data` field above must conform to [RFC 2822 - Internet Message Format](https://www.rfc-editor.org/rfc/rfc2822). Notably:
* Lines, including \r\n have a maximum length of 1000.
* Any line that beginning with a '.' must be escaped with a '.' (in regex talk: `s/^\./../`)
* The message must be terminated with a \r\n.\r\n  (yes, the dot in there is intentional)

I plan on adding some type of `builder` to help with generating a valid `data` payload.

