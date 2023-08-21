# SMTP Client for Zig

Zig only supports TLS 1.3. Furthermore, the TLS implementation [has known issues](https://github.com/ziglang/zig/issues/14172).

This library does not work with Amazon SES as Amazon SES does not support TLS 1.3 (Amazon's documentation says that TLS 1.3 is supported with StartTLS but this does not appear to be the case (OpenSSL also reports an error)). 

The library supports the `PLAIN`, `LOGIN` and `CRAM-MD5` mechanisms of the `AUTH` extension.

If you're only sending occasional emails, using `smtp.send` as shown should be sufficient. The `Mailer` (TODO) provides a more efficient mechanism for sending multiple mails.

```zig
const std = @import("std");
const smtp = @import("smtp_client");
const Allocator = std.mem.Allocator;

pub fn main() !void {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  const allocator = gpa.allocator();

  var config = smtp.Config{
    .port = 25,
    .encryption = .none,
    .host = "localhost",
    // .username="username",
    // .password="password",
  };

  try smtp.send(allocator, .{
    .from = "admin@localhost",
    .to = &.{"user@localhost"},
    .data = "From: Admin <admin@localhost>\r\nTo: User <user@localhost>\r\nSuject: Test\r\n\r\nThis is karl, I'm testing a SMTP client for Zig\r\n.\r\n",
  }, config);
}
```

Note that the `data` field above must conform to [RFC 2822 - Internet Message Format](https://www.rfc-editor.org/rfc/rfc2822). Notably:
* Lines have a maximum length of 1000 (including the trailing `\r\n`)
* Any line that begins with a '.' must be escaped with a '.' (in regex talk: `s/^\./../`)
* The message must be terminated with a `\r\n.\r\n`  (yes, the dot in there is intentional)

I plan on adding some type of `builder` to help with generating a valid `data` payload.


## Encryption
Prefer using `.encryption = .tls` where possible. Most modern email vendors provider SMTP over TLS and support TLS 1.3. 

`.encryption = .start_tls` is also supported, but StartTLS is vulnerable to man-in-the-middle attack.

`.encryption = .none` will not use any encryption.  In this mode, authentication via `LOGIN` or `PLAIN` will be rejected.

`.encryption = .insecure` will not use any encryption. In this mode, authentication via `LOGIN` or `PLAIN` will be allowed and passwords will be sent in plain text. 

Regardless of the encryption setting, the library will favor authenticating via `CRAM-MD5` if the server supports it.


## sendAll
The `sendAll` function takes an array of `smtp.Message`. It is much more efficient than calling `send` in a loop.

```
  var config = smtp.Config{
   // same configuration as send
  };

  var sent: usize = 0;
  const messages = [_]smtp.Message{
    .{
      .from = "...",
      .to = &.{"..."},
      .data = "...",
    },
    .{
      .from = "...",
      .to = &.{"..."},
      .data = "...",
    }
  };
  try smtp.sendAll(allocator, &messages, config, &sent);
```

`sendAll` can fail part way, resulting in some messages being sent while others are not. `sendAll` stops at the first encountered error. The last parameter to `sendAll` is set to the number of successfully sent messages, thus it's possible for the caller to know which messages were and were not sent (e.g. if `sent == 3`, then messages 1, 2 and 3 were sent, message 4 failed and it, along with all subsequent messages, were not sent). Of course, when we say "successfully sent", we only mean from the point of view of this library. SMTP being asynchronous means that this library can successfully send the message to the configured upstream yet the message never reaches the final recipient(s).
