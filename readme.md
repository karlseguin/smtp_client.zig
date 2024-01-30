# SMTP Client for Zig

Zig only supports TLS 1.3. Furthermore, the TLS implementation [has known issues](https://github.com/ziglang/zig/issues/14172).

This library does not work with Amazon SES as Amazon SES does not support TLS 1.3 (Amazon's documentation says that TLS 1.3 is supported with StartTLS but this does not appear to be the case (OpenSSL also reports an error)). 

The library supports the `PLAIN`, `LOGIN` and `CRAM-MD5` mechanisms of the `AUTH` extension.

# Installation
Add this to your build.zig.zon

```zig
.dependencies = .{
    .smtp_client = .{
        .url = "https://github.com/karlseguin/smtp_client.zig/archive/refs/heads/master.tar.gz",
        //the correct hash will be suggested by zig
    }
}

```

And add this to you build.zig.zon

```zig
    const smtp_client = b.dependency("smtp_client", .{
        .target = target,
        .optimize = optimize,
    });
    exe.addModule("smtp_client", string.module("smtp_client"));

```

# Basic Usage

```zig
const std = @import("std");
const smtp = @import("smtp_client");

pub fn main() !void {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  const allocator = gpa.allocator();

  const config = smtp.Config{
    .port = 25,
    .encryption = .none,
    .host = "localhost",
    .allocator = allocator,
    // .username="username",
    // .password="password",
  };

  try smtp.send(.{
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

## Performance
### Tip 1 - sendAll
The `sendAll` function takes an array of `smtp.Message`. It is much more efficient than calling `send` in a loop.

```zig
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
  try smtp.sendAll(&messages, config, &sent);
```

`sendAll` can fail part way, resulting in some messages being sent while others are not. `sendAll` stops at the first encountered error. The last parameter to `sendAll` is set to the number of successfully sent messages, thus it's possible for the caller to know which messages were and were not sent (e.g. if `sent == 3`, then messages 1, 2 and 3 were sent, message 4 failed and it, along with all subsequent messages, were not sent). Of course, when we say "successfully sent", we only mean from the point of view of this library. SMTP being asynchronous means that this library can successfully send the message to the configured upstream yet the message never reaches the final recipient(s).

### Tip 2 - CA Bundle
If you're using TLS encryption (via either `.encryption = .tls` or `.encryption = .start_tls`), you can improve performance by providing your own CA bundle. When `send` or `sendAll` are called without a configured `ca_bundle`, one is created on each call, which involves reading and parsing your OS' root certificates from disk (again, on every call).

You can create a certificate bundle on app start, using: 

```zig
var ca_bundle = std.crypto.Certificate.Bundle{}
try ca_bundle.rescan(allocator);
defer ca_bundle.deinit(allocator);
```

And then pass the bundle to `send` or `sendAll`:

```zig
var config = smtp.Config{
  .port = 25,
  .host = "localhost",
  .encryption = .tls,
  .ca_bundle = ca_bundle,  
  // ...
};
```

### Tip 3 - Skip DNS Resolution
Every call to `send` and `sendAll` requires a DNS lookup on `config.host`. The `sendTo` and `sendAllTo` functions, which take an `std.net.Address`, can be used instead. When using these functions, `config.host` must still be set to the valid host when `.tls` or `.start_tls` is used.

### Allocator
`config.allocator` is required in two cases:
1. `send` or `sendAll` are used, OR
2. `config.ca_bundle` is not specified and `.tls` or `.start_tls` are used

Put differently, `config.allocator` can be null when both these cases are true:
1. `sendTo` or `sendAllTo` are used, AND
2. `config.ca_bundle` is provided or `.encryption` is set to `.none` or `.insecure`.

Put differently again, `config.allocator` is only used by the library to (a) call `std.net.tcpConnectToHost` which does a DNS lookup and (b) manage the `std.crypto.Certificate.Bundle`.

If `config.allocator` is required but not specified, the code will return an error.
