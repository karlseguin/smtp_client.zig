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

And add this to you build.zig

```zig
    const smtp_client = b.dependency("smtp_client", .{
        .target = target,
        .optimize = optimize,
    });
    exe.addModule("smtp_client", smtp_client.module("smtp_client"));
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
    // .username = "username",
    // .password = "password",
  };

  try smtp.send(.{
    .from = "admin@localhost",
    .to = &.{"user@localhost"},
    .subject = "This is the Subject"
    .text_body = "This is the text body",
    .html_body = "<b>This is the html body</b>",
  }, config);
}
```

## Encryption
Prefer using `.encryption = .tls` where possible. Most modern email vendors provide SMTP over TLS and support TLS 1.3. 

`.encryption = .start_tls` is also supported, but StartTLS is vulnerable to man-in-the-middle attack.

`.encryption = .none` will not use any encryption.  In this mode, authentication via `LOGIN` or `PLAIN` will be rejected.

`.encryption = .insecure` will not use any encryption. In this mode, authentication via `LOGIN` or `PLAIN` will be allowed and passwords will be sent in plain text. 

Regardless of the encryption setting, the library will favor authenticating via `CRAM-MD5` if the server supports it.

# Client
The `smtp.send` and `smtp.sendAll` functions are wrappers around an `smtp.Client`. Where `send` and `sendAll` open a connection, send one or more messages and then close the connection, an `smtp.Client` keeps the connection open until `deinit` is called. The client is **not** thread safe.

```zig
var client = try smtp.connect({
  .port = 25,
  .encryption = .none,
  .host = "localhost",
  .allocator = allocator,
  // .username = "username",
  // .password = "password",
});
defer client.deinit();

try client.hello();
try client.auth();

// Multiple messages can be sent here
try client.sendMessage(.{
    .subject = "This is the Subject"
    .text_body = "This is the text body",
});

// Once this is called, no more messages can be sent
try client.quit();
```

`hello` and `auth` can be called upfront, while `from`, `to` and `sendMessage` can be called repeatedly. To make the Client thread safe, protect the call to `sendMessage` with a mutex.

# Message
The `smtp.Message` which is passed to `smtp.send`, `smtp.sendAll` and `client.sendMessage` has the following fields:

* `from: Address` - The address the email is from
* `to: []const Address` - A list of addresses to send the email to
* `subject: ?[]const u8 = null` - The subject
* `text_body: ?[]const u8 = null` -  The Text body
* `html_body: ?[]const u8 = null` - The HTML body


The `timestamp: ?i64 = null` field can also be set. This is used when writing the `Date` header. By default `std.time.timestamp`. Only advance usage should set this.

As an alternative to setting the above fields, the `data: ?[]const u8 = null` field can be set. This is the complete raw data to send following the SMTP `DATA` command. When specified, the rest of the fields are ignored. The `data` must comform to [RFC 2822 - Internet Message Format](https://www.rfc-editor.org/rfc/rfc2822), including a trailing `\r\n.\r\n`. I realize that a union would normally be used to make `data` and the other fields mutually exclusive. However, the use of `data` is considered an advanced feature, and adding union simply makes the API more complicated for 99% of the cases which would not use it.


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
      .subject = "...",
      .text_body = "...",
    },
    .{
      .from = "...",
      .to = &.{"..."},
      .subject = "...",
      .text_body = "...",
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

Similarly, instead of `connect` to create a `Client`, `connectTo` can be used which takes an `std.net.Address`.

### Allocator
`config.allocator` is required in two cases:
1. `send`, `sendAll` or `connect` are used, OR
2. `config.ca_bundle` is not specified and `.tls` or `.start_tls` are used

Put differently, `config.allocator` can be null when both these cases are true:
1. `sendTo`, `sendAllTo` or `connectTo` are used, AND
2. `config.ca_bundle` is provided or `.encryption` is set to `.none` or `.insecure`.

Put differently again, `config.allocator` is only used by the library to (a) call `std.net.tcpConnectToHost` which does a DNS lookup and (b) manage the `std.crypto.Certificate.Bundle`.

If `config.allocator` is required but not specified, the code will return an error.
