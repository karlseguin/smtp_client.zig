const std = @import("std");
const tls = std.crypto.tls;
const Client = @This();
const net = std.net;
const mem = std.mem;
const crypto = std.crypto;
const assert = std.debug.assert;
const Certificate = @import("crypto/Certificate.zig");

const max_cleartext_len = 1 << 14;
const max_ciphertext_len = max_cleartext_len + 1024;
const int2 = tls.int2;
const int3 = tls.int3;
const array = tls.array;
const enum_array = tls.enum_array;

read_seq: u64,
write_seq: u64,
/// When this is true, the stream may still not be at the end because there
/// may be data in `partially_read_buffer`.
received_close_notify: bool,
/// By default, reaching the end-of-stream when reading from the server will
/// cause `error.TlsConnectionTruncated` to be returned, unless a close_notify
/// message has been received. By setting this flag to `true`, instead, the
/// end-of-stream will be forwarded to the application layer above TLS.
/// This makes the application vulnerable to truncation attacks unless the
/// application layer itself verifies that the amount of data received equals
/// the amount of data expected, such as HTTP with the Content-Length header.
allow_truncation_attacks: bool = false,
/// RFC 5746
secure_renegotiation: bool = false,
cipher: ?ApplicationCipher,
/// The size is enough to contain exactly one TLSCiphertext record.
/// This buffer is indexed by `cleartext_slice` and `ciphertext_slice`,
/// where `cleartext_slice` must preceed `ciphertext_slice`.
/// Note that this is a little bit off from `std.crypto.tls.Client`, which
/// requires `cleartext_slice.ptr + cleartext_slice.len == ciphertext.ptr`.
partially_read_buffer: [tls.max_ciphertext_record_len]u8,
/// Slice into `partially_read_buffer` which is cleartext
cleartext_slice: []u8,
/// Slice into `partially_read_buffer` which is ciphertext
ciphertext_slice: []u8,

/// `std.net.Stream` conforms to `std.crypto.tls.Client.StreamInterface`
pub const StreamInterface = std.crypto.tls.Client.StreamInterface;

pub fn makeClientHello(buf: []u8, host: []const u8, client_random: [32]u8) []const u8 {
    const host_len: u16 = @intCast(host.len);
    const extensions_payload =
        extension(.supported_versions, [_]u8{
        0x02, // byte length of supported versions
        0x03, 0x03, // TLS 1.2
    }) ++ extension(.signature_algorithms, enum_array(tls.SignatureScheme, &.{
        .ecdsa_secp256r1_sha256,
        .ecdsa_secp384r1_sha384,
        .rsa_pss_rsae_sha256,
        .rsa_pss_rsae_sha384,
        .rsa_pss_rsae_sha512,
        .rsa_pkcs1_sha256,
        .rsa_pkcs1_sha384,
        .rsa_pkcs1_sha512,
    })) ++ extension(.supported_groups, enum_array(tls.NamedGroup, &.{
        .secp256r1,
        .x25519,
    })) ++ extension(.ec_point_formats, [2]u8{
        1, // number of formats
        @intFromEnum(ECPointFormat.uncompressed),
    }) ++
        extension(.extended_master_secret, [0]u8{}) ++
        // no renegotiation data
        extension(.renegotiation_info, [1]u8{0}) ++
        int2(@intFromEnum(ExtensionType.server_name)) ++
        int2(host_len + 5) ++ // byte length of this extension payload
        int2(host_len + 3) ++ // server_name_list byte count
        [1]u8{0x00} ++ // name_type
        int2(host_len);

    const extensions_header =
        int2(@intCast(extensions_payload.len + host_len)) ++
        extensions_payload;

    const legacy_compression_methods = 0x0100;

    const client_hello =
        int2(@intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
        client_random ++
        [1]u8{0} ++ // session_id
        cipher_suites ++
        int2(legacy_compression_methods) ++
        extensions_header;

    const out_handshake =
        [_]u8{@intFromEnum(tls.HandshakeType.client_hello)} ++
        int3(@intCast(client_hello.len + host_len)) ++
        client_hello;

    const plaintext_header = [_]u8{
        @intFromEnum(tls.ContentType.handshake),
        0x03, 0x01, // legacy_record_version
    } ++ int2(@intCast(out_handshake.len + host_len)) ++ out_handshake;

    @memcpy(buf[0..plaintext_header.len], &plaintext_header);
    return buf[0..plaintext_header.len];
}

/// Initiates a TLS handshake and establishes a TLSv1.2 session with `stream`.
///
/// `host` is only borrowed during this function call.
pub fn init(stream: std.net.Stream, ca_bundle: Certificate.Bundle, host: []const u8) !Client {
    var random_buffer: [72]u8 = undefined;
    crypto.random.bytes(&random_buffer);
    const client_random = random_buffer[0..32].*;
    const keypair_seed = random_buffer[32..64].*;
    const explicit_iv_random = random_buffer[64..72].*;

    var hash: MessageHashType = undefined;
    var next_cipher: ApplicationCipher = undefined;

    var c: Client = .{
        .read_seq = 0,
        .write_seq = 0,
        .ciphertext_slice = undefined,
        .cleartext_slice = undefined,
        .received_close_notify = false,
        .cipher = null,
        .partially_read_buffer = undefined,
    };
    c.ciphertext_slice = c.partially_read_buffer[0..0];
    c.cleartext_slice = c.partially_read_buffer[0..0];
    const client_stream = ClientAndStream{ .c = &c, .s = stream };

    // 256 is enough for TLS 1.2
    var buf: [256]u8 = undefined;
    const plaintext_header = makeClientHello(&buf, host, client_random);

    {
        var iovecs = [_]std.posix.iovec_const{
            .{ .base = plaintext_header.ptr, .len = plaintext_header.len },
            .{ .base = host.ptr, .len = host.len },
        };
        try stream.writevAll(&iovecs);
    }

    const client_hello_bytes1 = plaintext_header[5..];
    var server_random: [32]u8 = undefined;
    var extended_master_secret: bool = false;

    // In theory the certificate could be as long as 16MB though.
    var handshake_buffer: [16000]u8 = undefined;
    var cipher_suite_tag: CipherSuite = undefined;
    var d: tls.Decoder = .{ .buf = &handshake_buffer };
    {
        try d.readAtLeastOurAmt(client_stream, 4);
        const handshake_type = d.decode(tls.HandshakeType);
        if (handshake_type != .server_hello) return error.TlsUnexpectedMessage;
        const length = d.decode(u24);
        try d.readAtLeast(client_stream, length);
        const server_hello_fragment = d.buf[d.idx - 4 ..][0 .. length + 4];
        var hsd = try d.sub(length);
        try hsd.ensure(2 + 32);
        const legacy_version = hsd.decode(u16);
        _ = legacy_version;
        server_random = hsd.array(32).*;
        try hsd.ensure(1);
        const legacy_session_id_echo_len = hsd.decode(u8);
        try hsd.ensure(legacy_session_id_echo_len);
        const legacy_session_id_echo = hsd.slice(legacy_session_id_echo_len);
        _ = legacy_session_id_echo;
        try hsd.ensure(2 + 1);
        cipher_suite_tag = hsd.decode(CipherSuite);
        const hash_tag = messageHash(getAEAD(cipher_suite_tag));
        hash = switch (hash_tag) {
            .sha256 => MessageHashType{ .sha256 = crypto.hash.sha2.Sha256.init(.{}) },
            .sha384 => MessageHashType{ .sha384 = crypto.hash.sha2.Sha384.init(.{}) },
        };
        next_cipher = switch (getAEAD(cipher_suite_tag)) {
            inline .AES_128_GCM_SHA256,
            .AES_256_GCM_SHA384,
            .CHACHA20_POLY1305_SHA256,
            => |tag| createApplicationCipher(tag),
            else => unreachable,
        };
        switch (hash) {
            inline else => |*h| {
                h.update(client_hello_bytes1);
                h.update(host);
                h.update(server_hello_fragment);
            },
        }
        hsd.skip(1); // legacy_compression_method
        var extensions_size: u16 = 0;
        if (!hsd.eof()) {
            try hsd.ensure(2);
            extensions_size = hsd.decode(u16);
        }
        var all_extd = try hsd.sub(extensions_size);
        var supported_version: u16 = 0;
        while (!all_extd.eof()) {
            try all_extd.ensure(2 + 2);
            const et = all_extd.decode(ExtensionType);
            const ext_size = all_extd.decode(u16);
            var extd = try all_extd.sub(ext_size);
            switch (et) {
                .supported_versions => {
                    if (supported_version != 0) return error.TlsIllegalParameter;
                    try extd.ensure(2);
                    supported_version = extd.decode(u16);
                },
                .extended_master_secret => {
                    extended_master_secret = true;
                },
                .renegotiation_info => {
                    c.secure_renegotiation = true;
                    if (ext_size != 1) return error.TlsHandshakeFailure;
                    try extd.ensure(1);
                    if (extd.decode(u8) != 0) return error.TlsHandshakeFailure;
                },
                else => {},
            }
        }
    }

    var main_cert_pub_key_algo: Certificate.AlgorithmCategory = undefined;
    var main_cert_pub_key_buf: [600]u8 = undefined;
    var main_cert_pub_key_len: u16 = undefined;

    // Server Certificate
    {
        try d.readAtLeastOurAmt(client_stream, 4);
        try d.ensure(4);
        const handshake_type = d.decode(HandshakeType);
        if (handshake_type != .certificate) return error.TlsUnexpectedMessage;
        const length = d.decode(u24);

        try d.readAtLeast(client_stream, length);
        switch (hash) {
            inline else => |*h| h.update(d.buf[d.idx - 4 ..][0 .. length + 4]),
        }
        var hsd = try d.sub(length);
        try hsd.ensure(3);
        const certs_size = hsd.decode(u24);
        var certs_decoder = try hsd.sub(certs_size);

        var cert_index: usize = 0;
        var prev_cert: Certificate.Parsed = undefined;
        const now_sec = std.time.timestamp();
        while (!certs_decoder.eof()) {
            try certs_decoder.ensure(3);
            const cert_size = certs_decoder.decode(u24);
            const certd = try certs_decoder.sub(cert_size);

            const subject_cert: Certificate = .{
                .buffer = certd.buf,
                .index = @intCast(certd.idx),
            };
            const subject = try subject_cert.parse();

            if (cert_index == 0) {
                // Verify the host on the first certificate.
                try subject.verifyHostName(host);

                // Keep track of the public key for the
                // certificate_verify message later.
                main_cert_pub_key_algo = subject.pub_key_algo;
                const pub_key = subject.pubKey();
                if (pub_key.len > main_cert_pub_key_buf.len)
                    return error.CertificatePublicKeyInvalid;
                @memcpy(main_cert_pub_key_buf[0..pub_key.len], pub_key);
                main_cert_pub_key_len = @intCast(pub_key.len);
            } else {
                try prev_cert.verify(subject, now_sec);
            }

            if (ca_bundle.verify(subject, now_sec)) |_| {
                break;
            } else |err| switch (err) {
                error.CertificateIssuerNotFound => {},
                else => |e| return e,
            }

            prev_cert = subject;
            cert_index += 1;
        } else return error.TlsAlertUnknownCa;
    }

    // Server Key Exchange Message
    var shared_key_buf: [48]u8 = undefined;
    var named_group: tls.NamedGroup = undefined;
    // First 4 bytes are group type and length
    var server_key_bytes: []const u8 = undefined;
    const kea = getKeyExchangeAlgorithm(cipher_suite_tag);
    if (kea != .RSA) {
        try d.readAtLeastOurAmt(client_stream, 4);
        try d.ensure(4);
        const handshake_type = d.decode(HandshakeType);
        if (handshake_type != .server_key_exchange) return error.TlsUnexpectedMessage;
        const length = d.decode(u24);

        try d.readAtLeast(client_stream, length);
        switch (hash) {
            inline else => |*h| h.update(d.buf[d.idx - 4 ..][0 .. length + 4]),
        }
        var hsd = try d.sub(length);

        switch (kea) {
            .ECDHE => {},
            .RSA, .DHE => unreachable,
        }
        try hsd.ensure(4);
        const curve_type = hsd.decode(ECCurveType);
        if (curve_type != .named_curve) return error.TlsIllegalParameter;
        named_group = hsd.decode(tls.NamedGroup);
        const key_size = hsd.decode(u8);
        try hsd.ensure(key_size);
        server_key_bytes = hsd.buf[hsd.idx - 4 ..][0 .. 4 + key_size];
        _ = hsd.slice(key_size);

        // verify certificate
        try hsd.ensure(4);
        const scheme = hsd.decode(tls.SignatureScheme);
        const sig_len = hsd.decode(u16);
        try hsd.ensure(sig_len);
        const encoded_sig = hsd.slice(sig_len);
        const main_cert_pub_key = main_cert_pub_key_buf[0..main_cert_pub_key_len];
        var verify_buf: [64 + 256]u8 = undefined;
        // TODO: figure out an upper bound
        assert(server_key_bytes.len < 256);
        @memcpy(verify_buf[0..32], &client_random);
        @memcpy(verify_buf[32..64], &server_random);
        @memcpy(verify_buf[64 .. 64 + server_key_bytes.len], server_key_bytes);
        const verify_bytes = verify_buf[0 .. 64 + server_key_bytes.len];

        switch (scheme) {
            inline .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
            => |comptime_scheme| {
                if (main_cert_pub_key_algo != .X9_62_id_ecPublicKey)
                    return error.TlsBadSignatureScheme;
                const Ecdsa = SchemeEcdsa(comptime_scheme);
                const sig = try Ecdsa.Signature.fromDer(encoded_sig);
                const key = try Ecdsa.PublicKey.fromSec1(main_cert_pub_key);
                try sig.verify(verify_bytes, key);
            },
            inline .rsa_pkcs1_sha1,
            .rsa_pkcs1_sha256,
            .rsa_pkcs1_sha384,
            .rsa_pkcs1_sha512,
            => |comptime_scheme| {
                if (main_cert_pub_key_algo != .rsaEncryption) return error.TlsBadSignatureScheme;
                const Hash = SchemeHash(comptime_scheme);
                try Certificate.verifyRsa(
                    Hash,
                    verify_bytes,
                    encoded_sig,
                    .rsaEncryption,
                    main_cert_pub_key,
                );
            },
            inline .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,
            => |comptime_scheme| {
                if (main_cert_pub_key_algo != .rsaEncryption) return error.TlsBadSignatureScheme;
                const Hash = SchemeHash(comptime_scheme);
                const rsa = Certificate.rsa;
                const components = try rsa.PublicKey.parseDer(main_cert_pub_key);
                const exponent = components.exponent;
                const modulus = components.modulus;
                switch (modulus.len) {
                    inline 128, 256, 384, 512 => |modulus_len| {
                        const key = try rsa.PublicKey.fromBytes(exponent, modulus);
                        const sig = rsa.PSSSignature.fromBytes(modulus_len, encoded_sig);
                        try rsa.PSSSignature.verify(modulus_len, sig, verify_bytes, key, Hash);
                    },
                    else => return error.TlsBadRsaSignatureBitCount,
                }
            },
            else => return error.TlsBadSignatureScheme,
        }
    }

    // Server Hello Done
    {
        try d.readAtLeastOurAmt(client_stream, 4);
        try d.ensure(4);
        const handshake_type = d.decode(HandshakeType);
        if (handshake_type != .server_hello_done) return error.TlsUnexpectedMessage;
        const length = d.decode(u24);

        try d.readAtLeast(client_stream, length);
        switch (hash) {
            inline else => |*h| h.update(d.buf[d.idx - 4 ..][0 .. length + 4]),
        }
        if (length != 0) return error.TlsDecodeError;
    }

    // Client Key Exchange
    var shared_key: []const u8 = undefined;
    {
        var public_key_buf: [512]u8 = undefined;
        const public_key: []const u8 = switch (kea) {
            .ECDHE => switch (named_group) {
                .x25519 => blk: {
                    const X25519 = crypto.dh.X25519;
                    const ksl = X25519.public_length;
                    if (server_key_bytes.len - 4 != ksl) return error.TlsIllegalParameter;

                    const x25519_kp = X25519.KeyPair.create(keypair_seed) catch |err| switch (err) {
                        // Only possible to happen if the private key is all zeroes.
                        error.IdentityElement => return error.InsufficientEntropy,
                    };

                    shared_key = &(X25519.scalarmult(
                        x25519_kp.secret_key,
                        server_key_bytes[4 .. 4 + ksl].*,
                    ) catch return error.TlsDecryptFailure);
                    break :blk &x25519_kp.public_key;
                },
                .secp256r1 => blk: {
                    const secp256r1 = crypto.sign.ecdsa.EcdsaP256Sha256;
                    const pk = secp256r1.PublicKey.fromSec1(server_key_bytes[4..]) catch {
                        return error.TlsDecryptFailure;
                    };

                    const secp256r1_kp = secp256r1.KeyPair.create(keypair_seed) catch |err| switch (err) {
                        // Only possible to happen if the private key is all zeroes.
                        error.IdentityElement => return error.InsufficientEntropy,
                    };

                    const mul = pk.p.mulPublic(secp256r1_kp.secret_key.bytes, .big) catch {
                        return error.TlsDecryptFailure;
                    };
                    shared_key = &mul.affineCoordinates().x.toBytes(.big);
                    break :blk &secp256r1_kp.public_key.toUncompressedSec1();
                },
                else => unreachable,
            },
            .RSA => blk: {
                // 0x0303 for TLS 1.2
                shared_key_buf[0] = 0x03;
                shared_key_buf[1] = 0x03;
                crypto.random.bytes(shared_key_buf[2..]);
                shared_key = &shared_key_buf;
                break :blk try Certificate.encryptPKCS1(&public_key_buf, &shared_key_buf, &main_cert_pub_key_buf);
            },
            .DHE => unreachable,
        };
        var record_header = [1]u8{@intFromEnum(tls.ContentType.handshake)} ++
            tls.int2(@intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
            [2]u8{ undefined, undefined };
        var header_buffer: [6]u8 = undefined;
        header_buffer[0] = @intFromEnum(HandshakeType.client_key_exchange);
        const header = switch (kea) {
            .ECDHE => blk: {
                record_header[3..5].* = int2(@intCast(public_key.len + 5));
                header_buffer[1..4].* = int3(@intCast(public_key.len + 1));
                header_buffer[4] = @intCast(public_key.len);
                break :blk header_buffer[0..5];
            },
            .RSA => blk: {
                record_header[3..5].* = int2(@intCast(public_key.len + 6));
                header_buffer[1..4].* = int3(@intCast(public_key.len + 2));
                header_buffer[4..6].* = int2(@intCast(public_key.len));
                break :blk header_buffer[0..6];
            },
            .DHE => unreachable,
        };
        var iovecs = [_]std.posix.iovec_const{
            .{ .base = &record_header, .len = record_header.len },
            .{ .base = header.ptr, .len = header.len },
            .{ .base = public_key.ptr, .len = public_key.len },
        };
        try stream.writevAll(&iovecs);
        switch (hash) {
            inline else => |*h| {
                h.update(header);
                h.update(public_key);
            },
        }
    }

    // Client Change Cipher Spec
    {
        const record = [1]u8{@intFromEnum(tls.ContentType.change_cipher_spec)} ++
            tls.int2(@intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
            tls.int2(1) ++
            [1]u8{1};
        try stream.writeAll(&record);
    }

    // Calculate Keys
    var master_secret: [48]u8 = undefined;
    {
        switch (hash) {
            inline else => |h| if (extended_master_secret) {
                master_secret = PRF(
                    crypto.auth.hmac.Hmac(@TypeOf(h)),
                    shared_key,
                    "extended master secret",
                    &h.peek(),
                    48,
                );
            } else {
                const seed = client_random ++ server_random;
                master_secret = PRF(
                    crypto.auth.hmac.Hmac(@TypeOf(h)),
                    shared_key,
                    "master secret",
                    &seed,
                    48,
                );
            },
        }
        // Key Expansion: note that AEAD do not need mac key
        const seed2 = server_random ++ client_random;
        switch (next_cipher) {
            inline else => |*cipher| {
                const Cipher = @TypeOf(cipher.*);
                const AEAD = Cipher.AEAD;
                const implicit_nonce_len = AEAD.nonce_length - Cipher.explicit_nonce_len;
                const key_len = AEAD.key_length;
                const total_len = 2 * (key_len + implicit_nonce_len);
                const key_material = PRF(
                    Cipher.Hmac,
                    &master_secret,
                    "key expansion",
                    &seed2,
                    total_len,
                );
                cipher.client_key = key_material[0..key_len].*;
                cipher.server_key = key_material[key_len .. 2 * key_len].*;
                const iv_material = key_material[2 * key_len ..];
                cipher.client_iv[0..implicit_nonce_len].* = iv_material[0..implicit_nonce_len].*;
                cipher.server_iv = iv_material[implicit_nonce_len .. 2 * implicit_nonce_len].* ++
                    [1]u8{0} ** Cipher.explicit_nonce_len;
                // RFC 9325, Section 7.2.1
                // Use the sequency counter as GC, but also add some randomness to it
                cipher.client_iv[implicit_nonce_len..].* = explicit_iv_random[0..Cipher.explicit_nonce_len].*;
            },
        }
    }

    c.cipher = next_cipher;

    // Client Finished
    {
        const verify_data = switch (hash) {
            inline else => |*h| PRF(
                crypto.auth.hmac.Hmac(@TypeOf(h.*)),
                &master_secret,
                "client finished",
                &h.peek(),
                12,
            ),
        };
        const handshake_finished: [16]u8 =
            [1]u8{@intFromEnum(HandshakeType.finished)} ++
            int3(12) ++ verify_data;
        const total = try c.writeEnd(stream, &handshake_finished, false, .handshake);
        assert(total == 16);
        switch (hash) {
            inline else => |*h| {
                h.update(&handshake_finished);
            },
        }
    }

    c.cipher = null;

    // Server Change Cipher Spec
    {
        try d.readAtLeastOurAmt(client_stream, 1);
        if (d.decode(u8) != 1) return error.TlsUnexpectedMessage;
    }

    c.cipher = next_cipher;

    // Server Finished
    {
        try d.readAtLeastOurAmt(client_stream, 4);
        try d.ensure(4);
        const handshake_type = d.decode(HandshakeType);
        if (handshake_type != .finished) return error.TlsUnexpectedMessage;
        const length = d.decode(u24);

        try d.readAtLeast(client_stream, length);
        if (length != 12) return error.TlsDecodeError;
        try d.ensure(12);
        const server_verify = d.array(12);
        const verify_data = switch (hash) {
            inline else => |*h| PRF(crypto.auth.hmac.Hmac(@TypeOf(h.*)), &master_secret, "server finished", &h.finalResult(), 12),
        };
        if (!mem.eql(u8, server_verify, &verify_data))
            return error.TlsHandshakeFailure;
    }

    return c;
}

const ClientAndStream = struct {
    c: *Client,
    s: std.net.Stream,

    pub fn readAtLeast(self: ClientAndStream, buffer: []u8, len: usize) !usize {
        return self.c.readAtLeast(self.s, buffer, len);
    }
};

/// Sends TLS-encrypted data to `stream`, which must conform to `StreamInterface`.
/// Returns the number of plaintext bytes sent, which may be fewer than `bytes.len`.
pub fn write(c: *Client, stream: std.net.Stream, bytes: []const u8) !usize {
    return writeEnd(c, stream, bytes, false, .application_data);
}

/// Sends TLS-encrypted data to `stream`, which must conform to `StreamInterface`.
pub fn writeAll(c: *Client, stream: std.net.Stream, bytes: []const u8) !void {
    var index: usize = 0;
    while (index < bytes.len) {
        index += try c.write(stream, bytes[index..]);
    }
}

/// Sends TLS-encrypted data to `stream`, which must conform to `StreamInterface`.
/// If `end` is true, then this function additionally sends a `close_notify` alert,
/// which is necessary for the server to distinguish between a properly finished
/// TLS session, or a truncation attack.
pub fn writeAllEnd(c: *Client, stream: std.net.Stream, bytes: []const u8, end: bool) !void {
    var index: usize = 0;
    while (index < bytes.len) {
        index += try c.writeEnd(stream, bytes[index..], end, .application_data);
    }
}

/// Sends TLS-encrypted data to `stream`, which must conform to `StreamInterface`.
/// Returns the number of plaintext bytes sent, which may be fewer than `bytes.len`.
/// If `end` is true, then this function additionally sends a `close_notify` alert,
/// which is necessary for the server to distinguish between a properly finished
/// TLS session, or a truncation attack.
pub fn writeEnd(c: *Client, stream: std.net.Stream, bytes: []const u8, end: bool, inner_content_type: tls.ContentType) !usize {
    var ciphertext_buf: [tls.max_ciphertext_record_len * 4]u8 = undefined;
    var iovecs_buf: [6]std.posix.iovec_const = undefined;
    var prepared = prepareCiphertextRecord(c, &iovecs_buf, &ciphertext_buf, bytes, inner_content_type);
    if (end) {
        prepared.iovec_end += prepareCiphertextRecord(
            c,
            iovecs_buf[prepared.iovec_end..],
            ciphertext_buf[prepared.ciphertext_end..],
            &tls.close_notify_alert,
            .alert,
        ).iovec_end;
    }

    const iovec_end = prepared.iovec_end;
    const overhead_len = prepared.overhead_len;

    // Ideally we would call writev exactly once here, however, we must ensure
    // that we don't return with a record partially written.
    var i: usize = 0;
    var total_amt: usize = 0;
    while (true) {
        var amt = try stream.writev(iovecs_buf[i..iovec_end]);
        while (amt >= iovecs_buf[i].len) {
            const encrypted_amt = iovecs_buf[i].len;
            total_amt += encrypted_amt - overhead_len;
            amt -= encrypted_amt;
            i += 1;
            // Rely on the property that iovecs delineate records, meaning that
            // if amt equals zero here, we have fortunately found ourselves
            // with a short read that aligns at the record boundary.
            if (i >= iovec_end) return total_amt;
            // We also cannot return on a vector boundary if the final close_notify is
            // not sent; otherwise the caller would not know to retry the call.
            if (amt == 0 and (!end or i < iovec_end - 1)) return total_amt;
        }
        iovecs_buf[i].base += amt;
        iovecs_buf[i].len -= amt;
    }
}

const CiphertextRecordResult = struct {
    iovec_end: usize,
    ciphertext_end: usize,
    /// How many bytes are taken up by overhead per record.
    overhead_len: usize,
};

fn prepareCiphertextRecord(
    c: *Client,
    iovecs: []std.posix.iovec_const,
    ciphertext_buf: []u8,
    bytes: []const u8,
    inner_content_type: tls.ContentType,
) CiphertextRecordResult {
    var ciphertext_end: usize = 0;
    var iovec_end: usize = 0;
    var bytes_i: usize = 0;
    switch (c.cipher.?) {
        inline else => |*p| {
            const P = @TypeOf(p.*);
            const V = @Vector(P.AEAD.nonce_length, u8);
            const overhead_len = tls.record_header_len + P.explicit_nonce_len + P.AEAD.tag_length;
            const close_notify_alert_reserved = tls.close_notify_alert.len + overhead_len;
            while (true) {
                const encrypted_content_len: u16 = @intCast(@min(
                    @min(bytes.len - bytes_i, max_ciphertext_len),
                    ciphertext_buf.len -| (close_notify_alert_reserved +
                        overhead_len + ciphertext_end),
                ));
                if (encrypted_content_len == 0) return .{
                    .iovec_end = iovec_end,
                    .ciphertext_end = ciphertext_end,
                    .overhead_len = overhead_len,
                };

                const cleartext = bytes[bytes_i..][0..encrypted_content_len];
                bytes_i += encrypted_content_len;

                const record_start = ciphertext_end;
                const header = ciphertext_buf[ciphertext_end..][0..5];
                // length including nonce, data and tag (and padding)
                const full_length = P.explicit_nonce_len + encrypted_content_len + P.AEAD.tag_length;
                header.* =
                    [1]u8{@intFromEnum(inner_content_type)} ++
                    int2(@intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                    int2(@intCast(full_length));
                ciphertext_end += header.len;
                const explicit_nonce = ciphertext_buf[ciphertext_end..][0..P.explicit_nonce_len];
                ciphertext_end += explicit_nonce.len;
                const ciphertext = ciphertext_buf[ciphertext_end..][0..encrypted_content_len];
                ciphertext_end += encrypted_content_len;
                const auth_tag = ciphertext_buf[ciphertext_end..][0..P.AEAD.tag_length];
                ciphertext_end += auth_tag.len;
                // The nonce for AEAD is always 4+8 bytes, whether the explicit part is send or not
                const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                const seq_big = @as([8]u8, @bitCast(big(c.write_seq)));
                const operand: V = pad ++ seq_big;
                c.write_seq += 1; // TODO send key_update on overflow
                const nonce = @as(V, p.client_iv) ^ operand;
                explicit_nonce.* = @as([12]u8, nonce)[12 - P.explicit_nonce_len .. 12].*;
                const ad = seq_big ++
                    [1]u8{@intFromEnum(inner_content_type)} ++
                    int2(@intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                    int2(@intCast(encrypted_content_len));
                P.AEAD.encrypt(ciphertext, auth_tag, cleartext, &ad, nonce, p.client_key);

                const record = ciphertext_buf[record_start..ciphertext_end];
                iovecs[iovec_end] = .{
                    .base = record.ptr,
                    .len = record.len,
                };
                iovec_end += 1;
            }
        },
    }
}

pub fn eof(c: Client) bool {
    return c.received_close_notify and
        c.ciphertext_slice.len == 0 and
        c.cleartext_slice.len == 0;
}

/// Receives TLS-encrypted data from `stream`, which must conform to `StreamInterface`.
/// Returns the number of bytes read, calling the underlying read function the
/// minimal number of times until the buffer has at least `len` bytes filled.
/// If the number read is less than `len` it means the stream reached the end.
/// Reaching the end of the stream is not an error condition.
pub fn readAtLeast(c: *Client, stream: std.net.Stream, buffer: []u8, len: usize) !usize {
    var iovecs = [1]std.posix.iovec{.{ .base = buffer.ptr, .len = buffer.len }};
    return readvAtLeast(c, stream, &iovecs, len);
}

/// Receives TLS-encrypted data from `stream`, which must conform to `StreamInterface`.
pub fn read(c: *Client, stream: std.net.Stream, buffer: []u8) !usize {
    return readAtLeast(c, stream, buffer, 1);
}

/// Receives TLS-encrypted data from `stream`, which must conform to `StreamInterface`.
/// Returns the number of bytes read. If the number read is smaller than
/// `buffer.len`, it means the stream reached the end. Reaching the end of the
/// stream is not an error condition.
pub fn readAll(c: *Client, stream: std.net.Stream, buffer: []u8) !usize {
    return readAtLeast(c, stream, buffer, buffer.len);
}

/// Receives TLS-encrypted data from `stream`, which must conform to `StreamInterface`.
/// Returns the number of bytes read. If the number read is less than the space
/// provided it means the stream reached the end. Reaching the end of the
/// stream is not an error condition.
/// The `iovecs` parameter is mutable because this function needs to mutate the fields in
/// order to handle partial reads from the underlying stream layer.
pub fn readv(c: *Client, stream: std.net.Stream, iovecs: []std.posix.iovec) !usize {
    return readvAtLeast(c, stream, iovecs, 1);
}

/// Receives TLS-encrypted data from `stream`, which must conform to `StreamInterface`.
/// Returns the number of bytes read, calling the underlying read function the
/// minimal number of times until the iovecs have at least `len` bytes filled.
/// If the number read is less than `len` it means the stream reached the end.
/// Reaching the end of the stream is not an error condition.
/// The `iovecs` parameter is mutable because this function needs to mutate the fields in
/// order to handle partial reads from the underlying stream layer.
pub fn readvAtLeast(c: *Client, stream: std.net.Stream, iovecs: []std.posix.iovec, len: usize) !usize {
    if (c.eof()) return 0;

    var off_i: usize = 0;
    var vec_i: usize = 0;
    while (true) {
        var amt = try c.readvAdvanced(stream, iovecs[vec_i..]);
        off_i += amt;
        if (c.eof() or off_i >= len) return off_i;
        while (amt >= iovecs[vec_i].len) {
            amt -= iovecs[vec_i].len;
            vec_i += 1;
        }
        iovecs[vec_i].base += amt;
        iovecs[vec_i].len -= amt;
    }
}

/// Receives TLS-encrypted data from `stream`, which must conform to `StreamInterface`.
/// Returns number of bytes that have been read, populated inside `iovecs`. A
/// return value of zero bytes does not mean end of stream. Instead, check the `eof()`
/// for the end of stream. The `eof()` may be true after any call to
/// `read`, including when greater than zero bytes are returned, and this
/// function asserts that `eof()` is `false`.
/// See `readv` for a higher level function that has the same, familiar API as
/// other read functions, such as `std.fs.File.read`.
pub fn readvAdvanced(c: *Client, stream: std.net.Stream, iovecs: []const std.posix.iovec) !usize {
    var vp: VecPut = .{ .iovecs = iovecs };

    // Give away the buffered cleartext we have, if any.
    if (c.cleartext_slice.len > 0) {
        const amt: u15 = @intCast(vp.put(c.cleartext_slice));
        c.cleartext_slice = c.cleartext_slice[amt..];

        if (c.cleartext_slice.len == 0) {
            // The buffer is now empty.
        }

        if (c.received_close_notify) {
            c.ciphertext_slice = c.partially_read_buffer[0..0];
            assert(vp.total == amt);
            return amt;
        } else if (amt > 0) {
            // We don't need more data, so don't call read.
            assert(vp.total == amt);
            return amt;
        }
    }
    assert(c.cleartext_slice.len == 0);

    // Receive until we have a complete record
    while (true) {
        // Skip `stream.readv` if there is a complete record unprocessed
        // This may happen when different types of traffic are mixed.
        if (c.ciphertext_slice.len > 5) {
            const record_len = mem.readInt(u16, c.ciphertext_slice[3..5], .big);
            if (record_len + 5 <= c.ciphertext_slice.len)
                break;
        }

        // Ensure c.partial_ciphertex_idx == 0
        // Recoup `partially_read_buffer space`. This is necessary because it is assumed
        // below that `frag0` is big enough to hold at least one record.
        if (c.ciphertext_slice.len != 0) {
            limitedOverlapCopy(
                c.partially_read_buffer[0..c.ciphertext_slice.len],
                c.ciphertext_slice,
            );
            c.ciphertext_slice = c.partially_read_buffer[0..c.ciphertext_slice.len];
        }

        const remaining_partial_buffer = c.partially_read_buffer[c.ciphertext_slice.len..];
        assert(remaining_partial_buffer.len != 0);

        var ask_iovecs_buf = [_]std.posix.iovec{
            .{
                .base = remaining_partial_buffer.ptr,
                .len = remaining_partial_buffer.len,
            },
            // TODO: enable larger buffer
        };

        assert(!c.received_close_notify);
        const received_len = try stream.readv(&ask_iovecs_buf);
        c.ciphertext_slice = c.partially_read_buffer[0 .. c.ciphertext_slice.len + received_len];
        if (received_len == 0) {
            // This is either a truncation attack, a bug in the server, or an
            // intentional omission of the close_notify message due to truncation
            // detection handled above the TLS layer.
            if (c.allow_truncation_attacks) {
                // No point in reading anymore
                c.received_close_notify = true;
                break;
            } else {
                return error.TlsConnectionTruncated;
            }
        }
    }

    // Decrypt. Note that we return as soon as we see one complete record.
    decrypt: {
        var in: usize = 0;
        const frag = c.ciphertext_slice;

        // Ensure a complete record is in `frag`
        const ct: tls.ContentType = @enumFromInt(frag[in]);
        const legacy_version = mem.readInt(u16, frag[in..][1..3], .big);
        const record_len = mem.readInt(u16, frag[in..][3..5], .big);
        if (record_len > max_ciphertext_len) return error.TlsRecordOverflow;
        if (record_len > max_cleartext_len)
            std.debug.print("{}", .{record_len});
        in += 5;
        const end = in + record_len;
        assert(end <= frag.len);

        // Now decode a complete record in `frag`
        switch (ct) {
            .alert => {
                if (in + 2 > frag.len) return error.TlsDecodeError;
                const level: tls.AlertLevel = @enumFromInt(frag[in]);
                const desc: tls.AlertDescription = @enumFromInt(frag[in + 1]);
                _ = level;

                try desc.toError();

                assert(desc == tls.AlertDescription.close_notify);
                c.received_close_notify = true;
                c.ciphertext_slice = c.ciphertext_slice[end..];
                break :decrypt;
            },
            // TODO: distinguish between these
            .application_data, .handshake, .change_cipher_spec => {},
            else => return error.TlsUnexpectedMessage,
        }

        // Ideally, this buffer would never be used. It is needed when `iovecs` are
        // too small to fit the cleartext, which may be as large as `max_ciphertext_len`.
        var cleartext_stack_buffer: [max_cleartext_len]u8 = undefined;
        const cleartext = if (c.cipher) |cipher| switch (cipher) {
            inline else => |*p| c: {
                const P = @TypeOf(p.*);
                const V = @Vector(P.AEAD.nonce_length, u8);
                const ciphertext_len = record_len - P.AEAD.tag_length - P.explicit_nonce_len;
                const explicit_nonce = frag[in..][0..P.explicit_nonce_len].*;
                in += explicit_nonce.len;
                const ciphertext = frag[in..][0..ciphertext_len];
                in += ciphertext_len;
                const auth_tag = frag[in..][0..P.AEAD.tag_length].*;
                const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                const seq_big = @as([8]u8, @bitCast(big(c.read_seq)));
                var nonce: [P.AEAD.nonce_length]u8 = undefined;
                if (explicit_nonce.len != 0) {
                    const implicit_nonce_len = P.AEAD.nonce_length - explicit_nonce.len;
                    nonce[0..implicit_nonce_len].* = p.server_iv[0..implicit_nonce_len].*;
                    nonce[implicit_nonce_len..P.AEAD.nonce_length].* = explicit_nonce;
                } else {
                    const operand: V = pad ++ seq_big;
                    nonce = @as(V, p.server_iv) ^ operand;
                }
                const out_buf = vp.peek();
                const cleartext_buf = if (ciphertext.len <= out_buf.len)
                    out_buf
                else
                    &cleartext_stack_buffer;
                const cleartext = cleartext_buf[0..ciphertext.len];
                const ad = seq_big ++
                    [1]u8{@intFromEnum(ct)} ++
                    int2(legacy_version) ++
                    int2(@intCast(ciphertext_len));
                P.AEAD.decrypt(cleartext, ciphertext, auth_tag, &ad, nonce, p.server_key) catch
                    return error.TlsBadRecordMac;
                break :c cleartext;
            },
        } else {
            const cleartext = frag[in..][0..record_len];
            const amt = vp.put(cleartext);
            if (amt < cleartext.len) {
                c.cleartext_slice = cleartext[amt..];
            }
            c.ciphertext_slice = c.ciphertext_slice[end..];
            break :decrypt;
        };

        c.read_seq = try std.math.add(u64, c.read_seq, 1);

        // Determine whether the output buffer or a stack
        // buffer was used for storing the cleartext.
        if (cleartext.ptr == &cleartext_stack_buffer) {
            // Stack buffer was used, so we must copy to the output buffer.
            if (c.cleartext_slice.len > 0) {
                // We have already run out of room in iovecs. Continue
                // appending to `partially_read_buffer`.
                const cleartxt_end = @intFromPtr(c.cleartext_slice.ptr) -
                    @intFromPtr(&c.partially_read_buffer[0]) + c.cleartext_slice.len;
                @memcpy(
                    c.partially_read_buffer[cleartxt_end..][0..cleartext.len],
                    cleartext,
                );
                c.cleartext_slice.len += cleartext.len;
                assert((c.cleartext_slice.ptr) == (&c.partially_read_buffer) and
                    @intFromPtr(c.cleartext_slice.ptr) + c.cleartext_slice.len <=
                    @intFromPtr(c.ciphertext_slice.ptr));
            } else {
                const amt = vp.put(cleartext);
                if (amt < cleartext.len) {
                    const rest = cleartext[amt..];
                    c.cleartext_slice = c.partially_read_buffer[0..rest.len];
                    limitedOverlapCopy(c.cleartext_slice, rest);
                }
            }
        } else {
            // Output buffer was used directly which means no
            // memory copying needs to occur, and we can move
            // on to the next ciphertext record.
            vp.next(cleartext.len);
        }
        c.ciphertext_slice = c.ciphertext_slice[end..];
    }
    return vp.total;
}

/// `@memcpy(dst, src)` but allows `dst.ptr + dst.len <= src.ptr`
fn limitedOverlapCopy(dst: []u8, src: []u8) void {
    if (dst.len == 0 and src.len == 0) return;
    if (@intFromPtr(dst.ptr) + dst.len <= @intFromPtr(src.ptr)) {
        // A single, non-overlapping memcpy suffices.
        @memcpy(dst, src);
    } else {
        // One memcpy call would overlap, so just do this instead.
        std.mem.copyForwards(u8, dst, src);
    }
}

const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

inline fn big(x: anytype) @TypeOf(x) {
    return switch (native_endian) {
        .big => x,
        .little => @byteSwap(x),
    };
}

pub fn SchemeEcdsa(comptime scheme: tls.SignatureScheme) type {
    return switch (scheme) {
        .ecdsa_secp256r1_sha256 => crypto.sign.ecdsa.EcdsaP256Sha256,
        .ecdsa_secp384r1_sha384 => crypto.sign.ecdsa.EcdsaP384Sha384,
        else => @compileError("bad scheme"),
    };
}

pub fn SchemeHash(comptime scheme: tls.SignatureScheme) type {
    return switch (scheme) {
        .rsa_pss_rsae_sha256 => crypto.hash.sha2.Sha256,
        .rsa_pss_rsae_sha384 => crypto.hash.sha2.Sha384,
        .rsa_pss_rsae_sha512 => crypto.hash.sha2.Sha512,

        .rsa_pkcs1_sha1 => crypto.hash.Sha1,
        .rsa_pkcs1_sha256 => crypto.hash.sha2.Sha256,
        .rsa_pkcs1_sha384 => crypto.hash.sha2.Sha384,
        .rsa_pkcs1_sha512 => crypto.hash.sha2.Sha512,
        else => @compileError("bad scheme"),
    };
}

pub const HashName = enum {
    // sha1,
    sha256,
    sha384,
    // sha512,
};

pub const MessageHashType = union(HashName) {
    // sha1: crypto.hash.Sha1,
    sha256: crypto.hash.sha2.Sha256,
    sha384: crypto.hash.sha2.Sha384,
    // sha512: crypto.hash.sha2.Sha512,
};

/// Abstraction for sending multiple byte buffers to a slice of iovecs.
const VecPut = struct {
    iovecs: []const std.posix.iovec,
    idx: usize = 0,
    off: usize = 0,
    total: usize = 0,

    /// Returns the amount actually put which is always equal to bytes.len
    /// unless the vectors ran out of space.
    fn put(vp: *VecPut, bytes: []const u8) usize {
        if (vp.idx >= vp.iovecs.len) return 0;
        var bytes_i: usize = 0;
        while (true) {
            const v = vp.iovecs[vp.idx];
            const dest = v.base[vp.off..v.len];
            const src = bytes[bytes_i..][0..@min(dest.len, bytes.len - bytes_i)];
            @memcpy(dest[0..src.len], src);
            bytes_i += src.len;
            vp.off += src.len;
            if (vp.off >= v.len) {
                vp.off = 0;
                vp.idx += 1;
                if (vp.idx >= vp.iovecs.len) {
                    vp.total += bytes_i;
                    return bytes_i;
                }
            }
            if (bytes_i >= bytes.len) {
                vp.total += bytes_i;
                return bytes_i;
            }
        }
    }

    /// Returns the next buffer that consecutive bytes can go into.
    fn peek(vp: VecPut) []u8 {
        if (vp.idx >= vp.iovecs.len) return &.{};
        const v = vp.iovecs[vp.idx];
        return v.base[vp.off..v.len];
    }

    // After writing to the result of peek(), one can call next() to
    // advance the cursor.
    fn next(vp: *VecPut, len: usize) void {
        vp.total += len;
        vp.off += len;
        if (vp.off >= vp.iovecs[vp.idx].len) {
            vp.off = 0;
            vp.idx += 1;
        }
    }

    fn freeSize(vp: VecPut) usize {
        if (vp.idx >= vp.iovecs.len) return 0;
        var total: usize = 0;
        total += vp.iovecs[vp.idx].len - vp.off;
        if (vp.idx + 1 >= vp.iovecs.len) return total;
        for (vp.iovecs[vp.idx + 1 ..]) |v| total += v.len;
        return total;
    }
};

pub const cipher_suites = tls.enum_array(CipherSuite, &.{
    .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,

    // Legacy
    .RSA_WITH_AES_128_GCM_SHA256,
    .RSA_WITH_AES_256_GCM_SHA384,
});

pub const CipherSuite = enum(u16) {
    // TLS 1.2 cipher suites equivalent to ones supported by TLS 1.3
    // Key exchange: DHE/ECDHE/RSA(only with AES-GCM)
    // Authentication: RSA/PSK/ECDSA(only with ECDHE)
    // AEAD: AES_128_GCM_SHA256/AES_256_GCM_SHA384/CHACHA20_POLY1305_SHA256
    RSA_WITH_AES_128_GCM_SHA256 = 0x009c,
    RSA_WITH_AES_256_GCM_SHA384 = 0x009d,
    DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009e,
    DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009f,
    DHE_PSK_WITH_AES_128_GCM_SHA256 = 0x00aa,
    DHE_PSK_WITH_AES_256_GCM_SHA384 = 0x00ab,
    ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b,
    ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c,
    ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f,
    ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030,
    ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8,
    ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9,
    DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xccaa,
    ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xccac,
    DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xccad,
    ECDHE_PSK_WITH_AES_128_GCM_SHA256 = 0xd001,
    ECDHE_PSK_WITH_AES_256_GCM_SHA384 = 0xd002,
    _,
};

pub const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20,
    key_update = 24,
    message_hash = 254,
    _,
};

pub const ECCurveType = enum(u8) {
    explicit_prime = 1, // deprecated by RFC 8422
    explicit_char2 = 2, // deprecated by RFC 8422
    named_curve = 3,
    _,
};

pub const ExtensionType = enum(u16) {
    server_name = 0,
    supported_groups = 10,
    ec_point_formats = 11,
    signature_algorithms = 13,
    extended_master_secret = 23,
    supported_versions = 43,
    renegotiation_info = 0xff01,
    _,
};

pub inline fn extension(comptime et: ExtensionType, bytes: anytype) [2 + 2 + bytes.len]u8 {
    return int2(@intFromEnum(et)) ++ array(1, bytes);
}

pub const ECPointFormat = enum(u8) {
    uncompressed = 0,
    ansiX962_compressed_prime = 1, // deprecated by RFC 8422
    ansiX962_compressed_char2 = 2, // deprecated by RFC 8422
    _,
};

pub fn getAEAD(cs: CipherSuite) tls.CipherSuite {
    return switch (cs) {
        .DHE_RSA_WITH_AES_128_GCM_SHA256 => .AES_128_GCM_SHA256,
        .ECDHE_RSA_WITH_AES_128_GCM_SHA256 => .AES_128_GCM_SHA256,
        .DHE_PSK_WITH_AES_128_GCM_SHA256 => .AES_128_GCM_SHA256,
        .ECDHE_PSK_WITH_AES_128_GCM_SHA256 => .AES_128_GCM_SHA256,
        .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => .AES_128_GCM_SHA256,
        .RSA_WITH_AES_128_GCM_SHA256 => .AES_128_GCM_SHA256,
        .DHE_RSA_WITH_AES_256_GCM_SHA384 => .AES_256_GCM_SHA384,
        .ECDHE_RSA_WITH_AES_256_GCM_SHA384 => .AES_256_GCM_SHA384,
        .DHE_PSK_WITH_AES_256_GCM_SHA384 => .AES_256_GCM_SHA384,
        .ECDHE_PSK_WITH_AES_256_GCM_SHA384 => .AES_256_GCM_SHA384,
        .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => .AES_256_GCM_SHA384,
        .RSA_WITH_AES_256_GCM_SHA384 => .AES_256_GCM_SHA384,
        .DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => .CHACHA20_POLY1305_SHA256,
        .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => .CHACHA20_POLY1305_SHA256,
        .DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => .CHACHA20_POLY1305_SHA256,
        .ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => .CHACHA20_POLY1305_SHA256,
        .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => .CHACHA20_POLY1305_SHA256,
        _ => unreachable,
    };
}

pub fn messageHash(cs: tls.CipherSuite) HashName {
    return switch (cs) {
        .AES_128_GCM_SHA256 => .sha256,
        .AES_256_GCM_SHA384 => .sha384,
        .CHACHA20_POLY1305_SHA256 => .sha256,
        else => unreachable,
    };
}

pub fn ApplicationCipherT(comptime AeadType: type, comptime HashType: type, comptime explicit_nonce: usize) type {
    return struct {
        pub const AEAD = AeadType;
        pub const Hash = HashType;
        pub const Hmac = crypto.auth.hmac.Hmac(Hash);
        pub const explicit_nonce_len = explicit_nonce;

        client_key: [AEAD.key_length]u8,
        server_key: [AEAD.key_length]u8,
        // For AES_GCM in TLS 1.2, lower 8 bytes are explicit nonce
        client_iv: [AEAD.nonce_length]u8,
        server_iv: [AEAD.nonce_length]u8,
    };
}

/// Encryption parameters for application traffic.
pub const ApplicationCipher = union(enum) {
    AES_128_GCM_SHA256: ApplicationCipherT(crypto.aead.aes_gcm.Aes128Gcm, crypto.hash.sha2.Sha256, 8),
    AES_256_GCM_SHA384: ApplicationCipherT(crypto.aead.aes_gcm.Aes256Gcm, crypto.hash.sha2.Sha384, 8),
    CHACHA20_POLY1305_SHA256: ApplicationCipherT(crypto.aead.chacha_poly.ChaCha20Poly1305, crypto.hash.sha2.Sha256, 0),
};

pub fn createApplicationCipher(comptime tag: tls.CipherSuite) ApplicationCipher {
    return @unionInit(ApplicationCipher, @tagName(tag), .{
        .client_key = undefined,
        .server_key = undefined,
        .client_iv = undefined,
        .server_iv = undefined,
    });
}

pub const KeyExchangeAlgorithm = enum { ECDHE, DHE, RSA };

pub fn getKeyExchangeAlgorithm(cs: CipherSuite) KeyExchangeAlgorithm {
    return switch (cs) {
        .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .ECDHE_PSK_WITH_AES_128_GCM_SHA256,
        .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        .ECDHE_PSK_WITH_AES_256_GCM_SHA384,
        .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        .ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
        .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        => .ECDHE,
        .DHE_RSA_WITH_AES_128_GCM_SHA256,
        .DHE_PSK_WITH_AES_128_GCM_SHA256,
        .DHE_RSA_WITH_AES_256_GCM_SHA384,
        .DHE_PSK_WITH_AES_256_GCM_SHA384,
        .DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        .DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
        => .DHE,
        .RSA_WITH_AES_128_GCM_SHA256,
        .RSA_WITH_AES_256_GCM_SHA384,
        => .RSA,
        _ => unreachable,
    };
}

pub fn read_single_record(stream: *const std.net.Stream, stream_decoder: *tls.Decoder, record_decoder: *tls.Decoder, content_type: tls.ContentType, handshake_type: HandshakeType) !tls.Decoder {
    if (record_decoder.eof()) {
        try stream_decoder.readAtLeastOurAmt(stream, tls.record_header_len);
        const ct = stream_decoder.decode(tls.ContentType);
        // TODO: Check content type even without eof
        if (ct != content_type) return error.TlsUnexpectedMessage;
        const protocol_version = stream_decoder.decode(u16);
        if (protocol_version != 0x0303) return error.TlsAlertProtocolVersion;
        const record_len = stream_decoder.decode(u16);
        record_decoder.* = stream_decoder.sub(record_len);
    }
    try record_decoder.ensure(4);
    const hst = record_decoder.decode(HandshakeType);
    if (hst != handshake_type) return error.TlsUnexpectedMessage;
    const length = record_decoder.decode(u24);
    // TODO: Handle fragmentation
    const hsd = try record_decoder.sub(length);
    return hsd;
}

// hmac: crypto.auth.hmac.sha2.HmacSha256/384
fn PRF_inner(comptime Hmac: type, secret: []const u8, label: []const u8, seed: []const u8, output: []u8) void {
    var i: u32 = 0;
    const hash_len = Hmac.mac_length;
    var a0: [hash_len]u8 = undefined;
    var a1: [hash_len]u8 = undefined;
    while (true) {
        if (output.len <= i * hash_len) {
            // we do not handle truncation here
            assert(output.len == i * hash_len);
            break;
        }

        // A(i) = hmac(secret, A(i-1))
        // A(0) = _seed
        {
            var ctx = Hmac.init(secret);
            if (i == 0) {
                ctx.update(label);
                ctx.update(seed);
            } else {
                ctx.update(&a0);
            }
            ctx.final(&a1);
        }

        // Output(i) = hmac(secret, A(i) + _seed)
        // where _seed = label + seed for PRF
        {
            var ctx = Hmac.init(secret);
            ctx.update(&a1);
            ctx.update(label);
            ctx.update(seed);
            ctx.final(output[i * hash_len ..][0..hash_len]);
        }
        i += 1;
        @memcpy(&a0, &a1);
    }
}

pub fn PRF(comptime hmac: type, secret: []const u8, label: []const u8, seed: []const u8, comptime output_len: usize) [output_len]u8 {
    const hash_len = hmac.mac_length;
    const extra_len = if (output_len % hash_len == 0) 0 else hash_len - output_len % hash_len;
    const buf_len = output_len + extra_len;
    var buf: [buf_len]u8 = undefined;
    PRF_inner(hmac, secret, label, seed, &buf);
    return buf[0..output_len].*;
}
