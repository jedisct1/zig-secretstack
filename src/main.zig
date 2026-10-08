//! Generates an ML-KEM-768 key pair, encapsulates a shared secret to its public key and decapsulates it, all on a secret stack.
//! Registers are cleared along with the secret stack.

const std = @import("std");
const MLKem768 = std.crypto.kem.ml_kem.MLKem768;
const SecretStack = @import("secretstack").SecretStack;

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    // ML-KEM-768 is a bit chonky in debug builds :)
    var stack: SecretStack = try .init(.{ .size = 256 * 1024 });
    defer stack.deinit();

    var key_pair = stack.run(MLKem768.KeyPair.generate, .{io});
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key_pair.secret_key));

    var encapsulated = stack.run(MLKem768.PublicKey.encaps, .{ key_pair.public_key, io });
    defer std.crypto.secureZero(u8, &encapsulated.shared_secret);

    const result, const stack_used = stack.measure(MLKem768.SecretKey.decaps, .{
        key_pair.secret_key,
        &encapsulated.ciphertext,
    });
    var shared_secret = try result;
    defer std.crypto.secureZero(u8, &shared_secret);

    if (!std.crypto.timing_safe.eql([MLKem768.shared_length]u8, shared_secret, encapsulated.shared_secret))
        return error.SharedSecretMismatch;

    var stdout_buffer: [256]u8 = undefined;
    var stdout_writer: std.Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_writer.interface;
    try stdout.print("{s} shared secrets match, ciphertext is {d} bytes\n", .{
        MLKem768.name,
        encapsulated.ciphertext.len,
    });
    try stdout.print("decapsulation used {d} of {d} secret stack bytes\n", .{ stack_used, stack.stack.len });
    try stdout.flush();
}

test "ML-KEM encapsulation and decapsulation on a secret stack" {
    const io = std.testing.io;

    var stack: SecretStack = try .init(.{ .size = 256 * 1024 });
    defer stack.deinit();

    const key_pair = stack.run(MLKem768.KeyPair.generate, .{io});
    const encapsulated = stack.run(MLKem768.PublicKey.encaps, .{ key_pair.public_key, io });
    const shared_secret = try stack.run(MLKem768.SecretKey.decaps, .{
        key_pair.secret_key,
        &encapsulated.ciphertext,
    });
    try std.testing.expectEqualSlices(u8, &encapsulated.shared_secret, &shared_secret);
    try std.testing.expect(std.mem.allEqual(u8, stack.stack, 0));
}
