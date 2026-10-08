# SecretStack

SecretStack is a Zig library that runs code handling secrets on a separate stack.
It wipes the whole stack and the CPU's scratch registers when your function returns.

Cryptographic code leaves a lot behind on the stack:

- Expanded keys
- Nonces
- Hash states
- Spilled registers

None of that gets cleared when the function returns.
It sits below the stack pointer until something else overwrites it.
A core dump, an uninitialized read, or another memory disclosure bug can expose it.

Can't you just zero every local by hand?
That doesn't help much, since the compiler can spill copies wherever it wants.

`SecretStack` runs your function on its own memory mapping.
On the way back, it zeros that mapping and clears the CPU's scratch registers, since those can hold secrets too.

The mapping is locked into RAM by default and sits above a guard area that catches overflows.
On Linux, it's also excluded from core dumps and wiped in forked children.

For more context, see [Zeroization, part 2: Clearing the stack and registers](https://00f.net/2026/10/06/zeroization-2/).

## Using it

```zig
const std = @import("std");
const MLKem768 = std.crypto.kem.ml_kem.MLKem768;
const SecretStack = @import("secretstack").SecretStack;

var stack: SecretStack = try .init(.{ .size = 256 * 1024 });
defer stack.deinit();

const key_pair = stack.run(MLKem768.KeyPair.generate, .{io});
const encapsulated = stack.run(MLKem768.PublicKey.encaps, .{ key_pair.public_key, io });
const shared_secret = try stack.run(MLKem768.SecretKey.decaps, .{
    key_pair.secret_key,
    &encapsulated.ciphertext,
});
```

You can pass `run` any function known at compile time and a tuple of its arguments.
It returns whatever your function returns.

Key generation and encapsulation get their randomness from the `io` you pass in, so the random seeds stay on the secret stack too.

Not sure how big the stack needs to be?

`measure` works like `run`, but also returns roughly how many bytes were used.
Set `Options.size` a bit higher to leave some room, and measure in debug builds too, since they use a lot more stack.

## Limitations

On x86_64, you need to compile with LLVM because the self-hosted backend can't assemble the AVX register wipe.
Set `.use_llvm = true` on the executable or test that imports the module, or you'll get a compile error saying so.

Only aarch64 and x86_64 are supported.
Windows isn't supported because it checks the stack pointer against the bounds stored in the thread environment block.

You can't use a `SecretStack` from two threads at the same time.
Give each thread its own stack, or keep a pool of them.
If you use the same stack concurrently, it panics instead of silently corrupting the stack.

Your function must not suspend, so it can't do evented `std.Io` operations.
Passing it an `Io` for randomness is fine with `std.Io.Threaded`, since getting random bytes never suspends there.
That's what `init.io` and `std.testing.io` are.

Only what happens inside your function is protected.
The arguments get wiped after the call, but the return value is copied back to the caller.
Any secrets you keep around afterwards are yours to clear with `std.crypto.secureZero`.

If you call `run` from code that's already on the same secret stack, it just calls your function directly.
