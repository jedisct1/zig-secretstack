//! A separate stack for code that handles secrets.
//!
//! `run(s, func, args)` switches to this stack, calls a function, switches back, then clears the scratch registers and the whole stack.
//! Anything the function leaves behind never reaches the thread's own stack.
//!
//! Big fat warning: a `SecretStack` can't be shared by threads running at the same time.
//! Give each thread its own, or keep a pool of them.
//!
//! The function must not suspend (evented `std.Io` operations).

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const testing = std.testing;
const native_arch = builtin.cpu.arch;

const SecretStack = @This();

mapping: []align(std.heap.page_size_min) u8,
stack: []align(std.heap.page_size_min) u8,
in_use: std.atomic.Value(bool),
vector_wipe: VectorWipe,

pub const Options = struct {
    /// Usable stack size, rounded up to whole pages.
    size: usize = 64 * 1024,
    /// Size of the inaccessible area below the stack.
    guard_size: usize = 64 * 1024,
    /// Prevent the stack from being swapped out.
    lock: bool = true,
};

/// Returns `error.InvalidSize` if `options.size` is zero, and `error.Overflow` if the rounded sizes don't fit in a `usize`.
pub fn init(options: Options) !SecretStack {
    comptime {
        switch (native_arch) {
            .aarch64, .x86_64 => {},
            else => @compileError("SecretStack is not implemented for " ++ @tagName(native_arch)),
        }
        if (builtin.os.tag == .windows)
            @compileError("Windows checks the stack pointer against the TEB stack bounds");
        if (native_arch == .x86_64 and builtin.zig_backend != .stage2_llvm)
            @compileError("SecretStack needs -fllvm on x86_64: the self-hosted assembler can't emit the AVX register wipe");
    }

    if (options.size == 0) return error.InvalidSize;
    const page_size = std.heap.pageSize();
    const max_aligned = std.mem.alignBackward(usize, std.math.maxInt(usize), page_size);
    if (options.size > max_aligned or options.guard_size > max_aligned) return error.Overflow;
    const guard_size = std.mem.alignForward(usize, options.guard_size, page_size);
    const size = std.mem.alignForward(usize, options.size, page_size);
    const mapping_size = try std.math.add(usize, guard_size, size);

    const mapping = try posix.mmap(
        null,
        mapping_size,
        .{ .READ = true, .WRITE = true },
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    );
    errdefer posix.munmap(mapping);
    try std.process.protectMemory(mapping[0..guard_size], .{});

    const stack: []align(std.heap.page_size_min) u8 = @alignCast(mapping[guard_size..]);
    if (options.lock) try std.process.lockMemory(stack, .{});
    if (builtin.os.tag == .linux) {
        try posix.madvise(stack.ptr, stack.len, posix.MADV.DONTDUMP);
        try posix.madvise(stack.ptr, stack.len, posix.MADV.WIPEONFORK);
    }

    return .{
        .mapping = mapping,
        .stack = stack,
        .in_use = .init(false),
        .vector_wipe = .detect(),
    };
}

pub fn deinit(s: *SecretStack) void {
    std.debug.assert(!s.in_use.load(.acquire));
    posix.munmap(s.mapping);
    s.* = undefined;
}

pub fn contains(s: *const SecretStack, addr: usize) bool {
    const base = @intFromPtr(s.stack.ptr);
    return addr >= base and addr < base + s.stack.len;
}

fn ReturnType(comptime func: anytype) type {
    return @typeInfo(@TypeOf(func)).@"fn".return_type.?;
}

/// Calls `func` with `args` on the secret stack, then clears the stack and the scratch registers.
pub fn run(
    s: *SecretStack,
    comptime func: anytype,
    args: std.meta.ArgsTuple(@TypeOf(func)),
) ReturnType(func) {
    if (s.contains(@frameAddress())) return @call(.auto, func, args);
    return s.switchAndRun(func, args, null);
}

/// Like `run`, but also returns roughly how many bytes of stack were used.
pub fn measure(
    s: *SecretStack,
    comptime func: anytype,
    args: std.meta.ArgsTuple(@TypeOf(func)),
) struct { ReturnType(func), usize } {
    std.debug.assert(!s.contains(@frameAddress()));
    var used: usize = undefined;
    const result = s.switchAndRun(func, args, &used);
    return .{ result, used };
}

fn switchAndRun(
    s: *SecretStack,
    comptime func: anytype,
    args: std.meta.ArgsTuple(@TypeOf(func)),
    used: ?*usize,
) ReturnType(func) {
    if (s.in_use.swap(true, .acquire)) @panic("SecretStack used by two threads at once");
    defer s.in_use.store(false, .release);

    const Closure = struct {
        args: @TypeOf(args),
        result: ReturnType(func),

        fn entry(closure: *@This()) callconv(.c) void {
            closure.result = @call(.auto, func, closure.args);
        }
    };
    var closure: Closure = .{ .args = args, .result = undefined };
    // Runs after the result has been copied out.
    defer std.crypto.secureZero(u8, std.mem.asBytes(&closure));

    const top = @intFromPtr(s.stack.ptr) + s.stack.len;
    switch (s.vector_wipe) {
        inline else => |wipe| callOnStack(wipe, top, &closure, @ptrCast(&Closure.entry)),
    }
    if (used) |u| u.* = s.stack.len - (std.mem.findNone(u8, s.stack, &.{0}) orelse s.stack.len);
    std.crypto.secureZero(u8, s.stack);
    return closure.result;
}

/// Vector registers to clear.
/// On x86_64 we check this at runtime instead of using the target features because libc may use AVX-512 registers even in a baseline build.
const VectorWipe = switch (native_arch) {
    .x86_64 => enum {
        sse,
        avx,
        avx512,

        fn detect() @This() {
            const osxsave_avx = (1 << 27) | (1 << 28);
            if (cpuid(1, 0).ecx & osxsave_avx != osxsave_avx) return .sse;
            const xcr0 = asm volatile ("xgetbv"
                : [_] "={eax}" (-> u32),
                : [_] "{ecx}" (0),
                : .{ .edx = true });
            if (xcr0 & 0b110 != 0b110) return .sse;
            const avx512f = cpuid(0, 0).eax >= 7 and cpuid(7, 0).ebx & (1 << 16) != 0;
            if (avx512f and xcr0 & 0b1110_0000 == 0b1110_0000) return .avx512;
            return .avx;
        }

        fn cpuid(leaf: u32, subleaf: u32) struct { eax: u32, ebx: u32, ecx: u32 } {
            var eax: u32 = undefined;
            var ebx: u32 = undefined;
            var ecx: u32 = undefined;
            asm volatile ("cpuid"
                : [_] "={eax}" (eax),
                  [_] "={ebx}" (ebx),
                  [_] "={ecx}" (ecx),
                : [_] "{eax}" (leaf),
                  [_] "{ecx}" (subleaf),
                : .{ .edx = true });
            return .{ .eax = eax, .ebx = ebx, .ecx = ecx };
        }
    },
    else => enum {
        simd,

        fn detect() @This() {
            return .simd;
        }
    },
};

// These platforms reserve x18 (even when the CPU features don't say so...)
const aarch64_x18_is_scratch = native_arch == .aarch64 and
    !builtin.os.tag.isDarwin() and builtin.os.tag != .windows and
    !builtin.abi.isAndroid() and !builtin.abi.isOpenHarmony() and
    !std.Target.aarch64.featureSetHas(builtin.cpu.features, .reserve_x18);

fn wipeCode(comptime wipe: VectorWipe) []const u8 {
    @setEvalBranchQuota(100_000);
    comptime var code: []const u8 = "";
    switch (native_arch) {
        .aarch64 => {
            for (0..20) |i| {
                if (i == 18 and !aarch64_x18_is_scratch) continue;
                code = code ++ std.fmt.comptimePrint("mov x{d}, xzr\n", .{i});
            }
            for (0..32) |i| code = code ++ std.fmt.comptimePrint("movi v{d}.2d, #0\n", .{i});
        },
        .x86_64 => {
            for ([_][]const u8{ "eax", "ecx", "edx", "esi", "edi", "ebx" }) |r|
                code = code ++ "xorl %%" ++ r ++ ", %%" ++ r ++ "\n";
            for (8..12) |i| code = code ++ std.fmt.comptimePrint("xorl %%r{d}d, %%r{d}d\n", .{ i, i });
            switch (wipe) {
                .sse => for (0..16) |i| {
                    code = code ++ std.fmt.comptimePrint("pxor %%xmm{d}, %%xmm{d}\n", .{ i, i });
                },
                .avx => code = code ++ "vzeroall\n",
                .avx512 => {
                    for (16..32) |i|
                        code = code ++ std.fmt.comptimePrint("vpxord %%zmm{d}, %%zmm{d}, %%zmm{d}\n", .{ i, i, i });
                    code = code ++ "vzeroall\n";
                },
            }
        },
        else => unreachable,
    }
    return code;
}

fn clobbers() std.lang.assembly.Clobbers {
    @setEvalBranchQuota(100_000);
    var c: std.lang.assembly.Clobbers = .{ .memory = true };
    switch (native_arch) {
        .aarch64 => {
            for (0..20) |i| {
                if (i == 18 and !aarch64_x18_is_scratch) continue;
                @field(c, std.fmt.comptimePrint("x{d}", .{i})) = true;
            }
            // Not `x30`! LLVM silently ignores that name, and the link register then isn't saved in functions without a frame. Nice surprise...
            c.lr = true;
            for (0..32) |i| @field(c, std.fmt.comptimePrint("v{d}", .{i})) = true;
            c.nzcv = true;
            c.fpsr = true;
        },
        .x86_64 => {
            for ([_][]const u8{ "rax", "rcx", "rdx", "rsi", "rdi", "rbx", "r8", "r9", "r10", "r11" }) |r|
                @field(c, r) = true;
            for (0..32) |i| @field(c, std.fmt.comptimePrint("zmm{d}", .{i})) = true;
            for (0..8) |i| {
                @field(c, std.fmt.comptimePrint("st{d}", .{i})) = true;
                @field(c, std.fmt.comptimePrint("mm{d}", .{i})) = true;
            }
            c.rflags = true;
            c.dirflag = true;
            c.fpsr = true;
            c.mxcsr = true;
        },
        else => unreachable,
    }
    return c;
}

noinline fn callOnStack(
    comptime wipe: VectorWipe,
    top: usize,
    ctx: *anyopaque,
    func: *const fn (*anyopaque) callconv(.c) void,
) void {
    switch (native_arch) {
        .aarch64 => asm volatile (
            \\ mov x19, sp
            \\ mov sp, x2
            \\ blr x1
            \\ mov sp, x19
            \\
        ++ wipeCode(wipe)
            :
            : [ctx] "{x0}" (ctx),
              [func] "{x1}" (func),
              [top] "{x2}" (top),
            : clobbers()),
        .x86_64 => asm volatile (
            \\ movq %%rsp, %%rbx
            \\ movq %%rdx, %%rsp
            \\ callq *%%rsi
            \\ movq %%rbx, %%rsp
            \\
        ++ wipeCode(wipe)
            :
            : [ctx] "{rdi}" (ctx),
              [func] "{rsi}" (func),
              [top] "{rdx}" (top),
            : clobbers()),
        else => unreachable,
    }
}

const test_secret: [32]u8 = "sixteen bytes!!!and sixteen more".*;
const test_marker: u64 = 0x5ec2e75ec2e75ec2;

noinline fn spill(key: *const [32]u8, out: *[32]u8) void {
    var buf: [2048]u8 = undefined;
    for (0..buf.len / key.len) |i| @memcpy(buf[i * key.len ..][0..key.len], key);
    std.mem.doNotOptimizeAway(&buf);
    std.crypto.hash.sha2.Sha256.hash(&buf, out, .{});
}

/// How far below the caller's frame we search
const scan_depth = 128 * 1024;

noinline fn scrubBelow() void {
    const below: [*]volatile u8 = @ptrFromInt(@frameAddress() - scan_depth);
    @memset(below[0 .. scan_depth - 512], 0);
}

noinline fn foundBelow(needle: []const u8) bool {
    const below: [*]const volatile u8 = @ptrFromInt(@frameAddress() - scan_depth);
    var i: usize = 0;
    outer: while (i + needle.len <= scan_depth - 512) : (i += 1) {
        for (needle, 0..) |b, j| if (below[i + j] != b) continue :outer;
        return true;
    }
    return false;
}

test "secrets stay off the regular stack" {
    var s = try SecretStack.init(.{});
    defer s.deinit();
    var out: [32]u8 = undefined;

    scrubBelow();
    spill(&test_secret, &out);
    try testing.expect(foundBelow(test_secret[0..16]));

    scrubBelow();
    s.run(spill, .{ &test_secret, &out });
    try testing.expect(!foundBelow(test_secret[0..16]));
    try testing.expect(std.mem.allEqual(u8, s.stack, 0));
}

const RegisterDump = [128]u64;

fn leakIntoRegisters(comptime wipe: VectorWipe) fn (*anyopaque) callconv(.c) void {
    @setEvalBranchQuota(100_000);
    comptime var code: []const u8 = "";
    switch (native_arch) {
        .aarch64 => {
            for (0..18) |i| {
                if (i != 9) code = code ++ std.fmt.comptimePrint("mov x{d}, x9\n", .{i});
            }
            for (0..32) |i| code = code ++ std.fmt.comptimePrint("dup v{d}.2d, x9\n", .{i});
        },
        .x86_64 => {
            for ([_][]const u8{ "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11" }) |r|
                code = code ++ "movq %%rax, %%" ++ r ++ "\n";
            code = code ++ "movq %%rax, %%xmm0\npunpcklqdq %%xmm0, %%xmm0\n";
            for (1..16) |i| code = code ++ std.fmt.comptimePrint("movdqa %%xmm0, %%xmm{d}\n", .{i});
            if (wipe != .sse) for (0..16) |i| {
                code = code ++ std.fmt.comptimePrint("vinsertf128 $1, %%xmm0, %%ymm0, %%ymm{d}\n", .{i});
            };
        },
        else => unreachable,
    }
    const leak_code = code;
    return struct {
        fn f(_: *anyopaque) callconv(.c) void {
            switch (native_arch) {
                .aarch64 => asm volatile (leak_code
                    :
                    : [_] "{x9}" (test_marker),
                    : clobbers()),
                .x86_64 => asm volatile (leak_code
                    :
                    : [_] "{rax}" (test_marker),
                    : clobbers()),
                else => unreachable,
            }
        }
    }.f;
}

inline fn dumpRegisters(comptime wipe: VectorWipe, dump: *RegisterDump) void {
    switch (native_arch) {
        .aarch64 => asm volatile (blk: {
                @setEvalBranchQuota(100_000);
                var code: []const u8 = "";
                for (0..9) |i| {
                    code = code ++ std.fmt.comptimePrint("stp x{d}, x{d}, [x28, #{d}]\n", .{ 2 * i, 2 * i + 1, 16 * i });
                }
                for (0..16) |i| {
                    code = code ++ std.fmt.comptimePrint("stp q{d}, q{d}, [x28, #{d}]\n", .{ 2 * i, 2 * i + 1, 144 + 32 * i });
                }
                break :blk code;
            }
            :
            : [_] "{x28}" (dump),
            : .{ .memory = true }),
        .x86_64 => asm volatile (blk: {
                @setEvalBranchQuota(100_000);
                var code: []const u8 = "";
                for ([_][]const u8{ "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11" }, 0..) |r, i| {
                    code = code ++ std.fmt.comptimePrint("movq %%{s}, {d}(%%r15)\n", .{ r, 8 * i });
                }
                for (0..16) |i| {
                    code = code ++ std.fmt.comptimePrint("movdqu %%xmm{d}, {d}(%%r15)\n", .{ i, 64 + 16 * i });
                }
                if (wipe != .sse) for (0..16) |i| {
                    code = code ++ std.fmt.comptimePrint("vextractf128 $1, %%ymm{d}, {d}(%%r15)\n", .{ i, 320 + 16 * i });
                };
                break :blk code;
            }
            :
            : [_] "{r15}" (dump),
            : .{ .memory = true }),
        else => unreachable,
    }
}

noinline fn dumpAfterDirectCall(comptime wipe: VectorWipe, dump: *RegisterDump) void {
    leakIntoRegisters(wipe)(undefined);
    dumpRegisters(wipe, dump);
}

noinline fn dumpAfterSwitchedCall(comptime wipe: VectorWipe, s: *SecretStack, dump: *RegisterDump) void {
    callOnStack(wipe, @intFromPtr(s.stack.ptr) + s.stack.len, undefined, &leakIntoRegisters(wipe));
    dumpRegisters(wipe, dump);
}

test "scratch registers are cleared after the switch back" {
    var s = try SecretStack.init(.{});
    defer s.deinit();

    switch (s.vector_wipe) {
        inline else => |wipe| {
            var dump: RegisterDump = @splat(0);
            dumpAfterDirectCall(wipe, &dump);
            try testing.expect(std.mem.count(u64, &dump, &.{test_marker}) > 0);

            dump = @splat(0);
            dumpAfterSwitchedCall(wipe, &s, &dump);
            try testing.expectEqual(0, std.mem.count(u64, &dump, &.{test_marker}));
        },
    }
}

test "nested run stays on the same stack" {
    var s = try SecretStack.init(.{});
    defer s.deinit();

    const Nested = struct {
        noinline fn inner() usize {
            return @frameAddress();
        }

        fn outer(stack: *SecretStack) [2]usize {
            return .{ @frameAddress(), stack.run(inner, .{}) };
        }
    };
    const frames = s.run(Nested.outer, .{&s});
    try testing.expect(s.contains(frames[0]));
    try testing.expect(s.contains(frames[1]));
    try testing.expect(frames[1] < frames[0]);
}

test "one secret stack per thread" {
    const X25519 = std.crypto.dh.X25519;
    const Worker = struct {
        fn shared(sk: *const [32]u8, pk: *const [32]u8) ![32]u8 {
            return X25519.scalarmult(sk.*, pk.*);
        }

        fn work(seed: u8, failed: *std.atomic.Value(bool)) void {
            var s = SecretStack.init(.{}) catch return failed.store(true, .release);
            defer s.deinit();
            const pk = X25519.recoverPublicKey(test_secret);
            var sk: [32]u8 = test_secret;
            sk[0] = seed;
            for (0..200) |i| {
                sk[1] = @truncate(i);
                const expected = shared(&sk, &pk) catch unreachable;
                const got = s.run(shared, .{ &sk, &pk }) catch unreachable;
                if (!std.mem.eql(u8, &expected, &got) or !std.mem.allEqual(u8, s.stack, 0))
                    failed.store(true, .release);
            }
        }
    };

    var failed: std.atomic.Value(bool) = .init(false);
    var threads: [8]std.Thread = undefined;
    for (&threads, 0..) |*t, i| t.* = try std.Thread.spawn(.{}, Worker.work, .{ @as(u8, @intCast(i)), &failed });
    for (threads) |t| t.join();
    try testing.expect(!failed.load(.acquire));
}

test "init rounds sizes up and rejects invalid ones" {
    const page_size = std.heap.pageSize();
    var s = try SecretStack.init(.{ .size = page_size + 1, .guard_size = 1, .lock = false });
    defer s.deinit();
    try testing.expectEqual(2 * page_size, s.stack.len);
    try testing.expectEqual(3 * page_size, s.mapping.len);
    try testing.expectEqual(@intFromPtr(s.mapping.ptr) + page_size, @intFromPtr(s.stack.ptr));

    const max = std.math.maxInt(usize);
    const max_aligned = std.mem.alignBackward(usize, max, page_size);
    try testing.expectError(error.InvalidSize, SecretStack.init(.{ .size = 0, .lock = false }));
    try testing.expectError(error.Overflow, SecretStack.init(.{ .size = max, .lock = false }));
    try testing.expectError(error.Overflow, SecretStack.init(.{ .guard_size = max, .lock = false }));
    try testing.expectError(error.Overflow, SecretStack.init(.{
        .size = max_aligned,
        .guard_size = page_size,
        .lock = false,
    }));
}
