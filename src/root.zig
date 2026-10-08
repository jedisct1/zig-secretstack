//! Run code that handles secrets on a dedicated, wiped stack.

pub const SecretStack = @import("SecretStack.zig");

test {
    _ = SecretStack;
}
