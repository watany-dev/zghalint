const std = @import("std");
const zghalint = @import("zghalint");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("zghalint - GitHub Actions workflow linter\n", .{});
}

test {
    _ = zghalint;
}
