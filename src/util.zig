const std = @import("std");

/// Return the action base name (part before `@`) from a raw action ref.
/// Example: "actions/checkout@v4" -> "actions/checkout".
pub fn actionBaseName(raw: []const u8) []const u8 {
    return if (std.mem.indexOf(u8, raw, "@")) |pos| raw[0..pos] else raw;
}

/// Build a step name from an action repo name by capitalizing the first ASCII letter.
/// Returns null on empty input or when the first character is not an ASCII letter.
/// The result is allocated on the provided allocator.
pub fn stepNameFromRepo(allocator: std.mem.Allocator, repo: []const u8) ?[]const u8 {
    if (repo.len == 0) return null;
    if (!std.ascii.isAlphabetic(repo[0])) return null;

    const buf = allocator.alloc(u8, repo.len) catch return null;
    buf[0] = std.ascii.toUpper(repo[0]);
    @memcpy(buf[1..], repo[1..]);
    return buf;
}

/// Build a step name from a `run:` command.
/// Trims the first line, caps length at 40 ASCII chars.
/// Returns null when the first line is empty or contains YAML-unsafe characters.
pub fn stepNameFromRun(allocator: std.mem.Allocator, run: []const u8) ?[]const u8 {
    // Find first newline or end of string
    const first_line_end = std.mem.indexOfScalar(u8, run, '\n') orelse run.len;
    const first_line = std.mem.trim(u8, run[0..first_line_end], " \t\r");
    if (first_line.len == 0) return null;

    // Reject characters that would require escaping in a YAML plain scalar
    for (first_line) |c| {
        if (c < 0x20) return null; // control chars
        switch (c) {
            '"', '\'', ':', '#', '&', '*', '!', '|', '>', '%', '@', '`' => return null,
            else => {},
        }
    }

    const max_len = @min(first_line.len, 40);
    return allocator.dupe(u8, first_line[0..max_len]) catch null;
}

/// ASCII-only Levenshtein distance. Returns `std.math.maxInt(usize)` for inputs
/// longer than MAX_LEN to avoid pathological allocations.
pub fn levenshteinDistance(a: []const u8, b: []const u8) usize {
    const MAX_LEN: usize = 64;
    if (a.len > MAX_LEN or b.len > MAX_LEN) return std.math.maxInt(usize);
    if (a.len == 0) return b.len;
    if (b.len == 0) return a.len;

    var prev: [MAX_LEN + 1]usize = undefined;
    var curr: [MAX_LEN + 1]usize = undefined;
    var i: usize = 0;
    while (i <= b.len) : (i += 1) prev[i] = i;

    i = 1;
    while (i <= a.len) : (i += 1) {
        curr[0] = i;
        var j: usize = 1;
        while (j <= b.len) : (j += 1) {
            const cost: usize = if (a[i - 1] == b[j - 1]) 0 else 1;
            const del = prev[j] + 1;
            const ins = curr[j - 1] + 1;
            const sub = prev[j - 1] + cost;
            curr[j] = @min(@min(del, ins), sub);
        }
        @memcpy(prev[0 .. b.len + 1], curr[0 .. b.len + 1]);
    }
    return prev[b.len];
}

test "levenshteinDistance basic cases" {
    try std.testing.expectEqual(@as(usize, 0), levenshteinDistance("abc", "abc"));
    try std.testing.expectEqual(@as(usize, 1), levenshteinDistance("chekout", "checkout"));
    try std.testing.expectEqual(@as(usize, 1), levenshteinDistance("runs", "run"));
    try std.testing.expectEqual(@as(usize, 1), levenshteinDistance("cache", "cach"));
    try std.testing.expectEqual(
        std.math.maxInt(usize),
        levenshteinDistance("a" ** 65, "b"),
    );
}

test "actionBaseName strips version suffix" {
    try std.testing.expectEqualStrings("actions/checkout", actionBaseName("actions/checkout@v4"));
    try std.testing.expectEqualStrings("actions/checkout", actionBaseName("actions/checkout@abc123"));
    try std.testing.expectEqualStrings("actions/checkout", actionBaseName("actions/checkout"));
    try std.testing.expectEqualStrings("", actionBaseName(""));
    try std.testing.expectEqualStrings("", actionBaseName("@v1"));
}

test "stepNameFromRepo capitalizes first letter" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    try std.testing.expectEqualStrings("Checkout", stepNameFromRepo(alloc, "checkout").?);
    try std.testing.expectEqualStrings("Setup-node", stepNameFromRepo(alloc, "setup-node").?);
    try std.testing.expectEqualStrings("Already", stepNameFromRepo(alloc, "Already").?);
    try std.testing.expect(stepNameFromRepo(alloc, "") == null);
    try std.testing.expect(stepNameFromRepo(alloc, "-foo") == null);
    try std.testing.expect(stepNameFromRepo(alloc, "123") == null);
}

test "stepNameFromRun trims and caps length" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    try std.testing.expectEqualStrings("echo hello", stepNameFromRun(alloc, "echo hello").?);
    try std.testing.expectEqualStrings("echo hello", stepNameFromRun(alloc, "echo hello\nnext line").?);
    try std.testing.expectEqualStrings("echo hello", stepNameFromRun(alloc, "  echo hello  \n").?);
    try std.testing.expect(stepNameFromRun(alloc, "") == null);
    try std.testing.expect(stepNameFromRun(alloc, "\n") == null);
    try std.testing.expect(stepNameFromRun(alloc, "echo 'hello'") == null); // contains quote
    try std.testing.expect(stepNameFromRun(alloc, "echo # comment") == null); // contains #
    try std.testing.expect(stepNameFromRun(alloc, "foo: bar") == null); // contains :

    const long = "a" ** 50;
    const result = stepNameFromRun(alloc, long).?;
    try std.testing.expectEqual(@as(usize, 40), result.len);
}
