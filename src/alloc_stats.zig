//! Process-wide allocation and phase counters, used by the CLI when built
//! with `-Dalloc-stats`.
//!
//! The wrapper sits in front of the same parent the uninstrumented binary
//! uses (`smp_allocator` in ReleaseFast, `DebugAllocator` otherwise), so the
//! counts are the allocations the process actually makes rather than a
//! Debug-only picture. The wrap is not free: do not compare wall time from
//! an instrumented binary with `--perf`.

const std = @import("std");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;

pub const line_prefix = "alloc-stats: ";

pub const Phase = enum {
    startup,
    args,
    config,
    workspace,
    caches,
    lint_read,
    lint_yaml,
    lint_workflow,
    lint_rules,
    lint_copy,
    output,
    shutdown,
};

pub const Snapshot = struct {
    allocs: usize = 0,
    frees: usize = 0,
    remaps: usize = 0,
    bytes: usize = 0,
    peak: usize = 0,
    current: usize = 0,
    small: usize = 0,
    medium: usize = 0,
    large: usize = 0,
};

pub const PhaseSample = struct {
    ns: u64 = 0,
    allocs: usize = 0,
    bytes: usize = 0,
};

pub const CountingAllocator = struct {
    parent: Allocator,
    allocs: std.atomic.Value(usize) = .init(0),
    frees: std.atomic.Value(usize) = .init(0),
    remaps: std.atomic.Value(usize) = .init(0),
    bytes: std.atomic.Value(usize) = .init(0),
    current: std.atomic.Value(usize) = .init(0),
    peak: std.atomic.Value(usize) = .init(0),
    small: std.atomic.Value(usize) = .init(0),
    medium: std.atomic.Value(usize) = .init(0),
    large: std.atomic.Value(usize) = .init(0),

    pub fn init(parent: Allocator) CountingAllocator {
        return .{ .parent = parent };
    }

    pub fn allocator(self: *CountingAllocator) Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    pub fn snapshot(self: *const CountingAllocator) Snapshot {
        return .{
            .allocs = self.allocs.load(.monotonic),
            .frees = self.frees.load(.monotonic),
            .remaps = self.remaps.load(.monotonic),
            .bytes = self.bytes.load(.monotonic),
            .peak = self.peak.load(.monotonic),
            .current = self.current.load(.monotonic),
            .small = self.small.load(.monotonic),
            .medium = self.medium.load(.monotonic),
            .large = self.large.load(.monotonic),
        };
    }

    fn recordAlloc(self: *CountingAllocator, n: usize) void {
        _ = self.allocs.fetchAdd(1, .monotonic);
        _ = self.bytes.fetchAdd(n, .monotonic);
        recordSize(self, n);
        bumpCurrent(self, n);
    }

    fn recordGrow(self: *CountingAllocator, delta: usize) void {
        if (delta == 0) return;
        _ = self.bytes.fetchAdd(delta, .monotonic);
        bumpCurrent(self, delta);
    }

    fn recordShrink(self: *CountingAllocator, delta: usize) void {
        if (delta == 0) return;
        _ = self.current.fetchSub(delta, .monotonic);
    }

    fn bumpCurrent(self: *CountingAllocator, n: usize) void {
        const now_cur = self.current.fetchAdd(n, .monotonic) + n;
        var peak = self.peak.load(.monotonic);
        while (now_cur > peak) {
            if (self.peak.cmpxchgWeak(peak, now_cur, .monotonic, .monotonic)) |cur| {
                peak = cur;
            } else break;
        }
    }

    fn recordSize(self: *CountingAllocator, n: usize) void {
        if (n <= 64) {
            _ = self.small.fetchAdd(1, .monotonic);
        } else if (n <= 4096) {
            _ = self.medium.fetchAdd(1, .monotonic);
        } else {
            _ = self.large.fetchAdd(1, .monotonic);
        }
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: Alignment, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const ptr = self.parent.rawAlloc(len, alignment, ret_addr) orelse return null;
        self.recordAlloc(len);
        return ptr;
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        if (!self.parent.rawResize(memory, alignment, new_len, ret_addr)) return false;
        if (new_len > memory.len) {
            self.recordGrow(new_len - memory.len);
        } else {
            self.recordShrink(memory.len - new_len);
        }
        return true;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const ptr = self.parent.rawRemap(memory, alignment, new_len, ret_addr) orelse return null;
        _ = self.remaps.fetchAdd(1, .monotonic);
        if (new_len > memory.len) {
            self.recordGrow(new_len - memory.len);
        } else {
            self.recordShrink(memory.len - new_len);
        }
        return ptr;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: Alignment, ret_addr: usize) void {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        self.parent.rawFree(memory, alignment, ret_addr);
        _ = self.frees.fetchAdd(1, .monotonic);
        self.recordShrink(memory.len);
    }
};

var attached: ?*CountingAllocator = null;
var samples: [std.meta.tags(Phase).len]PhaseSample = @splat(.{});
var current_phase: Phase = .startup;
var phase_start_ns: u64 = 0;
var phase_start_allocs: usize = 0;
var phase_start_bytes: usize = 0;
var origin_ns: u64 = 0;
var tracking: bool = false;

fn nowNs() u64 {
    const ts = std.time.nanoTimestamp();
    return if (ts > 0) @intCast(ts) else 0;
}

pub fn attach(counter: *CountingAllocator) void {
    attached = counter;
    @memset(&samples, .{});
    current_phase = .startup;
    origin_ns = nowNs();
    phase_start_ns = origin_ns;
    const snap = counter.snapshot();
    phase_start_allocs = snap.allocs;
    phase_start_bytes = snap.bytes;
    tracking = true;
}

pub fn enter(phase: Phase) void {
    if (!tracking) return;
    const counter = attached orelse return;
    const t = nowNs();
    const snap = counter.snapshot();
    const idx = @intFromEnum(current_phase);
    samples[idx].ns += t -| phase_start_ns;
    samples[idx].allocs += snap.allocs -| phase_start_allocs;
    samples[idx].bytes += snap.bytes -| phase_start_bytes;
    current_phase = phase;
    phase_start_ns = t;
    phase_start_allocs = snap.allocs;
    phase_start_bytes = snap.bytes;
}

/// Peak RSS from `/proc/self/status` (`VmHWM`), in KiB. Null when the file
/// cannot be read (non-Linux, or a restricted proc).
pub fn readVmHwmKb() ?usize {
    if (builtin.os.tag != .linux) return null;
    const file = std.fs.openFileAbsolute("/proc/self/status", .{}) catch return null;
    defer file.close();
    var buf: [4096]u8 = undefined;
    const n = file.readAll(&buf) catch return null;
    return parseVmHwmKb(buf[0..n]);
}

fn parseVmHwmKb(status: []const u8) ?usize {
    const key = "VmHWM:";
    const start = std.mem.indexOf(u8, status, key) orelse return null;
    var rest = status[start + key.len ..];
    while (rest.len > 0 and (rest[0] == ' ' or rest[0] == '\t')) rest = rest[1..];
    var end: usize = 0;
    while (end < rest.len and rest[end] >= '0' and rest[end] <= '9') end += 1;
    if (end == 0) return null;
    return std.fmt.parseInt(usize, rest[0..end], 10) catch null;
}

pub fn dump(writer: *std.Io.Writer) void {
    if (!tracking) return;
    enter(.shutdown);
    const counter = attached orelse return;
    const snap = counter.snapshot();
    const rss = readVmHwmKb();
    const elapsed = nowNs() -| origin_ns;

    writer.print("{s}{{\"allocs\":{d},\"frees\":{d},\"remaps\":{d},\"bytes\":{d},\"peak\":{d},\"current\":{d},\"small\":{d},\"medium\":{d},\"large\":{d},\"elapsed_ns\":{d}", .{
        line_prefix,
        snap.allocs,
        snap.frees,
        snap.remaps,
        snap.bytes,
        snap.peak,
        snap.current,
        snap.small,
        snap.medium,
        snap.large,
        elapsed,
    }) catch return;
    if (rss) |kb| {
        writer.print(",\"rss_kb\":{d}", .{kb}) catch return;
    } else {
        writer.writeAll(",\"rss_kb\":null") catch return;
    }
    writer.writeAll(",\"phases\":{") catch return;
    var first = true;
    for (std.meta.tags(Phase), samples) |phase, sample| {
        if (sample.ns == 0 and sample.allocs == 0) continue;
        if (!first) writer.writeAll(",") catch return;
        first = false;
        writer.print("\"{s}\":{{\"ns\":{d},\"allocs\":{d},\"bytes\":{d}}}", .{
            @tagName(phase),
            sample.ns,
            sample.allocs,
            sample.bytes,
        }) catch return;
    }
    writer.writeAll("}}\n") catch return;
}

test "CountingAllocator tracks alloc, free, and peak" {
    var backing: std.heap.DebugAllocator(.{}) = .init;
    defer _ = backing.deinit();
    var counting = CountingAllocator.init(backing.allocator());
    const alloc = counting.allocator();

    const a = try alloc.alloc(u8, 100);
    const after_a = counting.snapshot();
    try std.testing.expectEqual(@as(usize, 1), after_a.allocs);
    try std.testing.expectEqual(@as(usize, 0), after_a.frees);
    try std.testing.expectEqual(@as(usize, 100), after_a.bytes);
    try std.testing.expectEqual(@as(usize, 100), after_a.peak);
    try std.testing.expectEqual(@as(usize, 100), after_a.current);
    try std.testing.expectEqual(@as(usize, 0), after_a.small);
    try std.testing.expectEqual(@as(usize, 1), after_a.medium);

    const b = try alloc.alloc(u8, 50);
    const after_b = counting.snapshot();
    try std.testing.expectEqual(@as(usize, 2), after_b.allocs);
    try std.testing.expectEqual(@as(usize, 150), after_b.peak);
    try std.testing.expectEqual(@as(usize, 1), after_b.small);

    alloc.free(b);
    const after_free = counting.snapshot();
    try std.testing.expectEqual(@as(usize, 1), after_free.frees);
    try std.testing.expectEqual(@as(usize, 100), after_free.current);
    try std.testing.expectEqual(@as(usize, 150), after_free.peak);

    alloc.free(a);
    try std.testing.expectEqual(@as(usize, 0), counting.snapshot().current);
}

test "parseVmHwmKb reads the kB integer" {
    const status =
        \\Name:\tzghalint
        \\VmPeak:\t  12345 kB
        \\VmHWM:\t    2048 kB
        \\VmRSS:\t    1024 kB
        \\
    ;
    try std.testing.expectEqual(@as(usize, 2048), parseVmHwmKb(status).?);
}

test "dump emits a single alloc-stats JSON line" {
    var backing: std.heap.DebugAllocator(.{}) = .init;
    defer _ = backing.deinit();
    var counting = CountingAllocator.init(backing.allocator());
    attach(&counting);
    defer {
        tracking = false;
        attached = null;
    }
    const buf_mem = try counting.allocator().alloc(u8, 8);
    defer counting.allocator().free(buf_mem);

    var out: [1024]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    dump(&w);
    const line = w.buffered();
    try std.testing.expect(std.mem.startsWith(u8, line, line_prefix));
    try std.testing.expect(std.mem.endsWith(u8, line, "\n"));
    try std.testing.expect(std.mem.indexOf(u8, line, "\"allocs\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"phases\":") != null);
}
