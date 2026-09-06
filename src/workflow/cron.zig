const std = @import("std");

/// POSIX 5-field cron schedule used by GitHub Actions `on.schedule`.
pub const Schedule = struct {
    minute: Field,
    hour: Field,
    dom: Field,
    month: Field,
    dow: Field,

    pub const ParseError = error{
        EmptySpec,
        Nickname,
        WrongFieldCount,
        TooManyFields,
        EmptyField,
        EmptyListElement,
        MissingStep,
        ZeroStep,
        RangeStartAfterEnd,
        EmptyToken,
        InvalidNumber,
        InvalidToken,
        OutOfRange,
        FieldMatchesNothing,
    };

    pub fn parse(spec: []const u8) ParseError!Schedule {
        const trimmed = std.mem.trim(u8, spec, " \t\r\n");
        if (trimmed.len == 0) return error.EmptySpec;
        if (trimmed[0] == '@') return error.Nickname;

        var fields: [5][]const u8 = undefined;
        var count: usize = 0;
        var it = std.mem.tokenizeAny(u8, trimmed, " \t");
        while (it.next()) |part| {
            if (count >= 5) return error.TooManyFields;
            fields[count] = part;
            count += 1;
        }
        if (count != 5) return error.WrongFieldCount;

        return .{
            .minute = try parseField(fields[0], 0, 59, null),
            .hour = try parseField(fields[1], 0, 23, null),
            .dom = try parseField(fields[2], 1, 31, null),
            .month = try parseField(fields[3], 1, 12, &month_names),
            .dow = try parseField(fields[4], 0, 7, &dow_names),
        };
    }

    pub fn errorMessage(err: ParseError) []const u8 {
        return switch (err) {
            error.EmptySpec => "empty spec string",
            error.Nickname => "nicknames such as @daily are not supported in GitHub Actions schedule events",
            error.WrongFieldCount => "expected exactly 5 fields",
            error.TooManyFields => "too many fields",
            error.EmptyField => "empty field",
            error.EmptyListElement => "empty list element in field",
            error.MissingStep => "missing step value",
            error.ZeroStep => "step must be greater than 0",
            error.RangeStartAfterEnd => "range start must not exceed range end",
            error.EmptyToken => "empty token",
            error.InvalidNumber => "invalid number",
            error.InvalidToken => "invalid field token",
            error.OutOfRange => "value out of range",
            error.FieldMatchesNothing => "field matches no values",
        };
    }

    /// Minutes since Unix epoch (1970-01-01 00:00 UTC).
    pub fn nextAfter(self: *const Schedule, from_minute: u64) ?u64 {
        const limit = from_minute + 366 * 24 * 60 * 20;
        var minute = from_minute + 1;
        while (minute < limit) {
            if (self.matches(minute)) return minute;
            minute += 1;
        }
        return null;
    }

    /// Interval between the first two scheduled runs strictly after the epoch.
    pub fn minIntervalSeconds(self: *const Schedule) ?u64 {
        const first = self.nextAfter(0) orelse return null;
        const second = self.nextAfter(first) orelse return null;
        return (second - first) * 60;
    }

    fn matches(self: *const Schedule, minute_since_epoch: u64) bool {
        const parts = decompose(minute_since_epoch);
        if (!self.minute.contains(parts.minute)) return false;
        if (!self.hour.contains(parts.hour)) return false;
        if (!self.month.contains(parts.month)) return false;

        const dom_match = self.dom.contains(parts.dom);
        const dow_match = self.dow.contains(parts.dow);
        if (self.dom.is_star and self.dow.is_star) return true;
        if (self.dom.is_star) return dow_match;
        if (self.dow.is_star) return dom_match;
        return dom_match or dow_match;
    }
};

const Field = struct {
    mask: u64,
    is_star: bool,

    fn contains(self: Field, value: u8) bool {
        if (self.is_star) return true;
        const shift: u6 = @intCast(value);
        return (self.mask & (@as(u64, 1) << shift)) != 0;
    }
};

const month_names = [_][]const u8{ "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC" };
const dow_names = [_][]const u8{ "SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT" };

const DateParts = struct {
    minute: u8,
    hour: u8,
    dom: u8,
    month: u8,
    dow: u8,
};

fn decompose(minute_since_epoch: u64) DateParts {
    const minute = @as(u8, @intCast(minute_since_epoch % 60));
    const hours_since_epoch = minute_since_epoch / 60;
    const hour = @as(u8, @intCast(hours_since_epoch % 24));
    const days = @as(i64, @intCast(hours_since_epoch / 24));
    const date = civilFromDays(days);
    const dow = @as(u8, @intCast(@mod(days + 4, 7)));
    return .{
        .minute = minute,
        .hour = hour,
        .dom = date.day,
        .month = date.month,
        .dow = dow,
    };
}

const CivilDate = struct {
    month: u8,
    day: u8,
};

fn civilFromDays(z: i64) CivilDate {
    const days = z + 719468;
    const era = if (days >= 0) @divTrunc(days, 146097) else @divTrunc(days, 146097) - 1;
    const doe = @as(u64, @intCast(days - era * 146097));
    const yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const mp = (5 * doy + 2) / 153;
    const day = @as(u8, @intCast(doy - (153 * mp + 2) / 5 + 1));
    const month = @as(u8, @intCast(if (mp < 10) mp + 3 else mp - 9));
    return .{ .month = month, .day = day };
}

fn parseField(
    spec: []const u8,
    min: u8,
    max: u8,
    names: ?[]const []const u8,
) Schedule.ParseError!Field {
    if (spec.len == 0) return error.EmptyField;

    var field = Field{ .mask = 0, .is_star = false };
    var parts = std.mem.splitScalar(u8, spec, ',');
    while (parts.next()) |part| {
        if (part.len == 0) return error.EmptyListElement;
        try addPart(&field, part, min, max, names);
    }
    if (field.mask == 0 and !field.is_star) return error.FieldMatchesNothing;
    return field;
}

fn addPart(
    field: *Field,
    part: []const u8,
    min: u8,
    max: u8,
    names: ?[]const []const u8,
) Schedule.ParseError!void {
    const slash = std.mem.indexOfScalar(u8, part, '/');
    const step_str = if (slash) |idx| part[idx + 1 ..] else null;
    const base = if (slash) |idx| part[0..idx] else part;

    const step: u32 = if (step_str) |s| blk: {
        if (s.len == 0) return error.MissingStep;
        break :blk try parseNumber(s, min, max);
    } else 1;
    if (step == 0) return error.ZeroStep;

    if (std.mem.eql(u8, base, "*")) {
        if (step == 1) field.is_star = true;
        try setRange(field, min, max, step, min, max);
        return;
    }

    const dash = std.mem.indexOfScalar(u8, base, '-');
    if (dash) |idx| {
        const start = try parseToken(base[0..idx], min, max, names);
        const end = try parseToken(base[idx + 1 ..], min, max, names);
        if (start > end) return error.RangeStartAfterEnd;
        try setRange(field, start, end, step, min, max);
        return;
    }

    const value = try parseToken(base, min, max, names);
    try setValue(field, value, min, max);
}

fn setRange(
    field: *Field,
    start: u8,
    end: u8,
    step: u32,
    field_min: u8,
    field_max: u8,
) Schedule.ParseError!void {
    var value: u32 = start;
    while (true) {
        try setValue(field, @intCast(value), field_min, field_max);
        if (value >= end) return;
        const next = value + step;
        if (next > end) return;
        value = next;
    }
}

fn setValue(field: *Field, value: u8, min: u8, max: u8) Schedule.ParseError!void {
    if (value < min or value > max) return error.OutOfRange;
    const shift: u6 = @intCast(value);
    field.mask |= @as(u64, 1) << shift;
    if (value == 7 and max == 7) field.mask |= @as(u64, 1);
}

fn parseToken(token: []const u8, min: u8, max: u8, names: ?[]const []const u8) Schedule.ParseError!u8 {
    if (token.len == 0) return error.EmptyToken;
    if (std.ascii.isDigit(token[0])) {
        return @intCast(try parseNumber(token, min, max));
    }
    if (names) |table| {
        for (table, 0..) |name, i| {
            if (token.len >= 3 and asciiEqualPrefix(name, token)) {
                const value = @as(u8, @intCast(i + min));
                if (max == 7 and value == 7) return 0;
                return value;
            }
        }
    }
    return error.InvalidToken;
}

fn asciiEqualPrefix(expected: []const u8, actual: []const u8) bool {
    const len = @min(expected.len, actual.len);
    for (expected[0..len], actual[0..len]) |a, b| {
        if (std.ascii.toUpper(a) != std.ascii.toUpper(b)) return false;
    }
    return true;
}

fn parseNumber(text: []const u8, min: u8, max: u8) Schedule.ParseError!u32 {
    if (text.len == 0) return error.InvalidNumber;
    var value: u32 = 0;
    for (text) |c| {
        if (!std.ascii.isDigit(c)) return error.InvalidNumber;
        value = value * 10 + (c - '0');
        if (value > max) return error.OutOfRange;
    }
    if (value < min) return error.OutOfRange;
    return value;
}

const testing = std.testing;

test "parse valid cron expressions" {
    _ = try Schedule.parse("0 0 * * *");
    _ = try Schedule.parse("*/30 9-17 * * MON-FRI");
    _ = try Schedule.parse("0 0 1 1 *");
}

test "parse rejects wrong field count" {
    try testing.expectError(error.WrongFieldCount, Schedule.parse("0 0 * *"));
}

test "parse rejects out of range minute" {
    try testing.expectError(error.OutOfRange, Schedule.parse("99 * * * *"));
}

test "parse rejects out of range day of week" {
    try testing.expectError(error.OutOfRange, Schedule.parse("0 0 * * 8"));
}

test "parse rejects nicknames" {
    try testing.expectError(error.Nickname, Schedule.parse("@daily"));
}

test "minIntervalSeconds every minute" {
    const sched = try Schedule.parse("* * * * *");
    try testing.expectEqual(@as(?u64, 60), sched.minIntervalSeconds());
}

test "minIntervalSeconds every three minutes" {
    const sched = try Schedule.parse("*/3 * * * *");
    try testing.expectEqual(@as(?u64, 180), sched.minIntervalSeconds());
}

test "minIntervalSeconds every five minutes" {
    const sched = try Schedule.parse("*/5 * * * *");
    try testing.expectEqual(@as(?u64, 300), sched.minIntervalSeconds());
}

test "minIntervalSeconds every four minutes is too frequent" {
    const sched = try Schedule.parse("*/4 * * * *");
    try testing.expectEqual(@as(?u64, 240), sched.minIntervalSeconds());
}

test "minIntervalSeconds comma list in minute field" {
    const sched = try Schedule.parse("0,1,2 * * * *");
    try testing.expectEqual(@as(?u64, 60), sched.minIntervalSeconds());
}

test "minIntervalSeconds wildcard minute with stepped hour matches actionlint" {
    const sched = try Schedule.parse("* */3 * * *");
    try testing.expectEqual(@as(?u64, 60), sched.minIntervalSeconds());
}
