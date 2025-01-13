const std = @import("std");

const month_names = [_][]const u8{"", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

pub fn write(writer: anytype, ts: i64) !void {
    const date = getDate(ts);
    const time = getTime(ts);

    var buf: [26]u8 = undefined;
    const formatted = try std.fmt.bufPrint(&buf, "{d:02} {s} {d} {d:02}:{d:02}:{d:02} +0000", .{date.day, month_names[date.month], date.year, time.hour, time.min, time.sec});
    return writer.writeAll(formatted);
}

const Date = struct {
    year: i16,
    month: u8,
    day: u8,
};

const Time = struct {
    hour: u8,
    min: u8,
    sec: u8,
};

fn getDate(ts: i64) Date {
    // 2000-03-01 (mod 400 year, immediately after feb29
    const leap_epoch = 946684800 + 86400 * (31 + 29);
    const days_per_400y = 365 * 400 + 97;
    const days_per_100y = 365 * 100 + 24;
    const days_per_4y = 365 * 4 + 1;

    // march-based
    const month_days = [_]u8{ 31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 31, 29 };

    const secs = ts - leap_epoch;

    var days = @divTrunc(secs, 86400);
    if (@rem(secs, 86400) < 0) {
        days -= 1;
    }

    var qc_cycles = @divTrunc(days, days_per_400y);
    var rem_days = @rem(days, days_per_400y);
    if (rem_days < 0) {
        rem_days += days_per_400y;
        qc_cycles -= 1;
    }

    var c_cycles = @divTrunc(rem_days, days_per_100y);
    if (c_cycles == 4) {
        c_cycles -= 1;
    }
    rem_days -= c_cycles * days_per_100y;

    var q_cycles = @divTrunc(rem_days, days_per_4y);
    if (q_cycles == 25) {
        q_cycles -= 1;
    }
    rem_days -= q_cycles * days_per_4y;

    var rem_years = @divTrunc(rem_days, 365);
    if (rem_years == 4) {
        rem_years -= 1;
    }
    rem_days -= rem_years * 365;

    var year = rem_years + 4 * q_cycles + 100 * c_cycles + 400 * qc_cycles + 2000;

    var month: u8 = 0;
    while (month_days[month] <= rem_days) : (month += 1) {
        rem_days -= month_days[month];
    }

    month += 2;
    if (month >= 12) {
        year += 1;
        month -= 12;
    }

    return .{
        .year = @intCast(year),
        .month = month + 1,
        .day = @intCast(rem_days + 1),
    };
}

fn getTime(ts: i64) Time {
    const seconds = @mod(ts, 86400);
    return .{
        .hour = @intCast(@divTrunc(seconds, 3600)),
        .min = @intCast(@divTrunc(@rem(seconds, 3600), 60)),
        .sec = @intCast(@rem(seconds, 60)),
    };
}
