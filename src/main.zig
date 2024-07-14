const std = @import("std");
const builtin = @import("builtin");
const sockets = @import("sockets.zig");
const process = @import("process.zig");
const c = @cImport({
    @cInclude("pwd.h");
    @cInclude("arpa/inet.h");
    @cInclude("signal.h");
});

pub const std_options = .{ .log_level = .info };

pub fn main() !u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const alloc = gpa.allocator();

    const ports = try_parse_args(alloc) catch |err| {
        try usage();
        if (builtin.mode == std.builtin.Mode.Debug) {
            return err;
        }

        return 1;
    };
    defer alloc.free(ports);

    const pids = try print_clogs(alloc, ports);
    defer alloc.free(pids);

    if (pids.len == 0) {
        return 0;
    }

    var kills: []u16 = undefined;
    while(true) {
        kills = choose_kill(alloc, pids.len) catch |err| {
            if (builtin.mode == std.builtin.Mode.Debug) {
                try kill_usage();
                return err;
            }

            try kill_usage();
            continue;
        };
        break;
    }
    defer alloc.free(kills);

    for(kills) |k| {
        kill(pids[k-1]);
    }

    return 0;
}

fn try_parse_args(alloc: std.mem.Allocator) ![]u16 {
    var argsit = std.process.args();
    _ = argsit.next() orelse return error.Args; // program name

    return try_parse_num(alloc, &argsit);
}

fn try_parse_num(alloc: std.mem.Allocator, iterator: anytype) ![]u16 {
    var buf = std.ArrayList(u16).init(alloc);
    defer buf.deinit(); // noop after memory re-owned to caller

    argloop: while (iterator.next()) |arg| {
        if (std.mem.indexOfScalar(u8, arg, '-')) |i| {
            const port_start = try std.fmt.parseInt(u16, arg[0..i], 10);
            const port_end = try std.fmt.parseInt(u16, arg[i + 1 ..], 10);

            if (port_start > port_end+1) return error.InvalidPortRange;

            for (port_start..port_end+1) |p| {
                try buf.append(@intCast(p));
            }
            continue :argloop;
        }

        const port = try std.fmt.parseInt(u16, arg, 10);
        try buf.append(port);
    }

    return try buf.toOwnedSlice();
}

fn kill(pid: std.posix.pid_t) void {
    if (c.kill(pid, c.SIGTERM) == 0) {
        for(0..10) |_| { // wait up to 10 sec
            // Wait briefly for process to exit
            std.time.sleep(100000000); // ns = 0.1s

            // Check if process already dead
            if (c.kill(pid, 0) == -1) break;
        }
    }

    if (c.kill(pid, 0) == 0) { // Check if process still exists
        _ = c.kill(pid, c.SIGKILL); // ...and try with force
    }
}

fn choose_kill(alloc: std.mem.Allocator, choices: usize) ![]u16 {
    var stdin = std.io.getStdIn().reader();
    var stdout = std.io.getStdOut().writer();

    try stdout.writeAll("Kill? ");

    const buf = try stdin.readUntilDelimiterAlloc(alloc, '\n', 1024);
    defer alloc.free(buf);

    var iterator = std.mem.splitScalar(u8, buf, ' ');

    const kills = try try_parse_num(alloc, &iterator);
    errdefer alloc.free(kills);

    for(kills) |k| {
        if(k > choices or k < 1) {
            return error.InvalidKill;
        }
    }

    return kills;
}

fn print_clogs(alloc: std.mem.Allocator, ports: []u16) ![]std.posix.pid_t {
    var writer = std.io.getStdOut().writer();
    var pids = std.ArrayList(std.posix.pid_t).init(alloc);
    defer pids.deinit(); // noop after re-owning memory at end

    const clog_sockets = try sockets.parse(alloc, null);
    defer alloc.free(clog_sockets);

    var any: bool = false;
    for (clog_sockets) |cs| {
        if(std.mem.indexOfScalar(u16, ports, cs.port)) |_| {
            any = true;
        }
    }

    if (!any) {
        try writer.writeAll("Ports look unclogged\n");
        return &[_]std.posix.pid_t{};
    }

    try writer.print("{s: <3}{s: <10} {s: <30} {s: <12} {s: <15} {s: <10} {s: <6} {s: <5}\n", .{ "#", "Command", "Path", "Protocol", "Address", "User", "Inode", "Port" });
    var idx: usize = 1;

    for (clog_sockets) |cs| {
        if (std.mem.indexOfScalar(u16, ports, cs.port)) |_| {
            const clogs = try process.find_by_inode(alloc, cs.inode, null);
            defer clogs.deinit();

            const user = c.getpwuid(cs.uid);

            for (clogs.items) |clog| {
                switch (cs.protocol_data) {
                    // zig fmt: off
                    .tcp_v4 => |proto| {
                        var addr: [c.INET_ADDRSTRLEN:0]u8 = undefined;
                        _ = c.inet_ntop(c.AF_INET, &proto.addr, &addr, c.INET_ADDRSTRLEN);
                        try writer.print("{d: <3}{s: <10} {s: <30} {s: <12} {s: <15} {s: <10} {d: <6} {d: <5}\n", .{
                            idx,
                            clog.comm[0..@min(10, clog.comm.len)], clog.exe[0..@min(30, clog.exe.len)],
                            "TCP/IPv4", std.mem.sliceTo(&addr, 0),
                            user.*.pw_name, cs.inode, cs.port });
                    },
                    .tcp_v6 => |proto| {
                        var addr: [c.INET6_ADDRSTRLEN:0]u8 = undefined;
                        _ = c.inet_ntop(c.AF_INET6, &proto.addr, &addr, c.INET6_ADDRSTRLEN);
                        try writer.print("{d: <3}{s: <10} {s: <30} {s: <12} {s: <15} {s: <10} {d: <6} {d: <5}\n", .{
                            idx,
                            clog.comm[0..@min(10, clog.comm.len)], clog.exe[0..@min(30, clog.exe.len)],
                            "TCP/IPv6", std.mem.sliceTo(&addr, 0),
                            user.*.pw_name, cs.inode, cs.port });
                    },
                    .udp_v4 => |proto| {
                        var addr: [c.INET_ADDRSTRLEN:0]u8 = undefined;
                        _ = c.inet_ntop(c.AF_INET, &proto.addr, &addr, c.INET_ADDRSTRLEN);
                        try writer.print("{d: <3}{s: <10} {s: <30} {s: <12} {s: <15} {s: <10} {d: <6} {d: <5}\n", .{
                            idx,
                            clog.comm[0..@min(10, clog.comm.len)], clog.exe[0..@min(30, clog.exe.len)],
                            "UDP/IPv4", std.mem.sliceTo(&addr, 0),
                            user.*.pw_name, cs.inode, cs.port });
                    },
                    .udp_v6 => |proto| {
                        var addr: [c.INET6_ADDRSTRLEN:0]u8 = undefined;
                        _ = c.inet_ntop(c.AF_INET6, &proto.addr, &addr, c.INET6_ADDRSTRLEN);
                        try writer.print("{d: <3}{s: <10} {s: <30} {s: <12} {s: <15} {s: <10} {d: <6} {d: <5}\n", .{
                            idx,
                            clog.comm[0..@min(10, clog.comm.len)], clog.exe[0..@min(30, clog.exe.len)],
                            "UDP/IPv6", std.mem.sliceTo(&addr, 0),
                            user.*.pw_name, cs.inode, cs.port });
                    },
                    // zig fmt: on
                }

                try pids.append(clog.pid);
                idx += 1;
            }
        }
    }

    return pids.toOwnedSlice();
}

fn usage() !void {
    var stdout = std.io.getStdOut().writer();

    try stdout.writeAll(
        \\USAGE: unclog <port(s)>
        \\
        \\EXAMPLE:  unclog 8080
        \\          unclog 8080-9090
        \\          unclog 8080 8081 9000-9090
        \\
    );
}

fn kill_usage() !void {
    var stdout = std.io.getStdOut().writer();

    try stdout.writeAll(
        \\Invalid kill choice
        \\
        \\EXAMPLES:  1
        \\           1-3
        \\           1 3 7-9 5
        \\
    );
}
