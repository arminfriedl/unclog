const std = @import("std");
const sockets = @import("sockets.zig");
const process = @import("process.zig");
const c = @cImport({
    @cInclude("pwd.h");
    @cInclude("arpa/inet.h");
    @cInclude("signal.h");
});

pub const std_options = .{ .log_level = .info };

pub fn main() !void {
    var argsit = std.process.args();
    _ = argsit.next() orelse return error.Args;
    const port = try std.fmt.parseInt(u16, argsit.next().?, 10);

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const alloc = gpa.allocator();

    const pids = try print_clogs(alloc, port);
    defer alloc.free(pids);

    if (pids.len == 0) {
        return;
    }

    const kill_pids = try choose_kill();

    kill(&[_]std.posix.pid_t{
        pids[kill_pids[0]],
    });
}

fn kill(pids: []const std.posix.pid_t) void {
    for (pids) |pid| {
        if (c.kill(pid, c.SIGTERM) == 0) {
            // Wait briefly for process to exit
            std.time.sleep(100000000); // 100ms

            // Check if process still exists
            if (c.kill(pid, 0) == 0) {
                _ = c.kill(pid, c.SIGKILL); // now try with force
            }
        }
    }
}

fn choose_kill() ![]usize {
    var stdin = std.io.getStdIn().reader();
    var stdout = std.io.getStdOut().writer();

    try stdout.writeAll("Kill? ");

    var buf: [2]u8 = undefined;
    _ = try stdin.readUntilDelimiter(&buf, '\n');

    var kills = [_]usize{
        (try std.fmt.parseInt(usize, buf[0..1], 10)) - 1,
    };

    return &kills;
}

fn print_clogs(alloc: std.mem.Allocator, port: u16) ![]std.posix.pid_t {
    var writer = std.io.getStdOut().writer();
    var pids = std.ArrayList(std.posix.pid_t).init(alloc);
    defer pids.deinit(); // noop after re-owning memory at end

    const clog_sockets = try sockets.parse(alloc, null);
    defer alloc.free(clog_sockets);

    var any: bool = false;
    for (clog_sockets) |cs| {
        if (cs.port == port) any = true;
    }
    if (!any) {
        try writer.print("Port {d} looks unclogged\n", .{port});
        return &[_]std.posix.pid_t{};
    }

    try writer.print("{s: <3}{s: <10} {s: <30} {s: <12} {s: <15} {s: <10} {s: <6} {s: <5}\n", .{ "#", "Command", "Path", "Protocol", "Address", "User", "Inode", "Port" });
    var idx: usize = 1;

    for (clog_sockets) |cs| {
        if (cs.port == port) {
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
