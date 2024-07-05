const std = @import("std");
const proc = @import("procnet.zig");
const pid = @import("procpid.zig");
const clog = @import("proc.zig");
const proces = @import("process.zig");
const c = @cImport({
    @cInclude("arpa/inet.h");
    @cInclude("signal.h");
});

pub const std_options = .{ .log_level = .err };

pub fn main() !void {
    var argsit = std.process.args();
    _ = argsit.next() orelse return error.Args;
    const port = try std.fmt.parseInt(u16, argsit.next().?, 10);

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const alloc = gpa.allocator();

    var clogged = false;

    var procs = std.ArrayList(pid.Process).init(alloc);
    defer procs.deinit();

    const tcp = try proc.read_proc_net(alloc, .V4, "/proc/net/tcp");
    defer alloc.free(tcp);
    for (tcp) |pn| {
        if (pn.V4.port == port) {
            clogged = true;
            try print_proc_net(&pn, "TCP/IPv4");
            try append_processes(alloc, pn.V4.inode, &procs);
        }
    }

    const tcp6 = try proc.read_proc_net(alloc, .V6, "/proc/net/tcp6");
    defer alloc.free(tcp6);
    for (tcp6) |pn| {
        if (pn.V6.port == port) {
            clogged = true;
            try print_proc_net(&pn, "TCP/IPv6");
            try append_processes(alloc, pn.V6.inode, &procs);
        }
    }

    const udp = try proc.read_proc_net(alloc, .V4, "/proc/net/udp");
    defer alloc.free(udp);
    for (udp) |pn| {
        if (pn.V4.port == port) {
            clogged = true;
            try print_proc_net(&pn, "UDP/IPv4");
            try append_processes(alloc, pn.V4.inode, &procs);
        }
    }

    const udp6 = try proc.read_proc_net(alloc, .V6, "/proc/net/udp6");
    defer alloc.free(udp6);
    for (udp6) |pn| {
        if (pn.V6.port == port) {
            clogged = true;
            try print_proc_net(&pn, "UDP/IPv6");
            try append_processes(alloc, pn.V6.inode, &procs);
        }
    }

    if (!clogged) {
        try std.io.getStdOut().writer().print("Port {d} looks unclogged already\n", .{port});
    } else {
        _ = try std.io.getStdOut().writer().write("Kill? ");
        var buf: [10]u8 = undefined;
        if (try std.io.getStdIn().reader().readUntilDelimiterOrEof(buf[0..], '\n')) |input| {
            const killproc = try std.fmt.parseInt(usize, input, 10);
            const process = procs.items[killproc - 1];
            _ = c.kill(@intCast(process.proc_pid.pid), c.SIGTERM);
        }
    }
}

fn append_processes(alloc: std.mem.Allocator, inode: u32, buf: *std.ArrayList(pid.Process)) !void {
    const pids = try pid.find_proc(alloc, inode);
    defer alloc.free(pids);
    try std.io.getStdOut().writer().print("\t{s: <5}{s: <10}{s: <20}{s}\n", .{ "#", "PID", "CMD", "ARGS" });

    for (pids) |p| {
        const process = try pid.resolve_process(alloc, p);
        defer process.deinit();
        try buf.append(process);

        const cmdline = try std.mem.join(alloc, " ", process.cmdline[1..]);
        defer alloc.free(cmdline);
        try std.io.getStdOut().writer().print("\t{d: <5}{d: <10}{s: <20}{s}\n", .{ buf.items.len, process.proc_pid.pid, process.comm[0 .. process.comm.len - 1], cmdline });
    }
    _ = try std.io.getStdOut().writer().write("\n");
}

fn print_proc_net(entry: *const proc.ProcNet, addr_type: []const u8) !void {
    var stdio = std.io.getStdOut();

    switch (entry.*) {
        .V4 => |v4| {
            const src_addr_pp = c.inet_ntoa(.{ .s_addr = v4.addr }); // allocates static global buffer, don't free
            try stdio.writer().print("Port {d} clogged on {s} Address {s} with socket inode {d}\n", .{ v4.port, addr_type, src_addr_pp, v4.inode });
        },
        .V6 => |v6| {
            try stdio.writer().print("Port {d} clogged on {s} Address ", .{ v6.port, addr_type });
            for (@as(*const [16]u8, @ptrCast(&v6.addr)), 0..) |h, idx| {
                if (idx % 2 == 0 and idx != 0) {
                    _ = try stdio.writer().write(":");
                }

                try stdio.writer().print("{X:0<2}", .{h});
            }
            try stdio.writer().print(" with socket inode {d}\n", .{v6.inode});
        },
    }
}
