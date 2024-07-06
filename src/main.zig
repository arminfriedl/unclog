const std = @import("std");
const sockets = @import("sockets.zig");
const process = @import("process.zig");

pub const std_options = .{ .log_level = .info };

pub fn main() !void {
    var argsit = std.process.args();
    _ = argsit.next() orelse return error.Args;
    const port = try std.fmt.parseInt(u16, argsit.next().?, 10);

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const alloc = gpa.allocator();

    const clog_sockets = try sockets.parse(alloc, null);
    defer alloc.free(clog_sockets);

    for (clog_sockets) |clog_socket| {
        if (clog_socket.port == port) {
            const p = try process.find_by_inode(alloc, clog_socket.inode, null);
            defer p.deinit();
            switch (clog_socket.protocol_data) {
                .tcp_v4 => |v4| std.log.info("Found process {any} clogging address {any}", .{ p, v4.addr }),
                .udp_v4 => |v4| std.log.info("Found process {any} clogging address {any}", .{ p, v4.addr }),
                .tcp_v6 => |v6| std.log.info("Found process {any} clogging address {any}", .{ p, v6.addr }),
                .udp_v6 => |v6| std.log.info("Found process {any} clogging address {any}", .{ p, v6.addr }),
            }
        }
    }
}
