const std = @import("std");
const process = @import("process.zig");
const sockets = @import("sockets.zig");

pub const Clogs = struct {
    items: []Clog,
    alloc: std.mem.Allocator,

    pub fn deinit(self: @This()) void {
        for(self.items) |clog| {
            clog.deinit();
        }

        self.alloc.free(self.items);
    }
};

pub const Clog = struct {
    port: u16,
    sock: sockets.ClogSocket,
    procs: process.ClogProcesses,

    alloc: std.mem.Allocator,

    pub fn deinit(self: @This()) void {
        self.procs.deinit();
    }
};

pub fn match(alloc: std.mem.Allocator, ports: []u16) !Clogs {
    var buf = std.ArrayList(Clog).init(alloc);
    defer(buf.deinit()); // noop after re-owned at end

    const socks = try sockets.parse(alloc, null);
    defer alloc.free(socks);

    for (socks) |sock| {
        if (std.mem.indexOfScalar(u16, ports, sock.port) == null) continue;

        const procs = try process.find_by_inode(alloc, sock.inode, null);
        defer procs.deinit();

        try buf.append(Clog {
            .port = sock.port,
            .sock = sock.clone(),
            .procs = try procs.clone(alloc),
            .alloc = alloc,
        });
    }

    return Clogs{
        .items = try buf.toOwnedSlice(),
        .alloc = alloc,
    };
}
