const std = @import("std");
const log = std.log;
const testing = std.testing;
const Allocator = std.mem.Allocator;

const c = @cImport({
    @cInclude("arpa/inet.h");
});


pub const ProcNet = union(enum) {
    V4: struct {
       addr: u32,
        port: u16,
        inode: u32
    },
    V6: struct {
        addr: u128,
        port: u16,
        inode: u32
    },

    pub fn format(value: @This(), comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        switch(value) {
            .V4 => |v4| {
                const src_addr_pp = c.inet_ntoa(.{.s_addr = v4.addr}); // allocates static global buffer, don't free
                try writer.print("{s: <15}{d: <10}{d}", .{src_addr_pp, v4.port, v4.inode});
            },

            .V6 => |v6| {
                for(@as(*const [16]u8, @ptrCast(&v6.addr)), 0..) |h, idx| {
                    if(idx % 2 == 0 and idx != 0) {
                        _ = try writer.write(":");
                    }

                    try writer.print("{X:0<2}", .{h});
                }

                try writer.print("\t{d: <10}{d}", .{v6.port, v6.inode});
            },

            .RAW => |raw| {
                try writer.print("{d} {d}", .{raw.port, raw.inode});
            }

        }
    }
};

pub fn read_proc_net(alloc: Allocator, comptime addr_len: enum{V4, V6}, path: []const u8) ![]ProcNet {
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const proc_net_parsed: [][3][]u8 = try parse_proc_net(arena.allocator(), path);

    var buf = try std.ArrayList(ProcNet).initCapacity(alloc, proc_net_parsed.len);
    defer buf.deinit();

    const addr_len_t = switch(addr_len){.V4 => u32, .V6 => u128};

    for(proc_net_parsed) |line| {
        const src_addr = try std.fmt.parseUnsigned(addr_len_t, line[0], 16);
        const src_port = try std.fmt.parseUnsigned(u16, line[1], 16);
        const inode = try std.fmt.parseUnsigned(u32, line[2], 10);


        try buf.append(
            switch(addr_len) {
                .V4 =>  ProcNet{.V4 = .{.addr = src_addr, .port = src_port, .inode = inode}},
                .V6 => ProcNet{.V6 = .{.addr = src_addr, .port = src_port, .inode = inode}},
            }
        );
    }

    return buf.toOwnedSlice();
}

fn parse_proc_net(alloc: Allocator, path: []const u8) ![][3][]u8 {
    var proc_net_file = try std.fs.openFileAbsolute(path, .{});
    defer proc_net_file.close();

    var buf_reader = std.io.bufferedReader(proc_net_file.reader());
    var reader = buf_reader.reader();

    try reader.skipUntilDelimiterOrEof('\n'); // skip header

    // allocates caller-owned memory
    var res = std.ArrayList([3][]u8).init(alloc);
    defer res.deinit();

    // used for internal allocations, owned
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    while(try reader.readUntilDelimiterOrEofAlloc(arena.allocator(), '\n', 256)) |line| {

        var tokens = std.ArrayList([]const u8).init(arena.allocator()); // buffer for a line in the proc file split by tokenizer
        defer tokens.deinit();
        var tokenizer = std.mem.tokenize(u8, line, " \t\n");
        while(tokenizer.next()) |elem| { try tokens.append(elem); }

        var src_it = std.mem.splitScalar(u8, tokens.items[1], ':');

        try res.append(
            .{
                try alloc.dupe(u8, src_it.next().?),
                try alloc.dupe(u8, src_it.next().?),
                try alloc.dupe(u8, tokens.items[9])
            }
        );
    }

    return res.toOwnedSlice();
}

// test "basic 2" {
//     std.testing.log_level = .info;
//     const alloc = std.testing.allocator;
//     try read_proc_net(alloc);
// }

test "basic 3" {
    std.testing.log_level = .info;
    const alloc = std.testing.allocator;

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    const res = try parse_proc_net(arena.allocator(), "/proc/net/tcp");
    for(res) |line| {
        for(line) |field| {
            std.debug.print("{s}\t", .{field});
        }
        std.debug.print("\n", .{});
    }
}

test "basic 4" {
    std.testing.log_level = .info;
    const alloc = std.testing.allocator;

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    const res = try read_proc_net(arena.allocator(), .V4, "/proc/net/tcp");
    for(res) |pn| {
        std.debug.print("{any}\n", .{pn});
    }
}

test "basic 5" {
    std.testing.log_level = .info;
    const alloc = std.testing.allocator;

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    const res = try read_proc_net(arena.allocator(), .V6, "/proc/net/tcp6");
    for(res) |pn| {
        std.debug.print("{any}\n", .{pn});
    }
}

test "basic 6" {
    std.testing.log_level = .info;
    const alloc = std.testing.allocator;

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    const res = try read_proc_net(arena.allocator(), .V4, "/proc/net/udp");
    for(res) |pn| {
        std.debug.print("{any}\n", .{pn});
    }
}

test "basic 7" {
    std.testing.log_level = .info;
    const alloc = std.testing.allocator;

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    const res = try read_proc_net(arena.allocator(), .V6, "/proc/net/udp6");
    for(res) |pn| {
        std.debug.print("{any}\n", .{pn});
    }
}
