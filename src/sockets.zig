//! Parse some protocol files in /proc/net directory in Linux
//!
//! Understands TCP/IPv4, TCP/IPv6, UDP/IPv4 and UDP/IPv6 which
//! are the only major protocols using ports

const std = @import("std");

/// Socket that currently clogs a port with protocol information
pub const ClogSocket = struct {
    port: u16,
    inode: std.posix.ino_t,
    uid: std.posix.uid_t,
    protocol_data: ProtocolData,

    pub fn clone(self: @This()) ClogSocket {
        return ClogSocket {
            .port = self.port,
            .inode = self.inode,
            .uid = self.uid,
            .protocol_data = self.protocol_data
        };
    }
};

/// Known protocols
pub const Protocol = enum {
    udp_v4,
    udp_v6,
    tcp_v4,
    tcp_v6,
};

/// Protocol specific data
pub const ProtocolData = union(Protocol) {
    udp_v4: struct { addr: u32 },
    udp_v6: struct { addr: u128 },
    tcp_v4: struct { addr: u32 },
    tcp_v6: struct { addr: u128 },
};

/// Parses `/proc/net` information into a flat list of ClogSockets.
///
/// Memory is owned by caller. []ClogSocket must be freed by caller.
///
/// If proc_path is `null` will default to `/proc/net`
pub fn parse(alloc: std.mem.Allocator, proc_path: ?[]u8) ![]ClogSocket {
    const base = proc_path orelse "/proc/net";

    var buf = std.ArrayList(ClogSocket).init(alloc);
    defer buf.deinit(); // noop we re-own memory to parent at the end

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const child_alloc = arena.allocator();

    const tcp_v4_path = try std.fs.path.join(child_alloc, &[_][]const u8{ base, "tcp" });
    const tcp_v6_path = try std.fs.path.join(child_alloc, &[_][]const u8{ base, "tcp6" });
    const udp_v4_path = try std.fs.path.join(child_alloc, &[_][]const u8{ base, "udp" });
    const udp_v6_path = try std.fs.path.join(child_alloc, &[_][]const u8{ base, "udp6" });

    parse_internal(tcp_v4_path, .tcp_v4, &buf) catch |err| {
        switch(err) {
            error.FileNotFound => {
                std.log.warn("{s} not found, skipping", .{tcp_v4_path});
            },
            else => return err
        }
    };

    parse_internal(tcp_v6_path, .tcp_v6, &buf) catch |err| {
        switch(err) {
            error.FileNotFound => {
                std.log.warn("{s} not found, skipping", .{tcp_v6_path});
            },
            else => return err

        }
    };

    parse_internal(udp_v4_path, .udp_v4, &buf) catch |err| {
        switch(err) {
            error.FileNotFound => {
                std.log.warn("{s} not found, skipping", .{udp_v4_path});
            },
            else => return err

        }
    };

    parse_internal(udp_v6_path, .udp_v6, &buf) catch |err| {
        switch(err) {
            error.FileNotFound => {
                std.log.warn("{s} not found, skipping", .{udp_v6_path});
            },
            else => return err
        }
    };

    return buf.toOwnedSlice();
}

// Parse a protocol file in `/proc/net`. Write results to buf.
//
// `path` must be absolute
fn parse_internal(path: []const u8, protocol: Protocol, buf: *std.ArrayList(ClogSocket)) !void {
    var file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();

    var buf_reader = std.io.bufferedReader(file.reader());
    var reader = buf_reader.reader();

    // we could conditionalize from here onwards on protocol, but we don't since
    // all known protocols look the same

    // skip header line
    try reader.skipUntilDelimiterOrEof('\n');

    const LineReader = struct {
        reader: @TypeOf(reader),

        // now the big question is, how long can a line be? frankly, I dunno,
        // one would need to check the linux source (and even then it may not be
        // reliable).
        //
        // however, we do know that lines are 150 chars long on my machine. We
        // give it enough buffer so it shouldn't be a problem. If it is, it'll
        // just fail.
        //
        // also note that this buffer is reused for each `read_line`.
        var line_buf: [256]u8 = undefined;
        fn read_line(self: @This()) !?[]const u8 {
            const line = try self.reader.readUntilDelimiterOrEof(&line_buf, '\n') orelse return null;

            return std.mem.trim(u8, line, "\n");
        }

        fn split(_: @This()) std.mem.TokenIterator(u8, .scalar) {
            return std.mem.tokenizeScalar(u8, &line_buf, ' ');
        }
    };

    var line_reader = LineReader{ .reader = reader };

    while (try line_reader.read_line()) |_| {
        var split = line_reader.split();

        // see e.g. /proc/net/tcp
        _ = split.next().?; // sl, ignore but assert it's there
        var local_address = split.next().?; //local address
        _ = split.next().?; // remote address
        _ = split.next().?; // st (state? might be interesting future extension)
        _ = split.next().?; // tx_queue:rx_queue
        _ = split.next().?; // tr:tm->when
        _ = split.next().?; // retrnsmt
        const uid = split.next().?; // uid
        _ = split.next().?; // timeout
        const inode = split.next().?; // tx_queue:rx_queue
        // ignore everything else

        try buf.append(ClogSocket{
            .port = switch (protocol) {
                .tcp_v4, .udp_v4 => try std.fmt.parseInt(u16, local_address[9..13], 16),
                .tcp_v6, .udp_v6 => try std.fmt.parseInt(u16, local_address[33..37], 16),
            },
            .inode = try std.fmt.parseInt(std.posix.ino_t, inode, 10),
            .uid = try std.fmt.parseInt(std.posix.uid_t, uid, 10),
            .protocol_data = switch (protocol) {
                .tcp_v4 => .{ .tcp_v4 = .{ .addr = try std.fmt.parseInt(u32, local_address[0..8], 16) } },
                .tcp_v6 => .{ .tcp_v6 = .{ .addr = try parse_v6_address(local_address[0..32]) } },

                .udp_v4 => .{ .udp_v4 = .{ .addr = try std.fmt.parseInt(u32, local_address[0..8], 16) } },
                .udp_v6 => .{ .udp_v6 = .{ .addr = try parse_v6_address(local_address[0..32]) } },
            },
        });
    }
}

// v6 addresses in /proc/net are not actually one big number, but an array of 4
// 32-bit (4 byte) numbers, each in base-16 little-endian (or just host byte order
// probably)
fn parse_v6_address(data: []const u8) !u128 {
    var buf: [4]u32 = undefined;

    buf[0] = try std.fmt.parseInt(u32, data[0..8], 16);
    buf[1] = try std.fmt.parseInt(u32, data[8..16], 16);
    buf[2] = try std.fmt.parseInt(u32, data[16..24], 16);
    buf[3] = try std.fmt.parseInt(u32, data[24..32], 16);

    // now do the fun stuff, just re-interpret the array as u128
    return std.mem.bytesToValue(u128, &buf);
}

test "parse_v6" {
    std.testing.log_level = .info;

    const data = "00000000000000000000000001000000";
    const r = try parse_v6_address(data);
    std.log.info("Got {d}", .{r});
}

test "parse" {
    var alloc = std.testing.allocator;

    std.testing.log_level = .info;

    const file_path = try std.fs.cwd().realpathAlloc(alloc, "./test/proc1");
    defer alloc.free(file_path);

    const clogs = try parse(alloc, file_path);
    defer alloc.free(clogs);
}
