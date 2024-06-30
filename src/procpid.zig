const std = @import("std");
const log = std.log;
const testing = std.testing;
const Allocator = std.mem.Allocator;

const c = @cImport({
    @cInclude("regex.h");
    @cInclude("regex_slim.h");
});

pub const ProcPid = struct {
    pid: u32,
    inode: u32,
    fd: u32,
};

pub const Process = struct {
    proc_pid: ProcPid,
    comm: []u8,
    cmdline: [][]u8,
    alloc: std.heap.ArenaAllocator,

    pub fn deinit(self: @This()) void {
        self.alloc.deinit();
    }
};

pub fn find_proc(alloc: Allocator, inode: u32) ![]ProcPid {
    var proc_dir = try std.fs.openDirAbsolute("/proc", .{ .iterate = true });
    defer proc_dir.close();

    const regex_t = c.alloc_regex_t() orelse {
        log.err("Could not allocate regex_t memory", .{});
        return error.RegexAllocFailed;
    };
    defer c.free_regex_t(regex_t);

    if (c.regcomp(regex_t, "^[0-9]\\{1,\\}/fd/[0-9]\\{1,\\}$", c.REG_NOSUB) != 0) {
        return error.REGCOMP;
    }

    var walker = try proc_dir.walk(alloc);
    defer walker.deinit();

    var buf = std.ArrayList(ProcPid).init(alloc);
    defer buf.deinit();

    while (true) {
        const entry = walker.next() catch |err| switch (err) {
            error.AccessDenied => continue,
            else => return err,
        } orelse {
            log.info("No more entry. Exiting.", .{});
            break;
        };

        if (c.regexec(regex_t, entry.path, 0, null, 0) == 0) {
            const stat = proc_dir.statFile(entry.path) catch |err| switch(err) {
                error.AccessDenied => continue,
                else => return err
            };

            if(stat.kind == .unix_domain_socket) {
                if(stat.inode == inode) {
                    log.info("Found procpid path {s}", .{entry.path});

                    // <pid>/fd/<fd>
                    var compit = try std.fs.path.componentIterator(entry.path);
                    const pid = try std.fmt.parseInt(u32, compit.next().?.name, 10); // parse <pid>
                    _ = compit.next().?.name; // skip /fd/
                    const fd = try std.fmt.parseInt(u32, compit.next().?.name, 10); // parse <fd>

                    try buf.append(ProcPid{
                        .pid = pid,
                        .inode = inode,
                        .fd = fd
                    });
                }
            }
        }
    }

    return buf.toOwnedSlice();
}

pub fn resolve_process(alloc: Allocator, proc_pid: ProcPid) !Process {
    var fmt_buf = [_]u8{0}**20;
    const path = try std.fmt.bufPrint(&fmt_buf, "/proc/{d}", .{proc_pid.pid});
    const proc_dir = try std.fs.openDirAbsolute(path, .{});

    var arena_alloc = std.heap.ArenaAllocator.init(alloc);

    const comm_file = try proc_dir.openFile("comm", .{});
    const comm = try comm_file.reader().readAllAlloc(arena_alloc.allocator(), 4096);

    const cmdline_file = try proc_dir.openFile("cmdline", .{});
    const cmdline_raw = try cmdline_file.reader().readAllAlloc(alloc, 4096);
    defer alloc.free(cmdline_raw);
    var cmdline_it = std.mem.splitScalar(u8, cmdline_raw, 0x0);

    var cmdline_buf = std.ArrayList([]u8).init(arena_alloc.allocator());
    defer cmdline_buf.deinit();
    while(cmdline_it.next()) |cmdline_elem| {
        try cmdline_buf.append(try arena_alloc.allocator().dupe(u8, cmdline_elem));
    }

    return Process{
        .proc_pid = proc_pid,
        .comm = comm,
        .cmdline = try cmdline_buf.toOwnedSlice(),
        .alloc = arena_alloc
    };
}
