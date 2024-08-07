//! Find and get information about a processes

const std = @import("std");

/// A simple array of clogging processes. Mainly a memory-owning wrapper for
/// handling deallocation correctly. Call `deinit` to deallocate the memory.
///
/// Processes can be accessed via `.items`
pub const ClogProcesses = struct {
    items: []ClogProcess,
    alloc: std.mem.Allocator,

    pub fn format(value: @This(), comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.print("{any}", .{value.items});
    }

    pub fn clone(self: @This(), alloc: std.mem.Allocator) !ClogProcesses {
        var items = try alloc.alloc(ClogProcess, self.items.len);
        for(self.items, 0..) |item, idx| {
            items[idx] = try item.clone(alloc);
        }

        return ClogProcesses {
            .items = items,
            .alloc = alloc
        };
    }

    pub fn deinit(self: @This()) void {
        for (self.items) |item| {
            item.deinit();
        }
        self.alloc.free(self.items);
    }
};

/// Process metadata of a clogging process
pub const ClogProcess = struct {
    // central data
    pid: std.posix.pid_t,
    inode: std.posix.ino_t,
    fd: std.posix.fd_t,
    comm: []u8,
    exe: []u8,
    cmdline: [][]u8,

    // for housekeeping
    alloc: std.mem.Allocator,

    pub fn format(value: @This(), comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.writeAll("\nClogProcess{\n");
        try writer.print("\t.pid={d}, .inode={d}, .fd={d},\n", .{ value.pid, value.inode, value.fd });
        try writer.print("\t.comm={s}\n", .{value.comm});
        try writer.print("\t.exe={s}\n", .{value.exe});
        try writer.print("\t.cmdline={s}\n", .{value.cmdline});
        try writer.writeAll("}");
    }

    pub fn clone(self: @This(), alloc: std.mem.Allocator) !ClogProcess {
        var cmdline: [][]u8 = try alloc.alloc([]u8, self.cmdline.len);
        for(self.cmdline, 0..) |line, idx| {
            cmdline[idx] = try alloc.dupe(u8, line);
        }

        return ClogProcess {
            .pid = self.pid,
            .inode = self.inode,
            .fd = self.fd,
            .comm = try alloc.dupe(u8, self.comm),
            .exe = try alloc.dupe(u8, self.exe),
            .cmdline = cmdline,

            .alloc = alloc
        };
    }

    fn deinit(self: @This()) void {
        self.alloc.free(self.comm);
        self.alloc.free(self.exe);
        for (self.cmdline) |cl| {
            self.alloc.free(cl);
        }
        self.alloc.free(self.cmdline);
    }
};

/// Find clogging processes that hold a file handle on an inode
pub fn find_by_inode(alloc: std.mem.Allocator, inode: std.posix.ino_t, proc_path: ?[]const u8) !ClogProcesses {
    const base = proc_path orelse "/proc";

    var clogs = std.ArrayList(ClogProcess).init(alloc);
    defer clogs.deinit(); // noop we re-own memory at the end

    var proc_dir = try std.fs.openDirAbsolute(base, .{ .iterate = true });
    defer proc_dir.close();

    var process_it = PidIterator{ .it = AccessSafeIterator{ .it = proc_dir.iterate() } };
    while (try process_it.next()) |process_entry| {
        var process_dir = proc_dir.openDir(process_entry.name, .{ .iterate = true }) catch |err| switch (err) {
            error.AccessDenied => continue,
            else => return err,
        };
        defer process_dir.close();

        var fd_dir = process_dir.openDir("fd", .{ .iterate = true }) catch |err| switch (err) {
            error.AccessDenied => continue,
            else => return err,
        };
        defer fd_dir.close();

        var fd_it = FdIterator{ .it = AccessSafeIterator{ .it = fd_dir.iterate() } };
        fdit: while (try fd_it.next()) |fd_entry| {
            _ = std.fmt.parseInt(std.posix.pid_t, fd_entry.name, 10) catch continue;
            const fd_stat = fd_dir.statFile(fd_entry.name) catch |err| switch (err) {
                error.AccessDenied => continue,
                else => return err,
            };

            if (fd_stat.inode == inode) {
                std.log.debug("Found inode {d} in {s}/{s}", .{ fd_stat.inode, process_entry.name, fd_entry.name });

                const pid = try std.fmt.parseInt(std.posix.pid_t, process_entry.name, 10);
                for (clogs.items) |clog| {
                    if (clog.pid == pid) {
                        std.log.debug("pid {d} already in clogs", .{pid});
                        continue :fdit;
                    }
                }

                const pfd: ProcessFileData = try parse_process_files(alloc, &process_dir) orelse continue;

                try clogs.append(ClogProcess{
                    .pid = pid,
                    .inode = fd_stat.inode,
                    .fd = try std.fmt.parseInt(std.posix.pid_t, fd_entry.name, 10),
                    .comm = pfd.comm,
                    .cmdline = pfd.cmdline,
                    .exe = pfd.exe,
                    .alloc = alloc,
                });
            }
        }
    }

    return ClogProcesses{ .items = try clogs.toOwnedSlice(), .alloc = alloc };
}

const ProcessFileData = struct {
    comm: []u8,
    cmdline: [][]u8,
    exe: []u8,
};

fn parse_process_files(alloc: std.mem.Allocator, process_dir: *const std.fs.Dir) !?ProcessFileData {
    var comm_file = process_dir.openFile("comm", .{}) catch |err| switch (err) {
        error.AccessDenied => return null,
        else => return err,
    };
    var cmdline_file = process_dir.openFile("cmdline", .{}) catch |err| switch (err) {
        error.AccessDenied => return null,
        else => return err,
    };

    var exe_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const exe_path = process_dir.readLink("exe", &exe_path_buf) catch |err| switch (err) {
        error.AccessDenied => return null,
        else => return err,
    };

    const comm = try comm_file.readToEndAlloc(alloc, 4096);
    defer alloc.free(comm);

    var cmdline = std.ArrayList([]u8).init(alloc);
    const cmdline_raw = try cmdline_file.readToEndAlloc(alloc, 4096);
    defer alloc.free(cmdline_raw);
    var cmdline_it = std.mem.splitScalar(u8, cmdline_raw, 0x0);
    while (cmdline_it.next()) |cl| {
        try cmdline.append(try alloc.dupe(u8, std.mem.trim(u8, cl, "\n")));
    }

    return .{
        .comm = try alloc.dupe(u8, std.mem.trim(u8, comm, "\n")),
        .cmdline = try cmdline.toOwnedSlice(),
        .exe = try alloc.dupe(u8, exe_path),
    };
}

const FdIterator = struct {
    it: AccessSafeIterator,

    pub fn next(self: *@This()) !?std.fs.Dir.Entry {
        return try self.it.next();
    }
};

/// Iterator over directories that look like a process directory
const PidIterator = struct {
    it: AccessSafeIterator,

    pub fn next(self: *@This()) !?std.fs.Dir.Entry {
        while (try self.it.next()) |entry| {
            if (entry.kind == .directory) {
                _ = std.fmt.parseInt(std.posix.pid_t, entry.name, 10) catch continue;
                return entry;
            }
        }

        return null;
    }
};

/// Iterator which ignores `AccessDenied` errors from child iterator
const AccessSafeIterator = struct {
    it: std.fs.Dir.Iterator,

    pub fn next(self: *@This()) !?std.fs.Dir.Entry {
        while (true) {
            const elem = self.it.next() catch |err| switch (err) {
                error.AccessDenied => continue,
                else => return err,
            };

            if (elem) |e| {
                self.it.dir.access(e.name, .{}) catch continue;
            }

            return elem;
        }

        return null;
    }
};

test "simple" {
    std.testing.log_level = .info;

    const clogs = try find_by_inode(std.testing.allocator, 721, null);
    defer clogs.deinit();
    std.log.info("clogs: {any}", .{clogs});
}
