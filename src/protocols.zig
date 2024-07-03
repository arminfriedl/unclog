const std = @import("std");

pub const Protocol {
    proto: enum {
        TCP_V4,
        TCP_V6,
        UDP_V4,
        UDP_V6
    },
    port_map: std.AutoHashMap(u16, Process);
};
