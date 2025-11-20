//! main.zig
//!
//! Author: skywolf
//! Date: 2025-11-20
//!
//! Entry point for REVcore
//! - Initializes global allocators and basic terminal I/O
//! - Enters the main event loop: draw -> read key -> react
//! - Delegates visual work to the `tui` layer and data to `core` types
//!
//! Notes:
//! - For the skeleton, the loop only draws a header and a demo tool list,
//!   exiting on `q`.
//! - Later, this file will host the top-level application state
//!   (workspaces, focus, active file) and dispatch keybindings to
//!   dedicated handlers.

const std = @import("std");
const render = @import("tui/render.zig");

pub fn main() !void {
    // stdin file handle
    var stdin_file = std.fs.File.stdin();

    const width: u16 = 80;
    var buf: [1]u8 = undefined;

    while (true) {
        try render.clearScreen();
        try render.drawHeader(width);
        try render.drawToolList();

        const read_bytes = try stdin_file.read(&buf);
        if (read_bytes == 0) break; // EOF

        const ch = buf[0];
        if (ch == 'q') break;

        //later: handle more keys here
    }
}
