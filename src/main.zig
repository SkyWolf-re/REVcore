//! main.zig
//!
//! Author: skywolf
//! Date: 2025-11-20 | Last modified: 2025-11-22
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
const terminal = @import("tui/terminal.zig");
const app_state = @import("core/app_state.zig");

pub fn main() !void {
    var term = try terminal.TerminalGuard.enter();
    defer term.exit();

    var stdin_file = std.fs.File.stdin();
    var buf: [1]u8 = undefined;

    const initial_size = terminal.getSize();
    var state = app_state.AppState{
        .term_width = initial_size.width,
        .term_height = initial_size.height,
    };

    while (state.running) {
        const size = terminal.getSize();
        state.term_width = size.width;
        state.term_height = size.height;

        try render.clearScreen();
        try render.drawHeader(state.term_width);
        try render.drawToolList();
        try render.drawFooter(state.term_width, state.term_height);

        const n = try stdin_file.read(&buf);
        if (n == 0) break;

        switch (buf[0]) {
            'q' => state.running = false,
            else => {},
            //more buttons ahh
        }
    }
}
