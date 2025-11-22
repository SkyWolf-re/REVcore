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
const file_handler = @import("core/file_handler.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    //var term = try terminal.TerminalGuard.enter();
    //defer term.exit();

    //var stdin_file = std.fs.File.stdin();
    //var buf: [1]u8 = undefined;

    const initial_size = terminal.getSize();
    var state = app_state.AppState{
        .term_width = initial_size.width,
        .term_height = initial_size.height,
        .file_json = null,
    };

    const argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, argv);

    if (argv.len > 1) {
        const path = std.mem.sliceTo(argv[1], 0);
        state.file_json = file_handler.runFileValidator(allocator, path) catch |err| blk: {
            std.debug.print(
                "REVcore: fileValidator failed for '{s}': {s}\n",
                .{ path, @errorName(err) },
            );
            break :blk null;
        };
    }

    //while (state.running) {
    //const size = terminal.getSize();
    //  state.term_width = size.width;
    //state.term_height = size.height;

    //try render.clearScreen();
    //try render.drawHeader(state.term_width);
    //try render.drawToolList();
    //try render.drawFooter(state.term_width, state.term_height);

    //const n = try stdin_file.read(&buf);
    //if (n == 0) break;

    //switch (buf[0]) {
    //    'q' => state.running = false,
    //    else => {},
    //    //more buttons ahh
    //}
    //}
    {
        var term = try terminal.TerminalGuard.enter();
        defer term.exit();

        var stdin_file = std.fs.File.stdin();
        var buf: [1]u8 = undefined;

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
            }
        }
    }

    // Testing purposes only
    if (state.file_json) |json| {
        std.debug.print("\n=== fileValidator JSON ===\n{s}\n", .{json});
        allocator.free(json);
        state.file_json = null;
    } else {
        std.debug.print("\n(no file_json in state; run as `REVcore <path>`)\n", .{});
    }
}
