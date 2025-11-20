//! render.zig
//!
//! Author: skywolf
//! Date: 2025-11-20
//!
//! Low-level rendering helpers for the TUI
//! - Handles ANSI screen clearing and basic header/list drawing
//! - Renders the demo tool list from the static registry
//! - Provides the foundation for future pane and widget rendering
//!
//! Notes:
//! - For the initial skeleton, this uses `std.debug.print` directly;
//!   later it will be upgraded but for now I'm a lazy fuck.
//! - All drawing here should be deterministic so that screen updates are
//!   easy to reason about and test.
//! - Higher-level components (workspaces, widgets) should call into this
//!   module rather than printing ANSI escape codes on their own.

const std = @import("std");
const registry = @import("../core/registry.zig");

pub fn clearScreen() !void {
    // ANSI clear + home
    std.debug.print("\x1b[2J\x1b[H", .{});
}

pub fn drawHeader(width: u16) !void {
    const title = "REVcore – REVenge TUI orchestrator (skeleton)";
    const len = @min(title.len, width);
    std.debug.print("{s}\n", .{title[0..len]});
}

pub fn drawToolList() !void {
    std.debug.print("\nTools (demo registry):\n", .{});
    for (registry.tools, 0..) |tool, idx| {
        std.debug.print("  [{d}] {s} ({s})\n", .{ idx, tool.id, tool.name });
    }
    std.debug.print("\nPress q to quit\n", .{});
}
