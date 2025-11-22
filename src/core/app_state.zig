//! app_state.zig
//!
//! Author: skywolf
//! Date: 2025-11-22
//!
//! Top-level application state for REVcore.
//! - Tracks whether the main loop is running
//! - Stores current terminal size and active layout
//! - Keeps selection indices and focus info for the TUI
//!
//! Notes:
//! - This struct is intentionally small for the skeleton; new fields
//!   (active file, workspaces, etc.) should be added here rather than
//!   as globals scattered across the codebase

const std = @import("std");
const types = @import("types.zig");

pub const AppState = struct {
    running: bool = true,

    term_width: u16,
    term_height: u16,

    layout: types.LayoutMode = .single,

    active_tool_index: usize = 0,

    // later:
    // workspaces: []Workspace,
    // focused_workspace: usize,
    // status_message: ?[]const u8,
    // active_file: ?FileId,
    // and some other shit
};
