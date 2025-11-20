//! types.zig
//!
//! Author: skywolf
//! Date: 2025-11-20 
//!
//! Core type definitions shared across REVcore
//! - Describes tools, widgets and workspace layout in a UI-agnostic way
//! - Centralizes enums like `WidgetType` and `LayoutMode`
//! - Provides small geometry helpers (e.g. `Rect`) used by the TUI layer
//!
//! Notes:
//! - These types deliberately avoid any OS/terminal specifics so they
//!   can be reused by headless or alternative frontends later.
//! - `WidgetDescriptor`/`ToolDescriptor` model *capabilities*,
//!   while `WidgetInstance` and `Workspace` represent concrete runtime
//!   state.
//! - When REVSDK stabilizes, some of these types may become part of the
//!   public SDK surface (at least that's the plan).


const std = @import("std");

pub const WidgetType = enum {
    table,
    list,
    hex,
    text,
    log,
};

pub const LayoutMode = enum {
    single,
    vertical_split,
    horizontal_split,
    grid2x2,
};

pub const Rect = struct {
    x: u16,
    y: u16,
    w: u16,
    h: u16,
};

pub const WidgetDescriptor = struct {
    id: []const u8,
    name: []const u8,
    widget_type: WidgetType,
    min_w: u16,
    min_h: u16,
};

pub const ToolDescriptor = struct {
    id: []const u8,
    name: []const u8,
    widgets: []const WidgetDescriptor,
};

pub const WidgetInstance = struct {
    descriptor: *const WidgetDescriptor,
    rect: Rect,
    scroll_x: i32,
    scroll_y: i32,
    focused: bool,
};

pub const Workspace = struct {
    layout: LayoutMode,
    panes: []WidgetInstance,
    focused_index: usize,
};
