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

pub const AdapterTransport = enum {
    stdio_json,
};

pub const ToolDescriptor = struct {
    id: []u8,
    name: []u8,
    version: []u8,

    revsdk_version: []u8,

    manifest_path: []u8,
    tool_root: []u8,

    adapter: AdapterDescriptor,
    operations: []OperationDescriptor,
    widgets: []WidgetDescriptor,
};

pub const AdapterDescriptor = struct {
    transport: AdapterTransport,
    entrypoint: []u8,
};

pub const OperationDescriptor = struct {
    id: []u8,
    name: []u8,
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

pub const ToolState = enum {
    /// Manifest parsed and registered, but adapter not contacted
    discovered,

    /// REVcore is launching the adapter or waiting for its handshake
    handshaking,

    ///Adapter answered correctly and can accept invocations
    ready,

    /// Adapter could not be found, launched, or accessed
    unavailable,

    /// Adapter answered, but its identity or REVSDK version is incompatible
    incompatible,

    /// Adapter crashed, timed out, or returned malformed protocol data
    failed,
};

pub const RegisteredTool = struct {
    descriptor: ToolDescriptor,

    state: ToolState = .discovered,

    /// Human-readable diagnostic owned by the registry
    ///
    /// Examples:
    /// - "Adapter entrypoint does not exist"
    /// - "Handshake timed out"
    /// - "Expected tool id 'stringer', received 'strings'"
    status_message: ?[]u8 = null,
};

pub const RegistryIssueKind = enum {
    manifest_unreadable,
    manifest_invalid,
    allocation_failure,
};

pub const RegistryIssue = struct {
    path: []const u8,
    kind: RegistryIssueKind,
    message: []const u8,
};
