//! registry.zig
//!
//! Author: skywolf
//! Date: 2025-11-20
//!
//! Static tool/widget registry for early REVcore prototypes
//! - Defines a hard-coded list of `ToolDescriptor` instances
//! - Each tool advertises its available widgets and human-readable name
//! - Used by the TUI to populate the tool palette and demo views
//!
//! Notes:
//! - This is intentionally simple for v0.0: no dynamic discovery,
//!   manifests or version negotiation yet.
//! - In the future, this module will likely evolve into a loader that
//!   reads tool manifests from disk/plugins and performs compatibility
//!   checks.
//! - Demo tools self-contained so they can be used as examples
//!   for external tool authors. (contributions are welcome, guys)

const std = @import("std");
const types = @import("types.zig");

const stringer_widgets = [_]types.WidgetDescriptor{
    .{
        .id = "string_table",
        .name = "String table",
        .widget_type = .table,
        .min_w = 40,
        .min_h = 10,
    },
};

//static data for testing purposes only
pub const tools = [_]types.ToolDescriptor{
    .{
        .id = "stringer",
        .name = "Stringer (demo)",
        .widgets = &stringer_widgets,
    },
};

pub fn toolCount() usize {
    return tools.len;
}
