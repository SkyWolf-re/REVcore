//! layout.zig
//!
//! Author: skywolf
//! Date: 2025-11-20 
//!
//! Minimal layout engine for TUI
//! - Converts a `LayoutMode` + terminal width/height into pane `Rect`s
//! - Encodes basic presets: single, vertical split, horizontal split,
//!   2x2 grid, etc.
//! - Reserves space for a top status / header row
//!
//! Notes:
//! - Future work: honor per-widget `min_w`/`min_h` hints and reject
//!   layouts that would make panes unusably small.
//! - Additional layout modes (e.g. golden-ratio splits, stacked views)
//!   can be added here without touching core types.


const std = @import("std");
const types = @import("../core/types.zig");

pub fn computeRects(
    alloc: std.mem.Allocator,
    mode: types.LayoutMode,
    width: u16,
    height: u16,
) ![]types.Rect {
    return switch (mode) {
        .single => blk: {
            var rects = try alloc.alloc(types.Rect, 1);
            rects[0] = .{ .x = 0, .y = 1, .w = width, .h = height - 1 };
            break :blk rects;
        },
        .vertical_split => blk: {
            var rects = try alloc.alloc(types.Rect, 2);
            const half = width / 2;
            rects[0] = .{ .x = 0, .y = 1, .w = half, .h = height - 1 };
            rects[1] = .{ .x = half, .y = 1, .w = width - half, .h = height - 1 };
            break :blk rects;
        },
        .horizontal_split => blk: {
            var rects = try alloc.alloc(types.Rect, 2);
            const half = height / 2;
            rects[0] = .{ .x = 0, .y = 1, .w = width, .h = half - 1 };
            rects[1] = .{ .x = 0, .y = half, .w = width, .h = height - half };
            break :blk rects;
        },
        .grid2x2 => blk: {
            var rects = try alloc.alloc(types.Rect, 4);
            const half_w = width / 2;
            const half_h = (height - 1) / 2;

            rects[0] = .{ .x = 0, .y = 1, .w = half_w, .h = half_h };
            rects[1] = .{ .x = half_w, .y = 1, .w = width - half_w, .h = half_h };
            rects[2] = .{ .x = 0, .y = 1 + half_h, .w = half_w, .h = (height - 1) - half_h };
            rects[3] = .{ .x = half_w, .y = 1 + half_h, .w = width - half_w, .h = (height - 1) - half_h };
            //what a headache
            break :blk rects;
        },
    };
}
