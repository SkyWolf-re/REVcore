//! registry.zig
//!
//! Author: skywolf
//! Date: 2025-11-20 |Last modified: 2026-04-17
//!
//! Runtime tool/widget registry for REVcore.
//! - Loads tool manifests from disk through REVSDK
//! - Converts discovered manifests into REVcore-native tool descriptors
//! - Exposes the loaded registry to the TUI and other orchestration layers
//!
//! Notes:
//! - Discovery is passive for now: manifest parsing only, no handshake yet
//! - Future revisions should extend this module with adapter validation and
//!   compatibility status tracking

const std = @import("std");
const types = @import("types.zig");
const protocol = @import("revsdk");

var loaded_tools: []types.ToolDescriptor = &.{};

pub fn loadToolsFromDir(
    allocator: std.mem.Allocator,
    tools_root_path: []const u8,
) !void {
    if (loaded_tools.len != 0) {
        deinit(allocator);
    }

    var root_dir = try std.fs.cwd().openDir(tools_root_path, .{ .iterate = true });
    defer root_dir.close();

    var iterator = root_dir.iterate();
    var tools = std.ArrayList(types.ToolDescriptor){};
    errdefer {
        for (tools.items) |tool| {
            freeToolDescriptor(allocator, tool);
        }
        tools.deinit(allocator);
    }

    while (try iterator.next()) |entry| {
        if (entry.kind != .directory) continue;

        const manifest_path = try std.fmt.allocPrint(
            allocator,
            "{s}/{s}/rev_tool.json",
            .{ tools_root_path, entry.name },
        );
        defer allocator.free(manifest_path);

        const tool = loadToolFromManifest(allocator, manifest_path) catch |err| {
            std.debug.print("SKIP {s}: {s}\n", .{
                manifest_path,
                @errorName(err),
            });
            continue;
        };

        try tools.append(allocator, tool);
    }

loaded_tools = try tools.toOwnedSlice(allocator);
}

pub fn getTools() []const types.ToolDescriptor {
    return loaded_tools;
}

pub fn toolCount() usize {
    return loaded_tools.len;
}

pub fn deinit(allocator: std.mem.Allocator) void {
    for (loaded_tools) |tool| {
        freeToolDescriptor(allocator, tool);
    }

    if (loaded_tools.len > 0) {
        allocator.free(loaded_tools);
    }

    loaded_tools = &.{};
}

fn loadToolFromManifest(
    allocator: std.mem.Allocator,
    manifest_path: []const u8,
) !types.ToolDescriptor {
    const manifest = try protocol.parseManifestFile(allocator, manifest_path);
    defer manifest.deinit(allocator);

    var widgets = try allocator.alloc(types.WidgetDescriptor, manifest.widgets.len);
    errdefer allocator.free(widgets);

    for (manifest.widgets, 0..) |w, i| {
        widgets[i] = .{
            .id = try allocator.dupe(u8, w.id),
            .name = try allocator.dupe(u8, w.name),
            .widget_type = mapWidgetType(w.widget_type),
            .min_w = w.min_w,
            .min_h = w.min_h,
        };
    }

    return .{
        .id = try allocator.dupe(u8, manifest.tool.id),
        .name = try allocator.dupe(u8, manifest.tool.name),
        .widgets = widgets,
    };
}

fn freeToolDescriptor(
    allocator: std.mem.Allocator,
    tool: types.ToolDescriptor,
) void {
    allocator.free(tool.id);
    allocator.free(tool.name);

    for (tool.widgets) |widget| {
        allocator.free(widget.id);
        allocator.free(widget.name);
    }
    allocator.free(tool.widgets);
}

fn mapWidgetType(widget_type: protocol.WidgetType) types.WidgetType {
    return switch (widget_type) {
        .table => .table,
        .text => .text,
        .summary => .list,
        .error_box => .log,
    };
}
