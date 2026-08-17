//! registry.zig
//!
//! Author: skywolf
//! Date: 2025-11-20 |Last modified: 2026-08-03
//!
//! Runtime tool/widget registry for REVcore.
//! - Loads tool manifests from disk through REVSDK
//! - Converts discovered manifests into REVcore-native tool descriptors
//! - Exposes the loaded registry to the TUI and other orchestration layers
//!
//! Notes:
//! - Discovery remains passive: every valid manifest begins in `.discovered`
//! - Active adapter handshakes will transition tools into ready/error states
//! - The registry owns all descriptor strings, operations, widgets and
//!   diagnostic messages

const std = @import("std");
const types = @import("types.zig");
const protocol = @import("revsdk");

var loaded_tools: []types.RegisteredTool = &.{};
var loaded_issues: []types.RegistryIssue = &.{};

pub fn getIssues() []const types.RegistryIssue {
    return loaded_issues;
}

pub fn issueCount() usize {
    return loaded_issues.len;
}
pub fn loadToolsFromDir(
    allocator: std.mem.Allocator,
    tools_root_path: []const u8,
) !void {
    if (loaded_tools.len != 0 or loaded_issues.len != 0) {
        deinit(allocator);
    }

    var root_dir = try std.fs.cwd().openDir(tools_root_path, .{ .iterate = true });
    defer root_dir.close();

    var iterator = root_dir.iterate();

    var tools = std.ArrayList(types.RegisteredTool){};
    var issues = std.ArrayList(types.RegistryIssue){};

    errdefer {
        for (tools.items) |tool| {
            freeRegisteredTool(allocator, tool);
        }
        tools.deinit(allocator);

        for (issues.items) |issue| {
            freeRegistryIssue(allocator, issue);
        }
        issues.deinit(allocator);
    }

    while (try iterator.next()) |entry| {
        if (entry.kind != .directory and entry.kind != .sym_link) {
            continue;
        }

        const manifest_path = try std.fmt.allocPrint(
            allocator,
            "{s}/{s}/rev_tool.json",
            .{ tools_root_path, entry.name },
        );
        defer allocator.free(manifest_path);

        const tool = loadToolFromManifest(
            allocator,
            manifest_path,
        ) catch |err| {
            // Allocation failures should stop loading instead of being disguised
            // as malformed manifests
            if (err == error.OutOfMemory) {
                return err;
            }

            try appendRegistryIssue(
                allocator,
                &issues,
                manifest_path,
                classifyManifestError(err),
                @errorName(err),
            );

            continue;
        };

        errdefer freeRegisteredTool(allocator, tool);
        try tools.append(allocator, tool);
    }

    const owned_tools = try tools.toOwnedSlice(allocator);
    errdefer {
        for (owned_tools) |tool| {
            freeRegisteredTool(allocator, tool);
        }

        allocator.free(owned_tools);
    }

    const owned_issues = try issues.toOwnedSlice(allocator);
    errdefer {
        for (owned_issues) |issue| {
            freeRegistryIssue(allocator, issue);
        }

        allocator.free(owned_issues);
    }

    loaded_tools = owned_tools;
    loaded_issues = owned_issues;
}

pub fn getTools() []const types.RegisteredTool {
    return loaded_tools;
}

pub fn toolCount() usize {
    return loaded_tools.len;
}

pub fn deinit(allocator: std.mem.Allocator) void {
    for (loaded_tools) |tool| {
        freeRegisteredTool(allocator, tool);
    }

    if (loaded_tools.len > 0) {
        allocator.free(loaded_tools);
    }

    for (loaded_issues) |issue| {
        freeRegistryIssue(allocator, issue);
    }

    if (loaded_issues.len > 0) {
        allocator.free(loaded_issues);
    }

    loaded_tools = &.{};
    loaded_issues = &.{};
}

fn loadToolFromManifest(
    allocator: std.mem.Allocator,
    manifest_path: []const u8,
) !types.RegisteredTool {
    const manifest = try protocol.parseManifestFile(
        allocator,
        manifest_path,
    );
    defer manifest.deinit(allocator);

    //Deriving filesystem paths
    const tool_root_view =
        std.fs.path.dirname(manifest_path) orelse
        return error.InvalidManifestPath;

    const owned_manifest_path =
        try allocator.dupe(u8, manifest_path);
    errdefer allocator.free(owned_manifest_path);

    const tool_root =
        try allocator.dupe(u8, tool_root_view);
    errdefer allocator.free(tool_root);

    const adapter_entrypoint_relative =
        manifest.adapter.entrypoint orelse
        return error.MissingAdapterEntrypoint;

    const adapter_entrypoint = try std.fs.path.join(
        allocator,
        &.{
            tool_root_view,
            adapter_entrypoint_relative,
        },
    );
    errdefer allocator.free(adapter_entrypoint);

    //Copying tool metadata
    const tool_id =
        try allocator.dupe(u8, manifest.tool.id);
    errdefer allocator.free(tool_id);

    const tool_name =
        try allocator.dupe(u8, manifest.tool.name);
    errdefer allocator.free(tool_name);

    const tool_version =
        try allocator.dupe(u8, manifest.tool.version);
    errdefer allocator.free(tool_version);

    const revsdk_version =
        try allocator.dupe(u8, manifest.revsdk_version);
    errdefer allocator.free(revsdk_version);

    //Copying operations
    var operations = try allocator.alloc(
        types.OperationDescriptor,
        manifest.operations.len,
    );

    var initialized_operations: usize = 0;

    errdefer {
        for (operations[0..initialized_operations]) |operation| {
            allocator.free(operation.id);
            allocator.free(operation.name);
        }

        allocator.free(operations);
    }

    for (manifest.operations, 0..) |operation, index| {
        const id = try allocator.dupe(u8, operation.id);
        errdefer allocator.free(id);

        const name = try allocator.dupe(u8, operation.name);
        errdefer allocator.free(name);

        operations[index] = .{
            .id = id,
            .name = name,
        };

        initialized_operations += 1;
    }

    //Copying widgets
    var widgets = try allocator.alloc(
        types.WidgetDescriptor,
        manifest.widgets.len,
    );

    var initialized_widgets: usize = 0;

    errdefer {
        for (widgets[0..initialized_widgets]) |widget| {
            freeWidgetDescriptor(allocator, widget);
        }

        allocator.free(widgets);
    }

    for (manifest.widgets, 0..) |widget, index| {
        const id = try allocator.dupe(u8, widget.id);
        errdefer allocator.free(id);

        const name = try allocator.dupe(u8, widget.name);
        errdefer allocator.free(name);

        widgets[index] = .{
            .id = id,
            .name = name,
            .widget_type = mapWidgetType(widget.type),
            .min_w = widget.min_w,
            .min_h = widget.min_h,
        };

        initialized_widgets += 1;
    }

    //Complete runtime-owned object
    return .{
        .descriptor = .{
            .id = tool_id,
            .name = tool_name,
            .version = tool_version,

            .revsdk_version = revsdk_version,

            .manifest_path = owned_manifest_path,
            .tool_root = tool_root,

            .adapter = .{
                .transport = mapAdapterTransport(
                    manifest.adapter.transport,
                ),
                .entrypoint = adapter_entrypoint,
            },

            .operations = operations,
            .widgets = widgets,
        },

        .state = .discovered,
        .status_message = null,
    };
}

fn freeRegisteredTool(
    allocator: std.mem.Allocator,
    tool: types.RegisteredTool,
) void {
    freeToolDescriptor(allocator, tool.descriptor);

    if (tool.status_message) |message| {
        allocator.free(message);
    }
}

fn freeToolDescriptor(
    allocator: std.mem.Allocator,
    tool: types.ToolDescriptor,
) void {
    allocator.free(tool.id);
    allocator.free(tool.name);
    allocator.free(tool.version);
    allocator.free(tool.revsdk_version);

    allocator.free(tool.manifest_path);
    allocator.free(tool.tool_root);

    allocator.free(tool.adapter.entrypoint);

    for (tool.operations) |operation| {
        allocator.free(operation.id);
        allocator.free(operation.name);
    }
    allocator.free(tool.operations);

    for (tool.widgets) |widget| {
        freeWidgetDescriptor(allocator, widget);
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

fn mapAdapterTransport(
    transport: protocol.Transport,
) types.AdapterTransport {
    return switch (transport) {
        .@"stdio-json" => .stdio_json,
    };
}

pub const RegistryError = error{
    ToolIndexOutOfBounds,
};

pub fn setToolState(
    allocator: std.mem.Allocator,
    tool_index: usize,
    new_state: types.ToolState,
    message: ?[]const u8,
) !void {
    if (tool_index >= loaded_tools.len) {
        return RegistryError.ToolIndexOutOfBounds;
    }

    const new_message = if (message) |text|
        try allocator.dupe(u8, text)
    else
        null;

    const tool = &loaded_tools[tool_index];

    if (tool.status_message) |old_message| {
        allocator.free(old_message);
    }

    tool.state = new_state;
    tool.status_message = new_message;
}

fn freeWidgetDescriptor(
    allocator: std.mem.Allocator,
    widget: types.WidgetDescriptor,
) void {
    allocator.free(widget.id);
    allocator.free(widget.name);
}

fn appendRegistryIssue(
    allocator: std.mem.Allocator,
    issues: *std.ArrayList(types.RegistryIssue),
    path: []const u8,
    kind: types.RegistryIssueKind,
    message: []const u8,
) !void {
    const owned_path = try allocator.dupe(u8, path);
    errdefer allocator.free(owned_path);

    const owned_message = try allocator.dupe(u8, message);
    errdefer allocator.free(owned_message);

    try issues.append(allocator, .{
        .path = owned_path,
        .kind = kind,
        .message = owned_message,
    });
}

fn classifyManifestError(err: anyerror) types.RegistryIssueKind {
    return switch (err) {
        error.FileNotFound,
        error.AccessDenied,
        error.NotDir,
        error.IsDir,
        error.InputOutput,
        => .manifest_unreadable,

        else => .manifest_invalid,
    };
}

fn freeRegistryIssue(
    allocator: std.mem.Allocator,
    issue: types.RegistryIssue,
) void {
    allocator.free(issue.path);
    allocator.free(issue.message);
}
