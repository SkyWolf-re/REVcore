//! adapter_runtime.zig
//!
//! Author: skywolf
//! Date: 2026-08-17
//!
//! Active adapter lifecycle orchestration.
//!
//! Connects:
//!
//!     registry
//!        |
//!        v
//!     AdapterSession
//!        |
//!        v
//!     REVSDK handshake
//!        |
//!        v
//!     adapter verification
//!        |
//!        v
//!     registry runtime state
//!
//! Handshakes are performed sequentially. Only one adapter process is active
//! during discovery verification at a time.

const std = @import("std");

const types = @import("types.zig");
const registry = @import("registry.zig");
const adapter_verify = @import("adapter_verify.zig");

const AdapterSession =
    @import("adapter_session.zig").AdapterSession;

/// Actively verify every passively discovered tool.
///
/// Each adapter is launched, handshaken, verified and then released before
/// the next tool is processed.
pub fn handshakeDiscoveredTools(
    allocator: std.mem.Allocator,
) !void {
    const tools = registry.getTools();

    for (tools, 0..) |tool, index| {
        if (tool.state != .discovered) {
            continue;
        }

        try handshakeTool(
            allocator,
            index,
        );
    }
}

/// Performs the active handshake lifecycle for one registered tool.
///
/// Ordinary adapter failures are represented through ToolState rather than
/// being propagated to the caller. Infrastructure failures such as allocation
/// failure may still propagate.
pub fn handshakeTool(
    allocator: std.mem.Allocator,
    tool_index: usize,
) !void {
    if (tool_index >= registry.toolCount()) {
        return registry.RegistryError.ToolIndexOutOfBounds;
    }

    try registry.setToolState(
        allocator,
        tool_index,
        .handshaking,
        null,
    );

    const tool = &registry.getTools()[tool_index];

    var session = AdapterSession.start(
        allocator,
        tool,
    ) catch |err| {
        try registry.setToolState(
            allocator,
            tool_index,
            .unavailable,
            @errorName(err),
        );

        return;
    };
    defer session.deinit();

    // No heap allocation is needed for the correlation identifier
    // 64 bytes is also the REVSDK v0.1 request_id limit
    var request_id_buffer: [64]u8 = undefined;

    const request_id = std.fmt.bufPrint(
        &request_id_buffer,
        "handshake-{d}",
        .{tool_index},
    ) catch unreachable;

    var response = session.handshake(
        request_id,
    ) catch |err| {
        try registry.setToolState(
            allocator,
            tool_index,
            .failed,
            @errorName(err),
        );

        return;
    };
    defer response.deinit();

    // A structurally valid handshake may still be an explicit adapter-level
    // rejection rather than a successful capability response.
    if (response.value.status == .@"error") {
        const protocol_error = response.value.@"error" orelse {
            try registry.setToolState(
                allocator,
                tool_index,
                .failed,
                "Handshake error response contained no error object",
            );

            return;
        };

        const state: types.ToolState =
            if (protocol_error.code == .UNSUPPORTED_VERSION)
                .incompatible
            else
                .failed;

        try registry.setToolState(
            allocator,
            tool_index,
            state,
            protocol_error.message,
        );

        return;
    }

    adapter_verify.verifyHandshake(
        &tool.descriptor,
        response.value,
    ) catch |err| {
        try registry.setToolState(
            allocator,
            tool_index,
            .incompatible,
            @errorName(err),
        );

        return;
    };

    try registry.setToolState(
        allocator,
        tool_index,
        .ready,
        null,
    );
}
