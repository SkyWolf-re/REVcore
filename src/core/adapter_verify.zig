//! adapter_verify.zig
//!
//! Author: skywolf
//! Date: 2026-08-17
//!
//! Active adapter verification for REVcore
//!
//! REVSDK validates the structure and correlation of a handshake response.
//! This module performs the REVcore-specific second stage: comparing the
//! running adapter's claims against the descriptor discovered earlier from
//! rev_tool.json.

const std = @import("std");
const types = @import("types.zig");
const revsdk = @import("revsdk");

pub const VerificationError = error{
    HandshakeRejected,

    MissingToolInfo,
    MissingAdapterInfo,

    REVSDKVersionMismatch,

    ToolIdMismatch,
    ToolNameMismatch,
    ToolVersionMismatch,

    AdapterTransportMismatch,

    OperationCountMismatch,
    OperationMismatch,

    WidgetCountMismatch,
    WidgetMismatch,
};

/// Verifies that a successful runtime handshake matches the tool descriptor
/// previously accepted during passive manifest discovery.
///
/// This function assumes normal REVSDK structural validation has already been
/// performed through `HandshakeResponse.validateAgainst()`.
///
/// It intentionally does not compare:
/// - adapter entrypoint, because that is launch metadata rather than a runtime
///   capability
/// - tool description, because it is optional descriptive metadata
///
/// Capability arrays are compared by descriptor identity rather than array
/// position. Their ordering therefore has no protocol significance.
pub fn verifyHandshake(
    descriptor: *const types.ToolDescriptor,
    response: revsdk.HandshakeResponse,
) VerificationError!void {
    if (response.status != .ok) {
        return error.HandshakeRejected;
    }

    const runtime_tool = response.tool orelse
        return error.MissingToolInfo;

    const runtime_adapter = response.adapter orelse
        return error.MissingAdapterInfo;

    if (!std.mem.eql(
        u8,
        descriptor.revsdk_version,
        response.revsdk_version,
    )) {
        return error.REVSDKVersionMismatch;
    }

    if (!std.mem.eql(
        u8,
        descriptor.id,
        runtime_tool.id,
    )) {
        return error.ToolIdMismatch;
    }

    if (!std.mem.eql(
        u8,
        descriptor.name,
        runtime_tool.name,
    )) {
        return error.ToolNameMismatch;
    }

    if (!std.mem.eql(
        u8,
        descriptor.version,
        runtime_tool.version,
    )) {
        return error.ToolVersionMismatch;
    }

    if (!transportMatches(
        descriptor.adapter.transport,
        runtime_adapter.transport,
    )) {
        return error.AdapterTransportMismatch;
    }

    if (descriptor.operations.len != response.operations.len) {
        return error.OperationCountMismatch;
    }

    for (descriptor.operations) |expected| {
        if (!containsOperation(
            response.operations,
            expected,
        )) {
            return error.OperationMismatch;
        }
    }

    if (descriptor.widgets.len != response.widgets.len) {
        return error.WidgetCountMismatch;
    }

    for (descriptor.widgets) |expected| {
        if (!containsWidget(
            response.widgets,
            expected,
        )) {
            return error.WidgetMismatch;
        }
    }
}

/// Maps REVcore's internal transport representation to the corresponding
/// REVSDK protocol transport.
fn transportMatches(
    expected: types.AdapterTransport,
    actual: revsdk.Transport,
) bool {
    return switch (expected) {
        .stdio_json => actual == .@"stdio-json",
    };
}

/// Returns true when the runtime handshake exposes an operation identical to
/// the manifest-derived REVcore descriptor.
///
/// Array order is deliberately ignored.
fn containsOperation(
    actual: []const revsdk.OperationDescriptor,
    expected: types.OperationDescriptor,
) bool {
    for (actual) |operation| {
        if (std.mem.eql(u8, expected.id, operation.id) and
            std.mem.eql(u8, expected.name, operation.name))
        {
            return true;
        }
    }

    return false;
}

/// Returns true when the runtime handshake exposes a widget identical to the
/// manifest-derived REVcore descriptor.
///
/// `@tagName()` is used because REVcore and REVSDK deliberately own separate
/// widget enums even though compatible variants share protocol names
fn containsWidget(
    actual: []const revsdk.WidgetDescriptor,
    expected: types.WidgetDescriptor,
) bool {
    for (actual) |widget| {
        if (!std.mem.eql(u8, expected.id, widget.id)) {
            continue;
        }

        if (!std.mem.eql(u8, expected.name, widget.name)) {
            continue;
        }

        if (!std.mem.eql(
            u8,
            @tagName(expected.widget_type),
            @tagName(widget.type),
        )) {
            continue;
        }

        if (expected.min_w != widget.min_w) {
            continue;
        }

        if (expected.min_h != widget.min_h) {
            continue;
        }

        return true;
    }

    return false;
}
