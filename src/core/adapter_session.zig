//! adapter_session.zig
//!
//! Author: skywolf
//! Date: 2026-08-17
//!
//! Runtime session for one active REVenge tool adapter
//! - Launches and owns one adapter process
//! - Performs bounded REVSDK communication over stdio-json
//! - Uses resettable scratch memory for temporary protocol data
//! - Performs the active REVSDK handshake
//!
//! Notes:
//! - Persistent session state uses the caller-provided allocator
//! - Temporary request/response work uses a reusable scratch arena
//! - Scratch allocations must never escape a protocol transaction
//! - v0.1 currently supports `stdio-json` only
//! - Each stdio-json message is one compact JSON object terminated by `\n`
//! - This module is synchronous; a worker thread may call it later
//! - Registry, tool-state, and TUI updates belong to higher-level REVcore code

const std = @import("std");
const types = @import("types.zig");
const revsdk = @import("revsdk");

/// Maximum amount of scratch arena capacity retained between transactions
/// Large temporary allocations may exceed this during a transaction, but the
/// arena is shrunk back toward this limit when the transaction finishes
const SCRATCH_RETAIN_LIMIT: usize = 64 * 1024;

pub const AdapterSession = struct {
    /// Persistent allocator supplied by REVcore
    allocator: std.mem.Allocator,

    /// Temporary allocator reused between protocol transactions
    scratch: std.heap.ArenaAllocator,

    /// Session-owned adapter entrypoint
    /// This is duplicated from the registry so the session does not depend on
    /// registry descriptor memory remaining valid for its entire lifetime
    entrypoint: []u8,

    /// Heap-backed because std.process.Child retains the argv slice
    argv: [][]const u8,

    /// Running adapter child process
    child: std.process.Child,

    /// True while this session owns a spawned child process
    active: bool = true,

    /// Launches the adapter described by a registered tool
    ///
    /// This performs process startup only
    pub fn start(
        allocator: std.mem.Allocator,
        tool: *const types.RegisteredTool,
    ) !AdapterSession {
        if (tool.descriptor.adapter.transport != .stdio_json) {
            return error.UnsupportedAdapterTransport;
        }

        const entrypoint = try allocator.dupe(
            u8,
            tool.descriptor.adapter.entrypoint,
        );
        errdefer allocator.free(entrypoint);

        const argv = try allocator.alloc([]const u8, 1);
        errdefer allocator.free(argv);

        argv[0] = entrypoint;

        var child = std.process.Child.init(
            argv,
            allocator,
        );

        child.stdin_behavior = .Pipe;
        child.stdout_behavior = .Pipe;

        // Adapter diagnostics will eventually be captured separately.
        // Ignoring stderr for the first handshake implementation avoids
        // contaminating the TUI or blocking on an undrained stderr pipe
        child.stderr_behavior = .Ignore;

        try child.spawn();

        errdefer {
            _ = child.kill() catch {};
        }

        // Some POSIX spawn failures may only become visible after spawn()
        try child.waitForSpawn();

        return .{
            .allocator = allocator,
            .scratch = std.heap.ArenaAllocator.init(allocator),
            .entrypoint = entrypoint,
            .argv = argv,
            .child = child,
            .active = true,
        };
    }

    /// Performs one REVSDK handshake against the running adapter
    ///
    /// Temporary serialization and framing memory comes from the session's
    /// scratch arena. The returned Parsed value uses the persistent allocator
    /// and therefore remains valid after scratch memory is reset
    pub fn handshake(
        self: *AdapterSession,
        request_id: []const u8,
    ) !std.json.Parsed(revsdk.HandshakeResponse) {
        if (!self.active) {
            return error.AdapterNotRunning;
        }

        const scratch = self.beginTransaction();
        defer self.endTransaction();

        const request = revsdk.HandshakeRequest.init(request_id);
        try request.validate();

        const encoded_request = try std.json.Stringify.valueAlloc(
            scratch,
            request,
            .{
                .emit_null_optional_fields = false,
            },
        );

        if (encoded_request.len > revsdk.MAX_HANDSHAKE_REQUEST_SIZE) {
            return error.HandshakeRequestTooLarge;
        }

        try self.writeMessage(encoded_request);

        const response_bytes = try self.readHandshakeMessage(
            scratch,
        );

        var parsed = try std.json.parseFromSlice(
            revsdk.HandshakeResponse,
            self.allocator,
            response_bytes,
            .{
                .allocate = .alloc_always,
            },
        );
        errdefer parsed.deinit();

        try parsed.value.validateAgainst(request);

        return parsed;
    }

    /// Releases the adapter process and all session-owned memory
    pub fn deinit(self: *AdapterSession) void {
        if (self.active) {
            self.stopChild();
            self.active = false;
        }

        self.scratch.deinit();

        self.allocator.free(self.argv);
        self.argv = &.{};

        self.allocator.free(self.entrypoint);
        self.entrypoint = &.{};
    }

    /// Resets temporary transaction memory and returns its allocator
    fn beginTransaction(
        self: *AdapterSession,
    ) std.mem.Allocator {
        _ = self.scratch.reset(.{
            .retain_with_limit = SCRATCH_RETAIN_LIMIT,
        });

        return self.scratch.allocator();
    }

    /// Releases temporary transaction allocations while retaining only a small
    /// reusable arena capacity
    fn endTransaction(self: *AdapterSession) void {
        _ = self.scratch.reset(.{
            .retain_with_limit = SCRATCH_RETAIN_LIMIT,
        });
    }

    /// Writes one newline-framed JSON protocol message to adapter stdin
    fn writeMessage(
        self: *AdapterSession,
        message: []const u8,
    ) !void {
        const stdin_file = self.child.stdin orelse
            return error.AdapterStdinUnavailable;

        var buffer: [4096]u8 = undefined;
        var file_writer = stdin_file.writerStreaming(&buffer);
        const writer = &file_writer.interface;

        try writer.writeAll(message);
        try writer.writeByte('\n');
        try writer.flush();
    }

    /// Reads one bounded newline-framed handshake response
    ///
    /// Returned memory belongs to the transaction scratch allocator
    fn readHandshakeMessage(
        self: *AdapterSession,
        scratch: std.mem.Allocator,
    ) ![]u8 {
        const stdout_file = self.child.stdout orelse
            return error.AdapterStdoutUnavailable;

        // Protocol limit applies to the JSON object itself
        // The additional byte is reserved for the framing newline.
        var buffer: [revsdk.MAX_HANDSHAKE_RESPONSE_SIZE + 1]u8 = undefined;

        var file_reader = stdout_file.readerStreaming(&buffer);
        const reader = &file_reader.interface;

        const framed = reader.takeDelimiterInclusive('\n') catch |err| {
            return switch (err) {
                error.StreamTooLong => error.HandshakeResponseTooLarge,

                error.EndOfStream => error.AdapterClosedStdout,

                error.ReadFailed => error.AdapterReadFailed,
            };
        };

        // A bare newline is not a valid protocol response
        if (framed.len <= 1) {
            return error.EmptyAdapterResponse;
        }

        const response = framed[0 .. framed.len - 1];

        if (response.len > revsdk.MAX_HANDSHAKE_RESPONSE_SIZE) {
            return error.HandshakeResponseTooLarge;
        }

        return try scratch.dupe(u8, response);
    }

    /// Terminates or reaps the child process and lets Child clean up its pipes
    fn stopChild(self: *AdapterSession) void {
        if (self.child.kill()) |_| {
            return;
        } else |err| switch (err) {
            // The process exited before REVcore tried to terminate it
            // wait() still performs process/stream cleanup
            error.AlreadyTerminated => {
                _ = self.child.wait() catch {};
            },

            else => {},
        }
    }
};
