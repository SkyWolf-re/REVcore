//! file_header.zig
//!
//! Author: skywolf
//! Date: 2025-11-22
//!
//! Bridge to the Python `fileValidator.py` script
//! - spawn `python3 scripts/fileValidator.py <path>` as a child process
//! - capture stdout as a JSON blob
//! - (optionally) validate that stdout is syntactically valid JSON
//! - return the JSON bytes to caller (REVcore will store them under `"file": {}`)
//!
//! Notes:
//! - I keep the JSON as raw bytes for now; higher-level widgets can
//!   parse it again as needed
//! - this is intentionally format-agnostic: PE / ELF / Mach-O are all
//!   handled on the Python side

const std = @import("std");

pub const Error = error{
    FileValidatorFailed,
} || std.process.Child.SpawnError || std.mem.Allocator.Error || std.json.ParseError(std.json.Scanner);

/// Run `fileValidator.py` on `file_path` and return its JSON stdout as an
/// allocator-owned slice.
///
/// On success:
///   - returns `[]u8` containing the JSON document
///   - caller owns the slice and must free it with `allocator.free`
///
/// On failure:
///   - returns `Error` (see `Error` above)
pub fn runFileValidator(
    allocator: std.mem.Allocator,
    file_path: []const u8,
) ![]u8 {
    const exe_path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(exe_path);

    const exe_dir_path = std.fs.path.dirname(exe_path) orelse ".";
    // exe_dir_path is a slice into exe_path, so it stays valid as long as exe_path lives

    const script_path = try std.fs.path.join(
        allocator,
        &.{ exe_dir_path, "..", "..", "scripts", "fileValidator.py" },
    );
    defer allocator.free(script_path);

    var child = std.process.Child.init(
        &.{ "python3", script_path, file_path },
        allocator,
    );
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    try child.spawn();

    var stdout_buf = std.ArrayList(u8).empty;
    defer stdout_buf.deinit(allocator);
    var stderr_buf = std.ArrayList(u8).empty;
    defer stderr_buf.deinit(allocator);

    try std.process.Child.collectOutput(child, allocator, &stdout_buf, &stderr_buf, 16 * 1024);

    const term = try child.wait();

    switch (term) {
        .Exited => |code| {
            if (code != 0) {
                std.debug.print("fileValidator stderr:\n{s}\n", .{stderr_buf.items});
                return error.FileValidatorFailed;
            }
        },
        else => {
            std.debug.print("fileValidator: child did not exit normally\n", .{});
            return error.FileValidatorFailed;
        },
    }

    const trimmed = std.mem.trimRight(u8, stdout_buf.items, "\r\n");

    // sanity-check JSON
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, trimmed, .{});
    parsed.deinit();

    const copy = try allocator.dupe(u8, trimmed);
    return copy;
}
