//! terminal.zig
//!
//! Author: skywolf
//! Date: 2025-11-22
//!
//! Low-level terminal control utilities for the TUI.
//! - Switches stdin into raw (non-canonical, no-echo) mode so single
//!   keypresses are delivered immediately
//! - Optionally enters the terminal's alternate screen buffer and hides
//!   the cursor while REVcore is running
//! - Restores the original terminal settings and screen state on exit
//!   via small RAII-style guards
//!
//! Notes:
//! - This is the only module that should talk directly to termios/OS
//!   console APIs or emit global ANSI control sequences.
//! - Higher-level rendering code (layout, widgets) should assume a
//!   clean drawing surface and never modify terminal modes itself.
//! - Current implementation targets POSIX terminals; Windows or other
//!   backends can be added here later behind the same interface

const std = @import("std");
const posix = std.posix;

pub const TermSize = struct {
    width: u16,
    height: u16,
};

//UNIX only for now, Windows support for later
pub fn getSize() TermSize {
    var ws: posix.winsize = .{
        .row = 0,
        .col = 0,
        .xpixel = 0,
        .ypixel = 0,
    };

    const fd: posix.fd_t = posix.STDOUT_FILENO;
    const rc = posix.system.ioctl(fd, posix.T.IOCGWINSZ, @intFromPtr(&ws));

    if (posix.errno(rc) != .SUCCESS or ws.col == 0 or ws.row == 0) {
        return .{ .width = 80, .height = 25 };
    }

    return .{
        .width = @intCast(ws.col),
        .height = @intCast(ws.row),
    };
}

pub const RawModeGuard = struct {
    orig: posix.termios,
    fd: posix.fd_t,

    pub fn enter() !RawModeGuard {
        const fd: posix.fd_t = posix.STDIN_FILENO;

        var tio = try posix.tcgetattr(fd);
        const orig = tio;

        tio.lflag.ICANON = false;
        tio.lflag.ECHO = false;

        try posix.tcsetattr(fd, .NOW, tio);
        return .{ .orig = orig, .fd = fd };
    }

    pub fn exit(self: *RawModeGuard) void {
        //best-effort restore - ignores errors
        _ = posix.tcsetattr(self.fd, .NOW, self.orig) catch {};
    }
};

pub const TerminalGuard = struct {
    raw: RawModeGuard,

    pub fn enter() !TerminalGuard {
        std.debug.print("\x1b[?1049h\x1b[?25l", .{});
        const raw = try RawModeGuard.enter();
        return .{ .raw = raw };
    }

    pub fn exit(self: *TerminalGuard) void {
        self.raw.exit();
        std.debug.print("\x1b[?1049l\x1b[?25h", .{});
    }
};
