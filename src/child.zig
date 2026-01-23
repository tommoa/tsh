//! Process Execution Primitives
//!
//! Low-level utilities for process management including fork/exec
//! configuration and wait status handling. This module provides
//! shared primitives used by both executor.zig and subshell.zig.
//!
//! POSIX Reference: Section 2.5.2 - Command Execution Environment

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;

const state = @import("state.zig");
const ExitStatus = state.ExitStatus;

/// Configuration for child process execution.
/// Used for pipe wiring and execution mode flags.
pub const ExecConfig = struct {
    /// fd to wire to stdin (null = inherit).
    stdin_fd: ?posix.fd_t = null,
    /// fd to wire to stdout (null = inherit).
    stdout_fd: ?posix.fd_t = null,
    /// Additional fds to close before exec.
    /// TODO: Used for here-docs and process substitution where children need
    /// to close fds they shouldn't inherit (e.g., write ends of here-doc pipes).
    close_fds: []const posix.fd_t = &.{},

    /// Apply pipe fd wiring. Call at start of child process.
    pub fn applyPipes(self: ExecConfig) void {
        if (self.stdin_fd) |fd| {
            posix.dup2(fd, posix.STDIN_FILENO) catch posix.exit(ExitStatus.GENERAL_ERROR);
            posix.close(fd);
        }
        if (self.stdout_fd) |fd| {
            posix.dup2(fd, posix.STDOUT_FILENO) catch posix.exit(ExitStatus.GENERAL_ERROR);
            posix.close(fd);
        }
        for (self.close_fds) |fd| {
            posix.close(fd);
        }
    }
};

/// Convert wait status to ExitStatus.
pub fn statusFromWaitResult(wait_status: u32) ExitStatus {
    if (posix.W.IFEXITED(wait_status)) {
        return .{ .exited = posix.W.EXITSTATUS(wait_status) };
    } else if (posix.W.IFSIGNALED(wait_status)) {
        return .{ .signaled = posix.W.TERMSIG(wait_status) };
    } else {
        // Stopped or other - treat as exit 1
        return .{ .exited = 1 };
    }
}

/// Errors that can occur during subshell execution.
pub const SubshellError = error{
    /// fork() system call failed.
    ForkFailed,
    /// pipe() system call failed.
    PipeFailed,
    /// Failed to read from pipe.
    ReadFailed,
} || Allocator.Error;
