//! Subshell Execution Primitives
//!
//! This module provides primitives for executing commands in subshells,
//! including capturing output for command substitution.
//!
//! POSIX Reference: Section 2.6.3 - Command Substitution

const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const fs = std.fs;

const child = @import("child.zig");
const executor = @import("executor.zig");
const parser = @import("parser.zig");
const state = @import("state.zig");

const CompoundList = parser.CompoundList;
const ShellState = state.ShellState;
const ExitStatus = state.ExitStatus;
const printError = state.printError;
const statusFromWaitResult = child.statusFromWaitResult;
const SubshellError = child.SubshellError;

/// Execute commands in a subshell and capture stdout.
///
/// This function:
/// 1. Creates a pipe for capturing output
/// 2. Forks a child process
/// 3. Executes the commands in the child with stdout redirected to the pipe
/// 4. Reads all output from the pipe in the parent
/// 5. Strips trailing newlines per POSIX 2.6.3
/// 6. Updates shell_state.last_status with the command's exit status
///
/// POSIX Reference: Section 2.6.3 - Command Substitution
/// "The shell shall expand the command substitution by executing command
/// in a subshell environment and replacing the command substitution with
/// the standard output of the command, with any trailing <newline>
/// characters deleted."
///
/// Returns the captured output (allocated using the provided allocator).
pub fn captureOutput(
    allocator: Allocator,
    commands: CompoundList,
    shell_state: *ShellState,
) SubshellError![]const u8 {
    // Create pipe for capturing stdout
    const pipe_fds = posix.pipe() catch {
        printError("pipe failed for command substitution\n", .{});
        return error.PipeFailed;
    };
    const read_fd = pipe_fds[0];
    const write_fd = pipe_fds[1];

    // Fork child process
    const pid = posix.fork() catch {
        posix.close(read_fd);
        posix.close(write_fd);
        printError("fork failed for command substitution\n", .{});
        return error.ForkFailed;
    };

    if (pid == 0) {
        // Child process: execute commands with stdout redirected to pipe

        // Close read end - we only write
        posix.close(read_fd);

        // Redirect stdout to write end of pipe
        posix.dup2(write_fd, posix.STDOUT_FILENO) catch posix.exit(ExitStatus.GENERAL_ERROR);
        posix.close(write_fd);

        // Execute the commands
        // Create a new executor for the child process
        var exec = executor.Executor.init(allocator, shell_state);
        const status = exec.executeCompoundList(commands) catch |err| {
            // Handle execution errors
            switch (err) {
                error.ExitRequested => posix.exit(shell_state.exit_code),
                error.BreakRequested, error.ContinueRequested => {
                    // break/continue in command substitution - treat as error
                    printError("break/continue not valid in command substitution\n", .{});
                    posix.exit(ExitStatus.GENERAL_ERROR);
                },
                else => posix.exit(ExitStatus.GENERAL_ERROR),
            }
        };

        // Exit with the command's exit status
        posix.exit(status.toExitCode());
    }

    // Parent process: read output from pipe

    // Close write end - we only read
    posix.close(write_fd);

    // Read all data from pipe using std.fs.File
    const file = fs.File{ .handle = read_fd };

    const output = file.readToEndAlloc(allocator, std.math.maxInt(usize)) catch |err| {
        posix.close(read_fd);
        _ = posix.waitpid(pid, 0);
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.ReadFailed,
        };
    };
    errdefer allocator.free(output);

    posix.close(read_fd);

    // Wait for child and update last_status
    const wait_result = posix.waitpid(pid, 0);
    shell_state.last_status = statusFromWaitResult(wait_result.status);

    // Strip trailing newlines per POSIX 2.6.3
    var trimmed = output;
    while (trimmed.len > 0 and trimmed[trimmed.len - 1] == '\n') {
        trimmed = trimmed[0 .. trimmed.len - 1];
    }

    // Return trimmed output
    // We need to dupe if we trimmed, otherwise just return the slice
    if (trimmed.len < output.len) {
        const result_str = try allocator.dupe(u8, trimmed);
        allocator.free(output);
        return result_str;
    } else {
        return output;
    }
}
