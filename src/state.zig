//! Shell state management.
//!
//! ShellState maintains the persistent state of the shell between commands:
//! - Environment variables (exported, inherited by child processes)
//! - Last exit status (for $?)
//! - Future: shell variables, options, functions, aliases, traps, etc.

const std = @import("std");
const Allocator = std.mem.Allocator;
const process = std.process;

/// The result of executing a command.
///
/// POSIX defines the following exit status conventions (section 2.8.2):
///
///   0       Success
///   1-125   Command-specific failure (e.g., redirection error, expansion error)
///   126     Command found but not executable (permission denied, invalid format)
///   127     Command not found
///   >128    Command terminated by signal (128 + signal number)
///
/// The shell uses these codes to communicate execution results. Applications
/// should use 1-125 for their own error conditions, reserving 126-127 for
/// command resolution errors and >128 for signal termination.
pub const ExitStatus = union(enum) {
    /// Command exited normally with this exit code.
    exited: u8,
    /// Command was killed by this signal.
    signaled: u32,

    // Well-known exit codes per POSIX section 2.8.2.
    pub const SUCCESS: u8 = 0;
    pub const GENERAL_ERROR: u8 = 1;
    pub const NOT_EXECUTABLE: u8 = 126;
    pub const NOT_FOUND: u8 = 127;
    pub const SIGNAL_BASE: u8 = 128;

    /// Convert to a shell exit code (for use with std.posix.exit).
    /// Signals are converted to 128 + signal number per POSIX convention.
    pub fn toExitCode(self: ExitStatus) u8 {
        return switch (self) {
            .exited => |code| code,
            .signaled => |sig| @truncate(SIGNAL_BASE +| sig),
        };
    }
};

/// Persistent shell state maintained between command executions.
///
/// This struct owns the shell's environment and other state that persists
/// across commands. It should be created once at shell startup and passed
/// to the Executor for each command execution.
pub const ShellState = struct {
    /// Allocator for state management.
    allocator: Allocator,

    /// Environment variables (exported variables).
    /// These are inherited by child processes.
    env: process.EnvMap,

    /// Exit status of the last executed command.
    /// Accessible as $? in the shell.
    last_status: ExitStatus,

    // Future fields:
    // /// Shell variables (not exported, shell-internal only).
    // vars: std.StringHashMap([]const u8),
    // /// Shell options (set -e, set -x, etc.).
    // options: ShellOptions,
    // /// Positional parameters ($1, $2, etc.).
    // positional_params: []const []const u8,

    /// Initialize shell state by inheriting the current process environment.
    ///
    /// This is the standard initialization for a shell process.
    pub fn init(allocator: Allocator) !ShellState {
        return initWithEnv(allocator, try process.getEnvMap(allocator));
    }

    /// Initialize shell state with a provided environment map.
    ///
    /// This is useful for testing or for cases where you want to start
    /// with a custom environment rather than inheriting from the process.
    pub fn initWithEnv(allocator: Allocator, env: process.EnvMap) ShellState {
        return ShellState{
            .allocator = allocator,
            .env = env,
            .last_status = .{ .exited = 0 },
        };
    }

    /// Clean up shell state resources.
    pub fn deinit(self: *ShellState) void {
        self.env.deinit();
    }

    /// Get an environment variable.
    pub fn getEnv(self: *const ShellState, key: []const u8) ?[]const u8 {
        return self.env.get(key);
    }

    /// Set an environment variable.
    pub fn setEnv(self: *ShellState, key: []const u8, value: []const u8) !void {
        try self.env.put(key, value);
    }

    /// Remove an environment variable.
    pub fn unsetEnv(self: *ShellState, key: []const u8) void {
        _ = self.env.remove(key);
    }
};

// --- Tests ---

test "ShellState: init inherits environment" {
    var state = try ShellState.init(std.testing.allocator);
    defer state.deinit();

    // PATH should be inherited from the process environment
    const path = state.getEnv("PATH");
    try std.testing.expect(path != null);
}

test "ShellState: initWithEnv uses provided env" {
    var env = process.EnvMap.init(std.testing.allocator);
    try env.put("FOO", "bar");
    try env.put("BAZ", "qux");

    var state = ShellState.initWithEnv(std.testing.allocator, env);
    defer state.deinit();

    try std.testing.expectEqualStrings("bar", state.getEnv("FOO").?);
    try std.testing.expectEqualStrings("qux", state.getEnv("BAZ").?);
    try std.testing.expect(state.getEnv("PATH") == null); // Not in custom env
}

test "ShellState: setEnv and getEnv" {
    const env = process.EnvMap.init(std.testing.allocator);
    var state = ShellState.initWithEnv(std.testing.allocator, env);
    defer state.deinit();

    try state.setEnv("TEST_VAR", "test_value");
    try std.testing.expectEqualStrings("test_value", state.getEnv("TEST_VAR").?);
}

test "ShellState: unsetEnv" {
    var env = process.EnvMap.init(std.testing.allocator);
    try env.put("TO_REMOVE", "value");

    var state = ShellState.initWithEnv(std.testing.allocator, env);
    defer state.deinit();

    try std.testing.expect(state.getEnv("TO_REMOVE") != null);
    state.unsetEnv("TO_REMOVE");
    try std.testing.expect(state.getEnv("TO_REMOVE") == null);
}

test "ShellState: initial last_status is 0" {
    const env = process.EnvMap.init(std.testing.allocator);
    var state = ShellState.initWithEnv(std.testing.allocator, env);
    defer state.deinit();

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, state.last_status);
}
