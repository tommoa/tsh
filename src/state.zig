//! Shell state management.
//!
//! ShellState maintains the persistent state of the shell between commands:
//! - Environment variables (exported, inherited by child processes)
//! - Shell variables (non-exported, shell-internal only)
//! - Last exit status (for $?)
//! - Shell options (interactive mode, etc.)
//! - PS1 prompt string
//! - Current and previous working directory
//!
//! POSIX Reference: Section 2.5 - Parameters and Variables
//! POSIX Reference: Section 2.9.1 - Simple Commands (variable assignment)

const std = @import("std");
const Allocator = std.mem.Allocator;
const process = std.process;
const posix = std.posix;

/// Print an error message to stderr with "tsh: " prefix.
/// Uses writerStreaming to ensure correct output with redirections.
pub fn printError(comptime fmt: []const u8, args: anytype) void {
    var buf: [256]u8 = undefined;
    var stderr = std.fs.File.stderr().writerStreaming(&buf);
    stderr.interface.print("tsh: " ++ fmt, args) catch {};
    stderr.interface.flush() catch {};
}

/// Shell options that can be set via command-line flags or the `set` builtin.
///
/// These correspond to POSIX shell options (see section 2.14.2):
/// - `-i`: Interactive mode
/// - `-e`: errexit - exit on error (future)
/// - `-x`: xtrace - print commands before execution (future)
/// - `-u`: nounset - error on unset variables (future)
pub const ShellOptions = struct {
    /// Whether the shell is running in interactive mode.
    /// Set at startup based on isatty(stdin) or `-i` flag.
    /// Note: POSIX says `-i` can only be set at invocation, not changed later.
    interactive: bool = false,

    // TODO: Add more options for `set` builtin:
    // errexit: bool = false,    // -e
    // xtrace: bool = false,     // -x
    // nounset: bool = false,    // -u
    // noclobber: bool = false,  // -C
    // allexport: bool = false,  // -a
};

/// Default PS1 prompt per POSIX: "$ " for regular users.
/// POSIX specifies this in section 2.5.3.
pub const DEFAULT_PS1 = "$ ";

/// Processing mode for shell input.
///
/// This determines what the shell does with each command/line of input.
/// The mode is set at startup via command-line flags and applies to all
/// input sources (interactive, file, or -c command string).
pub const ProcessingMode = enum {
    /// Parse and execute commands (default behavior).
    execute,
    /// Tokenize input and dump tokens to stdout (--dump-tokens).
    dump_tokens,
    /// Parse input and dump AST to stdout (--dump-ast).
    dump_ast,
};

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
    /// POSIX Reference: Section 2.5.3 - Environment Variables
    env: process.EnvMap,

    /// Shell variables (non-exported, shell-internal only).
    /// These are not passed to child processes.
    /// POSIX Reference: Section 2.5.2 - Shell Variables
    variables: std.StringHashMap([]const u8),

    /// Set of variable names marked for export.
    /// A name can be in this set without having a value yet (e.g., `export VAR`
    /// before `VAR=value`). When a variable in this set is assigned, the value
    /// goes to `env` instead of `variables`.
    /// POSIX Reference: Section 2.5.3 - export marking
    exported_names: std.StringHashMap(void),

    /// Exit status of the last executed command.
    /// Accessible as $? in the shell.
    last_status: ExitStatus,

    /// Exit code for when exit builtin is invoked.
    /// Set by the exit builtin and read by the REPL to determine final exit code.
    exit_code: u8,

    /// Current working directory.
    /// Initialized from getcwd() at startup, updated by cd builtin.
    /// Also exported as $PWD.
    /// POSIX Reference: Section 2.5.3 - PWD
    cwd: []const u8,

    /// Previous working directory.
    /// Updated by cd builtin, used for `cd -`.
    /// Also exported as $OLDPWD.
    /// POSIX Reference: Section 2.5.3 - OLDPWD
    oldcwd: ?[]const u8,

    /// Cached HOME environment variable for tilde expansion.
    /// Updated when HOME is set or unset via setEnv().
    home: ?[]const u8,

    /// PS1 prompt string for interactive mode.
    /// TODO: Expand variables in PS1 before displaying.
    ps1: []const u8,

    /// Shell options (interactive mode, etc.).
    options: ShellOptions,

    /// Positional parameters ($1, $2, ...).
    /// Set from script arguments or the `set` builtin.
    /// POSIX Reference: Section 2.5.1 - Positional Parameters
    positional_params: std.ArrayListUnmanaged([]const u8) = .empty,

    /// Shell/script name ($0).
    /// Set from the script path or shell invocation name.
    /// POSIX Reference: Section 2.5.2 - Special Parameters
    ///
    /// Ownership: This is a borrowed pointer, not owned by ShellState.
    /// The caller (typically main.zig) must ensure the backing memory
    /// (e.g., from argv or a filename string) outlives the ShellState.
    /// This field is not freed by deinit().
    shell_name: []const u8 = "tsh",

    /// Process ID of the shell ($$).
    /// Cached at initialization since it never changes during process lifetime.
    /// POSIX Reference: Section 2.5.2 - Special Parameters
    pid: std.posix.pid_t,

    /// Initialize shell state by inheriting the current process environment.
    ///
    /// This is the standard initialization for a shell process.
    pub fn init(allocator: Allocator) !ShellState {
        var env = try process.getEnvMap(allocator);
        return initWithEnv(allocator, &env);
    }

    /// Initialize shell state with a provided environment map.
    ///
    /// This is useful for testing or for cases where you want to start
    /// with a custom environment rather than inheriting from the process.
    pub fn initWithEnv(allocator: Allocator, env: *process.EnvMap) !ShellState {
        // Get current working directory
        var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
        const cwd_slice = posix.getcwd(&cwd_buf) catch "/";
        const cwd = try allocator.dupe(u8, cwd_slice);

        // Set PWD in environment (POSIX requires it to be exported)
        try env.put("PWD", cwd);

        return ShellState{
            .allocator = allocator,
            .env = env.*,
            .variables = std.StringHashMap([]const u8).init(allocator),
            .exported_names = std.StringHashMap(void).init(allocator),
            .last_status = .{ .exited = 0 },
            .exit_code = 0,
            .cwd = cwd,
            .oldcwd = null,
            .home = env.get("HOME"),
            .ps1 = env.get("PS1") orelse DEFAULT_PS1,
            .options = .{},
            .pid = std.c.getpid(),
        };
    }

    /// Clean up shell state resources.
    pub fn deinit(self: *ShellState) void {
        // Free variable values
        var var_iter = self.variables.iterator();
        while (var_iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.variables.deinit();

        // Free exported_names keys
        var exp_iter = self.exported_names.iterator();
        while (exp_iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.exported_names.deinit();

        // Free cwd and oldcwd
        self.allocator.free(self.cwd);
        if (self.oldcwd) |old| {
            self.allocator.free(old);
        }

        // Free positional parameters
        for (self.positional_params.items) |p| {
            self.allocator.free(p);
        }
        self.positional_params.deinit(self.allocator);

        self.env.deinit();
    }

    /// Get an environment variable.
    pub fn getEnv(self: *const ShellState, key: []const u8) ?[]const u8 {
        return self.env.get(key);
    }

    /// Set or unset an environment variable.
    ///
    /// If value is non-null, sets the variable. If null, removes it.
    /// Updates cached fields (`home`, `ps1`) when their corresponding
    /// environment variables are modified.
    pub fn setEnv(self: *ShellState, key: []const u8, value: ?[]const u8) !void {
        if (value) |v| {
            try self.env.put(key, v);
        } else {
            _ = self.env.remove(key);
        }
        // Update cached values when their environment variables change
        if (std.mem.eql(u8, key, "HOME")) {
            // Re-fetch from env to get the EnvMap-owned copy, not the caller's slice
            self.home = self.env.get("HOME");
        } else if (std.mem.eql(u8, key, "PS1")) {
            self.ps1 = self.env.get("PS1") orelse DEFAULT_PS1;
        }
    }

    /// Get a variable's value.
    ///
    /// Checks the environment (exported variables) first, then shell variables.
    /// Returns null if the variable is not set in either location.
    ///
    /// POSIX Reference: Section 2.5.2 - Parameter Expansion
    pub fn getVariable(self: *const ShellState, name: []const u8) ?[]const u8 {
        // Check env (exported variables) first
        if (self.env.get(name)) |value| {
            return value;
        }
        // Then check shell variables
        return self.variables.get(name);
    }

    /// Set a variable's value.
    ///
    /// If the variable name is marked as exported (via `export`) or already
    /// exists in the environment, the value is stored in `env`. Otherwise,
    /// the value is stored in `variables`.
    ///
    /// The value is duplicated into the state's allocator, so the caller
    /// does not need to ensure the value's lifetime.
    ///
    /// POSIX Reference: Section 2.9.1 - Simple Commands (variable assignment)
    pub fn setVariable(self: *ShellState, name: []const u8, value: []const u8) !void {
        // If name is marked as exported or already in env, update env
        // Note: EnvMap.put() duplicates the value internally, so we pass
        // the original value directly (no need to dupe ourselves)
        if (self.exported_names.contains(name) or self.env.get(name) != null) {
            try self.env.put(name, value);
            // Update cached values when their environment variables change
            if (std.mem.eql(u8, name, "HOME")) {
                self.home = self.env.get("HOME");
            } else if (std.mem.eql(u8, name, "PS1")) {
                self.ps1 = self.env.get("PS1") orelse DEFAULT_PS1;
            }
        } else {
            // For shell variables, we need to dupe the value ourselves
            const duped_value = try self.allocator.dupe(u8, value);
            errdefer self.allocator.free(duped_value);
            // Check if we need to allocate the key
            const key_entry = self.variables.getEntry(name);
            if (key_entry) |entry| {
                // Key exists, free old value and update
                self.allocator.free(entry.value_ptr.*);
                entry.value_ptr.* = duped_value;
            } else {
                // Key doesn't exist, need to dupe it
                const duped_name = try self.allocator.dupe(u8, name);
                errdefer self.allocator.free(duped_name);
                try self.variables.put(duped_name, duped_value);
            }
        }
    }

    /// Set positional parameters ($1, $2, ...).
    ///
    /// Replaces all existing positional parameters with the provided values.
    /// The values are copied, so the caller retains ownership of the input.
    /// Used by script argument handling and the `set` builtin.
    ///
    /// POSIX Reference: Section 2.5.1 - Positional Parameters
    pub fn setPositionalParams(self: *ShellState, params: []const []const u8) !void {
        // Free old params
        for (self.positional_params.items) |p| {
            self.allocator.free(p);
        }
        self.positional_params.clearRetainingCapacity();

        // Copy new params
        try self.positional_params.ensureTotalCapacity(self.allocator, params.len);
        for (params) |p| {
            const duped = try self.allocator.dupe(u8, p);
            self.positional_params.appendAssumeCapacity(duped);
        }
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

    var state = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer state.deinit();

    try std.testing.expectEqualStrings("bar", state.getEnv("FOO").?);
    try std.testing.expectEqualStrings("qux", state.getEnv("BAZ").?);
    try std.testing.expect(state.getEnv("PATH") == null); // Not in custom env
}

test "ShellState: setEnv and getEnv" {
    var env = process.EnvMap.init(std.testing.allocator);
    var state = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer state.deinit();

    try state.setEnv("TEST_VAR", "test_value");
    try std.testing.expectEqualStrings("test_value", state.getEnv("TEST_VAR").?);
}

test "ShellState: setEnv with null removes variable" {
    var env = process.EnvMap.init(std.testing.allocator);
    try env.put("TO_REMOVE", "value");

    var state = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer state.deinit();

    try std.testing.expect(state.getEnv("TO_REMOVE") != null);
    try state.setEnv("TO_REMOVE", null);
    try std.testing.expect(state.getEnv("TO_REMOVE") == null);
}

test "ShellState: initial last_status is 0" {
    var env = process.EnvMap.init(std.testing.allocator);
    var state = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer state.deinit();

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, state.last_status);
}

test "ShellState: home is cached from env" {
    var env = process.EnvMap.init(std.testing.allocator);
    try env.put("HOME", "/home/testuser");

    var state = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer state.deinit();

    try std.testing.expectEqualStrings("/home/testuser", state.home.?);
}

test "ShellState: home is null when HOME not set" {
    var env = process.EnvMap.init(std.testing.allocator);
    var state = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer state.deinit();

    try std.testing.expect(state.home == null);
}

test "ShellState: setEnv updates cached home" {
    var env = process.EnvMap.init(std.testing.allocator);
    var state = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer state.deinit();

    try std.testing.expect(state.home == null);
    try state.setEnv("HOME", "/new/home");
    try std.testing.expectEqualStrings("/new/home", state.home.?);
}

test "ShellState: setEnv with null clears cached home" {
    var env = process.EnvMap.init(std.testing.allocator);
    try env.put("HOME", "/home/testuser");

    var state = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer state.deinit();

    try std.testing.expect(state.home != null);
    try state.setEnv("HOME", null);
    try std.testing.expect(state.home == null);
}

test "ShellState: ps1 defaults to DEFAULT_PS1" {
    var env = process.EnvMap.init(std.testing.allocator);
    var state = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer state.deinit();

    try std.testing.expectEqualStrings(DEFAULT_PS1, state.ps1);
}

test "ShellState: ps1 is read from environment" {
    var env = process.EnvMap.init(std.testing.allocator);
    try env.put("PS1", "custom> ");

    var state = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer state.deinit();

    try std.testing.expectEqualStrings("custom> ", state.ps1);
}

test "ShellState: options default to non-interactive" {
    var env = process.EnvMap.init(std.testing.allocator);
    var state = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer state.deinit();

    try std.testing.expect(!state.options.interactive);
}

test "ShellState: setEnv updates cached ps1" {
    var env = process.EnvMap.init(std.testing.allocator);
    var state = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer state.deinit();

    try std.testing.expectEqualStrings(DEFAULT_PS1, state.ps1);
    try state.setEnv("PS1", "new> ");
    try std.testing.expectEqualStrings("new> ", state.ps1);
}

test "ShellState: setEnv with null resets ps1 to default" {
    var env = process.EnvMap.init(std.testing.allocator);
    try env.put("PS1", "custom> ");

    var state = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer state.deinit();

    try std.testing.expectEqualStrings("custom> ", state.ps1);
    try state.setEnv("PS1", null);
    try std.testing.expectEqualStrings(DEFAULT_PS1, state.ps1);
}

// --- New tests for variables, cwd, etc. ---

test "ShellState: cwd is initialized from getcwd" {
    var state = try ShellState.init(std.testing.allocator);
    defer state.deinit();

    // cwd should be non-empty
    try std.testing.expect(state.cwd.len > 0);
    // PWD should be set in env
    try std.testing.expectEqualStrings(state.cwd, state.getEnv("PWD").?);
}

test "ShellState: oldcwd is initially null" {
    var state = try ShellState.init(std.testing.allocator);
    defer state.deinit();

    try std.testing.expect(state.oldcwd == null);
}

test "ShellState: getVariable returns env value if present" {
    var env = process.EnvMap.init(std.testing.allocator);
    try env.put("FOO", "from_env");

    var state = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer state.deinit();

    try std.testing.expectEqualStrings("from_env", state.getVariable("FOO").?);
}

test "ShellState: getVariable returns shell variable if not in env" {
    var env = process.EnvMap.init(std.testing.allocator);
    var state = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer state.deinit();

    try state.setVariable("FOO", "from_var");
    try std.testing.expectEqualStrings("from_var", state.getVariable("FOO").?);
}

test "ShellState: getVariable returns null if not found" {
    var env = process.EnvMap.init(std.testing.allocator);
    var state = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer state.deinit();

    try std.testing.expect(state.getVariable("NONEXISTENT") == null);
}

test "ShellState: setVariable stores in variables by default" {
    var env = process.EnvMap.init(std.testing.allocator);
    var state = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer state.deinit();

    try state.setVariable("FOO", "bar");

    // Should be in variables, not env
    try std.testing.expectEqualStrings("bar", state.variables.get("FOO").?);
    try std.testing.expect(state.env.get("FOO") == null);
}

test "ShellState: setVariable routes to env if name is exported" {
    var env = process.EnvMap.init(std.testing.allocator);
    var state = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer state.deinit();

    // Mark FOO as exported (use state.allocator so deinit can free it)
    const duped_name = try state.allocator.dupe(u8, "FOO");
    try state.exported_names.put(duped_name, {});

    try state.setVariable("FOO", "bar");

    // Should be in env, not variables
    try std.testing.expectEqualStrings("bar", state.env.get("FOO").?);
    try std.testing.expect(state.variables.get("FOO") == null);
}

test "ShellState: setVariable routes to env if already in env" {
    var env = process.EnvMap.init(std.testing.allocator);
    try env.put("FOO", "old_value");

    var state = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer state.deinit();

    try state.setVariable("FOO", "new_value");

    // Should update env
    try std.testing.expectEqualStrings("new_value", state.env.get("FOO").?);
}

test "ShellState: setVariable updates existing variable" {
    var env = process.EnvMap.init(std.testing.allocator);
    var state = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer state.deinit();

    try state.setVariable("FOO", "first");
    try state.setVariable("FOO", "second");

    try std.testing.expectEqualStrings("second", state.getVariable("FOO").?);
}
