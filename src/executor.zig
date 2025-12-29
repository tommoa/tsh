//! Executor for POSIX shell simple commands.
//!
//! Takes a parsed SimpleCommand AST and executes it by:
//! 1. Expanding words (currently just concatenating literal parts)
//! 2. Setting up environment variables from assignments
//! 3. Setting up I/O redirections
//! 4. Forking and executing the command

const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;
const process = std.process;

const parser = @import("parser.zig");
const lexer = @import("lexer.zig");
const state = @import("state.zig");
const SimpleCommand = parser.SimpleCommand;
const Word = parser.Word;
const WordPart = parser.WordPart;
const Assignment = parser.Assignment;
const ParsedRedirection = parser.ParsedRedirection;
const Redirection = lexer.Redirection;
const ShellState = state.ShellState;
pub const ExitStatus = state.ExitStatus;

/// Errors that can occur during command execution.
pub const ExecuteError = error{
    /// fork() system call failed.
    ForkFailed,
    /// Command not found in PATH.
    CommandNotFound,
    /// execve() system call failed.
    ExecFailed,
    /// Failed to set up redirections.
    RedirectionFailed,
} || Allocator.Error || process.GetEnvMapError;

/// Information about an execution error for error reporting.
pub const ErrorInfo = struct {
    /// A human-readable description of the error.
    message: []const u8,
    /// Additional context (e.g., filename that failed).
    context: ?[]const u8,
};

/// Result of applying redirections to a process.
///
/// The caller is responsible for printing any error message and
/// determining the appropriate exit status.
pub const RedirectionResult = union(enum) {
    /// All redirections applied successfully.
    ok,
    /// A redirection failed. Contains the error message to display.
    err: []const u8,
};

/// Result of searching for an executable command.
///
/// Different failure modes map to different POSIX exit codes:
/// - not_found: exit 127 (command not found)
/// - not_executable: exit 126 (permission denied, invalid executable)
pub const FindResult = union(enum) {
    /// Command found at this path.
    found: [*:0]const u8,
    /// Command not found in PATH or at specified path (exit 127).
    not_found,
    /// Command exists but cannot be executed (exit 126).
    /// Contains error message describing why (e.g., "permission denied").
    not_executable: []const u8,
};

/// Executor for shell commands.
///
/// The executor takes parsed SimpleCommand ASTs and runs them using
/// the provided ShellState for environment and status tracking.
///
/// Memory Management: The executor allocates memory for argv expansion,
/// environment maps, and other temporary data during command execution.
/// This memory is not explicitly freed after execution completes. Callers
/// should use an arena allocator that is freed after each command, or
/// accept that memory will accumulate over the executor's lifetime.
pub const Executor = struct {
    /// Allocator for temporary allocations during execution.
    /// Should be an arena allocator that is freed after each command.
    allocator: Allocator,
    /// Reference to the shell state (environment, last status, etc.).
    shell_state: *ShellState,
    /// Error context for the most recent error.
    error_info: ?ErrorInfo,

    /// Initialize a new executor with a reference to shell state.
    pub fn init(allocator: Allocator, shell_state: *ShellState) Executor {
        return Executor{
            .allocator = allocator,
            .shell_state = shell_state,
            .error_info = null,
        };
    }

    /// Get error information for the most recent execution error.
    pub fn getErrorInfo(self: *const Executor) ?ErrorInfo {
        return self.error_info;
    }

    /// Get the last exit status.
    pub fn lastStatus(self: *const Executor) ExitStatus {
        return self.shell_state.last_status;
    }

    /// Execute a simple command.
    ///
    /// Returns the exit status of the command.
    pub fn execute(self: *Executor, cmd: SimpleCommand) ExitStatus {
        self.error_info = null;

        // Handle commands with no argv
        if (cmd.argv.len == 0) {
            // If there are redirections, apply them to the shell (e.g., "> file" creates/truncates file)
            if (cmd.redirections.len > 0) {
                // files_only=true: only create/truncate files, don't redirect shell's fds.
                // TODO: Add test for this once we support multiple commands - verify that
                // `> file; echo hello` still outputs to terminal, not to file.
                switch (applyRedirections(self.allocator, cmd.redirections, true)) {
                    .ok => {
                        self.shell_state.last_status = .{ .exited = 0 };
                    },
                    .err => |msg| {
                        printError("{s}\n", .{msg});
                        self.setError(msg, null);
                        self.shell_state.last_status = .{ .exited = ExitStatus.GENERAL_ERROR };
                    },
                }
                return self.shell_state.last_status;
            }
            // Assignments-only: no-ops for now. When we add shell state, they'll set shell variables.
            self.shell_state.last_status = .{ .exited = 0 };
            return self.shell_state.last_status;
        }

        // Expand argv
        const argv = expandArgv(self.allocator, cmd.argv) catch |err| {
            self.setError("failed to expand arguments", @errorName(err));
            self.shell_state.last_status = .{ .exited = 1 };
            return self.shell_state.last_status;
        };

        // Build child environment map (copy shell env, add command assignments)
        var env_map = self.buildChildEnvMap(cmd.assignments) catch |err| {
            self.setError("failed to build environment", @errorName(err));
            self.shell_state.last_status = .{ .exited = 1 };
            return self.shell_state.last_status;
        };
        defer env_map.deinit();

        // Fork
        const pid = posix.fork() catch |err| {
            self.setError("fork failed", @errorName(err));
            self.shell_state.last_status = .{ .exited = 1 };
            return self.shell_state.last_status;
        };

        if (pid == 0) {
            // Child process - executeChild is noreturn (it execs or exits)
            self.executeChild(cmd, argv, &env_map);
        }

        // Parent process
        const result = posix.waitpid(pid, 0);
        self.shell_state.last_status = statusFromWaitResult(result.status);
        return self.shell_state.last_status;
    }

    /// Execute in the child process (after fork).
    /// This function never returns - it either execs or exits.
    fn executeChild(
        self: *Executor,
        cmd: SimpleCommand,
        argv: [*:null]const ?[*:0]const u8,
        env_map: *const process.EnvMap,
    ) noreturn {
        // Set up redirections (files_only=false: actually redirect fds for the child)
        switch (applyRedirections(self.allocator, cmd.redirections, false)) {
            .ok => {},
            .err => |msg| {
                printError("{s}\n", .{msg});
                posix.exit(ExitStatus.GENERAL_ERROR);
            },
        }

        const cmd_name = argv[0] orelse {
            printError("empty command\n", .{});
            posix.exit(ExitStatus.NOT_FOUND);
        };

        // Find the executable path using the child's environment
        const exe_path = switch (findExecutable(self.allocator, cmd_name, env_map)) {
            .found => |path| path,
            .not_found => {
                printError("{s}: command not found\n", .{cmd_name});
                posix.exit(ExitStatus.NOT_FOUND);
            },
            .not_executable => |msg| {
                printError("{s}: {s}\n", .{ cmd_name, msg });
                posix.exit(ExitStatus.NOT_EXECUTABLE);
            },
        };

        // Convert env_map to null-delimited format for execve
        const envp = process.createNullDelimitedEnvMap(self.allocator, env_map) catch {
            printError("{s}: failed to create environment\n", .{cmd_name});
            posix.exit(ExitStatus.GENERAL_ERROR);
        };

        // Execute the command
        const envp_ptr: [*:null]const ?[*:0]const u8 = @ptrCast(envp.ptr);
        const err = posix.execveZ(exe_path, argv, envp_ptr);

        // If we get here, exec failed
        const exit_code: u8 = switch (err) {
            error.FileNotFound => ExitStatus.NOT_FOUND,
            else => ExitStatus.NOT_EXECUTABLE,
        };

        printError("{s}: {s}\n", .{ cmd_name, @errorName(err) });
        posix.exit(exit_code);
    }

    /// Build the child environment map by copying shell env and adding command assignments.
    ///
    /// Command assignments (e.g., `FOO=bar cmd`) are added to a copy of the shell's
    /// environment for the child process only - they don't modify the shell's env.
    fn buildChildEnvMap(self: *Executor, assignments: []const Assignment) !process.EnvMap {
        // Copy the shell's environment
        var env_map = process.EnvMap.init(self.allocator);

        // Copy all entries from shell state's environment
        var iter = self.shell_state.env.hash_map.iterator();
        while (iter.next()) |entry| {
            try env_map.put(entry.key_ptr.*, entry.value_ptr.*);
        }

        // Add/override with command-specific assignments
        for (assignments) |assignment| {
            const value = try expandWord(self.allocator, assignment.value);
            try env_map.put(assignment.name, value);
        }

        return env_map;
    }

    /// Set error information.
    fn setError(self: *Executor, message: []const u8, context: ?[]const u8) void {
        self.error_info = ErrorInfo{
            .message = message,
            .context = context,
        };
    }
};

/// Get the default source file descriptor for a redirection operation.
fn defaultSourceFd(op: Redirection) u32 {
    return switch (op) {
        .In => 0, // stdin
        .Out, .Append, .Fd => 1, // stdout
    };
}

/// Get the open flags for a redirection operation.
fn openFlagsForOp(op: Redirection) posix.O {
    return switch (op) {
        .In => .{ .ACCMODE = .RDONLY },
        .Out => .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true },
        .Append => .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true },
        .Fd => unreachable, // fd duplication doesn't use open
    };
}

/// Expand a Word into a null-terminated string.
///
/// Currently just concatenates all literal parts. When command substitution
/// is added, this will need to recursively execute nested commands.
fn expandWord(allocator: Allocator, word: Word) Allocator.Error![:0]const u8 {
    var total_len: usize = 0;
    for (word.parts) |part| {
        switch (part) {
            .literal => |lit| total_len += lit.len,
        }
    }

    const buf = try allocator.allocSentinel(u8, total_len, 0);

    var offset: usize = 0;
    for (word.parts) |part| {
        switch (part) {
            .literal => |lit| {
                @memcpy(buf[offset..][0..lit.len], lit);
                offset += lit.len;
            },
        }
    }

    return buf;
}

/// Expand an array of Words into a null-terminated array of null-terminated strings.
fn expandArgv(allocator: Allocator, words: []const Word) Allocator.Error![:null]const ?[*:0]const u8 {
    const argv = try allocator.allocSentinel(?[*:0]const u8, words.len, null);

    for (words, 0..) |word, i| {
        argv[i] = (try expandWord(allocator, word)).ptr;
    }

    return argv;
}

/// Find an executable in PATH or return the command if it contains a slash.
///
/// POSIX behavior:
/// - If command contains '/', use it as-is (absolute or relative path)
/// - Otherwise, search each directory in PATH
///
/// Returns FindResult indicating success, not found (exit 127), or not executable (exit 126).
fn findExecutable(allocator: Allocator, cmd: [*:0]const u8, env_map: *const process.EnvMap) FindResult {
    const cmd_slice = std.mem.span(cmd);

    // If command contains '/', use as-is (don't search PATH)
    if (std.mem.indexOfScalar(u8, cmd_slice, '/') != null) {
        // Check if it exists and is executable
        posix.accessZ(cmd, posix.X_OK) catch |err| {
            return switch (err) {
                error.FileNotFound => .not_found,
                error.AccessDenied => .{ .not_executable = "permission denied" },
                else => .{ .not_executable = @errorName(err) },
            };
        };
        return .{ .found = cmd };
    }

    // Search PATH from the child's environment
    const path_env = env_map.get("PATH") orelse "/usr/bin:/bin";

    var path_iter = std.mem.splitScalar(u8, path_env, ':');
    while (path_iter.next()) |dir| {
        // Empty component means current directory
        const search_dir = if (dir.len == 0) "." else dir;

        // Build full path: dir + "/" + cmd
        const full_path = std.fmt.allocPrintSentinel(
            allocator,
            "{s}/{s}",
            .{ search_dir, cmd_slice },
            0,
        ) catch continue;

        // Check if executable
        posix.accessZ(full_path, posix.X_OK) catch continue;

        return .{ .found = full_path };
    }

    return .not_found;
}

/// Apply redirections to the current process.
///
/// Opens files, performs dup2 operations, and handles fd close.
/// Works in any context (parent or child process).
///
/// When `files_only` is true, only file operations are performed (open/create/truncate)
/// without modifying file descriptors. This is used for redirections-only commands
/// like `> file` which should create the file but not redirect the shell's fds.
///
/// On success, returns .ok.
/// On failure, returns .err with an error message. The caller is responsible
/// for printing the error and determining the appropriate exit status.
fn applyRedirections(allocator: Allocator, redirections: []const ParsedRedirection, files_only: bool) RedirectionResult {
    for (redirections) |redir| {
        const source_fd: posix.fd_t = @intCast(redir.source_fd orelse defaultSourceFd(redir.op));

        switch (redir.target) {
            .file => |word| {
                const path = expandWord(allocator, word) catch {
                    return .{ .err = "failed to expand redirection target" };
                };
                const flags = openFlagsForOp(redir.op);
                const fd = posix.openZ(path, flags, 0o666) catch |err| {
                    // Format error message with path
                    const msg = std.fmt.allocPrint(allocator, "{s}: {s}", .{ path, @errorName(err) }) catch {
                        return .{ .err = @errorName(err) };
                    };
                    return .{ .err = msg };
                };
                if (files_only) {
                    // Just close the file - we only wanted to create/truncate it
                    posix.close(fd);
                } else if (fd != source_fd) {
                    posix.dup2(fd, source_fd) catch |err| {
                        posix.close(fd);
                        const msg = std.fmt.allocPrint(allocator, "dup2: {s}", .{@errorName(err)}) catch {
                            return .{ .err = @errorName(err) };
                        };
                        return .{ .err = msg };
                    };
                    posix.close(fd);
                }
                // Note: if fd == source_fd, no action needed - the fd is already
                // in the correct position. This can occur if a standard fd was
                // previously closed and open() reused that fd number.
            },
            .fd => |target_fd| {
                // fd duplication is a no-op in files_only mode
                if (!files_only) {
                    posix.dup2(@intCast(target_fd), source_fd) catch |err| {
                        const msg = std.fmt.allocPrint(allocator, "dup2: {s}", .{@errorName(err)}) catch {
                            return .{ .err = @errorName(err) };
                        };
                        return .{ .err = msg };
                    };
                }
            },
            .close => {
                // fd close is a no-op in files_only mode
                if (!files_only) {
                    posix.close(source_fd);
                }
            },
        }
    }
    return .ok;
}

/// Convert wait status to ExitStatus.
fn statusFromWaitResult(status: u32) ExitStatus {
    if (posix.W.IFEXITED(status)) {
        return .{ .exited = posix.W.EXITSTATUS(status) };
    } else if (posix.W.IFSIGNALED(status)) {
        return .{ .signaled = posix.W.TERMSIG(status) };
    } else {
        // Stopped or other - treat as exit 1
        return .{ .exited = 1 };
    }
}

/// Print an error message to stderr (for use in child process).
/// Note: Uses a 512-byte buffer which may truncate very long paths.
fn printError(comptime fmt: []const u8, args: anytype) void {
    // TODO: Consider increasing buffer size or using unbuffered writes for long paths
    var buf: [512]u8 = undefined;
    const stderr = std.fs.File.stderr();
    var writer = stderr.writer(&buf);
    writer.interface.print("tsh: " ++ fmt, args) catch {};
    writer.interface.flush() catch {};
}

// --- Tests ---

fn parseCommand(allocator: Allocator, input: []const u8) !?SimpleCommand {
    var reader = std.io.Reader.fixed(input);
    var lex = lexer.Lexer.init(&reader);
    var p = parser.Parser.init(allocator, &lex);
    return p.parseCommand();
}

test "execute: simple echo" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const cmd = try parseCommand(arena.allocator(), "/bin/echo hello\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = exec.execute(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);
}

test "execute: exit status success" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const cmd = try parseCommand(arena.allocator(), "true\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = exec.execute(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);
}

test "execute: exit status failure" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const cmd = try parseCommand(arena.allocator(), "false\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = exec.execute(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 1 }, status);
}

test "execute: PATH lookup" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const cmd = try parseCommand(arena.allocator(), "echo hello\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = exec.execute(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);
}

test "execute: command not found" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const cmd = try parseCommand(arena.allocator(), "nonexistent_cmd_12345\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = exec.execute(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 127 }, status);
}

test "execute: output redirection" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_output";

    // Clean up any existing file
    std.fs.deleteFileAbsolute(tmp_path) catch {};

    const cmd = try parseCommand(arena.allocator(), "echo hello > " ++ tmp_path ++ "\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = exec.execute(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);

    // Verify file contents
    const contents = try std.fs.cwd().readFileAlloc(std.testing.allocator, tmp_path, 1024);
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualStrings("hello\n", contents);

    // Clean up
    std.fs.deleteFileAbsolute(tmp_path) catch {};
}

test "execute: input redirection" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_input";

    // Create input file
    {
        const file = try std.fs.createFileAbsolute(tmp_path, .{});
        defer file.close();
        try file.writeAll("test input\n");
    }

    // cat < file should succeed
    const cmd = try parseCommand(arena.allocator(), "cat < " ++ tmp_path ++ "\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = exec.execute(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);

    // Clean up
    std.fs.deleteFileAbsolute(tmp_path) catch {};
}

test "execute: append redirection" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_append";

    // Clean up any existing file
    std.fs.deleteFileAbsolute(tmp_path) catch {};

    // First write
    const cmd1 = try parseCommand(arena.allocator(), "echo first > " ++ tmp_path ++ "\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    _ = exec.execute(cmd1);

    // Append
    const cmd2 = try parseCommand(arena.allocator(), "echo second >> " ++ tmp_path ++ "\n") orelse return error.NoCommand;
    const status = exec.execute(cmd2);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);

    // Verify file contents
    const contents = try std.fs.cwd().readFileAlloc(std.testing.allocator, tmp_path, 1024);
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualStrings("first\nsecond\n", contents);

    // Clean up
    std.fs.deleteFileAbsolute(tmp_path) catch {};
}

test "execute: env assignment" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_env";
    std.fs.deleteFileAbsolute(tmp_path) catch {};

    // FOO=bar sh -c 'echo $FOO' > file
    const cmd = try parseCommand(arena.allocator(), "FOO=testvalue sh -c 'echo $FOO' > " ++ tmp_path ++ "\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = exec.execute(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);

    // Verify FOO was set
    const contents = try std.fs.cwd().readFileAlloc(std.testing.allocator, tmp_path, 1024);
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualStrings("testvalue\n", contents);

    std.fs.deleteFileAbsolute(tmp_path) catch {};
}

test "execute: assignments only" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const cmd = try parseCommand(arena.allocator(), "FOO=bar\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = exec.execute(cmd);

    // Assignments-only commands return success
    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);
}

test "execute: redirection only (like touch)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_redir_only";

    // Clean up any existing file
    std.fs.deleteFileAbsolute(tmp_path) catch {};

    // "> file" should create an empty file (like touch)
    const cmd = try parseCommand(arena.allocator(), "> " ++ tmp_path ++ "\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = exec.execute(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);

    // Verify file was created and is empty
    const contents = try std.fs.cwd().readFileAlloc(std.testing.allocator, tmp_path, 1024);
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualStrings("", contents);

    // Clean up
    std.fs.deleteFileAbsolute(tmp_path) catch {};
}

test "execute: assignment with redirection only" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_assign_redir";

    // Clean up any existing file
    std.fs.deleteFileAbsolute(tmp_path) catch {};

    // "FOO=bar > file" should create an empty file
    const cmd = try parseCommand(arena.allocator(), "FOO=bar > " ++ tmp_path ++ "\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = exec.execute(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);

    // Verify file was created and is empty
    const contents = try std.fs.cwd().readFileAlloc(std.testing.allocator, tmp_path, 1024);
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualStrings("", contents);

    // Clean up
    std.fs.deleteFileAbsolute(tmp_path) catch {};
}

test "execute: fd duplication 2>&1" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_dup";
    std.fs.deleteFileAbsolute(tmp_path) catch {};

    // sh -c 'echo error >&2' > file 2>&1
    // POSIX processes redirections left-to-right:
    // 1. > file: redirect stdout to file
    // 2. 2>&1: redirect stderr to wherever stdout points (the file)
    const cmd = try parseCommand(arena.allocator(), "sh -c 'echo error >&2' > " ++ tmp_path ++ " 2>&1\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = exec.execute(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);

    // The error output should be in the file
    const contents = try std.fs.cwd().readFileAlloc(std.testing.allocator, tmp_path, 1024);
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualStrings("error\n", contents);

    std.fs.deleteFileAbsolute(tmp_path) catch {};
}

test "expandWord: single literal" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const word = Word{
        .parts = &[_]WordPart{.{ .literal = "hello" }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWord(arena.allocator(), word);
    try std.testing.expectEqualStrings("hello", result);
}

test "expandWord: multiple literals" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const word = Word{
        .parts = &[_]WordPart{
            .{ .literal = "hello" },
            .{ .literal = "world" },
        },
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWord(arena.allocator(), word);
    try std.testing.expectEqualStrings("helloworld", result);
}

test "ExitStatus.toExitCode" {
    try std.testing.expectEqual(@as(u8, 0), (ExitStatus{ .exited = 0 }).toExitCode());
    try std.testing.expectEqual(@as(u8, 1), (ExitStatus{ .exited = 1 }).toExitCode());
    try std.testing.expectEqual(@as(u8, 127), (ExitStatus{ .exited = 127 }).toExitCode());
    try std.testing.expectEqual(@as(u8, 137), (ExitStatus{ .signaled = 9 }).toExitCode()); // SIGKILL
    try std.testing.expectEqual(@as(u8, 143), (ExitStatus{ .signaled = 15 }).toExitCode()); // SIGTERM
}
