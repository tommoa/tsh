//! Executor for POSIX shell simple commands.
//!
//! Takes a parsed SimpleCommand AST and executes it by:
//! 1. Expanding words (tilde, parameter, and quote expansion)
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
const builtins = @import("builtins.zig");
const expand = @import("expand.zig");
const SimpleCommand = parser.SimpleCommand;
const ParsedCommand = parser.ParsedCommand;
const Command = parser.Command;
const IfClause = parser.IfClause;
const LoopClause = parser.LoopClause;
const CompoundList = parser.CompoundList;
const AndOrList = parser.AndOrList;

const Word = parser.Word;
const WordPart = parser.WordPart;
const Assignment = parser.Assignment;
const ParsedRedirection = parser.ParsedRedirection;
const Redirection = lexer.Redirection;
const ShellState = state.ShellState;
const printError = state.printError;
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
    /// The `exit` builtin was invoked. The exit code is in shell_state.exit_code.
    ExitRequested,
    /// The `break` builtin was invoked. The level count is in shell_state.break_levels.
    BreakRequested,
    /// The `continue` builtin was invoked. The level count is in shell_state.continue_levels.
    ContinueRequested,
    /// Feature not yet implemented (e.g., multi-command pipelines).
    NotImplemented,
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

/// Saved file descriptors for restoration after builtin execution with redirections.
/// This allows builtins to have redirections applied, then restored afterward
/// so the shell's own stdin/stdout/stderr remain intact.
const SavedFds = struct {
    const Entry = struct {
        fd: posix.fd_t,
        saved: ?posix.fd_t,
    };

    /// Maximum number of redirections we can save/restore.
    /// Bounded to 16 entries - if a command has more than 16 redirections,
    /// the excess ones won't be saved/restored. This is a reasonable limit;
    /// typical commands have 1-3 redirections.
    const MAX_ENTRIES = 16;

    entries: [MAX_ENTRIES]Entry = undefined,
    len: usize = 0,

    const SaveError = error{TooManyRedirections};

    /// Save file descriptors that will be modified by the given redirections.
    /// For each fd: if it currently exists, dup it for later restoration.
    /// If it doesn't exist, record null so we know to close it later.
    /// If there are no redirections, this returns an empty entries list
    /// and restore() will be a no-op.
    ///
    /// The saved fds are created with FD_CLOEXEC set to prevent them from
    /// leaking to child processes if a builtin ever forks.
    ///
    /// Returns error.TooManyRedirections if there are more unique fds to save
    /// than MAX_ENTRIES (16). This is a safeguard to prevent silent fd corruption.
    fn save(redirections: []const ParsedRedirection) SaveError!SavedFds {
        var self = SavedFds{};

        for (redirections) |redir| {
            const fd: posix.fd_t = @intCast(redir.source_fd orelse defaultSourceFd(redir.op));

            // Check if we've already saved this fd
            var already_saved = false;
            for (self.entries[0..self.len]) |entry| {
                if (entry.fd == fd) {
                    already_saved = true;
                    break;
                }
            }
            if (already_saved) continue;

            // Check capacity before adding
            if (self.len >= MAX_ENTRIES) {
                // Clean up already-saved fds before returning error
                for (self.entries[0..self.len]) |entry| {
                    if (entry.saved) |saved_fd| {
                        posix.close(saved_fd);
                    }
                }
                return error.TooManyRedirections;
            }

            // Try to dup with CLOEXEC - succeeds if fd exists, fails if not
            // Use dup() then set FD_CLOEXEC via fcntl for cross-platform compatibility
            const saved: ?posix.fd_t = if (posix.dup(fd)) |duped_fd| blk: {
                // Set CLOEXEC on the duplicated fd so it doesn't leak to child processes
                _ = posix.fcntl(duped_fd, posix.F.SETFD, @as(usize, posix.FD_CLOEXEC)) catch {};
                break :blk duped_fd;
            } else |_| null;
            self.entries[self.len] = .{ .fd = fd, .saved = saved };
            self.len += 1;
        }
        return self;
    }

    /// Restore file descriptors to their original state.
    /// If we saved a copy, restore it with dup2 (which implicitly closes
    /// the redirection's fd). If we didn't save a copy (fd didn't exist
    /// before), just close the fd that the redirection created.
    /// If there are no entries, this is a no-op.
    ///
    /// Returns true if all restorations succeeded, false if any dup2 failed.
    /// On failure, continues restoring remaining fds but logs an error.
    fn restore(self: SavedFds) bool {
        var success = true;
        for (self.entries[0..self.len]) |entry| {
            if (entry.saved) |saved_fd| {
                // Existed before - restore original (dup2 closes entry.fd implicitly)
                posix.dup2(saved_fd, entry.fd) catch {
                    // Log error but continue restoring other fds
                    printError("failed to restore fd {d}\n", .{entry.fd});
                    success = false;
                };
                posix.close(saved_fd);
            } else {
                // Didn't exist before - close the fd created by redirection
                posix.close(entry.fd);
            }
        }
        return success;
    }
};

/// Configuration for child process execution.
/// Used for pipe wiring and execution mode flags.
const ExecConfig = struct {
    /// fd to wire to stdin (null = inherit).
    stdin_fd: ?posix.fd_t = null,
    /// fd to wire to stdout (null = inherit).
    stdout_fd: ?posix.fd_t = null,
    /// Additional fds to close before exec.
    /// TODO: Used for here-docs and process substitution where children need
    /// to close fds they shouldn't inherit (e.g., write ends of here-doc pipes).
    close_fds: []const posix.fd_t = &.{},

    /// Apply pipe fd wiring. Call at start of child process.
    fn applyPipes(self: ExecConfig) void {
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
    /// Returns the exit status of the command, or error.ExitRequested if
    /// the exit builtin was invoked.
    ///
    /// POSIX Reference: Section 2.9.1 - Simple Commands
    pub fn execute(self: *Executor, cmd: SimpleCommand, redirections: []const ParsedRedirection) ExecuteError!ExitStatus {
        self.error_info = null;

        // Handle commands with no argv
        if (cmd.argv.len == 0) {
            // Apply assignments to shell variables
            // POSIX Reference: Section 2.9.1 - variable assignments without command
            for (cmd.assignments) |assignment| {
                const value = expand.expandWordJoined(self.allocator, assignment.value, self.shell_state) catch |err| {
                    switch (err) {
                        // Error message already printed by expansion
                        error.ParameterUnsetOrNull, error.ParameterAssignmentInvalid => {},
                        else => self.setError("failed to expand assignment value", @errorName(err)),
                    }
                    self.shell_state.last_status = .{ .exited = 1 };
                    return self.shell_state.last_status;
                };
                try self.shell_state.setVariable(assignment.name, value);
            }

            // Apply redirections with save/restore (no-op if empty).
            // This handles commands like "> file" which create/truncate the file.
            // The save/restore ensures the shell's fds are not permanently modified.
            const saved_fds = SavedFds.save(redirections) catch {
                printError("too many redirections\n", .{});
                self.setError("too many redirections", null);
                self.shell_state.last_status = .{ .exited = ExitStatus.GENERAL_ERROR };
                return self.shell_state.last_status;
            };
            defer _ = saved_fds.restore();

            switch (applyRedirections(self.allocator, redirections, self.shell_state)) {
                .ok => {},
                .err => |msg| {
                    // Empty message means error was already printed (e.g., ParameterUnsetOrNull)
                    if (msg.len > 0) {
                        printError("{s}\n", .{msg});
                        self.setError(msg, null);
                    }
                    self.shell_state.last_status = .{ .exited = ExitStatus.GENERAL_ERROR };
                    return self.shell_state.last_status;
                },
            }

            self.shell_state.last_status = .{ .exited = 0 };
            return self.shell_state.last_status;
        }

        // Expand argv
        const argv = expand.expandArgv(self.allocator, cmd.argv, self.shell_state) catch |err| {
            switch (err) {
                // Error message already printed by expansion
                error.ParameterUnsetOrNull, error.ParameterAssignmentInvalid => {},
                else => self.setError("failed to expand arguments", @errorName(err)),
            }
            self.shell_state.last_status = .{ .exited = 1 };
            return self.shell_state.last_status;
        };

        // Get the command name
        const cmd_name = std.mem.span(argv[0] orelse {
            self.setError("empty command", null);
            self.shell_state.last_status = .{ .exited = 1 };
            return self.shell_state.last_status;
        });

        // Check if this is a builtin command
        if (builtins.Builtin.fromName(cmd_name)) |builtin| {
            // For special builtins, variable assignments are persistent
            // POSIX Reference: Section 2.14 - Special Built-In Utilities
            for (cmd.assignments) |assignment| {
                const value = expand.expandWordJoined(self.allocator, assignment.value, self.shell_state) catch |err| {
                    switch (err) {
                        // Error message already printed by expansion
                        error.ParameterUnsetOrNull, error.ParameterAssignmentInvalid => {},
                        else => self.setError("failed to expand assignment value", @errorName(err)),
                    }
                    self.shell_state.last_status = .{ .exited = 1 };
                    return self.shell_state.last_status;
                };
                try self.shell_state.setVariable(assignment.name, value);
            }

            // Build args slice for builtin
            // Count args first, then create a fixed slice
            var argc: usize = 0;
            while (argv[argc] != null) : (argc += 1) {}
            const args = try self.allocator.alloc([]const u8, argc);
            defer self.allocator.free(args);
            for (0..argc) |i| {
                args[i] = std.mem.span(argv[i].?);
            }

            // Save fds and apply redirections for builtins
            // If no redirections, save/restore are no-ops (empty entries list)
            const saved_fds = SavedFds.save(redirections) catch {
                printError("too many redirections\n", .{});
                self.setError("too many redirections", null);
                self.shell_state.last_status = .{ .exited = ExitStatus.GENERAL_ERROR };
                return self.shell_state.last_status;
            };
            defer _ = saved_fds.restore();

            switch (applyRedirections(self.allocator, redirections, self.shell_state)) {
                .ok => {},
                .err => |msg| {
                    // Empty message means error was already printed (e.g., ParameterUnsetOrNull)
                    if (msg.len > 0) {
                        printError("{s}\n", .{msg});
                        self.setError(msg, null);
                    }
                    self.shell_state.last_status = .{ .exited = ExitStatus.GENERAL_ERROR };
                    return self.shell_state.last_status;
                },
            }

            // Run the builtin
            const result = builtin.run(args, self.shell_state);

            switch (result) {
                .exit_code => |code| {
                    self.shell_state.last_status = .{ .exited = code };
                    return self.shell_state.last_status;
                },
                .exit => |code| {
                    self.shell_state.last_status = .{ .exited = code };
                    self.shell_state.exit_code = code;
                    return error.ExitRequested;
                },
                .break_loop => |levels| {
                    self.shell_state.break_levels = levels;
                    return error.BreakRequested;
                },
                .continue_loop => |levels| {
                    self.shell_state.continue_levels = levels;
                    return error.ContinueRequested;
                },
                .builtin_error => |code| {
                    // POSIX Section 2.8.1: Special built-in errors cause
                    // non-interactive shells to exit, interactive shells continue.
                    self.shell_state.last_status = .{ .exited = code };
                    if (!self.shell_state.options.interactive) {
                        self.shell_state.exit_code = code;
                        return error.ExitRequested;
                    }
                    return self.shell_state.last_status;
                },
            }
        }

        // Not a builtin - fork and exec external command

        // Fork
        const pid = posix.fork() catch |err| {
            self.setError("fork failed", @errorName(err));
            self.shell_state.last_status = .{ .exited = 1 };
            return self.shell_state.last_status;
        };

        if (pid == 0) {
            // Child process - executeChild is noreturn (it execs or exits)
            self.executeChild(cmd, redirections, argv, .{});
        }

        // Parent process
        const result = posix.waitpid(pid, 0);
        self.shell_state.last_status = statusFromWaitResult(result.status);
        return self.shell_state.last_status;
    }

    /// Clean up after pipeline failure.
    /// Kills already-forked children and closes pipe fd.
    fn cleanupPipeline(self: *Executor, pids: []const posix.pid_t, read_fd: ?posix.fd_t) void {
        _ = self;
        if (read_fd) |fd| posix.close(fd);
        for (pids) |pid| {
            posix.kill(pid, posix.SIG.KILL) catch {};
            _ = posix.waitpid(pid, 0);
        }
    }

    /// Execute a multi-command pipeline.
    /// Each command runs in a subshell. Returns exit status of last command.
    ///
    /// Note: This function should only be called for pipelines with 2+ commands.
    /// Single-command "pipelines" are executed directly via execute() to ensure
    /// builtins like cd, export, exit affect the current shell environment.
    fn executePipeline(self: *Executor, pipeline: parser.Pipeline) ExecuteError!ExitStatus {
        const cmds = pipeline.commands;
        std.debug.assert(cmds.len >= 2);

        var pids: std.ArrayListUnmanaged(posix.pid_t) = .empty;
        defer pids.deinit(self.allocator);
        var read_fd: ?posix.fd_t = null;

        for (cmds, 0..) |cmd, i| {
            const is_last = (i == cmds.len - 1);

            // Create pipe for non-last commands
            const pipe_fds: ?[2]posix.fd_t = if (!is_last)
                posix.pipe() catch {
                    printError("pipe failed\n", .{});
                    self.cleanupPipeline(pids.items, read_fd);
                    self.shell_state.last_status = .{ .exited = ExitStatus.GENERAL_ERROR };
                    return self.shell_state.last_status;
                }
            else
                null;

            const pid = posix.fork() catch {
                printError("fork failed\n", .{});
                if (pipe_fds) |fds| {
                    posix.close(fds[0]);
                    posix.close(fds[1]);
                }
                self.cleanupPipeline(pids.items, read_fd);
                self.shell_state.last_status = .{ .exited = ExitStatus.GENERAL_ERROR };
                return self.shell_state.last_status;
            };

            if (pid == 0) {
                // Child: close read end of new pipe (parent saves it for next stage)
                if (pipe_fds) |fds| posix.close(fds[0]);

                self.executeSingleCommandInChild(cmd, .{
                    .stdin_fd = read_fd,
                    .stdout_fd = if (pipe_fds) |fds| fds[1] else null,
                });
            }

            // Parent: close fds we're done with
            if (read_fd) |fd| posix.close(fd);
            if (pipe_fds) |fds| {
                posix.close(fds[1]); // Close write end
                read_fd = fds[0]; // Save read end for next stage
            } else {
                read_fd = null; // Last command, no more pipes
            }

            pids.append(self.allocator, pid) catch {
                printError("failed to track child process\n", .{});
                self.cleanupPipeline(pids.items, read_fd);
                self.shell_state.last_status = .{ .exited = ExitStatus.GENERAL_ERROR };
                return self.shell_state.last_status;
            };
        }

        // Close final read fd
        if (read_fd) |fd| posix.close(fd);

        // Wait for all children, capture exit status of last.
        //
        // Note on SIGPIPE: When a downstream command exits early (e.g., `yes | head -1`),
        // upstream commands may receive SIGPIPE when writing to the closed pipe. This is
        // normal pipeline behavior - the signaled status is captured by waitpid but doesn't
        // affect the pipeline's exit status, which is always from the last command.
        // This matches standard shell behavior (bash, dash, zsh).
        var last_status: ExitStatus = .{ .exited = 0 };
        for (pids.items) |pid| {
            const result = posix.waitpid(pid, 0);
            last_status = statusFromWaitResult(result.status);
        }

        self.shell_state.last_status = last_status;
        return last_status;
    }

    /// Execute a command (simple or compound).
    ///
    /// This is the primary interface for pull-based execution.
    /// Returns the exit status of the command, or error.ExitRequested
    /// if the exit builtin was invoked.
    ///
    /// For AND/OR lists (POSIX Section 2.9.3):
    /// - `&&` executes the next pipeline only if the previous succeeded (exit 0)
    /// - `||` executes the next pipeline only if the previous failed (exit non-zero)
    /// - Evaluation is left-to-right with short-circuit semantics
    /// - Exit status is the last pipeline that was actually executed
    ///
    /// Example: `false && echo a || echo b && echo c`
    /// items: [(false, And), (a, Or), (b, And), (c, null)]
    /// - Execute false -> status=1, trailing_op=And, failed so set execute_next=false
    /// - Item (a, Or): execute_next=false, skip. trailing_op=Or, status=1 (failed), so set execute_next=true
    /// - Item (b, And): execute_next=true, execute b -> status=0. trailing_op=And, succeeded, so execute_next=true
    /// - Item (c, null): execute_next=true, execute c -> status=0
    /// - Final exit status: 0
    ///
    /// Example usage with parser iterator:
    /// ```
    /// while (try parser.next()) |cmd| {
    ///     _ = try executor.executeCommand(cmd);
    /// }
    /// ```
    pub fn executeCommand(self: *Executor, cmd: ParsedCommand) ExecuteError!ExitStatus {
        const and_or = cmd.and_or;
        var status: ExitStatus = .{ .exited = 0 };
        var execute_next = true;

        for (and_or.items) |item| {
            if (execute_next) {
                status = try self.executePipelineWithNegation(item.pipeline);
            }

            // Decide whether to execute the next item based on trailing_op and current status.
            // When we skip a pipeline, we still check its trailing_op against the unchanged
            // status to decide about the pipeline after that.
            if (item.trailing_op) |op| {
                const succeeded = (status.toExitCode() == 0);
                execute_next = switch (op) {
                    .And => succeeded, // && : execute next only if this succeeded
                    .Or => !succeeded, // || : execute next only if this failed
                };
            }
        }

        self.shell_state.last_status = status;
        return status;
    }

    /// Execute a pipeline and return its exit status, handling negation.
    ///
    /// This handles empty pipelines, single commands, multi-command pipelines,
    /// and pipeline negation (! prefix) per POSIX Section 2.9.2.
    fn executePipelineWithNegation(self: *Executor, pipeline: parser.Pipeline) ExecuteError!ExitStatus {
        // Execute the pipeline and get the exit status
        const status: ExitStatus = if (pipeline.commands.len == 0)
            // Empty pipeline - return success
            .{ .exited = 0 }
        else if (pipeline.commands.len == 1)
            // Single-command "pipeline" - execute in current environment.
            // This ensures builtins like cd, export, exit work correctly.
            // Let BreakRequested/ContinueRequested propagate up to the loop handler.
            try self.executeSingleCommand(pipeline.commands[0])
        else
            // Multi-command pipeline - all stages run in subshells
            try self.executePipeline(pipeline);

        // Handle negation (! prefix per POSIX Section 2.9.2):
        // "If the pipeline begins with the reserved word !, the exit status
        // shall be the logical NOT of the exit status of the last command."
        if (pipeline.negated) {
            return switch (status) {
                .exited => |code| ExitStatus{ .exited = if (code == 0) 1 else 0 },
                .signaled => ExitStatus{ .exited = 0 }, // Non-zero exit negated to 0
            };
        }

        return status;
    }

    /// Execute a compound-list (sequence of AND/OR lists).
    ///
    /// Reference: POSIX.1-2017 Section 2.9.3 Lists
    /// The exit status of a compound-list is the exit status of the last
    /// AND/OR list that was executed.
    fn executeCompoundList(self: *Executor, list: CompoundList) ExecuteError!ExitStatus {
        var status: ExitStatus = .{ .exited = 0 };
        for (list.commands) |and_or| {
            status = try self.executeAndOrList(and_or);
        }
        return status;
    }

    /// Execute an AND/OR list.
    ///
    /// This is a helper that wraps an AndOrList in a ParsedCommand and
    /// delegates to executeCommand, reusing its AND/OR evaluation logic.
    fn executeAndOrList(self: *Executor, and_or: AndOrList) ExecuteError!ExitStatus {
        return self.executeCommand(.{ .and_or = and_or });
    }

    /// Execute an if clause (if/elif/else/fi construct).
    ///
    /// Reference: POSIX.1-2017 Section 2.9.4.1
    /// "The if command shall execute a compound-list and use its exit status
    /// to determine whether to execute another compound-list."
    ///
    /// The exit status of the if command is the exit status of the then or
    /// else compound-list that was executed, or zero if none was executed.
    fn executeIfClause(self: *Executor, ic: IfClause) ExecuteError!ExitStatus {
        // Evaluate each branch's condition in order
        for (ic.branches) |branch| {
            const cond_status = try self.executeCompoundList(branch.condition);
            if (cond_status.toExitCode() == 0) {
                // Condition succeeded (exit status 0), execute body
                return try self.executeCompoundList(branch.body);
            }
        }

        // No condition matched, try else
        if (ic.else_body) |else_body| {
            return try self.executeCompoundList(else_body);
        }

        // POSIX.1-2017 Section 2.9.4.1:
        // "...or zero, if none was executed."
        return ExitStatus{ .exited = 0 };
    }

    /// Execute a while or until loop.
    ///
    /// Reference: POSIX.1-2017 Section 2.9.4.3
    /// "The while loop shall continuously execute one compound-list as long as
    /// another compound-list has a zero exit status."
    /// "The until loop shall continuously execute one compound-list as long as
    /// another compound-list has a non-zero exit status."
    ///
    /// Handles break and continue builtins:
    /// - break n: Exits n levels of loops. Decrements level counter and re-propagates
    ///   if > 1, otherwise breaks from this loop and returns.
    /// - continue n: Skips to next iteration of nth enclosing loop. Decrements level
    ///   counter and re-propagates if > 1, otherwise continues to next iteration.
    ///
    /// The exit status is the exit status of the last body execution,
    /// or zero if the body was never executed.
    fn executeLoopClause(self: *Executor, lc: LoopClause, is_until: bool) ExecuteError!ExitStatus {
        var status: ExitStatus = .{ .exited = 0 };

        while (true) {
            const cond_status = self.executeCompoundList(lc.condition) catch |err| switch (err) {
                error.BreakRequested => {
                    self.shell_state.break_levels -= 1;
                    if (self.shell_state.break_levels > 0) return error.BreakRequested;
                    return .{ .exited = 0 }; // break exits with status 0 (POSIX)
                },
                error.ContinueRequested => {
                    self.shell_state.continue_levels -= 1;
                    if (self.shell_state.continue_levels > 0) return error.ContinueRequested;
                    continue; // skip to next iteration
                },
                else => return err,
            };

            const cond_exit = cond_status.toExitCode();

            // while: continue if condition exits 0
            // until: continue if condition exits non-zero
            const should_continue = if (is_until) (cond_exit != 0) else (cond_exit == 0);

            if (!should_continue) break;

            status = self.executeCompoundList(lc.body) catch |err| switch (err) {
                error.BreakRequested => {
                    self.shell_state.break_levels -= 1;
                    if (self.shell_state.break_levels > 0) return error.BreakRequested;
                    return .{ .exited = 0 }; // break exits with status 0 (POSIX)
                },
                error.ContinueRequested => {
                    self.shell_state.continue_levels -= 1;
                    if (self.shell_state.continue_levels > 0) return error.ContinueRequested;
                    continue;
                },
                else => return err,
            };
        }

        return status;
    }

    /// Execute a single command (simple or compound) in the current environment.
    ///
    /// This is the unified dispatch point for all command types. Simple commands
    /// are executed via execute(), compound commands via their specific handlers.
    ///
    /// For compound commands, redirections are applied here with save/restore since
    /// they run entirely in the current shell. For simple commands, execute() handles
    /// redirections (save/restore for builtins, child-only for externals).
    ///
    /// Reference: POSIX.1-2017 Section 2.9.1 Simple Commands
    /// Reference: POSIX.1-2017 Section 2.9.4 Compound Commands
    fn executeSingleCommand(self: *Executor, cmd: Command) ExecuteError!ExitStatus {
        // Simple commands handle their own redirections (different logic for builtins vs externals)
        if (cmd.type == .simple) {
            return self.execute(cmd.type.simple, cmd.redirections);
        }

        // Compound commands run in current shell - apply redirections with save/restore
        const saved_fds = SavedFds.save(cmd.redirections) catch {
            printError("too many redirections\n", .{});
            self.setError("too many redirections", null);
            self.shell_state.last_status = .{ .exited = ExitStatus.GENERAL_ERROR };
            return self.shell_state.last_status;
        };
        defer _ = saved_fds.restore();

        switch (applyRedirections(self.allocator, cmd.redirections, self.shell_state)) {
            .ok => {},
            .err => |msg| {
                if (msg.len > 0) {
                    printError("{s}\n", .{msg});
                    self.setError(msg, null);
                }
                self.shell_state.last_status = .{ .exited = ExitStatus.GENERAL_ERROR };
                return self.shell_state.last_status;
            },
        }

        return switch (cmd.type) {
            .simple => unreachable, // handled above
            .if_clause => |ic| self.executeIfClause(ic),
            .while_clause => |lc| self.executeLoopClause(lc, false),
            .until_clause => |lc| self.executeLoopClause(lc, true),
        };
    }

    /// Handle an ExecuteError in a child process by exiting with appropriate status.
    ///
    /// For ExitRequested errors (from the exit builtin), uses the shell's exit code.
    /// For all other errors, prints a diagnostic message and exits with GENERAL_ERROR.
    /// This function never returns - it always calls posix.exit().
    fn exitWithError(self: *Executor, err: ExecuteError) noreturn {
        switch (err) {
            error.ExitRequested => posix.exit(self.shell_state.exit_code),
            error.BreakRequested => {
                // break in a child process should exit normally
                // The break was handled within the child's loop
                posix.exit(0);
            },
            error.ContinueRequested => {
                // continue in a child process should exit normally
                // The continue was handled within the child's loop
                posix.exit(0);
            },
            else => {
                printError("command execution failed: {s}\n", .{@errorName(err)});
                posix.exit(ExitStatus.GENERAL_ERROR);
            },
        }
    }

    /// Execute a single command in a child process (for pipeline stages).
    ///
    /// Applies pipe wiring and executes the command, then exits with its status.
    /// This function never returns.
    ///
    /// Simple commands use the specialized executeChild path which handles
    /// redirections, builtins, and external command execution. Compound commands
    /// apply redirections here before execution (no save/restore needed in child).
    fn executeSingleCommandInChild(self: *Executor, cmd: Command, config: ExecConfig) noreturn {
        // Apply pipe wiring first
        config.applyPipes();

        // Simple commands use executeChild which handles redirections internally
        if (cmd.type == .simple) {
            const s = cmd.type.simple;
            const argv = expand.expandArgv(self.allocator, s.argv, self.shell_state) catch |err| {
                switch (err) {
                    error.ParameterUnsetOrNull, error.ParameterAssignmentInvalid => {},
                    else => printError("failed to expand arguments: {s}\n", .{@errorName(err)}),
                }
                posix.exit(ExitStatus.GENERAL_ERROR);
            };
            // executeChild applies redirections and handles builtins/externals.
            // Pass a no-op config since pipes are already set up.
            self.executeChild(s, cmd.redirections, argv, .{ .stdin_fd = null, .stdout_fd = null });
        }

        // Compound commands: apply redirections here (no save/restore in child)
        switch (applyRedirections(self.allocator, cmd.redirections, self.shell_state)) {
            .ok => {},
            .err => |msg| {
                if (msg.len > 0) printError("{s}\n", .{msg});
                posix.exit(ExitStatus.GENERAL_ERROR);
            },
        }

        const status = switch (cmd.type) {
            .simple => unreachable, // handled above
            .if_clause => |ic| self.executeIfClause(ic) catch |err| self.exitWithError(err),
            .while_clause => |lc| self.executeLoopClause(lc, false) catch |err| self.exitWithError(err),
            .until_clause => |lc| self.executeLoopClause(lc, true) catch |err| self.exitWithError(err),
        };
        posix.exit(status.toExitCode());
    }

    /// Execute a simple command in the child process.
    /// Handles redirections, builtins, and external commands.
    /// This function never returns - it either execs or exits.
    ///
    /// Note: When called from executeSingleCommandInChild, pipe wiring is
    /// already applied and config will have null fds. When called directly
    /// from tests or other paths, config may contain pipe fds to apply.
    fn executeChild(
        self: *Executor,
        cmd: SimpleCommand,
        redirections: []const ParsedRedirection,
        argv: [*:null]const ?[*:0]const u8,
        config: ExecConfig,
    ) noreturn {
        // 1. Apply pipe wiring if provided (before redirections)
        config.applyPipes();

        // 2. Apply command redirections
        switch (applyRedirections(self.allocator, redirections, self.shell_state)) {
            .ok => {},
            .err => |msg| {
                // Empty message means error was already printed (e.g., ParameterUnsetOrNull)
                if (msg.len > 0) {
                    printError("{s}\n", .{msg});
                }
                posix.exit(ExitStatus.GENERAL_ERROR);
            },
        }

        // 3. Handle empty argv (assignment-only command in pipeline)
        const cmd_name = argv[0] orelse {
            // Assignment-only command in pipeline subshell.
            // Pipe wiring and redirections already applied above.
            // Assignments only affect shell variables in this subshell,
            // which exits immediately, so we skip applying them.
            // Matches bash/dash behavior.
            posix.exit(0);
        };

        // 4. Check for builtin (for pipeline stages)
        if (builtins.Builtin.fromName(std.mem.span(cmd_name))) |builtin| {
            var argc: usize = 0;
            while (argv[argc] != null) : (argc += 1) {}
            const args = self.allocator.alloc([]const u8, argc) catch {
                printError("failed to allocate arguments\n", .{});
                posix.exit(ExitStatus.GENERAL_ERROR);
            };
            for (0..argc) |i| {
                args[i] = std.mem.span(argv[i].?);
            }
            const result = builtin.run(args, self.shell_state);
            // In a child process, handle results appropriately.
            // For break/continue, exit with 0 (child is isolated).
            switch (result) {
                .exit_code => |code| posix.exit(code),
                .exit => |code| posix.exit(code),
                .break_loop, .continue_loop => posix.exit(0),
                .builtin_error => |code| posix.exit(code),
            }
        }

        // 5. Build env map (moved from parent - only needed for external commands)
        var env_map = self.buildChildEnvMap(cmd.assignments) catch |err| {
            switch (err) {
                // Error message already printed by expansion
                error.ParameterUnsetOrNull, error.ParameterAssignmentInvalid => {},
                else => printError("failed to build environment: {s}\n", .{@errorName(err)}),
            }
            posix.exit(ExitStatus.GENERAL_ERROR);
        };

        // 6. Find executable
        const exe_path = switch (findExecutable(self.allocator, cmd_name, &env_map)) {
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

        // 7. Execute
        const envp = process.createNullDelimitedEnvMap(self.allocator, &env_map) catch {
            printError("{s}: failed to create environment\n", .{cmd_name});
            posix.exit(ExitStatus.GENERAL_ERROR);
        };
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
    fn buildChildEnvMap(self: *Executor, assignments: []const Assignment) expand.ExpansionError!process.EnvMap {
        // Copy the shell's environment
        var env_map = process.EnvMap.init(self.allocator);

        // Copy all entries from shell state's environment
        var iter = self.shell_state.env.hash_map.iterator();
        while (iter.next()) |entry| {
            try env_map.put(entry.key_ptr.*, entry.value_ptr.*);
        }

        // Add/override with command-specific assignments
        for (assignments) |assignment| {
            const value = try expand.expandWordJoined(self.allocator, assignment.value, self.shell_state);
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

/// Find an executable in PATH or return the command if it contains a slash.
///
/// POSIX behavior:
/// - If command contains '/', use it as-is (absolute or relative path)
/// - Otherwise, search each directory in PATH
///
/// Returns FindResult indicating success, not found (exit 127), or not executable (exit 126).
///
/// TODO: Implement PATH lookup caching to avoid repeated filesystem searches for
/// frequently-used commands. Shells like bash maintain a hash table (accessible via
/// the `hash` builtin) that maps command names to their resolved paths. The cache
/// should be invalidated when PATH changes or when `hash -r` is invoked.
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
/// On success, returns .ok.
/// On failure, returns .err with an error message. The caller is responsible
/// for printing the error and determining the appropriate exit status.
/// Note: An empty error message indicates the error was already printed (e.g.,
/// by ExpansionError.ParameterUnsetOrNull or ParameterAssignmentInvalid) and
/// should not be printed again.
fn applyRedirections(allocator: Allocator, redirections: []const ParsedRedirection, shell: *ShellState) RedirectionResult {
    for (redirections) |redir| {
        const source_fd: posix.fd_t = @intCast(redir.source_fd orelse defaultSourceFd(redir.op));

        switch (redir.target) {
            .file => |word| {
                // POSIX 2.7 (Redirection): Following dash behavior, field splitting and
                // pathname expansion are not performed on redirection targets.
                const path_slice = expand.expandWordJoined(allocator, word, shell) catch |err| {
                    return .{
                        .err = switch (err) {
                            // Error message already printed by expansion
                            error.ParameterUnsetOrNull, error.ParameterAssignmentInvalid => "",
                            else => "failed to expand redirection target",
                        },
                    };
                };
                const path = allocator.dupeZ(u8, path_slice) catch {
                    return .{ .err = "failed to allocate redirection path" };
                };
                const flags = openFlagsForOp(redir.op);
                const fd = posix.openZ(path, flags, 0o666) catch |err| {
                    // Format error message with path
                    const msg = std.fmt.allocPrint(allocator, "{s}: {s}", .{ path, @errorName(err) }) catch {
                        return .{ .err = @errorName(err) };
                    };
                    return .{ .err = msg };
                };
                if (fd != source_fd) {
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
                posix.dup2(@intCast(target_fd), source_fd) catch |err| {
                    const msg = std.fmt.allocPrint(allocator, "dup2: {s}", .{@errorName(err)}) catch {
                        return .{ .err = @errorName(err) };
                    };
                    return .{ .err = msg };
                };
            },
            .close => {
                posix.close(source_fd);
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

// --- Tests ---

fn parseCommand(allocator: Allocator, input: []const u8) !?ParsedCommand {
    var reader = std.io.Reader.fixed(input);
    var lex = lexer.Lexer.init(&reader);
    var p = parser.Parser.init(allocator, &lex);
    return p.parseCommand();
}

/// Run a command and check its exit status.
fn runCommand(
    arena: *std.heap.ArenaAllocator,
    shell_state: *ShellState,
    command: []const u8,
) !ExitStatus {
    const cmd = try parseCommand(arena.allocator(), command) orelse return error.NoCommand;
    var exec = Executor.init(arena.allocator(), shell_state);
    return exec.executeCommand(cmd) catch |err| switch (err) {
        error.BreakRequested => {
            // break outside a loop - print warning and return 0 (bash behavior)
            printError("break: not in a loop\n", .{});
            shell_state.break_levels = 0;
            return .{ .exited = 0 };
        },
        error.ContinueRequested => {
            // continue outside a loop - print warning and return 0 (bash behavior)
            printError("continue: not in a loop\n", .{});
            shell_state.continue_levels = 0;
            return .{ .exited = 0 };
        },
        error.ExitRequested => {
            // For tests: return the exit code that was set
            return .{ .exited = shell_state.exit_code };
        },
        else => return err,
    };
}

/// Run a command and expect a specific exit code.
fn expectStatus(
    arena: *std.heap.ArenaAllocator,
    shell_state: *ShellState,
    command: []const u8,
    expected_code: u8,
) !void {
    const status = try runCommand(arena, shell_state, command);
    try std.testing.expectEqual(ExitStatus{ .exited = expected_code }, status);
}

/// Expect that a file exists and contains the expected content.
fn expectFileContent(path: []const u8, expected: []const u8) !void {
    const contents = try std.fs.cwd().readFileAlloc(std.testing.allocator, path, 4096);
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualStrings(expected, contents);
}

/// Expect that a file does not exist.
fn expectFileNotFound(path: []const u8) !void {
    const result = std.fs.cwd().readFileAlloc(std.testing.allocator, path, 1024);
    try std.testing.expectError(error.FileNotFound, result);
}

/// Delete a temp file, ignoring errors if it doesn't exist.
fn cleanupTempFile(path: []const u8) void {
    std.fs.deleteFileAbsolute(path) catch {};
}

test "execute: simple echo" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const cmd = try parseCommand(arena.allocator(), "echo hello\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = try exec.executeCommand(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);
}

test "execute: exit status success" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const cmd = try parseCommand(arena.allocator(), "true\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = try exec.executeCommand(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);
}

test "execute: exit status failure" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const cmd = try parseCommand(arena.allocator(), "false\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = try exec.executeCommand(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 1 }, status);
}

test "execute: PATH lookup" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const cmd = try parseCommand(arena.allocator(), "echo hello\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = try exec.executeCommand(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);
}

test "execute: command not found" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const cmd = try parseCommand(arena.allocator(), "nonexistent_cmd_12345\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = try exec.executeCommand(cmd);

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
    const status = try exec.executeCommand(cmd);

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
    const status = try exec.executeCommand(cmd);

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
    _ = try exec.executeCommand(cmd1);

    // Append
    const cmd2 = try parseCommand(arena.allocator(), "echo second >> " ++ tmp_path ++ "\n") orelse return error.NoCommand;
    const status = try exec.executeCommand(cmd2);

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
    const status = try exec.executeCommand(cmd);

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
    const status = try exec.executeCommand(cmd);

    // Assignments-only commands return success
    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);

    // Verify variable was set
    try std.testing.expectEqualStrings("bar", shell_state.getVariable("FOO").?);
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
    const status = try exec.executeCommand(cmd);

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
    const status = try exec.executeCommand(cmd);

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
    const status = try exec.executeCommand(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);

    // The error output should be in the file
    const contents = try std.fs.cwd().readFileAlloc(std.testing.allocator, tmp_path, 1024);
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualStrings("error\n", contents);

    std.fs.deleteFileAbsolute(tmp_path) catch {};
}

test "ExitStatus.toExitCode" {
    try std.testing.expectEqual(@as(u8, 0), (ExitStatus{ .exited = 0 }).toExitCode());
    try std.testing.expectEqual(@as(u8, 1), (ExitStatus{ .exited = 1 }).toExitCode());
    try std.testing.expectEqual(@as(u8, 127), (ExitStatus{ .exited = 127 }).toExitCode());
    try std.testing.expectEqual(@as(u8, 137), (ExitStatus{ .signaled = 9 }).toExitCode()); // SIGKILL
    try std.testing.expectEqual(@as(u8, 143), (ExitStatus{ .signaled = 15 }).toExitCode()); // SIGTERM
}

test "executeCommand: redirection-only command does not affect subsequent command" {
    // Verify that `> file; echo hello` works correctly:
    // - First command creates/truncates the file
    // - Second command outputs to stdout, not to the file
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_redir_then_echo";
    std.fs.deleteFileAbsolute(tmp_path) catch {};

    const input = "> " ++ tmp_path ++ "; echo hello\n";
    var reader = std.io.Reader.fixed(input);
    var lex = lexer.Lexer.init(&reader);
    var p = parser.Parser.init(arena.allocator(), &lex);

    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);

    // Execute commands one at a time using the iterator
    var status: ExitStatus = .{ .exited = 0 };
    while (try p.next()) |cmd| {
        status = try exec.executeCommand(cmd);
    }

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);

    // Verify file was created and is empty (not containing "hello")
    const contents = try std.fs.cwd().readFileAlloc(std.testing.allocator, tmp_path, 1024);
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualStrings("", contents);

    // Clean up
    std.fs.deleteFileAbsolute(tmp_path) catch {};
}

// --- Builtin tests ---

test "execute: exit builtin returns ExitRequested" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const cmd = try parseCommand(arena.allocator(), "exit 42\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);

    const result = exec.executeCommand(cmd);
    try std.testing.expectError(ExecuteError.ExitRequested, result);
    try std.testing.expectEqual(@as(u8, 42), shell_state.exit_code);
}

test "execute: pwd builtin" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const cmd = try parseCommand(arena.allocator(), "pwd\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = try exec.executeCommand(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);
}

test "execute: export and variable visibility" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var shell_state = try ShellState.init(arena.allocator());

    // Set a shell variable
    const cmd1 = try parseCommand(arena.allocator(), "FOO=bar\n") orelse return error.NoCommand;
    var exec = Executor.init(arena.allocator(), &shell_state);
    _ = try exec.executeCommand(cmd1);

    // Should be in variables, not env
    try std.testing.expectEqualStrings("bar", shell_state.getVariable("FOO").?);
    try std.testing.expect(shell_state.env.get("FOO") == null);

    // Export it
    const cmd2 = try parseCommand(arena.allocator(), "export FOO\n") orelse return error.NoCommand;
    _ = try exec.executeCommand(cmd2);

    // Should now be in env
    try std.testing.expectEqualStrings("bar", shell_state.env.get("FOO").?);
}

test "execute: builtin with output redirection" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_builtin_redir";
    std.fs.deleteFileAbsolute(tmp_path) catch {};

    // pwd > file should write cwd to file
    const cmd = try parseCommand(arena.allocator(), "pwd > " ++ tmp_path ++ "\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = try exec.executeCommand(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);

    // Verify file contains the cwd
    const contents = try std.fs.cwd().readFileAlloc(std.testing.allocator, tmp_path, 4096);
    defer std.testing.allocator.free(contents);

    // Contents should match shell_state.cwd with a newline
    const expected = try std.fmt.allocPrint(std.testing.allocator, "{s}\n", .{shell_state.cwd});
    defer std.testing.allocator.free(expected);
    try std.testing.expectEqualStrings(expected, contents);

    // Clean up
    std.fs.deleteFileAbsolute(tmp_path) catch {};
}

test "execute: builtin redirection does not affect subsequent commands" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_builtin_redir_restore";
    std.fs.deleteFileAbsolute(tmp_path) catch {};

    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);

    // First: pwd > file
    const cmd1 = try parseCommand(arena.allocator(), "pwd > " ++ tmp_path ++ "\n") orelse return error.NoCommand;
    _ = try exec.executeCommand(cmd1);

    // Second: pwd (no redirection) - should NOT go to file
    // We can't easily capture stdout in a test, but we can verify the file wasn't appended
    const contents_after_first = try std.fs.cwd().readFileAlloc(std.testing.allocator, tmp_path, 4096);
    defer std.testing.allocator.free(contents_after_first);

    const cmd2 = try parseCommand(arena.allocator(), "pwd\n") orelse return error.NoCommand;
    _ = try exec.executeCommand(cmd2);

    // File should still have the same contents (not doubled)
    const contents_after_second = try std.fs.cwd().readFileAlloc(std.testing.allocator, tmp_path, 4096);
    defer std.testing.allocator.free(contents_after_second);
    try std.testing.expectEqualStrings(contents_after_first, contents_after_second);

    // Clean up
    std.fs.deleteFileAbsolute(tmp_path) catch {};
}

test "execute: builtin with append redirection" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_builtin_append";
    std.fs.deleteFileAbsolute(tmp_path) catch {};

    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);

    // pwd > file (create)
    const cmd1 = try parseCommand(arena.allocator(), "pwd > " ++ tmp_path ++ "\n") orelse return error.NoCommand;
    _ = try exec.executeCommand(cmd1);

    // pwd >> file (append)
    const cmd2 = try parseCommand(arena.allocator(), "pwd >> " ++ tmp_path ++ "\n") orelse return error.NoCommand;
    _ = try exec.executeCommand(cmd2);

    // File should contain cwd twice
    const contents = try std.fs.cwd().readFileAlloc(std.testing.allocator, tmp_path, 4096);
    defer std.testing.allocator.free(contents);

    const expected = try std.fmt.allocPrint(std.testing.allocator, "{s}\n{s}\n", .{ shell_state.cwd, shell_state.cwd });
    defer std.testing.allocator.free(expected);
    try std.testing.expectEqualStrings(expected, contents);

    // Clean up
    std.fs.deleteFileAbsolute(tmp_path) catch {};
}

test "execute: builtin redirection error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // pwd > /nonexistent/path should fail
    const cmd = try parseCommand(arena.allocator(), "pwd > /nonexistent_dir_12345/file\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = try exec.executeCommand(cmd);

    // Should return error status
    try std.testing.expectEqual(ExitStatus{ .exited = ExitStatus.GENERAL_ERROR }, status);
}

// --- Pipeline tests ---

test "executor: simple pipeline" {
    // echo hello | cat -> outputs "hello"
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_simple_pipeline";
    std.fs.deleteFileAbsolute(tmp_path) catch {};

    // Use redirection to capture output: echo hello | cat > file
    const cmd = try parseCommand(arena.allocator(), "echo hello | cat > " ++ tmp_path ++ "\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = try exec.executeCommand(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);

    // Verify output
    const contents = try std.fs.cwd().readFileAlloc(std.testing.allocator, tmp_path, 1024);
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualStrings("hello\n", contents);

    std.fs.deleteFileAbsolute(tmp_path) catch {};
}

test "executor: pipeline exit status from last command" {
    // true | false -> exit 1
    // false | true -> exit 0
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);

    // true | false -> exit 1
    const cmd1 = try parseCommand(arena.allocator(), "true | false\n") orelse return error.NoCommand;
    const status1 = try exec.executeCommand(cmd1);
    try std.testing.expectEqual(ExitStatus{ .exited = 1 }, status1);

    // false | true -> exit 0
    const cmd2 = try parseCommand(arena.allocator(), "false | true\n") orelse return error.NoCommand;
    const status2 = try exec.executeCommand(cmd2);
    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status2);
}

test "executor: negated simple command" {
    // ! true -> exit 1
    // ! false -> exit 0
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);

    // ! true -> exit 1
    const cmd1 = try parseCommand(arena.allocator(), "! true\n") orelse return error.NoCommand;
    const status1 = try exec.executeCommand(cmd1);
    try std.testing.expectEqual(ExitStatus{ .exited = 1 }, status1);

    // ! false -> exit 0
    const cmd2 = try parseCommand(arena.allocator(), "! false\n") orelse return error.NoCommand;
    const status2 = try exec.executeCommand(cmd2);
    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status2);
}

test "executor: negated pipeline" {
    // ! true | false -> exit 0 (last is false=1, negated=0)
    // ! false | true -> exit 1 (last is true=0, negated=1)
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);

    // ! true | false -> last command is false (exit 1), negated = 0
    const cmd1 = try parseCommand(arena.allocator(), "! true | false\n") orelse return error.NoCommand;
    const status1 = try exec.executeCommand(cmd1);
    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status1);

    // ! false | true -> last command is true (exit 0), negated = 1
    const cmd2 = try parseCommand(arena.allocator(), "! false | true\n") orelse return error.NoCommand;
    const status2 = try exec.executeCommand(cmd2);
    try std.testing.expectEqual(ExitStatus{ .exited = 1 }, status2);
}

test "executor: three-stage pipeline" {
    // echo hello | cat | cat -> outputs "hello"
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_three_stage_pipeline";
    std.fs.deleteFileAbsolute(tmp_path) catch {};

    const cmd = try parseCommand(arena.allocator(), "echo hello | cat | cat > " ++ tmp_path ++ "\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = try exec.executeCommand(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);

    // Verify output
    const contents = try std.fs.cwd().readFileAlloc(std.testing.allocator, tmp_path, 1024);
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualStrings("hello\n", contents);

    std.fs.deleteFileAbsolute(tmp_path) catch {};
}

test "executor: builtin in pipeline" {
    // pwd | cat -> outputs current directory
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_builtin_pipeline";
    std.fs.deleteFileAbsolute(tmp_path) catch {};

    const cmd = try parseCommand(arena.allocator(), "pwd | cat > " ++ tmp_path ++ "\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = try exec.executeCommand(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);

    // Verify output contains the cwd
    const contents = try std.fs.cwd().readFileAlloc(std.testing.allocator, tmp_path, 4096);
    defer std.testing.allocator.free(contents);

    const expected = try std.fmt.allocPrint(std.testing.allocator, "{s}\n", .{shell_state.cwd});
    defer std.testing.allocator.free(expected);
    try std.testing.expectEqualStrings(expected, contents);

    std.fs.deleteFileAbsolute(tmp_path) catch {};
}

test "executor: builtin in single-command pipeline affects current env" {
    // Verify that `cd /tmp` (which is parsed as a single-command pipeline)
    // actually changes the current directory
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);

    // Save original cwd
    const original_cwd = shell_state.cwd;

    // Execute cd /tmp
    const cmd = try parseCommand(arena.allocator(), "cd /tmp\n") orelse return error.NoCommand;
    const status = try exec.executeCommand(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);

    // Verify cwd changed
    try std.testing.expectEqualStrings("/tmp", shell_state.cwd);
    try std.testing.expect(!std.mem.eql(u8, original_cwd, shell_state.cwd) or std.mem.eql(u8, original_cwd, "/tmp"));
}

test "executor: builtin in multi-command pipeline does not affect current env" {
    // Verify that `echo x | cd /tmp` does NOT change the current directory
    // (cd runs in a subshell)
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);

    // Save original cwd
    const original_cwd = try arena.allocator().dupe(u8, shell_state.cwd);

    // Execute echo x | cd /
    // Note: cd in a pipeline runs in a subshell and doesn't affect parent
    const cmd = try parseCommand(arena.allocator(), "echo x | cd /\n") orelse return error.NoCommand;
    _ = try exec.executeCommand(cmd);

    // Verify cwd did NOT change
    try std.testing.expectEqualStrings(original_cwd, shell_state.cwd);
}

test "executor: assignment-only command in pipeline" {
    // X=test | cat -> exits 0, X not set in parent
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);

    // Ensure X is not set
    try std.testing.expect(shell_state.getVariable("X") == null);

    // Execute X=test | cat
    const cmd = try parseCommand(arena.allocator(), "X=test | cat\n") orelse return error.NoCommand;
    const status = try exec.executeCommand(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);

    // X should still not be set in parent (assignment was in subshell)
    try std.testing.expect(shell_state.getVariable("X") == null);
}

// --- AND/OR list tests ---

test "executor: && runs second on success" {
    // true && echo yes -> should print "yes" and exit 0
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_and_success";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "true && echo yes > " ++ tmp_path ++ "\n", 0);
    try expectFileContent(tmp_path, "yes\n");
}

test "executor: && skips second on failure" {
    // false && echo yes -> should NOT print "yes" and exit 1
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_and_failure";
    cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "false && echo yes > " ++ tmp_path ++ "\n", 1);
    try expectFileNotFound(tmp_path);
}

test "executor: || skips second on success" {
    // true || echo no -> should NOT print "no" and exit 0
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_or_success";
    cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "true || echo no > " ++ tmp_path ++ "\n", 0);
    try expectFileNotFound(tmp_path);
}

test "executor: || runs second on failure" {
    // false || echo yes -> should print "yes" and exit 0
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_or_failure";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "false || echo yes > " ++ tmp_path ++ "\n", 0);
    try expectFileContent(tmp_path, "yes\n");
}

test "executor: && chain all succeed" {
    // true && true && true -> exit 0
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "true && true && true\n", 0);
}

test "executor: && chain early failure" {
    // true && false && echo no -> should NOT print and exit 1
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_and_chain_failure";
    cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "true && false && echo no > " ++ tmp_path ++ "\n", 1);
    try expectFileNotFound(tmp_path);
}

test "executor: || chain early success" {
    // false || true || echo no -> should NOT print "no" and exit 0
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_or_chain_success";
    cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "false || true || echo no > " ++ tmp_path ++ "\n", 0);
    try expectFileNotFound(tmp_path);
}

test "executor: && then || (false && a || b)" {
    // false && echo a || echo b -> should print "b" (not "a")
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_a = "/tmp/tsh_test_and_or_a";
    const tmp_b = "/tmp/tsh_test_and_or_b";
    cleanupTempFile(tmp_a);
    cleanupTempFile(tmp_b);
    defer cleanupTempFile(tmp_b);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "false && echo a > " ++ tmp_a ++ " || echo b > " ++ tmp_b ++ "\n", 0);
    try expectFileNotFound(tmp_a);
    try expectFileContent(tmp_b, "b\n");
}

test "executor: || then && (true || a && b)" {
    // true || echo a && echo b -> should print "b" (not "a")
    // This matches POSIX: true succeeds, || skips a, but then we check the trailing And
    // with status=0 (succeeded), so execute_next=true, execute b
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_a = "/tmp/tsh_test_or_and_a";
    const tmp_b = "/tmp/tsh_test_or_and_b";
    cleanupTempFile(tmp_a);
    cleanupTempFile(tmp_b);
    defer cleanupTempFile(tmp_b);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "true || echo a > " ++ tmp_a ++ " && echo b > " ++ tmp_b ++ "\n", 0);
    try expectFileNotFound(tmp_a);
    try expectFileContent(tmp_b, "b\n");
}

test "executor: exit status is last executed (&&)" {
    // false && true -> 1 (true never runs)
    // true && false -> 1 (false runs)
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "false && true\n", 1);
    try expectStatus(&arena, &shell_state, "true && false\n", 1);
}

test "executor: exit status is last executed (||)" {
    // true || false -> 0 (false never runs)
    // false || true -> 0 (true runs)
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "true || false\n", 0);
    try expectStatus(&arena, &shell_state, "false || true\n", 0);
}

test "executor: negation with && (! false && echo yes)" {
    // ! false && echo yes -> prints "yes" (! false = 0, && runs)
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_neg_and_yes";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "! false && echo yes > " ++ tmp_path ++ "\n", 0);
    try expectFileContent(tmp_path, "yes\n");
}

test "executor: negation with && (! true && echo no)" {
    // ! true && echo no -> no print (! true = 1, && skips)
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_neg_and_no";
    cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "! true && echo no > " ++ tmp_path ++ "\n", 1);
    try expectFileNotFound(tmp_path);
}

test "executor: negation with || (! true || echo yes)" {
    // ! true || echo yes -> prints "yes" (! true = 1, || runs)
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_neg_or_yes";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "! true || echo yes > " ++ tmp_path ++ "\n", 0);
    try expectFileContent(tmp_path, "yes\n");
}

test "executor: negation with || (! false || echo no)" {
    // ! false || echo no -> no print (! false = 0, || skips)
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_neg_or_no";
    cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "! false || echo no > " ++ tmp_path ++ "\n", 0);
    try expectFileNotFound(tmp_path);
}

test "executor: pipeline in and_or succeeds" {
    // echo hello | grep hello && echo found -> prints "hello" and "found"
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_pipeline_and_success";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "echo hello | grep hello && echo found > " ++ tmp_path ++ "\n", 0);
    try expectFileContent(tmp_path, "found\n");
}

test "executor: pipeline in and_or fails" {
    // echo hello | grep bye && echo found -> prints "hello", NOT "found"
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_pipeline_and_failure";
    cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    // grep returns 1 when no match found
    try expectStatus(&arena, &shell_state, "echo hello | grep bye && echo found > " ++ tmp_path ++ "\n", 1);
    try expectFileNotFound(tmp_path);
}

test "executor: complex short-circuit (false && exit 99 || true)" {
    // false && exit 99 || true -> should NOT exit, final status 0
    // This should NOT return ExitRequested because exit 99 is skipped
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "false && exit 99 || true\n", 0);
}

test "executor: mixed pipelines and and_or" {
    // echo a | cat && echo b | cat || echo c
    // -> should print "a" and "b" (both succeed)
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_a = "/tmp/tsh_test_mixed_a";
    const tmp_b = "/tmp/tsh_test_mixed_b";
    const tmp_c = "/tmp/tsh_test_mixed_c";
    cleanupTempFile(tmp_a);
    cleanupTempFile(tmp_b);
    cleanupTempFile(tmp_c);
    defer cleanupTempFile(tmp_a);
    defer cleanupTempFile(tmp_b);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "echo a | cat > " ++ tmp_a ++ " && echo b | cat > " ++ tmp_b ++ " || echo c > " ++ tmp_c ++ "\n", 0);
    try expectFileContent(tmp_a, "a\n");
    try expectFileContent(tmp_b, "b\n");
    try expectFileNotFound(tmp_c);
}

test "executor: empty negated pipeline in AND/OR list" {
    // Test that negated assignment-only pipelines work correctly in AND/OR lists.
    // An assignment-only command (like X=1) has no command to execute, so it's an
    // "empty" pipeline that returns exit 0. With negation, it returns exit 1.
    //
    // ! X=1 && echo yes  -> should NOT print "yes" (! X=1 = 1, && skips)
    // ! X=1 || echo yes  -> should print "yes" (! X=1 = 1, || runs)
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_and = "/tmp/tsh_test_empty_neg_and";
    const tmp_or = "/tmp/tsh_test_empty_neg_or";
    cleanupTempFile(tmp_and);
    cleanupTempFile(tmp_or);
    defer cleanupTempFile(tmp_or);

    var shell_state = try ShellState.init(arena.allocator());

    // ! X=1 && echo yes -> exit 1 (! negates 0 to 1, && skips echo)
    try expectStatus(&arena, &shell_state, "! X=1 && echo yes > " ++ tmp_and ++ "\n", 1);
    try expectFileNotFound(tmp_and);

    // ! Y=2 || echo yes -> exit 0 (! negates 0 to 1, || runs echo)
    try expectStatus(&arena, &shell_state, "! Y=2 || echo yes > " ++ tmp_or ++ "\n", 0);
    try expectFileContent(tmp_or, "yes\n");
}

// --- If statement tests ---

test "executor: if true; then echo yes; fi" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_if_true";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "if true; then echo yes > " ++ tmp_path ++ "; fi\n", 0);
    try expectFileContent(tmp_path, "yes\n");
}

test "executor: if false; then echo yes; fi" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_if_false";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    // No branch executed, exit status is 0
    try expectStatus(&arena, &shell_state, "if false; then echo yes > " ++ tmp_path ++ "; fi\n", 0);
    // File should not exist (body not executed)
    try expectFileNotFound(tmp_path);
}

test "executor: if true; then echo yes; else echo no; fi" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_if_else_true";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "if true; then echo yes > " ++ tmp_path ++ "; else echo no > " ++ tmp_path ++ "; fi\n", 0);
    try expectFileContent(tmp_path, "yes\n");
}

test "executor: if false; then echo yes; else echo no; fi" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_if_else_false";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "if false; then echo yes > " ++ tmp_path ++ "; else echo no > " ++ tmp_path ++ "; fi\n", 0);
    try expectFileContent(tmp_path, "no\n");
}

test "executor: if false; then echo 1; elif true; then echo 2; fi" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_if_elif";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "if false; then echo 1 > " ++ tmp_path ++ "; elif true; then echo 2 > " ++ tmp_path ++ "; fi\n", 0);
    try expectFileContent(tmp_path, "2\n");
}

test "executor: if false; then echo 1; elif false; then echo 2; else echo 3; fi" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_if_elif_else";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "if false; then echo 1 > " ++ tmp_path ++ "; elif false; then echo 2 > " ++ tmp_path ++ "; else echo 3 > " ++ tmp_path ++ "; fi\n", 0);
    try expectFileContent(tmp_path, "3\n");
}

test "executor: if true; then echo 1; elif true; then echo 2; else echo 3; fi" {
    // First matching branch wins
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_if_first_match";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "if true; then echo 1 > " ++ tmp_path ++ "; elif true; then echo 2 > " ++ tmp_path ++ "; else echo 3 > " ++ tmp_path ++ "; fi\n", 0);
    try expectFileContent(tmp_path, "1\n");
}

test "executor: multiple elif branches" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_multi_elif";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    // First true elif wins
    try expectStatus(&arena, &shell_state, "if false; then echo 1 > " ++ tmp_path ++ "; elif false; then echo 2 > " ++ tmp_path ++ "; elif true; then echo 3 > " ++ tmp_path ++ "; elif true; then echo 4 > " ++ tmp_path ++ "; fi\n", 0);
    try expectFileContent(tmp_path, "3\n");
}

test "executor: if exit status propagation from body" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var shell_state = try ShellState.init(arena.allocator());

    // Exit status from executed body
    try expectStatus(&arena, &shell_state, "if true; then false; fi\n", 1);
    try expectStatus(&arena, &shell_state, "if true; then true; fi\n", 0);
}

test "executor: if with no branch executed returns 0" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "if false; then echo yes; fi\n", 0);
}

test "executor: multi-command condition" {
    // Exit status of condition is from last command
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_multi_cond";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());

    // Condition: echo checking; true -> exit 0, body runs
    try expectStatus(&arena, &shell_state, "if echo checking > /dev/null; true; then echo yes > " ++ tmp_path ++ "; fi\n", 0);
    try expectFileContent(tmp_path, "yes\n");

    cleanupTempFile(tmp_path);

    // Condition: echo checking; false -> exit 1, body skipped
    try expectStatus(&arena, &shell_state, "if echo checking > /dev/null; false; then echo yes > " ++ tmp_path ++ "; else echo no > " ++ tmp_path ++ "; fi\n", 0);
    try expectFileContent(tmp_path, "no\n");
}

test "executor: multi-command body" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_multi_body";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "if true; then echo a > " ++ tmp_path ++ "; echo b >> " ++ tmp_path ++ "; echo c >> " ++ tmp_path ++ "; fi\n", 0);
    try expectFileContent(tmp_path, "a\nb\nc\n");
}

test "executor: nested if statements" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_nested_if";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());

    // if true; then if true; then echo nested; fi; fi
    try expectStatus(&arena, &shell_state, "if true; then if true; then echo nested > " ++ tmp_path ++ "; fi; fi\n", 0);
    try expectFileContent(tmp_path, "nested\n");

    cleanupTempFile(tmp_path);

    // if true; then if false; then echo a; else echo b; fi; fi
    try expectStatus(&arena, &shell_state, "if true; then if false; then echo a > " ++ tmp_path ++ "; else echo b > " ++ tmp_path ++ "; fi; fi\n", 0);
    try expectFileContent(tmp_path, "b\n");

    cleanupTempFile(tmp_path);

    // if false; then echo outer; else if true; then echo inner; fi; fi
    try expectStatus(&arena, &shell_state, "if false; then echo outer > " ++ tmp_path ++ "; else if true; then echo inner > " ++ tmp_path ++ "; fi; fi\n", 0);
    try expectFileContent(tmp_path, "inner\n");
}

test "executor: pipeline with if" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_if_pipeline";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());

    // if true; then echo hello; fi | cat > file
    try expectStatus(&arena, &shell_state, "if true; then echo hello; fi | cat > " ++ tmp_path ++ "\n", 0);
    try expectFileContent(tmp_path, "hello\n");
}

test "executor: AND/OR in condition" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_if_and_or";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());

    // if true && true; then echo yes; fi
    try expectStatus(&arena, &shell_state, "if true && true; then echo yes > " ++ tmp_path ++ "; fi\n", 0);
    try expectFileContent(tmp_path, "yes\n");

    cleanupTempFile(tmp_path);

    // if true && false; then echo yes; else echo no; fi
    try expectStatus(&arena, &shell_state, "if true && false; then echo yes > " ++ tmp_path ++ "; else echo no > " ++ tmp_path ++ "; fi\n", 0);
    try expectFileContent(tmp_path, "no\n");

    cleanupTempFile(tmp_path);

    // if false || true; then echo yes; fi
    try expectStatus(&arena, &shell_state, "if false || true; then echo yes > " ++ tmp_path ++ "; fi\n", 0);
    try expectFileContent(tmp_path, "yes\n");

    cleanupTempFile(tmp_path);

    // if false || false; then echo yes; else echo no; fi
    try expectStatus(&arena, &shell_state, "if false || false; then echo yes > " ++ tmp_path ++ "; else echo no > " ++ tmp_path ++ "; fi\n", 0);
    try expectFileContent(tmp_path, "no\n");
}

test "executor: newline-separated if statement" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_if_newlines";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());

    // if true\nthen\necho yes\nfi
    try expectStatus(&arena, &shell_state, "if true\nthen\necho yes > " ++ tmp_path ++ "\nfi\n", 0);
    try expectFileContent(tmp_path, "yes\n");

    cleanupTempFile(tmp_path);

    // Multi-line body
    try expectStatus(&arena, &shell_state, "if true\nthen\necho a > " ++ tmp_path ++ "\necho b >> " ++ tmp_path ++ "\nfi\n", 0);
    try expectFileContent(tmp_path, "a\nb\n");
}

test "executor: if statement affects shell environment" {
    // Verify that if statements run in the current environment, not a subshell
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);

    // Set a variable in an if body
    const cmd = try parseCommand(arena.allocator(), "if true; then FOO=bar; fi\n") orelse return error.NoCommand;
    _ = try exec.executeCommand(cmd);

    // Variable should persist in shell state
    try std.testing.expectEqualStrings("bar", shell_state.getVariable("FOO").?);
}

test "executor: exit in if condition" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);

    // if exit 5; then echo yes; fi
    const cmd = try parseCommand(arena.allocator(), "if exit 5; then echo yes; fi\n") orelse return error.NoCommand;
    const result = exec.executeCommand(cmd);

    // Should return ExitRequested
    try std.testing.expectError(ExecuteError.ExitRequested, result);
    try std.testing.expectEqual(@as(u8, 5), shell_state.exit_code);
}

test "executor: exit in if body" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);

    // if true; then exit 42; fi
    const cmd = try parseCommand(arena.allocator(), "if true; then exit 42; fi\n") orelse return error.NoCommand;
    const result = exec.executeCommand(cmd);

    // Should return ExitRequested
    try std.testing.expectError(ExecuteError.ExitRequested, result);
    try std.testing.expectEqual(@as(u8, 42), shell_state.exit_code);
}

// --- while/until loop tests ---

test "executor: while false never executes body" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_while_false";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "while false; do echo body > " ++ tmp_path ++ "; done\n", 0);
    // File should not exist (body never executed)
    try expectFileNotFound(tmp_path);
}

test "executor: until true never executes body" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_until_true";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "until true; do echo body > " ++ tmp_path ++ "; done\n", 0);
    // File should not exist (body never executed)
    try expectFileNotFound(tmp_path);
}

test "executor: while with break exits immediately" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_while_break";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    // break should exit the loop, writing "before" but not "after"
    try expectStatus(&arena, &shell_state, "while true; do echo before > " ++ tmp_path ++ "; break; echo after >> " ++ tmp_path ++ "; done\n", 0);
    try expectFileContent(tmp_path, "before\n");
}

test "executor: until with break exits immediately" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_until_break";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "until false; do echo before > " ++ tmp_path ++ "; break; echo after >> " ++ tmp_path ++ "; done\n", 0);
    try expectFileContent(tmp_path, "before\n");
}

test "executor: break exits with status 0 regardless of previous command" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var shell_state = try ShellState.init(arena.allocator());
    // false sets exit status to 1, but break should make the loop return 0
    try expectStatus(&arena, &shell_state, "while true; do false; break; done\n", 0);
}

test "executor: continue skips to next iteration" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_continue";
    const flag_path = "/tmp/tsh_test_continue_flag";
    cleanupTempFile(tmp_path);
    cleanupTempFile(flag_path);
    defer cleanupTempFile(tmp_path);
    defer cleanupTempFile(flag_path);

    var shell_state = try ShellState.init(arena.allocator());
    // First iteration: write "before", create flag, continue (skip "after")
    // Second iteration: flag exists, condition fails, exit loop
    // Only "before" should be written, not "after"
    try expectStatus(&arena, &shell_state, "while test ! -f " ++ flag_path ++ "; do " ++
        "echo before >> " ++ tmp_path ++ "; " ++
        "touch " ++ flag_path ++ "; " ++
        "continue; " ++
        "echo after >> " ++ tmp_path ++ "; " ++
        "done\n", 0);
    try expectFileContent(tmp_path, "before\n");
}

test "executor: break outside loop prints warning" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var shell_state = try ShellState.init(arena.allocator());
    // break outside a loop should print warning but return 0
    try expectStatus(&arena, &shell_state, "break\n", 0);
}

test "executor: continue outside loop prints warning" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var shell_state = try ShellState.init(arena.allocator());
    // continue outside a loop should print warning but return 0
    try expectStatus(&arena, &shell_state, "continue\n", 0);
}

test "executor: break with invalid argument returns builtin_error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var shell_state = try ShellState.init(arena.allocator());
    // break 0 is invalid - returns builtin_error which causes exit in non-interactive mode
    try expectStatus(&arena, &shell_state, "break 0\n", 1);
}

test "executor: break with non-numeric argument returns builtin_error code 2" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var shell_state = try ShellState.init(arena.allocator());
    // break abc is invalid - returns builtin_error with code 2
    try expectStatus(&arena, &shell_state, "break abc\n", 2);
}

test "executor: nested loops with break 2" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_nested_break2";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    // break 2 should exit both loops
    // Only "inner" should be written, not "outer_after"
    try expectStatus(&arena, &shell_state, "while true; do " ++
        "while true; do " ++
        "echo inner > " ++ tmp_path ++ "; " ++
        "break 2; " ++
        "done; " ++
        "echo outer_after >> " ++ tmp_path ++ "; " ++
        "done\n", 0);
    try expectFileContent(tmp_path, "inner\n");
}

test "executor: loop with if statement" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_loop_if";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "while true; do " ++
        "if true; then echo yes > " ++ tmp_path ++ "; fi; " ++
        "break; " ++
        "done\n", 0);
    try expectFileContent(tmp_path, "yes\n");
}

test "executor: if with loop inside" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const tmp_path = "/tmp/tsh_test_if_loop";
    cleanupTempFile(tmp_path);
    defer cleanupTempFile(tmp_path);

    var shell_state = try ShellState.init(arena.allocator());
    try expectStatus(&arena, &shell_state, "if true; then " ++
        "while true; do echo looped > " ++ tmp_path ++ "; break; done; " ++
        "fi\n", 0);
    try expectFileContent(tmp_path, "looped\n");
}
