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
const builtins = @import("builtins.zig");
const SimpleCommand = parser.SimpleCommand;
const Command = parser.Command;

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
            // Using fcntl F_DUPFD_CLOEXEC to atomically dup and set CLOEXEC
            const saved: ?posix.fd_t = if (posix.fcntl(fd, posix.F.DUPFD_CLOEXEC, 0)) |fd_usize|
                @intCast(fd_usize)
            else |_|
                null;
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
    pub fn execute(self: *Executor, cmd: SimpleCommand) ExecuteError!ExitStatus {
        self.error_info = null;

        // Handle commands with no argv
        if (cmd.argv.len == 0) {
            // Apply assignments to shell variables
            // POSIX Reference: Section 2.9.1 - variable assignments without command
            for (cmd.assignments) |assignment| {
                const value = try expandWordJoined(self.allocator, assignment.value, self.shell_state);
                try self.shell_state.setVariable(assignment.name, value);
            }

            // If there are redirections, apply them to the shell (e.g., "> file" creates/truncates file)
            if (cmd.redirections.len > 0) {
                // files_only=true: only create/truncate files, don't redirect shell's fds.
                switch (applyRedirections(self.allocator, cmd.redirections, true, self.shell_state)) {
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

            self.shell_state.last_status = .{ .exited = 0 };
            return self.shell_state.last_status;
        }

        // Expand argv
        const argv = expandArgv(self.allocator, cmd.argv, self.shell_state) catch |err| {
            self.setError("failed to expand arguments", @errorName(err));
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
                const value = try expandWordJoined(self.allocator, assignment.value, self.shell_state);
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
            const saved_fds = SavedFds.save(cmd.redirections) catch {
                printError("too many redirections\n", .{});
                self.setError("too many redirections", null);
                self.shell_state.last_status = .{ .exited = ExitStatus.GENERAL_ERROR };
                return self.shell_state.last_status;
            };
            defer _ = saved_fds.restore();

            if (cmd.redirections.len > 0) {
                switch (applyRedirections(self.allocator, cmd.redirections, false, self.shell_state)) {
                    .ok => {},
                    .err => |msg| {
                        printError("{s}\n", .{msg});
                        self.setError(msg, null);
                        self.shell_state.last_status = .{ .exited = ExitStatus.GENERAL_ERROR };
                        return self.shell_state.last_status;
                    },
                }
            }

            // Run the builtin
            const result = builtin.run(args, self.shell_state);
            self.shell_state.last_status = .{ .exited = result.exit_code };

            if (result.should_exit) {
                self.shell_state.exit_code = result.exit_code;
                return error.ExitRequested;
            }

            return self.shell_state.last_status;
        }

        // Not a builtin - fork and exec external command

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

    /// Execute a command (simple or compound).
    ///
    /// This is the primary interface for pull-based execution.
    /// Returns the exit status of the command, or error.ExitRequested
    /// if the exit builtin was invoked.
    ///
    /// Example usage with parser iterator:
    /// ```
    /// while (try parser.next()) |cmd| {
    ///     _ = try executor.executeCommand(cmd);
    /// }
    /// ```
    pub fn executeCommand(self: *Executor, cmd: Command) ExecuteError!ExitStatus {
        switch (cmd.payload) {
            .simple => |simple| return self.execute(simple),
        }
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
        switch (applyRedirections(self.allocator, cmd.redirections, false, self.shell_state)) {
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
            const value = try expandWordJoined(self.allocator, assignment.value, self.shell_state);
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

/// Expand a tilde prefix in a literal string.
///
/// POSIX tilde expansion rules (section 2.6.1):
/// - `~` alone expands to $HOME
/// - `~/...` expands to $HOME/...
/// - `~user` would expand to user's home directory (not yet implemented)
///
/// Returns the expanded string if tilde expansion applies, null otherwise.
/// When null is returned, the caller should use the original literal unchanged.
inline fn expandTilde(allocator: Allocator, literal: []const u8, home: ?[]const u8) Allocator.Error!?[]const u8 {
    if (literal.len == 0 or literal[0] != '~') {
        return null;
    }

    // ~ alone -> $HOME
    if (literal.len == 1) {
        return home;
    }

    // ~/... -> $HOME/...
    if (literal[1] == '/') {
        const home_val = home orelse return null;
        return try std.fmt.allocPrint(allocator, "{s}{s}", .{ home_val, literal[1..] });
    }

    // TODO: ~user form - implement passwd lookup for user home directories
    return null;
}

/// Transform a tilde prefix in the first WordPart into quoted content.
///
/// Per POSIX 2.6.1, the result of tilde expansion is "treated as if quoted"
/// to prevent further expansion processing (field splitting, globbing).
fn applyTildeExpansion(
    allocator: Allocator,
    parts: []const WordPart,
    home: ?[]const u8,
) Allocator.Error![]const WordPart {
    if (parts.len == 0) return parts;
    if (parts[0] != .literal) return parts;

    const expanded = try expandTilde(allocator, parts[0].literal, home) orelse return parts;

    // Create new parts array with first element as quoted (won't be re-expanded)
    const new_parts = try allocator.alloc(WordPart, parts.len);
    new_parts[0] = .{ .quoted = expanded };
    if (parts.len > 1) {
        @memcpy(new_parts[1..], parts[1..]);
    }
    return new_parts;
}

/// Intermediate representation of expanded content within a word.
///
/// TODO: When implementing parameter expansion ($VAR) and command substitution
/// ($(cmd)), field splitting must be considered. Per POSIX 2.6.5:
///
/// - Field splitting applies to results of parameter expansion, command
///   substitution, and arithmetic expansion - but NOT to tilde expansion
///   or literal content.
/// - Content inside double quotes is not subject to field splitting.
/// - Tilde expansion results are explicitly "treated as if quoted" (POSIX 2.6.1).
///
/// Field splitting interacts with adjacent content:
///   text$(cmd)  where cmd outputs "a b c" → ["texta", "b", "c"]
///   $(cmd)text  where cmd outputs "a b c" → ["a", "b", "ctext"]
///   $(cmd1)$(cmd2) where outputs are "a b" and "c d" → ["a", "bc", "d"]
///
/// The first and last fragments of a split expansion concatenate with adjacent
/// literals or expansion results. The `complete` flag indicates field boundaries
/// (similar to lexer token completion), where `complete = true` means "this ends
/// a word boundary."
///
/// When field splitting is implemented, this function may need to:
/// - Return []ExpandedPart instead of a single ExpandedPart
/// - Set `complete` flags based on IFS splitting within expansion results
/// - Ensure literal content and tilde expansion results have `complete = false`
///   (allowing them to merge with adjacent content)
const ExpandedPart = struct {
    content: []const u8,
    complete: bool,
};

/// A buffer for building a single word during expansion.
/// Multiple WordBuffers form the argv array.
const WordBuffer = std.ArrayListUnmanaged(u8);

/// A list of word buffers being built during expansion.
const WordBufferList = std.ArrayListUnmanaged(WordBuffer);

/// Start a new empty word in the word buffer list.
fn startNewWord(allocator: Allocator, words: *WordBufferList) Allocator.Error!void {
    try words.append(allocator, .{});
}

/// Append content to the current (last) word being built.
/// If no word exists, starts a new one first.
fn appendToCurrentWord(allocator: Allocator, words: *WordBufferList, content: []const u8) Allocator.Error!void {
    if (words.items.len == 0) {
        try startNewWord(allocator, words);
    }
    try words.items[words.items.len - 1].appendSlice(allocator, content);
}

/// Append expanded parameter parts to word buffers, handling word boundaries.
///
/// When a part has `complete = true`, it signals a word boundary (used by $@ to
/// produce multiple words). This function handles starting new words when needed
/// and tracks whether any complete parts have been seen.
///
/// Returns true if any content was added.
fn appendParameterParts(
    allocator: Allocator,
    words: *WordBufferList,
    parts: []const ExpandedPart,
    seen_complete: *bool,
) Allocator.Error!bool {
    var content_added = false;
    for (parts, 0..) |p, i| {
        // If this part is complete and not the first, start a new word
        if (p.complete and (seen_complete.* or i > 0)) {
            try startNewWord(allocator, words);
        }
        try appendToCurrentWord(allocator, words, p.content);
        content_added = true;
        if (p.complete) {
            seen_complete.* = true;
        }
    }
    return content_added;
}

/// Convert word buffers to null-terminated argv array for execve.
/// Each word buffer becomes a null-terminated string.
fn wordBuffersToArgv(allocator: Allocator, words: *const WordBufferList) Allocator.Error![:null]const ?[*:0]const u8 {
    const argv = try allocator.allocSentinel(?[*:0]const u8, words.items.len, null);

    for (words.items, 0..) |*buf, i| {
        const str = try allocator.dupeZ(u8, buf.items);
        argv[i] = str.ptr;
    }

    return argv;
}

/// Join word buffers into a single string with the given separator.
///
/// POSIX 2.5.2: For $*, "when the expansion occurs within double-quotes, it shall
/// expand to a single field with the value of each parameter separated by the
/// first character of the IFS variable."
///
/// Note: Returns a static empty string ("") for empty/zero-length cases instead of
/// allocating. This is safe because callers use arena allocators and don't free
/// individual strings. If ownership semantics change, this should allocate instead.
///
/// TODO: Use first char of IFS as separator. Currently uses space.
fn joinWordBuffers(allocator: Allocator, words: *const WordBufferList, separator: []const u8) Allocator.Error![]const u8 {
    if (words.items.len == 0) {
        return "";
    }

    // Calculate total length
    var total_len: usize = 0;
    for (words.items) |*buf| {
        total_len += buf.items.len;
    }
    // Add separator lengths (one less than number of words)
    if (words.items.len > 1) {
        total_len += separator.len * (words.items.len - 1);
    }

    if (total_len == 0) {
        return "";
    }

    const result = try allocator.alloc(u8, total_len);
    var offset: usize = 0;

    for (words.items, 0..) |*buf, i| {
        @memcpy(result[offset..][0..buf.items.len], buf.items);
        offset += buf.items.len;
        if (i < words.items.len - 1) {
            @memcpy(result[offset..][0..separator.len], separator);
            offset += separator.len;
        }
    }

    return result;
}

/// Expand a single Word into word buffers, appending to the provided list.
///
/// This is the core expansion function that handles the `complete` flag for word
/// boundaries. When `$@` expands to multiple parameters, each parameter has
/// `complete = true`, which signals a word boundary.
///
/// POSIX 2.5.2 specifies that "$@" expands such that "each positional parameter
/// shall expand as a separate field." The `complete` flag implements this by
/// marking where word splits occur.
///
/// Prefix/suffix handling:
///   - Content before $@ attaches to the first parameter
///   - Content after $@ attaches to the last parameter
///   - Example: "prefix$@suffix" with params ["a", "b"] → ["prefixa", "bsuffix"]
///
/// TODO: Apply field splitting to unquoted expansions (POSIX 2.6.5)
/// TODO: Apply pathname expansion (globbing) after field splitting (POSIX 2.6.6)
fn expandWordIntoBuffers(
    allocator: Allocator,
    word: Word,
    shell: *const ShellState,
    words: *WordBufferList,
) Allocator.Error!void {
    // Pre-process: apply tilde expansion to first part if applicable
    const parts = try applyTildeExpansion(allocator, word.parts, shell.home);

    // Track the starting position so we can detect if this Word produced zero fields.
    // This is needed for "$@" with no positional parameters, which should produce
    // zero words per POSIX 2.5.2: "If there are no positional parameters, the
    // expansion of '@' shall generate zero fields."
    const starting_word_count = words.items.len;

    // Start a new word for this Word. We may remove it at the end if nothing was added
    // (e.g., "$@" with no params).
    try startNewWord(allocator, words);

    // Track if we've seen any complete=true parts (for proper prefix/suffix handling)
    var seen_complete = false;

    // Track whether any expansion produced content (even empty content like $* → "").
    // This is different from the buffer being non-empty: "$*" with no params returns
    // one empty part, which counts as "content added" and should produce one empty field.
    // "$@" with no params returns zero parts, so no content is added, producing zero fields.
    var content_added = false;

    for (parts) |part| {
        switch (part) {
            .literal => |lit| {
                try appendToCurrentWord(allocator, words, lit);
                content_added = true;
            },
            .quoted => |q| {
                try appendToCurrentWord(allocator, words, q);
                content_added = true;
            },
            .double_quoted => |inner| {
                if (inner.len == 0) {
                    // Empty quoted string "" should produce one empty word.
                    // The word was already started above, so just mark content as added.
                    // This is distinct from "$@" with no params, which produces zero words.
                    // For "$@", inner.len > 0 (contains the $@ expansion), but the expansion
                    // returns zero parts, so content_added stays false.
                    content_added = true;
                } else {
                    // Expand inner parts in quoted context
                    const inner_added = try expandInnerPartsIntoBuffers(allocator, inner, shell, words, &seen_complete);
                    if (inner_added) content_added = true;
                }
            },
            .parameter => |param| {
                // Evaluate parameter expansion (unquoted context)
                const paramParts = try evaluateParameterExpansion(allocator, shell, param, false);
                if (try appendParameterParts(allocator, words, paramParts, &seen_complete)) {
                    content_added = true;
                }
            },
        }
    }

    // If this Word started a new word but no content was added, remove the empty word.
    // This handles "$@" with no params producing zero fields per POSIX 2.5.2.
    //
    // Cases:
    // - "" (empty double_quoted) → content_added = true → keep empty word
    // - "$*" with no params → returns 1 empty part → content_added = true → keep empty word
    // - "$@" with no params → returns 0 parts → content_added = false → remove empty word
    if (!content_added and words.items.len == starting_word_count + 1) {
        // Remove the empty word - this expansion produced zero fields
        _ = words.pop();
    }
}

/// Expand inner parts of a double-quoted region into word buffers.
///
/// This handles the special case where "$@" inside double quotes should still
/// produce multiple words. POSIX 2.5.2: "When the expansion occurs within
/// double-quotes [...] each positional parameter shall expand as a separate field."
///
/// Returns true if any content was added (even empty content from $*), false if
/// no content was added (e.g., $@ with no params returns zero parts).
fn expandInnerPartsIntoBuffers(
    allocator: Allocator,
    inner: []const WordPart,
    shell: *const ShellState,
    words: *WordBufferList,
    seen_complete: *bool,
) Allocator.Error!bool {
    var content_added = false;

    for (inner) |part| {
        switch (part) {
            .literal => |l| {
                try appendToCurrentWord(allocator, words, l);
                content_added = true;
            },
            .quoted => |q| {
                try appendToCurrentWord(allocator, words, q);
                content_added = true;
            },
            .double_quoted => unreachable, // Parser doesn't nest double_quoted
            .parameter => |param| {
                // Evaluate in quoted context
                const paramParts = try evaluateParameterExpansion(allocator, shell, param, true);
                if (try appendParameterParts(allocator, words, paramParts, seen_complete)) {
                    content_added = true;
                }
            },
        }
    }

    return content_added;
}

/// Expand a Word and return a joined string for assignment/redirection contexts.
///
/// POSIX 2.9.1 (Simple Commands): Variable assignments undergo "tilde expansion,
/// parameter expansion, command substitution, arithmetic expansion, and quote
/// removal" but NOT field splitting or pathname expansion.
///
/// POSIX 2.7 (Redirection): Redirection targets undergo similar expansion.
/// Following dash behavior, field splitting and pathname expansion are not
/// performed on redirection targets.
///
/// TODO: Use first char of IFS as separator for $* per POSIX 2.5.2
fn expandWordJoined(allocator: Allocator, word: Word, shell: *const ShellState) Allocator.Error![]const u8 {
    var words: WordBufferList = .{};
    try expandWordIntoBuffers(allocator, word, shell, &words);
    return joinWordBuffers(allocator, &words, " ");
}

/// Evaluate a parameter expansion and return the expanded parts.
///
/// Handles both regular variables ($VAR, ${VAR}) and special parameters
/// ($?, $#, $@, $*, $$, $-, $0-$9, ${10}+).
///
/// The `quoted` parameter indicates whether the expansion is inside double quotes,
/// which affects the behavior of $@ and $*.
///
/// TODO: Implement modifier evaluation (:-, :=, :?, :+, #, ##, %, %%)
fn evaluateParameterExpansion(
    allocator: Allocator,
    shell: *const ShellState,
    param: parser.ParameterExpansion,
    quoted: bool,
) Allocator.Error![]ExpandedPart {
    // Check for special parameters first
    if (try getSpecialParameter(allocator, shell, param.name, quoted)) |parts| {
        // TODO: Apply modifiers to special parameters.
        // POSIX 2.6.2 allows modifiers on special parameters (e.g., ${?:-0}, ${#:+x}).
        // Currently modifiers are silently ignored on special parameters. When
        // modifier support is implemented, this should apply them to the expanded
        // value. For now, users should be aware that ${?:-default} returns $?'s
        // value, not "default" if $? is unset (which it never is anyway).
        if (param.modifier != null) {
            // Silently ignored - see TODO above
        }
        return parts;
    }

    // Regular variable lookup
    const value = shell.getVariable(param.name) orelse "";

    // No modifier - just return the value
    if (param.modifier == null) {
        const result = try allocator.alloc(ExpandedPart, 1);
        result[0] = .{ .content = value, .complete = false };
        return result;
    }

    // TODO: Apply modifiers (UseDefault, AssignDefault, ErrorIfUnset, UseAlternative,
    // Length, RemoveSmallestPrefix, RemoveLargestPrefix, RemoveSmallestSuffix, RemoveLargestSuffix)
    // For now, just return the value unchanged
    const result = try allocator.alloc(ExpandedPart, 1);
    result[0] = .{ .content = value, .complete = false };
    return result;
}

/// Get the value of a special parameter.
///
/// Returns null if the name is not a special parameter.
/// POSIX Reference: Section 2.5.2 - Special Parameters
fn getSpecialParameter(
    allocator: Allocator,
    shell: *const ShellState,
    name: []const u8,
    quoted: bool,
) Allocator.Error!?[]ExpandedPart {
    // Single-character special parameters
    if (name.len == 1) {
        switch (name[0]) {
            '?' => {
                // Exit status of last command
                const result = try allocator.alloc(ExpandedPart, 1);
                const str = try std.fmt.allocPrint(allocator, "{d}", .{shell.last_status.toExitCode()});
                result[0] = .{ .content = str, .complete = false };
                return result;
            },
            '#' => {
                // Number of positional parameters
                const result = try allocator.alloc(ExpandedPart, 1);
                const str = try std.fmt.allocPrint(allocator, "{d}", .{shell.positional_params.items.len});
                result[0] = .{ .content = str, .complete = false };
                return result;
            },
            '@' => {
                // POSIX 2.5.2: "@ - Expands to the positional parameters, starting
                // from one. When the expansion occurs within double-quotes, [...] each
                // positional parameter shall expand as a separate field".
                //
                // Note: The `quoted` parameter is intentionally not checked here because
                // $@ always expands to separate words regardless of quoting context. The
                // difference is that unquoted $@ is subject to field splitting afterward
                // (not yet implemented), but the initial expansion is identical.
                const params = shell.positional_params.items;
                if (params.len == 0) {
                    // POSIX 2.5.2: "If there are no positional parameters, the
                    // expansion of '@' shall generate zero fields"
                    return try allocator.alloc(ExpandedPart, 0);
                }
                const parts = try allocator.alloc(ExpandedPart, params.len);
                for (params, 0..) |p, i| {
                    parts[i] = .{ .content = p, .complete = true };
                }
                return parts;
            },
            '*' => {
                // POSIX 2.5.2: "* - Expands to the positional parameters, starting
                // from one. When the expansion occurs within double-quotes, it shall
                // expand to a single field with the value of each parameter separated
                // by the first character of the IFS variable".
                const params = shell.positional_params.items;
                if (params.len == 0) {
                    if (quoted) {
                        // POSIX 2.5.2: When within double-quotes with no positional
                        // parameters, "$*" expands to a single empty field.
                        const result = try allocator.alloc(ExpandedPart, 1);
                        result[0] = .{ .content = "", .complete = false };
                        return result;
                    } else {
                        // Unquoted $* with no params = zero fields (subject to
                        // field splitting which produces nothing from empty string)
                        return try allocator.alloc(ExpandedPart, 0);
                    }
                }
                // Join with spaces (TODO: use first char of IFS per POSIX 2.5.2)
                const joined = try std.mem.join(allocator, " ", params);
                const result = try allocator.alloc(ExpandedPart, 1);
                result[0] = .{ .content = joined, .complete = false };
                return result;
            },
            '$' => {
                // PID of shell (cached at startup)
                const result = try allocator.alloc(ExpandedPart, 1);
                const str = try std.fmt.allocPrint(allocator, "{d}", .{shell.pid});
                result[0] = .{ .content = str, .complete = false };
                return result;
            },
            '!' => {
                // TODO: PID of last background command (requires job control)
                const result = try allocator.alloc(ExpandedPart, 1);
                result[0] = .{ .content = "", .complete = false };
                return result;
            },
            '-' => {
                // Current option flags
                const result = try allocator.alloc(ExpandedPart, 1);
                var flags: [16]u8 = undefined;
                var len: usize = 0;
                if (shell.options.interactive) {
                    flags[len] = 'i';
                    len += 1;
                }
                // TODO: Add these as options are implemented:
                // 'e' - errexit
                // 'u' - nounset
                // 'x' - xtrace
                // 'v' - verbose
                // 'f' - noglob
                // 'C' - noclobber
                // 'a' - allexport
                const str = try allocator.dupe(u8, flags[0..len]);
                result[0] = .{ .content = str, .complete = false };
                return result;
            },
            else => {},
        }
    }

    // Positional parameters: $0 (shell name), $1-$9, ${10}, ${11}, etc.
    // The lexer ensures $10 is parsed as $1 + literal "0", so single-digit
    // names come from $0-$9 and multi-digit names come from ${10}+.
    if (std.fmt.parseInt(usize, name, 10)) |idx| {
        const result = try allocator.alloc(ExpandedPart, 1);
        if (idx == 0) {
            result[0] = .{ .content = shell.shell_name, .complete = false };
        } else {
            const params = shell.positional_params.items;
            if (idx <= params.len) {
                result[0] = .{ .content = params[idx - 1], .complete = false };
            } else {
                result[0] = .{ .content = "", .complete = false };
            }
        }
        return result;
    } else |_| {}

    return null; // Not a special parameter
}

/// Expand an array of Words into a null-terminated array of null-terminated strings.
///
/// Each Word may expand to one or more argv entries (e.g., "$@" expands to
/// multiple entries when there are multiple positional parameters).
///
/// POSIX 2.6 specifies the order of word expansions:
/// 1. Tilde expansion
/// 2. Parameter expansion, command substitution, arithmetic expansion
/// 3. Field splitting (TODO)
/// 4. Pathname expansion (TODO)
/// 5. Quote removal
fn expandArgv(allocator: Allocator, words: []const Word, shell: *const ShellState) Allocator.Error![:null]const ?[*:0]const u8 {
    var wordBuffers: WordBufferList = .{};

    for (words) |word| {
        try expandWordIntoBuffers(allocator, word, shell, &wordBuffers);
    }

    return wordBuffersToArgv(allocator, &wordBuffers);
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
/// When `files_only` is true, only file operations are performed (open/create/truncate)
/// without modifying file descriptors. This is used for redirections-only commands
/// like `> file` which should create the file but not redirect the shell's fds.
///
/// On success, returns .ok.
/// On failure, returns .err with an error message. The caller is responsible
/// for printing the error and determining the appropriate exit status.
fn applyRedirections(allocator: Allocator, redirections: []const ParsedRedirection, files_only: bool, shell: *const ShellState) RedirectionResult {
    for (redirections) |redir| {
        const source_fd: posix.fd_t = @intCast(redir.source_fd orelse defaultSourceFd(redir.op));

        switch (redir.target) {
            .file => |word| {
                // POSIX 2.7 (Redirection): Following dash behavior, field splitting and
                // pathname expansion are not performed on redirection targets.
                const path_slice = expandWordJoined(allocator, word, shell) catch {
                    return .{ .err = "failed to expand redirection target" };
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
    const status = try exec.execute(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);
}

test "execute: exit status success" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const cmd = try parseCommand(arena.allocator(), "true\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = try exec.execute(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);
}

test "execute: exit status failure" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const cmd = try parseCommand(arena.allocator(), "false\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = try exec.execute(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 1 }, status);
}

test "execute: PATH lookup" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const cmd = try parseCommand(arena.allocator(), "echo hello\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = try exec.execute(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);
}

test "execute: command not found" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const cmd = try parseCommand(arena.allocator(), "nonexistent_cmd_12345\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = try exec.execute(cmd);

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
    const status = try exec.execute(cmd);

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
    const status = try exec.execute(cmd);

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
    _ = try exec.execute(cmd1);

    // Append
    const cmd2 = try parseCommand(arena.allocator(), "echo second >> " ++ tmp_path ++ "\n") orelse return error.NoCommand;
    const status = try exec.execute(cmd2);

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
    const status = try exec.execute(cmd);

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
    const status = try exec.execute(cmd);

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
    const status = try exec.execute(cmd);

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
    const status = try exec.execute(cmd);

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
    const status = try exec.execute(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);

    // The error output should be in the file
    const contents = try std.fs.cwd().readFileAlloc(std.testing.allocator, tmp_path, 1024);
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualStrings("error\n", contents);

    std.fs.deleteFileAbsolute(tmp_path) catch {};
}

test "expandWordJoined: single literal" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);

    const word = Word{
        .parts = &[_]WordPart{.{ .literal = "hello" }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("hello", result);
}

test "expandWordJoined: multiple literals" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);

    const word = Word{
        .parts = &[_]WordPart{
            .{ .literal = "hello" },
            .{ .literal = "world" },
        },
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("helloworld", result);
}

test "expandTilde: tilde alone expands to HOME" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const result = try expandTilde(arena.allocator(), "~", "/home/user");
    try std.testing.expectEqualStrings("/home/user", result.?);
}

test "expandTilde: tilde with path expands to HOME/path" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const result = try expandTilde(arena.allocator(), "~/Documents/file.txt", "/home/user");
    try std.testing.expectEqualStrings("/home/user/Documents/file.txt", result.?);
}

test "expandTilde: tilde alone with no HOME returns null" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const result = try expandTilde(arena.allocator(), "~", null);
    try std.testing.expect(result == null);
}

test "expandTilde: tilde path with no HOME returns null" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const result = try expandTilde(arena.allocator(), "~/foo", null);
    try std.testing.expect(result == null);
}

test "expandTilde: tilde-user returns null (not implemented)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const result = try expandTilde(arena.allocator(), "~root", "/home/user");
    try std.testing.expect(result == null);
}

test "expandTilde: no tilde returns null" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const result = try expandTilde(arena.allocator(), "foo", "/home/user");
    try std.testing.expect(result == null);
}

test "expandTilde: tilde not at start returns null" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const result = try expandTilde(arena.allocator(), "a~b", "/home/user");
    try std.testing.expect(result == null);
}

test "expandWordJoined: tilde expands in unquoted literal" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    try env.put("HOME", "/home/testuser");
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);

    const word = Word{
        .parts = &[_]WordPart{.{ .literal = "~" }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("/home/testuser", result);
}

test "expandWordJoined: tilde with path expands" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    try env.put("HOME", "/home/testuser");
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);

    const word = Word{
        .parts = &[_]WordPart{.{ .literal = "~/bin" }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("/home/testuser/bin", result);
}

test "expandWordJoined: quoted tilde does not expand" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    try env.put("HOME", "/home/testuser");
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);

    const word = Word{
        .parts = &[_]WordPart{.{ .quoted = "~" }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("~", result);
}

test "expandWordJoined: double-quoted tilde does not expand" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    try env.put("HOME", "/home/testuser");
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);

    const word = Word{
        .parts = &[_]WordPart{.{ .double_quoted = &[_]WordPart{.{ .literal = "~" }} }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("~", result);
}

test "expandWordJoined: tilde with no HOME stays literal" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);

    const word = Word{
        .parts = &[_]WordPart{.{ .literal = "~" }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("~", result);
}

test "expandWordJoined: quoted prefix prevents tilde expansion" {
    // Tests that tilde expansion only occurs when the FIRST part of a word is
    // an unquoted literal starting with ~. Any quoted content before the tilde
    // (even empty quotes like ""~) prevents expansion per POSIX 2.6.1.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    try env.put("HOME", "/home/testuser");
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);

    // Simulates ""~ - an empty quoted part followed by tilde
    const word = Word{
        .parts = &[_]WordPart{
            .{ .quoted = "" },
            .{ .literal = "~" },
        },
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("~", result);
}

test "applyTildeExpansion: transforms tilde literal to quoted" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const parts = [_]WordPart{
        .{ .literal = "~/docs" },
        .{ .literal = "/more" },
    };

    const result = try applyTildeExpansion(arena.allocator(), &parts, "/home/user");

    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expect(result[0] == .quoted);
    try std.testing.expectEqualStrings("/home/user/docs", result[0].quoted);
    try std.testing.expect(result[1] == .literal);
    try std.testing.expectEqualStrings("/more", result[1].literal);
}

test "applyTildeExpansion: no transform when first part is not literal" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const parts = [_]WordPart{
        .{ .quoted = "~" },
        .{ .literal = "/more" },
    };

    const result = try applyTildeExpansion(arena.allocator(), &parts, "/home/user");

    // Should return original parts unchanged
    try std.testing.expectEqual(&parts, result.ptr);
}

test "applyTildeExpansion: no transform when HOME is null" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const parts = [_]WordPart{
        .{ .literal = "~/docs" },
    };

    const result = try applyTildeExpansion(arena.allocator(), &parts, null);

    // Should return original parts unchanged
    try std.testing.expectEqual(&parts, result.ptr);
}

test "applyTildeExpansion: no transform for non-tilde literal" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const parts = [_]WordPart{
        .{ .literal = "hello" },
    };

    const result = try applyTildeExpansion(arena.allocator(), &parts, "/home/user");

    // Should return original parts unchanged
    try std.testing.expectEqual(&parts, result.ptr);
}

test "applyTildeExpansion: empty parts returns empty" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const parts = [_]WordPart{};

    const result = try applyTildeExpansion(arena.allocator(), &parts, "/home/user");

    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "expandWordJoined: double-quoted inner parts concatenated" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    try env.put("HOME", "/home/user");
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);

    // A word with a double-quoted region containing inner parts
    // Tilde inside double quotes should NOT expand
    const inner_parts = [_]WordPart{
        .{ .literal = "hello" },
        .{ .literal = "~" },
    };
    const word = Word{
        .parts = &[_]WordPart{.{ .double_quoted = &inner_parts }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("hello~", result);
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

    const input = "> " ++ tmp_path ++ "; /bin/echo hello\n";
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

    const result = exec.execute(cmd);
    try std.testing.expectError(ExecuteError.ExitRequested, result);
    try std.testing.expectEqual(@as(u8, 42), shell_state.exit_code);
}

test "execute: pwd builtin" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const cmd = try parseCommand(arena.allocator(), "pwd\n") orelse return error.NoCommand;
    var shell_state = try ShellState.init(arena.allocator());
    var exec = Executor.init(arena.allocator(), &shell_state);
    const status = try exec.execute(cmd);

    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, status);
}

test "execute: export and variable visibility" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var shell_state = try ShellState.init(arena.allocator());

    // Set a shell variable
    const cmd1 = try parseCommand(arena.allocator(), "FOO=bar\n") orelse return error.NoCommand;
    var exec = Executor.init(arena.allocator(), &shell_state);
    _ = try exec.execute(cmd1);

    // Should be in variables, not env
    try std.testing.expectEqualStrings("bar", shell_state.getVariable("FOO").?);
    try std.testing.expect(shell_state.env.get("FOO") == null);

    // Export it
    const cmd2 = try parseCommand(arena.allocator(), "export FOO\n") orelse return error.NoCommand;
    _ = try exec.execute(cmd2);

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
    const status = try exec.execute(cmd);

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
    _ = try exec.execute(cmd1);

    // Second: pwd (no redirection) - should NOT go to file
    // We can't easily capture stdout in a test, but we can verify the file wasn't appended
    const contents_after_first = try std.fs.cwd().readFileAlloc(std.testing.allocator, tmp_path, 4096);
    defer std.testing.allocator.free(contents_after_first);

    const cmd2 = try parseCommand(arena.allocator(), "pwd\n") orelse return error.NoCommand;
    _ = try exec.execute(cmd2);

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
    _ = try exec.execute(cmd1);

    // pwd >> file (append)
    const cmd2 = try parseCommand(arena.allocator(), "pwd >> " ++ tmp_path ++ "\n") orelse return error.NoCommand;
    _ = try exec.execute(cmd2);

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
    const status = try exec.execute(cmd);

    // Should return error status
    try std.testing.expectEqual(ExitStatus{ .exited = ExitStatus.GENERAL_ERROR }, status);
}

// --- Parameter expansion tests ---

test "expandWordJoined: simple variable expansion" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("FOO", "hello");

    // Construct a word with a parameter expansion: $FOO
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{ .name = "FOO", .modifier = null } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("hello", result);
}

test "expandWordJoined: undefined variable expands to empty" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);

    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{ .name = "UNDEFINED", .modifier = null } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("", result);
}

test "expandWordJoined: variable in double quotes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("NAME", "world");

    // Construct "hello $NAME"
    const inner_parts = [_]WordPart{
        .{ .literal = "hello " },
        .{ .parameter = .{ .name = "NAME", .modifier = null } },
    };
    const word = Word{
        .parts = &[_]WordPart{.{ .double_quoted = &inner_parts }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("hello world", result);
}

test "expandWordJoined: special parameter $?" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    shell.last_status = .{ .exited = 42 };

    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{ .name = "?", .modifier = null } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("42", result);
}

test "expandWordJoined: special parameter $#" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{ "a", "b", "c" });

    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{ .name = "#", .modifier = null } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("3", result);
}

test "expandWordJoined: special parameter $0" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    shell.shell_name = "myscript.sh";

    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{ .name = "0", .modifier = null } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("myscript.sh", result);
}

test "expandWordJoined: positional parameter $1" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{ "first", "second" });

    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{ .name = "1", .modifier = null } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("first", result);
}

test "expandWordJoined: positional parameter out of range" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{"only_one"});

    // $5 when only $1 is set
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{ .name = "5", .modifier = null } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("", result);
}

test "expandWordJoined: special parameter $$" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);

    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{ .name = "$", .modifier = null } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    // Result should be a valid PID (non-empty number)
    try std.testing.expect(result.len > 0);
    // Should be parseable as a number
    _ = try std.fmt.parseInt(i32, result, 10);
}

test "expandWordIntoBuffers: quoted $@ produces multiple words" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{ "a", "b", "c" });

    // Construct "$@" - a double_quoted word containing a parameter expansion
    const inner_parts = [_]WordPart{
        .{ .parameter = .{ .name = "@", .modifier = null } },
    };
    const word = Word{
        .parts = &[_]WordPart{.{ .double_quoted = &inner_parts }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    var words: WordBufferList = .{};
    try expandWordIntoBuffers(arena.allocator(), word, &shell, &words);

    // Should produce exactly 3 words: "a", "b", "c"
    try std.testing.expectEqual(@as(usize, 3), words.items.len);
    try std.testing.expectEqualStrings("a", words.items[0].items);
    try std.testing.expectEqualStrings("b", words.items[1].items);
    try std.testing.expectEqualStrings("c", words.items[2].items);
}

test "expandWordIntoBuffers: quoted $@ with no params produces zero words" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // No positional params set

    // Construct "$@"
    const inner_parts = [_]WordPart{
        .{ .parameter = .{ .name = "@", .modifier = null } },
    };
    const word = Word{
        .parts = &[_]WordPart{.{ .double_quoted = &inner_parts }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    var words: WordBufferList = .{};
    try expandWordIntoBuffers(arena.allocator(), word, &shell, &words);

    // POSIX 2.5.2: "If there are no positional parameters, the expansion of '@'
    // shall generate zero fields"
    try std.testing.expectEqual(@as(usize, 0), words.items.len);
}

test "expandWordIntoBuffers: prefix$@suffix produces correct words" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{ "a", "b" });

    // Construct "prefix$@suffix"
    const inner_parts = [_]WordPart{
        .{ .literal = "prefix" },
        .{ .parameter = .{ .name = "@", .modifier = null } },
        .{ .literal = "suffix" },
    };
    const word = Word{
        .parts = &[_]WordPart{.{ .double_quoted = &inner_parts }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    var words: WordBufferList = .{};
    try expandWordIntoBuffers(arena.allocator(), word, &shell, &words);

    // Should produce 2 words: "prefixa", "bsuffix"
    try std.testing.expectEqual(@as(usize, 2), words.items.len);
    try std.testing.expectEqualStrings("prefixa", words.items[0].items);
    try std.testing.expectEqualStrings("bsuffix", words.items[1].items);
}

test "expandArgv: echo with $@ produces correct argv" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{ "a", "b", "c" });

    // Construct: echo "$@"
    // Word 1: echo (literal)
    const word1 = Word{
        .parts = &[_]WordPart{.{ .literal = "echo" }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    // Word 2: "$@" (double_quoted containing parameter)
    const inner_parts = [_]WordPart{
        .{ .parameter = .{ .name = "@", .modifier = null } },
    };
    const word2 = Word{
        .parts = &[_]WordPart{.{ .double_quoted = &inner_parts }},
        .position = 5,
        .line = 1,
        .column = 6,
    };

    const words = [_]Word{ word1, word2 };
    const argv = try expandArgv(arena.allocator(), &words, &shell);

    // Should produce: ["echo", "a", "b", "c", null]
    // Count non-null entries
    var argc: usize = 0;
    while (argv[argc] != null) : (argc += 1) {}

    try std.testing.expectEqual(@as(usize, 4), argc);
    try std.testing.expectEqualStrings("echo", std.mem.span(argv[0].?));
    try std.testing.expectEqualStrings("a", std.mem.span(argv[1].?));
    try std.testing.expectEqualStrings("b", std.mem.span(argv[2].?));
    try std.testing.expectEqualStrings("c", std.mem.span(argv[3].?));
}
