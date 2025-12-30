//! REPL (Read-Eval-Print Loop) for the shell.
//!
//! This module handles the main input loop, reading commands from any source
//! (stdin, file, or string), and processing them according to the specified mode.
//!
//! The processing mode determines what happens with each line of input:
//! - execute: Parse and execute commands (default)
//! - dump_tokens: Tokenize and dump tokens to stdout
//! - dump_ast: Parse and dump AST to stdout
//!
//! TODO: Expand variables in PS1 before displaying
//! TODO: PS2 support for multi-line/incomplete commands
//! TODO: PS4 for xtrace output
//! TODO: Signal handling (SIGINT should cancel line, not exit shell)
//! TODO: Read startup files before entering loop:
//!       - Login shell: /etc/profile, ~/.profile
//!       - Interactive non-login: $ENV
//! TODO: History and line editing

const std = @import("std");
const Allocator = std.mem.Allocator;

const tsh = @import("root.zig");
const ShellState = tsh.ShellState;
const ProcessingMode = tsh.ProcessingMode;
const Lexer = tsh.Lexer;
const Parser = tsh.Parser;
const Executor = tsh.Executor;

/// Run the main input loop.
///
/// Reads commands from the provided reader, processes them according to the
/// specified mode, and optionally displays prompts (if state.options.interactive).
///
/// Returns the exit code of the last command when EOF is encountered.
pub fn run(
    allocator: Allocator,
    state: *ShellState,
    reader: *std.io.Reader,
    mode: ProcessingMode,
) !u8 {
    const stdout_file = std.fs.File.stdout();
    const stderr_file = std.fs.File.stderr();

    var stdout_buf: [4096]u8 = undefined;
    var stderr_buf: [4096]u8 = undefined;

    var stdout_writer = stdout_file.writer(&stdout_buf);
    var stderr_writer = stderr_file.writer(&stderr_buf);

    while (true) {
        // Display prompt if interactive
        // TODO: Expand variables in PS1
        if (state.options.interactive) {
            try stdout_writer.interface.writeAll(state.ps1);
            try stdout_writer.interface.flush();
        }

        // Read a line from the input (until newline delimiter)
        // takeDelimiter returns null on EOF with no remaining data
        const line = reader.takeDelimiter('\n') catch |err| {
            switch (err) {
                error.StreamTooLong => {
                    try stderr_writer.interface.writeAll("tsh: input line too long\n");
                    try stderr_writer.interface.flush();
                    state.last_status = .{ .exited = 1 };
                    continue;
                },
                else => return err,
            }
        };

        // Handle EOF (null means end of stream with no remaining data)
        if (line == null) {
            // Write a newline for cleaner terminal output if interactive
            if (state.options.interactive) {
                try stdout_writer.interface.writeByte('\n');
                try stdout_writer.interface.flush();
            }
            return state.last_status.toExitCode();
        }

        const command_line = line.?;

        // Skip empty lines (no command to run, no tokens to dump)
        if (command_line.len == 0 or isBlank(command_line)) {
            continue;
        }

        // Process the line according to the mode
        const result = try processLine(
            allocator,
            state,
            command_line,
            mode,
            &stdout_writer.interface,
            &stderr_writer.interface,
        );
        try stdout_writer.interface.flush();

        // Check if exit was requested
        if (result == .exit_requested) {
            return state.exit_code;
        }
    }
}

/// Process a single line of input according to the specified mode.
/// Returns .exit_requested if the exit builtin was called.
fn processLine(
    allocator: Allocator,
    state: *ShellState,
    command_line: []const u8,
    mode: ProcessingMode,
    stdout: *std.io.Writer,
    stderr: *std.io.Writer,
) !ExecuteResult {
    // Use an arena allocator per line so we can free everything after processing
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    switch (mode) {
        .execute => return try executeCommands(arena.allocator(), state, command_line, stderr),
        .dump_tokens => {
            try dumpTokens(command_line, stdout, stderr);
            return .ok;
        },
        .dump_ast => {
            try dumpAst(arena.allocator(), command_line, stdout, stderr);
            return .ok;
        },
    }
}

/// Result of executing commands.
const ExecuteResult = enum {
    /// Commands executed, continue REPL.
    ok,
    /// Exit was requested via the exit builtin.
    exit_requested,
};

/// Parse and execute commands from the line.
fn executeCommands(
    allocator: Allocator,
    state: *ShellState,
    command_line: []const u8,
    stderr: *std.io.Writer,
) !ExecuteResult {
    var line_reader = std.io.Reader.fixed(command_line);
    var lexer = Lexer.init(&line_reader);
    var parser = Parser.init(allocator, &lexer);

    const cmd_list = parser.parseCommandList() catch |err| {
        if (parser.getErrorInfo()) |info| {
            try stderr.print("tsh: [{d}:{d}] {s}\n", .{
                info.line,
                info.column,
                info.message,
            });
        } else {
            try stderr.print("tsh: parse error: {s}\n", .{@errorName(err)});
        }
        try stderr.flush();
        state.last_status = .{ .exited = 1 };
        return .ok;
    };

    if (cmd_list) |list| {
        var exec = Executor.init(allocator, state);
        state.last_status = exec.executeList(list) catch |err| switch (err) {
            error.ExitRequested => return .exit_requested,
            else => {
                try stderr.print("tsh: execution error: {s}\n", .{@errorName(err)});
                try stderr.flush();
                state.last_status = .{ .exited = 1 };
                return .ok;
            },
        };
    }

    return .ok;
}

/// Tokenize the line and dump tokens to stdout.
fn dumpTokens(
    command_line: []const u8,
    stdout: *std.io.Writer,
    stderr: *std.io.Writer,
) !void {
    var line_reader = std.io.Reader.fixed(command_line);
    var lexer = Lexer.init(&line_reader);

    while (true) {
        const token = lexer.nextToken() catch |err| {
            try stderr.print("[{d}:{d}] Error: {s}\n", .{
                lexer.line,
                lexer.column,
                @errorName(err),
            });
            try stderr.flush();
            break;
        };

        if (token) |tok| {
            switch (tok.type) {
                .Separator => {
                    // End of command in this line - print blank line
                    try stdout.writeByte('\n');
                },
                else => {
                    try tok.format(stdout);
                    try stdout.writeByte('\n');
                },
            }
        } else {
            // null means EOF for this line
            break;
        }
    }
}

/// Parse the line and dump AST to stdout.
fn dumpAst(
    allocator: Allocator,
    command_line: []const u8,
    stdout: *std.io.Writer,
    stderr: *std.io.Writer,
) !void {
    var line_reader = std.io.Reader.fixed(command_line);
    var lexer = Lexer.init(&line_reader);
    var parser = Parser.init(allocator, &lexer);

    const cmd_list = parser.parseCommandList() catch |err| {
        if (parser.getErrorInfo()) |info| {
            try stderr.print("tsh: [{d}:{d}] {s}\n", .{
                info.line,
                info.column,
                info.message,
            });
        } else {
            try stderr.print("tsh: parse error: {s}\n", .{@errorName(err)});
        }
        try stderr.flush();
        return;
    };

    if (cmd_list) |list| {
        try list.format(stdout);
        try stdout.writeByte('\n');
    }
}

/// Check if a string contains only whitespace.
fn isBlank(s: []const u8) bool {
    for (s) |c| {
        if (c != ' ' and c != '\t' and c != '\r' and c != '\n') {
            return false;
        }
    }
    return true;
}

// --- Tests ---

test "isBlank: empty string" {
    try std.testing.expect(isBlank(""));
}

test "isBlank: whitespace only" {
    try std.testing.expect(isBlank("   "));
    try std.testing.expect(isBlank("\t\t"));
    try std.testing.expect(isBlank("  \t  \n"));
}

test "isBlank: non-blank strings" {
    try std.testing.expect(!isBlank("hello"));
    try std.testing.expect(!isBlank("  hello  "));
    try std.testing.expect(!isBlank("\thello"));
}
