//! Parser for POSIX shell syntax.
//!
//! Consumes tokens from the lexer and produces an AST for simple commands.
//! Simple commands consist of optional variable assignments, a command with
//! arguments, and optional redirections.
//!
//! The parser uses a labeled switch state machine for consistency with the
//! lexer and to prepare for future compound command support.

const std = @import("std");
const Allocator = std.mem.Allocator;
pub const lexer = @import("lexer.zig");

/// A part of a word. Words can be composed of multiple parts when they
/// contain quotes, escapes, or (in the future) expansions.
pub const WordPart = union(enum) {
    /// Literal text from unquoted content, single quotes,
    /// double quote content, or escaped characters.
    literal: []const u8,

    // Future expansion types:
    // variable: VariableExpansion,
    // command_sub: CommandSubstitution,
    // arithmetic: ArithmeticExpansion,
};

/// A complete word, which may consist of multiple parts.
/// For example, `abc'def'ghi` is one word with three literal parts.
pub const Word = struct {
    /// The parts that make up this word.
    parts: []const WordPart,
    /// The absolute position in the input where this word starts.
    position: usize,
    /// The line number where this word starts (1-indexed).
    line: usize,
    /// The column number where this word starts (1-indexed).
    column: usize,
};

/// A variable assignment (e.g., `FOO=bar`).
/// The name must be a valid identifier: [A-Za-z_][A-Za-z0-9_]*
pub const Assignment = struct {
    /// The variable name (always literal, no expansions).
    name: []const u8,
    /// The value (may contain expansions in the future).
    value: Word,
    /// The absolute position in the input where this assignment starts.
    position: usize,
    /// The line number where this assignment starts (1-indexed).
    line: usize,
    /// The column number where this assignment starts (1-indexed).
    column: usize,
};

/// A parsed redirection with its target.
pub const ParsedRedirection = struct {
    /// The type of redirection operation.
    op: lexer.RedirectionOp,
    /// The source file descriptor (e.g., "2" in "2>file"), if specified.
    source_fd: ?u32,
    /// The target of the redirection (file path or fd number as a word).
    target: Word,
    /// The absolute position in the input where this redirection starts.
    position: usize,
    /// The line number where this redirection starts (1-indexed).
    line: usize,
    /// The column number where this redirection starts (1-indexed).
    column: usize,
};

/// A simple command consisting of assignments, arguments, and redirections.
pub const SimpleCommand = struct {
    /// Variable assignments that precede the command.
    assignments: []const Assignment,
    /// The command name and its arguments.
    argv: []const Word,
    /// Redirections in the order they appeared.
    redirections: []const ParsedRedirection,
};

/// Errors that can occur during parsing.
pub const ParseError = error{
    /// Reached end of input when more tokens were expected.
    UnexpectedEndOfInput,
    /// A redirection operator was not followed by a target.
    MissingRedirectionTarget,
} || lexer.LexerError || Allocator.Error;

/// Information about a parse error for error reporting.
pub const ErrorInfo = struct {
    /// A human-readable description of the error.
    message: []const u8,
    /// The absolute position in the input where the error occurred.
    position: usize,
    /// The line number where the error occurred (1-indexed).
    line: usize,
    /// The column number where the error occurred (1-indexed).
    column: usize,
};

/// Parser state machine states.
const ParseState = enum {
    /// Initial state - assignments and reserved words are recognized.
    /// TODO: When compound commands are implemented, check for reserved
    /// words here (if, while, for, case, {, etc.) and branch to appropriate
    /// compound command parsing states. Reserved words are recognized
    /// pre-expansion, only when the literal token matches and is unquoted.
    /// See POSIX Section 2.4 - Reserved Words.
    start,
    /// Seen command name - only arguments and redirections allowed.
    /// Assignments (FOO=bar) are treated as regular arguments.
    after_command,
    /// Collecting tokens for a word until complete=true.
    collecting_word,
    /// After redirection operator, must collect target word.
    need_redir_target,
    /// Word collection finished, decide what to do with it.
    word_complete,
    /// Finished parsing command.
    done,
};

/// Pending redirection info while collecting target.
const PendingRedir = struct {
    op: lexer.RedirectionOp,
    source_fd: ?u32,
    position: usize,
    line: usize,
    column: usize,
};

/// Parser for POSIX shell simple commands.
///
/// The parser consumes tokens from a lexer and produces an AST.
/// All strings are copied to the provided allocator (typically an arena),
/// since lexer token slices are invalidated on the next `nextToken()` call.
pub const Parser = struct {
    /// Allocator for AST nodes and string copies.
    allocator: Allocator,
    /// The lexer to read tokens from.
    lex: *lexer.Lexer,

    /// Error context for the most recent error.
    error_info: ?ErrorInfo,

    // --- State machine fields ---

    /// Current parser state.
    state: ParseState,

    /// In-progress word parts.
    word_parts: std.ArrayListUnmanaged(WordPart),
    /// Position where current word started.
    word_start_position: usize,
    /// Line where current word started.
    word_start_line: usize,
    /// Column where current word started.
    word_start_column: usize,

    /// Pending redirection (while collecting target).
    pending_redir: ?PendingRedir,

    /// Results being built.
    assignments: std.ArrayListUnmanaged(Assignment),
    argv: std.ArrayListUnmanaged(Word),
    redirections: std.ArrayListUnmanaged(ParsedRedirection),

    /// Track if we've seen a command (for assignment detection).
    seen_command: bool,

    /// Initialize a new parser.
    pub fn init(allocator: Allocator, lex: *lexer.Lexer) Parser {
        return Parser{
            .allocator = allocator,
            .lex = lex,
            .error_info = null,
            .state = .start,
            .word_parts = .{},
            .word_start_position = 0,
            .word_start_line = 0,
            .word_start_column = 0,
            .pending_redir = null,
            .assignments = .{},
            .argv = .{},
            .redirections = .{},
            .seen_command = false,
        };
    }

    /// Get error information for the most recent parse error.
    pub fn getErrorInfo(self: *const Parser) ?ErrorInfo {
        return self.error_info;
    }

    /// Parse a simple command from the input.
    ///
    /// Returns the parsed command, or `null` if the input is empty.
    /// Returns an error if the input is malformed.
    pub fn parseCommand(self: *Parser) ParseError!?SimpleCommand {
        self.reset();

        state: switch (self.state) {
            .start => {
                const tok = self.lex.nextToken() catch |err| {
                    self.setError("lexer error", self.lex.position, self.lex.line, self.lex.column);
                    return err;
                } orelse {
                    continue :state .done;
                };

                switch (tok.type) {
                    .Redirection => |redir| {
                        self.setPendingRedir(redir, tok);
                        continue :state .need_redir_target;
                    },
                    else => {
                        self.startWord(tok);
                        try self.addTokenToParts(tok);
                        if (tok.complete) {
                            continue :state .word_complete;
                        } else {
                            continue :state .collecting_word;
                        }
                    },
                }
            },

            .after_command => {
                const tok = self.lex.nextToken() catch |err| {
                    self.setError("lexer error", self.lex.position, self.lex.line, self.lex.column);
                    return err;
                } orelse {
                    continue :state .done;
                };

                switch (tok.type) {
                    .Redirection => |redir| {
                        self.setPendingRedir(redir, tok);
                        continue :state .need_redir_target;
                    },
                    else => {
                        self.startWord(tok);
                        try self.addTokenToParts(tok);
                        if (tok.complete) {
                            continue :state .word_complete;
                        } else {
                            continue :state .collecting_word;
                        }
                    },
                }
            },

            .collecting_word => {
                const tok = self.lex.nextToken() catch |err| {
                    self.setError("lexer error while collecting word", self.lex.position, self.lex.line, self.lex.column);
                    return err;
                } orelse {
                    // End of input mid-word, finish what we have
                    continue :state .word_complete;
                };

                try self.addTokenToParts(tok);
                if (tok.complete) {
                    continue :state .word_complete;
                } else {
                    continue :state .collecting_word;
                }
            },

            .need_redir_target => {
                const tok = self.lex.nextToken() catch |err| {
                    self.setError("lexer error reading redirection target", self.lex.position, self.lex.line, self.lex.column);
                    return err;
                } orelse {
                    const redir = self.pending_redir.?;
                    self.setError("missing redirection target", redir.position, redir.line, redir.column);
                    return ParseError.MissingRedirectionTarget;
                };

                switch (tok.type) {
                    .Redirection => {
                        const redir = self.pending_redir.?;
                        self.setError("missing redirection target", redir.position, redir.line, redir.column);
                        return ParseError.MissingRedirectionTarget;
                    },
                    else => {
                        self.startWord(tok);
                        try self.addTokenToParts(tok);
                        if (tok.complete) {
                            continue :state .word_complete;
                        } else {
                            continue :state .collecting_word;
                        }
                    },
                }
            },

            .word_complete => {
                const word = try self.finishWord();

                // If we have a pending redirection, this word is its target
                if (self.pending_redir) |redir| {
                    try self.redirections.append(self.allocator, .{
                        .op = redir.op,
                        .source_fd = redir.source_fd,
                        .target = word,
                        .position = redir.position,
                        .line = redir.line,
                        .column = redir.column,
                    });
                    self.pending_redir = null;
                    continue :state if (self.seen_command) .after_command else .start;
                }

                // Check if it's an assignment (only valid before command name)
                if (!self.seen_command) {
                    if (try self.tryBuildAssignment(word)) |assignment| {
                        try self.assignments.append(self.allocator, assignment);
                        continue :state .start;
                    }
                }

                // It's a command/argument
                try self.argv.append(self.allocator, word);
                self.seen_command = true;
                continue :state .after_command;
            },

            .done => {
                if (self.assignments.items.len == 0 and
                    self.argv.items.len == 0 and
                    self.redirections.items.len == 0)
                {
                    return null;
                }

                return SimpleCommand{
                    .assignments = try self.assignments.toOwnedSlice(self.allocator),
                    .argv = try self.argv.toOwnedSlice(self.allocator),
                    .redirections = try self.redirections.toOwnedSlice(self.allocator),
                };
            },
        }
    }

    // --- Helper methods ---

    /// Reset parser state for a new command.
    fn reset(self: *Parser) void {
        self.error_info = null;
        self.state = .start;
        self.word_parts = .{};
        self.word_start_position = 0;
        self.word_start_line = 0;
        self.word_start_column = 0;
        self.pending_redir = null;
        self.assignments = .{};
        self.argv = .{};
        self.redirections = .{};
        self.seen_command = false;
    }

    /// Start collecting a new word.
    fn startWord(self: *Parser, tok: lexer.Token) void {
        self.word_parts = .{};
        self.word_start_position = tok.position;
        self.word_start_line = tok.line;
        self.word_start_column = tok.column;
    }

    /// Finish collecting the current word and return it.
    fn finishWord(self: *Parser) ParseError!Word {
        return Word{
            .parts = try self.word_parts.toOwnedSlice(self.allocator),
            .position = self.word_start_position,
            .line = self.word_start_line,
            .column = self.word_start_column,
        };
    }

    /// Set up pending redirection info.
    fn setPendingRedir(self: *Parser, redir: lexer.Redirection, tok: lexer.Token) void {
        const source_fd: ?u32 = if (redir.fd) |fd_str|
            std.fmt.parseInt(u32, fd_str, 10) catch null
        else
            null;

        self.pending_redir = .{
            .op = redir.operation.?,
            .source_fd = source_fd,
            .position = tok.position,
            .line = tok.line,
            .column = tok.column,
        };
    }

    /// Add a token's content to the word parts list.
    fn addTokenToParts(self: *Parser, token: lexer.Token) ParseError!void {
        switch (token.type) {
            .Literal => |lit| {
                const copied = try self.allocator.dupe(u8, lit);
                try self.word_parts.append(self.allocator, .{ .literal = copied });
            },
            .Continuation => |cont| {
                // Continuation may be empty (signals word boundary with no content)
                if (cont.len > 0) {
                    const copied = try self.allocator.dupe(u8, cont);
                    try self.word_parts.append(self.allocator, .{ .literal = copied });
                }
            },
            .SingleQuoted => |sq| {
                const copied = try self.allocator.dupe(u8, sq);
                try self.word_parts.append(self.allocator, .{ .literal = copied });
            },
            .DoubleQuoteBegin, .DoubleQuoteEnd => {
                // Quote markers don't add content, just affect parsing context
            },
            .Redirection => {
                // Shouldn't happen during word collection
            },
        }
    }

    /// Try to build an assignment from a word.
    /// Returns the assignment if valid, or null if it's not an assignment.
    ///
    /// An assignment must have:
    /// 1. An unquoted `=` not at position 0
    /// 2. A valid identifier before the `=`: [A-Za-z_][A-Za-z0-9_]*
    fn tryBuildAssignment(self: *Parser, word: Word) ParseError!?Assignment {
        // For now, we only support simple assignments where the first part
        // is a literal containing `=`
        if (word.parts.len == 0) return null;

        switch (word.parts[0]) {
            .literal => |lit| {
                // Find `=` in the literal
                const eq_pos = std.mem.indexOf(u8, lit, "=") orelse return null;
                if (eq_pos == 0) return null; // `=foo` is not an assignment

                const name = lit[0..eq_pos];

                // Validate the name is a valid identifier
                if (!isValidIdentifier(name)) return null;

                // Extract the value
                const value_start = lit[eq_pos + 1 ..];

                // Build the value Word
                var value_parts: std.ArrayListUnmanaged(WordPart) = .{};

                // Add the part after `=` from the first literal (if non-empty)
                if (value_start.len > 0) {
                    const copied = try self.allocator.dupe(u8, value_start);
                    try value_parts.append(self.allocator, .{ .literal = copied });
                }

                // Add remaining parts from the original word
                for (word.parts[1..]) |part| {
                    switch (part) {
                        .literal => |l| {
                            const copied = try self.allocator.dupe(u8, l);
                            try value_parts.append(self.allocator, .{ .literal = copied });
                        },
                    }
                }

                const value = Word{
                    .parts = try value_parts.toOwnedSlice(self.allocator),
                    .position = word.position + eq_pos + 1,
                    .line = word.line,
                    .column = word.column + eq_pos + 1,
                };

                const name_copied = try self.allocator.dupe(u8, name);

                return Assignment{
                    .name = name_copied,
                    .value = value,
                    .position = word.position,
                    .line = word.line,
                    .column = word.column,
                };
            },
        }
    }

    /// Check if a string is a valid shell identifier.
    fn isValidIdentifier(s: []const u8) bool {
        if (s.len == 0) return false;

        // First character must be letter or underscore
        const first = s[0];
        if (!((first >= 'A' and first <= 'Z') or
            (first >= 'a' and first <= 'z') or
            first == '_'))
        {
            return false;
        }

        // Rest can be letters, digits, or underscores
        for (s[1..]) |c| {
            if (!((c >= 'A' and c <= 'Z') or
                (c >= 'a' and c <= 'z') or
                (c >= '0' and c <= '9') or
                c == '_'))
            {
                return false;
            }
        }

        return true;
    }

    /// Set error information.
    fn setError(self: *Parser, message: []const u8, position: usize, line: usize, column: usize) void {
        self.error_info = ErrorInfo{
            .message = message,
            .position = position,
            .line = line,
            .column = column,
        };
    }
};

// --- Parser tests ---

fn expectWord(word: Word, expected_parts: []const []const u8) !void {
    try std.testing.expectEqual(expected_parts.len, word.parts.len);
    for (word.parts, expected_parts) |part, expected| {
        switch (part) {
            .literal => |lit| try std.testing.expectEqualStrings(expected, lit),
        }
    }
}

fn expectSimpleCommand(
    cmd: ?SimpleCommand,
    expected_assignments: []const struct { name: []const u8, value: []const []const u8 },
    expected_argv: []const []const []const u8,
    expected_redirections: usize,
) !void {
    const c = cmd orelse return error.ExpectedCommand;

    try std.testing.expectEqual(expected_assignments.len, c.assignments.len);
    for (c.assignments, expected_assignments) |assignment, expected| {
        try std.testing.expectEqualStrings(expected.name, assignment.name);
        try expectWord(assignment.value, expected.value);
    }

    try std.testing.expectEqual(expected_argv.len, c.argv.len);
    for (c.argv, expected_argv) |word, expected| {
        try expectWord(word, expected);
    }

    try std.testing.expectEqual(expected_redirections, c.redirections.len);
}

test "parseCommand: empty input returns null" {
    var reader = std.io.Reader.fixed("");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(std.testing.allocator, &lex);

    const result = try parser_inst.parseCommand();
    try std.testing.expectEqual(null, result);
}

test "parseCommand: whitespace only returns null" {
    var reader = std.io.Reader.fixed("   \t  ");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(std.testing.allocator, &lex);

    const result = try parser_inst.parseCommand();
    try std.testing.expectEqual(null, result);
}

test "parseCommand: simple command" {
    var reader = std.io.Reader.fixed("cmd arg1 arg2\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try expectSimpleCommand(
        result,
        &.{},
        &.{ &.{"cmd"}, &.{"arg1"}, &.{"arg2"} },
        0,
    );
}

test "parseCommand: simple assignment" {
    var reader = std.io.Reader.fixed("FOO=bar\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try expectSimpleCommand(
        result,
        &.{.{ .name = "FOO", .value = &.{"bar"} }},
        &.{},
        0,
    );
}

test "parseCommand: empty assignment value" {
    var reader = std.io.Reader.fixed("FOO=\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try expectSimpleCommand(
        result,
        &.{.{ .name = "FOO", .value = &.{} }},
        &.{},
        0,
    );
}

test "parseCommand: assignment with command" {
    var reader = std.io.Reader.fixed("FOO=bar cmd arg\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try expectSimpleCommand(
        result,
        &.{.{ .name = "FOO", .value = &.{"bar"} }},
        &.{ &.{"cmd"}, &.{"arg"} },
        0,
    );
}

test "parseCommand: multiple assignments" {
    var reader = std.io.Reader.fixed("FOO=bar BAZ=qux cmd\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try expectSimpleCommand(
        result,
        &.{
            .{ .name = "FOO", .value = &.{"bar"} },
            .{ .name = "BAZ", .value = &.{"qux"} },
        },
        &.{&.{"cmd"}},
        0,
    );
}

test "parseCommand: non-assignment (equals at start)" {
    var reader = std.io.Reader.fixed("=foo\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try expectSimpleCommand(
        result,
        &.{},
        &.{&.{"=foo"}},
        0,
    );
}

test "parseCommand: non-assignment (invalid identifier)" {
    var reader = std.io.Reader.fixed("123=foo\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try expectSimpleCommand(
        result,
        &.{},
        &.{&.{"123=foo"}},
        0,
    );
}

test "parseCommand: simple redirection" {
    var reader = std.io.Reader.fixed("> file\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    try std.testing.expectEqual(@as(usize, 0), cmd.assignments.len);
    try std.testing.expectEqual(@as(usize, 0), cmd.argv.len);
    try std.testing.expectEqual(@as(usize, 1), cmd.redirections.len);

    const redir = cmd.redirections[0];
    try std.testing.expectEqual(lexer.RedirectionOp.Out, redir.op);
    try std.testing.expectEqual(@as(?u32, null), redir.source_fd);
    try expectWord(redir.target, &.{"file"});
}

test "parseCommand: command with redirection" {
    var reader = std.io.Reader.fixed("cmd > out\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    try std.testing.expectEqual(@as(usize, 1), cmd.argv.len);
    try std.testing.expectEqual(@as(usize, 1), cmd.redirections.len);
    try expectWord(cmd.redirections[0].target, &.{"out"});
}

test "parseCommand: fd redirection 2>&1" {
    var reader = std.io.Reader.fixed("cmd 2>&1\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    try std.testing.expectEqual(@as(usize, 1), cmd.argv.len);
    try std.testing.expectEqual(@as(usize, 1), cmd.redirections.len);

    const redir = cmd.redirections[0];
    try std.testing.expectEqual(lexer.RedirectionOp.Fd, redir.op);
    try std.testing.expectEqual(@as(?u32, 2), redir.source_fd);
    try expectWord(redir.target, &.{"1"});
}

test "parseCommand: multiple redirections" {
    var reader = std.io.Reader.fixed("cmd > out 2>&1 < in\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    try std.testing.expectEqual(@as(usize, 1), cmd.argv.len);
    try std.testing.expectEqual(@as(usize, 3), cmd.redirections.len);

    try std.testing.expectEqual(lexer.RedirectionOp.Out, cmd.redirections[0].op);
    try std.testing.expectEqual(lexer.RedirectionOp.Fd, cmd.redirections[1].op);
    try std.testing.expectEqual(lexer.RedirectionOp.In, cmd.redirections[2].op);
}

test "parseCommand: missing redirection target" {
    var reader = std.io.Reader.fixed(">\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = parser_inst.parseCommand();
    try std.testing.expectError(ParseError.MissingRedirectionTarget, result);

    const err_info = parser_inst.getErrorInfo();
    try std.testing.expect(err_info != null);
    try std.testing.expectEqualStrings("missing redirection target", err_info.?.message);
}

test "parseCommand: single-quoted word" {
    var reader = std.io.Reader.fixed("'hello world'\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try expectSimpleCommand(
        result,
        &.{},
        &.{&.{"hello world"}},
        0,
    );
}

test "parseCommand: double-quoted word" {
    var reader = std.io.Reader.fixed("\"hello world\"\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try expectSimpleCommand(
        result,
        &.{},
        &.{&.{"hello world"}},
        0,
    );
}

test "parseCommand: mixed quotes in word" {
    var reader = std.io.Reader.fixed("a'b'c\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try expectSimpleCommand(
        result,
        &.{},
        &.{&.{ "a", "b", "c" }},
        0,
    );
}

test "parseCommand: escaped character" {
    var reader = std.io.Reader.fixed("\\$HOME\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try expectSimpleCommand(
        result,
        &.{},
        &.{&.{ "$", "HOME" }},
        0,
    );
}

test "parseCommand: complex command" {
    var reader = std.io.Reader.fixed("FOO=bar cmd 'arg 1' >out 2>&1\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    try std.testing.expectEqual(@as(usize, 1), cmd.assignments.len);
    try std.testing.expectEqualStrings("FOO", cmd.assignments[0].name);

    try std.testing.expectEqual(@as(usize, 2), cmd.argv.len);
    try expectWord(cmd.argv[0], &.{"cmd"});
    try expectWord(cmd.argv[1], &.{"arg 1"});

    try std.testing.expectEqual(@as(usize, 2), cmd.redirections.len);
}

test "parseCommand: assignment after command is not assignment" {
    // Once we've seen a command, further FOO=bar are arguments, not assignments
    var reader = std.io.Reader.fixed("cmd FOO=bar\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try expectSimpleCommand(
        result,
        &.{}, // no assignments
        &.{ &.{"cmd"}, &.{"FOO=bar"} }, // FOO=bar is an argument
        0,
    );
}
