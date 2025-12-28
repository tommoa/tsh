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

/// The target of a redirection operation.
pub const RedirectionTarget = union(enum) {
    /// For file redirections (In, Out, Append): the target filename.
    file: Word,
    /// For fd duplication (Fd): the target file descriptor number.
    fd: u32,
    /// For fd close (Fd with "-" target): close the source fd.
    close,
};

/// A parsed redirection with its target.
pub const ParsedRedirection = struct {
    /// The type of redirection operation.
    op: lexer.Redirection,
    /// The source file descriptor (e.g., "2" in "2>file"), if specified.
    source_fd: ?u32,
    /// The target of the redirection.
    target: RedirectionTarget,
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
    /// For >& or <&, the target must be a digit sequence or '-'.
    InvalidFdRedirectionTarget,
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
    op: lexer.Redirection,
    source_fd: ?u32,
    position: usize,
    line: usize,
    column: usize,
    /// End position of the redirection operator (for error reporting).
    end_line: usize,
    end_column: usize,
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

                switch (tok.type) {
                    .Redirection => |redir| {
                        // Encountered redirection while collecting word.
                        // Try to interpret word_parts as a source fd number.
                        // If successful, use it as the source fd for this redirection.
                        // If not (overflow, non-digits), treat word as a regular argument.
                        if (wordPartsToFdNumber(self.word_parts.items)) |source_fd| {
                            // Valid source fd - use it for the redirection
                            self.word_parts = .{};
                            self.pending_redir = .{
                                .op = redir,
                                .source_fd = source_fd,
                                .position = self.word_start_position,
                                .line = self.word_start_line,
                                .column = self.word_start_column,
                                .end_line = tok.end_line,
                                .end_column = tok.end_column,
                            };
                            continue :state .need_redir_target;
                        } else {
                            // Not a valid fd - finalize word as argument and handle redirection
                            const word = try self.finishWord();
                            if (!self.seen_command) {
                                if (try self.tryBuildAssignment(word)) |assignment| {
                                    try self.assignments.append(self.allocator, assignment);
                                } else {
                                    try self.argv.append(self.allocator, word);
                                    self.seen_command = true;
                                }
                            } else {
                                try self.argv.append(self.allocator, word);
                            }
                            // Now handle the redirection with default source fd
                            self.setPendingRedir(redir, tok);
                            continue :state .need_redir_target;
                        }
                    },
                    else => {
                        try self.addTokenToParts(tok);
                        if (tok.complete) {
                            continue :state .word_complete;
                        } else {
                            continue :state .collecting_word;
                        }
                    },
                }
            },

            .need_redir_target => {
                const tok = self.lex.nextToken() catch |err| {
                    self.setError("lexer error reading redirection target", self.lex.position, self.lex.line, self.lex.column);
                    return err;
                } orelse {
                    // EOF - error points to end of redirection operator
                    const redir = self.pending_redir.?;
                    self.setError("missing redirection target", redir.position, redir.end_line, redir.end_column);
                    return ParseError.MissingRedirectionTarget;
                };

                switch (tok.type) {
                    .Redirection => {
                        // Another redirection where target was expected - error points to end of first redirection
                        const redir = self.pending_redir.?;
                        self.setError("missing redirection target", redir.position, redir.end_line, redir.end_column);
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
                    const target: RedirectionTarget = if (redir.op == .Fd)
                        try self.parseFdTarget(word)
                    else
                        .{ .file = word };

                    try self.redirections.append(self.allocator, .{
                        .op = redir.op,
                        .source_fd = redir.source_fd,
                        .target = target,
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

    /// Set up pending redirection info with default source fd (null).
    fn setPendingRedir(self: *Parser, redir: lexer.Redirection, tok: lexer.Token) void {
        self.pending_redir = .{
            .op = redir,
            .source_fd = null,
            .position = tok.position,
            .line = tok.line,
            .column = tok.column,
            .end_line = tok.end_line,
            .end_column = tok.end_column,
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

    /// Try to convert word parts to an fd number.
    /// Returns null if:
    ///   - parts is empty
    ///   - any part contains non-digit characters
    ///   - the number overflows u32
    fn wordPartsToFdNumber(parts: []const WordPart) ?u32 {
        if (parts.len == 0) return null;

        var result: u32 = 0;

        for (parts) |part| {
            const lit = switch (part) {
                .literal => |l| l,
            };
            if (lit.len == 0) continue;

            // Parse this part as an integer
            const part_value = std.fmt.parseInt(u32, lit, 10) catch return null;

            // Shift result left by the number of digits in this part
            for (0..lit.len) |_| {
                result = std.math.mul(u32, result, 10) catch return null;
            }

            // Add the new part's value
            result = std.math.add(u32, result, part_value) catch return null;
        }
        return result;
    }

    /// Parse an fd duplication target from a word.
    /// Valid targets are:
    ///   - "-" (close the source fd)
    ///   - A digit sequence (duplicate to that fd)
    /// Returns InvalidFdRedirectionTarget if the word is not a valid fd target.
    fn parseFdTarget(self: *Parser, word: Word) ParseError!RedirectionTarget {
        // Check for close: exactly one part that is "-"
        if (word.parts.len == 1) {
            switch (word.parts[0]) {
                .literal => |lit| {
                    if (std.mem.eql(u8, lit, "-")) {
                        return .close;
                    }
                },
            }
        }

        // Check for fd number: all parts must be digits and fit in u32
        if (wordPartsToFdNumber(word.parts)) |fd| {
            return .{ .fd = fd };
        }

        // Invalid target (non-digits or overflow)
        self.setError("invalid fd redirection target (expected digits or '-')", word.position, word.line, word.column);
        return ParseError.InvalidFdRedirectionTarget;
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

fn expectFileTarget(target: RedirectionTarget, expected_parts: []const []const u8) !void {
    switch (target) {
        .file => |word| try expectWord(word, expected_parts),
        .fd => return error.ExpectedFileTarget,
        .close => return error.ExpectedFileTarget,
    }
}

fn expectFdTarget(target: RedirectionTarget, expected_fd: u32) !void {
    switch (target) {
        .fd => |fd| try std.testing.expectEqual(expected_fd, fd),
        .file => return error.ExpectedFdTarget,
        .close => return error.ExpectedFdTarget,
    }
}

fn expectCloseTarget(target: RedirectionTarget) !void {
    switch (target) {
        .close => {},
        .file => return error.ExpectedCloseTarget,
        .fd => return error.ExpectedCloseTarget,
    }
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
    try std.testing.expectEqual(lexer.Redirection.Out, redir.op);
    try std.testing.expectEqual(@as(?u32, null), redir.source_fd);
    try expectFileTarget(redir.target, &.{"file"});
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
    try expectFileTarget(cmd.redirections[0].target, &.{"out"});
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
    try std.testing.expectEqual(lexer.Redirection.Fd, redir.op);
    try std.testing.expectEqual(@as(?u32, 2), redir.source_fd);
    try expectFdTarget(redir.target, 1);
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

    try std.testing.expectEqual(lexer.Redirection.Out, cmd.redirections[0].op);
    try std.testing.expectEqual(lexer.Redirection.Fd, cmd.redirections[1].op);
    try std.testing.expectEqual(lexer.Redirection.In, cmd.redirections[2].op);
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

test "parseCommand: quoted redirection-like string is literal" {
    // "2>&1" in quotes should be a literal argument, not a redirection
    var reader = std.io.Reader.fixed("cmd \"2>&1\"\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    // Should have 2 argv items: "cmd" and "2>&1"
    try std.testing.expectEqual(@as(usize, 2), cmd.argv.len);
    try expectWord(cmd.argv[0], &.{"cmd"});
    try expectWord(cmd.argv[1], &.{ "2", ">", "&", "1" }); // Separate tokens from double-quote parsing

    // No redirections
    try std.testing.expectEqual(@as(usize, 0), cmd.redirections.len);
}

test "parseCommand: single-quoted redirection-like string is literal" {
    // '2>&1' in single quotes should be a literal argument, not a redirection
    var reader = std.io.Reader.fixed("cmd '2>&1'\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    // Should have 2 argv items: "cmd" and "2>&1"
    try std.testing.expectEqual(@as(usize, 2), cmd.argv.len);
    try expectWord(cmd.argv[0], &.{"cmd"});
    try expectWord(cmd.argv[1], &.{"2>&1"}); // Single quotes preserve content as-is

    // No redirections
    try std.testing.expectEqual(@as(usize, 0), cmd.redirections.len);
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

// --- Fd duplication validation tests ---

test "parseCommand: fd close >&-" {
    var reader = std.io.Reader.fixed("cmd >&-\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    try std.testing.expectEqual(@as(usize, 1), cmd.argv.len);
    try std.testing.expectEqual(@as(usize, 1), cmd.redirections.len);

    const redir = cmd.redirections[0];
    try std.testing.expectEqual(lexer.Redirection.Fd, redir.op);
    try std.testing.expectEqual(@as(?u32, null), redir.source_fd);
    try expectCloseTarget(redir.target);
}

test "parseCommand: fd close 2>&-" {
    var reader = std.io.Reader.fixed("cmd 2>&-\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    try std.testing.expectEqual(@as(usize, 1), cmd.redirections.len);

    const redir = cmd.redirections[0];
    try std.testing.expectEqual(lexer.Redirection.Fd, redir.op);
    try std.testing.expectEqual(@as(?u32, 2), redir.source_fd);
    try expectCloseTarget(redir.target);
}

test "parseCommand: invalid fd target >&foo errors" {
    var reader = std.io.Reader.fixed("cmd >&foo\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = parser_inst.parseCommand();
    try std.testing.expectError(ParseError.InvalidFdRedirectionTarget, result);

    const err_info = parser_inst.getErrorInfo();
    try std.testing.expect(err_info != null);
}

test "parseCommand: invalid fd target >&1x errors" {
    // "1x" is not a valid fd (contains non-digit)
    var reader = std.io.Reader.fixed("cmd >&1x\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = parser_inst.parseCommand();
    try std.testing.expectError(ParseError.InvalidFdRedirectionTarget, result);
}

test "parseCommand: escaped quote after fd target errors" {
    // \'2>&1\' - the trailing \' makes target "1'" which is invalid
    var reader = std.io.Reader.fixed("\\'2>&1\\'\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = parser_inst.parseCommand();
    try std.testing.expectError(ParseError.InvalidFdRedirectionTarget, result);
}

// --- Buffer boundary tests ---

test "parseCommand: fd redirection 2>&1 with buffer boundary" {
    // Test that 2>&1 is correctly parsed when buffer boundary falls within the fd prefix.
    // The parser should correctly combine the split digits into source_fd=2.
    const pipe = try std.posix.pipe();
    defer std.posix.close(pipe[0]);

    _ = try std.posix.write(pipe[1], "cmd 2>&1\n");
    std.posix.close(pipe[1]);

    // Small buffer that forces splits within the input
    const file = std.fs.File{ .handle = pipe[0] };
    var small_buf: [1]u8 = undefined;
    var file_reader = file.reader(&small_buf);
    var lex = lexer.Lexer.init(&file_reader.interface);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    try std.testing.expectEqual(@as(usize, 1), cmd.argv.len);
    try expectWord(cmd.argv[0], &.{"cmd"});

    try std.testing.expectEqual(@as(usize, 1), cmd.redirections.len);
    const redir = cmd.redirections[0];
    try std.testing.expectEqual(lexer.Redirection.Fd, redir.op);
    try std.testing.expectEqual(@as(?u32, 2), redir.source_fd);
    try expectFdTarget(redir.target, 1);
}

test "parseCommand: multi-digit fd 12>&1 with buffer boundary" {
    // Test that 12>&1 is correctly parsed when buffer boundary splits the fd digits.
    const pipe = try std.posix.pipe();
    defer std.posix.close(pipe[0]);

    _ = try std.posix.write(pipe[1], "cmd 12>&1\n");
    std.posix.close(pipe[1]);

    const file = std.fs.File{ .handle = pipe[0] };
    var small_buf: [1]u8 = undefined;
    var file_reader = file.reader(&small_buf);
    var lex = lexer.Lexer.init(&file_reader.interface);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    try std.testing.expectEqual(@as(usize, 1), cmd.argv.len);
    try std.testing.expectEqual(@as(usize, 1), cmd.redirections.len);

    const redir = cmd.redirections[0];
    try std.testing.expectEqual(lexer.Redirection.Fd, redir.op);
    try std.testing.expectEqual(@as(?u32, 12), redir.source_fd);
    try expectFdTarget(redir.target, 1);
}

test "parseCommand: non-digit word before redirection with buffer boundary" {
    // Test that a2>file correctly treats "a2" as a word and ">file" as redirection.
    const pipe = try std.posix.pipe();
    defer std.posix.close(pipe[0]);

    _ = try std.posix.write(pipe[1], "a2>file\n");
    std.posix.close(pipe[1]);

    const file = std.fs.File{ .handle = pipe[0] };
    var small_buf: [1]u8 = undefined;
    var file_reader = file.reader(&small_buf);
    var lex = lexer.Lexer.init(&file_reader.interface);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    // "a2" should be argv[0], redirection should be separate
    try std.testing.expectEqual(@as(usize, 1), cmd.argv.len);
    try expectWord(cmd.argv[0], &.{ "a", "2" }); // Split across buffer boundaries

    try std.testing.expectEqual(@as(usize, 1), cmd.redirections.len);
    const redir = cmd.redirections[0];
    try std.testing.expectEqual(lexer.Redirection.Out, redir.op);
    try std.testing.expectEqual(@as(?u32, null), redir.source_fd);
    try expectFileTarget(redir.target, &.{"file"});
}

test "parseCommand: input fd redirection 0<&3 with buffer boundary" {
    // Test input fd duplication with buffer boundary.
    const pipe = try std.posix.pipe();
    defer std.posix.close(pipe[0]);

    _ = try std.posix.write(pipe[1], "cmd 0<&3\n");
    std.posix.close(pipe[1]);

    const file = std.fs.File{ .handle = pipe[0] };
    var small_buf: [1]u8 = undefined;
    var file_reader = file.reader(&small_buf);
    var lex = lexer.Lexer.init(&file_reader.interface);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    try std.testing.expectEqual(@as(usize, 1), cmd.argv.len);
    try expectWord(cmd.argv[0], &.{"cmd"});

    try std.testing.expectEqual(@as(usize, 1), cmd.redirections.len);
    const redir = cmd.redirections[0];
    try std.testing.expectEqual(lexer.Redirection.Fd, redir.op);
    try std.testing.expectEqual(@as(?u32, 0), redir.source_fd);
    try expectFdTarget(redir.target, 3);
}

test "parseCommand: input redirection 0<file with buffer boundary" {
    // Test input redirection with fd prefix and buffer boundary.
    const pipe = try std.posix.pipe();
    defer std.posix.close(pipe[0]);

    _ = try std.posix.write(pipe[1], "cmd 0<input\n");
    std.posix.close(pipe[1]);

    const file = std.fs.File{ .handle = pipe[0] };
    var small_buf: [1]u8 = undefined;
    var file_reader = file.reader(&small_buf);
    var lex = lexer.Lexer.init(&file_reader.interface);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    try std.testing.expectEqual(@as(usize, 1), cmd.argv.len);
    try std.testing.expectEqual(@as(usize, 1), cmd.redirections.len);

    const redir = cmd.redirections[0];
    try std.testing.expectEqual(lexer.Redirection.In, redir.op);
    try std.testing.expectEqual(@as(?u32, 0), redir.source_fd);
    try expectFileTarget(redir.target, &.{"input"});
}

// --- Fuzz test for buffer boundary invariance ---

/// Parse input with a fixed reader (large buffer) and return semantic results.
fn parseWithFixedReader(allocator: Allocator, input: []const u8) !?SimpleCommand {
    var reader = std.io.Reader.fixed(input);
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(allocator, &lex);
    return parser_inst.parseCommand();
}

/// Parse input with a pipe-based reader (small buffer) and return semantic results.
fn parseWithSmallBuffer(allocator: Allocator, input: []const u8, buf_size: usize) !?SimpleCommand {
    const pipe = try std.posix.pipe();
    defer std.posix.close(pipe[0]);

    _ = try std.posix.write(pipe[1], input);
    std.posix.close(pipe[1]);

    const file = std.fs.File{ .handle = pipe[0] };

    // Use buffer size 1-5 based on buf_size parameter
    var small_buf_1: [1]u8 = undefined;
    var small_buf_2: [2]u8 = undefined;
    var small_buf_3: [3]u8 = undefined;
    var small_buf_4: [4]u8 = undefined;
    var small_buf_5: [5]u8 = undefined;

    switch (buf_size) {
        1 => {
            var file_reader = file.reader(&small_buf_1);
            var lex = lexer.Lexer.init(&file_reader.interface);
            var parser_inst = Parser.init(allocator, &lex);
            return parser_inst.parseCommand();
        },
        2 => {
            var file_reader = file.reader(&small_buf_2);
            var lex = lexer.Lexer.init(&file_reader.interface);
            var parser_inst = Parser.init(allocator, &lex);
            return parser_inst.parseCommand();
        },
        3 => {
            var file_reader = file.reader(&small_buf_3);
            var lex = lexer.Lexer.init(&file_reader.interface);
            var parser_inst = Parser.init(allocator, &lex);
            return parser_inst.parseCommand();
        },
        4 => {
            var file_reader = file.reader(&small_buf_4);
            var lex = lexer.Lexer.init(&file_reader.interface);
            var parser_inst = Parser.init(allocator, &lex);
            return parser_inst.parseCommand();
        },
        else => {
            var file_reader = file.reader(&small_buf_5);
            var lex = lexer.Lexer.init(&file_reader.interface);
            var parser_inst = Parser.init(allocator, &lex);
            return parser_inst.parseCommand();
        },
    }
}

/// Concatenate word parts into a single string for comparison.
fn wordToString(allocator: Allocator, word: Word) ![]const u8 {
    var result: std.ArrayListUnmanaged(u8) = .{};
    for (word.parts) |part| {
        switch (part) {
            .literal => |lit| try result.appendSlice(allocator, lit),
        }
    }
    return result.toOwnedSlice(allocator);
}

/// Compare two SimpleCommands for semantic equality.
fn commandsEqual(allocator: Allocator, a: ?SimpleCommand, b: ?SimpleCommand) !bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;

    const cmd_a = a.?;
    const cmd_b = b.?;

    // Compare assignments
    if (cmd_a.assignments.len != cmd_b.assignments.len) return false;
    for (cmd_a.assignments, cmd_b.assignments) |ass_a, ass_b| {
        if (!std.mem.eql(u8, ass_a.name, ass_b.name)) return false;
        const val_a = try wordToString(allocator, ass_a.value);
        const val_b = try wordToString(allocator, ass_b.value);
        if (!std.mem.eql(u8, val_a, val_b)) return false;
    }

    // Compare argv
    if (cmd_a.argv.len != cmd_b.argv.len) return false;
    for (cmd_a.argv, cmd_b.argv) |word_a, word_b| {
        const str_a = try wordToString(allocator, word_a);
        const str_b = try wordToString(allocator, word_b);
        if (!std.mem.eql(u8, str_a, str_b)) return false;
    }

    // Compare redirections
    if (cmd_a.redirections.len != cmd_b.redirections.len) return false;
    for (cmd_a.redirections, cmd_b.redirections) |redir_a, redir_b| {
        if (redir_a.op != redir_b.op) return false;
        if (redir_a.source_fd != redir_b.source_fd) return false;
        // Compare targets based on their type
        switch (redir_a.target) {
            .file => |word_a| {
                switch (redir_b.target) {
                    .file => |word_b| {
                        const str_a = try wordToString(allocator, word_a);
                        const str_b = try wordToString(allocator, word_b);
                        if (!std.mem.eql(u8, str_a, str_b)) return false;
                    },
                    else => return false,
                }
            },
            .fd => |fd_a| {
                switch (redir_b.target) {
                    .fd => |fd_b| {
                        if (fd_a != fd_b) return false;
                    },
                    else => return false,
                }
            },
            .close => {
                switch (redir_b.target) {
                    .close => {},
                    else => return false,
                }
            },
        }
    }

    return true;
}

test "parseCommand: buffer boundary invariance for fd redirections" {
    // Test that specific fd-related inputs parse identically across buffer sizes.
    const test_inputs = [_][]const u8{
        "2>&1\n",
        "12>&1\n",
        "cmd 2>&1\n",
        "cmd 12>file\n",
        "a2>file\n",
        "2>file\n",
        "cmd >out 2>&1\n",
        "FOO=bar cmd 2>&1\n",
        // Input redirections
        "0<&3\n",
        "cmd 0<&3\n",
        "0<input\n",
        "cmd 0<input\n",
        "3<&0\n",
        // Quoted redirection-like strings (should be literals, not redirections)
        "cmd \"2>&1\"\n",
        "cmd '2>&1'\n",
    };

    for (test_inputs) |input| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        // Parse with large buffer (reference result)
        const ref_result = try parseWithFixedReader(arena.allocator(), input);

        // Parse with various small buffer sizes and compare
        for (1..6) |buf_size| {
            var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
            defer arena2.deinit();

            const small_result = parseWithSmallBuffer(arena2.allocator(), input, buf_size) catch |err| {
                // If small buffer parse fails, reference should also fail or be null
                if (ref_result != null) {
                    std.debug.print("Small buffer (size {d}) failed but reference succeeded for: {s}\n", .{ buf_size, input });
                    return err;
                }
                continue;
            };

            if (!try commandsEqual(arena2.allocator(), ref_result, small_result)) {
                std.debug.print("Mismatch for input '{s}' with buffer size {d}\n", .{ input, buf_size });
                return error.BufferBoundaryMismatch;
            }
        }
    }
}
