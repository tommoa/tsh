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
///
/// The distinction between literal, quoted, and double_quoted is important
/// for expansion phases:
/// - `literal`: Subject to tilde expansion, globbing, and field splitting
/// - `quoted`: Not subject to any expansion (from escapes or single quotes)
/// - `double_quoted`: Contents may include expansions, but results are not
///   subject to field splitting or globbing
pub const WordPart = union(enum) {
    /// Unquoted literal text - subject to tilde expansion, globbing, field splitting.
    literal: []const u8,

    /// Quoted/escaped literal text - not subject to any expansion.
    /// This includes content from single quotes ('...') and backslash escapes (\x).
    quoted: []const u8,

    /// Double-quoted region - contents may include expansions (variables, command
    /// substitution) but results are not subject to field splitting or globbing.
    double_quoted: []const WordPart,

    /// Parameter expansion - ${param}, ${param:-default}, etc.
    parameter: ParameterExpansion,

    // Future expansion types:
    // command_sub: CommandSubstitution,
    // arithmetic: ArithmeticExpansion,

    /// Format the word part for human-readable output.
    /// Implements the standard format interface for use with std.fmt.
    pub fn format(self: WordPart, writer: *std.io.Writer) std.io.Writer.Error!void {
        switch (self) {
            .literal => |lit| try writer.print("\"{s}\"", .{lit}),
            .quoted => |q| try writer.print("quoted(\"{s}\")", .{q}),
            .double_quoted => |parts| {
                try writer.writeAll("double_quoted([");
                for (parts, 0..) |part, i| {
                    if (i > 0) try writer.writeAll(", ");
                    try part.format(writer);
                }
                try writer.writeAll("])");
            },
            .parameter => |param| try param.format(writer),
        }
    }

    /// Format the word part for shell-like output (used inside double quotes).
    /// Unlike format(), this outputs content as it would appear in shell syntax.
    pub fn formatInner(self: WordPart, writer: *std.io.Writer) std.io.Writer.Error!void {
        switch (self) {
            .literal => |lit| try writer.writeAll(lit),
            .quoted => |q| {
                try writer.writeByte('\'');
                try writer.writeAll(q);
                try writer.writeByte('\'');
            },
            .double_quoted => |parts| {
                try writer.writeByte('"');
                for (parts) |part| {
                    try part.formatInner(writer);
                }
                try writer.writeByte('"');
            },
            .parameter => |param| try param.format(writer),
        }
    }
};

/// A parameter expansion (${param}, ${param:-default}, etc.)
/// Represents POSIX shell parameter expansion from Section 2.6.2.
pub const ParameterExpansion = struct {
    /// The parameter name (VAR, 1, ?, @, *, etc.)
    name: []const u8,
    /// Optional modifier for the expansion
    modifier: ?Modifier = null,

    pub const Modifier = struct {
        /// The modifier operation
        op: lexer.ModifierOp,
        /// True if colon present (checks for null/empty, not just unset)
        /// For example, ${VAR:-default} vs ${VAR-default}
        check_null: bool,
        /// The word after the modifier (null for Length modifier)
        word: ?[]const WordPart,
    };

    /// Format for debugging output.
    /// Reconstructs a shell-like representation of the expansion.
    /// Implements the standard format interface for use with std.fmt.
    pub fn format(self: ParameterExpansion, writer: *std.io.Writer) std.io.Writer.Error!void {
        try writer.writeAll("${");

        // Handle length modifier (prefix operator)
        if (self.modifier) |mod| {
            if (mod.op == .Length) {
                try writer.writeByte('#');
                try writer.writeAll(self.name);
                try writer.writeByte('}');
                return;
            }
        }

        try writer.writeAll(self.name);

        if (self.modifier) |mod| {
            // Write colon if check_null is set (for applicable modifiers)
            switch (mod.op) {
                .UseDefault, .AssignDefault, .ErrorIfUnset, .UseAlternative => {
                    if (mod.check_null) try writer.writeByte(':');
                },
                else => {},
            }

            // Write the operator
            switch (mod.op) {
                .Length => unreachable, // Handled above
                .UseDefault => try writer.writeByte('-'),
                .AssignDefault => try writer.writeByte('='),
                .ErrorIfUnset => try writer.writeByte('?'),
                .UseAlternative => try writer.writeByte('+'),
                .RemoveSmallestPrefix => try writer.writeByte('#'),
                .RemoveLargestPrefix => try writer.writeAll("##"),
                .RemoveSmallestSuffix => try writer.writeByte('%'),
                .RemoveLargestSuffix => try writer.writeAll("%%"),
            }

            // Write the word if present
            if (mod.word) |word_parts| {
                for (word_parts) |part| {
                    try part.formatInner(writer);
                }
            }
        }

        try writer.writeByte('}');
    }
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

    /// Format the word for human-readable output.
    pub fn format(self: Word, writer: *std.io.Writer) std.io.Writer.Error!void {
        if (self.parts.len == 0) {
            try writer.writeAll("\"\"");
            return;
        }

        if (self.parts.len == 1) {
            try self.parts[0].format(writer);
            return;
        }

        // Multiple parts - show as list
        try writer.writeByte('[');
        for (self.parts, 0..) |part, i| {
            if (i > 0) try writer.writeAll(", ");
            try part.format(writer);
        }
        try writer.writeByte(']');
    }
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

    /// Format the assignment for human-readable output.
    pub fn format(self: Assignment, writer: *std.io.Writer) std.io.Writer.Error!void {
        try writer.print("{s} = ", .{self.name});
        try self.value.format(writer);
    }
};

/// The target of a redirection operation.
pub const RedirectionTarget = union(enum) {
    /// For file redirections (In, Out, Append): the target filename.
    file: Word,
    /// For fd duplication (Fd): the target file descriptor number.
    fd: u32,
    /// For fd close (Fd with "-" target): close the source fd.
    close,

    /// Format the redirection target for human-readable output.
    pub fn format(self: RedirectionTarget, writer: *std.io.Writer) std.io.Writer.Error!void {
        switch (self) {
            .file => |word| try word.format(writer),
            .fd => |fd| try writer.print("{d}", .{fd}),
            .close => try writer.writeAll("-"),
        }
    }
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

    /// Format the redirection for human-readable output.
    pub fn format(self: ParsedRedirection, writer: *std.io.Writer) std.io.Writer.Error!void {
        if (self.source_fd) |fd| {
            try writer.print("{d}", .{fd});
        }
        switch (self.op) {
            .In => try writer.writeByte('<'),
            .Out => try writer.writeByte('>'),
            .Append => try writer.writeAll(">>"),
            .Fd => try writer.writeAll(">&"),
        }
        try writer.writeByte(' ');
        try self.target.format(writer);
    }
};

/// A simple command consisting of assignments, arguments, and redirections.
pub const SimpleCommand = struct {
    /// Variable assignments that precede the command.
    assignments: []const Assignment,
    /// The command name and its arguments.
    argv: []const Word,
    /// Redirections in the order they appeared.
    redirections: []const ParsedRedirection,

    /// Format the command for human-readable output.
    pub fn format(self: SimpleCommand, writer: *std.io.Writer) std.io.Writer.Error!void {
        try self.formatIndented(writer, 0);
    }

    /// Format the command with indentation (for nested commands).
    fn formatIndented(self: SimpleCommand, writer: *std.io.Writer, indent: usize) std.io.Writer.Error!void {
        try writer.splatByteAll(' ', indent);
        try writer.writeAll("SimpleCommand:\n");

        if (self.assignments.len > 0) {
            try writer.splatByteAll(' ', indent + 2);
            try writer.writeAll("assignments:\n");
            for (self.assignments, 0..) |assignment, i| {
                try writer.splatByteAll(' ', indent + 4);
                try writer.print("[{d}] ", .{i});
                try assignment.format(writer);
                try writer.writeByte('\n');
            }
        }

        if (self.argv.len > 0) {
            try writer.splatByteAll(' ', indent + 2);
            try writer.writeAll("argv:\n");
            for (self.argv, 0..) |word, i| {
                try writer.splatByteAll(' ', indent + 4);
                try writer.print("[{d}] ", .{i});
                try word.format(writer);
                try writer.writeByte('\n');
            }
        }

        if (self.redirections.len > 0) {
            try writer.splatByteAll(' ', indent + 2);
            try writer.writeAll("redirections:\n");
            for (self.redirections, 0..) |redir, i| {
                try writer.splatByteAll(' ', indent + 4);
                try writer.print("[{d}] ", .{i});
                try redir.format(writer);
                try writer.writeByte('\n');
            }
        }
    }
};

/// A command that can be executed.
/// Currently only supports simple commands, but will expand to include
/// compound commands (if, while, for, case), pipelines, and subshells.
pub const Command = union(enum) {
    simple: SimpleCommand,

    /// Format the command for human-readable output.
    pub fn format(self: Command, writer: *std.io.Writer) std.io.Writer.Error!void {
        switch (self) {
            .simple => |cmd| try cmd.format(writer),
        }
    }
};

/// Errors that can occur during parsing.
pub const ParseError = error{
    /// Reached end of input when more tokens were expected.
    UnexpectedEndOfInput,
    /// A redirection operator was not followed by a target.
    MissingRedirectionTarget,
    /// For >& or <&, the target must be a digit sequence or '-'.
    InvalidFdRedirectionTarget,
    /// Encountered syntax that is not yet implemented (e.g., subshells, functions).
    UnsupportedSyntax,
    /// Invalid parameter expansion syntax (e.g., empty ${}).
    BadSubstitution,
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

/// Maximum depth for nested contexts (double quotes, brace expansions).
/// Matches the lexer's max_context_depth.
const max_context_depth = 32;

/// Parser context for nested constructs (double quotes, parameter expansions).
/// The parser maintains a stack of these to handle nesting like "${var:-${other}}".
const ParserContext = union(enum) {
    /// Inside double quotes - collecting parts for a double_quoted WordPart.
    double_quote: struct {
        parts: std.ArrayListUnmanaged(WordPart),
    },
    /// Inside ${...} - collecting the parameter expansion.
    brace_expansion: struct {
        /// The parameter name (null until we see it).
        name: ?[]const u8,
        /// The modifier operation (null if no modifier).
        modifier_op: ?lexer.ModifierOp,
        /// Whether the modifier has a colon (for :-, :=, etc.).
        modifier_check_null: bool,
        /// Parts being collected for the modifier's word.
        word_parts: std.ArrayListUnmanaged(WordPart),
        /// True after we've seen a modifier token.
        seen_modifier: bool,
    },

    /// Initialize a double_quote context.
    fn initDoubleQuote() ParserContext {
        return .{ .double_quote = .{ .parts = .{} } };
    }

    /// Initialize a brace_expansion context.
    fn initBraceExpansion() ParserContext {
        return .{ .brace_expansion = .{
            .name = null,
            .modifier_op = null,
            .modifier_check_null = false,
            .word_parts = .{},
            .seen_modifier = false,
        } };
    }

    /// Clean up any allocated memory in this context.
    fn deinit(self: *ParserContext, allocator: Allocator) void {
        switch (self.*) {
            .double_quote => |*dq| dq.parts.deinit(allocator),
            .brace_expansion => |*be| be.word_parts.deinit(allocator),
        }
    }
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

    /// Context stack for nested constructs (double quotes, brace expansions).
    /// Index 0 is the bottom of the stack; context_depth - 1 is the top.
    context_stack: [max_context_depth]ParserContext,
    /// Current depth of the context stack (0 = no active context).
    context_depth: usize,

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
            .context_stack = undefined,
            .context_depth = 0,
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

    // --- Context stack operations ---

    /// Push a new context onto the stack.
    fn pushContext(self: *Parser, ctx: ParserContext) void {
        std.debug.assert(self.context_depth < max_context_depth);
        self.context_stack[self.context_depth] = ctx;
        self.context_depth += 1;
    }

    /// Pop the top context from the stack.
    fn popContext(self: *Parser) ParserContext {
        std.debug.assert(self.context_depth > 0);
        self.context_depth -= 1;
        return self.context_stack[self.context_depth];
    }

    /// Get a mutable pointer to the current (top) context.
    fn currentContext(self: *Parser) ?*ParserContext {
        if (self.context_depth == 0) return null;
        return &self.context_stack[self.context_depth - 1];
    }

    /// Check if we're currently inside a double-quote context.
    fn inDoubleQuote(self: *const Parser) bool {
        if (self.context_depth == 0) return false;
        return self.context_stack[self.context_depth - 1] == .double_quote;
    }

    /// Check if we're currently inside a brace expansion context.
    fn inBraceExpansion(self: *const Parser) bool {
        if (self.context_depth == 0) return false;
        return self.context_stack[self.context_depth - 1] == .brace_expansion;
    }

    /// Get a user-friendly error message for a lexer error.
    fn lexerErrorMessage(err: lexer.LexerError) []const u8 {
        return switch (err) {
            error.InvalidModifier => "invalid modifier",
            error.UnterminatedQuote => "unterminated quote",
            error.UnterminatedBraceExpansion => "unterminated brace expansion",
            error.NestingTooDeep => "nesting too deep",
            error.UnexpectedEndOfFile => "unexpected end of file",
        };
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
                    self.setError(lexerErrorMessage(err), self.lex.position, self.lex.line, self.lex.column);
                    return err;
                } orelse {
                    continue :state .done;
                };

                switch (tok.type) {
                    .Newline, .Semicolon, .DoubleSemicolon => {
                        // Empty command (e.g., leading semicolon or blank line) - skip
                        // TODO: DoubleSemicolon (`;;`) will need special handling for case/esac
                        continue :state .start;
                    },
                    .Redirection => |redir| {
                        self.setPendingRedir(redir, tok);
                        continue :state .need_redir_target;
                    },
                    .LeftParen => {
                        self.setError("subshells are not yet implemented", tok.position, tok.line, tok.column);
                        return ParseError.UnsupportedSyntax;
                    },
                    .RightParen => {
                        self.setError("syntax error near unexpected token `)'", tok.position, tok.line, tok.column);
                        return ParseError.UnsupportedSyntax;
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
                    self.setError(lexerErrorMessage(err), self.lex.position, self.lex.line, self.lex.column);
                    return err;
                } orelse {
                    continue :state .done;
                };

                switch (tok.type) {
                    .Newline, .Semicolon, .DoubleSemicolon => {
                        // Command is complete, separator consumed
                        // TODO: DoubleSemicolon (`;;`) will need special handling for case/esac
                        continue :state .done;
                    },
                    .Redirection => |redir| {
                        self.setPendingRedir(redir, tok);
                        continue :state .need_redir_target;
                    },
                    .LeftParen => {
                        self.setError("syntax error near unexpected token `('", tok.position, tok.line, tok.column);
                        return ParseError.UnsupportedSyntax;
                    },
                    .RightParen => {
                        self.setError("syntax error near unexpected token `)'", tok.position, tok.line, tok.column);
                        return ParseError.UnsupportedSyntax;
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
                    self.setError(lexerErrorMessage(err), self.lex.position, self.lex.line, self.lex.column);
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
                    .LeftParen => {
                        self.setError("syntax error near unexpected token `('", tok.position, tok.line, tok.column);
                        return ParseError.UnsupportedSyntax;
                    },
                    .RightParen => {
                        self.setError("syntax error near unexpected token `)'", tok.position, tok.line, tok.column);
                        return ParseError.UnsupportedSyntax;
                    },
                    .Newline, .Semicolon, .DoubleSemicolon => {
                        // Unreachable: The lexer marks words complete when followed by separators.
                        // Even on a buffer boundary, the lexer emits a complete empty Continuation
                        // token before the separator, which transitions us to .word_complete first.
                        // This invariant is verified by the buffer boundary tests in this file.
                        unreachable;
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
                    self.setError(lexerErrorMessage(err), self.lex.position, self.lex.line, self.lex.column);
                    return err;
                } orelse {
                    // EOF - error points to end of redirection operator
                    const redir = self.pending_redir.?;
                    self.setError("missing redirection target", redir.position, redir.end_line, redir.end_column);
                    return ParseError.MissingRedirectionTarget;
                };

                switch (tok.type) {
                    .Newline, .Semicolon, .DoubleSemicolon => {
                        // Separator where redirection target was expected
                        const redir = self.pending_redir.?;
                        self.setError("missing redirection target", redir.position, redir.end_line, redir.end_column);
                        return ParseError.MissingRedirectionTarget;
                    },
                    .Redirection => {
                        // Another redirection where target was expected - error points to end of first redirection
                        const redir = self.pending_redir.?;
                        self.setError("missing redirection target", redir.position, redir.end_line, redir.end_column);
                        return ParseError.MissingRedirectionTarget;
                    },
                    .LeftParen => {
                        self.setError("syntax error near unexpected token `('", tok.position, tok.line, tok.column);
                        return ParseError.UnsupportedSyntax;
                    },
                    .RightParen => {
                        self.setError("syntax error near unexpected token `)'", tok.position, tok.line, tok.column);
                        return ParseError.UnsupportedSyntax;
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

    /// Pull the next command from the input.
    ///
    /// This is the primary iterator interface for pull-based execution.
    /// Returns the next parsed command, or `null` when input is exhausted.
    /// Empty commands (e.g., `;;;` or blank lines) are silently skipped.
    ///
    /// Example usage:
    /// ```
    /// while (try parser.next()) |cmd| {
    ///     try executor.execute(cmd);
    /// }
    /// ```
    pub fn next(self: *Parser) ParseError!?Command {
        const simple_cmd = try self.parseCommand() orelse return null;
        return .{ .simple = simple_cmd };
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
        // Clean up any leftover contexts (shouldn't happen in normal operation)
        while (self.context_depth > 0) {
            var ctx = self.popContext();
            ctx.deinit(self.allocator);
        }
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
    /// Handles nested contexts (double quotes, brace expansions) by collecting
    /// parts into the appropriate context and finalizing when the context ends.
    fn addTokenToParts(self: *Parser, token: lexer.Token) ParseError!void {
        switch (token.type) {
            .Literal => |lit| {
                const copied = try self.allocator.dupe(u8, lit);
                try self.addPartToCurrentContext(.{ .literal = copied });
            },
            .EscapedLiteral => |esc| {
                const copied = try self.allocator.dupe(u8, esc);
                try self.addPartToCurrentContext(.{ .quoted = copied });
            },
            .Continuation => |cont| {
                // Continuation may be empty (signals word boundary with no content)
                if (cont.len > 0) {
                    const copied = try self.allocator.dupe(u8, cont);
                    try self.addPartToCurrentContext(.{ .literal = copied });
                }
            },
            .SingleQuoted => |sq| {
                // SingleQuoted tokens appear outside double quotes (inside double quotes,
                // single quote characters are emitted as Literal tokens by the lexer).
                // They're valid in any context: top-level, brace expansion word, etc.
                const copied = try self.allocator.dupe(u8, sq);
                try self.addPartToCurrentContext(.{ .quoted = copied });
            },
            .DoubleQuoteBegin => {
                // Push a double-quote context onto the stack.
                self.pushContext(ParserContext.initDoubleQuote());
            },
            .DoubleQuoteEnd => {
                // Pop the double-quote context and finalize it.
                std.debug.assert(self.inDoubleQuote());
                var ctx = self.popContext();
                errdefer ctx.deinit(self.allocator);
                const parts_slice = try ctx.double_quote.parts.toOwnedSlice(self.allocator);
                try self.addPartToCurrentContext(.{ .double_quoted = parts_slice });
            },
            .SimpleExpansion => |name| {
                // Simple expansion: $VAR, $1, $?, etc.
                const copied_name = try self.allocator.dupe(u8, name);
                const expansion = ParameterExpansion{ .name = copied_name };
                try self.addPartToCurrentContext(.{ .parameter = expansion });
            },
            .BraceExpansionBegin => {
                // Push a brace expansion context onto the stack.
                self.pushContext(ParserContext.initBraceExpansion());
            },
            .Modifier => |mod| {
                // Modifier inside ${...}
                std.debug.assert(self.inBraceExpansion());
                const ctx = self.currentContext().?;
                ctx.brace_expansion.modifier_op = mod.op;
                ctx.brace_expansion.modifier_check_null = mod.check_null;
                ctx.brace_expansion.seen_modifier = true;
            },
            .BraceExpansionEnd => {
                // Pop the brace expansion context and build the ParameterExpansion.
                std.debug.assert(self.inBraceExpansion());
                var ctx = self.popContext();
                errdefer ctx.deinit(self.allocator);
                const be = &ctx.brace_expansion;

                // Check for missing parameter name (e.g., ${} or ${:-foo})
                if (be.name == null) {
                    self.setError("bad substitution", token.position, token.line, token.column);
                    return error.BadSubstitution;
                }

                // Build the ParameterExpansion
                const expansion = ParameterExpansion{
                    .name = be.name.?, // Confirmed not null above
                    .modifier = if (be.modifier_op) |op| blk: {
                        break :blk ParameterExpansion.Modifier{
                            .op = op,
                            .check_null = be.modifier_check_null,
                            .word = if (be.word_parts.items.len > 0)
                                try be.word_parts.toOwnedSlice(self.allocator)
                            else
                                null,
                        };
                    } else null,
                };

                try self.addPartToCurrentContext(.{ .parameter = expansion });
            },
            .Redirection => {
                // Shouldn't happen during word collection
            },
            .LeftParen, .RightParen => {
                // Shouldn't happen during word collection - handled by state machine
            },
            .Newline, .Semicolon, .DoubleSemicolon => {
                // Shouldn't happen during word collection - handled by state machine
            },
        }
    }

    /// Add a WordPart to the current context.
    /// If inside a brace expansion, handles the special case where the first
    /// literal becomes the parameter name.
    fn addPartToCurrentContext(self: *Parser, part: WordPart) !void {
        if (self.currentContext()) |ctx| {
            switch (ctx.*) {
                .double_quote => |*dq| {
                    try dq.parts.append(self.allocator, part);
                },
                .brace_expansion => |*be| {
                    // In brace expansion context:
                    // - If we haven't seen a modifier yet and name is null,
                    //   a literal becomes the parameter name
                    // - After a modifier (or for non-literal parts), add to word_parts
                    if (!be.seen_modifier and be.name == null) {
                        switch (part) {
                            .literal => |lit| {
                                be.name = lit;
                                return;
                            },
                            else => {},
                        }
                    }
                    // For Length modifier, the name comes AFTER the modifier token
                    if (be.modifier_op == .Length and be.name == null) {
                        switch (part) {
                            .literal => |lit| {
                                be.name = lit;
                                return;
                            },
                            else => {},
                        }
                    }
                    try be.word_parts.append(self.allocator, part);
                },
            }
        } else {
            // No context - add directly to word_parts
            try self.word_parts.append(self.allocator, part);
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
                    try value_parts.append(self.allocator, try self.copyWordPart(part));
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
            // If the first part is quoted, double_quoted, or parameter, it's not an assignment
            // (the `=` would need to be in an unquoted literal)
            .quoted, .double_quoted, .parameter => return null,
        }
    }

    /// Deep copy a WordPart, including nested parts for double_quoted and parameter.
    fn copyWordPart(self: *Parser, part: WordPart) ParseError!WordPart {
        return switch (part) {
            .literal => |lit| WordPart{ .literal = try self.allocator.dupe(u8, lit) },
            .quoted => |q| WordPart{ .quoted = try self.allocator.dupe(u8, q) },
            .double_quoted => |parts| blk: {
                var copied_parts = try self.allocator.alloc(WordPart, parts.len);
                for (parts, 0..) |p, i| {
                    copied_parts[i] = try self.copyWordPart(p);
                }
                break :blk WordPart{ .double_quoted = copied_parts };
            },
            .parameter => |param| blk: {
                const copied_name = try self.allocator.dupe(u8, param.name);
                const copied_modifier: ?ParameterExpansion.Modifier = if (param.modifier) |mod| m: {
                    const copied_word: ?[]const WordPart = if (mod.word) |word_parts| w: {
                        var copied_parts = try self.allocator.alloc(WordPart, word_parts.len);
                        for (word_parts, 0..) |p, i| {
                            copied_parts[i] = try self.copyWordPart(p);
                        }
                        break :w copied_parts;
                    } else null;
                    break :m ParameterExpansion.Modifier{
                        .op = mod.op,
                        .check_null = mod.check_null,
                        .word = copied_word,
                    };
                } else null;
                break :blk WordPart{ .parameter = ParameterExpansion{
                    .name = copied_name,
                    .modifier = copied_modifier,
                } };
            },
        };
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
    ///   - any part is quoted or double_quoted (fd numbers must be unquoted)
    ///   - any part contains non-digit characters
    ///   - the number overflows u32
    fn wordPartsToFdNumber(parts: []const WordPart) ?u32 {
        if (parts.len == 0) return null;

        var result: u32 = 0;

        for (parts) |part| {
            // Only unquoted literals can form fd numbers
            const lit = switch (part) {
                .literal => |l| l,
                // Quoted, double_quoted, or parameter parts can't be fd numbers
                .quoted, .double_quoted, .parameter => return null,
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
        // This works with literal, quoted, or double_quoted containing just "-"
        if (word.parts.len == 1) {
            const text: ?[]const u8 = switch (word.parts[0]) {
                .literal => |lit| lit,
                .quoted => |q| q,
                .double_quoted => |parts| blk: {
                    // double_quoted with exactly one literal/quoted part containing "-"
                    if (parts.len == 1) {
                        break :blk switch (parts[0]) {
                            .literal => |lit| lit,
                            .quoted => |q| q,
                            .double_quoted, .parameter => null,
                        };
                    }
                    break :blk null;
                },
                // Parameter expansions can't be evaluated at parse time
                .parameter => null,
            };
            if (text) |t| {
                if (std.mem.eql(u8, t, "-")) {
                    return .close;
                }
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
        // For simple tests, just compare the text content regardless of quote type
        const text = switch (part) {
            .literal => |lit| lit,
            .quoted => |q| q,
            .double_quoted => {
                // For double_quoted, we need a more complex comparison
                // For now, skip - tests that need this should use expectWordPart
                return error.UseExpectWordPartForDoubleQuoted;
            },
            .parameter => {
                // For parameter expansions, we need a more complex comparison
                // Tests that need this should check the parameter fields directly
                return error.UseExpectWordPartForParameter;
            },
        };
        try std.testing.expectEqualStrings(expected, text);
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

test "parseCommand: command followed by double-quoted expansion" {
    // echo "$@" should produce exactly 2 argv items, not 3
    var reader = std.io.Reader.fixed("echo \"$@\"\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    // Should have exactly 2 argv items: "echo" and "$@" (in double quotes)
    try std.testing.expectEqual(@as(usize, 2), cmd.argv.len);
    try expectWord(cmd.argv[0], &.{"echo"});

    // Second word should be a double_quoted containing a parameter expansion
    try std.testing.expectEqual(@as(usize, 1), cmd.argv[1].parts.len);
    switch (cmd.argv[1].parts[0]) {
        .double_quoted => |inner| {
            try std.testing.expectEqual(@as(usize, 1), inner.len);
            switch (inner[0]) {
                .parameter => |param| {
                    try std.testing.expectEqualStrings("@", param.name);
                },
                else => return error.ExpectedParameterExpansion,
            }
        },
        else => return error.ExpectedDoubleQuoted,
    }
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
        try appendWordPartText(allocator, &result, part);
    }
    return result.toOwnedSlice(allocator);
}

/// Recursively append text content from a WordPart to a list.
fn appendWordPartText(allocator: Allocator, result: *std.ArrayListUnmanaged(u8), part: WordPart) !void {
    switch (part) {
        .literal => |lit| try result.appendSlice(allocator, lit),
        .quoted => |q| try result.appendSlice(allocator, q),
        .double_quoted => |parts| {
            for (parts) |p| {
                try appendWordPartText(allocator, result, p);
            }
        },
        .parameter => |param| {
            // Append the parameter name as a placeholder for comparison purposes.
            // This allows buffer boundary tests to compare commands with expansions.
            try result.appendSlice(allocator, "$");
            try result.appendSlice(allocator, param.name);
        },
    }
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

// --- Parenthesis error tests ---

test "parseCommand: left parenthesis at start returns UnsupportedSyntax" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("(cmd)");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const result = parser.parseCommand();
    try std.testing.expectError(ParseError.UnsupportedSyntax, result);
    try std.testing.expectEqualStrings("subshells are not yet implemented", parser.error_info.?.message);
}

test "parseCommand: right parenthesis at start returns UnsupportedSyntax" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed(")");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const result = parser.parseCommand();
    try std.testing.expectError(ParseError.UnsupportedSyntax, result);
    try std.testing.expectEqualStrings("syntax error near unexpected token `)'", parser.error_info.?.message);
}

test "parseCommand: left parenthesis after command returns UnsupportedSyntax" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("cmd (");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const result = parser.parseCommand();
    try std.testing.expectError(ParseError.UnsupportedSyntax, result);
    try std.testing.expectEqualStrings("syntax error near unexpected token `('", parser.error_info.?.message);
}

test "parseCommand: right parenthesis after command returns UnsupportedSyntax" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("cmd )");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const result = parser.parseCommand();
    try std.testing.expectError(ParseError.UnsupportedSyntax, result);
    try std.testing.expectEqualStrings("syntax error near unexpected token `)'", parser.error_info.?.message);
}

test "parseCommand: parenthesis as redirection target returns UnsupportedSyntax" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("cmd >(");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const result = parser.parseCommand();
    try std.testing.expectError(ParseError.UnsupportedSyntax, result);
}

test "parseCommand: parenthesis in word returns UnsupportedSyntax" {
    // "cmd(" should tokenize as "cmd", "(" - then ( triggers error
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("cmd(");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const result = parser.parseCommand();
    try std.testing.expectError(ParseError.UnsupportedSyntax, result);
}

test "parseCommand: single-quoted parentheses are valid arguments" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo '(foo)'");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);
    try std.testing.expectEqual(@as(usize, 2), cmd.?.argv.len);
    try expectWord(cmd.?.argv[0], &[_][]const u8{"echo"});
    try expectWord(cmd.?.argv[1], &[_][]const u8{"(foo)"});
}

test "parseCommand: double-quoted parentheses are valid arguments" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo \"(bar)\"");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);
    try std.testing.expectEqual(@as(usize, 2), cmd.?.argv.len);
    try expectWord(cmd.?.argv[0], &[_][]const u8{"echo"});
    try expectWord(cmd.?.argv[1], &[_][]const u8{"(bar)"});
}

// --- Command list tests ---

test "next: buffer boundary with separator (1 byte buffer)" {
    // Test parsing "foo;bar" with a tiny buffer to check if separator
    // can arrive while parser is in .collecting_word state
    const pipe = try std.posix.pipe();
    defer std.posix.close(pipe[0]);

    _ = try std.posix.write(pipe[1], "foo;bar");
    std.posix.close(pipe[1]);

    const file = std.fs.File{ .handle = pipe[0] };
    var buf: [1]u8 = undefined;
    var file_reader = file.reader(&buf);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var lex = lexer.Lexer.init(&file_reader.interface);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    // Collect commands using iterator
    var commands: [2]SimpleCommand = undefined;
    var count: usize = 0;
    while (try parser_inst.next()) |cmd| {
        if (count < 2) commands[count] = cmd.simple;
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), count);

    // Verify first command is "foo"
    try std.testing.expectEqual(@as(usize, 1), commands[0].argv.len);
    const word1 = try wordToString(arena.allocator(), commands[0].argv[0]);
    try std.testing.expectEqualStrings("foo", word1);

    // Verify second command is "bar"
    try std.testing.expectEqual(@as(usize, 1), commands[1].argv.len);
    const word2 = try wordToString(arena.allocator(), commands[1].argv[0]);
    try std.testing.expectEqualStrings("bar", word2);
}

test "next: two commands with newline separator" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo a\necho b");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    var count: usize = 0;
    while (try parser_inst.next()) |_| {
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), count);
}

test "next: only separators yields no commands" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // Use spaces between semicolons to avoid `;;` which is DoubleSemicolon
    var reader = std.io.Reader.fixed("; ; ;");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const cmd = try parser_inst.next();
    try std.testing.expectEqual(null, cmd);
}

test "next: mixed separators" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo a\n; echo b; \n echo c");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    var count: usize = 0;
    while (try parser_inst.next()) |_| {
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), count);
}

test "next: double semicolon treated as separator" {
    // TODO: `;;` will need special handling for case/esac
    // For now, it's treated as a separator (empty command between)
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo a;; echo b");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    var count: usize = 0;
    while (try parser_inst.next()) |_| {
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), count);
}

// --- Parameter expansion tests ---

test "parseCommand: simple expansion $VAR" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo $VAR");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);
    try std.testing.expectEqual(@as(usize, 2), cmd.?.argv.len);

    // Second argument should be a parameter expansion
    const arg = cmd.?.argv[1];
    try std.testing.expectEqual(@as(usize, 1), arg.parts.len);
    try std.testing.expect(arg.parts[0] == .parameter);
    try std.testing.expectEqualStrings("VAR", arg.parts[0].parameter.name);
    try std.testing.expect(arg.parts[0].parameter.modifier == null);
}

test "parseCommand: simple expansion $1" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo $1");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);
    const arg = cmd.?.argv[1];
    try std.testing.expect(arg.parts[0] == .parameter);
    try std.testing.expectEqualStrings("1", arg.parts[0].parameter.name);
}

test "parseCommand: simple expansion $?" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo $?");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);
    const arg = cmd.?.argv[1];
    try std.testing.expect(arg.parts[0] == .parameter);
    try std.testing.expectEqualStrings("?", arg.parts[0].parameter.name);
}

test "parseCommand: braced expansion ${VAR}" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo ${VAR}");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);
    const arg = cmd.?.argv[1];
    try std.testing.expect(arg.parts[0] == .parameter);
    try std.testing.expectEqualStrings("VAR", arg.parts[0].parameter.name);
    try std.testing.expect(arg.parts[0].parameter.modifier == null);
}

test "parseCommand: expansion with default ${VAR:-default}" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo ${VAR:-default}");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);
    const arg = cmd.?.argv[1];
    try std.testing.expect(arg.parts[0] == .parameter);

    const param = arg.parts[0].parameter;
    try std.testing.expectEqualStrings("VAR", param.name);
    try std.testing.expect(param.modifier != null);
    try std.testing.expectEqual(lexer.ModifierOp.UseDefault, param.modifier.?.op);
    try std.testing.expect(param.modifier.?.check_null);
    try std.testing.expect(param.modifier.?.word != null);
    try std.testing.expectEqual(@as(usize, 1), param.modifier.?.word.?.len);
    try std.testing.expectEqualStrings("default", param.modifier.?.word.?[0].literal);
}

test "parseCommand: expansion without colon ${VAR-default}" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo ${VAR-default}");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);
    const param = cmd.?.argv[1].parts[0].parameter;
    try std.testing.expectEqual(lexer.ModifierOp.UseDefault, param.modifier.?.op);
    try std.testing.expect(!param.modifier.?.check_null);
}

test "parseCommand: length expansion ${#VAR}" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo ${#VAR}");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);
    const param = cmd.?.argv[1].parts[0].parameter;
    try std.testing.expectEqualStrings("VAR", param.name);
    try std.testing.expect(param.modifier != null);
    try std.testing.expectEqual(lexer.ModifierOp.Length, param.modifier.?.op);
    try std.testing.expect(param.modifier.?.word == null);
}

test "parseCommand: prefix removal ${VAR#pattern}" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo ${VAR#*.}");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);
    const param = cmd.?.argv[1].parts[0].parameter;
    try std.testing.expectEqualStrings("VAR", param.name);
    try std.testing.expectEqual(lexer.ModifierOp.RemoveSmallestPrefix, param.modifier.?.op);
    try std.testing.expectEqualStrings("*.", param.modifier.?.word.?[0].literal);
}

test "parseCommand: suffix removal ${VAR%pattern}" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo ${VAR%.*}");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);
    const param = cmd.?.argv[1].parts[0].parameter;
    try std.testing.expectEqualStrings("VAR", param.name);
    try std.testing.expectEqual(lexer.ModifierOp.RemoveSmallestSuffix, param.modifier.?.op);
    try std.testing.expectEqualStrings(".*", param.modifier.?.word.?[0].literal);
}

test "parseCommand: expansion in double quotes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo \"hello $VAR\"");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);
    const arg = cmd.?.argv[1];
    try std.testing.expectEqual(@as(usize, 1), arg.parts.len);
    try std.testing.expect(arg.parts[0] == .double_quoted);

    const inner = arg.parts[0].double_quoted;
    try std.testing.expectEqual(@as(usize, 2), inner.len);
    try std.testing.expect(inner[0] == .literal);
    try std.testing.expectEqualStrings("hello ", inner[0].literal);
    try std.testing.expect(inner[1] == .parameter);
    try std.testing.expectEqualStrings("VAR", inner[1].parameter.name);
}

test "parseCommand: mixed literal and expansion" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo prefix${VAR}suffix");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);
    const arg = cmd.?.argv[1];
    try std.testing.expectEqual(@as(usize, 3), arg.parts.len);
    try std.testing.expect(arg.parts[0] == .literal);
    try std.testing.expectEqualStrings("prefix", arg.parts[0].literal);
    try std.testing.expect(arg.parts[1] == .parameter);
    try std.testing.expectEqualStrings("VAR", arg.parts[1].parameter.name);
    try std.testing.expect(arg.parts[2] == .literal);
    try std.testing.expectEqualStrings("suffix", arg.parts[2].literal);
}

test "parseCommand: nested expansion ${VAR:-${OTHER}}" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo ${VAR:-${OTHER}}");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);
    const param = cmd.?.argv[1].parts[0].parameter;
    try std.testing.expectEqualStrings("VAR", param.name);
    try std.testing.expectEqual(lexer.ModifierOp.UseDefault, param.modifier.?.op);

    // The word should contain a nested parameter expansion
    const word = param.modifier.?.word.?;
    try std.testing.expectEqual(@as(usize, 1), word.len);
    try std.testing.expect(word[0] == .parameter);
    try std.testing.expectEqualStrings("OTHER", word[0].parameter.name);
}

test "parseCommand: expansion in assignment value" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("FOO=$BAR");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);
    try std.testing.expectEqual(@as(usize, 1), cmd.?.assignments.len);
    try std.testing.expectEqualStrings("FOO", cmd.?.assignments[0].name);

    const value = cmd.?.assignments[0].value;
    try std.testing.expectEqual(@as(usize, 1), value.parts.len);
    try std.testing.expect(value.parts[0] == .parameter);
    try std.testing.expectEqualStrings("BAR", value.parts[0].parameter.name);
}

test "parseCommand: empty ${} is BadSubstitution error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo ${}");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const result = parser.parseCommand();
    try std.testing.expectError(error.BadSubstitution, result);

    // Verify error message
    const err_info = parser.getErrorInfo();
    try std.testing.expect(err_info != null);
    try std.testing.expectEqualStrings("bad substitution", err_info.?.message);
}

test "parseCommand: ${:-foo} missing parameter name is BadSubstitution" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo ${:-foo}");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const result = parser.parseCommand();
    try std.testing.expectError(error.BadSubstitution, result);

    const err_info = parser.getErrorInfo();
    try std.testing.expect(err_info != null);
    try std.testing.expectEqualStrings("bad substitution", err_info.?.message);
}

// --- Iterator interface tests (next()) ---

test "next: empty input returns null" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const result = try parser.next();
    try std.testing.expectEqual(null, result);
}

test "next: single command yields one Command then null" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo hello");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    // First call should yield the command
    const cmd1 = try parser.next();
    try std.testing.expect(cmd1 != null);
    try std.testing.expectEqual(@as(usize, 2), cmd1.?.simple.argv.len);

    // Second call should yield null
    const cmd2 = try parser.next();
    try std.testing.expectEqual(null, cmd2);
}

test "next: multiple commands yields each in sequence" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo a; echo b; echo c");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    // Count commands
    var count: usize = 0;
    while (try parser.next()) |_| {
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), count);
}

test "next: skips empty commands" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // Use spaces between semicolons to avoid `;;` which is DoubleSemicolon
    var reader = std.io.Reader.fixed("; ; echo a ; ;");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    // Should yield exactly one command
    const cmd1 = try parser.next();
    try std.testing.expect(cmd1 != null);

    const cmd2 = try parser.next();
    try std.testing.expectEqual(null, cmd2);
}

test "next: returns Command union with simple variant" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("FOO=bar cmd arg");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.next();
    try std.testing.expect(cmd != null);

    // Verify it's a simple command with expected structure
    const simple = cmd.?.simple;
    try std.testing.expectEqual(@as(usize, 1), simple.assignments.len);
    try std.testing.expectEqual(@as(usize, 2), simple.argv.len);
}
