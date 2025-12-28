//! By convention, root.zig is the root source file when making a library.
//! This file implements a basic lexer for POSIX shell.
//!
//! The subset of POSIX that this file implements:
//!  - Simple commands
//!
//! Note that no expansions are supported yet, so that phase is skipped.
//!
//! ## Definitions
//!
//! ### Simple commands
//!
//! Simple commands are lines that have optional environment variable assignment and redirections.
//! For example:
//! ```sh
//! env=var command > test
//! 2>&1 env=var command
//! ```
//! These are valid "simple" commands.
const std = @import("std");

/// The type of redirection occurring.
pub const RedirectionOp = enum { In, Out, Append, Fd };

/// A redirection operation.
/// The target is not included - it is emitted as separate tokens following this one.
///
/// Note: Redirection tokens with complete=false do NOT set in_continuation,
/// because whitespace is allowed between the operator and target (e.g., "> file").
/// The complete flag tells the parser to collect following tokens as the target,
/// but doesn't affect lexer word-continuation behavior.
pub const Redirection = struct {
    /// The type of redirection occurring.
    operation: ?RedirectionOp = null,
    /// The file descriptor being redirected (e.g., "2" in "2>file").
    fd: ?[]const u8 = null,
};

/// The type of token returned by the lexer.
pub const TokenType = union(enum) {
    /// A literal word.
    Literal: []const u8,
    /// A redirection from a process to something else.
    Redirection: Redirection,
    /// A continuation of the previous token (if it was not completed).
    Continuation: []const u8,
    /// A complete single-quoted string. Content is literal (no expansions).
    SingleQuoted: []const u8,
    /// Marks the start of a double-quoted string.
    DoubleQuoteBegin,
    /// Marks the end of a double-quoted string.
    DoubleQuoteEnd,
};

/// The lexer's Token structure.
pub const Token = struct {
    /// The absolute position in the input stream where this token starts.
    position: usize,
    /// The absolute position in the input stream after the last byte of this token.
    end_position: usize,
    /// The line number where this token starts (1-indexed).
    line: usize,
    /// The column number where this token starts (1-indexed).
    column: usize,
    /// Whether the word boundary has been reached.
    /// When false, subsequent tokens are part of the same word.
    complete: bool,
    /// The type and payload of this token.
    type: TokenType,

    /// Format the token for human-readable output.
    pub fn format(self: Token, writer: *std.io.Writer) !void {
        try writer.print("[{d}:{d}] ", .{ self.line, self.column });
        switch (self.type) {
            .Literal => |lit| try writer.print("Literal(\"{s}\")", .{lit}),
            .Continuation => |cont| try writer.print("Continuation(\"{s}\")", .{cont}),
            .SingleQuoted => |s| try writer.print("SingleQuoted(\"{s}\")", .{s}),
            .DoubleQuoteBegin => try writer.writeAll("DoubleQuoteBegin"),
            .DoubleQuoteEnd => try writer.writeAll("DoubleQuoteEnd"),
            .Redirection => |r| {
                try writer.writeAll("Redirection(");
                if (r.fd) |fd| try writer.print("{s}", .{fd});
                if (r.operation) |op| {
                    switch (op) {
                        .In => try writer.writeByte('<'),
                        .Out => try writer.writeByte('>'),
                        .Append => try writer.writeAll(">>"),
                        .Fd => try writer.writeAll(">&"),
                    }
                }
                try writer.writeByte(')');
            },
        }
        if (!self.complete) try writer.writeAll(" [incomplete]");
    }
};

/// Errors that can occur during lexing.
pub const LexerError = error{
    UnexpectedEndOfFile,
    UnterminatedQuote,
};

/// The current parsing context of the lexer.
/// Tracks when we're inside constructs that span multiple tokens.
pub const ParseContext = enum {
    /// Normal parsing - not inside any special construct.
    none,
    /// Saw backslash outside quotes, waiting for next character.
    none_escape,
    /// Inside single quotes (no escape handling - everything is literal).
    single_quote,
    /// Inside double quotes.
    double_quote,
    /// Saw backslash inside double quotes, waiting for next character.
    double_quote_escape,
};

/// A lexer for POSIX shell syntax.
/// Reads from a stream and produces tokens.
/// Token slices are valid only until the next call to nextToken().
/// Note: Token length is limited by the reader's buffer size.
pub const Lexer = struct {
    /// Where we will read from.
    reader: *std.io.Reader,
    /// Our current position in the reader.
    position: usize,
    /// The current line number of the reader.
    line: usize,
    /// The current column number of the reader.
    column: usize,
    /// The location where the last token began.
    token_start_position: usize,
    token_start_line: usize,
    token_start_column: usize,
    /// Whether the previous token was incomplete and we're continuing it.
    in_continuation: bool,
    /// Current parsing context.
    parse_context: ParseContext,

    pub fn init(reader: *std.io.Reader) Lexer {
        return Lexer{
            .reader = reader,
            .position = 0,
            .line = 1,
            .column = 1,
            .token_start_position = 0,
            .token_start_line = 1,
            .token_start_column = 1,
            .in_continuation = false,
            .parse_context = .none,
        };
    }

    /// Peek at the next byte without consuming it. Returns null on EOF.
    inline fn peekByte(self: *Lexer) LexerError!?u8 {
        const buf = self.reader.peek(1) catch |err| switch (err) {
            error.EndOfStream => return null,
            else => return LexerError.UnexpectedEndOfFile,
        };
        if (buf.len == 0) return null;
        return buf[0];
    }

    /// Consume n bytes and update position tracking.
    inline fn consume(self: *Lexer, bytes: []const u8) void {
        for (bytes) |c| {
            self.position += 1;
            if (c == '\n') {
                self.line += 1;
                self.column = 1;
            } else {
                self.column += 1;
            }
        }
        self.reader.toss(bytes.len);
    }

    /// Consume a single byte and update position tracking.
    inline fn consumeOne(self: *Lexer) LexerError!?u8 {
        const buf = self.reader.peek(1) catch |err| switch (err) {
            error.EndOfStream => return null,
            else => return LexerError.UnexpectedEndOfFile,
        };
        if (buf.len == 0) return null;
        const c = buf[0];
        self.consume(buf[0..1]);
        return c;
    }

    /// Skip whitespace (spaces and tabs, not newlines).
    inline fn skipWhitespace(self: *Lexer) LexerError!void {
        while (try self.peekByte()) |c| {
            if (c == ' ' or c == '\t') {
                _ = try self.consumeOne();
            } else {
                break;
            }
        }
    }

    /// Check if a character is "plain" - can be included in a word chunk by `readWord`.
    ///
    /// This is different from `isWordComplete`: a character can be "not plain"
    /// (requiring special handling) while still continuing the same word.
    ///
    /// For example, backslash `\` returns false here because escapes need special
    /// processing, but the escaped character is still part of the same word.
    /// Quotes also return false because they start a new token type, but the
    /// quoted content is part of the same word.
    ///
    /// Characters that return false here and do NOT complete the word:
    /// - `\` (escape - continues word with escaped char)
    /// - `'` and `"` (quotes - continue word with quoted content)
    ///
    /// Characters that return false here and DO complete the word:
    /// - whitespace, newline (separate words)
    /// - `<`, `>`, `&`, `|`, `;` (metacharacters - separate tokens)
    fn isPlainCharacter(c: u8) bool {
        return switch (c) {
            ' ', '\t', '\n', '<', '>', '&', '|', ';', '\'', '"', '\\' => false,
            else => true,
        };
    }

    fn isDigit(c: u8) bool {
        return c >= '0' and c <= '9';
    }

    /// Check if a character completes the current word (ends it entirely).
    ///
    /// This is different from `isPlainCharacter`: a character can require special
    /// handling (not be "plain") while still being part of the same word.
    ///
    /// Used after emitting a token to set the `complete` flag, which tells the
    /// parser whether more tokens belong to this word.
    ///
    /// Returns true for characters that separate words (whitespace, metacharacters).
    /// Returns false for characters that continue the word with special handling
    /// (quotes, escapes) or regular content.
    fn isWordComplete(self: *Lexer, c: ?u8) bool {
        const char = c orelse return true; // EOF is always a boundary

        return switch (self.parse_context) {
            .none, .none_escape => switch (char) {
                // Whitespace and metacharacters end words
                // Quotes and backslash do NOT end words - they continue the word
                ' ', '\t', '\n', '<', '>', '|', ';', '&' => true,
                else => false,
            },
            .double_quote, .double_quote_escape => switch (char) {
                // Inside double quotes, these characters end the current literal segment
                // but " ends the quote context entirely
                '"', '$', '`', '\\' => true,
                else => false,
            },
            .single_quote => char == '\'',
        };
    }

    const ReadResult = struct {
        slice: []const u8,
        complete: bool,
    };

    /// Read bytes while they satisfy the predicate.
    /// Returns the content and whether we hit a boundary (complete) or buffer limit (incomplete).
    fn readWhile(self: *Lexer, comptime predicate: fn (u8) bool) LexerError!?ReadResult {
        const buf = self.reader.peekGreedy(1) catch |err| switch (err) {
            error.EndOfStream => return null,
            else => return LexerError.UnexpectedEndOfFile,
        };
        if (buf.len == 0) return null;

        var len: usize = 0;
        var found_boundary = false;
        for (buf) |c| {
            if (predicate(c)) {
                len += 1;
            } else {
                found_boundary = true;
                break;
            }
        }

        if (len == 0) return null;

        const content = buf[0..len];
        self.consume(content);

        // Complete if we found a non-matching char, or buffer has room (meaning we saw everything)
        const complete = found_boundary or (len < buf.len);
        return .{ .slice = content, .complete = complete };
    }

    /// Read bytes until we hit one of the stop characters.
    /// Returns the content before the stop char and whether we found a stop char (complete).
    /// The stop character is NOT consumed.
    fn readUntil(self: *Lexer, comptime stop_chars: []const u8) LexerError!?ReadResult {
        const buf = self.reader.peekGreedy(1) catch |err| switch (err) {
            error.EndOfStream => return null,
            else => return LexerError.UnexpectedEndOfFile,
        };
        if (buf.len == 0) return null;

        var len: usize = 0;
        var found_stop = false;
        for (buf) |c| {
            const is_stop = comptime_contains: {
                for (stop_chars) |stop| {
                    if (c == stop) break :comptime_contains true;
                }
                break :comptime_contains false;
            };
            if (is_stop) {
                found_stop = true;
                break;
            }
            len += 1;
        }

        if (len == 0) return null;

        const content = buf[0..len];
        self.consume(content);

        // Complete if we found a stop char
        const complete = found_stop or (len < buf.len);
        return .{ .slice = content, .complete = complete };
    }

    /// Read a word (sequence of plain characters).
    /// Returns a slice from the reader's buffer and whether the word is complete.
    /// A word is incomplete if it was truncated due to buffer limits.
    fn readWord(self: *Lexer) LexerError!?ReadResult {
        return self.readWhile(isPlainCharacter);
    }

    /// Read a sequence of digits. Returns a slice from the reader's buffer.
    /// A sequence is incomplete if it was truncated due to buffer limits.
    fn readDigits(self: *Lexer) LexerError!?ReadResult {
        return self.readWhile(isDigit);
    }

    /// Read the content of a single-quoted string (everything until closing ').
    /// The opening quote should already be consumed.
    /// Returns the content (without quotes) and whether it's complete.
    /// If complete, the closing quote is also consumed.
    /// Returns null on EOF (unterminated quote should be handled by caller).
    fn readSingleQuoted(self: *Lexer) LexerError!?ReadResult {
        // Check if we're immediately at a closing quote (empty string case)
        const first = try self.peekByte() orelse return null;
        if (first == '\'') {
            _ = try self.consumeOne();
            return .{ .slice = "", .complete = true };
        }

        // Read until closing quote
        const result = try self.readUntil("'") orelse return null;

        if (result.complete) {
            // Found closing quote - consume it
            _ = try self.consumeOne();
            return .{ .slice = result.slice, .complete = true };
        }

        // No closing quote found - check if this is EOF or buffer limit
        const more = self.reader.peek(1) catch |err| switch (err) {
            error.EndOfStream => {
                // EOF - return content as incomplete, next call will error
                return .{ .slice = result.slice, .complete = false };
            },
            else => return LexerError.UnexpectedEndOfFile,
        };

        if (more.len == 0) {
            return .{ .slice = result.slice, .complete = false };
        }

        // More data available - continuation
        return .{ .slice = result.slice, .complete = false };
    }

    /// Create a token from the current state.
    /// Also updates in_continuation flag based on whether the token is complete.
    inline fn makeToken(self: *Lexer, token_type: TokenType, complete: bool) Token {
        self.in_continuation = !complete;
        return Token{
            .position = self.token_start_position,
            .end_position = self.position,
            .line = self.token_start_line,
            .column = self.token_start_column,
            .complete = complete,
            .type = token_type,
        };
    }

    pub fn nextToken(self: *Lexer) LexerError!?Token {
        self.token_start_position = self.position;
        self.token_start_line = self.line;
        self.token_start_column = self.column;

        // Handle parse context first
        switch (self.parse_context) {
            .single_quote => {
                // Inside single quotes - we're continuing from a previous incomplete token
                // All tokens from here should be Continuation
                const result = try self.readSingleQuoted() orelse {
                    // EOF inside single quote
                    return LexerError.UnterminatedQuote;
                };
                if (result.complete) {
                    // Found closing quote - done with single-quoted string
                    self.parse_context = .none;
                    // Check if word continues after closing quote
                    const next = try self.peekByte();
                    const at_boundary = self.isWordComplete(next);
                    return self.makeToken(.{ .Continuation = result.slice }, at_boundary);
                } else {
                    // Buffer full, need more continuations
                    return self.makeToken(.{ .Continuation = result.slice }, false);
                }
            },
            .double_quote => {
                // Inside double quotes - read literal content until special char
                const first = try self.peekByte() orelse {
                    // EOF inside double quote
                    return LexerError.UnterminatedQuote;
                };

                switch (first) {
                    '"' => {
                        // End of double quote
                        _ = try self.consumeOne();
                        self.parse_context = .none;
                        // Check if word continues after closing quote
                        const next = try self.peekByte();
                        const at_boundary = self.isWordComplete(next);
                        return self.makeToken(.DoubleQuoteEnd, at_boundary);
                    },
                    '\\' => {
                        // Escape sequence - try to peek at both backslash and next char
                        const buf = self.reader.peekGreedy(2) catch |err| switch (err) {
                            error.EndOfStream => return LexerError.UnterminatedQuote,
                            else => return LexerError.UnexpectedEndOfFile,
                        };
                        if (buf.len < 2) {
                            // Buffer boundary - can't see next char yet.
                            // Consume backslash and transition to escape state.
                            self.consume(buf[0..1]);
                            self.parse_context = .double_quote_escape;
                            // Don't emit a token - next call will handle the escape
                            return self.nextToken();
                        }
                        // POSIX: only \$, \`, \", \\, and \newline are special in double quotes
                        // Other backslashes are literal (e.g., \n becomes \ and n)
                        const escaped_char = buf[1];
                        if (escaped_char == '$' or escaped_char == '`' or
                            escaped_char == '"' or escaped_char == '\\' or
                            escaped_char == '\n')
                        {
                            // Special escape - consume both, return the escaped char
                            const escaped_slice = buf[1..2];
                            self.consume(buf[0..2]);
                            return self.makeToken(.{ .Literal = escaped_slice }, false);
                        } else {
                            // Not a special escape - backslash is literal
                            // Consume just the backslash, next char handled in next iteration
                            self.consume(buf[0..1]);
                            return self.makeToken(.{ .Literal = buf[0..1] }, false);
                        }
                    },
                    '$', '`' => {
                        // Expansion - for now, treat as literal (TODO: Phase 4)
                        // Peek to get a slice, then consume
                        const buf = self.reader.peek(1) catch |err| switch (err) {
                            error.EndOfStream => return LexerError.UnterminatedQuote,
                            else => return LexerError.UnexpectedEndOfFile,
                        };
                        self.consume(buf);
                        // complete=false: still inside double quotes, more content follows
                        return self.makeToken(.{ .Literal = buf }, false);
                    },
                    else => {
                        // Regular literal content - read until special char
                        const result = try self.readUntil("\"$`\\") orelse {
                            return LexerError.UnterminatedQuote;
                        };
                        // complete=false: still inside double quotes
                        return self.makeToken(.{ .Literal = result.slice }, false);
                    },
                }
            },
            .double_quote_escape => {
                // We saw a backslash inside double quotes on the previous call.
                // The backslash was consumed but not emitted.
                // Now we can see the next character and determine the escape behavior.
                const next = try self.peekByte() orelse {
                    return LexerError.UnterminatedQuote;
                };

                // POSIX: only \$, \`, \", \\, and \newline are special in double quotes
                if (next == '$' or next == '`' or next == '"' or next == '\\' or next == '\n') {
                    // Special escape - consume and return the escaped char
                    const buf = self.reader.peek(1) catch |err| switch (err) {
                        error.EndOfStream => return LexerError.UnterminatedQuote,
                        else => return LexerError.UnexpectedEndOfFile,
                    };
                    self.consume(buf);
                    self.parse_context = .double_quote;
                    return self.makeToken(.{ .Literal = buf }, false);
                } else {
                    // Not a special escape - the backslash we consumed was literal.
                    // Emit a backslash literal using a static string slice.
                    self.parse_context = .double_quote;
                    return self.makeToken(.{ .Literal = "\\" }, false);
                }
            },
            .none_escape => {
                // We saw a backslash outside quotes on the previous call.
                // Backslash escapes the next character (makes it literal).
                const next = try self.peekByte() orelse {
                    // EOF after backslash outside quotes - backslash is discarded per POSIX
                    self.parse_context = .none;
                    return null;
                };

                if (next == '\n') {
                    // Line continuation - backslash-newline is removed entirely
                    _ = try self.consumeOne();
                    self.parse_context = .none;
                    // Continue processing on the next line
                    return self.nextToken();
                }

                // Consume the escaped character and return it as a literal
                const buf = self.reader.peek(1) catch |err| switch (err) {
                    error.EndOfStream => {
                        self.parse_context = .none;
                        return null;
                    },
                    else => return LexerError.UnexpectedEndOfFile,
                };
                self.consume(buf);
                self.parse_context = .none;
                // Check if word continues after this escaped char
                const after = try self.peekByte();
                const at_boundary = self.isWordComplete(after);
                return self.makeToken(.{ .Literal = buf }, at_boundary);
            },
            .none => {
                // Normal processing - continue below
            },
        }

        // If the previous token was incomplete, handle continuation
        if (self.in_continuation) {
            const next = try self.peekByte();

            // Check what follows the incomplete token
            if (next == null) {
                // EOF - word is complete
                self.in_continuation = false;
                return null;
            } else if (next == '\'' or next == '"' or next == '\\') {
                // Quote or escape follows - process it normally (word continues)
                // Don't emit a continuation, fall through to normal processing
                self.in_continuation = false;
            } else if (self.isWordComplete(next)) {
                // Whitespace or metachar - word is complete, emit empty continuation
                self.in_continuation = false;
                return self.makeToken(.{ .Continuation = "" }, true);
            } else {
                // Word char - read as continuation
                const result = try self.readWord() orelse {
                    self.in_continuation = false;
                    return null;
                };
                // Check if word continues after this
                const after = try self.peekByte();
                const at_boundary = self.isWordComplete(after);
                return self.makeToken(.{ .Continuation = result.slice }, at_boundary);
            }
        }

        try self.skipWhitespace();

        self.token_start_position = self.position;
        self.token_start_line = self.line;
        self.token_start_column = self.column;

        const first = try self.peekByte() orelse return null;

        // Handle newline - end of command
        if (first == '\n') {
            _ = try self.consumeOne();
            return null;
        }

        switch (first) {
            '\'' => {
                // Single quote - consume it and read content
                _ = try self.consumeOne();
                const result = try self.readSingleQuoted() orelse {
                    return LexerError.UnterminatedQuote;
                };
                if (result.complete) {
                    // Check if word continues after closing quote
                    const next = try self.peekByte();
                    const at_boundary = self.isWordComplete(next);
                    return self.makeToken(.{ .SingleQuoted = result.slice }, at_boundary);
                } else {
                    // Need continuation - first chunk is SingleQuoted with complete=false
                    self.parse_context = .single_quote;
                    self.in_continuation = true;
                    return self.makeToken(.{ .SingleQuoted = result.slice }, false);
                }
            },
            '"' => {
                // Double quote - consume it and enter double quote state
                _ = try self.consumeOne();
                self.parse_context = .double_quote;
                // DoubleQuoteBegin always has complete=false (content follows)
                return self.makeToken(.DoubleQuoteBegin, false);
            },
            '\\' => {
                // Escape - try to peek both backslash and next char
                const buf = self.reader.peekGreedy(2) catch |err| switch (err) {
                    error.EndOfStream => return null,
                    else => return LexerError.UnexpectedEndOfFile,
                };
                if (buf.len < 2) {
                    // Buffer boundary or EOF - transition to escape state
                    self.consume(buf[0..1]);
                    self.parse_context = .none_escape;
                    return self.nextToken();
                }

                const escaped_char = buf[1];
                if (escaped_char == '\n') {
                    // Line continuation - backslash-newline is removed entirely
                    self.consume(buf[0..2]);
                    // Continue to next line
                    return self.nextToken();
                }

                // Backslash escapes the next character (makes it literal)
                const escaped_slice = buf[1..2];
                self.consume(buf[0..2]);
                // Check if word continues after this escaped char
                const after = try self.peekByte();
                const at_boundary = self.isWordComplete(after);
                return self.makeToken(.{ .Literal = escaped_slice }, at_boundary);
            },
            '<' => {
                _ = try self.consumeOne();
                return try self.finishRedirection(null, .In);
            },
            '>' => {
                _ = try self.consumeOne();
                const next = try self.peekByte();
                if (next == '>') {
                    _ = try self.consumeOne();
                    return try self.finishRedirection(null, .Append);
                }
                return try self.finishRedirection(null, .Out);
            },
            '0'...'9' => {
                // Could be fd prefix for redirection, or a word starting with digits
                // Peek ahead to find the full extent of digits and check what follows
                const buf = self.reader.peekGreedy(1) catch |err| switch (err) {
                    error.EndOfStream => return null,
                    else => return LexerError.UnexpectedEndOfFile,
                };
                if (buf.len == 0) return null;

                // Find where digits end
                var digit_len: usize = 0;
                for (buf) |c| {
                    if (isDigit(c)) {
                        digit_len += 1;
                    } else {
                        break;
                    }
                }

                // Check what follows the digits
                const after_digits: u8 = if (digit_len < buf.len) buf[digit_len] else 0;

                if (after_digits == '<' or after_digits == '>') {
                    // It's an fd-prefixed redirection - keep fd as string slice
                    const fd_slice = buf[0..digit_len];
                    self.consume(fd_slice);
                    _ = try self.consumeOne(); // consume '<' or '>'

                    if (after_digits == '<') {
                        return try self.finishRedirection(fd_slice, .In);
                    } else {
                        const next2 = try self.peekByte();
                        if (next2 == '>') {
                            _ = try self.consumeOne();
                            return try self.finishRedirection(fd_slice, .Append);
                        }
                        return try self.finishRedirection(fd_slice, .Out);
                    }
                } else {
                    // It's a word (may continue with non-digit chars)
                    const result = try self.readWord() orelse return null;
                    // Check if word continues (e.g., followed by quote)
                    // Only peek if word wasn't truncated by buffer - otherwise slice would be invalidated
                    const at_boundary = if (result.complete)
                        self.isWordComplete(try self.peekByte())
                    else
                        false;
                    return self.makeToken(.{ .Literal = result.slice }, at_boundary);
                }
            },
            else => {
                if (!isPlainCharacter(first)) {
                    // Consume the unhandled character to avoid infinite loop
                    _ = try self.consumeOne();
                    return null;
                }
                const result = try self.readWord() orelse return null;
                // Check if word continues (e.g., followed by quote)
                // Only peek if word wasn't truncated by buffer - otherwise slice would be invalidated
                const at_boundary = if (result.complete)
                    self.isWordComplete(try self.peekByte())
                else
                    false;
                return self.makeToken(.{ .Literal = result.slice }, at_boundary);
            },
        }
    }

    /// Finish parsing a redirection operator and emit the token.
    ///
    /// Unlike other tokens, redirection tokens are created directly instead of using
    /// `makeToken`. This is intentional: redirection operators don't set `in_continuation`
    /// because whitespace is allowed between the operator and its target (e.g., `> file`).
    ///
    /// The target is always emitted as separate token(s) following the redirection.
    /// The `complete` flag is always `false` to indicate a target must follow.
    fn finishRedirection(self: *Lexer, fd_value: ?[]const u8, redir_op: RedirectionOp) LexerError!?Token {
        // Check for >&fd or <&fd (fd duplication)
        const next = try self.peekByte();
        const op = if (next == '&') blk: {
            _ = try self.consumeOne();
            break :blk RedirectionOp.Fd;
        } else redir_op;

        return Token{
            .position = self.token_start_position,
            .end_position = self.position,
            .line = self.token_start_line,
            .column = self.token_start_column,
            .complete = false,
            .type = .{ .Redirection = .{ .operation = op, .fd = fd_value } },
        };
    }
};

// --- Lexer tests ---

fn expectLiteral(token: ?Token, expected: []const u8) !void {
    const t = token orelse return error.ExpectedToken;
    switch (t.type) {
        .Literal => |lit| try std.testing.expectEqualStrings(expected, lit),
        else => return error.ExpectedLiteral,
    }
}

fn expectRedirection(token: ?Token, expected_op: RedirectionOp, expected_fd: ?[]const u8) !void {
    const t = token orelse return error.ExpectedToken;
    switch (t.type) {
        .Redirection => |r| {
            try std.testing.expectEqual(expected_op, r.operation.?);
            if (expected_fd) |efd| {
                try std.testing.expectEqualStrings(efd, r.fd.?);
            } else {
                try std.testing.expectEqual(@as(?[]const u8, null), r.fd);
            }
        },
        else => return error.ExpectedRedirection,
    }
    // Redirection tokens should always have complete=false (target follows)
    try std.testing.expectEqual(false, t.complete);
}

test "nextToken: simple literal" {
    var reader = std.io.Reader.fixed("hello");
    var lexer = Lexer.init(&reader);
    try expectLiteral(try lexer.nextToken(), "hello");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: multiple literals" {
    var reader = std.io.Reader.fixed("hello world foo");
    var lexer = Lexer.init(&reader);
    try expectLiteral(try lexer.nextToken(), "hello");
    try expectLiteral(try lexer.nextToken(), "world");
    try expectLiteral(try lexer.nextToken(), "foo");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: literal with leading/trailing whitespace" {
    var reader = std.io.Reader.fixed("   hello   ");
    var lexer = Lexer.init(&reader);
    try expectLiteral(try lexer.nextToken(), "hello");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: numeric literal" {
    var reader = std.io.Reader.fixed("123");
    var lexer = Lexer.init(&reader);
    try expectLiteral(try lexer.nextToken(), "123");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: numeric literal followed by space" {
    var reader = std.io.Reader.fixed("123 456");
    var lexer = Lexer.init(&reader);
    try expectLiteral(try lexer.nextToken(), "123");
    try expectLiteral(try lexer.nextToken(), "456");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: alphanumeric literal starting with digit" {
    var reader = std.io.Reader.fixed("123abc");
    var lexer = Lexer.init(&reader);
    try expectLiteral(try lexer.nextToken(), "123abc");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: word with equals sign" {
    var reader = std.io.Reader.fixed("FOO=bar");
    var lexer = Lexer.init(&reader);
    try expectLiteral(try lexer.nextToken(), "FOO=bar");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: word with equals sign followed by literal" {
    var reader = std.io.Reader.fixed("FOO=bar command");
    var lexer = Lexer.init(&reader);
    try expectLiteral(try lexer.nextToken(), "FOO=bar");
    try expectLiteral(try lexer.nextToken(), "command");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: output redirection" {
    var reader = std.io.Reader.fixed(">file");
    var lexer = Lexer.init(&reader);
    try expectRedirection(try lexer.nextToken(), .Out, null);
    try expectLiteral(try lexer.nextToken(), "file");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: output redirection with space" {
    var reader = std.io.Reader.fixed("> file");
    var lexer = Lexer.init(&reader);
    try expectRedirection(try lexer.nextToken(), .Out, null);
    try expectLiteral(try lexer.nextToken(), "file");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: input redirection" {
    var reader = std.io.Reader.fixed("<input");
    var lexer = Lexer.init(&reader);
    try expectRedirection(try lexer.nextToken(), .In, null);
    try expectLiteral(try lexer.nextToken(), "input");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: append redirection" {
    var reader = std.io.Reader.fixed(">>logfile");
    var lexer = Lexer.init(&reader);
    try expectRedirection(try lexer.nextToken(), .Append, null);
    try expectLiteral(try lexer.nextToken(), "logfile");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: fd-prefixed output redirection" {
    var reader = std.io.Reader.fixed("2>errors");
    var lexer = Lexer.init(&reader);
    try expectRedirection(try lexer.nextToken(), .Out, "2");
    try expectLiteral(try lexer.nextToken(), "errors");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: fd-prefixed append redirection" {
    var reader = std.io.Reader.fixed("2>>errors");
    var lexer = Lexer.init(&reader);
    try expectRedirection(try lexer.nextToken(), .Append, "2");
    try expectLiteral(try lexer.nextToken(), "errors");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: fd-prefixed input redirection" {
    var reader = std.io.Reader.fixed("0<input");
    var lexer = Lexer.init(&reader);
    try expectRedirection(try lexer.nextToken(), .In, "0");
    try expectLiteral(try lexer.nextToken(), "input");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: fd duplication 2>&1" {
    var reader = std.io.Reader.fixed("2>&1");
    var lexer = Lexer.init(&reader);
    try expectRedirection(try lexer.nextToken(), .Fd, "2");
    try expectLiteral(try lexer.nextToken(), "1");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: fd duplication >&2" {
    var reader = std.io.Reader.fixed(">&2");
    var lexer = Lexer.init(&reader);
    try expectRedirection(try lexer.nextToken(), .Fd, null);
    try expectLiteral(try lexer.nextToken(), "2");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: complex command line" {
    var reader = std.io.Reader.fixed("FOO=bar cmd arg1 arg2 >out 2>&1");
    var lexer = Lexer.init(&reader);
    try expectLiteral(try lexer.nextToken(), "FOO=bar");
    try expectLiteral(try lexer.nextToken(), "cmd");
    try expectLiteral(try lexer.nextToken(), "arg1");
    try expectLiteral(try lexer.nextToken(), "arg2");
    try expectRedirection(try lexer.nextToken(), .Out, null);
    try expectLiteral(try lexer.nextToken(), "out");
    try expectRedirection(try lexer.nextToken(), .Fd, "2");
    try expectLiteral(try lexer.nextToken(), "1");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: redirection at start" {
    var reader = std.io.Reader.fixed("2>&1 command");
    var lexer = Lexer.init(&reader);
    try expectRedirection(try lexer.nextToken(), .Fd, "2");
    try expectLiteral(try lexer.nextToken(), "1");
    try expectLiteral(try lexer.nextToken(), "command");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: empty input" {
    var reader = std.io.Reader.fixed("");
    var lexer = Lexer.init(&reader);
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: whitespace only" {
    var reader = std.io.Reader.fixed("   \t  ");
    var lexer = Lexer.init(&reader);
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: newline terminates" {
    var reader = std.io.Reader.fixed("hello\nworld");
    var lexer = Lexer.init(&reader);
    try expectLiteral(try lexer.nextToken(), "hello");
    try std.testing.expectEqual(null, try lexer.nextToken()); // newline
    try expectLiteral(try lexer.nextToken(), "world");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: single character literal" {
    var reader = std.io.Reader.fixed("a");
    var lexer = Lexer.init(&reader);
    try expectLiteral(try lexer.nextToken(), "a");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: single digit" {
    var reader = std.io.Reader.fixed("5");
    var lexer = Lexer.init(&reader);
    try expectLiteral(try lexer.nextToken(), "5");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: redirection at EOF emits incomplete token" {
    // Lexer emits Redirection token; parser validates target presence
    var reader = std.io.Reader.fixed(">");
    var lexer = Lexer.init(&reader);
    try expectRedirection(try lexer.nextToken(), .Out, null);
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: fd redirection at EOF emits incomplete token" {
    // Lexer emits Redirection token; parser validates target presence
    var reader = std.io.Reader.fixed(">&");
    var lexer = Lexer.init(&reader);
    try expectRedirection(try lexer.nextToken(), .Fd, null);
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: unhandled metacharacters are skipped" {
    // Characters like |, ;, & should be consumed and return null
    // This prevents infinite loops - each call makes progress
    var reader = std.io.Reader.fixed("| ; & cmd");
    var lexer = Lexer.init(&reader);
    // Each metacharacter returns null but is consumed
    try std.testing.expectEqual(null, try lexer.nextToken()); // |
    try std.testing.expectEqual(null, try lexer.nextToken()); // ;
    try std.testing.expectEqual(null, try lexer.nextToken()); // &
    // Finally we get the literal
    try expectLiteral(try lexer.nextToken(), "cmd");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: metacharacter at end of input" {
    // Ensure we don't infinite loop on metachar at end
    var reader = std.io.Reader.fixed("|");
    var lexer = Lexer.init(&reader);
    try std.testing.expectEqual(null, try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken()); // Should hit EOF, not loop
}

test "nextToken: token position tracking" {
    var reader = std.io.Reader.fixed("  hello world");
    var lexer = Lexer.init(&reader);

    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(@as(usize, 2), tok1.position);
    try std.testing.expectEqual(@as(usize, 1), tok1.line);
    try std.testing.expectEqual(@as(usize, 3), tok1.column);

    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(@as(usize, 8), tok2.position);
    try std.testing.expectEqual(@as(usize, 1), tok2.line);
    try std.testing.expectEqual(@as(usize, 9), tok2.column);
}

test "nextToken: line tracking across newlines" {
    var reader = std.io.Reader.fixed("hello\nworld");
    var lexer = Lexer.init(&reader);

    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(@as(usize, 1), tok1.line);

    _ = try lexer.nextToken(); // consume newline

    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(@as(usize, 2), tok2.line);
    try std.testing.expectEqual(@as(usize, 1), tok2.column);
}

test "nextToken: end_position tracking" {
    var reader = std.io.Reader.fixed("hello world");
    var lexer = Lexer.init(&reader);

    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(@as(usize, 0), tok1.position);
    try std.testing.expectEqual(@as(usize, 5), tok1.end_position); // "hello" is 5 chars

    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(@as(usize, 6), tok2.position); // after space
    try std.testing.expectEqual(@as(usize, 11), tok2.end_position); // "world" is 5 chars
}

test "nextToken: end_position for single-quoted string" {
    var reader = std.io.Reader.fixed("'hello'");
    var lexer = Lexer.init(&reader);

    const tok = (try lexer.nextToken()).?;
    try std.testing.expectEqual(@as(usize, 0), tok.position);
    try std.testing.expectEqual(@as(usize, 7), tok.end_position); // includes both quotes
}

test "nextToken: large fd numbers stored as strings" {
    // Test that extremely large fd numbers are stored as strings (caller validates)
    // >&99999999999999999999 -> Redirection(.Fd), Literal("99999999999999999999")
    var reader = std.io.Reader.fixed(">&99999999999999999999");
    var lexer = Lexer.init(&reader);
    try expectRedirection(try lexer.nextToken(), .Fd, null);
    try expectLiteral(try lexer.nextToken(), "99999999999999999999");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: incomplete token with small buffer" {
    // Test that tokens larger than the buffer are marked incomplete.
    // We use a pipe to create a streaming reader with a small buffer.
    const pipe = try std.posix.pipe();
    defer std.posix.close(pipe[0]);

    // Write test data "abcdefg " (7 chars + space) and close write end
    // The space ensures the continuation "efg" is complete
    _ = try std.posix.write(pipe[1], "abcdefg ");
    std.posix.close(pipe[1]);

    // Create a file reader with a 4-byte buffer
    const file = std.fs.File{ .handle = pipe[0] };
    var small_buf: [4]u8 = undefined;
    var file_reader = file.reader(&small_buf);
    var lexer = Lexer.init(&file_reader.interface);

    // First token should be incomplete (buffer full, no delimiter found)
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(false, tok1.complete);
    try std.testing.expectEqualStrings("abcd", tok1.type.Literal);

    // Second token should be a Continuation (continuing the incomplete token)
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(true, tok2.complete);
    try std.testing.expectEqualStrings("efg", tok2.type.Continuation);

    // No more tokens
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: escape at buffer boundary in double quotes - special escape" {
    // Test that backslash at buffer boundary inside double quotes is handled correctly.
    // Buffer size 3: can fit `"` + `\` but not the escaped char
    const pipe = try std.posix.pipe();
    defer std.posix.close(pipe[0]);

    // Write "\"" (escaped quote inside double quotes) followed by closing quote and space
    _ = try std.posix.write(pipe[1], "\"\\\"\" ");
    std.posix.close(pipe[1]);

    const file = std.fs.File{ .handle = pipe[0] };
    var small_buf: [3]u8 = undefined;
    var file_reader = file.reader(&small_buf);
    var lexer = Lexer.init(&file_reader.interface);

    // DoubleQuoteBegin
    try expectDoubleQuoteBegin(try lexer.nextToken());
    // The escape \\" should produce Literal("\"")
    // Even if the backslash is at buffer boundary, the escape state handles it
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("\"", tok2.type.Literal);
    // DoubleQuoteEnd
    try expectDoubleQuoteEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: escape at buffer boundary in double quotes - non-special escape" {
    // Test backslash followed by non-special char (e.g., \n) at buffer boundary.
    // Should produce Literal("\\") then the char is processed normally.
    const pipe = try std.posix.pipe();
    defer std.posix.close(pipe[0]);

    // Write "\n" (backslash-n, NOT a special escape) inside double quotes
    _ = try std.posix.write(pipe[1], "\"\\nx\" ");
    std.posix.close(pipe[1]);

    const file = std.fs.File{ .handle = pipe[0] };
    var small_buf: [3]u8 = undefined;
    var file_reader = file.reader(&small_buf);
    var lexer = Lexer.init(&file_reader.interface);

    try expectDoubleQuoteBegin(try lexer.nextToken());
    // Backslash is literal (not a special escape)
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("\\", tok2.type.Literal);
    // "nx" follows as literal content
    const tok3 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("n", tok3.type.Literal);
    const tok4 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("x", tok4.type.Literal);
    try expectDoubleQuoteEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: escape outside quotes" {
    // Test backslash escapes outside quotes with a normal-sized buffer.
    // The buffer boundary case is hard to test reliably due to reader constraints.
    var reader = std.io.Reader.fixed("\\$x ");
    var lexer = Lexer.init(&reader);

    // \$ produces Literal("$")
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("$", tok1.type.Literal);
    try std.testing.expectEqual(false, tok1.complete);
    // "x" continues the word
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("x", tok2.type.Continuation);
    try std.testing.expectEqual(true, tok2.complete);
    try std.testing.expectEqual(null, try lexer.nextToken());
}

// --- Quote tests ---

fn expectSingleQuoted(token: ?Token, expected: []const u8) !void {
    const t = token orelse return error.ExpectedToken;
    switch (t.type) {
        .SingleQuoted => |s| try std.testing.expectEqualStrings(expected, s),
        else => return error.ExpectedSingleQuoted,
    }
}

fn expectDoubleQuoteBegin(token: ?Token) !void {
    const t = token orelse return error.ExpectedToken;
    switch (t.type) {
        .DoubleQuoteBegin => {},
        else => return error.ExpectedDoubleQuoteBegin,
    }
}

fn expectDoubleQuoteEnd(token: ?Token) !void {
    const t = token orelse return error.ExpectedToken;
    switch (t.type) {
        .DoubleQuoteEnd => {},
        else => return error.ExpectedDoubleQuoteEnd,
    }
}

test "nextToken: simple single-quoted string" {
    var reader = std.io.Reader.fixed("'hello'");
    var lexer = Lexer.init(&reader);
    try expectSingleQuoted(try lexer.nextToken(), "hello");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: single-quoted string with spaces" {
    var reader = std.io.Reader.fixed("'hello world'");
    var lexer = Lexer.init(&reader);
    try expectSingleQuoted(try lexer.nextToken(), "hello world");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: single-quoted string preserves special chars" {
    var reader = std.io.Reader.fixed("'$var > file'");
    var lexer = Lexer.init(&reader);
    try expectSingleQuoted(try lexer.nextToken(), "$var > file");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: empty single-quoted string" {
    var reader = std.io.Reader.fixed("''");
    var lexer = Lexer.init(&reader);
    try expectSingleQuoted(try lexer.nextToken(), "");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: simple double-quoted string" {
    var reader = std.io.Reader.fixed("\"hello\"");
    var lexer = Lexer.init(&reader);
    try expectDoubleQuoteBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "hello");
    try expectDoubleQuoteEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: double-quoted string with spaces" {
    var reader = std.io.Reader.fixed("\"hello world\"");
    var lexer = Lexer.init(&reader);
    try expectDoubleQuoteBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "hello world");
    try expectDoubleQuoteEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: empty double-quoted string" {
    var reader = std.io.Reader.fixed("\"\"");
    var lexer = Lexer.init(&reader);
    try expectDoubleQuoteBegin(try lexer.nextToken());
    try expectDoubleQuoteEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: double-quoted string with escaped quote" {
    var reader = std.io.Reader.fixed("\"say \\\"hi\\\"\"");
    var lexer = Lexer.init(&reader);
    try expectDoubleQuoteBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "say ");
    try expectLiteral(try lexer.nextToken(), "\""); // escaped quote
    try expectLiteral(try lexer.nextToken(), "hi");
    try expectLiteral(try lexer.nextToken(), "\""); // escaped quote
    try expectDoubleQuoteEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: double-quoted string with dollar sign" {
    // $ is preserved as literal for now (expansions in Phase 4)
    var reader = std.io.Reader.fixed("\"$var\"");
    var lexer = Lexer.init(&reader);
    try expectDoubleQuoteBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "$");
    try expectLiteral(try lexer.nextToken(), "var");
    try expectDoubleQuoteEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: POSIX escape - backslash-n is literal" {
    // \n inside double quotes is NOT a special escape - backslash and n are separate
    var reader = std.io.Reader.fixed("\"\\n\"");
    var lexer = Lexer.init(&reader);
    try expectDoubleQuoteBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "\\"); // backslash is literal
    try expectLiteral(try lexer.nextToken(), "n"); // n is literal
    try expectDoubleQuoteEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: POSIX escape - backslash-backslash" {
    // \\ is a special escape - produces single backslash
    var reader = std.io.Reader.fixed("\"\\\\\"");
    var lexer = Lexer.init(&reader);
    try expectDoubleQuoteBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "\\"); // escaped backslash
    try expectDoubleQuoteEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: POSIX escape - backslash-quote" {
    // \" is a special escape - produces literal quote
    var reader = std.io.Reader.fixed("\"\\\"\"");
    var lexer = Lexer.init(&reader);
    try expectDoubleQuoteBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "\""); // escaped quote
    try expectDoubleQuoteEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: POSIX escape - backslash-dollar" {
    // \$ is a special escape - produces literal $
    var reader = std.io.Reader.fixed("\"\\$\"");
    var lexer = Lexer.init(&reader);
    try expectDoubleQuoteBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "$"); // escaped dollar
    try expectDoubleQuoteEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

// --- Unquoted escape tests ---

test "nextToken: unquoted escape - backslash escapes next char" {
    // \$ outside quotes produces literal $
    var reader = std.io.Reader.fixed("\\$HOME ");
    var lexer = Lexer.init(&reader);
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("$", tok1.type.Literal);
    try std.testing.expectEqual(false, tok1.complete); // more word follows
    // "HOME" is a continuation of the word started by the escape
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("HOME", tok2.type.Continuation);
    try std.testing.expectEqual(true, tok2.complete);
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: unquoted escape - backslash-quote" {
    // \" outside quotes produces literal "
    // say\"hi\" is one word: say + " + hi + "
    var reader = std.io.Reader.fixed("say\\\"hi\\\" ");
    var lexer = Lexer.init(&reader);
    // "say" stops at backslash
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("say", tok1.type.Literal);
    try std.testing.expectEqual(false, tok1.complete); // backslash follows
    // \" produces literal "
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("\"", tok2.type.Literal);
    try std.testing.expectEqual(false, tok2.complete); // more follows
    // "hi" is a continuation
    const tok3 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("hi", tok3.type.Continuation);
    try std.testing.expectEqual(false, tok3.complete); // backslash follows
    // \" produces literal "
    const tok4 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("\"", tok4.type.Literal);
    try std.testing.expectEqual(true, tok4.complete); // space follows
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: unquoted escape - backslash-backslash" {
    // \\ outside quotes produces literal \
    var reader = std.io.Reader.fixed("\\\\");
    var lexer = Lexer.init(&reader);
    try expectLiteral(try lexer.nextToken(), "\\");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: unquoted escape - backslash-newline is line continuation" {
    // \<newline> is removed entirely, continues to next line
    var reader = std.io.Reader.fixed("echo \\\nhello");
    var lexer = Lexer.init(&reader);
    try expectLiteral(try lexer.nextToken(), "echo");
    // The \<newline> is consumed silently, then "hello" is read
    try expectLiteral(try lexer.nextToken(), "hello");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: unquoted escape - trailing backslash at EOF" {
    // Per POSIX, a trailing backslash at EOF is discarded
    var reader = std.io.Reader.fixed("hello\\");
    var lexer = Lexer.init(&reader);
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("hello", tok1.type.Literal);
    try std.testing.expectEqual(false, tok1.complete); // backslash follows
    // Backslash at EOF is discarded, returns null (end of input)
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: unquoted escape - backslash-space" {
    // \<space> produces literal space (escaped space, part of word)
    // "hello\ world" is ONE word: hello + <space> + world
    var reader = std.io.Reader.fixed("hello\\ world ");
    var lexer = Lexer.init(&reader);
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("hello", tok1.type.Literal);
    try std.testing.expectEqual(false, tok1.complete); // backslash follows
    // Space is escaped, continues the word
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings(" ", tok2.type.Literal);
    try std.testing.expectEqual(false, tok2.complete); // word continues
    // "world" is a continuation of the same word
    const tok3 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("world", tok3.type.Continuation);
    try std.testing.expectEqual(true, tok3.complete); // trailing space
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: escape in middle of word" {
    // foo\$bar is one word: foo + $ + bar
    var reader = std.io.Reader.fixed("foo\\$bar ");
    var lexer = Lexer.init(&reader);
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("foo", tok1.type.Literal);
    try std.testing.expectEqual(false, tok1.complete); // backslash follows
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("$", tok2.type.Literal);
    try std.testing.expectEqual(false, tok2.complete); // more word follows
    // "bar" is a continuation
    const tok3 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("bar", tok3.type.Continuation);
    try std.testing.expectEqual(true, tok3.complete); // trailing space
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: unterminated single quote" {
    var reader = std.io.Reader.fixed("'hello");
    var lexer = Lexer.init(&reader);
    // First call returns partial content as incomplete
    const tok = (try lexer.nextToken()).?;
    try std.testing.expectEqual(false, tok.complete);
    try std.testing.expectEqualStrings("hello", tok.type.SingleQuoted);
    // Second call hits EOF in quote state -> error
    try std.testing.expectError(LexerError.UnterminatedQuote, lexer.nextToken());
}

test "nextToken: unterminated double quote" {
    var reader = std.io.Reader.fixed("\"hello");
    var lexer = Lexer.init(&reader);
    try expectDoubleQuoteBegin(try lexer.nextToken());
    // Content is returned, then EOF in quote state -> error
    const tok = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("hello", tok.type.Literal);
    try std.testing.expectError(LexerError.UnterminatedQuote, lexer.nextToken());
}

test "nextToken: single-quoted followed by literal" {
    var reader = std.io.Reader.fixed("'hello' world");
    var lexer = Lexer.init(&reader);
    try expectSingleQuoted(try lexer.nextToken(), "hello");
    try expectLiteral(try lexer.nextToken(), "world");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: literal followed by single-quoted" {
    var reader = std.io.Reader.fixed("echo 'hello'");
    var lexer = Lexer.init(&reader);
    try expectLiteral(try lexer.nextToken(), "echo");
    try expectSingleQuoted(try lexer.nextToken(), "hello");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: adjacent single-quoted strings form one word" {
    var reader = std.io.Reader.fixed("'abc''def'");
    var lexer = Lexer.init(&reader);
    // First single-quoted string - complete=false because another quote follows
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("abc", tok1.type.SingleQuoted);
    try std.testing.expectEqual(false, tok1.complete);
    // Second single-quoted string - complete=true because EOF follows
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("def", tok2.type.SingleQuoted);
    try std.testing.expectEqual(true, tok2.complete);
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: single-quoted followed by double-quoted" {
    var reader = std.io.Reader.fixed("'abc'\"def\"");
    var lexer = Lexer.init(&reader);
    // Single-quoted - complete=false because double quote follows
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("abc", tok1.type.SingleQuoted);
    try std.testing.expectEqual(false, tok1.complete);
    // Double-quoted section - all complete=false until end
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(TokenType.DoubleQuoteBegin, tok2.type);
    try std.testing.expectEqual(false, tok2.complete);
    try expectLiteral(try lexer.nextToken(), "def");
    // DoubleQuoteEnd - complete=true because EOF follows
    const tok4 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(TokenType.DoubleQuoteEnd, tok4.type);
    try std.testing.expectEqual(true, tok4.complete);
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: double-quoted followed by single-quoted" {
    var reader = std.io.Reader.fixed("\"abc\"'def'");
    var lexer = Lexer.init(&reader);
    // DoubleQuoteBegin - complete=false
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(TokenType.DoubleQuoteBegin, tok1.type);
    try std.testing.expectEqual(false, tok1.complete);
    // Literal inside - complete=false (more tokens in this word)
    try expectLiteral(try lexer.nextToken(), "abc");
    // DoubleQuoteEnd - complete=false because single quote follows
    const tok3 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(TokenType.DoubleQuoteEnd, tok3.type);
    try std.testing.expectEqual(false, tok3.complete);
    // SingleQuoted - complete=true because EOF follows
    const tok4 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("def", tok4.type.SingleQuoted);
    try std.testing.expectEqual(true, tok4.complete);
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: double-quoted with space after" {
    var reader = std.io.Reader.fixed("\"abc\" def");
    var lexer = Lexer.init(&reader);
    // DoubleQuoteBegin - complete=false
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(TokenType.DoubleQuoteBegin, tok1.type);
    try std.testing.expectEqual(false, tok1.complete);
    try expectLiteral(try lexer.nextToken(), "abc");
    // DoubleQuoteEnd - complete=true because space follows (word boundary)
    const tok3 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(TokenType.DoubleQuoteEnd, tok3.type);
    try std.testing.expectEqual(true, tok3.complete);
    // Next word
    try expectLiteral(try lexer.nextToken(), "def");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: literal followed by single-quote (adjacent)" {
    var reader = std.io.Reader.fixed("abc'def'");
    var lexer = Lexer.init(&reader);
    // Literal - complete=false because quote follows
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("abc", tok1.type.Literal);
    try std.testing.expectEqual(false, tok1.complete);
    // SingleQuoted - complete=true because EOF follows
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("def", tok2.type.SingleQuoted);
    try std.testing.expectEqual(true, tok2.complete);
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: literal followed by double-quote (adjacent)" {
    var reader = std.io.Reader.fixed("abc\"def\"");
    var lexer = Lexer.init(&reader);
    // Literal - complete=false because quote follows
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("abc", tok1.type.Literal);
    try std.testing.expectEqual(false, tok1.complete);
    // DoubleQuoteBegin
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(TokenType.DoubleQuoteBegin, tok2.type);
    try std.testing.expectEqual(false, tok2.complete);
    try expectLiteral(try lexer.nextToken(), "def");
    // DoubleQuoteEnd - complete=true because EOF
    const tok4 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(TokenType.DoubleQuoteEnd, tok4.type);
    try std.testing.expectEqual(true, tok4.complete);
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: mixed literal and quotes" {
    // abc'def'ghi"jkl" - all one word
    var reader = std.io.Reader.fixed("abc'def'ghi\"jkl\"");
    var lexer = Lexer.init(&reader);
    // abc - complete=false (quote follows)
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("abc", tok1.type.Literal);
    try std.testing.expectEqual(false, tok1.complete);
    // 'def' - complete=false (more follows)
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("def", tok2.type.SingleQuoted);
    try std.testing.expectEqual(false, tok2.complete);
    // ghi - this is a Continuation because previous token was incomplete
    const tok3 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("ghi", tok3.type.Continuation);
    try std.testing.expectEqual(false, tok3.complete); // quote follows
    // "jkl" section
    try expectDoubleQuoteBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "jkl");
    const tok6 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(TokenType.DoubleQuoteEnd, tok6.type);
    try std.testing.expectEqual(true, tok6.complete); // EOF follows
    try std.testing.expectEqual(null, try lexer.nextToken());
}

// --- Quoted redirection target tests ---

test "nextToken: redirection with double-quoted target" {
    var reader = std.io.Reader.fixed(">\"file\"");
    var lexer = Lexer.init(&reader);
    try expectRedirection(try lexer.nextToken(), .Out, null);
    // Then the quoted target tokens
    try expectDoubleQuoteBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "file");
    try expectDoubleQuoteEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: redirection with single-quoted target" {
    var reader = std.io.Reader.fixed(">'file'");
    var lexer = Lexer.init(&reader);
    try expectRedirection(try lexer.nextToken(), .Out, null);
    // Then the single-quoted target
    try expectSingleQuoted(try lexer.nextToken(), "file");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: redirection with fd and double-quoted target" {
    var reader = std.io.Reader.fixed("2>\"errors\"");
    var lexer = Lexer.init(&reader);
    try expectRedirection(try lexer.nextToken(), .Out, "2");
    try expectDoubleQuoteBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "errors");
    try expectDoubleQuoteEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: redirection with mixed target (word then quote)" {
    // >name"suffix" - redirection followed by unquoted + quoted parts
    var reader = std.io.Reader.fixed(">name\"suffix\"");
    var lexer = Lexer.init(&reader);
    try expectRedirection(try lexer.nextToken(), .Out, null);
    // "name" as literal (incomplete because quote follows)
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("name", tok2.type.Literal);
    try std.testing.expectEqual(false, tok2.complete);
    // Then the quoted suffix
    try expectDoubleQuoteBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "suffix");
    try expectDoubleQuoteEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: redirection with space before quoted target" {
    var reader = std.io.Reader.fixed("> \"file\"");
    var lexer = Lexer.init(&reader);
    try expectRedirection(try lexer.nextToken(), .Out, null);
    try expectDoubleQuoteBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "file");
    try expectDoubleQuoteEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

// --- Fuzz tests ---

fn fuzzRandomBytes(_: void, input: []const u8) anyerror!void {
    var reader = std.io.Reader.fixed(input);
    var lexer = Lexer.init(&reader);

    // Consume all tokens until end of input or error
    var iterations: usize = 0;
    const max_iterations = input.len + 100; // Reasonable upper bound

    while (iterations < max_iterations) : (iterations += 1) {
        const token = lexer.nextToken() catch |err| {
            // Errors are acceptable, panics are not
            switch (err) {
                LexerError.UnexpectedEndOfFile,
                LexerError.UnterminatedQuote,
                => break,
            }
        };
        if (token == null) {
            // null means end of command (newline) or end of input
            // Check if we're at end of input by checking if reader buffer is empty
            if (reader.bufferedLen() == 0) break;
            // Otherwise continue (was a newline)
            continue;
        }
        // Token was returned successfully - validate it makes sense
        switch (token.?.type) {
            .Literal => |lit| {
                // Literal should not be empty
                if (lit.len == 0) return error.EmptyLiteral;
            },
            .Continuation => {
                // Continuation can be empty (signals end of incomplete token)
            },
            .Redirection => {},
            .SingleQuoted => {},
            .DoubleQuoteBegin => {},
            .DoubleQuoteEnd => {},
        }
    }
}

test "fuzz: random bytes don't panic" {
    // Simple fuzz test: feed random bytes to the lexer
    // The lexer should never panic - only return valid tokens or errors
    try std.testing.fuzz({}, fuzzRandomBytes, .{});
}

fn fuzzStructuredInput(_: void, input: []const u8) anyerror!void {
    // Use input bytes to construct shell-like commands
    var buffer: [1024]u8 = undefined;
    var len: usize = 0;

    for (input) |byte| {
        if (len >= buffer.len - 10) break;

        // Use byte to decide what to append
        switch (byte % 16) {
            0 => {
                // Word
                const word = "cmd";
                @memcpy(buffer[len..][0..word.len], word);
                len += word.len;
            },
            1 => {
                // Space
                buffer[len] = ' ';
                len += 1;
            },
            2 => {
                // Newline
                buffer[len] = '\n';
                len += 1;
            },
            3 => {
                // Output redirect
                const redir = ">file";
                @memcpy(buffer[len..][0..redir.len], redir);
                len += redir.len;
            },
            4 => {
                // Input redirect
                const redir = "<input";
                @memcpy(buffer[len..][0..redir.len], redir);
                len += redir.len;
            },
            5 => {
                // Append redirect
                const redir = ">>log";
                @memcpy(buffer[len..][0..redir.len], redir);
                len += redir.len;
            },
            6 => {
                // Fd redirect
                const redir = "2>&1";
                @memcpy(buffer[len..][0..redir.len], redir);
                len += redir.len;
            },
            7 => {
                // Assignment-like
                const assign = "FOO=bar";
                @memcpy(buffer[len..][0..assign.len], assign);
                len += assign.len;
            },
            8 => {
                // Numeric
                const num = "123";
                @memcpy(buffer[len..][0..num.len], num);
                len += num.len;
            },
            9 => {
                // Tab
                buffer[len] = '\t';
                len += 1;
            },
            10 => {
                // Pipe (not yet supported, but shouldn't crash)
                buffer[len] = '|';
                len += 1;
            },
            11 => {
                // Semicolon
                buffer[len] = ';';
                len += 1;
            },
            12 => {
                // Ampersand
                buffer[len] = '&';
                len += 1;
            },
            13 => {
                // Random printable char
                buffer[len] = (byte % 95) + 32; // ASCII 32-126
                len += 1;
            },
            14 => {
                // Equals sign
                buffer[len] = '=';
                len += 1;
            },
            else => {
                // Raw byte (potentially invalid)
                buffer[len] = byte;
                len += 1;
            },
        }
    }

    // Now lex the constructed input
    var reader = std.io.Reader.fixed(buffer[0..len]);
    var lexer = Lexer.init(&reader);

    var iterations: usize = 0;
    const max_iterations = len + 100;

    while (iterations < max_iterations) : (iterations += 1) {
        const token = lexer.nextToken() catch {
            // Any error is acceptable
            break;
        };
        if (token == null) {
            if (reader.bufferedLen() == 0) break;
            continue;
        }
    }
}

test "fuzz: structured shell-like input" {
    // Structured fuzz: generate semi-valid shell-like input
    // This is more likely to exercise meaningful code paths
    try std.testing.fuzz({}, fuzzStructuredInput, .{});
}
