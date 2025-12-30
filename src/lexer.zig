//! This file implements a basic lexer for POSIX shell.
//!
//! The subset of POSIX that this file implements:
//!  - Simple commands
//!
//! Parameter expansion is supported at the lexer level (tokenization only).
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

/// A redirection operation.
///
/// The target (filename or fd number) is always emitted as separate token(s) following
/// the redirection token. The parser collects these tokens to form the complete target.
///
/// For file redirections (In, Out, Append): target is a filename.
/// For fd duplication (Fd): target is a digit string (fd number) or "-" (close).
///   The parser validates that the target is valid for fd duplication.
///
/// Note: Redirection tokens always have complete=false because a target must follow.
/// Whitespace is allowed between the operator and target (e.g., "> file", ">& 1").
///
/// Source fd handling: The source fd (e.g., "2" in "2>file") is NOT stored in
/// this token. Instead, it is emitted as a separate Literal token with
/// complete=false immediately before the Redirection token. The parser is
/// responsible for checking if a preceding incomplete literal is a valid fd.
pub const Redirection = enum { In, Out, Append, Fd };

/// Modifier operations for parameter expansion inside ${...}.
pub const ModifierOp = enum {
    /// ${#param} - string length
    Length,
    /// ${param:-word} or ${param-word} - use default value
    UseDefault,
    /// ${param:=word} or ${param=word} - assign default value
    AssignDefault,
    /// ${param:?word} or ${param?word} - error if unset/null
    ErrorIfUnset,
    /// ${param:+word} or ${param+word} - use alternative value
    UseAlternative,
    /// ${param#pattern} - remove smallest prefix
    RemoveSmallestPrefix,
    /// ${param##pattern} - remove largest prefix
    RemoveLargestPrefix,
    /// ${param%pattern} - remove smallest suffix
    RemoveSmallestSuffix,
    /// ${param%%pattern} - remove largest suffix
    RemoveLargestSuffix,
};

/// The type of token returned by the lexer.
pub const TokenType = union(enum) {
    /// A literal word.
    Literal: []const u8,
    /// An escaped literal (from backslash escape). Content should not undergo
    /// tilde expansion or globbing. Currently always a single character, but
    /// consumers should not assume length to allow for future extensions
    /// (e.g., multi-byte escape sequences).
    EscapedLiteral: []const u8,
    /// A redirection operator. The payload indicates the type of redirection.
    Redirection: Redirection,
    /// A continuation of the previous token (if it was not completed).
    Continuation: []const u8,
    /// A complete single-quoted string. Content is literal (no expansions).
    SingleQuoted: []const u8,
    /// Marks the start of a double-quoted string.
    DoubleQuoteBegin,
    /// Marks the end of a double-quoted string.
    DoubleQuoteEnd,
    /// Left parenthesis - used for subshells, case patterns, function definitions.
    /// TODO: When implementing arithmetic expansion, `((` needs special handling
    /// to parse `$((...))` as arithmetic rather than nested command substitution.
    LeftParen,
    /// Right parenthesis - closes subshells, case patterns, function definitions.
    /// TODO: When implementing arithmetic expansion, `))` needs special handling
    /// to close `$((...))` arithmetic expressions.
    RightParen,
    /// Command separator - `;` or newline. Separates commands in a command list.
    Separator,
    /// Double semicolon `;;` - terminates a case clause in case/esac statements.
    DoubleSemicolon,
    /// Simple parameter expansion: $VAR, $1, $?, etc.
    /// Contains the name/symbol (no $ prefix).
    SimpleExpansion: []const u8,
    /// Start of braced expansion: ${
    BraceExpansionBegin,
    /// End of braced expansion: }
    BraceExpansionEnd,
    /// Modifier operator inside ${...}
    Modifier: struct {
        op: ModifierOp,
        /// True if colon present (:-) vs absent (-)
        check_null: bool,
    },
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
    /// The line number where this token ends (1-indexed).
    end_line: usize,
    /// The column number after the last character of this token (1-indexed).
    end_column: usize,
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
            .EscapedLiteral => |esc| try writer.print("EscapedLiteral(\"{s}\")", .{esc}),
            .Continuation => |cont| try writer.print("Continuation(\"{s}\")", .{cont}),
            .SingleQuoted => |s| try writer.print("SingleQuoted(\"{s}\")", .{s}),
            .DoubleQuoteBegin => try writer.writeAll("DoubleQuoteBegin"),
            .DoubleQuoteEnd => try writer.writeAll("DoubleQuoteEnd"),
            .Redirection => |r| {
                try writer.writeAll("Redirection(");
                switch (r) {
                    .In => try writer.writeByte('<'),
                    .Out => try writer.writeByte('>'),
                    .Append => try writer.writeAll(">>"),
                    .Fd => try writer.writeAll(">&"),
                }
                try writer.writeByte(')');
            },
            .LeftParen => try writer.writeAll("LeftParen"),
            .RightParen => try writer.writeAll("RightParen"),
            .Separator => try writer.writeAll("Separator"),
            .DoubleSemicolon => try writer.writeAll("DoubleSemicolon"),
            .SimpleExpansion => |name| try writer.print("SimpleExpansion(\"{s}\")", .{name}),
            .BraceExpansionBegin => try writer.writeAll("BraceExpansionBegin"),
            .BraceExpansionEnd => try writer.writeAll("BraceExpansionEnd"),
            .Modifier => |m| {
                try writer.writeAll("Modifier(");
                switch (m.op) {
                    .Length => try writer.writeAll("#"),
                    .UseDefault => try writer.writeAll(if (m.check_null) ":-" else "-"),
                    .AssignDefault => try writer.writeAll(if (m.check_null) ":=" else "="),
                    .ErrorIfUnset => try writer.writeAll(if (m.check_null) ":?" else "?"),
                    .UseAlternative => try writer.writeAll(if (m.check_null) ":+" else "+"),
                    .RemoveSmallestPrefix => try writer.writeAll("#"),
                    .RemoveLargestPrefix => try writer.writeAll("##"),
                    .RemoveSmallestSuffix => try writer.writeAll("%"),
                    .RemoveLargestSuffix => try writer.writeAll("%%"),
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
    /// Exceeded maximum nesting depth for ${...}, quotes, etc.
    NestingTooDeep,
    /// Hit EOF while inside ${...}
    UnterminatedBraceExpansion,
    /// Invalid modifier after : (e.g., ${var:} or ${var:x})
    InvalidModifier,
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
    /// Saw $ - determining expansion type.
    dollar,
    /// Reading simple expansion name after $ (buffer boundary case).
    simple_expansion,
    /// Just entered ${...}, first char has special handling for #.
    brace_expansion_start,
    /// Saw ${# - need next char to disambiguate length op vs param #.
    brace_hash_ambiguous,
    /// Saw ${## - need next char to disambiguate ${##} (length of #) vs ${###...} (# with ## modifier).
    brace_hash_double_ambiguous,
    /// After emitting Literal "#" for ${###...}, need to emit the ## modifier.
    brace_emit_double_hash_modifier,
    /// After length modifier, reading parameter name.
    brace_expansion_after_length,
    /// Inside ${...}, after param name - checking for modifiers.
    brace_expansion,
    /// Inside ${...}, after modifier - reading word/pattern content.
    /// Only }, $, \, and quotes are special here (not :, #, %, -, etc.)
    brace_expansion_word,
    /// Saw : in modifier position, waiting for -, =, ?, +.
    brace_expansion_colon,
    /// Saw # in modifier position, need to check for ##.
    brace_expansion_hash,
    /// Saw % in modifier position, need to check for %%.
    brace_expansion_percent,
    /// Saw \ inside ${...}.
    brace_expansion_escape,
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
    /// Context stack for nested constructs (${...}, quotes, etc.).
    context_stack: [32]ParseContext = undefined,
    /// Current depth in the context stack.
    context_depth: u8 = 0,

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

    /// Push the current context onto the stack and switch to a new context.
    fn pushContext(self: *Lexer, ctx: ParseContext) LexerError!void {
        if (self.context_depth >= self.context_stack.len) return LexerError.NestingTooDeep;
        self.context_stack[self.context_depth] = self.parse_context;
        self.context_depth += 1;
        self.parse_context = ctx;
    }

    /// Pop the context stack and restore the previous context.
    fn popContext(self: *Lexer) void {
        if (self.context_depth > 0) {
            self.context_depth -= 1;
            self.parse_context = self.context_stack[self.context_depth];
        } else {
            self.parse_context = .none;
        }
    }

    /// Valid first char for parameter name: [A-Za-z_]
    fn isParamStartChar(c: u8) bool {
        return std.ascii.isAlphabetic(c) or c == '_';
    }

    /// Valid char in parameter name: [A-Za-z0-9_]
    fn isParamChar(c: u8) bool {
        return std.ascii.isAlphanumeric(c) or c == '_';
    }

    /// Special single-char parameters: @, *, #, ?, -, $, !, 0-9
    fn isSpecialParam(c: u8) bool {
        return switch (c) {
            '@', '*', '#', '?', '-', '$', '!' => true,
            '0'...'9' => true,
            else => false,
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
    /// - `$` (parameter expansion - continues word with expansion)
    ///
    /// Characters that return false here and DO complete the word:
    /// - whitespace, newline (separate words)
    /// - `<`, `>`, `&`, `|`, `;` (metacharacters - separate tokens)
    fn isPlainCharacter(c: u8) bool {
        return switch (c) {
            ' ', '\t', '\n', '<', '>', '&', '|', ';', '(', ')', '\'', '"', '\\', '$' => false,
            else => true,
        };
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
    ///
    /// Note: `<` and `>` return false because words immediately preceding a
    /// redirection operator may be source fd prefixes (e.g., "2" in "2>file").
    /// The parser is responsible for determining if the preceding word is a
    /// valid fd number or should be treated as a regular argument.
    fn isWordComplete(self: *Lexer, c: ?u8) bool {
        const char = c orelse return true; // EOF is always a boundary

        return switch (self.parse_context) {
            .none, .none_escape, .dollar, .simple_expansion => switch (char) {
                // Whitespace and metacharacters end words
                // Quotes and backslash do NOT end words - they continue the word
                // Note: < and > do NOT end words - see comment above
                ' ', '\t', '\n', '|', ';', '&', '(', ')' => true,
                else => false,
            },
            .double_quote, .double_quote_escape => switch (char) {
                // Inside double quotes, these characters end the current literal segment
                // but " ends the quote context entirely
                '"', '$', '`', '\\' => true,
                else => false,
            },
            .single_quote => char == '\'',
            .brace_expansion_start,
            .brace_hash_ambiguous,
            .brace_hash_double_ambiguous,
            .brace_emit_double_hash_modifier,
            .brace_expansion_after_length,
            .brace_expansion,
            .brace_expansion_colon,
            .brace_expansion_hash,
            .brace_expansion_percent,
            .brace_expansion_escape,
            => switch (char) {
                // Inside brace expansion (modifier position), these characters have special meaning
                '}', ':', '$', '\\', '"', '\'' => true,
                else => false,
            },
            .brace_expansion_word => switch (char) {
                // Inside brace expansion word (after modifier), only structural chars are special
                // :, #, %, -, +, =, ? are NOT special here - they're literal content
                '}', '$', '\\', '"', '\'' => true,
                else => false,
            },
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
            .end_line = self.line,
            .end_column = self.column,
            .complete = complete,
            .type = token_type,
        };
    }

    /// Returns the next token from the input stream.
    ///
    /// ## State Machine Design
    ///
    /// This function implements a state machine using Zig's labeled switch pattern
    /// for explicit, self-documenting state transitions. The design separates two
    /// types of state transitions:
    ///
    /// **Intra-call transitions** (`continue :state <new_state>`):
    /// Used when we can transition to a new state immediately without returning
    /// a token. Examples include:
    /// - Line continuations (backslash-newline) - consumed silently, continue parsing
    /// - Buffer boundary handling - transition to escape state, continue processing
    ///
    /// **Inter-call transitions** (set `self.parse_context`, then `break :state <token>`):
    /// Used when we need to return a token and resume in a different state on the
    /// next call. Examples include:
    /// - Entering a quoted string - return DoubleQuoteBegin, resume in .double_quote
    /// - Returning content from inside quotes - return Literal, stay in quote state
    ///
    /// The `parse_context` field persists state across calls, while `continue :state`
    /// enables efficient intra-call transitions without recursive function calls.
    pub fn nextToken(self: *Lexer) LexerError!?Token {
        self.token_start_position = self.position;
        self.token_start_line = self.line;
        self.token_start_column = self.column;

        return state: switch (self.parse_context) {
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
                    break :state self.makeToken(.{ .Continuation = result.slice }, at_boundary);
                } else {
                    // Buffer full, need more continuations
                    break :state self.makeToken(.{ .Continuation = result.slice }, false);
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
                        self.popContext();
                        // Check if word continues after closing quote
                        const next = try self.peekByte();
                        const at_boundary = self.isWordComplete(next);
                        break :state self.makeToken(.DoubleQuoteEnd, at_boundary);
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
                            // Intra-call transition: continue processing in escape state
                            continue :state .double_quote_escape;
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
                            break :state self.makeToken(.{ .EscapedLiteral = escaped_slice }, false);
                        } else {
                            // Not a special escape - backslash is literal
                            // Consume just the backslash, next char handled in next iteration
                            // Note: This is a regular Literal because the backslash is literal content.
                            self.consume(buf[0..1]);
                            break :state self.makeToken(.{ .Literal = buf[0..1] }, false);
                        }
                    },
                    '$' => {
                        // Parameter expansion inside double quotes
                        _ = try self.consumeOne();
                        continue :state .dollar;
                    },
                    '`' => {
                        // TODO: Command substitution - for now, treat as literal
                        const buf = self.reader.peek(1) catch |err| switch (err) {
                            error.EndOfStream => return LexerError.UnterminatedQuote,
                            else => return LexerError.UnexpectedEndOfFile,
                        };
                        self.consume(buf);
                        // complete=false: still inside double quotes, more content follows
                        break :state self.makeToken(.{ .Literal = buf }, false);
                    },
                    else => {
                        // Regular literal content - read until special char
                        const result = try self.readUntil("\"$`\\") orelse {
                            return LexerError.UnterminatedQuote;
                        };
                        // complete=false: still inside double quotes
                        break :state self.makeToken(.{ .Literal = result.slice }, false);
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
                    break :state self.makeToken(.{ .EscapedLiteral = buf }, false);
                } else {
                    // Not a special escape - the backslash we consumed was literal.
                    // Emit a backslash literal using a static string slice.
                    // Note: This is a regular Literal, not EscapedLiteral, because the
                    // backslash itself is literal content (not an escape sequence result).
                    self.parse_context = .double_quote;
                    break :state self.makeToken(.{ .Literal = "\\" }, false);
                }
            },
            .none_escape => {
                // We saw a backslash outside quotes on the previous call.
                // Backslash escapes the next character (makes it literal).
                const next = try self.peekByte() orelse {
                    // EOF after backslash outside quotes - backslash is discarded per POSIX
                    self.parse_context = .none;
                    break :state null;
                };

                if (next == '\n') {
                    // Line continuation - backslash-newline is removed entirely
                    _ = try self.consumeOne();
                    self.parse_context = .none;
                    // Intra-call transition: continue processing on the next line
                    continue :state .none;
                }

                // Consume the escaped character and return it as an escaped literal
                const buf = self.reader.peek(1) catch |err| switch (err) {
                    error.EndOfStream => {
                        self.parse_context = .none;
                        break :state null;
                    },
                    else => return LexerError.UnexpectedEndOfFile,
                };
                self.consume(buf);
                self.parse_context = .none;
                // Check if word continues after this escaped char
                const after = try self.peekByte();
                const at_boundary = self.isWordComplete(after);
                break :state self.makeToken(.{ .EscapedLiteral = buf }, at_boundary);
            },
            .dollar => {
                // We saw $ - determine what kind of expansion this is
                const next = try self.peekByte() orelse {
                    // $ at EOF - treat as literal
                    break :state self.makeToken(.{ .Literal = "$" }, true);
                };

                if (next == '{') {
                    // Braced expansion: ${...}
                    _ = try self.consumeOne();
                    try self.pushContext(.brace_expansion_start);
                    break :state self.makeToken(.BraceExpansionBegin, false);
                } else if (isSpecialParam(next)) {
                    // Special parameter: $@, $*, $#, $?, $-, $$, $!, $0-$9
                    const buf = self.reader.peek(1) catch |err| switch (err) {
                        error.EndOfStream => break :state self.makeToken(.{ .Literal = "$" }, true),
                        else => return LexerError.UnexpectedEndOfFile,
                    };
                    self.consume(buf);
                    // Check if word continues
                    const after = try self.peekByte();
                    const at_boundary = self.isWordComplete(after);
                    break :state self.makeToken(.{ .SimpleExpansion = buf }, at_boundary);
                } else if (isParamStartChar(next)) {
                    // Variable name: $VAR
                    const result = try self.readWhile(isParamChar) orelse {
                        // Shouldn't happen since we peeked a valid char
                        break :state self.makeToken(.{ .Literal = "$" }, true);
                    };
                    const after = try self.peekByte();
                    const at_boundary = self.isWordComplete(after);
                    break :state self.makeToken(.{ .SimpleExpansion = result.slice }, at_boundary);
                } else {
                    // $ followed by invalid char - $ is literal
                    break :state self.makeToken(.{ .Literal = "$" }, false);
                }
            },
            .simple_expansion => {
                // Continuing to read a simple expansion name after buffer boundary
                // The $ was consumed, we're reading the rest of the name
                const next = try self.peekByte() orelse {
                    // EOF - emit what we have
                    self.parse_context = .none;
                    break :state null;
                };

                if (isParamChar(next)) {
                    const result = try self.readWhile(isParamChar) orelse {
                        self.parse_context = .none;
                        break :state null;
                    };
                    self.parse_context = .none;
                    const after = try self.peekByte();
                    const at_boundary = self.isWordComplete(after);
                    break :state self.makeToken(.{ .Continuation = result.slice }, at_boundary);
                } else {
                    // No more param chars
                    self.parse_context = .none;
                    const at_boundary = self.isWordComplete(next);
                    break :state self.makeToken(.{ .Continuation = "" }, at_boundary);
                }
            },
            .brace_expansion_start => {
                // Just entered ${...}, first char has special handling for #
                const first = try self.peekByte() orelse {
                    return LexerError.UnterminatedBraceExpansion;
                };

                if (first == '}') {
                    // Empty ${} - emit end, parser will error
                    _ = try self.consumeOne();
                    self.popContext();
                    const after = try self.peekByte();
                    const at_boundary = self.isWordComplete(after);
                    break :state self.makeToken(.BraceExpansionEnd, at_boundary);
                } else if (first == '#') {
                    // Could be length operator or param #
                    // Need to peek next char to disambiguate
                    const buf = self.reader.peekGreedy(2) catch |err| switch (err) {
                        error.EndOfStream => return LexerError.UnterminatedBraceExpansion,
                        else => return LexerError.UnexpectedEndOfFile,
                    };
                    if (buf.len < 2) {
                        // Buffer boundary - consume # and defer decision
                        self.consume(buf[0..1]);
                        self.parse_context = .brace_hash_ambiguous;
                        continue :state .brace_hash_ambiguous;
                    }

                    const second = buf[1];
                    if (second == '}') {
                        // ${#} - # is the parameter (value of $#)
                        self.consume(buf[0..1]);
                        self.parse_context = .brace_expansion;
                        break :state self.makeToken(.{ .Literal = "#" }, false);
                    } else if (second == '#') {
                        // ${## - could be ${##} (length of #) or ${###...} (# with ## modifier)
                        // Need third char to disambiguate
                        self.consume(buf[0..1]); // consume first #
                        self.parse_context = .brace_hash_ambiguous;
                        continue :state .brace_hash_ambiguous;
                    } else if (isSpecialParam(second) or isParamStartChar(second)) {
                        // ${#name} - first # is length operator (but not ${##})
                        self.consume(buf[0..1]);
                        self.parse_context = .brace_expansion_after_length;
                        break :state self.makeToken(.{ .Modifier = .{ .op = .Length, .check_null = false } }, false);
                    } else {
                        // ${#<modifier>} - # is the parameter
                        self.consume(buf[0..1]);
                        self.parse_context = .brace_expansion;
                        break :state self.makeToken(.{ .Literal = "#" }, false);
                    }
                } else if (first >= '0' and first <= '9') {
                    // Positional parameter - in braces, can be multi-digit (${10}, ${123}, etc.)
                    // Check digits BEFORE isSpecialParam since digits are special params outside braces
                    // but multi-digit inside braces.
                    const result = try self.readWhile(std.ascii.isDigit) orelse {
                        return LexerError.UnterminatedBraceExpansion;
                    };
                    self.parse_context = .brace_expansion;
                    break :state self.makeToken(.{ .Literal = result.slice }, false);
                } else if (isSpecialParam(first)) {
                    // Special param: ${?}, ${@}, etc. (but not digits - handled above)
                    const buf = self.reader.peek(1) catch |err| switch (err) {
                        error.EndOfStream => return LexerError.UnterminatedBraceExpansion,
                        else => return LexerError.UnexpectedEndOfFile,
                    };
                    self.consume(buf);
                    self.parse_context = .brace_expansion;
                    break :state self.makeToken(.{ .Literal = buf }, false);
                } else if (isParamStartChar(first)) {
                    // Variable name
                    const result = try self.readWhile(isParamChar) orelse {
                        return LexerError.UnterminatedBraceExpansion;
                    };
                    self.parse_context = .brace_expansion;
                    break :state self.makeToken(.{ .Literal = result.slice }, false);
                } else if (first >= '0' and first <= '9') {
                    // Positional parameter - in braces, can be multi-digit (${10}, ${123}, etc.)
                    // Check digits BEFORE isSpecialParam since digits are special params outside braces
                    // but multi-digit inside braces.
                    const result = try self.readWhile(std.ascii.isDigit) orelse {
                        return LexerError.UnterminatedBraceExpansion;
                    };
                    self.parse_context = .brace_expansion;
                    break :state self.makeToken(.{ .Literal = result.slice }, false);
                } else if (first == ':') {
                    // Modifier without parameter name (e.g., ${:-foo}) - let brace_expansion_colon handle it
                    _ = try self.consumeOne();
                    self.parse_context = .brace_expansion_colon;
                    continue :state .brace_expansion_colon;
                } else {
                    // Invalid char after ${ - emit as literal, parser will handle
                    const buf = self.reader.peek(1) catch |err| switch (err) {
                        error.EndOfStream => return LexerError.UnterminatedBraceExpansion,
                        else => return LexerError.UnexpectedEndOfFile,
                    };
                    self.consume(buf);
                    self.parse_context = .brace_expansion;
                    break :state self.makeToken(.{ .Literal = buf }, false);
                }
            },
            .brace_hash_ambiguous => {
                // We saw ${# and consumed the #, now need next char to decide
                const next = try self.peekByte() orelse {
                    return LexerError.UnterminatedBraceExpansion;
                };

                if (next == '}') {
                    // ${#} - the # was the parameter (value of $#)
                    self.parse_context = .brace_expansion;
                    break :state self.makeToken(.{ .Literal = "#" }, false);
                } else if (next == '#') {
                    // ${## - could be:
                    // - ${##} → length of $#
                    // - ${###...} → $# with ## modifier
                    // Need to peek one more char to decide
                    _ = try self.consumeOne(); // consume second #
                    self.parse_context = .brace_hash_double_ambiguous;
                    continue :state .brace_hash_double_ambiguous;
                } else if (isSpecialParam(next) or isParamStartChar(next)) {
                    // ${#name} - the # was length operator
                    self.parse_context = .brace_expansion_after_length;
                    break :state self.makeToken(.{ .Modifier = .{ .op = .Length, .check_null = false } }, false);
                } else {
                    // ${#<modifier>} - the # was parameter (e.g., ${#%...})
                    self.parse_context = .brace_expansion;
                    break :state self.makeToken(.{ .Literal = "#" }, false);
                }
            },
            .brace_hash_double_ambiguous => {
                // We saw ${# and consumed two #s. Position is after the second #.
                // We need to distinguish:
                // - ${##} → length of $# (emit Length, then Literal "#")
                // - ${###...} → $# with ## modifier (emit Literal "#", then Modifier ##)
                const next = try self.peekByte() orelse {
                    return LexerError.UnterminatedBraceExpansion;
                };

                if (next == '}') {
                    // ${##} - this is ${#<length op>#<param>}
                    // First # was length operator, second # is parameter name
                    self.parse_context = .brace_expansion_after_length;
                    break :state self.makeToken(.{ .Modifier = .{ .op = .Length, .check_null = false } }, false);
                } else if (next == '#') {
                    // ${###...} - this is ${#<param>##<modifier>}
                    // First # was the parameter name, positions 2-3 are the ## modifier
                    // Consume the third # (part of ## modifier) and emit Literal "#" for param
                    _ = try self.consumeOne();
                    self.parse_context = .brace_emit_double_hash_modifier;
                    break :state self.makeToken(.{ .Literal = "#" }, false);
                } else {
                    // ${##X...} where X is not # or } - this is invalid or edge case
                    // Treat first # as length op, second # as param name, X is part of modifier
                    // Actually: ${##foo} is length of "foo"? No, that would be ${#foo}.
                    // ${##foo} with ## as modifier of what? There's no param before ##.
                    // This is actually invalid syntax. But let's handle it gracefully.
                    // Treat as: # is length op, # is param, rest is modifier
                    self.parse_context = .brace_expansion_after_length;
                    break :state self.makeToken(.{ .Modifier = .{ .op = .Length, .check_null = false } }, false);
                }
            },
            .brace_emit_double_hash_modifier => {
                // We already determined this is ${###...} and emitted Literal "#".
                // Now emit the ## (RemoveLargestPrefix) modifier.
                // The two # chars were already consumed in brace_hash_double_ambiguous.
                self.parse_context = .brace_expansion_word;
                break :state self.makeToken(.{ .Modifier = .{ .op = .RemoveLargestPrefix, .check_null = false } }, false);
            },
            .brace_expansion_after_length => {
                // Just emitted Length modifier, now read the parameter name
                const first = try self.peekByte() orelse {
                    return LexerError.UnterminatedBraceExpansion;
                };

                if (first == '}') {
                    // ${##} case - we already consumed both #s, second # was the param
                    // Emit Literal "#" for the param name
                    self.parse_context = .brace_expansion;
                    break :state self.makeToken(.{ .Literal = "#" }, false);
                } else if (isSpecialParam(first)) {
                    _ = try self.consumeOne();
                    self.parse_context = .brace_expansion;
                    break :state self.makeToken(.{ .Literal = &.{first} }, false);
                } else if (isParamStartChar(first)) {
                    const result = try self.readWhile(isParamChar) orelse {
                        return LexerError.UnterminatedBraceExpansion;
                    };
                    self.parse_context = .brace_expansion;
                    break :state self.makeToken(.{ .Literal = result.slice }, false);
                } else if (first >= '0' and first <= '9') {
                    // Positional parameter after length (e.g., ${#10})
                    const result = try self.readWhile(std.ascii.isDigit) orelse {
                        return LexerError.UnterminatedBraceExpansion;
                    };
                    self.parse_context = .brace_expansion;
                    break :state self.makeToken(.{ .Literal = result.slice }, false);
                } else {
                    return LexerError.InvalidModifier;
                }
            },
            .brace_expansion => {
                // Inside ${...} after parameter name, expecting modifier or }
                const first = try self.peekByte() orelse {
                    return LexerError.UnterminatedBraceExpansion;
                };

                switch (first) {
                    '}' => {
                        _ = try self.consumeOne();
                        self.popContext();
                        const after = try self.peekByte();
                        const at_boundary = self.isWordComplete(after);
                        break :state self.makeToken(.BraceExpansionEnd, at_boundary);
                    },
                    ':' => {
                        _ = try self.consumeOne();
                        self.parse_context = .brace_expansion_colon;
                        continue :state .brace_expansion_colon;
                    },
                    '-' => {
                        _ = try self.consumeOne();
                        self.parse_context = .brace_expansion_word;
                        break :state self.makeToken(.{ .Modifier = .{ .op = .UseDefault, .check_null = false } }, false);
                    },
                    '=' => {
                        _ = try self.consumeOne();
                        self.parse_context = .brace_expansion_word;
                        break :state self.makeToken(.{ .Modifier = .{ .op = .AssignDefault, .check_null = false } }, false);
                    },
                    '?' => {
                        _ = try self.consumeOne();
                        self.parse_context = .brace_expansion_word;
                        break :state self.makeToken(.{ .Modifier = .{ .op = .ErrorIfUnset, .check_null = false } }, false);
                    },
                    '+' => {
                        _ = try self.consumeOne();
                        self.parse_context = .brace_expansion_word;
                        break :state self.makeToken(.{ .Modifier = .{ .op = .UseAlternative, .check_null = false } }, false);
                    },
                    '#' => {
                        _ = try self.consumeOne();
                        self.parse_context = .brace_expansion_hash;
                        continue :state .brace_expansion_hash;
                    },
                    '%' => {
                        _ = try self.consumeOne();
                        self.parse_context = .brace_expansion_percent;
                        continue :state .brace_expansion_percent;
                    },
                    '$' => {
                        // Nested expansion in word
                        _ = try self.consumeOne();
                        continue :state .dollar;
                    },
                    '\\' => {
                        _ = try self.consumeOne();
                        self.parse_context = .brace_expansion_escape;
                        continue :state .brace_expansion_escape;
                    },
                    '\'' => {
                        // Single quote inside ${...}
                        _ = try self.consumeOne();
                        const result = try self.readSingleQuoted() orelse {
                            return LexerError.UnterminatedBraceExpansion;
                        };
                        if (result.complete) {
                            break :state self.makeToken(.{ .SingleQuoted = result.slice }, false);
                        } else {
                            try self.pushContext(.single_quote);
                            break :state self.makeToken(.{ .SingleQuoted = result.slice }, false);
                        }
                    },
                    '"' => {
                        // Double quote inside ${...}
                        _ = try self.consumeOne();
                        try self.pushContext(.double_quote);
                        break :state self.makeToken(.DoubleQuoteBegin, false);
                    },
                    else => {
                        // Read word content until special char
                        const result = try self.readUntil("}:$\\\"'") orelse {
                            return LexerError.UnterminatedBraceExpansion;
                        };
                        break :state self.makeToken(.{ .Literal = result.slice }, false);
                    },
                }
            },
            .brace_expansion_colon => {
                // Saw : in modifier position, waiting for -, =, ?, +
                const next = try self.peekByte() orelse {
                    return LexerError.UnterminatedBraceExpansion;
                };

                switch (next) {
                    '-' => {
                        _ = try self.consumeOne();
                        self.parse_context = .brace_expansion_word;
                        break :state self.makeToken(.{ .Modifier = .{ .op = .UseDefault, .check_null = true } }, false);
                    },
                    '=' => {
                        _ = try self.consumeOne();
                        self.parse_context = .brace_expansion_word;
                        break :state self.makeToken(.{ .Modifier = .{ .op = .AssignDefault, .check_null = true } }, false);
                    },
                    '?' => {
                        _ = try self.consumeOne();
                        self.parse_context = .brace_expansion_word;
                        break :state self.makeToken(.{ .Modifier = .{ .op = .ErrorIfUnset, .check_null = true } }, false);
                    },
                    '+' => {
                        _ = try self.consumeOne();
                        self.parse_context = .brace_expansion_word;
                        break :state self.makeToken(.{ .Modifier = .{ .op = .UseAlternative, .check_null = true } }, false);
                    },
                    else => {
                        // Invalid modifier after :
                        return LexerError.InvalidModifier;
                    },
                }
            },
            .brace_expansion_hash => {
                // Saw # in modifier position, check for ##
                const next = try self.peekByte() orelse {
                    return LexerError.UnterminatedBraceExpansion;
                };

                self.parse_context = .brace_expansion_word;
                if (next == '#') {
                    _ = try self.consumeOne();
                    break :state self.makeToken(.{ .Modifier = .{ .op = .RemoveLargestPrefix, .check_null = false } }, false);
                } else {
                    break :state self.makeToken(.{ .Modifier = .{ .op = .RemoveSmallestPrefix, .check_null = false } }, false);
                }
            },
            .brace_expansion_percent => {
                // Saw % in modifier position, check for %%
                const next = try self.peekByte() orelse {
                    return LexerError.UnterminatedBraceExpansion;
                };

                self.parse_context = .brace_expansion_word;
                if (next == '%') {
                    _ = try self.consumeOne();
                    break :state self.makeToken(.{ .Modifier = .{ .op = .RemoveLargestSuffix, .check_null = false } }, false);
                } else {
                    break :state self.makeToken(.{ .Modifier = .{ .op = .RemoveSmallestSuffix, .check_null = false } }, false);
                }
            },
            .brace_expansion_escape => {
                // Saw \ inside ${...}
                const next = try self.peekByte() orelse {
                    return LexerError.UnterminatedBraceExpansion;
                };

                self.parse_context = .brace_expansion;
                // POSIX: $, `, ", \, } and newline are special inside ${...}
                if (next == '$' or next == '`' or next == '"' or next == '\\' or next == '}') {
                    const buf = self.reader.peek(1) catch |err| switch (err) {
                        error.EndOfStream => return LexerError.UnterminatedBraceExpansion,
                        else => return LexerError.UnexpectedEndOfFile,
                    };
                    self.consume(buf);
                    break :state self.makeToken(.{ .EscapedLiteral = buf }, false);
                } else if (next == '\n') {
                    // Line continuation
                    _ = try self.consumeOne();
                    continue :state .brace_expansion;
                } else {
                    // Backslash is literal
                    break :state self.makeToken(.{ .Literal = "\\" }, false);
                }
            },
            .brace_expansion_word => {
                // Inside ${...} after modifier - reading word/pattern content.
                // Only }, $, \, and quotes are special here.
                // Characters like :, #, %, -, +, =, ? are literal content.
                const first = try self.peekByte() orelse {
                    return LexerError.UnterminatedBraceExpansion;
                };

                switch (first) {
                    '}' => {
                        _ = try self.consumeOne();
                        self.popContext();
                        const after = try self.peekByte();
                        const at_boundary = self.isWordComplete(after);
                        break :state self.makeToken(.BraceExpansionEnd, at_boundary);
                    },
                    '$' => {
                        // Nested expansion in word
                        _ = try self.consumeOne();
                        continue :state .dollar;
                    },
                    '\\' => {
                        // Escape in word - reuse brace_expansion_escape but return here
                        _ = try self.consumeOne();
                        const next = try self.peekByte() orelse {
                            return LexerError.UnterminatedBraceExpansion;
                        };
                        // POSIX: $, `, ", \, } and newline are special
                        if (next == '$' or next == '`' or next == '"' or next == '\\' or next == '}') {
                            const buf = self.reader.peek(1) catch |err| switch (err) {
                                error.EndOfStream => return LexerError.UnterminatedBraceExpansion,
                                else => return LexerError.UnexpectedEndOfFile,
                            };
                            self.consume(buf);
                            break :state self.makeToken(.{ .EscapedLiteral = buf }, false);
                        } else if (next == '\n') {
                            // Line continuation
                            _ = try self.consumeOne();
                            continue :state .brace_expansion_word;
                        } else {
                            // Backslash is literal
                            break :state self.makeToken(.{ .Literal = "\\" }, false);
                        }
                    },
                    '\'' => {
                        // Single quote inside word
                        _ = try self.consumeOne();
                        const result = try self.readSingleQuoted() orelse {
                            return LexerError.UnterminatedBraceExpansion;
                        };
                        if (result.complete) {
                            break :state self.makeToken(.{ .SingleQuoted = result.slice }, false);
                        } else {
                            try self.pushContext(.single_quote);
                            break :state self.makeToken(.{ .SingleQuoted = result.slice }, false);
                        }
                    },
                    '"' => {
                        // Double quote inside word
                        _ = try self.consumeOne();
                        try self.pushContext(.double_quote);
                        break :state self.makeToken(.DoubleQuoteBegin, false);
                    },
                    else => {
                        // Read word content until special char - only }, $, \, quotes are special
                        const result = try self.readUntil("}$\\\"'") orelse {
                            return LexerError.UnterminatedBraceExpansion;
                        };
                        break :state self.makeToken(.{ .Literal = result.slice }, false);
                    },
                }
            },
            .none => {
                // Normal processing

                // If the previous token was incomplete, handle continuation
                if (self.in_continuation) {
                    const next = try self.peekByte();

                    // Check what follows the incomplete token
                    if (next == null) {
                        // EOF - word is complete
                        self.in_continuation = false;
                        break :state null;
                    } else if (next == '\'' or next == '"' or next == '\\' or next == '$') {
                        // Quote, escape, or expansion follows - process it normally (word continues)
                        // Don't emit a continuation, fall through to normal processing
                        self.in_continuation = false;
                    } else if (next == '<' or next == '>') {
                        // Redirection operator - don't emit continuation, let normal processing handle it.
                        // Parser will join incomplete digits with the redirection if applicable.
                        // This handles cases like "2>&1" split across buffer boundaries.
                        self.in_continuation = false;
                        continue :state .none;
                    } else if (self.isWordComplete(next)) {
                        // Whitespace or other metachar - word is complete, emit empty continuation
                        self.in_continuation = false;
                        break :state self.makeToken(.{ .Continuation = "" }, true);
                    } else {
                        // Word char - read as continuation
                        const result = try self.readWord() orelse {
                            self.in_continuation = false;
                            break :state null;
                        };
                        // Check if word continues after this.
                        // When result.complete=true, the buffer has more data so peeking is safe.
                        // When result.complete=false, we consumed all buffered data. Peeking might
                        // trigger buffer refill which can invalidate the slice on streaming readers.
                        // We conservatively mark as incomplete; the parser handles joining tokens.
                        const at_boundary = if (result.complete) blk: {
                            const after = try self.peekByte();
                            // Don't mark complete if followed by redirection operator - parser may need to join
                            break :blk if (after == '<' or after == '>') false else self.isWordComplete(after);
                        } else false;
                        break :state self.makeToken(.{ .Continuation = result.slice }, at_boundary);
                    }
                }

                // Skip whitespace (spaces and tabs, not newlines)
                while (try self.peekByte()) |c| {
                    if (c == ' ' or c == '\t') {
                        _ = try self.consumeOne();
                    } else {
                        break;
                    }
                }

                self.token_start_position = self.position;
                self.token_start_line = self.line;
                self.token_start_column = self.column;

                const first = try self.peekByte() orelse break :state null;

                // Handle newline - command separator
                if (first == '\n') {
                    _ = try self.consumeOne();
                    break :state self.makeToken(.Separator, true);
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
                            break :state self.makeToken(.{ .SingleQuoted = result.slice }, at_boundary);
                        } else {
                            // Need continuation - first chunk is SingleQuoted with complete=false
                            self.parse_context = .single_quote;
                            self.in_continuation = true;
                            break :state self.makeToken(.{ .SingleQuoted = result.slice }, false);
                        }
                    },
                    '"' => {
                        // Double quote - consume it and enter double quote state
                        _ = try self.consumeOne();
                        self.parse_context = .double_quote;
                        // DoubleQuoteBegin always has complete=false (content follows)
                        break :state self.makeToken(.DoubleQuoteBegin, false);
                    },
                    '\\' => {
                        // Escape - try to peek both backslash and next char
                        const buf = self.reader.peekGreedy(2) catch |err| switch (err) {
                            error.EndOfStream => break :state null,
                            else => return LexerError.UnexpectedEndOfFile,
                        };
                        if (buf.len < 2) {
                            // Buffer boundary or EOF - transition to escape state
                            self.consume(buf[0..1]);
                            self.parse_context = .none_escape;
                            // Intra-call transition: continue processing in escape state
                            continue :state .none_escape;
                        }

                        const escaped_char = buf[1];
                        if (escaped_char == '\n') {
                            // Line continuation - backslash-newline is removed entirely
                            self.consume(buf[0..2]);
                            // Intra-call transition: continue to next line
                            continue :state .none;
                        }

                        // Backslash escapes the next character (makes it literal)
                        const escaped_slice = buf[1..2];
                        self.consume(buf[0..2]);
                        // Check if word continues after this escaped char
                        const after = try self.peekByte();
                        const at_boundary = self.isWordComplete(after);
                        break :state self.makeToken(.{ .EscapedLiteral = escaped_slice }, at_boundary);
                    },
                    '<' => {
                        _ = try self.consumeOne();
                        break :state try self.finishRedirection(.In);
                    },
                    '>' => {
                        _ = try self.consumeOne();
                        const next = try self.peekByte();
                        if (next == '>') {
                            _ = try self.consumeOne();
                            break :state try self.finishRedirection(.Append);
                        }
                        break :state try self.finishRedirection(.Out);
                    },
                    '(' => {
                        _ = try self.consumeOne();
                        break :state self.makeToken(.LeftParen, true);
                    },
                    ')' => {
                        _ = try self.consumeOne();
                        break :state self.makeToken(.RightParen, true);
                    },
                    ';' => {
                        _ = try self.consumeOne();
                        const next = try self.peekByte();
                        if (next == ';') {
                            _ = try self.consumeOne();
                            break :state self.makeToken(.DoubleSemicolon, true);
                        }
                        break :state self.makeToken(.Separator, true);
                    },
                    '$' => {
                        // Parameter expansion - need to determine type
                        _ = try self.consumeOne();
                        continue :state .dollar;
                    },
                    else => {
                        if (!isPlainCharacter(first)) {
                            // Consume the unhandled character to avoid infinite loop
                            _ = try self.consumeOne();
                            break :state null;
                        }
                        const result = try self.readWord() orelse break :state null;
                        // Check if word continues (e.g., followed by quote)
                        // Only peek if word wasn't truncated by buffer - otherwise slice would be invalidated
                        const at_boundary = if (result.complete)
                            self.isWordComplete(try self.peekByte())
                        else
                            false;
                        break :state self.makeToken(.{ .Literal = result.slice }, at_boundary);
                    },
                }
            },
        };
    }

    /// Finish parsing a redirection operator and emit the token.
    ///
    /// Unlike other tokens, redirection tokens are created directly instead of using
    /// `makeToken`. This is intentional: redirection operators don't set `in_continuation`
    /// because whitespace is allowed between the operator and its target (e.g., `> file`).
    ///
    /// The target is always emitted as separate token(s) following the redirection.
    /// The `complete` flag is always `false` to indicate a target must follow.
    fn finishRedirection(self: *Lexer, redir_op: Redirection) LexerError!?Token {
        // Check for >&fd or <&fd (fd duplication)
        const next = try self.peekByte();
        const op = if (next == '&') blk: {
            _ = try self.consumeOne();
            break :blk Redirection.Fd;
        } else redir_op;

        // Target follows as separate token(s). Parser will collect and validate.
        return Token{
            .position = self.token_start_position,
            .end_position = self.position,
            .line = self.token_start_line,
            .column = self.token_start_column,
            .end_line = self.line,
            .end_column = self.column,
            .complete = false,
            .type = .{ .Redirection = op },
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

fn expectIncompleteLiteral(token: ?Token, expected: []const u8) !void {
    const t = token orelse return error.ExpectedToken;
    switch (t.type) {
        .Literal => |lit| try std.testing.expectEqualStrings(expected, lit),
        else => return error.ExpectedLiteral,
    }
    try std.testing.expectEqual(false, t.complete);
}

fn expectEscapedLiteral(token: ?Token, expected: []const u8) !void {
    const t = token orelse return error.ExpectedToken;
    switch (t.type) {
        .EscapedLiteral => |esc| try std.testing.expectEqualStrings(expected, esc),
        else => return error.ExpectedEscapedLiteral,
    }
}

fn expectRedirection(token: ?Token, expected_op: Redirection) !void {
    const t = token orelse return error.ExpectedToken;
    switch (t.type) {
        .Redirection => |r| {
            try std.testing.expectEqual(expected_op, r);
        },
        else => return error.ExpectedRedirection,
    }
    // Redirection tokens should always have complete=false (target follows)
    try std.testing.expectEqual(false, t.complete);
}

fn expectSeparator(token: ?Token) !void {
    const t = token orelse return error.ExpectedToken;
    switch (t.type) {
        .Separator => {},
        else => return error.ExpectedSeparator,
    }
}

fn expectDoubleSemicolon(token: ?Token) !void {
    const t = token orelse return error.ExpectedToken;
    switch (t.type) {
        .DoubleSemicolon => {},
        else => return error.ExpectedDoubleSemicolon,
    }
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
    try expectRedirection(try lexer.nextToken(), .Out);
    try expectLiteral(try lexer.nextToken(), "file");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: output redirection with space" {
    var reader = std.io.Reader.fixed("> file");
    var lexer = Lexer.init(&reader);
    try expectRedirection(try lexer.nextToken(), .Out);
    try expectLiteral(try lexer.nextToken(), "file");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: input redirection" {
    var reader = std.io.Reader.fixed("<input");
    var lexer = Lexer.init(&reader);
    try expectRedirection(try lexer.nextToken(), .In);
    try expectLiteral(try lexer.nextToken(), "input");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: append redirection" {
    var reader = std.io.Reader.fixed(">>logfile");
    var lexer = Lexer.init(&reader);
    try expectRedirection(try lexer.nextToken(), .Append);
    try expectLiteral(try lexer.nextToken(), "logfile");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: fd-prefixed output redirection" {
    var reader = std.io.Reader.fixed("2>errors");
    var lexer = Lexer.init(&reader);
    try expectIncompleteLiteral(try lexer.nextToken(), "2");
    try expectRedirection(try lexer.nextToken(), .Out);
    try expectLiteral(try lexer.nextToken(), "errors");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: fd-prefixed append redirection" {
    var reader = std.io.Reader.fixed("2>>errors");
    var lexer = Lexer.init(&reader);
    try expectIncompleteLiteral(try lexer.nextToken(), "2");
    try expectRedirection(try lexer.nextToken(), .Append);
    try expectLiteral(try lexer.nextToken(), "errors");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: fd-prefixed input redirection" {
    var reader = std.io.Reader.fixed("0<input");
    var lexer = Lexer.init(&reader);
    try expectIncompleteLiteral(try lexer.nextToken(), "0");
    try expectRedirection(try lexer.nextToken(), .In);
    try expectLiteral(try lexer.nextToken(), "input");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: fd duplication 2>&1" {
    var reader = std.io.Reader.fixed("2>&1");
    var lexer = Lexer.init(&reader);
    try expectIncompleteLiteral(try lexer.nextToken(), "2");
    try expectRedirection(try lexer.nextToken(), .Fd);
    try expectLiteral(try lexer.nextToken(), "1");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: fd duplication >&2" {
    var reader = std.io.Reader.fixed(">&2");
    var lexer = Lexer.init(&reader);
    try expectRedirection(try lexer.nextToken(), .Fd);
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
    try expectRedirection(try lexer.nextToken(), .Out);
    try expectLiteral(try lexer.nextToken(), "out");
    try expectIncompleteLiteral(try lexer.nextToken(), "2");
    try expectRedirection(try lexer.nextToken(), .Fd);
    try expectLiteral(try lexer.nextToken(), "1");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: redirection at start" {
    var reader = std.io.Reader.fixed("2>&1 command");
    var lexer = Lexer.init(&reader);
    try expectIncompleteLiteral(try lexer.nextToken(), "2");
    try expectRedirection(try lexer.nextToken(), .Fd);
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

test "nextToken: newline emits separator" {
    var reader = std.io.Reader.fixed("hello\nworld");
    var lexer = Lexer.init(&reader);
    try expectLiteral(try lexer.nextToken(), "hello");
    try expectSeparator(try lexer.nextToken()); // newline
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
    try expectRedirection(try lexer.nextToken(), .Out);
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: fd redirection at EOF emits incomplete token" {
    // Lexer emits Redirection token; parser validates target presence
    var reader = std.io.Reader.fixed(">&");
    var lexer = Lexer.init(&reader);
    try expectRedirection(try lexer.nextToken(), .Fd);
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: semicolon emits separator" {
    // `;` emits Separator token, `|` and `&` are still consumed without token
    var reader = std.io.Reader.fixed("| ; & cmd");
    var lexer = Lexer.init(&reader);
    try std.testing.expectEqual(null, try lexer.nextToken()); // | (unhandled)
    try expectSeparator(try lexer.nextToken()); // ;
    try std.testing.expectEqual(null, try lexer.nextToken()); // & (unhandled)
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

test "nextToken: double semicolon" {
    var reader = std.io.Reader.fixed(";;");
    var lexer = Lexer.init(&reader);
    try expectDoubleSemicolon(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: semicolon followed by semicolon as separate tokens" {
    // "; ;" should be two Separator tokens (space separates them)
    var reader = std.io.Reader.fixed("; ;");
    var lexer = Lexer.init(&reader);
    try expectSeparator(try lexer.nextToken());
    try expectSeparator(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: multiple newlines" {
    var reader = std.io.Reader.fixed("\n\n\n");
    var lexer = Lexer.init(&reader);
    try expectSeparator(try lexer.nextToken());
    try expectSeparator(try lexer.nextToken());
    try expectSeparator(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: command list with semicolons" {
    var reader = std.io.Reader.fixed("echo a; echo b");
    var lexer = Lexer.init(&reader);
    try expectLiteral(try lexer.nextToken(), "echo");
    try expectLiteral(try lexer.nextToken(), "a");
    try expectSeparator(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "echo");
    try expectLiteral(try lexer.nextToken(), "b");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

// --- Parenthesis tests ---

fn expectLeftParen(token: ?Token) !void {
    const t = token orelse return error.ExpectedToken;
    switch (t.type) {
        .LeftParen => {},
        else => return error.ExpectedLeftParen,
    }
}

fn expectRightParen(token: ?Token) !void {
    const t = token orelse return error.ExpectedToken;
    switch (t.type) {
        .RightParen => {},
        else => return error.ExpectedRightParen,
    }
}

test "nextToken: left parenthesis" {
    var reader = std.io.Reader.fixed("(");
    var lexer = Lexer.init(&reader);
    try expectLeftParen(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: right parenthesis" {
    var reader = std.io.Reader.fixed(")");
    var lexer = Lexer.init(&reader);
    try expectRightParen(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: parentheses as word boundaries" {
    // echo(foo) should tokenize as: echo, (, foo, )
    var reader = std.io.Reader.fixed("echo(foo)");
    var lexer = Lexer.init(&reader);
    try expectLiteral(try lexer.nextToken(), "echo");
    try expectLeftParen(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "foo");
    try expectRightParen(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: subshell syntax" {
    // (cmd) should tokenize as: (, cmd, )
    var reader = std.io.Reader.fixed("(cmd)");
    var lexer = Lexer.init(&reader);
    try expectLeftParen(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "cmd");
    try expectRightParen(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: parentheses with spaces" {
    var reader = std.io.Reader.fixed("( cmd )");
    var lexer = Lexer.init(&reader);
    try expectLeftParen(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "cmd");
    try expectRightParen(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: nested parentheses" {
    var reader = std.io.Reader.fixed("(())");
    var lexer = Lexer.init(&reader);
    try expectLeftParen(try lexer.nextToken());
    try expectLeftParen(try lexer.nextToken());
    try expectRightParen(try lexer.nextToken());
    try expectRightParen(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: parenthesis complete flag" {
    // Parentheses should always be complete tokens
    var reader = std.io.Reader.fixed("(a)");
    var lexer = Lexer.init(&reader);
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(TokenType.LeftParen, tok1.type);
    try std.testing.expectEqual(true, tok1.complete);
    _ = try lexer.nextToken(); // skip 'a'
    const tok3 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(TokenType.RightParen, tok3.type);
    try std.testing.expectEqual(true, tok3.complete);
}

test "nextToken: parentheses inside single quotes are literal" {
    // Parentheses inside single quotes should be treated as literal content
    var reader = std.io.Reader.fixed("'(foo)'");
    var lex = Lexer.init(&reader);
    try expectSingleQuoted(try lex.nextToken(), "(foo)");
    try std.testing.expectEqual(null, try lex.nextToken());
}

test "nextToken: parentheses inside double quotes are literal" {
    // Parentheses inside double quotes should be treated as literal content
    var reader = std.io.Reader.fixed("\"(foo)\"");
    var lex = Lexer.init(&reader);
    try expectDoubleQuoteBegin(try lex.nextToken());
    try expectLiteral(try lex.nextToken(), "(foo)");
    try expectDoubleQuoteEnd(try lex.nextToken());
    try std.testing.expectEqual(null, try lex.nextToken());
}

// --- EscapedLiteral tests ---

test "nextToken: escaped tilde produces EscapedLiteral" {
    // \~ should produce EscapedLiteral, not Literal
    // This is important for tilde expansion - \~ should not expand
    var reader = std.io.Reader.fixed("\\~");
    var lex = Lexer.init(&reader);
    try expectEscapedLiteral(try lex.nextToken(), "~");
    try std.testing.expectEqual(null, try lex.nextToken());
}

test "nextToken: escaped tilde in word" {
    // echo \~foo should tokenize with EscapedLiteral for the ~
    var reader = std.io.Reader.fixed("echo \\~foo");
    var lex = Lexer.init(&reader);
    try expectLiteral(try lex.nextToken(), "echo");
    try expectEscapedLiteral(try lex.nextToken(), "~");
    const tok3 = (try lex.nextToken()).?;
    try std.testing.expectEqualStrings("foo", tok3.type.Continuation);
    try std.testing.expectEqual(null, try lex.nextToken());
}

test "nextToken: escaped dollar produces EscapedLiteral" {
    // \$ outside quotes produces EscapedLiteral
    var reader = std.io.Reader.fixed("\\$");
    var lex = Lexer.init(&reader);
    try expectEscapedLiteral(try lex.nextToken(), "$");
    try std.testing.expectEqual(null, try lex.nextToken());
    try std.testing.expectEqual(null, try lex.nextToken());
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
    try expectRedirection(try lexer.nextToken(), .Fd);
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
    // The escape \\" should produce EscapedLiteral("\"")
    // Even if the backslash is at buffer boundary, the escape state handles it
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("\"", tok2.type.EscapedLiteral);
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

    // \$ produces EscapedLiteral("$")
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("$", tok1.type.EscapedLiteral);
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
    try expectEscapedLiteral(try lexer.nextToken(), "\""); // escaped quote
    try expectLiteral(try lexer.nextToken(), "hi");
    try expectEscapedLiteral(try lexer.nextToken(), "\""); // escaped quote
    try expectDoubleQuoteEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: double-quoted string with dollar sign" {
    // $var inside double quotes is a parameter expansion
    var reader = std.io.Reader.fixed("\"$var\"");
    var lexer = Lexer.init(&reader);
    try expectDoubleQuoteBegin(try lexer.nextToken());
    try expectSimpleExpansion(try lexer.nextToken(), "var");
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
    // \\ is a special escape - produces single escaped backslash
    var reader = std.io.Reader.fixed("\"\\\\\"");
    var lexer = Lexer.init(&reader);
    try expectDoubleQuoteBegin(try lexer.nextToken());
    try expectEscapedLiteral(try lexer.nextToken(), "\\"); // escaped backslash
    try expectDoubleQuoteEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: POSIX escape - backslash-quote" {
    // \" is a special escape - produces escaped literal quote
    var reader = std.io.Reader.fixed("\"\\\"\"");
    var lexer = Lexer.init(&reader);
    try expectDoubleQuoteBegin(try lexer.nextToken());
    try expectEscapedLiteral(try lexer.nextToken(), "\""); // escaped quote
    try expectDoubleQuoteEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: POSIX escape - backslash-dollar" {
    // \$ is a special escape - produces escaped literal $
    var reader = std.io.Reader.fixed("\"\\$\"");
    var lexer = Lexer.init(&reader);
    try expectDoubleQuoteBegin(try lexer.nextToken());
    try expectEscapedLiteral(try lexer.nextToken(), "$"); // escaped dollar
    try expectDoubleQuoteEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

// --- Unquoted escape tests ---

test "nextToken: unquoted escape - backslash escapes next char" {
    // \$ outside quotes produces escaped literal $
    var reader = std.io.Reader.fixed("\\$HOME ");
    var lexer = Lexer.init(&reader);
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("$", tok1.type.EscapedLiteral);
    try std.testing.expectEqual(false, tok1.complete); // more word follows
    // "HOME" is a continuation of the word started by the escape
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("HOME", tok2.type.Continuation);
    try std.testing.expectEqual(true, tok2.complete);
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: unquoted escape - backslash-quote" {
    // \" outside quotes produces escaped literal "
    // say\"hi\" is one word: say + " + hi + "
    var reader = std.io.Reader.fixed("say\\\"hi\\\" ");
    var lexer = Lexer.init(&reader);
    // "say" stops at backslash
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("say", tok1.type.Literal);
    try std.testing.expectEqual(false, tok1.complete); // backslash follows
    // \" produces escaped literal "
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("\"", tok2.type.EscapedLiteral);
    try std.testing.expectEqual(false, tok2.complete); // more follows
    // "hi" is a continuation
    const tok3 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("hi", tok3.type.Continuation);
    try std.testing.expectEqual(false, tok3.complete); // backslash follows
    // \" produces escaped literal "
    const tok4 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("\"", tok4.type.EscapedLiteral);
    try std.testing.expectEqual(true, tok4.complete); // space follows
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: unquoted escape - backslash-backslash" {
    // \\ outside quotes produces escaped literal \
    var reader = std.io.Reader.fixed("\\\\");
    var lexer = Lexer.init(&reader);
    try expectEscapedLiteral(try lexer.nextToken(), "\\");
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
    // \<space> produces escaped literal space (escaped space, part of word)
    // "hello\ world" is ONE word: hello + <space> + world
    var reader = std.io.Reader.fixed("hello\\ world ");
    var lexer = Lexer.init(&reader);
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("hello", tok1.type.Literal);
    try std.testing.expectEqual(false, tok1.complete); // backslash follows
    // Space is escaped, continues the word
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings(" ", tok2.type.EscapedLiteral);
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
    try std.testing.expectEqualStrings("$", tok2.type.EscapedLiteral);
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
    try expectRedirection(try lexer.nextToken(), .Out);
    // Then the quoted target tokens
    try expectDoubleQuoteBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "file");
    try expectDoubleQuoteEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: redirection with single-quoted target" {
    var reader = std.io.Reader.fixed(">'file'");
    var lexer = Lexer.init(&reader);
    try expectRedirection(try lexer.nextToken(), .Out);
    // Then the single-quoted target
    try expectSingleQuoted(try lexer.nextToken(), "file");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: redirection with fd and double-quoted target" {
    var reader = std.io.Reader.fixed("2>\"errors\"");
    var lexer = Lexer.init(&reader);
    try expectIncompleteLiteral(try lexer.nextToken(), "2");
    try expectRedirection(try lexer.nextToken(), .Out);
    try expectDoubleQuoteBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "errors");
    try expectDoubleQuoteEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: redirection with mixed target (word then quote)" {
    // >name"suffix" - redirection followed by unquoted + quoted parts
    var reader = std.io.Reader.fixed(">name\"suffix\"");
    var lexer = Lexer.init(&reader);
    try expectRedirection(try lexer.nextToken(), .Out);
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
    try expectRedirection(try lexer.nextToken(), .Out);
    try expectDoubleQuoteBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "file");
    try expectDoubleQuoteEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

// --- Parameter expansion tests ---

fn expectSimpleExpansion(token: ?Token, expected: []const u8) !void {
    const t = token orelse return error.ExpectedToken;
    switch (t.type) {
        .SimpleExpansion => |name| try std.testing.expectEqualStrings(expected, name),
        else => return error.ExpectedSimpleExpansion,
    }
}

fn expectBraceExpansionBegin(token: ?Token) !void {
    const t = token orelse return error.ExpectedToken;
    switch (t.type) {
        .BraceExpansionBegin => {},
        else => return error.ExpectedBraceExpansionBegin,
    }
}

fn expectBraceExpansionEnd(token: ?Token) !void {
    const t = token orelse return error.ExpectedToken;
    switch (t.type) {
        .BraceExpansionEnd => {},
        else => return error.ExpectedBraceExpansionEnd,
    }
}

fn expectModifier(token: ?Token, expected_op: ModifierOp, expected_check_null: bool) !void {
    const t = token orelse return error.ExpectedToken;
    switch (t.type) {
        .Modifier => |m| {
            try std.testing.expectEqual(expected_op, m.op);
            try std.testing.expectEqual(expected_check_null, m.check_null);
        },
        else => return error.ExpectedModifier,
    }
}

test "nextToken: simple expansion $VAR" {
    var reader = std.io.Reader.fixed("$HOME");
    var lexer = Lexer.init(&reader);
    try expectSimpleExpansion(try lexer.nextToken(), "HOME");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: simple expansion $1" {
    var reader = std.io.Reader.fixed("$1");
    var lexer = Lexer.init(&reader);
    try expectSimpleExpansion(try lexer.nextToken(), "1");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: $10 is $1 followed by 0" {
    var reader = std.io.Reader.fixed("$10");
    var lexer = Lexer.init(&reader);
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("1", tok1.type.SimpleExpansion);
    try std.testing.expectEqual(false, tok1.complete);
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("0", tok2.type.Continuation);
    // With peek safety fix, word is marked incomplete when buffer is exhausted.
    // Next call sees EOF and returns null.
    try std.testing.expectEqual(false, tok2.complete);
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: simple expansion $?" {
    var reader = std.io.Reader.fixed("$?");
    var lexer = Lexer.init(&reader);
    try expectSimpleExpansion(try lexer.nextToken(), "?");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: simple expansion $@" {
    var reader = std.io.Reader.fixed("$@");
    var lexer = Lexer.init(&reader);
    try expectSimpleExpansion(try lexer.nextToken(), "@");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: $ at EOF is literal" {
    var reader = std.io.Reader.fixed("$");
    var lexer = Lexer.init(&reader);
    try expectLiteral(try lexer.nextToken(), "$");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: $ followed by invalid char is literal" {
    var reader = std.io.Reader.fixed("$,rest");
    var lexer = Lexer.init(&reader);
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("$", tok1.type.Literal);
    try std.testing.expectEqual(false, tok1.complete);
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings(",rest", tok2.type.Continuation);
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: braced expansion ${var}" {
    var reader = std.io.Reader.fixed("${var}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "var");
    try expectBraceExpansionEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: empty ${}" {
    var reader = std.io.Reader.fixed("${}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectBraceExpansionEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: ${#var} length operator" {
    var reader = std.io.Reader.fixed("${#var}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectModifier(try lexer.nextToken(), .Length, false);
    try expectLiteral(try lexer.nextToken(), "var");
    try expectBraceExpansionEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: ${##} length of $#" {
    var reader = std.io.Reader.fixed("${##}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectModifier(try lexer.nextToken(), .Length, false);
    try expectLiteral(try lexer.nextToken(), "#");
    try expectBraceExpansionEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: ${###} is $# with ## modifier" {
    var reader = std.io.Reader.fixed("${###}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "#");
    try expectModifier(try lexer.nextToken(), .RemoveLargestPrefix, false);
    try expectBraceExpansionEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: ${#} is value of $#" {
    var reader = std.io.Reader.fixed("${#}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "#");
    try expectBraceExpansionEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: ${var:-default}" {
    var reader = std.io.Reader.fixed("${var:-default}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "var");
    try expectModifier(try lexer.nextToken(), .UseDefault, true);
    try expectLiteral(try lexer.nextToken(), "default");
    try expectBraceExpansionEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: ${var-default} without colon" {
    var reader = std.io.Reader.fixed("${var-default}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "var");
    try expectModifier(try lexer.nextToken(), .UseDefault, false);
    try expectLiteral(try lexer.nextToken(), "default");
    try expectBraceExpansionEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: ${var:=value}" {
    var reader = std.io.Reader.fixed("${var:=value}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "var");
    try expectModifier(try lexer.nextToken(), .AssignDefault, true);
    try expectLiteral(try lexer.nextToken(), "value");
    try expectBraceExpansionEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: ${var:?error}" {
    var reader = std.io.Reader.fixed("${var:?error}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "var");
    try expectModifier(try lexer.nextToken(), .ErrorIfUnset, true);
    try expectLiteral(try lexer.nextToken(), "error");
    try expectBraceExpansionEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: ${var:+alt}" {
    var reader = std.io.Reader.fixed("${var:+alt}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "var");
    try expectModifier(try lexer.nextToken(), .UseAlternative, true);
    try expectLiteral(try lexer.nextToken(), "alt");
    try expectBraceExpansionEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: ${var#pattern}" {
    var reader = std.io.Reader.fixed("${var#pattern}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "var");
    try expectModifier(try lexer.nextToken(), .RemoveSmallestPrefix, false);
    try expectLiteral(try lexer.nextToken(), "pattern");
    try expectBraceExpansionEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: ${var##pattern}" {
    var reader = std.io.Reader.fixed("${var##pattern}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "var");
    try expectModifier(try lexer.nextToken(), .RemoveLargestPrefix, false);
    try expectLiteral(try lexer.nextToken(), "pattern");
    try expectBraceExpansionEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: ${var%pattern}" {
    var reader = std.io.Reader.fixed("${var%pattern}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "var");
    try expectModifier(try lexer.nextToken(), .RemoveSmallestSuffix, false);
    try expectLiteral(try lexer.nextToken(), "pattern");
    try expectBraceExpansionEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: ${var%%pattern}" {
    var reader = std.io.Reader.fixed("${var%%pattern}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "var");
    try expectModifier(try lexer.nextToken(), .RemoveLargestSuffix, false);
    try expectLiteral(try lexer.nextToken(), "pattern");
    try expectBraceExpansionEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: ${var:-} empty default" {
    var reader = std.io.Reader.fixed("${var:-}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "var");
    try expectModifier(try lexer.nextToken(), .UseDefault, true);
    try expectBraceExpansionEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: ${var:} invalid modifier" {
    var reader = std.io.Reader.fixed("${var:}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "var");
    try std.testing.expectError(LexerError.InvalidModifier, lexer.nextToken());
}

test "nextToken: nested ${var:-${other}}" {
    var reader = std.io.Reader.fixed("${var:-${other}}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "var");
    try expectModifier(try lexer.nextToken(), .UseDefault, true);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "other");
    try expectBraceExpansionEnd(try lexer.nextToken());
    try expectBraceExpansionEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: $VAR inside double quotes" {
    var reader = std.io.Reader.fixed("\"$VAR\"");
    var lexer = Lexer.init(&reader);
    try expectDoubleQuoteBegin(try lexer.nextToken());
    try expectSimpleExpansion(try lexer.nextToken(), "VAR");
    try expectDoubleQuoteEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: ${var} inside double quotes" {
    var reader = std.io.Reader.fixed("\"${var}\"");
    var lexer = Lexer.init(&reader);
    try expectDoubleQuoteBegin(try lexer.nextToken());
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "var");
    try expectBraceExpansionEnd(try lexer.nextToken());
    try expectDoubleQuoteEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: unterminated ${" {
    var reader = std.io.Reader.fixed("${var");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "var");
    try std.testing.expectError(LexerError.UnterminatedBraceExpansion, lexer.nextToken());
}

test "nextToken: ${10} multi-digit positional" {
    var reader = std.io.Reader.fixed("${10}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "10");
    try expectBraceExpansionEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: ${?} special param" {
    var reader = std.io.Reader.fixed("${?}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "?");
    try expectBraceExpansionEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: expansion followed by word via braces" {
    // prefix${VAR}suffix - VAR is separate from suffix because of braces
    var reader = std.io.Reader.fixed("prefix${VAR}suffix");
    var lexer = Lexer.init(&reader);
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("prefix", tok1.type.Literal);
    try std.testing.expectEqual(false, tok1.complete);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "VAR");
    const tok4 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(TokenType.BraceExpansionEnd, tok4.type);
    try std.testing.expectEqual(false, tok4.complete); // suffix follows
    const tok5 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("suffix", tok5.type.Continuation);
    // With peek safety fix, word is marked incomplete when buffer is exhausted.
    // Next call sees EOF and returns null.
    try std.testing.expectEqual(false, tok5.complete);
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: expansion consumes full identifier" {
    // $VARsuffix is a single variable name VARsuffix
    var reader = std.io.Reader.fixed("$VARsuffix");
    var lexer = Lexer.init(&reader);
    try expectSimpleExpansion(try lexer.nextToken(), "VARsuffix");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: ${var:-\"quoted\"}" {
    var reader = std.io.Reader.fixed("${var:-\"quoted\"}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "var");
    try expectModifier(try lexer.nextToken(), .UseDefault, true);
    try expectDoubleQuoteBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "quoted");
    try expectDoubleQuoteEnd(try lexer.nextToken());
    try expectBraceExpansionEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: ${var:-foo:bar} colon in default value" {
    // Colon within default value should be literal, not trigger modifier parsing
    var reader = std.io.Reader.fixed("${var:-foo:bar}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "var");
    try expectModifier(try lexer.nextToken(), .UseDefault, true);
    try expectLiteral(try lexer.nextToken(), "foo:bar");
    try expectBraceExpansionEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: ${PATH:-/usr/bin:/bin} PATH-like default" {
    // Real-world example with colons in default value
    var reader = std.io.Reader.fixed("${PATH:-/usr/bin:/bin}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "PATH");
    try expectModifier(try lexer.nextToken(), .UseDefault, true);
    try expectLiteral(try lexer.nextToken(), "/usr/bin:/bin");
    try expectBraceExpansionEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: ${var:-#comment} hash at start of default" {
    // Hash at start of default value should be literal, not length/prefix operator
    var reader = std.io.Reader.fixed("${var:-#comment}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "var");
    try expectModifier(try lexer.nextToken(), .UseDefault, true);
    try expectLiteral(try lexer.nextToken(), "#comment");
    try expectBraceExpansionEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: ${var:-%pattern} percent at start of default" {
    // Percent at start of default value should be literal, not suffix operator
    var reader = std.io.Reader.fixed("${var:-%pattern}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "var");
    try expectModifier(try lexer.nextToken(), .UseDefault, true);
    try expectLiteral(try lexer.nextToken(), "%pattern");
    try expectBraceExpansionEnd(try lexer.nextToken());
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: ${var#pat-tern} hyphen in pattern" {
    // Hyphen in pattern should be literal
    var reader = std.io.Reader.fixed("${var#pat-tern}");
    var lexer = Lexer.init(&reader);
    try expectBraceExpansionBegin(try lexer.nextToken());
    try expectLiteral(try lexer.nextToken(), "var");
    try expectModifier(try lexer.nextToken(), .RemoveSmallestPrefix, false);
    try expectLiteral(try lexer.nextToken(), "pat-tern");
    try expectBraceExpansionEnd(try lexer.nextToken());
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
                LexerError.NestingTooDeep,
                LexerError.UnterminatedBraceExpansion,
                LexerError.InvalidModifier,
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
            .EscapedLiteral => {},
            .LeftParen => {},
            .RightParen => {},
            .Separator => {},
            .DoubleSemicolon => {},
            .SimpleExpansion => {},
            .BraceExpansionBegin => {},
            .BraceExpansionEnd => {},
            .Modifier => {},
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

// --- Buffer boundary tests for fd-prefixed redirections ---

test "nextToken: multi-digit fd at buffer boundary" {
    // Test 12>&1 with 1-byte buffer.
    // With such a small buffer, each character is a separate token.
    const pipe = try std.posix.pipe();
    defer std.posix.close(pipe[0]);

    _ = try std.posix.write(pipe[1], "12>&1 ");
    std.posix.close(pipe[1]);

    const file = std.fs.File{ .handle = pipe[0] };
    var small_buf: [1]u8 = undefined;
    var file_reader = file.reader(&small_buf);
    var lexer = Lexer.init(&file_reader.interface);

    // First token: "1" incomplete (1-byte buffer)
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("1", tok1.type.Literal);
    try std.testing.expectEqual(false, tok1.complete);

    // Second token: "2" as continuation
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("2", tok2.type.Continuation);
    try std.testing.expectEqual(false, tok2.complete);

    // Third token: Redirection(Fd) - the >& operator
    const tok3 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(Redirection.Fd, tok3.type.Redirection);

    // Fourth token: "1" (the target fd)
    const tok4 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("1", tok4.type.Literal);
    try std.testing.expectEqual(false, tok4.complete);

    // Fifth token: empty continuation (word complete, space follows)
    const tok5 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("", tok5.type.Continuation);
    try std.testing.expectEqual(true, tok5.complete);

    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: non-digit word before redirection at buffer boundary" {
    // Test a2>file with 1-byte buffer.
    // With such a small buffer, each character is a separate token.
    // This tests that continuation handling works correctly across buffer boundaries.
    const pipe = try std.posix.pipe();
    defer std.posix.close(pipe[0]);

    _ = try std.posix.write(pipe[1], "a2>file ");
    std.posix.close(pipe[1]);

    const file = std.fs.File{ .handle = pipe[0] };
    var small_buf: [1]u8 = undefined;
    var file_reader = file.reader(&small_buf);
    var lexer = Lexer.init(&file_reader.interface);

    // First token: "a" incomplete (1-byte buffer)
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("a", tok1.type.Literal);
    try std.testing.expectEqual(false, tok1.complete);

    // Second token: "2" as continuation, incomplete (followed by >)
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("2", tok2.type.Continuation);
    try std.testing.expectEqual(false, tok2.complete);

    // Third token: Redirection(Out) - the > was seen, word "a2" ends
    const tok3 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(Redirection.Out, tok3.type.Redirection);

    // Fourth and following tokens: "file" split across buffer boundaries
    // With 1-byte buffer, we get: "f", "i", "l", "e" as separate tokens
    const tok4 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("f", tok4.type.Literal);
    try std.testing.expectEqual(false, tok4.complete);

    const tok5 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("i", tok5.type.Continuation);
    try std.testing.expectEqual(false, tok5.complete);

    const tok6 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("l", tok6.type.Continuation);
    try std.testing.expectEqual(false, tok6.complete);

    const tok7 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("e", tok7.type.Continuation);
    try std.testing.expectEqual(false, tok7.complete);

    // Final token: empty continuation marking end of word (space follows)
    const tok8 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("", tok8.type.Continuation);
    try std.testing.expectEqual(true, tok8.complete);

    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: fd close >&-" {
    // Test that >&- is lexed as Redirection(Fd) followed by Literal("-")
    var reader = std.io.Reader.fixed(">&- ");
    var lexer = Lexer.init(&reader);

    // First token: Redirection(Fd) - incomplete, target follows
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(Redirection.Fd, tok1.type.Redirection);
    try std.testing.expectEqual(false, tok1.complete);

    // Second token: "-" target
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("-", tok2.type.Literal);
    try std.testing.expectEqual(true, tok2.complete);

    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: fd dup with invalid target >&foo" {
    // Test that >&foo is lexed as Redirection(Fd) followed by Literal("foo")
    // Parser will validate that "foo" is not a valid fd target
    var reader = std.io.Reader.fixed(">&foo ");
    var lexer = Lexer.init(&reader);

    // First token: Redirection(Fd) - incomplete, target follows
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(Redirection.Fd, tok1.type.Redirection);
    try std.testing.expectEqual(false, tok1.complete);

    // Second token: "foo" target (parser will reject this)
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("foo", tok2.type.Literal);
    try std.testing.expectEqual(true, tok2.complete);

    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: fd dup with space >&  1" {
    // Test that >& 1 is lexed as Redirection(Fd) followed by Literal("1")
    var reader = std.io.Reader.fixed(">&  1 ");
    var lexer = Lexer.init(&reader);

    // First token: Redirection(Fd)
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(Redirection.Fd, tok1.type.Redirection);
    try std.testing.expectEqual(false, tok1.complete);

    // Second token: "1" target
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("1", tok2.type.Literal);
    try std.testing.expectEqual(true, tok2.complete);

    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: source fd overflow treated as word" {
    // Test that 99999999999999999999>&1 is treated as word + redirection
    // (number exceeds fd_t max, so not a valid source fd - parser will handle)
    var reader = std.io.Reader.fixed("99999999999999999999>&1 ");
    var lexer = Lexer.init(&reader);

    // First token: the overflow number as a literal word (incomplete, followed by redirection)
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("99999999999999999999", tok1.type.Literal);
    try std.testing.expectEqual(false, tok1.complete);

    // Second token: Redirection(Fd)
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(Redirection.Fd, tok2.type.Redirection);

    // Third token: "1" target
    const tok3 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("1", tok3.type.Literal);

    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: max valid source fd" {
    // Test that max fd_t value is emitted as literal before redirection
    // (parser will validate and use as source fd)
    const max_fd = std.math.maxInt(std.posix.fd_t);
    const max_fd_str = std.fmt.comptimePrint("{d}>&1 ", .{max_fd});

    var reader = std.io.Reader.fixed(max_fd_str);
    var lexer = Lexer.init(&reader);

    // First token: fd number as literal (incomplete)
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings(std.fmt.comptimePrint("{d}", .{max_fd}), tok1.type.Literal);
    try std.testing.expectEqual(false, tok1.complete);

    // Second token: Redirection(Fd)
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(Redirection.Fd, tok2.type.Redirection);

    // Third token: "1" target
    const tok3 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("1", tok3.type.Literal);

    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: source fd just over max treated as word" {
    // Test that max fd_t + 1 is treated as word (overflow - parser will handle)
    const max_fd = std.math.maxInt(std.posix.fd_t);
    const overflow_fd: u64 = @as(u64, @intCast(max_fd)) + 1;
    const overflow_fd_str = std.fmt.comptimePrint("{d}>&1 ", .{overflow_fd});

    var reader = std.io.Reader.fixed(overflow_fd_str);
    var lexer = Lexer.init(&reader);

    // First token: the overflow number as literal (incomplete)
    const tok1 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings(std.fmt.comptimePrint("{d}", .{overflow_fd}), tok1.type.Literal);
    try std.testing.expectEqual(false, tok1.complete);

    // Second token: Redirection(Fd)
    const tok2 = (try lexer.nextToken()).?;
    try std.testing.expectEqual(Redirection.Fd, tok2.type.Redirection);

    // Third token: "1" target
    const tok3 = (try lexer.nextToken()).?;
    try std.testing.expectEqualStrings("1", tok3.type.Literal);

    try std.testing.expectEqual(null, try lexer.nextToken());
}
