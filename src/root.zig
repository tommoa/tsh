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

/// Where the redirection is either coming from or going to.
pub const RedirectionTarget = union(enum) {
    File: []const u8,
    Fd: []const u8,
};

/// A redirection operation.
/// Fields are nullable to support incomplete tokens split across buffer boundaries.
pub const Redirection = struct {
    operation: ?RedirectionOp = null,
    target: ?RedirectionTarget = null,
    fd: ?[]const u8 = null,
};

/// The type of token returned by the lexer.
pub const TokenType = union(enum) {
    Literal: []const u8,
    Redirection: Redirection,
    Continuation: []const u8,
};

/// The lexer's Token structure.
pub const Token = struct {
    /// The absolute position in the input stream where this token starts.
    position: usize,
    /// The line number where this token starts (1-indexed).
    line: usize,
    /// The column number where this token starts (1-indexed).
    column: usize,
    /// Whether this token is complete, or if more fragments follow.
    /// When false, the next token will be a continuation of this one.
    complete: bool,
    /// The type and payload of this token.
    type: TokenType,

    /// Format the token for human-readable output.
    pub fn format(self: Token, writer: *std.io.Writer) !void {
        try writer.print("[{d}:{d}] ", .{ self.line, self.column });
        switch (self.type) {
            .Literal => |lit| try writer.print("Literal(\"{s}\")", .{lit}),
            .Continuation => |cont| try writer.print("Continuation(\"{s}\")", .{cont}),
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
                if (r.target) |target| {
                    switch (target) {
                        .File => |f| try writer.print("\"{s}\"", .{f}),
                        .Fd => |fd| try writer.print("{s}", .{fd}),
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
    InvalidRedirection,
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

    inline fn isWordChar(c: u8) bool {
        return switch (c) {
            ' ', '\t', '\n', '=', '<', '>', '&', '|', ';' => false,
            else => true,
        };
    }

    inline fn isDigit(c: u8) bool {
        return c >= '0' and c <= '9';
    }

    const ReadResult = struct {
        slice: []const u8,
        complete: bool,
    };

    /// Read a word (sequence of word chars, optionally including '=').
    /// Returns a slice from the reader's buffer and whether the word is complete.
    /// A word is incomplete if it was truncated due to buffer limits.
    fn readWord(self: *Lexer, include_equals: bool) LexerError!?ReadResult {
        // Peek as much as possible
        const buf = self.reader.peekGreedy(1) catch |err| switch (err) {
            error.EndOfStream => return null,
            else => return LexerError.UnexpectedEndOfFile,
        };
        if (buf.len == 0) return null;

        // Find word boundary
        var len: usize = 0;
        var found_boundary = false;
        for (buf) |c| {
            if (isWordChar(c) or (include_equals and c == '=')) {
                len += 1;
            } else {
                found_boundary = true;
                break;
            }
        }

        if (len == 0) return null;

        // Check what's after the word (if anything) before consuming
        // This tells us if the word is complete:
        // - found_boundary: there's a delimiter right after
        // - len < buf.len: there's at least one more byte (could be delimiter or EOF marker)
        const complete = found_boundary or (len < buf.len);

        const word = buf[0..len];
        self.consume(word);

        return .{ .slice = word, .complete = complete };
    }

    /// Read a sequence of digits. Returns a slice from the reader's buffer.
    /// A sequence is incomplete if it was truncated due to buffer limits.
    fn readDigits(self: *Lexer) LexerError!?ReadResult {
        const buf = self.reader.peekGreedy(1) catch |err| switch (err) {
            error.EndOfStream => return null,
            else => return LexerError.UnexpectedEndOfFile,
        };
        if (buf.len == 0) return null;

        var len: usize = 0;
        var found_boundary = false;
        for (buf) |c| {
            if (isDigit(c)) {
                len += 1;
            } else {
                found_boundary = true;
                break;
            }
        }

        if (len == 0) return null;

        // Complete if we found a delimiter, or there's room left in buffer.
        const complete = found_boundary or (len < buf.len);

        const digits = buf[0..len];
        self.consume(digits);

        return .{ .slice = digits, .complete = complete };
    }

    /// Create a token from the current state.
    /// Also updates in_continuation flag based on whether the token is complete.
    inline fn makeToken(self: *Lexer, token_type: TokenType, complete: bool) Token {
        self.in_continuation = !complete;
        return Token{
            .position = self.token_start_position,
            .line = self.token_start_line,
            .column = self.token_start_column,
            .complete = complete,
            .type = token_type,
        };
    }

    pub fn nextToken(self: *Lexer) LexerError!?Token {
        // If the previous token was incomplete, return a continuation token
        if (self.in_continuation) {
            self.token_start_position = self.position;
            self.token_start_line = self.line;
            self.token_start_column = self.column;

            // Read available word chars as continuation
            const result = try self.readWord(true) orelse {
                // No more data - end of input. The incomplete token is implicitly complete.
                self.in_continuation = false;
                return null;
            };
            self.in_continuation = !result.complete;
            return self.makeToken(.{ .Continuation = result.slice }, result.complete);
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
                    const result = try self.readWord(true) orelse return null;
                    return self.makeToken(.{ .Literal = result.slice }, result.complete);
                }
            },
            else => {
                if (!isWordChar(first)) {
                    // Consume the unhandled character to avoid infinite loop
                    _ = try self.consumeOne();
                    return null;
                }
                const result = try self.readWord(true) orelse return null;
                return self.makeToken(.{ .Literal = result.slice }, result.complete);
            },
        }
    }

    fn finishRedirection(self: *Lexer, fd_value: ?[]const u8, redir_op: RedirectionOp) LexerError!?Token {
        // Check for >&fd or <&fd
        const next = try self.peekByte();
        if (next == '&') {
            _ = try self.consumeOne();
            const result = try self.readDigits() orelse return LexerError.InvalidRedirection;
            return self.makeToken(.{ .Redirection = .{
                .operation = .Fd,
                .target = .{ .Fd = result.slice },
                .fd = fd_value,
            } }, result.complete);
        }

        // Read target filename
        try self.skipWhitespace();
        const result = try self.readWord(false) orelse return LexerError.InvalidRedirection;

        return self.makeToken(.{ .Redirection = .{
            .operation = redir_op,
            .target = .{ .File = result.slice },
            .fd = fd_value,
        } }, result.complete);
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

fn expectRedirectionWithFile(token: ?Token, expected_op: RedirectionOp, expected_fd: ?[]const u8, expected_file: []const u8) !void {
    const t = token orelse return error.ExpectedToken;
    switch (t.type) {
        .Redirection => |r| {
            try std.testing.expectEqual(expected_op, r.operation.?);
            if (expected_fd) |efd| {
                try std.testing.expectEqualStrings(efd, r.fd.?);
            } else {
                try std.testing.expectEqual(@as(?[]const u8, null), r.fd);
            }
            switch (r.target.?) {
                .File => |f| try std.testing.expectEqualStrings(expected_file, f),
                .Fd => return error.ExpectedFileTarget,
            }
        },
        else => return error.ExpectedRedirection,
    }
}

fn expectRedirectionWithFd(token: ?Token, expected_op: RedirectionOp, expected_fd: ?[]const u8, expected_target_fd: []const u8) !void {
    const t = token orelse return error.ExpectedToken;
    switch (t.type) {
        .Redirection => |r| {
            try std.testing.expectEqual(expected_op, r.operation.?);
            if (expected_fd) |efd| {
                try std.testing.expectEqualStrings(efd, r.fd.?);
            } else {
                try std.testing.expectEqual(@as(?[]const u8, null), r.fd);
            }
            switch (r.target.?) {
                .Fd => |fd| try std.testing.expectEqualStrings(expected_target_fd, fd),
                .File => return error.ExpectedFdTarget,
            }
        },
        else => return error.ExpectedRedirection,
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
    try expectRedirectionWithFile(try lexer.nextToken(), .Out, null, "file");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: output redirection with space" {
    var reader = std.io.Reader.fixed("> file");
    var lexer = Lexer.init(&reader);
    try expectRedirectionWithFile(try lexer.nextToken(), .Out, null, "file");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: input redirection" {
    var reader = std.io.Reader.fixed("<input");
    var lexer = Lexer.init(&reader);
    try expectRedirectionWithFile(try lexer.nextToken(), .In, null, "input");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: append redirection" {
    var reader = std.io.Reader.fixed(">>logfile");
    var lexer = Lexer.init(&reader);
    try expectRedirectionWithFile(try lexer.nextToken(), .Append, null, "logfile");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: fd-prefixed output redirection" {
    var reader = std.io.Reader.fixed("2>errors");
    var lexer = Lexer.init(&reader);
    try expectRedirectionWithFile(try lexer.nextToken(), .Out, "2", "errors");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: fd-prefixed append redirection" {
    var reader = std.io.Reader.fixed("2>>errors");
    var lexer = Lexer.init(&reader);
    try expectRedirectionWithFile(try lexer.nextToken(), .Append, "2", "errors");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: fd-prefixed input redirection" {
    var reader = std.io.Reader.fixed("0<input");
    var lexer = Lexer.init(&reader);
    try expectRedirectionWithFile(try lexer.nextToken(), .In, "0", "input");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: fd duplication 2>&1" {
    var reader = std.io.Reader.fixed("2>&1");
    var lexer = Lexer.init(&reader);
    try expectRedirectionWithFd(try lexer.nextToken(), .Fd, "2", "1");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: fd duplication >&2" {
    var reader = std.io.Reader.fixed(">&2");
    var lexer = Lexer.init(&reader);
    try expectRedirectionWithFd(try lexer.nextToken(), .Fd, null, "2");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: complex command line" {
    var reader = std.io.Reader.fixed("FOO=bar cmd arg1 arg2 >out 2>&1");
    var lexer = Lexer.init(&reader);
    try expectLiteral(try lexer.nextToken(), "FOO=bar");
    try expectLiteral(try lexer.nextToken(), "cmd");
    try expectLiteral(try lexer.nextToken(), "arg1");
    try expectLiteral(try lexer.nextToken(), "arg2");
    try expectRedirectionWithFile(try lexer.nextToken(), .Out, null, "out");
    try expectRedirectionWithFd(try lexer.nextToken(), .Fd, "2", "1");
    try std.testing.expectEqual(null, try lexer.nextToken());
}

test "nextToken: redirection at start" {
    var reader = std.io.Reader.fixed("2>&1 command");
    var lexer = Lexer.init(&reader);
    try expectRedirectionWithFd(try lexer.nextToken(), .Fd, "2", "1");
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

test "nextToken: invalid redirection missing target" {
    var reader = std.io.Reader.fixed(">");
    var lexer = Lexer.init(&reader);
    try std.testing.expectError(LexerError.InvalidRedirection, lexer.nextToken());
}

test "nextToken: invalid fd redirection missing fd" {
    var reader = std.io.Reader.fixed(">&");
    var lexer = Lexer.init(&reader);
    try std.testing.expectError(LexerError.InvalidRedirection, lexer.nextToken());
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

test "nextToken: large fd numbers stored as strings" {
    // Test that extremely large fd numbers are stored as strings (caller validates)
    var reader = std.io.Reader.fixed(">&99999999999999999999");
    var lexer = Lexer.init(&reader);
    const tok = (try lexer.nextToken()).?;
    switch (tok.type) {
        .Redirection => |r| {
            try std.testing.expectEqual(RedirectionOp.Fd, r.operation.?);
            try std.testing.expectEqualStrings("99999999999999999999", r.target.?.Fd);
        },
        else => return error.ExpectedRedirection,
    }
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
                LexerError.InvalidRedirection,
                LexerError.UnexpectedEndOfFile,
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
