//! Word Expansion for POSIX Shell
//!
//! This module implements word expansion as specified in POSIX.1-2017,
//! Section 2.6 "Word Expansions". Word expansion transforms shell words
//! (tokens from the parser) into the final strings used for command
//! arguments, variable assignments, and redirection targets.
//!
//! ## POSIX Expansion Order (Section 2.6)
//!
//! POSIX specifies that expansions are performed in this order:
//!
//! 1. **Tilde Expansion** (2.6.1) - `~` and `~/path` expand to $HOME
//! 2. **Parameter Expansion** (2.6.2) - `$VAR`, `${VAR}`, `${VAR:-default}`, etc.
//! 3. **Command Substitution** (2.6.3) - `$(cmd)` and `` `cmd` `` (not yet implemented)
//! 4. **Arithmetic Expansion** (2.6.4) - `$((expr))` (not yet implemented)
//! 5. **Field Splitting** (2.6.5) - Split on IFS (not yet implemented)
//! 6. **Pathname Expansion** (2.6.6) - Glob patterns `*`, `?`, `[...]` (not yet implemented)
//! 7. **Quote Removal** (2.6.7) - Remove quotes that aren't part of expansions
//!
//! ## Special Parameters (Section 2.5.2)
//!
//! The following special parameters are supported:
//!
//! | Parameter | Description                                    |
//! |-----------|------------------------------------------------|
//! | `$?`      | Exit status of last command                    |
//! | `$#`      | Number of positional parameters                |
//! | `$@`      | All positional parameters (separate words)     |
//! | `$*`      | All positional parameters (joined by IFS)      |
//! | `$$`      | Process ID of the shell                        |
//! | `$!`      | PID of last background command (not yet impl)  |
//! | `$-`      | Current option flags                           |
//! | `$0`      | Name of the shell or script                    |
//! | `$1`-`$9` | Positional parameters 1-9                      |
//! | `${10}+`  | Positional parameters 10 and above             |
//!
//! ## Parameter Expansion Modifiers (Section 2.6.2)
//!
//! The following modifiers are parsed but not yet fully implemented:
//!
//! | Syntax           | Description                              |
//! |------------------|------------------------------------------|
//! | `${VAR:-word}`   | Use default if unset or null             |
//! | `${VAR:=word}`   | Assign default if unset or null          |
//! | `${VAR:?word}`   | Error if unset or null                   |
//! | `${VAR:+word}`   | Use alternative if set and non-null      |
//! | `${#VAR}`        | Length of value                          |
//! | `${VAR#pattern}` | Remove smallest prefix matching pattern  |
//! | `${VAR##pattern}`| Remove largest prefix matching pattern   |
//! | `${VAR%pattern}` | Remove smallest suffix matching pattern  |
//! | `${VAR%%pattern}`| Remove largest suffix matching pattern   |
//!
//! ## Quoting Effects on Expansion
//!
//! - **Unquoted**: Subject to field splitting and pathname expansion
//! - **Single-quoted** (`'...'`): No expansion performed
//! - **Double-quoted** (`"..."`): Parameter expansion occurs, but results
//!   are not subject to field splitting or pathname expansion. Exception:
//!   `"$@"` expands to separate fields per POSIX 2.5.2.
//!
//! ## References
//!
//! - POSIX.1-2017 Section 2.5.2: Special Parameters
//! - POSIX.1-2017 Section 2.6: Word Expansions
//! - POSIX.1-2017 Section 2.6.1: Tilde Expansion
//! - POSIX.1-2017 Section 2.6.2: Parameter Expansion

const std = @import("std");
const Allocator = std.mem.Allocator;

const parser = @import("parser.zig");
const state = @import("state.zig");

const Word = parser.Word;
const WordPart = parser.WordPart;
const ShellState = state.ShellState;

// ============================================================================
// Public API
// ============================================================================

/// Expand an array of Words into a null-terminated argv array for execve.
///
/// Each Word may expand to one or more argv entries (e.g., `"$@"` expands to
/// multiple entries when there are multiple positional parameters).
///
/// This is the primary entry point for command argument expansion.
pub fn expandArgv(allocator: Allocator, words: []const Word, shell: *const ShellState) Allocator.Error![:null]const ?[*:0]const u8 {
    var builder = WordBuilder.init(allocator);
    for (words) |word| {
        try expandWord(&builder, word, shell);
    }
    return builder.toArgv();
}

/// Expand a Word and return a joined string for assignment/redirection contexts.
///
/// POSIX 2.9.1 (Simple Commands): Variable assignments undergo tilde expansion,
/// parameter expansion, command substitution, arithmetic expansion, and quote
/// removal - but NOT field splitting or pathname expansion.
///
/// POSIX 2.7 (Redirection): Redirection targets undergo similar expansion.
pub fn expandWordJoined(allocator: Allocator, word: Word, shell: *const ShellState) Allocator.Error![]const u8 {
    var builder = WordBuilder.init(allocator);
    try expandWord(&builder, word, shell);
    return builder.join(" ");
}

// ============================================================================
// Types
// ============================================================================

/// Intermediate representation of expanded content within a word.
///
/// The `complete` flag indicates field boundaries for expansions like `$@`
/// that produce multiple words. When `complete = true`, it signals "this
/// ends a word boundary" (similar to lexer token completion).
///
/// Field splitting behavior (POSIX 2.6.5):
/// - Field splitting applies to parameter expansion, command substitution,
///   and arithmetic expansion results - NOT to tilde expansion or literals.
/// - Content inside double quotes is not subject to field splitting.
/// - Tilde expansion results are "treated as if quoted" (POSIX 2.6.1).
///
/// Example with adjacent expansions:
///   `text$(cmd)` where cmd outputs "a b c" -> `["texta", "b", "c"]`
///   `$(cmd)text` where cmd outputs "a b c" -> `["a", "b", "ctext"]`
const ExpandedPart = struct {
    content: []const u8,
    complete: bool,
};

/// Builds word lists during expansion, encapsulating buffer management.
///
/// WordBuilder handles:
/// - Creating new words in the argv being built
/// - Appending content to the current word
/// - Tracking word boundaries from $@ expansion
/// - Converting to final argv or joined string
pub const WordBuilder = struct {
    allocator: Allocator,
    buffers: std.ArrayListUnmanaged(Buffer) = .{},
    /// Tracks whether we've seen a complete word boundary from $@ expansion.
    /// This is word-scoped state: callers must reset it to false before
    /// expanding each new Word to prevent state leaking between words.
    seen_complete: bool = false,

    const Buffer = std.ArrayListUnmanaged(u8);

    pub fn init(allocator: Allocator) WordBuilder {
        return .{ .allocator = allocator };
    }

    /// Start a new word in the output.
    pub fn startWord(self: *WordBuilder) Allocator.Error!void {
        try self.buffers.append(self.allocator, .{});
    }

    /// Append content to the current word. Starts a new word if none exists.
    pub fn append(self: *WordBuilder, content: []const u8) Allocator.Error!void {
        if (self.buffers.items.len == 0) {
            try self.startWord();
        }
        try self.buffers.items[self.buffers.items.len - 1].appendSlice(self.allocator, content);
    }

    /// Append expanded parts, handling word boundaries from $@ expansion.
    /// Returns true if any content was added.
    pub fn appendParts(self: *WordBuilder, parts: []const ExpandedPart) Allocator.Error!bool {
        var content_added = false;
        for (parts, 0..) |p, i| {
            if (p.complete and (self.seen_complete or i > 0)) {
                try self.startWord();
            }
            try self.append(p.content);
            content_added = true;
            if (p.complete) {
                self.seen_complete = true;
            }
        }
        return content_added;
    }

    /// Get current word count.
    pub fn wordCount(self: *const WordBuilder) usize {
        return self.buffers.items.len;
    }

    /// Remove the last word if it's empty and we added exactly one word.
    /// This handles the case where $@ with no params should produce zero fields
    /// (POSIX 2.5.2) rather than leaving behind the empty word we started with.
    /// Only removes if buffers.len == starting_count + 1 and that word is empty.
    pub fn removeTrailingEmpty(self: *WordBuilder, starting_count: usize) void {
        if (self.buffers.items.len == starting_count + 1) {
            if (self.buffers.items[self.buffers.items.len - 1].items.len == 0) {
                _ = self.buffers.pop();
            }
        }
    }

    /// Convert to null-terminated argv array for execve.
    pub fn toArgv(self: *const WordBuilder) Allocator.Error![:null]const ?[*:0]const u8 {
        const argv = try self.allocator.allocSentinel(?[*:0]const u8, self.buffers.items.len, null);
        for (self.buffers.items, 0..) |*buf, i| {
            const str = try self.allocator.dupeZ(u8, buf.items);
            argv[i] = str.ptr;
        }
        return argv;
    }

    /// Join all words with a separator.
    /// Used for assignment/redirection contexts and $* expansion.
    pub fn join(self: *const WordBuilder, separator: []const u8) Allocator.Error![]const u8 {
        if (self.buffers.items.len == 0) return "";

        var total_len: usize = 0;
        for (self.buffers.items) |*buf| {
            total_len += buf.items.len;
        }
        if (self.buffers.items.len > 1) {
            total_len += separator.len * (self.buffers.items.len - 1);
        }
        if (total_len == 0) return "";

        const result = try self.allocator.alloc(u8, total_len);
        var offset: usize = 0;
        for (self.buffers.items, 0..) |*buf, i| {
            @memcpy(result[offset..][0..buf.items.len], buf.items);
            offset += buf.items.len;
            if (i < self.buffers.items.len - 1) {
                @memcpy(result[offset..][0..separator.len], separator);
                offset += separator.len;
            }
        }
        return result;
    }
};

// ============================================================================
// Tilde Expansion (POSIX 2.6.1)
// ============================================================================

/// Expand a tilde prefix in a literal string.
///
/// POSIX tilde expansion rules:
/// - `~` alone expands to $HOME
/// - `~/...` expands to $HOME/...
/// - `~user` expands to user's home directory (not yet implemented)
///
/// Returns the expanded string if tilde expansion applies, null otherwise.
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

// ============================================================================
// Parameter Expansion (POSIX 2.6.2)
// ============================================================================

/// Create a single-element ExpandedPart array with the given content.
/// Helper to reduce repetition in parameter expansion functions.
fn makeSinglePart(allocator: Allocator, content: []const u8) Allocator.Error![]ExpandedPart {
    const result = try allocator.alloc(ExpandedPart, 1);
    result[0] = .{ .content = content, .complete = false };
    return result;
}

/// Get the value of a special parameter (POSIX 2.5.2).
///
/// Returns null if the name is not a special parameter, allowing the caller
/// to fall back to regular variable lookup.
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
                // $? - Exit status of last command
                const result = try allocator.alloc(ExpandedPart, 1);
                const str = try std.fmt.allocPrint(allocator, "{d}", .{shell.last_status.toExitCode()});
                result[0] = .{ .content = str, .complete = false };
                return result;
            },
            '#' => {
                // $# - Number of positional parameters
                const result = try allocator.alloc(ExpandedPart, 1);
                const str = try std.fmt.allocPrint(allocator, "{d}", .{shell.positional_params.items.len});
                result[0] = .{ .content = str, .complete = false };
                return result;
            },
            '@' => {
                // $@ - All positional parameters as separate words
                // POSIX 2.5.2: "each positional parameter shall expand as a separate field"
                const params = shell.positional_params.items;
                if (params.len == 0) {
                    // "If there are no positional parameters, the expansion of '@'
                    // shall generate zero fields"
                    return try allocator.alloc(ExpandedPart, 0);
                }
                const parts = try allocator.alloc(ExpandedPart, params.len);
                for (params, 0..) |p, i| {
                    parts[i] = .{ .content = p, .complete = true };
                }
                return parts;
            },
            '*' => {
                // $* - All positional parameters joined by IFS
                // POSIX 2.5.2: In double-quotes, expands to single field separated by IFS[0]
                const params = shell.positional_params.items;
                if (params.len == 0) {
                    if (quoted) {
                        // "$*" with no params -> single empty field
                        const result = try allocator.alloc(ExpandedPart, 1);
                        result[0] = .{ .content = "", .complete = false };
                        return result;
                    } else {
                        // $* with no params -> zero fields
                        return try allocator.alloc(ExpandedPart, 0);
                    }
                }
                // TODO: use first char of IFS instead of space
                const joined = try std.mem.join(allocator, " ", params);
                const result = try allocator.alloc(ExpandedPart, 1);
                result[0] = .{ .content = joined, .complete = false };
                return result;
            },
            '$' => {
                // $$ - PID of shell (cached at startup)
                const result = try allocator.alloc(ExpandedPart, 1);
                const str = try std.fmt.allocPrint(allocator, "{d}", .{shell.pid});
                result[0] = .{ .content = str, .complete = false };
                return result;
            },
            '!' => {
                // $! - PID of last background command
                // TODO: implement when job control is added
                const result = try allocator.alloc(ExpandedPart, 1);
                result[0] = .{ .content = "", .complete = false };
                return result;
            },
            '-' => {
                // $- - Current option flags
                var flags: [16]u8 = undefined;
                var len: usize = 0;
                if (shell.options.interactive) {
                    flags[len] = 'i';
                    len += 1;
                }
                // TODO: Add flags as options are implemented:
                // 'e' - errexit, 'u' - nounset, 'x' - xtrace, 'v' - verbose,
                // 'f' - noglob, 'C' - noclobber, 'a' - allexport
                const str = try allocator.dupe(u8, flags[0..len]);
                const result = try allocator.alloc(ExpandedPart, 1);
                result[0] = .{ .content = str, .complete = false };
                return result;
            },
            else => {},
        }
    }

    // Positional parameters: $0, $1-$9, ${10}, ${11}, etc.
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

/// Evaluate a parameter expansion and return the expanded parts.
///
/// Handles both regular variables ($VAR, ${VAR}) and special parameters.
/// The `quoted` parameter affects behavior of $@ and $*.
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
        // TODO: Apply modifiers to special parameters (POSIX 2.6.2 allows this)
        if (param.modifier != null) {
            // Currently silently ignored
        }
        return parts;
    }

    // Regular variable lookup
    const value = shell.getVariable(param.name) orelse "";

    // TODO: Apply modifiers (UseDefault, AssignDefault, ErrorIfUnset, UseAlternative,
    // Length, RemoveSmallestPrefix, RemoveLargestPrefix, RemoveSmallestSuffix, RemoveLargestSuffix)
    return makeSinglePart(allocator, value);
}

// ============================================================================
// Core Expansion Logic
// ============================================================================

/// Expand a single Word into the builder, appending to the word list.
///
/// This is the core expansion function that orchestrates all expansion phases
/// and handles word boundary tracking via the `complete` flag.
///
/// POSIX 2.5.2: "$@" expands such that "each positional parameter shall expand
/// as a separate field." Prefix/suffix handling:
///   - Content before $@ attaches to the first parameter
///   - Content after $@ attaches to the last parameter
///   - Example: "prefix$@suffix" with ["a", "b"] -> ["prefixa", "bsuffix"]
fn expandWord(
    builder: *WordBuilder,
    word: Word,
    shell: *const ShellState,
) Allocator.Error!void {
    // Reset word-scoped state for each new Word
    builder.seen_complete = false;

    // Tilde expansion (POSIX 2.6.1)
    const parts = try applyTildeExpansion(builder.allocator, word.parts, shell.home);

    const starting_count = builder.wordCount();
    try builder.startWord();
    var content_added = false;

    for (parts) |part| {
        switch (part) {
            .literal => |lit| {
                try builder.append(lit);
                content_added = true;
            },
            .quoted => |q| {
                try builder.append(q);
                content_added = true;
            },
            .double_quoted => |inner| {
                if (inner.len == 0) {
                    // Empty "" produces one empty word
                    content_added = true;
                } else {
                    if (try expandInnerParts(builder, inner, shell)) {
                        content_added = true;
                    }
                }
            },
            .parameter => |param| {
                // Parameter expansion (POSIX 2.6.2) - unquoted context
                const paramParts = try evaluateParameterExpansion(builder.allocator, shell, param, false);
                if (try builder.appendParts(paramParts)) {
                    content_added = true;
                }
            },
        }
    }

    // Handle "$@" with no params producing zero fields (POSIX 2.5.2)
    if (!content_added) {
        builder.removeTrailingEmpty(starting_count);
    }
}

/// Expand inner parts of a double-quoted region into the builder.
///
/// POSIX 2.5.2: "$@" inside double quotes still produces multiple words.
/// Returns true if any content was added.
fn expandInnerParts(
    builder: *WordBuilder,
    inner: []const WordPart,
    shell: *const ShellState,
) Allocator.Error!bool {
    var content_added = false;

    for (inner) |part| {
        switch (part) {
            .literal => |l| {
                try builder.append(l);
                content_added = true;
            },
            .quoted => |q| {
                try builder.append(q);
                content_added = true;
            },
            .double_quoted => unreachable, // Parser doesn't nest double_quoted
            .parameter => |param| {
                // Parameter expansion in quoted context
                const paramParts = try evaluateParameterExpansion(builder.allocator, shell, param, true);
                if (try builder.appendParts(paramParts)) {
                    content_added = true;
                }
            },
        }
    }

    return content_added;
}

// ============================================================================
// Tests
// ============================================================================

const process = std.process;

// --- Tilde Expansion Tests (POSIX 2.6.1) ---

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

    try std.testing.expectEqual(&parts, result.ptr);
}

test "applyTildeExpansion: no transform when HOME is null" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const parts = [_]WordPart{
        .{ .literal = "~/docs" },
    };

    const result = try applyTildeExpansion(arena.allocator(), &parts, null);

    try std.testing.expectEqual(&parts, result.ptr);
}

test "applyTildeExpansion: no transform for non-tilde literal" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const parts = [_]WordPart{
        .{ .literal = "hello" },
    };

    const result = try applyTildeExpansion(arena.allocator(), &parts, "/home/user");

    try std.testing.expectEqual(&parts, result.ptr);
}

test "applyTildeExpansion: empty parts returns empty" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const parts = [_]WordPart{};

    const result = try applyTildeExpansion(arena.allocator(), &parts, "/home/user");

    try std.testing.expectEqual(@as(usize, 0), result.len);
}

// --- Parameter Expansion Tests (POSIX 2.6.2) ---

test "expandWordJoined: simple variable expansion" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("FOO", "hello");

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

// --- Special Parameter Tests (POSIX 2.5.2) ---

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
    try std.testing.expect(result.len > 0);
    _ = try std.fmt.parseInt(i32, result, 10);
}

test "expandWord: quoted $@ produces multiple words" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{ "a", "b", "c" });

    const inner_parts = [_]WordPart{
        .{ .parameter = .{ .name = "@", .modifier = null } },
    };
    const word = Word{
        .parts = &[_]WordPart{.{ .double_quoted = &inner_parts }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    var builder = WordBuilder.init(arena.allocator());
    try expandWord(&builder, word, &shell);

    try std.testing.expectEqual(@as(usize, 3), builder.wordCount());
    try std.testing.expectEqualStrings("a", builder.buffers.items[0].items);
    try std.testing.expectEqualStrings("b", builder.buffers.items[1].items);
    try std.testing.expectEqualStrings("c", builder.buffers.items[2].items);
}

test "expandWord: quoted $@ with no params produces zero words" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);

    const inner_parts = [_]WordPart{
        .{ .parameter = .{ .name = "@", .modifier = null } },
    };
    const word = Word{
        .parts = &[_]WordPart{.{ .double_quoted = &inner_parts }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    var builder = WordBuilder.init(arena.allocator());
    try expandWord(&builder, word, &shell);

    try std.testing.expectEqual(@as(usize, 0), builder.wordCount());
}

test "expandWord: prefix$@suffix produces correct words" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{ "a", "b" });

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

    var builder = WordBuilder.init(arena.allocator());
    try expandWord(&builder, word, &shell);

    try std.testing.expectEqual(@as(usize, 2), builder.wordCount());
    try std.testing.expectEqualStrings("prefixa", builder.buffers.items[0].items);
    try std.testing.expectEqualStrings("bsuffix", builder.buffers.items[1].items);
}

// --- Word Expansion Integration Tests ---

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
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    try env.put("HOME", "/home/testuser");
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);

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

test "expandWordJoined: double-quoted inner parts concatenated" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    try env.put("HOME", "/home/user");
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);

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

test "expandArgv: echo with $@ produces correct argv" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{ "a", "b", "c" });

    const word1 = Word{
        .parts = &[_]WordPart{.{ .literal = "echo" }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

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

    var argc: usize = 0;
    while (argv[argc] != null) : (argc += 1) {}

    try std.testing.expectEqual(@as(usize, 4), argc);
    try std.testing.expectEqualStrings("echo", std.mem.span(argv[0].?));
    try std.testing.expectEqualStrings("a", std.mem.span(argv[1].?));
    try std.testing.expectEqualStrings("b", std.mem.span(argv[2].?));
    try std.testing.expectEqualStrings("c", std.mem.span(argv[3].?));
}

// --- WordBuilder Unit Tests ---

test "WordBuilder: append creates word if none exists" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var builder = WordBuilder.init(arena.allocator());
    try builder.append("hello");
    try std.testing.expectEqual(@as(usize, 1), builder.wordCount());
}

test "WordBuilder: startWord creates new word" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var builder = WordBuilder.init(arena.allocator());
    try builder.append("first");
    try builder.startWord();
    try builder.append("second");
    try std.testing.expectEqual(@as(usize, 2), builder.wordCount());
}

test "WordBuilder: appendParts handles complete flag" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var builder = WordBuilder.init(arena.allocator());
    const parts = [_]ExpandedPart{
        .{ .content = "a", .complete = true },
        .{ .content = "b", .complete = true },
    };
    _ = try builder.appendParts(&parts);
    try std.testing.expectEqual(@as(usize, 2), builder.wordCount());
}

test "WordBuilder: join with separator" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var builder = WordBuilder.init(arena.allocator());
    try builder.append("one");
    try builder.startWord();
    try builder.append("two");

    const result = try builder.join(" ");
    try std.testing.expectEqualStrings("one two", result);
}

test "WordBuilder: removeTrailingEmpty" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var builder = WordBuilder.init(arena.allocator());
    try builder.startWord(); // empty word
    try std.testing.expectEqual(@as(usize, 1), builder.wordCount());
    builder.removeTrailingEmpty(0);
    try std.testing.expectEqual(@as(usize, 0), builder.wordCount());
}

test "expandArgv: multiple $@ expansions do not leak seen_complete state" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{"x"});

    // echo "$@" bar "$@"
    const word1 = Word{
        .parts = &[_]WordPart{.{ .literal = "echo" }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const inner_parts1 = [_]WordPart{
        .{ .parameter = .{ .name = "@", .modifier = null } },
    };
    const word2 = Word{
        .parts = &[_]WordPart{.{ .double_quoted = &inner_parts1 }},
        .position = 5,
        .line = 1,
        .column = 6,
    };

    const word3 = Word{
        .parts = &[_]WordPart{.{ .literal = "bar" }},
        .position = 10,
        .line = 1,
        .column = 11,
    };

    const inner_parts2 = [_]WordPart{
        .{ .parameter = .{ .name = "@", .modifier = null } },
    };
    const word4 = Word{
        .parts = &[_]WordPart{.{ .double_quoted = &inner_parts2 }},
        .position = 14,
        .line = 1,
        .column = 15,
    };

    const words = [_]Word{ word1, word2, word3, word4 };
    const argv = try expandArgv(arena.allocator(), &words, &shell);

    var argc: usize = 0;
    while (argv[argc] != null) : (argc += 1) {}

    // Expected: ["echo", "x", "bar", "x"] - 4 args, not 5
    try std.testing.expectEqual(@as(usize, 4), argc);
    try std.testing.expectEqualStrings("echo", std.mem.span(argv[0].?));
    try std.testing.expectEqualStrings("x", std.mem.span(argv[1].?));
    try std.testing.expectEqualStrings("bar", std.mem.span(argv[2].?));
    try std.testing.expectEqualStrings("x", std.mem.span(argv[3].?));
}
