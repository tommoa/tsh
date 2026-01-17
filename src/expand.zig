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
//! | Syntax            | Description                              |
//! |-------------------|------------------------------------------|
//! | `${#VAR}`         | Length of value (in characters)          |
//! | `${VAR:-word}`    | Use default if unset or null             |
//! | `${VAR-word}`     | Use default if unset                     |
//! | `${VAR:+word}`    | Use alternative if set and non-null      |
//! | `${VAR+word}`     | Use alternative if set                   |
//! | `${VAR:=word}`    | Assign default if unset or null          |
//! | `${VAR=word}`     | Assign default if unset                  |
//! | `${VAR:?word}`    | Error if unset or null                   |
//! | `${VAR?word}`     | Error if unset                           |
//! | `${VAR#pattern}`  | Remove smallest prefix matching pattern  |
//! | `${VAR##pattern}` | Remove largest prefix matching pattern   |
//! | `${VAR%pattern}`  | Remove smallest suffix matching pattern  |
//! | `${VAR%%pattern}` | Remove largest suffix matching pattern   |
//!
//! ## Quoting Effects on Expansion
//!
//! - **Unquoted**: Subject to field splitting and pathname expansion
//! - **Single-quoted** (`'...'`): No expansion performed
//! - **Double-quoted** (`"..."`): Parameter expansion occurs, but results
//!   are not subject to field splitting or pathname expansion. Exception:
//!   `"$@"` expands to separate fields per POSIX 2.5.2.
//!
//! ## Expansion Part Kinds
//!
//! During expansion, each part is tagged with a Kind that affects later processing:
//!
//! | Kind         | Word Boundary | Field Splitting | Source                      |
//! |--------------|---------------|-----------------|-----------------------------|
//! | `.normal`    | No            | Yes (future)    | Unquoted `$VAR`             |
//! | `.positional`| Conditional*  | No              | `$@` expansion              |
//! | `.quoted`    | No            | No              | `"$VAR"`, literals in `"…"` |
//!
//! *Positional parts create word boundaries between consecutive positional parts,
//! enabling `"$@"` to expand to separate arguments while allowing prefix/suffix
//! attachment (e.g., `"prefix$@suffix"` with `["a","b"]` → `["prefixa", "bsuffix"]`).
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
const pattern = @import("pattern.zig");
const state = @import("state.zig");

const Word = parser.Word;
const WordPart = parser.WordPart;
const ShellState = state.ShellState;
const printError = state.printError;

// ============================================================================
// Expansion Errors
// ============================================================================

/// Errors that can occur during word expansion.
///
/// These errors indicate expansion-time failures that should cause the
/// current command to fail with a non-zero exit status. The error message
/// has already been printed to stderr when these are returned.
///
/// POSIX Reference: Section 2.8.1 - Consequences of Shell Errors
/// "If a non-interactive shell encounters an expansion error, the shell
/// shall write a diagnostic message to standard error and exit with a
/// non-zero status."
pub const ExpansionError = error{
    /// ${parameter:?word} failed because parameter is unset or null.
    /// POSIX 2.6.2: "If parameter is unset or null, the expansion of word
    /// (or a message indicating it is unset if word is omitted) shall be
    /// written to standard error and [...] the shell shall exit."
    /// The error message has already been printed to stderr.
    ParameterUnsetOrNull,
    /// ${parameter:=word} failed because parameter cannot be assigned.
    /// POSIX 2.6.2: "Attempting to assign a value in this way to a readonly
    /// variable or a positional parameter [...] shall cause an expansion error."
    /// This occurs for positional parameters ($1, $2, ...) and special
    /// parameters ($@, $*, $#, $?, etc.).
    /// The error message has already been printed to stderr.
    ParameterAssignmentInvalid,
    /// Command substitution $(command) is not yet implemented.
    CommandSubstitutionNotImplemented,
} || Allocator.Error;

// ============================================================================
// Public API
// ============================================================================

/// Expand an array of Words into a null-terminated argv array for execve.
///
/// Each Word may expand to one or more argv entries (e.g., `"$@"` expands to
/// multiple entries when there are multiple positional parameters).
///
/// This is the primary entry point for command argument expansion.
///
/// Returns ExpansionError.ParameterUnsetOrNull if a ${parameter:?word}
/// expansion fails. The error message is printed to stderr before returning.
pub fn expandArgv(allocator: Allocator, words: []const Word, shell: *ShellState) ExpansionError![:null]const ?[*:0]const u8 {
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
///
/// Returns ExpansionError.ParameterUnsetOrNull if a ${parameter:?word}
/// expansion fails. The error message is printed to stderr before returning.
pub fn expandWordJoined(allocator: Allocator, word: Word, shell: *ShellState) ExpansionError![]const u8 {
    var builder = WordBuilder.init(allocator);
    try expandWord(&builder, word, shell);
    return builder.join(" ");
}

// ============================================================================
// Types
// ============================================================================

/// Intermediate representation of expanded content within a word.
///
/// Each part has a `kind` that determines word boundary behavior and future
/// field splitting:
///
/// - `.normal`: Unquoted content, subject to field splitting (when implemented)
/// - `.positional`: From `$@` expansion, creates word boundaries between
///   consecutive positional parts. Not subject to field splitting.
/// - `.quoted`: From quoted context, not subject to field splitting.
///
/// Word boundary logic (POSIX 2.5.2):
/// - `$@` produces separate fields for each positional parameter
/// - Prefix/suffix attachment: `prefix$@suffix` with ["a","b"] -> ["prefixa", "bsuffix"]
/// - Consecutive positional parts trigger word breaks
///
/// Field splitting behavior (POSIX 2.6.5):
/// - Field splitting applies to parameter expansion, command substitution,
///   and arithmetic expansion results - NOT to tilde expansion or literals.
/// - Content inside double quotes is not subject to field splitting.
/// - Tilde expansion results are "treated as if quoted" (POSIX 2.6.1).
const ExpandedPart = struct {
    content: []const u8,
    kind: Kind,

    const Kind = enum {
        /// Regular unquoted content. Subject to field splitting (when implemented).
        normal,

        /// From $@ expansion. Creates word boundary before this part if previous
        /// part was also positional. Not subject to field splitting.
        positional,

        /// From quoted context ("$VAR", literals in double quotes).
        /// Not subject to field splitting.
        quoted,
    };
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
    /// Tracks whether the last appended part was .positional.
    /// Used to determine if a word break is needed before the next .positional part.
    /// Must be reset to false before expanding each new Word.
    last_was_positional: bool = false,

    const Buffer = std.ArrayListUnmanaged(u8);

    pub fn init(allocator: Allocator) WordBuilder {
        return .{ .allocator = allocator };
    }

    /// Start a new word in the output.
    pub fn startWord(self: *WordBuilder) Allocator.Error!void {
        try self.buffers.append(self.allocator, .{});
    }

    /// Append content to the current word. Starts a new word if none exists.
    ///
    /// Resets `last_was_positional` to false, since appending non-$@ content
    /// interrupts any sequence of positional parts. This ensures that patterns
    /// like "$@ $@" produce correct word boundaries: the space between the two
    /// $@ expansions prevents spurious word breaks.
    ///
    /// Note: When called from `appendParts`, the flag is immediately updated
    /// based on the part's kind, so this reset has no effect in that path.
    pub fn append(self: *WordBuilder, content: []const u8) Allocator.Error!void {
        if (self.buffers.items.len == 0) {
            try self.startWord();
        }
        try self.buffers.items[self.buffers.items.len - 1].appendSlice(self.allocator, content);
        self.last_was_positional = false;
    }

    /// Append expanded parts, handling word boundaries from $@ expansion.
    /// Returns true if any content was added.
    pub fn appendParts(self: *WordBuilder, parts: []const ExpandedPart) Allocator.Error!bool {
        for (parts) |p| {
            if (p.kind == .positional and self.last_was_positional) {
                try self.startWord();
            }
            try self.append(p.content);
            self.last_was_positional = (p.kind == .positional);
        }
        return parts.len > 0;
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

    /// Convert builder contents to ExpandedPart slice.
    /// Used when expansion results need to preserve word boundaries (e.g., modifier words).
    ///
    /// All parts are marked as .positional to preserve word boundaries when the result
    /// is later processed by appendParts. This ensures that $@ in modifier words
    /// (e.g., ${VAR:-$@}) correctly produces separate words.
    pub fn toParts(self: *WordBuilder) Allocator.Error![]ExpandedPart {
        if (self.buffers.items.len == 0) {
            return try self.allocator.alloc(ExpandedPart, 0);
        }

        const parts = try self.allocator.alloc(ExpandedPart, self.buffers.items.len);
        for (self.buffers.items, 0..) |*buf, i| {
            parts[i] = .{
                .content = buf.items,
                .kind = .positional,
            };
        }
        return parts;
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

/// Check if a parameter name is a special parameter or positional parameter.
///
/// POSIX 2.6.2 states that only variables (not positional parameters or special
/// parameters) can be assigned via ${parameter:=word}. This function identifies
/// those parameters that cannot be assigned.
fn isSpecialOrPositional(name: []const u8) bool {
    if (name.len == 0) return false;

    // Single-char special parameters
    if (name.len == 1) {
        return switch (name[0]) {
            '@', '*', '#', '?', '-', '$', '!', '0'...'9' => true,
            else => false,
        };
    }

    // Multi-digit positional parameters (${10}, ${11}, ...)
    for (name) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

/// Create a single-element ExpandedPart array with the specified kind.
fn makeSinglePart(allocator: Allocator, content: []const u8, kind: ExpandedPart.Kind) Allocator.Error![]ExpandedPart {
    const result = try allocator.alloc(ExpandedPart, 1);
    result[0] = .{ .content = content, .kind = kind };
    return result;
}

/// Intermediate result from getting a parameter's base value.
///
/// POSIX 2.6.2 (Parameter Expansion) defines modifiers that can be applied to
/// any parameter. This struct abstracts the difference between special parameters
/// (POSIX 2.5.2) and regular variables, allowing modifiers to be applied uniformly.
const BaseValue = struct {
    /// The expanded parts representing the parameter's value.
    ///
    /// For $@, these are multiple parts with .positional kind (preserving word boundaries).
    /// For $*, this is a single pre-joined part. For regular variables, a single part.
    /// The parts already have the correct Kind set by getSpecialParameter or init,
    /// so callers can return them directly without additional processing.
    parts: []ExpandedPart,
    /// False for unset variables and non-existent positional parameters.
    ///
    /// Note: Special parameters $@, $*, $#, $?, $$, $!, $0 are always considered
    /// "set" per POSIX 2.5.2, even when they expand to empty (e.g., $@ with zero
    /// positional params). This means ${@-default} returns empty (because $@ is
    /// "set"), while ${@:-default} returns "default" (because $@ is empty).
    ///
    /// Shell divergence for $@/$* with zero positional parameters:
    ///   - bash: treats as "unset" (no arguments = nothing is set)
    ///       ${@-def} → "def", ${@+alt} → ""
    ///   - dash/zsh: treats as "set but empty" (per POSIX 2.5.2, special params are always defined)
    ///       ${@-def} → "", ${@+alt} → "alt"
    /// We follow dash/zsh behavior. Both agree when colon is used: ${@:-def} → "def".
    is_set: bool,

    /// Initialize a BaseValue by looking up a parameter (special or regular).
    ///
    /// This abstracts the difference between special parameters and regular
    /// variables, allowing modifiers to be applied uniformly.
    pub fn init(
        allocator: Allocator,
        shell: *const ShellState,
        name: []const u8,
        quoted: bool,
    ) Allocator.Error!BaseValue {
        const kind: ExpandedPart.Kind = if (quoted) .quoted else .normal;

        // Try special parameter first.
        // getSpecialParameter returns null for non-existent positional parameters
        // (e.g., $1 when no args provided), which correctly falls through to the
        // regular variable path where is_set will be false.
        if (try getSpecialParameter(allocator, shell, name, quoted)) |parts| {
            return .{ .parts = parts, .is_set = true };
        }

        // Regular variable
        const raw_value = shell.getVariable(name);
        return .{
            .parts = try makeSinglePart(allocator, raw_value orelse "", kind),
            .is_set = raw_value != null,
        };
    }

    /// Get the scalar string value (joins parts with space if multi-value).
    pub fn getValue(self: *const BaseValue, allocator: Allocator) Allocator.Error![]const u8 {
        if (self.parts.len == 0) return "";
        if (self.parts.len == 1) return self.parts[0].content;
        return joinExpandedParts(allocator, self.parts, " ");
    }

    /// POSIX 2.6.2: "In the parameter expansion forms that use the colon,
    /// the test includes checking whether the parameter is unset or null;
    /// omitting the colon results in a test only for a parameter that is unset."
    ///
    /// When check_null is true (colon present), checks if unset OR empty.
    /// When check_null is false (no colon), only checks if unset.
    pub fn shouldUseDefault(self: *const BaseValue, check_null: bool) bool {
        if (!self.is_set) return true;
        if (!check_null) return false;

        // Check if value is empty (null). For multi-value params like $@,
        // empty means no parts or all parts have zero-length content.
        if (self.parts.len == 0) return true;
        if (self.parts.len == 1) return self.parts[0].content.len == 0;
        for (self.parts) |p| {
            if (p.content.len > 0) return false;
        }
        return true;
    }
};

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
    const kind: ExpandedPart.Kind = if (quoted) .quoted else .normal;

    // Single-character special parameters
    if (name.len == 1) {
        switch (name[0]) {
            '?' => {
                // $? - Exit status of last command
                const result = try allocator.alloc(ExpandedPart, 1);
                const str = try std.fmt.allocPrint(allocator, "{d}", .{shell.last_status.toExitCode()});
                result[0] = .{ .content = str, .kind = kind };
                return result;
            },
            '#' => {
                // $# - Number of positional parameters
                const result = try allocator.alloc(ExpandedPart, 1);
                const str = try std.fmt.allocPrint(allocator, "{d}", .{shell.positional_params.items.len});
                result[0] = .{ .content = str, .kind = kind };
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
                // $@ always uses .positional kind to mark word boundaries
                const parts = try allocator.alloc(ExpandedPart, params.len);
                for (params, 0..) |p, i| {
                    parts[i] = .{ .content = p, .kind = .positional };
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
                        result[0] = .{ .content = "", .kind = .quoted };
                        return result;
                    } else {
                        // $* with no params -> zero fields
                        return try allocator.alloc(ExpandedPart, 0);
                    }
                }
                // TODO: use first char of IFS instead of space
                const joined = try std.mem.join(allocator, " ", params);
                const result = try allocator.alloc(ExpandedPart, 1);
                result[0] = .{ .content = joined, .kind = kind };
                return result;
            },
            '$' => {
                // $$ - PID of shell (cached at startup)
                const result = try allocator.alloc(ExpandedPart, 1);
                const str = try std.fmt.allocPrint(allocator, "{d}", .{shell.pid});
                result[0] = .{ .content = str, .kind = kind };
                return result;
            },
            '!' => {
                // $! - PID of last background command
                // TODO: implement when job control is added
                const result = try allocator.alloc(ExpandedPart, 1);
                result[0] = .{ .content = "", .kind = kind };
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
                result[0] = .{ .content = str, .kind = kind };
                return result;
            },
            else => {},
        }
    }

    // Positional parameters: $0, $1-$9, ${10}, ${11}, etc.
    //
    // POSIX 2.5.2 (Special Parameters) and 2.6.2 (Parameter Expansion):
    // Positional parameters that were never provided are "unset", not "set but null".
    // $0 is always set (the shell name). We return null for non-existent positional
    // parameters so modifiers like ${1:-default} correctly treat them as unset.
    if (std.fmt.parseInt(usize, name, 10)) |idx| {
        if (idx == 0) {
            const result = try allocator.alloc(ExpandedPart, 1);
            result[0] = .{ .content = shell.shell_name, .kind = kind };
            return result;
        } else {
            const params = shell.positional_params.items;
            if (idx <= params.len) {
                const result = try allocator.alloc(ExpandedPart, 1);
                result[0] = .{ .content = params[idx - 1], .kind = kind };
                return result;
            } else {
                // Positional parameter doesn't exist - return null so it's
                // treated as unset (not as "set but null")
                return null;
            }
        }
    } else |_| {}

    return null; // Not a special parameter
}

/// Expand the "word" part of a modifier (e.g., `default` in `${VAR:-default}`).
///
/// The word can contain nested expansions which must be recursively expanded.
/// Returns the expanded parts.
fn expandModifierWord(
    allocator: Allocator,
    shell: *ShellState,
    word_parts: ?[]const parser.WordPart,
) ExpansionError![]ExpandedPart {
    const parts = word_parts orelse return try allocator.alloc(ExpandedPart, 0);

    var builder = WordBuilder.init(allocator);
    _ = try expandInnerParts(&builder, parts, shell);

    return builder.toParts();
}

/// Expand the pattern word for pattern removal modifiers (# ## % %%).
///
/// Similar to expandModifierWord, but returns a single joined string suitable
/// for pattern matching. Pattern characters (*, ?, [, ]) retain their special
/// meaning; only parameter expansions within the pattern are expanded.
fn expandPatternWord(
    allocator: Allocator,
    shell: *ShellState,
    word_parts: []const parser.WordPart,
) ExpansionError![]const u8 {
    var builder = WordBuilder.init(allocator);
    _ = try expandInnerParts(&builder, word_parts, shell);

    // Join all parts into a single pattern string
    return builder.join("");
}

/// Join ExpandedPart array into a single string.
///
/// This is distinct from WordBuilder.join() which operates on word buffers.
/// Used when modifiers need to operate on the joined value of $@ or $*.
fn joinExpandedParts(allocator: Allocator, parts: []const ExpandedPart, sep: []const u8) Allocator.Error![]const u8 {
    if (parts.len == 0) return "";
    if (parts.len == 1) return parts[0].content;

    var total_len: usize = 0;
    for (parts) |p| total_len += p.content.len;
    total_len += sep.len * (parts.len - 1);

    if (total_len == 0) return "";

    const result = try allocator.alloc(u8, total_len);
    var offset: usize = 0;
    for (parts, 0..) |p, i| {
        @memcpy(result[offset..][0..p.content.len], p.content);
        offset += p.content.len;
        if (i < parts.len - 1) {
            @memcpy(result[offset..][0..sep.len], sep);
            offset += sep.len;
        }
    }
    return result;
}

/// Apply a modifier to a parameter value.
///
/// This is the unified modifier application function that handles both single-value
/// parameters (regular variables, $?, $#, $1, etc.) and multi-value parameters ($@, $*).
///
/// The `base` parameter provides the value and metadata, `param_name` is used for
/// error messages and assignment validation.
///
/// The `quoted` parameter determines the Kind for newly-created parts (e.g., length
/// strings, pattern removal results, assigned values). When returning the original
/// value unchanged, we return `base.parts` directly since it already has the correct
/// Kind set by BaseValue.init().
fn applyModifier(
    allocator: Allocator,
    shell: *ShellState,
    base: *const BaseValue,
    mod: parser.ParameterExpansion.Modifier,
    param_name: []const u8,
    quoted: bool,
) ExpansionError![]ExpandedPart {
    const kind: ExpandedPart.Kind = if (quoted) .quoted else .normal;

    switch (mod.op) {
        .Length => {
            // POSIX 2.6.2: ${#parameter} - String length.
            // Returns the length in characters (Unicode codepoints).
            // Note: ${#@} and ${#*} are handled specially in evaluateParameterExpansion
            // to return the count of positional parameters instead.
            const value = try base.getValue(allocator);
            const char_count = std.unicode.utf8CountCodepoints(value) catch value.len;
            const len_str = try std.fmt.allocPrint(allocator, "{d}", .{char_count});
            return makeSinglePart(allocator, len_str, kind);
        },
        .UseDefault => {
            // POSIX 2.6.2: ${parameter:-word} - Use default value.
            // Substitutes word if parameter is unset or null (with colon) or just unset (without).
            if (base.shouldUseDefault(mod.check_null)) {
                return try expandModifierWord(allocator, shell, mod.word);
            }
            return base.parts;
        },
        .UseAlternative => {
            // POSIX 2.6.2: ${parameter:+word} - Use alternative value.
            // Substitutes word if parameter is set and non-null (with colon) or just set (without).
            const use_alt = !base.shouldUseDefault(mod.check_null);
            if (use_alt) {
                return try expandModifierWord(allocator, shell, mod.word);
            }
            return makeSinglePart(allocator, "", kind);
        },
        .AssignDefault => {
            // POSIX 2.6.2: ${parameter:=word} - Assign default value.
            // Assigns word to parameter and substitutes if unset or null (with colon) or just unset (without).
            if (base.shouldUseDefault(mod.check_null)) {
                // POSIX 2.6.2: Cannot assign to special or positional parameters
                if (isSpecialOrPositional(param_name)) {
                    printError("{s}: cannot assign in this way\n", .{param_name});
                    return ExpansionError.ParameterAssignmentInvalid;
                }

                // Expand the modifier word and join with space
                const word_value = if (mod.word) |parts| blk: {
                    var builder = WordBuilder.init(allocator);
                    _ = try expandInnerParts(&builder, parts, shell);
                    break :blk try builder.join(" ");
                } else "";

                try shell.setVariable(param_name, word_value);
                return makeSinglePart(allocator, word_value, kind);
            }
            return base.parts;
        },
        .ErrorIfUnset => {
            // POSIX 2.6.2: ${parameter:?word} - Error if null or unset.
            // Displays error and exits if parameter is unset or null (with colon) or just unset (without).
            if (base.shouldUseDefault(mod.check_null)) {
                const msg = if (mod.word) |word_parts| blk: {
                    var builder = WordBuilder.init(allocator);
                    _ = try expandInnerParts(&builder, word_parts, shell);
                    break :blk try builder.join(" ");
                } else "";

                const display_msg = if (msg.len > 0) msg else "parameter null or not set";
                printError("{s}: {s}\n", .{ param_name, display_msg });
                return ExpansionError.ParameterUnsetOrNull;
            }
            return base.parts;
        },
        .RemoveSmallestPrefix, .RemoveLargestPrefix, .RemoveSmallestSuffix, .RemoveLargestSuffix => {
            // Pattern removal operates on the joined value.
            //
            // POSIX 2.6.2 note: The behavior of ${@#pattern}, ${*#pattern}, etc.
            // is unspecified. Implementations vary:
            //   - bash: applies pattern to each positional parameter separately
            //   - dash: ignores the pattern modifier entirely
            //   - tsh: joins with space, applies pattern once to the result
            //
            // TODO: Consider matching bash behavior (apply to each element)
            // for better script compatibility.
            const value = try base.getValue(allocator);
            return applyPatternModifier(allocator, shell, value, mod, kind);
        },
    }
}

/// POSIX 2.6.2: Apply pattern removal modifiers to a single value.
///   ${parameter#word}  - Remove smallest prefix matching word
///   ${parameter##word} - Remove largest prefix matching word
///   ${parameter%word}  - Remove smallest suffix matching word
///   ${parameter%%word} - Remove largest suffix matching word
fn applyPatternModifier(
    allocator: Allocator,
    shell: *ShellState,
    value: []const u8,
    mod: parser.ParameterExpansion.Modifier,
    kind: ExpandedPart.Kind,
) ExpansionError![]ExpandedPart {
    switch (mod.op) {
        .RemoveSmallestPrefix => {
            const word_parts = mod.word orelse return makeSinglePart(allocator, value, kind);
            const pat = try expandPatternWord(allocator, shell, word_parts);
            var pos: usize = 0;
            while (pos <= value.len) {
                if (pattern.match(pat, value[0..pos])) {
                    return makeSinglePart(allocator, value[pos..], kind);
                }
                if (pos >= value.len) break;
                pos += pattern.codepointLen(value, pos);
            }
            return makeSinglePart(allocator, value, kind);
        },
        .RemoveLargestPrefix => {
            const word_parts = mod.word orelse return makeSinglePart(allocator, value, kind);
            const pat = try expandPatternWord(allocator, shell, word_parts);
            var pos: usize = value.len;
            while (true) {
                if (pattern.match(pat, value[0..pos])) {
                    return makeSinglePart(allocator, value[pos..], kind);
                }
                if (pos == 0) break;
                pos = prevCodepointPos(value, pos);
            }
            return makeSinglePart(allocator, value, kind);
        },
        .RemoveSmallestSuffix => {
            const word_parts = mod.word orelse return makeSinglePart(allocator, value, kind);
            const pat = try expandPatternWord(allocator, shell, word_parts);
            var pos: usize = value.len;
            while (true) {
                if (pattern.match(pat, value[pos..])) {
                    return makeSinglePart(allocator, value[0..pos], kind);
                }
                if (pos == 0) break;
                pos = prevCodepointPos(value, pos);
            }
            return makeSinglePart(allocator, value, kind);
        },
        .RemoveLargestSuffix => {
            const word_parts = mod.word orelse return makeSinglePart(allocator, value, kind);
            const pat = try expandPatternWord(allocator, shell, word_parts);
            var pos: usize = 0;
            while (pos <= value.len) {
                if (pattern.match(pat, value[pos..])) {
                    return makeSinglePart(allocator, value[0..pos], kind);
                }
                if (pos >= value.len) break;
                pos += pattern.codepointLen(value, pos);
            }
            return makeSinglePart(allocator, value, kind);
        },
        else => unreachable, // Non-pattern modifiers are handled by applyModifier
    }
}

/// Step backward to the previous codepoint boundary.
/// Returns the byte position of the previous codepoint start.
fn prevCodepointPos(bytes: []const u8, pos: usize) usize {
    if (pos == 0) return 0;
    var i = pos - 1;
    // UTF-8 continuation bytes have the form 10xxxxxx (0x80-0xBF)
    // Walk back until we find a non-continuation byte
    while (i > 0 and (bytes[i] & 0xC0) == 0x80) : (i -= 1) {}
    return i;
}

/// Evaluate a parameter expansion and return the expanded parts.
///
/// Handles both regular variables ($VAR, ${VAR}) and special parameters ($@, $*, $?, $#, etc.).
/// Modifiers (:-default, :+alt, :=assign, :?error, #pattern, %pattern) are applied to all
/// parameter types per POSIX 2.6.2.
///
/// The `quoted` parameter affects behavior of $@ and $*:
/// - Quoted "$@" produces separate words for each positional parameter
/// - Quoted "$*" joins all parameters with IFS[0] (currently space)
///
/// Special cases:
/// - ${#@} and ${#*} return the count of positional parameters (equivalent to $#)
/// - Assignment modifiers (:=) error on special/positional parameters per POSIX
///
/// Returns ExpansionError.ParameterUnsetOrNull if a ${parameter:?word}
/// expansion fails. The error message is printed to stderr before returning.
fn evaluateParameterExpansion(
    allocator: Allocator,
    shell: *ShellState,
    param: parser.ParameterExpansion,
    quoted: bool,
) ExpansionError![]ExpandedPart {
    const kind: ExpandedPart.Kind = if (quoted) .quoted else .normal;

    // Handle ${#@} and ${#*} specially - returns count of positional parameters.
    //
    // POSIX 2.6.2 (Parameter Expansion) states:
    //   "${#parameter} - String Length. [...] If parameter is '*' or '@',
    //    the result of the expansion is unspecified."
    //
    // We follow bash/zsh behavior (return count), while dash returns the
    // length of the joined string. Example with `set -- abc def`:
    //   - bash/zsh: ${#@} → 2 (count of parameters)
    //   - dash:     ${#@} → 7 (length of "abc def")
    if (param.modifier) |mod| {
        if (mod.op == .Length) {
            if (std.mem.eql(u8, param.name, "@") or std.mem.eql(u8, param.name, "*")) {
                const count = shell.positional_params.items.len;
                const count_str = try std.fmt.allocPrint(allocator, "{d}", .{count});
                return makeSinglePart(allocator, count_str, kind);
            }
        }
    }

    // Get base value - works for both special and regular parameters
    const base = try BaseValue.init(allocator, shell, param.name, quoted);

    // No modifier - just return the base value
    if (param.modifier == null) {
        return base.parts;
    }

    // Apply the modifier using the unified modifier handling
    return applyModifier(allocator, shell, &base, param.modifier.?, param.name, quoted);
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
    shell: *ShellState,
) ExpansionError!void {
    // Reset word-scoped state for each new Word
    builder.last_was_positional = false;

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
            .command_sub => {
                // Command substitution (POSIX 2.6.3) - not yet implemented
                // TODO: Execute the command in a subshell and capture stdout
                return error.CommandSubstitutionNotImplemented;
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
    shell: *ShellState,
) ExpansionError!bool {
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
            .command_sub => {
                // Command substitution (POSIX 2.6.3) - not yet implemented
                return error.CommandSubstitutionNotImplemented;
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

test "expandWord: $@ space $@ produces correct word boundaries" {
    // POSIX: "$@ $@" should join the last param of first $@ with the space
    // and first param of second $@. The space interrupts the positional sequence.
    // With params ["a", "b"]: "$@ $@" -> ["a", "b a", "b"]
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{ "a", "b" });

    const inner_parts = [_]WordPart{
        .{ .parameter = .{ .name = "@", .modifier = null } },
        .{ .literal = " " },
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

    // Expected: ["a", "b a", "b"] - the space joins "b" and "a"
    try std.testing.expectEqual(@as(usize, 3), builder.wordCount());
    try std.testing.expectEqualStrings("a", builder.buffers.items[0].items);
    try std.testing.expectEqualStrings("b a", builder.buffers.items[1].items);
    try std.testing.expectEqualStrings("b", builder.buffers.items[2].items);
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

test "WordBuilder: appendParts handles positional kind" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var builder = WordBuilder.init(arena.allocator());
    const parts = [_]ExpandedPart{
        .{ .content = "a", .kind = .positional },
        .{ .content = "b", .kind = .positional },
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

test "expandArgv: multiple $@ expansions do not leak last_was_positional state" {
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

// --- Parameter Expansion Modifier Tests (POSIX 2.6.2) ---

// Length modifier tests: ${#VAR}

test "modifier: ${#VAR} returns length" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "hello");

    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .Length, .check_null = false, .word = null },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("5", result);
}

test "modifier: ${#VAR} with empty string returns 0" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "");

    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .Length, .check_null = false, .word = null },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("0", result);
}

test "modifier: ${#VAR} with unset variable returns 0" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // VAR is not set

    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .Length, .check_null = false, .word = null },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("0", result);
}

test "modifier: ${#VAR} counts UTF-8 codepoints not bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // "日本" is 2 characters but 6 bytes in UTF-8
    try shell.setVariable("VAR", "日本");

    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .Length, .check_null = false, .word = null },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    // POSIX requires character count, not byte count
    try std.testing.expectEqualStrings("2", result);
}

test "modifier: ${#VAR} with mixed ASCII and UTF-8" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // "Hello, 世界!" is 10 characters (7 ASCII + 2 CJK + 1 ASCII)
    try shell.setVariable("VAR", "Hello, 世界!");

    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .Length, .check_null = false, .word = null },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("10", result);
}

// UseDefault modifier tests: ${VAR:-word} and ${VAR-word}

test "modifier: ${VAR:-default} with unset VAR returns default" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // VAR is not set

    const default_word = [_]WordPart{.{ .literal = "default" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .UseDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("default", result);
}

test "modifier: ${VAR:-default} with empty VAR returns default" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "");

    const default_word = [_]WordPart{.{ .literal = "default" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .UseDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("default", result);
}

test "modifier: ${VAR:-default} with set VAR returns value" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "value");

    const default_word = [_]WordPart{.{ .literal = "default" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .UseDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("value", result);
}

test "modifier: ${VAR-default} with empty VAR returns empty (no colon)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "");

    const default_word = [_]WordPart{.{ .literal = "default" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .UseDefault, .check_null = false, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    // Without colon, only unset triggers default. VAR is set (to empty), so empty is returned.
    try std.testing.expectEqualStrings("", result);
}

// --- ErrorIfUnset modifier tests: ${VAR:?word} and ${VAR?word} ---

test "modifier: ${VAR:?} returns error with default message when unset" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // VAR is not set

    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .ErrorIfUnset, .check_null = true, .word = null },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectError(ExpansionError.ParameterUnsetOrNull, result);
}

test "modifier: ${VAR:?custom message} returns error with custom message when unset" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // VAR is not set

    const msg_word = [_]WordPart{.{ .literal = "custom message" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .ErrorIfUnset, .check_null = true, .word = &msg_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectError(ExpansionError.ParameterUnsetOrNull, result);
}

test "modifier: ${VAR:?} returns error when empty" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "");

    const msg_word = [_]WordPart{.{ .literal = "error" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .ErrorIfUnset, .check_null = true, .word = &msg_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectError(ExpansionError.ParameterUnsetOrNull, result);
}

test "modifier: ${VAR?} does not error when empty (no colon)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "");

    const msg_word = [_]WordPart{.{ .literal = "error" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .ErrorIfUnset, .check_null = false, .word = &msg_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    // Without colon, only checks if unset, not if null/empty
    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("", result);
}

test "modifier: ${VAR:?} returns value when set" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "value");

    const msg_word = [_]WordPart{.{ .literal = "error" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .ErrorIfUnset, .check_null = true, .word = &msg_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("value", result);
}

test "modifier: ${VAR:?${MSG}} expands error message" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("MSG", "expanded error");
    // VAR is not set

    const msg_word = [_]WordPart{.{ .parameter = .{ .name = "MSG", .modifier = null } }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .ErrorIfUnset, .check_null = true, .word = &msg_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectError(ExpansionError.ParameterUnsetOrNull, result);
}

test "modifier: ${VAR?} errors when unset (no colon)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // VAR is not set

    const msg_word = [_]WordPart{.{ .literal = "error" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .ErrorIfUnset, .check_null = false, .word = &msg_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectError(ExpansionError.ParameterUnsetOrNull, result);
}

test "modifier: expansion error prevents subsequent expansions in argv" {
    // When ${VAR:?} fails, the rest of the command should not be expanded
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // VAR is not set

    // First word has the failing expansion
    const word1 = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .ErrorIfUnset, .check_null = true, .word = null },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    // Second word should not be expanded
    const word2 = Word{
        .parts = &[_]WordPart{.{ .literal = "should not appear" }},
        .position = 10,
        .line = 1,
        .column = 11,
    };

    const words = [_]Word{ word1, word2 };
    const result = expandArgv(arena.allocator(), &words, &shell);
    try std.testing.expectError(ExpansionError.ParameterUnsetOrNull, result);
}

// --- Tests for ErrorIfUnset with nested error expansion ---

test "modifier: ${A:?${B:?nested}} nested error expansion evaluates inner first" {
    // POSIX: The word operand is expanded before use. If the nested expansion
    // also fails with :?, its error is printed first and propagates.
    // This matches dash and bash behavior.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // Neither A nor B is set

    const inner_msg = [_]WordPart{.{ .literal = "inner error" }};
    const nested_word = [_]WordPart{.{ .parameter = .{
        .name = "B",
        .modifier = .{ .op = .ErrorIfUnset, .check_null = true, .word = &inner_msg },
    } }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "A",
            .modifier = .{ .op = .ErrorIfUnset, .check_null = true, .word = &nested_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    // The nested ${B:?inner error} is evaluated first and fails
    const result = expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectError(ExpansionError.ParameterUnsetOrNull, result);
}

test "modifier: ${VAR-default} with unset VAR returns default (no colon)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // VAR is not set

    const default_word = [_]WordPart{.{ .literal = "default" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .UseDefault, .check_null = false, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("default", result);
}

test "modifier: ${VAR:-${OTHER}} nested expansion" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("OTHER", "fallback");
    // VAR is not set

    const default_word = [_]WordPart{.{ .parameter = .{ .name = "OTHER", .modifier = null } }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .UseDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("fallback", result);
}

// UseAlternative modifier tests: ${VAR:+word} and ${VAR+word}

test "modifier: ${VAR:+alt} with unset VAR returns empty" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // VAR is not set

    const alt_word = [_]WordPart{.{ .literal = "alt" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .UseAlternative, .check_null = true, .word = &alt_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("", result);
}

test "modifier: ${VAR:+alt} with empty VAR returns empty" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "");

    const alt_word = [_]WordPart{.{ .literal = "alt" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .UseAlternative, .check_null = true, .word = &alt_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("", result);
}

test "modifier: ${VAR:+alt} with set VAR returns alt" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "value");

    const alt_word = [_]WordPart{.{ .literal = "alt" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .UseAlternative, .check_null = true, .word = &alt_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("alt", result);
}

test "modifier: ${VAR+alt} with empty VAR returns alt (no colon)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "");

    const alt_word = [_]WordPart{.{ .literal = "alt" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .UseAlternative, .check_null = false, .word = &alt_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    // Without colon, only checks if set (not if null)
    try std.testing.expectEqualStrings("alt", result);
}

test "modifier: ${VAR+alt} with unset VAR returns empty (no colon)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // VAR is not set

    const alt_word = [_]WordPart{.{ .literal = "alt" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .UseAlternative, .check_null = false, .word = &alt_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("", result);
}

// --- Word Boundary Preservation in Modifier Words ---

test "modifier: ${VAR:-$@} with unset VAR expands to multiple words" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{ "a", "b" });
    // VAR is not set

    const default_word = [_]WordPart{.{ .parameter = .{ .name = "@", .modifier = null } }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .UseDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    // Use expandArgv to test word splitting behavior
    const argv = try expandArgv(arena.allocator(), &[_]Word{word}, &shell);
    var argc: usize = 0;
    while (argv[argc] != null) : (argc += 1) {}

    try std.testing.expectEqual(@as(usize, 2), argc);
    try std.testing.expectEqualStrings("a", std.mem.span(argv[0].?));
    try std.testing.expectEqualStrings("b", std.mem.span(argv[1].?));
}

test "modifier: ${VAR:-$@} with single positional param" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{"x"});
    // VAR is not set

    const default_word = [_]WordPart{.{ .parameter = .{ .name = "@", .modifier = null } }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .UseDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const argv = try expandArgv(arena.allocator(), &[_]Word{word}, &shell);
    var argc: usize = 0;
    while (argv[argc] != null) : (argc += 1) {}

    try std.testing.expectEqual(@as(usize, 1), argc);
    try std.testing.expectEqualStrings("x", std.mem.span(argv[0].?));
}

test "modifier: ${VAR:-$@} with no positional params" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // No positional params, VAR is not set

    const default_word = [_]WordPart{.{ .parameter = .{ .name = "@", .modifier = null } }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .UseDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const argv = try expandArgv(arena.allocator(), &[_]Word{word}, &shell);
    var argc: usize = 0;
    while (argv[argc] != null) : (argc += 1) {}

    // With no positional params, $@ produces zero fields
    try std.testing.expectEqual(@as(usize, 0), argc);
}

test "modifier: ${VAR:-prefix$@suffix} attaches prefix and suffix" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{ "a", "b" });
    // VAR is not set

    const default_word = [_]WordPart{
        .{ .literal = "prefix" },
        .{ .parameter = .{ .name = "@", .modifier = null } },
        .{ .literal = "suffix" },
    };
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .UseDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const argv = try expandArgv(arena.allocator(), &[_]Word{word}, &shell);
    var argc: usize = 0;
    while (argv[argc] != null) : (argc += 1) {}

    try std.testing.expectEqual(@as(usize, 2), argc);
    try std.testing.expectEqualStrings("prefixa", std.mem.span(argv[0].?));
    try std.testing.expectEqualStrings("bsuffix", std.mem.span(argv[1].?));
}

test "modifier: ${VAR:+$@} with set VAR expands to multiple words" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{ "a", "b" });
    try shell.setVariable("VAR", "value");

    const alt_word = [_]WordPart{.{ .parameter = .{ .name = "@", .modifier = null } }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .UseAlternative, .check_null = true, .word = &alt_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const argv = try expandArgv(arena.allocator(), &[_]Word{word}, &shell);
    var argc: usize = 0;
    while (argv[argc] != null) : (argc += 1) {}

    try std.testing.expectEqual(@as(usize, 2), argc);
    try std.testing.expectEqualStrings("a", std.mem.span(argv[0].?));
    try std.testing.expectEqualStrings("b", std.mem.span(argv[1].?));
}

test "modifier: ${VAR:-$OTHER} returns single word (regression)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("OTHER", "value");
    // VAR is not set

    const default_word = [_]WordPart{.{ .parameter = .{ .name = "OTHER", .modifier = null } }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .UseDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const argv = try expandArgv(arena.allocator(), &[_]Word{word}, &shell);
    var argc: usize = 0;
    while (argv[argc] != null) : (argc += 1) {}

    // Regular variable should produce single word, not split
    try std.testing.expectEqual(@as(usize, 1), argc);
    try std.testing.expectEqualStrings("value", std.mem.span(argv[0].?));
}

test "modifier: ${VAR:-$@} with set VAR returns VAR value" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{ "a", "b" });
    try shell.setVariable("VAR", "myvalue");

    const default_word = [_]WordPart{.{ .parameter = .{ .name = "@", .modifier = null } }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .UseDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const argv = try expandArgv(arena.allocator(), &[_]Word{word}, &shell);
    var argc: usize = 0;
    while (argv[argc] != null) : (argc += 1) {}

    // VAR is set, so its value is used, not $@
    try std.testing.expectEqual(@as(usize, 1), argc);
    try std.testing.expectEqualStrings("myvalue", std.mem.span(argv[0].?));
}

// --- AssignDefault modifier tests: ${VAR:=word} and ${VAR=word} ---

test "modifier: ${VAR:=default} assigns and returns default when unset" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // VAR is not set

    const default_word = [_]WordPart{.{ .literal = "default" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .AssignDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("default", result);

    // Verify VAR is now set
    try std.testing.expectEqualStrings("default", shell.getVariable("VAR").?);
}

test "modifier: ${VAR:=default} assigns and returns default when empty" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "");

    const default_word = [_]WordPart{.{ .literal = "default" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .AssignDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("default", result);

    // Verify VAR is now "default"
    try std.testing.expectEqualStrings("default", shell.getVariable("VAR").?);
}

test "modifier: ${VAR:=default} returns existing value when set" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "existing");

    const default_word = [_]WordPart{.{ .literal = "default" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .AssignDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("existing", result);

    // Verify VAR is unchanged
    try std.testing.expectEqualStrings("existing", shell.getVariable("VAR").?);
}

test "modifier: ${VAR=default} does not assign when empty (no colon)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "");

    const default_word = [_]WordPart{.{ .literal = "default" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .AssignDefault, .check_null = false, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    // Without colon, empty is considered "set", so returns empty
    try std.testing.expectEqualStrings("", result);

    // Verify VAR is still empty (not assigned)
    try std.testing.expectEqualStrings("", shell.getVariable("VAR").?);
}

test "modifier: ${VAR:=default} assignment persists" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // VAR is not set

    // First expansion: ${VAR:=first}
    const first_word = [_]WordPart{.{ .literal = "first" }};
    const word1 = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .AssignDefault, .check_null = true, .word = &first_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result1 = try expandWordJoined(arena.allocator(), word1, &shell);
    try std.testing.expectEqualStrings("first", result1);

    // Second expansion: ${VAR:=second} - should return "first" since VAR is now set
    const second_word = [_]WordPart{.{ .literal = "second" }};
    const word2 = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .AssignDefault, .check_null = true, .word = &second_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result2 = try expandWordJoined(arena.allocator(), word2, &shell);
    try std.testing.expectEqualStrings("first", result2);
}

test "modifier: ${VAR:=${OTHER}} nested expansion in default" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("OTHER", "fallback");
    // VAR is not set

    const default_word = [_]WordPart{.{ .parameter = .{ .name = "OTHER", .modifier = null } }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .AssignDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("fallback", result);

    // Verify VAR is now "fallback"
    try std.testing.expectEqualStrings("fallback", shell.getVariable("VAR").?);
}

test "modifier: ${VAR:=$@} assigns positional parameters joined with space" {
    // POSIX: In assignment context, $@ expands to positional parameters
    // joined with space (like $* behavior in assignment contexts).
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{ "arg1", "arg2", "arg3" });
    // VAR is not set

    const default_word = [_]WordPart{.{ .parameter = .{ .name = "@", .modifier = null } }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .AssignDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    // Positional parameters should be joined with space
    try std.testing.expectEqualStrings("arg1 arg2 arg3", result);

    // Verify VAR is now "arg1 arg2 arg3"
    try std.testing.expectEqualStrings("arg1 arg2 arg3", shell.getVariable("VAR").?);
}

test "isSpecialOrPositional: identifies special parameters" {
    try std.testing.expect(isSpecialOrPositional("@"));
    try std.testing.expect(isSpecialOrPositional("*"));
    try std.testing.expect(isSpecialOrPositional("#"));
    try std.testing.expect(isSpecialOrPositional("?"));
    try std.testing.expect(isSpecialOrPositional("-"));
    try std.testing.expect(isSpecialOrPositional("$"));
    try std.testing.expect(isSpecialOrPositional("!"));
    try std.testing.expect(isSpecialOrPositional("0"));
    try std.testing.expect(isSpecialOrPositional("1"));
    try std.testing.expect(isSpecialOrPositional("9"));
}

test "isSpecialOrPositional: identifies multi-digit positional parameters" {
    try std.testing.expect(isSpecialOrPositional("10"));
    try std.testing.expect(isSpecialOrPositional("11"));
    try std.testing.expect(isSpecialOrPositional("99"));
    try std.testing.expect(isSpecialOrPositional("123"));
}

test "isSpecialOrPositional: rejects regular variable names" {
    try std.testing.expect(!isSpecialOrPositional("VAR"));
    try std.testing.expect(!isSpecialOrPositional("FOO"));
    try std.testing.expect(!isSpecialOrPositional("HOME"));
    try std.testing.expect(!isSpecialOrPositional("PATH"));
    try std.testing.expect(!isSpecialOrPositional("a"));
    try std.testing.expect(!isSpecialOrPositional("_"));
    try std.testing.expect(!isSpecialOrPositional("VAR1"));
    try std.testing.expect(!isSpecialOrPositional("1VAR")); // starts with digit but has non-digit
}

test "isSpecialOrPositional: empty string returns false" {
    try std.testing.expect(!isSpecialOrPositional(""));
}

// --- Tests for AssignDefault with special/positional parameters ---

test "modifier: ${1:=default} with set positional returns current value" {
    // When $1 is already set, the :=default modifier doesn't trigger assignment
    // (the parameter is neither unset nor null). The current value is returned.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{"first_arg"});

    const default_word = [_]WordPart{.{ .literal = "default" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "1",
            .modifier = .{ .op = .AssignDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    // $1 is set, so the current value is returned without attempting assignment
    try std.testing.expectEqualStrings("first_arg", result);
}

test "modifier: ${1:=default} with unset positional returns error" {
    // POSIX 2.6.2: Cannot assign to positional parameters.
    // "Attempting to assign a value in this way to a readonly variable or a
    // positional parameter shall cause an expansion error."
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // No positional parameters set

    const default_word = [_]WordPart{.{ .literal = "default" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "1",
            .modifier = .{ .op = .AssignDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    // Should error because you cannot assign to positional parameters
    const result = expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectError(ExpansionError.ParameterAssignmentInvalid, result);
}

test "modifier: ${10:=default} with set multi-digit positional returns current value" {
    // When ${10} is already set, the :=default modifier doesn't trigger assignment
    // (the parameter is neither unset nor null). The current value is returned.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // Set 10 positional parameters so $10 would be "tenth"
    try shell.setPositionalParams(&[_][]const u8{ "1", "2", "3", "4", "5", "6", "7", "8", "9", "tenth" });

    const default_word = [_]WordPart{.{ .literal = "default" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "10",
            .modifier = .{ .op = .AssignDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    // $10 is set, so the current value is returned without attempting assignment
    try std.testing.expectEqualStrings("tenth", result);
}

test "modifier: ${10:=default} with unset multi-digit positional returns error" {
    // POSIX 2.6.2: Cannot assign to positional parameters.
    // "Attempting to assign a value in this way to a readonly variable or a
    // positional parameter shall cause an expansion error."
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // Only 2 positional parameters, so $10 is unset
    try shell.setPositionalParams(&[_][]const u8{ "first", "second" });

    const default_word = [_]WordPart{.{ .literal = "default" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "10",
            .modifier = .{ .op = .AssignDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    // Should error because you cannot assign to positional parameters
    const result = expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectError(ExpansionError.ParameterAssignmentInvalid, result);
}

// --- Pattern Removal Modifier Tests (POSIX 2.6.2) ---

test "modifier: ${VAR#pattern} removes smallest prefix" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "/home/user/file.txt");

    // ${VAR#*/} -> home/user/file.txt (remove smallest prefix matching */)
    const pattern_word = [_]WordPart{.{ .literal = "*/" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .RemoveSmallestPrefix, .check_null = false, .word = &pattern_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("home/user/file.txt", result);
}

test "modifier: ${VAR##pattern} removes largest prefix" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "/home/user/file.txt");

    // ${VAR##*/} -> file.txt (remove largest prefix matching */)
    const pattern_word = [_]WordPart{.{ .literal = "*/" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .RemoveLargestPrefix, .check_null = false, .word = &pattern_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("file.txt", result);
}

test "modifier: ${VAR%pattern} removes smallest suffix" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "/home/user/file.txt");

    // ${VAR%/*} -> /home/user (remove smallest suffix matching /*)
    const pattern_word = [_]WordPart{.{ .literal = "/*" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .RemoveSmallestSuffix, .check_null = false, .word = &pattern_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("/home/user", result);
}

test "modifier: ${VAR%%pattern} removes largest suffix" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "/home/user/file.txt");

    // ${VAR%%/*} -> "" (remove largest suffix matching /*)
    const pattern_word = [_]WordPart{.{ .literal = "/*" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .RemoveLargestSuffix, .check_null = false, .word = &pattern_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("", result);
}

test "modifier: ${VAR#pattern} with no match returns unchanged" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "hello");

    // ${VAR#x*} -> hello (no match, unchanged)
    const pattern_word = [_]WordPart{.{ .literal = "x*" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .RemoveSmallestPrefix, .check_null = false, .word = &pattern_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("hello", result);
}

test "modifier: ${VAR%.*} removes extension" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "file.tar.gz");

    // ${VAR%.*} -> file.tar (remove smallest suffix matching .*)
    const pattern_word = [_]WordPart{.{ .literal = ".*" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .RemoveSmallestSuffix, .check_null = false, .word = &pattern_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("file.tar", result);
}

test "modifier: ${VAR%%.*} removes all extensions" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "file.tar.gz");

    // ${VAR%%.*} -> file (remove largest suffix matching .*)
    const pattern_word = [_]WordPart{.{ .literal = ".*" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .RemoveLargestSuffix, .check_null = false, .word = &pattern_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("file", result);
}

test "modifier: ${VAR##*.} extracts extension" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "file.tar.gz");

    // ${VAR##*.} -> gz (remove largest prefix matching *.)
    const pattern_word = [_]WordPart{.{ .literal = "*." }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .RemoveLargestPrefix, .check_null = false, .word = &pattern_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("gz", result);
}

test "modifier: ${VAR#pattern} with bracket expression" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "abc123");

    // ${VAR#[a-z]} -> bc123 (remove one lowercase letter)
    const pattern_word = [_]WordPart{.{ .literal = "[a-z]" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .RemoveSmallestPrefix, .check_null = false, .word = &pattern_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("bc123", result);
}

test "modifier: ${VAR#[a-z]*} removes all matching pattern" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "abc123");

    // ${VAR#[a-z]*} -> "" (a followed by zero-or-more matches the shortest, which is just "a")
    // Actually: [a-z]* matches "a" (one letter + zero more), so result should be "bc123"
    const pattern_word = [_]WordPart{.{ .literal = "[a-z]*" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .RemoveSmallestPrefix, .check_null = false, .word = &pattern_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    // [a-z]* will match "a" (the smallest match starting at position 0)
    try std.testing.expectEqualStrings("bc123", result);
}

test "modifier: ${VAR##[a-z]*} removes largest matching pattern" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "abc123");

    // ${VAR##[a-z]*} -> "" (largest prefix matching [a-z]* is entire string)
    const pattern_word = [_]WordPart{.{ .literal = "[a-z]*" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .RemoveLargestPrefix, .check_null = false, .word = &pattern_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    // [a-z]* matches the entire "abc123" as the largest match
    try std.testing.expectEqualStrings("", result);
}

test "modifier: ${VAR#} with no pattern returns unchanged" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "hello");

    // ${VAR#} with null pattern word -> unchanged
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .RemoveSmallestPrefix, .check_null = false, .word = null },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("hello", result);
}

test "modifier: ${VAR#pattern} with nested expansion" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "/home/user/file.txt");
    try shell.setVariable("SEP", "/");

    // ${VAR#*$SEP} -> home/user/file.txt (pattern is "*" + value of SEP)
    const pattern_word = [_]WordPart{
        .{ .literal = "*" },
        .{ .parameter = .{ .name = "SEP", .modifier = null } },
    };
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .RemoveSmallestPrefix, .check_null = false, .word = &pattern_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("home/user/file.txt", result);
}

test "modifier: ${VAR#https://} strips URL prefix" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("URL", "https://example.com/path");

    // ${URL#https://} -> example.com/path
    const pattern_word = [_]WordPart{.{ .literal = "https://" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "URL",
            .modifier = .{ .op = .RemoveSmallestPrefix, .check_null = false, .word = &pattern_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("example.com/path", result);
}

test "modifier: ${VAR%pattern} with empty value" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "");

    // ${VAR%*} -> "" (empty value stays empty)
    const pattern_word = [_]WordPart{.{ .literal = "*" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .RemoveSmallestSuffix, .check_null = false, .word = &pattern_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("", result);
}

test "modifier: ${VAR%?} removes last character" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "hello");

    // ${VAR%?} -> hell (remove last character)
    const pattern_word = [_]WordPart{.{ .literal = "?" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .RemoveSmallestSuffix, .check_null = false, .word = &pattern_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("hell", result);
}

test "modifier: ${VAR#?} removes first character" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "hello");

    // ${VAR#?} -> ello (remove first character)
    const pattern_word = [_]WordPart{.{ .literal = "?" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .RemoveSmallestPrefix, .check_null = false, .word = &pattern_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("ello", result);
}

// --- UTF-8 Pattern Matching Tests ---
// These tests verify that pattern removal operates on Unicode codepoints,
// not bytes, matching bash/zsh behavior and POSIX "character" semantics.

test "modifier: ${VAR#?} with UTF-8 removes first codepoint" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // "日本語" is 3 codepoints, 9 bytes (3 bytes each)
    try shell.setVariable("VAR", "日本語");

    // ${VAR#?} -> "本語" (remove first codepoint, not first byte)
    const pattern_word = [_]WordPart{.{ .literal = "?" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .RemoveSmallestPrefix, .check_null = false, .word = &pattern_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("本語", result);
}

test "modifier: ${VAR%?} with UTF-8 removes last codepoint" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "日本語");

    // ${VAR%?} -> "日本" (remove last codepoint)
    const pattern_word = [_]WordPart{.{ .literal = "?" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .RemoveSmallestSuffix, .check_null = false, .word = &pattern_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("日本", result);
}

test "modifier: ${VAR##???} with UTF-8 removes three codepoints" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "日本語abc");

    // ${VAR##???} -> "abc" (remove largest prefix matching 3 chars)
    const pattern_word = [_]WordPart{.{ .literal = "???" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .RemoveLargestPrefix, .check_null = false, .word = &pattern_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("abc", result);
}

test "modifier: ${VAR%%???} with UTF-8 removes three codepoints from end" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setVariable("VAR", "abc日本語");

    // ${VAR%%???} -> "abc" (remove largest suffix matching 3 chars)
    const pattern_word = [_]WordPart{.{ .literal = "???" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .RemoveLargestSuffix, .check_null = false, .word = &pattern_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("abc", result);
}

test "modifier: ${VAR#*} with UTF-8 handles mixed content" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // Mix of ASCII and multi-byte: "hello世界" (5 ASCII + 2 CJK = 7 codepoints)
    try shell.setVariable("VAR", "hello世界");

    // ${VAR#?????} -> "世界" (remove 5 characters)
    const pattern_word = [_]WordPart{.{ .literal = "?????" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "VAR",
            .modifier = .{ .op = .RemoveSmallestPrefix, .check_null = false, .word = &pattern_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("世界", result);
}

// --- Special Parameter Modifier Tests (POSIX 2.6.2 applied to 2.5.2) ---

test "modifier: ${#@} returns positional parameter count" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{ "a", "b", "c" });

    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "@",
            .modifier = .{ .op = .Length, .check_null = false, .word = null },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("3", result);
}

test "modifier: ${#@} with no positional params returns 0" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // No positional params set

    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "@",
            .modifier = .{ .op = .Length, .check_null = false, .word = null },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("0", result);
}

test "modifier: ${#*} returns positional parameter count" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{ "one", "two", "three", "four", "five" });

    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "*",
            .modifier = .{ .op = .Length, .check_null = false, .word = null },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("5", result);
}

test "modifier: ${1:-default} with no positional params returns default" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // No positional params set - $1 is empty

    const default_word = [_]WordPart{.{ .literal = "default" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "1",
            .modifier = .{ .op = .UseDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("default", result);
}

test "modifier: ${1:-default} with positional params returns first param" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{"value"});

    const default_word = [_]WordPart{.{ .literal = "default" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "1",
            .modifier = .{ .op = .UseDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("value", result);
}

test "modifier: ${@:+has args} with no positional params returns empty" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // No positional params set

    const alt_word = [_]WordPart{.{ .literal = "has args" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "@",
            .modifier = .{ .op = .UseAlternative, .check_null = true, .word = &alt_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("", result);
}

test "modifier: ${@:+has args} with positional params returns 'has args'" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{ "a", "b" });

    const alt_word = [_]WordPart{.{ .literal = "has args" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "@",
            .modifier = .{ .op = .UseAlternative, .check_null = true, .word = &alt_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("has args", result);
}

test "modifier: ${#?} returns length of exit status" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    shell.last_status = .{ .exited = 0 };

    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "?",
            .modifier = .{ .op = .Length, .check_null = false, .word = null },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    // Exit status 0 -> "0" -> length 1
    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("1", result);
}

test "modifier: ${#?} returns length of three digit exit status" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    shell.last_status = .{ .exited = 127 };

    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "?",
            .modifier = .{ .op = .Length, .check_null = false, .word = null },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    // Exit status 127 -> "127" -> length 3
    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("3", result);
}

test "modifier: ${@:-default} with no positional params returns default" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // No positional params

    const default_word = [_]WordPart{.{ .literal = "fallback" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "@",
            .modifier = .{ .op = .UseDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("fallback", result);
}

test "modifier: ${@:-default} with positional params returns params" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{ "one", "two" });

    const default_word = [_]WordPart{.{ .literal = "fallback" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "@",
            .modifier = .{ .op = .UseDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("one two", result);
}

test "expandArgv: quoted ${@:-default} preserves separate words" {
    // Verifies POSIX 2.5.2: "$@" produces separate fields even with modifiers.
    // This is a regression test - previously modifiers on $@ incorrectly joined
    // the positional parameters into a single word.
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

    const default_word = [_]WordPart{.{ .literal = "fallback" }};
    const inner_parts = [_]WordPart{
        .{ .parameter = .{ .name = "@", .modifier = .{
            .op = .UseDefault,
            .check_null = true,
            .word = &default_word,
        } } },
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

    // Should produce 4 words: echo, a, b, c (not: echo, "a b c")
    try std.testing.expectEqual(@as(usize, 4), argc);
    try std.testing.expectEqualStrings("echo", std.mem.span(argv[0].?));
    try std.testing.expectEqualStrings("a", std.mem.span(argv[1].?));
    try std.testing.expectEqualStrings("b", std.mem.span(argv[2].?));
    try std.testing.expectEqualStrings("c", std.mem.span(argv[3].?));
}

test "modifier: ${@#pattern} removes prefix from joined args" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{ "one", "two", "three" });

    // Pattern to remove "one " from "one two three"
    const pattern_word = [_]WordPart{.{ .literal = "one " }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "@",
            .modifier = .{ .op = .RemoveSmallestPrefix, .check_null = false, .word = &pattern_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("two three", result);
}

test "modifier: ${*%pattern} removes suffix from joined args" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{ "one", "two", "three" });

    // Pattern to remove " three" from "one two three"
    const pattern_word = [_]WordPart{.{ .literal = " three" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "*",
            .modifier = .{ .op = .RemoveSmallestSuffix, .check_null = false, .word = &pattern_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("one two", result);
}

test "modifier: ${1:=default} errors on positional parameter" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // No positional params - trying to assign to $1 should fail

    const default_word = [_]WordPart{.{ .literal = "value" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "1",
            .modifier = .{ .op = .AssignDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    // Should error because you cannot assign to positional parameters
    const result = expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectError(ExpansionError.ParameterAssignmentInvalid, result);
}

test "modifier: ${?:-0} returns exit status (never uses default)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    shell.last_status = .{ .exited = 42 };

    const default_word = [_]WordPart{.{ .literal = "0" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "?",
            .modifier = .{ .op = .UseDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    // $? is never unset and always has a value, so it uses the actual value
    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("42", result);
}

test "modifier: ${#:+alt} returns alternative when positional params exist" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{ "a", "b", "c" });

    // $# is "3" which is non-empty, so :+ should use the alternative
    const alt_word = [_]WordPart{.{ .literal = "has count" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "#",
            .modifier = .{ .op = .UseAlternative, .check_null = true, .word = &alt_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("has count", result);
}

test "modifier: ${@:-default} with empty first param returns params (not default)" {
    // When positional params include an empty string, the overall value is
    // not empty because other params have content.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    try shell.setPositionalParams(&[_][]const u8{ "", "b", "c" });

    const default_word = [_]WordPart{.{ .literal = "default" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "@",
            .modifier = .{ .op = .UseDefault, .check_null = true, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    // First param is empty but others have content, so not "empty" overall
    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings(" b c", result);
}

test "modifier: ${@-default} with no params returns empty (dash/zsh behavior)" {
    // Shell divergence: bash treats $@ with zero params as "unset", returning "default".
    // dash/zsh treat it as "set but empty", returning empty. We follow dash/zsh.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // No positional params

    const default_word = [_]WordPart{.{ .literal = "default" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "@",
            .modifier = .{ .op = .UseDefault, .check_null = false, .word = &default_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    // Without colon, only checks if "set" - $@ is always set, returns empty
    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("", result);
}

test "modifier: ${@+alt} with no params returns alt (dash/zsh behavior)" {
    // Shell divergence: bash treats $@ with zero params as "unset", returning empty.
    // dash/zsh treat it as "set but empty", returning "alt". We follow dash/zsh.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var env = process.EnvMap.init(arena.allocator());
    var shell = try ShellState.initWithEnv(arena.allocator(), &env);
    // No positional params

    const alt_word = [_]WordPart{.{ .literal = "alt" }};
    const word = Word{
        .parts = &[_]WordPart{.{ .parameter = .{
            .name = "@",
            .modifier = .{ .op = .UseAlternative, .check_null = false, .word = &alt_word },
        } }},
        .position = 0,
        .line = 1,
        .column = 1,
    };

    // Without colon, only checks if "set" - $@ is always set, returns alternative
    const result = try expandWordJoined(arena.allocator(), word, &shell);
    try std.testing.expectEqualStrings("alt", result);
}
