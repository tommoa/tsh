//! Shell pattern matching (fnmatch-style).
//!
//! Implements POSIX shell pattern matching for:
//! - Parameter expansion modifiers (${var#pattern}, etc.)
//! - Pathname expansion (globbing) - future use
//!
//! Pattern syntax:
//! - `?` matches any single character (Unicode codepoint)
//! - `*` matches zero or more characters (Unicode codepoints)
//! - `[abc]` matches any character in the set
//! - `[a-z]` matches any character in the range
//! - `[!...]` or `[^...]` matches any character NOT in the set
//! - `\x` escapes character x, removing special meaning
//!
//! This implementation treats "character" as Unicode codepoint, matching
//! bash/zsh behavior rather than dash's byte-oriented matching.
//!
//! POSIX Reference: Section 2.13 - Pattern Matching Notation
//!
//! TODO: Evaluate optimization opportunities:
//! - Current implementation uses backtracking, which is O(n×m) per match
//! - Pattern removal (# ## % %%) tries multiple prefixes/suffixes, potentially O(n²×m)
//! - Possible improvements:
//!   1. Pattern specialization: fast-path common patterns like `*`, `?`, `*.suffix`, `prefix*`
//!   2. NFA/DFA compilation: O(n) matching but adds build cost
//!   3. Single-pass boundary finding: find shortest/longest match position in one scan
//! - Current approach is likely fine for typical shell patterns (small m), but worth
//!   revisiting if profiling shows pattern matching as a bottleneck.

const std = @import("std");

/// Match a shell pattern against a string.
///
/// Returns true if the pattern matches the entire string.
/// The pattern is anchored at both ends (no implicit wildcards).
/// Characters are treated as Unicode codepoints, not bytes.
pub fn match(pattern: []const u8, string: []const u8) bool {
    return matchImpl(pattern, string, 0, 0);
}

/// Get the byte length of the UTF-8 codepoint starting at the given position.
/// Returns 1 for invalid sequences (fall back to byte-by-byte).
pub fn codepointLen(bytes: []const u8, pos: usize) usize {
    if (pos >= bytes.len) return 0;
    const len = std.unicode.utf8ByteSequenceLength(bytes[pos]) catch return 1;
    // Validate we have enough bytes and the sequence is valid
    if (pos + len > bytes.len) return 1;
    _ = std.unicode.utf8Decode(bytes[pos..][0..len]) catch return 1;
    return len;
}

/// Decode the UTF-8 codepoint at the given position.
/// Returns the codepoint value and its byte length.
/// For invalid sequences, returns the byte value as codepoint with length 1.
fn decodeCodepoint(bytes: []const u8, pos: usize) struct { cp: u21, len: usize } {
    if (pos >= bytes.len) return .{ .cp = 0, .len = 0 };
    const seq_len = std.unicode.utf8ByteSequenceLength(bytes[pos]) catch
        return .{ .cp = bytes[pos], .len = 1 };
    if (pos + seq_len > bytes.len)
        return .{ .cp = bytes[pos], .len = 1 };
    const cp = std.unicode.utf8Decode(bytes[pos..][0..seq_len]) catch
        return .{ .cp = bytes[pos], .len = 1 };
    return .{ .cp = cp, .len = seq_len };
}

fn matchImpl(pattern: []const u8, string: []const u8, pi: usize, si: usize) bool {
    var p = pi;
    var s = si;

    while (p < pattern.len) {
        const pc = pattern[p];

        switch (pc) {
            '*' => {
                // Skip consecutive stars
                while (p < pattern.len and pattern[p] == '*') : (p += 1) {}

                // Trailing star matches everything
                if (p >= pattern.len) return true;

                // Try matching * against 0, 1, 2, ... codepoints
                // We iterate by codepoint boundaries in the string
                var try_pos = s;
                while (try_pos <= string.len) {
                    if (matchImpl(pattern, string, p, try_pos)) return true;
                    if (try_pos >= string.len) break;
                    // Advance by one codepoint
                    try_pos += codepointLen(string, try_pos);
                }
                return false;
            },
            '?' => {
                // Must match exactly one codepoint (not one byte)
                if (s >= string.len) return false;
                const cp_len = codepointLen(string, s);
                if (cp_len == 0) return false;
                p += 1;
                s += cp_len;
            },
            '[' => {
                // Character class - matches one codepoint against bracket expression
                if (s >= string.len) return false;

                const decoded = decodeCodepoint(string, s);
                const result = matchBracket(pattern, p, decoded.cp);
                if (result.matched) {
                    p = result.end_pos;
                    s += decoded.len;
                } else {
                    return false;
                }
            },
            '\\' => {
                // Escaped character - match literally (byte by byte for escape sequences)
                p += 1;
                if (p >= pattern.len) return false;
                if (s >= string.len or string[s] != pattern[p]) return false;
                p += 1;
                s += 1;
            },
            else => {
                // Literal character - match byte by byte
                // Multi-byte UTF-8 in pattern matches the same bytes in string
                if (s >= string.len or string[s] != pc) return false;
                p += 1;
                s += 1;
            },
        }
    }

    // Pattern exhausted - string must also be exhausted
    return s >= string.len;
}

const BracketResult = struct {
    matched: bool,
    end_pos: usize, // position after the closing ]
};

/// Match a codepoint against a bracket expression.
/// Both the input codepoint and the pattern contents are treated as Unicode codepoints.
fn matchBracket(pattern: []const u8, start: usize, codepoint: u21) BracketResult {
    var p = start + 1; // skip opening [

    // Check for negation
    var negate = false;
    if (p < pattern.len and (pattern[p] == '!' or pattern[p] == '^')) {
        negate = true;
        p += 1;
    }

    // First ] is literal if immediately after [ or [! or [^
    var matched = false;
    var first = true;

    while (p < pattern.len) {
        // Check for end of bracket expression
        if (pattern[p] == ']' and !first) {
            const result = if (negate) !matched else matched;
            return .{ .matched = result, .end_pos = p + 1 };
        }

        first = false;

        // Decode the current codepoint from pattern
        const decoded = decodeCodepoint(pattern, p);
        if (decoded.len == 0) break;
        const c = decoded.cp;

        // Check for range (a-z, あ-ん, etc.)
        // Range is: <char> '-' <char> where '-' is not at end
        if (p + decoded.len < pattern.len and pattern[p + decoded.len] == '-') {
            const dash_pos = p + decoded.len;
            if (dash_pos + 1 < pattern.len and pattern[dash_pos + 1] != ']') {
                // This is a range
                const end_decoded = decodeCodepoint(pattern, dash_pos + 1);
                if (end_decoded.len > 0) {
                    const range_end = end_decoded.cp;
                    if (codepoint >= c and codepoint <= range_end) {
                        matched = true;
                    }
                    p = dash_pos + 1 + end_decoded.len;
                    continue;
                }
            }
        }

        // Single character match
        if (c == codepoint) {
            matched = true;
        }
        p += decoded.len;
    }

    // Unclosed bracket - treat as literal [
    return .{ .matched = false, .end_pos = start + 1 };
}

// ============================================================================
// Tests
// ============================================================================

test "pattern: literal match" {
    try std.testing.expect(match("hello", "hello"));
    try std.testing.expect(!match("hello", "world"));
    try std.testing.expect(!match("hello", "hell"));
    try std.testing.expect(!match("hello", "helloo"));
}

test "pattern: ? matches single character" {
    try std.testing.expect(match("h?llo", "hello"));
    try std.testing.expect(match("h?llo", "hallo"));
    try std.testing.expect(!match("h?llo", "hllo"));
    try std.testing.expect(!match("h?llo", "heello"));
    try std.testing.expect(match("???", "abc"));
    try std.testing.expect(!match("???", "ab"));
}

test "pattern: * matches zero or more" {
    try std.testing.expect(match("*", ""));
    try std.testing.expect(match("*", "anything"));
    try std.testing.expect(match("*.txt", "file.txt"));
    try std.testing.expect(!match("*.txt", "file.doc"));
    try std.testing.expect(match("file.*", "file.txt"));
    try std.testing.expect(match("*/*", "path/file"));
    try std.testing.expect(!match("*/*", "nopath"));
}

test "pattern: bracket expression" {
    try std.testing.expect(match("[abc]", "a"));
    try std.testing.expect(match("[abc]", "b"));
    try std.testing.expect(!match("[abc]", "d"));
    try std.testing.expect(match("[a-z]", "m"));
    try std.testing.expect(!match("[a-z]", "M"));
    try std.testing.expect(match("[0-9]", "5"));
}

test "pattern: negated bracket" {
    try std.testing.expect(!match("[!abc]", "a"));
    try std.testing.expect(match("[!abc]", "d"));
    try std.testing.expect(match("[^abc]", "d"));
    try std.testing.expect(!match("[!a-z]", "m"));
    try std.testing.expect(match("[!a-z]", "M"));
}

test "pattern: escaped characters" {
    try std.testing.expect(match("\\*", "*"));
    try std.testing.expect(!match("\\*", "a"));
    try std.testing.expect(match("\\?", "?"));
    try std.testing.expect(match("\\[a\\]", "[a]"));
}

test "pattern: empty pattern and string" {
    try std.testing.expect(match("", ""));
    try std.testing.expect(!match("", "a"));
    try std.testing.expect(!match("a", ""));
}

test "pattern: consecutive stars" {
    try std.testing.expect(match("**", "anything"));
    try std.testing.expect(match("a**b", "ab"));
    try std.testing.expect(match("a**b", "aXXXb"));
}

test "pattern: bracket edge cases" {
    // ] as first char is literal
    try std.testing.expect(match("[]a]", "]"));
    try std.testing.expect(match("[]a]", "a"));
    // - at start or end is literal
    try std.testing.expect(match("[-a]", "-"));
    try std.testing.expect(match("[a-]", "-"));
}

test "pattern: path-like patterns" {
    // Common shell patterns for path manipulation
    try std.testing.expect(match("*/", "foo/"));
    try std.testing.expect(match("*/", "bar/"));
    try std.testing.expect(!match("*/", "nobslash"));

    // Basename extraction: remove everything up to and including last /
    try std.testing.expect(match("*/", "/"));
    try std.testing.expect(match("*/", "a/"));

    // Extension patterns
    try std.testing.expect(match(".*", ".txt"));
    try std.testing.expect(match(".*", ".tar.gz"));
    try std.testing.expect(!match(".*", "notdot"));

    // Directory patterns
    try std.testing.expect(match("/*", "/anything"));
    try std.testing.expect(!match("/*", "noslash"));
}

test "pattern: mixed wildcards" {
    try std.testing.expect(match("*?*", "a"));
    try std.testing.expect(match("*?*", "abc"));
    try std.testing.expect(!match("*?*", ""));
    try std.testing.expect(match("?*?", "ab"));
    try std.testing.expect(match("?*?", "abc"));
    try std.testing.expect(!match("?*?", "a"));
}

test "pattern: complex patterns" {
    try std.testing.expect(match("*.tar.gz", "archive.tar.gz"));
    try std.testing.expect(!match("*.tar.gz", "archive.tar"));
    try std.testing.expect(match("[a-z]*[0-9]", "test1"));
    try std.testing.expect(match("[a-z]*[0-9]", "a9"));
    try std.testing.expect(!match("[a-z]*[0-9]", "Test1"));
}

// --- UTF-8 Tests ---
// These verify that pattern matching operates on Unicode codepoints,
// matching bash/zsh behavior rather than dash's byte-oriented matching.

test "pattern: ? matches single UTF-8 codepoint" {
    // "日" is 3 bytes but 1 codepoint
    try std.testing.expect(match("?", "日"));
    try std.testing.expect(match("???", "日本語"));
    try std.testing.expect(!match("??", "日本語")); // 3 codepoints, not 2
    try std.testing.expect(!match("????", "日本語")); // 3 codepoints, not 4
}

test "pattern: * with UTF-8 strings" {
    try std.testing.expect(match("*", "日本語"));
    try std.testing.expect(match("日*", "日本語"));
    try std.testing.expect(match("*語", "日本語"));
    try std.testing.expect(match("日*語", "日本語"));
    try std.testing.expect(match("?*?", "日本語")); // at least 2 codepoints
}

test "pattern: literal UTF-8 in pattern" {
    try std.testing.expect(match("日本語", "日本語"));
    try std.testing.expect(!match("日本語", "日本"));
    try std.testing.expect(match("hello世界", "hello世界"));
}

test "pattern: mixed ASCII and UTF-8" {
    try std.testing.expect(match("a?c", "abc")); // ASCII
    try std.testing.expect(match("a?c", "a日c")); // UTF-8 in middle
    try std.testing.expect(match("???abc", "日本語abc"));
    try std.testing.expect(match("abc???", "abc日本語"));
}

test "pattern: bracket expression with UTF-8 characters" {
    // Single UTF-8 character in bracket
    try std.testing.expect(match("[日]", "日"));
    try std.testing.expect(!match("[日]", "本"));
    try std.testing.expect(match("[日本語]", "日"));
    try std.testing.expect(match("[日本語]", "本"));
    try std.testing.expect(match("[日本語]", "語"));
    try std.testing.expect(!match("[日本語]", "中"));
}

test "pattern: bracket expression with UTF-8 ranges" {
    // Hiragana range: あ (U+3042) to ん (U+3093)
    try std.testing.expect(match("[あ-ん]", "あ")); // start of range
    try std.testing.expect(match("[あ-ん]", "ん")); // end of range
    try std.testing.expect(match("[あ-ん]", "か")); // middle of range
    try std.testing.expect(match("[あ-ん]", "さ")); // middle of range
    try std.testing.expect(!match("[あ-ん]", "ア")); // katakana, outside range

    // Katakana range: ア (U+30A2) to ン (U+30F3)
    try std.testing.expect(match("[ア-ン]", "ア"));
    try std.testing.expect(match("[ア-ン]", "カ"));
    try std.testing.expect(!match("[ア-ン]", "あ")); // hiragana, outside range
}

test "pattern: negated bracket with UTF-8" {
    try std.testing.expect(!match("[!日本語]", "日"));
    try std.testing.expect(!match("[!日本語]", "本"));
    try std.testing.expect(match("[!日本語]", "中"));
    try std.testing.expect(match("[!日本語]", "a"));

    // Negated range
    try std.testing.expect(!match("[!あ-ん]", "か"));
    try std.testing.expect(match("[!あ-ん]", "ア"));
}

test "pattern: bracket with mixed ASCII and UTF-8" {
    try std.testing.expect(match("[aあ]", "a"));
    try std.testing.expect(match("[aあ]", "あ"));
    try std.testing.expect(!match("[aあ]", "b"));
    try std.testing.expect(!match("[aあ]", "い"));

    // Mixed in pattern context
    try std.testing.expect(match("[日a-z]", "日"));
    try std.testing.expect(match("[日a-z]", "m"));
    try std.testing.expect(!match("[日a-z]", "M"));
}

test "pattern: unclosed bracket treated as literal" {
    // Unclosed bracket should be treated as a literal '[' character
    // and the match should fail (since '[' != 'a', etc.)
    try std.testing.expect(!match("[abc", "a"));
    try std.testing.expect(!match("[abc", "b"));
    try std.testing.expect(!match("[a-z", "m"));

    // The literal '[' would need to match
    try std.testing.expect(!match("[", "a"));
    try std.testing.expect(!match("[", "[a")); // pattern is just '[', string is '[a'

    // Unclosed bracket at end of longer pattern
    try std.testing.expect(!match("test[abc", "testa"));
    try std.testing.expect(!match("test[abc", "test[abc")); // '[' is literal, rest are literal too
}

test "pattern: escaped backslash" {
    // Escaped backslash matches literal backslash
    try std.testing.expect(match("\\\\", "\\"));
    try std.testing.expect(!match("\\\\", "a"));

    // Backslash followed by regular char
    try std.testing.expect(match("\\a", "a"));

    // Multiple escapes
    try std.testing.expect(match("\\*\\?\\[", "*?["));
}

test "pattern: escape at end of pattern" {
    // Trailing backslash with nothing after - should fail to match anything
    // (pattern expects another character after backslash)
    try std.testing.expect(!match("test\\", "test"));
    try std.testing.expect(!match("test\\", "test\\"));
    try std.testing.expect(!match("\\", ""));
    try std.testing.expect(!match("\\", "\\"));
}
