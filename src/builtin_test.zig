//! POSIX test expression evaluation.
//!
//! This module implements the test expression evaluator per POSIX.1-2017.
//! The evaluation uses the argument-count algorithm specified in the standard,
//! which determines operator precedence based on the number of arguments.
//!
//! POSIX Reference: Section 4 Utilities, test
//! https://pubs.opengroup.org/onlinepubs/9699919799/utilities/test.html

const std = @import("std");

/// Errors that can occur during test expression evaluation.
pub const TestError = error{
    /// An operator was not recognized.
    UnknownOperator,
    /// Too many arguments for the expression structure.
    TooManyArguments,
    /// An integer was expected but the operand could not be parsed as one.
    IntegerExpected,
};

/// Unary operators for test expressions.
const UnaryOp = enum {
    /// -n: "True if the length of string is non-zero."
    /// POSIX.1-2017 Section 4 Utilities, test, OPERANDS
    str_not_empty,
    /// -z: "True if the length of string is zero."
    /// POSIX.1-2017 Section 4 Utilities, test, OPERANDS
    str_empty,
};

/// Binary operators for test expressions.
const BinaryOp = enum {
    // String operators
    /// =: "True if the strings s1 and s2 are identical."
    /// POSIX.1-2017 Section 4 Utilities, test, OPERANDS
    str_equal,
    /// !=: "True if the strings s1 and s2 are not identical."
    /// POSIX.1-2017 Section 4 Utilities, test, OPERANDS
    str_not_equal,

    // Integer operators
    /// -eq: "True if the integers n1 and n2 are algebraically equal."
    /// POSIX.1-2017 Section 4 Utilities, test, OPERANDS
    int_eq,
    /// -ne: "True if the integers n1 and n2 are not algebraically equal."
    /// POSIX.1-2017 Section 4 Utilities, test, OPERANDS
    int_ne,
    /// -lt: "True if the integer n1 is algebraically less than the integer n2."
    /// POSIX.1-2017 Section 4 Utilities, test, OPERANDS
    int_lt,
    /// -le: "True if the integer n1 is algebraically less than or equal to the integer n2."
    /// POSIX.1-2017 Section 4 Utilities, test, OPERANDS
    int_le,
    /// -gt: "True if the integer n1 is algebraically greater than the integer n2."
    /// POSIX.1-2017 Section 4 Utilities, test, OPERANDS
    int_gt,
    /// -ge: "True if the integer n1 is algebraically greater than or equal to the integer n2."
    /// POSIX.1-2017 Section 4 Utilities, test, OPERANDS
    int_ge,
};

/// Evaluate a test expression per POSIX.1-2017 argument-count algorithm.
///
/// The algorithm determines operator precedence based on the number of arguments
/// presented to test, not by parsing operators first. This avoids ambiguity when
/// operands look like operators (e.g., `test "=" = "="`).
///
/// POSIX.1-2017 Section 4 Utilities, test, OPERANDS:
/// "The algorithm for determining the precedence of the operators and the
/// return value that shall be generated is based on the number of arguments
/// presented to test."
pub fn evaluate(args: []const []const u8) TestError!bool {
    var pos: usize = 0;
    var negate = false;

    state: switch (args.len - pos) {
        // POSIX.1-2017 Section 4 Utilities, test, OPERANDS (0 arguments):
        // "Exit false (1)."
        0 => {
            return negate;
        },

        // POSIX.1-2017 Section 4 Utilities, test, OPERANDS (1 argument):
        // "Exit true (0) if $1 is not null; otherwise, exit false."
        1 => {
            const result = args[pos].len > 0;
            return if (negate) !result else result;
        },

        // POSIX.1-2017 Section 4 Utilities, test, OPERANDS (2 arguments):
        // "If $1 is '!', exit true if $2 is null, false if $2 is not null."
        // "If $1 is a unary primary, exit true if the unary test is true,
        //  false if the unary test is false."
        // "Otherwise, produce unspecified results."
        2 => {
            const a1 = args[pos];
            const a2 = args[pos + 1];

            if (std.mem.eql(u8, a1, "!")) {
                negate = !negate;
                pos += 1;
                continue :state args.len - pos;
            }

            if (unaryOp(a1)) |op| {
                const result = evalUnary(op, a2);
                return if (negate) !result else result;
            }

            return error.UnknownOperator;
        },

        // POSIX.1-2017 Section 4 Utilities, test, OPERANDS (3 arguments):
        // "If $2 is a binary primary, perform the binary test of $1 and $3."
        // "If $1 is '!', negate the two-argument test of $2 and $3."
        // "If $1 is '(' and $3 is ')', perform the unary test of $2."
        // "Otherwise, produce unspecified results."
        3 => {
            const a1 = args[pos];
            const a2 = args[pos + 1];
            const a3 = args[pos + 2];

            if (binaryOp(a2)) |op| {
                const result = try evalBinary(op, a1, a3);
                return if (negate) !result else result;
            }

            if (std.mem.eql(u8, a1, "!")) {
                negate = !negate;
                pos += 1;
                continue :state args.len - pos;
            }

            return error.TooManyArguments;
        },

        // POSIX.1-2017 Section 4 Utilities, test, OPERANDS (4 arguments):
        // "If $1 is '!', negate the three-argument test of $2, $3, and $4."
        // "If $1 is '(' and $4 is ')', perform the two-argument test of $2 and $3."
        // "Otherwise, the results are unspecified."
        4 => {
            const a1 = args[pos];

            if (std.mem.eql(u8, a1, "!")) {
                negate = !negate;
                pos += 1;
                continue :state args.len - pos;
            }

            return error.TooManyArguments;
        },

        // POSIX.1-2017 Section 4 Utilities, test, OPERANDS (>4 arguments):
        // "The results are unspecified."
        //
        // We handle leading '!' to allow chains like `! ! ! expr`, but otherwise
        // return an error for expressions we cannot reliably parse.
        else => {
            const a1 = args[pos];
            if (std.mem.eql(u8, a1, "!")) {
                negate = !negate;
                pos += 1;
                continue :state args.len - pos;
            }
            return error.TooManyArguments;
        },
    }
}

/// Look up a unary operator by its string representation.
fn unaryOp(s: []const u8) ?UnaryOp {
    const ops = std.StaticStringMap(UnaryOp).initComptime(.{
        .{ "-n", .str_not_empty },
        .{ "-z", .str_empty },
    });
    return ops.get(s);
}

/// Look up a binary operator by its string representation.
fn binaryOp(s: []const u8) ?BinaryOp {
    const ops = std.StaticStringMap(BinaryOp).initComptime(.{
        .{ "=", .str_equal },
        .{ "!=", .str_not_equal },
        .{ "-eq", .int_eq },
        .{ "-ne", .int_ne },
        .{ "-lt", .int_lt },
        .{ "-le", .int_le },
        .{ "-gt", .int_gt },
        .{ "-ge", .int_ge },
    });
    return ops.get(s);
}

/// Evaluate a unary operator.
fn evalUnary(op: UnaryOp, operand: []const u8) bool {
    return switch (op) {
        .str_not_empty => operand.len > 0,
        .str_empty => operand.len == 0,
    };
}

/// Evaluate a binary operator.
fn evalBinary(op: BinaryOp, left: []const u8, right: []const u8) TestError!bool {
    return switch (op) {
        .str_equal => std.mem.eql(u8, left, right),
        .str_not_equal => !std.mem.eql(u8, left, right),
        .int_eq, .int_ne, .int_lt, .int_le, .int_gt, .int_ge => {
            const l = std.fmt.parseInt(i64, left, 10) catch return error.IntegerExpected;
            const r = std.fmt.parseInt(i64, right, 10) catch return error.IntegerExpected;
            return switch (op) {
                .int_eq => l == r,
                .int_ne => l != r,
                .int_lt => l < r,
                .int_le => l <= r,
                .int_gt => l > r,
                .int_ge => l >= r,
                else => unreachable,
            };
        },
    };
}

// --- Tests ---

const testing = std.testing;

// === 0 arguments ===
// POSIX.1-2017: "Exit false (1)."

test "0 args returns false" {
    try testing.expectEqual(false, try evaluate(&.{}));
}

// === 1 argument ===
// POSIX.1-2017: "Exit true (0) if $1 is not null; otherwise, exit false."

test "1 arg: non-empty string is true" {
    try testing.expectEqual(true, try evaluate(&.{"hello"}));
}

test "1 arg: empty string is false" {
    try testing.expectEqual(false, try evaluate(&.{""}));
}

test "1 arg: operator names are just strings" {
    // POSIX.1-2017 APPLICATION USAGE notes these edge cases:
    // "The test and [ utilities can be used safely with the constructs
    // described here... when one of the operands might be null (the empty
    // string)... if the string operand could be confused with a unary primary..."
    //
    // When there is only one argument, it is always treated as a string operand,
    // never as an operator. This is how the argument-count algorithm avoids
    // ambiguity.
    try testing.expectEqual(true, try evaluate(&.{"!"}));
    try testing.expectEqual(true, try evaluate(&.{"-n"}));
    try testing.expectEqual(true, try evaluate(&.{"-z"}));
    try testing.expectEqual(true, try evaluate(&.{"="}));
}

// === 2 arguments ===
// POSIX.1-2017: "If $1 is '!', exit true if $2 is null, false if $2 is not null."

test "2 args: ! empty-string is true" {
    try testing.expectEqual(true, try evaluate(&.{ "!", "" }));
}

test "2 args: ! non-empty is false" {
    try testing.expectEqual(false, try evaluate(&.{ "!", "hello" }));
}

test "2 args: ! ! is negation of non-empty string !" {
    // "! !" means: negate the 1-arg test of "!"
    // 1-arg test of "!" is true (non-empty string)
    // negated: false
    try testing.expectEqual(false, try evaluate(&.{ "!", "!" }));
}

// POSIX.1-2017: "If $1 is a unary primary, exit true if the unary test is true,
//               false if the unary test is false."

test "2 args: -n non-empty is true" {
    try testing.expectEqual(true, try evaluate(&.{ "-n", "hello" }));
}

test "2 args: -n empty is false" {
    try testing.expectEqual(false, try evaluate(&.{ "-n", "" }));
}

test "2 args: -z empty is true" {
    try testing.expectEqual(true, try evaluate(&.{ "-z", "" }));
}

test "2 args: -z non-empty is false" {
    try testing.expectEqual(false, try evaluate(&.{ "-z", "hello" }));
}

// POSIX.1-2017: "Otherwise, produce unspecified results."

test "2 args: unknown operator is error" {
    try testing.expectError(error.UnknownOperator, evaluate(&.{ "foo", "bar" }));
}

// === 3 arguments ===
// POSIX.1-2017: "If $2 is a binary primary, perform the binary test of $1 and $3."

test "3 args: string equality true" {
    try testing.expectEqual(true, try evaluate(&.{ "foo", "=", "foo" }));
}

test "3 args: string equality false" {
    try testing.expectEqual(false, try evaluate(&.{ "foo", "=", "bar" }));
}

test "3 args: string inequality true" {
    try testing.expectEqual(true, try evaluate(&.{ "foo", "!=", "bar" }));
}

test "3 args: string inequality false" {
    try testing.expectEqual(false, try evaluate(&.{ "foo", "!=", "foo" }));
}

// POSIX.1-2017 APPLICATION USAGE: operators can be operands
test "3 args: = = = (comparing = to =)" {
    // This tests that operators are treated as operands when in operand position.
    // The middle "=" is the operator, the first and third are operands.
    try testing.expectEqual(true, try evaluate(&.{ "=", "=", "=" }));
}

test "3 args: ! = ! (comparing ! to !)" {
    // Similar test: "!" in operand position is just a string.
    try testing.expectEqual(true, try evaluate(&.{ "!", "=", "!" }));
}

// POSIX.1-2017: "If $1 is '!', negate the two-argument test of $2 and $3."

test "3 args: ! -n non-empty is false" {
    try testing.expectEqual(false, try evaluate(&.{ "!", "-n", "hello" }));
}

test "3 args: ! -z non-empty is true" {
    try testing.expectEqual(true, try evaluate(&.{ "!", "-z", "hello" }));
}

test "3 args: ! -n empty is true" {
    try testing.expectEqual(true, try evaluate(&.{ "!", "-n", "" }));
}

// === 4 arguments ===
// POSIX.1-2017: "If $1 is '!', negate the three-argument test of $2, $3, and $4."

test "4 args: ! foo = foo is false" {
    try testing.expectEqual(false, try evaluate(&.{ "!", "foo", "=", "foo" }));
}

test "4 args: ! foo = bar is true" {
    try testing.expectEqual(true, try evaluate(&.{ "!", "foo", "=", "bar" }));
}

test "4 args: ! ! -n hello is true" {
    // Double negation: ! ! (-n hello) = ! (false) = ! true of "hello" being non-empty
    // Wait, let's trace: -n hello = true, ! true = false, ! false = true
    try testing.expectEqual(true, try evaluate(&.{ "!", "!", "-n", "hello" }));
}

test "4 args: without leading ! is error" {
    try testing.expectError(error.TooManyArguments, evaluate(&.{ "a", "b", "c", "d" }));
}

// === >4 arguments ===
// POSIX.1-2017: "The results are unspecified."
//
// We handle leading '!' chains but error on anything else.

test ">4 args: with leading ! strips and continues" {
    // ! ! foo = foo -> negate negate (foo = foo) -> true
    try testing.expectEqual(true, try evaluate(&.{ "!", "!", "foo", "=", "foo" }));
}

test ">4 args: without valid structure is error" {
    try testing.expectError(error.TooManyArguments, evaluate(&.{ "a", "b", "c", "d", "e" }));
}

// === Integer comparisons ===
// POSIX.1-2017: "True if the integers n1 and n2 are algebraically [comparison]."

test "3 args: -eq equal" {
    try testing.expectEqual(true, try evaluate(&.{ "5", "-eq", "5" }));
}

test "3 args: -eq not equal" {
    try testing.expectEqual(false, try evaluate(&.{ "5", "-eq", "10" }));
}

test "3 args: -ne not equal" {
    try testing.expectEqual(true, try evaluate(&.{ "5", "-ne", "10" }));
}

test "3 args: -ne equal" {
    try testing.expectEqual(false, try evaluate(&.{ "5", "-ne", "5" }));
}

test "3 args: -lt less" {
    try testing.expectEqual(true, try evaluate(&.{ "5", "-lt", "10" }));
}

test "3 args: -lt equal" {
    try testing.expectEqual(false, try evaluate(&.{ "5", "-lt", "5" }));
}

test "3 args: -lt greater" {
    try testing.expectEqual(false, try evaluate(&.{ "10", "-lt", "5" }));
}

test "3 args: -le less" {
    try testing.expectEqual(true, try evaluate(&.{ "5", "-le", "10" }));
}

test "3 args: -le equal" {
    try testing.expectEqual(true, try evaluate(&.{ "5", "-le", "5" }));
}

test "3 args: -le greater" {
    try testing.expectEqual(false, try evaluate(&.{ "10", "-le", "5" }));
}

test "3 args: -gt greater" {
    try testing.expectEqual(true, try evaluate(&.{ "10", "-gt", "5" }));
}

test "3 args: -gt equal" {
    try testing.expectEqual(false, try evaluate(&.{ "5", "-gt", "5" }));
}

test "3 args: -gt less" {
    try testing.expectEqual(false, try evaluate(&.{ "5", "-gt", "10" }));
}

test "3 args: -ge greater" {
    try testing.expectEqual(true, try evaluate(&.{ "10", "-ge", "5" }));
}

test "3 args: -ge equal" {
    try testing.expectEqual(true, try evaluate(&.{ "5", "-ge", "5" }));
}

test "3 args: -ge less" {
    try testing.expectEqual(false, try evaluate(&.{ "5", "-ge", "10" }));
}

// Negative numbers (algebraic comparison)
test "3 args: -lt with negative numbers" {
    try testing.expectEqual(true, try evaluate(&.{ "-10", "-lt", "5" }));
    try testing.expectEqual(true, try evaluate(&.{ "-10", "-lt", "-5" }));
}

test "3 args: -eq with negative numbers" {
    try testing.expectEqual(true, try evaluate(&.{ "-5", "-eq", "-5" }));
}

// Error cases
test "3 args: -eq with non-integer left" {
    try testing.expectError(error.IntegerExpected, evaluate(&.{ "foo", "-eq", "5" }));
}

test "3 args: -eq with non-integer right" {
    try testing.expectError(error.IntegerExpected, evaluate(&.{ "5", "-eq", "bar" }));
}

test "3 args: -eq with empty string" {
    try testing.expectError(error.IntegerExpected, evaluate(&.{ "", "-eq", "5" }));
}

// With negation
test "4 args: ! 5 -eq 5 is false" {
    try testing.expectEqual(false, try evaluate(&.{ "!", "5", "-eq", "5" }));
}

test "4 args: ! 5 -lt 3 is true" {
    try testing.expectEqual(true, try evaluate(&.{ "!", "5", "-lt", "3" }));
}
