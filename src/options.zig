//! POSIX-compliant option parsing for shell builtins.
//!
//! This module provides a declarative framework for parsing command-line
//! options following POSIX.1-2017 Utility Conventions (Section 12.2).
//!
//! Key POSIX requirements implemented:
//! - Options are single alphanumeric characters preceded by '-'
//! - Multiple options can be combined after a single '-' (e.g., "-LP")
//! - The "--" argument terminates option processing
//! - A single '-' is treated as an operand, not an option
//!
//! Usage:
//! ```
//! const PwdOptions = struct {
//!     physical: bool = false,
//!
//!     pub const meta = .{
//!         .name = "pwd",
//!         .options = &.{
//!             .{ .short = 'L', .field = "physical", .value = false },
//!             .{ .short = 'P', .field = "physical", .value = true },
//!         },
//!         .operands = .{ .min = 0, .max = @as(?usize, 0) },
//!     };
//! };
//!
//! const parsed = options.OptionParser(PwdOptions).parse(args) catch {
//!     return .{ .exit_code = 1 };
//! };
//! ```
//!
//! TODO: Option arguments (e.g., `-d ':'` for read builtin)
//! TODO: Long options (e.g., `--physical`)

const std = @import("std");
const state = @import("state.zig");
const printError = state.printError;

/// Creates a specialized option parser for the given options struct.
///
/// The options struct must have a `meta` declaration containing:
/// - `name`: Command name for error messages
/// - `options`: Slice of option specifications
/// - `operands`: Struct with `min` and optional `max` operand counts
pub fn OptionParser(comptime Opts: type) type {
    return struct {
        const Self = @This();
        const Meta = Opts.meta;

        pub const Error = error{
            InvalidOption,
            TooManyOperands,
            MissingOperand,
        };

        pub const Result = struct {
            options: Opts,
            operands: []const []const u8,
        };

        /// Parse arguments according to the option spec.
        ///
        /// POSIX 12.2 Utility Syntax Guidelines:
        /// - Guideline 3: Option names are single alphanumeric characters
        /// - Guideline 4: All options are preceded by '-'
        /// - Guideline 5: Options without arguments can be grouped (e.g., "-LP")
        /// - Guideline 10: "--" terminates options; "-" is an operand
        ///
        /// args[0] is assumed to be the command name.
        pub fn parse(args: []const []const u8) Error!Result {
            var opts = Opts{};
            var i: usize = 1;

            // Parse options
            while (i < args.len) : (i += 1) {
                const arg = args[i];

                // POSIX Guideline 10: "--" terminates option processing
                if (std.mem.eql(u8, arg, "--")) {
                    i += 1;
                    break;
                }

                // Not an option: empty, doesn't start with '-', or bare '-'
                // POSIX Guideline 10: "-" is treated as an operand
                if (arg.len == 0 or arg[0] != '-' or arg.len == 1) {
                    break;
                }

                // POSIX Guideline 5: Parse combined short options (e.g., "-LP")
                for (arg[1..]) |c| {
                    if (!Self.applyShortOption(&opts, c)) {
                        Self.printInvalidOption(c);
                        return Error.InvalidOption;
                    }
                }
            }

            // Remaining args are operands
            const operands = args[i..];

            // Validate operand count
            if (comptime Meta.operands.max != null) {
                if (operands.len > Meta.operands.max.?) {
                    printError("{s}: too many arguments\n", .{Meta.name});
                    return Error.TooManyOperands;
                }
            }
            if (operands.len < Meta.operands.min) {
                printError("{s}: missing operand\n", .{Meta.name});
                return Error.MissingOperand;
            }

            return .{
                .options = opts,
                .operands = operands,
            };
        }

        /// Apply a short option character to the options struct.
        /// Returns false if the option is not recognized.
        fn applyShortOption(opts: *Opts, c: u8) bool {
            inline for (Meta.options) |opt| {
                if (opt.short == c) {
                    @field(opts, opt.field) = opt.value;
                    return true;
                }
            }
            return false;
        }

        /// Print an error message for an invalid option.
        fn printInvalidOption(c: u8) void {
            printError("{s}: -{c}: invalid option\n", .{ Meta.name, c });
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parse: no options, no operands" {
    const TestOpts = struct {
        flag: bool = false,

        pub const meta = .{
            .name = "test",
            .options = &.{
                .{ .short = 'f', .field = "flag", .value = true },
            },
            .operands = .{ .min = 0, .max = @as(?usize, null) },
        };
    };

    const result = try OptionParser(TestOpts).parse(&.{"test"});
    try std.testing.expectEqual(false, result.options.flag);
    try std.testing.expectEqual(@as(usize, 0), result.operands.len);
}

test "parse: single option" {
    const TestOpts = struct {
        flag: bool = false,

        pub const meta = .{
            .name = "test",
            .options = &.{
                .{ .short = 'f', .field = "flag", .value = true },
            },
            .operands = .{ .min = 0, .max = @as(?usize, null) },
        };
    };

    const result = try OptionParser(TestOpts).parse(&.{ "test", "-f" });
    try std.testing.expectEqual(true, result.options.flag);
    try std.testing.expectEqual(@as(usize, 0), result.operands.len);
}

test "parse: combined options" {
    const TestOpts = struct {
        physical: bool = false,

        pub const meta = .{
            .name = "pwd",
            .options = &.{
                .{ .short = 'L', .field = "physical", .value = false },
                .{ .short = 'P', .field = "physical", .value = true },
            },
            .operands = .{ .min = 0, .max = @as(?usize, 0) },
        };
    };

    // -LP means last option wins
    const result = try OptionParser(TestOpts).parse(&.{ "pwd", "-LP" });
    try std.testing.expectEqual(true, result.options.physical);
}

test "parse: last option wins" {
    const TestOpts = struct {
        physical: bool = false,

        pub const meta = .{
            .name = "pwd",
            .options = &.{
                .{ .short = 'L', .field = "physical", .value = false },
                .{ .short = 'P', .field = "physical", .value = true },
            },
            .operands = .{ .min = 0, .max = @as(?usize, 0) },
        };
    };

    // -P then -L means logical mode
    const result = try OptionParser(TestOpts).parse(&.{ "pwd", "-P", "-L" });
    try std.testing.expectEqual(false, result.options.physical);
}

test "parse: double dash ends options" {
    const TestOpts = struct {
        flag: bool = false,

        pub const meta = .{
            .name = "test",
            .options = &.{
                .{ .short = 'f', .field = "flag", .value = true },
            },
            .operands = .{ .min = 0, .max = @as(?usize, null) },
        };
    };

    // -- then -f means -f is an operand
    const result = try OptionParser(TestOpts).parse(&.{ "test", "--", "-f" });
    try std.testing.expectEqual(false, result.options.flag);
    try std.testing.expectEqual(@as(usize, 1), result.operands.len);
    try std.testing.expectEqualStrings("-f", result.operands[0]);
}

test "parse: bare dash is operand" {
    const TestOpts = struct {
        flag: bool = false,

        pub const meta = .{
            .name = "cd",
            .options = &.{
                .{ .short = 'L', .field = "flag", .value = false },
            },
            .operands = .{ .min = 0, .max = @as(?usize, 1) },
        };
    };

    // - is an operand (e.g., cd -)
    const result = try OptionParser(TestOpts).parse(&.{ "cd", "-" });
    try std.testing.expectEqual(@as(usize, 1), result.operands.len);
    try std.testing.expectEqualStrings("-", result.operands[0]);
}

test "parse: invalid option returns error" {
    const TestOpts = struct {
        flag: bool = false,

        pub const meta = .{
            .name = "test",
            .options = &.{
                .{ .short = 'f', .field = "flag", .value = true },
            },
            .operands = .{ .min = 0, .max = @as(?usize, null) },
        };
    };

    const result = OptionParser(TestOpts).parse(&.{ "test", "-x" });
    try std.testing.expectError(error.InvalidOption, result);
}

test "parse: too many operands returns error" {
    const TestOpts = struct {
        pub const meta = .{
            .name = "pwd",
            .options = &.{},
            .operands = .{ .min = 0, .max = @as(?usize, 0) },
        };
    };

    const result = OptionParser(TestOpts).parse(&.{ "pwd", "extra" });
    try std.testing.expectError(error.TooManyOperands, result);
}

test "parse: missing operand returns error" {
    const TestOpts = struct {
        pub const meta = .{
            .name = "test",
            .options = &.{},
            .operands = .{ .min = 1, .max = @as(?usize, null) },
        };
    };

    const result = OptionParser(TestOpts).parse(&.{"test"});
    try std.testing.expectError(error.MissingOperand, result);
}

test "parse: operands after options" {
    const TestOpts = struct {
        verbose: bool = false,

        pub const meta = .{
            .name = "unset",
            .options = &.{
                .{ .short = 'v', .field = "verbose", .value = true },
            },
            .operands = .{ .min = 1, .max = @as(?usize, null) },
        };
    };

    const result = try OptionParser(TestOpts).parse(&.{ "unset", "-v", "FOO", "BAR" });
    try std.testing.expectEqual(true, result.options.verbose);
    try std.testing.expectEqual(@as(usize, 2), result.operands.len);
    try std.testing.expectEqualStrings("FOO", result.operands[0]);
    try std.testing.expectEqualStrings("BAR", result.operands[1]);
}

test "parse: options after operand are treated as operands" {
    const TestOpts = struct {
        flag: bool = false,

        pub const meta = .{
            .name = "test",
            .options = &.{
                .{ .short = 'f', .field = "flag", .value = true },
            },
            .operands = .{ .min = 0, .max = @as(?usize, null) },
        };
    };

    // POSIX: once a non-option is seen, remaining args are operands
    const result = try OptionParser(TestOpts).parse(&.{ "test", "operand", "-f" });
    try std.testing.expectEqual(false, result.options.flag);
    try std.testing.expectEqual(@as(usize, 2), result.operands.len);
    try std.testing.expectEqualStrings("operand", result.operands[0]);
    try std.testing.expectEqualStrings("-f", result.operands[1]);
}
