//! Builtin commands for the POSIX shell.
//!
//! This module implements shell builtin commands that must run in the shell
//! process itself (not forked), because they modify shell state.
//!
//! POSIX Reference: Section 2.14 - Special Built-In Utilities
//!
//! Special builtins differ from regular builtins in that:
//! - Variable assignments preceding them persist after the command completes
//! - Errors in special builtins may cause the shell to exit
//!
//! Currently implemented builtins:
//! - cd: Change working directory (Section 2.14.1)
//! - exit: Exit the shell (Section 2.14.1)
//! - export: Export variables to the environment (Section 2.14.1)
//! - pwd: Print working directory (Section 2.14.1)
//! - test/[: Evaluate conditional expressions (Section 4 Utilities)
//! - unset: Unset variables (Section 2.14.1)

const std = @import("std");
const posix = std.posix;
const state = @import("state.zig");
const options = @import("options.zig");
const builtin_test = @import("builtin_test.zig");
const ShellState = state.ShellState;
const printError = state.printError;

/// Result of executing a builtin command.
pub const BuiltinResult = union(enum) {
    /// Normal completion with exit code.
    exit_code: u8,
    /// Exit the shell with the given exit code.
    exit: u8,
    /// Break n levels of enclosing loops.
    break_loop: u32,
    /// Continue n levels of enclosing loops.
    continue_loop: u32,
    /// Special builtin error. POSIX requires non-interactive shells to exit
    /// on special builtin errors, while interactive shells continue.
    /// (See POSIX Section 2.8.1 - Consequences of Shell Errors)
    builtin_error: u8,
};

/// Enumeration of all builtin commands.
///
/// Use `fromName` to look up a builtin by name, and `run` to execute it.
pub const Builtin = enum {
    @"[",
    @"break",
    cd,
    @"continue",
    exit,
    @"export",
    pwd,
    @"test",
    unset,

    /// Look up a builtin by name.
    ///
    /// Returns null if the name is not a builtin command.
    pub fn fromName(name: []const u8) ?Builtin {
        return std.meta.stringToEnum(Builtin, name);
    }

    /// Execute the builtin command.
    ///
    /// Args should include the command name as args[0].
    pub fn run(self: Builtin, args: []const []const u8, shell: *ShellState) BuiltinResult {
        return switch (self) {
            .@"[" => runBracket(args),
            .@"break" => runBreak(args, shell),
            .cd => runCd(args, shell),
            .@"continue" => runContinue(args, shell),
            .exit => runExit(args, shell),
            .@"export" => runExport(args, shell),
            .pwd => runPwd(args, shell),
            .@"test" => runTest(args),
            .unset => runUnset(args, shell),
        };
    }
};

// --- Builtin implementations ---

/// exit [n]
///
/// Exit the shell with status n. If n is omitted, exit with the status
/// of the last command executed. If n is not a valid number, print an
/// error and return status 2.
///
/// POSIX Reference: Section 2.14.1 - exit
fn runExit(args: []const []const u8, shell: *ShellState) BuiltinResult {
    // exit with no args: use last exit status
    if (args.len <= 1) {
        return .{ .exit = shell.last_status.toExitCode() };
    }

    // exit with too many args
    if (args.len > 2) {
        printError("exit: too many arguments\n", .{});
        return .{ .builtin_error = 1 };
    }

    // Parse the exit code
    // POSIX specifies "unsigned decimal integer", but common shells (bash, dash)
    // accept negative values and interpret them modulo 256. We follow this
    // convention: exit -1 produces exit code 255.
    const code_str = args[1];
    const code = std.fmt.parseInt(i32, code_str, 10) catch {
        printError("exit: {s}: numeric argument required\n", .{code_str});
        return .{ .builtin_error = 2 };
    };

    // Truncate to low 8 bits (handles both positive overflow and negative values)
    const exit_code: u8 = @truncate(@as(u32, @bitCast(code)));

    return .{ .exit = exit_code };
}

/// Parse loop level argument for break/continue builtins.
/// Returns the level count (default 1) or a builtin_error result.
fn parseLoopLevel(name: []const u8, args: []const []const u8) union(enum) {
    levels: u32,
    err: BuiltinResult,
} {
    if (args.len <= 1) return .{ .levels = 1 };

    if (args.len > 2) {
        printError("{s}: too many arguments\n", .{name});
        return .{ .err = .{ .builtin_error = 1 } };
    }

    const num = std.fmt.parseInt(i32, args[1], 10) catch {
        printError("{s}: {s}: numeric argument required\n", .{ name, args[1] });
        return .{ .err = .{ .builtin_error = 2 } };
    };

    if (num <= 0) {
        printError("{s}: {}: loop count out of range\n", .{ name, num });
        return .{ .err = .{ .builtin_error = 1 } };
    }

    return .{ .levels = @intCast(num) };
}

/// break [n]
///
/// Exit from the nth enclosing loop. If n is omitted, break exits from
/// the immediately enclosing loop. n must be a positive integer >= 1.
/// If n is 0, negative, or non-numeric, an error is returned.
///
/// POSIX Reference: Section 2.9.4.3 - break
fn runBreak(args: []const []const u8, _: *ShellState) BuiltinResult {
    return switch (parseLoopLevel("break", args)) {
        .levels => |n| .{ .break_loop = n },
        .err => |e| e,
    };
}

/// continue [n]
///
/// Continue with the next iteration of the nth enclosing loop. If n is
/// omitted, continue skips to the next iteration of the immediately
/// enclosing loop. n must be a positive integer >= 1. If n is 0, negative,
/// or non-numeric, an error is returned.
///
/// POSIX Reference: Section 2.9.4.4 - continue
fn runContinue(args: []const []const u8, _: *ShellState) BuiltinResult {
    return switch (parseLoopLevel("continue", args)) {
        .levels => |n| .{ .continue_loop = n },
        .err => |e| e,
    };
}

/// cd [-L|-P] [directory]
///
/// Change the current working directory. If directory is not specified,
/// change to $HOME. If directory is "-", change to $OLDPWD.
///
/// Options:
///   -L  Handle the operand dot-dot logically (default)
///   -P  Handle the operand dot-dot physically (resolve symlinks)
///
/// POSIX Reference: Section 2.14.1 - cd
fn runCd(args: []const []const u8, shell: *ShellState) BuiltinResult {
    const CdOptions = struct {
        physical: bool = false,

        pub const meta = .{
            .name = "cd",
            .options = &.{
                .{ .short = 'L', .field = "physical", .value = false },
                .{ .short = 'P', .field = "physical", .value = true },
            },
            .operands = .{ .min = 0, .max = @as(?usize, 1) },
        };
    };

    const parsed = options.OptionParser(CdOptions).parse(args) catch {
        return .{ .exit_code = 1 };
    };

    const physical = parsed.options.physical;
    const dir_arg: ?[]const u8 = if (parsed.operands.len > 0) parsed.operands[0] else null;

    // Determine target directory
    // For "cd -", we swap cwd and oldcwd, so track this case specially
    const is_cd_minus = if (dir_arg) |d| std.mem.eql(u8, d, "-") else false;

    const target: []const u8 = if (dir_arg) |d| blk: {
        if (std.mem.eql(u8, d, "-")) {
            // cd - : go to OLDPWD
            if (shell.oldcwd) |old| {
                // Print the directory we're changing to
                var buf: [256]u8 = undefined;
                var stdout = std.fs.File.stdout().writerStreaming(&buf);
                stdout.interface.print("{s}\n", .{old}) catch {};
                stdout.interface.flush() catch {};
                break :blk old;
            } else {
                printError("cd: OLDPWD not set\n", .{});
                return .{ .exit_code = 1 };
            }
        } else {
            break :blk d;
        }
    } else blk: {
        // No directory specified: go to HOME
        if (shell.home) |home| {
            break :blk home;
        } else {
            printError("cd: HOME not set\n", .{});
            return .{ .exit_code = 1 };
        }
    };

    // Change directory
    posix.chdir(target) catch |err| {
        printError("cd: {s}: {s}\n", .{ target, @errorName(err) });
        return .{ .exit_code = 1 };
    };

    // Update cwd - get the new path as an owned slice
    const new_cwd: []const u8 = if (physical) blk: {
        // Physical mode: get actual path from filesystem
        var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
        const cwd_slice = posix.getcwd(&cwd_buf) catch {
            printError("cd: error getting current directory\n", .{});
            return .{ .exit_code = 1 };
        };
        break :blk shell.allocator.dupe(u8, cwd_slice) catch {
            printError("cd: memory allocation failed\n", .{});
            return .{ .exit_code = 1 };
        };
    } else if (is_cd_minus) blk: {
        // For cd -, we already have oldcwd allocated, just swap pointers
        // This avoids the dangling pointer issue where target points to oldcwd
        break :blk shell.oldcwd.?;
    } else blk: {
        // Logical mode: compute path based on current logical cwd and target
        // Uses std.fs.path.resolvePosix to normalize . and .. components
        break :blk std.fs.path.resolvePosix(shell.allocator, &.{ shell.cwd, target }) catch {
            // Fallback to getcwd if path resolution fails
            var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
            const cwd_slice = posix.getcwd(&cwd_buf) catch {
                printError("cd: error getting current directory\n", .{});
                return .{ .exit_code = 1 };
            };
            break :blk shell.allocator.dupe(u8, cwd_slice) catch {
                printError("cd: memory allocation failed\n", .{});
                return .{ .exit_code = 1 };
            };
        };
    };

    // Update shell state
    if (is_cd_minus and !physical) {
        // For cd - in logical mode, swap cwd and oldcwd (no allocation/free needed)
        shell.oldcwd = shell.cwd;
        shell.cwd = new_cwd;
    } else {
        // Normal case (including cd -P -): free old oldcwd, shift cwd to oldcwd, set new cwd
        if (shell.oldcwd) |old| {
            shell.allocator.free(old);
        }
        shell.oldcwd = shell.cwd;
        shell.cwd = new_cwd;
    }

    // Update PWD and OLDPWD in environment
    // Note: We ignore allocation failures here. The directory change has already
    // succeeded, and failing to update the environment variable is non-fatal.
    // Child processes will inherit the correct working directory regardless.
    shell.env.put("PWD", new_cwd) catch {};
    if (shell.oldcwd) |old| {
        shell.env.put("OLDPWD", old) catch {};
    }

    return .{ .exit_code = 0 };
}

/// pwd [-L|-P]
///
/// Print the current working directory.
/// -L: Logical path (default) - from shell tracking, may include symlinks
/// -P: Physical path - resolved from filesystem
///
/// POSIX Reference: Section 2.14.1 - pwd
fn runPwd(args: []const []const u8, shell: *ShellState) BuiltinResult {
    const PwdOptions = struct {
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

    const parsed = options.OptionParser(PwdOptions).parse(args) catch {
        return .{ .exit_code = 1 };
    };

    // Buffer declared outside conditional so it remains valid for the write
    var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
    const output = if (parsed.options.physical)
        posix.getcwd(&cwd_buf) catch {
            printError("pwd: error getting current directory\n", .{});
            return .{ .exit_code = 1 };
        }
    else
        shell.cwd;

    // Write to stdout using streaming writer
    var buf: [256]u8 = undefined;
    var stdout = std.fs.File.stdout().writerStreaming(&buf);
    stdout.interface.print("{s}\n", .{output}) catch {};
    stdout.interface.flush() catch {};

    return .{ .exit_code = 0 };
}

/// Write a shell-escaped value to the given writer.
/// Uses single quotes for safety, escaping embedded single quotes as '\''
/// (end quote, escaped quote, start quote).
fn writeShellEscaped(w: *std.io.Writer, value: []const u8) void {
    w.writeAll("'") catch {};
    var remaining = value;
    while (std.mem.indexOfScalar(u8, remaining, '\'')) |quote_pos| {
        // Write everything up to the quote
        w.writeAll(remaining[0..quote_pos]) catch {};
        // Write escaped quote: end quote, backslash-quote, start quote
        w.writeAll("'\\''") catch {};
        // Continue after the quote
        remaining = remaining[quote_pos + 1 ..];
    }
    // Write the rest (no more quotes)
    w.writeAll(remaining) catch {};
    w.writeAll("'") catch {};
}

/// export [name[=value]...]
///
/// Mark variables for export to the environment. If no arguments are given,
/// print all exported variables.
///
/// POSIX Reference: Section 2.14.1 - export
fn runExport(args: []const []const u8, shell: *ShellState) BuiltinResult {
    // No arguments: list all exported variables.
    // POSIX (Section 2.14 - export): "export shall write to the standard output
    // the names and values of all exported variables"
    // This includes inherited environment variables, not just those explicitly
    // exported in this session. Output format must be suitable for shell reinput.
    if (args.len <= 1) {
        var buf: [256]u8 = undefined;
        var stdout = std.fs.File.stdout().writerStreaming(&buf);
        defer stdout.interface.flush() catch {};

        // Print all variables in env (all have the export attribute)
        var env_iter = shell.env.hash_map.iterator();
        while (env_iter.next()) |entry| {
            stdout.interface.print("export {s}=", .{entry.key_ptr.*}) catch {};
            writeShellEscaped(&stdout.interface, entry.value_ptr.*);
            stdout.interface.writeAll("\n") catch {};
        }

        // Also print variables marked for export but without values yet
        // (e.g., `export FOO` without assignment)
        var names_iter = shell.exported_names.keyIterator();
        while (names_iter.next()) |name_ptr| {
            const name = name_ptr.*;
            if (!shell.env.hash_map.contains(name)) {
                stdout.interface.print("export {s}\n", .{name}) catch {};
            }
        }
        return .{ .exit_code = 0 };
    }

    // Process each argument, tracking if any errors occurred
    var had_error = false;
    for (args[1..]) |arg| {
        // Check for NAME=VALUE form
        if (std.mem.indexOf(u8, arg, "=")) |eq_pos| {
            const name = arg[0..eq_pos];
            const value = arg[eq_pos + 1 ..];

            if (!isValidIdentifier(name)) {
                printError("export: `{s}': not a valid identifier\n", .{arg});
                had_error = true;
                continue;
            }

            // Set the variable in env
            shell.env.put(name, value) catch {
                printError("export: memory allocation failed\n", .{});
                return .{ .exit_code = 1 };
            };

            // Update cached values if necessary
            if (std.mem.eql(u8, name, "HOME")) {
                shell.home = shell.env.get("HOME");
            } else if (std.mem.eql(u8, name, "PS1")) {
                shell.ps1 = shell.env.get("PS1") orelse state.DEFAULT_PS1;
            }

            // Remove from variables if present (it's now in env)
            if (shell.variables.fetchRemove(name)) |old| {
                shell.allocator.free(old.key);
                shell.allocator.free(old.value);
            }

            // Mark as exported
            if (!shell.exported_names.contains(name)) {
                const duped_name = shell.allocator.dupe(u8, name) catch {
                    printError("export: memory allocation failed\n", .{});
                    return .{ .exit_code = 1 };
                };
                shell.exported_names.put(duped_name, {}) catch {
                    shell.allocator.free(duped_name);
                    printError("export: memory allocation failed\n", .{});
                    return .{ .exit_code = 1 };
                };
            }
        } else {
            // NAME only: mark for export
            const name = arg;

            if (!isValidIdentifier(name)) {
                printError("export: `{s}': not a valid identifier\n", .{name});
                had_error = true;
                continue;
            }

            // If variable exists in shell variables, move to env
            if (shell.variables.fetchRemove(name)) |old| {
                shell.env.put(name, old.value) catch {
                    printError("export: memory allocation failed\n", .{});
                    return .{ .exit_code = 1 };
                };
                shell.allocator.free(old.key);
                // EnvMap duplicates the value, so we need to free our copy
                shell.allocator.free(old.value);
            }

            // Mark as exported (even if no value yet)
            if (!shell.exported_names.contains(name)) {
                const duped_name = shell.allocator.dupe(u8, name) catch {
                    printError("export: memory allocation failed\n", .{});
                    return .{ .exit_code = 1 };
                };
                shell.exported_names.put(duped_name, {}) catch {
                    shell.allocator.free(duped_name);
                    printError("export: memory allocation failed\n", .{});
                    return .{ .exit_code = 1 };
                };
            }
        }
    }

    // POSIX: special builtin errors should cause non-interactive shells to exit
    if (had_error) {
        return .{ .builtin_error = 1 };
    }
    return .{ .exit_code = 0 };
}

/// unset [-v] name...
///
/// Unset variables. The -v option explicitly specifies variables (default).
/// The -f option for functions is not yet supported.
///
/// POSIX Reference: Section 2.14.1 - unset
fn runUnset(args: []const []const u8, shell: *ShellState) BuiltinResult {
    const UnsetMode = enum { variables, functions };
    const UnsetOptions = struct {
        // -v (default) unsets variables, -f unsets functions
        // These are mutually exclusive; last one wins per POSIX
        mode: UnsetMode = .variables,

        pub const meta = .{
            .name = "unset",
            .options = &.{
                .{ .short = 'v', .field = "mode", .value = UnsetMode.variables },
                .{ .short = 'f', .field = "mode", .value = UnsetMode.functions },
            },
            .operands = .{ .min = 0, .max = @as(?usize, null) },
        };
    };

    const parsed = options.OptionParser(UnsetOptions).parse(args) catch {
        return .{ .exit_code = 1 };
    };

    // -f for functions is recognized but not yet supported
    if (parsed.options.mode == .functions) {
        printError("unset: functions not yet supported\n", .{});
        return .{ .exit_code = 1 };
    }

    // Unset each variable, tracking if any errors occurred.
    //
    // Note on PWD/OLDPWD: POSIX (Section 2.5.3 Shell Variables) states that if
    // an application unsets PWD or OLDPWD, the behavior of cd and pwd is
    // unspecified. We allow the unset but maintain internal cwd/oldcwd tracking,
    // matching bash and dash behavior. The shell.cwd and shell.oldcwd allocations
    // are independent from the environment variables, so no memory issues arise.
    var had_error = false;
    for (parsed.operands) |name| {

        // Validate identifier
        if (!isValidIdentifier(name)) {
            printError("unset: `{s}': not a valid identifier\n", .{name});
            had_error = true;
            continue;
        }

        // Remove from shell variables
        if (shell.variables.fetchRemove(name)) |old| {
            shell.allocator.free(old.key);
            shell.allocator.free(old.value);
        }

        // Remove from environment
        _ = shell.env.remove(name);

        // Remove from exported_names
        if (shell.exported_names.fetchRemove(name)) |old| {
            shell.allocator.free(old.key);
        }

        // Update cached values if necessary
        if (std.mem.eql(u8, name, "HOME")) {
            shell.home = null;
        } else if (std.mem.eql(u8, name, "PS1")) {
            shell.ps1 = state.DEFAULT_PS1;
        }
    }

    // POSIX: special builtin errors should cause non-interactive shells to exit
    if (had_error) {
        return .{ .builtin_error = 1 };
    }
    return .{ .exit_code = 0 };
}

/// test expression
///
/// Evaluate a conditional expression and return an exit status of 0 (true)
/// or 1 (false). Returns 2 if an error occurs.
///
/// POSIX Reference: Section 4 Utilities - test
fn runTest(args: []const []const u8) BuiltinResult {
    // Skip argv[0] ("test")
    const test_args = if (args.len > 0) args[1..] else args;

    const result = builtin_test.evaluate(test_args) catch |err| {
        printTestError("test", err);
        // POSIX.1-2017 Section 4 Utilities, test, EXIT STATUS:
        // ">1: An error occurred."
        return .{ .exit_code = 2 };
    };

    // POSIX.1-2017 Section 4 Utilities, test, EXIT STATUS:
    // "0: expression evaluated to true."
    // "1: expression evaluated to false or expression was missing."
    return .{ .exit_code = if (result) 0 else 1 };
}

/// [ expression ]
///
/// Alternate form of test. The closing bracket ] must be present as the
/// last argument.
///
/// POSIX Reference: Section 4 Utilities - test
fn runBracket(args: []const []const u8) BuiltinResult {
    // Skip argv[0] ("[")
    const test_args = if (args.len > 0) args[1..] else args;

    // POSIX.1-2017 Section 4 Utilities, test, DESCRIPTION:
    // "the application shall ensure that the closing square bracket
    // is a separate argument"
    if (test_args.len == 0 or !std.mem.eql(u8, test_args[test_args.len - 1], "]")) {
        printError("[: missing ']'\n", .{});
        return .{ .exit_code = 2 };
    }

    // POSIX.1-2017 Section 4 Utilities, test, OPERANDS:
    // "when using the "[...]" form, the <right-square-bracket> final argument
    // shall not be counted in this algorithm"
    const inner_args = test_args[0 .. test_args.len - 1];

    const result = builtin_test.evaluate(inner_args) catch |err| {
        printTestError("[", err);
        return .{ .exit_code = 2 };
    };

    return .{ .exit_code = if (result) 0 else 1 };
}

/// Print an error message for test/[ builtin errors.
fn printTestError(name: []const u8, err: builtin_test.TestError) void {
    const msg = switch (err) {
        error.IntegerExpected => "integer expected",
        error.UnknownOperator => "unknown operator",
        error.TooManyArguments => "too many arguments",
    };
    printError("{s}: {s}\n", .{ name, msg });
}

/// Check if a string is a valid shell identifier.
///
/// Valid identifiers match: [A-Za-z_][A-Za-z0-9_]*
fn isValidIdentifier(s: []const u8) bool {
    if (s.len == 0) return false;

    // First character must be letter or underscore
    const first = s[0];
    if (!std.ascii.isAlphabetic(first) and first != '_') {
        return false;
    }

    // Rest can be letters, digits, or underscores
    for (s[1..]) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '_') {
            return false;
        }
    }

    return true;
}

// --- Tests ---

test {
    _ = @import("builtin_test.zig");
}

test "Builtin.fromName: recognizes builtins" {
    try std.testing.expectEqual(Builtin.@"[", Builtin.fromName("[").?);
    try std.testing.expectEqual(Builtin.cd, Builtin.fromName("cd").?);
    try std.testing.expectEqual(Builtin.exit, Builtin.fromName("exit").?);
    try std.testing.expectEqual(Builtin.@"export", Builtin.fromName("export").?);
    try std.testing.expectEqual(Builtin.pwd, Builtin.fromName("pwd").?);
    try std.testing.expectEqual(Builtin.@"test", Builtin.fromName("test").?);
    try std.testing.expectEqual(Builtin.unset, Builtin.fromName("unset").?);
}

test "Builtin.fromName: returns null for non-builtins" {
    try std.testing.expect(Builtin.fromName("echo") == null);
    try std.testing.expect(Builtin.fromName("ls") == null);
    try std.testing.expect(Builtin.fromName("") == null);
}

test "isValidIdentifier: valid identifiers" {
    try std.testing.expect(isValidIdentifier("FOO"));
    try std.testing.expect(isValidIdentifier("foo"));
    try std.testing.expect(isValidIdentifier("_foo"));
    try std.testing.expect(isValidIdentifier("FOO_BAR"));
    try std.testing.expect(isValidIdentifier("foo123"));
    try std.testing.expect(isValidIdentifier("_"));
    try std.testing.expect(isValidIdentifier("_1"));
}

test "isValidIdentifier: invalid identifiers" {
    try std.testing.expect(!isValidIdentifier(""));
    try std.testing.expect(!isValidIdentifier("123"));
    try std.testing.expect(!isValidIdentifier("1foo"));
    try std.testing.expect(!isValidIdentifier("foo-bar"));
    try std.testing.expect(!isValidIdentifier("foo.bar"));
    try std.testing.expect(!isValidIdentifier("foo=bar"));
}

test "runExit: no args uses last_status" {
    var env = std.process.EnvMap.init(std.testing.allocator);
    var shell = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer shell.deinit();

    shell.last_status = .{ .exited = 42 };

    const result = runExit(&[_][]const u8{"exit"}, &shell);
    try std.testing.expect(result == .exit);
    try std.testing.expectEqual(@as(u8, 42), result.exit);
}

test "runExit: with numeric arg" {
    var env = std.process.EnvMap.init(std.testing.allocator);
    var shell = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer shell.deinit();

    const result = runExit(&[_][]const u8{ "exit", "5" }, &shell);
    try std.testing.expect(result == .exit);
    try std.testing.expectEqual(@as(u8, 5), result.exit);
}

test "runExit: with invalid arg returns builtin_error with status 2" {
    // POSIX: "exit abc" is a special builtin error
    var env = std.process.EnvMap.init(std.testing.allocator);
    var shell = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer shell.deinit();

    const result = runExit(&[_][]const u8{ "exit", "abc" }, &shell);
    try std.testing.expect(result == .builtin_error);
    try std.testing.expectEqual(@as(u8, 2), result.builtin_error);
}

test "runExit: with too many args returns builtin_error" {
    var env = std.process.EnvMap.init(std.testing.allocator);
    var shell = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer shell.deinit();

    const result = runExit(&[_][]const u8{ "exit", "1", "2" }, &shell);
    try std.testing.expect(result == .builtin_error);
    try std.testing.expectEqual(@as(u8, 1), result.builtin_error);
}

test "runExit: large value wraps to 8 bits" {
    // POSIX: only low-order 8 bits are used by waitpid
    // exit 256 should wrap to 0, exit 257 to 1, etc.
    var env = std.process.EnvMap.init(std.testing.allocator);
    var shell = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer shell.deinit();

    const result256 = runExit(&[_][]const u8{ "exit", "256" }, &shell);
    try std.testing.expect(result256 == .exit);
    try std.testing.expectEqual(@as(u8, 0), result256.exit);

    const result257 = runExit(&[_][]const u8{ "exit", "257" }, &shell);
    try std.testing.expect(result257 == .exit);
    try std.testing.expectEqual(@as(u8, 1), result257.exit);

    const result300 = runExit(&[_][]const u8{ "exit", "300" }, &shell);
    try std.testing.expect(result300 == .exit);
    try std.testing.expectEqual(@as(u8, 44), result300.exit); // 300 % 256 = 44
}

test "runExit: negative values wrap correctly" {
    // Common shells accept negative values: exit -1 becomes 255
    var env = std.process.EnvMap.init(std.testing.allocator);
    var shell = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer shell.deinit();

    const result_neg1 = runExit(&[_][]const u8{ "exit", "-1" }, &shell);
    try std.testing.expect(result_neg1 == .exit);
    try std.testing.expectEqual(@as(u8, 255), result_neg1.exit);

    const result_neg2 = runExit(&[_][]const u8{ "exit", "-2" }, &shell);
    try std.testing.expect(result_neg2 == .exit);
    try std.testing.expectEqual(@as(u8, 254), result_neg2.exit);

    const result_neg256 = runExit(&[_][]const u8{ "exit", "-256" }, &shell);
    try std.testing.expect(result_neg256 == .exit);
    try std.testing.expectEqual(@as(u8, 0), result_neg256.exit);
}

// --- test builtin tests ---

test "runTest: returns 0 for true expression" {
    const result = runTest(&[_][]const u8{ "test", "-n", "hello" });
    try std.testing.expect(result == .exit_code);
    try std.testing.expectEqual(@as(u8, 0), result.exit_code);
}

test "runTest: returns 1 for false expression" {
    const result = runTest(&[_][]const u8{ "test", "-z", "hello" });
    try std.testing.expectEqual(@as(u8, 1), result.exit_code);
}

test "runTest: returns 1 for empty expression" {
    // POSIX: "0 arguments: Exit false (1)."
    const result = runTest(&[_][]const u8{"test"});
    try std.testing.expectEqual(@as(u8, 1), result.exit_code);
}

test "runTest: returns 2 for error" {
    // Too many arguments causes an error
    const result = runTest(&[_][]const u8{ "test", "a", "b", "c", "d", "e" });
    try std.testing.expectEqual(@as(u8, 2), result.exit_code);
}

test "runTest: string equality" {
    const result_true = runTest(&[_][]const u8{ "test", "foo", "=", "foo" });
    try std.testing.expectEqual(@as(u8, 0), result_true.exit_code);

    const result_false = runTest(&[_][]const u8{ "test", "foo", "=", "bar" });
    try std.testing.expectEqual(@as(u8, 1), result_false.exit_code);
}

test "runTest: integer comparison" {
    const result = runTest(&[_][]const u8{ "test", "5", "-lt", "10" });
    try std.testing.expectEqual(@as(u8, 0), result.exit_code);
}

test "runTest: file test -d /tmp" {
    const result = runTest(&[_][]const u8{ "test", "-d", "/tmp" });
    try std.testing.expectEqual(@as(u8, 0), result.exit_code);
}

// --- [ builtin tests ---

test "runBracket: returns 0 for true expression" {
    const result = runBracket(&[_][]const u8{ "[", "-n", "hello", "]" });
    try std.testing.expect(result == .exit_code);
    try std.testing.expectEqual(@as(u8, 0), result.exit_code);
}

test "runBracket: returns 1 for false expression" {
    const result = runBracket(&[_][]const u8{ "[", "-z", "hello", "]" });
    try std.testing.expectEqual(@as(u8, 1), result.exit_code);
}

test "runBracket: returns 2 for missing ]" {
    const result = runBracket(&[_][]const u8{ "[", "-n", "hello" });
    try std.testing.expectEqual(@as(u8, 2), result.exit_code);
}

test "runBracket: returns 2 for empty args (no ])" {
    const result = runBracket(&[_][]const u8{"["});
    try std.testing.expectEqual(@as(u8, 2), result.exit_code);
}

test "runBracket: empty expression with ] returns 1" {
    // [ ] is equivalent to test with 0 args -> false
    const result = runBracket(&[_][]const u8{ "[", "]" });
    try std.testing.expectEqual(@as(u8, 1), result.exit_code);
}

test "runBracket: string equality" {
    const result = runBracket(&[_][]const u8{ "[", "foo", "=", "foo", "]" });
    try std.testing.expectEqual(@as(u8, 0), result.exit_code);
}

test "runBracket: ] in wrong position is not closing bracket" {
    // [ ] = ] ] - the middle ] is treated as an operand, last ] is the closer
    // This is "test ] = ]" which is string equality, should be true
    const result = runBracket(&[_][]const u8{ "[", "]", "=", "]", "]" });
    try std.testing.expectEqual(@as(u8, 0), result.exit_code);
}

// --- break builtin tests ---

test "runBreak: no argument returns break_loop with level 1" {
    var shell: ShellState = undefined;
    const result = runBreak(&[_][]const u8{"break"}, &shell);
    try std.testing.expect(result == .break_loop);
    try std.testing.expectEqual(@as(u32, 1), result.break_loop);
}

test "runBreak: with numeric argument returns that level" {
    var shell: ShellState = undefined;
    const result = runBreak(&[_][]const u8{ "break", "3" }, &shell);
    try std.testing.expect(result == .break_loop);
    try std.testing.expectEqual(@as(u32, 3), result.break_loop);
}

test "runBreak: zero argument returns builtin_error" {
    var shell: ShellState = undefined;
    const result = runBreak(&[_][]const u8{ "break", "0" }, &shell);
    try std.testing.expect(result == .builtin_error);
    try std.testing.expectEqual(@as(u8, 1), result.builtin_error);
}

test "runBreak: negative argument returns builtin_error" {
    var shell: ShellState = undefined;
    const result = runBreak(&[_][]const u8{ "break", "-1" }, &shell);
    try std.testing.expect(result == .builtin_error);
    try std.testing.expectEqual(@as(u8, 1), result.builtin_error);
}

test "runBreak: non-numeric argument returns builtin_error with code 2" {
    var shell: ShellState = undefined;
    const result = runBreak(&[_][]const u8{ "break", "abc" }, &shell);
    try std.testing.expect(result == .builtin_error);
    try std.testing.expectEqual(@as(u8, 2), result.builtin_error);
}

test "runBreak: too many arguments returns builtin_error" {
    var shell: ShellState = undefined;
    const result = runBreak(&[_][]const u8{ "break", "1", "2" }, &shell);
    try std.testing.expect(result == .builtin_error);
    try std.testing.expectEqual(@as(u8, 1), result.builtin_error);
}

// --- continue builtin tests ---

test "runContinue: no argument returns continue_loop with level 1" {
    var shell: ShellState = undefined;
    const result = runContinue(&[_][]const u8{"continue"}, &shell);
    try std.testing.expect(result == .continue_loop);
    try std.testing.expectEqual(@as(u32, 1), result.continue_loop);
}

test "runContinue: with numeric argument returns that level" {
    var shell: ShellState = undefined;
    const result = runContinue(&[_][]const u8{ "continue", "2" }, &shell);
    try std.testing.expect(result == .continue_loop);
    try std.testing.expectEqual(@as(u32, 2), result.continue_loop);
}

test "runContinue: zero argument returns builtin_error" {
    var shell: ShellState = undefined;
    const result = runContinue(&[_][]const u8{ "continue", "0" }, &shell);
    try std.testing.expect(result == .builtin_error);
    try std.testing.expectEqual(@as(u8, 1), result.builtin_error);
}

test "runContinue: negative argument returns builtin_error" {
    var shell: ShellState = undefined;
    const result = runContinue(&[_][]const u8{ "continue", "-1" }, &shell);
    try std.testing.expect(result == .builtin_error);
    try std.testing.expectEqual(@as(u8, 1), result.builtin_error);
}

test "runContinue: non-numeric argument returns builtin_error with code 2" {
    var shell: ShellState = undefined;
    const result = runContinue(&[_][]const u8{ "continue", "abc" }, &shell);
    try std.testing.expect(result == .builtin_error);
    try std.testing.expectEqual(@as(u8, 2), result.builtin_error);
}

test "runContinue: too many arguments returns builtin_error" {
    var shell: ShellState = undefined;
    const result = runContinue(&[_][]const u8{ "continue", "1", "2" }, &shell);
    try std.testing.expect(result == .builtin_error);
    try std.testing.expectEqual(@as(u8, 1), result.builtin_error);
}
