const std = @import("std");
const tsh = @import("tsh");

fn printUsage() void {
    std.debug.print(
        \\Usage: tsh [options] [file]
        \\
        \\Options:
        \\  -c <command>   Execute command string
        \\  -i             Force interactive mode (show prompts)
        \\  -l, --login    Run as login shell
        \\
        \\Output (default: execute commands):
        \\  --dump-tokens  Dump lexer tokens instead of executing
        \\  --dump-ast     Parse and dump AST instead of executing
        \\
        \\Other:
        \\  --help, -h     Show this help message
        \\
        \\If no file is provided and stdin is a terminal, runs in interactive mode.
        \\If file is "-", reads from stdin.
        \\
    , .{});
}

pub fn main() !u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    // Check if we're invoked as a login shell (argv[0] starts with '-')
    const program_name = args.next() orelse "tsh";
    var is_login_shell = program_name.len > 0 and program_name[0] == '-';

    // Parse command line arguments
    // TODO: Refactor to use options.zig once it supports:
    //   - Long options (--dump-tokens, --dump-ast, --login, --help)
    //   - Options with required arguments (-c <command>)
    //   - Special handling for script filename stopping option parsing
    //   - Collecting remaining args as positional parameters
    var processing_mode: tsh.ProcessingMode = .execute;
    var filename: ?[]const u8 = null;
    var command_string: ?[]const u8 = null;
    var force_interactive = false;
    var show_help = false;
    var positional_params: std.ArrayListUnmanaged([]const u8) = .{};
    defer positional_params.deinit(allocator);

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--dump-tokens")) {
            processing_mode = .dump_tokens;
        } else if (std.mem.eql(u8, arg, "--dump-ast")) {
            processing_mode = .dump_ast;
        } else if (std.mem.eql(u8, arg, "-c")) {
            command_string = args.next() orelse {
                std.debug.print("tsh: -c requires a command string\n", .{});
                printUsage();
                return 1;
            };
            // Remaining args after -c command become positional parameters
            while (args.next()) |positional| {
                try positional_params.append(allocator, positional);
            }
            break;
        } else if (std.mem.eql(u8, arg, "--login") or std.mem.eql(u8, arg, "-l")) {
            is_login_shell = true;
        } else if (std.mem.eql(u8, arg, "-i")) {
            force_interactive = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            show_help = true;
        } else if (std.mem.eql(u8, arg, "-")) {
            // "-" means read from stdin (POSIX convention)
            filename = arg;
        } else if (arg.len > 0 and arg[0] == '-') {
            std.debug.print("tsh: unknown option: {s}\n", .{arg});
            printUsage();
            return 1;
        } else {
            // Script filename - remaining args become positional parameters
            filename = arg;
            while (args.next()) |positional| {
                try positional_params.append(allocator, positional);
            }
            break;
        }
    }

    // Handle help
    if (show_help) {
        printUsage();
        return 0;
    }

    // Determine if interactive mode
    // Interactive if: forced with -i, OR (no -c, no file, and stdin is a tty)
    const is_interactive = force_interactive or
        (command_string == null and filename == null and std.posix.isatty(std.posix.STDIN_FILENO));

    // TODO: Use is_login_shell for startup file loading:
    //       - Login shell: /etc/profile, ~/.profile
    //       - Interactive non-login: $ENV
    if (is_login_shell) {
        // Placeholder - startup file loading will be implemented later
    }

    // Initialize shell state
    var shell_state = try tsh.ShellState.init(allocator);
    defer shell_state.deinit();
    shell_state.options.interactive = is_interactive;

    // Set $0 (shell/script name)
    // For -c mode: first positional param becomes $0, rest are $1, $2, ...
    // For script mode: script filename is $0
    // For interactive/stdin: program name is $0
    if (command_string != null) {
        if (positional_params.items.len > 0) {
            shell_state.shell_name = positional_params.items[0];
            try shell_state.setPositionalParams(positional_params.items[1..]);
        }
        // else shell_name stays "tsh"
    } else if (filename) |fname| {
        shell_state.shell_name = fname;
        try shell_state.setPositionalParams(positional_params.items);
    }
    // else interactive mode: shell_name stays "tsh", no positional params

    // Determine input source and create reader
    var file: ?std.fs.File = null;
    defer if (file) |f| f.close();

    var read_buf: [4096]u8 = undefined;

    const exit_code = if (command_string) |cmd| blk: {
        // -c mode: fixed string reader
        var fixed_reader = std.io.Reader.fixed(cmd);
        break :blk try tsh.repl.run(allocator, &shell_state, &fixed_reader, processing_mode);
    } else if (filename) |fname| blk: {
        // File or "-" for stdin
        const input_file = if (std.mem.eql(u8, fname, "-"))
            std.fs.File.stdin()
        else inner: {
            file = std.fs.cwd().openFile(fname, .{}) catch |err| {
                std.debug.print("tsh: cannot open '{s}': {s}\n", .{ fname, @errorName(err) });
                return 1;
            };
            break :inner file.?;
        };
        var file_reader = input_file.reader(&read_buf);
        break :blk try tsh.repl.run(allocator, &shell_state, &file_reader.interface, processing_mode);
    } else blk: {
        // stdin (default)
        var stdin_reader = std.fs.File.stdin().reader(&read_buf);
        break :blk try tsh.repl.run(allocator, &shell_state, &stdin_reader.interface, processing_mode);
    };

    return exit_code;
}

// --- Integration tests for the CLI ---

/// Helper to run token dumping on a string and capture output
fn runTokenDumpTest(input: []const u8) ![]u8 {
    var writer = std.io.Writer.Allocating.init(std.testing.allocator);
    errdefer writer.deinit();

    var reader = std.io.Reader.fixed(input);

    // We test the token format directly using the lexer
    var lexer = tsh.Lexer.init(&reader);

    while (true) {
        const token = lexer.nextToken() catch |err| {
            try writer.writer.print("[{d}:{d}] Error: {s}\n", .{ lexer.line, lexer.column, @errorName(err) });
            break;
        };

        if (token) |tok| {
            switch (tok.type) {
                .Separator => {
                    try writer.writer.writeByte('\n');
                },
                else => {
                    try tok.format(&writer.writer);
                    try writer.writer.writeByte('\n');
                },
            }
        } else {
            break;
        }
    }

    return writer.toOwnedSlice();
}

fn expectTokenOutput(input: []const u8, expected: []const u8) !void {
    const output = try runTokenDumpTest(input);
    defer std.testing.allocator.free(output);
    try std.testing.expectEqualStrings(expected, output);
}

/// Helper to run AST dumping on a string and capture output
fn runAstDumpTest(input: []const u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var writer = std.io.Writer.Allocating.init(std.testing.allocator);
    errdefer writer.deinit();

    var reader = std.io.Reader.fixed(input);
    var lexer = tsh.Lexer.init(&reader);
    var parser = tsh.Parser.init(arena.allocator(), &lexer);

    const cmd_list = parser.parseCommandList() catch |err| {
        if (parser.getErrorInfo()) |info| {
            try writer.writer.print("[{d}:{d}] Error: {s} ({s})\n", .{
                info.line,
                info.column,
                info.message,
                @errorName(err),
            });
        } else {
            try writer.writer.print("Error: {s}\n", .{@errorName(err)});
        }
        return writer.toOwnedSlice();
    };

    if (cmd_list) |list| {
        try list.format(&writer.writer);
        try writer.writer.writeByte('\n');
    }

    return writer.toOwnedSlice();
}

fn expectAstOutput(input: []const u8, expected: []const u8) !void {
    const output = try runAstDumpTest(input);
    defer std.testing.allocator.free(output);
    try std.testing.expectEqualStrings(expected, output);
}

// CLI integration tests - representative examples to verify output formatting.
// Comprehensive token/parsing tests are in lexer.zig and parser.zig.

test "CLI: basic token output format" {
    try expectTokenOutput("hello world\n",
        \\[1:1] Literal("hello")
        \\[1:7] Literal("world")
        \\
        \\
    );
}

test "CLI: redirection output format" {
    try expectTokenOutput("cmd <in >out >>log 2>&1\n",
        \\[1:1] Literal("cmd")
        \\[1:5] Redirection(<) [incomplete]
        \\[1:6] Literal("in")
        \\[1:9] Redirection(>) [incomplete]
        \\[1:10] Literal("out")
        \\[1:14] Redirection(>>) [incomplete]
        \\[1:16] Literal("log")
        \\[1:20] Literal("2") [incomplete]
        \\[1:21] Redirection(>&) [incomplete]
        \\[1:23] Literal("1")
        \\
        \\
    );
}

test "CLI: multi-line output format" {
    try expectTokenOutput("echo hello\necho world\n",
        \\[1:1] Literal("echo")
        \\[1:6] Literal("hello")
        \\
        \\[2:1] Literal("echo")
        \\[2:6] Literal("world")
        \\
        \\
    );
}

test "CLI: empty and whitespace input" {
    // Note: These test the lexer directly, not the full CLI which skips blank lines
    try expectTokenOutput("", "");
    try expectTokenOutput("   \t  ", "");
    try expectTokenOutput("\n\n\n", "\n\n\n"); // Lexer produces Separator tokens for newlines
}

// --- Parser CLI tests ---

test "CLI parse: complex command output format" {
    try expectAstOutput("FOO=bar cmd 'arg 1' >out 2>&1\n",
        \\SimpleCommand:
        \\  assignments:
        \\    [0] FOO = "bar"
        \\  argv:
        \\    [0] "cmd"
        \\    [1] quoted("arg 1")
        \\  redirections:
        \\    [0] > "out"
        \\    [1] 2>& 1
        \\
        \\
    );
}
