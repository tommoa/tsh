const std = @import("std");
const tsh = @import("tsh");

/// Dump all tokens from the reader to the writer in human-readable format.
/// Returns the number of tokens processed.
fn dumpTokens(reader: *std.io.Reader, writer: *std.io.Writer) !usize {
    var lexer = tsh.Lexer.init(reader);
    var token_count: usize = 0;
    var had_token_on_line = false;

    while (true) {
        const token = lexer.nextToken() catch |err| {
            try writer.print("[{d}:{d}] Error: {s}\n", .{ lexer.line, lexer.column, @errorName(err) });
            break;
        };

        if (token) |tok| {
            try tok.format(writer);
            try writer.writeByte('\n');
            token_count += 1;
            had_token_on_line = true;
        } else {
            // null means end of command (newline) or end of input
            if (had_token_on_line) {
                try writer.writeByte('\n');
                had_token_on_line = false;
            }
            // Check if we've reached actual end of input
            if (reader.bufferedLen() == 0) {
                break;
            }
            // Otherwise it was just a newline, continue to next command
        }
    }
    return token_count;
}

/// Dump a Word to the writer.
fn dumpWord(word: tsh.Word, writer: *std.io.Writer) !void {
    if (word.parts.len == 0) {
        try writer.writeAll("\"\"");
        return;
    }

    if (word.parts.len == 1) {
        switch (word.parts[0]) {
            .literal => |lit| try writer.print("\"{s}\"", .{lit}),
        }
        return;
    }

    // Multiple parts - show as list
    try writer.writeByte('[');
    for (word.parts, 0..) |part, i| {
        if (i > 0) try writer.writeAll(", ");
        switch (part) {
            .literal => |lit| try writer.print("\"{s}\"", .{lit}),
        }
    }
    try writer.writeByte(']');
}

/// Dump a parsed command to the writer in human-readable format.
fn dumpCommand(cmd: tsh.SimpleCommand, writer: *std.io.Writer) !void {
    try writer.writeAll("SimpleCommand:\n");

    // Assignments
    if (cmd.assignments.len > 0) {
        try writer.writeAll("  assignments:\n");
        for (cmd.assignments, 0..) |assignment, i| {
            try writer.print("    [{d}] {s} = ", .{ i, assignment.name });
            try dumpWord(assignment.value, writer);
            try writer.writeByte('\n');
        }
    }

    // Argv
    if (cmd.argv.len > 0) {
        try writer.writeAll("  argv:\n");
        for (cmd.argv, 0..) |word, i| {
            try writer.print("    [{d}] ", .{i});
            try dumpWord(word, writer);
            try writer.writeByte('\n');
        }
    }

    // Redirections
    if (cmd.redirections.len > 0) {
        try writer.writeAll("  redirections:\n");
        for (cmd.redirections, 0..) |redir, i| {
            try writer.print("    [{d}] ", .{i});
            if (redir.source_fd) |fd| {
                try writer.print("{d}", .{fd});
            }
            switch (redir.op) {
                .In => try writer.writeByte('<'),
                .Out => try writer.writeByte('>'),
                .Append => try writer.writeAll(">>"),
                .Fd => try writer.writeAll(">&"),
            }
            try writer.writeByte(' ');
            switch (redir.target) {
                .file => |word| try dumpWord(word, writer),
                .fd => |fd| try writer.print("{d}", .{fd}),
                .close => try writer.writeAll("-"),
            }
            try writer.writeByte('\n');
        }
    }
}

/// Parse and dump all commands from the reader.
fn parseAndDump(allocator: std.mem.Allocator, reader: *std.io.Reader, writer: *std.io.Writer) !usize {
    var lexer = tsh.Lexer.init(reader);
    var command_count: usize = 0;

    while (true) {
        var parser = tsh.Parser.init(allocator, &lexer);

        const cmd = parser.parseCommand() catch |err| {
            if (parser.getErrorInfo()) |info| {
                try writer.print("[{d}:{d}] Error: {s} ({s})\n", .{
                    info.line,
                    info.column,
                    info.message,
                    @errorName(err),
                });
            } else {
                try writer.print("Error: {s}\n", .{@errorName(err)});
            }
            // Stop processing on parse error - recovery is complex and error-prone
            break;
        };

        if (cmd) |c| {
            try dumpCommand(c, writer);
            try writer.writeByte('\n');
            command_count += 1;
        }

        // Check if we've reached end of input
        if (reader.bufferedLen() == 0) {
            break;
        }
    }

    return command_count;
}

const Command = enum {
    dump_tokens,
    parse,
    help,
};

fn printUsage() void {
    std.debug.print(
        \\Usage: tsh [options] [file]
        \\
        \\Options:
        \\  --dump-tokens  Dump lexer tokens (default behavior)
        \\  --parse, -p    Parse and dump AST
        \\  --help, -h     Show this help message
        \\
        \\If no file is provided, reads from stdin.
        \\
    , .{});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.skip(); // skip program name

    // Parse command line arguments
    var command: Command = .dump_tokens;
    var filename: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--dump-tokens")) {
            command = .dump_tokens;
        } else if (std.mem.eql(u8, arg, "--parse") or std.mem.eql(u8, arg, "-p")) {
            command = .parse;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            command = .help;
        } else if (arg.len > 0 and arg[0] == '-') {
            std.debug.print("Unknown option: {s}\n", .{arg});
            printUsage();
            return error.InvalidArgument;
        } else {
            filename = arg;
        }
    }

    // Handle help command
    if (command == .help) {
        printUsage();
        return;
    }

    // Open file if provided, otherwise use stdin
    var file: ?std.fs.File = null;
    defer if (file) |f| f.close();

    var read_buf: [4096]u8 = undefined;

    // Create File.Reader, then get the std.io.Reader interface
    var file_reader = if (filename) |fname| blk: {
        file = std.fs.cwd().openFile(fname, .{}) catch |err| {
            std.debug.print("Error opening file '{s}': {}\n", .{ fname, err });
            return err;
        };
        break :blk file.?.reader(&read_buf);
    } else std.fs.File.stdin().reader(&read_buf);

    var stderr_buf: [4096]u8 = undefined;
    var stderr_writer = std.fs.File.stderr().writer(&stderr_buf);

    switch (command) {
        .dump_tokens => {
            _ = try dumpTokens(&file_reader.interface, &stderr_writer.interface);
            try stderr_writer.interface.flush();
        },
        .parse => {
            // Use an arena for parser allocations
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();
            _ = try parseAndDump(arena.allocator(), &file_reader.interface, &stderr_writer.interface);
            try stderr_writer.interface.flush();
        },
        .help => unreachable, // handled above
    }
}

// --- Integration tests for the CLI ---

fn runTest(input: []const u8) ![]u8 {
    var reader = std.io.Reader.fixed(input);
    var writer = std.io.Writer.Allocating.init(std.testing.allocator);
    errdefer writer.deinit();
    _ = try dumpTokens(&reader, &writer.writer);

    return writer.toOwnedSlice();
}

fn expectOutput(input: []const u8, expected: []const u8) !void {
    const output = try runTest(input);
    defer std.testing.allocator.free(output);
    try std.testing.expectEqualStrings(expected, output);
}

fn runParseTest(input: []const u8) ![]u8 {
    var reader = std.io.Reader.fixed(input);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var writer = std.io.Writer.Allocating.init(std.testing.allocator);
    errdefer writer.deinit();
    _ = try parseAndDump(arena.allocator(), &reader, &writer.writer);

    return writer.toOwnedSlice();
}

fn expectParseOutput(input: []const u8, expected: []const u8) !void {
    const output = try runParseTest(input);
    defer std.testing.allocator.free(output);
    try std.testing.expectEqualStrings(expected, output);
}

// CLI integration tests - representative examples to verify output formatting.
// Comprehensive token/parsing tests are in lexer.zig and parser.zig.

test "CLI: basic token output format" {
    // Tests basic literal output with position and incomplete flag
    try expectOutput("hello world\n",
        \\[1:1] Literal("hello")
        \\[1:7] Literal("world")
        \\
        \\
    );
}

test "CLI: redirection output format" {
    // Tests all redirection types in one command
    try expectOutput("cmd <in >out >>log 2>&1\n",
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
    // Tests line number tracking across multiple commands
    try expectOutput("echo hello\necho world\n",
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
    try expectOutput("", "");
    try expectOutput("   \t  ", "");
    try expectOutput("\n\n\n", "");
}

// --- Parser CLI tests ---

test "CLI parse: complex command output format" {
    // Single comprehensive test covering assignments, argv, and redirections
    try expectParseOutput("FOO=bar cmd 'arg 1' >out 2>&1\n",
        \\SimpleCommand:
        \\  assignments:
        \\    [0] FOO = "bar"
        \\  argv:
        \\    [0] "cmd"
        \\    [1] "arg 1"
        \\  redirections:
        \\    [0] > "out"
        \\    [1] 2>& 1
        \\
        \\
    );
}
