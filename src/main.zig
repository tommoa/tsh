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
            continue;
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

const Command = enum {
    dump_tokens,
    help,
};

fn printUsage() void {
    std.debug.print(
        \\Usage: tsh [options] [file]
        \\
        \\Options:
        \\  --dump-tokens  Dump lexer tokens (default behavior)
        \\  --help         Show this help message
        \\
        \\If no file is provided, reads from stdin.
        \\
    , .{});
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.skip(); // skip program name

    // Parse command line arguments
    var command: Command = .dump_tokens;
    var filename: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--dump-tokens")) {
            command = .dump_tokens;
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

test "CLI: simple literal" {
    try expectOutput("hello",
        \\[1:1] Literal("hello") [incomplete]
        \\
        \\
    );
}

test "CLI: simple literal with newline" {
    try expectOutput("hello\n",
        \\[1:1] Literal("hello")
        \\
        \\
    );
}

test "CLI: multiple literals" {
    try expectOutput("hello world",
        \\[1:1] Literal("hello")
        \\[1:7] Literal("world") [incomplete]
        \\
        \\
    );
}

test "CLI: multiple literals with trailing space" {
    try expectOutput("hello world ",
        \\[1:1] Literal("hello")
        \\[1:7] Literal("world")
        \\
        \\
    );
}

test "CLI: output redirection" {
    try expectOutput(">file",
        \\[1:1] Redirection(>) [incomplete]
        \\[1:2] Literal("file") [incomplete]
        \\
        \\
    );
}

test "CLI: output redirection with space" {
    try expectOutput("> file ",
        \\[1:1] Redirection(>) [incomplete]
        \\[1:3] Literal("file")
        \\
        \\
    );
}

test "CLI: input redirection" {
    try expectOutput("<input ",
        \\[1:1] Redirection(<) [incomplete]
        \\[1:2] Literal("input")
        \\
        \\
    );
}

test "CLI: append redirection" {
    try expectOutput(">>logfile ",
        \\[1:1] Redirection(>>) [incomplete]
        \\[1:3] Literal("logfile")
        \\
        \\
    );
}

test "CLI: fd-prefixed redirection" {
    try expectOutput("2>errors ",
        \\[1:1] Redirection(2>) [incomplete]
        \\[1:3] Literal("errors")
        \\
        \\
    );
}

test "CLI: fd duplication" {
    try expectOutput("2>&1 ",
        \\[1:1] Redirection(2>&) [incomplete]
        \\[1:4] Literal("1")
        \\
        \\
    );
}

test "CLI: complex command" {
    try expectOutput("FOO=bar cmd arg1 >out 2>&1\n",
        \\[1:1] Literal("FOO=bar")
        \\[1:9] Literal("cmd")
        \\[1:13] Literal("arg1")
        \\[1:18] Redirection(>) [incomplete]
        \\[1:19] Literal("out")
        \\[1:23] Redirection(2>&) [incomplete]
        \\[1:26] Literal("1")
        \\
        \\
    );
}

test "CLI: multiple commands (multiple lines)" {
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

test "CLI: empty input" {
    try expectOutput("", "");
}

test "CLI: whitespace only" {
    try expectOutput("   \t  ", "");
}

test "CLI: newline only" {
    try expectOutput("\n", "");
}

test "CLI: multiple newlines" {
    try expectOutput("\n\n\n", "");
}

test "CLI: environment variable assignment" {
    try expectOutput("FOO=bar BAZ=qux cmd\n",
        \\[1:1] Literal("FOO=bar")
        \\[1:9] Literal("BAZ=qux")
        \\[1:17] Literal("cmd")
        \\
        \\
    );
}

test "CLI: redirection at newline emits incomplete token" {
    // Lexer emits the redirection; parser would validate target
    try expectOutput(">\n",
        \\[1:1] Redirection(>) [incomplete]
        \\
        \\
    );
}

test "CLI: fd redirection at newline emits incomplete token" {
    // Lexer emits the redirection; parser would validate target
    try expectOutput(">&\n",
        \\[1:1] Redirection(>&) [incomplete]
        \\
        \\
    );
}
