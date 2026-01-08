//! Parser for POSIX shell syntax.
//!
//! Consumes tokens from the lexer and produces an AST for simple commands.
//! Simple commands consist of optional variable assignments, a command with
//! arguments, and optional redirections.
//!
//! The parser uses a labeled switch state machine for consistency with the
//! lexer and to prepare for future compound command support.

const std = @import("std");
const Allocator = std.mem.Allocator;
pub const lexer = @import("lexer.zig");

/// A part of a word. Words can be composed of multiple parts when they
/// contain quotes, escapes, or (in the future) expansions.
///
/// The distinction between literal, quoted, and double_quoted is important
/// for expansion phases:
/// - `literal`: Subject to tilde expansion, globbing, and field splitting
/// - `quoted`: Not subject to any expansion (from escapes or single quotes)
/// - `double_quoted`: Contents may include expansions, but results are not
///   subject to field splitting or globbing
pub const WordPart = union(enum) {
    /// Unquoted literal text - subject to tilde expansion, globbing, field splitting.
    literal: []const u8,

    /// Quoted/escaped literal text - not subject to any expansion.
    /// This includes content from single quotes ('...') and backslash escapes (\x).
    quoted: []const u8,

    /// Double-quoted region - contents may include expansions (variables, command
    /// substitution) but results are not subject to field splitting or globbing.
    double_quoted: []const WordPart,

    /// Parameter expansion - ${param}, ${param:-default}, etc.
    parameter: ParameterExpansion,

    // Future expansion types:
    // command_sub: CommandSubstitution,
    // arithmetic: ArithmeticExpansion,

    /// Format the word part for human-readable output.
    /// Implements the standard format interface for use with std.fmt.
    pub fn format(self: WordPart, writer: *std.io.Writer) std.io.Writer.Error!void {
        switch (self) {
            .literal => |lit| try writer.print("\"{s}\"", .{lit}),
            .quoted => |q| try writer.print("quoted(\"{s}\")", .{q}),
            .double_quoted => |parts| {
                try writer.writeAll("double_quoted([");
                for (parts, 0..) |part, i| {
                    if (i > 0) try writer.writeAll(", ");
                    try part.format(writer);
                }
                try writer.writeAll("])");
            },
            .parameter => |param| try param.format(writer),
        }
    }

    /// Format the word part for shell-like output (used inside double quotes).
    /// Unlike format(), this outputs content as it would appear in shell syntax.
    pub fn formatInner(self: WordPart, writer: *std.io.Writer) std.io.Writer.Error!void {
        switch (self) {
            .literal => |lit| try writer.writeAll(lit),
            .quoted => |q| {
                try writer.writeByte('\'');
                try writer.writeAll(q);
                try writer.writeByte('\'');
            },
            .double_quoted => |parts| {
                try writer.writeByte('"');
                for (parts) |part| {
                    try part.formatInner(writer);
                }
                try writer.writeByte('"');
            },
            .parameter => |param| try param.format(writer),
        }
    }
};

/// A parameter expansion (${param}, ${param:-default}, etc.)
/// Represents POSIX shell parameter expansion from Section 2.6.2.
pub const ParameterExpansion = struct {
    /// The parameter name (VAR, 1, ?, @, *, etc.)
    name: []const u8,
    /// Optional modifier for the expansion
    modifier: ?Modifier = null,

    pub const Modifier = struct {
        /// The modifier operation
        op: lexer.ModifierOp,
        /// True if colon present (checks for null/empty, not just unset)
        /// For example, ${VAR:-default} vs ${VAR-default}
        check_null: bool,
        /// The word after the modifier (null for Length modifier)
        word: ?[]const WordPart,
    };

    /// Format for debugging output.
    /// Reconstructs a shell-like representation of the expansion.
    /// Implements the standard format interface for use with std.fmt.
    pub fn format(self: ParameterExpansion, writer: *std.io.Writer) std.io.Writer.Error!void {
        try writer.writeAll("${");

        // Handle length modifier (prefix operator)
        if (self.modifier) |mod| {
            if (mod.op == .Length) {
                try writer.writeByte('#');
                try writer.writeAll(self.name);
                try writer.writeByte('}');
                return;
            }
        }

        try writer.writeAll(self.name);

        if (self.modifier) |mod| {
            // Write colon if check_null is set (for applicable modifiers)
            switch (mod.op) {
                .UseDefault, .AssignDefault, .ErrorIfUnset, .UseAlternative => {
                    if (mod.check_null) try writer.writeByte(':');
                },
                else => {},
            }

            // Write the operator
            switch (mod.op) {
                .Length => unreachable, // Handled above
                .UseDefault => try writer.writeByte('-'),
                .AssignDefault => try writer.writeByte('='),
                .ErrorIfUnset => try writer.writeByte('?'),
                .UseAlternative => try writer.writeByte('+'),
                .RemoveSmallestPrefix => try writer.writeByte('#'),
                .RemoveLargestPrefix => try writer.writeAll("##"),
                .RemoveSmallestSuffix => try writer.writeByte('%'),
                .RemoveLargestSuffix => try writer.writeAll("%%"),
            }

            // Write the word if present
            if (mod.word) |word_parts| {
                for (word_parts) |part| {
                    try part.formatInner(writer);
                }
            }
        }

        try writer.writeByte('}');
    }
};

/// A complete word, which may consist of multiple parts.
/// For example, `abc'def'ghi` is one word with three literal parts.
pub const Word = struct {
    /// The parts that make up this word.
    parts: []const WordPart,
    /// The absolute position in the input where this word starts.
    position: usize,
    /// The line number where this word starts (1-indexed).
    line: usize,
    /// The column number where this word starts (1-indexed).
    column: usize,

    /// Format the word for human-readable output.
    pub fn format(self: Word, writer: *std.io.Writer) std.io.Writer.Error!void {
        if (self.parts.len == 0) {
            try writer.writeAll("\"\"");
            return;
        }

        if (self.parts.len == 1) {
            try self.parts[0].format(writer);
            return;
        }

        // Multiple parts - show as list
        try writer.writeByte('[');
        for (self.parts, 0..) |part, i| {
            if (i > 0) try writer.writeAll(", ");
            try part.format(writer);
        }
        try writer.writeByte(']');
    }
};

/// A variable assignment (e.g., `FOO=bar`).
/// The name must be a valid identifier: [A-Za-z_][A-Za-z0-9_]*
pub const Assignment = struct {
    /// The variable name (always literal, no expansions).
    name: []const u8,
    /// The value (including expansions).
    value: Word,
    /// The absolute position in the input where this assignment starts.
    position: usize,
    /// The line number where this assignment starts (1-indexed).
    line: usize,
    /// The column number where this assignment starts (1-indexed).
    column: usize,

    /// Format the assignment for human-readable output.
    pub fn format(self: Assignment, writer: *std.io.Writer) std.io.Writer.Error!void {
        try writer.print("{s} = ", .{self.name});
        try self.value.format(writer);
    }
};

/// The target of a redirection operation.
pub const RedirectionTarget = union(enum) {
    /// For file redirections (In, Out, Append): the target filename.
    file: Word,
    /// For fd duplication (Fd): the target file descriptor number.
    fd: u32,
    /// For fd close (Fd with "-" target): close the source fd.
    close,

    /// Format the redirection target for human-readable output.
    pub fn format(self: RedirectionTarget, writer: *std.io.Writer) std.io.Writer.Error!void {
        switch (self) {
            .file => |word| try word.format(writer),
            .fd => |fd| try writer.print("{d}", .{fd}),
            .close => try writer.writeAll("-"),
        }
    }
};

/// A parsed redirection with its target.
pub const ParsedRedirection = struct {
    /// The type of redirection operation.
    op: lexer.Redirection,
    /// The source file descriptor (e.g., "2" in "2>file"), if specified.
    source_fd: ?u32,
    /// The target of the redirection.
    target: RedirectionTarget,
    /// The absolute position in the input where this redirection starts.
    position: usize,
    /// The line number where this redirection starts (1-indexed).
    line: usize,
    /// The column number where this redirection starts (1-indexed).
    column: usize,

    /// Format the redirection for human-readable output.
    pub fn format(self: ParsedRedirection, writer: *std.io.Writer) std.io.Writer.Error!void {
        if (self.source_fd) |fd| {
            try writer.print("{d}", .{fd});
        }
        switch (self.op) {
            .In => try writer.writeByte('<'),
            .Out => try writer.writeByte('>'),
            .Append => try writer.writeAll(">>"),
            .Fd => try writer.writeAll(">&"),
        }
        try writer.writeByte(' ');
        try self.target.format(writer);
    }
};

/// A simple command consisting of assignments, arguments, and redirections.
pub const SimpleCommand = struct {
    /// Variable assignments that precede the command.
    assignments: []const Assignment,
    /// The command name and its arguments.
    argv: []const Word,
    /// Redirections in the order they appeared.
    redirections: []const ParsedRedirection,

    /// Format the command for human-readable output.
    pub fn format(self: SimpleCommand, writer: *std.io.Writer) std.io.Writer.Error!void {
        try self.formatIndented(writer, 0);
    }

    /// Format the command with indentation (for nested commands).
    fn formatIndented(self: SimpleCommand, writer: *std.io.Writer, indent: usize) std.io.Writer.Error!void {
        try writer.splatByteAll(' ', indent);
        try writer.writeAll("SimpleCommand:\n");

        if (self.assignments.len > 0) {
            try writer.splatByteAll(' ', indent + 2);
            try writer.writeAll("assignments:\n");
            for (self.assignments, 0..) |assignment, i| {
                try writer.splatByteAll(' ', indent + 4);
                try writer.print("[{d}] ", .{i});
                try assignment.format(writer);
                try writer.writeByte('\n');
            }
        }

        if (self.argv.len > 0) {
            try writer.splatByteAll(' ', indent + 2);
            try writer.writeAll("argv:\n");
            for (self.argv, 0..) |word, i| {
                try writer.splatByteAll(' ', indent + 4);
                try writer.print("[{d}] ", .{i});
                try word.format(writer);
                try writer.writeByte('\n');
            }
        }

        if (self.redirections.len > 0) {
            try writer.splatByteAll(' ', indent + 2);
            try writer.writeAll("redirections:\n");
            for (self.redirections, 0..) |redir, i| {
                try writer.splatByteAll(' ', indent + 4);
                try writer.print("[{d}] ", .{i});
                try redir.format(writer);
                try writer.writeByte('\n');
            }
        }
    }
};

/// A pipeline of N commands connected by pipes.
/// Each command runs in a subshell (forked process).
///
/// May be negated with the `!` reserved word (Section 2.9.2). Negation only
/// affects exit status, not execution environment - `! cd /tmp` still changes
/// the working directory. The `!` must appear literally (not from expansion)
/// as the first word of the pipeline (Section 2.4).
///
/// POSIX Reference: Section 2.9.2
pub const Pipeline = struct {
    negated: bool,
    commands: []const Command,

    pub fn format(self: Pipeline, writer: *std.io.Writer) std.io.Writer.Error!void {
        if (self.negated) try writer.writeAll("! ");
        for (self.commands, 0..) |cmd, i| {
            if (i > 0) try writer.writeAll(" | ");
            try cmd.format(writer);
        }
    }
};

/// Operator connecting pipelines in an AND/OR list (POSIX 2.9.3)
pub const AndOrOp = enum {
    /// && - execute next pipeline only if previous succeeded (exit status 0)
    And,
    /// || - execute next pipeline only if previous failed (exit status non-zero)
    Or,
};

/// An item in an AND/OR list.
/// Each item contains a pipeline and an optional trailing operator.
/// The trailing operator is null for the last item in the list.
pub const AndOrItem = struct {
    pipeline: Pipeline,
    /// Operator that follows this pipeline (null for the last item)
    trailing_op: ?AndOrOp,

    pub fn format(self: AndOrItem, writer: *std.io.Writer) std.io.Writer.Error!void {
        try self.pipeline.format(writer);
        if (self.trailing_op) |op| {
            switch (op) {
                .And => try writer.writeAll(" && "),
                .Or => try writer.writeAll(" || "),
            }
        }
    }
};

/// An AND/OR list of pipelines (POSIX 2.9.3)
///
/// This is the primary unit returned by Parser.next(). Even a single
/// simple command is represented as an AndOrList with one item.
///
/// Examples:
///   "foo"           -> AndOrList{ items: [(pipeline(foo), null)] }
///   "foo && bar"    -> AndOrList{ items: [(pipeline(foo), And), (pipeline(bar), null)] }
///   "foo || bar"    -> AndOrList{ items: [(pipeline(foo), Or), (pipeline(bar), null)] }
///   "a && b || c"   -> AndOrList{ items: [(a, And), (b, Or), (c, null)] }
pub const AndOrList = struct {
    items: []const AndOrItem,

    pub fn format(self: AndOrList, writer: *std.io.Writer) std.io.Writer.Error!void {
        for (self.items) |item| {
            try item.format(writer);
        }
    }
};

/// Reserved words recognized by the shell.
/// These are only recognized when unquoted and in command position.
///
/// Reference: POSIX.1-2017 Section 2.4 Reserved Words
pub const ReservedWord = enum {
    @"if",
    then,
    elif,
    @"else",
    fi,
};

/// A compound-list: a sequence of AND/OR lists.
///
/// Reference: POSIX.1-2017 Section 2.9.3 Lists
/// "A compound-list is a sequence of lists, separated by <newline>
/// characters"
///
/// The exit status of a compound-list is the exit status of the last
/// AND/OR list executed.
pub const CompoundList = struct {
    commands: []const AndOrList,
};

/// A condition-body pair used in if/elif branches.
pub const ConditionBodyPair = struct {
    condition: CompoundList,
    body: CompoundList,
};

/// An if-elif-else construct.
///
/// Reference: POSIX.1-2017 Section 2.9.4.1 Compound Commands: if
pub const IfClause = struct {
    /// The condition and body for 'if' plus all 'elif' branches (in order).
    /// There is always at least one branch (the initial 'if').
    branches: []const ConditionBodyPair,
    /// Optional 'else' body (null if no else clause).
    else_body: ?CompoundList,

    pub fn format(self: IfClause, writer: *std.io.Writer) std.io.Writer.Error!void {
        for (self.branches, 0..) |branch, i| {
            if (i == 0) {
                try writer.writeAll("if ");
            } else {
                try writer.writeAll("elif ");
            }
            try formatCompoundList(branch.condition, writer);
            try writer.writeAll("; then ");
            try formatCompoundList(branch.body, writer);
        }
        if (self.else_body) |else_body| {
            try writer.writeAll("; else ");
            try formatCompoundList(else_body, writer);
        }
        try writer.writeAll("; fi");
    }

    fn formatCompoundList(cl: CompoundList, writer: *std.io.Writer) std.io.Writer.Error!void {
        for (cl.commands, 0..) |cmd, i| {
            if (i > 0) try writer.writeAll("; ");
            try cmd.format(writer);
        }
    }
};

/// A single command in a pipeline (POSIX 2.9.2)
///
/// Currently supports simple commands and if clauses. Future additions will
/// include other compound commands (brace groups, subshells, while/for/case
/// clauses) and function definitions per POSIX Section 2.9.5.
///
/// TODO: POSIX allows redirections on compound commands (e.g., `if ...; fi > file`).
/// The grammar is: `command : compound_command redirect_list`. Currently, redirections
/// after compound commands are incorrectly parsed as separate empty commands. To fix:
/// 1. Add an optional `redirections` field to Command (or wrap compound commands)
/// 2. After parsing a compound command, check for trailing redirections
/// 3. Update executor to apply redirections around compound command execution
pub const Command = union(enum) {
    simple: SimpleCommand,
    if_clause: IfClause,

    pub fn format(self: Command, writer: *std.io.Writer) std.io.Writer.Error!void {
        switch (self) {
            .simple => |s| try s.format(writer),
            .if_clause => |ic| try ic.format(writer),
        }
    }
};

/// The result of parsing one complete command unit.
///
/// This is what Parser.next() returns. It wraps an AndOrList to allow
/// for future extensions (e.g., source location tracking, async commands).
pub const ParsedCommand = struct {
    and_or: AndOrList,

    pub fn format(self: ParsedCommand, writer: *std.io.Writer) std.io.Writer.Error!void {
        try self.and_or.format(writer);
    }
};

/// Errors that can occur during parsing.
pub const ParseError = error{
    /// Reached end of input when more tokens were expected.
    UnexpectedEndOfInput,
    /// A redirection operator was not followed by a target.
    MissingRedirectionTarget,
    /// For >& or <&, the target must be a digit sequence or '-'.
    InvalidFdRedirectionTarget,
    /// Encountered syntax that is not yet implemented (e.g., subshells, functions).
    UnsupportedSyntax,
    /// Invalid parameter expansion syntax (e.g., empty ${}).
    BadSubstitution,
} || lexer.LexerError || Allocator.Error;

/// Information about a parse error for error reporting.
pub const ErrorInfo = struct {
    /// A human-readable description of the error.
    message: []const u8,
    /// The absolute position in the input where the error occurred.
    position: usize,
    /// The line number where the error occurred (1-indexed).
    line: usize,
    /// The column number where the error occurred (1-indexed).
    column: usize,
};

/// Pending redirection info while collecting target.
const PendingRedir = struct {
    op: lexer.Redirection,
    source_fd: ?u32,
    position: usize,
    line: usize,
    column: usize,
    /// End position of the redirection operator (for error reporting).
    end_line: usize,
    end_column: usize,
};

/// Maximum depth for nested contexts (double quotes, brace expansions).
/// Matches the lexer's max_context_depth.
const max_context_depth = 32;

/// Parser context for nested constructs (double quotes, parameter expansions).
/// The parser maintains a stack of these to handle nesting like "${var:-${other}}".
///
/// POSIX section 2.10.2 defines a grammar for parsing POSIX sh, which includes a
/// number of rules that are specific to the context that you are parsing.
///
/// For example:
///  - Pipelines are N commands, separated by N-1 `|` symbols, and an optional `!` to
///    negate the exit code of the entire pipeline to begin.
///  - AND and OR statements are pipelines joined by `&&` or `||` symbols.
///  - Terms are AND and OR statements, separated by `&` or `;`.
///  - Brace groups are made up of a list of terms.
///  - Compound commands are either brace-groups, subshells, for_clauses,
///    case_clauses, if_clauses, while_clauses or until_clauses.
///  - Commands are either simple-commands, compound commands or function
///    definitions.
///
/// And the whole set repeats itself.
///
/// We use this object to track which of the contexts we are in, and can push/pop
/// this when a relevant symbol appears. This is also useful in nested scenarios,
/// e.g. shell expansion (`"$(some-command)"`).
const ParserContext = union(enum) {
    /// Pipelines, as defined by POSIX section 2.9.2.
    pipeline: struct {
        state: enum {
            /// POSIX Section 2.4: Reserved words are recognized only when none
            /// of the characters are quoted and when the word is used as the
            /// first word of a command. The reserved word `!` is recognized
            /// before parameter expansion (Section 2.6), so `x="!"; $x cmd`
            /// does NOT negate - the expanded `!` is a literal command name,
            /// not a reserved word.
            ///
            /// Section 2.9.2: "If the pipeline begins with the reserved word
            /// !, the exit status shall be the logical NOT of the exit status
            /// of the last command."
            start,
            /// Consumed an incomplete `!` token - need to check if it's negation or part of command name.
            saw_bang,
            /// Collecting commands.
            collecting_commands,
            /// Finished making the pipeline.
            done,
        },
        /// Negation state: null = no `!` seen, false = even count, true = odd count.
        /// Used during parsing to track whether content exists; converted to bool for AST.
        negated: ?bool,
        /// The commands that have been parsed as part of this pipeline.
        commands: std.ArrayListUnmanaged(Command),
        /// Track the command count before parsing after a pipe.
        /// If non-null, we just consumed a pipe and expect the command count to increase.
        command_count_before_pipe: ?usize,
    },
    /// A simple command, as defined by POSIX section 2.9.1.
    simple_command: struct {
        state: enum {
            /// Reserved words are recognized pre-expansion, but only when the
            /// literal token matches and is unquoted.
            /// See POSIX Section 2.4 - Reserved Words.
            start,
            /// Collecting tokens for a word until complete=true.
            collecting_word,
            /// After redirection operator, must collect target word.
            need_redir_target,
            /// Word collection finished, decide what to do with it.
            word_complete,
            /// Finished parsing command.
            done,
        },
        /// Whether we've seen a command. This helps us track whether we may be doing
        /// assignments or not.
        /// Assignments (FOO=bar) are treated as regular arguments if this is `true`.
        seen_command: bool,
        /// Pending redirection (while collecting target).
        pending_redir: ?PendingRedir,
        /// The builder of the words (arguments) for this command.
        word_collector: WordCollector,

        /// The assignments for this command.
        assignments: std.ArrayListUnmanaged(Assignment),
        /// The arguments for this command.
        argv: std.ArrayListUnmanaged(Word),
        /// The redirections for this command.
        redirections: std.ArrayListUnmanaged(ParsedRedirection),

        /// Set up pending redirection info with default source fd (null).
        fn setPendingRedir(self: *@This(), redir: lexer.Redirection, tok: lexer.Token) void {
            self.pending_redir = .{
                .op = redir,
                .source_fd = null,
                .position = tok.position,
                .line = tok.line,
                .column = tok.column,
                .end_line = tok.end_line,
                .end_column = tok.end_column,
            };
        }
    },
    /// Parsing an AND/OR list (POSIX 2.9.3)
    /// Handles: pipeline (('&&' | '||') linebreak pipeline)*
    and_or_list: struct {
        state: enum {
            /// Initial state - need to parse first pipeline.
            start,
            /// Collecting pipelines - check for && or || operators.
            collecting_pipelines,
            /// Finished parsing the AND/OR list.
            done,
        },
        /// Accumulated items (pipeline + trailing operator)
        items: std.ArrayListUnmanaged(AndOrItem),
    },

    /// Parsing an if clause (POSIX 2.9.4.1)
    if_clause: struct {
        state: enum {
            /// Parsing the condition compound-list (after 'if' or 'elif').
            in_condition,
            /// Parsing the body compound-list (after 'then').
            in_body,
            /// Parsing the else body compound-list (after 'else').
            in_else,
        },
        /// Completed if/elif branches.
        branches: std.ArrayListUnmanaged(ConditionBodyPair),
        /// AND/OR lists for the current condition being built.
        current_condition: std.ArrayListUnmanaged(AndOrList),
        /// AND/OR lists for the current body being built.
        current_body: std.ArrayListUnmanaged(AndOrList),
        /// AND/OR lists for the else body being built.
        else_body: std.ArrayListUnmanaged(AndOrList),
        /// Filled by child and_or_list context when it completes.
        completed_and_or: ?AndOrList,
    },

    /// Initialize a pipeline context.
    fn initPipeline() ParserContext {
        return .{ .pipeline = .{
            .state = .start,
            .negated = null,
            .commands = .empty,
            .command_count_before_pipe = null,
        } };
    }

    /// Initialize an and_or_list context.
    fn initAndOrList() ParserContext {
        return .{ .and_or_list = .{
            .state = .start,
            .items = .empty,
        } };
    }

    /// Initialize a simple_command context.
    fn initSimpleCommand(allocator: Allocator) ParserContext {
        return .{ .simple_command = .{
            .state = .start,
            .seen_command = false,
            .pending_redir = null,
            .word_collector = WordCollector.init(allocator),
            .assignments = .empty,
            .argv = .empty,
            .redirections = .empty,
        } };
    }

    /// Initialize an if_clause context.
    fn initIfClause() ParserContext {
        return .{ .if_clause = .{
            .state = .in_condition,
            .branches = .empty,
            .current_condition = .empty,
            .current_body = .empty,
            .else_body = .empty,
            .completed_and_or = null,
        } };
    }

    fn deinit(self: *ParserContext, allocator: Allocator) void {
        switch (self.*) {
            .pipeline => |*pl| {
                pl.commands.deinit(allocator);
            },
            .simple_command => |*sc| {
                sc.word_collector.deinit();
                sc.assignments.deinit(allocator);
                sc.argv.deinit(allocator);
                sc.redirections.deinit(allocator);
            },
            .and_or_list => |*aol| {
                aol.items.deinit(allocator);
            },
            .if_clause => |*ic| {
                ic.branches.deinit(allocator);
                ic.current_condition.deinit(allocator);
                ic.current_body.deinit(allocator);
                ic.else_body.deinit(allocator);
            },
        }
    }
};

const WordCollector = struct {
    allocator: Allocator,
    /// In-progress word parts.
    parts: std.ArrayListUnmanaged(WordPart),
    /// The current quote context we're collecting into, or null if at top level.
    current_quote: ?QuoteContext = null,
    /// Stack of saved parent quote contexts for nested constructs.
    ///
    /// This is currently set to 8, as doing 8 nested quotes is relatively
    /// pathological. It is also worth noting that command expansion won't come
    /// through here, but instead it will be a nested ParserContext.
    quote_stack: [8]QuoteContext,
    quote_depth: u8 = 0,
    // TODO: Consider removing (or shrinking) these position attributes.
    /// The position where the word started.
    start_position: usize,
    /// The line where the word started.
    start_line: usize,
    /// The column where the word started.
    start_column: usize,

    const QuoteContext = union(enum) {
        /// Inside double quotes - collecting parts for a double_quoted WordPart.
        double_quote: struct {
            parts: std.ArrayListUnmanaged(WordPart),
        },
        /// Inside ${...} - collecting the parameter expansion.
        brace_expansion: struct {
            /// Parts being collected for the modifier's word.
            word_parts: std.ArrayListUnmanaged(WordPart),
            /// The parameter name (null until we see it).
            name: ?[]const u8,
            /// The modifier operation (null if no modifier).
            modifier_op: ?lexer.ModifierOp,
            /// True after we've seen a modifier token.
            seen_modifier: bool,
            /// Whether the modifier has a colon (for :-, :=, etc.).
            modifier_check_null: bool,
        },

        /// Initialize a double_quote context.
        fn initDoubleQuote() QuoteContext {
            return .{ .double_quote = .{ .parts = .empty } };
        }

        /// Initialize a brace_expansion context.
        fn initBraceExpansion() QuoteContext {
            return .{ .brace_expansion = .{
                .name = null,
                .modifier_op = null,
                .modifier_check_null = false,
                .word_parts = .empty,
                .seen_modifier = false,
            } };
        }

        fn deinit(self: *QuoteContext, allocator: Allocator) void {
            switch (self.*) {
                .double_quote => |*dq| dq.parts.deinit(allocator),
                .brace_expansion => |*be| be.word_parts.deinit(allocator),
            }
        }
    };

    fn init(allocator: Allocator) WordCollector {
        return WordCollector{
            .allocator = allocator,
            .parts = .empty,
            .quote_stack = undefined,
            .quote_depth = 0,
            .start_position = 0,
            .start_line = 0,
            .start_column = 0,
        };
    }

    /// Push a new quote context, saving the current one (if any) to the stack.
    fn pushContext(self: *WordCollector, ctx: QuoteContext) void {
        if (self.current_quote) |current| {
            std.debug.assert(self.quote_depth < self.quote_stack.len);
            self.quote_stack[self.quote_depth] = current;
            self.quote_depth += 1;
        }
        self.current_quote = ctx;
    }

    /// Pop the parent quote context from the stack into current_quote.
    /// Returns the old current_quote (which the caller should finalize).
    /// After this call, current_quote is the restored parent (or null if at top level).
    fn popContext(self: *WordCollector) ?QuoteContext {
        const old_current = self.current_quote;
        if (self.quote_depth == 0) {
            self.current_quote = null;
        } else {
            self.quote_depth -= 1;
            self.current_quote = self.quote_stack[self.quote_depth];
        }
        return old_current;
    }

    /// Start collecting a new word.
    fn startWord(self: *WordCollector, tok: lexer.Token) void {
        self.parts = .empty;
        self.start_position = tok.position;
        self.start_line = tok.line;
        self.start_column = tok.column;
    }

    /// Finish collecting the current word and return it.
    fn finishWord(self: *WordCollector) ParseError!Word {
        return Word{
            .parts = try self.parts.toOwnedSlice(self.allocator),
            .position = self.start_position,
            .line = self.start_line,
            .column = self.start_column,
        };
    }

    /// Add a token's content to the word parts list.
    /// Handles nested contexts (double quotes, brace expansions) by collecting
    /// parts into the appropriate context and finalizing when the context ends.
    fn addTokenToParts(self: *WordCollector, token: lexer.Token) ParseError!void {
        switch (token.type) {
            .Literal => |lit| {
                const copied = try self.allocator.dupe(u8, lit);
                try self.addPartToCurrentContext(.{ .literal = copied });
            },
            .EscapedLiteral => |esc| {
                const copied = try self.allocator.dupe(u8, esc);
                try self.addPartToCurrentContext(.{ .quoted = copied });
            },
            .Continuation => |cont| {
                try self.continueLastPart(cont);
            },
            .SingleQuoted => |sq| {
                // SingleQuoted tokens appear outside double quotes (inside double quotes,
                // single quote characters are emitted as Literal tokens by the lexer).
                // They're valid in any context: top-level, brace expansion word, etc.
                const copied = try self.allocator.dupe(u8, sq);
                try self.addPartToCurrentContext(.{ .quoted = copied });
            },
            .DoubleQuoteBegin => {
                // Push a double-quote context onto the stack.
                self.pushContext(QuoteContext.initDoubleQuote());
            },
            .DoubleQuoteEnd => {
                // Pop the double-quote context and finalize it.
                var ctx = self.popContext().?;
                std.debug.assert(ctx == .double_quote);
                errdefer ctx.deinit(self.allocator);
                const parts_slice = try ctx.double_quote.parts.toOwnedSlice(self.allocator);
                try self.addPartToCurrentContext(.{ .double_quoted = parts_slice });
            },
            .SimpleExpansion => |name| {
                // Simple expansion: $VAR, $1, $?, etc.
                const copied_name = try self.allocator.dupe(u8, name);
                const expansion = ParameterExpansion{ .name = copied_name };
                try self.addPartToCurrentContext(.{ .parameter = expansion });
            },
            .BraceExpansionBegin => {
                // Push a brace expansion context onto the stack.
                self.pushContext(QuoteContext.initBraceExpansion());
            },
            .Modifier => |mod| {
                // Modifier inside ${...}
                std.debug.assert(self.current_quote != null and self.current_quote.? == .brace_expansion);
                self.current_quote.?.brace_expansion.modifier_op = mod.op;
                self.current_quote.?.brace_expansion.modifier_check_null = mod.check_null;
                self.current_quote.?.brace_expansion.seen_modifier = true;
            },
            .BraceExpansionEnd => {
                // Pop the brace expansion context and build the ParameterExpansion.
                var ctx = self.popContext().?;
                std.debug.assert(ctx == .brace_expansion);
                errdefer ctx.deinit(self.allocator);
                const be = &ctx.brace_expansion;

                // Check for missing parameter name (e.g., ${} or ${:-foo})
                if (be.name == null) {
                    return error.BadSubstitution;
                }

                // Build the ParameterExpansion
                const expansion = ParameterExpansion{
                    .name = be.name.?, // Confirmed not null above
                    .modifier = if (be.modifier_op) |op| blk: {
                        break :blk ParameterExpansion.Modifier{
                            .op = op,
                            .check_null = be.modifier_check_null,
                            .word = if (be.word_parts.items.len > 0)
                                try be.word_parts.toOwnedSlice(self.allocator)
                            else
                                null,
                        };
                    } else null,
                };

                try self.addPartToCurrentContext(.{ .parameter = expansion });
            },
            .Redirection => {
                // Shouldn't happen during word collection
            },
            .LeftParen, .RightParen => {
                // Shouldn't happen during word collection - handled by state machine
            },
            .Newline, .Semicolon, .DoubleSemicolon => {
                // Shouldn't happen during word collection - handled by state machine
            },
            .Pipe, .DoublePipe, .Ampersand, .DoubleAmpersand => {
                // Shouldn't happen during word collection - handled by state machine
            },
        }
    }

    /// Add a WordPart to the current context.
    /// If inside a brace expansion, handles the special case where the first
    /// literal becomes the parameter name.
    fn addPartToCurrentContext(self: *WordCollector, part: WordPart) !void {
        if (self.current_quote) |*ctx| {
            switch (ctx.*) {
                .double_quote => |*dq| {
                    try dq.parts.append(self.allocator, part);
                },
                .brace_expansion => |*be| {
                    // In brace expansion context:
                    // - If we haven't seen a modifier yet and name is null,
                    //   a literal becomes the parameter name
                    // - After a modifier (or for non-literal parts), add to word_parts
                    if (!be.seen_modifier and be.name == null) {
                        switch (part) {
                            .literal => |lit| {
                                be.name = lit;
                                return;
                            },
                            else => {},
                        }
                    }
                    // For Length modifier, the name comes AFTER the modifier token
                    if (be.modifier_op == .Length and be.name == null) {
                        switch (part) {
                            .literal => |lit| {
                                be.name = lit;
                                return;
                            },
                            else => {},
                        }
                    }
                    try be.word_parts.append(self.allocator, part);
                },
            }
        } else {
            // No context - add directly to word parts
            try self.parts.append(self.allocator, part);
        }
    }

    /// Extend the last part in the current context with additional content.
    /// Used for Continuation tokens that continue a previous incomplete token.
    fn continueLastPart(self: *WordCollector, content: []const u8) ParseError!void {
        if (content.len == 0) return;

        const ExtendError = ParseError;
        const allocator = self.allocator;

        // Extend a string with additional content using realloc.
        // Safe to cast because the parser owns all allocated strings.
        const extendString = struct {
            fn f(alloc: Allocator, old: []const u8, suffix: []const u8) ExtendError![]const u8 {
                const new_len = old.len + suffix.len;
                // Safe to cast: we own this buffer (allocated by this parser)
                const old_mut: []u8 = @constCast(old);
                const resized = try alloc.realloc(old_mut, new_len);
                @memcpy(resized[old.len..], suffix);
                return resized;
            }
        }.f;

        // Extend the last WordPart in a list with additional content.
        const extendLastPartInList = struct {
            fn f(alloc: Allocator, parts: *std.ArrayListUnmanaged(WordPart), cont: []const u8) ExtendError!void {
                // The lexer only emits Continuation tokens after an incomplete token,
                // so there must always be a preceding part to continue.
                if (parts.items.len == 0) unreachable;

                const last = &parts.items[parts.items.len - 1];

                switch (last.*) {
                    .literal => |old| {
                        last.* = .{ .literal = try extendString(alloc, old, cont) };
                    },
                    .quoted => |old| {
                        last.* = .{ .quoted = try extendString(alloc, old, cont) };
                    },
                    .parameter => |*param| {
                        param.name = try extendString(alloc, param.name, cont);
                    },
                    // double_quoted parts are only created when a double_quote context
                    // is finalized. While inside double quotes, we're in a double_quote
                    // context, not looking at a double_quoted part. So continuations
                    // cannot target a double_quoted part.
                    .double_quoted => unreachable,
                }
            }
        }.f;

        if (self.current_quote) |*ctx| {
            switch (ctx.*) {
                .double_quote => |*dq| {
                    try extendLastPartInList(allocator, &dq.parts, content);
                },
                .brace_expansion => |*be| {
                    if (be.word_parts.items.len > 0) {
                        // Continuing a word part after the modifier
                        try extendLastPartInList(allocator, &be.word_parts, content);
                    } else if (be.name != null) {
                        // Continuing the parameter name (before any modifier)
                        be.name = try extendString(allocator, be.name.?, content);
                    } else {
                        // The lexer emits BraceExpansionBegin, then a Literal for the
                        // parameter name. A Continuation can only follow an incomplete
                        // token, so either name or word_parts must have content.
                        unreachable;
                    }
                },
            }
        } else {
            // No context - extend in top-level word parts
            try extendLastPartInList(allocator, &self.parts, content);
        }
    }

    /// Clean up any allocated memory in this context.
    fn deinit(self: *WordCollector) void {
        self.parts.deinit(self.allocator);
        if (self.current_quote) |*ctx| {
            ctx.deinit(self.allocator);
        }
        for (self.quote_stack[0..self.quote_depth]) |*context| {
            context.deinit(self.allocator);
        }
    }
};

/// Parser for POSIX shell simple commands.
///
/// The parser consumes tokens from a lexer and produces an AST.
/// All strings are copied to the provided allocator (typically an arena),
/// since lexer token slices are invalidated on the next `nextToken()` call.
pub const Parser = struct {
    /// Allocator for AST nodes and string copies.
    allocator: Allocator,
    /// The lexer to read tokens from.
    lex: *lexer.Lexer,
    /// The token that has been peeked.
    peeked: ?lexer.Token = null,

    /// Error context for the most recent error.
    error_info: ?ErrorInfo,

    // --- State machine fields ---

    /// Context stack for parsing in different contexts.
    /// Index 0 is the bottom of the stack; context_depth - 1 is the top.
    context_stack: [max_context_depth]ParserContext,
    /// Current depth of the context stack (there is always at least one).
    context_depth: usize,

    /// Initialize a new parser.
    pub fn init(allocator: Allocator, lex: *lexer.Lexer) Parser {
        var parser = Parser{
            .allocator = allocator,
            .lex = lex,
            .error_info = null,
            .context_stack = undefined,
            .context_depth = 0,
        };
        _ = parser.pushContext(ParserContext.initPipeline());
        return parser;
    }

    /// Get error information for the most recent parse error.
    pub fn getErrorInfo(self: *const Parser) ?ErrorInfo {
        return self.error_info;
    }

    // --- Lexer operations ---

    /// Peek a token from the lexer.
    fn peekToken(self: *Parser) !?lexer.Token {
        if (self.peeked) |tok| {
            return tok;
        }
        self.peeked = try self.lex.nextToken();
        return self.peeked;
    }

    /// Get the next token from the lexer.
    fn consumeToken(self: *Parser) !?lexer.Token {
        if (self.peeked) |tok| {
            self.peeked = null;
            return tok;
        }
        return try self.lex.nextToken();
    }

    // --- Context stack operations ---

    /// Push a context onto the stack.
    ///
    /// Use this to save the current context before transitioning to a
    /// nested context. The saved context can be restored with `popContext()`.
    fn pushContext(self: *Parser, ctx: ParserContext) void {
        std.debug.assert(self.context_depth < max_context_depth);
        self.context_stack[self.context_depth] = ctx;
        self.context_depth += 1;
    }

    /// Pop the top context from the stack.
    ///
    /// Returns `null` if the stack is empty (we're at root level).
    /// Use this to restore a parent context after finishing a nested one.
    fn popContext(self: *Parser) ?ParserContext {
        if (self.context_depth == 0) return null;
        self.context_depth -= 1;
        return self.context_stack[self.context_depth];
    }

    /// Check if a context of the given type exists in the context stack.
    ///
    /// This is used to determine if we're inside a compound command like
    /// `if_clause`, which affects reserved word recognition.
    fn hasContextInStack(self: *Parser, comptime context_tag: std.meta.Tag(ParserContext)) bool {
        for (self.context_stack[0..self.context_depth]) |ctx| {
            if (ctx == context_tag) return true;
        }
        return false;
    }

    /// Get a user-friendly error message for a lexer error.
    fn lexerErrorMessage(err: lexer.LexerError) []const u8 {
        return switch (err) {
            error.InvalidModifier => "invalid modifier",
            error.UnterminatedQuote => "unterminated quote",
            error.UnterminatedBraceExpansion => "unterminated brace expansion",
            error.NestingTooDeep => "nesting too deep",
            error.UnexpectedEndOfFile => "unexpected end of file",
        };
    }

    /// Parse a simple command from the input.
    ///
    /// Returns the parsed command, or `null` if the input is empty.
    /// Returns an error if the input is malformed.
    pub fn parseCommand(self: *Parser) ParseError!?ParsedCommand {
        state: switch (self.reset()) {
            .and_or_list => |and_or_val| {
                var and_or = and_or_val;
                and_or: switch (and_or.state) {
                    .start => {
                        // Need to parse first pipeline
                        and_or.state = .collecting_pipelines;
                        self.pushContext(.{ .and_or_list = and_or });
                        continue :state ParserContext.initPipeline();
                    },
                    .collecting_pipelines => {
                        // Check if last item has trailing_op set - means we consumed
                        // an operator but nothing was added after it.
                        if (and_or.items.items.len > 0) {
                            const last = and_or.items.items[and_or.items.items.len - 1];
                            if (last.trailing_op != null) {
                                // Consumed operator but no pipeline added after - error
                                const tok = self.peekToken() catch |err| {
                                    self.setError(lexerErrorMessage(err), self.lex.position, self.lex.line, self.lex.column);
                                    return err;
                                } orelse {
                                    self.setError("syntax error: unexpected end of file", self.lex.position, self.lex.line, self.lex.column);
                                    return ParseError.UnexpectedEndOfInput;
                                };
                                self.setError("syntax error near unexpected token", tok.position, tok.line, tok.column);
                                return ParseError.UnsupportedSyntax;
                            }
                        }

                        // A pipeline just completed. Check for && or ||
                        const tok = self.peekToken() catch |err| {
                            self.setError(lexerErrorMessage(err), self.lex.position, self.lex.line, self.lex.column);
                            return err;
                        } orelse {
                            // EOF - finish the and_or list
                            continue :and_or .done;
                        };

                        switch (tok.type) {
                            .DoubleAmpersand, .DoublePipe => {
                                // Validate: pipeline before operator must have commands.
                                // An empty pipeline (even with `!`) cannot precede an operator.
                                if (and_or.items.items.len == 0) {
                                    self.setError("syntax error near unexpected token", tok.position, tok.line, tok.column);
                                    return ParseError.UnsupportedSyntax;
                                }
                                const last_pipeline = and_or.items.items[and_or.items.items.len - 1].pipeline;
                                if (last_pipeline.commands.len == 0) {
                                    self.setError("syntax error near unexpected token", tok.position, tok.line, tok.column);
                                    return ParseError.UnsupportedSyntax;
                                }

                                _ = try self.consumeToken();
                                // Set trailing_op on the last item
                                and_or.items.items[and_or.items.items.len - 1].trailing_op = if (tok.type == .DoubleAmpersand) .And else .Or;
                                // Skip newlines after operator (line continuation per POSIX 2.10.2)
                                while (true) {
                                    const nl_tok = self.peekToken() catch |err| {
                                        self.setError(lexerErrorMessage(err), self.lex.position, self.lex.line, self.lex.column);
                                        return err;
                                    } orelse break;
                                    if (nl_tok.type != .Newline) break;
                                    _ = try self.consumeToken();
                                }
                                self.pushContext(.{ .and_or_list = and_or });
                                continue :state ParserContext.initPipeline();
                            },
                            .Semicolon, .Newline, .Ampersand => {
                                // End of and_or list
                                continue :and_or .done;
                            },
                            else => {
                                // Unexpected token - finish the list
                                continue :and_or .done;
                            },
                        }
                    },
                    .done => {
                        // Finished parsing the AND/OR list.
                        // Check if we have a parent context (if_clause) or are at root level.
                        const parent = self.popContext();

                        if (and_or.items.items.len == 0) {
                            and_or.items.deinit(self.allocator);

                            if (parent) |p| {
                                switch (p) {
                                    .if_clause => |*ic_val| {
                                        // Empty and_or - continue if_clause without adding anything
                                        var ic = ic_val.*;
                                        ic.completed_and_or = null;
                                        continue :state .{ .if_clause = ic };
                                    },
                                    .pipeline, .simple_command, .and_or_list => unreachable,
                                }
                            }
                            return null;
                        }

                        const result = AndOrList{
                            .items = try and_or.items.toOwnedSlice(self.allocator),
                        };

                        if (parent) |p| {
                            switch (p) {
                                .if_clause => |*ic_val| {
                                    var ic = ic_val.*;
                                    ic.completed_and_or = result;
                                    continue :state .{ .if_clause = ic };
                                },
                                .pipeline, .simple_command, .and_or_list => unreachable,
                            }
                        }

                        return ParsedCommand{ .and_or = result };
                    },
                }
            },
            .pipeline => |pipeline_val| {
                var pipeline = pipeline_val;
                pipeline: switch (pipeline.state) {
                    .start => {
                        const tok = self.peekToken() catch |err| {
                            self.setError(
                                lexerErrorMessage(err),
                                self.lex.position,
                                self.lex.line,
                                self.lex.column,
                            );
                            return err;
                        } orelse {
                            pipeline.state = .done;
                            continue :pipeline .done;
                        };

                        switch (tok.type) {
                            .Literal => |lit| {
                                if (std.mem.eql(u8, lit, "!")) {
                                    _ = try self.consumeToken();
                                    if (tok.complete) {
                                        // `!` as standalone first word - pipeline negation
                                        pipeline.negated = !(pipeline.negated orelse false);
                                        continue :pipeline .start;
                                    } else {
                                        // Incomplete `!` - need to peek next token to decide
                                        continue :pipeline .saw_bang;
                                    }
                                }
                                // Not a `!`, fall through to collect as a command
                                pipeline.state = .collecting_commands;
                                self.pushContext(.{ .pipeline = pipeline });
                                continue :state ParserContext.initSimpleCommand(self.allocator);
                            },
                            else => {
                                pipeline.state = .collecting_commands;
                                self.pushContext(.{ .pipeline = pipeline });
                                continue :state ParserContext.initSimpleCommand(self.allocator);
                            },
                        }
                    },
                    .saw_bang => {
                        // We consumed an incomplete `!` and need to determine if it was
                        // negation or part of a command name.
                        const tok = self.peekToken() catch |err| {
                            self.setError(
                                lexerErrorMessage(err),
                                self.lex.position,
                                self.lex.line,
                                self.lex.column,
                            );
                            return err;
                        } orelse {
                            // EOF - `!` was negation of empty pipeline
                            pipeline.negated = !(pipeline.negated orelse false);
                            pipeline.state = .done;
                            continue :pipeline .done;
                        };

                        switch (tok.type) {
                            .Continuation => |cont| {
                                _ = try self.consumeToken();
                                if (cont.len == 0) {
                                    // Empty continuation - word boundary confirmed
                                    // `!` was negation
                                    pipeline.negated = !(pipeline.negated orelse false);
                                    continue :pipeline .start;
                                } else {
                                    // Non-empty continuation - `!` is part of longer word like `!foo`
                                    // Pre-seed simple_command with "!" and continue collecting
                                    pipeline.state = .collecting_commands;
                                    self.pushContext(.{ .pipeline = pipeline });
                                    var sc = ParserContext.initSimpleCommand(self.allocator);
                                    // Set position to 1 before continuation (where `!` was)
                                    sc.simple_command.word_collector.start_position = tok.position -| 1;
                                    sc.simple_command.word_collector.start_line = tok.line;
                                    sc.simple_command.word_collector.start_column = tok.column -| 1;
                                    // Add "!" as first part
                                    const bang = try self.allocator.dupe(u8, "!");
                                    try sc.simple_command.word_collector.parts.append(self.allocator, .{ .literal = bang });
                                    // Add the continuation content
                                    try sc.simple_command.word_collector.continueLastPart(cont);
                                    // Transition to collecting_word state
                                    sc.simple_command.state = .collecting_word;
                                    continue :state sc;
                                }
                            },
                            else => {
                                // Any other token (quote, expansion, etc.) - word continues
                                // `!` is part of command name, not negation
                                pipeline.state = .collecting_commands;
                                self.pushContext(.{ .pipeline = pipeline });
                                var sc = ParserContext.initSimpleCommand(self.allocator);
                                // Set position to 1 before this token (where `!` was)
                                sc.simple_command.word_collector.start_position = tok.position -| 1;
                                sc.simple_command.word_collector.start_line = tok.line;
                                sc.simple_command.word_collector.start_column = tok.column -| 1;
                                // Add "!" as first part
                                const bang = try self.allocator.dupe(u8, "!");
                                try sc.simple_command.word_collector.parts.append(self.allocator, .{ .literal = bang });
                                // Transition to collecting_word state (don't consume token - let simple_command handle it)
                                sc.simple_command.state = .collecting_word;
                                continue :state sc;
                            },
                        }
                    },
                    .collecting_commands => {
                        // We only get here after `simple_command` has finished.

                        // Check if we expected a command after pipe but didn't get one
                        if (pipeline.command_count_before_pipe) |count_before| {
                            if (pipeline.commands.items.len == count_before) {
                                // No command was added - this is an error
                                const tok = self.peekToken() catch |err| {
                                    self.setError(
                                        lexerErrorMessage(err),
                                        self.lex.position,
                                        self.lex.line,
                                        self.lex.column,
                                    );
                                    return err;
                                } orelse {
                                    self.setError(
                                        "syntax error: unexpected end of file",
                                        self.lex.position,
                                        self.lex.line,
                                        self.lex.column,
                                    );
                                    return ParseError.UnexpectedEndOfInput;
                                };
                                self.setError(
                                    "syntax error near unexpected token",
                                    tok.position,
                                    tok.line,
                                    tok.column,
                                );
                                return ParseError.UnsupportedSyntax;
                            }
                            pipeline.command_count_before_pipe = null;
                        }

                        const tok = self.peekToken() catch |err| {
                            self.setError(
                                lexerErrorMessage(err),
                                self.lex.position,
                                self.lex.line,
                                self.lex.column,
                            );
                            return err;
                        } orelse {
                            pipeline.state = .done;
                            continue :pipeline .done;
                        };

                        switch (tok.type) {
                            .Pipe => {
                                // Check for pipe at start (no commands yet)
                                if (pipeline.commands.items.len == 0) {
                                    self.setError(
                                        "syntax error near unexpected token `|'",
                                        tok.position,
                                        tok.line,
                                        tok.column,
                                    );
                                    return ParseError.UnsupportedSyntax;
                                }

                                // We got a pipeline token. This means that we
                                // continue to build the pipeline by looking at
                                // the next command.
                                _ = try self.consumeToken();

                                // Skip newlines after pipe (POSIX line continuation).
                                // This allows commands like "echo |\ncat" to work.
                                while (true) {
                                    const next_tok = self.peekToken() catch |err| {
                                        self.setError(
                                            lexerErrorMessage(err),
                                            self.lex.position,
                                            self.lex.line,
                                            self.lex.column,
                                        );
                                        return err;
                                    } orelse break;
                                    if (next_tok.type != .Newline) break;
                                    _ = try self.consumeToken();
                                }

                                pipeline.command_count_before_pipe = pipeline.commands.items.len;
                                self.pushContext(.{ .pipeline = pipeline });
                                continue :state ParserContext.initSimpleCommand(self.allocator);
                            },
                            else => {
                                // We got a different token. We should finish
                                // pipeline.
                                pipeline.state = .done;
                                continue :pipeline .done;
                            },
                        }
                    },
                    .done => {
                        // We've finished making a pipeline.
                        // Only add to and_or_list if there's content:
                        // - commands.len > 0: has actual commands
                        // - negated != null: saw at least one `!` token
                        const has_content = pipeline.commands.items.len > 0 or pipeline.negated != null;

                        // Pop back to the and_or_list context
                        var next_context = self.popContext() orelse {
                            // Stack empty at root - this shouldn't happen with and_or_list
                            unreachable;
                        };

                        switch (next_context) {
                            .and_or_list => |*and_or_ctx| {
                                if (has_content) {
                                    const new_pipeline = Pipeline{
                                        .negated = pipeline.negated orelse false,
                                        .commands = try pipeline.commands.toOwnedSlice(self.allocator),
                                    };
                                    try and_or_ctx.items.append(self.allocator, .{
                                        .pipeline = new_pipeline,
                                        .trailing_op = null,
                                    });
                                } else {
                                    // No content - just free the commands list
                                    pipeline.commands.deinit(self.allocator);
                                }
                                // Continue processing and_or_list
                                continue :state next_context;
                            },
                            .simple_command, .pipeline, .if_clause => {
                                // Pipeline should only pop to and_or_list.
                                unreachable;
                            },
                        }
                    },
                }
            },
            .simple_command => |simple_command_val| {
                var simple_command = simple_command_val;
                simple_command: switch (simple_command.state) {
                    .start => {
                        const tok = self.peekToken() catch |err| {
                            self.setError(
                                lexerErrorMessage(err),
                                self.lex.position,
                                self.lex.line,
                                self.lex.column,
                            );
                            return err;
                        } orelse {
                            continue :simple_command .done;
                        };

                        switch (tok.type) {
                            // Tokens that can start or continue a word
                            .Literal, .EscapedLiteral, .SingleQuoted, .DoubleQuoteBegin, .SimpleExpansion, .BraceExpansionBegin, .Continuation => {
                                // Start the first word of the simple_command.
                                _ = try self.consumeToken();
                                simple_command.word_collector.startWord(tok);
                                simple_command.word_collector.addTokenToParts(tok) catch |err| {
                                    switch (err) {
                                        error.BadSubstitution => {
                                            self.setError("bad substitution", self.lex.position, self.lex.line, self.lex.column);
                                        },
                                        else => {},
                                    }
                                    return err;
                                };
                                if (tok.complete) {
                                    continue :simple_command .word_complete;
                                } else {
                                    continue :simple_command .collecting_word;
                                }
                            },
                            .Redirection => |redir| {
                                simple_command.setPendingRedir(redir, tok);
                                _ = try self.consumeToken();
                                continue :simple_command .need_redir_target;
                            },
                            // Tokens that explicitly terminate (and consume)
                            .Newline, .Semicolon, .DoubleSemicolon => {
                                // End of simple command - consume separator and yield.
                                // TODO: Do NOT consume the separator here when we
                                // have other states (e.g., command lists with `;`).
                                _ = try self.consumeToken();
                                continue :simple_command .done;
                            },
                            // Tokens not yet implemented - explicit errors
                            .LeftParen => {
                                // TODO: Implement subshells (POSIX 2.6.3, 2.9.4).
                                self.setError(
                                    "subshells are not yet implemented",
                                    tok.position,
                                    tok.line,
                                    tok.column,
                                );
                                return ParseError.UnsupportedSyntax;
                            },
                            .RightParen => {
                                self.setError(
                                    "syntax error near unexpected token `)'",
                                    tok.position,
                                    tok.line,
                                    tok.column,
                                );
                                return ParseError.UnsupportedSyntax;
                            },
                            // Unknown/unhandled tokens - yield to parent without consuming
                            else => {
                                continue :simple_command .done;
                            },
                        }
                    },

                    .collecting_word => {
                        const tok = self.peekToken() catch |err| {
                            self.setError(lexerErrorMessage(err), self.lex.position, self.lex.line, self.lex.column);
                            return err;
                        } orelse {
                            // End of input mid-word, finish what we have
                            continue :simple_command .word_complete;
                        };

                        switch (tok.type) {
                            .Redirection => |redir| {
                                // Encountered redirection while collecting word.
                                // Try to interpret word_parts as a source fd number.
                                // If successful, use it as the source fd for this
                                // redirection.
                                // If not (overflow, non-digits), treat word as a
                                // regular argument.
                                if (wordPartsToFdNumber(simple_command.word_collector.parts.items)) |source_fd| {
                                    // Valid source fd - use it for the redirection
                                    simple_command.setPendingRedir(redir, tok);
                                    _ = try self.consumeToken();
                                    simple_command.word_collector.parts = .empty;
                                    simple_command.pending_redir.?.source_fd = source_fd;
                                    continue :simple_command .need_redir_target;
                                } else {
                                    // The word isn't valid for use as an fd.
                                    // Finalize the previous word and we'll look at
                                    // the redirection again later.
                                    continue :simple_command .word_complete;
                                }
                            },
                            .LeftParen => {
                                self.setError("syntax error near unexpected token `('", tok.position, tok.line, tok.column);
                                return ParseError.UnsupportedSyntax;
                            },
                            .RightParen => {
                                self.setError("syntax error near unexpected token `)'", tok.position, tok.line, tok.column);
                                return ParseError.UnsupportedSyntax;
                            },
                            .Newline, .Semicolon, .DoubleSemicolon, .Pipe, .DoublePipe, .Ampersand, .DoubleAmpersand => {
                                // Unreachable: The lexer marks words complete when followed by separators
                                // or operators. Even on a buffer boundary, the lexer emits a complete empty
                                // Continuation token before the separator/operator, which transitions us to
                                // .word_complete first. This invariant is verified by the buffer boundary
                                // tests in this file.
                                unreachable;
                            },
                            else => {
                                _ = try self.consumeToken();
                                simple_command.word_collector.addTokenToParts(tok) catch |err| {
                                    switch (err) {
                                        error.BadSubstitution => {
                                            self.setError("bad substitution", self.lex.position, self.lex.line, self.lex.column);
                                        },
                                        else => {},
                                    }
                                    return err;
                                };
                                if (tok.complete) {
                                    continue :simple_command .word_complete;
                                } else {
                                    continue :simple_command .collecting_word;
                                }
                            },
                        }
                    },

                    .need_redir_target => {
                        const tok = self.peekToken() catch |err| {
                            self.setError(
                                lexerErrorMessage(err),
                                self.lex.position,
                                self.lex.line,
                                self.lex.column,
                            );
                            return err;
                        } orelse {
                            // EOF - error points to end of redirection operator
                            const redir = simple_command.pending_redir.?;
                            self.setError(
                                "missing redirection target",
                                redir.position,
                                redir.end_line,
                                redir.end_column,
                            );
                            return ParseError.MissingRedirectionTarget;
                        };

                        switch (tok.type) {
                            .Newline, .Semicolon, .DoubleSemicolon => {
                                // Separator where redirection target was expected
                                const redir = simple_command.pending_redir.?;
                                self.setError(
                                    "missing redirection target",
                                    redir.position,
                                    redir.end_line,
                                    redir.end_column,
                                );
                                return ParseError.MissingRedirectionTarget;
                            },
                            .Redirection => {
                                // Another redirection where target was expected -
                                // error points to end of first redirection
                                const redir = simple_command.pending_redir.?;
                                self.setError(
                                    "missing redirection target",
                                    redir.position,
                                    redir.end_line,
                                    redir.end_column,
                                );
                                return ParseError.MissingRedirectionTarget;
                            },
                            .LeftParen => {
                                // TODO: Subshell redirection (not specified by
                                // POSIX, but useful).
                                self.setError("syntax error near unexpected token `('", tok.position, tok.line, tok.column);
                                return ParseError.UnsupportedSyntax;
                            },
                            .RightParen => {
                                self.setError("syntax error near unexpected token `)'", tok.position, tok.line, tok.column);
                                return ParseError.UnsupportedSyntax;
                            },
                            else => {
                                _ = try self.consumeToken();
                                simple_command.word_collector.startWord(tok);
                                simple_command.word_collector.addTokenToParts(tok) catch |err| {
                                    switch (err) {
                                        error.BadSubstitution => {
                                            self.setError("bad substitution", self.lex.position, self.lex.line, self.lex.column);
                                        },
                                        else => {},
                                    }
                                    return err;
                                };
                                if (tok.complete) {
                                    continue :simple_command .word_complete;
                                } else {
                                    continue :simple_command .collecting_word;
                                }
                            },
                        }
                    },

                    .word_complete => {
                        const word = try simple_command.word_collector.finishWord();

                        // If we have a pending redirection, this word is its target
                        if (simple_command.pending_redir) |redir| {
                            const target: RedirectionTarget = if (redir.op == .Fd)
                                try self.parseFdTarget(word)
                            else
                                .{ .file = word };

                            try simple_command.redirections.append(self.allocator, .{
                                .op = redir.op,
                                .source_fd = redir.source_fd,
                                .target = target,
                                .position = redir.position,
                                .line = redir.line,
                                .column = redir.column,
                            });
                            simple_command.pending_redir = null;
                            continue :simple_command .start;
                        }

                        // Reserved word check - only for first word of command with
                        // no preceding assignments or redirections.
                        // Reference: POSIX.1-2017 Section 2.4 Reserved Words
                        // "when the word is used as: The first word of a command"
                        if (simple_command.argv.items.len == 0 and
                            simple_command.assignments.items.len == 0 and
                            simple_command.redirections.items.len == 0)
                        {
                            if (isUnquotedReservedWord(word)) |reserved| {
                                switch (reserved) {
                                    .@"if" => {
                                        // Swap simple_command for if_clause context.
                                        // The pipeline parent remains on the stack.
                                        // Clean up simple_command resources before swapping.
                                        var ctx = ParserContext{ .simple_command = simple_command };
                                        ctx.deinit(self.allocator);
                                        continue :state ParserContext.initIfClause();
                                    },
                                    .then, .elif, .@"else", .fi => {
                                        // These reserved words only terminate an if_clause.
                                        // At root level (not inside if_clause), they're
                                        // treated as regular command names.
                                        if (self.hasContextInStack(.if_clause)) {
                                            // Push the reserved word back as a Literal token
                                            // for parent context (if_clause) to handle.
                                            // Uses static memory from @tagName - safe because
                                            // we only compare strings, don't index into source.
                                            self.peeked = .{
                                                .type = .{ .Literal = @tagName(reserved) },
                                                .complete = true,
                                                .position = simple_command.word_collector.start_position,
                                                .end_position = simple_command.word_collector.start_position + @tagName(reserved).len,
                                                .line = simple_command.word_collector.start_line,
                                                .column = simple_command.word_collector.start_column,
                                                .end_line = simple_command.word_collector.start_line,
                                                .end_column = simple_command.word_collector.start_column + @tagName(reserved).len,
                                            };
                                            continue :simple_command .done;
                                        }
                                        // Fall through to treat as regular command name
                                    },
                                }
                            }
                        }

                        // Check if it's an assignment (only valid before command name)
                        if (!simple_command.seen_command) {
                            if (try self.tryBuildAssignment(word)) |assignment| {
                                try simple_command.assignments.append(self.allocator, assignment);
                                continue :simple_command .start;
                            }
                        }

                        // It's a command/argument
                        try simple_command.argv.append(self.allocator, word);
                        simple_command.seen_command = true;
                        continue :simple_command .start;
                    },

                    .done => {
                        // Build the SimpleCommand if we have any content.
                        var new_command: ?SimpleCommand = null;
                        if (simple_command.assignments.items.len != 0 or
                            simple_command.argv.items.len != 0 or
                            simple_command.redirections.items.len != 0)
                        {
                            new_command = SimpleCommand{
                                .assignments = try simple_command.assignments.toOwnedSlice(self.allocator),
                                .argv = try simple_command.argv.toOwnedSlice(self.allocator),
                                .redirections = try simple_command.redirections.toOwnedSlice(self.allocator),
                            };
                        }

                        // Pop parent context from stack and add our result to it.
                        var next_context = self.popContext() orelse {
                            // Stack empty - we're at root level, which shouldn't
                            // happen since simple_command is always nested in pipeline.
                            unreachable;
                        };

                        switch (next_context) {
                            .simple_command, .and_or_list, .if_clause => {
                                // simple_command should only pop to pipeline.
                                unreachable;
                            },
                            .pipeline => |*pipeline| {
                                if (new_command) |cmd| {
                                    try pipeline.commands.append(self.allocator, .{ .simple = cmd });
                                }
                            },
                        }
                        continue :state next_context;
                    },
                }
            },
            .if_clause => |if_clause_ctx| {
                var ic = if_clause_ctx;

                // Handle completed and_or from child context.
                if (ic.completed_and_or) |result| {
                    ic.completed_and_or = null;
                    switch (ic.state) {
                        .in_condition => try ic.current_condition.append(self.allocator, result),
                        .in_body => try ic.current_body.append(self.allocator, result),
                        .in_else => try ic.else_body.append(self.allocator, result),
                    }
                }

                // Check for reserved word terminator that was pushed back by simple_command
                const tok = self.peekToken() catch |err| {
                    self.setError(lexerErrorMessage(err), self.lex.position, self.lex.line, self.lex.column);
                    return err;
                } orelse {
                    // EOF inside if - error
                    self.setError("syntax error: unexpected end of input (expected 'fi')", self.lex.position, self.lex.line, self.lex.column);
                    return ParseError.UnexpectedEndOfInput;
                };

                // Check if it's a reserved word. Only consider complete tokens -
                // when simple_command detects a reserved word like "fi", it pushes
                // back a synthetic Literal token with complete=true. However, if
                // the token came directly from the lexer (e.g., incomplete "fi" at
                // EOF), it may have complete=false, meaning more content could follow
                // (like "file"). We must wait for the complete word before matching.
                const maybe_reserved: ?ReservedWord = switch (tok.type) {
                    .Literal => |lit| if (tok.complete) std.meta.stringToEnum(ReservedWord, lit) else null,
                    else => null,
                };

                if (maybe_reserved) |reserved| {
                    switch (ic.state) {
                        .in_condition => {
                            if (reserved == .then) {
                                _ = try self.consumeToken();
                                if (ic.current_condition.items.len == 0) {
                                    self.setError("syntax error: expected command before 'then'", tok.position, tok.line, tok.column);
                                    return ParseError.UnsupportedSyntax;
                                }
                                ic.state = .in_body;
                                self.pushContext(.{ .if_clause = ic });
                                continue :state ParserContext.initAndOrList();
                            } else {
                                self.setError("syntax error: expected 'then'", tok.position, tok.line, tok.column);
                                return ParseError.UnsupportedSyntax;
                            }
                        },
                        .in_body => {
                            switch (reserved) {
                                .elif => {
                                    _ = try self.consumeToken();
                                    if (ic.current_body.items.len == 0) {
                                        self.setError("syntax error: expected command before 'elif'", tok.position, tok.line, tok.column);
                                        return ParseError.UnsupportedSyntax;
                                    }
                                    // Save current branch, start new condition
                                    try ic.branches.append(self.allocator, .{
                                        .condition = .{ .commands = try ic.current_condition.toOwnedSlice(self.allocator) },
                                        .body = .{ .commands = try ic.current_body.toOwnedSlice(self.allocator) },
                                    });
                                    ic.current_condition = .empty;
                                    ic.current_body = .empty;
                                    ic.state = .in_condition;
                                    self.pushContext(.{ .if_clause = ic });
                                    continue :state ParserContext.initAndOrList();
                                },
                                .@"else" => {
                                    _ = try self.consumeToken();
                                    if (ic.current_body.items.len == 0) {
                                        self.setError("syntax error: expected command before 'else'", tok.position, tok.line, tok.column);
                                        return ParseError.UnsupportedSyntax;
                                    }
                                    // Save current branch, start else body
                                    try ic.branches.append(self.allocator, .{
                                        .condition = .{ .commands = try ic.current_condition.toOwnedSlice(self.allocator) },
                                        .body = .{ .commands = try ic.current_body.toOwnedSlice(self.allocator) },
                                    });
                                    ic.current_condition = .empty;
                                    ic.current_body = .empty;
                                    ic.state = .in_else;
                                    self.pushContext(.{ .if_clause = ic });
                                    continue :state ParserContext.initAndOrList();
                                },
                                .fi => {
                                    _ = try self.consumeToken();
                                    if (ic.current_body.items.len == 0) {
                                        self.setError("syntax error: expected command before 'fi'", tok.position, tok.line, tok.column);
                                        return ParseError.UnsupportedSyntax;
                                    }
                                    // Save final branch, complete if_clause
                                    try ic.branches.append(self.allocator, .{
                                        .condition = .{ .commands = try ic.current_condition.toOwnedSlice(self.allocator) },
                                        .body = .{ .commands = try ic.current_body.toOwnedSlice(self.allocator) },
                                    });
                                    const result = IfClause{
                                        .branches = try ic.branches.toOwnedSlice(self.allocator),
                                        .else_body = null,
                                    };
                                    // Pop to pipeline, add command
                                    var parent = self.popContext() orelse unreachable;
                                    switch (parent) {
                                        .pipeline => |*pl| {
                                            try pl.commands.append(self.allocator, .{ .if_clause = result });
                                            continue :state parent;
                                        },
                                        .simple_command, .and_or_list, .if_clause => unreachable,
                                    }
                                },
                                .@"if" => {
                                    // Nested if - let and_or_list handle it
                                    self.pushContext(.{ .if_clause = ic });
                                    continue :state ParserContext.initAndOrList();
                                },
                                .then => {
                                    self.setError("syntax error: unexpected 'then'", tok.position, tok.line, tok.column);
                                    return ParseError.UnsupportedSyntax;
                                },
                            }
                        },
                        .in_else => {
                            if (reserved == .fi) {
                                _ = try self.consumeToken();
                                if (ic.else_body.items.len == 0) {
                                    self.setError("syntax error: expected command before 'fi'", tok.position, tok.line, tok.column);
                                    return ParseError.UnsupportedSyntax;
                                }
                                const result = IfClause{
                                    .branches = try ic.branches.toOwnedSlice(self.allocator),
                                    .else_body = .{ .commands = try ic.else_body.toOwnedSlice(self.allocator) },
                                };
                                var parent = self.popContext() orelse unreachable;
                                switch (parent) {
                                    .pipeline => |*pl| {
                                        try pl.commands.append(self.allocator, .{ .if_clause = result });
                                        continue :state parent;
                                    },
                                    .simple_command, .and_or_list, .if_clause => unreachable,
                                }
                            } else if (reserved == .@"if") {
                                // Nested if in else - let and_or_list handle it
                                self.pushContext(.{ .if_clause = ic });
                                continue :state ParserContext.initAndOrList();
                            } else {
                                self.setError("syntax error: unexpected reserved word after 'else'", tok.position, tok.line, tok.column);
                                return ParseError.UnsupportedSyntax;
                            }
                        },
                    }
                }

                // Not a reserved word - push and_or_list to parse more commands
                self.pushContext(.{ .if_clause = ic });
                continue :state ParserContext.initAndOrList();
            },
        }
    }

    /// Pull the next command from the input.
    ///
    /// This is the primary iterator interface for pull-based execution.
    /// Returns the next parsed command, or `null` when input is exhausted.
    /// Empty commands (e.g., `;;;` or blank lines) are silently skipped.
    ///
    /// Example usage:
    /// ```
    /// while (try parser.next()) |cmd| {
    ///     try executor.execute(cmd);
    /// }
    /// ```
    pub fn next(self: *Parser) ParseError!?ParsedCommand {
        // TODO: Change this when we support non-simple commands.
        while (true) {
            const command = try self.parseCommand();
            if (command) |cmd| {
                return cmd;
            }
            // Check if there are more tokens.
            const peeked = try self.peekToken();
            if (peeked == null) {
                return null;
            }
            // Another command is coming.
        }
    }

    // --- Helper methods ---

    /// Reset parser state for a new command.
    ///
    /// Returns the initial and_or_list context to start parsing with.
    /// The stack is cleared; contexts are only pushed when nesting.
    fn reset(self: *Parser) ParserContext {
        self.error_info = null;
        // Clean up any leftover contexts (shouldn't happen in normal operation)
        while (self.popContext()) |*ctx| {
            var mutable_ctx = ctx.*;
            mutable_ctx.deinit(self.allocator);
        }
        return ParserContext.initAndOrList();
    }

    /// Try to build an assignment from a word.
    /// Returns the assignment if valid, or null if it's not an assignment.
    ///
    /// An assignment must have:
    /// 1. An unquoted `=` not at position 0
    /// 2. A valid identifier before the `=`: [A-Za-z_][A-Za-z0-9_]*
    fn tryBuildAssignment(self: *Parser, word: Word) ParseError!?Assignment {
        // For now, we only support simple assignments where the first part
        // is a literal containing `=`
        if (word.parts.len == 0) return null;

        switch (word.parts[0]) {
            .literal => |lit| {
                // Find `=` in the literal
                const eq_pos = std.mem.indexOf(u8, lit, "=") orelse return null;
                if (eq_pos == 0) return null; // `=foo` is not an assignment

                const name = lit[0..eq_pos];

                // Validate the name is a valid identifier
                if (!isValidIdentifier(name)) return null;

                // Extract the value
                const value_start = lit[eq_pos + 1 ..];

                // Build the value Word
                var value_parts: std.ArrayListUnmanaged(WordPart) = .empty;

                // Add the part after `=` from the first literal (if non-empty)
                if (value_start.len > 0) {
                    const copied = try self.allocator.dupe(u8, value_start);
                    try value_parts.append(self.allocator, .{ .literal = copied });
                }

                // Add remaining parts from the original word
                for (word.parts[1..]) |part| {
                    try value_parts.append(self.allocator, try self.copyWordPart(part));
                }

                const value = Word{
                    .parts = try value_parts.toOwnedSlice(self.allocator),
                    .position = word.position + eq_pos + 1,
                    .line = word.line,
                    .column = word.column + eq_pos + 1,
                };

                const name_copied = try self.allocator.dupe(u8, name);

                return Assignment{
                    .name = name_copied,
                    .value = value,
                    .position = word.position,
                    .line = word.line,
                    .column = word.column,
                };
            },
            // If the first part is quoted, double_quoted, or parameter, it's not an assignment
            // (the `=` would need to be in an unquoted literal)
            .quoted, .double_quoted, .parameter => return null,
        }
    }

    /// Deep copy a WordPart, including nested parts for double_quoted and parameter.
    fn copyWordPart(self: *Parser, part: WordPart) ParseError!WordPart {
        return switch (part) {
            .literal => |lit| WordPart{ .literal = try self.allocator.dupe(u8, lit) },
            .quoted => |q| WordPart{ .quoted = try self.allocator.dupe(u8, q) },
            .double_quoted => |parts| blk: {
                var copied_parts = try self.allocator.alloc(WordPart, parts.len);
                for (parts, 0..) |p, i| {
                    copied_parts[i] = try self.copyWordPart(p);
                }
                break :blk WordPart{ .double_quoted = copied_parts };
            },
            .parameter => |param| blk: {
                const copied_name = try self.allocator.dupe(u8, param.name);
                const copied_modifier: ?ParameterExpansion.Modifier = if (param.modifier) |mod| m: {
                    const copied_word: ?[]const WordPart = if (mod.word) |word_parts| w: {
                        var copied_parts = try self.allocator.alloc(WordPart, word_parts.len);
                        for (word_parts, 0..) |p, i| {
                            copied_parts[i] = try self.copyWordPart(p);
                        }
                        break :w copied_parts;
                    } else null;
                    break :m ParameterExpansion.Modifier{
                        .op = mod.op,
                        .check_null = mod.check_null,
                        .word = copied_word,
                    };
                } else null;
                break :blk WordPart{ .parameter = ParameterExpansion{
                    .name = copied_name,
                    .modifier = copied_modifier,
                } };
            },
        };
    }

    /// Check if a string is a valid shell identifier.
    fn isValidIdentifier(s: []const u8) bool {
        if (s.len == 0) return false;

        // First character must be letter or underscore
        const first = s[0];
        if (!((first >= 'A' and first <= 'Z') or
            (first >= 'a' and first <= 'z') or
            first == '_'))
        {
            return false;
        }

        // Rest can be letters, digits, or underscores
        for (s[1..]) |c| {
            if (!((c >= 'A' and c <= 'Z') or
                (c >= 'a' and c <= 'z') or
                (c >= '0' and c <= '9') or
                c == '_'))
            {
                return false;
            }
        }

        return true;
    }

    /// Checks if a word is an unquoted reserved word.
    ///
    /// Reserved words are only recognized when:
    /// 1. The word consists of exactly one part
    /// 2. That part is a literal (no quoting or expansions)
    /// 3. The text matches a reserved word exactly
    ///
    /// Note: WordCollector already concatenates continuation tokens into single
    /// literal parts, so we don't need to handle multi-part literals here.
    /// A reserved word split by buffer boundaries (e.g., "i" + "f") becomes
    /// a single literal "if" after word collection.
    ///
    /// Reference: POSIX.1-2017 Section 2.4 Reserved Words
    /// "This recognition shall only occur when none of the characters
    /// are quoted"
    fn isUnquotedReservedWord(word: Word) ?ReservedWord {
        // Reserved word must be a single unquoted literal part
        if (word.parts.len != 1) return null;

        return switch (word.parts[0]) {
            .literal => |lit| std.meta.stringToEnum(ReservedWord, lit),
            else => null,
        };
    }

    /// Set error information.
    fn setError(self: *Parser, message: []const u8, position: usize, line: usize, column: usize) void {
        self.error_info = ErrorInfo{
            .message = message,
            .position = position,
            .line = line,
            .column = column,
        };
    }

    /// Try to convert word parts to an fd number.
    /// Returns null if:
    ///   - parts is empty
    ///   - any part is quoted or double_quoted (fd numbers must be unquoted)
    ///   - any part contains non-digit characters
    ///   - the number overflows u32
    fn wordPartsToFdNumber(parts: []const WordPart) ?u32 {
        if (parts.len == 0) return null;

        var result: u32 = 0;

        for (parts) |part| {
            // Only unquoted literals can form fd numbers
            const lit = switch (part) {
                .literal => |l| l,
                // Quoted, double_quoted, or parameter parts can't be fd numbers
                .quoted, .double_quoted, .parameter => return null,
            };
            if (lit.len == 0) continue;

            // Parse this part as an integer
            const part_value = std.fmt.parseInt(u32, lit, 10) catch return null;

            // Shift result left by the number of digits in this part
            for (0..lit.len) |_| {
                result = std.math.mul(u32, result, 10) catch return null;
            }

            // Add the new part's value
            result = std.math.add(u32, result, part_value) catch return null;
        }
        return result;
    }

    /// Parse an fd duplication target from a word.
    /// Valid targets are:
    ///   - "-" (close the source fd)
    ///   - A digit sequence (duplicate to that fd)
    /// Returns InvalidFdRedirectionTarget if the word is not a valid fd target.
    fn parseFdTarget(self: *Parser, word: Word) ParseError!RedirectionTarget {
        // Check for close: exactly one part that is "-"
        // This works with literal, quoted, or double_quoted containing just "-"
        if (word.parts.len == 1) {
            const text: ?[]const u8 = switch (word.parts[0]) {
                .literal => |lit| lit,
                .quoted => |q| q,
                .double_quoted => |parts| blk: {
                    // double_quoted with exactly one literal/quoted part containing "-"
                    if (parts.len == 1) {
                        break :blk switch (parts[0]) {
                            .literal => |lit| lit,
                            .quoted => |q| q,
                            .double_quoted, .parameter => null,
                        };
                    }
                    break :blk null;
                },
                // Parameter expansions can't be evaluated at parse time
                .parameter => null,
            };
            if (text) |t| {
                if (std.mem.eql(u8, t, "-")) {
                    return .close;
                }
            }
        }

        // Check for fd number: all parts must be digits and fit in u32
        if (wordPartsToFdNumber(word.parts)) |fd| {
            return .{ .fd = fd };
        }

        // Invalid target (non-digits or overflow)
        self.setError("invalid fd redirection target (expected digits or '-')", word.position, word.line, word.column);
        return ParseError.InvalidFdRedirectionTarget;
    }
};

// --- Parser tests ---

fn expectWordPart(actual: WordPart, expected: WordPart) !void {
    switch (expected) {
        .literal => |exp_lit| {
            if (actual != .literal) return error.ExpectedLiteral;
            try std.testing.expectEqualStrings(exp_lit, actual.literal);
        },
        .quoted => |exp_q| {
            if (actual != .quoted) return error.ExpectedQuoted;
            try std.testing.expectEqualStrings(exp_q, actual.quoted);
        },
        .double_quoted => |exp_parts| {
            if (actual != .double_quoted) return error.ExpectedDoubleQuoted;
            try std.testing.expectEqual(exp_parts.len, actual.double_quoted.len);
            for (actual.double_quoted, exp_parts) |act_part, exp_part| {
                try expectWordPart(act_part, exp_part);
            }
        },
        .parameter => |exp_param| {
            if (actual != .parameter) return error.ExpectedParameter;
            try std.testing.expectEqualStrings(exp_param.name, actual.parameter.name);
            // For now, just check modifier presence matches
            if (exp_param.modifier == null) {
                try std.testing.expect(actual.parameter.modifier == null);
            } else {
                try std.testing.expect(actual.parameter.modifier != null);
                try std.testing.expectEqual(exp_param.modifier.?.op, actual.parameter.modifier.?.op);
                try std.testing.expectEqual(exp_param.modifier.?.check_null, actual.parameter.modifier.?.check_null);
            }
        },
    }
}

fn expectWord(word: Word, expected_parts: []const WordPart) !void {
    try std.testing.expectEqual(expected_parts.len, word.parts.len);
    for (word.parts, expected_parts) |actual, expected| {
        try expectWordPart(actual, expected);
    }
}

fn expectSimpleCommand(
    cmd: ?ParsedCommand,
    expected_assignments: []const struct { name: []const u8, value: []const WordPart },
    expected_argv: []const []const WordPart,
    expected_redirections: usize,
) !void {
    const c = cmd orelse return error.ExpectedCommand;
    const simple = blk: {
        const pipeline = c.and_or.items[0].pipeline;
        // For testing simple commands wrapped in pipelines, use first command
        // TODO: Add dedicated pipeline testing helper when pipeline execution is implemented
        try std.testing.expectEqual(@as(usize, 1), pipeline.commands.len);
        break :blk switch (pipeline.commands[0]) {
            .simple => |s| s,
            .if_clause => return error.ExpectedSimpleCommand,
        };
    };

    try std.testing.expectEqual(expected_assignments.len, simple.assignments.len);
    for (simple.assignments, expected_assignments) |assignment, expected| {
        try std.testing.expectEqualStrings(expected.name, assignment.name);
        try expectWord(assignment.value, expected.value);
    }

    try std.testing.expectEqual(expected_argv.len, simple.argv.len);
    for (simple.argv, expected_argv) |word, expected| {
        try expectWord(word, expected);
    }

    try std.testing.expectEqual(expected_redirections, simple.redirections.len);
}

fn expectFileTarget(target: RedirectionTarget, expected_parts: []const WordPart) !void {
    switch (target) {
        .file => |word| try expectWord(word, expected_parts),
        .fd => return error.ExpectedFileTarget,
        .close => return error.ExpectedFileTarget,
    }
}

fn expectFdTarget(target: RedirectionTarget, expected_fd: u32) !void {
    switch (target) {
        .fd => |fd| try std.testing.expectEqual(expected_fd, fd),
        .file => return error.ExpectedFdTarget,
        .close => return error.ExpectedFdTarget,
    }
}

fn expectCloseTarget(target: RedirectionTarget) !void {
    switch (target) {
        .close => {},
        .file => return error.ExpectedCloseTarget,
        .fd => return error.ExpectedCloseTarget,
    }
}

/// Helper to extract the first SimpleCommand from a ParsedCommand.
/// Use this when testing simple commands that are wrapped in the AndOrList/Pipeline structure.
fn getFirstSimpleCommand(cmd: ParsedCommand) SimpleCommand {
    return switch (getPipeline(cmd).commands[0]) {
        .simple => |s| s,
        .if_clause => unreachable,
    };
}

/// Helper to extract the Pipeline from a ParsedCommand.
fn getPipeline(cmd: ParsedCommand) Pipeline {
    return cmd.and_or.items[0].pipeline;
}

test "parseCommand: empty input returns null" {
    var reader = std.io.Reader.fixed("");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(std.testing.allocator, &lex);

    const result = try parser_inst.parseCommand();
    try std.testing.expectEqual(null, result);
}

test "parseCommand: whitespace only returns null" {
    var reader = std.io.Reader.fixed("   \t  ");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(std.testing.allocator, &lex);

    const result = try parser_inst.parseCommand();
    try std.testing.expectEqual(null, result);
}

test "parseCommand: simple command" {
    var reader = std.io.Reader.fixed("cmd arg1 arg2\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try expectSimpleCommand(
        result,
        &.{},
        &.{ &.{.{ .literal = "cmd" }}, &.{.{ .literal = "arg1" }}, &.{.{ .literal = "arg2" }} },
        0,
    );
}

test "parseCommand: simple assignment" {
    var reader = std.io.Reader.fixed("FOO=bar\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try expectSimpleCommand(
        result,
        &.{.{ .name = "FOO", .value = &.{.{ .literal = "bar" }} }},
        &.{},
        0,
    );
}

test "parseCommand: empty assignment value" {
    var reader = std.io.Reader.fixed("FOO=\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try expectSimpleCommand(
        result,
        &.{.{ .name = "FOO", .value = &.{} }},
        &.{},
        0,
    );
}

test "parseCommand: assignment with command" {
    var reader = std.io.Reader.fixed("FOO=bar cmd arg\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try expectSimpleCommand(
        result,
        &.{.{ .name = "FOO", .value = &.{.{ .literal = "bar" }} }},
        &.{ &.{.{ .literal = "cmd" }}, &.{.{ .literal = "arg" }} },
        0,
    );
}

test "parseCommand: multiple assignments" {
    var reader = std.io.Reader.fixed("FOO=bar BAZ=qux cmd\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try expectSimpleCommand(
        result,
        &.{
            .{ .name = "FOO", .value = &.{.{ .literal = "bar" }} },
            .{ .name = "BAZ", .value = &.{.{ .literal = "qux" }} },
        },
        &.{&.{.{ .literal = "cmd" }}},
        0,
    );
}

test "parseCommand: non-assignment (equals at start)" {
    var reader = std.io.Reader.fixed("=foo\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try expectSimpleCommand(
        result,
        &.{},
        &.{&.{.{ .literal = "=foo" }}},
        0,
    );
}

test "parseCommand: non-assignment (invalid identifier)" {
    var reader = std.io.Reader.fixed("123=foo\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try expectSimpleCommand(
        result,
        &.{},
        &.{&.{.{ .literal = "123=foo" }}},
        0,
    );
}

test "parseCommand: simple redirection" {
    var reader = std.io.Reader.fixed("> file\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    const simple = getFirstSimpleCommand(cmd);

    try std.testing.expectEqual(@as(usize, 0), simple.assignments.len);
    try std.testing.expectEqual(@as(usize, 0), simple.argv.len);
    try std.testing.expectEqual(@as(usize, 1), simple.redirections.len);

    const redir = simple.redirections[0];
    try std.testing.expectEqual(lexer.Redirection.Out, redir.op);
    try std.testing.expectEqual(@as(?u32, null), redir.source_fd);
    try expectFileTarget(redir.target, &.{.{ .literal = "file" }});
}

test "parseCommand: command with redirection" {
    var reader = std.io.Reader.fixed("cmd > out\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    const simple = getFirstSimpleCommand(cmd);

    try std.testing.expectEqual(@as(usize, 1), simple.argv.len);
    try std.testing.expectEqual(@as(usize, 1), simple.redirections.len);
    try expectFileTarget(simple.redirections[0].target, &.{.{ .literal = "out" }});
}

test "parseCommand: fd redirection 2>&1" {
    var reader = std.io.Reader.fixed("cmd 2>&1\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    const simple = getFirstSimpleCommand(cmd);

    try std.testing.expectEqual(@as(usize, 1), simple.argv.len);
    try std.testing.expectEqual(@as(usize, 1), simple.redirections.len);

    const redir = simple.redirections[0];
    try std.testing.expectEqual(lexer.Redirection.Fd, redir.op);
    try std.testing.expectEqual(@as(?u32, 2), redir.source_fd);
    try expectFdTarget(redir.target, 1);
}

test "parseCommand: multiple redirections" {
    var reader = std.io.Reader.fixed("cmd > out 2>&1 < in\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    const simple = getFirstSimpleCommand(cmd);

    try std.testing.expectEqual(@as(usize, 1), simple.argv.len);
    try std.testing.expectEqual(@as(usize, 3), simple.redirections.len);

    try std.testing.expectEqual(lexer.Redirection.Out, simple.redirections[0].op);
    try std.testing.expectEqual(lexer.Redirection.Fd, simple.redirections[1].op);
    try std.testing.expectEqual(lexer.Redirection.In, simple.redirections[2].op);
}

test "parseCommand: missing redirection target" {
    var reader = std.io.Reader.fixed(">\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = parser_inst.parseCommand();
    try std.testing.expectError(ParseError.MissingRedirectionTarget, result);

    const err_info = parser_inst.getErrorInfo();
    try std.testing.expect(err_info != null);
    try std.testing.expectEqualStrings("missing redirection target", err_info.?.message);
}

test "parseCommand: single-quoted word" {
    var reader = std.io.Reader.fixed("'hello world'\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try expectSimpleCommand(
        result,
        &.{},
        &.{&.{.{ .quoted = "hello world" }}},
        0,
    );
}

test "parseCommand: double-quoted word" {
    var reader = std.io.Reader.fixed("\"hello world\"\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try expectSimpleCommand(
        result,
        &.{},
        &.{&.{.{ .double_quoted = &.{.{ .literal = "hello world" }} }}},
        0,
    );
}

test "parseCommand: quoted redirection-like string is literal" {
    // "2>&1" in quotes should be a literal argument, not a redirection
    var reader = std.io.Reader.fixed("cmd \"2>&1\"\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    const simple = getFirstSimpleCommand(cmd);

    // Should have 2 argv items: "cmd" and "2>&1"
    try std.testing.expectEqual(@as(usize, 2), simple.argv.len);
    try expectWord(simple.argv[0], &.{.{ .literal = "cmd" }});
    // Separate tokens from double-quote parsing
    try expectWord(simple.argv[1], &.{.{ .double_quoted = &.{.{ .literal = "2>&1" }} }});

    // No redirections
    try std.testing.expectEqual(@as(usize, 0), simple.redirections.len);
}

test "parseCommand: single-quoted redirection-like string is literal" {
    // '2>&1' in single quotes should be a literal argument, not a redirection
    var reader = std.io.Reader.fixed("cmd '2>&1'\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    const simple = getFirstSimpleCommand(cmd);

    // Should have 2 argv items: "cmd" and "2>&1"
    try std.testing.expectEqual(@as(usize, 2), simple.argv.len);
    try expectWord(simple.argv[0], &.{.{ .literal = "cmd" }});
    try expectWord(simple.argv[1], &.{.{ .quoted = "2>&1" }}); // Single quotes preserve content as-is

    // No redirections
    try std.testing.expectEqual(@as(usize, 0), simple.redirections.len);
}

test "parseCommand: command followed by double-quoted expansion" {
    // echo "$@" should produce exactly 2 argv items, not 3
    var reader = std.io.Reader.fixed("echo \"$@\"\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    const simple = getFirstSimpleCommand(cmd);

    // Should have exactly 2 argv items: "echo" and "$@" (in double quotes)
    try std.testing.expectEqual(@as(usize, 2), simple.argv.len);
    try expectWord(simple.argv[0], &.{.{ .literal = "echo" }});

    // Second word should be a double_quoted containing a parameter expansion
    try std.testing.expectEqual(@as(usize, 1), simple.argv[1].parts.len);
    switch (simple.argv[1].parts[0]) {
        .double_quoted => |inner| {
            try std.testing.expectEqual(@as(usize, 1), inner.len);
            switch (inner[0]) {
                .parameter => |param| {
                    try std.testing.expectEqualStrings("@", param.name);
                },
                else => return error.ExpectedParameterExpansion,
            }
        },
        else => return error.ExpectedDoubleQuoted,
    }
}

test "parseCommand: mixed quotes in word" {
    var reader = std.io.Reader.fixed("a'b'c\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try expectSimpleCommand(
        result,
        &.{},
        &.{&.{ .{ .literal = "a" }, .{ .quoted = "b" }, .{ .literal = "c" } }},
        0,
    );
}

test "parseCommand: escaped character" {
    var reader = std.io.Reader.fixed("\\$HOME\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try expectSimpleCommand(
        result,
        &.{},
        &.{&.{ .{ .quoted = "$" }, .{ .literal = "HOME" } }},
        0,
    );
}

test "parseCommand: complex command" {
    var reader = std.io.Reader.fixed("FOO=bar cmd 'arg 1' >out 2>&1\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    const simple = getFirstSimpleCommand(cmd);

    try std.testing.expectEqual(@as(usize, 1), simple.assignments.len);
    try std.testing.expectEqualStrings("FOO", simple.assignments[0].name);

    try std.testing.expectEqual(@as(usize, 2), simple.argv.len);
    try expectWord(simple.argv[0], &.{.{ .literal = "cmd" }});
    try expectWord(simple.argv[1], &.{.{ .quoted = "arg 1" }});

    try std.testing.expectEqual(@as(usize, 2), simple.redirections.len);
}

test "parseCommand: assignment after command is not assignment" {
    // Once we've seen a command, further FOO=bar are arguments, not assignments
    var reader = std.io.Reader.fixed("cmd FOO=bar\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try expectSimpleCommand(
        result,
        &.{}, // no assignments
        &.{ &.{.{ .literal = "cmd" }}, &.{.{ .literal = "FOO=bar" }} }, // FOO=bar is an argument
        0,
    );
}

// --- Fd duplication validation tests ---

test "parseCommand: fd close >&-" {
    var reader = std.io.Reader.fixed("cmd >&-\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    const simple = getFirstSimpleCommand(cmd);

    try std.testing.expectEqual(@as(usize, 1), simple.argv.len);
    try std.testing.expectEqual(@as(usize, 1), simple.redirections.len);

    const redir = simple.redirections[0];
    try std.testing.expectEqual(lexer.Redirection.Fd, redir.op);
    try std.testing.expectEqual(@as(?u32, null), redir.source_fd);
    try expectCloseTarget(redir.target);
}

test "parseCommand: fd close 2>&-" {
    var reader = std.io.Reader.fixed("cmd 2>&-\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    const simple = getFirstSimpleCommand(cmd);

    try std.testing.expectEqual(@as(usize, 1), simple.redirections.len);

    const redir = simple.redirections[0];
    try std.testing.expectEqual(lexer.Redirection.Fd, redir.op);
    try std.testing.expectEqual(@as(?u32, 2), redir.source_fd);
    try expectCloseTarget(redir.target);
}

test "parseCommand: invalid fd target >&foo errors" {
    var reader = std.io.Reader.fixed("cmd >&foo\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = parser_inst.parseCommand();
    try std.testing.expectError(ParseError.InvalidFdRedirectionTarget, result);

    const err_info = parser_inst.getErrorInfo();
    try std.testing.expect(err_info != null);
}

test "parseCommand: invalid fd target >&1x errors" {
    // "1x" is not a valid fd (contains non-digit)
    var reader = std.io.Reader.fixed("cmd >&1x\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = parser_inst.parseCommand();
    try std.testing.expectError(ParseError.InvalidFdRedirectionTarget, result);
}

test "parseCommand: escaped quote after fd target errors" {
    // \'2>&1\' - the trailing \' makes target "1'" which is invalid
    var reader = std.io.Reader.fixed("\\'2>&1\\'\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = parser_inst.parseCommand();
    try std.testing.expectError(ParseError.InvalidFdRedirectionTarget, result);
}

// --- Buffer boundary tests ---

test "parseCommand: fd redirection 2>&1 with buffer boundary" {
    // Test that 2>&1 is correctly parsed when buffer boundary falls within the fd prefix.
    // The parser should correctly combine the split digits into source_fd=2.
    const pipe = try std.posix.pipe();
    defer std.posix.close(pipe[0]);

    _ = try std.posix.write(pipe[1], "cmd 2>&1\n");
    std.posix.close(pipe[1]);

    // Small buffer that forces splits within the input
    const file = std.fs.File{ .handle = pipe[0] };
    var small_buf: [1]u8 = undefined;
    var file_reader = file.reader(&small_buf);
    var lex = lexer.Lexer.init(&file_reader.interface);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    const simple = getFirstSimpleCommand(cmd);

    try std.testing.expectEqual(@as(usize, 1), simple.argv.len);
    try expectWord(simple.argv[0], &.{.{ .literal = "cmd" }});

    try std.testing.expectEqual(@as(usize, 1), simple.redirections.len);
    const redir = simple.redirections[0];
    try std.testing.expectEqual(lexer.Redirection.Fd, redir.op);
    try std.testing.expectEqual(@as(?u32, 2), redir.source_fd);
    try expectFdTarget(redir.target, 1);
}

test "parseCommand: multi-digit fd 12>&1 with buffer boundary" {
    // Test that 12>&1 is correctly parsed when buffer boundary splits the fd digits.
    const pipe = try std.posix.pipe();
    defer std.posix.close(pipe[0]);

    _ = try std.posix.write(pipe[1], "cmd 12>&1\n");
    std.posix.close(pipe[1]);

    const file = std.fs.File{ .handle = pipe[0] };
    var small_buf: [1]u8 = undefined;
    var file_reader = file.reader(&small_buf);
    var lex = lexer.Lexer.init(&file_reader.interface);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    const simple = getFirstSimpleCommand(cmd);

    try std.testing.expectEqual(@as(usize, 1), simple.argv.len);
    try std.testing.expectEqual(@as(usize, 1), simple.redirections.len);

    const redir = simple.redirections[0];
    try std.testing.expectEqual(lexer.Redirection.Fd, redir.op);
    try std.testing.expectEqual(@as(?u32, 12), redir.source_fd);
    try expectFdTarget(redir.target, 1);
}

test "parseCommand: non-digit word before redirection with buffer boundary" {
    // Test that a2>file correctly treats "a2" as a word and ">file" as redirection.
    const pipe = try std.posix.pipe();
    defer std.posix.close(pipe[0]);

    _ = try std.posix.write(pipe[1], "a2>file\n");
    std.posix.close(pipe[1]);

    const file = std.fs.File{ .handle = pipe[0] };
    var small_buf: [1]u8 = undefined;
    var file_reader = file.reader(&small_buf);
    var lex = lexer.Lexer.init(&file_reader.interface);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    const simple = getFirstSimpleCommand(cmd);

    // "a2" should be argv[0], redirection should be separate
    try std.testing.expectEqual(@as(usize, 1), simple.argv.len);
    try expectWord(simple.argv[0], &.{.{ .literal = "a2" }}); // Split across buffer boundaries

    try std.testing.expectEqual(@as(usize, 1), simple.redirections.len);
    const redir = simple.redirections[0];
    try std.testing.expectEqual(lexer.Redirection.Out, redir.op);
    try std.testing.expectEqual(@as(?u32, null), redir.source_fd);
    try expectFileTarget(redir.target, &.{.{ .literal = "file" }});
}

test "parseCommand: input fd redirection 0<&3 with buffer boundary" {
    // Test input fd duplication with buffer boundary.
    const pipe = try std.posix.pipe();
    defer std.posix.close(pipe[0]);

    _ = try std.posix.write(pipe[1], "cmd 0<&3\n");
    std.posix.close(pipe[1]);

    const file = std.fs.File{ .handle = pipe[0] };
    var small_buf: [1]u8 = undefined;
    var file_reader = file.reader(&small_buf);
    var lex = lexer.Lexer.init(&file_reader.interface);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    const simple = getFirstSimpleCommand(cmd);

    try std.testing.expectEqual(@as(usize, 1), simple.argv.len);
    try expectWord(simple.argv[0], &.{.{ .literal = "cmd" }});

    try std.testing.expectEqual(@as(usize, 1), simple.redirections.len);
    const redir = simple.redirections[0];
    try std.testing.expectEqual(lexer.Redirection.Fd, redir.op);
    try std.testing.expectEqual(@as(?u32, 0), redir.source_fd);
    try expectFdTarget(redir.target, 3);
}

test "parseCommand: input redirection 0<file with buffer boundary" {
    // Test input redirection with fd prefix and buffer boundary.
    const pipe = try std.posix.pipe();
    defer std.posix.close(pipe[0]);

    _ = try std.posix.write(pipe[1], "cmd 0<input\n");
    std.posix.close(pipe[1]);

    const file = std.fs.File{ .handle = pipe[0] };
    var small_buf: [1]u8 = undefined;
    var file_reader = file.reader(&small_buf);
    var lex = lexer.Lexer.init(&file_reader.interface);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    const cmd = result orelse return error.ExpectedCommand;

    const simple = getFirstSimpleCommand(cmd);

    try std.testing.expectEqual(@as(usize, 1), simple.argv.len);
    try std.testing.expectEqual(@as(usize, 1), simple.redirections.len);

    const redir = simple.redirections[0];
    try std.testing.expectEqual(lexer.Redirection.In, redir.op);
    try std.testing.expectEqual(@as(?u32, 0), redir.source_fd);
    try expectFileTarget(redir.target, &.{.{ .literal = "input" }});
}

// --- Fuzz test for buffer boundary invariance ---

/// Parse input with a fixed reader (large buffer) and return semantic results.
fn parseWithFixedReader(allocator: Allocator, input: []const u8) !?ParsedCommand {
    var reader = std.io.Reader.fixed(input);
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(allocator, &lex);
    return parser_inst.parseCommand();
}

/// Parse input with a pipe-based reader (small buffer) and return semantic results.
fn parseWithSmallBuffer(allocator: Allocator, input: []const u8, buf_size: usize) !?ParsedCommand {
    const pipe = try std.posix.pipe();
    defer std.posix.close(pipe[0]);

    _ = try std.posix.write(pipe[1], input);
    std.posix.close(pipe[1]);

    const file = std.fs.File{ .handle = pipe[0] };

    // Use buffer size 1-5 based on buf_size parameter
    var small_buf_1: [1]u8 = undefined;
    var small_buf_2: [2]u8 = undefined;
    var small_buf_3: [3]u8 = undefined;
    var small_buf_4: [4]u8 = undefined;
    var small_buf_5: [5]u8 = undefined;

    switch (buf_size) {
        1 => {
            var file_reader = file.reader(&small_buf_1);
            var lex = lexer.Lexer.init(&file_reader.interface);
            var parser_inst = Parser.init(allocator, &lex);
            return parser_inst.parseCommand();
        },
        2 => {
            var file_reader = file.reader(&small_buf_2);
            var lex = lexer.Lexer.init(&file_reader.interface);
            var parser_inst = Parser.init(allocator, &lex);
            return parser_inst.parseCommand();
        },
        3 => {
            var file_reader = file.reader(&small_buf_3);
            var lex = lexer.Lexer.init(&file_reader.interface);
            var parser_inst = Parser.init(allocator, &lex);
            return parser_inst.parseCommand();
        },
        4 => {
            var file_reader = file.reader(&small_buf_4);
            var lex = lexer.Lexer.init(&file_reader.interface);
            var parser_inst = Parser.init(allocator, &lex);
            return parser_inst.parseCommand();
        },
        else => {
            var file_reader = file.reader(&small_buf_5);
            var lex = lexer.Lexer.init(&file_reader.interface);
            var parser_inst = Parser.init(allocator, &lex);
            return parser_inst.parseCommand();
        },
    }
}

/// Concatenate word parts into a single string for comparison.
fn wordToString(allocator: Allocator, word: Word) ![]const u8 {
    var result: std.ArrayListUnmanaged(u8) = .empty;
    for (word.parts) |part| {
        try appendWordPartText(allocator, &result, part);
    }
    return result.toOwnedSlice(allocator);
}

/// Recursively append text content from a WordPart to a list.
fn appendWordPartText(allocator: Allocator, result: *std.ArrayListUnmanaged(u8), part: WordPart) !void {
    switch (part) {
        .literal => |lit| try result.appendSlice(allocator, lit),
        .quoted => |q| try result.appendSlice(allocator, q),
        .double_quoted => |parts| {
            for (parts) |p| {
                try appendWordPartText(allocator, result, p);
            }
        },
        .parameter => |param| {
            // Append the parameter name as a placeholder for comparison purposes.
            // This allows buffer boundary tests to compare commands with expansions.
            try result.appendSlice(allocator, "$");
            try result.appendSlice(allocator, param.name);
        },
    }
}

/// Compare two Commands for semantic equality (by comparing their simple command payloads).
fn commandsEqual(allocator: Allocator, a: ?ParsedCommand, b: ?ParsedCommand) !bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;

    const cmd_a = a.?;
    const cmd_b = b.?;

    const simple_a = getFirstSimpleCommand(cmd_a);
    const simple_b = getFirstSimpleCommand(cmd_b);

    // Compare assignments
    if (simple_a.assignments.len != simple_b.assignments.len) return false;
    for (simple_a.assignments, simple_b.assignments) |ass_a, ass_b| {
        if (!std.mem.eql(u8, ass_a.name, ass_b.name)) return false;
        const val_a = try wordToString(allocator, ass_a.value);
        const val_b = try wordToString(allocator, ass_b.value);
        if (!std.mem.eql(u8, val_a, val_b)) return false;
    }

    // Compare argv
    if (simple_a.argv.len != simple_b.argv.len) return false;
    for (simple_a.argv, simple_b.argv) |word_a, word_b| {
        const str_a = try wordToString(allocator, word_a);
        const str_b = try wordToString(allocator, word_b);
        if (!std.mem.eql(u8, str_a, str_b)) return false;
    }

    // Compare redirections
    if (simple_a.redirections.len != simple_b.redirections.len) return false;
    for (simple_a.redirections, simple_b.redirections) |redir_a, redir_b| {
        if (redir_a.op != redir_b.op) return false;
        if (redir_a.source_fd != redir_b.source_fd) return false;
        // Compare targets based on their type
        switch (redir_a.target) {
            .file => |word_a| {
                switch (redir_b.target) {
                    .file => |word_b| {
                        const str_a = try wordToString(allocator, word_a);
                        const str_b = try wordToString(allocator, word_b);
                        if (!std.mem.eql(u8, str_a, str_b)) return false;
                    },
                    else => return false,
                }
            },
            .fd => |fd_a| {
                switch (redir_b.target) {
                    .fd => |fd_b| {
                        if (fd_a != fd_b) return false;
                    },
                    else => return false,
                }
            },
            .close => {
                switch (redir_b.target) {
                    .close => {},
                    else => return false,
                }
            },
        }
    }

    return true;
}

test "parseCommand: buffer boundary invariance for fd redirections" {
    // Test that specific fd-related inputs parse identically across buffer sizes.
    const test_inputs = [_][]const u8{
        "2>&1\n",
        "12>&1\n",
        "cmd 2>&1\n",
        "cmd 12>file\n",
        "a2>file\n",
        "2>file\n",
        "cmd >out 2>&1\n",
        "FOO=bar cmd 2>&1\n",
        // Input redirections
        "0<&3\n",
        "cmd 0<&3\n",
        "0<input\n",
        "cmd 0<input\n",
        "3<&0\n",
        // Quoted redirection-like strings (should be literals, not redirections)
        "cmd \"2>&1\"\n",
        "cmd '2>&1'\n",
    };

    for (test_inputs) |input| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();

        // Parse with large buffer (reference result)
        const ref_result = try parseWithFixedReader(arena.allocator(), input);

        // Parse with various small buffer sizes and compare
        for (1..6) |buf_size| {
            var arena2 = std.heap.ArenaAllocator.init(std.testing.allocator);
            defer arena2.deinit();

            const small_result = parseWithSmallBuffer(arena2.allocator(), input, buf_size) catch |err| {
                // If small buffer parse fails, reference should also fail or be null
                if (ref_result != null) {
                    std.debug.print("Small buffer (size {d}) failed but reference succeeded for: {s}\n", .{ buf_size, input });
                    return err;
                }
                continue;
            };

            if (!try commandsEqual(arena2.allocator(), ref_result, small_result)) {
                std.debug.print("Mismatch for input '{s}' with buffer size {d}\n", .{ input, buf_size });
                std.debug.print("Large buffer: {f}\n", .{ref_result.?});
                std.debug.print("Small buffer: {f}\n", .{small_result.?});
                return error.BufferBoundaryMismatch;
            }
        }
    }
}

// --- Parenthesis error tests ---

test "parseCommand: left parenthesis at start returns UnsupportedSyntax" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("(cmd)");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const result = parser.parseCommand();
    try std.testing.expectError(ParseError.UnsupportedSyntax, result);
    try std.testing.expectEqualStrings("subshells are not yet implemented", parser.error_info.?.message);
}

test "parseCommand: right parenthesis at start returns UnsupportedSyntax" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed(")");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const result = parser.parseCommand();
    try std.testing.expectError(ParseError.UnsupportedSyntax, result);
    try std.testing.expectEqualStrings("syntax error near unexpected token `)'", parser.error_info.?.message);
}

test "parseCommand: left parenthesis after command returns UnsupportedSyntax" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("cmd (");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const result = parser.parseCommand();
    try std.testing.expectError(ParseError.UnsupportedSyntax, result);
    try std.testing.expectEqualStrings("subshells are not yet implemented", parser.error_info.?.message);
}

test "parseCommand: right parenthesis after command returns UnsupportedSyntax" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("cmd )");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const result = parser.parseCommand();
    try std.testing.expectError(ParseError.UnsupportedSyntax, result);
    try std.testing.expectEqualStrings("syntax error near unexpected token `)'", parser.error_info.?.message);
}

test "parseCommand: parenthesis as redirection target returns UnsupportedSyntax" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("cmd >(");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const result = parser.parseCommand();
    try std.testing.expectError(ParseError.UnsupportedSyntax, result);
}

test "parseCommand: parenthesis in word returns UnsupportedSyntax" {
    // "cmd(" should tokenize as "cmd", "(" - then ( triggers error
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("cmd(");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const result = parser.parseCommand();
    try std.testing.expectError(ParseError.UnsupportedSyntax, result);
}

test "parseCommand: single-quoted parentheses are valid arguments" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo '(foo)'");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);

    const simple = getFirstSimpleCommand(cmd.?);

    try std.testing.expectEqual(@as(usize, 2), simple.argv.len);
    try expectWord(simple.argv[0], &.{.{ .literal = "echo" }});
    try expectWord(simple.argv[1], &.{.{ .quoted = "(foo)" }});
}

test "parseCommand: double-quoted parentheses are valid arguments" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo \"(bar)\"");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);

    const simple = getFirstSimpleCommand(cmd.?);

    try std.testing.expectEqual(@as(usize, 2), simple.argv.len);
    try expectWord(simple.argv[0], &.{.{ .literal = "echo" }});
    try expectWord(simple.argv[1], &.{.{ .double_quoted = &.{.{ .literal = "(bar)" }} }});
}

// --- Command list tests ---

test "next: buffer boundary with separator (1 byte buffer)" {
    // Test parsing "foo;bar" with a tiny buffer to check if separator
    // can arrive while parser is in .collecting_word state
    const pipe = try std.posix.pipe();
    defer std.posix.close(pipe[0]);

    _ = try std.posix.write(pipe[1], "foo;bar");
    std.posix.close(pipe[1]);

    const file = std.fs.File{ .handle = pipe[0] };
    var buf: [1]u8 = undefined;
    var file_reader = file.reader(&buf);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var lex = lexer.Lexer.init(&file_reader.interface);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    // Collect commands using iterator
    var commands: [2]SimpleCommand = undefined;
    var count: usize = 0;
    while (try parser_inst.next()) |cmd| {
        if (count < 2) {
            commands[count] = getFirstSimpleCommand(cmd);
        }
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), count);

    // Verify first command is "foo"
    try std.testing.expectEqual(@as(usize, 1), commands[0].argv.len);
    const word1 = try wordToString(arena.allocator(), commands[0].argv[0]);
    try std.testing.expectEqualStrings("foo", word1);

    // Verify second command is "bar"
    try std.testing.expectEqual(@as(usize, 1), commands[1].argv.len);
    const word2 = try wordToString(arena.allocator(), commands[1].argv[0]);
    try std.testing.expectEqualStrings("bar", word2);
}

test "next: two commands with newline separator" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo a\necho b");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    var count: usize = 0;
    while (try parser_inst.next()) |_| {
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), count);
}

test "next: only separators yields no commands" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // Use spaces between semicolons to avoid `;;` which is DoubleSemicolon
    var reader = std.io.Reader.fixed("; ; ;");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const cmd = try parser_inst.next();
    try std.testing.expectEqual(null, cmd);
}

test "next: mixed separators" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo a\n; echo b; \n echo c");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    var count: usize = 0;
    while (try parser_inst.next()) |_| {
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), count);
}

test "next: double semicolon treated as separator" {
    // TODO: `;;` will need special handling for case/esac
    // For now, it's treated as a separator (empty command between)
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo a;; echo b");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    var count: usize = 0;
    while (try parser_inst.next()) |_| {
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), count);
}

// --- Parameter expansion tests ---

test "parseCommand: simple expansion $VAR" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo $VAR");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);

    const simple = getFirstSimpleCommand(cmd.?);

    try std.testing.expectEqual(@as(usize, 2), simple.argv.len);

    // Second argument should be a parameter expansion
    const arg = simple.argv[1];
    try std.testing.expectEqual(@as(usize, 1), arg.parts.len);
    try std.testing.expect(arg.parts[0] == .parameter);
    try std.testing.expectEqualStrings("VAR", arg.parts[0].parameter.name);
    try std.testing.expect(arg.parts[0].parameter.modifier == null);
}

test "parseCommand: simple expansion $1" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo $1");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);

    const simple = getFirstSimpleCommand(cmd.?);

    const arg = simple.argv[1];
    try std.testing.expect(arg.parts[0] == .parameter);
    try std.testing.expectEqualStrings("1", arg.parts[0].parameter.name);
}

test "parseCommand: simple expansion $?" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo $?");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);

    const simple = getFirstSimpleCommand(cmd.?);

    const arg = simple.argv[1];
    try std.testing.expect(arg.parts[0] == .parameter);
    try std.testing.expectEqualStrings("?", arg.parts[0].parameter.name);
}

test "parseCommand: braced expansion ${VAR}" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo ${VAR}");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);

    const simple = getFirstSimpleCommand(cmd.?);

    const arg = simple.argv[1];
    try std.testing.expect(arg.parts[0] == .parameter);
    try std.testing.expectEqualStrings("VAR", arg.parts[0].parameter.name);
    try std.testing.expect(arg.parts[0].parameter.modifier == null);
}

test "parseCommand: expansion with default ${VAR:-default}" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo ${VAR:-default}");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);

    const simple = getFirstSimpleCommand(cmd.?);

    const arg = simple.argv[1];
    try std.testing.expect(arg.parts[0] == .parameter);

    const param = arg.parts[0].parameter;
    try std.testing.expectEqualStrings("VAR", param.name);
    try std.testing.expect(param.modifier != null);
    try std.testing.expectEqual(lexer.ModifierOp.UseDefault, param.modifier.?.op);
    try std.testing.expect(param.modifier.?.check_null);
    try std.testing.expect(param.modifier.?.word != null);
    try std.testing.expectEqual(@as(usize, 1), param.modifier.?.word.?.len);
    try std.testing.expectEqualStrings("default", param.modifier.?.word.?[0].literal);
}

test "parseCommand: expansion without colon ${VAR-default}" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo ${VAR-default}");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);

    const simple = getFirstSimpleCommand(cmd.?);

    const param = simple.argv[1].parts[0].parameter;
    try std.testing.expectEqual(lexer.ModifierOp.UseDefault, param.modifier.?.op);
    try std.testing.expect(!param.modifier.?.check_null);
}

test "parseCommand: length expansion ${#VAR}" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo ${#VAR}");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);

    const simple = getFirstSimpleCommand(cmd.?);

    const arg = simple.argv[1];
    try std.testing.expect(arg.parts[0] == .parameter);

    const param = arg.parts[0].parameter;
    try std.testing.expectEqualStrings("VAR", param.name);
    try std.testing.expect(param.modifier != null);
    try std.testing.expectEqual(lexer.ModifierOp.Length, param.modifier.?.op);
    try std.testing.expect(param.modifier.?.word == null);
}

test "parseCommand: prefix removal ${VAR#pattern}" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo ${VAR#*.}");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);

    const simple = getFirstSimpleCommand(cmd.?);

    const param = simple.argv[1].parts[0].parameter;
    try std.testing.expectEqualStrings("VAR", param.name);
    try std.testing.expectEqual(lexer.ModifierOp.RemoveSmallestPrefix, param.modifier.?.op);
    try std.testing.expectEqualStrings("*.", param.modifier.?.word.?[0].literal);
}

test "parseCommand: suffix removal ${VAR%pattern}" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo ${VAR%.*}");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);

    const simple = getFirstSimpleCommand(cmd.?);

    const param = simple.argv[1].parts[0].parameter;
    try std.testing.expectEqualStrings("VAR", param.name);
    try std.testing.expectEqual(lexer.ModifierOp.RemoveSmallestSuffix, param.modifier.?.op);
    try std.testing.expectEqualStrings(".*", param.modifier.?.word.?[0].literal);
}

test "parseCommand: expansion in double quotes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo \"hello $VAR\"");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);

    const simple = getFirstSimpleCommand(cmd.?);

    const arg = simple.argv[1];
    try std.testing.expectEqual(@as(usize, 1), arg.parts.len);
    try std.testing.expect(arg.parts[0] == .double_quoted);

    const inner = arg.parts[0].double_quoted;
    try std.testing.expectEqual(@as(usize, 2), inner.len);
    try std.testing.expect(inner[0] == .literal);
    try std.testing.expectEqualStrings("hello ", inner[0].literal);
    try std.testing.expect(inner[1] == .parameter);
    try std.testing.expectEqualStrings("VAR", inner[1].parameter.name);
}

test "parseCommand: mixed literal and expansion" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo prefix${VAR}suffix");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);

    const simple = getFirstSimpleCommand(cmd.?);

    const arg = simple.argv[1];
    try std.testing.expectEqual(@as(usize, 3), arg.parts.len);
    try std.testing.expect(arg.parts[0] == .literal);
    try std.testing.expectEqualStrings("prefix", arg.parts[0].literal);
    try std.testing.expect(arg.parts[1] == .parameter);
    try std.testing.expectEqualStrings("VAR", arg.parts[1].parameter.name);
    try std.testing.expect(arg.parts[2] == .literal);
    try std.testing.expectEqualStrings("suffix", arg.parts[2].literal);
}

test "parseCommand: nested expansion ${VAR:-${OTHER}}" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo ${VAR:-${OTHER}}");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);

    const simple = getFirstSimpleCommand(cmd.?);

    const param = simple.argv[1].parts[0].parameter;
    try std.testing.expectEqualStrings("VAR", param.name);
    try std.testing.expectEqual(lexer.ModifierOp.UseDefault, param.modifier.?.op);

    // The word should contain a nested parameter expansion
    const word = param.modifier.?.word.?;
    try std.testing.expectEqual(@as(usize, 1), word.len);
    try std.testing.expect(word[0] == .parameter);
    try std.testing.expectEqualStrings("OTHER", word[0].parameter.name);
}

test "parseCommand: expansion in assignment value" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("FOO=$BAR");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.parseCommand();
    try std.testing.expect(cmd != null);

    const simple = getFirstSimpleCommand(cmd.?);

    try std.testing.expectEqual(@as(usize, 1), simple.assignments.len);
    try std.testing.expectEqualStrings("FOO", simple.assignments[0].name);

    const value = simple.assignments[0].value;
    try std.testing.expectEqual(@as(usize, 1), value.parts.len);
    try std.testing.expect(value.parts[0] == .parameter);
    try std.testing.expectEqualStrings("BAR", value.parts[0].parameter.name);
}

test "parseCommand: empty ${} is BadSubstitution error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo ${}");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const result = parser.parseCommand();
    try std.testing.expectError(error.BadSubstitution, result);

    // Verify error message
    const err_info = parser.getErrorInfo();
    try std.testing.expect(err_info != null);
    try std.testing.expectEqualStrings("bad substitution", err_info.?.message);
}

test "parseCommand: ${:-foo} missing parameter name is BadSubstitution" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo ${:-foo}");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const result = parser.parseCommand();
    try std.testing.expectError(error.BadSubstitution, result);

    const err_info = parser.getErrorInfo();
    try std.testing.expect(err_info != null);
    try std.testing.expectEqualStrings("bad substitution", err_info.?.message);
}

// --- Iterator interface tests (next()) ---

test "next: empty input returns null" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const result = try parser.next();
    try std.testing.expectEqual(null, result);
}

test "next: single command yields one Command then null" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo hello");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    // First call should yield the command
    const cmd1 = try parser.next();
    try std.testing.expect(cmd1 != null);

    const simple1 = getFirstSimpleCommand(cmd1.?);

    try std.testing.expectEqual(@as(usize, 2), simple1.argv.len);

    // Second call should yield null
    const cmd2 = try parser.next();
    try std.testing.expectEqual(null, cmd2);
}

test "next: multiple commands yields each in sequence" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo a; echo b; echo c");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    // Count commands
    var count: usize = 0;
    while (try parser.next()) |_| {
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), count);
}

test "next: skips empty commands" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // Use spaces between semicolons to avoid `;;` which is DoubleSemicolon
    var reader = std.io.Reader.fixed("; ; echo a ; ;");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    // Should yield exactly one command
    const cmd1 = try parser.next();
    try std.testing.expect(cmd1 != null);

    const cmd2 = try parser.next();
    try std.testing.expectEqual(null, cmd2);
}

test "next: returns Command union with simple variant" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("FOO=bar cmd arg");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.next();
    try std.testing.expect(cmd != null);

    // Verify it's a simple command with expected structure
    const simple = getFirstSimpleCommand(cmd.?);
    try std.testing.expectEqual(@as(usize, 1), simple.assignments.len);
    try std.testing.expectEqual(@as(usize, 2), simple.argv.len);
}

// --- ParsedCommand/AndOrList structure tests ---

test "ParsedCommand: accessing simple command through helpers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("cmd arg1 arg2");
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.next();
    try std.testing.expect(cmd != null);

    // Test access via payload.simple (the new pattern after refactoring)
    const simple = getFirstSimpleCommand(cmd.?);
    try std.testing.expectEqual(@as(usize, 3), simple.argv.len);
    try std.testing.expectEqualStrings("cmd", simple.argv[0].parts[0].literal);
    try std.testing.expectEqualStrings("arg1", simple.argv[1].parts[0].literal);
    try std.testing.expectEqualStrings("arg2", simple.argv[2].parts[0].literal);
}

test "ParsedCommand: accessing pipeline through and_or" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("echo hello");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const cmd = try parser_inst.next();
    try std.testing.expect(cmd != null);

    // Test accessing via the new and_or structure (pattern used by executor)
    const pipeline = cmd.?.and_or.items[0].pipeline;
    // For a single command, pipeline has one command
    try std.testing.expectEqual(@as(usize, 1), pipeline.commands.len);
    const simple = switch (pipeline.commands[0]) {
        .simple => |s| s,
        .if_clause => unreachable,
    };
    try std.testing.expectEqual(@as(usize, 2), simple.argv.len);
    try std.testing.expectEqualStrings("echo", simple.argv[0].parts[0].literal);
}

// --- WordCollector quote stack depth tests ---

test "WordCollector: deeply nested brace expansions at stack boundary" {
    // Test 7 levels of nested brace expansions (near the limit of 8)
    // ${a:-${b:-${c:-${d:-${e:-${f:-${g:-default}}}}}}}
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const input = "echo ${a:-${b:-${c:-${d:-${e:-${f:-${g:-default}}}}}}}";
    var reader = std.io.Reader.fixed(input);
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.next();
    try std.testing.expect(cmd != null);

    const simple = getFirstSimpleCommand(cmd.?);
    try std.testing.expectEqual(@as(usize, 2), simple.argv.len);
    try std.testing.expectEqualStrings("echo", simple.argv[0].parts[0].literal);

    // Verify the nested structure exists (we just check the outer parameter name)
    const param_part = simple.argv[1].parts[0];
    try std.testing.expect(param_part == .parameter);
    try std.testing.expectEqualStrings("a", param_part.parameter.name);
}

test "WordCollector: nested double quotes and brace expansions" {
    // Test alternating double quotes and brace expansions
    // "${a:-"${b:-"${c:-default}"}"}"
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // 3 levels of alternating: double quote -> brace -> double quote -> brace -> double quote -> brace
    const input = "echo \"${a:-\"${b:-inner}\"}\"";
    var reader = std.io.Reader.fixed(input);
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.next();
    try std.testing.expect(cmd != null);

    const simple = getFirstSimpleCommand(cmd.?);
    try std.testing.expectEqual(@as(usize, 2), simple.argv.len);

    // The second argument should be a double_quoted containing the nested expansion
    const arg1 = simple.argv[1];
    try std.testing.expectEqual(@as(usize, 1), arg1.parts.len);
    try std.testing.expect(arg1.parts[0] == .double_quoted);
}

test "WordCollector: maximum safe nesting depth (7 levels)" {
    // Test exactly 7 levels which is within the 8-slot stack
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // 7 nested brace expansions
    const input = "cmd ${1:-${2:-${3:-${4:-${5:-${6:-${7:-x}}}}}}}";
    var reader = std.io.Reader.fixed(input);
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.next();
    try std.testing.expect(cmd != null);

    const simple = getFirstSimpleCommand(cmd.?);
    try std.testing.expectEqual(@as(usize, 2), simple.argv.len);

    // Verify the outermost parameter
    const param_part = simple.argv[1].parts[0];
    try std.testing.expect(param_part == .parameter);
    try std.testing.expectEqualStrings("1", param_part.parameter.name);
    try std.testing.expect(param_part.parameter.modifier != null);
}

// --- popContext pointer validity tests ---

test "WordCollector: popContext pointer remains valid for immediate use" {
    // This test verifies the popContext API works correctly when the returned
    // pointer is used immediately (before any pushContext call)
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // Double quoted string with nested parameter - tests the popContext path
    const input = "\"${VAR:-default}\"";
    var reader = std.io.Reader.fixed(input);
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.next();
    try std.testing.expect(cmd != null);

    const simple = getFirstSimpleCommand(cmd.?);
    try std.testing.expectEqual(@as(usize, 1), simple.argv.len);

    // The word should be a double_quoted containing a parameter expansion
    const word = simple.argv[0];
    try std.testing.expectEqual(@as(usize, 1), word.parts.len);
    try std.testing.expect(word.parts[0] == .double_quoted);

    const inner = word.parts[0].double_quoted;
    try std.testing.expectEqual(@as(usize, 1), inner.len);
    try std.testing.expect(inner[0] == .parameter);
    try std.testing.expectEqualStrings("VAR", inner[0].parameter.name);
}

test "WordCollector: multiple sequential pop operations" {
    // Test that multiple pops in sequence work correctly (pop brace, then pop double quote)
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // This creates push(double) -> push(brace) -> pop(brace) -> pop(double) sequence
    const input = "\"before${VAR}after\"";
    var reader = std.io.Reader.fixed(input);
    var lex = lexer.Lexer.init(&reader);
    var parser = Parser.init(arena.allocator(), &lex);

    const cmd = try parser.next();
    try std.testing.expect(cmd != null);

    const simple = getFirstSimpleCommand(cmd.?);
    try std.testing.expectEqual(@as(usize, 1), simple.argv.len);

    const word = simple.argv[0];
    try std.testing.expectEqual(@as(usize, 1), word.parts.len);
    try std.testing.expect(word.parts[0] == .double_quoted);

    // Should have: literal "before", parameter VAR, literal "after"
    const inner = word.parts[0].double_quoted;
    try std.testing.expectEqual(@as(usize, 3), inner.len);
    try std.testing.expect(inner[0] == .literal);
    try std.testing.expectEqualStrings("before", inner[0].literal);
    try std.testing.expect(inner[1] == .parameter);
    try std.testing.expectEqualStrings("VAR", inner[1].parameter.name);
    try std.testing.expect(inner[2] == .literal);
    try std.testing.expectEqualStrings("after", inner[2].literal);
}

// --- Pipeline tests ---

test "parseCommand: negated simple command" {
    var reader = std.io.Reader.fixed("! echo hello\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try std.testing.expect(result != null);
    const pipeline = getPipeline(result.?);
    try std.testing.expect(pipeline.negated);
}

test "parseCommand: simple pipeline" {
    var reader = std.io.Reader.fixed("echo | cat\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try std.testing.expect(result != null);

    const pipeline = getPipeline(result.?);
    try std.testing.expect(!pipeline.negated);
    try std.testing.expectEqual(@as(usize, 2), pipeline.commands.len);
}

test "parseCommand: negated pipeline" {
    var reader = std.io.Reader.fixed("! echo | cat\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try std.testing.expect(result != null);

    const pipeline = getPipeline(result.?);
    try std.testing.expect(pipeline.negated);
    try std.testing.expectEqual(@as(usize, 2), pipeline.commands.len);
}

test "parseCommand: three-stage pipeline" {
    var reader = std.io.Reader.fixed("a | b | c\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try std.testing.expect(result != null);

    const pipeline = getPipeline(result.?);
    try std.testing.expectEqual(@as(usize, 3), pipeline.commands.len);
}

test "parseCommand: pipeline with newline continuation" {
    // POSIX allows newlines after pipes to continue the command on the next line.
    var reader = std.io.Reader.fixed("echo |\ncat\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try std.testing.expect(result != null);

    const pipeline = getPipeline(result.?);
    try std.testing.expectEqual(@as(usize, 2), pipeline.commands.len);
}

test "parseCommand: pipe semicolon error" {
    var reader = std.io.Reader.fixed("echo |;\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = parser_inst.parseCommand();
    try std.testing.expectError(ParseError.UnsupportedSyntax, result);
}

test "parseCommand: pipe at start error" {
    var reader = std.io.Reader.fixed("| echo\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = parser_inst.parseCommand();
    try std.testing.expectError(ParseError.UnsupportedSyntax, result);
}

test "parseCommand: bang in word is not negation" {
    var reader = std.io.Reader.fixed("!echo hello\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try std.testing.expect(result != null);

    const simple = getFirstSimpleCommand(result.?);
    try std.testing.expectEqual(@as(usize, 2), simple.argv.len);
    try expectWord(simple.argv[0], &.{.{ .literal = "!echo" }});
    try expectWord(simple.argv[1], &.{.{ .literal = "hello" }});
}

test "parseCommand: bang from would-be expansion position" {
    var reader = std.io.Reader.fixed("echo !\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try std.testing.expect(result != null);

    const simple = getFirstSimpleCommand(result.?);
    try std.testing.expectEqual(@as(usize, 2), simple.argv.len);
    try expectWord(simple.argv[0], &.{.{ .literal = "echo" }});
    try expectWord(simple.argv[1], &.{.{ .literal = "!" }});
}

test "parseCommand: bang alone without newline is negated empty pipeline" {
    // This tests the saw_bang state handling EOF
    var reader = std.io.Reader.fixed("!");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try std.testing.expect(result != null);

    const pipeline = getPipeline(result.?);
    try std.testing.expect(pipeline.negated);
    try std.testing.expectEqual(@as(usize, 0), pipeline.commands.len);
}

test "parseCommand: bang with newline is negated empty pipeline" {
    var reader = std.io.Reader.fixed("!\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try std.testing.expect(result != null);

    const pipeline = getPipeline(result.?);
    try std.testing.expect(pipeline.negated);
    try std.testing.expectEqual(@as(usize, 0), pipeline.commands.len);
}

test "parseCommand: double bang is double negation (valid command)" {
    var reader = std.io.Reader.fixed("! !");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    // Double negation cancels out - still a valid command (empty pipeline, negated=false)
    // This is valid because `!` tokens were seen, so it's not "truly empty"
    try std.testing.expect(result != null);
    const pipeline = getPipeline(result.?);
    try std.testing.expectEqual(@as(usize, 0), pipeline.commands.len);
    try std.testing.expect(!pipeline.negated); // Double negation = false
}

test "parseCommand: bang followed by quote is command name" {
    // !"foo" should parse as command named !foo, not negation
    var reader = std.io.Reader.fixed("!\"foo\"\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try std.testing.expect(result != null);

    const pipeline = getPipeline(result.?);
    try std.testing.expect(!pipeline.negated);
    try std.testing.expectEqual(@as(usize, 1), pipeline.commands.len);

    const simple = switch (pipeline.commands[0]) {
        .simple => |s| s,
        .if_clause => unreachable,
    };
    try std.testing.expectEqual(@as(usize, 1), simple.argv.len);
    // Word should have "!" literal part and "foo" quoted part
    try std.testing.expectEqual(@as(usize, 2), simple.argv[0].parts.len);
    try std.testing.expect(simple.argv[0].parts[0] == .literal);
    try std.testing.expectEqualStrings("!", simple.argv[0].parts[0].literal);
    try std.testing.expect(simple.argv[0].parts[1] == .double_quoted);
}

test "parseCommand: bang followed by expansion is command name" {
    // !$var should parse as command with ! prefix and expansion, not negation
    var reader = std.io.Reader.fixed("!$var\n");
    var lex = lexer.Lexer.init(&reader);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try std.testing.expect(result != null);

    const pipeline = getPipeline(result.?);
    try std.testing.expect(!pipeline.negated);
    try std.testing.expectEqual(@as(usize, 1), pipeline.commands.len);

    const simple = switch (pipeline.commands[0]) {
        .simple => |s| s,
        .if_clause => unreachable,
    };
    try std.testing.expectEqual(@as(usize, 1), simple.argv.len);
    // Word should have "!" literal part and parameter expansion part
    try std.testing.expectEqual(@as(usize, 2), simple.argv[0].parts.len);
    try std.testing.expect(simple.argv[0].parts[0] == .literal);
    try std.testing.expectEqualStrings("!", simple.argv[0].parts[0].literal);
    try std.testing.expect(simple.argv[0].parts[1] == .parameter);
}

test "parseCommand: simple && produces AndOrList with And" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("foo && bar\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = (try parser_inst.parseCommand()).?;
    try std.testing.expectEqual(@as(usize, 2), result.and_or.items.len);
    try std.testing.expectEqual(AndOrOp.And, result.and_or.items[0].trailing_op.?);
    try std.testing.expectEqual(@as(?AndOrOp, null), result.and_or.items[1].trailing_op);
}

test "parseCommand: simple || produces AndOrList with Or" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("foo || bar\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = (try parser_inst.parseCommand()).?;
    try std.testing.expectEqual(@as(usize, 2), result.and_or.items.len);
    try std.testing.expectEqual(AndOrOp.Or, result.and_or.items[0].trailing_op.?);
    try std.testing.expectEqual(@as(?AndOrOp, null), result.and_or.items[1].trailing_op);
}

test "parseCommand: chained && operators" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("a && b && c\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = (try parser_inst.parseCommand()).?;
    try std.testing.expectEqual(@as(usize, 3), result.and_or.items.len);
    try std.testing.expectEqual(AndOrOp.And, result.and_or.items[0].trailing_op.?);
    try std.testing.expectEqual(AndOrOp.And, result.and_or.items[1].trailing_op.?);
    try std.testing.expectEqual(@as(?AndOrOp, null), result.and_or.items[2].trailing_op);
}

test "parseCommand: mixed && and ||" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("a && b || c && d\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = (try parser_inst.parseCommand()).?;
    try std.testing.expectEqual(@as(usize, 4), result.and_or.items.len);
    try std.testing.expectEqual(AndOrOp.And, result.and_or.items[0].trailing_op.?);
    try std.testing.expectEqual(AndOrOp.Or, result.and_or.items[1].trailing_op.?);
    try std.testing.expectEqual(AndOrOp.And, result.and_or.items[2].trailing_op.?);
    try std.testing.expectEqual(@as(?AndOrOp, null), result.and_or.items[3].trailing_op);
}

test "parseCommand: pipeline then &&" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("a | b && c\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = (try parser_inst.parseCommand()).?;
    try std.testing.expectEqual(@as(usize, 2), result.and_or.items.len);
    // First pipeline has 2 commands
    try std.testing.expectEqual(@as(usize, 2), result.and_or.items[0].pipeline.commands.len);
    try std.testing.expectEqual(AndOrOp.And, result.and_or.items[0].trailing_op.?);
    // Second pipeline has 1 command
    try std.testing.expectEqual(@as(usize, 1), result.and_or.items[1].pipeline.commands.len);
}

test "parseCommand: && at start is syntax error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("&& foo\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    try std.testing.expectError(ParseError.UnsupportedSyntax, parser_inst.parseCommand());
}

test "parseCommand: || at start is syntax error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("|| foo\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    try std.testing.expectError(ParseError.UnsupportedSyntax, parser_inst.parseCommand());
}

test "parseCommand: && at end (EOF) is syntax error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("foo &&");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    try std.testing.expectError(ParseError.UnexpectedEndOfInput, parser_inst.parseCommand());
}

test "parseCommand: && followed by ; is syntax error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("foo && ;\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    try std.testing.expectError(ParseError.UnsupportedSyntax, parser_inst.parseCommand());
}

test "parseCommand: && followed by && is syntax error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("foo && && bar\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    try std.testing.expectError(ParseError.UnsupportedSyntax, parser_inst.parseCommand());
}

test "parseCommand: newline continuation after &&" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("foo &&\nbar\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = (try parser_inst.parseCommand()).?;
    try std.testing.expectEqual(@as(usize, 2), result.and_or.items.len);
}

test "parseCommand: ! || cmd is syntax error (empty pipeline before operator)" {
    // `!` alone is valid as a complete command, but an empty pipeline
    // (no commands) cannot precede an operator.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("! || echo yes\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    try std.testing.expectError(ParseError.UnsupportedSyntax, parser_inst.parseCommand());
}

test "parseCommand: cmd && ! is valid (negated empty pipeline at end)" {
    // `!` alone is valid, so `cmd && !` should be valid too.
    // The `!` at the end doesn't precede an operator, so it's allowed.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("true && !\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = (try parser_inst.parseCommand()).?;
    try std.testing.expectEqual(@as(usize, 2), result.and_or.items.len);
    // Second pipeline: ! (negated, empty)
    try std.testing.expect(result.and_or.items[1].pipeline.negated);
    try std.testing.expectEqual(@as(usize, 0), result.and_or.items[1].pipeline.commands.len);
}

test "parseCommand: cmd && ! ! is valid (double negation at end)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("true && ! !\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = (try parser_inst.parseCommand()).?;
    try std.testing.expectEqual(@as(usize, 2), result.and_or.items.len);
    // Second pipeline: ! ! (double negation = not negated, empty)
    try std.testing.expect(!result.and_or.items[1].pipeline.negated);
    try std.testing.expectEqual(@as(usize, 0), result.and_or.items[1].pipeline.commands.len);
}

test "parseCommand: & terminates and_or list (background not yet executed)" {
    // Background execution (&) is not yet implemented in executor,
    // but parser should accept it as a list terminator.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("foo &");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    // Should parse successfully - & terminates the and_or list
    const result = (try parser_inst.parseCommand()).?;
    try std.testing.expectEqual(@as(usize, 1), result.and_or.items.len);
}

test "parseCommand: semicolon terminates and_or list" {
    // "a && b; c" should parse as two separate commands
    // First parseCommand: a && b
    // Second parseCommand: c
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("a && b; c\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    // First command: a && b
    const result1 = (try parser_inst.parseCommand()).?;
    try std.testing.expectEqual(@as(usize, 2), result1.and_or.items.len);
    try std.testing.expectEqual(AndOrOp.And, result1.and_or.items[0].trailing_op.?);

    // Second command: c
    const result2 = (try parser_inst.parseCommand()).?;
    try std.testing.expectEqual(@as(usize, 1), result2.and_or.items.len);
}

// --- If statement tests ---

/// Helper to extract the first IfClause from a ParsedCommand.
fn getFirstIfClause(cmd: ParsedCommand) IfClause {
    return switch (getPipeline(cmd).commands[0]) {
        .if_clause => |ic| ic,
        .simple => unreachable,
    };
}

test "parseCommand: simple if statement" {
    // if true; then echo yes; fi
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("if true; then echo yes; fi\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    // Use next() like dumpAst does
    const result = try parser_inst.next();
    try std.testing.expect(result != null);

    const ic = getFirstIfClause(result.?);

    // Should have exactly 1 branch (the if branch)
    try std.testing.expectEqual(@as(usize, 1), ic.branches.len);
    // No else body
    try std.testing.expect(ic.else_body == null);

    // Condition should have 1 and_or list with "true"
    try std.testing.expectEqual(@as(usize, 1), ic.branches[0].condition.commands.len);
    // Body should have 1 and_or list with "echo yes"
    try std.testing.expectEqual(@as(usize, 1), ic.branches[0].body.commands.len);

    // After the if statement, next() should return null (no more commands)
    const next_result = try parser_inst.next();
    try std.testing.expect(next_result == null);
}

test "parseCommand: simple if statement (no trailing newline)" {
    // Tests that parsing "if ... fi" without a trailing newline works correctly.
    // This is the scenario used by --dump-ast mode.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const command_line = "if true; then echo yes; fi";

    var reader = std.io.Reader.fixed(command_line);
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    var command_count: usize = 0;
    while (try parser_inst.next()) |_| {
        command_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), command_count);
}

test "parseCommand: if-else statement" {
    // if false; then echo a; else echo b; fi
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("if false; then echo a; else echo b; fi\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try std.testing.expect(result != null);

    const ic = getFirstIfClause(result.?);

    // Should have exactly 1 branch
    try std.testing.expectEqual(@as(usize, 1), ic.branches.len);
    // Should have else body
    try std.testing.expect(ic.else_body != null);
    try std.testing.expectEqual(@as(usize, 1), ic.else_body.?.commands.len);
}

test "parseCommand: if-elif statement" {
    // if false; then echo 1; elif true; then echo 2; fi
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("if false; then echo 1; elif true; then echo 2; fi\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try std.testing.expect(result != null);

    const ic = getFirstIfClause(result.?);

    // Should have 2 branches (if + elif)
    try std.testing.expectEqual(@as(usize, 2), ic.branches.len);
    // No else body
    try std.testing.expect(ic.else_body == null);
}

test "parseCommand: if-elif-else statement" {
    // if false; then echo 1; elif false; then echo 2; else echo 3; fi
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("if false; then echo 1; elif false; then echo 2; else echo 3; fi\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try std.testing.expect(result != null);

    const ic = getFirstIfClause(result.?);

    // Should have 2 branches
    try std.testing.expectEqual(@as(usize, 2), ic.branches.len);
    // Should have else body
    try std.testing.expect(ic.else_body != null);
}

test "parseCommand: if with multiple commands in condition" {
    // if echo a; echo b; then echo c; fi
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("if echo a; echo b; then echo c; fi\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try std.testing.expect(result != null);

    const ic = getFirstIfClause(result.?);

    // Condition should have 2 and_or lists
    try std.testing.expectEqual(@as(usize, 2), ic.branches[0].condition.commands.len);
}

test "parseCommand: if with multiple commands in body" {
    // if true; then echo a; echo b; fi
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("if true; then echo a; echo b; fi\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try std.testing.expect(result != null);

    const ic = getFirstIfClause(result.?);

    // Body should have 2 and_or lists
    try std.testing.expectEqual(@as(usize, 2), ic.branches[0].body.commands.len);
}

test "parseCommand: nested if statement" {
    // if true; then if true; then echo nested; fi; fi
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("if true; then if true; then echo nested; fi; fi\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try std.testing.expect(result != null);

    const ic = getFirstIfClause(result.?);

    // Outer if has 1 branch
    try std.testing.expectEqual(@as(usize, 1), ic.branches.len);
    // Body has 1 command which is another if_clause
    try std.testing.expectEqual(@as(usize, 1), ic.branches[0].body.commands.len);
    const body_pipeline = ic.branches[0].body.commands[0].items[0].pipeline;
    try std.testing.expectEqual(@as(usize, 1), body_pipeline.commands.len);
    try std.testing.expect(body_pipeline.commands[0] == .if_clause);
}

test "parseCommand: quoted 'then' is not reserved word" {
    // if 'then'; then echo yes; fi - 'then' is quoted so it's a command
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("if 'then'; then echo yes; fi\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try std.testing.expect(result != null);

    const ic = getFirstIfClause(result.?);

    // Condition should contain the command 'then'
    try std.testing.expectEqual(@as(usize, 1), ic.branches[0].condition.commands.len);
}

test "parseCommand: if with newlines" {
    // Multi-line if statement
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("if true\nthen\necho yes\nfi\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try std.testing.expect(result != null);

    const ic = getFirstIfClause(result.?);
    try std.testing.expectEqual(@as(usize, 1), ic.branches.len);
}

test "parseCommand: if then (no condition) is syntax error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("if then echo yes; fi\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = parser_inst.parseCommand();
    try std.testing.expectError(ParseError.UnsupportedSyntax, result);
    const err = parser_inst.getErrorInfo();
    try std.testing.expect(err != null);
    try std.testing.expectEqualStrings("syntax error: expected command before 'then'", err.?.message);
}

test "parseCommand: if without fi is syntax error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("if true; then echo yes\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = parser_inst.parseCommand();
    try std.testing.expectError(ParseError.UnexpectedEndOfInput, result);
}

test "parseCommand: if with empty body is syntax error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("if true; then fi\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = parser_inst.parseCommand();
    try std.testing.expectError(ParseError.UnsupportedSyntax, result);
}

test "parseCommand: fi at root level is regular command" {
    // Reserved words like 'fi' are only recognized inside their respective
    // compound commands. At root level (not inside an if_clause), 'fi' is
    // treated as a regular command name.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("fi\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try std.testing.expect(result != null);
    // It's a simple command with argv[0] = "fi"
    const simple = getFirstSimpleCommand(result.?);
    try std.testing.expectEqual(@as(usize, 1), simple.argv.len);
    try std.testing.expectEqualStrings("fi", simple.argv[0].parts[0].literal);
}

test "parseCommand: assignment before then is valid condition" {
    // if FOO=bar; then echo $FOO; fi
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var reader = std.io.Reader.fixed("if FOO=bar; then echo yes; fi\n");
    var lex = lexer.Lexer.init(&reader);
    var parser_inst = Parser.init(arena.allocator(), &lex);

    const result = try parser_inst.parseCommand();
    try std.testing.expect(result != null);

    const ic = getFirstIfClause(result.?);
    try std.testing.expectEqual(@as(usize, 1), ic.branches.len);
}
