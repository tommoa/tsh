//! tsh - A POSIX shell implementation in Zig.
//!
//! This module re-exports the lexer, parser, executor, and state for library consumers.

pub const lexer = @import("lexer.zig");
pub const parser = @import("parser.zig");
pub const executor = @import("executor.zig");
pub const state = @import("state.zig");
pub const repl = @import("repl.zig");

// Re-export commonly used types at the top level for convenience
pub const Lexer = lexer.Lexer;
pub const Token = lexer.Token;
pub const TokenType = lexer.TokenType;
pub const LexerError = lexer.LexerError;
pub const Redirection = lexer.Redirection;

pub const Parser = parser.Parser;
pub const ParseError = parser.ParseError;
pub const SimpleCommand = parser.SimpleCommand;
pub const Word = parser.Word;
pub const WordPart = parser.WordPart;
pub const Assignment = parser.Assignment;
pub const ParsedRedirection = parser.ParsedRedirection;

pub const Executor = executor.Executor;
pub const ExecuteError = executor.ExecuteError;

pub const ShellState = state.ShellState;
pub const ShellOptions = state.ShellOptions;
pub const ProcessingMode = state.ProcessingMode;
pub const ExitStatus = state.ExitStatus;

test {
    @import("std").testing.refAllDecls(@This());
}
