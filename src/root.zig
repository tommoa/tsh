//! tsh - A POSIX shell implementation in Zig.
//!
//! This module re-exports the lexer and parser for library consumers.

pub const lexer = @import("lexer.zig");
pub const parser = @import("parser.zig");

// Re-export commonly used types at the top level for convenience
pub const Lexer = lexer.Lexer;
pub const Token = lexer.Token;
pub const TokenType = lexer.TokenType;
pub const LexerError = lexer.LexerError;
pub const Redirection = lexer.Redirection;
pub const RedirectionOp = lexer.RedirectionOp;

pub const Parser = parser.Parser;
pub const ParseError = parser.ParseError;
pub const SimpleCommand = parser.SimpleCommand;
pub const Word = parser.Word;
pub const WordPart = parser.WordPart;
pub const Assignment = parser.Assignment;
pub const ParsedRedirection = parser.ParsedRedirection;

test {
    @import("std").testing.refAllDecls(@This());
}
