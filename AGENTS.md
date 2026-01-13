# AGENTS.md - tsh

This file provides guidance for AI coding agents working in this repository.

## Project Overview

tsh is a POSIX shell implementation written in Zig. It implements shell features
per POSIX.1-2017, including lexing, parsing, word expansion, and command execution.

- **Language**: Zig 0.15.2+ (uses master from zig-overlay)
- **Dependencies**: Links libc for POSIX functions (getpid, fork, exec, etc.)
- **Dev Environment**: Nix flake provides zig and zls

## Build Commands

```bash
# Build the project
zig build

# Build with optimizations
zig build -Doptimize=ReleaseSafe

# Run the shell
zig build run

# Run with arguments
zig build run -- -c "echo hello"
zig build run -- script.sh

# Run all tests
zig build test

# Debug output modes
zig build run -- --dump-tokens < script.sh
zig build run -- --dump-ast < script.sh
```

### Running a Single Test

Zig's build system runs all tests together. To run tests from a specific file,
you can compile and run tests directly:

```bash
# Run tests for a specific module (compiles and runs in one step)
zig test src/lexer.zig --dep tsh -Mroot=src/root.zig
```

Note: Zig does not support filtering tests by name. To isolate a test, temporarily
comment out other tests or use a conditional compilation approach.

## Project Structure

```
src/
├── root.zig        # Library entry point, re-exports public API
├── main.zig        # CLI entry point, argument parsing
├── lexer.zig       # Tokenizer (streaming, handles quoting/escapes)
├── parser.zig      # AST construction (SimpleCommand, IfClause, etc.)
├── executor.zig    # Command execution (fork/exec, redirections, pipes)
├── expand.zig      # Word expansion (tilde, parameter, globbing)
├── state.zig       # Shell state (env, variables, exit status, cwd)
├── builtins.zig    # Builtin commands (cd, exit, export, pwd, test)
├── options.zig     # POSIX-compliant option parsing framework
├── builtin_test.zig # test/[ expression evaluator
├── pattern.zig     # Pattern matching for glob and parameter expansion
└── repl.zig        # Read-eval-print loop
```

## Code Style Guidelines

### Imports

Order imports: standard library, project modules, then type aliases.

```zig
const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;

const parser = @import("parser.zig");
const state = @import("state.zig");
const ShellState = state.ShellState;
const printError = state.printError;
```

### Naming Conventions

| Kind          | Convention          | Examples                              |
|---------------|---------------------|---------------------------------------|
| Types/Structs | PascalCase          | `ShellState`, `TokenType`, `Word`     |
| Functions     | camelCase           | `nextToken`, `getVariable`, `runCd`   |
| Constants     | SCREAMING_SNAKE     | `DEFAULT_PS1`, `SUCCESS`, `NOT_FOUND` |
| Variables     | snake_case          | `exit_code`, `last_status`            |
| Enum variants | Context-dependent   | `.Literal`, `.exited`, `.str_equal`   |

Use `@"keyword"` syntax for reserved words as identifiers:
```zig
pub const Builtin = enum {
    @"break",
    @"continue",
    @"export",
    // ...
};
```

### Types and Patterns

Use tagged unions for discriminated types:
```zig
pub const ExitStatus = union(enum) {
    exited: u8,
    signaled: u32,
};

pub const BuiltinResult = union(enum) {
    exit_code: u8,
    exit: u8,
    break_loop: u32,
    builtin_error: u8,
};
```

Define module-specific error sets:
```zig
pub const LexerError = error{
    UnexpectedEndOfFile,
    UnterminatedQuote,
    // ...
};

pub const ExecuteError = error{
    ForkFailed,
    CommandNotFound,
    // ...
} || Allocator.Error;
```

### Error Handling

- Use `printError` from `state.zig` for user-facing errors (prefixes with "tsh: ")
- Return structured error info when context is needed
- Prefer explicit error handling over `try` for user-facing code

```zig
// User-facing error
printError("{s}: {s}: No such file or directory\n", .{ name, path });
return .{ .exit_code = 1 };

// Internal error propagation
const value = try self.allocator.dupe(u8, input);
```

### Memory Management

- Use `ArenaAllocator` for parse-time allocations (freed in batch)
- Pass `Allocator` explicitly to functions that allocate
- Use `defer` for cleanup and document ownership in comments
- `EnvMap.put()` duplicates values internally; shell variables need manual duping

### Documentation

Reference POSIX sections in doc comments:
```zig
/// Exit the shell with status n.
///
/// POSIX Reference: Section 2.14.1 - exit
fn runExit(args: []const []const u8, shell: *ShellState) BuiltinResult {
```

Use `//!` for module-level docs at file top, `///` for public API.

### Testing

Tests go at the bottom of each file with descriptive names:
```zig
test "ShellState: setEnv updates cached home" {
    var env = process.EnvMap.init(std.testing.allocator);
    var state = try ShellState.initWithEnv(std.testing.allocator, &env);
    defer state.deinit();

    try std.testing.expect(state.home == null);
    try state.setEnv("HOME", "/new/home");
    try std.testing.expectEqualStrings("/new/home", state.home.?);
}
```

Use helper functions prefixed with `run*Test` or `expect*` for complex setups.

### Commit Messages

Format: `type(scope): description`

- **feat**: New feature (`feat(executor): add if statement execution support`)
- **fix**: Bug fix (`fix: resolve test failures on Linux`)
- **refactor**: Code restructuring (`refactor(parser): reorganize token dispatch`)
- **test**: Test additions/changes
- **docs**: Documentation updates

## Architecture Notes

- **Lexer**: Streaming reader with small buffer, produces tokens incrementally
  - It is important when changing the lexer that potential buffer boundary
    issues are considered.
- **Parser**: Consumes tokens, builds AST using labeled switch state machine
  - The parser should be invariant on the buffer size for the lexer.
- **Executor**: Handles fork/exec, pipes, redirections; builtins run in-process
- **State**: Persists env vars, shell vars, cwd, exit status between commands
- **Expand**: Processes words through tilde, parameter, and glob expansion phases

Builtins that modify shell state (cd, export, exit) must run in the shell
process, not forked children. The `BuiltinResult` union signals control flow
(exit, break, continue) back to the executor.
