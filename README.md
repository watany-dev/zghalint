# zghalint

A comprehensive, fast GitHub Actions workflow linter written in Zig.

## Features

- **Security**: Detect script injection, unpinned actions, hardcoded secrets, dangerous triggers
- **Performance**: Missing caching, redundant steps, matrix optimization
- **Best Practices**: Timeouts, naming, permissions, concurrency
- **Expression Validation**: `${{ }}` syntax checking, context access, function validation
- **Multiple Output Formats**: Terminal (with colors), JSON, SARIF (for GitHub Code Scanning)

## Requirements

- Zig 0.14.0 or later

## Build

```bash
zig build
```

## Run

```bash
# Lint workflow files
zig build run -- .github/workflows/*.yml

# Or use the built binary directly
./zig-out/bin/zghalint .github/workflows/*.yml
```

## Test

```bash
zig build test
```

## Format

```bash
# Check formatting
zig fmt --check src/ build.zig

# Auto-format
zig fmt src/ build.zig
```

## License

Apache License 2.0
