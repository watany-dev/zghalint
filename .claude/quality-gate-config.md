# Quality Gate — zghalint Project Config

> Loaded by autopilot `quality-pipeline` when working in the zghalint repository.

## Test Command

```bash
zig build test --summary all
```

## Build Command

```bash
zig build
```

## Scan Command

```bash
zig fmt --check src/ build.zig
```

## Full CI (pre-commit / task completion)

```bash
zig build && zig fmt --check src/ build.zig && zig build test --summary all
```

## Code Review

Primary: dispatch `autopilot:reviewer`.

For over-engineering review on diffs, also consider the repo's `ponytail-review` skill.

## Route Overrides

- **S**: format check → test → review
- **L**: build → format check → test per phase → review before merge
- **hotfix**: test → review only (format check still required before merge)
