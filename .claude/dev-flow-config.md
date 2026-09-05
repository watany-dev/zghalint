# Dev Flow — zghalint Project Config

> Loaded by autopilot `dev-flow` when working in the zghalint repository.

## Size Rules

- **S**: single rule or small module change, no public API change → direct commit on a feature branch
- **L**: 3+ modules, new rule category, parser change, or design doc required → plan + phased commits + PR
- **Fix**: bug fix in existing behavior → fix branch, PR to `main`

## Quality Gate

Before considering any task complete, run:

```bash
zig build && zig fmt --check src/ build.zig && zig build test --summary all
```

- **S**: full CI above before commit
- **L**: full CI per phase, review before merge

## Build & Deploy

- **Build**: `zig build`
- **Format check**: `zig fmt --check src/ build.zig`
- **Auto-format**: `zig fmt src/ build.zig`
- **Test**: `zig build test --summary all`
- **Run**: `zig build run -- [workflow files]`
- **Prerequisite**: Zig 0.15.2 or later

## Project Paths

- **Design docs**: `docs/design/*.md`
- **Roadmap**: `docs/ROADMAP.md`
- **Requirements**: `docs/requirements.md`
- **Rules reference**: `docs/rules.md`
- **ADR**: `docs/adr/`
- **E2E fixtures**: `tests/fixtures/e2e/`
- **Agent guidance**: `AGENTS.md`, `CLAUDE.md`

## Branch Rules

- **Default branch**: `main`
- **Feature branches**: project convention (e.g. `cursor/<descriptive-name>-<suffix>`)

## Pre-Work Gates

```bash
git fetch origin
git status
```

## Post-Work Commands

```bash
zig build && zig fmt --check src/ build.zig && zig build test --summary all
```

## Docs Sync (session end)

Check for staleness when design or behavior changed:

- Relevant `docs/design/*.md` sections
- `docs/rules.md` when rule IDs or severities change
- `AGENTS.md` / `CLAUDE.md` when CLI options or architecture shift

## zghalint-Specific Rules

- Zero external dependencies — do not add third-party libraries
- YAML parser and workflow parser are in-house; match existing patterns in `src/yaml/` and `src/workflow/`
- Separate structural tidying commits from behavioral changes when practical
- Each iteration should finish with passing CI before moving on
