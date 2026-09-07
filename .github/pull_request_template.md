## What this changes

<!-- What the change does, and why. Link the issue it closes. -->

## Rule impact

<!--
Does this change what zghalint reports on an unchanged workflow? If so, name
the rule IDs and say which way. A previously green CI run turning red is a
breaking change for users, and belongs in CHANGELOG.md.
Write "none" if the reported diagnostics are unchanged.
-->

none

## Checks

- [ ] `zig build`
- [ ] `zig fmt --check src/ build.zig`
- [ ] `zig build test --summary all`
- [ ] `docs/rules.md` updated if a rule was added, removed, or changed
- [ ] `CHANGELOG.md` updated under `## [Unreleased]` if this is user-visible
