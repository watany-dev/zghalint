# Security Policy

zghalint is a security tool: it reports supply-chain and injection risks in
GitHub Actions workflows, and it ships rule data about known-vulnerable
actions. A defect in zghalint can therefore hide a real vulnerability from
its users, not just misbehave. Reports about zghalint itself are welcome.

## Supported Versions

zghalint is pre-1.0. Only the latest release receives security fixes; there
are no maintained backport branches.

| Version | Supported |
|---------|-----------|
| latest release | ✅ |
| older releases | ❌ |

## Reporting a Vulnerability

**Do not open a public issue for a security report.**

Use GitHub's private vulnerability reporting:
[Report a vulnerability](https://github.com/watany-dev/zghalint/security/advisories/new).
The report stays private until an advisory is published.

Please include:

- What the problem is, and which version or commit you observed it on
- A minimal workflow file or input that reproduces it
- What zghalint did, and what it should have done

### What counts as a security issue

- **A missed detection** — a workflow that is genuinely vulnerable (script
  injection, `pull_request_target` misuse, a compromised action ref) that
  zghalint reports as clean. A user relying on a green run is exposed.
- **A parser defect reachable from input** — a crash, hang, unbounded memory
  growth, or out-of-bounds access triggered by a `.yml` file. zghalint is run
  in CI against attacker-influenced branches.
- **Anything that lets a scanned workflow affect the machine running
  zghalint** — file writes outside the target paths (including via `--fix`),
  command execution, or exfiltration through the network lookups used by the
  SC rules.
- **A defect in the distribution path** — the release archives, `SHA256SUMS`,
  or `action.yml`'s download-and-verify step.

A false positive, or a rule you disagree with, is a normal bug: open a public
issue for it.

## Response

This is a small project maintained in spare time. Expect an initial reply
within 7 days. If you have not heard back in that window, please ping the
advisory thread — reports do not go stale on purpose.

Fixes are released as a new version with an advisory describing the impact
and the affected versions. Reporters are credited unless they ask not to be.
