# Rules Reference

zghalint includes **47 rules** across 8 categories to help you write secure, efficient, and maintainable GitHub Actions workflows.

## Severity Levels

| Level | Description |
|-------|-------------|
| error | Must fix — likely a security vulnerability or broken workflow |
| warning | Should fix — potential issue or bad practice |
| info | Consider fixing — suggestion for improvement |

---

## Security Rules (SEC)

Detect security vulnerabilities in workflow definitions.

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SEC001 | unpinned-action | warning | Action references should be pinned to a full SHA |
| SEC002 | script-injection | error | Untrusted GitHub context used in `run:` block risks script injection |
| SEC003 | hardcoded-secret | error | Hardcoded secrets should use GitHub Secrets |
| SEC004 | excessive-permissions | warning | Avoid write-all permissions, specify only needed scopes |
| SEC005 | dangerous-pr-target | error | `pull_request_target` with checkout of PR head is dangerous |
| SEC006 | untrusted-input-condition | error | Untrusted context in `if:` condition expression |
| SEC007 | missing-permissions | info | Workflow should define top-level permissions |
| SEC008 | github-env-injection | error | Untrusted input written to `GITHUB_ENV`/`GITHUB_PATH` risks environment injection |
| SEC009 | workflow-run-untrusted-checkout | error | `workflow_run` job checks out a ref from the triggering workflow, which may allow arbitrary code execution from forks |
| SEC010 | secrets-inherit | warning | Reusable workflow calls should specify secrets explicitly instead of using `inherit` |
| SEC011 | overprovisioned-secrets | warning | Entire secrets context should not be exposed; reference individual secrets instead |
| SEC012 | unredacted-secrets | error | Secrets processed via `toJSON()`/`fromJSON()` bypass masking and may be exposed in logs |
| SEC013 | hardcoded-container-credentials | error | Container credentials should use GitHub Secrets, not plaintext values |
| SEC014 | bot-conditions | warning | Bot account checks using `github.actor` are spoofable |
| SEC015 | artipacked | warning | Checkout with persisted credentials followed by `upload-artifact` can leak `GITHUB_TOKEN` |
| SEC016 | cache-poisoning | warning | Cache usage in release/deploy workflows risks cache poisoning attacks |
| SEC017 | insecure-commands | warning | `ACTIONS_ALLOW_UNSECURE_COMMANDS` re-enables deprecated insecure workflow commands |
| SEC018 | checkout-persist-credentials | warning | `actions/checkout` persists `GITHUB_TOKEN` in `.git/config` by default |
| SEC019 | secrets-outside-env | info | Secrets should be bound to `env:` variables instead of used directly in `run:`/`with:` |
| SEC020 | self-hosted-runner-fork-triggered | warning | Self-hosted runners used with fork-accessible triggers allow untrusted code execution |

## Supply Chain Security Rules (SC)

Detect supply chain risks in action and container image references.

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SC001 | unpinned-images | warning | Container images should be pinned to a SHA256 digest for supply chain security |
| SC002 | compromised-action-sha | error | Action references a SHA or tag of a known-compromised release |
| SC003 | known-vulnerable-action | warning | Action has known security advisories (CVE) in GitHub Advisory Database |
| SC004 | archived-uses | warning | Action references an archived (unmaintained) repository |
| SC005 | stale-action-refs | info | SHA-pinned action does not correspond to any known Git tag |
| SC006 | ref-confusion | warning | Action ref matches both a tag and branch, creating exploitable ambiguity |

## Performance Rules (PERF)

Detect CI performance issues and resource waste.

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| PERF001 | cache-not-used | warning | Job uses a language setup action without caching enabled |
| PERF002 | redundant-checkout | warning | Multiple `actions/checkout` without `path` in the same job |
| PERF003 | fail-fast-disabled | warning | Strategy has `fail-fast` disabled, wasting CI resources on failures |

## Best Practices Rules (BP)

Enforce workflow best practices for maintainability and reliability.

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| BP001 | missing-timeout | warning | Job is missing `timeout-minutes` (default 6 hours is too long) |
| BP002 | missing-step-name | info | Step is missing a `name` field |
| BP003 | deprecated-action-version | warning | Using a known deprecated action version |
| BP004 | cross-platform-shell | warning | Run step without `shell` in a Windows-targeting job |
| BP005 | push-without-concurrency | info | Push trigger without concurrency setting |
| BP007 | obfuscation | warning | Obfuscated or indirect command execution patterns detected in `run:` block |

## Permissions Rules (PERM)

Validate the principle of least privilege in workflow permissions.

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| PERM001 | broad-permissions | warning | Overly broad permission scope detected |
| PERM002 | missing-job-permissions | warning | Job with third-party actions lacks explicit permissions |

## Expression Validation Rules (EXPR)

Validate `${{ }}` expression syntax, context access, and function calls.

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| EXPR001 | invalid-syntax | error | Empty expression or syntax error in `${{ }}` |
| EXPR002 | unknown-context | error | Unknown context reference (e.g. `${{ foo.bar }}`) |
| EXPR003 | unknown-property | warning | Unknown context property (e.g. `${{ github.unknown }}`) |
| EXPR004 | unknown-function | error | Unknown function name |
| EXPR005 | wrong-argument-count | error | Function called with wrong number of arguments |
| EXPR006 | unsound-contains | warning | `contains()` uses substring matching which may match unintended values |
| EXPR007 | unsound-condition | warning | Bare literal as operand in logical operator is always truthy |

## Dependency Rules (DEP)

Validate Dependabot configuration files (`dependabot.yml`).

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| DEP001 | dependabot-cooldown | info | Dependabot updates should configure a cooldown period to avoid excessive PRs |
| DEP002 | dependabot-execution | warning | `insecure-external-code-execution: allow` is a supply chain attack risk |

## Runner Rules (RUNNER)

Validate GitHub-hosted runner labels in `runs-on:`.

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| RUNNER001 | deprecated-runner | error/warning | `runs-on` label is retired (error) or scheduled for retirement (warning) by GitHub |

---

## Configuring Rules

You can override rule severity or disable rules in `.zghalint.yml`:

```yaml
rules:
  SEC001:
    severity: error        # Upgrade from warning to error
  BP002:
    enabled: false         # Disable a rule
  SEC007:
    severity: warning      # Upgrade from info to warning
```

See the [README](../README.md#configuration) for full configuration options.
