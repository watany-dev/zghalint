# AGENTS.md

Do not include any closing suggestions such as "if needed" or similar conditional offers at the end of your response.

## Project Overview

zghalint is a comprehensive, fast GitHub Actions workflow linter written in Zig. It analyzes `.yml`/`.yaml` workflow files to detect security vulnerabilities, performance issues, best practices violations, expression syntax errors, and permission model problems.

## Build & Development

```bash
zig build                           # Build executable and library
zig build run -- [workflow files]   # Run with arguments
zig build test                      # Run all unit tests
zig build test --summary all        # With detailed summary
zig fmt --check src/ build.zig      # Check formatting
zig fmt src/ build.zig              # Auto-format
```

### Prerequisites

- Zig 0.15.2 or later

### Completion Requirements

**各タスク完了時**、コミット前に以下の全CIチェックを必ず通すこと:
```bash
zig build && zig fmt --check src/ build.zig && zig build test --summary all
```

1. `build` — バイナリビルド成功
2. `fmt --check` — Zig formatting check
3. `build test` — All unit tests

**これらのステップは絶対にスキップしないこと。** タスク単位でCIを通すのは最低限の品質基準である。

## Architecture

- `src/main.zig` — CLI entry point and argument parsing
- `src/lib.zig` — Library public API and test orchestration
- `src/config.zig` — Configuration parsing and rule overrides (.zghalint.yml)
- `src/diagnostics.zig` — Diagnostic types, severity, categories
- `src/util.zig` — Shared helpers (e.g. step name generation for autofix)
- `src/e2e_test.zig` — Fixture-driven E2E tests over `tests/fixtures/e2e/` (real files through parser → rules)
- `src/fix/` — Auto-fix engine
  - `engine.zig` — Collect and apply `--fix` / `--fix-unsafe` rewrites in place
- `src/rules/` — Linting rule implementations
  - `engine.zig` — Rule execution framework
  - `registry.zig` — The single list of all lint rules (`all_rules`)
  - `security.zig` — Security checks (script injection, unpinned actions, hardcoded secrets)
  - `expressions.zig` — `${{ }}` expression validation
  - `performance.zig` — Performance optimization rules (caching, redundant steps)
  - `best_practices.zig` — Best practice checks (timeouts, naming, concurrency)
  - `permissions.zig` — Permission model validation
  - `advisory.zig` — Known-vulnerable action detection (SC003)
  - `archived.zig` — Archived repository detection (SC004)
  - `stale_refs.zig` — SHA-to-tag resolution (SC005)
  - `refconfusion.zig` — Tag/branch ref confusion (SC006)
  - `dependabot.zig` — Dependabot configuration checks
  - `http_client.zig` — Shared `std.http.Client` for GitHub API reuse
  - `graphql.zig` — GitHub GraphQL batching (SC004-SC006 in 1-2 POSTs)
  - `disk_cache.zig` — Per-repo JSON cache (24h TTL) for warm runs
  - `prefetch.zig` — Orchestrator: disk → GraphQL → REST fallback
- `src/workflow/` — Workflow data structures and parsing
  - `types.zig` — Workflow, Job, Step, Trigger types
  - `parser.zig` — Workflow structure parser
  - `validator.zig` — Workflow validation logic
- `src/yaml/` — YAML parsing (from scratch, no external deps)
  - `tokenizer.zig` — YAML tokenization
  - `parser.zig` — YAML AST parsing
  - `types.zig` — YAML node and span types
- `src/output/` — Output formatters
  - `terminal.zig` — Colored terminal output
  - `json.zig` — JSON output format
  - `sarif.zig` — SARIF 2.1.0 format for GitHub Code Scanning

## CLI Options

- `--config <path>` — Load rule overrides from .zghalint.yml
- `--format <fmt>` — Output format (terminal, json, sarif; default: terminal)
- `--color <mode>` — Color control (auto, always, never; default: auto)
- `--quick` / `--offline` — Disable network requests; use local data/cache only
- `--no-cache` — Bypass the on-disk prefetch cache and refetch from GitHub
- `--fix` / `--fix-unsafe` — Apply auto-fixes in place
- `-h, --help` — Show help
- `-v, --version` — Show version

## Configuration File (.zghalint.yml)

Supports rule severity overrides, enable/disable rules, file ignore patterns, output format/color settings.

## Diagnostic Categories

syntax, security, performance, best_practice, expression, dependency, permissions, runner, reusable_workflow

## プロジェクト基本方針

### 目的
GitHub Actions ワークフローファイルを静的解析し、セキュリティ・パフォーマンス・ベストプラクティスの問題を検出する高速リンター。

### 技術方針
- **ゼロ依存**: 外部ライブラリなし。YAML パーサも自前実装
- **安全性重視**: Zig の安全機能（bounds checking, optional types）を活用
- **高速性**: コンパイル時最適化とゼロアロケーション志向
- **クロスプラットフォーム**: Linux, macOS, Windows 対応（x86_64, aarch64）
- **テスト品質**: インラインテストによる網羅的な単体テスト

## TDDサイクル
各機能は以下のサイクルで実装します:
1. **Red**: テストを書く（失敗する）
2. **Green**: 最小限の実装でテストを通す
3. **Refactor**: コードを改善する

## Tidy First? (Kent Beck)
機能変更の前に、まずコードを整理（tidy）するかを検討します:

**原則**:
- **構造的変更と機能的変更を分離する**: tidyingは別コミットで行う
- **小さく整理してから変更する**: 大きなリファクタリングより、小さな整理を積み重ねる
- **読みやすさを優先**: 次の開発者（未来の自分を含む）のために整理する

**Tidying パターン**:
1. **Guard Clauses**: ネストを減らすために早期リターンを使う
2. **Dead Code**: 使われていないコードを削除
3. **Normalize Symmetries**: 似た処理は同じ形式で書く
4. **Extract Helper**: 再利用可能な部分を関数に抽出
5. **One Pile**: 散らばった関連コードを一箇所にまとめる
6. **Explaining Comments**: 理解しにくい箇所にコメントを追加
7. **Explaining Variables**: 複雑な式を説明的な変数に分解

**タイミング**:
- 変更対象のコードが読みにくい → Tidy First
- 変更が簡単にできる状態 → そのまま実装
- Tidyingのコストが高すぎる → 機能変更後に検討

## イテレーション単位
機能を最小単位に分割し、各イテレーションで1つの機能を完成させます。各イテレーションでコミットを行います。

## Agent Skills

このリポジトリのスキルは `.claude/skills/` に 1 本だけ置き、`.agents/skills`
（Codex / Cursor が参照）は同ディレクトリへのシンボリックリンクとする。

作業完了時は `wrapup` スキル（レビュー2本 → 取り込み → コメント掃除）を通す。

`ponytail-review`（差分の過剰設計レビュー）と `ponytail-audit`（リポジトリ全体の
監査）は [DietrichGebert/ponytail](https://github.com/DietrichGebert/ponytail) (MIT)
から vendoring したもの。
