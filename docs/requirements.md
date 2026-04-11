# 要件定義

## 目的

zghalint の実装・設計・レビューで参照する基準要件を定義する。  
本書は `docs/design/*.md` のトレーサビリティ起点であり、各設計書は関連する要件 ID を明示する。

## 機能要件

| ID | 要件 | 根拠 |
|----|------|------|
| `FR-001` | GitHub Actions workflow (`.yml` / `.yaml`) を解析し、security / performance / best practices / permissions / expression 系の診断を返せること | `AGENTS.md` の Project Overview / Goal |
| `FR-002` | Dependabot 設定ファイルを解析し、依存更新ポリシーに関する診断を返せること | `docs/rules.md` の `DEP001`, `DEP002` |
| `FR-003` | 診断は rule ID・severity・span・fix hint を保持し、設定ファイルで rule override を受けられること | `src/diagnostics.zig`, `src/config.zig` |
| `FR-004` | 出力は terminal / json / sarif をサポートし、CLI から選択できること | `src/output/`, `src/main.zig` |
| `FR-005` | safe / unsafe を区別した autofix を提供し、`--fix` と `--fix-unsafe` で適用モードを切り替えられること | `src/diagnostics.zig`, `src/fix/engine.zig`, `src/main.zig` |
| `FR-006` | ネットワーク依存の検査を無効化できる offline mode (`--quick` / `--offline`) を持つこと | `src/main.zig` |

## 非機能要件

| ID | 要件 | 根拠 |
|----|------|------|
| `NFR-001` | 外部依存を導入せず、自前 YAML parser を含む zero-dependency 方針を維持すること | `AGENTS.md` の Technical Direction |
| `NFR-002` | Safety first を優先し、autofix は機械的で説明可能な変更に限定すること | `AGENTS.md` の Technical Direction / Tidy First |
| `NFR-003` | 低オーバーヘッドな parsing・rule 実行を優先し、ローカル解析で完結する経路を第一選択にすること | `AGENTS.md` の Technical Direction |
| `NFR-004` | Linux / macOS / Windows、x86_64 / aarch64 を対象とする cross-platform 性を維持すること | `AGENTS.md` の Technical Direction |
| `NFR-005` | 変更完了前に `zig build && zig fmt --check src/ build.zig && zig build test --summary all` を通すこと | `AGENTS.md` の Completion Requirements |
| `NFR-006` | `docs/design/*.md` は関連する roadmap item と requirement ID を明示し、存在しない文書を参照しないこと | 本タスクで定める設計レビュー基準 |

## 設計レビュー基準

設計レビューでは最低限次を満たすこと。

1. 目的、スコープ、非スコープが明示されている
2. `docs/ROADMAP.md` の関連 item ID と本書の requirement ID が明示されている
3. 影響を受ける `src/` 配下モジュール、データフロー、テスト方針が記載されている
4. safe / unsafe の判断が必要な場合、その根拠が記載されている
5. 参照リンク・参照文書がすべて実在している
6. 最終検証コマンドとして `NFR-005` の完了条件が記載されている

## 運用ルール

- 新しい設計書を追加するときは、同時に `docs/ROADMAP.md` へ対応 item を追加または更新する
- 実装計画書は、設計書と同じ requirement ID を再利用して差分だけを補足する
- `update-plan` 系のレビューは、本書と `docs/ROADMAP.md` を基準に整合性を判定する
