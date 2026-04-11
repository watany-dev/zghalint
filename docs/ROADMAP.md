# ROADMAP

## 目的

zghalint の設計書・実装計画書を、要件定義と 1 対多で結びつけるための基準ロードマップ。  
`docs/design/*.md` は本書の item ID を参照し、設計レビューでは item の状態と要件対応を確認する。

## ステータス定義

| ステータス | 意味 |
|------------|------|
| `done` | 文書または実装が反映済みで、レビュー基準に照らして完了扱い |
| `planned` | 設計書または実装計画書があり、着手対象として合意済み |
| `backlog` | 必要性は把握しているが、まだ具体実装へ切り出していない |

## ロードマップ

| Phase | Item ID | ステータス | 内容 | 対応要件 | 対応設計書 |
|-------|---------|------------|------|----------|------------|
| `P0` | `RM-001` | `done` | 設計レビュー基盤として `docs/ROADMAP.md` と `docs/requirements.md` を整備し、欠落文書参照をなくす | `NFR-005`, `NFR-006` | `docs/ROADMAP.md`, `docs/requirements.md` |
| `P1` | `RM-100` | `planned` | autofix 全体の棚卸しと優先順位付けを行い、段階的な実装順序を定める | `FR-005`, `NFR-002`, `NFR-003`, `NFR-006` | `docs/design/autofix-implementation-plan.md` |
| `P1` | `RM-110` | `planned` | `DEP002` に safe autofix を追加し、Dependabot 設定の insecure external code execution を `deny` へ収束させる | `FR-002`, `FR-005`, `NFR-002`, `NFR-006` | `docs/design/dep002-autofix-design.md` |
| `P1` | `RM-120` | `planned` | `SEC017` に safe autofix を追加し、`env` metadata を最小拡張して `true -> false` 置換を可能にする | `FR-001`, `FR-005`, `NFR-002`, `NFR-006` | `docs/design/sec017-autofix-design.md`, `docs/design/sec017-implementation-plan.md` |
| `P2` | `RM-200` | `backlog` | permission / concurrency / cooldown など insertion 系・unsafe 系 autofix を設計単位で拡張する | `FR-005`, `NFR-002`, `NFR-003`, `NFR-006` | `docs/design/autofix-implementation-plan.md` |
| `P3` | `RM-300` | `backlog` | expression / security の条件付き rewrite を限定パターンで検討する | `FR-005`, `NFR-002`, `NFR-006` | `docs/design/autofix-implementation-plan.md` |

## 運用ルール

- 設計書を新規追加するときは、対応する item を本書に追加する
- item のステータス変更は、設計書・実装・テストの実態に合わせて更新する
- `planned` の item には少なくとも 1 つの `docs/design/*.md` を紐付ける
