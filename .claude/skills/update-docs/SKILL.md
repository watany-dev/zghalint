---
description: Update zghalint documentation (docs/design/*.md, docs/adr/*.md, README.md) to match current source code. Use when the user asks to update docs, refresh README, sync design documents with implementation, or check doc/code consistency. Trigger examples - "ドキュメントを最新化して", "設計書を更新", "update docs", "README を直して", "docs と src の乖離を確認", "sync documentation".
---

# update-docs

ソースコードの現状に基づき、すべてのドキュメントを一括で最新化するスキル。

## Phase 1: ソースコードの現状把握

1. `src/` 配下のZigソースコードを読み込む
   - モジュール構成は `AGENTS.md` の「Architecture」節が唯一の一覧。
     ここに写経せず、そちらを参照してから対象ファイルを開く
     （写しを置くと実装追加のたびに二重更新が要る）
2. `build.zig` のビルド構成を確認する
3. `build.zig.zon` の依存パッケージ一覧を確認する
4. 公開API・構造体・enumの一覧を把握する

## Phase 2: 各ドキュメントの更新

### 2-1. 設計書 (`docs/design/<feature>.md`) と ADR (`docs/adr/NNNN-*.md`)

1. 各設計書の内容をソースコードと照合する
2. 以下を更新する:
   - モジュール構成の変更
   - 構造体・enumの追加・変更・削除
   - 関数シグネチャの変更
   - ビルドオプションの変更
3. 設計書が存在しない新機能がある場合、設計書の新規作成を提案する
4. 実装が完了して陳腐化した「実装計画書」（Phase 分けや優先度表のみで、
   現行実装の説明価値がないもの）は削除を提案する。判断の記録は ADR に残す

### 2-2. README.md

1. プロジェクト概要が最新か確認する
2. インストール・ビルド手順を確認する
   - `zig build` コマンドが正しいか
   - `build.zig.zon` との整合性を確認する
3. 使用方法・CLIオプションの説明を確認する
   - `src/main.zig` の実装と一致しているか
4. アーキテクチャ図・モジュール構成が最新か確認する
   - `src/` のモジュール構成と一致しているか

## Phase 3: 一貫性チェック

すべてのドキュメント間で以下の一貫性を確認する:

1. **モジュール名・構造体名の統一**
   - すべてのドキュメントで同じ名前を使用しているか
2. **コマンド参照の統一**
   - `zig build` / `zig build test` / `zig fmt` コマンドが正しく参照されているか
   - `cargo` / `make` / `npm` 等の他言語コマンドが残っていないか
3. **ファイルパス参照の統一**
   - `src/main.zig`, `src/rules/` 等のパスが正しいか
   - 存在しないファイルへの参照がないか
4. **依存情報の統一**
   - `build.zig.zon` に記載されたパッケージとドキュメントの記載が一致しているか
   - ゼロ依存の方針が維持されているか確認する
5. **`@import` 文の検証**
   - ドキュメント中のコード例で使用されている `@import` 文が実際のモジュール構成と一致しているか

## Phase 4: 更新レポートの出力

以下の形式で更新内容をレポートする:

```markdown
## ドキュメント更新レポート

### 更新したドキュメント
| ファイル | 更新内容 |
|---------|---------|
| docs/design/&lt;feature&gt;-design.md | [変更概要] |
| docs/adr/NNNN-&lt;decision&gt;.md | [変更概要] |
| README.md | [変更概要] |
| ... | ... |

### 新規作成を提案するドキュメント
- [ファイル名]: [理由]

### 検出した不整合
- [不整合の詳細]
```

## 記述ルール

- コード例はZigで記述すること
- README.mdは英語で記述すること
- 開発ドキュメント（設計書）は日本語で記述すること
- 構造体名・関数名はZigの命名規則（camelCase / PascalCase）に従うこと
- 定数名はscreaming_snake_caseまたはZigの慣例に従うこと
