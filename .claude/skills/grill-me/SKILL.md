---
description: 実装プランや設計について、意思決定ツリーの各分岐を解消するまで容赦なく質問攻め（インタビュー）にし、共有理解に到達してから実装に進むためのスキル。ユーザーが「grill me」「グリルして」「質問攻めにして」「プランを stress-test して」と発言したとき、または設計・プランの徹底レビューを求めたときに発動する。
---

# grill-me

Matt Pocock 氏が公開しているスキル [mattpocock/skills/grill-me](https://github.com/mattpocock/skills/blob/main/grill-me/SKILL.md) を zghalint プロジェクト向けに取り入れたもの。Frederick P. Brooks, Jr. の *The Design of Design* に由来する「設計ツリーの分岐を一つずつ解決する」というアプローチを、プランモードの品質向上に活用する。

## 原典（翻訳前の原文）

> Interview me relentlessly about every aspect of this plan until we reach a shared understanding. Walk down each branch of the design tree, resolving dependencies between decisions one-by-one. For each question, provide your recommended answer.
>
> Ask the questions one at a time.
>
> If a question can be answered by exploring the codebase, explore the codebase instead.

## 発動条件

以下のいずれかで発動する:

- ユーザーが「grill me」「グリルして」「徹底的に質問して」「プランを stress-test して」などと依頼した
- ユーザーがプランや設計について「妥協なくレビューしてほしい」と明示的に求めた
- プランモードで、ユーザーが `ExitPlanMode` 前に「詰めきってから確定したい」と表明した

## インタビューの原則

1. **一問一答**: 質問は **必ず1つずつ** 提示する。複数の質問を同時に投げない
2. **推奨回答を必ず添える**: 各質問には Claude 自身の推奨回答とその根拠をセットで提示する。ユーザーが「それで」と答えるだけで済む状態にする
3. **設計ツリーを上から辿る**: トップレベルの意思決定から始め、依存関係を解決しながら分岐を下っていく。途中で横道に逸れない
4. **コードで答えられる質問はコードで答える**: コードベースや既存ドキュメントを読めば分かる事項は、ユーザーに訊かず自分で調べる
5. **曖昧な回答を許さない**: ユーザーが「どちらでも」「任せる」と答えた場合でも、推奨回答を再提示して合意を明示的に取る
6. **共有理解に到達するまで続ける**: 目安として 16〜50 問。早期に切り上げない

## zghalint 文脈で優先的にグリルする観点

本プロジェクトは Zig 製の GitHub Actions ワークフローリンター。プラン・設計に対して以下のカテゴリから質問を組み立てる。

### 1. モジュール境界

- 追加・変更するコードは `src/rules/`, `src/workflow/`, `src/yaml/`, `src/output/`, `src/diagnostics.zig`, `src/config.zig` のどこに属するか
- 既存モジュールの責務を侵食していないか
- 新規モジュールを追加する場合、公開 API と内部 API の境界をどう引くか

### 2. YAML パーサ・ワークフロー型への影響

- `src/yaml/types.zig` の Node 型や Span 情報を変更する必要があるか
- `src/workflow/types.zig` の `Workflow` / `Job` / `Step` / `Trigger` 型に新フィールドが必要か
- 既存 YAML パーサの振る舞いに後方非互換な変更はないか

### 3. ルール設計

- 新規ルールなら `category`（security / performance / best_practice / expression / permissions / ...）と severity をどう設定するか
- `src/rules/engine.zig` のルール実行フレームワークに収まるか、拡張が必要か
- 誤検知（false positive）と見逃し（false negative）のトレードオフをどう評価するか
- `.zghalint.yml` からの severity 上書き・enable/disable に対応するか

### 4. Diagnostics とエラー伝播

- `src/diagnostics.zig` の `Diagnostic` 型で表現できるか
- 位置情報（`Span`）は入力 YAML まで正確に遡れるか
- エラーメッセージは actionable（ユーザーが何を直せばよいか明確）か

### 5. 出力フォーマット互換性

- terminal / JSON / SARIF 2.1.0 の 3 形式すべてで整合的に出力されるか
- SARIF ルール ID・help URI・レベル（error/warning/note）のマッピングは妥当か
- `--color auto|always|never` の挙動を壊していないか

### 6. テスト戦略

- Zig のインラインテスト（`test "..." { ... }`）でカバーできるか
- fixture YAML を追加する必要があるか、追加するなら `tests/` のどこに置くか
- エッジケース（空ファイル、BOM 付き、巨大ファイル、不正 YAML、タブ混在インデント）を網羅しているか
- ゼロアロケーション志向・ゼロ依存方針を崩していないか

### 7. 設定・CLI への影響

- `.zghalint.yml` に新しい設定キーが必要か。既存キーとの衝突はないか
- CLI の `--config` / `--format` / `--color` との組み合わせで壊れないか

### 8. Tidy First 判定（Kent Beck）

- 機能変更の前に構造的整理（tidy）が必要か
- tidy と機能変更を別コミットに分割できるか
- tidy 候補: Guard Clauses / Dead Code 削除 / Normalize Symmetries / Extract Helper / One Pile / Explaining Comments / Explaining Variables のどれに該当するか

### 9. 完了条件（CLAUDE.md 準拠）

- `zig build && zig fmt --check src/ build.zig && zig build test --summary all` がそのまま通る構成か
- クロスプラットフォーム（Linux / macOS / Windows × x86_64 / aarch64）で破綻する箇所はないか

## 終了条件

以下がすべて満たされた時点でインタビューを終了し、最終プランを提示する:

- すべての意思決定分岐に明示的な回答がある
- モジュール境界・型定義・テスト方針・Tidy 判定が確定している
- `update-plan` スキルの検証観点（設計書・ロードマップ・要件定義との整合性）と矛盾しない
- ユーザーが「OK、これで実装して」と明示的に合意した

## 禁止事項

- 質問を省略して早急にプランを確定すること
- 推奨回答を添えずに質問だけを投げること
- 複数の質問を 1 回のターンでまとめて投げること
- 曖昧な合意のまま `ExitPlanMode` に進むこと
- コードを読めば分かる事項をユーザーに訊くこと
