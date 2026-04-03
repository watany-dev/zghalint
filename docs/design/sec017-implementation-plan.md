# SEC017 実装計画書

## 目的

`docs/design/sec017-autofix-design.md` を実装に落とし込み、`SEC017` に safe autofix を追加する。  
対象は `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` の検出時に、YAML の scalar style を保持したまま `false` へ置換する機能である。

## update-plan 検証結果

### 設計書品質評価

| 設計書 | モジュール設計 | YAML・WF解析 | エラー処理 | 技術選定 | データフロー | 平均 |
|--------|-------------|-------------|-----------|---------|------------|------|
| `sec017-autofix-design.md` | 93/100 | 95/100 | 90/100 | 93/100 | 94/100 | 93.0 |

### 整合性チェック

| チェック項目 | スコア | 詳細 |
|-------------|--------|------|
| 設計書 ↔ ソースコード | 94/100 | `src/workflow/parser.zig` が `env` の span/style を落としている点、`src/rules/security.zig` が fix 未実装である点を設計書が正しく捉えている |
| ロードマップ ↔ 設計書 ↔ 要件定義 | 72/100 | `docs/ROADMAP.md` と `docs/requirements.md` は現状リポジトリ内に見当たらないため、`AGENTS.md` と既存設計書を基準に整合性を確認した |

### 修正事項

- **P0**: parser/model 拡張と rule 実装を分離し、Tidy First で進める
- **P1**: parser テストと rule/fix integration テストを別コミット単位で切れる粒度に保つ
- **P2**: `env_meta` が今後 `SEC019` でも再利用できるよう、`env` 専用 metadata として命名を一般化し過ぎない

## 実装対象

- `src/workflow/types.zig`
- `src/workflow/parser.zig`
- `src/rules/security.zig`

## 非対象

- `src/yaml/parser.zig`
- `src/yaml/types.zig`
- `src/fix/engine.zig`
- `SEC017` 以外の rule 実装
- `ACTIONS_ALLOW_UNSECURE_COMMANDS` entry 全体の削除

## 完了条件

- workflow/job/step の `env` で `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` を検出したとき `Diagnostic.fix != null`
- replacement が scalar style を保持して `false` へ置換される
- metadata がない手組み workflow では diagnostic を維持しつつ fix は省略できる
- `zig build`
- `zig fmt --check src/ build.zig`
- `zig build test --summary all`

## 実装方針

### Phase 1: parser/model の最小拡張

目的:
`env` value の `span` と `style` を rule 側へ渡せるようにする。

作業:
1. `src/workflow/types.zig` に `ScalarValueMeta` と `ScalarValueMetaMap` を追加する
2. `Workflow`, `Job`, `Step` に `env_meta: ?ScalarValueMetaMap = null` を追加する
3. `src/workflow/parser.zig` に `ParsedStringMap` と `parseStringMapWithMeta` を追加する
4. workflow/job/step の `env` parse だけを `parseStringMapWithMeta` に切り替える

Red:
- `parseWorkflow with env and concurrency`
- `parseJob with env and concurrency and with`
- `parseStep with timeout and continue-on-error`
- 新規 `parseStringMapWithMeta` テスト

Green:
- `env` 既存値の互換性を保ったまま `env_meta` が埋まる状態にする

Refactor:
- `parseStringMap` は他用途が多いため維持し、`env` 専用 helper のみに閉じる

### Phase 2: SEC017 rule の autofix 実装

目的:
metadata がある場合にのみ `SEC017` へ safe fix を付与する。

作業:
1. `src/rules/security.zig` に `buildInsecureCommandsFix` を追加する
2. `checkEnvForInsecureCommands` の引数を `env_map` と `env_meta` に拡張する
3. workflow/job/step 呼び出し側から `env_meta` を渡す
4. metadata がない場合は既存どおり `fix_hint` のみ返す fallback を残す

Red:
- existing SEC017 tests を fix 前提に拡張
- plain/single/double quote の replacement テストを追加
- metadata 不在時に `diag.fix == null` を確認するテストを追加
- `literal` / `folded` で fix を付けないテストを追加

Green:
- `Fix.description == "set ACTIONS_ALLOW_UNSECURE_COMMANDS to false"`
- `Fix.safety == .safe`
- edit 数は 1 件

Refactor:
- replacement 組み立てを helper に閉じ、rule 本体では条件分岐を最小化する

### Phase 3: integration test 追加

目的:
YAML parse から fix 適用までが実際に通ることを担保する。

作業:
1. `src/rules/security.zig` に workflow-level integration test を追加する
2. job-level integration test を追加する
3. step-level integration test を追加する
4. quoted style と inline comment の保持を確認する

ベースにする既存テスト:
- `SEC015: integration - YAML parse to fix apply`

期待結果:
- `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` が `false` に変わる
- `'true'` は `'false'` に変わる
- `"true"` は `"false"` に変わる
- 行構造や comment を壊さない

### Phase 4: 検証と整備

作業:
1. `zig build`
2. `zig fmt --check src/ build.zig`
3. `zig build test --summary all`
4. 必要ならテスト名と helper 名を揃える小さな整理を入れる

## 変更順序

1. parser テスト追加
2. parser/model 実装
3. SEC017 unit test 追加
4. SEC017 fix 実装
5. integration test 追加
6. 最終検証

この順序にする理由:

- `SEC017` の fix 実装は `env_meta` がないと成立しない
- parser 拡張を先に閉じることで、rule 側の差分を小さく保てる
- TDD の Red/Green を parser 層と rule 層で分離できる

## テスト追加先

- `src/workflow/parser.zig`
  - `parseStringMapWithMeta`
  - workflow/job/step の `env_meta` 伝播
- `src/rules/security.zig`
  - SEC017 の fix attachment
  - scalar style 別 replacement
  - metadata fallback
  - parse-to-fix integration

## リスクと対策

### リスク 1: metadata 追加で既存テストの手組み struct 初期化が壊れる

対策:
- 新 field はすべて `= null` の default を付ける
- 既存 unit test の `Workflow`, `Job`, `Step` 初期化を壊さない

### リスク 2: `StringArrayHashMap` を増やすことで所有権が曖昧になる

対策:
- parser 経由のデータは既存どおり arena allocator 前提で扱う
- 手組み test で `env_meta` を使う場合だけ明示的に `deinit()` する

### リスク 3: style 保持ロジックが block scalar に誤適用される

対策:
- `plain` / `single_quoted` / `double_quoted` のみ fix 対象に限定する
- `literal` / `folded` は diagnostic のみ残す

## レビュー観点

- `env_meta` が `env` のみに限定され、不要な汎用化をしていないか
- parser 拡張が既存の `with` / `secrets` / `permissions` に波及していないか
- `SEC017` の fallback が残り、手組み workflow test を壊していないか
- fix が `.safe` として妥当か

## 実装メモ

- `docs/ROADMAP.md` と `docs/requirements.md` は現時点で見当たらないため、本計画は [sec017-autofix-design.md](/workspaces/zghalint/docs/design/sec017-autofix-design.md) と `AGENTS.md`、既存 autofix 実装パターンを基準にしている
- 既存の `SEC017` テストは検出確認だけなので、fix attachment と integration の 2 系統に分けて拡張するのが最小差分
