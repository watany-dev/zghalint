# コードベース改善バックログ

`2026-04-11` 時点の `src/` と `build.zig` を見直し、現行実装に対してまだ有効な改善項目だけを残した。旧版にあった行番号依存の記述はすべて廃止し、ファイル名と関数名で追える形に揃えている。

## 仕分け方針

- `今やる`: 重複削減や責務整理の効果が大きく、単独の refactor task としてすぐ切れるもの
- `後回し`: 方針決めが先に必要、または設計変更の波及が広いもの
- `誤検知`: 旧版では課題として挙がっていたが、現状では問題化しないか、別の論点として扱うべきもの

---

## 今やる

### RB-001: `security.zig` の `${{ ... }}` 走査を共通化する

- 対象: `src/rules/security.zig`
- 根拠:
  - `hasDangerousContextExpression`
  - `checkStringForOverprovisionedSecrets`
  - `checkStringForUnredactedSecrets`
  - `checkStringForSecretsOutsideEnv`
  - `checkBotActorInString`
  - `checkDangerousContextInString`
- 問題:
  - `${{ ... }}` の開始判定、終端探索、trim、次の探索位置更新が同じ形で繰り返されている
  - ルール追加時に同じバグを横展開しやすい
- 作業:
  - 式を 1 個ずつ取り出す共通ヘルパーを `security.zig` 内に導入する
  - 各ルールは「抽出した式をどう判定するか」だけを持つ形に寄せる
- 完了条件:
  - `SEC002`, `SEC008`, `SEC011`, `SEC012`, `SEC014`, `SEC019` の既存テストが維持される
  - 走査ロジックが 1 箇所に集約される

### RB-002: `Step` の `run` / `with` / `env` 巡回を共通化する

- 対象: `src/rules/security.zig`
- 根拠:
  - `checkHardcodedSecrets`
  - `checkOverprovisionedSecrets`
  - `checkUnredactedSecrets`
  - `checkSecretsOutsideEnv`
- 問題:
  - `run`、`with`、`env` を順に走査する処理が何度も出てくる
  - `SEC019` だけ `env` を除外するなど、差分が見えにくい
- 作業:
  - `Step` から文字列入力候補を列挙する小さな共通ヘルパーを作る
  - `env` を含めるかどうかだけを呼び出し側で指定できるようにする
- 完了条件:
  - 各ルールの関心が「判定条件」に寄る
  - `SEC003`, `SEC011`, `SEC012`, `SEC019` のテスト結果が変わらない

### RB-003: `lintFile` / `lintDependabotFile` の共通前処理をまとめる

- 対象: `src/main.zig`
- 根拠:
  - `lintFile`
  - `lintDependabotFile`
  - `applyFixesForFile`
- 問題:
  - ファイル open、`10 * 1024 * 1024` 制限付き read、stderr 出力、YAML parse までの流れが重複している
  - 設定適用後に `all_diags` へ流し込む処理も重複している
- 作業:
  - ファイル読込と YAML parse の共通ヘルパーを作る
  - 診断へ `file` と config override を適用する処理を別ヘルパーへ出す
  - 読込上限は名前付き定数へ寄せる
- 完了条件:
  - `lintFile` と `lintDependabotFile` の差分が「workflow 解析か dependabot 解析か」だけになる
  - エラーメッセージの挙動は維持される

### RB-004: `actionBaseName` を共有ユーティリティへ抽出する

- 対象:
  - `src/rules/security.zig`
  - `src/rules/performance.zig`
  - `src/rules/best_practices.zig`
- 問題:
  - `owner/repo@ref` から `owner/repo` を抜く同一実装が 3 回出てくる
- 作業:
  - rules 共通の小さな utility を追加し、3 箇所から参照する
- 完了条件:
  - 同名関数の重複定義が解消される
  - `SEC001`, `BP003`, `PERF001`, `PERF002` の挙動が維持される

### RB-005: JSON 文字列エスケープ処理を共有化する

- 対象:
  - `src/output/json.zig`
  - `src/output/sarif.zig`
- 問題:
  - `writeJsonString` が完全重複している
  - JSON 出力の修正が 2 箇所に分散する
- 作業:
  - `src/output/` 配下に共通 writer helper を追加する
  - `json` と `sarif` はその helper を呼ぶだけにする
- 完了条件:
  - JSON エスケープ実装が 1 箇所になる
  - 既存の JSON/SARIF テストがそのまま通る

### RB-006: `write-all` 診断と autofix の共有部を寄せる

- 対象:
  - `src/rules/security.zig`
  - `src/rules/permissions.zig`
- 根拠:
  - 両方に `makeWriteAllFix` がある
  - `permissions: write-all` の検出と fix 生成が同じ構造
- 問題:
  - ルール ID と文言は違うが、fix 生成と基本判定が二重管理になっている
- 作業:
  - fix 生成と `write-all` 判定の共通ヘルパーを抽出する
  - ルール固有の severity / message / rule_id だけ各ファイルに残す
- 完了条件:
  - autofix 実装が 1 箇所になる
  - `SEC004` と `PERM001` のテストが維持される

### RB-007: `workflow/parser.zig` の definition parser を畳む

- 対象: `src/workflow/parser.zig`
- 根拠:
  - `parseInputDefs`
  - `parseOutputDefs`
  - `parseSecretDefs`
- 問題:
  - mapping を走査して定義オブジェクトへ詰める形がほぼ同じ
  - `required` の bool 解釈も個別実装になっている
- 作業:
  - mapping 走査の共通土台を作る
  - `InputDef` / `OutputDef` / `SecretDef` の差分だけを個別処理に閉じ込める
- 完了条件:
  - 3 関数の重複が大きく減る
  - `workflow_call` / `workflow_dispatch` 系の既存テストが通る

### RB-008: config 文字列パースの責務を整理する

- 対象:
  - `src/config.zig`
  - `src/diagnostics.zig`
- 根拠:
  - `parseSeverity`
  - `parseBool`
  - `findConfigFile`
  - `Severity.toString`
- 問題:
  - severity の文字列変換が片方向ずつ別管理になっている
  - `parseBool` は未知の文字列を `true` 扱いする
  - `findConfigFile` は `start_dir` を受け取るが実際には使っていない
- 作業:
  - `Severity.fromString` を定義して変換責務を寄せる
  - bool の受理値を明示化する
  - `findConfigFile` は引数どおり探索するか、そうしないなら API 名とコメントを現在仕様に合わせる
- 完了条件:
  - config 解析の仕様がコード上で明確になる
  - config 関連テストが現仕様に合わせて整理される

---

## 後回し

### RB-LATER-001: 診断集計ロジックを共通化する

- 対象:
  - `src/output/terminal.zig`
  - `src/output/json.zig`
- 内容:
  - severity ごとの件数集計が別々に書かれている
  - 小さな helper で寄せられるが、影響は限定的なので優先度は落とす

### RB-LATER-002: `DiagnosticList` の所有権と OOM 方針を整理する

- 対象:
  - `src/diagnostics.zig`
  - `src/main.zig`
- 内容:
  - `allocEdit` は `null`、`append` は error 返却で方針が揺れている
  - `lintFile` / `lintDependabotFile` では `all_diags.append` の OOM を握りつぶしている
  - `toOwnedSlice` と `fix_arena` の所有権も読み取りづらい
- 保留理由:
  - API 設計の再確認が先に必要

### RB-LATER-003: YAML の重複キー方針を明文化する

- 対象:
  - `src/yaml/types.zig`
  - `src/yaml/parser.zig`
- 内容:
  - `Mapping.get` は先勝ちで返す
  - duplicate key を last-win にするのか、エラーにするのか、現状維持にするのかを先に決めたい

### RB-LATER-004: `workflow/parser.zig` の bool 解釈を揃える

- 対象: `src/workflow/parser.zig`
- 内容:
  - `required`、`continue-on-error`、`cancel-in-progress`、`fail-fast` の真偽値解釈が関数ごとにばらつく
- 保留理由:
  - `fail-fast` は「未指定時に true」という仕様が混ざるため、単純な共通化だけでは片付かない

### RB-LATER-005: invalid node の扱いを厳格化するか決める

- 対象: `src/workflow/parser.zig`
- 内容:
  - 一部の sub-field は `else => {}` で黙って無視している
  - 互換性を優先するのか、設定ミスを早く落とすのかを決めてから触るべき

### RB-LATER-006: SARIF のメッセージ切り詰め方針を整理する

- 対象: `src/output/sarif.zig`
- 内容:
  - fix hint を連結する際に固定長バッファで切り詰めている
- 保留理由:
  - 出力互換性とメモリ使用量のトレードオフを先に決めたい

### RB-LATER-007: dead code / 薄い wrapper をまとめて掃除する

- 対象:
  - `src/diagnostics.zig`
  - `src/yaml/parser.zig`
  - `src/main.zig`
  - `src/config.zig`
- 候補:
  - `Diagnostic.format`
  - `Parser.errors`
  - `outputTerminal`
  - `outputJson`
  - `outputSarif`
  - `config.zig` の未使用 `Mapping` import
- 保留理由:
  - 個別では小さすぎるので、他の refactor に合わせてまとめて消す

### RB-LATER-008: `build.zig` の test module 構築を補助関数へ寄せる

- 対象: `build.zig`
- 内容:
  - `lib` / `cov` / `exe` の test module 作成パターンが近い
- 保留理由:
  - ビルド定義の可読性はまだ大きく崩れていない

---

## 誤検知

### FP-001: `skipNonNewlineWhitespace()` が no-op なのは不具合ではない

- 対象: `src/yaml/parser.zig`
- 判断:
  - tokenizer 側で空白を読み飛ばしているため、現状の no-op は実装意図と一致している
  - 削除するか残すかは style の話で、独立した backlog にはしない

### FP-002: `parseBlockMapping()` のインデント分岐は「到達不能コード」ではない

- 対象: `src/yaml/parser.zig`
- 判断:
  - `< key_indent` と `> key_indent` の 2 分岐は冗長ではあるが、到達不能という指摘は不正確
  - 簡略化は可能でも、専用タスクを切るほどの問題ではない

### FP-003: step/job/workflow wrapper の全面統合は現行 engine API と噛み合わない

- 対象:
  - `src/rules/engine.zig`
  - `src/rules/security.zig`
- 判断:
  - `Rule` が `check_workflow` / `check_job` / `check_step` を別々に受ける設計なので、`enum { workflow, job, step }` で統合する案はそのままでは入らない
  - backlog として残すなら wrapper 統合ではなく、内側の共通 helper 抽出で追うべき

### FP-004: `toString()` を全部 `@tagName` に置き換える必要はない

- 対象: `src/diagnostics.zig`
- 判断:
  - これは重複削減というより好みの問題
  - public API とテストの読みやすさもあるので、単独の refactor task にはしない

### FP-005: 変数名や re-export の「不統一」を単独タスクにはしない

- 対象:
  - `src/lib.zig`
  - `src/rules/`
- 判断:
  - 指摘自体が広すぎて完了条件を置きにくい
  - 具体的な構造改善タスクに付随して直す

---

## 着手順

1. `RB-001` と `RB-002` を同じ PR 系列で進める
2. `RB-003` を別 PR で切り出す
3. `RB-004` から `RB-006` を小粒な重複削減 PR として順に処理する
4. `RB-007` と `RB-008` は parser / config の整理としてまとめて扱う

## 完了の定義

このバックログから切った各 task は、少なくとも次を満たして完了とする。

- `zig build`
- `zig fmt --check src/ build.zig`
- `zig build test --summary all`
