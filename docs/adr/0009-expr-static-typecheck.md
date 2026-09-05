# 0009. 式の静的型検査エンジン

- Status: Accepted
- Date: 2026-09-03
- Deciders: issue #94（設計 issue。grill-me セッションは行わず、現行実装・actionlint `expr_type.go` / `expr_sema.go`・誤検出ゼロ方針から決定）

## Context

`src/rules/expressions.zig` は `${{ }}` 式を名前ベースで検証している。context 名（EXPR002）、`github` / `runner` の第一プロパティ名（EXPR003）、関数名（EXPR004）、引数個数（EXPR005）までで、型の概念が無い。そのため次が実装できない。

- 深いプロパティアクセスの検証（`github.repository.permissions` のように string を object として辿る誤り）
- 配列添字と `*` object filter の receiver 型
- 比較演算子の型不整合（EXPR017 / issue #93）
- 関数の戻り値型を使った連鎖検証（`startsWith(github.event, 'x')` など）

actionlint は `Any` / `Number` / `Bool` / `String` / `Null` / `Array<T>` / loose object / strict object / map object の型体系で式を検査する。zghalint は「誤検出を出さない」ことを actionlint より強く優先してきた。全面導入すると誤検出とバイナリ肥大のリスクがある。

本 ADR は実装ではなく、型表現・カタログ方針・`github.event` の扱い・段階導入・誤検出時の逃げ道を固定する。実装詳細は `docs/design/expr-static-typecheck-design.md`。

## Interview Summary

本 issue は設計専用であり、コードベースと actionlint 実装から分岐を閉じた。主な事実確認:

1. **actionlint は webhook payload の完全型を持たない**。`github.event` は `NewEmptyObjectType()`（loose object。未知プロパティは `any`）である。コメントに "Stricter type check for this payload would be possible" とあるだけで、octokit 由来の巨大テーブルは投入されていない（`expr_sema.go` の `BuiltinGlobalVariableTypes["github"].event`）
2. actionlint が厳密に型付けしているのは、ドキュメント化された context（`github` の第一プロパティ、`runner`、`job` 等）と、ワークフローから構築する contextual overlay（`steps` / `matrix` / `needs` / `inputs` / `secrets` / `github.event.inputs`）である
3. zghalint の現行 EXPR003 は `github` / `runner` の第一プロパティだけを見る。`github.repository.foo` は今日警告しない
4. EXPR010〜EXPR014 は型エンジン無しでも実装できる（issue #94 推奨）。エンジン完成をゲートにすると D グループ全体が止まる
5. 既存の逃げ道は `.zghalint.yml` の `rules.<ID>.enabled` / `severity` だけ。型検査専用の新キーはまだ無い

## Decisions

### D1. 型表現は tagged union + intern テーブル（ハイブリッド）

- `Type` を `union` 相当の tagged struct とし、`TypeRef = *const Type` で共有する
- 組込み context / スカラー / 既知 object は **comptime intern**（静的 `Type` 定数。実行時 alloc なし）
- ワークフロー依存の overlay（`steps.<id>` 等）だけ `TypeArena` で実行時 intern する

対立案:

| 案 | 採用しない理由 |
|---|---|
| tagged union のみ（毎回 object を構築） | 組込みカタログが毎回 alloc され、ホットパスに乗る |
| comptime テーブルのみ | `steps` / `matrix` / `needs` はワークフロー依存で comptime に閉じられない |
| actionlint と同じ Go `interface` + `map[string]ExprType` | Zig に interface は無く、`StringHashMap` を組込みカタログに使うのは過剰。組込みはソート済み `[]const Prop` + 二分探索 |

根拠: 組込みは不変データ、contextual overlay は可変データ、という二層に分けるとゼロ依存・低 alloc 方針と両立する。実装者が迷う分岐（「object を HashMap で持つか」）をここで閉じる。

### D2. 組込み context はドキュメント化された第一階層までを intern する

カタログに載せるもの:

- スカラー 5 種 + `array<any>` 1 種
- `github`（strict。`event` 以外の第一プロパティ型。issue #81 で揃えた名前と一致）
- `runner`（strict）
- `job`（strict。`container` / `services` をネスト）
- `strategy`（loose + 既知 4 プロパティ。actionlint と同じ。未知キーは `any`）
- `env` / `vars` / `secrets`（map object `{string => string}`）
- `steps` / `matrix` / `needs` / `inputs` / `jobs`（V1 は **loose object**。overlay 投入まで未知キーをエラーにしない）

カタログに載せないもの:

- webhook payload 全体（D3）
- popular action の `steps.<id>.outputs` 厳密型（DEP004 / DEP005 の領域）

保守コスト: プロパティ追加は `expr_catalog.zig` の 1 行。GitHub が context を足したら EXPR003 の誤検出になるため、issue #81 と同じ「欠けると誤検出」のメンテ経路を踏む。

### D3. `github.event` はイベント切替せず、常に loose object とする

- V1: `github.event` = loose object。`github.event.pull_request.head.sha` は `any`。存在検証も型検証もしない
- 例外 overlay（後段、EXPR013 / SYN017 と同時）: `workflow_dispatch.inputs` があるときだけ `github.event.inputs` を strict `{name: string, ...}` に差し替える。actionlint の `UpdateDispatchInputs` と同じ。payload 全体は触らない
- イベント別 payload 切替は **採用しない**。複数イベントの merge はほぼ `any` に潰れ、octokit schema は数十〜数百 KB の rodata になり、GitHub 側のフィールド追加で誤検出が先行する

対立案:

| 案 | 採用しない理由 |
|---|---|
| 単一イベントのときだけ payload 型に切替 | schema 保守が SYN009 を超える。actionlint 自身がやっていない |
| 頻出パスだけ curated scalar（`issue.number: number` 等）を V1 で入れる | 選択基準が主観的で、入れたパスと入れないパスで EXPR017 の当たり方が不均一になる。Follow-up に送る |

EXPR017 への帰結: V1 で検出できるのは型がカタログから分かる比較だけ。`github.event.issue.number == 'foo'` は両辺が `any` / `string` になり **検出しない**（誤検出ゼロを優先）。`github.event > 3`（object vs number）と `github.event_name == 1`（string vs number）は検出する。

### D4. 既存 EXPR001〜EXPR005 は ID を維持したままエンジンに吸収する。置き換えない

診断 ID の単一情報源:

| 現象 | ID | エンジン導入後 |
|---|---|---|
| 構文エラー | EXPR001 | パーサ専任。型エンジンは妥当な AST だけ見る |
| 未知 context 名 | EXPR002 | カタログ lookup に移行。メッセージ互換 |
| 未知プロパティ / 非 object への deref | EXPR003 | 型ウォークに移行。severity は現行どおり **warning** |
| 未知関数 | EXPR004 | シグネチャ表 lookup。**大小文字区別は現行維持**（actionlint は insensitive。変更は別 issue） |
| 引数個数 | EXPR005 | シグネチャの min/max に移行 |
| 比較型不整合 | EXPR017 | エンジンの compare 規則。**warning**（issue #93） |
| 関数引数の型不整合 / `${{ }}` 全体が object・array・null | （未採番） | V1 では **出さない**。`any` に倒す。Follow-up で EXPR018 を予約 |

段階導入（実装 issue 側。本 ADR は順序だけ固定する）:

1. **T0** `Type` / intern / カタログ。`typeOf` はテスト専用。`validateNode` は無改変
2. **T1** プロパティウォークを EXPR003 に接続。`github` / `runner` / `job` の深いアクセスが動き始める。loose な context は現状どおり無警告
3. **T2** 関数シグネチャに戻り値型を足す。EXPR004/005 の情報源をカタログに一本化。引数型エラーは出さない
4. **T3** EXPR017（比較）。本 ADR の比較行列
5. **T4** EXPR010〜EXPR014 が先行実装した集合を `TypeEnv` overlay に接続。接続までそれらの context は loose のまま

EXPR010〜EXPR014 は **エンジンを待たず個別実装する**（issue #94 の推奨を採用）。接続は T4。二重メンテ期間は「存在検証は各ルール、型は overlay 後にエンジン」と役割分担する。

EXPR006 / EXPR007 は型と独立した AST パターン診断なので、エンジンの外に残す。

### D5. 不明な型は常に `any` に倒す。新 config キーは作らない

`any` にする条件（網羅）:

- loose object の未知プロパティ
- map object の任意キー（値型は mapped 型。`env.FOO` は `string`）
- `fromJSON` の非リテラル引数
- `case()` の戻り値
- 添字がリテラルでない、または receiver が `any`
- `.*` の receiver が `any`
- `Merge` で衝突した型
- 型エラーを検出したノードの **結果型**（カスケード防止。診断は 1 箇所だけ）

逃げ道:

- `.zghalint.yml` の既存 `rules.EXPR003.enabled: false` / `rules.EXPR017.enabled: false`
- ファイル単位 `ignore`
- **型検査モード（strict/loose）のような新キーは V1 で追加しない**。ルール単位の既存機構で足りる

根拠: 新キーはドキュメント・実装・テストを増やすだけで、誤検出時の実務的な対処（そのルールを止める）と等価。PERF001 のようなルール固有キーは「正解がリポジトリ依存」なときに限る。型の厳しさはエンジン側の `any` 倒しで固定する。

### D6. 比較可能性は actionlint 互換 + `any` 短絡

`==` / `!=`:

- いずれかが `any` または `null` → 許可
- number/bool/string 同士 → 許可（暗黙変換を警告しない。GitHub が変換するため）
- number/bool/string vs object/array → **不許可**（NaN / 常に false になる）
- object vs object / null / any → 許可
- array vs array（要素型を再帰）/ null / any → 許可

`<` `>` `<=` `>=`:

- いずれかが `any` → 許可
- number/string 同士 → 許可
- null / bool / object / array が片方でもある → **不許可**

論理演算 `&&` `||` の結果型は `Merge`。型 narrowing（`x && 60 || 20` を number にする）は V1 対象外。

### D7. バイナリサイズ予算は intern カタログ 32 KiB 未満

- webhook schema を入れない（D3）時点で、組込みカタログはプロパティ名文字列 + 小さな `Type` / `Prop` 配列に収まる
- 実装 PR は `zig build -Doptimize=ReleaseSmall` のバイナリサイズを **導入前とカタログ投入後で記録** し、増分が 32 KiB を超えたらテーブルの持ち方を見直す（HashMap 化やイベント別 payload は禁止のまま、文字列の重複排除を先に行う）
- 実行時 `TypeArena` はワークフローあたりの overlay 用で、プロセス常駐の肥大要因にしない

## Consequences

### Positive

- EXPR017 と「string への誤った deref」が、誤検出を増やさずに実装可能になる
- EXPR010〜EXPR014 が後から overlay で接続できる口（`TypeEnv`）が先に決まる
- EXPR003 の情報源が「`github`/`runner` の一次元配列」から「strict object のウォーク」に上がり、`job` やネストにも同じ機構で拡張できる
- actionlint との差分が文書化される（payload 非搭載は同等、関数名の大小文字は意図的な差）

### Negative / Risks

- `github.event.*` の深い typo（`pull_request.hea.sha`）は V1 で沈黙する。SEC002 の untrusted リスト（issue #101）とは別経路
- T4 までの間、EXPR010〜EXPR014 とエンジンが存在検証を二重に持つ。overlay 接続時に診断が二重出力されないよう、接続完了後は存在検証をエンジン側に寄せる必要がある
- `job` を V1 から strict にすると、今日通っている `job.unknown` が EXPR003 になる。これは true positive だが、初めての「第一プロパティ以外の新規警告」なのでリリースノートで明示する
- 関数名の大小文字非区別は actionlint 互換にしない。`Contains()` は引き続き EXPR004。意図的な差

### Follow-up

- EXPR018: 関数引数の型不整合、および `${{ }}` 全体が object/array/null のときの診断（actionlint はこれを error にしている）
- curated scalar overlay（`github.event.issue.number: number` 等、20 件規模）。D3 を崩さず EXPR017 の到達範囲だけ広げる
- 型 narrowing（`&&` / `||`）
- 関数名の case-insensitive lookup（EXPR004 の仕様変更。誤検出修正ではなく互換変更）
- パーサが数値添字 `arr[0]` を受け付けるようにする（現状は string 添字のみ）。型エンジンは数値添字の規則だけ先に定義する
- EXPR010〜EXPR014 overlay 接続（T4）
- `github.event.inputs` overlay（SYN017 / EXPR013 と同時）

## 参考

- issue #94 — 本 ADR の起票
- issue #55 — actionlint parity 親 issue
- issue #93 — EXPR017（本 ADR D4 / D6 に依存）
- issue #86〜#90 — EXPR010〜EXPR014（エンジンを待たず先行。T4 で接続）
- `docs/design/expr-static-typecheck-design.md` — モジュール・型・データフローの実装詳細
- `src/rules/expressions.zig` — 現行パーサ / EXPR001〜EXPR007
- `src/config.zig` — `RuleOverride.enabled` / `severity`
- actionlint `expr_type.go` — `ExprType` / `ObjectType.Mapped` / `ArrayType.Deref`
- actionlint `expr_sema.go` — `BuiltinGlobalVariableTypes` / `BuiltinFuncSignatures` / `validateCompareOpOperands`
