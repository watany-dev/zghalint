# 実施ロードマップ（2026-09-05 更新 / rev.3）

オープンな PR / issue を main の実装状況と突き合わせて棚卸しし、以後の実施順序を示す。

## 0. 前版からの差分

前版（rev.2）以降、main は 2 つの波を消化した。

### 0.1 基盤欠陥 4 件（rev.2 で P0 としたもの）— すべて解決済み

| 項目 | 結果 |
|---|---|
| #131 / #137 プレーンスカラーの切り詰め | **解決**（PR #139）。`Tokenizer.flow_depth` を導入し、`,` `[` `]` `{` `}` を flow context の中でのみ指示子として扱うようになった |
| #133 診断 span の `0:0` | **解決**（PR #140）。`src/rules/spans.zig` を新設し全ルールへ伝搬。`src/rules/` の `Span.point(0, 0, 0)` は 0 箇所 |
| #132 E2E テスト | **解決**（PR #141）。`src/e2e_test.zig` + `tests/fixtures/e2e/*.yml`。併せて `src/rules/registry.zig` へルール登録表を抽出 |
| #138 SEC006 の誤検知 | **解決**（PR #144）。`if:` 条件専用の `condition_dangerous_contexts` を分離。`parseFlowSequence` が未閉じ `[` で回り続ける不具合も同 PR で修正 |

これを受けて #62 / #101 / #102 / #103 / #133 / #138 を実バイナリの出力を根拠に close した。
#55 の parity 進捗は **13/54 → 17/54（31%）**、オープン issue は 49 → 43 件。

### 0.2 リファクタ波（#145 umbrella）— 完了

`ponytail-audit` 起点の重複削減 issue #145 とその sub-issue #146〜#150 が **すべて close**、
PR #152〜#157 で main にマージ済み。主な構造変更:

| 変更 | 内容 |
|---|---|
| `src/test_support.zig` 新設 | `parseWorkflowSource` / `runStep` / `runJob` / `runWorkflow` / `lintAndFix` などテスト雛形を集約（#146） |
| `src/workflow/validator.zig` 廃止 | `schema.zig` と `type_validation.zig` に分割（#147） |
| `src/rules/json_util.zig` 新設 | ルール間で重複していた JSON 処理を集約（#148） |
| ADR 番号の重複解消 | 同番号が複数あった状態を `0001`〜`0009` に整理（SEC009 は ADR-0004、式の静的型検査は ADR-0009） |
| ドキュメント整理 | 完了済みの `docs/codebase-improvements.md` と autofix 実装計画書を削除（#150） |
| ビルド整理 | `build.zig` から未使用の `addLibrary` / `fmt` ステップ / embed path を削除。版番号は `build.zig.zon` 一本に集約し `build_options` 経由で `main.zig` が読む。`scripts/setup-zig.sh` の wrapper は `-fllvm` 注入のみに簡素化（#150） |

実測: `src/**/*.zig` は 29,891 行、`zig build test` は **1099 テスト**（前版 1142。重複テストの集約による減少で、カバレッジの後退ではない）。

**基盤フェーズ・整理フェーズはいずれも完了**とみなし、以降は §3 の残件と Phase 1 に進む。

## 1. 現状サマリ

| 項目 | 状態 |
|---|---|
| ルール数（`docs/rules.md`） | 59 |
| `src/**/*.zig` | 29,891 行 |
| ユニットテスト | 1099 件（`zig build test` 緑） |
| #55 actionlint parity | 54 sub-issue 中 **17 close 済み（31%）** |
| 型検査エンジン | T0〜T3 実装済み。T4（overlay 接続）は #129 |
| E2E テスト | `src/e2e_test.zig` に fixture 駆動 |
| PBT（`tests/pbt/`） | xfail 0 件 |
| オープン PR | #130（本 PR）と #151（#143 の下準備リファクタ） |
| オープン issue | 43 件。うち #55 本体と parity sub-issue 40 件 |
| 未解決の既知バグ | #143（`workflow_run` 信頼ゲート無検出）、#136（SYN002 / SYN005 二重報告）。いずれも main のバイナリで再現を確認済み |

## 2. close 済みの棚卸し結果

rev.2 の §2 で「実装済み・未 close」と判定した 6 件は、根拠を各 issue にコメントしたうえで close 済み。

| issue | close の根拠 |
|---|---|
| #62 SYN007 env 変数名 | `checkEnvNames` が workflow / job / step の 3 レベルに配線済み。`env: { "BAD NAME": x }` → `SYN007` を実位置で報告 |
| #101 SEC002 untrusted inputs 拡充 | `security.zig` の untrusted context テーブルを拡充済み。現在は `run_dangerous_contexts`（21 エントリ）と `condition_dangerous_contexts`（15 エントリ）の 2 本立て（close 時点の 3 系統からリファクタ波で集約された） |
| #102 SEC002 object filter `.*` | `${{ github.event.commits.*.message }}` → SEC002。`${{ steps.meta.outputs.github.head_ref }}` は正しく非報告 |
| #103 SEC002 github-script の `script:` | `actions/github-script` の `with.script` → `SEC002: ... used in actions/github-script script: input` |
| #133 診断 span | `Span.point(0, 0, 0)` が 0 箇所 |
| #138 SEC006 の誤検知 | PR #144。ただし副作用が #143 として残るため、close コメントで #143 へリンク済み |

**現時点で「作業不要のまま open」な issue はない。** 残り 43 件はすべて実装作業を伴う。

## 3. 最優先: #138 の副作用と積み残しバグ

### 3.1 #143 — `workflow_run.head_branch` の信頼ゲートが無検出（P0）

#138 で `if:` 条件専用テーブルを分けた結果、ref 形状のコンテキストは SEC006 の対象外になった。
ブランチ名でのルーティングは正当なイディオムなので判断としては正しいが、`workflow_run` だけは事情が違う。

```yaml
on: workflow_run
jobs:
  deploy:
    if: github.event.workflow_run.head_branch == 'main'   # fork が main という名のブランチを作れば通る
    steps:
      - run: ./deploy.sh
```

main（`07496d7`）のバイナリで確認したところ、`permissions` と `timeout-minutes` を書いたこのワークフローは
**`No issues found.`** になる。信頼ゲートの穴に対する診断は 1 件も出ない。
`workflow_run` は privileged コンテキストで走るため、ゲート突破は権限昇格に直結する。

SEC009 の `checkWorkflowRunUntrustedCheckout` は `step.uses` と `with.ref` しか見ておらず `if:` を検査しない。
`security.zig` のテスト `SEC006: ref-shaped contexts in conditions are not reported` が現挙動を固定しているため、
テーブルを戻すだけの修正はテストと正面衝突する。

**方針**: issue の選択肢 2（専用ルール SEC0xx を新設し `on: workflow_run` のワークフローに限定）を推す。
`head_repository.full_name` の検証や `head_sha` 突き合わせという具体的な fix hint を出せて、誤検知も抑えられる。

### 3.2 #136 — SYN002 と SYN005 の二重報告

```
p4.yml:8:3: error[SYN002]: key "build" is duplicated in "jobs" section...
p4.yml:8:3: error[SYN005]: job ID "build" duplicates...
```

同一位置・同一原因で 2 件。#118 で E2E のアサーションを件数比較から緩める原因になった。
ADR-0004（SEC002 と SEC009 の責務境界）と同じ形で、SYN002 の走査対象から `jobs:` を外し、
ジョブ ID の重複は SYN005 の責務に一本化する。修正後は E2E を `diags.len()` の厳密比較に戻せる。

## 4. オープン PR の裁き方

| PR | 内容 | 判定 |
|---|---|---|
| #130 | 本ロードマップ | main（`07496d7`）に追随のうえマージ。docs のみで競合なし |
| #151 | `refactor(security): extract findAnyContext from containsAnyContext`（+258 / -12、4 ファイル） | #143 の下準備。マッチ位置を返すようにして診断のアンカーに使えるようにする、挙動不変のリファクタ。**base が `5271a4d` のままでリファクタ波 12 コミット分遅れており、CI も未実行**（`total_count: 0`）。main を取り込んで CI を回してからマージし、その上に #143 の本体を載せる |

rev.2 で保留にしていた PR #142（skills の vendoring）は close 済みで、`.agents/skills` も main から削除された。

## 5. ロードマップ

原則:

- 1 issue = 1 PR = 1 ルール。TDD（Red → Green → Refactor）、完了時に `docs/rules.md` へ行追加
- 同一ファイル（`types.zig` / `parser.zig` / `security.zig`）を触る issue は直列にし、rebase 地獄を避ける
- 誤検出ゼロを優先。不確かなものは検出しない（ADR-0009 の方針を全ルールに適用）
- 新ルールは `src/rules/registry.zig` へ登録し、`tests/fixtures/e2e/` に fixture を 1 本足す

### Phase 1: 依存なし・小粒ルール

`types.zig` を触らず、既存の走査ループにチェックを足すだけで済むもの。

| 順 | issue | ルール | 状態 / 触る主なファイル |
|---|---|---|---|
| 0 | #143 | SEC0xx `workflow_run` の信頼ゲート | §3.1。セキュリティ検出漏れなので最優先。方針決定 → 実装 |
| 0 | #136 | SYN002 / SYN005 の責務分離 | §3.2。小さく、E2E のアサーションを戻せる |
| 1 | #79 | PERM003 permissions スコープ / レベル | `permissions.zig` / `parser.zig` の `parsePermissions`。表引きのみ |
| 2 | #95 | DEP003 `uses` フォーマット | `types.zig` の `ActionRef.parse` 近傍 |
| 3 | #78 | BP004 拡張 shell 名 | `best_practices.zig`。#79 と同型なので連続で処理できる |
| 4 | #85 | EXPR009 fromJSON リテラル | `expressions.zig`（JSON 妥当性チェッカを `util.zig` に切り出す） |
| 5 | #84 | EXPR008 format() 整合 | `expressions.zig` |
| 6 | #83 | EXPR007 拡張 定数条件 / `${{ }}` 外の文字 | `expressions.zig` |
| 7 | #104 | RW001 workflow_call inputs type | `parser.zig` の `parseInputDefs`（単一ファイルで完結する RW 唯一の項目） |

### Phase 2: トリガー `on:` 群

`ScheduleEntry` / `EventConfig` の拡張を伴うため直列。イベント名テーブルと cron パーサを先に作り、後続で再利用する。

| 順 | issue | ルール | 依存 |
|---|---|---|---|
| 1 | #70 | SYN014 CRON 構文 | cron パーサを `util.zig` か `workflow/cron.zig` に新設。自己完結でテストしやすく、Phase 2 の入口に向く |
| 2 | #71 | SYN015 5 分未満 | #70 のパーサ。#70 と同一 PR に載せてよい |
| 3 | #69 | SYN013 glob 構文 | なし。独立して着手可 |
| 4 | #65 | SYN009 webhook イベント名（+ 近似候補提案） | イベント名 / activity type の埋め込みテーブルを新設 |
| 5 | #66 | SYN010 `types` 値 | #65 のテーブル |
| 6 | #67 | SYN011 イベントで使えないフィルタ | #65 のテーブル。SYN012 で `EventFilter` の key span は記録済み |
| 7 | #72 | SYN016 timezone | `ScheduleEntry.timezone` 追加 + IANA 名テーブル（`scripts/` で生成、`src/rules/data/` に置く） |
| 8 | #73 | SYN017 workflow_dispatch inputs | #129 の `github.event.inputs` overlay と同時に実装 |

### Phase 3: job / step / matrix

`Strategy` 型の拡張（matrix 軸・include / exclude の保持）が起点。

| 順 | issue | ルール | 依存 |
|---|---|---|---|
| 1 | #74 | SYN018 matrix 値重複 | `Strategy` に matrix 構造を追加 |
| 2 | #75 | SYN019 include / exclude 整合 | #74 |
| 3 | #76 | RUNNER002 未知ラベル | RUNNER001 のラベルデータを既知ラベル一覧に拡張。`.zghalint.yml` に self-hosted ラベル許可設定が要る |
| 4 | #77 | RUNNER003 ラベル衝突 | #76 |

### Phase 4: contextual typing（エンジン T4 = #129）

各 issue で「存在検証」を実装し、最後に `TypeEnv` overlay へ接続する（ADR-0009 の二重メンテ期間を短くするため Phase 4 内で一気に片付ける）。

| 順 | issue | ルール | 依存 |
|---|---|---|---|
| 1 | #86 | EXPR010 `steps.<id>` | なし |
| 2 | #88 | EXPR012 `needs.<job>.outputs` | なし |
| 3 | #89 | EXPR013 `inputs.<name>` | #73（SYN017 の inputs 構造） |
| 4 | #87 | EXPR011 `matrix.<key>` | #74（matrix 構造） |
| 5 | #90 | EXPR014 `secrets.<name>` | #104（workflow_call secrets の定義） |
| 6 | #129 | T4: 上記を `expr_check.zig` の overlay に接続し、存在検証をエンジン側に寄せる | #86〜#90 |
| 7 | #91 | EXPR015 キーごとの context 利用可否 | 式を検証する箇所に「どのキーか」を渡す配線が必要 |
| 8 | #92 | EXPR016 特殊関数の利用可否 | #91 の配線 |
| 9 | #124 | curated scalar overlay（`github.event.issue.number: number` 等） | EXPR017 の到達範囲拡大 |

### Phase 5: action.yml / reusable workflow（複数ファイル横断）

「他ファイルを読む」仕組みが共通基盤。`action.yml` ローダーと `workflow_call` ローダーを 1 つのモジュールにまとめる。

| 順 | issue | ルール | 依存 |
|---|---|---|---|
| 1 | #100 | 基盤: action.yml をリント対象化 + メタデータ構文 | `main.zig` の対象判定拡張、`workflow/action_meta.zig` 新設 |
| 2 | #96 | DEP004 ローカルアクション inputs | #100 のローダー |
| 3 | #99 | BP003 拡張 node12 / node16 | ローカルは #100、リモートは `prefetch.zig` 経由で `action.yml` を取得（オフライン時はスキップ） |
| 4 | #105 | RW002 required inputs 欠落 | ローカル reusable workflow ローダー（#100 と同モジュール） |
| 5 | #106 | RW003 未定義 inputs / 型不整合 | #105 |
| 6 | #107 | RW004 secrets | #105 |
| 7 | #108 | RW005 outputs 実在 | #105 + #88 |
| 8 | #97 | DEP005 popular actions inputs | 埋め込みデータセット（`scripts/` で生成）。バイナリサイズを計測してから採否を決める |
| 9 | #98 | DEP006 非推奨 inputs | #97 のデータセット |

### 並行トラック

| 項目 | 位置づけ |
|---|---|
| #134 SEC021 untrusted checkout ref | #55 の対象外。ADR-0006 と `docs/design/sec021-untrusted-checkout-ref-design.md` で設計済み・未実装。#143 と同じ `security.zig` の `workflow_run` 周辺を触るので、**#143 の直後にまとめて着手**すると手戻りが少ない |
| #135 SC007 typosquat 検出 | 同上（`docs/design/sc007-typosquat-design.md`）。`src/rules/data/trusted_actions.zig` を追加しオフラインで完結するので、他と完全に並列可 |
| #64 YAML anchor / alias / merge key | パーサ基盤。GitHub Actions が anchor をサポートしたため実用価値あり。#131 の `flow_depth` 対応と同じ層なので、記憶が新しいうちに着手すると得。`yaml/parser.zig` の整理を Tidy First で先に行い、PBT にラウンドトリップ / 循環参照テストを追加する |
| `docs/design/pbt-strategy.md` #3〜#5 | xfail は解消済み。新ルールが増えるたびに detection PBT を横展開する |

## 6. 直近の着手順（上位 10 件）

close 作業（§2）とリファクタ波（§0.2）はいずれも完了しているので、次の順に着手する。

| 順 | issue | 理由 |
|---|---|---|
| 1 | #143 | 唯一のセキュリティ検出漏れ。`workflow_run` の権限昇格に直結し、実バイナリで無検出を確認済み。方針決定が要るので着手も早い方がよい |
| 2 | #136 | `bug` ラベル。小さく、#118 で緩めた E2E アサーションを厳密比較に戻せる |
| 3 | #134 | #143 と同じ `security.zig` の `workflow_run` 周辺。設計済みなので連続で処理する |
| 4 | #135 | 設計済み・オフライン完結・他と非競合。並列で流せる |
| 5 | #79 | Phase 1 の表引き系の先頭。`permissions.zig` のみ |
| 6 | #78 | #79 と同型。連続で処理できる |
| 7 | #70 + #71 | cron パーサを 1 本書けば 2 件。自己完結でテストしやすい |
| 8 | #69 | glob パーサ。#70 と独立なので並列可 |
| 9 | #65 | イベント名テーブルを作る。これが入ると #66 / #67 が同じ表の上に乗り 3 件まとまる |
| 10 | #129 | 最大の山。#86〜#89 の 4 件が一気に解ける。5〜9 で足場を固めてから着手 |

## 7. 進め方の注意

- #143 と #134 は同じ `security.zig` の `workflow_run` 経路を触るので直列にする。それ以外の Phase 1 は並列に走らせられる
- Phase 2 以降は `types.zig` の拡張を伴うため、同 Phase 内は直列にする
- エージェント PR は CI 緑でもマージ前に main へ rebase する
- ルールを追加・変更したら `tests/fixtures/e2e/` に fixture を足し、行 : 列まで含めてアサートする（#131 を見逃したのは、既存のインラインテストが `Step` 構造体を直接組み立てておりパーサを通っていなかったため）
- 各 Phase 完了時に `docs/rules.md` のルール数と #55 の進捗表を更新する
- リファクタ波でテスト雛形が `src/test_support.zig` に集約された。新ルールのテストは自前でワークフローを組み立てず、`parseWorkflowSource` / `runStep` / `runJob` / `runWorkflow` を使う
- `scripts/setup-zig.sh` が簡素化され `zig build` は build.zig 一本になった。**古い wrapper が `/usr/local/bin/zig` に残っていると `no module named 'build_options'` でビルドが落ちる**。main を取り込んだら `bash scripts/setup-zig.sh` を必ず流し直す
