# 実施ロードマップ（2026-09-07 時点）

オープンな PR / issue を main（`83a3d9d`）の実装状況と突き合わせ、以後の実施順序を示す。
経緯や前版との差分は git log と PR #130 / #207 の履歴に残しているため、本書には現在形の内容だけを書く。

## 1. 現状サマリ

| 項目 | 状態 |
|---|---|
| ルール数 | `docs/rules.md` の表は 98 行（DEP005 / DEP006 追加分）で `registry.all_rules` と一致。`src/docs_sync_test.zig`（#242）が ID の欠落・余剰を両方向でテストする。残る不一致は**見出しの「90 rules」だけ**（同期テストは ID 集合のみを見て本文の数字は見ない） |
| `src/**/*.zig` | 51,322 行 |
| ユニットテスト | 1752 件（`zig build test` 緑） |
| #55 actionlint parity | 54 sub-issue 中 **54 close 済み（100%）**。umbrella #55 本体も close 済み |
| 型検査エンジン | T0〜T4 完了（#129 は PR #256 で overlay 接続、close 済み）。EXPR018 引数型検査（#162）も同 PR で完了・close 済み |
| E2E テスト | `src/e2e_test.zig` が `tests/fixtures/e2e/*.yml`（45 本）と `tests/fixtures/e2e-action/*.yml`（7 本）の `# zghalint:expect RULE@line` / `forbid` コメントを読んで検証 |
| bench | `bench/cases/` に 129 ファイル（複数ファイルのケースをまとめて 124 ケース）。A〜D は PR #277、E〜J は PR #287 で揃った。`scripts/bench.py` の採点で zghalint は recall 100%（105/105）・precision 100%・位置一致 96%（101/105）。FN・FP ともに 0 件で、実行エラーは #284 の 1 件のみ。外部ツール未導入の環境では zghalint 単独で採点する |
| PBT（`tests/pbt/`） | 42 個の `@given`、xfail 0 件。依存は固定済み（#235） |
| ファズ | `src/fuzz_test.zig` が YAML パーサと式パーサのターゲットを持ち、CI で回る（#241） |
| ADR | `docs/adr/0001`〜`0013`（0012 は RUNNER002 matrix 展開、0013 は RUNNER003） |
| オープン PR | #207（本ロードマップ）と #217（形式仕様とモデル検査）の 2 本。#272 / #277 / #287（bench）と #278（G5〜G8）/ #279（#159）/ #288（G11）/ #289（G12）/ #290（#64）/ #292（G9）/ #291（G14）はマージ済み |
| オープン issue | 9 件。内訳はその他 1（#135）、パーサ堅牢性 1（#293、実ワークフロー 228 件中 36 件が parse error）、ベンチマーク系 4（#262 本体と #268〜#270）、bench 由来の parity gap 3（#281 #284 #286 = G10 / G13 / G15）。#55 #64 #263 #264 #265〜#267 #271 #273〜#276 #280 #282 #283 #285 #159 は実装済みのため close 済み |
| バージョン定義 | Zig の版は `build.zig.zon` の `minimum_zig_version` 一箇所が真。参照側の一覧と更新手順は `docs/maintenance.md`（#236） |
| 既知バグ | 形式検証由来の反例はすべて解消した。security 3 件（#218 / #219 / #220）に続き、prefetch キャッシュ（#221 / #222）・`--fix` の原子性（#223）・SEC021 の誤検知（#224）が PR #261 で修正・close 済み |

Phase 1（トリガー `on:` 群）、Phase 2（job / step / matrix）、Phase 3（contextual typing）、
Phase 4（action.yml / reusable workflow）はいずれも完了した。
Phase 4 は PR #258 で composite の `runs.steps`（ACT005 = #254）とローカル action.yml ローダー（DEP004 = #96）が、
PR #259 で reusable workflow 側 4 本（RW002〜RW005 = #105〜#108）が、
PR #260 で埋め込みメタデータによる DEP005 / DEP006 とランタイム判定版 BP003（#97〜#99）が着地している。
#55 は最後まで残っていたパーサ基盤の #64（YAML anchor / alias / merge key）が PR #290 で着地し、
sub-issue 54/54 で umbrella ごと close した。
実装済みだったルール系 issue（#72 #73 #75 #86 #91 #92 #96〜#100 #105〜#108 #124 #129 #159 #162 #210 #218〜#224 #254 #263〜#267 #271 #273〜#276）は close 済み。

リポジトリ運用・CI 基盤トラックは完了した。CI は fmt / build / test に加えて
クロスコンパイル・3 OS スモーク・自リポジトリの dogfooding・外部静的解析（actionlint / zizmor / shellcheck / ruff）・
ファズ・coverage を回し、release は provenance attestation とバイナリスモークを持つ。
該当 issue（#230 #234〜#244）12 件も本回で close 済みで、この track に残作業はない。

## 2. ロードマップ

原則:

- 1 issue = 1 PR = 1 ルール。TDD（Red → Green → Refactor）、完了時に `docs/rules.md` へ行追加
- 同一ファイル（`types.zig` / `parser.zig` / `security.zig`）を触る issue は直列にし、rebase 地獄を避ける
- 誤検出ゼロを優先。不確かなものは検出しない（ADR-0009 の方針を全ルールに適用）
- 新ルールは `src/rules/registry.zig` へ登録し、`tests/fixtures/e2e/` に `# zghalint:expect RULE@line` つきの fixture を 1 本足す。`docs/rules.md` の行を忘れると `src/docs_sync_test.zig` が落ちる

### Phase 1: トリガー `on:` 群 — 完了

SYN009（イベント名）/ SYN010（activity type）/ SYN011（イベント別フィルタ）は
`src/workflow/events.zig` の表に、SYN016 の IANA タイムゾーンは `src/workflow/timezones.zig` に、
SYN017 の `workflow_dispatch` inputs は `workflow/parser.zig` + `rules/syntax.zig` に入った。
cron（#70 / #71）と glob（#69）は `src/workflow/cron.zig` / `src/rules/glob.zig` として実装済み。
`events.zig` / `timezones.zig` の表は後続 Phase から再利用する。

### Phase 2: job / step / matrix — 完了

`Strategy` の matrix 構造は SYN018（#74）で `src/workflow/parser.zig` + `src/rules/syntax.zig` に入り、
SYN019（#75）の include / exclude 整合、RUNNER002 の matrix 展開（#210、ADR-0012）、
RUNNER003 のラベル衝突（#77、ADR-0013）が続けて着地した。
ラベル表は `src/rules/runner.zig` にあり、self-hosted のフリート表記は RUNNER002 / RUNNER003 とも対象外にしてある。
この matrix 構造は Phase 3 の EXPR011 がそのまま使っている。

### Phase 3: contextual typing（エンジン T4 = #129）— 完了

存在検証 5 本・T4 overlay 接続・EXPR018・利用可否検証 2 本がすべて実装済みで、Phase 3 は閉じた。式の走査は `src/rules/expr_scan.zig` に切り出され、
各 context ルールは同じ形（`<context>_context.zig`）で並んでいる。

| ルール | issue | 実装 | 状態 |
|---|---|---|---|
| EXPR010 `steps.<id>` | #86 | `src/rules/steps_ref.zig` | 完了（close 済み） |
| EXPR011 `matrix.<key>` | #87 | `src/rules/matrix_context.zig` | 完了 |
| EXPR012 `needs.<job>` | — | `src/rules/needs_context.zig` | 完了 |
| EXPR013 `inputs.<name>` | #89 | `src/rules/inputs_context.zig` | 完了 |
| EXPR014 `secrets.<name>` | #90 | `src/rules/secrets_context.zig` | 完了 |
| EXPR017 curated `github.event` overlay | #124 | `src/rules/expr_catalog.zig` | 完了（close 済み） |
| T4 overlay 接続 | #129 | `src/rules/expr_overlay.zig` | 完了（close 済み、PR #256） |
| EXPR018 引数型・補間値検査 | #162 | `src/rules/expressions.zig` | 完了（close 済み、PR #256） |
| EXPR015 キーごとの context 利用可否 | #91 | `src/rules/expr_availability.zig` | 完了（close 済み、PR #257） |
| EXPR016 特殊関数の利用可否 | #92 | `src/rules/expr_availability.zig` | 完了（close 済み、PR #257） |

キーパス情報は `src/rules/expr_scan.zig` が式に添えて配る形になり、EXPR015 / EXPR016 が同じ経路を共有する。

### Phase 4: action.yml / reusable workflow（複数ファイル横断）— 完了

基盤の #100 が着地した。`src/rules/action_metadata.zig` が ACT001〜ACT004（必須キー / `runs.using` /
未知キー / 定義の型）を見て、`tests/fixtures/e2e-action/` が fixture を持つ。
PR #258 で `src/rules/composite_steps.zig`（ACT005）と `src/rules/local_action.zig`（DEP004、ローカル action.yml ローダー）が、
PR #259 で `src/rules/called_workflow.zig`（呼び先ワークフローの読み取り）と RW002〜RW005 が入り、
PR #260 で埋め込みメタデータ（`src/rules/data/popular_actions.zig`）による DEP005 / DEP006 / BP003 が入った。
ローカルファイルもリモート action のメタデータも揃い、**Phase 4 は完了した**。

| 順 | issue | ルール | 状態 / 依存 |
|---|---|---|---|
| — | #254 | ACT005 composite の `runs.steps` | 完了（close 済み、PR #258）。`src/rules/composite_steps.zig` |
| — | #96 | DEP004 ローカルアクション inputs | 完了（close 済み、PR #258）。`src/rules/local_action.zig` |
| — | #105〜#108 | RW002〜RW005 reusable workflow 呼び出し検証 | 完了（close 済み、PR #259）。ルール本体は `src/rules/reusable_workflow.zig:515` 以降、呼び先の読み取りは `src/rules/called_workflow.zig` |
| — | #97 | DEP005 popular actions inputs | 完了（close 済み、PR #260）。`src/rules/popular_actions.zig` と生成テーブル `src/rules/data/popular_actions.zig`（`scripts/gen-popular-actions.py`）。`with:` の検査は `src/rules/with_inputs.zig` が DEP004 と共有する |
| — | #98 | DEP006 非推奨 inputs | 完了（close 済み、PR #260）。同じ埋め込みテーブルの deprecated 欄を見る |
| — | #99 | BP003 拡張 node12 / node16 | 完了（close 済み、PR #260）。ローカル action は `local_action.zig` の `deprecated_runtimes`、リモート action は埋め込みテーブルが持つ `runs.using` を見る |

### 並行トラック

| 項目 | 位置づけ |
|---|---|
| #135 SC007 typosquat 検出 | `docs/design/sc007-typosquat-design.md` で設計済み。`src/rules/data/trusted_actions.zig` を追加しオフラインで完結するので、他と完全に並列可 |
| ベンチマーク #262 | zghalint / actionlint / zizmor を三者比較し、改善課題を継続的に洗い出す umbrella。基盤（#263）は PR #272、ケース A〜D（#264）は PR #277、ケース E〜J（#265〜#267）と FN 候補の検証（#271）は PR #287 で完了した。残る sub-issue は性能計測 #268、autofix 交差検証 #269、運用ループ #270 の 3 本で、いずれもケース本体ではなく回し方の課題 |
| bench 由来の parity gap #280〜#286 | E〜J のケースで出た FP・FN・実行エラーを `docs/design/external-linter-parity.md` の G9〜G15 として起票したもの。残るのは 3 本で、いずれもルール追加。#281（`needs:` の未知 job と循環）/ #284（中身のないワークフローを診断で返す）/ #286（API トークンでの publish を trusted publishing へ誘導）。ルール改善の #285（G14、PERM001 の過剰警告）は PR #291、パーサ層の #280（G9、関数呼び出し結果へのプロパティ・インデックスアクセス）は PR #292、ファイル全体が検査対象から落ちる系の #282（G11、UTF-8 BOM）は PR #288、#283（G12、ドキュメントマーカー）は PR #289 で解消し、A〜D 由来の G5〜G8（#273〜#276）は PR #278 で解消済み |
| PR #217 形式仕様 | Alloy（ルール所有権）と TLA+（prefetch / autofix）の仕様と反例。#218〜#224 の出所で、指摘はすべて修正済み。マージすれば以後の反例追加が同じ場所に載る |
| リポジトリ運用・CI 基盤（旧 #230 #234〜#244） | 12 件すべて実装済み・close 済み（Dependabot / PBT 依存固定 / Zig 版一元化 / coverage / concurrency / 外部静的解析 / ファズ / 自リポジトリ dogfooding / action.yml スモーク / メタファイル / release provenance / タグ整合 / `docs/rules.md` 同期テスト）。track として終了 |

## 3. 直近の着手順（上位 4 件）

| 順 | 対象 | 理由 |
|---|---|---|
| 1 | `docs/rules.md` の見出し修正 | 表は 98 行で registry と同期済みなのに、見出しが「90 rules」のまま。#242 の同期テストは ID 集合しか見ないので本文の数字は守られない |
| 2 | #293 | 実ワークフロー 228 件のうち 36 件が parse error で lint できない（`-` 単独行、親キーと同一インデントのシーケンス）。実利用の 16% が丸ごと検査対象から落ちるので、単発ルールより優先度が高い |
| 3 | #284 | 中身のないワークフロー（コメントのみのファイル）を `InvalidValue` ではなく診断として返す。bench に残る唯一の実行エラー `i-robustness/comments-only.yml` がこれで消える。#293 と同じ YAML 入り口の話なので続けて入れられる |
| 4 | #281 / #135 | ルール追加の 2 本。#281 は `needs:` の未知 job と循環、#135 は SC007 typosquat で設計済み・オフライン完結のため他と完全に並列できる |

Phase 1〜4 はすべて閉じ、ルール追加の主戦場は #55 から bench（#262）へ移った。
E〜J のケースが揃ったことで採点は全カテゴリを覆い、recall 100% / precision 100% に到達した。
bench 上の FN・FP は消えたので、次の課題は採点済みケースの外——実ワークフローで落ちる
パーサ堅牢性（#293 / #284）へ移っている。

## 4. 進め方の注意

- `types.zig` / `parser.zig` / `security.zig` を触る変更は直列にする（Phase 4 で `types.zig` の拡張が重なった際の教訓）
- エージェント PR は CI 緑でもマージ前に main へ rebase する
- ルールを追加・変更したら `tests/fixtures/e2e/`（ワークフロー）または `tests/fixtures/e2e-action/`（action.yml）に fixture を足し、`# zghalint:expect RULE@line` で行まで含めてアサートする
- `docs/rules.md` への行追加は任意ではない。`src/docs_sync_test.zig` が registry との ID 差分でビルドを落とす
- 新ルールのテストは `Step` / `Job` を手で組まず、`src/test_support.zig` の `parseWorkflowSource`（YAML から `Workflow` を起こす）と `lintAndFix`（リント + autofix を 1 度に検証）を使う。`runStep` / `runJob` / `runWorkflow` は `security.zig` にあるファイル内ヘルパーなので、他ファイルからは呼べない
- 式を走査するルールは `src/rules/expr_scan.zig` を使う。`${{ }}` の切り出しを各ルールで書き直さない
- autofix を伴うルールは、フロースタイル（`{}` / `[]`）とブロックスカラー（`|` / `>`）の入力を必ずテストに含める（#171 / #172 はどちらもこの 2 形式の抜けだった）。`tests/pbt/strategies.py` に両形式の strategy があるので PBT 側にも足す
- CRLF のワークフローも入力になる（Windows CI で顕在化した）。行末を跨ぐ処理を書いたら `\r` を落とす経路を確認する
- 深い再帰を持つパーサには上限を入れる（YAML は `max_parse_depth = 256`、式は `max_expr_depth = 256`）。新しい再帰下降を書いたら同じガードを必ず付ける
- 実装が終わったら `/wrapup`（`.claude/skills/wrapup`）で正しさ・過剰設計・コメントの 3 点を見てからコミットする。コメントは「コードから復元できない why」だけ残す（`/cleanup-comments` の基準）
- ルールを増やしたら `docs/rules.md` のルール数と bench の採点（`scripts/bench.py`）を確認する
- Zig の版を上げるときは `build.zig.zon` の `minimum_zig_version` だけを触る。CI / release / `scripts/setup-zig.sh` はそこから読むので、他所に版を書かない（`docs/maintenance.md`）
- `zig build` は build.zig 一本で、`scripts/setup-zig.sh` の wrapper は `-fllvm` 注入のみ。**古い wrapper が `/usr/local/bin/zig` に残っていると `no module named 'build_options'` でビルドが落ちる**。main を取り込んだら `bash scripts/setup-zig.sh` を流し直す
