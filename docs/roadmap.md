# 実施ロードマップ（2026-09-11 時点）

オープンな PR / issue を main（`ff8068a`）の実装状況と突き合わせ、以後の実施順序を示す。
経緯や前版との差分は git log と PR #130 / #207 の履歴に残しているため、本書には現在形の内容だけを書く。

## 1. 現状サマリ

| 項目 | 状態 |
|---|---|
| ルール数 | `docs/rules.md` の表は 103 行（SYN021 / SYN022 の needs グラフ検証を含む）で `registry.all_rules` と一致。`src/docs_sync_test.zig`（#242）が ID の欠落・余剰を両方向でテストする。同期テストは ID 集合しか見ないため見出しの数字は手で守る必要があり、本回は表が 103 に増えた分だけ見出しを追随させた |
| `src/**/*.zig` | 64,349 行 |
| ユニットテスト | 2148 件（`zig build test` 緑）。#331 で低品質なテストの削除とテーブル駆動化を行った上で（PR #332）、SC007・ドッグフーディング・形式手法・autofix 拡張・fix の衝突修正・SEC023・SYN020・EXPR007 / EXPR011 の誤検出修正・性能最適化・空セクションのパース継続・SC003 のピンコメント版判定・BP007 のプロセス置換・SEC023 の crates.io・EXPR011 のオブジェクト軸・SYN021 / SYN022・BP003 の最新 major 比較・SEC016 の暗黙キャッシュ判定の分が積み増している。Zig 0.16 移行では stdout / stderr のリダイレクト保持と atomic replace の権限復元に回帰テストが加わり、PR #404 / #405 のファズキャンペーンがパーサとスパンと fix エンジンに 77 件を積み増した |
| #55 actionlint parity | 54 sub-issue 中 **54 close 済み（100%）**。umbrella #55 本体も close 済み |
| 型検査エンジン | T0〜T4 完了（#129 は PR #256 で overlay 接続、close 済み）。EXPR018 引数型検査（#162）も同 PR で完了・close 済み |
| E2E テスト | `src/e2e_test.zig` が `tests/fixtures/e2e/*.yml`（79 本）と `tests/fixtures/e2e-action/*.yml`（8 本）の `# zghalint:expect RULE@line` / `forbid` コメントを読んで検証。兄弟ファイル `<name>.fixed` / `<name>.fixed-unsafe` を置いたフィクスチャは `--fix` / `--fix-unsafe` 適用後のバイト列も固定する（PR #328、現在 17 本） |
| bench | `bench/cases/` に 144 ファイル（複数ファイルのケースをまとめて 139 ケース）。A〜D は PR #277、E〜J は PR #287 で揃い、G16 / G17 の堅牢性ケース 3 本が PR #301、G21 の再現ケース 1 本が PR #317、G25 の再現ケース 1 本が PR #357 で加わった。`scripts/bench.py` の採点で zghalint は recall 100%（116/116）・precision 100%・位置一致 97%（112/116）、実行エラー 0 件。FP も FN も 0 件で、`bench/baseline.json` に記録された既知 gap は残っていない。skip はネットワークを要する 2 ケースと、SEC002 が matrix.* を対象外にする意図的な非対応 1 ケースだけである。外部ツール未導入の環境では zghalint 単独で採点する。採点結果は `bench/baseline.json` に固定し、`scripts/bench_gate.py` が回帰を非ゼロ終了で落とす（#270、PR #373）。`.github/workflows/bench.yml` が週次で 3 モードを回して parity doc へ流す。`--perf`（`scripts/bench_perf.py`）が wall time と最大 RSS を 4 シナリオで測り、実ワークフローのコーパスは `scripts/fetch-corpus.py` が取得する（#268、PR #296）。`--fix`（`scripts/bench_fix.py`）は autofix 交差検証で、非冪等 0 / YAML 破損 0 / コメント欠落 0。意図した増加は各ケースの `# bench:fix-allow <flag> <tool>=<ID> <理由>` で宣言し、宣言のないものだけが問題として残る（#269、PR #345、宣言形式は PR #373）。PR #356 が §4.6 の性能表を無効と判定した——zghalint 列が Debug ビルド、actionlint 列が shellcheck 無しという二重の環境差で、ReleaseFast + shellcheck ありで測り直した §4.7 では §4.5 と同じ水準（wall time で 15〜60 倍、RSS で 6〜23 倍の差）に戻る |
| PBT（`tests/pbt/`） | 42 個の `@given`、xfail 0 件。依存は固定済み（#235） |
| ファズ | `src/fuzz_test.zig` が YAML パーサと式パーサのターゲットを持ち、CI で回る（#241）。長時間キャンペーン用に `src/fuzz_driver.zig` が単体ドライバとして立ち、PR #371 で入った。探索実行（`zig build fuzz --fuzz`）は Zig 0.16.0 で起動する。0.15.2 で出ていたファザ起動直後の失敗は再現しない（`docs/design/pbt-strategy.md` §6-4）。コールバックは `*std.testing.Smith` を受け取り、`slice` で最大 64 KiB の入力を作る。この経路が #364 / #366〜#370 の 6 件を掘り出して 6 件とも解決し（#366 は PR #376、#367〜#370 は PR #380、#364 は PR #390）、続く追加キャンペーンが出した #399 も PR #404 / #405 で解決した。変異器はブロックスカラー化・CRLF 化・二重引用のエスケープ列・アンカー / エイリアス対・マージキーまで広がり、`docs/design/pbt-strategy.md` §6 が各キャンペーンの出したクラスを記録する。PR #380 は E2E ハーネスに全フィクスチャ共通の不変条件を 2 つ足しており、診断の span が逆転しないことと `--fix` / `--fix-unsafe` が不動点に達することを常設で見る |
| ADR | `docs/adr/0001`〜`0016`（0012 は RUNNER002 matrix 展開、0013 は RUNNER003、0014 は SEC023 trusted publishing、0015 は BP003 の最新 major 比較、0016 はネットワーク到達不能時の fail fast とリクエスト単位の予算） |
| オープン PR | #217（形式仕様とモデル検査）、#306（bench 再実行記録）、#395（本ロードマップの同期）、#420（ドッグフーディングからの G36 起票）、#422（同 G37 起票）、#426（同 G38 / G39 起票）の 6 本。#418（`util` の `IgnoreCaseMap`）はマージされずに close された。#392（#375 = D7）/ #393（#382 = G30）/ #394（#281 = G10、SYN021 / SYN022 追加）/ #396（#358 = G26 の BP003 最新 major 比較）/ #397（SEC016 の暗黙キャッシュと PERF001 の逆向き助言の抑制）/ #400（Zig 0.16 移行と `std.Io` 採用）/ #401（0.0.1-rc.2 へのバージョン更新）/ #404 / #405（ファズキャンペーンによるパーサ・スパン・fix エンジンの修正と #403 の memset 除去）/ #407（引用状態の再走査を最終行だけに絞る YAML パーサの性能修正）/ #408（#402 のネットワーク fail fast とリクエスト単位の予算）/ #423（リリース版を 0.0.1 へ）はマージ済みである。本ロードマップの #207 は `3951cc7` でマージ済みで、以後の同期はこのブランチが引き継ぐ。#362（#284 = G13）/ #363（#359 / #360 = G27 / G28）/ #365（性能最適化）/ #371（ファズドライバと #364〜#370 の起票）/ #373（#270 = bench 運用ループ）/ #374（install.sh と Homebrew tap）/ #376（#366 = taint テーブル溢れ）/ #377（perf bench に ghalint / octoscan / poutine / action-validator を追加）/ #379（SEC013 の GHCR login と BP007 の PowerShell 代入の FP、G29 の起票）/ #385（G30〜G32 の起票）/ #387（G33 の起票）/ #380（#367〜#370 の span 逆転と fix 非収束）/ #389（G31〜G33 = #383 #384 #386）/ #390（#364 の空セクション）/ #391（D6 = #372 の SC003 / SC005 / Release / skip 注記）が新たにマージされた。#306 は別セッションの PR のため本 PR からは触らない |
| オープン issue | 28 件。内訳は v0.2.0 の GitHub Actions 最新仕様追従（GA0〜GA14 = #427〜#441）が 15 件、autofix 第 2 波（AF6〜AF14 = #409〜#417）が 9 件、ドッグフーディング由来の検出バグ（#419 = G36、#421 = G37、#424 = G38、#425 = G39）が 4 件である。#427 が GA トラックの追跡 issue で、第 1 段階の P0 4 件（#428 = `cache-mode` / `permissions.vulnerability-alerts` / `job.workflow_*` の受理と意味検証、#429 = EXPR005 が `case()` の偶数引数を通す、#430 = RUNNER001 が廃止済み macos-13 を current 扱いし autofix 先にもする、#431 = 比較基準の actionlint 1.7.12 / zizmor 1.30.1 への更新）が v0.2.0 の必須で、第 2 段階は `background` / `wait` / `parallel` の実行モデル（#432 / #433）、第 3 段階は cache / action の capability モデル（#434〜#438）、第 4 段階は追従漏れを防ぐ基盤（#439〜#441）である。P0 の 4 件は本ブランチの main 同期状態で実装を確認済みで、`expr_catalog.zig` の `case` は `min_args = 3` / `max_args = 255` の範囲判定しか持たず偶数を通し、`runner.zig` の `known_labels` は `macos-13` を既定の `.current` のまま置き、`macos-11` / `macos-12` の `replacement` もそこを指す。`cache-mode` と `permissions.vulnerability-alerts` は語彙に無く、`job.workflow_ref` / `workflow_sha` は `expr_catalog.zig` に型だけある。いずれも未解決のため触っていない。#409 が autofix の追跡 issue で、P1 の 4 件（#410 = EXPR002 / EXPR003 / EXPR004 の did-you-mean rename、#411 = ACT001 composite の `shell:` 挿入、#412 = SYN012 排他フィルタの後勝ちキー削除、#413 = SEC014 bot 判定の `sender.type` 比較）は既存の `rename` / `insertMappingEntry` / 式バイトオフセットで閉じ、通常 lint の壁時間と RSS を動かさない。残る 4 件は #414（SEC010 の `secrets: inherit` 展開）、#415（SC003 の `patched_version` へ bump）、#416（SEC002 の github-script `script:`）、#417（SC001 のコンテナイメージ digest ピン）で、後 2 件は JS 書き換えとレジストリ I/O のため別 ADR を要する。`--fix` / `--fix-unsafe` を持つのは現在 100 ルール中 49 である。#419 は SEC002 が `startsWith` などの真偽値関数の結果だけを `run:` へ展開する形にも発火する FP で、#421 は plain scalar の行継続を YAML トークナイザが読まないため、行をまたぐ `${{ }}` を EXPR001 にし、継続行側の汚染源を SEC002 が見落とす。#424 は `pull_requests[0]` のようなコンテキストパス上の数値インデックスを EXPR001 にする FP で、#425 はローカル `uses:` のパスセグメント名 `@scope` を `@ref` と誤認して DEP003 にする FP である。4 件とも `zig-out/bin/zghalint --quick` で再現する。issue を持たない追跡対象は SEC016 の暗黙キャッシュ FN だけである |
| 配布 | `install.sh`（`curl | sh` で GitHub Release から取得）と Homebrew tap（`brew install watany-dev/tap/zghalint`）が PR #374 で入った。tap は release ワークフローが `scripts/gen-homebrew-formula.sh` で更新し、`-rc.` のプレリリースは反映しないため、0.0.1 が最初に tap へ載る版になる。release は provenance attestation とバイナリスモークを持つ |
| 性能 | PR #365 が ReleaseFast のプロファイルからホットパスを削った——SEC002 の `${{` / `}}` 探索をベクトル化した `indexOfScalarPos` に、`pathMatchesPattern` を先頭バイトでの事前棄却つきに、taint 伝播の固定点を outputs を持つジョブだけに、SEC003 の秘密プレフィックス探索を 1 走査に、`didYouMean` を有界 Levenshtein の早期打ち切りに、cron の `nextAfter` を分単位から境界スキップに、terminal の `writeSanitized` を 16 バイト単位の読み飛ばしに、CA バンドル読込を最初の fetch まで遅延させた。`zig build -Dstrip` で Release でもシンボルを残せる。`c802c7f` が Zig 0.16 で顕在化した memset を潰した（#403）——`= undefined` の既定値を 4 つの固定容量バッファから外して構築側で明示し、`walkJobTaint` の 1 KiB 構造体コピーを生きた前置分だけの `TaintedNames.derive` に置き換えた。callgrind で memset が 149.6 万 Ir（2.83%）から 58.6 万 Ir（1.13%）へ、総命令数が 5288 万から 5193 万へ下がり、`parseContextPath` と `walkJobTaint` は memset の呼び出し元から消えている。PR #407 は `--fix` 用のエントリ範囲取得がエントリ先頭から引用状態を全部再走査していた分を削った——子を持つブロックマッピング / シーケンスは引用の開閉を最後の子の `extent` に折り込み済みなので触らず、フローとスカラーだけ自分の最終行を見る。hyperfine 10+3 の many-small が 123.9 ms から 102.2 ms へ戻り、rc2 比の増分は 33% から約 9% になった。残る 9% は sibling clamp と workflow パーサの型不一致分岐で、ファズ修正が持ち込んだ正しさの対価である |
| バージョン定義 | Zig の版は `build.zig.zon` の `minimum_zig_version` 一箇所が真で、現在は 0.16.0。リリース版は 0.0.1（PR #423 が `-rc.2` を外した）。参照側の一覧と更新手順は `docs/maintenance.md`（#236） |
| 既知バグ | 未修正は #419 / #421 / #424 / #425 / #429 / #430 の 6 件である。前 4 件はドッグフーディングが実運用の CI から掘り出した検出バグ、後 2 件は仕様追従の遅れから来る検出漏れで、#429 は EXPR005 が `case()` の偶数引数を通す FN、#430 は RUNNER001 が廃止済みの `macos-13` を current 扱いし、`macos-11` / `macos-12` の `--fix` 先にもする FN と誤修正の同居である。#419 は真偽値関数の結果だけが `run:` に届く形でも SEC002 が出る FP、#421 は plain scalar の行継続を読まないことによる EXPR001 の FP と SEC002 の FN の同居で、後者はパーサ側の欠落である。#424 は `parseContextAccess` がブラケット内を文字列リテラルに限る FP、#425 は `actionProblem` がローカル参照中の `@` を位置に関係なく ref とみなす FP で、どちらも 1 条件の緩和で閉じる。#402 は PR #408 が閉じた——`engine` がネットワーク期限からリクエスト単位の予算を導き、`http_client` が最初の transport 失敗で fail fast して in-flight のソケットを落とし、`prefetch` は到達不能を検出したら REST フォールバックを飛ばす。パケットを落とすプロキシ越しの `--no-cache` 実行が 134.5 秒から 5.1 秒になる。#399 も解決済みで、issue の最小入力 3 本と `--iterations 1000 --seed 42` のキャンペーンが 0 failures になる。ファズ由来の先行 6 件（#364 / #366〜#370）も同様である。クラッシュ（#366）も `--fix` がワークフローを壊す 3 件（#368〜#370）もspan 逆転（#367）も空セクションでの lint 不能（#364）も潰れており、形式検証由来の反例と PR #261 で直した 7 件も同様である |

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
| #135 SC007 typosquat 検出 | 完了（close 済み、PR #339）。`src/rules/data/trusted_actions.zig` の信頼 action 表と `util.levenshteinDistance` で編集距離 1〜2 の owner 一致リポジトリを警告する。ネットワーク不要でオフラインに完結し、`--fix` は付けていない（誤った action への自動書き換えは危険なため `fix_hint` のみ） |
| ベンチマーク #262 — 完了 | zghalint / actionlint / zizmor を三者比較し、改善課題を継続的に洗い出す umbrella。sub-issue 19 件が全て close したため umbrella ごと close した。基盤（#263）は PR #272、ケース A〜D（#264）は PR #277、ケース E〜J（#265〜#267）と FN 候補の検証（#271）は PR #287、性能計測（#268）は PR #296、autofix 交差検証（#269）は PR #345 で着地している。最後に残った運用ループ（#270）は PR #373 で着地し、`bench/baseline.json` に採点を固定する `scripts/bench_gate.py`、意図した autofix 増加を宣言する `# bench:fix-allow`、週次で 3 モードを回す `.github/workflows/bench.yml` が揃った。gap 洗い出しの役目は週次 bench とドッグフーディングへ移る |
| bench 由来の parity gap #280〜#286 / #297〜#300 / #304 #305 / #346〜#349 / #358〜#360 | bench と実コーパスで出た FP・FN・実行エラーを `docs/design/external-linter-parity.md` の G9〜G28 として起票したもの。**残るのは #281（G10、`needs:` の未知 job と循環）と #358（G26、BP003 が第三者アクションの古い major を見逃す）の 2 本だけ**になった。#284（G13、中身のないワークフロー）は PR #362 の新ルール SYN020 `empty-workflow`（error / syntax、fix なし）で診断として返るようになり、bench に残る唯一の実行エラーが消えた。#359（G27、動的マトリクスの include で EXPR011 が誤検出）と #360（G28、値の位置の `||` / `&&` を EXPR007 が条件と見なす）は PR #363 で解消した。#286（G15）は PR #361 の SEC023 `use-trusted-publishing`（ADR-0014）、#305（G21）は PR #317、#304（G20）は PR #316 で `src/rules/net_status.zig` が判定できなかったルールを stderr の注記で伝えるようになった。パーサ層の #293 = #297 / #298（G16 / G17）は PR #302、BP001 の reusable workflow 誤検出（G18 = #299）と fix エンジンの二重挿入（G19 = #300）は PR #303、#285（G14、PERM001 の過剰警告）は PR #291、#280（G9）は PR #292、#282（G11、UTF-8 BOM）は PR #288、#283（G12、ドキュメントマーカー）は PR #289、A〜D 由来の G5〜G8（#273〜#276）は PR #278 で解消した。autofix 交差検証から出た G22〜G25（#346〜#349）は PR #354 / #357 で片付いている。`docs/design/external-linter-parity.md` は G1〜G35 まで追記が追いつき、G36〜G39 は PR #420 / #422 / #426 が起票の形で待っている |
| ドッグフーディング #333〜#337（D1〜D5）/ #372 #375（D6 / D7）— 完了 | 実リポジトリの `.github/workflows` に zghalint をかけて出た FP とノイズ。D1（#333、EXPR006 の配列 `contains()` 誤検知）は PR #340、D2（#334、PERM002 が workflow-level の `permissions` を無視する）は PR #341、D4（#336、HTTP proxy 環境で SC003 / SC004 / SC005 / SC008 が全て skip される）は PR #342、D3（#335、SEC015 と SEC018 の重複）は PR #351、D5（#337、BP002 が `uses` のみの step にも出る）は PR #352 で解消し、D1〜D5 は全て close 済み。D6（#372、SC003 の SHA ピン誤検知 / SC005 の annotated tag / Release 資産欠落）は PR #391、D7（#375、EXPR007 の値 ternary / BP007 の process substitution 見逃し / SEC023 の crates.io）は PR #392 で解消し、どちらも close 済み。続く実運用 CI の三者比較が G36〜G39（#419 / #421 / #424 / #425）を出して 4 件とも未修正で残る。手順は `.claude/skills/doghooding/`（PR #378）に落ちていて、対象 OSS の workflows を取ってきて三者比較にかけ、zghalint 側の穴だけを**匿名化した最小 bench ケースと issue** にする。上流の名前・本文・行番号は成果物に残さない。bench が用意したケースで測るのに対し、こちらは実際の利用体験そのものから出てくる |
| autofix 拡張 #322（AF0〜AF5 = #323〜#327） | `--fix` / `--fix-unsafe` に fix を持つのは 101 ルール中 49 ルール（SC007 / SEC023 / SYN020 は fix を持たない）。#322 が全ルールを ◎ / ○ / △ / × で評価し、基盤 1 本あたりの解決ルール数で順を付けた。AF1（#323）は PR #328 で着地し、`src/rules/rename.zig` が did-you-mean 候補を safe な rename fix に変換して SYN001 / SYN009 / SYN010 / SYN016 / SYN019、EXPR010〜EXPR014、PERM003、ACT002 / ACT003 / ACT005、DEP004 / DEP005、RW003 / RW004 の 18 ルールに `--fix` が付いた。AF3（#325）は PR #329 で着地し、`yaml.Sequence` の `ItemDelete` と `fix.builder.deleteSequenceItems` で SYN008 / SYN018（safe）と SYN011 / PERF002（unsafe）が直せる。AF2（#324）は PR #330 で着地し、`graphql` の tag エイリアスが commit oid を運び `src/rules/sha_pin.zig` が SEC001 / SC006 に SHA ピン止め fix を出す（書き換えで意味が変わる場合は抑制）。AF4（#326、挿入系 = BP008 / RW001 / ACT001）と AF5（#327、SEC002 / SEC008 / SEC019 の untrusted 式を `env:` へ束縛する fix）は PR #353 でまとめて着地した——BP008 は `::set-output` 等を環境ファイル書き込みへ置き換える safe な fix、ACT001 / RW001 / SEC002 / SEC008 / SEC019 は値を推論・プレースホルダで補うため unsafe。逆に BP002 は D5（#337、PR #352）で `uses` のみの step を見なくなり、そこに付いていた fix が無くなっている。#322 と #323〜#327 は全て close 済みで、ファズ由来の fix 欠陥 3 件——#368（挿入位置が `on:` ブロックの途中に落ちる）・#369（EXPR010 の rename が収束しない）・#370（SEC019 の persist-credentials が無限に追記する）——も PR #380 で解消した。続く autofix 第 2 波は #409（AF6〜AF14）が追跡する |
| GitHub Actions 仕様追従 #427（GA0〜GA14 = #428〜#441） | 2026-09-11 の仕様追従レポート（調査範囲 2024-09-11〜2026-09-11、比較対象 actionlint 1.7.12 / zizmor 1.30.1 / ghalint 1.5.6）から起票された v0.2.0 の umbrella。狙いはルール数を増やすことではなく、正しい新構文を誤検出しないこと・受理した構文を最後まで検査すること・古い知識に基づく誤修正をなくすことの 3 点である。第 1 段階の P0（#428〜#431）が v0.2.0 の必須で、`cache-mode` / `permissions.vulnerability-alerts` / `job.workflow_*` の受理と意味検証、EXPR005 の `case()` 奇数引数、RUNNER001 の macos-13 retired 化と replacement 不変条件、比較基準バージョンの更新からなる。第 2 段階（#432 / #433）は `background` / `wait` / `parallel` の AST と再帰 lint 走査、および未同期 background 出力参照の検出で、`types.zig` / `parser.zig` を直列に触る。第 3 段階（#434〜#438）は cache / checkout を capability として持ち、SEC016 と PERF001 の判定をその上へ寄せた上で、setup-node の自動キャッシュ・node20 の deprecated 診断・`concurrency.queue` の矛盾検出を足す。第 4 段階（#439〜#441）は未対応 YAML merge key・`prefer-self-repository`・仕様追従用フィクスチャカタログで、追従漏れ自体を検出する側の整備である。意味が変わる書き換えは `--fix` にしない方針が umbrella に明記されている |
| 形式手法 #307（F0〜F7 = #308〜#314） | `scripts/formal/` が Z3 の有界モデル検査で SEC ルールの表の抜け漏れを列挙し（`model.py`）、実バイナリで確認する（`confirm.py`）。設計は `docs/design/formal-rule-model.md`。基盤は PR #315 で着地し、F1〜F7（#308〜#314）は PR #338 で全て解消した——SEC005 に `pull_request.merge_commit_sha`、SEC009 に `github.event.workflow_run.pull_requests`、SEC002 / SEC006 / SEC008 に `head.repo.description` / `.homepage` と `*.committer.*` が加わり、SEC021 の ChatOps 判定と SEC002 の env / job outputs 1 ホップ追跡も入った。追跡 issue #307 も PR #355 で close した。`ca923a9` の表分割（`dispatched_inputs_contexts` → `bare_inputs_contexts` + `dispatch_payload_table`）に抽出器が追随できず `LookupError` で落ちていたのを直し、同時に腐敗を検出する経路を CI（`.github/workflows/ci.yml` の "Formal extractor still finds the tables" が z3 なしで `scripts/formal/impl.py` を実行する）と PBT（`tests/pbt/test_formal_extractor.py`）の両方に入れた。`model.py` は現在 P4 の証人 1 件（`workflow_call` + `inputs.*`）を出すのみ。bench が実ワークフローから経験的に穴を探すのに対し、こちらは表の定義から網羅的に探す |
| PR #217 形式仕様 | Alloy（ルール所有権）と TLA+（prefetch / autofix）の仕様と反例。#218〜#224 の出所で、指摘はすべて修正済み。マージすれば以後の反例追加が同じ場所に載る |
| リポジトリ運用・CI 基盤（旧 #230 #234〜#244） | 12 件すべて実装済み・close 済み（Dependabot / PBT 依存固定 / Zig 版一元化 / coverage / concurrency / 外部静的解析 / ファズ / 自リポジトリ dogfooding / action.yml スモーク / メタファイル / release provenance / タグ整合 / `docs/rules.md` 同期テスト）。track として終了 |

## 3. 直近の着手順（上位 5 件）

| 順 | 対象 | 理由 |
|---|---|---|
| 1 | #421（G37） | 唯一の検出漏れを含むドッグフーディング由来のバグ。`src/yaml/tokenizer.zig` の `scanPlainScalar` と `skipExpressionInterpolation` が plain scalar の行継続を読まないため、正当な式を EXPR001 にし、継続行側の汚染源を SEC002 が見落とす。FP と FN の両方が同じ欠落から出るので、直す価値が最も高い |
| 2 | #429 / #430（GA2 / GA3） | v0.2.0 必須の P0 のうち、データとシグネチャの更新だけで閉じる 2 本。`case` の引数個数を範囲判定から奇数判定へ変え、runner カタログの `macos-13` を retired にして replacement を current へ付け替える。`--fix` が廃止済みランナーへ誘導する誤修正も同時に消える |
| 3 | #424 / #425（G38 / G39） | どちらも 1 条件の緩和で閉じる FP。`parseContextAccess` がブラケット内を文字列リテラルに限っている分を数値まで広げ、`actionProblem` がローカル参照中の `@` を位置に関係なく ref とみなす分をセグメント先頭だけ除外する。既存の受理範囲を狭めない |
| 4 | #419（G36） | SEC002 が `startsWith` / `endsWith` / `contains` の真偽値だけを `run:` へ展開する形にも発火する FP。同じ切り分けは SEC006 が `if:` に対して既に持っており、`containsAnyContext` の呼び出し側を絞れば閉じる。パーサに触らない |
| 5 | #428 / #431（GA1 / GA4） | P0 の残り 2 本。`cache-mode` / `permissions.vulnerability-alerts` / `job.workflow_*` を語彙へ入れて意味まで検査する分はスキーマ側の直列変更で、比較基準の actionlint 1.7.12 / zizmor 1.30.1 への更新は bench 環境の更新と再採点で足りる |

v0.2.0 の GitHub Actions 仕様追従（#427 = GA0）は 14 本の子 issue を持ち、第 1 段階の P0 4 件（#428〜#431）だけがリリースの必須である。
第 2 段階の `background` / `wait` / `parallel`（#432 / #433）は AST と再帰走査の新設で、`types.zig` と `parser.zig` を直列に触る最大の塊になる。
第 3 段階（#434〜#438）は cache と action を capability として持ち、SEC016 / PERF001 の重複判定をその上へ寄せる。
第 4 段階（#439〜#441）は merge key の非対応検出・`prefer-self-repository`・仕様追従用フィクスチャカタログで、追従漏れ自体を検出する側の整備である。
方針は誤検出ゼロを優先し、意味が変わる書き換え（wait 自動挿入、`./` → `$/`、`node20` → `node24`、`case()` の fallback 生成）は `--fix` にしない。

autofix 第 2 波の残りは 4 本ある。#412 / #413（AF9 / AF10）は `--fix-unsafe` 側で、SYN012 のマッピング要素削除と SEC014 の `==` / `!=` 書き換えで足りる。
続く #414（SEC010 の `secrets: inherit` 展開）はローカル完結、#415（SC003 の `patched_version` へ bump）は `--fix` 時に追加 GraphQL を引くが Advisory 型が bump 先を既に持つ。
#416（SEC002 の github-script `script:`）と #417（SC001 のイメージ digest ピン）は現行 autofix エンジンの延長ではない。
前者は `run:` とは別設計の JS 書き換え、後者は GHCR / Docker Hub への新規ネットワークで、いずれも別 ADR を先に置く。
ドキュメント PR の #217（形式仕様とモデル検査）と #306（bench 全モードの再実行記録）は最後に残る。
#306 は別セッションの PR のため本 PR からは触らない。

Zig 0.16.0 への移行は PR #400 / #401 で完了し、`std.Io` のファイル / ディレクトリ API、
`std.process.Init` による CLI 資源、`std.testing.Smith` のファズ API へ乗り換えた。
探索実行の `zig build fuzz --fuzz` が起動するようになり、長時間キャンペーンの経路が 1 本増えた。
移行後に上がった 3 件（#399 / #402 / #403）はいずれも閉じている。

parity doc（`docs/design/external-linter-parity.md`）は main では G1〜G35 まで記録が追いつき、G36〜G39 は PR #420 / #422 / #426 が起票の形で待っている。
`bench/baseline.json` の数値と経緯の記録が同じ地点に並んでいる。

Phase 1〜4 はすべて閉じ、ルール追加の主戦場は #55 から bench（#262）へ移り、その bench も閉じた。
採点は全カテゴリを覆って recall 100%（116/116）・precision 100%・位置一致 97%、実行エラー 0 件で、
`bench/baseline.json` と `scripts/bench_gate.py` が回帰を落とす形で常設化されている。
baseline に既知 gap は残っておらず、bench は穴を探す道具から回帰を止める道具へ役割を移した。

**穴を探す役目は経験的な bench から、ファズ・形式手法・ドッグフーディングの 3 経路へ完全に移った。**
形式手法は F1〜F7 を PR #338 で出し切って SEC 表の抜けを 7 件埋め、その PR 自身が壊した抽出器も PR #355 で直って
CI と PBT の両方から回るようになった。ドッグフーディングは D1〜D5 を片付けた後、D6（#372）を PR #391 で、
D7（#375）を PR #392 で閉じ、続く実運用 CI の三者比較が G36〜G39（#419 / #421 / #424 / #425）を出して 4 件とも未修正で残る。
PR #378 で `doghooding` スキルとして手順が固定され、PR #385 / #387 がその手順どおり G30〜G33 を起票し、
PR #389 / #393 がそれを全て潰した。
そしてファズが最も鋭い——PR #371 の単体ドライバは 1 回のキャンペーンで 6 件（#364 / #366〜#370）を掘り出し、
そのうち 1 件は Release ビルドでのみ落ちるクラッシュ、3 件は `--fix` がワークフローを壊す欠陥だった。
`bench/cases/` の交差検証も形式手法も、この 3 件の fix 欠陥を見つけられていない。
**6 件は PR #376 / #380 / #390 で全て片付き、続く追加キャンペーンが出した #399 も PR #404 / #405 で閉じた。**
#399 は片方の PR だけでは再現が消えず、パーサ側の型エラー化とスパン修正、fix エンジン側の「ソースに合わない edit は fix ごと捨てる」変更が
両方揃った合流点で初めて 3 本の最小入力が通るようになった。
PR #380 が E2E ハーネスへ span の非逆転と fix の不動点を全フィクスチャ共通の不変条件として足したので、
ファズが見つけた性質の一部は通常のテストからも守られるようになった。

SEC016 は PR #397 で `astral-sh/setup-uv` のような setup-* アクションが既定で有効にするキャッシュを見るようになり、
同時に PERF001 がリリース / デプロイのジョブで `enable-cache: false` を指摘しないよう狭められた。
2 つのルールが逆向きの助言を出す衝突を、片方の抑制で解いた形である。

検出と autofix が一段落したことで、配布（PR #374 の `install.sh` と Homebrew tap）と
GitHub Actions 以外への展開（PR #320 の v0.2 マルチ CI ロードマップ）が次の軸として重なる。
release ワークフローは PR #391 で、既に Release があるタグへもアセットを揃えて upload するようになった。
性能側は PR #377 で ghalint / octoscan / poutine / action-validator まで計測対象が広がり、
比較の基準が actionlint / zizmor の 2 本から実質 6 本になった。

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
