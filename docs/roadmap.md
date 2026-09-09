# 実施ロードマップ（2026-09-09 時点）

オープンな PR / issue を main（`1da00fc`）の実装状況と突き合わせ、以後の実施順序を示す。
経緯や前版との差分は git log と PR #130 / #207 の履歴に残しているため、本書には現在形の内容だけを書く。

## 1. 現状サマリ

| 項目 | 状態 |
|---|---|
| ルール数 | `docs/rules.md` の表は 101 行（SYN020 追加分）で `registry.all_rules` と一致。`src/docs_sync_test.zig`（#242）が ID の欠落・余剰を両方向でテストする。長く残っていた見出しの「92 rules」は本回で 101 に直したため、本文と表の不一致はなくなった。ただし同期テストは今も ID 集合しか見ないので、見出しの数字は手で守る |
| `src/**/*.zig` | 58,848 行 |
| ユニットテスト | 1981 件（`zig build test` 緑）。#331 で低品質なテストの削除とテーブル駆動化を行った上で（PR #332）、SC007・ドッグフーディング・形式手法・autofix 拡張・fix の衝突修正・SEC023・SYN020・EXPR007 / EXPR011 の誤検出修正・性能最適化の分が積み増している |
| #55 actionlint parity | 54 sub-issue 中 **54 close 済み（100%）**。umbrella #55 本体も close 済み |
| 型検査エンジン | T0〜T4 完了（#129 は PR #256 で overlay 接続、close 済み）。EXPR018 引数型検査（#162）も同 PR で完了・close 済み |
| E2E テスト | `src/e2e_test.zig` が `tests/fixtures/e2e/*.yml`（70 本）と `tests/fixtures/e2e-action/*.yml`（8 本）の `# zghalint:expect RULE@line` / `forbid` コメントを読んで検証。兄弟ファイル `<name>.fixed` / `<name>.fixed-unsafe` を置いたフィクスチャは `--fix` / `--fix-unsafe` 適用後のバイト列も固定する（PR #328、現在 11 本） |
| bench | `bench/cases/` に 142 ファイル（複数ファイルのケースをまとめて 137 ケース）。A〜D は PR #277、E〜J は PR #287 で揃い、G16 / G17 の堅牢性ケース 3 本が PR #301、G21 の再現ケース 1 本が PR #317、G25 の再現ケース 1 本が PR #357 で加わった。`scripts/bench.py` の採点で zghalint は recall 99%（111/112）・位置一致 96%（107/112）、実行エラー 0 件（#284 の実行エラーは SYN020 で解消）。FN 1（G30 = #382、`matrix-object-property-undeclared`）と FP 2（G31 = #383 の `self-repository-prefix`、G32 = #384 の `ubuntu-slim-runner`）が本回 `bench/baseline.json` に記録された——実運用 CI の三者比較（PR #385）で出た穴で、記録した時点が「既知の gap」であって回帰ではない。外部ツール未導入の環境では zghalint 単独で採点する。採点結果は `bench/baseline.json` に固定し、`scripts/bench_gate.py` が回帰を非ゼロ終了で落とす（#270、PR #373）。`.github/workflows/bench.yml` が週次で 3 モードを回して parity doc へ流す。`--perf`（`scripts/bench_perf.py`）が wall time と最大 RSS を 4 シナリオで測り、実ワークフローのコーパスは `scripts/fetch-corpus.py` が取得する（#268、PR #296）。`--fix`（`scripts/bench_fix.py`）は autofix 交差検証で、非冪等 0 / YAML 破損 0 / コメント欠落 0。意図した増加は各ケースの `# bench:fix-allow <flag> <tool>=<ID> <理由>` で宣言し、宣言のないものだけが問題として残る（#269、PR #345、宣言形式は PR #373）。PR #356 が §4.6 の性能表を無効と判定した——zghalint 列が Debug ビルド、actionlint 列が shellcheck 無しという二重の環境差で、ReleaseFast + shellcheck ありで測り直した §4.7 では §4.5 と同じ水準（wall time で 15〜60 倍、RSS で 6〜23 倍の差）に戻る |
| PBT（`tests/pbt/`） | 42 個の `@given`、xfail 0 件。依存は固定済み（#235） |
| ファズ | `src/fuzz_test.zig` が YAML パーサと式パーサのターゲットを持ち、CI で回る（#241）。長時間キャンペーン用に `src/fuzz_driver.zig` が単体ドライバとして立ち、PR #371 で入った。探索実行（`zig build fuzz --fuzz`）は Zig 0.15.2 のファザ側の不具合で動かず、シード資産の再生のみ（`docs/design/pbt-strategy.md` §6-4）。この経路が #364 / #366〜#370 の 6 件を掘り出し、うち #366 は PR #376 で解決した |
| ADR | `docs/adr/0001`〜`0014`（0012 は RUNNER002 matrix 展開、0013 は RUNNER003、0014 は SEC023 trusted publishing） |
| オープン PR | #217（形式仕様とモデル検査）・#306（bench 再実行記録）・#380（#367〜#370 の span 逆転と fix 非収束を 4 件まとめて直す）の 3 本。本ロードマップの #207 は `3951cc7` でマージ済みで、以後の同期はこのブランチが引き継ぐ。#362（#284 = G13）/ #363（#359 / #360 = G27 / G28）/ #365（性能最適化）/ #371（ファズドライバと #364〜#370 の起票）/ #373（#270 = bench 運用ループ）/ #374（install.sh と Homebrew tap）/ #376（#366 = taint テーブル溢れ）/ #377（perf bench に ghalint / octoscan / poutine / action-validator を追加）/ #379（SEC013 の GHCR login と BP007 の PowerShell 代入の FP、G29 の起票）/ #385（実運用 CI の三者比較から G30〜G32 を起票）が新たにマージされた。#306 は別セッションの PR のため本 PR からは触らない |
| オープン issue | 13 件。内訳はファズ由来の未修正バグ 5（#364 / #367〜#370、うち #367〜#370 は PR #380 で対処中）、ドッグフーディング D6 / D7（#372 / #375）、bench 由来の parity gap 5（#281 = G10、#358 = G26、#382 = G30、#383 = G31、#384 = G32）、および bot が立てた本文「ignore」の #381（実体のない試験用で対象外）。#366 は PR #376 の `37588ef` が `ContextSet` へ畳んで重複 append を無視する形にしたため、ReleaseFast で重複 10 件・40 件・`repository_dispatch` 4 件を再現確認した上で本回 close した。ベンチマーク umbrella #262 は sub-issue 19 件が全て close したため本回で close し、#284（G13）は SYN020 の着地で、#360（G28）は EXPR007 の修正で本回 close した。#55 #64 #135 #159 #262〜#271 #273〜#276 #280 #282〜#286 #293 #294 #297〜#300 #304 #305 #307〜#314 #322〜#327 #331 #333〜#337 #346〜#349 #359 #360 #284 は実装済みのため close 済み |
| 配布 | `install.sh`（`curl | sh` で GitHub Release から取得）と Homebrew tap（`brew install watany-dev/tap/zghalint`）が PR #374 で入った。tap は release ワークフローが `scripts/gen-homebrew-formula.sh` で更新し、`-rc.` のプレリリースは反映しない。release は provenance attestation とバイナリスモークを持つ |
| 性能 | PR #365 が ReleaseFast のプロファイルからホットパスを削った——SEC002 の `${{` / `}}` 探索をベクトル化した `indexOfScalarPos` に、`pathMatchesPattern` を先頭バイトでの事前棄却つきに、taint 伝播の固定点を outputs を持つジョブだけに、SEC003 の秘密プレフィックス探索を 1 走査に、`didYouMean` を有界 Levenshtein の早期打ち切りに、cron の `nextAfter` を分単位から境界スキップに、terminal の `writeSanitized` を 16 バイト単位の読み飛ばしに、CA バンドル読込を最初の fetch まで遅延させた。`zig build -Dstrip` で Release でもシンボルを残せる |
| バージョン定義 | Zig の版は `build.zig.zon` の `minimum_zig_version` 一箇所が真。参照側の一覧と更新手順は `docs/maintenance.md`（#236） |
| 既知バグ | ファズ由来の 5 件が未修正。クラッシュ（#366）は解消したため、残りは全て診断品質と書き換えの問題である。**#364**（空の `permissions:` / `concurrency:` でファイル全体が lint 不能）と **#367**（マージキー `<<:` で診断の span が逆転する）が入力側、**#368**（SEC007 / BP005 の挿入が `on:` ブロックの途中に落ちて `--fix-unsafe` がワークフローを壊す）・**#369**（EXPR010 の rename fix が収束せず式が伸び続ける）・**#370**（SEC019 の persist-credentials fix が `with:` 非マッピングで無限に追記する）が fix 側。形式検証由来の反例と PR #261 で直した 7 件はすべて解消済み。#367〜#370 の 4 件は PR #380 が同時に扱っている |

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
| bench 由来の parity gap #280〜#286 / #297〜#300 / #304 #305 / #346〜#349 / #358〜#360 | bench と実コーパスで出た FP・FN・実行エラーを `docs/design/external-linter-parity.md` の G9〜G28 として起票したもの。**残るのは #281（G10、`needs:` の未知 job と循環）と #358（G26、BP003 が第三者アクションの古い major を見逃す）の 2 本だけ**になった。#284（G13、中身のないワークフロー）は PR #362 の新ルール SYN020 `empty-workflow`（error / syntax、fix なし）で診断として返るようになり、bench に残る唯一の実行エラーが消えた。#359（G27、動的マトリクスの include で EXPR011 が誤検出）と #360（G28、値の位置の `||` / `&&` を EXPR007 が条件と見なす）は PR #363 で解消した。#286（G15）は PR #361 の SEC023 `use-trusted-publishing`（ADR-0014）、#305（G21）は PR #317、#304（G20）は PR #316 で `src/rules/net_status.zig` が判定できなかったルールを stderr の注記で伝えるようになった。パーサ層の #293 = #297 / #298（G16 / G17）は PR #302、BP001 の reusable workflow 誤検出（G18 = #299）と fix エンジンの二重挿入（G19 = #300）は PR #303、#285（G14、PERM001 の過剰警告）は PR #291、#280（G9）は PR #292、#282（G11、UTF-8 BOM）は PR #288、#283（G12、ドキュメントマーカー）は PR #289、A〜D 由来の G5〜G8（#273〜#276）は PR #278 で解消した。autofix 交差検証から出た G22〜G25（#346〜#349）は PR #354 / #357 で片付いている。**`docs/design/external-linter-parity.md` は G25 までしか書かれておらず、G26〜G28 の 3 本が未追記のまま残っている** |
| ドッグフーディング #333〜#337（D1〜D5）— 完了 / #372 #375（D6 / D7）— 未着手 | 実リポジトリの `.github/workflows` に zghalint をかけて出た FP とノイズ。D1（#333、EXPR006 の配列 `contains()` 誤検知）は PR #340、D2（#334、PERM002 が workflow-level の `permissions` を無視する）は PR #341、D4（#336、HTTP proxy 環境で SC003 / SC004 / SC005 / SC008 が全て skip される）は PR #342、D3（#335、SEC015 と SEC018 の重複）は PR #351、D5（#337、BP002 が `uses` のみの step にも出る）は PR #352 で解消し、D1〜D5 は全て close 済み。新たに D6（#372、chokkin — SC003 の SHA ピン誤検知 / SC005 の annotated tag / Release 資産欠落）と D7（#375、ptuf — EXPR007 の値 ternary / BP007 の process substitution 見逃し / SEC023 の crates.io）が上がっており、どちらも未着手。手順は `.claude/skills/doghooding/`（PR #378）に落ちていて、対象 OSS の workflows を取ってきて三者比較にかけ、zghalint 側の穴だけを**匿名化した最小 bench ケースと issue** にする。上流の名前・本文・行番号は成果物に残さない。bench が用意したケースで測るのに対し、こちらは実際の利用体験そのものから出てくる |
| autofix 拡張 #322（AF0〜AF5 = #323〜#327） | `--fix` / `--fix-unsafe` に fix を持つのは 101 ルール中 49 ルール（SC007 / SEC023 / SYN020 は fix を持たない）。#322 が全ルールを ◎ / ○ / △ / × で評価し、基盤 1 本あたりの解決ルール数で順を付けた。AF1（#323）は PR #328 で着地し、`src/rules/rename.zig` が did-you-mean 候補を safe な rename fix に変換して SYN001 / SYN009 / SYN010 / SYN016 / SYN019、EXPR010〜EXPR014、PERM003、ACT002 / ACT003 / ACT005、DEP004 / DEP005、RW003 / RW004 の 18 ルールに `--fix` が付いた。AF3（#325）は PR #329 で着地し、`yaml.Sequence` の `ItemDelete` と `fix.builder.deleteSequenceItems` で SYN008 / SYN018（safe）と SYN011 / PERF002（unsafe）が直せる。AF2（#324）は PR #330 で着地し、`graphql` の tag エイリアスが commit oid を運び `src/rules/sha_pin.zig` が SEC001 / SC006 に SHA ピン止め fix を出す（書き換えで意味が変わる場合は抑制）。AF4（#326、挿入系 = BP008 / RW001 / ACT001）と AF5（#327、SEC002 / SEC008 / SEC019 の untrusted 式を `env:` へ束縛する fix）は PR #353 でまとめて着地した——BP008 は `::set-output` 等を環境ファイル書き込みへ置き換える safe な fix、ACT001 / RW001 / SEC002 / SEC008 / SEC019 は値を推論・プレースホルダで補うため unsafe。逆に BP002 は D5（#337、PR #352）で `uses` のみの step を見なくなり、そこに付いていた fix が無くなっている。#322 と #323〜#327 は全て close 済みだが、**fix の正しさには未修正の欠陥が 3 件残る**——#368（挿入位置が `on:` ブロックの途中に落ちる）・#369（EXPR010 の rename が収束しない）・#370（SEC019 の persist-credentials が無限に追記する）。いずれもファズ由来で、`bench/cases/` の交差検証では出ていない |
| 形式手法 #307（F0〜F7 = #308〜#314） | `scripts/formal/` が Z3 の有界モデル検査で SEC ルールの表の抜け漏れを列挙し（`model.py`）、実バイナリで確認する（`confirm.py`）。設計は `docs/design/formal-rule-model.md`。基盤は PR #315 で着地し、F1〜F7（#308〜#314）は PR #338 で全て解消した——SEC005 に `pull_request.merge_commit_sha`、SEC009 に `github.event.workflow_run.pull_requests`、SEC002 / SEC006 / SEC008 に `head.repo.description` / `.homepage` と `*.committer.*` が加わり、SEC021 の ChatOps 判定と SEC002 の env / job outputs 1 ホップ追跡も入った。追跡 issue #307 も PR #355 で close した。`ca923a9` の表分割（`dispatched_inputs_contexts` → `bare_inputs_contexts` + `dispatch_payload_table`）に抽出器が追随できず `LookupError` で落ちていたのを直し、同時に腐敗を検出する経路を CI（`.github/workflows/ci.yml` の "Formal extractor still finds the tables" が z3 なしで `scripts/formal/impl.py` を実行する）と PBT（`tests/pbt/test_formal_extractor.py`）の両方に入れた。`model.py` は現在 P4 の証人 1 件（`workflow_call` + `inputs.*`）を出すのみ。bench が実ワークフローから経験的に穴を探すのに対し、こちらは表の定義から網羅的に探す |
| PR #217 形式仕様 | Alloy（ルール所有権）と TLA+（prefetch / autofix）の仕様と反例。#218〜#224 の出所で、指摘はすべて修正済み。マージすれば以後の反例追加が同じ場所に載る |
| リポジトリ運用・CI 基盤（旧 #230 #234〜#244） | 12 件すべて実装済み・close 済み（Dependabot / PBT 依存固定 / Zig 版一元化 / coverage / concurrency / 外部静的解析 / ファズ / 自リポジトリ dogfooding / action.yml スモーク / メタファイル / release provenance / タグ整合 / `docs/rules.md` 同期テスト）。track として終了 |

## 3. 直近の着手順（上位 5 件）

| 順 | 対象 | 理由 |
|---|---|---|
| 1 | #368 / #369 / #370 | `--fix` がワークフローを壊す 3 本。#368 は挿入位置が `on:` ブロックの途中に落ち、#369 は EXPR010 の rename が収束せず式が伸び続け、#370 は SEC019 の persist-credentials が `with:` 非マッピングで無限に追記する。壊れた書き換えは誤検出より利用体験を損なう。PR #380 が #367 と併せて 4 件を扱っているので、まずはそのレビューを通す |
| 2 | #364 / #367 | 入力側の 2 本。#364 は空の `permissions:` / `concurrency:` でファイル全体が lint 不能になり（#284 と同じ「ファイルが丸ごと落ちる」系）、#367 はマージキー `<<:` で診断の span が逆転する。#367 は PR #380 に含まれ、#364 だけが手つかずで残る |
| 3 | #382 / #383 / #384（G30〜G32） | 実運用 CI の三者比較で出た新しい gap 3 本。#382 は EXPR011 がオブジェクト軸の未定義プロパティを見ない見逃し、#383 は DEP003 が `$/` の自己参照 `uses` を形式不正と誤判定、#384 は RUNNER002 が `ubuntu-slim` を未知ラベル扱いする。いずれも baseline に記録済みなので、直せば gate がそのまま改善を検知する |
| 4 | #372 / #375（D6 / D7） | 実運用リポジトリから出た FP と見逃し。D6 は SC003 の SHA ピン誤検知・SC005 の annotated tag・Release 資産欠落、D7 は EXPR007 の値 ternary・BP007 の process substitution 見逃し・SEC023 の crates.io。PR #379 が SEC013 の GHCR login と BP007 の PowerShell 代入を先に潰しており、残りが本体 |
| 5 | #281 / #358 | bench 由来で残る旧 parity gap 2 本。#281 は `needs:` の未知 job と循環の検出（ルール追加 1 本）、#358 は BP003 が第三者アクションの古い major を見逃す |

あわせて `docs/design/external-linter-parity.md` へ G26〜G32 を追記する。G25 までしか書かれておらず、
解決済みの G27 / G28 / G29 も未解決の G26 / G30〜G32 もどこにも記録されていない。
`bench/baseline.json` には数値として入っているのに、経緯を残す側が追いついていない状態である。

Phase 1〜4 はすべて閉じ、ルール追加の主戦場は #55 から bench（#262）へ移り、その bench も閉じた。
採点は全カテゴリを覆って recall 99%（111/112）・位置一致 96%、実行エラー 0 件で、
`bench/baseline.json` と `scripts/bench_gate.py` が回帰を落とす形で常設化されている。
本回 FN 1・FP 2 が新たに載ったのは品質低下ではなく、bench が実運用ワークフローを取り込んで
未知の gap を 3 件掘り出したためで、これは gate の設計どおりの動きである。

**穴を探す役目は経験的な bench から、ファズ・形式手法・ドッグフーディングの 3 経路へ完全に移った。**
形式手法は F1〜F7 を PR #338 で出し切って SEC 表の抜けを 7 件埋め、その PR 自身が壊した抽出器も PR #355 で直って
CI と PBT の両方から回るようになった。ドッグフーディングは D1〜D5 を片付けた後、新たに D6 / D7（#372 / #375）を出しており、
PR #378 で `doghooding` スキルとして手順が固定され、PR #385 がその手順どおり G30〜G32 を起票した。
そしてファズが最も鋭い——PR #371 の単体ドライバは 1 回のキャンペーンで 6 件（#364 / #366〜#370）を掘り出し、
そのうち 1 件は Release ビルドでのみ落ちるクラッシュ、3 件は `--fix` がワークフローを壊す欠陥だった。
`bench/cases/` の交差検証も形式手法も、この 3 件の fix 欠陥を見つけられていない。
唯一のクラッシュだった #366 は PR #376 で解決したので、**未修正の 5 件は全て診断品質と書き換えの問題であり、
うち 4 件は PR #380 が扱っている。**

検出と autofix が一段落したことで、配布（PR #374 の `install.sh` と Homebrew tap）と
GitHub Actions 以外への展開（PR #320 の v0.2 マルチ CI ロードマップ）が次の軸として重なる。
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
