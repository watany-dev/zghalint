# 実施ロードマップ（2026-09-04 更新）

オープンな PR / issue を main の実装状況と突き合わせて棚卸しし、以後の実施順序を示す。

## 0. 前版からの差分（Phase 0「整理」は完了）

前版で挙げた棚卸しは全て反映済み。

| 項目 | 結果 |
|---|---|
| #8 / #6 / #11 / #115 | close 済み |
| #25 | close の上、内容は #125 で reland 済み（`Config.strings_arena` による use-after-free 解消、`isValidEdit`、PBT の xfail 3 件解除）→ main `e2cb1f3` |
| #121（SYN003） | マージ済み → `9509e66`。#58 も close |
| #93 / #94 | close 済み。follow-up として #124（curated scalar overlay）と #129（T4 overlay 接続）を起票済み |

したがって残作業は Phase 1 以降と、下記 §2 の新規案件。

## 1. 現状サマリ

| 項目 | 状態 |
|---|---|
| ルール数（`docs/rules.md`） | 58（SYN001〜006 / 008 / 012、EXPR017 を含む） |
| #55 actionlint parity | 53 sub-issue 中 13 完了（#56 #57 #58 #59 #60 #61 #63 #68 #80 #81 #82 #93 #94） |
| 型検査エンジン | T0〜T3 実装済み。T4（overlay 接続）は #129 |
| PBT（`tests/pbt/`） | xfail 0 件（#125 で解消） |
| オープン PR | 4 件（#123 #126 #127 #128）+ 本 PR #130 |

## 2. 最優先: プレーンスカラーの切り詰め（#131 / #132）

Phase 1 の SEC002 拡充より前に潰すべき欠陥が YAML トークナイザにある。

`src/yaml/tokenizer.zig` の `scanPlainScalar` は `,` `[` `]` `{` `}` に当たると常にスカラーを打ち切る。
これらが指示子になるのは YAML の flow context の中だけで、ブロックスタイルの値では本文の一部である。
結果、引用符で囲っていない `run:` / `if:` の値が途中で失われる。

```
in : contains(github.event.issue.title, 'x')
out: contains(github.event.issue.title
in : npm run build -- --flag [x]
out: npm run build -- --flag
```

影響は誤検出ではなく **検出漏れ**。実ファイルで確認した例:

```yaml
- run: echo "${{ github.event.issue.title }}"   # main では SEC002 が出ない
```

`run:` の値が `echo "$` に切り詰められ、式がルールに届いていない。
`run: "..."`（引用）と `run: |`（ブロックスカラー）では正しく検出されるため、
既存のインラインテストはすべて Step 構造体を直接組み立てており、この経路を通っていない。

- 対応 1（暫定）: `${{ ... }}` を丸ごと読み飛ばす。PR #126 / #127 に同等の修正が含まれており、どちらかのマージで解消する
- 対応 2（本命）: flow depth を持ち、flow context の中でのみ `,` `[` `{` を指示子として扱う。`run:` 本文のカンマや角括弧全般に効く
- 併せて: 実ワークフローファイルを入力とする E2E テスト（`tests/` に fixture を置き `zghalint` を通す）を追加する。ユニットテストだけではこの層を検証できない

対応 2 を #131、E2E テストを #132 として起票済み。Phase 1 の先頭に置く。

なお、この確認中に診断の行 / 列がすべて `0:0` になる事象も観測している（`run:` 由来の SEC002 など）。
`src/rules/` に `Span.point(0, 0, 0)` が 51 箇所あり、`Step.run_value_span` などの既存 span が使われていない。#133 として起票済み。

## 3. オープン PR の裁き方

3 本（#126 #127 #128）が同じ `security.zig` の SEC002 周辺を触るため、マージ順を固定しないと三つ巴で競合する。

| PR | issue | CI | main との併合 | 判定 |
|---|---|---|---|---|
| #123 SYN007 env 変数名 | #62 | 緑 | clean | **そのままマージ可**。他 PR と重複なし（`syntax.zig` / `parser.zig` / `types.zig`） |
| #127 SEC002 object filter | #102 | — | clean（main の 2 コミット遅れ） | **最初にマージ**。文字列一致だった `stringContainsContext` をセグメント単位の経路照合に置き換える基盤変更を含む |
| #126 SEC002 untrusted inputs 拡充 | #101 | — | clean（同上） | **#127 の後に rebase**。#127 と同じトークナイザ修正と前方一致ロジックを重複して持つので、rebase 時に `dangerous_contexts` への追加エントリだけを残す |
| #128 SEC002 github-script `script:` | #103 | — | clean（同上） | **#126 の後に rebase**。`checkScriptInjection` の書き換えが #127 と衝突する |

補足:

- #126 と #127 は独立に作られたため、`src/yaml/tokenizer.zig` に**ほぼ同一の** `${{ }}` 読み飛ばし修正が両方入っている（§2 の対応 1）。先にマージした側が採用され、もう一方は rebase で落とす
- #127 の経路照合は `github.event.commits[0].message` と `github.event.commits.*.message` を同一視し、文字列リテラルや `steps.meta.outputs.github.head_ref` のような別コンテキスト配下の同名パスを除外する。#126 の前方一致より厳密なので、こちらを土台にする
- いずれも main より 2 コミット遅れているため、マージ前に rebase する

## 4. ロードマップ

原則:

- 1 issue = 1 PR = 1 ルール。TDD（Red → Green → Refactor）、完了時に `docs/rules.md` へ行追加
- 同一ファイル（`types.zig` / `parser.zig` / `security.zig`）を触る issue は直列にし、rebase 地獄を避ける
- 誤検出ゼロを優先。不確かなものは検出しない（ADR-0006 の方針を全ルールに適用）

### Phase 1: 依存なし・小粒ルール

`types.zig` を触らず、既存の走査ループにチェックを足すだけで済むもの。

| 順 | issue | ルール | 状態 / 触る主なファイル |
|---|---|---|---|
| 0 | #131 | プレーンスカラーの flow context 対応 | §2。他の全ルールの検出率に効くので最優先 |
| 0 | #132 | 実ワークフローを入力とする E2E テスト | §2。#131 の回帰を止める土台 |
| 0 | #133 | 診断 span の伝搬（`0:0` 解消） | §2。`src/rules/` の `Span.point(0, 0, 0)` 51 箇所 |
| 1 | #102 | SEC002 object filter `.*` | **PR #127 レビュー中** |
| 2 | #101 | SEC002 untrusted inputs 拡充 | **PR #126 要 rebase** |
| 3 | #103 | SEC002 github-script の `script:` | **PR #128 要 rebase** |
| 4 | #62 | SYN007 env 変数名 | **PR #123 マージ可** |
| 5 | #79 | PERM003 permissions スコープ / レベル | `permissions.zig` / `parser.zig` の `parsePermissions` |
| 6 | #95 | DEP003 `uses` フォーマット | `types.zig` の `ActionRef.parse` 近傍 |
| 7 | #78 | BP004 拡張 shell 名 | `best_practices.zig` |
| 8 | #85 | EXPR009 fromJSON リテラル | `expressions.zig`（JSON 妥当性チェッカを `util.zig` に切り出す） |
| 9 | #84 | EXPR008 format() 整合 | `expressions.zig` |
| 10 | #83 | EXPR007 拡張 定数条件 / `${{ }}` 外の文字 | `expressions.zig` |
| 11 | #104 | RW001 workflow_call inputs type | `parser.zig` の `parseInputDefs`（単一ファイルで完結する RW 唯一の項目） |

### Phase 2: トリガー `on:` 群

`ScheduleEntry` / `EventConfig` の拡張を伴うため直列。イベント名テーブルと cron パーサを先に作り、後続で再利用する。

| 順 | issue | ルール | 依存 |
|---|---|---|---|
| 1 | #65 | SYN009 webhook イベント名（+ 近似候補提案） | イベント名 / activity type の埋め込みテーブルを新設 |
| 2 | #66 | SYN010 `types` 値 | #65 のテーブル |
| 3 | #67 | SYN011 イベントで使えないフィルタ | SYN012 で `EventFilter` の key span は記録済み |
| 4 | #69 | SYN013 glob 構文 | なし |
| 5 | #70 | SYN014 CRON 構文 | cron パーサを `util.zig` か `workflow/cron.zig` に新設 |
| 6 | #71 | SYN015 5 分未満 | #70 のパーサ |
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

各 issue で「存在検証」を実装し、最後に `TypeEnv` overlay へ接続する（ADR-0006 の二重メンテ期間を短くするため Phase 4 内で一気に片付ける）。

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
| #64 YAML anchor / alias / merge key | パーサ基盤。GitHub Actions が anchor をサポートしたため実用価値あり。§2 の flow context 対応と同じ層なので、続けて着手すると手戻りが少ない。`docs/codebase-improvements.md` §7 の yaml/parser 整理を Tidy First で先に行い、PBT にラウンドトリップ / 循環参照テストを追加する |
| `docs/codebase-improvements.md` 優先度 1〜8 | 各 Phase で該当ファイルを触る前に Tidy First で消化する（例: SEC002 拡充の前に「`${{ }}` 式スキャンのイテレータヘルパー」を入れる） |
| `docs/design/pbt-strategy.md` #3〜#5 | xfail は解消済み。新ルールが増えるたびに detection PBT を横展開する |
| #134 SEC021 untrusted checkout ref | #55 の対象外。ADR-0004 と `docs/design/sec021-untrusted-checkout-ref-design.md` で設計済み・未実装。起票済みなので Phase 1 の末尾に入れられる |
| #135 SC007 typosquat 検出 | 同上（`docs/design/sc007-typosquat-design.md`）。オフラインで完結するので #134 と並列可 |

## 5. 進め方の注意

- Phase 1 のうち SEC002 系 3 本は同一ファイルなので §3 の順序を守る。それ以外は並列に走らせられる
- Phase 2 以降は `types.zig` の拡張を伴うため、同 Phase 内は直列にする
- エージェント PR は CI 緑でもマージ前に main へ rebase する
- 各 Phase 完了時に `docs/rules.md` のルール数と #55 の進捗表を更新する
