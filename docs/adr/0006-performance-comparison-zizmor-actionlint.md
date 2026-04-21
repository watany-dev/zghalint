# 0006. 性能比較ベンチマーク: zghalint vs zizmor vs actionlint

- Status: Accepted
- Date: 2026-04-21
- Deciders: grill-me セッション（2026-04-21、ブランチ `claude/performance-comparison-3bsIj`）

## Context

ユーザから「zghalint は zizmor に比べてどれくらい速いか」という質問が出た。
現状、リポジトリ内に性能比較データは存在せず、`docs/adr/0003` および
`docs/adr/0004` で zizmor はルールカバレッジの参照先として言及されている
のみで、速度計測は行われていない。

本 ADR は、zghalint と先行ツール（zizmor, actionlint）の**再現可能な性能
比較ベンチマーク**の設計を確定する。実測結果そのものは
`docs/bench/` 配下の生データおよび本 ADR 後続セクションに追記する運用とし、
本 ADR では**方法論**を規定する。

## Decisions

### D1. 計測軸は "cold-start 体感" と "offline bulk スループット" の 2 軸

- **cold 計測**: ディスクキャッシュ・ネットワークキャッシュをクリアした
  状態で、1 つの中規模 repo（`astral-sh/uv`）の `.github/workflows/` を
  各ツールのデフォルトモードで 1 回解析する。ユーザの体感速度を再現する。
- **bulk 計測**: 13 OSS のワークフローを集めたコーパス全体を、全ツール
  offline モードで解析する。純解析エンジン速度を測る。
- 根拠:
  - cold のみだと「zizmor はオンライン監査 DB を引くので不公平」との反論
  - bulk のみだと「現実に 1000 本同時 lint しない」との反論
  - 両軸報告で、別々の強みを別々に示せる

### D2. 比較対象は zizmor と actionlint の 2 ツール

- zizmor: ユーザが名指しした対象
- actionlint: GitHub Actions lint のデファクト標準（Go 製）。これが無いと
  「actionlint には勝ってないのでは」との疑問が残る
- poutine / StepSecurity は本 ADR の射程外（poutine は OPA/Rego ベースで
  カテゴリが異なり、速度比較のノイズになる。必要なら別 ADR）

### D3. コーパスは 13 OSS を commit-sha pin で shallow sparse clone

- cold 用 (1 repo): `astral-sh/uv`（~10 wf、Python 中規模、matrix 豊富）
- bulk 用 (12 repo 追加): `denoland/deno`, `vercel/next.js`,
  `kubernetes/minikube`, `rust-lang/cargo`, `python/cpython`,
  `microsoft/vscode`, `facebook/react`, `home-assistant/core`,
  `grafana/grafana`, `hashicorp/terraform`, `apache/spark`, `golang/go`
- 合計見込 ~160 本の workflow yml
- 固定化: `scripts/bench/corpus.txt` に `owner/repo@<commit-sha>` 形式で
  列挙。`scripts/bench/fetch-corpus.sh` が sha pin で clone
- clone は `--depth 1 --filter=blob:none --sparse` で
  `.github/workflows/` のみ取得（容量を数十 MB 規模に抑える）
- 選定基準:
  - スター 10k 以上・アクティブ
  - エコシステム分散（Node / Python / Rust / Go / JVM / TS）
  - workflow 数の分布（少 / 中 / 大）
  - matrix, reusable workflow 等の構文多様性
  - zizmor / actionlint 作者自身の repo は除外（チューニング疑念回避）

### D4. 計測ツールは hyperfine

- 統計値（mean, stddev, min, max, speedup factor）を自動算出
- `--export-json` で生データを `docs/bench/` に commit 可能
- インストール: `cargo install hyperfine`（cargo 利用可、未インストール）
- 実行設定:
  - **cold**: `--warmup 0 --runs 5`、`--prepare 'rm -rf ~/.cache/zghalint ~/.cache/zizmor'`
  - **bulk**: `--warmup 3 --runs 10`（ディスクキャッシュ温存）
- cold で試行数 5 の根拠: ネット往復で cold 間分散が大きく、試行数を増やしても
  収束しにくい。代表値は min を使う

### D5. 公平性担保の 4 原則

1. **ルールセット正規化はしない**（共通領域のみに絞らない）。各ツールが
   箱から出した姿で持つ検出力も含めて測る
2. **入力正規化**: 各ツールに `.yml`/`.yaml` ファイルリストを明示的に渡す
3. **出力フォーマット統一**: 全ツール JSON 出力（terminal 色付け時間を排除）
   - `zghalint --format json`
   - `zizmor --format json`
   - `actionlint -format '{{json .}}'`
4. **デフォルトルール有効/無効には手を付けない**
- モード切り分け:
  - **cold**: 各ツールのデフォルト（素で実行）
  - **bulk**: 全ツール offline（`zghalint --offline`, `zizmor --offline`,
    actionlint は元々ネット不使用）

### D6. 報告指標の固定

| 指標 | cold | bulk | 備考 |
|---|---|---|---|
| mean ± stddev | ✓ | ✓ | hyperfine 基本出力 |
| min | ✓ | ✓ | ベストケース、cold の代表値 |
| files/sec | – | ✓ | bulk 直感指標 |
| speedup factor (×N 倍) | ✓ | ✓ | hyperfine 自動算出、ユーザ質問への直接回答 |
| 診断件数 | ✓ | ✓ | 「速い＝手抜き検出」反論封じ |
| ネット/解析時間内訳 | ✓ | – | `default - offline` 差分、cold のみ |
| RSS ピーク | ✓ | ✓ | `/usr/bin/time -v` 別途取得、中央値 |

- 中央値・max は採用しない（mean+stddev+min で代替可）
- 診断件数は**総数ではなく「各ツールの検出力の目安」**として併記。ADR 本文に
  「カバレッジが異なるため総数比較は不適切」と明記

### D7. ツールバージョンは最新安定版を pin

- 計測直前に zizmor / actionlint の最新リリースを確認し pin する
- インストールコマンド例:
  - `cargo install zizmor --version X.Y.Z`
  - `go install github.com/rhysd/actionlint/cmd/actionlint@vX.Y.Z`
  - または公式リリースバイナリを sha256 固定
- zghalint 自身も commit sha で pin（`git rev-parse HEAD` を `provenance.md`
  に記録）
- 複数バージョンでの推移比較は本 ADR の射程外（別 ADR）

### D8. ファイル配置

```
scripts/bench/
  corpus.txt                # owner/repo@sha の列挙
  fetch-corpus.sh           # shallow sparse clone
  run-bench.sh              # hyperfine 実行（cold / bulk 両方）
  parse-results.sh          # hyperfine JSON → Markdown 表
docs/bench/
  README.md                 # 再現手順
  provenance.md             # 計測マシンスペック・計測日・ツール version
  results-cold.json         # hyperfine 生出力
  results-bulk.json
  counts.txt                # 各ツールの診断件数
docs/adr/
  0006-performance-comparison-zizmor-actionlint.md  # 本 ADR
```

- 生データを commit することで将来の回帰比較・診断時に diff が取れる
- `provenance.md` で CPU / OS / ディスク / RAM を明記し、環境依存性の
  批判に備える

### D9. エラーハンドリングとマルチスレッドの扱い

- `hyperfine --ignore-failure` を付け、ツールが warning/error で非 0 終了
  しても計測は続行する。異常件数は `counts.txt` で別途集計
- マルチスレッド動作は**各ツールの設計特性**として測り、揃えない
  - zghalint: 現状シングルスレッド
  - zizmor: rayon で並列
  - actionlint: 並列対応
- ADR 本文に「zghalint は並列化未実装の条件下でも X 倍速い」等の文脈を
  付記できる場合、強い主張になる

### D10. 実測・スクリプト実装は本 ADR のスコープ外

- 本 ADR は**方法論の確定**のみを目的とする
- 実際のスクリプト実装 (`scripts/bench/*.sh`) およびコーパス clone・
  hyperfine 実行・結果貼り付けは、本 ADR を受けて別コミット・別 PR で行う
- 計測結果は `docs/bench/` 配下の生データと、本 ADR 末尾の「Results」
  セクション追記として記録する

## Consequences

- ユーザの「zizmor に比べてどれくらい速いか」という質問に、再現可能で
  公平な数値で回答できる基盤ができる
- 将来 zghalint を最適化した際の回帰比較が可能（生データ diff）
- zghalint の強み（Zig ゼロ依存・offline bulk の純解析速度、キャッシュ層で
  cold も速い）を、それぞれ異なる軸で示せる
- `provenance.md` で計測環境を明示するため、別マシンでの再計測時に差分が
  どこから来るか追跡可能
- 13 repo の clone は数十 MB オーダ（shallow sparse で抑制）で、CI では
  回さずローカル / 専用ジョブ運用
- ツールバージョン更新 / コーパス sha 更新は半年〜1 年に一度の手動メンテ
  として別 ADR で行う

## Alternatives Considered

### A1. cold のみ計測（体感速度のみ主張）

却下: bulk が無いと「エンジン単体速度では負けているかも」との疑念が残る。
zghalint の強みは offline bulk にあるはずで、これを出さないのは機会損失。

### A2. bulk のみ計測（エンジン速度のみ主張）

却下: ユーザが素朴に `zghalint ci.yml` を叩いたときの速度を答えられない。
ユーザ質問との直接対応が薄れる。

### A3. zizmor のみと比較（actionlint を省く）

却下: actionlint は事実上の業界標準で、これとの比較が無いと「zghalint は
zizmor より速いが actionlint には負けているのでは」との反論を封じられない。

### A4. poutine / StepSecurity も含めて 4+ ツール比較

却下: poutine は OPA/Rego ベースで入力形式・ルール表現が異質。StepSecurity
は一部が SaaS。速度比較の意味が薄れる。別 ADR で扱う。

### A5. GitHub Search API で workflow yml のみ収集

却下: API rate limit と、対象 workflow が時間と共に変化することによる再現性
喪失のリスク。shallow sparse clone + sha pin の方が確実。

### A6. zizmor リポジトリ内の既成 corpus を流用

却下: zizmor に都合の良いサンプルである疑念を封じにくい。第三者 OSS から
無作為に選んだ方が公平性の説得力が高い。

### A7. 共通ルール領域のみに絞って比較（ルール正規化）

却下: 「速度を稼ぐためにルールを絞った」という疑念を招く。zghalint の
固有ルール (SC003–SC006 など) も含めた「箱から出した姿」での比較の方が
誠実。カバレッジ差は診断件数の併記で文脈化する。

### A8. `time` コマンド 1 発 / 自作 shell loop で計測

却下: warmup・統計処理・外れ値検出が自前だと信頼性が低い。hyperfine が
これらを標準提供しているため採用コストが低い。

### A9. perf stat で CPU cycle / キャッシュミスまで計測

却下: Linux 専用で sudo が要る場合があり、ADR 読者が再現しにくい。一次
レポートとしては過剰。将来ミクロ最適化が必要になった段階で別 ADR。

### A10. 最新版 (main ブランチ) での比較

却下: 数値の再現性が時間と共に失われ、半年後に読むと意味不明になる。
最新安定版を pin する方が ADR として長寿命。

### A11. 複数バージョン推移比較

却下: 工数 2〜3 倍、表が複雑化。「現時点の相対位置」を示す 1 発勝負で十分。
推移は将来別 ADR で。

### A12. CI で定期ベンチ実行・グラフ化

却下: 本 ADR のスコープ外。別 ADR（回帰検知ベンチ）で検討。

## References

- grill-me セッション Q1–Q11（2026-04-21）
- ユーザ質問: "zizmor に比べてどれくらいはやい？"
- 作業ブランチ: `claude/performance-comparison-3bsIj`
- 関連 ADR:
  - `docs/adr/0003-sec009-workflow-run-untrusted-checkout.md` (zizmor 参照)
  - `docs/adr/0004-security-gap-fill-sec018-sec021-sc002-sc007.md` (zizmor 参照)
- 外部ツール:
  - hyperfine: https://github.com/sharkdp/hyperfine
  - zizmor: https://github.com/woodruffw/zizmor
  - actionlint: https://github.com/rhysd/actionlint
