# CLI / 設定の穴埋め

最終更新: 2026-09-16

追跡 issue: C0 #546（子 C1〜C6 = #556〜#561）

## 1. 目的

0.0.2 までは検出精度に注力し、利用側の道具立ては `.zghalint.yml` の
severity / enabled / ignore と 3 形式の出力で止まっている。actionlint /
zizmor と並べて使われるために足りないものを、入出力・既定値・非目標を
先に固定してから実装する。

## 2. 非スコープ

- LSP / エディタ拡張（C4 の `--stdin` までが境界）
- 外部プラグイン・カスタムルール
- 複数 CI（GitLab / CircleCI）
- ファイル全体を黙らせる `# zghalint-disable` ブロックコメント（行単位だけ）

## 3. 機能

### C1. ルール単位のパス除外 (`rules.<ID>.exclude`) — #556、P0

```yaml
rules:
  SEC001:
    exclude:
      - "**/release.yml"
      - ".github/workflows/legacy-*.yml"
```

- glob は既存の `ignore`（`config.matchGlob`）を再利用する。未知の glob
  文法で落ちない。
- ファイル全体の `ignore` は今どおり **lint 対象から外す**。除外した
  ファイルではどのルールも走らない。
- `rules.<ID>.exclude` は lint 対象に残ったファイルについて、そのルールの
  診断だけを落とす。`appendFiltered` で見る。エンジンは config を持たない。
- 複数パターンは OR。1 つでも当たればそのルールは沈黙する。
- `enabled: false` の方が強い（ファイルを問わず出さない）。

### C2. `--fail-on <severity>` — #557、P0

| 値 | 終了コード 1 になる条件 |
|---|---|
| `error`（既定） | error が 1 件以上（現状と同じ） |
| `warning` | warning 以上 |
| `info` | info 以上 |

- hint だけの入力はどの値でも 0。hint を失敗にする値は持たない。
- `--format` とは独立。変わるのは終了コードだけ。
- 致命（ファイルが読めない、引数が不正、`--fix` の書き込み失敗）は今どおり 2。
- 設定ファイルには置かない。CI のジョブごとに変えたいフラグだから。

### C3. インライン抑制コメント — #558、P0

```yaml
- uses: actions/checkout@v4  # zghalint-disable-line SEC001
- run: echo "${{ github.event.issue.title }}"
  # zghalint-disable-next-line SEC002
```

- 複数 ID はカンマ区切り。空白は無視する。ID を省略したらその行の全ルール。
- 対象は診断の `span.start_line`。`disable-line` はコメントと同じ行、
  `disable-next-line` は次の非空行（コメントと空行は飛ばさない。次の
  物理行。YAML の継続行まで含めて「次の行」1 行だけ）。
- 未知のルール ID は **黙る**。誤字で抑制が効かないのはテストで気づく。
  新しい警告を設定ファイルの typo と混ぜない。
- `# zizmor: ignore[...]` は読まない。zghalint のプレフィックスだけ。
- 抑制された件数は `--format json` の summary に `suppressed` として出す。
  terminal / SARIF には出さない。
- tokenizer がコメントの行番号を既に持っている。AST には載せない。
  `lintFile` がソースをもう一度走査して抑制表を作り、`appendFiltered` で
  適用する。パーサの挙動は変えない。

### C4. `--stdin` / `--stdin-filename` — #559、P1

- `--stdin` と `-` は同じ。標準入力を 1 ファイルとして読む。
- `--stdin-filename` が ignore / exclude と `isDependabotFile` /
  `isActionMetadataFile` に使うパス。省略時は `<stdin>`（どの ignore にも
  当たらない）。
- `--fix` / `--fix-unsafe` は stdin に対して拒否する（終了コード 2）。
  書き戻す先が無い。
- 他のファイル引数と同時に渡したら拒否する。stdin は単一入力。

### C5. JSON Schema と未知キー warning — #560、P1

- `docs/schema/zghalint.schema.json` を `config.zig` の公開面から生成する。
- 未知のルートキーと `rules.<ID>` 配下の未知キーは lint 実行時に
  **stderr の warning**（診断 ID は付けない。ワークフローのルールではない）。
  既知キーは従来どおり読む。終了コードは変えない。
- CI は `scripts/check-version-sync.sh` と同じ流儀で schema と構造体の
  ずれを落とす。
- C1 の `exclude` を schema に含める。

### C6. `--format github` — #561、P2

- `::error file={file},line={line},col={col}::{message} [{rule_id}]`
- severity の写し: error → `error`、warning → `warning`、info / hint → `notice`
- `%` / `\r` / `\n` は workflow command の規則でエスケープする。
- 既定フォーマットは変えない。`--fail-on` とは独立。

## 4. 実装配置

| 機能 | 主ファイル |
|---|---|
| C1 | `src/config.zig`、`src/main.zig` の `appendFiltered` |
| C2 | `src/main.zig`（`CliArgs`、終了判定、help） |
| C3 | `src/main.zig`（コメント走査 + filter）、`src/output/json.zig` |
| C4 | `src/main.zig`（収集と読み込み） |
| C5 | `src/config.zig`、`docs/schema/zghalint.schema.json`、生成スクリプト |
| C6 | `src/output/github.zig`、`OutputFormat` |

C1 / C2 / C4 / C6 は独立。C3 だけ tokenizer / parser 変更と直列にする
（本設計では tokenizer の出力は変えず、ソースの再走査で済ます）。

## 5. 着手順

C0 の本ファイル → C1 → C2 → C3 →（間に合えば）C4 / C5 / C6。
P0 が v0.0.3 の必須。P1 以降は間に合わなければ v0.0.4 へ。
