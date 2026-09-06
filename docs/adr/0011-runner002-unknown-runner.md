# 0011. RUNNER002 unknown-runner

- Status: Accepted
- Date: 2026-09-06
- Issue: [#76](https://github.com/watany-dev/zghalint/issues/76)（親: #55 actionlint parity）

## Context

RUNNER001 は「撤去済み・撤去予定ラベルの固定リスト」との完全一致のみを見ている。
`runs-on: ubunut-latest` のような打ち間違いは既知リストに載らないため素通りし、
ジョブは永久に `queued` のまま止まる。GitHub 側はエラーを返さず、ワークフローの
タイムアウトまで気付けない。actionlint は `runs-on:` のラベルをホストランナーの
既知一覧と突き合わせて未知ラベルを報告しており、parity として取り込む。

難しいのは偽陽性である。セルフホストランナーのラベルは各リポジトリの運用者が
自由に付けるもので、リンタ側から列挙できない。`gpu-box` を未知ラベルとして
報告するリンタは、セルフホストを使う全リポジトリで使い物にならなくなる。

## Decisions

### D1. 「未知」ではなく「ホストランナーのつもりで書き損じたもの」を報告する

未知ラベルのうち、次のどちらかを満たすものだけを RUNNER002 とする:

1. `ubuntu-` / `windows-` / `macos-` で始まる（ホストランナーを名乗っている）
2. 既知ラベルとの編集距離が 2 以内（打ち間違いの形をしている）

`gpu-box` や `my-runner-2xlarge` はどちらにも当たらず報告しない。セルフホストの
ラベルを網羅できない以上、「知らないものは黙る」を既定とし、ホストランナーを
名乗ったものだけ責任を持って検証する。

### D2. ホストラベルは `-<suffix>` 付きも既知、慣用ラベルは完全一致のみ

larger runner は既知のベースラベルに独自の接尾辞が付く（`ubuntu-latest-4-cores`、
`macos-latest-xlarge`）。名前は課金プランごとに任意なので、接頭辞一致で既知と
みなす。

一方 `self-hosted` / `linux` / `macos` / `x64` などセルフホストの慣用ラベルは
`LabelKind.convention` として完全一致のみで扱い、接頭辞一致からも D3 の候補
からも外す。接尾辞を許すと `macos` が `macos-99` を飲み込んで RUNNER002 が
存在する理由そのものを潰し、候補に含めると `runs-on: mac` を「`macos` の
打ち間違い」と断じて `--fix-unsafe` が動くワークフローを壊す。

### D3. 提案は一意に定まるときだけ出す

編集距離 2 以内の最近傍が一意なら `did you mean "ubuntu-latest"?` を出し、
`--fix-unsafe` の置換候補にもする。`macos-99` は macos-13 / macos-14 / macos-15 の
いずれからも距離 2 で並ぶため、候補を出さず診断のみとする。同点の推測で他人の
ワークフローを書き換えない。

### D4. 独自ラベルは `.zghalint.yml` の `runner.labels` で登録する

actionlint の `self-hosted-runner.labels` に相当する。ルールは config ハンドルを
持たないため、PERF001 の workspace probe と同じく `main` が起動時に
`runner.setAllowedLabels()` でモジュール変数へ流し込む。

### D5. 式は当面スキップする

`runs-on: ${{ matrix.os }}` の検証には matrix 展開（SYN018）が必要なため、
第一段階では `${{` を含む値を対象外とする。

### D6. severity は error

誤設定されたラベルはジョブが起動しない。警告ではなくエラーが妥当である。

## Consequences

- ラベル表は RUNNER001 と共有の `known_labels` 一枚に統合された。GitHub が新しい
  ランナーを出すたび、この一箇所を更新すれば両ルールに反映される。
- 逆に、テーブルの更新が遅れると新ランナー（例: 将来の `ubuntu-26.04`）が偽陽性に
  なる。`runner.labels` が当座の逃げ道になる。
