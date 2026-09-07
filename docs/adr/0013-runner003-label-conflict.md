# 0013. RUNNER003 runner-label-conflict

- Status: Accepted
- Date: 2026-09-07
- Issue: [#77](https://github.com/watany-dev/zghalint/issues/77)（親: #55 actionlint parity）

## Context

`runs-on:` は配列で複数ラベルを取れる。ジョブは「列挙されたラベルを**すべて**
備えた 1 台のランナー」で実行されるため、`[ubuntu-latest, windows-latest]` の
ように OS が異なるラベルを並べると、条件を満たすランナーは永久に現れない。
GitHub はエラーを返さず、ジョブはワークフローのタイムアウトまで `queued` の
まま止まる。actionlint は同時に満たせない組み合わせを報告しており、parity として
取り込む。

前提として、`Job.runs_on` は単一スカラーしか保持していなかった。配列指定は
`getScalar` が null を返すため、RUNNER001 / RUNNER002 も配列を素通りしていた。

## Decisions

### D1. ラベル列を `Job` に持たせ、3 ルールで共有する

`runs_on_labels` / `runs_on_label_spans`（`needs` / `needs_spans` と同じ並列配列
の形）を追加し、スカラー・配列・ランナーグループ（`runs-on: {group:, labels:}`）
のいずれもラベル列として正規化する。既存の `runs_on` / `runs_on_value_span` は
スカラーの意味のまま残す。BP004 の OS 判定など既存の利用箇所と、`.runs_on` だけ
を組み立てる多数のインラインテストを壊さないためである。

RUNNER001 / RUNNER002 はこのラベル列を 1 個ずつ走査する形に変えた。副作用として
配列指定・ランナーグループでも撤去済みラベルや打ち間違いを検出できるようになる。

### D2. OS を名乗る「既知の」ラベルだけを衝突判定に使う

`ubuntu*` / `linux` は Linux、`windows*` は Windows、`macos*` は macOS。ただし
判定に使うのは `known_labels`（と `runner.labels`）に載っているラベルだけとする。
フリートの運用者は Linux マシンに `macos-m1` と名付けられるので、接頭辞だけで
OS を決めつけると存在しない衝突を作り出す。`[self-hosted, linux, macos-m1]` は
報告せず、`[self-hosted, linux, macos-14]` は報告する。

`self-hosted` / `x64` や自前フリートの独自ラベルは OS を主張しないので判定に
使わない。`[self-hosted, linux, x64]` は正当な指定であり、`self-hosted` と OS
ラベルの併記を衝突として扱わないのはこの帰結である。

セルフホストのラベルを列挙できない以上、RUNNER002 と同じく「知らないものは黙る」
を既定に置く。

### D2'. `self-hosted` を含む集合では RUNNER002 を黙らせる

配列を検査するようになった副作用で、`[self-hosted, windows-gpu]` の `windows-gpu`
が「ホストランナーを名乗る未知のラベル」に見えてしまう。`self-hosted` があれば
残りのラベルは運用者が付けた名前なので、そのジョブでは RUNNER002 を出さない。
0011 の D1（ホストランナーを名乗ったものだけ検証する）を配列に持ち込むと、
セルフホストのフリートで使い物にならなくなるためである。

### D3. 最初に見つかった衝突 1 件だけ報告する

3 つ以上の OS が並んでも、直すべきは「ラベルを 1 つの OS に揃える」という 1 箇所
である。組み合わせを全列挙しても同じ修正を何度も指すだけなので、最初の食い違いで
打ち切る。診断は衝突した側のラベルに当て、メッセージに両方のラベル名を出す。

### D4. 式を含むラベルがあるジョブは対象外

`[self-hosted, "${{ matrix.os }}"]` の OS は matrix 展開まで決まらない。式が
1 つでもあればジョブ全体を対象外にする。判定は走査前に済ませる — 途中で打ち切る
形だと、式より前に衝突が並んだときだけ報告されて結果がラベルの順序に依存する。
RUNNER002 の D5 と同じ立場で、matrix 展開は #210 で追う。

### D5. autofix は付けない

どの OS を残すのが正しいかはワークフローの意図次第で、リンタからは決められない。
`fix_hint` で「1 つの OS に揃えるか、matrix でジョブを分ける」とだけ示す。

### D6. severity は error

該当するランナーが存在せず、ジョブは起動しない。RUNNER001 の撤去済みラベルや
RUNNER002 と同じ扱いが妥当である。

## Consequences

- `runs-on` の表現形（スカラー / 配列 / ランナーグループ）はパーサ側で 1 本に
  正規化され、以後の RUNNER 系ルールは表現形を意識しなくてよい。
- OS 判定（`labelOs`）は `known_labels` に依存する。GitHub が新しいランナー
  イメージを出したとき、テーブルの更新が遅れると衝突を見逃す。既知ラベルの表を
  一箇所に集めてある以上、見逃す側に倒れるのは意図した挙動である。
- `self-hosted` を含むジョブでは RUNNER002 の打ち間違い検出も効かなくなる。
  独自ラベルの誤検出とは引き換えで、必要なら `runner.labels` で明示できる。
