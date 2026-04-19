# ADR 0001: SEC020 における `runs-on:` シーケンス形への対応

- Status: Proposed
- Date: 2026-04-19
- Related: PR [#34](https://github.com/watany-dev/zghalint/pull/34),
  review [`pullrequestreview-4135404632`](https://github.com/watany-dev/zghalint/pull/34#pullrequestreview-4135404632)
- Implementation plan: `docs/design/sec020-runs-on-sequence-fix-plan.md`

## コンテキスト

SEC020（self-hosted runner が fork-accessible trigger 付き workflow で使われることを検出する
ルール）は PR #34 で追加された。Copilot レビューで 3 件の指摘が付いた:

1. `runs-on: [self-hosted, ...]` のシーケンス形を検出できない（false negative）。
2. 既存の "array-literal" テストは Zig 文字列リテラルを直接 `Job.runs_on` に入れているだけで、
   YAML → workflow parser を通していないため、偽の網羅感を与えている。
3. `for (wf.jobs) |*job|` は読み取りのみなので値キャプチャ `|job|` が適切。

指摘 1 は根本原因として、`Job.runs_on: ?[]const u8` が単一スカラのみ保持する
モデル設計と、`parser.zig:281` の `m.getScalar("runs-on")`（scalar 以外は null を返す）に
由来する。現実の workflow では `runs-on: [self-hosted, linux, x64]` が頻出するため、
取りこぼしの影響範囲は広い。

## 検討した代替案

### 案 A: `runs_on` を `union(enum){ scalar: []const u8, labels: []const []const u8 }` に変更

- 利点: "scalar か sequence のいずれか" という排他性をモデルで表現できる。
- 欠点: 既存の `job.runs_on` を参照している全箇所（validator / tests 多数）が
  パターンマッチ書き換えとなり、変更範囲が広く回帰リスクが高い。

### 案 B: `runs_on` を `?[]const []const u8` に型変更し、scalar は長さ 1 のスライスで表現

- 利点: 表現が一本化される。
- 欠点: 既存の `job.runs_on.?` 直接比較パターンが全部壊れる。A と同じく影響が広い。

### 案 C（採用）: `runs_on_labels: ?[]const []const u8` を追加併設

- 利点: 既存 `runs_on`（scalar 形）を参照しているコードは全て非破壊。
  parser で sequence を検知したときだけ新フィールドを埋め、SEC020 のみ両方を確認する。
- 欠点: 同一情報が 2 フィールドに分散する。ただし parser で排他セットする（両方同時には埋めない）
  ため意味の曖昧さは無く、将来 union に移行する場合も追加削除のみで済む。

## 決定

**案 C を採用する。**

- `Job` に `runs_on_labels: ?[]const []const u8 = null` を追加する。
- workflow parser は `runs-on:` Node が `.scalar` なら `runs_on` に、`.sequence` なら
  `runs_on_labels` に排他セットする。
- SEC020 は両方をチェックし、`self-hosted` の有無を判定する（scalar 側は既存の
  substring match を維持、labels 側は完全一致で判定）。
- `validator.zig` の "runs-on required" チェックは `runs_on == null and runs_on_labels == null`
  に緩和する。
- 既存の Zig リテラル依存テストは削除し、parser 経由の e2e テストで置き換える。

## 結果（想定）

**肯定的**:

- `runs-on: [self-hosted, linux, x64]` 形の workflow で SEC020 が発火するようになる。
- parser 経由テストにより "Zig 側で埋めた値が通ったから OK" 型の偽通過を排除できる。
- `runs_on_labels` フィールドは将来の SEC / PERM ルール（例: specific label の混入検知、
  matrix 展開時のラベル集合検査）で再利用できる。

**否定的 / 受容リスク**:

- 同じ論理量が 2 フィールドに分かれるため、ルール実装者は両方を確認する必要がある。
  これは util 関数（例: `jobHasRunnerLabel(job, label)`）を切り出せば緩和可能だが、
  現時点では SEC020 のみ対象のため汎用化は後回しとする。
- YAML 式展開 (`${{ matrix.os }}`) はどちらのフィールドにもラベル情報として現れない
  （scalar 文字列として `runs_on` に残る）ため、この方針で解決できるスコープ外である。

## 非対象（将来検討）

- scalar 判定を完全一致（`eql`）へ厳密化するか、
  `self-hosted-foo` などのユーザー定義ラベルを誤検知しない形に絞るか。
- `runs-on:` の式展開 (`${{ ... }}`) の解決。
- `runs_on` / `runs_on_labels` を単一 union へ統合するリファクタ。

## 実装計画

詳細手順・見積もり・検証は
`docs/design/sec020-runs-on-sequence-fix-plan.md` を参照。
