# 0014. SEC023 use-trusted-publishing

- Status: Accepted
- Date: 2026-09-08
- Deciders: issue #286（`docs/design/external-linter-parity.md` §4.1 G15。#271 の FN 候補 1）

## Context

`bench/cases/d-permissions-secrets/api-token-instead-of-oidc.yml` は、長命の
PyPI API トークンをリポジトリ secret に置いて publish する形である。

```yaml
- uses: pypa/gh-action-pypi-publish@76f52bc...  # v1.12.4
  with:
    password: ${{ secrets.PYPI_API_TOKEN }}
```

この action は OIDC (trusted publishing) に対応しており、ジョブに
`id-token: write` があればトークン自体が不要になる。zizmor は
`use-trusted-publishing` として指摘するが、zghalint には該当ルールが無かった。

SEC019（secret を `env:` 経由にせず直接使う）は同じ step で発火するが、伝えて
いるのは「トークンの渡し方」であって「そもそもトークンが要らない」ことではない。
両者は別の対処を指すので、SEC019 の拡張ではなく新しいルールを立てる。

## Decisions

### D1. Rule ID は SEC023、name は `use-trusted-publishing`

SEC001–SEC022 は使用済み。name は zizmor の ident と揃える。ベンチの kind マップ
（`scripts/bench.py` の `DEFAULT_KIND_MAP`）が両者を同じ指摘種別として突き合わせる
ため、名前が一致していると対応関係が読みやすい。

### D2. Severity は info

トークンが漏れて初めて被害が出る hardening 提案であり、ワークフロー自体は正しく
動く。同じ「より安全な書き方がある」クラスの SEC019 / SEC007 と揃えて info とする。

### D3. 対象は 3 つの形に限る

| 対象 | 発火条件 |
|---|---|
| `pypa/gh-action-pypi-publish` | `with.password` が空でない |
| `rubygems/release-gem` | `with.setup-trusted-publisher: false` |
| `npm publish` を含む `run:` | 同じ step の `env.NODE_AUTH_TOKEN` が `${{ secrets.* }}` |

`rubygems/release-gem` だけ条件が反転しているのは、この action の既定が trusted
publishing だからである。既定のままの step を報告するのは誤りなので、明示的な
opt-out (`false`) だけを見る。

npm はトークンを `with:` ではなく環境変数で受けるため、`run:` の中身と step の
`env:` の組で判定する。`npm publish --provenance` をトークン無しで実行する
`bench/cases/j-clean/clean-release-publish.yml` は片方しか満たさないので出ない。

### D4. `env:` は step 自身のものだけを見る

ジョブ / ワークフローに束ねた `NODE_AUTH_TOKEN` を対象にすると、どの step が
publish するのかを静的に決められないまま、同じジョブの無関係な step まで巻き込む。
実務でも publish する step に直接付けるのが一般的なので、step スコープに限る。

### D5. 実行時に組み立てた値は報告しない

`${{ steps.mint.outputs.token }}` のような値は、既に別ルートで発行した短命
トークンである可能性がある。secret を直接参照している形（`isSecretsExpression`）
だけを「長命トークン」と見なす。`with.password` 側は逆に、値の出所を問わず
「その入力を使っている」ことが trusted publishing 未使用の証拠なので、空でなければ
報告する。

### D6. composite action には適用しない

composite action が呼び出し元から受け取った `inputs.token` を publish に渡すのは
正しい書き方であり、OIDC へ切り替えるかを決めるのは呼び出し側のワークフローである。
`src/rules/composite_steps.zig` の適用リストには入れない。

### D7. autofix は提供しない

トークンを外すにはレジストリ側に publisher を登録する必要があり、ワークフローの
書き換えだけでは publish が通らなくなる。`fix_hint` で「`id-token: write` を付けて
trusted publishing へ切り替える」ことを示すに留める。

## Consequences

- G15 が解消し、ベンチの kind マップの `zghalint` が `None` から `SEC023` になる
- 回帰ガードは `tests/fixtures/e2e/sec023-trusted-publishing.yml`（3 つの形が出る）
  と `sec023-trusted-publishing-clean.yml`（OIDC で publish する形は出ない）
- 対応レジストリの表は D3 の 3 つで始める。増やす場合は「トークンを渡す入力名」が
  一意に決まる action に限る — 入力名が分からなければ発火条件を書けない
