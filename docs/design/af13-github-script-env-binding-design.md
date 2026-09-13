# AF13: SEC002 `github-script` `script:` env 束縛 autofix 設計書

## 目的

AF5（#327、`docs/design/af5-env-binding-autofix-design.md`）は SEC002 の
`run:` 本文に env 束縛 fix を付けた。同じルールの第二経路である
`actions/github-script` の `with.script` は、診断は出るが `fix` は常に null
である。本設計は issue #416 が実装前に決めることとして挙げた 3 点を確定させる。

対象は SEC002 だけ。検出範囲は現状どおり `actions/github-script` の `script:`
に限る。

`Fix.safety` は AF5 と同じ `.unsafe`。`--fix-unsafe` のみ。挿入する env
変数名の衝突と、`script:` 本文を JavaScript の構文レベルで書き換えることの
両方が理由である。

## スコープ

- `with.script` 内の、命名できる untrusted `${{ ... }}` を step の `env:` に
  束縛し、参照を `process.env.VAR` に置き換える
- 束縛先・命名・衝突回避・「1 つでも無理なら step 全体を見送る」は AF5 と同じ
- env 挿入は AF5 が入れた `insertMappingEntryBlockBefore` /
  `appendMappingEntries` をそのまま使う。新しい挿入点は作らない

## 非スコープ

- `with:` の `script` 以外。AF5 と同じで、env に束縛しても `${{ env.X }}` に
  戻るだけである
- `github-script` 以外のコード実行 input。現状の検出もこの action だけである
- JavaScript パーサの導入（ゼロ依存）
- `script:` がフロースタイル、または `with_meta["script"]` が無く byte range
  が取れない入力

## 1. `${{ }}` を `process.env.VAR` に置換する範囲

GitHub Actions は YAML の値を JavaScript に渡す**前に** `${{ }}` を展開する。
JS の引用符は GHA の展開を止めない。シェルの単一引用符（AF5 §2）とはそこが違う。

置換してよいのは、JS の文字列リテラル（`"` / `'`）またはテンプレートリテラル
（`` ` ``）の**中身全体が、空白を除いてその `${{ ... }}` 1 つだけ**である場合
に限る。置換範囲は引用符を含むリテラル全体で、置き換え先は裸の
`process.env.VAR` である。

```js
const title = "${{ github.event.pull_request.title }}";
// →
const title = process.env.PULL_REQUEST_TITLE;
```

`'...'` と `` `...` `` も、中身が式 1 つだけなら同じ（GHA 展開後はどれも
文字列リテラルの中に untrusted 値が入る）。

次は step 全体を見送る。部分適用は「直ったように見える未修正」になる。

| 形 | 理由 |
|---|---|
| `"prefix ${{ expr }}"` のようにリテラル内に他の文字がある | 連結やテンプレートへの書き換えが要り、単純置換では構文が壊れる |
| 引用の外の裸の `${{ expr }}` | 展開結果の JS 型が文字列とは限らず、`process.env.VAR`（常に文字列 / undefined）へ寄せると意味が変わる |
| `//` / `/* */` の中 | 実行されない位置を動かす価値が無く、コメント終端をまたぐと構文が壊れる |
| 引用状態が決まらない（未閉じ、エスケープが追えない） | 疑わしいときは fix なし |

引用状態は `script:` 先頭からの 1 パスで取る。状態は `plain` / `dquote` /
`squote` / `template` / `line_comment` / `block_comment`。`dquote` /
`squote` / `template` の中では `\` の次の 1 文字を飛ばす。テンプレート内の
`${ ... }` 入れ子は追わない——中に `${{ }}` があれば「中身が式 1 つだけ」
を満たさないので、その occurrence で step 全体が落ちる。

`process.env.VAR` は引用符を付けない。付けた `"process.env.VAR"` は環境変数名
の文字列になり、値が届かない。

## 2. AF5 の env 挿入ヘルパーを `script:` から呼ぶ

step の `env:` は AF5 で入った。`first_key_start_byte` / `first_key_col` /
`env_last_entry_end_byte` / `env_key_col` を `script:` 経路でも使う。
`github-script` の step は `uses:` を持ち `run:` を持たないが、挿入点は
step mapping のキー位置であり `run:` の有無に依存しない。

`env_binding.buildFix` は `step.run` とシェル参照形に結合しているので、
本文書き換えだけを `script:` 用に分ける。共有するのは命名
（`deriveName` / `uniqueName`）、env 挿入（`buildEnvEdits`）、
「overflow / 命名不能 / 引用不能なら null」の契約である。

`script:` 側はシェルを見ない。`resolveShell` が null でも、`script:` 経路の
fix は出せる。

本文のオフセット写像は `spans.Anchor.fromMeta(step.with_meta.get("script"),
step.span)`。`withAnchor` と同じ。style は AF5 §4 と同じく `.plain` と
`.literal`（`|`）だけを対象にする。`.folded` / quoted YAML は
`expects` が edit 単位で落ちて部分適用になるため、最初から null にする。

## 3. 1 ステップに複数の式がある場合

AF5 §5 と同じ。束縛と参照書き換えは step 単位で 1 つの `Fix` にまとめ、
その step の最初の SEC002 診断にだけ付ける。`run:` と `script:` は同じ
step に共存しない。

SEC002 と SEC008 が同じ step で同時に発火することは、`github-script` では
通常起きない（SEC008 は `run:` の `GITHUB_ENV` 書き込み）。仮に重なっても
engine が片方を捨て、残った fix は単独で完結する。

## 実装配置

- `src/rules/env_binding.zig` — `script:` 用の引用判定と `buildScriptFix`。
  命名と env 挿入は既存関数を使う
- `src/rules/security.zig` — `checkScriptInputInjection` がいま
  `fix = null` で呼んでいる箇所に、最初の診断だけ `buildScriptFix` を渡す
- parser 変更なし（`Step.with_meta` は既にある）

## テスト計画

- 単体: `"..."`, `'...'`, `` `...` `` の中身が式 1 つのとき `process.env.VAR`
- 単体: 混在文字列・裸の埋め込み・コメント内・未閉じ引用は null
- 単体: 命名不能が 1 つあれば null（AF5 と同じ式）
- 単体: 既存 `env:` あり / なし。`run:` 経路のテストは触らない
- e2e: `tests/fixtures/e2e/` に `github-script` の `script:` と
  `.fixed-unsafe` sibling。`--fix`（safe のみ）では本文が変わらないこと
