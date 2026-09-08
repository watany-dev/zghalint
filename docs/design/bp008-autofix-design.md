# BP008 autofix設計書

## 目的

`BP008`（deprecated-workflow-command）は `run:` スクリプト中の無効化済みワークフローコマンド
（`::set-output` / `::save-state` / `::set-env` / `::add-path`）を検出する。

本設計書では autofix の変換規則・安全境界を定義する。検出（issue #80 の第一段階）に続き、
autofix は issue #326 で実装済みである。

関連資料:
- `docs/design/bp003-autofix-design.md`（scalar style 分岐の先例）
- `docs/design/autofix-phase2-insertion-design.md`

## スコープ

- `run:` の中で検出された deprecated workflow command 呼び出しを、対応する `$GITHUB_*` ファイル追記形式へ書き換える
- `Fix.safety` は `.safe`（`--fix` で適用）。書き換えは「変換可能な形」に限定され、
  元の引用符とインデントを保存したうえで同じ値を同じ名前に書き込むため、ワークフローの意味は変わらない
- 変換が機械的に安全と判断できる形（後述の「変換可能な形」）に限定し、それ以外は `fix_hint` のみに留める

## 非スコープ

- `echo` 以外のコマンド（`printf`、`node -e`、ヒアドキュメント等）からの出力の書き換え
- `run:` を跨いだ step output の参照（`steps.<id>.outputs.<name>`）の整合性検査
- multiline value（`%0A` エンコードを含む値）の delimiter 形式（`NAME<<EOF`）への展開

## 原文 byte offset の復元

`Step.run` は parser が正規化した値で、block scalar（`|` / `>`）ではインデントが除去されている。
したがって `Step.run` 内のオフセットはそのままでは原文の byte offset に一致しない。

この対応付けは `src/rules/spans.zig` の `Anchor` が既に提供する。`spans.runAnchor(step)` が
`Step.run_meta`（値の token span と scalar style）から `Anchor` を作り、`Anchor.at(value, offset, len)` が
正規化後オフセットを原文の `Span` に戻す。したがって parser 側の追加情報は不要である。

ただし次の 2 つは対応付けが成立しないため fix を生成しない。

- `run_meta` が無い（parser が値の span を取れなかった）場合
- folded scalar（`>`）: 行が空白で連結されるため、正規化後のオフセットに対応する原文 byte が存在しない

加えて、正規化で原文と byte 列が変わりうる escape（double-quoted scalar 等）に備え、各 `Edit` には
`expects` に元の行スライスを入れる。原文が一致しない場合 `fix/engine.zig` が edit を捨てる（fail-closed）。

## 変換規則

| 非推奨 | 代替 |
|---|---|
| `::set-output name=X::Y` | `echo "X=Y" >> "$GITHUB_OUTPUT"` |
| `::save-state name=X::Y` | `echo "X=Y" >> "$GITHUB_STATE"` |
| `::set-env name=X::Y` | `echo "X=Y" >> "$GITHUB_ENV"` |
| `::add-path::X` | `echo "X" >> "$GITHUB_PATH"` |

## 変換可能な形

autofix を付与するのは、1 行が次のパターンに完全一致する場合のみとする（`^\s*` のインデントは保持）。

```
echo "::set-output name=NAME::VALUE"
echo '::set-output name=NAME::VALUE'
```

条件:

- 行全体が `echo` 1 コマンドで構成され、パイプ・リダイレクト・`&&` などの制御演算子を含まない
- コマンド文字列全体が単一の引用符で囲まれている（引用符の対応が取れている）
- `NAME` が `[A-Za-z_][A-Za-z0-9_-]*` に一致する
- `VALUE` に改行エスケープ（`%0A`）を含まない

上記を満たさない行は edit を生成せず、診断と `fix_hint` のみを出す。
1 つの `run:` 内で変換可能な行と不可能な行が混在する場合、変換可能な行のみを edit 対象とする。

## 引用の扱い

- 元が double quote の場合、`VALUE` 中の `$`・`` ` ``・`\` はシェル展開の対象であり、
  書き換え後も double quote 内に置かれるため意味は保存される
- 元が single quote の場合、`VALUE` はリテラルである。書き換え後も single quote を維持し
  `echo 'NAME=VALUE' >> "$GITHUB_OUTPUT"` とする（`$GITHUB_OUTPUT` 側は展開が必要なため double quote 固定）
- `VALUE` に `${{ ... }}` 式が含まれる場合も、式はそのまま引用ごと移動するだけで展開のされ方は変わらない

## Edit 生成

- 各変換対象行につき 1 つの `Edit` を生成し、1 つの `Fix` にまとめる
  （`fix/engine.zig` は重なりを `Fix` 単位で捨てるため、まとめる粒度は「同一コマンド種別の診断 1 件」＝
  `Fix` 1 件とする。種別が違う行同士は重ならない）
- `start_byte` = 行の `echo` 開始位置の原文 byte、`end_byte` = 行末（改行を含まない）の原文 byte
- `replacement` は `DiagnosticList.fixAllocator()` 上に構築する
- `Fix.description` は `"Replace deprecated workflow command with $GITHUB_* file append"` 相当

## テスト計画

- 変換対象: 4 コマンド × double / single quote の 8 ケースで replacement 文字列を検証
- インデント保持: block scalar 内の 6 スペースインデントが維持されること
- 非変換: パイプ付き、リダイレクト付き、引用符なし、`NAME` 不正、`%0A` 含みの各ケースで `fix` が `null`
- 混在: 1 つの `run:` 内で変換可能行のみが edit 対象になること
- `--fix` で適用されること（`Fix.safety` は `.safe`）
- 適用後の YAML を再度 lint して BP008 が消えること（round-trip）。e2e fixture
  `tests/fixtures/e2e/bp008-workflow-commands.yml` と その `.fixed` sibling が実ファイル経路で固定する
