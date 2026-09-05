# BP008 autofix設計書

## 目的

`BP008`（deprecated-workflow-command）は `run:` スクリプト中の無効化済みワークフローコマンド
（`::set-output` / `::save-state` / `::set-env` / `::add-path`）を検出するが、現状は `fix_hint` のみで
自動修正を提供していない。

本設計書では、`--fix-unsafe` 側の autofix として実装するための前提条件・変換規則・安全境界を定義する。
検出（issue #80 の第一段階）は実装済みで、autofix は本設計書に基づく後続イテレーションとする。

関連資料:
- `docs/design/bp003-autofix-design.md`（scalar style 分岐の先例）
- `docs/design/autofix-phase2-insertion-design.md`

## スコープ

- `run:` の中で検出された deprecated workflow command 呼び出しを、対応する `$GITHUB_*` ファイル追記形式へ書き換える
- `Fix.safety` は `.unsafe`（`--fix-unsafe` でのみ適用）
- 変換が機械的に安全と判断できる形（後述の「変換可能な形」）に限定し、それ以外は `fix_hint` のみに留める

## 非スコープ

- `echo` 以外のコマンド（`printf`、`node -e`、ヒアドキュメント等）からの出力の書き換え
- `run:` を跨いだ step output の参照（`steps.<id>.outputs.<name>`）の整合性検査
- multiline value（`%0A` エンコードを含む値）の delimiter 形式（`NAME<<EOF`）への展開

## 前提条件（ブロッカー）

現状の rule engine は **source text にアクセスできない**。

- `Rule.check_step` のシグネチャは `fn (*const Step, *DiagnosticList) void` で、原文バイト列を受け取らない
- `Step.run` は parser が正規化した値であり、block scalar（`|` / `>`）では
  インデントが除去されている。したがって `Step.run` 内のオフセットは原文の byte offset に一致しない
- `Step.run_value_span` は block scalar の場合、インジケータ（`|`）からブロック末尾までを指す

したがって autofix の実装には、以下いずれかの前処理が必要となる。

1. **推奨**: parser 側で `run:` の各行について「正規化後オフセット → 原文 byte offset」を復元できる情報
   （block scalar の base indent と本文開始 byte、または行単位の byte offset 表）を `Step` に持たせる
2. rule engine に source slice を渡し、`run_value_span` の範囲内を直接走査する

1 は `Step` に `run_value_style` / `run_body_start_byte` / `run_base_indent` を追加するだけで済み、
既存の rule シグネチャを変えないため影響範囲が小さい。本設計書は 1 を前提とする。

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
- `VALUE` に `${{ ... }}` 式が含まれる場合は展開結果が予測できないため `.unsafe` である根拠となる。
  edit 自体は生成してよい（引用は保存される）

## Edit 生成

- 各変換対象行につき 1 つの `Edit` を生成し、1 つの `Fix` にまとめる
- `start_byte` = 行の `echo` 開始位置の原文 byte、`end_byte` = 行末（改行を含まない）の原文 byte
- `replacement` は `DiagnosticList.fixAllocator()` 上に構築する
- `Fix.description` は `"Replace deprecated workflow command with $GITHUB_* file append"` 相当

## テスト計画

- 変換対象: 4 コマンド × double / single quote の 8 ケースで replacement 文字列を検証
- インデント保持: block scalar 内の 6 スペースインデントが維持されること
- 非変換: パイプ付き、リダイレクト付き、引用符なし、`NAME` 不正、`%0A` 含みの各ケースで `fix` が `null`
- 混在: 1 つの `run:` 内で変換可能行のみが edit 対象になること
- `--fix` では適用されず `--fix-unsafe` でのみ適用されること
- 適用後の YAML を再度 lint して BP008 が消えること（round-trip）
