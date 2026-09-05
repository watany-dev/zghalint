# PERF001 lockfile detection & cache autofix 設計書

## 目的

`PERF001` (cache-not-used) は `actions/setup-node` / `setup-python` / `setup-go`
がキャッシュを有効化していない場合に診断を出す。現状は `setup-go` のみに
`cache: true` を挿入する autofix を提供していたが、`setup-node` / `setup-python`
は `cache` input に具体的なパッケージマネージャ名（`npm` / `yarn` / `pnpm` /
`pip` / `pipenv` / `poetry`）を必要とするため保留されていた。

本設計書は、リポジトリ内の lockfile を起動時に一度だけ走査して
`workspace.Context` を構築し、それを PERF001 fix builder から参照することで
setup-node / setup-python の autofix を解禁する方針を定義する。同時に setup-go
についても `go.sum` が存在するときに限って fix を生成するよう挙動を引き締める。

関連資料:
- `docs/adr/0005-perf001-cache-extension.md`
- `src/rules/engine.zig:66` `network_deadline_ns`（モジュール変数パターンの先例）

## 技術選定

### 採用: プロセス1回の FS probe + モジュール変数

- 起動時に repo root を特定し、6種類の lockfile + `go.sum` の存在を確認
- 結果を `workspace.current` に格納し、PERF001 fix builder が参照する
- probe は `--quick` / `--offline` でも実施（FS read はネットワーク I/O ではない）
- ディスクキャッシュは不要（FS access は十分に高速で、プロセス内で1回）

### 検討・不採用

- **rule 内で都度 FS access**: 同じ probe が workflow / job / step 単位で繰り返し
  走るため遅い。rule 間の重複も増える。
- **lockfile パース内容まで利用**: 依存関係までは見ない。ファイル名ベースの
  検出のみ（`pnpm-lock.yaml` があれば pnpm、等）。
- **monorepo 内の subdirectory 探索**: 現スコープ外。リポルートの lockfile
  のみを見る。

## 型定義

```zig
// src/workspace.zig
pub const NodeCache = enum { npm, yarn, pnpm };
pub const PythonCache = enum { pip, pipenv, poetry };

pub const Context = struct {
    node_cache: ?NodeCache = null,
    python_cache: ?PythonCache = null,
    go_sum_present: bool = false,
    ambiguous_node_lockfiles: []const []const u8 = &.{},
    ambiguous_python_lockfiles: []const []const u8 = &.{},
};

pub var current: Context = .{};
```

`ambiguous_*_lockfiles` は複数マネージャに該当する lockfile が同居する
場合に検出したファイル名を並べたもの。fix は抑止し `fix_hint` に埋め込んで
ユーザーに選択を促す。

## 公開 API

```zig
pub fn set(ctx: Context) void;
pub fn clear() void;
pub fn detectFromRoot(allocator: std.mem.Allocator, root: []const u8) !Context;
pub fn findWorkspaceRoot(allocator: std.mem.Allocator, hint_path: []const u8) ![]const u8;
```

### `findWorkspaceRoot`

`hint_path` (workflow file パス) のディレクトリから親方向へ `.git` を
探索し、最初に見つかったディレクトリを返す。見つからなければ cwd を返す。

### `detectFromRoot`

指定ディレクトリ直下で以下を確認し `Context` を返す:

| ファイル | 推定マネージャ |
|---|---|
| `package-lock.json` / `npm-shrinkwrap.json` | `NodeCache.npm` |
| `yarn.lock` | `NodeCache.yarn` |
| `pnpm-lock.yaml` | `NodeCache.pnpm` |
| `Pipfile.lock` | `PythonCache.pipenv` |
| `poetry.lock` | `PythonCache.poetry` |
| `requirements.txt` | `PythonCache.pip` |
| `go.sum` | `go_sum_present = true` |

FS access エラーは全て「不在」として扱う。`FileNotFound` と `PermissionDenied`
等を区別しないのは、probe の結果を「能動的に fix を生成するか否か」にしか
使わないためで、不確定ならデフォルトの fix 抑止にフォールバックすれば安全側。

## エラー型

`detectFromRoot` / `findWorkspaceRoot` はアロケータ OOM のみを伝播する。
I/O エラーは内部で吸収され、空の `Context` が返る。呼び出し側（`main.zig`）は
`catch return` で握り潰し、PERF001 は diagnostic のみを出す。

## データフロー

```
main.zig
  ├─ config.Config をロード（.zghalint.yml）
  ├─ findWorkspaceRoot(files[0]) → root
  ├─ detectFromRoot(root) → Context
  ├─ config.perf001.node_cache_manager があれば Context を上書き
  ├─ workspace.set(ctx)
  └─ lint 実行
       └─ performance.checkCacheNotUsed
            └─ dispatchCacheFix(setup_action)
                 ├─ workspace.current を参照
                 ├─ buildCacheFix(action, cache_value, description)
                 └─ ambiguous なら fix_hint 拡張
```

## Config 拡張

`.zghalint.yml` の `rules.PERF001` セクションに以下のキーを受け付ける:

```yaml
rules:
  PERF001:
    node_cache_manager: pnpm     # probe 結果を上書き
    python_cache_manager: poetry
```

`src/config.zig` に `Perf001Override` を追加し、`Config.perf001` として保持。
値が指定されていれば `initWorkspaceContext` で probe 結果より優先される。

## Fix 安全性

全ての PERF001 fix は `FixSafety.unsafe`。lockfile からの推論が決定的でも、
`cache:` 追加は CI の runtime 挙動を変えるため `safe` 昇格はしない。

## テスト戦略

1. **`src/workspace.zig` inline tests** — `tmpDir()` に lockfile を配置し、
   各マネージャ / 曖昧 / 不在 / `findWorkspaceRoot` を検証（10+ ケース）
2. **`src/config.zig` inline tests** — `rules.PERF001.node_cache_manager` /
   `python_cache_manager` パース、無効値は null に落ちること
3. **`src/rules/performance.zig` inline tests** — `workspace.set` で context を
   セットして setup-node/python/go × 各マネージャ / ambiguous / go.sum なしの
   fix 生成を確認
4. **PBT** — `tests/pbt/` で tmpdir に lockfile + workflow を配置し、
   `cwd=tmpdir` で CLI 呼び出し、`--fix-unsafe` 適用後に PERF001 が消えることを
   確認（idempotency）

## イテレーション

1. Tidy First: ADR 番号衝突解消（`0002-sec009` → `0003`）
2. `src/workspace.zig` 新設 + lib.zig re-export
3. `src/config.zig` に `Perf001Override` 追加
4. `src/rules/performance.zig` を `buildCacheFix` / `dispatchCacheFix` に再編
5. `src/main.zig` で probe → workspace.set
6. テスト & fixtures 追加
7. docs (README) 更新

## 独立 setup action の取り扱い (bun / uv)

`actions/setup-node` と `actions/setup-python` はいずれも `cache:` input で公式
に bun / uv をサポートしない。これらは `oven-sh/setup-bun` / `astral-sh/setup-uv`
という独立した action として提供されているため、PERF001 では別系統のロジック
を追加する。関連 ADR: `docs/adr/0007-perf001-bun-uv-extension.md`。

### SetupKind の分類

`src/rules/performance.zig` の `CacheableSetup` に `kind: SetupKind` を追加し、
以下 3 分類で検査ロジックを分岐する:

| Kind | 対象 action | 警告条件 | autofix |
|---|---|---|---|
| `.with_cache_input` | `actions/setup-node` / `actions/setup-python` / `actions/setup-go` | `cache:` 未設定かつ `actions/cache` 不在 | lockfile 推論に従って生成 |
| `.bun_independent` | `oven-sh/setup-bun` | setup-bun 使用かつ `actions/cache` 不在 | なし（手動追加をガイド） |
| `.uv_independent` | `astral-sh/setup-uv` | `with.enable-cache == "false"` 明示かつ `actions/cache` 不在 | なし |

### bun の lockfile hint

`Context.bun_lockfile_present` は `bun.lock` OR `bun.lockb` の OR 判定で設定する。
bun の警告は lockfile 有無と独立して発火するが、`bun_lockfile_present == false`
の場合は `fix_hint` に「Note: no bun.lock or bun.lockb detected at the workspace
root」を追記してユーザへ追加情報を提供する。

### uv の inverse logic

uv は `enable-cache: auto` (GitHub-hosted runner で ON、self-hosted で OFF) が
デフォルト。通常は追加設定不要なため、PERF001 は `with.enable-cache == "false"`
が明示された場合のみ警告する。`enable-cache` 未指定 or `true` は無警告とする。
文字列比較のため、YAML boolean と quoted string の双方が `"false"` に正規化
される前提で動く（`src/workflow/parser.zig` の `parseStringMap` が値をそのまま
スカラ文字列として保持する挙動に依存）。

さらに、同一ジョブ内に `actions/cache` ステップが存在する場合は警告を抑止
する。`enable-cache: false` + 自前 `actions/cache` の組み合わせは「built-in
cache を意図的に切って外部 cache で代替する」正当な構成のため、setup-node
/ setup-python / setup-go / setup-bun と同じく `actions/cache` の存在を
補完と扱う。

### 例外: fix 非対応の根拠

- bun は `with.cache` のような input を持たず、挿入すべき key が存在しない
- uv は `enable-cache: false` を削除するか `true` に書き換える操作がユーザ判断
  に依存する（意図的に無効化している可能性がある）ため、自動修正は危険

両 kind は `dispatchCacheFix` に到達せず、`fix = null` を固定する。
