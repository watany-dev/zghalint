# 式の静的型検査エンジン 設計書

## 目的

GitHub Actions の `${{ }}` 式に対し、actionlint と同型の静的型体系を zghalint に導入する。本設計は **実装ではなく基盤** であり、判断の単一情報源は `docs/adr/0009-expr-static-typecheck.md` である。

行番号は本ドキュメント記述時点（`src/rules/expressions.zig` の EXPR001〜EXPR007 実装、`src/config.zig` の `RuleOverride`）のもの。

## スコープ

- 型表現（`Type` / `TypeRef` / intern / `TypeArena`）
- 組込み context カタログと関数シグネチャ（戻り値型を含む）
- `typeOf` による式 AST の型推論
- EXPR003 / EXPR017 が後から接続する検査規則
- EXPR010〜EXPR014 と同じ材料から組む `TypeEnv` overlay（T4, #129）
- 誤検出時の `any` 倒しと既存 `.zghalint.yml` による抑制

## 非スコープ

- 本 PR での Zig 実装（issue #94 は設計のみ）
- webhook payload 全体の型、イベント別 `github.event` 切替（ADR D3）
- EXPR010〜EXPR014 自体の検出ロジック（各 issue で先行実装）
- EXPR008（`format` プレースホルダ）/ EXPR009（`fromJSON` リテラル妥当性）/ EXPR015 / EXPR016
- EXPR006 / EXPR007 の検出・autofix（型と独立。現行 `validateNode` に残す）
- 関数名の大小文字非区別化
- 型 narrowing（`&&` / `||`）

## 現状整理

| 既存資産 | 位置 | 備考 |
|---|---|---|
| 式トークナイザ / 再帰下降パーサ | `src/rules/expressions.zig` | `ExprNode`。`context_access` はフラットな path 文字列 |
| EXPR001〜EXPR007 | 同ファイル `validateNode` | 名前ベース。型なし |
| `github_properties` / `runner_properties` | 同ファイル L546-566 | 第一プロパティ名の一次元配列 |
| `FuncSpec` `{name, min_args, max_args}` | 同ファイル L568-583 | 戻り値型も引数型も無い |
| `valid_contexts` | 同ファイル L540-544 | 12 context。`jobs` を含む |
| ルール登録 | `expression_rule` L1118-1127 | `check_step` / `check_job` のみ。workflow レベル式は未走査 |
| 設定の抑制 | `src/config.zig` `RuleOverride` | `enabled` / `severity`。型検査専用キーは無い |
| ワークフロー上の式出現 | `Job.if_condition` / `Step.if_condition` / `run` / `env` / `with` | キーパス情報は持たない（EXPR015 の前提不足） |
| `EventType` / `Trigger` | `src/workflow/types.zig` | イベント名は分かるが payload 型は無い |
| `InputDef` / `SecretDef` | 同 | `inputs` / `secrets` overlay の構築材料 |

現行 `context_access` の限界:

```
github.event.pull_request.head.sha   → 第一プロパティ "event" が既知なので EXPR003 なし
github.repository.permissions        → 同上（"repository" は既知）。string への deref を見逃す
github.reposiory                     → EXPR003（typo）
arr[0]                               → パーサが string リテラル添字しか受け付けない
foo.*                                → path 文字列に `*` が残るだけで意味解析しない
```

## 設計方針

### 1. モジュール構成

`expressions.zig` は既に 2,800 行超なので、型エンジンは隣接ファイルに分割する（Tidy First。パーサ移動はしない）。

```
src/rules/expr_type.zig     — Type / TypeRef / Prop / assignable / merge / display
src/rules/expr_catalog.zig  — intern 済み組込み context と関数シグネチャ
src/rules/expr_check.zig    — typeOf / プロパティウォーク / 比較規則
src/rules/expressions.zig   — パーサ・EXPR006/007・validateNode から check を呼ぶ（接続は後続 PR）
```

`src/lib.zig` の test ブロックに 3 ファイルを追加する。

`src/expr/` への独立パッケージ化はしない。消費者が `rules/expressions.zig` だけであり、公開 API を増やす理由が無い。

公開関数（カタログ）:

```zig
/// 未知なら null。EXPR002 の判定に使う。
pub fn lookupContext(name: []const u8) ?TypeRef

/// 未知なら null。EXPR004 の判定に使う。名前は大小文字区別（現行どおり）。
pub fn lookupFunction(name: []const u8) ?[]const FuncSig
```

実装は `std.StaticStringMap(TypeRef)`（comptime）でよい。プロパティ名の一次元配列は廃止し、strict object の `props` から名前集合を復元できることをテストで担保する。

### 2. 型表現

Zig に Go の `interface{ Assignable; Merge }` は無い。kind タグと intern ポインタで同等の操作を関数にする。

```zig
pub const TypeKind = enum {
    any,
    null,
    number,
    bool,
    string,
    array,
    object,
};

/// How unknown keys of an object are treated.
pub const ObjectShape = enum {
    /// Unknown key → type error (EXPR003). github / runner / job.
    strict,
    /// Unknown key → any. github.event, and workflow-defined contexts with no overlay.
    loose,
    /// Every key has `elem` type. env / vars / secrets.
    map,
};

pub const Prop = struct {
    name: []const u8,
    ty: *const Type,
};

pub const Type = struct {
    kind: TypeKind,
    /// array の要素型、または map object の値型。
    elem: ?*const Type = null,
    /// object の既知プロパティ。名前昇順。探索は二分探索。
    props: []const Prop = &.{},
    shape: ObjectShape = .loose,
    /// `.*` object filter 由来の array のとき true（actionlint ArrayType.Deref）。
    deref: bool = false,
};

pub const TypeRef = *const Type;
```

スカラー intern（プロセス生存期間、alloc なし）:

```zig
pub const type_any: Type = .{ .kind = .any };
pub const type_null: Type = .{ .kind = .null };
pub const type_number: Type = .{ .kind = .number };
pub const type_bool: Type = .{ .kind = .bool };
pub const type_string: Type = .{ .kind = .string };
pub const type_array_any: Type = .{ .kind = .array, .elem = &type_any };
```

`Type` を値でネストコピーしない。object の子もすべて `TypeRef`。組込み object は `expr_catalog.zig` の `const` として intern する。

#### なぜ HashMap ではないか

組込みプロパティ数は `github` でも 40 件前後。ソート済みスライスの二分探索で足りる。contextual overlay も job あたりの step 数・matrix 軸数程度。`StringHashMap` をカタログに使うとテストと dealloc が増えるだけで、lookup は速くならない。

#### `TypeArena`（実行時 intern）

```zig
pub const TypeArena = struct {
    arena: std.heap.ArenaAllocator,

    pub fn init(backing: std.mem.Allocator) TypeArena {
        return .{ .arena = std.heap.ArenaAllocator.init(backing) };
    }

    pub fn deinit(self: *TypeArena) void {
        self.arena.deinit();
    }

    pub fn internObject(
        self: *TypeArena,
        shape: ObjectShape,
        props: []const Prop,
        mapped: ?*const Type,
    ) error{OutOfMemory}!TypeRef {
        const alloc = self.arena.allocator();
        const copy = try alloc.create(Type);
        copy.* = .{
            .kind = .object,
            .elem = mapped,
            .props = props,
            .shape = shape,
        };
        return copy;
    }

    pub fn internArray(self: *TypeArena, elem: TypeRef, deref: bool) error{OutOfMemory}!TypeRef {
        const copy = try self.arena.allocator().create(Type);
        copy.* = .{ .kind = .array, .elem = elem, .deref = deref };
        return copy;
    }
};
```

ライフタイム: 1 ワークフローの lint 中だけ生きる。T0〜T3 は arena を使わず intern 定数だけで完結できる（object merge が必要なら `any` に倒す）。T4 の overlay は `expressions.checkWorkflow` のスコープで `ArenaAllocator` を作り、そこで破棄する。組込み `Type` は arena に載せない。intern 定数は不変なのでスレッド間で共有してよい。arena は共有しない。

#### assignable / merge / display

actionlint `expr_type.go` と同一の意味論。実装者が Go を見比べられるよう、関数名も合わせる。

```zig
/// `dst` に `src` を入れてよいか。`any` は常に true。
pub fn assignable(dst: TypeRef, src: TypeRef) bool { ... }

/// 衝突したら `any`。論理演算の結果型に使う。
pub fn merge(arena: ?*TypeArena, a: TypeRef, b: TypeRef) TypeRef { ... }

/// 診断メッセージ用。strict object は `{a: string; b: number}`、
/// loose は `object`、map は `{string => string}`。
pub fn display(ty: TypeRef, buf: []u8) []const u8 { ... }
```

`merge` が新しい object/array を作る必要があるときだけ `TypeArena` を使う。スカラー同士の merge は intern 済み定数を返す。arena が `null` で object merge が必要なら `any` に倒す（T0 の単体テストは arena 無しで完結させる）。

`bool` の assignable は actionlint どおり **常に true**（`if: ${{ steps.foo }}` が合法）。ただしこれは「比較してよいか」とは別で、比較規則（§6）は bool を `<` の対象にしない。

### 3. 組込みカタログ

`expr_catalog.zig` が単一情報源。`expressions.zig` の `github_properties` / `runner_properties` / `valid_functions` / `valid_contexts` は接続 PR でカタログ参照に置き換え、二重定義しない。

#### context 表（V1）

| context | shape | 既知プロパティ | EXPR003 |
|---|---|---|---|
| `github` | strict | issue #81 の全第一プロパティ。型は下記 | 未知キー・非 object deref |
| `github.event` | **loose** | curated scalar overlay（ADR D3-a / #124）。中間 object も loose | 出さない |
| `runner` | strict | `name/os/arch/temp/tool_cache/debug/environment`: string | 未知キー |
| `job` | strict | `check_run_id: number`, `status: string`, `container: {id,network: string}`, `services: map of {id,network: string, ports: map of string}` | 未知キー（新規 true positive。リリースノート必須） |
| `strategy` | loose | `fail-fast: bool`, `job-index/job-total/max-parallel: number` | 既知以外は `any` |
| `env` | map | — | 値は string。キーは自由 |
| `vars` | map | — | 同上 |
| `secrets` | map | — | `workflow_call.secrets` overlay がなければ map のまま。`GITHUB_TOKEN` も string |
| `steps` | loose | — | overlay がなければ EXPR003 なし |
| `matrix` | loose | — | 同上 |
| `needs` | loose | — | 同上 |
| `inputs` | loose | — | 同上 |
| `jobs` | loose | — | 同上。reusable workflow 用。現状 `valid_contexts` にあるため欠かさない |

`github` 第一プロパティの型（actionlint `BuiltinGlobalVariableTypes` と一致させる）:

- **string**: `action`, `action_path`, `action_ref`, `action_repository`, `action_status`, `actor`, `actor_id`, `api_url`, `base_ref`, `env`, `event_name`, `event_path`, `graphql_url`, `head_ref`, `job`, `output`, `path`, `ref`, `ref_name`, `ref_type`, `repository`, `repository_id`, `repository_owner`, `repository_owner_id`, `repository_visibility`, `repositoryUrl`（カタログ上のキーは `repositoryurl` として保持し、lookup は原文のまま `repositoryUrl` も別名で載せる。現行 `github_properties` が `repositoryUrl` を含むため）、`run_attempt`, `run_id`, `run_number`, `secret_source`, `server_url`, `sha`, `state`, `step_summary`, `token`, `triggering_actor`, `workflow`, `workflow_ref`, `workflow_sha`, `workspace`
- **number**: `artifact_cache_size_limit`, `retention_days`
- **bool**: `ref_protected`
- **loose object**: `event`

lookup は GitHub の公開名どおり大小文字区別。`github.repositoryurl` と `github.repositoryUrl` の両方を載せる（actionlint は `repositoryurl` のみ + コメント）。現行配列が `repositoryUrl` なので、**両方載せて誤検出を増やさない**。

#### 関数シグネチャ

```zig
pub const FuncSig = struct {
    name: []const u8,
    min_args: u8,
    max_args: u8,
    /// 先頭から min(args, params.len) を型検査する。余った可変引数は last を繰り返す。
    params: []const TypeRef,
    ret: TypeRef,
    variadic: bool = false,
};

/// 同一 name に複数 overload。contains / join。
pub const FuncOverloads = struct {
    name: []const u8,
    sigs: []const FuncSig,
};
```

| 関数 | シグネチャ | 戻り値 |
|---|---|---|
| `contains` | `(string, string)` / `(array<any>, any)` | `bool` |
| `startsWith` / `endsWith` | `(string, string)` | `bool` |
| `format` | `(string, any...)` | `string` |
| `join` | `(array<string>, string)` / `(array<string>)` | `string` |
| `toJSON` | `(any)` | `string` |
| `fromJSON` | `(string)` | リテラルなら JSON から推論、否则 `any` |
| `hashFiles` | `(string, string...)` | `string` |
| `success` / `failure` / `always` / `cancelled` | `()` | `bool` |
| `case` | `(bool, any, any, any...)` 最小 3 | `any` |

V1 の引数型不一致は診断しない（ADR D4）。overload 解決: 引数型がすべて非 `any` で、どれかの overload に `assignable` ならその `ret`。どれにも合わなくても **診断せず** `ret` は「全 overload の merge」、衝突すれば `any`。`contains` の両 overload は `bool` なので戻り値は安定する。

`fromJSON` のリテラル推論は EXPR009 と材料を共有できるが、EXPR009 は JSON 妥当性（error）、こちらは型だけ。リテラルが不正なら EXPR009 に任せ、型は `any`。

### 4. `TypeEnv` と overlay

実装（T4, #129）は `std.StringHashMapUnmanaged` ではなく固定フィールドの構造体に
した。overlay 対象は下表の 5 つで増えず、5 回の `std.mem.eql` は
ハッシュ 1 回より速く、アロケーションも `deinit` も要らない。

```zig
pub const TypeEnv = struct {
    steps: ?TypeRef = null,
    matrix: ?TypeRef = null,
    needs: ?TypeRef = null,
    inputs: ?TypeRef = null,
    secrets: ?TypeRef = null,

    /// overlay なしの環境。`check_step` と単体テストが使う。
    pub const empty: TypeEnv = .{};

    pub fn lookup(self: *const TypeEnv, name: []const u8) ?TypeRef { ... }
};
```

`lookup` が null を返したときだけ `walkPath` が `catalog.lookupContext` に落ちる。
root 名の照合は `lookupContext` と同じく完全一致（GitHub の context 名は小文字固定）。
`github.event.inputs` の差し替え（SYN017）は未着手なので、そのフィールドは持たない。

overlay の内訳:

| overlay | 構築材料 | shape |
|---|---|---|
| `steps` | 同一 job、参照より前の step `id` | strict。各 id → `{outputs: loose, conclusion: string, outcome: string}` |
| `matrix` | `strategy.matrix` 軸 + `include` キー（SYN018 依存） | strict。値型は要素の merge、不明なら `any` |
| `needs` | 当該 job の `needs` と対象 job の `outputs` | strict。各 job → `{outputs: strict names→string, result: string}` |
| `inputs` | `workflow_dispatch` ∪ `workflow_call` の input 名 | strict。`type: boolean/number/string` を反映。`github.event.inputs` はすべて string |
| `secrets` | `workflow_call.secrets` があるときだけ strict。通常 WF では map のまま | EXPR014 と同じ限定 |

構築は `src/rules/expr_overlay.zig`。overlay を作れないとき（宣言がない、
`matrix: ${{ fromJSON(...) }}` のような動的形、アロケーション失敗）は null を返し、
その context はカタログの loose エントリのままになる。overlay の `Type` /
`Prop` は `checkWorkflow` スコープの `ArenaAllocator` から取り、そこで破棄する。

overlay が載る前に strict へ上げると、正当な `steps.setup.outputs.v` が EXPR003 になる。
**overlay を作れないときは loose を維持する**のが誤検出ゼロの担保。

EXPR010〜EXPR014 の先行実装は文字列集合で存在検証し、独自の診断を出す。overlay を
載せても存在検証の診断 ID は各ルール（EXPR010 等）に残し、エンジンは型
（`steps.foo.conclusion` が string である等）だけを見る。同一 span に EXPR003 と
EXPR010 を重ねない: overlay 由来の root を辿って出た `Problem` は
`walkPath` が握りつぶして `any` を返し、EXPR003 は組込み strict context 専用とする。

overlay の props は job/workflow から作るのでソートも case 正規化もされていない。
GitHub は context キーを case-insensitive に解決するため、overlay 由来の
プロパティ照合だけ `findPropIgnoreCase`（線形）を使い、組込みカタログは
ソート済み二分探索の `findProp` のままにしてある。

#### ルールエンジンとの接続口

現行 `Rule.check_step` は `*const Step` しか受け取らず、同一 job の先行 step 一覧を見られない（`src/rules/engine.zig` の `Rule`）。

**エンジンのシグネチャは広げなかった**。overlay 付きの式検証は
`expressions.checkWorkflow(*const Workflow)` に集約し、その中で
`wf.jobs` → `job.steps` をエンジンと同じ順に自前で走査する
（診断の並び順が変わらない）。`expression_rule` は `check_workflow` だけを持つ。
`checkJob` / `checkStep` は overlay なしの入口として public のまま残し、単体テストが使う。

`threadlocal` は採らなかった。`inputs` / `secrets` は workflow 単位、
`matrix` / `needs` は job 単位、`steps` は step index 単位で
`checkWorkflow` のローカル `TypeEnv` を差し替えるだけで足り、
グローバル可変状態を増やさずに済む。

### 5. `typeOf` データフロー

```
ワークフロー YAML
  → yaml parser → workflow parser
  → Engine.run
  → expressions.checkStep / checkJob
  → findAndValidateExpressions
  → ExprParser.parse          （失敗 → EXPR001。型エンジンに入らない）
  → validateNode              （EXPR006/007 は従来どおり AST 走査）
  → expr_check.typeOf(node, env)
       context_access → path をセグメント化し catalog/overlay をウォーク
       function_call  → 子の typeOf → overload の ret
       property_access / index_access
                      → 受け手の typeOf にセグメントを 1 つ適用（#280）。
                        受け手は関数結果なので診断は出さず不明は any
       binary_op ==   → 比較規則（T3 で診断）結果型 bool
       binary_op &&   → merge(lhs, rhs)
       unary_op !     → 子を typeOf し bool
       literals       → string / number / bool / null
  → 診断は DiagnosticList へ（既存 allocator 規約）
```

`typeOf` は失敗しない。不明は `any`。OOM だけ `error{OutOfMemory}`。診断 append 失敗は現行どおり `catch return`。

#### path ウォーク（フラット `context_access.value`）

パーサをネスト AST に作り直さない（影響範囲が EXPR006 autofix の byte 計算に及ぶ）。T1 は path 文字列を走査する。

セグメント規則:

- `.` で分割。ただし `[...]` の内側は分割しない
- 識別子セグメント → object プロパティ
- `*` セグメント → object filter
- `['key']` または `["key"]`（現行パーサは単引用の string_literal を path に連結） → 文字列添字

```zig
pub const Segment = union(enum) {
    ident: []const u8,
    star,
    index_string: []const u8,
};

pub fn walkPath(path: []const u8, env: *const TypeEnv) TypeRef {
    // 1. 先頭識別子で context を lookup。無ければ呼び出し側が EXPR002
    // 2. 以降のセグメントを applySegment
}

fn applySegment(recv: TypeRef, seg: Segment) TypeRef {
    if (recv.kind == .any) return &type_any;
    switch (seg) {
        .ident => |name| return derefProp(recv, name),
        .star => return objectFilter(recv),
        .index_string => |key| return indexString(recv, key),
    }
}
```

`derefProp`:

| receiver | 既知キー | 未知キー |
|---|---|---|
| strict object | その型 | EXPR003、結果 `any` |
| loose object | あればその型、なければ `any` | `any`、診断なし |
| map object | `elem` | `elem` |
| array かつ `deref=true` | 要素が object なら要素に対して deref して array で包む | actionlint と同じ filter 連鎖 |
| string/number/bool/null/array(deref=false) | — | EXPR003「receiver が object でない」、結果 `any` |

`objectFilter` (`.*`):

| receiver | 結果 | 診断 |
|---|---|---|
| `any` | `any` | なし |
| array of object | `array<merge(各 object に filter)>`、`deref=true` | なし |
| object | 各プロパティ型の merge を要素とする array、`deref=true` | なし |
| それ以外 | `any` | EXPR003。カスケードしない |

`indexString`:

- object → `derefProp` と同じ
- array → 文字列添字は GitHub では通常使われない。V1 は `any` + 診断なし（誤検出回避）
- それ以外 → EXPR003、結果 `any`

数値添字 `arr[0]` は現行パーサが弾く（EXPR001）。型規則だけ先に定義する: receiver が array なら `elem`、object なら `any`（キーが静的に不明）、それ以外は EXPR003。パーサ拡張は Follow-up。

### 6. 比較規則（EXPR017 / ADR D6）

`checkCompare(op, lhs, rhs) bool` — `false` のときだけ診断。結果型は常に `bool`。

`==` / `!=`:

```
any または null を含む     → ok
number|bool|string 同士    → ok（暗黙変換は警告しない）
number|bool|string vs obj/arr → EXPR017
object vs object|null|any  → ok
array vs array             → 要素型を再帰。不可なら EXPR017
array vs null|any          → ok
その他                     → EXPR017
```

`<` `>` `<=` `>=`:

```
any を含む                 → ok
number|string 同士         → ok
null|bool|object|array を含む → EXPR017
```

severity は warning。メッセージ例:

```
"number" value cannot be compared to "string" value with "==" operator
```

actionlint の文言に合わせ、`display` の出力をそのまま埋め込む。

### 7. `validateNode` との共存

T0 では `validateNode` を変更しない。T1 以降の差し込み位置:

```zig
fn validateNode(...) void {
    switch (node.kind) {
        .context_access => {
            // T1: expr_check.checkContextAccess(...) が EXPR002/EXPR003 を出す
            // 現行 validateContextAccess は削除し、二重診断を防ぐ
        },
        .function_call => {
            validateFunctionCall(...); // EXPR004/005/006。T2 で catalog の arity を使う
            for (node.children) |*child| validateNode(..., child, ...);
        },
        .binary_op => {
            if (isCompare(node.value)) {
                // T3: 子を typeOf して EXPR017
            }
            checkUnsoundCondition(...); // EXPR007 は残す
            for (node.children) |*child| validateNode(..., child, ...);
        },
        // literals: 何もしない
    }
}
```

EXPR002 の「未知 context」は `catalog.lookupContext == null` と同等なので、T1 で情報源を一本化する。許可 context の集合は T0 時点で現行 12 個をカタログにそのまま移す。

### 8. エラーハンドリング

| 失敗 | 扱い |
|---|---|
| パース失敗 | EXPR001。型エンジン未起動 |
| 未知 context | EXPR002 error |
| 未知プロパティ / 非 object deref | EXPR003 warning。結果型 `any` |
| 未知関数 | EXPR004 error。呼び出しの型は `any` |
| 引数個数 | EXPR005 error。戻り値型はシグネチャがあればそれを使う |
| 比較不能 | EXPR017 warning。結果型 `bool` |
| OOM | 現行どおり診断を捨てて return |
| arena OOM | merge を `any` に倒す。診断は出さない |

Span: 現行どおり `base_span`（式全体）。セグメント単位の span は `ExprNode.start_byte` があるが、フラット path ではプロパティ単位に切れない。T1 は式全体 span のまま（EXPR003 の現行と互換）。セグメント span はパーサをネスト化する Follow-up。

診断メッセージの文字列は `allocator` 経由で `DiagnosticList` が所有する。型エンジンは `[]const u8` を返さず、呼び出し側が `allocPrint` する（現行 EXPR002/003 と同じ）。

### 9. 設定・逃げ道

新キーなし。既存:

```yaml
rules:
  EXPR003:
    enabled: false          # プロパティ型警告を止める
  EXPR017:
    enabled: false          # 比較型警告を止める
    severity: error         # あるいは上げる
ignore:
  - ".github/workflows/legacy.yml"
```

`typecheck:` や `strict_event_payload:` は追加しない。厳しさは ADR D5 の `any` 倒しで固定し、ユーザが触るのはルール単位だけにする。

### 10. バイナリサイズ

計測方法（実装 PR のチェックリスト）:

```bash
zig build -Doptimize=ReleaseSmall
stat -c%s zig-out/bin/zghalint
```

予算: カタログ投入による増分 **32 KiB 未満**（ADR D7）。超えた場合の対処順は (1) プロパティ名文字列の intern（同一 `"string"` を共有）(2) `Prop` 配列の圧縮 (3) **payload テーブルは依然禁止**。

`Type` はポインタ共有なので、`github` の 40 プロパティがすべて `&type_string` を指せばスカラー分の rodata は 5 個で足りる。

## 段階導入とテスト

各イテレーションは独立 PR。本設計 issue の成果物はドキュメントのみ。

| 段階 | 内容 | テストの核 |
|---|---|---|
| T0 | `Type` / catalog / `typeOf`（診断なし） | intern 同一性、`display`、`assignable`/`merge` の表、`github.sha`→string、`github.event.foo`→any、`job.unknown` はまだ診断しない |
| T1 | path ウォークを EXPR003 に接続 | 既存 EXPR003 テストがグリーンのまま。追加: `github.repository.permissions` が EXPR003。`github.event.foo` は沈黙。`steps.x` は沈黙 |
| T2 | シグネチャ表へ EXPR004/005 を移行。戻り値型 | `startsWith(github.sha, 'a')` の型が bool。`startsWith(github.event, 'a')` は T2 時点では **診断しない**（T5 で EXPR018 が拾う）が typeOf は bool |
| T3 | EXPR017 | §6 の行列を表駆動テスト。`any` 短絡。`github.event > 3` は発火、`github.event.issue.number == 'foo'` は沈黙 |
| #124 | curated scalar overlay | `github.event.issue == 'bug'` / `github.event.pull_request.draft > 1` が発火。curated 配下の typo は無診断 |
| T4 | overlay 接続 | EXPR010〜EXPR014 の既存テストが二重診断にならないこと |
| T5 | EXPR018（引数型・補間値） | `startsWith(github.event, 'a')` が発火。overlay 未接続の loose context と `if:` 条件は沈黙 |

T0 の表駆動例:

```zig
test "catalog: github.ref_protected is bool" {
    const ty = walkPath("github.ref_protected", &TypeEnv{});
    try std.testing.expectEqual(TypeKind.bool, ty.kind);
}

test "catalog: an uncurated github.event path is any" {
    const ty = walkPath("github.event.deployment.payload", &TypeEnv{});
    try std.testing.expectEqual(TypeKind.any, ty.kind);
}

test "merge: number with string is any" {
    const ty = merge(null, &type_number, &type_string);
    try std.testing.expectEqual(TypeKind.any, ty.kind);
}
```

既存 EXPR001〜EXPR007 のインラインテストは T1 以降もすべて残す。新規警告は **追加テストでピン止め** し、既存の「通る式」を赤くしない。

## 既存診断との差分（実装者が驚かないため）

T1 で新たに EXPR003 が出る例（true positive）:

```yaml
- run: echo ${{ github.repository.permissions.admin }}
# repository は string。プロパティアクセスは意味をなさない
- if: job.unknown == 'x'
# job は strict。unknown は存在しない
```

T1 でも沈黙する例（意図的）:

```yaml
- run: echo ${{ github.event.pull_request.head.sha }}
- run: echo ${{ steps.setup.outputs.v }}
- run: echo ${{ matrix.os }}
- if: github.event.issue.number == 'foo'   # curated 後も scalar 同士なので沈黙
- run: echo ${{ github.event.issue.numer }} # curated 配下の typo も沈黙
```

T3 で EXPR017 が出る例:

```yaml
- if: github.event > 3
- if: github.event_name == 1
- if: secrets.FOO == 1          # map of string vs number
- if: github.ref_protected > 1  # bool vs number、関係演算
```

## 実装イテレーション（後続 issue 用）

本設計の実装は issue #94 の外。推奨コミット分割:

1. Tidy First: `expr_type.zig` + スカラー intern + assignable/merge/display のテスト
2. `expr_catalog.zig` に github/runner/job/strategy/maps/loose contexts。`github_properties` との一致テスト（名前集合が現行配列を包含）
3. `expr_check.zig` の path ウォーク。診断なし
4. T1 接続（EXPR003）
5. T2 シグネチャ移行
6. T3 EXPR017
7. ドキュメント: `docs/rules.md` に EXPR017 行（T3 の PR で追加。本設計 PR では rules.md を触らない）

各コミットで `zig build && zig fmt --check src/ build.zig && zig build test --summary all`。

## Follow-up

ADR 「Follow-up」と同じ。実装順の目安だけここへ落とす。

1. EXPR010〜EXPR014 先行 → T4 overlay
2. `github.event.inputs` overlay（SYN017）
3. パーサの数値添字
4. EXPR018（引数型と補間値。#162 で完了）
5. curated scalar（#124 で完了。ADR D3-a）
6. 型 narrowing
7. 関数名 case-insensitive

## 実装状況（T0〜T5）

T0〜T3 を `src/rules/expr_type.zig` / `expr_catalog.zig` / `expr_check.zig`、
T4（steps / matrix / needs / inputs / secrets の overlay）を
`src/rules/expr_overlay.zig` + `expressions.checkWorkflow` として実装済み。
`github.event` の curated scalar overlay（ADR D3-a / #124）も `expr_catalog.zig` に
入っている（`github_event` とその配下の `event_*` 定数）。

T5（EXPR018）は `FuncSig.args` / `.rest` に `ArgKind`（`any` / `string` /
`string_or_array`）を持たせ、`expr_check.acceptsArg` と
`expr_check.interpolationProblem` で判定する。D3（誤検出ゼロ優先）を守るため:

- `ArgKind` は「絶対に渡せないコンテナ」だけを弾く。スカラーは GitHub が
  文字列へ強制変換するので `number` / `bool` / `null` は常に受理する
- overlay が付かず `catalog.unknown_context` へ落ちたコンテキスト
  （`steps` / `matrix` / `needs` / `inputs` / `jobs`）は
  `ObjectShape.unknown` を持ち、`catalog.isUnmodelledObject` が shape で
  判別して沈黙する。`github.event` と `fromJSON` のオブジェクトリテラルは
  `loose` なので診断対象に残る。
  shape を分けるのは、構造が同一の comptime 定数はアドレスが統合されうる
  ため（実際 aarch64 で `type_loose_object` と同一視された）。
  「unmodelled」はポインタ同一性ではなく型の構造で表す
- 補間側は `${{ }}` 全体の型のみを見る。`toJSON()` や比較の内側にある
  コンテナは対象外
- `if:` は値を評価するだけでレンダリングしないため、補間側の診断は出さない
  （`ExprUse.condition`）。引数型の診断は `if:` でも出る

### バイナリサイズ実測（ADR D7）

`zig build -Doptimize=ReleaseSmall` の `text` セクション:

| | text (bytes) |
|---|---|
| 導入前 | 5,579,402 |
| T0〜T3 投入後 | 5,600,226 |
| 増分 | +20,824（約 20.3 KiB） |

32 KiB の予算内。

T4（#129）投入時。上表とは測定時点のベースラインが異なるため、直前の HEAD で
測り直した値と比較する:

| | text (bytes) |
|---|---|
| T4 直前 | 953,405 |
| T4 投入後 | 957,607 |
| 増分 | +4,202（約 4.1 KiB） |

T5（#162）投入時:

| | text (bytes) |
|---|---|
| T5 直前 | 957,607 |
| T5 投入後 | 959,722 |
| 増分 | +2,115（約 2.1 KiB） |

curated scalar overlay（#124）の増分は同じ計測方法で `text` +1,290 バイト（約 1.3 KiB）。

累計 +28 KiB 程度で、32 KiB の予算内。

## 参考

- `docs/adr/0009-expr-static-typecheck.md` — 決定の単一情報源
- `docs/design/expr006-autofix-design.md` — `ExprNode` の byte 範囲。本エンジンはパーサを壊さない
- `docs/rules.md` Expression 節 — 現行 ID
- actionlint `expr_type.go` / `expr_sema.go`
- GitHub Docs: [Contexts](https://docs.github.com/en/actions/learn-github-actions/contexts), [Expressions](https://docs.github.com/en/actions/learn-github-actions/expressions)
