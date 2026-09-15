# Prefetch — TLC の結果と反例

対象: `src/rules/prefetch.zig`（disk → GraphQL → REST の 3 層プリフェッチ）と `docs/design/network-io.md` の宣言。
モデル: [`Prefetch.tla`](Prefetch.tla)。同じディスクキャッシュを共有する 3 回連続の lint 実行をモデル化した。

- 実行 1 はリポジトリ A の SHA `A1` だけを pin している。
- 実行 2 と 3 は `A1`, `A2`（リポジトリ A）と `B1`（リポジトリ B）を pin している。
- 真実: すべての SHA にタグが付いている。archived なリポジトリはない。
- 定数 `ArchActive` は SC004（archived 検出）が有効かどうか。両方の値で検査した。

## 実行方法

```bash
cd docs/formal/prefetch
java -cp /path/to/tla2tools.jar tlc2.TLC -workers auto -config Prefetch_archTRUE.cfg  Prefetch.tla
java -cp /path/to/tla2tools.jar tlc2.TLC -workers auto -config Prefetch_archFALSE.cfg Prefetch.tla
```

cfg には全不変条件が並んでいる。TLC は最初に見つけた違反で止まるので、1 つずつ確かめたい場合は cfg の `INVARIANTS` を 1 行にして実行する。

## 結果一覧

| 性質 | 由来 | ArchActive=TRUE | ArchActive=FALSE |
| --- | --- | --- | --- |
| `AllResolvedAtEnd` | S4（ルール実行時に全 SHA が解決済み） | 成立（297 状態） | 成立（472 状態） |
| `RateLimitAborts` | S3（RateLimited は「中断」） | **違反** | **違反** |
| `NoDowngrade` | S2（一度取れた結果は劣化しない） | **違反** | **違反** |
| `WarmRunIsWarm` | S1（同じワークフローの 2 回目はネットワーク 0） | **違反** | **違反** |
| `CleanRunPersistsAll` | 「成功した実行の結果はディスクに残る」 | **違反** | **違反** |
| `CleanGqlRunPersistsAll` | 同上、GraphQL 経由に限定 | **違反** | **違反** |

## 反例 1: RateLimited は「中断」ではなく REST への切り替え（`RateLimitAborts`）

```
run 1  DiskSweep     shaSet={A1} repoSet={A}
       GqlBatch(A)   outcome=rateLimited, idx=0  -> usedGql=FALSE, rateLimitedSeen=TRUE
       RestFallback  netCalls=2, restUsed=TRUE
```

`network-io.md` は RateLimited を「GraphQL フェーズを中断する」と説明している。実装は最初のバッチで RateLimited を受けると `false` を返し、その結果 REST フォールバックが**同じ GitHub API に対して**さらにリクエストを送る。レート制限を受けた直後に REST を叩くので、状況を悪化させる方向に動く。2 バッチ目以降で RateLimited を受けた場合だけ「中断」（`idx > 0` で `true`）になる。

## 反例 2: 成功した結果が `unknown` に上書きされる（`NoDowngrade`）

```
run 1  GqlBatch(A) failed -> RestFallback ok  (A1 = has_tag, ディスクには書かれない)
run 2  DiskSweep   shaSet={A1,A2,B1} repoSet={A,B}
       GqlBatch(A) ok      -> A1,A2 = has_tag  (everGood ∋ A1,A2)
       GqlBatch(B) failed  -> tryGraphQlBatch は false
       RestFallback        -> REST は全 SHA を取り直す。グループ A が失敗
                              -> tagCache[A1] = tagCache[A2] = "unknown"
```

**前提**: モデルはリポジトリ 1 つを 1 バッチとしているが、実装は 1 POST に最大 30 リポジトリ（SC008 有効時は 20）を詰める。したがって「2 バッチ目の失敗」は、lint 対象全体で 31 以上（SC008 有効時は 21 以上）の異なるアクションリポジトリを参照しているときにだけ起きる。

GraphQL の 2 バッチ目が失敗すると `tryGraphQlBatch` は「GraphQL は使えなかった」として `false` を返す。REST フォールバックは**縮小されていない**元の集合を全部取り直し、REST 側の一時的な失敗で SC005 のキャッシュに `unknown` を `put`（上書き）する。GraphQL 1 バッチ目で得た正しい結果は捨てられ、ユーザーには「解決できませんでした」系の診断が出る。

## 反例 3: ウォームランなのに毎回ネットワークに出る（`WarmRunIsWarm`）

### SC004 有効（ArchActive=TRUE）

```
run 1  GqlBatch(A) ok -> Persist: disk[A] = {arch TRUE, shas {A1}}
run 2  DiskSweep: A の archived フラグがキャッシュ済み -> repoSet から A を除去
       A2 はディスクにない (shaSet={A2,B1}) が repoSet={B} なので GraphQL には乗らない
       GqlBatch(B) ok -> B1
       LazyCheck: SC005 が A2 を遅延取得 (netCalls=2)。遅延取得は永続化されない
       Persist: disk[B] = {B1}。disk[A] は {A1} のまま
run 3  同じワークフロー、前回は clean。DiskSweep: shaSet={A2} repoSet={}
       GqlNoRepos -> RestFallback が A2 を取得 (netCalls=1)
```

archived フラグがディスクに乗った瞬間、そのリポジトリの新しい SHA は GraphQL バッチに入らなくなる。遅延取得と REST フォールバックは永続化しないので、**A2 は毎回ネットワークから取り直され、決してウォームにならない**。ワークフローに新しい pin を 1 つ足しただけで、以後の全実行が 1 リクエスト以上を払い続ける。

### SC004 無効（ArchActive=FALSE）

```
run 1  GqlBatch(A) failed -> REST (永続化なし)
run 2  完全コールド。GqlBatch(A) ok, GqlBatch(B) ok
       Persist: disk[A]={A1,A2}, disk[B]={B1}
run 3  DiskSweep: 全 SHA がヒット (shaSet={}) が repoSet={A,B} は残る
       GqlBatch(A), GqlBatch(B): SHA リスト空のまま 2 リクエスト
       Persist: disk[A].shas = {}, disk[B].shas = {}   <- キャッシュが消える
```

`collectRefs` はどのルールが有効かに関係なく全リポジトリを `sets.repos` に入れ、`applyCacheEntry` は SC004 が有効なときにしか repo を除去しない。SC004 を無効にすると repo が常に残り、**SHA が全部キャッシュ済みでも空の GraphQL を 2 回送り、`persistRepoResult` がその空結果でディスクを上書きする**。次の実行はまたコールドになり、以後ウォームとコールドを交互に繰り返す。

## 反例 4: 成功した実行でもディスクの内容が減る（`CleanRunPersistsAll`）

### SC004 有効

run 2 が clean に終わっても、A2 は遅延取得で来たので `disk[A]` は `{A1}` のまま（反例 3 と同じトレース）。

### SC004 無効

```
run 1  GqlBatch(A) ok -> disk[A]={A1}
run 2  DiskSweep: A1 はヒット、A2,B1 がミス。repoSet={A,B}
       GqlBatch(A) は A2 だけを問い合わせ
       Persist: disk[A].shas = {A2}   <- A1 が消える
```

`persistRepoResult` は「この実行で問い合わせた SHA」だけで新しい `CachedRepo` を作って上書きする。ディスクにあった SHA はマージされないので、キャッシュは「最後に問い合わせた差分」しか覚えていない。ワークフローが 2 つ以上のバージョンを行き来する（例: 複数ブランチで lint する）と、ディスクキャッシュは実質的に機能しない。
