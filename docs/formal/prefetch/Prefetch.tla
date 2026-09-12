----------------------------- MODULE Prefetch -----------------------------
(***************************************************************************)
(* Formal model of `src/rules/prefetch.zig` across three consecutive lint  *)
(* runs sharing one on-disk cache (docs/design/network-io.md).             *)
(*                                                                         *)
(* Declared specification (network-io.md, "disk -> GraphQL -> REST"):      *)
(*   S1  a warm run (same workflow, cache < 24h) makes no network request  *)
(*   S2  a result obtained from the network is never degraded afterwards   *)
(*   S3  RateLimited aborts the GraphQL phase ("中断")                       *)
(*   S4  every ref the rules need is resolved by the time rules run        *)
(*                                                                         *)
(* Code-derived specification:                                             *)
(*   C1  applyCacheEntry removes a repo from `sets.repos` as soon as its   *)
(*       archived flag is cached (SC004 active); buildRepoInputs iterates  *)
(*       `sets.repos` only, so SHAs of a removed repo never reach GraphQL  *)
(*   C2  tryGraphQlBatch: NoToken / other error -> false (REST refetches   *)
(*       every set, unreduced); RateLimited / deadline -> idx > 0          *)
(*   C3  REST group failure writes `.unknown` over the whole group; the    *)
(*       rule caches are `put` (overwrite)                                 *)
(*   C4  persistRepoResult overwrites the disk entry with only the SHAs    *)
(*       queried in this run                                               *)
(*   C5  rules fetch lazily on a cache miss and never persist              *)
(*   C6  only GraphQL results are persisted (REST results never are)       *)
(*                                                                         *)
(* Workflow under test: run 1 pins A1; runs 2 and 3 pin A1, A2 (repo A)    *)
(* and B1 (repo B). Ground truth: every SHA has a tag, no repo is missing. *)
(*                                                                         *)
(* Abstraction: one GraphQL POST per repo. The code packs up to 30 repos   *)
(* (20 when SC008 is active) into one POST, so every scenario in which a   *)
(* later batch fails after an earlier one succeeded needs more than 30     *)
(* (21+) distinct action repositories across the linted workflows.         *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANT ArchActive     \* SC004 enabled (TRUE) or disabled (FALSE)

Refs == {"A1", "A2", "B1"}
Repos == {"A", "B"}
RepoOf == [r \in Refs |-> IF r \in {"A1", "A2"} THEN "A" ELSE "B"]
RunRefs == << {"A1"}, {"A1", "A2", "B1"}, {"A1", "A2", "B1"} >>
MaxRun == Len(RunRefs)

Tag == {"none", "has_tag", "unknown"}
Outcomes == {"ok", "noToken", "rateLimited", "failed"}

\* Fixed iteration order of `sets.repos` (a hash map in the code; the order
\* only matters for which batch a failure lands on, and both orders are
\* covered by the nondeterministic outcome per batch).
NextRepo(pending) == IF "A" \in pending THEN "A" ELSE "B"

VARIABLES
    run,          \* 1..MaxRun
    phase,        \* "disk" | "gql" | "rest" | "check" | "persist" | "end" | "final"
    disk,         \* [Repos -> [arch: BOOLEAN, shas: SUBSET Refs]]  (has_tag entries)
    repoSet,      \* remaining repos after the disk sweep (sets.repos)
    shaSet,       \* remaining SHAs after the disk sweep (sets.sha_refs)
    tagCache,     \* in-memory SC005 cache for this run
    everGood,     \* refs that held has_tag at some point during this run
    gqlDone,      \* repos already answered by GraphQL this run
    usedGql,      \* return value of tryGraphQlBatch
    persistBuf,   \* [Repos -> SUBSET Refs] SHAs queried per repo this run
    persistRepos, \* repos with a buffered GraphQL result
    netCalls,     \* network requests issued this run
    curFail,      \* any transport failure this run
    rateLimitedSeen,
    restUsed,
    prevOk        \* previous run finished clean and fully resolved

vars == << run, phase, disk, repoSet, shaSet, tagCache, everGood, gqlDone, usedGql,
           persistBuf, persistRepos, netCalls, curFail, rateLimitedSeen, restUsed, prevOk >>

EmptyDisk == [p \in Repos |-> [arch |-> FALSE, shas |-> {}]]

Init ==
    /\ run = 1
    /\ phase = "disk"
    /\ disk = EmptyDisk
    /\ repoSet = {} /\ shaSet = {}
    /\ tagCache = [r \in Refs |-> "none"]
    /\ everGood = {}
    /\ gqlDone = {} /\ usedGql = FALSE
    /\ persistBuf = [p \in Repos |-> {}] /\ persistRepos = {}
    /\ netCalls = 0 /\ curFail = FALSE
    /\ rateLimitedSeen = FALSE /\ restUsed = FALSE
    /\ prevOk = FALSE

\* ---------------------------------------------------------------------------
\* Phase 1: collectRefs + applyDiskCache (C1).
\* ---------------------------------------------------------------------------
DiskSweep ==
    /\ phase = "disk"
    /\ LET refs == RunRefs[run]
           repos0 == {RepoOf[r] : r \in refs}
           hitRepos == {p \in repos0 : ArchActive /\ disk[p].arch}
           hitShas == {r \in refs : r \in disk[RepoOf[r]].shas}
       IN /\ repoSet' = repos0 \ hitRepos
          /\ shaSet' = refs \ hitShas
          /\ tagCache' = [r \in Refs |-> IF r \in hitShas THEN "has_tag" ELSE "none"]
          /\ everGood' = hitShas
    /\ gqlDone' = {} /\ usedGql' = FALSE
    /\ persistBuf' = [p \in Repos |-> {}] /\ persistRepos' = {}
    /\ netCalls' = 0 /\ curFail' = FALSE
    /\ rateLimitedSeen' = FALSE /\ restUsed' = FALSE
    /\ phase' = "gql"
    /\ UNCHANGED << run, disk, prevOk >>

\* ---------------------------------------------------------------------------
\* Phase 2: tryGraphQlBatch, one repo per POST (C2).
\* ---------------------------------------------------------------------------
GqlNoRepos ==
    /\ phase = "gql" /\ repoSet = {}
    /\ usedGql' = FALSE /\ phase' = "rest"
    /\ UNCHANGED << run, disk, repoSet, shaSet, tagCache, everGood, gqlDone,
                    persistBuf, persistRepos, netCalls, curFail, rateLimitedSeen, restUsed, prevOk >>

GqlAllDone ==
    /\ phase = "gql" /\ repoSet # {} /\ repoSet \subseteq gqlDone
    /\ usedGql' = TRUE /\ phase' = "rest"
    /\ UNCHANGED << run, disk, repoSet, shaSet, tagCache, everGood, gqlDone,
                    persistBuf, persistRepos, netCalls, curFail, rateLimitedSeen, restUsed, prevOk >>

GqlBatch ==
    /\ phase = "gql" /\ repoSet # {} /\ ~(repoSet \subseteq gqlDone)
    /\ LET p == NextRepo(repoSet \ gqlDone)
           shas == {r \in shaSet : RepoOf[r] = p}
       IN \E out \in Outcomes :
            /\ netCalls' = netCalls + 1
            /\ IF out = "ok" THEN
                  /\ tagCache' = [r \in Refs |-> IF r \in shas THEN "has_tag" ELSE tagCache[r]]
                  /\ everGood' = everGood \cup shas
                  /\ persistBuf' = [persistBuf EXCEPT ![p] = shas]
                  /\ persistRepos' = persistRepos \cup {p}
                  /\ gqlDone' = gqlDone \cup {p}
                  /\ UNCHANGED << usedGql, phase, curFail, rateLimitedSeen >>
               ELSE
                  /\ curFail' = TRUE
                  /\ rateLimitedSeen' = (out = "rateLimited")
                  /\ usedGql' = (out = "rateLimited" /\ gqlDone # {})   \* idx > 0
                  /\ phase' = "rest"
                  /\ UNCHANGED << tagCache, everGood, persistBuf, persistRepos, gqlDone >>
    /\ UNCHANGED << run, disk, repoSet, shaSet, restUsed, prevOk >>

\* ---------------------------------------------------------------------------
\* Phase 3: REST fallback over the *unreduced* sets (C2, C3, C6).
\* ---------------------------------------------------------------------------
RestSkipped ==
    /\ phase = "rest" /\ usedGql
    /\ phase' = "check"
    /\ UNCHANGED << run, disk, repoSet, shaSet, tagCache, everGood, gqlDone, usedGql,
                    persistBuf, persistRepos, netCalls, curFail, rateLimitedSeen, restUsed, prevOk >>

RestFallback ==
    /\ phase = "rest" /\ ~usedGql
    /\ LET groups == {RepoOf[r] : r \in shaSet}
       IN \E out \in [groups -> {"ok", "fail"}] :
            /\ tagCache' = [r \in Refs |->
                              IF r \in shaSet
                              THEN IF out[RepoOf[r]] = "ok" THEN "has_tag" ELSE "unknown"
                              ELSE tagCache[r]]
            /\ everGood' = everGood \cup {r \in shaSet : out[RepoOf[r]] = "ok"}
            /\ curFail' = (curFail \/ (\E g \in groups : out[g] = "fail"))
            /\ netCalls' = netCalls + Cardinality(groups)
                           + (IF ArchActive THEN Cardinality(repoSet) ELSE 0)
    /\ restUsed' = (repoSet # {} \/ shaSet # {})
    /\ phase' = "check"
    /\ UNCHANGED << run, disk, repoSet, shaSet, gqlDone, usedGql, persistBuf, persistRepos,
                    rateLimitedSeen, prevOk >>

\* ---------------------------------------------------------------------------
\* Phase 4: rules run; SC005 fetches lazily on a cache miss (C5).
\* ---------------------------------------------------------------------------
LazyCheck ==
    /\ phase = "check"
    /\ LET misses == {r \in RunRefs[run] : tagCache[r] = "none"}
       IN \E out \in [misses -> {"ok", "fail"}] :
            /\ tagCache' = [r \in Refs |->
                              IF r \in misses
                              THEN IF out[r] = "ok" THEN "has_tag" ELSE "unknown"
                              ELSE tagCache[r]]
            /\ everGood' = everGood \cup {r \in misses : out[r] = "ok"}
            /\ curFail' = (curFail \/ (\E r \in misses : out[r] = "fail"))
            /\ netCalls' = netCalls + Cardinality(misses)
    /\ phase' = "persist"
    /\ UNCHANGED << run, disk, repoSet, shaSet, gqlDone, usedGql, persistBuf, persistRepos,
                    rateLimitedSeen, restUsed, prevOk >>

\* ---------------------------------------------------------------------------
\* Phase 5: persistRepoResult for every buffered GraphQL result (C4).
\* ---------------------------------------------------------------------------
Persist ==
    /\ phase = "persist"
    /\ disk' = [p \in Repos |-> IF p \in persistRepos
                                THEN [arch |-> TRUE, shas |-> persistBuf[p]]
                                ELSE disk[p]]
    /\ phase' = "end"
    /\ UNCHANGED << run, repoSet, shaSet, tagCache, everGood, gqlDone, usedGql, persistBuf,
                    persistRepos, netCalls, curFail, rateLimitedSeen, restUsed, prevOk >>

EndRun ==
    /\ phase = "end"
    /\ prevOk' = (~curFail /\ \A r \in RunRefs[run] : tagCache[r] = "has_tag")
    /\ IF run < MaxRun THEN run' = run + 1 /\ phase' = "disk"
                       ELSE run' = run /\ phase' = "final"
    /\ UNCHANGED << disk, repoSet, shaSet, tagCache, everGood, gqlDone, usedGql, persistBuf,
                    persistRepos, netCalls, curFail, rateLimitedSeen, restUsed >>

Final == phase = "final" /\ UNCHANGED vars

Next == DiskSweep \/ GqlNoRepos \/ GqlAllDone \/ GqlBatch \/ RestSkipped \/ RestFallback
        \/ LazyCheck \/ Persist \/ EndRun \/ Final

Spec == Init /\ [][Next]_vars

\* ---------------------------------------------------------------------------
\* Properties
\* ---------------------------------------------------------------------------

\* S2: once a SHA is known to have a tag this run, it is not degraded to unknown.
NoDowngrade == \A r \in everGood : tagCache[r] # "unknown"

\* S1: a run that repeats a clean, fully resolved run over the same refs is warm.
WarmRunIsWarm ==
    (phase = "end" /\ run >= 2 /\ RunRefs[run] = RunRefs[run - 1] /\ prevOk /\ ~curFail)
        => netCalls = 0

\* Cache completeness: after a clean run every pinned SHA is on disk, so the
\* next run can be warm at all.
CleanRunPersistsAll ==
    (phase = "end" /\ ~curFail) => \A r \in RunRefs[run] : r \in disk[RepoOf[r]].shas

\* Same, restricted to runs where GraphQL was actually used (rules out C6).
CleanGqlRunPersistsAll ==
    (phase = "end" /\ ~curFail /\ usedGql) => \A r \in RunRefs[run] : r \in disk[RepoOf[r]].shas

\* S3: RateLimited aborts; REST is not attempted afterwards.
RateLimitAborts == rateLimitedSeen => ~restUsed

\* S4: every ref of the run is resolved (has_tag or unknown) once rules ran.
AllResolvedAtEnd == phase \in {"persist", "end"} => \A r \in RunRefs[run] : tagCache[r] # "none"

=============================================================================
