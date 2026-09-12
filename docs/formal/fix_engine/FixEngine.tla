---------------------------- MODULE FixEngine ----------------------------
(***************************************************************************)
(* Formal model of `src/fix/engine.zig` (`flattenAndSort` + `applyFixes`). *)
(*                                                                         *)
(* Declared specification (docs/adr/0001, docs/design/pbt-strategy.md):    *)
(*   S1  edits are applied back-to-front so byte offsets never shift       *)
(*   S2  overlapping edits are dropped, "first wins by position"           *)
(*   S3  zero-width insertions at the same byte both survive               *)
(*   S4  the result equals the source with every surviving edit applied    *)
(*   S5  order between two same-byte insertions is decided by the sort     *)
(*       tie-break only (ADR 0001 D5, "pinned by golden tests")            *)
(*                                                                         *)
(* Code-derived specification (engine.zig:30-148):                         *)
(*   C1  `isValidEdit` drops end<start and end>len                         *)
(*   C2  stable sort by (start_byte, end_byte)                             *)
(*   C3  `e.start_byte < last_end` is the overlap predicate; a dropped     *)
(*       edit does not advance `last_end`                                  *)
(*   C4  an edit is dropped individually: a multi-edit Fix is not atomic   *)
(*                                                                         *)
(* Abstraction: `snapInsertionToLineEnd` (engine.zig:46,82), which moves a *)
(* newline-leading insertion to the end of its physical line before the    *)
(* sort, is not modelled; positions here are the ones the sort sees.       *)
(*                                                                         *)
(* The source is a sequence of N distinguishable tokens <<"s",i>> and each *)
(* replacement is a sequence of tokens <<"r",fix,edit,k>> so the output    *)
(* reveals exactly which bytes survived and in what order.                 *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANT N            \* source length in bytes
CONSTANT MaxFixes     \* number of Fix records collected by collectFixes
CONSTANT MaxEditsPerFix

Src == [i \in 1..N |-> <<"s", i>>]

\* ---------------------------------------------------------------------------
\* Input space.  An edit shape is (start, end, replacement length).  Ends up
\* to N+1 and end<start are included so that C1 is exercised.
\* ---------------------------------------------------------------------------
Shapes == [s : 0..N, e : 0..(N+1), len : 0..1]

Repl(f, k, len) == [j \in 1..len |-> <<"r", f, k, j>>]

MkEdit(f, k, sh) == [s |-> sh.s, e |-> sh.e, r |-> Repl(f, k, sh.len), fix |-> f, idx |-> k]

EditSeqs(f) ==
    UNION { { [k \in 1..m |-> MkEdit(f, k, shs[k])] : shs \in [1..m -> Shapes] }
            : m \in 1..MaxEditsPerFix }

\* Up to two Fix records (enumerated explicitly so TLC can build the set).
ASSUME MaxFixes = 2
FixLists ==
    { <<a>> : a \in EditSeqs(1) }
    \cup { <<a, b>> : a \in EditSeqs(1), b \in EditSeqs(2) }

\* ---------------------------------------------------------------------------
\* flattenAndSort, written functionally.
\* ---------------------------------------------------------------------------
IsValid(e) == e.e >= e.s /\ e.e <= N                              \* C1

Flatten(fl) ==
    LET RECURSIVE Cat(_)
        Cat(f) == IF f > Len(fl) THEN <<>>
                  ELSE SelectSeq(fl[f], IsValid) \o Cat(f + 1)
    IN Cat(1)

\* Stable insertion sort by (s, e): equal keys keep their input order (C2).
Less(a, b) == a.s < b.s \/ (a.s = b.s /\ a.e < b.e)

Insert(sorted, x) ==
    LET RECURSIVE Ins(_, _)
        Ins(sq, i) == IF i > Len(sq) THEN Append(sq, x)
                      ELSE IF Less(x, sq[i])
                           THEN SubSeq(sq, 1, i - 1) \o <<x>> \o SubSeq(sq, i, Len(sq))
                           ELSE Ins(sq, i + 1)
    IN Ins(sorted, 1)

Sort(seq) ==
    LET RECURSIVE Go(_, _)
        Go(acc, i) == IF i > Len(seq) THEN acc ELSE Go(Insert(acc, seq[i]), i + 1)
    IN Go(<<>>, 1)

\* Overlap filter (C3): ascending, keep e iff e.s >= last_end.
Keep(sorted) ==
    LET RECURSIVE Go(_, _, _)
        Go(acc, i, last_end) ==
            IF i > Len(sorted) THEN acc
            ELSE LET e == sorted[i]
                 IN IF Len(acc) > 0 /\ e.s < last_end
                    THEN Go(acc, i + 1, last_end)
                    ELSE Go(Append(acc, e), i + 1, e.e)
    IN Go(<<>>, 1, 0)

Reverse(seq) == [i \in 1..Len(seq) |-> seq[Len(seq) - i + 1]]

KeptAsc(fl) == Keep(Sort(Flatten(fl)))
Descending(fl) == Reverse(KeptAsc(fl))                            \* what applyFixes iterates

\* ---------------------------------------------------------------------------
\* Reference semantics (S4): left-to-right splice of the surviving edits.
\* ---------------------------------------------------------------------------
Expected(fl) ==
    LET kept == KeptAsc(fl)
        RECURSIVE Fwd(_, _)
        Fwd(k, pos) ==
            IF k > Len(kept) THEN SubSeq(Src, pos + 1, N)
            ELSE SubSeq(Src, pos + 1, kept[k].s) \o kept[k].r \o Fwd(k + 1, kept[k].e)
    IN Fwd(1, 0)

\* ---------------------------------------------------------------------------
\* applyFixes as a state machine: the back-to-front copy loop.
\* ---------------------------------------------------------------------------
VARIABLES fixes, edits, i, src_pos, result, pc

vars == <<fixes, edits, i, src_pos, result, pc>>

Init ==
    /\ fixes \in FixLists
    /\ edits = Descending(fixes)
    /\ i = 1
    /\ src_pos = N
    /\ result = <<>>
    /\ pc = "loop"

Step ==
    /\ pc = "loop"
    /\ i <= Len(edits)
    /\ LET e == edits[i]
           after == SubSeq(Src, e.e + 1, src_pos)     \* source[end .. src_pos)
       IN /\ result' = e.r \o after \o result
          /\ src_pos' = e.s
    /\ i' = i + 1
    /\ UNCHANGED <<fixes, edits, pc>>

Finish ==
    /\ pc = "loop"
    /\ i > Len(edits)
    /\ result' = SubSeq(Src, 1, src_pos) \o result
    /\ pc' = "done"
    /\ UNCHANGED <<fixes, edits, i, src_pos>>

Done == pc = "done" /\ UNCHANGED vars

Next == Step \/ Finish \/ Done

Spec == Init /\ [][Next]_vars

\* ---------------------------------------------------------------------------
\* Properties
\* ---------------------------------------------------------------------------

\* C3 never lets the copy loop underflow (`src_pos - e.end_byte`).
NoUnderflow == pc = "loop" /\ i <= Len(edits) => edits[i].e <= src_pos

\* S2: the surviving edits are pairwise disjoint (touching is allowed).
KeptDisjoint ==
    LET k == KeptAsc(fixes)
    IN \A a, b \in 1..Len(k) : a < b => k[a].e <= k[b].s

\* S4: the loop refines the reference semantics.
LoopMatchesSpec == pc = "done" => result = Expected(fixes)

\* S3: two zero-width insertions at one byte both survive.
InsertionsCoexist ==
    LET flat == Flatten(fixes)
        kept == KeptAsc(fixes)
        Survives(a) == \E b \in 1..Len(kept) : kept[b].fix = flat[a].fix /\ kept[b].idx = flat[a].idx
        Covered(a) == \E c \in 1..Len(flat) : c # a /\ flat[c].s < flat[a].s /\ flat[c].e > flat[a].s
    IN \A a \in 1..Len(flat) :
         (flat[a].s = flat[a].e /\ IsValid(flat[a])) => (Survives(a) \/ Covered(a))

\* C4: a Fix is applied atomically (all of its valid edits or none).
\* Expected to FAIL: the engine filters per edit, not per Fix.
\* Only fixes whose own edits are pairwise disjoint are considered, so the
\* counterexample is a genuine cross-fix interaction.
Disjoint(a, b) == a.e <= b.s \/ b.e <= a.s
SelfConsistent(sq) == \A x, y \in 1..Len(sq) : x < y => Disjoint(sq[x], sq[y])
FixAtomic ==
    LET flat == Flatten(fixes)
        kept == KeptAsc(fixes)
        Applied(f, k) == \E b \in 1..Len(kept) : kept[b].fix = f /\ kept[b].idx = k
    IN \A f \in 1..Len(fixes) :
         LET valid == SelectSeq(fixes[f], IsValid)
         IN SelfConsistent(valid) =>
              (\A k \in 1..Len(valid) : Applied(f, valid[k].idx))
              \/ (\A k \in 1..Len(valid) : ~Applied(f, valid[k].idx))

\* S5: the output does not depend on the order collectFixes saw the fixes.
\* Expected to FAIL: same-byte insertions and same-range replacements are
\* ordered / chosen by list position (stable sort tie-break).
OrderIndependent == Expected(fixes) = Expected(Reverse(fixes))

\* Same as above but with zero-width insertions excluded, to isolate the
\* "same-range replacement: first registered rule wins" case.
NoInsertions == \A e \in { Flatten(fixes)[k] : k \in 1..Len(Flatten(fixes)) } : e.s < e.e
OrderIndependentNoInsert == NoInsertions => OrderIndependent

=============================================================================
