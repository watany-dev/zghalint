#!/usr/bin/env python3
"""Soundness of the SEC022 trust-anchor heuristic (src/rules/security.zig).

Declared specification (SEC022 message / fix hint, tests at security.zig):
  S1  a `workflow_run` gate that a fork can satisfy is reported
  S2  a gate that "verifies the triggering repository" is not reported

Code-derived specification (checkWorkflowRunBranchGate, hasWorkflowRunTrustAnchor,
matchesAnyContext(.equality_operand)):
  C1  gate contexts: head_branch, head_commit.{message,author,committer},
      display_title  -> `reported` needs one of them anywhere outside a string
  C2  anchor: head_repository.{full_name,name,id,owner} directly adjacent to
      `==` (either side), or workflow_run.event adjacent to `==` while the
      condition text does not contain `pull_request`
  C3  an anchor anywhere in the condition suppresses the whole condition;
      boolean structure (||, !, nesting) is not analysed

The condition is modelled as a bounded boolean AST over atoms with known
fork-semantics. Z3 enumerates conditions that the detector suppresses although
a fork can make them true (S2 unsound) and, in the other direction, conditions
reported although no fork can satisfy them (false positives).

Run:  python3 sec022_anchor.py
"""
import itertools

from z3 import And, Bool, BoolVal, Implies, Int, Not, Or, Solver, sat

# ---------------------------------------------------------------------------
# Atom table.
#   fork:  value of the atom in a run whose triggering PR came from a fork; the
#          fork author picks branch name / commit message freely (None).
#   base:  value in a legitimate run from the base repository (None = the
#          maintainer's choice); used to discard contradictory conditions.
#   gate:  mentions a SEC022 gate context.
#   anchorEq: detector sees an anchor context next to `==`.
#   eventEq:  workflow_run.event next to `==`.
#   mentionsPR: literal 'pull_request' in the text.
# ---------------------------------------------------------------------------
ATOMS = [
    # name,                                           fork,  base,  gate,  anchorEq, eventEq, mentionsPR
    ("head_branch == 'main'",                          None,  None,  True,  False,    False,   False),
    ("head_branch != 'main'",                          None,  None,  True,  False,    False,   False),
    ("contains(head_commit.message, 'x')",             None,  None,  True,  False,    False,   False),
    ("head_repository.full_name == github.repository", False, True,  False, True,     False,   False),
    ("head_repository.full_name != github.repository", True,  False, False, False,    False,   False),
    ("head_repository.name == 'repo'",                 True,  True,  False, True,     False,   False),
    ("head_repository.owner.login == 'org'",           False, True,  False, True,     False,   False),
    ("workflow_run.event == 'push'",                   False, True,  False, False,    True,    False),
    ("workflow_run.event == 'pull_request'",           True,  True,  False, False,    True,    True),
    ("workflow_run.event != 'pull_request'",           False, True,  False, False,    False,   True),
    ("workflow_run.conclusion == 'success'",           None,  None,  False, False,    False,   False),
    ("head_repository.fork == true",                   True,  False, False, False,    False,   False),
    ("head_repository.fork == false",                  False, True,  False, False,    False,   False),
]
NA = len(ATOMS)
COL_FORK, COL_BASE, COL_GATE, COL_ANCHOR, COL_EVENT, COL_PR = range(1, 7)
CHOICE_ATOMS = [a for a in range(NA) if ATOMS[a][COL_FORK] is None]

MAX_NODES = 5
K_NONE, K_ATOM, K_NOT, K_AND, K_OR = range(5)


def build():
    """Return the solver and the decoded views of a bounded AST rooted at 0."""
    s = Solver()
    kind = [Int(f"kind_{i}") for i in range(MAX_NODES)]
    atom = [Int(f"atom_{i}") for i in range(MAX_NODES)]
    left = [Int(f"left_{i}") for i in range(MAX_NODES)]
    right = [Int(f"right_{i}") for i in range(MAX_NODES)]

    for i in range(MAX_NODES):
        s.add(kind[i] >= K_NONE, kind[i] <= K_OR)
        s.add(atom[i] >= 0, atom[i] < NA)
        # children point strictly forward so the tree is finite; leaves and
        # unused nodes pin their child slots to a dummy value.
        inner = Or(kind[i] == K_NOT, kind[i] == K_AND, kind[i] == K_OR)
        binary = Or(kind[i] == K_AND, kind[i] == K_OR)
        s.add(Implies(inner, And(left[i] > i, left[i] < MAX_NODES)))
        s.add(Implies(Not(inner), left[i] == MAX_NODES))
        s.add(Implies(binary, And(right[i] > i, right[i] < MAX_NODES,
                                  left[i] != right[i])))
        s.add(Implies(Not(binary), right[i] == MAX_NODES))
        s.add(Implies(Not(kind[i] == K_ATOM), atom[i] == 0))
    s.add(kind[0] != K_NONE)
    # Node i>0 used only if some parent references it (keeps models tidy)
    for i in range(1, MAX_NODES):
        used = Or([Or(And(kind[p] == K_NOT, left[p] == i),
                     And(Or(kind[p] == K_AND, kind[p] == K_OR),
                         Or(left[p] == i, right[p] == i)))
                   for p in range(i)])
        s.add((kind[i] != K_NONE) == used)

    def child(i, arr, which):
        idx = which[i]
        return Or([And(idx == j, arr[j]) for j in range(i + 1, MAX_NODES)])

    def atom_flag(i, col):
        return Or([And(atom[i] == a, BoolVal(ATOMS[a][col])) for a in range(NA)])

    def evaluate(tag, col, choice):
        """Truth value per node under `col` semantics, `choice` per atom."""
        val = [Bool(f"val_{tag}_{i}") for i in range(MAX_NODES)]

        def leaf(i):
            cases = []
            for a in range(NA):
                fv = ATOMS[a][col]
                v = choice[a] if fv is None else BoolVal(fv)
                cases.append(And(atom[i] == a, v))
            return Or(cases)

        for i in range(MAX_NODES):
            s.add(Implies(kind[i] == K_NONE, Not(val[i])))
            s.add(Implies(kind[i] == K_ATOM, val[i] == leaf(i)))
            s.add(Implies(kind[i] == K_NOT, val[i] == Not(child(i, val, left))))
            for k, op in ((K_AND, And), (K_OR, Or)):
                s.add(Implies(kind[i] == k,
                              val[i] == op(child(i, val, left), child(i, val, right))))
        return val[0]

    # Textual flags, propagated up the tree (C1, C2): they only depend on
    # which atoms appear somewhere in the condition.
    flags = {}
    for name, col in (("gate", COL_GATE), ("anchor", COL_ANCHOR),
                      ("event", COL_EVENT), ("pr", COL_PR)):
        arr = [Bool(f"{name}_{i}") for i in range(MAX_NODES)]
        for i in range(MAX_NODES):
            s.add(Implies(kind[i] == K_NONE, Not(arr[i])))
            s.add(Implies(kind[i] == K_ATOM, arr[i] == atom_flag(i, col)))
            s.add(Implies(kind[i] == K_NOT, arr[i] == child(i, arr, left)))
            s.add(Implies(Or(kind[i] == K_AND, kind[i] == K_OR),
                          arr[i] == Or(child(i, arr, left), child(i, arr, right))))
        flags[name] = arr[0]

    # C2 + C3: textual anchor test on the whole condition
    verified = Or(flags["anchor"], And(flags["event"], Not(flags["pr"])))
    reported = And(flags["gate"], Not(verified))

    # Existential fork choice: "some fork author can pass the gate".
    fork_choice = [Bool(f"fork_choice_{a}") for a in range(NA)]
    fork_satisfies = evaluate("fork", COL_FORK, fork_choice)

    # Universal fork choice, unrolled over the attacker-controlled atoms:
    # "no fork author can pass the gate".
    unforgeable = []
    for bits in itertools.product([False, True], repeat=len(CHOICE_ATOMS)):
        fixed = [BoolVal(False)] * NA
        for a, b in zip(CHOICE_ATOMS, bits):
            fixed[a] = BoolVal(b)
        unforgeable.append(Not(evaluate("u" + "".join("1" if b else "0" for b in bits),
                                        COL_FORK, fixed)))
    unforgeable = And(unforgeable)

    # A maintainer's own run can pass the gate (rules out `x && !x`).
    base_choice = [Bool(f"base_choice_{a}") for a in range(NA)]
    base_satisfiable = evaluate("base", COL_BASE, base_choice)

    def decode(m):
        def go(i):
            k = m.eval(kind[i]).as_long()
            if k == K_ATOM:
                return ATOMS[m.eval(atom[i]).as_long()][0]
            if k == K_NOT:
                return "!(" + go(m.eval(left[i]).as_long()) + ")"
            op = " && " if k == K_AND else " || "
            return "(" + go(m.eval(left[i]).as_long()) + op + go(m.eval(right[i]).as_long()) + ")"
        return go(0)

    def block(m):
        return Not(And([And(kind[i] == m.eval(kind[i]), atom[i] == m.eval(atom[i]),
                            left[i] == m.eval(left[i]), right[i] == m.eval(right[i]))
                        for i in range(MAX_NODES)]))

    views = dict(reported=reported, gate=flags["gate"], fork_satisfies=fork_satisfies,
                 unforgeable=unforgeable, base_satisfiable=base_satisfiable)
    return s, views, decode, block


def enumerate_models(goal, limit, title):
    s, v, decode, block = build()
    s.add(goal(v))
    seen = set()
    print(f"\n== {title} ==")
    n = 0
    while n < limit and s.check() == sat:
        m = s.model()
        text = decode(m)
        if text not in seen:
            seen.add(text)
            n += 1
            print(f"  {n:2d}. if: {text}")
        s.add(block(m))
    if n == 0:
        print("  (none: property holds within the bound)")
    return n


if __name__ == "__main__":
    # Unsound suppression: the detector stays silent, but the condition names
    # a fork-controlled gate context and a fork can make the whole gate true.
    enumerate_models(
        lambda v: And(v["gate"], Not(v["reported"]), v["fork_satisfies"]),
        limit=16,
        title="S2 violated: suppressed by an anchor, yet a fork satisfies the gate")

    # False positives: reported although no fork can make the gate true, while
    # a legitimate run from the base repository can.
    enumerate_models(
        lambda v: And(v["reported"], v["unforgeable"], v["base_satisfiable"]),
        limit=8,
        title="reported although unforgeable (false positive direction)")

    # Sanity: the shapes the unit tests pin must be reachable.
    enumerate_models(
        lambda v: And(v["reported"], v["fork_satisfies"]),
        limit=3,
        title="sanity: true positives (reported and forgeable)")
