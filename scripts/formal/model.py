#!/usr/bin/env python3
"""Bounded model check of zghalint's injection / checkout rules against the
GitHub Actions trust model.

``spec.py`` says which contexts an attacker authors under which trigger and
where such a value does damage; ``impl.py`` reads the tables the rules in
``src/rules/security.zig`` actually consult. Both are encoded as relations
over finite sorts and handed to Z3, which is asked for witnesses of

    Unsafe(trigger, context, sink, flow)  ∧  ¬Covered(trigger, context, sink, flow)

for each property below. Every witness is a candidate false negative — a
workflow the specification calls dangerous that no rule reports.
``confirm.py`` turns each one into a minimal workflow and runs the real
binary, so nothing is filed on the strength of the model alone.

Usage:
    python3 scripts/formal/model.py

A completed run exits 0 whatever it found: the model is a *finder*, not a CI
gate — the gaps it reports are tracked as issues (see
docs/design/formal-rule-model.md). A table the extractor cannot find or a
solver that does not finish is an error, not a clean run.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

import z3

import impl
import spec

DISPATCH_TRIGGERS = {"workflow_dispatch", "workflow_call"}


@dataclass(frozen=True)
class Witness:
    property: str
    trigger: str
    context: str
    sink: str
    flow: str
    expected_rule: str
    note: str = ""


class Model:
    """The finite relational model. Predicates are total functions defined
    extensionally (one assertion per tuple), so every query is decidable and
    Z3 returns every witness when asked to enumerate."""

    def __init__(self, im: impl.Impl) -> None:
        self.im = im
        self.Trigger, self.triggers = z3.EnumSort("Trigger", spec.TRIGGERS)
        self.Ctx, self.ctxs = z3.EnumSort("Ctx", [c.path for c in spec.CONTEXTS])
        self.Sink, self.sinks = z3.EnumSort("Sink", spec.SINKS)
        self.Flow, self.flows = z3.EnumSort("Flow", spec.FLOWS)
        self.t_of = dict(zip(spec.TRIGGERS, self.triggers))
        self.c_of = {c.path: v for c, v in zip(spec.CONTEXTS, self.ctxs)}
        self.s_of = dict(zip(spec.SINKS, self.sinks))
        self.f_of = dict(zip(spec.FLOWS, self.flows))
        self.solver = z3.Solver()
        self._define_spec()
        self._define_impl()

    def _define_unary(self, name: str, values: dict, truth) -> z3.FuncDeclRef:
        fn = z3.Function(name, next(iter(values.values())).sort(), z3.BoolSort())
        for key, sym in values.items():
            self.solver.add(fn(sym) == bool(truth(key)))
        return fn

    def _define_tc(self, name: str, truth) -> z3.FuncDeclRef:
        fn = z3.Function(name, self.Trigger, self.Ctx, z3.BoolSort())
        for t, ts in self.t_of.items():
            for c, cs in self.c_of.items():
                self.solver.add(fn(ts, cs) == bool(truth(t, c)))
        return fn

    def _define_spec(self) -> None:
        ctx_by_path = {c.path: c for c in spec.CONTEXTS}
        avail = {t: {c.path for c in cs} for t, cs in spec.AVAILABLE.items()}

        self.available = self._define_tc("available", lambda t, c: c in avail[t])
        self.external = self._define_unary(
            "external", self.c_of, lambda c: ctx_by_path[c].author == spec.Author.EXTERNAL
        )
        self.dispatcher = self._define_unary(
            "dispatcher", self.c_of, lambda c: ctx_by_path[c].author == spec.Author.DISPATCHER
        )
        self.ref_shaped = self._define_unary("ref_shaped", self.c_of, lambda c: ctx_by_path[c].ref_shaped)
        self.free_text = self._define_unary("free_text", self.c_of, lambda c: ctx_by_path[c].free_text)
        self.privileged = self._define_unary("privileged", self.t_of, lambda t: t in spec.PRIVILEGED)
        self.externally_triggerable = self._define_unary(
            "externally_triggerable", self.t_of, lambda t: t in spec.EXTERNALLY_TRIGGERABLE
        )
        self.carries_fork_code = self._define_unary(
            "carries_fork_code", self.t_of, lambda t: t in spec.CARRIES_FORK_CODE
        )

    def _define_impl(self) -> None:
        im = self.im

        def sec002(t: str, c: str) -> bool:
            if impl.matches_any_prefix(c, im.run_dangerous):
                return True
            return t in DISPATCH_TRIGGERS and impl.matches_any_prefix(c, im.dispatched_inputs)

        def sec008(t: str, c: str) -> bool:
            return impl.matches_any_prefix(c, im.run_dangerous)

        def sec006(t: str, c: str) -> bool:
            return impl.matches_any_prefix(c, im.condition_dangerous)

        def sec022(t: str, c: str) -> bool:
            return t == "workflow_run" and impl.matches_any_prefix(c, im.workflow_run_gate)

        def sec005(t: str, c: str) -> bool:
            return t == "pull_request_target" and impl.matches_marker(spec.checkout_with(c), im.pr_head_markers)

        def sec009(t: str, c: str) -> bool:
            return t == "workflow_run" and impl.matches_marker(spec.checkout_with(c), im.workflow_run_markers)

        def sec021(t: str, c: str) -> bool:
            owned = im.trigger_contexts.get(t, [])
            if t == "workflow_dispatch":
                owned = owned + ["inputs"]
            return impl.matches_any_prefix(c, owned)

        self.sec002 = self._define_tc("sec002", sec002)
        self.sec008 = self._define_tc("sec008", sec008)
        self.sec006 = self._define_tc("sec006", sec006)
        self.sec022 = self._define_tc("sec022", sec022)
        self.sec005 = self._define_tc("sec005", sec005)
        self.sec009 = self._define_tc("sec009", sec009)
        self.sec021 = self._define_tc("sec021", sec021)
        self.sec020 = self._define_unary("sec020", self.t_of, lambda t: t in im.fork_accessible_triggers)
        self.followed = self._define_unary("followed", self.f_of, lambda f: f in im.followed_flows)

    def properties(self) -> list[tuple[str, str, z3.BoolRef, z3.BoolRef, str]]:
        """(name, expected rule, Unsafe, Covered, note) over free variables t, c, f."""
        t, c, f = self.t, self.c, self.f
        S = self.s_of
        direct = f == self.f_of["direct"]
        # A number or a SHA is server-formatted and carries no shell
        # metacharacters; only text a human types is an injection vector.
        injectable = z3.And(z3.Or(self.external(c), self.dispatcher(c)), self.free_text(c))

        return [
            (
                "P1 script injection",
                "SEC002",
                z3.And(self.available(t, c), injectable, direct, self.sink == S["run"]),
                self.sec002(t, c),
                "attacker-authored value interpolated into run:",
            ),
            (
                "P2 GITHUB_ENV injection",
                "SEC008",
                z3.And(self.available(t, c), injectable, direct, self.sink == S["github_env"]),
                self.sec008(t, c),
                "attacker-authored value written to $GITHUB_ENV / $GITHUB_PATH",
            ),
            (
                "P3 condition gate",
                "SEC006",
                # Ref-shaped and label contexts are excluded on purpose (#138).
                z3.And(
                    self.available(t, c),
                    self.external(c),
                    self.free_text(c),
                    z3.Not(self.ref_shaped(c)),
                    direct,
                    self.sink == S["condition"],
                ),
                z3.Or(self.sec006(t, c), self.sec022(t, c)),
                "free text an attacker writes decides an if: gate",
            ),
            (
                "P4 untrusted checkout",
                "SEC005/SEC009/SEC021",
                z3.And(
                    self.available(t, c),
                    self.privileged(t),
                    z3.Or(self.external(c), self.dispatcher(c)),
                    self.ref_shaped(c),
                    direct,
                    self.sink == S["checkout_ref"],
                ),
                z3.Or(self.sec005(t, c), self.sec009(t, c), self.sec021(t, c)),
                "privileged job checks out code the attacker picked",
            ),
            (
                "P5 SEC021 ⊆ SEC002",
                "SEC002",
                # Whatever chooses a checkout ref is a string the attacker wrote,
                # so it is at least as dangerous inside run:.
                z3.And(self.sec021(t, c), direct, self.sink == S["run"]),
                self.sec002(t, c),
                "cross-rule consistency: SEC021 owns the context but SEC002 does not",
            ),
            (
                "P6 SEC022 ⊆ SEC002",
                "SEC002",
                z3.And(self.sec022(t, c), direct, self.sink == S["run"]),
                self.sec002(t, c),
                "cross-rule consistency: SEC022 owns the context but SEC002 does not",
            ),
            # P7 and P8 are about a trigger alone / a flow alone. The other
            # variables are pinned to one representative so each gap is
            # reported once rather than once per unrelated tuple.
            (
                "P7 self-hosted fork reach",
                "SEC020",
                z3.And(self.carries_fork_code(t), self.externally_triggerable(t), self.sink == S["run"], direct, c == self.c_of["github.event.pull_request.head.sha"]),
                self.sec020(t),
                "trigger reaches a self-hosted runner with a fork's code but SEC020 ignores it",
            ),
            (
                "P8 taint flow",
                "SEC002",
                z3.And(
                    t == self.t_of["issue_comment"],
                    c == self.c_of["github.event.comment.body"],
                    self.sink == S["run"],
                    self.sec002(t, c),
                ),
                self.followed(f),
                "an indirection SEC002 does not follow between a known source and run:",
            ),
        ]

    def check(self) -> list[Witness]:
        self.t = z3.Const("t", self.Trigger)
        self.c = z3.Const("c", self.Ctx)
        self.f = z3.Const("f", self.Flow)
        self.sink = z3.Const("sink", self.Sink)
        witnesses: list[Witness] = []
        for name, rule, unsafe, covered, note in self.properties():
            witnesses.extend(self._enumerate(name, rule, z3.And(unsafe, z3.Not(covered)), note))
        return witnesses

    def _enumerate(self, name: str, rule: str, query: z3.BoolRef, note: str) -> list[Witness]:
        out: list[Witness] = []
        self.solver.push()
        self.solver.add(query)
        while self.solver.check() == z3.sat:
            m = self.solver.model()
            t, c, f, s = (m.eval(v, model_completion=True) for v in (self.t, self.c, self.f, self.sink))
            out.append(Witness(name, str(t), str(c), str(s), str(f), rule, note))
            self.solver.add(z3.Not(z3.And(self.t == t, self.c == c, self.f == f, self.sink == s)))
        # The loop only ends on unsat or unknown; unknown would mean the
        # enumeration is incomplete, which must not pass as "no more gaps".
        assert self.solver.check() == z3.unsat, f"{name}: solver returned unknown"
        self.solver.pop()
        return out


def _sort_key(w: Witness) -> tuple:
    return (w.property, w.trigger, w.context, w.flow)


def main() -> int:
    witnesses = sorted(Model(impl.load()).check(), key=_sort_key)
    current = None
    for w in witnesses:
        if w.property != current:
            current = w.property
            print(f"\n== {w.property}  (expected {w.expected_rule}: {w.note})")
        flow = "" if w.flow == "direct" else f"  via {w.flow}"
        print(f"  {w.trigger:28} {w.context}{flow}")
    print(f"\n{len(witnesses)} witnesses")
    return 0


if __name__ == "__main__":
    sys.exit(main())
