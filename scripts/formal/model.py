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
    #: `spec.ACTIONS` key when the property is about an action, else "".
    action: str = ""


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
        self.Action, self.actions = z3.EnumSort("Action", spec.ACTIONS)
        self.t_of = dict(zip(spec.TRIGGERS, self.triggers, strict=True))
        self.c_of = {c.path: v for c, v in zip(spec.CONTEXTS, self.ctxs, strict=True)}
        self.s_of = dict(zip(spec.SINKS, self.sinks, strict=True))
        self.f_of = dict(zip(spec.FLOWS, self.flows, strict=True))
        self.a_of = dict(zip(spec.ACTIONS, self.actions, strict=True))
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
        self.ref_shaped = self._define_unary(
            "ref_shaped", self.c_of, lambda c: ctx_by_path[c].ref_shaped
        )
        self.free_text = self._define_unary(
            "free_text", self.c_of, lambda c: ctx_by_path[c].free_text
        )
        self.fetch_only = self._define_unary(
            "fetch_only", self.c_of, lambda c: ctx_by_path[c].fetch_only
        )
        self.privileged = self._define_unary(
            "privileged", self.t_of, lambda t: t in spec.PRIVILEGED
        )
        self.externally_triggerable = self._define_unary(
            "externally_triggerable", self.t_of, lambda t: t in spec.EXTERNALLY_TRIGGERABLE
        )
        self.carries_fork_code = self._define_unary(
            "carries_fork_code", self.t_of, lambda t: t in spec.CARRIES_FORK_CODE
        )

        code_inputs = {ci.key for ci in spec.CODE_EXECUTING_INPUTS}
        outputs = {ao.key: ao for ao in spec.ACTION_OUTPUTS}
        self.code_input = self._define_unary("code_input", self.a_of, lambda a: a in code_inputs)
        self.untrusted_output = self._define_unary(
            "untrusted_output", self.a_of, lambda a: a in outputs
        )
        # Where an action output comes from: the (trigger, payload field) the
        # specification names for it. Total functions, so the actions that
        # are not outputs map to arbitrary values the properties never read.
        self.ao_trigger = z3.Function("ao_trigger", self.Action, self.Trigger)
        self.ao_source = z3.Function("ao_source", self.Action, self.Ctx)
        for key, ao in outputs.items():
            self.solver.add(self.ao_trigger(self.a_of[key]) == self.t_of[ao.trigger])
            self.solver.add(self.ao_source(self.a_of[key]) == self.c_of[ao.source])

    def _define_impl(self) -> None:
        im = self.im

        def run_taint(t: str, c: str) -> bool:
            # `runTaintContexts`: the fixed table, plus the dispatch payload
            # the declared trigger actually fills, plus bare `inputs` when a
            # dispatch / call can populate it. SEC002 and SEC008 share this
            # (#312).
            if impl.matches_any_prefix(c, im.run_dangerous):
                return True
            if impl.matches_any_prefix(c, im.dispatch_payload.get(t, [])):
                return True
            return t in DISPATCH_TRIGGERS and impl.matches_any_prefix(c, im.bare_inputs)

        def sec006(t: str, c: str) -> bool:
            return impl.matches_any_prefix(c, im.condition_dangerous)

        def sec022(t: str, c: str) -> bool:
            return t == "workflow_run" and impl.matches_any_prefix(c, im.workflow_run_gate)

        def sec005(t: str, c: str) -> bool:
            return t in im.privileged_pr_head and impl.matches_marker(
                spec.checkout_with(c), im.pr_head_markers
            )

        def sec009(t: str, c: str) -> bool:
            return t == "workflow_run" and impl.matches_marker(
                spec.checkout_with(c), im.workflow_run_markers
            )

        def sec021(t: str, c: str) -> bool:
            owned = im.trigger_contexts.get(t, [])
            if t == "workflow_dispatch":
                owned = owned + im.bare_inputs
            return impl.matches_any_prefix(c, owned)

        self.sec002 = self._define_tc("sec002", run_taint)
        self.sec008 = self._define_tc("sec008", run_taint)
        self.sec006 = self._define_tc("sec006", sec006)
        self.sec022 = self._define_tc("sec022", sec022)
        self.sec005 = self._define_tc("sec005", sec005)
        self.sec009 = self._define_tc("sec009", sec009)
        self.sec021 = self._define_tc("sec021", sec021)
        self.sec020 = self._define_unary(
            "sec020", self.t_of, lambda t: t in im.fork_accessible_triggers
        )
        self.followed = self._define_unary("followed", self.f_of, lambda f: f in im.followed_flows)

        # Probes for rules the specification asks for that have no table yet
        # (`impl._probe_string_table`): false everywhere until the rule lands.
        self.shell_fetch = self._define_tc(
            "shell_fetch", lambda t, c: impl.matches_any_prefix(c, im.shell_fetch_contexts)
        )
        self.artifact_run_id = self._define_tc(
            "artifact_run_id", lambda t, c: impl.matches_any_prefix(c, im.artifact_run_id_contexts)
        )

        def code_input_known(a: str) -> bool:
            if a == spec.NO_ACTION:
                return False
            action, _, input_name = a.partition("#")
            # `getWithInput` compares the key with `eqlIgnoreCase`.
            return any(
                impl.matches_action(action, [known])
                and input_name.lower() in {i.lower() for i in inputs}
                for known, inputs in im.code_executing_inputs.items()
            )

        self.code_input_known = self._define_unary("code_input_known", self.a_of, code_input_known)
        self.output_known = self._define_unary(
            "output_known",
            self.a_of,
            lambda a: impl.matches_action(a.partition("#")[0], im.untrusted_output_actions),
        )

    def properties(self) -> list[tuple[str, str, z3.BoolRef, z3.BoolRef, str]]:
        """(name, expected rule, Unsafe, Covered, note) over free variables t, c, f."""
        t, c, f, a = self.t, self.c, self.f, self.a
        S = self.s_of
        direct = f == self.f_of["direct"]
        # Properties that are not about an action pin it to the placeholder
        # so the enumeration does not repeat each tuple per action.
        no_action = a == self.a_of[spec.NO_ACTION]
        # A number or a SHA is server-formatted and carries no shell
        # metacharacters; only text a human types is an injection vector.
        injectable = z3.And(z3.Or(self.external(c), self.dispatcher(c)), self.free_text(c))
        # Code the attacker picked, fetched by a job that holds secrets.
        picks_code = z3.And(
            self.available(t, c),
            self.privileged(t),
            z3.Or(self.external(c), self.dispatcher(c)),
            self.ref_shaped(c),
        )

        return [
            (
                "P1 script injection",
                "SEC002",
                z3.And(self.available(t, c), injectable, direct, self.sink == S["run"], no_action),
                self.sec002(t, c),
                "attacker-authored value interpolated into run:",
            ),
            (
                "P2 GITHUB_ENV injection",
                "SEC008",
                z3.And(
                    self.available(t, c),
                    injectable,
                    direct,
                    self.sink == S["github_env"],
                    no_action,
                ),
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
                    no_action,
                ),
                z3.Or(self.sec006(t, c), self.sec022(t, c)),
                "free text an attacker writes decides an if: gate",
            ),
            (
                "P4 untrusted checkout",
                "SEC005/SEC009/SEC021",
                # `fetch_only` handles have no `with:` spelling under
                # `actions/checkout`; P9 covers them.
                z3.And(
                    picks_code,
                    z3.Not(self.fetch_only(c)),
                    direct,
                    self.sink == S["checkout_ref"],
                    no_action,
                ),
                z3.Or(self.sec005(t, c), self.sec009(t, c), self.sec021(t, c)),
                "privileged job checks out code the attacker picked",
            ),
            (
                "P5 SEC021 ⊆ SEC002",
                "SEC002",
                # A checkout-ref context that is also free text is injection
                # inside run:. A number or SHA is not (P1); SEC021 may still
                # own those for checkout without SEC002 treating them as taint.
                z3.And(
                    self.sec021(t, c), self.free_text(c), direct, self.sink == S["run"], no_action
                ),
                self.sec002(t, c),
                "cross-rule consistency: SEC021 owns the context but SEC002 does not",
            ),
            (
                "P6 SEC022 ⊆ SEC002",
                "SEC002",
                z3.And(self.sec022(t, c), direct, self.sink == S["run"], no_action),
                self.sec002(t, c),
                "cross-rule consistency: SEC022 owns the context but SEC002 does not",
            ),
            # P7 and P8 are about a trigger alone / a flow alone. The other
            # variables are pinned to one representative so each gap is
            # reported once rather than once per unrelated tuple.
            (
                "P7 self-hosted fork reach",
                "SEC020",
                z3.And(
                    self.carries_fork_code(t),
                    self.externally_triggerable(t),
                    self.sink == S["run"],
                    direct,
                    c == self.c_of["github.event.pull_request.head.sha"],
                    no_action,
                ),
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
                    no_action,
                ),
                self.followed(f),
                "an indirection SEC002 does not follow between a known source and run:",
            ),
            # P9–P12 are the known vulnerability classes the checkout /
            # injection rules do not reach through `actions/checkout` and
            # `run:` alone (see docs/design/formal-rule-model.md §7).
            (
                "P9 shell fetch",
                "SEC005/SEC009/SEC021",
                # The same shape as P4 with `git` / `gh` doing the fetch. A
                # free-text handle also trips SEC002 there, but SEC002's fix
                # (bind it to env:) leaves the attacker's code checked out.
                z3.And(picks_code, direct, self.sink == S["run_fetch"], no_action),
                self.shell_fetch(t, c),
                "privileged job fetches code the attacker picked with git / gh inside run:",
            ),
            (
                "P10 artifact poisoning",
                "SEC009",
                # c is pinned: the run id is the only handle an artifact
                # download takes, and only `workflow_run` carries it.
                z3.And(
                    self.available(t, c),
                    self.privileged(t),
                    self.external(c),
                    c == self.c_of["github.event.workflow_run.id"],
                    direct,
                    self.sink == S["artifact_run_id"],
                    no_action,
                ),
                self.artifact_run_id(t, c),
                "the upstream (fork) run's artifact is downloaded by run id and used",
            ),
            (
                "P11 code-executing input",
                "SEC002",
                # Pinned to one known-tainted (trigger, context) pair; what
                # varies is the action whose input runs as code. `sec002`
                # keeps a witness from meaning "the context left the table".
                z3.And(
                    t == self.t_of["issues"],
                    c == self.c_of["github.event.issue.title"],
                    self.sec002(t, c),
                    self.sink == S["action_script"],
                    direct,
                    self.code_input(a),
                ),
                self.code_input_known(a),
                "an action input executed as code that SEC002 does not scan",
            ),
            (
                "P12 untrusted action output",
                "SEC002",
                z3.And(
                    self.untrusted_output(a),
                    t == self.ao_trigger(a),
                    c == self.ao_source(a),
                    self.sink == S["run"],
                    f == self.f_of["action_output"],
                ),
                self.output_known(a),
                "an action output derived from attacker content, interpolated into run:",
            ),
        ]

    def check(self) -> list[Witness]:
        self.t = z3.Const("t", self.Trigger)
        self.c = z3.Const("c", self.Ctx)
        self.f = z3.Const("f", self.Flow)
        self.a = z3.Const("a", self.Action)
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
            t, c, f, s, a = (
                m.eval(v, model_completion=True)
                for v in (self.t, self.c, self.f, self.sink, self.a)
            )
            action = "" if str(a) == spec.NO_ACTION else str(a)
            out.append(Witness(name, str(t), str(c), str(s), str(f), rule, note, action))
            self.solver.add(
                z3.Not(z3.And(self.t == t, self.c == c, self.f == f, self.sink == s, self.a == a))
            )
        # The loop only ends on unsat or unknown; unknown would mean the
        # enumeration is incomplete, which must not pass as "no more gaps".
        assert self.solver.check() == z3.unsat, f"{name}: solver returned unknown"
        self.solver.pop()
        return out


def _sort_key(w: Witness) -> tuple:
    # P10 sorts after P9, not after P1.
    number = int(w.property.split(" ")[0][1:])
    return (number, w.trigger, w.context, w.flow, w.action)


def describe(w: Witness) -> str:
    """`trigger  context [via flow] [action]`, the line both scripts print."""
    flow = "" if w.flow == "direct" else f"  via {w.flow}"
    action = f"  {w.action}" if w.action else ""
    return f"{w.trigger:28} {w.context}{flow}{action}"


def main() -> int:
    witnesses = sorted(Model(impl.load()).check(), key=_sort_key)
    current = None
    for w in witnesses:
        if w.property != current:
            current = w.property
            print(f"\n== {w.property}  (expected {w.expected_rule}: {w.note})")
        print(f"  {describe(w)}")
    print(f"\n{len(witnesses)} witnesses")
    return 0


if __name__ == "__main__":
    sys.exit(main())
