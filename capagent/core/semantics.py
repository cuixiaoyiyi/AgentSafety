"""Abstract domain, capability policy, and the capsafe checker.

This module realizes the operational content of Section 3-4 of the paper:

* An abstract state is a set of *facts* (Boolean coordinates of a property-directed
  domain, Section 4.1): payload labels ``PRIV::v`` / ``UNTR::v``, held capabilities
  ``HELD::<key>``, and the derived predicate ``BADCAP``.
* ``Policy.high_impact`` is the parameter ``High : Eff -> {0,1}`` (Section 3.4).
* ``Policy.has_req`` is ``HasReq`` (Definition 5).
* ``BADCAP`` is set exactly by the bad-capability instrumentation of Definition 8.
* Capability safety is a *prefix* property (Definition 6): the checker inspects the
  source state of every high-impact action, not only final states.

The checker computes the reachable set of abstract prefix-states by explicit-state
exploration.  For the Boolean instance this is the same finite-state problem as the
matrix least fixed point (paper Section 5.3); ``core.matrices`` provides the matrix
view and cross-checks agreement.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from . import ir
from .types import (
    Capability, Effect, ContractTable, ToolContract,
    KIND_SEND_EXT, KIND_EXEC, KIND_DELETE, KIND_OVERWRITE, KIND_MODIFY_REPO,
    KIND_MOD_HARNESS, KIND_VERDICT, KIND_INSTR_USE, KIND_DELEGATE, KIND_CRED,
    LABEL_PRIVATE, LABEL_PUBLIC, PROV_TRUSTED, PROV_UNTRUSTED,
)

ONE = "ONE"
BADCAP = "BADCAP"

State = frozenset  # frozenset[str] of true facts


def priv(v: str) -> str:
    return f"PRIV::{v}"


def untr(v: str) -> str:
    return f"UNTR::{v}"


def held(key: str) -> str:
    return f"HELD::{key}"


# ---------------------------------------------------------------------------
# Policy: which effects are high-impact and when a state satisfies the requirement.
# ---------------------------------------------------------------------------
DEFAULT_HIGH_IMPACT = frozenset({
    KIND_DELETE, KIND_OVERWRITE, KIND_EXEC, KIND_MODIFY_REPO, KIND_MOD_HARNESS,
    KIND_VERDICT, KIND_INSTR_USE, KIND_DELEGATE, KIND_CRED, KIND_SEND_EXT,
})


@dataclass
class Policy:
    high_impact_kinds: frozenset = DEFAULT_HIGH_IMPACT
    # capkey -> Capability, the grantable capabilities discovered in the program.
    caps: Dict[str, Capability] = field(default_factory=dict)

    def high_impact(self, eps: Effect) -> bool:
        """High : Eff -> {0,1} (Section 3.4).

        SendExt is high-impact only for private/untrusted payloads; other kinds are
        unconditionally high-impact.
        """
        if eps.kind == KIND_SEND_EXT:
            return eps.label == LABEL_PRIVATE or eps.prov == PROV_UNTRUSTED
        return eps.kind in self.high_impact_kinds

    def has_req(self, state: State, eps: Effect) -> bool:
        """HasReq(sigma, eps): a held capability matches the effect (Definition 5)."""
        for key, cap in self.caps.items():
            if held(key) in state and cap.matches(eps):
                return True
        return False

    def matching_caps(self, eps: Effect) -> List[str]:
        return [k for k, c in self.caps.items() if c.matches(eps)]


# ---------------------------------------------------------------------------
# Action labels (for witnesses / traces).
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ActionLabel:
    op: str
    detail: str = ""
    site: str = ""

    def __str__(self) -> str:
        return self.op + (f"({self.detail})" if self.detail else "")


@dataclass
class Witness:
    """A violating prefix (Section 5.6)."""
    path: Tuple[ActionLabel, ...]
    effect: Effect
    missing_capability: str
    sink_site: str
    evidence: Tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "path": [str(a) for a in self.path],
            "sink": str(self.effect),
            "missing_capability": self.missing_capability,
            "sink_site": self.sink_site,
            "evidence": list(self.evidence),
        }


@dataclass
class CheckResult:
    safe: bool
    witnesses: List[Witness]
    reachable_states: int
    fact_universe: Tuple[str, ...]
    steps: int

    @property
    def unsafe(self) -> bool:
        return not self.safe


# ---------------------------------------------------------------------------
# The checker.
# ---------------------------------------------------------------------------
class Checker:
    """Explicit-state capability-safety checker over lambda_cap / IR."""

    def __init__(self, contracts: ContractTable, policy: Optional[Policy] = None,
                 max_states: int = 200_000, record_edges: bool = False):
        self.contracts = contracts
        self.policy = policy or Policy()
        self.max_states = max_states
        self.witnesses: List[Witness] = []
        self.fact_universe: Set[str] = {ONE, BADCAP}
        self.steps = 0
        self.record_edges = record_edges
        self.edges: Set[Tuple[State, State]] = set()
        self.init_states: Set[State] = set()

    # -- capability discovery (policy completion) --------------------------
    def _register_caps(self, program: ir.Stmt) -> None:
        for s in ir.walk(program):
            if isinstance(s, (ir.Require, ir.Grant, ir.Revoke)):
                self.policy.caps.setdefault(s.cap.key(), s.cap)
                self.fact_universe.add(held(s.cap.key()))

    # -- effect of a tool call given the current state ---------------------
    def _tool_effect(self, tc: ir.ToolCall, state: State) -> Optional[Effect]:
        c = self.contracts.get(tc.tool)
        if c is None or not c.high_impact:
            return None
        resource = c.resource_of(tc.args)
        label = LABEL_PUBLIC
        prov = PROV_TRUSTED
        # Data-label / provenance of the effect come from the payload variable.
        data_var = None
        if c.effect_kind == KIND_SEND_EXT:
            data_var = self._data_var(c, tc)
        elif c.effect_kind in (KIND_EXEC, KIND_INSTR_USE, KIND_DELEGATE):
            data_var = self._data_var(c, tc)
        if data_var is not None:
            if priv(data_var) in state:
                label = LABEL_PRIVATE
            if untr(data_var) in state:
                prov = PROV_UNTRUSTED
        return Effect(kind=c.effect_kind, resource=resource, label=label, prov=prov)

    @staticmethod
    def _data_var(c: ToolContract, tc: ir.ToolCall) -> Optional[str]:
        idx = c.external_dest_arg  # reuse: for send/exec the *data* arg index
        # by convention the data payload is the last argument
        if tc.args:
            return str(tc.args[-1])
        return None

    # -- one primitive transition -----------------------------------------
    def _step_primitive(self, stmt: ir.Stmt, state: State, trace: Tuple[ActionLabel, ...]):
        """Return (new_state, label) for a primitive; may append a witness."""
        s = set(state)
        s.add(ONE)

        if isinstance(stmt, ir.Skip) or isinstance(stmt, ir.Assume):
            return frozenset(s), None

        if isinstance(stmt, ir.Require) or isinstance(stmt, ir.Grant):
            s.add(held(stmt.cap.key()))
            self.policy.caps.setdefault(stmt.cap.key(), stmt.cap)
            lab = ActionLabel("grant", stmt.cap.kind, stmt.site)
            return frozenset(s), lab

        if isinstance(stmt, ir.Revoke):
            s.discard(held(stmt.cap.key()))
            return frozenset(s), ActionLabel("revoke", stmt.cap.kind, stmt.site)

        if isinstance(stmt, ir.Declassify):
            s.discard(priv(stmt.var))
            if stmt.src and stmt.src != stmt.var:
                s.discard(priv(stmt.var))
            return frozenset(s), ActionLabel("declassify", stmt.var, stmt.site)

        if isinstance(stmt, ir.MemRead):
            if stmt.untrusted:
                s.add(untr(stmt.var))
                self.fact_universe.add(untr(stmt.var))
            return frozenset(s), ActionLabel("memread", stmt.key, stmt.site)

        if isinstance(stmt, ir.MemWrite):
            return frozenset(s), ActionLabel("memwrite", stmt.key, stmt.site)

        if isinstance(stmt, ir.Check):
            if not self.policy.has_req(frozenset(s), stmt.effect):
                s.add(BADCAP)
            return frozenset(s), ActionLabel("check", str(stmt.effect), stmt.site)

        if isinstance(stmt, ir.ToolCall):
            return self._step_toolcall(stmt, frozenset(s), trace)

        # Unknown primitive: no-op.
        return frozenset(s), None

    def _step_toolcall(self, tc: ir.ToolCall, state: State, trace):
        s = set(state)
        c = self.contracts.get(tc.tool)
        label = ActionLabel("call", tc.tool, tc.site)

        # 1) high-impact effect check (the sink) -- prefix property.
        eps = self._tool_effect(tc, state)
        if eps is not None and self.policy.high_impact(eps):
            if not self.policy.has_req(state, eps):
                if BADCAP not in s:
                    missing = self._missing_cap_str(eps)
                    ev = c.evidence if c else ()
                    self.witnesses.append(Witness(
                        path=trace + (label,), effect=eps,
                        missing_capability=missing, sink_site=tc.site, evidence=tuple(ev),
                    ))
                s.add(BADCAP)

        # 2) label / provenance propagation onto the result variable.
        if c is not None and tc.result:
            self._propagate(c, tc, s)
        return frozenset(s), label

    def _propagate(self, c: ToolContract, tc: ir.ToolCall, s: set) -> None:
        mode = c.propagate.mode
        rv = tc.result
        if mode == "fresh_private":
            s.add(priv(rv)); self.fact_universe.add(priv(rv))
        elif mode == "fresh_untrusted":
            s.add(untr(rv)); self.fact_universe.add(untr(rv))
        elif mode == "keep":
            src = tc.args[c.propagate.from_arg] if c.propagate.from_arg < len(tc.args) else None
            if src is not None:
                if priv(str(src)) in s:
                    s.add(priv(rv)); self.fact_universe.add(priv(rv))
                if untr(str(src)) in s:
                    s.add(untr(rv)); self.fact_universe.add(untr(rv))
        elif mode == "declassify":
            pass  # result is public: add nothing
        # "public": nothing.

    def _missing_cap_str(self, eps: Effect) -> str:
        if eps.kind == KIND_SEND_EXT:
            return f"Cap(SendExt, dst={eps.resource}, label={eps.label})"
        if eps.kind == KIND_EXEC:
            return f"Cap(Exec, provenance={eps.prov}, sandbox=on)"
        if eps.kind == KIND_MOD_HARNESS:
            return f"Cap(ModHarness, {eps.resource})"
        return f"Cap({eps.kind}, {eps.resource})"

    # -- structural exploration -------------------------------------------
    def _explore(self, stmt: ir.Stmt, configs):
        """configs: list of (state, trace). Returns list of (state, trace)."""
        if isinstance(stmt, ir.Seq):
            mid = self._explore(stmt.first, configs)
            return self._explore(stmt.second, mid)

        if isinstance(stmt, ir.Choice):
            return self._explore(stmt.left, configs) + self._explore(stmt.right, configs)

        if isinstance(stmt, ir.Think):
            out = []
            for ch in stmt.choices:
                out += self._explore(ch, configs)
            return out if out else list(configs)

        if isinstance(stmt, ir.If):
            return self._explore(stmt.then, configs) + self._explore(stmt.otherwise, configs)

        if isinstance(stmt, ir.While):
            # least fixed point over the set of reachable states (Kleene closure).
            seen = set()
            out = list(configs)
            frontier = list(configs)
            while frontier:
                nxt = []
                for cfg in self._explore(stmt.body, frontier):
                    key = cfg[0]
                    if key not in seen:
                        seen.add(key)
                        nxt.append(cfg)
                        out.append(cfg)
                frontier = nxt
                if len(seen) > self.max_states:
                    break
            return out

        # primitive
        out = []
        for state, trace in configs:
            self.steps += 1
            new_state, lab = self._step_primitive(stmt, state, trace)
            self.fact_universe.update(new_state)
            if self.record_edges:
                self.edges.add((state, new_state))
            new_trace = trace + (lab,) if lab is not None else trace
            out.append((new_state, new_trace))
        return out

    def check(self, program: ir.Stmt, init_state: Optional[State] = None) -> CheckResult:
        self.witnesses = []
        self.steps = 0
        self._register_caps(program)
        init = init_state if init_state is not None else frozenset({ONE})
        self.init_states = {init}
        configs = [(init, tuple())]
        ends = self._explore(program, configs)
        reachable = {c[0] for c in ends}
        safe = len(self.witnesses) == 0
        return CheckResult(
            safe=safe,
            witnesses=list(self.witnesses),
            reachable_states=len(reachable),
            fact_universe=tuple(sorted(self.fact_universe)),
            steps=self.steps,
        )
