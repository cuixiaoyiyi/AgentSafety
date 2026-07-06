"""Diagnostic baselines (paper Section 5.1 / 6.3).

These are deliberately *simpler* defenses, each with a known blind spot, used to
show that capability-safe tool use needs a property-specific abstraction over
effects, capabilities, resources, and provenance.  Each baseline returns a verdict
(safe/unsafe) and the warnings it raised; ``report-generator`` compares them to
CapAgent's ground truth.

  * sink_only        -- flag any high-impact API.  (over-reports; no authorization notion)
  * allowlist        -- reject any tool not on a name allowlist. (ignores resource/provenance)
  * guard_dominator  -- accept a sink if *some* guard precedes it. (misses scope/kind/prov mismatch)
  * taint_to_sink    -- flag untrusted/private data reaching a sink. (misses pure-authorization bugs;
                        flags authorized sends)
  * generic_reach    -- kind-only reachability: reject a sink lacking a same-kind grant anywhere.
                        (no region/label/provenance; flags benign public sends)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from ..core import ir
from ..core.types import ContractTable
from ..core.semantics import (
    priv, untr, KIND_SEND_EXT, KIND_EXEC, KIND_INSTR_USE, KIND_DELEGATE,
)

SAFE_TOOL_ALLOWLIST = {"read_file", "read_public", "summarize", "redact",
                       "validate_provenance", "memread", "memwrite"}


@dataclass
class BaselineOutcome:
    safe: bool
    warnings: List[str] = field(default_factory=list)


def _sinks_and_grants(program: ir.Stmt, contracts: ContractTable):
    """Statically collect high-impact sinks (tool, kind) and granted kinds."""
    sinks: List[Tuple[str, str]] = []
    grant_kinds: Set[str] = set()
    tools_called: Set[str] = set()
    for s in ir.walk(program):
        if isinstance(s, ir.ToolCall):
            tools_called.add(s.tool)
            c = contracts.get(s.tool)
            if c is not None and c.high_impact:
                sinks.append((s.tool, c.effect_kind))
        elif isinstance(s, (ir.Require, ir.Grant)):
            grant_kinds.add(s.cap.kind)
    return sinks, grant_kinds, tools_called


# -- taint pass: does untrusted/private data reach a sink? -----------------
def _taint_reaches_sink(program: ir.Stmt, contracts: ContractTable) -> bool:
    hit = {"v": False}

    def run(stmt, tainted: Set[str]) -> List[Set[str]]:
        if isinstance(stmt, ir.Seq):
            outs = []
            for t in run(stmt.first, tainted):
                outs += run(stmt.second, t)
            return outs
        if isinstance(stmt, (ir.Choice, ir.If)):
            a = stmt.left if isinstance(stmt, ir.Choice) else stmt.then
            b = stmt.right if isinstance(stmt, ir.Choice) else stmt.otherwise
            return run(a, set(tainted)) + run(b, set(tainted))
        if isinstance(stmt, ir.While):
            return run(stmt.body, set(tainted)) + [tainted]
        if isinstance(stmt, ir.Think):
            outs = []
            for ch in stmt.choices:
                outs += run(ch, set(tainted))
            return outs or [tainted]
        t = set(tainted)
        if isinstance(stmt, ir.MemRead):
            if stmt.untrusted:
                t.add(stmt.var)
        elif isinstance(stmt, ir.ToolCall):
            c = contracts.get(stmt.tool)
            if c is not None and c.high_impact and stmt.args:
                data_var = str(stmt.args[-1])
                if data_var in t:
                    hit["v"] = True
            # propagation
            if c is not None and stmt.result:
                mode = c.propagate.mode
                if mode == "fresh_private":
                    t.add(stmt.result)
                elif mode == "keep":
                    src = stmt.args[c.propagate.from_arg] if c.propagate.from_arg < len(stmt.args) else None
                    if src is not None and str(src) in t:
                        t.add(stmt.result)
                elif mode in ("declassify", "public"):
                    t.discard(stmt.result)
        elif isinstance(stmt, ir.Declassify):
            t.discard(stmt.var)
        return [t]

    run(program, set())
    return hit["v"]


def sink_only(program, contracts) -> BaselineOutcome:
    sinks, _, _ = _sinks_and_grants(program, contracts)
    if sinks:
        return BaselineOutcome(False, [f"high-impact API used: {t} ({k})" for t, k in sinks])
    return BaselineOutcome(True, [])


def allowlist(program, contracts) -> BaselineOutcome:
    _, _, tools = _sinks_and_grants(program, contracts)
    bad = [t for t in sorted(tools) if t not in SAFE_TOOL_ALLOWLIST]
    if bad:
        return BaselineOutcome(False, [f"tool not on allowlist: {t}" for t in bad])
    return BaselineOutcome(True, [])


def guard_dominator(program, contracts) -> BaselineOutcome:
    sinks, grants, _ = _sinks_and_grants(program, contracts)
    if sinks and not grants:
        return BaselineOutcome(False, ["high-impact sink with no dominating guard"])
    return BaselineOutcome(True, [])


def generic_reach(program, contracts) -> BaselineOutcome:
    sinks, grants, _ = _sinks_and_grants(program, contracts)
    unmatched = [(t, k) for (t, k) in sinks if k not in grants]
    if unmatched:
        return BaselineOutcome(False, [f"sink {t} ({k}) has no same-kind grant" for t, k in unmatched])
    return BaselineOutcome(True, [])


def taint_to_sink(program, contracts) -> BaselineOutcome:
    if _taint_reaches_sink(program, contracts):
        return BaselineOutcome(False, ["untrusted/private data reaches a high-impact sink"])
    return BaselineOutcome(True, [])


BASELINES = {
    "sink_only": sink_only,
    "allowlist": allowlist,
    "guard_dominator": guard_dominator,
    "generic_reach": generic_reach,
    "taint_to_sink": taint_to_sink,
}


def run_all(program: ir.Stmt, contracts: ContractTable) -> Dict[str, BaselineOutcome]:
    return {name: fn(program, contracts) for name, fn in BASELINES.items()}
