"""Unified evaluation dataset: policy kernels + extracted scaffold plans.

Assembles the four object classes of the evaluation protocol (paper Section 6.1):
policy kernels, agent scaffolds, security witnesses (buggy paths), repaired versions,
and negative controls.  Kernels use curated contracts; scaffold cases use contracts
recovered by the extractor, so the same checker runs on both hand-written IR and
extracted IR.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .core import ir
from .core.types import ContractTable
from .core.acg import ACG
from . import kernels as K
from .library import standard_contracts
from .tools import contract_extractor as CE
from .tools import guard_extractor as GE
from .tools import acg_builder as AB
from .tools import translator as TR


@dataclass
class Case:
    id: str
    subject: str                 # kernel | scaffold
    mode: str
    effect_kind: str
    family: str                  # overview | kernel | control | scaffold
    variant: str                 # buggy | fixed | control
    expected_safe: bool
    program: ir.Stmt
    contracts: ContractTable
    repair_pattern: str = ""
    pair_id: str = ""
    description: str = ""
    acg: Optional[ACG] = None
    extraction: dict = field(default_factory=dict)


def _first_sink_kind(program: ir.Stmt, contracts: ContractTable) -> str:
    for s in ir.walk(program):
        if isinstance(s, ir.ToolCall):
            c = contracts.get(s.tool)
            if c is not None and c.high_impact:
                return c.effect_kind
    return "-"


def kernel_cases() -> List[Case]:
    ct = standard_contracts()
    out = []
    for k in K.build_kernels():
        out.append(Case(
            id=k.id, subject="kernel", mode=k.mode, effect_kind=k.effect_kind,
            family=k.family, variant=k.variant, expected_safe=k.expected_safe,
            program=k.program, contracts=ct, repair_pattern=k.repair_pattern,
            pair_id=k.pair_id, description=k.description,
        ))
    return out


SCAFFOLD_MODULES = ["doc_agent", "swe_agent", "manager_agent"]


def scaffold_cases() -> List[Case]:
    import importlib
    out = []
    for modname in SCAFFOLD_MODULES:
        mod = importlib.import_module(f"capagent.scaffolds.{modname}")
        with open(mod.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        ce = CE.extract_from_source(src, mod.META["id"])
        ge = GE.extract_from_source(src, mod.META["id"])
        ct = ce.table()
        n_tools = len(ce.contracts)
        n_sinks = sum(1 for c in ce.contracts if c.high_impact)
        for pname, meta in mod.META["plans"].items():
            acg = AB.build_acg_from_source(src, pname, ct)
            prog = TR.acg_to_ir(acg)
            if pname.endswith("buggy"):
                variant, pair = "buggy", pname.rsplit("_", 1)[0]
            elif pname.endswith("fixed"):
                variant, pair = "fixed", pname.rsplit("_", 1)[0]
            elif meta["expected_safe"]:
                variant, pair = "control", pname          # unpaired
            else:
                variant, pair = "buggy", pname             # unsafe, unpaired witness
            out.append(Case(
                id=f"{mod.META['id']}/{pname}", subject="scaffold", mode=mod.META["mode"],
                effect_kind=_first_sink_kind(prog, ct), family="scaffold", variant=variant,
                expected_safe=meta["expected_safe"], program=prog, contracts=ct,
                pair_id=f"{mod.META['id']}:{pair}", description=meta.get("note", ""),
                acg=acg,
                extraction={
                    "tools": n_tools, "sinks": n_sinks, "unresolved": len(ce.unresolved),
                    "guards": len(ge.guards), "warnings": len(acg.warnings),
                    "module": mod.META["id"],
                },
            ))
    return out


def all_cases() -> List[Case]:
    return kernel_cases() + scaffold_cases()


def witness_pairs(cases: List[Case]):
    """Group buggy/fixed cases sharing a pair_id (security witnesses + repairs)."""
    by_pair = {}
    for c in cases:
        if c.variant in ("buggy", "fixed") and c.pair_id:
            by_pair.setdefault(c.pair_id, {})[c.variant] = c
    pairs = []
    for pid, d in by_pair.items():
        if "buggy" in d and "fixed" in d:
            b, fx = d["buggy"], d["fixed"]
            pairs.append({
                "pair_id": pid, "mode": b.mode, "effect_kind": b.effect_kind,
                "repair_pattern": fx.repair_pattern or _infer_repair(b, fx),
                "buggy": b.program, "fixed": fx.program, "contracts": b.contracts,
            })
    return pairs


def _tool_multiset(program: ir.Stmt):
    from collections import Counter
    tools = Counter()
    requires = 0
    sink_resources = []
    for s in ir.walk(program):
        if isinstance(s, ir.ToolCall):
            tools[s.tool] += 1
            if s.args:
                sink_resources.append((s.tool, tuple(s.args)))
        elif isinstance(s, ir.Require):
            requires += 1
        elif isinstance(s, ir.Declassify):
            tools["<declassify>"] += 1
    return tools, requires, sink_resources


def _infer_repair(buggy: Case, fixed: Case) -> str:
    """Infer the repair pattern by diffing the buggy and fixed programs."""
    bt, breq, bres = _tool_multiset(buggy.program)
    ft, freq, fres = _tool_multiset(fixed.program)
    added = ft - bt
    if any(t in ("redact", "<declassify>") for t in added):
        return "declassify"
    if any("validate" in t or "provenance" in t for t in added):
        return "provenance"
    if freq > breq:
        return "guard"
    if set(bres) != set(fres):
        return "scope"
    return "contract"
