"""witness-replayer: replay buggy/fixed pairs as formal witnesses (plan Sec 1.8).

For each buggy/fixed pair it checks both versions and records whether the buggy
path is rejected, the repaired path is accepted, and which repair pattern discharged
the missing capability (guard insertion, scope refinement, provenance validation,
declassification, or contract tightening).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from ..core.semantics import Checker, Policy
from ..core.types import ContractTable


@dataclass
class ReplayRow:
    pair_id: str
    mode: str
    effect_kind: str
    buggy_unsafe: bool
    fixed_safe: bool
    repair_pattern: str
    missing_capability: str
    consistent: bool          # buggy rejected AND fixed accepted

    def as_dict(self) -> dict:
        return self.__dict__.copy()


def replay(pairs, contracts: ContractTable, policy: Optional[Policy] = None) -> List[ReplayRow]:
    """`pairs`: list of dicts {pair_id, mode, effect_kind, repair_pattern, buggy, fixed}."""
    rows = []
    for p in pairs:
        rb = Checker(contracts, policy or Policy()).check(p["buggy"])
        rf = Checker(contracts, policy or Policy()).check(p["fixed"])
        missing = rb.witnesses[0].missing_capability if rb.witnesses else ""
        buggy_unsafe = not rb.safe
        fixed_safe = rf.safe
        rows.append(ReplayRow(
            pair_id=p["pair_id"], mode=p.get("mode", ""), effect_kind=p.get("effect_kind", ""),
            buggy_unsafe=buggy_unsafe, fixed_safe=fixed_safe,
            repair_pattern=p.get("repair_pattern", ""), missing_capability=missing,
            consistent=(buggy_unsafe and fixed_safe),
        ))
    return rows
