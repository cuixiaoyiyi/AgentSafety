"""capsafe-checker: check whether a program admits an unguarded high-impact effect.

Runs both the explicit-state checker (exact for the Boolean instance) and the
matrix-mode check (Section 4.4 projection), and produces witnesses + a human-readable
diagnostic (Section 5.6).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from ..core import ir
from ..core.semantics import Checker, Policy, CheckResult, Witness
from ..core.matrices import check_matrix, Certificate
from ..core.types import ContractTable


@dataclass
class CheckReport:
    name: str
    safe: bool
    matrix_safe: bool
    agree: bool
    witnesses: List[Witness]
    certificate: Certificate
    result: CheckResult

    def diagnostic(self) -> str:
        if self.safe:
            return (f"[{self.name}] SAFE: bad-capability projection is zero over "
                    f"{self.certificate.reachable_count} reachable abstract states.")
        w = self.witnesses[0]
        path = "\n  -> ".join(str(a) for a in w.path)
        return (f"[{self.name}] UNSAFE\nUnsafe path:\n  -> {path}\n"
                f"Missing capability:\n  {w.missing_capability}\n"
                f"Triggered bad component:\n  BadCap\n"
                f"Evidence: {', '.join(w.evidence) if w.evidence else 'n/a'}")


def check(program: ir.Stmt, contracts: ContractTable, name: str = "",
          policy: Optional[Policy] = None) -> CheckReport:
    chk = Checker(contracts, policy or Policy())
    result = chk.check(program)
    cert = check_matrix(program, contracts, policy or Policy())
    return CheckReport(
        name=name,
        safe=result.safe,
        matrix_safe=cert.safe,
        agree=(result.safe == cert.safe),
        witnesses=result.witnesses,
        certificate=cert,
        result=result,
    )
