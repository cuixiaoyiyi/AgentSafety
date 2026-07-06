"""guard-extractor: extract capability grants and guard nodes (plan Sec 1.3).

Recognizes explicit ``require(kind, region=[...], ...)`` policy interactions and
confirmation-style guards (``ask_confirm``/``confirm_*``) in scaffold source.  Each
grant is reported with its site and the capability it produces, feeding acg-builder.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List

from .astutil import call_name, parse_capability

GRANT_NAMES = {"require", "ask_confirm", "confirm", "confirm_delete", "grant", "authorize"}


@dataclass
class GuardRecord:
    site: str
    func: str
    grant_call: str
    cap: dict
    evidence: List[str] = field(default_factory=list)


@dataclass
class GuardResult:
    guards: List[GuardRecord] = field(default_factory=list)
    # site (line) -> cap dict, for acg-builder to attach to require() statements
    by_line: Dict[int, dict] = field(default_factory=dict)


def extract_from_source(source: str, module: str = "") -> GuardResult:
    tree = ast.parse(source)
    res = GuardResult()
    func_of = {}
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        for c in ast.walk(fn):
            if isinstance(c, ast.Call):
                func_of[id(c)] = fn.name

    for c in ast.walk(tree):
        if not isinstance(c, ast.Call):
            continue
        cn = call_name(c).split(".")[-1]
        if cn in GRANT_NAMES:
            cap = parse_capability(c) if c.args else {"kind": None, "region": []}
            line = getattr(c, "lineno", 0)
            site = f"{module}:{line}" if module else f"L{line}"
            res.guards.append(GuardRecord(
                site=site, func=func_of.get(id(c), "?"), grant_call=cn,
                cap=cap, evidence=[f"{cn}(...)"],
            ))
            res.by_line[line] = cap
    return res


def extract_from_file(path: str, module: str = "") -> GuardResult:
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()
    return extract_from_source(src, module or path)
