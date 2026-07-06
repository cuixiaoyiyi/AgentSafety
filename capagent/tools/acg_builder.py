"""acg-builder: construct an Action-Capability Graph from a scaffold plan (plan Sec 1.4).

Parses a ``plan_*`` function body (structured Python: sequencing, if/else model
choice, while loops) into an ACG whose sink nodes are resolved via the extracted
tool contracts and whose grant nodes come from ``require(...)`` guards.  Dynamic
dispatch / unresolved calls are recorded in ``acg.warnings`` rather than dropped.
"""
from __future__ import annotations

import ast
from typing import List, Optional, Tuple

from .astutil import call_name, parse_capability, literal
from ..core.acg import (
    ACG, Node, N_INIT, N_LLM_CHOICE, N_TOOL, N_GUARD, N_MEMREAD, N_MEMWRITE,
    N_SINK, N_MERGE, E_CONTROL,
)
from ..core.types import ContractTable

MEM_TOOLS = {"memread", "memwrite"}
GRANT_TOOLS = {"require", "grant", "ask_confirm", "confirm", "authorize"}


class _Builder:
    def __init__(self, acg: ACG, contracts: ContractTable):
        self.acg = acg
        self.contracts = contracts
        self._n = 0

    def nid(self, kind: str) -> str:
        self._n += 1
        return f"{kind[:3].lower()}{self._n}"

    def _args(self, call: ast.Call) -> tuple:
        out = []
        for a in call.args:
            v = literal(a)
            out.append(str(v) if v is not None else "?")
        return tuple(out)

    def stmt_node(self, stmt: ast.stmt) -> Optional[Node]:
        """Translate a simple (non-control) statement into an ACG node."""
        call = None
        result = None
        if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
            call = stmt.value
            if stmt.targets and isinstance(stmt.targets[0], ast.Name):
                result = stmt.targets[0].id
        elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            call = stmt.value
        if call is None:
            return None

        name = call_name(call).split(".")[-1]
        site = f"L{getattr(call, 'lineno', 0)}"
        args = self._args(call)

        if name in GRANT_TOOLS:
            cap = parse_capability(call) if call.args else {"kind": None, "region": []}
            return self.acg.add_node(Node(self.nid("grant"), N_GUARD, label=f"require {cap.get('kind')}",
                                          cap=cap, site=site))
        if name == "memread":
            key = args[0] if args else "?"
            untr = _kw_bool(call, "untrusted")
            return self.acg.add_node(Node(self.nid("mr"), N_MEMREAD, label=f"memread {key}",
                                          result=result, args=args, untrusted=untr, site=site))
        if name == "memwrite":
            key = args[0] if args else "?"
            untr = _kw_bool(call, "untrusted")
            return self.acg.add_node(Node(self.nid("mw"), N_MEMWRITE, label=f"memwrite {key}",
                                          args=args, untrusted=untr, site=site))

        contract = self.contracts.get(name)
        if contract is None:
            self.acg.warnings.append({"site": site, "call": name, "reason": "no contract"})
            n = Node(self.nid("tool"), N_TOOL, label=name, tool=name, args=args, result=result, site=site)
            return self.acg.add_node(n)

        high = contract.high_impact
        kind = N_SINK if high else N_TOOL
        n = Node(self.nid("tool"), kind, label=name, tool=name, args=args, result=result,
                 effect_kind=contract.effect_kind, high_impact=high, site=site)
        return self.acg.add_node(n)

    def build_seq(self, body: List[ast.stmt]) -> Tuple[Optional[str], List[str]]:
        """Return (entry_id, exit_ids) for a statement list; wire control edges."""
        entry = None
        prev_exits: List[str] = []
        for stmt in body:
            e_in, e_out = self.build_stmt(stmt)
            if e_in is None:
                continue
            if entry is None:
                entry = e_in
            for p in prev_exits:
                self.acg.add_edge(p, e_in, E_CONTROL)
            prev_exits = e_out
        return entry, prev_exits

    def build_stmt(self, stmt: ast.stmt) -> Tuple[Optional[str], List[str]]:
        if isinstance(stmt, ast.If):
            choice = self.acg.add_node(Node(self.nid("llm"), N_LLM_CHOICE,
                                            label="model choice", site=f"L{stmt.lineno}"))
            merge = self.acg.add_node(Node(self.nid("mrg"), N_MERGE, label="merge"))
            choice.attrs["merge"] = merge.id
            t_in, t_out = self.build_seq(stmt.body)
            e_in, e_out = self.build_seq(stmt.orelse) if stmt.orelse else (None, [])
            if t_in is not None:
                self.acg.add_edge(choice.id, t_in, E_CONTROL)
                for x in t_out:
                    self.acg.add_edge(x, merge.id, E_CONTROL)
            else:
                self.acg.add_edge(choice.id, merge.id, E_CONTROL)
            if e_in is not None:
                self.acg.add_edge(choice.id, e_in, E_CONTROL)
                for x in e_out:
                    self.acg.add_edge(x, merge.id, E_CONTROL)
            else:
                self.acg.add_edge(choice.id, merge.id, E_CONTROL)
            return choice.id, [merge.id]

        if isinstance(stmt, (ast.While, ast.For)):
            choice = self.acg.add_node(Node(self.nid("llm"), N_LLM_CHOICE,
                                            label="loop head", site=f"L{stmt.lineno}"))
            choice.attrs["loop"] = True
            b_in, b_out = self.build_seq(stmt.body)
            if b_in is not None:
                self.acg.add_edge(choice.id, b_in, E_CONTROL)
                for x in b_out:
                    self.acg.add_edge(x, choice.id, E_CONTROL)   # back-edge
            choice.attrs["exit"] = True
            return choice.id, [choice.id]

        node = self.stmt_node(stmt)
        if node is None:
            return None, []
        return node.id, [node.id]


def build_acg(plan_fn: ast.FunctionDef, contracts: ContractTable, name: str = "") -> ACG:
    acg = ACG(name=name or plan_fn.name)
    init = acg.add_node(Node("init", N_INIT, label="initial state"))
    acg.entry = init.id
    b = _Builder(acg, contracts)
    entry, exits = b.build_seq(plan_fn.body)
    if entry is not None:
        acg.add_edge(init.id, entry, E_CONTROL)
        acg.exits = exits
    else:
        acg.exits = [init.id]
    return acg


def build_acg_from_source(source: str, plan_name: str, contracts: ContractTable) -> ACG:
    tree = ast.parse(source)
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == plan_name), None)
    if fn is None:
        raise ValueError(f"plan function {plan_name} not found")
    return build_acg(fn, contracts, name=plan_name)


def _kw_bool(call: ast.Call, name: str) -> bool:
    for kw in call.keywords:
        if kw.arg == name:
            try:
                return bool(ast.literal_eval(kw.value))
            except Exception:
                return False
    return False
