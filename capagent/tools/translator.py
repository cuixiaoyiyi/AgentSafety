"""capagent-translator: translate an ACG into lambda_cap / CapAgent IR (plan Sec 1.5).

Each ACG path maps to an IR fragment (paper Definition 12): tool-call nodes become
``x := t(e)``, guard nodes become ``require``, memory edges become memread/memwrite,
branches become nondeterministic choice, and loops become ``while``.
"""
from __future__ import annotations

from typing import List, Optional

from ..core import ir
from ..core.ir import seq, Choice, While, Skip
from ..core.acg import (
    ACG, N_INIT, N_TOOL, N_SINK, N_GUARD, N_MEMREAD, N_MEMWRITE, N_LLM_CHOICE, N_MERGE,
)
from ..core.types import Capability, Region


def _region(region_list) -> Region:
    if not region_list:
        return Region.top()
    names = [str(r) for r in region_list if not str(r).endswith("/")]
    prefixes = [str(r) for r in region_list if str(r).endswith("/")]
    return Region(names=frozenset(names), prefixes=tuple(prefixes))


def _capability(cap: dict) -> Capability:
    kind = cap.get("kind")
    region = _region(cap.get("region"))
    labels = frozenset(cap["labels"]) if cap.get("labels") else frozenset({"private", "public"})
    provs = frozenset(cap["provs"]) if cap.get("provs") else frozenset({"trusted", "untrusted"})
    return Capability(kind, region, labels, provs)


def _node_to_stmt(acg: ACG, nid: str) -> ir.Stmt:
    n = acg.nodes[nid]
    if n.kind in (N_TOOL, N_SINK):
        return ir.ToolCall(tool=n.tool, args=n.args, result=n.result, site=n.site)
    if n.kind == N_GUARD:
        return ir.Require(cap=_capability(n.cap or {}), capvar="c", site=n.site)
    if n.kind == N_MEMREAD:
        key = n.args[0] if n.args else n.label.split()[-1]
        return ir.MemRead(var=n.result or "m", key=key, untrusted=n.untrusted, site=n.site)
    if n.kind == N_MEMWRITE:
        key = n.args[0] if n.args else "k"
        var = n.args[1] if len(n.args) > 1 else "x"
        return ir.MemWrite(key=key, var=var, untrusted=n.untrusted, site=n.site)
    return Skip()


def _first_succ(acg: ACG, nid: str) -> Optional[str]:
    s = acg.successors(nid)
    return s[0] if s else None


def _chain(acg: ACG, nid: Optional[str], stop: Optional[str]) -> ir.Stmt:
    stmts: List[ir.Stmt] = []
    while nid is not None and nid != stop:
        node = acg.nodes[nid]
        if node.kind == N_MERGE:
            break
        if node.kind == N_LLM_CHOICE:
            if node.attrs.get("loop"):
                succs = [s for s in acg.successors(nid) if s != nid]
                body = _chain(acg, succs[0], stop=nid) if succs else Skip()
                stmts.append(While(guard="*", body=body))
                nid = None
                continue
            merge = node.attrs.get("merge")
            branches = []
            for s in acg.successors(nid):
                if s == merge:
                    branches.append(Skip())
                else:
                    branches.append(_chain(acg, s, stop=merge))
            if len(branches) == 1:
                stmts.append(branches[0])
            elif len(branches) >= 2:
                stmts.append(Choice(branches[0], branches[1]))
            nid = _first_succ(acg, merge) if merge else None
            continue
        stmts.append(_node_to_stmt(acg, nid))
        nid = _first_succ(acg, nid)
    return seq(*stmts)


def acg_to_ir(acg: ACG) -> ir.Stmt:
    start = _first_succ(acg, acg.entry) if acg.entry else None
    if start is None:
        return Skip()
    return _chain(acg, start, stop=None)


def to_capagent_text(program: ir.Stmt) -> str:
    """Render the textual CapAgent IR surface syntax (program.capagent)."""
    return ir.pretty(program)
