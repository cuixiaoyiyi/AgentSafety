"""Per-framework registry adapter: automate real-repo RQ3 (Milestone 5).

Instead of hand-curating witnesses, this adapter *discovers a framework's tool
registry* directly from source, classifies each registered tool's effect (reusing the
contract-extractor inference), builds an Action-Capability Graph in which the model
may nondeterministically call any registered tool (paper Section 4.3: "if the
implementation permits arbitrary calls to a registry, the choice set includes all such
calls"), translates it to lambda_cap, and runs the capsafe checker.

The automated finding is registry-level and *literally true*: the static tool registry
attaches no capability requirement to its high-impact tools, so the ACG admits a path
from a model choice to an unguarded high-impact effect.  Whether a runtime approval
layer exists *outside* the registry is a separate concern (reported, not modeled).
"""
from __future__ import annotations

import ast
import os
import warnings
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..tools.astutil import call_name, decorator_names
from ..tools.contract_extractor import infer_effect, NAME_HEURISTICS
from ..core import ir
from ..core.ir import seq, Require, Think, ToolCall as T
from ..core.acg import ACG, Node, N_INIT, N_LLM_CHOICE, N_TOOL, N_SINK, E_CONTROL
from ..core.types import ContractTable, ToolContract, Propagation
from ..core.semantics import Checker, Policy, DEFAULT_HIGH_IMPACT, KIND_SEND_EXT

REG_DECORATOR_LEAVES = {"tool", "register_tool", "function_tool", "agent_tool",
                        "tool_registry", "mcp_tool", "kernel_function", "tool_spec"}
TOOL_BASE_LEAVES = {"Tool", "BaseTool", "FunctionTool", "Toolkit", "AgentTool", "BaseToolkit"}
ACTION_METHODS = ["forward", "_run", "run", "execute", "step", "_arun", "_execute", "__call__"]
GUARD_KEYWORDS = ("confirm", "approve", "permission", "authoriz", "sandbox",
                  "consent", "allowlist", "safe_mode", "dangerously")

UNCONDITIONAL_HIGH = DEFAULT_HIGH_IMPACT - {KIND_SEND_EXT}


@dataclass
class DiscoveredTool:
    name: str
    effect_kind: str
    high_impact: bool
    registration: str        # decorator | subclass
    source: str
    evidence: List[str]
    site: str
    guarded_hint: bool = False


@dataclass
class RegistryScan:
    repo: str
    mode: str
    files: int = 0
    tools: List[DiscoveredTool] = field(default_factory=list)
    kind_counts: Counter = field(default_factory=Counter)

    def high_impact_tools(self):
        return [t for t in self.tools if t.high_impact]


def _base_leaf(b) -> str:
    if isinstance(b, ast.Name):
        return b.id
    if isinstance(b, ast.Attribute):
        return b.attr
    if isinstance(b, ast.Subscript):
        return _base_leaf(b.value)
    if isinstance(b, ast.Call):
        return _base_leaf(b.func)
    return ""


def _find_action_method(cls: ast.ClassDef) -> Optional[ast.FunctionDef]:
    methods = {n.name: n for n in cls.body if isinstance(n, ast.FunctionDef)}
    for m in ACTION_METHODS:
        if m in methods:
            return methods[m]
    return None


def _module_has_guard(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        nm = ""
        if isinstance(node, ast.Call):
            nm = call_name(node).split(".")[-1].lower()
        elif isinstance(node, ast.FunctionDef):
            nm = node.name.lower()
        if nm and any(k in nm for k in GUARD_KEYWORDS):
            return True
    return False


def discover_in_source(source: str, module: str) -> List[DiscoveredTool]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        tree = ast.parse(source)
    funcs = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    guarded = _module_has_guard(tree)
    out: List[DiscoveredTool] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            leaves = [d.split(".")[-1] for d in decorator_names(node)]
            if any(l in REG_DECORATOR_LEAVES for l in leaves):
                inf = infer_effect(node, funcs, node.name)
                out.append(_mk(node.name, inf, module, node.lineno, "decorator", guarded))
        elif isinstance(node, ast.ClassDef):
            deco_leaves = [d.split(".")[-1] for d in decorator_names(node)]
            reg_deco = any(l in REG_DECORATOR_LEAVES for l in deco_leaves)
            is_sub = any(_base_leaf(b) in TOOL_BASE_LEAVES for b in node.bases)
            if not (reg_deco or is_sub):
                continue
            method = _find_action_method(node)
            inf = infer_effect(method, funcs, node.name) if method is not None else None
            reg = "register-decorator" if reg_deco else "subclass"
            out.append(_mk(node.name, inf, module, node.lineno, reg, guarded))
    return out


def _name_kind(name: str):
    """Fallback effect classification from the tool's (class) name alone."""
    for needles, k in NAME_HEURISTICS:
        if any(nd in name.lower() for nd in needles):
            return k, [f"name~{needles[0]}"]
    return None, []


def _mk(name, inf, module, line, registration, guarded) -> DiscoveredTool:
    if inf is not None:
        kind, source, evidence, _prop, _rp = inf
    else:
        nk, nev = _name_kind(name)
        if nk is not None:
            kind, source, evidence = nk, "name", nev
        else:
            kind, source, evidence = "-", "unresolved", []
    high = kind in DEFAULT_HIGH_IMPACT
    return DiscoveredTool(name=name, effect_kind=kind, high_impact=high,
                          registration=registration, source=source, evidence=list(evidence),
                          site=f"{module}:{line}", guarded_hint=guarded)


def scan_registry(repo: str, mode: str, root: str, max_files: int = 100000) -> RegistryScan:
    rs = RegistryScan(repo=repo, mode=mode)
    seen = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in
                       (".git", "node_modules", "__pycache__", ".venv", "venv",
                        "build", "dist", ".tox", "site-packages")]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            fp = os.path.join(dirpath, fn)
            rel = os.path.relpath(fp, root).replace("\\", "/")
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as f:
                    src = f.read()
            except Exception:
                continue
            rs.files += 1
            try:
                tools = discover_in_source(src, f"{repo}/{rel}")
            except (SyntaxError, ValueError):
                continue
            for t in tools:
                # dedupe by name, prefer the high-impact classification
                if t.name in seen and not (t.high_impact and not seen[t.name].high_impact):
                    continue
                seen[t.name] = t
    rs.tools = list(seen.values())
    for t in rs.tools:
        if t.effect_kind != "-":
            rs.kind_counts[t.effect_kind] += 1
    return rs


# --------------------------------------------------------------------------
# ACG + IR from the discovered registry
# --------------------------------------------------------------------------
def _contract_table(tools: List[DiscoveredTool]) -> ContractTable:
    ct = ContractTable(high_impact_kinds=DEFAULT_HIGH_IMPACT)
    for t in tools:
        if t.effect_kind == "-":
            continue
        res_const = "sandbox" if t.effect_kind == "Exec" else (
            "oracle" if t.effect_kind == "Verdict" else None)
        ct.add(ToolContract(tool=t.name, effect_kind=t.effect_kind, high_impact=t.high_impact,
                            resource_arg=0 if res_const is None else None, resource_const=res_const,
                            propagate=Propagation("public"), source=t.source,
                            evidence=tuple(t.evidence)))
    return ct


def build_registry_acg(rs: RegistryScan) -> ACG:
    acg = ACG(name=f"{rs.repo}-registry")
    init = acg.add_node(Node("init", N_INIT, label="agent start"))
    choice = acg.add_node(Node("choice", N_LLM_CHOICE, label="model tool choice"))
    acg.entry = init.id
    acg.add_edge(init.id, choice.id, E_CONTROL)
    for i, t in enumerate(rs.high_impact_tools()):
        nid = f"t{i}"
        acg.add_node(Node(nid, N_SINK, label=t.name, tool=t.name,
                          effect_kind=t.effect_kind, high_impact=True, site=t.site))
        acg.add_edge(choice.id, nid, E_CONTROL)
    acg.exits = [choice.id]
    return acg


def check_registry(rs: RegistryScan) -> dict:
    """Build Think(registry) IR and check; count unguarded high-impact reachable tools."""
    hi = rs.high_impact_tools()
    ct = _contract_table(rs.tools)
    calls = [T(tool=t.name, args=("res",), site=t.site) for t in hi]
    program = Think(choices=calls) if calls else ir.Skip()
    chk = Checker(ct, Policy())
    result = chk.check(program)
    flagged = {w.effect.kind for w in result.witnesses}
    flagged_tools = sorted({(str(w.effect.kind), w.sink_site) for w in result.witnesses})
    return {
        "high_impact_tools": len(hi),
        "unguarded_reachable": len(result.witnesses),
        "flagged_kinds": dict(Counter(w.effect.kind for w in result.witnesses)),
        "module_guard_hint_fraction": round(
            sum(1 for t in hi if t.guarded_hint) / len(hi), 3) if hi else None,
        "sample_flagged": flagged_tools[:8],
    }
