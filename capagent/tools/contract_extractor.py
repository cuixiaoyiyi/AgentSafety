"""contract-extractor: infer tool effect contracts from scaffold source (plan Sec 1.2).

Input:  a Python scaffold file (or module source).
Output: tool_contracts (one record per tool wrapper), effect_evidence, and a list
        of unresolved tools.

Extraction combines four evidence sources, in priority order:
  1. decorator evidence  (@reads/@transform/@declassifies/@provenance_check)
  2. strong name heuristics for indirect sinks (patch/verdict/dispatch/instruction)
  3. direct high-impact API call patterns (os.remove, requests.post, subprocess, ...)
  4. one-level local-call resolution (wrapper delegates to a helper with a sink)
Anything unresolved is reported conservatively rather than silently dropped.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .astutil import call_name, decorator_names, arg_names
from ..core.types import (
    ToolContract, Propagation, ContractTable,
    KIND_DELETE, KIND_OVERWRITE, KIND_SEND_EXT, KIND_EXEC, KIND_MODIFY_REPO,
    KIND_MOD_HARNESS, KIND_VERDICT, KIND_INSTR_USE, KIND_DELEGATE, KIND_CRED,
    KIND_READ, KIND_TRANSFORM, KIND_DECLASSIFY,
)
from ..core.semantics import DEFAULT_HIGH_IMPACT

# Direct high-impact API sink patterns -> effect kind.
API_PATTERNS = [
    (("os.remove", "os.unlink", "shutil.rmtree", "Path.unlink"), KIND_DELETE),
    (("requests.post", "requests.put", "requests.patch",
      "smtplib.SMTP.sendmail", "server.sendmail", "session.post",
      "urllib.request.urlopen", "httpx.post"), KIND_SEND_EXT),
    (("subprocess.run", "subprocess.call", "subprocess.Popen",
      "subprocess.check_output", "os.system", "eval", "exec"), KIND_EXEC),
    (("os.environ.get", "keyring.get_password", "get_secret"), KIND_CRED),
]

# Name heuristics for wrappers that delegate to helpers (indirect sinks).
# Order matters: more specific names first (e.g. "dispatch" before "patch", since
# "patch" is a substring of "dis-patch").  The first five are the strong indirect
# sinks checked before generic API patterns.
NAME_HEURISTICS = [
    (("harness",), KIND_MOD_HARNESS),
    (("dispatch", "delegate"), KIND_DELEGATE),
    (("instruction", "as_instruction"), KIND_INSTR_USE),
    (("verdict", "oracle", "set_result", "resolve"), KIND_VERDICT),
    (("apply_patch", "patch", "git_apply"), KIND_MODIFY_REPO),
    (("delete", "unlink", "remove"), KIND_DELETE),
    (("send", "email", "upload", "post", "webhook"), KIND_SEND_EXT),
    (("exec", "shell", "run_cmd"), KIND_EXEC),
    (("write", "overwrite", "save"), KIND_OVERWRITE),
]

HIGH_IMPACT = set(DEFAULT_HIGH_IMPACT)


@dataclass
class ExtractionResult:
    contracts: List[ToolContract] = field(default_factory=list)
    evidence: List[dict] = field(default_factory=list)
    unresolved: List[dict] = field(default_factory=list)

    def table(self) -> ContractTable:
        t = ContractTable(high_impact_kinds=frozenset(HIGH_IMPACT))
        for c in self.contracts:
            t.add(c)
        return t


def _write_sink_kind(body_calls) -> Optional[str]:
    for cn in body_calls:
        # open(..., 'w'/'a') or .write/.write_text
        if cn.endswith(".write") or cn.endswith(".write_text") or cn == "write":
            return KIND_OVERWRITE
    return None


def _propagation_for(kind: str, reads_private: bool) -> Propagation:
    if kind == KIND_READ:
        return Propagation("fresh_private" if reads_private else "public")
    if kind == KIND_TRANSFORM:
        return Propagation("keep", 0)
    if kind == KIND_DECLASSIFY:
        return Propagation("declassify")
    return Propagation("public")


def _defaults_for(kind: str):
    """Return (resource_arg, resource_const, dest_arg) for a kind."""
    if kind == KIND_EXEC:
        return (None, "sandbox", 0)
    if kind == KIND_VERDICT:
        return (None, "oracle", None)
    if kind == KIND_SEND_EXT:
        return (0, None, 1)
    return (0, None, None)


def infer_effect(fn: ast.FunctionDef, funcs: Dict[str, ast.FunctionDef], name: str = None):
    """Infer the effect of a single function definition.

    Returns (kind, source_kind, evidence, prop_override, reads_private) or None if no
    effect can be inferred.  Shared by ``extract_from_source`` and the registry adapter.
    """
    name = name or fn.name
    decos = [d.split(".")[-1] for d in decorator_names(fn)]
    body_calls = [call_name(c) for c in ast.walk(fn) if isinstance(c, ast.Call)]

    kind = None
    source_kind = "manual"
    evidence = []
    reads_private = False
    prop_override = None

    # 1) decorator evidence
    if "reads" in decos:
        kind = KIND_READ
        reads_private = _reads_private(fn)
        source_kind = "doc"; evidence.append("@reads")
    elif "transform" in decos:
        kind = KIND_TRANSFORM; source_kind = "doc"; evidence.append("@transform")
    elif "declassifies" in decos:
        kind = KIND_DECLASSIFY; source_kind = "doc"; evidence.append("@declassifies")
    elif "provenance_check" in decos:
        kind = KIND_TRANSFORM; source_kind = "doc"; evidence.append("@provenance_check")
        prop_override = Propagation("public")

    # 2) strong name heuristics (indirect sinks)
    if kind is None:
        for needles, k in NAME_HEURISTICS[:5]:
            if any(nd in name for nd in needles):
                kind = k; source_kind = "wrapper"
                evidence.append(f"name~{needles[0]}"); break

    # 3) direct API patterns
    if kind is None:
        for pats, k in API_PATTERNS:
            leaves = [p.split(".")[-1] for p in pats]
            if any(bc in pats or bc.split(".")[-1] in leaves for bc in body_calls):
                kind = k; source_kind = "api"
                hit = next(bc for bc in body_calls if bc.split(".")[-1] in leaves)
                evidence.append(hit); break

    # 3b) open(...,'w') style write
    if kind is None:
        wk = _write_sink_kind(body_calls)
        if wk:
            kind = wk; source_kind = "api"; evidence.append("open(...,'w')")

    # 4) remaining name heuristics + one-level local resolution
    if kind is None:
        for needles, k in NAME_HEURISTICS[5:]:
            if any(nd in name for nd in needles):
                kind = k; source_kind = "wrapper"
                evidence.append(f"name~{needles[0]}"); break
    if kind is None:
        for bc in body_calls:
            helper = funcs.get(bc)
            if helper is not None and helper is not fn:
                sub = [call_name(c) for c in ast.walk(helper) if isinstance(c, ast.Call)]
                for pats, k in API_PATTERNS:
                    leaves = [p.split(".")[-1] for p in pats]
                    if any(s.split(".")[-1] in leaves for s in sub):
                        kind = k; source_kind = "wrapper"
                        evidence.append(f"->{bc}"); break
                if kind:
                    break

    if kind is None:
        return None
    return kind, source_kind, evidence, prop_override, reads_private


def extract_from_source(source: str, module: str = "") -> ExtractionResult:
    tree = ast.parse(source)
    funcs: Dict[str, ast.FunctionDef] = {
        n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
    }
    res = ExtractionResult()

    for name, fn in funcs.items():
        if name.startswith("plan_") or name in ("META",):
            continue
        line = fn.lineno
        site = f"{module}:{line}" if module else f"L{line}"
        inferred = infer_effect(fn, funcs, name)
        if inferred is None:
            body_calls = [call_name(c) for c in ast.walk(fn) if isinstance(c, ast.Call)]
            res.unresolved.append({"tool": name, "site": site,
                                   "reason": "no recognized effect", "body_calls": body_calls})
            continue
        kind, source_kind, evidence, prop_override, reads_private = inferred

        res_arg, res_const, dest_arg = _defaults_for(kind)
        contract = ToolContract(
            tool=name, effect_kind=kind, high_impact=(kind in HIGH_IMPACT),
            resource_arg=res_arg, resource_const=res_const, external_dest_arg=dest_arg,
            propagate=prop_override or _propagation_for(kind, reads_private),
            source=source_kind, evidence=tuple(evidence), confidence="high" if source_kind in ("api", "doc") else "medium",
        )
        res.contracts.append(contract)
        res.evidence.append({"tool": name, "site": site, "effect": kind,
                             "source": source_kind, "evidence": evidence,
                             "high_impact": contract.high_impact})
    return res


def _reads_private(fn: ast.FunctionDef) -> bool:
    for d in fn.decorator_list:
        if isinstance(d, ast.Call) and call_name(d).split(".")[-1] == "reads":
            for kw in d.keywords:
                if kw.arg == "private":
                    try:
                        return bool(ast.literal_eval(kw.value))
                    except Exception:
                        return False
    return False


def extract_from_file(path: str, module: str = "") -> ExtractionResult:
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()
    return extract_from_source(src, module or path)
