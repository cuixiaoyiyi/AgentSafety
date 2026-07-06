"""llm-assist: OPTIONAL, offline candidate summarizer (plan Sec 1.9 / 3).

By design this component is NOT a trusted autonomous agent and never runs code,
edits repos, or opens the network.  It is a bounded batch classifier that proposes
*candidate* effect labels from tool names and docstrings, each with an evidence span
and a confidence, marked ``accepted=False`` until human review.  The deterministic
offline implementation here stands in for a bounded model API call so that the
pipeline is fully reproducible; its outputs never enter the trusted verification
chain.
"""
from __future__ import annotations

import ast
from typing import List

from .astutil import call_name

_KEYWORD_EFFECTS = [
    (("delete", "remove", "unlink", "rmtree"), "Delete"),
    (("overwrite", "write", "save", "update"), "Overwrite"),
    (("send", "email", "upload", "post", "webhook", "notify"), "SendExt"),
    (("exec", "shell", "subprocess", "run", "eval"), "Exec"),
    (("patch", "apply", "commit"), "ModifyRepo"),
    (("harness", "oracle", "verdict", "grade", "score"), "Verdict"),
    (("dispatch", "delegate", "manager"), "Delegate"),
    (("instruction", "prompt", "memory"), "InstrUse"),
    (("secret", "credential", "token", "api_key"), "CredAccess"),
]


def _candidate_for(name: str, doc: str) -> tuple:
    hay = (name + " " + (doc or "")).lower()
    for needles, eff in _KEYWORD_EFFECTS:
        for nd in needles:
            if nd in hay:
                span = nd
                conf = "high" if nd in name.lower() else "medium"
                return eff, span, conf
    return None, None, "low"


def summarize_tools(source: str, module: str = "") -> List[dict]:
    """Propose candidate effect labels for wrapper functions.  Advisory only."""
    tree = ast.parse(source)
    out = []
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        if fn.name.startswith("plan_"):
            continue
        doc = ast.get_docstring(fn) or ""
        # a lightweight "summary" of the body: the API calls it makes
        calls = sorted({call_name(c) for c in ast.walk(fn) if isinstance(c, ast.Call)})
        eff, span, conf = _candidate_for(fn.name, doc + " " + " ".join(calls))
        out.append({
            "tool": fn.name,
            "module": module,
            "candidate_effect": eff,
            "evidence_span": span,
            "confidence": conf,
            "summary": f"{fn.name}: calls {', '.join(calls) if calls else 'none'}",
            "status": "candidate",
            "accepted": False,          # never trusted until human review
            "note": "advisory; not part of the trusted verification base",
        })
    return out
