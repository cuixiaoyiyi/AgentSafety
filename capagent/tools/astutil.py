"""Shared AST helpers for the extractors."""
from __future__ import annotations

import ast
from typing import List, Optional


def literal(node) -> object:
    try:
        return ast.literal_eval(node)
    except Exception:
        if isinstance(node, ast.Name):
            return node.id
        return None


def call_name(node: ast.Call) -> str:
    """Dotted name of a call target, e.g. 'os.remove', 'requests.post', 'f.write'."""
    f = node.func
    parts = []
    while isinstance(f, ast.Attribute):
        parts.append(f.attr)
        f = f.value
    if isinstance(f, ast.Name):
        parts.append(f.id)
    return ".".join(reversed(parts))


def decorator_names(fn: ast.FunctionDef) -> List[str]:
    out = []
    for d in fn.decorator_list:
        if isinstance(d, ast.Call):
            out.append(call_name(d))
        elif isinstance(d, ast.Attribute):
            out.append(d.attr)
        elif isinstance(d, ast.Name):
            out.append(d.id)
    return out


def decorator_call(fn: ast.FunctionDef, name: str) -> Optional[ast.Call]:
    for d in fn.decorator_list:
        if isinstance(d, ast.Call) and (call_name(d).split(".")[-1] == name):
            return d
    return None


def arg_names(fn: ast.FunctionDef) -> List[str]:
    return [a.arg for a in fn.args.args]


def parse_capability(node: ast.Call) -> dict:
    """Parse a require(kind, region=[...], labels=[...], provs=[...]) call."""
    kind = literal(node.args[0]) if node.args else None
    cap = {"kind": kind, "region": [], "labels": None, "provs": None}
    if len(node.args) > 1:
        cap["region"] = literal(node.args[1]) or []
    for kw in node.keywords:
        if kw.arg in ("region", "labels", "provs"):
            cap[kw.arg] = literal(kw.value)
    return cap
