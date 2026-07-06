"""Repository-scale extractor for real agent frameworks (Milestone 5, RQ2).

Precise, conservative high-impact **sink** inventory + guard inventory over a real
Python source tree.  Matching is intentionally strict (fully-qualified module.func or
unambiguous leaves) so counts *under*-approximate rather than inflate; that direction
is the honest one for "the property is pervasive in real agent code".
"""
from __future__ import annotations

import ast
import os
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..tools.astutil import call_name
from ..core.types import (
    KIND_DELETE, KIND_OVERWRITE, KIND_SEND_EXT, KIND_EXEC, KIND_CRED,
)

# Fully-qualified (last-two-component) exec sinks.
EXEC_QUALIFIED = {
    "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output",
    "subprocess.check_call", "subprocess.getoutput", "os.system", "os.popen",
    "os.execv", "os.execvp", "pty.spawn", "commands.getoutput",
}
DELETE_QUALIFIED = {"os.remove", "os.unlink", "os.rmdir", "shutil.rmtree"}
DELETE_LEAF = {"rmtree"}
SEND_HINT_MODULES = ("requests", "httpx", "aiohttp", "urllib", "urllib3", "session", "client")
SEND_LEAF = {"post", "put", "patch"}
SEND_QUALIFIED = {"smtplib.SMTP.sendmail", "urllib.request.urlopen"}
SEND_LEAF_ALWAYS = {"sendmail", "urlopen", "send_message"}
CRED_QUALIFIED = {"os.getenv", "os.environ.get", "keyring.get_password", "dotenv.get_key"}
CRED_ALWAYS = {"keyring.get_password", "dotenv.get_key"}
SECRET_HINTS = ("key", "token", "secret", "password", "passwd", "credential",
                "apikey", "api_key", "auth")

GUARD_KEYWORDS = (
    "confirm", "approve", "approval", "permission", "authorize", "authoriz",
    "sandbox", "allowlist", "whitelist", "allowed", "consent", "ask_user",
    "safe_mode", "dangerously", "is_safe", "require_", "check_permission",
)


@dataclass
class SinkSite:
    repo: str
    path: str
    line: int
    api: str
    effect_kind: str


@dataclass
class RepoScan:
    name: str
    mode: str
    sha: str
    files: int = 0
    parse_errors: int = 0
    loc: int = 0
    sinks: List[SinkSite] = field(default_factory=list)
    sink_by_kind: Counter = field(default_factory=Counter)
    guard_sites: int = 0
    guard_by_kw: Counter = field(default_factory=Counter)

    def summary(self) -> dict:
        return {
            "repo": self.name, "mode": self.mode, "sha": self.sha,
            "files": self.files, "parse_errors": self.parse_errors, "loc": self.loc,
            "sink_sites": len(self.sinks), "sink_by_kind": dict(self.sink_by_kind),
            "guard_sites": self.guard_sites,
            "guard_density_per_sink": round(self.guard_sites / len(self.sinks), 3) if self.sinks else None,
        }


def _mode_str(node: ast.Call) -> str:
    # open(path, mode) or open(path, mode=...)
    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
        return node.args[1].value
    for kw in node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            return kw.value.value
    return ""


def _classify(node: ast.Call) -> Optional[str]:
    dotted = call_name(node)
    if not dotted:
        return None
    parts = dotted.split(".")
    leaf = parts[-1]
    last2 = ".".join(parts[-2:]) if len(parts) >= 2 else dotted

    # exec
    if last2 in EXEC_QUALIFIED or dotted in EXEC_QUALIFIED:
        return KIND_EXEC
    if dotted in ("eval", "exec", "compile") and len(node.args) >= 1:
        return KIND_EXEC
    # delete
    if last2 in DELETE_QUALIFIED or dotted in DELETE_QUALIFIED:
        return KIND_DELETE
    if leaf in DELETE_LEAF:
        return KIND_DELETE
    if leaf == "unlink" and len(parts) >= 2:      # Path(...).unlink()
        return KIND_DELETE
    # send
    if last2 in SEND_QUALIFIED or leaf in SEND_LEAF_ALWAYS:
        return KIND_SEND_EXT
    if leaf in SEND_LEAF and any(m in parts for m in SEND_HINT_MODULES):
        return KIND_SEND_EXT
    # credential: keyring/dotenv always; os.getenv/environ only for secret-like keys
    if last2 in CRED_ALWAYS or dotted in CRED_ALWAYS:
        return KIND_CRED
    if last2 in CRED_QUALIFIED or dotted in CRED_QUALIFIED:
        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            if any(h in node.args[0].value.lower() for h in SECRET_HINTS):
                return KIND_CRED
        return None      # benign config/env read, not a credential sink
    # overwrite
    if dotted == "open" or leaf == "open":
        m = _mode_str(node)
        if any(c in m for c in ("w", "a", "x", "+")):
            return KIND_OVERWRITE
    if leaf in ("write_text", "write_bytes"):
        return KIND_OVERWRITE
    return None


def _is_guard(node) -> Optional[str]:
    name = ""
    if isinstance(node, ast.Call):
        name = call_name(node).split(".")[-1]
    elif isinstance(node, ast.FunctionDef):
        name = node.name
    else:
        return None
    low = name.lower()
    for kw in GUARD_KEYWORDS:
        if kw in low:
            return kw
    return None


def scan_repo(name: str, mode: str, root: str, sha: str) -> RepoScan:
    rs = RepoScan(name=name, mode=mode, sha=sha)
    for dirpath, dirnames, filenames in os.walk(root):
        # skip vendored / vcs / build dirs
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
            rs.loc += src.count("\n") + 1
            try:
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    tree = ast.parse(src)
            except (SyntaxError, ValueError):
                rs.parse_errors += 1
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    k = _classify(node)
                    if k:
                        rs.sinks.append(SinkSite(name, rel, getattr(node, "lineno", 0),
                                                 call_name(node), k))
                        rs.sink_by_kind[k] += 1
                g = _is_guard(node)
                if g:
                    rs.guard_sites += 1
                    rs.guard_by_kw[g] += 1
    return rs
