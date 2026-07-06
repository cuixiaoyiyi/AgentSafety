"""Manually-curated security witnesses grounded in real sink locations (Milestone 5).

Each witness encodes a *well-known capability-safety property* of the corresponding
framework as a buggy/fixed lambda_cap pair, with its ``evidence`` set to an actual
high-impact sink location discovered by the scanner in the pinned checkout.  This is
the plan's Milestone 2 ("encode known issue witnesses manually") applied to real code:
the checker's job is to reject the buggy path with the exact missing capability and
accept the repaired path.  We do NOT claim these are auto-discovered defects.
"""
from __future__ import annotations

from typing import List, Optional

from ..core import ir
from ..core.ir import seq, ToolCall as T, Require, MemRead
from ..core.types import KIND_EXEC, KIND_MOD_HARNESS, KIND_DELEGATE, KIND_CRED
from .. import library as lib
from .scan import RepoScan, SinkSite


_PERIPHERAL_DIRS = {"tests", "test", "examples", "example", "scripts", "script",
                    "docs", "doc", "benchmark", "benchmarks", ".codex", "vendor",
                    "demos", ".devcontainer", "sandbox_smoketests", "cookbook",
                    "cookbooks", "ci_cd", "ci", "dev", "notebooks", "tutorials",
                    "recipes", "evals"}


def _is_peripheral(path: str) -> bool:
    segs = path.lower().split("/")
    fname = segs[-1]
    if fname == "setup.py" or fname.startswith("test_") or fname.endswith("_test.py") \
            or "conftest" in fname:
        return True
    return any(seg in _PERIPHERAL_DIRS for seg in segs[:-1])


def _rank(sinks: List[SinkSite]) -> List[SinkSite]:
    """Prefer sinks in core package code over setup/test/example/script/vendor files."""
    def score(s: SinkSite):
        return (1 if _is_peripheral(s.path) else 0, s.path.lower().count("/"), s.line)
    return sorted(sinks, key=score)


def _first_sink(scan: RepoScan, kind: str, path_hint: Optional[str] = None) -> Optional[SinkSite]:
    cands = [s for s in scan.sinks if s.effect_kind == kind]
    if not cands:
        return None
    if path_hint:
        pref = [s for s in cands if path_hint in s.path.lower()]
        if pref:
            return _rank(pref)[0]
    return _rank(cands)[0]


def _site(s: Optional[SinkSite]) -> str:
    return f"{s.repo}/{s.path}:{s.line}" if s else "n/a"


def build_for(scan: RepoScan) -> List[dict]:
    """Return grounded witness pairs for one repository scan."""
    out = []

    def add(pair_id, effect_kind, prop, evidence, buggy, fixed, repair):
        out.append({
            "pair_id": pair_id, "repo": scan.name, "mode": scan.mode,
            "effect_kind": effect_kind, "property": prop, "evidence_site": evidence,
            "buggy": buggy, "fixed": fixed, "repair_pattern": repair,
            "contracts": lib.standard_contracts(),
        })

    # ---- Exec of model-generated code without confirmation/sandbox --------
    ex = _first_sink(scan, KIND_EXEC)
    if ex is not None:
        site = _site(ex)
        buggy = seq(
            MemRead(var="cmd", key="model_output", untrusted=True, site=site),
            T(tool="shell_exec", args=("cmd",), site=site),
        )
        fixed = seq(
            MemRead(var="cmd", key="model_output", untrusted=True, site=site),
            T(tool="validate_provenance", args=("cmd",), result="cmd2", site=site),
            Require(cap=lib.cap_exec_trusted(), capvar="c", site=site),
            T(tool="shell_exec", args=("cmd2",), site=site),
        )
        add(f"{scan.name}:exec-untrusted", KIND_EXEC,
            "model-generated command executed without a trusted/sandboxed exec capability",
            site, buggy, fixed, "provenance")

    # ---- Harness / test-path patch overlap (SWE-bench style) -------------
    if scan.mode == "M3":
        hp = _first_sink(scan, "Overwrite", path_hint="test") or _first_sink(scan, "Overwrite")
        site = _site(hp)
        buggy = seq(
            Require(cap=lib.cap_modrepo_task(), capvar="c", site=site),
            T(tool="apply_patch_harness", args=("harness/test_patch",), site=site),
        )
        fixed = seq(
            Require(cap=lib.cap_modrepo_task(), capvar="c", site=site),
            T(tool="apply_patch", args=("task/module",), site=site),
        )
        add(f"{scan.name}:harness-overlap", KIND_MOD_HARNESS,
            "agent patch may overlap harness/oracle paths while holding only a task-write capability",
            site, buggy, fixed, "scope")

    # ---- Role delegation from untrusted content (MetaGPT style) ----------
    if scan.mode == "M2":
        de = _first_sink(scan, KIND_EXEC) or _first_sink(scan, "Overwrite")
        site = _site(de)
        buggy = seq(
            MemRead(var="task", key="peer_message", untrusted=True, site=site),
            T(tool="dispatch", args=("engineer", "task"), site=site),
        )
        fixed = seq(
            MemRead(var="task", key="peer_message", untrusted=True, site=site),
            T(tool="validate_provenance", args=("task",), result="task2", site=site),
            Require(cap=lib.cap_delegate("engineer"), capvar="c", site=site),
            T(tool="dispatch", args=("engineer", "task2"), site=site),
        )
        add(f"{scan.name}:delegate-untrusted", KIND_DELEGATE,
            "high-privilege role invoked from untrusted peer content without a delegation capability",
            site, buggy, fixed, "provenance")

    # ---- Credential read without capability (thin-bridge style) ----------
    if not scan.sink_by_kind.get(KIND_EXEC) and scan.sink_by_kind.get(KIND_CRED):
        cr = _first_sink(scan, KIND_CRED)
        site = _site(cr)
        buggy = T(tool="read_credential", args=("api_key",), site=site)
        fixed = seq(
            Require(cap=_cap_cred(), capvar="c", site=site),
            T(tool="read_credential", args=("api_key",), site=site),
        )
        add(f"{scan.name}:cred-access", KIND_CRED,
            "credential/secret read without an explicit credential capability",
            site, buggy, fixed, "guard")

    return out


def _cap_cred():
    from ..core.types import Capability, Region, KIND_CRED as K
    return Capability(K, region=Region.of("api_key"))


def build_all(scans: List[RepoScan]) -> List[dict]:
    out = []
    for s in scans:
        out += build_for(s)
    return out
