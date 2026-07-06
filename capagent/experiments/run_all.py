"""Run the full CapAgent evaluation pipeline and emit all artifacts (paper Sec 5-6).

Pipeline (implementation-plan Section 2):
    caprule-miner
      -> contract-extractor + guard-extractor      (scaffolds)
      -> acg-builder -> capagent-translator         (per plan)
      -> matrix-compiler -> capsafe-checker          (per case)
      -> baselines
      -> witness-replayer / report-generator

All numeric artifacts are written under experiments/out/.
"""
from __future__ import annotations

import json
import os
import importlib

import yaml

from .. import dataset as DS
from ..core import ir
from ..core.acg import ACG
from ..tools import caprule_miner as CRM
from ..tools import contract_extractor as CE
from ..tools import guard_extractor as GE
from ..tools import matrix_compiler as MC
from ..tools import capsafe_checker as CK
from ..tools import witness_replayer as WR
from ..tools import baselines as BL
from ..tools import llm_assist as LA
from ..tools import report_generator as RG
from ..tools import translator as TR

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(os.path.dirname(HERE))            # capagent/
POLICY_DIR = os.path.join(BASE, "policy")
OUT = os.path.join(HERE, "out")


def _safe(name: str) -> str:
    return name.replace("/", "__").replace(":", "_")


def _ensure(*paths):
    for p in paths:
        os.makedirs(p, exist_ok=True)


def _write(path: str, text: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def _write_jsonl(path: str, records):
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def run(out_dir: str = OUT) -> dict:
    _ensure(out_dir,
            os.path.join(out_dir, "programs"),
            os.path.join(out_dir, "matrices"),
            os.path.join(out_dir, "domain_specs"),
            os.path.join(out_dir, "certificates"),
            os.path.join(out_dir, "baseline_outputs"),
            os.path.join(out_dir, "acg"),
            os.path.join(out_dir, "tables"))

    log = {}

    # ---- 1. caprule-miner -------------------------------------------------
    log["caprule_miner"] = CRM.write_outputs(POLICY_DIR, out_dir)

    # ---- 2. extraction artifacts (scaffolds) -----------------------------
    all_contracts, all_guards, llm_logs, extraction = [], [], [], []
    for modname in DS.SCAFFOLD_MODULES:
        mod = importlib.import_module(f"capagent.scaffolds.{modname}")
        src = open(mod.__file__, "r", encoding="utf-8").read()
        ce = CE.extract_from_source(src, mod.META["id"])
        ge = GE.extract_from_source(src, mod.META["id"])
        for c in ce.contracts:
            all_contracts.append({
                "project": mod.META["id"], "tool": c.tool, "effect": c.effect_kind,
                "high_impact": c.high_impact, "resource_arg": c.resource_arg,
                "resource_const": c.resource_const, "propagate": c.propagate.mode,
                "source": c.source, "evidence": list(c.evidence), "confidence": c.confidence,
            })
        for u in ce.unresolved:
            all_contracts.append({"project": mod.META["id"], "tool": u["tool"],
                                  "effect": None, "unresolved": True, "reason": u["reason"]})
        for g in ge.guards:
            all_guards.append({"project": mod.META["id"], "site": g.site, "func": g.func,
                               "grant_call": g.grant_call, "cap": g.cap, "evidence": g.evidence})
        llm_logs += LA.summarize_tools(src, mod.META["id"])

    _write_jsonl(os.path.join(out_dir, "tool_contracts.jsonl"), all_contracts)
    _write_jsonl(os.path.join(out_dir, "guards.jsonl"), all_guards)
    _write_jsonl(os.path.join(out_dir, "llm_assist_logs.jsonl"), llm_logs)

    # ---- 3. build cases ---------------------------------------------------
    cases = DS.all_cases()

    # subjects (repos.csv) and issues (issues.csv)
    repo_rows = []
    issue_rows = []
    for c in cases:
        repo_rows.append([c.id, c.subject, c.mode, c.effect_kind, c.family, c.variant, c.expected_safe])
        if c.variant == "buggy":
            issue_rows.append([c.id, c.mode, c.effect_kind, "unsafe", c.pair_id, "has_fixed"])
    _write(os.path.join(out_dir, "repos.csv"),
           RG.to_csv(["case", "subject", "mode", "effect", "family", "variant", "expected_safe"], repo_rows))
    _write(os.path.join(out_dir, "issues.csv"),
           RG.to_csv(["case", "mode", "effect", "impact", "pair_id", "fixed_status"], issue_rows))

    # ACG node/edge dumps (aggregate) + per-scaffold acg json
    acg_node_rows, acg_edge_rows = [], []
    for c in cases:
        if c.acg is not None:
            _write(os.path.join(out_dir, "acg", f"{_safe(c.id)}.json"),
                   json.dumps(c.acg.to_json(), ensure_ascii=False, indent=2))
            for n in c.acg.nodes.values():
                acg_node_rows.append([c.id, n.id, n.kind, n.label, n.tool, n.effect_kind, n.high_impact])
            for e in c.acg.edges:
                acg_edge_rows.append([c.id, e.src, e.dst, e.kind])
    _write(os.path.join(out_dir, "acg_nodes.csv"),
           RG.to_csv(["case", "node", "kind", "label", "tool", "effect", "high_impact"], acg_node_rows))
    _write(os.path.join(out_dir, "acg_edges.csv"),
           RG.to_csv(["case", "src", "dst", "kind"], acg_edge_rows))

    # ---- 4. per-case check + matrix + baselines --------------------------
    records = []
    witnesses_all = []
    for c in cases:
        rep = CK.check(c.program, c.contracts, name=c.id)
        cert = rep.certificate

        # programs/*.capagent
        _write(os.path.join(out_dir, "programs", f"{_safe(c.id)}.capagent"),
               TR.to_capagent_text(c.program))
        # matrices + domain spec
        MC.write_outputs(c.program, c.contracts, out_dir, _safe(c.id))
        # certificate json
        _write(os.path.join(out_dir, "certificates", f"{_safe(c.id)}.json"),
               json.dumps(cert.as_dict(), ensure_ascii=False, indent=2))

        # baselines
        bls = BL.run_all(c.program, c.contracts)
        _write(os.path.join(out_dir, "baseline_outputs", f"{_safe(c.id)}.jsonl"),
               "\n".join(json.dumps({"baseline": k, "safe": v.safe, "warnings": v.warnings},
                                    ensure_ascii=False) for k, v in bls.items()))

        w0 = rep.witnesses[0] if rep.witnesses else None
        for w in rep.witnesses:
            wd = w.as_dict(); wd["case"] = c.id; wd["mode"] = c.mode
            witnesses_all.append(wd)

        rec = {
            "id": c.id, "subject": c.subject, "mode": c.mode, "effect_kind": c.effect_kind,
            "family": c.family, "variant": c.variant, "expected_safe": c.expected_safe,
            "capagent_safe": rep.safe, "matrix_safe": rep.matrix_safe,
            "explicit_matrix_agree": rep.agree,
            "matrix_dim": cert.matrix_dim, "nnz": cert.nnz, "fact_dim": cert.fact_dim,
            "closure_iters": cert.iterations, "check_time_s": cert.check_time_s,
            "missing_capability": w0.missing_capability if w0 else "",
            "sink_site": w0.sink_site if w0 else "",
        }
        for k, v in bls.items():
            rec[f"bl_{k}_safe"] = v.safe
        records.append(rec)

    _write_jsonl(os.path.join(out_dir, "witnesses.jsonl"), witnesses_all)
    _write_jsonl(os.path.join(out_dir, "results.jsonl"), records)

    # manual labels (ground truth)
    _write(os.path.join(out_dir, "manual_labels.csv"),
           RG.to_csv(["case", "variant", "expected_safe", "capagent_safe", "correct"],
                     [[r["id"], r["variant"], r["expected_safe"], r["capagent_safe"],
                       r["expected_safe"] == r["capagent_safe"]] for r in records]))

    # ---- 5. witness-replayer ---------------------------------------------
    pairs = DS.witness_pairs(cases)
    # replay uses each pair's own contract table
    replay_rows = []
    for p in pairs:
        replay_rows += WR.replay([p], p["contracts"])
    _write(os.path.join(out_dir, "witness_replay.csv"),
           RG.to_csv(["pair_id", "mode", "effect", "buggy_rejected", "fixed_accepted",
                      "repair_pattern", "missing_capability", "consistent"],
                     [[r.pair_id, r.mode, r.effect_kind, r.buggy_unsafe, r.fixed_safe,
                       r.repair_pattern, r.missing_capability, r.consistent] for r in replay_rows]))
    _write(os.path.join(out_dir, "fix_consistency.json"),
           json.dumps([r.as_dict() for r in replay_rows], ensure_ascii=False, indent=2))
    _write(os.path.join(out_dir, "before_after.md"), _before_after_md(replay_rows))

    # ---- 6. report-generator: paper tables -------------------------------
    baseline_names = list(BL.BASELINES.keys())
    tables = {}
    tables["table1_extraction_coverage"] = RG.table_extraction_coverage(
        [c.extraction for c in cases if c.acg is not None and c.extraction], )
    # dedupe extraction rows per module
    tables["table1_extraction_coverage"] = RG.table_extraction_coverage(_dedup_extraction(cases))
    tables["table2_3_witness_replay"] = RG.table_replay(replay_rows)
    tables["table4_baseline_comparison"] = RG.table_baseline_comparison(records, baseline_names)
    tables["table5_certificates"] = RG.table_certificates(records)
    tables["table6_new_warnings"] = RG.table_new_warnings(records)

    captions = {
        "table1_extraction_coverage": ("Tool/effect extraction coverage by project.", "tab:coverage"),
        "table2_3_witness_replay": ("Known-bug replay and fixed-version discharge.", "tab:replay"),
        "table4_baseline_comparison": ("Baseline comparison by verdict (positive = flagged unsafe).", "tab:baselines"),
        "table5_certificates": ("Matrix / certificate size and checking time.", "tab:certs"),
        "table6_new_warnings": ("Missing-capability warnings and outcomes.", "tab:warnings"),
    }
    for key, (headers, rows) in tables.items():
        _write(os.path.join(out_dir, "tables", key + ".csv"), RG.to_csv(headers, rows))
        cap, lab = captions.get(key, ("", ""))
        _write(os.path.join(out_dir, "tables", key + ".tex"), RG.to_latex(headers, rows, cap, lab))

    metrics = RG.metric_summary(records, replay_rows, _dedup_extraction(cases))
    _write(os.path.join(out_dir, "metrics_summary.json"),
           json.dumps(metrics, ensure_ascii=False, indent=2))

    # certificate schema
    _write(os.path.join(out_dir, "certificate_schema.json"),
           json.dumps(MC.certificate_schema(), ensure_ascii=False, indent=2))

    # master markdown report
    _write(os.path.join(out_dir, "RESULTS.md"),
           _results_md(metrics, tables, captions, records, baseline_names))

    log.update({
        "cases": len(cases), "scaffold_contracts": len(all_contracts),
        "guards": len(all_guards), "witness_pairs": len(pairs),
        "metrics": metrics,
    })
    return log


def _dedup_extraction(cases):
    seen = {}
    for c in cases:
        if c.extraction:
            seen[c.extraction["module"]] = c.extraction
    return list(seen.values())


def _before_after_md(rows) -> str:
    out = ["# Before / After (witness replay)\n"]
    for r in rows:
        out.append(f"## {r.pair_id} ({r.mode}, {r.effect_kind})")
        out.append(f"- buggy rejected: **{r.buggy_unsafe}**  missing: `{r.missing_capability}`")
        out.append(f"- fixed accepted: **{r.fixed_safe}**  repair pattern: **{r.repair_pattern}**")
        out.append(f"- consistent: **{r.consistent}**\n")
    return "\n".join(out)


def _results_md(metrics, tables, captions, records, baseline_names) -> str:
    from ..tools.report_generator import to_markdown
    out = ["# CapAgent Evaluation Results\n",
           "Auto-generated by `capagent.experiments.run_all`. "
           "All numbers are computed from the synthetic kernels, extracted scaffolds, "
           "security witnesses, and negative controls.\n",
           "## Metric summary (paper Section 5.2)\n"]
    for k, v in metrics.items():
        out.append(f"- **{k}**: {v}")
    out.append("")
    titles = {
        "table1_extraction_coverage": "Table 1. Extraction coverage by project",
        "table2_3_witness_replay": "Table 2/3. Known-bug replay + fixed-version discharge",
        "table4_baseline_comparison": "Table 4. Baseline comparison",
        "table5_certificates": "Table 5. Matrix / certificate size and checking time",
        "table6_new_warnings": "Table 6. Missing-capability warnings",
    }
    for key, (headers, rows) in tables.items():
        out.append(f"\n### {titles.get(key, key)}\n")
        out.append(to_markdown(headers, rows))
    return "\n".join(out)


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, ensure_ascii=False, indent=2))
