"""report-generator: reproducible tables for the paper (plan Sec 1.10, paper Sec 6.4).

Pure functions over collected results; each returns (rows, headers) that are rendered
to CSV / Markdown / LaTeX.  Produces the six planned paper tables plus the metric
summary of Section 5.2 (replay rate, discharge rate, coverage, matrix size, time,
diagnostic quality) and the baseline confusion matrices of Section 5.1.
"""
from __future__ import annotations

from typing import Dict, List, Tuple


# --------------------------------------------------------------------------
# rendering helpers
# --------------------------------------------------------------------------
def to_csv(headers: List[str], rows: List[list]) -> str:
    import csv, io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(headers)
    for r in rows:
        w.writerow(r)
    return buf.getvalue()


def to_markdown(headers: List[str], rows: List[list]) -> str:
    out = ["| " + " | ".join(str(h) for h in headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out)


def to_latex(headers: List[str], rows: List[list], caption: str = "", label: str = "") -> str:
    cols = "l" * len(headers)
    lines = [r"\begin{table}[t]", r"\centering",
             r"\begin{tabular}{" + cols + "}", r"\toprule",
             " & ".join(_tex(str(h)) for h in headers) + r" \\", r"\midrule"]
    for r in rows:
        lines.append(" & ".join(_tex(str(c)) for c in r) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    if caption:
        lines.append(r"\caption{" + _tex(caption) + "}")
    if label:
        lines.append(r"\label{" + label + "}")
    lines.append(r"\end{table}")
    return "\n".join(lines)


def _tex(s: str) -> str:
    return s.replace("_", r"\_").replace("%", r"\%").replace("&", r"\&")


# --------------------------------------------------------------------------
# confusion matrix (positive = "flagged unsafe")
# --------------------------------------------------------------------------
def confusion(records: List[dict], verdict_key: str) -> dict:
    tp = fp = tn = fn = 0
    for r in records:
        gt_unsafe = not r["expected_safe"]
        flagged_unsafe = not r[verdict_key]
        if gt_unsafe and flagged_unsafe:
            tp += 1
        elif (not gt_unsafe) and flagged_unsafe:
            fp += 1
        elif (not gt_unsafe) and (not flagged_unsafe):
            tn += 1
        else:
            fn += 1
    prec = tp / (tp + fp) if (tp + fp) else 1.0
    rec = tp / (tp + fn) if (tp + fn) else 1.0
    acc = (tp + tn) / len(records) if records else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(prec, 3), "recall": round(rec, 3), "accuracy": round(acc, 3)}


# --------------------------------------------------------------------------
# Table 1: extraction coverage by project
# --------------------------------------------------------------------------
def table_extraction_coverage(extraction: List[dict]) -> Tuple[List[str], List[list]]:
    headers = ["project", "tools", "sinks", "resolved", "unresolved",
               "guards", "acg_warnings", "contract_coverage"]
    rows = []
    for e in extraction:
        total = e["tools"] + e["unresolved"]
        cov = e["tools"] / total if total else 1.0
        rows.append([e["module"], e["tools"], e["sinks"], e["tools"], e["unresolved"],
                     e["guards"], e["warnings"], f"{cov:.0%}"])
    return headers, rows


# --------------------------------------------------------------------------
# Table 2/3: witness replay + fixed-version discharge
# --------------------------------------------------------------------------
def table_replay(rows_in) -> Tuple[List[str], List[list]]:
    headers = ["pair_id", "mode", "effect", "buggy_rejected", "fixed_accepted",
               "repair_pattern", "missing_capability", "consistent"]
    rows = []
    for r in rows_in:
        rows.append([r.pair_id, r.mode, r.effect_kind, r.buggy_unsafe, r.fixed_safe,
                     r.repair_pattern, r.missing_capability, r.consistent])
    return headers, rows


# --------------------------------------------------------------------------
# Table 4: baseline comparison
# --------------------------------------------------------------------------
def table_baseline_comparison(records: List[dict], baseline_names: List[str]) -> Tuple[List[str], List[list]]:
    headers = ["method", "tp", "fp", "fn", "tn", "precision", "recall", "accuracy", "expected_limitation"]
    limits = {
        "CapAgent": "target method (effect+resource+provenance)",
        "sink_only": "over-reports; no authorization notion",
        "allowlist": "ignores resource and provenance",
        "guard_dominator": "coarse scoped capabilities",
        "generic_reach": "kind-only; no scope/label/provenance",
        "taint_to_sink": "misses pure-authorization bugs",
    }
    rows = []
    for name in ["CapAgent"] + baseline_names:
        key = "capagent_safe" if name == "CapAgent" else f"bl_{name}_safe"
        cm = confusion(records, key)
        rows.append([name, cm["tp"], cm["fp"], cm["fn"], cm["tn"],
                     cm["precision"], cm["recall"], cm["accuracy"], limits.get(name, "")])
    return headers, rows


# --------------------------------------------------------------------------
# Table 5: matrix / certificate size and checking time
# --------------------------------------------------------------------------
def table_certificates(records: List[dict]) -> Tuple[List[str], List[list]]:
    headers = ["case", "subject", "matrix_dim", "nnz", "fact_dim",
               "closure_iters", "check_time_ms", "safe"]
    rows = []
    for r in records:
        rows.append([r["id"], r["subject"], r["matrix_dim"], r["nnz"], r["fact_dim"],
                     r["closure_iters"], round(r["check_time_s"] * 1000, 3), r["capagent_safe"]])
    return headers, rows


# --------------------------------------------------------------------------
# Table 6: new warnings / outcomes
# --------------------------------------------------------------------------
def table_new_warnings(records: List[dict]) -> Tuple[List[str], List[list]]:
    headers = ["case", "mode", "effect", "missing_capability", "sink_site", "status", "maintainer_outcome"]
    rows = []
    for r in records:
        if not r["capagent_safe"]:
            rows.append([r["id"], r["mode"], r["effect_kind"], r["missing_capability"],
                         r["sink_site"], "unsafe", "synthetic-dataset"])
    return headers, rows


# --------------------------------------------------------------------------
# metric summary (Section 5.2)
# --------------------------------------------------------------------------
def metric_summary(records: List[dict], replay_rows, extraction: List[dict]) -> dict:
    buggy = [r for r in records if not r["expected_safe"]]
    replayed = sum(1 for r in buggy if not r["capagent_safe"])
    fixed = [r for r in records if r["expected_safe"] and r["variant"] == "fixed"]
    discharged = sum(1 for r in fixed if r["capagent_safe"])
    tot_tools = sum(e["tools"] + e["unresolved"] for e in extraction)
    res_tools = sum(e["tools"] for e in extraction)
    diag_ok = sum(1 for r in records if (not r["capagent_safe"]) and r["missing_capability"]
                  and r["sink_site"])
    n_unsafe = sum(1 for r in records if not r["capagent_safe"])
    agree = sum(1 for r in records if r["explicit_matrix_agree"])
    return {
        "cases_total": len(records),
        "buggy_cases": len(buggy),
        "known_bug_replay_rate": round(replayed / len(buggy), 3) if buggy else None,
        "fixed_versions": len(fixed),
        "fixed_version_discharge_rate": round(discharged / len(fixed), 3) if fixed else None,
        "contract_extraction_coverage": round(res_tools / tot_tools, 3) if tot_tools else None,
        "controls_total": sum(1 for r in records if r["variant"] == "control"),
        "controls_false_rejections": sum(1 for r in records if r["variant"] == "control" and not r["capagent_safe"]),
        "diagnostic_quality": round(diag_ok / n_unsafe, 3) if n_unsafe else None,
        "explicit_matrix_agreement": round(agree / len(records), 3) if records else None,
        "matrix_dim_max": max((r["matrix_dim"] for r in records), default=0),
        "check_time_total_ms": round(sum(r["check_time_s"] for r in records) * 1000, 3),
    }
