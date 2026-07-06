"""Command-line entry point exposing each toolchain command (implementation-plan Sec 2).

Usage:
    python -m capagent <command> [args]

Commands:
    caprule-miner            curate effects/rules -> rule_evidence
    contract-extractor FILE  extract tool contracts from a scaffold
    guard-extractor FILE     extract capability grants/guards
    acg-builder FILE PLAN    build an Action-Capability Graph for a plan
    translate FILE PLAN      ACG -> CapAgent IR (prints program.capagent)
    check-kernels            check all policy kernels
    check FILE PLAN          extract+build+translate+check one scaffold plan
    witness-replay           replay all buggy/fixed pairs
    llm-assist FILE          advisory candidate effect labels
    run-all                  run the full evaluation pipeline (emits artifacts)
"""
from __future__ import annotations

import argparse
import json
import os
import sys


def _read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def cmd_caprule_miner(args):
    from .tools import caprule_miner as CRM
    base = os.path.dirname(os.path.abspath(__file__))
    policy = os.path.join(base, "policy")
    out = args.out or os.path.join(base, "experiments", "out")
    print(json.dumps(CRM.write_outputs(policy, out), indent=2))


def cmd_contract_extractor(args):
    from .tools import contract_extractor as CE
    r = CE.extract_from_file(args.file, os.path.basename(args.file))
    for c in r.contracts:
        print(f"{c.tool:24s} {c.effect_kind:12s} high={c.high_impact} "
              f"src={c.source:8s} ev={list(c.evidence)}")
    if r.unresolved:
        print("unresolved:", [u["tool"] for u in r.unresolved])


def cmd_guard_extractor(args):
    from .tools import guard_extractor as GE
    r = GE.extract_from_file(args.file, os.path.basename(args.file))
    for g in r.guards:
        print(f"{g.site:16s} {g.func:20s} {g.grant_call}({g.cap.get('kind')}, region={g.cap.get('region')})")


def cmd_acg_builder(args):
    from .tools import contract_extractor as CE, acg_builder as AB
    src = _read(args.file)
    ct = CE.extract_from_source(src, os.path.basename(args.file)).table()
    acg = AB.build_acg_from_source(src, args.plan, ct)
    print(json.dumps(acg.summary(), indent=2))
    if args.json:
        print(json.dumps(acg.to_json(), indent=2))


def cmd_translate(args):
    from .tools import contract_extractor as CE, acg_builder as AB, translator as TR
    src = _read(args.file)
    ct = CE.extract_from_source(src, os.path.basename(args.file)).table()
    acg = AB.build_acg_from_source(src, args.plan, ct)
    prog = TR.acg_to_ir(acg)
    print(TR.to_capagent_text(prog))


def cmd_check(args):
    from .tools import contract_extractor as CE, acg_builder as AB, translator as TR, capsafe_checker as CK
    src = _read(args.file)
    ct = CE.extract_from_source(src, os.path.basename(args.file)).table()
    acg = AB.build_acg_from_source(src, args.plan, ct)
    prog = TR.acg_to_ir(acg)
    rep = CK.check(prog, ct, name=args.plan)
    print(rep.diagnostic())
    print(f"\n[matrix] dim={rep.certificate.matrix_dim} nnz={rep.certificate.nnz} "
          f"fact_dim={rep.certificate.fact_dim} agree={rep.agree}")


def cmd_check_kernels(args):
    from .kernels import build_kernels
    from .library import standard_contracts
    from .tools import capsafe_checker as CK
    ct = standard_contracts()
    ok = 0
    for k in build_kernels():
        rep = CK.check(k.program, ct, name=k.id)
        good = (rep.safe == k.expected_safe)
        ok += good
        print(f"{'OK' if good else 'XX'} {k.id:20s} "
              f"exp={'safe' if k.expected_safe else 'unsafe':6s} "
              f"got={'safe' if rep.safe else 'unsafe'}")
    print(f"--- {ok}/{len(build_kernels())} correct")


def cmd_witness_replay(args):
    from . import dataset as DS
    from .tools import witness_replayer as WR
    cases = DS.all_cases()
    for p in DS.witness_pairs(cases):
        rows = WR.replay([p], p["contracts"])
        r = rows[0]
        print(f"{r.pair_id:28s} buggy_rejected={r.buggy_unsafe} fixed_accepted={r.fixed_safe} "
              f"repair={r.repair_pattern} consistent={r.consistent}")


def cmd_llm_assist(args):
    from .tools import llm_assist as LA
    for rec in LA.summarize_tools(_read(args.file), os.path.basename(args.file)):
        print(f"{rec['tool']:24s} candidate={rec['candidate_effect']} "
              f"conf={rec['confidence']} accepted={rec['accepted']}")


def cmd_run_all(args):
    from .experiments import run_all as RA
    out = RA.run(args.out) if args.out else RA.run()
    print(json.dumps(out.get("metrics", {}), indent=2))


def cmd_run_real(args):
    from .realeval import run_real as RR
    print(json.dumps(RR.run(), indent=2))


def cmd_scan_repo(args):
    from .realeval import scan as S
    import os as _os
    rs = S.scan_repo(_os.path.basename(args.path.rstrip("/\\")), args.mode or "?", args.path, "-")
    print(json.dumps(rs.summary(), indent=2))


def build_parser():
    p = argparse.ArgumentParser(prog="capagent", description="Capability-safe tool-use checker")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("caprule-miner"); s.add_argument("--out"); s.set_defaults(fn=cmd_caprule_miner)
    s = sub.add_parser("contract-extractor"); s.add_argument("file"); s.set_defaults(fn=cmd_contract_extractor)
    s = sub.add_parser("guard-extractor"); s.add_argument("file"); s.set_defaults(fn=cmd_guard_extractor)
    s = sub.add_parser("acg-builder"); s.add_argument("file"); s.add_argument("plan"); s.add_argument("--json", action="store_true"); s.set_defaults(fn=cmd_acg_builder)
    s = sub.add_parser("translate"); s.add_argument("file"); s.add_argument("plan"); s.set_defaults(fn=cmd_translate)
    s = sub.add_parser("check"); s.add_argument("file"); s.add_argument("plan"); s.set_defaults(fn=cmd_check)
    s = sub.add_parser("check-kernels"); s.set_defaults(fn=cmd_check_kernels)
    s = sub.add_parser("witness-replay"); s.set_defaults(fn=cmd_witness_replay)
    s = sub.add_parser("llm-assist"); s.add_argument("file"); s.set_defaults(fn=cmd_llm_assist)
    s = sub.add_parser("run-all"); s.add_argument("--out"); s.set_defaults(fn=cmd_run_all)
    s = sub.add_parser("run-real"); s.set_defaults(fn=cmd_run_real)
    s = sub.add_parser("scan-repo"); s.add_argument("path"); s.add_argument("--mode"); s.set_defaults(fn=cmd_scan_repo)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
