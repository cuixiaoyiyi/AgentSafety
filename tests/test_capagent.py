"""Test suite validating the CapAgent formal core and toolchain.

Run: python -m pytest -q     (or: python tests/test_capagent.py)
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from capagent.kernels import build_kernels
from capagent.library import standard_contracts
from capagent.core.semantics import Checker, Policy
from capagent.core.matrices import check_matrix
from capagent import dataset as DS
from capagent.tools import baselines as BL
from capagent.tools import witness_replayer as WR


def test_kernels_classified_correctly():
    ct = standard_contracts()
    for k in build_kernels():
        r = Checker(ct, Policy()).check(k.program)
        assert r.safe == k.expected_safe, f"{k.id}: expected {k.expected_safe} got {r.safe}"


def test_matrix_agrees_with_explicit():
    ct = standard_contracts()
    for k in build_kernels():
        r = Checker(ct, Policy()).check(k.program)
        cert = check_matrix(k.program, ct, Policy())
        assert r.safe == cert.safe, f"{k.id}: explicit {r.safe} vs matrix {cert.safe}"


def test_witnesses_name_missing_capability():
    ct = standard_contracts()
    for k in build_kernels():
        if k.expected_safe:
            continue
        r = Checker(ct, Policy()).check(k.program)
        assert r.witnesses, f"{k.id}: no witness for unsafe program"
        w = r.witnesses[0]
        assert w.missing_capability and w.effect and w.sink_site


def test_extraction_pipeline_classifies_scaffolds():
    cases = DS.scaffold_cases()
    assert cases
    for c in cases:
        r = Checker(c.contracts, Policy()).check(c.program)
        assert r.safe == c.expected_safe, f"{c.id}: expected {c.expected_safe} got {r.safe}"


def test_negative_controls_not_rejected():
    for c in DS.all_cases():
        if c.variant == "control":
            r = Checker(c.contracts, Policy()).check(c.program)
            assert r.safe, f"control {c.id} was falsely rejected"


def test_witness_replay_consistent():
    cases = DS.all_cases()
    for p in DS.witness_pairs(cases):
        rows = WR.replay([p], p["contracts"])
        r = rows[0]
        assert r.consistent, f"{r.pair_id}: buggy_rejected={r.buggy_unsafe} fixed_accepted={r.fixed_safe}"


def test_capagent_beats_baselines_on_precision():
    """CapAgent should have no false positives/negatives; baselines should be worse."""
    cases = DS.all_cases()
    cap_errors = 0
    baseline_errors = {n: 0 for n in BL.BASELINES}
    for c in cases:
        r = Checker(c.contracts, Policy()).check(c.program)
        cap_errors += (r.safe != c.expected_safe)
        for name, outcome in BL.run_all(c.program, c.contracts).items():
            baseline_errors[name] += (outcome.safe != c.expected_safe)
    assert cap_errors == 0
    # every baseline should make strictly more mistakes than CapAgent
    for name, errs in baseline_errors.items():
        assert errs > cap_errors, f"baseline {name} unexpectedly matched CapAgent"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL {fn.__name__}: {e}")
    print(f"--- {passed}/{len(fns)} tests passed")
