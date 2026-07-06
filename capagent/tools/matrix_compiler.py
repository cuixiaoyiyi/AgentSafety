"""matrix-compiler: compile CapAgent IR into semiring-valued transformers (plan Sec 1.6).

Emits, for a program: a ``domain_spec`` (abstract vector dimensions + the derived
bad predicate), the sparse Boolean transition matrix (``matrices/*.npz``), the
bad-state projection vector, and a ``certificate_schema``.  Default semantics is the
Boolean semiring; sequential composition is matrix multiplication, choice is
addition, loops are closure (paper Section 4.3, Definition 11).
"""
from __future__ import annotations

import json
import os

import numpy as np
import scipy.sparse as sp

from ..core import matrices as M
from ..core.semantics import Policy, BADCAP
from ..core.types import ContractTable
from ..core import ir


def compile_program(program: ir.Stmt, contracts: ContractTable, policy: Policy = None):
    ts, chk = M.build_transition_system(program, contracts, policy or Policy())
    domain_spec = {
        "vector_dimensions": list(chk.fact_universe),
        "fact_dim": len(chk.fact_universe),
        "bad_predicate": BADCAP,
        "state_basis_dim": ts.n,
        "primitive_transitions": ts.nnz,
        "semiring": "Boolean",
    }
    return ts, domain_spec


def write_outputs(program, contracts, out_dir, name, policy=None):
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(os.path.join(out_dir, "matrices"), exist_ok=True)
    os.makedirs(os.path.join(out_dir, "domain_specs"), exist_ok=True)
    ts, domain_spec = compile_program(program, contracts, policy)

    # matrices/<name>.npz : the sparse Boolean adjacency (primitive transformer sum).
    sp.save_npz(os.path.join(out_dir, "matrices", f"{name}.npz"),
                ts.adjacency.astype(np.int8).tocsr())
    with open(os.path.join(out_dir, "domain_specs", f"{name}.yaml"), "w", encoding="utf-8") as f:
        import yaml
        yaml.safe_dump(domain_spec, f, sort_keys=False, allow_unicode=True)

    bad_proj = {
        "bad_predicate": BADCAP,
        "bad_states": [i for i, b in enumerate(ts.bad_mask) if b],
        "init_states": [i for i, b in enumerate(ts.init_vec) if b],
    }
    return ts, domain_spec, bad_proj


CERTIFICATE_SCHEMA = {
    "type": "object",
    "properties": {
        "safe": {"type": "boolean"},
        "matrix_dim": {"type": "integer"},
        "nnz": {"type": "integer"},
        "fact_dim": {"type": "integer"},
        "closure_iterations": {"type": "integer"},
        "bad_projection_zero": {"type": "boolean"},
        "check_time_s": {"type": "number"},
    },
    "required": ["safe", "matrix_dim", "bad_projection_zero"],
}


def certificate_schema() -> dict:
    return CERTIFICATE_SCHEMA
