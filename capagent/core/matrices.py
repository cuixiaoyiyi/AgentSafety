"""Boolean-semiring matrix compilation, closure, and certificates.

This realizes the linear abstract semantics of Section 4 in its finite-state
(Boolean-semiring) instance, which by Section 5.3 coincides with graph reachability
over the Action-Capability Graph:

* the abstract transition system is compiled to a sparse Boolean adjacency matrix A
  over the basis of reachable abstract states;
* sequential composition is matrix multiplication, nondeterministic choice is
  semiring addition (logical OR), and the loop/whole-program reachability is the
  Kleene closure  A^* = I (+) A (+) A^2 (+) ...  (Section 4.3);
* capability safety is the linear projection  e_BadCap^T (A^* v0) = 0  (Section 4.4).

A certificate (Section 4.6) records the domain, the projection, and the closure
result, and can be re-checked by a verifier that never calls a language model.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple
import time

import numpy as np
import scipy.sparse as sp

from . import ir
from .semantics import Checker, Policy, BADCAP, ONE, State
from .types import ContractTable


@dataclass
class TransitionSystem:
    states: List[State]
    index: Dict[State, int]
    adjacency: sp.csr_matrix          # A[j,i] = 1 iff state i -> state j
    init_vec: np.ndarray              # Boolean indicator of initial states
    bad_mask: np.ndarray              # Boolean indicator of BadCap states
    fact_dim: int                     # |D|, number of abstract facts (vector dimensions)

    @property
    def n(self) -> int:
        return len(self.states)

    @property
    def nnz(self) -> int:
        return int(self.adjacency.nnz)


def build_transition_system(program: ir.Stmt, contracts: ContractTable,
                            policy: Policy = None) -> Tuple[TransitionSystem, Checker]:
    chk = Checker(contracts, policy or Policy(), record_edges=True)
    chk.check(program)

    states = set(chk.init_states)
    for a, b in chk.edges:
        states.add(a); states.add(b)
    states = sorted(states, key=lambda s: (len(s), tuple(sorted(s))))
    index = {s: i for i, s in enumerate(states)}
    n = len(states)

    rows, cols = [], []
    for a, b in chk.edges:
        rows.append(index[b]); cols.append(index[a])   # column-stochastic style: A x
    data = [True] * len(rows)
    A = sp.csr_matrix((data, (rows, cols)), shape=(n, n), dtype=bool) if rows else sp.csr_matrix((n, n), dtype=bool)

    init_vec = np.zeros(n, dtype=bool)
    for s in chk.init_states:
        init_vec[index[s]] = True
    bad_mask = np.array([BADCAP in s for s in states], dtype=bool)

    ts = TransitionSystem(states, index, A, init_vec, bad_mask,
                          fact_dim=len(chk.fact_universe))
    return ts, chk


def _bool_matvec(A: sp.csr_matrix, v: np.ndarray) -> np.ndarray:
    """Boolean semiring matrix-vector product: (Av)_i = OR_j A[i,j] & v_j."""
    if A.shape[1] == 0:
        return v.copy()
    return (A.dot(v.astype(np.int8)) > 0)


def reachable_closure(ts: TransitionSystem):
    """Compute the Kleene closure applied to the initial vector: r = A^* v0.

    Returns (reach_vec, iterations).  This is the least fixed point
    r = v0 (+) A r  in the Boolean semiring (Section 4.3 / 4.4).
    """
    r = ts.init_vec.copy()
    it = 0
    while True:
        it += 1
        nxt = r | _bool_matvec(ts.adjacency, r)
        if np.array_equal(nxt, r):
            break
        r = nxt
    return r, it


@dataclass
class Certificate:
    """A checkable safety/witness certificate (Section 4.6)."""
    safe: bool
    matrix_dim: int
    nnz: int
    fact_dim: int
    iterations: int
    reachable_count: int
    bad_reachable_count: int
    check_time_s: float
    bad_projection_zero: bool

    def as_dict(self) -> dict:
        return {
            "safe": self.safe,
            "matrix_dim": self.matrix_dim,
            "nnz": self.nnz,
            "fact_dim": self.fact_dim,
            "closure_iterations": self.iterations,
            "reachable_states": self.reachable_count,
            "bad_reachable_states": self.bad_reachable_count,
            "check_time_s": round(self.check_time_s, 6),
            "bad_projection_zero": self.bad_projection_zero,
        }


def check_matrix(program: ir.Stmt, contracts: ContractTable,
                 policy: Policy = None) -> Certificate:
    """Matrix-mode capsafe check: build A, compute A^* v0, project onto BadCap."""
    t0 = time.perf_counter()
    ts, _ = build_transition_system(program, contracts, policy)
    reach, iters = reachable_closure(ts)
    # Safety projection: e_BadCap^T (A^* v0) = 0  (Section 4.4).
    bad_reach = reach & ts.bad_mask
    proj_zero = not bool(bad_reach.any())
    dt = time.perf_counter() - t0
    return Certificate(
        safe=proj_zero,
        matrix_dim=ts.n,
        nnz=ts.nnz,
        fact_dim=ts.fact_dim,
        iterations=iters,
        reachable_count=int(reach.sum()),
        bad_reachable_count=int(bad_reach.sum()),
        check_time_s=dt,
        bad_projection_zero=proj_zero,
    )
