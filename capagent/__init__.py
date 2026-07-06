"""CapAgent: a prototype checker for capability-safe tool use in agentic programs.

This package implements the toolchain described in ``capagent_implementation_plan.md``
and the formal semantics of the paper *Capability-Safe Tool Use in Agentic Programs*
(the small language lambda_cap, its linear/Boolean-semiring abstract semantics, and
Action-Capability Graphs).

Module map
----------
core.types      Effects, capabilities, regions, tool contracts, matching.
core.ir         lambda_cap abstract syntax (the CapAgent IR).
core.domain     Property-directed abstract domain (facts) via policy completion.
core.transfer   Monotone-Boolean transfer functions for primitive actions.
core.checker    capsafe checker: linear/join semantics + disjunctive witness search.
core.matrices   Boolean-semiring sparse-matrix compilation and certificates.
core.acg        Action-Capability Graph structures.

tools.*         The command-line toolchain (caprule-miner, contract-extractor,
                guard-extractor, acg-builder, capagent-translator, matrix-compiler,
                capsafe-checker, witness-replayer, report-generator, llm-assist).
"""

__version__ = "0.1.0"
