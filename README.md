# AgentSafety
A core calculus for capability-safe agentic programs. 

**Program Language**

# CapAgent

A prototype checker for **capability-safe tool use** in tool-using agentic programs,
implementing the toolchain of capagent and the formal
semantics of the paper *Capability-Safe Tool Use in Agentic Programs* (the
language `lambda_cap`, its Boolean-semiring linear abstract semantics, and
Action-Capability Graphs).

> Target property : *a tool-using agent should not perform a
> high-impact tool effect unless the current abstract state contains a matching
> capability for the effect kind, resource scope, and provenance requirement.*

## Install

```bash
pip install -r requirements.txt          # numpy scipy networkx pyyaml pandas
```

## Run the whole evaluation

```bash
python -m capagent run-all                # emits capagent/experiments/out/*
python tests/test_capagent.py             # 7 validation tests
```

Artifacts land in `capagent/experiments/out/` (see `RESULTS.md`, `metrics_summary.json`,
and `tables/`).

## Toolchain 

| Command | Module | Role |
|---|---|---|
| `caprule-miner` | `tools/caprule_miner.py` | curate `effects.yaml` + `capability_rules.yaml` (+ evidence) |
| `contract-extractor` | `tools/contract_extractor.py` | infer tool effect contracts from scaffold `ast` |
| `guard-extractor` | `tools/guard_extractor.py` | extract capability grants / guards |
| `acg-builder` | `tools/acg_builder.py` | build the Action-Capability Graph |
| `translate` | `tools/translator.py` | ACG -> CapAgent IR (`program.capagent`) |
| `matrix-compiler` | `tools/matrix_compiler.py` | Boolean-semiring matrices + domain spec + certificate schema |
| `capsafe-checker` | `tools/capsafe_checker.py` | explicit-state + matrix check, witnesses, diagnostics |
| `witness-replayer` | `tools/witness_replayer.py` | replay buggy/fixed pairs, classify repair pattern |
| `report-generator` | `tools/report_generator.py` | CSV / Markdown / LaTeX tables + metrics |
| `llm-assist` | `tools/llm_assist.py` | *optional*, offline, advisory candidate labels (untrusted) |

The **deterministic core** (`core/`) — IR, abstract domain, checker, matrices — never
calls a language model. `llm-assist` is bounded, offline, and its output is marked
`accepted=False`; it is never part of the trusted verification base.

## Formal core (`core/`)

* `types.py` — Effects, Capabilities, Regions, ToolContracts, `Match` (Defs 1-3, 9).
* `ir.py` — `lambda_cap` abstract syntax + textual `.capagent` surface form.
* `semantics.py` — abstract domain (facts), `Policy` (`High`, `HasReq`), and the
  explicit-state capsafe checker (Defs 5-8; prefix property).
* `matrices.py` — Boolean-semiring transition matrices, Kleene closure, and the
  linear safety projection `e_BadCap^T (A^* v0) = 0` (Section 4.4) with certificates.
* `acg.py` — Action-Capability Graph structures (Section 5.1).

Explicit-state and matrix checks are cross-validated to agree on every case
(paper Section 5.3: graph reachability = the Boolean matrix fixed point).

## Individual commands

```bash
python -m capagent contract-extractor capagent/scaffolds/doc_agent.py
python -m capagent guard-extractor     capagent/scaffolds/swe_agent.py
python -m capagent acg-builder         capagent/scaffolds/manager_agent.py plan_exec_buggy
python -m capagent translate           capagent/scaffolds/manager_agent.py plan_exec_fixed
python -m capagent check               capagent/scaffolds/manager_agent.py plan_exec_buggy
python -m capagent check-kernels
python -m capagent witness-replay
python -m capagent llm-assist          capagent/scaffolds/doc_agent.py
```

## Real repositories

```bash
python -m capagent run-real        # scan pinned real repos + replay grounded witnesses
python -m capagent scan-repo <path> --mode M1
```

Pinned subjects (shallow-cloned into `capagent/realeval/_repos/`, gitignored): **open-interpreter**
, **smolagents** , **SWE-bench** , **MetaGPT** , **langchain-mcp-adapters** .
The scanner produces an automated high-impact **sink & guard inventory** over ~1.2k files /
180k LOC ; security witnesses are manually-curated capability-safety properties encoded
as `lambda_cap` pairs and *grounded* in real sink locations. Results and
scope in `capagent/experiments/out_real/REAL_REPORT.md`.

## Scope of the guarantee

Under sound contracts and sound extraction, a `SAFE` verdict means no represented
execution performs a high-impact effect (delete / overwrite / send / exec / patch /
harness / verdict / memory-instruction / delegation) without a matching capability.
It does **not** prove task correctness, intent understanding, or model alignment
(paper Section 8.1).
