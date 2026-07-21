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

### Agent Security Defects

| NO. | Project | Fork | Star | # Misuse (*Fixed) | Confirmed Issue Id | Fixed PR / Commit |
| ---: | --- | ---: | ---: | ---: | --- | --- |
| **Mode 1** | - | - | - | - | - | - |
| 1 | [agno-agi/agno](https://github.com/agno-agi/agno) | 5.6k | 40.9k | 1 (1) | [#8288](https://github.com/agno-agi/agno/issues/8288) | [PR #8289](https://github.com/agno-agi/agno/pull/8289) merged |
| 2 | [TransformerOptimus/SuperAGI](https://github.com/TransformerOptimus/SuperAGI) | 2.2k | 17.6k | 1 (0) | [#1561](https://github.com/TransformerOptimus/SuperAGI/issues/1561) | - |
| 3 | [openinterpreter/openinterpreter](https://github.com/openinterpreter/openinterpreter) | 5.6k | 64.1k | 1 (0) | [GHSA-mj45-wj38-4fmh](https://github.com/openinterpreter/open-interpreter/security/advisories/GHSA-mj45-wj38-4fmh) | Not publicly accessible |
| 4 | [camel-ai/camel](https://github.com/camel-ai/camel) | 2k | 17.2k | 2 (0) | [GHSA-fj6c-h8x4-3m97](https://github.com/camel-ai/camel/security/advisories/GHSA-fj6c-h8x4-3m97), [GHSA-pf8v-vwcx-28gh](https://github.com/camel-ai/camel/security/advisories/GHSA-pf8v-vwcx-28gh) | Not publicly accessible |
| 5 | [chatchat-space/Langchain-Chatchat](https://github.com/chatchat-space/Langchain-Chatchat) | 6.2k | 38.2k | 2 (0) | [#5482](https://github.com/chatchat-space/Langchain-Chatchat/issues/5482), [#5483](https://github.com/chatchat-space/Langchain-Chatchat/issues/5483) | - |
| 6 | [stitionai/devika](https://github.com/stitionai/devika) | 2.6k | 19.5k | 1 (0) | [#716](https://github.com/stitionai/devika/issues/716) | - |
| 7 | [OpenBMB/ChatDev](https://github.com/OpenBMB/ChatDev) | 4.2k | 33.5k | 1 (0) | [#637](https://github.com/OpenBMB/ChatDev/issues/637) | - |
| 8 | [zylon-ai/private-gpt](https://github.com/zylon-ai/private-gpt) | 7.6k | 57.3k | 1 (0) | [#2269](https://github.com/zylon-ai/private-gpt/issues/2269) | - |
| 9 | [FoundationAgents/MetaGPT](https://github.com/FoundationAgents/MetaGPT) | 8.8k | 69k | 1 (0) | [#2064](https://github.com/FoundationAgents/MetaGPT/issues/2064) | - |
| 10 | [microsoft/semantic-kernel](https://github.com/microsoft/semantic-kernel) | 4.6k | 28.1k | 1 (0) | [#14072](https://github.com/microsoft/semantic-kernel/issues/14072) | - |
| 11 | [agiresearch/AIOS](https://github.com/agiresearch/AIOS) | 835 | 6k | 1 (0) | [#549](https://github.com/agiresearch/AIOS/issues/549) | - |
| 12 | [stanfordnlp/dspy](https://github.com/stanfordnlp/dspy) | 3k | 35.3k | 1 (0) | [#9918](https://github.com/stanfordnlp/dspy/issues/9918) | Closed; no public fixing PR/commit found |
| 13 | [sweepai/sweep](https://github.com/sweepai/sweep) | 463 | 7.7k | 1 (0) | [#4177](https://github.com/sweepai/sweep/issues/4177) | - |
| 14 | [zylon-ai/private-gpt](https://github.com/zylon-ai/private-gpt) | 7.6k | 57.3k | 1 (0) | [#2270](https://github.com/zylon-ai/private-gpt/issues/2270) | - |
| 15 | [BerriAI/litellm](https://github.com/BerriAI/litellm) | 9k | 50.8k | 1 (0) | [#30416](https://github.com/BerriAI/litellm/issues/30416) | [PR #31487](https://github.com/BerriAI/litellm/pull/31487) |
| 16 | [openai/swarm](https://github.com/openai/swarm) | 2.3k | 21.7k | 2 (0) | [#97](https://github.com/openai/swarm/issues/97), [#98](https://github.com/openai/swarm/issues/98) | [PR #100](https://github.com/openai/swarm/pull/100) for #98, open PR |
| 17 | [browser-use/browser-use](https://github.com/browser-use/browser-use) | 11.2k | 100k | 1 (0) | [#5041](https://github.com/browser-use/browser-use/issues/5041) | [PR #5077](https://github.com/browser-use/browser-use/pull/5077), open PR |
| 18 | [browser-use/workflow-use](https://github.com/browser-use/workflow-use) | 330 | 4.1k | 1 (0) | [#159](https://github.com/browser-use/workflow-use/issues/159) | - |
| 19 | [SWE-bench/SWE-bench](https://github.com/SWE-bench/SWE-bench) | 902 | 5.2k | 3 (0) | [#600](https://github.com/SWE-bench/SWE-bench/issues/600), [#601](https://github.com/SWE-bench/SWE-bench/issues/601), [#602](https://github.com/SWE-bench/SWE-bench/issues/602) | commit `6a99eb3`, [PR #606](https://github.com/SWE-bench/SWE-bench/pull/606) for #600, open PR; [PR #607](https://github.com/SWE-bench/SWE-bench/pull/607), commit `4635739` for #602; [PR #608](https://github.com/SWE-bench/SWE-bench/pull/608), for #601 | 
| 20 | [OpenHands/OpenHands](https://github.com/OpenHands/OpenHands) | 9.9k | 78.1k | 1 (0) | [#14902](https://github.com/OpenHands/OpenHands/issues/14902) | [PR #14939](https://github.com/OpenHands/OpenHands/pull/14939), open PR |
| 21 | [FoundationAgents/MetaGPT](https://github.com/FoundationAgents/MetaGPT) | 8.8k | 69k | 1 (0) | [#2073](https://github.com/FoundationAgents/MetaGPT/issues/2073) | [PR #31487](https://github.com/BerriAI/litellm/pull/31487) |
| 22 | [agno-agi/agno](https://github.com/agno-agi/agno) | 5.6k | 40.9k | 1 (0) | [#8482](https://github.com/agno-agi/agno/issues/8482) | [PR #8500](https://github.com/agno-agi/agno/pull/8500), open PR |
| 23 | [huggingface/smolagents](https://github.com/huggingface/smolagents) | 2.7k | 28k | 1 (0) | [#2395](https://github.com/huggingface/smolagents/issues/2395) | [PR #2406](https://github.com/huggingface/smolagents/pull/2406), open PR; [PR #2398](https://github.com/huggingface/smolagents/pull/2398), open PR |
| 24 | [stitionai/devika](https://github.com/stitionai/devika) | 2.6k | 19.5k | 1 (0) | [#717](https://github.com/stitionai/devika/issues/717) | - |
| 25 | [letta-ai/letta](https://github.com/letta-ai/letta) | 2.5k | 23.5k | 1 (0) | [#3388](https://github.com/letta-ai/letta/issues/3388) | - |
| 26 | [langchain-ai/langchain-mcp-adapters](https://github.com/langchain-ai/langchain-mcp-adapters) | 448 | 3.6k | 1 (0) | [#551](https://github.com/langchain-ai/langchain-mcp-adapters/issues/551) | - |
| 27 | [run-llama/llama_index](https://github.com/run-llama/llama_index) | 7.6k | 50.4k | 2 (0) | [#22101](https://github.com/run-llama/llama_index/issues/22101), [#22140](https://github.com/run-llama/llama_index/issues/22140) | [PR #22110](https://github.com/run-llama/llama_index/pull/22110), open PR; [PR #22106](https://github.com/run-llama/llama_index/pull/22106), open PR; [PR #22142](https://github.com/run-llama/llama_index/pull/22142), open PR |
| 28 | [agno-agi/agno](https://github.com/agno-agi/agno) | 5.6k | 40.9k | 3 (2) | [#8533](https://github.com/agno-agi/agno/issues/8533), [#8534](https://github.com/agno-agi/agno/issues/8534), [#8535](https://github.com/agno-agi/agno/issues/8535) | [PR #8539](https://github.com/agno-agi/agno/pull/8539) for #8533, merged; [PR #8537](https://github.com/agno-agi/agno/pull/8537) for #8534, merged; [PR #8535](https://github.com/agno-agi/agno/pull/8556)for #8535, Merged|
| 29 | [FoundationAgents/MetaGPT](https://github.com/FoundationAgents/MetaGPT) | 8.8k | 69.1k | 2 (0) | [#2078](https://github.com/FoundationAgents/MetaGPT/issues/2078), [#2079](https://github.com/FoundationAgents/MetaGPT/issues/2079) | - |
| 30 | [langgenius/dify](https://github.com/langgenius/dify) | 23.1k | 147k | 3 (0) | [#37884](https://github.com/langgenius/dify/issues/37884), [#37885](https://github.com/langgenius/dify/issues/37885), [#37886](https://github.com/langgenius/dify/issues/37886) | [PR #37895](https://github.com/langgenius/dify/pull/37895), open PR, fixes #37884/#37885/#37886; [PR #38052](https://github.com/langgenius/dify/pull/38052), open PR, fixes #37885; [PR #38070](https://github.com/langgenius/dify/pull/38070), open PR, fixes #37884/#37886 |
| 31 | [letta-ai/letta](https://github.com/letta-ai/letta) | 2.5k | 23.5k | 1 (0) | [#3390](https://github.com/letta-ai/letta/issues/3390) | - |
| 32 | [FlowiseAI/Flowise](https://github.com/FlowiseAI/Flowise) | 24.6k | 54k | 1 (0) | [#6567](https://github.com/FlowiseAI/Flowise/issues/6567) | [PR #6570](https://github.com/FlowiseAI/Flowise/pull/6570), open PR |
| 33 | [langflow-ai/langflow](https://github.com/langflow-ai/langflow) | 9.3k | 150k | 1 (0) | [#13827](https://github.com/langflow-ai/langflow/issues/13827) | [PR #13849](https://github.com/langflow-ai/langflow/pull/13849), open PR |
| **Total** | - | - | - | **55 (28)** | - | - |
