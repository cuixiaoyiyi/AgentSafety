# CapAgent — Real-Repository Evaluation (Milestone 5)

Pinned real agent frameworks, spanning the plan's M1-M4 families. Regenerate with:

```bash
python -m capagent.realeval.run_real
```

## Pinned subjects

| repo | mode | commit | commit_date | files | loc | sinks | guards |
|---|---|---|---|---|---|---|---|
| open-interpreter | M1 | ac1b565c72 | 2026-06-19 | 134 | 36765 | 172 | 125 |
| smolagents | M3 | 526069c1ea | 2026-06-16 | 75 | 30683 | 51 | 25 |
| SWE-bench | M3 | f7bbbb2ccd | 2026-03-18 | 89 | 17667 | 88 | 3 |
| MetaGPT | M2 | 11cdf466d0 | 2026-01-21 | 890 | 89755 | 205 | 6 |
| langchain-mcp-adapters | M4 | 6a10b83516 | 2026-06-19 | 26 | 5187 | 0 | 0 |
| agno | M1 | 3138e34b98 | 2026-07-02 | 4051 | 789958 | 1267 | 1079 |
| dspy | M2 | 498760149b | 2026-06-16 | 260 | 63112 | 63 | 78 |
| browser-use | M2 | 18484f23ac | 2026-07-02 | 362 | 106049 | 216 | 311 |
| OpenHands | M3 | ae5b8a995d | 2026-07-02 | 876 | 222004 | 235 | 1115 |
| litellm | M2 | b96f1aa686 | 2026-07-02 | 4649 | 1658988 | 1764 | 1630 |
| swarm | M2 | 6af0b4caf3 | 2026-04-15 | 62 | 3786 | 3 | 0 |
| private-gpt | M1 | 603152a62a | 2026-06-29 | 712 | 117213 | 74 | 42 |
| letta | M4 | 6d8cb7fd48 | 2026-06-25 | 878 | 249295 | 223 | 713 |
| SuperAGI | M1 | c3c1982e7b | 2025-01-22 | 461 | 33024 | 99 | 32 |
| AIOS | M2 | 4171a8ea2d | 2026-06-22 | 152 | 28327 | 123 | 0 |
| dify | M4 | dcc06dee20 | 2026-07-02 | 3508 | 832158 | 272 | 1954 |

## RQ2 — high-impact sink & guard inventory (automated)

| repo | mode | commit | files | loc | sinks | Exec | Overwrite | Delete | SendExt | CredAccess | guards | guard_density_per_sink |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| open-interpreter | M1 | ac1b565c72 | 134 | 36765 | 172 | 62 | 66 | 32 | 9 | 3 | 125 | 0.727 |
| smolagents | M3 | 526069c1ea | 75 | 30683 | 51 | 13 | 12 | 7 | 4 | 15 | 25 | 0.49 |
| SWE-bench | M3 | f7bbbb2ccd | 89 | 17667 | 88 | 34 | 37 | 5 | 0 | 12 | 3 | 0.034 |
| MetaGPT | M2 | 11cdf466d0 | 890 | 89755 | 205 | 42 | 97 | 47 | 16 | 3 | 6 | 0.029 |
| langchain-mcp-adapters | M4 | 6a10b83516 | 26 | 5187 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | None |
| agno | M1 | 3138e34b98 | 4051 | 789958 | 1267 | 25 | 439 | 114 | 574 | 115 | 1079 | 0.852 |
| dspy | M2 | 498760149b | 260 | 63112 | 63 | 7 | 44 | 4 | 5 | 3 | 78 | 1.238 |
| browser-use | M2 | 18484f23ac | 362 | 106049 | 216 | 16 | 63 | 18 | 21 | 98 | 311 | 1.44 |
| OpenHands | M3 | ae5b8a995d | 876 | 222004 | 235 | 9 | 27 | 13 | 119 | 67 | 1115 | 4.745 |
| litellm | M2 | b96f1aa686 | 4649 | 1658988 | 1764 | 77 | 176 | 51 | 697 | 763 | 1630 | 0.924 |
| swarm | M2 | 6af0b4caf3 | 62 | 3786 | 3 | 0 | 3 | 0 | 0 | 0 | 0 | 0.0 |
| private-gpt | M1 | 603152a62a | 712 | 117213 | 74 | 15 | 30 | 19 | 9 | 1 | 42 | 0.568 |
| letta | M4 | 6d8cb7fd48 | 878 | 249295 | 223 | 32 | 20 | 21 | 89 | 61 | 713 | 3.197 |
| SuperAGI | M1 | c3c1982e7b | 461 | 33024 | 99 | 26 | 19 | 12 | 42 | 0 | 32 | 0.323 |
| AIOS | M2 | 4171a8ea2d | 152 | 28327 | 123 | 33 | 48 | 6 | 32 | 4 | 0 | 0.0 |
| dify | M4 | dcc06dee20 | 3508 | 832158 | 272 | 19 | 117 | 12 | 95 | 29 | 1954 | 7.184 |

**Aggregate sinks by effect kind:** Exec=410, Overwrite=1198, Delete=361, SendExt=1712, CredAccess=1174

Total: **4855 high-impact sink sites** across **17185 files / 4,283,971 LOC**, **7113 guard sites** (1 files unparsed).

Guard density varies by two orders of magnitude across frameworks — a direct, automated observation that high-impact effects are pervasive and unevenly mediated.


## RQ3 (automated) — tool-registry ACG adapter

For frameworks with a discoverable tool registry (`@tool`, `@register_tool`, or `Tool` subclasses), the adapter extracts every registered tool, classifies its effect, builds an ACG in which the model may call any registered tool, and checks it. `unguarded_reachable` counts registered high-impact tools reachable from a model choice with **no capability requirement attached in the registry**.

| repo | mode | registry_tools | high_impact_tools | unguarded_reachable | flagged_kinds | module_guard_hint_frac |
|---|---|---|---|---|---|---|
| open-interpreter | M1 | 0 | 0 | 0 |  | None |
| smolagents | M3 | 80 | 15 | 13 | CredAccess=12;Exec=1 | 0.0 |
| SWE-bench | M3 | 0 | 0 | 0 |  | None |
| MetaGPT | M2 | 45 | 7 | 7 | Overwrite=6;CredAccess=1 | 0.0 |
| langchain-mcp-adapters | M4 | 10 | 0 | 0 |  | None |
| agno | M1 | 298 | 33 | 24 | Overwrite=2;CredAccess=16;Exec=3;Delete=3 | 0.364 |
| dspy | M2 | 6 | 0 | 0 |  | None |
| browser-use | M2 | 0 | 0 | 0 |  | None |
| OpenHands | M3 | 0 | 0 | 0 |  | None |
| litellm | M2 | 2 | 0 | 0 |  | None |
| swarm | M2 | 0 | 0 | 0 |  | None |
| private-gpt | M1 | 0 | 0 | 0 |  | None |
| letta | M4 | 4 | 0 | 0 |  | None |
| SuperAGI | M1 | 55 | 17 | 12 | CredAccess=4;Overwrite=4;Delete=4 | 0.0 |
| AIOS | M2 | 0 | 0 | 0 |  | None |
| dify | M4 | 9 | 0 | 0 |  | None |

Across frameworks the adapter discovered **509 registered tools**, of which **72 are high-impact**; the checker flags **56** as reachable from a model choice with no capability mediation in the registry itself. This is the paper's core point made automatically on real code: a tool *name allowlist is not a capability* — the registry exposes raw effects.


## RQ1/RQ3 — grounded witness replay (curated, tied to real sinks)

| pair_id | mode | effect | evidence_site | buggy_rejected | fixed_accepted | repair | missing_capability |
|---|---|---|---|---|---|---|---|
| open-interpreter:exec-untrusted | M1 | Exec | open-interpreter/codex-rs/windows-sandbox-rs/sandbox_smoketests.py:95 | True | True | provenance | Cap(Exec, provenance=untrusted, sandbox=on) |
| smolagents:exec-untrusted | M3 | Exec | smolagents/src/smolagents/tools.py:575 | True | True | provenance | Cap(Exec, provenance=untrusted, sandbox=on) |
| smolagents:harness-overlap | M3 | ModHarness | smolagents/tests/test_all_docs.py:76 | True | True | scope | Cap(ModHarness, harness/test_patch) |
| SWE-bench:exec-untrusted | M3 | Exec | SWE-bench/swebench/inference/run_live.py:113 | True | True | provenance | Cap(Exec, provenance=untrusted, sandbox=on) |
| SWE-bench:harness-overlap | M3 | ModHarness | SWE-bench/swebench/harness/docker_utils.py:35 | True | True | scope | Cap(ModHarness, harness/test_patch) |
| MetaGPT:exec-untrusted | M2 | Exec | MetaGPT/metagpt/repo_parser.py:731 | True | True | provenance | Cap(Exec, provenance=untrusted, sandbox=on) |
| MetaGPT:delegate-untrusted | M2 | Delegate | MetaGPT/metagpt/repo_parser.py:731 | True | True | provenance | Cap(Delegate, engineer) |
| agno:exec-untrusted | M1 | Exec | agno/libs/agno/agno/utils/shell.py:12 | True | True | provenance | Cap(Exec, provenance=untrusted, sandbox=on) |
| dspy:exec-untrusted | M2 | Exec | dspy/dspy/teleprompt/infer_rules.py:28 | True | True | provenance | Cap(Exec, provenance=untrusted, sandbox=on) |
| dspy:delegate-untrusted | M2 | Delegate | dspy/dspy/teleprompt/infer_rules.py:28 | True | True | provenance | Cap(Delegate, engineer) |
| browser-use:exec-untrusted | M2 | Exec | browser-use/browser_use/cli.py:127 | True | True | provenance | Cap(Exec, provenance=untrusted, sandbox=on) |
| browser-use:delegate-untrusted | M2 | Delegate | browser-use/browser_use/cli.py:127 | True | True | provenance | Cap(Delegate, engineer) |
| OpenHands:exec-untrusted | M3 | Exec | OpenHands/openhands/app_server/utils/git.py:14 | True | True | provenance | Cap(Exec, provenance=untrusted, sandbox=on) |
| OpenHands:harness-overlap | M3 | ModHarness | OpenHands/tests/unit/test_binaryornot_dependency.py:6 | True | True | scope | Cap(ModHarness, harness/test_patch) |
| litellm:exec-untrusted | M2 | Exec | litellm/litellm/proxy/prisma_migration.py:18 | True | True | provenance | Cap(Exec, provenance=untrusted, sandbox=on) |
| litellm:delegate-untrusted | M2 | Delegate | litellm/litellm/proxy/prisma_migration.py:18 | True | True | provenance | Cap(Delegate, engineer) |
| swarm:delegate-untrusted | M2 | Delegate | swarm/examples/airline/evals/eval_utils.py:90 | True | True | provenance | Cap(Delegate, engineer) |
| private-gpt:exec-untrusted | M1 | Exec | private-gpt/private_gpt/cli/commands/run.py:71 | True | True | provenance | Cap(Exec, provenance=untrusted, sandbox=on) |
| letta:exec-untrusted | M4 | Exec | letta/sandbox/node_server.py:17 | True | True | provenance | Cap(Exec, provenance=untrusted, sandbox=on) |
| SuperAGI:exec-untrusted | M1 | Exec | SuperAGI/run_gui.py:16 | True | True | provenance | Cap(Exec, provenance=untrusted, sandbox=on) |
| AIOS:exec-untrusted | M2 | Exec | AIOS/aios/tool/manager.py:38 | True | True | provenance | Cap(Exec, provenance=untrusted, sandbox=on) |
| AIOS:delegate-untrusted | M2 | Delegate | AIOS/aios/tool/manager.py:38 | True | True | provenance | Cap(Delegate, engineer) |
| dify:exec-untrusted | M4 | Exec | dify/scripts/check_no_new_getattr.py:75 | True | True | provenance | Cap(Exec, provenance=untrusted, sandbox=on) |

- **known-bug replay rate:** 1.0  (every buggy path rejected with its exact missing capability)
- **fixed-version discharge rate:** 1.0  (every repaired path accepted)

## Honest scope

- The sink/guard inventory is **fully automated** over real source.
- The witnesses are **manually curated properties** encoded as lambda_cap pairs and *grounded* in a real sink location (file:line above); they are not auto-discovered defects. A faithful ACG for each framework's agent loop needs per-framework registry/dispatcher adapters (future work, plan Milestone 5).
- The soundness guarantee remains *relative to accepted contracts* (paper §8.1).