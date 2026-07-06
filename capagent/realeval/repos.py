"""Pinned real-repository manifest (Milestone 5 subjects).

Commits are pinned to whatever HEAD the shallow clone resolved to; ``run_real`` reads
the actual SHA from each working copy at run time and records it, so the manifest is
always faithful to what was analyzed.
"""
from __future__ import annotations

import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
REPOS_DIR = os.path.join(HERE, "_repos")

# name, url, mode, one-line reason (from the plan's M1-M4 tables)
SUBJECTS = [
    ("open-interpreter", "https://github.com/OpenInterpreter/open-interpreter", "M1",
     "computer-use agent with code execution and approval surfaces"),
    ("smolagents", "https://github.com/huggingface/smolagents", "M3",
     "lightweight code/tool agent with a local Python executor"),
    ("SWE-bench", "https://github.com/SWE-bench/SWE-bench", "M3",
     "repository patching and harness/verdict integrity"),
    ("MetaGPT", "https://github.com/FoundationAgents/MetaGPT", "M2",
     "multi-agent software company with role delegation"),
    ("langchain-mcp-adapters", "https://github.com/langchain-ai/langchain-mcp-adapters", "M4",
     "MCP-to-LangChain/LangGraph tool bridge"),
    ("agno", "https://github.com/agno-agi/agno", "M1",
     "agent framework with tools, execution and persistent resources"),
    ("dspy", "https://github.com/stanfordnlp/dspy", "M2",
     "LLM programming framework with module composition and tool calls"),
    ("camel", "https://github.com/camel-ai/camel", "M1",
     "multi-agent framework with tool-use and role interactions"),
    ("browser-use", "https://github.com/browser-use/browser-use", "M2",
     "browser agent with high-impact interactive actions"),
    ("OpenHands", "https://github.com/All-Hands-AI/OpenHands", "M3",
     "coding-agent platform with repo modification and evaluation"),
    ("litellm", "https://github.com/BerriAI/litellm", "M2",
     "LLM gateway/proxy with routing and policy surfaces"),
    ("swarm", "https://github.com/openai/swarm", "M2",
     "multi-agent orchestration example framework"),
    ("private-gpt", "https://github.com/zylon-ai/private-gpt", "M1",
     "local RAG agent with document and retrieval surfaces"),
    ("ChatDev", "https://github.com/OpenBMB/ChatDev", "M1",
     "multi-agent software-development workflow"),
    ("letta", "https://github.com/letta-ai/letta", "M4",
     "stateful/memory-centric agent framework with tool surfaces"),
    ("SuperAGI", "https://github.com/TransformerOptimus/SuperAGI", "M1",
     "autonomous agent framework with tools and execution workflows"),
    ("AIOS", "https://github.com/agiresearch/AIOS", "M2",
     "agent operating-system style architecture"),
    ("dify", "https://github.com/langgenius/dify", "M4",
     "LLM application/agent platform with workflows and tools"),
]


def repo_path(name: str) -> str:
    return os.path.join(REPOS_DIR, name)


def head_sha(name: str) -> str:
    try:
        out = subprocess.run(["git", "-C", repo_path(name), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=30)
        return out.stdout.strip()
    except Exception:
        return "unknown"


def available_subjects():
    """Only the subjects whose working copy exists on disk."""
    return [(n, u, m, r) for (n, u, m, r) in SUBJECTS if os.path.isdir(repo_path(n))]
