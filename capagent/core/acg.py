"""Action-Capability Graph (ACG) structures (paper Section 5.1).

An ACG is a finite directed graph G = <N, E, n0, lambda> whose nodes are abstract
action-layer events and whose edges carry control/data/provenance/authorization
flow.  It is an implementation-level abstraction of the scaffold; graph reachability
to an unguarded high-impact sink is an instance of the linear semantics (Section 5.2).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Node kinds (Section 5.1).
N_INIT = "Init"
N_LLM_CHOICE = "LLMChoice"
N_TOOL = "ToolCall"
N_GUARD = "CapabilityGrant"
N_CHECK = "CapabilityCheck"
N_MEMREAD = "MemoryRead"
N_MEMWRITE = "MemoryWrite"
N_SINK = "HighImpactSink"
N_ORACLE = "OracleAction"
N_MERGE = "Merge"

# Edge kinds.
E_CONTROL = "control"
E_DATA = "data"
E_PROVENANCE = "provenance"
E_MEMORY = "memory"
E_AUTH = "authorization"


@dataclass
class Node:
    id: str
    kind: str
    label: str = ""
    tool: str = ""
    args: tuple = ()
    result: Optional[str] = None
    effect_kind: str = ""
    high_impact: bool = False
    cap: Optional[dict] = None       # for guard nodes
    untrusted: bool = False          # for memory-read nodes
    site: str = ""
    attrs: dict = field(default_factory=dict)


@dataclass
class Edge:
    src: str
    dst: str
    kind: str = E_CONTROL


@dataclass
class ACG:
    nodes: Dict[str, Node] = field(default_factory=dict)
    edges: List[Edge] = field(default_factory=list)
    entry: str = ""
    exits: List[str] = field(default_factory=list)
    name: str = ""
    warnings: List[dict] = field(default_factory=list)

    def add_node(self, node: Node) -> Node:
        self.nodes[node.id] = node
        return node

    def add_edge(self, src: str, dst: str, kind: str = E_CONTROL) -> None:
        self.edges.append(Edge(src, dst, kind))

    def successors(self, nid: str) -> List[str]:
        return [e.dst for e in self.edges if e.src == nid]

    def sinks(self) -> List[Node]:
        return [n for n in self.nodes.values() if n.high_impact]

    def summary(self) -> dict:
        from collections import Counter
        kinds = Counter(n.kind for n in self.nodes.values())
        ekinds = Counter(e.kind for e in self.edges)
        return {
            "name": self.name,
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "sinks": len(self.sinks()),
            "node_kinds": dict(kinds),
            "edge_kinds": dict(ekinds),
            "warnings": len(self.warnings),
        }

    def to_json(self) -> dict:
        return {
            "name": self.name,
            "entry": self.entry,
            "exits": self.exits,
            "nodes": [
                {
                    "id": n.id, "kind": n.kind, "label": n.label, "tool": n.tool,
                    "args": list(n.args), "result": n.result,
                    "effect_kind": n.effect_kind, "high_impact": n.high_impact,
                    "cap": n.cap, "untrusted": n.untrusted, "site": n.site,
                }
                for n in self.nodes.values()
            ],
            "edges": [{"src": e.src, "dst": e.dst, "kind": e.kind} for e in self.edges],
            "warnings": self.warnings,
        }
