"""caprule-miner: curate the capability-safety rule set (plan Sec 1.1).

Loads the curated ``effects.yaml`` and ``capability_rules.yaml`` policy files and
emits ``rule_evidence.jsonl`` linking each rule to its documentation/policy source.
LLM assistance is optional and never part of the trusted base -- candidate rules
would be marked ``candidate`` until a human accepts them (here all rules ship
pre-accepted in the policy files).
"""
from __future__ import annotations

import json
import os
from typing import List

import yaml


def load_effects(policy_dir: str) -> dict:
    with open(os.path.join(policy_dir, "effects.yaml"), "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_rules(policy_dir: str) -> dict:
    with open(os.path.join(policy_dir, "capability_rules.yaml"), "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def mine(policy_dir: str) -> dict:
    effects = load_effects(policy_dir)
    rules = load_rules(policy_dir)
    evidence: List[dict] = []
    for r in rules.get("rules", []):
        for ev in r.get("evidence", []):
            evidence.append({
                "effect": r["effect"],
                "requires": r["requires"],
                "evidence_kind": ev.get("kind"),
                "note": ev.get("note"),
                "status": "accepted",     # human-reviewed policy
            })
    return {"effects": effects, "rules": rules, "rule_evidence": evidence}


def write_outputs(policy_dir: str, out_dir: str) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    data = mine(policy_dir)
    with open(os.path.join(out_dir, "effects.yaml"), "w", encoding="utf-8") as f:
        yaml.safe_dump(data["effects"], f, sort_keys=False, allow_unicode=True)
    with open(os.path.join(out_dir, "capability_rules.yaml"), "w", encoding="utf-8") as f:
        yaml.safe_dump(data["rules"], f, sort_keys=False, allow_unicode=True)
    with open(os.path.join(out_dir, "rule_evidence.jsonl"), "w", encoding="utf-8") as f:
        for e in data["rule_evidence"]:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    return {
        "effect_kinds": len(data["effects"].get("effects", [])),
        "rules": len(data["rules"].get("rules", [])),
        "evidence_records": len(data["rule_evidence"]),
    }
