"""Synthetic manager/executor agent (memory provenance + privilege crossing). Mode M2/M1.

Mirrors the overview example in Section 2.3.  A low-privilege tool writes an
untrusted observation into memory; a manager later reads it and dispatches to a
high-privilege executor or a shell.  Safety requires provenance validation before
the privilege crossing.
"""
from __future__ import annotations

import subprocess

from ._dsl import require, memread, provenance_check


# --------------------------------------------------------------------------
# Tool wrappers.
# --------------------------------------------------------------------------
def shell_exec(cmd):
    subprocess.run(cmd, shell=True)


def dispatch(role, task):
    # manager invokes a high-privilege executor role
    manager_run(role, task)


def manager_run(role, task):
    return (role, task)


def use_as_instruction(key, text):
    # feeds memory content back into the model as an instruction
    return "PROMPT:" + text


@provenance_check
def validate_provenance(x):
    assert x is not None
    return x


# --------------------------------------------------------------------------
# Plans.
# --------------------------------------------------------------------------
META = {
    "id": "manager_agent",
    "mode": "M2",
    "plans": {
        "plan_exec_buggy": {"expected_safe": False, "note": "untrusted memory executed as shell command"},
        "plan_exec_fixed": {"expected_safe": True, "note": "provenance validated + sandboxed exec cap"},
        "plan_dispatch_buggy": {"expected_safe": False, "note": "privilege crossing from untrusted content"},
        "plan_instr_buggy": {"expected_safe": False, "note": "untrusted memory used as instruction"},
    },
}


def plan_exec_buggy():
    cmd = memread("k_web", untrusted=True)
    shell_exec(cmd)


def plan_exec_fixed():
    cmd = memread("k_web", untrusted=True)
    cmd2 = validate_provenance(cmd)
    require("Exec", region=["sandbox"], provs=["trusted"])
    shell_exec(cmd2)


def plan_dispatch_buggy():
    task = memread("k_web", untrusted=True)
    dispatch("shell_role", task)


def plan_instr_buggy():
    m = memread("k_web", untrusted=True)
    use_as_instruction("k_web", m)
