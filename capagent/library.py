"""A standard library of tool contracts and helpers shared by kernels and scaffolds.

The contracts here play the role of ``tool_contracts.json`` -- the trusted boundary
of the verification problem (paper Definition 3).  In the full pipeline these are
produced by ``contract-extractor``; the library provides curated equivalents so the
formal layer can be exercised independently of any one heuristic extractor.
"""
from __future__ import annotations

from .core.types import (
    ContractTable, ToolContract, Propagation, Region,
    KIND_DELETE, KIND_OVERWRITE, KIND_SEND_EXT, KIND_EXEC, KIND_MODIFY_REPO,
    KIND_MOD_HARNESS, KIND_VERDICT, KIND_INSTR_USE, KIND_DELEGATE, KIND_CRED,
    KIND_READ, KIND_TRANSFORM, KIND_DECLASSIFY,
)
from .core.semantics import DEFAULT_HIGH_IMPACT


def standard_contracts() -> ContractTable:
    t = ContractTable(high_impact_kinds=DEFAULT_HIGH_IMPACT)

    def add(tool, kind, high=False, res_arg=None, res_const=None, dest_arg=None,
            prop=None, source="api", evidence=()):
        t.add(ToolContract(
            tool=tool, effect_kind=kind, high_impact=high,
            resource_arg=res_arg, resource_const=res_const, external_dest_arg=dest_arg,
            propagate=prop or Propagation(), source=source, evidence=tuple(evidence),
        ))

    # -- benign / data-flow tools -----------------------------------------
    add("read_file", KIND_READ, res_arg=0, prop=Propagation("fresh_private"),
        source="api", evidence=["open(path)"])
    add("read_public", KIND_READ, res_arg=0, prop=Propagation("public"),
        source="api", evidence=["open(path)"])
    add("summarize", KIND_TRANSFORM, prop=Propagation("keep", 0),
        source="wrapper", evidence=["llm.summarize(x)"])
    add("redact", KIND_DECLASSIFY, prop=Propagation("declassify"),
        source="wrapper", evidence=["strip_private_fields(x)"])
    add("validate_provenance", KIND_TRANSFORM, prop=Propagation("public"),
        source="policy", evidence=["assert trusted(x)"])

    # -- high-impact sinks -------------------------------------------------
    add("delete_file", KIND_DELETE, high=True, res_arg=0,
        source="api", evidence=["Path(p).unlink()"])
    add("write_file", KIND_OVERWRITE, high=True, res_arg=0,
        source="api", evidence=["open(p, 'w').write(...)"])
    # send_email(dst, data): dest = arg0, payload = last arg
    add("send_email", KIND_SEND_EXT, high=True, res_arg=0, dest_arg=1,
        source="api", evidence=["smtp.send(dst, x)"])
    add("http_post", KIND_SEND_EXT, high=True, res_arg=0, dest_arg=1,
        source="api", evidence=["requests.post(url, data=x)"])
    add("shell_exec", KIND_EXEC, high=True, res_const="sandbox", dest_arg=0,
        source="api", evidence=["subprocess.run(cmd)"])
    add("apply_patch", KIND_MODIFY_REPO, high=True, res_arg=0,
        source="wrapper", evidence=["repo.apply(delta)"])
    add("apply_patch_harness", KIND_MOD_HARNESS, high=True, res_arg=0,
        source="wrapper", evidence=["repo.apply(delta) over harness paths"])
    add("emit_verdict", KIND_VERDICT, high=True, res_const="oracle",
        source="wrapper", evidence=["parser.set_result(pass)"])
    add("use_as_instruction", KIND_INSTR_USE, high=True, res_arg=0, dest_arg=0,
        source="wrapper", evidence=["prompt += memory[k]"])
    add("dispatch", KIND_DELEGATE, high=True, res_arg=0, dest_arg=1,
        source="wrapper", evidence=["manager.run(role, task)"])
    add("read_credential", KIND_CRED, high=True, res_arg=0,
        source="api", evidence=["os.environ[secret]"])
    return t


# -- capability constructors (what guards / require() grant) ---------------
def cap_delete(*resources):
    from .core.types import Capability
    return Capability(KIND_DELETE, region=Region.of(*resources))


def cap_send(dst, labels=("private", "public")):
    from .core.types import Capability
    return Capability(KIND_SEND_EXT, region=Region.of(dst), labels=frozenset(labels))


def cap_exec_trusted():
    from .core.types import Capability
    return Capability(KIND_EXEC, region=Region.of("sandbox"), provs=frozenset({"trusted"}))


def cap_overwrite(*resources):
    from .core.types import Capability
    return Capability(KIND_OVERWRITE, region=Region.of(*resources))


def cap_modrepo_task():
    from .core.types import Capability
    return Capability(KIND_MODIFY_REPO, region=Region.prefix("task/"))


def cap_modharness():
    from .core.types import Capability
    return Capability(KIND_MOD_HARNESS, region=Region.prefix("harness/"))


def cap_verdict():
    from .core.types import Capability
    return Capability(KIND_VERDICT, region=Region.of("oracle"), provs=frozenset({"trusted"}))


def cap_delegate(role):
    from .core.types import Capability
    return Capability(KIND_DELEGATE, region=Region.of(role), provs=frozenset({"trusted"}))


def cap_trustmem(*keys):
    from .core.types import Capability
    return Capability(KIND_INSTR_USE, region=Region.of(*keys), provs=frozenset({"trusted"}))
