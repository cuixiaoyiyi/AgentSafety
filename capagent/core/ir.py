"""lambda_cap abstract syntax -- the CapAgent IR.

Grammar (paper Section 3.2):

    P ::= skip | x := t(e) | c := require(rho) | check(c, eps) | grant(c)
        | x := declassify(x, c) | x := memread(k) | memwrite(k, x)
        | think(Pi) | assume(g) | P1 ; P2 | P1 (+) P2
        | if g then P1 else P2 | while g do P

The textual surface form used by ``programs/*.capagent`` mirrors the example in
the implementation plan:

    choice {
      memread(k_untrusted);
      dispatch(manager, shell_exec);
      shell_exec(cmd)
    }
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .types import Capability, Effect


class Stmt:
    """Base class for lambda_cap statements."""


@dataclass
class Skip(Stmt):
    pass


@dataclass
class ToolCall(Stmt):
    """x := t(e).  ``result`` may be None for effect-only calls."""
    tool: str
    args: tuple = ()
    result: Optional[str] = None
    site: str = ""              # source provenance (file:line or graph node id)


@dataclass
class Require(Stmt):
    """c := require(rho): a policy interaction that grants a capability.

    Concretely a user-confirmation, role check, sandbox gate, path-scope
    validator, oracle-trust check, or provenance validator.  All are treated
    uniformly as capability-producing operations.
    """
    cap: Capability
    capvar: str = ""
    site: str = ""


@dataclass
class Grant(Stmt):
    """grant(c): unconditionally add a capability to the state."""
    cap: Capability
    site: str = ""


@dataclass
class Revoke(Stmt):
    """Weaken/clear a capability (Definition 9, authority weakening)."""
    cap: Capability
    site: str = ""


@dataclass
class Check(Stmt):
    """check(c, eps): sets BadCap if the capability does not match the effect."""
    cap: Capability
    effect: Effect
    site: str = ""


@dataclass
class Declassify(Stmt):
    """x := declassify(x, c): clear the private label of a payload variable."""
    var: str
    src: str = ""
    site: str = ""


@dataclass
class MemRead(Stmt):
    """x := memread(k).  ``untrusted`` records the provenance of the key/region."""
    var: str
    key: str
    untrusted: bool = False
    site: str = ""


@dataclass
class MemWrite(Stmt):
    """memwrite(k, x)."""
    key: str
    var: str
    untrusted: bool = False
    site: str = ""


@dataclass
class Think(Stmt):
    """think(Pi): nondeterministic model-mediated choice among fragments."""
    choices: List[Stmt] = field(default_factory=list)
    site: str = ""


@dataclass
class Assume(Stmt):
    guard: str = "true"


@dataclass
class Seq(Stmt):
    first: Stmt
    second: Stmt


@dataclass
class Choice(Stmt):
    """P1 (+) P2: nondeterministic choice (semiring addition)."""
    left: Stmt
    right: Stmt


@dataclass
class If(Stmt):
    guard: str
    then: Stmt
    otherwise: Stmt


@dataclass
class While(Stmt):
    guard: str
    body: Stmt


# ---------------------------------------------------------------------------
# Convenience constructors.
# ---------------------------------------------------------------------------
def seq(*stmts: Stmt) -> Stmt:
    """Right-fold a list of statements into a Seq tree, dropping Skips."""
    items = [s for s in stmts if not isinstance(s, Skip)]
    if not items:
        return Skip()
    acc = items[-1]
    for s in reversed(items[:-1]):
        acc = Seq(s, acc)
    return acc


def choice(*stmts: Stmt) -> Stmt:
    items = list(stmts)
    if not items:
        return Skip()
    acc = items[-1]
    for s in reversed(items[:-1]):
        acc = Choice(s, acc)
    return acc


def walk(stmt: Stmt):
    """Yield every sub-statement (pre-order)."""
    yield stmt
    if isinstance(stmt, Seq):
        yield from walk(stmt.first)
        yield from walk(stmt.second)
    elif isinstance(stmt, Choice):
        yield from walk(stmt.left)
        yield from walk(stmt.right)
    elif isinstance(stmt, If):
        yield from walk(stmt.then)
        yield from walk(stmt.otherwise)
    elif isinstance(stmt, While):
        yield from walk(stmt.body)
    elif isinstance(stmt, Think):
        for c in stmt.choices:
            yield from walk(c)


def pretty(stmt: Stmt, indent: int = 0) -> str:
    """Render a statement in the textual CapAgent IR surface syntax."""
    pad = "  " * indent

    def arglist(args):
        return ", ".join(str(a) for a in args)

    if isinstance(stmt, Skip):
        return pad + "skip"
    if isinstance(stmt, ToolCall):
        lhs = f"{stmt.result} := " if stmt.result else ""
        return pad + f"{lhs}{stmt.tool}({arglist(stmt.args)})"
    if isinstance(stmt, Require):
        return pad + f"{stmt.capvar or 'c'} := require({stmt.cap})"
    if isinstance(stmt, Grant):
        return pad + f"grant({stmt.cap})"
    if isinstance(stmt, Revoke):
        return pad + f"revoke({stmt.cap})"
    if isinstance(stmt, Check):
        return pad + f"check(c, {stmt.effect})"
    if isinstance(stmt, Declassify):
        return pad + f"{stmt.var} := declassify({stmt.src or stmt.var})"
    if isinstance(stmt, MemRead):
        tag = "_untrusted" if stmt.untrusted else ""
        return pad + f"{stmt.var} := memread({stmt.key}{tag})"
    if isinstance(stmt, MemWrite):
        return pad + f"memwrite({stmt.key}, {stmt.var})"
    if isinstance(stmt, Assume):
        return pad + f"assume({stmt.guard})"
    if isinstance(stmt, Think):
        inner = ";\n".join(pretty(c, indent + 1) for c in stmt.choices)
        return pad + "choice {\n" + inner + "\n" + pad + "}"
    if isinstance(stmt, Seq):
        return pretty(stmt.first, indent) + ";\n" + pretty(stmt.second, indent)
    if isinstance(stmt, Choice):
        return pad + "choice {\n" + pretty(stmt.left, indent + 1) + ";\n" + pretty(stmt.right, indent + 1) + "\n" + pad + "}"
    if isinstance(stmt, If):
        return (pad + f"if {stmt.guard} then\n" + pretty(stmt.then, indent + 1)
                + "\n" + pad + "else\n" + pretty(stmt.otherwise, indent + 1))
    if isinstance(stmt, While):
        return pad + f"while {stmt.guard} do\n" + pretty(stmt.body, indent + 1)
    return pad + f"<{type(stmt).__name__}>"
