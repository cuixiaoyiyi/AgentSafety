"""Effects, capabilities, resource regions, tool contracts, and the matching relation.

These datatypes realize Definitions 1-3 of the paper:

* Definition 1 (Effect):  eps = <kind, resource, label, provenance>
* Definition 2 (Capability): c = <kind, Region, Labels, Provs>, with Match(c, eps)
* Definition 3 (Tool contract): kappa_t = <pre, R, eff, req, post>

The formal development is *parametric* in the effect-kind set and in the policy;
the concrete kinds and default requirements live in the YAML policy files and are
loaded into these structures at run time.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Effect kinds (parameter of the framework; see effects.yaml for the taxonomy).
# ---------------------------------------------------------------------------
# High-impact effect kinds used by the default policy.
KIND_DELETE = "Delete"
KIND_OVERWRITE = "Overwrite"
KIND_SEND_EXT = "SendExt"
KIND_EXEC = "Exec"
KIND_MODIFY_REPO = "ModifyRepo"
KIND_MOD_HARNESS = "ModHarness"
KIND_VERDICT = "Verdict"
KIND_INSTR_USE = "InstrUse"        # use untrusted memory as an instruction source
KIND_DELEGATE = "Delegate"         # high-privilege delegation / privilege crossing
KIND_CRED = "CredAccess"

# Non high-impact effect kinds (tracked for data-flow, never sinks by default).
KIND_READ = "Read"
KIND_TRANSFORM = "Transform"       # summarize etc. (label-preserving)
KIND_DECLASSIFY = "Declassify"     # redact etc. (label-clearing)

# Provenance classes.
PROV_TRUSTED = "trusted"
PROV_UNTRUSTED = "untrusted"

# Data / authority labels.
LABEL_PRIVATE = "private"
LABEL_PUBLIC = "public"


# ---------------------------------------------------------------------------
# Resource regions.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Region:
    """A resource region R subseteq R.

    A region is described by an explicit set of exact resource names plus a set
    of path/name *prefixes*.  ``TOP`` regions (``any=True``) contain every
    resource and model an unknown / unrestricted scope.
    """
    names: frozenset = field(default_factory=frozenset)
    prefixes: tuple = ()
    any: bool = False

    def contains(self, resource: str) -> bool:
        if self.any:
            return True
        if resource in self.names:
            return True
        return any(resource.startswith(p) for p in self.prefixes)

    def __str__(self) -> str:  # pragma: no cover - display only
        if self.any:
            return "*"
        parts = sorted(self.names) + [p + "*" for p in self.prefixes]
        return "{" + ",".join(parts) + "}"

    @staticmethod
    def of(*names: str) -> "Region":
        return Region(names=frozenset(names))

    @staticmethod
    def prefix(*prefixes: str) -> "Region":
        return Region(prefixes=tuple(prefixes))

    @staticmethod
    def top() -> "Region":
        return Region(any=True)


# ---------------------------------------------------------------------------
# Effects and capabilities.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Effect:
    """Definition 1: an abstract effect eps = <kind, resource, label, provenance>."""
    kind: str
    resource: str = "-"
    label: str = LABEL_PUBLIC
    prov: str = PROV_TRUSTED

    def __str__(self) -> str:  # pragma: no cover - display only
        return f"{self.kind}({self.resource}, {self.label}, {self.prov})"


@dataclass(frozen=True)
class Capability:
    """Definition 2: a capability c = <kind, Region, Labels, Provs>."""
    kind: str
    region: Region = field(default_factory=Region.top)
    labels: frozenset = field(default_factory=lambda: frozenset({LABEL_PRIVATE, LABEL_PUBLIC}))
    provs: frozenset = field(default_factory=lambda: frozenset({PROV_TRUSTED, PROV_UNTRUSTED}))

    def matches(self, eps: Effect) -> bool:
        """Match(c, eps): kind = kind ∧ res ∈ R ∧ lab ∈ L ∧ prov ∈ Q (Definition 2)."""
        return (
            eps.kind == self.kind
            and self.region.contains(eps.resource)
            and eps.label in self.labels
            and eps.prov in self.provs
        )

    def weaker_than(self, other: "Capability") -> bool:
        """Definition 9 (capability weakening): c1 <= c2."""
        if self.kind != other.kind:
            return False
        region_ok = other.region.any or (
            (not self.region.any)
            and self.region.names <= other.region.names
            and set(self.region.prefixes) <= set(other.region.prefixes)
        )
        return region_ok and self.labels <= other.labels and self.provs <= other.provs

    def key(self) -> str:
        return f"{self.kind}|{self.region}|{'+'.join(sorted(self.labels))}|{'+'.join(sorted(self.provs))}"

    def __str__(self) -> str:  # pragma: no cover - display only
        return f"Cap({self.kind}, {self.region}, L={set(self.labels)}, Q={set(self.provs)})"


# ---------------------------------------------------------------------------
# Tool contracts.
# ---------------------------------------------------------------------------
@dataclass
class Propagation:
    """How a tool call transforms the abstract label/provenance of its result.

    ``mode`` is one of:
      * ``"fresh_private"``  -> result is private / trusted (e.g. read_file(secret))
      * ``"fresh_untrusted"``-> result carries untrusted provenance (e.g. memread of tool-derived key)
      * ``"keep"``           -> result inherits label/prov of ``from_arg`` (e.g. summarize)
      * ``"declassify"``     -> result label is cleared to public (e.g. redact)
      * ``"public"``         -> result is public / trusted (default)
    """
    mode: str = "public"
    from_arg: int = 0


@dataclass
class ToolContract:
    """Definition 3 (tool contract), in the analyzer-facing form.

    ``effect_kind`` and ``resource_arg`` say what abstract effect an invocation
    produces; ``requires`` is derived from the policy (capability_rules).  The
    contract is the *trusted boundary* of the verification problem.
    """
    tool: str
    effect_kind: str
    resource_arg: Optional[int] = None      # which positional arg names the resource
    resource_const: Optional[str] = None    # or a fixed resource
    external_dest_arg: Optional[int] = None
    propagate: Propagation = field(default_factory=Propagation)
    high_impact: bool = False
    source: str = "manual"                  # api | wrapper | doc | policy | repair | manual
    evidence: tuple = ()
    confidence: str = "high"

    def resource_of(self, args) -> str:
        if self.resource_const is not None:
            return self.resource_const
        if self.resource_arg is not None and self.resource_arg < len(args):
            return str(args[self.resource_arg])
        return "-"


@dataclass
class ContractTable:
    """A registry of tool contracts plus the effect taxonomy and policy rules."""
    contracts: dict = field(default_factory=dict)             # tool -> ToolContract
    high_impact_kinds: frozenset = field(default_factory=frozenset)
    # kind -> capability requirement template description (for reporting)
    requirement_notes: dict = field(default_factory=dict)

    def add(self, c: ToolContract) -> None:
        self.contracts[c.tool] = c

    def get(self, tool: str) -> Optional[ToolContract]:
        return self.contracts.get(tool)

    def is_high_impact(self, kind: str) -> bool:
        return kind in self.high_impact_kinds
