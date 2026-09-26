"""Stage 7 core functional IDs, the upstream schemas it pins, and one symbol resolver.

Twenty-two stable functional ids, ``ORPH-F01 … ORPH-F22``, one per architecture layer
7.0-7.21 (spec §4.24). They serve the purpose Stage 2's ``DTL-F*``, Stage 5's ``SAFE-F*``
and Stage 6's ``HEL-F*`` sets already serve: the hub and the gate depend on *functions*,
not on ORPHEUS or HIVELOCK. Every stage so far has rejected most of its own machinery on
measurement; if ECHO's cluster cap, contextual trust or collective novelty lose to their
simple controls, the collective fabric keeps working against the same ids and degrades to
whatever survives.

Each id is **REQUIRED** (the boundary that keeps foreign knowledge untrusted cannot run
without it) or **OPTIONAL** (a mechanism a measured ablation may delete). A row carries
its ablation flags and, position for position, the simple control each flag switches to:
ORPH-F09 alone has five, so a single "control" string could not be joined to five
ablation rows. An OPTIONAL row with no flag could never be removed and is refused on
construction; a REQUIRED row may carry flags too (``dependence_clustering``, the ECHO
terms, ``falsifier``, ``differential_privacy``) because a required defence that never
fires is still a finding (spec §4.24, Rule C).

**Symbols are resolved lazily.** Every row names the ``"module:qualname"`` that
implements it, and this module imports none of them: eight work packages build in
parallel and most of those modules do not exist when this one is written.
:func:`resolve_symbols` walks the table with :mod:`importlib` on demand; ``()`` is the
only passing answer. ORPH-F22 names a ``labs`` symbol: it is only ever *resolved* here,
by string, for the gate — no runtime module binds a ``labs`` name through this table.

**Schemas are pinned, not assumed.** :data:`PINNED_SCHEMAS` names the three Stage 6
schemas Stage 7 consumes, at the versions the spec was written against.
:func:`pinned_schema_drift` loads the *Stage 7 module that consumes each one* and joins
the pins to ``SCHEMA_REGISTRY``, so a Stage 6 bump is named rather than silently consumed.
It never imports a Stage 6 module itself: the §2.3 allow-list says which Stage 7 file may
import ``fleet.package`` and ``export.learning_record``, and this is not one of them.

This module decides nothing at runtime, holds no state and has no authority.
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from pocketsec.stage0.contracts.common import ContractError

__all__ = [
    "ABLATION_FLAGS",
    "ARCHITECTURE_LAYERS",
    "PINNED_SCHEMAS",
    "PINNED_SCHEMA_CONSUMERS",
    "STAGE7_FUNCTIONS",
    "SYMBOL_PATTERN",
    "FunctionClass",
    "Stage7Function",
    "optional_functions",
    "pinned_schema_drift",
    "resolve_symbols",
    "stage7_function",
    "symbol_problem",
]

#: ``pocketsec.stage7.<module path>:<Qualified.name>``. Stage 7 names only its own
#: symbols here; a row pointing into another stage would make that stage's rename a
#: silent Stage 7 regression.
SYMBOL_PATTERN = re.compile(
    r"^pocketsec\.stage7(?:\.[a-z_][a-z0-9_]*)+:[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$"
)

#: Every ablation flag §4.24 names, in table order. Held as data so the integrator's
#: ablation runner can be joined to it: a flag with no ``AblationRow`` is an unablated
#: mechanism, and a row naming a flag not listed here ablates nothing.
ABLATION_FLAGS: tuple[str, ...] = (
    "epistemic_distance",
    "gravity",
    "dependence_clustering",
    "cluster_cap",
    "contextual_trust",
    "falsification_weight",
    "contest_mass",
    "probation",
    "antibody_minimisation",
    "reconstruction",
    "collective_novelty",
    "hypergraph",
    "falsifier",
    "secure_aggregation",
    "differential_privacy",
)

#: Architecture §2's layer map, verbatim: layer id -> subsystem name. The row names are
#: these names, so a renamed or renumbered layer fails the foundation test that parses
#: the architecture source rather than drifting quietly.
ARCHITECTURE_LAYERS: Mapping[str, str] = MappingProxyType(
    {
        "7.0": "Collective Constitution",
        "7.1": "Peer Identity Plane",
        "7.2": "Knowledge Capsule Compiler",
        "7.3": "Privacy Distiller",
        "7.4": "Epistemic Distance Engine",
        "7.5": "Knowledge Gravity Engine",
        "7.6": "HIVELOCK Ingress",
        "7.7": "Dependence/Sybil Graph",
        "7.8": "Byzantine Evidence Engine",
        "7.9": "Antibody Forge",
        "7.10": "Partial-World Reconstructor",
        "7.11": "Collective Novelty Engine",
        "7.12": "Campaign Hypergraph",
        "7.13": "Consensus Falsifier",
        "7.14": "Cross-Host Lineage DAG",
        "7.15": "Revocation Plane",
        "7.16": "Stage-6 Local Gate",
        "7.17": "Optional Secure Aggregation",
        "7.18": "Privacy Budget Plane",
        "7.19": "Communication Governor",
        "7.20": "Offline/Partition Mode",
        "7.21": "Assurance & Falsification",
    }
)

#: The three Stage 6 schemas Stage 7 is built against (spec §4.24), at ``1.0.0``.
PINNED_SCHEMAS: Mapping[str, str] = MappingProxyType(
    {
        "pocketsec.experience_capsule.v1": "1.0.0",
        "pocketsec.knowledge_package.v1": "1.0.0",
        "pocketsec.learning_record.v1": "1.0.0",
    }
)

#: The Stage 7 module whose import registers each pinned schema, because it is the one
#: Stage 7 file allowed (spec §2.3) to import the Stage 6 module that registers it. The
#: pin is therefore on what Stage 7's consumer actually loads.
PINNED_SCHEMA_CONSUMERS: Mapping[str, str] = MappingProxyType(
    {
        "pocketsec.experience_capsule.v1": "pocketsec.stage7.capsule.knowledge_capsule",
        "pocketsec.knowledge_package.v1": "pocketsec.stage7.hivelock.stage6_bridge",
        "pocketsec.learning_record.v1": "pocketsec.stage7.capsule.compiler",
    }
)


class FunctionClass(StrEnum):
    #: The boundary that keeps foreign knowledge untrusted cannot operate without this.
    REQUIRED = "REQUIRED"
    #: Experimental. Must justify itself by ablation against its simple control, or go.
    OPTIONAL = "OPTIONAL"


@dataclass(frozen=True, slots=True)
class Stage7Function:
    """One row of spec §4.24: a functional id, its layer, where it lives, how it is ablated.

    ``simple_control[i]`` is what ``ablation_flags[i]`` switches the mechanism to.
    """

    core_id: str
    architecture_layer: str
    name: str
    symbol: str
    function_class: FunctionClass
    ablation_flags: tuple[str, ...]
    simple_control: tuple[str, ...]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"ORPH-F\d{2}", self.core_id):
            raise ContractError(f"core_id must look like ORPH-F01, got {self.core_id!r}")
        expected_layer = f"7.{int(self.core_id[-2:]) - 1}"
        if self.architecture_layer != expected_layer:
            raise ContractError(
                f"{self.core_id} must map to layer {expected_layer}, "
                f"got {self.architecture_layer!r}"
            )
        if ARCHITECTURE_LAYERS.get(self.architecture_layer) != self.name:
            raise ContractError(f"{self.core_id}: {self.name!r} is not layer {expected_layer}")
        if not SYMBOL_PATTERN.fullmatch(self.symbol):
            raise ContractError(f"{self.core_id}: symbol {self.symbol!r} is not module:qualname")
        if not isinstance(self.function_class, FunctionClass):
            raise ContractError(f"{self.core_id}: function_class must be a FunctionClass")
        self._check_ablation()

    def _check_ablation(self) -> None:
        flags, controls = self.ablation_flags, self.simple_control
        if not isinstance(flags, tuple) or not isinstance(controls, tuple):
            raise ContractError(f"{self.core_id}: flags and controls are tuples")
        if len(flags) != len(controls):
            raise ContractError(f"{self.core_id}: every ablation flag names its simple control")
        if len(set(flags)) != len(flags):
            raise ContractError(f"{self.core_id}: an ablation flag is listed twice")
        unknown = [flag for flag in flags if flag not in ABLATION_FLAGS]
        if unknown:
            raise ContractError(f"{self.core_id}: unknown ablation flag {unknown[0]!r}")
        if any(not isinstance(c, str) or not c.strip() for c in controls):
            raise ContractError(f"{self.core_id}: a control must be named, not blank")
        if self.function_class is FunctionClass.OPTIONAL and not flags:
            raise ContractError(
                f"{self.core_id} is OPTIONAL with no ablation flag: it could never be removed"
            )

    def controls(self) -> Mapping[str, str]:
        """``ablation flag -> simple control`` for this row."""
        return MappingProxyType(dict(zip(self.ablation_flags, self.simple_control, strict=True)))


def _row(
    number: int,
    symbol: str,
    function_class: FunctionClass = FunctionClass.REQUIRED,
    ablation: tuple[tuple[str, str], ...] = (),
) -> Stage7Function:
    """Build one table row; ``symbol`` is relative to ``pocketsec.stage7``."""
    layer = f"7.{number - 1}"
    return Stage7Function(
        core_id=f"ORPH-F{number:02d}",
        architecture_layer=layer,
        name=ARCHITECTURE_LAYERS[layer],
        symbol=f"pocketsec.stage7.{symbol}",
        function_class=function_class,
        ablation_flags=tuple(flag for flag, _ in ablation),
        simple_control=tuple(control for _, control in ablation),
    )


_OPTIONAL = FunctionClass.OPTIONAL

#: Spec §4.24, verbatim. The REQUIRED/OPTIONAL split and every control are the spec's.
STAGE7_FUNCTIONS: tuple[Stage7Function, ...] = (
    _row(1, "constitution.collective:verify_collective_constitution"),
    _row(2, "identity.integrity:Keyring.verify"),
    _row(3, "capsule.compiler:compile_capsule"),
    _row(4, "privacy.distiller:residual_identifier_hits"),
    _row(
        5,
        "relevance.epistemic_distance:epistemic_distance",
        _OPTIONAL,
        (("epistemic_distance", "role equality"),),
    ),
    _row(6, "relevance.gravity:knowledge_gravity", _OPTIONAL,
         (("gravity", "validate every capsule"),)),
    _row(7, "hivelock.ingress:HivelockIngress.receive"),
    _row(8, "graph.dependence:DependenceGraph.observe",
         ablation=(("dependence_clustering", "declared roots only"),)),
    _row(
        9,
        "echo.inference:EchoEngine.infer",
        ablation=(
            ("cluster_cap", "uncapped identity sum"),
            ("contextual_trust", "constant prior"),
            ("falsification_weight", "1.0"),
            ("contest_mass", "ignore contests"),
            ("probation", "0 rounds"),
        ),
    ),
    _row(10, "antibody.forge:forge_antibody", _OPTIONAL,
         (("antibody_minimisation", "copied_rule"),)),
    _row(11, "reconstruct.partial_world:PartialWorldReconstructor.reconstruct", _OPTIONAL,
         (("reconstruction", "no reconstruction"),)),
    _row(12, "novelty.collective:CollectiveNoveltyEngine.evaluate", _OPTIONAL,
         (("collective_novelty", "local novelty only"),)),
    _row(13, "campaign.hypergraph:CampaignHypergraph.build_edges", _OPTIONAL,
         (("hypergraph", "pairwise co-occurrence"),)),
    _row(14, "falsifier.consensus:ConsensusFalsifier.falsify",
         ablation=(("falsifier", "count_threshold_join"),)),
    _row(15, "lineage.cross_host:CrossHostLineageDAG.ancestry_complete"),
    _row(16, "lineage.cross_host:RevocationPlane.submit"),
    _row(17, "hivelock.stage6_bridge:Stage6Bridge.hand_over"),
    _row(18, "aggregation.secure:aggregate_masked", _OPTIONAL,
         (("secure_aggregation", "plaintext sum"),)),
    # REQUIRED: the ledger's budget enforcement is the privacy boundary. The DP noise it
    # can add to population counts is the OPTIONAL part, ablated to exact counts.
    _row(19, "privacy.ledger:PrivacyLedger.charge",
         ablation=(("differential_privacy", "exact counts"),)),
    _row(20, "governor.communication:CommunicationGovernor.admit_inbound"),
    _row(21, "orpheus.fabric:OrpheusFabric.run_round"),
    _row(22, "labs.byzantine_suite:run_byzantine_suite"),
)  # fmt: skip

_BY_ID: Mapping[str, Stage7Function] = MappingProxyType(
    {function.core_id: function for function in STAGE7_FUNCTIONS}
)

# Import-time invariants: a table that drifts from the architecture fails on import, not
# in a gate run weeks later. Raised rather than asserted so ``-O`` cannot strip them.
if len(_BY_ID) != len(STAGE7_FUNCTIONS) or len(STAGE7_FUNCTIONS) != len(ARCHITECTURE_LAYERS):
    raise ContractError("STAGE7_FUNCTIONS must hold exactly one distinct id per layer 7.0-7.21")
if [f.architecture_layer for f in STAGE7_FUNCTIONS] != list(ARCHITECTURE_LAYERS):
    raise ContractError("STAGE7_FUNCTIONS must cover layers 7.0-7.21 in order")
_USED_FLAGS = [flag for f in STAGE7_FUNCTIONS for flag in f.ablation_flags]
if sorted(_USED_FLAGS) != sorted(ABLATION_FLAGS):
    raise ContractError("every ABLATION_FLAGS entry is used by exactly one row")
if set(PINNED_SCHEMA_CONSUMERS) != set(PINNED_SCHEMAS):
    raise ContractError("every pinned schema names the Stage 7 module that consumes it")


def stage7_function(core_id: str) -> Stage7Function:
    """The row for ``core_id``; a ``ContractError`` for an id the spec never named."""
    try:
        return _BY_ID[core_id]
    except KeyError:
        raise ContractError(f"unknown Stage 7 core id {core_id!r}") from None


def optional_functions() -> tuple[Stage7Function, ...]:
    """Every row a measured ablation may delete, in table order."""
    return tuple(f for f in STAGE7_FUNCTIONS if f.function_class is FunctionClass.OPTIONAL)


def _import_problem(module_name: str) -> tuple[object | None, str | None]:
    """Import ``module_name``; the module, or why it could not be imported."""
    try:
        return importlib.import_module(module_name), None
    except ModuleNotFoundError as exc:
        return None, f"module not found: {exc.name}"
    except Exception as exc:  # another package's module raising on import
        return None, f"module raises on import: {type(exc).__name__}: {exc}"


def symbol_problem(symbol: str) -> str | None:
    """Why ``symbol`` does not resolve, or ``None`` when it does.

    Importing the module is the test: a module that exists but raises on import is as
    unusable as one that does not exist, so the exception text becomes the reason rather
    than propagating into the caller's report. Only a string matching
    :data:`SYMBOL_PATTERN` is looked up — this function never imports an arbitrary dotted
    path handed to it, and never anything outside ``pocketsec.stage7``.
    """
    if not isinstance(symbol, str) or not SYMBOL_PATTERN.fullmatch(symbol):
        return "malformed: not pocketsec.stage7.<module>:<qualname>"
    module_name, qualname = symbol.split(":", 1)
    target, problem = _import_problem(module_name)
    if problem is not None:
        return problem
    for part in qualname.split("."):
        if not hasattr(target, part):
            return f"{module_name} has no attribute {qualname!r}"
        target = getattr(target, part)
    if not callable(target):
        return f"{symbol} resolves to a non-callable {type(target).__name__}"
    return None


def resolve_symbols() -> tuple[str, ...]:
    """Symbols of :data:`STAGE7_FUNCTIONS` that fail to resolve; ``()`` = all resolve."""
    return tuple(f.symbol for f in STAGE7_FUNCTIONS if symbol_problem(f.symbol) is not None)


def pinned_schema_drift() -> tuple[str, ...]:
    """Pinned schemas whose registered version differs from :data:`PINNED_SCHEMAS`.

    Each consuming Stage 7 module is imported first (by string, like a symbol), so the
    registry holds what that consumer actually loads. A consumer that cannot be imported
    is reported with its reason; an id that is registered at no version is drift too — a
    pin against nothing pins nothing.
    """
    from pocketsec.stage0.contracts.common import SCHEMA_REGISTRY

    problems: list[str] = []
    for schema_id, version in sorted(PINNED_SCHEMAS.items()):
        consumer = PINNED_SCHEMA_CONSUMERS[schema_id]
        _, problem = _import_problem(consumer)
        registered = SCHEMA_REGISTRY.get(schema_id)
        if registered == version:
            continue
        reason = "" if problem is None else f" (consumer {consumer}: {problem})"
        problems.append(f"{schema_id}: pinned {version}, registered {registered}{reason}")
    return tuple(problems)
