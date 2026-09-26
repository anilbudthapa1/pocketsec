"""Stage 6 core functional IDs, the upstream schemas it pins, and one symbol resolver.

Twenty-six stable functional ids, mapped one-to-one onto architecture §45's
``S6-F01 … S6-F26``. Their purpose is the one Stage 2's ``DTL-F*`` and Stage 5's
``SAFE-F*`` sets already serve: the hub depends on *functions*, not on HELIOS or
MNEMOSYNE. Every completed stage so far has rejected most of its own machinery on
measurement (Stage 2 ADR-0010, Stage 3 ADR-0021, Stage 4 ADR-0036, Stage 5 ADR-0048);
if the plasticity field, the half-life or the competition engine lose to their simple
controls, the learning loop keeps working against the same ids and degrades to whatever
survives.

Each id is **REQUIRED** (the quarantine → validation → promotion boundary cannot run
without it) or **OPTIONAL** (a mechanism a measured ablation may delete). An OPTIONAL id
must name the ``StageSixConfig`` flag that removes it *and* the simple control that
replaces it (spec §7), because a mechanism with no off switch cannot be ablated and a
mechanism with no named control can only be compared against nothing. Two REQUIRED ids
(HEL-F04 source independence, HEL-F18 homeostasis) carry a flag too: they are security
mechanisms that are ablated anyway, since a required defence that never fires is still a
finding (spec §7, Rule C).

**Symbols are resolved lazily.** Every row names the ``"module:qualname"`` that
implements it, and this module imports none of them: eight work packages build in
parallel and most of those modules do not exist when this one is written.
:func:`resolve_symbols` walks the table with :mod:`importlib` on demand and returns the
symbols that fail; ``()`` is the only passing answer (G6.1 depends on it). A symbol that
names a module which does not exist is a docstring, not a mechanism.

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
    "PINNED_SCHEMAS",
    "STAGE6_FUNCTIONS",
    "SYMBOL_PATTERN",
    "FunctionClass",
    "Stage6Function",
    "optional_functions",
    "pinned_schema_drift",
    "resolve_symbols",
    "stage6_function",
    "symbol_problem",
]

#: ``pocketsec.stage6.<module path>:<Qualified.name>``. Stage 6 names only its own
#: symbols here; a row pointing into another stage would make that stage's rename a
#: silent Stage 6 regression.
SYMBOL_PATTERN = re.compile(
    r"^pocketsec\.stage6(?:\.[a-z_][a-z0-9_]*)+:[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$"
)

#: The ``StageSixConfig`` boolean fields (spec D6.20, ``labs/endurance.py``). Held here
#: as data because a runtime module may not import ``labs`` (boundary rule 6); the
#: foundation test joins this tuple to the real dataclass once it exists.
ABLATION_FLAGS: tuple[str, ...] = (
    "independence_check",
    "homeostasis",
    "plasticity_field",
    "half_life",
    "competition",
    "counterfactual_variants",
    "value_aware_rehearsal",
    "drift_discriminator",
    "resurrection",
)

#: The five upstream schema versions Stage 6 is built against, read from
#: ``SCHEMA_REGISTRY`` at ``1.0.0`` in the spec session (§0). Pinned as data so a gate
#: can *join* the table to the registry: if an upstream wave bumps one, the join names
#: the id that moved instead of Stage 6 quietly consuming a new shape.
PINNED_SCHEMAS: Mapping[str, str] = MappingProxyType(
    {
        "pocketsec.ssir_transition.v1": "1.0.0",
        "pocketsec.cbf_resolution.v1": "1.0.0",
        "pocketsec.response_record.v1": "1.0.0",
        "pocketsec.threat_prediction.v1": "1.0.0",
        "pocketsec.security_event_sequence.v1": "1.0.0",
    }
)


class FunctionClass(StrEnum):
    #: The learning boundary cannot operate without this.
    REQUIRED = "REQUIRED"
    #: Experimental. Must justify itself by ablation against its simple control, or go.
    OPTIONAL = "OPTIONAL"


@dataclass(frozen=True, slots=True)
class Stage6Function:
    """One row of spec §4.22: a functional id, where it lives, and how it is ablated."""

    core_id: str
    architecture_id: str
    name: str
    symbol: str
    function_class: FunctionClass
    ablation_flag: str | None
    simple_control: str | None

    def __post_init__(self) -> None:
        if not re.fullmatch(r"HEL-F\d{2}", self.core_id):
            raise ContractError(f"core_id must look like HEL-F01, got {self.core_id!r}")
        if self.architecture_id != "S6-F" + self.core_id[-2:]:
            raise ContractError(
                f"{self.core_id} must map to S6-F{self.core_id[-2:]}, got {self.architecture_id!r}"
            )
        if not SYMBOL_PATTERN.fullmatch(self.symbol):
            raise ContractError(f"{self.core_id}: symbol {self.symbol!r} is not module:qualname")
        if (self.ablation_flag is None) != (self.simple_control is None):
            raise ContractError(f"{self.core_id}: an ablation flag and its control come together")
        if self.ablation_flag is not None and self.ablation_flag not in ABLATION_FLAGS:
            raise ContractError(f"{self.core_id}: unknown ablation flag {self.ablation_flag!r}")
        if self.function_class is FunctionClass.OPTIONAL and self.ablation_flag is None:
            raise ContractError(
                f"{self.core_id} is OPTIONAL with no ablation flag: it could never be removed"
            )


def _row(
    number: int,
    name: str,
    symbol: str,
    function_class: FunctionClass = FunctionClass.REQUIRED,
    ablation: tuple[str, str] | None = None,
) -> Stage6Function:
    """Build one table row; ``symbol`` is relative to ``pocketsec.stage6``."""
    flag, control = ablation if ablation is not None else (None, None)
    return Stage6Function(
        core_id=f"HEL-F{number:02d}",
        architecture_id=f"S6-F{number:02d}",
        name=name,
        symbol=f"pocketsec.stage6.{symbol}",
        function_class=function_class,
        ablation_flag=flag,
        simple_control=control,
    )


_OPTIONAL = FunctionClass.OPTIONAL

#: Spec §4.22, verbatim. The REQUIRED/OPTIONAL split and every control are the spec's.
STAGE6_FUNCTIONS: tuple[Stage6Function, ...] = (
    _row(1, "build_experience_capsule", "capsule.experience_capsule:build_experience_capsule"),
    _row(2, "quarantine_experience", "capsule.quarantine:QuarantineGateway.admit"),
    _row(3, "score_provenance", "provenance.trust:score_provenance"),
    _row(
        4,
        "detect_evidence_dependence",
        "provenance.trust:detect_evidence_dependence",
        ablation=("independence_check", "off"),
    ),
    _row(5, "estimate_poison_suspicion", "homeostasis.poisoning:estimate_poison_suspicion"),
    _row(6, "admit_episode", "memory.episodic:EpisodicMemory.admit_episode"),
    _row(
        7,
        "update_epistemic_half_life",
        "memory.half_life:update_epistemic_half_life",
        _OPTIONAL,
        ("half_life", "LRU"),
    ),
    _row(
        8,
        "compute_plasticity_field",
        "plasticity.field:compute_plasticity_field",
        _OPTIONAL,
        ("plasticity_field", "uniform_mask"),
    ),
    _row(9, "generate_plasticity_mask", "plasticity.masks:generate_plasticity_mask"),
    _row(
        10,
        "compete_knowledge",
        "memory.competition:compete_knowledge",
        _OPTIONAL,
        ("competition", "NEWEST_WINS"),
    ),
    _row(
        11,
        "generate_counterfactual_replay",
        "rehearsal.counterfactual:generate_counterfactual_replay",
        _OPTIONAL,
        ("counterfactual_variants", "plain replay"),
    ),
    _row(12, "create_fossil", "fossils.store:FossilStore.create_fossil"),
    _row(13, "update_lineage_dag", "fossils.lineage:KnowledgeLineageDAG.update_lineage_dag"),
    _row(
        14,
        "spawn_evolution_candidate",
        "chamber.evolution:EvolutionChamber.spawn_evolution_candidate",
    ),
    _row(
        15,
        "consolidate_memory",
        "consolidator.mnemosyne:MnemosyneConsolidator.consolidate_memory",
        _OPTIONAL,
        ("value_aware_rehearsal", "reservoir"),
    ),
    _row(16, "run_shadow_mind", "shadow.mind:ShadowMind.run_shadow_mind"),
    _row(17, "run_conservation_gate", "conservation.gate:offline_validation"),
    _row(
        18,
        "detect_semantic_normalization_attack",
        "homeostasis.poisoning:detect_semantic_normalization_attack",
        ablation=("homeostasis", "Stage 2 anchors only"),
    ),
    _row(
        19,
        "classify_drift_vs_poisoning",
        "homeostasis.drift:classify_drift_vs_poisoning",
        _OPTIONAL,
        ("drift_discriminator", "corroborated change => legitimate"),
    ),
    _row(20, "open_new_epoch", "homeostasis.drift:KnowledgeContextRegistry.open_new_epoch"),
    _row(
        21,
        "resurrect_dormant_knowledge",
        "homeostasis.drift:KnowledgeContextRegistry.resurrect_dormant_knowledge",
        _OPTIONAL,
        ("resurrection", "relearn"),
    ),
    _row(22, "promote_canary", "promotion.controller:LearningPromotionController.promote_canary"),
    _row(
        23, "promote_trusted", "promotion.controller:LearningPromotionController.promote_trusted"
    ),
    _row(
        24,
        "rollback_learning",
        "promotion.controller:LearningPromotionController.rollback_learning",
    ),
    _row(
        25,
        "melt_or_retire_knowledge",
        "consolidator.mnemosyne:MnemosyneConsolidator.melt_or_retire_knowledge",
        _OPTIONAL,
        ("half_life", "LRU retire"),
    ),
    _row(26, "export_learning_record", "export.learning_record:export_learning_record"),
)

_BY_ID: Mapping[str, Stage6Function] = MappingProxyType(
    {function.core_id: function for function in STAGE6_FUNCTIONS}
)

# Import-time invariants: a table that drifts from the architecture fails on import,
# not in a gate run weeks later. Raised rather than asserted so ``-O`` cannot strip them.
if len(_BY_ID) != len(STAGE6_FUNCTIONS) or len(STAGE6_FUNCTIONS) != 26:
    raise ContractError("STAGE6_FUNCTIONS must hold exactly 26 distinct core ids")
if len({function.name for function in STAGE6_FUNCTIONS}) != 26:
    raise ContractError("STAGE6_FUNCTIONS must name 26 distinct functions")


def stage6_function(core_id: str) -> Stage6Function:
    """The row for ``core_id``; a ``ContractError`` for an id the architecture never named."""
    try:
        return _BY_ID[core_id]
    except KeyError:
        raise ContractError(f"unknown Stage 6 core id {core_id!r}") from None


def optional_functions() -> tuple[Stage6Function, ...]:
    """Every row a measured ablation may delete, in table order."""
    return tuple(f for f in STAGE6_FUNCTIONS if f.function_class is FunctionClass.OPTIONAL)


def symbol_problem(symbol: str) -> str | None:
    """Why ``symbol`` does not resolve, or ``None`` when it does.

    Importing the module is the test: a module that exists but raises on import is as
    unusable as one that does not exist, so the exception text becomes the reason
    rather than propagating into the caller's report. Only a string that matches
    :data:`SYMBOL_PATTERN` is looked up — this function never imports an arbitrary
    dotted path handed to it.
    """
    if not SYMBOL_PATTERN.fullmatch(symbol):
        return "malformed: not pocketsec.stage6.<module>:<qualname>"
    module_name, qualname = symbol.split(":", 1)
    try:
        target: object = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        return f"module not found: {exc.name}"
    except Exception as exc:  # another package's module raising on import
        return f"module raises on import: {type(exc).__name__}: {exc}"
    for part in qualname.split("."):
        if not hasattr(target, part):
            return f"{module_name} has no attribute {qualname!r}"
        target = getattr(target, part)
    if not callable(target):
        return f"{symbol} resolves to a non-callable {type(target).__name__}"
    return None


def resolve_symbols() -> tuple[str, ...]:
    """Symbols of :data:`STAGE6_FUNCTIONS` that fail to resolve; ``()`` = all resolve."""
    return tuple(f.symbol for f in STAGE6_FUNCTIONS if symbol_problem(f.symbol) is not None)


def pinned_schema_drift() -> tuple[str, ...]:
    """Pinned upstream schemas whose registered version differs from :data:`PINNED_SCHEMAS`.

    The registering modules are imported here, inside the function, so importing this
    module never drags Stages 4 and 5 in; both imports are the allow-listed handoff
    modules (spec §2.5). An id that is not registered at all is reported as drift too:
    a pin against nothing pins nothing.
    """
    import pocketsec.stage0.contracts.security_event_v1
    import pocketsec.stage0.contracts.threat_prediction_v1
    import pocketsec.stage1.ssir.transition
    import pocketsec.stage4.stage5_interface
    import pocketsec.stage5.stage6_interface  # noqa: F401
    from pocketsec.stage0.contracts.common import SCHEMA_REGISTRY

    return tuple(
        f"{schema_id}: pinned {version}, registered {SCHEMA_REGISTRY.get(schema_id)}"
        for schema_id, version in sorted(PINNED_SCHEMAS.items())
        if SCHEMA_REGISTRY.get(schema_id) != version
    )
