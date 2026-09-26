"""D6.1 — the Learning Constitution: what Stage 6 may learn from, and what it may never forget.

Stage 6 is where learning is allowed to change **trusted** state, which makes learning a
privileged operation in the same sense a Stage 5 action is (architecture §2): an attacker
who controls what the endpoint learns controls what it ignores next month. This module
turns the architecture's prose laws into data the rest of the stage — and the gate — can
check. It holds no state, performs no learning and grants nothing.

Five things live here, each refusing something specific:

**The five laws** (:data:`LEARNING_CONSTITUTION`). Each law is bound to the one symbol
that enforces it and the one test whose name says it. A law bound to a symbol that does
not exist is a docstring, so :func:`verify_constitution` resolves every binding lazily
and G6.1 fails on any non-empty answer. The bindings are strings resolved on demand
because the enforcing modules are built by other work packages, in parallel.

**The conservation terms** (:class:`ConservationTerm`). Architecture §3's six conjuncts,
each bound to the conservation-gate check(s) that measure it. "Conservation" is an
engineering law here, not a physical one; the binding is what makes it checkable.

**The lifecycle machine** (:data:`ALLOWED_TRANSITIONS`). Architecture §42 exactly.
``CANDIDATE → TRUSTED`` is absent on purpose: a candidate reaches trust only through
offline validation, shadow and canary, in that order, and :func:`require_transition`
refuses every shortcut with a ``ContractError``.

**The timescales** (:data:`TIMESCALES`). "Different timescales must not share the same
learning rule" (§4), so each names exactly one update-rule symbol, and two sharing one
fails on import.

**The protected anchors** (:data:`PROTECTED_ANCHORS`). Architecture §21's semantic
homeostasis: baseline *frequency* may adapt, protected *meaning* never adapts merely
from frequency. The anchors generalise Stage 2's escalation rule
(``stage2.adaptation.quarantine.ESCALATION_PROPERTIES``) and may never be narrower
than it — enforced on import, because a homeostasis layer that forgot one of Stage 2's
four properties would quietly re-open a path Stage 2 had closed. Masks are derived from
the encoder's own ``feature_names()`` labels exactly as Stage 2 derives its escalation
mask, never from hard-coded bit indices: a magic index into a frozen layout points at
the wrong property the moment the layout grows.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from pocketsec.stage0.contracts.common import ContractError, require_identifier
from pocketsec.stage1.ssir.entities import SemanticProperty
from pocketsec.stage1.state.security_state import DIMENSIONS
from pocketsec.stage2.adaptation.quarantine import ESCALATION_PROPERTIES
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_LAYOUT, GROUP_OFFSETS, feature_names
from pocketsec.stage6.core_ids import SYMBOL_PATTERN, symbol_problem

__all__ = [
    "ALLOWED_TRANSITIONS",
    "CONSERVATION_CHECKS",
    "CONSERVATION_CHECK_NAMES",
    "CONSERVATION_UPSTREAM",
    "LEARNING_CONSTITUTION",
    "MIN_INDEPENDENT_GROUPS",
    "MIN_INDEPENDENT_LABEL_GROUPS",
    "PROTECTED_ANCHORS",
    "TERMINAL_STATES",
    "TESTED_BY_PATTERN",
    "TIMESCALES",
    "ConservationTerm",
    "LawBinding",
    "LearningLaw",
    "LifecycleState",
    "ProtectedAnchor",
    "Timescale",
    "property_mask",
    "raised_mask",
    "require_transition",
    "touches_protected",
    "verify_conservation_terms",
    "verify_constitution",
    "verify_timescales",
]

#: Normality: a pattern must be observed from at least this many distinct independence
#: groups before Stage 2's controller is even asked (ADR-0054). Stage 2's gate promotes
#: one source's escalation-free repetition once it spans two corroborated epochs
#: (spec §0: 3 promotions in the probe) because ``AdaptationSample`` carries no source.
#: Chosen, not measured.
MIN_INDEPENDENT_GROUPS: int = 3

#: Threat learning: distinct groups that must assert MALICIOUS before a label counts.
#: One analyst, however many episodes they label, is one vote. Chosen, not measured.
MIN_INDEPENDENT_LABEL_GROUPS: int = 2

#: ``tests/test_stage6_<package>.py::test_<name>`` — a law names a test in this stage.
TESTED_BY_PATTERN = re.compile(r"^tests/test_stage6_[a-z0-9_]+\.py::test_[a-z0-9_]+$")

_S6 = "pocketsec.stage6."


class LearningLaw(StrEnum):
    """Architecture §2, one member per inequality."""

    RAW_TELEMETRY_IS_NOT_TRAINING_DATA = "RAW_TELEMETRY_IS_NOT_TRAINING_DATA"
    REPETITION_IS_NOT_TRUTH = "REPETITION_IS_NOT_TRUTH"
    MODEL_SCORE_IS_NOT_KNOWLEDGE = "MODEL_SCORE_IS_NOT_KNOWLEDGE"
    NOVELTY_IS_NOT_PERMISSION_TO_ADAPT = "NOVELTY_IS_NOT_PERMISSION_TO_ADAPT"
    SUCCESS_IS_NOT_PERMISSION_TO_FORGET = "SUCCESS_IS_NOT_PERMISSION_TO_FORGET"


@dataclass(frozen=True, slots=True)
class LawBinding:
    """One law, the symbol that enforces it, and the test that proves the symbol does."""

    law: LearningLaw
    enforced_by: str
    tested_by: str
    statement: str

    def __post_init__(self) -> None:
        if not isinstance(self.law, LearningLaw):
            raise ContractError(f"LawBinding.law must be a LearningLaw, got {self.law!r}")
        if not SYMBOL_PATTERN.fullmatch(self.enforced_by):
            raise ContractError(
                f"{self.law}: enforced_by {self.enforced_by!r} is not pocketsec.stage6.<m>:<q>"
            )
        if not TESTED_BY_PATTERN.fullmatch(self.tested_by):
            raise ContractError(f"{self.law}: tested_by {self.tested_by!r} is not a test id")
        if not self.statement.strip():
            raise ContractError(f"{self.law}: a law with no statement binds nothing")


#: Architecture §2, one binding per law. ``enforced_by`` is the spec §4.22 symbol; the
#: ``tested_by`` names are the ones the owning packages' test files must define (the
#: foundation test lists every one not yet present, for the integrator to clear).
LEARNING_CONSTITUTION: tuple[LawBinding, ...] = (
    LawBinding(
        LearningLaw.RAW_TELEMETRY_IS_NOT_TRAINING_DATA,
        _S6 + "capsule.quarantine:QuarantineGateway.admit",
        "tests/test_stage6_gateway.py::test_a_sample_injected_straight_from_telemetry_is_refused",
        "Raw telemetry is not training data: nothing reaches learning except an "
        "ExperienceCapsuleV1 the quarantine gateway admitted and minted a verdict for.",
    ),
    LawBinding(
        LearningLaw.REPETITION_IS_NOT_TRUTH,
        _S6 + "provenance.trust:detect_evidence_dependence",
        "tests/test_stage6_capsule.py::test_repetition_from_one_independence_group_counts_once",
        "Repetition is not truth: observations sharing an independence group or evidence "
        "count as one vote, however many times they recur.",
    ),
    LawBinding(
        LearningLaw.MODEL_SCORE_IS_NOT_KNOWLEDGE,
        _S6 + "conservation.gate:offline_validation",
        "tests/test_stage6_promotion.py::test_a_candidate_is_not_promoted_on_score_alone",
        "A model score is not knowledge: a candidate becomes trusted only after offline "
        "validation, shadow and canary, never because it scores well.",
    ),
    LawBinding(
        LearningLaw.NOVELTY_IS_NOT_PERMISSION_TO_ADAPT,
        _S6 + "homeostasis.poisoning:detect_semantic_normalization_attack",
        "tests/test_stage6_gateway.py::test_protected_meaning_does_not_adapt_from_frequency",
        "Novelty is not permission to adapt: baseline frequency may adapt, protected "
        "semantic meaning never adapts merely from frequency.",
    ),
    LawBinding(
        LearningLaw.SUCCESS_IS_NOT_PERMISSION_TO_FORGET,
        _S6 + "conservation.gate:offline_validation",
        "tests/test_stage6_promotion.py::test_a_candidate_that_forgets_a_historical_detection_is_refused",
        "Success on new data is not permission to forget an old security capability: a "
        "candidate that loses historical recall beyond EPS_SECURITY is refused.",
    ),
)

if {binding.law for binding in LEARNING_CONSTITUTION} != set(LearningLaw) or len(
    LEARNING_CONSTITUTION
) != len(LearningLaw):
    raise ContractError("LEARNING_CONSTITUTION must bind every LearningLaw exactly once")


def verify_constitution() -> tuple[str, ...]:
    """``enforced_by`` symbols that do not resolve; ``()`` means every law has an enforcer.

    Resolved with :mod:`importlib` at call time, never at import, so this module loads
    while the enforcing packages are still being built. A non-empty answer is a G6.1
    failure: a law whose enforcer does not exist is enforced by nothing.
    """
    return tuple(
        binding.enforced_by
        for binding in LEARNING_CONSTITUTION
        if symbol_problem(binding.enforced_by) is not None
    )


# --- architecture §3: the conservation law ----------------------------------


class ConservationTerm(StrEnum):
    """Architecture §3's six conjuncts of ``Promote(ΔK)``."""

    NEW_UTILITY = "NEW_UTILITY"
    HISTORICAL_SECURITY_LOSS = "HISTORICAL_SECURITY_LOSS"
    SAFETY_INVARIANT_LOSS = "SAFETY_INVARIANT_LOSS"
    POISON_RISK = "POISON_RISK"
    RESOURCE_GROWTH = "RESOURCE_GROWTH"
    ROLLBACK_STATE_EXISTS = "ROLLBACK_STATE_EXISTS"


#: The nine ``conservation.gate.ConservationCheck`` names of spec D6.14, as strings so
#: this module does not import the gate. :func:`verify_conservation_terms` joins this
#: tuple to the real enum once it exists; a rename on either side fails there.
CONSERVATION_CHECK_NAMES: tuple[str, ...] = (
    "G1_INTEGRITY",
    "G2_HISTORICAL_REPLAY",
    "G3_CURRENT_HOLDOUT",
    "G4_COUNTERFACTUAL",
    "G5_ADVERSARIAL",
    "G6_CALIBRATION",
    "G7_RESOURCE",
    "G8_SHADOW",
    "G9_ROLLBACK",
)

#: Which conservation check measures each term (spec D6.1).
CONSERVATION_CHECKS: Mapping[ConservationTerm, tuple[str, ...]] = MappingProxyType(
    {
        ConservationTerm.NEW_UTILITY: ("G3_CURRENT_HOLDOUT",),
        ConservationTerm.HISTORICAL_SECURITY_LOSS: ("G2_HISTORICAL_REPLAY",),
        ConservationTerm.SAFETY_INVARIANT_LOSS: ("G5_ADVERSARIAL",),
        ConservationTerm.POISON_RISK: ("G5_ADVERSARIAL",),
        ConservationTerm.RESOURCE_GROWTH: ("G7_RESOURCE",),
        ConservationTerm.ROLLBACK_STATE_EXISTS: ("G9_ROLLBACK",),
    }
)

#: The two terms the gate alone does not carry: poison risk is also scored at the
#: gateway, before a candidate exists, and safety-invariant loss is also watched by
#: homeostasis. Spec D6.1: "gateway suspicion + G5" and "G5 (+ homeostasis)".
CONSERVATION_UPSTREAM: Mapping[ConservationTerm, str] = MappingProxyType(
    {
        ConservationTerm.POISON_RISK: _S6 + "homeostasis.poisoning:estimate_poison_suspicion",
        ConservationTerm.SAFETY_INVARIANT_LOSS: (
            _S6 + "homeostasis.poisoning:detect_semantic_normalization_attack"
        ),
    }
)

if set(CONSERVATION_CHECKS) != set(ConservationTerm) or not all(
    checks and set(checks) <= set(CONSERVATION_CHECK_NAMES)
    for checks in CONSERVATION_CHECKS.values()
):
    raise ContractError("every ConservationTerm must bind to at least one known check")


def verify_conservation_terms() -> tuple[str, ...]:
    """Problems joining the terms to the real gate; ``()`` means every binding holds.

    Lazily imports ``conservation.gate`` (another package's module) and reports rather
    than raises when it is absent, so the answer is data a gate can print.
    """
    problems: list[str] = []
    gate_symbol = _S6 + "conservation.gate:offline_validation"
    reason = symbol_problem(gate_symbol)
    if reason is not None:
        problems.append(f"{gate_symbol}: {reason}")
    else:
        import importlib

        gate = importlib.import_module(_S6 + "conservation.gate")
        enum = getattr(gate, "ConservationCheck", None)
        names = tuple(member.name for member in enum) if enum is not None else ()
        if names != CONSERVATION_CHECK_NAMES:
            problems.append(f"ConservationCheck is {names}, expected {CONSERVATION_CHECK_NAMES}")
    for term, symbol in CONSERVATION_UPSTREAM.items():
        reason = symbol_problem(symbol)
        if reason is not None:
            problems.append(f"{term}: {symbol}: {reason}")
    return tuple(problems)


# --- architecture §42: the promotion state machine --------------------------


class LifecycleState(StrEnum):
    """Architecture §42, exactly eleven states."""

    QUARANTINED = "QUARANTINED"
    CANDIDATE = "CANDIDATE"
    OFFLINE_VALIDATED = "OFFLINE_VALIDATED"
    SHADOW = "SHADOW"
    CANARY = "CANARY"
    TRUSTED = "TRUSTED"
    DORMANT = "DORMANT"
    FOSSILIZED = "FOSSILIZED"
    RETIRED = "RETIRED"
    REJECTED = "REJECTED"
    ROLLED_BACK = "ROLLED_BACK"


_S = LifecycleState

#: "Any stage may → REJECTED; any promoted stage may → ROLLBACK" (§42), and nothing
#: else. There is no edge that skips a gate and no edge out of a terminal state: a
#: rejected or rolled-back candidate is re-submitted as a *new* candidate with its own
#: lineage, never resurrected in place.
ALLOWED_TRANSITIONS: Mapping[LifecycleState, frozenset[LifecycleState]] = MappingProxyType(
    {
        _S.QUARANTINED: frozenset({_S.CANDIDATE, _S.REJECTED}),
        _S.CANDIDATE: frozenset({_S.OFFLINE_VALIDATED, _S.REJECTED}),
        _S.OFFLINE_VALIDATED: frozenset({_S.SHADOW, _S.REJECTED}),
        _S.SHADOW: frozenset({_S.CANARY, _S.REJECTED}),
        _S.CANARY: frozenset({_S.TRUSTED, _S.REJECTED}),
        _S.TRUSTED: frozenset({_S.DORMANT, _S.FOSSILIZED, _S.RETIRED, _S.ROLLED_BACK}),
        _S.DORMANT: frozenset({_S.TRUSTED, _S.FOSSILIZED, _S.RETIRED, _S.ROLLED_BACK}),
        _S.FOSSILIZED: frozenset({_S.RETIRED}),
        _S.RETIRED: frozenset(),
        _S.REJECTED: frozenset(),
        _S.ROLLED_BACK: frozenset(),
    }
)

TERMINAL_STATES: frozenset[LifecycleState] = frozenset(
    state for state, targets in ALLOWED_TRANSITIONS.items() if not targets
)

if set(ALLOWED_TRANSITIONS) != set(LifecycleState):
    raise ContractError("ALLOWED_TRANSITIONS must define every LifecycleState")


def require_transition(current: LifecycleState, target: LifecycleState) -> None:
    """Refuse any lifecycle move §42 does not draw. Returns ``None`` when it is allowed.

    Plain strings are refused even when they spell a member: a caller that built a
    state from untrusted text should have to say so by constructing the enum.
    """
    for label, value in (("current", current), ("target", target)):
        if not isinstance(value, LifecycleState):
            raise ContractError(f"require_transition: {label} must be a LifecycleState")
    if target not in ALLOWED_TRANSITIONS[current]:
        allowed = sorted(state.value for state in ALLOWED_TRANSITIONS[current])
        raise ContractError(
            f"lifecycle transition {current.value} -> {target.value} is not allowed; "
            f"{current.value} may move only to {allowed}"
        )


# --- architecture §4: multi-timescale cognition ------------------------------


class Timescale(StrEnum):
    """Architecture §4's six rows, from milliseconds to years."""

    WORKING = "WORKING"
    HOST_BASELINE = "HOST_BASELINE"
    EPISODIC = "EPISODIC"
    SEMANTIC = "SEMANTIC"
    STRUCTURAL = "STRUCTURAL"
    ARCHAEOLOGY = "ARCHAEOLOGY"


#: One update rule per timescale. Two rows are not Stage 6 symbols and say so in the
#: value: working state is Stage 1's volatile state, and no structural candidate kind
#: exists because nothing could execute one (ADR-0056).
TIMESCALES: Mapping[Timescale, str] = MappingProxyType(
    {
        Timescale.WORKING: "stage1 (volatile, not Stage 6)",
        Timescale.HOST_BASELINE: _S6 + "capsule.quarantine:QuarantineGateway.admit",
        Timescale.EPISODIC: _S6 + "memory.episodic:EpisodicMemory.admit_episode",
        Timescale.SEMANTIC: (
            _S6 + "promotion.controller:LearningPromotionController.promote_trusted"
        ),
        Timescale.STRUCTURAL: "UNMEASURED: no structural candidate kind exists (ADR-0056)",
        Timescale.ARCHAEOLOGY: (
            _S6 + "consolidator.mnemosyne:MnemosyneConsolidator.consolidate_memory"
        ),
    }
)

if set(TIMESCALES) != set(Timescale) or len(set(TIMESCALES.values())) != len(TIMESCALES):
    raise ContractError("each Timescale needs its own update rule (§4)")


def verify_timescales() -> tuple[str, ...]:
    """Timescale rules that name a Stage 6 symbol which does not resolve."""
    return tuple(
        rule
        for rule in TIMESCALES.values()
        if SYMBOL_PATTERN.fullmatch(rule) and symbol_problem(rule) is not None
    )


# --- architecture §21: semantic homeostasis ----------------------------------

_NAMES = feature_names()


def _group_labels(group: str) -> tuple[str, ...]:
    offset = GROUP_OFFSETS[group]
    return _NAMES[offset : offset + dict(FEATURE_LAYOUT)[group]]


_OBJECT_LABELS: tuple[str, ...] = _group_labels("object_semantics")
_RAISED_LABELS: tuple[str, ...] = _group_labels("state_delta_raised")
_OBJECT_WIDTH_MASK: int = (1 << len(_OBJECT_LABELS)) - 1
_RAISED_WIDTH_MASK: int = (1 << len(_RAISED_LABELS)) - 1


def property_mask(properties: Iterable[SemanticProperty]) -> int:
    """Bits of ``properties`` inside an ``object_property_mask``.

    The bit order is the encoder's object-semantics group order, read from
    ``feature_names()``'s ``"object.<P>"`` labels — the derivation
    ``stage2.adaptation.quarantine._mask_from_properties`` uses, so the two masks agree
    by construction rather than by coincidence.
    """
    mask = 0
    for prop in properties:
        if not isinstance(prop, SemanticProperty):
            raise ContractError(f"property_mask takes SemanticProperty members, got {prop!r}")
        label = f"object.{prop.value}"
        if label not in _OBJECT_LABELS:
            raise ContractError(f"{label!r} is not in the encoder's object-semantics group")
        mask |= 1 << _OBJECT_LABELS.index(label)
    return mask


def raised_mask(dimensions: Iterable[str]) -> int:
    """Bits of ``dimensions`` inside a ``state_delta_mask``, from ``"raised.<dim>"`` labels."""
    mask = 0
    for dimension in dimensions:
        label = f"raised.{dimension}"
        if label not in _RAISED_LABELS:
            raise ContractError(f"{dimension!r} is not a raised-dimension label of the encoder")
        mask |= 1 << _RAISED_LABELS.index(label)
    return mask


@dataclass(frozen=True, slots=True)
class ProtectedAnchor:
    """One protected meaning (§21). ``structural`` anchors hold by construction, not masks."""

    anchor_id: str
    properties: frozenset[SemanticProperty]
    dimensions: frozenset[str]
    structural: bool
    rationale: str

    def __post_init__(self) -> None:
        require_identifier(self.anchor_id, "ProtectedAnchor.anchor_id")
        object.__setattr__(self, "properties", frozenset(self.properties))
        object.__setattr__(self, "dimensions", frozenset(self.dimensions))
        unknown = sorted(self.dimensions - set(DIMENSIONS))
        if unknown:
            raise ContractError(f"{self.anchor_id}: unknown dimensions {unknown}")
        if any(not isinstance(prop, SemanticProperty) for prop in self.properties):
            raise ContractError(f"{self.anchor_id}: properties must be SemanticProperty members")
        has_masks = bool(self.properties or self.dimensions)
        if self.structural == has_masks:
            raise ContractError(
                f"{self.anchor_id}: a structural anchor carries no masks and a mask anchor "
                "carries at least one property or dimension"
            )
        if not self.rationale.strip():
            raise ContractError(f"{self.anchor_id}: an anchor needs a rationale")

    def matches(self, object_property_mask: int, state_delta_mask: int) -> bool:
        """Whether a step touches this anchor. Structural anchors never match a step."""
        if self.structural:
            return False
        return bool(
            object_property_mask & property_mask(self.properties)
            or state_delta_mask & raised_mask(self.dimensions)
        )


_P = SemanticProperty

#: Architecture §21, bound by spec D6.1. Order is the spec's; ids are what
#: :func:`touches_protected` returns and what a ``NormalizationFinding`` cites.
PROTECTED_ANCHORS: tuple[ProtectedAnchor, ...] = (
    ProtectedAnchor(
        "privilege_boundary", frozenset(), frozenset({"privilege"}), False,
        "A privilege raise is never baseline behaviour, however often it recurs.",
    ),
    ProtectedAnchor(
        "credential_material", frozenset({_P.CREDENTIAL, _P.CREDENTIAL_READER}),
        frozenset({"credential"}), False,
        "Credential access is the precondition of the egress families; it may not normalise.",
    ),
    ProtectedAnchor(
        "authorization_material", frozenset({_P.AUTHORIZATION_DATA}), frozenset(), False,
        "Authorisation data defines who may do what; its meaning is fixed.",
    ),
    ProtectedAnchor(
        "executable_trust", frozenset(), frozenset({"execution", "trust"}), False,
        "What may execute, and what is trusted to, is an executable trust boundary.",
    ),
    ProtectedAnchor(
        "persistence", frozenset({_P.PERSISTENCE, _P.PERSISTENCE_WRITER}),
        frozenset({"persistence"}), False,
        "Persistence outlives the session that created it; repetition does not make it benign.",
    ),
    ProtectedAnchor(
        "external_egress", frozenset({_P.EXTERNAL_ENDPOINT}), frozenset({"reachability"}), False,
        "Reaching outside the host is how data leaves; the slow-drip adversary needs it normal.",
    ),
    ProtectedAnchor(
        "evidence_integrity", frozenset(), frozenset(), True,
        "No candidate alters a rehearsal exemplar's evidence or lineage (conservation G1).",
    ),
    ProtectedAnchor(
        "response_authority", frozenset(), frozenset(), True,
        "No learned object carries response authority: T5 field screen, and no Stage 5 "
        "import except stage6_interface.",
    ),
)

if len({anchor.anchor_id for anchor in PROTECTED_ANCHORS}) != len(PROTECTED_ANCHORS):
    raise ContractError("PROTECTED_ANCHORS ids must be unique")

#: Stage 6 generalises Stage 2's escalation rule and may never be narrower than it.
_ANCHOR_PROPERTIES = frozenset().union(*(anchor.properties for anchor in PROTECTED_ANCHORS))
if not set(ESCALATION_PROPERTIES) <= _ANCHOR_PROPERTIES:
    raise ContractError(
        "PROTECTED_ANCHORS no longer cover Stage 2's ESCALATION_PROPERTIES: "
        f"missing {sorted(p.value for p in set(ESCALATION_PROPERTIES) - _ANCHOR_PROPERTIES)}"
    )


def _require_mask(value: int, width_mask: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractError(f"{label} must be an int bitmask, got {type(value).__name__}")
    if value < 0 or value & ~width_mask:
        raise ContractError(f"{label}={value} sets bits outside the encoder's group width")


def touches_protected(object_property_mask: int, state_delta_mask: int) -> tuple[str, ...]:
    """Sorted ids of the mask anchors a step touches; ``()`` means it touches none.

    A malformed mask — negative, or with a bit outside the encoder's group — raises
    rather than being truncated: silently dropping an unknown bit would make an
    unrecognised meaning look unprotected, which is the failure this function exists
    to prevent.
    """
    _require_mask(object_property_mask, _OBJECT_WIDTH_MASK, "object_property_mask")
    _require_mask(state_delta_mask, _RAISED_WIDTH_MASK, "state_delta_mask")
    return tuple(
        sorted(
            anchor.anchor_id
            for anchor in PROTECTED_ANCHORS
            if anchor.matches(object_property_mask, state_delta_mask)
        )
    )
