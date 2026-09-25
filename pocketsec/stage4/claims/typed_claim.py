"""D4.13 part one — the six epistemic claim kinds, separated by construction.

Architecture §22 gives Stage 4 an epistemic type system: OBS / DER / INF / CF /
EXT / UNK. This module is the reason "the authoritative output contains zero
unsupported factual claims" (G4.8) is a graph walk rather than a promise.

**Why six frozen dataclasses and not one class with a ``kind: str`` field.** A
tagged union with a string tag is enforced by convention. Nothing stops
``ObservedClaim(kind="OBS", evidence=())`` from being handed an inference's
content, and the only thing standing between that object and an authoritative
output is a reviewer noticing. Six classes with kind-specific ``__post_init__``
refusals make the illegal state *unconstructable*: an observation without
evidence, a derivation resting on an inference, an unknown carrying evidence —
none of them exist as values. ``TypedClaim`` is a ``|`` union so ``mypy
--strict`` is exhaustive over it, and ``AUTHORITATIVE_KINDS`` /
``DERIVABLE_FROM`` are the *only* place the emission policy is written down.
ADR-0031 records the decision.

What this module refuses to do:

* it never lets a claim assert a kind its class does not hold — ``kind`` is
  derived from the class, and a text carrying a contradicting ``[KIND]`` marker
  is refused;
* it never accepts an observation without at least one ``EvidenceRef`` whose
  digest matches ``^sha256:[0-9a-f]{64}$`` — an OBS claim nothing can be traced
  back to is an inference wearing a costume;
* it never inlines raw evidence (Stage 0 invariant): evidence is *referenced*;
* it never imports ``pocketsec.stage4.counterfactual`` at runtime. ``CF`` needs
  the ``Intervention`` type from another work package, so it is typed under
  ``TYPE_CHECKING`` and validated structurally through ``InterventionLike``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, ClassVar, Protocol, runtime_checkable

from pocketsec.stage0.contracts.common import (
    ContractError,
    EvidenceRef,
    register_schema,
    require_finite_unit_interval,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage1.telemetry.raw_event_v1 import SensorPath

if TYPE_CHECKING:  # pragma: no cover - typing only, never imported at runtime
    from pocketsec.stage4.counterfactual.intervention import Intervention

__all__ = [
    "AUTHORITATIVE_KINDS",
    "DERIVABLE_FROM",
    "KNOWLEDGE_SOURCES",
    "MAX_CLAIM_TEXT",
    "MAX_PREMISES_PER_CLAIM",
    "MAX_SUBJECT_LENGTH",
    "TYPED_CLAIM_V1_ID",
    "TYPED_CLAIM_V1_VERSION",
    "UNKNOWN_REASONS",
    "ClaimKind",
    "CounterfactualClaim",
    "DerivedClaim",
    "ExternalClaim",
    "InferredClaim",
    "InterventionLike",
    "ObservedClaim",
    "TypedClaim",
    "UnknownClaim",
    "is_authoritative_kind",
    "kind_of",
    "sensor_of_evidence",
]

TYPED_CLAIM_V1_ID = "pocketsec.typed_claim.v1"
TYPED_CLAIM_V1_VERSION = register_schema(TYPED_CLAIM_V1_ID, "1.0.0")

#: Upper bound on a claim's rendered text. A claim is a sentence, not a report;
#: an unbounded string on an endpoint with a 2 GB target is an unbounded buffer.
MAX_CLAIM_TEXT = 240
#: Upper bound on direct premises. Combined with ``MAX_CLAIM_DEPTH`` in
#: ``graph.py`` this bounds the premise-chain walk that G4.8 performs.
MAX_PREMISES_PER_CLAIM = 8
MAX_SUBJECT_LENGTH = 128

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SUBJECT_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:/\-]{0,127}$")
_KIND_MARKER_RE = re.compile(r"^\s*\[([A-Z]{3})\]")
#: ``RawEventV1.evidence_ref()`` writes ``store="raw.<sensor>"``, so the sensor
#: that saw a record is recoverable from its evidence reference. Matching that
#: convention is why ``sensor_of_evidence`` can refuse rather than guess.
_EVIDENCE_STORE_PREFIX = "raw."


class ClaimKind(StrEnum):
    """Architecture §22's epistemic types. Closed, and ordered by trust."""

    OBS = "OBS"
    DER = "DER"
    INF = "INF"
    CF = "CF"
    EXT = "EXT"
    UNK = "UNK"


#: Kinds that may appear in an authoritative output. Closed, and the only place
#: this policy is written down. An INF or CF claim can never be emitted as
#: authoritative, whatever its support.
AUTHORITATIVE_KINDS: frozenset[ClaimKind] = frozenset({ClaimKind.OBS, ClaimKind.DER})

#: Kinds that may be a premise of a ``DerivedClaim``. A DER chain must root in
#: OBS, so "deterministic derivation" cannot quietly become "derived from a
#: model's guess".
DERIVABLE_FROM: frozenset[ClaimKind] = frozenset({ClaimKind.OBS, ClaimKind.DER})

#: §33's closed adapter list: external knowledge constrains and names, it never
#: decides. The set is closed so a fourth source arrives with a spec change
#: rather than a free-text string nobody audits.
KNOWLEDGE_SOURCES: frozenset[str] = frozenset({"attack", "sigma", "local"})

#: Why something is unknown. Closed for the same reason Stage 4 reuses Stage 0's
#: ``Verdict`` instead of inventing a parallel vocabulary (ADR-0032).
UNKNOWN_REASONS: frozenset[str] = frozenset(
    {"shadowed", "not_observed", "insufficient_evidence"}
)


def _require_text(value: object, field: str, kind: ClaimKind) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{field} must be a non-empty string, got {value!r}")
    if len(value) > MAX_CLAIM_TEXT:
        raise ContractError(f"{field} must be <= {MAX_CLAIM_TEXT} chars, got {len(value)}")
    marker = _KIND_MARKER_RE.match(value)
    if marker is not None and marker.group(1) != kind.value:
        # A claim whose own text announces a different kind is the cheapest
        # laundering attempt available, so it is refused at construction.
        raise ContractError(
            f"{field} carries marker [{marker.group(1)}] but the claim is {kind.value}"
        )
    return value


def _require_subject(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SUBJECT_RE.fullmatch(value):
        raise ContractError(
            f"{field} must be a 1-{MAX_SUBJECT_LENGTH} char DIMENSIONS key, signal name "
            f"or causal signature, got {value!r}"
        )
    return value


def _require_premises(value: object, field: str, owner: str) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise ContractError(f"{field} must be a tuple, got {type(value).__name__}")
    if len(value) > MAX_PREMISES_PER_CLAIM:
        raise ContractError(f"{field} must hold <= {MAX_PREMISES_PER_CLAIM}, got {len(value)}")
    seen: set[str] = set()
    for premise in value:
        require_identifier(premise, f"{field} entry")
        if premise == owner:
            raise ContractError(f"{field} must not contain the claim's own id {owner!r}")
        if premise in seen:
            raise ContractError(f"{field} must not repeat premise {premise!r}")
        seen.add(premise)
    return value


def _require_evidence(value: object, field: str) -> tuple[EvidenceRef, ...]:
    if not isinstance(value, tuple):
        raise ContractError(f"{field} must be a tuple, got {type(value).__name__}")
    for ref in value:
        if not isinstance(ref, EvidenceRef):
            raise ContractError(f"{field} entries must be EvidenceRef, got {type(ref).__name__}")
        # EvidenceRef validates its own digest; re-checking here is deliberate
        # defence in depth, because G4.8 reads this predicate and a duck-typed
        # stand-in must not be able to satisfy it.
        if not _DIGEST_RE.fullmatch(ref.digest):
            raise ContractError(
                f"{field} digest must match sha256:<64 hex>, got {ref.digest!r}"
            )
    return value


def _require_unit(value: object, field: str) -> float:
    return require_finite_unit_interval(value, field)


@runtime_checkable
class InterventionLike(Protocol):
    """The narrow shape ``CounterfactualClaim`` needs from an intervention.

    ``claims`` must not import ``pocketsec.stage4.counterfactual`` at runtime —
    that package consumes this one — so the dependency is structural. The real
    ``Intervention`` satisfies it; ``_intervention_conforms`` below is what makes
    mypy check that claim rather than trusting this docstring.
    """

    @property
    def kind(self) -> object: ...

    @property
    def target_signature(self) -> str: ...


if TYPE_CHECKING:  # pragma: no cover - a compile-time conformance assertion

    def _intervention_conforms(value: Intervention) -> InterventionLike:
        return value


@dataclass(frozen=True, slots=True, kw_only=True)
class _ClaimBase:
    """Fields and refusals every claim kind shares.

    Abstract: ``_KIND`` is unset here and ``__post_init__`` refuses to build the
    base directly, because a claim with no kind is exactly the untyped record
    this module exists to make impossible.
    """

    _KIND: ClassVar[ClaimKind | None] = None

    claim_id: str
    subject: str
    text: str
    premises: tuple[str, ...] = ()
    evidence: tuple[EvidenceRef, ...] = ()

    def __post_init__(self) -> None:
        kind = type(self)._KIND
        if kind is None:
            raise ContractError(
                "_ClaimBase is abstract; construct one of the six ClaimKind classes"
            )
        name = type(self).__name__
        require_identifier(self.claim_id, f"{name}.claim_id")
        _require_subject(self.subject, f"{name}.subject")
        _require_text(self.text, f"{name}.text", kind)
        object.__setattr__(self, "premises", tuple(self.premises))
        object.__setattr__(self, "evidence", tuple(self.evidence))
        _require_premises(self.premises, f"{name}.premises", self.claim_id)
        _require_evidence(self.evidence, f"{name}.evidence")

    @property
    def kind(self) -> ClaimKind:
        kind = type(self)._KIND
        if kind is None:  # pragma: no cover - __post_init__ refuses the base
            raise ContractError(f"{type(self).__name__} declares no ClaimKind")
        return kind


@dataclass(frozen=True, slots=True, kw_only=True)
class ObservedClaim(_ClaimBase):
    """OBS — something a named sensor actually saw, at a named sequence point.

    Refuses empty evidence, any premises, and any digest that is not a canonical
    ``sha256:``. An observation is the only place a fact enters the system, so it
    is the only place that must be un-fakeable: no evidence means no OBS, and a
    premise would mean it was reasoned to rather than seen.
    """

    _KIND: ClassVar[ClaimKind] = ClaimKind.OBS

    sensor: SensorPath
    at_sequence: int

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.sensor, SensorPath):
            raise ContractError(f"ObservedClaim.sensor must be a SensorPath, got {self.sensor!r}")
        require_non_negative_int(self.at_sequence, "ObservedClaim.at_sequence")
        if not self.evidence:
            raise ContractError(
                "ObservedClaim requires at least one EvidenceRef: an observation "
                "nothing can be traced back to is an inference"
            )
        if self.premises:
            raise ContractError("ObservedClaim must have no premises; it was observed, not derived")


@dataclass(frozen=True, slots=True, kw_only=True)
class DerivedClaim(_ClaimBase):
    """DER — a deterministic consequence of premises already in the graph.

    Refuses empty premises, an empty ``rule_id`` and inline evidence. A
    derivation cites the premises it transformed and the rule that transformed
    them; if it also carried its own evidence there would be no way to tell
    which part of it was observed.
    """

    _KIND: ClassVar[ClaimKind] = ClaimKind.DER

    rule_id: str

    def __post_init__(self) -> None:
        super().__post_init__()
        require_identifier(self.rule_id, "DerivedClaim.rule_id")
        if not self.premises:
            raise ContractError(
                "DerivedClaim requires premises; a derivation from nothing is an INF"
            )
        if self.evidence:
            raise ContractError(
                "DerivedClaim must not inline evidence; it cites premises, which cite evidence"
            )


@dataclass(frozen=True, slots=True, kw_only=True)
class InferredClaim(_ClaimBase):
    """INF — what a world proposes. Never authoritative, at any support.

    Refuses an empty ``world_id`` and support or shadow penalty outside [0, 1].
    The world id is required because an inference with no world behind it cannot
    be killed when its world dies, and would outlive the reason it was believed.
    """

    _KIND: ClassVar[ClaimKind] = ClaimKind.INF

    world_id: str
    support: float
    shadow_penalty: float = 0.0

    def __post_init__(self) -> None:
        super().__post_init__()
        require_identifier(self.world_id, "InferredClaim.world_id")
        object.__setattr__(self, "support", _require_unit(self.support, "InferredClaim.support"))
        object.__setattr__(
            self,
            "shadow_penalty",
            _require_unit(self.shadow_penalty, "InferredClaim.shadow_penalty"),
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class CounterfactualClaim(_ClaimBase):
    """CF — the measured result of a bounded virtual intervention (§9).

    Refuses an intervention whose ``target_signature`` is empty: a
    counterfactual that names no target is untestable, and an untestable
    counterfactual is an inference with extra ceremony.
    """

    _KIND: ClassVar[ClaimKind] = ClaimKind.CF

    intervention: InterventionLike
    outcome_shift: float

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.intervention, InterventionLike):
            raise ContractError(
                "CounterfactualClaim.intervention must expose kind and target_signature, "
                f"got {type(self.intervention).__name__}"
            )
        target = self.intervention.target_signature
        if not isinstance(target, str) or not target:
            raise ContractError(
                "CounterfactualClaim.intervention.target_signature must be non-empty"
            )
        if not isinstance(self.outcome_shift, (int, float)) or isinstance(self.outcome_shift, bool):
            raise ContractError(
                f"CounterfactualClaim.outcome_shift must be a number, got {self.outcome_shift!r}"
            )
        shift = float(self.outcome_shift)
        if shift != shift or shift in (float("inf"), float("-inf")):
            raise ContractError("CounterfactualClaim.outcome_shift must be finite")
        object.__setattr__(self, "outcome_shift", shift)


@dataclass(frozen=True, slots=True, kw_only=True)
class ExternalClaim(_ClaimBase):
    """EXT — an external mapping, kept only with a version and a reason (§33).

    Refuses an unknown ``knowledge_source``, an empty ``source_version`` and an
    empty ``rationale``. ATT&CK and Sigma constrain and *name* behaviour; they do
    not decide the world. An unversioned mapping cannot be re-audited when the
    external schema moves, and a mapping with no evidence rationale is an
    argument from authority.
    """

    _KIND: ClassVar[ClaimKind] = ClaimKind.EXT

    knowledge_source: str
    source_version: str
    rationale: str

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.knowledge_source not in KNOWLEDGE_SOURCES:
            raise ContractError(
                f"ExternalClaim.knowledge_source must be one of "
                f"{sorted(KNOWLEDGE_SOURCES)}, got {self.knowledge_source!r}"
            )
        if not isinstance(self.source_version, str) or not self.source_version.strip():
            raise ContractError(
                "ExternalClaim.source_version is required: an unversioned external "
                "mapping cannot be re-audited when the source schema changes"
            )
        if not isinstance(self.rationale, str) or not self.rationale.strip():
            raise ContractError(
                "ExternalClaim.rationale is required: a mapping retained without an "
                "evidence reason is an argument from authority"
            )


@dataclass(frozen=True, slots=True, kw_only=True)
class UnknownClaim(_ClaimBase):
    """UNK — a named hole. A first-class result, not an error.

    Refuses any evidence and any premises, and a ``reason`` outside
    ``UNKNOWN_REASONS``. If an unknown could carry evidence it would be an
    observation; if it could carry premises it would be a derivation. What it
    records is that something *was not seen*, and why.
    """

    _KIND: ClassVar[ClaimKind] = ClaimKind.UNK

    reason: str
    shadow_region: str = ""

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.reason not in UNKNOWN_REASONS:
            raise ContractError(
                f"UnknownClaim.reason must be one of {sorted(UNKNOWN_REASONS)}, "
                f"got {self.reason!r}"
            )
        if not isinstance(self.shadow_region, str):
            raise ContractError("UnknownClaim.shadow_region must be a string")
        if len(self.shadow_region) > MAX_SUBJECT_LENGTH:
            raise ContractError(
                f"UnknownClaim.shadow_region must be <= {MAX_SUBJECT_LENGTH} chars"
            )
        if self.evidence:
            raise ContractError("UnknownClaim must carry no evidence; it records what was not seen")
        if self.premises:
            raise ContractError("UnknownClaim must have no premises; a hole is not derived")


#: The closed union. ``mypy --strict`` is exhaustive over it, and
#: ``typing.get_args(TypedClaim)`` is how G4.7 asserts there are exactly six
#: members covering every ``ClaimKind``.
TypedClaim = (
    ObservedClaim
    | DerivedClaim
    | InferredClaim
    | CounterfactualClaim
    | ExternalClaim
    | UnknownClaim
)


#: The closed union as an EXACT-type table. ``kind_of`` looks the claim's own class
#: up here instead of reading its ``_KIND`` attribute, because an attribute can be
#: overridden: a subclass of ``InferredClaim`` declaring ``_KIND = DER``, or any
#: duck-typed class carrying ``_KIND``, was accepted as authoritative and passed
#: both G4.8 walks — the laundering path ADR-0031 says cannot be built
#: (S4-SEC-02 / S4-FC-13). Exact type, so a subclass is refused whatever it declares.
_KIND_BY_CLASS: dict[type, ClaimKind] = {
    ObservedClaim: ClaimKind.OBS,
    DerivedClaim: ClaimKind.DER,
    InferredClaim: ClaimKind.INF,
    CounterfactualClaim: ClaimKind.CF,
    ExternalClaim: ClaimKind.EXT,
    UnknownClaim: ClaimKind.UNK,
}


def kind_of(claim: TypedClaim | type[TypedClaim]) -> ClaimKind:
    """Return a claim's (or a claim class's) ``ClaimKind``, by exact type.

    Accepts a class as well as an instance so the structural half of G4.7 can be
    written over ``typing.get_args(TypedClaim)`` without instantiating six
    objects whose required fields it would have to invent. Anything that is not
    exactly one of the six classes is refused, subclasses included.
    """
    holder = claim if isinstance(claim, type) else type(claim)
    kind = _KIND_BY_CLASS.get(holder)
    if kind is None:
        raise ContractError(
            f"{getattr(holder, '__name__', holder)!r} is not one of the six claim classes; "
            "the union is closed by exact type, so a subclass or look-alike is refused"
        )
    return kind


def is_authoritative_kind(claim: TypedClaim | type[TypedClaim]) -> bool:
    """True when this kind may appear in an authoritative output."""
    return kind_of(claim) in AUTHORITATIVE_KINDS


def sensor_of_evidence(ref: EvidenceRef) -> SensorPath | None:
    """Recover the sensor that produced ``ref``, or ``None`` when it cannot.

    ``RawEventV1.evidence_ref()`` writes ``store="raw.<sensor>"``, so the sensor
    is recoverable for Stage 1 evidence. ``None`` is returned — never a default
    sensor — for any other store, because ADR-0004's lesson generalises: an
    unknown provenance is not a coin flip, and a fabricated sensor on an OBS
    claim would license exactly the inference §22 exists to forbid.
    """
    if not ref.store.startswith(_EVIDENCE_STORE_PREFIX):
        return None
    tail = ref.store[len(_EVIDENCE_STORE_PREFIX) :]
    try:
        return SensorPath(tail)
    except ValueError:
        return None
