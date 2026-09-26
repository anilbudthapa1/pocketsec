"""D7.2 (schema) — ``KnowledgeCapsuleV1``, the one unit of knowledge that crosses hosts.

Architecture §4: "the default exchanged object is not a gradient and not a raw log. It is a
compact claim with evidence lineage and explicit uncertainty." This module defines that
claim's wire form and refuses, **on construction**, every shape that could carry more than
a claim across the boundary. Parsing is construction: ``from_bytes`` and ``from_dict`` end
in the same ``__post_init__`` a local compiler's :func:`seal_capsule` ends in, so a peer's
bytes get no weaker check than our own.

What a capsule may say, and why nothing else:

* **What to fear, never what to trust (ADR-0063).** :class:`KnowledgeType` has five members,
  each with a consumer (ADR-0062). None asserts normality, a baseline or a benign verdict;
  ``DRIFT_NOTICE`` and ``MODEL_DELTA`` have no consumer and are refused as unknown types.
  ``CONTEST`` exists only on ``ANTIBODY`` and can only *reduce* support downstream.
* **A behaviour pattern in Stage 6's detector grammar, exactly.** ``semantic_invariant`` is
  1..``MAX_MOTIF_LENGTH`` :class:`MotifRow` s, the four integers of a Stage 6 ``MotifStep``.
  Masks are sized from Stage 2's ``feature_names()``, so a row sets no bit the encoder
  cannot emit: no bit that could never match, and no spare bits to hide anything in.
* **A closed string vocabulary.** Every string value on the wire must fullmatch one of
  :data:`WIRE_STRING_SHAPES` (fixed-width hex ids, enum values, the schema id, a semver). A
  path, user name, address or command line matches none, whatever field it is put in.
  Every *key* at every depth is screened against ``FORBIDDEN_AUTHORITY_FIELDS``.
* **Provenance or nothing.** A contributor pseudonym, a declared provenance root and
  1..``MAX_EVIDENCE_COMMITMENTS`` keyed evidence commitments are mandatory.
  ``independence_group`` must equal the declared root: a *claim* the receiver's dependence
  graph tests, never a fact this schema grants.
* **Derived fields are recomputed, not believed:** ``capsule_id``,
  ``compact_feature_signature`` and ``causal_motif``.
* **Bounded before parsed.** ``from_bytes`` refuses more than
  :data:`MAX_KNOWLEDGE_CAPSULE_BYTES` *before* ``json.loads`` runs, refuses duplicate keys
  and non-finite numbers, and refuses every encoding but the canonical one, so one capsule
  has exactly one byte string.

What this module does **not** do: verify ``signature`` (``identity.integrity.Keyring``;
HMAC proves possession of a key, not the identity of a host, ADR-0064), judge whether a
claim is true, or admit anything anywhere. A capsule that constructs is well-formed
foreign input, nothing more.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, fields
from enum import StrEnum
from typing import Any, cast

from pocketsec.stage0.contracts.common import ContractError, digest_of_bytes, register_schema
from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS
from pocketsec.stage1.ssir.entities import SemanticProperty
from pocketsec.stage1.ssir.relations import Relation, RelationFamily, family_of
from pocketsec.stage2.encoder.ssir_encoder import feature_names
from pocketsec.stage6.capsule.experience_capsule import PrivacyClass
from pocketsec.stage6.memory.semantic import MAX_MOTIF_LENGTH, MotifStep
from pocketsec.stage7.capsule.wire_json import Parser as _Parser
from pocketsec.stage7.capsule.wire_json import enum_of as _enum_of
from pocketsec.stage7.capsule.wire_json import exact_keys as _exact_keys
from pocketsec.stage7.capsule.wire_json import finite_float as _finite_float
from pocketsec.stage7.capsule.wire_json import json_float as _json_float
from pocketsec.stage7.capsule.wire_json import json_int as _json_int
from pocketsec.stage7.capsule.wire_json import json_str as _json_str
from pocketsec.stage7.capsule.wire_json import key_text as _key_text
from pocketsec.stage7.capsule.wire_json import optional_of as _optional_of
from pocketsec.stage7.capsule.wire_json import refuse_duplicate_keys as _refuse_duplicate_keys
from pocketsec.stage7.capsule.wire_json import tuple_of as _tuple_of

__all__ = [
    "CAPSULE_ID_PATTERN",
    "COMMITMENT_PATTERN",
    "CONTRIBUTOR_PATTERN",
    "COUNTER_HYPOTHESIS_VALUES",
    "DECISION_PATTERN",
    "FAMILY_PROFILE_LEVELS",
    "FINGERPRINT_PATTERN",
    "KEY_ID_PATTERN",
    "KNOWLEDGE_CAPSULE_V1_ID",
    "KNOWLEDGE_CAPSULE_V1_VERSION",
    "MAX_COUNTER_HYPOTHESES",
    "MAX_EVIDENCE_COMMITMENTS",
    "MAX_EXPIRY_HORIZON_ROUNDS",
    "MAX_KNOWLEDGE_CAPSULE_BYTES",
    "MAX_PARENT_CAPSULES",
    "MAX_WINDOW_ROUNDS",
    "MAX_WIRE_INT",
    "ROOT_PATTERN",
    "SIGNATURE_PATTERN",
    "SOFTWARE_EPOCH_PATTERN",
    "WIRE_STRING_SHAPES",
    "ChainStage",
    "EpochContext",
    "FalsificationSummary",
    "KnowledgeCapsuleV1",
    "KnowledgeType",
    "MotifRow",
    "ObservabilityClaim",
    "ProvenanceCommitment",
    "RevocationGround",
    "RoleClass",
    "SourceContextSketch",
    "Stance",
    "ValidationSummary",
    "VisibilityClass",
    "authority_key_violations",
    "derive_chain_stages",
    "is_wire_string",
    "motif_fingerprint",
    "seal_capsule",
    "wire_string_violations",
]

KNOWLEDGE_CAPSULE_V1_ID = "pocketsec.knowledge_capsule.v1"
KNOWLEDGE_CAPSULE_V1_VERSION = register_schema(KNOWLEDGE_CAPSULE_V1_ID, "1.0.0")

#: Spec §4.23. Every value chosen, not measured.
MAX_KNOWLEDGE_CAPSULE_BYTES: int = 4096  # "KB-scale" (§28): §45's 10 KB+ classes never parse
MAX_EVIDENCE_COMMITMENTS: int = 8
MAX_PARENT_CAPSULES: int = 8
MAX_EXPIRY_HORIZON_ROUNDS: int = 64
MAX_WINDOW_ROUNDS: int = 16
FAMILY_PROFILE_LEVELS: int = 4
#: Not in §4.23; chosen, not measured. The largest integer every JSON parser holds exactly
#: (2**53 - 1): a larger one reads differently on a peer that parses numbers as doubles,
#: which would give one byte string two meanings.
MAX_WIRE_INT: int = 2**53 - 1

#: The six ``falsifier.consensus.CounterHypothesis`` values (spec D7.15), the only strings a
#: ``FalsificationSummary`` may name. Strings, because a schema must not import the
#: falsifier; the foundation test joins the two once the falsifier exists.
COUNTER_HYPOTHESIS_VALUES: tuple[str, ...] = (
    "H0_COINCIDENCE",
    "H1_SHARED_UPDATE",
    "H2_ADMIN_AUTOMATION",
    "H3_TELEMETRY_ARTIFACT",
    "H4_COLLUDING_PEERS",
    "H5_REAL_CAMPAIGN",
)
MAX_COUNTER_HYPOTHESES: int = len(COUNTER_HYPOTHESIS_VALUES)

# The id shapes: a type prefix and fixed-width lowercase hex. Used with ``fullmatch``.
CAPSULE_ID_PATTERN = re.compile(r"kc-[0-9a-f]{24}")
FINGERPRINT_PATTERN = re.compile(r"mf-[0-9a-f]{16}")
SOFTWARE_EPOCH_PATTERN = re.compile(r"se-[0-9a-f]{16}")
CONTRIBUTOR_PATTERN = re.compile(r"peer-[0-9a-f]{16}")
ROOT_PATTERN = re.compile(r"root-[0-9a-f]{16}")
COMMITMENT_PATTERN = re.compile(r"hc-[0-9a-f]{32}")
DECISION_PATTERN = re.compile(r"agg-[0-9a-f]{32}")
KEY_ID_PATTERN = re.compile(r"key-[0-9a-f]{16}")
SIGNATURE_PATTERN = re.compile(r"[0-9a-f]{64}")


class KnowledgeType(StrEnum):
    """Architecture §5 minus the two types with no consumer (ADR-0062).

    ``DRIFT_NOTICE`` is context only, and epoch context already rides on every capsule.
    ``MODEL_DELTA`` has nothing to apply to: Stage 6's learner is parameter-free (ADR-0050).
    Both are refused as unknown, so model replacement and backdoor adapters (S7X-48/49) are
    refused by construction. No member asserts normality (ADR-0063).
    """

    ANTIBODY = "ANTIBODY"  # consumer: ECHO -> bridge -> Stage 6 quarantine
    NOVELTY = "NOVELTY"  # consumer: collective novelty engine (advisory)
    CAMPAIGN_FRAGMENT = "CAMPAIGN_FRAGMENT"  # consumer: hypergraph / reconstructor (advisory)
    NEGATIVE_EVIDENCE = "NEGATIVE_EVIDENCE"  # consumer: consensus falsifier (§19)
    REVOCATION = "REVOCATION"  # consumer: RevocationPlane


class Stance(StrEnum):
    SUPPORT = "SUPPORT"
    #: ANTIBODY only. Reduces support mass downstream; never creates trusted knowledge.
    CONTEST = "CONTEST"


class RoleClass(StrEnum):
    WEB = "WEB"
    DEV = "DEV"
    ADMIN = "ADMIN"
    DESKTOP = "DESKTOP"
    UNKNOWN = "UNKNOWN"


class VisibilityClass(StrEnum):
    FULL = "FULL"
    PARTIAL = "PARTIAL"
    LOW = "LOW"


class ChainStage(StrEnum):
    """Orderable ACCESS < CREDENTIAL < ELEVATION < PERSISTENCE < EGRESS; OTHER is unordered."""

    ACCESS = "ACCESS"
    CREDENTIAL = "CREDENTIAL"
    ELEVATION = "ELEVATION"
    PERSISTENCE = "PERSISTENCE"
    EGRESS = "EGRESS"
    OTHER = "OTHER"


class RevocationGround(StrEnum):
    SELF_RETRACTION = "SELF_RETRACTION"
    LOCAL_EVIDENCE = "LOCAL_EVIDENCE"


def _literal(values: Sequence[str]) -> re.Pattern[str]:
    return re.compile("(?:" + "|".join(re.escape(v) for v in sorted(values)) + ")")


_WIRE_ENUMS: tuple[type[StrEnum], ...] = (
    KnowledgeType, Stance, RoleClass, VisibilityClass, ChainStage, RevocationGround, PrivacyClass,
)  # fmt: skip

#: The closed vocabulary of string values the wire may carry (spec D7.2), each used with
#: ``fullmatch``. The empty string is the unsigned signature and a revocation's empty
#: fingerprint; it can carry nothing.
WIRE_STRING_SHAPES: tuple[re.Pattern[str], ...] = (
    CAPSULE_ID_PATTERN,
    FINGERPRINT_PATTERN,
    SOFTWARE_EPOCH_PATTERN,
    CONTRIBUTOR_PATTERN,
    ROOT_PATTERN,
    COMMITMENT_PATTERN,
    DECISION_PATTERN,
    KEY_ID_PATTERN,
    SIGNATURE_PATTERN,
    _literal([member.value for enum_type in _WIRE_ENUMS for member in enum_type]),
    _literal(COUNTER_HYPOTHESIS_VALUES),
    _literal([KNOWLEDGE_CAPSULE_V1_ID]),
    re.compile(r"\d{1,6}\.\d{1,6}\.\d{1,6}"),
    re.compile(""),
)


def is_wire_string(value: object) -> bool:
    """True iff ``value`` is a string that one of :data:`WIRE_STRING_SHAPES` fullmatches."""
    return isinstance(value, str) and any(p.fullmatch(value) for p in WIRE_STRING_SHAPES)


# --- bit positions, derived from the encoder's own labels, never hard-coded -------------


def _labels(prefix: str) -> tuple[str, ...]:
    return tuple(name[len(prefix) :] for name in feature_names() if name.startswith(prefix))


_OBJECT_LABELS = _labels("object.")
_RAISED_LABELS = _labels("raised.")


def _bits(labels: tuple[str, ...], wanted: Sequence[str]) -> int:
    missing = [name for name in wanted if name not in labels]
    if missing:  # the encoder dropped a label a chain stage is defined by: fail on import
        raise ContractError(f"the Stage 2 encoder no longer emits {missing}")
    return sum(1 << labels.index(name) for name in wanted)


_P = SemanticProperty
_CREDENTIAL_BITS = _bits(_OBJECT_LABELS, (_P.CREDENTIAL.value, _P.CREDENTIAL_READER.value))
_PERSISTENCE_BITS = _bits(_OBJECT_LABELS, (_P.PERSISTENCE.value, _P.PERSISTENCE_WRITER.value))
_EGRESS_BITS = _bits(_OBJECT_LABELS, (_P.EXTERNAL_ENDPOINT.value,))
_ELEVATION_BITS = _bits(_RAISED_LABELS, ("privilege",))
#: Spec D7.2's "access/read family" is read as the family ``Relation.READ`` belongs to:
#: Stage 1 has no family named ACCESS. Derived, so re-familying READ moves it.
_ACCESS_FAMILY: RelationFamily = family_of(Relation.READ)
#: Inclusive upper bounds of the four MotifRow integers, in field order.
_ROW_LIMITS: tuple[int, ...] = (
    len(Relation) - 1,
    (1 << len(_OBJECT_LABELS)) - 1,
    (1 << len(_OBJECT_LABELS)) - 1,
    (1 << len(_RAISED_LABELS)) - 1,
)


# --- construction-side validators ---------------------------------------------------------


def _require_int(value: object, field: str, *, upper: int = MAX_WIRE_INT) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= upper:
        raise ContractError(f"{field} must be an int in [0, {upper}], got {value!r}")
    return int(value)  # an IntEnum such as Relation.READ is stored as its plain int


def _require_shape(value: object, pattern: re.Pattern[str], field: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ContractError(f"{field} must match {pattern.pattern!r}, got {value!r}")
    return value


def _require_enum(value: object, enum_type: type[StrEnum], field: str) -> None:
    if not isinstance(value, enum_type):  # a plain string is not coerced into an enum
        raise ContractError(f"{field} must be a {enum_type.__name__}, got {value!r}")


def _as_tuple(value: object, field: str) -> tuple[Any, ...]:
    """A list or tuple as a tuple; a string (also a Sequence) or anything else refused."""
    if not isinstance(value, (list, tuple)):
        raise ContractError(f"{field} must be a list or tuple, got {type(value).__name__}")
    return tuple(value)


def _require_ids(value: object, pattern: re.Pattern[str], field: str, cap: int) -> tuple[str, ...]:
    ids = _as_tuple(value, field)
    if len(ids) > cap:
        raise ContractError(f"{field} holds {len(ids)} ids; cap is {cap}")
    for item in ids:
        _require_shape(item, pattern, field)
    if len(set(ids)) != len(ids):
        raise ContractError(f"{field} holds a duplicate")
    return ids


def _canonical(payload: object) -> bytes:
    """Sorted keys, compact separators, no NaN, a trailing newline: one form per value."""
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return (text + "\n").encode("utf-8")


# --- the sub-records ----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MotifRow:
    """One Stage 6 ``MotifStep`` as four integers — ``MotifStep.to_payload()`` exactly.

    Each mask may set only bits the encoder emits. A row that requires and forbids one
    property never matches and is refused, as ``MotifStep`` refuses it.
    """

    relation: int
    require_properties: int
    forbid_properties: int
    require_raised: int

    def __post_init__(self) -> None:
        for spec, upper in zip(fields(self), _ROW_LIMITS, strict=True):
            value = _require_int(getattr(self, spec.name), f"MotifRow.{spec.name}", upper=upper)
            object.__setattr__(self, spec.name, value)
        if self.require_properties & self.forbid_properties:
            raise ContractError("a motif row requiring and forbidding one property never matches")

    def to_motif_step(self) -> MotifStep:
        return MotifStep(*self.to_payload())

    @classmethod
    def from_motif_step(cls, step: MotifStep) -> MotifRow:
        if not isinstance(step, MotifStep):
            raise ContractError(f"from_motif_step needs a MotifStep, got {type(step).__name__}")
        return cls(*step.to_payload())

    def to_payload(self) -> list[int]:
        return [self.relation, self.require_properties, self.forbid_properties, self.require_raised]


@dataclass(frozen=True, slots=True)
class EpochContext:
    """Architecture "epoch_context": a coarse software-image class and a visibility class."""

    software_epoch: str  # "se-" + 16 hex (privacy.distiller.software_epoch_class)
    visibility: VisibilityClass

    def __post_init__(self) -> None:
        _require_shape(self.software_epoch, SOFTWARE_EPOCH_PATTERN, "software_epoch")
        _require_enum(self.visibility, VisibilityClass, "visibility")


@dataclass(frozen=True, slots=True)
class SourceContextSketch:
    """Architecture "source_context_sketch": the role class and a 4-level family profile."""

    role: RoleClass
    family_profile: tuple[int, ...]  # one level per RelationFamily, 0..FAMILY_PROFILE_LEVELS-1

    def __post_init__(self) -> None:
        _require_enum(self.role, RoleClass, "role")
        profile = _as_tuple(self.family_profile, "family_profile")
        if len(profile) != len(RelationFamily):
            raise ContractError(f"family_profile needs {len(RelationFamily)} levels")
        top = FAMILY_PROFILE_LEVELS - 1
        levels = tuple(_require_int(level, "family_profile", upper=top) for level in profile)
        object.__setattr__(self, "family_profile", levels)


@dataclass(frozen=True, slots=True)
class ValidationSummary:
    """SELF-REPORTED by the contributor. The receiver never treats it as evidence."""

    episodes_replayed: int
    true_matches: int
    false_matches: int

    def __post_init__(self) -> None:
        for spec in fields(self):
            object.__setattr__(self, spec.name, _require_int(getattr(self, spec.name), spec.name))
        if self.true_matches + self.false_matches > self.episodes_replayed:
            raise ContractError("more matches than episodes replayed")


@dataclass(frozen=True, slots=True)
class FalsificationSummary:
    """SELF-REPORTED. ``counter_hypotheses`` are distinct ``CounterHypothesis`` values."""

    mutations_tried: int
    mutations_survived: int
    counter_hypotheses: tuple[str, ...]

    def __post_init__(self) -> None:
        tried = _require_int(self.mutations_tried, "mutations_tried")
        survived = _require_int(self.mutations_survived, "mutations_survived", upper=tried)
        object.__setattr__(self, "mutations_tried", tried)
        object.__setattr__(self, "mutations_survived", survived)
        names = _as_tuple(self.counter_hypotheses, "counter_hypotheses")
        unknown = [n for n in names if not isinstance(n, str) or n not in COUNTER_HYPOTHESIS_VALUES]
        if unknown:
            raise ContractError(f"unknown counter-hypothesis {unknown[0]!r}")
        if len(set(names)) != len(names):
            raise ContractError("counter_hypotheses holds a duplicate")
        object.__setattr__(self, "counter_hypotheses", tuple(str(n) for n in names))


@dataclass(frozen=True, slots=True)
class ProvenanceCommitment:
    """Who contributed, under which declared root, over which committed evidence.

    Knowledge without it is refused. ``provenance_root`` is a DECLARED administrative
    domain. ``evidence_commitments`` are keyed commitments, so a peer cannot test whether an
    evidence digest it guesses is among them. ``aggregation_decision`` names the ECHO
    decision a derived capsule came from (``None`` for an original).
    """

    contributor: str
    provenance_root: str
    evidence_commitments: tuple[str, ...]
    aggregation_decision: str | None

    def __post_init__(self) -> None:
        _require_shape(self.contributor, CONTRIBUTOR_PATTERN, "contributor")
        _require_shape(self.provenance_root, ROOT_PATTERN, "provenance_root")
        commitments = _require_ids(
            self.evidence_commitments, COMMITMENT_PATTERN, "evidence_commitments",
            MAX_EVIDENCE_COMMITMENTS,
        )  # fmt: skip
        if not commitments:
            raise ContractError("knowledge without provenance is refused: no evidence commitment")
        object.__setattr__(self, "evidence_commitments", commitments)
        if self.aggregation_decision is not None:
            _require_shape(self.aggregation_decision, DECISION_PATTERN, "aggregation_decision")


@dataclass(frozen=True, slots=True)
class ObservabilityClaim:
    """NEGATIVE_EVIDENCE only (§19): how well the contributor *could* have seen the absence."""

    expected_observability: float
    sensor_health: float
    temporal_coverage: float

    def __post_init__(self) -> None:
        for spec in fields(self):
            value = getattr(self, spec.name)
            if not isinstance(value, float) or not 0.0 <= value <= 1.0:  # NaN fails both
                raise ContractError(f"{spec.name} must be a float in [0, 1], got {value!r}")
            object.__setattr__(self, spec.name, value + 0.0)  # fold -0.0: one spelling


_RECORDS: tuple[type, ...] = (
    EpochContext, SourceContextSketch, ValidationSummary, FalsificationSummary,
    ProvenanceCommitment, ObservabilityClaim,
)  # fmt: skip


def _plain(value: object) -> Any:
    """A field value as plain JSON: enums by value, rows as int lists, records as objects."""
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, MotifRow):
        return value.to_payload()
    if isinstance(value, _RECORDS):
        record = cast(Any, value)  # one of the frozen dataclasses above
        return {spec.name: _plain(getattr(record, spec.name)) for spec in fields(record)}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


# --- key and string screens ---------------------------------------------------------------


def _walk(payload: object, prefix: str) -> Iterator[tuple[str, object, object]]:
    """Yield ``(path, key, value)`` for every mapping entry and list item (key ``None``).

    Iterative with a visited set, so a deeply nested or self-referencing structure handed
    to ``from_dict`` can neither exhaust the stack nor loop forever.
    """
    stack: list[tuple[str, object]] = [(prefix, payload)]
    seen: set[int] = set()
    while stack:
        path, node = stack.pop()
        if not isinstance(node, (Mapping, list, tuple)) or id(node) in seen:
            continue
        seen.add(id(node))
        items = node.items() if isinstance(node, Mapping) else enumerate(node)
        for key, value in items:
            is_list = not isinstance(node, Mapping)
            child = f"{path}[{key}]" if is_list else f"{path}.{_key_text(key)}"
            yield child, None if is_list else key, value
            stack.append((child, value))


def authority_key_violations(payload: object, *, prefix: str = "capsule") -> tuple[str, ...]:
    """Every key path, at every depth, whose lowercased key contains an authority word.

    Stricter than T5: it screens the *wire* — keys of nested records and keys no field
    declares — against every ``FORBIDDEN_AUTHORITY_FIELDS`` member as a substring. A
    payload with any hit is refused before anything else is read from it.
    """
    return tuple(
        sorted(
            path
            for path, key, _ in _walk(payload, prefix)
            if key is not None
            and any(word in _key_text(key).lower() for word in FORBIDDEN_AUTHORITY_FIELDS)
        )
    )


def wire_string_violations(payload: object, *, prefix: str = "capsule") -> tuple[str, ...]:
    """Every path whose string value lies outside :data:`WIRE_STRING_SHAPES`."""
    found = [
        path
        for path, _, value in _walk(payload, prefix)
        if isinstance(value, str) and not is_wire_string(value)
    ]
    if isinstance(payload, str) and not is_wire_string(payload):
        found.append(prefix)
    return tuple(sorted(found))


# --- derivations --------------------------------------------------------------------------


def _require_rows(rows: object, field: str) -> tuple[MotifRow, ...]:
    values = _as_tuple(rows, field)
    if not all(isinstance(row, MotifRow) for row in values):
        raise ContractError(f"{field} must hold MotifRow values")
    return values


def motif_fingerprint(rows: Sequence[MotifRow]) -> str:
    """``"mf-"`` + 16 hex of the canonical rows: the antibody key (spec §4.0)."""
    values = _require_rows(rows, "motif rows")
    if not 1 <= len(values) <= MAX_MOTIF_LENGTH:
        raise ContractError(f"a motif has 1..{MAX_MOTIF_LENGTH} rows, got {len(values)}")
    digest = hashlib.sha256(_canonical([row.to_payload() for row in values])).hexdigest()
    return "mf-" + digest[:16]


def _chain_stage(row: MotifRow) -> ChainStage:
    if row.require_properties & _CREDENTIAL_BITS:
        return ChainStage.CREDENTIAL
    if row.require_raised & _ELEVATION_BITS:
        return ChainStage.ELEVATION
    if row.require_properties & _PERSISTENCE_BITS:
        return ChainStage.PERSISTENCE
    if row.require_properties & _EGRESS_BITS:
        return ChainStage.EGRESS
    if family_of(Relation(row.relation)) is _ACCESS_FAMILY:
        return ChainStage.ACCESS
    return ChainStage.OTHER


def derive_chain_stages(rows: Sequence[MotifRow]) -> tuple[ChainStage, ...]:
    """One stage per row: the first of CREDENTIAL, ELEVATION, PERSISTENCE, EGRESS, ACCESS
    that applies, else OTHER. Only *required* bits count: a forbidden property is not
    something the behaviour does."""
    return tuple(_chain_stage(row) for row in _require_rows(rows, "motif rows"))


def _capsule_id_of(payload: Mapping[str, Any]) -> str:
    """``"kc-"`` + 24 hex over the unsigned payload minus ``capsule_id``."""
    unsigned = {k: v for k, v in payload.items() if k not in ("capsule_id", "signature")}
    return "kc-" + hashlib.sha256(_canonical(unsigned)).hexdigest()[:24]


# --- the capsule --------------------------------------------------------------------------

_KT = KnowledgeType
#: The knowledge types each type-specific field belongs to: present there, absent elsewhere.
_TYPE_FIELDS: Mapping[str, frozenset[KnowledgeType]] = {
    "time_window": frozenset({_KT.CAMPAIGN_FRAGMENT, _KT.NEGATIVE_EVIDENCE}),
    "observability": frozenset({_KT.NEGATIVE_EVIDENCE}),
    "revocation_target": frozenset({_KT.REVOCATION}),
    "revocation_ground": frozenset({_KT.REVOCATION}),
}


@dataclass(frozen=True, slots=True)
class KnowledgeCapsuleV1:
    """The wire unit. Every field is spec D7.2's; every refusal is in ``__post_init__``."""

    capsule_id: str
    knowledge_type: KnowledgeType
    stance: Stance
    semantic_invariant: tuple[MotifRow, ...]
    compact_feature_signature: str
    causal_motif: tuple[ChainStage, ...]
    attack_mappings: tuple[str, ...]
    epoch_context: EpochContext
    source_context_sketch: SourceContextSketch
    validation_summary: ValidationSummary
    falsification_summary: FalsificationSummary
    provenance_commitment: ProvenanceCommitment
    independence_group: str
    privacy_class: PrivacyClass
    created_round: int
    expiry_round: int
    sequence: int
    parent_capsules: tuple[str, ...]
    time_window: tuple[int, int] | None
    observability: ObservabilityClaim | None
    revocation_target: str | None
    revocation_ground: RevocationGround | None
    key_id: str
    signature: str
    schema_version: str = KNOWLEDGE_CAPSULE_V1_VERSION

    def __post_init__(self) -> None:
        self._check_header()
        self._check_records()
        self._check_invariant()
        self._check_rounds()
        self._check_type_fields()
        self._check_lineage()
        self._check_wire()

    def _check_header(self) -> None:
        if self.schema_version != KNOWLEDGE_CAPSULE_V1_VERSION:
            raise ContractError(f"unknown knowledge capsule version {self.schema_version!r}")
        _require_enum(self.knowledge_type, KnowledgeType, "knowledge_type")
        _require_enum(self.stance, Stance, "stance")
        if self.stance is Stance.CONTEST and self.knowledge_type is not KnowledgeType.ANTIBODY:
            raise ContractError("CONTEST is an ANTIBODY stance only")
        if self.privacy_class is not PrivacyClass.PUBLIC_DERIVED:
            raise ContractError(f"privacy_class must be PUBLIC_DERIVED, got {self.privacy_class!r}")
        if _as_tuple(self.attack_mappings, "attack_mappings"):  # "if evidenced"; none is
            raise ContractError("attack_mappings must be empty in v1: nothing evidences them")
        object.__setattr__(self, "attack_mappings", ())
        _require_shape(self.key_id, KEY_ID_PATTERN, "key_id")
        if self.signature != "":
            _require_shape(self.signature, SIGNATURE_PATTERN, "signature")

    def _check_records(self) -> None:
        for name in ("epoch_context", "source_context_sketch", "validation_summary",
                     "falsification_summary", "provenance_commitment"):  # fmt: skip
            expected = _FIELD_TYPES[name]
            if not isinstance(getattr(self, name), expected):
                raise ContractError(f"{name} must be a {expected.__name__}")
        _require_shape(self.independence_group, ROOT_PATTERN, "independence_group")
        if self.independence_group != self.provenance_commitment.provenance_root:
            raise ContractError("independence_group must equal the declared provenance_root")

    def _check_invariant(self) -> None:
        rows = _require_rows(self.semantic_invariant, "semantic_invariant")
        stages = _as_tuple(self.causal_motif, "causal_motif")
        object.__setattr__(self, "semantic_invariant", rows)
        object.__setattr__(self, "causal_motif", stages)
        if self.knowledge_type is KnowledgeType.REVOCATION:
            if rows or self.compact_feature_signature != "":
                raise ContractError("a REVOCATION carries no invariant and no fingerprint")
        elif not 1 <= len(rows) <= MAX_MOTIF_LENGTH:
            raise ContractError(f"semantic_invariant holds 1..{MAX_MOTIF_LENGTH} rows")
        elif self.compact_feature_signature != motif_fingerprint(rows):
            raise ContractError("compact_feature_signature does not match the invariant")
        if stages != derive_chain_stages(rows):
            raise ContractError("causal_motif does not match the invariant's chain stages")

    def _check_rounds(self) -> None:
        created = _require_int(self.created_round, "created_round")
        expiry = _require_int(self.expiry_round, "expiry_round")
        _require_int(self.sequence, "sequence")
        if not created < expiry <= created + MAX_EXPIRY_HORIZON_ROUNDS:
            raise ContractError(
                f"expiry_round must lie in ({created}, {created + MAX_EXPIRY_HORIZON_ROUNDS}]"
            )
        if self.time_window is None:
            return
        window = _as_tuple(self.time_window, "time_window")
        if len(window) != 2:
            raise ContractError("time_window is (lo, hi)")
        lo, hi = (_require_int(bound, "time_window") for bound in window)
        if not lo <= hi <= lo + MAX_WINDOW_ROUNDS:
            raise ContractError(f"time_window must satisfy lo <= hi <= lo + {MAX_WINDOW_ROUNDS}")
        object.__setattr__(self, "time_window", (lo, hi))

    def _check_type_fields(self) -> None:
        for name, owners in _TYPE_FIELDS.items():
            belongs = self.knowledge_type in owners
            if (getattr(self, name) is not None) != belongs:
                verdict = "required" if belongs else "refused"
                raise ContractError(f"{name} is {verdict} on {self.knowledge_type}")
        if self.observability is not None and not isinstance(
            self.observability, ObservabilityClaim
        ):
            raise ContractError("observability must be an ObservabilityClaim")
        if self.revocation_target is not None:
            _require_shape(self.revocation_target, CAPSULE_ID_PATTERN, "revocation_target")
            _require_enum(self.revocation_ground, RevocationGround, "revocation_ground")

    def _check_lineage(self) -> None:
        parents = _require_ids(
            self.parent_capsules, CAPSULE_ID_PATTERN, "parent_capsules", MAX_PARENT_CAPSULES
        )
        object.__setattr__(self, "parent_capsules", parents)
        if self.provenance_commitment.aggregation_decision is not None and not parents:
            raise ContractError("a capsule derived by an aggregation decision cites its parents")
        _require_shape(self.capsule_id, CAPSULE_ID_PATTERN, "capsule_id")
        if self.capsule_id in parents or self.capsule_id == self.revocation_target:
            raise ContractError("a capsule cannot be its own parent or revoke itself")
        if self.capsule_id != _capsule_id_of(self.to_dict()):
            raise ContractError("capsule_id does not match the unsigned payload")

    def _check_wire(self) -> None:
        # Belt and braces over the per-field checks: a field added later is screened too.
        payload = self.to_dict()
        problems = authority_key_violations(payload) + wire_string_violations(payload)
        if problems:
            raise ContractError(f"not wire-safe: {problems[:4]}")
        if len(_canonical(payload)) > MAX_KNOWLEDGE_CAPSULE_BYTES:
            raise ContractError(f"a capsule encodes to over {MAX_KNOWLEDGE_CAPSULE_BYTES} bytes")

    # --- encoding ------------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """The wire payload: plain JSON, every field, plus ``schema_id``."""
        return _payload_of(lambda name: getattr(self, name))

    def unsigned_bytes(self) -> bytes:
        """What the HMAC covers: the canonical payload without ``signature``."""
        payload = self.to_dict()
        del payload["signature"]
        return _canonical(payload)

    def canonical_bytes(self) -> bytes:
        return _canonical(self.to_dict())

    def digest(self) -> str:
        return digest_of_bytes(self.canonical_bytes())

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> KnowledgeCapsuleV1:
        """Strict: authority keys first, then schema id and version, then exact keys and
        exact JSON types at every depth. Nothing is coerced."""
        if not isinstance(payload, Mapping):
            raise ContractError(f"a capsule payload must be an object, not {type(payload)}")
        authority = authority_key_violations(payload)
        if authority:
            raise ContractError(f"authority-named keys refused: {authority[:4]}")
        if payload.get("schema_id") != KNOWLEDGE_CAPSULE_V1_ID:
            raise ContractError(f"unknown schema_id {payload.get('schema_id')!r}")
        if payload.get("schema_version") != KNOWLEDGE_CAPSULE_V1_VERSION:
            raise ContractError(f"unknown schema_version {payload.get('schema_version')!r}")
        raw = _exact_keys(payload, _CAPSULE_KEYS, "capsule")
        parsers = _PARSERS[cls]
        return cls(**{name: parse(raw[name], f"capsule.{name}") for name, parse in parsers.items()})

    @classmethod
    def from_bytes(cls, data: bytes) -> KnowledgeCapsuleV1:
        """Refuse oversize input BEFORE parsing it; refuse every non-canonical encoding."""
        if not isinstance(data, bytes):
            raise ContractError(f"capsule bytes must be bytes, got {type(data).__name__}")
        if len(data) > MAX_KNOWLEDGE_CAPSULE_BYTES:
            raise ContractError(f"{len(data)} bytes; the cap is {MAX_KNOWLEDGE_CAPSULE_BYTES}")
        try:
            payload = json.loads(
                data.decode("utf-8"), object_pairs_hook=_refuse_duplicate_keys,
                parse_constant=_finite_float, parse_float=_finite_float,
            )  # fmt: skip
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise ContractError(f"capsule bytes are not strict JSON: {exc}") from None
        capsule = cls.from_dict(payload)
        if capsule.canonical_bytes() != data:
            raise ContractError("capsule bytes are not the canonical encoding")
        return capsule


_FIELD_NAMES: tuple[str, ...] = tuple(spec.name for spec in fields(KnowledgeCapsuleV1))
_CAPSULE_KEYS: frozenset[str] = frozenset({*_FIELD_NAMES, "schema_id"})
_FIELD_TYPES: Mapping[str, type] = {
    "epoch_context": EpochContext,
    "source_context_sketch": SourceContextSketch,
    "validation_summary": ValidationSummary,
    "falsification_summary": FalsificationSummary,
    "provenance_commitment": ProvenanceCommitment,
}


def _payload_of(get: Callable[[str], Any]) -> dict[str, Any]:
    """The wire dict from a field getter; shared by ``to_dict`` and :func:`seal_capsule`."""
    return {"schema_id": KNOWLEDGE_CAPSULE_V1_ID, **{n: _plain(get(n)) for n in _FIELD_NAMES}}


# --- strict JSON readers: exact keys, exact types, no coercion ----------------------------

def _record_of(record: type) -> _Parser:
    def parse_record(value: object, where: str) -> Any:
        parsers = _PARSERS[record]
        raw = _exact_keys(value, frozenset(parsers), where)
        return record(**{n: parse(raw[n], f"{where}.{n}") for n, parse in parsers.items()})

    return parse_record


def _parse_row(value: object, where: str) -> MotifRow:
    return MotifRow(*_tuple_of(_json_int, length=len(_ROW_LIMITS))(value, where))


_PARSERS: Mapping[type, Mapping[str, _Parser]] = {
    EpochContext: {"software_epoch": _json_str, "visibility": _enum_of(VisibilityClass)},
    SourceContextSketch: {"role": _enum_of(RoleClass), "family_profile": _tuple_of(_json_int)},
    ValidationSummary: dict.fromkeys(
        ("episodes_replayed", "true_matches", "false_matches"), _json_int
    ),
    FalsificationSummary: {
        "mutations_tried": _json_int,
        "mutations_survived": _json_int,
        "counter_hypotheses": _tuple_of(_json_str),
    },
    ProvenanceCommitment: {
        "contributor": _json_str,
        "provenance_root": _json_str,
        "evidence_commitments": _tuple_of(_json_str),
        "aggregation_decision": _optional_of(_json_str),
    },
    ObservabilityClaim: dict.fromkeys(
        ("expected_observability", "sensor_health", "temporal_coverage"), _json_float
    ),
    KnowledgeCapsuleV1: {
        **dict.fromkeys(
            ("capsule_id", "compact_feature_signature", "independence_group", "key_id",
             "signature", "schema_version"), _json_str,
        ),
        **dict.fromkeys(("created_round", "expiry_round", "sequence"), _json_int),
        "knowledge_type": _enum_of(KnowledgeType),
        "stance": _enum_of(Stance),
        "privacy_class": _enum_of(PrivacyClass),
        "semantic_invariant": _tuple_of(_parse_row),
        "causal_motif": _tuple_of(_enum_of(ChainStage)),
        "attack_mappings": _tuple_of(_json_str),
        "parent_capsules": _tuple_of(_json_str),
        "time_window": _optional_of(_tuple_of(_json_int, length=2)),
        "observability": _optional_of(_record_of(ObservabilityClaim)),
        "revocation_target": _optional_of(_json_str),
        "revocation_ground": _optional_of(_enum_of(RevocationGround)),
        **{name: _record_of(record) for name, record in _FIELD_TYPES.items()},
    },
}  # fmt: skip

# Import-time invariant: a field with no parser could never be read, and a parser with no
# field would read a key nothing declares. Raised rather than asserted so -O keeps it.
for _record, _parsers in _PARSERS.items():
    if set(_parsers) != {spec.name for spec in fields(_record)}:
        raise ContractError(f"{_record.__name__}: parsers and fields disagree")


# --- sealing --------------------------------------------------------------------------------

#: What :func:`seal_capsule` derives. A caller supplying one is refused, so a sealed
#: capsule's derived fields are never the caller's claim.
_DERIVED_FIELDS = frozenset(
    {"capsule_id", "compact_feature_signature", "causal_motif", "signature", "schema_version"}
)
_SEAL_DEFAULTS: Mapping[str, Any] = {
    "attack_mappings": (),
    "privacy_class": PrivacyClass.PUBLIC_DERIVED,
    "parent_capsules": (),
    "time_window": None,
    "observability": None,
    "revocation_target": None,
    "revocation_ground": None,
}


def seal_capsule(**fields_: Any) -> KnowledgeCapsuleV1:
    """An UNSIGNED capsule whose derived fields are computed, never supplied.

    Derives ``compact_feature_signature`` and ``causal_motif`` from the invariant and
    ``capsule_id`` from the unsigned payload; ``signature`` is ``""`` (signing is
    ``Keyring.sign``). Every other refusal is the constructor's.
    """
    supplied = sorted(_DERIVED_FIELDS & fields_.keys())
    if supplied:
        raise ContractError(f"seal_capsule derives {supplied}; they may not be supplied")
    unknown = sorted(fields_.keys() - set(_FIELD_NAMES))
    if unknown:
        raise ContractError(f"seal_capsule got unknown fields {unknown}")
    values: dict[str, Any] = {**_SEAL_DEFAULTS, **fields_}
    rows = _require_rows(values.get("semantic_invariant"), "semantic_invariant")
    values.update(
        semantic_invariant=rows,
        compact_feature_signature=motif_fingerprint(rows) if rows else "",
        causal_motif=derive_chain_stages(rows),
        signature="",
        schema_version=KNOWLEDGE_CAPSULE_V1_VERSION,
        capsule_id="",
    )
    try:
        values["capsule_id"] = _capsule_id_of(_payload_of(values.__getitem__))
    except KeyError as exc:
        raise ContractError(f"seal_capsule: missing field {exc}") from None
    except (TypeError, ValueError) as exc:  # json.dumps refused a value
        raise ContractError(f"seal_capsule: a field is not wire-encodable: {exc}") from None
    return KnowledgeCapsuleV1(**values)
