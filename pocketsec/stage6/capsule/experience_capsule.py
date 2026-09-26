"""D6.2 (types) / HEL-F01 — ``ExperienceCapsuleV1``: the only form experience takes in Stage 6.

Stage 6 is where learning may change trusted state, so the first thing it needs is a
value that *cannot* be mistaken for trusted state. That value is the capsule. Every
observation, resolution, response outcome, label and foreign package reaches Stage 6
as one of these, and the quarantine gateway is the only reader that may turn it into
anything else (architecture §5-§6). A capsule is evidence about experience; it is
never knowledge, and nothing in this module writes anywhere but the capsule itself.

What the type refuses, each by construction rather than by convention:

* **Ground truth by the side door.** :func:`capsule_from_scenario` never reads
  ``result.scenario`` at all — not its label, name or technique — so two
  ``ScenarioResult`` values that differ only in ``scenario.label`` produce byte-identical
  capsules. A verdict reaches a capsule only as an explicit :class:`LabelAssertion`,
  whose origin must agree with the provenance carrying it.
* **Content instead of lineage.** Evidence is ``sha256:`` digests only. No path,
  command line, user name, pid or display name is stored: the Stage 2 encoder already
  drops ``display_name`` (ADR-0007) and the acting lineage survives only as the hashed
  ``source_group``, which is accounting and never a feature.
* **Forged content addresses.** ``capsule_id`` is derived from the payload; a capsule
  whose id does not match its content is refused, so a tampered ``from_dict`` payload
  fails loudly instead of loading under someone else's name.
* **Silent loss.** Every cap truncates with ``truncated=True`` *and*
  :attr:`ContaminationFlag.TRUNCATED`; the two must agree or construction fails.
* **Laundering a simulator.** A response capsule holding any row not explicitly
  ``simulated: false`` must carry :attr:`ContaminationFlag.SIMULATED_RECORD`, and
  :func:`reseal_capsule` only ever *adds* flags, so nothing downstream can clear it.
* **Mislabelled secrets.** A capsule whose string values match the secret screen is
  ``SECRET_BEARING`` or it does not construct; the gateway discards those outright.

A false positive of the secret screen, pinned by a test rather than hidden: Stage 5
names a refusal ``REFUSED_TOKEN`` and the spec's pattern matches ``token``, so a
response capsule carrying such a row is ``SECRET_BEARING`` and will be discarded. That
fails closed; narrowing the pattern is a spec change, not an implementation one.

Stdlib only; the upstream imports are exactly the ones ADR-0053 allows.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, fields, replace
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    digest_of_bytes,
    register_schema,
    require_finite_unit_interval,
    require_identifier,
)
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.epoch.model import Epoch
from pocketsec.stage1.pipeline import ScenarioResult
from pocketsec.stage1.ssir.transition import SSIRTransitionV1
from pocketsec.stage2.adaptation.quarantine import meaning_vector
from pocketsec.stage2.encoder.ssir_encoder import (
    FEATURE_WIDTH,
    GROUP_OFFSETS,
    EncodedTransition,
    encode_ssir_transition,
)
from pocketsec.stage4.stage5_interface import CBFResolutionV1
from pocketsec.stage5.stage6_interface import (
    ResponseRecordV1,
    authority_violations,
    seam_violations,
)
from pocketsec.stage6.memory.semantic import context_id_for

__all__ = [
    "EXPERIENCE_CAPSULE_V1_ID",
    "EXPERIENCE_CAPSULE_V1_VERSION",
    "FEATURE_DECIMALS",
    "GROUND_TRUTH_SOURCES",
    "MAX_AUDIT_OFFENDERS",
    "MAX_CAPSULE_BYTES",
    "MAX_CONTRADICTIONS",
    "MAX_EVIDENCE_PER_STEP",
    "MAX_EVIDENCE_REFS_PER_CAPSULE",
    "MAX_LINEAGE_ENTRIES",
    "MAX_PROCEDURE_ROWS",
    "MAX_SECURITY_WORLDS",
    "MAX_STEPS_PER_CAPSULE",
    "RESOLUTION_GAP_VISIBILITY",
    "SECRET_PATTERN",
    "CapsuleKind",
    "ContaminationFlag",
    "EncodedStep",
    "ExperienceCapsuleV1",
    "LabelAssertion",
    "LabelOrigin",
    "PrivacyAuditReport",
    "PrivacyClass",
    "SourceClass",
    "SourceProvenance",
    "build_experience_capsule",
    "capsule_from_label",
    "capsule_from_resolution",
    "capsule_from_response",
    "capsule_from_scenario",
    "privacy_audit",
    "reseal_capsule",
    "source_group_of",
    "step_draft_fields",
]

EXPERIENCE_CAPSULE_V1_ID = "pocketsec.experience_capsule.v1"
EXPERIENCE_CAPSULE_V1_VERSION = register_schema(EXPERIENCE_CAPSULE_V1_ID, "1.0.0")

# §4.21 — every value is a chosen parameter, not a measurement.
MAX_STEPS_PER_CAPSULE: int = 64
MAX_EVIDENCE_REFS_PER_CAPSULE: int = 32
MAX_EVIDENCE_PER_STEP: int = 4
MAX_PROCEDURE_ROWS: int = 16
MAX_CAPSULE_BYTES: int = 65536
FEATURE_DECIMALS: int = 6
#: Not in §4.21: bounds this module adds so no tuple field is unbounded. Chosen.
MAX_SECURITY_WORLDS: int = 16
MAX_CONTRADICTIONS: int = 16
MAX_LINEAGE_ENTRIES: int = 8
MAX_AUDIT_OFFENDERS: int = 256
#: Visibility of a resolution that reports a sensor shadow or information gaps. Stage 4
#: exports no visibility share, so this is a chosen parameter, not a measurement.
RESOLUTION_GAP_VISIBILITY: float = 0.5

#: The §D6.2 secret screen, verbatim.
SECRET_PATTERN = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|BEGIN [A-Z ]*PRIVATE KEY)"
)

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CAPSULE_ID_RE = re.compile(r"^cap-[0-9a-f]{24}$")
_GROUP_RE = re.compile(r"^grp-[0-9a-f]{16}$")
_CONTEXT_RE = re.compile(r"^ctx-[0-9a-f]{16}$")
_SIGNATURE_RE = re.compile(r"^[0-9A-Za-z._:\-]{0,128}$")
_IDENTIFIER_SHAPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$")
#: ``uncertainty[1]`` in the encoder layout is ``observation_incomplete`` (0.0 / 1.0).
_OBSERVATION_INCOMPLETE_INDEX = GROUP_OFFSETS["uncertainty"] + 1


class CapsuleKind(StrEnum):
    TRANSITION_EPISODE = "TRANSITION_EPISODE"
    WORLD_RESOLUTION = "WORLD_RESOLUTION"
    RESPONSE_OUTCOME = "RESPONSE_OUTCOME"
    LABEL_ASSERTION = "LABEL_ASSERTION"
    FOREIGN_PACKAGE = "FOREIGN_PACKAGE"


class SourceClass(StrEnum):
    KERNEL_SENSOR = "KERNEL_SENSOR"
    DERIVED_INFERENCE = "DERIVED_INFERENCE"
    ANALYST = "ANALYST"
    EXTERNAL_DATASET = "EXTERNAL_DATASET"
    LAB_GROUND_TRUTH = "LAB_GROUND_TRUTH"
    TEACHER = "TEACHER"
    FOREIGN_HOST = "FOREIGN_HOST"


class LabelOrigin(StrEnum):
    NONE = "NONE"
    GROUND_TRUTH = "GROUND_TRUTH"
    ANALYST = "ANALYST"
    INFERENCE = "INFERENCE"
    WEAK = "WEAK"
    TEACHER = "TEACHER"


class PrivacyClass(StrEnum):
    PUBLIC_DERIVED = "PUBLIC_DERIVED"
    HOST_SENSITIVE = "HOST_SENSITIVE"
    SECRET_BEARING = "SECRET_BEARING"


class ContaminationFlag(StrEnum):
    ATTACKER_CONTROLLED_SOURCE = "ATTACKER_CONTROLLED_SOURCE"
    OBSERVATION_INCOMPLETE = "OBSERVATION_INCOMPLETE"
    SENSOR_DISAGREEMENT = "SENSOR_DISAGREEMENT"
    UNCORROBORATED_EPOCH = "UNCORROBORATED_EPOCH"
    SIMULATED_RECORD = "SIMULATED_RECORD"
    FOREIGN_ORIGIN = "FOREIGN_ORIGIN"
    DUPLICATE_EVIDENCE = "DUPLICATE_EVIDENCE"
    TRUNCATED = "TRUNCATED"


#: Sources that may not claim a stronger label than their own kind: teacher output is
#: weak evidence until validated (§26) and foreign knowledge is a candidate, never
#: authority (§37). A teacher asserting GROUND_TRUTH is refused at construction.
_LABEL_CEILING: Mapping[SourceClass, frozenset[LabelOrigin]] = MappingProxyType(
    {
        SourceClass.TEACHER: frozenset({LabelOrigin.NONE, LabelOrigin.TEACHER}),
        SourceClass.FOREIGN_HOST: frozenset({LabelOrigin.NONE, LabelOrigin.WEAK}),
        SourceClass.DERIVED_INFERENCE: frozenset(
            {LabelOrigin.NONE, LabelOrigin.INFERENCE, LabelOrigin.WEAK}
        ),
    }
)
#: The only source classes that may *declare* GROUND_TRUTH. A whitelist, not a blacklist:
#: a GROUND_TRUTH vote settles an episode alone and is exempt from the label-poisoning
#: rules, so a sensor, an analyst or a dataset claiming it would switch every one of those
#: defences off with one enum value (review S6-AUTH-01). Declaring it is necessary, not
#: sufficient — ``source_class`` is self-declared, so the gateway honours GROUND_TRUTH only
#: from an independence group the deployment authenticated (``ground_truth_groups``).
GROUND_TRUTH_SOURCES: frozenset[SourceClass] = frozenset({SourceClass.LAB_GROUND_TRUTH})
#: Kinds that carry encoded steps, and whose label (if any) is about the capsule itself.
_STEP_KINDS = frozenset({CapsuleKind.TRANSITION_EPISODE, CapsuleKind.FOREIGN_PACKAGE})
#: Kinds whose label names *another* capsule, which must therefore be named.
_TARGETING_KINDS = frozenset({CapsuleKind.LABEL_ASSERTION, CapsuleKind.WORLD_RESOLUTION})


# --- validators and JSON helpers -----------------------------------------------


def _require_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ContractError(f"{field} must be a sha256:<64 hex> digest, got {value!r}")
    return value


def _require_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContractError(f"{field} must be a non-negative int, got {value!r}")
    return value


def _require_float(value: object, field: str) -> float:
    """Strict: a JSON ``1`` is not a float here, so a reader never coerces what it read."""
    if not isinstance(value, float) or value != value or abs(value) == float("inf"):
        raise ContractError(f"{field} must be a finite float, got {value!r}")
    return value


def _require_enum(enum: type[StrEnum], value: object, field: str) -> Any:
    """Exact value match only; ``"benign"`` is not ``BENIGN``."""
    if isinstance(value, enum):
        return value
    if not isinstance(value, str) or value not in enum.__members__:
        raise ContractError(f"{field} must be a {enum.__name__} value, got {value!r}")
    return enum(value)


def _require_list(value: object, field: str) -> tuple[Any, ...]:
    if not isinstance(value, (list, tuple)):
        raise ContractError(f"{field} must be a list, got {type(value).__name__}")
    return tuple(value)


def _freeze(value: Any, field: str) -> Any:
    """Deep-copy plain JSON into immutable containers, refusing anything else."""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return _require_float(value, field)
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise ContractError(f"{field} keys must be strings")
        return MappingProxyType({k: _freeze(v, f"{field}.{k}") for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item, f"{field}[{i}]") for i, item in enumerate(value))
    raise ContractError(f"{field} holds {type(value).__name__}, which is not plain JSON")


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _canonical(payload: Mapping[str, Any]) -> bytes:
    text = json.dumps(payload, sort_keys=True, allow_nan=False, separators=(",", ":"))
    return text.encode("utf-8") + b"\n"


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def _exact_keys(cls: type, payload: object, name: str) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise ContractError(f"{name} payload must be a mapping, got {type(payload).__name__}")
    expected = {item.name for item in fields(cls)}
    missing, extra = sorted(expected - set(payload)), sorted(set(payload) - expected)
    if missing or extra:
        raise ContractError(f"{name} payload missing {missing}, unexpected {extra}")
    return {key: payload[key] for key in expected}


def source_group_of(identity: str) -> str:
    """The accounting key for one acting lineage: a hash, never the identity itself."""
    return "grp-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]


# --- EncodedStep -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EncodedStep:
    """One Stage 2 ``EncodedTransition``, re-constructible, plus provenance accounting.

    Two deliberate differences from the encoder's output, documented rather than hidden:
    ``features`` are rounded to ``FEATURE_DECIMALS`` so canonical bytes are stable, and
    ``evidence`` holds the transitions' ``EvidenceRef.digest`` values where the encoder
    carries locators — a capsule stores lineage, never where content lives.
    """

    features: tuple[float, ...]
    relation: int
    relation_family: int
    state_delta_mask: int
    time_bucket: int
    delta_phi: float
    object_property_mask: int
    epoch_id: int
    actor_slot: int
    uncertainty: float
    source_group: str
    causal_signature: str
    parent_signature: str
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        features = _require_list(self.features, "EncodedStep.features")
        if len(features) != FEATURE_WIDTH:
            raise ContractError(f"EncodedStep.features needs {FEATURE_WIDTH} values")
        for index, value in enumerate(features):
            if round(_require_float(value, f"features[{index}]"), FEATURE_DECIMALS) != value:
                raise ContractError(f"features[{index}] is not rounded to {FEATURE_DECIMALS} dp")
        for name in ("relation", "relation_family", "state_delta_mask", "time_bucket",
                     "object_property_mask", "epoch_id", "actor_slot"):
            _require_int(getattr(self, name), f"EncodedStep.{name}")
        _require_float(self.delta_phi, "EncodedStep.delta_phi")
        require_finite_unit_interval(
            _require_float(self.uncertainty, "EncodedStep.uncertainty"), "EncodedStep.uncertainty"
        )
        if not isinstance(self.source_group, str) or not _GROUP_RE.fullmatch(self.source_group):
            raise ContractError(f"source_group must be grp-<16 hex>, got {self.source_group!r}")
        for name in ("causal_signature", "parent_signature"):
            value = getattr(self, name)
            if not isinstance(value, str) or not _SIGNATURE_RE.fullmatch(value):
                raise ContractError(f"EncodedStep.{name} must be a short signature, got {value!r}")
        evidence = _require_list(self.evidence, "EncodedStep.evidence")
        if len(evidence) > MAX_EVIDENCE_PER_STEP or len(set(evidence)) != len(evidence):
            raise ContractError(f"step evidence must be <= {MAX_EVIDENCE_PER_STEP} distinct")
        for index, digest in enumerate(evidence):
            _require_digest(digest, f"EncodedStep.evidence[{index}]")
        object.__setattr__(self, "features", features)
        object.__setattr__(self, "evidence", evidence)

    @property
    def observation_incomplete(self) -> bool:
        return self.features[_OBSERVATION_INCOMPLETE_INDEX] > 0.5

    def to_encoded(self) -> EncodedTransition:
        return EncodedTransition(
            features=self.features,
            relation=self.relation,
            relation_family=self.relation_family,
            state_delta_mask=self.state_delta_mask,
            time_bucket=self.time_bucket,
            delta_phi=self.delta_phi,
            object_property_mask=self.object_property_mask,
            epoch_id=self.epoch_id,
            actor_slot=self.actor_slot,
            evidence=self.evidence,
        )

    def meaning(self) -> tuple[float, ...]:
        return meaning_vector(self.to_encoded())

    @classmethod
    def from_transition(cls, transition: SSIRTransitionV1, *, actor_slot: int) -> EncodedStep:
        """Encode through Stage 2's encoder; never a second encoder (ADR-0051).

        Evidence past ``MAX_EVIDENCE_PER_STEP`` is cut here and the capsule builders raise
        the ``TRUNCATED`` flag for it: a step has no flag of its own, and the loss must
        not be silent.
        """
        if not isinstance(transition, SSIRTransitionV1):
            raise ContractError(f"from_transition needs SSIRTransitionV1, got {type(transition)}")
        encoded = encode_ssir_transition(transition, actor_slot=actor_slot)
        digests = tuple(dict.fromkeys(ref.digest for ref in transition.evidence))
        return cls(
            features=tuple(round(value, FEATURE_DECIMALS) for value in encoded.features),
            relation=encoded.relation,
            relation_family=encoded.relation_family,
            state_delta_mask=encoded.state_delta_mask,
            time_bucket=encoded.time_bucket,
            delta_phi=float(encoded.delta_phi),
            object_property_mask=encoded.object_property_mask,
            epoch_id=encoded.epoch_id,
            actor_slot=actor_slot,
            uncertainty=float(transition.uncertainty),
            source_group=source_group_of(transition.actor.identity),
            causal_signature=transition.causal_signature,
            parent_signature=transition.parent_signature,
            evidence=digests[:MAX_EVIDENCE_PER_STEP],
        )

    def to_dict(self) -> dict[str, Any]:
        return {item.name: _thaw(getattr(self, item.name)) for item in fields(self)}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> EncodedStep:
        """Strict and uncoerced: ``__post_init__`` judges exactly what was on the wire."""
        return cls(**_exact_keys(cls, payload, "EncodedStep"))


# --- provenance and labels -------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SourceProvenance:
    """Where a capsule came from, and which vote it is (architecture §7).

    ``independence_group`` is the unit of corroboration: capsules sharing it count as ONE
    vote however many there are.
    """

    source_class: SourceClass
    source_id: str
    independence_group: str
    label_origin: LabelOrigin
    transformation_lineage: tuple[str, ...]
    host_id: str

    def __post_init__(self) -> None:
        source = _require_enum(SourceClass, self.source_class, "source_class")
        origin = _require_enum(LabelOrigin, self.label_origin, "label_origin")
        for name in ("source_id", "independence_group", "host_id"):
            require_identifier(getattr(self, name), f"SourceProvenance.{name}")
        lineage = _require_list(self.transformation_lineage, "transformation_lineage")
        if len(lineage) > MAX_LINEAGE_ENTRIES:
            raise ContractError(f"transformation_lineage exceeds {MAX_LINEAGE_ENTRIES} entries")
        for index, step in enumerate(lineage):
            require_identifier(step, f"transformation_lineage[{index}]")
        ceiling = _LABEL_CEILING.get(source)
        if ceiling is not None and origin not in ceiling:
            raise ContractError(
                f"a {source.value} source may not claim a {origin.value} label; teacher and "
                "foreign output is weak evidence until validated locally"
            )
        if origin is LabelOrigin.GROUND_TRUTH and source not in GROUND_TRUTH_SOURCES:
            raise ContractError(
                f"a {source.value} source may not claim GROUND_TRUTH: only "
                "LAB_GROUND_TRUTH may, and the gateway still authenticates its group"
            )
        object.__setattr__(self, "source_class", source)
        object.__setattr__(self, "label_origin", origin)
        object.__setattr__(self, "transformation_lineage", lineage)

    def to_dict(self) -> dict[str, Any]:
        return {item.name: _thaw(getattr(self, item.name)) for item in fields(self)}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> SourceProvenance:
        return cls(**_exact_keys(cls, payload, "SourceProvenance"))


@dataclass(frozen=True, slots=True)
class LabelAssertion:
    """A verdict someone asserted about a capsule — the ONLY way ground truth enters.

    ``target_capsule_id`` is ``""`` only while a self-label is being sealed into its own
    capsule, which then fills in its id.
    """

    verdict: Verdict
    origin: LabelOrigin
    asserted_by: str
    target_capsule_id: str

    def __post_init__(self) -> None:
        verdict = _require_enum(Verdict, self.verdict, "LabelAssertion.verdict")
        origin = _require_enum(LabelOrigin, self.origin, "LabelAssertion.origin")
        if origin is LabelOrigin.NONE:
            raise ContractError("a LabelAssertion with origin NONE asserts nothing; omit it")
        require_identifier(self.asserted_by, "LabelAssertion.asserted_by")
        target = self.target_capsule_id
        if not isinstance(target, str) or (target and not _CAPSULE_ID_RE.fullmatch(target)):
            raise ContractError(f"target_capsule_id must be '' or cap-<24 hex>, got {target!r}")
        object.__setattr__(self, "verdict", verdict)
        object.__setattr__(self, "origin", origin)

    def to_dict(self) -> dict[str, Any]:
        return {"verdict": str(self.verdict), "origin": str(self.origin),
                "asserted_by": self.asserted_by, "target_capsule_id": self.target_capsule_id}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> LabelAssertion:
        return cls(**_exact_keys(cls, payload, "LabelAssertion"))


# --- the capsule -----------------------------------------------------------------


def _capsule_payload(values: Mapping[str, Any]) -> dict[str, Any]:
    """The one wire projection: ``to_dict``, the id derivation and the byte fit all use it."""
    label = values["label"]
    return {
        "schema_id": EXPERIENCE_CAPSULE_V1_ID,
        "schema_version": values["schema_version"],
        "capsule_id": values["capsule_id"],
        "kind": str(values["kind"]),
        "epoch_id": values["epoch_id"],
        "context_id": values["context_id"],
        "evidence_refs": list(values["evidence_refs"]),
        "source_provenance": values["source_provenance"].to_dict(),
        "security_worlds": list(values["security_worlds"]),
        "resolution_state": str(values["resolution_state"]),
        "response_outcome": values["response_outcome"],
        "visibility": values["visibility"],
        "confidence_components": [[name, value] for name, value in values["confidence_components"]],
        "contradiction_history": list(values["contradiction_history"]),
        "privacy_class": str(values["privacy_class"]),
        "contamination_flags": sorted(str(flag) for flag in values["contamination_flags"]),
        "steps": [step.to_dict() for step in values["steps"]],
        "label": None if label is None else label.to_dict(),
        "procedure_rows": [_thaw(row) for row in values["procedure_rows"]],
        "truncated": values["truncated"],
        "created_sequence": values["created_sequence"],
    }


def _derive_id(payload: Mapping[str, Any]) -> str:
    """``cap-`` + sha256 prefix of the payload without its id, a self-label's target blank."""
    material = {key: value for key, value in payload.items() if key != "capsule_id"}
    if payload["kind"] in _STEP_KINDS and payload["label"] is not None:
        material["label"] = {**payload["label"], "target_capsule_id": ""}
    return "cap-" + hashlib.sha256(_canonical(material)).hexdigest()[:24]


def _secret_hits(payload: Mapping[str, Any]) -> int:
    """String values matching the screen. ``privacy_class`` is skipped: its own value
    ``SECRET_BEARING`` contains "secret" and would convict every classified capsule."""
    material = {key: value for key, value in payload.items() if key != "privacy_class"}
    return sum(1 for text in _strings(material) if SECRET_PATTERN.search(text))


@dataclass(frozen=True, slots=True)
class ExperienceCapsuleV1:
    """Architecture §5, every field bound; ``action_outcome`` is ``response_outcome`` (T5).

    Construct with ``capsule_id=""`` to have the content address derived. Any other value
    must equal the derived one, or construction fails.
    """

    capsule_id: str
    kind: CapsuleKind
    epoch_id: int
    context_id: str
    evidence_refs: tuple[str, ...]
    source_provenance: SourceProvenance
    security_worlds: tuple[str, ...]
    resolution_state: Verdict
    response_outcome: str | None
    visibility: float
    confidence_components: tuple[tuple[str, float], ...]
    contradiction_history: tuple[str, ...]
    privacy_class: PrivacyClass
    contamination_flags: frozenset[ContaminationFlag]
    steps: tuple[EncodedStep, ...]
    label: LabelAssertion | None
    procedure_rows: tuple[Mapping[str, Any], ...]
    truncated: bool
    created_sequence: int
    schema_version: str = EXPERIENCE_CAPSULE_V1_VERSION

    def __post_init__(self) -> None:
        self._check_scalars()
        self._check_collections()
        self._check_kind_rules()
        self._check_flags()
        payload = _capsule_payload(self._values())
        derived = _derive_id(payload)
        if self.capsule_id not in ("", derived):
            raise ContractError(f"capsule_id {self.capsule_id!r} does not match its content")
        object.__setattr__(self, "capsule_id", derived)
        payload["capsule_id"] = derived
        label = self.label
        if self.kind in _STEP_KINDS and label is not None and label.target_capsule_id != derived:
            if label.target_capsule_id:
                raise ContractError("a self-label must target its own capsule")
            object.__setattr__(self, "label", replace(label, target_capsule_id=derived))
            payload["label"] = self.label.to_dict() if self.label is not None else None
        if len(_canonical(payload)) > MAX_CAPSULE_BYTES:
            raise ContractError(f"capsule exceeds MAX_CAPSULE_BYTES={MAX_CAPSULE_BYTES}")
        if self.privacy_class is not PrivacyClass.SECRET_BEARING and _secret_hits(payload):
            raise ContractError("capsule holds a secret-pattern value but is not SECRET_BEARING")

    def _values(self) -> dict[str, Any]:
        return {item.name: getattr(self, item.name) for item in fields(self)}

    def _check_scalars(self) -> None:
        cid = self.capsule_id
        if not isinstance(cid, str) or (cid and not _CAPSULE_ID_RE.fullmatch(cid)):
            raise ContractError(f"capsule_id must be cap-<24 hex>, got {cid!r}")
        for name, enum in (("kind", CapsuleKind), ("resolution_state", Verdict),
                           ("privacy_class", PrivacyClass)):
            object.__setattr__(self, name, _require_enum(enum, getattr(self, name), name))
        _require_int(self.epoch_id, "epoch_id")
        _require_int(self.created_sequence, "created_sequence")
        if not isinstance(self.context_id, str) or not _CONTEXT_RE.fullmatch(self.context_id):
            raise ContractError(f"context_id must be ctx-<16 hex>, got {self.context_id!r}")
        if not isinstance(self.source_provenance, SourceProvenance):
            raise ContractError("source_provenance must be a SourceProvenance")
        require_finite_unit_interval(_require_float(self.visibility, "visibility"), "visibility")
        if not isinstance(self.truncated, bool):
            raise ContractError("truncated must be an explicit bool")
        if self.schema_version != EXPERIENCE_CAPSULE_V1_VERSION:
            raise ContractError(f"schema_version {self.schema_version!r} is not supported")
        if self.response_outcome is not None:
            require_identifier(self.response_outcome, "response_outcome")
        if self.label is not None and not isinstance(self.label, LabelAssertion):
            raise ContractError("label must be a LabelAssertion or None")

    def _check_collections(self) -> None:
        refs = _require_list(self.evidence_refs, "evidence_refs")
        if len(refs) > MAX_EVIDENCE_REFS_PER_CAPSULE or len(set(refs)) != len(refs):
            raise ContractError(f"evidence_refs: <= {MAX_EVIDENCE_REFS_PER_CAPSULE} distinct")
        for index, ref in enumerate(refs):
            _require_digest(ref, f"evidence_refs[{index}]")
        worlds = _require_list(self.security_worlds, "security_worlds")
        history = _require_list(self.contradiction_history, "contradiction_history")
        if len(worlds) > MAX_SECURITY_WORLDS or len(history) > MAX_CONTRADICTIONS:
            raise ContractError("security_worlds / contradiction_history over their caps")
        for index, world in enumerate(worlds):
            require_identifier(world, f"security_worlds[{index}]")
        if not all(isinstance(o, str) and _CAPSULE_ID_RE.fullmatch(o) for o in history):
            raise ContractError("contradiction_history must hold capsule ids")
        components = tuple(
            tuple(_require_list(pair, "confidence_components[]"))
            for pair in _require_list(self.confidence_components, "confidence_components")
        )
        for pair in components:
            if len(pair) != 2 or not isinstance(pair[0], str) or not pair[0]:
                raise ContractError(f"confidence_components entries are (name, value): {pair!r}")
            _require_float(pair[1], f"confidence_components[{pair[0]}]")
        names = [pair[0] for pair in components]
        if names != sorted(set(names)):
            raise ContractError("confidence_components must be sorted by unique name")
        steps = _require_list(self.steps, "steps")
        if len(steps) > MAX_STEPS_PER_CAPSULE or not all(isinstance(s, EncodedStep) for s in steps):
            raise ContractError(f"steps must be <= {MAX_STEPS_PER_CAPSULE} EncodedStep values")
        rows = _require_list(self.procedure_rows, "procedure_rows")
        if len(rows) > MAX_PROCEDURE_ROWS or not all(isinstance(r, Mapping) for r in rows):
            raise ContractError(f"procedure_rows must be <= {MAX_PROCEDURE_ROWS} mappings")
        frozen_rows = tuple(_freeze(row, f"procedure_rows[{i}]") for i, row in enumerate(rows))
        for name, value in (("evidence_refs", refs), ("security_worlds", worlds),
                            ("contradiction_history", history),
                            ("confidence_components", components), ("steps", steps),
                            ("procedure_rows", frozen_rows)):
            object.__setattr__(self, name, value)

    def _check_kind_rules(self) -> None:
        kind, label = self.kind, self.label
        if kind is not CapsuleKind.LABEL_ASSERTION and not self.evidence_refs:
            raise ContractError(f"a {kind.value} capsule must reference evidence digests")
        if (kind in _STEP_KINDS) != bool(self.steps):
            raise ContractError("steps belong on, and only on, TRANSITION_EPISODE/FOREIGN_PACKAGE")
        if kind is not CapsuleKind.RESPONSE_OUTCOME and (
            self.procedure_rows or self.response_outcome is not None
        ):
            raise ContractError("procedure rows and response_outcome are RESPONSE_OUTCOME only")
        if kind in _TARGETING_KINDS and (label is None or not label.target_capsule_id):
            raise ContractError(f"a {kind.value} capsule must carry a label naming its target")
        if kind is CapsuleKind.RESPONSE_OUTCOME and label is not None:
            raise ContractError("a RESPONSE_OUTCOME capsule carries no label")
        provenance = self.source_provenance
        if kind is CapsuleKind.LABEL_ASSERTION and label is not None and (
            label.asserted_by != provenance.independence_group
        ):
            raise ContractError("a label's asserted_by must be its provenance independence_group")
        if label is not None and label.origin is not provenance.label_origin:
            raise ContractError(
                f"label origin {label.origin.value} disagrees with provenance label_origin "
                f"{provenance.label_origin.value}; one of them would be a lie"
            )

    def _check_flags(self) -> None:
        flags = frozenset(
            _require_enum(ContaminationFlag, flag, "contamination_flags")
            for flag in self.contamination_flags
        )
        object.__setattr__(self, "contamination_flags", flags)
        if self.truncated != (ContaminationFlag.TRUNCATED in flags):
            raise ContractError("truncated and the TRUNCATED flag must agree; never silent")
        foreign = self.kind is CapsuleKind.FOREIGN_PACKAGE
        if foreign and ContaminationFlag.FOREIGN_ORIGIN not in flags:
            raise ContractError("a FOREIGN_PACKAGE capsule must carry FOREIGN_ORIGIN")
        simulated = any(row.get("simulated") is not False for row in self.procedure_rows)
        if simulated and ContaminationFlag.SIMULATED_RECORD not in flags:
            raise ContractError("simulated rows require the SIMULATED_RECORD flag (ADR-0046)")

    def to_dict(self) -> dict[str, Any]:
        return _capsule_payload(self._values())

    def canonical_bytes(self) -> bytes:
        """Sorted keys, no NaN, compact separators, trailing newline."""
        return _canonical(self.to_dict())

    def digest(self) -> str:
        return digest_of_bytes(self.canonical_bytes())

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ExperienceCapsuleV1:
        """Strict and uncoerced (Stage 5's discipline); the content address is re-verified.

        Enum and list fields are handed to ``__post_init__`` as read, which accepts only
        exact enum values and real lists — nothing here converts a wrong type into a right one.
        """
        names = {item.name for item in fields(cls)} | {"schema_id"}
        got = set(payload) if isinstance(payload, Mapping) else set()
        if got != names:
            missing, extra = sorted(names - got), sorted(got - names)
            raise ContractError(f"ExperienceCapsuleV1 keys: missing {missing}, extra {extra}")
        if payload["schema_id"] != EXPERIENCE_CAPSULE_V1_ID:
            raise ContractError(f"schema_id {payload['schema_id']!r} is not this schema")
        data = {key: payload[key] for key in names - {"schema_id"}}
        data["source_provenance"] = SourceProvenance.from_dict(payload["source_provenance"])
        steps = _require_list(data["steps"], "steps")
        data["steps"] = tuple(EncodedStep.from_dict(step) for step in steps)
        data["label"] = None if data["label"] is None else LabelAssertion.from_dict(data["label"])
        data["contamination_flags"] = frozenset(
            _require_list(data["contamination_flags"], "contamination_flags")
        )
        return cls(**data)


def reseal_capsule(capsule: ExperienceCapsuleV1, **changes: Any) -> ExperienceCapsuleV1:
    """A new capsule with ``changes`` applied and its content address re-derived.

    Contamination flags are monotone: the result must carry every flag the original did,
    so ``SIMULATED_RECORD``, ``TRUNCATED`` or ``ATTACKER_CONTROLLED_SOURCE`` can be added
    downstream and never cleared. ``capsule_id`` is not a field anyone may set.
    """
    if not isinstance(capsule, ExperienceCapsuleV1):
        raise ContractError("reseal_capsule needs an ExperienceCapsuleV1")
    if "capsule_id" in changes:
        raise ContractError("capsule_id is derived from content and cannot be set")
    lost = capsule.contamination_flags - frozenset(
        changes.get("contamination_flags", capsule.contamination_flags)
    )
    if lost:
        raise ContractError(f"contamination flags are never cleared downstream: {sorted(lost)}")
    label = changes.get("label", capsule.label)
    if changes.get("kind", capsule.kind) in _STEP_KINDS and label is not None:
        changes["label"] = replace(label, target_capsule_id="")
    return replace(capsule, capsule_id="", **changes)


# --- builders --------------------------------------------------------------------


def _seal(draft: dict[str, Any], *, privacy: PrivacyClass) -> ExperienceCapsuleV1:
    """Finish a draft: truncation flag, byte fit, privacy class, content address.

    The byte fit drops trailing steps, then procedure rows, raising the truncation flag in
    the same breath. It is reached only when the count caps were not enough (64 steps
    with four evidence digests each is enough).
    """
    draft.update(capsule_id="", privacy_class=privacy)
    draft["confidence_components"] = tuple(sorted(draft["confidence_components"]))
    if draft["truncated"]:
        draft["contamination_flags"] = draft["contamination_flags"] | {ContaminationFlag.TRUNCATED}
    while len(_canonical(_capsule_payload(draft))) > MAX_CAPSULE_BYTES:
        if len(draft["steps"]) > 1:
            draft["steps"] = draft["steps"][:-1]
        elif draft["procedure_rows"]:
            draft["procedure_rows"] = draft["procedure_rows"][:-1]
        else:
            raise ContractError("capsule cannot fit MAX_CAPSULE_BYTES even at its minimum")
        draft["truncated"] = True
        draft["contamination_flags"] = draft["contamination_flags"] | {ContaminationFlag.TRUNCATED}
    if _secret_hits(_capsule_payload(draft)):
        draft["privacy_class"] = PrivacyClass.SECRET_BEARING
    return ExperienceCapsuleV1(**draft)


def _base_draft(
    kind: CapsuleKind, *, epoch: Epoch, provenance: SourceProvenance, sequence: int
) -> dict[str, Any]:
    if not isinstance(epoch, Epoch):
        raise ContractError(f"epoch must be a Stage 1 Epoch, got {type(epoch).__name__}")
    return {
        "capsule_id": "", "kind": kind, "epoch_id": epoch.epoch_id,
        "context_id": context_id_for(epoch.identity), "evidence_refs": (),
        "source_provenance": provenance, "security_worlds": (),
        "resolution_state": Verdict.UNKNOWN, "response_outcome": None, "visibility": 1.0,
        "confidence_components": (), "contradiction_history": (),
        "privacy_class": PrivacyClass.HOST_SENSITIVE, "contamination_flags": frozenset(),
        "steps": (), "label": None, "procedure_rows": (), "truncated": False,
        "created_sequence": sequence, "schema_version": EXPERIENCE_CAPSULE_V1_VERSION,
    }


def _cap_evidence(digests: Iterable[str]) -> tuple[tuple[str, ...], bool]:
    unique = tuple(dict.fromkeys(digests))
    return unique[:MAX_EVIDENCE_REFS_PER_CAPSULE], len(unique) > MAX_EVIDENCE_REFS_PER_CAPSULE


def _steps_from(transitions: Sequence[SSIRTransitionV1]) -> tuple[tuple[EncodedStep, ...], bool]:
    """Encode up to the step cap; ``actor_slot`` by order of first appearance in the capsule."""
    slots: dict[str, int] = {}
    steps: list[EncodedStep] = []
    cut = len(transitions) > MAX_STEPS_PER_CAPSULE
    for transition in transitions[:MAX_STEPS_PER_CAPSULE]:
        slot = slots.setdefault(transition.actor.identity, len(slots))
        cut = cut or len({ref.digest for ref in transition.evidence}) > MAX_EVIDENCE_PER_STEP
        steps.append(EncodedStep.from_transition(transition, actor_slot=slot))
    return tuple(steps), cut


def step_draft_fields(steps: tuple[EncodedStep, ...], *, cut: bool) -> dict[str, Any]:
    """Evidence, visibility, flags and confidence derived from the steps actually kept.

    ``evidence_refs`` is a summary: the first ``MAX_EVIDENCE_REFS_PER_CAPSULE`` distinct
    digests in step order. Cutting the summary is NOT truncation, because every digest
    still travels on its own step; flagging it would mark every episode longer than 32
    steps TRUNCATED (measured: a 64-transition episode was) while losing nothing.
    ``cut`` reports real loss — steps or per-step evidence dropped.

    Public because ``fleet/package.py`` builds FOREIGN_PACKAGE capsules from steps too, and
    two derivations of visibility from one set of steps is how two key spaces are born.
    """
    every = [digest for step in steps for digest in step.evidence]
    refs, _ = _cap_evidence(every)
    incomplete = sum(1 for step in steps if step.observation_incomplete)
    flags: set[ContaminationFlag] = set()
    if incomplete:
        flags.add(ContaminationFlag.OBSERVATION_INCOMPLETE)
    if len(set(every)) != len(every):
        # Stage 1 gives every transition its own evidence, so one digest cited by two
        # steps is the same bytes replayed, which must not count twice.
        flags.add(ContaminationFlag.DUPLICATE_EVIDENCE)
    peak_phi = max((step.delta_phi for step in steps), default=0.0)
    peak_u = max((step.uncertainty for step in steps), default=0.0)
    return {
        "steps": steps, "evidence_refs": refs, "truncated": cut,
        "contamination_flags": frozenset(flags),
        "visibility": round(1.0 - incomplete / len(steps), FEATURE_DECIMALS) if steps else 1.0,
        "confidence_components": (("delta_phi_max", round(peak_phi, FEATURE_DECIMALS)),
                                  ("uncertainty_max", round(peak_u, FEATURE_DECIMALS))),
    }


def capsule_from_scenario(
    result: ScenarioResult, *, epoch: Epoch, provenance: SourceProvenance, sequence: int,
    label: LabelAssertion | None = None,
) -> ExperienceCapsuleV1:
    """A TRANSITION_EPISODE from Stage 1's transitions. Never reads ``result.scenario``.

    ``label``, if given, is the caller's explicit assertion about *this* capsule; its
    target is filled with the capsule's own id.
    """
    if not isinstance(result, ScenarioResult):
        raise ContractError(f"capsule_from_scenario needs a ScenarioResult, got {type(result)}")
    draft = _base_draft(CapsuleKind.TRANSITION_EPISODE, epoch=epoch, provenance=provenance,
                        sequence=sequence)
    steps, cut = _steps_from(result.transitions)
    if not steps:
        raise ContractError("a scenario with no transitions carries no experience")
    draft.update(step_draft_fields(steps, cut=cut), label=label)
    return _seal(draft, privacy=PrivacyClass.HOST_SENSITIVE)


def _resolution_digest(resolution: CBFResolutionV1) -> str:
    """The digest ``write_resolution`` would return, computed without touching disk."""
    text = json.dumps(resolution.to_dict(), sort_keys=True, allow_nan=False, indent=2)
    return digest_of_bytes(text.encode("utf-8") + b"\n")


def capsule_from_resolution(
    resolution: CBFResolutionV1, *, target_capsule_id: str, epoch: Epoch,
    provenance: SourceProvenance, sequence: int,
) -> ExperienceCapsuleV1:
    """A WORLD_RESOLUTION: Stage 4's conclusion about an episode, carried as an INFERENCE label.

    ``resolution.to_dict()`` runs Stage 4's own export refusals first, so a resolution
    Stage 4 would refuse to export cannot become a capsule either.
    """
    if not isinstance(resolution, CBFResolutionV1):
        raise ContractError(f"needs a CBFResolutionV1, got {type(resolution).__name__}")
    draft = _base_draft(CapsuleKind.WORLD_RESOLUTION, epoch=epoch, provenance=provenance,
                        sequence=sequence)
    digests = [_resolution_digest(resolution)]
    for row in resolution.hypotheses:
        digests.extend(str(d) for d in row.get("evidence_digests", ()) or ())
    digests.extend(str(row.get("digest")) for row in resolution.evidence_lineage)
    refs, refs_cut = _cap_evidence(d for d in digests if _DIGEST_RE.fullmatch(d))
    worlds = tuple(dict.fromkeys(str(row.get("mechanism_id")) for row in resolution.hypotheses))
    blind = bool(resolution.shadow) or bool(resolution.information_gaps)
    leading = resolution.hypotheses[0].get("support", 0.0) if resolution.hypotheses else 0.0
    draft.update(
        evidence_refs=refs, security_worlds=worlds[:MAX_SECURITY_WORLDS],
        resolution_state=resolution.verdict,
        visibility=RESOLUTION_GAP_VISIBILITY if blind else 1.0,
        contamination_flags=frozenset({ContaminationFlag.OBSERVATION_INCOMPLETE} if blind else ()),
        truncated=refs_cut or len(worlds) > MAX_SECURITY_WORLDS or bool(resolution.truncations),
        confidence_components=(("leading_support", float(leading)),
                               ("resolution_uncertainty", float(resolution.uncertainty))),
        label=LabelAssertion(verdict=resolution.verdict, origin=LabelOrigin.INFERENCE,
                             asserted_by=provenance.independence_group,
                             target_capsule_id=target_capsule_id),
    )
    return _seal(draft, privacy=PrivacyClass.HOST_SENSITIVE)


def capsule_from_response(
    record: ResponseRecordV1, *, epoch: Epoch, provenance: SourceProvenance, sequence: int
) -> ExperienceCapsuleV1:
    """A RESPONSE_OUTCOME from Stage 5's handoff; every such record today is simulated.

    ``record.digest()`` runs Stage 5's four export refusals first. Each receipt row is then
    screened again with Stage 5's own ``seam_violations`` and ``authority_violations``
    (reused, never re-implemented) and kept only if both are empty; drops are counted in
    ``confidence_components``.
    """
    if not isinstance(record, ResponseRecordV1):
        raise ContractError(f"capsule_from_response needs ResponseRecordV1, got {type(record)}")
    draft = _base_draft(CapsuleKind.RESPONSE_OUTCOME, epoch=epoch, provenance=provenance,
                        sequence=sequence)
    record_digest = record.digest()
    rows = tuple(r for r in record.receipts if seam_violations(r) == () == authority_violations(r))
    kept = rows[:MAX_PROCEDURE_ROWS]
    digests = [record_digest] + [
        str(row.get(key)) for row in kept for key in ("evidence_bundle_digest", "target_digest")
    ]
    refs, refs_cut = _cap_evidence(d for d in digests if _DIGEST_RE.fullmatch(d))
    outcomes = sorted({str(row.get("outcome")) for row in kept})
    simulated = record.simulated or any(row.get("simulated") is not False for row in kept)
    draft.update(
        evidence_refs=refs, procedure_rows=kept,
        contamination_flags=frozenset({ContaminationFlag.SIMULATED_RECORD} if simulated else ()),
        truncated=refs_cut or len(rows) > MAX_PROCEDURE_ROWS,
        response_outcome=(outcomes[0] if len(outcomes) == 1 else "MIXED") if kept else None,
        confidence_components=(("rows_kept", float(len(kept))),
                               ("rows_screened_out", float(len(record.receipts) - len(rows)))),
    )
    return _seal(draft, privacy=PrivacyClass.HOST_SENSITIVE)


def capsule_from_label(
    label: LabelAssertion, *, epoch: Epoch, provenance: SourceProvenance, sequence: int
) -> ExperienceCapsuleV1:
    """A LABEL_ASSERTION about another capsule. It carries no evidence of its own."""
    if not isinstance(label, LabelAssertion):
        raise ContractError(f"capsule_from_label needs a LabelAssertion, got {type(label)}")
    draft = _base_draft(CapsuleKind.LABEL_ASSERTION, epoch=epoch, provenance=provenance,
                        sequence=sequence)
    draft["label"] = label
    return _seal(draft, privacy=PrivacyClass.PUBLIC_DERIVED)


def build_experience_capsule(
    source: ScenarioResult | CBFResolutionV1 | ResponseRecordV1 | LabelAssertion, *,
    epoch: Epoch, provenance: SourceProvenance, sequence: int,
    label: LabelAssertion | None = None, target_capsule_id: str = "",
) -> ExperienceCapsuleV1:
    """HEL-F01 — dispatch only. An argument the chosen builder does not take is refused."""
    common: dict[str, Any] = {"epoch": epoch, "provenance": provenance, "sequence": sequence}
    if isinstance(source, ScenarioResult) and not target_capsule_id:
        return capsule_from_scenario(source, label=label, **common)
    if label is not None or (target_capsule_id and not isinstance(source, CBFResolutionV1)):
        raise ContractError(f"label/target_capsule_id do not apply to {type(source).__name__}")
    if isinstance(source, CBFResolutionV1):
        return capsule_from_resolution(source, target_capsule_id=target_capsule_id, **common)
    if isinstance(source, ResponseRecordV1):
        return capsule_from_response(source, **common)
    if isinstance(source, LabelAssertion):
        return capsule_from_label(source, **common)
    raise ContractError(f"no capsule builder for {type(source).__name__}")


# --- privacy audit (S6X-57) --------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PrivacyAuditReport:
    """``secret_pattern_hits`` is the complete count; ``offenders`` lists at most
    ``MAX_AUDIT_OFFENDERS`` capsule ids and says so when it stopped."""

    capsules: int
    free_text_values: int
    secret_pattern_hits: int
    offenders: tuple[str, ...]
    offenders_truncated: bool


def privacy_audit(capsules: Iterable[ExperienceCapsuleV1]) -> PrivacyAuditReport:
    """S6X-57: how many free-text and secret-pattern values a capsule set holds.

    Free text is any string that is neither a digest nor identifier-shaped: prose, a
    path, a command line. A capsule built by this module should hold none.
    """
    count = free = hits = 0
    offenders: list[str] = []
    truncated = False
    for capsule in capsules:
        if not isinstance(capsule, ExperienceCapsuleV1):
            raise ContractError(f"privacy_audit reads capsules, got {type(capsule).__name__}")
        count += 1
        payload = capsule.to_dict()
        material = {key: value for key, value in payload.items() if key != "privacy_class"}
        free += sum(1 for text in _strings(material) if not _IDENTIFIER_SHAPE.fullmatch(text)
                    and not _DIGEST_RE.fullmatch(text))
        found = _secret_hits(payload)
        hits += found
        if found and len(offenders) < MAX_AUDIT_OFFENDERS:
            offenders.append(capsule.capsule_id)
        elif found:
            truncated = True
    return PrivacyAuditReport(
        capsules=count, free_text_values=free, secret_pattern_hits=hits,
        offenders=tuple(offenders), offenders_truncated=truncated,
    )
