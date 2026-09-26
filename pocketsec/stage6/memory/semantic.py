"""D6.4 — the trusted knowledge state, and the one score that reads it.

Stage 6 is where learning is allowed to change trusted state, so the trusted state
has to be a thing that can be named, hashed, compared and restored. This module is
that thing: :class:`TrustedKnowledgeState` is one immutable value holding every
``DETECTOR``, ``BASELINE`` and ``PROCEDURE`` item, exactly one ``THRESHOLD`` item and
the protected rehearsal set. It has one canonical byte form and one ``sha256:``
digest, and ``from_canonical_bytes(s.canonical_bytes()).canonical_bytes()`` is
byte-identical to ``s.canonical_bytes()``. **Rollback identity depends on that
sentence**: a rollback that restores "the same knowledge" but not the same bytes
cannot be verified by digest, and an unverifiable rollback is a claim.

What this module refuses to do:

* **It writes nothing.** Every "change" returns a new value
  (:meth:`TrustedKnowledgeState.with_changes`); installing one as *the* trusted state
  is the promotion controller's job and nobody else's (ADR-0052).
* **It never drops silently.** A state past any cap raises :class:`CapacityError`;
  the caller decides what to give up, and the refusal is visible.
* **It never loads an item without lineage.** ``from_canonical_bytes`` refuses, with
  :class:`LineageError`, any item that names no capsule or no evidence digest. The
  only exemption is the genesis ``THRESHOLD`` item, which is configuration rather
  than learned knowledge; a *detector* claiming to be "genesis" is refused, because
  otherwise the word "genesis" would be a lineage bypass.
* **Identity is content.** ``item_id`` is a digest over what the item *is* (kind,
  motif, anchor, pattern key, contexts); an item whose id does not match its content
  is refused at construction, so an id cannot be forged to shadow another item.

The score (§4.0) is what "detection capability" means in this stage — the thing
retention is measured on and the thing poisoning tries to move::

    D = max weight of every applicable DETECTOR whose motif matches, else 0.0
    U = UNEXPLAINED_WEIGHT x max over actors of unexplained / non-escalating
    score = max(D, U)

``U`` is capped at ``UNEXPLAINED_WEIGHT`` (0.5): unexplained behaviour is anomaly
evidence, never a verdict. Novelty is not maliciousness. ``U`` exists so that a
BASELINE item has a consumer (lesson 3): a baseline changes an outcome only by
explaining a step, which is exactly the harm slow poisoning is after.

Context keys come from exactly one function, :func:`context_id_for`; baseline keys
are exactly Stage 2's ``pattern_key``. Two key spaces that drift apart is the
S2-FC-01 defect class, and Rule A tests both joins.
"""

from __future__ import annotations

import dataclasses
import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol

from pocketsec.stage0.contracts.common import ContractError, digest_of_bytes
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.epoch.model import SystemIdentity
from pocketsec.stage1.ssir.relations import Relation
from pocketsec.stage2.adaptation.quarantine import (
    MEANING_GROUPS,
    meaning_distance,
    pattern_key,
)
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_LAYOUT, FEATURE_WIDTH, EncodedTransition
from pocketsec.stage6.constitution.learning import touches_protected

if TYPE_CHECKING:
    # Type-only: the capsule module derives its context ids from this module, and
    # episodic/procedural import this module, so importing them at runtime here
    # would be a cycle. The runtime imports are local to the two loaders below.
    from pocketsec.stage6.capsule.experience_capsule import EncodedStep
    from pocketsec.stage6.memory.episodic import EpisodeSkeleton
    from pocketsec.stage6.memory.procedural import ProcedureRecord
    from pocketsec.stage6.resources import WorkMeter

__all__ = [
    "ALL_CONTEXTS",
    "DEFAULT_THRESHOLD",
    "GENESIS_CANDIDATE_ID",
    "MAX_BASELINE_ITEMS",
    "MAX_DETECTOR_ITEMS",
    "MAX_ITEM_CAPSULE_REFS",
    "MAX_ITEM_EPOCHS",
    "MAX_MOTIF_LENGTH",
    "MAX_PROCEDURE_ITEMS",
    "MAX_REHEARSAL_EXEMPLARS",
    "MAX_TRUSTED_STATE_BYTES",
    "MEANING_WIDTH",
    "STAGE2_BASELINE_KEYS",
    "STATE_FLOAT_DECIMALS",
    "STATE_FORMAT",
    "UNEXPLAINED_WEIGHT",
    "CapacityError",
    "ItemKind",
    "ItemLineage",
    "ItemStatus",
    "ItemValidation",
    "KnowledgeItem",
    "LineageChecker",
    "LineageError",
    "MotifStep",
    "SemanticMemory",
    "SessionScore",
    "TrustedKnowledgeState",
    "anchor_masks",
    "canonical_float",
    "context_id_for",
    "genesis_state",
    "is_escalating",
    "item_applies",
    "knowledge_item_id",
    "match_motif",
    "motif_pattern_key",
    "score_session",
]

ALL_CONTEXTS = "*"
GENESIS_CANDIDATE_ID = "genesis"
STATE_FORMAT = "pocketsec.stage6.trusted_knowledge_state/1"

MAX_DETECTOR_ITEMS: int = 64
MAX_BASELINE_ITEMS: int = 128
MAX_PROCEDURE_ITEMS: int = 64
MAX_REHEARSAL_EXEMPLARS: int = 128
MAX_TRUSTED_STATE_BYTES: int = 1_048_576
MAX_MOTIF_LENGTH: int = 2
MAX_ITEM_CAPSULE_REFS: int = 16
#: Epochs remembered per item. Stage 2 bounds a pending pattern's epoch history at 8
#: for the same reason: a long-lived item must not accumulate unbounded history.
#: :meth:`ItemValidation.matched` keeps the most recent ones; construction refuses more.
MAX_ITEM_EPOCHS: int = 16
UNEXPLAINED_WEIGHT: float = 0.5
DEFAULT_THRESHOLD: float = 0.5
#: Floats in the canonical form are rounded to this many places. Chosen to equal the
#: capsule's ``FEATURE_DECIMALS`` so rounding here never changes a stored feature.
STATE_FLOAT_DECIMALS: int = 6

_LAYOUT = dict(FEATURE_LAYOUT)
MEANING_WIDTH: int = sum(_LAYOUT[group] for group in MEANING_GROUPS)
_OBJECT_WIDTH: int = _LAYOUT["object_semantics"]
_RAISED_WIDTH: int = _LAYOUT["state_delta_raised"]
# The meaning vector starts with object_semantics then state_delta_raised; the
# anchor -> mask derivation below depends on that order, so it is asserted.
assert MEANING_GROUPS[:2] == ("object_semantics", "state_delta_raised")

#: Every key Stage 2's ``pattern_key`` can produce, computed BY that function over a
#: probe per relation rather than by copying its format string. A BASELINE keyed
#: anywhere else could never explain a step (Rule A), so it is refused at construction
#: instead of sitting inert in trusted state.
STAGE2_BASELINE_KEYS: frozenset[str] = frozenset(
    pattern_key(EncodedTransition((0.0,) * FEATURE_WIDTH, int(r), 0, 0, 0, 0.0, 0, 0))
    for r in Relation
)

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_HEX = 32  # 128-bit content ids: a 64-bit prefix is collidable by a patient attacker


class LineageError(ContractError):
    """A trusted item that cannot say where it came from."""


class CapacityError(ContractError):
    """A trusted store would exceed a named cap. Raised instead of dropping anything."""


class LineageChecker(Protocol):
    """What ``from_canonical_bytes`` needs from the lineage DAG, and nothing more.

    A Protocol so this module never imports ``fossils/``: the DAG depends on trusted
    items, and trusted items must not depend on the DAG's implementation.
    """

    def lineage_complete(self, item: KnowledgeItem) -> bool: ...


def canonical_float(value: float) -> float:
    """Round for the canonical form; ``+ 0.0`` folds ``-0.0`` into ``0.0``."""
    numeric = float(value)
    if numeric != numeric or numeric in (float("inf"), float("-inf")):
        raise ContractError(f"trusted state floats must be finite, got {value!r}")
    return round(numeric, STATE_FLOAT_DECIMALS) + 0.0


def _canonical_json(payload: Any) -> bytes:
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return (text + "\n").encode("utf-8")


def _short_digest(payload: Any) -> str:
    return digest_of_bytes(_canonical_json(payload))[len("sha256:") :][:_ID_HEX]


def context_id_for(identity: SystemIdentity) -> str:
    """THE context key. Every producer and consumer of a context id calls this."""
    if not isinstance(identity, SystemIdentity):
        raise ContractError(f"context_id_for needs a SystemIdentity, got {type(identity).__name__}")
    return "ctx-" + identity.key()


class ItemKind(StrEnum):
    DETECTOR = "DETECTOR"
    BASELINE = "BASELINE"
    PROCEDURE = "PROCEDURE"
    THRESHOLD = "THRESHOLD"


class ItemStatus(StrEnum):
    """RETIRED and FOSSILIZED items leave the state; they are not statuses here."""

    ACTIVE = "ACTIVE"
    DORMANT = "DORMANT"


def _require_count(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ContractError(f"{field} must be a non-negative int, got {value!r}")
    return value


@dataclass(frozen=True, slots=True)
class MotifStep:
    """One bitmask test against the encoder's own masks — no float, no learned weight."""

    relation: int
    require_properties: int
    forbid_properties: int
    require_raised: int

    def __post_init__(self) -> None:
        for name in ("relation", "require_properties", "forbid_properties", "require_raised"):
            _require_count(getattr(self, name), f"MotifStep.{name}")
        if self.require_properties & self.forbid_properties:
            raise ContractError("a motif step requiring and forbidding one property never matches")

    def matches(self, step: EncodedStep) -> bool:
        props = step.object_property_mask
        return (
            step.relation == self.relation
            and (props & self.require_properties) == self.require_properties
            and (props & self.forbid_properties) == 0
            and (step.state_delta_mask & self.require_raised) == self.require_raised
        )

    def to_payload(self) -> list[int]:
        return [self.relation, self.require_properties, self.forbid_properties, self.require_raised]


def motif_pattern_key(motif: Sequence[MotifStep]) -> str:
    """A DETECTOR's pattern key: ``"motif:<digest>"`` over its steps."""
    return "motif:" + _short_digest([step.to_payload() for step in motif])


def anchor_masks(anchor: Sequence[float]) -> tuple[int, int]:
    """(object property mask, raised mask) a Stage 2 meaning vector asserts.

    The meaning vector's object group is in the encoder's property order and its
    raised group in ``DIMENSIONS`` order — the same bit orders as
    ``object_property_mask`` and ``StateDelta.bitmask()``.
    """
    props = sum(1 << i for i, v in enumerate(anchor[:_OBJECT_WIDTH]) if v >= 0.5)
    raised_values = anchor[_OBJECT_WIDTH : _OBJECT_WIDTH + _RAISED_WIDTH]
    raised = sum(1 << i for i, v in enumerate(raised_values) if v >= 0.5)
    return props, raised


def is_escalating(step: EncodedStep) -> bool:
    """A step that touches a protected anchor or raises any capability.

    The complement of the score's "non-escalating" test, kept in one place so
    episodic skeletons and the score can never disagree about it.
    """
    return bool(step.state_delta_mask) or bool(
        touches_protected(step.object_property_mask, step.state_delta_mask)
    )


@dataclass(frozen=True, slots=True)
class ItemLineage:
    candidate_id: str
    capsule_ids: tuple[str, ...]
    evidence_digests: tuple[str, ...]
    parent_item_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.candidate_id, str) or not self.candidate_id:
            raise ContractError("ItemLineage.candidate_id must be a non-empty string")
        for name in ("capsule_ids", "evidence_digests", "parent_item_ids"):
            values = tuple(getattr(self, name))
            if any(not isinstance(v, str) or not v for v in values):
                raise ContractError(f"ItemLineage.{name} must hold non-empty strings")
            object.__setattr__(self, name, values)
        if len(self.capsule_ids) > MAX_ITEM_CAPSULE_REFS:
            raise CapacityError(
                f"an item cites {len(self.capsule_ids)} capsules; cap is {MAX_ITEM_CAPSULE_REFS}"
            )
        bad = [d for d in self.evidence_digests if not _DIGEST_RE.fullmatch(d)]
        if bad:
            raise ContractError(f"evidence is referenced by sha256 digest only; got {bad[0]!r}")

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"candidate_id": self.candidate_id}
        for name in ("capsule_ids", "evidence_digests", "parent_item_ids"):
            payload[name] = list(getattr(self, name))
        return payload


_VALIDATION_COUNTS = (
    "validations", "recurrence", "contradictions", "first_sequence", "last_matched_sequence"
)


@dataclass(frozen=True, slots=True)
class ItemValidation:
    validations: int
    recurrence: int
    contradictions: int
    first_sequence: int
    last_matched_sequence: int
    epochs_seen: frozenset[int]

    def __post_init__(self) -> None:
        for name in _VALIDATION_COUNTS:
            _require_count(getattr(self, name), f"ItemValidation.{name}")
        epochs = frozenset(self.epochs_seen)
        for epoch in epochs:
            _require_count(epoch, "ItemValidation.epochs_seen[]")
        if len(epochs) > MAX_ITEM_EPOCHS:
            raise CapacityError(f"an item remembers at most {MAX_ITEM_EPOCHS} epochs")
        object.__setattr__(self, "epochs_seen", epochs)

    @classmethod
    def fresh(cls, *, sequence: int, epoch_id: int | None = None) -> ItemValidation:
        epochs = frozenset() if epoch_id is None else frozenset({epoch_id})
        return cls(0, 0, 0, sequence, sequence, epochs)

    def matched(self, *, sequence: int, epoch_id: int) -> ItemValidation:
        """One more recurrence. Keeps the most recent ``MAX_ITEM_EPOCHS`` epochs."""
        epochs = sorted(self.epochs_seen | {epoch_id})[-MAX_ITEM_EPOCHS:]
        return dataclasses.replace(
            self,
            recurrence=self.recurrence + 1,
            last_matched_sequence=max(self.last_matched_sequence, sequence),
            epochs_seen=frozenset(epochs),
        )

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {name: getattr(self, name) for name in _VALIDATION_COUNTS}
        payload["epochs_seen"] = sorted(self.epochs_seen)
        return payload


def knowledge_item_id(
    kind: ItemKind,
    motif: Sequence[MotifStep],
    anchor: Sequence[float],
    pattern_key_value: str,
    context_ids: Iterable[str],
) -> str:
    """``"k-"`` + digest prefix of what the item *is*. Weight, status and lineage
    are excluded on purpose: re-weighting or making an item dormant is the same item."""
    material = {
        "kind": ItemKind(kind).value,
        "motif": [step.to_payload() for step in motif],
        "anchor": [canonical_float(v) for v in anchor],
        "pattern_key": pattern_key_value,
        "context_ids": sorted(context_ids),
    }
    return "k-" + _short_digest(material)


def _check_contexts(context_ids: frozenset[str]) -> None:
    if not context_ids:
        raise ContractError("an item must apply to at least one context")
    for ctx in context_ids:
        if not isinstance(ctx, str) or not (ctx == ALL_CONTEXTS or ctx.startswith("ctx-")):
            raise ContractError(
                f"context ids come from context_id_for() or are ALL_CONTEXTS; got {ctx!r}"
            )


def _derived_protection(item: KnowledgeItem) -> bool:
    if item.kind is ItemKind.DETECTOR:
        return any(touches_protected(s.require_properties, s.require_raised) for s in item.motif)
    if item.kind is ItemKind.BASELINE:
        props, raised = anchor_masks(item.anchor)
        return bool(touches_protected(props, raised))
    return False


def _check_shape(item: KnowledgeItem) -> None:
    kind = item.kind
    if kind is ItemKind.DETECTOR:
        if not 1 <= len(item.motif) <= MAX_MOTIF_LENGTH or item.anchor:
            raise ContractError(f"a DETECTOR holds 1..{MAX_MOTIF_LENGTH} motif steps and no anchor")
        if item.pattern_key != motif_pattern_key(item.motif):
            raise ContractError("a DETECTOR's pattern_key is motif_pattern_key(motif)")
        if item.origin_verdict is not Verdict.MALICIOUS or not 0.0 <= item.weight <= 1.0:
            raise ContractError("a DETECTOR is MALICIOUS-origin with a precision weight in [0, 1]")
    elif kind is ItemKind.BASELINE:
        if item.motif or len(item.anchor) != MEANING_WIDTH:
            raise ContractError(f"a BASELINE holds a {MEANING_WIDTH}-float anchor and no motif")
        if item.pattern_key not in STAGE2_BASELINE_KEYS:
            raise ContractError(f"BASELINE key {item.pattern_key!r} is not a Stage 2 pattern_key")
        if item.origin_verdict is not Verdict.BENIGN or item.weight < 0.0:
            raise ContractError("a BASELINE is BENIGN-origin with a non-negative radius")
    elif kind is ItemKind.PROCEDURE:
        _check_procedure(item)
    elif item.motif or item.anchor or not 0.0 <= item.weight <= 1.0:
        raise ContractError("the THRESHOLD item holds one weight in [0, 1] and nothing else")
    if kind is not ItemKind.PROCEDURE and item.procedure is not None:
        raise ContractError("only a PROCEDURE item carries a ProcedureRecord")


def _check_procedure(item: KnowledgeItem) -> None:
    from pocketsec.stage6.memory.procedural import ProcedureRecord, procedure_key

    record = item.procedure
    if not isinstance(record, ProcedureRecord) or item.motif or item.anchor:
        raise ContractError("a PROCEDURE carries a ProcedureRecord and nothing else")
    if item.pattern_key != procedure_key(record.operator_id, record.context_id):
        raise ContractError("a PROCEDURE's pattern_key is procedure_key(operator_id, context_id)")
    if item.context_ids != frozenset({record.context_id}):
        raise ContractError("a PROCEDURE applies to exactly the context it was verified in")


@dataclass(frozen=True, slots=True)
class KnowledgeItem:
    """One unit of trusted knowledge. Content-addressed; lineage mandatory to load."""

    item_id: str
    kind: ItemKind
    status: ItemStatus
    context_ids: frozenset[str]
    motif: tuple[MotifStep, ...]
    anchor: tuple[float, ...]
    pattern_key: str
    weight: float
    origin_verdict: Verdict
    protected: bool
    lineage: ItemLineage
    validation: ItemValidation
    procedure: ProcedureRecord | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", ItemKind(self.kind))
        object.__setattr__(self, "status", ItemStatus(self.status))
        object.__setattr__(self, "context_ids", frozenset(self.context_ids))
        object.__setattr__(self, "motif", tuple(self.motif))
        object.__setattr__(self, "anchor", tuple(canonical_float(v) for v in self.anchor))
        object.__setattr__(self, "weight", canonical_float(self.weight))
        if not isinstance(self.protected, bool):
            raise ContractError(f"protected must be a bool, got {self.protected!r}")
        if not isinstance(self.origin_verdict, Verdict):
            # A family name ("credential_theft") is not a verdict and never becomes one.
            raise ContractError(f"origin_verdict must be a Verdict, got {self.origin_verdict!r}")
        if not isinstance(self.lineage, ItemLineage):
            raise ContractError("an item carries an ItemLineage")
        if not isinstance(self.validation, ItemValidation):
            raise ContractError("an item carries an ItemValidation")
        _check_contexts(self.context_ids)
        _check_shape(self)
        expected = knowledge_item_id(
            self.kind, self.motif, self.anchor, self.pattern_key, self.context_ids
        )
        if self.item_id != expected:
            raise ContractError(
                f"item_id {self.item_id!r} is not content-addressed (expected {expected!r}); "
                "build items with KnowledgeItem.build"
            )
        if _derived_protection(self) and not self.protected:
            raise ContractError(
                "an item touching a protected anchor must be protected; it cannot opt out"
            )

    @classmethod
    def build(
        cls,
        *,
        kind: ItemKind,
        context_ids: Iterable[str],
        pattern_key: str,
        weight: float,
        origin_verdict: Verdict,
        lineage: ItemLineage,
        validation: ItemValidation,
        motif: Sequence[MotifStep] = (),
        anchor: Sequence[float] = (),
        status: ItemStatus = ItemStatus.ACTIVE,
        protected: bool | None = None,
        procedure: ProcedureRecord | None = None,
    ) -> KnowledgeItem:
        """Construct an item with its content id computed; ``protected=None`` derives it."""
        contexts = frozenset(context_ids)
        item_id = knowledge_item_id(kind, motif, anchor, pattern_key, contexts)
        # Built protected first so the opt-out check passes, then narrowed to the
        # derived value: derivation needs a constructed (validated) item.
        item = cls(
            item_id, kind, status, contexts, tuple(motif), tuple(anchor), pattern_key, weight,
            origin_verdict, True if protected is None else protected, lineage, validation,
            procedure,
        )
        if protected is None:
            return dataclasses.replace(item, protected=_derived_protection(item))
        return item

    def to_payload(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "kind": self.kind.value,
            "status": self.status.value,
            "context_ids": sorted(self.context_ids),
            "motif": [step.to_payload() for step in self.motif],
            "anchor": list(self.anchor),
            "pattern_key": self.pattern_key,
            "weight": self.weight,
            "origin_verdict": self.origin_verdict.value,
            "protected": self.protected,
            "lineage": self.lineage.to_payload(),
            "validation": self.validation.to_payload(),
            "procedure": None if self.procedure is None else self.procedure.to_payload(),
        }


def _require_lineage(item: KnowledgeItem) -> None:
    lineage = item.lineage
    if lineage.candidate_id == GENESIS_CANDIDATE_ID:
        if item.kind is not ItemKind.THRESHOLD:
            raise LineageError(
                f"item {item.item_id} ({item.kind.value}) claims genesis; only the genesis "
                "THRESHOLD may carry no evidence"
            )
        return
    if not lineage.capsule_ids or not lineage.evidence_digests:
        raise LineageError(
            f"item {item.item_id} names no capsule or no evidence digest; an item without "
            "lineage is never trusted"
        )


def item_applies(item: KnowledgeItem, context_id: str) -> bool:
    """ACTIVE and bound to this context (or to all). Other contexts are dormant by construction."""
    return item.status is ItemStatus.ACTIVE and (
        ALL_CONTEXTS in item.context_ids or context_id in item.context_ids
    )


_KIND_CAPS: dict[ItemKind, int] = {
    ItemKind.DETECTOR: MAX_DETECTOR_ITEMS,
    ItemKind.BASELINE: MAX_BASELINE_ITEMS,
    ItemKind.PROCEDURE: MAX_PROCEDURE_ITEMS,
    ItemKind.THRESHOLD: 1,
}

_STATE_KEYS = frozenset(
    {"format", "version", "parent_digest", "active_context", "items", "rehearsal"}
)


@dataclass(frozen=True, slots=True)
class TrustedKnowledgeState:
    """The endpoint's trusted cognition as one immutable, hashable value."""

    version: int
    parent_digest: str | None
    active_context: str
    items: tuple[KnowledgeItem, ...]
    rehearsal: tuple[EpisodeSkeleton, ...]

    def __post_init__(self) -> None:
        _require_count(self.version, "TrustedKnowledgeState.version")
        if self.parent_digest is not None and not _DIGEST_RE.fullmatch(str(self.parent_digest)):
            raise ContractError("parent_digest is None or a sha256 digest")
        if not isinstance(self.active_context, str) or not self.active_context.startswith("ctx-"):
            raise ContractError("active_context comes from context_id_for()")
        from pocketsec.stage6.memory.episodic import EpisodeSkeleton  # cycle: see top

        if not all(isinstance(item, KnowledgeItem) for item in self.items):
            raise ContractError("trusted state holds KnowledgeItem values only")
        if not all(isinstance(sk, EpisodeSkeleton) for sk in self.rehearsal):
            raise ContractError("the rehearsal set holds EpisodeSkeleton values only")
        items = tuple(sorted(self.items, key=lambda item: item.item_id))
        rehearsal = tuple(sorted(self.rehearsal, key=lambda sk: sk.episode_id))
        _refuse_duplicates([item.item_id for item in items], "item")
        _refuse_duplicates([sk.episode_id for sk in rehearsal], "rehearsal exemplar")
        object.__setattr__(self, "items", items)
        object.__setattr__(self, "rehearsal", rehearsal)
        for kind, cap in _KIND_CAPS.items():
            count = sum(1 for item in items if item.kind is kind)
            if count > cap:
                raise CapacityError(f"{count} {kind.value} items exceed the cap of {cap}")
        if sum(1 for item in items if item.kind is ItemKind.THRESHOLD) != 1:
            raise ContractError("a trusted state holds exactly one THRESHOLD item")
        if len(rehearsal) > MAX_REHEARSAL_EXEMPLARS:
            raise CapacityError(
                f"{len(rehearsal)} rehearsal exemplars exceed the cap of {MAX_REHEARSAL_EXEMPLARS}"
            )
        size = len(self.canonical_bytes())
        if size > MAX_TRUSTED_STATE_BYTES:
            raise CapacityError(f"trusted state is {size} bytes; cap is {MAX_TRUSTED_STATE_BYTES}")

    def canonical_bytes(self) -> bytes:
        """Sorted keys, rounded floats, no NaN, trailing newline. The digest's input."""
        return _canonical_json(
            {
                "format": STATE_FORMAT,
                "version": self.version,
                "parent_digest": self.parent_digest,
                "active_context": self.active_context,
                "items": [item.to_payload() for item in self.items],
                "rehearsal": [sk.to_payload() for sk in self.rehearsal],
            }
        )

    def digest(self) -> str:
        return digest_of_bytes(self.canonical_bytes())

    def byte_size(self) -> int:
        return len(self.canonical_bytes())

    @classmethod
    def from_canonical_bytes(
        cls, data: bytes, *, lineage: LineageChecker | None = None
    ) -> TrustedKnowledgeState:
        """Load a state, refusing any item without lineage and any non-canonical input."""
        # Local imports: see the TYPE_CHECKING block at the top of the module.
        from pocketsec.stage6.memory.episodic import EpisodeSkeleton

        payload = _parse_state(data)
        items = tuple(_item_from_payload(raw) for raw in payload["items"])
        for item in items:
            _require_lineage(item)
            if lineage is not None and not lineage.lineage_complete(item):
                raise LineageError(f"item {item.item_id} has no complete lineage in the DAG")
        state = cls(
            version=payload["version"],
            parent_digest=payload["parent_digest"],
            active_context=payload["active_context"],
            items=items,
            rehearsal=tuple(EpisodeSkeleton.from_payload(raw) for raw in payload["rehearsal"]),
        )
        if state.canonical_bytes() != data:
            raise ContractError("trusted state bytes are not canonical; refusing to load them")
        return state

    def with_changes(
        self,
        *,
        add: Sequence[KnowledgeItem] = (),
        remove: Sequence[str] = (),
        replace: Sequence[tuple[str, KnowledgeItem]] = (),
        threshold: float | None = None,
        rehearsal: Sequence[EpisodeSkeleton] | None = None,
        active_context: str | None = None,
        threshold_lineage: ItemLineage | None = None,
    ) -> TrustedKnowledgeState:
        """A new state one version on, whose parent is this one. Raises past any cap.

        ``threshold_lineage`` — the candidate and the evidence a learned threshold was fitted
        on — replaces the THRESHOLD item's lineage; the chamber always passes it. The item id
        never changes (weight is not identity), so without it a learned threshold kept
        claiming genesis provenance (review F3 / S6-AUTH-08). A draft built without it keeps
        the old lineage and is refused wherever trust is conferred: a THRESHOLD claiming
        genesis at a non-genesis weight fails ``lineage_complete`` at load.
        """
        by_id = {item.item_id: item for item in self.items}
        for item_id in remove:
            if item_id not in by_id:
                raise ContractError(f"cannot remove unknown item {item_id!r}")
            del by_id[item_id]
        for old_id, new_item in replace:
            if old_id not in by_id:
                raise ContractError(f"cannot replace unknown item {old_id!r}")
            del by_id[old_id]
            _admit_into(by_id, new_item)
        for new_item in add:
            _admit_into(by_id, new_item)
        if threshold is not None:
            current = [item for item in by_id.values() if item.kind is ItemKind.THRESHOLD]
            if len(current) != 1:
                raise ContractError("a threshold change needs exactly one THRESHOLD item")
            by_id[current[0].item_id] = _rethreshold(current[0], threshold, threshold_lineage)
        return TrustedKnowledgeState(
            version=self.version + 1,
            parent_digest=self.digest(),
            active_context=self.active_context if active_context is None else active_context,
            items=tuple(by_id.values()),
            rehearsal=self.rehearsal if rehearsal is None else tuple(rehearsal),
        )

    def _of_kind(self, kind: ItemKind) -> tuple[KnowledgeItem, ...]:
        return tuple(item for item in self.items if item.kind is kind)

    def detectors(self) -> tuple[KnowledgeItem, ...]:
        return self._of_kind(ItemKind.DETECTOR)

    def baselines(self) -> tuple[KnowledgeItem, ...]:
        return self._of_kind(ItemKind.BASELINE)

    def procedures(self) -> tuple[KnowledgeItem, ...]:
        return self._of_kind(ItemKind.PROCEDURE)

    def threshold(self) -> float:
        return self._of_kind(ItemKind.THRESHOLD)[0].weight


def _rethreshold(item: KnowledgeItem, threshold: float,
                 lineage: ItemLineage | None) -> KnowledgeItem:
    if lineage is None:
        return dataclasses.replace(item, weight=threshold)
    if lineage.candidate_id == GENESIS_CANDIDATE_ID:
        raise LineageError("a learned threshold cannot claim genesis provenance")
    return dataclasses.replace(item, weight=threshold, lineage=lineage)


def _refuse_duplicates(ids: Sequence[str], what: str) -> None:
    if len(set(ids)) != len(ids):
        raise ContractError(f"duplicate {what} id in a trusted state")


def _admit_into(by_id: dict[str, KnowledgeItem], item: KnowledgeItem) -> None:
    if not isinstance(item, KnowledgeItem):
        raise ContractError(f"only KnowledgeItem enters trusted state, got {type(item).__name__}")
    _require_lineage(item)
    if item.item_id in by_id:
        raise ContractError(f"item {item.item_id} is already present; replace it instead")
    by_id[item.item_id] = item


def _parse_state(data: bytes) -> dict[str, Any]:
    if not isinstance(data, (bytes, bytearray)):
        raise ContractError("trusted state loads from bytes")
    try:
        payload = json.loads(bytes(data).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"trusted state bytes are not canonical JSON: {exc}") from exc
    if not isinstance(payload, dict) or set(payload) != _STATE_KEYS:
        raise ContractError("trusted state payload has the wrong keys")
    if payload["format"] != STATE_FORMAT:
        raise ContractError(f"unknown trusted state format {payload['format']!r}")
    if not isinstance(payload["items"], list) or not isinstance(payload["rehearsal"], list):
        raise ContractError("trusted state items and rehearsal are lists")
    return payload


_ITEM_KEYS = frozenset(KnowledgeItem.__dataclass_fields__)


def _item_from_payload(raw: object) -> KnowledgeItem:
    from pocketsec.stage6.memory.procedural import ProcedureRecord

    if not isinstance(raw, dict) or set(raw) != _ITEM_KEYS:
        raise ContractError("a trusted item payload has the wrong keys")
    try:
        lineage = ItemLineage(**raw["lineage"])
        checks = dict(raw["validation"])
        checks["epochs_seen"] = frozenset(checks["epochs_seen"])
        validation = ItemValidation(**checks)
        motif = tuple(MotifStep(*step) for step in raw["motif"])
        record = raw["procedure"]
        procedure = None if record is None else ProcedureRecord.from_payload(record)
        fields = {**raw, "kind": ItemKind(raw["kind"]), "status": ItemStatus(raw["status"])}
        fields.update(
            context_ids=frozenset(raw["context_ids"]), motif=motif, anchor=tuple(raw["anchor"]),
            origin_verdict=Verdict(raw["origin_verdict"]), lineage=lineage,
            validation=validation, procedure=procedure,
        )
        return KnowledgeItem(**fields)
    except (TypeError, ValueError, KeyError) as exc:
        if isinstance(exc, ContractError):
            raise
        raise ContractError(f"malformed trusted item payload: {exc}") from exc


def genesis_state(
    *, identity: SystemIdentity, threshold: float = DEFAULT_THRESHOLD
) -> TrustedKnowledgeState:
    """Version 0: one THRESHOLD item and nothing learned."""
    item = KnowledgeItem.build(
        kind=ItemKind.THRESHOLD,
        context_ids=(ALL_CONTEXTS,),
        pattern_key="threshold",
        weight=threshold,
        origin_verdict=Verdict.UNKNOWN,
        lineage=ItemLineage(GENESIS_CANDIDATE_ID, (), (), ()),
        validation=ItemValidation.fresh(sequence=0),
        protected=False,
    )
    return TrustedKnowledgeState(0, None, context_id_for(identity), (item,), ())


@dataclass(frozen=True, slots=True)
class SessionScore:
    score: float
    detector_hits: tuple[str, ...]
    unexplained: float  # the U term itself, already weighted: never above UNEXPLAINED_WEIGHT
    work_units: int


def match_motif(motif: Sequence[MotifStep], steps: Sequence[EncodedStep]) -> bool:
    """Length 1: any step matches. Length 2: step i then step j (i < j) of ONE actor.

    The same-actor rule is the whole point: "read a credential, later send to an
    external endpoint" is a conjunction over one lineage, and two actors each doing
    half of it is a different — usually benign — session.
    """
    if not 1 <= len(motif) <= MAX_MOTIF_LENGTH:
        raise ContractError(f"a motif has 1..{MAX_MOTIF_LENGTH} steps, got {len(motif)}")
    first = motif[0]
    if len(motif) == 1:
        return any(first.matches(step) for step in steps)
    second = motif[1]
    armed: set[int] = set()
    for step in steps:
        # Checking the second step before arming keeps i < j strict for one step
        # that would satisfy both halves.
        if step.actor_slot in armed and second.matches(step):
            return True
        if first.matches(step):
            armed.add(step.actor_slot)
    return False


def _unexplained_share(
    steps: Sequence[EncodedStep], baselines: Sequence[KnowledgeItem], charge: _Counter
) -> float:
    per_actor: dict[int, list[int]] = {}
    for step in steps:
        if is_escalating(step):
            continue  # escalating steps are never "unexplained normality"
        counts = per_actor.setdefault(step.actor_slot, [0, 0])
        counts[1] += 1
        charge.add(len(baselines))
        if not baselines:
            counts[0] += 1
            continue
        key = pattern_key(step.to_encoded())
        meaning = step.meaning()
        explained = any(
            b.pattern_key == key and meaning_distance(meaning, b.anchor) <= b.weight
            for b in baselines
        )
        if not explained:
            counts[0] += 1
    return max((u / n for u, n in per_actor.values() if n), default=0.0)


class _Counter:
    __slots__ = ("meter", "units")

    def __init__(self, meter: WorkMeter | None) -> None:
        self.meter = meter
        self.units = 0

    def add(self, units: int) -> None:
        if units <= 0:
            return
        if self.meter is not None:
            self.meter.charge(units)
        self.units += units


def score_session(
    state: TrustedKnowledgeState,
    steps: Sequence[EncodedStep],
    *,
    context_id: str,
    meter: WorkMeter | None = None,
) -> SessionScore:
    """score = max(D, U), charging one work unit per item x step comparison."""
    charge = _Counter(meter)
    applicable = [item for item in state.items if item_applies(item, context_id)]
    detector_score = 0.0
    hits: list[str] = []
    for item in applicable:
        if item.kind is not ItemKind.DETECTOR:
            continue
        charge.add(len(steps))
        if match_motif(item.motif, steps):
            hits.append(item.item_id)
            detector_score = max(detector_score, item.weight)
    baselines = [item for item in applicable if item.kind is ItemKind.BASELINE]
    unexplained = UNEXPLAINED_WEIGHT * _unexplained_share(steps, baselines, charge)
    return SessionScore(
        score=max(detector_score, unexplained),
        detector_hits=tuple(sorted(hits)),
        unexplained=unexplained,
        work_units=charge.units,
    )


class SemanticMemory:
    """Read-only view of a trusted state — the plan's exposed name. Holds no state of its own."""

    __slots__ = ("_state",)

    def __init__(self, state: TrustedKnowledgeState) -> None:
        if not isinstance(state, TrustedKnowledgeState):
            raise ContractError("SemanticMemory views a TrustedKnowledgeState")
        self._state = state

    def lookup(self, pattern_key_value: str) -> tuple[KnowledgeItem, ...]:
        return tuple(item for item in self._state.items if item.pattern_key == pattern_key_value)

    def detectors(self) -> tuple[KnowledgeItem, ...]:
        return self._state.detectors()

    def baselines(self, context_id: str) -> tuple[KnowledgeItem, ...]:
        """Baselines that would explain a step in ``context_id`` — dormant contexts excluded."""
        return tuple(item for item in self._state.baselines() if item_applies(item, context_id))
