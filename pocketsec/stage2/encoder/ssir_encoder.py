"""DTL-F01 — ``encode_ssir_transition``.

Turns one Stage 1 SSIR transition into a fixed feature vector. **Every** Stage 2
model — DTL and all nine baselines — consumes this exact encoding, which is what
makes acceptance criterion 1 ("identical Stage 1 inputs and evaluation splits")
mean something. A baseline fed a different encoding would be a different
experiment.

Design constraints inherited from Stage 1:

* **No identity, no names.** `exact_identity` was frozen out of the model-facing
  encoding (ADR-0007) after measuring that behaviour alone suffices. Executable
  names and command strings must not become model vocabulary.
* **The three signals stay separate.** Novelty, security potential and
  uncertainty occupy distinct feature slots; nothing here collapses them.
* **Surprise is structured, not scalar.** The feature layout mirrors the surprise
  geometry of spec section 9, so a downstream head can learn a *direction* of
  surprise rather than only a magnitude.

Stdlib only: this runs on the endpoint.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pocketsec.stage1.novelty.engine import NOVELTY_CONTEXTS
from pocketsec.stage1.ssir.entities import SemanticProperty
from pocketsec.stage1.ssir.relations import Relation, RelationFamily, family_of
from pocketsec.stage1.ssir.transition import SSIRTransitionV1
from pocketsec.stage1.state.security_state import DIMENSIONS

__all__ = [
    "ENCODER_VERSION",
    "GROUP_OFFSETS",
    "NEED_SIGNAL_INDICES",
    "FEATURE_LAYOUT",
    "FEATURE_WIDTH",
    "EncodedTransition",
    "encode_ssir_transition",
    "feature_names",
]

ENCODER_VERSION = "dtl-encoder.1.0.0"

#: Semantic properties the encoder exposes, in a frozen order. A subset of the
#: full vocabulary: only properties that a model could plausibly act on, kept
#: stable so learned weights stay meaningful across runs.
_ENCODED_PROPERTIES: tuple[SemanticProperty, ...] = (
    SemanticProperty.CREDENTIAL,
    SemanticProperty.AUTHORIZATION_DATA,
    SemanticProperty.PERSISTENCE,
    SemanticProperty.ROOT_OWNED,
    SemanticProperty.USER_WRITABLE,
    SemanticProperty.SYSTEM_BINARY,
    SemanticProperty.TEMP_LOCATION,
    SemanticProperty.EXTERNAL_ENDPOINT,
    SemanticProperty.INTERPRETER,
    SemanticProperty.NETWORK_CLIENT,
    SemanticProperty.NETWORK_SERVER,
    SemanticProperty.PROCESS_SPAWNER,
    SemanticProperty.CREDENTIAL_READER,
    SemanticProperty.PRIVILEGE_CHANGER,
    SemanticProperty.PERSISTENCE_WRITER,
)

_DIMENSION_NAMES: tuple[str, ...] = tuple(DIMENSIONS)
_MAX_TIME_BUCKET = 15.0
#: ΔΦ is unbounded above; squashed rather than clipped so large jumps still
#: order correctly instead of saturating at the ceiling.
_PHI_SCALE = 8.0


def _feature_layout() -> tuple[tuple[str, int], ...]:
    """(group, width) pairs. The single source of truth for the vector shape."""
    return (
        ("relation_onehot", len(Relation)),
        ("relation_family_onehot", len(RelationFamily)),
        ("actor_semantics", len(_ENCODED_PROPERTIES)),
        ("object_semantics", len(_ENCODED_PROPERTIES)),
        ("state_delta_raised", len(_DIMENSION_NAMES)),
        ("state_delta_scalars", 2),  # magnitude, dimension count
        ("delta_phi", 2),  # squashed ΔΦ, sign of movement
        ("novelty_tensor", len(NOVELTY_CONTEXTS)),
        ("novelty_scalars", 2),  # peak, mean
        ("uncertainty", 2),  # uncertainty, observation_incomplete
        ("temporal", 3),  # actor bucket, host bucket, burst indicator
        ("causal", 2),  # responsibility, has-parent
        ("representation_level", 4),
    )


FEATURE_LAYOUT: tuple[tuple[str, int], ...] = _feature_layout()
FEATURE_WIDTH: int = sum(width for _, width in FEATURE_LAYOUT)


def _group_offsets() -> dict[str, int]:
    """Start index of each feature group, derived from the layout."""
    offsets: dict[str, int] = {}
    cursor = 0
    for group, width in FEATURE_LAYOUT:
        offsets[group] = cursor
        cursor += width
    return offsets


GROUP_OFFSETS: dict[str, int] = _group_offsets()

#: Named indices for the five Need-to-Compute signals (DTL-F02). Derived from
#: the layout, never hardcoded: a magic index into a frozen layout silently
#: points at the wrong feature the moment the layout grows.
NEED_SIGNAL_INDICES: dict[str, int] = {
    "novelty_peak": GROUP_OFFSETS["novelty_scalars"],
    "delta_phi": GROUP_OFFSETS["delta_phi"],
    "uncertainty": GROUP_OFFSETS["uncertainty"],
    "responsibility": GROUP_OFFSETS["causal"],
    "state_delta_magnitude": GROUP_OFFSETS["state_delta_scalars"],
}


def feature_names() -> tuple[str, ...]:
    """Per-slot names, for ablation reports and weight inspection."""
    names: list[str] = []
    for group, width in FEATURE_LAYOUT:
        if group == "relation_onehot":
            names.extend(f"relation={r.name}" for r in Relation)
        elif group == "relation_family_onehot":
            names.extend(f"relfam={f.name}" for f in RelationFamily)
        elif group in ("actor_semantics", "object_semantics"):
            prefix = "actor" if group.startswith("actor") else "object"
            names.extend(f"{prefix}.{p.value}" for p in _ENCODED_PROPERTIES)
        elif group == "state_delta_raised":
            names.extend(f"raised.{d}" for d in _DIMENSION_NAMES)
        elif group == "novelty_tensor":
            names.extend(f"novelty.{c}" for c in NOVELTY_CONTEXTS)
        else:
            names.extend(f"{group}[{i}]" for i in range(width))
    return tuple(names)


@dataclass(frozen=True, slots=True)
class EncodedTransition:
    """One transition as a feature vector, with its supervision targets.

    The targets are what the multi-head engine (D2.5) learns to predict about
    the *next* transition. They live here so a dataset built once serves every
    model identically.
    """

    features: tuple[float, ...]
    #: Head targets, describing this transition as the "next" of its predecessor.
    relation: int
    relation_family: int
    state_delta_mask: int
    time_bucket: int
    delta_phi: float
    object_property_mask: int
    epoch_id: int
    #: Evidence locators, carried through so a prediction can be bound back to
    #: immutable Stage 1 evidence (DTL-F20). Never used as a model feature.
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "relation": self.relation,
            "relation_family": self.relation_family,
            "state_delta_mask": self.state_delta_mask,
            "time_bucket": self.time_bucket,
            "delta_phi": round(self.delta_phi, 4),
            "object_property_mask": self.object_property_mask,
            "epoch_id": self.epoch_id,
            "evidence": list(self.evidence),
        }


def _property_mask(asserted: frozenset[SemanticProperty]) -> int:
    mask = 0
    for index, prop in enumerate(_ENCODED_PROPERTIES):
        if prop in asserted:
            mask |= 1 << index
    return mask


def encode_ssir_transition(transition: SSIRTransitionV1) -> EncodedTransition:
    """DTL-F01. Deterministic, allocation-light, stdlib only."""
    features: list[float] = []

    # Relation and its family. The family generalises: an unseen relation in a
    # familiar family is less surprising than one in a novel family.
    relation_index = int(transition.relation)
    features.extend(1.0 if i == relation_index else 0.0 for i in range(len(Relation)))
    family_index = int(family_of(transition.relation))
    features.extend(
        1.0 if i == family_index else 0.0 for i in range(len(RelationFamily))
    )

    actor_asserted = transition.actor.semantics.asserted
    object_asserted = transition.object.semantics.asserted
    features.extend(1.0 if p in actor_asserted else 0.0 for p in _ENCODED_PROPERTIES)
    features.extend(1.0 if p in object_asserted else 0.0 for p in _ENCODED_PROPERTIES)

    raised = transition.state_delta.dimensions
    features.extend(1.0 if name in raised else 0.0 for name in _DIMENSION_NAMES)
    features.append(min(1.0, transition.state_delta.magnitude / 4.0))
    features.append(min(1.0, len(raised) / len(_DIMENSION_NAMES)))

    phi = transition.delta_phi
    features.append(abs(phi) / (abs(phi) + _PHI_SCALE) if phi else 0.0)
    features.append(1.0 if phi > 0 else 0.0)

    features.extend(transition.novelty[context] for context in NOVELTY_CONTEXTS)
    features.append(transition.novelty.peak)
    features.append(transition.novelty.mean)

    features.append(transition.uncertainty)
    features.append(1.0 if transition.observation_incomplete else 0.0)

    actor_bucket = transition.temporal.since_actor_bucket
    features.append(actor_bucket / _MAX_TIME_BUCKET)
    features.append(transition.temporal.since_host_bucket / _MAX_TIME_BUCKET)
    # Burst indicator: machine-speed activity, which timing-shift attacks try to
    # hide behind and which slow legitimate work does not produce.
    features.append(1.0 if actor_bucket <= 1 else 0.0)

    features.append(min(1.0, transition.responsibility / _PHI_SCALE))
    features.append(0.0 if transition.parent_signature.strip("0") == "" else 1.0)

    level = int(transition.level)
    features.extend(1.0 if i == level else 0.0 for i in range(4))

    if len(features) != FEATURE_WIDTH:  # pragma: no cover - guarded by a test
        raise AssertionError(
            f"encoder produced {len(features)} features, layout declares {FEATURE_WIDTH}"
        )

    return EncodedTransition(
        features=tuple(features),
        relation=relation_index,
        relation_family=family_index,
        state_delta_mask=transition.state_delta.bitmask(),
        time_bucket=actor_bucket,
        delta_phi=phi,
        object_property_mask=_property_mask(object_asserted),
        epoch_id=transition.epoch_id,
        evidence=tuple(ref.locator for ref in transition.evidence),
    )
