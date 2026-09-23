"""D1.1 — the SSIR transition (spec section 3).

    τ_t = (A, R, O, ΔS, U, N, P, T, E)

The fundamental intelligence unit is a **transition, not a log line**. Everything
Stage 2 learns from arrives in this shape.

Representation levels L0-L3 (spec section 18) control how much of the tuple is
materialised. Escalation is policy-driven: richness increases when novelty,
security potential, uncertainty or causal responsibility justify the cost. A
routine, well-understood transition costs L0 bytes; an incident path costs L3
and keeps the evidence linkage.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import IntEnum
from typing import Any

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef, register_schema
from pocketsec.stage1.novelty.engine import NoveltyTensor
from pocketsec.stage1.ssir.entities import Entity
from pocketsec.stage1.ssir.relations import Relation
from pocketsec.stage1.state.security_state import StateDelta

__all__ = [
    "RepresentationLevel",
    "SSIR_TRANSITION_V1_ID",
    "SSIR_TRANSITION_V1_VERSION",
    "SSIRTransitionV1",
    "TemporalContext",
]

SSIR_TRANSITION_V1_ID = "pocketsec.ssir_transition.v1"
SSIR_TRANSITION_V1_VERSION = register_schema(SSIR_TRANSITION_V1_ID, "1.0.0")


class RepresentationLevel(IntEnum):
    """How much of the transition is materialised (spec section 18)."""

    L0 = 0  # actor + relation + object
    L1 = 1  # + ΔS + novelty + temporal context
    L2 = 2  # + uncertainty + richer semantics + causal context
    L3 = 3  # + evidence linkage + preserved raw context


@dataclass(frozen=True, slots=True)
class TemporalContext:
    """T — time since relevant transitions, bucketed.

    Bucketed rather than exact: a fixed set of log-spaced buckets keeps the
    field one byte and makes timing-shift attacks (spec section 22) harder to
    tune against, since small jitter does not change the bucket.
    """

    #: Log-spaced bucket index of time since the actor's previous transition.
    since_actor_bucket: int = 0
    #: Same, since the previous transition anywhere on the host.
    since_host_bucket: int = 0

    @staticmethod
    def bucket(delta_ns: int) -> int:
        """Map a nanosecond gap to a bucket in [0, 15]."""
        if delta_ns <= 0:
            return 0
        bucket = 0
        threshold = 1_000_000  # 1 ms
        while bucket < 15 and delta_ns >= threshold:
            bucket += 1
            threshold *= 4
        return bucket

    def to_dict(self) -> dict[str, Any]:
        return {
            "since_actor_bucket": self.since_actor_bucket,
            "since_host_bucket": self.since_host_bucket,
        }


@dataclass(frozen=True, slots=True)
class SSIRTransitionV1:
    """One security state transition, source-independent."""

    # A, R, O
    actor: Entity
    relation: Relation
    object: Entity
    # ΔS
    state_delta: StateDelta
    # U — combined semantic and observational uncertainty
    uncertainty: float
    # N
    novelty: NoveltyTensor
    # P — causal signature and responsibility
    causal_signature: str
    parent_signature: str
    responsibility: float
    # T
    temporal: TemporalContext
    # E — evidence references, never inlined content
    evidence: tuple[EvidenceRef, ...]
    # Context
    epoch_id: int
    sequence: int
    level: RepresentationLevel = RepresentationLevel.L1
    #: ΔΦ for this transition. Kept beside the delta because the delta says
    #: *which* dimensions moved and this says how much that mattered.
    delta_phi: float = 0.0
    #: True when fusion was incomplete or sensors disagreed.
    observation_incomplete: bool = False
    schema_version: str = SSIR_TRANSITION_V1_VERSION

    def __post_init__(self) -> None:
        if not 0.0 <= self.uncertainty <= 1.0:
            raise ContractError(f"uncertainty must be in [0, 1], got {self.uncertainty!r}")
        if not isinstance(self.novelty, NoveltyTensor):
            raise ContractError("novelty must be a NoveltyTensor")
        if not isinstance(self.state_delta, StateDelta):
            raise ContractError("state_delta must be a StateDelta")
        object.__setattr__(self, "relation", Relation(self.relation))
        object.__setattr__(self, "level", RepresentationLevel(self.level))
        object.__setattr__(self, "evidence", tuple(self.evidence))

    @property
    def is_high_consequence(self) -> bool:
        """True when this transition raised any security capability.

        The aggregation policy keys off this: a high-consequence transition is
        never hidden merely because it repeats.
        """
        return bool(self.state_delta)

    def at_level(self, level: RepresentationLevel) -> SSIRTransitionV1:
        """Project to a representation level.

        Projection drops fields the level does not carry, so byte-cost
        measurements at L0 reflect an actual L0 record rather than a full record
        that was merely labelled cheap.
        """
        level = RepresentationLevel(level)
        if level >= self.level:
            return replace(self, level=level)

        projected = replace(self, level=level)
        if level < RepresentationLevel.L3:
            projected = replace(projected, evidence=())
        if level < RepresentationLevel.L2:
            projected = replace(projected, uncertainty=0.0, parent_signature="")
        if level < RepresentationLevel.L1:
            projected = replace(
                projected,
                state_delta=StateDelta.empty(),
                temporal=TemporalContext(),
                delta_phi=0.0,
            )
        return projected

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SSIR_TRANSITION_V1_ID,
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "epoch_id": self.epoch_id,
            "level": int(self.level),
            "actor": self.actor.to_dict(),
            "relation": self.relation.name,
            "object": self.object.to_dict(),
            "state_delta": self.state_delta.to_dict(),
            "delta_phi": round(self.delta_phi, 4),
            "uncertainty": round(self.uncertainty, 4),
            "novelty": self.novelty.to_dict(),
            "causal_signature": self.causal_signature,
            "parent_signature": self.parent_signature,
            "responsibility": round(self.responsibility, 4),
            "temporal": self.temporal.to_dict(),
            "evidence": [ref.to_dict() for ref in self.evidence],
            "observation_incomplete": self.observation_incomplete,
            "is_high_consequence": self.is_high_consequence,
        }

    def semantic_key(self) -> tuple[Any, ...]:
        """Identity for cross-sensor equivalence comparison.

        Deliberately excludes evidence, timing, pids and display names — two
        sensors observing the same action must agree on *this* even though their
        raw records look nothing alike.
        """
        return (
            self.actor.kind,
            frozenset(self.actor.semantics.asserted),
            self.relation,
            self.object.kind,
            frozenset(self.object.semantics.asserted),
            self.state_delta.bitmask(),
        )
