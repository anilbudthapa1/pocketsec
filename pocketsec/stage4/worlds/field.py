"""D4.1 (continued) — ``CausalBeliefField``: the bounded set of competing worlds.

``CBF_t = {(W_i, support_i)} for i = 1..K``, with K hard-bounded (architecture §3).
This is the object the whole stage is named after, and it is **immutable**: every
lifecycle function returns a new field. That is not a style preference. Two
mechanisms depend on it directly:

* :meth:`CausalBeliefField.support_distance` is the primitive under both
  Responsibility Flux (§10) and sensor planning (§16), and both need the
  *predecessor* field to compare against. A mutated field has no predecessor.
* The oscillation guard (§13) needs two comparable snapshots to notice a
  spawn → kill → spawn cycle.

What this module refuses to do:

* **It refuses duplicate mechanisms.** Two worlds with the same ``mechanism_id``
  are a fusion that did not happen, and they double-count the same explanation's
  support in every downstream comparison.
* **It refuses to exceed K.** ``len(worlds) <= max_worlds <= MAX_WORLDS_CEILING``
  is checked at construction, so an attacker who can make the system branch
  cannot make it branch without limit. Exceeding a bound raises here; the
  *recorded* degradation path (a ``Truncation`` naming what was lost) belongs to
  the lifecycle package, which must produce one rather than let this refusal
  escape.
* **It refuses to compare incomparable support.** ``support_vector()`` raises when
  the field mixes belief geometries, because normalising a log-odds against an
  e-value produces a number that means nothing (§11).

**Forward dependencies are structural types, not imports.** ``sensor_shadow``,
``horizon``, ``budget``, ``graph``, ``claim_graph`` and ``truncations`` are owned
by work packages that depend on *this* one. A runtime import from foundation up
into a consumer would be a cycle, so each is declared as a narrow
:class:`typing.Protocol` defined here and satisfied structurally. The decision is
made once, in this docstring: **foundation defines the Protocol, the consumer
satisfies it, and neither imports the other.**
"""

from __future__ import annotations

import math
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Protocol

from pocketsec.stage0.contracts.common import (
    ContractError,
    EvidenceRef,
    register_schema,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage1.state.security_state import SecurityStateV1
from pocketsec.stage4.worlds.world import (
    BeliefGeometry,
    LatentSecurityState,
    SecurityWorldV1,
    WorldSupport,
    WorldSupportState,
    canonical_bytes,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Mapping, Sequence

__all__ = [
    "CAUSAL_BELIEF_FIELD_V1_ID",
    "CAUSAL_BELIEF_FIELD_V1_VERSION",
    "CausalBeliefField",
    "ClaimGraphLike",
    "EntropyBudgetLike",
    "MAX_WORLDS",
    "MAX_WORLDS_CEILING",
    "ResolutionHorizonLike",
    "SensorShadowLike",
    "TruncationLike",
    "UNKNOWN_MECHANISM_ID",
    "WorldGraphLike",
    "unknown_world",
]

CAUSAL_BELIEF_FIELD_V1_ID = "pocketsec.causal_belief_field.v1"
CAUSAL_BELIEF_FIELD_V1_VERSION = register_schema(CAUSAL_BELIEF_FIELD_V1_ID, "1.0.0")

#: §44: "K capped 4-16 normally". The default is the low end, deliberately: a
#: bound you have to raise on purpose is a bound; a bound set at the ceiling is
#: decoration.
MAX_WORLDS: int = 8

#: §44: "exceptional cap explicit". No field may declare a larger K.
MAX_WORLDS_CEILING: int = 16

#: The §12 UNKNOWN world's mechanism. Novelty is not maliciousness, so this world
#: asserts no dimension and claims no consequence — it records only that
#: something happened that no surviving world explains.
UNKNOWN_MECHANISM_ID = "unresolved_novel_mechanism"


class SensorShadowLike(Protocol):
    """``visibility.sensor_shadow.SensorShadow``, structurally."""

    def confidence_penalty(self) -> float: ...

    def covers(self, signal: str) -> bool: ...

    def to_dict(self) -> dict[str, Any]: ...


class ResolutionHorizonLike(Protocol):
    """``identifiability.horizon.ResolutionHorizon``, structurally."""

    def exhausted(self) -> bool: ...


class EntropyBudgetLike(Protocol):
    """``graph.entropy_budget.EntropyBudget``, structurally."""

    @property
    def max_worlds(self) -> int: ...

    @property
    def max_reasoning_units(self) -> int: ...


class WorldGraphLike(Protocol):
    """``graph.sparse_world_graph.SparseWorldGraph``, structurally."""

    def memory_bytes(self) -> int: ...


class ClaimGraphLike(Protocol):
    """``claims.graph.ClaimGraph``, structurally."""

    def to_dict(self) -> dict[str, Any]: ...


class TruncationLike(Protocol):
    """``graph.sparse_world_graph.Truncation``, structurally.

    A truncation is the explicit record of a loss. The field carries them so that
    a bound being hit is visible in the serialised incident rather than inferable
    from a missing world.
    """

    @property
    def what(self) -> str: ...

    @property
    def identifier(self) -> str: ...

    @property
    def reason(self) -> str: ...

    @property
    def consequence_lost(self) -> float: ...


@dataclass(frozen=True, slots=True)
class CausalBeliefField:
    """CBF_t = {(W_i, support_i)} for i = 1..K, K hard-bounded (§3)."""

    incident_id: str
    epoch_id: int
    worlds: tuple[SecurityWorldV1, ...]
    max_worlds: int = MAX_WORLDS
    #: Optional because a field exists before its shadow, horizon, budget, graph
    #: and claim graph are computed. ``None`` means *not yet computed*, never
    #: "zero": ADR-0004's lesson, and the reason nothing here defaults to a
    #: fabricated instance.
    sensor_shadow: SensorShadowLike | None = None
    horizon: ResolutionHorizonLike | None = None
    budget: EntropyBudgetLike | None = None
    graph: WorldGraphLike | None = None
    claim_graph: ClaimGraphLike | None = None
    evidence_refs: tuple[EvidenceRef, ...] = ()
    truncations: tuple[TruncationLike, ...] = ()
    at_sequence: int = 0
    schema_version: str = CAUSAL_BELIEF_FIELD_V1_VERSION

    def __post_init__(self) -> None:
        require_identifier(self.incident_id, "CausalBeliefField.incident_id")
        require_non_negative_int(self.epoch_id, "CausalBeliefField.epoch_id")
        require_non_negative_int(self.at_sequence, "CausalBeliefField.at_sequence")
        self._refuse_bad_capacity()
        self._refuse_duplicates()

    def _refuse_bad_capacity(self) -> None:
        if not isinstance(self.max_worlds, int) or isinstance(self.max_worlds, bool):
            raise ContractError(f"max_worlds must be an int, got {self.max_worlds!r}")
        if self.max_worlds < 1:
            raise ContractError("max_worlds must be at least 1; an empty cap holds no hypothesis")
        if self.max_worlds > MAX_WORLDS_CEILING:
            raise ContractError(
                f"max_worlds {self.max_worlds} exceeds the explicit ceiling "
                f"{MAX_WORLDS_CEILING} (§44)"
            )
        if len(self.worlds) > self.max_worlds:
            raise ContractError(
                f"field {self.incident_id} holds {len(self.worlds)} worlds against a cap of "
                f"{self.max_worlds}; the caller must prune and record a Truncation, not grow"
            )

    def _refuse_duplicates(self) -> None:
        ids = [world.world_id for world in self.worlds]
        if len(set(ids)) != len(ids):
            raise ContractError(f"duplicate world_ids in {self.incident_id}: {sorted(ids)}")
        mechanisms = [world.mechanism_id for world in self.worlds]
        if len(set(mechanisms)) != len(mechanisms):
            raise ContractError(
                f"duplicate mechanism_ids in {self.incident_id}: {sorted(mechanisms)}; "
                "a duplicate mechanism is a fusion that did not happen"
            )

    # --- lookup ---------------------------------------------------------

    def world(self, world_id: str) -> SecurityWorldV1 | None:
        for candidate in self.worlds:
            if candidate.world_id == world_id:
                return candidate
        return None

    def unknown_world(self) -> SecurityWorldV1 | None:
        """The §12 UNKNOWN world, if this field holds one."""
        for candidate in self.worlds:
            if candidate.mechanism_id == UNKNOWN_MECHANISM_ID:
                return candidate
        return None

    def leaders(self, *, n: int = 2) -> tuple[SecurityWorldV1, ...]:
        """The ``n`` best-supported worlds, ties broken by ``world_id``.

        Deterministic ordering matters: the identifiability margin is the gap
        between the first two, so a hash-ordered tie would make the verdict
        depend on the interpreter's salt.
        """
        if n < 0:
            raise ContractError(f"n must be non-negative, got {n!r}")
        shares = self.support_vector()
        ranked = sorted(self.worlds, key=lambda w: (-shares[w.world_id], w.world_id))
        return tuple(ranked[:n])

    # --- support geometry ----------------------------------------------

    def support_vector(self) -> Mapping[str, float]:
        """Relative support share per world id, summing to 1 over a non-empty field.

        **This is a comparison measure, not a probability.** It exists so two
        fields can be compared with a divergence, and so the identifiability
        margin has a scale. ``WorldSupport.as_probability()`` remains the only
        route to a probability claim, and it returns ``None`` for three of the
        four geometries.

        Mixing geometries is refused rather than normalised: an e-value of 3.0
        and a log-odds of 3.0 are not comparable magnitudes, and silently
        treating them as one would make every downstream distance meaningless.
        """
        if not self.worlds:
            return {}
        geometries = {world.support.geometry for world in self.worlds}
        if len(geometries) > 1:
            raise ContractError(
                f"field {self.incident_id} mixes belief geometries "
                f"{sorted(g.value for g in geometries)}; support is not comparable across them"
            )
        weights = {world.world_id: _support_weight(world.support) for world in self.worlds}
        total = math.fsum(weights.values())
        if total <= 0.0:
            uniform = 1.0 / len(weights)
            return {key: uniform for key in weights}
        return {key: value / total for key, value in weights.items()}

    def support_distance(self, other: CausalBeliefField) -> float:
        """Categorical Jensen-Shannon divergence between two support vectors.

        Base-2, so the result lies in ``[0, 1]``: 0 means the evidence moved
        nothing, 1 means the two fields put their mass on disjoint worlds. Pure
        stdlib arithmetic — ADR-0030 leaves Stage 4 no numpy, and a categorical
        JS over at most 16 worlds needs none.

        Comparing a populated field against an empty one returns 1.0: going from
        "no hypothesis" to "a hypothesis" is the largest move there is, and
        returning 0.0 there would tell the sensor planner that spawning the first
        world was worthless.
        """
        left = self.support_vector()
        right = other.support_vector()
        if not left and not right:
            return 0.0
        if not left or not right:
            return 1.0
        return _jensen_shannon(left, right)

    # --- transformation -------------------------------------------------

    def with_worlds(self, worlds: Sequence[SecurityWorldV1]) -> CausalBeliefField:
        """A new field with a new world set. The field itself never mutates."""
        return replace(self, worlds=tuple(worlds))

    # --- accounting -----------------------------------------------------

    def state_bytes(self) -> int:
        """Canonical serialised size of the whole incident state.

        Every optional member contributes through its own ``to_dict`` when it has
        one, so the number is the size of what would actually be persisted rather
        than a sum of guesses. A member with no ``to_dict`` contributes a presence
        marker, which is visible in the output rather than silently omitted.
        """
        return len(canonical_bytes(self.to_dict()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "epoch_id": self.epoch_id,
            "worlds": [world.to_dict() for world in self.worlds],
            "max_worlds": self.max_worlds,
            "sensor_shadow": _member_dict(self.sensor_shadow),
            "horizon": _member_dict(self.horizon),
            "budget": _member_dict(self.budget),
            "graph": _member_dict(self.graph),
            "claim_graph": _member_dict(self.claim_graph),
            "evidence_refs": [ref.to_dict() for ref in self.evidence_refs],
            "truncations": [_truncation_dict(item) for item in self.truncations],
            "at_sequence": self.at_sequence,
            "schema_version": self.schema_version,
        }


def _member_dict(member: object | None) -> dict[str, Any] | None:
    if member is None:
        return None
    to_dict = getattr(member, "to_dict", None)
    if callable(to_dict):
        result = to_dict()
        if isinstance(result, dict):
            return result
    memory_bytes = getattr(member, "memory_bytes", None)
    if callable(memory_bytes):
        return {"present": True, "memory_bytes": int(memory_bytes())}
    return {"present": True}


def _truncation_dict(item: TruncationLike) -> dict[str, Any]:
    """A truncation serialised by its four contract members.

    Read through ``getattr`` because the concrete class lives in a package that
    depends on this one; a missing member is a contract violation and says so.
    """
    try:
        return {
            "what": str(item.what),
            "identifier": str(item.identifier),
            "reason": str(item.reason),
            "consequence_lost": round(float(item.consequence_lost), 6),
        }
    except AttributeError as exc:
        raise ContractError(
            f"truncation record {item!r} does not satisfy TruncationLike: {exc}"
        ) from exc


def _support_weight(support: WorldSupport) -> float:
    """A positive, monotone weight for one support value within its geometry."""
    probability = support.as_probability()
    if probability is not None:
        return probability
    if support.geometry is BeliefGeometry.E_VALUE:
        return float(support.value)
    # LOG_ODDS and EVIDENCE_INTERVAL are additive scales; exponentiating gives
    # the odds, which is the multiplicative quantity a share is taken over.
    return math.exp(float(support.value))


def _jensen_shannon(left: Mapping[str, float], right: Mapping[str, float]) -> float:
    keys = set(left) | set(right)
    divergence = 0.0
    for key in keys:
        p = left.get(key, 0.0)
        q = right.get(key, 0.0)
        mixture = 0.5 * (p + q)
        if mixture <= 0.0:
            continue
        if p > 0.0:
            divergence += 0.5 * p * math.log2(p / mixture)
        if q > 0.0:
            divergence += 0.5 * q * math.log2(q / mixture)
    # Floating-point accumulation can land a hair outside [0, 1]; clamping keeps
    # callers that treat this as a fraction honest without hiding a real excess,
    # which would be orders of magnitude larger than 1e-12.
    if divergence < -1e-9 or divergence > 1.0 + 1e-9:  # pragma: no cover - arithmetic guard
        raise ContractError(f"Jensen-Shannon divergence out of range: {divergence!r}")
    return min(1.0, max(0.0, divergence))


def unknown_world(incident_id: str, *, at_sequence: int) -> SecurityWorldV1:
    """The bounded UNKNOWN world of §12.

    Spawned when a security-relevant residual persists that no existing world
    explains and no visibility artefact accounts for. It is deliberately the
    weakest possible claim:

    * it asserts **no** dimension, because novelty is not maliciousness;
    * it predicts nothing and forbids nothing, so it cannot be falsified by an
      observation and cannot be used to justify one either;
    * its support state is ``UNRESOLVED``, which is a valid Stage 4 answer and
      maps onto ``Verdict.UNKNOWN`` — not onto ``SUSPICIOUS``.

    A system whose response to "I do not recognise this" is to invent a mechanism
    is the confident single-world storyteller Stage 4 exists to prevent.
    """
    require_identifier(incident_id, "unknown_world.incident_id")
    require_non_negative_int(at_sequence, "unknown_world.at_sequence")
    baseline = SecurityStateV1()
    return SecurityWorldV1(
        world_id=f"{incident_id}-unknown",
        mechanism_id=UNKNOWN_MECHANISM_ID,
        latent_state=LatentSecurityState.from_state(baseline, frozenset()),
        # A log-odds of 0.0 is even odds: the UNKNOWN world starts with no
        # evidence for or against it, which a probability of 0.0 would misstate
        # as refuted.
        support=WorldSupport(BeliefGeometry.LOG_ODDS, 0.0),
        support_state=WorldSupportState.UNRESOLVED,
        expected_evidence=frozenset(),
        forbidden_evidence=frozenset(),
        contradictions=(),
        tension=None,
        uncertainty=1.0,
        visibility_requirements=frozenset(),
        spine_signatures=(),
        evidence_refs=(),
        born_at_sequence=at_sequence,
    )
