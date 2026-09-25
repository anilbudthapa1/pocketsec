"""D4.5a — world birth, death, fission, fusion and dominance pruning.

This module gatekeeps the Causal Belief Field's population, and almost all of its
value is in what it **refuses**.

*   **Novelty alone never spawns a world.** §12's residual gate is five
    conjunctions — security-relevant AND large enough AND persistent AND not a
    visibility artifact AND not already explained — and only then, if the field
    has capacity. F3 is the falsifier: a benign corpus spawning more than one
    world per hundred transitions, or ``NOT_SECURITY_RELEVANT`` never firing.
    Novelty is not maliciousness; a spawn per anomaly is the failure mode.
*   **Dominance pruning has a hard veto.** §30's fifth clause — no
    security-critical future unique to the loser is lost — overrides the other
    four, and all five are reported separately so a pruning can be audited. A
    pruning that removes the only world predicting exfiltration has not reduced
    complexity; it has lost the answer.
*   **Every removal that loses something records a ``Truncation``.** The one
    exception is fusion, licensed by ``observationally_equivalent`` at
    ``FUSION_EQUIVALENCE_EPSILON``: the survivor explains everything the absorbed
    world did.

Every function here returns a **new** field: ``CausalBeliefField`` is immutable,
and both the oscillation guard and ``support_distance`` need the predecessor.

Types from ``worlds/world.py``, ``worlds/field.py`` and ``visibility/`` are
consumed **structurally** (the Protocols below), because ``field.py`` holds an
``EntropyBudget`` and importing it here would close a cycle through ``graph/``.
"""

from __future__ import annotations

import dataclasses
import hashlib
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_finite_unit_interval,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage1.observation.policy import MANDATORY_SIGNALS
from pocketsec.stage4.graph.sparse_world_graph import Truncation, append_truncations
from pocketsec.stage4.worlds.tombstone import TombstoneLedger, WorldTombstone, reopenable_for

__all__ = [
    "DIMENSION_SIGNALS",
    "FUSION_EQUIVALENCE_EPSILON",
    "MAX_FISSION_DEPTH",
    "MAX_RESIDUAL_SIGNALS",
    "MIN_RESIDUAL_FOR_BIRTH",
    "RESIDUAL_PERSISTENCE_STEPS",
    "SECURITY_RELEVANCE_MIN_CONSEQUENCE",
    "BirthRefusal",
    "DeathCause",
    "DominanceTest",
    "EvidenceRegime",
    "FieldLike",
    "Residual",
    "ShadowLike",
    "WorldLike",
    "dominance_report",
    "dominance_test",
    "fission_world",
    "fuse_worlds",
    "kill_world",
    "prune_dominated_worlds",
    "residual_from_transition",
    "spawn_refusal",
    "spawn_world",
    "unexplained_signals",
]

#: §12 / the Stage 4 constant table.
MIN_RESIDUAL_FOR_BIRTH: float = 0.25
RESIDUAL_PERSISTENCE_STEPS: int = 2
MAX_FISSION_DEPTH: int = 2
FUSION_EQUIVALENCE_EPSILON: float = 0.05

#: A residual describing more signals than a world may expect is not a residual,
#: it is a firehose. Matches ``MAX_EXPECTED_SIGNALS`` in ``worlds/world.py``.
MAX_RESIDUAL_SIGNALS: int = 32

#: A residual must have moved the security potential at all before it can be
#: security-relevant. Deliberately a *consequence* floor and not a novelty
#: threshold: a never-before-seen benign command is maximally novel and has zero
#: consequence, and spawning a world for it is exactly the F3 failure. The value
#: is 0.0 rather than a tuned number because any positive threshold picked here
#: would be fitted to whatever corpus happened to be at hand.
SECURITY_RELEVANCE_MIN_CONSEQUENCE: float = 0.0

#: Stage 1 dimension -> the signal whose observation would reveal that dimension
#: moving. The six values are exactly ``MANDATORY_SIGNALS``; the three dimensions
#: with no mandatory signal (reachability, modification, discovery) name
#: themselves. Asserted in ``tests/test_stage4_lifecycle.py`` rather than trusted:
#: if Stage 1 ever adds a mandatory signal, this map must be updated with it.
DIMENSION_SIGNALS: Mapping[str, str] = {
    "privilege": "privilege_change",
    "credential": "credential_access",
    "persistence": "persistence_write",
    "isolation": "boundary_crossing",
    "execution": "module_load",
    "trust": "authentication",
    "reachability": "reachability",
    "modification": "modification",
    "discovery": "discovery",
}


class BirthRefusal(StrEnum):
    """Why §12's gate declined to create a world. Every member is reachable and
    ``tests/test_stage4_lifecycle.py`` fires all six."""

    RESIDUAL_TOO_SMALL = "RESIDUAL_TOO_SMALL"
    NOT_PERSISTENT = "NOT_PERSISTENT"
    VISIBILITY_ARTIFACT = "VISIBILITY_ARTIFACT"
    EXPLAINED_BY_EXISTING = "EXPLAINED_BY_EXISTING"
    FIELD_AT_CAPACITY = "FIELD_AT_CAPACITY"
    NOT_SECURITY_RELEVANT = "NOT_SECURITY_RELEVANT"


class DeathCause(StrEnum):
    """§13's five causes plus the budget truncation §29 forces on us."""

    HARD_CONTRADICTION = "HARD_CONTRADICTION"
    SUSTAINED_TENSION = "SUSTAINED_TENSION"
    DOMINATED = "DOMINATED"
    EPOCH_INVALIDATION = "EPOCH_INVALIDATION"
    ASSURANCE_BELOW_THRESHOLD = "ASSURANCE_BELOW_THRESHOLD"
    BUDGET_TRUNCATION = "BUDGET_TRUNCATION"


# --- the structural contracts this module consumes ---------------------------


class ShadowLike(Protocol):
    """``visibility/sensor_shadow.SensorShadow`` — only the member used here."""

    def covers(self, signal: str) -> bool: ...


class SupportLike(Protocol):
    """``worlds/world.WorldSupport`` — only the member used here."""

    value: float


class LatentStateLike(Protocol):
    """``worlds/world.LatentSecurityState`` — only the members used here."""

    asserted_dimensions: frozenset[str]
    consequence: float


class WorldLike(Protocol):
    """``worlds/world.SecurityWorldV1``, structurally."""

    world_id: str
    mechanism_id: str
    latent_state: LatentStateLike
    support: SupportLike
    expected_evidence: frozenset[str]
    forbidden_evidence: frozenset[str]
    contradictions: tuple[str, ...]
    uncertainty: float
    visibility_requirements: frozenset[str]
    spine_signatures: tuple[str, ...]
    evidence_refs: tuple[Any, ...]
    born_at_sequence: int
    fission_depth: int

    def predicts(self, signal: str) -> bool: ...

    def forbids(self, signal: str) -> bool: ...

    def observationally_equivalent(self, other: Any, *, epsilon: float) -> bool: ...

    def state_bytes(self) -> int: ...


class FieldLike(Protocol):
    """``worlds/field.CausalBeliefField``, structurally."""

    incident_id: str
    epoch_id: int
    worlds: tuple[Any, ...]
    max_worlds: int
    truncations: tuple[Truncation, ...]
    at_sequence: int

    def world(self, world_id: str) -> Any | None: ...

    def with_worlds(self, worlds: Sequence[Any]) -> Any: ...

    def state_bytes(self) -> int: ...


# --- residuals ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Residual:
    """``Residual = ObservedEvidence - BestExplainedEvidence`` (§12).

    ``visibility_explained`` is the field that matters most: a residual the sensor
    shadow already accounts for is an artifact of not looking, and spawning on it
    manufactures hypotheses out of blindness.
    """

    signals: frozenset[str]
    magnitude: float
    persistent_steps: int
    visibility_explained: bool
    consequence: float

    def __post_init__(self) -> None:
        if not isinstance(self.signals, frozenset):
            object.__setattr__(self, "signals", frozenset(self.signals))
        if len(self.signals) > MAX_RESIDUAL_SIGNALS:
            raise ContractError(
                f"Residual.signals exceeds MAX_RESIDUAL_SIGNALS={MAX_RESIDUAL_SIGNALS}"
            )
        for signal in self.signals:
            if not isinstance(signal, str) or not signal:
                raise ContractError(f"Residual.signals members must be non-empty, got {signal!r}")
        require_finite_unit_interval(self.magnitude, "Residual.magnitude")
        require_non_negative_int(self.persistent_steps, "Residual.persistent_steps")
        if not isinstance(self.visibility_explained, bool):
            raise ContractError("Residual.visibility_explained must be a bool")
        value = self.consequence
        ok = not isinstance(value, bool) and isinstance(value, (int, float))
        if not ok or not math.isfinite(float(value)) or float(value) < 0.0:
            raise ContractError(f"Residual.consequence must be finite and >= 0, got {value!r}")
        object.__setattr__(self, "consequence", float(value))

    def is_security_relevant(self) -> bool:
        """A residual is security-relevant when it moved the security potential
        AND names a signal Stage 1 itself declares security-critical.

        Grounded rather than invented: Stage 1 marks six signals
        ``MANDATORY_SIGNALS``, which AOP may never stop collecting
        (``observation/policy.py:47``), and those six are exactly privilege,
        credential, persistence, isolation, execution and trust. The three
        dimensions with no mandatory signal — reachability, modification,
        discovery — are the ones ordinary work moves all day.

        **The limitation, plainly:** a residual confined to those three can never
        spawn a world, however large or persistent. A deliberate conservative
        trade against F3, and a measurable weakness recorded as one.
        """
        if not self.signals or self.consequence <= SECURITY_RELEVANCE_MIN_CONSEQUENCE:
            return False
        return bool(self.signals & MANDATORY_SIGNALS)

    def is_persistent(self) -> bool:
        return self.persistent_steps >= RESIDUAL_PERSISTENCE_STEPS

    def to_dict(self) -> dict[str, Any]:
        return {
            "signals": sorted(self.signals),
            "magnitude": round(self.magnitude, 6),
            "persistent_steps": self.persistent_steps,
            "visibility_explained": self.visibility_explained,
            "consequence": round(self.consequence, 6),
        }


@dataclass(frozen=True, slots=True)
class EvidenceRegime:
    """One internally consistent evidence regime a world predicts (§14).

    ``incompatible_with`` is deliberately narrow: only an expected/forbidden clash
    counts. Two regimes that merely differ are one world with a wide prediction.
    """

    label: str
    expected: frozenset[str]
    forbidden: frozenset[str]
    consequence: float = 0.0

    def __post_init__(self) -> None:
        require_identifier(self.label, "EvidenceRegime.label")
        object.__setattr__(self, "expected", frozenset(self.expected))
        object.__setattr__(self, "forbidden", frozenset(self.forbidden))
        if self.expected & self.forbidden:
            raise ContractError(
                f"EvidenceRegime {self.label!r} expects and forbids "
                f"{sorted(self.expected & self.forbidden)}"
            )
        if isinstance(self.consequence, bool) or not isinstance(self.consequence, (int, float)):
            raise ContractError("EvidenceRegime.consequence must be a number")
        object.__setattr__(self, "consequence", float(self.consequence))

    def incompatible_with(self, other: EvidenceRegime) -> bool:
        return bool(self.expected & other.forbidden) or bool(other.expected & self.forbidden)


def unexplained_signals(observed: frozenset[str], worlds: Sequence[Any]) -> frozenset[str]:
    """The signals the single best-explaining world still does not account for.

    "Best" means explaining the most of what was observed, not having the highest
    support: support would let a confident world suppress a residual it does not
    explain, which is the single-world storytelling Stage 4 exists to prevent.
    """
    if not observed:
        return frozenset()
    best = observed
    for world in worlds:
        remainder = frozenset(s for s in observed if not world.predicts(s))
        if len(remainder) < len(best):
            best = remainder
    return best


def residual_from_transition(
    transition: Any,
    worlds: Sequence[Any],
    *,
    shadow: ShadowLike | None = None,
    previous: Residual | None = None,
) -> Residual:
    """Build §12's residual from one Stage 1 transition.

    Added beyond the spec's D4.5 list deliberately: ``Residual`` feeds the only
    birth gate in the system, and a type nobody can build from real telemetry
    cannot be falsified by F3. The vocabulary is ``DIMENSION_SIGNALS`` over ΔS,
    the only part of the record that says what security truth changed.
    """
    raised = frozenset(transition.state_delta.dimensions)
    observed = frozenset(DIMENSION_SIGNALS[d] for d in raised if d in DIMENSION_SIGNALS)
    remainder = unexplained_signals(observed, worlds)
    # Persistence accumulates: a signal no world explains stays in the residual
    # until one does. Resetting the count whenever the newest transition happens
    # to raise a *different* dimension would make persistence unreachable on any
    # real attack chain, which climbs one dimension at a time.
    carried = (
        frozenset(s for s in previous.signals if not any(w.predicts(s) for w in worlds))
        if previous is not None
        else frozenset()
    )
    signals = remainder | carried
    magnitude = (len(remainder) / len(observed)) if observed else _carried_magnitude(previous)
    blind = shadow is not None and bool(signals) and all(shadow.covers(s) for s in signals)
    steps = (previous.persistent_steps + 1) if carried else 1
    consequence = max(0.0, float(getattr(transition, "delta_phi", 0.0)))
    if previous is not None and carried:
        consequence = max(consequence, previous.consequence)
    return Residual(
        signals=signals,
        magnitude=magnitude,
        persistent_steps=steps,
        visibility_explained=bool(getattr(transition, "observation_incomplete", False)) or blind,
        consequence=consequence,
    )


def _carried_magnitude(previous: Residual | None) -> float:
    """With no new observation, the previous unexplained fraction stands: zeroing
    it would let a quiet interval erase an unexplained residual (low-and-slow)."""
    return previous.magnitude if previous is not None else 0.0


# --- birth -------------------------------------------------------------------


def _mechanism_id_for(field: Any, residual: Residual) -> str:
    """``unresolved_novel_mechanism`` for the first unknown world, then a
    signal-derived suffix — a field refuses duplicate mechanism_ids, and a
    duplicate mechanism is a fusion that did not happen."""
    base = "unresolved_novel_mechanism"
    taken = {w.mechanism_id for w in field.worlds}
    if base not in taken:
        return base
    material = "|".join(sorted(residual.signals))
    return f"{base}.{hashlib.sha256(material.encode('utf-8')).hexdigest()[:12]}"


def _world_id_for(field: Any, residual: Residual, mechanism_id: str) -> str:
    material = f"{field.incident_id}|{field.at_sequence}|{mechanism_id}|" + ",".join(
        sorted(residual.signals)
    )
    return f"w-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def spawn_refusal(
    field: Any,
    residual: Residual,
    *,
    shadow: ShadowLike | None = None,
    tombstones: TombstoneLedger | None = None,
    mechanism_id: str | None = None,
) -> BirthRefusal | None:
    """§12's gate, as a pure predicate, so a caller can see *why* without spawning.

    Order is part of the contract: relevance before size, because a large
    residual with no consequence is exactly the benign-novelty case F3 watches
    for, and calling it RESIDUAL_TOO_SMALL would hide the refusal that proves the
    gate works.
    """
    if not residual.is_security_relevant():
        return BirthRefusal.NOT_SECURITY_RELEVANT
    if residual.magnitude < MIN_RESIDUAL_FOR_BIRTH:
        return BirthRefusal.RESIDUAL_TOO_SMALL
    if not residual.is_persistent():
        return BirthRefusal.NOT_PERSISTENT
    if residual.visibility_explained or _shadowed(residual, shadow):
        return BirthRefusal.VISIBILITY_ARTIFACT
    if _explained_by_existing(field, residual):
        return BirthRefusal.EXPLAINED_BY_EXISTING
    candidate = mechanism_id or _mechanism_id_for(field, residual)
    if tombstones is not None and tombstones.oscillating(candidate):
        # §13 gives the tombstone the job of preventing oscillation: the tombstone
        # IS the existing account of this mechanism. `reopen()` is the deliberate
        # path back, and it costs the caller an explicit decision.
        return BirthRefusal.EXPLAINED_BY_EXISTING
    if len(field.worlds) >= field.max_worlds:
        return BirthRefusal.FIELD_AT_CAPACITY
    return None


def _shadowed(residual: Residual, shadow: ShadowLike | None) -> bool:
    if shadow is None or not residual.signals:
        return False
    return all(shadow.covers(signal) for signal in residual.signals)


def _explained_by_existing(field: Any, residual: Residual) -> bool:
    """A world explains the residual when it predicts every unexplained signal and
    forbids none: forbidding one is a contradiction, not an explanation, and that
    world should be dying rather than absorbing the residual."""
    for world in field.worlds:
        if any(world.forbids(signal) for signal in residual.signals):
            continue
        if all(world.predicts(signal) for signal in residual.signals):
            return True
    return False


def spawn_world(
    field: Any,
    residual: Residual,
    *,
    shadow: ShadowLike | None,
    epoch_id: int,
    tombstones: TombstoneLedger | None = None,
    world_factory: Any = None,
) -> tuple[Any, str | None, BirthRefusal | None]:
    """CBF-F02 — create a bounded UNKNOWN world, or refuse and say why.

    ``world_factory`` defaults to ``worlds.field.unknown_world``; it is a
    parameter so the gate can be exercised without that import.
    """
    if epoch_id != field.epoch_id:
        raise ContractError(
            f"spawn_world called with epoch_id={epoch_id} on a field at {field.epoch_id}; "
            "an epoch change invalidates worlds (§13), it does not silently rebase them"
        )
    mechanism_id = _mechanism_id_for(field, residual)
    refusal = spawn_refusal(
        field, residual, shadow=shadow, tombstones=tombstones, mechanism_id=mechanism_id
    )
    if refusal is not None:
        return field, None, refusal
    factory = world_factory if world_factory is not None else _default_world_factory()
    base = factory(field.incident_id, at_sequence=field.at_sequence)
    world = dataclasses.replace(
        base,
        world_id=_world_id_for(field, residual, mechanism_id),
        mechanism_id=mechanism_id,
        expected_evidence=frozenset(residual.signals),
        visibility_requirements=frozenset(residual.signals),
        born_at_sequence=field.at_sequence,
    )
    return field.with_worlds((*field.worlds, world)), world.world_id, None


def _default_world_factory() -> Any:
    """Imported on call, not at module scope: ``worlds/field.py`` holds an
    ``EntropyBudget`` and a ``SparseWorldGraph``, so a module-level import here
    would close a cycle through ``graph/``."""
    from pocketsec.stage4.worlds.field import unknown_world

    return unknown_world


# --- death -------------------------------------------------------------------


def kill_world(
    field: Any, world_id: str, cause: DeathCause, detail: str
) -> tuple[Any, WorldTombstone]:
    """CBF-F03 — remove a world and return the tombstone that remembers it.

    The tombstone is not optional bookkeeping: without it the same residual
    re-spawns the same world and the field oscillates while the budget drains.
    """
    world = field.world(world_id)
    if world is None:
        raise ContractError(f"kill_world: no world {world_id!r} in field {field.incident_id!r}")
    cause = DeathCause(cause)
    stone = WorldTombstone(
        world_id=world.world_id,
        mechanism_id=world.mechanism_id,
        cause=cause,
        detail=detail or str(cause),
        retired_at_sequence=field.at_sequence,
        support_at_death=float(world.support.value),
        reopenable=reopenable_for(cause),
        evidence_digests=tuple(ref.digest for ref in world.evidence_refs),
        consequence=float(world.latent_state.consequence),
    )
    survivors = tuple(w for w in field.worlds if w.world_id != world_id)
    return field.with_worlds(survivors), stone


# --- fission and fusion ------------------------------------------------------


def fission_world(
    field: Any, world_id: str, regimes: Sequence[EvidenceRegime]
) -> tuple[Any, tuple[str, str] | None]:
    """CBF-F04 — split a world that predicts incompatible evidence regimes.

    A refusal is recorded as a ``branch`` truncation: a fission the depth or
    capacity bound declined is a material alternative never considered, and that
    is a loss the incident record must show.
    """
    world = field.world(world_id)
    if world is None:
        raise ContractError(f"fission_world: no world {world_id!r}")
    if len(regimes) != 2:
        raise ContractError(f"fission needs exactly two regimes, got {len(regimes)}")
    left, right = regimes[0], regimes[1]
    if not left.incompatible_with(right):
        return field, None
    reason = _fission_refusal(field, world)
    if reason is not None:
        lost = max(left.consequence, right.consequence, world.latent_state.consequence)
        return _with_truncations(
            field,
            (
                Truncation(
                    what="branch",
                    identifier=f"{world_id}:{left.label}|{right.label}",
                    reason=reason,
                    consequence_lost=lost,
                ),
            ),
        ), None
    children = tuple(_fission_child(field, world, regime) for regime in (left, right))
    survivors = tuple(w for w in field.worlds if w.world_id != world_id)
    new_field = field.with_worlds((*survivors, *children))
    return new_field, (children[0].world_id, children[1].world_id)


def _fission_refusal(field: Any, world: Any) -> str | None:
    if world.fission_depth + 1 > MAX_FISSION_DEPTH:
        return f"fission_depth_exceeds_MAX_FISSION_DEPTH={MAX_FISSION_DEPTH}"
    # The parent is replaced by two children, so fission costs one world slot.
    if len(field.worlds) + 1 > field.max_worlds:
        return f"field_at_capacity_max_worlds={field.max_worlds}"
    return None


def _fission_child(field: Any, world: Any, regime: EvidenceRegime) -> Any:
    """Support is **not** redistributed across children.

    §11 leaves the belief geometry to the runtime package, and halving a value
    that happens to be in log-odds space would be a silent arithmetic error. Both
    children carry the parent's until the next evidence update re-derives it.
    """
    mechanism_id = f"{world.mechanism_id}.{regime.label}"
    material = f"{world.world_id}|{regime.label}|{field.at_sequence}"
    return dataclasses.replace(
        world,
        world_id=f"w-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}",
        mechanism_id=mechanism_id,
        expected_evidence=frozenset(world.expected_evidence | regime.expected),
        forbidden_evidence=frozenset(world.forbidden_evidence | regime.forbidden),
        fission_depth=world.fission_depth + 1,
    )


def fuse_worlds(field: Any, left_id: str, right_id: str) -> tuple[Any, str | None]:
    """CBF-F05 — merge two observationally/security-equivalent worlds.

    The only removal here that records **no** ``Truncation``: the survivor
    predicts and forbids everything the absorbed world did, so nothing was lost.
    ε is a *chosen constant*, not a measured one, and is reported as a parameter.
    """
    left, right = field.world(left_id), field.world(right_id)
    if left is None or right is None or left_id == right_id:
        raise ContractError(f"fuse_worlds: need two distinct live worlds, got {left_id}/{right_id}")
    if not left.observationally_equivalent(right, epsilon=FUSION_EQUIVALENCE_EPSILON):
        return field, None
    survivor, absorbed = (
        (left, right) if left.support.value >= right.support.value else (right, left)
    )
    expected = frozenset(survivor.expected_evidence | absorbed.expected_evidence)
    forbidden = frozenset(survivor.forbidden_evidence | absorbed.forbidden_evidence)
    if expected & forbidden:
        # Equivalent worlds cannot disagree this way; if they do, the equivalence
        # test was wrong and fusing would manufacture a self-contradicting world.
        return field, None
    try:
        fused = dataclasses.replace(
            survivor,
            expected_evidence=expected,
            forbidden_evidence=forbidden,
            contradictions=_dedup(survivor.contradictions + absorbed.contradictions),
            spine_signatures=_dedup(survivor.spine_signatures + absorbed.spine_signatures),
            evidence_refs=_dedup(survivor.evidence_refs + absorbed.evidence_refs),
            uncertainty=max(survivor.uncertainty, absorbed.uncertainty),
            fission_depth=min(survivor.fission_depth, absorbed.fission_depth),
        )
    except ContractError:
        # The fused world breached its own bound (MAX_WORLD_BYTES, signal counts).
        # Refusing the fusion keeps two valid worlds; forcing it would keep none.
        return field, None
    survivors = tuple(w for w in field.worlds if w.world_id not in (left_id, right_id))
    return field.with_worlds((*survivors, fused)), fused.world_id


def _dedup(items: tuple[Any, ...]) -> tuple[Any, ...]:
    seen: list[Any] = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return tuple(seen)


# --- dominance ---------------------------------------------------------------

#: The §30 clause that is a hard veto rather than a cost comparison.
_VETO_CLAUSE = "no_unique_critical_future_lost"


@dataclass(frozen=True, slots=True)
class DominanceTest:
    """§30's five clauses, each reported separately so a pruning can be audited.

    A single boolean would make a pruning unreviewable, and the clause that
    matters most is precisely the one a scalar hides.
    """

    explains_critical_evidence: bool
    no_more_contradictions: bool
    no_more_unsupported_assumptions: bool
    within_representation_budget: bool
    no_unique_critical_future_lost: bool

    def dominates(self) -> bool:
        """All five clauses. ``vetoed()`` exists beside this so an auditor can see
        that a pruning was blocked by the safety clause, not merely by cost."""
        return all(self.to_dict().values())

    def vetoed(self) -> bool:
        """True when the other four passed and only the safety clause refused.
        This is the case that must never be silently overridden."""
        others = {k: v for k, v in self.to_dict().items() if k != _VETO_CLAUSE}
        return not self.no_unique_critical_future_lost and all(others.values())

    def to_dict(self) -> dict[str, bool]:
        return {f.name: getattr(self, f.name) for f in dataclasses.fields(self)}


def _default_futures(world: Any) -> frozenset[str]:
    """Conservative floor for "the critical futures this world predicts".

    Everything the world expects counts. Defaulting to ``MANDATORY_SIGNALS`` would
    be the wrong kind of cheap — exfiltration is not one, so the veto would not
    fire on the case it exists for. The future cone (D4.7) supplies the real map.
    """
    return frozenset(world.expected_evidence)


def dominance_test(
    winner: Any,
    loser: Any,
    *,
    critical_evidence: frozenset[str] | None = None,
    observed: frozenset[str] = frozenset(),
    futures: Mapping[str, frozenset[str]] | None = None,
) -> DominanceTest:
    """§30, clause by clause. ``futures`` maps world_id -> predicted critical
    futures; when omitted, ``_default_futures`` over-protects."""
    critical = (
        critical_evidence
        if critical_evidence is not None
        else (winner.expected_evidence | loser.expected_evidence) & MANDATORY_SIGNALS
    )
    winner_futures = (futures or {}).get(winner.world_id, _default_futures(winner))
    loser_futures = (futures or {}).get(loser.world_id, _default_futures(loser))
    return DominanceTest(
        explains_critical_evidence=critical <= winner.expected_evidence,
        no_more_contradictions=len(winner.contradictions) <= len(loser.contradictions),
        no_more_unsupported_assumptions=(
            len(winner.expected_evidence - observed) <= len(loser.expected_evidence - observed)
        ),
        within_representation_budget=winner.state_bytes() <= loser.state_bytes(),
        no_unique_critical_future_lost=not (loser_futures - winner_futures),
    )


def dominance_report(
    field: Any,
    *,
    observed: frozenset[str] = frozenset(),
    futures: Mapping[str, frozenset[str]] | None = None,
) -> tuple[tuple[str, str, DominanceTest], ...]:
    """Every ordered pair and its five clauses, for the audit trail."""
    return tuple(
        (w.world_id, other.world_id, dominance_test(w, other, observed=observed, futures=futures))
        for w in field.worlds
        for other in field.worlds
        if w.world_id != other.world_id
    )


def prune_dominated_worlds(
    field: Any,
    *,
    observed: frozenset[str] = frozenset(),
    futures: Mapping[str, frozenset[str]] | None = None,
) -> tuple[Any, tuple[str, ...]]:
    """CBF-F17 — remove dominated worlds, with §30's fifth clause as a hard veto.

    The veto is evaluated against the worlds that would actually **survive**, not
    the winner alone: a future is only safe to drop if some survivor still
    predicts it. That is what stops a chain of pairwise prunings from quietly
    removing the last world predicting exfiltration.
    """
    pruned: list[str] = []
    losses: list[Truncation] = []
    survivors = list(field.worlds)
    live = {w.world_id for w in survivors}
    for loser in field.worlds:
        if len(survivors) <= 1:
            break
        if loser.world_id not in live:
            continue
        candidates = [w for w in survivors if w.world_id != loser.world_id]
        winner = _dominating_winner(loser, candidates, observed=observed, futures=futures)
        if winner is None:
            continue
        if _future_unique_to(loser, candidates, futures=futures):
            continue
        survivors = candidates
        live = {w.world_id for w in survivors}
        pruned.append(loser.world_id)
        losses.append(
            Truncation(
                what="world",
                identifier=loser.world_id,
                reason=f"dominated_by:{winner.world_id}",
                consequence_lost=float(loser.latent_state.consequence),
            )
        )
    if not pruned:
        return field, ()
    return _with_truncations(field.with_worlds(tuple(survivors)), tuple(losses)), tuple(pruned)


def _dominating_winner(
    loser: Any,
    candidates: Sequence[Any],
    *,
    observed: frozenset[str],
    futures: Mapping[str, frozenset[str]] | None,
) -> Any | None:
    for winner in candidates:
        if dominance_test(winner, loser, observed=observed, futures=futures).dominates():
            return winner
    return None


def _future_unique_to(
    loser: Any, survivors: Sequence[Any], *, futures: Mapping[str, frozenset[str]] | None
) -> bool:
    """The hard veto, evaluated collectively: does the loser predict a
    security-critical future that no survivor predicts?"""
    mapping = futures or {}
    loser_futures = mapping.get(loser.world_id, _default_futures(loser))
    covered: set[str] = set()
    for world in survivors:
        covered |= set(mapping.get(world.world_id, _default_futures(world)))
    return bool(loser_futures - covered)


def _with_truncations(field: Any, extra: tuple[Truncation, ...]) -> Any:
    """Append to the field's truncation record without mutating it.

    ``with_worlds`` cannot carry these, so ``dataclasses.replace`` is used.
    """
    if not extra:
        return field
    if not dataclasses.is_dataclass(field):
        raise ContractError("a causal belief field must be a frozen dataclass")
    return dataclasses.replace(
        field, truncations=append_truncations(field.truncations, extra)
    )

