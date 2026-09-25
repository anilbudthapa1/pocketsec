"""D4.6 — bounded counterfactual interventions and Responsibility Flux (architecture §9, §10).

This module exists so that "this event caused the incident" is a *measured* shift in
the Causal Belief Field rather than a story told over ancestry. It performs bounded
virtual interventions — ``do(remove E17)``, ``do(replace actor semantic class)`` and
the rest of §9 — against a copy of the field, and reports four separate shifts:
world support, predicted consequence, predicted evidence, and the field distance.

What it refuses to do:

- It never applies an intervention to the real world. Every intervention builds a
  throwaway counterfactual field, measures it, and drops it (§44: the counterfactual
  workspace is allocated per call and dropped on return). There is no module-level
  cache here, and ``tests/test_stage4_counterfactual.py`` asserts that.
- It never composes interventions. ``MAX_INTERVENTION_DEPTH`` is 1 because §9 says
  *bounded* virtual interventions, and a composition tree is the unbounded version.
- It never accepts a target that is not a real ``CausalNode.signature`` present in the
  spine it was handed. Stage 2's most expensive defect (S2-FC-01) was a counterfactual
  credit function keyed on ``CausalNode.signature`` but looked up by a positional
  locator ``lineage:index:rN:mM`` — two disjoint key spaces, so the function was never
  called once while the gate reported a measurement. Here a key-space mismatch raises
  ``ContractError`` on the first call instead of silently measuring nothing.
- It never renames a security dimension into an authority field. Architecture §9 writes
  ``do(block privilege transition)`` and both ``block`` and ``privilege`` are in
  ``FORBIDDEN_AUTHORITY_FIELDS`` (trust rule T5), so the kind is
  ``SUPPRESS_ESCALATION`` and the field is ``suppressed_dimension``, holding a
  ``DIMENSIONS`` key. Reading a value out of that mapping is fine; naming a field after
  it is a T5 violation.

Responsibility Flux (§10) is the aggregate: responsibility *moves* between events as
evidence arrives, so the causal spine is a flux rather than something frozen at first
detection. ``calculate_responsibility_flux`` is therefore given the previous flux
samples and carries a bounded history.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.causal.memory import CausalNode
from pocketsec.stage1.state.security_state import DIMENSIONS

if TYPE_CHECKING:  # pragma: no cover - typing only, and deliberately so
    # Stage 4's world types are written by the `foundation` package. Importing them
    # only for typing keeps this module importable on its own, which matters because
    # claims/typed_claim.py imports `Intervention` from here: a runtime import cycle
    # through the world types would make the claim graph unloadable.
    from pocketsec.stage4.worlds.field import CausalBeliefField
    from pocketsec.stage4.worlds.world import SecurityWorldV1

__all__ = [
    "MAX_COUNTERFACTUALS_PER_INCIDENT",
    "MAX_FLUX_HISTORY",
    "MAX_INTERVENTION_DEPTH",
    "NOVELTY_BORN_MECHANISM",
    "SUPPORT_SENSITIVITY",
    "Intervention",
    "InterventionKind",
    "InterventionResult",
    "ResponsibilityFlux",
    "calculate_responsibility_flux",
    "counterfactual_intervene",
    "enumerate_interventions",
    "jensen_shannon",
    "normalised_support",
    "sweep_interventions",
]

#: §29's entropy budget line for counterfactual work. Charged per incident, not per call.
MAX_COUNTERFACTUALS_PER_INCIDENT: int = 32
#: §9 "bounded virtual interventions". Depth 1 means: no intervention on an intervention.
MAX_INTERVENTION_DEPTH: int = 1
#: §10's flux history, bounded like every other piece of endpoint state.
MAX_FLUX_HISTORY: int = 8

#: Log-odds sensitivity of world support to a fully-depended-upon intervention.
#: A fixed constant on purpose: what this module measures is the *ratio* between
#: worlds and between interventions, never an absolute probability. Tuning this
#: would move every number in the same direction and change no ordering.
SUPPORT_SENSITIVITY: float = 2.0

#: The mechanism id of the bounded UNKNOWN world (``worlds/field.unknown_world``).
#: It is the only world whose support may depend on novelty, because novelty is not
#: maliciousness: removing novelty must not weaken a world that rests on evidence.
NOVELTY_BORN_MECHANISM: str = "unresolved_novel_mechanism"

_SIGNATURE_LENGTH: int = 16
_HEX_DIGITS: frozenset[str] = frozenset("0123456789abcdef")
#: Work charged for the intervention itself, before the per-world and per-spine-node
#: terms. The spine term is not decoration: measured in one run on this host, a single
#: intervention over a 48-node spine took 2.664x the wall clock of the same intervention
#: over a 6-node spine (loadavg 14.78 13.14 10.37) while a spine-free charge stayed flat
#: at 4 units. A budget that cannot see that is a budget an attacker starves by growing
#: the spine, so the charge is linear in both K and the spine length.
_WORK_UNITS_BASE: int = 2


class InterventionKind(StrEnum):
    """The closed set of §9 operators.

    ``SUPPRESS_ESCALATION`` is §9's ``do(block privilege transition)`` renamed: see the
    module docstring and spec §2.4. The rename is mandatory, not cosmetic.
    """

    REMOVE_EVENT = "REMOVE_EVENT"
    REPLACE_ACTOR_CLASS = "REPLACE_ACTOR_CLASS"
    SUPPRESS_ESCALATION = "SUPPRESS_ESCALATION"
    REMOVE_NOVELTY = "REMOVE_NOVELTY"
    DELAY_STEP = "DELAY_STEP"


@dataclass(frozen=True, slots=True)
class Intervention:
    """One bounded virtual intervention.

    ``target_signature`` is a :attr:`CausalNode.signature` — 16 lowercase hex digits —
    and nothing else. The shape is validated here so the key space cannot drift from
    the spine's key space without the very first call failing loudly.
    """

    kind: InterventionKind
    target_signature: str
    suppressed_dimension: str = ""
    replacement_class: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.kind, InterventionKind):
            raise ContractError(f"kind must be an InterventionKind, got {self.kind!r}")
        _require_signature(self.target_signature)
        if self.kind is InterventionKind.SUPPRESS_ESCALATION:
            if self.suppressed_dimension not in DIMENSIONS:
                raise ContractError(
                    "SUPPRESS_ESCALATION requires suppressed_dimension in DIMENSIONS, "
                    f"got {self.suppressed_dimension!r}"
                )
        elif self.suppressed_dimension:
            raise ContractError(
                f"{self.kind.value} must not carry suppressed_dimension "
                f"{self.suppressed_dimension!r}"
            )
        if self.kind is InterventionKind.REPLACE_ACTOR_CLASS:
            if not self.replacement_class:
                raise ContractError("REPLACE_ACTOR_CLASS requires a replacement_class")
        elif self.replacement_class:
            raise ContractError(
                f"{self.kind.value} must not carry replacement_class "
                f"{self.replacement_class!r}"
            )

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind.value,
            "target_signature": self.target_signature,
            "suppressed_dimension": self.suppressed_dimension,
            "replacement_class": self.replacement_class,
        }


@dataclass(frozen=True, slots=True)
class InterventionResult:
    """What one intervention did, with the four shifts kept separate.

    They are separate because they answer different questions and a single scalar
    would hide the disagreement: an intervention can move world support a long way
    while changing predicted consequence not at all, and that is informative.
    """

    intervention: Intervention
    support_shift: Mapping[str, float]
    outcome_shift: float
    evidence_shift: float
    field_distance: float
    work_units: int

    def moved_the_field(self, *, epsilon: float = 1e-12) -> bool:
        return self.field_distance > epsilon

    def to_dict(self) -> dict[str, object]:
        return {
            "intervention": self.intervention.to_dict(),
            "support_shift": {k: round(v, 6) for k, v in self.support_shift.items()},
            "outcome_shift": round(self.outcome_shift, 6),
            "evidence_shift": round(self.evidence_shift, 6),
            "field_distance": round(self.field_distance, 6),
            "work_units": self.work_units,
        }


@dataclass(frozen=True, slots=True)
class ResponsibilityFlux:
    """RF(E_j, t) (§10) — responsibility as a flux, not frozen at first detection."""

    node_signature: str
    flux: float
    at_sequence: int
    history: tuple[tuple[int, float], ...] = ()

    def __post_init__(self) -> None:
        _require_signature(self.node_signature)
        if len(self.history) > MAX_FLUX_HISTORY:
            raise ContractError(
                f"flux history is bounded to {MAX_FLUX_HISTORY}, got {len(self.history)}"
            )

    def with_sample(self, at_sequence: int, flux: float) -> ResponsibilityFlux:
        """Append one sample, dropping the oldest past ``MAX_FLUX_HISTORY``.

        Bounded by construction: an incident that runs for hours may not grow this.
        """
        history = (*self.history, (self.at_sequence, self.flux))[-MAX_FLUX_HISTORY:]
        return ResponsibilityFlux(
            node_signature=self.node_signature,
            flux=flux,
            at_sequence=at_sequence,
            history=history,
        )

    def moved(self) -> float:
        """How much this node's responsibility changed since the previous sample.

        Zero when there is no history: an unmeasured movement is zero movement, not a
        guessed one.
        """
        if not self.history:
            return 0.0
        return self.flux - self.history[-1][1]


def _require_signature(value: object) -> str:
    """Refuse anything that is not a ``CausalNode.signature``.

    This is the S2-FC-01 guard. ``causal_signature`` returns ``sha256(...)[:16]``, so a
    positional locator, a world id or a lineage string fails here rather than joining
    against nothing later.
    """
    if not isinstance(value, str) or len(value) != _SIGNATURE_LENGTH:
        raise ContractError(
            f"target_signature must be {_SIGNATURE_LENGTH} hex chars (a CausalNode."
            f"signature), got {value!r}"
        )
    if not _HEX_DIGITS.issuperset(value):
        raise ContractError(f"target_signature must be lowercase hex, got {value!r}")
    return value


def _dimension_bit(dimension: str) -> int:
    """The ``StateDelta.bitmask()`` bit for a dimension.

    Uses ``DIMENSIONS`` insertion order, which is what ``StateDelta.bitmask`` uses and
    which the SSIR v1 spec freezes.
    """
    for index, name in enumerate(DIMENSIONS):
        if name == dimension:
            return 1 << index
    raise ContractError(f"unknown dimension {dimension!r}")


def _spine_index(spine: Sequence[CausalNode]) -> Mapping[str, CausalNode]:
    return {node.signature: node for node in spine}


def _share_of_world(world: SecurityWorldV1, node: CausalNode,
                    index: Mapping[str, CausalNode]) -> float:
    """The fraction of a world's spine consequence carried by one node.

    Falls back to an equal share when the world's other spine nodes are not in the
    supplied spine: an unknown weight is an equal weight, never a maximal one.
    """
    signatures = tuple(world.spine_signatures)
    if not signatures or node.signature not in signatures:
        return 0.0
    weights = [max(0.0, index[s].delta_phi) for s in signatures if s in index]
    total = sum(weights)
    if total <= 0.0:
        return 1.0 / len(signatures)
    return max(0.0, node.delta_phi) / total


def _dependence(world: SecurityWorldV1, intervention: Intervention,
                node: CausalNode, index: Mapping[str, CausalNode]) -> float:
    """How much of this world's explanation rests on the intervened node, in [0, 1]."""
    kind = intervention.kind
    if kind is InterventionKind.DELAY_STEP:
        # The null probe, on purpose. Causal signatures are built from semantics and
        # exclude timing, so a semantics-preserving delay must not move support. A
        # non-zero shift here is a defect in the support model, which is why §25's
        # low-and-slow perturbation is worth running.
        return 0.0
    if kind is InterventionKind.REMOVE_NOVELTY:
        # Novelty is not maliciousness: only a world that was *born* from unexplained
        # residual may lose support when novelty is removed.
        return 1.0 if world.mechanism_id == NOVELTY_BORN_MECHANISM else 0.0
    if kind is InterventionKind.SUPPRESS_ESCALATION:
        bit = _dimension_bit(intervention.suppressed_dimension)
        if not node.state_delta_mask & bit:
            return 0.0
        if intervention.suppressed_dimension not in world.latent_state.asserted_dimensions:
            return 0.0
        return _share_of_world(world, node, index)
    # REMOVE_EVENT and REPLACE_ACTOR_CLASS both invalidate the node's semantic premise:
    # causal_signature chains actor semantics, so replacing the class breaks the chain
    # exactly as removing the event does.
    return _share_of_world(world, node, index)


def _reweighted_worlds(field: CausalBeliefField, intervention: Intervention,
                       node: CausalNode,
                       index: Mapping[str, CausalNode]) -> tuple[SecurityWorldV1, ...]:
    """The counterfactual world tuple. Allocated here, dropped by the caller (§44)."""
    worlds: list[SecurityWorldV1] = []
    for world in field.worlds:
        dependence = _dependence(world, intervention, node, index)
        if dependence <= 0.0:
            worlds.append(world)
            continue
        llr = -SUPPORT_SENSITIVITY * min(1.0, dependence)
        worlds.append(replace(world, support=world.support.combine(llr)))
    return tuple(worlds)


def normalised_support(field: CausalBeliefField) -> Mapping[str, float]:
    """The field's support vector normalised to sum to 1, for comparison only.

    A field whose support geometry does not legitimately normalise still has a
    *relative* ordering, and that is all any shift here is measured against — see
    ``WorldSupport.as_probability``, which returns ``None`` rather than pretending.
    An all-zero vector becomes uniform, because "no world is favoured" is the honest
    reading of no support at all.
    """
    vector = dict(field.support_vector())
    total = sum(vector.values())
    if total <= 0.0:
        if not vector:
            return {}
        uniform = 1.0 / len(vector)
        return dict.fromkeys(vector, uniform)
    return {key: value / total for key, value in vector.items()}


def _expected_consequence(field: CausalBeliefField, weights: Mapping[str, float]) -> float:
    return sum(
        weights.get(world.world_id, 0.0) * float(world.latent_state.consequence)
        for world in field.worlds
    )


def _evidence_distribution(field: CausalBeliefField,
                           weights: Mapping[str, float]) -> Mapping[str, float]:
    """The field's predicted-evidence distribution over signal names."""
    mass: dict[str, float] = {}
    for world in field.worlds:
        signals = tuple(sorted(world.expected_evidence))
        weight = weights.get(world.world_id, 0.0)
        if not signals or weight <= 0.0:
            continue
        per_signal = weight / len(signals)
        for signal in signals:
            mass[signal] = mass.get(signal, 0.0) + per_signal
    return mass


def jensen_shannon(left: Mapping[str, float], right: Mapping[str, float]) -> float:
    """Categorical Jensen-Shannon divergence in bits, pure stdlib (ADR-0030).

    Returns 0.0 when either side has no mass: an undefined divergence is reported as
    "no measured difference", never as a large one.
    """
    left_total = sum(left.values())
    right_total = sum(right.values())
    if left_total <= 0.0 or right_total <= 0.0:
        return 0.0
    keys = set(left) | set(right)
    divergence = 0.0
    for key in keys:
        p = left.get(key, 0.0) / left_total
        q = right.get(key, 0.0) / right_total
        m = 0.5 * (p + q)
        if p > 0.0:
            divergence += 0.5 * p * math.log2(p / m)
        if q > 0.0:
            divergence += 0.5 * q * math.log2(q / m)
    return max(0.0, min(1.0, divergence))


def counterfactual_intervene(
    field: CausalBeliefField,
    intervention: Intervention,
    *,
    spine: Sequence[CausalNode],
    depth: int = 1,
) -> InterventionResult:
    """CBF-F09 — measure one bounded virtual intervention against ``field``.

    Refuses a ``depth`` past ``MAX_INTERVENTION_DEPTH`` and refuses a target that is
    not in ``spine``. The second refusal is the whole point: if the intervention key
    space ever drifts from ``CausalNode.signature``, every call fails here instead of
    the caller reporting a measurement over an empty join.
    """
    if depth < 1 or depth > MAX_INTERVENTION_DEPTH:
        raise ContractError(
            f"intervention depth must be 1..{MAX_INTERVENTION_DEPTH}, got {depth}"
        )
    index = _spine_index(spine)
    node = index.get(intervention.target_signature)
    if node is None:
        raise ContractError(
            f"intervention target {intervention.target_signature!r} is not a spine "
            f"CausalNode.signature ({len(index)} spine nodes offered)"
        )
    before_weights = normalised_support(field)
    counterfactual = field.with_worlds(_reweighted_worlds(field, intervention, node, index))
    after_weights = normalised_support(counterfactual)
    support_shift = {
        world_id: after_weights.get(world_id, 0.0) - weight
        for world_id, weight in before_weights.items()
    }
    return InterventionResult(
        intervention=intervention,
        support_shift=support_shift,
        outcome_shift=(
            _expected_consequence(counterfactual, after_weights)
            - _expected_consequence(field, before_weights)
        ),
        evidence_shift=jensen_shannon(
            _evidence_distribution(field, before_weights),
            _evidence_distribution(counterfactual, after_weights),
        ),
        field_distance=field.support_distance(counterfactual),
        work_units=_WORK_UNITS_BASE + len(field.worlds) + len(index),
    )
    # `counterfactual` and both weight maps go out of scope here: the counterfactual
    # workspace is per-call and is never retained (§44).


def enumerate_interventions(
    field: CausalBeliefField,
    spine: Sequence[CausalNode],
    *,
    limit: int = MAX_COUNTERFACTUALS_PER_INCIDENT,
) -> tuple[Intervention, ...]:
    """Every intervention worth running against this field, bounded and deterministic.

    Targets come from ``spine`` node signatures, so the key space is correct by
    construction rather than by hope. Ordered by descending node ΔΦ then signature so
    the truncation drops the least consequential candidates first.
    """
    if limit < 0:
        raise ContractError(f"limit must be non-negative, got {limit}")
    ordered = sorted(spine, key=lambda n: (-max(0.0, n.delta_phi), n.signature))
    asserted = {
        dimension
        for world in field.worlds
        for dimension in world.latent_state.asserted_dimensions
    }
    candidates: list[Intervention] = []
    for node in ordered:
        candidates.append(
            Intervention(kind=InterventionKind.REMOVE_EVENT, target_signature=node.signature)
        )
        for dimension in sorted(asserted):
            if node.state_delta_mask & _dimension_bit(dimension):
                candidates.append(
                    Intervention(
                        kind=InterventionKind.SUPPRESS_ESCALATION,
                        target_signature=node.signature,
                        suppressed_dimension=dimension,
                    )
                )
    return tuple(candidates[:limit])


def sweep_interventions(
    field: CausalBeliefField,
    interventions: Sequence[Intervention],
    *,
    spine: Sequence[CausalNode],
) -> tuple[InterventionResult, ...]:
    """Run a bounded batch. Refuses more than ``MAX_COUNTERFACTUALS_PER_INCIDENT``.

    Refusing rather than silently truncating: a caller that wants 400 counterfactuals
    has a bug or is an amplification path, and either way the entropy budget must see
    it.
    """
    if len(interventions) > MAX_COUNTERFACTUALS_PER_INCIDENT:
        raise ContractError(
            f"at most {MAX_COUNTERFACTUALS_PER_INCIDENT} counterfactuals per incident, "
            f"got {len(interventions)}"
        )
    return tuple(
        counterfactual_intervene(field, intervention, spine=spine)
        for intervention in interventions
    )


def calculate_responsibility_flux(
    field: CausalBeliefField,
    spine: Sequence[CausalNode],
    *,
    at_sequence: int,
    previous: Sequence[ResponsibilityFlux] = (),
) -> tuple[ResponsibilityFlux, ...]:
    """CBF-F10 — responsibility as the field shift a node's removal would cause (§10).

    ``previous`` is what makes this a *flux* rather than a snapshot: responsibility
    moves between events as evidence arrives, so each node carries the bounded history
    of its own earlier samples. Passing nothing yields first samples with empty
    histories, which is honest — an unmeasured movement is not a guessed one.

    Bounded to ``MAX_COUNTERFACTUALS_PER_INCIDENT`` nodes, highest ΔΦ first.
    """
    if at_sequence < 0:
        raise ContractError(f"at_sequence must be non-negative, got {at_sequence}")
    history = {flux.node_signature: flux for flux in previous}
    ordered = sorted(spine, key=lambda n: (-max(0.0, n.delta_phi), n.signature))
    out: list[ResponsibilityFlux] = []
    for node in ordered[:MAX_COUNTERFACTUALS_PER_INCIDENT]:
        result = counterfactual_intervene(
            field,
            Intervention(kind=InterventionKind.REMOVE_EVENT, target_signature=node.signature),
            spine=spine,
        )
        earlier = history.get(node.signature)
        if earlier is None:
            out.append(
                ResponsibilityFlux(
                    node_signature=node.signature,
                    flux=result.field_distance,
                    at_sequence=at_sequence,
                )
            )
        else:
            out.append(earlier.with_sample(at_sequence, result.field_distance))
    return tuple(out)
