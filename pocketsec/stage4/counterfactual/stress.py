"""D4.11 — adversarial belief stress on high-consequence worlds (architecture §25).

Before an incident resolves, the conclusion is attacked. All eight §25 perturbations are
implemented here as structured tests that actually run against a counterfactual copy of
the Causal Belief Field, and each returns whether the conclusion survived, how far
support moved, and whether the attack exposed the conclusion as **spurious**.

The load-bearing one is ``RENAME_SEMANTIC_PRESERVING``, and it is nearly free.
``causal_signature`` is built from semantics and excludes identities
(``stage1/causal/memory.py:47``): no pid, path, inode or command line participates. So
renaming binaries, users and paths must leave ``field.support_vector()``
**bit-identical**, and that is asserted as equality, not similarity. The same argument
covers ``REPLACE_IOC_WITH_EQUIVALENT``, ``DELAY_LOW_AND_SLOW`` and
``PERTURB_EPOCH_CONTEXT``: each perturbs something the support model must not be
reading, so any movement at all is a defect in this stage, not a property of the
attacker.

What this module refuses to do:

- It never reports survival it did not test. A perturbation the corpus could not supply
  material for returns a row whose ``detail`` begins with :data:`NO_MATERIAL`, and
  :func:`stresses_actually_run` is how a caller counts the rows that mean something. A
  suite of eight untested "survived" rows would be the most flattering possible lie.
- It never mutates the field. Every perturbation is measured on a throwaway copy.
- It never treats a support *rise* under dropped telemetry as good news. Under
  ``DROP_TELEMETRY`` a conclusion that gets stronger with less evidence is flagged
  spurious, because that is falsifier F4 — the most dangerous single failure available
  to this stage.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field as dataclass_field, replace
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.causal.memory import CausalNode
from pocketsec.stage1.state.security_state import DIMENSIONS
from pocketsec.stage4.counterfactual.intervention import (
    SUPPORT_SENSITIVITY,
    Intervention,
    InterventionKind,
    counterfactual_intervene,
    normalised_support,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pocketsec.stage4.worlds.field import CausalBeliefField
    from pocketsec.stage4.worlds.world import SecurityWorldV1

__all__ = [
    "COLLAPSE_DROP",
    "MAX_STRESS_PERTURBATIONS",
    "NO_MATERIAL",
    "RISE_EPSILON",
    "PerturbationKind",
    "StressMaterial",
    "StressResult",
    "effective_observation",
    "explanatory_fit",
    "implied_signals",
    "stress_world_adversarially",
    "stresses_actually_run",
]

#: §25 lists eight perturbations. Exactly eight, and the enum is asserted against this.
MAX_STRESS_PERTURBATIONS: int = 8
#: A normalised-support drop at or beyond this is a collapsed conclusion.
COLLAPSE_DROP: float = 0.25
#: Any rise past this under dropped telemetry is a defect, not noise.
RISE_EPSILON: float = 1e-9
#: Prefix of a ``StressResult.detail`` that was never actually exercised.
NO_MATERIAL: str = "NO_MATERIAL"

_EMPTY_RENAMES: Mapping[str, str] = MappingProxyType({})

#: Which mandatory signal a raised lattice dimension implies. Deliberately partial:
#: ``discovery`` and ``modification`` have no member of ``MANDATORY_SIGNALS`` that
#: corresponds to them, and inventing one would put a signal into the observation set
#: that no sensor ever emits. An unmapped dimension implies nothing.
_DIMENSION_SIGNALS: Mapping[str, str] = MappingProxyType(
    {
        "privilege": "privilege_change",
        "credential": "credential_access",
        "persistence": "persistence_write",
        "execution": "module_load",
        "trust": "authentication",
        "isolation": "boundary_crossing",
        "reachability": "boundary_crossing",
    }
)


class PerturbationKind(StrEnum):
    """§25's eight attacks, verbatim in intent."""

    INSERT_BENIGN_CONTEXT = "INSERT_BENIGN_CONTEXT"
    REMOVE_CRITICAL_EVENT = "REMOVE_CRITICAL_EVENT"
    RENAME_SEMANTIC_PRESERVING = "RENAME_SEMANTIC_PRESERVING"
    DELAY_LOW_AND_SLOW = "DELAY_LOW_AND_SLOW"
    INJECT_DECOY_ANCESTRY = "INJECT_DECOY_ANCESTRY"
    DROP_TELEMETRY = "DROP_TELEMETRY"
    REPLACE_IOC_WITH_EQUIVALENT = "REPLACE_IOC_WITH_EQUIVALENT"
    PERTURB_EPOCH_CONTEXT = "PERTURB_EPOCH_CONTEXT"


@dataclass(frozen=True, slots=True)
class StressMaterial:
    """What one perturbation needs from the corpus in order to be real.

    The corpus owns ground truth; this module owns the attack. Keeping the material
    outside means a perturbation cannot quietly invent the evidence it then finds.
    """

    observed_signals: frozenset[str] = frozenset()
    spine: tuple[CausalNode, ...] = ()
    benign_signals: frozenset[str] = frozenset()
    critical_signature: str = ""
    decoy: CausalNode | None = None
    dropped_signals: frozenset[str] = frozenset()
    identity_renames: Mapping[str, str] = dataclass_field(default=_EMPTY_RENAMES)
    ioc_equivalents: Mapping[str, str] = dataclass_field(default=_EMPTY_RENAMES)
    delay_steps: int = 0
    epoch_shift: int = 0

    def __post_init__(self) -> None:
        if self.delay_steps < 0:
            raise ContractError(f"delay_steps must be non-negative, got {self.delay_steps}")


@dataclass(frozen=True, slots=True)
class StressResult:
    """One attack's outcome. ``detail`` names what was done, not what was hoped."""

    kind: PerturbationKind
    conclusion_survived: bool
    support_shift: float
    spurious_detected: bool
    detail: str

    def exercised(self) -> bool:
        return not self.detail.startswith(NO_MATERIAL)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "conclusion_survived": self.conclusion_survived,
            "support_shift": round(self.support_shift, 9),
            "spurious_detected": self.spurious_detected,
            "detail": self.detail,
        }


def explanatory_fit(world: SecurityWorldV1, observed: frozenset[str]) -> float:
    """How much of what this world predicts was actually observed, in [0, 1].

    Zero when the observation contains something the world forbids: a world that
    forbade what happened does not explain it at all. Zero also when the world predicts
    nothing — a world with no expected evidence makes no claim and may not draw support
    from silence.
    """
    forbidden = frozenset(world.forbidden_evidence)
    if forbidden & observed:
        return 0.0
    expected = frozenset(world.expected_evidence)
    if not expected:
        return 0.0
    return len(expected & observed) / len(expected)


def implied_signals(spine: Sequence[CausalNode]) -> frozenset[str]:
    """The signals a causal spine implies, read from state deltas only.

    This is the function the four semantics-preserving perturbations are aimed at. It
    reads ``state_delta_mask`` and nothing else — no ``actor_identity``, no
    ``sequence``, no ``evidence_locators`` — which is precisely why a rename, an IOC
    swap and a delay must leave the field bit-identical. If anyone ever makes this read
    an identity or a timestamp, three tests in ``tests/test_stage4_counterfactual.py``
    go red, which is the point of routing the perturbations through here.
    """
    signals: set[str] = set()
    for node in spine:
        for index, dimension in enumerate(DIMENSIONS):
            if node.state_delta_mask & (1 << index):
                signal = _DIMENSION_SIGNALS.get(dimension)
                if signal is not None:
                    signals.add(signal)
    return frozenset(signals)


def effective_observation(observed: frozenset[str], spine: Sequence[CausalNode]) -> frozenset[str]:
    """What the incident actually shows: direct observations plus spine-implied signals."""
    return observed | implied_signals(spine)


def _reweighted(field: CausalBeliefField, base: frozenset[str],
                observed: frozenset[str]) -> CausalBeliefField:
    """A counterfactual field under a perturbed observation set. Dropped by the caller."""
    worlds: list[SecurityWorldV1] = []
    for world in field.worlds:
        delta = explanatory_fit(world, observed) - explanatory_fit(world, base)
        if delta == 0.0:
            worlds.append(world)
            continue
        worlds.append(replace(world, support=world.support.combine(SUPPORT_SENSITIVITY * delta)))
    return field.with_worlds(tuple(worlds))


def _share(field: CausalBeliefField, world_id: str) -> float:
    return normalised_support(field).get(world_id, 0.0)


def _signal_stress(field: CausalBeliefField, world_id: str, kind: PerturbationKind,
                   base: frozenset[str], observed: frozenset[str], detail: str) -> StressResult:
    """Apply an observation-set perturbation and read the stressed world's shift."""
    before = _share(field, world_id)
    after = _share(_reweighted(field, base, observed), world_id)
    shift = after - before
    if kind is PerturbationKind.DROP_TELEMETRY:
        # A conclusion that strengthens when evidence is removed is unsafe (F4).
        return StressResult(
            kind=kind,
            conclusion_survived=shift > -COLLAPSE_DROP,
            support_shift=shift,
            spurious_detected=shift > RISE_EPSILON,
            detail=detail,
        )
    survived = shift > -COLLAPSE_DROP
    return StressResult(
        kind=kind,
        conclusion_survived=survived,
        support_shift=shift,
        spurious_detected=not survived,
        detail=detail,
    )


def _identity_stress(field: CausalBeliefField, world_id: str, kind: PerturbationKind,
                     perturbed: CausalBeliefField, detail: str) -> StressResult:
    """Require bit-identity of the whole support vector, not just the stressed world.

    Equality of ``dict[str, float]`` is exact. That is deliberate: the invariant is that
    the support model reads no identity, no timestamp and no epoch label, so "close
    enough" would hide exactly the leak this test exists to find.
    """
    before = dict(normalised_support(field))
    after = dict(normalised_support(perturbed))
    identical = before == after
    shift = after.get(world_id, 0.0) - before.get(world_id, 0.0)
    return StressResult(
        kind=kind,
        conclusion_survived=identical,
        support_shift=shift,
        spurious_detected=not identical,
        detail=f"{detail}; support_vector_bit_identical={identical}",
    )


def _renamed_spine(spine: Sequence[CausalNode],
                   renames: Mapping[str, str]) -> tuple[CausalNode, ...]:
    """Rewrite identities only. Signatures, ΔΦ and state masks are untouched."""
    out: list[CausalNode] = []
    for node in spine:
        identity = renames.get(node.actor_identity, node.actor_identity)
        locators = tuple(renames.get(loc, loc) for loc in node.evidence_locators)
        out.append(replace(node, actor_identity=identity, evidence_locators=locators))
    return tuple(out)


def _intervention_stress(field: CausalBeliefField, world_id: str, kind: PerturbationKind,
                         signature: str, spine: Sequence[CausalNode],
                         detail: str) -> StressResult:
    """Remove one node through the intervention machinery and read the shift."""
    result = counterfactual_intervene(
        field,
        Intervention(kind=InterventionKind.REMOVE_EVENT, target_signature=signature),
        spine=spine,
    )
    shift = result.support_shift.get(world_id, 0.0)
    survived = shift > -COLLAPSE_DROP
    return StressResult(
        kind=kind,
        conclusion_survived=survived,
        support_shift=shift,
        spurious_detected=not survived,
        detail=f"{detail}; field_distance={result.field_distance:.6f}",
    )


def _no_material(kind: PerturbationKind, why: str) -> StressResult:
    """A row that says plainly that nothing was tested.

    ``conclusion_survived`` is False on purpose: an untested conclusion has not
    survived anything, and defaulting it to True is how a stress suite comes to report
    eight passes it never ran.
    """
    return StressResult(
        kind=kind,
        conclusion_survived=False,
        support_shift=0.0,
        spurious_detected=False,
        detail=f"{NO_MATERIAL}: {why}",
    )


def _run_one(field: CausalBeliefField, world_id: str, kind: PerturbationKind,
             material: StressMaterial) -> StressResult:
    base = effective_observation(material.observed_signals, material.spine)
    if kind is PerturbationKind.INSERT_BENIGN_CONTEXT:
        if not material.benign_signals:
            return _no_material(kind, "no benign context supplied")
        return _signal_stress(field, world_id, kind, base, base | material.benign_signals,
                              f"inserted {len(material.benign_signals)} benign signals")
    if kind is PerturbationKind.DROP_TELEMETRY:
        if not material.dropped_signals:
            return _no_material(kind, "no dropped signals supplied")
        return _signal_stress(field, world_id, kind, base, base - material.dropped_signals,
                              f"dropped {sorted(material.dropped_signals)}")
    if kind is PerturbationKind.REMOVE_CRITICAL_EVENT:
        if not material.critical_signature or not material.spine:
            return _no_material(kind, "no critical event or spine supplied")
        return _intervention_stress(field, world_id, kind, material.critical_signature,
                                    material.spine, f"removed {material.critical_signature}")
    if kind is PerturbationKind.INJECT_DECOY_ANCESTRY:
        if material.decoy is None:
            return _no_material(kind, "no decoy node supplied")
        return _intervention_stress(field, world_id, kind, material.decoy.signature,
                                    (*material.spine, material.decoy),
                                    f"decoy {material.decoy.signature} dPhi="
                                    f"{material.decoy.delta_phi:.4f}")
    return _run_semantics_preserving(field, world_id, kind, material)


def _run_semantics_preserving(field: CausalBeliefField, world_id: str, kind: PerturbationKind,
                              material: StressMaterial) -> StressResult:
    """The four perturbations that must change nothing at all.

    Each rebuilds the field through the *same* support path as the real one, from a
    perturbed spine or a perturbed field. That is what keeps them from being
    tautologies: the perturbation genuinely flows through
    :func:`effective_observation`, and only the fact that nothing there reads an
    identity, a sequence number or an epoch makes the result identical.
    """
    base = effective_observation(material.observed_signals, material.spine)
    if kind is PerturbationKind.RENAME_SEMANTIC_PRESERVING:
        if not material.identity_renames:
            return _no_material(kind, "no identity renames supplied")
        renamed = _renamed_spine(material.spine, material.identity_renames)
        perturbed = _reweighted(field, base, effective_observation(
            material.observed_signals, renamed))
        return _identity_stress(field, world_id, kind, perturbed,
                                f"renamed {len(material.identity_renames)} identities over "
                                f"{len(renamed)} spine nodes")
    if kind is PerturbationKind.REPLACE_IOC_WITH_EQUIVALENT:
        if not material.ioc_equivalents:
            return _no_material(kind, "no IOC equivalents supplied")
        swapped = _renamed_spine(material.spine, material.ioc_equivalents)
        perturbed = _reweighted(field, base, effective_observation(
            material.observed_signals, swapped))
        return _identity_stress(field, world_id, kind, perturbed,
                                f"replaced {len(material.ioc_equivalents)} IOCs over "
                                f"{len(swapped)} spine nodes")
    if kind is PerturbationKind.DELAY_LOW_AND_SLOW:
        if material.delay_steps <= 0:
            return _no_material(kind, "no delay supplied")
        delayed = tuple(
            replace(node, sequence=node.sequence + material.delay_steps)
            for node in material.spine
        )
        perturbed = _reweighted(field, base, effective_observation(
            material.observed_signals, delayed))
        return _identity_stress(field, world_id, kind, perturbed,
                                f"delayed {len(delayed)} nodes by {material.delay_steps}")
    if material.epoch_shift == 0:
        return _no_material(kind, "no epoch shift supplied")
    shifted = replace(field, epoch_id=field.epoch_id + material.epoch_shift)
    perturbed = _reweighted(shifted, base, base)
    return _identity_stress(field, world_id, kind, perturbed,
                            f"epoch shifted by {material.epoch_shift}")


def stress_world_adversarially(
    field: CausalBeliefField,
    world_id: str,
    *,
    corpus_hook: Callable[[PerturbationKind], StressMaterial | None],
) -> tuple[StressResult, ...]:
    """CBF-F16 — run all eight §25 perturbations against one world's conclusion.

    ``corpus_hook`` is asked for material per perturbation and may return ``None``; the
    resulting row is marked ``NO_MATERIAL`` rather than counted as a pass. Returns at
    most ``MAX_STRESS_PERTURBATIONS`` rows, in enum order, deterministically.
    """
    if field.world(world_id) is None:
        raise ContractError(f"world {world_id!r} is not in incident {field.incident_id!r}")
    results: list[StressResult] = []
    for kind in PerturbationKind:
        material = corpus_hook(kind)
        if material is None:
            results.append(_no_material(kind, "corpus supplied no material"))
            continue
        if not isinstance(material, StressMaterial):
            raise ContractError(
                f"corpus_hook must return StressMaterial or None, got {type(material).__name__}"
            )
        results.append(_run_one(field, world_id, kind, material))
    if len(results) > MAX_STRESS_PERTURBATIONS:  # pragma: no cover - enum is closed at 8
        raise ContractError(f"stress suite is bounded to {MAX_STRESS_PERTURBATIONS} perturbations")
    return tuple(results)


def stresses_actually_run(results: Sequence[StressResult]) -> int:
    """How many rows were real. This is the number an ablation may quote, not eight."""
    return sum(1 for result in results if result.exercised())
