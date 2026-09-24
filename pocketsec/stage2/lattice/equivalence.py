"""D2.7 — predictive equivalence: when are two Behaviour Atoms the same thing?

Merging atoms is how the lattice stays small enough to compile. It is also the
single most dangerous operation in this subsystem, because a wrong merge is
invisible: two behaviours share one node, the node's successor distribution
becomes an average of two different futures, and every alert built on it inherits
the average. That is the merge bug that costs alert stability.

So equivalence here is a **conjunction of four independent checks**, and any one
of them can refuse:

1. **Predictive distance.** Jensen-Shannon divergence between the two atoms'
   successor distributions, base 2, so the number lies in ``[0, 1]`` bits and is
   symmetric. Divergence alone is not enough — two atoms can predict the same
   future for different reasons.
2. **Epoch compatibility.** The atoms must share at least one recorded epoch. An
   atom learned before a system change and one learned after are not the same
   behaviour even when they predict identically (spec §24).
3. **Uncertainty compatibility.** Their uncertainty envelopes must overlap.
   Merging a well-observed atom with a barely-observed one launders the second
   one's doubt into the first one's confidence.
4. **State compatibility.** Their ``SecurityStateV1`` summaries must agree on all
   nine ``DIMENSIONS``. Two atoms that predict the same continuation from
   *different capability states* are different security facts, and Stage 1's whole
   argument (ADR-0005) is that the state is the meaning.

And one refusal that comes before all four: **thin evidence**. Below
``min_evidence`` visits an atom has no successor distribution worth comparing, so
the verdict is ``equivalent=False`` with the reason named, never a coin flip
dressed up as a distance.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from pocketsec.stage1.state.security_state import DIMENSIONS
from pocketsec.stage2.lattice.atom import BehaviourAtom
from pocketsec.stage2.lattice.transitions import TransitionLattice

__all__ = [
    "REASON_EPOCH",
    "REASON_INSUFFICIENT_EVIDENCE",
    "REASON_PREDICTIVE_DISTANCE",
    "REASON_STATE",
    "REASON_UNCERTAINTY",
    "EquivalenceVerdict",
    "jensen_shannon",
    "predictive_equivalence",
    "successor_distribution",
]

#: Refusal reasons. Named constants because they are counted in
#: ``RestructureReport.reason_counts`` and a typo would silently split a tally.
REASON_INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
REASON_PREDICTIVE_DISTANCE = "PREDICTIVE_DISTANCE"
REASON_EPOCH = "EPOCH_INCOMPATIBLE"
REASON_UNCERTAINTY = "UNCERTAINTY_INCOMPATIBLE"
REASON_STATE = "STATE_INCOMPATIBLE"

_UNSEEN_BUCKET = "unseen"


@dataclass(frozen=True, slots=True)
class EquivalenceVerdict:
    """Why two atoms were, or were not, judged the same behaviour."""

    left: int
    right: int
    #: Jensen-Shannon divergence in bits, ``[0, 1]``.
    distance: float
    epoch_compatible: bool
    uncertainty_compatible: bool
    state_compatible: bool
    equivalent: bool
    #: The refusal reason, or ``"EQUIVALENT"``. Human-readable *and* machine-
    #: countable: the reason code is the first token.
    detail: str

    @property
    def reason(self) -> str:
        return self.detail.split(":", 1)[0]

    def to_dict(self) -> dict[str, Any]:
        return {
            "left": self.left,
            "right": self.right,
            "distance": round(self.distance, 6),
            "epoch_compatible": self.epoch_compatible,
            "uncertainty_compatible": self.uncertainty_compatible,
            "state_compatible": self.state_compatible,
            "equivalent": self.equivalent,
            "detail": self.detail,
        }


def successor_distribution(
    lattice: TransitionLattice, source: int, *, epoch_id: int | None = None
) -> dict[int | str, float]:
    """P(next | source) over recorded targets plus one ``unseen`` bucket.

    The unseen bucket is what makes the comparison honest: two atoms with
    disjoint successor sets would otherwise be compared over a union in which
    each one's mass is zero everywhere the other has evidence, and the divergence
    would depend on how much *unrecorded* mass each one is hiding.
    """
    distribution: dict[int | str, float] = {
        target: lattice.probability(source, target, epoch_id=epoch_id)
        for target in lattice.known_targets(source, epoch_id=epoch_id)
    }
    distribution[_UNSEEN_BUCKET] = lattice.unseen_mass(source, epoch_id=epoch_id)
    return distribution


def _entropy(values: list[float]) -> float:
    return -sum(p * math.log2(p) for p in values if p > 0.0)


def jensen_shannon(
    left: dict[int | str, float], right: dict[int | str, float]
) -> float:
    """JS divergence in bits over the union of support. Symmetric, ``[0, 1]``.

    Both inputs are renormalised first. They arrive from Laplace-smoothed counts
    which already sum to one, but floating-point drift over many buckets would
    otherwise push the result marginally outside ``[0, 1]`` and break a bound a
    caller is entitled to rely on.
    """
    keys = set(left) | set(right)
    if not keys:
        return 0.0
    left_total = sum(left.values()) or 1.0
    right_total = sum(right.values()) or 1.0
    p = [left.get(key, 0.0) / left_total for key in sorted(keys, key=repr)]
    q = [right.get(key, 0.0) / right_total for key in sorted(keys, key=repr)]
    mixture = [(a + b) / 2.0 for a, b in zip(p, q, strict=True)]
    divergence = _entropy(mixture) - (_entropy(p) + _entropy(q)) / 2.0
    # Clamp: the identity JSD >= 0 is exact in real arithmetic and only
    # approximate in floating point, and a caller testing "zero for identical
    # distributions" deserves an exact zero rather than -1e-17.
    return min(1.0, max(0.0, divergence))


def _envelopes_overlap(
    left: tuple[float, float], right: tuple[float, float]
) -> bool:
    return left[0] <= right[1] and right[0] <= left[1]


def _state_disagreements(left: BehaviourAtom, right: BehaviourAtom) -> tuple[str, ...]:
    return tuple(
        name
        for name in DIMENSIONS
        if left.state_summary.level(name) != right.state_summary.level(name)
    )


def predictive_equivalence(
    lattice: TransitionLattice,
    left: BehaviourAtom,
    right: BehaviourAtom,
    *,
    epsilon: float = 0.05,
    min_evidence: int = 8,
) -> EquivalenceVerdict:
    """Are ``left`` and ``right`` the same behaviour? Refuses on thin evidence.

    The four compatibility flags are always reported, even when the verdict was
    decided by an earlier refusal, so a caller can see *which* properties held.
    ``distance`` is likewise always computed: a refused merge whose distributions
    were in fact far apart is a different diagnostic from one that was only short
    of evidence.
    """
    distance = jensen_shannon(
        successor_distribution(lattice, left.atom_id),
        successor_distribution(lattice, right.atom_id),
    )
    epoch_shared = sorted(set(left.epoch_counts) & set(right.epoch_counts))
    epoch_compatible = bool(epoch_shared)
    uncertainty_compatible = _envelopes_overlap(
        left.uncertainty_envelope, right.uncertainty_envelope
    )
    disagreements = _state_disagreements(left, right)
    state_compatible = not disagreements

    def verdict(equivalent: bool, detail: str) -> EquivalenceVerdict:
        return EquivalenceVerdict(
            left=left.atom_id,
            right=right.atom_id,
            distance=distance,
            epoch_compatible=epoch_compatible,
            uncertainty_compatible=uncertainty_compatible,
            state_compatible=state_compatible,
            equivalent=equivalent,
            detail=detail,
        )

    thin = min(left.visit_count, right.visit_count)
    if thin < min_evidence:
        return verdict(
            False,
            f"{REASON_INSUFFICIENT_EVIDENCE}: {thin} visits < min_evidence "
            f"{min_evidence}; an equivalence asserted on thin evidence is a "
            f"silent merge bug",
        )
    if not epoch_compatible:
        return verdict(
            False,
            f"{REASON_EPOCH}: no shared epoch "
            f"({sorted(left.epoch_counts)} vs {sorted(right.epoch_counts)})",
        )
    if not state_compatible:
        return verdict(
            False,
            f"{REASON_STATE}: summaries disagree on {list(disagreements)}",
        )
    if not uncertainty_compatible:
        return verdict(
            False,
            f"{REASON_UNCERTAINTY}: envelopes {left.uncertainty_envelope} and "
            f"{right.uncertainty_envelope} do not overlap",
        )
    if distance > epsilon:
        return verdict(
            False,
            f"{REASON_PREDICTIVE_DISTANCE}: JS {distance:.6f} > epsilon {epsilon}",
        )
    return verdict(
        True,
        f"EQUIVALENT: JS {distance:.6f} <= {epsilon}, shared epochs {epoch_shared}",
    )
