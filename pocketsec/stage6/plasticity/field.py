"""HEL-F08 — ``compute_plasticity_field``: how much each component may change.

Architecture §11 assigns plasticity **locally**: a detector that nothing else
covers, or one learned from a single suspicious source, should be harder to move
than a well-validated, freshly useful one. The whole trusted state never becomes
equally plastic. The score is the architecture's formula, bound symbol by symbol
to things this repository can actually compute::

    P = (N * V * S * U) / (1 + R + C + Q + B)

What this module refuses to do:

* It never decides anything by itself. A field is a table of numbers; only
  ``plasticity/masks.py`` turns it into a permission, and the protected-anchor
  freeze there does not read this table at all. The field can make a mask
  *stricter* than the uniform control — never more permissive than the safety
  bounds.
* It never invents a value. Every term is validated to ``[0, 1]`` at
  construction, and an unknown component has plasticity ``0.0``: a component the
  field was not told about is frozen, not guessed at.

HEL-F08 is OPTIONAL (spec §4.22). Its simple control is ``masks.uniform_mask``
at **identical** mutation and threshold budgets (lesson 4: the budget is the
knob, so the control holds it fixed). Its firing count is the number of changes
the field froze that the uniform mask would have allowed; zero means ``INERT``.
Every constant here is a chosen parameter, not a measurement (§4.21).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from pocketsec.stage0.contracts.common import ContractError, require_finite_unit_interval
from pocketsec.stage6.constitution.learning import MIN_INDEPENDENT_GROUPS

__all__ = [
    "PLASTICITY_FLOOR",
    "PlasticityField",
    "PlasticityTerms",
    "baseline_terms",
    "compute_plasticity_field",
    "detector_terms",
    "jaccard",
    "novelty",
    "plasticity",
    "procedure_terms",
    "safe_share",
    "threshold_terms",
    "validation_share",
]

#: Below this a component is frozen by ``generate_plasticity_mask``. Chosen, not
#: measured: with every term in [0, 1] the numerator is a product of four shares,
#: so 0.05 freezes a component only when at least one factor is small.
PLASTICITY_FLOOR: float = 0.05

_TERM_FIELDS: tuple[str, ...] = (
    "novelty",
    "validation",
    "stability",
    "utility",
    "forgetting_risk",
    "contradiction",
    "poison",
    "budget_pressure",
)


def safe_share(numerator: float, denominator: float) -> float:
    """``numerator / denominator`` clipped to [0, 1]; ``0.0`` when nothing was counted.

    Every term below is a share of something. An empty denominator means there
    was nothing to measure, and the honest share of nothing is zero — not one,
    which would silently *grant* plasticity on missing evidence.
    """
    if denominator <= 0:
        return 0.0
    return max(0.0, min(1.0, numerator / denominator))


def jaccard(left: frozenset[str], right: frozenset[str]) -> float:
    """|L & R| / |L | R|; two empty sets share nothing (0.0), not everything."""
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def novelty(own: frozenset[str], residents: Sequence[frozenset[str]]) -> float:
    """N = 1 - max overlap (Jaccard of replay match-sets) with a resident of the same kind."""
    return 1.0 - max((jaccard(own, other) for other in residents), default=0.0)


def validation_share(independent_groups: int) -> float:
    """V = independent groups / MIN_INDEPENDENT_GROUPS, capped at 1.

    Groups, not observations: one source repeating itself is one vote
    (architecture §7), so frequency cannot buy plasticity.
    """
    return safe_share(independent_groups, MIN_INDEPENDENT_GROUPS)


@dataclass(frozen=True, slots=True)
class PlasticityTerms:
    """Architecture §11, every symbol bound to a computable quantity.

    ``component_id`` is an ``item_id``, the literal ``"threshold"``, or
    ``"new:<pattern_key>"`` for knowledge that does not exist yet.
    """

    component_id: str
    novelty: float  # N: 1 - max overlap with resident items of the same kind
    validation: float  # V: independent_groups / MIN_INDEPENDENT_GROUPS, capped at 1
    stability: float  # S: EpistemicHalfLife.trust (1.0 for new components)
    utility: float  # U: holdout recall gain (detectors) / FP reduction (baselines), >= 0
    forgetting_risk: float  # R: share of rehearsal positives this component covers alone
    contradiction: float  # C: share of contradicting labels on its episodes
    poison: float  # Q: PoisonSuspicion scalar summary
    budget_pressure: float  # B: occupied / capacity of its store

    def __post_init__(self) -> None:
        if not isinstance(self.component_id, str) or not self.component_id:
            raise ContractError("PlasticityTerms.component_id must be a non-empty string")
        for name in _TERM_FIELDS:
            require_finite_unit_interval(getattr(self, name), f"PlasticityTerms.{name}")


def plasticity(terms: PlasticityTerms) -> float:
    """``(N*V*S*U) / (1 + R + C + Q + B)``; in [0, 1] because every term is."""
    numerator = terms.novelty * terms.validation * terms.stability * terms.utility
    denominator = (
        1.0 + terms.forgetting_risk + terms.contradiction + terms.poison + terms.budget_pressure
    )
    return numerator / denominator


@dataclass(frozen=True, slots=True)
class PlasticityField:
    """The per-component plasticity table one candidate was built under."""

    entries: tuple[tuple[str, float], ...]  # (component_id, P), sorted by id
    terms: tuple[PlasticityTerms, ...]  # same order as entries

    def __post_init__(self) -> None:
        ids = [component for component, _ in self.entries]
        if ids != sorted(set(ids)):
            raise ContractError("PlasticityField.entries must be unique and sorted by id")
        if tuple(t.component_id for t in self.terms) != tuple(ids):
            raise ContractError("PlasticityField.terms must align with entries")

    def value(self, component_id: str) -> float:
        """P for ``component_id``; ``0.0`` (frozen) for a component never scored."""
        for component, value in self.entries:
            if component == component_id:
                return value
        return 0.0

    def component_ids(self) -> tuple[str, ...]:
        return tuple(component for component, _ in self.entries)


def compute_plasticity_field(terms: Sequence[PlasticityTerms]) -> PlasticityField:
    """HEL-F08. One entry per component; a duplicate component id is refused.

    Refusing duplicates rather than keeping the first or the max matters: two
    different term rows for one component mean two callers disagree about what
    that component is, and silently picking one hides the disagreement.
    """
    by_id: dict[str, PlasticityTerms] = {}
    for row in terms:
        if not isinstance(row, PlasticityTerms):
            raise ContractError(f"expected PlasticityTerms, got {type(row).__name__}")
        if row.component_id in by_id:
            raise ContractError(f"duplicate plasticity component {row.component_id!r}")
        by_id[row.component_id] = row
    ordered = tuple(by_id[key] for key in sorted(by_id))
    return PlasticityField(
        entries=tuple((row.component_id, plasticity(row)) for row in ordered),
        terms=ordered,
    )


# --- the bindings, per component kind (spec §D6.6) -------------------------------------
#
# Each builder takes counts the chamber measured and states, in one place, which
# measurement stands for which symbol. Keeping the bindings here rather than
# inline in the chamber is what lets a reader check them against §11.


def detector_terms(
    component_id: str,
    *,
    own_matches: frozenset[str],
    resident_matches: Sequence[frozenset[str]],
    groups: int,
    stability: float,
    utility: float,
    sole_coverage: float,
    true_positives: int,
    false_positives: int,
    poison: float,
    occupied: int,
    capacity: int,
) -> PlasticityTerms:
    """A DETECTOR add/replace. C is the training false-positive share of its motif."""
    return PlasticityTerms(
        component_id=component_id,
        novelty=novelty(own_matches, resident_matches),
        validation=validation_share(groups),
        stability=stability,
        utility=utility,
        forgetting_risk=sole_coverage,
        contradiction=safe_share(false_positives, true_positives + false_positives),
        poison=poison,
        budget_pressure=safe_share(occupied, capacity),
    )


def baseline_terms(
    component_id: str,
    *,
    covered: bool,
    groups: int,
    utility: float,
    poison: float,
    occupied: int,
    capacity: int,
) -> PlasticityTerms:
    """A BASELINE add. N is 0 when a resident baseline already explains its anchor;
    a baseline covers no rehearsal positive, so R is 0; nothing contradicts it but
    its poison suspicion, which is Q."""
    return PlasticityTerms(
        component_id=component_id,
        novelty=0.0 if covered else 1.0,
        validation=validation_share(groups),
        stability=1.0,
        utility=utility,
        forgetting_risk=0.0,
        contradiction=0.0,
        poison=poison,
        budget_pressure=safe_share(occupied, capacity),
    )


def procedure_terms(
    component_id: str, *, groups: int, stability: float, poison: float, occupied: int, capacity: int
) -> PlasticityTerms:
    """A PROCEDURE add/merge. U is 1: a procedure record changes no score, so it
    claims no detection utility and the field is not a detection-utility test for
    it (G3 checks it on non-regression instead)."""
    return PlasticityTerms(
        component_id=component_id,
        novelty=1.0,
        validation=validation_share(groups),
        stability=stability,
        utility=1.0,
        forgetting_risk=0.0,
        contradiction=0.0,
        poison=poison,
        budget_pressure=safe_share(occupied, capacity),
    )


def threshold_terms(
    *, fp_before: int, fp_after: int, negatives: int, positives_lost: int, positives: int
) -> PlasticityTerms:
    """The THRESHOLD. U is the FP reduction on the calibration negatives; R is the
    share of rehearsal positives the new threshold would stop alerting on."""
    return PlasticityTerms(
        component_id="threshold",
        novelty=1.0,
        validation=1.0,
        stability=1.0,
        utility=safe_share(fp_before - fp_after, negatives),
        forgetting_risk=safe_share(positives_lost, positives),
        contradiction=0.0,
        poison=0.0,
        budget_pressure=0.0,
    )
