"""D5.8b / Action Shadow — what the planner does NOT know about an action it wants to take.

Architecture §10 states the whole mechanism in one line::

    AS(A) = unmodelled dependencies + uncertain side effects + unobservable post-action effects

and one consequence: *"High Action Shadow pushes the action toward
observe/defer/human approval even when predicted security benefit is large."*

That consequence is the reason this module exists, and it is enforced **by the
shape of the function rather than by the body of it**: :func:`shadow_gate` takes
no benefit argument. There is no parameter through which a large predicted
security delta, a high-confidence Stage 4 verdict or an eager planner can enter
the autonomy decision, so benefit structurally cannot override shadow. A gate
that accepted both and then promised to weigh them correctly would be one
refactor away from the opposite behaviour (ADR-0003).

**What this module refuses to do.**

* It refuses to report a bare score. :class:`ActionShadow` carries the three
  counted terms of §10 plus the upstream-truncation count, and ``components``
  decomposes the score back into exactly those contributions — the rule Φ
  established in Stage 1 (``PhiBreakdown``) and that every score in this
  repository follows.
* It refuses to let a missing measurement look like a good one.
  :func:`calibrate_shadow` returns ``rank_correlation=None`` below
  :data:`MIN_CALIBRATION_SAMPLES`, and ``None`` is not zero and is not a pass
  (ADR-0004). If shadow does not rank-correlate with measured residual then it
  cannot gate autonomy on evidence, falsifier F3 fires, and the ceilings below
  remain what they already are: **chosen parameters**, not measured ones.
* It refuses to import :mod:`pocketsec.stage5.aegis.cone` at runtime. The cone
  needs ``FieldTruncation`` from :mod:`pocketsec.stage5.safe.action_field`,
  which needs :class:`ActionShadow` from here, so the three modules form a cycle
  that has to be cut somewhere. It is cut here because here it is safest: the
  shadow estimator can read a cone's counted structure but cannot call into the
  cone *builder*, so there is no path by which the thing being measured
  re-derives the measurement. :data:`UNKNOWN_BRANCH_NAME` is the one name shared
  across that cut — :func:`estimate_action_shadow` reads the branch label by value
  — and ``tests/test_stage5_field.py`` asserts it equals ``Branch.UNKNOWN.value``.
  That is §4.9's key-space rule applied to a string constant, because two waves
  have already shipped a defect where two key spaces were joined that could never
  match, and a label compared by value is exactly that shape of join.

Every threshold in this module is a **chosen** parameter. None is fitted, none
is measured, and a findings document that quotes one as a result is quoting a
fabrication (§4.9, §9.2).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_finite_unit_interval,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage5.operators.algebra import OperatorClass, OperatorSpec, Reversibility

if TYPE_CHECKING:  # pragma: no cover - annotations only; see the module docstring
    from pocketsec.stage4.stage5_interface import CBFResolutionV1
    from pocketsec.stage5.aegis.cone import InterventionCone
    from pocketsec.stage5.executor.residual import InterventionResidual
    from pocketsec.stage5.host.simulated import HostSnapshot
    from pocketsec.stage5.twin.response_twin import TwinPrediction

__all__ = [
    "MIN_CALIBRATION_SAMPLES",
    "SHADOW_AUTONOMY_CEILING",
    "SHADOW_CALIBRATION_BUCKETS",
    "SHADOW_HUMAN_CEILING",
    "SHADOW_SATURATION_COUNT",
    "SHADOW_TERMS",
    "SHADOW_WEIGHTS",
    "UNKNOWN_BRANCH_NAME",
    "ActionShadow",
    "AutonomyEligibility",
    "ShadowCalibration",
    "calibrate_shadow",
    "estimate_action_shadow",
    "generation_shadow",
    "shadow_gate",
]

#: A CHOSEN parameter. Above this, an action is not eligible for autonomous
#: execution however large its predicted benefit is. Nothing measured 0.35; it is
#: the value this contract fixed so that eight packages agree, and §9.2 lists it
#: among the parameters a findings document may not quote as a result.
SHADOW_AUTONOMY_CEILING: float = 0.35

#: A CHOSEN parameter. Above this, observation is the only remaining option and a
#: human decision contract is required for anything else.
SHADOW_HUMAN_CEILING: float = 0.70

#: A CHOSEN parameter. Below this many (shadow, residual) pairs, rank correlation
#: is ``None`` — not 0.0, and not a pass.
MIN_CALIBRATION_SAMPLES: int = 30

#: How many equal-width score bands :func:`calibrate_shadow` reports.
SHADOW_CALIBRATION_BUCKETS: int = 5

#: The count at which a term contributes half its weight. A saturating map is
#: used rather than a linear one because the difference between two unmodelled
#: dependencies and three matters, and the difference between forty and forty-one
#: does not. Also a CHOSEN parameter.
SHADOW_SATURATION_COUNT: int = 4

#: The four counted terms, in the order §10 names the first three. Declared as a
#: tuple so ``components`` keys cannot drift from the dataclass fields: the test
#: suite asserts these are exactly the integer fields of :class:`ActionShadow`.
SHADOW_TERMS: tuple[str, ...] = (
    "unmodelled_dependencies",
    "uncertain_side_effects",
    "unobservable_effects",
    "upstream_truncations",
)

#: CHOSEN weights summing to 1.0, so the score lies in [0, 1). The upstream term
#: is weighted lowest because it is the least specific to the action, and highest
#: on unmodelled dependencies because §8 names them as the term that can make
#: autonomy ineligible on its own.
SHADOW_WEIGHTS: Mapping[str, float] = MappingProxyType(
    {
        "unmodelled_dependencies": 0.35,
        "uncertain_side_effects": 0.25,
        "unobservable_effects": 0.25,
        "upstream_truncations": 0.15,
    }
)

#: The single name shared across the shadow/cone import cut. See the module
#: docstring; ``tests/test_stage5_field.py`` pins it against ``Branch.UNKNOWN``.
UNKNOWN_BRANCH_NAME: str = "UNKNOWN"

assert set(SHADOW_WEIGHTS) == set(SHADOW_TERMS)
assert abs(sum(SHADOW_WEIGHTS.values()) - 1.0) < 1e-9


class AutonomyEligibility(StrEnum):
    """What the shadow alone permits. Never what the authority plane permits."""

    ELIGIBLE = "ELIGIBLE"
    OBSERVE_ONLY = "OBSERVE_ONLY"
    HUMAN_REQUIRED = "HUMAN_REQUIRED"


def _term_contribution(count: int) -> float:
    """Saturating normalisation of one counted term into [0, 1).

    Monotone non-decreasing in ``count``, which is the property that makes
    "adding the cone can only raise the shadow" checkable rather than hoped for.
    """
    return count / (count + SHADOW_SATURATION_COUNT)


@dataclass(frozen=True, slots=True)
class ActionShadow:
    """§10's AS(A): three counted terms, one upstream term, one decomposable score.

    ``score`` is never reported without ``components``, and ``components`` sums to
    ``score``. A consumer that wants to know *why* an action was held back reads
    the counts, not the float.
    """

    candidate_id: str
    unmodelled_dependencies: int
    uncertain_side_effects: int
    unobservable_effects: int
    upstream_truncations: int
    score: float
    components: Mapping[str, float]

    def __post_init__(self) -> None:
        require_identifier(self.candidate_id, "ActionShadow.candidate_id")
        for term in SHADOW_TERMS:
            require_non_negative_int(getattr(self, term), f"ActionShadow.{term}")
        require_finite_unit_interval(self.score, "ActionShadow.score")
        if not isinstance(self.components, Mapping):
            raise ContractError("ActionShadow.components must be a mapping")
        if set(self.components) != set(SHADOW_TERMS):
            raise ContractError(
                f"ActionShadow.components keys {sorted(self.components)} must be exactly "
                f"{list(SHADOW_TERMS)}; a score that cannot be decomposed back into the "
                "counts that produced it is a bare number (Φ's rule)"
            )
        total = 0.0
        frozen: dict[str, float] = {}
        for key, value in self.components.items():
            contribution = require_finite_unit_interval(value, f"ActionShadow.components[{key!r}]")
            frozen[key] = contribution
            total += contribution
        if abs(total - self.score) > 1e-9:
            raise ContractError(
                f"ActionShadow.components sum to {total!r} but score is {self.score!r}; the "
                "decomposition must reconstruct the score exactly"
            )
        object.__setattr__(self, "components", MappingProxyType(frozen))

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "unmodelled_dependencies": self.unmodelled_dependencies,
            "uncertain_side_effects": self.uncertain_side_effects,
            "unobservable_effects": self.unobservable_effects,
            "upstream_truncations": self.upstream_truncations,
            "score": self.score,
            "components": dict(sorted(self.components.items())),
        }


def _shadow_from_counts(candidate_id: str, counts: Mapping[str, int]) -> ActionShadow:
    """Build the shadow from four counts. The ONLY place the score is computed."""
    components = {
        term: SHADOW_WEIGHTS[term] * _term_contribution(counts[term]) for term in SHADOW_TERMS
    }
    return ActionShadow(
        candidate_id=candidate_id,
        unmodelled_dependencies=counts["unmodelled_dependencies"],
        uncertain_side_effects=counts["uncertain_side_effects"],
        unobservable_effects=counts["unobservable_effects"],
        upstream_truncations=counts["upstream_truncations"],
        score=sum(components.values()),
        components=components,
    )


def _host_dependency_holes(snapshot: HostSnapshot) -> int:
    """Services that depend on a unit the snapshot does not contain.

    Host-wide rather than target-scoped on purpose: the twin walks at most
    ``MAX_TWIN_DEPTH`` edges, so a dependency edge leaving the snapshot entirely
    is unmodelled by definition and no amount of walking would find it.
    """
    known = {service.unit for service in snapshot.services}
    return sum(
        1
        for service in snapshot.services
        for required in service.depends_on
        if required not in known
    )


def _base_counts(
    prediction: TwinPrediction, snapshot: HostSnapshot, resolution: CBFResolutionV1
) -> dict[str, int]:
    """The three §10 terms plus the upstream term, from the twin and the snapshot alone."""
    unobserved_nodes = sum(1 for node in prediction.predicted.nodes if not node.observed)
    return {
        "unmodelled_dependencies": (
            len(prediction.unknown_dependencies)
            + unobserved_nodes
            + _host_dependency_holes(snapshot)
        ),
        "uncertain_side_effects": len(prediction.recovery_state_needed),
        "unobservable_effects": len(prediction.evidence_lost) + (1 if prediction.truncated else 0),
        # A resolution that lost worlds, or whose Stage 4 subsystem degraded,
        # raises shadow. It never raises confidence (§3.2 fact 4).
        "upstream_truncations": len(resolution.truncations) + len(resolution.degradations),
    }


def generation_shadow(
    candidate_id: str,
    *,
    prediction: TwinPrediction,
    snapshot: HostSnapshot,
    resolution: CBFResolutionV1,
) -> ActionShadow:
    """The shadow available at candidate-generation time, before any cone exists.

    The action field needs a shadow to construct a :class:`CandidateAction`, and a
    cone needs a candidate to be built from, so the two cannot both come first.
    This is the cone-free half: it counts exactly the terms the twin and the
    snapshot support. Because every cone term is non-negative and
    :func:`_term_contribution` is monotone, re-estimating with a cone can only
    **raise** the score — never lower it — so a candidate admitted on this shadow
    is never admitted on an optimistic one. ``tests/test_stage5_field.py`` asserts
    that monotonicity rather than assuming it.
    """
    return _shadow_from_counts(candidate_id, _base_counts(prediction, snapshot, resolution))


def estimate_action_shadow(
    candidate_id: str,
    *,
    prediction: TwinPrediction,
    cone: InterventionCone,
    snapshot: HostSnapshot,
    resolution: CBFResolutionV1,
) -> ActionShadow:
    """Count what is not known about this candidate, then normalise once.

    The cone's contribution is counted structurally, from three facts a cone states
    about itself: a node whose ``probability`` is ``None`` is a consequence nothing
    measured, a node whose ``state`` is ``None`` is a consequence the twin could not
    project and therefore could not verify afterwards, and a node whose ``branch`` is
    the Action Shadow branch is a consequence §9 already declares undescribable. The
    first two are what §10 calls uncertain and unobservable; none of the three
    requires this module to know how the cone was built, which is what keeps the
    import cut described in the module docstring safe rather than merely convenient.
    """
    counts = _base_counts(prediction, snapshot, resolution)
    counts["uncertain_side_effects"] += sum(1 for node in cone.nodes if node.probability is None)
    # A node on the Action Shadow branch counts as an unobservable effect even if
    # something attached a projected state to it. §9 defines that branch as the part
    # the twin cannot describe, so the branch label — not the presence of a state —
    # is what decides. Reading the label by value is why UNKNOWN_BRANCH_NAME exists.
    counts["unobservable_effects"] += sum(
        1
        for node in cone.nodes
        if node.state is None or str(node.branch) == UNKNOWN_BRANCH_NAME
    )
    return _shadow_from_counts(candidate_id, counts)


def shadow_gate(shadow: ActionShadow, *, spec: OperatorSpec) -> AutonomyEligibility:
    """What the shadow permits for this operator. **Takes no benefit argument.**

    ``spec`` is read for two structural facts only, neither of which is a score:
    an irreversible operator can never be shadow-eligible for autonomy (§2's
    IRREVERSIBLE_NEEDS_HIGHER_AUTHORITY), and a read-only O0 observation stays
    eligible at any shadow, because the alternative to observing under
    uncertainty is being blind under uncertainty (§2's
    NO_ACTION_IS_ALWAYS_AVAILABLE and FAILURE_MUST_NOT_STOP_MONITORING).
    """
    if not isinstance(shadow, ActionShadow):
        raise ContractError(
            f"shadow_gate needs an ActionShadow, got {type(shadow).__name__}; a duck-typed "
            "score cannot gate autonomy"
        )
    if spec.operator_class is OperatorClass.O0_OBSERVE:
        return AutonomyEligibility.ELIGIBLE
    if spec.reversibility is Reversibility.IRREVERSIBLE:
        return AutonomyEligibility.HUMAN_REQUIRED
    if shadow.score > SHADOW_HUMAN_CEILING:
        return AutonomyEligibility.HUMAN_REQUIRED
    if shadow.score > SHADOW_AUTONOMY_CEILING:
        return AutonomyEligibility.OBSERVE_ONLY
    return AutonomyEligibility.ELIGIBLE


@dataclass(frozen=True, slots=True)
class ShadowCalibration:
    """Whether shadow ranks actions the way measured residual ranks them.

    ``rank_correlation is None`` is the honest answer in three distinct cases —
    too few pairs, no variation in shadow, no variation in residual — and
    ``detail`` says which. None of the three is a pass (falsifier F3).
    """

    n: int
    buckets: tuple[tuple[float, float, int], ...]
    rank_correlation: float | None
    detail: str

    def __post_init__(self) -> None:
        require_non_negative_int(self.n, "ShadowCalibration.n")
        object.__setattr__(self, "buckets", tuple(self.buckets))
        if self.rank_correlation is not None:
            value = float(self.rank_correlation)
            if value != value or not -1.0 <= value <= 1.0:
                raise ContractError(
                    f"ShadowCalibration.rank_correlation must be within [-1, 1] or None, "
                    f"got {self.rank_correlation!r}"
                )
            object.__setattr__(self, "rank_correlation", value)
        if not isinstance(self.detail, str) or not self.detail.strip():
            raise ContractError("ShadowCalibration.detail must say why the result is what it is")

    def to_dict(self) -> dict[str, Any]:
        return {
            "n": self.n,
            "buckets": [list(row) for row in self.buckets],
            "rank_correlation": self.rank_correlation,
            "detail": self.detail,
        }


def _average_ranks(values: Sequence[float]) -> list[float]:
    """Ranks with ties averaged, so a tie cannot invent an ordering."""
    order = sorted(range(len(values)), key=lambda index: values[index])
    ranks = [0.0] * len(values)
    position = 0
    while position < len(order):
        end = position
        while end + 1 < len(order) and values[order[end + 1]] == values[order[position]]:
            end += 1
        shared = (position + end) / 2.0 + 1.0
        for index in order[position : end + 1]:
            ranks[index] = shared
        position = end + 1
    return ranks


def _pearson(xs: Sequence[float], ys: Sequence[float]) -> float | None:
    mean_x = sum(xs) / len(xs)
    mean_y = sum(ys) / len(ys)
    dx = [x - mean_x for x in xs]
    dy = [y - mean_y for y in ys]
    var_x = sum(value * value for value in dx)
    var_y = sum(value * value for value in dy)
    if var_x <= 0.0 or var_y <= 0.0:
        return None
    raw = sum(a * b for a, b in zip(dx, dy, strict=True)) / ((var_x**0.5) * (var_y**0.5))
    # Clamped because floating-point summation can put a perfect ranking at
    # 1.0000000000000002, and a coefficient outside [-1, 1] is a bug report, not a result.
    return max(-1.0, min(1.0, raw))


def _buckets(
    shadows: Sequence[float], residuals: Sequence[float]
) -> tuple[tuple[float, float, int], ...]:
    width = 1.0 / SHADOW_CALIBRATION_BUCKETS
    rows: list[tuple[float, float, int]] = []
    for index in range(SHADOW_CALIBRATION_BUCKETS):
        low = index * width
        high = low + width
        picked = [
            residual
            for shadow, residual in zip(shadows, residuals, strict=True)
            if low <= shadow < high or (index == SHADOW_CALIBRATION_BUCKETS - 1 and shadow >= high)
        ]
        mean = sum(picked) / len(picked) if picked else 0.0
        rows.append((low, mean, len(picked)))
    return tuple(rows)


def calibrate_shadow(
    pairs: Sequence[tuple[ActionShadow, InterventionResidual]],
) -> ShadowCalibration:
    """Rank-correlate shadow against measured residual, or refuse to.

    Below :data:`MIN_CALIBRATION_SAMPLES` the correlation is ``None``: thirty is
    the smallest sample this contract is willing to call a calibration, and
    reporting a coefficient over eleven pairs would be reporting noise with a
    decimal point on it. §9.2 expects this to return ``None`` on the Stage 5
    corpus, and that is the honest outcome rather than a failure of the run.
    """
    shadows = [shadow.score for shadow, _ in pairs]
    residuals = [float(residual.distance) for _, residual in pairs]
    n = len(pairs)
    buckets = _buckets(shadows, residuals) if n else ()
    if n < MIN_CALIBRATION_SAMPLES:
        return ShadowCalibration(
            n=n,
            buckets=buckets,
            rank_correlation=None,
            detail=(
                f"{n} pairs is below MIN_CALIBRATION_SAMPLES={MIN_CALIBRATION_SAMPLES}; "
                "rank correlation is None, which is not zero and not a pass (ADR-0004)"
            ),
        )
    correlation = _pearson(_average_ranks(shadows), _average_ranks(residuals))
    if correlation is None:
        return ShadowCalibration(
            n=n,
            buckets=buckets,
            rank_correlation=None,
            detail=(
                "one of the two rankings has no variation, so no rank correlation exists; "
                "a constant shadow cannot rank anything and None says so"
            ),
        )
    return ShadowCalibration(
        n=n,
        buckets=buckets,
        rank_correlation=correlation,
        detail=(
            f"Spearman rank correlation over {n} measured (shadow, residual) pairs; "
            "the residuals are simulated-host measurements (ADR-0046)"
        ),
    )
