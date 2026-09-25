"""D3.8 — the dual oracle: §19 security divergence gated by §20's two-source rule.

A candidate passes only when **both** halves agree:

    teacher divergence <= permitted envelope   AND   hard security properties hold

Neither half alone is sufficient, and that is the entire design. Oracle A (the frozen
teacher snapshot) is a recording of the scorer being compiled, so on its own it would
certify a cell for reproducing the teacher's mistakes. Oracle B (Stage 1's invariants)
on its own would certify a cell that is safe and useless — one that abstains on
everything, or answers alarmingly about everything. Two tests in
``tests/test_stage3_oracles.py`` are named for exactly these two failures.

``d_future_hazard`` is typed ``None`` and can hold nothing else. ADR-0116 rejected the
Future Cone and the hazard heads on measured calibration; typing the field rather than
defaulting it means a contributor who wants hazard back has to change the type, which is
a visible change in a diff rather than a number quietly appearing in a sum.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.state.potential import phi
from pocketsec.stage1.state.security_state import DIMENSIONS, StateDelta
from pocketsec.stage3.oracles.security_specs import (
    CellLike,
    Violation,
    apply_delta,
    check_hard_security_constraints,
)
from pocketsec.stage3.oracles.teacher import PHI_SQUASHED_SCALE, TeacherOracle
from pocketsec.stage3.theory import SecurityConsequence, consequence_of

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pocketsec.stage3.bytecode.vm import CellFrame, CellResult, CellVM

__all__ = [
    "DEFAULT_DIVERGENCE_WEIGHTS",
    "DIVERGENCE_TERMS",
    "ENVELOPES",
    "DualOracleEvaluator",
    "DualOracleVerdict",
    "SecurityDivergence",
    "envelope_for",
]

#: §19's six terms, in the order the architecture writes them.
DIVERGENCE_TERMS = (
    "d_state_delta",
    "d_security_potential",
    "d_future_hazard",
    "d_uncertainty",
    "d_evidence_requirement",
    "d_causal_attribution",
)

#: Weights sum to 1.0 so ``total`` stays in [0, 1] and is comparable to an envelope.
#: ``d_future_hazard`` is pinned at 0.0: the term is not merely unweighted, it is
#: *unmeasurable*, because the mechanism that would produce it was removed.
DEFAULT_DIVERGENCE_WEIGHTS: Mapping[str, float] = MappingProxyType(
    {
        "d_state_delta": 0.30,
        "d_security_potential": 0.30,
        "d_future_hazard": 0.0,
        "d_uncertainty": 0.10,
        "d_evidence_requirement": 0.20,
        "d_causal_attribution": 0.10,
    }
)

#: Θ_c — the permitted teacher-divergence envelope per consequence class. Tighter as
#: consequence rises: being 20% off about a routine frame is a cost question; being 20%
#: off about a critical one is a security failure. These are thresholds, not
#: measurements, and no run in this repository has calibrated them.
ENVELOPES: Mapping[SecurityConsequence, float] = MappingProxyType(
    {
        SecurityConsequence.ROUTINE: 0.20,
        SecurityConsequence.ELEVATED: 0.10,
        SecurityConsequence.HIGH: 0.04,
        SecurityConsequence.CRITICAL: 0.01,
    }
)


def _assert_envelopes_are_closed_and_monotone() -> None:
    """Checked at import: a missing or slackened envelope must not be a runtime surprise."""
    missing = [c.name for c in SecurityConsequence if c not in ENVELOPES]
    if missing:
        raise ContractError(f"ENVELOPES must cover every SecurityConsequence; missing {missing}")
    ordered = [ENVELOPES[c] for c in sorted(SecurityConsequence)]
    if not all(higher > lower for higher, lower in zip(ordered, ordered[1:])):
        raise ContractError(
            f"ENVELOPES must tighten strictly with consequence, got {ordered}"
        )


_assert_envelopes_are_closed_and_monotone()


def envelope_for(consequence: SecurityConsequence) -> float:
    """The permitted teacher divergence for a frame of this consequence."""
    try:
        return ENVELOPES[consequence]
    except KeyError as exc:  # pragma: no cover - closed mapping, asserted at import
        raise ContractError(f"no envelope for consequence {consequence!r}") from exc


@dataclass(frozen=True, slots=True)
class SecurityDivergence:
    """D_sec(K, T, x) — §19, one term per axis, with the rejected axis kept visible."""

    d_state_delta: float
    d_security_potential: float
    d_uncertainty: float
    d_evidence_requirement: float
    d_causal_attribution: float
    d_future_hazard: None = None
    weights: Mapping[str, float] = DEFAULT_DIVERGENCE_WEIGHTS

    def __post_init__(self) -> None:
        if self.d_future_hazard is not None:
            raise ContractError(
                "d_future_hazard is permanently None: ADR-0116 rejected the Future Cone "
                "and the hazard heads on measured calibration. Restoring the term means "
                "changing this type, not passing a number."
            )
        for name in DIVERGENCE_TERMS:
            if name == "d_future_hazard":
                continue
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ContractError(f"SecurityDivergence.{name} must be a number, got {value!r}")
            numeric = float(value)
            if numeric != numeric or numeric in (float("inf"), float("-inf")):
                raise ContractError(f"SecurityDivergence.{name} must be finite, got {value!r}")
            object.__setattr__(self, name, numeric)
        weights = self.weights
        if not isinstance(weights, Mapping):
            raise ContractError("SecurityDivergence.weights must be a mapping")
        missing = [name for name in DIVERGENCE_TERMS if name not in weights]
        if missing:
            raise ContractError(f"SecurityDivergence.weights is missing {missing}")
        if float(weights["d_future_hazard"]) != 0.0:
            raise ContractError(
                "d_future_hazard must carry weight 0.0; a non-zero weight would make "
                "`total` permanently None and hide the fact that the term was removed"
            )
        object.__setattr__(
            self, "weights", MappingProxyType({k: float(weights[k]) for k in DIVERGENCE_TERMS})
        )

    @property
    def total(self) -> float | None:
        """The weighted sum, or ``None`` when a *weighted* term is unmeasured.

        ``d_future_hazard`` carries weight 0.0, so its permanent ``None`` does not make
        the total unmeasured — it makes it a total over five axes, which is what it is.
        """
        running = 0.0
        for name in DIVERGENCE_TERMS:
            weight = self.weights[name]
            if weight == 0.0:
                continue
            value = getattr(self, name)
            if value is None:
                return None
            running += weight * float(value)
        return running

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {name: getattr(self, name) for name in DIVERGENCE_TERMS}
        payload["weights"] = dict(self.weights)
        payload["total"] = self.total
        return payload


@dataclass(frozen=True, slots=True)
class DualOracleVerdict:
    """The decision, with both halves' evidence attached so a refusal can be argued with."""

    passed: bool
    teacher_available: bool
    teacher_divergence: float | None
    envelope: float
    divergence: SecurityDivergence
    hard_violations: tuple[Violation, ...]
    consequence: SecurityConsequence
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "teacher_available": self.teacher_available,
            "teacher_divergence": self.teacher_divergence,
            "envelope": self.envelope,
            "divergence": self.divergence.to_dict(),
            "hard_violations": [v.to_dict() for v in self.hard_violations],
            "consequence": self.consequence.name,
            "reason": self.reason,
        }


@dataclass
class _Accumulator:
    """Running per-frame divergence sums. Mutable by design; never leaves this module."""

    frames: int = 0
    state_delta: float = 0.0
    security_potential: float = 0.0
    uncertainty: float = 0.0
    evidence_requirement: float = 0.0
    causal_attribution: float = 0.0
    teacher_absolute_error: float = 0.0
    teacher_responses: int = 0
    violations: list[Violation] = field(default_factory=list)

    def mean(self, total: float) -> float:
        return total / self.frames if self.frames else 0.0


def _squash(magnitude: float) -> float:
    """The project's own Φ squash (``ssir_encoder.py:221``), reused so scales agree."""
    magnitude = abs(magnitude)
    return magnitude / (magnitude + PHI_SQUASHED_SCALE) if magnitude else 0.0


def _phi_of(frame: CellFrame, delta: StateDelta) -> float | None:
    applied = apply_delta(frame.state, delta)
    return None if applied is None else phi(applied).total


def _accumulate_frame(acc: _Accumulator, frame: CellFrame, result: CellResult) -> None:
    acc.frames += 1

    expected_dims = frame.delta.dimensions
    observed_dims = result.delta.dimensions
    acc.state_delta += len(expected_dims ^ observed_dims) / len(DIMENSIONS)

    expected_phi = _phi_of(frame, frame.delta)
    observed_phi = _phi_of(frame, result.delta)
    if expected_phi is None or observed_phi is None:
        # An out-of-lattice delta is already a hard violation; as a divergence it is
        # maximal rather than unmeasured, because we know it is wrong.
        acc.security_potential += 1.0
    else:
        acc.security_potential += _squash(observed_phi - expected_phi)

    # Answering under high substrate uncertainty is itself divergence from the learned
    # path: the cell is claiming resolution the evidence did not support. An abstention
    # contributes nothing, because abstaining is what the learned path would do.
    acc.uncertainty += 0.0 if result.abstained else float(frame.uncertainty)

    frame_digests = {ref.digest for ref in frame.evidence}
    if frame_digests:
        carried = frame_digests & {ref.digest for ref in result.evidence}
        acc.evidence_requirement += 1.0 - len(carried) / len(frame_digests)
        if not result.evidence and not result.abstained:
            acc.causal_attribution += 1.0


class DualOracleEvaluator:
    """§20. Runs the candidate over frames and asks both oracles about every result.

    What it refuses to do: it refuses to return ``passed=True`` when the teacher has no
    opinion. An unavailable or silent teacher is UNKNOWN, and UNKNOWN is not agreement —
    crystallizing on it would be crystallizing on nothing at all.
    """

    __slots__ = ("_teacher", "_vm")

    def __init__(self, *, teacher: TeacherOracle, vm: CellVM) -> None:
        if not isinstance(teacher, TeacherOracle):
            raise ContractError(
                f"DualOracleEvaluator needs a TeacherOracle, got {type(teacher).__name__}"
            )
        self._teacher = teacher
        self._vm = vm

    def evaluate(self, cell: CellLike, frames: Sequence[CellFrame]) -> DualOracleVerdict:
        if not frames:
            raise ContractError(
                "a verdict over zero frames is not a pass and not a fail; give the "
                "evaluator the frames the cell claims to resolve"
            )
        acc = _Accumulator()
        consequence = SecurityConsequence.ROUTINE
        for frame in frames:
            result = self._vm.run(cell.operator, frame)
            acc.violations.extend(check_hard_security_constraints(cell, frame, result))
            _accumulate_frame(acc, frame, result)
            frame_consequence = consequence_of(frame.delta, frame.state)
            if frame_consequence > consequence:
                consequence = frame_consequence
            teacher_score = self._teacher.consult(frame)
            if teacher_score is not None:
                acc.teacher_responses += 1
                acc.teacher_absolute_error += abs(float(teacher_score) - float(result.risk))

        divergence = SecurityDivergence(
            d_state_delta=acc.mean(acc.state_delta),
            d_security_potential=acc.mean(acc.security_potential),
            d_uncertainty=acc.mean(acc.uncertainty),
            d_evidence_requirement=acc.mean(acc.evidence_requirement),
            d_causal_attribution=acc.mean(acc.causal_attribution),
        )
        teacher_available = self._teacher.available and acc.teacher_responses > 0
        teacher_divergence = (
            acc.teacher_absolute_error / acc.teacher_responses if teacher_available else None
        )
        envelope = envelope_for(consequence)
        violations = tuple(acc.violations)

        passed, reason = _decide(teacher_available, teacher_divergence, envelope, violations)
        return DualOracleVerdict(
            passed=passed,
            teacher_available=teacher_available,
            teacher_divergence=teacher_divergence,
            envelope=envelope,
            divergence=divergence,
            hard_violations=violations,
            consequence=consequence,
            reason=reason,
        )


def _decide(
    teacher_available: bool,
    teacher_divergence: float | None,
    envelope: float,
    violations: tuple[Violation, ...],
) -> tuple[bool, str]:
    """Both halves must hold. Hard violations are reported first: they are not tradeable."""
    if violations:
        kinds = sorted({v.kind.value for v in violations})
        return False, f"HARD_CONSTRAINT_VIOLATED: {', '.join(kinds)}"
    if not teacher_available or teacher_divergence is None:
        return False, "TEACHER_UNAVAILABLE"
    if teacher_divergence > envelope:
        return (
            False,
            f"DIVERGENCE_ABOVE_ENVELOPE: {teacher_divergence} > {envelope}",
        )
    return True, "PASSED"
