"""D2.8 / DTL-F08 — multi-horizon security hazards (spec section 22).

Some security questions are hazards, not next events: "probability of a privilege
transition within the next N relevant events", "credential exposure before
session termination". Spec section 22 proposes compact hazard heads for exactly
that, on the argument that a hazard may catch a slow chain without storing or
generating a long context.

Horizons are counted in **relevant events, not wall time**. A host that is idle
for an hour has not moved through any horizon; a host that executes sixteen
consequential transitions in four seconds has moved through all of them. Wall
time would make the hazard a property of the machine's load.

``calibration_id`` is ``None`` on every estimate this module produces, and that
is deliberate rather than unfinished. Stage 1 ships ``calibration_id=None``
honestly and Stage 2 fixes it in D2.9; until an isotonic fit exists these
probabilities are *uncalibrated compounded rates*, so putting a plausible-looking
identifier on them would be the exact dishonesty this repository has a rule
against.

``constant_hazard`` is the control: the empirical base rate per
``(outcome, horizon)`` bucket, with no state and no cone. If the cone-derived
hazard cannot beat it on Brier or ECE at any horizon, DTL-F08 does not earn its
place (acceptance criterion 6 permits removal; see ADR-0116).

**MEASURED VERDICT — the hazard heads are rejected and default off (ADR-0116).**
On ``corpus='ambiguous'``, ``count=240``, ``seed=11``, 36 000 points at a 0.189722
positive rate: Brier **0.189552** against ``constant_hazard``'s **0.077958**, and
ECE **0.189625** against **0.036822**. Worse than a base rate on both metrics, by
2.4× and 5.2×. So this module refuses to drive an escalation, a verdict or a
compile candidate. It stays in the tree because ``constant_hazard`` is the control
that produced the rejection.

One trap, recorded here because it has already cost this project a wrong answer:
``Stage2Sample.final_phi`` is ``ScenarioResult.peak_phi`` (``dataset.py:143``),
**not** a terminal value. It must never be used as hazard ground truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping, Sequence

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.state.security_state import DIMENSIONS, SecurityStateV1
from pocketsec.stage2.predictors.future_cone import ConeBranch, FutureCone

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pocketsec.stage2.lattice.transitions import TransitionLattice

__all__ = [
    "HAZARD_DEFAULT_ENABLED",
    "HORIZONS",
    "OUTCOMES",
    "OUTCOME_DIMENSIONS",
    "HazardEstimate",
    "HazardReport",
    "constant_hazard",
    "estimate_security_hazard",
]

#: ADR-0116 rejected DTL-F08 on measured calibration: worse than `constant_hazard`
#: by 2.4x on Brier and 5.2x on ECE. Same reason as the cone's flag — the
#: rejection has to be readable from code, not only from the ADR.
HAZARD_DEFAULT_ENABLED: bool = False

#: Relevant events, not seconds.
HORIZONS: tuple[int, ...] = (1, 4, 16)

#: The four bounded outcomes spec section 22 names.
OUTCOMES: tuple[str, ...] = (
    "privilege_raise",
    "credential_exposure",
    "egress",
    "persistence",
)

#: Which Stage 1 capability dimension each outcome reads.
#:
#: ``egress`` maps to ``reachability`` because that is what the state lattice can
#: express: the state calculus knows that a lineage became externally reachable,
#: not that bytes left the host. A byte-level egress claim is an evidence
#: question for Stage 1, and asserting it from a state dimension would overstate
#: what was observed.
OUTCOME_DIMENSIONS: Mapping[str, str] = {
    "privilege_raise": "privilege",
    "credential_exposure": "credential",
    "egress": "reachability",
    "persistence": "persistence",
}

assert set(OUTCOME_DIMENSIONS) == set(OUTCOMES)
assert set(OUTCOME_DIMENSIONS.values()) <= set(DIMENSIONS)


@dataclass(frozen=True, slots=True)
class HazardEstimate:
    """One (outcome, horizon) hazard."""

    outcome: str
    horizon: int
    probability: float
    evidence_count: int
    #: ``None`` until D2.9 fits a calibration map. Never a guess.
    calibration_id: str | None = None

    def __post_init__(self) -> None:
        if self.outcome not in OUTCOMES:
            raise ContractError(
                f"unknown hazard outcome {self.outcome!r}; known: {list(OUTCOMES)}"
            )
        if self.horizon < 1:
            raise ContractError(
                f"horizon must be at least one relevant event, got {self.horizon}"
            )
        if not 0.0 <= self.probability <= 1.0:
            raise ContractError(
                f"hazard probability {self.probability} outside [0, 1]"
            )
        if self.evidence_count < 0:
            raise ContractError("evidence_count cannot be negative")
        if self.calibration_id is not None and not self.calibration_id.strip():
            raise ContractError(
                "calibration_id must be a real identifier or None, not blank"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "horizon": self.horizon,
            "probability": round(self.probability, 6),
            "evidence_count": self.evidence_count,
            "calibration_id": self.calibration_id,
        }


@dataclass(frozen=True, slots=True)
class HazardReport:
    """Every (outcome, horizon) estimate from one call."""

    estimates: tuple[HazardEstimate, ...]

    def __post_init__(self) -> None:
        keys = [(est.outcome, est.horizon) for est in self.estimates]
        if len(set(keys)) != len(keys):
            raise ContractError("duplicate (outcome, horizon) in a hazard report")

    def for_outcome(self, outcome: str, horizon: int) -> HazardEstimate | None:
        for estimate in self.estimates:
            if estimate.outcome == outcome and estimate.horizon == horizon:
                return estimate
        return None

    def calibrated(self) -> bool:
        """True only when every estimate carries a calibration identifier."""
        return bool(self.estimates) and all(
            estimate.calibration_id is not None for estimate in self.estimates
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "estimates": [estimate.to_dict() for estimate in self.estimates],
            "calibrated": self.calibrated(),
        }


def _branch_edges_confirmed(
    lattice: TransitionLattice, branch: ConeBranch
) -> bool:
    """Drop a branch whose internal lattice edges no longer exist.

    A cone can outlive the lattice it was expanded from: an atom may be merged,
    split or evicted between expansion and use. A hazard built on a vanished edge
    is a stale claim, so it is dropped rather than quietly carried forward.
    """
    path = branch.atom_path
    for source, target in zip(path, path[1:]):
        if lattice.probability(source, target) <= 0.0:
            return False
    return True


def _per_event_rate(
    cone: FutureCone,
    lattice: TransitionLattice,
    *,
    state: SecurityStateV1,
    dimension: str,
) -> tuple[float, int]:
    """Per-event hazard rate and its supporting branch count.

    A branch that reaches the outcome in one event implies a higher per-event
    rate than one taking three, so each branch contributes
    ``probability / len(atom_path)``. Cone mass the lattice could not name stays
    in ``unresolved_mass`` and contributes nothing: an unknown continuation is
    not evidence of a hazard, and is not evidence against one either.
    """
    rate = 0.0
    supporting = 0
    for branch in cone.branches:
        if branch.terminal_state.level(dimension) <= state.level(dimension):
            continue
        if not _branch_edges_confirmed(lattice, branch):
            continue
        steps = max(1, len(branch.atom_path))
        rate += branch.probability / steps
        supporting += 1
    return min(1.0, rate), supporting


def estimate_security_hazard(
    cone: FutureCone,
    lattice: TransitionLattice,
    *,
    state: SecurityStateV1,
    horizons: Sequence[int] = HORIZONS,
) -> HazardReport:
    """DTL-F08 — compound the cone's branch mass out to each horizon.

    ``P(outcome within H) = 1 - (1 - rate)^H``: a constant per-event rate
    compounded over H relevant events. That is monotone non-decreasing in H by
    construction, which is the one property a horizon family must never violate —
    a hazard that falls as the window widens is a bug, not a finding.
    """
    if not horizons:
        raise ContractError("estimate_security_hazard needs at least one horizon")
    estimates: list[HazardEstimate] = []
    for outcome in OUTCOMES:
        rate, supporting = _per_event_rate(
            cone, lattice, state=state, dimension=OUTCOME_DIMENSIONS[outcome]
        )
        for horizon in horizons:
            if horizon < 1:
                raise ContractError(f"horizon must be >= 1, got {horizon}")
            estimates.append(
                HazardEstimate(
                    outcome=outcome,
                    horizon=horizon,
                    probability=1.0 - (1.0 - rate) ** horizon,
                    evidence_count=supporting,
                    calibration_id=None,
                )
            )
    return HazardReport(estimates=tuple(estimates))


def constant_hazard(
    counts: Mapping[tuple[str, int], tuple[int, int]],
) -> HazardReport:
    """THE SIMPLE CONTROL — empirical base rate per bucket. No state, no cone.

    ``counts`` maps ``(outcome, horizon)`` to ``(occurrences, opportunities)``.
    An empty bucket reports 0.0 with ``evidence_count == 0``, so a caller can
    tell "never observed" from "observed and never happened" instead of having
    both arrive as the same number.
    """
    estimates: list[HazardEstimate] = []
    for (outcome, horizon), (occurrences, opportunities) in sorted(counts.items()):
        if occurrences < 0 or opportunities < 0:
            raise ContractError("hazard counts cannot be negative")
        if occurrences > opportunities:
            raise ContractError(
                f"bucket ({outcome}, {horizon}) has {occurrences} occurrences in "
                f"{opportunities} opportunities"
            )
        estimates.append(
            HazardEstimate(
                outcome=outcome,
                horizon=horizon,
                probability=(occurrences / opportunities) if opportunities else 0.0,
                evidence_count=opportunities,
                calibration_id=None,
            )
        )
    return HazardReport(estimates=tuple(estimates))
