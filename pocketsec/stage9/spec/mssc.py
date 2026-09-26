"""D9.1: the Minimum Sufficient Security Computation (MSSC) objective, bound to code.

The architecture (§0) states MSSC as ``argmin DescriptionLength + RuntimeCost +
UnexplainedSecurityEvidence`` subject to seven constraints. Written that way it is a
weighted sum with unstated weights, and a weighted sum lets a search trade detection
quality for cost at an exchange rate nobody chose. This module exists to replace the
prose with something that cannot be traded silently:

* **Cost is an objective, never a tiebreak.** :class:`ObjectiveVector` holds the three
  axes a candidate is judged on: held-out worst-case AP (up), static work units per
  event (down) and static session state bytes (down). :func:`dominates` and
  :func:`pareto_front` are the only selection rules. Description length is carried and
  reported but is deliberately **not** a dominance axis: it depends on an encoding this
  stage chose, and letting it vote would make the result depend on that choice.
* **Unmeasured is not measured.** An AP of ``None`` never dominates and never sits on a
  front. Calibration (``k_min``) has no calibrator anywhere in the repository, so
  :func:`check_constraints` lists ``"calibration"`` as unmeasured on every call and can
  therefore never report the MSSC constraints as *satisfied*, only as not violated.
* **"Beats" has one definition.** :func:`beats` implements the Phase 9 gate's wording
  literally: better on one meaningful Pareto dimension, no hard requirement violated,
  and not dominated by the baseline.
* **Every ablation verdict has one record shape.** :class:`DetectorComparison` is what
  every ``compare_*`` function in Stage 9 returns and what gate G9.9 reads. It carries a
  firing count, and it refuses a ``JUSTIFIED`` verdict for a mechanism that never
  changed an outcome (Stages 4-6 each shipped a mechanism that fired zero times).

What this module refuses to do: it decides nothing about any particular genome, it holds
no state, and it carries no authority. It is arithmetic over numbers other modules
measured.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from pocketsec.stage0.contracts.common import ContractError

__all__ = [
    "DEFAULT_CONSTRAINTS",
    "MSSC_STATEMENT",
    "BeatVerdict",
    "DetectorComparison",
    "MSSCConstraints",
    "MSSCVerdict",
    "MechanismVerdict",
    "ObjectiveVector",
    "beats",
    "check_constraints",
    "dominates",
    "hypervolume_2d",
    "pareto_front",
]

#: Architecture §0 restated with the bindings of spec §3.4. It is text for the report,
#: not configuration: nothing reads it to decide anything.
MSSC_STATEMENT: str = (
    "Minimum Sufficient Security Computation (Stage 9, bound form). Among typed "
    "computational genomes (ComputationalGenomeV1), report the Pareto front of "
    "(held-out worst-case AP over the ARGUS scenario attacks: maximise; static update "
    "work units per event: minimise; static session state bytes: minimise). "
    "Description length is reported, never a dominance axis, and no weighted sum is "
    "formed. A candidate is admissible when: DetectionQuality - held-out worst-case AP "
    ">= base rate + q_min_margin; Robustness - worst-case AP / clean AP >= r_min; "
    "Calibration - UNMEASURED (k_min is None; scores are rankings and no calibrator "
    "exists), never reported as met; Privacy - inputs are EncodedTransition fields only, "
    "identity unreachable by construction (ADR-0007); RAM - session_state_bytes_max <= "
    "ram_bytes_max; CPU - update_wu_per_event <= wu_per_event_max; SafetyInvariants - "
    "IR validation passes, the computation contract holds and the Stage 9 import "
    "boundary holds. The output is a candidate, never a deployed component."
)

def _finite(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError(f"{field} must be a number, got {type(value).__name__}")
    number = float(value)
    if not math.isfinite(number):
        raise ContractError(f"{field} must be finite, got {value!r}")
    return number


def _unit(value: object, field: str) -> float:
    number = _finite(value, field)
    if not 0.0 <= number <= 1.0:
        raise ContractError(f"{field} must lie in [0, 1], got {value!r}")
    return number


def _count(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContractError(f"{field} must be a non-negative int, got {value!r}")
    return value


@dataclass(frozen=True, slots=True)
class MSSCConstraints:
    """The MSSC constraint set. Every value is *chosen* (spec §4.21), not measured."""

    #: Held-out worst-case AP must reach base rate + this margin.
    q_min_margin: float = 0.05
    #: Worst-case AP / clean AP must reach this ratio.
    r_min: float = 0.85
    #: Calibration floor. ``None`` means UNMEASURED; it is never satisfied silently.
    k_min: float | None = None
    #: Per-session phenotype state ceiling, bytes.
    ram_bytes_max: int = 65536
    #: Static update work units per event ceiling.
    wu_per_event_max: int = 64

    def __post_init__(self) -> None:
        _unit(self.q_min_margin, "q_min_margin")
        _unit(self.r_min, "r_min")
        if self.k_min is not None:
            _unit(self.k_min, "k_min")
        if _count(self.ram_bytes_max, "ram_bytes_max") == 0:
            raise ContractError("ram_bytes_max must be positive")
        if _count(self.wu_per_event_max, "wu_per_event_max") == 0:
            raise ContractError("wu_per_event_max must be positive")


DEFAULT_CONSTRAINTS = MSSCConstraints()


@dataclass(frozen=True, slots=True)
class ObjectiveVector:
    """One candidate's position in objective space.

    ``worst_case_ap`` is ``None`` when it was not measured; such a vector never
    dominates, is never dominated and is never placed on a Pareto front.
    """

    worst_case_ap: float | None
    wu_per_event: int
    #: ``StaticBounds.session_state_bytes_max`` of the genome: a bound, not a sample.
    state_bytes: int
    #: Reported, NOT a dominance axis (see the module docstring).
    description_length_bits: float

    def __post_init__(self) -> None:
        if self.worst_case_ap is not None:
            _unit(self.worst_case_ap, "worst_case_ap")
        _count(self.wu_per_event, "wu_per_event")
        _count(self.state_bytes, "state_bytes")
        if _finite(self.description_length_bits, "description_length_bits") < 0.0:
            raise ContractError("description_length_bits must be non-negative")

    @property
    def measured(self) -> bool:
        return self.worst_case_ap is not None


def dominates(a: ObjectiveVector, b: ObjectiveVector) -> bool:
    """``a`` is at least as good as ``b`` on all three axes and strictly better on one.

    The axes are worst-case AP (higher is better), WU/event and state bytes (lower is
    better). Description length does not vote. If either AP is ``None`` the answer is
    ``False``: an unmeasured quality cannot be compared, in either direction.
    """
    if a.worst_case_ap is None or b.worst_case_ap is None:
        return False
    no_worse = (
        a.worst_case_ap >= b.worst_case_ap
        and a.wu_per_event <= b.wu_per_event
        and a.state_bytes <= b.state_bytes
    )
    strictly_better = (
        a.worst_case_ap > b.worst_case_ap
        or a.wu_per_event < b.wu_per_event
        or a.state_bytes < b.state_bytes
    )
    return no_worse and strictly_better


def pareto_front(points: Sequence[tuple[str, ObjectiveVector]]) -> tuple[str, ...]:
    """Names of the non-dominated, measured points, in input order.

    Points with an unmeasured AP are left out: they are not "undominated", they are
    unplaced, and the caller reports them separately. Duplicate vectors are all kept,
    since neither dominates the other. Stable order means the same input always yields
    the same output, so a report built from it is reproducible.
    """
    names = [name for name, _ in points]
    if len(set(names)) != len(names):
        raise ContractError("pareto_front needs distinct point names")
    measured = [(name, vector) for name, vector in points if vector.measured]
    return tuple(
        name
        for name, vector in measured
        if not any(dominates(other, vector) for _, other in measured)
    )


def hypervolume_2d(
    points: Sequence[ObjectiveVector], *, ap_ref: float, wu_ref: int
) -> float:
    """Exact 2-D hypervolume over (AP above ``ap_ref``, ``wu_ref`` minus WU/event).

    Each measured point with ``ap > ap_ref`` and ``wu < wu_ref`` covers the rectangle
    ``[0, wu_ref - wu] x [0, ap - ap_ref]``; the result is the area of their union,
    computed by one sweep in descending WU gain. Points with ``None`` AP are ignored.
    State bytes are not an axis here: this is the 2-D summary the report plots.
    """
    reference_ap = _unit(ap_ref, "ap_ref")
    _count(wu_ref, "wu_ref")
    boxes = sorted(
        (
            (float(wu_ref - vector.wu_per_event), vector.worst_case_ap - reference_ap)
            for vector in points
            if vector.worst_case_ap is not None
            and vector.worst_case_ap > reference_ap
            and vector.wu_per_event < wu_ref
        ),
        reverse=True,
    )
    area = 0.0
    best_height = 0.0
    for position, (width, height) in enumerate(boxes):
        best_height = max(best_height, height)
        next_width = boxes[position + 1][0] if position + 1 < len(boxes) else 0.0
        area += (width - next_width) * best_height
    return area


@dataclass(frozen=True, slots=True)
class MSSCVerdict:
    """The constraint check. ``satisfied`` is ``None`` whenever anything is unmeasured
    and nothing is violated; because calibration is always unmeasured, it is never
    ``True`` in this stage."""

    satisfied: bool | None
    violations: tuple[str, ...]
    unmeasured: tuple[str, ...]


def _quality(
    vector: ObjectiveVector, base_rate: float, constraints: MSSCConstraints
) -> str | None:
    """``"violated"``, ``"unmeasured"`` or ``None`` (met) for DetectionQuality."""
    if vector.worst_case_ap is None:
        return "unmeasured"
    if vector.worst_case_ap < base_rate + constraints.q_min_margin:
        return "violated"
    return None


def _robustness(
    vector: ObjectiveVector, clean_ap: float | None, constraints: MSSCConstraints
) -> str | None:
    if vector.worst_case_ap is None or clean_ap is None or clean_ap == 0.0:
        # A zero clean AP makes the ratio undefined; that is unmeasured, not met.
        return "unmeasured"
    if vector.worst_case_ap / clean_ap < constraints.r_min:
        return "violated"
    return None


def check_constraints(
    vector: ObjectiveVector,
    *,
    clean_ap: float | None,
    base_rate: float,
    constraints: MSSCConstraints = DEFAULT_CONSTRAINTS,
) -> MSSCVerdict:
    """Check one objective vector against the MSSC constraints.

    Violation and unmeasured names are ``detection_quality``, ``robustness``,
    ``calibration``, ``ram_bytes`` and ``wu_per_event``. Privacy and the safety
    invariants are properties of the representation and the boundary, proven
    elsewhere, so they are not re-litigated per vector.
    """
    rate = _unit(base_rate, "base_rate")
    if clean_ap is not None:
        _unit(clean_ap, "clean_ap")
    violations: list[str] = []
    unmeasured: list[str] = []
    for name, outcome in (
        ("detection_quality", _quality(vector, rate, constraints)),
        ("robustness", _robustness(vector, clean_ap, constraints)),
    ):
        if outcome == "violated":
            violations.append(name)
        elif outcome == "unmeasured":
            unmeasured.append(name)
    # No calibrator exists (spec §3.4). Even a caller-supplied k_min has nothing to be
    # compared against, so calibration is unmeasured on every call, not only when None.
    unmeasured.append("calibration")
    if vector.state_bytes > constraints.ram_bytes_max:
        violations.append("ram_bytes")
    if vector.wu_per_event > constraints.wu_per_event_max:
        violations.append("wu_per_event")
    satisfied: bool | None = False if violations else (None if unmeasured else True)
    return MSSCVerdict(satisfied, tuple(violations), tuple(unmeasured))


@dataclass(frozen=True, slots=True)
class BeatVerdict:
    beats: bool
    #: ``"worst_case_ap"`` | ``"wu_per_event"`` | ``"state_bytes"`` when ``beats``.
    dimension: str | None
    detail: str


def _better_dimension(
    candidate: ObjectiveVector,
    baseline: ObjectiveVector,
    ap_margin: float,
    cost_margin: float,
) -> str | None:
    """The first meaningful dimension on which the candidate is better, if any."""
    mine_ap, theirs_ap = candidate.worst_case_ap, baseline.worst_case_ap
    if mine_ap is not None and theirs_ap is not None and mine_ap >= theirs_ap + ap_margin:
        return "worst_case_ap"
    for axis in ("wu_per_event", "state_bytes"):
        mine, theirs = getattr(candidate, axis), getattr(baseline, axis)
        # Strictly lower AND at least cost_margin lower: equal zero costs are not a win.
        if mine < theirs and mine <= theirs * (1.0 - cost_margin):
            return axis
    return None


def beats(
    candidate: ObjectiveVector,
    baseline: ObjectiveVector,
    *,
    candidate_ok: bool,
    ap_margin: float = 0.02,
    cost_margin: float = 0.10,
) -> BeatVerdict:
    """Phase 9 criterion 1, literally.

    ``True`` iff the candidate (a) is better on one meaningful Pareto dimension - AP at
    least ``ap_margin`` higher, or WU/event or state bytes at least ``cost_margin``
    lower - (b) violates no hard requirement (``candidate_ok``: its ``MSSCVerdict``
    has no violations) and (c) is not dominated by the baseline. An unmeasured AP on
    either side is never a win: a cost saving of unknown quality proves nothing.
    """
    _unit(ap_margin, "ap_margin")
    _unit(cost_margin, "cost_margin")
    if not candidate_ok:
        return BeatVerdict(False, None, "candidate violates a hard MSSC requirement")
    if candidate.worst_case_ap is None or baseline.worst_case_ap is None:
        return BeatVerdict(False, None, "worst-case AP unmeasured on one side: no comparison")
    if dominates(baseline, candidate):
        return BeatVerdict(False, None, "candidate is dominated by the baseline")
    dimension = _better_dimension(candidate, baseline, ap_margin, cost_margin)
    if dimension is None:
        return BeatVerdict(
            False,
            None,
            f"not better on any axis by the margins (AP +{ap_margin}, cost -{cost_margin:.0%})",
        )
    mine, theirs = getattr(candidate, dimension), getattr(baseline, dimension)
    return BeatVerdict(True, dimension, f"{dimension}: {mine} vs baseline {theirs}")


class MechanismVerdict(StrEnum):
    JUSTIFIED = "JUSTIFIED"
    NOT_YET_JUSTIFIED = "NOT_YET_JUSTIFIED"
    REJECTED = "REJECTED"
    UNMEASURED = "UNMEASURED"


@dataclass(frozen=True, slots=True)
class DetectorComparison:
    """The one verdict record every Stage 9 ``compare_*`` returns (gate G9.9 reads it).

    ``fired`` counts how many times the mechanism changed an outcome; ``0`` means the
    mechanism is INERT, and an inert mechanism cannot be ``JUSTIFIED``: whatever the
    metric said, the mechanism was not what produced it.
    """

    #: The ablation flag it decides, as ``"module:CONSTANT"``.
    mechanism: str
    metric: str
    value: float | None
    controls: tuple[tuple[str, float | None], ...]
    verdict: MechanismVerdict
    fired: int
    detail: str

    def __post_init__(self) -> None:
        if not isinstance(self.mechanism, str) or ":" not in self.mechanism:
            raise ContractError(f"mechanism must be 'module:CONSTANT', got {self.mechanism!r}")
        if not isinstance(self.metric, str) or not self.metric.strip():
            raise ContractError("metric must be named")
        if self.value is not None:
            _finite(self.value, "value")
        if not isinstance(self.controls, tuple):
            raise ContractError("controls must be a tuple of (name, value) pairs")
        for pair in self.controls:
            if not isinstance(pair, tuple) or len(pair) != 2 or not isinstance(pair[0], str):
                raise ContractError(f"a control must be a (name, value) pair, got {pair!r}")
            if pair[1] is not None:
                _finite(pair[1], f"control {pair[0]!r}")
        if not isinstance(self.verdict, MechanismVerdict):
            raise ContractError("verdict must be a MechanismVerdict")
        _count(self.fired, "fired")
        if self.verdict is MechanismVerdict.JUSTIFIED and self.fired == 0:
            raise ContractError(
                f"{self.mechanism} never changed an outcome (fired=0) and cannot be JUSTIFIED"
            )

    @property
    def inert(self) -> bool:
        return self.fired == 0
