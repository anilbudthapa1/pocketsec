"""D3.4 (part) — Boundary Pressure: CRYSTAL's active falsification mechanism.

Architecture §11 asks for a search that *starts inside the validated region and
walks toward divergence*, one axis at a time. This module implements that
(:data:`PressureStrategy.GUIDED`) and, in the same file and on the same probe
budget, the naive control it has to beat (:data:`PressureStrategy.RANDOM_REPLAY`).

**This mechanism is built to be able to lose.** The architecture acceptance gate
says Boundary Pressure must find counterexamples that naive random replay misses
"in at least controlled test classes, or it is removed". So the comparison is a
first-class function, :func:`compare_strategies`, returning both reports and the
set difference between their counterexample classes. If that difference is
empty, the honest reading is that guided search buys nothing and D3.4's guided
half should be deleted — that is a result, not a bug.

The comparison is deliberately built so guided cannot win by construction:

- Both strategies perturb through the *same* pure function
  :func:`perturbed_frame`, so they explore an identical lattice of frames. The
  only difference is search (guided follows the oracle's divergence gradient)
  against sampling (random draws axes and depths uniformly).
- Both take the same budget *cap* and the same seed, and budget over-runs are
  reported in :attr:`BoundaryPressureReport.budget_exhausted` rather than
  concealed by quietly returning fewer probes. The cap is shared; the **spend**
  is not, and the two are not the same claim. Random replay always spends the
  whole cap, while the guided walk stops when it runs out of axes and depths
  (``7 x MAX_STEPS_PER_AXIS`` per seed), so a comparison must read
  :attr:`BoundaryPressureReport.probes_run` on both sides rather than calling
  the pair "equal-budget" and leaving the reader to assume equal spend.
- A random probe that moved several axes is credited with a counterexample class
  for *every* axis it moved. Attribution ambiguity is a real weakness of random
  replay, but resolving it against random would rig the comparison, so it is
  resolved in random's favour. An axis that was **drawn and skipped** gets
  nothing: crediting it invents a finding about a frame the axis never touched,
  and doing so is what produced G3.4's withdrawn "strict superset" result.

``false_inside`` and ``false_outside`` are counted separately (architecture §37
"boundary quality") because they are different security failures. Neither counts
a probe on which the oracle had no opinion — those are ``unmeasured_probes``.
Oracle A is an exact-digest snapshot of corpus frames, so every perturbed frame
misses it; folding ``TEACHER_UNAVAILABLE`` into ``false_inside`` reported
snapshot key misses as missed detections.
``false_inside`` is a frame the boundary claims to contain on which the oracle
diverges — the cell answers with the cheap path's authority and is wrong, which
is a missed detection. ``false_outside`` is a frame the boundary excludes on
which the oracle agrees — lost coverage, which costs compute and wakes the
learned path. Summing them into one "error rate" would hide the one that
matters.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from random import Random
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError, digest_of_bytes
from pocketsec.stage1.state.potential import phi
from pocketsec.stage1.state.security_state import Privilege
from pocketsec.stage3.boundary.index import BOUNDARY_PROPERTY_ORDER

if TYPE_CHECKING:  # pragma: no cover - imports exist only for annotations
    from pocketsec.stage3.bytecode.vm import CellFrame
    from pocketsec.stage3.cells.schema import KnowledgeCellV1
    from pocketsec.stage3.oracles.dual_oracle import DualOracleEvaluator, DualOracleVerdict

__all__ = [
    "AXIS_ORDER",
    "BoundaryPressureReport",
    "BoundaryProbe",
    "MAX_PRESSURE_BUDGET",
    "MAX_STEPS_PER_AXIS",
    "Perturbation",
    "PressureStrategy",
    "apply_boundary_pressure",
    "compare_strategies",
    "perturbed_frame",
    "random_replay_control",
]

#: Architecture §11's seven perturbation axes, verbatim and one member each.
class Perturbation(StrEnum):
    SEMANTIC_DIMENSION = "SEMANTIC_DIMENSION"
    TIMING = "TIMING"
    CAUSAL_PREDECESSOR = "CAUSAL_PREDECESSOR"
    EPOCH = "EPOCH"
    PRIVILEGE = "PRIVILEGE"
    ACTOR_SUBSTITUTION = "ACTOR_SUBSTITUTION"
    EVIDENCE_ABLATION = "EVIDENCE_ABLATION"


class PressureStrategy(StrEnum):
    GUIDED = "GUIDED"
    RANDOM_REPLAY = "RANDOM_REPLAY"


#: Walked in this fixed order so a guided run is reproducible from its seed.
AXIS_ORDER: tuple[Perturbation, ...] = tuple(Perturbation)

#: Depth cap on one axis. Both strategies see the same depths, so neither gets a
#: reachable region the other cannot enter.
MAX_STEPS_PER_AXIS = 8

MAX_PRESSURE_BUDGET = 4096

_PROPERTY_WIDTH = len(BOUNDARY_PROPERTY_ORDER)

#: ΔΦ increment per causal-predecessor step. A policy constant, not a measured
#: quantity: it sets how coarsely the search samples the causal axis.
_CAUSAL_PHI_STEP = 0.25

#: Divergence terms consulted for the dominant-term class label.
#: ``d_future_hazard`` is absent on purpose — ADR-0116 rejected future hazard on
#: measured calibration and the field is permanently ``None``.
_DIVERGENCE_TERMS: tuple[str, ...] = (
    "d_state_delta",
    "d_security_potential",
    "d_uncertainty",
    "d_evidence_requirement",
    "d_causal_attribution",
)


@dataclass(frozen=True, slots=True)
class BoundaryProbe:
    """One perturbed frame and how it was reached.

    ``seed_digest`` identifies the *origin* — the pressure seed, the strategy and
    which in-region frame the walk started from — so a divergence can be
    replayed without storing the whole walk.
    """

    frame: CellFrame
    perturbation: Perturbation
    steps_from_seed: int
    seed_digest: str


@dataclass(frozen=True, slots=True)
class BoundaryPressureReport:
    """What one pressure run found, and what it did not get to.

    ``probes_by_axis`` and ``divergences_by_axis`` are per-axis counts over the
    axes a probe **actually moved**, not the axes it drew. Without them the only
    denominator available to a per-axis metric was ``probes_run`` — the total
    over all seven axes — which is how ``_substitution_consistency`` came to
    divide actor-substitution divergences by every probe in the run.

    ``unmeasured_probes`` counts probes on which the oracle had no opinion: the
    frozen teacher snapshot is keyed on exact frame digests and every perturbed
    frame is by construction not a corpus frame, so a run can consist entirely
    of snapshot key misses. Those are **not** boundary-quality errors, and
    ``false_inside`` / ``false_outside`` / ``near_boundary_errors`` exclude them.
    """

    strategy: PressureStrategy
    seed: int
    probes_run: int
    budget: int
    budget_exhausted: bool
    divergences: tuple[BoundaryProbe, ...]
    counterexample_classes: frozenset[str]
    false_inside: int
    false_outside: int
    near_boundary_errors: int
    probes_by_axis: tuple[tuple[str, int], ...] = ()
    divergences_by_axis: tuple[tuple[str, int], ...] = ()
    unmeasured_probes: int = 0

    def probes_on(self, axis: Perturbation) -> int:
        """How many probes actually moved along ``axis``. Zero means unprobed."""
        return dict(self.probes_by_axis).get(str(axis), 0)

    def divergences_on(self, axis: Perturbation) -> int:
        """How many divergences are attributed to ``axis``."""
        return dict(self.divergences_by_axis).get(str(axis), 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": str(self.strategy),
            "seed": self.seed,
            "probes_run": self.probes_run,
            "budget": self.budget,
            "budget_exhausted": self.budget_exhausted,
            "divergence_count": len(self.divergences),
            "counterexample_classes": sorted(self.counterexample_classes),
            "false_inside": self.false_inside,
            "false_outside": self.false_outside,
            "near_boundary_errors": self.near_boundary_errors,
            "probes_by_axis": [list(item) for item in self.probes_by_axis],
            "divergences_by_axis": [list(item) for item in self.divergences_by_axis],
            "unmeasured_probes": self.unmeasured_probes,
        }


def _rotate_left(mask: int, amount: int, width: int) -> int:
    amount %= width
    limit = (1 << width) - 1
    mask &= limit
    return ((mask << amount) | (mask >> (width - amount))) & limit


def perturbed_frame(frame: CellFrame, axis: Perturbation, step: int) -> CellFrame | None:
    """Move ``frame`` ``step`` units along one axis — pure and deterministic.

    Purity is what makes the guided/random comparison meaningful: both
    strategies address the identical frame lattice, so any difference in what
    they find is a difference in search, not in reach. Nothing here consults a
    random source.

    Returns ``None`` when this frame cannot move along this axis at all, which
    today means only ``EVIDENCE_ABLATION`` on a frame holding a single
    ``EvidenceRef``. The caller skips the step; it must not treat the frame as
    unperturbed-and-therefore-robust.
    """
    if not 1 <= step <= MAX_STEPS_PER_AXIS:
        raise ContractError(f"perturbation step must be in 1..{MAX_STEPS_PER_AXIS}, got {step}")

    if axis is Perturbation.SEMANTIC_DIMENSION:
        return replace(frame, actor_properties=frame.actor_properties ^ ((1 << step) - 1))
    if axis is Perturbation.TIMING:
        counts = dict(frame.window_counts) or {0: 0}
        return replace(frame, window_counts={k: v + step for k, v in counts.items()})
    if axis is Perturbation.CAUSAL_PREDECESSOR:
        return replace(frame, delta_phi=frame.delta_phi + step * _CAUSAL_PHI_STEP)
    if axis is Perturbation.EPOCH:
        return replace(frame, epoch_id=frame.epoch_id + step)
    if axis is Perturbation.PRIVILEGE:
        level = Privilege(min(step, int(max(Privilege))))
        raised = frame.state.raised_to("privilege", level)
        # Φ is a function of the state, so a state move that left Φ behind would
        # hand the oracle an inconsistent frame and the divergence would be an
        # artefact of this module rather than of the cell.
        return replace(frame, state=raised, phi=phi(raised).total)
    if axis is Perturbation.ACTOR_SUBSTITUTION:
        # Rotation preserves popcount: a different actor with the same semantic
        # weight. §9 requires the outcome to be stable under this, so divergence
        # here means the cell learned an identity rather than a property.
        return replace(
            frame,
            actor_properties=_rotate_left(frame.actor_properties, step, _PROPERTY_WIDTH),
        )
    if axis is Perturbation.EVIDENCE_ABLATION:
        # Floor of one, not zero. ``CellFrame`` refuses an empty evidence tuple
        # outright — a frame with no lineage could not be audited back to bytes —
        # so ablating to zero raised ContractError mid-walk and took the whole
        # pressure run down with it. Any real corpus frame carrying a single
        # EvidenceRef hit this on the first EVIDENCE_ABLATION step.
        #
        # A frame that already holds one ref therefore cannot be perturbed along
        # this axis at all, and the walk is told so by returning ``None`` rather
        # than by handing back the unchanged frame: an unchanged frame would be
        # scored as "no divergence found", which reads as evidence that the cell
        # is robust to evidence loss when nothing was actually removed.
        keep = len(frame.evidence) - step
        if keep < 1:
            return None
        return replace(frame, evidence=frame.evidence[:keep])
    raise ContractError(f"unknown perturbation axis {axis!r}")


def _divergence_score(verdict: DualOracleVerdict) -> float | None:
    """The gradient the guided walk climbs; ``None`` when nothing measured it."""
    divergence = getattr(verdict, "divergence", None)
    if divergence is None:
        return None
    total = getattr(divergence, "total", None)
    return float(total) if isinstance(total, (int, float)) else None


def _counterexample_classes(
    axes: Sequence[Perturbation], verdict: DualOracleVerdict
) -> set[str]:
    """Classify a divergence by ``(axis, why)``, never by the raw frame.

    G3.4 compares *classes*, so two probes that break the same constraint on the
    same axis must count once. Keying on the frame would let a strategy win by
    generating more frames rather than by finding more kinds of failure.
    """
    reasons: list[str] = [
        str(getattr(violation, "kind", "UNKNOWN_CONSTRAINT"))
        for violation in getattr(verdict, "hard_violations", ())
    ]
    if not reasons:
        if not getattr(verdict, "teacher_available", False):
            reasons.append("TEACHER_UNAVAILABLE")
        else:
            reasons.append(f"DIVERGENCE:{_dominant_term(verdict)}")
    return {f"{axis}:{reason}" for axis in axes for reason in reasons}


def _dominant_term(verdict: DualOracleVerdict) -> str:
    divergence = getattr(verdict, "divergence", None)
    best_name = "UNATTRIBUTED"
    best_value: float | None = None
    for name in _DIVERGENCE_TERMS:
        value = getattr(divergence, name, None)
        if not isinstance(value, (int, float)):
            continue
        if best_value is None or value > best_value:
            best_name, best_value = name, float(value)
    return best_name


class _PressureTally:
    """Mutable accumulator, kept out of the frozen report until the run ends."""

    def __init__(self) -> None:
        self.probes_run = 0
        self.budget_exhausted = False
        self.divergences: list[BoundaryProbe] = []
        self.classes: set[str] = set()
        self.false_inside = 0
        self.false_outside = 0
        self.near_boundary_errors = 0
        self.unmeasured_probes = 0
        self.probes_by_axis: dict[str, int] = {}
        self.divergences_by_axis: dict[str, int] = {}

    def record(
        self,
        *,
        cell: KnowledgeCellV1,
        probe: BoundaryProbe,
        axes: Sequence[Perturbation],
        verdict: DualOracleVerdict,
    ) -> bool:
        """Fold one evaluated probe in; returns whether it diverged.

        ``axes`` must name the axes that actually **moved** this frame. A drawn
        but skipped axis is not an axis this probe explored, and crediting it
        with a counterexample class fabricates a finding about a frame the axis
        never touched.

        The boundary-quality counters (§37) are only advanced when the oracle
        had an opinion: a hard violation, or a teacher that answered. Oracle A is
        an exact-digest snapshot of corpus frames and every perturbed frame
        misses it, so counting ``TEACHER_UNAVAILABLE`` as ``false_inside`` would
        report a snapshot key miss as a missed detection and feed it, at weight
        0.25, into the melt decision.
        """
        self.probes_run += 1
        for axis in axes:
            name = str(axis)
            self.probes_by_axis[name] = self.probes_by_axis.get(name, 0) + 1
        passed = bool(getattr(verdict, "passed", False))
        measured = bool(getattr(verdict, "hard_violations", ())) or bool(
            getattr(verdict, "teacher_available", False)
        )
        if not passed and not measured:
            self.unmeasured_probes += 1
        distance = cell.boundary.distance(probe.frame)
        if measured or passed:
            if distance == 0 and not passed:
                self.false_inside += 1
            elif distance > 0 and passed:
                self.false_outside += 1
            if distance == 1 and not passed:
                self.near_boundary_errors += 1
        if not passed:
            self.divergences.append(probe)
            self.classes |= _counterexample_classes(axes, verdict)
            for axis in axes:
                name = str(axis)
                self.divergences_by_axis[name] = self.divergences_by_axis.get(name, 0) + 1
        return not passed

    def report(
        self, *, strategy: PressureStrategy, seed: int, budget: int
    ) -> BoundaryPressureReport:
        return BoundaryPressureReport(
            strategy=strategy,
            seed=seed,
            probes_run=self.probes_run,
            budget=budget,
            budget_exhausted=self.budget_exhausted,
            divergences=tuple(self.divergences),
            counterexample_classes=frozenset(self.classes),
            false_inside=self.false_inside,
            false_outside=self.false_outside,
            near_boundary_errors=self.near_boundary_errors,
            probes_by_axis=tuple(sorted(self.probes_by_axis.items())),
            divergences_by_axis=tuple(sorted(self.divergences_by_axis.items())),
            unmeasured_probes=self.unmeasured_probes,
        )


def _validate(budget: int, seeds: Sequence[CellFrame]) -> None:
    if not isinstance(budget, int) or isinstance(budget, bool) or budget < 1:
        raise ContractError(f"pressure budget must be an int >= 1, got {budget!r}")
    if budget > MAX_PRESSURE_BUDGET:
        raise ContractError(
            f"pressure budget {budget} exceeds MAX_PRESSURE_BUDGET {MAX_PRESSURE_BUDGET}"
        )
    if not seeds:
        raise ContractError(
            "boundary pressure needs at least one frame inside the validated region; "
            "fabricating a seed would start the search somewhere nothing validated"
        )


def _seed_digest(seed: int, strategy: PressureStrategy, index: int) -> str:
    return digest_of_bytes(f"{seed}|{strategy}|{index}".encode("utf-8"))


def apply_boundary_pressure(
    cell: KnowledgeCellV1,
    *,
    oracle: DualOracleEvaluator,
    budget: int,
    seed: int,
    strategy: PressureStrategy = PressureStrategy.GUIDED,
    seeds: Sequence[CellFrame] = (),
) -> BoundaryPressureReport:
    """Walk from inside the validated region toward divergence (§11).

    ``seeds`` are frames already known to be inside the region — this module
    will not invent one, because a fabricated start point would make every
    "divergence" a property of the fabrication. The parameter is additive to the
    signature in ``docs/stage-3-spec.md`` §D3.4, which named no source for the
    starting frame.

    With ``strategy=RANDOM_REPLAY`` this delegates to
    :func:`random_replay_control`, so a caller can run the control through the
    same entry point and cannot accidentally give it a different budget.
    """
    if strategy is PressureStrategy.RANDOM_REPLAY:
        return random_replay_control(cell, oracle=oracle, budget=budget, seed=seed, seeds=seeds)
    _validate(budget, seeds)

    tally = _PressureTally()
    for index, start in enumerate(seeds):
        digest = _seed_digest(seed, PressureStrategy.GUIDED, index)
        if _walk_axes(cell, oracle=oracle, budget=budget, start=start, digest=digest, tally=tally):
            tally.budget_exhausted = True
            break
    return tally.report(strategy=PressureStrategy.GUIDED, seed=seed, budget=budget)


def _walk_axes(
    cell: KnowledgeCellV1,
    *,
    oracle: DualOracleEvaluator,
    budget: int,
    start: CellFrame,
    digest: str,
    tally: _PressureTally,
) -> bool:
    """One guided walk from one seed frame; returns True if budget ran out.

    The gradient is followed *across* axes: whichever depth on this axis scored
    the highest divergence becomes the base for the next axis. That accumulation
    is the whole claim — it is what lets the walk reach conjunctive regions that
    a single uniform draw is unlikely to land in.
    """
    current, steps = start, 0
    for axis in AXIS_ORDER:
        best_frame: CellFrame | None = None
        best_score: float | None = None
        best_steps = 0
        for step in range(1, MAX_STEPS_PER_AXIS + 1):
            if tally.probes_run >= budget:
                return True
            candidate = perturbed_frame(current, axis, step)
            if candidate is None:
                continue
            verdict = oracle.evaluate(cell, (candidate,))
            probe = BoundaryProbe(candidate, axis, steps + step, digest)
            if tally.record(cell=cell, probe=probe, axes=(axis,), verdict=verdict):
                # The first divergence on an axis is the empirical boundary
                # point for it; walking deeper only re-finds the same failure.
                break
            score = _divergence_score(verdict)
            if score is None:
                # No gradient to climb, so the walk degrades to systematic
                # deepening. That is still a search, not a sample.
                if best_score is None:
                    best_frame, best_steps = candidate, step
            elif best_score is None or score > best_score:
                best_frame, best_score, best_steps = candidate, score, step
        if best_frame is not None:
            current, steps = best_frame, steps + best_steps
    return False


def random_replay_control(
    cell: KnowledgeCellV1,
    *,
    oracle: DualOracleEvaluator,
    budget: int,
    seed: int,
    seeds: Sequence[CellFrame] = (),
) -> BoundaryPressureReport:
    """The mandated naive control for G3.4 — same budget cap, same seed family.

    Draws a non-empty subset of axes and a uniform depth on each, from an
    unperturbed in-region frame. That reaches the same lattice
    :func:`apply_boundary_pressure` walks, so the two differ only in how they
    spend the budget.

    ``budget_exhausted`` is always ``True`` here by construction: uniform
    sampling never runs out of work, it only runs out of budget. Reporting it
    honestly matters more than making the field look discriminating.
    """
    _validate(budget, seeds)
    rng = Random(f"{seed}|{PressureStrategy.RANDOM_REPLAY}")
    tally = _PressureTally()
    while tally.probes_run < budget:
        index = rng.randrange(len(seeds))
        axes = tuple(axis for axis in AXIS_ORDER if rng.random() < 0.5) or (
            AXIS_ORDER[rng.randrange(len(AXIS_ORDER))],
        )
        candidate = seeds[index]
        total_steps = 0
        applied: list[Perturbation] = []
        for axis in axes:
            step = rng.randint(1, MAX_STEPS_PER_AXIS)
            moved = perturbed_frame(candidate, axis, step)
            if moved is None:
                # Drawn but unmovable — ``perturbed_frame`` returns ``None`` for
                # EVIDENCE_ABLATION on a frame holding a single ``EvidenceRef``,
                # which is every seed on the real corpus. The probe still costs
                # budget, so it is still evaluated, but it explored nothing on
                # this axis and must not be credited with a class for it.
                continue
            candidate = moved
            total_steps += step
            applied.append(axis)
        verdict = oracle.evaluate(cell, (candidate,))
        probe = BoundaryProbe(
            candidate,
            applied[-1] if applied else axes[-1],
            total_steps,
            _seed_digest(seed, PressureStrategy.RANDOM_REPLAY, index),
        )
        # Credited with a class for every axis it actually moved: attribution
        # ambiguity across several *applied* axes is random replay's real
        # weakness, and resolving that against random would win the G3.4
        # comparison by bookkeeping instead of by search. Crediting an axis it
        # never moved is a different thing — it is a fabricated finding, and it
        # was the whole measured basis for G3.4's "strict superset" (see
        # ADR-0026's correction).
        tally.record(cell=cell, probe=probe, axes=tuple(applied), verdict=verdict)
    tally.budget_exhausted = True
    return tally.report(strategy=PressureStrategy.RANDOM_REPLAY, seed=seed, budget=budget)


def compare_strategies(
    cell: KnowledgeCellV1,
    *,
    oracle: DualOracleEvaluator,
    budget: int,
    seed: int,
    seeds: Sequence[CellFrame] = (),
) -> tuple[BoundaryPressureReport, BoundaryPressureReport, frozenset[str]]:
    """Run both strategies at one budget and return ``(guided, random, gained)``.

    ``gained`` is ``guided.counterexample_classes - random.counterexample_classes``
    — the one number gate criterion G3.4 and ADR-0026 turn on. An empty set is
    the measured verdict that guided search adds nothing at this budget, and the
    architecture gate's own wording is then binding: *or it is removed*.

    The two reports carry their own ``probes_run``, and they differ: read both
    before describing the pair as equally budgeted.
    """
    guided = apply_boundary_pressure(
        cell,
        oracle=oracle,
        budget=budget,
        seed=seed,
        strategy=PressureStrategy.GUIDED,
        seeds=seeds,
    )
    control = random_replay_control(cell, oracle=oracle, budget=budget, seed=seed, seeds=seeds)
    return guided, control, guided.counterexample_classes - control.counterexample_classes
