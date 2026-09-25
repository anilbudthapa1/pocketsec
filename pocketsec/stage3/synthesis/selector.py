"""D3.7 (part) — measure every synthesised operator, then choose the cheapest.

§13 says CRYSTAL takes "the cheapest candidate satisfying the constraints". Two
words in that sentence carry the whole module.

**"Satisfying" is checked first.** :func:`select_operator_form` discards every
candidate carrying a hard security violation *before* it looks at cost. Cost is
never allowed to argue with a violated invariant, so the ordering is structural
rather than a convention a later edit could reverse.

**"Cheapest" requires a measurement.** A candidate whose
``microseconds_per_event`` is ``None`` is never selected. ``None`` means
UNMEASURED, and UNMEASURED is not cheap — treating it as zero would make the
unmeasured candidate win every comparison, which is precisely the failure mode
this repository rejected its own Stage 2 core to avoid.

**On timing, and why every candidate carries a load average.** This host is
contended: a Stage 2 gate run measured a 7× inflation at load 23–67 versus load
8–12. An absolute microsecond figure produced here is therefore *not* a device
measurement and must never be reported as one. :func:`measure_candidate` takes
the **minimum** of repeated runs (the minimum is the least contaminated sample,
not the average) and records ``os.getloadavg()[0]`` alongside it, so a reader
can see the conditions. Only **within-run ratios** between two candidates timed
in the same run transfer to any other machine.
"""

from __future__ import annotations

import os
import time
from collections.abc import Sequence
from dataclasses import dataclass

from pocketsec.stage3.bytecode.vm import (
    REASON_NOT_EXECUTABLE_FORM,
    REASON_UNVERIFIED_PREFIX,
    CellVM,
)
from pocketsec.stage3.cells.frame import CellFrame
from pocketsec.stage3.cells.operator import OperatorProgram
from pocketsec.stage3.cells.schema import HardConstraint
from pocketsec.stage3.oracles.dual_oracle import DualOracleVerdict

__all__ = [
    "DEFAULT_REPETITIONS",
    "OperatorCandidate",
    "admissible_candidates",
    "measure_candidate",
    "pareto_frontier",
    "select_operator_form",
]

#: Odd, and small enough that measurement does not dominate synthesis.
DEFAULT_REPETITIONS = 7


@dataclass(frozen=True, slots=True)
class OperatorCandidate:
    """One synthesised program with everything needed to judge it.

    ``loadavg_at_measurement`` is a field and not a log line because the number
    it qualifies is meaningless without it.
    """

    program: OperatorProgram
    microseconds_per_event: float | None
    bytes_resident: int
    equivalence: DualOracleVerdict
    loadavg_at_measurement: float

    @property
    def measured(self) -> bool:
        return self.microseconds_per_event is not None

    @property
    def admissible(self) -> bool:
        """No hard violation. Cost is not consulted here, on purpose."""
        return not self.equivalence.hard_violations


def measure_candidate(
    program: OperatorProgram,
    frames: Sequence[CellFrame],
    *,
    equivalence: DualOracleVerdict,
    repetitions: int = DEFAULT_REPETITIONS,
    vm: CellVM | None = None,
) -> OperatorCandidate:
    """Time ``program`` over ``frames``; minimum of ``repetitions`` passes.

    Returns ``microseconds_per_event=None`` in two cases, both of which mean
    UNMEASURED rather than fast:

    * there are no frames, so nothing was timed; and
    * the VM refuses the program's form. ``CellVM`` executes ``BYTECODE`` and
      abstains on every other form (``REASON_NOT_EXECUTABLE_FORM``), so timing
      a lookup table through it measures the cost of a refusal, not of a table.
      Reporting that number as the operator's cost would hand the selector a
      cheap candidate that never answers, which is exactly the failure the
      "UNMEASURED is not cheap" rule exists to prevent.
    """
    if repetitions < 1:
        raise ValueError("repetitions must be >= 1")
    runner = vm if vm is not None else CellVM()
    resident = program.size_bytes()
    loadavg = os.getloadavg()[0]
    if not frames or not _is_executable(runner, program, frames[0]):
        return OperatorCandidate(
            program=program,
            microseconds_per_event=None,
            bytes_resident=resident,
            equivalence=equivalence,
            loadavg_at_measurement=loadavg,
        )
    best = _fastest_pass(runner, program, frames, repetitions)
    return OperatorCandidate(
        program=program,
        microseconds_per_event=(best / len(frames)) * 1e6,
        bytes_resident=resident,
        equivalence=equivalence,
        # Averaged across the measurement window rather than sampled once,
        # because a run that starts quiet and ends contended is neither.
        loadavg_at_measurement=(loadavg + os.getloadavg()[0]) / 2.0,
    )


def _is_executable(runner: CellVM, program: OperatorProgram, frame: CellFrame) -> bool:
    """Whether the VM will actually run this program, rather than refuse it."""
    probe = runner.run(program, frame)
    if not probe.abstained:
        return True
    return not (
        probe.reason == REASON_NOT_EXECUTABLE_FORM
        or probe.reason.startswith(REASON_UNVERIFIED_PREFIX)
    )


def _fastest_pass(
    runner: CellVM, program: OperatorProgram, frames: Sequence[CellFrame], repetitions: int
) -> float:
    """Minimum wall-clock over ``repetitions`` full passes.

    The minimum, not the mean: on a contended host the mean measures the other
    processes, while the minimum is the least contaminated sample available.
    """
    best = float("inf")
    for _ in range(repetitions):
        start = time.perf_counter()
        for frame in frames:
            runner.run(program, frame)
        best = min(best, time.perf_counter() - start)
    return best


def admissible_candidates(
    candidates: Sequence[OperatorCandidate], *, constraints: Sequence[HardConstraint]
) -> tuple[OperatorCandidate, ...]:
    """Candidates carrying no hard violation, declared in ``constraints`` or not.

    An *undeclared* violation is still disqualifying, so the filter is on the
    violations the oracle found rather than on the ids the cell remembered to
    name; a cell cannot escape a constraint by forgetting to declare it.

    Divergence is deliberately **not** a filter here. A candidate whose
    divergence exceeds its envelope is refinable — that is what the CRYSTAL
    pressure loop is for — while a hard violation is not. Collapsing the two
    would report every "needs another refinement" as a security violation.

    ``constraints`` is part of the D3.7 signature and is not read: the dual
    oracle has already checked the cell's constraint set and reported what it
    violated, and re-deriving admissibility from the declared ids here would
    give the same question two answers.
    """
    return tuple(c for c in candidates if not c.equivalence.hard_violations)


def select_operator_form(
    candidates: Sequence[OperatorCandidate], *, constraints: Sequence[HardConstraint]
) -> OperatorCandidate | None:
    """Cheapest admissible, measured candidate; ``None`` when there is none.

    Order of operations is the contract: violations, then measurement, then
    cost. Ties on microseconds break on resident bytes, then on the program
    digest so the choice is reproducible across runs.
    """
    admissible = admissible_candidates(candidates, constraints=constraints)
    measured = [c for c in admissible if c.microseconds_per_event is not None]
    if not measured:
        return None
    return min(
        measured,
        key=lambda c: (c.microseconds_per_event, c.bytes_resident, c.program.digest),
    )


def pareto_frontier(
    candidates: Sequence[OperatorCandidate],
) -> tuple[OperatorCandidate, ...]:
    """Non-dominated candidates on (µs/event, resident bytes) — the D3.7 report.

    Unmeasured and violating candidates are excluded rather than plotted at the
    origin, which is where an unmeasured cost would otherwise appear.
    """
    pool = [c for c in candidates if c.measured and c.admissible]
    frontier: list[OperatorCandidate] = []
    for candidate in pool:
        cost = candidate.microseconds_per_event
        assert cost is not None
        dominated = any(
            other is not candidate
            and (other.microseconds_per_event or 0.0) <= cost
            and other.bytes_resident <= candidate.bytes_resident
            and (
                (other.microseconds_per_event or 0.0) < cost
                or other.bytes_resident < candidate.bytes_resident
            )
            for other in pool
        )
        if not dominated:
            frontier.append(candidate)
    return tuple(sorted(frontier, key=lambda c: (c.microseconds_per_event, c.bytes_resident)))
