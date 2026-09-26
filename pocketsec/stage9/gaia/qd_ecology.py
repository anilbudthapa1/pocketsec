"""D9.13 — GAIA: a bounded quality-diversity archive, fossils, symbiosis and parasites.

Architecture §34-§35 asks for MAP-Elites: keep the best genome *per behaviour cell*
instead of one global best, so cheap and expensive computations are both kept and the
cheap ones are not crowded out while their quality is still low. §34 also says MAP-Elites
is the baseline a custom ecology must beat, and §68 says QD is rejected if one
architecture dominates every niche. This module therefore holds both arms of that test:

* :class:`QualityDiversityArchive` with ``niches=True`` bins each genome by static cost
  (work units per event, session state bytes), statefulness and size — 7 x 6 x 2 x 6 =
  **504 cells at most**, overflow bins included. With ``niches=False`` (the shipped
  default, :data:`QD_ARCHIVE_DEFAULT_ENABLED`) it is a **single-cell elitist archive**:
  the plain elitist GA the niches must beat.
* :func:`compare_qd` decides that flag on held-out data, and
  :func:`single_architecture_dominance` measures the §68 falsifier.

Within one cell, quality is worst-case train AP; an exact tie is broken only by Pareto
dominance on cost (``spec.mssc.dominates``), never by a weighted sum.

What this module refuses to do:

* It never grows past its cell bound: occupancy is a property of the binning, and
  :func:`hypothesis_explosion` floods an archive with ten times its bound to prove it.
* :class:`FossilStore` never grows past :data:`MAX_FOSSILS`; the oldest fossil is evicted
  and **counted**, and every skipped re-proposal is counted in ``avoided``.
* An unmeasured fitness (``worst_case_ap is None``) never becomes an elite.
* Nothing here writes trusted state or reaches Stage 5: an elite is a candidate.
"""

from __future__ import annotations

import hashlib
import random
import statistics
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING

from pocketsec.stage0.benchmark.security_metrics import average_precision
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage9.argus.adversary import ArgusFinding, ArgusSurface
from pocketsec.stage9.chemistry.typed_ir import NodeKind
from pocketsec.stage9.genesis.variation import ablate_node, node_total, random_genome
from pocketsec.stage9.genome.computational import ComputationalGenomeV1
from pocketsec.stage9.ontogenesis.fitness import EvaluationSuite, FitnessRecord, evaluate
from pocketsec.stage9.spec.mssc import (
    DetectorComparison,
    MechanismVerdict,
    dominates,
    pareto_front,
)

if TYPE_CHECKING:  # pragma: no cover - search imports this module; typing only
    from pocketsec.stage9.ontogenesis.search import SearchRun, WinnerReport

__all__ = [
    "BYTES_BINS",
    "CELL_COUNT",
    "DOMINANCE_FALSIFIER_SHARE",
    "FOSSIL_AVOIDANCE_DEFAULT_ENABLED",
    "MAX_FOSSILS",
    "MAX_LINEAGE_RECORDED",
    "QD_ARCHIVE_DEFAULT_ENABLED",
    "QD_MARGIN",
    "SIZE_BINS",
    "WU_BINS",
    "ArchiveOutcome",
    "ComputationalFossil",
    "DominanceReport",
    "Elite",
    "FossilReason",
    "FossilStore",
    "NicheKey",
    "QualityDiversityArchive",
    "compare_arm",
    "compare_qd",
    "dominance_of",
    "hypothesis_explosion",
    "is_stateful",
    "niche_of",
    "parasites",
    "single_architecture_dominance",
    "synergy",
]

#: Bin upper edges; a value above the last edge falls in one overflow bin.
WU_BINS: tuple[int, ...] = (2, 4, 8, 16, 32, 64)
BYTES_BINS: tuple[int, ...] = (256, 1024, 4096, 16384, 65536)
SIZE_BINS: tuple[int, ...] = (3, 6, 12, 24, 64)
#: 7 x 6 x 2 x 6 = 504: the hard occupancy bound of a niched archive.
CELL_COUNT: int = (len(WU_BINS) + 1) * (len(BYTES_BINS) + 1) * 2 * (len(SIZE_BINS) + 1)

#: Off until :func:`compare_qd` returns JUSTIFIED and the integrator flips it (G9.9).
QD_ARCHIVE_DEFAULT_ENABLED: bool = False
#: Off until the search's fossil arm is JUSTIFIED (``ontogenesis.search.compare_arm``).
FOSSIL_AVOIDANCE_DEFAULT_ENABLED: bool = False

MAX_FOSSILS: int = 2048
MAX_LINEAGE_RECORDED: int = 16
#: Verdict margin on held-out worst-case AP (spec §4.21). Chosen, not measured.
QD_MARGIN: float = 0.02
#: §68 falsifier: one elite dominating this share of occupied cells. Chosen, not measured.
DOMINANCE_FALSIFIER_SHARE: float = 0.90
_AP_TIE: float = 1e-12
_EXPLOSION_SEED: int = 68  # architecture §68, for a memorable fixed seed
_EXPLOSION_MULTIPLIER: int = 10
_MECHANISM = "pocketsec.stage9.gaia.qd_ecology:QD_ARCHIVE_DEFAULT_ENABLED"
#: The three optional ecology flags a seed-matched ablation arm can switch on.
_ARM_FLAGS: dict[str, str] = {
    "subtractive": "pocketsec.stage9.ontogenesis.search:SUBTRACTIVE_BIAS_DEFAULT_ENABLED",
    "fossil_avoidance": "pocketsec.stage9.gaia.qd_ecology:FOSSIL_AVOIDANCE_DEFAULT_ENABLED",
    "niches": _MECHANISM,
}
#: Arm verdict margins (spec §4.9 / §4.21): AP within 0.01 at >= 10% lower cost. Chosen.
_ARM_AP_TOLERANCE: float = 0.01
_ARM_COST_SHARE: float = 0.10


def _bin(value: int, edges: Sequence[int]) -> int:
    for position, edge in enumerate(edges):
        if value <= edge:
            return position
    return len(edges)


@dataclass(frozen=True, slots=True)
class NicheKey:
    """One behaviour cell. Every coordinate is a static property of the genome."""

    wu_bin: int
    bytes_bin: int
    stateful: bool
    size_bin: int

    def __post_init__(self) -> None:
        limits = (
            (self.wu_bin, len(WU_BINS)),
            (self.bytes_bin, len(BYTES_BINS)),
            (self.size_bin, len(SIZE_BINS)),
        )
        for value, top in limits:
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= top:
                raise ContractError(f"NicheKey bin {value!r} outside [0, {top}]")


_SINGLE_CELL = NicheKey(wu_bin=0, bytes_bin=0, stateful=False, size_bin=0)


def is_stateful(genome: ComputationalGenomeV1) -> bool:
    """The update reads a register and writes it back through a non-identity APPLY."""
    nodes = genome.update.nodes
    for register, out in enumerate(genome.update.outputs):
        if nodes[out].kind is not NodeKind.APPLY:
            continue
        stack, seen = [out], set()
        while stack:
            index = stack.pop()
            if index in seen:
                continue
            seen.add(index)
            node = nodes[index]
            if node.kind is NodeKind.REG and node.index == register:
                return True
            stack.extend(node.args)
    return False


def niche_of(genome: ComputationalGenomeV1) -> NicheKey:
    bounds = genome.bounds
    size = len(genome.update.nodes) + len(genome.readout.nodes)
    return NicheKey(
        wu_bin=_bin(bounds.update_wu_per_event, WU_BINS),
        bytes_bin=_bin(bounds.session_state_bytes_max, BYTES_BINS),
        stateful=is_stateful(genome),
        size_bin=_bin(size, SIZE_BINS),
    )


@dataclass(frozen=True, slots=True)
class Elite:
    """Architecture §35's cell content: organism, fitness, lineage and ARGUS record."""

    genome: ComputationalGenomeV1
    fitness: FitnessRecord
    niche: NicheKey
    lineage: tuple[str, ...]
    argus_failures_survived: int
    inserted_at: int


class ArchiveOutcome(StrEnum):
    NEW_CELL = "NEW_CELL"
    IMPROVED = "IMPROVED"
    REJECTED_WORSE = "REJECTED_WORSE"
    REJECTED_FOSSIL = "REJECTED_FOSSIL"


class FossilReason(StrEnum):
    DOMINATED = "DOMINATED"
    ARGUS_FAILURE = "ARGUS_FAILURE"
    RESOURCE_FAILURE = "RESOURCE_FAILURE"
    #: For callers that hold the hash of a refused artefact (a tampered genome). The
    #: search never records it: a child the IR refuses is never constructed, so has no hash.
    INVALID = "INVALID"


@dataclass(frozen=True, slots=True)
class ComputationalFossil:
    """Architecture §45, every field bound. A disproven idea, kept so it is not re-tried."""

    genome_hash: str
    niche: NicheKey | None
    ancestry: tuple[str, ...]
    mutation_history: tuple[str, ...]
    reason_for_failure: FossilReason
    counterexample_signature: str | None
    resource_failure: str | None
    security_regression: float | None
    epochs_tested: tuple[int, ...]

    def __post_init__(self) -> None:
        if not self.genome_hash:
            raise ContractError("ComputationalFossil needs a genome_hash")
        if len(self.ancestry) > MAX_LINEAGE_RECORDED:
            raise ContractError(f"fossil ancestry above {MAX_LINEAGE_RECORDED} entries")


class FossilStore:
    """Bounded fossil memory: oldest evicted first, every eviction and avoidance counted."""

    __slots__ = ("_avoided", "_capacity", "_evictions", "_fossils")

    def __init__(self, capacity: int = MAX_FOSSILS) -> None:
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
            raise ContractError(f"FossilStore capacity must be a positive int, got {capacity!r}")
        self._capacity = capacity
        self._fossils: OrderedDict[str, ComputationalFossil] = OrderedDict()
        self._evictions = 0
        self._avoided = 0

    def add(self, fossil: ComputationalFossil) -> None:
        if fossil.genome_hash in self._fossils:
            return  # the first recorded failure is the counterexample; keep it
        if len(self._fossils) >= self._capacity:
            self._fossils.popitem(last=False)
            self._evictions += 1
        self._fossils[fossil.genome_hash] = fossil

    def __contains__(self, genome_hash: object) -> bool:
        return genome_hash in self._fossils

    def __len__(self) -> int:
        return len(self._fossils)

    def avoid(self, genome_hash: str) -> bool:
        """``True`` (and counted) when ``genome_hash`` is a fossil the caller should skip."""
        if genome_hash in self._fossils:
            self._avoided += 1
            return True
        return False

    def fossils(self) -> tuple[ComputationalFossil, ...]:
        return tuple(self._fossils.values())

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def evictions(self) -> int:
        return self._evictions

    @property
    def avoided(self) -> int:
        return self._avoided


def _improves(new: FitnessRecord, old: FitnessRecord) -> bool:
    if new.worst_case_ap is None:
        return False
    if old.worst_case_ap is None or new.worst_case_ap > old.worst_case_ap + _AP_TIE:
        return True
    if abs(new.worst_case_ap - old.worst_case_ap) <= _AP_TIE:
        return dominates(new.objective(), old.objective())
    return False


def _argus_failures_survived(fitness: FitnessRecord) -> int:
    clean = fitness.clean_ap
    if clean is None:
        return 0
    return sum(
        1
        for name, ap in fitness.variant_aps
        if name != "clean" and ap is not None and ap < clean - _AP_TIE
    )


class QualityDiversityArchive:
    """MAP-Elites over static cost bins, or (``niches=False``) one elitist cell."""

    __slots__ = ("_cells", "_fossils", "_inserted", "_niches", "_outcomes")

    def __init__(
        self, *, niches: bool = QD_ARCHIVE_DEFAULT_ENABLED, fossils: FossilStore | None = None
    ) -> None:
        self._niches = bool(niches)
        self._fossils = fossils
        self._cells: dict[NicheKey, Elite] = {}
        self._inserted = 0
        self._outcomes: dict[ArchiveOutcome, int] = dict.fromkeys(ArchiveOutcome, 0)

    @property
    def niches(self) -> bool:
        return self._niches

    @property
    def cell_bound(self) -> int:
        return CELL_COUNT if self._niches else 1

    def outcome_counts(self) -> dict[str, int]:
        return {outcome.value: count for outcome, count in self._outcomes.items()}

    def insert(
        self,
        genome: ComputationalGenomeV1,
        fitness: FitnessRecord,
        *,
        lineage: tuple[str, ...] = (),
    ) -> tuple[ArchiveOutcome, Elite | None]:
        if fitness.genome_digest != genome.digest:
            raise ContractError("archive insert: fitness record belongs to another genome")
        outcome, elite = self._place(genome, fitness, lineage)
        self._outcomes[outcome] += 1
        return outcome, elite

    def _place(
        self, genome: ComputationalGenomeV1, fitness: FitnessRecord, lineage: tuple[str, ...]
    ) -> tuple[ArchiveOutcome, Elite | None]:
        if self._fossils is not None and self._fossils.avoid(genome.digest):
            return ArchiveOutcome.REJECTED_FOSSIL, None
        niche = niche_of(genome)
        cell = niche if self._niches else _SINGLE_CELL
        current = self._cells.get(cell)
        if fitness.worst_case_ap is None or (
            current is not None and not _improves(fitness, current.fitness)
        ):
            return ArchiveOutcome.REJECTED_WORSE, None
        self._inserted += 1
        elite = Elite(
            genome=genome,
            fitness=fitness,
            niche=niche,
            lineage=tuple(lineage)[-MAX_LINEAGE_RECORDED:],
            argus_failures_survived=_argus_failures_survived(fitness),
            inserted_at=self._inserted,
        )
        self._cells[cell] = elite
        return (ArchiveOutcome.NEW_CELL if current is None else ArchiveOutcome.IMPROVED), elite

    def elites(self) -> tuple[Elite, ...]:
        return tuple(self._cells.values())

    def pareto_elites(self) -> tuple[Elite, ...]:
        elites = self.elites()
        front = set(pareto_front([(e.genome.digest, e.fitness.objective()) for e in elites]))
        return tuple(e for e in elites if e.genome.digest in front)

    def occupied(self) -> int:
        return len(self._cells)


# --------------------------------------------------------------------------- ecology


def _dense(scores: Sequence[float | None]) -> list[float]:
    return [0.0 if score is None else float(score) for score in scores]


def _rank_normalise(scores: Sequence[float]) -> list[float]:
    """Average ranks in [0, 1]; ties share a rank so neither operand is favoured."""
    order = sorted(range(len(scores)), key=scores.__getitem__)
    ranks = [0.0] * len(scores)
    start = 0
    while start < len(order):
        end = start
        while end + 1 < len(order) and scores[order[end + 1]] == scores[order[start]]:
            end += 1
        for position in range(start, end + 1):
            ranks[order[position]] = (start + end) / 2
        start = end + 1
    top = max(len(scores) - 1, 1)
    return [rank / top for rank in ranks]


def synergy(
    a: Sequence[float | None], b: Sequence[float | None], labels: Sequence[int]
) -> float | None:
    """Architecture §43: ``AP(max of rank-normalised a, b) - AP(a) - AP(b)``.

    Read literally with AP as utility, this is negative whenever the pair is not
    complementary; a positive value is the rare cooperative pair. Abstentions rank as 0.0,
    as in fitness.
    """
    if not len(a) == len(b) == len(labels):
        raise ContractError("synergy: score vectors and labels differ in length")
    dense_a, dense_b = _dense(a), _dense(b)
    ap_a = average_precision(labels, dense_a)
    ap_b = average_precision(labels, dense_b)
    ranked = zip(_rank_normalise(dense_a), _rank_normalise(dense_b), strict=True)
    pair = [max(x, y) for x, y in ranked]
    ap_pair = average_precision(labels, pair)
    if ap_a is None or ap_b is None or ap_pair is None:
        return None
    return ap_pair - ap_a - ap_b


def parasites(
    elite: Elite, suite: EvaluationSuite, *, meter: WorkMeter, tolerance: float = 0.005
) -> tuple[int, ...]:
    """Architecture §44: flat node indices whose UniqueUtility is at most ``tolerance``.

    Same quantity as :func:`~pocketsec.stage9.genesis.variation.unique_utility`, with the
    full genome evaluated once instead of once per node. Every evaluation is charged to
    ``meter``. A node that cannot be removed (a CONST, or an ablation the IR refuses) is
    never reported as a parasite.
    """
    base = evaluate(elite.genome, suite, meter=meter).worst_case_ap
    if base is None:
        return ()
    found: list[int] = []
    for index in range(node_total(elite.genome)):
        ablated = ablate_node(elite.genome, index)
        if ablated is None:
            continue
        without = evaluate(ablated, suite, meter=meter).worst_case_ap
        if without is not None and base - without <= tolerance:
            found.append(index)
    return tuple(found)


@dataclass(frozen=True, slots=True)
class DominanceReport:
    dominating_digest: str | None
    cells_dominated: int  # includes the dominating elite's own cell
    cells_occupied: int

    @property
    def share(self) -> float | None:
        return None if self.cells_occupied == 0 else self.cells_dominated / self.cells_occupied


def dominance_of(elites: Sequence[Elite]) -> DominanceReport:
    """The elite whose objective dominates (or is) the most occupied cells."""
    best: Elite | None = None
    best_count = -1
    for elite in elites:
        mine = elite.fitness.objective()
        count = sum(
            1 for other in elites if other is elite or dominates(mine, other.fitness.objective())
        )
        if count > best_count:
            best, best_count = elite, count
    if best is None:
        return DominanceReport(None, 0, 0)
    return DominanceReport(best.genome.digest, best_count, len(elites))


def single_architecture_dominance(archive: QualityDiversityArchive) -> DominanceReport:
    """§68 QD falsifier input: does one architecture dominate across the niches?"""
    return dominance_of(archive.elites())


def compare_qd(
    main: Sequence[SearchRun], niches: Sequence[SearchRun], heldout: EvaluationSuite
) -> DetectorComparison:
    """Decide :data:`QD_ARCHIVE_DEFAULT_ENABLED` against the single-cell elitist arm.

    JUSTIFIED iff the seed-matched median held-out worst-case AP delta is >= +0.02 AND no
    niched run has one elite dominating >= 90% of its occupied cells. REJECTED iff the
    median delta is <= -0.02, or every niched run is dominated by one elite (§68).
    ``fired`` counts seeds whose winner changed when niches were switched on.
    """
    from pocketsec.stage9.ontogenesis.search import heldout_report, seed_matched

    pairs = seed_matched(main, niches)
    main_reports = heldout_report([m for m, _ in pairs], heldout)
    arm_reports = heldout_report([n for _, n in pairs], heldout)
    deltas = [
        None if m.heldout_worst_case_ap is None or a.heldout_worst_case_ap is None
        else a.heldout_worst_case_ap - m.heldout_worst_case_ap
        for m, a in zip(main_reports, arm_reports, strict=True)
    ]
    shares = [dominance_of(run.archive_elites).share for _, run in pairs]
    known = [f for f in shares if f is not None]
    fired = sum(1 for m, a in zip(main_reports, arm_reports, strict=True)
                if m.genome_digest != a.genome_digest)
    measured = [d for d in deltas if d is not None]
    median = statistics.median(measured) if measured and len(measured) == len(deltas) else None
    verdict = _qd_verdict(median, known, len(shares))
    return DetectorComparison(
        mechanism=_MECHANISM,
        metric="median seed-matched held-out worst-case AP delta (niches - single cell)",
        value=median,
        controls=(
            ("single_cell_median_heldout_worst_case_ap", _median_of(main_reports)),
            ("niches_median_heldout_worst_case_ap", _median_of(arm_reports)),
            ("max_single_elite_dominance_share", max(known) if known else None),
        ),
        verdict=verdict,
        fired=fired,
        detail=(
            f"{len(pairs)} seed-matched pairs; deltas={deltas}; dominance shares="
            f"{shares}; falsifier threshold {DOMINANCE_FALSIFIER_SHARE}"
        ),
    )


def _median_of(reports: Sequence[WinnerReport]) -> float | None:
    known = [r.heldout_worst_case_ap for r in reports if r.heldout_worst_case_ap is not None]
    return statistics.median(known) if known else None


def _qd_verdict(median: float | None, shares: Sequence[float], runs: int) -> MechanismVerdict:
    if median is None or runs == 0:
        return MechanismVerdict.UNMEASURED
    dominated_everywhere = len(shares) == runs and all(
        f >= DOMINANCE_FALSIFIER_SHARE for f in shares
    )
    if median <= -QD_MARGIN or dominated_everywhere:
        return MechanismVerdict.REJECTED
    no_dominator = len(shares) == runs and all(
        f < DOMINANCE_FALSIFIER_SHARE for f in shares
    )
    if median >= QD_MARGIN and no_dominator:
        return MechanismVerdict.JUSTIFIED
    return MechanismVerdict.NOT_YET_JUSTIFIED


def compare_arm(
    main: Sequence[SearchRun], arm: Sequence[SearchRun], heldout: EvaluationSuite, *, flag: str
) -> DetectorComparison:
    """Seed-matched ablation of one ecology flag against the main (all-off) arm.

    Exported from ``ontogenesis.search`` as well, where the spec names it. ``subtractive``:
    the arm's winner costs >= 10% fewer WU/event at held-out worst-case AP within 0.01, on
    every seed. ``fossil_avoidance``: the arm reaches its final best with >= 10% fewer WU at
    held-out AP within 0.01, on every seed; ``fired`` counts seeds whose trajectory differs
    from the main arm's, and an arm that replays the main arm on every seed is INERT and
    REJECTED (S9-R1). ``niches`` is decided by :func:`compare_qd`.
    """
    key = next((k for k, name in _ARM_FLAGS.items() if flag in (k, name)), None)
    if key is None:
        raise ContractError(f"compare_arm: unknown flag {flag!r}; known {sorted(_ARM_FLAGS)}")
    if key == "niches":
        return compare_qd(main, arm, heldout)
    from pocketsec.stage9.ontogenesis.search import heldout_report, seed_matched

    pairs = seed_matched(main, arm)
    reports = heldout_report([*(m for m, _ in pairs), *(a for _, a in pairs)], heldout)
    mains, arms = reports[: len(pairs)], reports[len(pairs) :]
    if key == "subtractive":
        matched = list(zip(mains, arms, strict=True))
        costs = [(float(m.wu_per_event), float(a.wu_per_event)) for m, a in matched]
        fired = sum(1 for m, a in matched if m.genome_digest != a.genome_digest)
        return _arm_comparison(key, mains, arms, costs, fired)
    costs = [(float(_wu_to_best(m)), float(_wu_to_best(a))) for m, a in pairs]
    # ``fired`` counts seeds whose OUTCOME changed (S9-R1), never skipped genomes: a skip
    # that replays the main arm's trajectory changed nothing (DetectorComparison contract).
    fired = sum(1 for m, a in pairs if _trajectory(m) != _trajectory(a))
    comparison = _arm_comparison(key, mains, arms, costs, fired)
    if fired or not pairs:
        return comparison
    return replace(
        comparison,
        verdict=MechanismVerdict.REJECTED,
        detail=(
            f"INERT: on {len(pairs)}/{len(pairs)} seeds the arm replayed the main arm's "
            "trajectory exactly (recorded digests, WU at each record, winner, WU spent) while "
            f"skipping {sum(run.fossils_avoided for _, run in pairs)} fossil re-proposals. "
            "A fossil is only ever a digest the run already recorded, and the search refuses "
            "every recorded digest at 0 WU with no rng draw, so avoidance cannot change an "
            "outcome at any budget: remove it. " + comparison.detail
        ),
    )


def _trajectory(run: SearchRun) -> tuple[object, ...]:
    """Everything an ablation could change: what was recorded, when, the winner, the spend."""
    return (
        tuple(record.genome_digest for record in run.records),
        run.wu_at_record,
        run.winner,
        run.wu_spent,
    )


def _wu_to_best(run: SearchRun) -> int:
    return 0 if run.winner is None or not run.wu_at_record else run.wu_at_record[run.winner]


def _arm_comparison(
    key: str,
    mains: Sequence[WinnerReport],
    arms: Sequence[WinnerReport],
    costs: Sequence[tuple[float, float]],
    fired: int,
) -> DetectorComparison:
    deltas = [
        None if m.heldout_worst_case_ap is None or a.heldout_worst_case_ap is None
        else a.heldout_worst_case_ap - m.heldout_worst_case_ap
        for m, a in zip(mains, arms, strict=True)
    ]
    reductions = [1.0 - arm / main if main > 0 else None for main, arm in costs]
    wins = sum(
        1 for d, r in zip(deltas, reductions, strict=True)
        if d is not None and r is not None and d >= -_ARM_AP_TOLERANCE and r >= _ARM_COST_SHARE
    )
    known = [d for d in deltas if d is not None]
    median_delta = statistics.median(known) if known else None
    if not deltas or None in deltas or None in reductions:
        verdict = MechanismVerdict.UNMEASURED
    elif wins == len(deltas):
        verdict = MechanismVerdict.JUSTIFIED
    elif wins == 0 and median_delta is not None and median_delta <= -QD_MARGIN:
        verdict = MechanismVerdict.REJECTED
    else:
        verdict = MechanismVerdict.NOT_YET_JUSTIFIED
    cost = "wu_per_event" if key == "subtractive" else "wu_to_final_best"
    known_cuts = [r for r in reductions if r is not None]
    return DetectorComparison(
        mechanism=_ARM_FLAGS[key],
        metric=f"median relative {cost} reduction at held-out worst-case AP within "
        f"{_ARM_AP_TOLERANCE}",
        value=statistics.median(known_cuts) if known_cuts else None,
        controls=(
            ("main_median_" + cost, statistics.median([c[0] for c in costs]) if costs else None),
            ("arm_median_" + cost, statistics.median([c[1] for c in costs]) if costs else None),
            ("median_heldout_ap_delta", median_delta),
        ),
        verdict=verdict,
        fired=fired,
        detail=f"{wins}/{len(deltas)} seeds met both conditions; deltas={deltas}; "
        f"reductions={reductions}",
    )


def _synthetic_record(genome: ComputationalGenomeV1, ap: float) -> FitnessRecord:
    """A structural fitness for the flood: this attack tests the bound, not quality."""
    return FitnessRecord(
        genome_digest=genome.digest,
        suite="hypothesis-explosion",
        clean_ap=ap,
        variant_aps=(("clean", ap),),
        worst_case_ap=ap,
        worst_variant="clean",
        wu_per_event=genome.bounds.update_wu_per_event,
        state_bytes=genome.bounds.session_state_bytes_max,
        description_length_bits=genome.description_length_bits(),
        work_units_spent=0,
        constant_output=False,
        lineage_evictions=0,
        scores_digest="sha256:" + hashlib.sha256(genome.digest.encode()).hexdigest(),
    )


def hypothesis_explosion(
    archive_factory: Callable[[], QualityDiversityArchive],
) -> ArgusFinding:
    """ARGUS [SEARCH]: offer ten times the cell bound of distinct genomes to one archive.

    A DEFENCE: ``fired`` counts offers after which occupancy was still within the bound,
    so ``fired == total`` iff the bound held on every offer. Fitness values are synthetic
    (seeded uniform AP) because the claim under attack is the occupancy bound, not quality.
    """
    archive = archive_factory()
    bound = archive.cell_bound
    target = _EXPLOSION_MULTIPLIER * bound
    rng = random.Random(_EXPLOSION_SEED)
    seen: set[str] = set()
    offered = held = rejected = draws = 0
    while offered < target and draws < 4 * target:
        draws += 1
        genome = random_genome(rng)
        if genome.digest in seen:
            continue
        seen.add(genome.digest)
        outcome, _ = archive.insert(genome, _synthetic_record(genome, round(rng.random(), 6)))
        offered += 1
        rejected += outcome in (ArchiveOutcome.REJECTED_WORSE, ArchiveOutcome.REJECTED_FOSSIL)
        held += archive.occupied() <= bound and len(archive.elites()) <= bound
    return ArgusFinding(
        attack_id="hypothesis_explosion",
        surface=ArgusSurface.SEARCH,
        kind="DEFENCE",
        fired=held,
        total=offered,
        inert=held == 0,
        metric_before=float(bound),
        metric_after=float(archive.occupied()),
        detail=(
            f"offered {offered} distinct genomes (target {target}, {draws} draws) to an archive "
            f"bounded at {bound} cells; occupied {archive.occupied()}; rejected {rejected}; "
            f"bound held after {held}/{offered} offers; fitness synthetic"
        ),
        measured_by="pocketsec.stage9.gaia.qd_ecology:hypothesis_explosion",
    )
