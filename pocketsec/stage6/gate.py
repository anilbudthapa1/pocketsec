"""The Stage 6 acceptance gate (``docs/stage-6-spec.md`` §6), as an executable check.

Thirteen criteria, one per bullet of architecture §52 in its order, each evaluated by
running the real subsystems rather than inspecting a document. Like every earlier stage's
gate this is code: ``pocketsec-stage6 gate`` exits non-zero if any criterion fails.

Four things about this gate are worth stating before anyone reads a result off it.

**It is expected to fail, and its failures are Stage 6's findings.** Spec §6.1 said so in
advance: G6.13 fails *by construction* on synthetic data (PASS additionally requires
``EnduranceReport.synthetic is False``). Beyond that, every check that would otherwise pass
on an empty result is written to fail instead: a regression bound examined over zero
promotions, a lineage check over zero learned items, an FP rate that "returns" to 1.0 are
*vacuous*, and a vacuous check is reported FAILED with the reason, never PASSED (the
Stage 4 lesson: a component that never fires is INERT, not measured).

**Where the gate uses a rig, it says so.** G6.3's firing proof, G6.6, G6.7(b) and G6.8 are
about the one trusted writer, and on the endurance corpus the real learner promotes almost
nothing, so :mod:`pocketsec.stage6.gate_rig` builds those situations on purpose with a lab
chamber that mints real ``EvolutionCandidate`` values. Everything else runs the real
Stage 6 learner (gateway -> chamber -> consolidator -> controller) on the compiled 12-month
and 60-month timelines, and the real poison suite.

**No check reads a document to decide a mechanism question.** G6.13 reads the findings
document because its subject is the findings document (the honesty-ledger headings and the
novelty-word rule); nothing else does.

**Nothing measured here is a detection result, and no timing is a device figure.** Every
corpus is synthetic. ``/proc/loadavg`` is recorded beside every timing because a Stage 2
gate saw 7x inflation on this contended host.

This gate **never** appends to ``experiments/registry.jsonl`` (spec §2.7): nothing here
opens the registry for writing, and G6.13 asserts the ledger is byte-identical before and
after the run. Registration is ``pocketsec-stage6 experiments --register``.
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pocketsec.stage0.gate import REPO_ROOT, GateReport
from pocketsec.stage6 import gate_construction as construction
from pocketsec.stage6 import gate_measured as measured
from pocketsec.stage6.labs.continual_baselines import (
    CalibrationOnly,
    FullRetrain,
    Learner,
    NaiveFinetune,
    NeverUpdate,
    PrototypeCentroid,
    ReservoirReplay,
    Stage2Only,
)
from pocketsec.stage6.labs.endurance import (
    CAPACITY_SWEEP,
    POISON_MULTIPLIERS,
    REPLAY_BUDGETS_BYTES,
    AblationRow,
    EnduranceReport,
    PoisonReport,
    PreconditionReport,
    StageSixConfig,
    StageSixLearner,
    check_preconditions,
    run_ablation,
    run_endurance,
    run_poison_suite,
)
from pocketsec.stage6.labs.endurance_corpus import (
    ENDURANCE_SEED,
    EVAL_SESSIONS_PER_FAMILY,
    SESSIONS_PER_MONTH,
    YEAR_CYCLES,
    CompiledTimeline,
    build_endurance_timeline,
    build_year_timeline,
    compile_timeline,
)
from pocketsec.stage6.resources import loadavg

__all__ = [
    "EXPERIMENT_ID",
    "REGISTRY_PATH",
    "STAGE6_HYPOTHESIS",
    "STAGE6_LEARNER",
    "Stage6GateContext",
    "baseline_learners",
    "registry_digest",
    "run_gate",
]

#: Spec §2.8 / ADR-0055: Stage 6 mints no hypothesis and binds to H6 (H8 for ablation).
STAGE6_HYPOTHESIS = "H6"
EXPERIMENT_ID = "PS-S6-20260926-H6-helios-gate-0001"
REGISTRY_PATH = REPO_ROOT / "experiments" / "registry.jsonl"
#: The Stage 6 learner's name in every endurance report (``StageSixLearner`` default).
STAGE6_LEARNER = "stage6"

Timing = tuple[str, float, tuple[float, float, float]]


def registry_digest(path: Path = REGISTRY_PATH) -> str | None:
    """sha256 of the real experiment ledger's bytes, or ``None`` when it does not exist."""
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _timed(label: str, timings: list[Timing], work: Callable[[], Any]) -> Any:
    """Run ``work`` and record wall clock beside ``/proc/loadavg``. Observed, never asserted."""
    started = time.perf_counter()
    result = work()
    timings.append((label, round(time.perf_counter() - started, 3), loadavg()))
    return result


def baseline_learners(compiled: CompiledTimeline) -> list[Learner]:
    """Spec §7's baselines on the same stream, with the capacity and byte-budget sweeps."""
    genesis = compiled.genesis
    naive = []
    for capacity in CAPACITY_SWEEP:
        learner = NaiveFinetune(genesis, detector_capacity=capacity)
        learner.name = f"naive-cap{capacity}"
        naive.append(learner)
    reservoirs = [ReservoirReplay(genesis, budget_bytes=b) for b in REPLAY_BUDGETS_BYTES]
    return [NeverUpdate(genesis), CalibrationOnly(genesis), *naive, *reservoirs,
            FullRetrain(genesis), PrototypeCentroid(genesis), Stage2Only(genesis)]


@dataclass
class Stage6GateContext:
    """One compile and one run of everything, so thirteen checks do not replay them."""

    compiled: CompiledTimeline
    preconditions: PreconditionReport
    endurance: EnduranceReport
    learners: Mapping[str, Learner]
    stage6: StageSixLearner
    budget_runs: EnduranceReport
    year: EnduranceReport
    year_learner: StageSixLearner
    poison: PoisonReport
    ablation: tuple[AblationRow, ...]
    registry_before: str | None
    scratch: Path
    sessions_per_month: int
    seed: int
    timings: list[Timing] = field(default_factory=list)

    @classmethod
    def build(
        cls,
        *,
        sessions_per_month: int = SESSIONS_PER_MONTH,
        eval_per_family: int = EVAL_SESSIONS_PER_FAMILY,
        cycles: int = YEAR_CYCLES,
        multipliers: tuple[int, ...] = POISON_MULTIPLIERS,
        poison_background: int | None = None,
        seed: int = ENDURANCE_SEED,
    ) -> Stage6GateContext:
        before = registry_digest()
        scratch = Path(tempfile.mkdtemp(prefix="pocketsec-stage6-gate-"))
        timings: list[Timing] = []
        compiled = _timed("compile 12-month timeline", timings, lambda: compile_timeline(
            build_endurance_timeline(sessions_per_month=sessions_per_month,
                                     eval_per_family=eval_per_family, seed=seed), seed=seed))
        pre = _timed("preconditions E1-E5", timings, lambda: check_preconditions(compiled))
        stage6 = StageSixLearner(compiled.genesis, fossil_dir=_dir(scratch, "stage6"), seed=seed)
        learners = [*baseline_learners(compiled), stage6]
        endurance = _timed("endurance, every learner", timings,
                           lambda: run_endurance(compiled, learners, pre))
        budgets = [StageSixLearner(compiled.genesis, seed=seed, name=f"stage6-rehearsal-{b}",
                                   config=StageSixConfig(rehearsal_budget_bytes=b))
                   for b in REPLAY_BUDGETS_BYTES]
        budget_runs = _timed("stage6 at each replay budget", timings,
                             lambda: run_endurance(compiled, budgets, pre))
        year_compiled = _timed("compile 60-month timeline", timings, lambda: compile_timeline(
            build_year_timeline(cycles=cycles, sessions_per_month=sessions_per_month, seed=seed),
            seed=seed))
        year_learner = StageSixLearner(year_compiled.genesis, seed=seed)
        year = _timed("60-month stage6 run", timings,
                      lambda: run_endurance(year_compiled, [year_learner]))
        poison = _timed("poison suite", timings, lambda: run_poison_suite(
            multipliers=multipliers, seed=seed, background=poison_background,
            fossil_root=_dir(scratch, "poison")))
        ablation = _timed("ablation", timings,
                          lambda: run_ablation(compiled, preconditions=pre))
        return cls(compiled=compiled, preconditions=pre, endurance=endurance,
                   learners={learner.name: learner for learner in learners}, stage6=stage6,
                   budget_runs=budget_runs, year=year, year_learner=year_learner,
                   poison=poison, ablation=ablation, registry_before=before, scratch=scratch,
                   sessions_per_month=sessions_per_month, seed=seed, timings=timings)

    def fresh_dir(self, name: str) -> Path:
        return _dir(self.scratch, name)

    def close(self) -> None:
        shutil.rmtree(self.scratch, ignore_errors=True)


def _dir(root: Path, name: str) -> Path:
    path = root / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def run_gate(ctx: Stage6GateContext | None = None) -> GateReport:
    """Evaluate all thirteen Stage 6 acceptance criteria against one shared run."""
    owned = ctx is None
    ctx = ctx if ctx is not None else Stage6GateContext.build()
    try:
        return GateReport(
            checks=(
                construction.check_raw_telemetry_cannot_modify(ctx),
                measured.check_provenance_and_lineage(ctx),
                measured.check_historical_capability_bounds(ctx),
                measured.check_repetition_is_not_normality(ctx),
                measured.check_epoch_adaptation(ctx),
                construction.check_isolated_evaluation(ctx),
                construction.check_no_authority_path(ctx),
                construction.check_rollback_restores(ctx),
                measured.check_poisoning_coverage(ctx),
                measured.check_resource_envelope(ctx),
                construction.check_retraining_off_endpoint(ctx),
                measured.check_bounded_growth(ctx),
                measured.check_ablation_survival(ctx),
            )
        )
    finally:
        if owned:
            ctx.close()
