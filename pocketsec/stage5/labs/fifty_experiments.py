"""D5.19 — the fifty-experiment register, the ablation table, and the saturation guard.

Three things live here, in the order the gate must use them.

**The register.** Architecture §41 names fifty experiments; :data:`EXPERIMENTS` holds
all fifty with the titles verbatim and dense ids ``S5X-01`` … ``S5X-50``. Each row is
either ``runnable`` here or carries a :class:`BlockedReason`, never both and never
neither. :class:`BlockedReason` is a **closed** StrEnum because an open reason field
is where "we did not get to it" hides behind "it is blocked".

**The saturation guard, which runs first.** :func:`saturation_check` is called *before*
any ablation row is recorded. If the best and median arms are within
:data:`SATURATION_EPSILON` on :data:`PRIMARY_METRIC`, or if an act-always or act-never
control ties the best at the best containment, the split is ``DEGENERATE`` and nothing
is recorded. This is not caution: Stage 2 spent a whole wave believing ablations taken
on corpora that five architectures tied on at 0.9992 (``MEMORY.md`` trap 9, ADR-0120).
A task a degenerate control solves cannot show that any component helps.

**The ablation table.** :func:`run_ablation` flips one reference-arm flag and measures
the delta on the primary metric, which is collateral *at equal containment* — so
:func:`verdict_for` lets containment decide first and collateral only break a tie. A
mechanism that blocks every containment action has zero collateral; judged on
collateral alone it would look free, and judged here it is ``HARMFUL``. A flag whose
delta is ``None`` is ``UNMEASURED`` and fails; a delta that is merely zero at equal
containment is ``NOT_YET_JUSTIFIED``, **not** ``REJECTED`` — ADR-0009
got that distinction right under pressure and two Stage 2 components turned out to be
actively harmful only on the third corpus.

**What the ablation is an ablation of.** The arm being toggled is the real
:class:`~pocketsec.stage5.aegis.planner.AegisPlanner` under a real
``PlannerConfig``, so each flag removes the mechanism the flag names and nothing else.
:data:`ABLATION_FLAG_ORDER` is ``PlannerConfig``'s own ``ABLATION_FLAG_FIELDS``, which
is why a flag the planner does not understand cannot be ablated by accident and quietly
produce a zero delta. Two of the eleven — ``enable_residual`` and ``enable_d3fend`` —
are read by nothing at all (an earlier version said "by other subsystems", which was
false: finding R7), and ``enable_response_cells`` switches a field the generator never
reads; all three ids' deltas are 0.0 by construction, and G5.14 reports them as inert and
unmeasured rather than as measured zeros.

**Measurements go through Stage 0's ledger and nowhere else.** Stage 5 mints no
hypothesis: it appends to neither ``HYPOTHESES`` nor the prior-art ledger, and its ids
use the grammar's own ``BASE`` token — ``PS-S5-20260925-BASE-safe-gate-0001`` is valid
and was verified by running ``format_experiment_id``. A gate must never mutate
``experiments/registry.jsonl``, so :func:`record_ablation` takes the registry it is
handed and the gate hands it a temporary one.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.experiments.ids import format_experiment_id
from pocketsec.stage0.experiments.registry import ExperimentRegistry
from pocketsec.stage5.aegis.planner import ABLATION_FLAG_FIELDS
from pocketsec.stage5.core_ids import ABLATION_FLAGS
from pocketsec.stage5.labs.baselines import (
    BASELINES,
    DEGENERATE_CONTROL_IDS,
    REFERENCE_ARM_ID,
    REFERENCE_FLAGS,
    BaselineOutcome,
    ExecutorFactory,
    primary_metric_value,
    reference_policy,
    run_arm,
)
from pocketsec.stage5.labs.response_corpus import RESPONSE_CORPUS_VERSION, ResponseCase

__all__ = [
    "ABLATION_EXPERIMENT_ID",
    "ABLATION_FLAG_ORDER",
    "EXPERIMENTS",
    "EXPERIMENTS_BY_ID",
    "PRIMARY_METRIC",
    "SATURATION_EPSILON",
    "STAGE5_EXPERIMENTS_VERSION",
    "STAGE5_HYPOTHESIS",
    "UNBUILT_BASELINE_REASONS",
    "AblationRow",
    "AblationVerdict",
    "BlockedReason",
    "ExperimentSpec",
    "ablation_row",
    "blocked_experiments",
    "core_ids_for_flag",
    "experiment_id_for",
    "ranked_arms",
    "record_ablation",
    "run_ablation",
    "runnable_experiments",
    "saturation_check",
    "verdict_for",
]

#: Derived from the corpus version, so an experiment row can never claim to describe a
#: corpus it was not run on.
STAGE5_EXPERIMENTS_VERSION: str = f"stage5-experiments-v0.1.0+{RESPONSE_CORPUS_VERSION}"

#: The grammar's token for "not a learning hypothesis". Stage 5's claims are about
#: authority, reversibility and verification — properties of a control boundary, not
#: of a model — so it binds to no H-number and appends to no ledger.
STAGE5_HYPOTHESIS: str = "BASE"

#: Best and median within this on the primary metric means the split is degenerate.
SATURATION_EPSILON: float = 0.01

PRIMARY_METRIC: str = "collateral_per_1000_at_equal_containment"


class BlockedReason(StrEnum):
    """Why an experiment cannot run here. **Closed**, and that is the point.

    An open reason field is where "we did not get to it" hides behind "it is blocked".
    Two members carry no row in :data:`EXPERIMENTS`: ``NEEDS_REAL_TELEMETRY``, because
    every §41 experiment that would need it is runnable against the simulator and its
    *result* is simulator-bound rather than blocked; and
    ``NEEDS_NUMPY_FORBIDDEN_HERE``, which applies to the unbuilt RL baselines
    (:data:`UNBUILT_BASELINE_REASONS`) rather than to a numbered experiment. Both are
    kept so the field cannot take an arbitrary string, and their absence from the table
    is stated rather than left for a reader to notice.
    """

    NEEDS_REAL_HOST = "NEEDS_REAL_HOST"
    NEEDS_REAL_TELEMETRY = "NEEDS_REAL_TELEMETRY"
    NEEDS_D3FEND_SNAPSHOT = "NEEDS_D3FEND_SNAPSHOT"
    NEEDS_TWO_EPOCHS = "NEEDS_TWO_EPOCHS"
    NEEDS_NUMPY_FORBIDDEN_HERE = "NEEDS_NUMPY_FORBIDDEN_HERE"


#: The §40 baselines this wave did not build, keyed to the closed reason. The strings
#: live in ``baselines.UNBUILT_BASELINES``; this maps them onto the enum so the
#: findings' blocked-count and the unbuilt-baseline list cannot drift apart.
UNBUILT_BASELINE_REASONS: Mapping[str, BlockedReason] = {
    "B10": BlockedReason.NEEDS_NUMPY_FORBIDDEN_HERE,
    "B11": BlockedReason.NEEDS_NUMPY_FORBIDDEN_HERE,
    "B12": BlockedReason.NEEDS_REAL_TELEMETRY,
}


@dataclass(frozen=True, slots=True)
class ExperimentSpec:
    """One §41 row: what it is, what it measures, and whether it can run here."""

    experiment_id: str
    title: str
    deliverable: str
    runnable: bool
    blocked_reason: BlockedReason | None
    metric: str

    def __post_init__(self) -> None:
        if not self.experiment_id.startswith("S5X-"):
            raise ContractError(f"{self.experiment_id!r} is not an S5X id")
        for name in ("title", "deliverable", "metric"):
            if not str(getattr(self, name)).strip():
                raise ContractError(f"ExperimentSpec.{name} must be non-empty for {self.experiment_id}")
        if self.runnable == (self.blocked_reason is not None):
            raise ContractError(
                f"{self.experiment_id}: runnable={self.runnable!r} and "
                f"blocked_reason={self.blocked_reason!r} are mutually exclusive and one is "
                "required; a row that is both is a row nobody has to resolve"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "title": self.title,
            "deliverable": self.deliverable,
            "runnable": self.runnable,
            "blocked_reason": None if self.blocked_reason is None else self.blocked_reason.value,
            "metric": self.metric,
        }


#: ``(title, deliverable, metric)`` for S5X-01 … S5X-50, titles **verbatim** from
#: architecture §41. The ids are assigned by position, so a missing row is a dense-id
#: test failure rather than a silently renumbered table.
_ROWS: tuple[tuple[str, str, str], ...] = (
    ("response constitution tests", "D5.1", "refusals raised over the constitution's own law set"),
    ("typed operator verifier", "D5.5", "forged constructions refused, target 5 of 5"),
    ("arbitrary-shell impossibility test", "D5.5", "no_arbitrary_command_path() rows, target 0"),
    ("target identity / PID reuse", "D5.11", "wrong-target applications, target 0"),
    ("TOCTOU precondition recheck", "D5.11", "races refused at pid_reuse_rate=1.0"),
    ("authority type enforcement", "D5.6", "escalating grants refused"),
    ("capability token scope", "D5.6", "scope mismatches refused"),
    ("token replay resistance", "D5.6", "replays refused within MAX_SPENT_NONCES"),
    ("SENTINEL independent denial", "D5.4", "denials over 14 operators x 13 inputs"),
    ("evidence preservation", "D5.10", "REFUSED_WOULD_DESTROY on destroying cases"),
    ("response identifiability", "D5.2", "NOT_IDENTIFIABLE rate on ambiguous pairs"),
    ("counterfactual twin fidelity", "D5.7", "simulated_twin_prediction_error"),
    ("intervention cone accuracy", "D5.8", "cone leaf degradation vs observed"),
    ("action-shadow calibration", "D5.8", "rank_correlation, None below 30 pairs"),
    ("mission invariant enforcement", "D5.1", "mission_invariant_violations, target 0"),
    ("dependency graph bounds", "D5.7", "twin nodes <= MAX_TWIN_NODES"),
    ("Pareto selection", "D5.9", "collateral_per_1000 at equal containment vs B6"),
    ("minimax regret", "D5.9", "per-world worst-case loss"),
    ("minimum intervention", "D5.2", "scope_size of the chosen candidate"),
    ("observe-vs-act choice", "D5.3", "observe-only share on ambiguous pairs"),
    ("suspend/resume lab", "D5.11", "simulated suspend/resume round trips"),
    ("temporary local restriction lab", "D5.11", "simulated socket restrict/release round trips"),
    ("service containment lab", "D5.11", "simulated service constrain/release round trips"),
    ("benign-admin ambiguity", "D5.19", "collateral on the benign member of each pair"),
    ("critical-service bait", "D5.1", "MISSION_INVARIANT denials on baited units"),
    ("attacker adaptation", "D5.8", "ATTACKER_ADAPTATION branch count"),
    ("lease expiry", "D5.12", "leases expired by data under a ManualClock"),
    ("lease renewal", "D5.12", "renewals refused without evidence"),
    ("hysteresis", "D5.12", "actions_taken vs B8 at equal containment"),
    ("transactional execution", "D5.11", "phase order over every receipt"),
    ("failed enforcement detection", "D5.13", "INEFFECTIVE rate at enforcement_failure_rate=1.0"),
    ("postcondition verification", "D5.13", "UNVERIFIABLE never reported as verified"),
    ("intervention residual", "D5.13", "residual distance distribution"),
    ("automatic rollback", "D5.11", "simulated_rollback_success"),
    ("rollback fault injection", "D5.11", "simulated_rollback_success at injected failure rates"),
    ("safe-state recovery", "D5.14", "ManifoldStatus after containment, in-simulator"),
    ("staged restoration", "D5.14", "capabilities restored per probe, target <= 1"),
    ("effectiveness memory", "D5.15", "effect_rate, None below MIN_SAMPLES_FOR_RATE"),
    ("epoch-conditioned effectiveness", "D5.15", "records spanning two epochs"),
    ("D3FEND adapter", "D5.16", "mapped_fraction, expected 0 of 14"),
    ("response crystallization", "D5.17", "cells crystallized, expected 0"),
    ("response melting", "D5.17", "melt reports per epoch change"),
    ("prompt/log injection", "D5.5", "O6 candidates generated from hostile prose, target 0"),
    ("action-field DoS", "D5.23", "candidates <= MAX_CANDIDATES under flood"),
    ("executor compromise containment", "D5.11", "journal bytes and lease count under abuse"),
    ("planner crash independence", "D5.4", "SENTINEL verdicts after a planner fault"),
    ("resource benchmark", "D5.18", "ResourceSampler incremental and peak RSS"),
    ("operational availability benchmark", "D5.18", "downtime attributable to PocketSec"),
    ("full ablation", "D5.19", "AblationRow delta per OPTIONAL core id"),
    (
        "falsification against static/simple response",
        "D5.19",
        "fixed playbook vs the reference arm on collateral, containment and work units",
    ),
)

#: The blocked rows, declared up front. Everything else is runnable here, and where a
#: runnable experiment's *result* is simulator-bound rather than blocked, §6.1 says so
#: — that distinction is why S5X-21/22/23, S5X-35, S5X-36 and S5X-37 are runnable.
_BLOCKED: Mapping[str, BlockedReason] = {
    "S5X-39": BlockedReason.NEEDS_TWO_EPOCHS,
    "S5X-40": BlockedReason.NEEDS_D3FEND_SNAPSHOT,
    "S5X-48": BlockedReason.NEEDS_REAL_HOST,
}


def _spec(index: int, row: tuple[str, str, str]) -> ExperimentSpec:
    experiment_id = f"S5X-{index:02d}"
    blocked = _BLOCKED.get(experiment_id)
    title, deliverable, metric = row
    return ExperimentSpec(
        experiment_id=experiment_id,
        title=title,
        deliverable=deliverable,
        runnable=blocked is None,
        blocked_reason=blocked,
        metric=metric,
    )


EXPERIMENTS: tuple[ExperimentSpec, ...] = tuple(
    _spec(index, row) for index, row in enumerate(_ROWS, start=1)
)
EXPERIMENTS_BY_ID: Mapping[str, ExperimentSpec] = {row.experiment_id: row for row in EXPERIMENTS}


def runnable_experiments() -> tuple[ExperimentSpec, ...]:
    return tuple(row for row in EXPERIMENTS if row.runnable)


def blocked_experiments() -> tuple[ExperimentSpec, ...]:
    return tuple(row for row in EXPERIMENTS if not row.runnable)


# --- saturation ---------------------------------------------------------------


def ranked_arms(outcomes: Mapping[str, BaselineOutcome]) -> tuple[BaselineOutcome, ...]:
    """Arms best first under :data:`PRIMARY_METRIC`: containment down, then collateral up.

    This ordering *is* the metric's name read literally. Collateral is only comparable
    "at equal containment", so containment decides first and collateral breaks the tie;
    the arm id breaks what is left, so the order never depends on dict iteration.
    """
    return tuple(
        sorted(
            outcomes.values(),
            key=lambda row: (-row.incidents_contained, primary_metric_value(row), row.baseline_id),
        )
    )


def saturation_check(outcomes: Mapping[str, BaselineOutcome]) -> tuple[bool, str]:
    """``(degenerate, reason)``. Run this **before** recording any ablation.

    Degenerate when the best and the median arm are within :data:`SATURATION_EPSILON`
    on :data:`PRIMARY_METRIC` — which, because the metric is collateral *at equal
    containment*, means they contain the same number of incidents **and** sit within
    epsilon on collateral — or when an act-always / act-never control reaches the best
    containment at the best collateral. The median is the lower-median element of
    :func:`ranked_arms`, so it is always an arm that actually ran.

    **Why containment comes first, measured rather than argued.** The first version of
    this check compared collateral alone. On ``build_response_corpus(count=20,
    seed=11)`` eight of ten arms scored 0.0 on the primary metric, six of them by
    containing nothing, so best and median were both 0.0 and it answered DEGENERATE —
    on a split where containment ranged from 0 to 10 and the fixed playbook contained
    all ten hostile incidents while the full planner contained none. A saturation check
    that hides the one comparison §7 calls most important is not conservative, it is
    wrong.
    """
    if len(outcomes) < 3:
        return True, f"DEGENERATE: {len(outcomes)} arms is too few to have a median"
    ranked = ranked_arms(outcomes)
    best, middle = ranked[0], ranked[(len(ranked) - 1) // 2]
    best_value, middle_value = primary_metric_value(best), primary_metric_value(middle)
    if (
        middle.incidents_contained == best.incidents_contained
        and abs(middle_value - best_value) <= SATURATION_EPSILON
    ):
        return True, (
            f"DEGENERATE: best {best.baseline_id} and median {middle.baseline_id} both contain "
            f"{best.incidents_contained} at {PRIMARY_METRIC} {best_value:.4f} vs "
            f"{middle_value:.4f}, within SATURATION_EPSILON={SATURATION_EPSILON}; a split "
            "every arm solves cannot show that any component helps"
        )
    tied = sorted(
        row.baseline_id
        for row in ranked
        if row.baseline_id in DEGENERATE_CONTROL_IDS
        and row.incidents_contained == best.incidents_contained
        and primary_metric_value(row) <= best_value + SATURATION_EPSILON
    )
    if tied:
        return True, (
            f"DEGENERATE: degenerate control(s) {tied} reach the best containment "
            f"{best.incidents_contained} at {PRIMARY_METRIC} {best_value:.4f}; §7 reports B1 "
            "and B4 as the frontier's endpoints, never as competitors, so a split they win "
            "is a split with no headroom"
        )
    return False, (
        f"not degenerate: best {best.baseline_id} contains {best.incidents_contained} at "
        f"{best_value:.4f}, median {middle.baseline_id} contains "
        f"{middle.incidents_contained} at {middle_value:.4f} on {PRIMARY_METRIC}"
    )


# --- ablation -----------------------------------------------------------------


class AblationVerdict(StrEnum):
    """Four verdicts, and the middle two are different facts.

    ``NOT_YET_JUSTIFIED`` is not ``HARMFUL`` and neither is ``UNMEASURED``. ADR-0009
    kept those apart under pressure and it paid: three components showed no benefit on
    a saturated corpus, were retained and re-tested, and two turned out to be actively
    harmful only on the third corpus.
    """

    JUSTIFIED = "JUSTIFIED"
    NOT_YET_JUSTIFIED = "NOT_YET_JUSTIFIED"
    HARMFUL = "HARMFUL"
    UNMEASURED = "UNMEASURED"


@dataclass(frozen=True, slots=True)
class AblationRow:
    """One flag's measured effect, or an honest ``UNMEASURED``.

    ``with_contained`` / ``without_contained`` extend the spec's field list, and the
    extension is load-bearing: the primary metric is collateral *at equal
    containment*, so a row that recorded collateral alone could not say whether the
    comparison it reports was at equal containment at all. They default to ``None`` so
    a hand-built row stays constructible, and ``None`` means "not recorded", never 0.
    """

    core_id: str
    flag: str
    metric: str
    with_value: float | None
    without_value: float | None
    delta: float | None
    verdict: AblationVerdict
    experiment_id: str
    with_contained: int | None = None
    without_contained: int | None = None

    def __post_init__(self) -> None:
        unmeasured = self.delta is None
        if unmeasured and self.verdict is not AblationVerdict.UNMEASURED:
            raise ContractError(
                f"{self.core_id}: delta is None so the verdict must be UNMEASURED, not "
                f"{self.verdict}; a missing measurement is not a passing one (ADR-0004)"
            )
        if not unmeasured and self.verdict is AblationVerdict.UNMEASURED:
            raise ContractError(
                f"{self.core_id}: delta {self.delta!r} was measured, so UNMEASURED is wrong"
            )
        if self.experiment_id not in EXPERIMENTS_BY_ID:
            raise ContractError(f"{self.core_id} cites unknown experiment {self.experiment_id!r}")
        for name in ("with_contained", "without_contained"):
            value = getattr(self, name)
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value < 0
            ):
                raise ContractError(f"AblationRow.{name} must be a count or None, got {value!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "core_id": self.core_id,
            "flag": self.flag,
            "metric": self.metric,
            "with_value": self.with_value,
            "without_value": self.without_value,
            "delta": self.delta,
            "verdict": self.verdict.value,
            "experiment_id": self.experiment_id,
            "with_contained": self.with_contained,
            "without_contained": self.without_contained,
        }


#: ``PlannerConfig``'s own flag list, sorted for a stable report. Taken from the
#: planner rather than restated here, because two copies of a flag list is how one of
#: them ends up describing a mechanism that no longer has an off switch.
ABLATION_FLAG_ORDER: tuple[str, ...] = tuple(sorted(ABLATION_FLAG_FIELDS))

#: §41's "full ablation" row. Every per-flag measurement cites it.
ABLATION_EXPERIMENT_ID: str = "S5X-49"


def experiment_id_for(sequence: int) -> str:
    """A Stage 0 experiment id under the ``BASE`` hypothesis."""
    return format_experiment_id(
        stage=5, hypothesis=STAGE5_HYPOTHESIS, slug="safe-ablation", sequence=sequence
    )


def core_ids_for_flag(flag: str) -> tuple[str, ...]:
    """The SAFE-F core ids whose ablation switch is ``flag``, sorted. §4.9 Rule A's join.

    Read from ``core_ids.ABLATION_FLAGS`` rather than restated, because the gate joins
    ``AblationRow.core_id`` to ``OPTIONAL_IDS``: a row keyed by an id that is not in that
    table is a row the join can never find (S2-FC-01).
    """
    return tuple(sorted(core for core, owned in ABLATION_FLAGS.items() if owned == flag))


def _resolve_core_id(flag: str, core_id: str | None) -> str:
    """The core id an ablation row is keyed by, or a refusal naming the mismatch.

    An earlier revision defaulted to ``"SAFE-F00"``, an id that exists nowhere, so every
    row built without an explicit id was invisible to G5.14's join. Now an omitted id is
    derived from the flag, a flag that switches two ids must be told which one, and a
    supplied id must actually own the flag.
    """
    owners = core_ids_for_flag(flag)
    if core_id is None:
        if len(owners) == 1:
            return owners[0]
        if not owners:
            raise ContractError(
                f"{flag!r} switches no SAFE-F core id (it is in UNMAPPED_PLANNER_FLAGS); it is "
                "measured as a baseline arm (B7), not as a core-id ablation row"
            )
        raise ContractError(f"{flag!r} switches {list(owners)}; name the core id explicitly")
    if core_id not in owners:
        raise ContractError(
            f"core id {core_id!r} is not switched by {flag!r} (owners: {list(owners)}); a row "
            "keyed that way joins two key spaces that cannot match (§4.9 Rule A)"
        )
    return core_id


def verdict_for(delta: float, containment_delta: int = 0) -> AblationVerdict:
    """The verdict for one measured row. Public so a test can exercise every boundary.

    ``delta`` is ``without - with`` on collateral (positive: the mechanism reduced
    collateral); ``containment_delta`` is ``with - without`` on incidents contained
    (positive: the mechanism contained more). Collateral only decides at *equal*
    containment, which is what the primary metric's name says:

    * equal containment — the collateral delta decides, with ``SATURATION_EPSILON`` as
      the no-difference band;
    * the mechanism contains more at no worse collateral — ``JUSTIFIED``;
    * the mechanism contains less at no better collateral — ``HARMFUL``, because
      switching it off is better on both axes;
    * a trade in either direction — ``NOT_YET_JUSTIFIED``: whether more containment is
      worth more collateral is a policy question, and an ablation does not answer it.
    """
    if containment_delta > 0:
        return (
            AblationVerdict.JUSTIFIED
            if delta >= -SATURATION_EPSILON
            else AblationVerdict.NOT_YET_JUSTIFIED
        )
    if containment_delta < 0:
        return (
            AblationVerdict.HARMFUL
            if delta <= SATURATION_EPSILON
            else AblationVerdict.NOT_YET_JUSTIFIED
        )
    if delta > SATURATION_EPSILON:
        return AblationVerdict.JUSTIFIED
    if delta < -SATURATION_EPSILON:
        return AblationVerdict.HARMFUL
    return AblationVerdict.NOT_YET_JUSTIFIED


def ablation_row(
    with_outcome: BaselineOutcome,
    without_outcome: BaselineOutcome,
    *,
    core_id: str,
    flag: str,
    experiment_id: str = ABLATION_EXPERIMENT_ID,
) -> AblationRow:
    """Turn two measured arms into one row. Pure, so the verdict rule is testable alone.

    Either collateral rate being ``None`` — an arm that never acted — makes the row
    ``UNMEASURED``, not zero: there is no rate to compare (ADR-0004).
    """
    with_value = with_outcome.collateral_per_1000()
    without_value = without_outcome.collateral_per_1000()
    delta = None if with_value is None or without_value is None else without_value - with_value
    return AblationRow(
        core_id=core_id,
        flag=flag,
        metric=PRIMARY_METRIC,
        with_value=with_value,
        without_value=without_value,
        delta=delta,
        verdict=(
            AblationVerdict.UNMEASURED
            if delta is None
            else verdict_for(
                delta, with_outcome.incidents_contained - without_outcome.incidents_contained
            )
        ),
        experiment_id=experiment_id,
        with_contained=with_outcome.incidents_contained,
        without_contained=without_outcome.incidents_contained,
    )


def run_ablation(
    cases: Sequence[ResponseCase],
    *,
    flag: str,
    build_executor: ExecutorFactory,
    core_id: str | None = None,
    experiment_id: str = ABLATION_EXPERIMENT_ID,
) -> AblationRow:
    """Measure one flag: the reference arm with it on, then with it off, same corpus.

    ``build_executor`` is required beyond the spec's ``run_ablation(cases, *, flag)``
    for the reason ``labs/baselines.py`` gives: trust rule T4 keeps
    ``TransactionalExecutor`` out of ``labs/``, and an ablation that did not run
    through the real executor would not be measuring the system.
    """
    if flag not in REFERENCE_FLAGS:
        raise ContractError(f"unknown ablation flag {flag!r}; known: {ABLATION_FLAG_ORDER}")
    resolved = _resolve_core_id(flag, core_id)
    on = dict(REFERENCE_FLAGS)
    off = {**on, flag: False}
    with_outcome = run_arm(
        reference_policy(on),
        cases,
        baseline_id=f"{REFERENCE_ARM_ID}+{flag}",
        build_executor=build_executor,
    )
    without_outcome = run_arm(
        reference_policy(off),
        cases,
        baseline_id=f"{REFERENCE_ARM_ID}-{flag}",
        build_executor=build_executor,
    )
    return ablation_row(
        with_outcome, without_outcome, core_id=resolved, flag=flag, experiment_id=experiment_id
    )


def record_ablation(
    registry: ExperimentRegistry,
    row: AblationRow,
    *,
    sequence: int,
    seeds: Mapping[str, int],
    dataset_sha256: str,
) -> str:
    """Append one measured row to the registry it is handed, returning the id.

    The registry is a parameter and not a module default, because
    ``experiments/registry.jsonl`` is append-only and digest-chained and G5.15 asserts
    it is byte-identical before and after a gate run. A gate hands this a temporary
    path. ``dataset_sha256`` is :func:`~pocketsec.stage5.labs.response_corpus.corpus_digest`
    of the cases the row was measured on; an earlier revision wrote ``""`` there, which
    is a ledger entry nobody can tie back to a corpus.
    """
    if row.verdict is AblationVerdict.UNMEASURED:
        raise ContractError(
            f"{row.core_id} is UNMEASURED and has no measurement to record; the ledger holds "
            "results, and an UNMEASURED row belongs in the findings' UNMEASURED table"
        )
    if len(dataset_sha256) != 64 or any(c not in "0123456789abcdef" for c in dataset_sha256):
        raise ContractError("dataset_sha256 must be the corpus digest as 64 lowercase hex digits")
    experiment_id = experiment_id_for(sequence)
    registry.register(
        experiment_id=experiment_id,
        hypothesis=STAGE5_HYPOTHESIS,
        title=f"Stage 5 ablation {row.flag} on {row.metric}",
        slot_name=row.core_id,
        dataset_name=RESPONSE_CORPUS_VERSION,
        dataset_version=STAGE5_EXPERIMENTS_VERSION,
        dataset_sha256=dataset_sha256,
        git_commit=None,
        seeds=dict(seeds),
        synthetic_data=True,
        notes=(
            f"{row.verdict.value} delta={row.delta!r} with={row.with_value!r} "
            f"without={row.without_value!r} contained with={row.with_contained!r} "
            f"without={row.without_contained!r}; simulated host, {row.experiment_id}"
        ),
    )
    return experiment_id


assert len(EXPERIMENTS) == 50, "architecture §41 names exactly fifty experiments"
assert set(ABLATION_FLAG_ORDER) == set(REFERENCE_FLAGS), "every planner flag must be ablatable"
assert set(BASELINES) == {f"B{index}" for index in range(1, 10)}, "§7 names nine baselines"
