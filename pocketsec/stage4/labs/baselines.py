"""§7's eight baselines — the dumbest things that could work, as the comparison.

These are not a formality. Stage 2 rejected its own central thesis against controls
like these (ADR-0010: at equal detection a TCN cost 6.6 µs/event against DTL-C's
22.3), and Stage 4's multi-world machinery faces the same bar against **B1
SingleWorldMAP**, which is the same engine with ``max_worlds=1``. On synthetic data B1
may well win, and if it does, ADR-0036 says so and recommends removal.

B1 and the mechanism live here; B2–B8 live in ``labs/simple_baselines.py`` and the
shared replay/metric types in ``labs/baseline_metrics.py``. The split is on the line
that matters — B1 is the mechanism with one world, and that identity is only credible
if it is literally the same code path — and it keeps every module inside the
repository's ~800-line limit.

Every baseline runs in the **same process** with the **same replays** as the mechanism
it controls: :func:`run_baselines` replays the corpus once and hands the same bundles
to all nine rows. Two separate runs on this host would be indistinguishable from load
— a Stage 2 gate read the same passes as 7x slower at load 23-67 than at load 8-12 —
so only within-run ratios are reported and ``/proc/loadavg`` rides on every comparison.

**Three non-negotiable rules, each of which this project has paid to learn.**

1. **Every baseline must beat the corpus base rate or the comparison is REFUSED, not
   reported.** A model below chance is a bug, not a weak architecture (``MEMORY.md``
   trap 2). :attr:`BaselineComparison.refused` names them and
   :attr:`BaselineComparison.reportable` drops them.
2. **The saturation guard runs first.** If best and median detection accuracy are
   within :data:`SATURATION_EPSILON`, the split cannot separate mechanisms and
   *nothing* is reported: Stage 2's G2.2 reported ``ORDER_FREE_BASELINE_TIES_BEST``
   with best 1.0 and median 0.6586, and a frontier computed on such a split measures
   the split.
3. **Same run, same seed family, same process, loadavg recorded.**

**Two of §42's named baselines are absent and that is declared, not hidden:** the
dynamic Bayesian network and the tiny GNN both need numerical linear algebra, which
ADR-0030 forbids in Stage 4. A hand-rolled stdlib DBN would be a *worse* comparison
than none, because a slow or wrong baseline flatters the mechanism — Stage 2's
detached projection scored 0.55 and 0.94 once fixed. :data:`UNBUILDABLE_BASELINES`
carries all four absent comparisons with their reasons so the honesty ledger can quote
it rather than paraphrase it.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from statistics import median
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.observation.policy import AdaptiveObservationPolicy
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage1.telemetry.raw_event_v1 import SensorPath
from pocketsec.stage4.engine.lucid import LucidConfig, LucidEngine
from pocketsec.stage4.identifiability.resolution import IdentifiabilityState
from pocketsec.stage4.labs.baseline_metrics import (
    EVIDENCE_LOAD_WEIGHT,
    BaselineOutcome,
    Replay,
    accuracy_of,
    efficiency_of,
    loadavg,
    predicted_label,
    replay_corpus,
)
from pocketsec.stage4.labs.incident_corpus import IncidentCase, build_incident_corpus
from pocketsec.stage4.labs.simple_baselines import (
    always_on_rich_telemetry,
    fixed_window_correlation,
    information_gain_planner,
    naive_ancestry,
    no_stage4,
    phi_threshold_playbook,
    two_state_hmm,
)
from pocketsec.stage4.sensing.simulate import signal_payload_bytes
from pocketsec.stage4.visibility.model import (
    VisibilityModel,
    fit_visibility_model,
    measure_visibility,
)

__all__ = [
    "BASELINE_REGISTRY",
    "EVIDENCE_LOAD_WEIGHT",
    "SATURATION_EPSILON",
    "UNBUILDABLE_BASELINES",
    "BaselineComparison",
    "BaselineOutcome",
    "Replay",
    "cbf_lucid",
    "compare_baselines",
    "pareto_frontier",
    "replay_corpus",
    "run_baselines",
    "run_engine_baseline",
    "saturation_guard",
    "single_world_map",
]

#: Best-minus-median below this and the split is degenerate. 0.01 is Stage 2's own
#: threshold, kept so the two waves' saturation verdicts are comparable.
SATURATION_EPSILON: float = 0.01

#: §42 baselines that cannot be built under ADR-0030, with the reason each. Declared
#: rather than omitted: four of §42's nine named comparisons are absent, and a reader
#: who does not know that would over-read the frontier.
UNBUILDABLE_BASELINES: Mapping[str, str] = MappingProxyType(
    {
        "dynamic_bayesian_network": (
            "needs numerical linear algebra; ADR-0030 forbids numpy in Stage 4, and a "
            "hand-rolled stdlib DBN would flatter the mechanism by being slow or wrong"
        ),
        "tiny_gnn": "same reason as the DBN: no numpy under ADR-0030",
        "provenance_graph_scoring": (
            "an external system (Orthrus-like); not present in this repository. B2 and B5 "
            "cover the cheap end of the same axis and are partial substitutes, not equivalents"
        ),
        "llm_incident_summarizer": (
            "no language model exists in this repository; D4.15 measures the guard, which is "
            "the part that matters for hallucination cost"
        ),
    }
)


@dataclass(frozen=True, slots=True)
class BaselineComparison:
    """The whole comparison, with its refusals and its saturation verdict attached.

    ``degenerate`` and ``refused`` are the two ways this object says *do not read the
    frontier*. Both are first-class rather than exceptions, because "the split cannot
    separate mechanisms" is a result about the corpus and deserves to be recorded.
    """

    outcomes: tuple[BaselineOutcome, ...]
    base_rate: float
    degenerate: bool
    degenerate_reason: str
    refused: tuple[tuple[str, str], ...]
    loadavg: tuple[float, float, float]

    @property
    def reportable(self) -> tuple[BaselineOutcome, ...]:
        """Outcomes the rules permit reporting: none at all on a degenerate split."""
        if self.degenerate:
            return ()
        refused = {name for name, _ in self.refused}
        return tuple(item for item in self.outcomes if item.baseline_id not in refused)

    def frontier(self) -> tuple[tuple[str, ...], tuple[str, ...]]:
        return pareto_frontier(self.reportable)

    def to_dict(self) -> dict[str, Any]:
        frontier, dominated = self.frontier()
        return {
            "base_rate": self.base_rate,
            "degenerate": self.degenerate,
            "degenerate_reason": self.degenerate_reason,
            "refused": [list(row) for row in self.refused],
            "frontier": list(frontier),
            "dominated": list(dominated),
            "outcomes": [item.to_dict() for item in self.outcomes],
            "loadavg": list(self.loadavg),
            "unbuildable": dict(UNBUILDABLE_BASELINES),
        }




# --- B1 and the mechanism it controls ----------------------------------------


def _score_case(
    engine: LucidEngine, replay: Replay, tally: dict[str, float]
) -> None:
    """Run one incident through the engine and fold its scores into ``tally``.

    Split out of :func:`run_engine_baseline` to keep that function inside the
    repository's ~50-line guidance; the metric definitions are what a reader has to
    audit and they are easier to audit on their own.
    """
    case = replay.case
    epoch = replay.result.transitions[0].epoch_id if replay.result.transitions else 0
    field = engine.open_incident(case.incident_id, epoch)
    spine = replay.pipeline.causal.spine()
    for transition in replay.result.transitions:
        field = engine.update(field, transition, spine).field
    resolution = engine.resolve(field)
    engine.close_incident(field)

    # "Preserves the ground-truth world **or an equivalent explanation**" (G4.2), read
    # as observable coverage rather than as a label match: the engine's mechanism
    # vocabulary is its own, and scoring it against the corpus's labels would measure
    # the naming rather than the reasoning.
    if any(
        replay.truth_signals <= (w.expected_evidence | w.visibility_requirements)
        for w in field.worlds
    ):
        tally["covered"] += 1
    identified = resolution.verdict.state is IdentifiabilityState.IDENTIFIED
    if identified and (
        case.truth.discriminating_signal is None
        or case.truth.discriminating_signal not in replay.observed
    ):
        tally["premature"] += 1
    if replay.expects_unidentifiable:
        tally["nonident_total"] += 1
        if resolution.verdict.state is IdentifiabilityState.UNIDENTIFIABLE:
            tally["nonident_hits"] += 1
    tally["unsupported"] += len(resolution.claim_graph.unsupported_authoritative())
    tally["claims_read"] += len(resolution.compiled)
    tally["telemetry"] += signal_payload_bytes(sorted(replay.observed))
    predicted = predicted_label(resolution.prediction_verdict)
    if predicted is not None:
        tally["committed"] += 1
        if predicted == case.label:
            tally["detect_hits"] += 1


def run_engine_baseline(
    replays: Sequence[Replay],
    model: VisibilityModel,
    config: LucidConfig,
    *,
    baseline_id: str,
) -> BaselineOutcome:
    """Run the LUCID engine over the replays under one configuration.

    Shared by B1 (``max_worlds=1``, no fission/fusion), by the full mechanism and by the
    ablation, because "the control is the same engine with one world" is only true if it
    is literally the same code path.
    """
    # With Stage 1's AOP. Without one the planner refused every discriminating action
    # for "no observation policy", identifiability certified those incidents
    # UNIDENTIFIABLE, and this row's nonidentifiability_accuracy was scored on answers
    # produced by the wiring (S4-REV-03).
    engine = LucidEngine(
        config=config, visibility=model, observation=AdaptiveObservationPolicy()
    )
    tally: dict[str, float] = dict.fromkeys(
        (
            "committed",
            "covered",
            "premature",
            "nonident_total",
            "nonident_hits",
            "unsupported",
            "claims_read",
            "telemetry",
            "detect_hits",
        ),
        0.0,
    )
    started = time.process_time()
    for replay in replays:
        _score_case(engine, replay, tally)
    cpu = time.process_time() - started
    total = len(replays)
    telemetry = int(tally["telemetry"])
    return BaselineOutcome(
        baseline_id=baseline_id,
        world_set_recall=accuracy_of(int(tally["covered"]), total),
        premature_collapse_rate=accuracy_of(int(tally["premature"]), total),
        nonidentifiability_accuracy=accuracy_of(
            int(tally["nonident_hits"]), int(tally["nonident_total"])
        ),
        unsupported_claim_count=int(tally["unsupported"]),
        telemetry_bytes=telemetry,
        cpu_units=cpu,
        work_units=engine.work_units,
        resolution_efficiency=efficiency_of(
            int(tally["detect_hits"]),
            cpu=cpu,
            telemetry=telemetry,
            claims=int(tally["claims_read"]),
        ),
        detection_accuracy=accuracy_of(int(tally["detect_hits"]), total),
        detection_coverage=accuracy_of(int(tally["committed"]), total),
        loadavg=loadavg(),
    )


def single_world_map(replays: Sequence[Replay], model: VisibilityModel, **_: Any) -> BaselineOutcome:
    """B1 — keep one world, never branch. The control for the entire CBF."""
    return run_engine_baseline(
        replays,
        model,
        LucidConfig(max_worlds=1, enable_fission_fusion=False),
        baseline_id="B1_SingleWorldMAP",
    )


def cbf_lucid(replays: Sequence[Replay], model: VisibilityModel, **_: Any) -> BaselineOutcome:
    """The mechanism itself, on the frontier beside its controls."""
    return run_engine_baseline(replays, model, LucidConfig(), baseline_id="CBF_LUCID")



#: Every row of §7's table plus the mechanism, so ``run_baselines`` cannot silently
#: omit a control. Keyed by the id that appears in the findings document.
BASELINE_REGISTRY: Mapping[str, Callable[..., BaselineOutcome]] = MappingProxyType(
    {
        "B1_SingleWorldMAP": single_world_map,
        "B2_NaiveAncestryAttribution": naive_ancestry,
        "B3_AlwaysOnRichTelemetry": always_on_rich_telemetry,
        "B4_PhiThresholdPlaybook": phi_threshold_playbook,
        "B5_FixedWindowCorrelation": fixed_window_correlation,
        "B6_TwoStateHMM": two_state_hmm,
        "B7_InformationGainPlanner": information_gain_planner,
        "B8_NoStage4": no_stage4,
        "CBF_LUCID": cbf_lucid,
    }
)


# --- the rules ---------------------------------------------------------------


def saturation_guard(outcomes: Sequence[BaselineOutcome]) -> tuple[bool, str]:
    """Rule 2 — is this split able to separate mechanisms at all?

    Degenerate when best minus median detection accuracy is within
    :data:`SATURATION_EPSILON`. Stage 2's G2.2 is the precedent and the warning: a
    frontier computed on a split that cannot separate mechanisms measures the split.
    """
    scores = [
        item.detection_accuracy for item in outcomes if item.detection_accuracy is not None
    ]
    if len(scores) < 2:
        return True, f"only {len(scores)} baselines produced a comparable score"
    best = max(scores)
    middle = median(scores)
    if best - middle <= SATURATION_EPSILON:
        return True, (
            f"SATURATED: best {best:.4f} within {SATURATION_EPSILON} of median {middle:.4f}"
        )
    return False, f"best {best:.4f} vs median {middle:.4f}"


def _refusals(
    outcomes: Sequence[BaselineOutcome], base_rate: float
) -> tuple[tuple[str, str], ...]:
    """Rule 1 — a baseline at or below chance is a bug, and its row is refused."""
    refused: list[tuple[str, str]] = []
    for item in outcomes:
        if item.detection_accuracy is None:
            refused.append((item.baseline_id, "no comparable detection accuracy"))
        elif item.detection_accuracy <= base_rate:
            refused.append(
                (
                    item.baseline_id,
                    f"detection accuracy {item.detection_accuracy:.4f} <= base rate "
                    f"{base_rate:.4f}; a model at or below chance is a bug",
                )
            )
    return tuple(refused)


#: Axes the frontier is computed over: higher is better for the first three, lower for
#: the rest. Closed, so a later contributor cannot quietly add an axis on which the
#: mechanism happens to lead.
_MAXIMISE = ("world_set_recall", "nonidentifiability_accuracy", "resolution_efficiency")
_MINIMISE = ("premature_collapse_rate", "cpu_units", "telemetry_bytes", "work_units")


def pareto_frontier(
    outcomes: Sequence[BaselineOutcome],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return ``(frontier, dominated)`` baseline ids.

    A ``None`` metric makes that axis **incomparable** for the pair rather than
    zero-valued: a baseline that did not attempt world recall must not be dominated on
    it, and must not dominate on it either. Two baselines whose comparable axes all
    tie are both on the frontier, because a tie is not domination.
    """
    ids = [item.baseline_id for item in outcomes]
    by_id = {item.baseline_id: item for item in outcomes}
    dominated: set[str] = set()
    for candidate in ids:
        for rival in ids:
            if rival == candidate:
                continue
            if _dominates(by_id[rival], by_id[candidate]):
                dominated.add(candidate)
                break
    frontier = tuple(sorted(item for item in ids if item not in dominated))
    return frontier, tuple(sorted(dominated))


def _dominates(winner: BaselineOutcome, loser: BaselineOutcome) -> bool:
    strictly_better = False
    for axis in _MAXIMISE:
        left, right = getattr(winner, axis), getattr(loser, axis)
        if left is None or right is None:
            continue
        if left < right:
            return False
        if left > right:
            strictly_better = True
    for axis in _MINIMISE:
        left, right = getattr(winner, axis), getattr(loser, axis)
        if left is None or right is None:
            continue
        if left > right:
            return False
        if left < right:
            strictly_better = True
    return strictly_better


def run_baselines(
    corpus: Sequence[IncidentCase],
    *,
    seed: int,
    train: Sequence[IncidentCase] | None = None,
    model: VisibilityModel | None = None,
) -> tuple[BaselineOutcome, ...]:
    """Run all eight baselines plus the mechanism, in one process, on one replay set.

    ``train`` defaults to a corpus built from ``seed ^ 0xB6`` so B6 is never fitted on
    the split it scores. ``model`` defaults to a visibility model fitted from the same
    replays through both simulated sensor paths.
    """
    if not corpus:
        raise ContractError("run_baselines needs a non-empty corpus")
    replays = replay_corpus(corpus)
    train_cases = train if train is not None else build_incident_corpus(
        count=max(4, len(corpus)), seed=seed ^ 0xB6
    )
    train_replays = replay_corpus(train_cases)
    fitted = model if model is not None else fit_visibility_model(
        measure_visibility(
            Stage1Pipeline,
            [case.scenario for case in corpus],
            [SensorPath.EBPF, SensorPath.AUDITD],
        )
    )
    outcomes: list[BaselineOutcome] = []
    for baseline_id in sorted(BASELINE_REGISTRY):
        outcomes.append(
            BASELINE_REGISTRY[baseline_id](replays, fitted, train=train_replays)
        )
    return tuple(outcomes)


def compare_baselines(
    corpus: Sequence[IncidentCase],
    *,
    seed: int,
    base_rate: float | None = None,
    train: Sequence[IncidentCase] | None = None,
) -> BaselineComparison:
    """Run the comparison and apply all three rules. G4.10 reads exactly this.

    ``base_rate`` defaults to the **corpus under test**'s own positive fraction.
    ``Stage2Dataset.base_rate`` may be passed instead; the corpus's own rate is the
    default because comparing against a different split's base rate would refuse or
    admit a baseline for a reason that has nothing to do with this measurement.
    """
    outcomes = run_baselines(corpus, seed=seed, train=train)
    rate = (
        base_rate
        if base_rate is not None
        else (sum(case.label for case in corpus) / len(corpus))
    )
    degenerate, reason = saturation_guard(outcomes)
    return BaselineComparison(
        outcomes=outcomes,
        base_rate=float(rate),
        degenerate=degenerate,
        degenerate_reason=reason,
        refused=_refusals(outcomes, float(rate)),
        loadavg=loadavg(),
    )
