"""D2.14 / D2.2 / D2.1 — the Stage 2 resource, robustness, drift, attribution and
ablation report (research only, ADR-0008).

This module answers one question per component: **does it beat the dumbest thing
that could work?** (spec §5). It answers with four words only — ``JUSTIFIED``,
``REJECTED``, ``NOT_YET_JUSTIFIED``, ``UNMEASURABLE`` — and every number beside
one of those words was produced by running the code named in ``measured_by``.

What this module refuses to do:

* It refuses to record any component delta on a corpus the degeneracy guard
  rejects (:mod:`pocketsec.stage2.research.saturation`). On a degenerate split
  every verdict becomes ``UNMEASURABLE``, never ``NOT_YET_JUSTIFIED`` and never
  ``JUSTIFIED`` — a component cannot be credited by a corpus-size artefact.
* It refuses to report ``PATH_COST_UNITS`` as calibrated. That table's docstring
  claims calibration from measured CPU time and no calibration code exists
  anywhere in the repository; this module measures per-``WorkKind`` wall clock
  instead and marks the declared ladder ``UNMEASURED``.
* It refuses to build a second harness. Security metrics come from
  ``stage0.benchmark.security_metrics``, resources from ``ResourceSampler`` plus
  ``check_profile``, corpora from Stage 1's builders through
  :class:`Stage1Pipeline`, and the ledger from ``stage0.experiments.registry``.
* It refuses to sweep a latent dimension whose fastest convolution block would be
  zero-width or negative. ``DTLConvConfig.block_sizes()`` returns ``fast=-2`` at
  ``latent=8`` (a numpy ``ValueError``) and ``fast=0`` at ``latent=10``, where the
  model trains happily with its fastest timescale entirely absent — measured this
  session. ``experiments.latent_sweep`` still defaults to a first point that
  crashes.

Traps this module is written against, all of which have already produced a wrong
answer in this repository (``planning/MEMORY.md``):

* ``sleeping_brain_report`` and ``experiments._evaluate`` call ``.fit()``
  themselves, and ``_TorchLikeModule.fit`` *continues* training rather than
  restarting. Every model handed to them here is freshly constructed.
* ``len(dataset)`` is a sample count and ``dataset.transition_count`` is an event
  count. Mixing them rescales every per-event cost by the mean sequence length,
  so per-event figures here divide by the transition count, always.
* ``experiments.py`` drives the REJECTED recurrent ``DTLModel`` at all four entry
  points and never ``DTLConvModel``; nothing here calls it.
"""

from __future__ import annotations

import importlib
import time
from collections import Counter
from dataclasses import dataclass, field, replace
from statistics import mean
from typing import Any, Callable, Mapping

from pocketsec.stage0.benchmark.profiles import ProfileReport, check_profile
from pocketsec.stage0.benchmark.resource_metrics import ResourceMetrics, ResourceSampler
from pocketsec.stage0.benchmark.security_metrics import average_precision
from pocketsec.stage0.experiments.ids import format_experiment_id, parse_experiment_id
from pocketsec.stage1.labs.ambiguous_corpus import build_ambiguous_corpus
from pocketsec.stage1.labs.corpus import Scenario
from pocketsec.stage1.labs.hard_corpus import build_hard_corpus
from pocketsec.stage1.labs.longhorizon_corpus import build_long_horizon_corpus
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage1.ssir.relations import RelationFamily
from pocketsec.stage1.ssir.transition import SSIRTransitionV1
from pocketsec.stage1.state.potential import phi
from pocketsec.stage1.state.security_state import DIMENSIONS, SecurityStateV1
from pocketsec.stage2.adaptation.epoch_guard import (
    AdaptationPolicy,
    drift_report,
    run_adaptation,
)
from pocketsec.stage2.cache.transition_cache import (
    CachedTransition,
    TransitionCache,
    transition_cache_key,
)
from pocketsec.stage2.cache.utility import (
    forget_low_utility_memory,
    future_security_utility,
    lru_control,
    random_control,
)
from pocketsec.stage2.core_ids import CORE_IDS, PATH_COST_UNITS, REQUIRED_IDS
from pocketsec.stage2.gate_measures import (
    DRIFT_EPOCH_SIGNALS,
    STAGE2_INCREMENTAL_RSS_CEILING_BYTES,
    lineage_windows as _lineage_windows,
    lineage_windows_with_signatures as _lineage_windows_with_signatures,
    atom_pairs as _atom_pairs,
    build_lattice as _build_model,
    cone_distribution as _cone_distribution,
    cone_heads as _cone_heads,
    fold_state as _fold,
    hazard_base_rates as _hazard_base_rates,
    hazard_truth as _hazard_truth,
    multiclass_brier as _brier,
    next_transition as _next_transition,
    positions as _positions,
    walk,
)
from pocketsec.stage2.counterfactual.twin import counterfactual_probe, phi_only_probe
from pocketsec.stage2.credit.ledger import (
    CausalCreditLedger,
    chain_recall,
    naive_ancestry,
)
from pocketsec.stage2.dataset import Stage2Dataset, build_dataset
from pocketsec.stage2.encoder.ssir_encoder import (
    ENCODER_VERSION,
    EncodedTransition,
    encode_ssir_transition,
)
from pocketsec.stage2.labs.drift_corpus import build_drift_corpus, malicious_lineage
from pocketsec.stage2.labs.poison_suite import build_poison_suite, poison_lineage
from pocketsec.stage2.lattice.quantizer import (
    BehaviourQuantizer,
    HashBucketQuantizer,
    QuantizeResult,
)
from pocketsec.stage2.lattice.restructure import LatticeRestructurer
from pocketsec.stage2.lattice.transitions import TransitionLattice
from pocketsec.stage2.predictors.future_cone import (
    FutureCone,
    branch_label,
    marginal_cone,
    predict_future_cone,
)
from pocketsec.stage2.predictors.hazard import (
    HORIZONS,
    OUTCOME_DIMENSIONS,
    constant_hazard,
    estimate_security_hazard,
)
from pocketsec.stage2.research.baselines import (
    MLPBaseline,
    PhiOracleBaseline,
    TCNBaseline,
)
from pocketsec.stage2.research.dtl_conv import DTLC_BLOCKS, DTLConvConfig, DTLConvModel
from pocketsec.stage2.research.saturation import (
    CorpusDegenerate,
    SaturationVerdict,
    refuse_if_degenerate,
    saturation_check,
)
from pocketsec.stage2.research.sleeping_brain import sleeping_brain_report
from pocketsec.stage2.router.accounting import MAX_LEDGER_EVENTS, WorkKind, WorkLedger
from pocketsec.stage2.state.window import MAX_WINDOW, WindowStore
from pocketsec.stage2.uncertainty.abstention import estimate_uncertainty, one_minus_max
from pocketsec.stage2.uncertainty.calibration import (
    expected_calibration_error,
    reliability_bins,
)

__all__ = [
    "DEFAULT_LATENT_DIMENSIONS",
    "MIN_BLOCK_WIDTH",
    "STAGE2_INCREMENTAL_RSS_CEILING_BYTES",
    "UNMEASURED",
    "VERDICT_JUSTIFIED",
    "VERDICT_NOT_YET",
    "VERDICT_REJECTED",
    "VERDICT_UNMEASURABLE",
    "ComponentVerdict",
    "Stage2Report",
    "block_width_floor",
    "build_report",
    "core_id_audit",
    "latent_frontier",
    "runtime_path",
    "safe_latent_dimensions",
]

VERDICT_JUSTIFIED = "JUSTIFIED"
VERDICT_REJECTED = "REJECTED"
VERDICT_NOT_YET = "NOT_YET_JUSTIFIED"
VERDICT_UNMEASURABLE = "UNMEASURABLE"
VALID_VERDICTS = frozenset(
    {VERDICT_JUSTIFIED, VERDICT_REJECTED, VERDICT_NOT_YET, VERDICT_UNMEASURABLE}
)

#: The word used wherever a figure could not be produced by running code.
UNMEASURED = "UNMEASURED"


#: A delta smaller than this is noise on these corpora, not an effect.
EFFECT_FLOOR: float = 0.005

#: Two detectors are "at equal PR-AUC" within this band. Same tolerance the
#: sleeping-brain Pareto check uses (``research/sleeping_brain.py:_pareto``), so
#: cost comparisons here and there mean the same thing.
QUALITY_TIE: float = 0.01

#: Φ is unbounded above; this is the stated scale that maps it into the [0, 1]
#: credit argument ``future_security_utility`` requires. It is a reporting
#: convention, not a measured constant.
PHI_CREDIT_SCALE: float = 16.0

#: Latent sizes that leave every DTL-C block at least this wide.
MIN_BLOCK_WIDTH: int = 1

#: Starts at 12, never 8 — see the module docstring.
DEFAULT_LATENT_DIMENSIONS: tuple[int, ...] = (12, 16, 24, 32, 48, 64, 96)

#: The shortest padded sequence ``DTLConvModel`` can process, measured this
#: session: at 64 steps it fits, at 63 ``_dilated_windows`` raises
#: ``ValueError: all the input array dimensions except for the concatenation axis
#: must match exactly`` (``research/dtl_conv.py:234``). The dilation-32 branch
#: left-pads by ``2 * 32`` and then slices ``batch[:, : steps - 64]``, which goes
#: negative below that. ``dtl_conv.py`` is frozen for this wave, so the report
#: refuses to feed it a corpus it cannot process instead of crashing on one.
DTL_CONV_MIN_STEPS: int = 2 * max(dilation for _, _, dilation in DTLC_BLOCKS)

#: Stage 2's experiment counter reached 0006; this wave starts here.
EXPERIMENT_SEQUENCE_START: int = 7

_MODULE = "pocketsec.stage2.research.stage2_report"

#: Core-id -> ``module:attribute`` of the stdlib-only implementation that closes
#: it. The D2.1 audit resolves each one by import, because a name in a frozen
#: registry is not evidence that the function exists.
CORE_ID_IMPLEMENTATIONS: dict[str, str] = {
    "DTL-F01": "pocketsec.stage2.encoder.ssir_encoder:encode_ssir_transition",
    "DTL-F02": "pocketsec.stage2.router.policy:route_information_need",
    "DTL-F03": "pocketsec.stage2.state.window:WindowStore.update_multiscale_state",
    "DTL-F04": "pocketsec.stage2.lattice.quantizer:BehaviourQuantizer.quantize_behaviour_atom",
    "DTL-F05": "pocketsec.stage2.predictors.future_cone:predict_future_cone",
    "DTL-F06": "pocketsec.stage2.predictors.heads:PredictiveHeads.predict_security_state_delta",
    "DTL-F07": "pocketsec.stage2.uncertainty.abstention:estimate_uncertainty",
    "DTL-F08": "pocketsec.stage2.predictors.hazard:estimate_security_hazard",
    "DTL-F09": "pocketsec.stage2.predictors.residual:score_prediction_residual",
    "DTL-F10": "pocketsec.stage2.credit.ledger:CausalCreditLedger.assign_causal_credit",
    "DTL-F11": "pocketsec.stage2.counterfactual.twin:counterfactual_probe",
    "DTL-F12": (
        "pocketsec.stage2.counterfactual.value_of_information"
        ":request_observation_escalation"
    ),
    "DTL-F13": "pocketsec.stage2.lattice.restructure:LatticeRestructurer.merge_equivalent_atoms",
    "DTL-F14": "pocketsec.stage2.lattice.restructure:LatticeRestructurer.split_heterogeneous_atom",
    "DTL-F15": "pocketsec.stage2.cache.utility:forget_low_utility_memory",
    "DTL-F16": "pocketsec.stage2.cache.transition_cache:TransitionCache.lookup_transition_cache",
    "DTL-F17": "pocketsec.stage2.compile_candidates.exporter:propose_compile_candidate",
    "DTL-F18": "pocketsec.stage2.adaptation.epoch_guard:detect_epoch_mismatch",
    "DTL-F19": "pocketsec.stage2.adaptation.quarantine:QuarantineBuffer.quarantine_adaptation_sample",
    "DTL-F20": (
        "pocketsec.stage2.compile_candidates.stage3_interface"
        ":export_evidence_bound_prediction"
    ),
}

_CORPUS_BUILDERS: dict[str, Any] = {
    "hard": build_hard_corpus,
    "long": build_long_horizon_corpus,
    "ambiguous": build_ambiguous_corpus,
}

_DRIFT_SIGNALS = DRIFT_EPOCH_SIGNALS


# --- verdict records ---------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ComponentVerdict:
    """One component, its control, and the measured gap between them."""

    component: str
    core_ids: tuple[str, ...]
    control: str
    metric: str
    with_component: float | None
    without_component: float | None
    delta: float | None
    experiment_id: str | None
    verdict: str
    detail: str = ""
    measured_by: str | None = None

    def __post_init__(self) -> None:
        if self.verdict not in VALID_VERDICTS:
            raise ValueError(f"unknown verdict {self.verdict!r}")
        if self.verdict != VERDICT_UNMEASURABLE and self.delta is None:
            raise ValueError(
                f"{self.component}: a {self.verdict} verdict needs a measured delta"
            )
        if self.verdict == VERDICT_JUSTIFIED and self.experiment_id is None:
            raise ValueError(f"{self.component}: JUSTIFIED needs an experiment id")
        if self.experiment_id is not None:
            # G2.12 joins a verdict to the ledger by this id. An id that does not
            # parse can never be found there, so it is rejected here rather than
            # travelling with a number as if it were provenance.
            parse_experiment_id(self.experiment_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "core_ids": list(self.core_ids),
            "control": self.control,
            "metric": self.metric,
            "with_component": _r(self.with_component),
            "without_component": _r(self.without_component),
            "delta": _r(self.delta),
            "experiment_id": self.experiment_id,
            "verdict": self.verdict,
            "detail": self.detail,
            "measured_by": self.measured_by,
        }


@dataclass(frozen=True, slots=True)
class Stage2Report:
    """The whole Stage 2 evidence record for one fixed ``(corpus, count, seed)``."""

    saturation: tuple[SaturationVerdict, ...]
    components: tuple[ComponentVerdict, ...]
    resources: dict[str, Any]
    drift: dict[str, Any]
    poisoning: dict[str, Any]
    attribution: dict[str, Any]
    latent_frontier: dict[str, Any]
    sleeping_brain: dict[str, Any]
    core_id_audit: dict[str, Any] = field(default_factory=dict)
    path_cost: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "saturation": [v.to_dict() for v in self.saturation],
            "components": [c.to_dict() for c in self.components],
            "resources": self.resources,
            "drift": self.drift,
            "poisoning": self.poisoning,
            "attribution": self.attribution,
            "latent_frontier": self.latent_frontier,
            "sleeping_brain": self.sleeping_brain,
            "core_id_audit": self.core_id_audit,
            "path_cost": self.path_cost,
            "provenance": self.provenance,
            "synthetic_data": True,
        }


def _r(value: float | None, digits: int = 4) -> float | None:
    return None if value is None else round(value, digits)


def _verdict(
    *,
    component: str,
    core_ids: tuple[str, ...],
    control: str,
    metric: str,
    with_component: float | None,
    without_component: float | None,
    experiment_id: str | None,
    higher_is_better: bool = True,
    detail: str = "",
    measured_by: str,
) -> ComponentVerdict:
    """Turn two measured numbers into one of the four words.

    ``higher_is_better`` fixes the sign convention in one place: ``delta`` is
    always *the component's advantage*, so a Brier score or a log-loss reads the
    same way as a PR-AUC and a reader cannot be misled by a metric whose good
    direction is down. When either side is ``None`` the row is ``UNMEASURABLE``:
    there is no half-measured comparison.
    """
    if with_component is None or without_component is None:
        return unmeasurable(
            component,
            core_ids,
            control,
            metric,
            reason=detail or "one side of the comparison produced no number",
        )
    raw = with_component - without_component
    delta = raw if higher_is_better else -raw
    if delta > EFFECT_FLOOR:
        verdict = VERDICT_JUSTIFIED
    elif delta < -EFFECT_FLOOR:
        verdict = VERDICT_REJECTED
    else:
        verdict = VERDICT_NOT_YET
    return ComponentVerdict(
        component=component,
        core_ids=core_ids,
        control=control,
        metric=metric,
        with_component=with_component,
        without_component=without_component,
        delta=delta,
        experiment_id=experiment_id,
        verdict=verdict,
        detail=detail,
        measured_by=measured_by,
    )


def unmeasurable(
    component: str,
    core_ids: tuple[str, ...],
    control: str,
    metric: str,
    *,
    reason: str,
) -> ComponentVerdict:
    """The honest verdict when the split cannot support a comparison."""
    return ComponentVerdict(
        component=component,
        core_ids=core_ids,
        control=control,
        metric=metric,
        with_component=None,
        without_component=None,
        delta=None,
        experiment_id=None,
        verdict=VERDICT_UNMEASURABLE,
        detail=reason,
    )


#: (component, core ids, control, metric) for every row of spec §5 this module
#: measures. The table is the single source of the component list, so a
#: refused corpus cannot silently shorten the report.
COMPONENT_ROWS: tuple[tuple[str, tuple[str, ...], str, str], ...] = (
    ("behaviour_atom_quantizer", ("DTL-F04",), "HashBucketQuantizer", "transition_log_loss"),
    ("transition_lattice", ("DTL-F04",), "relation_family_bigram", "next_family_top1"),
    ("merge_fission", ("DTL-F13", "DTL-F14"), "max_macro=0", "log_loss_per_kib"),
    ("future_cone", ("DTL-F05",), "marginal_cone", "branch_brier"),
    ("hazard_heads", ("DTL-F08",), "constant_hazard", "hazard_brier"),
    ("uncertainty", ("DTL-F07",), "one_minus_max", "expected_calibration_error"),
    ("multiscale_window", ("DTL-F03",), "window=1", "next_family_top1"),
    ("transition_cache", ("DTL-F16",), "lru_control", "hit_rate"),
    ("utility_forgetting", ("DTL-F15",), "lru_control/random_control", "hit_rate"),
    ("causal_credit", ("DTL-F10", "DTL-F11"), "naive_ancestry", "nodes_inspected_at_recall"),
    ("epoch_guard", ("DTL-F18",), "accept_everything", "malicious_patterns_normalised"),
    ("quarantine_promotion", ("DTL-F19",), "accept_everything", "poisoned_promotions"),
    ("compile_candidate_export", ("DTL-F17", "DTL-F20"), "phi_oracle", "microseconds_per_event"),
)

#: The rows whose delta is measured on the detection split, and which the
#: degeneracy guard therefore refuses. The other four are measured on their own
#: fixtures (drift corpus, poison suite, sleeping-brain frontier).
SPLIT_DEPENDENT_COMPONENTS: frozenset[str] = frozenset(
    {
        "behaviour_atom_quantizer",
        "transition_lattice",
        "merge_fission",
        "future_cone",
        "hazard_heads",
        "uncertainty",
        "multiscale_window",
        "transition_cache",
        "utility_forgetting",
    }
)


# --- corpus compilation ------------------------------------------------------


def compile_scenarios(scenarios: tuple[Scenario, ...]) -> tuple[tuple[SSIRTransitionV1, ...], ...]:
    """Replay scenarios through one fresh Stage 1 pipeline, as ``dataset.py`` does.

    A pipeline per split, never per report: sharing one across splits would let
    the training split warm the novelty engine that scores the evaluation split.
    """
    pipeline = Stage1Pipeline()
    return tuple(
        pipeline.run_scenario(scenario, offset=index).transitions
        for index, scenario in enumerate(scenarios)
    )


def _corpus(name: str, *, count: int, seed: int) -> tuple[Scenario, ...]:
    builder = _CORPUS_BUILDERS.get(name)
    if builder is None:
        raise ValueError(f"unknown corpus {name!r}; known: {sorted(_CORPUS_BUILDERS)}")
    return tuple(builder(count=count, seed=seed, split="eval"))


# --- the stdlib runtime path -------------------------------------------------


@dataclass(slots=True)
class RuntimeTrace:
    """What one pass of the runtime path produced, per event."""

    events: int = 0
    cache_resolved: int = 0
    inferred: int = 0
    atoms: list[int] = field(default_factory=list)
    distances: list[float] = field(default_factory=list)
    cones: list[FutureCone] = field(default_factory=list)
    uncertainty: list[float] = field(default_factory=list)
    abstentions: int = 0
    kind_seconds: dict[str, list[float]] = field(default_factory=dict)

    def record_time(self, kind: WorkKind, seconds: float) -> None:
        self.kind_seconds.setdefault(kind.value, []).append(seconds)

    def to_dict(self) -> dict[str, Any]:
        return {
            "events": self.events,
            "cache_resolved": self.cache_resolved,
            "inferred": self.inferred,
            "abstentions": self.abstentions,
        }


def runtime_path(
    transitions: tuple[SSIRTransitionV1, ...],
    *,
    store: WindowStore,
    quantizer: Any,
    lattice: TransitionLattice,
    cache: TransitionCache,
    ledger: WorkLedger,
    collect: bool = False,
    max_events: int = MAX_LEDGER_EVENTS,
) -> RuntimeTrace:
    """One pass of the whole stdlib path, with every unit of work accounted.

    The order is the one the spec fixes: ``WindowStore`` → ``BehaviourQuantizer``
    → ``TransitionLattice`` → ``TransitionCache`` → ``predict_future_cone`` →
    ``estimate_uncertainty``. Nothing here imports a research model; this is the
    path that would run on a 2 GB host.

    A cache hit **genuinely skips** the cone and the uncertainty estimate. That
    is not an optimisation, it is the honesty requirement: the cache writes a
    ``performed=False`` record for ``CORE_INFERENCE`` on a hit, and if this
    function then ran the inference anyway the ledger's
    ``assert_no_phantom_savings()`` would refuse the run — which is exactly the
    ADR-0010 defect it exists to catch.

    ``max_events`` matches the ledger's own bound; beyond it the ledger stops
    retaining accounts and ``truncated()`` says so, so the pass stops with it.
    """
    trace = RuntimeTrace()
    states: dict[str, SecurityStateV1] = {}
    previous_atom: dict[str, int] = {}

    for transition in transitions[:max_events]:
        ledger.begin(f"{transition.causal_signature}:{transition.sequence}")
        window = _timed(
            trace,
            WorkKind.WINDOW_UPDATE,
            ledger,
            1.0,
            store.update_multiscale_state,
            transition,
        )
        key = window.lineage_key
        state = _fold(states.get(key, SecurityStateV1()), transition)
        states[key] = state
        encoded = encode_ssir_transition(transition, actor_slot=0)
        result: QuantizeResult = _timed(
            trace,
            WorkKind.LATTICE_LOOKUP,
            ledger,
            2.0,
            quantizer.quantize_behaviour_atom,
            encoded,
            state=state,
            epoch_id=transition.epoch_id,
            sequence=transition.sequence,
        )
        source = previous_atom.get(key)
        if source is not None:
            _timed(
                trace,
                WorkKind.LATTICE_LOOKUP,
                ledger,
                2.0,
                lattice.observe,
                source,
                result.atom_id,
                epoch_id=transition.epoch_id,
                delta_phi=transition.delta_phi,
                uncertainty=transition.uncertainty,
            )
        previous_atom[key] = result.atom_id
        hit = _cache_step(trace, ledger, cache, encoded, result, state, transition)
        if hit is None:
            _deep_step(trace, ledger, transition, state, result, lattice, quantizer, collect)
        else:
            trace.cache_resolved += 1
        ledger.close()
        trace.events += 1
        if collect:
            trace.atoms.append(result.atom_id)
            trace.distances.append(result.distance)
    return trace


def _deep_step(
    trace: RuntimeTrace,
    ledger: WorkLedger,
    transition: SSIRTransitionV1,
    state: SecurityStateV1,
    result: QuantizeResult,
    lattice: TransitionLattice,
    quantizer: Any,
    collect: bool,
) -> None:
    """The expensive half of the path, run only when the cache could not answer."""
    cone = _timed(
        trace,
        WorkKind.CONE_EXPANSION,
        ledger,
        8.0,
        predict_future_cone,
        lattice,
        quantizer,
        from_atom=result.atom_id,
        state=state,
        epoch_id=transition.epoch_id,
    )
    estimate = _timed(
        trace,
        WorkKind.CORE_INFERENCE,
        ledger,
        40.0,
        estimate_uncertainty,
        heads=_cone_heads(cone),
        cone=cone,
        prototype_distance=result.distance,
        transition=transition,
        phi_total=phi(state).total,
    )
    trace.inferred += 1
    trace.abstentions += int(estimate.abstain)
    if collect:
        trace.cones.append(cone)
        trace.uncertainty.append(estimate.value)


def _timed(
    _trace: RuntimeTrace,
    _kind: WorkKind,
    _ledger: WorkLedger,
    _units: float,
    _call: Callable[..., Any],
    /,
    *args: Any,
    **kwargs: Any,
) -> Any:
    """Run one unit of work, time it, and record that it genuinely ran.

    ``performed=True`` is written only after the call returned, so the ledger
    cannot claim work that was skipped — the defect ADR-0010 recorded. The
    leading parameters are positional-only so a wrapped callable may take its own
    ``ledger`` keyword without colliding with this one.
    """
    started = time.perf_counter()
    value = _call(*args, **kwargs)
    elapsed = time.perf_counter() - started
    _trace.record_time(_kind, elapsed)
    _ledger.record(_kind, performed=True, units=_units, detail=getattr(_call, "__name__", ""))
    return value


def _cache_step(
    trace: RuntimeTrace,
    ledger: WorkLedger,
    cache: TransitionCache,
    encoded: EncodedTransition,
    result: QuantizeResult,
    state: SecurityStateV1,
    transition: SSIRTransitionV1,
) -> CachedTransition | None:
    """Look the transition up, and store it on a miss.

    The stored entry is pinned to the cache's own versions; storing under any
    other pair raises, which is how a stale-weight hit is made impossible.
    """
    started = time.perf_counter()
    hit = cache.lookup_transition_cache(
        atom_id=result.atom_id,
        epoch_id=encoded.epoch_id,
        state_delta_mask=encoded.state_delta_mask,
        ledger=ledger,
    )
    trace.record_time(WorkKind.CACHE_LOOKUP, time.perf_counter() - started)
    if hit is not None:
        return hit
    cache.store(
        CachedTransition(
            key=transition_cache_key(
                atom_id=result.atom_id,
                epoch_id=encoded.epoch_id,
                state_delta_mask=encoded.state_delta_mask,
            ),
            atom_id=result.atom_id,
            epoch_id=encoded.epoch_id,
            model_version=cache.model_version,
            encoder_version=cache.encoder_version,
            predicted_delta=state.delta_from(SecurityStateV1()),
            predicted_phi=phi(state).total,
            uncertainty=transition.uncertainty,
            hits=0,
            utility=0.0,
            last_sequence=max(0, transition.sequence),
        )
    )
    return None


# --- resource measurement ----------------------------------------------------


def resource_report(
    transitions: tuple[SSIRTransitionV1, ...], *, max_events: int = MAX_LEDGER_EVENTS
) -> dict[str, Any]:
    """Measure the runtime path with ``ResourceSampler`` and the Edge profile.

    ``max_events`` is the ledger's own retention bound: past it the accounting
    stops being complete, so the measured window stops with it and the reported
    event count says how many events it covered.
    """
    store = WindowStore()
    quantizer = BehaviourQuantizer()
    lattice = TransitionLattice()
    cache = TransitionCache(model_version="stage2-report", encoder_version=ENCODER_VERSION)
    ledger = WorkLedger()

    with ResourceSampler(interval_seconds=0.01) as sampler:
        trace = runtime_path(
            transitions,
            store=store,
            quantizer=quantizer,
            lattice=lattice,
            cache=cache,
            ledger=ledger,
            max_events=max_events,
        )
    metrics: ResourceMetrics = sampler.result(
        events_processed=trace.events, startup_seconds=None
    )
    model_bytes = (
        quantizer.memory_bytes() + lattice.memory_bytes() + store.memory_bytes()
    )
    profile: ProfileReport = check_profile(metrics, "edge", model_bytes=model_bytes)
    ledger.assert_no_phantom_savings()
    return {
        "events": trace.events,
        "trace": trace.to_dict(),
        "ledger_truncated": ledger.truncated(),
        "metrics": metrics.to_dict(),
        "profile": profile.to_dict(),
        "within_target": profile.within_target,
        "model_bytes": model_bytes,
        "component_bytes": {
            "window_store": store.memory_bytes(),
            "quantizer": quantizer.memory_bytes(),
            "lattice": lattice.memory_bytes(),
            "cache": cache.stats().memory_bytes,
        },
        "incremental_rss_bytes": metrics.delta_rss_bytes,
        "incremental_rss_ceiling_bytes": STAGE2_INCREMENTAL_RSS_CEILING_BYTES,
        "within_incremental_ceiling": (
            None
            if metrics.delta_rss_bytes is None
            else metrics.delta_rss_bytes <= STAGE2_INCREMENTAL_RSS_CEILING_BYTES
        ),
        "work_histogram": ledger.histogram(),
        "path_fractions": ledger.path_fractions(),
        "cache": cache.stats().to_dict(),
        "measured_by": f"{_MODULE}:resource_report",
    }


def path_cost_report(
    transitions: tuple[SSIRTransitionV1, ...], *, max_events: int = MAX_LEDGER_EVENTS
) -> dict[str, Any]:
    """Measure per-``WorkKind`` wall clock, and refuse to call the ladder calibrated.

    ``PATH_COST_UNITS``' docstring says it is "calibrated from measured CPU time
    in ``research.sleeping_brain``". No such calibration exists in this
    repository, so the declared ladder is reported ``UNMEASURED`` beside the
    figures that *were* measured here.
    """
    store = WindowStore()
    lattice = TransitionLattice()
    cache = TransitionCache(model_version="stage2-report", encoder_version=ENCODER_VERSION)
    ledger = WorkLedger()
    trace = runtime_path(
        transitions,
        store=store,
        quantizer=BehaviourQuantizer(),
        lattice=lattice,
        cache=cache,
        ledger=ledger,
        max_events=max_events,
    )
    per_kind = {
        kind: mean(samples) * 1e6
        for kind, samples in sorted(trace.kind_seconds.items())
        if samples
    }
    cheapest = min(per_kind.values()) if per_kind else None
    return {
        "declared_path_cost_units": {p.value: PATH_COST_UNITS[p] for p in PATH_COST_UNITS},
        "declared_status": UNMEASURED,
        "declared_status_detail": (
            "PATH_COST_UNITS claims calibration from measured CPU time; no "
            "calibration code exists in the repository. It remains a policy "
            "simulation. The honest cost number is wall-clock us/event."
        ),
        "measured_microseconds_by_work_kind": {k: round(v, 3) for k, v in per_kind.items()},
        "measured_relative_units": (
            None
            if cheapest in (None, 0.0)
            else {k: round(v / cheapest, 2) for k, v in per_kind.items()}
        ),
        "microseconds_per_event": (
            round(sum(sum(s) for s in trace.kind_seconds.values()) / trace.events * 1e6, 3)
            if trace.events
            else None
        ),
        "events": trace.events,
        "measured_by": f"{_MODULE}:path_cost_report",
    }


# --- D2.1 audit --------------------------------------------------------------


def core_id_audit() -> dict[str, Any]:
    """Assert every ``CoreFunction`` now resolves to real stdlib-only code.

    D2.1 froze twenty names. This checks that they are no longer only names, by
    importing the module and resolving the attribute — a docstring naming a
    function is not evidence that the function exists.
    """
    resolved: list[dict[str, str]] = []
    unresolved: list[dict[str, str]] = []
    for core_id in sorted(CORE_IDS):
        target = CORE_ID_IMPLEMENTATIONS.get(core_id)
        if target is None:
            unresolved.append({"core_id": core_id, "reason": "no implementation mapped"})
            continue
        module_name, attribute = target.split(":", 1)
        row = {"core_id": core_id, "implementation": target}
        try:
            obj: Any = importlib.import_module(module_name)
            for part in attribute.split("."):
                obj = getattr(obj, part)
        except (ImportError, AttributeError) as exc:
            unresolved.append({**row, "reason": f"{type(exc).__name__}: {exc}"})
            continue
        if not callable(obj):
            unresolved.append({**row, "reason": "resolved but not callable"})
            continue
        resolved.append(row)
    missing_required = sorted(
        core_id for core_id in REQUIRED_IDS
        if core_id not in {row["core_id"] for row in resolved}
    )
    return {
        "core_ids": len(CORE_IDS),
        "resolved": resolved,
        "unresolved": unresolved,
        "required_ids": sorted(REQUIRED_IDS),
        "required_unresolved": missing_required,
        "all_required_resolved": not missing_required,
        "measured_by": f"{_MODULE}:core_id_audit",
    }


# --- the latent frontier and its block-width guard ---------------------------


def block_width_floor(latent: int) -> dict[str, int]:
    """The DTL-C block widths at ``latent``, whatever they come out as.

    Returned unfiltered on purpose: ``latent=8`` gives ``fast=-2`` and
    ``latent=10`` gives ``fast=0``, and a caller has to be able to see that
    rather than be protected from it.
    """
    return DTLConvConfig(latent=latent).block_sizes()


def safe_latent_dimensions(dimensions: tuple[int, ...]) -> tuple[int, ...]:
    """Refuse a sweep containing a latent size with a degenerate block.

    A zero-width "fast" block trains without complaint and silently removes the
    dilation-1 timescale, which makes the sweep's smallest point measure a
    different architecture from every other point.
    """
    for latent in dimensions:
        widths = block_width_floor(latent)
        thin = {name: width for name, width in widths.items() if width < MIN_BLOCK_WIDTH}
        if thin:
            raise ValueError(
                f"latent={latent} leaves blocks below width {MIN_BLOCK_WIDTH}: {thin}. "
                f"The DTL-C block shares are {[(n, s) for n, s, _ in DTLC_BLOCKS]}; "
                "start the sweep at 12."
            )
    return tuple(dimensions)


def latent_frontier(
    *,
    dimensions: tuple[int, ...] = DEFAULT_LATENT_DIMENSIONS,
    corpus: str,
    count: int,
    seed: int,
    epochs: int = 40,
    test_seed: int | None = None,
) -> dict[str, Any]:
    """The minimum-sufficient latent frontier, on a fixed ``(corpus, count, seed)``.

    Every point is a freshly constructed ``DTLConvModel``: handing an already
    fitted model to a second evaluation continues its training and invents an
    advantage for the later point.
    """
    safe_latent_dimensions(dimensions)
    train = build_dataset(name="frontier-train", count=count, seed=seed, corpus=corpus)
    test = build_dataset(
        name="frontier-test", count=count, seed=test_seed or seed + 8, corpus=corpus
    )
    excluded = dtl_conv_runnable(train, test)
    if excluded:
        # A frontier of the core without the core is not a frontier. Refusing is
        # the honest outcome; silently dropping the model would leave a knee that
        # describes nothing.
        raise ValueError(excluded)
    labels = list(test.labels)
    points: list[dict[str, Any]] = []
    for latent in dimensions:
        model = DTLConvModel(DTLConvConfig(latent=latent, epochs=epochs))
        model.fit(train)
        scores = model.predict_scores(test)
        points.append(
            {
                "latent": latent,
                "block_sizes": block_width_floor(latent),
                "pr_auc": _r(average_precision(labels, scores)),
                "parameters": model.resource_profile()["parameters"],
                "above_base_rate": (average_precision(labels, scores) or 0.0)
                > test.base_rate,
            }
        )
    best = max(points, key=lambda p: p["pr_auc"] or 0.0) if points else None
    knee = None
    if best is not None:
        acceptable = [
            p for p in points if (p["pr_auc"] or 0.0) >= (best["pr_auc"] or 0.0) - 0.01
        ]
        knee = min(acceptable, key=lambda p: p["latent"]) if acceptable else None
    return {
        "dimensions": list(dimensions),
        "points": points,
        "best": best,
        "knee": knee,
        "train": train.to_provenance(),
        "test": test.to_provenance(),
        "measured_by": f"{_MODULE}:latent_frontier",
    }


# --- component measurements --------------------------------------------------


def measure_atom_layer(
    train: tuple[tuple[SSIRTransitionV1, ...], ...],
    test: tuple[tuple[SSIRTransitionV1, ...], ...],
    *,
    experiment_id: str,
) -> ComponentVerdict:
    """Learned prototypes against the zero-training hash bucket, on log-loss."""
    learned = BehaviourQuantizer()
    control = HashBucketQuantizer()
    learned_lattice, _ = _build_model(learned, train)
    control_lattice, _ = _build_model(control, train)
    learned_loss = learned_lattice.log_loss(_atom_pairs(learned, test))
    control_loss = control_lattice.log_loss(_atom_pairs(control, test))
    return _verdict(
        component="behaviour_atom_quantizer",
        core_ids=("DTL-F04",),
        control="HashBucketQuantizer",
        metric="transition_log_loss",
        with_component=learned_loss,
        without_component=control_loss,
        experiment_id=experiment_id,
        higher_is_better=False,
        detail=(
            f"learned {learned.stats().atoms} atoms / {learned.memory_bytes()} B vs "
            f"bucket {control.stats().atoms} atoms / {control.memory_bytes()} B"
        ),
        measured_by=f"{_MODULE}:measure_atom_layer",
    )


def _family_sequences(
    sessions: tuple[tuple[SSIRTransitionV1, ...], ...],
) -> tuple[tuple[int, ...], ...]:
    """Relation families grouped the way ``WindowStore`` actually groups them.

    Per **causal lineage**, not per session. ``measure_window`` is the DTL-F03
    ablation, and DTL-F03 is ``WindowStore.update_multiscale_state``, which keys
    on the causal-signature root (ADR-0005/ADR-0119). Grouping by session instead
    fed the look-back offsets a stream the store never produces — sessions
    interleave several lineages — and the measured +0.0002 "null" was an artefact
    of that grouping: on the store's own per-lineage sequences the same offsets
    measure a *loss*, not a null (S2-FC-12).

    One store per session so the bound is exercised the way the runtime exercises
    it, and the family is read off the window the store returned rather than
    re-encoded, so this cannot drift from what the store holds.
    """
    sequences: list[tuple[int, ...]] = []
    for session in sessions:
        store = WindowStore()
        lineages: dict[str, list[int]] = {}
        for transition in session:
            window = store.update_multiscale_state(transition)
            lineages.setdefault(window.lineage_key, []).append(
                window.steps[-1].relation_family
            )
        sequences.extend(tuple(families) for families in lineages.values())
    return tuple(sequences)


def _family_context_accuracy(
    train: tuple[tuple[SSIRTransitionV1, ...], ...],
    test: tuple[tuple[SSIRTransitionV1, ...], ...],
    *,
    offsets: tuple[int, ...],
) -> float | None:
    """Top-1 next-family accuracy from a context of the given look-back offsets.

    The table is fitted on ``train`` only and backs off to the training marginal
    when the context was never seen, so a longer context cannot win by having
    memorised the evaluation split.
    """
    table: dict[tuple[int, ...], Counter[int]] = {}
    marginal: Counter[int] = Counter()
    span = max(offsets)

    def context(history: tuple[int, ...]) -> tuple[int, ...] | None:
        if len(history) < span:
            return None
        return tuple(history[-offset] for offset in offsets)

    for families in _family_sequences(train):
        for index, family in enumerate(families):
            key = context(families[:index])
            if key is not None:
                table.setdefault(key, Counter())[family] += 1
            marginal[family] += 1
    if not marginal:
        return None
    fallback = marginal.most_common(1)[0][0]

    correct = total = 0
    for families in _family_sequences(test):
        for index, family in enumerate(families):
            key = context(families[:index])
            counts = table.get(key) if key is not None else None
            predicted = counts.most_common(1)[0][0] if counts else fallback
            correct += int(predicted == family)
            total += 1
    return correct / total if total else None


def measure_lattice(
    train: tuple[tuple[SSIRTransitionV1, ...], ...],
    test: tuple[tuple[SSIRTransitionV1, ...], ...],
    *,
    experiment_id: str,
) -> ComponentVerdict:
    """The atom lattice against an order-1 relation-family bigram.

    Both predict the next relation family, so the eight-symbol space is shared
    and the comparison is like-for-like. The learned side asks the lattice for
    its most likely successor atom and reads that atom's modal family.
    """
    quantizer = BehaviourQuantizer()
    lattice, families = _build_model(quantizer, train)
    correct = total = 0
    for step in walk(quantizer, test):
        if step.previous_atom is None:
            continue
        successors = lattice.successors(step.previous_atom, limit=1)
        modal = (
            families.get(successors[0][0], Counter()).most_common(1) if successors else []
        )
        if modal:
            correct += int(modal[0][0] == step.encoded.relation_family)
        total += 1
    learned = correct / total if total else None
    bigram = _family_context_accuracy(train, test, offsets=(1,))
    return _verdict(
        component="transition_lattice",
        core_ids=("DTL-F04",),
        control="relation_family_bigram",
        metric="next_family_top1",
        with_component=learned,
        without_component=bigram,
        experiment_id=experiment_id,
        detail=(
            f"{total} held-out transitions, {len(lattice)} atom edges; the "
            "quantizer is online and keeps adapting while the split is walked, "
            "which the frozen bigram table does not"
        ),
        measured_by=f"{_MODULE}:measure_lattice",
    )


def measure_window(
    train: tuple[tuple[SSIRTransitionV1, ...], ...],
    test: tuple[tuple[SSIRTransitionV1, ...], ...],
    *,
    experiment_id: str,
) -> ComponentVerdict:
    """DTL-F03: the store's multi-scale taps (1, 2, 4 back) against window=1.

    This is now an ablation of ``WindowStore`` and not merely of "context
    width". ``_family_sequences`` groups by the causal lineage the store keys on,
    so the look-back offsets see the stream the store actually produces; the
    accuracy figures move when the store's grouping moves, which is what makes
    the DTL-F03 attribution legitimate.

    It used to group by *session*. Sessions interleave lineages, so the offsets
    were fed a stream the store never produces, and this function's own docstring
    said so — "it does not measure ``WindowStore`` itself ... the accuracy figures
    would be the same for any component that supplied the same taps" — while
    ``core_ids=("DTL-F03",)`` and ``docs/stage-2-findings.md`` attributed the
    number to the runtime multiscale state ADR-0119 keeps. Replacing the store
    with a stub that held nothing returned bit-identical accuracies, which proved
    the row was independent of the component it named (S2-FC-12).

    Corrected grouping, same offsets, same split (ambiguous count=240,
    seed=3/11): 0.5912 with the taps against 0.7099 at window=1, delta -0.1187.
    The row was NOT_YET_JUSTIFIED at +0.0002 and is REJECTED at -0.1187 — a
    measured loss, not a null. Still not a detection result: this is next-family
    top-1 under a majority-vote table.
    """
    multiscale = _family_context_accuracy(train, test, offsets=(1, 2, 4))
    single = _family_context_accuracy(train, test, offsets=(1,))
    store = WindowStore()
    for session in train[:1]:
        for transition in session:
            store.update_multiscale_state(transition)
    return _verdict(
        component="multiscale_window",
        core_ids=("DTL-F03",),
        control="window=1",
        metric="next_family_top1",
        with_component=multiscale,
        without_component=single,
        experiment_id=experiment_id,
        detail=(
            f"WindowStore(max_window={MAX_WINDOW}) holds "
            f"{store.stats().transitions_held} steps in {store.memory_bytes()} B"
        ),
        measured_by=f"{_MODULE}:measure_window",
    )


def measure_restructuring(
    train: tuple[tuple[SSIRTransitionV1, ...], ...],
    test: tuple[tuple[SSIRTransitionV1, ...], ...],
    *,
    experiment_id: str,
) -> ComponentVerdict:
    """Merging against no restructuring at all, on log-loss per kibibyte."""
    def fit(max_macro: int) -> tuple[float | None, int, int]:
        quantizer = BehaviourQuantizer()
        lattice, _ = _build_model(quantizer, train)
        restructurer = LatticeRestructurer(max_macro=max_macro)
        report = restructurer.merge_equivalent_atoms(quantizer, lattice)
        pairs = _atom_pairs(quantizer, test)
        loss = lattice.log_loss(pairs) if pairs else None
        kib = max(lattice.memory_bytes() + quantizer.memory_bytes(), 1) / 1024
        return (None if loss is None else loss / kib), report.merges, report.refused

    merged, merges, refused = fit(64)
    control, _, _ = fit(0)
    if merges == 0:
        # `fit(64)` and `fit(0)` produce identical lattices when nothing merged,
        # so the two arms are the same object measured twice and the delta is an
        # arithmetic identity, not a null result (S2-FC-04). The zero-merge
        # finding itself is real and is recorded in ADR-0115; what is not real
        # is calling the comparison "measured".
        return unmeasurable(
            "merge_fission",
            ("DTL-F13", "DTL-F14"),
            "max_macro=0",
            "log_loss_per_kib",
            reason=(
                f"0 merges occurred ({refused} refused on insufficient evidence), so "
                "max_macro=64 and max_macro=0 produced the same lattice and the two "
                "arms are one measurement counted twice"
            ),
        )
    return _verdict(
        component="merge_fission",
        core_ids=("DTL-F13", "DTL-F14"),
        control="max_macro=0",
        metric="log_loss_per_kib",
        with_component=merged,
        without_component=control,
        experiment_id=experiment_id,
        higher_is_better=False,
        detail=f"{merges} merges, {refused} refused on insufficient evidence",
        measured_by=f"{_MODULE}:measure_restructuring",
    )


def measure_future_cone(
    train: tuple[tuple[SSIRTransitionV1, ...], ...],
    test: tuple[tuple[SSIRTransitionV1, ...], ...],
    *,
    experiment_id: str,
) -> ComponentVerdict:
    """Cone branch probabilities against the epoch-marginal continuation."""
    quantizer = BehaviourQuantizer()
    lattice, _ = _build_model(quantizer, train)
    cone_scores: list[float] = []
    marginal_scores: list[float] = []
    successor = _next_transition(test)
    for step in walk(quantizer, test):
        following = successor.get(id(step.transition))
        if following is None:
            continue
        actual = branch_label(step.state, _fold(step.state, following))
        cone = predict_future_cone(
            lattice,
            quantizer,
            from_atom=step.result.atom_id,
            state=step.state,
            epoch_id=step.transition.epoch_id,
            max_depth=1,
        )
        control = marginal_cone(
            lattice,
            epoch_id=step.transition.epoch_id,
            quantizer=quantizer,
            state=step.state,
        )
        cone_scores.append(_brier(_cone_distribution(cone), actual))
        marginal_scores.append(_brier(_cone_distribution(control), actual))
    return _verdict(
        component="future_cone",
        core_ids=("DTL-F05",),
        control="marginal_cone",
        metric="branch_brier",
        with_component=mean(cone_scores) if cone_scores else None,
        without_component=mean(marginal_scores) if marginal_scores else None,
        experiment_id=experiment_id,
        higher_is_better=False,
        detail=f"{len(cone_scores)} one-step continuations scored",
        measured_by=f"{_MODULE}:measure_future_cone",
    )


def measure_hazard(
    train: tuple[tuple[SSIRTransitionV1, ...], ...],
    test: tuple[tuple[SSIRTransitionV1, ...], ...],
    *,
    experiment_id: str,
) -> ComponentVerdict:
    """Hazard estimates against the empirical per-bucket base rate."""
    quantizer = BehaviourQuantizer()
    lattice, _ = _build_model(quantizer, train)
    control = constant_hazard(_hazard_base_rates(train))
    hazard_scores: list[float] = []
    control_scores: list[float] = []
    position = _positions(test)
    for step in walk(quantizer, test):
        session, index = position[id(step.transition)]
        cone = predict_future_cone(
            lattice,
            quantizer,
            from_atom=step.result.atom_id,
            state=step.state,
            epoch_id=step.transition.epoch_id,
        )
        report = estimate_security_hazard(cone, lattice, state=step.state)
        for outcome in OUTCOME_DIMENSIONS:
            for horizon in HORIZONS:
                truth = _hazard_truth(session, index, outcome, horizon)
                estimate = report.for_outcome(outcome, horizon)
                baseline = control.for_outcome(outcome, horizon)
                if estimate is None or baseline is None:
                    continue
                hazard_scores.append((estimate.probability - truth) ** 2)
                control_scores.append((baseline.probability - truth) ** 2)
    return _verdict(
        component="hazard_heads",
        core_ids=("DTL-F08",),
        control="constant_hazard",
        metric="hazard_brier",
        with_component=mean(hazard_scores) if hazard_scores else None,
        without_component=mean(control_scores) if control_scores else None,
        experiment_id=experiment_id,
        higher_is_better=False,
        detail=f"{len(hazard_scores)} (outcome, horizon) predictions scored",
        measured_by=f"{_MODULE}:measure_hazard",
    )


def measure_uncertainty(
    train: tuple[tuple[SSIRTransitionV1, ...], ...],
    test: tuple[tuple[SSIRTransitionV1, ...], ...],
    *,
    experiment_id: str,
) -> ComponentVerdict:
    """Calibration of the composed estimate against ``1 - max p``.

    The event being predicted is whether the lattice's top-1 successor atom is
    the one that actually followed, so both confidences answer the same question
    and ECE is comparable between them.
    """
    quantizer = BehaviourQuantizer()
    lattice, _ = _build_model(quantizer, train)
    labels: list[int] = []
    composed: list[float] = []
    control: list[float] = []
    for step in walk(quantizer, test):
        if step.previous_atom is None:
            continue
        successors = lattice.successors(step.previous_atom, limit=1)
        labels.append(int(bool(successors) and successors[0][0] == step.result.atom_id))
        cone = predict_future_cone(
            lattice,
            quantizer,
            from_atom=step.previous_atom,
            state=step.state,
            epoch_id=step.transition.epoch_id,
            max_depth=1,
        )
        heads = _cone_heads(cone)
        estimate = estimate_uncertainty(
            heads=heads,
            cone=cone,
            prototype_distance=step.result.distance,
            transition=step.transition,
            phi_total=phi(step.state).total,
        )
        composed.append(1.0 - estimate.value)
        control.append(1.0 - one_minus_max(heads))
    return _verdict(
        component="uncertainty",
        core_ids=("DTL-F07",),
        control="one_minus_max",
        metric="expected_calibration_error",
        with_component=expected_calibration_error(labels, composed) if labels else None,
        without_component=expected_calibration_error(labels, control) if labels else None,
        experiment_id=experiment_id,
        higher_is_better=False,
        detail=(
            f"{len(labels)} next-atom predictions, "
            f"{len(reliability_bins(labels, composed)) if labels else 0} reliability bins"
        ),
        measured_by=f"{_MODULE}:measure_uncertainty",
    )


def _fill_cache(transitions: tuple[tuple[SSIRTransitionV1, ...], ...]) -> TransitionCache:
    """A cache filled from the real path, with a measured utility per entry."""
    store = WindowStore()
    quantizer = BehaviourQuantizer()
    lattice = TransitionLattice()
    cache = TransitionCache(model_version="stage2-report", encoder_version=ENCODER_VERSION)
    ledger = WorkLedger()
    for session in transitions:
        runtime_path(
            session,
            store=store,
            quantizer=quantizer,
            lattice=lattice,
            cache=cache,
            ledger=ledger,
        )
    return cache


def _replay_hits(cache: TransitionCache, keys: tuple[str, ...]) -> float | None:
    """Hit rate of a pruned cache replayed against the keys the path asked for."""
    if not keys:
        return None
    hits = sum(1 for key in keys if cache.get(key) is not None)
    return hits / len(keys)


def measure_cache_and_forgetting(
    train: tuple[tuple[SSIRTransitionV1, ...], ...],
    test: tuple[tuple[SSIRTransitionV1, ...], ...],
    *,
    experiment_id: str,
) -> tuple[ComponentVerdict, ComponentVerdict]:
    """Utility-based forgetting against LRU and random, at equal capacity.

    ``keep`` is a target **cache size**, so it is computed from the cache's own
    occupancy. It used to be a quarter of the held-out *lookup* count, which at
    the shipped ``count=240`` is 4,474 against a cache holding 416 entries
    (capacity ``MAX_CACHE_ENTRIES`` = 1024). ``_require_keep`` therefore returned
    surplus 0, all three policies took their ``if surplus == 0: return ()`` early
    exit, and ``prune`` replayed the same unpruned cache three times: the
    "with component" and "without component" arms were bit-identical floats, not
    numbers that happened to agree to four decimals. Two of the eleven ablation
    rows the wave presents as measured were arithmetic identities (S2-FC-04).

    Each strategy is now required to have actually evicted something; if it did
    not, the row is UNMEASURABLE rather than a delta of 0.0.
    """
    keys = _requested_keys(test)
    evicted: dict[str, int] = {}

    def prune(
        name: str, strategy: Callable[[TransitionCache], tuple[str, ...]]
    ) -> float | None:
        cache = _fill_cache(train)
        _apply_utilities(cache)
        evicted[name] = len(strategy(cache))
        return _replay_hits(cache, keys)

    reference = _fill_cache(train)
    keep = max(1, len(reference) // 4)

    utility_rate = prune("utility", lambda c: forget_low_utility_memory(c, keep=keep))
    lru_rate = prune("lru", lambda c: lru_control(c, keep=keep))
    random_rate = prune("random", lambda c: random_control(c, keep=keep, seed=11))
    if not all(evicted.get(name) for name in ("utility", "lru", "random")):
        # No policy ran, so neither row is a comparison. Saying so is the
        # result; a delta of 0.0 here would be an arithmetic identity wearing a
        # measurement's clothes.
        reason = (
            f"no eviction occurred: cache held {len(reference)} entries at "
            f"keep={keep}, evictions per policy {evicted}. Nothing was compared"
        )
        return (
            unmeasurable(
                "transition_cache", ("DTL-F16",), "lru_control", "hit_rate", reason=reason
            ),
            unmeasurable(
                "utility_forgetting",
                ("DTL-F15",),
                "lru_control/random_control",
                "hit_rate",
                reason=reason,
            ),
        )
    cache_verdict = _verdict(
        component="transition_cache",
        core_ids=("DTL-F16",),
        control="lru_control",
        metric="hit_rate",
        with_component=utility_rate,
        without_component=lru_rate,
        experiment_id=experiment_id,
        detail=(
            f"{len(keys)} held-out lookups, cache held {len(reference)} entries, "
            f"keep={keep}, evictions {evicted}"
        ),
        measured_by=f"{_MODULE}:measure_cache_and_forgetting",
    )
    forgetting_verdict = _verdict(
        component="utility_forgetting",
        core_ids=("DTL-F15",),
        control="lru_control/random_control",
        metric="hit_rate",
        with_component=utility_rate,
        without_component=(
            None
            if lru_rate is None or random_rate is None
            else max(lru_rate, random_rate)
        ),
        experiment_id=experiment_id,
        detail=f"lru={_r(lru_rate)} random={_r(random_rate)}",
        measured_by=f"{_MODULE}:measure_cache_and_forgetting",
    )
    return cache_verdict, forgetting_verdict


def _apply_utilities(cache: TransitionCache) -> None:
    """Score every entry by future security utility, from its measured fields.

    Credit is the entry's own Φ scaled into [0, 1]; nothing here invents a
    credit figure a ledger did not produce, and the scale is stated rather than
    hidden inside the utility function.
    """
    for entry in cache.entries():
        cache.store(
            replace(
                entry,
                utility=future_security_utility(
                    entry,
                    credit=min(1.0, max(0.0, entry.predicted_phi / PHI_CREDIT_SCALE)),
                    uncertainty_reduction=1.0 - entry.uncertainty,
                ),
            )
        )


def _requested_keys(
    sessions: tuple[tuple[SSIRTransitionV1, ...], ...],
) -> tuple[str, ...]:
    """The cache keys a held-out pass would ask for, in order."""
    return tuple(
        transition_cache_key(
            atom_id=step.result.atom_id,
            epoch_id=step.encoded.epoch_id,
            state_delta_mask=step.encoded.state_delta_mask,
        )
        for step in walk(BehaviourQuantizer(), sessions)
    )


# --- drift, poisoning, attribution -------------------------------------------


def drift_and_poison(*, count: int, seed: int) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run the drift corpus and the poison suite through the quarantine gate.

    Both controls are run too. "No malicious pattern was normalised" is also
    true of a system that never learns anything, so ``ACCEPT_EVERYTHING`` and
    ``ACCEPT_NOTHING`` bound the measurement.
    """
    out: list[dict[str, Any]] = []
    for scenarios, attack in (
        (build_drift_corpus(count=count, seed=seed), malicious_lineage),
        (build_poison_suite(count=count, seed=seed), poison_lineage),
    ):
        rows: dict[str, Any] = {}
        for policy in AdaptationPolicy:
            quantizer = BehaviourQuantizer()
            run = run_adaptation(
                scenarios,
                quantizer=quantizer,
                epoch_signals=_DRIFT_SIGNALS,
                lattice=TransitionLattice(),
                policy=policy,
                attack_lineage=attack,
            )
            rows[policy.value] = {
                "drift": drift_report(run).to_dict(),
                "promotions": run.promotions,
                "attack_lineage_promotions": run.attack_lineage_promotions,
                "escalating_promotions": run.escalating_promotions,
                "outcomes": run.outcomes,
                "quarantine": run.quarantine,
                "trusted_atoms": quantizer.stats().atoms,
            }
        rows["scenarios"] = len(scenarios)
        rows["measured_by"] = f"{_MODULE}:drift_and_poison"
        out.append(rows)
    return out[0], out[1]


def attribution_report(*, count: int, seed: int) -> dict[str, Any]:
    """Causal credit against naive ancestry, with a real ground-truth chain.

    The drift corpus is used because it exposes the attack lineage
    (``malicious_lineage``), so ground truth comes from the fixture rather than
    from ΔΦ — scoring a ΔΦ-ranked mechanism against a ΔΦ-derived ground truth
    would be circular.
    """
    scenarios = [s for s in build_drift_corpus(count=count, seed=seed) if malicious_lineage(s)]
    rows: list[dict[str, Any]] = []
    for scenario in scenarios:
        pipeline = Stage1Pipeline()
        result = pipeline.run_scenario(scenario, offset=0)
        lineage = malicious_lineage(scenario)
        truth = frozenset(
            t.causal_signature for t in result.transitions if t.actor.identity == lineage
        )
        if not truth:
            continue
        row = _attribute_one(pipeline, result.transitions, truth)
        row["phi_only_chain_recall"] = _r(phi_only_attribution(result.transitions, truth))
        rows.append(row)
    return {
        "sessions": len(rows),
        "rows": rows,
        "conciseness_gain_mean": (
            mean([r["conciseness_gain"] for r in rows if r["conciseness_gain"] is not None])
            if any(r["conciseness_gain"] is not None for r in rows)
            else None
        ),
        "sessions_more_concise_at_equal_recall": sum(
            1 for r in rows if r["more_concise_at_equal_recall"]
        ),
        "measured_by": f"{_MODULE}:attribution_report",
    }


def _attribute_one(
    pipeline: Stage1Pipeline,
    transitions: tuple[SSIRTransitionV1, ...],
    truth: frozenset[str],
) -> dict[str, Any]:
    """One session: probe every step of every lineage, then compare with ancestry."""
    quantizer = BehaviourQuantizer()
    lattice, _ = _build_model(quantizer, (transitions,))
    nodes = {node.signature: node for node in naive_ancestry(pipeline.causal)}
    ledger = CausalCreditLedger(probe_budget=len(transitions) + 1)
    for window, signatures in _lineage_windows_with_signatures(transitions):
        for index in range(len(window.steps)):
            probe = counterfactual_probe(window, quantizer, lattice, target_index=index)
            # The probed transition's real causal signature, not
            # `probe.target_signature` — a positional locator that can never
            # equal a 16-hex `CausalNode.signature`, so the lookup never matched
            # and `assign_causal_credit` was never called (S2-FC-01). This file
            # and `gate_criteria.py` carried the identical defective line, so
            # their agreement was never a cross-check.
            node = nodes.get(signatures[index])
            if node is not None:
                ledger.assign_causal_credit(probe, node)
    report = ledger.report(pipeline.causal, ground_truth=truth)
    naive_recall = chain_recall(frozenset(nodes), ground_truth=truth)
    return {
        "nodes_inspected": report.nodes_inspected,
        "naive_ancestry_nodes": report.naive_ancestry_nodes,
        "chain_recall": _r(report.chain_recall),
        "naive_chain_recall": _r(naive_recall),
        "conciseness_gain": _r(report.conciseness_gain),
        "ground_truth_nodes": len(truth),
        "more_concise_at_equal_recall": bool(
            report.nodes_inspected < report.naive_ancestry_nodes
            and report.chain_recall is not None
            and naive_recall is not None
            and report.chain_recall >= naive_recall
        ),
    }


def phi_only_attribution(
    transitions: tuple[SSIRTransitionV1, ...], truth: frozenset[str]
) -> float | None:
    """The zero-parameter control: replay with one step masked, score with Φ alone.

    Chain recall of the transitions this control flags, so the credit ledger is
    compared against the cheapest thing that could work rather than only against
    full ancestry.
    """
    windows = _lineage_windows(transitions)
    if not windows:
        return None
    flagged: set[str] = set()
    for window in windows:
        for index in range(len(window.steps)):
            probe = phi_only_probe(window, target_index=index)
            if probe.divergence > 0.0:
                flagged.add(probe.target_signature)
    return chain_recall(frozenset(flagged), ground_truth=truth)


# --- the report --------------------------------------------------------------


def longest_sequence(dataset: Stage2Dataset) -> int:
    """Length of the longest sample, which is what padding pads to."""
    return max((len(sample) for sample in dataset.samples), default=0)


def dtl_conv_runnable(*datasets: Stage2Dataset) -> str:
    """Empty when ``DTLConvModel`` can process every split, else the reason."""
    for dataset in datasets:
        longest = longest_sequence(dataset)
        if longest < DTL_CONV_MIN_STEPS:
            return (
                f"dtl-conv excluded: {dataset.name} longest sequence {longest} < "
                f"{DTL_CONV_MIN_STEPS}; research/dtl_conv.py:234 raises on a padded "
                "batch shorter than twice its widest dilation"
            )
    return ""


def _sleeping_brain(train: Stage2Dataset, test: Stage2Dataset) -> dict[str, Any]:
    """Wall-clock µs/event for the four models that matter, freshly constructed.

    Fresh instances only: ``sleeping_brain_report`` calls ``fit`` itself, and
    ``fit`` continues training rather than restarting, so a model that arrived
    already fitted would be trained twice and look faster than it is.
    """
    excluded = dtl_conv_runnable(train, test)
    models: list[Any] = [
        PhiOracleBaseline(),
        MLPBaseline(name="mlp-pooled", hidden=24, epochs=40),
        TCNBaseline(name="tcn", hidden=24, epochs=40),
    ]
    if not excluded:
        models.append(DTLConvModel(DTLConvConfig(latent=48, epochs=40)))
    report = sleeping_brain_report(models, train, test)
    report["excluded_models"] = [excluded] if excluded else []
    report["longest_sequence"] = {
        "train": longest_sequence(train),
        "test": longest_sequence(test),
        "dtl_conv_minimum": DTL_CONV_MIN_STEPS,
    }
    report["measured_by"] = f"{_MODULE}:_sleeping_brain"
    return report


def _export_verdict(sleeping: dict[str, Any], experiment_id: str) -> ComponentVerdict:
    """Does any learned candidate beat the Φ-oracle on µs/event **at equal PR-AUC**?

    The quality tie is part of the question (spec §5). A candidate that is cheaper
    while detecting worse has not beaten the zero-parameter scorer, and a candidate
    that detects better while costing more is not what this row asks about — so
    only candidates within ``QUALITY_TIE`` of the oracle are compared on cost, and
    if none is, the row is ``UNMEASURABLE`` rather than decided on the wrong axis.
    """
    points = {p["name"]: p for p in sleeping.get("points", [])}
    oracle = points.get("phi-oracle")
    if oracle is None:
        return unmeasurable(
            "compile_candidate_export",
            ("DTL-F17", "DTL-F20"),
            "phi_oracle",
            "microseconds_per_event",
            reason="the sleeping-brain frontier produced no Φ-oracle point",
        )
    tied = [
        p
        for name, p in points.items()
        if name != "phi-oracle" and abs(p["pr_auc"] - oracle["pr_auc"]) <= QUALITY_TIE
    ]
    cheapest = min(tied, key=lambda p: p["microseconds_per_event"]) if tied else None
    if cheapest is None:
        return unmeasurable(
            "compile_candidate_export",
            ("DTL-F17", "DTL-F20"),
            "phi_oracle",
            "microseconds_per_event",
            reason=(
                "no learned candidate matched the Φ-oracle's PR-AUC "
                f"({oracle['pr_auc']}) within {QUALITY_TIE}, so there is no "
                "equal-quality cost comparison to make"
            ),
        )
    return _verdict(
        component="compile_candidate_export",
        core_ids=("DTL-F17", "DTL-F20"),
        control="phi_oracle",
        metric="microseconds_per_event",
        with_component=cheapest["microseconds_per_event"],
        without_component=oracle["microseconds_per_event"],
        experiment_id=experiment_id,
        higher_is_better=False,
        detail=(
            f"cheapest learned candidate {cheapest['name']} at "
            f"{cheapest['pr_auc']} PR-AUC vs phi-oracle {oracle['pr_auc']}"
        ),
        measured_by=f"{_MODULE}:_export_verdict",
    )


def _gate_verdicts(
    drift: dict[str, Any], poison: dict[str, Any], *, ids: Mapping[str, str]
) -> list[ComponentVerdict]:
    """Epoch guard and quarantine, each against accept-everything."""
    out: list[ComponentVerdict] = []
    gated = drift[AdaptationPolicy.QUARANTINED.value]["drift"]
    open_gate = drift[AdaptationPolicy.ACCEPT_EVERYTHING.value]["drift"]
    closed = drift[AdaptationPolicy.ACCEPT_NOTHING.value]["drift"]
    if gated["transitions_to_recover"] is None:
        # Refusing everything also normalises nothing. Without a measured
        # recovery the gate is indistinguishable from the accept-nothing
        # control, so there is nothing to credit it for.
        out.append(
            unmeasurable(
                "epoch_guard",
                ("DTL-F18",),
                "accept_everything",
                "malicious_patterns_normalised",
                reason=(
                    "the gate never re-adapted inside the corpus "
                    "(transitions_to_recover is None), so it cannot be "
                    "distinguished from accept-nothing"
                ),
            )
        )
    else:
        out.append(
            _verdict(
                component="epoch_guard",
                core_ids=("DTL-F18",),
                control="accept_everything",
                metric="malicious_patterns_normalised",
                with_component=float(gated["malicious_patterns_normalised"]),
                without_component=float(open_gate["malicious_patterns_normalised"]),
                experiment_id=ids["epoch_guard"],
                higher_is_better=False,
                detail=(
                    f"recovered after {gated['transitions_to_recover']} transitions; "
                    f"accept-nothing normalised {closed['malicious_patterns_normalised']} "
                    f"and recovered {closed['transitions_to_recover']}"
                ),
                measured_by=f"{_MODULE}:_gate_verdicts",
            )
        )
    gated_p = poison[AdaptationPolicy.QUARANTINED.value]
    open_p = poison[AdaptationPolicy.ACCEPT_EVERYTHING.value]
    out.append(
        _verdict(
            component="quarantine_promotion",
            core_ids=("DTL-F19",),
            control="accept_everything",
            metric="poisoned_promotions",
            with_component=float(gated_p["attack_lineage_promotions"]),
            without_component=float(open_p["attack_lineage_promotions"]),
            experiment_id=ids["quarantine_promotion"],
            higher_is_better=False,
            detail=f"{gated_p['promotions']} promotions under the gate",
            measured_by=f"{_MODULE}:_gate_verdicts",
        )
    )
    return out


def _credit_verdict(attribution: dict[str, Any], *, experiment_id: str) -> ComponentVerdict:
    rows = attribution.get("rows", [])
    if not rows:
        return unmeasurable(
            "causal_credit",
            ("DTL-F10", "DTL-F11"),
            "naive_ancestry",
            "nodes_inspected_at_recall",
            reason="no attack session produced a ground-truth chain",
        )
    recall = [r["chain_recall"] or 0.0 for r in rows]
    naive_recall = [r["naive_chain_recall"] or 0.0 for r in rows]
    detail = (
        f"{attribution['sessions_more_concise_at_equal_recall']}/{len(rows)} sessions "
        f"more concise at equal or better chain recall; ledger recall "
        f"{_r(mean(recall))} vs naive {_r(mean(naive_recall))}; "
        f"phi-only control recall "
        f"{_r(mean([r.get('phi_only_chain_recall') or 0.0 for r in rows]))}"
    )
    if mean(recall) < mean(naive_recall) - 1e-9:
        # Fewer nodes at lower recall is not conciseness, it is missing the
        # chain. The metric reported is therefore the one that failed, so a
        # ledger that credits nothing cannot look like a concise ledger.
        return _verdict(
            component="causal_credit",
            core_ids=("DTL-F10", "DTL-F11"),
            control="naive_ancestry",
            metric="chain_recall",
            with_component=float(mean(recall)),
            without_component=float(mean(naive_recall)),
            experiment_id=experiment_id,
            detail=detail,
            measured_by=f"{_MODULE}:_credit_verdict",
        )
    return _verdict(
        component="causal_credit",
        core_ids=("DTL-F10", "DTL-F11"),
        control="naive_ancestry",
        metric="nodes_inspected_at_recall",
        with_component=float(mean([r["nodes_inspected"] for r in rows])),
        without_component=float(mean([r["naive_ancestry_nodes"] for r in rows])),
        experiment_id=experiment_id,
        higher_is_better=False,
        detail=detail,
        measured_by=f"{_MODULE}:_credit_verdict",
    )


def _unmeasurable_rows(reason: str) -> tuple[ComponentVerdict, ...]:
    """The split-dependent rows only.

    Robustness, attribution and cost are measured on their own fixtures — the
    drift corpus, the poison suite, the sleeping-brain frontier — so a degenerate
    *detection* split does not refuse them. Emitting an UNMEASURABLE row for them
    here as well would put two contradictory verdicts for one component in the
    same report.
    """
    return tuple(
        unmeasurable(component, core_ids, control, metric, reason=reason)
        for component, core_ids, control, metric in COMPONENT_ROWS
        if component in SPLIT_DEPENDENT_COMPONENTS
    )


def mint_experiment_ids(*, date: str | None = None) -> dict[str, str]:
    """One well-formed experiment id per component row, from 0007 onward.

    Minted, **not registered**. ``experiments/registry.jsonl`` is digest-chained
    and append-only, and this module runs beside seven other packages, so it does
    not write to the ledger: two concurrent appends would break the chain. The
    integrator's CLI records the run, and until it does, an id here identifies a
    measurement that exists in this report and not yet in the ledger — which is
    why ``provenance["experiment_ids_registered"]`` says ``False``.
    """
    return {
        component: format_experiment_id(
            stage=2,
            hypothesis="H8",
            slug=component.replace("_", "-"),
            sequence=EXPERIMENT_SEQUENCE_START + index,
            date=date,
        )
        for index, (component, _, _, _) in enumerate(COMPONENT_ROWS)
    }


def build_report(
    *,
    corpus: str = "ambiguous",
    count: int = 240,
    train_seed: int = 3,
    test_seed: int = 11,
    robustness_count: int = 24,
    latent_dimensions: tuple[int, ...] = DEFAULT_LATENT_DIMENSIONS,
) -> Stage2Report:
    """Measure everything Stage 2 claims, on one fixed ``(corpus, count, seed)``.

    The saturation check runs **first**. If it refuses, every component verdict
    is ``UNMEASURABLE`` and no ablation is recorded — the whole point of
    ADR-0120. The resource, drift, poisoning, attribution and sleeping-brain
    measurements still run, because none of them is a component delta.
    """
    ids = mint_experiment_ids()
    train = build_dataset(name="s2-train", count=count, seed=train_seed, corpus=corpus)
    test = build_dataset(name="s2-test", count=count, seed=test_seed, corpus=corpus)
    verdict = saturation_check(train, test)

    components: list[ComponentVerdict] = []
    frontier: dict[str, Any] = {}
    refusal = ""
    try:
        refuse_if_degenerate(verdict)
    except CorpusDegenerate as exc:
        refusal = str(exc)
        components.extend(_unmeasurable_rows(verdict.reason))
        frontier = {
            "refused": True,
            "reason": verdict.reason,
            "detail": refusal,
            "dimensions": list(latent_dimensions),
            "points": [],
        }

    train_sessions = compile_scenarios(_corpus(corpus, count=count, seed=train_seed))
    test_sessions = compile_scenarios(_corpus(corpus, count=count, seed=test_seed))
    flat_test = tuple(t for session in test_sessions for t in session)

    if not refusal:
        components.extend(_measure_components(train_sessions, test_sessions, ids=ids))
        frontier = latent_frontier(
            dimensions=latent_dimensions,
            corpus=corpus,
            count=count,
            seed=train_seed,
            test_seed=test_seed,
        )

    drift, poison = drift_and_poison(count=robustness_count, seed=test_seed)
    attribution = attribution_report(count=robustness_count, seed=test_seed)
    sleeping = _sleeping_brain(train, test)

    components.extend(_gate_verdicts(drift, poison, ids=ids))
    components.append(_credit_verdict(attribution, experiment_id=ids["causal_credit"]))
    components.append(_export_verdict(sleeping, ids["compile_candidate_export"]))

    return Stage2Report(
        saturation=(verdict,),
        components=tuple(components),
        resources=resource_report(flat_test),
        # A second, independent pass: timing every unit of work perturbs the
        # resource pass, so the two are never taken from the same run.
        drift=drift,
        poisoning=poison,
        attribution=attribution,
        latent_frontier=frontier,
        sleeping_brain=sleeping,
        core_id_audit=core_id_audit(),
        path_cost=path_cost_report(flat_test),
        provenance={
            "corpus": corpus,
            "count": count,
            "train_seed": train_seed,
            "test_seed": test_seed,
            "robustness_count": robustness_count,
            "encoder_version": ENCODER_VERSION,
            "experiment_sequence_start": EXPERIMENT_SEQUENCE_START,
            "train": train.to_provenance(),
            "test": test.to_provenance(),
            "saturation_refusal": refusal,
            "experiment_ids": ids,
            "experiment_ids_registered": False,
            "relation_families": len(RelationFamily),
        },
    )


def _measure_components(
    train_sessions: tuple[tuple[SSIRTransitionV1, ...], ...],
    test_sessions: tuple[tuple[SSIRTransitionV1, ...], ...],
    *,
    ids: Mapping[str, str],
) -> list[ComponentVerdict]:
    """The nine component deltas that need a non-degenerate split."""
    cache_verdict, forgetting_verdict = measure_cache_and_forgetting(
        train_sessions, test_sessions, experiment_id=ids["transition_cache"]
    )
    return [
        measure_atom_layer(
            train_sessions, test_sessions, experiment_id=ids["behaviour_atom_quantizer"]
        ),
        measure_lattice(train_sessions, test_sessions, experiment_id=ids["transition_lattice"]),
        measure_restructuring(
            train_sessions, test_sessions, experiment_id=ids["merge_fission"]
        ),
        measure_future_cone(train_sessions, test_sessions, experiment_id=ids["future_cone"]),
        measure_hazard(train_sessions, test_sessions, experiment_id=ids["hazard_heads"]),
        measure_uncertainty(train_sessions, test_sessions, experiment_id=ids["uncertainty"]),
        measure_window(train_sessions, test_sessions, experiment_id=ids["multiscale_window"]),
        cache_verdict,
        forgetting_verdict,
    ]
