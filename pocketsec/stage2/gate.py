"""The Stage 2 acceptance gate (architecture spec section 38), as an executable check.

Thirteen criteria, each evaluated by running the real subsystems rather than
inspecting a document. Like Stage 0's and Stage 1's gates, this is code:
``pocketsec-stage2 gate`` exits non-zero if any criterion fails.

Three things about this gate are unlike Stage 1's, and all three are deliberate.

**It is expected to fail.** ADR-0113 exists because a stage may not be declared
failed by prose. G2.1, G2.2 and G2.3 are unmeetable on synthetic data — measured,
not assumed (ADR-0010, ADR-0120) — and this gate reports them FAILED with the
figure that made them fail. Restating a criterion so it passes would be the worst
outcome available here.

**Rejection is a pass for two criteria.** The architecture gate says Behaviour
Atoms must be stable enough to reuse *or the discrete layer is rejected*, and the
Future Cone must add measurable value *or be removed*. Those checks pass in their
rejection branch only when this run reproduces the measurement that rejected the
mechanism and the mechanism is off in code — never on the strength of an ADR
alone. That was true of G2.4 and **false of G2.6**, whose removal branch accepted
two hardcoded flags plus a ``docs/adr/*.md`` filename while discarding the two
measurements it paid for; ADR-0125 records the repair and the FAIL it produced.
The claim above is now a property of the code in both places.

**Where the rest of this criterion lives.** The evidence the gate consumes, and
the four checks that prove it authentic, are in ``gate_evidence`` (ADR-0127). How
each criterion was measured is in ``gate_criteria`` and ``gate_measures``. What is
here is one context, thirteen verdicts, and the reason for each.

**Three checks need numpy and say so.** The CI ``gate`` job installs the package
with a bare ``pip install -e .``, so this module imports stdlib only. G2.1, G2.2
and G2.12 reach the offline baseline suite through a deferred import; without
numpy they FAIL with that as the reason, which is honest — an unmeasured
criterion is not a satisfied one.
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pocketsec.stage0.experiments.registry import ExperimentRegistry
from pocketsec.stage0.gate import REPO_ROOT, GateCheck, GateReport
from pocketsec.stage2.adaptation.epoch_guard import AdaptationPolicy, drift_report
from pocketsec.stage2.cache.transition_cache import TransitionCache
from pocketsec.stage2.compile_candidates.exporter import export_candidates
from pocketsec.stage2.compile_candidates.stage3_interface import (
    Stage3Handoff,
    build_handoff,
    seam_violations,
    write_handoff,
)
from pocketsec.stage2.core_ids import ABLATION_SLOTS, CORE_IDS, FunctionClass
from pocketsec.stage2.encoder.ssir_encoder import ENCODER_VERSION
from pocketsec.stage2 import gate_evidence
from pocketsec.stage2.gate_evidence import (
    GATE_CORPUS,
    GATE_COUNT,
    TEST_SEED,
    TRAIN_SEED,
    FrontierEvidence,
    load_frontier as _load_frontier,
)

# `gate_evidence` is imported as a MODULE above, not only for its names, because
# `FRONTIER_PATH` and `REGISTRY_PATH` are resolved at call time. Re-exporting them
# here would create a second binding for each, and a test that redirected this
# copy would silently not redirect the one `load_frontier` reads.
from pocketsec.stage2.gate_criteria import (
    CHEAP_PATHS,
    ROBUSTNESS_COUNT as _ROBUSTNESS_COUNT,
    _cheap_fraction,
    _expensive_fraction,
    _mean,
    _pct,
    _phantom_check_refuses_a_fake,
    _phantom_savings_reason,
    _round,
    _sequence_of,
    _skipped_inference_fraction,
    _us,
    ConformalCoverage,
    adaptation_run,
    adr_naming,
    attribution_rows,
    cone_briers,
    conformal_coverage,
    hazard_scores,
    phi_candidate,
    phi_oracle_scores,
    rejects_unevidenced_candidates,
    research_imports,
)
from pocketsec.stage2.gate_measures import (
    STAGE2_INCREMENTAL_RSS_CEILING_BYTES,
    CompiledSplit,
    RuntimePass,
    atom_pairs,
    build_lattice,
    compile_split,
    lru_key_control,
    resource_pass,
    runtime_pass,
)
from pocketsec.stage2.labs.drift_corpus import build_drift_corpus, malicious_lineage
from pocketsec.stage2.labs.poison_suite import build_poison_suite, poison_lineage
from pocketsec.stage2.lattice.quantizer import (
    BEHAVIOUR_QUANTIZER_ENABLED,
    DEFAULT_QUANTIZER,
    BehaviourQuantizer,
    HashBucketQuantizer,
)
from pocketsec.stage2.lattice.restructure import LatticeRestructurer
from pocketsec.stage2.lattice.transitions import TransitionLattice
from pocketsec.stage2.predictors.future_cone import FUTURE_CONE_DEFAULT_ENABLED
from pocketsec.stage2.predictors.hazard import HAZARD_DEFAULT_ENABLED
from pocketsec.stage2.router.accounting import WorkLedger
from pocketsec.stage2.router.policy import ROUTER_DEFAULT_ENABLED
from pocketsec.stage2.state.window import WindowStore
from pocketsec.stage2.uncertainty.calibration import IsotonicCalibrator

__all__ = ["FrontierEvidence", "Stage2GateContext", "run_gate"]

# GATE_CORPUS / GATE_COUNT / TRAIN_SEED / TEST_SEED are defined in
# `gate_evidence` and re-exported above: the measurement triple belongs beside
# the evidence it authenticates, and two definitions of it could drift.
# FRONTIER_PATH and REGISTRY_PATH are deliberately NOT re-exported — they are
# read as `gate_evidence.<name>` wherever they are needed.

#: The drift corpus and the poison suite are their own fixtures, run at the size
#: ``gate_criteria`` declares, so a detail string and the measurement behind it
#: cannot quote different corpus sizes.
ROBUSTNESS_COUNT = _ROBUSTNESS_COUNT

#: G2.4: Rand-style agreement two quantizer orders must reach to count as stable.
STABILITY_FLOOR = 0.90
#: G2.10: how often a cache hit must serve the answer the deep path would have
#: computed before its skipped fraction counts as avoided inference rather than
#: as a substituted answer. Set deliberately high — a cheap path is only cheap
#: if it is also right — and the measured figure on this corpus is far below it.
CACHE_AGREEMENT_FLOOR = 0.95
#: G2.5: the calibration ceiling the criterion names, and conformal's band.
ECE_CEILING = 0.10
NOMINAL_COVERAGE = 0.9
COVERAGE_TOLERANCE = 0.05
#: The three models the cost frontier is taken over: the zero-parameter scorer,
#: the order-free pooled control and the accepted Stage 2 core. DTL-C is absent
#: because `DTLConvModel` cannot process this corpus — its dilation-32 branch
#: needs 64 padded steps and the shortest ambiguous session has fewer.
PARETO_MODELS: tuple[str, ...] = ("phi-oracle", "mlp-pooled", "tcn")

#: Acceptance criterion 1's own number: "at least five strong baselines".
MIN_BASELINES = 5

#: Stage 2's experiment counter reached 0006 before this wave; anything from
#: 0007 on belongs to it.
WAVE_SEQUENCE_START = 7

#: The verdict word `research/cli.py:_register` writes at the head of a
#: registry row's notes when an ablation supported the component. G2.12 reads
#: it, because "a row exists" and "the row says the component earned its place"
#: are different facts.
JUSTIFIED_VERDICT = "JUSTIFIED"

#: Refusal reasons that mean "seen often, still not corroborated".
_FREQUENCY_REFUSALS = frozenset(
    {"frequency_alone", "insufficient_observations", "not_eligible"}
)

#: Paths a router would call cheap. Used only to compare a *proposal* with what
#: the ledger proves ran.
#: Slack on the delivered-routing comparison, so a single event's rounding
#: cannot decide a criterion. Not a threshold on quality: on the expensive
#: fraction alone.
_ROUTING_TOLERANCE = 1e-9

_CANDIDATE_PACKAGE = REPO_ROOT / "pocketsec" / "stage2" / "compile_candidates"



@dataclass
class Stage2GateContext:
    """One shared corpus compilation and one shared runtime pass.

    Compiling a split costs tens of seconds and the runtime path costs seconds,
    so thirteen checks share one of each rather than replaying the corpus
    thirteen times. Everything here is a measurement; no field is a verdict.
    """

    train: CompiledSplit
    test: CompiledSplit
    #: The stdlib path with the transition cache honoured — a hit genuinely
    #: skips the cone and the uncertainty estimate.
    cached: RuntimePass
    cached_ledger: WorkLedger
    #: The same work with the cache ignored. The control that makes "skipping
    #: reduced compute" a comparison instead of an assertion.
    uncached: RuntimePass
    uncached_ledger: WorkLedger
    #: A separate, un-timed pass under ``ResourceSampler``: timing every unit of
    #: work perturbs the resource measurement, so the two never share a run.
    resources: dict[str, Any]
    #: F10's control: the most a plain LRU key cache could ever skip.
    lru_fraction: float | None
    #: The baseline suite's measurement, supplied as data by offline research.
    #: ``None`` when nobody has measured it, and ``frontier_refusal`` says why.
    frontier: FrontierEvidence | None = None
    frontier_refusal: str = ""

    @classmethod
    def build(cls, *, frontier: FrontierEvidence | None = None) -> Stage2GateContext:
        train = compile_split(GATE_CORPUS, count=GATE_COUNT, seed=TRAIN_SEED)
        test = compile_split(GATE_CORPUS, count=GATE_COUNT, seed=TEST_SEED)
        flat = test.flat
        cached_ledger = WorkLedger()
        cached = runtime_pass(
            flat,
            store=WindowStore(),
            quantizer=DEFAULT_QUANTIZER(),
            lattice=TransitionLattice(),
            cache=TransitionCache(
                model_version="stage2-gate", encoder_version=ENCODER_VERSION
            ),
            ledger=cached_ledger,
        )
        uncached_ledger = WorkLedger()
        uncached = runtime_pass(
            flat,
            store=WindowStore(),
            quantizer=DEFAULT_QUANTIZER(),
            lattice=TransitionLattice(),
            cache=TransitionCache(
                model_version="stage2-gate", encoder_version=ENCODER_VERSION
            ),
            ledger=uncached_ledger,
            honour_cache=False,
        )
        loaded, refusal = (frontier, "") if frontier is not None else _load_frontier()
        return cls(
            frontier=loaded,
            frontier_refusal=refusal,
            train=train,
            test=test,
            cached=cached,
            cached_ledger=cached_ledger,
            uncached=uncached,
            uncached_ledger=uncached_ledger,
            resources=resource_pass(flat),
            lru_fraction=lru_key_control(flat),
        )



def run_gate(*, frontier: FrontierEvidence | None = None) -> GateReport:
    """Evaluate all thirteen Stage 2 acceptance criteria.

    ``frontier`` is the offline baseline measurement. Left out, the gate loads
    whatever research last wrote and refuses evidence from a different split.
    """
    ctx = Stage2GateContext.build(frontier=frontier)
    return GateReport(
        checks=(
            _baselines_and_pareto(ctx),
            _latent_frontier(ctx),
            _selective_routing(ctx),
            _behaviour_atoms(ctx),
            _calibrated_uncertainty(ctx),
            _future_cone_value(ctx),
            _causal_credit(ctx),
            _drift_without_normalising(ctx),
            _poisoning_quarantine(ctx),
            _sleeping_brain(ctx),
            _resource_envelope(ctx),
            _components_ablation_supported(ctx),
            _stage3_export(ctx),
        )
    )


def _baselines_and_pareto(ctx: Stage2GateContext) -> GateCheck:
    """1 — five strong baselines on identical splits, and the core not dominated."""
    evidence = ctx.frontier
    if evidence is None:
        return GateCheck(
            "G2.1",
            "Five strong baselines, Stage 2 core not dominated",
            False,
            f"UNMEASURED: {ctx.frontier_refusal}",
        )
    above = {
        name: value for name, value in evidence.scores.items() if value > evidence.base_rate
    }
    dominated = {
        row["name"]: row["dominated_by"] for row in evidence.pareto.get("dominated", ())
    }
    core_dominated = bool(set(PARETO_MODELS[1:]) & set(dominated))
    passed = (
        len(above) >= MIN_BASELINES
        and len(above) == len(evidence.scores)
        and not core_dominated
    )
    table = ", ".join(f"{name} {value:.4f}" for name, value in sorted(evidence.scores.items()))
    # The verdict language is derived from what was measured, not hardcoded. It
    # used to assert unconditionally that "the learned core is beaten on cost by
    # a zero-parameter scorer ... FAILED, not restated", so a PASSING check
    # printed a sentence contradicting its own verdict — and that sentence was
    # the one line a reader would have used to spot a forged frontier file
    # (S2-AUTH-02). Boilerplate cannot be a signal in either direction.
    if core_dominated:
        finding = (
            f"the learned core is beaten on cost by a zero-parameter scorer over "
            f"Stage 1's representation, which is Stage 2 falsification criterion 1 "
            f"firing (ADR-0010). FAILED, not restated."
        )
    elif not passed:
        reasons = []
        if len(above) < MIN_BASELINES:
            reasons.append(f"only {len(above)} baselines beat the base rate, need {MIN_BASELINES}")
        if len(above) != len(evidence.scores):
            reasons.append(
                f"{len(evidence.scores) - len(above)} of the fitted baselines are at "
                "or below the base rate, so the suite is not 'strong'"
            )
        finding = f"FAILED on: {'; '.join(reasons) or 'see the figures above'}."
    else:
        finding = (
            "no model on the frontier is dominated and every fitted baseline beats "
            "the base rate, so criterion 1 is met on this split."
        )
    return GateCheck(
        "G2.1",
        "Five strong baselines, Stage 2 core not dominated",
        passed,
        f"{len(evidence.scores)} baselines fitted on {evidence.corpus} "
        f"count={evidence.count} and scored on seed={evidence.seed} (base rate "
        f"{evidence.base_rate:.4f}), {len(above)} of them above base rate: {table}. "
        f"Cost frontier at tied quality: {evidence.pareto.get('verdict', 'UNMEASURED')} "
        f"Dominated: {dominated or 'none'} — {finding} "
        f"Measured by {evidence.measured_by}, experiment {evidence.experiment_id} "
        f"(registered), content digest {(evidence.content_digest or 'UNSIGNED')[:19]}….",
    )


def _latent_frontier(ctx: Stage2GateContext) -> GateCheck:
    """2 — a minimum-sufficient latent-state frontier, on a corpus with headroom."""
    evidence = ctx.frontier
    if evidence is None:
        return GateCheck(
            "G2.2",
            "Minimum-sufficient latent-state frontier measured",
            False,
            f"UNMEASURED: {ctx.frontier_refusal}",
        )
    detail = (
        f"saturation_check on {evidence.corpus} count={evidence.count} "
        f"seed={evidence.seed}: best {evidence.best} ({evidence.best_model}), median "
        f"{evidence.median}, spread {evidence.spread}, order-free control "
        f"{evidence.order_free_baseline}, Φ-oracle {evidence.phi_oracle}, base rate "
        f"{round(evidence.base_rate, 4)} — degenerate={evidence.degenerate} "
        f"reason={evidence.reason}. Measured by {evidence.measured_by}, experiment "
        f"{evidence.experiment_id} (registered), content digest "
        f"{(evidence.content_digest or 'UNSIGNED')[:19]}…."
    )
    if evidence.degenerate:
        detail += (
            " refuse_if_degenerate stops the sweep, so no knee is recorded: a knee "
            "measured here would be a corpus-size artefact, not a frontier "
            "(ADR-0120). FAILED with reason DEGENERATE_CORPUS."
        )
    return GateCheck(
        "G2.2",
        "Minimum-sufficient latent-state frontier measured",
        not evidence.degenerate,
        detail,
    )


def _selective_routing(ctx: Stage2GateContext) -> GateCheck:
    """3 — selective routing reduces measured compute without security loss."""
    phantom = _phantom_savings_reason(ctx.cached_ledger) or _phantom_savings_reason(
        ctx.uncached_ledger
    )
    proposed = _cheap_fraction(ctx.cached.proposed_paths)
    derived = _cheap_fraction(ctx.cached.derived_paths)
    expensive = _expensive_fraction(ctx.cached.derived_paths)
    skipped = _skipped_inference_fraction(ctx.cached_ledger)
    # `derived >= proposed` is UNSATISFIABLE in this harness and says nothing
    # about the router: `runtime_pass` performs a WINDOW_UPDATE on every event
    # before the cache is consulted, WINDOW_UPDATE derives P2_LOCAL, and
    # `_derive_path` takes the max — so no event can ever derive a path in
    # CHEAP_PATHS however well the cache performs. Measured this session: a
    # second pass over an already-warm cache resolved 464/464 events from the
    # cache, genuinely skipping the cone and the inference, and still reported a
    # derived cheap fraction of 0.0000 (S2-05/S2-FC-06).
    #
    # What *can* discriminate is the expensive half: a router that delivers its
    # proposal leaves at most (1 - proposed) of events performing P3/P4 work.
    # A perfect router satisfies that; the present one cannot fake it, because
    # the fractions come from performed records.
    delivered = (
        proposed is not None
        and expensive is not None
        and expensive <= (1.0 - proposed) + _ROUTING_TOLERANCE
    )
    passed = phantom == "" and delivered and ROUTER_DEFAULT_ENABLED
    return GateCheck(
        "G2.3",
        "Selective routing reduces measured compute",
        passed,
        f"ledger honesty over {ctx.cached.events} events (both passes): "
        f"{phantom or 'no phantom savings'}. route_information_need proposed a cheap "
        f"path (P0/P1) for {_pct(proposed)} of events. The derived cheap fraction is "
        f"{_pct(derived)} and is STRUCTURALLY PINNED AT ZERO, not a measurement: "
        f"runtime_pass performs a mandatory WINDOW_UPDATE on every event before the "
        f"cache is consulted, WINDOW_UPDATE derives P2_LOCAL (8.0 units) and a path "
        f"is the max over performed work, so no event can derive P0/P1 here however "
        f"well the cache performs. The figure that is not pinned: the ledger proves "
        f"CORE_INFERENCE genuinely skipped for {_pct(skipped)} of events, and "
        f"{_pct(expensive)} of events performed P3/P4 work against the "
        f"{_pct(None if proposed is None else 1.0 - proposed)} the proposal implies "
        f"— proposal {'delivered' if delivered else 'NOT delivered'}. "
        f"ROUTER_DEFAULT_ENABLED={ROUTER_DEFAULT_ENABLED}: the measured router costs "
        "-0.115 PR-AUC at 3.4x the time, so no routing is enabled and no saving is "
        "claimed. FAILED; D2.4's honest artefact is the WorkLedger, not a number.",
    )


def _behaviour_atoms(ctx: Stage2GateContext) -> GateCheck:
    """4 — atoms stable enough to reuse, or the discrete layer is rejected."""
    order_a, order_b = ctx.test.sessions, tuple(reversed(ctx.test.sessions))
    learned_a, learned_b = BehaviourQuantizer(), BehaviourQuantizer()
    lattice_a, _ = build_lattice(learned_a, order_a)
    lattice_b, _ = build_lattice(learned_b, order_b)
    restructurer_a, restructurer_b = LatticeRestructurer(), LatticeRestructurer()
    merge_a = restructurer_a.merge_equivalent_atoms(learned_a, lattice_a)
    restructurer_b.merge_equivalent_atoms(learned_b, lattice_b)
    stability = restructurer_a.stability(restructurer_b)
    ids_a = {atom.atom_id for atom in learned_a.atoms()}
    ids_b = {atom.atom_id for atom in learned_b.atoms()}
    overlap = len(ids_a & ids_b) / len(ids_a | ids_b) if (ids_a | ids_b) else 0.0

    learned, control = BehaviourQuantizer(), HashBucketQuantizer()
    learned_lattice, _ = build_lattice(learned, ctx.train.sessions)
    control_lattice, _ = build_lattice(control, ctx.train.sessions)
    learned_loss = learned_lattice.log_loss(atom_pairs(learned, ctx.test.sessions))
    control_loss = control_lattice.log_loss(atom_pairs(control, ctx.test.sessions))

    rejection_reproduced = control_loss < learned_loss
    defaults_off = not BEHAVIOUR_QUANTIZER_ENABLED and DEFAULT_QUANTIZER is HashBucketQuantizer
    adr = adr_naming("behaviour-atoms")
    # stability() alone reads 1.0000 when no merge happened at all, which is not
    # a stable partition; the atom-id overlap is required with it so the
    # acceptance branch cannot be satisfied vacuously.
    accepted = (
        stability >= STABILITY_FLOOR
        and overlap >= STABILITY_FLOOR
        and learned_loss < control_loss
    )
    passed = accepted or (rejection_reproduced and defaults_off and bool(adr))
    return GateCheck(
        "G2.4",
        "Behaviour Atoms stable enough to reuse, or rejected",
        passed,
        f"two quantizer orders over {len(order_a)} sessions: stability "
        f"{stability:.4f} (floor {STABILITY_FLOOR}), atom-id overlap {overlap:.4f} "
        f"across {len(ids_a)}/{len(ids_b)} atoms, {merge_a.merges} merges — quoted "
        "together because stability alone reads 1.0000 when no merge happens at "
        "all, which is not the same as a stable partition. Transition log-loss on "
        f"held-out seed={TEST_SEED}: learned {learned_loss:.6f} "
        f"({learned.memory_bytes()} B) vs HashBucketQuantizer {control_loss:.6f} "
        f"({control.memory_bytes()} B). REJECTED branch: "
        f"BEHAVIOUR_QUANTIZER_ENABLED={BEHAVIOUR_QUANTIZER_ENABLED}, "
        f"DEFAULT_QUANTIZER={DEFAULT_QUANTIZER.__name__}, ADR {adr or 'MISSING'}; "
        f"rejection reproduced this run: {rejection_reproduced}.",
    )


def _calibrated_uncertainty(ctx: Stage2GateContext) -> GateCheck:
    """5 — uncertainty calibrated well enough to support abstention/AOP."""
    calibrator = IsotonicCalibrator()
    fitted = calibrator.fit(*phi_oracle_scores(ctx.train))
    held_out = calibrator.evaluate(*phi_oracle_scores(ctx.test))
    measured = conformal_coverage(ctx)
    coverage, radius, samples = measured.coverage, measured.radius, measured.samples

    ece = held_out.expected_calibration_error
    failures = _calibration_failures(
        calibration_id=calibrator.calibration_id(),
        refusal_reason=held_out.refusal_reason,
        ece=ece,
        brier=held_out.brier_score,
        conformal=measured,
    )
    return GateCheck(
        "G2.5",
        "Prediction uncertainty calibrated for abstention/AOP",
        not failures,
        f"IsotonicCalibrator fitted on seed={TRAIN_SEED} ({fitted.sample_count} "
        f"sessions, in-sample ECE {fitted.expected_calibration_error} — 0 by "
        f"construction, which is why the gate reads the held-out report): "
        f"calibration_id {calibrator.calibration_id()!r}, held-out ECE {ece} "
        f"(ceiling {ECE_CEILING}), Brier {held_out.brier_score}, "
        f"{held_out.sample_count} held-out sessions. SplitConformal on atom ΔΦ "
        f"residuals: radius {radius}, empirical coverage {_round(coverage, 4)} vs "
        f"nominal {NOMINAL_COVERAGE} +/-{COVERAGE_TOLERANCE} over {samples} held-out "
        f"edges — {measured.provenance()}, so the coverage figure is an estimate "
        f"from a bounded reservoir and is quoted with the bound rather than "
        f"without it. The score calibrated is the Φ-oracle scorer Stage 2 actually "
        f"exports (PHI_ORACLE_SCORER), not a research model's output."
        + (f" FAILED on: {'; '.join(failures)}." if failures else ""),
    )


def _calibration_failures(
    *,
    calibration_id: str | None,
    refusal_reason: str,
    ece: float | None,
    brier: float | None,
    conformal: ConformalCoverage,
) -> list[str]:
    """Every clause G2.5 must fail on, as data. Pure, so it can be tested directly.

    Split out of ``_calibrated_uncertainty`` because one of these clauses used to
    exist only in the detail string. ``saturated`` — a held-out Brier of exactly
    0.0 — was computed, printed as prose, and never appended to ``failures``, so
    G2.5 could PASS on exactly the degenerate, perfectly-separable split that
    G2.2 refuses the corpus for: the calibration_id, ECE and Brier clauses all
    succeed on such a split, and only the (separately defective) conformal clause
    happened to keep the aggregate verdict honest. Repairing the conformal
    eviction bias under S2-04 would have flipped G2.5 to PASS on evidence the
    same gate calls degenerate two criteria earlier (S2-08).
    """
    failures: list[str] = []
    if calibration_id is None:
        failures.append(f"calibration_id is None ({refusal_reason or 'unfitted'})")
    if ece is None:
        failures.append("held-out ECE is UNMEASURED")
    elif ece > ECE_CEILING:
        failures.append(f"held-out ECE {ece} > {ECE_CEILING}")
    if brier is None:
        failures.append("held-out Brier is UNMEASURED")
    elif brier == 0.0:
        failures.append(
            "held-out Brier is 0.0, i.e. this scorer separates the split perfectly; "
            "that is the same saturation G2.2 refuses the corpus for, and a "
            "calibration measured on it says nothing about calibration"
        )
    if conformal.coverage is None:
        failures.append("conformal coverage is UNMEASURED")
    elif abs(conformal.coverage - NOMINAL_COVERAGE) > COVERAGE_TOLERANCE:
        failures.append(
            f"conformal coverage {conformal.coverage:.4f} is outside "
            f"{NOMINAL_COVERAGE} +/-{COVERAGE_TOLERANCE} ({conformal.provenance()})"
        )
    return failures


def _future_cone_value(ctx: Stage2GateContext) -> GateCheck:
    """6 — Future Cone or hazard adds value beyond next-event prediction, or is removed."""
    cone_brier, marginal_brier, scored = cone_briers(ctx)
    hazard, constant, hazard_ece, constant_ece, pairs = hazard_scores(ctx)
    cone_better = (
        cone_brier is not None and marginal_brier is not None and cone_brier < marginal_brier
    )
    hazard_better = hazard is not None and constant is not None and hazard < constant
    enabled = FUTURE_CONE_DEFAULT_ENABLED or HAZARD_DEFAULT_ENABLED
    removed = not FUTURE_CONE_DEFAULT_ENABLED and not HAZARD_DEFAULT_ENABLED
    adr = adr_naming("future-cone")
    # A mechanism that is switched off adds nothing at runtime however it scores,
    # so a measured improvement only satisfies the "adds value" branch while the
    # mechanism is actually enabled. Otherwise the removal branch is the one in
    # play — and it needs this run to REPRODUCE the rejecting measurement, not
    # only the flags and the ADR filename.
    #
    # This is what the module docstring above promises and what ADR-0113 rules 1
    # and 3 require: an ADR is consulted *beside* a measurement this run
    # reproduced. G2.4 already worked that way (`rejection_reproduced =
    # control_loss < learned_loss`); G2.6 did not. Its removal branch was
    # `removed and bool(adr)`, so it passed on two module constants being False
    # and a `docs/adr/*.md` filename containing both "future-cone" and
    # "rejected" — an empty file of that name was sufficient — while
    # `cone_briers` and `hazard_scores` were computed at real cost (4,297
    # continuations and 52,284 hazard predictions on this corpus) and then
    # discarded. It passed identically when the cone scored better than its
    # control and when both sides came back UNMEASURED (S2-FC-07).
    rejection_reproduced = (
        cone_brier is not None
        and marginal_brier is not None
        and hazard is not None
        and constant is not None
        and not cone_better
        and not hazard_better
    )
    passed = ((cone_better or hazard_better) and enabled) or (
        removed and bool(adr) and rejection_reproduced
    )
    return GateCheck(
        "G2.6",
        "Future Cone/hazard adds measurable value, or is removed",
        passed,
        f"branch Brier over {scored} one-step continuations on {GATE_CORPUS} "
        f"count={GATE_COUNT} seed={TEST_SEED}, cone measured at its most favourable "
        f"depth (1): cone {_round(cone_brier)} vs marginal_cone "
        f"{_round(marginal_brier)} — lower is better, improvement={cone_better}. "
        f"Hazard over {pairs} (outcome, horizon) predictions: Brier {_round(hazard)} "
        f"vs constant_hazard {_round(constant)}, ECE {_round(hazard_ece)} vs "
        f"{_round(constant_ece)} — improvement={hazard_better}. These absolute values "
        f"are NOT comparable with ADR-0116's: that measurement used its own truth "
        f"definition and corpus size, and only the sign within a single run means "
        f"anything. Nothing here overturns the ADR, and a cone that scores better "
        f"than its control on one saturated split is not a mechanism that earned "
        f"its place. REMOVED branch: FUTURE_CONE_DEFAULT_ENABLED="
        f"{FUTURE_CONE_DEFAULT_ENABLED}, HAZARD_DEFAULT_ENABLED="
        f"{HAZARD_DEFAULT_ENABLED}, ADR {adr or 'MISSING'}, rejection reproduced "
        f"this run: {rejection_reproduced} — the branch does NOT pass on the ADR "
        f"and the flags alone, because an ADR consulted without a measurement "
        f"this run reproduced is prose deciding a gate (ADR-0113). Neither "
        f"mechanism may reach a verdict, a score or a compile candidate while "
        f"those flags are off, so nothing downstream can turn this measurement "
        f"into a claim.",
    )


def _causal_credit(ctx: Stage2GateContext) -> GateCheck:
    """7 — causal credit is more concise than naive ancestry at equal recall."""
    rows = attribution_rows()
    if not rows:
        return GateCheck(
            "G2.7",
            "Causal credit more concise than naive ancestry",
            False,
            "no attack session in the drift corpus produced a ground-truth chain; "
            "nothing was measured, so nothing is claimed",
        )
    met = [row for row in rows if row["concise_at_equal_recall"]]
    ours = _mean([row["nodes_inspected"] for row in rows])
    naive = _mean([row["naive_nodes"] for row in rows])
    recall = _mean([row["recall"] for row in rows if row["recall"] is not None])
    naive_recall = _mean(
        [row["naive_recall"] for row in rows if row["naive_recall"] is not None]
    )
    attributed_nothing = ours == 0.0
    return GateCheck(
        "G2.7",
        "Causal credit more concise than naive ancestry",
        len(met) == len(rows),
        f"{len(rows)} attack sessions from the drift corpus (ground truth is the "
        f"fixture's own attack lineage, never ΔΦ): credit spine inspects "
        f"{_round(ours, 2)} nodes against naive ancestry's {_round(naive, 2)} at "
        f"chain recall {_round(recall, 4)} vs {_round(naive_recall, 4)}. Criterion "
        f"met on {len(met)}/{len(rows)} sessions."
        + (
            " The spine awarded credit to NOTHING on this fixture: no probe's "
            "divergence reached MATERIAL_DIVERGENCE, so the ledger stayed empty and "
            "recall is 0.0 while naive ancestry recovers the chain completely. That "
            "is not 'concise', it is 'attributed nothing', and the two must not be "
            "reported as if they were the same result (ADR-0122). FAILED."
            if attributed_nothing
            else " The criterion requires recall at least as good as the naive "
            "path's; concision bought with recall does not meet it. FAILED."
        ),
    )


def _drift_without_normalising(ctx: Stage2GateContext) -> GateCheck:
    """8 — drift/epoch adaptation without normalising repeated malicious behaviour."""
    gated = adaptation_run(
        build_drift_corpus(count=ROBUSTNESS_COUNT, seed=TEST_SEED),
        malicious_lineage,
        AdaptationPolicy.QUARANTINED,
    ).run
    ungated = adaptation_run(
        build_drift_corpus(count=ROBUSTNESS_COUNT, seed=TEST_SEED),
        malicious_lineage,
        AdaptationPolicy.ACCEPT_EVERYTHING,
    ).run
    report = drift_report(gated)
    recovered = report.transitions_to_recover is not None
    clean = report.malicious_patterns_normalised == 0
    learned_something = gated.promotions > 0
    passed = recovered and clean and learned_something
    return GateCheck(
        "G2.8",
        "Drift adapts without normalising malicious behaviour",
        passed,
        f"drift corpus count={ROBUSTNESS_COUNT} seed={TEST_SEED}, {gated.scenarios} "
        f"scenarios, {gated.samples} samples ({gated.escalating_samples} carrying "
        f"escalating meaning): transitions_to_recover "
        f"{report.transitions_to_recover}, atoms_invalidated "
        f"{report.atoms_invalidated}, reused after change "
        f"{report.atoms_reused_after_change}, malicious_patterns_normalised "
        f"{report.malicious_patterns_normalised} (must be 0). The gate promoted "
        f"{gated.promotions} patterns, so 'nothing normalised' is not satisfied by "
        f"never learning; ACCEPT_EVERYTHING control normalises "
        f"{ungated.escalating_promotions} escalating patterns against the gate's "
        f"{gated.escalating_promotions}. No atom became epoch-valid without a "
        f"corroborated EpochDecision: {len(gated.epoch_decisions)} decisions recorded.",
    )


def _poisoning_quarantine(ctx: Stage2GateContext) -> GateCheck:
    """9 — poisoning tests validate the quarantine/promotion path."""
    gated = adaptation_run(
        build_poison_suite(count=ROBUSTNESS_COUNT, seed=TEST_SEED),
        poison_lineage,
        AdaptationPolicy.QUARANTINED,
    )
    ungated = adaptation_run(
        build_poison_suite(count=ROBUSTNESS_COUNT, seed=TEST_SEED),
        poison_lineage,
        AdaptationPolicy.ACCEPT_EVERYTHING,
    )
    run, control = gated.run, ungated.run
    quarantine = run.quarantine
    bounded = (
        quarantine["pending_patterns"] + quarantine["retained_evidence"]
        <= gated.buffer.capacity
    )
    #: The criterion's literal reading: no sample of a poison lineage promoted.
    literal_met = run.attack_lineage_promotions == 0
    mechanism_holds = (
        run.escalating_promotions == 0 and gated.frequency_alone_refused and bounded
    )
    return GateCheck(
        "G2.9",
        "Poisoning validates the quarantine/promotion path",
        literal_met and mechanism_holds,
        f"poison suite count={ROBUSTNESS_COUNT} seed={TEST_SEED}, {run.samples} "
        f"samples: outcomes {run.outcomes}; {run.promotions} promotions, of which "
        f"{run.escalating_promotions} carried escalating meaning (must be 0) and "
        f"{run.attack_lineage_promotions} came from a poison lineage. "
        f"ACCEPT_EVERYTHING control: {control.escalating_promotions} escalating "
        f"promotions from {control.promotions}. Refusal reasons "
        f"{gated.refusal_reasons}; frequency alone refused: "
        f"{gated.frequency_alone_refused}. Buffer bounded at {gated.buffer.capacity} "
        f"records holding {quarantine['pending_patterns']} patterns + "
        f"{quarantine['retained_evidence']} evidence, "
        f"{quarantine['dropped_patterns']}/{quarantine['dropped_evidence']} drops "
        f"counted: {bounded}. The criterion as written — every poisoned *sample* "
        f"ends REFUSED or RETAINED_AS_EVIDENCE — is NOT MEASURABLE as stated: a "
        f"poisoned session also contains ordinary reads by the same lineage and "
        f"ADR-0007 removes identity from the encoding, so nothing could refuse "
        f"those without refusing legitimate traffic. The checkable invariant (no "
        f"escalating promotion) is reported beside it, never in place of it.",
    )


def _sleeping_brain(ctx: Stage2GateContext) -> GateCheck:
    """10 — quantify how much traffic avoids expensive inference, unfakeably."""
    phantom = _phantom_savings_reason(ctx.cached_ledger) or _phantom_savings_reason(
        ctx.uncached_ledger
    )
    refuses_a_fake = _phantom_check_refuses_a_fake()
    cached_us = ctx.cached.microseconds_per_event
    uncached_us = ctx.uncached.microseconds_per_event
    skipped = ctx.cached.cache_fraction
    # The control pass compares every would-be hit against the answer the deep
    # path computes for the same event. A skip whose answer differs from the
    # inference it replaced has not avoided that inference — it has substituted
    # a different answer for it, which is ADR-0010's "labelling work instead of
    # avoiding it" one layer down. So the skipped fraction is only a saving
    # while the agreement holds, and the criterion fails when it does not.
    agreement = ctx.uncached.cache_agreement
    answers_agree = agreement is not None and agreement >= CACHE_AGREEMENT_FLOOR
    quantified = (
        phantom == ""
        and refuses_a_fake
        and answers_agree
        and cached_us is not None
        and uncached_us is not None
        and skipped is not None
    )
    beats_lru = (
        None
        if skipped is None or ctx.lru_fraction is None
        else skipped > ctx.lru_fraction
    )
    return GateCheck(
        "G2.10",
        "Sleeping-brain traffic quantified, unfakeably",
        quantified,
        f"{ctx.cached.events} events through the stdlib path: "
        f"{ctx.cached.cache_resolved} resolved from the transition cache "
        f"({_pct(skipped)}) and {ctx.cached.inferred} needed cone + uncertainty, "
        f"{ctx.cached.abstentions} abstained; ledger work histogram "
        f"{ctx.cached_ledger.histogram()}; derived path fractions "
        f"{dict(ctx.cached.derived_paths)}. Wall clock {_us(cached_us)} µs/event with "
        f"the cache honoured against {_us(uncached_us)} µs/event with every hit "
        f"ignored — the same work, so the difference is the skip. F10 control: a "
        f"plain LRU keyed on (relation_family, state_delta_mask) finds "
        f"{_pct(ctx.lru_fraction)} of events resident, so the atom/epoch-keyed "
        f"cache's skipped fraction beats a key cache alone: {beats_lru}. No phantom "
        f"savings on either ledger: {phantom == ''}. A deliberately fabricated skip "
        f"is refused by assert_no_phantom_savings: {refuses_a_fake} — which is what "
        f"stops this number being the fakeable kind the criterion excludes. "
        f"ANSWER AGREEMENT, measured in the control pass where the deep path runs "
        f"anyway: {_pct(agreement)} of {ctx.uncached.cache_agreements + ctx.uncached.cache_disagreements} "
        f"would-be hits served the value the deep path computed for that same event "
        f"({ctx.uncached.cache_disagreements} disagreed), floor "
        f"{CACHE_AGREEMENT_FLOOR}: {answers_agree}. The P0 key is "
        f"(atom_id, epoch_id, state_delta_mask) and carries NO lineage, while the "
        f"stored payload is the first inserting lineage's own state snapshot — so a "
        f"hit serves another lineage's numbers. A skip whose answer differs from the "
        f"inference it replaced has not avoided that inference, it has replaced it "
        f"with a different answer, and counting it as sleep is ADR-0010's notional "
        f"accounting one layer down. Until this agreement figure existed nothing in "
        f"this repository ever compared a cheap-path answer with a deep-path one, so "
        f"the skipped fraction measured key repetition (S2-06).",
    )


def _resource_envelope(ctx: Stage2GateContext) -> GateCheck:
    """11 — Stage 2 stays inside the Stage 0 Edge envelope on the 2 GB target."""
    resources = ctx.resources
    within = resources["within_target"]
    incremental = resources["incremental_rss_bytes"]
    inside_ceiling = (
        None if incremental is None else incremental <= STAGE2_INCREMENTAL_RSS_CEILING_BYTES
    )
    passed = within is True and inside_ceiling is True
    metrics = resources["metrics"]
    return GateCheck(
        "G2.11",
        "Within the Stage 0 Edge memory/CPU envelope",
        passed,
        f"{resources['pass']['events']} events under ResourceSampler: peak sampled "
        f"RSS {metrics['peak_sampled_rss_bytes']} B, "
        f"{metrics['cpu_seconds_per_event']} CPU s/event; Edge profile "
        f"within_target={within} ({resources['profile']['observations']}, exceeded "
        f"{resources['profile']['exceeded']}, unmeasured "
        f"{resources['profile']['unmeasured']}). Incremental RSS {incremental} B "
        f"against the {STAGE2_INCREMENTAL_RSS_CEILING_BYTES} B Stage 2 ceiling: "
        f"{inside_ceiling}. Model bytes {resources['model_bytes']} "
        f"({resources['component_bytes']}). Measured on this development host, not "
        "on a 2 GB device: the Edge profile is a target comparison, not a device "
        "measurement.",
    )


def _components_ablation_supported(ctx: Stage2GateContext) -> GateCheck:
    """12 — every surviving optional component has an ablation-supported reason."""
    optional = tuple(
        function.core_id for function in CORE_IDS.values()
        if function.function_class is FunctionClass.OPTIONAL
    )
    entries = tuple(ExperimentRegistry(gate_evidence.REGISTRY_PATH).all())
    stage2 = sorted(
        entry.experiment_id
        for entry in entries
        if entry.experiment_id.startswith("PS-S2-")
    )
    this_wave = sorted(eid for eid in stage2 if _sequence_of(eid) >= WAVE_SEQUENCE_START)
    supported = _ablation_support(entries)
    unsupported = sorted(core_id for core_id in optional if core_id not in supported)
    degenerate = ctx.frontier is None or ctx.frontier.degenerate
    # `passed` used to be `len(this_wave) >= len(optional)`: two integers, with
    # nothing joining a registered experiment to a component and nothing reading
    # what any of them measured. Twelve rows about anything — reruns of one
    # ablation, or components already rejected — flipped it to PASS with every
    # OPTIONAL core id exactly as unjustified as before, which is the "make the
    # gate pass by restating the criterion" failure this gate exists to prevent
    # (S2-AUTH-09). The degeneracy clause the detail string already called
    # independent is now actually evaluated too (S2-FC-02).
    passed = not unsupported and not degenerate
    return GateCheck(
        "G2.12",
        "Every surviving optional component is ablation-supported",
        passed,
        f"{len(optional)} OPTIONAL core ids in CORE_IDS ({', '.join(optional)}); "
        f"{len(stage2)} Stage 2 experiments in experiments/registry.jsonl, of which "
        f"{len(this_wave)} are from this wave (sequence >= "
        f"{WAVE_SEQUENCE_START:04d}). Joined slot_name -> core id via "
        f"ABLATION_SLOTS and read each row's recorded verdict: "
        f"{len(optional) - len(unsupported)}/{len(optional)} OPTIONAL core ids "
        f"carry a registered JUSTIFIED ablation. WITHOUT ONE: "
        f"{', '.join(unsupported) or 'none'} — a REJECTED or NOT_YET_JUSTIFIED "
        f"verdict is a failure, never pending, and a component verdict this wave "
        f"minted but did not register identifies a measurement that lives in a "
        f"report and not in the append-only ledger. Appending a row proves "
        f"nothing here: the row has to name the component and carry its verdict. "
        f"Independently, the split this gate measured is degenerate="
        f"{degenerate} ({ctx.frontier.reason if ctx.frontier else 'UNMEASURED'}), "
        f"so every split-dependent component delta is UNMEASURABLE rather than "
        f"JUSTIFIED.",
    )


def _ablation_support(entries: Any) -> set[str]:
    """Core ids with a registered, JUSTIFIED ablation from this wave.

    The registry row carries the component under ``slot_name`` and its verdict
    at the head of ``notes`` — the two fields ``research/cli.py:_register``
    writes — so the join is on what was measured, not on how many rows exist.
    """
    supported: set[str] = set()
    for entry in entries:
        if not entry.experiment_id.startswith("PS-S2-"):
            continue
        if _sequence_of(entry.experiment_id) < WAVE_SEQUENCE_START:
            continue
        if not entry.notes.startswith(JUSTIFIED_VERDICT):
            continue
        supported.update(ABLATION_SLOTS.get(entry.slot_name, ()))
    return supported


def _stage3_export(ctx: Stage2GateContext) -> GateCheck:
    """13 — stable candidates exportable to Stage 3 without DTL assumptions."""
    problems: list[str] = []
    candidate = phi_candidate(ctx)
    with tempfile.TemporaryDirectory(prefix="stage2-gate-") as scratch:
        # The gate writes nowhere durable: `results/` holds registered
        # experiments, and an export made to prove the format works is not one.
        export = export_candidates((candidate,), Path(scratch) / "candidates.json")
        handoff = build_handoff(export, handoff_id="stage2-gate-handoff")
        digest = write_handoff(handoff, Path(scratch) / "handoff.json")
    if export.refused:
        problems.append(f"exporter refused the Φ-oracle candidate: {export.refused}")
    if Stage3Handoff.from_dict(handoff.to_dict()) != handoff:
        problems.append("handoff does not round-trip through from_dict(to_dict(...))")
    violations = seam_violations(handoff.to_dict())
    if violations:
        problems.append(f"handoff names Stage 2 machinery: {violations}")
    problems.extend(rejects_unevidenced_candidates(candidate))
    imports = research_imports(_CANDIDATE_PACKAGE)
    if imports:
        problems.append(f"compile_candidates/ imports research code: {imports}")
    # The detail used to be formatted from the candidate object regardless of
    # whether the exporter accepted it, so a run in which every candidate was
    # refused still read "... exported as DETERMINISTIC_SCORER with 4 evidence
    # refs ... 72 B exported ... round-trips, 0 seam violations". Those 72 bytes
    # are the JSON envelope of an EMPTY candidate list, and the seam check ran
    # over a handoff containing nothing — so "0 seam violations" was vacuous
    # rather than reassuring, and PROGRESS restated it as end-to-end
    # verification (S2-FC-10). The verdict language now follows what happened.
    if export.candidates:
        headline = (
            f"{candidate.candidate_id} exported as {candidate.kind.value} with "
            f"{len(candidate.evidence_lineage)} evidence refs, boundary "
            f"{sorted(candidate.boundary.epochs)} epochs @ "
            f"{candidate.boundary.encoder_version}, cost "
            f"{candidate.cost.microseconds_per_event} µs/event at "
            f"{candidate.cost.parameters} parameters, {export.total_bytes} B "
            f"exported; handoff digest {digest[:19]}…, round-trips, "
            f"{len(violations)} seam violations over {len(handoff.candidates)} "
            f"candidate(s)."
        )
    else:
        headline = (
            f"NOTHING WAS EXPORTED: the exporter refused every candidate "
            f"({export.refused or 'no candidate offered'}), so the file written "
            f"is the bare envelope of an empty list ({export.total_bytes} B) and "
            f"the handoff projects empty candidates, atom prototypes, transition "
            f"statistics, uncertainty envelopes and evidence requirements. The "
            f"round-trip and the {len(violations)} seam violations were measured "
            f"over that empty handoff and prove nothing about the seam; the "
            f"digest {digest[:19]}… is the digest of nothing. "
            f"{candidate.candidate_id} was BUILT ({candidate.kind.value}, "
            f"{len(candidate.evidence_lineage)} evidence refs, cost "
            f"{candidate.cost.microseconds_per_event} µs/event) but not accepted."
        )
    return GateCheck(
        "G2.13",
        "Stable candidates exportable to Stage 3",
        not problems,
        headline
        + f" {len(imports)} research imports under compile_candidates/ (a static "
        f"AST scan, independent of the export). An unevidenced or unparseable "
        f"candidate is rejected by construction — also checked on the candidate "
        f"object, independent of the export. A zero-parameter deterministic "
        f"scorer is designed to travel as a first-class candidate, which is what "
        f"Stage 3 crystallises first."
        + (f" PROBLEMS: {'; '.join(problems)}" if problems else ""),
    )
