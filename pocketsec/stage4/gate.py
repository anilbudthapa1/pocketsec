"""The Stage 4 acceptance gate (``docs/stage-4-spec.md`` §6), as an executable check.

Twelve criteria, one per bullet of architecture §47, each evaluated by running the real
subsystems rather than inspecting a document. Like Stage 0's, Stage 1's, Stage 2's and
Stage 3's gates, this is code: ``pocketsec-stage4 gate`` exits non-zero if any criterion
fails.

Four things about this gate are worth stating before anyone reads a result off it.

**It is expected to fail, and its failures are Stage 4's findings.** The spec said so in
advance (§6.2) so that a failing gate would not be mistaken for a failed wave, and so
that nobody would be tempted to restate a criterion until it passed — the single most
useful defect class found in Stage 2, where four gate numbers were structurally
incapable of coming out differently (ADR-0113).

**One defect dominates the result and it is named in every check it touches.** No step of
the LUCID loop ever writes a world's ``support`` back into the field: ``WorldSupport.combine``
is called from ``counterfactual/`` and from the labs, and from nowhere under
``engine/``. Measured this session over a 74-transition incident, every world sat at
log-odds 0.0 / ``UNRESOLVED`` for all 74 steps. Everything downstream of a moving support
vector therefore reads as a tie: the support margin is 0.0, so identifiability is
``UNIDENTIFIABLE`` on every case; confidence is 0.0 on every case; and every
counterfactual support shift is exactly 0.0. G4.2, G4.5 and G4.6 fail on that, and G4.4's
inequality holds *vacuously* because of it. **This gate does not fix it.** Authoring the
belief-update arithmetic here would mean the integrator inventing the mechanism that
G4.2 and G4.10 then score, against the corpus it is scored on — the authorship confound
§6.1 names. It is reported, not papered over.

**No check reads a document to decide a mechanism question.** Two read files and both are
*about* files: G4.1 writes and re-reads its own replay evidence so the provenance rule of
ADR-0127 has something to bind, and G4.12 checks the prior-art ledger and the findings
document. Everything else runs the subsystem.

**Nothing measured here is a detection result.** Every corpus in this repository is
synthetic (ADR-0010), the wave that authored ``GroundTruthWorld`` also authored the
mechanism vocabulary, and timings on this host are contended — a Stage 2 gate saw a 7x
inflation between load 8-12 and load 23-67. Figures are within-run ratios with
``/proc/loadavg`` beside them; no absolute microsecond figure here is a device
measurement.

This gate **never** appends to ``experiments/registry.jsonl`` (spec §2.7). It reads the
ledger's digest before and after itself and G4.12 asserts they match. Registration is
``pocketsec-stage4 register``, which an operator invokes deliberately.
"""

from __future__ import annotations

from dataclasses import dataclass

from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage0.gate import REPO_ROOT, GateCheck, GateReport
from pocketsec.stage0.prior_art import PriorArtLedger
from pocketsec.stage1.observation.policy import AdaptiveObservationPolicy, MANDATORY_SIGNALS
from pocketsec.stage4 import gate_bounds as bounds
from pocketsec.stage4 import gate_criteria as criteria
from pocketsec.stage4 import gate_optionality as optionality
from pocketsec.stage4 import gate_probes as probes
from pocketsec.stage4.claims.compiler import amplification_violations
from pocketsec.stage4.claims.typed_claim import (
    AUTHORITATIVE_KINDS,
    ClaimKind,
    TypedClaim,
    kind_of,
)
from pocketsec.stage4.core_ids import ABLATION_FLAGS, CORE_IDS, OPTIONAL_IDS
from pocketsec.stage4.counterfactual.stress import (
    PerturbationKind,
    stress_world_adversarially,
    stresses_actually_run,
)
from pocketsec.stage4.identifiability.resolution import IdentifiabilityState
from pocketsec.stage4.labs.baseline_metrics import BaselineOutcome, Replay, replay_corpus
from pocketsec.stage4.labs.baselines import pareto_frontier, run_baselines, saturation_guard
from pocketsec.stage4.labs.experiments import (
    EXPERIMENTS,
    blocked_experiments,
    run_ablation,
    saturation_check,
)
from pocketsec.stage4.labs.incident_corpus import (
    IncidentCase,
    decoy_cases,
)
from pocketsec.stage4.labs.nonidentifiable import (
    RESOLVING_SIGNAL,
    apply_granted_observation,
    build_corpus_visibility_model,
    build_nonidentifiable_pairs,
    build_resolvable_after_one_observation,
    field_for_nonidentifiable_pair,
    field_for_resolvable_case,
)
from pocketsec.stage4.resources import loadavg
from pocketsec.stage4.theory import unbound_terms
from pocketsec.stage4.visibility.sensor_shadow import verdict_committal_rank
from pocketsec.stage4.worlds.lifecycle import FUSION_EQUIVALENCE_EPSILON

__all__ = [
    "EXPERIMENT_ID",
    "STAGE4_HYPOTHESIS",
    "STAGE4_SECONDARY",
    "Stage4GateContext",
    "run_gate",
]

#: Stage 4 mints no hypothesis of its own. ``pocketsec.stage0.hypotheses`` holds H0-H8
#: and ``tests/test_harness_and_gate.py`` asserts the prior-art ledger covers exactly
#: that set, so appending H10 would mean editing a Stage 0 file another wave may be in.
#: Stage 3 hit this and took the honest route; spec §2.9 names the same one here. H3 is
#: the falsifiable, measurable half of Stage 4 — active sensing and the entropy budget.
STAGE4_HYPOTHESIS = "H3"
#: The world representation itself. Secondary because Stage 4 does not fit it.
STAGE4_SECONDARY = "H7"

EXPERIMENT_ID = "PS-S4-20260925-H3-cbf-gate-0001"

_FINDINGS = REPO_ROOT / "docs" / "stage-4-findings.md"
_STAGE4_ROOT = REPO_ROOT / "pocketsec" / "stage4"

#: G4.2's two thresholds, from the criterion's own wording.
MIN_WORLD_SET_RECALL = 0.9
MAX_PREMATURE_COLLAPSE = 0.1

#: G4.5's quality band, from the criterion's own wording.
SENSING_QUALITY_BAND = 0.02


@dataclass
class Stage4GateContext:
    """One corpus walk, one engine run, one baseline table, shared by twelve checks.

    Built once because the comparisons *are* within-run: G4.2, G4.5 and G4.10 all read
    the same engine walk and the same baseline table, and re-running them per check
    would compare three different moments of a contended host against each other
    (spec §2.8).
    """

    cases: tuple[IncidentCase, ...]
    replays: tuple[Replay, ...]
    dropped_replays: tuple[Replay, ...]
    visibility: criteria.VisibilitySplit
    runs: tuple[criteria.EngineRun, ...]
    dropped_runs: tuple[criteria.EngineRun, ...]
    recall: criteria.RecallReading
    work_units: int
    observation: AdaptiveObservationPolicy
    registry_digest_before: str | None
    loadavg: tuple[float, float, float]
    #: ONE baseline table for G4.2, G4.5 and G4.10. The docstring always said so and
    #: the code ran ``run_baselines`` three times, so G4.2's B1-vs-CBF CPU figure came
    #: from a different run than G4.5's and G4.10's (S4-MEAS-07).
    baselines: tuple[BaselineOutcome, ...] = ()

    @classmethod
    def build(cls) -> Stage4GateContext:
        digest_before = criteria.registry_digest()
        cases = criteria.corpus()
        replays = replay_corpus(cases)
        dropped = criteria.dropped_replays(cases)
        visibility = criteria.measure_visibility_split(cases)
        observation = AdaptiveObservationPolicy()
        runs, engine = criteria.drive_engine(
            replays, visibility.model, observation=observation
        )
        # The dropped-telemetry arm gets its own AOP and its own engine: sharing either
        # would let the full-telemetry run's escalation budget decide what the degraded
        # run was allowed to collect, and G4.4 is a paired comparison.
        dropped_runs, _ = criteria.drive_engine(
            dropped, visibility.model, observation=AdaptiveObservationPolicy()
        )
        return cls(
            cases=cases,
            replays=replays,
            dropped_replays=dropped,
            visibility=visibility,
            runs=runs,
            dropped_runs=dropped_runs,
            recall=criteria.world_set_recall(runs),
            work_units=engine.work_units,
            observation=observation,
            registry_digest_before=digest_before,
            loadavg=loadavg(),
            baselines=run_baselines(
                cases, seed=criteria.CORPUS_SEED, model=visibility.model
            ),
        )


def run_gate() -> GateReport:
    """Evaluate all twelve Stage 4 acceptance criteria."""
    ctx = Stage4GateContext.build()
    return GateReport(
        checks=(
            _visibility_empirically_measured(ctx),
            _ground_truth_world_preserved(ctx),
            _non_identifiability_recognised(ctx),
            _tension_and_shadow_under_dropped_telemetry(ctx),
            _active_sensing_pays_for_itself(ctx),
            _stress_finds_the_predefined_spurious_world(ctx),
            _claim_kinds_separated_by_construction(ctx),
            _no_unsupported_authoritative_claims(ctx),
            _bounds_hold_under_flood(ctx),
            _pareto_frontier_against_simpler_baselines(ctx),
            _stage4_remains_optional_when_it_crashes(ctx),
            _novelty_claims_stay_provisional(ctx),
        )
    )


# --- G4.1 --------------------------------------------------------------------


def _visibility_empirically_measured(ctx: Stage4GateContext) -> GateCheck:
    """G4.1 — the simulator half is measured; the telemetry-source clause is not.

    **This check fails by design and the spec says so in advance** (§6.1). The criterion
    is "empirically measured for supported telemetry sources", and the supported sources
    are eBPF, auditd, procfs, journald and LSM on a real Linux host. This repository has
    none: every path here is a replay of a synthetic corpus through a simulated
    collector. What *is* honestly measurable is the fitting and refusal behaviour of the
    visibility model, and that is measured and reported — but half a criterion is not a
    criterion, and Stage 3's G3.9 set the precedent for failing rather than passing on
    the measurable half.
    """
    split = ctx.visibility
    criteria.write_visibility_evidence(split)
    provenance_ok = criteria.visibility_evidence_matches(split)
    simulator_half = (
        not split.mismatches
        and not split.mandatory_not_certain
        and not split.unevidenced_not_none
        and split.compared_pairs > 0
        and provenance_ok
    )
    return GateCheck(
        "G4.1",
        "Partial-observability and visibility models empirically measured",
        False,
        f"MEASURED (simulator): {split.compared_pairs} held-out (signal, sensor) pairs with "
        f">={criteria.HELD_OUT_MIN_OCCURRENCES} occurrences, "
        f"{len(split.mismatches)} outside +-{criteria.VISIBILITY_TOLERANCE} of the fitted "
        f"probability"
        + (f" {split.mismatches[:3]}" if split.mismatches else "")
        + f"; all {len(MANDATORY_SIGNALS)} MANDATORY_SIGNALS answer 1.0: "
        f"{not split.mandatory_not_certain}; an unevidenced pair answers None not 0.0: "
        f"{not split.unevidenced_not_none}; coverage {split.coverage}; evidence written to "
        f"{criteria.VISIBILITY_EVIDENCE.relative_to(REPO_ROOT)} and its provenance matches the "
        f"split just run: {provenance_ok}; simulator half met: {simulator_half}. "
        "UNMEASURED (and the reason this check FAILS): the telemetry-source clause. No real "
        "eBPF, auditd, procfs, journald or LSM data exists in this repository, so nothing here "
        "measures Linux sensor visibility. What would measure it: paired eBPF/auditd collection "
        "on a real host with ground-truth injected actions. The coverage figure is "
        f"{split.coverage} because the model deliberately fits only relation-family signals — "
        "the corpus does not state whether a mandatory semantic signal's precondition held, and "
        "counting the operation as an occurrence measured 12 occurrences / 0 observations for "
        "'authentication', a fabricated 'totally blind' reading for a signal that never occurred.",
    )


# --- G4.2 --------------------------------------------------------------------


def _ground_truth_world_preserved(ctx: Stage4GateContext) -> GateCheck:
    """G4.2 — is the ground-truth world, or an equivalent, still standing?

    Three readings of "or an equivalent explanation" are measured because they disagree
    by a factor of seven on this corpus, and quoting only one would report the choice
    rather than the mechanism. The criterion is scored on the spec's own two clauses —
    the named mechanism, or ``observationally_equivalent`` at
    ``FUSION_EQUIVALENCE_EPSILON``.
    """
    recall = ctx.recall
    baselines = {outcome.baseline_id: outcome for outcome in ctx.baselines}
    b1 = baselines.get("B1_SingleWorldMAP")
    cbf = baselines.get("CBF_LUCID")
    b1_matches = (
        b1 is not None
        and cbf is not None
        and b1.world_set_recall is not None
        and cbf.world_set_recall is not None
        and b1.world_set_recall >= cbf.world_set_recall
        and b1.cpu_units <= cbf.cpu_units
    )
    passed = (
        recall.strict >= MIN_WORLD_SET_RECALL
        and recall.premature_collapse_rate <= MAX_PREMATURE_COLLAPSE
        and not b1_matches
    )
    return GateCheck(
        "G4.2",
        "CBF preserves the ground-truth world or an equivalent explanation",
        passed,
        f"over {recall.cases} cases of build_incident_corpus(count={criteria.CORPUS_COUNT}, "
        f"seed={criteria.CORPUS_SEED}): world-set recall by mechanism_id "
        f"{recall.by_mechanism_id:.4f}, by observational equivalence at eps="
        f"{FUSION_EQUIVALENCE_EPSILON} {recall.by_equivalence:.4f}, so the criterion's own "
        f"reading is {recall.strict:.4f} against the required {MIN_WORLD_SET_RECALL}. "
        f"Premature-collapse rate {recall.premature_collapse_rate:.4f} (<= "
        f"{MAX_PREMATURE_COLLAPSE}) — and it is 0.0000 for the wrong reason: the engine "
        f"resolved IDENTIFIED on zero of {recall.cases} cases, so it cannot collapse early "
        f"because it never collapses at all. THE NUMBER THAT DECIDED THIS: recall "
        f"{recall.strict:.4f}. WHY: every world the engine spawns is named "
        f"'unresolved_novel_mechanism' (worlds/lifecycle.py:_mechanism_id_for) and asserts no "
        f"dimension (worlds/field.py:unknown_world), so it can match the corpus's mechanism "
        f"vocabulary only by coincidence and can never be observationally equivalent to a "
        f"truth world that asserts one. The stage ships no mechanism-proposal path at all. "
        f"A third reading — signal coverage, which labs/baselines.py scores the frontier on — "
        f"gives {recall.by_signal_coverage:.4f}; it is reported and NOT used, because "
        f"B3_AlwaysOnRichTelemetry scores 1.0 on it by its own docstring's admission, so a "
        f"reading a do-nothing control saturates is measuring the reading. B1 single-world MAP "
        f"matches recall at no greater CPU: {b1_matches}"
        + (
            f" (B1 recall {b1.world_set_recall}, cpu {b1.cpu_units:.4f}; CBF recall "
            f"{cbf.world_set_recall}, cpu {cbf.cpu_units:.4f})"
            if b1 is not None and cbf is not None
            else ""
        )
        + f". loadavg {ctx.loadavg}.",
    )


# --- G4.3 --------------------------------------------------------------------


def _non_identifiability_recognised(ctx: Stage4GateContext) -> GateCheck:
    """G4.3 — UNIDENTIFIABLE on constructed pairs, INSUFFICIENT_EVIDENCE when one look would do.

    The distinction is the criterion. ``test_identifiability`` can only draw it against a
    plan that was actually computed, and a plan needs a measured cost table and Stage 1's
    AOP: without either, every action is refused and both case families answer
    ``UNIDENTIFIABLE``, which would have read as a pass on the first family and a failure
    on the second while measuring the wiring in both.
    """
    # The non-identifiability corpus's OWN visibility model, not the one fitted from the
    # incident corpus. Measured this session: the incident-corpus fit has no evidence at
    # all for ``file_staging`` — ``probability('file_staging', 'ebpf')`` is None — so the
    # planner fell back to UNMEASURED_VISIBILITY and the discriminating action's expected
    # value dropped from 0.1994 to 0.0120, under the 0.10 threshold. Every resolvable case
    # then answered UNIDENTIFIABLE, which would have read as this criterion failing on the
    # identifiability engine while it was actually failing on a model fitted to a corpus
    # that never emits the signal the cases turn on. Each corpus family carries its own
    # visibility model, and ``labs/nonidentifiable.py`` ships this one for this purpose.
    model = build_corpus_visibility_model()
    pairs = build_nonidentifiable_pairs(count=criteria.NONIDENT_COUNT, seed=criteria.NONIDENT_SEED)
    unidentifiable = empty_observations = not_alarming = 0
    verdict_ok = 0
    for pair in pairs:
        field = field_for_nonidentifiable_pair(pair)
        verdict, _plan = criteria.identifiability_of(
            field, model=model, observation=AdaptiveObservationPolicy()
        )
        if verdict.state is IdentifiabilityState.UNIDENTIFIABLE:
            unidentifiable += 1
        if not verdict.discriminating_observations:
            empty_observations += 1
        if verdict.to_verdict() is Verdict.UNIDENTIFIABLE and verdict.abstains():
            verdict_ok += 1
        leader = next(
            (w for w in field.worlds if w.world_id == verdict.leading_world_id), None
        )
        others = [w for w in field.worlds if w.world_id != verdict.leading_world_id]
        if leader is not None and others and all(
            leader.latent_state.consequence <= other.latent_state.consequence
            for other in others
        ):
            not_alarming += 1

    resolvable = build_resolvable_after_one_observation(
        count=criteria.NONIDENT_COUNT, seed=criteria.NONIDENT_SEED
    )
    insufficient = resolved_after_one = 0
    for case in resolvable:
        field = field_for_resolvable_case(case)
        before, _ = criteria.identifiability_of(
            field, model=model, observation=AdaptiveObservationPolicy()
        )
        if before.state is IdentifiabilityState.INSUFFICIENT_EVIDENCE:
            insufficient += 1
        after, _ = criteria.identifiability_of(
            apply_granted_observation(field, RESOLVING_SIGNAL, observed=True),
            model=model,
            observation=AdaptiveObservationPolicy(),
        )
        if after.state is IdentifiabilityState.IDENTIFIED:
            resolved_after_one += 1

    n, m = len(pairs), len(resolvable)
    passed = (
        unidentifiable == n
        and empty_observations == n
        and verdict_ok == n
        and not_alarming == n
        and insufficient == m
        and resolved_after_one == m
    )
    return GateCheck(
        "G4.3",
        "Constructed non-identifiable cases are explicitly recognised",
        passed,
        f"build_nonidentifiable_pairs(count={criteria.NONIDENT_COUNT}, "
        f"seed={criteria.NONIDENT_SEED}): {unidentifiable}/{n} returned "
        f"IdentifiabilityState.UNIDENTIFIABLE, {empty_observations}/{n} with "
        f"discriminating_observations == (), {verdict_ok}/{n} mapped to "
        f"Verdict.UNIDENTIFIABLE with abstained=True, and {not_alarming}/{n} did NOT pick the "
        f"more alarming world (the leader's consequence never exceeds the alternative's). "
        f"build_resolvable_after_one_observation: {insufficient}/{m} returned "
        f"INSUFFICIENT_EVIDENCE rather than UNIDENTIFIABLE — not having looked is not the same "
        f"as having looked and found nothing — and {resolved_after_one}/{m} reached IDENTIFIED "
        f"after exactly one granted '{RESOLVING_SIGNAL}' observation. THE NUMBERS THAT DECIDED "
        f"THIS: {unidentifiable}/{n} and {insufficient}/{m}. What would make it come out "
        f"differently: a planner that found a discriminating observation for the "
        f"non-identifiable pairs (it finds 0), or one that found none for the resolvable cases "
        f"(it finds 1, TRACE_FILE_ACCESS_SUBTREE).",
    )


# --- G4.4 --------------------------------------------------------------------


def _tension_and_shadow_under_dropped_telemetry(ctx: Stage4GateContext) -> GateCheck:
    """G4.4 — the paired drop. Clause (c) is falsifier F4, the most dangerous failure here.

    The inequality holds. It also holds **vacuously**, and this check says so rather than
    banking it: confidence is 0.0 on every case in both arms, so "confidence under the drop
    is <= confidence at full telemetry" is 0.0 <= 0.0 sixty times.

    The cause is NOT the frozen support vector — support is not an input to
    ``lucid_steps.confidence_of`` at all. It is two constructions, either sufficient
    (S4-REV-07, which corrected this docstring): the raw confidence is
    ``1 - leader.uncertainty`` and every world the engine holds has uncertainty exactly
    1.0 (``unknown_world`` sets it, ``spawn_world`` keeps it, fusion takes the max); and
    ``visibility_adjusted_confidence`` returns 0.0 whenever any expected signal is an
    unknown hole, which the lifecycle's own expected signals are on every incident.
    Fixing the support update would leave this check exactly as vacuous.
    """
    expected_blind = criteria.dropped_signal_names()
    full = {run.case.incident_id: run for run in ctx.runs}
    confidence_violations: list[str] = []
    verdict_violations: list[str] = []
    shadow_wrong: list[str] = []
    shadow_exact = 0
    informative = 0
    for run in ctx.dropped_runs:
        reference = full.get(run.case.incident_id)
        if reference is None:
            continue
        if run.confidence > reference.confidence + 1e-12:
            confidence_violations.append(
                f"{run.case.incident_id}: {reference.confidence:.6f} -> {run.confidence:.6f}"
            )
        if verdict_committal_rank(run.verdict) > verdict_committal_rank(reference.verdict):
            verdict_violations.append(
                f"{run.case.incident_id}: {reference.verdict.value} -> {run.verdict.value}"
            )
        if reference.confidence > 0.0 or run.confidence > 0.0:
            informative += 1
        shadow = run.field.sensor_shadow
        marked = frozenset(region.signal for region in shadow.regions) if shadow else frozenset()
        observed_in_full = probes.observed_signals(reference.replay)
        made_blind = expected_blind & observed_in_full
        if made_blind and not (made_blind <= marked):
            shadow_wrong.append(f"{run.case.incident_id}: expected {sorted(made_blind)} in {sorted(marked)}")
        elif made_blind:
            shadow_exact += 1

    inequality_holds = not confidence_violations and not verdict_violations
    passed = inequality_holds and not shadow_wrong and informative > 0
    uncertainties = sorted(
        {round(float(world.uncertainty), 6) for run in ctx.runs for world in run.field.worlds}
    )
    return GateCheck(
        "G4.4",
        "Evidence Tension and Sensor Shadow behave correctly under dropped telemetry",
        passed,
        f"paired over {len(ctx.dropped_runs)} cases, full telemetry against "
        f"drop_sensor_path(case, {criteria.DROPPED_SENSOR.value}), whose exclusive signals are "
        f"{sorted(expected_blind)}. (c) falsifier F4 — a dropped sensor must never raise "
        f"confidence or make the verdict more committal: {len(confidence_violations)} confidence "
        f"violations, {len(verdict_violations)} verdict violations"
        + (f" {confidence_violations[:3]}" if confidence_violations else "")
        + f". (a) the shadow marks the signals the drop made unobservable: "
        f"{len(shadow_wrong)} cases where it did not"
        + (f" {shadow_wrong[:2]}" if shadow_wrong else "")
        + f", {shadow_exact} where it did. THE NUMBER THAT DECIDED THIS AND WHY IT IS NOT "
        f"REASSURING: {informative} of {len(ctx.dropped_runs)} cases had a non-zero confidence "
        f"in either arm. The F4 inequality is satisfied as 0.0 <= 0.0 on every case, and the "
        f"reason is structural, not the frozen support vector (support is not an input to "
        f"confidence_of; S4-REV-07 corrected the explanation this check used to give): the raw "
        f"confidence is 1 - leader.uncertainty, and the set of world uncertainties across the "
        f"full-telemetry walk is {uncertainties} — unknown_world sets 1.0, spawn keeps it, "
        f"fusion takes the max; and separately visibility_adjusted_confidence returns 0.0 "
        f"whenever any expected signal is an unknown hole, which the lifecycle's own expected "
        f"signals are on every incident. A check that cannot fail is not a check, and this one "
        f"currently cannot: what would make it fail is a world uncertainty derived from "
        f"evidence AND a hole rule that does not fire on every incident — a moving support "
        f"vector alone would leave it vacuous. Tension under the drop is NOT read by this "
        f"check and is UNMEASURED here (S4-FC-11), and the dropped arm is handed the "
        f"undegraded visibility model. loadavg {ctx.loadavg}.",
    )


# --- G4.5 --------------------------------------------------------------------


def _active_sensing_pays_for_itself(ctx: Stage4GateContext) -> GateCheck:
    """G4.5 — targeted sensing against "turn everything on all the time".

    The control is B3 ``AlwaysOnRichTelemetry``. **Neither side of the byte/CPU ratio
    measures telemetry** (S4-FC-07 / S4-MEAS-05): the CBF figure is the payload size of the
    distinct signal names the replay already contained, fixed before the engine runs and
    identical whether the planner issues 0 requests or 1000, and B3's is a constant
    8-name list per incident plus the CPU of summing it. The ratios are therefore reported
    as labelled proxies and the telemetry clause is UNMEASURED, so this check cannot pass
    until a per-event collection model exists. It used to call them "real within-run
    measurements".
    """
    model = ctx.visibility.model
    outcomes = {outcome.baseline_id: outcome for outcome in ctx.baselines}
    b3 = outcomes.get("B3_AlwaysOnRichTelemetry")
    cbf = outcomes.get("CBF_LUCID")

    # How many actions the planner actually requested across the walk, and why it
    # refused the rest. A planner that issues nothing has not won a comparison.
    requested = refused_low = refused_other = 0
    best_discrimination = 0.0
    best_refused = 0.0
    for run in ctx.runs:
        plan = criteria.plan_for(
            run.field, model=model, observation=AdaptiveObservationPolicy()
        )
        requested += len(plan.requests)
        for _action, reason in plan.refused:
            if "below MIN_DISCRIMINATION_TO_SPEND" in reason:
                refused_low += 1
                best_refused = max(best_refused, _refused_discrimination(reason))
            else:
                refused_other += 1
        for request in plan.requests:
            best_discrimination = max(best_discrimination, request.discrimination)

    bytes_ratio = (
        cbf.telemetry_bytes / b3.telemetry_bytes
        if b3 is not None and cbf is not None and b3.telemetry_bytes
        else None
    )
    cpu_ratio = (
        cbf.cpu_units / b3.cpu_units
        if b3 is not None and cbf is not None and b3.cpu_units
        else None
    )
    quality_within_band = (
        b3 is not None
        and cbf is not None
        and b3.world_set_recall is not None
        and cbf.world_set_recall is not None
        and abs(b3.world_set_recall - cbf.world_set_recall) <= SENSING_QUALITY_BAND
    )
    strictly_cheaper = (
        bytes_ratio is not None and cpu_ratio is not None and bytes_ratio < 1.0 and cpu_ratio < 1.0
    )
    # The two proxies cannot respond to the sensing mechanism, so a pass on them would
    # be meaningless and so would a fail. Until telemetry is modelled per collected
    # event, the criterion is unevaluable and the check does not pass.
    telemetry_measured = False
    passed = requested > 0 and quality_within_band and telemetry_measured and strictly_cheaper
    return GateCheck(
        "G4.5",
        "At least one active sensing method reduces bytes/CPU versus always-on telemetry",
        passed,
        f"UNMEASURED — the telemetry clause cannot be evaluated: neither side of the ratio "
        f"measures telemetry (S4-FC-07). Labelled PROXIES only, same run: CBF/LUCID "
        f"'telemetry_bytes' is the payload of the distinct signal names each replay already "
        f"contained, fixed before the engine runs and identical at 0 or 1000 requests; B3's is "
        f"a constant 8-name list per incident, which leaves out 8 signal families the passive "
        f"stream carries. Proxy byte ratio "
        f"{bytes_ratio if bytes_ratio is None else round(bytes_ratio, 4)} "
        f"({cbf.telemetry_bytes if cbf else None} / {b3.telemetry_bytes if b3 else None}); "
        f"proxy cpu ratio {cpu_ratio if cpu_ratio is None else round(cpu_ratio, 4)} (B3's CPU is "
        f"the cost of summing constants; no collection CPU is modelled on either side). "
        f"Quality within {SENSING_QUALITY_BAND}: {quality_within_band} (B3 world-set recall "
        f"{b3.world_set_recall if b3 else None}, CBF {cbf.world_set_recall if cbf else None}). "
        f"THE NUMBER THAT DECIDED THIS: the planner issued {requested} ObservationRequests "
        f"across {len(ctx.runs)} incidents. It refused {refused_low} actions for expected "
        f"discrimination below MIN_DISCRIMINATION_TO_SPEND (the highest refused was "
        f"{best_refused:.4f}) and {refused_other} for any other reason; the best discrimination "
        f"any issued request carried was {best_discrimination:.4f}. The threshold was NOT "
        f"lowered to make this pass. What would make this check evaluable: bytes counted per "
        f"collected event plus the bytes of GRANTED requests over the rest of the incident, "
        f"and B3 modelled as every sensor on for every transition. loadavg {ctx.loadavg}.",
    )


def _refused_discrimination(reason: str) -> float:
    """The expected discrimination a below-threshold refusal quotes, or 0.0."""
    head = reason.removeprefix("expected discrimination ").split(" ", 1)[0]
    try:
        return float(head)
    except ValueError:
        return 0.0


# --- G4.6 --------------------------------------------------------------------


def _stress_finds_the_predefined_spurious_world(ctx: Stage4GateContext) -> GateCheck:
    """G4.6 — counterfactual stress against a decoy the corpus planted on purpose."""
    by_id = {replay.case.incident_id: replay for replay in ctx.replays}
    cases = decoy_cases(ctx.cases)
    constructed = detected = true_survived = remove_discriminates = rename_identical = 0
    ran_all_eight = 0
    flagged_the_true_world: list[str] = []
    for case in cases:
        built = probes.decoy_field(case, by_id[case.incident_id])
        if built is None:
            continue
        field, true_id, spurious_id = built
        constructed += 1
        material = probes.stress_material(case, by_id[case.incident_id])
        hook = lambda _kind, _material=material: _material  # noqa: E731 - one expression
        spurious_rows = stress_world_adversarially(field, spurious_id, corpus_hook=hook)
        true_rows = stress_world_adversarially(field, true_id, corpus_hook=hook)
        if stresses_actually_run(spurious_rows) == len(PerturbationKind):
            ran_all_eight += 1
        if any(row.spurious_detected for row in spurious_rows):
            detected += 1
        if any(row.spurious_detected for row in true_rows):
            flagged_the_true_world.append(case.incident_id)
        else:
            true_survived += 1
        removal_s = next(
            row for row in spurious_rows if row.kind is PerturbationKind.REMOVE_CRITICAL_EVENT
        )
        removal_t = next(
            row for row in true_rows if row.kind is PerturbationKind.REMOVE_CRITICAL_EVENT
        )
        if not removal_s.conclusion_survived and removal_t.conclusion_survived:
            remove_discriminates += 1
        rename = next(
            row for row in spurious_rows if row.kind is PerturbationKind.RENAME_SEMANTIC_PRESERVING
        )
        if "bit_identical=True" in rename.detail:
            rename_identical += 1

    passed = (
        constructed == len(cases)
        and detected == constructed
        and true_survived == constructed
        and remove_discriminates == constructed
        and rename_identical == constructed
        and constructed > 0
    )
    return GateCheck(
        "G4.6",
        "Counterfactual stress identifies predefined spurious causal explanations",
        passed,
        f"{constructed} of {len(cases)} predefined-decoy cases could be constructed as a "
        f"true/spurious world pair; the case that could not has ground truth "
        f"'unresolved_novel_mechanism', which raises no signal-bearing dimension, so there is "
        f"no true world to contrast a decoy against. All eight §25 perturbations ran on "
        f"{ran_all_eight}/{constructed} (a partially filled StressMaterial reports NO_MATERIAL "
        f"and would have let the suite quote eight passes it never ran). THE NUMBERS THAT "
        f"DECIDED THIS: spurious_detected on the SPURIOUS world {detected}/{constructed}, and "
        f"the stress flagged the TRUE world instead on {len(flagged_the_true_world)} cases "
        f"{flagged_the_true_world[:3]}. REMOVE_CRITICAL_EVENT collapses the spurious world and "
        f"not the true one on {remove_discriminates}/{constructed}: every support shift it "
        f"measured was exactly +0.0000, for both worlds, because removing an event cannot move "
        f"a support vector that the LUCID loop never updates. RENAME_SEMANTIC_PRESERVING leaves "
        f"field.support_vector() bit-identical on {rename_identical}/{constructed} — that "
        f"clause passes, and it is the one clause here that does not depend on support moving.",
    )


# --- G4.7 --------------------------------------------------------------------


def _claim_kinds_separated_by_construction(ctx: Stage4GateContext) -> GateCheck:
    """G4.7 — OBS/DER/INF/CF/EXT/UNK separation, structural and then behavioural."""
    import typing

    members = typing.get_args(TypedClaim)
    six_members = len(members) == len(ClaimKind) == 6  # noqa: PLR2004
    kinds_covered = {kind_of(cls) for cls in members} == set(ClaimKind)  # type: ignore[arg-type]
    inf_cf_authoritative = {ClaimKind.INF, ClaimKind.CF} & AUTHORITATIVE_KINDS
    unbound = unbound_terms()

    defects = [
        f"{name}: {why}"
        for name, probe in probes.laundering_probes()
        if (why := probes.refused(probe)) is not None
    ]

    present: set[ClaimKind] = set()
    for run in ctx.runs:
        present |= set(run.resolution.claim_graph.kinds_present())
    required = {ClaimKind.OBS, ClaimKind.DER, ClaimKind.INF, ClaimKind.UNK}
    exercised = required <= present

    passed = (
        six_members
        and kinds_covered
        and not inf_cf_authoritative
        and not unbound
        and not defects
        and exercised
    )
    return GateCheck(
        "G4.7",
        "Typed Claim Graph enforces OBS/DER/INF/CF/EXT/UNK separation",
        passed,
        f"structural: the TypedClaim union has {len(members)} members against "
        f"{len(ClaimKind)} ClaimKind values and kind_of covers every one: "
        f"{six_members and kinds_covered}; AUTHORITATIVE_KINDS is "
        f"{sorted(k.value for k in AUTHORITATIVE_KINDS)}, so an INF or CF claim can never be "
        f"emitted as authoritative: {not inf_cf_authoritative}; theory.unbound_terms() is "
        f"{unbound or '()'}. All seven spec §D4.13 laundering attempts (a)-(g) were refused: "
        f"{not defects}"
        + (f" — accepted: {defects}" if defects else "")
        + f". behavioural, over {len(ctx.runs)} real incidents: kinds actually present "
        f"{sorted(k.value for k in present)}; OBS, DER, INF and UNK all exercised: "
        f"{exercised} — a separation that never exercises a kind proves nothing"
        + (
            ""
            if ClaimKind.DER in present
            else ". DER IS NOT EXERCISED ON REAL OUTPUT, and that is the honest state since "
            "S4-FC-02: the only DER the compiler ever emitted was 'N observation(s) form the "
            "causal spine of <world>' — world attribution, which is the hypothesis, under an "
            "authoritative DER type — and it was removed. The requirement was NOT relaxed to "
            "keep this green; it fails until the engine has a derivation that is a "
            "deterministic function of its premises (compiler.DERIVATION_RULE_CATALOGUE is "
            "empty)"
        )
        + f". Separation is "
        f"by construction (six distinct frozen dataclasses), not by a string field, so this is "
        f"one of the four criteria §6.1 says this wave can actually settle.",
    )


# --- G4.8 --------------------------------------------------------------------


def _no_unsupported_authoritative_claims(ctx: Stage4GateContext) -> GateCheck:
    """G4.8 — walk every exported resolution's claim graph. Target and threshold are zero."""
    unsupported = 0
    amplifications: list[str] = []
    bad_digests: list[str] = []
    wrong_kind: list[str] = []
    authoritative_total = 0
    exports = 0
    unanchored: list[str] = []
    uncatalogued: list[str] = []
    for run in ctx.runs:
        graph = run.resolution.claim_graph
        unsupported += len(graph.unsupported_authoritative())
        authoritative_total += len(graph.authoritative)
        audit = probes.claim_support_audit(graph, probes.telemetry_digests(run.replay))
        unanchored.extend(f"{run.case.incident_id}:{cid}" for cid in audit["unanchored"])
        uncatalogued.extend(f"{run.case.incident_id}:{cid}" for cid in audit["uncatalogued"])
        amplifications.extend(amplification_violations(tuple(graph.claims.values())))
        for claim_id in graph.authoritative:
            claim = graph.claims.get(claim_id)
            if claim is None:
                bad_digests.append(f"{run.case.incident_id}:{claim_id} absent from the graph")
                continue
            if kind_of(claim) not in AUTHORITATIVE_KINDS:
                wrong_kind.append(f"{run.case.incident_id}:{claim_id} is {kind_of(claim).value}")
            # Walked per authoritative claim, not once for the graph: the criterion is
            # about each authoritative claim's own premise chain terminating in
            # digest-valid ObservedClaims, and the walk re-checks the digest pattern
            # rather than trusting ObservedClaim.__post_init__.
            elif not graph.traces_to_observation(claim_id):
                bad_digests.append(
                    f"{run.case.incident_id}:{claim_id} does not trace to a digest-valid OBS"
                )
        exports += 1

    vacuous = authoritative_total == 0
    passed = (
        unsupported == 0
        and not amplifications
        and not bad_digests
        and not wrong_kind
        and not unanchored
        and not uncatalogued
        and not vacuous
    )
    return GateCheck(
        "G4.8",
        "Authoritative output contains zero unsupported factual claims",
        passed,
        f"over {exports} exported CBFResolutionV1 records covering {authoritative_total} "
        f"authoritative claims: unsupported_authoritative() returned {unsupported} claims "
        f"(target and threshold are both zero); amplification_violations() returned "
        f"{len(amplifications)}"
        + (f" {amplifications[:3]}" if amplifications else "")
        + f"; every authoritative premise chain terminates in ObservedClaims whose digests "
        f"match ^sha256:[0-9a-f]{{64}}$ and are re-checked by the walk rather than trusted "
        f"from the constructor: {not bad_digests}"
        + (f" — defects {bad_digests[:3]}" if bad_digests else "")
        + f"; no claim of kind INF/CF/EXT/UNK appears in authoritative: {not wrong_kind}"
        + (f" {wrong_kind[:3]}" if wrong_kind else "")
        + f"; NOT ONLY STRUCTURAL since S4-FC-02 — every authoritative OBS digest is checked "
        f"against the digests the incident's own Stage 1 telemetry carried, so a well-formed "
        f"digest no telemetry produced fails: {len(unanchored)} unanchored"
        + (f" {unanchored[:3]}" if unanchored else "")
        + f"; every authoritative DER must use a rule in the closed "
        f"DERIVATION_RULE_CATALOGUE (empty — the compiler emits no DER): {len(uncatalogued)} "
        f"outside it" + (f" {uncatalogued[:3]}" if uncatalogued else "")
        + f". THE NUMBER THAT DECIDED THIS: {unsupported}. The vacuity guard matters as much "
        f"as the count — {authoritative_total} authoritative claims were emitted, so the zero "
        f"is a zero over real claims and not the zero of an empty output. A criterion that "
        f"passes by producing nothing is not a criterion, and if the engine stopped compiling "
        f"claims this check would fail on {vacuous=}.",
    )


# --- G4.9 --------------------------------------------------------------------


def _bounds_hold_under_flood(ctx: Stage4GateContext) -> GateCheck:
    """G4.9 — see ``gate_bounds.bounds_check``, which holds the three arms."""
    return bounds.bounds_check(ctx)


# --- G4.10 -------------------------------------------------------------------


def _pareto_frontier_against_simpler_baselines(ctx: Stage4GateContext) -> GateCheck:
    """G4.10 — the saturation guard runs first, and DEGENERATE means no comparison is recorded.

    Expected to fail for two reasons already paid for in this repository (spec §6.1):
    synthetic corpora here produce only trivial or impossible tasks, and the wave that
    authored ``GroundTruthWorld`` also authored the mechanism vocabulary.
    """
    corpus_ok, corpus_why = saturation_check(ctx.cases)
    outcomes = ctx.baselines
    degenerate, guard_why = saturation_guard(outcomes)

    base_rate_refusals = [
        outcome.baseline_id
        for outcome in outcomes
        if outcome.detection_accuracy is None or outcome.detection_accuracy <= 1 / 3
    ]
    frontier, dominated = pareto_frontier(outcomes)
    on_frontier = "CBF_LUCID" in frontier

    rows = run_ablation(ctx.cases, seed=criteria.CORPUS_SEED)
    justified = tuple(row.flag for row in rows if row.verdict == "JUSTIFIED")
    verdict_tally: dict[str, int] = {}
    for row in rows:
        verdict_tally[row.verdict] = verdict_tally.get(row.verdict, 0) + 1
    blocked = blocked_experiments()
    optional_with_delta = tuple(
        core_id
        for core_id in OPTIONAL_IDS
        if ABLATION_FLAGS.get(core_id) in justified
    )

    passed = (
        corpus_ok
        and not degenerate
        and not base_rate_refusals
        and on_frontier
        and len(optional_with_delta) == len(OPTIONAL_IDS)
    )
    return GateCheck(
        "G4.10",
        "CBF/LUCID beats or complements simpler baselines on the measured Pareto frontier",
        passed,
        f"saturation_check FIRST, on the corpus: degenerate={not corpus_ok} — {corpus_why}. "
        f"saturation_guard on the {len(outcomes)} baseline outcomes: degenerate={degenerate} — "
        f"{guard_why}. A DEGENERATE split means NO COMPARISON IS RECORDED, so the frontier "
        f"below is reported as a measurement of the split rather than of the mechanism. "
        f"{len(base_rate_refusals)} of {len(outcomes)} baselines are at or below the corpus "
        f"base rate 0.3333 and their comparison is REFUSED, not reported: "
        f"{base_rate_refusals}. Pareto frontier {list(frontier)}; dominated "
        f"{list(dominated)}; CBF_LUCID on the frontier: {on_frontier}. Flag ablation over "
        f"{len(rows)} rows: {len(justified)} of {len(ABLATION_FLAGS)} LucidConfig flags came "
        f"out JUSTIFIED {list(justified) or '[]'} (verdict tally {verdict_tally}), so "
        f"{len(optional_with_delta)} of {len(OPTIONAL_IDS)} OPTIONAL CBF-F ids carry a "
        f"measured delta. NOT_YET_JUSTIFIED is not REJECTED: on a corpus with no headroom, "
        f"'no measured benefit' cannot demonstrate absence of benefit (ADR-0009's lesson). "
        f"{len(EXPERIMENTS)} experiments are registered, {len(blocked)} of them blocked "
        f"(a DBN and a tiny GNN cannot be built under ADR-0030, and provenance scoring and "
        f"an LLM summarizer are not present in this repository). THE RESULT, PLAINLY: the "
        f"comparison could not be drawn on this corpus family, and where the frontier does "
        f"resolve, CBF_LUCID is dominated. ADR-0036 records it. This is the outcome §1.1 "
        f"planned for, not a fallback. loadavg {ctx.loadavg}.",
    )


# --- G4.11 -------------------------------------------------------------------


def _stage4_remains_optional_when_it_crashes(ctx: Stage4GateContext) -> GateCheck:
    """G4.11 — see ``gate_optionality.optionality_check``: the engine arm and the hook arm."""
    return optionality.optionality_check(ctx)


# --- G4.12 -------------------------------------------------------------------


def _novelty_claims_stay_provisional(ctx: Stage4GateContext) -> GateCheck:
    """G4.12 — no novelty claim ahead of a reviewed prior-art entry, and no ledger mutation."""
    ledger = PriorArtLedger.load()
    primary = ledger.entries.get(STAGE4_HYPOTHESIS)
    secondary = ledger.entries.get(STAGE4_SECONDARY)
    if primary is None or secondary is None:
        absent = [
            name
            for name, entry in ((STAGE4_HYPOTHESIS, primary), (STAGE4_SECONDARY, secondary))
            if entry is None
        ]
        return GateCheck(
            "G4.12",
            "All novelty claims remain provisional until formal prior-art/patent review",
            False,
            f"the prior-art ledger holds no entry for {absent}, which Stage 4's experiment "
            f"ids name ({EXPERIMENT_ID}); a novelty claim cannot be held provisional against "
            "an entry that does not exist",
        )

    text = _FINDINGS.read_text(encoding="utf-8") if _FINDINGS.is_file() else ""
    missing_headings = [head for head in criteria.LEDGER_HEADINGS if head not in text]
    claims = sorted(
        word for word in criteria.NOVELTY_WORDS if criteria.claims_novelty(text, word)
    )
    reviewed = (
        primary.literature_status.value != "NOT_REVIEWED"
        and secondary.literature_status.value != "NOT_REVIEWED"
    )

    digest_after = criteria.registry_digest()
    ledger_untouched = digest_after == ctx.registry_digest_before

    passed = (
        _FINDINGS.is_file()
        and not missing_headings
        and (reviewed or not claims)
        and ledger_untouched
    )
    return GateCheck(
        "G4.12",
        "All novelty claims remain provisional until formal prior-art/patent review",
        passed,
        f"hypothesis binding {STAGE4_HYPOTHESIS} ({primary.literature_status.value}) and "
        f"secondary {STAGE4_SECONDARY} ({secondary.literature_status.value}); no H10 was "
        f"minted, because pocketsec/stage0/hypotheses.py holds H0-H8 and "
        f"tests/test_harness_and_gate.py asserts the prior-art ledger covers exactly that set "
        f"(spec §2.9). {_FINDINGS.relative_to(REPO_ROOT)} exists: {_FINDINGS.is_file()} and "
        f"carries all five honesty-ledger headings: {not missing_headings}"
        + (f" (missing {missing_headings})" if missing_headings else "")
        + f"; novelty-claiming phrases found in it: {claims or 'NONE'}; both ledger entries "
        f"are REVIEWED: {reviewed}. experiments/registry.jsonl is byte-identical before and "
        f"after this gate run: {ledger_untouched} "
        f"({ctx.registry_digest_before} -> {digest_after}) — Stage 3's gate appended a "
        f"PS-S3-* row every time the suite ran (spec §2.7), so this gate reads the ledger and "
        f"registration lives in `pocketsec-stage4 register`, which an operator invokes "
        f"deliberately. THE NUMBER THAT DECIDED THIS: "
        + (
            f"{len(claims)} unbacked novelty claims against NOT_REVIEWED entries."
            if claims and not reviewed
            else f"{len(missing_headings)} missing headings and ledger_untouched={ledger_untouched}."
        ),
    )
