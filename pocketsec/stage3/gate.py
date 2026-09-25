"""The Stage 3 acceptance gate (``docs/stage-3-spec.md`` §6), as an executable check.

Thirteen criteria, each evaluated by running the real subsystems rather than
inspecting a document. Like Stage 0's, Stage 1's and Stage 2's gates, this is
code: ``pocketsec-stage3 gate`` exits non-zero if any criterion fails.

Three things about this gate are worth stating before anyone reads a result off
it.

**It is expected to fail, and several of its failures are the stage's findings.**
Stage 3 wraps a zero-parameter rule that already costs ~0.1 µs/event, so G3.9
asks whether the cell format earns its keep against that rule and reports the
measured answer whichever way it falls. G3.4 asks whether guided Boundary
Pressure beats random replay at the same budget cap, and the architecture gate
itself says "or it is removed". G3.11 runs a saturation guard first and refuses to record an
ablation on a split that cannot tell models apart. A criterion restated until it
passes would be the worst outcome available here (ADR-0113).

**No check reads a document to decide a mechanism question.** The two that do
read files — G3.12(b) and G3.13 — are *about* documents: one greps the stage's
own prose for unearned verification language, the other checks the prior-art
ledger. Everything else runs the subsystem.

**Nothing measured here is a detection result.** Every corpus in this repository
is synthetic (ADR-0010). Timings are contended and are reported as within-run
ratios with ``/proc/loadavg`` beside them; an absolute microsecond figure from
this host is not a device measurement.
"""

from __future__ import annotations

import collections
import json
from dataclasses import dataclass, replace
from typing import Any

from pocketsec.stage0.contracts.common import EvidenceRef
from pocketsec.stage0.contracts.threat_prediction_v1 import ComputePath
from pocketsec.stage0.gate import REPO_ROOT, GateCheck, GateReport
from pocketsec.stage0.prior_art import PriorArtLedger
from pocketsec.stage1.ssir.relations import RelationFamily
from pocketsec.stage3.boundary.index import MAX_KEYS_PER_CELL, BoundaryIndex
from pocketsec.stage3.boundary.pressure import compare_strategies
from pocketsec.stage3.bytecode.verifier import (
    ALL_PROVEN_PROPERTIES,
    TESTED_ONLY_PROPERTIES,
    verify,
)
from pocketsec.stage3.bytecode.vm import CellVM
from pocketsec.stage3.cells.field import MAX_CELLS, MAX_FIELD_BYTES, KnowledgeField
from pocketsec.stage3.cells.frame import CellFrame, frame_digest
from pocketsec.stage3.cells.schema import KNOWLEDGE_CELL_V1_ID, KnowledgeCellV1
from pocketsec.stage3.crystal.pipeline import CrystalConfig, crystallize
from pocketsec.stage3.gate_probes import (
    drift_probe,
    guard_outcome,
    lifecycle_region,
    ratio_band,
    region_sample,
    regions_of,
    return_risk_evidence_probe,
)
from pocketsec.stage3.gate_criteria import (
    NOVELTY_WORDS,
    VERIFICATION_WORDS,
    actor_predicate,
    audit_state_bytes,
    cell_vm_bytes,
    claims_novelty,
    lifecycle_stop_reason,
    property_set_defects,
    refusal_probes,
    stub_sequence,
    unbounded_verification_language,
    zero_stress,
)
from pocketsec.stage3.labs.ablation import run_ablation
from pocketsec.stage3.labs.baselines import (
    AT_CHANCE_PR_AUC_BAND,
    BaselineTable,
    run_baselines,
)
from pocketsec.stage3.labs.cell_path import phi_oracle_cell
from pocketsec.stage3.labs.crystal_corpus import (
    CrystalCorpus,
    build_crystal_corpus,
    session_frames,
)
from pocketsec.stage3.labs.teacher_error import teacher_error_cases
from pocketsec.stage3.melting.full import full_melt, recrystallize
from pocketsec.stage3.melting.partial import partial_melt
from pocketsec.stage3.oracles.counterexamples import CounterexampleStore
from pocketsec.stage3.oracles.dual_oracle import DualOracleEvaluator
from pocketsec.stage3.oracles.teacher import (
    TeacherOracle,
    TeacherSnapshotV1,
    phi_oracle_score,
)
from pocketsec.stage3.promotion.assurance import (
    AssuranceState,
    PromotionOutcome,
    promote_cell,
)
from pocketsec.stage3.promotion.audit import AuditSampler, audit_probability, sample_audit
from pocketsec.stage3.promotion.shadow import shadow_execute
from pocketsec.stage3.resources import (
    STAGE3_BUDGET,
    STAGE3_NORMAL_INCREMENTAL_RSS_BYTES,
    loadavg,
    measure_stage3_resources,
)
from pocketsec.stage3.slot import CrystalSlot

__all__ = ["Stage3GateContext", "crystallize_region", "run_gate"]

#: Corpus size. Sixty is ``labs/crystal_corpus.DEFAULT_CORPUS_COUNT`` and the
#: size Stage 2's own drift fixtures use, so a property that fails here would
#: have failed there rather than being an artefact of a size this gate picked.
CORPUS_COUNT = 60

#: Two disjoint labelled draws from the same named split. The seeds are Stage
#: 1's guillotine seeds (``stage1/gate.py``: fit 3, score 11), reused rather
#: than chosen, so that no seed in this gate was selected for the result it
#: produces. Stage 0 fair-comparison rule 6: scoring never touches the split a
#: model was fitted on.
FIT_SEED = 3
EVAL_SEED = 11

#: Stage 3 has no hypothesis of its own. ``pocketsec.stage0.hypotheses`` holds
#: H0–H8 and ``tests/test_harness_and_gate.py`` asserts the prior-art ledger
#: covers exactly that set, so minting H9 would mean editing Stage 0 under
#: another wave. Spec §10 names the alternative and this gate takes it: H4,
#: "Neural-to-symbolic JIT compilation", is the honest existing binding.
STAGE3_HYPOTHESIS = "H4"

EXPERIMENT_ID = "PS-S3-20260925-H4-crystal-gate-0001"

_FINDINGS = REPO_ROOT / "docs" / "stage-3-findings.md"
_FRONTIER = REPO_ROOT / "results" / "stage2-frontier.json"
_STAGE3_ROOT = REPO_ROOT / "pocketsec" / "stage3"



#: The five headings the honesty ledger must carry (spec §11).
_LEDGER_HEADINGS = (
    "MEASURED",
    "UNMEASURED",
    "REJECTED",
    "RETRACTED",
    "NOT A DETECTION RESULT",
)


@dataclass
class Stage3GateContext:
    """One shared corpus walk and one baseline run, so thirteen checks share them.

    Built once because the baseline table *is* the within-run comparison: G3.2,
    G3.9 and G3.11 all read it, and re-running it per check would compare figures
    from three different moments of a contended host against each other.
    """

    fit: CrystalCorpus
    evaluation: CrystalCorpus
    baselines: BaselineTable
    frames: tuple[CellFrame, ...]
    teacher: TeacherOracle
    vm: CellVM
    oracle: DualOracleEvaluator
    loadavg: tuple[float, float, float]

    @classmethod
    def build(cls) -> Stage3GateContext:
        fit = build_crystal_corpus(count=CORPUS_COUNT, seed=FIT_SEED)
        evaluation = build_crystal_corpus(count=CORPUS_COUNT, seed=EVAL_SEED)
        frames = tuple(
            frame for session in evaluation.sessions for frame in session_frames(session)
        )
        snapshot = TeacherSnapshotV1.create(
            teacher_id="phi-oracle-frozen",
            source="phi-oracle",
            encoder_version=evaluation.encoder_version,
            corpus_version=evaluation.version,
            seed=EVAL_SEED,
            responses={
                frame_digest(frame): phi_oracle_score(frame.delta_phi) for frame in frames
            },
            measured_by="pocketsec.stage3.gate:build_context",
            experiment_id=EXPERIMENT_ID,
        )
        # The snapshot goes to ``run_baselines`` as well as to the oracle. B4 is
        # the mandated "frozen-teacher cache with an LRU" control, and with
        # ``snapshot=None`` its ``TeacherOracle`` answers UNKNOWN on every miss:
        # the row then measured a cache in front of a fresh Φ-oracle evaluation,
        # exercising neither the frozen teacher nor its bytes.
        baselines = run_baselines(fit=fit, evaluation=evaluation, snapshot=snapshot)
        teacher = TeacherOracle(snapshot)
        vm = CellVM()
        return cls(
            fit=fit,
            evaluation=evaluation,
            baselines=baselines,
            frames=frames,
            teacher=teacher,
            vm=vm,
            oracle=DualOracleEvaluator(teacher=teacher, vm=vm),
            loadavg=loadavg(),
        )

    def claimed_frames(self, cell: KnowledgeCellV1, *, limit: int = 256) -> tuple[CellFrame, ...]:
        """Corpus frames this cell's own boundary contains.

        The default is well above ``SHADOW_MIN_COVERAGE``'s largest frame floor,
        so a shadow run that fails coverage fails on the corpus rather than on a
        cap this gate chose. Bounded all the same: endpoint state is bounded.
        """
        return tuple(f for f in self.frames if cell.boundary.contains(f))[:limit]

    def regions(self) -> list[tuple[tuple[int, int, int], list[CellFrame]]]:
        """Corpus frames grouped by boundary key, largest region first."""
        return regions_of(self.frames)


def run_gate() -> GateReport:
    """Evaluate all thirteen Stage 3 acceptance criteria."""
    ctx = Stage3GateContext.build()
    return GateReport(
        checks=(
            _stage2_baseline_frozen(ctx),
            _four_alternative_baselines(ctx),
            _cells_are_versioned_and_bounded(ctx),
            _boundary_pressure_beats_random_replay(ctx),
            _dual_oracle_stops_teacher_error(ctx),
            _lifecycle_end_to_end(ctx),
            _melting_is_localised(ctx),
            _evidence_and_causal_attribution_survive(ctx),
            _cost_against_the_phi_oracle(ctx),
            _incremental_memory_within_budget(ctx),
            _no_component_lacks_ablation_support(ctx),
            _verification_claims_are_bounded(ctx),
            _prior_art_reviewed_before_novelty(ctx),
        )
    )


def _stage2_baseline_frozen(ctx: Stage3GateContext) -> GateCheck:
    """G3.1 — the Stage 2 baseline is frozen and matches the split Stage 3 ran."""
    if not _FRONTIER.exists():
        return GateCheck(
            "G3.1",
            "Stage 2 baseline frozen and reproducibly benchmarked",
            False,
            f"UNMEASURED: {_FRONTIER.relative_to(REPO_ROOT)} does not exist; Stage 3 has no "
            "frozen Stage 2 evidence to compare against",
        )
    frontier = json.loads(_FRONTIER.read_text(encoding="utf-8"))
    recorded = (frontier.get("corpus"), frontier.get("count"), frontier.get("seed"))
    ours = ("drift", ctx.evaluation.count, ctx.evaluation.seed)
    matched = recorded == ours
    snapshot_pinned = ctx.teacher.available and ctx.teacher.snapshot is not None
    detail = (
        f"frozen evidence is ({recorded[0]!r}, count={recorded[1]}, seed={recorded[2]}) "
        f"from {frontier.get('measured_by')}; the split this gate ran is "
        f"({ours[0]!r}, count={ours[1]}, seed={ours[2]}). "
    )
    if not matched:
        detail += (
            "REFUSED as UNMEASURED: the frozen Stage 2 frontier was benchmarked on the "
            "'ambiguous' corpus, and Stage 3's corpus is the Stage 2 drift corpus replayed "
            "with DRIFT_EPOCH_SIGNALS (ADR-0028). Comparing Stage 3 against a frontier "
            "measured on a different split would be a cross-corpus claim wearing a "
            "within-run label. Re-running `python -m pocketsec.stage2.research.cli frontier` "
            "on the drift corpus needs numpy, which ADR-0020 keeps out of Stage 3."
        )
    else:
        detail += (
            f"teacher snapshot pinned at seed {ctx.evaluation.seed}, digest "
            f"{ctx.teacher.snapshot.digest if ctx.teacher.snapshot else None}"
        )
    return GateCheck(
        "G3.1",
        "Stage 2 baseline frozen and reproducibly benchmarked",
        matched and snapshot_pinned,
        detail,
    )


def _four_alternative_baselines(ctx: Stage3GateContext) -> GateCheck:
    """G3.2 — at least four alternative compilation/distillation baselines run."""
    table = ctx.baselines
    controls = [row for row in table.rows if row.baseline_id.startswith("B")]
    below = [row.baseline_id for row in controls if row.beats_base_rate is False]
    at_chance = [row.baseline_id for row in controls if row.beats_base_rate is None]
    passed = not table.refused and len(controls) >= 4 and not below and not at_chance
    rows = "; ".join(
        f"{row.baseline_id} PR-AUC "
        f"{'n/a' if row.pr_auc is None else format(row.pr_auc, '.4f')} at "
        f"{'n/a' if row.microseconds_per_event is None else format(row.microseconds_per_event, '.1f')}"
        f" µs/event, {row.bytes_resident} B"
        for row in table.rows
    )
    detail = (
        f"{len(controls)} controls on one split in one run (count={table.count}, fit seed "
        f"{ctx.fit.seed}, eval seed {ctx.evaluation.seed}, base rate {table.base_rate:.4f}, "
        f"loadavg {table.loadavg[0]:.2f}): {rows}. "
    )
    if table.refused:
        detail += f"COMPARISON REFUSED: {table.refusal_reason}"
    elif below:
        detail += f"measurably below chance and therefore a bug: {below}"
    elif at_chance:
        detail += (
            f"AT CHANCE: {at_chance} land within {AT_CHANCE_PR_AUC_BAND} of the base rate, "
            "so they are not working controls and the comparison cannot show that any "
            "component helps. B4's margin is +0.0086 on this split, inside the same band "
            "labs/ablation.SATURATION_PR_AUC_BAND uses to call a split unable to tell "
            "models apart, and sweeping the corpus size on this builder puts it on either "
            "side of zero — the sign of a difference that small is not a result. The cause "
            "is B4's deliberately coarse (relation_family, epoch_id, state_delta_mask) key, "
            "which serves 2017 hits from 23 entries; it is a measured property of that "
            "control, not a bug in it. B4 now runs with the gate's frozen teacher snapshot "
            "supplied and serves hits through lookup_transition_cache, so the row is a "
            "frozen-teacher LRU rather than, as before, a FIFO in front of a fresh "
            "Φ-oracle evaluation."
        )
    else:
        detail += (
            "every control beats the base rate by more than "
            f"{AT_CHANCE_PR_AUC_BAND}, so the comparison is reportable. "
            "Absolute µs figures are contended-host numbers, not device measurements; "
            "only the within-run ratios in G3.9 transfer."
        )
    return GateCheck("G3.2", "At least four alternative baselines implemented", passed, detail)


def _cells_are_versioned_and_bounded(ctx: Stage3GateContext) -> GateCheck:
    """G3.3 — versioned schema, bounded operator form, explicit validity boundary."""
    from pocketsec.stage0.contracts.common import SCHEMA_REGISTRY

    cell = phi_oracle_cell()
    report = verify(cell.operator)
    registered = KNOWLEDGE_CELL_V1_ID in SCHEMA_REGISTRY
    bounded = cell.operator.max_steps <= MAX_KEYS_PER_CELL * 2 and report.ok
    refusals = refusal_probes(cell)
    unrefused = [name for name, raised in refusals if not raised]
    passed = (
        registered
        and report.ok
        and not cell.boundary.is_empty
        and bounded
        and not unrefused
    )
    return GateCheck(
        "G3.3",
        "Cells carry versioned schema, bounded operator, explicit boundary",
        passed,
        f"schema {KNOWLEDGE_CELL_V1_ID} registered={registered}; operator form "
        f"{cell.operator.form.value} verifies ok={report.ok} with {report.instruction_count} "
        f"instructions, stack depth {report.max_stack_depth}, {cell.operator.size_bytes()} B; "
        f"boundary non-empty over {sorted(cell.boundary.state_dimensions)} in epochs "
        f"{sorted(cell.boundary.epochs)} claiming {len(cell.boundary.keys())} keys; "
        f"{len(refusals)} malformed-cell probes all refused"
        + (f"; NOT refused: {unrefused}" if unrefused else "")
    )


def _boundary_pressure_beats_random_replay(ctx: Stage3GateContext) -> GateCheck:
    """G3.4 — guided search finds a class random replay misses, or it is removed."""
    cell = phi_oracle_cell()
    seeds = ctx.claimed_frames(cell, limit=8)
    if not seeds:
        return GateCheck(
            "G3.4",
            "Boundary Pressure beats naive random replay",
            False,
            "UNMEASURED: no corpus frame falls inside the cell's boundary, so the pressure "
            "walk had no seed inside the validated region and was not run",
        )
    guided, random_control, guided_only = compare_strategies(
        cell, oracle=ctx.oracle, budget=256, seed=EVAL_SEED, seeds=seeds
    )
    passed = bool(guided_only)
    return GateCheck(
        "G3.4",
        "Boundary Pressure beats naive random replay",
        passed,
        f"same budget CAP (256), same seed family ({EVAL_SEED}), same run: guided SPENT "
        f"{guided.probes_run} probes finding {len(guided.counterexample_classes)} "
        f"counterexample classes; random replay SPENT {random_control.probes_run} probes "
        f"finding {len(random_control.counterexample_classes)}. The cap is shared, the "
        "spend is not — guided stops when it runs out of axes and depths, not when it runs "
        f"out of budget (budget_exhausted={guided.budget_exhausted}), so this is not an "
        "equal-spend comparison and is not described as one. Classes found by guided and "
        f"missed by random replay: {sorted(guided_only) or 'NONE'}; missed by guided and "
        f"found by random replay: "
        f"{sorted(random_control.counterexample_classes - guided.counterexample_classes) or 'NONE'}. "
        f"Probes on which the oracle had no opinion at all (frozen-snapshot key misses, "
        f"excluded from the §37 boundary-quality counts): guided {guided.unmeasured_probes}, "
        f"random {random_control.unmeasured_probes}."
        + (
            ""
            if passed
            else " FALSIFIER F3 FIRES: guided search found no counterexample class random "
            "replay missed. The architecture gate says 'or it is removed', so ADR-0026 "
            "removes D3.4's guided search as the default and CrystalConfig.strategy now "
            "defaults to RANDOM_REPLAY. WITHDRAWN: an earlier version of this line said "
            "random replay found a 'strict superset', naming two EVIDENCE_ABLATION classes. "
            "It did not. random_replay_control credited a class to every axis it DREW, "
            "including axes where perturbed_frame returned None and nothing was perturbed; "
            "every corpus seed carries exactly one EvidenceRef, so EVIDENCE_ABLATION can "
            "never move one, and those two classes were fabricated. With attribution "
            "corrected the two strategies find the same classes. This is a measured result, "
            "not a defect."
        ),
    )


def _dual_oracle_stops_teacher_error(ctx: Stage3GateContext) -> GateCheck:
    """G3.5 — the dual oracle refuses all three constructed teacher-error cases."""
    cases = teacher_error_cases()
    refused = [case for case in cases if case.dual_oracle_refused]
    teacher_only_would_pass = [case for case in cases if case.teacher_only_passed]
    passed = (
        len(cases) >= 3
        and len(refused) == len(cases)
        and len(teacher_only_would_pass) == len(cases)
    )
    detail = "; ".join(
        f"case {case.case_id}: dual oracle refused={case.dual_oracle_refused} on "
        f"{list(case.violation_kinds)}, teacher-only control would have passed="
        f"{case.teacher_only_passed}"
        for case in cases
    )
    return GateCheck(
        "G3.5",
        "Dual oracle prevents teacher-error crystallization",
        passed,
        detail
        + (
            ". Oracle B does the catching: a teacher-only rule accepts all three, so the "
            "second oracle is load-bearing rather than decorative (falsifier F4 does not "
            "fire). These are CONSTRUCTED corrupted snapshots — a valid mechanism test, and "
            "not evidence about any real teacher's error modes."
            if passed
            else ". FALSIFIER F4 FIRES: the dual oracle did not refuse every constructed "
            "teacher-error case, so §20's design does not prevent teacher-error "
            "crystallization."
        ),
    )


def _lifecycle_end_to_end(ctx: Stage3GateContext) -> GateCheck:
    """G3.6 — crystallize -> promote -> audit -> drift -> melt -> recrystallize."""
    steps: list[str] = []
    field, index = KnowledgeField(), BoundaryIndex()
    store = CounterexampleStore(cold_archive=None)

    run = crystallize_region(ctx, field, store)
    steps.append(
        f"crystallize: {run.outcome.value} over region {run.region_key} after trying "
        f"{[form.value for form in run.candidates_tried] or 'no form'} — {run.reason}"
    )
    crystallised = run.cell is not None

    # The remaining steps run on the lab-constructed Φ-oracle cell so the report
    # can say which parts of the lifecycle work even though the first does not.
    # This is stated, never smuggled: a pass here would require crystallize.
    cell = phi_oracle_cell()
    frames = ctx.claimed_frames(cell)
    shadow = shadow_execute(cell, frames, oracle=ctx.oracle, vm=ctx.vm)
    state = AssuranceState(
        level=cell.assurance,
        # A1's evidence is a replay, and the shadow run over the cell's own
        # claimed frames *is* that replay. Passing None here would refuse the
        # promotion on the gate's omission rather than on the cell's merit.
        replay=shadow,
        pressure=None,
        shadow=shadow,
        exhaustive_domain=None,
        proven_properties=(),
        prover=None,
        counterexamples_open=0,
    )
    verdict = promote_cell(cell, state, field=field, index=index)
    steps.append(
        f"promote: {verdict.outcome.value} ({verdict.reason}); shadow saw "
        f"{shadow.frames_seen} frames over {shadow.distinct_boundary_keys} boundary keys, "
        f"coverage_met={shadow.coverage_met}"
    )
    promoted = verdict.outcome is PromotionOutcome.PROMOTED

    audited = 0
    if promoted:
        probability = audit_probability(
            cell,
            stress=zero_stress(),
            epoch_age=1,
            boundary_distance=0,
            recent_agreement=1.0,
        )
        report = sample_audit(
            cell,
            frames,
            sampler=AuditSampler("gate-boot-salt"),
            oracle=ctx.oracle,
            probability=probability,
        )
        audited = report.audits
        steps.append(
            f"audit: rate {probability:.4f} sampled {report.audits}/{len(frames)} frames, "
            f"{report.disagreements} disagreements"
        )

    melted = recrystallised = False
    if promoted:
        drifted = replace(cell.boundary, predicates=(actor_predicate(RelationFamily.NETWORK),))
        partial = partial_melt(cell, drifted, field=field, index=index)
        steps.append(
            f"partial_melt: reopened {len(partial.reopened_keys)} keys, "
            f"repair_locality={partial.repair_locality}, {partial.reason}"
        )
        survivor = partial.surviving_cell or cell
        full = None
        if field.get(survivor.cell_id) is not None:
            full = full_melt(survivor, field=field, index=index)
            melted = field.get(survivor.cell_id) is None
            steps.append(
                f"full_melt: {full.reason}; field now holds {len(field.cells())} cells"
            )
        # Actually run it. ``recrystallised`` was initialised False and never
        # assigned, so ``passed`` — which requires it — could not become True under
        # any state of the code, including one where every step worked. A criterion
        # that cannot pass measures nothing.
        recrystallised_run = None
        if full is not None:
            recrystallised_run = recrystallize(
                full,
                config=CrystalConfig(seed=EVAL_SEED),
                teacher=ctx.teacher,
                field=field,
                store=store,
                region=lifecycle_region(ctx),
            )
        if recrystallised_run is None:
            steps.append(
                "recrystallize: returned None — "
                + (
                    "the full melt reopened no keys"
                    if full is None or not full.reopened_keys
                    else "no fresh region was available"
                )
            )
        else:
            recrystallised = recrystallised_run.cell is not None
            steps.append(
                f"recrystallize: {recrystallised_run.outcome.value} over region "
                f"{recrystallised_run.region_key} — {recrystallised_run.reason}"
            )

    bounded = len(field.cells()) <= MAX_CELLS and field.memory_bytes() <= MAX_FIELD_BYTES
    passed = crystallised and promoted and audited > 0 and melted and recrystallised
    return GateCheck(
        "G3.6",
        "Promotion, auditing, partial and full melting work end-to-end",
        passed,
        " | ".join(steps)
        + f" | field stayed within MAX_CELLS={MAX_CELLS} and MAX_FIELD_BYTES: {bounded}"
        + (
            ""
            if passed
            else " | "
            + lifecycle_stop_reason(
                run,
                promoted=promoted,
                audited=audited,
                melted=melted,
                recrystallised=recrystallised,
            )
        ),
    )


def crystallize_region(
    ctx: Stage3GateContext,
    field: KnowledgeField,
    store: CounterexampleStore,
    *,
    rank: int = 0,
) -> Any:
    """Run the real CRYSTAL pipeline on the corpus's ``rank``-th largest region.

    Public because ``cli.py`` drives the same code path the gate does. A second
    copy in the CLI would let the operator view and the gate view disagree about
    what CRYSTAL does, which is the one thing neither may do.
    """
    key, frames = ctx.regions()[rank]
    region = region_sample(
        key,
        frames,
        sessions=ctx.evaluation.sessions,
        transitions=ctx.evaluation.sessions[0].transitions[:3],
    )
    return crystallize(
        region,
        config=CrystalConfig(seed=EVAL_SEED),
        teacher=ctx.teacher,
        field=field,
        store=store,
    )


def _melting_is_localised(ctx: Stage3GateContext) -> GateCheck:
    """G3.7 — localised drift reopens one subregion and spares the rest.

    This is falsifier F2, the one the stage turns on. The cells are built by
    ``labs/cell_path.phi_oracle_cell`` rather than by ``crystallize``, because
    ``crystallize`` refuses on this corpus (G3.6); that provenance is stated in
    the detail string rather than left for a reader to assume. What is measured
    is the melting mechanism itself, which is what F2 asks about.
    """
    field, index = KnowledgeField(), BoundaryIndex()
    spanning = phi_oracle_cell(cell_id="cell-spanning")
    spanning = replace(
        spanning,
        boundary=replace(
            spanning.boundary,
            predicates=(
                actor_predicate(RelationFamily.FILESYSTEM),
                actor_predicate(RelationFamily.NETWORK),
            ),
        ),
    )
    field.insert(spanning)
    index.insert(spanning)
    unrelated: list[KnowledgeCellV1] = []
    for position, family in enumerate(
        (RelationFamily.IDENTITY, RelationFamily.AUTHORIZATION, RelationFamily.LOADING),
        start=1,
    ):
        other = phi_oracle_cell(cell_id=f"cell-{position}")
        other = replace(
            other, boundary=replace(other.boundary, predicates=(actor_predicate(family),))
        )
        field.insert(other)
        index.insert(other)
        unrelated.append(other)

    before_keys = {cell.cell_id: index.keys_for(cell.cell_id) for cell in unrelated}
    drifted = replace(
        spanning.boundary, predicates=(actor_predicate(RelationFamily.NETWORK),)
    )
    # One probe frame inside the drifted region, so the criterion can assert the
    # thing the spec actually asks for: that the reopened region routes to
    # abstention afterwards. It is CONSTRUCTED — a corpus frame with its relation
    # family and actor mask replaced to satisfy the drifted predicate — because no
    # corpus frame carries INTERPRETER in the NETWORK family. Constructed and said
    # so; the alternative was leaving the assertion vacuous, which is how a
    # whole-cell discard passed this criterion.
    probe = drift_probe(ctx, drifted)
    probe_before = None if probe is None else index.lookup(probe)
    report = partial_melt(spanning, drifted, field=field, index=index)

    region_keys = set(drifted.keys())
    original_keys = set(spanning.boundary.keys())
    # Non-empty as well as contained. The subset test alone is satisfied by the
    # empty set, so a partial_melt that discarded the whole cell and reopened
    # nothing passed this conjunct — and so did one that re-inserted nothing.
    reopened_within = bool(report.reopened_keys) and set(report.reopened_keys) <= region_keys
    survivors_intact = all(
        index.keys_for(cell.cell_id) == before_keys[cell.cell_id]
        and field.get(cell.cell_id) is not None
        for cell in unrelated
    )
    stale_gone = field.get(spanning.cell_id) is None
    locality = report.repair_locality
    survivor = report.surviving_cell
    # The four assertions F2 is actually about, which this criterion used to leave
    # to the unit tests while two documents cited it as the evidence: the survivor
    # is really in both containers, its region is strictly inside the original's
    # and disjoint from the drifted one, and a frame in the reopened region routes
    # to abstention rather than to a stale cell.
    survivor_live = survivor is not None and (
        field.get(survivor.cell_id) is not None and bool(index.keys_for(survivor.cell_id))
    )
    survivor_keys = set() if survivor is None else set(survivor.boundary.keys())
    survivor_narrower = bool(survivor_keys) and survivor_keys < original_keys
    survivor_avoids_region = survivor is not None and not survivor.boundary.intersects(drifted)
    region_abstains = (
        probe is not None
        and probe_before is not None
        and probe_before.cell_id == spanning.cell_id
        and index.lookup(probe) is None
    )
    passed = (
        locality == 1.0
        and reopened_within
        and survivors_intact
        and stale_gone
        and survivor_live
        and survivor_narrower
        and survivor_avoids_region
        and region_abstains
    )
    return GateCheck(
        "G3.7",
        "Localized drift reopens a subregion without discarding unrelated knowledge",
        passed,
        f"4 cells across 4 boundary regions; drift driven into 1 region "
        f"({sorted(region_keys)}). reopened_keys={list(report.reopened_keys)}, non-empty and "
        f"⊆ drifted region: {reopened_within}; unrelated cells keep their exact index "
        f"footprint: {survivors_intact}; the stale cell is gone from the field: {stale_gone}; "
        f"survivor {survivor.cell_id if survivor else None} is live in field and index: "
        f"{survivor_live}, keeping {list(index.keys_for(survivor.cell_id)) if survivor else []} "
        f"— a proper subset of the original's {sorted(original_keys)}: {survivor_narrower} — "
        f"and its boundary shares no satisfiable frame with the drifted region: "
        f"{survivor_avoids_region}; a constructed frame inside the drifted region that the "
        f"index answered with {probe_before.cell_id if probe_before else None} before the "
        f"melt now routes to abstention: {region_abstains}. "
        f"repair_locality={locality} "
        f"({report.unrelated_cells_retained}/{report.unrelated_cells_before} unrelated cells "
        "retained) is reported as a bystander-count sanity check and NOT as the number that "
        "falsifies F2: partial_melt touches only this cell's id and its successor's, and "
        "KnowledgeField.insert refuses rather than evicting, so the ratio is 1.0 by "
        "construction on every report that exists — a partial_melt with no narrowing logic "
        "at all would report the same 1.0. The seven conjuncts above are what can fail. "
        "Cells constructed by labs/cell_path.phi_oracle_cell, not by crystallize (see "
        "G3.6); the melting mechanism is what is measured here. The drift was authored by "
        "the corpus designer, so this is a mechanism demonstration and not a field claim.",
    )


def _evidence_and_causal_attribution_survive(ctx: Stage3GateContext) -> GateCheck:
    """G3.8 — crystallised execution preserves evidence and causal attribution."""
    cell = phi_oracle_cell()
    field, index = KnowledgeField(), BoundaryIndex()
    field.insert(cell)
    index.insert(cell)
    claimed = ctx.claimed_frames(cell)
    if not claimed:
        return GateCheck(
            "G3.8",
            "Crystallized execution preserves evidence and causal attribution",
            False,
            "UNMEASURED: no corpus frame falls inside the cell's boundary, so no frame was "
            "resolved by a cell and there was nothing to check",
        )
    sequence_id = "s3-gate-0001"
    slot = CrystalSlot(field=field, index=index, vm=ctx.vm, frames={sequence_id: claimed})
    prediction = slot.predict(stub_sequence(sequence_id))

    results = [ctx.vm.run(cell.operator, frame) for frame in claimed]
    answered = [r for r in results if not r.abstained]
    evidence_covered = all(
        {ref.digest for ref in frame.evidence} <= {ref.digest for ref in result.evidence}
        for frame, result in zip(claimed, results, strict=True)
        if not result.abstained
    )
    chain = prediction.evidence_relevance
    chain_bound = bool(chain) and all(isinstance(item.ref, EvidenceRef) for item in chain)
    cheap = prediction.compute_path is ComputePath.CHEAP_TRANSITION
    risk_only = return_risk_evidence_probe(ctx, claimed[0])
    passed = bool(answered) and evidence_covered and chain_bound and cheap
    return GateCheck(
        "G3.8",
        "Crystallized execution preserves evidence and causal attribution",
        passed,
        f"{len(answered)}/{len(claimed)} claimed frames answered by the cell; every answered "
        f"frame's result covers the frame's own evidence digests: {evidence_covered}; the "
        f"CrystalSlot prediction carries a non-empty EvidenceRef chain of {len(chain)} "
        f"entries: {chain_bound}; compute_path={prediction.compute_path.value} "
        f"(cell hit: {cheap}); verdict={prediction.verdict.value}. "
        f"Measured here for the RETURN_STATE terminator only: PRESERVE_EVIDENCE unions and "
        f"RETURN_STATE pops an EVIDENCE handle (isa.STACK_EFFECT), so a RETURN_STATE program "
        f"cannot answer with less evidence than it was given. That is NOT a general "
        f"structural guarantee, and this line used to claim one. RETURN_RISK pops only a "
        f"FLOAT: a verified program ending in it answers with "
        f"{risk_only['evidence_count']} evidence ref(s) "
        f"(abstained={risk_only['abstained']}), measured just now. What stops such a cell "
        f"is the oracle rather than the ISA — the same probe scores "
        f"d_causal_attribution={risk_only['d_causal_attribution']} and "
        f"d_evidence_requirement={risk_only['d_evidence_requirement']}, which crystal "
        f"refuses above epsilon — and CrystalSlot fills the prediction's chain from the "
        f"frame, so no evidence-free verdict reaches a consumer contract. Empirical, not "
        f"proven: the ISA permits it and nothing in the bytecode layer forbids it.",
    )


def _cost_against_the_phi_oracle(ctx: Stage3GateContext) -> GateCheck:
    """G3.9 — restated (ADR-0024): the bar is the Φ-oracle on cost and bytes.

    "Materially lower than pure DTL" is void: the DTL is rejected and the thing
    Stage 3 wraps is a zero-parameter rule. The honest bar is that a
    ``KnowledgeCellV1`` reproducing the Φ-oracle costs no more µs/event and no
    more bytes than running the Φ-oracle directly, at identical scores. The
    security-quality half of the criterion is UNMEASURED and is not claimed.
    """
    table = ctx.baselines
    rows = {row.baseline_id: row for row in table.rows}
    cell_row, phi_row = rows.get("S3"), rows.get("B3")
    if cell_row is None or phi_row is None:
        return GateCheck(
            "G3.9",
            "Crystallised path costs no more than the Φ-oracle it wraps",
            False,
            "UNMEASURED: the baseline table carries no S3 (cell path) or B3 (Φ-oracle) row",
        )
    if cell_row.microseconds_per_event is None or phi_row.microseconds_per_event is None:
        return GateCheck(
            "G3.9",
            "Crystallised path costs no more than the Φ-oracle it wraps",
            False,
            "UNMEASURED: one of the two paths carried no measured cost, and an unmeasured "
            "cost is never treated as cheap",
        )
    time_ratio = cell_row.microseconds_per_event / phi_row.microseconds_per_event
    byte_ratio = cell_row.bytes_resident / phi_row.bytes_resident
    scores_identical = cell_row.pr_auc == phi_row.pr_auc
    passed = time_ratio <= 1.0 and byte_ratio <= 1.0 and scores_identical
    # Each row's own repetitions already disagree, so the ratio is reported as the
    # band its inputs admit rather than as a point. The previous detail gave a
    # single best-of-N ratio with no dispersion at all, which reads as a
    # measurement with a zero error bar; repeating the whole procedure moves it.
    band = ratio_band(cell_row.microseconds_spread, phi_row.microseconds_spread)
    failing = [
        name
        for name, ok in (
            ("µs/event ratio > 1", time_ratio <= 1.0),
            ("byte ratio > 1", byte_ratio <= 1.0),
            ("scores not identical", scores_identical),
        )
        if not ok
    ]
    scores_line = (
        "Scores are identical"
        if scores_identical
        else (
            "Scores are NOT identical: the cell path reaches PR-AUC "
            f"{'n/a' if cell_row.pr_auc is None else format(cell_row.pr_auc, '.4f')} against "
            f"the base rate {table.base_rate:.4f}, while B3 reaches "
            f"{'n/a' if phi_row.pr_auc is None else format(phi_row.pr_auc, '.4f')}"
        )
    )
    return GateCheck(
        "G3.9",
        "Crystallised path costs no more than the Φ-oracle it wraps",
        passed,
        f"within one run at loadavg {table.loadavg[0]:.2f}: the Knowledge Cell path costs "
        f"{time_ratio:.2f}x baseline B3's µs/event"
        + (f" (band {band[0]:.2f}x–{band[1]:.2f}x from the two rows' own "
           f"repetition spreads; ONE sample, not a replicated estimate)" if band else
           " (dispersion UNMEASURED)")
        + f" and {byte_ratio:.2f}x its bytes "
        f"({cell_row.bytes_resident} B vs {phi_row.bytes_resident} B). {scores_line}. "
        + (
            f"FALSIFIER F1 FIRES on: {failing}. The cell format is rejected for this class "
            "of knowledge (ADR-0021). "
            if not passed
            else ""
        )
        + "The 'comparable security quality' clause is reported UNMEASURED: this corpus has "
        "no discriminable middle band (ADR-0010; the frozen frontier's own reason is "
        "ORDER_FREE_BASELINE_TIES_BEST), so a PR-AUC here is not evidence of equivalence. "
        "Absolute µs figures are contended-host numbers; only the ratios above transfer, "
        "and the byte ratio is the only one of the three that is not timing-dependent.",
    )


def _incremental_memory_within_budget(ctx: Stage3GateContext) -> GateCheck:
    """G3.10 — Stage 3's incremental memory sits inside the §38 Edge budget."""
    field, index = KnowledgeField(), BoundaryIndex()
    store = CounterexampleStore(cold_archive=None)
    cell = phi_oracle_cell()
    field.insert(cell)
    index.insert(cell)
    claimed = ctx.claimed_frames(cell, limit=256)

    def work() -> int:
        for frame in claimed:
            hit = index.lookup(frame)
            if hit is not None:
                ctx.vm.run(hit.operator, frame)
        return len(claimed)

    sampler = AuditSampler("gate-boot-salt")
    report = measure_stage3_resources(
        work,
        measured_by="pocketsec.stage3.gate:measure_memory",
        boundary_index=index,
        knowledge_cells=field,
        counterexample_hot=store,
        # Supplied rather than left out: an unsupplied component makes
        # within_budget None, and a criterion that reports UNMEASURED because
        # the gate did not bother to measure is not an honest UNMEASURED.
        cell_vm_bytes=cell_vm_bytes(ctx.vm),
        audit_state_bytes=audit_state_bytes(sampler, zero_stress()),
    )
    within_rss = (
        report.incremental_rss_bytes is not None
        and report.incremental_rss_bytes <= STAGE3_NORMAL_INCREMENTAL_RSS_BYTES
    )
    passed = report.within_budget is True and within_rss
    components = ", ".join(
        f"{name} {report.per_component_bytes.get(name, 0)}/{budget} B"
        for name, budget in STAGE3_BUDGET.items()
    )
    return GateCheck(
        "G3.10",
        "Stage 3 incremental memory within the declared Edge budget",
        passed,
        f"measured through ResourceSampler over {len(claimed)} frames at loadavg "
        f"{report.loadavg[0]:.2f}: incremental RSS {report.incremental_rss_bytes} B against "
        f"the {STAGE3_NORMAL_INCREMENTAL_RSS_BYTES} B normal ceiling; per component "
        f"{components}; within_budget={report.within_budget}"
        + (
            f"; over budget: {list(report.over_budget)}"
            if report.within_budget is not True
            else ""
        )
        + (
            f"; UNMEASURED components: {list(report.unmeasured)}"
            if report.unmeasured
            else ""
        ),
    )


def _no_component_lacks_ablation_support(ctx: Stage3GateContext) -> GateCheck:
    """G3.11 — every OPTIONAL function names a measured delta, saturation guard first."""
    report = run_ablation(ctx.baselines)
    payload = report.to_dict()
    saturation = payload.get("saturation", {})
    passed = bool(payload.get("passes_g3_11"))
    return GateCheck(
        "G3.11",
        "No surviving component lacks ablation-supported value",
        passed,
        f"saturation guard ran first and returned {payload.get('status')}: "
        f"{saturation.get('reason')}. {len(payload.get('entries', []))} ablation entries "
        f"recorded; failed={payload.get('failed')}, "
        f"not_yet_justified={payload.get('not_yet_justified')}, "
        f"rejected={payload.get('rejected')}. "
        + (
            "A saturated split cannot show that any component helps, so no ablation result "
            "is recorded and the criterion FAILS as DEGENERATE. NOT_YET_JUSTIFIED is not "
            "REJECTED: these components have not been disproven, they have not been tested."
            if not passed
            else "Every OPTIONAL function names a registered experiment with a measured delta."
        ),
    )


def _verification_claims_are_bounded(ctx: Stage3GateContext) -> GateCheck:
    """G3.12 — verification language limited to properties actually proven."""
    cell = phi_oracle_cell()
    field, index = KnowledgeField(), BoundaryIndex()
    shadow = shadow_execute(cell, ctx.claimed_frames(cell), oracle=ctx.oracle, vm=ctx.vm)
    state = AssuranceState(
        level=cell.assurance,
        # A1's evidence is a replay, and the shadow run over the cell's own
        # claimed frames *is* that replay. Passing None here would refuse the
        # promotion on the gate's omission rather than on the cell's merit.
        replay=shadow,
        pressure=None,
        shadow=shadow,
        exhaustive_domain=None,
        proven_properties=(),
        prover=None,
        counterexamples_open=0,
    )
    promote_cell(cell, state, field=field, index=index)
    promoted = field.cells()
    subset = set(state.proven_properties) <= set(ALL_PROVEN_PROPERTIES)
    a5_has_prover = state.level.value != "A5" or state.prover is not None

    # (b) An unfounded A5 must be refused mechanically, not by review — and the
    # probe has to REACH the guard. The forged state used to keep the cell at A1
    # while claiming A5, so ``_pre_insertion_refusal``'s level-mismatch branch
    # refused it and the A5/prover and unfounded-property logic was never the
    # reason: deleting ``_guard_verification_claims`` entirely left this check
    # green, still printing the sentence below. Each probe now differs from a
    # promotable A5 state in exactly one way, and each asserts the guard's own text.
    a5 = type(cell.assurance)("A5")
    a5_cell = replace(phi_oracle_cell(cell_id="cell-forged-a5"), assurance=a5)
    a5_state = replace(
        state,
        level=a5,
        exhaustive_domain="pocketsec.stage3.bytecode.verifier:verify",
        proven_properties=tuple(ALL_PROVEN_PROPERTIES[:1]),
        prover="pocketsec.stage3.bytecode.verifier:verify",
    )
    guard_probes = {
        "empirical property presented as proven": replace(
            a5_state, proven_properties=(next(iter(TESTED_ONLY_PROPERTIES)),)
        ),
        "property the verifier does not prove": replace(
            a5_state, proven_properties=("this VM is safe because no test broke it",)
        ),
        "A5 with no prover": replace(a5_state, prover=None),
        "A5 with an empty proof set": replace(a5_state, proven_properties=()),
    }
    guard_results = {
        label: guard_outcome(a5_cell, probe) for label, probe in guard_probes.items()
    }
    # Only a refusal from the guard itself counts. ``_guard_verification_claims``
    # runs before every other branch and is the only thing in ``promote_cell`` that
    # raises — field and index errors are caught and returned as verdicts — so
    # "GUARD" means that specific check fired. "REFUSED-ELSEWHERE" means another
    # branch got there first and this criterion measured nothing.
    forged_refused = all(result == "GUARD" for result in guard_results.values())
    # The control: a well-formed A5 claim must get *past* the guard. Without it,
    # "all four refused" would also be satisfied by a guard that raised on
    # everything. It is not expected to promote — this cell's shadow run diverges
    # (G3.6) — only to be refused somewhere other than the guard.
    control_outcome = guard_outcome(a5_cell, a5_state)
    control_promoted = control_outcome != "GUARD"

    defects = property_set_defects()
    unbounded = unbounded_verification_language(_FINDINGS)
    passed = (
        subset
        and a5_has_prover
        and forged_refused
        and control_promoted
        and not defects
        and not unbounded
        and _FINDINGS.exists()
    )
    return GateCheck(
        "G3.12",
        "Formal-verification claims limited to properties actually proven",
        passed,
        f"(a) {len(promoted)} promoted cell(s); claimed proven_properties ⊆ the "
        f"{len(ALL_PROVEN_PROPERTIES)} proven-by-construction properties: {subset}. Four "
        f"single-variable probes against a well-formed A5 state, each recorded by which "
        f"branch refused it — 'GUARD' means _guard_verification_claims raised (it runs first "
        f"and is the only thing in promote_cell that raises), 'REFUSED-ELSEWHERE' means "
        f"another branch got there first and this criterion measured nothing: "
        f"{guard_results}. The control — the same A5 state with valid claims — is refused "
        f"somewhere other than the guard ({control_outcome}), so 'all four refused' is not a "
        f"guard that refuses everything: {control_promoted}. "
        f"(b) the two property sets are disjoint, no PROVEN entry appeals to testing for its "
        f"backing, and every TESTED_ONLY entry words itself as empirical: {not defects}"
        + (f" — defects: {defects}" if defects else "")
        + f". (c) every occurrence of {list(VERIFICATION_WORDS)} in "
        f"{_FINDINGS.relative_to(REPO_ROOT)} — Stage 3's external claim surface — names what "
        f"backs it: {not unbounded and _FINDINGS.exists()}"
        + (
            f"; unbacked: {unbounded[:5]}"
            if unbounded
            else ("; the findings document does not exist" if not _FINDINGS.exists() else "")
        )
        + ". Part (c) is scoped to the findings document rather than grepped across "
        "docs/stage-3-*.md and pocketsec/stage3/**/*.py as the spec sketched. That grep was "
        "written, run and kept in gate_criteria.py; repo-wide it reported 'provenance' as a "
        "claim that something is proven, 'unverified' as a claim that it is verified, and "
        "docstrings citing PROVEN_PROPERTIES as unbacked. A check that cries wolf on its own "
        "vocabulary gets switched off, so the claim itself is checked by (b) and the wording "
        "is checked where an unearned claim actually escapes the repository.",
    )


def _prior_art_reviewed_before_novelty(ctx: Stage3GateContext) -> GateCheck:
    """G3.13 — no novelty claim ahead of a reviewed prior-art entry."""
    ledger = PriorArtLedger.load()
    entry = ledger.entries.get(STAGE3_HYPOTHESIS)
    if entry is None:
        return GateCheck(
            "G3.13",
            "Prior-art review completed before any external novelty claim",
            False,
            f"the prior-art ledger holds no entry for {STAGE3_HYPOTHESIS}, which Stage 3's "
            "experiment ids name",
        )
    if not _FINDINGS.exists():
        return GateCheck(
            "G3.13",
            "Prior-art review completed before any external novelty claim",
            False,
            f"{_FINDINGS.relative_to(REPO_ROOT)} does not exist, so the honesty ledger's "
            "five required sections cannot be checked",
        )
    text = _FINDINGS.read_text(encoding="utf-8")
    reviewed = entry.literature_status.value != "NOT_REVIEWED"
    claims = sorted(
        {word for word in NOVELTY_WORDS if claims_novelty(text, word)}
    )
    missing_headings = [head for head in _LEDGER_HEADINGS if head not in text]
    passed = not missing_headings and (reviewed or not claims)
    return GateCheck(
        "G3.13",
        "Prior-art review completed before any external novelty claim",
        passed,
        f"Stage 3's hypothesis binding is {STAGE3_HYPOTHESIS}: {entry.claim!r}, with "
        f"literature_status={entry.literature_status.value!r} and "
        f"patent_status={entry.patent_status.value!r}; "
        f"{_FINDINGS.relative_to(REPO_ROOT)} carries all five honesty-ledger headings: "
        f"{not missing_headings}"
        + (f" (missing {missing_headings})" if missing_headings else "")
        + f"; novelty-claiming phrases found: {claims or 'NONE'}"
        + (
            ""
            if passed
            else f". A novelty claim needs a REVIEWED ledger entry behind it and "
            f"{STAGE3_HYPOTHESIS} is {entry.literature_status.value}."
        ),
    )
