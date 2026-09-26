"""Stage 6 gate — the measured criteria: G6.2-G6.5, G6.9, G6.10, G6.12, G6.13.

Each check reads the shared run in :class:`pocketsec.stage6.gate.Stage6GateContext` (one
compile, one run of every learner, one 60-month run, one poison suite) and never replays
it. Two rules shape every function below.

**Vacuous is not passed.** A regression bound examined over zero promotions, a lineage
check over zero learned items, an FP rate that "returns" to a baseline of 1.0, a retention
figure for a detection that was never acquired: each would satisfy the letter of its
criterion while measuring nothing. Each is reported as ``vacuous`` and fails the check,
with the count that makes it vacuous in the detail.

**Unmeasured is not measured.** A figure a subsystem cannot produce (the Stage 6 learner
cannot run below ``MAX_DETECTOR_ITEMS``; RSS may be unreadable) is ``None`` in the detail
and fails the check that needed it.
"""

from __future__ import annotations

import copy
import dataclasses
import itertools
import json
import re
import subprocess
import sys
from collections.abc import Iterable, Mapping, Sequence
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.benchmark.security_metrics import recall_at_max_fpr
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.gate import REPO_ROOT, GateCheck
from pocketsec.stage0.hypotheses import HYPOTHESES
from pocketsec.stage6 import gate_rig as rig
from pocketsec.stage6.chamber.evolution import CandidateKind
from pocketsec.stage6.conservation.gate import EPS_FP_RATE, EPS_SECURITY
from pocketsec.stage6.constitution.learning import LifecycleState
from pocketsec.stage6.core_ids import STAGE6_FUNCTIONS, FunctionClass
from pocketsec.stage6.fossils.lineage import MAX_LINEAGE_NODES, NodeKind
from pocketsec.stage6.fossils.store import FossilIntegrityError, FossilReason
from pocketsec.stage6.labs.endurance import (
    CAPACITY_SWEEP,
    FPR_BUDGET,
    REPLAY_BUDGETS_BYTES,
    STORE_CAPS,
    VERDICTS,
    MonthCheckpoint,
    StageSixLearner,
    run_endurance,
    store_violations,
)
from pocketsec.stage6.labs.endurance_corpus import (
    ENDURANCE_SEED,
    EVAL_SESSIONS_PER_FAMILY,
    FAMILIES,
    SESSIONS_PER_MONTH,
    build_endurance_timeline,
    compile_timeline,
)
from pocketsec.stage6.labs.poison_suite import PoisonClass, PoisonRow, build_poison_arm
from pocketsec.stage6.memory.semantic import (
    ItemKind,
    LineageError,
    TrustedKnowledgeState,
    score_session,
)
from pocketsec.stage6.promotion.controller import GENESIS_PROMOTION_NODE
from pocketsec.stage6.resources import STORE_BUDGETS, loadavg, measure_stage6_resources
from pocketsec.stage6.shadow.canary import CANARY_WINDOW_SESSIONS, PROBATION_SESSIONS

if TYPE_CHECKING:
    from pocketsec.stage6.gate import Stage6GateContext

__all__ = [
    "BUDGET_STORES",
    "FINDINGS_PATH",
    "budget_bytes",
    "check_ablation_survival",
    "check_bounded_growth",
    "check_epoch_adaptation",
    "check_historical_capability_bounds",
    "pair_regressions",
    "check_poisoning_coverage",
    "check_provenance_and_lineage",
    "check_repetition_is_not_normality",
    "check_resource_envelope",
    "resource_measurement",
]

STAGE6 = "stage6"
FINDINGS_PATH = REPO_ROOT / "docs" / "stage-6-findings.md"
#: §39 budget row -> the ``StageSixLearner.stores()`` entries it covers. Every store the
#: learner reports is in exactly one row, so nothing is left unbudgeted by omission.
BUDGET_STORES: Mapping[str, tuple[str, ...]] = {
    "quarantine_metadata": ("gateway", "ledger", "episode_book"),
    "episodic_hot_index": ("episodic",),
    "semantic_procedural_memory": ("trusted", "contexts"),
    "lineage_fossil_metadata": ("lineage", "fossils"),
    "consolidation_workspace": ("consolidator", "chamber", "controller", "replay_ring"),
}
_LEDGER_HEADINGS = ("### MEASURED", "### UNMEASURED", "### REJECTED", "### RETRACTED",
                    "### NOT A DETECTION RESULT")
_NOVELTY = re.compile(r"\b(novel|novelty|first-ever|breakthrough|unprecedented|"
                      r"state-of-the-art|world-first)\b", re.IGNORECASE)
_CONSTRUCTS = re.compile(r"HELIOS|MNEMOSYNE|Shadow Mind|Plasticity Field|Epistemic Half-Life|"
                         r"Knowledge Fossil|Lineage DAG|Evolution Chamber|Semantic Homeostasis|"
                         r"Conservation Gate|Experience Capsule", re.IGNORECASE)


def budget_bytes(stores: Mapping[str, int]) -> dict[str, int]:
    """Fold per-store bytes into the five §39 rows; an unknown store is its own row."""
    folded = {row: sum(stores.get(name, 0) for name in names)
              for row, names in BUDGET_STORES.items()}
    covered = {name for names in BUDGET_STORES.values() for name in names}
    folded.update({f"UNBUDGETED:{name}": size for name, size in stores.items()
                   if name not in covered})
    return folded


def _stage6_points(ctx: Stage6GateContext) -> tuple[MonthCheckpoint, ...]:
    return ctx.endurance.for_learner(STAGE6)


# --- G6.2 -------------------------------------------------------------------------------


def _kinds(dag: Any, ids: Iterable[str]) -> set[NodeKind]:
    return {node.kind for node in (dag.node(i) for i in ids) if node is not None}


def _lineage_problems(learner: StageSixLearner) -> tuple[int, list[str]]:
    state, dag = learner.controller.mind.current(), learner.lineage
    learned = [i for i in state.items if i.kind is not ItemKind.THRESHOLD]
    problems = [f"incomplete {i.item_id}" for i in state.items if not dag.lineage_complete(i)]
    for node in dag.nodes():
        if node.kind is NodeKind.PROMOTION and node.node_id != GENESIS_PROMOTION_NODE:
            kinds = _kinds(dag, dag.parents(node.node_id))
            need = {NodeKind.CANDIDATE, NodeKind.CONSERVATION, NodeKind.SHADOW, NodeKind.CANARY}
            if not need <= kinds:
                problems.append(f"{node.node_id} parents {sorted(k.value for k in kinds)}")
    for item in learned:
        for capsule in item.lineage.capsule_ids:
            cited = dag.node(capsule)
            children = _kinds(dag, dag.children(capsule))
            live = cited is not None and cited.kind is NodeKind.CAPSULE
            if not live or NodeKind.VERDICT not in children:
                problems.append(f"{item.item_id} cites {capsule} without a live CAPSULE+VERDICT")
    problems += [f"edge digest {e}" for e in dag.verify()]
    return len(learned), problems


def _tamper_detected(learner: StageSixLearner) -> bool:
    """Alter one edge's ``reason`` in a COPY of the DAG; ``verify`` must name it."""
    copied = copy.deepcopy(learner.lineage)
    edge = next(iter(copied.edges()), None)
    if edge is None:
        return False
    copied._edges[(edge.parent, edge.child)] = dataclasses.replace(edge, reason="gate-tamper")
    return edge.edge_id in copied.verify()


def _load_refused(learner: StageSixLearner) -> bool:
    genesis = learner.controller.mind.current()
    foreign = rig.LabChamber(copy.deepcopy(learner.lineage)).mint(genesis, add=(rig.F1_MOTIF,))
    unlineaged = TrustedKnowledgeState(
        version=genesis.version + 1, parent_digest=genesis.digest(),
        active_context=genesis.active_context,
        items=(*genesis.items, *foreign.delta.added), rehearsal=())
    try:
        TrustedKnowledgeState.from_canonical_bytes(unlineaged.canonical_bytes(),
                                                   lineage=learner.lineage)
    except LineageError:
        return True
    return False


def check_provenance_and_lineage(ctx: Stage6GateContext) -> GateCheck:
    """G6.2 — every promoted knowledge object has complete provenance and lineage."""
    runs = {"12-month": ctx.stage6, "60-month": ctx.year_learner}
    rows, learned_total, problems = [], 0, []
    for name, learner in runs.items():
        learned, found = _lineage_problems(learner)
        learned_total += learned
        problems += [f"{name}: {p}" for p in found]
        rows.append(f"{name}: {learned} learned items, {len(found)} problems, DAG nodes "
                    f"{learner.lineage.stats().nodes}")
    tamper, load = _tamper_detected(ctx.stage6), _load_refused(ctx.stage6)
    vacuous = learned_total == 0
    passed = not problems and tamper and load and not vacuous
    return GateCheck(
        "G6.2", "Every promoted knowledge object has complete provenance and lineage", passed,
        f"{'; '.join(rows)}; problems {problems[:6]}; tamper probe (one edge reason altered "
        f"in a copy) detected by verify(): {tamper}; lineage-less item refused at load: "
        f"{load}" + ("; VACUOUS: no learned (non-THRESHOLD) item is trusted in either run, so "
                     "no promoted object's lineage was examined" if vacuous else ""),
    )


# --- G6.3 -------------------------------------------------------------------------------


Pool = Sequence[tuple[Any, str | None, str]]


def _family_rows(state: TrustedKnowledgeState, pool: Pool,
                 family: str) -> list[tuple[int, float]] | None:
    rows = [(1 if f == family else 0, score_session(state, s, context_id=c).score)
            for s, f, c in pool if f == family or f not in FAMILIES]
    return rows if any(label for label, _ in rows) else None


def _family_recall(state: TrustedKnowledgeState, pool: Pool, family: str) -> float | None:
    """Recall at the FPR budget — a threshold this metric re-chooses for itself."""
    rows = _family_rows(state, pool, family)
    if rows is None:
        return None
    return recall_at_max_fpr([r[0] for r in rows], [r[1] for r in rows], FPR_BUDGET)[0]


def _operating_recall(state: TrustedKnowledgeState, pool: Pool, family: str) -> float | None:
    """Recall at the state's OWN threshold: what the endpoint would actually alert on.

    ``_family_recall`` re-chooses the threshold, so a promotion that only raises the
    THRESHOLD above every detector weight left it unchanged while blinding every family
    (review F4). Both are reported and a drop in either is a violation.
    """
    rows = _family_rows(state, pool, family)
    if rows is None:
        return None
    positives = [score for label, score in rows if label]
    return sum(score >= state.threshold() for score in positives) / len(positives)


_METRICS = (("recall@FPR", _family_recall), ("operating recall", _operating_recall))


def pair_regressions(before: TrustedKnowledgeState, after: TrustedKnowledgeState,
                     pool: Pool) -> tuple[bool, list[str]]:
    """(could this pair have regressed at all, the violations it shows).

    A pair is *uninformative* when nothing learned changed (same items at the same
    weights) or when the before-state detected nothing in any family on either metric:
    a bound over a baseline of zero cannot be broken, so passing it proves nothing
    (review honesty F4).
    """
    changed = {(i.item_id, i.weight) for i in before.items} != {
        (i.item_id, i.weight) for i in after.items}
    violations: list[str] = []
    baseline = False
    for family in FAMILIES:
        for name, metric in _METRICS:
            b, a = metric(before, pool, family), metric(after, pool, family)
            baseline |= bool(b)
            if b is not None and (a is None or a < b - EPS_SECURITY):
                violations.append(f"{family} {name} {b} -> {a}")
    return changed and baseline, violations


def _promotion_regressions(learner: StageSixLearner,
                           pool: Pool) -> tuple[int, int, int, list[str]]:
    """(examined, informative, unexaminable, violations) over the run's real promotions."""
    examined = informative = unexaminable = 0
    violations: list[str] = []
    for decision in learner.controller.decisions():
        if decision.to_state is not LifecycleState.TRUSTED or decision.candidate_id.startswith(
                "context:"):
            continue
        try:
            before = learner.fossils.load(decision.trusted_before)
            after = learner.fossils.load(decision.trusted_after)
        except (FossilIntegrityError, LineageError, KeyError, ValueError):
            unexaminable += 1
            continue
        examined += 1
        useful, found = pair_regressions(before, after, pool)
        informative += int(useful)
        violations += [f"{decision.candidate_id} {v}" for v in found]
    return examined, informative, unexaminable, violations


def _g2_firing_proof() -> tuple[bool, str]:
    world = rig.build_world()
    state_a = rig.promote_f1_f3(world)
    drop = world.chamber.mint(state_a, remove=(rig.detector_id(state_a, rig.F1_MOTIF),),
                              kinds=frozenset({CandidateKind.CONSOLIDATION}))
    decision = world.controller.submit(drop, holdout=(), hostile=(), variant_seed=7)
    edge = world.dag.edge(drop.candidate_id, f"conservation-{drop.candidate_id}")
    gate = "" if edge is None else edge.gate_result
    fired = decision.to_state is LifecycleState.REJECTED and "G2_HISTORICAL_REPLAY" in gate
    return fired, f"rig candidate removing the F1 detector -> {decision.to_state.value} ({gate})"


def check_historical_capability_bounds(ctx: Stage6GateContext) -> GateCheck:
    """G6.3 — critical historical capabilities remain within predefined regression bounds."""
    pool = [(s, f, m.context_id) for m in ctx.compiled.months
            for s, f in zip(m.eval_steps, m.eval_families, strict=True)]
    examined, informative, unexaminable, violations = _promotion_regressions(ctx.stage6, pool)
    try:
        fired, proof = _g2_firing_proof()
    except ContractError as exc:
        fired, proof = False, f"firing proof aborted by {type(exc).__name__}: {exc}"
    g2 = sum("G2_HISTORICAL_REPLAY" in e.gate_result for e in ctx.stage6.lineage.edges())
    vacuous = informative == 0
    passed = not violations and not unexaminable and fired and not vacuous
    return GateCheck(
        "G6.3", "Critical historical capabilities stay within regression bounds", passed,
        f"12-month run: promotions examined {examined}, informative {informative} (learned "
        f"items changed AND the before-state detected something), unexaminable (fossil "
        f"evicted) {unexaminable}; per-family violations beyond EPS_SECURITY {EPS_SECURITY} "
        f"on recall@FPR{FPR_BUDGET} and on operating recall at each state's own threshold: "
        f"{violations}; G2 refusals recorded in lineage {g2}. Firing proof (rig only): "
        f"{proof}" + ("; VACUOUS: no examined promotion could have regressed (none changed "
                      "a learned item from a state that detected anything), so no regression "
                      "bound was exercised on the real learner" if vacuous else "")
        + ". Families are synthetic accounting labels (spec §6.1)",
    )


# --- G6.4 / G6.9 ------------------------------------------------------------------------


def _rows(ctx: Stage6GateContext, arm: str, learner: str) -> list[PoisonRow]:
    return sorted((r for r in ctx.poison.rows if r.arm_id == arm and r.learner == learner),
                  key=lambda r: r.multiplier)


def _series(rows: Iterable[PoisonRow]) -> list[int | None]:
    return [r.poisoned_promotions for r in rows]


def _poisoned_admissions(arm: str, multiplier: int, seed: int) -> tuple[int, int]:
    """(poisoned capsules offered, CandidateAdmissions minted from them) through one gateway.

    Not a promotion count: an admission is a candidate, and later gates may still refuse it.
    Reported because it shows whether the independence check (ADR-0054) is what held.
    """
    scenario = build_poison_arm(arm, multiplier=multiplier, seed=seed)
    learner = StageSixLearner(scenario.genesis, seed=seed, name=f"gate-{arm}-admissions")
    offered = admitted = 0
    for event in scenario.events:
        if event.kind == "epoch" and event.decision is not None:
            learner.gateway.record_epoch_decision(event.decision)
        elif event.capsule is not None:
            verdict = learner.gateway.admit(event.capsule)
            if event.poisoned:
                offered += 1
                admitted += len(verdict.admissions)
    return offered, admitted


def check_repetition_is_not_normality(ctx: Stage6GateContext) -> GateCheck:
    """G6.4 — slow malicious repetition cannot simply become normal through frequency."""
    parts, ok = [], True
    for arm in ("P1", "P2"):
        six, naive = _rows(ctx, arm, STAGE6), _rows(ctx, arm, "naive-finetune")
        stage2 = _rows(ctx, arm, "stage2-only")
        naive_p = _series(naive)
        six_ok = bool(six) and all(r.poisoned_promotions == 0 for r in six)
        real = bool(naive_p) and all(v is not None and v > 0 for v in naive_p) and all(
            (a or 0) <= (b or 0) for a, b in itertools.pairwise(naive_p))
        clean = sum(r.clean_promotions or 0 for r in six)
        ok = ok and six_ok and real and clean > 0
        parts.append(f"{arm}: stage6 poisoned {_series(six)} clean {clean}; naive poisoned "
                     f"{naive_p} (real and non-decreasing: {real}); stage2-only "
                     f"{_series(stage2)}")
    multipliers = sorted({r.multiplier for r in ctx.poison.rows})
    admissions = {arm: _poisoned_admissions(arm, max(multipliers), ctx.seed)
                  for arm in ("P1", "P1b")}
    return GateCheck(
        "G6.4", "Slow malicious repetition cannot become normal through frequency", ok,
        f"multipliers {multipliers}: " + "; ".join(parts)
        + f". Poisoned capsules offered -> CandidateAdmissions minted at x{max(multipliers)} "
        f"(one gateway, independence check on): {admissions}. PASS needs Stage 6 poisoned 0 "
        "AND Stage 6 clean > 0 (not accept-nothing, F10)",
    )


def check_poisoning_coverage(ctx: Stage6GateContext) -> GateCheck:
    """G6.9 — poisoning tests include data, label, model and slow-drift attacks."""
    rows = ctx.poison.rows
    arms = sorted({r.arm_id for r in rows})
    classes = {r.poison_class for r in rows}
    missing = sorted(c.value for c in PoisonClass if c.value not in classes)
    silent = sorted({r.arm_id for r in rows if r.poisoned_offered == 0})
    unreal = sorted({a for a in arms if _rows(ctx, a, STAGE6) and _rows(ctx, a, STAGE6)[0]
                     .poison_class != PoisonClass.MODEL.value
                     and not any(_series(_rows(ctx, a, "naive-finetune")))})
    six = [r for r in rows if r.learner == STAGE6]
    poisoned = sorted({r.arm_id for r in six if r.poisoned_promotions})
    vacuous = sorted({r.arm_id for r in six if r.poisoned_promotions is None})
    clean = [r.clean_rate for r in six if r.clean_rate is not None]
    clean_ok = any(rate > 0 for rate in clean)
    passed = (len(arms) == 11 and not missing and not silent and not unreal and not poisoned
              and not vacuous and clean_ok)
    verdicts = "; ".join(f"{k} {v.split(':')[0]}"
                         for k, v in sorted(ctx.poison.arm_verdicts.items()))
    return GateCheck(
        "G6.9", "Poisoning tests include data, label, model and slow-drift attacks", passed,
        f"{len(arms)} arms {arms}; classes missing {missing}; arms offering no poison {silent}; "
        f"non-MODEL arms NaiveFinetune never poisoned (DEGENERATE) {unreal}; Stage 6 "
        f"poisoned on {poisoned}; Stage 6 VACUOUS/UNMEASURED rows on {vacuous}; Stage 6 "
        f"clean promotion rate > 0 on any arm: {clean_ok} (max "
        f"{max(clean) if clean else None}). Arm verdicts: {verdicts}",
    )


# --- G6.5 -------------------------------------------------------------------------------


def _point(points: Sequence[MonthCheckpoint], month: int) -> MonthCheckpoint | None:
    return next((p for p in points if p.month == month), None)


def _time_to_adapt(points: Sequence[MonthCheckpoint], spm: int) -> tuple[int | None, str]:
    m1 = _point(points, 1)
    if m1 is None or m1.fp_rate is None:
        return None, "M01 FP rate UNMEASURED"
    if m1.fp_rate >= 1.0:
        return None, "VACUOUS: M01 benign FP rate is 1.0 (every benign session alerts)"
    for p in points:
        if p.month >= 2 and p.fp_rate is not None and p.fp_rate <= m1.fp_rate + EPS_FP_RATE:
            return (p.month - 1) * spm, f"M01 FP {m1.fp_rate}, back by M{p.month:02d}"
    return None, f"M01 FP {m1.fp_rate}; never returned"


def _context_a_baselines(learner: StageSixLearner, context_a: str) -> tuple[int, int]:
    resident = sum(1 for i in learner.controller.mind.current().baselines()
                   if context_a in i.context_ids)
    held = 0
    for fossil in learner.fossils.fossils():
        if fossil.creation_reason is FossilReason.CONTEXT_DORMANCY:
            try:
                state = learner.fossils.load(fossil.artifact_hash)
            except (FossilIntegrityError, LineageError):
                continue
            held += sum(1 for i in state.baselines() if context_a in i.context_ids)
    return resident, held


def check_epoch_adaptation(ctx: Stage6GateContext) -> GateCheck:
    """G6.5 — legitimate epoch changes adapt without destroying old recurring knowledge."""
    points = _stage6_points(ctx)
    adapt, why = _time_to_adapt(points, ctx.sessions_per_month)
    limit = PROBATION_SESSIONS + CANARY_WINDOW_SESSIONS
    a_ok = adapt is not None and adapt <= limit
    resident, held = _context_a_baselines(ctx.stage6, ctx.compiled.months[0].context_id)
    b_ok = resident + held > 0
    resurrections = ctx.stage6.registry.resurrections
    c_ok = resurrections >= 1 or resident >= 1
    m1, m8 = _point(points, 1), _point(points, 8)
    acquired = None if m1 is None else m1.acquisition.get("F1")
    retained = None if m8 is None else m8.retention.get("F1")
    d_ok = (acquired is not None and acquired > EPS_SECURITY and retained is not None
            and retained >= acquired - EPS_SECURITY)
    p5 = _rows(ctx, "P5", STAGE6)
    e_ok = bool(p5) and all(r.poisoned_promotions == 0 for r in p5)
    return GateCheck(
        "G6.5", "Legitimate epoch changes adapt without destroying old knowledge",
        a_ok and b_ok and c_ok and d_ok and e_ok,
        f"(a) time-to-adapt after M02 {adapt} sessions (limit {limit}; {why}); (b) context-A "
        f"baselines resident {resident}, held in verified CONTEXT_DORMANCY fossils {held} "
        f"({'VACUOUS: context A never had a baseline' if not b_ok else 'present'}); (c) "
        f"resurrections {resurrections}, A baselines resident {resident}; at detector_capacity "
        f"{CAPACITY_SWEEP[0]} UNMEASURED (the learner cannot run below MAX_DETECTOR_ITEMS); "
        f"(d) F1 acquisition M01 {acquired} vs retention M08 {retained} "
        f"({'VACUOUS: F1 never acquired' if not (acquired or 0) > EPS_SECURITY else 'measured'});"
        f" (e) arm P5 Stage 6 poisoned {_series(p5)}. Real upgrade drift UNMEASURED (§6.1)",
    )


# --- G6.10 ------------------------------------------------------------------------------


def resource_measurement(*, sessions_per_month: int = SESSIONS_PER_MONTH,
                         eval_per_family: int = EVAL_SESSIONS_PER_FAMILY,
                         seed: int = ENDURANCE_SEED) -> dict[str, Any]:
    """The 12-month Stage 6 loop under Stage 0's sampler, in THIS process.

    Called by ``pocketsec-stage6 resources`` in a fresh interpreter, so the process-wide
    figures are the stage's own and not the gate's (which holds every other run).
    """
    compiled = compile_timeline(build_endurance_timeline(
        sessions_per_month=sessions_per_month, eval_per_family=eval_per_family, seed=seed),
        seed=seed)
    learner = StageSixLearner(compiled.genesis, seed=seed, name=STAGE6)

    def work() -> dict[str, int]:
        run_endurance(compiled, [learner])
        return {name: row[0] for name, row in learner.stores().items()}

    events = sum(1 for m in compiled.months for e in m.events if e.capsule is not None)
    # The trusted state IS the model the endpoint scores with: its canonical bytes.
    report = measure_stage6_resources(
        work, events=events, model_bytes=lambda: learner.trusted_state().byte_size())
    return {"incremental_rss_bytes": report.incremental_rss_bytes,
            "within_ceiling": report.within_ceiling,
            "profile_within_target": report.profile.within_target,
            "profile_exceeded": list(report.profile.exceeded),
            "profile_unmeasured": list(report.profile.unmeasured),
            "peak_rss_bytes": report.metrics.peak_rss_bytes,
            "cpu_seconds": report.metrics.cpu_seconds, "events": events,
            "model_bytes": learner.trusted_state().byte_size(),
            "consolidator": {"runs": learner.consolidator.stats().runs,
                             "deferred": learner.consolidator.stats().deferred},
            "budget_bytes": budget_bytes(report.store_bytes), "loadavg": list(report.loadavg)}


def _measure_in_subprocess(ctx: Stage6GateContext) -> dict[str, Any] | None:
    command = [sys.executable, "-m", "pocketsec.stage6.cli", "--json", "resources",
               "--sessions-per-month", str(ctx.sessions_per_month), "--seed", str(ctx.seed)]
    done = subprocess.run(command, capture_output=True, text=True, cwd=REPO_ROOT, check=False,
                          timeout=1800)
    if done.returncode != 0:
        return None
    try:
        parsed: dict[str, Any] = json.loads(done.stdout)
    except json.JSONDecodeError:
        return None
    return parsed


def _over_budget(points: Sequence[MonthCheckpoint]) -> list[str]:
    limits = {b.name: b.normal_bytes for b in STORE_BUDGETS}
    over = []
    for p in points:
        for row, size in budget_bytes(p.store_bytes).items():
            if row not in limits or size > limits[row]:
                over.append(f"M{p.month:02d} {row} {size} B > {limits.get(row)}")
    return over


def check_resource_envelope(ctx: Stage6GateContext) -> GateCheck:
    """G6.10 — endpoint adaptation stays within the Stage 0 resource envelope."""
    measured = _measure_in_subprocess(ctx)
    points = _stage6_points(ctx)
    over = _over_budget(points)
    deferred = ctx.stage6.counters["consolidation_deferred"]
    cons = ctx.stage6.consolidator.stats()
    unscored = [p.month for p, m in zip(points, ctx.compiled.months, strict=True)
                if len(p.scores) != len(m.eval_steps)]
    rss = None if measured is None else measured["incremental_rss_bytes"]
    within = None if measured is None else measured["within_ceiling"]
    profile = None if measured is None else measured["profile_within_target"]
    passed = (within is True and profile is True and not over and deferred >= 1
              and not unscored)
    peaks = {row: max(budget_bytes(p.store_bytes)[row] for p in points) for row in BUDGET_STORES}
    return GateCheck(
        "G6.10", "Endpoint adaptation stays within the Stage 0 resource envelope", passed,
        f"fresh-process 12-month Stage 6 loop: incremental RSS {rss} B (ceiling 104857600, "
        f"normal target 57671680; within_ceiling {within}); edge profile within_target "
        f"{profile} (exceeded {None if measured is None else measured['profile_exceeded']}); "
        f"peak §39 row bytes over the run {peaks}; checkpoints over their normal budget "
        f"{over[:4]}; M11 deferred consolidations {deferred} (consolidator runs {cons.runs}, "
        f"not due {cons.not_due}, deferred {cons.deferred}: the §40 deferral fires only if a "
        f"consolidation falls due in M11); months with unscored sessions "
        f"{unscored}; loadavg {None if measured is None else measured['loadavg']}. Dev-host "
        "in-process figure, not a 2 GB device (§6.1); RSS UNMEASURED fails",
    )


# --- G6.12 ------------------------------------------------------------------------------


def _plateau(points: Sequence[MonthCheckpoint]) -> list[str]:
    mid = [p for p in points if 25 <= p.month <= 36]
    late = [p for p in points if 49 <= p.month <= 60]
    if not mid or not late:
        return ["NOT MEASURABLE: the run is shorter than 60 months"]
    grew = []
    for store in STORE_CAPS:
        for field in ("store_bytes", "store_counts"):
            a = max(getattr(p, field).get(store, 0) for p in mid)
            b = max(getattr(p, field).get(store, 0) for p in late)
            if b > a:
                grew.append(f"{store}.{field} {a} -> {b}")
    return grew


def check_bounded_growth(ctx: Stage6GateContext) -> GateCheck:
    """G6.12 — knowledge growth is bounded over month/year simulation."""
    points = ctx.year.for_learner(STAGE6)
    violations = [f"M{p.month:02d} {v}" for p in points for v in store_violations(p)]
    bound, silent = [], []
    for store, (byte_cap, count_cap) in STORE_CAPS.items():
        hit = any((count_cap is not None and p.store_counts.get(store, 0) >= count_cap)
                  or (byte_cap is not None and p.store_bytes.get(store, 0) >= byte_cap)
                  for p in points)
        if hit:
            bound.append(store)
            if not points or points[-1].evictions.get(store, 0) <= 0:
                silent.append(store)
    grew = _plateau(points)
    nodes = max((p.store_counts.get("lineage", 0) for p in points), default=0)
    fossils = ctx.year_learner.fossils
    tombstoned = len(fossils.tombstones()) >= min(fossils.evictions(), 1)
    passed = (bool(points) and not violations and not silent and not grew
              and nodes <= MAX_LINEAGE_NODES and tombstoned)
    last = points[-1] if points else None
    return GateCheck(
        "G6.12", "Knowledge growth is bounded over month/year simulation", passed,
        f"{len(points)} months; cap violations {violations[:4]}; stores whose cap bound "
        f"{bound}, of which evicted nothing {silent}; growth from months 25-36 to 49-60 "
        f"{grew}; max lineage nodes {nodes} (cap {MAX_LINEAGE_NODES}); fossil evictions "
        f"{fossils.evictions()} with tombstones {len(fossils.tombstones())}; final counts "
        f"{None if last is None else dict(last.store_counts)}. The plateau is caps binding on a "
        "repeating synthetic year (§6.1)",
    )


# --- G6.13 ------------------------------------------------------------------------------


def _final_f1(points: Sequence[MonthCheckpoint]) -> float | None:
    for p in reversed(points):
        if p.retention.get("F1") is not None:
            return p.retention["F1"]
    return None


def _anti_forgetting(ctx: Stage6GateContext) -> tuple[list[str], list[str]]:
    rows, unmeasured = [], []
    for budget in REPLAY_BUDGETS_BYTES:
        mine = _final_f1(ctx.budget_runs.for_learner(f"stage6-rehearsal-{budget}"))
        theirs = _final_f1(ctx.endurance.for_learner(f"reservoir-{budget}"))
        rows.append(f"F1 retention at {budget} B: stage6 {mine} vs reservoir {theirs}")
        if mine is None or theirs is None:
            unmeasured.append(f"replay budget {budget}")
    for capacity in CAPACITY_SWEEP:
        naive = _final_f1(ctx.endurance.for_learner(f"naive-cap{capacity}"))
        rows.append(f"capacity {capacity}: naive {naive}, stage6 "
                    f"{'UNMEASURED' if capacity != CAPACITY_SWEEP[-1] else 'as run'}")
        if capacity != CAPACITY_SWEEP[-1]:
            unmeasured.append(f"stage6 at capacity {capacity}")
    return rows, unmeasured


def _document_problems() -> list[str]:
    if not FINDINGS_PATH.is_file():
        return [f"{FINDINGS_PATH.relative_to(REPO_ROOT)} does not exist"]
    text = FINDINGS_PATH.read_text(encoding="utf-8")
    problems = [f"missing heading {h!r}" for h in _LEDGER_HEADINGS if h not in text]
    for paragraph in re.split(r"\n\s*\n", text):
        lines = paragraph.splitlines()
        for i, line in enumerate(lines):
            window = "\n".join(lines[max(0, i - 3): i + 4])
            if (_NOVELTY.search(line) and _CONSTRUCTS.search(window)
                    and "no novelty claim" not in paragraph.lower()):
                problems.append(f"novelty word near a construct name: {line.strip()[:80]}")
    return problems


def _ablation_problems(ctx: Stage6GateContext) -> tuple[list[str], list[str]]:
    by_id = {row.core_id: row for row in ctx.ablation}
    rows, problems = [], []
    for function in STAGE6_FUNCTIONS:
        if function.function_class is not FunctionClass.OPTIONAL:
            continue
        row = by_id.get(function.core_id)
        if row is None:
            problems.append(f"{function.core_id}: no ablation row")
            continue
        rows.append(f"{row.core_id} {row.flag} delta {row.delta} firing {row.firing_count} "
                    f"{row.verdict}")
        if row.delta is None or row.firing_count <= 0 or row.verdict not in VERDICTS:
            problems.append(f"{row.core_id} {row.verdict}")
    return rows, problems


def check_ablation_survival(ctx: Stage6GateContext) -> GateCheck:
    """G6.13 — every advanced mechanism survives ablation against simpler baselines."""
    from pocketsec.stage6.gate import registry_digest

    precondition = ctx.preconditions.verdict
    rows, problems = _ablation_problems(ctx)
    forgetting, unmeasured = _anti_forgetting(ctx)
    ledger_same = registry_digest() == ctx.registry_before
    documents = _document_problems()
    hypotheses = set(HYPOTHESES) == {f"H{n}" for n in range(9)}
    synthetic = ctx.endurance.synthetic
    passed = (precondition == "OK" and not problems and not unmeasured and ledger_same
              and not documents and hypotheses and synthetic is False)
    return GateCheck(
        "G6.13", "Every advanced mechanism survives ablation against simpler baselines", passed,
        f"preconditions E1-E5 {precondition}; OPTIONAL rows: {'; '.join(rows)}; rows without "
        f"a measured non-None delta and firing > 0: {problems}; anti-forgetting: "
        f"{'; '.join(forgetting)}; UNMEASURED points {unmeasured}; registry byte-identical "
        f"{ledger_same}; findings document problems {documents}; HYPOTHESES == H0..H8 "
        f"{hypotheses}; synthetic {synthetic} (PASS requires a non-synthetic run: FAILS BY "
        f"CONSTRUCTION on this corpus, spec §6.1). loadavg {loadavg()}",
    )
