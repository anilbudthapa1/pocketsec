"""The ten Stage 9 acceptance checks (spec §6), each read off one built gate context.

A check never runs a lab: the build steps did that (``gate_build``, ``gate_labs``). A check
decides its criterion from what was stored, and when an input it needs is missing it FAILS
and names the step error. Three rules hold throughout, from spec §6 and the lead's orders:

* a check over zero objects is VACUOUS, and VACUOUS is FAILED;
* an unmeasured figure is ``None`` and never counts as met;
* G9.1 and G9.4 fail by construction here (Stage 8's hand-designed baseline and a 2 GB
  reference machine are both absent), and say so rather than being re-worded into passes.
"""

from __future__ import annotations

import ast
from collections import Counter
from collections.abc import Callable

from pocketsec.stage0.gate import REPO_ROOT, GateCheck
from pocketsec.stage9.argus.adversary import LIFECYCLE_ATTACKS, ArgusSurface, coverage
from pocketsec.stage9.core_ids import flag_value, optional_flags
from pocketsec.stage9.foundry.promotion import (
    PROMOTION_MIN_RUNS,
    UNIQUE_CONTRIBUTION_MIN,
    PromotionVerdict,
)
from pocketsec.stage9.gate_build import PHI
from pocketsec.stage9.gate_state import Stage9GateContext, SuccessorEvidence
from pocketsec.stage9.genome.expressibility import phi_oracle_genome
from pocketsec.stage9.laplace.state_discovery import PRECISION_LEVELS
from pocketsec.stage9.observatory.convergence import LawStatus
from pocketsec.stage9.ontogenesis.search import NullVerdict
from pocketsec.stage9.renormalization.laboratory import CoarseGraining
from pocketsec.stage9.runtime.homeostatic import REGIME_ORDER, CoverageVector, Regime
from pocketsec.stage9.spec.mssc import (
    BeatVerdict,
    MechanismVerdict,
    beats,
    check_constraints,
    pareto_front,
)
from pocketsec.stage9.successor import boundary

__all__ = ["FINDINGS_HEADINGS", "FINDINGS_PATH", "all_checks", "bucket_readers"]

FINDINGS_PATH = REPO_ROOT / "docs" / "stage-9-findings.md"
#: Integration plan §7: every findings document ends with this honesty ledger.
FINDINGS_HEADINGS = (
    "## Honesty ledger",
    "### MEASURED",
    "### UNMEASURED",
    "### REJECTED",
    "### RETRACTED",
    "### NOT A DETECTION RESULT",
)
#: G9.10(b): the two Φ-oracle figures must agree to this (spec §6).
_ISOLATION_TOLERANCE = 1e-12
#: Spec §8.3: a winner's train-vs-held-out worst-case gap above this is overfitting.
_GAP_FALSIFIER = 0.10


def _fail_if_missing(
    ctx: Stage9GateContext, check_id: str, title: str, *steps: str
) -> GateCheck | None:
    """A FAILED check naming the refusal or the first failed step this check reads."""
    if ctx.refused:
        return GateCheck(check_id, title, False, f"context refused to build: {ctx.refused}")
    broken = [f"{s}: {ctx.errors[s]}" for s in steps if s in ctx.errors]
    if broken:
        return GateCheck(check_id, title, False, "a gate step failed; " + "; ".join(broken))
    return None


def _f(value: float | None) -> str:
    return "None" if value is None else f"{value:.4f}"


# --- G9.1 --------------------------------------------------------------------------------------


def _preconditions(ctx: Stage9GateContext) -> dict[str, bool]:
    rows = {row.target: row for row in ctx.expressibility}
    exact = all(
        rows.get(t) is not None and rows[t].exact is True
        for t in ("phi-oracle-squashed", "phi-oracle-raw")
    )
    headroom = ctx.saturation.get("headroom")
    contamination = ctx.contamination
    return {
        "(a) phi-oracle exact in the IR": exact,
        "(b) count-240 held-out not degenerate": headroom is not None and not headroom.degenerate,
        "(c) shuffled-label null not LEAK_SUSPECTED": ctx.shuffled is not None
        and ctx.shuffled.verdict is not NullVerdict.LEAK_SUSPECTED,
        "(d) 0 train/held-out overlap": contamination is not None
        and contamination.overlapping_sample_ids == 0
        and contamination.overlapping_content == 0,
    }


def _beat_rows(ctx: Stage9GateContext) -> tuple[str, list[tuple[str, str, BeatVerdict]]]:
    """Each winner against the strongest hand rule; ``identity`` names a winner that IS a
    hand baseline (a rediscovery beats nothing that already exists)."""
    held = ctx.heldout
    strongest = max(ctx.hand_heldout, key=lambda n: ctx.hand_heldout[n].worst_case_ap or -1.0)
    baseline = ctx.hand_heldout[strongest].objective()
    by_digest = {genome.digest: name for name, genome in ctx.hand.items()}
    rows = []
    for digest, (_, _, record) in ctx.winners.items():
        verdict = check_constraints(
            record.objective(), clean_ap=record.clean_ap, base_rate=held.base_rate if held else 0.0
        )
        beat = beats(record.objective(), baseline, candidate_ok=verdict.violations == ())
        rows.append((digest[:19], by_digest.get(digest, ""), beat))
    return strongest, rows


def _falsifier_1(rows: list[tuple[str, str, BeatVerdict]]) -> str:
    novel = [(d, v) for d, identity, v in rows if not identity]
    literal = any(v.beats for _, _, v in rows)
    fires = not any(v.beats for _, v in novel)
    return (
        f"§8 falsifier 1 {'FIRES' if fires else 'does not fire'}: "
        f"{'no' if fires else 'a'} search winner that is NOT itself a hand baseline beats the "
        f"strongest hand rule ({len(novel)} such winners); literal spec reading, rediscoveries "
        f"included: {'a winner beats it' if literal else 'no winner beats it'}"
    )


def _pareto_text(ctx: Stage9GateContext) -> str:
    points = [(name, r.objective()) for name, r in ctx.hand_heldout.items()]
    points += [(d[:19], rec.objective()) for d, (_, _, rec) in ctx.winners.items()]
    front = pareto_front(points)
    placed = ", ".join(
        f"{n} (AP {_f(v.worst_case_ap)}, {v.wu_per_event} WU/ev, "
        f"{v.state_bytes} B){' *' if n in front else ''}"
        for n, v in points
    )
    tcn, reason = ctx.tcn_point
    tcn_text = (
        "UNMEASURED"
        if tcn is None
        else (
            f"AP {_f(tcn.worst_case_ap)} (clean, count 60), {tcn.wu_per_event} WU/ev analytic, "
            f"{tcn.state_bytes} B analytic lower bound"
        )
    )
    return (
        f"held-out count-240 Pareto (* = on the front): {placed}. Count-60 (saturated, "
        f"the trap): Φ-oracle AP {_f(ctx.saturated_phi_ap)}; TCN {tcn_text} ({reason})"
    )


def check_g9_1(ctx: Stage9GateContext) -> GateCheck:
    """G9.1 — blocked on Stage 8; the rebound comparison is measured and carried."""
    title = "A Stage-9 computation beats the strongest Stage-8 hand-designed baseline"
    missing = _fail_if_missing(ctx, "G9.1", title, "references", "expressibility", "comparisons")
    if missing is not None:
        return missing
    pre = _preconditions(ctx)
    strongest, rows = _beat_rows(ctx)
    winners = [
        f"{d}{f' (IS the {i} genome, rediscovered)' if i else ''}: "
        f"{'BEATS' if v.beats else 'does not beat'} ({v.detail})"
        for d, i, v in rows
    ]
    gaps = [f"{r.run} {_f(r.gap)}" for r in ctx.reports if r.genome_digest]
    return GateCheck(
        "G9.1",
        title,
        False,
        (
            "BLOCKED_ON_STAGE8: the criterion names Stage 8's hand-designed baseline; Stage 8's "
            "named interface (docs/stage-8-spec.md §3.3, DiscoveryPackageV1) carries none Stage 9 "
            "may consume and Stage 9 imports nothing from Stage 8 (ADR-0087). Rebound comparison "
            f"against {{Φ-oracle, H1, H2}}: pre-conditions {pre}; strongest hand baseline on "
            f"held-out worst-case AP = {strongest}; winners: {winners or 'NONE'}; "
            f"{_falsifier_1(rows)}. Train-vs-"
            f"held-out worst-case gap per run winner: {gaps or 'no winners'} (falsifier 3 at > "
            f"{_GAP_FALSIFIER}). {_pareto_text(ctx)}"
        ),
    )


# --- G9.2 --------------------------------------------------------------------------------------


def check_g9_2(ctx: Stage9GateContext) -> GateCheck:
    """G9.2 — every PROMOTED primitive reproduced and ablated; no law promoted on a None."""
    title = "Every promoted primitive/law has independent-run reproduction and ablation evidence"
    missing = _fail_if_missing(ctx, "G9.2", title, "search", "laws")
    if missing is not None:
        return missing
    verdicts = Counter(d.verdict.value for d in ctx.promotions)
    promoted = [d for d in ctx.promotions if d.verdict is PromotionVerdict.PROMOTED]
    unsupported = [
        d.candidate.canonical
        for d in promoted
        if d.candidate.runs_containing < PROMOTION_MIN_RUNS
        or d.candidate.unique_contribution is None
        or d.candidate.unique_contribution < UNIQUE_CONTRIBUTION_MIN
    ]
    laws = [
        law
        for law in ctx.laws
        if law.status is LawStatus.CANDIDATE_LAW and any(c is None for c in law.criteria())
    ]
    statuses = Counter(law.status.value for law in ctx.laws)
    detail = (
        f"{ctx.candidates_examined} candidate subgraphs examined over "
        f"{len(ctx.runs.get('evolutionary', ()))} main-arm runs; decisions "
        f"{dict(verdicts) or 'none'}; PROMOTED without reproduction/ablation "
        f"{unsupported or 'none'}; law statuses {dict(statuses) or 'none'} (0 laws can be "
        f"promoted: cross_host is None on one synthetic host); convergence "
        f"{ctx.lab_notes.get('convergence', 'not measured')}"
    )
    if ctx.candidates_examined == 0:
        return GateCheck(
            "G9.2",
            title,
            False,
            f"VACUOUS: no candidate subgraph was examined, so nothing was tested. {detail}",
        )
    return GateCheck("G9.2", title, not unsupported and not laws, detail)


# --- G9.3 --------------------------------------------------------------------------------------


def check_g9_3(ctx: Stage9GateContext) -> GateCheck:
    """G9.3 — every abstraction (spec §6's list) has both tests, with pairs > 0."""
    title = "Every abstraction has semantic-conservation and counterfactual tests"
    missing = _fail_if_missing(ctx, "G9.3", title, "abstractions")
    if missing is not None:
        return missing
    expected = (
        {f"coarse:{level.value}" for level in CoarseGraining}
        | {f"precision:{b}" for b in PRECISION_LEVELS if b < 64}
        | {"minimal_state"}
    )
    have = {a.name: a for a in ctx.coarsenings}
    absent = sorted(expected - set(have))
    untested = sorted(n for n, a in have.items() if a.pairs <= 0 or a.decision_agreement is None)
    lost = [f"{a.name} lost {a.lost}/{a.pairs}" for a in ctx.coarsenings if a.lost]
    rows = "; ".join(
        f"{a.name}: agreement {_f(a.decision_agreement)}, AP {_f(a.ap_before)}->"
        f"{_f(a.ap_after)}, bytes {a.bytes_before}->{a.bytes_after}, pairs "
        f"{a.distinguished_before}->{a.distinguished_after}/{a.pairs}"
        for a in ctx.coarsenings
    )
    passed = not absent and not untested and bool(ctx.coarsenings)
    return GateCheck(
        "G9.3",
        title,
        passed,
        (
            f"{len(ctx.coarsenings)} abstractions of {len(expected)} expected on the subject "
            f"genome ({ctx.subject_reason}); absent {absent or 'none'}; without both tests "
            f"{untested or 'none'}; lost a counterfactual distinction: {lost or 'none'}. {rows}"
        ),
    )


# --- G9.4 --------------------------------------------------------------------------------------


def check_g9_4(ctx: Stage9GateContext) -> GateCheck:
    """G9.4 — measured RSS/CPU AND a 2 GB reference target, for every phenotype."""
    title = "Every phenotype has measured 2 GB target-machine resource data"
    missing = _fail_if_missing(ctx, "G9.4", title, "hardware")
    if missing is not None:
        return missing
    if not ctx.measurements:
        return GateCheck("G9.4", title, False, "VACUOUS: no phenotype was measured")
    unmeasured = [
        m.genome_digest[:19]
        for m in ctx.measurements
        if m.peak_sampled_rss_bytes is None or m.cpu_seconds_per_event is None
    ]
    reference = [m.is_reference_target for m in ctx.measurements]
    rows = "; ".join(
        f"{m.genome_digest[:19]}: {m.wu_per_event} WU/ev, incremental RSS "
        f"{m.incremental_rss_bytes} B, {_f(m.ratio_to_phi_oracle)}x the direct "
        f"Φ-oracle loop, load {m.loadavg_before}->{m.loadavg_after}"
        for m in ctx.measurements
    )
    first = ctx.measurements[0]
    passed = not unmeasured and all(r is True for r in reference)
    return GateCheck(
        "G9.4",
        title,
        passed,
        (
            f"{len(ctx.measurements)} phenotypes measured on this host (MemTotal "
            f"{first.host_mem_total_bytes} B, is_reference_target "
            f"{first.is_reference_target}: NOT a 2 GB target, B9-4); RSS/CPU unmeasured for "
            f"{unmeasured or 'none'}; proxy Spearman "
            f"(WU vs wall) {ctx.proxy.spearman_wu_vs_wall if ctx.proxy else None}; timings are "
            f"host-contended ratios, not device figures. {rows}"
        ),
    )


# --- G9.5 --------------------------------------------------------------------------------------


def check_g9_5(ctx: Stage9GateContext) -> GateCheck:
    """G9.5 — every degraded decision exposes coverage, loss and uncertainty; every regime hit."""
    title = "Every resource-degradation mode exposes lost coverage and uncertainty"
    missing = _fail_if_missing(ctx, "G9.5", title, "runtime")
    if missing is not None:
        return missing
    degraded = [d for d in ctx.regime_decisions if d.regime is not Regime.ADAPTIVE]
    bad = [
        d.step
        for d in degraded
        if not isinstance(d.coverage, CoverageVector)
        or not isinstance(d.lost, tuple)
        or d.uncertainty_penalty is None
    ]
    unvisited = [r.value for r in REGIME_ORDER if ctx.transitions_into.get(r.value, 0) < 1]
    lost = sorted({(d.regime.value, d.lost) for d in degraded})
    lost_fired = sum(1 for d in degraded if d.lost)
    inert = (
        " (INERT: every catalog phenotype reads the same inputs, so the coverage-loss path "
        "never fired on this catalog)"
        if not lost_fired
        else ""
    )
    penalties = sorted(
        {(d.regime.value, d.uncertainty_penalty) for d in degraded},
        key=lambda rp: (rp[0], rp[1] if rp[1] is not None else -1.0),
    )
    if not degraded:
        return GateCheck("G9.5", title, False, "VACUOUS: the trace never left ADAPTIVE")
    return GateCheck(
        "G9.5",
        title,
        not bad and not unvisited,
        (
            f"SIMULATED degradation trace, {len(ctx.regime_decisions)} decisions, {len(degraded)} "
            f"outside ADAPTIVE; missing coverage/loss/uncertainty at steps {bad[:10] or 'none'}; "
            f"transitions into each regime {ctx.transitions_into}; unvisited {unvisited or 'none'};"
            f" lost coverage by regime {lost}; decisions with a non-empty loss {lost_fired} of "
            f"{len(degraded)}{inert}; "
            f"uncertainty penalty by regime {penalties}; coverage "
            "basis STATIC_INPUT_READ (what the phenotype reads, not measured recall)"
        ),
    )


# --- G9.6 --------------------------------------------------------------------------------------


def _successor_problems(s: SuccessorEvidence) -> list[str]:
    """Everything wrong with one successor's rollback, tampering, exit and unit checks."""
    bad: list[str] = []
    if s.restored_scores_digest != s.parent_scores_digest:
        bad.append(f"{s.genome_digest[:19]} rollback scores differ")
    if s.active_after_install != s.installed_digest or \
            s.active_after_rollback != s.parent_digest or s.restored_digest != s.parent_digest:
        bad.append(
            f"{s.genome_digest[:19]} registry active after install {s.active_after_install}"
            f", after rollback {s.active_after_rollback} (parent {s.parent_digest})"
        )
    if s.tampering.defence_failed or s.tampering.total != 4:
        bad.append(
            f"{s.genome_digest[:19]} tampering {s.tampering.fired}/{s.tampering.total} refused"
        )
    if s.offered < 1 or s.offered != s.capsules_built or len(s.verdicts) != s.offered:
        bad.append(
            f"{s.genome_digest[:19]} exit offered {s.offered}, built "
            f"{s.capsules_built}, verdicts {len(s.verdicts)}"
        )
    if not s.unit_checks_passed:
        bad.append(f"{s.genome_digest[:19]} DAEDALUS unit checks failed")
    return bad


def check_g9_6(ctx: Stage9GateContext) -> GateCheck:
    """G9.6 — install/rollback restores byte-identical scores; 4/4 tamperings refused; exit."""
    title = "Every successor is rollbackable"
    missing = _fail_if_missing(ctx, "G9.6", title, "successor")
    if missing is not None:
        return missing
    if not ctx.successors:
        return GateCheck("G9.6", title, False, "VACUOUS: no search winner, so no successor")
    bad = [problem for s in ctx.successors for problem in _successor_problems(s)]
    # S9-R5 / S9-FC-05: installing the parent and "restoring" it proves nothing, so at least
    # one rollback must be distinguishable (different genome AND different held-out scores).
    vacuous = [s.genome_digest[:19] for s in ctx.successors if not s.rollback_distinguishable]
    if len(vacuous) == len(ctx.successors):
        bad.append("every rollback is vacuous: each installed successor is, or scores as, the "
                   "parent it rolls back to")
    buckets = Counter(bucket for s in ctx.successors for _, bucket, _ in s.verdicts)
    pcb = Counter(s.pcb_expressible for s in ctx.successors)
    return GateCheck(
        "G9.6",
        title,
        not bad,
        (
            f"{len(ctx.successors)} successors; problems {bad or 'none'}; rollbacks that "
            f"cannot be told from no rollback (successor is or scores as the Φ-oracle parent) "
            f"{vacuous or 'none'}; registry active genome checked after install and after "
            f"rollback; Stage 6 verdicts "
            f"recorded verbatim by bucket {dict(buckets)} (none acted on); PCB-lowerable "
            f"{dict(pcb)}; rollback is proven in Stage 9's lab registry only: Stage 6 has "
            "no genome executor (B9-2)"
        ),
    )


# --- G9.7 --------------------------------------------------------------------------------------


def bucket_readers() -> tuple[str, ...]:
    """Stage 9 files, other than the exit, that name ``QuarantineBucket`` or read ``.bucket``:
    an outcome can only be acted on where it is read, and only the exit records it."""
    offenders: list[str] = []
    for path in boundary.stage9_modules():
        rel = path.relative_to(boundary.STAGE9_ROOT).as_posix()
        if rel == boundary.EXIT_MODULE:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            named = isinstance(node, ast.Name) and node.id == "QuarantineBucket"
            imported = isinstance(node, ast.alias) and node.name == "QuarantineBucket"
            read = isinstance(node, ast.Attribute) and node.attr == "bucket"
            if named or imported or read:
                offenders.append(f"pocketsec/stage9/{rel}:{getattr(node, 'lineno', 0)}")
    return tuple(offenders)


def _boundary_results() -> dict[str, tuple[str, ...]]:
    admit_files = boundary.admit_call_files()
    exit_label = f"pocketsec/stage9/{boundary.EXIT_MODULE}"
    return {
        "direct_stage5_imports": boundary.direct_stage5_imports(),
        "transitive_stage5_reach": boundary.transitive_stage5_reach(),
        "admit_call_sites": boundary.admit_call_sites(),
        "admit_call_files_not_exactly_the_exit": ()
        if admit_files == (exit_label,)
        else admit_files or ("(no .admit call anywhere: the exit is unwired)",),
        "stage6_writer_names": boundary.stage6_writer_names(),
        "stage6_allow_list_offenders": boundary.stage6_allow_list_offenders(),
        "authority_field_offenders": boundary.authority_field_offenders(),
        "dynamic_execution_offenders": boundary.dynamic_execution_offenders(),
        "numpy_or_research_offenders": boundary.numpy_or_research_offenders(),
        "outside_importers_of_stage9": boundary.outside_importers_of_stage9(),
        "bucket_readers": bucket_readers(),
    }


def check_g9_7(ctx: Stage9GateContext) -> GateCheck:
    """G9.7 — the boundary predicates, the bucket rule, and an untouched experiment ledger."""
    title = "All architecture-search artifacts remain outside direct production authority"
    results = _boundary_results()
    offenders = {name: found for name, found in results.items() if found}
    ledger_same = ctx.registry_before == ctx.registry_after
    passed = not offenders and ledger_same
    return GateCheck(
        "G9.7",
        title,
        passed,
        (
            f"{len(results)} AST predicates over pocketsec/stage9 (boundary.py + bucket rule); "
            f"offenders {offenders or 'none'}; experiments/registry.jsonl byte-identical "
            f"across the gate run: {ledger_same}. The declared residual (ADR-0081): gate_exit.py, "
            "successor/stage6_exit.py and the harness reach Stage 5 only through stage6.capsule.*"
        ),
    )


# --- G9.8 --------------------------------------------------------------------------------------


def check_g9_8(ctx: Stage9GateContext) -> GateCheck:
    """G9.8 — all 8 surfaces covered by non-inert findings; every DEFENCE refused every trial."""
    title = "ARGUS adversarial tests cover the ML/search/system lifecycle"
    missing = _fail_if_missing(ctx, "G9.8", title, "argus", "successor")
    if missing is not None:
        return missing
    if not ctx.findings:
        return GateCheck("G9.8", title, False, "VACUOUS: no ARGUS finding was produced")
    uncovered = sorted(s.value for s in set(ArgusSurface) - coverage(ctx.findings))
    failed = sorted({f.attack_id for f in ctx.findings if f.defence_failed})
    ran = {f.attack_id for f in ctx.findings}
    not_run = sorted(a.attack_id for a in LIFECYCLE_ATTACKS if a.attack_id not in ran)
    inert = Counter(f.attack_id for f in ctx.findings if f.inert)
    fired = Counter(f.attack_id for f in ctx.findings if not f.inert)
    # The headline is the attack-induced count (S9-FC-01): the disjunctive "died" also counts
    # genomes whose CLEAN AP is below the Φ-oracle's worst case, which no attack caused.
    attrition = [f"{label}: {a.summary()}" for label, a in ctx.attrition]
    passed = not uncovered and not failed and not not_run
    return GateCheck(
        "G9.8",
        title,
        passed,
        (
            f"{len(ctx.findings)} findings; surfaces without a non-inert finding "
            f"{uncovered or 'none'}; DEFENCE findings that did not refuse every trial "
            f"{failed or 'none'}; lifecycle attacks never run {not_run or 'none'}; "
            f"INERT (attack: genomes) {dict(inert) or 'none'}; "
            f"fired {dict(fired)}; fittest-under-attack {attrition or 'no evolutionary run'}. The "
            "attacks, the corpus and H1/H2 share an author (lesson 6)"
        ),
    )


# --- G9.9 --------------------------------------------------------------------------------------


def _flag_rows(ctx: Stage9GateContext) -> tuple[list[str], list[str]]:
    problems: list[str] = []
    rows: list[str] = []
    for core_id, flag, control in optional_flags():
        comparison, value = ctx.comparisons.get(flag), flag_value(flag)
        short = flag.split(":")[1]
        if comparison is None:
            problems.append(f"{short}: no verdict this run")
            continue
        verdict = comparison.verdict
        if verdict is MechanismVerdict.UNMEASURED:
            problems.append(f"{short}: UNMEASURED")
        if value is None or (value and verdict is not MechanismVerdict.JUSTIFIED):
            problems.append(f"{short}: reads {value} with verdict {verdict.value}")
        rows.append(
            f"{core_id} {short}={value} -> {verdict.value} (value "
            f"{_f(comparison.value)}, controls {comparison.controls} [{control}], fired "
            f"{comparison.fired}{' INERT' if comparison.inert else ''})"
        )
    return problems, rows


def check_g9_9(ctx: Stage9GateContext) -> GateCheck:
    """G9.9 — every optional flag has a measured verdict; unjustified flags read False."""
    title = "Novel physics-inspired mechanisms must beat simpler baselines or be removed"
    problems, rows = _flag_rows(ctx)
    text = FINDINGS_PATH.read_text(encoding="utf-8") if FINDINGS_PATH.is_file() else ""
    headings = [h for h in FINDINGS_HEADINGS if h not in text]
    if headings:
        problems.append(f"docs/stage-9-findings.md lacks the honesty-ledger headings {headings}")
    errors = {
        k: v for k, v in ctx.errors.items() if k in ("comparisons", "physics", "laws", "runtime")
    }
    if errors:
        problems.append(f"steps that produce verdicts failed: {errors}")
    return GateCheck(
        "G9.9",
        title,
        not problems,
        (
            f"{len(rows)} of {len(optional_flags())} flags have a verdict; problems "
            f"{problems or 'none'}. " + "; ".join(rows)
        ),
    )


# --- G9.10 -------------------------------------------------------------------------------------


def check_g9_10(ctx: Stage9GateContext) -> GateCheck:
    """G9.10 — T7, the Stage 7-9-absent subprocess, and the no-catalog SURVIVAL fallback."""
    title = "The final endpoint remains useful with Stage 7-9 networking/research absent"
    importers = boundary.earlier_stage_importers()
    iso = ctx.isolation
    agree = (
        iso is not None
        and iso.subprocess_ap is not None
        and iso.in_process_ap is not None
        and abs(iso.subprocess_ap - iso.in_process_ap) <= _ISOLATION_TOLERANCE
    )
    useful = (
        iso is not None
        and iso.subprocess_ap is not None
        and iso.base_rate is not None
        and iso.subprocess_ap > iso.base_rate
    )
    enforced = iso is not None and iso.refused_imports >= 1 and not iso.loaded
    survival = ctx.survival_digest == f"SURVIVAL:{phi_oracle_genome().digest}"
    passed = not importers and agree and useful and enforced and survival
    iso_text = (
        ctx.errors.get("isolation", "not run")
        if iso is None
        else (
            f"child AP {_f(iso.subprocess_ap)} vs in-process {_f(iso.in_process_ap)} (base rate "
            f"{_f(iso.base_rate)}), exit {iso.returncode}; {iso.detail}"
        )
    )
    return GateCheck(
        "G9.10",
        title,
        passed,
        (
            f"(a) Stage 0-6 importers of Stage 7+ {importers or 'none'}; (b) {iso_text}; agree to "
            f"1e-12 {agree}, above base rate {useful}, absence enforced {enforced}; (c) no-catalog "
            f"controller -> {ctx.survival_digest or 'not run'} (Φ-oracle SURVIVAL {survival})"
        ),
    )


_CHECKS: tuple[Callable[[Stage9GateContext], GateCheck], ...] = (
    check_g9_1,
    check_g9_2,
    check_g9_3,
    check_g9_4,
    check_g9_5,
    check_g9_6,
    check_g9_7,
    check_g9_8,
    check_g9_9,
    check_g9_10,
)


def all_checks(ctx: Stage9GateContext) -> tuple[GateCheck, ...]:
    """The ten checks, in spec order. The hand baselines key is ``PHI`` (sanity-checked)."""
    if ctx.hand_heldout and PHI not in ctx.hand_heldout:
        raise KeyError(f"the reference table lacks {PHI!r}")
    return tuple(check(ctx) for check in _CHECKS)
