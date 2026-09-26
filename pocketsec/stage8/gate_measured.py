"""The Stage 8 gate's measured criteria: G8.11 (lightweight deployment) and G8.12 (baselines).

G8.11 reads the runaway-flood run, the long-lived endurance run and the endpoint footprint of
every shipped artifact; an RSS figure that could not be read is UNMEASURED and FAILS, never
"within target". G8.12 reads every comparison of spec §7 from the gate's one set of runs and
turns each into a verdict that can go against Stage 8. It **fails by construction on
synthetic data** (spec §6.1): its PASS additionally requires ``synthetic_data is False``, and
every corpus here is synthetic and shares an author with the engine (lesson 6). The
comparisons are still run, recorded and given verdicts; a mechanism that loses here has no
evidence for it at all, and the findings recommend removing it.

Wall clock and ``/proc/loadavg`` are recorded beside every timing and never asserted.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from pocketsec.stage0.gate import REPO_ROOT, GateCheck
from pocketsec.stage0.hypotheses import HYPOTHESES
from pocketsec.stage8.core_ids import optional_functions
from pocketsec.stage8.ecology.lineage import MAX_LINEAGE_NODES
from pocketsec.stage8.forge.tournament import (
    ENDPOINT_ARTIFACT_MAX_BYTES,
    STAGE8_ENDPOINT_INCREMENTAL_CEILING_BYTES,
)
from pocketsec.stage8.gate_evidence import degenerate
from pocketsec.stage8.labs.baselines import DIRECT_MODEL_RECALL_SLACK, ComponentVerdict
from pocketsec.stage8.labs.eighty_experiments import catalogue_problems
from pocketsec.stage8.ledger.theory import MAX_LEDGER_ENTRIES, MAX_THEORIES

if TYPE_CHECKING:
    from pocketsec.stage8.gate import Stage8GateContext

__all__ = [
    "ADR_BLOCK",
    "FINDINGS_PATH",
    "HONESTY_HEADINGS",
    "check_g8_11",
    "check_g8_12",
    "findings_headings_missing",
    "missing_adrs",
]

FINDINGS_PATH = REPO_ROOT / "docs" / "stage-8-findings.md"
ADR_DIR = REPO_ROOT / "docs" / "adr"
ADR_BLOCK = tuple(range(70, 80))
HONESTY_HEADINGS = ("### MEASURED", "### UNMEASURED", "### REJECTED", "### RETRACTED",
                    "### NOT A DETECTION RESULT", "### PARAMETERS")


# --- G8.11 ------------------------------------------------------------------------------------


def _flood(ctx: Stage8GateContext) -> tuple[bool, str]:
    run = ctx.flood
    if run is None or run.ledger is None or run.lineage is None:
        return False, "(a) flood run did not complete"
    ledger, lineage = run.ledger.stats(), run.lineage.stats()
    within = (ledger.get("theories", 0) <= MAX_THEORIES
              and ledger.get("entries", 0) <= MAX_LEDGER_ENTRIES + 1
              and lineage.get("nodes", 0) <= MAX_LINEAGE_NODES)
    external = sum(g.external_refused for g in run.generation)
    governor = sum(n for _, n in run.governor.refusals_by_bound)
    ok = run.budget_exhausted and within and external > 0 and governor > 0
    return ok, (f"(a) flood of {run.config.external_texts.__len__()} texts under "
                f"{run.governor.budget.work_units} units: budget_exhausted "
                f"{run.budget_exhausted}, spent {run.governor.spent}, stores within caps {within} "
                f"(theories {ledger.get('theories')}, entries {ledger.get('entries')}, lineage "
                f"nodes {lineage.get('nodes')}), external texts refused {external}, governor "
                f"refusals {dict(run.governor.refusals_by_bound)}")


def _endurance(ctx: Stage8GateContext) -> tuple[bool, str]:
    report = ctx.endurance
    if report is None:
        return False, "(b) endurance did not complete"
    ok = report.plateau_ok and report.cycles_completed == report.cycles
    finals = {name: sizes[-1] if sizes else None for name, sizes in report.store_sizes}
    return ok, (f"(b) endurance {report.cycles_completed}/{report.cycles} cycles, plateau_ok "
                f"{report.plateau_ok}, problems {list(report.problems)}, final store sizes "
                f"{finals}, packages {report.packages}, capsules created/admitted "
                f"{report.capsules_created}/{report.capsules_admitted}, research RSS start "
                f"{report.rss_start} B sampled peak {report.rss_peak} B (research side, not the "
                f"endpoint), wall {report.wall_seconds:.1f} s at loadavg {report.loadavg}")


def _deployed(ctx: Stage8GateContext) -> tuple[bool, str]:
    run, footprint, profile = ctx.main, ctx.footprint, ctx.footprint_profile
    if run is None or footprint is None:
        return False, "(c) no footprint measured"
    sizes = [p.resource_profile.artifact_bytes for p in run.packages
             if p.selected_representation is not None]
    oversize = [s for s in sizes if s is None or s > ENDPOINT_ARTIFACT_MAX_BYTES]
    tournaments = [p.detector_candidates for p in run.packages]
    ok = (footprint.detectors > 0 and footprint.within_ceiling is True and not oversize)
    ceiling = STAGE8_ENDPOINT_INCREMENTAL_CEILING_BYTES
    verdict = {True: "within", False: "OVER", None: "UNMEASURED"}[footprint.within_ceiling]
    vacuous = "" if footprint.detectors else " (VACUOUS)"
    return ok, (
        f"(c) shipped detectors {footprint.detectors}{vacuous}, artifact bytes {sizes} "
        f"(max {ENDPOINT_ARTIFACT_MAX_BYTES}); endpoint incremental "
        f"RSS {footprint.incremental_rss_bytes} B vs ceiling {ceiling} B: {verdict}; "
        f"{footprint.events} events, {footprint.work_units_per_event} wu/event, wall "
        f"{footprint.wall_seconds:.4f} s at loadavg {footprint.loadavg}; whole gate process vs "
        f"the edge profile (recorded, not asserted; includes research state): "
        f"{None if profile is None else profile.to_dict()}; DCR "
        f"{[t.compression_ratio for t in tournaments]}, knowledge_bytes_saved "
        f"{[t.knowledge_bytes_saved for t in tournaments]}")


def check_g8_11(ctx: Stage8GateContext) -> GateCheck:
    """Research cost may be high offline; deployed intelligence stays lightweight (G8.11)."""
    title = ("Research cost is allowed to be high offline; deployed intelligence remains "
             "lightweight")
    parts = [_flood(ctx), _endurance(ctx), _deployed(ctx)]
    return GateCheck("G8.11", title, all(ok for ok, _ in parts),
                     "; ".join(text for _, text in parts) + ". In-process on the dev host; "
                     "device figures on a real 2 GB endpoint are UNMEASURED")


# --- G8.12 ------------------------------------------------------------------------------------


def missing_adrs() -> list[str]:
    """ADR-0070 … ADR-0079: every number in the Stage 8 block must be a file (lesson 10)."""
    names = [p.name for p in ADR_DIR.glob("*.md")] if ADR_DIR.is_dir() else []
    return [f"ADR-{n:04d}" for n in ADR_BLOCK
            if not any(re.match(rf"^{n:04d}-", name) for name in names)]


def findings_headings_missing() -> list[str]:
    if not FINDINGS_PATH.is_file():
        return list(HONESTY_HEADINGS)
    lines = {line.strip() for line in FINDINGS_PATH.read_text(encoding="utf-8").splitlines()}
    return [h for h in HONESTY_HEADINGS if h not in lines]


def _forge_vs_direct(ctx: Stage8GateContext) -> tuple[bool | None, str]:
    """§7: the selected representation's REPLICATION recall >= direct - 0.02 at ≤ its FPR,
    and fewer work units per event. None = unmeasurable (no selected package or no model)."""
    run, direct = ctx.main, ctx.direct
    if run is None or direct is None or direct.replication_recall is None:
        return None, "FORGE vs direct model: UNMEASURED (no direct-model fit)"
    rows = []
    for package in run.packages:
        result = package.detector_candidates
        chosen = next((m for m in result.entrants if m.kind is result.selected), None)
        if chosen is None or chosen.recall is None:
            continue
        fpr_ok = (chosen.false_positive_rate is not None
                  and direct.replication_false_positive_rate is not None
                  and chosen.false_positive_rate <= direct.replication_false_positive_rate)
        cheaper = (chosen.work_units_per_event is not None
                   and direct.work_units_per_event is not None
                   and chosen.work_units_per_event < direct.work_units_per_event)
        wins = (chosen.recall >= direct.replication_recall - DIRECT_MODEL_RECALL_SLACK
                and fpr_ok and cheaper)
        rows.append((chosen.kind.value, chosen.recall, chosen.false_positive_rate,
                     chosen.work_units_per_event, wins))
    if not rows:
        return None, "FORGE vs direct model: UNMEASURED (no package selected a representation)"
    return all(r[-1] for r in rows), (
        f"FORGE vs direct model (recall {direct.replication_recall}, FPR "
        f"{direct.replication_false_positive_rate}, {direct.work_units_per_event} wu/event): "
        f"selected (kind, recall, FPR, wu/event, wins) {rows}")


def _ablation(ctx: Stage8GateContext) -> tuple[list[str], dict[str, str]]:
    rows = {row.flag: row for row in ctx.ablation}
    wanted = sorted({flag for f in optional_functions() for flag in f.ablation_flags})
    missing = [flag for flag in wanted if flag not in rows]
    verdicts = {flag: f"{row.verdict.value}(fired {row.firings}, changed {row.outcome_changes})"
                for flag, row in rows.items()}
    return missing, verdicts


def _discipline(ctx: Stage8GateContext) -> tuple[bool, str]:
    """NAIVE vs disciplined on PLANTED: is the trap refuted only with the discipline?"""
    main, naive = ctx.main, ctx.naive
    if main is None or naive is None:
        return False, "trap discipline control: UNMEASURED"
    naive_took = naive.trap.hypothesis_id is not None and naive.trap.hypothesis_id in naive.survived
    only_with = main.trap.refuted and naive_took
    return only_with, (f"PLANTED trap refuted with discipline {main.trap.refuted}; selected by "
                       f"the NAIVE control {naive_took} (NAIVE selected {len(naive.survived)})")


def _verdicts(ctx: Stage8GateContext) -> tuple[list[str], list[str]]:
    """(texts, verdicts that do not justify the mechanism)."""
    texts: list[str] = []
    against: list[str] = []
    search, gain, null, oracle = ctx.search, ctx.gain, ctx.null, ctx.oracle_cmp
    if search is None:
        against.append("search: UNMEASURED")
    else:
        texts.append(f"search {search.verdict.value}: " + ", ".join(
            f"{a.arm} recovered {a.planted_recovered} families {list(a.families)} false "
            f"{a.false_reproduced} wu {a.work_units} exhausted {a.budget_exhausted}"
            for a in search.arms) + f"; beats random {search.beats_random}; beyond exhaustive "
            f"{list(search.beyond_exhaustive)}")
        if search.verdict is not ComponentVerdict.JUSTIFIED:
            against.append(f"search {search.verdict.value}")
    if gain is None:
        against.append("residual gain: UNMEASURED")
    else:
        texts.append(f"residual gain over the Φ-oracle ({gain.label}): Φ missed "
                     f"{gain.phi_missed_positives}, packages caught {gain.caught_by_packages}, "
                     f"recall Φ {gain.phi_recall} -> Φ OR packages {gain.combined_recall}, FPR "
                     f"{gain.phi_false_positive_rate} -> {gain.combined_false_positive_rate}, "
                     f"beats Φ {gain.beats_phi}")
        if not gain.beats_phi:
            against.append("discovery vs Φ-oracle NOT_YET_JUSTIFIED")
    if null is None:
        against.append("null FDR: UNMEASURED")
    else:
        texts.append(f"null FDR {null.verdict.value} over {len(null.rows)} label seeds: "
                     f"disciplined mean reproduced {null.disciplined_mean_reproduced:.3f} "
                     f"(share with any {null.disciplined_any_share:.3f}), NAIVE mean selected "
                     f"{null.naive_mean_selected:.3f} (share {null.naive_any_share:.3f})")
        if null.verdict is not ComponentVerdict.JUSTIFIED:
            against.append(f"null FDR {null.verdict.value}")
    if oracle is None:
        against.append("ORACLE: UNMEASURED")
    else:
        texts.append(f"ORACLE {oracle.verdict.value}: EIG beats cheap {oracle.eig_beats_cheap}")
        if oracle.verdict is not ComponentVerdict.JUSTIFIED:
            against.append(f"ORACLE {oracle.verdict.value}")
    return texts, against


def check_g8_12(ctx: Stage8GateContext) -> GateCheck:
    """Advanced mechanisms beat or justify themselves against simpler baselines (G8.12)."""
    title = "Advanced mechanisms beat or justify themselves against simpler baselines"
    planted_problems = degenerate(ctx, "PLANTED")
    arms = {arm: list(r.problems) for arm, r in ctx.preconditions.items()}
    texts, against = _verdicts(ctx)
    trap_ok, trap_text = _discipline(ctx)
    forge_ok, forge_text = _forge_vs_direct(ctx)
    missing_rows, ablation = _ablation(ctx)
    weak = sorted(f for f, v in ablation.items()
                  if not v.startswith(ComponentVerdict.JUSTIFIED.value))
    decides = sorted({f"{r.parameter}={r.value}" for r in ctx.sensitivity if r.flag})
    catalogue = catalogue_problems()
    registry_same = ctx.registry_before == ctx.registry_now()
    headings, adrs = findings_headings_missing(), missing_adrs()
    hypotheses_ok = set(HYPOTHESES) == {f"H{n}" for n in range(9)}
    synthetic = all(r.synthetic_data for r in ctx.reports()) if ctx.reports() else True
    structural = (not planted_problems and not missing_rows and bool(ctx.sensitivity)
                  and not catalogue and registry_same and not headings and not adrs
                  and hypotheses_ok)
    justified = not against and trap_ok and forge_ok is True and not weak
    passed = structural and justified and not synthetic
    return GateCheck("G8.12", title, passed, (
        f"FAILS BY CONSTRUCTION: synthetic_data {synthetic} (PASS requires False, spec §6.1). "
        f"Preconditions per arm {arms}; " + "; ".join(texts) + f"; {trap_text}; {forge_text}; "
        f"ablation rows {len(ctx.ablation)} (missing OPTIONAL flags {missing_rows}): "
        f"{ablation}; threshold_sensitivity rows {len(ctx.sensitivity)}, THRESHOLD_DECIDES "
        f"{decides}; catalogue problems {len(catalogue)} {list(catalogue[:2])}; "
        f"registry.jsonl byte-identical {registry_same}; findings headings missing {headings}; "
        f"ADRs missing {adrs}; HYPOTHESES == H0..H8 {hypotheses_ok}. Not justified here: "
        f"{against + [f'ablation:{w}' for w in weak] or 'none'}"))

