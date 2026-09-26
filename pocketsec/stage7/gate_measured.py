"""G7.4-G7.8, G7.10 and G7.11 — the measured checks of the Stage 7 gate.

Every figure here comes from one ``run_byzantine_suite`` on identical pools, one campaign
simulation, the privacy attacks, the flood/scale/churn runs and the observed suite runs, all
built once by ``Stage7GateContext.build``. Three criteria are declared unmeetable on this
data before any code ran (spec §6.1) and are written to FAIL, never to pass on nothing:
G7.4 on the adaptive-Sybil arm (no identity authority exists), G7.8 (Stage 6 admits no
foreign capsule, B7-1) and G7.11 (synthetic data; PASS requires ``synthetic is False``).

Detection figures are ``counterfactual_at_boundary``: Stage 6 admits nothing foreign, so no
"gain" is realised on a host. Robustness figures are confounded: the adversary, the defence
and the ground truth share an author (lesson 6).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import TYPE_CHECKING

from pocketsec.stage0.gate import REPO_ROOT, GateCheck
from pocketsec.stage0.hypotheses import HYPOTHESES
from pocketsec.stage7.core_ids import ABLATION_FLAGS
from pocketsec.stage7.falsifier.consensus import CounterHypothesis, HypothesisStatus
from pocketsec.stage7.governor.communication import (
    STAGE7_INCREMENTAL_CEILING_BYTES,
    STAGE7_INCREMENTAL_NORMAL_BYTES,
)
from pocketsec.stage7.identity.integrity import MAX_KEYS
from pocketsec.stage7.identity.peer import MAX_PEERS
from pocketsec.stage7.labs.byzantine_suite import (
    DETECTION_GAIN_MIN,
    SUITE_ARMS,
    SYBIL_ARMS,
    BreakPoint,
    ByzantineReport,
    SuiteRow,
)
from pocketsec.stage7.labs.campaign_sim import CampaignArm
from pocketsec.stage7.labs.seventy_two_experiments import catalogue_problems
from pocketsec.stage7.labs.simulated_fleet import AdversaryArm
from pocketsec.stage7.reconstruct.partial_world import WorldStatus

if TYPE_CHECKING:
    from pocketsec.stage7.gate import Stage7GateContext

__all__ = [
    "AMPLIFICATION_BOUNDS",
    "FALSE_SYBIL_MAX",
    "FINDINGS_HEADINGS",
    "check_g7_10",
    "check_g7_11",
    "check_g7_4",
    "check_g7_5",
    "check_g7_6",
    "check_g7_7",
    "check_g7_8",
]

#: Spec §6 G7.4, verbatim: ECHO's amplification bound per Sybil arm, at every Sybil count.
AMPLIFICATION_BOUNDS = {
    AdversaryArm.SYBIL_DECLARED_ROOT.value: 1.05,
    AdversaryArm.SYBIL_FORGED_ROOTS.value: 2.0,
    AdversaryArm.SYBIL_ADAPTIVE.value: 2.0,
}
FALSE_SYBIL_MAX = 0.05  # G7.5(b)
RARE_ROLE_SLACK = 0.05  # G7.5(a)
FALSE_CAMPAIGN_MAX = 0.10  # G7.6
RAW_CONTROL_MIN_ADVANTAGE = 0.1  # G7.7(c)(d): below this the attack is not real (DEGENERATE)
DP_MIN_POINTS = 4  # G7.7(e)
FP_SLACK = 0.01  # §7 NO_SHARING row
MARGIN = 0.05  # §7 MEDIAN / ROOT_QUORUM rows
FINDINGS = REPO_ROOT / "docs" / "stage-7-findings.md"
FINDINGS_HEADINGS = ("## Honesty ledger", "### MEASURED", "### UNMEASURED", "### REJECTED",
                     "### RETRACTED", "### NOT A DETECTION RESULT")
_BYZANTINE_ARMS = tuple(a.value for a in SUITE_ARMS
                        if a not in SYBIL_ARMS and a is not AdversaryArm.NONE)


def _no_suite(check_id: str, title: str, ctx: Stage7GateContext) -> GateCheck:
    return GateCheck(check_id, title, False,
                     f"the Byzantine suite did not run: {ctx.errors.get('suite', 'unknown')}")


def _rows(report: ByzantineReport, arm: str, aggregator: str, *, lv: bool) -> list[SuiteRow]:
    return [r for r in report.rows if r.arm == arm and r.aggregator == aggregator and r.lv is lv]


def _rate(accepted: int, offered: int) -> float | None:
    return None if offered == 0 else accepted / offered


def _fmt(value: float | None) -> str:
    return "None" if value is None else f"{value:.3f}"


# --- G7.4 ---------------------------------------------------------------------------------------


def _sybil_rows(report: ByzantineReport, arm: str,
                counts: Sequence[int]) -> tuple[list[str], list[str]]:
    by_count = {r.sybils_per_root: r for r in _rows(report, arm, "ECHO", lv=False)}
    bound, failures, shown = AMPLIFICATION_BOUNDS[arm], [], []
    for count in counts:
        row = by_count.get(count)
        amp = None if row is None else row.amplification
        shown.append(f"S={count}:{_fmt(amp)}")
        if amp is None or amp > bound:
            failures.append(f"{arm} S={count} amplification {_fmt(amp)} (bound {bound})")
    return failures, shown


def _baseline_amplification(report: ByzantineReport, arm: str) -> str:
    parts = []
    for method in ("MAJORITY", "MEDIAN", "MEAN"):
        rows = sorted(_rows(report, arm, method, lv=False), key=lambda r: r.sybils_per_root)
        parts.append(f"{method} " + ",".join(_fmt(r.amplification) for r in rows))
    return "; ".join(parts)


def _break_share(points: Iterable[BreakPoint], arm: str, method: str, lv: bool) -> str:
    found = [p.share for p in points if (p.arm, p.aggregator, p.lv) == (arm, method, lv)]
    return "absent" if not found else "none in sweep" if found[0] is None else f"{found[0]:.3f}"


def check_g7_4(ctx: Stage7GateContext) -> GateCheck:
    """G7.4 — Sybil influence is bounded by provenance/dependence controls."""
    title = "Sybil influence is bounded by provenance/dependence controls"
    report = ctx.suite
    if report is None:
        return _no_suite("G7.4", title, ctx)
    failures, parts = [], []
    for arm in AMPLIFICATION_BOUNDS:
        arm_failures, shown = _sybil_rows(report, arm, ctx.config.sybil_counts)
        failures += arm_failures
        breaks = {m: _break_share(report.break_points, arm, m, False)
                  for m in ("ECHO", "MAJORITY", "MEDIAN", "MEAN")}
        parts.append(f"{arm}: ECHO amplification {' '.join(shown)}; "
                     f"{_baseline_amplification(report, arm)}; break points {breaks}")
    merges = {k.split(":", 1)[1]: n for k, n in report.firing if k.startswith("graph_merge:")}
    fired = sum(merges.values()) > 0
    detail = (f"{' | '.join(parts)}. DependenceGraph merges by kind {merges or '{}'} "
              f"(Rule C: {'fired' if fired else 'INERT'}). Failures: {failures or 'none'}. "
              f"Spec §6.1 declared the adaptive arm unmeetable: declared roots are claims and "
              f"binding them to real domains needs an identity authority stdlib cannot provide "
              f"(ADR-0064)")
    return GateCheck("G7.4", title, not failures and fired, detail)


# --- G7.5 ---------------------------------------------------------------------------------------


def check_g7_5(ctx: Stage7GateContext) -> GateCheck:
    """G7.5 — Non-IID legitimate hosts are not treated as malicious for statistical difference."""
    title = "Non-IID legitimate hosts are not treated as malicious merely for difference"
    e = ctx.non_iid
    if e is None:
        return GateCheck("G7.5", title, False,
                         f"arm NONE did not run: {ctx.errors.get('suite', 'unknown')}")
    rare = _rate(e.rare_eligible, e.rare_offered)
    majority = _rate(e.majority_eligible, e.majority_offered)
    merge_rate = _rate(e.false_merges, e.honest_pairs)
    a_ok = rare is not None and majority is not None and rare >= majority - RARE_ROLE_SLACK
    b_ok = merge_rate is not None and merge_rate <= FALSE_SYBIL_MAX
    c_ok = e.rare_trust_pairs > 0 and e.rare_trust_violations == 0
    detail = (
        f"(a) rare-role (ADMIN) honest antibodies ELIGIBLE at ADMIN receivers "
        f"{e.rare_eligible}/{e.rare_offered} = {_fmt(rare)} vs majority-role at own-role "
        f"receivers {e.majority_eligible}/{e.majority_offered} = {_fmt(majority)} (need rare >= "
        f"majority - {RARE_ROLE_SLACK}); (b) honest peers of different true roots merged into "
        f"one dependence cluster {e.false_merges}/{e.honest_pairs} = {_fmt(merge_rate)} (bound "
        f"{FALSE_SYBIL_MAX}); (c) rare-role (cluster, task) trust pairs below TRUST_PRIOR "
        f"without a local refutation {e.rare_trust_violations}/{e.rare_trust_pairs} (a "
        f"construction property, not evidence: reliability only falls below the prior on a "
        f"refutation and no runtime path calls record_outcome, so (c) cannot fail — S7-R5/F7); "
        f"rare-role "
        f"key exclusion share by {dict(e.krum_excluded)} (reported). Real rare roles UNMEASURED"
    )
    for label, n in (("(a) rare side", e.rare_offered), ("(a) majority side", e.majority_offered),
                     ("(b)", e.honest_pairs), ("(c)", e.rare_trust_pairs)):
        if n == 0:
            detail += f"; VACUOUS {label}: zero objects"
    return GateCheck("G7.5", title, a_ok and b_ok and c_ok, detail)


# --- G7.6 ---------------------------------------------------------------------------------------


def _world_problems(ctx: Stage7GateContext) -> tuple[int, list[str]]:
    supported, problems = 0, []
    for outcome in ctx.campaign_outcomes:
        for world in outcome.worlds:
            if world.status is not WorldStatus.SUPPORTED:
                continue
            supported += 1
            f = world.falsification
            if f is None or len(f.tests) != len(CounterHypothesis):
                problems.append(f"{world.world_id}: no six-test falsification")
            elif any(t.status is HypothesisStatus.UNEVALUATED for t in f.tests):
                problems.append(f"{world.world_id}: a test UNEVALUATED")
    return supported, problems


def _benign_rejections(ctx: Stage7GateContext) -> dict[str, int]:
    counts = {h.value: 0 for h in list(CounterHypothesis)[:5]}
    for outcome in ctx.campaign_outcomes:
        if outcome.is_campaign:
            continue
        for world in outcome.worlds:
            f = world.falsification
            if world.status in (WorldStatus.REJECTED_COMMON_CAUSE, WorldStatus.REJECTED_COLLUSION) \
                    and f is not None and f.explanation is not None \
                    and f.explanation.value in counts:
                counts[f.explanation.value] += 1
    return counts


def _true_recall_by_arm(ctx: Stage7GateContext) -> dict[str, float | None]:
    out = {}
    for arm in (CampaignArm.TRUE_CAMPAIGN_2, CampaignArm.TRUE_CAMPAIGN_4,
                CampaignArm.TRUE_CAMPAIGN_10):
        cases = [o for o in ctx.campaign_outcomes if o.arm is arm]
        found = sum(o.detected_after_rounds is not None for o in cases)
        out[arm.value] = _rate(found, len(cases))
    return out


def check_g7_6(ctx: Stage7GateContext) -> GateCheck:
    """G7.6 — Distributed campaigns are validated against benign common-cause hypotheses."""
    title = "Distributed campaigns are validated against benign common-cause hypotheses"
    report = ctx.campaign
    if report is None:
        return GateCheck("G7.6", title, False,
                         f"the campaign simulation did not run: {ctx.errors.get('campaign')}")
    supported, problems = _world_problems(ctx)
    rejected = _benign_rejections(ctx)
    recall = _true_recall_by_arm(ctx)
    false_rate, control = report.false_campaign_rate, report.control_false_campaign_rate
    inert = [h for h, n in rejected.items() if n == 0]
    rate_ok = (false_rate is not None and control is not None and false_rate <= control
               and false_rate <= FALSE_CAMPAIGN_MAX)
    passed = (supported > 0 and not problems and rate_ok and not inert
              and all(r is not None and r > 0 for r in recall.values()))
    detail = (
        f"{len(ctx.campaign_outcomes)} cases over {len(CampaignArm)} arms: {supported} SUPPORTED "
        f"worlds, falsification problems {problems[:3] or 'none'}; false collective campaign "
        f"rate {_fmt(false_rate)} vs count_threshold_join {_fmt(control)} (bound "
        f"{FALSE_CAMPAIGN_MAX}); true-campaign recall {recall}; benign-arm worlds explained by "
        f"{rejected} (INERT: {inert or 'none'}); suppression delay "
        f"{_fmt(report.suppression_delay_rounds)} rounds, SUPPRESSION cases never detected "
        f"{report.suppressed_never_detected}. Common causes are authored with the falsifier "
        f"(confounded); real common-cause events UNMEASURED"
    )
    return GateCheck("G7.6", title, passed, detail)


# --- G7.7 ---------------------------------------------------------------------------------------


def _field_table(ctx: Stage7GateContext) -> tuple[bool, str]:
    from pocketsec.stage7.privacy.distiller import (
        EXPORT_FIELD_TABLE,
        expected_wire_paths,
        flatten_keys,
        undeclared_wire_paths,
    )

    emitted: set[str] = set()
    bad = []
    for kind, capsule in ctx.capsule_samples.items():
        payload = capsule.to_dict()
        keys = set(flatten_keys(payload))
        emitted |= keys
        if undeclared_wire_paths(payload) or keys != expected_wire_paths(payload):
            bad.append(kind.value)
    ok = bool(ctx.capsule_samples) and not bad and emitted == set(EXPORT_FIELD_TABLE)
    return ok, (f"(b) {len(ctx.capsule_samples)} knowledge types: per-type wire paths == the "
                f"table's paths for that payload (null observability excepted by "
                f"expected_wire_paths) except {bad or 'none'}; union == EXPORT_FIELD_TABLE "
                f"({len(EXPORT_FIELD_TABLE)} rows) {emitted == set(EXPORT_FIELD_TABLE)}")


def _attacks(ctx: Stage7GateContext) -> tuple[bool, str]:
    parts, ok = [], True
    for name, results in (("membership", ctx.membership), ("property", ctx.property_attack)):
        distilled, raw = results.get("distilled"), results.get("raw_steps_control")
        measured = distilled is not None and raw is not None and \
            distilled.advantage is not None and raw.advantage is not None
        real = measured and raw.advantage >= RAW_CONTROL_MIN_ADVANTAGE  # type: ignore[union-attr,operator]
        ok = ok and measured and real
        # Each row with its OWN n and chance (F8): the distilled row can hold fewer hosts
        # than the raw control, so one shared chance figure was wrong for one of them.
        rows = [
            f"{label} {_fmt(r.advantage if r else None)} (chance {_fmt(r.chance if r else None)}"
            f", {r.trials if r else 0} {'hosts, exhaustive' if name == 'property' else 'trials'})"
            for label, r in (("distilled advantage", distilled), ("raw-steps control", raw))
        ]
        parts.append(f"{name}: {', '.join(rows)} ({'real' if real else 'DEGENERATE'})")
    return ok, "(c)(d) " + "; ".join(parts)


def check_g7_7(ctx: Stage7GateContext) -> GateCheck:
    """G7.7 — Privacy leakage is measured, not assumed absent because raw data stays local."""
    title = "Privacy leakage is measured, not assumed absent"
    if ctx.errors.get("privacy"):
        return GateCheck("G7.7", title, False, f"the privacy run failed: {ctx.errors['privacy']}")
    hits, names = ctx.canary_hits
    table_ok, table = _field_table(ctx)
    attacks_ok, attacks = _attacks(ctx)
    points = [p for p in ctx.dp_curve if p[0] is not None]
    siem_recall, siem_exposed = ctx.siem
    passed = (ctx.exported_count > 0 and hits == 0 and table_ok and attacks_ok
              and len(points) >= DP_MIN_POINTS)
    detail = (
        f"(a) canary scan over {ctx.exported_count} distinct exported blobs (every honest "
        f"delivery of every suite run, the receivers' local capsules and the type samples) "
        f"against {ctx.scan_size} raw strings and Stage 1 digests: {hits} hits {list(names)}; "
        f"{table}; {attacks}; (e) DP curve {len(points)} epsilon points "
        f"{[(p[0], _fmt(p[1]), _fmt(p[2])) for p in ctx.dp_curve]} (epsilon, novelty recall, "
        f"count-membership advantage; seeded RNG, so NOT private); (f) SIEM oracle baseline: "
        f"recall {_fmt(siem_recall)} at the cost of {siem_exposed} raw strings/digests exposed "
        f"(a lower bound). Real attackers UNMEASURED"
    )
    if ctx.exported_count == 0:
        detail += "; VACUOUS (a): nothing was exported"
    return GateCheck("G7.7", title, passed, detail)


# --- G7.8 ---------------------------------------------------------------------------------------


def check_g7_8(ctx: Stage7GateContext) -> GateCheck:
    """G7.8 — All promoted foreign knowledge has cross-host and local lineage."""
    title = "All promoted foreign knowledge has cross-host and local lineage"
    obs = ctx.observations
    eligible = sum(o.eligible for o in obs)
    incomplete = sum(o.eligible_incomplete for o in obs)
    bridged = sum(o.bridged for o in obs)
    missing = sum(o.bridged_lineage_missing for o in obs)
    trusted = sum(o.trusted_candidates for o in obs)
    lineage_ok = eligible > 0 and incomplete == 0 and bridged > 0 and missing == 0
    detail = (
        f"cross-host ancestry complete for {eligible - incomplete}/{eligible} ELIGIBLE decisions; "
        f"{bridged - missing}/{bridged} bridged capsules have a local Stage 6 lineage node with "
        f"a VERDICT child; Stage 6 put {trusted} bridged capsules in TRUSTED_CANDIDATE and the "
        f"lab receiver promotes nothing, so foreign items promoted with lineage = 0. "
    )
    if trusted == 0:
        detail += ("VACUOUS: the 'promoted' clause holds over zero objects — blocked on Stage 6 "
                   "(B7-1, ADR-0067): every foreign capsule scores below MIN_PROVENANCE_SCORE")
    else:
        detail += ("NOT MEASURABLE: TRUSTED_CANDIDATEs exist but no Stage 6 promotion runs in "
                   "the lab receiver, so 'later promoted' cannot be observed")
    # The lab receiver runs no Stage 6 promotion, so no foreign item is ever observed
    # promoted: the clause cannot pass here, and says why above.
    promoted_with_lineage = 0
    return GateCheck("G7.8", title, lineage_ok and promoted_with_lineage >= 1, detail)


# --- G7.10 --------------------------------------------------------------------------------------


def _store_problems(ctx: Stage7GateContext) -> list[str]:
    flood = ctx.flood
    if flood is None:
        return ["the flood run did not complete"]
    pressure = dict(flood.pressure)
    problems = list(flood.over_cap) + [f"outbound {o}" for o in flood.outbound_over]
    # A store filled exactly to its cap is bounded behaviour; a store OFFERED more than its
    # cap must have counted what it turned away. The keyring is the one store whose offer is
    # known exactly (the fleet's key directory); every other store is judged by count <= cap.
    if flood.keys_offered > MAX_KEYS and pressure.get("keyring", 0) == 0:
        problems.append(f"keyring offered {flood.keys_offered} > {MAX_KEYS} keys, 0 refused")
    if sum(n for _, n in flood.governor_refused) == 0:
        problems.append("the flood hit no governor bound")
    if not flood.scale or flood.scale[-1].refused_peers == 0:
        problems.append("the scale run hit no peer bound")
    problems += [f"scale {r.peers}: table {r.table_size} > {MAX_PEERS}"
                 for r in flood.scale if r.table_size > MAX_PEERS]
    churn = ctx.churn
    if churn is None:
        problems.append("the churn run did not complete")
    else:
        problems += [f"churn {s} peak {p} > cap {c}" for s, p, c in churn.store_peaks if p > c]
        if not churn.plateau_ok:
            problems.append("churn plateau failed: (store, middle-third peak, last-third peak) "
                            f"{list(churn.unplateaued)}")
    return problems


def check_g7_10(ctx: Stage7GateContext) -> GateCheck:
    """G7.10 — Stage 7 remains inside the Stage 0 resource envelope."""
    title = "Stage 7 remains inside the Stage 0 resource envelope"
    problems = _store_problems(ctx)
    flood = ctx.flood
    if flood is None:
        return GateCheck("G7.10", title, False, "; ".join(problems))
    r = flood.resources
    profile = None if r.profile is None else r.profile.within_target
    passed = r.within_ceiling is True and profile is True and not problems
    churn = ctx.churn
    detail = (
        f"FLOOD arm, {flood.rounds} rounds, {flood.deliveries} deliveries from "
        f"{flood.identities} simulated peers, then run_scale {[(s.peers, s.refused_peers, s.table_size, s.memory_bytes, s.work_units) for s in flood.scale]} "
        f"(peers, refused, table, bytes, work units): incremental RSS {r.incremental_rss_bytes} B "
        f"(sampled peak - start, floored 0; ceiling {STAGE7_INCREMENTAL_CEILING_BYTES}, normal "
        f"target {STAGE7_INCREMENTAL_NORMAL_BYTES}; within ceiling {r.within_ceiling}); edge "
        f"profile within_target {profile} (exceeded "
        f"{list(r.profile.exceeded) if r.profile else None}, UNMEASURED rows "
        f"{list(r.profile.unmeasured) if r.profile else None}: Stage 7 ships no model and "
        f"model_bytes=0 would claim a measurement of nothing — Stage 5 precedent); stores at "
        f"cap {list(flood.at_cap)} (keys offered {flood.keys_offered}), "
        f"pressure {dict(flood.pressure)}, governor refusals {dict(flood.governor_refused)}; "
        f"churn {churn.rounds if churn else None} rounds, {churn.peers_seen if churn else None} "
        f"peers seen, plateau_ok {churn.plateau_ok if churn else None}; problems "
        f"{problems or 'none'}. Wall {r.wall_seconds:.1f}s CPU {r.cpu_seconds:.1f}s at loadavg "
        f"{r.loadavg} (observed, never asserted). In-process dev-host figure; a real 2 GB "
        f"device is UNMEASURED"
    )
    return GateCheck("G7.10", title, passed, detail)


# --- G7.11 --------------------------------------------------------------------------------------


def _echo_row(report: ByzantineReport, arm: str, share: float) -> SuiteRow | None:
    return next((r for r in _rows(report, arm, "ECHO", lv=False)
                 if abs(r.adversary_share - share) < 1e-9), None)


def _detection_gain(ctx: Stage7GateContext, report: ByzantineReport) -> tuple[bool, str]:
    parts, ok = [], True
    for arm, share in ((AdversaryArm.NONE.value, 0.0), (AdversaryArm.BYZANTINE_POISON.value, 0.2)):
        row = _echo_row(report, arm, share)
        base = ctx.base_fp.get((arm, share))
        gain = None if row is None or row.recall_collective is None or \
            row.recall_no_sharing is None else row.recall_collective - row.recall_no_sharing
        fp = None if row is None else row.fp_rate_collective
        fp_ok = fp is not None and base is not None and fp <= base + FP_SLACK
        ok = ok and gain is not None and gain >= DETECTION_GAIN_MIN and fp_ok
        parts.append(f"{arm}@{share}: gain {_fmt(gain)} (need >= {DETECTION_GAIN_MIN}), FP "
                     f"{_fmt(fp)} vs NO_SHARING {_fmt(base)}")
    return ok, "detection (counterfactual_at_boundary, DEGENERATE_IN_FAVOUR per P5): " + \
        "; ".join(parts)


def _bp(points: Sequence[BreakPoint], arm: str, method: str, lv: bool) -> float | None:
    """Break share; ``inf`` when the method never broke in the sweep, None when absent."""
    found = [p.share for p in points if (p.arm, p.aggregator, p.lv) == (arm, method, lv)]
    return None if not found else float("inf") if found[0] is None else found[0]


def _break_points(report: ByzantineReport) -> tuple[bool, str]:
    failures, shown = [], []
    arms = [a.value for a in sorted(SYBIL_ARMS)] + list(_BYZANTINE_ARMS)
    for arm in arms:
        strict = arm in {a.value for a in SYBIL_ARMS}
        echo = _bp(report.break_points, arm, "ECHO", False)
        for method in ("MEDIAN", "TRIMMED_MEAN"):
            other = _bp(report.break_points, arm, method, False)
            beats = echo is not None and other is not None and (
                echo > other if strict else echo >= other)
            if not beats:
                failures.append(f"{arm}: ECHO {echo} {'>' if strict else '>='} {method} {other}")
        shown.append(f"{arm} ECHO {echo}")
    return not failures, f"break points ({'; '.join(shown)}), failures {failures or 'none'}"


def _mean_poison(report: ByzantineReport, arm: str, method: str, lv: bool) -> float | None:
    rates = [x for r in _rows(report, arm, method, lv=lv)
             if (x := _rate(r.poison_accepted, r.poison_offered)) is not None]
    return sum(rates) / len(rates) if rates else None


def _robustness(report: ByzantineReport) -> tuple[bool, str]:
    failures, median_lv = [], []
    for arm in [a.value for a in sorted(SYBIL_ARMS)] + list(_BYZANTINE_ARMS):
        for echo in _rows(report, arm, "ECHO", lv=False):
            med = next((r for r in _rows(report, arm, "MEDIAN", lv=True)
                        if r.adversary_share == echo.adversary_share
                        and r.sybils_per_root == echo.sybils_per_root), None)
            e, m = _rate(echo.poison_accepted, echo.poison_offered), \
                None if med is None else _rate(med.poison_accepted, med.poison_offered)
            if e is not None and m is not None and e > m + MARGIN:
                median_lv.append(f"{arm}@{echo.adversary_share:.2f}: {e:.2f}>{m:.2f}")
    failures += [f"poison above MEDIAN+LV+{MARGIN}: {median_lv[:4]}"] if median_lv else []
    none_echo = _rows(report, AdversaryArm.NONE.value, "ECHO", lv=False)
    none_median = _rows(report, AdversaryArm.NONE.value, "MEDIAN", lv=False)
    true_e = _rate(sum(r.true_accepted for r in none_echo), sum(r.true_offered for r in none_echo))
    true_m = _rate(sum(r.true_accepted for r in none_median),
                   sum(r.true_offered for r in none_median))
    if true_e is None or true_m is None or true_e < true_m - MARGIN:
        failures.append(f"share 0 true acceptance ECHO {_fmt(true_e)} < MEDIAN {_fmt(true_m)}-"
                        f"{MARGIN}")
    vf = {arm: (_mean_poison(report, arm, "ECHO", False),
                _mean_poison(report, arm, "VALIDATION_FILTER", False))
          for arm in (AdversaryArm.BYZANTINE_LATENT_POISON.value, AdversaryArm.SLOW_POISON.value)}
    failures += [f"{arm}: ECHO poison {_fmt(e)} not below VALIDATION_FILTER {_fmt(v)}"
                 for arm, (e, v) in vf.items() if e is None or v is None or not e < v]
    return not failures, (f"true acceptance at share 0 ECHO {_fmt(true_e)} vs MEDIAN "
                          f"{_fmt(true_m)}; mean poison acceptance ECHO vs VALIDATION_FILTER "
                          f"{ {a: (_fmt(e), _fmt(v)) for a, (e, v) in vf.items()} }; "
                          f"robustness failures {failures or 'none'}")


def _root_quorum(report: ByzantineReport) -> tuple[bool, str]:
    better = []
    for arm in [a.value for a in sorted(SYBIL_ARMS)] + list(_BYZANTINE_ARMS):
        e, q = _mean_poison(report, arm, "ECHO", False), _mean_poison(report, arm, "ROOT_QUORUM", True)
        if e is not None and q is not None and e < q - MARGIN:
            better.append(f"{arm} {e:.2f}<{q:.2f}")
    echo = next(iter(_rows(report, AdversaryArm.NONE.value, "ECHO", lv=False)), None)
    quorum = next(iter(_rows(report, AdversaryArm.NONE.value, "ROOT_QUORUM", lv=True)), None)
    re, rq = (None if echo is None else echo.recall_collective,
              None if quorum is None else quorum.recall_collective)
    keeps = re is not None and rq is not None and re >= rq
    return bool(better) and keeps, (
        f"ECHO vs ROOT_QUORUM+LV: arms where ECHO poison acceptance is lower by > {MARGIN} "
        f"{better or 'none'}; detection ECHO {_fmt(re)} vs ROOT_QUORUM+LV {_fmt(rq)}")


def _ablations(report: ByzantineReport) -> tuple[bool, str]:
    rows = {r.flag: r for r in report.ablations}
    missing = [f for f in ABLATION_FLAGS if f not in rows]
    no_delta = [f for f in ABLATION_FLAGS if f in rows and rows[f].delta is None]
    verdicts = {f: f"{rows[f].verdict}(firing {rows[f].firing_count}, delta "
                   f"{_fmt(rows[f].delta)})" for f in ABLATION_FLAGS if f in rows}
    sensitivity = [(name, lo, hi) for name, lo, hi in report.threshold_sensitivity]
    decides = [n for n, lo, hi in sensitivity if lo >= 1.0 or hi >= 1.0]
    inert = [n for n, lo, hi in sensitivity if lo == 0.0 and hi == 0.0]
    ok = not missing and not no_delta and bool(sensitivity)
    return ok, (f"ablation rows {verdicts}; missing {missing or 'none'}; delta None "
                f"{no_delta or 'none'}; threshold sensitivity (flip share x0.5, x2) "
                f"{[(n, round(lo, 3), round(hi, 3)) for n, lo, hi in sensitivity]}: silently "
                f"decides every outcome {decides or 'none'}, inert {inert or 'none'}")


def _discipline(ctx: Stage7GateContext) -> tuple[bool, str]:
    catalogue = catalogue_problems()
    registry_same = ctx.registry_before == ctx.registry_now()
    text = FINDINGS.read_text(encoding="utf-8") if FINDINGS.is_file() else ""
    headings = [h for h in FINDINGS_HEADINGS if h not in text]
    hypotheses = set(HYPOTHESES) == {f"H{n}" for n in range(9)}
    ok = catalogue == () and registry_same and not headings and hypotheses
    return ok, (f"catalogue problems {list(catalogue) or 'none'}; experiments/registry.jsonl "
                f"byte-identical {registry_same}; findings headings missing "
                f"{headings or 'none'}{' (docs/stage-7-findings.md absent)' if not text else ''}"
                f"; HYPOTHESES == H0..H8 {hypotheses}")


def check_g7_11(ctx: Stage7GateContext) -> GateCheck:
    """G7.11 — ECHO/ORPHEUS survives ablation against simpler FL and threat-intel baselines."""
    title = "ECHO/ORPHEUS survives ablation against simpler FL and threat-intel baselines"
    report = ctx.suite
    blocked = [p for p in ctx.preconditions if p.status == "BLOCKED"]
    pre = ", ".join(f"{p.name}={p.status}" for p in ctx.preconditions)
    if report is None:
        return GateCheck("G7.11", title, False, f"preconditions {pre}; " +
                         _no_suite("G7.11", title, ctx).detail)
    results = [_detection_gain(ctx, report), _break_points(report), _robustness(report),
               _root_quorum(report), _ablations(report), _discipline(ctx)]
    ttd = dict(report.time_to_detect)
    detail = (f"preconditions {pre}; " + " | ".join(d for _, d in results) +
              f" | time-to-detect (rounds) ECHO {_fmt(ttd.get('ECHO'))} vs CENTRAL_FEED "
              f"{_fmt(ttd.get('CENTRAL_FEED'))} | synthetic {report.synthetic}: FAILS by "
              f"construction on synthetic data (spec §6.1)")
    passed = not blocked and all(ok for ok, _ in results) and report.synthetic is False
    return GateCheck("G7.11", title, passed, detail)
