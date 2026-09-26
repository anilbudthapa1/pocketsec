"""Every §7 arm plus the full planner on four corpora, one process, one run.

Usage: ``python benchmarks/stage5/arms.py [--record EXPERIMENT_ID]``

Corpora (all synthetic, all on ``SimulatedHost``):
  C1 ``build_response_corpus(count=20, seed=11)`` — the gate's corpus.
  C2 ``build_decoupled_phi_corpus(count=20, seed=11)`` — C1 with a quarter of each
     class re-hosted so the playbook's Phi input contradicts ``truth``.
  C3 ``build_ambiguous_pairs(count=30, seed=11)``, flattened — benign world leads.
  C4 ``build_hostile_leading_pairs(count=30, seed=11)``, flattened — hostile world leads.

Planner arms (AEGIS, B6, B7, B8) run cold and primed (the gate's own LAB_SANDBOX
priming). Each arm is timed by Stage 0's ``ResourceSampler``; only within-run ratios
are meaningful and ``/proc/loadavg`` is recorded before and after.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import loadavg, primed, record, run_arm_measured  # noqa: E402

from pocketsec.stage5.labs.baselines import (  # noqa: E402
    BASELINES,
    REFERENCE_ARM_ID,
    reference_arm,
    single_scalar_utility,
    single_world_planner,
    no_hysteresis,
)
from pocketsec.stage5.labs.counter_corpora import (  # noqa: E402
    COUNTER_CORPORA_VERSION,
    build_decoupled_phi_corpus,
    build_hostile_leading_pairs,
)
from pocketsec.stage5.labs.response_corpus import (  # noqa: E402
    build_ambiguous_pairs,
    build_response_corpus,
    corpus_digest,
)

from pocketsec.stage5.labs.baselines import (  # noqa: E402
    B7_FLAGS,
    Choice,
    _by_id,
    _leading_world,
    reference_policy,
)


def true_single_world(rig):  # type: ignore[no-untyped-def]
    """SW — the lead's baseline (2) as literally specified: the leading world only.

    B7 turns ``enable_multi_world`` off but keeps Response Identifiability, which still
    refuses an action that is harmful in a *rival* world — so B7 is not single-world
    (measured: 60/60 NOT_IDENTIFIABLE rejections on C4's hostile halves). SW reads the
    leading mechanism and the case's **policy** harm table (never ``truth``): if that
    table makes an O3 intervention unacceptable in the leading world it observes,
    otherwise it suspends the target under a lease that is swept. No twin, cone, shadow,
    identifiability, memory or hysteresis. Defined here, outside the package, because it
    is a measurement control and not a candidate for the privileged stage.
    """
    lead = _leading_world(rig.case.resolution)
    candidate = _by_id(rig, "SUSPEND_PROCESS")
    if candidate is None:
        return Choice(None, escalate=False, lease_sweep=False, reason="SW no suspend candidate")
    forbidden = {cls for mechanism, cls in rig.case.harm.unacceptable if mechanism == lead}
    if candidate.operator.spec.operator_class in forbidden:
        return Choice(None, escalate=False, lease_sweep=False, reason="SW leading world forbids")
    return Choice(candidate, escalate=False, lease_sweep=True, reason="SW act on leading world")


PLANNER_ARMS = {
    REFERENCE_ARM_ID: reference_arm,
    "B6": single_scalar_utility,
    "B7": single_world_planner,
    "B8": no_hysteresis,
    "B7-nohyst": reference_policy({**B7_FLAGS, "enable_hysteresis": False}),
}
EXTRA_ARMS = {"SW": true_single_world}


def corpora() -> dict[str, tuple]:
    return {
        "C1_corpus_20_11": build_response_corpus(count=20, seed=11),
        "C2_decoupled_20_11": build_decoupled_phi_corpus(count=20, seed=11),
        "C3_benign_leading_pairs_30_11": tuple(
            m for pair in build_ambiguous_pairs(count=30, seed=11) for m in pair
        ),
        "C4_hostile_leading_pairs_30_11": tuple(
            m for pair in build_hostile_leading_pairs(count=30, seed=11) for m in pair
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", metavar="EXPERIMENT_ID")
    args = parser.parse_args()
    before = loadavg()
    results: dict[str, dict[str, dict]] = {}
    digests: dict[str, str] = {}
    for name, cases in corpora().items():
        digests[name] = corpus_digest(cases)
        rows = {arm: run_arm_measured(policy, cases, arm=arm) for arm, policy in
                {**BASELINES, REFERENCE_ARM_ID: reference_arm, **EXTRA_ARMS,
                 "B7-nohyst": PLANNER_ARMS["B7-nohyst"]}.items()}
        rows.update({f"{arm}+primed": run_arm_measured(primed(policy), cases, arm=f"{arm}+primed")
                     for arm, policy in PLANNER_ARMS.items()})
        results[name] = rows
    after = loadavg()
    for name, rows in results.items():
        hostile = sum(1 for c in corpora()[name] if not c.truth.benign_admin)
        print(f"\n{name}  ({len(corpora()[name])} cases, {hostile} hostile) sha256 {digests[name][:16]}")
        print(f"  {'arm':<13}{'contained':>10}{'missed':>8}{'actions':>9}{'collateral':>11}"
              f"{'collat/1000':>12}{'esc':>5}{'faults':>7}{'cpu_s/case':>12}{'x B2':>7}")
        b2 = rows["B2"]["cpu_seconds_per_case"]
        for arm, row in sorted(rows.items()):
            rate = row["collateral_per_1000"]
            ratio = row["cpu_seconds_per_case"] / b2 if b2 else None
            print(f"  {arm:<13}{row['incidents_contained']:>10}{row['incidents_missed']:>8}"
                  f"{row['actions_taken']:>9}{row['collateral_incidents']:>11}"
                  f"{'None' if rate is None else f'{rate:.1f}':>12}{row['human_escalations']:>5}"
                  f"{row['planner_faults']:>7}{row['cpu_seconds_per_case']:>12.5f}"
                  f"{'-' if ratio is None else f'{ratio:.1f}':>7}")
    print(f"\nloadavg before {before} after {after}")
    if args.record:
        record(
            experiment_id=args.record,
            title="Stage 5 arms on the gate corpus and three counter-corpora, cold and primed",
            slot_name="stage5-arms",
            dataset_name="stage5-arms-c1-c4-seed11",
            dataset_version=COUNTER_CORPORA_VERSION,
            dataset_sha256=corpus_digest(tuple(c for cs in corpora().values() for c in cs)),
            seeds={"corpus": 11},
            notes=json.dumps({name: {arm: [r["incidents_contained"], r["collateral_incidents"],
                                           r["actions_taken"], r["human_escalations"]]
                                     for arm, r in rows.items() if arm in
                                     ("AEGIS", "AEGIS+primed", "B1", "B2", "B4", "B7+primed", "SW")}
                              for name, rows in results.items()})
            + f" [contained, collateral, actions, escalations]; loadavg {before}->{after}",
            payload={"loadavg_before": before, "loadavg_after": after, "digests": digests,
                     "results": results},
            command="PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage5/arms.py",
        )


if __name__ == "__main__":
    main()
