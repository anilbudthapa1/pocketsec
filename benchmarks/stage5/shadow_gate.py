"""Why the full planner never acts: the Action Shadow gate, measured two ways.

Usage: ``python benchmarks/stage5/shadow_gate.py [--record EXPERIMENT_ID]``

A. **Constancy.** The cone-informed shadow the planner gates on, per operator, over
   every case of five builders. A gate whose input takes one value per operator
   across a whole corpus is a fixed per-operator policy, not a per-case judgement.
   Also: the rejection reason of every containment candidate on C1's hostile cases.
B. **Sensitivity** of the outcome to ``SHADOW_AUTONOMY_CEILING`` (chosen 0.35,
   uncalibrated — F3). The constant is patched on the module for the duration of one
   arm and restored in ``finally``. **A sensitivity sweep, not a tuning**: no value
   here is proposed as the ceiling, because choosing it on the evaluation corpus would
   be fitting the gate to the answer.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import loadavg, primed, record, run_arm_measured  # noqa: E402

import pocketsec.stage5.aegis.shadow as shadow_module  # noqa: E402
from pocketsec.stage5.aegis.pareto import Selector  # noqa: E402
from pocketsec.stage5.aegis.planner import (  # noqa: E402
    AegisPlanner,
    PlannerConfig,
    _adaptation_model,
)
from pocketsec.stage5.constitution.invariants import FROZEN_CONSTITUTION  # noqa: E402
from pocketsec.stage5.gate_runtime import prime_memory  # noqa: E402
from pocketsec.stage5.labs import response_corpus as rc  # noqa: E402
from pocketsec.stage5.labs.baselines import (  # noqa: E402
    REFERENCE_FLAGS,
    build_rig,
    reference_arm,
    single_scalar_utility,
)
from pocketsec.stage5.labs.counter_corpora import (  # noqa: E402
    COUNTER_CORPORA_VERSION,
    build_decoupled_phi_corpus,
    build_hostile_leading_pairs,
)
from pocketsec.stage5.twin.response_twin import ResponseTwin  # noqa: E402

CONTAINMENT = ("SUSPEND_PROCESS", "RESTRICT_LOCAL_SOCKET")
CEILINGS = (0.35, 0.37, 0.42, 0.50, 0.70)


def _planner(case, rig):  # type: ignore[no-untyped-def]
    return AegisPlanner(
        config=PlannerConfig(selector=Selector.PARETO_THEN_POLICY, **REFERENCE_FLAGS),
        constitution=FROZEN_CONSTITUTION, invariants=case.invariants,
        governor=rig.planner_governor, memory=rig.memory, cells=rig.cells,
        hysteresis=rig.hysteresis, harm=case.harm,
    )


def constancy(cases):  # type: ignore[no-untyped-def]
    """Distinct generation-time and cone-informed shadow values per operator."""
    generation, gated = collections.defaultdict(set), collections.defaultdict(set)
    for case in cases:
        rig = build_rig(case)
        planner = _planner(case, rig)
        twin = ResponseTwin(snapshot=rig.before, governor=rig.planner_governor)
        worlds, adapt = planner._worlds(case.resolution), _adaptation_model(rig.before)
        for candidate in rig.field.candidates:
            op = candidate.operator.spec.operator_id
            cones = planner._cones(candidate, worlds=worlds, twin=twin, adaptations=adapt)
            generation[op].add(round(candidate.shadow.score, 4))
            gated[op].add(round(planner._shadow(candidate, cones=cones,
                                                resolution=case.resolution, twin=twin).score, 4))
    return {op: {"generation": sorted(generation[op]), "cone_informed": sorted(gated[op])}
            for op in sorted(gated)}


def rejection_reasons(cases, *, prime):  # type: ignore[no-untyped-def]
    decisions, reasons = collections.Counter(), collections.Counter()
    for case in cases:
        if case.truth.benign_admin:
            continue
        rig = build_rig(case)
        if prime:
            prime_memory(rig)
        plan = _planner(case, rig).plan(case.resolution, rig.before, now=rig.clock.now(),
                                         active_leases=())
        decisions[plan.decision.value] += 1
        ops = {c.candidate_id: c.operator.spec.operator_id for c in rig.field.candidates}
        for row in plan.rejected:
            if ops.get(row.candidate_id) in CONTAINMENT:
                reasons[f"{ops[row.candidate_id]}:{row.reason}"] += 1
    return {"decisions": dict(decisions), "containment_rejections": dict(reasons)}


@contextmanager
def ceiling(value: float):  # type: ignore[no-untyped-def]
    saved = shadow_module.SHADOW_AUTONOMY_CEILING
    shadow_module.SHADOW_AUTONOMY_CEILING = value
    try:
        yield
    finally:
        shadow_module.SHADOW_AUTONOMY_CEILING = saved


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", metavar="EXPERIMENT_ID")
    args = parser.parse_args()
    before = loadavg()
    c1 = rc.build_response_corpus(count=20, seed=11)
    builders = {
        "C1_corpus_20_11": c1,
        "C3_benign_leading_pairs_30_11": tuple(m for p in rc.build_ambiguous_pairs(count=30, seed=11) for m in p),
        "two_epoch_20_11": rc.build_two_epoch_corpus(count=20, seed=11),
        "evidence_6_11": rc.build_evidence_destroying_cases(count=6, seed=11),
        "flood_10_11": rc.build_action_flood(count=10, seed=11),
    }
    part_a = {name: {"cases": len(cases), "shadow": constancy(cases)} for name, cases in builders.items()}
    reasons = {"cold": rejection_reasons(c1, prime=False), "primed": rejection_reasons(c1, prime=True)}
    print("A. distinct shadow values per operator (containment operators shown)")
    for name, row in part_a.items():
        shown = {op: v for op, v in row["shadow"].items() if op in CONTAINMENT}
        print(f"  {name:<32} n={row['cases']:<3} {json.dumps(shown)}")
    print(f"  ceiling SHADOW_AUTONOMY_CEILING = {shadow_module.SHADOW_AUTONOMY_CEILING}")
    print(f"  C1 hostile cases, full planner: {json.dumps(reasons)}")

    corpora = {
        "C1": c1,
        "C2": build_decoupled_phi_corpus(count=20, seed=11),
        "C3": builders["C3_benign_leading_pairs_30_11"],
        "C4": tuple(m for p in build_hostile_leading_pairs(count=30, seed=11) for m in p),
    }
    arms = {"AEGIS": reference_arm, "AEGIS+primed": primed(reference_arm),
            "B6+primed": primed(single_scalar_utility)}
    part_b: dict[str, dict[str, dict[str, list[int]]]] = {}
    print("\nB. sensitivity to SHADOW_AUTONOMY_CEILING: [contained, collateral, actions, escalations]")
    for value in CEILINGS:
        with ceiling(value):
            part_b[str(value)] = {
                cname: {arm: [(r := run_arm_measured(policy, cases, arm=arm))["incidents_contained"],
                              r["collateral_incidents"], r["actions_taken"], r["human_escalations"]]
                        for arm, policy in arms.items()}
                for cname, cases in corpora.items()}
        print(f"  ceiling {value:<5} {json.dumps(part_b[str(value)])}")
    assert shadow_module.SHADOW_AUTONOMY_CEILING == 0.35, "ceiling not restored"
    after = loadavg()
    print(f"loadavg before {before} after {after}")
    if args.record:
        record(
            experiment_id=args.record,
            title="Action Shadow gate: constancy of its input and sensitivity to its ceiling",
            slot_name="stage5-aegis-shadow-gate",
            dataset_name="stage5-shadow-c1-c4-seed11",
            dataset_version=COUNTER_CORPORA_VERSION,
            dataset_sha256=rc.corpus_digest(tuple(c for cs in corpora.values() for c in cs)),
            seeds={"corpus": 11},
            notes=json.dumps({"constancy_C1": part_a["C1_corpus_20_11"]["shadow"],
                              "reasons_C1": reasons, "sweep": part_b})[:3900]
            + f"; SENSITIVITY ONLY, not a tuning; loadavg {before}->{after}",
            payload={"loadavg_before": before, "loadavg_after": after, "constancy": part_a,
                     "rejection_reasons_C1": reasons, "sensitivity": part_b,
                     "ceilings": list(CEILINGS)},
            command="PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage5/shadow_gate.py",
        )


if __name__ == "__main__":
    main()
