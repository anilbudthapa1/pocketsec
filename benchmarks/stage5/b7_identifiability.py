"""Is B7 a single-world control? What decides the primed planner arms, case by case.

Usage: ``python benchmarks/stage5/b7_identifiability.py [--record EXPERIMENT_ID]``

B7 (``enable_multi_world``, ``enable_twin``, ``enable_cone``, ``enable_regret`` off) is the
spec's single-world control. The lead's baseline (2) is "a single-world planner that acts
on the most likely explanation only". This records, for the full planner, B7 and B7 with
hysteresis also off, all primed, the plan decision and the rejection reason of every
containment candidate on the hostile cases of C1, C2 and C4. A ``NOT_IDENTIFIABLE``
rejection names a *rival* world, so any such row under B7 means B7 still evaluates more
than one world.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import loadavg, record  # noqa: E402

from pocketsec.stage5.aegis.pareto import Selector  # noqa: E402
from pocketsec.stage5.aegis.planner import AegisPlanner, PlannerConfig  # noqa: E402
from pocketsec.stage5.constitution.invariants import FROZEN_CONSTITUTION  # noqa: E402
from pocketsec.stage5.gate_runtime import prime_memory  # noqa: E402
from pocketsec.stage5.labs import response_corpus as rc  # noqa: E402
from pocketsec.stage5.labs.baselines import B7_FLAGS, REFERENCE_FLAGS, build_rig  # noqa: E402
from pocketsec.stage5.labs.counter_corpora import (  # noqa: E402
    COUNTER_CORPORA_VERSION,
    build_decoupled_phi_corpus,
    build_hostile_leading_pairs,
)

CONTAINMENT = ("SUSPEND_PROCESS", "RESTRICT_LOCAL_SOCKET")
CONFIGS = {
    "AEGIS": {},
    "B7": dict(B7_FLAGS),
    "B7-nohyst": {**B7_FLAGS, "enable_hysteresis": False},
}


def diagnose(cases, flags):  # type: ignore[no-untyped-def]
    decisions, reasons = collections.Counter(), collections.Counter()
    for case in cases:
        if case.truth.benign_admin:
            continue
        rig = build_rig(case)
        prime_memory(rig)
        resolved = {**REFERENCE_FLAGS, **flags}
        planner = AegisPlanner(
            config=PlannerConfig(selector=Selector.PARETO_THEN_POLICY if resolved["enable_pareto"]
                                 else Selector.SCALAR_UTILITY, **resolved),
            constitution=FROZEN_CONSTITUTION, invariants=case.invariants,
            governor=rig.planner_governor, memory=rig.memory, cells=rig.cells,
            hysteresis=rig.hysteresis, harm=case.harm)
        plan = planner.plan(case.resolution, rig.before, now=rig.clock.now(), active_leases=())
        decisions[plan.decision.value] += 1
        ops = {c.candidate_id: c.operator.spec.operator_id for c in rig.field.candidates}
        for row in plan.rejected:
            if ops.get(row.candidate_id) in CONTAINMENT:
                reasons[row.reason] += 1
    return {"decisions": dict(decisions), "containment_rejection_reasons": dict(reasons)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", metavar="EXPERIMENT_ID")
    args = parser.parse_args()
    before = loadavg()
    corpora = {
        "C1": rc.build_response_corpus(count=20, seed=11),
        "C2": build_decoupled_phi_corpus(count=20, seed=11),
        "C4": tuple(m for p in build_hostile_leading_pairs(count=30, seed=11) for m in p),
    }
    out = {name: {arm: diagnose(cases, flags) for arm, flags in CONFIGS.items()}
           for name, cases in corpora.items()}
    for name, row in out.items():
        print(f"{name} (hostile cases, primed): {json.dumps(row)}")
    after = loadavg()
    print(f"loadavg before {before} after {after}")
    if args.record:
        record(
            experiment_id=args.record,
            title="B7 keeps Response Identifiability: it is not a single-world control",
            slot_name="stage5-b7-identifiability",
            dataset_name="stage5-b7-c1-c2-c4-seed11",
            dataset_version=COUNTER_CORPORA_VERSION,
            dataset_sha256=rc.corpus_digest(tuple(c for cs in corpora.values() for c in cs)),
            seeds={"corpus": 11},
            notes=json.dumps(out) + f"; loadavg {before}->{after}",
            payload={"loadavg_before": before, "loadavg_after": after, "results": out},
            command="PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage5/b7_identifiability.py",
        )


if __name__ == "__main__":
    main()
