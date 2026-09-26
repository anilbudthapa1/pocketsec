"""The two §43 rows ``resources.py`` leaves UNMEASURED, measured in separate processes.

Usage: ``python benchmarks/stage5/component_rss.py [--repeats 3] [--record EXPERIMENT_ID]``

``sentinel_and_executor`` and ``simulation_workspace`` have no self-reported footprint,
so the gate reports them UNMEASURED (G5.12). Here each is measured the only honest way
available without an allocator hook in the package: as the difference in peak RSS
(``resource.getrusage(RUSAGE_SELF).ru_maxrss``) between a fresh child process that
does the work and a fresh child that imports only the upstream modules Stage 5 sits on.
A Python-heap peak (``tracemalloc``) is reported beside it, because RSS also counts
bytecode and interpreter overhead of the imported modules.

Children:
  baseline     — imports Stage 0/1 contracts and ``stage4.stage5_interface`` only.
  privileged   — baseline + SENTINEL, executor, authority, evidence gate, host model;
                 runs ``labs.toctou.toctou_suite`` 25 times (100 raced transactions,
                 refused at revalidation) and 100 un-raced transactions on the same
                 setups' inner host (the commit path) through a real
                 ``TransactionalExecutor``, and asserts no planner
                 package (``aegis``, ``safe``, ``twin``, ``cells``, ``memory``) was loaded.
  simulation   — baseline + field, twin and cone; builds the twin and the cone for every
                 candidate of ``build_action_flood(count=40, seed=23)`` (the gate's flood).

Lives outside the package because P2 forbids a process launcher under ``pocketsec/stage5``.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import REPO_ROOT, loadavg, record  # noqa: E402

CHILD = r'''
import json, resource, sys, tracemalloc
mode = sys.argv[1]
import pocketsec.stage0.contracts.common, pocketsec.stage1.state.security_state
import pocketsec.stage4.stage5_interface
tracemalloc.start()
work = {}
if mode == "privileged":
    from pocketsec.stage5.executor.transactional import TransactionalExecutor
    from pocketsec.stage5.sentinel.kernel import SentinelKernel
    from pocketsec.stage5.executor.journal import RollbackJournal
    from pocketsec.stage5.executor.lease import LeaseRegistry
    from pocketsec.stage5.executor.verify import PostconditionProbe
    from pocketsec.stage5.evidence.preservation_gate import DEFAULT_RETENTION, EvidencePreservationGate
    from pocketsec.stage5.governor import ResourceGovernor
    from pocketsec.stage5.constitution.invariants import FROZEN_CONSTITUTION
    from pocketsec.stage5.labs.toctou import toctou_suite
    def factory(setup):
        return TransactionalExecutor(
            kernel=SentinelKernel(constitution=FROZEN_CONSTITUTION, invariants=setup.invariants, clock=setup.clock),
            host=setup.host, journal=RollbackJournal(),
            gate=EvidencePreservationGate(policy=DEFAULT_RETENTION, invariants=setup.invariants),
            governor=ResourceGovernor(), leases=LeaseRegistry(clock=setup.clock),
            probe=PostconditionProbe(invariants=setup.invariants), clock=setup.clock, tokens=setup.tokens)
    from pocketsec.stage5.labs.toctou import RACE_VARIANTS, build_race_setup
    from dataclasses import replace
    refused = 0
    for _ in range(25):
        refused += sum(race.refused for race in toctou_suite(build_executor=factory))
    outcomes = {}
    for i in range(100):
        setup = build_race_setup(RACE_VARIANTS[i % 4], seed=23 + i)
        receipt = factory(replace(setup, host=setup.inner)).execute(
            setup.operator, setup.token, resolution=setup.resolution)
        outcomes[receipt.outcome.value] = outcomes.get(receipt.outcome.value, 0) + 1
    work = {"race_transactions": 100, "races_refused": refused, "unraced_transactions": 100,
            "unraced_outcomes": outcomes}
elif mode == "simulation":
    from pocketsec.stage5.aegis.cone import build_intervention_cone
    from pocketsec.stage5.aegis.pareto import world_ids_of
    from pocketsec.stage5.aegis.planner import _adaptation_model
    from pocketsec.stage5.cells.response_cells import ResponseCellField
    from pocketsec.stage5.constitution.invariants import FROZEN_CONSTITUTION
    from pocketsec.stage5.governor import ResourceGovernor, BudgetExhausted
    from pocketsec.stage5.labs.response_corpus import build_action_flood
    from pocketsec.stage5.memory.effectiveness import EffectivenessMemory
    from pocketsec.stage5.safe.action_field import generate_action_field
    from pocketsec.stage5.twin.response_twin import ResponseTwin
    cones = twins = 0
    for case in build_action_flood(count=40, seed=23):
        governor, snapshot = ResourceGovernor(), case.host.snapshot()
        twin = ResponseTwin(snapshot=snapshot, governor=governor)
        field = generate_action_field(case.resolution, snapshot, constitution=FROZEN_CONSTITUTION,
            invariants=case.invariants, governor=governor, memory=EffectivenessMemory(),
            cells=ResponseCellField(), twin=twin)
        world = world_ids_of(case.resolution)[0]
        for candidate in field.candidates:
            try:
                build_intervention_cone(candidate, world_id=world, twin=twin,
                    adaptations=_adaptation_model(snapshot), governor=governor)
                twin.predict(candidate, world_id=world); cones += 1; twins += 1
            except BudgetExhausted:
                break
    work = {"cones": cones, "twin_predictions": twins, "cases": 40}
current, peak = tracemalloc.get_traced_memory()
planner_loaded = sorted(m for m in sys.modules if m.split(".")[:2] == ["pocketsec", "stage5"]
                        and len(m.split(".")) > 2 and m.split(".")[2] in ("aegis", "safe", "twin", "cells", "memory"))
print(json.dumps({"mode": mode, "ru_maxrss_kb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                  "tracemalloc_peak_bytes": peak, "planner_modules_loaded": planner_loaded, **work}))
'''


def child(mode: str) -> dict:
    output = subprocess.run([sys.executable, "-c", CHILD, mode], cwd=REPO_ROOT, check=True,
                            capture_output=True, text=True, env={"PYTHONHASHSEED": "0",
                                                                "PATH": "/usr/bin:/bin"})
    return json.loads(output.stdout.strip().splitlines()[-1])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--record", metavar="EXPERIMENT_ID")
    args = parser.parse_args()
    before = loadavg()
    runs = {mode: [child(mode) for _ in range(args.repeats)]
            for mode in ("baseline", "privileged", "simulation")}
    base = statistics.median(r["ru_maxrss_kb"] for r in runs["baseline"])
    summary = {}
    for mode, rows in runs.items():
        rss = statistics.median(r["ru_maxrss_kb"] for r in rows)
        summary[mode] = {
            "median_ru_maxrss_kb": rss,
            "incremental_over_baseline_bytes": int((rss - base) * 1024),
            "median_tracemalloc_peak_bytes": int(statistics.median(r["tracemalloc_peak_bytes"] for r in rows)),
            "planner_modules_loaded": rows[0]["planner_modules_loaded"],
            "work": {k: v for k, v in rows[0].items() if k not in ("mode", "ru_maxrss_kb",
                     "tracemalloc_peak_bytes", "planner_modules_loaded")},
            "all_ru_maxrss_kb": [r["ru_maxrss_kb"] for r in rows],
        }
        print(f"{mode}: {json.dumps(summary[mode])}")
    after = loadavg()
    print(f"loadavg before {before} after {after}")
    if args.record:
        record(
            experiment_id=args.record,
            title="SENTINEL+executor and simulation-workspace incremental RSS, separate processes",
            slot_name="stage5-component-rss",
            dataset_name="stage5-toctou-x25-and-flood-40-23",
            dataset_version="stage5-component-rss-v0.1.0",
            dataset_sha256=__import__("hashlib").sha256(CHILD.encode()).hexdigest(),
            seeds={"flood": 23, "repeats": args.repeats},
            notes=json.dumps({m: {k: s[k] for k in ("median_ru_maxrss_kb",
                                                    "incremental_over_baseline_bytes",
                                                    "median_tracemalloc_peak_bytes")}
                              for m, s in summary.items()}) + f"; loadavg {before}->{after}",
            payload={"loadavg_before": before, "loadavg_after": after, "summary": summary,
                     "runs": runs, "child_source": CHILD},
            command="PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage5/component_rss.py --repeats 3",
        )


if __name__ == "__main__":
    main()
