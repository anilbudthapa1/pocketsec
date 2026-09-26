"""End to end: what Stage 5 does with Stage 4's REAL ``CBFResolutionV1`` exports.

Usage: ``python benchmarks/stage5/stage4_seam.py [--record EXPERIMENT_ID]``

Every Stage 5 containment figure elsewhere comes from ``labs/response_corpus.py``, whose
``_lineage_row`` writes ``target_pid`` / ``target_unit`` / ``target_session`` /
``target_socket`` into each resolution's ``evidence_lineage``. Stage 5's field
generator resolves intervention targets from exactly those keys
(``safe/action_field.py:LINEAGE_TARGET_KEYS``). This script drives Stage 4's own gate
corpus through Stage 4's own engine (``stage4.gate_criteria.drive_engine``, the call the
Stage 4 gate makes), takes each incident's ``close_incident`` export, and puts it in
front of Stage 5: which lineage keys arrive, what the field generator makes of them,
and what the full planner decides.

The host each export is paired with is a Stage 5 fixture (the first hostile case of
``build_response_corpus(count=2, seed=11)``), because Stage 4 exports no host. A
different host cannot create a target the resolution does not name.

Lives outside the package: trust rule T1 permits Stage 5 to import Stage 4 only through
``stage5_interface``, and this script must also import Stage 4's gate criteria.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import loadavg, record  # noqa: E402

from pocketsec.stage1.observation.policy import AdaptiveObservationPolicy  # noqa: E402
from pocketsec.stage4 import gate_criteria as criteria  # noqa: E402
from pocketsec.stage4.labs.baseline_metrics import replay_corpus  # noqa: E402
from pocketsec.stage5.aegis.pareto import Selector  # noqa: E402
from pocketsec.stage5.aegis.planner import AegisPlanner, PlannerConfig  # noqa: E402
from pocketsec.stage5.constitution.invariants import FROZEN_CONSTITUTION  # noqa: E402
from pocketsec.stage5.labs.baselines import REFERENCE_FLAGS, build_rig  # noqa: E402
from pocketsec.stage5.labs.response_corpus import build_response_corpus  # noqa: E402
from pocketsec.stage5.safe.action_field import (  # noqa: E402
    LINEAGE_TARGET_KEYS,
    generate_action_field,
)
from pocketsec.stage5.twin.response_twin import ResponseTwin  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", metavar="EXPERIMENT_ID")
    args = parser.parse_args()
    before = loadavg()
    started = time.process_time()
    cases = criteria.corpus()
    runs, _engine = criteria.drive_engine(
        replay_corpus(cases), criteria.measure_visibility_split(cases).model,
        observation=AdaptiveObservationPolicy())
    stage4_cpu = time.process_time() - started
    exports = [run.export for run in runs]
    keys = collections.Counter(k for e in exports for row in e.evidence_lineage for k in row)
    rows_total = sum(len(e.evidence_lineage) for e in exports)
    rows_targeting = sum(1 for e in exports for row in e.evidence_lineage
                         if set(row) & set(LINEAGE_TARGET_KEYS))
    host_case = next(c for c in build_response_corpus(count=2, seed=11) if not c.truth.benign_admin)
    candidates, decisions, truncations = collections.Counter(), collections.Counter(), collections.Counter()
    for export in exports:
        rig = build_rig(host_case)
        field = generate_action_field(
            export, rig.before, constitution=FROZEN_CONSTITUTION, invariants=host_case.invariants,
            governor=rig.planner_governor, memory=rig.memory, cells=rig.cells,
            twin=ResponseTwin(snapshot=rig.before, governor=rig.planner_governor))
        candidates.update(c.operator.spec.operator_id for c in field.candidates)
        truncations.update(t.reason[:90] for t in field.truncations)
        planner = AegisPlanner(
            config=PlannerConfig(selector=Selector.PARETO_THEN_POLICY, **REFERENCE_FLAGS),
            constitution=FROZEN_CONSTITUTION, invariants=host_case.invariants,
            governor=rig.planner_governor, memory=rig.memory, cells=rig.cells,
            hysteresis=rig.hysteresis, harm=host_case.harm)
        decisions[planner.plan(export, rig.before, now=rig.clock.now(),
                               active_leases=()).decision.value] += 1
    out = {
        "stage4_incidents": len(exports),
        "stage4_engine_cpu_seconds": round(stage4_cpu, 3),
        "identifiability": dict(collections.Counter(e.identifiability for e in exports)),
        "verdict": dict(collections.Counter(e.verdict.value for e in exports)),
        "hypotheses_per_export": dict(collections.Counter(len(e.hypotheses) for e in exports)),
        "lineage_keys": dict(keys),
        "lineage_rows": rows_total,
        "lineage_rows_with_a_target_key": rows_targeting,
        "stage5_candidates_by_operator": dict(candidates),
        "stage5_field_truncations_top": truncations.most_common(4),
        "aegis_decisions": dict(decisions),
        "stage5_target_keys": sorted(LINEAGE_TARGET_KEYS),
        "exports_sha256": hashlib.sha256(json.dumps(
            [e.to_dict() for e in exports], sort_keys=True, default=str).encode()).hexdigest(),
    }
    for key, value in out.items():
        print(f"{key}: {json.dumps(value)}")
    after = loadavg()
    print(f"loadavg before {before} after {after}")
    if args.record:
        record(
            experiment_id=args.record,
            title="Stage 4 real CBFResolutionV1 exports through Stage 5: lineage carries no target key",
            slot_name="stage5-stage4-seam",
            dataset_name=f"stage4-gate-corpus-exports-{criteria.CORPUS_COUNT}-{criteria.CORPUS_SEED}",
            dataset_version="stage4-close_incident-exports",
            dataset_sha256=out["exports_sha256"],
            seeds={"corpus": criteria.CORPUS_SEED},
            notes=json.dumps({k: out[k] for k in ("stage4_incidents", "identifiability",
                                                  "lineage_keys", "lineage_rows",
                                                  "lineage_rows_with_a_target_key",
                                                  "stage5_candidates_by_operator",
                                                  "aegis_decisions")}),
            payload={"loadavg_before": before, "loadavg_after": after, **out},
            command="PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage5/stage4_seam.py",
        )


if __name__ == "__main__":
    main()
