"""Run the Stage 5 gate once and register the id ``gate.py`` has always cited.

Usage: ``python benchmarks/stage5/gate_record.py [--record]``

``pocketsec/stage5/gate.py`` cites ``PS-S5-20260925-BASE-safe-gate-0001`` but the gate
never registers it, by design (spec §2.7: G5.15 asserts the ledger byte-identical
across a gate run). This script runs the gate to completion first and only then
appends the row, so the gate's own byte-identity check is unaffected.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import loadavg, record  # noqa: E402

from pocketsec.stage5.gate import CORPUS_COUNT, CORPUS_SEED, EXPERIMENT_ID  # noqa: E402
from pocketsec.stage5.gate import Stage5GateContext, run_gate  # noqa: E402
from pocketsec.stage5.labs.response_corpus import RESPONSE_CORPUS_VERSION  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    before = loadavg()
    started = time.perf_counter()
    ctx = Stage5GateContext.build()
    report = run_gate(ctx)
    wall = time.perf_counter() - started
    after = loadavg()
    failed = [check.id for check in report.checks if not check.passed]
    print(f"GATE: {'PASSED' if report.passed else 'FAILED'} ({len(failed)}) {failed}; "
          f"wall {wall:.2f} s; loadavg {before} -> {after}")
    if args.record:
        record(
            experiment_id=EXPERIMENT_ID,
            title="Stage 5 SAFE+AEGIS+SENTINEL acceptance gate",
            slot_name="stage5-safe-aegis-sentinel",
            dataset_name=f"stage5-response-corpus-{CORPUS_COUNT}-{CORPUS_SEED}",
            dataset_version=RESPONSE_CORPUS_VERSION,
            dataset_sha256=ctx.corpus_sha256,
            seeds={"corpus": CORPUS_SEED},
            notes=f"{len(report.checks) - len(failed)}/{len(report.checks)} criteria met; "
            f"failures {failed}; simulated host (ADR-0046); the id gate.py cites, registered "
            f"here for the first time by the measurement wave; wall {wall:.2f} s at loadavg "
            f"{before}->{after}",
            payload={"loadavg_before": before, "loadavg_after": after, "wall_seconds": wall,
                     "report": report.to_dict()},
            command="PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage5/gate_record.py --record",
        )
    print(json.dumps({"failed": failed}))


if __name__ == "__main__":
    main()
