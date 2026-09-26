"""The eleven spec poisoning arms, re-run and recorded, optionally at a DIAGNOSTIC genesis threshold.

Usage::

    PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage6/poison_diag.py \
        [--threshold 0.6] [--record EXPERIMENT_ID]

The gate runs ``run_poison_suite`` at the shipped ``DEFAULT_THRESHOLD`` and finds Stage 6
ACCEPT_NOTHING_EQUIVALENT on every scored arm (it learns nothing clean either). This script
records that suite's full arm x learner x multiplier table in the ledger, and — with
``--threshold`` — asks whether removing the threshold defect alone makes Stage 6 learn
anything clean on the arms (if it still does not, F10 is not the threshold's doing).
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import genesis_threshold, loadavg, record

from pocketsec.stage0.contracts.common import digest_of_bytes
from pocketsec.stage6.labs.poison_suite import POISON6_VERSION, run_poison_suite


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--threshold", type=float, default=None)
    parser.add_argument("--seed", type=int, default=11)
    parser.add_argument("--record", default=None)
    args = parser.parse_args()
    started, before = time.perf_counter(), loadavg()
    with genesis_threshold(args.threshold), tempfile.TemporaryDirectory() as root:
        report = run_poison_suite(seed=args.seed, fossil_root=Path(root))
    wall, after = time.perf_counter() - started, loadavg()
    rows = [asdict(r) for r in report.rows]
    for r in rows:
        print(f"{r['arm_id']:<4} {r['learner']:<15} x{r['multiplier']:<3} offered "
              f"{r['poisoned_offered']:<5} poisoned {r['poisoned_promotions']} clean "
              f"{r['clean_promotions']} ({r['clean_rate']})")
    for arm, verdict in sorted(report.arm_verdicts.items()):
        print(f"verdict {arm}: {verdict}")
    print(f"# threshold {args.threshold}; wall {wall:.1f} s; loadavg {before} -> {after}")
    if args.record:
        record(
            experiment_id=args.record, hypothesis="H6",
            title="Stage 6 poison suite, 11 arms x 4 learners x (1,4,16)"
                  + (f", genesis threshold {args.threshold} (diagnostic)" if args.threshold
                     else ", shipped threshold"),
            slot_name="stage6-learning-boundary", dataset_name="stage6-poison-suite",
            dataset_version=POISON6_VERSION,
            dataset_sha256=digest_of_bytes(json.dumps(
                [(r["arm_id"], r["multiplier"], r["poisoned_offered"]) for r in rows]).encode()),
            seeds={"arm": args.seed},
            notes=json.dumps(report.arm_verdicts) + f"; wall {wall:.1f}s loadavg "
                  f"{before}->{after}",
            payload={"rows": rows, "arm_verdicts": dict(report.arm_verdicts),
                     "threshold": args.threshold},
            command="PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage6/poison_diag.py "
                    + " ".join(sys.argv[1:]),
        )


if __name__ == "__main__":
    main()
