"""Long horizon: does any Stage 6 store stop growing, and when? Per-cycle maxima over C years.

Usage::

    PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage6/horizon.py --cycles 15 \
        [--record EXPERIMENT_ID]

G6.12 runs 5 cycles (60 months) and found every store except the replay ring still growing
between months 25-36 and 49-60. This script runs the same ``build_year_timeline`` for
``--cycles`` years through one ``StageSixLearner`` and reports, per store, the maximum
count and bytes inside each 12-month cycle, the cycle after which the per-cycle maximum
never rises again (the plateau, or ``None``), the store's cap and its eviction count.
Process RSS is sampled at every cycle end. Synthetic: the plateau, if any, is caps and
eviction binding on a repeating year (spec §6.1), not a property of real knowledge.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import corpus_digest, loadavg, record

from pocketsec.stage0.benchmark.resource_metrics import read_rss_bytes
from pocketsec.stage6.labs.endurance import STORE_CAPS, StageSixLearner, run_endurance
from pocketsec.stage6.labs.endurance_corpus import (
    ENDURANCE_SEED,
    ENDURANCE_VERSION,
    build_year_timeline,
    compile_timeline,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cycles", type=int, default=15)
    parser.add_argument("--seed", type=int, default=ENDURANCE_SEED)
    parser.add_argument("--record", default=None)
    args = parser.parse_args()
    t0, l0 = time.perf_counter(), loadavg()
    compiled = compile_timeline(build_year_timeline(cycles=args.cycles, seed=args.seed),
                                seed=args.seed)
    compile_s, l1 = time.perf_counter() - t0, loadavg()
    rss_before = read_rss_bytes()
    six = StageSixLearner(compiled.genesis, seed=args.seed)
    t1 = time.perf_counter()
    report = run_endurance(compiled, [six])
    run_s, l2 = time.perf_counter() - t1, loadavg()
    points = report.for_learner(six.name)
    per_cycle: dict[str, list[tuple[int, int]]] = {}
    for name in STORE_CAPS:
        per_cycle[name] = [
            (max(p.store_counts.get(name, 0) for p in points[c * 12:(c + 1) * 12]),
             max(p.store_bytes.get(name, 0) for p in points[c * 12:(c + 1) * 12]))
            for c in range(args.cycles)]
    stores = {}
    for name, series in per_cycle.items():
        counts = [s[0] for s in series]
        plateau = next((c for c in range(len(counts))
                        if all(x <= counts[c] for x in counts[c:])
                        and all(x == counts[c] for x in counts[c:c + 3])), None)
        byte_cap, count_cap = STORE_CAPS[name]
        stores[name] = {"per_cycle_max_count": counts,
                        "per_cycle_max_bytes": [s[1] for s in series],
                        "count_plateau_from_cycle": plateau,
                        "grew_in_last_cycle": counts[-1] > counts[-2] if len(counts) > 1 else None,
                        "count_cap": count_cap, "byte_cap": byte_cap,
                        "evictions_final": points[-1].evictions.get(name)}
    out = {"cycles": args.cycles, "months": len(points), "compile_seconds": round(compile_s, 1),
           "run_seconds": round(run_s, 1), "loadavg": [l0, l1, l2], "rss_before_run": rss_before,
           "rss_after_run": read_rss_bytes(), "stores": stores,
           "items_final": len(six.trusted_state().items),
           "lineage_folded": six.counters.get("lineage_folded", 0)}
    print(json.dumps(out, indent=1, default=str))
    if args.record:
        record(
            experiment_id=args.record, hypothesis="H6",
            title=f"Stage 6 store growth over {args.cycles} synthetic years",
            slot_name="stage6-learning-boundary", dataset_name=f"stage6-year-x{args.cycles}",
            dataset_version=ENDURANCE_VERSION, dataset_sha256=corpus_digest(compiled),
            seeds={"endurance": args.seed},
            notes=json.dumps({k: {"plateau_from_cycle": v["count_plateau_from_cycle"],
                                  "last": v["per_cycle_max_count"][-1],
                                  "cap": v["count_cap"], "evictions": v["evictions_final"]}
                              for k, v in stores.items()})
                  + f"; run {run_s:.1f}s loadavg {l1}->{l2}",
            payload=out,
            command="PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage6/horizon.py "
                    + " ".join(sys.argv[1:]),
        )


if __name__ == "__main__":
    main()
