"""Stage 7 — resource cost and bounds beyond the gate's sizes, under Stage 0's sampler.

Two measurements, each in THIS fresh process (run the script alone; RSS is per process):

1. **Stress flood** (``--identities``, default 5x the gate's 1000) followed by the scale run at
   ``--scale`` peers (default 10 000 and 30 000, the gate stops at 10 000), through the gate's
   own ``gate_evidence.flood_evidence`` so the store/cap accounting is the gate's. Reports
   every store that went over its cap (must be none), the stores that reached their cap, the
   eviction/refusal counters, and incremental RSS (sampled peak - start, floored 0) against
   Stage 7's ceiling and the Stage 0 edge profile.
2. **CPU per unit of work, as a within-run ratio.** On one arm-NONE run of the simulated fleet
   the full fabric (HIVELOCK ingress + dependence graph + ECHO + bridge + lab Stage 6) is timed
   with ``time.process_time`` per delivered capsule, and MEDIAN+LV is timed over the SAME
   pooled capsules per round. Only the ratio transfers; loadavg is recorded beside both.

    PYTHONHASHSEED=0 python benchmarks/stage7/resources.py [--identities 5000]
        [--scale 10000 30000] [--record PS-S7-...]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import RESULTS_DIR, corpus_digest, loadavg, record  # noqa: E402

from pocketsec.stage7.aggregation.robust import Aggregator  # noqa: E402
from pocketsec.stage7.gate_evidence import flood_evidence  # noqa: E402
from pocketsec.stage7.labs.byzantine_suite import accepted_keys  # noqa: E402
from pocketsec.stage7.labs.fleet_corpus import build_fleet_corpus  # noqa: E402
from pocketsec.stage7.labs.partition import run_scale, simulate  # noqa: E402
from pocketsec.stage7.labs.simulated_fleet import (  # noqa: E402
    AdversaryArm,
    FleetSpec,
    default_receivers,
)


def cpu_ratio(corpus, seed: int) -> dict:  # type: ignore[no-untyped-def,type-arg]
    receivers = default_receivers(corpus)
    load_before = loadavg()
    c0, w0 = time.process_time(), time.perf_counter()
    run = simulate(corpus, FleetSpec(arm=AdversaryArm.NONE, seed=seed, receivers=receivers),
                   with_stage6=True)
    fabric_cpu, fabric_wall = time.process_time() - c0, time.perf_counter() - w0
    delivered = sum(len(d) for d in run.traffic)
    pooled = sum(len(r.pooled) for r in run.receivers.values())
    c1 = time.process_time()
    accepted_keys(run, Aggregator.MEDIAN, lv=True)
    median_cpu = time.process_time() - c1
    return {
        "deliveries": delivered, "pooled": pooled,
        "fabric_cpu_s": fabric_cpu, "fabric_wall_s": fabric_wall,
        "fabric_cpu_per_delivery_s": fabric_cpu / delivered if delivered else None,
        "median_lv_cpu_s_same_pools": median_cpu,
        "ratio_fabric_over_median_lv": fabric_cpu / median_cpu if median_cpu else None,
        "loadavg_before": load_before, "loadavg_after": loadavg(),
        "note": "fabric cpu includes simulating the senders' traffic (signing) — an upper bound "
                "on receiver cost; the MEDIAN+LV figure includes its local validation (one "
                "validator.validate per distinct key, cached) but not ingress, signature "
                "checks or the Stage 6 handoff",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identities", type=int, default=5000)
    parser.add_argument("--scale", type=int, nargs="+", default=[10000, 30000])
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--record", default=None)
    args = parser.parse_args()
    corpus = build_fleet_corpus(seed=7)
    receiver = default_receivers(corpus)[0]
    out: dict = {"loadavg_start": loadavg(), "identities": args.identities,  # type: ignore[type-arg]
                 "scale": args.scale}
    t0 = time.perf_counter()
    evidence = flood_evidence(corpus, receiver, seed=args.seed,
                              scale=lambda: run_scale(peer_counts=tuple(args.scale),
                                                      seed=args.seed, corpus=corpus),
                              identities=args.identities)
    out["flood"] = asdict(evidence)
    out["flood_wall_s"] = round(time.perf_counter() - t0, 2)
    out["loadavg_after_flood"] = loadavg()
    out["cpu_ratio"] = cpu_ratio(corpus, args.seed)
    out["loadavg_end"] = loadavg()
    res = evidence.resources
    print(f"flood identities {args.identities}: deliveries {evidence.deliveries}, keys offered "
          f"{evidence.keys_offered}")
    print(f"  over_cap {list(evidence.over_cap)}")
    print(f"  at_cap {list(evidence.at_cap)}")
    print(f"  pressure {dict(evidence.pressure)}")
    print(f"  governor_refused {dict(evidence.governor_refused)} outbound_over "
          f"{list(evidence.outbound_over)}")
    for row in evidence.scale:
        print(f"  scale peers {row.peers}: refused {row.refused_peers} table {row.table_size} "
              f"store bytes {row.memory_bytes} work units {row.work_units}")
    print(f"  peak sampled RSS {res.peak_sampled_rss_bytes} B, incremental "
          f"{res.incremental_rss_bytes} B, within ceiling {res.within_ceiling}, edge profile "
          f"within target {res.profile.within_target}; cpu {res.cpu_seconds:.2f} s wall "
          f"{res.wall_seconds:.2f} s at loadavg {res.loadavg}")
    print(f"  store bytes at end {dict(res.store_bytes)}")
    print(f"cpu ratio {json.dumps(out['cpu_ratio'], default=str)}")
    path = RESULTS_DIR / f"stage7-resources-i{args.identities}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=1, sort_keys=True, default=str) + "\n")
    print(f"wrote {path}")
    if args.record:
        record(experiment_id=args.record, hypothesis="H8",
               title="Stage 7 stress flood + scale bounds and fabric/median CPU ratio",
               slot_name="stage7-fabric", dataset_name="stage7-fleet-corpus",
               dataset_version="stage7-fleet-corpus-v0.1.0", dataset_sha256=corpus_digest(corpus),
               seeds={"corpus": 7, "fleet": args.seed},
               notes=json.dumps({"identities": args.identities, "scale": args.scale}),
               payload=out, command=" ".join(sys.argv))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
