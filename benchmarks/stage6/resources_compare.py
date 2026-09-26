"""Resource cost per learner, each in a FRESH process, on the identical compiled 12-month stream.

Usage::

    PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage6/resources_compare.py \
        --spm 16 --repeats 3 [--record EXPERIMENT_ID]

The gate's G6.11 ratio compares ``WorkMeter`` units, which count item x step comparisons
and motif evaluations only. The Stage 6 learner's gateway, provenance ledger, lineage DAG,
fossil store and shadow/canary replay are not metered, so work units cannot say what
Stage 6 costs. This script measures what the process actually spends:

* the parent compiles the timeline ONCE and pickles it to a scratch file;
* for each repeat and each learner a child process loads the pickle, then runs
  ``run_endurance`` for that learner alone inside Stage 0's ``ResourceSampler``;
* the child reports CPU seconds, wall seconds, peak sampled RSS, incremental RSS over the
  post-load baseline, and ``check_profile(..., "edge")`` with the learner's trusted-state
  canonical bytes as ``model_bytes``.

Timings are contended (loadavg recorded per child); the within-run RATIO to Stage 6, taken
per repeat, is the figure that transfers. This is a dev host, not a 2 GB device.
"""

from __future__ import annotations

import argparse
import json
import pickle
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import corpus_digest, loadavg, record

LEARNERS = ("stage6", "full-retrain", "never-update", "naive-finetune", "stage2-only",
            "reservoir-65536")


def _make(name: str, compiled):
    from pocketsec.stage6.labs.continual_baselines import (
        FullRetrain,
        NaiveFinetune,
        NeverUpdate,
        ReservoirReplay,
        Stage2Only,
    )
    from pocketsec.stage6.labs.endurance import StageSixLearner

    g = compiled.genesis
    return {"stage6": lambda: StageSixLearner(g, seed=compiled.seed),
            "full-retrain": lambda: FullRetrain(g), "never-update": lambda: NeverUpdate(g),
            "naive-finetune": lambda: NaiveFinetune(g), "stage2-only": lambda: Stage2Only(g),
            "reservoir-65536": lambda: ReservoirReplay(g, budget_bytes=65536)}[name]()


def child(name: str, path: str) -> None:
    from pocketsec.stage0.benchmark.profiles import check_profile
    from pocketsec.stage0.benchmark.resource_metrics import ResourceSampler
    from pocketsec.stage6.labs.endurance import run_endurance

    with open(path, "rb") as handle:
        compiled = pickle.load(handle)
    learner = _make(name, compiled)
    capsules = sum(1 for m in compiled.months for e in m.events if e.capsule is not None)
    before = loadavg()
    with ResourceSampler() as sampler:
        run_endurance(compiled, [learner])
    metrics = sampler.result(events_processed=capsules, startup_seconds=None)
    model_bytes = len(learner.trusted_state().canonical_bytes())
    profile = check_profile(metrics, "edge", model_bytes=model_bytes)
    cost = learner.cost()
    print(json.dumps({
        "learner": name, "capsules": capsules, "cpu_seconds": metrics.cpu_seconds,
        "cpu_seconds_per_capsule": metrics.cpu_seconds_per_event,
        "wall_seconds": metrics.wall_seconds, "peak_sampled_rss_bytes":
            metrics.peak_sampled_rss_bytes, "idle_rss_bytes": metrics.idle_rss_bytes,
        "delta_rss_bytes": metrics.delta_rss_bytes, "unavailable": list(metrics.unavailable),
        "edge_within_target": profile.within_target, "edge_exceeded": list(profile.exceeded),
        "edge_unmeasured": list(profile.unmeasured), "model_bytes": model_bytes,
        "work_units": cost.work_units, "stored_bytes": cost.stored_bytes,
        "loadavg": [before, loadavg()]}))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spm", type=int, default=16)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seed", type=int, default=11)
    parser.add_argument("--child", nargs=2, default=None)
    parser.add_argument("--record", default=None)
    args = parser.parse_args()
    if args.child:
        child(*args.child)
        return
    from pocketsec.stage6.labs.endurance_corpus import (
        ENDURANCE_VERSION,
        build_endurance_timeline,
        compile_timeline,
    )

    compiled = compile_timeline(build_endurance_timeline(sessions_per_month=args.spm,
                                                         seed=args.seed), seed=args.seed)
    digest = corpus_digest(compiled)
    scratch = Path(tempfile.mkdtemp(prefix="s6-res-"))
    path = scratch / "compiled.pkl"
    path.write_bytes(pickle.dumps(compiled))
    runs: list[dict] = []
    for repeat in range(args.repeats):
        for name in LEARNERS:
            done = subprocess.run([sys.executable, __file__, "--child", name, str(path)],
                                  capture_output=True, text=True, check=True)
            row = json.loads(done.stdout.strip().splitlines()[-1]) | {"repeat": repeat}
            runs.append(row)
            print(json.dumps(row), flush=True)
    summary = {}
    for name in LEARNERS:
        mine = [r for r in runs if r["learner"] == name]
        ratios = [r["cpu_seconds"] / s["cpu_seconds"] for r in mine for s in runs
                  if s["learner"] == "stage6" and s["repeat"] == r["repeat"]]
        summary[name] = {
            "cpu_seconds_median": statistics.median(r["cpu_seconds"] for r in mine),
            "cpu_ratio_to_stage6_per_repeat": [round(x, 3) for x in ratios],
            "peak_sampled_rss_max": max(r["peak_sampled_rss_bytes"] or 0 for r in mine),
            "delta_rss_max": max(r["delta_rss_bytes"] or 0 for r in mine),
            "work_units": mine[0]["work_units"], "stored_bytes": mine[0]["stored_bytes"],
            "model_bytes": mine[0]["model_bytes"],
            "edge_within_target": [r["edge_within_target"] for r in mine],
        }
    print(json.dumps(summary, indent=1))
    if args.record:
        record(
            experiment_id=args.record, hypothesis="H6",
            title="Stage 6 vs §7 baselines: CPU and RSS per learner, fresh process each",
            slot_name="stage6-learning-boundary", dataset_name=f"stage6-endurance-12m-spm{args.spm}",
            dataset_version=ENDURANCE_VERSION, dataset_sha256=digest,
            seeds={"endurance": args.seed},
            notes=json.dumps({k: {"cpu_med": round(v["cpu_seconds_median"], 3),
                                  "ratio": v["cpu_ratio_to_stage6_per_repeat"],
                                  "delta_rss_max": v["delta_rss_max"],
                                  "work": v["work_units"], "stored": v["stored_bytes"]}
                              for k, v in summary.items()}),
            payload={"runs": runs, "summary": summary},
            command="PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage6/resources_compare.py "
                    + " ".join(sys.argv[1:]),
        )


if __name__ == "__main__":
    main()
