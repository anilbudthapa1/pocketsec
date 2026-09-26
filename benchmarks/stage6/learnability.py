"""Does the Stage 6 learner learn anything, and what stops it? Every §7 baseline, same stream.

Usage::

    PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage6/learnability.py \
        --spm 16 64 --threshold default 0.6 [--record EXPERIMENT_ID]

Two knobs, both varied for EVERY learner at once so the comparison stays fair:

* ``--spm`` — sessions per month, a public parameter of ``build_endurance_timeline``.
  The shadow needs ``MIN_SHADOW_SESSIONS x SHADOW_SAMPLE_EVERY`` = 128 replayed sessions
  before anything is promoted; at the shipped 16/month that is month 8.
* ``--threshold`` — the genesis THRESHOLD item. ``default`` is the shipped
  ``DEFAULT_THRESHOLD`` (0.5 == ``UNEXPLAINED_WEIGHT``, so genesis alerts on every session
  with one unexplained step). Any other value is a DIAGNOSTIC configuration the package
  does not ship; the package constant is never edited (``_common.genesis_threshold``).

Per learner it reports items learned, acquisition (F1@M01, F2@M05, F3@M07), F1 retention
at M08 and M12, the per-month benign FP rate at the learner's own threshold, AP over every
eval session of the year (threshold-free), WorkMeter cost, stored bytes and in-process CPU
seconds (a within-run ratio; loadavg recorded). For Stage 6 it also prints the learning
funnel: gateway buckets, deferrals, spawns, controller decisions.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import corpus_digest, genesis_threshold, loadavg, record

from pocketsec.stage0.benchmark.resource_metrics import ResourceSampler
from pocketsec.stage0.benchmark.security_metrics import average_precision
from pocketsec.stage0.contracts.common import digest_of_bytes
from pocketsec.stage6.labs.continual_baselines import (
    CalibrationOnly,
    FullRetrain,
    NaiveFinetune,
    NeverUpdate,
    PrototypeCentroid,
    ReservoirReplay,
    Stage2Only,
)
from pocketsec.stage6.labs.endurance import (
    StageSixConfig,
    StageSixLearner,
    check_preconditions,
    run_endurance,
)
from pocketsec.stage6.labs.endurance_corpus import (
    ENDURANCE_SEED,
    ENDURANCE_VERSION,
    FAMILIES,
    build_endurance_timeline,
    compile_timeline,
)

ACQ_MONTH = {"F1": 1, "F2": 5, "F3": 7}
#: Every OPTIONAL mechanism off; the REQUIRED gateway checks (independence, homeostasis) and
#: G4 (which cannot be switched off) stay on. Isolates the boundary from the machinery.
MINIMAL = StageSixConfig(plasticity_field=False, half_life=False, competition=False,
                         value_aware_rehearsal=False, drift_discriminator=False,
                         resurrection=False)


def _learners(compiled):
    g = compiled.genesis
    return [NeverUpdate(g), CalibrationOnly(g), NaiveFinetune(g), ReservoirReplay(g, budget_bytes=65536),
            FullRetrain(g), PrototypeCentroid(g), Stage2Only(g),
            StageSixLearner(g, seed=compiled.seed, name="stage6-minimal", config=MINIMAL),
            StageSixLearner(g, seed=compiled.seed)]


def _summarise(report, learner, compiled, cpu_seconds):
    points = report.for_learner(learner.name)
    by_month = {p.month: p for p in points}
    labels = [1 if f in FAMILIES else 0 for m in compiled.months for f in m.eval_families]
    scores = [s for p in points for s in p.scores]
    kinds = Counter(i.kind.value for i in learner.trusted_state().items)
    capsules = sum(1 for m in compiled.months for e in m.events if e.capsule is not None)
    return {
        "items": dict(kinds),
        "promotions": sum(p.promotions for p in points),
        "poisoned_promotions": sum(p.poisoned_promotions for p in points),
        "acquisition": {f: by_month[m].acquisition.get(f) for f, m in ACQ_MONTH.items()},
        "retention_F1_M08": by_month[8].retention.get("F1"),
        "retention_F1_M12": by_month[12].retention.get("F1"),
        "retention_M12": dict(by_month[12].retention),
        "fp_by_month": [p.fp_rate for p in points],
        "ap_all_eval": average_precision(labels, scores),
        "threshold_final": learner.threshold(),
        "work_units": points[-1].cost.work_units,
        "stored_bytes": points[-1].cost.stored_bytes,
        "cpu_seconds": round(cpu_seconds, 4),
        "cpu_seconds_per_capsule": cpu_seconds / capsules if capsules else None,
    }


def _funnel(six: StageSixLearner) -> dict:
    return {
        "counters": dict(sorted(six.counters.items())),
        "chamber": {k: getattr(six.chamber.stats(), k) for k in (
            "spawned", "returned_none", "mask_refusals", "field_only_freezes",
            "competitions", "utility_fallbacks", "consolidation_candidates")},
        "decisions": [(d.candidate_id[:16], d.to_state.value, d.reason[:160])
                      for d in six.controller.decisions()],
        "refusals": list(six.refusals),
        "rollbacks": six.rollback_count,
    }


def run(spm: int, threshold: float | None, compiled) -> dict:
    with genesis_threshold(threshold):
        pre = check_preconditions(compiled)
        learners = _learners(compiled)
        rows, report_all = {}, None
        for learner in learners:
            with ResourceSampler() as sampler:
                report = run_endurance(compiled, [learner])
            metrics = sampler.result(events_processed=1, startup_seconds=None)
            rows[learner.name] = _summarise(report, learner, compiled, metrics.cpu_seconds)
            report_all = report
        six = learners[-1]
        return {"sessions_per_month": spm,
                "threshold": "default(0.5)" if threshold is None else threshold,
                "preconditions": pre.verdict, "precondition_details": list(pre.details),
                "learners": rows, "stage6_funnel": _funnel(six),
                "stage6_minimal_funnel": _funnel(learners[-2]), "loadavg": loadavg(),
                "timeline_version": report_all.timeline_version if report_all else None}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spm", type=int, nargs="+", default=[16])
    parser.add_argument("--threshold", nargs="+", default=["default"])
    parser.add_argument("--seed", type=int, default=ENDURANCE_SEED)
    parser.add_argument("--record", default=None)
    args = parser.parse_args()
    thresholds = [None if t == "default" else float(t) for t in args.threshold]
    results, digests = [], {}
    for spm in args.spm:
        t0, l0 = time.perf_counter(), loadavg()
        compiled = compile_timeline(build_endurance_timeline(sessions_per_month=spm,
                                                             seed=args.seed), seed=args.seed)
        digests[spm] = corpus_digest(compiled)
        print(f"# spm {spm}: compiled in {time.perf_counter() - t0:.1f} s, loadavg {l0} -> "
              f"{loadavg()}, corpus {digests[spm]}", flush=True)
        for threshold in thresholds:
            t1 = time.perf_counter()
            out = run(spm, threshold, compiled)
            out["wall_seconds"] = round(time.perf_counter() - t1, 2)
            results.append(out)
            print(json.dumps(out, sort_keys=True, default=str), flush=True)
    if args.record:
        record(
            experiment_id=args.record, hypothesis="H6",
            title="Stage 6 learnability: every §7 learner x sessions/month x genesis threshold",
            slot_name="stage6-learning-boundary", dataset_name="stage6-endurance-12m",
            dataset_version=ENDURANCE_VERSION,
            dataset_sha256=digests[args.spm[0]] if len(digests) == 1 else digest_of_bytes(
                json.dumps(digests, sort_keys=True).encode("utf-8")),
            seeds={"endurance": args.seed},
            notes=json.dumps([{"spm": r["sessions_per_month"], "thr": r["threshold"],
                               "pre": r["preconditions"],
                               "stage6_items": r["learners"]["stage6"]["items"],
                               "stage6_ap": r["learners"]["stage6"]["ap_all_eval"],
                               "never_ap": r["learners"]["never-update"]["ap_all_eval"]}
                              for r in results], default=str),
            payload={"runs": results, "corpus_digests": digests},
            command="PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage6/learnability.py "
                    + " ".join(sys.argv[1:]),
        )


if __name__ == "__main__":
    main()
