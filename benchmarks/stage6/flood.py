"""Bounds under flood: offer N novel-signature capsules to a live Stage 6 learner; watch every store.

Usage::

    PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage6/flood.py --capsules 20000 \
        [--record EXPERIMENT_ID]

The spec's P6 arm floods 64-1024 attacker sessions. This script goes two orders of
magnitude further, cheaply: it compiles ONE attacker staging session and ONE routine
session through a real Stage 1 pipeline, then mints ``--capsules`` variants with
``reseal_capsule`` (content-addressed, so every variant is a distinct capsule), each with
a fresh independence group per step, fresh evidence digests and a random object-semantics
bit pattern (a novel meaning, so the gateway must track or refuse a new pattern each
time). Every 16th offer is a legitimate labelled F2-shaped episode pair, to see whether the
flood evicts or starves legitimate learning input.

Each variant goes through ``StageSixLearner.observe`` — the whole live path: gateway,
provenance ledger, lineage DAG, episodic memory, replay ring — with a consolidation every
16 episodes. At 40 checkpoints it records every store's (bytes, count, evictions) from
``StageSixLearner.stores()`` against ``STORE_CAPS``, plus process RSS and loadavg.
A store is shown BOUNDED only if its maximum stays under its cap AND its growth over the
last quarter of the run is zero or it has recorded evictions.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import loadavg, record

from pocketsec.stage0.benchmark.resource_metrics import read_rss_bytes
from pocketsec.stage0.contracts.common import digest_of_bytes
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_LAYOUT, GROUP_OFFSETS
from pocketsec.stage6.capsule.experience_capsule import (
    reseal_capsule,
    source_group_of,
    step_draft_fields,
)
from pocketsec.stage6.labs import poison_suite as ps
from pocketsec.stage6.labs.endurance import STORE_CAPS, StageSixLearner
from pocketsec.stage6.labs.endurance_corpus import ENDURANCE_SEED, simulated_snapshot

_OBJ = GROUP_OFFSETS["object_semantics"]
_OBJ_W = dict(FEATURE_LAYOUT)["object_semantics"]


def _variant(template, index: int, rng: random.Random):
    bits = rng.getrandbits(_OBJ_W)
    steps = []
    for n, step in enumerate(template.steps):
        features = list(step.features)
        for b in range(_OBJ_W):
            features[_OBJ + b] = float(bits >> b & 1)
        steps.append(replace(
            step, features=tuple(features), object_property_mask=bits,
            source_group=source_group_of(f"flood-{index}-{n}"),
            evidence=(digest_of_bytes(f"flood-ev-{index}-{n}".encode()),)))
    fields = step_draft_fields(tuple(steps), cut=False)
    fields["contamination_flags"] = fields["contamination_flags"] | template.contamination_flags
    return reseal_capsule(template, **fields)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capsules", type=int, default=20000)
    parser.add_argument("--seed", type=int, default=ENDURANCE_SEED)
    parser.add_argument("--record", default=None)
    args = parser.parse_args()
    b = ps._ArmBuilder(ps._ARMS["P6"], multiplier=1, seed=args.seed, background=8)
    attacker = b.attacker("P1", 1)[0]
    legit = [b.family("F2", ps._MAL)[1] for _ in range(4)]
    legit_capsules = [c for c in b.clean if c.label is not None]
    # Post-flood probe: fresh routine sessions compiled now, offered AFTER the flood to the
    # flooded learner and, as the control, to a fresh learner that saw no flood.
    probes = b.routine(64)
    six = StageSixLearner(b.identities[0], seed=args.seed)
    rng = random.Random(args.seed)
    every = max(1, args.capsules // 40)
    trace, started, before = [], time.perf_counter(), loadavg()
    rss0 = read_rss_bytes()
    episodes = 0
    for i in range(args.capsules):
        capsule = _variant(attacker, i, rng)
        six.observe(capsule, sequence=i + 1)
        episodes += 1
        if i % 16 == 15:
            six.observe(legit[(i // 16) % len(legit)], sequence=i + 1)
            six.observe(legit_capsules[(i // 16) % len(legit_capsules)], sequence=i + 1)
        if episodes % 16 == 0:
            six.consolidate(simulated_snapshot(pressure=False), sequence=i + 1)
        if (i + 1) % every == 0:
            stores = six.stores()
            trace.append({"offered": i + 1, "rss": read_rss_bytes(), "loadavg": loadavg(),
                          "wall": round(time.perf_counter() - started, 2),
                          "stores": {k: list(v) for k, v in stores.items()}})
    wall, after = time.perf_counter() - started, loadavg()

    def probe(learner, base_seq):
        gw0 = learner.gateway.stats().get("pattern_overflow")
        ev0 = learner.gateway.stats().get("pattern_evictions")
        buckets = {}
        admitted = 0
        for n, capsule in enumerate(probes):
            verdict = learner.gateway.admit(capsule)
            buckets[verdict.bucket.value] = buckets.get(verdict.bucket.value, 0) + 1
            admitted += len(verdict.admissions)
        return {"pattern_overflow_delta": learner.gateway.stats().get("pattern_overflow") - gw0,
                "pattern_evictions_delta": (
                    learner.gateway.stats().get("pattern_evictions") - ev0),
                "buckets": buckets, "admissions": admitted,
                "patterns_tracked": learner.gateway.stats().get("patterns_tracked")}

    control = StageSixLearner(b.identities[0], seed=args.seed)
    post_flood = {"flooded": probe(six, args.capsules), "control_no_flood": probe(control, 0)}
    last_q = trace[len(trace) * 3 // 4]
    verdicts = {}
    for name, (byte_cap, count_cap) in STORE_CAPS.items():
        series = [t["stores"][name] for t in trace]
        max_bytes, max_count = max(s[0] for s in series), max(s[1] for s in series)
        grew = series[-1][0] - last_q["stores"][name][0]
        evictions = series[-1][2]
        over = (byte_cap is not None and max_bytes > byte_cap) or (
            count_cap is not None and max_count > count_cap)
        verdicts[name] = {
            "max_bytes": max_bytes, "byte_cap": byte_cap, "max_count": max_count,
            "count_cap": count_cap, "bytes_growth_last_quarter": grew, "evictions": evictions,
            "verdict": "OVER_CAP" if over else ("PLATEAU" if grew <= 0 else (
                "GROWING_WITH_EVICTION" if evictions else "GROWING"))}
    gw = six.gateway.stats()
    summary = {"capsules": args.capsules, "wall_seconds": round(wall, 2),
               "loadavg": [before, after], "rss_start": rss0, "rss_end": read_rss_bytes(),
               "rss_max_sampled": max(t["rss"] or 0 for t in trace), "stores": verdicts,
               "gateway": dict(gw.counts), "counters": dict(six.counters),
               "stage6_items": len(six.trusted_state().items), "post_flood_probe": post_flood}
    print(json.dumps(summary, indent=1, sort_keys=True, default=str))
    if args.record:
        record(
            experiment_id=args.record, hypothesis="H6",
            title=f"Stage 6 store bounds under a {args.capsules}-capsule novel-signature flood",
            slot_name="stage6-learning-boundary", dataset_name="stage6-flood",
            dataset_version=ps.POISON6_VERSION + "+flood-v0",
            dataset_sha256=digest_of_bytes(attacker.canonical_bytes()),
            seeds={"flood": args.seed},
            notes=json.dumps({k: v["verdict"] for k, v in verdicts.items()})
                  + "; post-flood probe " + json.dumps(post_flood)
                  + f"; rss {rss0}->{summary['rss_end']}; wall {wall:.1f}s loadavg "
                    f"{before}->{after}",
            payload={"summary": summary, "trace": trace},
            command="PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage6/flood.py "
                    + " ".join(sys.argv[1:]),
        )


if __name__ == "__main__":
    main()
