"""Why does the Stage 6 learner install no learned item? A census of every candidate's fate.

Usage::

    PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage6/refusal_census.py \
        --spm 16 64 --threshold default 0.6 [--record EXPERIMENT_ID]

For each (sessions/month, genesis threshold) configuration it runs the real
``StageSixLearner`` on the 12-month endurance timeline and, for every candidate the chamber
issued, reports: how many learned items it carried (by kind), the lifecycle state it
reached, and — when refused — every conservation/shadow check that failed with that
check's own measured value and detail string. It also reports the chamber's own
``None`` returns and the learner's deferrals, so a candidate that never existed is
counted too. This reads the controller's private per-candidate record
(``_records``) for the check details; it writes nothing.

It answers one question with a count: which gate refuses the candidates that carry
learned items, and on what measurement.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import corpus_digest, genesis_threshold, loadavg, record

from pocketsec.stage6.labs.endurance import StageSixLearner, run_endurance
from pocketsec.stage6.labs.endurance_corpus import (
    ENDURANCE_SEED,
    ENDURANCE_VERSION,
    build_endurance_timeline,
    compile_timeline,
)


def census(compiled, threshold):
    with genesis_threshold(threshold):
        six = StageSixLearner(compiled.genesis, seed=compiled.seed)
        seen: dict[str, object] = {}

        def observe_only(candidate):
            # The learner's lab hook, used read-only: record what was submitted, return it
            # unchanged (the controller drops a rejected candidate's body at terminal).
            seen[candidate.candidate_id] = candidate
            return candidate

        six.lab_tamper = observe_only
        run_endurance(compiled, [six])
    rows = []
    for cid, rec in six.controller._records.items():
        cand = rec.candidate or seen.get(cid)
        items = Counter(i.kind.value for i in cand.delta.added) if cand is not None else {}
        failed = []
        if rec.verdict is not None:
            for r in rec.verdict.results:
                if not r.passed:
                    failed.append({"check": r.check.value, "measured": r.measured,
                                   "bound": r.bound, "detail": r.detail[:300]})
        rows.append({"candidate": cid[:21], "kinds": sorted(k.value for k in cand.kinds)
                     if cand is not None else None, "items_added": dict(items),
                     "removed": len(cand.delta.removed) if cand is not None else None,
                     "state": rec.state.value, "failed": failed,
                     "submitted_via_learner": cid in seen})
    fates = Counter()
    for r in rows:
        carries = bool(r["items_added"])
        fates[(carries, r["state"], tuple(sorted({f["check"] for f in r["failed"]})))] += 1
    return {
        "threshold": "default(0.5)" if threshold is None else threshold,
        "candidates": rows,
        "fates": [{"carries_learned_items": k[0], "state": k[1], "failed_checks": list(k[2]),
                   "count": v} for k, v in sorted(fates.items(), key=str)],
        "chamber": {k: getattr(six.chamber.stats(), k) for k in (
            "spawned", "returned_none", "mask_refusals", "field_only_freezes",
            "utility_fallbacks", "consolidation_candidates")},
        "deferrals": {k: v for k, v in six.counters.items() if "defer" in k or "drift" in k},
        "items_final": dict(Counter(i.kind.value for i in six.trusted_state().items)),
        "loadavg": loadavg(),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spm", type=int, nargs="+", default=[16])
    parser.add_argument("--threshold", nargs="+", default=["default"])
    parser.add_argument("--seed", type=int, default=ENDURANCE_SEED)
    parser.add_argument("--record", default=None)
    args = parser.parse_args()
    out, digests = [], {}
    for spm in args.spm:
        compiled = compile_timeline(build_endurance_timeline(sessions_per_month=spm,
                                                             seed=args.seed), seed=args.seed)
        digests[spm] = corpus_digest(compiled)
        for t in args.threshold:
            result = {"sessions_per_month": spm,
                      **census(compiled, None if t == "default" else float(t))}
            out.append(result)
            print(json.dumps({k: v for k, v in result.items() if k != "candidates"},
                             sort_keys=True, default=str), flush=True)
            for row in result["candidates"]:
                print("   ", json.dumps(row, default=str)[:700], flush=True)
    if args.record:
        from pocketsec.stage0.contracts.common import digest_of_bytes

        record(
            experiment_id=args.record, hypothesis="H6",
            title="Stage 6 candidate refusal census on the 12-month timeline",
            slot_name="stage6-learning-boundary", dataset_name="stage6-endurance-12m",
            dataset_version=ENDURANCE_VERSION,
            dataset_sha256=digest_of_bytes(json.dumps(digests, sort_keys=True).encode()),
            seeds={"endurance": args.seed},
            notes=json.dumps([{"spm": r["sessions_per_month"], "thr": r["threshold"],
                               "fates": r["fates"], "items_final": r["items_final"]}
                              for r in out], default=str),
            payload={"runs": out, "corpus_digests": digests},
            command="PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage6/refusal_census.py "
                    + " ".join(sys.argv[1:]),
        )


if __name__ == "__main__":
    main()
