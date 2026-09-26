"""Paired comparison of detection between two aggregators on the SAME held-out episodes.

The sweep reports recall per method; this script reports, per pair of methods, the episodes
one method catches and the other misses (discordant pairs) and an exact two-sided sign test
over them. Episodes of one host are not independent draws, so the p-value is a descriptive
figure for this corpus, not an inference about a population. Arm NONE, share 0.

    PYTHONHASHSEED=0 python benchmarks/stage7/paired_detection.py --corpus-seed 7 [--all-receivers]
"""

from __future__ import annotations

import argparse
import itertools
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import loadavg  # noqa: E402

from pocketsec.stage7.aggregation.robust import Aggregator  # noqa: E402
from pocketsec.stage7.antibody.forge import matches  # noqa: E402
from pocketsec.stage7.labs.byzantine_suite import _invariants, accepted_keys  # noqa: E402
from pocketsec.stage7.labs.fleet_corpus import build_fleet_corpus  # noqa: E402
from pocketsec.stage7.labs.partition import simulate  # noqa: E402
from pocketsec.stage7.labs.simulated_fleet import (  # noqa: E402
    AdversaryArm,
    FleetSpec,
    default_receivers,
)

METHODS = (Aggregator.ECHO, Aggregator.ROOT_QUORUM, Aggregator.VALIDATION_FILTER)


def sign_test(b: int, c: int) -> float:
    n, k = b + c, min(b, c)
    if n == 0:
        return 1.0
    return min(1.0, 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus-seed", type=int, default=7)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--all-receivers", action="store_true")
    args = parser.parse_args()
    corpus = build_fleet_corpus(seed=args.corpus_seed)
    receivers = tuple(corpus.receivers()) if args.all_receivers else default_receivers(corpus)
    run = simulate(corpus, FleetSpec(arm=AdversaryArm.NONE, seed=args.seed, receivers=receivers))
    hits: dict[str, set[tuple[str, int]]] = {}
    fps: dict[str, int] = {}
    positives = 0
    for method in METHODS:
        accepted = accepted_keys(run, method)
        caught, fp = set(), 0
        for host_id, rx in run.receivers.items():
            rows = _invariants(rx)
            rules = [a.antibody.invariant for a in run.fleet.local_antibodies(host_id)]
            rules += [rows[k] for k in accepted[host_id] if k in rows]
            seen = corpus.host(host_id).families_local
            for e in corpus.for_host(host_id, history=False):
                if e.label == 1 and e.family in seen:
                    continue
                hit = any(matches(r, e.steps) for r in rules)
                if e.label == 1 and hit:
                    caught.add((host_id, e.index))
                fp += e.label == 0 and hit
        hits[method.value], fps[method.value] = caught, fp
    for host_id in receivers:
        seen = corpus.host(host_id).families_local
        positives += sum(1 for e in corpus.for_host(host_id, history=False)
                         if e.label == 1 and e.family not in seen)
    print(f"corpus seed {args.corpus_seed}, {len(receivers)} receivers, {positives} positives "
          f"(locally-unseen families), loadavg {loadavg()}")
    for m in METHODS:
        print(f"  {m.value:<18} caught {len(hits[m.value])}/{positives} FP {fps[m.value]}")
    for a, b in itertools.combinations([m.value for m in METHODS], 2):
        only_a, only_b = len(hits[a] - hits[b]), len(hits[b] - hits[a])
        print(f"  {a} vs {b}: only {a} {only_a}, only {b} {only_b}, exact sign-test p "
              f"{sign_test(only_a, only_b):.2e}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
