"""Random search at EQUAL SPEND, not equal caps (lead baseline 2, measured properly).

The gate's "equal budget" is the same ``ResearchBudget`` (50M units); neither arm exhausts it,
so the arms spend different amounts (PROMETHEUS ~9.4M, RANDOM at its default 512 draws per
cluster ~5.9M). This sweeps RandomGenerator's draw count per cluster and reports, per count and
run seed, planted families recovered, false reproduced and work units actually spent, next to
PROMETHEUS on the same run seeds -- the success probability of random search as a function of
spend.

Usage: ``PYTHONHASHSEED=0 python benchmarks/stage8/random_curve.py``
"""

from __future__ import annotations

import functools
import sys
import time
from dataclasses import replace

from _common import loadavg, save, stamp

import pocketsec.stage8.labs.discovery_run as dr
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage8.genome.hypothesis import GeneratorKind
from pocketsec.stage8.labs.discovery_corpus import CorpusArm, build_discovery_corpus
from pocketsec.stage8.prometheus.generators import RandomGenerator

COUNTS = (768, 1024, 1280, 1536, 2048)
SEEDS = (0, 1, 2, 3, 4)


def one(corpus, config) -> dict:
    """A run that raises is recorded as CRASHED (with the error) and re-run with ORACLE off,
    labelled ``oracle_off_after_crash``: the crash is a finding, not a skipped cell."""
    l0, w0, c0 = loadavg(), time.perf_counter(), time.process_time()
    try:
        r = dr.run_discovery(corpus, config)
    except ContractError as exc:
        row = one(corpus, replace(config, oracle_policy=None))
        return {**row, "crashed": f"{type(exc).__name__}: {exc}",
                "oracle_off_after_crash": True}
    return {"seed": config.seed, "crashed": None, "recovered": [f for f, ok in r.planted_recovered if ok],
            "false_reproduced": r.false_reproduced, "reproduced": len(r.reproduced),
            "work_units": r.governor.spent, "exhausted": r.budget_exhausted,
            "wall_s": time.perf_counter() - w0, "cpu_s": time.process_time() - c0,
            "loadavg": [l0, loadavg()]}


def main() -> None:
    corpus = build_discovery_corpus(arm=CorpusArm.PLANTED, seed=0)
    base = dr.RunConfig(arm=CorpusArm.PLANTED, seed=0)
    out = {"prometheus": [], "random": {}}
    stamp("PROMETHEUS seeds 3, 4 (seeds 0-2 are in search_controls)")
    for seed in (SEEDS[3:] if "--random-only" not in sys.argv else ()):
        row = one(corpus, replace(base, seed=seed))
        out["prometheus"].append(row)
        print(f"  PROMETHEUS seed {seed}: {row}", flush=True)
    original = dr.RandomGenerator
    try:
        for count in COUNTS:
            stamp(f"RANDOM count {count}")
            dr.RandomGenerator = functools.partial(RandomGenerator, count=count)
            rows = []
            for seed in SEEDS:
                row = one(corpus, replace(base, seed=seed,
                                          generators=(GeneratorKind.RANDOM_BASELINE,)))
                rows.append(row)
                print(f"  RANDOM {count} seed {seed}: crashed {row['crashed']} recovered "
                      f"{row['recovered']} false "
                      f"{row['false_reproduced']} wu {row['work_units']} wall "
                      f"{row['wall_s']:.1f}s load {row['loadavg']}", flush=True)
            out["random"][str(count)] = rows
            save("random_curve_random", out)
    finally:
        dr.RandomGenerator = original
    stamp("done")
    save("random_curve_random", out)


if __name__ == "__main__":
    main()
