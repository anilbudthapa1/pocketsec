"""False discoveries on a corpus whose ground truth is null, and whether that null is informative.

Part A re-measures the gate's figure: ``run_null_fdr(seeds=0..19, content_seed=0)`` -- the
disciplined loop and the NAIVE control (``holdout_discipline=False, bonferroni=False``) on 20
Bernoulli(0.34) label draws over one NULL render.

Part B is the isolating control the gate lacks (its null is DEGENERATE because NAIVE also
selects 0). Over the WHOLE <=2-step class on TRAIN's vocabulary (the class of
``search_controls.mechanism_class``), per label seed:
  naive_p        mechanisms with in-sample (TRAIN) exact-binomial p <= 0.05, nothing else --
                 selection by significance alone, what a scientist without the rules does;
  naive_rules    in-sample p <= 0.05 AND FPR <= 0.01 AND recall >= 0.10 -- the gate's NAIVE
                 rule set applied to the whole class;
  holdout_top64  the top 64 by TRAIN F1 tested once on HOLDOUT at alpha/64 with the three
                 registered rules, then REPLICATION at alpha/survivors -- the discipline;
  holdout_all    every mechanism tested once on HOLDOUT at alpha/N (full-family Bonferroni),
                 then REPLICATION.
The mechanisms selected under a null are all false by construction.

Usage: ``PYTHONHASHSEED=0 python benchmarks/stage8/null_fdr.py [--skip-engine]``
"""

from __future__ import annotations

import sys
import time
from dataclasses import asdict

from _common import loadavg, save, stamp
from search_controls import _passes, mechanism_class

from pocketsec.stage8.episode import Split
from pocketsec.stage8.labs.baselines import run_null_fdr
from pocketsec.stage8.labs.discovery_corpus import (
    CorpusArm,
    build_discovery_corpus,
    relabel_null,
)
from pocketsec.stage8.sandbox.integrity import ALPHA, binomial_upper_tail

SEEDS = tuple(range(20))


def _f1(m, episodes) -> float:
    tp = fp = pos = 0
    for e in episodes:
        y = int(e.label)
        pos += y
        if m.matches(e.steps):
            tp += y
            fp += 1 - y
    return 0.0 if tp == 0 else 2 * tp / (2 * tp + fp + (pos - tp))


def _in_sample_p(m, episodes) -> float:
    matched = tp = pos = 0
    for e in episodes:
        y = int(e.label)
        pos += y
        if m.matches(e.steps):
            matched += 1
            tp += y
    return 1.0 if matched == 0 else binomial_upper_tail(tp, matched, pos / len(episodes))


def part_b(content_seed: int = 0) -> list[dict]:
    base = build_discovery_corpus(arm=CorpusArm.NULL, seed=content_seed)
    rows = []
    for label_seed in SEEDS:
        c = relabel_null(base, label_seed=label_seed)
        train, hold = c.episodes(Split.TRAIN), c.episodes(Split.HOLDOUT)
        rep = c.episodes(Split.REPLICATION)
        mechs = mechanism_class(train)
        n = len(mechs)
        naive_p = [m for m in mechs if _in_sample_p(m, train) <= ALPHA]
        naive_rules = [m for m in naive_p if _passes(m, train, ALPHA)[0]]
        top = sorted(mechs, key=lambda m: (-_f1(m, train), m.description_length_bits(),
                                           m.to_dsl()))[:64]
        top_hold = [m for m in top if _passes(m, hold, ALPHA / 64)[0]]
        top_rep = [m for m in top_hold if _passes(m, rep, ALPHA / max(1, len(top_hold)))[0]]
        all_hold = [m for m in mechs if _passes(m, hold, ALPHA / n)[0]]
        all_rep = [m for m in all_hold if _passes(m, rep, ALPHA / max(1, len(all_hold)))[0]]
        row = {"label_seed": label_seed, "class_size": n, "naive_p": len(naive_p),
               "naive_rules": len(naive_rules), "top64_holdout": len(top_hold),
               "top64_reproduced": len(top_rep), "all_holdout": len(all_hold),
               "all_reproduced": len(all_rep), "loadavg": loadavg()}
        print(f"  null seed {label_seed:2d}: N {n} naive_p {len(naive_p)} naive_rules "
              f"{len(naive_rules)} top64 HOLDOUT {len(top_hold)} REPL {len(top_rep)} | "
              f"all HOLDOUT {len(all_hold)} REPL {len(all_rep)}", flush=True)
        rows.append(row)
    return rows


def main(skip_engine: bool) -> None:
    out: dict = {}
    stamp("part B: whole <=2-step class under 20 null label draws")
    w0, c0 = time.perf_counter(), time.process_time()
    out["part_b"] = part_b()
    out["part_b_wall_cpu"] = [time.perf_counter() - w0, time.process_time() - c0]
    save("null_fdr", out)
    if not skip_engine:
        stamp("part A: run_null_fdr (engine, disciplined vs NAIVE)")
        l0, w0, c0 = loadavg(), time.perf_counter(), time.process_time()
        report = run_null_fdr(seeds=SEEDS, content_seed=0)
        out["part_a"] = {
            "rows": [asdict(r) for r in report.rows],
            "disciplined_mean_reproduced": report.disciplined_mean_reproduced,
            "disciplined_any_share": report.disciplined_any_share,
            "naive_mean_selected": report.naive_mean_selected,
            "naive_any_share": report.naive_any_share,
            "verdict": report.verdict.value,
            "wall_s": time.perf_counter() - w0, "cpu_s": time.process_time() - c0,
            "loadavg": [l0, loadavg()]}
        a = out["part_a"]
        print(f"part A: disciplined mean reproduced {a['disciplined_mean_reproduced']:.3f} "
              f"(any {a['disciplined_any_share']:.3f}); NAIVE mean selected "
              f"{a['naive_mean_selected']:.3f} (any {a['naive_any_share']:.3f}); verdict "
              f"{a['verdict']}; wall {a['wall_s']:.1f}s cpu {a['cpu_s']:.1f}s", flush=True)
        for r in a["rows"]:
            print(f"  {r}")
    stamp("done")
    save("null_fdr", out)


if __name__ == "__main__":
    main("--skip-engine" in sys.argv[1:])
