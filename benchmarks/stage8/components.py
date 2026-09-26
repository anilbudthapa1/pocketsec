"""Does each component the stage added earn its existence? (lessons 1, 4, 5)

Re-runs, on PLANTED content seed 0 with ``RunConfig(seed=0)`` (the gate's corpus and config):
  * the base run's funnel, identifiability verdicts (F10), post-hoc rate (F7), novelty (F13),
    and every FORGE tournament entrant (F11, the direct-model rule of §7);
  * the NAIVE control on PLANTED (does it select the trap?) and the isolated trap probe;
  * ``run_ablation`` (one row per OPTIONAL flag: firings, outcome changes, deltas, verdict);
  * ``oracle_comparison`` over seeds 0-2, lab oracle off and on;
  * ``threshold_sensitivity`` (alpha, MDL gain per bit, FORGE tolerance; THRESHOLD_DECIDES).

Usage: ``PYTHONHASHSEED=0 python benchmarks/stage8/components.py``
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import asdict, replace

from _common import loadavg, save, stamp

from pocketsec.stage8.episode import Split, fit_counts
from pocketsec.stage8.labs.baselines import (
    oracle_comparison,
    run_ablation,
    threshold_sensitivity,
)
from pocketsec.stage8.labs.discovery_corpus import CorpusArm, build_discovery_corpus
from pocketsec.stage8.labs.discovery_run import RunConfig, probe_trap_at_holdout, run_discovery
from pocketsec.stage8.ledger.theory import TheoryStatus


def _timed(label, fn):
    stamp(label)
    l0, w0, c0 = loadavg(), time.perf_counter(), time.process_time()
    value = fn()
    t = {"wall_s": time.perf_counter() - w0, "cpu_s": time.process_time() - c0,
         "loadavg": [l0, loadavg()]}
    print(f"  {label}: wall {t['wall_s']:.1f}s cpu {t['cpu_s']:.1f}s load {t['loadavg']}",
          flush=True)
    return value, t


def base_details(corpus, report) -> dict:
    ledger, train = report.ledger, corpus.episodes(Split.TRAIN)
    killed = list(ledger.hypothesis_ids(TheoryStatus.FALSIFIED))
    killed_f1 = [fit_counts(ledger.genome(h).decides, train).f1 for h in killed]
    tournaments = []
    for p in report.packages:
        t = p.detector_candidates
        tournaments.append({
            "mechanism": p.mechanism.to_dsl(), "selected": None if t.selected is None
            else t.selected.value, "deployable": t.deployable, "reasons": list(t.reasons),
            "dcr": t.compression_ratio, "deployed_wu_per_event": t.deployed_work_units_per_event,
            "entrants": [asdict(e) for e in t.entrants],
            "identifiability": p.identifiability.value,
            "novelty": p.novelty_classification.value})
    return {
        "births": report.births, "challenged_out": report.challenged_out,
        "registered": report.registered, "survived": len(report.survived),
        "falsified": report.falsified, "reproduced": len(report.reproduced),
        "packages": len(report.packages), "work_units": report.governor.spent,
        "holdout_kill_rate": (report.registered - len(report.survived)) / report.registered
        if report.registered else None,
        "killed_train_f1": killed_f1,
        "identifiability": dict(Counter(v.klass.value for v in report.identifiability)),
        "identified_share_of_reproduced": _identified_share(report),
        "novelty": dict(Counter(n.classification.value for n in report.novelty)),
        "trap": asdict(report.trap), "tournaments": tournaments,
        "firings": [asdict(f) for f in report.firings],
    }


def _identified_share(report):
    repro = set(report.reproduced)
    verdicts = [v for v in report.identifiability if v.hypothesis_id in repro]
    if not verdicts:
        return None
    return sum(v.klass.value == "IDENTIFIED" for v in verdicts) / len(verdicts)


def main() -> None:
    out: dict = {}
    corpus = build_discovery_corpus(arm=CorpusArm.PLANTED, seed=0)
    base = RunConfig(arm=CorpusArm.PLANTED, seed=0)
    report, t = _timed("base run", lambda: run_discovery(corpus, base))
    out["base"] = {**base_details(corpus, report), **t}
    b = out["base"]
    print(f"  funnel births {b['births']} challenged_out {b['challenged_out']} registered "
          f"{b['registered']} survived {b['survived']} reproduced {b['reproduced']} packages "
          f"{b['packages']}; HOLDOUT kill rate {b['holdout_kill_rate']}; identifiability "
          f"{b['identifiability']} IDENTIFIED share of reproduced "
          f"{b['identified_share_of_reproduced']}; trap {b['trap']}", flush=True)
    for tn in b["tournaments"]:
        print(f"  tournament {tn['mechanism']}: selected {tn['selected']} deployable "
              f"{tn['deployable']} reasons {tn['reasons']} dcr {tn['dcr']}", flush=True)
        for e in tn["entrants"]:
            print(f"    {e}", flush=True)
    save("components", out)

    naive, t = _timed("NAIVE control on PLANTED", lambda: run_discovery(
        corpus, replace(base, holdout_discipline=False, bonferroni=False)))
    out["naive_planted"] = {"selected": len(naive.survived), "trap": asdict(naive.trap),
                            "planted_recovered": [f for f, ok in naive.planted_recovered if ok],
                            "false_selected": naive.false_reproduced, **t}
    print(f"  NAIVE: {out['naive_planted']}", flush=True)
    probe, t = _timed("trap probe", lambda: probe_trap_at_holdout(corpus, seed=0))
    out["trap_probe"] = {**asdict(probe), **t}
    print(f"  probe: {out['trap_probe']}", flush=True)
    save("components", out)

    rows, t = _timed("run_ablation", lambda: run_ablation(corpus, base))
    out["ablation"] = {"rows": [asdict(r) for r in rows], **t}
    for r in rows:
        print(f"  {r.flag:<20} {r.verdict.value:<18} fired {r.firings:<5} changed "
              f"{r.outcome_changes:<4} d_planted {r.delta_planted_recovered} d_false "
              f"{r.delta_false_reproduced} d_recall {r.delta_residual_recall} d_wu "
              f"{r.delta_work_units}", flush=True)
    save("components", out)

    oc, t = _timed("oracle_comparison", lambda: oracle_comparison(corpus, seeds=(0, 1, 2)))
    out["oracle"] = {"cells": [asdict(c) for c in oc.cells],
                     "eig_beats_cheap": oc.eig_beats_cheap, "verdict": oc.verdict.value, **t}
    for c in oc.cells:
        print(f"  {c.policy:<14} lab {c.lab_oracle!s:<5} seed {c.seed} experiments "
              f"{c.experiments} wu {c.work_units} correct_leading {c.correct_leading} "
              f"stops {c.stops}", flush=True)
    print(f"  eig_beats_cheap {oc.eig_beats_cheap} verdict {oc.verdict.value}", flush=True)
    save("components", out)

    sens, t = _timed("threshold_sensitivity", lambda: threshold_sensitivity(corpus, base))
    out["sensitivity"] = {"rows": [asdict(r) for r in sens], **t}
    for r in sens:
        print(f"  {r.parameter:<22} {r.value:<6} default {r.is_default!s:<5} repro "
              f"{r.reproduced:<3} planted {r.planted_recovered} false {r.false_reproduced} "
              f"deployable {r.deployable} changed {r.outcomes_changed}/{r.outcomes} "
              f"{r.flag}", flush=True)
    stamp("done")
    save("components", out)


if __name__ == "__main__":
    main()
