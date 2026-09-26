"""Does anything Stage 8 discovers on its own authored world transfer to a world it did not author?

Stage 8's corpus, planted mechanisms and engine share an author (lesson 6). Stage 1's four
corpora were written by a different wave, for a different purpose, before Stage 8 existed. They
are still synthetic, so this is not a detection result either; it only removes ONE author
confound: "does the discovered rule mean anything outside the world built to contain it?"

Each Stage 1 ``eval`` scenario is rendered on a FRESH ``Stage1Pipeline`` (the corpus trap:
Stage 1 corpora reuse pid 1000 across sessions) exactly as ``discovery_corpus`` renders its
INDEPENDENT split, truncated to ``MAX_EPISODE_STEPS`` (64) like every Stage 8 episode.

Artefacts, all fitted on PLANTED content seed 0 and applied unchanged:
  PHI                 the Φ-oracle at its Stage 8 TRAIN FPR-budget threshold (baseline 1);
  PACKAGES            the MALICIOUS mechanisms of PROMETHEUS's shipped DiscoveryPackages;
  PHI_OR_PACKAGES     the deployed union (through ``run_benchmark``);
  ALL_REPRODUCED      every MALICIOUS mechanism PROMETHEUS marked REPRODUCED;
  DIRECT_D2           stdlib LogisticProbe on pooled features fitted on TRAIN+HOLDOUT labels,
                      at its fit-side FPR<=0.01 threshold (the equal-information control).

Usage: ``PYTHONHASHSEED=0 python benchmarks/stage8/transfer.py``
"""

from __future__ import annotations

import time

from _common import (
    OUT_DIR,
    MechanismSetSlot,
    bench,
    loadavg,
    rates,
    save,
    stamp,
    threshold_at_fpr,
    write_split_dataset,
)

from pocketsec.stage0.benchmark.security_metrics import average_precision
from pocketsec.stage1.guillotine.features import LogisticProbe
from pocketsec.stage1.labs.ambiguous_corpus import AMBIGUOUS_VERSION, build_ambiguous_corpus
from pocketsec.stage1.labs.corpus import CORPUS_VERSION, build_corpus
from pocketsec.stage1.labs.hard_corpus import HARD_CORPUS_VERSION, build_hard_corpus
from pocketsec.stage1.labs.longhorizon_corpus import (
    LONG_HORIZON_VERSION,
    build_long_horizon_corpus,
)
from pocketsec.stage8.episode import EpisodeContext, Split, episode_from_result
from pocketsec.stage8.forge.representations import pooled_features
from pocketsec.stage8.genome.hypothesis import Direction
from pocketsec.stage8.labs.baselines import phi_oracle_baseline
from pocketsec.stage8.labs.discovery_corpus import CorpusArm, _render, build_discovery_corpus
from pocketsec.stage8.labs.discovery_run import RunConfig, run_discovery

CORPORA = (
    ("stage1-replay-eval", CORPUS_VERSION, lambda: build_corpus(count=120, seed=11, split="eval")),
    ("stage1-hard-eval", HARD_CORPUS_VERSION,
     lambda: build_hard_corpus(count=120, seed=11, split="eval")),
    ("stage1-ambiguous-eval", AMBIGUOUS_VERSION,
     lambda: build_ambiguous_corpus(count=90, seed=11, split="eval")),
    ("stage1-longhorizon-eval", LONG_HORIZON_VERSION,
     lambda: build_long_horizon_corpus(count=60, seed=11, split="eval")),
)


def render(name: str, version: str, scenarios) -> list:
    episodes = []
    for index, scenario in enumerate(scenarios):
        host = f"xfer-h{index % 4 + 1:02d}"
        context = EpisodeContext(host_id=host, epoch_id=9, family="", corpus=version,
                                 synthetic=True)
        result = _render(scenario.behaviours, host=host, serial=500_000 + index,
                         label=scenario.label)
        episodes.append(episode_from_result(result, split=Split.INDEPENDENT, context=context,
                                            label=scenario.label))
    return episodes


def main() -> None:
    stamp("fit artefacts on PLANTED seed 0")
    corpus = build_discovery_corpus(arm=CorpusArm.PLANTED, seed=0)
    phi = phi_oracle_baseline(corpus)
    w0, c0, l0 = time.perf_counter(), time.process_time(), loadavg()
    report = run_discovery(corpus, RunConfig(arm=CorpusArm.PLANTED, seed=0))
    discovery = {"wall_s": time.perf_counter() - w0, "cpu_s": time.process_time() - c0,
                 "loadavg": [l0, loadavg()], "work_units": report.governor.spent}
    packages = [p.mechanism for p in report.packages if p.direction is Direction.MALICIOUS]
    ledger = report.ledger
    reproduced = [ledger.genome(h).proposed_mechanism for h in report.reproduced
                  if ledger.genome(h).direction is Direction.MALICIOUS]
    print(f"  packages {[m.to_dsl() for m in packages]}; reproduced {len(reproduced)}; "
          f"Φ threshold {phi.threshold}", flush=True)
    fit = list(corpus.episodes(Split.TRAIN)) + list(corpus.episodes(Split.HOLDOUT))
    y_fit = [int(e.label) for e in fit]
    probe = LogisticProbe().fit([list(pooled_features(e)) for e in fit], y_fit)
    cut = threshold_at_fpr(probe.predict([list(pooled_features(e)) for e in fit]), y_fit)
    out = {"discovery_run": discovery, "phi_threshold": phi.threshold,
           "packages": [m.to_dsl() for m in packages],
           "reproduced": sorted(m.to_dsl() for m in reproduced), "direct_threshold": cut,
           "corpora": []}
    for name, version, build in CORPORA:
        stamp(f"render {name}")
        episodes = render(name, version, build())
        labels = [int(e.label) for e in episodes]
        phi_fire = [phi.threshold is not None and e.phi_oracle_score() >= phi.threshold
                    for e in episodes]
        pkg_fire = [any(m.matches(e.steps) for m in packages) for e in episodes]
        all_fire = [any(m.matches(e.steps) for m in reproduced) for e in episodes]
        direct_scores = probe.predict([list(pooled_features(e)) for e in episodes])
        row = {
            "corpus": name, "version": version, "episodes": len(episodes),
            "positives": sum(labels),
            "truncated_episodes": sum(1 for e in episodes if e.truncated),
            "PHI": rates(phi_fire, labels),
            "PHI_ap": average_precision(labels, [e.phi_oracle_score() for e in episodes]),
            "PACKAGES": rates(pkg_fire, labels),
            "PHI_OR_PACKAGES": rates([a or b for a, b in zip(phi_fire, pkg_fire, strict=True)],
                                     labels),
            "ALL_REPRODUCED": rates(all_fire, labels),
            "DIRECT_D2": rates([s >= cut for s in direct_scores], labels),
            "DIRECT_D2_ap": average_precision(labels, direct_scores),
        }
        dataset = write_split_dataset(episodes, OUT_DIR / f"{name}.jsonl", name=name,
                                      version=version)
        slot = MechanismSetSlot("stage8-phi-or-packages", packages,
                                {e.episode_id: e for e in episodes}, phi_threshold=phi.threshold)
        row["harness_PHI_OR_PACKAGES"] = bench(
            slot, dataset, "PS-S8-20260926-BASE-transfer-stage1-0101", seed=0)
        print(f"  {name}: n {row['episodes']} pos {row['positives']} trunc "
              f"{row['truncated_episodes']} | PHI {row['PHI']} | PACKAGES {row['PACKAGES']} | "
              f"ALL_REPRODUCED {row['ALL_REPRODUCED']} | DIRECT_D2 {row['DIRECT_D2']} "
              f"AP {row['DIRECT_D2_ap']:.4f} | harness recall "
              f"{row['harness_PHI_OR_PACKAGES']['recall_at_threshold']} fpr "
              f"{row['harness_PHI_OR_PACKAGES']['fpr_at_threshold']}", flush=True)
        out["corpora"].append(row)
    stamp("done")
    save("transfer", out)


if __name__ == "__main__":
    main()
