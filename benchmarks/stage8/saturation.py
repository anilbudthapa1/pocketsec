"""Is the PLANTED world saturated for a trivial model? (lesson 9, integration plan risk 2/3)

For content seeds 0-2 of the PLANTED arm, and seed 0 of the NULL arm (the same content rendered
without the trap, scored on CONTENT labels: the exact trap-free control named in
``PreconditionReport``), this prints:

* ``corpus_preconditions`` P1-P5, including the trap-stripped P5 control the gate computes but
  does not print;
* the direct model (stdlib ``LogisticProbe`` on ``pooled_features``, the §7 "direct model"
  baseline) under four information regimes, each scored on REPLICATION:
    D0 fit on TRAIN labels (the gate's baseline, trap present in TRAIN);
    D1 fit on HOLDOUT labels only (the trap is label-independent there);
    D2 fit on TRAIN + HOLDOUT labels (the labels the discovery loop reads: TRAIN for
       generation, HOLDOUT through the vault) -- the equal-information control;
    D3 fit on TRAIN with every trap step removed from every row (an ORACLE control: it
       knows the trap; reported as an upper bound, never as a baseline);
  each at the 0.5 threshold, at the fit-side FPR<=0.01 threshold, and as REPLICATION AP;
* the Φ-oracle at its TRAIN FPR-budget threshold on REPLICATION (baseline 1).

Usage: ``PYTHONHASHSEED=0 python benchmarks/stage8/saturation.py``
"""

from __future__ import annotations

from dataclasses import replace

from _common import rates, save, stamp, threshold_at_fpr, timed

from pocketsec.stage0.benchmark.security_metrics import average_precision
from pocketsec.stage1.guillotine.features import LogisticProbe
from pocketsec.stage8.episode import Split
from pocketsec.stage8.forge.representations import pooled_features
from pocketsec.stage8.labs.baselines import phi_oracle_baseline
from pocketsec.stage8.labs.discovery_corpus import (
    CorpusArm,
    build_discovery_corpus,
    content_label,
    corpus_preconditions,
)


def _rows(episodes, strip=None):
    """``pooled_features`` (per-slot max over steps); with ``strip``, over the kept steps
    (episodes are content-addressed, so the max is taken directly, identically)."""
    out = []
    for e in episodes:
        if strip is None:
            out.append(list(pooled_features(e)))
            continue
        kept = [s for s in e.steps if not strip.matches(s)] or list(e.steps)
        out.append([max(col) for col in zip(*(s.features for s in kept), strict=True)])
    return out


def direct(fit_eps, test_eps, *, strip=None, label=lambda e: int(e.label)):
    y_fit = [label(e) for e in fit_eps]
    probe = LogisticProbe().fit(_rows(fit_eps, strip), y_fit)
    fit_scores = probe.predict(_rows(fit_eps, strip))
    y_test = [label(e) for e in test_eps]
    scores = probe.predict(_rows(test_eps, strip))
    cut = threshold_at_fpr(fit_scores, y_fit)
    return {
        "fit_n": len(fit_eps), "test_n": len(test_eps),
        "replication_ap": average_precision(y_test, scores),
        "at_0.5": rates([s >= 0.5 for s in scores], y_test),
        "fit_side_fpr_threshold": cut,
        "at_fit_fpr_budget": (None if cut is None
                              else rates([s >= cut for s in scores], y_test)),
    }


def planted(seed: int) -> dict:
    corpus, wall, cpu, l0, l1 = timed(lambda: build_discovery_corpus(arm=CorpusArm.PLANTED,
                                                                     seed=seed))
    pre = corpus_preconditions(corpus)
    train, hold = corpus.episodes(Split.TRAIN), corpus.episodes(Split.HOLDOUT)
    rep = corpus.episodes(Split.REPLICATION)
    trap = corpus.trap_mechanism.steps[0]
    phi = phi_oracle_baseline(corpus)
    return {
        "seed": seed, "build_wall_s": wall, "loadavg": [l0, l1],
        "preconditions": {
            "phi_oracle_holdout_ap": pre.phi_oracle_holdout_ap,
            "best_single_step_holdout_f1": pre.best_single_step_holdout_f1,
            "best_single_step": pre.best_single_step,
            "planted_f1": pre.planted_f1,
            "pooled_logistic_holdout_ap": pre.pooled_logistic_holdout_ap,
            "pooled_logistic_trap_stripped_holdout_ap":
                pre.pooled_logistic_trap_stripped_holdout_ap,
            "median_delta_phi": pre.median_delta_phi, "problems": pre.problems,
        },
        "phi_oracle_replication": {
            "threshold": phi.threshold, "recall": phi.replication_recall,
            "fpr": phi.replication_false_positive_rate, "ap": phi.replication_ap,
            "missed_positives": phi.missed_positives},
        "D0_train": direct(train, rep),
        "D1_holdout": direct(hold, rep),
        "D2_train_plus_holdout": direct(list(train) + list(hold), rep),
        "D3_train_trap_stripped_ORACLE_CONTROL": direct(train, rep, strip=trap),
    }


def null_content(seed: int) -> dict:
    corpus = build_discovery_corpus(arm=CorpusArm.NULL, seed=seed)
    pre = corpus_preconditions(corpus)    # on content labels: the trap-free world
    truth = lambda e: int(content_label(e) or 0)  # noqa: E731
    train, rep = corpus.episodes(Split.TRAIN), corpus.episodes(Split.REPLICATION)
    return {
        "seed": seed,
        "pooled_logistic_holdout_ap_content_labels": pre.pooled_logistic_holdout_ap,
        "phi_oracle_holdout_ap_content_labels": pre.phi_oracle_holdout_ap,
        "problems": pre.problems,
        "direct_train_content_labels_on_replication": direct(train, rep, label=truth),
    }


def main() -> None:
    out = {"planted": [], "null_content": None}
    for seed in (0, 1, 2):
        stamp(f"planted seed {seed}")
        row = planted(seed)
        out["planted"].append(row)
        p = row["preconditions"]
        print(f"seed {seed}: P5 {p['pooled_logistic_holdout_ap']:.4f} "
              f"trap-stripped {p['pooled_logistic_trap_stripped_holdout_ap']:.4f} "
              f"phi HOLDOUT AP {p['phi_oracle_holdout_ap']:.4f} problems {p['problems']}")
        for key in ("D0_train", "D1_holdout", "D2_train_plus_holdout",
                    "D3_train_trap_stripped_ORACLE_CONTROL"):
            d = row[key]
            print(f"  {key}: REPLICATION AP {d['replication_ap']:.4f} "
                  f"@0.5 {d['at_0.5']} @fitFPR {d['at_fit_fpr_budget']}")
        print(f"  phi: {row['phi_oracle_replication']}")
    stamp("null content seed 0")
    out["null_content"] = null_content(0)
    n = out["null_content"]
    print(f"NULL content (trap-free) P5 {n['pooled_logistic_holdout_ap_content_labels']:.4f}; "
          f"direct on REPLICATION {n['direct_train_content_labels_on_replication']}")
    stamp("done")
    save("saturation", out)


if __name__ == "__main__":
    main()
