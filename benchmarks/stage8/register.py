"""Append this measurement session's records to ``experiments/registry.jsonl`` (explicit act).

The gate never writes the ledger (spec §2.5, lesson 7). This script is the only writer here, and
it runs only when invoked. Sequence numbers start at 0101 so they cannot collide with the
sequences ``pocketsec-stage8 experiments --register`` assigns (gate 0001, ablation 0001-0017).
Each row points at ``results/<id>.json``, which holds the raw output of the named script.

Usage: ``PYTHONHASHSEED=0 python benchmarks/stage8/register.py``
"""

from __future__ import annotations

import json

from _common import OUT_DIR, corpus_digest, record

from pocketsec.stage8.labs.discovery_corpus import (
    DISCOVERY_CORPUS_VERSION,
    CorpusArm,
    build_discovery_corpus,
)

ROWS = (
    ("PS-S8-20260926-BASE-transfer-stage1-0101", "BASE", "transfer",
     "Stage 8 artefacts (PLANTED seed 0) applied to Stage 1's four eval corpora",
     "benchmarks/stage8/transfer.py"),
    ("PS-S8-20260926-BASE-saturation-direct-model-0102", "BASE", "saturation",
     "PLANTED saturation check and the direct model under four information regimes",
     "benchmarks/stage8/saturation.py"),
    ("PS-S8-20260926-H4-endpoint-harness-0103", "H4", "resources",
     "Research and endpoint cost, flood bounds, endurance; endpoint slots via run_benchmark",
     "benchmarks/stage8/resources.py"),
    ("PS-S8-20260926-BASE-search-controls-0104", "BASE", "search_controls",
     "PROMETHEUS vs random (512/3840), enumerator-only, brute-force <=2-step, Bonferroni",
     "benchmarks/stage8/search_controls.py"),
    ("PS-S8-20260926-BASE-null-fdr-0105", "BASE", "null_fdr",
     "Null-corpus false discoveries: engine disciplined vs NAIVE, and whole-class controls",
     "benchmarks/stage8/null_fdr.py"),
    ("PS-S8-20260926-BASE-random-spend-curve-0106", "BASE", "random_curve_random",
     "Random search recovery as a function of work units actually spent",
     "benchmarks/stage8/random_curve.py"),
    ("PS-S8-20260926-BASE-search-controls-seed2-0108", "BASE", "search_controls_2",
     "Search controls on PLANTED content seed 2 (re-run after the ORACLE crash)",
     "benchmarks/stage8/search_controls.py 2"),
    ("PS-S8-20260926-H8-ablation-rerun-0107", "H8", "components",
     "Ablation rows, ORACLE policies, threshold sweep, NAIVE PLANTED, trap probe (re-run)",
     "benchmarks/stage8/components.py"),
)


def main() -> None:
    corpus = build_discovery_corpus(arm=CorpusArm.PLANTED, seed=0)
    digest = corpus_digest(corpus)
    for experiment_id, hypothesis, name, title, script in ROWS:
        path = OUT_DIR / f"{name}.json"
        if not path.is_file():
            print(f"SKIP {experiment_id}: {path} missing (not measured)")
            continue
        payload = json.loads(path.read_text())
        record(experiment_id=experiment_id, hypothesis=hypothesis, title=title,
               slot_name=f"stage8-{name}", dataset_name="stage8-discovery-corpus",
               dataset_version=DISCOVERY_CORPUS_VERSION, dataset_sha256=digest,
               seeds={"corpus": 0, "run": 0},
               notes=f"script {script}; synthetic; counterfactual_at_boundary (B8-1); "
                     f"PLANTED content seed 0 digest (other seeds named in the payload)",
               payload=payload, command=f"PYTHONHASHSEED=0 python {script}")


if __name__ == "__main__":
    main()
