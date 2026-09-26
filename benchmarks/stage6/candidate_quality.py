"""Were the candidates Stage 6's gates refused actually bad? Score each on held-out eval.

Usage::

    PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage6/candidate_quality.py \
        --spm 16 64 --threshold default 0.6 [--record EXPERIMENT_ID]

A gate that refuses everything is indistinguishable from accept-nothing unless one checks
what it refused. For every candidate the real ``EvolutionChamber`` issued during the
12-month run, this script takes the candidate's ``proposed`` state (captured through the
learner's read-only ``lab_tamper`` hook, returned unchanged) and scores it with
``score_session`` on EVERY held-out eval session of the year — sessions no learner ever
observed — reporting benign FP rate and per-family recall at the proposed state's own
threshold, the lifecycle state the controller gave it, and the added motifs. The same is
done for ``FullRetrain``'s final state as the reference that uses the same
``induce_motifs`` without the Stage 6 chamber.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import corpus_digest, genesis_threshold, loadavg, record

from pocketsec.stage0.benchmark.security_metrics import (
    average_precision,
    recall_at_max_fpr,
)
from pocketsec.stage1.ssir.relations import Relation
from pocketsec.stage6.labs.continual_baselines import (
    FullRetrain,
    NeverUpdate,
    Stage2Only,
)
from pocketsec.stage6.labs.endurance import StageSixLearner, run_endurance
from pocketsec.stage6.labs.endurance_corpus import (
    ENDURANCE_SEED,
    ENDURANCE_VERSION,
    FAMILIES,
    build_endurance_timeline,
    compile_timeline,
)
from pocketsec.stage6.memory.semantic import score_session


def _quality(state, steps, fams, ctxs) -> dict:
    """Operating point (the state's own threshold) AND threshold-free ranking, side by side.

    A state can show benign FP 0.0 at its own threshold by alerting on nothing; only the
    pair (operating recall, operating FP) plus AP / recall@FPR says which it is.
    """
    t = state.threshold()
    scores = [score_session(state, s, context_id=x).score for s, x in zip(steps, ctxs,
                                                                         strict=True)]
    benign = [v for v, f in zip(scores, fams, strict=True) if f not in FAMILIES]
    labels = [1 if f in FAMILIES else 0 for f in fams]
    out = {"threshold": t, "benign_fp": sum(v >= t for v in benign) / len(benign),
           "ap": average_precision(labels, scores),
           "recall_at_fpr_0.05": recall_at_max_fpr(labels, scores, 0.05)[0]}
    for fam in FAMILIES:
        pos = [v for v, f in zip(scores, fams, strict=True) if f == fam]
        out[f"{fam}_recall"] = sum(v >= t for v in pos) / len(pos) if pos else None
    return out


def _motif(item) -> str:
    return " -> ".join(f"{Relation(s.relation).name}[req={s.require_properties},"
                       f"forbid={s.forbid_properties},raised={s.require_raised}]"
                       for s in item.motif)


def run(compiled, threshold) -> dict:
    steps = [s for m in compiled.months for s in m.eval_steps]
    fams = [f for m in compiled.months for f in m.eval_families]
    ctxs = [m.context_id for m in compiled.months for _ in m.eval_steps]
    seen: dict = {}

    def hook(candidate):
        seen[candidate.candidate_id] = candidate
        return candidate

    with genesis_threshold(threshold):
        six = StageSixLearner(compiled.genesis, seed=compiled.seed)
        six.lab_tamper = hook
        full = FullRetrain(compiled.genesis)
        stage2, never = Stage2Only(compiled.genesis), NeverUpdate(compiled.genesis)
        run_endurance(compiled, [six, full, stage2, never])
    rows = []
    for cid, cand in seen.items():
        rows.append({"candidate": cid[:21],
                     "state": six.controller._records[cid].state.value,
                     "kinds": sorted(k.value for k in cand.kinds),
                     "items_added": len(cand.delta.added),
                     "motifs": [_motif(i) for i in cand.delta.added if i.motif][:6],
                     **_quality(cand.proposed, steps, fams, ctxs)})
    return {"threshold": "default(0.5)" if threshold is None else threshold,
            "eval_sessions": len(steps), "benign_eval": sum(f not in FAMILIES for f in fams),
            "candidates": rows,
            "full_retrain_final": {"motifs": [_motif(i) for i in full.trusted_state().detectors()],
                                   **_quality(full.trusted_state(), steps, fams, ctxs)},
            "stage6_final": _quality(six.trusted_state(), steps, fams, ctxs),
            "stage2_only_final": _quality(stage2.trusted_state(), steps, fams, ctxs),
            "never_update_final": _quality(never.trusted_state(), steps, fams, ctxs),
            "loadavg": loadavg()}


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
                      **run(compiled, None if t == "default" else float(t))}
            out.append(result)
            print(json.dumps(result, default=str), flush=True)
    if args.record:
        from pocketsec.stage0.contracts.common import digest_of_bytes

        record(
            experiment_id=args.record, hypothesis="H6",
            title="Quality of every chamber-issued candidate on held-out eval sessions",
            slot_name="stage6-learning-boundary", dataset_name="stage6-endurance-12m",
            dataset_version=ENDURANCE_VERSION,
            dataset_sha256=digest_of_bytes(json.dumps(digests, sort_keys=True).encode()),
            seeds={"endurance": args.seed},
            notes=json.dumps([{"spm": r["sessions_per_month"], "thr": r["threshold"],
                               "candidates": [(c["state"], c["items_added"], c["benign_fp"],
                                               c["F1_recall"]) for c in r["candidates"]],
                               "full_retrain": (r["full_retrain_final"]["benign_fp"],
                                                r["full_retrain_final"]["F1_recall"])}
                              for r in out], default=str),
            payload={"runs": out, "corpus_digests": digests},
            command="PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage6/candidate_quality.py "
                    + " ".join(sys.argv[1:]),
        )


if __name__ == "__main__":
    main()
