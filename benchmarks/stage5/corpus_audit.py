"""Corpus audit: what each Stage 5 corpus lets a trivial rule know, and what it cannot test.

Usage: ``python benchmarks/stage5/corpus_audit.py [--record EXPERIMENT_ID]``

1. **Label leak / saturation (C1).** Does the fixed playbook's single input, host Phi,
   carry ``truth.benign_admin``? Does Stage 4's leading world equal ``truth``?
2. **G5.9 feasibility.** On each ambiguous pair, the operators that are sufficient on
   the compromised half AND not harmful on the benign half. If that set is empty on
   every pair, no policy can reduce collateral at equal containment there: every policy
   acts on both halves (1 contained, 1 collateral) or on neither (0, 0).
3. **Which world leads** on each ambiguous pair.
4. **Rule 1** (session-unique identities) over every corpus this wave measured on.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import loadavg, record  # noqa: E402

from pocketsec.stage1.state.potential import phi  # noqa: E402
from pocketsec.stage5.labs import response_corpus as rc  # noqa: E402
from pocketsec.stage5.labs.baselines import build_rig, fixed_playbook  # noqa: E402
from pocketsec.stage5.labs.counter_corpora import (  # noqa: E402
    COUNTER_CORPORA_VERSION,
    build_decoupled_phi_corpus,
    build_hostile_leading_pairs,
)


def leading(case):  # type: ignore[no-untyped-def]
    return max(case.resolution.hypotheses, key=lambda h: h["support"])["mechanism_id"]


def label_leak(cases):  # type: ignore[no-untyped-def]
    table = collections.Counter(
        f"benign={c.truth.benign_admin},phi={phi(c.host.snapshot().security_state).total}"
        for c in cases)
    b2 = sum(1 for c in cases
             if (fixed_playbook(build_rig(c)).candidate is None) == c.truth.benign_admin)
    lead = sum(1 for c in cases if leading(c) == c.truth.true_mechanism_id)
    return {"phi_by_class": dict(table), "b2_decision_equals_truth": b2,
            "stage4_leading_equals_truth": lead, "cases": len(cases)}


def feasibility(pairs):  # type: ignore[no-untyped-def]
    sizes = collections.Counter()
    identical = 0
    for benign, hostile in pairs:
        identical += benign.resolution.to_dict() == hostile.resolution.to_dict()
        sizes[len(hostile.truth.sufficient_operator_ids - benign.truth.harmful_operator_ids)] += 1
    lead_benign = sum(1 for b, _ in pairs if leading(b) in rc.BENIGN_MECHANISMS)
    return {"pairs": len(pairs), "feasible_set_size_histogram": dict(sizes),
            "resolutions_identical": identical, "benign_world_leads": lead_benign}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", metavar="EXPERIMENT_ID")
    args = parser.parse_args()
    before = loadavg()
    c1 = rc.build_response_corpus(count=20, seed=11)
    c2 = build_decoupled_phi_corpus(count=20, seed=11)
    c3 = rc.build_ambiguous_pairs(count=30, seed=11)
    c4 = build_hostile_leading_pairs(count=30, seed=11)
    everything = (*c1, *[m for p in c3 for m in p], *[m for p in c4 for m in p])
    ids = rc.corpus_identities(everything)
    # Pair halves share their rows by design, so uniqueness is checked per distinct case_id stem.
    stems = {c.case_id.rsplit("-", 1)[0] if c.ambiguous else c.case_id: c for c in everything}
    stem_ids = rc.corpus_identities(tuple(stems.values()))
    out = {
        "C1_label_leak": label_leak(c1),
        "C2_label_leak": label_leak(c2),
        "C3_feasibility": feasibility(c3),
        "C4_feasibility": feasibility(c4),
        "rule1_identities": {"rows": len(stem_ids), "unique": len(set(stem_ids)),
                             "rows_incl_shared_pair_halves": len(ids)},
    }
    for key, value in out.items():
        print(f"{key}: {json.dumps(value)}")
    after = loadavg()
    print(f"loadavg before {before} after {after}")
    if args.record:
        record(
            experiment_id=args.record,
            title="Stage 5 corpus audit: playbook label leak, G5.9 infeasibility, leading world",
            slot_name="stage5-corpus-audit",
            dataset_name="stage5-audit-c1-c4-seed11",
            dataset_version=COUNTER_CORPORA_VERSION,
            dataset_sha256=rc.corpus_digest(everything),
            seeds={"corpus": 11},
            notes=json.dumps(out),
            payload={"loadavg_before": before, "loadavg_after": after, **out},
            command="PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage5/corpus_audit.py",
        )


if __name__ == "__main__":
    main()
