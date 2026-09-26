"""Leave-one-out ablation of every planner flag, cold AND primed, on four corpora.

Usage: ``python benchmarks/stage5/ablation_primed.py [--record EXPERIMENT_ID]``

The gate's G5.14 ablation runs cold, where the full planner takes no containment at
all, so every delta it reports (0.0) is a property of a planner that never acts and
cannot show that any component helps or harms (MEMORY.md trap 9). This script repeats
the leave-one-out with the effectiveness memory primed by the gate's own in-simulator
LAB_SANDBOX drills, which is the only configuration in which removing a component can
change an action. Default ``SHADOW_AUTONOMY_CEILING`` (0.35) throughout; nothing is
patched here.

Per flag and corpus the row is ``[contained, collateral, actions, escalations]``, and
the verdict compares against the full planner on the same corpus: a flag whose removal
contains more at no more collateral is HARMFUL; one whose removal changes nothing on
every corpus is NOT-YET-JUSTIFIED; one whose removal loses containment or adds
collateral somewhere is JUSTIFIED on that corpus.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import loadavg, primed, record, run_arm_measured  # noqa: E402

from pocketsec.stage5.aegis.planner import ABLATION_FLAG_FIELDS  # noqa: E402
from pocketsec.stage5.core_ids import ABLATION_FLAGS  # noqa: E402
from pocketsec.stage5.labs import response_corpus as rc  # noqa: E402
from pocketsec.stage5.labs.baselines import reference_policy  # noqa: E402
from pocketsec.stage5.labs.counter_corpora import (  # noqa: E402
    COUNTER_CORPORA_VERSION,
    build_decoupled_phi_corpus,
    build_hostile_leading_pairs,
)


def row(result: dict) -> list[int]:
    return [result["incidents_contained"], result["collateral_incidents"],
            result["actions_taken"], result["human_escalations"]]


def verdict(full: dict[str, list[int]], ablated: dict[str, list[int]]) -> str:
    better = worse = False
    for corpus, (fc, fcol, _fa, _fe) in full.items():
        ac, acol, _aa, _ae = ablated[corpus]
        if (ac > fc and acol <= fcol) or (ac >= fc and acol < fcol):
            better = True
        if ac < fc or acol > fcol:
            worse = True
    if better and not worse:
        return "HARMFUL (removal strictly better on some corpus, worse on none)"
    if worse and not better:
        return "JUSTIFIED on some corpus"
    if better and worse:
        return "MIXED"
    return "NOT-YET-JUSTIFIED (no effect on any corpus)"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", metavar="EXPERIMENT_ID")
    args = parser.parse_args()
    before = loadavg()
    corpora = {
        "C1": rc.build_response_corpus(count=20, seed=11),
        "C2": build_decoupled_phi_corpus(count=20, seed=11),
        "C3": tuple(m for p in rc.build_ambiguous_pairs(count=30, seed=11) for m in p),
        "C4": tuple(m for p in build_hostile_leading_pairs(count=30, seed=11) for m in p),
    }
    table: dict[str, dict[str, dict[str, list[int]]]] = {}
    for regime in ("cold", "primed"):
        wrap = primed if regime == "primed" else (lambda policy: policy)
        table[regime] = {"FULL": {c: row(run_arm_measured(wrap(reference_policy({})), cases, arm="FULL"))
                                  for c, cases in corpora.items()}}
        for flag in ABLATION_FLAG_FIELDS:
            table[regime][flag] = {
                c: row(run_arm_measured(wrap(reference_policy({flag: False})), cases, arm=f"-{flag}"))
                for c, cases in corpora.items()}
    after = loadavg()
    owners = {flag: sorted(core for core, f in ABLATION_FLAGS.items() if f == flag)
              for flag in ABLATION_FLAG_FIELDS}
    verdicts: dict[str, dict[str, str]] = {}
    for regime, rows in table.items():
        print(f"\n== {regime}: [contained, collateral, actions, escalations] per corpus")
        verdicts[regime] = {}
        for flag, per in rows.items():
            v = "-" if flag == "FULL" else verdict(rows["FULL"], per)
            verdicts[regime][flag] = v
            print(f"  {flag:<30}{','.join(owners.get(flag, [])):<20} {json.dumps(per)}  {v}")
    print(f"\nloadavg before {before} after {after}")
    if args.record:
        record(
            experiment_id=args.record,
            title="Leave-one-out ablation of every planner flag, cold and primed, C1-C4",
            slot_name="stage5-aegis-ablation",
            dataset_name="stage5-ablation-c1-c4-seed11",
            dataset_version=COUNTER_CORPORA_VERSION,
            dataset_sha256=rc.corpus_digest(tuple(c for cs in corpora.values() for c in cs)),
            seeds={"corpus": 11},
            notes=json.dumps(verdicts["primed"]) + f"; cold: every flag "
            f"{sorted(set(verdicts['cold'].values()) - {'-'})}; loadavg {before}->{after}",
            payload={"loadavg_before": before, "loadavg_after": after, "table": table,
                     "verdicts": verdicts, "core_ids_by_flag": owners},
            command="PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage5/ablation_primed.py",
        )


if __name__ == "__main__":
    main()
