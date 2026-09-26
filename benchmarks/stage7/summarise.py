"""Summarise one or more ``fraction_sweep.py`` JSON outputs into the findings tables.

    python benchmarks/stage7/summarise.py results/stage7-fraction-sweep-*.json

Prints, per file: (1) arm-NONE detection per method with TP/positives and FP/negatives;
(2) per adversarial arm, poison acceptance (accepted/offered, suite definition) per method
at every share or Sybil count, and ECHO's true-antibody acceptance beside it; (3) detection
recall at FPR 0.01 per method across the sweep; (4) the break points; (5) poison that ECHO
bridged into Stage 6 and the Stage 6 buckets. Reads only the JSON; computes nothing new.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SHOW = ("MAJORITY", "MEAN", "MEDIAN", "TRIMMED_MEAN", "MEDIAN+LV", "TRIMMED_MEAN+LV",
        "VALIDATION_FILTER", "ROOT_QUORUM+LV", "ECHO")


def _name(row: dict) -> str:  # type: ignore[type-arg]
    return row["aggregator"] + ("+LV" if row["lv"] else "")


def _x(run: dict) -> str:  # type: ignore[type-arg]
    return f"S={run['sybils_per_root']}" if run["arm"].startswith("SYBIL") else f"{run['share']:.1f}"


def summarise(path: Path) -> None:
    data = json.loads(path.read_text())
    print(f"\n######## {path.name}: corpus seed {data['corpus_seed']} fleet seed {data['seed']} "
          f"receivers {len(data['receivers'])} items {data['items']} positives {data['positives']}")
    print(f"preconditions: {[(n, s) for n, s, _ in data['preconditions']]}")
    arms: dict[str, list] = {}  # type: ignore[type-arg]
    for run in data["runs"]:
        arms.setdefault(run["arm"], []).append(run)
    print("\n[detection, run_benchmark] method: recall@FPR0.01 (tp/pos, fp/neg) per x")
    for arm, runs in arms.items():
        methods = [b["method"] for b in runs[0]["bench"]]
        print(f"  {arm}")
        for m in methods:
            cells = []
            for run in runs:
                b = next(b for b in run["bench"] if b["method"] == m)
                neg = b["items"] - b["positives"]
                r = b["recall_at_fpr_budget"]
                cells.append(f"{_x(run)}:{'-' if r is None else f'{r:.3f}'}"
                             f"({b['tp']}/{b['positives']},fp{b['fp']}/{neg})")
            print(f"    {m:<22} " + "  ".join(cells))
    print("\n[robustness, suite] poison accepted/offered per x; ECHO true accepted/offered")
    for arm, runs in arms.items():
        if arm == "NONE":
            continue
        print(f"  {arm}")
        for m in SHOW:
            cells = []
            for run in runs:
                row = next(r for r in run["suite_rows"] if _name(r) == m)
                cells.append(f"{_x(run)}:{row['poison_accepted']}/{row['poison_offered']}")
            print(f"    {m:<18} " + " ".join(cells))
        cells = []
        for run in runs:
            row = next(r for r in run["suite_rows"] if _name(r) == "ECHO")
            cells.append(f"{_x(run)}:{row['true_accepted']}/{row['true_offered']}")
        print(f"    {'ECHO true':<18} " + " ".join(cells))
        cells = []
        for run in runs:
            row = next(r for r in run["suite_rows"] if _name(r) == "MEDIAN+LV")
            cells.append(f"{_x(run)}:{row['true_accepted']}/{row['true_offered']}")
        print(f"    {'MEDIAN+LV true':<18} " + " ".join(cells))
        amp = [f"{_x(r)}:{next(s for s in r['suite_rows'] if _name(s) == 'ECHO')['amplification']}"
               for r in runs]
        print(f"    {'ECHO amplification':<18} " + " ".join(amp))
        amp = [f"{_x(r)}:{next(s for s in r['suite_rows'] if _name(s) == 'MEDIAN')['amplification']}"
               for r in runs]
        print(f"    {'MEDIAN amplif.':<18} " + " ".join(amp))
        s6 = [f"{_x(r)}:{r['stage6_poison']}" for r in runs
              if r["stage6_poison"].get("poison_decisions_bridged")]
        print(f"    stage6 poison: {s6 or 'none bridged'}")
    print("\n[break points] share (or identity share) where poison acceptance >= 0.5")
    for arm, agg, lv, share in data["break_points"]:
        name = agg + ("+LV" if lv else "")
        if name in SHOW and arm != "NONE":
            print(f"    {arm:<26} {name:<18} {share}")


def main() -> int:
    for arg in sys.argv[1:]:
        summarise(Path(arg))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
