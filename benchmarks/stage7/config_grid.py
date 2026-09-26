"""ECHO configurations on identical recorded traffic, across every adversary arm and share.

The fabric's traffic is simulated once per (arm, x) and replayed under each ``EchoConfig``
with ``labs.partition.replay_with`` (same pools, same local validation): a controlled
ablation, not a new simulation. Metrics per config: ECHO true-antibody acceptance, poison
acceptance, amplification (``byzantine_suite.echo_metric``) and counterfactual detection
(``byzantine_suite.detection``: recall at FPR 0.01 on locally-unseen families, FP rate).

Configs: ``full`` (shipped), ``no_distance`` (epistemic distance off), ``req+probation``
(only clustering, cap, local validation and probation), ``required`` (clustering, cap,
local validation only).

    PYTHONHASHSEED=0 python benchmarks/stage7/config_grid.py [--corpus-seed 7] [--all-receivers]
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import RESULTS_DIR, loadavg  # noqa: E402

from pocketsec.stage7.aggregation.robust import Aggregator  # noqa: E402
from pocketsec.stage7.echo.inference import EchoConfig  # noqa: E402
from pocketsec.stage7.labs.byzantine_suite import (  # noqa: E402
    SHARES,
    SYBIL_COUNTS,
    accepted_keys,
    detection,
    echo_metric,
)
from pocketsec.stage7.labs.fleet_corpus import build_fleet_corpus  # noqa: E402
from pocketsec.stage7.labs.partition import replay_with, simulate  # noqa: E402
from pocketsec.stage7.labs.simulated_fleet import (  # noqa: E402
    AdversaryArm,
    FleetSpec,
    default_receivers,
)

D = EchoConfig()
_REQ = dict(contextual_trust=False, epistemic_distance=False, falsification_weight=False,
            contest_mass=False)
CONFIGS = {
    "full": D,
    "no_distance": replace(D, epistemic_distance=False),
    "req+probation": replace(D, **_REQ),
    "required": replace(D, **_REQ, probation=False),
}
ARMS = ("NONE", "BYZANTINE_POISON", "BYZANTINE_LATENT_POISON", "SLOW_POISON",
        "COLLUSION_TIMING", "BYZANTINE_SUPPRESS", "SYBIL_DECLARED_ROOT", "SYBIL_FORGED_ROOTS",
        "SYBIL_ADAPTIVE")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus-seed", type=int, default=7)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--all-receivers", action="store_true")
    args = parser.parse_args()
    corpus = build_fleet_corpus(seed=args.corpus_seed)
    receivers = tuple(corpus.receivers()) if args.all_receivers else default_receivers(corpus)
    out: dict = {"corpus_seed": args.corpus_seed, "receivers": receivers,  # type: ignore[type-arg]
                 "loadavg_start": loadavg(), "rows": []}
    for arm_name in ARMS:
        arm = AdversaryArm(arm_name)
        xs = SYBIL_COUNTS if arm_name.startswith("SYBIL") else (
            (0.0,) if arm_name == "NONE" else SHARES[1:])
        for x in xs:
            spec = (FleetSpec(arm=arm, sybils_per_root=int(x), seed=args.seed,
                              receivers=receivers) if arm_name.startswith("SYBIL")
                    else FleetSpec(arm=arm, adversary_share=x, seed=args.seed,
                                   receivers=receivers))
            run = simulate(corpus, spec)
            cells = []
            for name, config in CONFIGS.items():
                r = run if name == "full" else replay_with(run, config=config)
                recall, fp = detection(r, accepted_keys(r, Aggregator.ECHO))
                row = {"arm": arm_name, "x": x, "config": name, "recall": recall, "fp_rate": fp,
                       **{m: echo_metric(r, m) for m in
                          ("true_acceptance", "poison_acceptance", "amplification")}}
                out["rows"].append(row)
                f = lambda v: "-" if v is None else f"{v:.3f}"  # noqa: E731
                cells.append(f"{name}: rec {f(recall)} fp {f(fp)} true {f(row['true_acceptance'])}"
                             f" poison {f(row['poison_acceptance'])} amp {f(row['amplification'])}")
            print(f"{arm_name} x={x}\n    " + "\n    ".join(cells), flush=True)
    out["loadavg_end"] = loadavg()
    tag = "all" if args.all_receivers else "default"
    path = RESULTS_DIR / f"stage7-config-grid-c{args.corpus_seed}-{tag}.json"
    path.write_text(json.dumps(out, indent=1, sort_keys=True, default=str) + "\n")
    print(f"wrote {path}; loadavg {out['loadavg_start']} -> {out['loadavg_end']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
