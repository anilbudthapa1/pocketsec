"""Why does ECHO refuse true antibodies that MEDIAN+LV / ROOT_QUORUM accept? And does a
reduced ECHO (only the required mechanisms) close the gap?

For each (arm, x) run: every (receiver, TRUE foreign key) accepted by MEDIAN+LV but never
ELIGIBLE under ECHO is listed with ECHO's final status and reasons (tallied). Then the same
recorded traffic is replayed (``labs.partition.replay_with``) under:

* ``full``      — the shipped ``EchoConfig()``;
* ``required``  — only dependence clustering, cluster cap and local validation on (every
                  OPTIONAL ECHO term off: distance, trust, falsification weight, contest mass,
                  probation);
* ``no_distance`` / ``no_trust`` / ``no_probation`` / ``no_contest`` — one term off each;
* ``floor_half`` — MASS_FLOOR x 0.5 (the parameter the refusals name).

and ECHO's true acceptance, poison acceptance and amplification are printed for each.

    PYTHONHASHSEED=0 python benchmarks/stage7/echo_refusals.py [--all-receivers]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import RESULTS_DIR, loadavg  # noqa: E402

from pocketsec.stage7.aggregation.robust import Aggregator  # noqa: E402
from pocketsec.stage7.echo.inference import EchoConfig, EchoStatus  # noqa: E402
from pocketsec.stage7.labs.byzantine_suite import (  # noqa: E402
    _supported,
    _true_keys,
    accepted_keys,
    echo_metric,
)
from pocketsec.stage7.labs.fleet_corpus import build_fleet_corpus  # noqa: E402
from pocketsec.stage7.labs.partition import replay_with, simulate  # noqa: E402
from pocketsec.stage7.labs.simulated_fleet import (  # noqa: E402
    AdversaryArm,
    FleetSpec,
    default_receivers,
)

CASES = (("NONE", 0.0), ("BYZANTINE_POISON", 0.1), ("BYZANTINE_POISON", 0.2),
         ("BYZANTINE_LATENT_POISON", 0.2), ("SLOW_POISON", 0.2), ("COLLUSION_TIMING", 0.2),
         ("SYBIL_ADAPTIVE", 16))
D = EchoConfig()
CONFIGS = {
    "full": D,
    "required": replace(D, contextual_trust=False, epistemic_distance=False,
                        falsification_weight=False, contest_mass=False, probation=False),
    "no_distance": replace(D, epistemic_distance=False),
    "no_trust": replace(D, contextual_trust=False),
    "no_probation": replace(D, probation=False),
    "no_contest": replace(D, contest_mass=False),
    "floor_half": replace(D, mass_floor=D.mass_floor * 0.5),
}


def refusal_reasons(run) -> Counter:  # type: ignore[no-untyped-def,type-arg]
    median = accepted_keys(run, Aggregator.MEDIAN, lv=True)
    echo = accepted_keys(run, Aggregator.ECHO)
    true = _true_keys(run.truth)
    tally: Counter[str] = Counter()
    for host_id, rx in run.receivers.items():
        final = {}
        for inference in rx.inferences:
            for d in inference.decisions:
                final[d.antibody_key] = d
        for key in (set(median[host_id]) & true) - set(echo[host_id]):
            d = final.get(key)
            if d is None:
                tally["never_decided"] += 1
                continue
            tally[f"status={d.status.value}"] += 1
            for reason in d.reasons:
                tally[f"reason={reason.split(':')[0]}"] += 1
    return tally


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all-receivers", action="store_true")
    parser.add_argument("--corpus-seed", type=int, default=7)
    args = parser.parse_args()
    corpus = build_fleet_corpus(seed=args.corpus_seed)
    receivers = tuple(corpus.receivers()) if args.all_receivers else default_receivers(corpus)
    out: dict = {"receivers": receivers, "loadavg_start": loadavg(), "cases": []}  # type: ignore[type-arg]
    for arm_name, x in CASES:
        arm = AdversaryArm(arm_name)
        spec = (FleetSpec(arm=arm, sybils_per_root=int(x), receivers=receivers)
                if arm_name.startswith("SYBIL")
                else FleetSpec(arm=arm, adversary_share=x, receivers=receivers))
        run = simulate(corpus, spec)
        tally = refusal_reasons(run)
        rows = {}
        for name, config in CONFIGS.items():
            r = run if name == "full" else replay_with(run, config=config)
            rows[name] = {m: echo_metric(r, m) for m in
                          ("true_acceptance", "poison_acceptance", "amplification")}
        med = accepted_keys(run, Aggregator.MEDIAN, lv=True)
        true = _true_keys(run.truth)
        offered = sum(len((true & _supported(rx).keys())
                          - {a.antibody.antibody_key for a in run.fleet.local_antibodies(h)})
                      for h, rx in run.receivers.items())
        med_true = sum(len((set(med[h]) & true) - {a.antibody.antibody_key for a in run.fleet.local_antibodies(h)}) for h in run.receivers)
        case = {"arm": arm_name, "x": x, "refusals_of_keys_median_lv_accepted": dict(tally),
                "median_lv_true_accepted": med_true, "true_offered": offered,
                "configs": rows, "loadavg": loadavg()}
        out["cases"].append(case)
        print(f"\n== {arm_name} x={x}: MEDIAN+LV true {med_true}/{offered}; ECHO refusals of "
              f"those keys: {dict(tally)}")
        for name, metrics in rows.items():
            print(f"   {name:<13} " + "  ".join(
                f"{k} {'-' if v is None else f'{v:.3f}'}" for k, v in metrics.items()))
        sys.stdout.flush()
    tag = "all" if args.all_receivers else "default"
    path = RESULTS_DIR / f"stage7-echo-refusals-c{args.corpus_seed}-{tag}.json"
    path.write_text(json.dumps(out, indent=1, sort_keys=True, default=str) + "\n")
    print(f"wrote {path}; loadavg end {loadavg()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
