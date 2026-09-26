"""Stage 7 — adversary-fraction sweep: every aggregator on identical pools, through run_benchmark.

For each (arm, adversary share or Sybil count) this script simulates the fleet ONCE with a
real ``OrpheusFabric`` per receiver and a real lab Stage 6 gateway behind the bridge
(``labs.partition.simulate(..., with_stage6=True)``), then, on that one run:

* ``byzantine_suite.evaluate_run`` gives the suite's canonical poison / true acceptance and
  amplification for every aggregator (plain and +LV) and ECHO;
* each aggregator's accepted antibody set is installed on its receiver and scored through
  Stage 0's ``run_benchmark`` (:mod:`_common`) -> recall at FPR 0.01 on locally-unseen
  families, FP rate and TP/FP counts (``counterfactual_at_boundary``);
* the poison keys ECHO bridged are followed into Stage 6: the buckets Stage 6's real
  ``QuarantineGateway.admit`` returned for them, and how many were TRUSTED_CANDIDATE.

The receivers are ``default_receivers`` (the gate's 4) unless ``--all-receivers``, which scores
every corpus host (a larger positive set; the gate's n is small). Nothing is registered unless
``--record ID`` is given.

    PYTHONHASHSEED=0 python benchmarks/stage7/fraction_sweep.py [--corpus-seed 7] [--seed 0]
        [--all-receivers] [--arms NONE,BYZANTINE_POISON,...] [--out results/x.json]
        [--record PS-S7-...]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import (  # noqa: E402
    RESULTS_DIR,
    AntibodySetSlot,
    bench,
    episode_id,
    loadavg,
    record,
    write_heldout_dataset,
)

from pocketsec.stage7.aggregation.robust import Aggregator  # noqa: E402
from pocketsec.stage7.labs.byzantine_suite import (  # noqa: E402
    SHARES,
    SYBIL_ARMS,
    SYBIL_COUNTS,
    _invariants,
    accepted_keys,
    break_points,
    evaluate_run,
)
from pocketsec.stage7.labs.fleet_corpus import build_fleet_corpus, fleet_preconditions  # noqa: E402
from pocketsec.stage7.labs.partition import simulate  # noqa: E402
from pocketsec.stage7.labs.simulated_fleet import (  # noqa: E402
    AdversaryArm,
    FleetSpec,
    default_receivers,
)

DEFAULT_ARMS = (
    "NONE", "BYZANTINE_POISON", "BYZANTINE_LATENT_POISON", "SLOW_POISON", "COLLUSION_TIMING",
    "BYZANTINE_SUPPRESS", "SYBIL_DECLARED_ROOT", "SYBIL_FORGED_ROOTS", "SYBIL_ADAPTIVE",
)
#: Methods scored through run_benchmark (the lead's baselines + the §7 controls + ECHO).
BENCH_METHODS: tuple[tuple[Aggregator, bool], ...] = (
    (Aggregator.NO_SHARING, False), (Aggregator.MAJORITY, False), (Aggregator.MEAN, False),
    (Aggregator.MEDIAN, False), (Aggregator.TRIMMED_MEAN, False), (Aggregator.MEDIAN, True),
    (Aggregator.TRIMMED_MEAN, True), (Aggregator.VALIDATION_FILTER, False),
    (Aggregator.ROOT_QUORUM, False), ("ROOT_QUORUM_DECLARED", False), (Aggregator.ECHO, False),
)


def _declared_root_quorum(sim) -> dict[str, dict[str, int]]:  # type: ignore[no-untyped-def]
    """ROOT_QUORUM with DECLARED roots as clusters (``clusters=None``): the same rule as the
    suite's ROOT_QUORUM minus the dependence graph. Isolates what the graph adds or removes."""
    from pocketsec.stage7.aggregation.robust import aggregate, stance_matrix
    from pocketsec.stage7.labs.byzantine_suite import _antibody_pool, _local_ok

    result: dict[str, dict[str, int]] = {}
    for host_id, receiver in sim.receivers.items():
        first: dict[str, int] = {}
        local_ok = _local_ok(receiver)
        for round_index in range(sim.spec.rounds):
            pool = _antibody_pool(receiver, round_index)
            if not pool:
                continue
            outcome = aggregate(stance_matrix(pool), Aggregator.ROOT_QUORUM, clusters=None,
                                local_ok=local_ok)
            for key in outcome.accepted:
                first.setdefault(key, round_index)
        result[host_id] = first
    return result


def _specs(arm: AdversaryArm, seed: int, receivers: tuple[str, ...]) -> list[FleetSpec]:
    if arm in SYBIL_ARMS:
        return [FleetSpec(arm=arm, sybils_per_root=s, seed=seed, receivers=receivers)
                for s in SYBIL_COUNTS]
    shares = (0.0,) if arm is AdversaryArm.NONE else SHARES
    return [FleetSpec(arm=arm, adversary_share=x, seed=seed, receivers=receivers) for x in shares]


def _poison_into_stage6(run) -> dict[str, int]:  # type: ignore[no-untyped-def]
    """Stage 6 buckets returned for capsules bridged from POISON keys, over all receivers."""
    poison = run.truth.poison_keys
    buckets: Counter[str] = Counter()
    decisions = 0
    for receiver in run.receivers.values():
        bridge = receiver.components.bridge
        if bridge is None:
            continue
        for receipt in bridge.receipts():
            if receipt.antibody_key in poison:
                decisions += 1
                buckets.update(receipt.stage6_buckets)
        buckets["receipts_evicted"] += bridge.stats().get("receipts_evicted", 0)
    return {"poison_decisions_bridged": decisions, **dict(buckets)}


def run(args: argparse.Namespace) -> dict:  # type: ignore[type-arg]
    corpus = build_fleet_corpus(seed=args.corpus_seed)
    pre = fleet_preconditions(corpus)
    receivers = tuple(corpus.receivers()) if args.all_receivers else default_receivers(corpus)
    tag = "all" if args.all_receivers else "default"
    dataset = write_heldout_dataset(
        corpus, receivers, RESULTS_DIR / f"stage7-heldout-c{args.corpus_seed}-{tag}.jsonl")
    episodes = {episode_id(e.host_id, e.index): e for e in corpus.episodes if not e.history}
    out: dict = {"corpus_seed": args.corpus_seed, "seed": args.seed, "receivers": receivers,
                 "dataset_sha256": dataset.sha256, "items": len(dataset),
                 "positives": dataset.positive_count,
                 "preconditions": [(p.name, p.status, p.detail) for p in pre],
                 "loadavg_start": loadavg(), "runs": []}
    suite_rows = []
    arms = [AdversaryArm(a) for a in args.arms.split(",")]
    for arm in arms:
        for spec in _specs(arm, args.seed, receivers):
            t0 = time.perf_counter()
            sim = simulate(corpus, spec, with_stage6=True)
            rows = evaluate_run(sim)
            suite_rows.extend(rows)
            benches = []
            for method, lv in BENCH_METHODS:
                if method == "ROOT_QUORUM_DECLARED":
                    accepted = _declared_root_quorum(sim)
                elif method is Aggregator.NO_SHARING:
                    accepted = {h: {} for h in sim.receivers}
                else:
                    accepted = accepted_keys(sim, method, lv=lv)
                installed = {}
                for host_id, rx in sim.receivers.items():
                    rows_by_key = _invariants(rx)
                    local = [a.antibody.invariant for a in sim.fleet.local_antibodies(host_id)]
                    installed[host_id] = local + [rows_by_key[k] for k in accepted[host_id]
                                                  if k in rows_by_key]
                name = f"{getattr(method, 'value', method)}{'+LV' if lv else ''}"
                slot = AntibodySetSlot(slot_name=f"s7-{name.lower().replace('+', '-')}",
                                       installed=installed, episodes=episodes)
                result = bench(slot, dataset, args.record or "PS-S7-20260926-H8-fraction-sweep-9999", args.seed)
                poison_installed = sum(len(set(accepted[h]) & sim.truth.poison_keys)
                                       for h in sim.receivers)
                benches.append({"method": name, "poison_installed": poison_installed, **result})
            entry = {
                "arm": arm.value, "share": spec.adversary_share,
                "sybils_per_root": spec.sybils_per_root,
                "suite_rows": [r.__dict__ if hasattr(r, "__dict__") else
                               {f: getattr(r, f) for f in r.__slots__} for r in rows],
                "bench": benches, "stage6_poison": _poison_into_stage6(sim),
                "wall_s": round(time.perf_counter() - t0, 2), "loadavg": loadavg(),
            }
            out["runs"].append(entry)
            _print(entry)
    out["break_points"] = [(b.arm, b.aggregator, b.lv, b.share) for b in break_points(suite_rows)]
    out["loadavg_end"] = loadavg()
    return out


def _print(entry: dict) -> None:  # type: ignore[type-arg]
    x = entry["sybils_per_root"] if entry["arm"].startswith("SYBIL") else entry["share"]
    print(f"\n== {entry['arm']} x={x}  wall {entry['wall_s']}s load {entry['loadavg']}  "
          f"stage6_poison {entry['stage6_poison']}")
    for r in entry["suite_rows"]:
        name = r["aggregator"] + ("+LV" if r["lv"] else "")
        print(f"   suite {name:<22} poison {r['poison_accepted']:>3}/{r['poison_offered']:<3} "
              f"true {r['true_accepted']:>3}/{r['true_offered']:<3} amp {r['amplification']}")
    for b in entry["bench"]:
        print(f"   bench {b['method']:<22} recall@0.01 {b['recall_at_fpr_budget']} "
              f"tp {b['tp']}/{b['positives']} fp {b['fp']} fpr {b['fp_rate']} "
              f"poison_installed {b['poison_installed']}")
    sys.stdout.flush()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus-seed", type=int, default=7)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--all-receivers", action="store_true")
    parser.add_argument("--arms", default=",".join(DEFAULT_ARMS))
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--record", default=None)
    args = parser.parse_args()
    out = run(args)
    print("\nbreak points (share where poison acceptance >= 0.5; None = none in sweep):")
    for arm, agg, lv, share in out["break_points"]:
        print(f"   {arm:<26} {agg}{'+LV' if lv else '':<4} {share}")
    print(f"loadavg start {out['loadavg_start']} end {out['loadavg_end']}")
    path = args.out or RESULTS_DIR / (
        f"stage7-fraction-sweep-c{args.corpus_seed}-s{args.seed}"
        f"-{'all' if args.all_receivers else 'default'}.json")
    path.write_text(json.dumps(out, indent=1, sort_keys=True, default=str) + "\n")
    print(f"wrote {path}")
    if args.record:
        record(experiment_id=args.record, hypothesis="H8",
               title="Stage 7 adversary-fraction sweep: aggregators vs ECHO, run_benchmark detection",
               slot_name="stage7-antibody-set", dataset_name="stage7-fleet-heldout",
               dataset_version="stage7-fleet-corpus-v0.1.0", dataset_sha256=out["dataset_sha256"],
               seeds={"corpus": args.corpus_seed, "fleet": args.seed},
               notes=json.dumps({"receivers": out["receivers"], "arms": args.arms,
                                 "break_points": out["break_points"]}, default=str),
               payload=out, command=" ".join(sys.argv))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
