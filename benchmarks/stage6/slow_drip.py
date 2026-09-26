"""Slow-drip poisoning across MANY corroborated epochs: poisoned vs clean promotion rates.

Usage::

    PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage6/slow_drip.py \
        --epochs 2 4 8 --drip 2 [--threshold 0.6] [--record EXPERIMENT_ID]

The eleven spec arms (``labs/poison_suite.py``) each span at most one corroborated change.
The project lead's standing order asks for a slow-drip adversary that feeds attack
behaviour *labelled or presented as benign over many epochs*. Three drips, each built with
the suite's own ``_ArmBuilder`` (one Stage 1 pipeline per arm, session-unique identities)
and scored by the suite's own ``run_arm`` (poisoned = attack steps a trusted BASELINE came
to explain + targets detected before the poison and suppressed after it; clean = the
legitimate normality/detection the same run should still achieve):

* ``DRIP-DATA``  — ``drip`` escalation-free attacker staging sessions per epoch (P1's
  step, a fresh lineage each session, as a repeated attacker job looks), for ``epochs``
  corroborated changes, interleaved with routine traffic.
* ``DRIP-LABEL-1G`` — F2 is first learned from the two-analyst MALICIOUS quorum; then
  ``drip`` F2 sessions per epoch are labelled BENIGN by ONE attacker-controlled analyst
  group.
* ``DRIP-LABEL-2G`` — the same, but BENIGN is asserted by TWO colluding groups, which
  meets ``MIN_INDEPENDENT_LABEL_GROUPS`` (2): the quorum itself is the thing attacked.

Learners: Stage 6, NaiveFinetune (the attack must be real), Stage2Only, AcceptNothing.
``--threshold`` is the diagnostic genesis threshold (see ``_common.genesis_threshold``);
omitted, the shipped ``DEFAULT_THRESHOLD`` is used.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict, replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import genesis_threshold, loadavg, record

from pocketsec.stage0.contracts.common import digest_of_bytes
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage6.capsule.experience_capsule import LabelOrigin
from pocketsec.stage6.labs import poison_suite as ps
from pocketsec.stage6.labs.continual_baselines import (
    AcceptNothing,
    NaiveFinetune,
    Stage2Only,
)
from pocketsec.stage6.labs.endurance import StageSixLearner
from pocketsec.stage6.labs.endurance_corpus import (
    ENDURANCE_SEED,
    POISON_ANALYST_GROUP,
    SessionLabel,
)

ROUTINE_PER_EPOCH = 24
WARMUP = 160  # fills the 128-session shadow window before any poison lands


def _drip_data(epochs: int, drip: int, seed: int) -> ps.PoisonScenario:
    arm = ps._ARMS["P1"]
    b = ps._ArmBuilder(arm, multiplier=1, seed=seed, background=WARMUP)
    clean = b.routine(WARMUP)
    poison = []
    for _ in range(epochs):
        clean += b.routine(ROUTINE_PER_EPOCH // 2)
        poison += b.attacker("P1", drip)
        clean += b.routine(ROUTINE_PER_EPOCH // 2)
        b.change()
    clean += b.routine(ROUTINE_PER_EPOCH)
    s = b.scenario(poison_steps=ps._groups_steps(poison), clean_steps=ps._groups_steps(clean))
    return replace(s, arm=replace(arm, arm_id="DRIP-DATA",
                                  title=f"P1 staging, {drip}/epoch over {epochs} epochs"))


def _drip_label(epochs: int, drip: int, seed: int, groups: int) -> ps.PoisonScenario:
    arm = ps._ARMS["P3"]
    b = ps._ArmBuilder(arm, multiplier=1, seed=seed, background=WARMUP)
    probes = [b.probe("F2") for _ in range(2)]
    b.routine(WARMUP // 2)
    for _ in range(3):
        b.family("F2", ps._MAL)
    b.routine(WARMUP // 2)
    liars = tuple(SessionLabel(Verdict.BENIGN, LabelOrigin.ANALYST,
                               POISON_ANALYST_GROUP + ("" if i == 0 else f"-{i}"))
                  for i in range(groups))
    for _ in range(epochs):
        b.routine(ROUTINE_PER_EPOCH // 2)
        for _ in range(drip):
            b.family("F2", liars, poisoned=True)
        b.routine(ROUTINE_PER_EPOCH // 2)
        b.change()
    b.routine(ROUTINE_PER_EPOCH)
    s = b.scenario(target_episodes=tuple(probes), clean_episodes=tuple(probes))
    name = f"DRIP-LABEL-{groups}G"
    return replace(s, arm=replace(arm, arm_id=name,
                                  title=f"F2 labelled BENIGN by {groups} group(s), {drip}/epoch "
                                        f"over {epochs} epochs"))


def _learners(scenario):
    g = scenario.genesis
    return [StageSixLearner(g, seed=ENDURANCE_SEED), NaiveFinetune(g), Stage2Only(g),
            AcceptNothing(g)]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--epochs", type=int, nargs="+", default=[2, 4, 8])
    parser.add_argument("--drip", type=int, default=2)
    parser.add_argument("--threshold", type=float, default=None)
    parser.add_argument("--seed", type=int, default=ENDURANCE_SEED)
    parser.add_argument("--record", default=None)
    args = parser.parse_args()
    rows, stage6_counters, capsule_ids = [], {}, []
    started, before = time.perf_counter(), loadavg()
    with genesis_threshold(args.threshold):
        for epochs in args.epochs:
            for build in (lambda e: _drip_data(e, args.drip, args.seed),
                          lambda e: _drip_label(e, args.drip, args.seed, 1),
                          lambda e: _drip_label(e, args.drip, args.seed, 2)):
                scenario = build(epochs)
                capsule_ids += [c.capsule_id for c in (*scenario.clean, *scenario.poisoned)]
                for learner in _learners(scenario):
                    row = ps.run_arm(scenario, learner)
                    out = {**asdict(row), "epochs": epochs, "drip": args.drip,
                           "poison_goal": len(scenario.poison_steps)
                           + len(scenario.target_episodes),
                           "clean_goal": len(scenario.clean_steps) + len(scenario.clean_episodes)}
                    if isinstance(learner, StageSixLearner):
                        c = learner.counters
                        stage6_counters[f"{row.arm_id}-e{epochs}"] = {
                            k: c[k] for k in ("promoted", "rejected_offline_or_shadow",
                                              "rejected_canary", "probation_rollbacks",
                                              "learning_deferred_short_ring",
                                              "drift_dropped_admissions")
                        } | {"items": len(learner.trusted_state().items),
                             "single_source_refusals":
                                 learner.gateway.stats().get("single_source_refusals")}
                        out["stage6_counters"] = stage6_counters[f"{row.arm_id}-e{epochs}"]
                    rows.append(out)
                    print(json.dumps(out, sort_keys=True, default=str), flush=True)
    wall, after = time.perf_counter() - started, loadavg()
    print(f"# wall {wall:.1f} s, loadavg {before} -> {after}")
    if args.record:
        record(
            experiment_id=args.record, hypothesis="H6",
            title="Stage 6 slow-drip poisoning over many corroborated epochs",
            slot_name="stage6-learning-boundary", dataset_name="stage6-slow-drip",
            dataset_version=ps.POISON6_VERSION + "+slow-drip-v0",
            dataset_sha256=digest_of_bytes(json.dumps(capsule_ids).encode("utf-8")),
            seeds={"arm": args.seed},
            notes=json.dumps([{k: r[k] for k in ("arm_id", "learner", "epochs",
                                                   "poisoned_promotions", "clean_promotions",
                                                   "poison_goal", "clean_goal")}
                              for r in rows]) + f"; threshold {args.threshold}; wall "
                  f"{wall:.1f}s loadavg {before}->{after}",
            payload={"rows": rows, "threshold": args.threshold, "drip": args.drip,
                     "wall_seconds": wall, "loadavg": [before, after]},
            command="PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage6/slow_drip.py "
                    + " ".join(sys.argv[1:]),
        )


if __name__ == "__main__":
    main()
