"""Rollback and canary under repetition: is every restore byte-identical, and does every
visible regression actually roll back (not just get logged)?

Usage::

    PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage6/rollback_stress.py \
        --promotions 12 --regressions 12 [--record EXPERIMENT_ID]

The gate (G6.8) exercises one automatic rollback and one corrupted fossil. This script
repeats the controller's reversibility claims many times on the gate's own rig
(``pocketsec/stage6/gate_rig.py``: the REAL ``LearningPromotionController``, fossil store
on disk and lineage DAG, with a lab chamber that mints real candidates). It says nothing
about what the real chamber would propose; it measures the one writer.

Phases, each counted:

A. ``--promotions`` candidates, each adding one single-step detector for a distinct object
   property bit, walked submit -> shadow -> canary -> trusted, then a full benign probation
   window. Control: spurious probation rollbacks on benign traffic (expected 0).
B. ``--regressions`` candidates, each REMOVING one resident detector, offline holdout benign
   only (so G2 cannot see the loss). Three variants rotate:
   B1 the regression is visible during the CANARY window -> must be REJECTED, never installed;
   B2 visible only on PROBATION traffic -> must roll back automatically to the byte-identical
      pre-promotion state;
   B3 never visible on any live traffic -> the honest miss (the rehearsal-gap limit).
C. Operator rollback to every fossil still held: digest and canonical bytes must match what
   was installed when that digest was current; a digest never fossilised must be refused.

``--collect-lineage`` calls ``controller.collect_lineage()`` after every promotion, as
``StageSixLearner.consolidate`` does in production once the DAG passes half its cap. The
original runs never collected, so their phase-C figures did not cover that regime
(review S6-R1 / honesty F2). A phase-C rollback whose restored digest differs from the one
requested is counted in ``substituted``.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import loadavg, record

from pocketsec.stage0.contracts.common import ContractError, digest_of_bytes
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.ssir.relations import Relation
from pocketsec.stage6 import gate_rig as rig
from pocketsec.stage6.chamber.evolution import CandidateKind
from pocketsec.stage6.constitution.learning import LifecycleState
from pocketsec.stage6.fossils.store import MAX_FOSSILS
from pocketsec.stage6.memory.semantic import MotifStep
from pocketsec.stage6.promotion.controller import PromotionDecision, RollbackTrigger
from pocketsec.stage6.shadow.mind import session_touches_protected

#: Object-semantics bits used for the synthetic detectors. Bits that carry protected
#: meaning (credential, persistence, ...) are fine here: the rig scores motifs only.
#: (relation, bit) pairs: 45 distinct single-step detectors, enough to exceed MAX_FOSSILS.
BITS = tuple((rel, bit) for rel in (Relation.READ, Relation.WRITE, Relation.SEND)
             for bit in range(15))


def _steps(key, tag: str):
    rel, bit = key
    return [rig._step(rel, props=1 << bit, group=tag),
            rig._step(Relation.READ, actor=1, actor_class=2, group=tag + "b")]


def _motif(key):
    rel, bit = key
    return (MotifStep(int(rel), 1 << bit, 0, 0),)


def _probation(c, sessions) -> list:
    return [r for s in sessions if (r := c.observe_probation(s)) is not None]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--promotions", type=int, default=12)
    parser.add_argument("--regressions", type=int, default=12)
    parser.add_argument("--record", default=None)
    parser.add_argument("--collect-lineage", action="store_true")
    args = parser.parse_args()
    folded = [0]

    def collect() -> None:
        if args.collect_lineage:
            folded[0] += c.collect_lineage()

    started, before = time.perf_counter(), loadavg()
    directory = Path(tempfile.mkdtemp(prefix="s6-rollback-"))
    world = rig.build_world(directory)
    c = world.controller
    installed = {c.mind.digest(): c.mind.current().canonical_bytes()}
    order = [c.mind.digest()]
    probation_len = rig.RIG_POLICY.probation_sessions
    a = {"attempted": 0, "promoted": 0, "spurious_rollbacks": 0}
    for k in range(min(args.promotions, len(BITS))):
        a["attempted"] += 1
        bit = BITS[k]
        holdout = [rig.skeleton(f"ah{k}", _steps(bit, f"ah{k}"), Verdict.MALICIOUS),
                   rig.benign_holdout(f"ahb{k}")]
        cand = world.chamber.mint(c.mind.current(), add=(_motif(bit),), holdout=holdout)
        walked = rig.walk(world, cand, holdout=holdout, shadow=rig.shadow_traffic(0, tag=f"as{k}"))
        if walked[-1].to_state is LifecycleState.TRUSTED:
            a["promoted"] += 1
            installed[c.mind.digest()] = c.mind.current().canonical_bytes()
            order.append(c.mind.digest())
        a["spurious_rollbacks"] += len(_probation(c, rig.benign_traffic(probation_len, f"ap{k}")))
        collect()
    items_after_a = c.mind.current().items
    a["lineage_complete_items"] = sum(world.dag.lineage_complete(i) for i in items_after_a)
    a["trusted_items"] = len(items_after_a)
    a["dag_verify_problems"] = len(world.dag.verify())
    b = {v: {"attempted": 0, "rejected_at_canary": 0, "installed": 0, "auto_rollbacks": 0,
             "restored_exact": 0, "missed": 0} for v in ("B1", "B2", "B3")}
    trials: list[dict] = []
    for j in range(args.regressions):
        variant = ("B1", "B2", "B3")[j % 3]
        state = c.mind.current()
        detectors = sorted(state.detectors(), key=lambda i: i.item_id)
        if not detectors:
            break
        victim = detectors[j % len(detectors)]
        bit = (Relation(victim.motif[0].relation),
               victim.motif[0].require_properties.bit_length() - 1)
        pre, pre_bytes = c.mind.digest(), state.canonical_bytes()
        holdout = [rig.benign_holdout(f"bh{j}")]
        cand = world.chamber.mint(state, remove=(victim.item_id,), holdout=holdout,
                                  kinds=frozenset({CandidateKind.CONSOLIDATION}))
        row = b[variant]
        row["attempted"] += 1
        protected = bool(session_touches_protected(_steps(bit, "probe")))
        trial = {"variant": variant, "bit": [int(bit[0]), bit[1]], "protected": protected,
                 "outcome": None}
        trials.append(trial)
        offline = c.submit(cand, holdout=holdout, hostile=(), variant_seed=j)
        if offline.to_state is LifecycleState.REJECTED:
            continue
        if c.run_shadow(cand.candidate_id, rig.shadow_traffic(0, tag=f"bs{j}")
                        ).to_state is LifecycleState.REJECTED:
            continue
        c.promote_canary(cand.candidate_id)
        canary = rig.benign_traffic(rig.RIG_POLICY.window_sessions - 1, f"bc{j}")
        canary.append(rig.session(f"bcm{j}", _steps(bit, f"bcm{j}"), Verdict.MALICIOUS)
                      if variant == "B1" else rig.benign_traffic(1, f"bcx{j}")[0])
        rejected = False
        for s in canary:
            if isinstance(c.observe_canary(s), PromotionDecision):
                rejected = True
                break
        if rejected:
            row["rejected_at_canary"] += 1
            trial["outcome"] = "rejected_at_canary"
            continue
        c.promote_trusted(cand.candidate_id)
        row["installed"] += 1
        live = rig.benign_traffic(probation_len - (variant == "B2"), f"bp{j}")
        if variant == "B2":
            live.insert(3, rig.session(f"bpm{j}", _steps(bit, f"bpm{j}"), Verdict.MALICIOUS))
        rolled = _probation(c, live)
        collect()
        trial["outcome"] = "auto_rollback" if rolled else "installed_and_kept"
        if rolled:
            row["auto_rollbacks"] += 1
            row["restored_exact"] += int(c.mind.digest() == pre
                                         and c.mind.current().canonical_bytes() == pre_bytes
                                         and rolled[0].restored_bytes_identical is True)
        else:
            row["missed"] += 1
            installed[c.mind.digest()] = c.mind.current().canonical_bytes()
            order.append(c.mind.digest())
    held = [d for d in dict.fromkeys(order) if world.store.get(d) is not None]
    evicted = [d for d in dict.fromkeys(order) if world.store.get(d) is None]
    cphase = {"fossils_held": len(held), "rollbacks": 0, "digest_match": 0, "bytes_match": 0,
              "refused": 0, "refusal_reasons": [], "substituted": 0,
              "collect_lineage": args.collect_lineage, "nodes_folded": folded[0]}
    for d in reversed(held):
        try:
            rb = c.rollback_learning(trigger=RollbackTrigger.OPERATOR_REQUEST, to_digest=d)
        except ContractError as exc:
            cphase["refused"] += 1
            cphase["refusal_reasons"].append(str(exc)[:120])
            continue
        cphase["rollbacks"] += 1
        cphase["substituted"] += int(rb.to_digest != d)
        cphase["digest_match"] += int(c.mind.digest() == d == rb.to_digest)
        cphase["bytes_match"] += int(c.mind.current().canonical_bytes() == installed[d])
    cphase["evicted_states"] = len(evicted)
    cphase["evicted_rollback_refused"] = 0
    for d in evicted:
        try:
            c.rollback_learning(trigger=RollbackTrigger.OPERATOR_REQUEST, to_digest=d)
        except ContractError:
            cphase["evicted_rollback_refused"] += 1
    never = digest_of_bytes(b"a state this controller never fossilised")
    try:
        c.rollback_learning(trigger=RollbackTrigger.OPERATOR_REQUEST, to_digest=never)
        cphase["unfossilised_refused"] = False
    except ContractError:
        cphase["unfossilised_refused"] = True
    wall, after = time.perf_counter() - started, loadavg()
    visible = [t for t in trials if t["variant"] in ("B1", "B2") and t["outcome"]]
    split = {p: {"visible_regressions": sum(t["protected"] == p for t in visible),
                 "acted_on": sum(t["protected"] == p and t["outcome"] != "installed_and_kept"
                                 for t in visible)} for p in (True, False)}
    out = {"A": a, "B": b, "C": cphase, "trials": trials,
           "visible_regressions_by_protected": {str(k): v for k, v in split.items()}, "max_fossils": MAX_FOSSILS,
           "distinct_states_installed": len(order), "wall_seconds": round(wall, 2),
           "loadavg": [before, after], "rig_policy": {
               "window": rig.RIG_POLICY.window_sessions, "probation": probation_len}}
    print(json.dumps(out, indent=1, sort_keys=True))
    if args.record:
        record(
            experiment_id=args.record, hypothesis="H6",
            title="Stage 6 rollback/canary under repetition on the gate rig",
            slot_name="stage6-learning-boundary", dataset_name="stage6-gate-rig",
            dataset_version="gate_rig+rollback-stress-v0",
            dataset_sha256=digest_of_bytes(json.dumps(order).encode()),
            seeds={"rig": 0},
            notes=json.dumps({"A": a, "B": b, "split": out["visible_regressions_by_protected"],
                              "C": {k: v for k, v in cphase.items()
                                                     if k != "refusal_reasons"}}),
            payload=out,
            command="PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage6/rollback_stress.py "
                    + " ".join(sys.argv[1:]),
        )


if __name__ == "__main__":
    main()
