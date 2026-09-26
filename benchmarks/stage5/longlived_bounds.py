"""State bounds and liveness of ONE long-lived Stage 5 executor stack.

Usage: ``python benchmarks/stage5/longlived_bounds.py [N] [--record EXPERIMENT_ID]``

``labs.baselines.build_rig`` builds a fresh kernel, journal, token store, lease registry
and governor for every case, so the gate's G5.12 figures (max journal 3296 B, max 1
active lease) are per-case and never approach a bound. Here one stack of those
components serves a stream of N hostile SUSPEND_PROCESS actions (each on its own
simulated host), with a ``ManualClock`` that moves only when this script moves it.

Regime A: advance past the lease's hard deadline and run ``LeaseSweeper.sweep`` after
every action (the healthy operating regime). Regime B: never sweep, advance 30 s per
action. Part C: 60 actions under regime B, then the clock is moved past every hard
deadline with no sweep, and the hosts are inspected: a containment whose lease *data*
says expired but whose host is still suspended is a change nothing will undo.
"""

from __future__ import annotations

import argparse
import collections
import json
import secrets
import sys
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import loadavg, record  # noqa: E402

from pocketsec.stage5.authority.tokens import MAX_SPENT_NONCES, TokenStore  # noqa: E402
from pocketsec.stage5.constitution.invariants import FROZEN_CONSTITUTION  # noqa: E402
from pocketsec.stage5.evidence.preservation_gate import (  # noqa: E402
    DEFAULT_RETENTION,
    EvidencePreservationGate,
)
from pocketsec.stage5.executor.identity import ManualClock  # noqa: E402
from pocketsec.stage5.executor.journal import (  # noqa: E402
    MAX_JOURNAL_BYTES,
    MAX_JOURNAL_ENTRIES,
    RollbackJournal,
)
from pocketsec.stage5.executor.lease import (  # noqa: E402
    MAX_CONCURRENT_LEASES,
    LeaseRegistry,
    LeaseSweeper,
)
from pocketsec.stage5.executor.transactional import TransactionalExecutor  # noqa: E402
from pocketsec.stage5.executor.verify import PostconditionProbe  # noqa: E402
from pocketsec.stage5.governor import ResourceGovernor  # noqa: E402
from pocketsec.stage5.host.simulated import ProcessState  # noqa: E402
from pocketsec.stage5.labs.baselines import _grant, build_rig  # noqa: E402
from pocketsec.stage5.labs.response_corpus import (  # noqa: E402
    CORPUS_INVARIANTS,
    RESPONSE_CORPUS_VERSION,
    build_response_corpus,
    corpus_digest,
)
from pocketsec.stage5.memory.effectiveness import (  # noqa: E402
    MAX_EFFECTIVENESS_RECORDS,
    EffectivenessMemory,
    LearningSource,
)
from pocketsec.stage5.sentinel.kernel import SentinelKernel  # noqa: E402


def stack(signer: str):  # type: ignore[no-untyped-def]
    clock = ManualClock(at=1_000)
    return {
        "clock": clock,
        "kernel": SentinelKernel(constitution=FROZEN_CONSTITUTION, invariants=CORPUS_INVARIANTS,
                                 clock=clock),
        "journal": RollbackJournal(),
        "leases": LeaseRegistry(clock=clock),
        "gate": EvidencePreservationGate(policy=DEFAULT_RETENTION, invariants=CORPUS_INVARIANTS),
        "governor": ResourceGovernor(),
        "probe": PostconditionProbe(invariants=CORPUS_INVARIANTS),
        "tokens": TokenStore(key=secrets.token_bytes(32), signer=signer, clock=clock),
        "memory": EffectivenessMemory(),
    }


def act(s, case, index, tag):  # type: ignore[no-untyped-def]
    rig = build_rig(case)
    candidate = next(c for c in rig.field.candidates
                     if c.operator.spec.operator_id == "SUSPEND_PROCESS")
    executor = TransactionalExecutor(
        kernel=s["kernel"], host=rig.host, journal=s["journal"], gate=s["gate"],
        governor=s["governor"], leases=s["leases"], probe=s["probe"], clock=s["clock"],
        tokens=s["tokens"])
    token = s["tokens"].mint(grant=_grant(candidate, human=False), operator=candidate.operator,
                             action_id=f"{tag}.{index}", ttl_seconds=900)
    receipt = executor.execute(candidate.operator, token, resolution=case.resolution)
    return rig, candidate, executor, receipt


def run_regime(cases, regime: str) -> dict:  # type: ignore[no-untyped-def]
    s = stack(f"measure.{regime}")
    outcomes, first, deny = collections.Counter(), {}, collections.Counter()
    checkpoints = []
    tracemalloc.start()
    base = tracemalloc.get_traced_memory()[0]
    for index, case in enumerate(cases):
        _rig, _cand, executor, receipt = act(s, case, index, regime)
        outcome = receipt.outcome.value
        outcomes[outcome] += 1
        first.setdefault(outcome, index)
        if outcome == "REFUSED_SENTINEL":
            deny.update(str(reason) for reason in receipt.sentinel_verdict.reasons)
        s["memory"].observe(receipt, source=LearningSource.LAB_SANDBOX, mechanism_id="m")
        if regime == "A_sweep_each":
            s["clock"].advance(3601)
            LeaseSweeper(registry=s["leases"], executor=executor, tokens=s["tokens"],
                         clock=s["clock"]).sweep(now=s["clock"].now())
        else:
            s["clock"].advance(30)
        if (index + 1) % 100 == 0 or index + 1 == len(cases):
            checkpoints.append({
                "actions": index + 1, "journal_bytes": s["journal"].bytes_used(),
                "journal_entries": len(s["journal"].entries()), "journal_full": s["journal"].full(),
                "active_leases": len(s["leases"].active(s["clock"].now())),
                "spent_nonces": s["tokens"].spent_count(), "nonce_evictions": s["tokens"].evictions(),
                "memory_rows": len(s["memory"].rows()), "memory_evictions": s["memory"].evictions(),
                "traced_bytes_over_start": tracemalloc.get_traced_memory()[0] - base})
    tracemalloc.stop()
    return {"outcomes": dict(outcomes), "first_index": first, "deny_reasons": dict(deny),
            "checkpoints": checkpoints}


def unswept(cases) -> dict:  # type: ignore[no-untyped-def]
    s = stack("measure.unswept")
    committed = []
    for index, case in enumerate(cases):
        rig, candidate, _executor, receipt = act(s, case, index, "unswept")
        if receipt.outcome.value.startswith("COMMITTED"):
            committed.append((rig.host, candidate.operator.target.identity.pid))
        s["clock"].advance(30)
    s["clock"].advance(3600 + 900)
    still = sum(1 for host, pid in committed
                if (row := host.snapshot().process(pid)) is not None
                and row.state is not ProcessState.RUNNING)
    return {"actions": len(cases), "committed": len(committed),
            "still_contained_after_every_hard_deadline_without_sweep": still,
            "leases_expired_by_data": len(s["leases"].expired(s["clock"].now())),
            "leases_active": len(s["leases"].active(s["clock"].now()))}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("n", nargs="?", type=int, default=600)
    parser.add_argument("--record", metavar="EXPERIMENT_ID")
    args = parser.parse_args()
    before = loadavg()
    hostile = [c for seed in (13, 14, 15, 16) for c in build_response_corpus(count=400, seed=seed)
               if not c.truth.benign_admin][: args.n]
    out = {regime: run_regime(hostile, regime) for regime in ("A_sweep_each", "B_never_sweep")}
    out["C_unswept_persistence"] = unswept(hostile[:60])
    out["bounds"] = {"MAX_JOURNAL_BYTES": MAX_JOURNAL_BYTES, "MAX_JOURNAL_ENTRIES": MAX_JOURNAL_ENTRIES,
                     "MAX_CONCURRENT_LEASES": MAX_CONCURRENT_LEASES, "MAX_SPENT_NONCES": MAX_SPENT_NONCES,
                     "MAX_EFFECTIVENESS_RECORDS": MAX_EFFECTIVENESS_RECORDS}
    for key, value in out.items():
        print(f"{key}: {json.dumps(value)}")
    after = loadavg()
    print(f"loadavg before {before} after {after}")
    if args.record:
        record(
            experiment_id=args.record,
            title="One long-lived Stage 5 executor stack: state bounds hold, journal liveness does not",
            slot_name="stage5-executor-longlived",
            dataset_name=f"stage5-hostile-stream-{len(hostile)}-seeds13-16",
            dataset_version=RESPONSE_CORPUS_VERSION,
            dataset_sha256=corpus_digest(hostile),
            seeds={"corpus_13": 13, "corpus_14": 14, "corpus_15": 15, "corpus_16": 16},
            notes=json.dumps({k: (v["outcomes"] if "outcomes" in v else v) for k, v in out.items()
                              if k != "bounds"}) + f"; loadavg {before}->{after}",
            payload={"loadavg_before": before, "loadavg_after": after, **out},
            command="PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage5/longlived_bounds.py 600",
        )


if __name__ == "__main__":
    main()
