"""Real Stage 5 output for the alert-explainer tests, built here because only a test may.

The assistant package imports nothing from Stage 5 (it reads the ResponseRecordV1 wire
form as plain rows), so the executor that produces a real receipt has to be assembled
somewhere else. Spec §5.1 rule 4 already reserves naming ``TransactionalExecutor`` to
tests and the gate; this helper follows ``tests/test_stage5_benchmarks.py:136``.

Nothing is hand-written: the case comes from ``build_response_corpus``, the choice is
the B9 human-only arm, the receipt is the real executor's, the lease is the real
registry's and the reversal is the real sweeper's. Everything is SIMULATED.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from pocketsec.stage5.executor.lease import LeaseSweeper
from pocketsec.stage5.executor.transactional import TransactionalExecutor
from pocketsec.stage5.host.simulated import HostKind
from pocketsec.stage5.labs.baselines import (
    MAX_OPERATOR_DURATION_SECONDS,
    BaselineRig,
    _mint,
    build_rig,
    human_only,
)
from pocketsec.stage5.labs.response_corpus import (
    build_critical_service_baits,
    build_response_corpus,
)
from pocketsec.stage5.stage6_interface import build_record

HANDOFF_SCHEMA = "pocketsec.assistant.alert_handoff.v1"


def _executor(rig: BaselineRig) -> TransactionalExecutor:
    return TransactionalExecutor(
        kernel=rig.kernel,
        host=rig.host,
        journal=rig.journal,
        gate=rig.gate,
        governor=rig.governor,
        leases=rig.leases,
        probe=rig.probe,
        clock=rig.clock,
        tokens=rig.tokens,
    )


def _lease_row(lease: Any, expiry: Any | None) -> dict[str, Any]:
    """Project a real Lease (+ LeaseExpiry) into the assistant's seam-safe lease row."""
    return {
        "lease_id": lease.lease_id,
        "operator_id": lease.operator_id,
        "granted_at": lease.granted_at,
        "ttl_seconds": lease.ttl_seconds,
        "expires_at": lease.expires_at(),
        "hard_deadline": lease.hard_deadline(),
        "rollback_operator_id": lease.rollback_operator_id,
        "expired_at": None if expiry is None else expiry.at,
        "rolled_back": None if expiry is None else expiry.rolled_back,
    }


@lru_cache(maxsize=1)
def _suspend_bundle() -> tuple[tuple[str, Any], ...]:
    case = next(c for c in build_response_corpus(count=4, seed=11) if not c.truth.benign_admin)
    rig = build_rig(case)
    choice = human_only(rig)
    assert choice.candidate is not None
    token = _mint(rig, choice)
    assert token is not None
    executor = _executor(rig)
    receipt = executor.execute(choice.candidate.operator, token, resolution=rig.case.resolution)
    leases = {lease.lease_id: lease for lease in rig.leases.active(rig.clock.now())}
    rig.clock.advance(MAX_OPERATOR_DURATION_SECONDS + 1)
    sweeper = LeaseSweeper(
        registry=rig.leases, executor=executor, tokens=rig.tokens, clock=rig.clock
    )
    expiries = sweeper.sweep(now=rig.clock.now())
    by_lease = {expiry.lease.lease_id: expiry for expiry in expiries}
    receipts = (receipt, *(e.receipt for e in expiries if e.receipt is not None))
    record = build_record(
        record_id=f"REC-{case.case_id}",
        incident_id=receipt.incident_id,
        epoch_id=receipt.epoch_id,
        resolution_id=receipt.resolution_id,
        plan_decision="ESCALATE",
        host_kind=HostKind.SIMULATED,
        receipts=receipts,
        governor_spend=rig.governor.spend_report(),
    )
    payload = {
        "schema": HANDOFF_SCHEMA,
        "synthetic": True,
        "provenance": "stage5 build_response_corpus(count=4, seed=11), B9 human-only arm",
        "resolution": case.resolution.to_dict(),
        "response": record.to_dict(),
        "leases": [_lease_row(lease, by_lease.get(lid)) for lid, lease in leases.items()],
    }
    return tuple(payload.items())


def stage5_bundle() -> dict[str, Any]:
    """A fresh copy each call, so no test can mutate another's input."""
    import copy

    return copy.deepcopy(dict(_suspend_bundle()))


@lru_cache(maxsize=1)
def _denial_bundle() -> tuple[tuple[str, Any], ...]:
    """A critical-service bait, suspended anyway: SENTINEL refuses it (gate G5.8's own path)."""
    from pocketsec.stage5.gate_runtime import _mint as gate_mint
    from pocketsec.stage5.gate_runtime import _record_for, _target_operator

    case = build_critical_service_baits(count=1, seed=31)[0]
    rig = build_rig(case)
    operator = _target_operator(rig, "SUSPEND_PROCESS")
    token = gate_mint(rig.tokens, operator, "act.assistant.bait.0")
    receipt = _executor(rig).execute(operator, token, resolution=case.resolution)
    record = _record_for(case, receipt, rig)
    payload = {
        "schema": HANDOFF_SCHEMA,
        "synthetic": True,
        "provenance": "stage5 build_critical_service_baits(count=1, seed=31), gate G5.8 path",
        "resolution": case.resolution.to_dict(),
        "response": record.to_dict(),
        "leases": [],
    }
    return tuple(payload.items())


def denial_bundle() -> dict[str, Any]:
    import copy

    return copy.deepcopy(dict(_denial_bundle()))


def release_cached_alerts() -> None:
    """Drop every cached demo run and Stage 5 bundle, then collect.

    The demo runs hold four live Stage 1 pipelines and engine fields. Left cached, they
    stay resident for the rest of the pytest process, and later tests that measure the
    process's own RSS (the Stage 1 gate's G1.12) would be charged for them.
    """
    import gc
    import os

    from pocketsec.assistant.demo import build_demo_alerts, build_demo_runs

    if os.environ.get("ASSISTANT_KEEP_CACHE"):  # measurement switch: show the effect
        return
    build_demo_alerts.cache_clear()
    build_demo_runs.cache_clear()
    _suspend_bundle.cache_clear()
    _denial_bundle.cache_clear()
    gc.collect()
