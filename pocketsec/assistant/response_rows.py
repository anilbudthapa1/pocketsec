"""Read Stage 5's response record and lease rows as plain data — never as live objects.

What this module is FOR: answering "what was done?" and "how do I undo it?" from what
Stage 5 *recorded*. It reads ``ResponseRecordV1.to_dict()`` (schema
``pocketsec.response_record.v1``, ``pocketsec/stage5/stage6_interface.py:276``) and a
list of lease rows, and imports nothing from Stage 5. That is the authority boundary
made structural: ``stage6_interface`` itself imports the transactional executor, so
importing it here would put an executor one attribute away from a chat question.
ADR-0003 says the assistant has no response authority; this module keeps that true by
construction rather than by care.

Two refusals, both about lineage:

* a response record for a different incident than the resolution is refused — an
  explanation that mixed two incidents' actions would be worse than none;
* ``simulated`` must be an explicit bool. Every Stage 5 record today is SIMULATED, and
  the explainer says so in every action sentence.

Lease rows are the assistant's own seam-safe projection of ``Lease`` / ``LeaseExpiry``
(``lease.py:155``/``:272``): ``ResponseRecordV1.leases_expired`` has no producer, and the
seam refuses ``LeaseExpiry.to_dict()`` because its ``action_id`` key carries an
authority token. The keys here carry none.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pocketsec.assistant.facts import (
    MAX_LEASES,
    MAX_RECEIPTS,
    Denial,
    FactKind,
    LeaseRow,
    Receipt,
    ResponseSummary,
)
from pocketsec.assistant.readers import (
    DIGEST_RE,
    HandoffError,
    clean_text,
    integer,
    names,
    opt_bool,
    opt_integer,
    opt_text,
    rows,
)

__all__ = ["MAX_REASONS", "RESPONSE_SCHEMA", "response_facts"]

#: ``stage6_interface.RESPONSE_RECORD_V1_ID``, written out so Stage 5 is not imported.
RESPONSE_SCHEMA = "pocketsec.response_record.v1"
#: Record-truncation reasons kept per alert: a handful explains, a hundred is a dump.
MAX_REASONS = 8

ResponseParts = tuple[
    ResponseSummary | None, tuple[Receipt, ...], tuple[Denial, ...], tuple[LeaseRow, ...]
]


def _digests(*values: object) -> tuple[str, ...]:
    return tuple(str(v) for v in values if isinstance(v, str) and DIGEST_RE.match(v))


def _flag(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise HandoffError(f"{field} must be an explicit bool")
    return value


def _summary(record: Mapping[str, Any]) -> ResponseSummary:
    cut = [
        clean_text(str(row.get("reason", "")), "response.truncations.reason")
        for row in rows(record.get("truncations"), "response.truncations")
    ]
    return ResponseSummary(
        fact_id="resp:record",
        kind=FactKind.REC,
        source=f"record:response/{clean_text(record['record_id'], 'response.record_id')}",
        digests=(),
        record_id=clean_text(record["record_id"], "response.record_id"),
        plan_decision=clean_text(record["plan_decision"], "response.plan_decision", limit=32),
        host_kind=clean_text(record["host_kind"], "response.host_kind", limit=32),
        simulated=_flag(record.get("simulated"), "response.simulated"),
        truncations=tuple(r for r in cut if r)[:MAX_REASONS],
    )


def _receipt(index: int, row: Mapping[str, Any]) -> Receipt:
    checks = rows(row.get("postconditions"), "receipts.postconditions")
    return Receipt(
        fact_id=f"resp:receipt:{index}",
        kind=FactKind.REC,
        source=f"record:response.receipts[{index}]",
        digests=_digests(row.get("target_digest"), row.get("evidence_bundle_digest")),
        operator_id=clean_text(row["operator_id"], "receipts.operator_id", limit=64),
        authority=clean_text(str(row.get("authority", "")), "receipts.authority", limit=8),
        outcome=clean_text(row["outcome"], "receipts.outcome", limit=48),
        verdict=clean_text(row["verdict"], "receipts.verdict", limit=16),
        denial_reasons=names(row.get("denial_reasons", ()), "receipts.denial_reasons"),
        rollback_operator_id=opt_text(
            row.get("rollback_operator_id"), "receipts.rollback", limit=64
        ),
        lease_id=opt_text(row.get("lease_id"), "receipts.lease_id", limit=128),
        verification=opt_text(row.get("verification"), "receipts.verification", limit=32),
        checks_passed=sum(1 for check in checks if check.get("satisfied") is True),
        checks_total=len(checks),
        simulated=_flag(row.get("simulated"), "receipts.simulated"),
    )


def _denial(index: int, row: Mapping[str, Any]) -> Denial:
    return Denial(
        fact_id=f"resp:denial:{index}",
        kind=FactKind.REC,
        source=f"record:response.sentinel_denials[{index}]",
        digests=_digests(row.get("target_digest"), row.get("evidence_bundle_digest")),
        operator_id=clean_text(row["operator_id"], "denials.operator_id", limit=64),
        outcome=clean_text(row["outcome"], "denials.outcome", limit=48),
        kernel_ran=_flag(row.get("kernel_ran"), "denials.kernel_ran"),
        denial_reasons=names(row.get("denial_reasons", ()), "denials.denial_reasons"),
        simulated=_flag(row.get("simulated"), "denials.simulated"),
    )


def _lease(index: int, row: Mapping[str, Any]) -> LeaseRow:
    return LeaseRow(
        fact_id=f"resp:lease:{index}",
        kind=FactKind.REC,
        source=f"record:leases[{index}]",
        digests=(),
        lease_id=clean_text(row["lease_id"], "leases.lease_id", limit=128),
        operator_id=clean_text(row["operator_id"], "leases.operator_id", limit=64),
        granted_at=integer(row["granted_at"], "leases.granted_at"),
        ttl_seconds=integer(row["ttl_seconds"], "leases.ttl_seconds"),
        expires_at=integer(row["expires_at"], "leases.expires_at"),
        hard_deadline=integer(row["hard_deadline"], "leases.hard_deadline"),
        rollback_operator_id=opt_text(row.get("rollback_operator_id"), "leases.rollback", limit=64),
        expired_at=opt_integer(row.get("expired_at"), "leases.expired_at"),
        # None covers both a missing key and Stage 5's own "pending" (LeaseExpiry:
        # "until a sweeper's executor call returns"). Either way the outcome is not
        # recorded, and ``handoff`` turns that into an Unknown, never "not attempted".
        rolled_back=opt_bool(row.get("rolled_back"), "leases.rolled_back"),
    )


def response_facts(payload: Mapping[str, Any], incident_id: str) -> ResponseParts:
    """The response facts of one handoff, or four empties when none is attached."""
    record = payload.get("response")
    lease_rows = rows(payload.get("leases"), "leases")
    if record is None:
        if lease_rows:
            raise HandoffError("leases were supplied without the response record they belong to")
        return None, (), (), ()
    if not isinstance(record, Mapping):
        raise HandoffError("response must be a ResponseRecordV1 object")
    if record.get("schema_id") != RESPONSE_SCHEMA:
        raise HandoffError("response is not a pocketsec.response_record.v1 record")
    if record.get("incident_id") != incident_id:
        raise HandoffError("response belongs to a different incident than the resolution")
    receipts = rows(record.get("receipts"), "response.receipts")[:MAX_RECEIPTS]
    denials = rows(record.get("sentinel_denials"), "response.sentinel_denials")[:MAX_RECEIPTS]
    return (
        _summary(record),
        tuple(_receipt(i, row) for i, row in enumerate(receipts)),
        tuple(_denial(i, row) for i, row in enumerate(denials)),
        tuple(_lease(i, row) for i, row in enumerate(lease_rows[:MAX_LEASES])),
    )
