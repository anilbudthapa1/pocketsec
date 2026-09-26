"""D5.19 / SAFE-F24 — the only artefact Stage 6 ever sees, and what it refuses to carry.

Integration plan §3.2 says Stage 6 consumes Stage 5's receipts and residuals.
:class:`ResponseRecordV1` is that handoff, and it is **plain JSON with a canonical
digest**, copying the shape of ``pocketsec/stage4/stage5_interface.py`` including its
refusals.

Why plain JSON rather than the live objects, stated because it looks like extra work:
Stage 5's class names are Stage 5's business. A handoff that carried a
``TransactionReceipt`` instance would couple Stage 6's lifetime to that class, and a
handoff that carries rows of strings and numbers survives a redesign. Stage 4 made the
same argument in the other direction and was right (ADR-0045).

**Four refusals, all at export time.**

1. *No key may name a Stage 5 class* (:data:`FORBIDDEN_SEAM_TOKENS`, eighteen names).
   **Deliberately absent**, exactly as Stage 4 documents its own omissions: ``lease``
   (``lease_id``, ``lease_ttl_seconds``), ``residual`` (``residual_distance``),
   ``receipt`` (``receipt_id``), ``operator`` (``operator_id`` — the catalog key *is*
   the payload), ``shadow`` (``shadow_score``), ``monitor`` (``monitor_findings``) and
   ``governor`` (``governor_spend``). Banning those would mean no record could cross
   the seam at all — a refusal so total it would be deleted within a week rather than
   respected.
2. *No authority-named key*, screened against
   :data:`~pocketsec.stage0.contracts.threat_prediction_v1.FORBIDDEN_AUTHORITY_FIELDS`,
   with exactly four enumerated exceptions Stage 5 cannot express without:
   :data:`SEAM_AUTHORITY_EXEMPTIONS`. A test asserts it has exactly four members,
   because **an exemption list that can grow silently is the trap**. Note what this
   costs and why the cost is right: a receipt row may not carry ``action_id``, because
   "action" is a forbidden token — nor ``transaction_id``, which contains it — so
   :func:`receipt_row` emits ``tx_id``.
3. *No unverified outcome may be exported as verified.* A row whose outcome is
   ``COMMITTED_VERIFIED`` while any of its postconditions has ``satisfied`` of ``None``
   raises. ``None`` means unverifiable, and unverifiable is not complete (ADR-0004).
4. *No simulated record may become a real one by omission.* ``simulated`` is required
   and non-defaulted on the record **and on every receipt row**, and ``to_dict`` raises
   if it is ``False`` while ``host_kind`` is not ``REAL``. Rollback reliability,
   containment and recovery figures inside these rows were produced by a simulator this
   wave wrote; three stages later, nobody will remember that unless the row says so
   (ADR-0046).
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    digest_of_bytes,
    register_schema,
    require_identifier,
)
from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS
from pocketsec.stage5.executor.residual import residual_feedback
from pocketsec.stage5.executor.transactional import Outcome, TransactionReceipt
from pocketsec.stage5.host.simulated import HostKind
from pocketsec.stage5.operators.catalog import spec as catalog_spec

__all__ = [
    "FORBIDDEN_SEAM_TOKENS",
    "REFUSAL_OUTCOMES",
    "RESPONSE_RECORD_V1_ID",
    "RESPONSE_RECORD_V1_VERSION",
    "SEAM_AUTHORITY_EXEMPTIONS",
    "VERIFIED_OUTCOME",
    "ResponseRecordV1",
    "authority_violations",
    "build_record",
    "denial_row",
    "receipt_row",
    "seam_violations",
    "write_record",
]

RESPONSE_RECORD_V1_ID = "pocketsec.response_record.v1"
RESPONSE_RECORD_V1_VERSION = register_schema(RESPONSE_RECORD_V1_ID, "1.0.0")

#: The outcome name whose export is conditional on every postcondition being ``True``.
#: A string rather than the enum, because the seam carries values and not classes.
VERIFIED_OUTCOME: str = "COMMITTED_VERIFIED"

#: Every outcome in which the system declined to act. Each one becomes a
#: ``sentinel_denials`` row, whichever gate refused: G5.8 requires an evidence-gate
#: refusal to be recorded there, and a refusal the record omits is a refusal nobody
#: downstream can audit. Enumerated rather than matched on a ``REFUSED_`` prefix, so a
#: new outcome has to be placed here deliberately.
REFUSAL_OUTCOMES: frozenset[Outcome] = frozenset(
    {
        Outcome.REFUSED_SENTINEL,
        Outcome.REFUSED_EVIDENCE,
        Outcome.REFUSED_IDENTITY,
        Outcome.REFUSED_TOKEN,
        Outcome.REFUSED_JOURNAL_FULL,
    }
)

#: The eighteen Stage 5 class names Stage 6 must never see as a key. Compared against
#: keys with separators stripped, so ``sentinel_kernel``, ``sentinelKernel`` and
#: ``SentinelKernel`` are all caught.
FORBIDDEN_SEAM_TOKENS: frozenset[str] = frozenset(
    {
        "defensiveoperator",
        "operatorspec",
        "capabilitytoken",
        "sentinelkernel",
        "sentinelverdict",
        "transactionalexecutor",
        "rollbackjournal",
        "responsetwin",
        "interventioncone",
        "actionshadow",
        "aegisplanner",
        "leaseregistry",
        "hysteresiscontroller",
        "effectivenessmemory",
        "responsecellfield",
        "safestateplanner",
        "evidencepreservationgate",
        "simulatedhost",
    }
)

#: Exactly four. Every other authority-named key is refused, and a test pins the count.
#: ``operator_id`` and ``operator_class`` are the catalog key and its consequence class —
#: the payload itself. ``authority`` is the class the action was carried under, which is
#: the single most important thing an auditor reads. ``rollback_operator_id`` is the undo
#: path, and a record that cannot say how an action was reversed is not auditable.
SEAM_AUTHORITY_EXEMPTIONS: frozenset[str] = frozenset(
    {"operator_id", "operator_class", "authority", "rollback_operator_id"}
)

def seam_violations(payload: object, *, prefix: str = "record") -> tuple[str, ...]:
    """Every key path whose name would leak a Stage 5 class across the seam.

    Recursive over mappings and sequences, because these payloads nest three deep and a
    violation buried in ``receipts[2].sentinel_verdict`` is exactly as coupling as one at
    the top level.
    """
    found: list[str] = []
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            path = f"{prefix}.{key}"
            flattened = str(key).lower().replace("_", "").replace("-", "")
            if any(token in flattened for token in FORBIDDEN_SEAM_TOKENS):
                found.append(path)
            found.extend(seam_violations(value, prefix=path))
    elif isinstance(payload, (list, tuple)):
        for index, item in enumerate(payload):
            found.extend(seam_violations(item, prefix=f"{prefix}[{index}]"))
    return tuple(found)


def authority_violations(payload: object, *, prefix: str = "record") -> tuple[str, ...]:
    """Every key path naming authority that is not one of the four exemptions.

    Substring-matched on the lowered key, exactly as ``stage4.worlds.authority_named_fields``
    matches dataclass field names — one rule with one spelling, because two spellings of
    one rule is how S2-AUTH-01 stayed open in neither checker. It bites: ``transaction_id``
    contains "action", so :func:`receipt_row` emits ``tx_id``. Renaming the key is the
    correct resolution; appending to the exemption list is the trap.

    Trust rule T5 exempts ``pocketsec/stage5/`` from the dataclass-field version of this
    check, which is exactly why the seam applies it here: Stage 5 is allowed to name an
    action internally, and Stage 6 is not allowed to receive one.
    """
    found: list[str] = []
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            path = f"{prefix}.{key}"
            name = str(key).lower()
            if name not in SEAM_AUTHORITY_EXEMPTIONS and any(
                token in name for token in FORBIDDEN_AUTHORITY_FIELDS
            ):
                found.append(path)
            found.extend(authority_violations(value, prefix=path))
    elif isinstance(payload, (list, tuple)):
        for index, item in enumerate(payload):
            found.extend(authority_violations(item, prefix=f"{prefix}[{index}]"))
    return tuple(found)


def _require_json(value: object, *, field: str) -> Any:
    """Refuse anything that is not a JSON scalar, list or mapping.

    A Stage 5 object reaching here would serialise by accident, or not at all, and would
    put a class name on the wire — so the refusal is structural rather than a
    ``json.dumps`` failure later.
    """
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ContractError(f"{field} must be a finite number, got {value!r}")
        return value
    if isinstance(value, Mapping):
        clean: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ContractError(f"{field} keys must be strings, got {type(key).__name__}")
            clean[key] = _require_json(item, field=f"{field}.{key}")
        return clean
    if isinstance(value, (list, tuple)):
        return [_require_json(item, field=f"{field}[{index}]") for index, item in enumerate(value)]
    raise ContractError(
        f"{field} holds {type(value).__name__}, which is not plain JSON; Stage 6 reads rows "
        "of strings and numbers so that Stage 5 can be redesigned without it"
    )


def _plain_rows(rows: Sequence[Mapping[str, Any]], *, field: str) -> tuple[Mapping[str, Any], ...]:
    normalised: list[Mapping[str, Any]] = []
    for index, row in enumerate(rows):
        where = f"{field}[{index}]"
        if not isinstance(row, Mapping):
            raise ContractError(f"{where} must be a mapping, got {type(row).__name__}")
        normalised.append(_require_json(row, field=where))
    return tuple(normalised)


def receipt_row(receipt: TransactionReceipt) -> dict[str, Any]:
    """Project one transaction receipt into a seam-safe plain row.

    Not ``receipt.to_dict()``: that payload carries a ``sentinel_verdict`` key, and
    ``sentinelverdict`` is one of the eighteen forbidden tokens. It also carries
    ``action_id``, and "action" is a forbidden authority token. Both are real refusals
    doing their job rather than obstacles, so the projection renames what it must and
    keeps the meaning: the verdict becomes ``denial_reasons`` plus ``verdict``, and the
    action id becomes ``tx_id`` — not ``transaction_id``, because "transaction" contains
    "action" and the substring rule is doing its job rather than being worked around.

    ``authority`` and ``rollback_operator_id`` are read from the catalog entry the
    receipt's ``operator_id`` names. A receipt does not carry them because they are
    properties of the operator, not of the transaction — and exporting ``None`` for
    them, as an earlier revision did, told an auditor the one thing they most need to
    know was unknown when it is fixed by construction.
    """
    verdict = receipt.sentinel_verdict
    entry = catalog_spec(receipt.operator_id)
    return {
        "receipt_id": receipt.receipt_id,
        "tx_id": receipt.action_id,
        "incident_id": receipt.incident_id,
        "resolution_id": receipt.resolution_id,
        "operator_id": receipt.operator_id,
        "operator_class": int(receipt.operator_class),
        "authority": str(entry.authority),
        "rollback_operator_id": entry.rollback_operator_id,
        "target_digest": receipt.target_digest,
        "outcome": receipt.outcome.value,
        "verdict": verdict.decision.value,
        "denial_reasons": [reason.value for reason in verdict.reasons],
        "identity_revalidation": receipt.identity_revalidation.value,
        "token_verdict": receipt.token_verdict.value,
        "evidence_bundle_digest": receipt.evidence_bundle_digest,
        "lease_id": receipt.lease_id,
        "postconditions": [
            {"kind": row.kind.value, "satisfied": row.satisfied, "observed": row.observed}
            for row in receipt.postconditions
        ],
        "verification": None if receipt.verification is None else receipt.verification.value,
        "residual_distance": None if receipt.residual is None else receipt.residual.distance,
        "rollback_attempted": receipt.rollback_attempted,
        "rollback_succeeded": receipt.rollback_succeeded,
        "host_kind": receipt.host_kind.value,
        "simulated": receipt.simulated,
        "work_units": receipt.work_units,
        "epoch_id": receipt.epoch_id,
    }


@dataclass(frozen=True, slots=True)
class ResponseRecordV1:
    """The Stage 6 handoff. Every nested member is plain JSON; ``to_dict`` does the refusing."""

    record_id: str
    incident_id: str
    epoch_id: int
    resolution_id: str
    plan_decision: str
    receipts: tuple[Mapping[str, Any], ...]
    residuals: tuple[Mapping[str, Any], ...]
    effectiveness_rows: tuple[Mapping[str, Any], ...]
    melt_reports: tuple[Mapping[str, Any], ...]
    leases_expired: tuple[Mapping[str, Any], ...]
    sentinel_denials: tuple[Mapping[str, Any], ...]
    monitor_findings: tuple[Mapping[str, Any], ...]
    governor_spend: Mapping[str, int]
    host_kind: str
    simulated: bool
    truncations: tuple[Mapping[str, Any], ...]
    interface_version: str = RESPONSE_RECORD_V1_VERSION

    _ROW_FIELDS = (
        "receipts",
        "residuals",
        "effectiveness_rows",
        "melt_reports",
        "leases_expired",
        "sentinel_denials",
        "monitor_findings",
        "truncations",
    )

    def __post_init__(self) -> None:
        for name in ("record_id", "incident_id", "resolution_id", "interface_version"):
            require_identifier(getattr(self, name), f"ResponseRecordV1.{name}")
        if not isinstance(self.epoch_id, int) or isinstance(self.epoch_id, bool):
            raise ContractError("ResponseRecordV1.epoch_id must be an int")
        if not isinstance(self.simulated, bool):
            raise ContractError(
                "ResponseRecordV1.simulated must be an explicit bool; a record that omits it "
                "is a record that could become a real-host record by accident (ADR-0046)"
            )
        if not isinstance(self.plan_decision, str) or not self.plan_decision.strip():
            raise ContractError("ResponseRecordV1.plan_decision must be a non-empty string")
        for name in self._ROW_FIELDS:
            object.__setattr__(
                self, name, _plain_rows(getattr(self, name), field=f"ResponseRecordV1.{name}")
            )
        object.__setattr__(self, "governor_spend", _checked_spend(self.governor_spend))
        object.__setattr__(self, "host_kind", HostKind(self.host_kind).value)

    def digest(self) -> str:
        """``sha256:`` over the canonical export. The lineage guarantee Stage 6 reads."""
        return digest_of_bytes(self.canonical_bytes())

    def canonical_bytes(self) -> bytes:
        """Sorted keys, no NaN, fixed indent, trailing newline. Goes through ``to_dict``."""
        return (
            json.dumps(self.to_dict(), sort_keys=True, allow_nan=False, indent=2).encode("utf-8")
            + b"\n"
        )

    def to_dict(self) -> dict[str, Any]:
        """The wire form, or a refusal. All four refusals live here.

        Ordering matters: the verified-outcome and simulated checks run *before* the key
        scans, because exporting an unverifiable result as verified is the more serious
        finding and the error a reader sees should name it.
        """
        self._refuse_unverifiable_as_verified()
        self._refuse_simulated_mismatch()
        payload: dict[str, Any] = {
            "interface_version": self.interface_version,
            "schema_id": RESPONSE_RECORD_V1_ID,
            "record_id": self.record_id,
            "incident_id": self.incident_id,
            "epoch_id": self.epoch_id,
            "resolution_id": self.resolution_id,
            "plan_decision": self.plan_decision,
            "host_kind": self.host_kind,
            "simulated": self.simulated,
            "governor_spend": dict(sorted(self.governor_spend.items())),
        }
        payload.update({name: [dict(row) for row in getattr(self, name)] for name in self._ROW_FIELDS})
        offenders = seam_violations(payload)
        if offenders:
            raise ContractError(
                f"ResponseRecordV1.to_dict would leak Stage 5 class names {list(offenders)}; a "
                "handoff that carries objects becomes a coupling Stage 6 cannot shed"
            )
        named = authority_violations(payload)
        if named:
            raise ContractError(
                f"ResponseRecordV1.to_dict would export authority-named keys {list(named)}; the "
                f"only exemptions are {sorted(SEAM_AUTHORITY_EXEMPTIONS)}, and an exemption list "
                "that grows silently is the trap this check exists to close"
            )
        return payload

    def _refuse_unverifiable_as_verified(self) -> None:
        for index, row in enumerate(self.receipts):
            if str(row.get("outcome")) != VERIFIED_OUTCOME:
                continue
            unverifiable = [
                str(item.get("kind"))
                for item in row.get("postconditions", ()) or ()
                if isinstance(item, Mapping) and item.get("satisfied") is None
            ]
            if unverifiable:
                raise ContractError(
                    f"receipts[{index}] exports outcome {VERIFIED_OUTCOME} while postconditions "
                    f"{unverifiable} are unverifiable (satisfied is None); None means "
                    "unverifiable and an action that cannot be verified cannot be considered "
                    "successfully completed (§2, ADR-0004)"
                )

    def _refuse_simulated_mismatch(self) -> None:
        """``simulated`` and ``host_kind`` must agree, on the record and on every row."""
        rows: list[tuple[str, Any, Any]] = [
            ("record", self.host_kind, self.simulated),
        ]
        for index, row in enumerate(self.receipts):
            if "simulated" not in row:
                raise ContractError(
                    f"receipts[{index}] omits `simulated`; it is required and non-defaulted on "
                    "every row, so a simulator's record cannot become a real host's by omission"
                )
            rows.append((f"receipts[{index}]", row.get("host_kind"), row.get("simulated")))
        for where, host_kind, simulated in rows:
            if not isinstance(simulated, bool):
                raise ContractError(f"{where}.simulated must be an explicit bool")
            if simulated is False and str(host_kind) != HostKind.REAL.value:
                raise ContractError(
                    f"{where} claims simulated=False while host_kind is {host_kind!r}; only a "
                    f"{HostKind.REAL.value} host may export a non-simulated row (ADR-0046)"
                )
            if simulated is True and str(host_kind) == HostKind.REAL.value:
                raise ContractError(
                    f"{where} claims simulated=True on a {HostKind.REAL.value} host"
                )

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ResponseRecordV1:
        """Rebuild from the wire form. Lossless against :meth:`to_dict`, and strict.

        Values are passed through **uncoerced** so ``__post_init__`` judges what was on
        the wire: ``bool("false")`` is ``True``, and a reader that coerced would turn a
        record claiming ``simulated: "false"`` into one claiming the opposite.
        """
        missing = sorted(set(_WIRE_FIELDS) - set(payload))
        if missing:
            raise ContractError(f"ResponseRecordV1 missing fields {missing}")
        if payload["schema_id"] != RESPONSE_RECORD_V1_ID:
            raise ContractError(
                f"schema_id {payload['schema_id']!r} is not {RESPONSE_RECORD_V1_ID!r}"
            )
        rows = {name: _wire_rows(payload[name], field=name) for name in cls._ROW_FIELDS}
        return cls(
            record_id=payload["record_id"],
            incident_id=payload["incident_id"],
            epoch_id=payload["epoch_id"],
            resolution_id=payload["resolution_id"],
            plan_decision=payload["plan_decision"],
            governor_spend=payload["governor_spend"],
            host_kind=payload["host_kind"],
            simulated=payload["simulated"],
            interface_version=payload["interface_version"],
            **rows,
        )


#: Every key :meth:`ResponseRecordV1.to_dict` writes. ``from_dict`` requires all of
#: them, so a payload that silently lost one cannot be rebuilt with a default.
_WIRE_FIELDS: tuple[str, ...] = (
    "interface_version",
    "schema_id",
    "record_id",
    "incident_id",
    "epoch_id",
    "resolution_id",
    "plan_decision",
    "host_kind",
    "simulated",
    "governor_spend",
    *ResponseRecordV1._ROW_FIELDS,
)


def _wire_rows(value: object, *, field: str) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, (list, tuple)):
        raise ContractError(f"ResponseRecordV1.{field} must be a list of rows")
    return tuple(value)


def _checked_spend(value: object) -> Mapping[str, int]:
    if not isinstance(value, Mapping):
        raise ContractError("ResponseRecordV1.governor_spend must be a mapping")
    snapshot: dict[str, int] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key:
            raise ContractError("governor_spend keys must be non-empty strings")
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise ContractError(f"governor_spend[{key!r}] must be a work-unit count")
        snapshot[key] = item
    return snapshot


def denial_row(receipt: TransactionReceipt) -> dict[str, Any] | None:
    """The ``sentinel_denials`` row for one refused transaction, or ``None`` if it acted.

    ``kernel_ran`` separates a SENTINEL denial from a refusal that stopped earlier — at
    the token plane or the evidence-preservation gate — whose receipt carries the
    executor's synthesised DENY. Both are recorded, because both are refusals an
    auditor must see; they are distinguished, because only one of them is evidence
    that the kernel was consulted. The test is structural: a kernel verdict always
    lists the checks it evaluated, and the synthesised one lists none.
    """
    if receipt.outcome not in REFUSAL_OUTCOMES:
        return None
    verdict = receipt.sentinel_verdict
    return {
        "receipt_id": receipt.receipt_id,
        "tx_id": receipt.action_id,
        "operator_id": receipt.operator_id,
        "target_digest": receipt.target_digest,
        "outcome": receipt.outcome.value,
        "kernel_ran": bool(verdict.evaluated_checks),
        "denial_reasons": [reason.value for reason in verdict.reasons],
        "detail": verdict.detail,
        "evidence_bundle_digest": receipt.evidence_bundle_digest,
        "host_kind": receipt.host_kind.value,
        "simulated": receipt.simulated,
    }


def build_record(
    *,
    record_id: str,
    incident_id: str,
    epoch_id: int,
    resolution_id: str,
    plan_decision: str,
    host_kind: HostKind,
    receipts: Sequence[TransactionReceipt],
    governor_spend: Mapping[str, int],
    effectiveness_rows: Sequence[Mapping[str, Any]] = (),
    melt_reports: Sequence[Mapping[str, Any]] = (),
    leases_expired: Sequence[Mapping[str, Any]] = (),
    monitor_findings: Sequence[Mapping[str, Any]] = (),
    truncations: Sequence[Mapping[str, Any]] = (),
) -> ResponseRecordV1:
    """Assemble a record from live receipts, deriving what must not be hand-supplied.

    Three things are derived rather than accepted, each because a caller supplying it
    could get it wrong in the one direction that matters: ``simulated`` comes from
    ``host_kind``; ``sentinel_denials`` comes from the receipts, so a refusal cannot be
    left out of the record by forgetting to list it; and ``residuals`` come from the
    receipts through ``residual_feedback``. Every receipt must name this record's
    incident, resolution, epoch and host kind — a record that mixed two incidents, or a
    simulated receipt into a real record, would break the lineage Stage 6 reads.
    """
    _require_one_lineage(
        receipts,
        incident_id=incident_id,
        resolution_id=resolution_id,
        epoch_id=epoch_id,
        host_kind=host_kind,
    )
    denials = tuple(row for row in (denial_row(receipt) for receipt in receipts) if row)
    return ResponseRecordV1(
        record_id=record_id,
        incident_id=incident_id,
        epoch_id=epoch_id,
        resolution_id=resolution_id,
        plan_decision=plan_decision,
        receipts=tuple(receipt_row(receipt) for receipt in receipts),
        residuals=tuple(
            dict(residual_feedback(receipt.residual))
            for receipt in receipts
            if receipt.residual is not None
        ),
        effectiveness_rows=tuple(effectiveness_rows),
        melt_reports=tuple(melt_reports),
        leases_expired=tuple(leases_expired),
        sentinel_denials=denials,
        monitor_findings=tuple(monitor_findings),
        governor_spend=governor_spend,
        host_kind=HostKind(host_kind).value,
        simulated=HostKind(host_kind) is not HostKind.REAL,
        truncations=tuple(truncations),
    )


def _require_one_lineage(
    receipts: Sequence[TransactionReceipt],
    *,
    incident_id: str,
    resolution_id: str,
    epoch_id: int,
    host_kind: HostKind,
) -> None:
    """Refuse a receipt that belongs to another incident, resolution, epoch or host kind."""
    for index, receipt in enumerate(receipts):
        mismatched = [
            name
            for name, expected, found in (
                ("incident_id", incident_id, receipt.incident_id),
                ("resolution_id", resolution_id, receipt.resolution_id),
                ("epoch_id", epoch_id, receipt.epoch_id),
                ("host_kind", host_kind, receipt.host_kind),
            )
            if expected != found
        ]
        if mismatched:
            raise ContractError(f"receipts[{index}] disagrees with the record on {mismatched}")


def write_record(record: ResponseRecordV1, path: Path) -> str:
    """Write canonical JSON and return its ``sha256:`` digest.

    Writing goes through :meth:`ResponseRecordV1.to_dict`, so a record that fails any of
    the four refusals never reaches the filesystem — the refusal has to be answered, not
    routed around by serialising a second time.
    """
    payload = record.canonical_bytes()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return digest_of_bytes(payload)


assert len(FORBIDDEN_SEAM_TOKENS) == 18, "the spec names eighteen Stage 5 class tokens"
assert len(SEAM_AUTHORITY_EXEMPTIONS) == 4, (
    "exactly four authority exemptions; an exemption list that can grow silently is the trap"
)
