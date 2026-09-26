"""D5.10 — the gate that runs BEFORE an action and refuses the ones that erase the incident.

Containment that destroys the evidence of the incident is a failure even when it stops the
attack: the host goes quiet and nobody can ever say what happened. So this is not a logger,
it is a veto on the path to COMMIT, and the only producer of the :class:`PreActionBundle`
that ``TransactionalExecutor._commit`` takes as a required, non-optional argument. Ordering
is therefore a construction rather than a discipline.

What it refuses to do. It never turns "the evidence would be lost" into a warning: an
operator whose ``evidence_effect`` degrades or destroys signals in
:attr:`RetentionPolicy.uniquely_necessary` is ``REFUSED_WOULD_DESTROY``, and the refusal
carries the bundle it *could* build plus the signal names, because a refusal nobody can audit
is not a control. It never opens an exception on policy: ``EXCEPTION_GRANTED`` needs an
``AuthorityGrant`` at ``A5`` from ``GrantSource.HUMAN``, and an ``A5`` ``POLICY`` grant is
refused — policy is written once and applies to every incident, while losing evidence that
exists nowhere else is a decision a person takes for one action (ADR-0003). It never
truncates lineage to fit a bound: over :data:`MAX_BUNDLE_BYTES` it drops ``pre_action_state``
rows and records each drop under :data:`TRUNCATION_KEY`, and if ``evidence_refs`` or
``rollback_state`` are what exceed the bound it raises instead. And it never invents lineage:
an ``EvidenceRef`` is rebuilt only from ``CBFResolutionV1.evidence_lineage``, so an operator
digest with no lineage row is refused. ``INSUFFICIENT_EVIDENCE`` is an answer, not an error.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError, EvidenceRef, digest_of_bytes, require_identifier, require_non_negative_int,
)
from pocketsec.stage4.stage5_interface import CBFResolutionV1
from pocketsec.stage5.authority.capability import AuthorityGrant, GrantSource
from pocketsec.stage5.constitution.invariants import FROZEN_CONSTITUTION, AuthorityClass
from pocketsec.stage5.constitution.schema import MissionInvariantSet
from pocketsec.stage5.host.simulated import HostSnapshot
from pocketsec.stage5.operators.algebra import DefensiveOperator, EvidenceEffect, TargetKind

__all__ = [
    "DEFAULT_RETENTION", "MAX_BUNDLE_BYTES", "MAX_VOLATILE_SIGNALS",
    "PRESERVATION_GATE_VERSION", "TRUNCATION_KEY", "EvidencePreservationGate",
    "EvidencePreservationVerdict", "PreActionBundle", "PreservationDecision", "RetentionPolicy",
]

PRESERVATION_GATE_VERSION: str = "preservation-gate-1.0.0"

#: Canonical-bytes ceiling for one bundle. A bundle is written to disk and endpoint state is
#: bounded (MEMORY.md), so this is a hard cap.
MAX_BUNDLE_BYTES: int = 65536

MAX_VOLATILE_SIGNALS: int = 16

#: Reserved key inside ``pre_action_state`` holding explicit truncation rows. §13 fixes the
#: bundle's field list, so there is no ``truncations`` field to put them in, and dropping
#: rows without recording the drop would make the bundle a quiet lie.
TRUNCATION_KEY: str = "__truncations__"

#: Rows never dropped to fit the budget: without them the bundle stops identifying what it
#: witnesses, which is the only thing it is for.
_UNDROPPABLE: frozenset[str] = frozenset({"at", "host_kind", "target_digest", TRUNCATION_KEY})


class PreservationDecision(StrEnum):
    PRESERVED = "PRESERVED"
    REFUSED_WOULD_DESTROY = "REFUSED_WOULD_DESTROY"
    EXCEPTION_GRANTED = "EXCEPTION_GRANTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    """What must survive, and what may never be traded away.

    ``uniquely_necessary`` is the subset whose loss is refused outright: a signal that exists
    nowhere else cannot be reconstructed afterwards, so no predicted benefit pays for it.
    """

    required_signals: frozenset[str]
    volatile_signals: frozenset[str]
    uniquely_necessary: frozenset[str]
    retention_seconds: int

    def __post_init__(self) -> None:
        for name in ("required_signals", "volatile_signals", "uniquely_necessary"):
            value = getattr(self, name)
            if not isinstance(value, (frozenset, set)):
                raise ContractError(f"RetentionPolicy.{name} must be a frozenset")
            object.__setattr__(self, name, frozenset(str(item) for item in value))
        require_non_negative_int(self.retention_seconds, "RetentionPolicy.retention_seconds")
        if not self.uniquely_necessary <= (self.required_signals | self.volatile_signals):
            raise ContractError(
                "RetentionPolicy.uniquely_necessary names signals nothing collects; such a "
                "signal cannot be uniquely necessary"
            )


#: The default policy. Every name is a chosen parameter, reported as such (§4.9).
DEFAULT_RETENTION: RetentionPolicy = RetentionPolicy(
    required_signals=frozenset({"process_metadata", "executable_digest", "lineage"}),
    volatile_signals=frozenset(
        {"process_memory", "open_file_descriptors", "socket_table", "environment"}
    ),
    uniquely_necessary=frozenset({"process_memory", "socket_table", "executable_digest"}),
    retention_seconds=86400,
)


def _canonical(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


@dataclass(frozen=True, slots=True)
class PreActionBundle:
    """§13's PRE-ACTION BUNDLE, field for field.

    ``integrity_digest`` is computed in ``__post_init__`` over every other field, so it cannot
    disagree with what it covers: no code path sets it to anything else.
    """

    incident_id: str
    evidence_refs: tuple[EvidenceRef, ...]
    volatile_preserved: tuple[str, ...]
    pre_action_state: Mapping[str, Any]
    rationale_claim_ids: tuple[str, ...]
    policy_version: str
    component_versions: Mapping[str, str]
    rollback_state: Mapping[str, Any]
    integrity_digest: str = ""

    def __post_init__(self) -> None:
        require_identifier(self.incident_id, "PreActionBundle.incident_id")
        if any(not isinstance(ref, EvidenceRef) for ref in self.evidence_refs):
            raise ContractError(
                "PreActionBundle.evidence_refs must hold EvidenceRef, so the digest travels"
            )
        if len(self.volatile_preserved) > MAX_VOLATILE_SIGNALS:
            raise ContractError(
                f"{len(self.volatile_preserved)} volatile signals over {MAX_VOLATILE_SIGNALS}"
            )
        for name in ("pre_action_state", "component_versions", "rollback_state"):
            object.__setattr__(self, name, MappingProxyType(dict(getattr(self, name))))
        object.__setattr__(self, "integrity_digest", digest_of_bytes(self.canonical_bytes()))
        if len(self.canonical_bytes()) > MAX_BUNDLE_BYTES:
            raise ContractError(
                f"PreActionBundle is {len(self.canonical_bytes())} bytes, over "
                f"MAX_BUNDLE_BYTES={MAX_BUNDLE_BYTES}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "evidence_refs": [
                {"store": r.store, "locator": r.locator, "digest": r.digest}
                for r in self.evidence_refs
            ],
            "volatile_preserved": list(self.volatile_preserved),
            "pre_action_state": dict(self.pre_action_state),
            "rationale_claim_ids": list(self.rationale_claim_ids),
            "policy_version": self.policy_version,
            "component_versions": dict(self.component_versions),
            "rollback_state": dict(self.rollback_state),
            "integrity_digest": self.integrity_digest,
        }

    def canonical_bytes(self) -> bytes:
        """The digested shape: everything the digest covers, and not the digest itself."""
        return _canonical(
            {k: v for k, v in self.to_dict().items() if k != "integrity_digest"}
        )

    @classmethod
    def build(
        cls,
        *,
        incident_id: str,
        operator: DefensiveOperator,
        resolution: CBFResolutionV1,
        snapshot: HostSnapshot,
        rollback_state: Mapping[str, Any],
    ) -> PreActionBundle:
        """Assemble a bundle, or raise rather than assemble a misleading one."""
        refs = _resolved_refs(operator, _lineage_index(resolution))
        row = snapshot.process(operator.target.identity.pid)
        # CAPTURED, not listed. This used to copy the names off the row, so every signal
        # that merely existed counted as preserved and MI-04 could never fire (findings
        # F4 / S5-SEC-01, reproduced: SUSPEND_PROCESS lost process_memory_map and the
        # receipt said COMMITTED_VERIFIED). Only what a preservation operator actually
        # captured for this identity, as the host reports it, is preserved.
        volatile = () if row is None else tuple(sorted(str(s) for s in row.preserved_signals))
        fixed: dict[str, Any] = {
            "incident_id": incident_id,
            "evidence_refs": refs,
            "volatile_preserved": volatile[:MAX_VOLATILE_SIGNALS],
            "rationale_claim_ids": tuple(
                dict.fromkeys(
                    str(claim_id)
                    for hypothesis in resolution.hypotheses
                    for claim_id in (hypothesis.get("claim_ids") or ())
                )
            ),
            "policy_version": FROZEN_CONSTITUTION.policy_version,
            "component_versions": {
                "preservation_gate": PRESERVATION_GATE_VERSION,
                "constitution": FROZEN_CONSTITUTION.schema_version,
                "policy": FROZEN_CONSTITUTION.policy_version,
                "resolution_interface": resolution.interface_version,
                "host": snapshot.host_version,
                "operator": operator.spec.operator_id,
            },
            "rollback_state": dict(rollback_state),
        }
        state = _fit_to_budget(_pre_action_state(operator, snapshot), fixed)
        return cls(**fixed, pre_action_state=state)


def _fit_to_budget(state: dict[str, Any], fixed: Mapping[str, Any]) -> dict[str, Any]:
    """Drop ``pre_action_state`` rows until the bundle fits, recording every drop.

    ``evidence_refs`` and ``rollback_state`` are never candidates: dropping lineage defeats
    the bundle, and dropping rollback state turns a reversible intervention into a permanent
    one. When those are what exceed the bound, this raises.
    """
    overhead = len(_canonical(dict(fixed)))
    kept, dropped = dict(state), []
    while overhead + len(_canonical(kept)) > MAX_BUNDLE_BYTES:
        droppable = [key for key in kept if key not in _UNDROPPABLE]
        if not droppable:
            raise ContractError(
                f"PreActionBundle for {fixed['incident_id']} exceeds MAX_BUNDLE_BYTES="
                f"{MAX_BUNDLE_BYTES} on evidence_refs/rollback_state alone; never truncated"
            )
        key = droppable[-1]
        dropped.append(
            {
                "what": "pre_action_state", "identifier": key, "reason": "MAX_BUNDLE_BYTES",
                "bytes_dropped": len(_canonical({key: kept.pop(key)})),
            }
        )
        kept[TRUNCATION_KEY] = dropped
    return kept


def _lineage_index(resolution: CBFResolutionV1) -> Mapping[str, Mapping[str, str]]:
    return {
        str(row["digest"]): row
        for row in resolution.evidence_lineage
        if isinstance(row.get("digest"), str)
    }


def _resolved_refs(
    operator: DefensiveOperator, lineage: Mapping[str, Mapping[str, str]]
) -> tuple[EvidenceRef, ...]:
    """Every operator evidence digest must have a lineage row, or the bundle is refused.

    A digest with no lineage row is a claim about bytes nobody can locate; passing it on would
    put an unauditable reference inside the one artefact whose job is to be auditable.
    """
    resolved = list(operator.evidence_refs)
    for ref in resolved:
        if ref.digest not in lineage:
            raise ContractError(
                f"operator {operator.spec.operator_id} cites evidence {ref.digest} with no "
                "lineage row; a reference nothing can resolve is not evidence"
            )
    known = {ref.digest for ref in resolved}
    for digest, row in sorted(lineage.items()):
        store, locator = row.get("store"), row.get("locator")
        if digest not in known and isinstance(store, str) and isinstance(locator, str):
            resolved.append(EvidenceRef(store=store, locator=locator, digest=digest))
    return tuple(resolved)


def _pre_action_state(operator: DefensiveOperator, snapshot: HostSnapshot) -> dict[str, Any]:
    """§13's process/service/session rows, read off the snapshot rather than the operator."""
    state: dict[str, Any] = {
        "at": snapshot.at, "host_kind": str(snapshot.host_kind),
        "target_digest": operator.target.identity.digest(),
        "scope_kind": str(operator.target.scope.kind),
        "scope_subject": operator.target.scope.subject,
        "restricted_sockets": sorted(snapshot.restricted_sockets),
        "sessions": list(snapshot.sessions),
    }
    row = snapshot.process(operator.target.identity.pid)
    if row is not None:
        state["process"] = asdict(row)
        service = None if row.unit is None else snapshot.service(row.unit)
        if service is not None:
            state["service"] = asdict(service)
    return state


@dataclass(frozen=True, slots=True)
class EvidencePreservationVerdict:
    """The gate's answer, shaped so an inconsistent one cannot be constructed."""

    decision: PreservationDecision
    bundle: PreActionBundle | None
    destroyed_signals: tuple[str, ...]
    unpreservable_signals: tuple[str, ...]
    exception_authority: AuthorityClass | None
    detail: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "decision", PreservationDecision(self.decision))
        object.__setattr__(self, "destroyed_signals", tuple(self.destroyed_signals))
        object.__setattr__(self, "unpreservable_signals", tuple(self.unpreservable_signals))
        if self.decision is PreservationDecision.PRESERVED and self.bundle is None:
            raise ContractError(
                "PRESERVED with no bundle; the bundle IS the preservation, so such a verdict "
                "preserved nothing"
            )
        if (
            self.decision is PreservationDecision.EXCEPTION_GRANTED
            and self.exception_authority is None
        ):
            raise ContractError(
                "EXCEPTION_GRANTED with no exception_authority is a decision nobody made"
            )
        if self.exception_authority not in (None, AuthorityClass.A5):
            raise ContractError(
                f"exception_authority {self.exception_authority}; only A5 may open an exception"
            )


class EvidencePreservationGate:
    """The pre-action veto. Holds no host handle and writes nothing."""

    __slots__ = ("_invariants", "_policy")

    def __init__(self, *, policy: RetentionPolicy, invariants: MissionInvariantSet) -> None:
        if not isinstance(policy, RetentionPolicy):
            raise ContractError("EvidencePreservationGate.policy must be a RetentionPolicy")
        if not isinstance(invariants, MissionInvariantSet):
            raise ContractError("EvidencePreservationGate.invariants must be a MissionInvariantSet")
        self._policy = policy
        self._invariants = invariants

    @property
    def policy(self) -> RetentionPolicy:
        return self._policy

    @property
    def invariants(self) -> MissionInvariantSet:
        """The mission invariants this gate enforces, read by the executor's monitors."""
        return self._invariants

    def evaluate(
        self,
        *,
        operator: DefensiveOperator,
        resolution: CBFResolutionV1,
        snapshot: HostSnapshot,
        rollback_state: Mapping[str, Any],
        exception: AuthorityGrant | None = None,
    ) -> EvidencePreservationVerdict:
        """Decide before the action, never after."""
        required = self._policy.required_signals | self._invariants.required_evidence()
        absent = tuple(sorted(required - self._available(operator, resolution, snapshot)))
        lost = self._signals_lost(operator, snapshot)
        fatal = tuple(sorted(set(lost) & self._policy.uniquely_necessary))
        try:
            bundle: PreActionBundle | None = PreActionBundle.build(
                incident_id=operator.incident_id, operator=operator, resolution=resolution,
                snapshot=snapshot, rollback_state=rollback_state,
            )
        except ContractError as exc:
            return EvidencePreservationVerdict(
                PreservationDecision.INSUFFICIENT_EVIDENCE, None, lost, absent, None,
                f"bundle could not be assembled: {exc}",
            )
        if absent:
            return EvidencePreservationVerdict(
                PreservationDecision.INSUFFICIENT_EVIDENCE, bundle, lost, absent, None,
                f"required signals absent: {list(absent)}",
            )
        if fatal:
            granted = self._exception_authority(exception, operator)
            if granted is None:
                return EvidencePreservationVerdict(
                    PreservationDecision.REFUSED_WOULD_DESTROY, bundle, fatal, absent, None,
                    f"{operator.spec.operator_id} is {operator.spec.evidence_effect} and would "
                    f"lose uniquely necessary signals {list(fatal)}",
                )
            return EvidencePreservationVerdict(
                PreservationDecision.EXCEPTION_GRANTED, bundle, fatal, absent, granted,
                f"A5 human exception for {list(fatal)}",
            )
        return EvidencePreservationVerdict(
            PreservationDecision.PRESERVED, bundle, lost, (), None,
            f"{len(bundle.evidence_refs)} refs, {len(bundle.volatile_preserved)} volatile",
        )

    def _available(
        self, operator: DefensiveOperator, resolution: CBFResolutionV1, snapshot: HostSnapshot
    ) -> frozenset[str]:
        """What the bundle can actually carry, derived from typed inputs only."""
        signals: set[str] = set()
        row = snapshot.process(operator.target.identity.pid)
        if row is not None:
            signals.update({"process_metadata", "lineage"})
            signals.update(str(name) for name in row.volatile_signals)
            if row.identity.executable_digest is not None:
                signals.add("executable_digest")
        if resolution.evidence_lineage:
            signals.add("lineage")
        return frozenset(signals)

    def _signals_lost(self, operator: DefensiveOperator, snapshot: HostSnapshot) -> tuple[str, ...]:
        """Which signals this operator's declared evidence effect takes away."""
        effect = operator.spec.evidence_effect
        if effect in {EvidenceEffect.PRESERVES, EvidenceEffect.NEUTRAL}:
            return ()
        row = snapshot.process(operator.target.identity.pid)
        # A target the snapshot cannot see puts the whole policy volatile set at risk rather
        # than nothing: absence of evidence is not safety.
        volatile = (
            set(self._policy.volatile_signals)
            if row is None
            else {str(name) for name in row.volatile_signals}
        )
        if effect is EvidenceEffect.DESTROYS:
            volatile |= {"process_metadata", "executable_digest"}
        if operator.target.scope.kind is TargetKind.HOST:
            volatile |= set(self._policy.volatile_signals)
        return tuple(sorted(volatile))

    def _exception_authority(
        self, exception: AuthorityGrant | None, operator: DefensiveOperator
    ) -> AuthorityClass | None:
        """Only an A5 HUMAN grant naming THIS operator opens an exception."""
        opens = (
            isinstance(exception, AuthorityGrant)
            and exception.granted_by is GrantSource.HUMAN
            and exception.authority is AuthorityClass.A5
            and exception.subject_operator_id == operator.spec.operator_id
        )
        return AuthorityClass.A5 if opens else None
