"""D5.11 — the transactional privileged executor, and the only door to privilege.

Architecture §35's *minimal* privileged executor. No model, no LLM, no hypothesis
generation, no candidate scoring, no network-facing API, and it never parses text.
Everything upstream produces beliefs; this is the one place a belief becomes a
change to a host, so it is written to be boring enough to audit.

Four properties, each enforced in code rather than by review, and each argued where
it is implemented. Not all four are constructions: the first is a runtime check and the
assurance table (``assurance/properties.py``) says which kind each one is:

* **Only typed operators reach privilege.** :meth:`TransactionalExecutor.execute`
  is the sole public entry point and its first parameter is annotated exactly
  ``DefensiveOperator`` (trust rule T4). The annotation is not type-checked by any
  gate, so it is documentation; the enforcement is :func:`_refuse_untyped`, a
  runtime check in THIS module that demands the exact type and catalog identity.
  Deleting it would leave ``DefensiveOperator.__post_init__`` and SENTINEL's schema
  check standing, but it is a deletable runtime check, and the assurance table
  records the property as TESTED, not proven (finding F5-honesty).
* **COMMIT is unreachable without an evidence bundle** — :meth:`
  TransactionalExecutor._commit` takes one as a required positional parameter.
* **No Python call sits between revalidation and the act** — :func:`revalidate`
  immediately precedes ``host.apply``. That makes the window *small*, not empty:
  they are two host calls and a real kernel can recycle a pid between them. What
  closes it is the host binding the act to the identity and the scoped subject at
  the moment it acts (``SimulatedHost.apply`` refuses with
  ``TARGET_BINDING_CHANGED``; on Linux the analogue is a pidfd). An earlier version
  of this docstring said "the TOCTOU window is empty"; that was false (F1-honesty).
* **Every call yields an auditable receipt**, refusals included, and every receipt
  feeds the four receipt-reading §33 monitors, whose ``HALT_AUTONOMY`` refuses
  further POLICY-granted interventions (restorations stay allowed).

It does not widen a bound when the budget runs out, act on an operator it cannot
lease, release rollback state a live lease still needs, or report an outcome as
verified when a postcondition came back ``None``.
:attr:`TransactionReceipt.host_kind` and :attr:`TransactionReceipt.simulated` are
required and non-defaulted, so a record produced against the simulated host cannot
become a real-host record by omission three stages later. **Nothing measured here
is a measurement of a Linux host** (ADR-0046, spec §9.1).
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    digest_of_bytes,
    register_schema,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage4.stage5_interface import CBFResolutionV1
from pocketsec.stage5.authority.capability import GrantSource
from pocketsec.stage5.authority.tokens import CapabilityToken, TokenStore, TokenVerdict
from pocketsec.stage5.evidence.preservation_gate import (
    EvidencePreservationGate,
    EvidencePreservationVerdict,
    PreActionBundle,
    PreservationDecision,
)
from pocketsec.stage5.executor.identity import (
    ACTIONABLE_REVALIDATIONS,
    Clock,
    IdentityRevalidation,
    identity_digest,
    revalidate,
)
from pocketsec.stage5.executor.journal import JournalFull, RollbackJournal
from pocketsec.stage5.executor.lease import Lease, LeaseDenial, LeaseRegistry, requires_lease
from pocketsec.stage5.governor import STAGE5_BUDGET, BudgetExhausted, ResourceGovernor, WorkKind
from pocketsec.stage5.host.simulated import (
    HostAdapter,
    HostEffect,
    HostFailure,
    HostKind,
    HostSnapshot,
)
from pocketsec.stage5.operators.algebra import DefensiveOperator, OperatorClass
from pocketsec.stage5.operators.catalog import CATALOG, RESTORATION_OPERATOR_IDS
from pocketsec.stage5.sentinel.kernel import Decision, SentinelKernel, SentinelVerdict
from pocketsec.stage5.sentinel.monitors import MonitorFinding, ResponseDefenseMonitors

if TYPE_CHECKING:  # pragma: no cover - the `outcome` package depends on this
    # module, so importing it at module scope would close a cycle. The one
    # runtime fact this module needs from it is fetched in `_verification`.
    from pocketsec.stage5.executor.residual import InterventionResidual
    from pocketsec.stage5.executor.verify import (
        PostconditionProbe,
        PostconditionResult,
        VerificationOutcome,
    )

__all__ = [
    "COMMITTED_OUTCOMES",
    "GOVERNOR_TOTAL_KEY",
    "HOST_TOUCHING_OUTCOMES",
    "LOADAVG_UNAVAILABLE",
    "MAX_RECENT_ACTION_TIMES",
    "PHASE_ORDER",
    "PRESERVING_DECISIONS",
    "TRANSACTION_RECEIPT_V1_ID",
    "TRANSACTION_RECEIPT_V1_VERSION",
    "Outcome",
    "Phase",
    "PhaseRecord",
    "TransactionReceipt",
    "TransactionalExecutor",
]

TRANSACTION_RECEIPT_V1_ID = "pocketsec.transaction_receipt.v1"
TRANSACTION_RECEIPT_V1_VERSION = register_schema(TRANSACTION_RECEIPT_V1_ID, "1.0.0")

#: Returned by :func:`_loadavg` when the host will not report one. Negative load
#: is impossible, so this can never be mistaken for a measurement — which is the
#: whole point: an unmeasured figure may not look plausible.
LOADAVG_UNAVAILABLE: tuple[float, float, float] = (-1.0, -1.0, -1.0)

#: The key ``ResourceGovernor.spend_report`` files the running total under. Named
#: here rather than spelled at two call sites, and pinned by
#: ``test_the_governor_total_key_exists`` so a rename upstream cannot silently
#: turn every receipt's ``work_units`` into zero — the shape of defect that made
#: two of Stage 2's gate figures structurally incapable of varying.
GOVERNOR_TOTAL_KEY: str = "TOTAL"

#: How many recent action times the executor keeps for SENTINEL's rate-limit
#: check. The governor allows 8 autonomous actions per 3600 s window, so twice
#: that is ample and the list cannot grow with uptime. Endpoint state is bounded
#: even when it is only timestamps.
MAX_RECENT_ACTION_TIMES: int = 16


class Phase(StrEnum):
    """The five phases. Declaration order *is* protocol order, enforced by
    ``TransactionReceipt.__post_init__``."""

    PREPARE = "PREPARE"
    COMMIT = "COMMIT"
    VERIFY = "VERIFY"
    ROLLBACK = "ROLLBACK"
    FINALIZE = "FINALIZE"


#: Declaration index per phase. A mapping rather than repeated ``list(Phase)``
#: lookups so the ordering rule has one implementation.
PHASE_ORDER: Mapping[Phase, int] = MappingProxyType(
    {phase: index for index, phase in enumerate(Phase)}
)


class Outcome(StrEnum):
    """Ten outcomes. Six are refusals, and a refusal is a first-class result with a
    receipt, not an error path that leaves no trace."""

    COMMITTED_VERIFIED = "COMMITTED_VERIFIED"
    COMMITTED_UNVERIFIED = "COMMITTED_UNVERIFIED"
    ROLLED_BACK = "ROLLED_BACK"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"
    REFUSED_SENTINEL = "REFUSED_SENTINEL"
    REFUSED_EVIDENCE = "REFUSED_EVIDENCE"
    REFUSED_IDENTITY = "REFUSED_IDENTITY"
    REFUSED_TOKEN = "REFUSED_TOKEN"
    REFUSED_JOURNAL_FULL = "REFUSED_JOURNAL_FULL"
    ESCALATED = "ESCALATED"


#: "The intervention stands." Named so the hysteresis controller, the sweeper and
#: Stage 6 never re-derive the set and drift from it.
COMMITTED_OUTCOMES: frozenset[Outcome] = frozenset(
    {Outcome.COMMITTED_VERIFIED, Outcome.COMMITTED_UNVERIFIED}
)

#: ``host.apply`` ran, whether or not the change survived. Cycle counting uses
#: this: a rolled-back action still disturbed the host.
HOST_TOUCHING_OUTCOMES: frozenset[Outcome] = COMMITTED_OUTCOMES | frozenset(
    {Outcome.ROLLED_BACK, Outcome.ROLLBACK_FAILED}
)

#: Evidence-gate decisions that permit an action. ``EXCEPTION_GRANTED`` is in the
#: set because the gate itself already required an A5 HUMAN grant to produce it.
PRESERVING_DECISIONS: frozenset[PreservationDecision] = frozenset(
    {PreservationDecision.PRESERVED, PreservationDecision.EXCEPTION_GRANTED}
)

#: The one value returned when COMMIT refuses on identity. A module constant, not
#: a constructor call, so no call sits between `revalidate` and `host.apply`.
_NO_EFFECT: HostEffect = HostEffect(
    applied=False, changed=(), failure=None, evidence_lost=(), collateral_units=()
)


def _loadavg() -> tuple[float, float, float]:
    """The host load, beside every timing figure this stage records.

    A Stage 2 gate measured the same two paths at 122/647 µs/event at load 8-12
    and 855/3040 at load 23-67 — 7x inflation — so no absolute timing figure here
    is a device measurement and the load travels with the receipt.
    """
    try:
        first, second, third = os.getloadavg()
    except OSError:
        return LOADAVG_UNAVAILABLE
    return (first, second, third)


@dataclass(frozen=True, slots=True)
class PhaseRecord:
    """One phase. ``ok`` is the phase's own success, never the security outcome:
    a COMMIT that applied cleanly still ends in a rollback when VERIFY says so."""

    phase: Phase
    at: int
    ok: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"phase": str(self.phase), "at": self.at, "ok": self.ok, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class TransactionReceipt:
    """§16's immutable response record — the type Stage 6 consumes.

    Five refusals live in ``__post_init__`` rather than in a reviewer's head;
    each is a way a receipt could lie about what happened.
    """

    receipt_id: str
    action_id: str
    incident_id: str
    resolution_id: str
    operator_id: str
    operator_class: OperatorClass
    target_digest: str
    outcome: Outcome
    phases: tuple[PhaseRecord, ...]
    sentinel_verdict: SentinelVerdict
    token_verdict: TokenVerdict
    identity_revalidation: IdentityRevalidation
    evidence_bundle_digest: str | None
    lease_id: str | None
    postconditions: tuple[PostconditionResult, ...]
    verification: VerificationOutcome | None
    residual: InterventionResidual | None
    rollback_attempted: bool
    rollback_succeeded: bool | None
    host_kind: HostKind
    simulated: bool
    work_units: int
    loadavg: tuple[float, float, float]
    epoch_id: int
    schema_version: str = TRANSACTION_RECEIPT_V1_VERSION

    def __post_init__(self) -> None:
        require_identifier(self.receipt_id, "receipt_id")
        require_identifier(self.action_id, "action_id")
        require_non_negative_int(self.work_units, "work_units")
        if self.outcome is Outcome.COMMITTED_VERIFIED and any(
            result.satisfied is not True for result in self.postconditions
        ):
            raise ContractError(
                "COMMITTED_VERIFIED requires every postcondition True; an unverifiable "
                "one is None, and None is not True (ADR-0004)"
            )
        if self.outcome in COMMITTED_OUTCOMES and self.sentinel_verdict.decision is Decision.DENY:
            raise ContractError("a committed outcome cannot carry a SENTINEL DENY verdict")
        if not self.rollback_attempted and self.rollback_succeeded is not None:
            raise ContractError(
                "rollback_succeeded must be None when none was attempted; "
                "False-by-default reports an untried rollback as a failed one"
            )
        if self.simulated != (self.host_kind is not HostKind.REAL):
            raise ContractError(
                f"simulated={self.simulated} contradicts host_kind={self.host_kind!s}"
            )
        self._require_ordered_phases()

    def _require_ordered_phases(self) -> None:
        """``phases`` is a prefix-ordered subsequence of ``Phase``: prefix because
        every transaction starts at PREPARE, subsequence because VERIFY and
        ROLLBACK may be absent, strictly increasing because a receipt listing
        COMMIT before PREPARE describes a protocol that did not run."""
        if not self.phases:
            raise ContractError("a receipt with no phase records describes nothing")
        indices = [PHASE_ORDER[record.phase] for record in self.phases]
        if indices[0] != 0:
            raise ContractError("phases must begin at Phase.PREPARE")
        if any(later <= earlier for earlier, later in zip(indices, indices[1:], strict=False)):
            raise ContractError(f"phases are not in declaration order: {indices}")

    def committed(self) -> bool:
        """True when the intervention stands. Exists so ``executor/lease.py`` can ask
        without importing :class:`Outcome` and closing an import cycle."""
        return self.outcome in COMMITTED_OUTCOMES

    def reached_host(self) -> bool:
        """True when ``host.apply`` ran, including when it was undone."""
        return self.outcome in HOST_TOUCHING_OUTCOMES

    def committed_at(self) -> int | None:
        """The clock reading of the COMMIT phase, or ``None`` if it never ran."""
        for record in self.phases:
            if record.phase is Phase.COMMIT:
                return record.at
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "action_id": self.action_id,
            "incident_id": self.incident_id,
            "resolution_id": self.resolution_id,
            "operator_id": self.operator_id,
            "operator_class": int(self.operator_class),
            "target_digest": self.target_digest,
            "outcome": str(self.outcome),
            "phases": [record.to_dict() for record in self.phases],
            "sentinel_verdict": self.sentinel_verdict.to_dict(),
            "token_verdict": str(self.token_verdict),
            "identity_revalidation": str(self.identity_revalidation),
            "evidence_bundle_digest": self.evidence_bundle_digest,
            "lease_id": self.lease_id,
            # Each result serialises itself: restating its fields here would be a
            # second definition of the same row, free to drift from the first.
            "postconditions": [result.to_dict() for result in self.postconditions],
            "verification": None if self.verification is None else str(self.verification),
            "residual": None if self.residual is None else self.residual.to_dict(),
            "rollback_attempted": self.rollback_attempted,
            "rollback_succeeded": self.rollback_succeeded,
            "host_kind": str(self.host_kind),
            "simulated": self.simulated,
            "work_units": self.work_units,
            "loadavg": list(self.loadavg),
            "epoch_id": self.epoch_id,
            "schema_version": self.schema_version,
        }

    def digest(self) -> str:
        canonical = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), default=str)
        return digest_of_bytes(canonical.encode("utf-8"))


class _Refusal(Exception):
    """An in-band refusal carrying the outcome it becomes.

    A private exception rather than a sentinel return so ``_prepare`` keeps the
    signature its contract gives it while stopping at six distinct points.
    """

    def __init__(self, outcome: Outcome, detail: str) -> None:
        super().__init__(detail)
        self.outcome = outcome
        self.detail = detail


@dataclass(slots=True)
class _InFlight:
    """The one transaction this instance may have open.

    Mutable on purpose: ``_commit`` records the revalidation result without making
    a call between :func:`revalidate` and ``host.apply``, and an attribute store
    is not a call.
    """

    action_id: str
    operator: DefensiveOperator
    resolution: CBFResolutionV1
    before: HostSnapshot
    argv: tuple[str, ...]
    at: int
    revalidation: IdentityRevalidation = IdentityRevalidation.UNOBSERVABLE
    refused_identity: bool = False
    bundle: PreActionBundle | None = None
    #: Fail-closed default. A transaction that ended before redemption records
    #: a non-VALID verdict; SCOPE_MISMATCH is the honest reading of "this token
    #: was never established as applying to this action". It is never VALID.
    token_verdict: TokenVerdict = TokenVerdict.SCOPE_MISMATCH
    sentinel: SentinelVerdict | None = None
    #: The host refused the act itself: identity or subject changed after revalidation.
    binding_changed: bool = False
    lease: Lease | None = None
    journalled: bool = False
    phases: list[PhaseRecord] = field(default_factory=list)


def _refuse_untyped(operator: object, token: object) -> None:
    """Raise unless ``operator`` is a catalog-bound ``DefensiveOperator`` and ``token`` a token.

    Identity, not equality, against ``CATALOG``: ``copy.deepcopy`` of a real operator
    never re-runs ``__post_init__``, so a deep-copied spec reaches here structurally
    perfect and would pass any equality test. SENTINEL's schema check refuses it too;
    this makes the refusal a raise at the entry rather than a receipt after PREPARE.
    Exact type, not ``isinstance``: a subclass could override ``argv()`` (S5-SEC-08).
    """
    if type(operator) is not DefensiveOperator:
        raise TypeError(f"execute() takes a DefensiveOperator, got {type(operator).__name__}")
    if not isinstance(token, CapabilityToken):
        raise TypeError(f"execute() takes a CapabilityToken, got {type(token).__name__}")
    if CATALOG.get(operator.spec.operator_id) is not operator.spec:
        raise ContractError(
            f"{operator.spec.operator_id}: operator spec is not a CATALOG entry by identity"
        )


class TransactionalExecutor:
    """PREPARE, COMMIT, VERIFY, ROLLBACK, FINALIZE — and a refusal at every step.

    One in-flight transaction per instance. A second :meth:`execute` while one is
    open raises: two interleaved transactions could revalidate one target and act
    on another, which is the race this whole module exists to close.
    """

    __slots__ = (
        "_active",
        "_clock",
        "_flight",
        "_gate",
        "_governor",
        "_host",
        "_journal",
        "_kernel",
        "_leases",
        "_monitors",
        "_probe",
        "_recent_action_times",
        "_tokens",
    )

    def __init__(
        self,
        *,
        kernel: SentinelKernel,
        host: HostAdapter,
        journal: RollbackJournal,
        gate: EvidencePreservationGate,
        governor: ResourceGovernor,
        leases: LeaseRegistry,
        probe: PostconditionProbe,
        clock: Clock,
        tokens: TokenStore,
    ) -> None:
        """``tokens`` is a DECLARED DEVIATION from spec §D5.11's parameter list.

        The protocol the same section specifies begins ``token = store.redeem(...)``
        and ``TransactionReceipt`` carries a required ``token_verdict``, so the
        executor must be able to redeem; without a store it could only check a
        token it has no key for, and single-use replay defence would move outside
        the privileged path. The parameter is required rather than defaulted:
        a missing argument is a loud ``TypeError``, whereas a ``None`` default
        would be a silently skipped authority check.
        """
        self._kernel = kernel
        self._host = host
        self._journal = journal
        self._gate = gate
        self._governor = governor
        self._leases = leases
        self._probe = probe
        self._clock = clock
        self._tokens = tokens
        self._active: str | None = None
        self._flight: _InFlight | None = None
        self._recent_action_times: list[int] = []
        # Built here, not injected: a monitor that could be passed as None is a monitor
        # that can be switched off. Before this, the §33 monitors existed only in a lab
        # harness fed hand-built stand-ins, and the loop never ran them (finding R2).
        self._monitors = ResponseDefenseMonitors(
            invariants=gate.invariants, budget=STAGE5_BUDGET
        )

    # --- the only public entry point ---------------------------------------

    def execute(
        self,
        operator: DefensiveOperator,
        token: CapabilityToken,
        *,
        resolution: CBFResolutionV1,
    ) -> TransactionReceipt:
        """Run one transaction against one typed operator.

        The first parameter's annotation is exactly ``DefensiveOperator`` (trust
        rule T4). Not a union, not ``object``, not a string, so nothing declares a
        way for text, a mapping or a deserialised payload to arrive here.

        No gate type-checks the annotation, so it declares the contract without
        enforcing it. :func:`_refuse_untyped` is the enforcement — a runtime check, which
        is why the assurance table records P1 as TESTED (finding F5-honesty) — and it
        runs before *anything* is read off the argument, including ``argv()``, which an
        impostor could otherwise define for itself.
        """
        _refuse_untyped(operator, token)
        if self._active is not None:
            raise ContractError(
                f"transaction {self._active!r} is still in flight; "
                "one in-flight transaction per executor instance"
            )
        self._active = token.action_id
        try:
            return self._run(operator, token, resolution=resolution)
        finally:
            self._active = None
            self._flight = None

    # --- the protocol ------------------------------------------------------

    def _run(
        self,
        operator: DefensiveOperator,
        token: CapabilityToken,
        *,
        resolution: CBFResolutionV1,
    ) -> TransactionReceipt:
        started = self._governor.spend_report().get(GOVERNOR_TOTAL_KEY, 0)
        before = self._host.snapshot()
        flight = _InFlight(
            action_id=token.action_id,
            operator=operator,
            resolution=resolution,
            before=before,
            argv=operator.argv(),
            at=self._clock.now(),
        )
        self._flight = flight
        # One handler over the whole protocol, not just PREPARE. A refusal raised
        # later — a journal that filled between phases, for instance — must still
        # become a receipt: a private exception escaping `execute` would hand the
        # caller an opaque error where the contract promises an auditable record.
        try:
            bundle, _ = self._prepare(operator, token, resolution=resolution)
            return self._act(operator, bundle, started)
        except _Refusal as refusal:
            return self._seal(flight, refusal.outcome, started, detail=refusal.detail)

    def _act(
        self, operator: DefensiveOperator, bundle: PreActionBundle, started: int
    ) -> TransactionReceipt:
        """COMMIT, then verify or undo. Reached only after PREPARE passed."""
        flight = self._require_flight()
        effect = self._commit(operator, bundle)
        flight.phases.append(
            PhaseRecord(
                phase=Phase.COMMIT,
                at=self._clock.now(),
                ok=effect.applied,
                detail=str(flight.revalidation),
            )
        )
        # The privileged act itself goes into the digest chain, including when it
        # was refused on identity: a chain that records the intent and the outcome
        # but not the act is an audit trail with the interesting row missing.
        self._journal_phase(
            Phase.COMMIT,
            {
                "revalidation": str(flight.revalidation),
                "applied": effect.applied,
                "changed": list(effect.changed),
                "evidence_lost": list(effect.evidence_lost),
            },
        )
        if flight.refused_identity or effect.failure is HostFailure.TARGET_BINDING_CHANGED:
            # Either revalidation refused, or the host refused inside the act because the
            # identity or subject changed after revalidation. Nothing changed either way.
            self._release_lease(flight)
            detail = "identity changed" if flight.refused_identity else (
                "target binding changed between revalidation and the act; host refused"
            )
            return self._seal(flight, Outcome.REFUSED_IDENTITY, started, detail=detail)
        if operator.spec.operator_id not in RESTORATION_OPERATOR_IDS:
            # An undo is not an intervention and does not spend the action-rate budget.
            self._note_action_time(self._clock.now())
        return self._verify_or_roll_back(operator, bundle, effect, started)

    def _prepare(
        self,
        operator: DefensiveOperator,
        token: CapabilityToken,
        *,
        resolution: CBFResolutionV1,
    ) -> tuple[PreActionBundle, SentinelVerdict]:
        """Spend, redeem, preserve, journal, verify, lease — in that order, and
        every step can stop the transaction *before* the host is touched."""
        flight = self._require_flight()
        try:
            self._governor.spend(WorkKind.HOST_CALL)
        except BudgetExhausted as exc:
            # A spent budget escalates; it never widens a cap.
            raise _Refusal(Outcome.ESCALATED, f"budget exhausted: {exc}") from exc
        flight.token_verdict = self._tokens.redeem(token, operator=operator)
        if flight.token_verdict is not TokenVerdict.VALID:
            raise _Refusal(Outcome.REFUSED_TOKEN, str(flight.token_verdict))
        if (
            self._monitors.halted()
            and token.granted_by is GrantSource.POLICY
            and operator.spec.operator_id not in RESTORATION_OPERATOR_IDS
        ):
            # HALT_AUTONOMY removes the system's own permission to intervene; it does
            # not stop a person, and it never stops an undo.
            raise _Refusal(Outcome.ESCALATED, "HALT_AUTONOMY: a §33 monitor latched")
        evidence = self._gate.evaluate(
            operator=operator,
            resolution=resolution,
            snapshot=flight.before,
            rollback_state=self._capture_rollback_state(operator, flight.before),
        )
        if evidence.decision not in PRESERVING_DECISIONS or evidence.bundle is None:
            raise _Refusal(
                Outcome.REFUSED_EVIDENCE,
                f"{evidence.decision!s}: would destroy {evidence.destroyed_signals}",
            )
        flight.bundle = evidence.bundle
        self._journal_phase(Phase.PREPARE, evidence.bundle.to_dict())
        verdict = self._kernel_verdict(operator, token, evidence)
        flight.sentinel = verdict
        flight.phases.append(
            PhaseRecord(
                phase=Phase.PREPARE,
                at=self._clock.now(),
                ok=verdict.decision is not Decision.DENY,
                detail=verdict.detail,
            )
        )
        if verdict.decision is Decision.DENY:
            raise _Refusal(Outcome.REFUSED_SENTINEL, ",".join(str(r) for r in verdict.reasons))
        self._grant_lease(operator, resolution=resolution)
        return evidence.bundle, verdict

    def _kernel_verdict(
        self,
        operator: DefensiveOperator,
        token: CapabilityToken,
        evidence: EvidencePreservationVerdict,
    ) -> SentinelVerdict:
        """Hand SENTINEL every input it asks for and none of the plan: no score, no
        confidence, no candidate. The argument list is the whole interface."""
        flight = self._require_flight()
        return self._kernel.verify(
            operator,
            token,
            evidence=evidence,
            observed_identity=self._host.observe_identity(operator.target.identity.pid),
            snapshot=flight.before,
            journal_bytes=self._journal.bytes_used(),
            # Occupied, not merely unexpired: an expired-but-unswept lease and a pending
            # undo still have their change on the host (R4).
            active_leases=self._leases.occupied(),
            recent_action_times=tuple(self._recent_action_times),
            concurrent_operator_ids=self._concurrent_operator_ids(),
        )

    def _commit(self, operator: DefensiveOperator, bundle: PreActionBundle) -> HostEffect:
        """Revalidate the target, then act. Nothing may come between the two.

        ``bundle`` is required and positional, and it is read, so a refactor
        cannot drop it as unused. The last four lines are the property: the
        revalidation answer is *stored on an attribute* rather than passed through
        a helper, and the refusal returns :data:`_NO_EFFECT` rather than
        constructing one, because a constructor is a call and the AST test permits
        none between ``revalidate`` and ``host.apply``. A pid is not an identity;
        between PREPARE and here the kernel may have recycled it.
        """
        flight = self._require_flight()
        flight.bundle = bundle
        expected = flight.operator.target.identity
        observed = self._host.observe_identity(expected.pid)
        flight.revalidation = revalidate(expected, observed)
        if flight.revalidation not in ACTIONABLE_REVALIDATIONS:
            flight.refused_identity = True
            return _NO_EFFECT
        return self._host.apply(operator, flight.argv)

    def _verify(
        self, operator: DefensiveOperator, effect: HostEffect
    ) -> tuple[PostconditionResult, ...]:
        """Probe the host. Command success is not security success, so this reads
        the host rather than the return value of the call that changed it — plus
        the evidence the host itself reported destroying, which the after-snapshot
        cannot show (F4)."""
        flight = self._require_flight()
        return self._probe.probe(
            operator,
            self._host,
            before=flight.before,
            resolution=flight.resolution,
            evidence_lost=effect.evidence_lost,
        )

    def _rollback(self, operator: DefensiveOperator, bundle: PreActionBundle) -> bool:
        """Undo the intervention, and refuse to undo it onto the wrong process.

        A rollback is itself a privileged act, so the identity is revalidated here
        too: applying ``RESUME_PROCESS`` to a recycled pid resumes a stranger.
        """
        flight = self._require_flight()
        rollback = operator.rollback()
        if rollback is None:
            return False
        self._journal_phase(Phase.ROLLBACK, {"rollback_operator_id": rollback.spec.operator_id})
        expected = rollback.target.identity
        observed = self._host.observe_identity(expected.pid)
        if revalidate(expected, observed) not in ACTIONABLE_REVALIDATIONS:
            return False
        effect = self._host.apply(rollback, rollback.argv())
        results = self._probe.probe(
            rollback,
            self._host,
            before=flight.before,
            resolution=flight.resolution,
            evidence_lost=effect.evidence_lost,
        )
        _, still_wrong = self._verification(results)
        # A host that says the undo silently failed has not undone anything, whatever
        # the probe happens to see; before this, a no-op undo of a no-op action was
        # scored as a successful rollback (F5).
        return effect.applied and effect.failure is None and not still_wrong

    def _finalize(self, receipt: TransactionReceipt) -> None:
        """Record the terminal phase and release rollback state that is now dead.

        Released **only** when no live lease still references the action: a lease
        whose undo state was reclaimed is a permanent change with an expiry
        timestamp attached to nothing.
        """
        flight = self._require_flight()
        if not flight.journalled:
            return
        self._journal.append(
            action_id=receipt.action_id,
            phase=Phase.FINALIZE,
            at=self._clock.now(),
            operator=flight.operator,
            payload={"outcome": str(receipt.outcome), "receipt_digest": receipt.digest()},
        )
        if not self._leases.holds_action(receipt.action_id):
            self._journal.release(receipt.action_id)

    # --- helpers -----------------------------------------------------------

    def _verify_or_roll_back(
        self,
        operator: DefensiveOperator,
        bundle: PreActionBundle,
        effect: HostEffect,
        started: int,
    ) -> TransactionReceipt:
        """Verified, unverified or undone — and never flattered: an action whose
        effect could not be observed is ``COMMITTED_UNVERIFIED``."""
        flight = self._require_flight()
        results = self._verify(operator, effect)
        verification, should_roll_back = self._verification(results)
        flight.phases.append(
            PhaseRecord(
                phase=Phase.VERIFY,
                at=self._clock.now(),
                ok=not should_roll_back,
                detail=str(verification),
            )
        )
        if not should_roll_back:
            outcome = (
                Outcome.COMMITTED_VERIFIED
                if all(result.satisfied is True for result in results) and effect.applied
                else Outcome.COMMITTED_UNVERIFIED
            )
            return self._seal(
                flight, outcome, started, results=results, verification=verification
            )
        succeeded = self._rollback(operator, bundle)
        flight.phases.append(
            PhaseRecord(
                phase=Phase.ROLLBACK, at=self._clock.now(), ok=succeeded, detail=str(verification)
            )
        )
        if succeeded:
            self._release_lease(flight)
        else:
            # The change is still on the host. Releasing the lease here used to discard
            # the lease AND (via _finalize) the undo state, leaving a permanent change
            # with no retry (F3). A pending undo keeps both, and the sweeper retries it.
            self._defer_lease(flight)
        return self._seal(
            flight,
            Outcome.ROLLED_BACK if succeeded else Outcome.ROLLBACK_FAILED,
            started,
            results=results,
            verification=verification,
            rollback_attempted=True,
            rollback_succeeded=succeeded,
        )

    def _verification(
        self, results: Sequence[PostconditionResult]
    ) -> tuple[VerificationOutcome, bool]:
        """Classify the probe results and say whether they demand a rollback.

        Deferred import with a reason: ``executor/verify.py`` belongs to the
        ``outcome`` package, which the work-package graph makes a consumer of this
        module, so a module-scope import would close a cycle. Re-deriving the
        classification here would put a safety decision in two places, which is
        worse than a late import.
        """
        from pocketsec.stage5.executor.verify import VerificationOutcome, verification_outcome

        outcome = verification_outcome(results)
        return outcome, outcome in {
            VerificationOutcome.INEFFECTIVE,
            VerificationOutcome.DIVERGENT,
        }

    def _seal(
        self,
        flight: _InFlight,
        outcome: Outcome,
        started: int,
        *,
        detail: str = "",
        results: Sequence[PostconditionResult] = (),
        verification: VerificationOutcome | None = None,
        rollback_attempted: bool = False,
        rollback_succeeded: bool | None = None,
    ) -> TransactionReceipt:
        """Every exit goes here, including every refusal, so no path leaves an
        action without a record."""
        if not flight.phases:
            # A refusal ahead of the PREPARE record still describes a PREPARE that
            # ran and failed; without this the receipt would open at FINALIZE.
            flight.phases.append(
                PhaseRecord(phase=Phase.PREPARE, at=flight.at, ok=False, detail=detail)
            )
        flight.phases.append(
            PhaseRecord(phase=Phase.FINALIZE, at=self._clock.now(), ok=True, detail=detail)
        )
        host_kind = self._host.host_kind
        spent = self._governor.spend_report().get(GOVERNOR_TOTAL_KEY, 0)
        bundle = flight.bundle
        receipt = TransactionReceipt(
            receipt_id=f"receipt.{flight.action_id}",
            action_id=flight.action_id,
            incident_id=flight.operator.incident_id,
            resolution_id=flight.resolution.resolution_id,
            operator_id=flight.operator.spec.operator_id,
            operator_class=flight.operator.spec.operator_class,
            target_digest=identity_digest(flight.operator.target.identity),
            outcome=outcome,
            phases=tuple(flight.phases),
            sentinel_verdict=self._sentinel_or_missing(flight),
            token_verdict=flight.token_verdict,
            identity_revalidation=flight.revalidation,
            evidence_bundle_digest=None if bundle is None else bundle.integrity_digest,
            lease_id=None if flight.lease is None else flight.lease.lease_id,
            postconditions=tuple(results),
            verification=verification,
            # The residual needs a twin prediction to compare against, which the
            # executor never has: `twin/response_twin.py` is unprivileged by design
            # (§35), so the residual is computed downstream from this receipt.
            residual=None,
            rollback_attempted=rollback_attempted,
            rollback_succeeded=rollback_succeeded,
            host_kind=host_kind,
            simulated=host_kind is not HostKind.REAL,
            work_units=max(0, spent - started),
            loadavg=_loadavg(),
            epoch_id=flight.resolution.epoch_id,
        )
        self._finalize(receipt)
        self._monitors.observe_receipt(receipt)
        return receipt

    def _sentinel_or_missing(self, flight: _InFlight) -> SentinelVerdict:
        """A receipt always carries a kernel verdict.

        Stopped before SENTINEL ran — bad token, refused evidence gate — the
        receipt records a synthesised DENY citing ``MISSING_INPUT``, never a PASS.
        A refusal that reads as "SENTINEL was fine with it" is an audit trail that
        lies.
        """
        if flight.sentinel is not None:
            return flight.sentinel
        from pocketsec.stage5.sentinel.kernel import DenyReason

        return SentinelVerdict(
            decision=Decision.DENY,
            reasons=(DenyReason.MISSING_INPUT,),
            detail="the transaction stopped before the kernel ran",
            operator_id=flight.operator.spec.operator_id,
            target_digest=identity_digest(flight.operator.target.identity),
            evaluated_checks=(),
        )

    def _journal_phase(self, phase: Phase, payload: Mapping[str, Any]) -> None:
        flight = self._require_flight()
        # An undo may use the journal's undo reserve; refusing it is what used to make a
        # full journal turn every expiring containment permanent (F2 / S5-SEC-03).
        restoration = flight.operator.spec.operator_id in RESTORATION_OPERATOR_IDS
        if not flight.journalled and self._journal.full(restoration=restoration):
            self._journal.compact()
            if self._journal.full(restoration=restoration):
                raise _Refusal(Outcome.REFUSED_JOURNAL_FULL, "journal cannot hold a new action")
        try:
            self._journal.append(
                action_id=flight.action_id,
                phase=phase,
                at=self._clock.now(),
                operator=flight.operator,
                payload=payload,
                restoration=restoration,
            )
        except JournalFull as exc:
            raise _Refusal(Outcome.REFUSED_JOURNAL_FULL, str(exc)) from exc
        flight.journalled = True

    def _grant_lease(self, operator: DefensiveOperator, *, resolution: CBFResolutionV1) -> None:
        """Lease before acting, and escalate rather than act unleased.

        :func:`requires_lease` decides: O0 and O1 leave nothing to expire, and a
        restoration operator puts the host back at its baseline, so neither needs
        a lease. A denial for anything else ends the transaction as ``ESCALATED``,
        because acting where you could not lease is the unbounded intervention §18
        forbids.
        """
        flight = self._require_flight()
        if not requires_lease(operator.spec):
            return
        granted = self._leases.grant(
            operator=operator,
            action_id=flight.action_id,
            ttl_seconds=operator.ttl_seconds,
            resolution=resolution,
        )
        if isinstance(granted, LeaseDenial):
            raise _Refusal(Outcome.ESCALATED, f"lease denied: {granted.reason!s}")
        flight.lease = granted

    def _release_lease(self, flight: _InFlight) -> None:
        if flight.lease is not None:
            self._leases.release(flight.lease.lease_id)
            flight.lease = None

    def _defer_lease(self, flight: _InFlight) -> None:
        if flight.lease is not None:
            self._leases.defer_undo(flight.lease.lease_id)

    # --- read-only surfaces and bookkeeping ----------------------------------

    def reclaim_settled_state(self) -> int:
        """Release the rollback state of every finalised action no lease still holds.

        The sweeper calls this after an undo commits. Without it the forward action's
        undo state stayed in the journal for ever once its lease had been live at
        FINALIZE, and the journal filled with dead state (F2, measured: 52 of 52 swept
        actions still held state). Returns how many were released.
        """
        if self._active is not None:
            raise ContractError("reclaim_settled_state() while a transaction is in flight")
        released = 0
        for action_id in sorted(self._journal.finalised_actions()):
            held = self._journal.rollback_state(action_id) is not None
            if held and not self._leases.holds_action(action_id):
                self._journal.release(action_id)
                released += 1
        return released

    def autonomy_halted(self) -> bool:
        """Whether a receipt-reading §33 monitor has latched HALT_AUTONOMY."""
        return self._monitors.halted()

    def monitor_findings(self) -> tuple[MonitorFinding, ...]:
        return self._monitors.findings()

    def _note_action_time(self, at: int) -> None:
        """Append to the rate-limit window, dropping oldest-first past the bound: a
        rate limit asks about the recent past."""
        self._recent_action_times.append(at)
        overflow = len(self._recent_action_times) - MAX_RECENT_ACTION_TIMES
        if overflow > 0:
            del self._recent_action_times[0:overflow]

    def _concurrent_operator_ids(self) -> frozenset[str]:
        """Ids whose change may still be on the host — live, unswept or pending undo;
        SENTINEL screens them for forbidden combinations."""
        return self._leases.held_operator_ids()

    def _capture_rollback_state(
        self, operator: DefensiveOperator, snapshot: HostSnapshot
    ) -> Mapping[str, Any]:
        """The pre-action state the undo needs, as plain JSON rows: the journal
        must digest it, and a live object would alias state about to change."""
        target = snapshot.process(operator.target.identity.pid)
        unit = target.unit if target is not None else None
        service = None if unit is None else snapshot.service(unit)
        return {
            "at": snapshot.at,
            "operator_id": operator.spec.operator_id,
            "rollback_operator_id": operator.spec.rollback_operator_id,
            "target_digest": identity_digest(operator.target.identity),
            "process_state": None if target is None else str(target.state),
            "process_unit": unit,
            "process_session_id": None if target is None else target.session_id,
            "process_socket_ids": [] if target is None else list(target.socket_ids),
            "service_running": None if service is None else service.running,
            "service_constrained": None if service is None else service.constrained,
            "restricted_sockets": sorted(snapshot.restricted_sockets),
            "sessions": list(snapshot.sessions),
        }

    def _require_flight(self) -> _InFlight:
        if self._flight is None:
            raise ContractError("no transaction is in flight")
        return self._flight

