"""D5.12 — leases that expire whether or not anybody asked, and hysteresis.

Architecture §18 says every autonomous intervention is **scoped, expiring,
observable and rollback-aware**. This module is where "expiring" stops being a
docstring.

**Expiry is a property of the data, not of a call.** :meth:`Lease.expired` reads
only the lease's own frozen fields. It consults no registry, no clock object and
no ambient state, so a lease that has run out is expired at the instant its
arithmetic says so — before anybody looks. That is the difference between a lease
and a comment: a mechanism whose expiry is only noticed when something else
happens to call in is a permanent change with an optimistic timestamp.

**The sweep is explicit and is the only thing that undoes anything.** There is no
hidden expiry check inside ``grant``, ``renew``, ``active`` or any other path.
:class:`LeaseSweeper` is owned by the CLI and the gate, it is the sole caller of
:meth:`LeaseRegistry.tick`, and
``test_no_sweep_means_the_lease_is_still_expired_and_the_host_is_still_changed``
records the honest consequence: without a sweeper the lease is expired *and the
host is still changed*. This design makes that visible instead of hiding it.

**A renewal needs evidence, not a timer.** :class:`RenewalEvidence` carries a
resolution id, the claim ids that support it and the leading hypothesis's
support. A lease extends because the belief that justified it still stands, and
even perfect evidence cannot push a lease past :meth:`Lease.hard_deadline`.

**Hysteresis exists because oscillation is an attack.** Two thresholds, a dwell,
a cooldown and a cycle ceiling, and the enter threshold must be strictly above
the exit threshold or :class:`HysteresisPolicy` refuses to exist. Every number in
:data:`DEFAULT_HYSTERESIS` is a **chosen** parameter, documented as such; none is
fitted, and reporting one as a finding would be a fabricated result.

**An expired lease is not a finished one.** Until an undo receipt actually
commits, the change is still on the host, so the lease keeps occupying capacity
and keeps its rollback context: :meth:`LeaseRegistry.tick` moves it to a
*pending undo* record rather than discarding the context on the next tick, and
:class:`LeaseSweeper` retries a refused or failed undo on every later sweep and
records it in :meth:`LeaseSweeper.unrollbackable`. Before this, a sweeper undo
refused by the rate limit or a full journal, or an in-transaction rollback that
failed, left the change in place with no lease, no retry and no undo state
(findings F2, F3, S5-SEC-02), and an expired-but-unswept lease stopped counting
against the concurrency cap while its containment stayed applied (R4). The only
way a pending undo is dropped is that its target identity is gone, and that drop
is counted by :meth:`LeaseRegistry.dropped_rollback_contexts`.

**What this module refuses to do.** It grants no lease for an intervention it
cannot undo, it renews nothing that has already expired or past a hard deadline,
it never widens its own capacity, and it holds bounded state only — at most
:data:`MAX_CONCURRENT_LEASES` leases *including pending undos*, and
:data:`MAX_TRACKED_TARGETS` hysteresis rows, with every eviction counted.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage4.stage5_interface import CBFResolutionV1
from pocketsec.stage5.authority.capability import (
    AuthorityGrant,
    GrantSource,
    required_authority,
)
from pocketsec.stage5.constitution.invariants import FROZEN_CONSTITUTION
from pocketsec.stage5.executor.identity import Clock, identity_digest
from pocketsec.stage5.operators.algebra import DefensiveOperator, OperatorClass, OperatorSpec
from pocketsec.stage5.operators.catalog import (
    RESTORATION_OPERATOR_IDS as CATALOG_RESTORATION_OPERATOR_IDS,
)

if TYPE_CHECKING:  # pragma: no cover - the sweeper calls these, never builds them;
    # a runtime import would close a cycle with transactional.py.
    from pocketsec.stage5.authority.tokens import TokenStore
    from pocketsec.stage5.executor.transactional import (
        TransactionalExecutor,
        TransactionReceipt,
    )

__all__ = [
    "DEFAULT_HYSTERESIS",
    "DEFAULT_LEASE_TTL_SECONDS",
    "LEASABLE_FROM_CLASS",
    "MAX_CONCURRENT_LEASES",
    "MAX_LEASE_LIFETIME_SECONDS",
    "MAX_RENEWALS",
    "MAX_TRACKED_TARGETS",
    "MAX_UNROLLBACKABLE_RECORDS",
    "MIN_RENEWAL_CLAIM_IDS",
    "MIN_RENEWAL_SUPPORT",
    "RESTORATION_OPERATOR_IDS",
    "ControlDecision",
    "HysteresisController",
    "HysteresisPolicy",
    "Lease",
    "LeaseDenial",
    "LeaseDenialReason",
    "LeaseExpiry",
    "LeaseRegistry",
    "LeaseSweeper",
    "RenewalEvidence",
    "leasable_operator_classes",
    "requires_lease",
]

#: §4.9. Four is the governor's ``max_concurrent_leases`` too; the two constants
#: name the same budget and a test asserts they agree.
MAX_CONCURRENT_LEASES: int = 4
MAX_RENEWALS: int = 3
MAX_LEASE_LIFETIME_SECONDS: int = 3600
DEFAULT_LEASE_TTL_SECONDS: int = 300

#: The lowest operator class that leaves something behind to expire. O0
#: observation and O1 preservation change no host state, so leasing them would
#: burn capacity that a real restriction needs.
LEASABLE_FROM_CLASS: OperatorClass = OperatorClass.O2_REVERSIBLE_RESTRICT

#: The operators that exist to *undo* another one, derived from the frozen catalog
#: rather than listed: an id is a restoration operator exactly when some catalog
#: entry names it as its ``rollback_operator_id``. Deriving it means a catalog edit
#: cannot leave this set stale.
#:
#: They are not leased, and the reason is load-bearing. Every restoration entry in
#: the catalog has ``rollback_operator_id is None`` — an undo has no undo — so
#: asking the registry to lease one returns ``NO_ROLLBACK_OPERATOR`` and the
#: executor escalates instead of restoring. A lease sweep would then be unable to
#: roll anything back, which is the exact permanent-change failure §18 exists to
#: prevent. Nothing is lost by not leasing them: a restoration puts the host back
#: at its baseline, so there is nothing left for an expiry to reclaim.
RESTORATION_OPERATOR_IDS: frozenset[str] = CATALOG_RESTORATION_OPERATOR_IDS

#: CHOSEN parameters, not measured ones. A renewal requires the leading
#: explanation to still hold the majority of the support (0.5) and to cite at
#: least one claim, so a lease cannot be extended by a resolution that has
#: stopped saying anything. Neither number is fitted to any corpus.
MIN_RENEWAL_SUPPORT: float = 0.5
MIN_RENEWAL_CLAIM_IDS: int = 1

#: Bounded hysteresis state. 64 targets, FIFO eviction, evictions counted.
MAX_TRACKED_TARGETS: int = 64

#: How many "could not roll this back" rows a sweeper keeps. Bounded because the
#: sweeper is long-lived: a host where every undo is refused would otherwise grow
#: a list for as long as the agent runs. The head is kept and the rest counted.
MAX_UNROLLBACKABLE_RECORDS: int = 32


@dataclass(frozen=True, slots=True)
class Lease:
    """A scoped, expiring authority to leave one change in place.

    ``maximum_lifetime_seconds`` is the lifetime remaining **from
    ``granted_at``**. A renewal re-bases ``granted_at`` to the renewal instant and
    shortens this field by the same amount, which keeps :meth:`hard_deadline`
    invariant across renewals while letting :meth:`expires_at` stay a pure
    function of the frozen fields. ``test_the_hard_deadline_is_invariant_across_a
    _renewal`` pins that.
    """

    lease_id: str
    action_id: str
    incident_id: str
    operator_id: str
    target_digest: str
    granted_at: int
    ttl_seconds: int
    maximum_lifetime_seconds: int
    renewals: int
    rollback_operator_id: str | None

    def __post_init__(self) -> None:
        require_identifier(self.lease_id, "lease_id")
        require_identifier(self.action_id, "action_id")
        require_non_negative_int(self.granted_at, "granted_at")
        require_non_negative_int(self.renewals, "renewals")
        if not 0 < self.ttl_seconds <= MAX_LEASE_LIFETIME_SECONDS:
            raise ContractError(
                f"ttl_seconds must be in (0, {MAX_LEASE_LIFETIME_SECONDS}], "
                f"got {self.ttl_seconds}"
            )
        if not 0 < self.maximum_lifetime_seconds <= MAX_LEASE_LIFETIME_SECONDS:
            raise ContractError(
                f"maximum_lifetime_seconds must be in (0, {MAX_LEASE_LIFETIME_SECONDS}], "
                f"got {self.maximum_lifetime_seconds}"
            )
        if self.renewals > MAX_RENEWALS:
            raise ContractError(f"renewals {self.renewals} exceeds {MAX_RENEWALS}")

    def expires_at(self) -> int:
        return self.granted_at + self.ttl_seconds

    def hard_deadline(self) -> int:
        return self.granted_at + self.maximum_lifetime_seconds

    def expired(self, now: int) -> bool:
        """Pure: frozen fields and the argument, nothing else.

        Reading a registry attribute here would make expiry a question somebody
        has to ask, and the ``ManualClock`` test that never touches the registry
        would fail — which is exactly what that test is for (property P7).
        """
        return now >= self.expires_at() or now >= self.hard_deadline()

    def to_dict(self) -> dict[str, Any]:
        return {
            "lease_id": self.lease_id,
            "action_id": self.action_id,
            "incident_id": self.incident_id,
            "operator_id": self.operator_id,
            "target_digest": self.target_digest,
            "granted_at": self.granted_at,
            "ttl_seconds": self.ttl_seconds,
            "maximum_lifetime_seconds": self.maximum_lifetime_seconds,
            "renewals": self.renewals,
            "rollback_operator_id": self.rollback_operator_id,
            "expires_at": self.expires_at(),
            "hard_deadline": self.hard_deadline(),
        }


class LeaseDenialReason(StrEnum):
    CAPACITY = "CAPACITY"
    EXPIRED = "EXPIRED"
    MAX_RENEWALS = "MAX_RENEWALS"
    HARD_DEADLINE = "HARD_DEADLINE"
    NO_RENEWAL_EVIDENCE = "NO_RENEWAL_EVIDENCE"
    NO_ROLLBACK_OPERATOR = "NO_ROLLBACK_OPERATOR"
    UNKNOWN_LEASE = "UNKNOWN_LEASE"


@dataclass(frozen=True, slots=True)
class LeaseDenial:
    """A denial is a returned value, not an exception: the caller must handle it,
    and a handled denial is auditable where a swallowed exception is not."""

    reason: LeaseDenialReason
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"reason": str(self.reason), "detail": self.detail}


@dataclass(frozen=True, slots=True)
class RenewalEvidence:
    """Why a lease should live longer. §18: expire by design unless evidence
    justifies renewal."""

    resolution_id: str
    supporting_claim_ids: tuple[str, ...]
    leading_support: float

    def sufficient(self, *, min_support: float) -> bool:
        """A renewal needs a live resolution, cited claims and majority support.

        All three, conjunctively. Support alone would let a resolution that has
        lost its evidence keep a restriction in place on a number.
        """
        return (
            bool(self.resolution_id)
            and len(self.supporting_claim_ids) >= MIN_RENEWAL_CLAIM_IDS
            and self.leading_support >= min_support
        )


@dataclass(frozen=True, slots=True)
class LeaseExpiry:
    """One expired lease and what became of its rollback.

    ``rolled_back`` is ``None`` until a sweeper's executor call returns, and stays
    ``None`` when no rollback was attempted at all. ``None`` is not ``False``: an
    untried rollback and a failed one are different facts.
    """

    lease: Lease
    at: int
    rollback_operator_id: str | None
    rolled_back: bool | None
    #: The undo transaction's receipt, when one ran. The loop driver feeds it to the
    #: hysteresis controller and the effectiveness memory like any other receipt.
    receipt: TransactionReceipt | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "lease": self.lease.to_dict(),
            "at": self.at,
            "rollback_operator_id": self.rollback_operator_id,
            "rolled_back": self.rolled_back,
            "receipt_id": None if self.receipt is None else self.receipt.receipt_id,
        }


@dataclass(frozen=True, slots=True)
class _RollbackContext:
    """What a sweeper needs to undo an action once the lease is gone.

    Held by the registry because the alternative — a sweeper that reconstructs the
    operator from ids — would be a second path from a string to a privileged
    action, which is the one thing this stage must not have.
    """

    rollback_operator: DefensiveOperator
    resolution: CBFResolutionV1


@dataclass(frozen=True, slots=True)
class _PendingUndo:
    """An expired (or rollback-failed) lease whose change is still on the host."""

    lease: Lease
    context: _RollbackContext | None


class LeaseRegistry:
    """Bounded, explicit, and it never sweeps itself."""

    __slots__ = (
        "_clock",
        "_context",
        "_dropped_contexts",
        "_leases",
        "_max_concurrent",
        "_pending",
    )

    def __init__(self, *, clock: Clock, max_concurrent: int = MAX_CONCURRENT_LEASES) -> None:
        if not 0 < max_concurrent <= MAX_CONCURRENT_LEASES:
            raise ContractError(
                f"max_concurrent must be in (0, {MAX_CONCURRENT_LEASES}], got {max_concurrent}"
            )
        self._clock = clock
        self._max_concurrent = max_concurrent
        self._leases: dict[str, Lease] = {}
        self._context: dict[str, _RollbackContext] = {}
        self._pending: dict[str, _PendingUndo] = {}
        self._dropped_contexts = 0

    # --- granting ----------------------------------------------------------

    def grant(
        self,
        *,
        operator: DefensiveOperator,
        action_id: str,
        ttl_seconds: int,
        resolution: CBFResolutionV1,
    ) -> Lease | LeaseDenial:
        """Lease one intervention, or say why not.

        ``resolution`` is a DECLARED DEVIATION from spec §D5.12's parameter list.
        :class:`LeaseSweeper` must call ``executor.execute(operator, token,
        resolution=...)`` when the lease expires, and the only honest place to get
        that resolution is the caller that already has it. Without it an expiring
        lease could not be rolled back at all, which is the permanent-change
        failure §18 exists to prevent.

        An operator at or above :data:`LEASABLE_FROM_CLASS` whose rollback is not
        expressible is refused outright: an unrollbackable restriction cannot be
        leased, because the lease's whole promise is that it ends.
        """
        require_identifier(action_id, "action_id")
        ceiling = min(operator.spec.max_duration_seconds, MAX_LEASE_LIFETIME_SECONDS)
        if not 0 < ttl_seconds <= ceiling:
            raise ContractError(
                f"ttl_seconds {ttl_seconds} exceeds the operator's declared "
                f"max_duration_seconds {operator.spec.max_duration_seconds}"
            )
        rollback = operator.rollback()
        if operator.spec.operator_class >= LEASABLE_FROM_CLASS and (
            operator.spec.rollback_operator_id is None or rollback is None
        ):
            return LeaseDenial(
                reason=LeaseDenialReason.NO_ROLLBACK_OPERATOR,
                detail=f"{operator.spec.operator_id} at class "
                f"{operator.spec.operator_class.name} declares no rollback operator",
            )
        now = self._clock.now()
        if self.occupied() >= self._max_concurrent:
            # Expired-but-unswept leases and pending undos count: their change is still on
            # the host. Counting only unexpired leases let 200 containments stand at once
            # behind a cap of four when nobody swept (R4, reproduced before the fix).
            return LeaseDenial(
                reason=LeaseDenialReason.CAPACITY,
                detail=f"{self._max_concurrent} leases (including unswept and pending undos) "
                "already held",
            )
        lease = Lease(
            lease_id=f"lease.{action_id}",
            action_id=action_id,
            incident_id=operator.incident_id,
            operator_id=operator.spec.operator_id,
            target_digest=identity_digest(operator.target.identity),
            granted_at=now,
            ttl_seconds=ttl_seconds,
            maximum_lifetime_seconds=MAX_LEASE_LIFETIME_SECONDS,
            renewals=0,
            rollback_operator_id=operator.spec.rollback_operator_id,
        )
        self._leases[lease.lease_id] = lease
        if rollback is not None:
            self._context[lease.lease_id] = _RollbackContext(
                rollback_operator=rollback, resolution=resolution
            )
        return lease

    def renew(self, lease_id: str, *, evidence: RenewalEvidence, now: int) -> Lease | LeaseDenial:
        """Extend a lease on evidence, never on a timer, and never past the deadline."""
        lease = self._leases.get(lease_id)
        if lease is None:
            return LeaseDenial(LeaseDenialReason.UNKNOWN_LEASE, f"no lease {lease_id!r}")
        if lease.expired(now):
            # Expired is expired whether or not a sweeper has arrived yet. Renewing here
            # would re-base an ended lease and leave the sweep nothing to undo (F6).
            return LeaseDenial(
                LeaseDenialReason.EXPIRED, f"{lease_id} expired at {lease.expires_at()}"
            )
        if lease.renewals >= MAX_RENEWALS:
            return LeaseDenial(
                LeaseDenialReason.MAX_RENEWALS,
                f"{lease_id} has used all {MAX_RENEWALS} renewals",
            )
        if not evidence.sufficient(min_support=MIN_RENEWAL_SUPPORT):
            return LeaseDenial(
                LeaseDenialReason.NO_RENEWAL_EVIDENCE,
                f"leading_support={evidence.leading_support} with "
                f"{len(evidence.supporting_claim_ids)} claim ids",
            )
        deadline = lease.hard_deadline()
        if now + lease.ttl_seconds > deadline:
            return LeaseDenial(
                LeaseDenialReason.HARD_DEADLINE,
                f"a renewal to {now + lease.ttl_seconds} would cross the hard deadline {deadline}",
            )
        renewed = replace(
            lease,
            granted_at=now,
            maximum_lifetime_seconds=deadline - now,
            renewals=lease.renewals + 1,
        )
        self._leases[lease_id] = renewed
        return renewed

    def release(self, lease_id: str) -> None:
        """Give a lease up early, because its change is already undone (or never
        happened). Silent on an unknown id: releasing something already gone is the
        desired end state, not an error."""
        self._leases.pop(lease_id, None)
        self._context.pop(lease_id, None)

    def defer_undo(self, lease_id: str) -> None:
        """Turn a live lease whose in-transaction rollback FAILED into a pending undo.

        The change is still on the host, so releasing the lease (what the executor used
        to do) made it permanent with no retry and no undo state (F3). A pending undo
        keeps its context and its capacity slot, and the sweeper retries it.
        """
        lease = self._leases.pop(lease_id, None)
        if lease is None:
            return
        self._pending[lease_id] = _PendingUndo(lease, self._context.pop(lease_id, None))

    def confirm_undone(self, lease_id: str) -> None:
        """An undo receipt committed: the change is gone, and so is its undo state."""
        self._pending.pop(lease_id, None)

    def abandon(self, lease_id: str) -> None:
        """Drop a pending undo whose target identity no longer exists. Counted: the
        undo state is discarded because it can never be applied, not quietly."""
        if self._pending.pop(lease_id, None) is not None:
            self._dropped_contexts += 1

    # --- reading -----------------------------------------------------------

    def active(self, now: int) -> tuple[Lease, ...]:
        return tuple(lease for lease in self._leases.values() if not lease.expired(now))

    def expired(self, now: int) -> tuple[Lease, ...]:
        return tuple(lease for lease in self._leases.values() if lease.expired(now))

    def leases_on(self, target_digest: str) -> tuple[Lease, ...]:
        """Every held lease on one target, keyed by ``identity_digest`` — the same
        function that produced the token, the receipt and the journal key."""
        return tuple(
            lease for lease in self._leases.values() if lease.target_digest == target_digest
        )

    def occupied(self) -> int:
        """Leases whose change may still be on the host: live, expired-unswept, pending."""
        return len(self._leases) + len(self._pending)

    def held_operator_ids(self) -> frozenset[str]:
        """Operator ids whose change may still be on the host, for SENTINEL's combinations."""
        held = [lease.operator_id for lease in self._leases.values()]
        held += [pending.lease.operator_id for pending in self._pending.values()]
        return frozenset(held)

    def holds_action(self, action_id: str) -> bool:
        """Whether any lease or pending undo still needs this action's rollback state."""
        return any(lease.action_id == action_id for lease in self._leases.values()) or any(
            pending.lease.action_id == action_id for pending in self._pending.values()
        )

    def pending_undos(self) -> tuple[Lease, ...]:
        """Leases that ended with their change still applied, awaiting a committed undo."""
        return tuple(pending.lease for pending in self._pending.values())

    def rollback_context(self, lease_id: str) -> _RollbackContext | None:
        """The undo context for a lease, live or pending undo."""
        pending = self._pending.get(lease_id)
        return self._context.get(lease_id) or (None if pending is None else pending.context)

    def dropped_rollback_contexts(self) -> int:
        """Pending undos abandoned because their target identity is gone.

        Contexts are no longer dropped because nobody swept: a pending undo is kept
        until an undo commits. Before that fix this counter also counted contexts the
        sweeper had *consumed*, a false alarm (F9).
        """
        return self._dropped_contexts

    # --- the one explicit sweep -------------------------------------------

    def tick(self, now: int) -> tuple[LeaseExpiry, ...]:
        """Move every expired lease to a pending undo and hand back the new ones.

        This is the only method that retires an expired lease, and nothing else in
        Stage 5 calls it. ``rolled_back`` comes back ``None``: retiring a lease is
        not undoing an action, and only :class:`LeaseSweeper` can do the latter. The
        pending undo keeps its context until :meth:`confirm_undone` or
        :meth:`abandon`; a second tick no longer throws it away.
        """
        require_non_negative_int(now, "now")
        expiries: list[LeaseExpiry] = []
        for lease in self.expired(now):
            del self._leases[lease.lease_id]
            self._pending[lease.lease_id] = _PendingUndo(
                lease, self._context.pop(lease.lease_id, None)
            )
            expiries.append(
                LeaseExpiry(
                    lease=lease,
                    at=now,
                    rollback_operator_id=lease.rollback_operator_id,
                    rolled_back=None,
                )
            )
        return tuple(expiries)


class LeaseSweeper:
    """Drives :meth:`LeaseRegistry.tick` and executes each expiry's rollback.

    Owned by the CLI and the gate. There is deliberately **no** implicit sweep
    anywhere else: an expiry noticed only when some unrelated call happens to pass
    through is not an expiry, and hiding the sweep would hide the failure mode
    instead of fixing it.
    """

    __slots__ = (
        "_clock",
        "_executor",
        "_registry",
        "_tokens",
        "_unrollbackable",
        "_unrollbackable_dropped",
    )

    def __init__(
        self,
        *,
        registry: LeaseRegistry,
        executor: TransactionalExecutor,
        tokens: TokenStore,
        clock: Clock,
    ) -> None:
        self._registry = registry
        self._executor = executor
        self._tokens = tokens
        self._clock = clock
        self._unrollbackable: list[tuple[str, str]] = []
        self._unrollbackable_dropped = 0

    def sweep(self, *, now: int) -> tuple[LeaseExpiry, ...]:
        """Retire the expired leases, then attempt the undo of every pending one.

        Pending includes undos that were refused or failed on an earlier sweep: those
        are retried here, every time, until one commits. A refusal is recorded with its
        reason in :meth:`unrollbackable` and the lease stays pending — it is never
        dropped because a rate limit, a full journal or an authority refusal said no
        (S5-SEC-02, F2). The only drop is a target whose identity is gone.
        """
        fresh = {expiry.lease.lease_id: expiry for expiry in self._registry.tick(now)}
        results: list[LeaseExpiry] = []
        for lease in self._registry.pending_undos():
            expiry = fresh.get(lease.lease_id) or LeaseExpiry(
                lease=lease, at=now, rollback_operator_id=lease.rollback_operator_id,
                rolled_back=None,
            )
            context = self._registry.rollback_context(lease.lease_id)
            if context is None:
                self._note_unrollbackable(lease.lease_id, "NO_ROLLBACK_CONTEXT")
                self._registry.abandon(lease.lease_id)
                results.append(expiry)
                continue
            results.append(self._roll_back(expiry, context, now=now))
        return tuple(results)

    def _roll_back(
        self, expiry: LeaseExpiry, context: _RollbackContext, *, now: int
    ) -> LeaseExpiry:
        operator = context.rollback_operator
        lease_id = expiry.lease.lease_id
        grant = AuthorityGrant(
            authority=required_authority(operator.spec),
            granted_by=GrantSource.POLICY,
            # The one frozen policy version. SENTINEL's signature_version check
            # compares the token's against the constitution's, so anything else
            # here — a lease id, a build string — is a guaranteed DENY.
            policy_version=FROZEN_CONSTITUTION.policy_version,
            subject_operator_id=operator.spec.operator_id,
            detail=f"lease {lease_id} expired at {expiry.lease.expires_at()}",
        )
        try:
            token = self._tokens.mint(
                grant=grant,
                operator=operator,
                # Unique per attempt: a retried undo is a new transaction, and a reused
                # action id would collide in the journal with the refused attempt.
                action_id=f"{expiry.lease.action_id}.undo.{now}",
                ttl_seconds=min(operator.ttl_seconds, operator.spec.max_duration_seconds),
            )
        except ContractError as exc:
            # The authority plane refused to mint for an autonomous undo. Recorded,
            # never forced: a rollback is itself a privileged act. Still pending.
            self._note_unrollbackable(lease_id, str(exc))
            return expiry
        receipt = self._executor.execute(operator, token, resolution=context.resolution)
        if receipt.committed():
            self._registry.confirm_undone(lease_id)
            self._executor.reclaim_settled_state()
            return replace(expiry, rolled_back=True, receipt=receipt)
        reason = f"UNDO_{receipt.outcome}: {receipt.sentinel_verdict.detail}"
        if _target_gone(receipt):
            self._registry.abandon(lease_id)
            reason = f"UNDO_TARGET_GONE ({receipt.identity_revalidation}): {reason}"
        self._note_unrollbackable(lease_id, reason)
        return replace(expiry, rolled_back=False, receipt=receipt)

    def _note_unrollbackable(self, lease_id: str, reason: str) -> None:
        """Bounded, head-kept, and one row per (lease, reason): a pending undo refused
        for the same reason on every sweep is one fact, not a growing list."""
        if (lease_id, reason) in self._unrollbackable:
            return
        if len(self._unrollbackable) < MAX_UNROLLBACKABLE_RECORDS:
            self._unrollbackable.append((lease_id, reason))
            return
        self._unrollbackable_dropped += 1

    def unrollbackable(self) -> tuple[tuple[str, str], ...]:
        """Leases whose undo was not minted, was refused, failed or was abandoned, with
        the reason. A lease listed here is still pending unless it was abandoned."""
        return tuple(self._unrollbackable)

    def unrollbackable_dropped(self) -> int:
        """Rows lost past :data:`MAX_UNROLLBACKABLE_RECORDS`. Non-zero is serious:
        it means undo failures are arriving faster than anyone is reading them."""
        return self._unrollbackable_dropped


@dataclass(frozen=True, slots=True)
class HysteresisPolicy:
    """§19. Two thresholds with a gap between them, and the gap is the point."""

    enter_threshold: float
    exit_threshold: float
    min_dwell_seconds: int
    cooldown_seconds: int
    max_action_cycles: int
    escalate_after_rollbacks: int

    def __post_init__(self) -> None:
        if not self.enter_threshold > self.exit_threshold:
            raise ContractError(
                f"enter_threshold ({self.enter_threshold}) must be strictly greater than "
                f"exit_threshold ({self.exit_threshold}); equal thresholds are a "
                "thrash generator, not a controller"
            )
        require_non_negative_int(self.min_dwell_seconds, "min_dwell_seconds")
        require_non_negative_int(self.cooldown_seconds, "cooldown_seconds")
        if self.max_action_cycles < 1 or self.escalate_after_rollbacks < 1:
            raise ContractError("a controller that permits zero actions is not a controller")


#: CHOSEN parameters. ``enter_threshold=6.0`` sits between Stage 1's measured
#: benign Phi mean of 0.62 and its malicious mean of 9.46 (MEMORY.md), which makes
#: it a *defensible* choice — it is **not** fitted to any corpus, and calling it
#: fitted would be a fabricated result. The dwell, cooldown, cycle ceiling and
#: rollback ceiling are engineering judgements with no measurement behind them.
DEFAULT_HYSTERESIS = HysteresisPolicy(
    enter_threshold=6.0,
    exit_threshold=3.0,
    min_dwell_seconds=120,
    cooldown_seconds=300,
    max_action_cycles=3,
    escalate_after_rollbacks=2,
)


class ControlDecision(StrEnum):
    ACT = "ACT"
    HOLD = "HOLD"
    RELEASE = "RELEASE"
    ESCALATE = "ESCALATE"


@dataclass(slots=True)
class _TargetHistory:
    cycles: int = 0
    rollbacks: int = 0
    last_action_at: int | None = None


class HysteresisController:
    """Decides ACT / HOLD / RELEASE / ESCALATE for one target at one Phi.

    Bounded: at most :data:`MAX_TRACKED_TARGETS` histories, FIFO eviction, and the
    eviction count is readable. Unbounded per-target state on a 2 GB host is how a
    controller becomes the denial of service it was meant to prevent.
    """

    __slots__ = ("_clock", "_evictions", "_history", "_policy")

    def __init__(self, *, policy: HysteresisPolicy, clock: Clock) -> None:
        self._policy = policy
        self._clock = clock
        self._history: dict[str, _TargetHistory] = {}
        self._evictions = 0

    def decide(
        self,
        *,
        target_digest: str,
        phi_total: float,
        now: int,
        active_lease: Lease | None,
    ) -> ControlDecision:
        """Escalate on exhaustion, release below the exit threshold after the
        dwell, act above the enter threshold after the cooldown, hold otherwise.

        The band between ``exit_threshold`` and ``enter_threshold`` is where a
        single-threshold controller oscillates. Here it resolves to HOLD, which is
        what makes ``test_hysteresis_stops_thrashing`` possible.
        """
        history = self._history.get(target_digest, _TargetHistory())
        if history.cycles >= self._policy.max_action_cycles:
            return ControlDecision.ESCALATE
        if history.rollbacks >= self._policy.escalate_after_rollbacks:
            return ControlDecision.ESCALATE
        if active_lease is not None:
            dwelled = (
                history.last_action_at is None
                or now - history.last_action_at >= self._policy.min_dwell_seconds
            )
            if phi_total <= self._policy.exit_threshold and dwelled:
                return ControlDecision.RELEASE
            return ControlDecision.HOLD
        cooled = (
            history.last_action_at is None
            or now - history.last_action_at >= self._policy.cooldown_seconds
        )
        if phi_total >= self._policy.enter_threshold and cooled:
            return ControlDecision.ACT
        return ControlDecision.HOLD

    def note_outcome(self, receipt: TransactionReceipt) -> None:
        """Count what actually happened to the host.

        A rolled-back action still counts as a cycle: it disturbed the host, and
        an oscillation of act-and-undo is the attack ``ACTION_OSCILLATION`` looks
        for. The receipt is asked ``reached_host()`` and ``committed_at()`` rather
        than being compared against ``Outcome``, so this module needs no runtime
        import of ``transactional.py`` and the two do not form a cycle.
        """
        history = self._ensure(receipt.target_digest)
        if receipt.reached_host():
            history.cycles += 1
            history.last_action_at = receipt.committed_at()
        if receipt.rollback_attempted:
            history.rollbacks += 1

    def cycles(self, target_digest: str) -> int:
        history = self._history.get(target_digest)
        return 0 if history is None else history.cycles

    def rollbacks(self, target_digest: str) -> int:
        history = self._history.get(target_digest)
        return 0 if history is None else history.rollbacks

    def evictions(self) -> int:
        return self._evictions

    def tracked(self) -> Mapping[str, Mapping[str, Any]]:
        return {
            digest: {
                "cycles": history.cycles,
                "rollbacks": history.rollbacks,
                "last_action_at": history.last_action_at,
            }
            for digest, history in self._history.items()
        }

    def _ensure(self, target_digest: str) -> _TargetHistory:
        history = self._history.get(target_digest)
        if history is not None:
            return history
        if len(self._history) >= MAX_TRACKED_TARGETS:
            oldest = next(iter(self._history))
            del self._history[oldest]
            self._evictions += 1
        fresh = _TargetHistory()
        self._history[target_digest] = fresh
        return fresh


def _target_gone(receipt: TransactionReceipt) -> bool:
    """Whether an undo failed because the target identity no longer exists.

    Such an undo can never be authorised again: SENTINEL's identity check and the
    executor's revalidation both refuse a different or exited process. Retrying it
    forever would pin a capacity slot to a process that is not there.
    """
    gone = str(receipt.identity_revalidation) in {"EXITED", "PID_REUSED"}
    return gone or "TARGET_IDENTITY" in {str(r) for r in receipt.sentinel_verdict.reasons}


def requires_lease(spec: OperatorSpec) -> bool:
    """Whether an action of this operator leaves something a lease must reclaim.

    Exported so the executor and the gate's G5.6 check read one predicate instead
    of restating the rule. Two conditions, both necessary: the class must be at or
    above :data:`LEASABLE_FROM_CLASS`, and the operator must not itself be a
    restoration operator (see :data:`RESTORATION_OPERATOR_IDS`).
    """
    return (
        spec.operator_class >= LEASABLE_FROM_CLASS
        and spec.operator_id not in RESTORATION_OPERATOR_IDS
    )


def leasable_operator_classes() -> tuple[OperatorClass, ...]:
    """The classes a lease is granted for. Exported so the gate's G5.6 check reads
    the same set the registry enforces rather than restating it."""
    return tuple(member for member in OperatorClass if member >= LEASABLE_FROM_CLASS)
