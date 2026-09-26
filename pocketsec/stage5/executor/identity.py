"""D5.11 — the clock, the single target-identity key space, and the TOCTOU decision table.

This module exists for three jobs, and each one is a security property rather
than a convenience.

**A clock that does not advance on its own.** :class:`ManualClock` is the clock
every expiry test uses. A lease whose expiry is only noticed because some other
call happened to look at the wall clock is a permanent change with an optimistic
docstring (architecture §18), so the tests drive time explicitly and the
production clock (:class:`SystemClock`) is the only thing that reads the host.

**One key space for "which process is this".** :func:`identity_digest` is *the*
function that produces ``CapabilityToken.target_digest``,
``TransactionReceipt.target_digest``, ``Lease.target_digest``, the effectiveness
memory's context keys and the rollback journal's action key. Two waves of this
project have already shipped a defect where two key spaces were joined that
could never match (S2-FC-01, then Stage 3 repeated the class), so there is
exactly one producer here and ``tests/test_stage5_executor.py`` asserts all five
consumers read the same string (§4.9 Rule A).

**A pid is not an identity.** :func:`revalidate` is the whole of the
time-of-check/time-of-use defence, and it is deliberately a pure function over
two snapshots so it can be exhaustively tested without a host. It refuses far
more than it accepts: :data:`ACTIONABLE_REVALIDATIONS` holds
:data:`IdentityRevalidation.MATCH` and nothing else, so every non-MATCH answer —
including "could not observe" — stops an intervention.

**What this module refuses to do.** It never observes a host (it is handed
snapshots), it never constructs an operator, it never decides authority, and it
has no notion of a plan, a score or a confidence. Its only upstream type,
``ProcessIdentity``, is imported for typing alone: this module is the innermost
part of the executor's trusted computing base and keeping its runtime import
graph to ``stage0.contracts.common`` is the point, not an accident. ``mypy
--strict`` still checks every use of it.
"""

from __future__ import annotations

import time
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol

from pocketsec.stage0.contracts.common import ContractError, digest_of_bytes

if TYPE_CHECKING:  # pragma: no cover - typing only; see the module docstring
    from pocketsec.stage5.operators.algebra import ProcessIdentity

__all__ = [
    "ACTIONABLE_REVALIDATIONS",
    "Clock",
    "IdentityRevalidation",
    "ManualClock",
    "SystemClock",
    "identity_digest",
    "revalidate",
]


class Clock(Protocol):
    """Monotonic whole seconds. Whole seconds because every bound in Stage 5 is
    an integer number of seconds and a float clock would invite sub-second
    arithmetic that no lease, token or dwell window is defined over."""

    def now(self) -> int: ...


class ManualClock:
    """A clock that advances only when a caller says so.

    Every expiry test in this stage uses this, because the property under test is
    "the lease is expired", not "something eventually noticed". A test that waits
    for a real clock measures the scheduler.
    """

    __slots__ = ("_at",)

    def __init__(self, at: int = 0) -> None:
        if not isinstance(at, int) or isinstance(at, bool) or at < 0:
            raise ContractError(f"ManualClock(at=) must be a non-negative int, got {at!r}")
        self._at = at

    def now(self) -> int:
        return self._at

    def advance(self, seconds: int) -> None:
        """Move forward. Time does not run backwards, so a negative step raises
        rather than silently un-expiring a lease."""
        if not isinstance(seconds, int) or isinstance(seconds, bool) or seconds < 0:
            raise ContractError(f"advance(seconds=) must be a non-negative int, got {seconds!r}")
        self._at += seconds


class SystemClock:
    """``time.monotonic_ns()`` floored to seconds.

    Monotonic rather than wall-clock deliberately: a lease must not be extended
    or expired by an NTP step, and containment duration is an interval, not a
    date.
    """

    __slots__ = ()

    def now(self) -> int:
        return time.monotonic_ns() // 1_000_000_000


def identity_digest(identity: ProcessIdentity) -> str:
    """THE key-space function for "which process is this".

    Every target string in Stage 5 — token, lease, receipt, journal action key
    and SENTINEL's identity check — is produced here and nowhere else. A second
    producer is how two key spaces drift into never matching, which this project
    has paid for twice.
    """
    return digest_of_bytes(identity.canonical_bytes())


class IdentityRevalidation(StrEnum):
    """The answers a revalidation may give. Only one of them permits an action."""

    MATCH = "MATCH"
    EXITED = "EXITED"
    PID_REUSED = "PID_REUSED"
    EXECUTABLE_CHANGED = "EXECUTABLE_CHANGED"
    UID_CHANGED = "UID_CHANGED"
    UNOBSERVABLE = "UNOBSERVABLE"


#: The one actionable answer. A frozenset of a single member rather than an
#: ``== MATCH`` comparison at each call site, so the set of things that permit
#: privilege is a single named object a reviewer can grep for and a test can pin.
ACTIONABLE_REVALIDATIONS: frozenset[IdentityRevalidation] = frozenset(
    {IdentityRevalidation.MATCH}
)


def revalidate(
    expected: ProcessIdentity, observed: ProcessIdentity | None
) -> IdentityRevalidation:
    """Compare the identity an action was planned against with the one observed now.

    The order of the checks is the order of decreasing certainty about what went
    wrong, and every branch is a refusal except the last:

    * ``observed is None`` is :data:`~IdentityRevalidation.EXITED`, **never**
      MATCH. The target this plan was about is gone; acting on "the pid" would
      act on whatever holds it now.
    * a differing ``pid`` or ``start_time_ticks`` is
      :data:`~IdentityRevalidation.PID_REUSED`. ``start_time_ticks`` is the field
      that makes a pid an identity; the kernel recycles the number, not the
      start time.
    * an ``executable_digest`` that is present on one side and absent on the
      other is :data:`~IdentityRevalidation.UNOBSERVABLE` — **an absence of
      evidence is not a match.** The architecture asks for executable identity
      "where available"; where it stopped being available between plan and act,
      that is a change we cannot rule out rather than one we can rule in.
    * two differing non-``None`` digests are
      :data:`~IdentityRevalidation.EXECUTABLE_CHANGED`: the process re-execed.
    * a differing ``uid`` is :data:`~IdentityRevalidation.UID_CHANGED`.
    * a differing non-``None`` ``cgroup_id`` or ``namespace_id`` is
      :data:`~IdentityRevalidation.UNOBSERVABLE`, for the same reason as the
      digest: the target moved out of the boundary the plan reasoned about and
      this function will not claim to know into what.

    **A declared deviation, recorded rather than smoothed over.** Spec §9.2 item
    8 reads as though a ``None`` ``executable_digest`` on *both* sides should
    also be UNOBSERVABLE. Implemented that way, MATCH would be unreachable for
    the majority of corpus processes (whose digests are ``None`` because there is
    no real filesystem here) and no transaction could ever commit, which would
    make the whole executor untestable rather than safe. The rule implemented is
    the architect's narrower one: *asymmetric* absence is UNOBSERVABLE. The cost
    is stated plainly — where both sides are ``None``, the strongest identity
    binding the architecture asks for is simply not exercised, and that is
    UNMEASURED, not satisfied.
    """
    if observed is None:
        return IdentityRevalidation.EXITED
    if observed.pid != expected.pid or observed.start_time_ticks != expected.start_time_ticks:
        return IdentityRevalidation.PID_REUSED
    if (expected.executable_digest is None) != (observed.executable_digest is None):
        return IdentityRevalidation.UNOBSERVABLE
    if (
        expected.executable_digest is not None
        and observed.executable_digest is not None
        and expected.executable_digest != observed.executable_digest
    ):
        return IdentityRevalidation.EXECUTABLE_CHANGED
    if observed.uid != expected.uid:
        return IdentityRevalidation.UID_CHANGED
    if _boundary_diverged(expected.cgroup_id, observed.cgroup_id):
        return IdentityRevalidation.UNOBSERVABLE
    if _boundary_diverged(expected.namespace_id, observed.namespace_id):
        return IdentityRevalidation.UNOBSERVABLE
    return IdentityRevalidation.MATCH


def _boundary_diverged(expected: str | None, observed: str | None) -> bool:
    """True when a containment boundary changed or stopped being observable.

    Both ``None`` is not a divergence: it is the honest "this host model does not
    expose namespaces", and §9.2 item 9 already records that these are fixture
    strings whose correspondence to a real namespace boundary is UNMEASURED.
    """
    if expected is None and observed is None:
        return False
    return expected != observed
