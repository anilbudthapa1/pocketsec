"""D5.13 — post-action verification: whether the *security* outcome happened.

Architecture §20: "Command success is not security success." A privileged call
that returned 0 tells you the kernel accepted it, not that the malicious
trajectory fell, not that the host is still serving, not that the evidence you
needed is still there and not that you can still undo what you did. The last
five members of :class:`PostconditionKind` are therefore about the *incident and
the host*, not about the call returning.

What this module refuses to do:

- **It never writes the host.** :class:`PostconditionProbe` calls
  ``host.snapshot()`` and nothing else. It lives on the privileged side (§35's
  "postcondition probe") so it can read what an unprivileged planner cannot, and
  that is the only privilege it has.
- **It never turns "I could not tell" into "no".** ``satisfied is None`` means
  UNVERIFIABLE and is never conflated with ``False`` (ADR-0004). An action that
  cannot be verified cannot be considered successfully completed (§2,
  ``UNVERIFIABLE_IS_NOT_COMPLETE``), but it is also not evidence that the action
  failed, and the two lead to different receipts:
  ``COMMITTED_UNVERIFIED`` versus a rollback.
- **It never reports EFFECTIVE on a partial answer.** ``EFFECTIVE`` requires
  every emitted result to be ``True``.

**:class:`PostconditionKind` is RE-EXPORTED here, not defined here.**
``docs/stage-5-spec.md`` lists the enum in this module, but
``OperatorSpec.postconditions`` needs its members at *catalog construction* time
and package 2 is strictly upstream of package 5, so ``operators/algebra.py``
defines it and this module re-exports it — on that module's explicit
instruction. Defining a second structurally-equal enum here is exactly the
defect this repository has already shipped twice (S2-FC-01): two enums that look
identical, compare unequal, and silently make every postcondition lookup miss.
The import runs one way only (``verify`` → ``algebra``); ``algebra`` imports
nothing from this package, which is what keeps it acyclic.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.state.potential import phi
from pocketsec.stage5.host.simulated import HostAdapter, HostSnapshot, ProcessState
from pocketsec.stage5.operators.algebra import (
    DefensiveOperator,
    OperatorClass,
    PostconditionKind,
    TargetKind,
)
from pocketsec.stage5.operators.catalog import RESTORATION_OPERATOR_IDS

if TYPE_CHECKING:  # pragma: no cover - annotations only
    from collections.abc import Sequence

    from pocketsec.stage4.stage5_interface import CBFResolutionV1
    from pocketsec.stage5.constitution.schema import MissionInvariantSet

__all__ = [
    "DIVERGENCE_POSTCONDITIONS",
    "HOST_POSTCONDITIONS",
    "MIN_INTERVENING_OPERATOR_CLASS",
    "PHI_EPSILON",
    "RESTORING_OPERATOR_IDS",
    "SECURITY_EFFECT_POSTCONDITIONS",
    "STATE_POSTCONDITIONS",
    "PostconditionKind",
    "PostconditionProbe",
    "PostconditionResult",
    "VerificationOutcome",
    "verification_outcome",
]

#: ``OperatorClass.O2_REVERSIBLE_RESTRICT``. An O0 observe or O1 preserve operator
#: does not intervene, so "did the malicious trajectory fall" is not a question
#: about it and is not probed — asking it would make every observation
#: INEFFECTIVE.
MIN_INTERVENING_OPERATOR_CLASS: OperatorClass = OperatorClass.O2_REVERSIBLE_RESTRICT

#: Φ is a sum of float weights, so equality needs a tolerance. This is not a
#: threshold on Φ; it is the resolution below which "Φ moved" is not a claim.
PHI_EPSILON: float = 1e-9

#: Every operator that exists to undo another one, derived from the catalog — the
#: same derivation ``host/simulated.py`` uses for its rollback fault injection, so
#: the two agree by construction rather than by two hand-written lists.
#:
#: **Why this set exists, found by running the code.** ``TRAJECTORY_REDUCED`` asks
#: whether the malicious trajectory fell, and a restore *raises* capability on
#: purpose. Probing it for ``RESUME_PROCESS`` made every rollback verify as
#: INEFFECTIVE, which made the executor try to roll back the rollback — and a
#: restore operator has no rollback of its own, so the result was
#: ``ROLLBACK_FAILED`` on a restore that had actually worked. Command success is
#: not security success, and neither is a security question the right question
#: about an undo.
RESTORING_OPERATOR_IDS: frozenset[str] = RESTORATION_OPERATOR_IDS


#: The operator's own intended state change. A ``False`` here means the operator
#: did not do what it said it would: INEFFECTIVE.
STATE_POSTCONDITIONS: frozenset[PostconditionKind] = frozenset(
    {
        PostconditionKind.PROCESS_SUSPENDED,
        PostconditionKind.PROCESS_RESUMED,
        PostconditionKind.SOCKET_RESTRICTED,
        PostconditionKind.SOCKET_RELEASED,
        PostconditionKind.SERVICE_CONSTRAINED,
        PostconditionKind.SERVICE_RELEASED,
        PostconditionKind.SESSION_REVOKED,
        PostconditionKind.EVIDENCE_PRESENT,
    }
)

#: The security question. A ``False`` here means the command worked and bought
#: nothing, which is INEFFECTIVE in exactly the sense §20 warns about.
SECURITY_EFFECT_POSTCONDITIONS: frozenset[PostconditionKind] = frozenset(
    {PostconditionKind.TRAJECTORY_REDUCED}
)

#: "The action worked and made things worse." A ``False`` here is DIVERGENT:
#: health lost, observation lost, the attacker moved, or the undo path is gone.
DIVERGENCE_POSTCONDITIONS: frozenset[PostconditionKind] = frozenset(
    {
        PostconditionKind.SERVICE_HEALTH_ACCEPTABLE,
        PostconditionKind.OBSERVATION_RETAINED,
        PostconditionKind.ATTACKER_PATH_UNCHANGED,
        PostconditionKind.ROLLBACK_STILL_POSSIBLE,
    }
)

#: Probed for every acting operator whether or not its catalog entry names them,
#: because an operator that only declares its own effect can never be found to
#: have made things worse.
HOST_POSTCONDITIONS: tuple[PostconditionKind, ...] = (
    PostconditionKind.TRAJECTORY_REDUCED,
    PostconditionKind.SERVICE_HEALTH_ACCEPTABLE,
    PostconditionKind.OBSERVATION_RETAINED,
    PostconditionKind.ATTACKER_PATH_UNCHANGED,
    PostconditionKind.ROLLBACK_STILL_POSSIBLE,
)


@dataclass(frozen=True, slots=True)
class PostconditionResult:
    """One answer, with the observation it was read from.

    ``satisfied is None`` is UNVERIFIABLE and is a *real answer*, distinct from
    ``False``. ``observed`` carries what was actually read so a reviewer can
    disagree with the verdict without re-running the host.
    """

    kind: PostconditionKind
    satisfied: bool | None
    observed: str
    detail: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, PostconditionKind):
            raise ContractError(
                f"PostconditionResult.kind must be a PostconditionKind, got {self.kind!r}"
            )
        if self.satisfied is not None and not isinstance(self.satisfied, bool):
            raise ContractError(
                "PostconditionResult.satisfied must be True, False or None "
                f"(None means UNVERIFIABLE), got {self.satisfied!r}"
            )
        if not isinstance(self.observed, str) or not self.observed.strip():
            raise ContractError(
                "PostconditionResult.observed must state what was read; an "
                "unsourced verdict cannot be reviewed"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "satisfied": self.satisfied,
            "observed": self.observed,
            "detail": self.detail,
        }


class VerificationOutcome(StrEnum):
    """§20's four answers. ``UNVERIFIABLE`` is not a failure and not a success."""

    EFFECTIVE = "EFFECTIVE"
    INEFFECTIVE = "INEFFECTIVE"
    DIVERGENT = "DIVERGENT"
    UNVERIFIABLE = "UNVERIFIABLE"


def verification_outcome(
    results: Sequence[PostconditionResult],
) -> VerificationOutcome:
    """Fold probe results into one outcome.

    Order is the contract, and it is deliberate:

    1. an empty result set is ``UNVERIFIABLE`` — probing nothing is not success;
    2. the operator's own state postcondition ``False`` ⇒ ``INEFFECTIVE``;
    3. the security postcondition ``False`` ⇒ ``INEFFECTIVE`` (it worked and
       bought nothing);
    4. a health / observation / attacker-path / rollback postcondition ``False``
       ⇒ ``DIVERGENT`` (it worked and made things worse);
    5. any ``None`` remaining ⇒ ``UNVERIFIABLE``;
    6. otherwise every result is ``True`` ⇒ ``EFFECTIVE``.

    Step 4 fires even when the state postcondition came back ``None`` rather
    than ``True``. The spec's clause reads "state postcondition is True *but* a
    health postcondition is False"; refusing to call the unverifiable-state case
    DIVERGENT would report "made things worse" as "cannot tell" and skip the
    rollback, which is the wrong direction to fail in.
    """
    if not results:
        return VerificationOutcome.UNVERIFIABLE
    if _any_false(results, STATE_POSTCONDITIONS):
        return VerificationOutcome.INEFFECTIVE
    if _any_false(results, SECURITY_EFFECT_POSTCONDITIONS):
        return VerificationOutcome.INEFFECTIVE
    if _any_false(results, DIVERGENCE_POSTCONDITIONS):
        return VerificationOutcome.DIVERGENT
    if any(result.satisfied is None for result in results):
        return VerificationOutcome.UNVERIFIABLE
    return VerificationOutcome.EFFECTIVE


def _any_false(
    results: Sequence[PostconditionResult], family: frozenset[PostconditionKind]
) -> bool:
    return any(
        result.satisfied is False and result.kind in family for result in results
    )


@dataclass(frozen=True, slots=True)
class _ProbeContext:
    """Everything a single postcondition handler is allowed to look at."""

    operator: DefensiveOperator
    before: HostSnapshot
    after: HostSnapshot
    invariants: MissionInvariantSet
    resolution: CBFResolutionV1
    lineage: tuple[int, ...]
    evidence_lost: frozenset[str]


class PostconditionProbe:
    """Reads the host after an action and answers §20's six questions.

    It holds the mission invariants because "evidence visibility retained" is a
    question about *what this host was told to keep*, not a generic one: an
    ``EVIDENCE_RETENTION`` invariant names the signal, and a probe with no
    invariant set would have to either assume nothing is required (and always
    pass) or assume everything is (and always fail).
    """

    def __init__(self, *, invariants: MissionInvariantSet) -> None:
        self._invariants = invariants

    def probe(
        self,
        operator: DefensiveOperator,
        host: HostAdapter,
        *,
        before: HostSnapshot,
        resolution: CBFResolutionV1,
        evidence_lost: Sequence[str] = (),
    ) -> tuple[PostconditionResult, ...]:
        """Probe the host after ``operator`` ran.

        ``evidence_lost`` is what the host itself reported destroying (``HostEffect.
        evidence_lost``). The executor always passes it; the empty default is the true
        answer for a probe that follows no act. Reading only the after-snapshot missed a
        loss the host had *reported* (findings F4 / S5-SEC-01), because a suspended row
        still lists the signal it stopped producing.
        """
        after = host.snapshot()
        context = _ProbeContext(
            operator=operator,
            before=before,
            after=after,
            invariants=self._invariants,
            resolution=resolution,
            lineage=_lineage_pids(before, operator),
            evidence_lost=frozenset(str(name) for name in evidence_lost),
        )
        return tuple(_evaluate(kind, context) for kind in _kinds_for(operator))


def _kinds_for(operator: DefensiveOperator) -> tuple[PostconditionKind, ...]:
    declared = tuple(operator.spec.postconditions)
    extra = tuple(
        kind
        for kind in HOST_POSTCONDITIONS
        if kind not in declared and _host_kind_applies(kind, operator)
    )
    return declared + extra


def _host_kind_applies(kind: PostconditionKind, operator: DefensiveOperator) -> bool:
    if kind is PostconditionKind.TRAJECTORY_REDUCED:
        return (
            operator.spec.operator_class >= MIN_INTERVENING_OPERATOR_CLASS
            and operator.spec.operator_id not in RESTORING_OPERATOR_IDS
        )
    if kind is PostconditionKind.ROLLBACK_STILL_POSSIBLE:
        # An operator declared IRREVERSIBLE never had an undo path, so probing
        # for one would report every authorised irreversible action as
        # DIVERGENT. Irreversibility is gated at A5 by the constitution, not here.
        return operator.spec.rollback_operator_id is not None
    return True


def _evaluate(kind: PostconditionKind, ctx: _ProbeContext) -> PostconditionResult:
    """Total dispatch over :class:`PostconditionKind` — no ``case _``.

    Adding a member to the enum without handling it here is a ``mypy --strict``
    error rather than a silently unprobed postcondition.
    """
    match kind:
        case PostconditionKind.PROCESS_SUSPENDED:
            satisfied, observed = _process_state_is(ctx, ProcessState.SUSPENDED)
        case PostconditionKind.PROCESS_RESUMED:
            satisfied, observed = _process_state_is(ctx, ProcessState.RUNNING)
        case PostconditionKind.SOCKET_RESTRICTED:
            satisfied, observed = _socket_restricted(ctx, expected=True)
        case PostconditionKind.SOCKET_RELEASED:
            satisfied, observed = _socket_restricted(ctx, expected=False)
        case PostconditionKind.SERVICE_CONSTRAINED:
            satisfied, observed = _service_constrained(ctx, expected=True)
        case PostconditionKind.SERVICE_RELEASED:
            satisfied, observed = _service_constrained(ctx, expected=False)
        case PostconditionKind.SESSION_REVOKED:
            satisfied, observed = _session_revoked(ctx)
        case PostconditionKind.EVIDENCE_PRESENT:
            satisfied, observed = _evidence_present(ctx)
        case PostconditionKind.TRAJECTORY_REDUCED:
            satisfied, observed = _trajectory_reduced(ctx)
        case PostconditionKind.SERVICE_HEALTH_ACCEPTABLE:
            satisfied, observed = _service_health(ctx)
        case PostconditionKind.OBSERVATION_RETAINED:
            satisfied, observed = _observation_retained(ctx)
        case PostconditionKind.ATTACKER_PATH_UNCHANGED:
            satisfied, observed = _attacker_path_unchanged(ctx)
        case PostconditionKind.ROLLBACK_STILL_POSSIBLE:
            satisfied, observed = _rollback_still_possible(ctx)
    return PostconditionResult(
        kind=kind,
        satisfied=satisfied,
        observed=observed,
        detail=f"{ctx.operator.spec.operator_id} on {ctx.operator.incident_id}",
    )


def _lineage_pids(
    snapshot: HostSnapshot, operator: DefensiveOperator
) -> tuple[int, ...]:
    """The pid set both snapshots are measured over.

    Computed once, from the *before* snapshot, so the two capability counts are
    taken over one key space rather than over whatever each snapshot happens to
    contain — the same reason §4.9 makes the key-space test mandatory.
    """
    pid = operator.target.identity.pid
    row = snapshot.process(pid)
    if row is None:
        return (pid,)
    return (pid, *row.children)


def _process_state_is(
    ctx: _ProbeContext, expected: ProcessState
) -> tuple[bool | None, str]:
    pid = ctx.operator.target.identity.pid
    row = ctx.after.process(pid)
    if row is None:
        return None, f"pid {pid} absent from the post-action snapshot"
    return row.state is expected, f"pid {pid} state {row.state.name}"


def _socket_restricted(
    ctx: _ProbeContext, *, expected: bool
) -> tuple[bool | None, str]:
    if ctx.operator.spec.target_kind is not TargetKind.SOCKET:
        return None, "operator target is not a socket; restriction unobservable"
    socket_id = ctx.operator.target.scope.subject
    restricted = socket_id in ctx.after.restricted_sockets
    return restricted is expected, f"socket {socket_id} restricted={restricted}"


def _service_constrained(
    ctx: _ProbeContext, *, expected: bool
) -> tuple[bool | None, str]:
    if ctx.operator.spec.target_kind is not TargetKind.SERVICE:
        return None, "operator target is not a service; constraint unobservable"
    unit = ctx.operator.target.scope.subject
    row = ctx.after.service(unit)
    if row is None:
        return None, f"unit {unit} absent from the post-action snapshot"
    return row.constrained is expected, f"unit {unit} constrained={row.constrained}"


def _session_revoked(ctx: _ProbeContext) -> tuple[bool | None, str]:
    if ctx.operator.spec.target_kind is not TargetKind.SESSION:
        return None, "operator target is not a session; revocation unobservable"
    session = ctx.operator.target.scope.subject
    present = session in ctx.after.sessions
    return not present, f"session {session} present={present}"


def _volatile_signals(snapshot: HostSnapshot) -> frozenset[str]:
    signals: set[str] = set()
    for row in snapshot.processes:
        signals.update(row.volatile_signals)
    return frozenset(signals)


def _evidence_present(ctx: _ProbeContext) -> tuple[bool | None, str]:
    lost = (_volatile_signals(ctx.before) - _volatile_signals(ctx.after)) | ctx.evidence_lost
    refs = len(ctx.operator.evidence_refs)
    if not lost:
        return True, f"no volatile signal lost; {refs} evidence refs carried"
    if refs:
        return True, f"{len(lost)} volatile signals lost, {refs} preserved by digest"
    return False, f"{len(lost)} volatile signals lost with no evidence ref: " + ",".join(
        sorted(lost)
    )


def _trajectory_reduced(ctx: _ProbeContext) -> tuple[bool | None, str]:
    before_phi = phi(ctx.before.security_state).total
    after_phi = phi(ctx.after.security_state).total
    moved = f"phi {before_phi:.4f}->{after_phi:.4f}"
    if after_phi < before_phi - PHI_EPSILON:
        return True, moved
    if after_phi > before_phi + PHI_EPSILON:
        return False, moved + " (rose)"
    before_cap = _capability_units(ctx.before, ctx)
    after_cap = _capability_units(ctx.after, ctx)
    capability = f"{moved} unchanged; lineage capability {before_cap}->{after_cap}"
    if after_cap < before_cap:
        return True, capability
    if _upstream_incomplete(ctx.resolution):
        # The resolution lost worlds or ran degraded, so "the trajectory did not
        # fall" is not something this host state can settle. §3.2 rule 4: a
        # truncated resolution raises shadow, it does not raise confidence.
        return None, capability + "; upstream resolution truncated/degraded"
    return False, capability


def _capability_units(snapshot: HostSnapshot, ctx: _ProbeContext) -> int:
    """What the target can still do, counted in comparable units.

    The count covers the process lineage *and* the operator's own scope, because
    an operator that constrains a service or restricts a socket leaves every
    process row untouched: a lineage-only count would report "capability
    unchanged" after a successful containment and every service constraint would
    verify as INEFFECTIVE.
    """
    units = 0
    for pid in ctx.lineage:
        row = snapshot.process(pid)
        if row is None:
            continue
        if row.state is ProcessState.RUNNING:
            units += 1
        units += sum(
            1
            for socket_id in row.socket_ids
            if socket_id not in snapshot.restricted_sockets
        )
    subject = ctx.operator.target.scope.subject
    kind = ctx.operator.spec.target_kind
    if kind is TargetKind.SESSION and subject in snapshot.sessions:
        units += 1
    if kind is TargetKind.SOCKET and subject not in snapshot.restricted_sockets:
        units += 1
    if kind is TargetKind.SERVICE:
        service = snapshot.service(subject)
        if service is not None and service.running and not service.constrained:
            units += 1
    return units


def _upstream_incomplete(resolution: CBFResolutionV1) -> bool:
    return bool(resolution.truncations) or bool(resolution.degradations)


def _service_health(ctx: _ProbeContext) -> tuple[bool | None, str]:
    own = (
        ctx.operator.target.scope.subject
        if ctx.operator.spec.target_kind is TargetKind.SERVICE
        else None
    )
    healthy_before = [
        row for row in ctx.before.services if row.running and row.healthy
    ]
    degraded: list[str] = []
    for row in healthy_before:
        if row.unit == own:
            # The operator's own target: constraining it is the intended effect
            # and is verified by SERVICE_CONSTRAINED. Counting it here would
            # report every successful containment as collateral.
            continue
        now = ctx.after.service(row.unit)
        if now is None or not now.running or not now.healthy:
            degraded.append(row.unit)
    observed = f"{len(healthy_before)} healthy before, {len(degraded)} degraded after"
    if degraded:
        return False, observed + ": " + ",".join(sorted(degraded))
    return True, observed


def _observation_retained(ctx: _ProbeContext) -> tuple[bool | None, str]:
    required = ctx.invariants.required_evidence()
    if not required:
        return True, "no EVIDENCE_RETENTION invariant declared"
    # Missing if it is gone from the host OR the host reported destroying it: a
    # suspended row still lists the signal it has stopped producing.
    missing = (required - _volatile_signals(ctx.after)) | (required & ctx.evidence_lost)
    observed = f"{len(required)} required signals, {len(missing)} missing"
    if missing:
        return False, observed + ": " + ",".join(sorted(missing))
    return True, observed


def _attacker_path_unchanged(ctx: _ProbeContext) -> tuple[bool | None, str]:
    pid = ctx.operator.target.identity.pid
    before_row = ctx.before.process(pid)
    after_row = ctx.after.process(pid)
    if before_row is None:
        return None, f"pid {pid} was absent before the action"
    if after_row is None:
        return None, f"pid {pid} is gone; adaptation on this lineage unobservable"
    new_children = set(after_row.children) - set(before_row.children)
    new_sockets = set(after_row.socket_ids) - set(before_row.socket_ids)
    observed = f"{len(new_children)} new children, {len(new_sockets)} new sockets"
    if new_children or new_sockets:
        return False, observed
    return True, observed


def _rollback_still_possible(ctx: _ProbeContext) -> tuple[bool | None, str]:
    rollback_id = ctx.operator.spec.rollback_operator_id
    if rollback_id is None:
        return False, "operator declares no rollback operator"
    if ctx.operator.spec.target_kind is TargetKind.SERVICE:
        unit = ctx.operator.target.scope.subject
        row = ctx.after.service(unit)
        if row is None:
            return False, f"unit {unit} is gone; {rollback_id} has no target"
        return row.restartable, f"unit {unit} restartable={row.restartable}"
    pid = ctx.operator.target.identity.pid
    if ctx.after.process(pid) is None:
        return False, f"pid {pid} is gone; {rollback_id} has no target"
    return True, f"pid {pid} present; {rollback_id} addressable"
