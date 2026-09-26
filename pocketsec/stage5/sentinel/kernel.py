"""D5.4 — SENTINEL: the independent constraint kernel that can deny every action.

Everything upstream produces beliefs; nothing reaches privilege unless this kernel says
PASS. The architecture separates it so the code able to stop an action stays small enough to
read in one sitting and to test exhaustively. Independence is a construction, not a
convention: ``__init__`` takes exactly three keyword-only parameters, so no plan, score,
confidence, planner verdict or permission to proceed can enter and the kernel cannot be
*told* the answer; the module defines no name from the escape-hatch vocabulary that
``tests/test_stage5_sentinel.py`` pins in ``ESCAPE_NAME_PATTERN`` (the pattern lives in the
test so this file holds no spelling of it); nothing under ``sentinel/`` imports ``aegis/``,
``safe/``, ``twin/``, ``memory/`` or ``cells/``, so kernel and planner share no type and no
mutable state; :meth:`SentinelKernel.verify` turns any raise from a check into
``DENY``/``KERNEL_FAULT`` and any ``None`` required argument into ``DENY``/``MISSING_INPUT``,
because **a kernel that crashes denies** rather than abstaining or passing; and it reads no
verdict, confidence or support, so a maximally confident planner and a maximally uncertain
one get the same answer (ADR-0003).

Two readings differ from the obvious one. ``_authority`` wants the token's class to be
*exactly* the catalog's class for the operator: less is an escalation, more is a capability
whose reach exceeds the declared action. ``_constitution`` denies on ``REFUSED`` but not on
``HUMAN_REQUIRED``, because SENTINEL cannot observe whether a person approved and denying on
it would make the human-approved path unreachable for the nine catalog entries the
constitution routes to a person. Instead the token (schema v2) carries its MAC-covered
``granted_by``, and ``_check_authority`` denies a ``POLICY`` token for any operator whose
autonomy needs a human, independently of ``TokenStore.mint`` refusing to issue one. What it
still cannot establish is that a ``HUMAN`` grant was made by a person: ``GrantSource.HUMAN``
is an enum value its caller writes (S5-SEC-07, an accepted, documented limit). What SENTINEL
holds independently is the part no planner can argue with: ``AX`` and the prohibited classes
are refused outright, the authority class must match the catalog, the token's binding digest
must name this exact operator, subject and ttl, a scoped subject must belong to the target
process, and an operator with no postcondition may not begin.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage5.authority.capability import (
    HUMAN_REQUIRED_AUTONOMY, GrantSource, autonomy_of, escalates, required_authority,
)
from pocketsec.stage5.authority.tokens import (
    CAPABILITY_TOKEN_V2_VERSION, MAX_TOKEN_LIFETIME_SECONDS, CapabilityToken,
)
from pocketsec.stage5.constitution.invariants import (
    AuthorityClass, ConstitutionDecision, ResponseConstitution,
)
from pocketsec.stage5.constitution.schema import InvariantKind, MissionInvariantSet
from pocketsec.stage5.evidence.preservation_gate import (
    EvidencePreservationVerdict, PreservationDecision,
)
from pocketsec.stage5.governor import STAGE5_BUDGET
from pocketsec.stage5.host.simulated import HostSnapshot
from pocketsec.stage5.operators.algebra import (
    DefensiveOperator, OperatorClass, PreconditionKind, ProcessIdentity, Reversibility,
    TargetKind,
)
from pocketsec.stage5.operators.catalog import CATALOG

if TYPE_CHECKING:  # pragma: no cover - typing only; no runtime coupling
    from pocketsec.stage5.executor.identity import Clock

__all__ = [
    "CHECK_ORDER", "FORBIDDEN_COMBINATIONS", "SENTINEL_KERNEL_VERSION", "Decision",
    "DenyReason", "SentinelKernel", "SentinelVerdict",
]

SENTINEL_KERNEL_VERSION: str = "sentinel-1.0.0"


class Decision(StrEnum):
    PASS = "PASS"
    DENY = "DENY"


class DenyReason(StrEnum):
    """§4's verification list, one member per bullet, plus the two fail-closed members."""

    SCHEMA = "SCHEMA"
    SIGNATURE_VERSION = "SIGNATURE_VERSION"
    AUTHORITY = "AUTHORITY"
    SCOPE = "SCOPE"
    TARGET_IDENTITY = "TARGET_IDENTITY"
    PRECONDITION = "PRECONDITION"
    MISSION_INVARIANT = "MISSION_INVARIANT"
    EVIDENCE_PRESERVATION = "EVIDENCE_PRESERVATION"
    ROLLBACK_MISSING = "ROLLBACK_MISSING"
    EXPIRY = "EXPIRY"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    FORBIDDEN_COMBINATION = "FORBIDDEN_COMBINATION"
    CONSTITUTION = "CONSTITUTION"
    KERNEL_FAULT = "KERNEL_FAULT"
    MISSING_INPUT = "MISSING_INPUT"


#: Method-name prefix for the thirteen checks. Named so the stored constitution and the
#: constitution *check* do not collide in ``__slots__``, and so a reader grepping for the
#: checks finds exactly thirteen methods.
_CHECK_PREFIX: str = "_check_"

#: The thirteen checks in evaluation order. ``schema`` is first because no later check can
#: read an input whose shape was refused; when it denies, the rest are not evaluated and
#: ``evaluated_checks`` says so.
CHECK_ORDER: tuple[str, ...] = (
    "schema", "signature_version", "constitution", "authority", "scope", "target_identity",
    "preconditions", "mission_invariants", "evidence_preservation", "rollback_expiry",
    "resource_limits", "forbidden_combinations", "lease_capacity",
)

#: Operator id sets that may not be in flight together on one incident: refused when the
#: active ids plus the proposed id contain all of a member. Named pairs rather than a rule
#: over consequence classes, which would have to reason about the host.
FORBIDDEN_COMBINATIONS: frozenset[frozenset[str]] = frozenset(
    {
        frozenset({"SUSPEND_PROCESS", "REVOKE_LOCAL_SESSION"}),
        frozenset({"SUSPEND_PROCESS", "TERMINATE_PROCESS"}),
        frozenset({"CONSTRAIN_SERVICE", "REVOKE_LOCAL_SESSION"}),
        frozenset({"RESTRICT_LOCAL_SOCKET", "TERMINATE_PROCESS"}),
        frozenset({"TRACE_PROCESS_BOUNDED", "TERMINATE_PROCESS"}),
    }
)

#: Preservation decisions that let an action proceed; the other two are denials because
#: evidence precedes intervention (§2).
_EVIDENCE_OK: frozenset[PreservationDecision] = frozenset(
    {PreservationDecision.PRESERVED, PreservationDecision.EXCEPTION_GRANTED}
)

#: Duration-bounded invariant kinds, compared against the lease TTL for *every* operator
#: class rather than relying on another package's class thresholds for a bound held here.
_DURATION_KINDS: frozenset[InvariantKind] = frozenset(
    {InvariantKind.MAX_AUTONOMOUS_DOWNTIME, InvariantKind.MAX_CONTAINMENT_DURATION}
)

#: The class at which an operator can change host state, and so cannot touch a critical unit.
_INTERRUPTING_CLASS: OperatorClass = OperatorClass.O2_REVERSIBLE_RESTRICT

@dataclass(frozen=True, slots=True)
class SentinelVerdict:
    """The kernel's whole output. An inconsistent verdict cannot be constructed."""

    decision: Decision
    reasons: tuple[DenyReason, ...]
    detail: str
    operator_id: str
    target_digest: str
    evaluated_checks: tuple[str, ...]
    kernel_version: str = SENTINEL_KERNEL_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "decision", Decision(self.decision))
        object.__setattr__(self, "reasons", tuple(DenyReason(r) for r in self.reasons))
        object.__setattr__(self, "evaluated_checks", tuple(str(c) for c in self.evaluated_checks))
        if self.decision is Decision.DENY and not self.reasons:
            raise ContractError("DENY with no reasons is an outage, not a denial")
        if self.decision is Decision.PASS and self.reasons:
            raise ContractError(f"PASS carrying {[str(r) for r in self.reasons]} hides a denial")
        if self.decision is Decision.PASS and (
            self.evaluated_checks != CHECK_ORDER or not _order_is_whole()
        ):
            raise ContractError(
                f"PASS evaluated {list(self.evaluated_checks)}, not all {len(CHECK_ORDER)} "
                "checks; a PASS that did not run every check is not a PASS"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": str(self.decision), "reasons": [str(r) for r in self.reasons],
            "detail": self.detail, "operator_id": self.operator_id,
            "target_digest": self.target_digest,
            "evaluated_checks": list(self.evaluated_checks), "kernel_version": self.kernel_version,
        }


@dataclass(frozen=True, slots=True)
class _Request:
    """One verification's nine arguments as a single value, so every check is a pure function
    of the request plus the kernel's three constructor values and none can reach state
    another check wrote."""

    operator: DefensiveOperator
    token: CapabilityToken
    evidence: EvidencePreservationVerdict
    observed_identity: ProcessIdentity | None
    snapshot: HostSnapshot
    journal_bytes: int
    active_leases: int
    recent_action_times: Sequence[int]
    concurrent_operator_ids: frozenset[str]


class SentinelKernel:
    """§4's independent constraint kernel. Three inputs, thirteen checks, two answers."""

    __slots__ = ("_clock", "_constitution", "_invariants")

    def __init__(
        self, *, constitution: ResponseConstitution, invariants: MissionInvariantSet, clock: Clock
    ) -> None:
        if not isinstance(constitution, ResponseConstitution):
            raise ContractError("SentinelKernel.constitution must be a ResponseConstitution")
        if not isinstance(invariants, MissionInvariantSet):
            raise ContractError("SentinelKernel.invariants must be a MissionInvariantSet")
        if not callable(getattr(clock, "now", None)):
            raise ContractError("SentinelKernel.clock must provide now() -> int")
        self._constitution = constitution
        self._invariants = invariants
        self._clock = clock

    def verify(
        self,
        operator: DefensiveOperator | None,
        token: CapabilityToken | None,
        *,
        evidence: EvidencePreservationVerdict | None,
        observed_identity: ProcessIdentity | None,
        snapshot: HostSnapshot | None,
        journal_bytes: int | None,
        active_leases: int | None,
        recent_action_times: Sequence[int] | None,
        concurrent_operator_ids: frozenset[str] | None,
    ) -> SentinelVerdict:
        """PASS only when all thirteen checks pass; otherwise DENY with reasons.

        Every argument is annotated ``| None`` not because a caller should pass ``None`` but
        because the kernel must have a defined answer when one does, and that answer is a
        denial: an input it cannot read is an input it cannot clear.
        """
        # Read from locals() rather than a hand-kept name list: a tenth argument is then
        # covered the moment it is declared, instead of the day somebody remembers.
        supplied = {name: value for name, value in locals().items() if name != "self"}
        operator_id, target_digest = _labels(operator)
        absent = tuple(name for name, value in supplied.items() if value is None)
        if absent:
            # An unobservable target is also an identity that cannot be confirmed.
            reasons = (DenyReason.MISSING_INPUT,) + (
                (DenyReason.TARGET_IDENTITY,) if observed_identity is None else ()
            )
            detail = f"absent required inputs: {list(absent)}"
            return SentinelVerdict(Decision.DENY, reasons, detail, operator_id, target_digest, ())
        request = _Request(
            operator, token, evidence, observed_identity, snapshot,  # type: ignore[arg-type]
            int(journal_bytes), int(active_leases),  # type: ignore[arg-type]
            tuple(int(at) for at in recent_action_times),  # type: ignore[union-attr]
            frozenset(concurrent_operator_ids),  # type: ignore[arg-type]
        )
        return self._run(request, operator_id, target_digest)

    def _run(self, request: _Request, operator_id: str, target_digest: str) -> SentinelVerdict:
        reasons: list[DenyReason] = []
        evaluated: list[str] = []
        details: list[str] = []
        if not _order_is_whole():
            # A rebound or emptied CHECK_ORDER used to yield a zero-check PASS (F4).
            reasons.append(DenyReason.KERNEL_FAULT)
            details.append("CHECK_ORDER does not name every _check_ method exactly once")
        for name in CHECK_ORDER:
            check: Callable[[_Request], tuple[DenyReason, ...]]
            check = getattr(self, f"{_CHECK_PREFIX}{name}")
            evaluated.append(name)
            try:
                found = check(request)
            except BaseException as exc:
                reasons.append(DenyReason.KERNEL_FAULT)
                details.append(f"{name} raised {type(exc).__name__}: {exc}")
                break
            if found:
                reasons.extend(found)
                details.append(f"{name}: {[str(r) for r in found]}")
                if name == "schema":
                    break
        ordered = _dedupe(reasons)
        if ordered:
            return SentinelVerdict(
                Decision.DENY, ordered, "; ".join(details), operator_id, target_digest,
                tuple(evaluated),
            )
        detail = f"{len(CHECK_ORDER)} checks passed"
        return SentinelVerdict(
            Decision.PASS, (), detail, operator_id, target_digest, CHECK_ORDER
        )

    # --- the thirteen checks, each returning the reasons it found --------------------

    def _check_schema(self, request: _Request) -> tuple[DenyReason, ...]:
        """Shapes, types and catalog identity; nothing downstream may assume these."""
        operator, token = request.operator, request.token
        ok = (
            isinstance(operator, DefensiveOperator)
            and isinstance(token, CapabilityToken)
            and isinstance(request.evidence, EvidencePreservationVerdict)
            and isinstance(request.snapshot, HostSnapshot)
            # Identity, not equality: a structurally equal forged spec is refused.
            and CATALOG.get(operator.spec.operator_id) is operator.spec
            and token.operator_id == operator.spec.operator_id
            and token.incident_id == operator.incident_id
            and request.journal_bytes >= 0
            and request.active_leases >= 0
        )
        return () if ok else (DenyReason.SCHEMA,)

    def _check_signature_version(self, request: _Request) -> tuple[DenyReason, ...]:
        """Versions must agree; a token from another policy generation is not a token."""
        token = request.token
        ok = (
            token.schema_version == CAPABILITY_TOKEN_V2_VERSION
            and token.policy_version == self._constitution.policy_version
            and bool(token.mac and token.signer and token.nonce)
        )
        return () if ok else (DenyReason.SIGNATURE_VERSION,)

    def _check_constitution(self, request: _Request) -> tuple[DenyReason, ...]:
        """The ten laws over typed facts only; see the module docstring on HUMAN_REQUIRED."""
        spec, authority = request.operator.spec, request.token.authority
        if authority is AuthorityClass.AX:
            return (DenyReason.CONSTITUTION,)
        if spec.operator_class in self._constitution.prohibited_operator_classes:
            return (DenyReason.CONSTITUTION,)
        if not spec.postconditions:
            # UNVERIFIABLE_IS_NOT_COMPLETE: an action with nothing to probe can never be
            # called successfully completed, so it may not begin.
            return (DenyReason.CONSTITUTION,)
        verdict = self._constitution.permits(
            operator_class=spec.operator_class, authority=authority,
            reversibility=spec.reversibility,
            has_rollback=spec.rollback_operator_id is not None, autonomous=True,
        )
        refused = verdict.decision is ConstitutionDecision.REFUSED
        return (DenyReason.CONSTITUTION,) if refused else ()

    def _check_authority(self, request: _Request) -> tuple[DenyReason, ...]:
        """Exactly the class the catalog binds to this operator — no more, no less."""
        spec, token = request.operator.spec, request.token
        granted, needed = token.authority, required_authority(spec)
        bad = escalates(granted, needed) or granted is not needed or spec.authority is not needed
        # Held here as well as in mint(): a POLICY token for an operator a person must
        # authorise is refused whatever path produced it.
        policy_for_human = (
            autonomy_of(spec) in HUMAN_REQUIRED_AUTONOMY
            and token.granted_by is not GrantSource.HUMAN
        )
        return (DenyReason.AUTHORITY,) if bad or policy_for_human else ()

    def _check_scope(self, request: _Request) -> tuple[DenyReason, ...]:
        """The token binds one operator to one target, subject and ttl, and this is that one.

        ``binding_digest`` covers the scope subject; before schema v2 only the process
        identity was compared, so a token approved for one unit acted on another (F1).
        """
        operator, token = request.operator, request.token
        scope = operator.target.scope
        ok = (
            scope.kind is operator.spec.target_kind
            and scope.host_local
            and token.target_digest == operator.target.identity.digest()
            and token.binding_digest == operator.binding_digest()
            and operator.ttl_seconds <= token.max_duration_seconds
        )
        return () if ok else (DenyReason.SCOPE,)

    def _check_target_identity(self, request: _Request) -> tuple[DenyReason, ...]:
        """A pid is not an identity (§17); the digest is the whole comparison.

        ``identity_digest`` in ``executor/identity.py`` is ``digest_of_bytes`` over
        ``ProcessIdentity.canonical_bytes()``, which is what ``ProcessIdentity.digest()``
        computes, so the kernel reads the same key space the token and the journal are keyed
        on without importing the executor (§4.9 rule A).
        """
        observed = request.observed_identity
        if not isinstance(observed, ProcessIdentity):
            return (DenyReason.TARGET_IDENTITY,)
        matches = observed.digest() == request.operator.target.identity.digest()
        return () if matches else (DenyReason.TARGET_IDENTITY,)

    def _check_preconditions(self, request: _Request) -> tuple[DenyReason, ...]:
        """Declared preconditions, plus existence whether declared or not: no precondition
        can be evaluated about a target the snapshot cannot locate, and an unevaluable
        precondition is a denial."""
        if not _target_present(request.operator, request.snapshot):
            return (DenyReason.PRECONDITION,)
        holds = all(
            self._precondition_holds(kind, request)
            for kind in request.operator.spec.preconditions
        )
        return () if holds else (DenyReason.PRECONDITION,)

    def _precondition_holds(self, kind: PreconditionKind, request: _Request) -> bool:
        """A total ``match`` over :class:`PreconditionKind`; a new member is a type error."""
        operator, snapshot = request.operator, request.snapshot
        match kind:
            case PreconditionKind.TARGET_EXISTS:
                return _target_present(operator, snapshot)
            case PreconditionKind.TARGET_IDENTITY_MATCHES:
                return (
                    request.observed_identity is not None
                    and request.observed_identity.digest() == operator.target.identity.digest()
                )
            case PreconditionKind.TARGET_NOT_CRITICAL:
                return not (_units_touched(operator, snapshot) & self._invariants.critical_units())
            case PreconditionKind.ROLLBACK_STATE_CAPTURED:
                bundle = request.evidence.bundle
                return bundle is not None and bool(bundle.rollback_state)
            case PreconditionKind.EVIDENCE_PRESERVED:
                return request.evidence.decision in _EVIDENCE_OK
            case PreconditionKind.NO_ACTIVE_LEASE_ON_TARGET:
                # The kernel is handed a count, not a list, so it cannot prove a live lease
                # is on some other target. Any live lease therefore fails this closed.
                return request.active_leases == 0
            case PreconditionKind.SERVICE_HAS_RESTART_SEMANTICS:
                service = snapshot.service(operator.target.scope.subject)
                return service is not None and service.restartable

    def _check_mission_invariants(self, request: _Request) -> tuple[DenyReason, ...]:
        """Machine-checked mission invariants (G5.8), from three independent readings."""
        operator, evidence = request.operator, request.evidence
        # A bundle the evidence gate refused preserves nothing: retention stays fail-closed.
        ok = evidence.bundle is not None and evidence.decision in _EVIDENCE_OK
        preserved = frozenset(evidence.bundle.volatile_preserved) if ok else frozenset()
        if self._invariants.violations(
            operator=operator, lease_ttl_seconds=operator.ttl_seconds,
            snapshot=request.snapshot, preserved=preserved,
        ):
            return (DenyReason.MISSION_INVARIANT,)
        if operator.spec.operator_class >= _INTERRUPTING_CLASS and (
            _units_touched(operator, request.snapshot) & self._invariants.critical_units()
        ):
            # Critical-process baiting (§33): a protected unit dressed as the obvious target.
            return (DenyReason.MISSION_INVARIANT,)
        over_bound = any(
            invariant.kind in _DURATION_KINDS
            and invariant.bound_seconds is not None
            and operator.ttl_seconds > invariant.bound_seconds
            for invariant in self._invariants.invariants
        )
        return (DenyReason.MISSION_INVARIANT,) if over_bound else ()

    def _check_evidence_preservation(self, request: _Request) -> tuple[DenyReason, ...]:
        """Evidence precedes intervention; the gate's answer is the whole input."""
        verdict = request.evidence
        bad = verdict.decision not in _EVIDENCE_OK or (
            verdict.decision is PreservationDecision.EXCEPTION_GRANTED
            and verdict.exception_authority is not AuthorityClass.A5
        )
        return (DenyReason.EVIDENCE_PRESERVATION,) if bad else ()

    def _check_rollback_expiry(self, request: _Request) -> tuple[DenyReason, ...]:
        """Rollback awareness and time bounds — the two ways a lease becomes permanent."""
        found: list[DenyReason] = []
        operator, token = request.operator, request.token
        bundle = request.evidence.bundle
        if bundle is None:
            # No pre-action bundle means no rollback state was captured, whatever the
            # operator's reversibility label claims.
            found.append(DenyReason.ROLLBACK_MISSING)
        elif (
            operator.spec.reversibility is not Reversibility.IRREVERSIBLE
            and not bundle.rollback_state
        ) or (token.rollback_required and operator.spec.rollback_operator_id is None):
            found.append(DenyReason.ROLLBACK_MISSING)
        now = int(self._clock.now())
        if now < token.valid_from or now >= token.expiry or token.expiry - token.valid_from > MAX_TOKEN_LIFETIME_SECONDS or operator.ttl_seconds > operator.spec.max_duration_seconds:
            found.append(DenyReason.EXPIRY)
        return tuple(found)

    def _check_resource_limits(self, request: _Request) -> tuple[DenyReason, ...]:
        """The journal and the action-rate window, against the frozen budget."""
        if request.journal_bytes > STAGE5_BUDGET.max_rollback_journal_bytes:
            return (DenyReason.RESOURCE_LIMIT,)
        now = int(self._clock.now())
        recent = [
            at for at in request.recent_action_times if now - at < STAGE5_BUDGET.window_seconds
        ]
        over = len(recent) >= STAGE5_BUDGET.max_autonomous_actions_per_window
        return (DenyReason.RESOURCE_LIMIT,) if over else ()

    def _check_forbidden_combinations(self, request: _Request) -> tuple[DenyReason, ...]:
        """Combinations that compound, including an operator racing itself."""
        proposed = request.operator.spec.operator_id
        active = set(request.concurrent_operator_ids)
        if proposed in active:
            # The same operator already in flight on this incident is how oscillation and
            # self-denial-of-service start, so it is refused before it can repeat.
            return (DenyReason.FORBIDDEN_COMBINATION,)
        together = active | {proposed}
        clash = any(combination <= together for combination in FORBIDDEN_COMBINATIONS)
        return (DenyReason.FORBIDDEN_COMBINATION,) if clash else ()

    def _check_lease_capacity(self, request: _Request) -> tuple[DenyReason, ...]:
        """One free lease slot, or no action; bounded state is a hard constraint."""
        over = request.active_leases >= STAGE5_BUDGET.max_concurrent_leases
        return (DenyReason.RESOURCE_LIMIT,) if over else ()


def _order_is_whole() -> bool:
    """CHECK_ORDER names each check the class defines, once — read off the class (F4)."""
    defined = {name for name in vars(SentinelKernel) if name.startswith(_CHECK_PREFIX)}
    return sorted(f"{_CHECK_PREFIX}{name}" for name in CHECK_ORDER) == sorted(defined)


def _dedupe(reasons: Sequence[DenyReason]) -> tuple[DenyReason, ...]:
    """Reasons in first-seen order, once each; ``dict`` preserves insertion order."""
    return tuple(dict.fromkeys(reasons))


def _labels(operator: object) -> tuple[str, str]:
    """Operator id and target digest for a verdict, degrading to ``UNKNOWN`` rather than
    taking the kernel down: a verdict about an unreadable operator must still be reportable."""
    try:
        return (
            str(operator.spec.operator_id),  # type: ignore[union-attr]
            str(operator.target.identity.digest()),  # type: ignore[union-attr]
        )
    except BaseException:
        return "UNKNOWN", "UNKNOWN"


def _units_touched(operator: DefensiveOperator, snapshot: HostSnapshot) -> frozenset[str]:
    """Unit names this operator's target belongs to, as the snapshot reports them."""
    units: set[str] = set()
    if operator.target.scope.kind is TargetKind.SERVICE:
        units.add(operator.target.scope.subject)
    row = snapshot.process(operator.target.identity.pid)
    if row is not None and row.unit is not None:
        units.add(row.unit)
    return frozenset(units)


def _target_present(operator: DefensiveOperator, snapshot: HostSnapshot) -> bool:
    """Can the snapshot locate the thing this operator names, *on this process*?

    A scoped subject must exist and must belong to the target process: the session is the
    process's session, the unit is the process's unit, the socket is one of its sockets.
    Existence alone let a token for process P revoke any session on the host (F3).
    """
    row = snapshot.process(operator.target.identity.pid)
    if row is None:
        return operator.target.scope.kind is TargetKind.HOST
    subject = operator.target.scope.subject
    match operator.target.scope.kind:
        case TargetKind.PROCESS | TargetKind.HOST:
            return True
        case TargetKind.SERVICE:
            return snapshot.service(subject) is not None and row.binds(
                operator.target.scope.kind, subject
            )
        case TargetKind.SESSION:
            return subject in set(snapshot.sessions) and row.binds(
                operator.target.scope.kind, subject
            )
        case TargetKind.SOCKET:
            return row.binds(operator.target.scope.kind, subject)
