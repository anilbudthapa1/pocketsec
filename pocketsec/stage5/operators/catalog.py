"""D5.5 — the frozen catalog. The complete set of things Stage 5 can do to a host.

The catalog is the *whole* action vocabulary. There is no "other" operator, no escape
hatch and no generic executor, so the reachable consequence space of PocketSec's
privileged side is exactly the fourteen rows below plus nothing.

Three properties this module holds by construction:

* :data:`_CATALOG_TOKEN` is module-private and is the only object that satisfies
  ``OperatorSpec.__post_init__``. An ``OperatorSpec`` therefore exists only if this module
  built it, which is what makes ``DefensiveOperator``'s identity check meaningful.
* :data:`CATALOG` is a :class:`types.MappingProxyType`, so a caller cannot add an entry at
  runtime. Bounded at :data:`MAX_CATALOG_ENTRIES`.
* ``OperatorClass.O7_DESTRUCTIVE`` has **zero** entries. §5 calls O7 "not autonomous";
  here it is not *expressible*, which is a stronger and cheaper statement.

**Rollback closure**, checked at import time by :func:`rollback_closure_violations`: every
entry that changes host state and is not irreversible either names a rollback operator or
is itself named as one. That is the property the spec's per-spec rule was reaching for —
see ``OperatorSpec._validate_rollback`` for why it could not live on the spec alone.

**Stage 3's lesson, made mechanical.** Stage 3 shipped seven of eight operator forms with
no interpreter and therefore measured nothing (ADR-0027). Every row here has a handler in
``host/simulated.py``, and ``tests/test_stage5_operators.py`` asserts the two key sets are
equal in both directions. Do not add a row without its handler.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage5.constitution.invariants import AuthorityClass, ConstitutionDecision
from pocketsec.stage5.operators.algebra import (
    EvidenceEffect,
    FieldAtom,
    LiteralAtom,
    OperatorClass,
    OperatorSpec,
    PostconditionKind,
    PreconditionKind,
    Reversibility,
    TargetField,
    TargetKind,
)
from pocketsec.stage5.operators.d3fend_ids import UNMAPPED

if TYPE_CHECKING:  # pragma: no cover - annotations only
    from pocketsec.stage5.constitution.invariants import ResponseConstitution

__all__ = [
    "CATALOG",
    "CATALOG_BY_CLASS",
    "MAX_CATALOG_ENTRIES",
    "RESTORATION_OPERATOR_IDS",
    "autonomous_ids",
    "rollback_closure_violations",
    "rollback_spec",
    "spec",
]

#: Module-private. The only object that satisfies ``OperatorSpec.__post_init__``, which is
#: what makes an ``OperatorSpec`` unconstructable outside this module. It is a bare
#: ``object()`` rather than a string or a hash so that it cannot be *guessed*, only
#: imported — and the only importer is this module.
_CATALOG_TOKEN: object = object()

#: Bounded, like every other piece of endpoint state. Fourteen entries are in use; the
#: headroom exists so a new operator does not arrive together with a bound change.
MAX_CATALOG_ENTRIES: int = 32

#: Operators that change state and are reversible need a named rollback *unless* they are
#: themselves the rollback of another entry. Computed, not asserted by hand.
_STATE_CHANGING_FROM: OperatorClass = OperatorClass.O2_REVERSIBLE_RESTRICT


def _entry(
    *,
    operator_id: str,
    operator_class: OperatorClass,
    target_kind: TargetKind,
    argv_template: tuple[LiteralAtom | FieldAtom, ...],
    rollback_operator_id: str | None,
    reversibility: Reversibility,
    evidence_effect: EvidenceEffect,
    authority: AuthorityClass,
    preconditions: tuple[PreconditionKind, ...],
    postconditions: tuple[PostconditionKind, ...],
    max_duration_seconds: int,
) -> OperatorSpec:
    """Build one catalog entry. The single place the token is handed to a spec."""
    return OperatorSpec(
        operator_id=operator_id,
        operator_class=operator_class,
        target_kind=target_kind,
        argv_template=argv_template,
        rollback_operator_id=rollback_operator_id,
        reversibility=reversibility,
        evidence_effect=evidence_effect,
        authority=authority,
        preconditions=preconditions,
        postconditions=postconditions,
        max_duration_seconds=max_duration_seconds,
        # Every entry ships UNMAPPED. A D3FEND id is written only from a committed dated
        # snapshot; a wrong external identifier is worse than an absent one (ADR-0047).
        d3fend_technique_id=UNMAPPED,
        catalog_token=_CATALOG_TOKEN,
    )


_EXISTS_AND_MATCHES: tuple[PreconditionKind, ...] = (
    PreconditionKind.TARGET_EXISTS,
    PreconditionKind.TARGET_IDENTITY_MATCHES,
)
#: What a reversible intervention must have established before COMMIT (§16).
_INTERVENTION_PRECONDITIONS: tuple[PreconditionKind, ...] = (
    PreconditionKind.TARGET_EXISTS,
    PreconditionKind.TARGET_IDENTITY_MATCHES,
    PreconditionKind.TARGET_NOT_CRITICAL,
    PreconditionKind.ROLLBACK_STATE_CAPTURED,
    PreconditionKind.EVIDENCE_PRESERVED,
    PreconditionKind.NO_ACTIVE_LEASE_ON_TARGET,
)

_ENTRIES: tuple[OperatorSpec, ...] = (
    _entry(
        operator_id="OBSERVE_PROCESS_METADATA",
        operator_class=OperatorClass.O0_OBSERVE,
        target_kind=TargetKind.PROCESS,
        argv_template=(LiteralAtom("procfs.read"), FieldAtom(TargetField.PID)),
        rollback_operator_id=None,
        reversibility=Reversibility.FULLY_REVERSIBLE,
        evidence_effect=EvidenceEffect.PRESERVES,
        authority=AuthorityClass.A0,
        preconditions=_EXISTS_AND_MATCHES,
        postconditions=(PostconditionKind.OBSERVATION_RETAINED,),
        max_duration_seconds=30,
    ),
    _entry(
        operator_id="HASH_EXECUTABLE",
        operator_class=OperatorClass.O0_OBSERVE,
        target_kind=TargetKind.PROCESS,
        argv_template=(LiteralAtom("digest.executable"), FieldAtom(TargetField.PID)),
        rollback_operator_id=None,
        reversibility=Reversibility.FULLY_REVERSIBLE,
        evidence_effect=EvidenceEffect.PRESERVES,
        authority=AuthorityClass.A0,
        preconditions=_EXISTS_AND_MATCHES,
        postconditions=(PostconditionKind.EVIDENCE_PRESENT,),
        max_duration_seconds=60,
    ),
    _entry(
        operator_id="TRACE_PROCESS_BOUNDED",
        operator_class=OperatorClass.O0_OBSERVE,
        target_kind=TargetKind.PROCESS,
        argv_template=(LiteralAtom("trace.bounded"), FieldAtom(TargetField.PID)),
        rollback_operator_id="STOP_TRACE",
        reversibility=Reversibility.FULLY_REVERSIBLE,
        evidence_effect=EvidenceEffect.PRESERVES,
        authority=AuthorityClass.A0,
        preconditions=_EXISTS_AND_MATCHES,
        postconditions=(
            PostconditionKind.OBSERVATION_RETAINED,
            PostconditionKind.ROLLBACK_STILL_POSSIBLE,
        ),
        max_duration_seconds=300,
    ),
    _entry(
        operator_id="STOP_TRACE",
        operator_class=OperatorClass.O0_OBSERVE,
        target_kind=TargetKind.PROCESS,
        argv_template=(LiteralAtom("trace.stop"), FieldAtom(TargetField.PID)),
        rollback_operator_id=None,
        reversibility=Reversibility.FULLY_REVERSIBLE,
        evidence_effect=EvidenceEffect.NEUTRAL,
        authority=AuthorityClass.A0,
        preconditions=(PreconditionKind.TARGET_EXISTS,),
        postconditions=(PostconditionKind.OBSERVATION_RETAINED,),
        max_duration_seconds=30,
    ),
    _entry(
        operator_id="SNAPSHOT_PROCESS_STATE",
        operator_class=OperatorClass.O1_PRESERVE,
        target_kind=TargetKind.PROCESS,
        argv_template=(LiteralAtom("snapshot.process"), FieldAtom(TargetField.PID)),
        rollback_operator_id=None,
        reversibility=Reversibility.FULLY_REVERSIBLE,
        evidence_effect=EvidenceEffect.PRESERVES,
        authority=AuthorityClass.A1,
        preconditions=_EXISTS_AND_MATCHES,
        postconditions=(PostconditionKind.EVIDENCE_PRESENT,),
        max_duration_seconds=60,
    ),
    _entry(
        operator_id="PRESERVE_VOLATILE_EVIDENCE",
        operator_class=OperatorClass.O1_PRESERVE,
        target_kind=TargetKind.PROCESS,
        argv_template=(LiteralAtom("preserve.volatile"), FieldAtom(TargetField.PID)),
        rollback_operator_id=None,
        reversibility=Reversibility.FULLY_REVERSIBLE,
        evidence_effect=EvidenceEffect.PRESERVES,
        authority=AuthorityClass.A1,
        preconditions=_EXISTS_AND_MATCHES,
        postconditions=(
            PostconditionKind.EVIDENCE_PRESENT,
            PostconditionKind.OBSERVATION_RETAINED,
        ),
        max_duration_seconds=120,
    ),
    _entry(
        operator_id="RESTRICT_LOCAL_SOCKET",
        operator_class=OperatorClass.O2_REVERSIBLE_RESTRICT,
        target_kind=TargetKind.SOCKET,
        argv_template=(LiteralAtom("socket.restrict"), FieldAtom(TargetField.SOCKET_ID)),
        rollback_operator_id="RELEASE_LOCAL_SOCKET",
        reversibility=Reversibility.FULLY_REVERSIBLE,
        evidence_effect=EvidenceEffect.NEUTRAL,
        authority=AuthorityClass.A2,
        preconditions=_INTERVENTION_PRECONDITIONS,
        postconditions=(
            PostconditionKind.SOCKET_RESTRICTED,
            PostconditionKind.TRAJECTORY_REDUCED,
            PostconditionKind.SERVICE_HEALTH_ACCEPTABLE,
            PostconditionKind.ROLLBACK_STILL_POSSIBLE,
        ),
        max_duration_seconds=900,
    ),
    _entry(
        operator_id="RELEASE_LOCAL_SOCKET",
        operator_class=OperatorClass.O2_REVERSIBLE_RESTRICT,
        target_kind=TargetKind.SOCKET,
        argv_template=(LiteralAtom("socket.release"), FieldAtom(TargetField.SOCKET_ID)),
        rollback_operator_id=None,
        reversibility=Reversibility.FULLY_REVERSIBLE,
        evidence_effect=EvidenceEffect.NEUTRAL,
        authority=AuthorityClass.A2,
        preconditions=(PreconditionKind.TARGET_EXISTS,),
        postconditions=(
            PostconditionKind.SOCKET_RELEASED,
            PostconditionKind.SERVICE_HEALTH_ACCEPTABLE,
        ),
        max_duration_seconds=120,
    ),
    _entry(
        operator_id="SUSPEND_PROCESS",
        operator_class=OperatorClass.O3_SUSPEND,
        target_kind=TargetKind.PROCESS,
        argv_template=(LiteralAtom("process.suspend"), FieldAtom(TargetField.PID)),
        rollback_operator_id="RESUME_PROCESS",
        reversibility=Reversibility.FULLY_REVERSIBLE,
        evidence_effect=EvidenceEffect.DEGRADES_VOLATILE,
        authority=AuthorityClass.A2,
        preconditions=_INTERVENTION_PRECONDITIONS,
        postconditions=(
            PostconditionKind.PROCESS_SUSPENDED,
            PostconditionKind.TRAJECTORY_REDUCED,
            PostconditionKind.OBSERVATION_RETAINED,
            PostconditionKind.ROLLBACK_STILL_POSSIBLE,
        ),
        max_duration_seconds=900,
    ),
    _entry(
        operator_id="RESUME_PROCESS",
        operator_class=OperatorClass.O3_SUSPEND,
        target_kind=TargetKind.PROCESS,
        argv_template=(LiteralAtom("process.resume"), FieldAtom(TargetField.PID)),
        rollback_operator_id=None,
        reversibility=Reversibility.FULLY_REVERSIBLE,
        evidence_effect=EvidenceEffect.NEUTRAL,
        authority=AuthorityClass.A2,
        preconditions=_EXISTS_AND_MATCHES,
        postconditions=(
            PostconditionKind.PROCESS_RESUMED,
            PostconditionKind.SERVICE_HEALTH_ACCEPTABLE,
        ),
        max_duration_seconds=120,
    ),
    _entry(
        operator_id="REVOKE_LOCAL_SESSION",
        operator_class=OperatorClass.O4_LOCAL_REVOKE,
        target_kind=TargetKind.SESSION,
        argv_template=(LiteralAtom("session.revoke"), FieldAtom(TargetField.SESSION_ID)),
        # DEGRADED, and deliberately no rollback: a revoked session is not un-revoked,
        # the principal re-authenticates. §2 therefore sends it across a higher authority
        # boundary (A3) instead of letting a lease expire it away.
        rollback_operator_id=None,
        reversibility=Reversibility.DEGRADED,
        evidence_effect=EvidenceEffect.NEUTRAL,
        authority=AuthorityClass.A3,
        preconditions=(
            PreconditionKind.TARGET_EXISTS,
            PreconditionKind.TARGET_NOT_CRITICAL,
            PreconditionKind.EVIDENCE_PRESERVED,
        ),
        postconditions=(
            PostconditionKind.SESSION_REVOKED,
            PostconditionKind.TRAJECTORY_REDUCED,
        ),
        max_duration_seconds=300,
    ),
    _entry(
        operator_id="CONSTRAIN_SERVICE",
        operator_class=OperatorClass.O5_SERVICE_CONTAINMENT,
        target_kind=TargetKind.SERVICE,
        argv_template=(LiteralAtom("service.constrain"), FieldAtom(TargetField.UNIT_NAME)),
        rollback_operator_id="RELEASE_SERVICE",
        reversibility=Reversibility.REVERSIBLE_WITH_STATE,
        evidence_effect=EvidenceEffect.NEUTRAL,
        authority=AuthorityClass.A4,
        preconditions=(
            PreconditionKind.TARGET_EXISTS,
            PreconditionKind.TARGET_NOT_CRITICAL,
            PreconditionKind.ROLLBACK_STATE_CAPTURED,
            PreconditionKind.EVIDENCE_PRESERVED,
            PreconditionKind.NO_ACTIVE_LEASE_ON_TARGET,
            PreconditionKind.SERVICE_HAS_RESTART_SEMANTICS,
        ),
        postconditions=(
            PostconditionKind.SERVICE_CONSTRAINED,
            PostconditionKind.TRAJECTORY_REDUCED,
            PostconditionKind.SERVICE_HEALTH_ACCEPTABLE,
            PostconditionKind.ROLLBACK_STILL_POSSIBLE,
        ),
        max_duration_seconds=900,
    ),
    _entry(
        operator_id="RELEASE_SERVICE",
        operator_class=OperatorClass.O5_SERVICE_CONTAINMENT,
        target_kind=TargetKind.SERVICE,
        argv_template=(LiteralAtom("service.release"), FieldAtom(TargetField.UNIT_NAME)),
        rollback_operator_id=None,
        reversibility=Reversibility.FULLY_REVERSIBLE,
        evidence_effect=EvidenceEffect.NEUTRAL,
        authority=AuthorityClass.A4,
        preconditions=(
            PreconditionKind.TARGET_EXISTS,
            PreconditionKind.SERVICE_HAS_RESTART_SEMANTICS,
        ),
        postconditions=(
            PostconditionKind.SERVICE_RELEASED,
            PostconditionKind.SERVICE_HEALTH_ACCEPTABLE,
        ),
        max_duration_seconds=300,
    ),
    _entry(
        operator_id="TERMINATE_PROCESS",
        operator_class=OperatorClass.O6_DISRUPTIVE,
        target_kind=TargetKind.PROCESS,
        argv_template=(LiteralAtom("process.terminate"), FieldAtom(TargetField.PID)),
        rollback_operator_id=None,
        reversibility=Reversibility.IRREVERSIBLE,
        evidence_effect=EvidenceEffect.DEGRADES_VOLATILE,
        authority=AuthorityClass.A5,
        preconditions=_INTERVENTION_PRECONDITIONS,
        postconditions=(
            PostconditionKind.TRAJECTORY_REDUCED,
            PostconditionKind.EVIDENCE_PRESENT,
            PostconditionKind.SERVICE_HEALTH_ACCEPTABLE,
        ),
        max_duration_seconds=60,
    ),
)


def _build_catalog(entries: tuple[OperatorSpec, ...]) -> Mapping[str, OperatorSpec]:
    if len(entries) > MAX_CATALOG_ENTRIES:
        raise ContractError(
            f"catalog holds {len(entries)} entries, bound is {MAX_CATALOG_ENTRIES}"
        )
    table: dict[str, OperatorSpec] = {}
    for entry in entries:
        if entry.operator_id in table:
            raise ContractError(f"duplicate catalog entry {entry.operator_id!r}")
        table[entry.operator_id] = entry
    return MappingProxyType(table)


#: The complete action vocabulary. Read-only at runtime.
CATALOG: Mapping[str, OperatorSpec] = _build_catalog(_ENTRIES)

#: Operator ids per class. ``O7_DESTRUCTIVE`` maps to ``()`` — present in the ordering,
#: absent from the vocabulary.
CATALOG_BY_CLASS: Mapping[OperatorClass, tuple[str, ...]] = MappingProxyType(
    {
        operator_class: tuple(
            entry.operator_id
            for entry in _ENTRIES
            if entry.operator_class is operator_class
        )
        for operator_class in OperatorClass
    }
)


#: The entries that are some other entry's rollback: ``RESUME_PROCESS``,
#: ``RELEASE_LOCAL_SOCKET``, ``STOP_TRACE``, ``RELEASE_SERVICE``. **The one derivation.**
#: Four modules (the lease registry, the postcondition probe, the simulated host and the
#: baselines) used to derive this set independently from the same expression; four
#: copies of a key space is how two of them drift apart (§4.9 Rule A), so they now all
#: import this one. Derived, never listed, so a catalog edit cannot leave it stale.
RESTORATION_OPERATOR_IDS: frozenset[str] = frozenset(
    entry.rollback_operator_id
    for entry in CATALOG.values()
    if entry.rollback_operator_id is not None
)


def rollback_closure_violations(entries: Mapping[str, OperatorSpec]) -> tuple[str, ...]:
    """Every way a catalog's rollback story can be incoherent. ``()`` is the property.

    Three arms, and each has cost this project or its predecessors a real defect:

    1. a ``rollback_operator_id`` that is not itself an entry — a dangling rollback is a
       lease that can never be released (Stage 3 shipped seven operator forms with no
       interpreter for exactly this class of reason);
    2. a state-changing reversible operator (``>= O2``) that neither names a rollback nor
       is named as one — an intervention with no way back;
    3. a rollback whose target kind differs from the operator it undoes, which would make
       ``DefensiveOperator.rollback()`` unconstructable at the moment it is needed.
    """
    named_as_rollback = {
        entry.rollback_operator_id
        for entry in entries.values()
        if entry.rollback_operator_id is not None
    }
    violations: list[str] = []
    for operator_id, entry in sorted(entries.items()):
        rollback = entry.rollback_operator_id
        if rollback is not None:
            if rollback not in entries:
                violations.append(f"{operator_id}: rollback {rollback!r} is not in the catalog")
                continue
            if entries[rollback].target_kind is not entry.target_kind:
                violations.append(
                    f"{operator_id}: rollback {rollback!r} targets "
                    f"{entries[rollback].target_kind}, not {entry.target_kind}"
                )
            continue
        if entry.reversibility in (
            Reversibility.FULLY_REVERSIBLE,
            Reversibility.REVERSIBLE_WITH_STATE,
        ) and entry.operator_class >= _STATE_CHANGING_FROM and operator_id not in named_as_rollback:
            violations.append(
                f"{operator_id}: a reversible {entry.operator_class.name} operator must "
                "name a rollback or be named as one"
            )
    return tuple(violations)


# Import-time, so a new entry with an incoherent rollback story is an ImportError rather
# than a runtime surprise during an incident.
_CLOSURE = rollback_closure_violations(CATALOG)
if _CLOSURE:  # pragma: no cover - an ImportError is the point
    raise ContractError(f"catalog rollback closure violated: {_CLOSURE}")


def spec(operator_id: str) -> OperatorSpec:
    """The catalog entry for ``operator_id``.

    A ``KeyError`` becomes a :class:`ContractError` because an unknown operator id is a
    contract failure, not a missing dictionary key — and because callers upstream of
    privilege must not have to distinguish the two.
    """
    try:
        return CATALOG[operator_id]
    except KeyError as exc:
        raise ContractError(f"unknown operator id {operator_id!r}") from exc


def rollback_spec(operator_id: str) -> OperatorSpec | None:
    """The entry that undoes ``operator_id``, or ``None`` when there is not one."""
    entry = spec(operator_id)
    if entry.rollback_operator_id is None:
        return None
    return CATALOG[entry.rollback_operator_id]


def _rollback_is_bound(operator_id: str, entry: OperatorSpec) -> bool:
    """Whether a rollback exists for ``entry``, for the constitution's ``has_rollback``.

    Three ways an operator is covered, and the second and third are why this is a function
    rather than ``rollback_operator_id is not None``:

    1. it names a rollback operator;
    2. it is below ``O2`` and therefore changes no host state — "what undoes it" has no
       referent, and reading ``has_rollback=False`` for an observe operator would make
       §5's own autonomy column ("O0 Observe: policy eligible") unreachable;
    3. it *is* another entry's rollback. ``RESUME_PROCESS`` restores rather than changes,
       and if it needed a rollback of its own no expiring lease could ever be swept
       without a human, which would defeat §18's whole purpose.
    """
    if entry.rollback_operator_id is not None:
        return True
    if entry.operator_class < _STATE_CHANGING_FROM:
        return True
    return operator_id in {
        other.rollback_operator_id
        for other in CATALOG.values()
        if other.rollback_operator_id is not None
    }


def autonomous_ids(constitution: ResponseConstitution) -> tuple[str, ...]:
    """The operators the constitution permits PocketSec to run without a human.

    The constitution decides; this function only asks. There is no local threshold, no
    configuration and no confidence term, because authority is not a function of belief
    (ADR-0003).
    """
    permitted: list[str] = []
    for operator_id, entry in CATALOG.items():
        verdict = constitution.permits(
            operator_class=entry.operator_class,
            authority=entry.authority,
            reversibility=entry.reversibility,
            has_rollback=_rollback_is_bound(operator_id, entry),
            autonomous=True,
        )
        if verdict.decision is ConstitutionDecision.PERMITTED:
            permitted.append(operator_id)
    return tuple(permitted)
