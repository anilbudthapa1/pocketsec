"""D5.5 — the typed Defensive Operator Algebra. This module IS the security boundary.

Architecture §6 states the rule this module exists to make structural:

    forbidden ActionObject:  {"command": "some shell string"}
    allowed:                 {operator: SUSPEND_PROCESS, target_pid: ..., ttl: ...}

Every other Stage of PocketSec produces beliefs. Stage 5 acts, and the only thing it is
allowed to act with is a :class:`DefensiveOperator`. So the job here is not to describe
actions well; it is to make the *wrong* action unconstructable:

* An :class:`OperatorSpec` cannot be built outside ``operators/catalog.py``, because
  ``__post_init__`` refuses any instance whose ``catalog_token`` is not that module's
  private sentinel object. No catalog entry's shape can come from a config file, a
  payload, a model output or a text field.
* A :class:`DefensiveOperator` refuses a ``spec`` that is not a ``CATALOG`` member **by
  identity** (``is``), not by equality. A structurally-identical forged spec — the exact
  attack that equality would wave through — is refused.
* An argument vector is produced in exactly one place, :func:`assemble_argv`, from a
  closed union of two atoms: a frozen literal matching :data:`LITERAL_ATOM_PATTERN` (no
  spaces, no shell metacharacters) and a selector over the closed :class:`TargetField`
  enum. There is no format string, no ``join`` into a single string, and no
  caller-supplied string reaches a vector.
* :func:`no_arbitrary_command_path` is the AST proof of the negative, and the gate and the
  boundary test call this one implementation rather than each writing their own — a
  boundary checked twice by two walkers has two different holes (S2-AUTH-01).

**What the catalog token does not claim.** It makes an ``OperatorSpec`` unreachable from
*data* — from anything that arrived as bytes, prose or configuration. It does not defend
against arbitrary in-process Python, which can import a private name; code that can do
that already owns the interpreter. The threat model is prompt/log injection and command
generation (architecture §33), and that is what the token closes.

**A pid is not an identity** (§17). :class:`ProcessIdentity` carries start time, uid and,
where a real host can supply them, an executable digest, cgroup and namespace, and
:meth:`ProcessIdentity.digest` is the single key space every Stage 5 subsystem keys a
target by.

**One deliberate deviation from ``docs/stage-5-spec.md``, recorded rather than
discovered.** The spec lists :class:`PostconditionKind` under ``executor/verify.py``,
which belongs to work package 5; but ``OperatorSpec.postconditions`` needs its members at
*catalog construction* time, and the spec's own build order (§5: "packages 5–8 do not
start until package 2's tests pass") makes package 2 strictly upstream of package 5. A
runtime import from ``executor/verify`` into ``operators/catalog`` would be a package
cycle and would leave this package un-testable until a downstream one lands. The enum is
therefore defined here, upstream, and ``executor/verify.py`` must re-export it rather than
define a second copy — two structurally-equal enums that compare unequal is the exact
defect class this repository has already shipped twice (S2-FC-01).
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import TYPE_CHECKING, Any, assert_never

from pocketsec.stage0.contracts.common import (
    ContractError,
    EvidenceRef,
    digest_of_bytes,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage5.operators.d3fend_ids import D3FEND_ID_PATTERN, UNMAPPED

if TYPE_CHECKING:  # pragma: no cover - annotations only, never imported at runtime
    from pocketsec.stage5.constitution.invariants import AuthorityClass

__all__ = [
    "ARGV_NAME_TOKENS",
    "FIELD_TARGET_KINDS",
    "FORBIDDEN_CALL_NAMES",
    "FORBIDDEN_IMPORT_ROOTS",
    "FORBIDDEN_OS_ATTRIBUTES",
    "LITERAL_ATOM_PATTERN",
    "MAX_ARGV_ATOMS",
    "MAX_EVIDENCE_REFS_PER_OPERATOR",
    "MAX_OPERATOR_DURATION_SECONDS",
    "MAX_PRECONDITIONS",
    "ArgvAtom",
    "DefensiveOperator",
    "EvidenceEffect",
    "FieldAtom",
    "LiteralAtom",
    "OperatorClass",
    "OperatorSpec",
    "PostconditionKind",
    "PreconditionKind",
    "ProcessIdentity",
    "ProcessTarget",
    "Reversibility",
    "TargetField",
    "TargetKind",
    "TargetScope",
    "assemble_argv",
    "no_arbitrary_command_path",
]


class OperatorClass(IntEnum):
    """§5. An ``IntEnum`` because O-classes are ordered by consequence and compared.

    ``O7_DESTRUCTIVE`` exists in the ordering so that "not autonomous" can be stated, and
    has zero catalog entries so that it is not *expressible* (assurance property P5).
    """

    O0_OBSERVE = 0
    O1_PRESERVE = 1
    O2_REVERSIBLE_RESTRICT = 2
    O3_SUSPEND = 3
    O4_LOCAL_REVOKE = 4
    O5_SERVICE_CONTAINMENT = 5
    O6_DISRUPTIVE = 6
    O7_DESTRUCTIVE = 7


class Reversibility(StrEnum):
    FULLY_REVERSIBLE = "FULLY_REVERSIBLE"
    REVERSIBLE_WITH_STATE = "REVERSIBLE_WITH_STATE"
    DEGRADED = "DEGRADED"
    IRREVERSIBLE = "IRREVERSIBLE"


class EvidenceEffect(StrEnum):
    """What an operator does to the evidence that justified it (§13).

    ``DESTROYS`` is reserved for O6 and above: containment that erases the record of the
    incident is a failure even when it stops the attack.
    """

    PRESERVES = "PRESERVES"
    NEUTRAL = "NEUTRAL"
    DEGRADES_VOLATILE = "DEGRADES_VOLATILE"
    DESTROYS = "DESTROYS"


class TargetKind(StrEnum):
    PROCESS = "PROCESS"
    SERVICE = "SERVICE"
    SESSION = "SESSION"
    SOCKET = "SOCKET"
    HOST = "HOST"


class TargetField(StrEnum):
    """The closed set of values that may be substituted into an argument vector.

    Every member resolves to an int rendered by :func:`str`, or to an identifier that is
    re-validated against :data:`LITERAL_ATOM_PATTERN` at substitution time. None of them
    can resolve to free text, which is the whole point.
    """

    PID = "PID"
    UID = "UID"
    UNIT_NAME = "UNIT_NAME"
    SOCKET_ID = "SOCKET_ID"
    SESSION_ID = "SESSION_ID"


class PreconditionKind(StrEnum):
    """What the transactional executor must establish before COMMIT (§16)."""

    TARGET_EXISTS = "TARGET_EXISTS"
    TARGET_IDENTITY_MATCHES = "TARGET_IDENTITY_MATCHES"
    TARGET_NOT_CRITICAL = "TARGET_NOT_CRITICAL"
    ROLLBACK_STATE_CAPTURED = "ROLLBACK_STATE_CAPTURED"
    EVIDENCE_PRESERVED = "EVIDENCE_PRESERVED"
    NO_ACTIVE_LEASE_ON_TARGET = "NO_ACTIVE_LEASE_ON_TARGET"
    SERVICE_HAS_RESTART_SEMANTICS = "SERVICE_HAS_RESTART_SEMANTICS"


class PostconditionKind(StrEnum):
    """§20. Command success is not security success.

    The last five members are about the incident and the host, not about the call
    returning, which is why an operator can be applied and still be ``INEFFECTIVE``.

    Defined here rather than in ``executor/verify.py`` — see the module docstring's
    recorded deviation. ``executor/verify.py`` re-exports this enum; it must not define a
    second one.
    """

    PROCESS_SUSPENDED = "PROCESS_SUSPENDED"
    PROCESS_RESUMED = "PROCESS_RESUMED"
    SOCKET_RESTRICTED = "SOCKET_RESTRICTED"
    SOCKET_RELEASED = "SOCKET_RELEASED"
    SERVICE_CONSTRAINED = "SERVICE_CONSTRAINED"
    SERVICE_RELEASED = "SERVICE_RELEASED"
    SESSION_REVOKED = "SESSION_REVOKED"
    EVIDENCE_PRESENT = "EVIDENCE_PRESENT"
    TRAJECTORY_REDUCED = "TRAJECTORY_REDUCED"
    SERVICE_HEALTH_ACCEPTABLE = "SERVICE_HEALTH_ACCEPTABLE"
    OBSERVATION_RETAINED = "OBSERVATION_RETAINED"
    ATTACKER_PATH_UNCHANGED = "ATTACKER_PATH_UNCHANGED"
    ROLLBACK_STILL_POSSIBLE = "ROLLBACK_STILL_POSSIBLE"


#: An argv token. No spaces and no shell metacharacter can match, so even a caller who
#: reached the constructor with attacker-controlled bytes cannot smuggle a second command:
#: there is no shell in the first place, and there is no separator in the second.
LITERAL_ATOM_PATTERN = re.compile(r"^[A-Za-z0-9._/-]{1,64}$")

#: Bounded because an argument vector is endpoint state that crosses a privilege boundary.
MAX_ARGV_ATOMS: int = 8
#: §5's catalog holds nothing longer-lived than a 15-minute containment.
MAX_OPERATOR_DURATION_SECONDS: int = 900
MAX_PRECONDITIONS: int = 8
MAX_POSTCONDITIONS: int = 8
MAX_EVIDENCE_REFS_PER_OPERATOR: int = 32

#: Which target kinds a field may be read from. Enforced at substitution time so a
#: template can never read a unit name off a process-scoped target.
FIELD_TARGET_KINDS: Mapping[TargetField, frozenset[TargetKind]] = {
    TargetField.PID: frozenset({TargetKind.PROCESS}),
    TargetField.UID: frozenset({TargetKind.PROCESS, TargetKind.SESSION}),
    TargetField.UNIT_NAME: frozenset({TargetKind.SERVICE}),
    TargetField.SOCKET_ID: frozenset({TargetKind.SOCKET}),
    TargetField.SESSION_ID: frozenset({TargetKind.SESSION}),
}

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _require_argv_token(value: object, field: str) -> str:
    """The one validator every argv token passes, literal or substituted."""
    if not isinstance(value, str) or not LITERAL_ATOM_PATTERN.fullmatch(value):
        raise ContractError(
            f"{field} must match {LITERAL_ATOM_PATTERN.pattern} "
            f"(no spaces, no shell metacharacters), got {value!r}"
        )
    return value


@dataclass(frozen=True, slots=True)
class LiteralAtom:
    """A frozen argv token decided by the catalog, never by a caller."""

    value: str

    def __post_init__(self) -> None:
        _require_argv_token(self.value, "LiteralAtom.value")


@dataclass(frozen=True, slots=True)
class FieldAtom:
    """A selector over the closed :class:`TargetField` enum."""

    field: TargetField

    def __post_init__(self) -> None:
        if not isinstance(self.field, TargetField):
            raise ContractError(f"FieldAtom.field must be a TargetField, got {self.field!r}")


#: The closed union. Adding a ``str`` member here makes :func:`assemble_argv`'s ``match``
#: non-exhaustive, which ``mypy --strict`` rejects at the ``assert_never`` call — that is
#: the construction behind assurance property P3.
ArgvAtom = LiteralAtom | FieldAtom


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    """§17. A pid is not an identity.

    ``executable_digest``, ``cgroup_id`` and ``namespace_id`` are ``None``-able because on a
    real host they are sometimes genuinely unavailable. ``None`` is a real answer, not a
    reason to fall back to the pid: revalidation reads it as ``UNOBSERVABLE``, never a match.
    """

    pid: int
    start_time_ticks: int
    uid: int
    executable_digest: str | None
    cgroup_id: str | None
    namespace_id: str | None

    def __post_init__(self) -> None:
        require_non_negative_int(self.pid, "ProcessIdentity.pid")
        require_non_negative_int(self.start_time_ticks, "ProcessIdentity.start_time_ticks")
        require_non_negative_int(self.uid, "ProcessIdentity.uid")
        digest = self.executable_digest
        if digest is not None and not _SHA256_RE.fullmatch(digest):
            raise ContractError(f"executable_digest must be sha256:<64 hex> or None: {digest!r}")
        for field, value in (("cgroup_id", self.cgroup_id), ("namespace_id", self.namespace_id)):
            if value is not None:
                require_identifier(value, f"ProcessIdentity.{field}")

    def canonical_bytes(self) -> bytes:
        """Sorted-key JSON. No float, so the bytes are identical on every host."""
        return json.dumps(
            {
                "cgroup_id": self.cgroup_id,
                "executable_digest": self.executable_digest,
                "namespace_id": self.namespace_id,
                "pid": self.pid,
                "start_time_ticks": self.start_time_ticks,
                "uid": self.uid,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")

    def digest(self) -> str:
        """THE target key space. Everything that keys a target calls this."""
        return digest_of_bytes(self.canonical_bytes())


@dataclass(frozen=True, slots=True)
class TargetScope:
    """What the action is allowed to touch, and nothing wider (§2's scope law)."""

    kind: TargetKind
    subject: str
    host_local: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.kind, TargetKind):
            raise ContractError(f"TargetScope.kind must be a TargetKind, got {self.kind!r}")
        # The subject can reach an argument vector (UNIT_NAME / SOCKET_ID / SESSION_ID), so
        # it is checked here *and* at substitution time. Validating once would make the
        # second reader trust the first.
        _require_argv_token(self.subject, "TargetScope.subject")
        if not isinstance(self.host_local, bool):
            raise ContractError(f"host_local must be a bool, got {self.host_local!r}")


@dataclass(frozen=True, slots=True)
class ProcessTarget:
    """An identity plus the scope the operator may act within."""

    identity: ProcessIdentity
    scope: TargetScope

    def __post_init__(self) -> None:
        if not isinstance(self.identity, ProcessIdentity):
            raise ContractError(f"identity must be a ProcessIdentity: {type(self.identity)!r}")
        if not isinstance(self.scope, TargetScope):
            raise ContractError(f"scope must be a TargetScope: {type(self.scope)!r}")


@dataclass(frozen=True, slots=True)
class OperatorSpec:
    """A frozen catalog entry. Constructible ONLY inside ``operators/catalog.py``.

    ``catalog_token`` defaults to ``None`` so the *default* construction — the one a
    deserialiser, a config loader or a generated payload performs — fails. A caller must
    hold ``operators.catalog._CATALOG_TOKEN``, and only the catalog does.
    """

    operator_id: str
    operator_class: OperatorClass
    target_kind: TargetKind
    argv_template: tuple[ArgvAtom, ...]
    rollback_operator_id: str | None
    reversibility: Reversibility
    evidence_effect: EvidenceEffect
    authority: AuthorityClass
    preconditions: tuple[PreconditionKind, ...]
    postconditions: tuple[PostconditionKind, ...]
    max_duration_seconds: int
    d3fend_technique_id: str
    catalog_token: object = None

    def __post_init__(self) -> None:
        # The token check runs FIRST. Nothing below it is a defence if a spec can be
        # built at all, so nothing below it should be reachable from outside the catalog.
        from pocketsec.stage5.operators.catalog import _CATALOG_TOKEN

        if self.catalog_token is not _CATALOG_TOKEN:
            raise ContractError(
                f"OperatorSpec {self.operator_id!r} is constructible only inside "
                "pocketsec.stage5.operators.catalog"
            )
        require_identifier(self.operator_id, "OperatorSpec.operator_id")
        for name, kind in (
            ("operator_class", OperatorClass),
            ("target_kind", TargetKind),
            ("reversibility", Reversibility),
            ("evidence_effect", EvidenceEffect),
        ):
            if not isinstance(getattr(self, name), kind):
                raise ContractError(f"{self.operator_id}: {name} must be a {kind.__name__}")
        self._validate_argv_template()
        self._validate_rollback()
        self._validate_evidence_effect()
        self._validate_authority()
        self._validate_conditions()
        self._validate_duration_and_vocabulary()

    # --- the five refusals, one method each so each can be read on its own -------

    def _validate_argv_template(self) -> None:
        template = self.argv_template
        if not isinstance(template, tuple) or not template:
            raise ContractError(f"{self.operator_id}: argv_template must be a non-empty tuple")
        if len(template) > MAX_ARGV_ATOMS:
            raise ContractError(f"{self.operator_id}: argv_template exceeds {MAX_ARGV_ATOMS}")
        if not isinstance(template[0], LiteralAtom):
            # The mechanism selector is never a substituted value.
            raise ContractError(f"{self.operator_id}: argv_template[0] must be a LiteralAtom")
        for index, atom in enumerate(template):
            # LiteralAtom.__post_init__ has already applied the pattern; re-applying it
            # here is what makes rule 5 hold for a spec built from atoms that were
            # constructed before the pattern was tightened.
            if isinstance(atom, LiteralAtom):
                _require_argv_token(atom.value, f"{self.operator_id}.argv_template[{index}]")
            elif isinstance(atom, FieldAtom):
                if self.target_kind not in FIELD_TARGET_KINDS[atom.field]:
                    raise ContractError(
                        f"{self.operator_id}: {atom.field} is not readable from a "
                        f"{self.target_kind} target"
                    )
            else:
                raise ContractError(
                    f"{self.operator_id}: argv_template[{index}] is {type(atom)!r}, "
                    "and ArgvAtom is closed over LiteralAtom | FieldAtom"
                )

    def _validate_rollback(self) -> None:
        """Rollback coherence that holds for *every* entry in the table.

        The spec's literal rule — "raises when reversibility is not IRREVERSIBLE and
        rollback_operator_id is None" — contradicts nine of its own fourteen catalog rows:
        ``STOP_TRACE``, ``RESUME_PROCESS``, ``RELEASE_SERVICE`` and the observe/preserve
        operators are all reversible and name no rollback, because they *are* the
        restoration. Enforcing it as written makes the catalog unconstructable; dropping it
        loses the property. So this keeps the two halves true of every row, and
        ``catalog.rollback_closure_violations`` carries the rest: every state-changing
        reversible operator either names a rollback or is itself named as one.
        """
        rollback = self.rollback_operator_id
        if rollback is not None:
            require_identifier(rollback, f"{self.operator_id}.rollback_operator_id")
            if self.reversibility is Reversibility.IRREVERSIBLE:
                # A promise it cannot keep.
                raise ContractError(f"{self.operator_id}: IRREVERSIBLE names {rollback!r}")
            if rollback == self.operator_id:
                raise ContractError(f"{self.operator_id}: an operator cannot roll back itself")
        elif self.reversibility is Reversibility.REVERSIBLE_WITH_STATE:
            # Captured state that nothing consumes.
            raise ContractError(f"{self.operator_id}: REVERSIBLE_WITH_STATE has no rollback")

    def _validate_evidence_effect(self) -> None:
        if (
            self.evidence_effect is EvidenceEffect.DESTROYS
            and self.operator_class < OperatorClass.O6_DISRUPTIVE
        ):
            raise ContractError(
                f"{self.operator_id}: evidence_effect DESTROYS is not available below "
                f"O6 (this operator is {self.operator_class.name})"
            )

    def _validate_authority(self) -> None:
        # Imported here, not at module scope: authority/capability.py imports this module
        # for OperatorClass, so a module-level import would be a cycle. A spec is only
        # ever built from catalog.py, which has already imported the authority plane.
        from pocketsec.stage5.authority.capability import AUTHORITY_BY_OPERATOR_CLASS

        expected = AUTHORITY_BY_OPERATOR_CLASS[self.operator_class]
        if self.authority is not expected:
            raise ContractError(
                f"{self.operator_id}: authority {self.authority!r} disagrees with "
                f"AUTHORITY_BY_OPERATOR_CLASS[{self.operator_class.name}] = {expected!r}; "
                "authority is a property of the operator class, not of the entry"
            )

    def _validate_conditions(self) -> None:
        """Both condition tuples, checked by the same code so neither can drift."""
        checks = (
            ("preconditions", self.preconditions, PreconditionKind, MAX_PRECONDITIONS),
            ("postconditions", self.postconditions, PostconditionKind, MAX_POSTCONDITIONS),
        )
        for name, values, kind, bound in checks:
            if not isinstance(values, tuple) or not values:
                raise ContractError(f"{self.operator_id}: {name} must be a non-empty tuple")
            if len(values) > bound:
                raise ContractError(f"{self.operator_id}: {name} exceeds the bound {bound}")
            if len(set(values)) != len(values):
                raise ContractError(f"{self.operator_id}: duplicate entry in {name}")
            for item in values:
                if not isinstance(item, kind):
                    raise ContractError(
                        f"{self.operator_id}: {item!r} in {name} is not a {kind.__name__}"
                    )

    def _validate_duration_and_vocabulary(self) -> None:
        require_non_negative_int(self.max_duration_seconds, f"{self.operator_id}.max_duration")
        if not 0 < self.max_duration_seconds <= MAX_OPERATOR_DURATION_SECONDS:
            raise ContractError(
                f"{self.operator_id}: max_duration_seconds must be in "
                f"(0, {MAX_OPERATOR_DURATION_SECONDS}], got {self.max_duration_seconds}"
            )
        # The two names come from ``d3fend_ids``, which imports only ``re``. Reading them
        # from ``d3fend.py`` loaded ``stage0.gate`` into every privileged process
        # (S5-SEC-11); the adapter itself stays out of this module's import graph (§28).
        if self.d3fend_technique_id != UNMAPPED and not D3FEND_ID_PATTERN.fullmatch(
            self.d3fend_technique_id
        ):
            raise ContractError(
                f"{self.operator_id}: d3fend_technique_id must be {UNMAPPED!r} or match "
                f"{D3FEND_ID_PATTERN.pattern}, got {self.d3fend_technique_id!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "operator_id": self.operator_id,
            "operator_class": self.operator_class.name,
            "target_kind": str(self.target_kind),
            "argv_template": [
                {"literal": atom.value}
                if isinstance(atom, LiteralAtom)
                else {"field": str(atom.field)}
                for atom in self.argv_template
            ],
            "rollback_operator_id": self.rollback_operator_id,
            "reversibility": str(self.reversibility),
            "evidence_effect": str(self.evidence_effect),
            "authority": str(self.authority),
            "preconditions": [str(item) for item in self.preconditions],
            "postconditions": [str(item) for item in self.postconditions],
            "max_duration_seconds": self.max_duration_seconds,
            "d3fend_technique_id": self.d3fend_technique_id,
        }


@dataclass(frozen=True, slots=True)
class DefensiveOperator:
    """**The only type the executor accepts.** §45: "Only typed operators reach privilege."

    There is no constructor path from a string, a model output, a text field, an LLM, a
    config value or a deserialised payload to an instance of this class, because ``spec``
    must be a ``CATALOG`` member *by identity* and a ``CATALOG`` entry cannot be built
    outside the catalog module. A deep copy of a real entry — which is what a
    round-trip through JSON produces — is refused for the same reason.
    """

    spec: OperatorSpec
    target: ProcessTarget
    incident_id: str
    ttl_seconds: int
    evidence_refs: tuple[EvidenceRef, ...]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        # Final by construction (S5-SEC-08). A subclass passes every ``isinstance`` test
        # and can override ``argv()``, which would hand the host a vector that never went
        # through ``assemble_argv``. The executor also demands the exact type; this makes
        # the subclass unconstructible rather than merely refused later.
        raise TypeError("DefensiveOperator is final; a subclass could override argv()")

    def __post_init__(self) -> None:
        from pocketsec.stage5.operators.catalog import CATALOG

        if not isinstance(self.spec, OperatorSpec):
            raise ContractError(f"spec must be an OperatorSpec, got {type(self.spec)!r}")
        # IDENTITY, not equality. A structurally-equal forged spec is the attack; `==`
        # would accept it and `is` does not.
        if not any(self.spec is entry for entry in CATALOG.values()):
            raise ContractError(
                f"spec must be a CATALOG member by identity; {self.spec.operator_id!r} "
                "is not the catalog's object"
            )
        if not isinstance(self.target, ProcessTarget):
            raise ContractError(f"target must be a ProcessTarget, got {type(self.target)!r}")
        if self.target.scope.kind is not self.spec.target_kind:
            raise ContractError(
                f"{self.spec.operator_id}: scope kind {self.target.scope.kind} is not "
                f"the operator's target kind {self.spec.target_kind}"
            )
        if not self.target.scope.host_local:
            # §24 HOST_LOCAL_SCOPE: outside the PocketSec defensive boundary.
            raise ContractError(f"{self.spec.operator_id}: scope is not host-local")
        require_identifier(self.incident_id, "DefensiveOperator.incident_id")
        require_non_negative_int(self.ttl_seconds, "DefensiveOperator.ttl_seconds")
        if not 0 < self.ttl_seconds <= self.spec.max_duration_seconds:
            raise ContractError(
                f"{self.spec.operator_id}: ttl_seconds must be in "
                f"(0, {self.spec.max_duration_seconds}], got {self.ttl_seconds}"
            )
        if not isinstance(self.evidence_refs, tuple):
            raise ContractError("DefensiveOperator.evidence_refs must be a tuple")
        if len(self.evidence_refs) > MAX_EVIDENCE_REFS_PER_OPERATOR:
            raise ContractError(f"evidence_refs exceeds {MAX_EVIDENCE_REFS_PER_OPERATOR}")
        for ref in self.evidence_refs:
            if not isinstance(ref, EvidenceRef):
                raise ContractError(f"evidence_refs must hold EvidenceRef, got {type(ref)!r}")

    def argv(self) -> tuple[str, ...]:
        return assemble_argv(self.spec.argv_template, self.target)

    def binding_digest(self) -> str:
        """THE authorisation key: what a capability token must name to act as this operator.

        ``ProcessIdentity.digest()`` keys the *process*. It does not key the object a
        SOCKET, SESSION or SERVICE operator actually acts on (``scope.subject``), so a
        token bound only to the identity digest authorised any subject of that process
        — a confused deputy (findings F1 / S5-SEC-04). This digest covers the operator
        id, the identity digest, the whole scope and the ttl, and the token plane and
        SENTINEL both compare against this one method, so the two key spaces are one
        function rather than two that must be kept in step.
        """
        return digest_of_bytes(
            json.dumps(
                {
                    "host_local": self.target.scope.host_local,
                    "identity_digest": self.target.identity.digest(),
                    "operator_id": self.spec.operator_id,
                    "scope_kind": str(self.target.scope.kind),
                    "scope_subject": self.target.scope.subject,
                    "ttl_seconds": self.ttl_seconds,
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        )

    def rollback(self) -> DefensiveOperator | None:
        """The operator that undoes this one, or ``None``.

        ``None`` is a real answer: an ``IRREVERSIBLE`` or ``DEGRADED`` operator has no
        rollback, which is why §2 sends it across a higher authority boundary instead of
        letting a lease expire it away.
        """
        from pocketsec.stage5.operators.catalog import CATALOG

        if self.spec.rollback_operator_id is None:
            return None
        rollback_spec = CATALOG[self.spec.rollback_operator_id]
        return DefensiveOperator(
            spec=rollback_spec,
            target=self.target,
            incident_id=self.incident_id,
            ttl_seconds=min(self.ttl_seconds, rollback_spec.max_duration_seconds),
            evidence_refs=self.evidence_refs,
        )

    def to_dict(self) -> dict[str, Any]:
        """Plain JSON. Evidence is referenced by digest, never inlined."""
        return {
            "operator_id": self.spec.operator_id,
            "operator_class": self.spec.operator_class.name,
            "authority": str(self.spec.authority),
            "incident_id": self.incident_id,
            "ttl_seconds": self.ttl_seconds,
            "target_digest": self.target.identity.digest(),
            "target_pid": self.target.identity.pid,
            "target_kind": str(self.target.scope.kind),
            "target_subject": self.target.scope.subject,
            "host_local": self.target.scope.host_local,
            "rollback_operator_id": self.spec.rollback_operator_id,
            "reversibility": str(self.spec.reversibility),
            "evidence_effect": str(self.spec.evidence_effect),
            "evidence_digests": [ref.digest for ref in self.evidence_refs],
            "vector": list(self.argv()),
        }


def _resolve_field(field: TargetField, target: ProcessTarget) -> str:
    """The closed field table. Total over :class:`TargetField`, no fallthrough."""
    if target.scope.kind not in FIELD_TARGET_KINDS[field]:
        raise ContractError(f"{field} is not readable from a {target.scope.kind} target")
    match field:
        case TargetField.PID:
            return str(target.identity.pid)
        case TargetField.UID:
            return str(target.identity.uid)
        case TargetField.UNIT_NAME | TargetField.SOCKET_ID | TargetField.SESSION_ID:
            # Re-validated at substitution time even though TargetScope already
            # validated it: the token that reaches the vector is checked by the code
            # that puts it there.
            return _require_argv_token(target.scope.subject, f"TargetScope.subject for {field}")
        case _ as unreachable:  # pragma: no cover - mypy exhaustiveness anchor
            assert_never(unreachable)


def assemble_argv(template: Sequence[ArgvAtom], target: ProcessTarget) -> tuple[str, ...]:
    """The ONLY place an argument vector is produced. Three refusals, in order:

    1. ``template`` must be a ``CATALOG`` entry's own ``argv_template`` object, by
       identity, so there is no "assemble this list of atoms I just made up" path.
    2. Each atom must be a :class:`LiteralAtom` or a :class:`FieldAtom`; anything else
       raises :class:`ContractError` before the ``match``, so a bad caller gets a contract
       failure and ``mypy --strict`` still sees the ``match`` as exhaustive.
    3. Every produced token passes :data:`LITERAL_ATOM_PATTERN`.

    No format string, no ``%``, no ``.format()``, no ``join``. The return value is a tuple
    of tokens, never a command line.
    """
    _require_catalog_template(template)
    tokens: list[str] = []
    for index, atom in enumerate(template):
        if not isinstance(atom, (LiteralAtom, FieldAtom)):
            raise ContractError(
                f"argv atom {index} is {type(atom)!r}; ArgvAtom is closed over "
                "LiteralAtom | FieldAtom and a string is not a member"
            )
        match atom:
            case LiteralAtom():
                tokens.append(_require_argv_token(atom.value, f"argv[{index}]"))
            case FieldAtom():
                resolved = _resolve_field(atom.field, target)
                tokens.append(_require_argv_token(resolved, f"argv[{index}]"))
            case _ as unreachable:  # pragma: no cover - mypy exhaustiveness anchor
                assert_never(unreachable)
    return tuple(tokens)


def _require_catalog_template(template: Sequence[ArgvAtom]) -> None:
    from pocketsec.stage5.operators.catalog import CATALOG

    if not any(template is entry.argv_template for entry in CATALOG.values()):
        raise ContractError(
            "assemble_argv refuses a template that is not a CATALOG entry's own "
            "argv_template object; an argument vector has exactly one provenance"
        )


# --- the static scan of the negative ----------------------------------------------

# Moved to ``operators/command_path.py`` when finding S5-SEC-09 extended it (aliases,
# ``posix``/``nt``, ``__import__``, ``getattr`` on ``os``, literal ``import_module``). The
# names stay importable from here so the gate, the boundary test and every caller keep
# one implementation, which is the S2-AUTH-01 lesson this re-export exists to keep.
from pocketsec.stage5.operators.command_path import (  # noqa: E402 - re-export
    ARGV_NAME_TOKENS,
    FORBIDDEN_CALL_NAMES,
    FORBIDDEN_IMPORT_ROOTS,
    FORBIDDEN_OS_ATTRIBUTES,
    no_arbitrary_command_path,
)
