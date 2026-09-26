"""D5.6 — the authority plane: who may grant what, and the two sources of a grant.

Architecture §14 gives seven authority classes and one sentence that this module
exists to make structural: *"Authority classes are encoded into policy and action
schemas, not inferred by a language model."*

So :class:`GrantSource` has exactly **two** members, ``POLICY`` and ``HUMAN``.
There is no ``MODEL`` member, no ``INFERRED`` member and no
``from_prediction()`` classmethod. ADR-0003 is not enforced here by a check that
a reviewer could delete; it is enforced by the absence of a member, and
``tests/test_stage5_boundary.py`` pins the membership by value so that adding one
is a visible edit to a closed enum in a file whose diff a human reads.

The second construction lives in :data:`AUTHORITY_BY_OPERATOR_CLASS`: a mapping
that is **total** over ``OperatorClass``, asserted at import time. An operator
class nobody assigned an authority to raises ``AssertionError`` when the module
loads, rather than defaulting to something permissive at the moment it is first
used. That is property P4 ("authority cannot escalate"): its mutation is
"remove one row and the package stops importing".

This module imports ``OperatorClass`` from ``operators/algebra.py`` and nothing
else from that package at runtime. The dependency points this way — algebra takes
:class:`AuthorityClass` from ``constitution/invariants.py``, which imports no
Stage 5 module at all — so the three modules form a chain rather than a cycle.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError, require_identifier
from pocketsec.stage5.constitution.invariants import (
    AuthorityClass,
    ConstitutionDecision,
    ResponseConstitution,
    authority_rank,
)
from pocketsec.stage5.operators.algebra import OperatorClass

if TYPE_CHECKING:  # pragma: no cover - annotation only; see the module docstring
    from pocketsec.stage5.operators.algebra import OperatorSpec

__all__ = [
    "AUTHORITY_BY_OPERATOR_CLASS",
    "AUTONOMY_BY_OPERATOR_CLASS",
    "HUMAN_REQUIRED_AUTONOMY",
    "POLICY_AUTONOMY",
    "AuthorityGrant",
    "Autonomy",
    "GrantSource",
    "autonomy_of",
    "autonomy_permitted",
    "escalates",
    "required_authority",
]


class GrantSource(StrEnum):
    """Two members. A model is not one of them (ADR-0003, spec §2.4 rule 3)."""

    POLICY = "POLICY"
    """A grant written into local policy ahead of the incident."""
    HUMAN = "HUMAN"
    """A grant a person made, for this action, under the §32 decision contract."""


class Autonomy(StrEnum):
    """Architecture §5's autonomy column, one member per distinct entry."""

    POLICY_ELIGIBLE = "POLICY_ELIGIBLE"
    """O0, O1 — observation and preservation may run on policy alone."""
    STRICT_GATE = "STRICT_GATE"
    """O2, O3 — reversible restriction and suspension, under every gate."""
    APPROVAL_USUAL = "APPROVAL_USUAL"
    """O4 — local revocation usually waits for approval."""
    HUMAN_BY_DEFAULT = "HUMAN_BY_DEFAULT"
    """O5, O6 — service containment and disruption default to a person."""
    NEVER_AUTONOMOUS = "NEVER_AUTONOMOUS"
    """O7 — destruction, which the constitution prohibits outright."""


@dataclass(frozen=True, slots=True)
class AuthorityGrant:
    """One grant, naming its source, its policy version and the operator it covers.

    A grant is scoped to a single ``operator_id``. A grant that covered "the
    incident" or "the host" would be a standing permission, and §15 says the
    executor has none: it receives a narrow capability per action.
    """

    authority: AuthorityClass
    granted_by: GrantSource
    policy_version: str
    subject_operator_id: str
    detail: str

    def __post_init__(self) -> None:
        require_identifier(self.policy_version, "AuthorityGrant.policy_version")
        require_identifier(self.subject_operator_id, "AuthorityGrant.subject_operator_id")
        if not isinstance(self.granted_by, GrantSource):
            raise ContractError(
                f"AuthorityGrant.granted_by must be a GrantSource, got {self.granted_by!r}"
            )
        if self.authority is AuthorityClass.AX:
            raise ContractError(
                "AX is prohibited autonomous action; there is no source that can grant it"
            )
        if not self.detail:
            raise ContractError("a grant must record why it was made")

    def to_dict(self) -> dict[str, Any]:
        return {
            "authority": self.authority.value,
            "granted_by": self.granted_by.value,
            "policy_version": self.policy_version,
            "subject_operator_id": self.subject_operator_id,
            "detail": self.detail,
        }


#: §5 and §14 joined: the authority an operator class requires. ``O3_SUSPEND``
#: shares ``A2`` with ``O2`` because a suspension with a validated resume *is* a
#: fully reversible local intervention; ``O7`` maps to ``AX``, which no grant can
#: carry, so the destructive class has no authority path at all.
AUTHORITY_BY_OPERATOR_CLASS: Mapping[OperatorClass, AuthorityClass] = MappingProxyType(
    {
        OperatorClass.O0_OBSERVE: AuthorityClass.A0,
        OperatorClass.O1_PRESERVE: AuthorityClass.A1,
        OperatorClass.O2_REVERSIBLE_RESTRICT: AuthorityClass.A2,
        OperatorClass.O3_SUSPEND: AuthorityClass.A2,
        OperatorClass.O4_LOCAL_REVOKE: AuthorityClass.A3,
        OperatorClass.O5_SERVICE_CONTAINMENT: AuthorityClass.A4,
        OperatorClass.O6_DISRUPTIVE: AuthorityClass.A5,
        OperatorClass.O7_DESTRUCTIVE: AuthorityClass.AX,
    }
)

#: §5's autonomy column, verbatim.
AUTONOMY_BY_OPERATOR_CLASS: Mapping[OperatorClass, Autonomy] = MappingProxyType(
    {
        OperatorClass.O0_OBSERVE: Autonomy.POLICY_ELIGIBLE,
        OperatorClass.O1_PRESERVE: Autonomy.POLICY_ELIGIBLE,
        OperatorClass.O2_REVERSIBLE_RESTRICT: Autonomy.STRICT_GATE,
        OperatorClass.O3_SUSPEND: Autonomy.STRICT_GATE,
        OperatorClass.O4_LOCAL_REVOKE: Autonomy.APPROVAL_USUAL,
        OperatorClass.O5_SERVICE_CONTAINMENT: Autonomy.HUMAN_BY_DEFAULT,
        OperatorClass.O6_DISRUPTIVE: Autonomy.HUMAN_BY_DEFAULT,
        OperatorClass.O7_DESTRUCTIVE: Autonomy.NEVER_AUTONOMOUS,
    }
)

#: Autonomy levels a POLICY grant can carry on its own.
POLICY_AUTONOMY: frozenset[Autonomy] = frozenset(
    {Autonomy.POLICY_ELIGIBLE, Autonomy.STRICT_GATE}
)

#: Autonomy levels that require a HUMAN grant. The complement of
#: :data:`POLICY_AUTONOMY`, written as its own constant because ``TokenStore.mint``
#: refuses against it and a refusal predicate computed by subtraction is one
#: refactor away from being empty.
HUMAN_REQUIRED_AUTONOMY: frozenset[Autonomy] = frozenset(
    {Autonomy.APPROVAL_USUAL, Autonomy.HUMAN_BY_DEFAULT, Autonomy.NEVER_AUTONOMOUS}
)


def required_authority(spec: OperatorSpec) -> AuthorityClass:
    """The authority class this operator needs, from its class alone.

    Read off :data:`AUTHORITY_BY_OPERATOR_CLASS` rather than off
    ``spec.authority``: the catalog entry's own field is checked against this
    mapping when the entry is built, so consulting the mapping here means a
    forged spec cannot lower its own requirement.
    """
    try:
        return AUTHORITY_BY_OPERATOR_CLASS[spec.operator_class]
    except KeyError as exc:
        raise ContractError(
            f"operator class {spec.operator_class!r} has no authority class; "
            "an unmapped class is not permission"
        ) from exc


def autonomy_of(spec: OperatorSpec) -> Autonomy:
    """The §5 autonomy level of this operator's class."""
    try:
        return AUTONOMY_BY_OPERATOR_CLASS[spec.operator_class]
    except KeyError as exc:
        raise ContractError(
            f"operator class {spec.operator_class!r} has no autonomy level; "
            "an unmapped class is not autonomous"
        ) from exc


def escalates(granted: AuthorityClass, required: AuthorityClass) -> bool:
    """True when acting under ``granted`` on something needing ``required`` escalates.

    Compared by :func:`authority_rank`, never as strings: ``"A2" < "AX"`` is a
    true statement about text and a dangerous one about privilege.
    """
    if required is AuthorityClass.AX:
        return True
    return authority_rank(required) > authority_rank(granted)


def autonomy_permitted(spec: OperatorSpec, constitution: ResponseConstitution) -> bool:
    """Whether this operator may run without a person, under this constitution.

    Two independent conditions, both required: §5's autonomy column must allow it,
    **and** the constitution must permit it as an autonomous action. They are not
    redundant — the autonomy column is a property of the operator class, the
    constitutional verdict is a property of reversibility and rollback, and an
    operator can pass either one while failing the other.
    """
    if autonomy_of(spec) not in POLICY_AUTONOMY:
        return False
    verdict = constitution.permits(
        operator_class=spec.operator_class,
        authority=required_authority(spec),
        reversibility=spec.reversibility,
        has_rollback=spec.rollback_operator_id is not None,
        autonomous=True,
    )
    return verdict.decision is ConstitutionDecision.PERMITTED


assert set(AUTHORITY_BY_OPERATOR_CLASS) == set(
    OperatorClass
), "every operator class must name the authority it requires (P4); unmapped is not permission"
assert set(AUTONOMY_BY_OPERATOR_CLASS) == set(
    OperatorClass
), "every operator class must name its §5 autonomy level"
assert set(
    Autonomy
) == POLICY_AUTONOMY | HUMAN_REQUIRED_AUTONOMY, "every autonomy level is either policy-eligible or human-required, never neither"
assert not POLICY_AUTONOMY & HUMAN_REQUIRED_AUTONOMY, "and never both"
assert len(GrantSource) == 2, "a grant comes from policy or from a person (ADR-0003)"
