"""D5.1 — the Response Constitution: the ten laws no Stage 5 caller may argue with.

Stage 5 is the only stage that touches privilege, so the laws that constrain it
are **data with no configuration path**. Architecture §2 lists ten constitutional
invariants; :class:`ConstitutionalLaw` holds exactly ten members, one per bullet,
and :class:`ResponseConstitution` refuses at construction time to be *weaker*
than :data:`FROZEN_CONSTITUTION`.

That refusal is the point. A permissive constitution is not a thing a caller can
build and hand to SENTINEL: there is no flag, no ``None`` and no policy file that
raises ``max_autonomous_authority`` above ``A2``, drops a law, or un-prohibits the
destructive operator class. SENTINEL independence case 3 — "a kernel that can be
disabled by a missing config is not independent" — is answered here, before
SENTINEL exists.

Two things this module deliberately refuses to do:

* **It never sees a confidence.** :meth:`ResponseConstitution.permits` takes an
  operator class, an authority class, a reversibility, whether a rollback exists
  and whether the action is autonomous. There is no parameter through which a
  model score could enter the decision, which is how ADR-0003 is enforced by
  construction rather than by review.
* **It never imports the operator algebra.** ``operators/algebra.py`` imports
  *this* module for :class:`AuthorityClass`, so importing ``OperatorClass`` back
  would close a runtime cycle. The prohibition is therefore written as the
  ordinal it is (:data:`O7_DESTRUCTIVE_ORDINAL`), which works because
  ``OperatorClass`` is an ``IntEnum`` whose members hash and compare as their
  int. ``tests/test_stage5_foundation.py`` pins that key space in both
  directions.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, cast

from pocketsec.stage0.contracts.common import (
    ContractError,
    digest_of_bytes,
    register_schema,
    require_identifier,
)

if TYPE_CHECKING:  # pragma: no cover - annotations only, see the module docstring
    from pocketsec.stage5.operators.algebra import OperatorClass, Reversibility

__all__ = [
    "AUTHORITY_ORDER",
    "FROZEN_CONSTITUTION",
    "IRREVERSIBLE",
    "MAX_AUTONOMOUS_AUTHORITY",
    "MIN_ROLLBACK_PLAN_RANK",
    "O7_DESTRUCTIVE_ORDINAL",
    "PROHIBITED_OPERATOR_CLASSES",
    "RESPONSE_CONSTITUTION_V1_ID",
    "RESPONSE_CONSTITUTION_V1_VERSION",
    "REVERSIBILITY_ORDER",
    "AuthorityClass",
    "ConstitutionDecision",
    "ConstitutionVerdict",
    "ConstitutionalLaw",
    "ResponseConstitution",
    "authority_rank",
    "canonical_bytes",
    "reversibility_rank",
]

RESPONSE_CONSTITUTION_V1_ID = "pocketsec.response_constitution.v1"
RESPONSE_CONSTITUTION_V1_VERSION = register_schema(RESPONSE_CONSTITUTION_V1_ID, "1.0.0")


def canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    """Deterministic JSON bytes — the substrate of every Stage 5 digest and byte bound.

    Stage 4 has the same one-liner in ``worlds/world.py``, but Stage 5 may import
    exactly one Stage 4 module (``stage5_interface``, ADR-0045), so reaching for
    it would break the dependency boundary for four lines of code. ``allow_nan``
    is off: a NaN that round-trips through a digest is a silent contract break.
    """
    return json.dumps(payload, sort_keys=True, allow_nan=False, separators=(",", ":")).encode(
        "utf-8"
    )


class AuthorityClass(StrEnum):
    """§14. Ordered, but the order lives in :data:`AUTHORITY_ORDER`, never in the string.

    ``"A2" < "AX"`` is true lexicographically and meaningless semantically, which
    is exactly the comparison an authority check must never make. Every
    comparison in Stage 5 goes through :func:`authority_rank`.
    """

    A0 = "A0"
    """read-only observation"""
    A1 = "A1"
    """bounded evidence preservation"""
    A2 = "A2"
    """local fully reversible intervention"""
    A3 = "A3"
    """local disruptive intervention"""
    A4 = "A4"
    """host-wide containment"""
    A5 = "A5"
    """administrator-only"""
    AX = "AX"
    """prohibited autonomous action — not "the highest", but "off the ladder" """


#: A0..A5 are a ladder; AX is deliberately far off the end so that no arithmetic
#: on ranks can ever walk from A5 into AX, and so a caller that sorts by rank
#: puts AX last rather than between A0 and A1.
AUTHORITY_ORDER: Mapping[AuthorityClass, int] = MappingProxyType(
    {
        AuthorityClass.A0: 0,
        AuthorityClass.A1: 1,
        AuthorityClass.A2: 2,
        AuthorityClass.A3: 3,
        AuthorityClass.A4: 4,
        AuthorityClass.A5: 5,
        AuthorityClass.AX: 99,
    }
)

#: The ceiling on autonomy: local, fully reversible intervention and no further.
MAX_AUTONOMOUS_AUTHORITY: AuthorityClass = AuthorityClass.A2


def authority_rank(authority: AuthorityClass) -> int:
    """The comparable rank of an authority class, refusing an unmapped member.

    A ``KeyError`` here would be a silently-skipped comparison in a caller's
    ``try``; a :class:`ContractError` is the fail-closed answer.
    """
    try:
        return AUTHORITY_ORDER[authority]
    except KeyError as exc:  # pragma: no cover - AUTHORITY_ORDER is total, asserted below
        raise ContractError(f"unranked authority class {authority!r}") from exc


#: ``Reversibility`` (``operators/algebra.py``) as it bears on authority, keyed by
#: the member *value* because this module must not import the algebra. Stage 5
#: has one reversibility vocabulary, and this is it: ``governor.py`` imports this
#: mapping rather than restating the four strings, so the two cannot drift.
REVERSIBILITY_ORDER: Mapping[str, int] = MappingProxyType(
    {
        "FULLY_REVERSIBLE": 0,
        "REVERSIBLE_WITH_STATE": 1,
        "DEGRADED": 2,
        "IRREVERSIBLE": 3,
    }
)

#: The reversibility §2's sixth law is about: an action that cannot be rolled back.
#: Spelled once, because it is both a key of REVERSIBILITY_ORDER and the ceiling
#: that :func:`reversibility_rank` falls back to.
IRREVERSIBLE: str = "IRREVERSIBLE"

#: The rank at and above which undoing the action needs state captured beforehand,
#: so an autonomous action must have a rollback operator bound to it.
MIN_ROLLBACK_PLAN_RANK: int = REVERSIBILITY_ORDER["REVERSIBLE_WITH_STATE"]


def reversibility_rank(reversibility: Reversibility | str) -> int:
    """Rank a reversibility, treating anything unrecognised as IRREVERSIBLE.

    Fail-closed on purpose. A future member of ``Reversibility`` that nobody
    remembered to rank here must be treated as the *most* constrained case, not
    slipped through as ``0``; the test that pins this key space against the real
    enum is how the omission gets noticed, and this is what happens until it is.
    """
    return REVERSIBILITY_ORDER.get(str(reversibility), REVERSIBILITY_ORDER[IRREVERSIBLE])


class ConstitutionalLaw(StrEnum):
    """Architecture §2, one member per bullet. Ten members, closed."""

    NO_CONFIDENCE_GRANTS_AUTHORITY = "NO_CONFIDENCE_GRANTS_AUTHORITY"
    NO_NATURAL_LANGUAGE_TO_PRIVILEGE = "NO_NATURAL_LANGUAGE_TO_PRIVILEGE"
    NO_ACTION_EXCEEDS_DECLARED_SCOPE = "NO_ACTION_EXCEEDS_DECLARED_SCOPE"
    UNKNOWN_IS_NOT_PERMISSION = "UNKNOWN_IS_NOT_PERMISSION"
    UNVERIFIABLE_IS_NOT_COMPLETE = "UNVERIFIABLE_IS_NOT_COMPLETE"
    IRREVERSIBLE_NEEDS_HIGHER_AUTHORITY = "IRREVERSIBLE_NEEDS_HIGHER_AUTHORITY"
    EVIDENCE_PRECEDES_INTERVENTION = "EVIDENCE_PRECEDES_INTERVENTION"
    NO_ACTION_IS_ALWAYS_AVAILABLE = "NO_ACTION_IS_ALWAYS_AVAILABLE"
    FAILURE_MUST_NOT_STOP_MONITORING = "FAILURE_MUST_NOT_STOP_MONITORING"
    NO_OFFENSIVE_BEHAVIOUR = "NO_OFFENSIVE_BEHAVIOUR"


class ConstitutionDecision(StrEnum):
    PERMITTED = "PERMITTED"
    REFUSED = "REFUSED"
    HUMAN_REQUIRED = "HUMAN_REQUIRED"


@dataclass(frozen=True, slots=True)
class ConstitutionVerdict:
    """A decision that carries the laws that produced it.

    ``laws_invoked`` is empty only for a clean ``PERMITTED``: a refusal that
    cannot name its law is a refusal nobody can audit or appeal.
    """

    decision: ConstitutionDecision
    laws_invoked: tuple[ConstitutionalLaw, ...]
    detail: str

    def __post_init__(self) -> None:
        if self.decision is not ConstitutionDecision.PERMITTED and not self.laws_invoked:
            raise ContractError(f"a {self.decision.value} verdict must name the law it invokes")
        if not self.detail:
            raise ContractError("a constitutional verdict must carry a reason")

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "laws_invoked": [law.value for law in self.laws_invoked],
            "detail": self.detail,
        }


#: ``OperatorClass.O7_DESTRUCTIVE``'s ordinal. Spelled as an int because this
#: module is a leaf: see the module docstring.
O7_DESTRUCTIVE_ORDINAL: int = 7

#: The prohibited classes of the frozen constitution. ``OperatorClass`` is an
#: ``IntEnum``, so ``OperatorClass.O7_DESTRUCTIVE in PROHIBITED_OPERATOR_CLASSES``
#: is ``True`` — an ``IntEnum`` member hashes and compares as its int. The cast
#: states that relationship to the type checker instead of hiding it behind an
#: import cycle, and ``test_the_prohibited_class_key_space_is_operator_class``
#: proves it against the real enum the moment package 2 lands.
PROHIBITED_OPERATOR_CLASSES: frozenset[OperatorClass] = cast(
    "frozenset[OperatorClass]", frozenset({O7_DESTRUCTIVE_ORDINAL})
)


def _class_ordinal(operator_class: OperatorClass | int) -> int:
    """The int an ``OperatorClass`` member is, refusing anything that is not one."""
    if isinstance(operator_class, bool) or not isinstance(operator_class, int):
        raise ContractError(
            f"operator class must be an OperatorClass (an IntEnum), got {operator_class!r}"
        )
    return int(operator_class)


@dataclass(frozen=True, slots=True)
class ResponseConstitution:
    """The ten laws, the autonomy ceiling and the prohibited classes, as one frozen record.

    ``__post_init__`` refuses any instance weaker than :data:`FROZEN_CONSTITUTION`.
    A caller may construct an *equal* constitution (and must, to deserialise one),
    and may raise ``policy_version``; it may not drop a law, lift the autonomy
    ceiling or permit the destructive class. There is consequently no
    configuration, deserialisation or test-fixture path to a permissive
    constitution, which is the property SENTINEL's independence rests on.
    """

    laws: tuple[ConstitutionalLaw, ...]
    max_autonomous_authority: AuthorityClass
    prohibited_operator_classes: frozenset[OperatorClass]
    policy_version: str
    schema_version: str = RESPONSE_CONSTITUTION_V1_VERSION

    def __post_init__(self) -> None:
        require_identifier(self.policy_version, "ResponseConstitution.policy_version")
        require_identifier(self.schema_version, "ResponseConstitution.schema_version")
        if set(self.laws) != set(ConstitutionalLaw) or len(self.laws) != len(ConstitutionalLaw):
            raise ContractError(
                "the constitution is the complete set of architecture §2 laws, each once; "
                f"got {len(self.laws)} of {len(ConstitutionalLaw)}"
            )
        if authority_rank(self.max_autonomous_authority) > authority_rank(
            MAX_AUTONOMOUS_AUTHORITY
        ):
            raise ContractError(
                f"max_autonomous_authority {self.max_autonomous_authority.value} exceeds the "
                f"constitutional ceiling {MAX_AUTONOMOUS_AUTHORITY.value}"
            )
        ordinals = {_class_ordinal(entry) for entry in self.prohibited_operator_classes}
        if O7_DESTRUCTIVE_ORDINAL not in ordinals:
            raise ContractError(
                "the destructive operator class (O7) is prohibited by the constitution and "
                "cannot be un-prohibited by a caller"
            )

    def digest(self) -> str:
        """The constitution's content digest — what a receipt or a token pins to."""
        return digest_of_bytes(canonical_bytes(self.to_dict()))

    def permits(
        self,
        *,
        operator_class: OperatorClass,
        authority: AuthorityClass,
        reversibility: Reversibility,
        has_rollback: bool,
        autonomous: bool,
    ) -> ConstitutionVerdict:
        """Decide one action against the ten laws.

        **There is no confidence, score, support or text parameter, and there
        never may be.** ADR-0003 says model confidence grants no authority; the
        way to make that structural rather than aspirational is to give the
        function nothing to be confident with.
        """
        prohibited = self._refuse_prohibited(operator_class, authority)
        if prohibited is not None:
            return prohibited
        unrollbackable = self._gate_reversibility(reversibility, has_rollback, autonomous)
        if unrollbackable is not None:
            return unrollbackable
        if autonomous and authority_rank(authority) > authority_rank(
            self.max_autonomous_authority
        ):
            return ConstitutionVerdict(
                ConstitutionDecision.HUMAN_REQUIRED,
                (ConstitutionalLaw.NO_ACTION_EXCEEDS_DECLARED_SCOPE,),
                f"{authority.value} exceeds the autonomy ceiling "
                f"{self.max_autonomous_authority.value}",
            )
        return ConstitutionVerdict(
            ConstitutionDecision.PERMITTED,
            (),
            f"authority {authority.value} within "
            f"{'autonomous' if autonomous else 'human-authorised'} limits",
        )

    def _refuse_prohibited(
        self, operator_class: OperatorClass, authority: AuthorityClass
    ) -> ConstitutionVerdict | None:
        """AX and the prohibited classes are refusals, not escalations.

        Escalating a destructive operator to a human would make the constitution
        a routing table. §5 says O7 is "not autonomous"; §2's tenth law says
        destruction is outside the defensive boundary, so the answer is REFUSED
        and no authority can change it.
        """
        ordinal = _class_ordinal(operator_class)
        prohibited = {_class_ordinal(entry) for entry in self.prohibited_operator_classes}
        if ordinal in prohibited:
            return ConstitutionVerdict(
                ConstitutionDecision.REFUSED,
                (
                    ConstitutionalLaw.IRREVERSIBLE_NEEDS_HIGHER_AUTHORITY,
                    ConstitutionalLaw.NO_OFFENSIVE_BEHAVIOUR,
                ),
                f"operator class ordinal {ordinal} is constitutionally prohibited",
            )
        if authority is AuthorityClass.AX:
            return ConstitutionVerdict(
                ConstitutionDecision.REFUSED,
                (ConstitutionalLaw.NO_ACTION_EXCEEDS_DECLARED_SCOPE,),
                "AX is prohibited autonomous action, not the top of the ladder",
            )
        return None

    def _gate_reversibility(
        self, reversibility: Reversibility, has_rollback: bool, autonomous: bool
    ) -> ConstitutionVerdict | None:
        """§2: an action that cannot be rolled back must cross a higher authority boundary.

        Two rules, and the second is where ``has_rollback`` earns its place.
        ``IRREVERSIBLE`` never runs autonomously. From
        :data:`MIN_ROLLBACK_PLAN_RANK` upward — ``REVERSIBLE_WITH_STATE`` and
        ``DEGRADED`` — the action cannot be undone without state somebody had to
        capture first, so an autonomous one must have a rollback operator bound.

        ``FULLY_REVERSIBLE`` is deliberately *not* required to name one: an
        observation changes nothing, and a release or a resume **is** the inverse
        of the action that preceded it. Demanding a rollback operator for those
        would make the constitution refuse the recovery half of every containment,
        which is the opposite of what §22 ("recovery is part of response") asks
        for.
        """
        if not autonomous:
            return None
        rank = reversibility_rank(reversibility)
        if rank >= REVERSIBILITY_ORDER[IRREVERSIBLE]:
            return ConstitutionVerdict(
                ConstitutionDecision.HUMAN_REQUIRED,
                (ConstitutionalLaw.IRREVERSIBLE_NEEDS_HIGHER_AUTHORITY,),
                f"reversibility {reversibility!s} cannot be undone autonomously",
            )
        if rank >= MIN_ROLLBACK_PLAN_RANK and not has_rollback:
            return ConstitutionVerdict(
                ConstitutionDecision.HUMAN_REQUIRED,
                (ConstitutionalLaw.IRREVERSIBLE_NEEDS_HIGHER_AUTHORITY,),
                f"reversibility {reversibility!s} needs a bound rollback operator and has none",
            )
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": RESPONSE_CONSTITUTION_V1_ID,
            "schema_version": self.schema_version,
            "policy_version": self.policy_version,
            "laws": sorted(law.value for law in self.laws),
            "max_autonomous_authority": self.max_autonomous_authority.value,
            "prohibited_operator_classes": sorted(
                _class_ordinal(entry) for entry in self.prohibited_operator_classes
            ),
        }


#: The one constitution. Every Stage 5 subsystem takes this instance; the type
#: exists so it can be serialised and compared, not so it can be varied.
FROZEN_CONSTITUTION: ResponseConstitution = ResponseConstitution(
    laws=tuple(ConstitutionalLaw),
    max_autonomous_authority=MAX_AUTONOMOUS_AUTHORITY,
    prohibited_operator_classes=PROHIBITED_OPERATOR_CLASSES,
    policy_version="1.0.0",
)


assert len(ConstitutionalLaw) == 10, "architecture §2 lists exactly ten constitutional invariants"
assert set(AUTHORITY_ORDER) == set(AuthorityClass), "every authority class must be rankable"
assert len(REVERSIBILITY_ORDER) == 4, "operators/algebra.py's Reversibility has four members"
assert authority_rank(MAX_AUTONOMOUS_AUTHORITY) < authority_rank(
    AuthorityClass.A3
), "autonomy stops below local disruptive intervention"
