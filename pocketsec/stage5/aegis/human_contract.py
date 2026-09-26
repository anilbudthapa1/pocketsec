"""D5.9b / §32 — the structure a human is shown when autonomy stops, heading for heading.

Architecture §32 asks for a *decision contract*, and the distinction it is making
is the whole content of this module: **the human sees the decision structure, not
an AI recommendation.** There is no model here, no generated prose, no summary
and no persuasion. Every field is derived from typed data by a pure function, and
every string is a catalog id, a ``sha256:`` digest, a validated host identifier or
a member of a closed vocabulary declared in this file.

**Why that matters enough to make it structural.** An escalation is the one place
where a model's belief could reach a privileged action by way of a human being
who was told what to think. A free-text ``recommendation`` field would be exactly
the natural-language-to-privilege path ADR-0003 forbids, laundered through an
approval click. So the refusals here are type-level:

* :class:`WorldEffect`'s two effect fields draw from
  :data:`SECURITY_EFFECTS` and :data:`OPERATIONAL_EFFECTS`. There is no third
  field for nuance.
* :class:`HumanDecisionContract` has no ``detail``, ``summary``, ``rationale`` or
  ``recommendation`` field, and ``approval_reason`` is a
  :data:`APPROVAL_REASONS` member. ``__post_init__`` refuses anything else.
* :meth:`HumanDecisionContract.render` is pure, deterministic and bounded by
  :data:`MAX_CONTRACT_BYTES`. Two calls produce the same bytes; an over-long
  contract raises rather than truncating, because a silently-truncated
  escalation is one whose missing line was the important one.

An escalation with no decision structure is a notification, which is why
``ResponsePlan.__post_init__`` refuses ``ESCALATE`` or ``DEFER`` with a ``None``
contract.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_finite_unit_interval,
    require_non_negative_int,
)
from pocketsec.stage5.aegis.shadow import AutonomyEligibility
from pocketsec.stage5.constitution.invariants import ResponseConstitution, authority_rank
from pocketsec.stage5.operators.algebra import EvidenceEffect, OperatorClass, Reversibility
from pocketsec.stage5.operators.catalog import CATALOG

if TYPE_CHECKING:  # pragma: no cover - annotations only
    from pocketsec.stage4.stage5_interface import CBFResolutionV1
    from pocketsec.stage5.safe.action_field import CandidateAction

__all__ = [
    "APPROVAL_REASONS",
    "CONTRACT_HEADINGS",
    "CONTRACT_TOKEN_RE",
    "MAX_CONTRACT_BYTES",
    "MAX_CONTRACT_LIST_ITEMS",
    "MAX_WORLD_EFFECTS",
    "NO_APPROVAL_REQUIRED",
    "OPERATIONAL_EFFECTS",
    "SECURITY_EFFECTS",
    "HumanDecisionContract",
    "WorldEffect",
    "build_contract",
]

#: §32's bound. A contract a human will not read is a contract that does not
#: inform consent, so the structure is capped rather than allowed to grow.
MAX_CONTRACT_BYTES: int = 8192

#: Bounded list fields. ``MAX_WORLD_EFFECTS`` matches
#: ``MAX_HYPOTHESES_PER_RESOLUTION`` upstream: a contract cannot describe more
#: worlds than Stage 4 can hand over.
MAX_WORLD_EFFECTS: int = 16
MAX_CONTRACT_LIST_ITEMS: int = 16

#: Host identifiers — unit names, session ids, volatile-signal names — are
#: validated against this rather than against ``require_identifier``, which
#: rejects the underscore that signal names such as ``socket_table`` use. No
#: whitespace and no shell metacharacter can pass, which is the property that
#: matters: nothing in a contract can become an argument vector, and nothing in
#: it is free text.
CONTRACT_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,63}$")

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

#: The closed vocabulary for a world's predicted security effect. Four members,
#: and ``UNKNOWN`` is one of them: "we do not know what this does in that world"
#: is a valid thing to show a human and the one a generated sentence would hide.
SECURITY_EFFECTS: frozenset[str] = frozenset({"CONTAINS", "REDUCES", "NO_EFFECT", "UNKNOWN"})

#: The closed vocabulary for a world's predicted operational effect.
OPERATIONAL_EFFECTS: frozenset[str] = frozenset({"NONE", "DEGRADES", "INTERRUPTS", "UNKNOWN"})

#: The sentinel member of :data:`APPROVAL_REASONS` that means no approval is
#: needed. Named rather than written inline because ``approval_required`` and
#: ``approval_reason`` must agree and the agreement is asserted.
NO_APPROVAL_REQUIRED: str = "NO_APPROVAL_REQUIRED"

#: Why a human is being asked. Closed, ordered by the order
#: :func:`build_contract` tests them in, and every member is a condition some
#: piece of Stage 5 can actually produce.
APPROVAL_REASONS: frozenset[str] = frozenset(
    {
        NO_APPROVAL_REQUIRED,
        "NO_ADMISSIBLE_ACTION",
        "AUTHORITY_ABOVE_AUTONOMOUS_CEILING",
        "HUMAN_GRANT_REQUIRED",
        "ACTION_SHADOW_ABOVE_CEILING",
        "IRREVERSIBLE_WITHOUT_ROLLBACK",
        "EVIDENCE_WOULD_BE_LOST",
        "ROLLBACK_RELIABILITY_UNKNOWN",
        "MISSION_INVARIANT_AT_RISK",
    }
)

#: §32's headings, in §32's order. :meth:`HumanDecisionContract.render` emits
#: exactly these, which is what makes the rendering comparable across versions.
CONTRACT_HEADINGS: tuple[str, ...] = (
    "PROPOSED ACTION",
    "TARGET",
    "WORLD EFFECTS",
    "EXPECTED BENEFIT",
    "COLLATERAL",
    "ACTION SHADOW",
    "EVIDENCE PRESERVED",
    "ROLLBACK",
    "LEASE",
    "APPROVAL",
    "SAFER ALTERNATIVE",
)

_NONE_TOKEN = "NONE"


def _require_catalog_id(value: object, field: str) -> str:
    if not isinstance(value, str) or value not in CATALOG:
        raise ContractError(
            f"{field} must be a CATALOG operator id, got {value!r}; a contract that "
            "names an operator the catalog does not hold is a contract about nothing"
        )
    return value


def _require_token(value: object, field: str) -> str:
    if not isinstance(value, str) or not CONTRACT_TOKEN_RE.fullmatch(value):
        raise ContractError(
            f"{field} must match CONTRACT_TOKEN_RE, got {value!r}; nothing in a human "
            "decision contract is free text (§32)"
        )
    return value


def _require_token_tuple(values: object, field: str) -> tuple[str, ...]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise ContractError(f"{field} must be a sequence of tokens")
    items = tuple(values)
    if len(items) > MAX_CONTRACT_LIST_ITEMS:
        raise ContractError(
            f"{field} carries {len(items)} items, over "
            f"MAX_CONTRACT_LIST_ITEMS={MAX_CONTRACT_LIST_ITEMS}"
        )
    return tuple(_require_token(item, f"{field}[{index}]") for index, item in enumerate(items))


@dataclass(frozen=True, slots=True)
class WorldEffect:
    """What one hypothesis's world would experience if the proposal were applied.

    ``support`` is carried because a human deciding under ambiguity needs to know
    how much evidence stands behind each world. It is shown, never summed, and it
    does not appear anywhere in the authority decision that produced this
    contract (ADR-0003).
    """

    mechanism_id: str
    support: float
    predicted_security_effect: str
    predicted_operational_effect: str
    harmful: bool

    def __post_init__(self) -> None:
        _require_token(self.mechanism_id, "WorldEffect.mechanism_id")
        require_finite_unit_interval(self.support, "WorldEffect.support")
        if self.predicted_security_effect not in SECURITY_EFFECTS:
            raise ContractError(
                f"WorldEffect.predicted_security_effect {self.predicted_security_effect!r} "
                f"is not in SECURITY_EFFECTS {sorted(SECURITY_EFFECTS)}"
            )
        if self.predicted_operational_effect not in OPERATIONAL_EFFECTS:
            raise ContractError(
                "WorldEffect.predicted_operational_effect "
                f"{self.predicted_operational_effect!r} is not in OPERATIONAL_EFFECTS "
                f"{sorted(OPERATIONAL_EFFECTS)}"
            )
        if not isinstance(self.harmful, bool):
            raise ContractError("WorldEffect.harmful must be a bool")

    def to_dict(self) -> dict[str, Any]:
        return {
            "mechanism_id": self.mechanism_id,
            "support": self.support,
            "predicted_security_effect": self.predicted_security_effect,
            "predicted_operational_effect": self.predicted_operational_effect,
            "harmful": self.harmful,
        }


@dataclass(frozen=True, slots=True)
class HumanDecisionContract:
    """§32's contract. Thirteen typed fields and not one sentence of prose."""

    proposal_operator_id: str
    proposal_target_digest: str
    world_effects: tuple[WorldEffect, ...]
    expected_benefit: float
    collateral_units: tuple[str, ...]
    action_shadow: float
    evidence_preserved: tuple[str, ...]
    rollback_operator_id: str | None
    lease_ttl_seconds: int
    approval_required: bool
    approval_reason: str
    safer_alternative_id: str | None

    def __post_init__(self) -> None:
        self._check_catalog_ids()
        self._check_numbers()
        self._check_approval()
        rendered = self._render_unchecked()
        if len(rendered.encode("utf-8")) > MAX_CONTRACT_BYTES:
            raise ContractError(
                f"rendered contract is {len(rendered.encode('utf-8'))} bytes, over "
                f"MAX_CONTRACT_BYTES={MAX_CONTRACT_BYTES}; a silently-truncated escalation "
                "is one whose missing line was the important one"
            )

    def _check_catalog_ids(self) -> None:
        """Every operator-shaped field names a CATALOG entry; the target is a digest."""
        _require_catalog_id(self.proposal_operator_id, "HumanDecisionContract.proposal_operator_id")
        if not _DIGEST_RE.fullmatch(str(self.proposal_target_digest)):
            raise ContractError(
                "HumanDecisionContract.proposal_target_digest must be a sha256 digest, got "
                f"{self.proposal_target_digest!r}; the target is named by identity, never by pid"
            )
        if self.rollback_operator_id is not None:
            _require_catalog_id(
                self.rollback_operator_id, "HumanDecisionContract.rollback_operator_id"
            )
        if self.safer_alternative_id is not None:
            _require_catalog_id(
                self.safer_alternative_id, "HumanDecisionContract.safer_alternative_id"
            )
        object.__setattr__(
            self,
            "collateral_units",
            _require_token_tuple(self.collateral_units, "HumanDecisionContract.collateral_units"),
        )
        object.__setattr__(
            self,
            "evidence_preserved",
            _require_token_tuple(
                self.evidence_preserved, "HumanDecisionContract.evidence_preserved"
            ),
        )

    def _check_numbers(self) -> None:
        """The two unit intervals, the ttl, and the world-effect bound."""
        if not isinstance(self.world_effects, tuple):
            raise ContractError("HumanDecisionContract.world_effects must be a tuple")
        if len(self.world_effects) > MAX_WORLD_EFFECTS:
            raise ContractError(
                f"HumanDecisionContract carries {len(self.world_effects)} world effects, "
                f"over MAX_WORLD_EFFECTS={MAX_WORLD_EFFECTS}"
            )
        require_finite_unit_interval(self.expected_benefit, "HumanDecisionContract.expected_benefit")
        require_finite_unit_interval(self.action_shadow, "HumanDecisionContract.action_shadow")
        require_non_negative_int(self.lease_ttl_seconds, "HumanDecisionContract.lease_ttl_seconds")

    def _check_approval(self) -> None:
        """The two approval fields must agree.

        Otherwise a contract could ask for approval while stating no reason, or state
        a reason while claiming none is needed — and a human reading either would be
        reading something the system does not mean.
        """
        if not isinstance(self.approval_required, bool):
            raise ContractError("HumanDecisionContract.approval_required must be a bool")
        if self.approval_reason not in APPROVAL_REASONS:
            raise ContractError(
                f"HumanDecisionContract.approval_reason {self.approval_reason!r} is not in "
                f"APPROVAL_REASONS {sorted(APPROVAL_REASONS)}"
            )
        if self.approval_required == (self.approval_reason == NO_APPROVAL_REQUIRED):
            raise ContractError(
                f"approval_required={self.approval_required} contradicts "
                f"approval_reason={self.approval_reason!r}"
            )

    def _render_unchecked(self) -> str:
        """The rendering, without the bound check that ``__post_init__`` performs.

        Split out so ``__post_init__`` can measure the result before the object is
        considered valid, without :meth:`render` having to re-check a bound that
        construction already guaranteed.
        """
        worlds = (
            "\n".join(
                f"  - {effect.mechanism_id} support={effect.support:.4f} "
                f"security={effect.predicted_security_effect} "
                f"operational={effect.predicted_operational_effect} "
                f"harmful={'yes' if effect.harmful else 'no'}"
                for effect in self.world_effects
            )
            or f"  - {_NONE_TOKEN}"
        )
        body: dict[str, str] = {
            "PROPOSED ACTION": self.proposal_operator_id,
            "TARGET": self.proposal_target_digest,
            "WORLD EFFECTS": f"\n{worlds}",
            "EXPECTED BENEFIT": f"{self.expected_benefit:.4f}",
            "COLLATERAL": ", ".join(self.collateral_units) or _NONE_TOKEN,
            "ACTION SHADOW": f"{self.action_shadow:.4f}",
            "EVIDENCE PRESERVED": ", ".join(self.evidence_preserved) or _NONE_TOKEN,
            "ROLLBACK": self.rollback_operator_id or _NONE_TOKEN,
            "LEASE": f"{self.lease_ttl_seconds}s",
            "APPROVAL": f"{'REQUIRED' if self.approval_required else 'NOT_REQUIRED'} "
            f"{self.approval_reason}",
            "SAFER ALTERNATIVE": self.safer_alternative_id or _NONE_TOKEN,
        }
        return "\n".join(f"{heading}: {body[heading]}" for heading in CONTRACT_HEADINGS)

    def render(self) -> str:
        """Pure, deterministic, bounded. No clock, no randomness, no host read."""
        return self._render_unchecked()

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_operator_id": self.proposal_operator_id,
            "proposal_target_digest": self.proposal_target_digest,
            "world_effects": [effect.to_dict() for effect in self.world_effects],
            "expected_benefit": self.expected_benefit,
            "collateral_units": list(self.collateral_units),
            "action_shadow": self.action_shadow,
            "evidence_preserved": list(self.evidence_preserved),
            "rollback_operator_id": self.rollback_operator_id,
            "lease_ttl_seconds": self.lease_ttl_seconds,
            "approval_required": self.approval_required,
            "approval_reason": self.approval_reason,
            "safer_alternative_id": self.safer_alternative_id,
        }


def _security_effect(candidate: CandidateAction, world_id: str) -> str:
    """Bucket a candidate's effect in one world into the closed vocabulary.

    The thresholds are the class boundaries the catalog already commits to, not
    fitted numbers: an operator that does not apply to a world has NO_EFFECT
    there, an O0/O1 operator observes rather than contains, and an operator at or
    above O4 (local revoke) is the first that removes the attacker's access
    rather than narrowing it.
    """
    if world_id not in candidate.world_applicability:
        return "NO_EFFECT"
    operator_class = candidate.operator.spec.operator_class
    if operator_class <= OperatorClass.O1_PRESERVE:
        return "NO_EFFECT"
    if operator_class >= OperatorClass.O4_LOCAL_REVOKE:
        return "CONTAINS"
    return "REDUCES"


def _operational_effect(candidate: CandidateAction) -> str:
    operator_class = candidate.operator.spec.operator_class
    if operator_class <= OperatorClass.O1_PRESERVE:
        return "NONE"
    if operator_class >= OperatorClass.O4_LOCAL_REVOKE:
        return "INTERRUPTS"
    return "DEGRADES"


def _world_effects(
    candidate: CandidateAction, resolution: CBFResolutionV1, *, harmful: frozenset[str]
) -> tuple[WorldEffect, ...]:
    effects: list[WorldEffect] = []
    seen: set[str] = set()
    for row in resolution.hypotheses:
        mechanism_id = str(row.get("mechanism_id", ""))
        if not mechanism_id or mechanism_id in seen:
            continue
        seen.add(mechanism_id)
        effects.append(
            WorldEffect(
                mechanism_id=mechanism_id,
                support=float(row.get("support", 0.0)),
                predicted_security_effect=_security_effect(candidate, mechanism_id),
                predicted_operational_effect=_operational_effect(candidate),
                harmful=mechanism_id in harmful,
            )
        )
        if len(effects) == MAX_WORLD_EFFECTS:
            break
    return tuple(effects)


def _approval_reason(
    candidate: CandidateAction,
    *,
    constitution: ResponseConstitution,
    shadow_eligibility: AutonomyEligibility,
) -> str:
    """The first reason, in a fixed order, that a human is being asked.

    Fixed order rather than a set, because a human reading "approval required"
    needs the *binding* reason: widening the socket restriction will not help if
    the real problem is that the operator is above the autonomy ceiling.
    """
    spec = candidate.operator.spec
    if authority_rank(spec.authority) > authority_rank(
        constitution.max_autonomous_authority
    ):
        return "AUTHORITY_ABOVE_AUTONOMOUS_CEILING"
    if spec.operator_class in constitution.prohibited_operator_classes:
        return "HUMAN_GRANT_REQUIRED"
    if shadow_eligibility is not AutonomyEligibility.ELIGIBLE:
        return "ACTION_SHADOW_ABOVE_CEILING"
    if spec.reversibility is Reversibility.IRREVERSIBLE or (
        spec.operator_class >= OperatorClass.O2_REVERSIBLE_RESTRICT
        and spec.rollback_operator_id is None
    ):
        return "IRREVERSIBLE_WITHOUT_ROLLBACK"
    if spec.evidence_effect in {EvidenceEffect.DEGRADES_VOLATILE, EvidenceEffect.DESTROYS}:
        return "EVIDENCE_WOULD_BE_LOST"
    return NO_APPROVAL_REQUIRED


def _safer_alternative(
    plan_candidates: Sequence[CandidateAction], chosen: CandidateAction | None
) -> str | None:
    """The lowest-consequence candidate that is not the proposal itself.

    "Safer" is ordered by the catalog's own consequence order and then by
    reversibility, both of which are declared data — never by a score, and never
    by a model's opinion of which action a human would like better.
    """
    pool = [
        candidate
        for candidate in plan_candidates
        if chosen is None or candidate.candidate_id != chosen.candidate_id
    ]
    if not pool:
        return None
    if chosen is not None:
        ceiling = chosen.operator.spec.operator_class
        pool = [c for c in pool if c.operator.spec.operator_class < ceiling] or pool
    safest = min(
        pool,
        key=lambda candidate: (
            int(candidate.operator.spec.operator_class),
            candidate.shadow.score,
            candidate.candidate_id,
        ),
    )
    if chosen is not None and safest.operator.spec.operator_id == chosen.operator.spec.operator_id:
        return None
    return safest.operator.spec.operator_id


def build_contract(
    plan_candidates: Sequence[CandidateAction],
    chosen: CandidateAction | None,
    *,
    resolution: CBFResolutionV1,
    constitution: ResponseConstitution,
    shadow_eligibility: AutonomyEligibility,
    harmful_worlds: frozenset[str] = frozenset(),
    collateral_units: Sequence[str] = (),
    preserved_signals: Sequence[str] = (),
    reliability_unknown: bool = False,
    mission_invariant_at_risk: bool = False,
) -> HumanDecisionContract:
    """Derive §32's structure from typed data. Pure: no clock, no host, no model.

    ``chosen`` may be ``None`` — that is the case where nothing was admissible
    and the human is being shown *that*, with the least-consequence candidate in
    the field as the proposal so the target and the worlds are still legible. A
    contract is required for every ``ESCALATE`` and ``DEFER`` plan, so this
    function must not have a path that refuses to produce one for a real field.

    ``harmful_worlds``, ``collateral_units``, ``preserved_signals``,
    ``reliability_unknown`` and ``mission_invariant_at_risk`` are supplied by the
    planner from checks it has already run and from the read-only snapshot it
    holds. They are keyword-only with defaults that **understate safety rather
    than overstate it**: omitting ``preserved_signals`` shows no evidence as
    preserved, and omitting ``collateral_units`` shows no collateral — the first
    is conservative, the second is why the planner always passes it.
    """
    if not plan_candidates and chosen is None:
        raise ContractError(
            "build_contract needs at least one candidate; §2's "
            "NO_ACTION_IS_ALWAYS_AVAILABLE guarantees the action field is never empty, "
            "so an empty field here is a defect upstream, not a case to paper over"
        )
    proposal = chosen if chosen is not None else _least_consequence(plan_candidates)
    reason = _resolved_reason(
        proposal,
        constitution=constitution,
        shadow_eligibility=shadow_eligibility,
        no_admissible_action=chosen is None,
        reliability_unknown=reliability_unknown,
        mission_invariant_at_risk=mission_invariant_at_risk,
    )
    spec = proposal.operator.spec
    return HumanDecisionContract(
        proposal_operator_id=spec.operator_id,
        proposal_target_digest=proposal.operator.target.identity.digest(),
        world_effects=_world_effects(proposal, resolution, harmful=harmful_worlds),
        expected_benefit=proposal.expected_security_delta,
        collateral_units=tuple(collateral_units)[:MAX_CONTRACT_LIST_ITEMS],
        action_shadow=proposal.shadow.score,
        evidence_preserved=_preserved_signals(proposal, preserved_signals),
        rollback_operator_id=spec.rollback_operator_id,
        lease_ttl_seconds=proposal.lease_ttl_seconds,
        approval_required=reason != NO_APPROVAL_REQUIRED,
        approval_reason=reason,
        safer_alternative_id=_safer_alternative(plan_candidates, chosen),
    )


def _least_consequence(candidates: Sequence[CandidateAction]) -> CandidateAction:
    """The lowest-consequence candidate, by the catalog's own class order.

    Used as the proposal when nothing was admissible, so the contract still shows
    the target and the worlds. Ordered by declared data, never by a score.
    """
    return min(
        candidates,
        key=lambda candidate: (
            int(candidate.operator.spec.operator_class),
            candidate.candidate_id,
        ),
    )


def _preserved_signals(
    candidate: CandidateAction, observable: Sequence[str]
) -> tuple[str, ...]:
    """The signals the caller observed on the target, minus the ones this action loses.

    Derived by **subtraction** rather than asserted, so a candidate that loses a
    signal can never also be shown as preserving it — the one arithmetic in this
    module that could overstate the safety of a proposal, done in the direction
    that cannot. An operator whose evidence effect is not PRESERVES reports ``()``
    even when nothing is lost: failing to destroy evidence is not preserving it,
    and §13's pre-action bundle, not a contract field, is what preservation means.
    """
    if candidate.evidence_effect is not EvidenceEffect.PRESERVES:
        return ()
    lost = set(candidate.evidence_loss)
    kept = sorted(
        signal
        for signal in set(observable) - lost
        if CONTRACT_TOKEN_RE.fullmatch(signal)
    )
    return tuple(kept[:MAX_CONTRACT_LIST_ITEMS])


def _resolved_reason(
    proposal: CandidateAction,
    *,
    constitution: ResponseConstitution,
    shadow_eligibility: AutonomyEligibility,
    no_admissible_action: bool,
    reliability_unknown: bool,
    mission_invariant_at_risk: bool,
) -> str:
    """The approval reason, with the caller's three extra conditions folded in.

    The operator's own properties are checked first by :func:`_approval_reason`; the
    caller's conditions only apply when that found nothing, so a contract never
    reports "reliability unknown" for an action that is above the authority ceiling
    anyway. A human needs the binding reason, not the last one tested.
    """
    reason = _approval_reason(
        proposal, constitution=constitution, shadow_eligibility=shadow_eligibility
    )
    if reason != NO_APPROVAL_REQUIRED:
        return reason
    if no_admissible_action:
        return "NO_ADMISSIBLE_ACTION"
    if reliability_unknown:
        return "ROLLBACK_RELIABILITY_UNKNOWN"
    if mission_invariant_at_risk:
        return "MISSION_INVARIANT_AT_RISK"
    return NO_APPROVAL_REQUIRED
