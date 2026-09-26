"""D5.9 — the nine-objective score, the Pareto frontier, minimax regret, and the scalar control.

Architecture §12 makes one argument and this module is built to let that argument
be **falsified rather than assumed**: a response decision has nine objectives,
any single weighted sum over them hides the trade-off, and so AEGIS removes
dominated actions *before* any policy is applied. The counter-argument — that an
arbitrary weighted sum does just as well — is :func:`scalar_utility`, and it
lives in this same module, is exercised by the same tests and runs on the same
corpus in the same process. Putting the control in a sibling file would make the
comparison a comparison of two code paths; putting it here makes it a comparison
of two selectors.

**What this module refuses to do.**

* It refuses to sum the nine objectives into one number anywhere on the
  :data:`Selector.PARETO_THEN_POLICY` path. :func:`select` removes dominated
  vectors first and then applies :data:`POLICY_ORDER`, a *lexicographic* order
  over the harm objectives. A lexicographic order commits to a priority; a
  weighted sum pretends to commit to a rate of exchange it cannot justify.
* It refuses to let an absent cone make an action look cheap.
  :data:`Objective.COLLATERAL` and :data:`Objective.ACTION_SHADOW` take the
  *worse* of the generation-time estimate and the cone's worst leaf, so running
  with ``enable_cone=False`` (the SAFE-F05 ablation) can never lower a
  candidate's measured harm. An ablation that made actions look safer would
  reward turning the safety machinery off.
* It refuses to use an inadmissible action as a hindsight benchmark. §26's
  ``Regret(A,W) = Loss(A,W) - Loss(best action in hindsight, W)`` is only a
  meaningful number when the hindsight action was one the system was allowed to
  take: measuring a permitted action's regret against a constitutionally
  forbidden one manufactures regret out of the constitution. :func:`regret`
  filters through :func:`admissible_in_world` and **raises** when no admissible
  action exists, rather than quietly benchmarking against zero.
* It refuses to hide the arbitrariness of :data:`DEFAULT_WEIGHTS` and
  :data:`LOSS_RISK_WEIGHT`. Both are arbitrary. That arbitrariness is §12's
  entire argument, not an embarrassment, and no result may be attributed to
  their values.

**Where the rejection types live, and why here rather than in the planner.**
:class:`RejectionRecord` and :data:`REJECTION_REASONS` are listed under D5.3 in
the specification but are defined here, because :func:`select` is the first
producer of a rejection and ``planner.py`` already imports this module. Defining
them in the planner would make ``pareto -> planner -> pareto`` an import cycle;
``planner.py`` re-exports both names so the specified import path still works.

Every threshold in this module is a **chosen** parameter. None is fitted and
none is measured (§4.9).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_finite_unit_interval,
    require_identifier,
)
from pocketsec.stage5.aegis.shadow import AutonomyEligibility, shadow_gate
from pocketsec.stage5.constitution.invariants import (
    FROZEN_CONSTITUTION,
    ConstitutionDecision,
    ResponseConstitution,
)
from pocketsec.stage5.executor.lease import MAX_LEASE_LIFETIME_SECONDS
from pocketsec.stage5.executor.verify import PostconditionKind
from pocketsec.stage5.operators.algebra import (
    EvidenceEffect,
    OperatorClass,
    Reversibility,
)

if TYPE_CHECKING:  # pragma: no cover - annotations only, and the cone import is a cycle
    from pocketsec.stage4.stage5_interface import CBFResolutionV1
    from pocketsec.stage5.aegis.cone import InterventionCone
    from pocketsec.stage5.safe.action_field import CandidateAction

__all__ = [
    "DEFAULT_WEIGHTS",
    "DEFERRED_PREDICATES",
    "EVIDENCE_LOSS_SCALE",
    "IRREVERSIBILITY_SCALE",
    "LOSS_RISK_WEIGHT",
    "MAXIMISED",
    "MAX_EVIDENCE_LOSS_SIGNALS",
    "MAX_SCOPE_UNITS",
    "MINIMISED",
    "POLICY_ORDER",
    "REJECTION_REASONS",
    "Objective",
    "ObjectiveVector",
    "RejectionRecord",
    "ScoredCandidate",
    "Selector",
    "admissible_in_world",
    "dominates",
    "minimal_regret_set",
    "minimax_regret",
    "pareto_frontier",
    "policy_pick",
    "regret",
    "scalar_utility",
    "score",
    "select",
    "world_ids_of",
]


class Objective(StrEnum):
    """§12's nine dimensions, exactly, in §12's order.

    The order is load-bearing twice: :data:`POLICY_ORDER` is a *different*
    ordering and the difference must be visible, and ``ObjectiveVector.to_dict``
    emits declaration order so two vectors compare byte-identically.
    """

    SECURITY_BENEFIT = "SECURITY_BENEFIT"
    WORST_WORLD_SECURITY_BENEFIT = "WORST_WORLD_SECURITY_BENEFIT"
    COLLATERAL = "COLLATERAL"
    SCOPE = "SCOPE"
    IRREVERSIBILITY = "IRREVERSIBILITY"
    EVIDENCE_LOSS = "EVIDENCE_LOSS"
    ACTION_SHADOW = "ACTION_SHADOW"
    DOWNTIME = "DOWNTIME"
    VERIFICATION_LATENCY = "VERIFICATION_LATENCY"


#: The two objectives where more is better. Every other member is a harm.
MAXIMISED: frozenset[Objective] = frozenset(
    {Objective.SECURITY_BENEFIT, Objective.WORST_WORLD_SECURITY_BENEFIT}
)

#: The seven harms, in declaration order, so the mean over them is stable.
MINIMISED: tuple[Objective, ...] = tuple(o for o in Objective if o not in MAXIMISED)

#: §12's irreversibility axis, as numbers. Not a measurement of how hard a
#: rollback is on a real host — that is UNMEASURED (§9.1) — but the ordering the
#: constitution already commits to in ``REVERSIBILITY_ORDER``.
IRREVERSIBILITY_SCALE: Mapping[Reversibility, float] = MappingProxyType(
    {
        Reversibility.FULLY_REVERSIBLE: 0.0,
        Reversibility.REVERSIBLE_WITH_STATE: 0.25,
        Reversibility.DEGRADED: 0.6,
        Reversibility.IRREVERSIBLE: 1.0,
    }
)

#: PRESERVES and NEUTRAL are both 0.0 deliberately: neither loses evidence, and
#: giving PRESERVES a negative-cost bonus would let an observation operator
#: dominate an intervention on an axis that is about loss, not gain.
EVIDENCE_LOSS_SCALE: Mapping[EvidenceEffect, float] = MappingProxyType(
    {
        EvidenceEffect.PRESERVES: 0.0,
        EvidenceEffect.NEUTRAL: 0.0,
        EvidenceEffect.DEGRADES_VOLATILE: 0.5,
        EvidenceEffect.DESTROYS: 1.0,
    }
)

# A missing member here would silently score as 0.0 — the most permissive value
# on a harm axis — so both scales are asserted total at import time. This is the
# same construction ``AUTHORITY_BY_OPERATOR_CLASS`` uses in authority/capability.
assert set(IRREVERSIBILITY_SCALE) == set(Reversibility)
assert set(EVIDENCE_LOSS_SCALE) == set(EvidenceEffect)

#: Scope normaliser. Equal to ``ResourceBudget.max_dependency_nodes``: the
#: governor will not walk more entities than this, so no candidate can honestly
#: claim a larger scope.
MAX_SCOPE_UNITS: int = 64

#: Evidence-loss normaliser. Equal to ``MAX_VOLATILE_SIGNALS`` in
#: ``evidence/preservation_gate.py``; a candidate cannot lose more volatile
#: signals than the gate can track.
MAX_EVIDENCE_LOSS_SIGNALS: int = 16

#: The postconditions that cannot be observed in the same breath as the call:
#: each needs the host to evolve before it can be read. ``VERIFICATION_LATENCY``
#: is the fraction of a candidate's predicates drawn from this set — a **chosen
#: proxy**, because this repository holds no measured verification latency and a
#: made-up millisecond figure would be worse than a proxy that says what it is.
DEFERRED_PREDICATES: frozenset[PostconditionKind] = frozenset(
    {
        PostconditionKind.TRAJECTORY_REDUCED,
        PostconditionKind.SERVICE_HEALTH_ACCEPTABLE,
        PostconditionKind.ATTACKER_PATH_UNCHANGED,
    }
)

#: The class at which an intervention starts costing availability. O0/O1 read and
#: copy; O2 restricts a socket the attacker holds. Suspension is the first
#: operator whose own effect is downtime.
FIRST_DOWNTIME_CLASS: OperatorClass = OperatorClass.O3_SUSPEND

#: §26 needs a scalar ``Loss`` before it can define regret, so this split exists.
#: **It is arbitrary in exactly the sense DEFAULT_WEIGHTS is arbitrary.** It is
#: not tuned, it is not measured, and no reported result may be attributed to it.
#: Its only defence is that half-and-half asserts nothing about the exchange rate
#: between residual risk and operational harm.
LOSS_RISK_WEIGHT: float = 0.5

#: The lexicographic policy applied *after* dominated vectors are gone. §11's
#: Minimum Effective Intervention read as a priority order rather than a sum:
#: prefer the reversible action, then the one that keeps the evidence, then the
#: one the planner understands best, then the narrowest, then the cheapest.
#: A **chosen** policy, and the one thing on this path that could be reordered
#: without changing any measured number's meaning.
POLICY_ORDER: tuple[Objective, ...] = (
    Objective.IRREVERSIBILITY,
    Objective.EVIDENCE_LOSS,
    Objective.ACTION_SHADOW,
    Objective.SCOPE,
    Objective.COLLATERAL,
    Objective.DOWNTIME,
    Objective.VERIFICATION_LATENCY,
)

assert set(POLICY_ORDER) == set(MINIMISED)

#: The closed vocabulary of reasons a candidate can be refused. Closed because a
#: free-text reason is a reason nobody can count, and G5.14 counts these.
REJECTION_REASONS: frozenset[str] = frozenset(
    {
        "DOMINATED",
        "NOT_IDENTIFIABLE",
        "SHADOW",
        "AUTHORITY",
        "MISSION_INVARIANT",
        "EVIDENCE",
        "HYSTERESIS",
        "BUDGET",
        "NO_ROLLBACK",
        "INSUFFICIENT_BENEFIT",
        "RELIABILITY",
    }
)


class Selector(StrEnum):
    """The three ways a decision can be taken. Two are §12's; one is its control."""

    PARETO_THEN_POLICY = "PARETO_THEN_POLICY"
    MINIMAX_REGRET = "MINIMAX_REGRET"
    SCALAR_UTILITY = "SCALAR_UTILITY"


#: **These weights are arbitrary, which is §12's entire argument for removing
#: dominated actions before scalarising; they are not a tuned parameter and no
#: result may be attributed to their values.** They exist only to make the B6
#: baseline runnable. If B6 matches the frontier selector on measured collateral
#: at equal containment, falsifier F4 fires and §12's argument is unsupported —
#: which is a result, and ADR-0048 records it either way.
DEFAULT_WEIGHTS: Mapping[Objective, float] = MappingProxyType(
    {
        Objective.SECURITY_BENEFIT: 1.0,
        Objective.WORST_WORLD_SECURITY_BENEFIT: 1.0,
        Objective.COLLATERAL: 1.0,
        Objective.SCOPE: 1.0,
        Objective.IRREVERSIBILITY: 1.0,
        Objective.EVIDENCE_LOSS: 1.0,
        Objective.ACTION_SHADOW: 1.0,
        Objective.DOWNTIME: 1.0,
        Objective.VERIFICATION_LATENCY: 1.0,
    }
)

assert set(DEFAULT_WEIGHTS) == set(Objective)


@dataclass(frozen=True, slots=True)
class RejectionRecord:
    """Why one candidate did not survive. ``reason`` is a REJECTION_REASONS member."""

    candidate_id: str
    reason: str
    detail: str

    def __post_init__(self) -> None:
        require_identifier(self.candidate_id, "RejectionRecord.candidate_id")
        if self.reason not in REJECTION_REASONS:
            raise ContractError(
                f"RejectionRecord.reason {self.reason!r} is not in REJECTION_REASONS; "
                "a rejection nobody can count is a rejection nobody can audit"
            )
        if not isinstance(self.detail, str):
            raise ContractError("RejectionRecord.detail must be a string")

    def to_dict(self) -> dict[str, str]:
        return {
            "candidate_id": self.candidate_id,
            "reason": self.reason,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class ObjectiveVector:
    """Nine numbers in [0, 1], every one of them present.

    A partially-populated vector would make :func:`dominates` compare a present
    value against a default, and the default on a harm axis is the permissive
    end. ``__post_init__`` therefore refuses an incomplete mapping rather than
    filling it in.
    """

    values: Mapping[Objective, float]

    def __post_init__(self) -> None:
        if not isinstance(self.values, Mapping):
            raise ContractError("ObjectiveVector.values must be a mapping")
        frozen: dict[Objective, float] = {}
        for objective in Objective:
            if objective not in self.values:
                raise ContractError(
                    f"ObjectiveVector is missing {objective.value}; an absent objective "
                    "would be compared against a default, and the default on a harm "
                    "axis is the permissive end"
                )
            frozen[objective] = require_finite_unit_interval(
                self.values[objective], f"ObjectiveVector[{objective.value}]"
            )
        unknown = sorted(str(key) for key in self.values if key not in set(Objective))
        if unknown:
            raise ContractError(f"ObjectiveVector carries unknown objectives {unknown}")
        object.__setattr__(self, "values", MappingProxyType(frozen))

    def __getitem__(self, objective: Objective) -> float:
        return self.values[objective]

    def to_dict(self) -> dict[str, float]:
        return {objective.value: self.values[objective] for objective in Objective}


@dataclass(frozen=True, slots=True)
class ScoredCandidate:
    """A candidate plus its vector plus its per-world loss.

    ``caller_inadmissible`` is the one field the specification's field list does
    not name, and it is a deliberate addition: admissibility in §26's sense also
    covers the **mission invariants**, which are runtime data this module is
    never handed. The planner, which does hold them, sets this flag when its own
    invariant or identifiability check refused the candidate, and
    :func:`admissible_in_world` honours it. Without the flag, ``regret`` would
    benchmark against an action that violates a mission invariant — exactly the
    failure §26 warns about — and the alternative of passing the invariant set
    into ``score`` would give this unprivileged module a second reason to know
    about host policy.
    """

    candidate: CandidateAction
    objectives: ObjectiveVector
    per_world_loss: Mapping[str, float]
    caller_inadmissible: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.per_world_loss, Mapping):
            raise ContractError("ScoredCandidate.per_world_loss must be a mapping")
        frozen: dict[str, float] = {}
        for world_id, loss in self.per_world_loss.items():
            require_identifier(world_id, "ScoredCandidate.per_world_loss key")
            frozen[world_id] = require_finite_unit_interval(
                loss, f"ScoredCandidate.per_world_loss[{world_id!r}]"
            )
        object.__setattr__(self, "per_world_loss", MappingProxyType(frozen))
        if not isinstance(self.caller_inadmissible, bool):
            raise ContractError("ScoredCandidate.caller_inadmissible must be a bool")

    @property
    def candidate_id(self) -> str:
        return self.candidate.candidate_id

    def loss(self, world_id: str) -> float:
        """Loss in one world, or a refusal.

        A missing world is an error rather than a default: a silently-zero loss
        for an unscored world would make that world look like the best one.
        """
        if world_id not in self.per_world_loss:
            raise ContractError(
                f"{self.candidate_id!r} has no loss for world {world_id!r}; "
                "scoring and selection must share one world key space (§4.9 Rule A)"
            )
        return self.per_world_loss[world_id]

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "operator_id": self.candidate.operator.spec.operator_id,
            "objectives": self.objectives.to_dict(),
            "per_world_loss": dict(sorted(self.per_world_loss.items())),
            "caller_inadmissible": self.caller_inadmissible,
        }


def world_ids_of(resolution: CBFResolutionV1) -> tuple[str, ...]:
    """THE world key function: the mechanism ids of a resolution, deduplicated.

    Every world key space in AEGIS comes from here — ``cones`` keys,
    ``per_world_loss`` keys and the ``world_ids`` argument to :func:`select` —
    because ``CandidateAction.world_applicability`` is a set of ``mechanism_id``
    strings and two waves have already shipped a defect where two key spaces were
    joined that could never match (§4.9 Rule A). Order is first-appearance, so
    the tuple is deterministic for a deterministic resolution.
    """
    seen: list[str] = []
    for row in resolution.hypotheses:
        mechanism_id = str(row.get("mechanism_id", ""))
        if mechanism_id and mechanism_id not in seen:
            seen.append(mechanism_id)
    return tuple(seen)


def _support_of(resolution: CBFResolutionV1, world_id: str) -> float:
    for row in resolution.hypotheses:
        if str(row.get("mechanism_id", "")) == world_id:
            return require_finite_unit_interval(
                row.get("support", 0.0), f"hypothesis[{world_id!r}].support"
            )
    return 0.0


def _cone_collateral(cones: Mapping[str, InterventionCone]) -> float:
    """The worst leaf degradation any cone found, clamped into [0, 1]."""
    worst = 0.0
    for cone in cones.values():
        worst = max(worst, min(1.0, max(0.0, cone.worst_leaf_degradation())))
    return worst


def _verification_latency(candidate: CandidateAction) -> float:
    predicates = candidate.verification_predicates
    if not predicates:
        # CandidateAction.__post_init__ forbids this; a defensive 1.0 here means
        # "worst case", never "free".
        return 1.0
    deferred = sum(1 for kind in predicates if kind in DEFERRED_PREDICATES)
    return deferred / len(predicates)


def _downtime(candidate: CandidateAction) -> float:
    if candidate.operator.spec.operator_class < FIRST_DOWNTIME_CLASS:
        return 0.0
    return min(1.0, candidate.lease_ttl_seconds / MAX_LEASE_LIFETIME_SECONDS)


def score(
    candidate: CandidateAction,
    *,
    cones: Mapping[str, InterventionCone],
    resolution: CBFResolutionV1,
    caller_inadmissible: bool = False,
) -> ScoredCandidate:
    """Project one candidate onto §12's nine axes and onto a per-world loss.

    Two properties this function is built to have, both tested:

    * **Safety monotonicity under ablation.** ``COLLATERAL`` and
      ``ACTION_SHADOW`` are the *maximum* of the generation-time estimate and
      what the cones found. Passing ``cones={}`` — which is what
      ``enable_cone=False`` does — therefore never lowers a harm score. If it
      did, the ablation that removes the safety machinery would make every
      action look better and G5.14 would reward turning it off.
    * **Confidence enters only through magnitude, never through ordering.**
      ``SECURITY_BENEFIT`` carries the resolution's support because that is what
      §12's benefit axis *is*, and ADR-0003 permits it: benefit is evidence.
      Authority is computed elsewhere, from the operator class and the policy,
      and ``AegisPlanner._authority_outcome`` is not given this vector.
    """
    objectives = ObjectiveVector(values=_objective_values(candidate, cones, resolution))
    harm = sum(objectives[o] for o in MINIMISED) / len(MINIMISED)
    return ScoredCandidate(
        candidate=candidate,
        objectives=objectives,
        per_world_loss={
            world_id: _loss_in_world(candidate, world_id, harm=harm)
            for world_id in world_ids_of(resolution)
        },
        caller_inadmissible=caller_inadmissible,
    )


def _objective_values(
    candidate: CandidateAction,
    cones: Mapping[str, InterventionCone],
    resolution: CBFResolutionV1,
) -> dict[Objective, float]:
    """The nine axes for one candidate. Split out so :func:`score` stays readable."""
    cone_worst = _cone_collateral(cones)
    return {
        Objective.SECURITY_BENEFIT: require_finite_unit_interval(
            candidate.expected_security_delta, "candidate.expected_security_delta"
        ),
        Objective.WORST_WORLD_SECURITY_BENEFIT: _worst_world_benefit(candidate, resolution),
        Objective.COLLATERAL: max(
            require_finite_unit_interval(
                candidate.expected_operational_delta, "candidate.expected_operational_delta"
            ),
            cone_worst,
        ),
        Objective.SCOPE: min(1.0, candidate.scope_size / MAX_SCOPE_UNITS),
        Objective.IRREVERSIBILITY: IRREVERSIBILITY_SCALE[candidate.reversibility],
        Objective.EVIDENCE_LOSS: max(
            EVIDENCE_LOSS_SCALE[candidate.evidence_effect],
            min(1.0, len(candidate.evidence_loss) / MAX_EVIDENCE_LOSS_SIGNALS),
        ),
        Objective.ACTION_SHADOW: max(
            require_finite_unit_interval(candidate.shadow.score, "candidate.shadow.score"),
            cone_worst if cones else 0.0,
        ),
        Objective.DOWNTIME: _downtime(candidate),
        Objective.VERIFICATION_LATENCY: _verification_latency(candidate),
    }


def _worst_world_benefit(candidate: CandidateAction, resolution: CBFResolutionV1) -> float:
    """The benefit in the world where this action helps least.

    A candidate that applies to one of three worlds scores 0.0 here, which is
    the point: §12 asks for the worst-case security benefit precisely so an
    action that only works if the leading hypothesis is right cannot dominate one
    that works in every world.
    """
    worlds = world_ids_of(resolution)
    if not worlds:
        return 0.0
    return min(
        candidate.expected_security_delta if world_id in candidate.world_applicability else 0.0
        for world_id in worlds
    )


def _loss_in_world(candidate: CandidateAction, world_id: str, *, harm: float) -> float:
    """§26's ``Loss(A, W)``: residual risk in W plus the action's own harm.

    The split is :data:`LOSS_RISK_WEIGHT` and it is arbitrary. Both halves are
    in [0, 1], so the loss is too, which is what lets regret be compared across
    worlds at all.
    """
    benefit = (
        candidate.expected_security_delta if world_id in candidate.world_applicability else 0.0
    )
    residual_risk = 1.0 - benefit
    return LOSS_RISK_WEIGHT * residual_risk + (1.0 - LOSS_RISK_WEIGHT) * harm


def dominates(left: ObjectiveVector, right: ObjectiveVector) -> bool:
    """Pareto dominance: at least as good everywhere, strictly better somewhere.

    Strict, so it is irreflexive and asymmetric; and because every comparison is
    a total order on a float, it is transitive. ``tests/test_stage5_aegis.py``
    checks all three over generated vectors rather than trusting the argument.
    """
    at_least_as_good = True
    strictly_better = False
    for objective in Objective:
        a = left[objective]
        b = right[objective]
        if objective in MAXIMISED:
            if a < b:
                at_least_as_good = False
                break
            if a > b:
                strictly_better = True
        else:
            if a > b:
                at_least_as_good = False
                break
            if a < b:
                strictly_better = True
    return at_least_as_good and strictly_better


def pareto_frontier(scored: Sequence[ScoredCandidate]) -> tuple[ScoredCandidate, ...]:
    """The non-dominated set, in input order.

    Input order rather than a sort: the frontier is a *set*, and giving it an
    order that looks meaningful invites a caller to read the first element as the
    best one. :func:`select` applies :data:`POLICY_ORDER` for that.
    """
    return tuple(
        item
        for index, item in enumerate(scored)
        if not any(
            dominates(other.objectives, item.objectives)
            for other_index, other in enumerate(scored)
            if other_index != index
        )
    )


def admissible_in_world(
    scored: ScoredCandidate,
    *,
    world_id: str,
    constitution: ResponseConstitution = FROZEN_CONSTITUTION,
) -> bool:
    """Whether this action was one the system was *allowed* to take in that world.

    §26's hindsight benchmark. Three clauses, and the third is the caller's:

    1. the constitution does not **refuse** it — ``HUMAN_REQUIRED`` still counts
       as admissible, because §26 asks what the best action *in hindsight* was
       and "a human would have done better" is a true and useful answer. Reading
       ``HUMAN_REQUIRED`` as inadmissible would zero out exactly the regret that
       argues for escalation, which is the opposite of what a minimax-regret
       selector is for. This is an interpretive choice and it is stated here so a
       reviewer can disagree with it in one place.
    2. the shadow gate does not refuse it outright,
    3. the planner did not already refuse it on a mission invariant or on
       response identifiability (``caller_inadmissible``).

    ``world_id`` is accepted and validated but does not currently change the
    answer: all three clauses are world-independent in this implementation, and
    saying so here is better than a signature that implies a per-world check
    nobody wrote. A future per-world harm model belongs in clause 3, where the
    planner already owns the :class:`HarmModel`.
    """
    require_identifier(world_id, "admissible_in_world.world_id")
    if scored.caller_inadmissible:
        return False
    spec = scored.candidate.operator.spec
    verdict = constitution.permits(
        operator_class=spec.operator_class,
        authority=spec.authority,
        reversibility=spec.reversibility,
        has_rollback=spec.rollback_operator_id is not None,
        autonomous=True,
    )
    if verdict.decision is ConstitutionDecision.REFUSED:
        return False
    return shadow_gate(scored.candidate.shadow, spec=spec) is not AutonomyEligibility.HUMAN_REQUIRED


def regret(
    candidate: ScoredCandidate,
    *,
    world_id: str,
    all_candidates: Sequence[ScoredCandidate],
) -> float:
    """§26: ``Regret(A, W) = Loss(A, W) - Loss(best admissible action in hindsight, W)``.

    The hindsight set is filtered by :func:`admissible_in_world`. An
    inadmissible action is not a hindsight benchmark: measuring a permitted
    action against a constitutionally forbidden one manufactures regret out of
    the constitution, and a planner minimising that regret would be pulled
    towards the forbidden action it can never take.

    Raises when the admissible set is empty. That is not a defensive
    impossibility — it is reachable by handing this function a list containing
    only refused candidates — and returning ``0.0`` there would report "no
    regret" for a world in which nothing could legally be done.
    """
    admissible = [
        other for other in all_candidates if admissible_in_world(other, world_id=world_id)
    ]
    if not admissible:
        raise ContractError(
            f"no admissible hindsight action in world {world_id!r}, so §26's regret is "
            "undefined; returning 0.0 here would report 'no regret' for a world in "
            "which nothing could legally be done"
        )
    best = min(other.loss(world_id) for other in admissible)
    return candidate.loss(world_id) - best


def minimax_regret(
    scored: Sequence[ScoredCandidate], world_ids: Sequence[str]
) -> ScoredCandidate | None:
    """The candidate whose worst-world regret is smallest. ``None`` on an empty input.

    Ties break on ``candidate_id`` so two runs on one corpus agree, which is what
    makes an ablation delta a number rather than a coin flip.
    """
    if not scored or not world_ids:
        return None
    best: ScoredCandidate | None = None
    best_key: tuple[float, str] | None = None
    for item in scored:
        worst = max(regret(item, world_id=world_id, all_candidates=scored) for world_id in world_ids)
        key = (worst, item.candidate_id)
        if best_key is None or key < best_key:
            best, best_key = item, key
    return best


def scalar_utility(
    scored: Sequence[ScoredCandidate], weights: Mapping[Objective, float]
) -> ScoredCandidate | None:
    """The B6 control: one weighted sum, argmax, done.

    Deliberately in this module and exercised by the same tests, so the
    comparison against :data:`Selector.PARETO_THEN_POLICY` runs in one process on
    one corpus. If this wins, §12's argument is unsupported and F4 fires.
    """
    if not scored:
        return None
    missing = sorted(o.value for o in Objective if o not in weights)
    if missing:
        raise ContractError(
            f"scalar_utility weights are missing {missing}; a weighted sum over an "
            "incomplete objective set silently prices the absent axes at zero"
        )
    best: ScoredCandidate | None = None
    best_key: tuple[float, str] | None = None
    for item in scored:
        utility = sum(
            weights[objective] * item.objectives[objective]
            if objective in MAXIMISED
            else -weights[objective] * item.objectives[objective]
            for objective in Objective
        )
        key = (-utility, item.candidate_id)
        if best_key is None or key < best_key:
            best, best_key = item, key
    return best


def minimal_regret_set(
    scored: Sequence[ScoredCandidate], world_ids: Sequence[str]
) -> tuple[ScoredCandidate, ...]:
    """The subset whose worst-world regret is minimal, in input order.

    This is SAFE-F07 as a *stage* rather than as a selector: §12 removes dominated
    actions first, and §26's regret is then a way of choosing among what is left
    when the worlds disagree. Returning the whole minimal set rather than one
    element keeps the lexicographic policy as the final tie-break, so enabling
    regret cannot reorder the policy's priorities — it can only narrow what the
    policy chooses from. Returns the input unchanged when there are no worlds.
    """
    if not scored or not world_ids:
        return tuple(scored)
    worst = [
        max(regret(item, world_id=world_id, all_candidates=scored) for world_id in world_ids)
        for item in scored
    ]
    floor = min(worst)
    return tuple(item for item, value in zip(scored, worst, strict=True) if value <= floor)


def policy_pick(scored: Sequence[ScoredCandidate]) -> ScoredCandidate | None:
    """Apply :data:`POLICY_ORDER` and return the winner. ``None`` on an empty input.

    Exported so the planner's three-stage path (frontier, then regret, then
    policy) and :func:`select`'s two-stage path apply the *same* policy. Two
    implementations of one order is how the two prior stages shipped a check that
    tested something other than what it named.
    """
    if not scored:
        return None
    return min(scored, key=_policy_key)


def _policy_key(item: ScoredCandidate) -> tuple[Any, ...]:
    """§11's minimum-sufficiency order, lexicographic, with benefit as the tie-break.

    Benefit comes last on purpose. Everything ahead of it is a harm, and §11's
    claim is that the *smallest sufficient* action wins — sufficiency having
    already been enforced by the planner's benefit filter before selection runs.
    """
    return (
        *(item.objectives[objective] for objective in POLICY_ORDER),
        -item.objectives[Objective.WORST_WORLD_SECURITY_BENEFIT],
        -item.objectives[Objective.SECURITY_BENEFIT],
        item.candidate_id,
    )


def select(
    scored: Sequence[ScoredCandidate],
    *,
    selector: Selector,
    world_ids: Sequence[str],
) -> tuple[ScoredCandidate | None, tuple[RejectionRecord, ...]]:
    """Pick one candidate, and say what was dropped and why.

    ``PARETO_THEN_POLICY`` is §12's: remove dominated vectors, *then* apply a
    policy. The other two are its controls, and both are single-stage, so
    neither emits a ``DOMINATED`` rejection — a scalar sum never identifies a
    dominated action as such, which is the readable symptom of the thing §12
    objects to.
    """
    if not scored:
        return None, ()
    if selector is Selector.PARETO_THEN_POLICY:
        frontier = pareto_frontier(scored)
        on_frontier = {id(item) for item in frontier}
        rejections = tuple(
            RejectionRecord(
                candidate_id=item.candidate_id,
                reason="DOMINATED",
                detail="another candidate is at least as good on all nine objectives "
                "and strictly better on at least one",
            )
            for item in scored
            if id(item) not in on_frontier
        )
        return policy_pick(frontier), rejections
    if selector is Selector.MINIMAX_REGRET:
        return minimax_regret(scored, world_ids), ()
    return scalar_utility(scored, DEFAULT_WEIGHTS), ()
