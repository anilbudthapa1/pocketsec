"""D5.3 — AEGIS: the unprivileged decision layer, and the place ADR-0003 is enforced.

AEGIS decides *what to propose*. It cannot mint a capability token, it cannot
touch a :class:`HostAdapter`, and it cannot import the executor — asserted by AST
in ``tests/test_stage5_boundary.py`` and again here. Everything it produces is a
:class:`ResponsePlan`, which is data. Something else, holding privilege, decides
whether that data becomes an action, and SENTINEL can deny it regardless of
anything written here.

**The confidence-invariance property (G5.4), and the shape that makes it checkable.**

ADR-0003: no model output carries response authority. :meth:`AegisPlanner.plan`
reads ``resolution.verdict`` and per-hypothesis ``support``/``uncertainty`` for
exactly three things — ``world_applicability``, ``expected_security_delta`` and
the Action Shadow — all of which are *evidence about effect*, not authority. The
authority decision lives in :func:`_autonomy_refusal`, reached through
:meth:`AegisPlanner._authority_outcome`, and neither takes a resolution, a
candidate, a support value, a verdict or a benefit. A reviewer can read the two
signatures and see that confidence cannot enter.

Two design decisions that property forced, stated because a later reader would
otherwise "fix" them:

1. **The benefit floor is relative, not absolute** (:meth:`_sufficient`). An
   absolute 0.30 would make ACT-versus-ESCALATE a function of model confidence,
   which is the coupling ADR-0003 forbids.
2. **Rollback reliability gates autonomy, and an empty memory blocks it**
   (``None`` below ``MIN_SAMPLES_FOR_RATE``, G5.7). A fresh planner therefore
   cannot autonomously run an operator that needs a rollback. That is not a bug
   to work around; it is the check working.

**What this module refuses to do.** It refuses to return a plan it cannot justify
structurally: ``ResponsePlan.__post_init__`` raises on ACT with no chosen
candidate, on ACT above :data:`MAX_AUTONOMOUS_AUTHORITY`, and on ESCALATE or
DEFER with no :class:`HumanDecisionContract` — an escalation with no decision
structure is a notification, and §32 asked for the structure.

**A declared deviation, so nobody has to discover it.** This file is over the
repository's ~800-line guidance: 1164 lines, of which 764 are statements and 400 are
docstrings, comments and blanks (measured with ``ast``, not estimated). Splitting it would mean a fourth module under ``aegis/``, and spec §2.1
fixes this package's layout at three files and says "no package may create a module
not listed here". Every function is under ~60 lines including its docstring, which
is the half of that guidance that protects review.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields
from enum import StrEnum
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_finite_unit_interval,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage1.state.potential import phi
from pocketsec.stage4.stage5_interface import CBFResolutionV1
from pocketsec.stage5.aegis.cone import (
    AdaptationKind,
    AdaptationModel,
    InterventionCone,
    build_intervention_cone,
)
from pocketsec.stage5.aegis.human_contract import HumanDecisionContract, build_contract
from pocketsec.stage5.aegis.pareto import (
    REJECTION_REASONS,
    Objective,
    RejectionRecord,
    ScoredCandidate,
    Selector,
    minimal_regret_set,
    pareto_frontier,
    policy_pick,
    score,
    select,
    world_ids_of,
)
from pocketsec.stage5.aegis.shadow import (
    AutonomyEligibility,
    estimate_action_shadow,
    shadow_gate,
)
from pocketsec.stage5.authority.capability import (
    HUMAN_REQUIRED_AUTONOMY,
    Autonomy,
    autonomy_of,
    required_authority,
)
from pocketsec.stage5.cells.response_cells import ResponseCellField
from pocketsec.stage5.constitution.invariants import (
    MAX_AUTONOMOUS_AUTHORITY,
    AuthorityClass,
    ConstitutionDecision,
    ResponseConstitution,
    authority_rank,
)
from pocketsec.stage5.constitution.schema import InvariantViolation, MissionInvariantSet
from pocketsec.stage5.executor.lease import (
    ControlDecision,
    HysteresisController,
    Lease,
    requires_lease,
)
from pocketsec.stage5.governor import BudgetExhausted, PruneRecord, ResourceGovernor
from pocketsec.stage5.host.simulated import HostSnapshot
from pocketsec.stage5.memory.effectiveness import (
    AUTONOMOUS_ROLLBACK_THRESHOLD,
    EffectivenessMemory,
)
from pocketsec.stage5.operators.algebra import OperatorClass, OperatorSpec, Reversibility
from pocketsec.stage5.safe.action_field import (
    OBSERVE_CLASSES,
    ActionField,
    CandidateAction,
    FieldTruncation,
    HarmModel,
    IdentifiabilityOutcome,
    ResponseIdentifiability,
    RiskAcceptancePolicy,
    check_response_identifiability,
    generate_action_field,
)
from pocketsec.stage5.twin.response_twin import ResponseTwin, TwinPrediction

__all__ = [
    "ABLATION_FLAG_FIELDS",
    "DEFAULT_REQUIRED_RISK_REDUCTION",
    "REJECTION_REASONS",
    "UNMAPPED_PLANNER_FLAGS",
    "AegisPlanner",
    "PlanDecision",
    "PlannerConfig",
    "RejectionRecord",
    "ResponsePlan",
]

#: §11's minimum-sufficiency floor, read **relatively** (see the module
#: docstring). A chosen parameter, not a measured one.
DEFAULT_REQUIRED_RISK_REDUCTION: float = 0.30

#: The class at which an intervention needs a rollback operator and a lease. Equal
#: to ``executor.lease.LEASABLE_FROM_CLASS``; named here because the planner must
#: apply the same boundary when it refuses a candidate for NO_ROLLBACK, and a
#: second literal at a use site is a defect (§4.9).
FIRST_LEASED_CLASS: OperatorClass = OperatorClass.O2_REVERSIBLE_RESTRICT

#: Every ablation flag on :class:`PlannerConfig`, in declaration order. Built from
#: the dataclass rather than written out, so a flag added to the config cannot be
#: silently missing from the ablation key.
ABLATION_FLAG_FIELDS: tuple[str, ...] = ()  # filled after PlannerConfig is defined

#: The one :class:`PlannerConfig` flag that ``core_ids.ABLATION_FLAGS`` does not
#: name, pinned so a *second* unmapped flag fails the test rather than joining it.
#:
#: ``enable_multi_world`` has no SAFE-F* id of its own: SAFE-F04's ablation flag is
#: ``enable_twin``, and single-world planning is the **B7 baseline** (§7), which
#: the gate runs as a baseline arm rather than as a core-id ablation. It is a
#: config flag anyway, because §5's rule is that an ablation must be a flag the
#: gate sets and never a code edit — and B7 has to be reachable the same way.
UNMAPPED_PLANNER_FLAGS: frozenset[str] = frozenset({"enable_multi_world"})


class PlanDecision(StrEnum):
    """§3's outcomes. ``NO_ACTION`` is a first-class result, never an error path."""

    ACT = "ACT"
    OBSERVE = "OBSERVE"
    DEFER = "DEFER"
    ESCALATE = "ESCALATE"
    NO_ACTION = "NO_ACTION"
    ROLLBACK = "ROLLBACK"


@dataclass(frozen=True, slots=True)
class PlannerConfig:
    """Every optional mechanism's off switch, in one frozen object.

    An ablation must be a flag the gate sets, never a code edit nobody dares make
    (``stage4/core_ids.py``'s precedent). Ten of the eleven flags are
    ``core_ids.ABLATION_FLAGS`` values; ``enable_multi_world`` is the B7 baseline's
    switch, listed in :data:`UNMAPPED_PLANNER_FLAGS` with its reason.

    ``enable_residual`` (SAFE-F16) and ``enable_d3fend`` (SAFE-F23) are carried here so
    the gate can set every ablation through one object, and **nothing reads them** — not
    the planner and not any other subsystem. An earlier version of this docstring said
    "read by other subsystems"; that was false (finding R7), and G5.14 now reports both
    ids as inert (``gate_measured.unread_ablation_flags``) rather than as a measured 0.0. ``enable_pareto`` and
    ``selector`` must agree, or G5.14 would attribute a delta to the wrong
    mechanism, so ``__post_init__`` refuses both mismatches.
    """

    enable_multi_world: bool = True
    enable_twin: bool = True
    enable_cone: bool = True
    enable_shadow_gate: bool = True
    enable_regret: bool = True
    enable_pareto: bool = True
    enable_hysteresis: bool = True
    enable_effectiveness_memory: bool = True
    enable_response_cells: bool = True
    enable_residual: bool = True
    enable_d3fend: bool = True
    selector: Selector = Selector.PARETO_THEN_POLICY
    required_risk_reduction: float = DEFAULT_REQUIRED_RISK_REDUCTION

    def __post_init__(self) -> None:
        require_finite_unit_interval(
            self.required_risk_reduction, "PlannerConfig.required_risk_reduction"
        )
        object.__setattr__(self, "selector", Selector(self.selector))
        for name in ABLATION_FLAG_FIELDS:
            if not isinstance(getattr(self, name), bool):
                raise ContractError(f"PlannerConfig.{name} must be a bool")
        # An explicitly requested selector must not be silently overridden by the
        # pareto flag, and vice versa: G5.14 joins an ablation row to a flag, so a
        # configuration whose effective selector differs from its declared one
        # would attribute a measured delta to the wrong mechanism.
        if not self.enable_pareto and self.selector is Selector.PARETO_THEN_POLICY:
            raise ContractError(
                "PlannerConfig(enable_pareto=False) must name a non-Pareto selector; "
                "SCALAR_UTILITY is the B6 control and MINIMAX_REGRET is §26's"
            )
        if self.enable_pareto and self.selector is not Selector.PARETO_THEN_POLICY:
            raise ContractError(
                f"PlannerConfig(enable_pareto=True, selector={self.selector.value}) is "
                "ambiguous; set enable_pareto=False to run a single-stage selector"
            )

    def as_ablation_key(self) -> str:
        """A deterministic key G5.14 can join an ``AblationRow`` to.

        Total: every flag appears, so two configs differing in one flag produce two
        different keys and one config produces one key in every process.
        """
        flags = ",".join(
            f"{name[len('enable_'):]}={int(getattr(self, name))}" for name in ABLATION_FLAG_FIELDS
        )
        return f"aegis:{flags};selector={self.selector.value};rrr={self.required_risk_reduction:.3f}"

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {name: getattr(self, name) for name in ABLATION_FLAG_FIELDS}
        payload["selector"] = self.selector.value
        payload["required_risk_reduction"] = self.required_risk_reduction
        payload["config_key"] = self.as_ablation_key()
        return payload


ABLATION_FLAG_FIELDS = tuple(
    field.name for field in fields(PlannerConfig) if field.name.startswith("enable_")
)


@dataclass(frozen=True, slots=True)
class ResponsePlan:
    """The plan, as data. Unprivileged, and refused rather than fixed up if incoherent."""

    plan_id: str
    incident_id: str
    resolution_id: str
    decision: PlanDecision
    chosen: CandidateAction | None
    frontier: tuple[CandidateAction, ...]
    rejected: tuple[RejectionRecord, ...]
    human_contract: HumanDecisionContract | None
    selector: Selector
    config_key: str
    work_units: int
    truncations: tuple[FieldTruncation, ...]
    loadavg: tuple[float, float, float]

    def __post_init__(self) -> None:
        require_identifier(self.plan_id, "ResponsePlan.plan_id")
        require_identifier(self.incident_id, "ResponsePlan.incident_id")
        require_identifier(self.resolution_id, "ResponsePlan.resolution_id")
        object.__setattr__(self, "decision", PlanDecision(self.decision))
        object.__setattr__(self, "selector", Selector(self.selector))
        require_non_negative_int(self.work_units, "ResponsePlan.work_units")
        if len(self.loadavg) != 3:
            raise ContractError("ResponsePlan.loadavg must be three floats")
        if self.decision is PlanDecision.ACT:
            if self.chosen is None:
                raise ContractError(
                    "ResponsePlan(decision=ACT) with chosen=None is an instruction to do "
                    "nothing labelled as an instruction to act"
                )
            if authority_rank(self.chosen.authority) > authority_rank(MAX_AUTONOMOUS_AUTHORITY):
                raise ContractError(
                    f"ResponsePlan(decision=ACT) chose {self.chosen.candidate_id!r} at "
                    f"authority {self.chosen.authority.value}, above "
                    f"MAX_AUTONOMOUS_AUTHORITY={MAX_AUTONOMOUS_AUTHORITY.value}; autonomy "
                    "above the ceiling is not a planning choice"
                )
        if (
            self.decision in {PlanDecision.ESCALATE, PlanDecision.DEFER}
            and self.human_contract is None
        ):
            raise ContractError(
                f"ResponsePlan(decision={self.decision.value}) with human_contract=None is a "
                "notification, not an escalation; §32 asked for the decision structure"
            )
        for record in self.rejected:
            if record.reason not in REJECTION_REASONS:
                raise ContractError(f"ResponsePlan carries rejection reason {record.reason!r}")

    def rejections_by_reason(self) -> Mapping[str, int]:
        counts: dict[str, int] = {}
        for record in self.rejected:
            counts[record.reason] = counts.get(record.reason, 0) + 1
        return dict(sorted(counts.items()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "incident_id": self.incident_id,
            "resolution_id": self.resolution_id,
            "decision": self.decision.value,
            "chosen": self.chosen.to_dict() if self.chosen is not None else None,
            "frontier": [candidate.candidate_id for candidate in self.frontier],
            "rejected": [record.to_dict() for record in self.rejected],
            "human_contract": (
                self.human_contract.to_dict() if self.human_contract is not None else None
            ),
            "selector": self.selector.value,
            "config_key": self.config_key,
            "work_units": self.work_units,
            "truncations": [row.to_dict() for row in self.truncations],
            "loadavg": list(self.loadavg),
        }


@dataclass(frozen=True, slots=True)
class _AuthorityOutcome:
    """The result of the confidence-free authority computation.

    A separate type so :meth:`AegisPlanner._authority_outcome` can return several
    facts without its *inputs* growing: that parameter list is the construction
    behind G5.4, and widening it to carry one more output would destroy it.
    """

    required: AuthorityClass
    autonomy: Autonomy
    constitution_decision: ConstitutionDecision
    autonomous_eligible: bool
    reason: str
    approval_reason_hint: str


#: One candidate, its confidence-free authority outcome, and its nine-objective
#: score. A tuple alias rather than a fourth dataclass: it never leaves this module
#: and a named type would suggest it was part of the interface.
_Evaluated = tuple[CandidateAction, "_AuthorityOutcome", ScoredCandidate]


class AegisPlanner:
    """§35's unprivileged planner.

    It holds a governor, a memory, a cell field, a hysteresis controller, a
    constitution, a mission-invariant set and a harm model. It holds **no** token
    store, **no** journal and **no** host adapter, and the only host state it ever
    sees is a read-only :class:`HostSnapshot` handed to :meth:`plan`.
    """

    def __init__(
        self,
        *,
        config: PlannerConfig,
        constitution: ResponseConstitution,
        invariants: MissionInvariantSet,
        governor: ResourceGovernor,
        memory: EffectivenessMemory,
        cells: ResponseCellField,
        hysteresis: HysteresisController,
        harm: HarmModel,
    ) -> None:
        self._config = config
        self._constitution = constitution
        self._invariants = invariants
        self._governor = governor
        self._memory = memory
        self._cells = cells
        self._hysteresis = hysteresis
        self._harm = harm
        self._risk_policy = RiskAcceptancePolicy(
            accept_residual_below_support=config.required_risk_reduction
        )

    @property
    def config(self) -> PlannerConfig:
        return self._config

    # --- the authority half: no confidence may enter here --------------------

    def _authority_outcome(
        self,
        *,
        spec: OperatorSpec,
        rollback_reliability: float | None,
        eligibility: AutonomyEligibility,
        invariant_violations: tuple[InvariantViolation, ...],
    ) -> _AuthorityOutcome:
        """Decide what authority this operator needs and whether policy may grant it.

        **Read the parameter list.** No resolution, no verdict, no support, no
        uncertainty, no benefit — only the catalog spec, the measured rollback
        reliability, the shadow gate's verdict and the invariant check, which is
        exactly the set ADR-0003 permits to decide authority. Two resolutions
        differing only in confidence hand this method identical arguments.
        """
        required = required_authority(spec)
        verdict = self._constitution.permits(
            operator_class=spec.operator_class,
            authority=required,
            reversibility=spec.reversibility,
            has_rollback=spec.rollback_operator_id is not None,
            autonomous=True,
        )
        reason, hint = _autonomy_refusal(
            spec=spec,
            required=required,
            constitution_decision=verdict.decision,
            ceiling=self._constitution.max_autonomous_authority,
            rollback_reliability=rollback_reliability,
            eligibility=eligibility,
            invariant_violations=invariant_violations,
        )
        return _AuthorityOutcome(
            required=required,
            autonomy=autonomy_of(spec),
            constitution_decision=verdict.decision,
            autonomous_eligible=reason == "",
            reason=reason,
            approval_reason_hint=hint,
        )

    # --- the planning half --------------------------------------------------

    def plan(
        self,
        resolution: CBFResolutionV1,
        snapshot: HostSnapshot,
        *,
        now: int,
        active_leases: Sequence[Lease],
    ) -> ResponsePlan:
        """Turn a belief field plus a host snapshot into a proposal, or into NO_ACTION."""
        require_non_negative_int(now, "AegisPlanner.plan.now")
        twin = ResponseTwin(snapshot=snapshot, governor=self._governor)
        field = self._generate(resolution, snapshot, twin=twin)
        worlds = self._worlds(resolution)
        adaptations = _adaptation_model(snapshot)

        rejections: list[RejectionRecord] = []
        surviving: list[_Evaluated] = []
        harmful_worlds: set[str] = set()

        candidates, prune_records = self._prune(field.candidates)
        known = {candidate.candidate_id for candidate in field.candidates}
        rejections.extend(
            RejectionRecord(candidate_id=row.identifier, reason="BUDGET", detail=row.reason)
            for row in prune_records
            if row.identifier in known
        )

        for candidate in candidates:
            evaluated, refusal, harmful = self._evaluate(
                candidate,
                resolution=resolution,
                snapshot=snapshot,
                worlds=worlds,
                twin=twin,
                adaptations=adaptations,
            )
            harmful_worlds.update(harmful)
            if refusal is not None:
                rejections.append(refusal)
                continue
            surviving.append(evaluated)

        return self._decide(
            resolution=resolution,
            snapshot=snapshot,
            field=field,
            worlds=worlds,
            surviving=surviving,
            rejections=rejections,
            harmful_worlds=frozenset(harmful_worlds),
            now=now,
            active_leases=active_leases,
        )

    # --- the pieces plan() is assembled from --------------------------------

    def _evaluate(
        self,
        candidate: CandidateAction,
        *,
        resolution: CBFResolutionV1,
        snapshot: HostSnapshot,
        worlds: Sequence[str],
        twin: ResponseTwin,
        adaptations: AdaptationModel,
    ) -> tuple[_Evaluated, RejectionRecord | None, frozenset[str]]:
        """Score one candidate and decide whether it survives to selection.

        Returns the evaluation, the refusal that removed it (or ``None``) and the
        worlds where it would do unacceptable harm. The two refusals here —
        identifiability and the mission invariants — make an action *inadmissible*
        rather than merely *not autonomous*, so they also set
        ``caller_inadmissible`` and keep it out of §26's hindsight benchmark.
        """
        cones = self._cones(candidate, worlds=worlds, twin=twin, adaptations=adaptations)
        shadow = self._shadow(candidate, cones=cones, resolution=resolution, twin=twin)
        eligibility = (
            shadow_gate(shadow, spec=candidate.operator.spec)
            if self._config.enable_shadow_gate
            else AutonomyEligibility.ELIGIBLE
        )
        identifiability = check_response_identifiability(
            candidate, resolution, truth=self._harm, policy=self._risk_policy
        )
        violations = self._invariants.violations(
            operator=candidate.operator,
            lease_ttl_seconds=candidate.lease_ttl_seconds,
            snapshot=snapshot,
        )
        not_identifiable = identifiability.outcome is IdentifiabilityOutcome.NOT_IDENTIFIABLE
        outcome = self._authority_outcome(
            spec=candidate.operator.spec,
            rollback_reliability=self._rollback_reliability(candidate, resolution),
            eligibility=eligibility,
            invariant_violations=violations,
        )
        scored = score(
            candidate,
            cones=cones,
            resolution=resolution,
            caller_inadmissible=not_identifiable or bool(violations),
        )
        return (
            (candidate, outcome, scored),
            _inadmissibility(candidate, identifiability, violations),
            frozenset(identifiability.harmful_worlds),
        )

    def _generate(
        self, resolution: CBFResolutionV1, snapshot: HostSnapshot, *, twin: ResponseTwin
    ) -> ActionField:
        """Generate the bounded candidate field, honouring the two memory ablations.

        Both ablations hand the generator **empty** instances rather than the live
        ones. Two honest notes, because the alternative is a reported delta nobody
        can interpret: ``generate_action_field`` currently declines to consult the
        cell field at all (it emits a truncation saying the key spaces are not
        shared), so the SAFE-F21/F22 delta through this flag is expected to be
        **0.0** and 0.0 is the result to report; and turning the memory off also
        forces :meth:`_rollback_reliability` to ``None``, which *blocks* autonomy —
        an ablation must never be a way to gain authority.
        """
        return generate_action_field(
            resolution,
            snapshot,
            constitution=self._constitution,
            invariants=self._invariants,
            governor=self._governor,
            memory=self._memory if self._config.enable_effectiveness_memory
            else EffectivenessMemory(),
            cells=self._cells if self._config.enable_response_cells else ResponseCellField(),
            twin=twin,
        )

    def _worlds(self, resolution: CBFResolutionV1) -> tuple[str, ...]:
        """The world key space, or just the leading world under the B7 ablation.

        ``enable_multi_world=False`` keeps the single highest-support hypothesis —
        §7's B7 control, "act on the most likely explanation only". Ties break on
        the mechanism id so the control is deterministic.
        """
        worlds = world_ids_of(resolution)
        if self._config.enable_multi_world or not worlds:
            return worlds
        supports = {
            str(row.get("mechanism_id", "")): float(row.get("support", 0.0))
            for row in resolution.hypotheses
        }
        return (max(worlds, key=lambda world: (supports.get(world, 0.0), world)),)

    def _prune(
        self, candidates: Sequence[CandidateAction]
    ) -> tuple[tuple[CandidateAction, ...], tuple[PruneRecord, ...]]:
        """Bound the field, and let the governor decide what goes.

        The generator has already charged ``CANDIDATE_GENERATION``, so this does not
        charge it again: G5.14 compares work units across arms, and a double charge
        would measure the call graph rather than the work.
        """
        kept, records = self._governor.prune(candidates)
        return tuple(item for item in kept if isinstance(item, CandidateAction)), records

    def _cones(
        self,
        candidate: CandidateAction,
        *,
        worlds: Sequence[str],
        twin: ResponseTwin,
        adaptations: AdaptationModel,
    ) -> Mapping[str, InterventionCone]:
        """Build one cone per world, or none at all under the SAFE-F05 ablation.

        The cone keys are :func:`world_ids_of`'s strings — the same key space
        ``candidate.world_applicability`` and ``per_world_loss`` use (§4.9 Rule A).
        """
        if not (self._config.enable_cone and self._config.enable_twin):
            return {}
        cones: dict[str, InterventionCone] = {}
        for world_id in worlds:
            try:
                cones[world_id] = build_intervention_cone(
                    candidate,
                    world_id=world_id,
                    twin=twin,
                    adaptations=adaptations,
                    governor=self._governor,
                )
            except BudgetExhausted:
                break
        return cones

    def _shadow(
        self,
        candidate: CandidateAction,
        *,
        cones: Mapping[str, InterventionCone],
        resolution: CBFResolutionV1,
        twin: ResponseTwin,
    ) -> Any:
        """The Action Shadow used for gating, cone-informed where a cone exists.

        Falls back to the candidate's generation-time shadow when the twin or cone is
        ablated. That fallback can only be *lower*, so the gate under ablation is the
        more permissive of the two — which is why
        ``test_ablating_the_cone_does_not_lower_a_harm_score`` pins the scoring side,
        where the maximum is taken instead.
        """
        if not cones:
            return candidate.shadow
        world_id = next(iter(cones))
        try:
            prediction: TwinPrediction = twin.predict(candidate, world_id=world_id)
        except BudgetExhausted:
            return candidate.shadow
        return estimate_action_shadow(
            candidate.candidate_id,
            prediction=prediction,
            cone=cones[world_id],
            snapshot=_snapshot_of(twin),
            resolution=resolution,
        )

    def _rollback_reliability(
        self, candidate: CandidateAction, resolution: CBFResolutionV1
    ) -> float | None:
        """The measured rollback reliability for this operator in this epoch, or ``None``.

        ``None`` when the memory is ablated: the ablation reports "no evidence",
        never "no constraint".
        """
        if not self._config.enable_effectiveness_memory:
            return None
        return self._memory.rollback_reliability(
            operator_id=candidate.operator.spec.operator_id, epoch_id=resolution.epoch_id
        )

    def _control(
        self,
        *,
        candidate: CandidateAction | None,
        snapshot: HostSnapshot,
        now: int,
        active_leases: Sequence[Lease],
    ) -> tuple[ControlDecision, Lease | None]:
        """The hysteresis controller's verdict for the focus target.

        ``enable_hysteresis=False`` is §7's B8 control: it returns ``ACT`` without
        consulting the controller at all, so the ablation removes the mechanism
        rather than reconfiguring it.
        """
        digest = (
            candidate.operator.target.identity.digest()
            if candidate is not None
            else (active_leases[0].target_digest if active_leases else "")
        )
        lease = next(
            (item for item in active_leases if item.target_digest == digest and digest), None
        )
        if not self._config.enable_hysteresis or not digest:
            return ControlDecision.ACT, lease
        return (
            self._hysteresis.decide(
                target_digest=digest,
                phi_total=phi(snapshot.security_state).total,
                now=now,
                active_lease=lease,
            ),
            lease,
        )

    def _partition(
        self, surviving: Sequence[_Evaluated], rejections: list[RejectionRecord]
    ) -> tuple[list[_Evaluated], list[_Evaluated], list[_Evaluated]]:
        """Split the survivors into the autonomous, the human and the observational.

        **Observation and intervention are never put on one frontier.** An
        observation dominates every intervention on every harm axis, so a single pool
        would make ``policy_pick`` choose an observation every time and ``ACT`` would
        be structurally unreachable — §7's act-never bound reached by accident rather
        than by measurement.

        Every candidate that needs a human is recorded as a rejection here, so a plan
        always carries the reason each intervention was not taken autonomously.
        """
        interventions = [
            row for row in surviving if row[0].operator.spec.operator_class >= FIRST_LEASED_CLASS
        ]
        sufficient = self._sufficient(interventions, rejections)
        autonomous = [row for row in sufficient if row[1].autonomous_eligible]
        human = [row for row in sufficient if not row[1].autonomous_eligible]
        observational = [
            row
            for row in surviving
            if row[0].operator.spec.operator_class in OBSERVE_CLASSES
            and row[1].autonomous_eligible
        ]
        rejections.extend(
            RejectionRecord(
                candidate_id=candidate.candidate_id,
                reason=outcome.reason or "AUTHORITY",
                detail=f"{outcome.approval_reason_hint} "
                f"(required={outcome.required.value}, autonomy={outcome.autonomy.value})",
            )
            for candidate, outcome, _ in human
        )
        return autonomous, human, observational

    def _decide(
        self,
        *,
        resolution: CBFResolutionV1,
        snapshot: HostSnapshot,
        field: ActionField,
        worlds: Sequence[str],
        surviving: Sequence[_Evaluated],
        rejections: list[RejectionRecord],
        harmful_worlds: frozenset[str],
        now: int,
        active_leases: Sequence[Lease],
    ) -> ResponsePlan:
        """Partition, select, apply the controller, and assemble the plan."""
        autonomous, human, observational = self._partition(surviving, rejections)
        chosen, frontier, select_rejections = self._select(
            autonomous or human or observational, worlds
        )
        rejections.extend(select_rejections)
        control, lease = self._control(
            candidate=chosen, snapshot=snapshot, now=now, active_leases=active_leases
        )
        control = self._budget_override(control, chosen, rejections)
        decision, proposal = self._decision(
            control=control,
            lease=lease,
            chosen=chosen,
            autonomous=autonomous,
            human=human,
            observational=observational,
            rejections=rejections,
        )
        contract = self._contract(
            decision=decision,
            proposal=proposal,
            field=field,
            resolution=resolution,
            snapshot=snapshot,
            surviving=surviving,
            harmful_worlds=harmful_worlds,
        )
        return ResponsePlan(
            plan_id=f"plan.{resolution.resolution_id}.{self._config.selector.value}",
            incident_id=resolution.incident_id,
            resolution_id=resolution.resolution_id,
            decision=decision,
            chosen=proposal,
            frontier=frontier,
            rejected=tuple(rejections),
            human_contract=contract,
            selector=self._config.selector,
            config_key=self._config.as_ablation_key(),
            work_units=int(self._governor.spend_report().get("TOTAL", 0)),
            truncations=field.truncations,
            loadavg=_loadavg(),
        )

    def _budget_override(
        self,
        control: ControlDecision,
        chosen: CandidateAction | None,
        rejections: list[RejectionRecord],
    ) -> ControlDecision:
        """An exhausted budget escalates; it never widens a cap (D5.23).

        Recorded against the chosen candidate so the rejection is attributable rather
        than a bare counter. ``"NO-ACTION"`` stands in when nothing was chosen,
        because a ``RejectionRecord`` needs an identifier and inventing a candidate
        id would be worse than a reserved one.
        """
        exhausted = self._governor.escalation()
        if exhausted is None:
            return control
        rejections.append(
            RejectionRecord(
                candidate_id=chosen.candidate_id if chosen is not None else "NO-ACTION",
                reason="BUDGET",
                detail=exhausted,
            )
        )
        return ControlDecision.ESCALATE

    def _sufficient(
        self,
        surviving: Sequence[_Evaluated],
        rejections: list[RejectionRecord],
    ) -> list[_Evaluated]:
        """Drop interventions that buy too little of the risk reduction on offer.

        ``floor = required_risk_reduction * max(benefit over this same population)``,
        with ``required_risk_reduction < 1``, so **the argmax always survives**. The
        intervention pool is therefore non-empty whenever any intervention survived
        the authority, reliability, shadow, invariant and identifiability gates —
        all of which are confidence-free. That is how G5.4 holds by construction
        rather than by luck: no benefit value can change ACT versus ESCALATE versus
        OBSERVE. An absolute floor would lose exactly that (at support 0.01 nothing
        clears 0.30 and the plan changes, which is confidence deciding authority).

        What the floor still does is §11's job: among the legal interventions it
        refuses the ones buying a small fraction of what the best one buys, so the
        selector cannot pick a barely-effective action merely for being cheapest.
        """
        if not surviving:
            return []
        best = max(row[2].objectives[Objective.SECURITY_BENEFIT] for row in surviving)
        floor = best * self._config.required_risk_reduction
        kept: list[_Evaluated] = []
        for candidate, outcome, scored in surviving:
            if scored.objectives[Objective.SECURITY_BENEFIT] >= floor:
                kept.append((candidate, outcome, scored))
                continue
            rejections.append(
                RejectionRecord(
                    candidate_id=candidate.candidate_id,
                    reason="INSUFFICIENT_BENEFIT",
                    detail=f"security benefit below {self._config.required_risk_reduction:.2f} "
                    f"of the {best:.4f} best available in this field",
                )
            )
        return kept

    def _select(
        self,
        pool: Sequence[_Evaluated],
        worlds: Sequence[str],
    ) -> tuple[
        CandidateAction | None, tuple[CandidateAction, ...], tuple[RejectionRecord, ...]
    ]:
        """Run the configured selector and report what it dropped.

        Three stages on the ``PARETO_THEN_POLICY`` path — frontier, §26's regret,
        then ``POLICY_ORDER`` — composed here rather than inside :func:`select` so
        ``enable_regret`` is a flag rather than a second selector. At
        ``enable_regret=False`` the composition is exactly what :func:`select` does.
        """
        if not pool:
            return None, (), ()
        scored = [row[2] for row in pool]
        if self._config.selector is not Selector.PARETO_THEN_POLICY:
            selected, rejections = select(
                scored, selector=self._config.selector, world_ids=worlds
            )
            chosen = selected.candidate if selected is not None else None
            return chosen, tuple(row[0] for row in pool), rejections
        frontier_scored = pareto_frontier(scored)
        on_frontier = {id(item) for item in frontier_scored}
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
        narrowed = (
            minimal_regret_set(frontier_scored, worlds)
            if self._config.enable_regret
            else frontier_scored
        )
        selected = policy_pick(narrowed)
        frontier = tuple(
            row[0]
            for row in pool
            if any(item.candidate_id == row[0].candidate_id for item in frontier_scored)
        )
        chosen = selected.candidate if selected is not None else None
        return chosen, frontier, rejections

    def _decision(
        self,
        *,
        control: ControlDecision,
        lease: Lease | None,
        chosen: CandidateAction | None,
        autonomous: Sequence[_Evaluated],
        human: Sequence[_Evaluated],
        observational: Sequence[_Evaluated],
        rejections: list[RejectionRecord],
    ) -> tuple[PlanDecision, CandidateAction | None]:
        """Name the decision. The order of these clauses *is* the policy.

        One rule worth stating because it looks like an oversight: **the hysteresis
        controller does not gate observation.** ``HOLD`` defers an intervention, never
        a read — a cooldown that could suppress observation would blind the system
        during the window it was cooling down from, which §2's
        ``FAILURE_MUST_NOT_STOP_MONITORING`` forbids.
        """
        intervening = chosen is not None and any(
            row[0].candidate_id == chosen.candidate_id for row in autonomous
        )
        if control is ControlDecision.ESCALATE:
            proposal = chosen or (human[0][0] if human else None)
            if proposal is not None:
                return PlanDecision.ESCALATE, proposal
        if control is ControlDecision.RELEASE and intervening:
            if lease is not None:
                return PlanDecision.ROLLBACK, chosen
            # RELEASE means the trajectory fell below the exit threshold. With no
            # lease to release there is nothing to roll back, and acting anyway
            # would be the oscillation §19 exists to stop — so the intervention is
            # dropped and the plan falls through to observation.
            intervening = False
        if intervening and chosen is not None:
            if control is ControlDecision.HOLD:
                rejections.append(
                    RejectionRecord(
                        candidate_id=chosen.candidate_id,
                        reason="HYSTERESIS",
                        detail="controller HOLD: dwell or cooldown not satisfied",
                    )
                )
                return PlanDecision.DEFER, chosen
            return PlanDecision.ACT, chosen
        if chosen is not None and any(
            row[0].candidate_id == chosen.candidate_id for row in human
        ):
            return PlanDecision.ESCALATE, chosen
        if human:
            return PlanDecision.ESCALATE, human[0][0]
        if chosen is not None and any(
            row[0].candidate_id == chosen.candidate_id for row in observational
        ):
            return PlanDecision.OBSERVE, chosen
        return PlanDecision.NO_ACTION, None

    def _contract(
        self,
        *,
        decision: PlanDecision,
        proposal: CandidateAction | None,
        field: ActionField,
        resolution: CBFResolutionV1,
        snapshot: HostSnapshot,
        surviving: Sequence[_Evaluated],
        harmful_worlds: frozenset[str],
    ) -> HumanDecisionContract | None:
        """Build the §32 structure for the decisions that need one.

        ESCALATE, DEFER and NO_ACTION. NO_ACTION is deliberate: "the system declined
        to act on your incident" is the case a human most needs the structure for,
        and ``ResponsePlan`` does not require it there, so it is a choice.
        """
        if decision not in {PlanDecision.ESCALATE, PlanDecision.DEFER, PlanDecision.NO_ACTION}:
            return None
        if not field.candidates:
            return None
        hint = next(
            (
                outcome.approval_reason_hint
                for candidate, outcome, _ in surviving
                if proposal is not None and candidate.candidate_id == proposal.candidate_id
            ),
            "",
        )
        eligibility = (
            AutonomyEligibility.ELIGIBLE
            if hint != "ACTION_SHADOW_ABOVE_CEILING"
            else AutonomyEligibility.HUMAN_REQUIRED
        )
        return build_contract(
            field.candidates,
            proposal,
            resolution=resolution,
            constitution=self._constitution,
            shadow_eligibility=eligibility,
            harmful_worlds=harmful_worlds,
            collateral_units=_collateral_units(proposal, snapshot),
            preserved_signals=_observable_signals(proposal, snapshot),
            reliability_unknown=hint == "ROLLBACK_RELIABILITY_UNKNOWN",
            mission_invariant_at_risk=hint == "MISSION_INVARIANT_AT_RISK",
        )


# --- module-level helpers, all pure -----------------------------------------


def _inadmissibility(
    candidate: CandidateAction,
    identifiability: ResponseIdentifiability,
    violations: tuple[InvariantViolation, ...],
) -> RejectionRecord | None:
    """The refusal that makes a candidate inadmissible, or ``None``.

    Identifiability first: "this action harms a world we cannot rule out" is a
    stronger statement than "it would breach a mission invariant", and a human
    shown only the second would not learn the first.
    """
    if identifiability.outcome is IdentifiabilityOutcome.NOT_IDENTIFIABLE:
        return RejectionRecord(
            candidate_id=candidate.candidate_id,
            reason="NOT_IDENTIFIABLE",
            detail=identifiability.detail,
        )
    if violations:
        return RejectionRecord(
            candidate_id=candidate.candidate_id,
            reason="MISSION_INVARIANT",
            detail="; ".join(f"{v.invariant_id}:{v.kind.value}" for v in violations),
        )
    return None


def _autonomy_refusal(
    *,
    spec: OperatorSpec,
    required: AuthorityClass,
    constitution_decision: ConstitutionDecision,
    ceiling: AuthorityClass,
    rollback_reliability: float | None,
    eligibility: AutonomyEligibility,
    invariant_violations: tuple[InvariantViolation, ...],
) -> tuple[str, str]:
    """The first reason autonomy is refused, and its approval hint. ``("", "")`` if none.

    A module-level pure function, not a method: it closes over nothing, so no instance
    attribute can carry a resolution, a score or a confidence into it. The order is by
    severity, because the caller shows a human the *binding* reason.
    """
    if invariant_violations:
        return "MISSION_INVARIANT", "MISSION_INVARIANT_AT_RISK"
    if constitution_decision is not ConstitutionDecision.PERMITTED or authority_rank(
        required
    ) > authority_rank(ceiling):
        return "AUTHORITY", "AUTHORITY_ABOVE_AUTONOMOUS_CEILING"
    if autonomy_of(spec) in HUMAN_REQUIRED_AUTONOMY:
        return "AUTHORITY", "HUMAN_GRANT_REQUIRED"
    if eligibility is not AutonomyEligibility.ELIGIBLE:
        return "SHADOW", "ACTION_SHADOW_ABOVE_CEILING"
    if spec.reversibility is Reversibility.IRREVERSIBLE or (
        requires_lease(spec) and spec.rollback_operator_id is None
    ):
        return "NO_ROLLBACK", "IRREVERSIBLE_WITHOUT_ROLLBACK"
    if requires_lease(spec) and (
        rollback_reliability is None or rollback_reliability < AUTONOMOUS_ROLLBACK_THRESHOLD
    ):
        # ``None`` blocks: fewer than MIN_SAMPLES_FOR_RATE observed rollbacks is not
        # evidence of reliability, and G5.7 reads a None as a failure, not a pass.
        return "RELIABILITY", "ROLLBACK_RELIABILITY_UNKNOWN"
    return "", ""


def _snapshot_of(twin: ResponseTwin) -> HostSnapshot:
    """The snapshot a twin was built from.

    It reads a private attribute of a sibling module's class, which is ugly; the
    alternative, threading the snapshot through five more frames, was uglier.
    """
    snapshot = getattr(twin, "_snapshot", None)
    if not isinstance(snapshot, HostSnapshot):
        raise ContractError("ResponseTwin does not expose the snapshot it projects")
    return snapshot


def _adaptation_model(snapshot: HostSnapshot) -> AdaptationModel:
    """§25's adaptation model, derived from what the snapshot actually shows.

    "ONLY observed/learned adaptations; no unrestricted game-theoretic search."
    Each kind appears only when the host holds the structure that makes it possible,
    and the count is how many places it is possible — so an adaptation the host
    cannot perform is absent, never assigned a made-up probability.
    """
    counts: dict[AdaptationKind, int] = {}
    children = sum(len(row.children) for row in snapshot.processes)
    if children:
        counts[AdaptationKind.PROCESS_REPLACEMENT] = children
    sockets = sum(len(row.socket_ids) for row in snapshot.processes)
    if sockets > 1:
        counts[AdaptationKind.ALTERNATE_DESTINATION] = sockets
    restartable = sum(1 for row in snapshot.services if row.restartable)
    if restartable:
        counts[AdaptationKind.PERSISTENCE_RESTART] = restartable
    if len(snapshot.sessions) > 1:
        counts[AdaptationKind.SESSION_MIGRATION] = len(snapshot.sessions)
    return AdaptationModel(observed=frozenset(counts), observation_counts=counts)


def _collateral_units(
    candidate: CandidateAction | None, snapshot: HostSnapshot
) -> tuple[str, ...]:
    """The units a proposal could plausibly disturb: the target's unit and its dependents."""
    if candidate is None:
        return ()
    target = candidate.operator.target
    unit = None
    row = snapshot.process(target.identity.pid)
    if row is not None:
        unit = row.unit
    if unit is None and target.scope.subject in {
        service.unit for service in snapshot.services
    }:
        unit = target.scope.subject
    if unit is None:
        return ()
    dependents = sorted(
        service.unit for service in snapshot.services if unit in service.depends_on
    )
    return tuple([unit, *dependents])


def _observable_signals(
    candidate: CandidateAction | None, snapshot: HostSnapshot
) -> tuple[str, ...]:
    if candidate is None:
        return ()
    row = snapshot.process(candidate.operator.target.identity.pid)
    return row.volatile_signals if row is not None else ()


def _loadavg() -> tuple[float, float, float]:
    """The host's load, carried on every plan.

    Not decoration: this repository measured the same two code paths 7x apart at load
    8-12 versus 23-67, so a work-unit count is comparable only when the load is on
    the record beside it (§2.8).
    """
    try:
        with open("/proc/loadavg", encoding="ascii") as handle:
            parts = handle.read().split()
        return (float(parts[0]), float(parts[1]), float(parts[2]))
    except (OSError, IndexError, ValueError):  # pragma: no cover - non-Linux hosts
        return (0.0, 0.0, 0.0)
