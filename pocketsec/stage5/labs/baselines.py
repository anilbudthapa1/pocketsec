"""D5.19 — the nine baselines Stage 5 must beat, and the arm it is compared as.

§7's table is the comparison, not a formality. Every arm here runs through the
**real** :class:`AegisPlanner` or a deliberately dumber chooser, the **real**
:class:`SentinelKernel`, the **real** transactional executor and the **same**
:class:`SimulatedHost`, in one process and one run. A baseline that bypassed the
kernel would measure a different system and flatter the mechanism, and that is not
hypothetical: ``planning/MEMORY.md`` records a Stage 2 baseline that scored 0.55
broken and 0.94 once fixed, and the broken figure had already been quoted.

**The arms differ only in which candidate they choose and whether they lease.**
Every arm calls the same :func:`build_rig`, sees the same
:func:`generate_action_field` output on a freshly respawned host, and is handed the
same executor factory. A :class:`Policy` returns a :class:`Choice`; nothing else
varies. Four of the ten arms are the real planner under four ``PlannerConfig`` flag
sets — which is what makes B6, B7 and B8 controls for a *mechanism* rather than for a
different program.

**This module cannot build a privileged executor, deliberately.** Trust rule T4
(spec §5.1, enforced by ``tests/test_stage5_boundary.py``) permits the name
``TransactionalExecutor`` only under ``executor/`` and ``recovery/``, so the harness
takes an :data:`ExecutorFactory` from its caller. A lab that could assemble its own
executor could quietly wire a permissive kernel into one, and a baseline that "passed"
would then prove nothing.

That is also why the nine baselines are :data:`Policy` functions — ``rig -> Choice`` —
rather than the spec's ``fn(cases) -> BaselineOutcome``. An outcome needs an execution,
an execution needs an executor, and this module may not construct one; the uniform
signature the spec asks for is kept, one level down, and :func:`run_arm` turns any
policy into an outcome given a factory. The same rule binds ``gate.py``, which sits
outside ``executor/`` too — so the integrator needs a factory exported from
``executor/`` (any name but the class's) or must receive one from its caller.

**There is no reinforcement-learning arm**, and the omission is recorded rather than
left for a reader to notice. ADR-0040 forbids numpy in Stage 5 permanently — a
research package in the privileged stage is a supply-chain path into the executor —
and a hand-rolled stdlib policy-gradient learner would be a *worse* comparison than
none, because a broken baseline flatters whatever it is compared against.
:data:`UNBUILT_BASELINES` carries it UNMEASURED with that reason.

**One arm reads ground truth, and only one.** B9 is §7's scripted analyst, defined as
the reviewer who always picks correctly, so it reads ``case.truth`` to do its job and
is therefore the upper bound on correctness and the lower bound on autonomy. No
autonomous arm reads ``truth``, and ``HarmModel`` — which the planner *does* read — is
a pure function of the mechanism ids and is byte-identical for both members of an
ambiguous pair.

**Every number this module produces is a property of a simulator this wave wrote.**
Rollback figures are named ``simulated_rollback_*`` so the caveat travels into every
table that quotes them; against a real host they are UNMEASURED (ADR-0046).
"""

from __future__ import annotations

import secrets
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Protocol

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.state.potential import phi
from pocketsec.stage1.state.security_state import DIMENSIONS, SecurityStateV1, StateDelta
from pocketsec.stage4.stage5_interface import CBFResolutionV1
from pocketsec.stage5.aegis.pareto import Selector
from pocketsec.stage5.aegis.planner import (
    ABLATION_FLAG_FIELDS,
    AegisPlanner,
    PlanDecision,
    PlannerConfig,
    ResponsePlan,
)
from pocketsec.stage5.authority.capability import (
    AuthorityGrant,
    GrantSource,
    required_authority,
)
from pocketsec.stage5.authority.tokens import (
    MAX_TOKEN_LIFETIME_SECONDS,
    CapabilityToken,
    TokenStore,
)
from pocketsec.stage5.cells.response_cells import ResponseCellField
from pocketsec.stage5.constitution.invariants import (
    FROZEN_CONSTITUTION,
    MAX_AUTONOMOUS_AUTHORITY,
    authority_rank,
)
from pocketsec.stage5.evidence.preservation_gate import DEFAULT_RETENTION, EvidencePreservationGate
from pocketsec.stage5.executor.identity import ManualClock
from pocketsec.stage5.executor.journal import RollbackJournal
from pocketsec.stage5.executor.lease import (
    DEFAULT_HYSTERESIS,
    RESTORATION_OPERATOR_IDS,
    HysteresisController,
    LeaseRegistry,
    LeaseSweeper,
)
from pocketsec.stage5.executor.transactional import Outcome, TransactionReceipt
from pocketsec.stage5.executor.verify import PostconditionProbe
from pocketsec.stage5.governor import ResourceGovernor
from pocketsec.stage5.host.simulated import HostSnapshot, SimulatedHost
from pocketsec.stage5.labs.response_corpus import ResponseCase
from pocketsec.stage5.memory.effectiveness import EffectivenessMemory
from pocketsec.stage5.operators.algebra import DefensiveOperator, EvidenceEffect, OperatorClass
from pocketsec.stage5.operators.d3fend import mapping_for
from pocketsec.stage5.safe.action_field import ActionField, CandidateAction, generate_action_field
from pocketsec.stage5.sentinel.kernel import Decision, SentinelKernel
from pocketsec.stage5.twin.response_twin import ResponseTwin

__all__ = [
    "B6_FLAGS",
    "B7_FLAGS",
    "B8_FLAGS",
    "BASELINES",
    "DEGENERATE_CONTROL_IDS",
    "MAX_OPERATOR_DURATION_SECONDS",
    "PLAYBOOK_PHI_THRESHOLD",
    "PRIVILEGE_BIT",
    "REFERENCE_ARM_ID",
    "REFERENCE_FLAGS",
    "SIMPLE_RULE_TABLE",
    "UNBUILT_BASELINES",
    "BaselineOutcome",
    "BaselineRig",
    "Choice",
    "ExecutorFactory",
    "ExecutorLike",
    "Policy",
    "UnbuiltBaseline",
    "always_isolate",
    "build_rig",
    "d3fend_lookup_only",
    "fixed_playbook",
    "human_only",
    "no_automated_response",
    "no_hysteresis",
    "pareto_frontier_of",
    "primary_metric_value",
    "reference_arm",
    "reference_policy",
    "run_arm",
    "run_baselines",
    "simple_if_then_containment",
    "single_scalar_utility",
    "single_world_planner",
]

#: The catalog's own ceiling, and the largest lease a candidate can ask for.
MAX_OPERATOR_DURATION_SECONDS: int = MAX_TOKEN_LIFETIME_SECONDS

#: B2's threshold, a **chosen** parameter. It sits between Stage 1's measured benign
#: Phi mean of 0.62 and malicious 9.46 (``planning/MEMORY.md``); that makes it
#: defensible, not fitted, and calling it fitted would be a fabricated result.
PLAYBOOK_PHI_THRESHOLD: float = 6.0

#: Bit 0 of ``StateDelta.bitmask()``: ``DIMENSIONS`` is insertion-ordered and
#: ``privilege`` is first. Read from ``DIMENSIONS`` rather than written as ``1``, so
#: reordering the SSIR field breaks the import instead of the meaning.
PRIVILEGE_BIT: int = 1 << list(DIMENSIONS).index("privilege")

#: B3's whole intelligence: one rule per mechanism id, read from a dict, ignoring the
#: host snapshot, the uncertainty and the mission invariants. B3 is B2 plus a mechanism
#: vocabulary and nothing else.
SIMPLE_RULE_TABLE: Mapping[str, str] = MappingProxyType(
    {
        "admin_maintenance_window": "SUSPEND_PROCESS",
        "credential_theft_chain": "SUSPEND_PROCESS",
        "service_reconfiguration": "RESTRICT_LOCAL_SOCKET",
        "persistence_install": "SUSPEND_PROCESS",
    }
)

#: The degenerate bounds of the frontier. If either ties the best at the best
#: containment, the split cannot show that any mechanism helps (MEMORY.md trap 9).
DEGENERATE_CONTROL_IDS: frozenset[str] = frozenset({"B1", "B4"})

#: The full planner, named for what it is. It is one of the ten arms, not the referee.
REFERENCE_ARM_ID: str = "AEGIS"

#: Every ``PlannerConfig`` ablation flag on. :func:`reference_policy` flips one at a
#: time; a mechanism with no off switch cannot be ablated, which is why
#: ``core_ids.ABLATION_FLAGS`` exists at all.
REFERENCE_FLAGS: Mapping[str, bool] = MappingProxyType(dict.fromkeys(ABLATION_FLAG_FIELDS, True))

#: B6 — scalarise instead of taking the frontier. ``PlannerConfig`` refuses a config
#: whose ``enable_pareto`` and ``selector`` disagree, so both move together here.
B6_FLAGS: Mapping[str, bool] = MappingProxyType({"enable_pareto": False})

#: B7 — the lead's mandated single-world control: highest-support hypothesis only, no
#: twin, no cone, no per-world regret. ``enable_multi_world`` exists in
#: ``PlannerConfig`` precisely as this baseline's switch.
B7_FLAGS: Mapping[str, bool] = MappingProxyType(
    {
        "enable_multi_world": False,
        "enable_twin": False,
        "enable_cone": False,
        "enable_regret": False,
    }
)

#: B8 — immediate action: no dwell, no cooldown, no lease sweep.
B8_FLAGS: Mapping[str, bool] = MappingProxyType({"enable_hysteresis": False})

_POLICY_VERSION = FROZEN_CONSTITUTION.policy_version


@dataclass(frozen=True, slots=True)
class UnbuiltBaseline:
    """A §40 baseline this wave did **not** build, with the reason. Never omitted.

    An absent baseline nobody wrote down becomes, three documents later, a baseline
    somebody assumes was beaten.
    """

    baseline_id: str
    name: str
    why_not: str

    def __post_init__(self) -> None:
        if not self.why_not.strip():
            raise ContractError(f"{self.baseline_id} must say why it was not built")


UNBUILT_BASELINES: tuple[UnbuiltBaseline, ...] = (
    UnbuiltBaseline(
        "B10",
        "reinforcement-learning response planner",
        "needs gradient descent, and ADR-0040 forbids numpy in Stage 5 permanently; a "
        "hand-rolled stdlib policy-gradient learner would be a worse comparison than none, "
        "because a broken baseline flatters the mechanism (MEMORY.md trap 3)",
    ),
    UnbuiltBaseline(
        "B11",
        "learned model-free safe controller",
        "same reason as B10; B2 and B8 cover the model-free end deterministically and are "
        "named as partial substitutes, not equivalents",
    ),
    UnbuiltBaseline(
        "B12",
        "commercial EDR playbooks",
        "not present in this repository and not reimplementable honestly at this scale; B2 is "
        "the stand-in and is described as what a competent sysadmin writes in an afternoon, "
        "never as an industry baseline",
    ),
)


@dataclass(frozen=True, slots=True)
class BaselineOutcome:
    """What one arm did over one corpus. Counts, not rates, except where asked."""

    baseline_id: str
    actions_taken: int
    collateral_incidents: int
    mission_invariant_violations: int
    evidence_violations: int
    incidents_contained: int
    incidents_missed: int
    simulated_rollback_successes: int
    simulated_rollback_attempts: int
    work_units: int
    human_escalations: int
    #: Verdicts the real kernel **issued** — not receipts. A transaction the token
    #: plane or the evidence gate stops before PREPARE carries a synthesised DENY that
    #: no kernel produced; counting those here would let an arm whose executor never
    #: consulted SENTINEL report that it had. See :func:`_score_receipt`.
    sentinel_verdicts: int = 0
    sentinel_denials: int = 0
    refused_before_kernel: int = 0
    planner_faults: int = 0

    _COUNTS = (
        "actions_taken",
        "collateral_incidents",
        "mission_invariant_violations",
        "evidence_violations",
        "incidents_contained",
        "incidents_missed",
        "simulated_rollback_successes",
        "simulated_rollback_attempts",
        "work_units",
        "human_escalations",
        "sentinel_verdicts",
        "sentinel_denials",
        "refused_before_kernel",
        "planner_faults",
    )

    def __post_init__(self) -> None:
        for name in self._COUNTS:
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ContractError(f"BaselineOutcome.{name} must be a count, got {value!r}")
        if self.simulated_rollback_successes > self.simulated_rollback_attempts:
            raise ContractError(f"{self.baseline_id} reports more rollback successes than attempts")

    def collateral_per_1000(self) -> float | None:
        """Collateral per 1000 actions, or ``None`` when the arm never acted.

        ``None`` means "no rate to report", never 0.0 (ADR-0004). An arm that never
        acts occupies the zero-collateral end of the frontier, and
        :func:`primary_metric_value` scores it there *for the saturation test only*.
        """
        if self.actions_taken == 0:
            return None
        return self.collateral_incidents / self.actions_taken * 1000.0

    def simulated_rollback_success(self) -> float | None:
        """In-simulator rollback success, or ``None`` with no attempts. Never a real host."""
        if self.simulated_rollback_attempts == 0:
            return None
        return self.simulated_rollback_successes / self.simulated_rollback_attempts

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"baseline_id": self.baseline_id}
        payload.update({name: getattr(self, name) for name in self._COUNTS})
        payload["collateral_per_1000"] = self.collateral_per_1000()
        payload["simulated_rollback_success"] = self.simulated_rollback_success()
        return payload


class ExecutorLike(Protocol):
    """What an arm needs from the privileged executor, and nothing more."""

    def execute(
        self,
        operator: DefensiveOperator,
        token: CapabilityToken,
        *,
        resolution: CBFResolutionV1,
    ) -> TransactionReceipt: ...


@dataclass(frozen=True, slots=True)
class BaselineRig:
    """Every real Stage 5 component one case needs, on a freshly respawned host."""

    case: ResponseCase
    clock: ManualClock
    host: SimulatedHost
    kernel: SentinelKernel
    journal: RollbackJournal
    gate: EvidencePreservationGate
    governor: ResourceGovernor
    leases: LeaseRegistry
    probe: PostconditionProbe
    tokens: TokenStore
    planner_governor: ResourceGovernor
    memory: EffectivenessMemory
    cells: ResponseCellField
    hysteresis: HysteresisController
    field: ActionField
    before: HostSnapshot


#: Builds the privileged rig for one case. Supplied by the caller, because only the
#: gate and the test file may name ``TransactionalExecutor``.
ExecutorFactory = Callable[[BaselineRig], ExecutorLike]


@dataclass(frozen=True, slots=True)
class Choice:
    """What one arm decided. The only thing that varies between arms."""

    candidate: CandidateAction | None
    escalate: bool
    lease_sweep: bool
    reason: str
    human_grant: bool = False


Policy = Callable[[BaselineRig], Choice]


def build_rig(case: ResponseCase) -> BaselineRig:
    """One case's real components, on a host no other arm has touched.

    The kernel is built from :data:`FROZEN_CONSTITUTION`, and
    ``ResponseConstitution.__post_init__`` refuses anything weaker, so no permissive
    variant can be constructed here. That is why handing this rig to ten arms is safe.
    """
    fresh = case.respawn()
    before = fresh.host.snapshot()
    clock = ManualClock(at=before.at)
    # Two governors, deliberately. ``governor`` pays for the field the simple arms read;
    # ``planner_governor`` pays for the field the planner generates for itself. One shared
    # governor would have the rig's own field generation exhaust
    # ``max_candidate_actions`` before the planner ran, and every planner arm would come
    # back BUDGET-exhausted and ESCALATE — a broken arm that would have flattered every
    # simple control it was compared against. ``run_arm`` reports the sum of both.
    governor = ResourceGovernor()
    memory = EffectivenessMemory()
    cells = ResponseCellField()
    return BaselineRig(
        case=fresh,
        clock=clock,
        host=fresh.host,
        kernel=SentinelKernel(
            constitution=FROZEN_CONSTITUTION, invariants=fresh.invariants, clock=clock
        ),
        journal=RollbackJournal(),
        gate=EvidencePreservationGate(policy=DEFAULT_RETENTION, invariants=fresh.invariants),
        governor=governor,
        leases=LeaseRegistry(clock=clock),
        probe=PostconditionProbe(invariants=fresh.invariants),
        planner_governor=ResourceGovernor(),
        tokens=TokenStore(
            key=secrets.token_bytes(32), signer="stage5.labs.baselines", clock=clock
        ),
        memory=memory,
        cells=cells,
        hysteresis=HysteresisController(policy=DEFAULT_HYSTERESIS, clock=clock),
        field=generate_action_field(
            fresh.resolution,
            before,
            constitution=FROZEN_CONSTITUTION,
            invariants=fresh.invariants,
            governor=governor,
            memory=memory,
            cells=cells,
            twin=ResponseTwin(snapshot=before, governor=governor),
        ),
        before=before,
    )


# --- shared predicates --------------------------------------------------------


def _autonomous(candidate: CandidateAction) -> bool:
    """Whether policy alone may carry this candidate. Never a confidence question."""
    return authority_rank(candidate.authority) <= authority_rank(MAX_AUTONOMOUS_AUTHORITY)


def _is_intervention(candidate: CandidateAction) -> bool:
    """O2 or above, and not a restore operator.

    ``generate_action_field`` used to offer restore operators (``RESUME_PROCESS``,
    ``RELEASE_LOCAL_SOCKET``, ``STOP_TRACE``, ``RELEASE_SERVICE``) as incident
    candidates, and only this harness filtered them — so the simple arms were protected
    from the accident and AEGIS was not, and AEGIS chose a restoration as "containment"
    on every hostile case. The field now refuses them itself (integrator fix), which
    makes this filter redundant; it is kept as a second line so a regression in the
    field shows up as a test failure rather than as a baseline suddenly acting on
    nothing. ``RESTORATION_OPERATOR_IDS`` is the catalog's one derivation.
    """
    spec = candidate.operator.spec
    return (
        spec.operator_class >= OperatorClass.O2_REVERSIBLE_RESTRICT
        and spec.operator_id not in RESTORATION_OPERATOR_IDS
    )


def _by_id(rig: BaselineRig, operator_id: str) -> CandidateAction | None:
    """The autonomous candidate for one operator id, widest scope first.

    "Widest scope" stands in for §7's "highest-dPhi lineage": a ``HostSnapshot``
    carries one security state and no per-lineage history, so a playbook reading a
    snapshot has no per-lineage dPhi available. The limitation is the playbook's, and
    it is stated rather than papered over with a fabricated per-lineage score.
    """
    matches = [
        candidate
        for candidate in rig.field.candidates
        if candidate.operator.spec.operator_id == operator_id and _autonomous(candidate)
    ]
    if not matches:
        return None
    return sorted(matches, key=lambda c: (-c.scope_size, c.operator.target.identity.pid))[0]


def _leading_world(resolution: CBFResolutionV1) -> str:
    best, support = "", -1.0
    for row in resolution.hypotheses:
        value = float(row.get("support", 0.0))
        if value > support:
            best, support = str(row.get("mechanism_id", "")), value
    return best


# --- the four planner arms ----------------------------------------------------


def reference_policy(flags: Mapping[str, bool]) -> Policy:
    """A :class:`Policy` running the real planner under one flag set.

    Public rather than private because ``fifty_experiments`` must flip a flag without
    reaching into this module: an ablation that has to touch a private name is an
    ablation somebody will eventually implement as a code edit instead.

    ``enable_pareto`` drags ``selector`` with it, because ``PlannerConfig`` refuses a
    config whose two disagree — which is how G5.14 is stopped from attributing a
    measured delta to the wrong mechanism.
    """
    unknown = sorted(set(flags) - set(ABLATION_FLAG_FIELDS))
    if unknown:
        raise ContractError(
            f"unknown planner flags {unknown}; known: {sorted(ABLATION_FLAG_FIELDS)}"
        )
    resolved = {**REFERENCE_FLAGS, **flags}
    config = PlannerConfig(
        selector=(
            Selector.PARETO_THEN_POLICY if resolved["enable_pareto"] else Selector.SCALAR_UTILITY
        ),
        **resolved,
    )

    def policy(rig: BaselineRig) -> Choice:
        planner = AegisPlanner(
            config=config,
            constitution=FROZEN_CONSTITUTION,
            invariants=rig.case.invariants,
            governor=rig.planner_governor,
            memory=rig.memory,
            cells=rig.cells,
            hysteresis=rig.hysteresis,
            harm=rig.case.harm,
        )
        plan = planner.plan(
            rig.case.resolution, rig.before, now=rig.clock.now(), active_leases=()
        )
        return _choice_from_plan(plan, lease_sweep=resolved["enable_hysteresis"])

    return policy


def _choice_from_plan(plan: ResponsePlan, *, lease_sweep: bool) -> Choice:
    """Map a :class:`ResponsePlan` onto a :class:`Choice`, total over ``PlanDecision``.

    ``OBSERVE`` carries the plan's chosen O0/O1 candidate — that is §2's
    ``NO_ACTION_IS_ALWAYS_AVAILABLE`` made an outcome rather than an error path, and it
    is what a multi-world planner does on an ambiguous pair instead of committing.
    ``ROLLBACK`` takes no new action here: the sweeper performs rollbacks, and an arm
    that opened a second transaction to undo one would be measuring the wrong thing.
    """
    match plan.decision:
        case PlanDecision.ACT:
            return Choice(plan.chosen, False, lease_sweep, "plan ACT")
        case PlanDecision.OBSERVE:
            return Choice(plan.chosen, False, False, "plan OBSERVE")
        case PlanDecision.DEFER | PlanDecision.ESCALATE:
            return Choice(None, True, False, f"plan {plan.decision.value}")
        case PlanDecision.NO_ACTION | PlanDecision.ROLLBACK:
            return Choice(None, False, False, f"plan {plan.decision.value}")


def reference_arm(rig: BaselineRig) -> Choice:
    """The full planner, every optional mechanism on. The arm the ablation toggles."""
    return reference_policy({})(rig)


def single_scalar_utility(rig: BaselineRig) -> Choice:
    """B6 — one weighted sum over §12's nine objectives instead of the frontier.

    ``DEFAULT_WEIGHTS`` is arbitrary and ``aegis/pareto.py`` says so; that is §12's
    entire argument, because the claim is that scalarising hides trade-offs and the
    control therefore has to be an arbitrary scalarisation. If arbitrary weights match
    the frontier-then-policy selector, §12's argument is unsupported and ADR-0048
    records it.
    """
    return reference_policy(B6_FLAGS)(rig)


def single_world_planner(rig: BaselineRig) -> Choice:
    """B7 — the lead's mandated single-world control: leading hypothesis only.

    On an ambiguous pair it must commit, and is therefore wrong on half of them. Expect
    it to be strong on the unambiguous half: Stage 2's zero-parameter Phi-oracle beat
    four learned models.
    """
    return reference_policy(B7_FLAGS)(rig)


def no_hysteresis(rig: BaselineRig) -> Choice:
    """B8 — immediate action. No dwell, no cooldown, no lease sweep.

    The control for D5.12. If hysteresis does not reduce the action count on a corpus
    whose belief fluctuates around the threshold, ADR-0049 reports it as not justified.
    """
    return reference_policy(B8_FLAGS)(rig)


# --- the six dumber arms ------------------------------------------------------


def no_automated_response(rig: BaselineRig) -> Choice:
    """B1, act-never. Observe and record; never act. The degenerate lower bound.

    §44's falsifier F7 lives here: if B1 shows lower collateral *and* containment
    within one case of the planner, Stage 5 is not justified as an actor and reduces
    to a recommender. That is a legitimate and possibly correct outcome.
    """
    return Choice(None, escalate=False, lease_sweep=False, reason="B1 never acts")


def fixed_playbook(rig: BaselineRig) -> Choice:
    """B2 — the competent-sysadmin control, and the single most important row in §7.

    Three conditions, one table, no worlds, no twin, no cone, no Pareto, no lease: if
    Phi is over the chosen threshold and privilege was raised, suspend the widest
    lineage. If the SAFE Action Field, the twin, the cone and the Pareto selector
    cannot beat this on collateral at equal-or-better containment, ADR-0048 reports the
    machinery as not justified and recommends removing it.
    """
    state = rig.before.security_state
    raised = StateDelta.between(SecurityStateV1(), state).bitmask()
    if phi(state).total <= PLAYBOOK_PHI_THRESHOLD or not raised & PRIVILEGE_BIT:
        return Choice(None, escalate=False, lease_sweep=False, reason="B2 threshold not crossed")
    return Choice(
        _by_id(rig, "SUSPEND_PROCESS"),
        escalate=False,
        lease_sweep=False,
        reason="B2 suspend on the widest lineage",
    )


def simple_if_then_containment(rig: BaselineRig) -> Choice:
    """B3 — one rule per mechanism id, ignoring host, uncertainty and invariants."""
    operator_id = SIMPLE_RULE_TABLE.get(_leading_world(rig.case.resolution))
    if operator_id is None:
        return Choice(None, escalate=False, lease_sweep=False, reason="B3 no rule for mechanism")
    return Choice(
        _by_id(rig, operator_id),
        escalate=False,
        lease_sweep=False,
        reason=f"B3 rule {operator_id}",
    )


def always_isolate(rig: BaselineRig) -> Choice:
    """B4, act-always. Suspend the leading lineage on every incident, unconditionally.

    The top of both the containment and the collateral axis, and reported as the
    frontier's endpoint rather than as a competitor.
    """
    candidate = _by_id(rig, "SUSPEND_PROCESS")
    if candidate is None:
        interventions = [c for c in rig.field.candidates if _autonomous(c) and _is_intervention(c)]
        candidate = (
            sorted(
                interventions,
                key=lambda c: (-int(c.operator.spec.operator_class), c.candidate_id),
            )[0]
            if interventions
            else None
        )
    return Choice(candidate, escalate=False, lease_sweep=False, reason="B4 isolate always")


def d3fend_lookup_only(rig: BaselineRig) -> Choice:
    """B5 — act on whatever the external ontology maps, and nothing else.

    With no committed D3FEND snapshot every catalog entry is ``UNMAPPED``, so
    :func:`mapping_for` returns ``None`` for all of them and B5 takes zero actions.
    **That degeneracy is the result**, not a loss: an ontology that maps nothing cannot
    prioritise anything, which is MITRE's own statement about D3FEND (§28). Reported as
    ``UNMAPPED, 0 actions``.
    """
    for candidate in rig.field.candidates:
        if not _autonomous(candidate) or not _is_intervention(candidate):
            continue
        if mapping_for(candidate.operator.spec.operator_id) is not None:
            return Choice(candidate, escalate=False, lease_sweep=False, reason="B5 mapped")
    return Choice(None, escalate=False, lease_sweep=False, reason="B5 every operator is UNMAPPED")


def human_only(rig: BaselineRig) -> Choice:
    """B9 — every candidate escalates; a scripted analyst approves the truth-optimal act.

    The only arm that reads ``truth``, and legitimately: §7 defines B9 as the analyst
    who always picks correctly, which makes it the upper bound on correctness and the
    lower bound on autonomy. No autonomous arm reads ``truth``, and none does.
    """
    sufficient = rig.case.truth.sufficient_operator_ids
    for candidate in sorted(rig.field.candidates, key=lambda c: c.candidate_id):
        if candidate.operator.spec.operator_id in sufficient and _autonomous(candidate):
            return Choice(
                candidate,
                escalate=True,
                lease_sweep=True,
                reason="B9 analyst approved the truth-optimal action",
                human_grant=True,
            )
    return Choice(None, escalate=True, lease_sweep=False, reason="B9 analyst declined")


BASELINES: Mapping[str, Policy] = MappingProxyType(
    {
        "B1": no_automated_response,
        "B2": fixed_playbook,
        "B3": simple_if_then_containment,
        "B4": always_isolate,
        "B5": d3fend_lookup_only,
        "B6": single_scalar_utility,
        "B7": single_world_planner,
        "B8": no_hysteresis,
        "B9": human_only,
    }
)


# --- the harness --------------------------------------------------------------


def _grant(candidate: CandidateAction, *, human: bool) -> AuthorityGrant:
    return AuthorityGrant(
        authority=required_authority(candidate.operator.spec),
        granted_by=GrantSource.HUMAN if human else GrantSource.POLICY,
        policy_version=_POLICY_VERSION,
        subject_operator_id=candidate.operator.spec.operator_id,
        detail="labs baseline grant at the operator's own authority class",
    )


def _mint(rig: BaselineRig, choice: Choice) -> CapabilityToken | None:
    """Mint through the real store, or return ``None`` when the plane refuses.

    A refusal here is not a bug in the arm: ``mint()`` refuses a ``POLICY`` grant for an
    operator whose ``autonomy_of`` demands a human, which is the authority plane turning
    a baseline's ambition into an escalation. The caller counts it as one.
    """
    candidate = choice.candidate
    if candidate is None:
        return None
    try:
        return rig.tokens.mint(
            grant=_grant(candidate, human=choice.human_grant),
            operator=candidate.operator,
            action_id=f"act.{rig.case.case_id}.{candidate.candidate_id}",
            ttl_seconds=min(candidate.lease_ttl_seconds, MAX_TOKEN_LIFETIME_SECONDS),
        )
    except ContractError:
        return None


@dataclass(slots=True)
class _Tally:
    """Mutable running counts for one arm, frozen into an outcome at the end."""

    actions: int = 0
    collateral: int = 0
    invariant_violations: int = 0
    evidence_violations: int = 0
    contained: int = 0
    missed: int = 0
    rollback_successes: int = 0
    rollback_attempts: int = 0
    work_units: int = 0
    escalations: int = 0
    verdicts: int = 0
    denials: int = 0
    refused_before_kernel: int = 0
    planner_faults: int = 0
    fault_detail: str = ""


def _harm_counts(rig: BaselineRig, candidate: CandidateAction, tally: _Tally) -> None:
    """Score one action that reached the host against this case's ``truth``.

    The collateral and evidence figures are figures about the corpus's authored tables
    (§9.2 item 2). The invariant count is the exception: it is read from
    ``MissionInvariantSet.violations``, which is machine-enforced code and would be a
    real defect if it ever fired.
    """
    truth = rig.case.truth
    spec = candidate.operator.spec
    if spec.operator_id in truth.harmful_operator_ids:
        tally.collateral += 1
    if rig.case.invariants.violations(
        operator=candidate.operator,
        lease_ttl_seconds=candidate.lease_ttl_seconds,
        snapshot=rig.before,
    ):
        tally.invariant_violations += 1
    if spec.evidence_effect in {EvidenceEffect.DEGRADES_VOLATILE, EvidenceEffect.DESTROYS}:
        row = rig.before.process(candidate.operator.target.identity.pid)
        volatile = frozenset(() if row is None else row.volatile_signals)
        if volatile & truth.uniquely_necessary_evidence:
            tally.evidence_violations += 1


def _score_receipt(
    rig: BaselineRig, candidate: CandidateAction, receipt: TransactionReceipt, tally: _Tally
) -> bool:
    """Fold one receipt into the tally; return whether the incident was contained.

    A kernel verdict always lists the checks it evaluated — at least one, because the
    kernel records a check before running it — while the executor's synthesised DENY
    for a transaction that stopped before PREPARE lists none. That structural
    difference, not the verdict's prose, decides which counter a receipt feeds.
    """
    verdict = receipt.sentinel_verdict
    if verdict.evaluated_checks:
        tally.verdicts += 1
        if verdict.decision is Decision.DENY:
            tally.denials += 1
    else:
        tally.refused_before_kernel += 1
    # Not ``tally.work_units += receipt.work_units`` (finding F10): the executor spends
    # HOST_CALL on ``rig.governor``, whose TOTAL ``run_arm`` already adds, so the receipt's
    # delta was counted twice — and sweeper transactions only once, so the inflation varied
    # by arm on one of the three Pareto axes.
    if receipt.rollback_attempted:
        tally.rollback_attempts += 1
        if receipt.rollback_succeeded is True:
            tally.rollback_successes += 1
    if not receipt.reached_host():
        return False
    tally.actions += 1
    _harm_counts(rig, candidate, tally)
    # Containment is only meaningful on a hostile case. Counting a benign-admin case as
    # contained because an observation operator ran would let an arm bank credit for
    # doing nothing wrong, and would turn the containment axis into a count of actions.
    return (
        receipt.outcome in {Outcome.COMMITTED_VERIFIED, Outcome.COMMITTED_UNVERIFIED}
        and not rig.case.truth.benign_admin
        and candidate.operator.spec.operator_id in rig.case.truth.sufficient_operator_ids
    )


def _sweep(rig: BaselineRig, executor: ExecutorLike, tally: _Tally) -> None:
    """Advance a clock that does not move on its own, then run the explicit sweep.

    ``ManualClock`` never advances by itself, so a lease is expired here only because
    this line says so — which is what makes "the lease actually expires" a claim about
    the lease's own data rather than about a background timer somebody hopes exists.
    """
    rig.clock.advance(MAX_OPERATOR_DURATION_SECONDS + 1)
    sweeper = LeaseSweeper(
        registry=rig.leases, executor=executor, tokens=rig.tokens, clock=rig.clock
    )
    for expiry in sweeper.sweep(now=rig.clock.now()):
        tally.rollback_attempts += 1
        if expiry.rolled_back is True:
            tally.rollback_successes += 1


def _run_case(
    rig: BaselineRig, choice: Choice, tally: _Tally, *, build_executor: ExecutorFactory
) -> None:
    """One case for one arm: mint, execute, score, sweep. ``None`` anywhere is a no-op."""
    if choice.escalate:
        tally.escalations += 1
    token = _mint(rig, choice)
    if choice.candidate is None or token is None:
        if choice.candidate is not None:
            tally.escalations += 1
        if not rig.case.truth.benign_admin:
            tally.missed += 1
        return
    executor = build_executor(rig)
    receipt = executor.execute(
        choice.candidate.operator, token, resolution=rig.case.resolution
    )
    contained = _score_receipt(rig, choice.candidate, receipt, tally)
    if choice.lease_sweep:
        _sweep(rig, executor, tally)
    if contained:
        tally.contained += 1
    elif not rig.case.truth.benign_admin:
        tally.missed += 1


def _decide(policy: Policy, rig: BaselineRig, tally: _Tally) -> Choice:
    """Ask the arm to choose, and survive it failing.

    §2's ``FAILURE_MUST_NOT_STOP_MONITORING`` and §33's "planner crash independence"
    (experiment S5X-46) both say the same thing: a planner that raises must not take the
    response loop down with it, and it certainly must not be treated as having granted
    anything. A fault becomes an escalation and a **counted, reported** figure —
    ``BaselineOutcome.planner_faults`` — rather than a swallowed exception. A run with a
    non-zero count is a run whose planner is broken, and the test suite asserts the count
    is zero rather than accepting a quiet zero-action arm as a result.
    """
    try:
        return policy(rig)
    except Exception as exc:
        tally.planner_faults += 1
        if not tally.fault_detail:
            tally.fault_detail = f"{type(exc).__name__}: {exc}"
        return Choice(
            None, escalate=True, lease_sweep=False, reason=f"planner fault: {type(exc).__name__}"
        )


def run_arm(
    policy: Policy,
    cases: Sequence[ResponseCase],
    *,
    baseline_id: str,
    build_executor: ExecutorFactory,
    observe: Callable[[BaselineRig], None] | None = None,
) -> BaselineOutcome:
    """Run one arm over one corpus, through the real kernel and the real executor.

    Each case gets a freshly respawned host, so the arms are independent and the
    caller's corpus is never mutated. A case the arm declines counts as missed only when
    ``truth`` says it was not a benign administrator: declining a benign case is the
    correct answer, not a miss.

    ``work_units`` is ``rig.governor`` plus ``rig.planner_governor`` totals per case, so
    ``build_executor`` must spend on ``rig.governor`` — every factory in the repository
    does (``gate.executor_for_rig``); an executor on its own governor is not counted.

    ``observe`` is handed each case's rig after the case has run, and exists for
    ``resources.py``: the journal, memory and cells a real run filled are the only honest
    subjects for §43's per-component rows. It can read the rig; it cannot choose for it.
    """
    tally = _Tally()
    for case in cases:
        rig = build_rig(case)
        _run_case(rig, _decide(policy, rig, tally), tally, build_executor=build_executor)
        if observe is not None:
            observe(rig)
        tally.work_units += (
            rig.governor.spend_report()["TOTAL"]
            + rig.planner_governor.spend_report()["TOTAL"]
        )
    return BaselineOutcome(
        baseline_id=baseline_id,
        actions_taken=tally.actions,
        collateral_incidents=tally.collateral,
        mission_invariant_violations=tally.invariant_violations,
        evidence_violations=tally.evidence_violations,
        incidents_contained=tally.contained,
        incidents_missed=tally.missed,
        simulated_rollback_successes=tally.rollback_successes,
        simulated_rollback_attempts=tally.rollback_attempts,
        work_units=tally.work_units,
        human_escalations=tally.escalations,
        sentinel_verdicts=tally.verdicts,
        sentinel_denials=tally.denials,
        refused_before_kernel=tally.refused_before_kernel,
        planner_faults=tally.planner_faults,
    )


def run_baselines(
    cases: Sequence[ResponseCase], *, build_executor: ExecutorFactory
) -> Mapping[str, BaselineOutcome]:
    """All nine §7 baselines plus the full planner, in one process on one corpus.

    Same run, same corpus, same simulator, same fault profiles. Only within-run ratios
    transfer off this host (§2.8), so running the arms in separate processes or on
    separate corpora would make the comparison meaningless.
    """
    outcomes = {
        baseline_id: run_arm(policy, cases, baseline_id=baseline_id, build_executor=build_executor)
        for baseline_id, policy in BASELINES.items()
    }
    outcomes[REFERENCE_ARM_ID] = run_arm(
        reference_arm, cases, baseline_id=REFERENCE_ARM_ID, build_executor=build_executor
    )
    return MappingProxyType(outcomes)


def primary_metric_value(outcome: BaselineOutcome) -> float:
    """Collateral per 1000, with an act-never arm scored 0.0 rather than ``None``.

    Scored that way **here only**. ``collateral_per_1000`` keeps the ``None``, because
    "no rate to report" and "a rate of zero" are different facts (ADR-0004). The
    saturation test needs the degenerate arms on the same axis as the rest so it can
    notice when one of them ties the best, and that is the one place the substitution is
    the correct reading.
    """
    rate = outcome.collateral_per_1000()
    return 0.0 if rate is None else rate


def pareto_frontier_of(outcomes: Mapping[str, BaselineOutcome]) -> tuple[str, ...]:
    """Arm ids not dominated on (containment up, collateral down, work units down).

    Three axes rather than one, because §7 says B1 and B4 define the endpoints of the
    collateral/containment box and an arm inside that box has added nothing. Sorted, for
    a report that does not change between runs.
    """

    def at_least_as_good(left: BaselineOutcome, right: BaselineOutcome) -> bool:
        return (
            left.incidents_contained >= right.incidents_contained
            and primary_metric_value(left) <= primary_metric_value(right)
            and left.work_units <= right.work_units
        )

    def better_somewhere(left: BaselineOutcome, right: BaselineOutcome) -> bool:
        return (
            left.incidents_contained > right.incidents_contained
            or primary_metric_value(left) < primary_metric_value(right)
            or left.work_units < right.work_units
        )

    return tuple(
        sorted(
            row_id
            for row_id, row in outcomes.items()
            if not any(
                at_least_as_good(other, row) and better_somewhere(other, row)
                for other_id, other in outcomes.items()
                if other_id != row_id
            )
        )
    )


assert set(BASELINES) == {f"B{index}" for index in range(1, 10)}, "§7 names nine baselines"
assert set(REFERENCE_FLAGS) == set(ABLATION_FLAG_FIELDS), "every planner flag must be ablatable"
