"""The discriminating-observation planner (architecture §16, §17) — and the one seam it may use.

§16 says the next sensor action should distinguish worlds rather than merely collect
more data, with utility ``Discrimination * SecurityConsequence / cost``. §17 adds the
refusal that carries the low-overhead claim: if predicted outcomes are nearly identical
across worlds, do not spend the budget.

Two rules are load-bearing and both are enforced here rather than reviewed:

1. **Below ``MIN_DISCRIMINATION_TO_SPEND`` an action is refused, with the reason
   recorded.** The refusal string is kept verbatim so a run can be audited for *why*
   nothing was collected, which is the difference between a planner that decided not to
   spend and one that silently did nothing.
2. **Escalation goes through ``AdaptiveObservationPolicy.consider()`` and nowhere else**
   (ADR-0035). Stage 4 has no code that enables a sensor, raises no ``AOPBudget`` cap and
   keeps no escalation state of its own. A second observation planner would be a second
   unbudgeted amplification path, which is exactly the failure Stage 1's AOP exists to
   prevent. ``observation=None`` is legal and means every candidate is refused with
   ``"no observation policy"`` — the planner does not escalate on its own initiative.

``SENSOR_COSTS`` is **unmeasured by default and the planner refuses to rank on it.** The
measured table comes from ``simulate.measure_sensor_costs`` (or, in the full wave, from
``labs/experiments.py``) and is injected. Fields named for §16's "privilege/risk cost"
are called ``authority_risk_units``: ``privilege_cost`` is a T5 authority-field violation
(``FORBIDDEN_AUTHORITY_FIELDS``, spec §2.4).
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError, require_identifier
from pocketsec.stage1.observation.policy import AdaptiveObservationPolicy, EscalationDecision
from pocketsec.stage4.identifiability.horizon import DEFAULT_HORIZON_ESCALATIONS
from pocketsec.stage4.sensing.simulate import (
    COST_MEMORY_UNIT_BYTES,
    COST_TELEMETRY_UNIT_BYTES,
    simulate_sensor_value,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pocketsec.stage4.cones.incident_cone import IncidentFutureCone
    from pocketsec.stage4.visibility.model import VisibilityModel
    from pocketsec.stage4.visibility.sensor_shadow import SensorShadow
    from pocketsec.stage4.worlds.field import CausalBeliefField

__all__ = [
    "ACTION_SIGNALS",
    "AUTHORITY_RISK_PARAMETERS",
    "MAX_CANDIDATE_ACTIONS",
    "MIN_DISCRIMINATION_TO_SPEND",
    "NON_POSITIVE_COST_REASON",
    "NOT_ATTEMPTED_REASONS",
    "NO_OBSERVATION_POLICY",
    "SENSOR_COSTS",
    "UNMEASURED_COST_REASON",
    "UNMEASURED_PROVENANCE",
    "ObservationPlan",
    "ObservationRequest",
    "SensorAction",
    "SensorCost",
    "plan_discriminating_observation",
]

#: Candidate actions simulated per planning call. §17 names six; the bound is eight so
#: that adding a seventh does not silently make planning cost grow without a check.
MAX_CANDIDATE_ACTIONS: int = 8

#: Below this expected discrimination, do not spend the telemetry budget (§17). A chosen
#: parameter (spec §9.11), reported as a parameter and never as a finding.
MIN_DISCRIMINATION_TO_SPEND: float = 0.1

#: Provenance string for a cost nobody has measured.
UNMEASURED_PROVENANCE: str = "UNMEASURED"

#: The refusal recorded when a candidate's cost is unmeasured.
UNMEASURED_COST_REASON: str = (
    "sensor cost unmeasured; the planner refuses to rank on a guessed cost"
)

#: The refusal recorded when no AOP is available.
NO_OBSERVATION_POLICY: str = "no observation policy"

#: The refusal recorded when a measured cost does not total to a positive number.
NON_POSITIVE_COST_REASON: str = "sensor cost total is not positive; utility undefined"

#: Refusals that say nothing about the EVIDENCE. They are issued only after an action
#: has already cleared ``MIN_DISCRIMINATION_TO_SPEND`` (see ``_consider_action``), so
#: the actions refused for these reasons are exactly the ones that WOULD separate the
#: worlds. A plan whose only reason for issuing nothing is one of these has not shown
#: the case is non-identifiable; it has shown the planner was not wired to look
#: (S4-REV-03). ``resolution.test_identifiability`` answers INSUFFICIENT_EVIDENCE for
#: them, never UNIDENTIFIABLE.
NOT_ATTEMPTED_REASONS: frozenset[str] = frozenset(
    {UNMEASURED_COST_REASON, NO_OBSERVATION_POLICY, NON_POSITIVE_COST_REASON}
)


class SensorAction(StrEnum):
    """§17's six candidate sensor actions, as a closed set.

    Closed on purpose. An open vocabulary here would let a caller name an action the
    cost table has never measured and the visibility model has never seen, which is how
    a "targeted" observation becomes an unbudgeted one.
    """

    TRACE_FILE_ACCESS_SUBTREE = "TRACE_FILE_ACCESS_SUBTREE"
    INCREASE_EXEC_LINEAGE_DEPTH = "INCREASE_EXEC_LINEAGE_DEPTH"
    CAPTURE_DNS_METADATA = "CAPTURE_DNS_METADATA"
    WATCH_PERSISTENCE_PATH = "WATCH_PERSISTENCE_PATH"
    COLLECT_PROCESS_HASH = "COLLECT_PROCESS_HASH"
    INSPECT_SERVICE_UNIT_CHANGE = "INSPECT_SERVICE_UNIT_CHANGE"


#: Which signals each action can reach. The union is the whole closed incident-cone
#: vocabulary, which is what makes "no SensorAction discriminates these two worlds" a
#: statement about the entire observable space rather than about one lucky gap.
ACTION_SIGNALS: Mapping[SensorAction, frozenset[str]] = MappingProxyType(
    {
        SensorAction.TRACE_FILE_ACCESS_SUBTREE: frozenset({"file_staging", "credential_access"}),
        SensorAction.INCREASE_EXEC_LINEAGE_DEPTH: frozenset(
            {"privilege_change", "authentication"}
        ),
        SensorAction.CAPTURE_DNS_METADATA: frozenset({"boundary_crossing"}),
        SensorAction.WATCH_PERSISTENCE_PATH: frozenset({"persistence_write"}),
        SensorAction.COLLECT_PROCESS_HASH: frozenset({"module_load"}),
        SensorAction.INSPECT_SERVICE_UNIT_CHANGE: frozenset(
            {"persistence_write", "session_teardown"}
        ),
    }
)

#: Declared authority-risk parameters per action, keyed by the action's value.
#:
#: These are **not measurements** and cannot be: how much authority a collection method
#: needs is a policy judgement, not a quantity this repository can sample. They are
#: reported as parameters in the findings document (spec §9.11). Reading a process hash
#: and inspecting a service unit are ranked highest because both require reaching
#: outside the lineage being investigated.
AUTHORITY_RISK_PARAMETERS: Mapping[str, float] = MappingProxyType(
    {
        SensorAction.TRACE_FILE_ACCESS_SUBTREE.value: 1.0,
        SensorAction.INCREASE_EXEC_LINEAGE_DEPTH.value: 0.5,
        SensorAction.CAPTURE_DNS_METADATA.value: 1.0,
        SensorAction.WATCH_PERSISTENCE_PATH.value: 0.75,
        SensorAction.COLLECT_PROCESS_HASH.value: 1.5,
        SensorAction.INSPECT_SERVICE_UNIT_CHANGE.value: 1.5,
    }
)


@dataclass(frozen=True, slots=True)
class SensorCost:
    """What one sensor action costs.

    The three resource fields are ``None`` when unmeasured. ``None`` is not zero
    (ADR-0004): a cost of zero would make every action look free and the utility
    ordering meaningless, which is why ``total()`` returns ``None`` instead of a number
    and the planner refuses the action.
    """

    cpu_units: float | None
    memory_bytes: int | None
    telemetry_bytes: int | None
    #: §16's "privilege/risk cost", renamed per spec §2.4 — ``privilege_cost`` is a
    #: forbidden authority field name. A declared parameter, never a measurement.
    authority_risk_units: float
    provenance: str = UNMEASURED_PROVENANCE

    def __post_init__(self) -> None:
        for name in ("cpu_units", "authority_risk_units"):
            value = getattr(self, name)
            if value is None:
                continue
            numeric = float(value)
            if numeric != numeric or numeric in (math.inf, -math.inf) or numeric < 0.0:
                raise ContractError(f"SensorCost.{name} must be finite and >= 0, got {value!r}")
        for name in ("memory_bytes", "telemetry_bytes"):
            value = getattr(self, name)
            if value is None:
                continue
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ContractError(f"SensorCost.{name} must be a non-negative int, got {value!r}")
        if not isinstance(self.provenance, str) or not self.provenance:
            raise ContractError("SensorCost.provenance must say where the numbers came from")
        if self.is_measured and self.provenance == UNMEASURED_PROVENANCE:
            raise ContractError(
                "a SensorCost with measured fields must name the module:function that "
                "produced them; an unattributed number is not a measurement"
            )
        if not self.is_measured and self.provenance != UNMEASURED_PROVENANCE:
            raise ContractError(
                f"SensorCost.provenance claims {self.provenance!r} but a resource field "
                "is None; partial measurement is reported as unmeasured"
            )

    @property
    def is_measured(self) -> bool:
        return (
            self.cpu_units is not None
            and self.memory_bytes is not None
            and self.telemetry_bytes is not None
        )

    def total(self) -> float | None:
        """Combined cost in cost units, or ``None`` when any resource is unmeasured.

        The two byte-to-unit divisors are declared parameters, not measurements; they
        exist so that a kilobyte of telemetry and one cpu unit are commensurable at all.
        """
        if not self.is_measured:
            return None
        assert self.cpu_units is not None  # narrowed by is_measured
        assert self.memory_bytes is not None
        assert self.telemetry_bytes is not None
        return (
            self.cpu_units
            + self.memory_bytes / COST_MEMORY_UNIT_BYTES
            + self.telemetry_bytes / COST_TELEMETRY_UNIT_BYTES
            + self.authority_risk_units
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "cpu_units": self.cpu_units,
            "memory_bytes": self.memory_bytes,
            "telemetry_bytes": self.telemetry_bytes,
            "authority_risk_units": self.authority_risk_units,
            "provenance": self.provenance,
            "total": self.total(),
        }


def _unmeasured_costs() -> Mapping[SensorAction, SensorCost]:
    return MappingProxyType(
        {
            action: SensorCost(
                cpu_units=None,
                memory_bytes=None,
                telemetry_bytes=None,
                authority_risk_units=AUTHORITY_RISK_PARAMETERS[action.value],
                provenance=UNMEASURED_PROVENANCE,
            )
            for action in SensorAction
        }
    )


#: The default cost table: **unmeasured**. Every entry is marked so and the planner
#: refuses to rank on it. A measured table is produced by
#: ``simulate.measure_sensor_costs`` and injected via ``plan_discriminating_observation``.
SENSOR_COSTS: Mapping[SensorAction, SensorCost] = _unmeasured_costs()


@dataclass(frozen=True, slots=True)
class ObservationRequest:
    """One candidate observation, with the utility that justifies it.

    The field is ``sensor_method`` and not ``action``: ``action`` is a
    ``FORBIDDEN_AUTHORITY_FIELDS`` token (``threat_prediction_v1.py:48``, trust rule T5),
    and a Stage 4 output field named ``action`` would read as an instruction to act. The
    specification's D4.9 sketch writes ``action``; §2.3's rule outranks it, and the rule
    has no exemption list on purpose.
    """

    sensor_method: SensorAction
    #: The AOP target string. Passed straight through to ``consider()``; Stage 4 never
    #: interprets it, because target selection is Stage 1's business.
    target: str
    signals: frozenset[str]
    #: Expected JS distance between posterior fields — from ``simulate_sensor_value``,
    #: computed before any escalation.
    discrimination: float
    consequence: float
    cost: SensorCost
    #: ``discrimination * consequence / cost.total()`` (§16).
    utility: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "sensor_method", SensorAction(self.sensor_method))
        require_identifier(self.target, "ObservationRequest.target")
        if not self.cost.is_measured:
            raise ContractError(
                "an ObservationRequest may not be built on an unmeasured cost; refuse "
                "the action instead so the reason appears in the plan"
            )
        for name in ("discrimination", "consequence", "utility"):
            value = float(getattr(self, name))
            if value != value or value in (math.inf, -math.inf) or value < 0.0:
                raise ContractError(f"ObservationRequest.{name} must be finite and >= 0")
        object.__setattr__(self, "signals", frozenset(str(s) for s in self.signals))

    def worth_spending(self) -> bool:
        """§17's rule, as one predicate."""
        return self.discrimination >= MIN_DISCRIMINATION_TO_SPEND

    def to_dict(self) -> dict[str, Any]:
        return {
            "sensor_method": self.sensor_method.value,
            "target": self.target,
            "signals": sorted(self.signals),
            "discrimination": round(self.discrimination, 6),
            "consequence": round(self.consequence, 6),
            "cost": self.cost.to_dict(),
            "utility": round(self.utility, 6),
            "worth_spending": self.worth_spending(),
        }


@dataclass(frozen=True, slots=True)
class ObservationPlan:
    """What the planner proposed, what it refused, and what Stage 1 actually granted."""

    requests: tuple[ObservationRequest, ...]
    #: ``(action, why)``. The reason is kept verbatim so a run with no collection can be
    #: audited for the decision rather than for the silence.
    refused: tuple[tuple[SensorAction, str], ...]
    #: Every ``EscalationDecision`` AOP returned, granted or refused. Stage 4 records
    #: these; it does not make them.
    escalations: tuple[EscalationDecision, ...] = ()

    def __post_init__(self) -> None:
        if len(self.requests) + len(self.refused) > MAX_CANDIDATE_ACTIONS:
            raise ContractError(
                f"ObservationPlan considered {len(self.requests) + len(self.refused)} "
                f"actions, above MAX_CANDIDATE_ACTIONS {MAX_CANDIDATE_ACTIONS}"
            )
        utilities = [request.utility for request in self.requests]
        if utilities != sorted(utilities, reverse=True):
            raise ContractError("ObservationPlan.requests must be utility-ordered, descending")
        if len(self.granted()) > len(self.requests):
            raise ContractError("more granted escalations than requests")

    def best(self) -> ObservationRequest | None:
        return self.requests[0] if self.requests else None

    def not_attempted(self) -> tuple[tuple[SensorAction, str], ...]:
        """Refusals about the wiring, not the evidence. See ``NOT_ATTEMPTED_REASONS``."""
        return tuple(row for row in self.refused if row[1] in NOT_ATTEMPTED_REASONS)

    def granted(self) -> tuple[EscalationDecision, ...]:
        return tuple(decision for decision in self.escalations if decision.escalated)

    def granted_requests(self) -> tuple[tuple[ObservationRequest, EscalationDecision], ...]:
        """Pair each granted escalation with the request that asked for it.

        The pairing is what makes "every granted observation has a matching
        EscalationDecision" checkable. An unpaired grant would mean Stage 4 collected
        something the planner never proposed.
        """
        by_target = {request.target: request for request in self.requests}
        pairs: list[tuple[ObservationRequest, EscalationDecision]] = []
        for decision in self.granted():
            request = by_target.get(decision.target)
            if request is None:
                raise ContractError(
                    f"granted escalation for target {decision.target!r} has no matching "
                    "ObservationRequest; Stage 4 may not collect what it did not plan"
                )
            pairs.append((request, decision))
        return tuple(pairs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "requests": [request.to_dict() for request in self.requests],
            "refused": [[action.value, reason] for action, reason in self.refused],
            "escalations": [decision.to_dict() for decision in self.escalations],
        }


# --- CBF-F13 ----------------------------------------------------------------


def plan_discriminating_observation(
    field: CausalBeliefField,
    *,
    cones: Mapping[str, IncidentFutureCone] | None = None,
    shadow: SensorShadow | None = None,
    observation: AdaptiveObservationPolicy | None,
    now_ns: int,
    model: VisibilityModel | None = None,
    costs: Mapping[SensorAction, SensorCost] = SENSOR_COSTS,
    max_escalations: int = DEFAULT_HORIZON_ESCALATIONS,
) -> ObservationPlan:
    """Plan the observation that would best separate the leading worlds. CBF-F13.

    The order of operations is the contract. Simulate first, refuse cheaply, and only
    then hand the survivors to Stage 1's AOP. Nothing before ``consider()`` touches a
    sensor, and nothing after it does either.
    """
    if not isinstance(now_ns, int) or isinstance(now_ns, bool) or now_ns < 0:
        raise ContractError(f"plan_discriminating_observation.now_ns must be >= 0, got {now_ns!r}")
    candidates = tuple(SensorAction)[:MAX_CANDIDATE_ACTIONS]
    consequence = _consequence(field)
    blind = frozenset() if shadow is None else frozenset(shadow.blind_signals())

    requests: list[ObservationRequest] = []
    refused: list[tuple[SensorAction, str]] = []

    for action in candidates:
        outcome = _consider_action(
            field,
            action,
            cones=cones,
            model=model,
            costs=costs,
            observation=observation,
            consequence=consequence,
            blind=blind,
        )
        if isinstance(outcome, ObservationRequest):
            requests.append(outcome)
        else:
            refused.append(outcome)

    requests.sort(key=lambda request: (-request.utility, request.sensor_method.value))
    escalations = _escalate(
        field,
        requests,
        observation=observation,
        now_ns=now_ns,
        consequence=consequence,
        max_escalations=max_escalations,
    )
    return ObservationPlan(
        requests=tuple(requests), refused=tuple(refused), escalations=escalations
    )


def _consider_action(
    field: CausalBeliefField,
    action: SensorAction,
    *,
    cones: Mapping[str, IncidentFutureCone] | None,
    model: VisibilityModel | None,
    costs: Mapping[SensorAction, SensorCost],
    observation: AdaptiveObservationPolicy | None,
    consequence: float,
    blind: frozenset[str],
) -> ObservationRequest | tuple[SensorAction, str]:
    """Either a request worth making, or the action paired with the reason it was refused.

    Every refusal carries its own sentence. A single generic "refused" would make the
    plan unauditable, and the refusal reasons are the evidence that §17's do-not-spend
    rule is what kept telemetry down rather than a broken simulator.
    """
    discrimination = simulate_sensor_value(field, action, cones=cones, model=model)
    if discrimination < MIN_DISCRIMINATION_TO_SPEND:
        return (
            action,
            f"expected discrimination {discrimination:.4f} below "
            f"MIN_DISCRIMINATION_TO_SPEND {MIN_DISCRIMINATION_TO_SPEND}",
        )
    cost = costs.get(action)
    if cost is None or not cost.is_measured:
        return (action, UNMEASURED_COST_REASON)
    if observation is None:
        return (action, NO_OBSERVATION_POLICY)
    total = cost.total()
    if total is None or total <= 0.0:
        return (action, NON_POSITIVE_COST_REASON)
    signals = ACTION_SIGNALS[action] - blind
    if not signals:
        return (action, "every signal this action reaches is inside the sensor shadow")
    return ObservationRequest(
        sensor_method=action,
        target=_target(field, action),
        signals=signals,
        discrimination=discrimination,
        consequence=consequence,
        cost=cost,
        utility=discrimination * consequence / total,
    )


def _escalate(
    field: CausalBeliefField,
    requests: Sequence[ObservationRequest],
    *,
    observation: AdaptiveObservationPolicy | None,
    now_ns: int,
    consequence: float,
    max_escalations: int,
) -> tuple[EscalationDecision, ...]:
    """Hand the top requests to Stage 1's AOP. The ONLY escalation path in Stage 4.

    ``AdaptiveObservationPolicy.consider`` decides. Stage 4 supplies the three factors
    it is able to compute and records whatever comes back, including the refusal string
    verbatim. It does not retry, does not raise a cap and does not keep its own
    escalation ledger (ADR-0035).
    """
    if observation is None:
        return ()
    if not isinstance(max_escalations, int) or max_escalations < 0:
        raise ContractError(f"max_escalations must be >= 0, got {max_escalations!r}")
    uncertainty = _uncertainty(field)
    decisions: list[EscalationDecision] = []
    for request in tuple(requests)[:max_escalations]:
        decisions.append(
            observation.consider(
                target=request.target,
                uncertainty=uncertainty,
                security_potential=consequence,
                causal_relevance=min(1.0, max(0.0, request.discrimination)),
                now_ns=now_ns,
            )
        )
    return tuple(decisions)


def _consequence(field: CausalBeliefField) -> float:
    """Highest consequence among the worlds still in the field.

    The maximum, not the mean: the reason to spend telemetry on an ambiguous incident is
    the worst explanation still standing, and averaging it away is how a real threat
    gets planned out of the budget.
    """
    worlds = tuple(getattr(field, "worlds", ()))
    if not worlds:
        return 0.0
    return max(float(world.latent_state.consequence) for world in worlds)


def _uncertainty(field: CausalBeliefField) -> float:
    worlds = tuple(getattr(field, "worlds", ()))
    if not worlds:
        return 0.0
    return max(0.0, min(1.0, max(float(world.uncertainty) for world in worlds)))


def _target(field: CausalBeliefField, action: SensorAction) -> str:
    """The AOP target string for one action on one incident.

    Per-action rather than per-incident, because AOP deduplicates on the target and one
    shared target would silently collapse six distinct observation requests into one.
    """
    incident = str(getattr(field, "incident_id", "incident"))
    return f"{incident}:{action.value}"
