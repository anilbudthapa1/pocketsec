"""D4.2 / CBF-F01 — the LUCID update loop: the one place the whole field changes.

Everything else in Stage 4 is a mechanism. This module is the *order* those
mechanisms run in, and the order is part of the contract:

    integrate evidence -> update visibility and shadow -> recompute tension
    -> kill -> fission -> fuse -> spawn -> prune dominated -> charge budget

Spawn happens **after** kill deliberately. A field at ``max_worlds`` whose worst
worlds are about to die by contradiction would otherwise refuse a birth with
``FIELD_AT_CAPACITY`` and lose the true world to a queue position. Killing first
frees the slot the evidence just earned.

**Every flag in :class:`LucidConfig` changes ``work_units``, and
``tests/test_stage4_runtime.py`` asserts it.** ADR-0116 said two Stage 2 mechanisms
were "default off" and no constant in the code said so; the Future Cone then ran on
every deep event while being described as removed (``PROGRESS.md`` G2.6). A flag the
engine does not honour is worse than no flag, because it turns a measurement into a
story. Units are charged for the *attempt*: a pairwise equivalence scan is real work
whether or not it fuses anything, and charging only on success would price an
expensive mechanism at zero on exactly the runs that would keep it.

Work units, not milliseconds, are the primary bound (§2.8) — a Stage 2 gate read the
same two passes as 7x slower at load 23-67 than at load 8-12. ``max_reasoning_ms``
stays advisory and observed-only.

Nothing past argument validation raises out of ``update``, ``resolve`` or
``close_incident``. Every subsystem call goes through ``engine/degradation.guarded``
with its own ``Subsystem`` — including the shadow verdict adjustment, the gap pricing,
the uncertainty read-out and the Stage 5 export, which the first version ran
unguarded while this docstring said otherwise (S4-FC-03) — because Stage 4 is an
attachment and Stages 1-3 must keep producing verdicts when the cognition above them
breaks (D4.17, G4.11). A guarded failure can only make Stage 4's contribution *less*
committal — never benign — and it does so for **the incident it happened in**: each
incident carries its own degradation ledger, rolled up into ``engine.degradation``
for reporting, so one fault no longer downgrades every later incident (S4-REV-06).

**The work bound is enforced before the work, not booked after it.** Two layers:
once the §29 reasoning-unit budget is spent, the optional and O(K^2) passes are
refused with a recorded ``Truncation``; once the §20 ``ResolutionHorizon`` is spent
(transitions, work units or escalations), the incident stops reasoning altogether —
later transitions only extend the evidence lineage, and a committal verdict reached
before them is downgraded because it did not see them. The first version only
saturated a counter and ran every step anyway (S4-REV-01 / S4-FC-04 / S4-RES-03).

Step bodies live in ``engine/lucid_steps.py`` and the arithmetic in
``engine/lucid_support.py``, so this file stays the loop and stays inside its
600-line bound.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, field as dataclass_field
from dataclasses import replace
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.causal.memory import CausalNode
from pocketsec.stage1.observation.policy import AdaptiveObservationPolicy
from pocketsec.stage1.ssir.transition import SSIRTransitionV1
from pocketsec.stage4.claims.compiler import CompiledClaim
from pocketsec.stage4.claims.graph import EMPTY_CLAIM_GRAPH, ClaimGraph
from pocketsec.stage4.crystal.handoff import EMPTY_KNOWLEDGE, CrystalKnowledge
from pocketsec.stage4.engine import lucid_bounds as bounds
from pocketsec.stage4.engine import lucid_steps as steps
from pocketsec.stage4.engine.degradation import (
    DegradationLedger,
    DegradationRecord,
    Subsystem,
    downgrade_verdict,
    guarded,
)
from pocketsec.stage4.engine.lucid_support import (
    INERT_FLAGS,
    WORK_UNITS,
    IncidentState,
    gaps_from,
    uncertainty_of,
    unknown_verdict,
    with_truncations,
)
from pocketsec.stage4.graph.entropy_budget import EntropyBudget
from pocketsec.stage4.graph.sparse_world_graph import Truncation
from pocketsec.stage4.identifiability.horizon import HorizonOutcome, ResolutionHorizon
from pocketsec.stage4.identifiability.resolution import (
    IdentifiabilityState,
    IdentifiabilityVerdict,
    test_identifiability,
)
from pocketsec.stage4.stage5_interface import CBFResolutionV1, InformationGap
from pocketsec.stage4.visibility.model import VisibilityModel
from pocketsec.stage4.visibility.sensor_shadow import visibility_adjusted_verdict
from pocketsec.stage4.worlds.field import MAX_WORLDS, CausalBeliefField

__all__ = [
    "INERT_FLAGS",
    "MAX_OPEN_INCIDENTS",
    "MAX_UPDATE_STEPS_PER_TRANSITION",
    "IncidentResolution",
    "LucidConfig",
    "LucidEngine",
    "UpdateOutcome",
]

#: Internal passes one transition may cost. The loop has nine ordered steps plus at
#: most ``MAX_WORLDS`` per-world tension recomputations, so 16 is a real ceiling
#: rather than a decorative one; exceeding it records a ``Truncation``.
MAX_UPDATE_STEPS_PER_TRANSITION: int = 16

#: Incidents whose reasoning state the engine holds at once. Endpoint state is
#: bounded (MEMORY.md) and per-incident state is the largest thing Stage 4 keeps.
MAX_OPEN_INCIDENTS: int = 8


@dataclass(frozen=True, slots=True)
class LucidConfig:
    """What the loop may do, and what it may spend.

    Only two flags default **on**: ``enable_active_sensing`` and
    ``enable_fission_fusion``, the two whose output reaches the decision (the plan
    feeds ``test_identifiability``; fission/fusion replaces the field). Every flag in
    :data:`INERT_FLAGS` defaults **off**, because its result is discarded or never
    read: turning it on buys work units and nothing else. That is not free — the
    §20 horizon is charged in work units, so on ``build_incident_corpus(count=60,
    seed=11)`` the five formerly-on inert flags spent 250905 - 241266 = 9639 units and
    closed the horizon earlier on 29 of 60 incidents, which then spawned fewer
    worlds (measured this session; S4-FC-08 / S4-CPLX-02). G4.10's ablation excludes
    inert flags rather than reporting a structural zero as a measured delta.
    """

    max_worlds: int = MAX_WORLDS
    budget: EntropyBudget = dataclass_field(default_factory=EntropyBudget)
    enable_free_energy: bool = False
    enable_sequential_evidence: bool = False
    enable_verbalizer: bool = False
    enable_active_sensing: bool = True
    enable_fission_fusion: bool = True
    enable_counterfactual: bool = False
    enable_self_questioning: bool = False
    enable_stress: bool = False
    enable_cell_feedback: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.max_worlds, int) or self.max_worlds < 1:
            raise ContractError(f"LucidConfig.max_worlds must be >= 1, got {self.max_worlds!r}")
        if not isinstance(self.budget, EntropyBudget):
            raise ContractError("LucidConfig.budget must be an EntropyBudget")
        for name in self.flag_names():
            if not isinstance(getattr(self, name), bool):
                raise ContractError(f"LucidConfig.{name} must be a bool")

    @staticmethod
    def flag_names() -> tuple[str, ...]:
        """Every ablation flag, so a test enumerates them without a literal list.

        A hand-kept list in the test would drift the first time a flag is added,
        and the drift would look like a passing test.
        """
        return (
            "enable_free_energy",
            "enable_sequential_evidence",
            "enable_verbalizer",
            "enable_active_sensing",
            "enable_fission_fusion",
            "enable_counterfactual",
            "enable_self_questioning",
            "enable_stress",
            "enable_cell_feedback",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_worlds": self.max_worlds,
            "budget": self.budget.to_dict(),
            **{name: getattr(self, name) for name in self.flag_names()},
        }


@dataclass(frozen=True, slots=True)
class UpdateOutcome:
    """Everything one transition did to the field, including what it lost."""

    field: CausalBeliefField
    spawned: tuple[str, ...]
    #: ``(world_id, DeathCause)`` per retired world. Spec D4.2 names this field
    #: ``killed``; ``kill`` is a ``FORBIDDEN_AUTHORITY_FIELDS`` token and §2.4's rule
    #: has no exemption list, so the field is ``retired`` — the same word
    #: ``WorldTombstone.retired_at_sequence`` already chose for the same collision.
    retired: tuple[tuple[str, str], ...]
    fissioned: tuple[tuple[str, tuple[str, str]], ...]
    fused: tuple[tuple[tuple[str, str], str], ...]
    truncations: tuple[Truncation, ...]
    work_units: int
    degraded: tuple[DegradationRecord, ...]
    #: Beyond the spec's field list and load-bearing for the ablation.
    #: ``free_energy`` is ``None`` when §18's objective did not run, never 0.0
    #: (ADR-0004).
    steps: int = 0
    free_energy: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.field.incident_id,
            "worlds": len(self.field.worlds),
            "spawned": list(self.spawned),
            "retired": [list(row) for row in self.retired],
            "fissioned": [[parent, list(kids)] for parent, kids in self.fissioned],
            "fused": [[list(pair), survivor] for pair, survivor in self.fused],
            "truncations": [item.to_dict() for item in self.truncations],
            "work_units": self.work_units,
            "steps": self.steps,
            "free_energy": self.free_energy,
            "degraded": [record.to_dict() for record in self.degraded],
        }


@dataclass(frozen=True, slots=True)
class IncidentResolution:
    """What LUCID concluded, with the reason and the cost attached.

    ``confidence`` comes from ``visibility_adjusted_confidence`` and can never rise
    when a sensor is dropped — falsifier F4, the most dangerous single failure
    available to this stage.
    """

    field: CausalBeliefField
    verdict: IdentifiabilityVerdict
    prediction_verdict: Verdict
    horizon_outcome: HorizonOutcome
    claim_graph: ClaimGraph
    compiled: tuple[CompiledClaim, ...]
    gaps: tuple[InformationGap, ...]
    confidence: float
    uncertainty: float
    work_units: int
    degraded: tuple[DegradationRecord, ...]

    @property
    def abstained(self) -> bool:
        return self.verdict.abstains()

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.field.incident_id,
            "verdict": self.prediction_verdict.value,
            "identifiability": self.verdict.state.value,
            "horizon_outcome": self.horizon_outcome.value,
            "abstained": self.abstained,
            "confidence": self.confidence,
            "uncertainty": self.uncertainty,
            "compiled_claims": len(self.compiled),
            "information_gaps": [gap.to_dict() for gap in self.gaps],
            "unsupported_authoritative": list(self.claim_graph.unsupported_authoritative()),
            "work_units": self.work_units,
            "degraded": [record.to_dict() for record in self.degraded],
        }


@dataclass(frozen=True, slots=True)
class _Changes:
    """What steps 1-8 did, threaded back to ``update`` without a seven-tuple.

    Private because it is an internal shape: ``UpdateOutcome`` is the public record.
    """

    spawned: tuple[str, ...]
    retired: tuple[tuple[str, str], ...]
    fissioned: tuple[tuple[str, tuple[str, str]], ...]
    fused: tuple[tuple[tuple[str, str], str], ...]
    passes: int


class LucidEngine:
    """The LUCID loop over a bounded set of competing security worlds.

    ``observation`` is Stage 1's ``AdaptiveObservationPolicy`` and it is the **only**
    observation planner (ADR-0035). ``observation=None`` is legal and means no
    sensing is possible: every request is refused and nothing escalates. Stage 4
    contains no code that enables a sensor.
    """

    def __init__(
        self,
        *,
        config: LucidConfig,
        visibility: VisibilityModel,
        observation: AdaptiveObservationPolicy | None = None,
        cells: CrystalKnowledge | None = None,
        ledger: DegradationLedger | None = None,
        sensor_costs: Mapping[Any, Any] | None = None,
    ) -> None:
        if not isinstance(config, LucidConfig):
            raise ContractError("LucidEngine needs a LucidConfig")
        if not isinstance(visibility, VisibilityModel):
            raise ContractError("LucidEngine needs a VisibilityModel; there is no default")
        self.config = config
        self.visibility = visibility
        self.observation = observation
        #: ``SensorAction -> SensorCost``. ``None`` means "measure on first plan and
        #: cache"; ``active_plan.SENSOR_COSTS`` is UNMEASURED and the planner refuses
        #: every action priced from it, so this may never silently default to it.
        self.sensor_costs = sensor_costs
        self.cells = cells if cells is not None else EMPTY_KNOWLEDGE
        self.degradation = ledger if ledger is not None else DegradationLedger()
        self._incidents: dict[str, IncidentState] = {}
        self._work_units = 0

    @property
    def work_units(self) -> int:
        """Cumulative reasoning units charged across incidents.

        Exposed because the ablation compares whole-incident cost: a flag whose work
        lands in ``resolve`` rather than ``update`` still has to be visible to a
        measurement.
        """
        return self._work_units

    def open_incident(self, incident_id: str, epoch_id: int) -> CausalBeliefField:
        """Start an incident with an empty field. No world is assumed."""
        if incident_id in self._incidents:
            raise ContractError(f"incident {incident_id!r} is already open")
        if len(self._incidents) >= MAX_OPEN_INCIDENTS:
            raise ContractError(
                f"{len(self._incidents)} incidents already open, at "
                f"MAX_OPEN_INCIDENTS={MAX_OPEN_INCIDENTS}; close one first"
            )
        state = IncidentState(self.config.budget)
        self._incidents[incident_id] = state
        return CausalBeliefField(
            incident_id=incident_id,
            epoch_id=epoch_id,
            worlds=(),
            max_worlds=self.config.max_worlds,
            horizon=ResolutionHorizon(),
            budget=self.config.budget,
            graph=state.graph,
            claim_graph=EMPTY_CLAIM_GRAPH,
        )

    def close_incident(self, field: CausalBeliefField) -> CBFResolutionV1:
        """Resolve, export the Stage 5 handoff, and drop the incident's state.

        A failed export degrades *this incident* and retries on a minimal field with
        an empty graph, then falls back to ``lucid_bounds.bare_export``; nothing
        re-runs unguarded (S4-FC-03). ``degradations`` lists THIS incident's only.
        """
        resolution = self.resolve(field)
        state = self._state(field)
        resolution_id = f"cbf-res-{field.incident_id}"
        with bounds.incident_ledger(self, state):
            exported = bounds.guarded_export(
                self,
                resolution.field,
                resolution_id=resolution_id,
                verdict=resolution.verdict,
                claim_graph=resolution.claim_graph.to_dict(),
                gaps=resolution.gaps,
                state=state,
            )
            if exported is None:
                exported = bounds.guarded_export(
                    self,
                    replace(resolution.field, worlds=(), truncations=()),
                    resolution_id=resolution_id,
                    verdict=unknown_verdict(resolution.verdict),
                    claim_graph=EMPTY_CLAIM_GRAPH.to_dict(),
                    gaps=(),
                    state=state,
                )
        if exported is None:
            exported = bounds.bare_export(field, resolution_id, state)
        self._incidents.pop(field.incident_id, None)
        return exported

    # --- the loop ------------------------------------------------------------

    def update(
        self,
        field: CausalBeliefField,
        transition: SSIRTransitionV1,
        spine: tuple[CausalNode, ...],
    ) -> UpdateOutcome:
        """CBF-F01 — one transition's worth of belief update. Never raises.

        Each step is guarded, so a failure leaves the field as its predecessor
        produced it, records one ``DegradationRecord`` against this incident, and
        the loop continues. Once the §20 horizon is spent the reasoning steps are
        refused and only the evidence lineage is extended.
        """
        state = self._state(field)
        started = time.perf_counter_ns()
        spend: dict[str, int] = {}
        before = frozenset(field.truncations)

        with bounds.incident_ledger(self, state):
            if bounds.reasoning_closed(field.horizon):
                field = bounds.horizon_closed_update(field, transition, state, spend)
                changes = _Changes(spawned=(), retired=(), fissioned=(), fused=(), passes=1)
            else:
                field, changes = self._ordered_steps(field, transition, spine, state, spend)
            charged = sum(spend.values())
            field = steps.charge(self, field, state, spend, started)
            field = bounds.charge_horizon(field, state, charged)
            degraded = state.ledger.records()
        self._work_units += charged
        return UpdateOutcome(
            field=field,
            spawned=changes.spawned,
            retired=changes.retired,
            fissioned=changes.fissioned,
            fused=changes.fused,
            truncations=tuple(item for item in field.truncations if item not in before),
            work_units=charged,
            degraded=degraded,
            steps=changes.passes,
            free_energy=(
                steps.free_energy_term(field) if self.config.enable_free_energy else None
            ),
        )

    def _ordered_steps(
        self,
        field: CausalBeliefField,
        transition: SSIRTransitionV1,
        spine: tuple[CausalNode, ...],
        state: IncidentState,
        spend: dict[str, int],
    ) -> tuple[CausalBeliefField, _Changes]:
        """Steps 1-8 in the contract's order. Step 9 (charging) is the caller's.

        Kept as one function so the order is readable in one screen, which is the
        property most likely to be broken by a well-meaning refactor: spawn after kill
        is not a style choice.
        """
        field, spend["integrate"] = steps.integrate(self, field, transition, spine, state)
        shadow, spend["visibility"] = steps.visibility(self, field, state)
        # ``at_sequence`` advances with the transition, never with the loop: a
        # tombstone's retirement point and a claim's sequence must name the evidence,
        # not how many passes the engine happened to make.
        field = replace(
            field,
            sensor_shadow=shadow,
            at_sequence=max(field.at_sequence, int(transition.sequence)),
        )
        field, spend["tension"] = steps.tension(self, field, transition, shadow, state)
        field, retired, spend["kill"] = steps.kill(self, field, state)
        passes = 4

        # Checked BEFORE the optional and O(K^2) work, not booked after it. Kill,
        # spawn and prune stay mandatory: refusing a birth or a death because the
        # budget ran out would drop the true world silently, which is worse than
        # the cost it saves.
        over_budget = state.budget.units_exhausted()
        fissioned: tuple[tuple[str, tuple[str, str]], ...] = ()
        fused: tuple[tuple[tuple[str, str], str], ...] = ()
        if self.config.enable_fission_fusion and not over_budget:
            field, fissioned, fused, spend["fission_fusion"] = steps.fission_and_fuse(
                self, field
            )
            passes += 2

        field, spawned, spend["spawn"] = steps.spawn(self, field, transition, shadow, state)
        field, spend["prune"] = steps.prune(self, field)
        if over_budget:
            field = with_truncations(
                field, (bounds.budget_refusal(field, self.config.budget.max_reasoning_units),)
            )
        else:
            field = steps.optional_passes(self, field, spine, state, spend)
        passes += 3
        if passes > MAX_UPDATE_STEPS_PER_TRANSITION:  # pragma: no cover - defensive
            field = with_truncations(
                field,
                (
                    Truncation(
                        what="world",
                        identifier=field.incident_id,
                        reason=f"max_update_steps:{MAX_UPDATE_STEPS_PER_TRANSITION}",
                        consequence_lost=0.0,
                    ),
                ),
            )
        return field, _Changes(
            spawned=spawned, retired=retired, fissioned=fissioned, fused=fused, passes=passes
        )

    # --- resolution ----------------------------------------------------------

    def resolve(self, field: CausalBeliefField) -> IncidentResolution:
        """Decide identifiability, compile the claims, and price the gaps.

        The verdict is downgraded whenever anything in THIS incident degraded, when
        transitions arrived after the horizon closed (the verdict never saw them),
        and again if the shadow cannot support it. None of these can ever make it
        *more* committal, so a dropped sensor cannot buy confidence (F4).
        """
        state = self._state(field)
        with bounds.incident_ledger(self, state):
            return self._resolve(field, state)

    def _resolve(self, field: CausalBeliefField, state: IncidentState) -> IncidentResolution:
        units = WORK_UNITS["identifiability"] * (1 + len(field.worlds))
        plan = steps.plan_observation(self, field) if self.config.enable_active_sensing else None
        shadow = field.sensor_shadow
        verdict: IdentifiabilityVerdict = self._run(
            Subsystem.WORLD_LIFECYCLE,
            field,
            unknown_verdict(None),
            lambda: test_identifiability(field, shadow=shadow, plan=plan),
        )
        graph, compiled, claim_units = steps.compile_claims(self, field, shadow, verdict)
        units += claim_units
        if self.config.enable_verbalizer:
            units += WORK_UNITS["verbalizer"] * max(1, len(compiled))
            steps.verbalize(self, field, compiled)

        horizon = field.horizon if field.horizon is not None else ResolutionHorizon()
        outcome: HorizonOutcome = self._run(
            Subsystem.WORLD_LIFECYCLE,
            field,
            HorizonOutcome.PRESERVE_UNRESOLVED,
            lambda: horizon.outcome(verdict),
        )
        proposed = self._run(
            Subsystem.ACTIVE_SENSING,
            field,
            bounds.DEGRADED_FALLBACK_VERDICT,
            lambda: (
                visibility_adjusted_verdict(verdict.to_verdict(), shadow)
                if shadow is not None
                else verdict.to_verdict()
            ),
        )
        gaps = self._run(Subsystem.ACTIVE_SENSING, field, (), lambda: gaps_from(verdict, plan))
        uncertainty = self._run(
            Subsystem.CALIBRATION, field, 1.0, lambda: uncertainty_of(field)
        )
        confidence = steps.confidence_of(self, field, state=state, shadow=shadow)
        proposed = downgrade_verdict(
            proposed, degraded=state.ledger.degraded_any() or state.refused_updates > 0
        )
        self._work_units += units
        if verdict.state is IdentifiabilityState.IDENTIFIED and verdict.leading_mechanism_id:
            state.resolutions.append(verdict.leading_mechanism_id)
        return IncidentResolution(
            # The compiled graph is written back into the resolved field, so a
            # reader of ``resolution.field.claim_graph`` measures the real graph and
            # not the empty sentinel ``open_incident`` placed there (S4-FC-10).
            field=replace(field, claim_graph=graph),
            verdict=verdict,
            prediction_verdict=proposed,
            horizon_outcome=outcome,
            claim_graph=graph,
            compiled=compiled,
            gaps=gaps,
            confidence=confidence,
            uncertainty=uncertainty,
            work_units=units,
            degraded=state.ledger.records(),
        )

    def _run(self, subsystem: Subsystem, field: CausalBeliefField, fallback: Any, call: Any) -> Any:
        """One guarded call with a declared fallback. The only way resolve calls out."""
        scope = guarded(subsystem, self.degradation, at_sequence=field.at_sequence, fallback=fallback)
        with scope:
            scope.result = call()
        return scope.result

    def resolved_mechanisms(self, incident_id: str) -> tuple[str, ...]:
        """Mechanism ids this open incident has resolved to. Read by D4.14."""
        state = self._incidents.get(incident_id)
        return tuple(state.resolutions) if state is not None else ()

    def _state(self, field: CausalBeliefField) -> IncidentState:
        state = self._incidents.get(field.incident_id)
        if state is None:
            raise ContractError(
                f"incident {field.incident_id!r} is not open; call open_incident first so its "
                "reasoning state is bounded and attributable"
            )
        return state

    def memory_bytes(self) -> int:
        """Bytes of per-incident reasoning state, for the Stage 4 resource budget.

        Includes the retained shadow evidence and each incident's own ledger. The
        first version left the incident's transition history out, so the report
        stayed at ~4 KB while real state grew without bound (S4-REV-01). The field's
        own truncation log is the caller's object and is measured by
        ``CausalBeliefField.state_bytes``.
        """
        total = self.degradation.memory_bytes()
        for state in self._incidents.values():
            total += state.memory_bytes()
        return total
