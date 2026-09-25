"""The nine ordered LUCID steps, as free functions over an engine.

``engine/lucid.py`` owns the *order*; this module owns each step's body. The split
is a size constraint honestly met — the spec bounds ``lucid.py`` at 600 lines and
the repository bounds every module at ~800 — and it has one real benefit: a step is
a function of ``(engine, field, ...)`` returning ``(field, work_units)``, so
nothing here can accumulate hidden state between transitions.

**Every step is wrapped in :class:`~pocketsec.stage4.engine.degradation.guarded`
with its own ``Subsystem``.** That is the whole of D4.17 as it applies to the loop:
a step that raises returns the field its predecessor produced, writes one
``DegradationRecord``, and the loop continues. A broken tension engine must not
stop world birth, because the residual is the only mechanism that can notice an
explanation nobody holds.

``engine`` is typed as :class:`LucidLike` rather than ``LucidEngine`` to keep the
import one-directional: ``lucid.py`` imports this module, never the reverse.
"""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Any, Protocol

from pocketsec.stage1.causal.memory import CausalNode
from pocketsec.stage1.ssir.transition import SSIRTransitionV1
from pocketsec.stage4.claims.compiler import CompiledClaim, compile_typed_claim_graph
from pocketsec.stage4.claims.graph import EMPTY_CLAIM_GRAPH, ClaimGraph
from pocketsec.stage4.engine.degradation import DegradationLedger, Subsystem, guarded
from pocketsec.stage4.engine.lucid_support import (
    BUDGET_KIND_FOR,
    WORK_UNITS,
    IncidentState,
    attach_evidence,
    bounded_credit,
    death_cause,
    regimes_for,
    retain_evidence,
    retain_shadow_evidence,
    with_truncations,
)
from pocketsec.stage4.graph.sparse_world_graph import Truncation, WorldGraphNode
from pocketsec.stage4.identifiability.resolution import IdentifiabilityVerdict
from pocketsec.stage4.tension.evidence_tension import calculate_evidence_tension
from pocketsec.stage4.visibility.model import VisibilityModel, signals_of_transition
from pocketsec.stage4.visibility.sensor_shadow import (
    SensorShadow,
    estimate_sensor_shadow,
    visibility_adjusted_confidence,
)
from pocketsec.stage4.worlds.field import CausalBeliefField
from pocketsec.stage4.worlds.lifecycle import (
    BirthRefusal,
    fission_world,
    fuse_worlds,
    kill_world,
    prune_dominated_worlds,
    residual_from_transition,
    spawn_world,
)
from pocketsec.stage4.worlds.world import SecurityWorldV1

__all__ = [
    "LucidLike",
    "accumulate_evidence",
    "charge",
    "compile_claims",
    "confidence_of",
    "fission_and_fuse",
    "free_energy_term",
    "integrate",
    "kill",
    "optional_passes",
    "plan_observation",
    "prune",
    "spawn",
    "tension",
    "verbalize",
    "visibility",
]

#: Repeats for the one-off sensor-cost measurement. ``measure_sensor_costs``' own
#: default, deliberately: a first draft cut it to 8 to save time and the *ordering* of
#: the two cheapest actions changed between 8 and 64 repeats (measured this session:
#: ``COLLECT_PROCESS_HASH``/``CAPTURE_DNS_METADATA`` swapped, 0.81 ms against 5.38 ms
#: per engine, loadavg 0.90 1.69 3.28). A cost table whose ranking depends on how hard
#: it was measured is not a measurement, and 5 ms once per engine is not a cost worth
#: buying it with.
_COST_REPEATS: int = 64


class LucidLike(Protocol):
    """What a step needs from the engine: configuration, the model, the ledger.

    Structural rather than a concrete type so ``lucid.py`` imports this module and
    not the other way around. Nothing here mutates the engine.
    """

    config: Any
    visibility: VisibilityModel
    observation: Any
    cells: Any
    degradation: DegradationLedger
    #: Measured ``SensorAction -> SensorCost`` table, or ``None`` for "measure on
    #: first use". The module default ``SENSOR_COSTS`` is UNMEASURED and the planner
    #: refuses every action priced from it, so a planner called without a measured
    #: table can never issue a request (see :func:`plan_observation`).
    sensor_costs: Any


def _scope(engine: LucidLike, subsystem: Subsystem, field: Any, fallback: Any) -> guarded:
    return guarded(
        subsystem, engine.degradation, at_sequence=field.at_sequence, fallback=fallback
    )


# --- step 1 ------------------------------------------------------------------


def integrate(
    engine: LucidLike,
    field: CausalBeliefField,
    transition: SSIRTransitionV1,
    spine: Sequence[CausalNode],
    state: IncidentState,
) -> tuple[CausalBeliefField, int]:
    """Record the transition, its signals, its spine nodes and its evidence."""
    scope = _scope(engine, Subsystem.WORLD_GRAPH, field, field)
    with scope:
        state.transition_count += 1
        state.last_signals = frozenset(signals_of_transition(transition))
        state.observed |= state.last_signals
        losses: list[Truncation] = list(retain_shadow_evidence(state, transition))
        for node in spine:
            losses.extend(
                state.graph.add(
                    WorldGraphNode(
                        signature=node.signature,
                        causal_credit=bounded_credit(node.delta_phi),
                        contradiction_value=0.0,
                        discrimination_value=0.0,
                        mandatory=bool(transition.is_high_consequence),
                        state_delta_mask=int(node.state_delta_mask),
                    )
                )
            )
            if node.parent_signature:
                losses.extend(state.graph.link(node.parent_signature, node.signature))
        current, lineage = retain_evidence(field, transition.evidence)
        scope.result = with_truncations(current, (*losses, *lineage))
    return scope.result, WORK_UNITS["integrate"] * (1 + len(spine))


# --- step 2 ------------------------------------------------------------------


def visibility(
    engine: LucidLike, field: CausalBeliefField, state: IncidentState
) -> tuple[SensorShadow, int]:
    """Refit the shadow over the signals the live worlds depend on seeing.

    Walks the worlds' *expectations*, never what arrived: a shadow derived from
    observed evidence could not contain the evidence that never came.
    """
    expected = sorted(
        {
            signal
            for world in field.worlds
            for signal in (world.expected_evidence | world.visibility_requirements)
        }
    )
    fallback = field.sensor_shadow or SensorShadow(regions=(), truncated=False)
    scope = _scope(engine, Subsystem.ACTIVE_SENSING, field, fallback)
    with scope:
        # Only the shadow-changing incomplete transitions are held (see
        # ``retain_shadow_evidence``), so this is O(signal vocabulary) per update
        # rather than O(incident length): the same shadow, at a bounded cost.
        scope.result = estimate_sensor_shadow(
            engine.visibility, expected=expected, transitions=tuple(state.shadow_evidence)
        )
    return scope.result, WORK_UNITS["visibility"] * (1 + len(expected))


# --- step 3 ------------------------------------------------------------------


def tension(
    engine: LucidLike,
    field: CausalBeliefField,
    transition: SSIRTransitionV1,
    shadow: SensorShadow,
    state: IncidentState,
) -> tuple[CausalBeliefField, int]:
    """Recompute tension per world, carrying each world's own history forward."""
    scope = _scope(engine, Subsystem.WORLD_LIFECYCLE, field, field)
    with scope:
        worlds: list[SecurityWorldV1] = []
        for world in field.worlds:
            current = calculate_evidence_tension(
                world,
                transition,
                shadow=shadow,
                model=engine.visibility,
                history=state.tension.get(world.world_id),
                observed=frozenset(state.observed),
            )
            state.tension[world.world_id] = current
            worlds.append(replace(world, tension=current))
        scope.result = field.with_worlds(worlds)
    return scope.result, WORK_UNITS["tension"] * (1 + len(field.worlds))


# --- step 4 ------------------------------------------------------------------


def kill(
    engine: LucidLike, field: CausalBeliefField, state: IncidentState
) -> tuple[CausalBeliefField, tuple[tuple[str, str], ...], int]:
    """Retire refuted worlds, before any spawn, keeping a tombstone for each.

    The last world is never killed here: a field with no worlds cannot abstain in a
    way that names anything, and the UNKNOWN world is a legitimate survivor.
    """
    killed: list[tuple[str, str]] = []
    scope = _scope(engine, Subsystem.WORLD_LIFECYCLE, field, field)
    with scope:
        current = field
        for world in field.worlds:
            cause = death_cause(state.tension.get(world.world_id))
            if cause is None or len(current.worlds) <= 1:
                continue
            found = state.tension.get(world.world_id)
            detail = (
                f"total={found.total:.4f} sustained={found.sustained_steps}"
                if found is not None
                else str(cause)
            )
            current, stone = kill_world(current, world.world_id, cause, detail)
            state.tombstones.record(stone)
            killed.append((world.world_id, cause.value))
        scope.result = current
    return scope.result, tuple(killed), WORK_UNITS["kill"] * (1 + len(field.worlds))


# --- steps 5 and 6 -----------------------------------------------------------


def fission_and_fuse(
    engine: LucidLike, field: CausalBeliefField
) -> tuple[
    CausalBeliefField,
    tuple[tuple[str, tuple[str, str]], ...],
    tuple[tuple[tuple[str, str], str], ...],
    int,
]:
    """Split incompatible worlds, merge equivalent ones.

    Charged for the O(K^2) equivalence scan rather than for the splits: the scan
    runs whether or not anything fuses, and charging only on success would price
    this mechanism at zero on exactly the runs that would keep it.
    """
    fissioned: list[tuple[str, tuple[str, str]]] = []
    fused: list[tuple[tuple[str, str], str]] = []
    count = len(field.worlds)
    scope = _scope(engine, Subsystem.WORLD_LIFECYCLE, field, field)
    with scope:
        current = field
        for world in field.worlds:
            regimes = regimes_for(world)
            if regimes is None:
                continue
            current, children = fission_world(current, world.world_id, regimes)
            if children is not None:
                fissioned.append((world.world_id, children))
        ids = [world.world_id for world in current.worlds]
        for index, left in enumerate(ids):
            for right in ids[index + 1 :]:
                if current.world(left) is None or current.world(right) is None:
                    continue
                current, survivor = fuse_worlds(current, left, right)
                if survivor is not None:
                    fused.append(((left, right), survivor))
        scope.result = current
    units = WORK_UNITS["fission_fusion"] * (1 + count + count * count)
    return scope.result, tuple(fissioned), tuple(fused), units


# --- step 7 ------------------------------------------------------------------


def spawn(
    engine: LucidLike,
    field: CausalBeliefField,
    transition: SSIRTransitionV1,
    shadow: SensorShadow,
    state: IncidentState,
) -> tuple[CausalBeliefField, tuple[str, ...], int]:
    """Birth from the unexplained residual — after the kills, so a slot exists."""
    scope = _scope(engine, Subsystem.WORLD_LIFECYCLE, field, field)
    born: list[str] = []
    with scope:
        residual = residual_from_transition(
            transition, field.worlds, shadow=shadow, previous=state.residual
        )
        state.residual = residual
        current, world_id, refusal = spawn_world(
            field,
            residual,
            shadow=shadow,
            epoch_id=field.epoch_id,
            tombstones=state.tombstones,
        )
        if world_id is not None:
            born.append(world_id)
            current = attach_evidence(current, world_id, transition.evidence)
        elif refusal is BirthRefusal.FIELD_AT_CAPACITY:
            current = with_truncations(current, (_capacity_loss(current, residual),))
        scope.result = current
    return scope.result, tuple(born), WORK_UNITS["spawn"] * (1 + len(field.worlds))


def _capacity_loss(field: CausalBeliefField, residual: Any) -> Truncation:
    """The explanation the world bound refused to create, as an explicit loss.

    ``spawn_world`` refuses a birth at ``max_worlds`` and the step used to discard
    that refusal, so the world that would have been born next — possibly the true
    one — vanished without a record, while the findings document certified that
    hitting the bound "degrades explicitly" (S4-FC-05 / S4-RES-02). The identifier
    is the residual's signal set, so the same refused explanation is one record
    however many transitions re-offer it, and ``consequence_lost`` is the residual's
    own Φ-scale consequence: an auditor can tell a bound that shed noise from one
    that shed the answer.
    """
    signals = ",".join(sorted(residual.signals)) or "no-signal"
    return Truncation(
        what="world",
        identifier=f"{field.incident_id}:unborn:{signals}"[:256],
        reason=f"field_at_capacity:max_worlds={field.max_worlds}",
        consequence_lost=float(residual.consequence),
    )


# --- step 8 ------------------------------------------------------------------


def prune(engine: LucidLike, field: CausalBeliefField) -> tuple[CausalBeliefField, int]:
    """Dominance pruning, with §30's fifth clause as a hard veto."""
    scope = _scope(engine, Subsystem.WORLD_LIFECYCLE, field, field)
    with scope:
        pruned, _ids = prune_dominated_worlds(field)
        scope.result = pruned
    return scope.result, WORK_UNITS["prune"] * (1 + len(field.worlds))


# --- step 9 ------------------------------------------------------------------


def charge(
    engine: LucidLike,
    field: CausalBeliefField,
    state: IncidentState,
    spend: Mapping[str, int],
    started_ns: int,
) -> CausalBeliefField:
    """Charge the budget per kind and let ``safe_prune`` hold the bound.

    Per kind rather than as one lump so ``spend_report()`` names which mechanism
    spent what: a total says the bound held, a breakdown says which flag to ablate.
    ``safe_prune`` may never remove the last non-benign world or turn an unresolved
    field benign (§45), and every removal leaves a ``Truncation``. Wall clock is
    observed here, never asserted (§2.8).
    """
    scope = _scope(engine, Subsystem.WORLD_GRAPH, field, field)
    with scope:
        for step, units in sorted(spend.items()):
            state.budget.charge(BUDGET_KIND_FOR[step], units)
        state.budget.observe(time.perf_counter_ns() - started_ns)
        pruned, losses = state.budget.safe_prune(field)
        scope.result = with_truncations(pruned, losses)
    return scope.result


# --- the flagged passes ------------------------------------------------------


def optional_passes(
    engine: LucidLike,
    field: CausalBeliefField,
    spine: Sequence[CausalNode],
    state: IncidentState,
    spend: dict[str, int],
) -> CausalBeliefField:
    """Run the flagged mechanisms, writing each one's units into ``spend``."""
    worlds = max(1, len(field.worlds))
    if engine.config.enable_sequential_evidence:
        spend["sequential_evidence"] = WORK_UNITS["sequential_evidence"] * worlds
        accumulate_evidence(engine, field, state)
    if engine.config.enable_active_sensing:
        spend["active_sensing"] = WORK_UNITS["active_sensing"] * worlds
        plan = plan_observation(engine, field)
        # Granted escalations are counted so the engine can charge them to the §29
        # budget and the §20 horizon. Before this, ``max_sensor_escalations`` could
        # never trigger: nothing charged the escalation kind (S4-SEC-09).
        state.pending_escalations += len(plan.granted()) if plan is not None else 0
    if engine.config.enable_free_energy:
        spend["free_energy"] = WORK_UNITS["free_energy"] * worlds
    if engine.config.enable_cell_feedback:
        spend["cell_feedback"] = WORK_UNITS["cell_feedback"] * max(
            1, len(engine.cells.cell_ids())
        )
    return _counterfactual_family(engine, field, spine, state, spend)


def _counterfactual_family(
    engine: LucidLike,
    field: CausalBeliefField,
    spine: Sequence[CausalNode],
    state: IncidentState,
    spend: dict[str, int],
) -> CausalBeliefField:
    """D4.6 and D4.11 under §29's shared cap, with the refusal recorded.

    The cap is checked before the work, and declining writes a ``Truncation``: an
    attacker who can make the field branch must not also be able to make it reason
    without limit, and the bound holding has to be visible in the incident record
    rather than only in a counter.
    """
    if not (
        engine.config.enable_counterfactual
        or engine.config.enable_self_questioning
        or engine.config.enable_stress
    ):
        return field
    cap = engine.config.budget.max_counterfactuals
    if state.budget.spend_report()["counterfactuals"] >= cap:
        return with_truncations(
            field,
            (
                Truncation(
                    what="claim",
                    identifier=f"{field.incident_id}:counterfactual",
                    reason=f"max_counterfactuals:{cap}",
                    consequence_lost=0.0,
                ),
            ),
        )
    worlds = max(1, len(field.worlds))
    if engine.config.enable_counterfactual:
        spend["counterfactual"] = WORK_UNITS["counterfactual"] * max(1, len(spine))
        _intervene(engine, field, spine)
    if engine.config.enable_self_questioning:
        spend["self_questioning"] = WORK_UNITS["self_questioning"] * worlds
        _question(engine, field, spine, state)
    if engine.config.enable_stress:
        spend["stress"] = WORK_UNITS["stress"] * worlds
    return field


def accumulate_evidence(
    engine: LucidLike, field: CausalBeliefField, state: IncidentState
) -> None:
    """§31's e-process per world. The import is local, and that is deliberate.

    A module-scope import of another package's leaf would make the engine — and
    therefore Stages 1-3's detection path while the engine is attached —
    unimportable if that package were absent, which is the opposite of the
    optionality property D4.17 exists to guarantee.
    """
    scope = _scope(engine, Subsystem.SEQUENTIAL_EVIDENCE, field, None)
    with scope:
        from pocketsec.stage4.evidence.sequential import (
            SIGNAL_VOCABULARY,
            StopReason,
            benign_null_likelihood_ratio,
            start_benign_null_evidence,
        )

        # Restricted to the null's closed vocabulary, because that is what makes
        # ``anytime_valid`` mean anything: widening it to whatever telemetry
        # arrived would void the guarantee while the field still read True.
        #
        # ONE likelihood ratio per transition, over THIS transition's observation.
        # The first version multiplied in the ratio of the incident's cumulative
        # ``state.observed`` on every update, so a signal seen once was re-applied
        # on every later transition — N counts of one piece of evidence under an
        # ``anytime_valid=True`` stamp (S4-REV-02).
        seen = sorted(state.last_signals & SIGNAL_VOCABULARY)
        for world in field.worlds:
            current = state.sequential.get(world.world_id) or start_benign_null_evidence(
                world.world_id
            )
            if current.stop_reason is not StopReason.STILL_RUNNING:
                # A stopped e-process stays stopped. Restarting it would count the
                # same evidence twice and make the anytime-validity claim false
                # rather than merely unproven.
                continue
            state.sequential[world.world_id] = current.update(
                benign_null_likelihood_ratio(
                    seen,
                    expected=frozenset(world.expected_evidence) & SIGNAL_VOCABULARY,
                    forbidden=frozenset(world.forbidden_evidence) & SIGNAL_VOCABULARY,
                )
            )


def plan_observation(engine: LucidLike, field: CausalBeliefField) -> Any:
    """CBF-F13 through Stage 1's AOP and nowhere else (ADR-0035).

    The cost table is passed **explicitly**. Omitting it silently selects
    ``active_plan.SENSOR_COSTS``, whose every entry is UNMEASURED by design, and
    ``ObservationRequest`` refuses an unmeasured cost — so the engine issued zero
    requests on every incident and CBF-F13/F14 could not fire at all. Measured
    against ``build_incident_corpus(count=12, seed=11)`` this session: 0 requests
    and 6 refusals per step, every refusal reading "no measured cost". The table
    comes from the stage's own ``measure_sensor_costs``, which reports within-run
    ratios rather than absolute microseconds (spec §2.8), so nothing here is a
    chosen constant.
    """
    scope = _scope(engine, Subsystem.ACTIVE_SENSING, field, None)
    with scope:
        from pocketsec.stage4.cones.incident_cone import compose_cones
        from pocketsec.stage4.sensing.active_plan import plan_discriminating_observation

        cones = compose_cones(field)
        horizon = field.horizon
        scope.result = plan_discriminating_observation(
            field,
            cones=cones,
            shadow=field.sensor_shadow,
            observation=engine.observation,
            now_ns=time.monotonic_ns(),
            model=engine.visibility,
            costs=_costs_for(engine, field, cones),
            # The per-incident escalation bound (§20/§29): an incident that has spent
            # its escalations hands AOP nothing more, instead of up to four
            # requests on every update for the life of the incident.
            max_escalations=(
                horizon.escalations_remaining() if horizon is not None else 0
            ),
        )
    return scope.result


def _costs_for(engine: LucidLike, field: CausalBeliefField, cones: Any) -> Any:
    """The engine's measured cost table, measured once and cached on the engine.

    Measured lazily rather than at construction because the payload half of the
    measurement is taken from a real field, and an engine is built before any
    incident is open. Timed at 5.38 ms per call at ``_COST_REPEATS`` on this host
    (loadavg 0.90 1.69 3.28), so measuring once per engine is not a per-step cost.
    """
    from pocketsec.stage4.sensing.simulate import measure_sensor_costs

    cached = getattr(engine, "sensor_costs", None)
    if cached is not None:
        return cached
    measured = measure_sensor_costs(
        field, cones=cones, model=engine.visibility, repeats=_COST_REPEATS
    )
    # Cached on the engine, not recomputed: a cost table that changed between
    # steps would make two refusals in the same incident incomparable.
    engine.sensor_costs = measured  # type: ignore[misc]
    return measured


def _intervene(engine: LucidLike, field: CausalBeliefField, spine: Sequence[CausalNode]) -> None:
    """CBF-F09/F10, guarded: a counterfactual failure drops CF claims only."""
    scope = _scope(engine, Subsystem.COUNTERFACTUAL, field, ())
    with scope:
        from pocketsec.stage4.counterfactual.intervention import calculate_responsibility_flux

        scope.result = calculate_responsibility_flux(
            field, tuple(spine), at_sequence=field.at_sequence
        )


def _question(
    engine: LucidLike,
    field: CausalBeliefField,
    spine: Sequence[CausalNode],
    state: IncidentState,
) -> None:
    """CBF-F15 over the leading world. A challenge that raises is not a verdict."""
    scope = _scope(engine, Subsystem.COUNTERFACTUAL, field, ())
    with scope:
        from pocketsec.stage4.counterfactual.questions import self_question_world

        leaders = field.leaders(n=1)
        if leaders:
            scope.result = self_question_world(
                field,
                leaders[0].world_id,
                shadow=field.sensor_shadow,
                graph=field.claim_graph,
                observed=frozenset(state.observed),
                spine=tuple(spine),
            )


def free_energy_term(field: CausalBeliefField) -> float:
    """§18's objective term: expected consequence weighted by support spread.

    Reported, not believed. The flag is **off** by default because §18 states
    plainly that the objective is removed unless it beats plain information-gain
    planning, and that comparison is ADR-0038's rather than this module's.
    """
    support = field.support_vector()
    if not support:
        return 0.0
    spread = max(support.values()) - min(support.values())
    consequence = max(
        (float(world.latent_state.consequence) for world in field.worlds), default=0.0
    )
    return float(consequence * (1.0 - spread))


# --- resolution helpers ------------------------------------------------------


def compile_claims(
    engine: LucidLike,
    field: CausalBeliefField,
    shadow: SensorShadow | None,
    verdict: IdentifiabilityVerdict,
) -> tuple[ClaimGraph, tuple[CompiledClaim, ...], int]:
    """CBF-F18. A compiler failure emits no authoritative claim, never a guess."""
    scope = _scope(engine, Subsystem.CLAIM_COMPILER, field, (EMPTY_CLAIM_GRAPH, ()))
    with scope:
        scope.result = compile_typed_claim_graph(field, shadow=shadow, verdict=verdict)
    graph, compiled = scope.result
    return graph, compiled, WORK_UNITS["claims"] * (1 + len(field.worlds))


def verbalize(
    engine: LucidLike, field: CausalBeliefField, compiled: Sequence[CompiledClaim]
) -> None:
    """Run the guard, never a model. ``verbalizer=None`` is the shipped config."""
    scope = _scope(engine, Subsystem.VERBALIZER, field, ())
    with scope:
        from pocketsec.stage4.claims.verbalizer import verbalize_guarded

        scope.result = tuple(verbalize_guarded(item, None) for item in compiled)


def confidence_of(
    engine: LucidLike,
    field: CausalBeliefField,
    *,
    state: IncidentState,
    shadow: SensorShadow | None,
) -> float:
    """0.0 when there is no shadow model: an unmeasured shadow is not a clear view."""
    if shadow is None:
        return 0.0
    leaders = field.leaders(n=1)
    raw = 1.0 - float(leaders[0].uncertainty) if leaders else 0.0
    scope = _scope(engine, Subsystem.CALIBRATION, field, 0.0)
    with scope:
        scope.result = visibility_adjusted_confidence(
            raw_confidence=raw,
            expected=frozenset(
                signal for world in field.worlds for signal in world.expected_evidence
            ),
            observed=frozenset(state.observed),
            shadow=shadow,
            model=engine.visibility,
        )
    return float(scope.result)
