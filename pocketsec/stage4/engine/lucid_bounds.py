"""The LUCID loop's hard bounds and failure plumbing, split out of ``engine/lucid.py``.

This module is FOR the parts of the loop that decide how much Stage 4 may spend on
one incident and what happens when something breaks — the parts the review of this
wave found to be counters and conventions rather than enforcement:

* **The §20 horizon is charged and obeyed.** ``charge_horizon`` bills every update
  (one transition, its work units, the escalations AOP granted). Nothing did before,
  so ``ResolutionHorizon.exhausted()`` was always False and every unresolved incident
  asked for a higher observation tier forever (S4-REV-10). Once the horizon's
  transition or work-unit budget is spent, ``horizon_closed_update`` replaces the
  reasoning steps: the evidence lineage is still extended, and the refusal is ONE
  recorded ``Truncation`` however many transitions follow (S4-REV-01 / S4-FC-04).
* **Failures belong to the incident they happened in.** ``incident_ledger`` points
  the engine's ledger at the incident's own for the duration of a call and rolls the
  records up afterwards. One engine-lifetime ledger made a single fault downgrade
  every later incident and put its records into their Stage 5 exports (S4-REV-06,
  S4-FC-09, S4-RES-04, S4-SEC-06).
* **The Stage 5 export cannot escape.** ``guarded_export`` wraps it; the engine
  retries on a minimal field; ``bare_export`` is the last resort built from
  primitives only. The first version re-ran the failing export unguarded (S4-FC-03).

Split for size: the spec bounds ``engine/lucid.py`` at 600 lines and the loop, its
public types and these helpers did not fit.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import replace
from typing import Any

from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage4.claims.graph import EMPTY_CLAIM_GRAPH
from pocketsec.stage4.engine.degradation import Subsystem, guarded
from pocketsec.stage4.engine.lucid_support import (
    WORK_UNITS,
    IncidentState,
    retain_evidence,
    with_truncations,
)
from pocketsec.stage4.graph.entropy_budget import SENSOR_ESCALATION_KIND
from pocketsec.stage4.graph.sparse_world_graph import Truncation
from pocketsec.stage4.identifiability.horizon import ResolutionHorizon
from pocketsec.stage4.identifiability.resolution import IdentifiabilityState
from pocketsec.stage4.stage5_interface import (
    CBFResolutionV1,
    InformationGap,
    export_incident_world_record,
)

__all__ = [
    "DEGRADED_FALLBACK_VERDICT",
    "bare_export",
    "budget_refusal",
    "charge_horizon",
    "guarded_export",
    "horizon_closed_update",
    "incident_ledger",
    "reasoning_closed",
]

#: The verdict ``resolve`` falls back to when the shadow adjustment itself fails.
#: Non-committal by construction: a failed adjustment cannot be read as support.
DEGRADED_FALLBACK_VERDICT: Verdict = Verdict.UNKNOWN


def reasoning_closed(horizon: ResolutionHorizon | None) -> bool:
    """True once the horizon's transition or work-unit budget is spent.

    Escalation exhaustion is deliberately NOT a reason to stop integrating: it stops
    further escalation (the planner is handed ``escalations_remaining()``) and routes
    the ending to an analyst, but the evidence the last escalation paid for must
    still be read when it arrives.
    """
    if horizon is None:
        return False
    return (
        horizon.consumed_transitions >= horizon.max_transitions
        or horizon.consumed_work_units >= horizon.max_work_units
    )


def charge_horizon(field: Any, state: IncidentState, charged: int) -> Any:
    """Charge the §20 horizon and the §29 escalation count for one update."""
    granted, state.pending_escalations = state.pending_escalations, 0
    for _ in range(granted):
        state.budget.charge(SENSOR_ESCALATION_KIND, 0)
    horizon = field.horizon if field.horizon is not None else ResolutionHorizon()
    return replace(
        field,
        horizon=horizon.charge(transitions=1, work_units=charged, escalations=granted),
    )


def horizon_closed_update(
    field: Any, transition: Any, state: IncidentState, spend: dict[str, int]
) -> Any:
    """The incident is out of horizon: keep the lineage, refuse the reasoning.

    The evidence digests are still retained (bounded by ``MAX_FIELD_EVIDENCE_REFS``)
    so Stage 5 can reconstruct the incident. ``state.refused_updates`` makes
    ``resolve`` downgrade a committal verdict, because that verdict never read these
    transitions.
    """
    state.transition_count += 1
    state.refused_updates += 1
    current, lineage = retain_evidence(field, transition.evidence)
    refusal = Truncation(
        what="branch",
        identifier=f"{field.incident_id}:resolution_horizon",
        reason="resolution_horizon_exhausted:reasoning_refused",
        consequence_lost=0.0,
    )
    current = with_truncations(current, (*lineage, refusal))
    spend["integrate"] = WORK_UNITS["integrate"]
    return replace(current, at_sequence=max(current.at_sequence, int(transition.sequence)))


def budget_refusal(field: Any, max_reasoning_units: int) -> Truncation:
    """The one record an over-budget incident carries for its refused passes."""
    return Truncation(
        what="branch",
        identifier=f"{field.incident_id}:reasoning_budget",
        reason=(
            f"max_reasoning_units:{max_reasoning_units}:optional_and_fission_passes_refused"
        ),
        consequence_lost=0.0,
    )


@contextmanager
def incident_ledger(engine: Any, state: IncidentState) -> Iterator[None]:
    """Route every guarded failure inside the block to ``state.ledger``.

    The steps reach the ledger through ``engine.degradation``, so it is pointed at the
    incident's own ledger for the duration and what was recorded is copied into the
    engine-wide roll-up afterwards. The roll-up is for reporting; verdict downgrades
    and exports read the incident's ledger.
    """
    aggregate = engine.degradation
    if aggregate is state.ledger:  # re-entrant: close_incident -> resolve
        yield
        return
    before = state.ledger.count + state.ledger.dropped
    engine.degradation = state.ledger
    try:
        yield
    finally:
        engine.degradation = aggregate
        recorded = state.ledger.count + state.ledger.dropped - before
        if recorded > 0:
            for record in state.ledger.records()[-recorded:]:
                aggregate.record(record)


def guarded_export(
    engine: Any,
    field: Any,
    *,
    resolution_id: str,
    verdict: Any,
    claim_graph: Mapping[str, Any],
    gaps: tuple[InformationGap, ...],
    state: IncidentState,
) -> CBFResolutionV1 | None:
    """One guarded attempt at the Stage 5 handoff; ``None`` when it failed."""
    scope = guarded(
        Subsystem.CLAIM_COMPILER,
        engine.degradation,
        at_sequence=field.at_sequence,
        fallback=None,
    )
    with scope:
        scope.result = export_incident_world_record(
            field,
            verdict=verdict,
            resolution_id=resolution_id,
            claim_graph=claim_graph,
            gaps=gaps,
            degradations=tuple(row.to_dict() for row in state.ledger.records()),
        )
    return scope.result


def bare_export(field: Any, resolution_id: str, state: IncidentState) -> CBFResolutionV1:
    """The last-resort Stage 5 record, built from primitives only.

    Reached only when the export and its minimal-field retry both failed. It says
    Stage 4 concluded nothing (``UNKNOWN``, no hypotheses, empty graph) and carries the
    degradations that explain why; it touches no world, shadow or claim object, so it
    cannot fail on whatever broke the first two attempts.
    """
    return CBFResolutionV1(
        resolution_id=resolution_id,
        incident_id=field.incident_id,
        epoch_id=int(field.epoch_id),
        verdict=Verdict.UNKNOWN,
        identifiability=IdentifiabilityState.UNKNOWN.value,
        hypotheses=(),
        consequence_distribution={},
        claim_graph=EMPTY_CLAIM_GRAPH.to_dict(),
        evidence_lineage=(),
        uncertainty=1.0,
        shadow={},
        information_gaps=(),
        truncations=(),
        degradations=tuple(row.to_dict() for row in state.ledger.records()),
    )
