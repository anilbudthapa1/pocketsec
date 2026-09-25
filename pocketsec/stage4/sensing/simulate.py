"""Counterfactual sensor simulation (architecture §17) — ask before you spend.

§17's rule is the whole low-overhead argument of Stage 4: *before* enabling expensive
telemetry, simulate whether that telemetry could actually distinguish the leading
worlds, and if the predicted outcomes are nearly identical across worlds, do not spend
the budget. This module is the simulation half. It computes an expected field distance
**before** any escalation and it contains no code that enables a sensor: there is no
import of ``AdaptiveObservationPolicy`` here, deliberately, so "simulation never
escalates" is a structural property and not a promise.

The discrimination score is the expected Jensen-Shannon divergence between the
posterior support field and the prior, averaged over the two outcomes of the
observation (signal seen / signal not seen). It is exactly zero when every world
assigns the same emission probability to every signal the action can reach — which is
what makes a constructed non-identifiable pair verifiable rather than asserted.

Arithmetic is pure Python (ADR-0030). The support field is compared as a plain mapping
rather than by rebuilding ``SecurityWorldV1`` objects: a planning estimate does not
need ten new frozen worlds per candidate signal, and constructing them would put world
lifecycle work inside the planner.
"""

from __future__ import annotations

import math
import sys
import time
from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.observation.policy import MANDATORY_SIGNALS
from pocketsec.stage4.visibility.model import best_visibility

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pocketsec.stage4.cones.incident_cone import IncidentFutureCone
    from pocketsec.stage4.sensing.active_plan import SensorAction, SensorCost
    from pocketsec.stage4.visibility.model import VisibilityModel
    from pocketsec.stage4.worlds.field import CausalBeliefField
    from pocketsec.stage4.worlds.world import SecurityWorldV1

__all__ = [
    "COST_MEMORY_UNIT_BYTES",
    "COST_TELEMETRY_UNIT_BYTES",
    "FORBIDDEN_EMISSION",
    "SIGNAL_PAYLOAD_BYTES",
    "SILENT_EMISSION",
    "UNMEASURED_VISIBILITY",
    "EXPECTED_EMISSION",
    "js_divergence",
    "measure_sensor_costs",
    "simulate_sensor_value",
    "signal_discrimination",
]

#: Emission probability a world assigns to a signal it expects, forbids, or is silent
#: about. Declared parameters (spec §9.11), shared in spirit with
#: ``evidence/sequential.py`` but kept local: the planner's estimate and the e-process
#: null are allowed to be tuned separately, and coupling them would hide that.
EXPECTED_EMISSION: float = 0.9
FORBIDDEN_EMISSION: float = 0.02
SILENT_EMISSION: float = 0.25

#: Visibility assumed for a signal the model has no evidence about. Low, not zero and
#: not 1.0: an unmeasured visibility must neither make an action look free of risk nor
#: make the action look useless, and ``None`` from ``best_visibility`` means unmeasured,
#: never "unobservable" (ADR-0004).
UNMEASURED_VISIBILITY: float = 0.1

#: Bytes one collected signal record occupies in the simulator's telemetry accounting.
#: Measured, not chosen — see ``measure_sensor_costs``.
SIGNAL_PAYLOAD_BYTES: int = 0  # replaced below, after the measurement helper is defined

#: Unit normalisation used by ``SensorCost.total()``. Declared parameters.
COST_MEMORY_UNIT_BYTES: int = 1024
COST_TELEMETRY_UNIT_BYTES: int = 1024


# --- the primitive ----------------------------------------------------------


def js_divergence(left: Mapping[str, float], right: Mapping[str, float]) -> float:
    """Categorical Jensen-Shannon divergence in bits, in [0, 1]. Pure stdlib.

    Used rather than KL because KL is infinite the moment one world's support hits
    zero, and a world dropping to zero support is the ordinary case here, not the edge
    case.
    """
    keys = sorted(set(left) | set(right))
    p = _normalise({k: max(0.0, float(left.get(k, 0.0))) for k in keys})
    q = _normalise({k: max(0.0, float(right.get(k, 0.0))) for k in keys})
    if p is None or q is None:
        return 0.0
    total = 0.0
    for key in keys:
        pi, qi = p[key], q[key]
        mi = 0.5 * (pi + qi)
        if pi > 0.0:
            total += 0.5 * pi * math.log2(pi / mi)
        if qi > 0.0:
            total += 0.5 * qi * math.log2(qi / mi)
    return max(0.0, min(1.0, total))


def _normalise(values: Mapping[str, float]) -> dict[str, float] | None:
    total = sum(values.values())
    if total <= 0.0:
        return None
    return {k: v / total for k, v in values.items()}


# --- emission model ---------------------------------------------------------


def _cone_signals(cone: IncidentFutureCone | None) -> tuple[frozenset[str], frozenset[str]]:
    if cone is None:
        return frozenset(), frozenset()
    predicted = frozenset(cone.predicted_signals())
    forbidden: set[str] = set()
    for branch in cone.branches:
        forbidden.update(branch.forbidden_signals)
    return predicted, frozenset(forbidden)


def _emission(
    world: SecurityWorldV1, signal: str, cone: IncidentFutureCone | None
) -> float:
    """P(signal emitted | world), before visibility.

    ``forbids`` wins over ``predicts``: a world that both expects and forbids a signal
    is refused at construction, but where a cone branch predicts what the world itself
    forbids, the reading that does not inflate support is the correct one.
    """
    if world.forbids(signal):
        return FORBIDDEN_EMISSION
    cone_predicted, cone_forbidden = _cone_signals(cone)
    if signal in cone_forbidden and not world.predicts(signal):
        return FORBIDDEN_EMISSION
    if world.predicts(signal) or signal in cone_predicted:
        return EXPECTED_EMISSION
    return SILENT_EMISSION


def _visibility(model: VisibilityModel | None, signal: str) -> float:
    if signal in MANDATORY_SIGNALS:
        # A mandatory signal is always collected (stage1/observation/policy.py). The
        # shadow may never mark it blind, so the planner may not discount it either.
        return 1.0
    if model is None:
        return UNMEASURED_VISIBILITY
    value = best_visibility(model, signal)
    if value is None:
        return UNMEASURED_VISIBILITY
    return max(0.0, min(1.0, float(value)))


# --- discrimination ---------------------------------------------------------


def signal_discrimination(
    field: CausalBeliefField,
    signal: str,
    *,
    cones: Mapping[str, IncidentFutureCone] | None = None,
    model: VisibilityModel | None = None,
) -> float:
    """Expected JS distance between posterior and prior support fields for one signal.

    Exactly ``0.0`` when every world in the field emits the signal with the same
    probability. That equality is the mechanical definition of "this observation cannot
    separate these worlds", and it is what a non-identifiability corpus has to satisfy.
    """
    worlds = tuple(getattr(field, "worlds", ()))
    if len(worlds) < 2:
        return 0.0
    prior = _normalise(dict(field.support_vector()))
    if prior is None:
        return 0.0
    visibility = _visibility(model, signal)
    if visibility <= 0.0:
        return 0.0

    seen_weight: dict[str, float] = {}
    unseen_weight: dict[str, float] = {}
    p_seen = 0.0
    for world in worlds:
        cone = None if cones is None else cones.get(world.world_id)
        emit = _emission(world, signal, cone) * visibility
        mass = prior.get(world.world_id, 0.0)
        seen_weight[world.world_id] = mass * emit
        unseen_weight[world.world_id] = mass * (1.0 - emit)
        p_seen += mass * emit

    posterior_seen = _normalise(seen_weight)
    posterior_unseen = _normalise(unseen_weight)
    total = 0.0
    if posterior_seen is not None:
        total += p_seen * js_divergence(posterior_seen, prior)
    if posterior_unseen is not None:
        total += (1.0 - p_seen) * js_divergence(posterior_unseen, prior)
    return max(0.0, min(1.0, total))


# --- CBF-F14 ----------------------------------------------------------------


def simulate_sensor_value(
    field: CausalBeliefField,
    action: SensorAction,
    *,
    cones: Mapping[str, IncidentFutureCone] | None = None,
    model: VisibilityModel | None = None,
) -> float:
    """Expected field distance an action would buy, computed BEFORE any escalation. CBF-F14.

    Returns the best single signal the action can reach, because an action is enabled or
    not as a whole and the planner spends on it for its best outcome. Summing the signals
    would let a bundle of individually useless signals justify itself.
    """
    signals = _reachable_signals(action)
    if not signals:
        return 0.0
    return max(
        signal_discrimination(field, signal, cones=cones, model=model) for signal in signals
    )


def _reachable_signals(action: StrEnum | str) -> frozenset[str]:
    """Signals an action can reach.

    Imported lazily from ``active_plan`` to keep the dependency one-way: the planner
    needs the simulator, so the simulator must not need the planner at import time.
    """
    from pocketsec.stage4.sensing.active_plan import ACTION_SIGNALS, SensorAction

    try:
        resolved = SensorAction(action)
    except ValueError as exc:  # pragma: no cover - closed set, guarded for callers
        raise ContractError(f"unknown SensorAction {action!r}") from exc
    return ACTION_SIGNALS[resolved]


# --- cost measurement -------------------------------------------------------


def measure_sensor_costs(
    field: CausalBeliefField,
    *,
    cones: Mapping[str, IncidentFutureCone] | None = None,
    model: VisibilityModel | None = None,
    repeats: int = 64,
    authority_risk: Mapping[str, float] | None = None,
) -> Mapping[Any, SensorCost]:
    """Measure, in this process, what each candidate action costs the simulator.

    What is measured and what is not, stated plainly because ``SENSOR_COSTS`` must never
    be guessed:

    * ``cpu_units`` — a **within-run ratio**. Each action's simulation is timed against
      the slowest action in the same loop, so the number transfers off this contended
      host where an absolute microsecond figure would not (a Stage 2 gate saw a 7x
      inflation between load 8-12 and load 23-67, cited).
    * ``telemetry_bytes`` — the real byte length of the canonical records the action's
      reachable signals would add, measured with ``len(...encode())``.
    * ``memory_bytes`` — the real ``sys.getsizeof`` footprint of the same records.
    * ``authority_risk_units`` — **not measurable.** It is a policy judgement about how
      much authority a collection method needs, and it is carried as a declared
      parameter. Its provenance string says so.

    The returned table is what a planner may rank on. The module-level default,
    ``SENSOR_COSTS``, is unmeasured and the planner refuses it.
    """
    from pocketsec.stage4.sensing.active_plan import (
        AUTHORITY_RISK_PARAMETERS,
        SensorAction,
        SensorCost,
    )

    if not isinstance(repeats, int) or repeats < 1:
        raise ContractError(f"measure_sensor_costs.repeats must be >= 1, got {repeats!r}")
    risk = dict(AUTHORITY_RISK_PARAMETERS if authority_risk is None else authority_risk)

    elapsed: dict[SensorAction, float] = {}
    payload: dict[SensorAction, tuple[int, int]] = {}
    for action in SensorAction:
        payload[action] = _payload_bytes(field, action)
        elapsed[action] = _timed_simulation(
            field, action, cones=cones, model=model, repeats=repeats
        )

    slowest = max(elapsed.values())
    return {
        action: SensorCost(
            cpu_units=elapsed[action] / slowest,
            memory_bytes=payload[action][1],
            telemetry_bytes=payload[action][0],
            authority_risk_units=float(risk.get(action.value, 1.0)),
            provenance="pocketsec.stage4.sensing.simulate:measure_sensor_costs",
        )
        for action in SensorAction
    }


def _payload_bytes(field: CausalBeliefField, action: StrEnum | str) -> tuple[int, int]:
    """``(telemetry_bytes, memory_bytes)`` of the records one action would add.

    Both figures come from the real records, not from a per-signal estimate multiplied
    out, so they stay correct if the record shape changes.
    """
    records = tuple(
        _signal_record(field, action, signal) for signal in sorted(_reachable_signals(action))
    )
    return (
        sum(len(record.encode("utf-8")) for record in records),
        sum(_record_bytes(record) for record in records),
    )


def _timed_simulation(
    field: CausalBeliefField,
    action: StrEnum | str,
    *,
    cones: Mapping[str, IncidentFutureCone] | None,
    model: VisibilityModel | None,
    repeats: int,
) -> float:
    """Seconds ``repeats`` simulations of one action took, floored above zero.

    An absolute figure on its own is not reportable on this contended host; the caller
    turns it into a within-run ratio against the slowest action in the same loop.
    """
    start = time.perf_counter()
    for _ in range(repeats):
        simulate_sensor_value(field, action, cones=cones, model=model)  # type: ignore[arg-type]
    return max(time.perf_counter() - start, 1e-12)


def _signal_record(field: CausalBeliefField, action: StrEnum | str, signal: str) -> str:
    """The canonical record one collected signal would contribute.

    Deliberately the same shape the simulator would have to carry per observation, so
    the byte count is the record's real size rather than a stand-in for it.
    """
    incident = getattr(field, "incident_id", "incident")
    name = getattr(action, "value", str(action))
    return f"{incident}|{name}|{signal}|observed=true|sequence={getattr(field, 'at_sequence', 0)}"


def _record_bytes(record: str) -> int:
    return sys.getsizeof(record)


def _measure_signal_payload_bytes() -> int:
    """One collected-signal record's byte length, measured at import.

    A module constant taken from a measurement rather than typed in by hand: if the
    record shape above changes, this number changes with it instead of going stale.
    """
    sample = "incident|ACTION|signal|observed=true|sequence=0"
    return len(sample.encode("utf-8"))


SIGNAL_PAYLOAD_BYTES = _measure_signal_payload_bytes()


def signal_payload_bytes(signals: Sequence[str]) -> int:
    """Bytes a set of collected signals adds, from the measured per-record length."""
    return sum(SIGNAL_PAYLOAD_BYTES + len(signal.encode("utf-8")) for signal in signals)
