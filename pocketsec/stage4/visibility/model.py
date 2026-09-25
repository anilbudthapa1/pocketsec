"""D4.3 (part) — the sensor visibility model, P(observe e | e occurred, A_t, V_t).

Architecture §5 separates latent world state from observed evidence so that the
system can never make the inference *"I did not observe it, therefore it did not
happen"*. That separation is only worth anything if something in the code knows
**how likely an occurrence was to be seen**. This module is that something.

What this module refuses to do, and why the refusal is the deliverable:

* :meth:`VisibilityModel.probability` returns ``None`` for any ``(signal,
  sensor)`` pair with no replay evidence. There is no default of 0.5, no
  smoothing prior and no fallback. ADR-0004's lesson ("``None`` never means
  zero") generalises: an unmeasured visibility is not a coin flip, and a
  fabricated one would silently license exactly the inference §5 exists to
  forbid. Every caller must treat ``None`` as UNKNOWN.
* :func:`measure_visibility` counts only **relation-family** signals, which a
  corpus behaviour's operation token determines exactly. It never manufactures
  an occurrence count for one of the six semantic ``MANDATORY_SIGNALS``, because
  a Stage 1 operation rule raises those *conditionally* on object semantics and
  the corpus does not state whether the precondition held. Counting the
  operation as an occurrence of the conditional signal measured 12 occurrences
  and 0 observations for ``authentication`` and ``module_load`` on the eval
  corpus — a fabricated "totally blind" reading for a signal that never
  occurred. That path is closed here rather than documented as a caveat.
* :attr:`VisibilityModel.level` is **recorded, not applied**. Multiplying a
  measured replay frequency by an observation-level factor nobody measured would
  turn a measurement into an estimate. The level is carried so the sensor shadow
  can cite it as a reason (``below_observation_level``); it never scales a
  probability.
* A row for a ``MANDATORY_SIGNALS`` member is **refused** at construction.
  :meth:`probability` answers ``1.0`` for those from the contract in
  ``policy.py:47`` (AOP may add observation; it may never take a mandatory
  signal away), so a fitted row would be dead data that could mislead a reader
  into thinking a mandatory signal had been measured at 0.4 and honoured.

Everything here is fitted from *replays of a synthetic corpus through simulated
sensor paths*. It is a real property of this code and it is **not** a
measurement of Linux telemetry visibility (spec §6.1).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    register_schema,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage1.compiler.rules import OPERATION_RULES
from pocketsec.stage1.labs.corpus import Behaviour, Scenario
from pocketsec.stage1.observation.policy import MANDATORY_SIGNALS, ObservationLevel
from pocketsec.stage1.pipeline import ScenarioResult, Stage1Pipeline
from pocketsec.stage1.ssir.transition import SSIRTransitionV1
from pocketsec.stage1.telemetry.raw_event_v1 import SensorPath

__all__ = [
    "DIMENSION_SIGNALS",
    "MAX_VISIBILITY_ROWS",
    "RELATION_SIGNALS",
    "VISIBILITY_MODEL_V1_ID",
    "VISIBILITY_MODEL_V1_VERSION",
    "VisibilityModel",
    "VisibilityObservation",
    "best_visibility",
    "fit_visibility_model",
    "measure_visibility",
    "occurrence_counts",
    "signal_dimensions",
    "signal_for_operation",
    "signals_of_transition",
]

VISIBILITY_MODEL_V1_ID = "pocketsec.visibility_model.v1"
VISIBILITY_MODEL_V1_VERSION = register_schema(VISIBILITY_MODEL_V1_ID, "1.0.0")

#: Hard bound on fitted rows (spec D4.3: "visibility model <= 256 rows"). The
#: endpoint state budget is the reason: a model that grows with the vocabulary
#: is an unbounded cache wearing a statistical hat.
MAX_VISIBILITY_ROWS: int = 256

#: Stage 1 lattice dimension -> the mandatory security signal it evidences.
#: Only the six dimensions that map onto a ``MANDATORY_SIGNALS`` member appear;
#: ``reachability``, ``modification`` and ``discovery`` have no mandatory signal
#: and are deliberately absent rather than given an invented name.
DIMENSION_SIGNALS: Mapping[str, str] = MappingProxyType(
    {
        "privilege": "privilege_change",
        "credential": "credential_access",
        "persistence": "persistence_write",
        "execution": "module_load",
        "isolation": "boundary_crossing",
        "trust": "authentication",
    }
)

#: The relation-family signal vocabulary, derived from Stage 1's operation rules
#: rather than restated. ``rules.py`` asserts one rule per relation, so a
#: relation name is an exact, condition-free description of what happened.
RELATION_SIGNALS: frozenset[str] = frozenset(
    rule.relation.name.lower() for rule in OPERATION_RULES
)

_OPERATION_PREFIXES = ("sys_", "syscall_", "do_", "__x64_sys_")

_TOKEN_TO_SIGNAL: Mapping[str, str] = MappingProxyType(
    {
        token: rule.relation.name.lower()
        for rule in OPERATION_RULES
        for token in rule.tokens
    }
)

_SIGNAL_DIMENSIONS: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        rule.relation.name.lower(): frozenset(
            {name for name, _ in rule.raises}
            | {name for _, name, _ in rule.conditional_raises}
        )
        for rule in OPERATION_RULES
    }
)


def _normalise_operation(raw: str) -> str:
    """Strip the probe/syscall prefixes that carry no semantic content."""
    token = raw.strip().lower()
    for prefix in _OPERATION_PREFIXES:
        if token.startswith(prefix):
            token = token[len(prefix) :]
    return token


def signal_for_operation(operation: str) -> str | None:
    """The relation-family signal a corpus operation produces, or ``None``.

    ``None`` means Stage 1 has no rule for the token, so the corpus cannot state
    that any signal occurred. Guessing here would put fabricated occurrences
    into every fitted probability downstream.
    """
    return _TOKEN_TO_SIGNAL.get(_normalise_operation(operation))


def signal_dimensions(signal: str) -> frozenset[str]:
    """Stage 1 lattice dimensions this signal could raise.

    For a relation-family signal these are the rule's unconditional *and*
    conditional raises: the question is what the signal *could* have raised, so
    the consequence of not seeing it is not understated.
    """
    if signal in MANDATORY_SIGNALS:
        return frozenset(
            name for name, mapped in DIMENSION_SIGNALS.items() if mapped == signal
        )
    return _SIGNAL_DIMENSIONS.get(signal, frozenset())


def signals_of_transition(transition: SSIRTransitionV1) -> frozenset[str]:
    """Signals one compiled transition actually carries.

    The relation family is always present. A mandatory semantic signal is
    present only when the transition's ``state_delta`` really raised the
    dimension that evidences it — the observed side of the asymmetry this
    module's docstring explains.
    """
    signals = {transition.relation.name.lower()}
    for dimension in transition.state_delta.dimensions:
        mapped = DIMENSION_SIGNALS.get(dimension)
        if mapped is not None:
            signals.add(mapped)
    return frozenset(signals)


def occurrence_counts(behaviours: Iterable[Behaviour]) -> Counter[str]:
    """Ground-truth relation-family occurrences for a behaviour sequence.

    Only relation families are counted, for the reason in the module docstring.
    Verified on ``build_corpus(count=40, seed=5, split="eval")`` and
    ``build_ambiguous_corpus(count=20, seed=7)``: observations never exceed
    occurrences for any pair, on any of eBPF, auditd and procfs.
    """
    counts: Counter[str] = Counter()
    for behaviour in behaviours:
        signal = signal_for_operation(behaviour.operation)
        if signal is not None:
            counts[signal] += 1
    return counts


@dataclass(frozen=True, slots=True)
class VisibilityObservation:
    """One replay's worth of ground truth: the signal occurred; was it observed?

    ``observations > occurrences`` is refused. Observing more than occurred is
    not a large number, it is a broken attribution, and letting it through would
    hand callers a probability above 1.0 to reason with.
    """

    signal: str
    sensor: SensorPath
    occurrences: int
    observations: int
    epoch_id: int

    def __post_init__(self) -> None:
        require_identifier(self.signal, "VisibilityObservation.signal")
        require_non_negative_int(self.occurrences, "VisibilityObservation.occurrences")
        require_non_negative_int(self.observations, "VisibilityObservation.observations")
        require_non_negative_int(self.epoch_id, "VisibilityObservation.epoch_id")
        object.__setattr__(self, "sensor", SensorPath(self.sensor))
        if self.observations > self.occurrences:
            raise ContractError(
                f"VisibilityObservation({self.signal!r}, {self.sensor.value}): "
                f"observations {self.observations} exceeds occurrences {self.occurrences}"
            )

    @property
    def key(self) -> tuple[str, str]:
        return (self.signal, self.sensor.value)

    @property
    def frequency(self) -> float | None:
        """Observed frequency, or ``None`` when nothing occurred to be seen."""
        if self.occurrences == 0:
            return None
        return self.observations / self.occurrences

    def merged_with(self, other: VisibilityObservation) -> VisibilityObservation:
        """Pool two replays of the same pair.

        ``epoch_id`` takes the larger value: pooled counts describe the run as a
        whole, and claiming the earlier epoch would date the evidence wrongly.
        """
        if other.key != self.key:
            raise ContractError("cannot merge visibility observations for different pairs")
        return VisibilityObservation(
            signal=self.signal,
            sensor=self.sensor,
            occurrences=self.occurrences + other.occurrences,
            observations=self.observations + other.observations,
            epoch_id=max(self.epoch_id, other.epoch_id),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal": self.signal,
            "sensor": self.sensor.value,
            "occurrences": self.occurrences,
            "observations": self.observations,
            "epoch_id": self.epoch_id,
            "frequency": self.frequency,
        }


@dataclass(frozen=True, slots=True)
class VisibilityModel:
    """P(observe e | e occurred, A_t, V_t), fitted from replays — never defaulted."""

    rows: Mapping[tuple[str, str], VisibilityObservation]
    level: ObservationLevel = ObservationLevel.BASELINE
    dropped_paths: frozenset[SensorPath] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.rows, Mapping):
            raise ContractError("VisibilityModel.rows must be a mapping")
        if len(self.rows) > MAX_VISIBILITY_ROWS:
            raise ContractError(
                f"VisibilityModel holds {len(self.rows)} rows, bound is {MAX_VISIBILITY_ROWS}"
            )
        snapshot: dict[tuple[str, str], VisibilityObservation] = {}
        for key, row in self.rows.items():
            if not isinstance(row, VisibilityObservation):
                raise ContractError(
                    f"VisibilityModel.rows[{key!r}] must hold a VisibilityObservation"
                )
            if key != row.key:
                raise ContractError(f"VisibilityModel.rows key {key!r} does not match {row.key!r}")
            if row.signal in MANDATORY_SIGNALS:
                raise ContractError(
                    f"refusing a fitted row for mandatory signal {row.signal!r}: "
                    "probability() answers 1.0 from policy.py:47 and the row would be ignored"
                )
            snapshot[key] = row
        object.__setattr__(self, "rows", MappingProxyType(snapshot))
        object.__setattr__(self, "level", ObservationLevel(self.level))
        object.__setattr__(
            self, "dropped_paths", frozenset(SensorPath(p) for p in self.dropped_paths)
        )

    # --- queries --------------------------------------------------------

    def is_mandatory(self, signal: str) -> bool:
        return signal in MANDATORY_SIGNALS

    def probability(self, signal: str, sensor: SensorPath) -> float | None:
        """P(observe ``signal`` | it occurred) on ``sensor``, or ``None``.

        ``None`` means UNMEASURED and every caller must treat it as UNKNOWN. A
        dropped path returns ``0.0`` only when the pair *was* measured, because
        "this path is down" is an operational fact about a pair we know about;
        for a pair with no evidence the drop teaches us nothing and ``None``
        remains the honest answer.
        """
        if signal in MANDATORY_SIGNALS:
            return 1.0
        key = (signal, SensorPath(sensor).value)
        if SensorPath(sensor) in self.dropped_paths:
            return 0.0 if key in self.rows else None
        row = self.rows.get(key)
        if row is None:
            return None
        return row.frequency

    def signals(self) -> tuple[str, ...]:
        return tuple(sorted({row.signal for row in self.rows.values()}))

    def observable_sensors(self, signal: str) -> tuple[SensorPath, ...]:
        """Sensors with evidence that they observe ``signal`` and are not dropped."""
        found: list[SensorPath] = []
        for sensor in SensorPath:
            probability = self.probability(signal, sensor)
            if probability is not None and probability > 0.0:
                found.append(sensor)
        return tuple(found)

    def evidenced_sensors(self, signal: str) -> tuple[SensorPath, ...]:
        """Sensors that have a fitted row for ``signal``, dropped or not."""
        return tuple(
            sensor for sensor in SensorPath if (signal, sensor.value) in self.rows
        )

    def coverage(self) -> float:
        """Fraction of ``(signal, SensorPath)`` pairs that carry evidence.

        The denominator is every sensor path, not only the replayed ones: a model
        fitted on two of five paths has 0.4 coverage and should say so rather
        than report 1.0 of what it happened to look at.
        """
        signals = self.signals()
        if not signals:
            return 0.0
        return len(self.rows) / (len(signals) * len(SensorPath))

    # --- derived models -------------------------------------------------

    def with_dropped(self, sensor: SensorPath) -> VisibilityModel:
        return VisibilityModel(
            rows=self.rows,
            level=self.level,
            dropped_paths=self.dropped_paths | {SensorPath(sensor)},
        )

    def with_level(self, level: ObservationLevel) -> VisibilityModel:
        return VisibilityModel(rows=self.rows, level=level, dropped_paths=self.dropped_paths)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": VISIBILITY_MODEL_V1_ID,
            "schema_version": VISIBILITY_MODEL_V1_VERSION,
            "level": self.level.value,
            "dropped_paths": sorted(p.value for p in self.dropped_paths),
            "coverage": round(self.coverage(), 4),
            "rows": [self.rows[key].to_dict() for key in sorted(self.rows)],
        }


def best_visibility(model: VisibilityModel, signal: str) -> float | None:
    """The best measured visibility for ``signal`` over live sensor paths.

    ``None`` when no live path carries evidence. Used by the negative-evidence
    classifier, which must never treat "nobody measured this" as "nobody saw it".
    """
    measured = [
        probability
        for sensor in SensorPath
        if (probability := model.probability(signal, sensor)) is not None
    ]
    if not measured:
        return None
    return max(measured)


def fit_visibility_model(observations: Sequence[VisibilityObservation]) -> VisibilityModel:
    """Pool replay observations into a model. No prior, no smoothing."""
    pooled: dict[tuple[str, str], VisibilityObservation] = {}
    for observation in observations:
        existing = pooled.get(observation.key)
        pooled[observation.key] = (
            observation if existing is None else existing.merged_with(observation)
        )
    return VisibilityModel(rows=pooled)


def _replay_counts(
    pipeline_factory: Callable[[], Stage1Pipeline],
    scenarios: Sequence[Scenario],
    sensor: SensorPath,
) -> tuple[Counter[str], Counter[str], int]:
    """Replay every scenario through one sensor path and count both sides.

    A **fresh pipeline per scenario**: ``Stage1Pipeline`` carries lineage state,
    and reusing one across scenarios put every lineage at saturated privilege in
    a prior wave, which retracted a published result (MEMORY.md). ``offset``
    also separates the synthetic pids, so two scenarios never share a lineage.
    """
    occurrences: Counter[str] = Counter()
    observations: Counter[str] = Counter()
    epoch_id = 0
    for index, scenario in enumerate(scenarios):
        pipeline = pipeline_factory()
        result: ScenarioResult = pipeline.run_scenario(scenario, sensor=sensor, offset=index)
        occurrences.update(occurrence_counts(scenario.behaviours))
        for transition in result.transitions:
            observations[transition.relation.name.lower()] += 1
            epoch_id = max(epoch_id, transition.epoch_id)
    return occurrences, observations, epoch_id


def measure_visibility(
    pipeline_factory: Callable[[], Stage1Pipeline],
    scenarios: Sequence[Scenario],
    sensors: Sequence[SensorPath],
) -> tuple[VisibilityObservation, ...]:
    """Replay the same scenarios through each sensor path and count.

    The *same* scenarios through every path, in one call, so the comparison is
    within-run: a cross-sensor difference measured across two separate runs on
    this contended host would be indistinguishable from load (spec §2.8).
    """
    measured: list[VisibilityObservation] = []
    for sensor in sensors:
        occurrences, observations, epoch_id = _replay_counts(
            pipeline_factory, scenarios, SensorPath(sensor)
        )
        for signal in sorted(occurrences):
            measured.append(
                VisibilityObservation(
                    signal=signal,
                    sensor=SensorPath(sensor),
                    occurrences=occurrences[signal],
                    observations=observations.get(signal, 0),
                    epoch_id=epoch_id,
                )
            )
    return tuple(measured)
