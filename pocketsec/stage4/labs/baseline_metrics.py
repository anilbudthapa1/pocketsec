"""Shared measurement types for §7's baseline comparison: one replay set, one metric set.

Split out of ``labs/baselines.py`` so that module stays inside the repository's
~800-line limit, and because these types genuinely belong to both halves: the
engine-based controls (``labs/baselines.py``) and the non-engine simple baselines
(``labs/simple_baselines.py``) must measure the *same* replays with the *same*
metrics or the comparison is between two runs rather than within one.

:class:`BaselineOutcome` is where the honesty rule lives: every metric is
``float | None`` and ``None`` means *not computable*, never 0.0 (ADR-0004). A baseline
that proposes no worlds reports ``world_set_recall=None`` rather than zero, because
"did not attempt" and "attempted and got none right" are different findings, and
averaging them together is how a comparison flatters whichever side attempted less.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import NON_COMMITTAL_VERDICTS, Verdict
from pocketsec.stage1.pipeline import ScenarioResult, Stage1Pipeline
from pocketsec.stage1.ssir.transition import TemporalContext
from pocketsec.stage1.telemetry.raw_event_v1 import SensorPath
from pocketsec.stage4.identifiability.resolution import IdentifiabilityState
from pocketsec.stage4.labs.incident_corpus import IncidentCase
from pocketsec.stage4.resources import loadavg
from pocketsec.stage4.visibility.model import DIMENSION_SIGNALS, signals_of_transition

__all__ = [
    "EVIDENCE_LOAD_WEIGHT",
    "HMM_STATES",
    "PHI_TREE",
    "WINDOW_BUCKET",
    "WINDOW_NS",
    "BaselineOutcome",
    "Replay",
    "accuracy_of",
    "efficiency_of",
    "loadavg",
    "predicted_label",
    "replay_corpus",
]

#: §40's Resolution Efficiency needs the three cost terms in one denominator, and they
#: are in different units. These weights are a **chosen parameter, not a measured
#: one**, and they are reported as a parameter in the findings document. A threshold
#: presented as a finding is a fabricated result.
EVIDENCE_LOAD_WEIGHT: Mapping[str, float] = MappingProxyType(
    {"cpu_units": 1000.0, "telemetry_kilobytes": 1.0, "claims_read": 1.0}
)

#: B5's correlation window: 60 s, §42's cheap operational baseline. Expressed as a
#: ``TemporalContext.bucket`` index rather than a nanosecond timestamp, because
#: ``SSIRTransitionV1`` carries **no absolute time** — only log-spaced buckets of the
#: gap since the actor's previous transition (``transition.py:62``). That is a
#: deliberate Stage 1 design (it makes timing-shift attacks harder to tune), so a
#: window here is "the gap to the previous transition exceeded 60 s", which is the
#: same grouping a real 60 s window produces on a per-lineage stream.
WINDOW_NS: int = 60_000_000_000
WINDOW_BUCKET: int = TemporalContext.bucket(WINDOW_NS)

#: B6's two hidden states. Two, not more, because §46's falsifier 1 names a *2-state*
#: HMM and widening it until it loses would be choosing the control to fail.
HMM_STATES: tuple[str, str] = ("benign", "compromised")

#: B4's decision tree, depth 4. Fixed thresholds over ``phi(state).total``: the point
#: of the baseline is that it has near-zero cost, so CBF/LUCID must beat a table.
PHI_TREE: tuple[tuple[float, str], ...] = (
    (8.0, "resolve_malicious"),
    (4.0, "escalate"),
    (1.0, "watch"),
    (0.0, "ignore"),
)


@dataclass(frozen=True, slots=True)
class Replay:
    """One case, replayed once, shared by every baseline in the run.

    A **fresh** ``Stage1Pipeline`` per case: the pipeline carries lineage state across
    scenarios, and reusing one put every lineage at saturated privilege in a prior
    wave, which retracted a published result (``MEMORY.md``). Sharing the *replay*
    across baselines is the opposite — it is what makes the comparison within-run.
    """

    case: IncidentCase
    result: ScenarioResult
    pipeline: Stage1Pipeline
    observed: frozenset[str]
    truth_signals: frozenset[str]

    @property
    def label(self) -> int:
        return self.case.label

    @property
    def expects_unidentifiable(self) -> bool:
        return self.case.expected_state == IdentifiabilityState.UNIDENTIFIABLE.value


@dataclass(frozen=True, slots=True)
class BaselineOutcome:
    """One baseline's measured position. Every metric ``None``-able; ``None`` != 0.0."""

    baseline_id: str
    world_set_recall: float | None
    premature_collapse_rate: float | None
    nonidentifiability_accuracy: float | None
    unsupported_claim_count: int
    telemetry_bytes: int
    cpu_units: float
    work_units: int
    resolution_efficiency: float | None
    #: Beyond the spec's list, and required by §7's own criteria: B2 is judged on
    #: chain recall at nodes inspected, and every baseline is admitted or refused on
    #: ``detection_accuracy`` against the base rate.
    detection_accuracy: float | None = None
    #: Fraction of cases on which the baseline committed to a verdict at all. An
    #: engine abstention is neither a hit nor a benign call; it is reported here and
    #: scored as not-a-hit in ``detection_accuracy`` (S4-REV-04).
    detection_coverage: float | None = None
    chain_recall: float | None = None
    nodes_inspected: int | None = None
    loadavg: tuple[float, float, float] = (-1.0, -1.0, -1.0)

    def __post_init__(self) -> None:
        if not self.baseline_id:
            raise ContractError("BaselineOutcome.baseline_id must be non-empty")
        for name in (
            "world_set_recall",
            "premature_collapse_rate",
            "nonidentifiability_accuracy",
            "resolution_efficiency",
            "detection_accuracy",
            "detection_coverage",
            "chain_recall",
        ):
            value = getattr(self, name)
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ContractError(f"BaselineOutcome.{name} must be a number or None")
            if float(value) != float(value):
                raise ContractError(f"BaselineOutcome.{name} must be finite or None")
        if self.cpu_units < 0.0:
            raise ContractError("BaselineOutcome.cpu_units must be >= 0")

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_id": self.baseline_id,
            "world_set_recall": self.world_set_recall,
            "premature_collapse_rate": self.premature_collapse_rate,
            "nonidentifiability_accuracy": self.nonidentifiability_accuracy,
            "unsupported_claim_count": self.unsupported_claim_count,
            "telemetry_bytes": self.telemetry_bytes,
            "cpu_units": self.cpu_units,
            "work_units": self.work_units,
            "resolution_efficiency": self.resolution_efficiency,
            "detection_accuracy": self.detection_accuracy,
            "detection_coverage": self.detection_coverage,
            "chain_recall": self.chain_recall,
            "nodes_inspected": self.nodes_inspected,
            "loadavg": list(self.loadavg),
        }


def replay_corpus(
    corpus: Sequence[IncidentCase], *, sensor: SensorPath = SensorPath.EBPF
) -> tuple[Replay, ...]:
    """Replay every case once, fresh pipeline per case, in this process."""
    replays: list[Replay] = []
    for index, case in enumerate(corpus):
        pipeline = Stage1Pipeline()
        result = pipeline.run_scenario(case.scenario, sensor=sensor, offset=index)
        observed: set[str] = set()
        for transition in result.transitions:
            observed |= signals_of_transition(transition)
        replays.append(
            Replay(
                case=case,
                result=result,
                pipeline=pipeline,
                observed=frozenset(observed),
                truth_signals=frozenset(
                    DIMENSION_SIGNALS[dimension]
                    for dimension in case.truth.raises_dimensions
                    if dimension in DIMENSION_SIGNALS
                ),
            )
        )
    return tuple(replays)




def efficiency_of(correct: int, *, cpu: float, telemetry: int, claims: int) -> float | None:
    """§40's Resolution Efficiency. ``None`` when the denominator is zero.

    ``None`` rather than infinity: a baseline that consumed nothing measurable has not
    achieved perfect efficiency, it has not been measured.
    """
    weights = EVIDENCE_LOAD_WEIGHT
    denominator = (
        cpu * weights["cpu_units"]
        + (telemetry / 1024.0) * weights["telemetry_kilobytes"]
        + claims * weights["claims_read"]
    )
    if denominator <= 0.0:
        return None
    return correct / denominator


def predicted_label(verdict: Verdict) -> int | None:
    """Map an engine verdict onto the corpus label, or ``None`` for an abstention.

    ``MALICIOUS`` and ``SUSPICIOUS`` predict 1, ``BENIGN`` predicts 0, and every
    ``NON_COMMITTAL_VERDICTS`` member predicts nothing. The first version scored
    ``int(not resolution.abstained)``, which read "did not abstain" as "predicted
    malicious": a correct BENIGN on a benign case counted as a miss, a wrong BENIGN on
    a malicious case as a hit, and an engine that abstained on everything scored
    exactly the benign base rate — the 0.6667 G4.10's saturation guard kept seeing
    (S4-REV-04).
    """
    committed = Verdict(verdict)
    if committed in NON_COMMITTAL_VERDICTS:
        return None
    return 0 if committed is Verdict.BENIGN else 1


def accuracy_of(hits: int, total: int) -> float | None:
    """``None`` when there was nothing to be accurate about — never 0.0."""
    return hits / total if total else None
