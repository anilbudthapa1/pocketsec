"""D1.13 — the Stage 2 model-facing interface.

Two deliberately different "model families" consume the *same* SSIR transitions:

* :class:`StateCalculusSlot` — a symbolic/threshold reader of ΔS and Φ.
* :class:`NoveltyStatisticalSlot` — a statistical reader of the novelty tensor
  and uncertainty.

Neither changes SSIR's semantics to suit itself, which is acceptance criterion
13. They disagree about what matters — that is the point: the representation is
not tuned to one consumer, and Stage 2 is free to pick a different architecture
without renegotiating Stage 1.

Both implement Stage 0's ``ModelSlot`` protocol, so Stage 1 reports through the
Stage 0 harness unchanged. Stage 0's measurement rules bind Stage 1, and this is
where that binding is made concrete rather than promised.
"""

from __future__ import annotations

from dataclasses import dataclass

from pocketsec.stage0.contracts.common import EvidenceRef
from pocketsec.stage0.contracts.model_slot import (
    ACCEPTED_INPUT_SCHEMA,
    PRODUCED_OUTPUT_SCHEMA,
)
from pocketsec.stage0.contracts.security_event_v1 import SecurityEventSequenceV1
from pocketsec.stage0.contracts.threat_prediction_v1 import (
    ComputePath,
    EvidenceRelevance,
    NextEventExpectation,
    ThreatPredictionV1,
    Verdict,
)
from pocketsec.stage1.pipeline import ScenarioResult

__all__ = ["NoveltyStatisticalSlot", "SSIRSlotBase", "StateCalculusSlot"]

#: Φ at or above which the state-calculus slot commits to SUSPICIOUS.
DEFAULT_PHI_THRESHOLD = 4.0

#: Φ is unbounded above; squash it into [0, 1] for the confidence field rather
#: than clipping, so very high potential still orders correctly.
def _squash(value: float, scale: float) -> float:
    return value / (value + scale) if value > 0 else 0.0


@dataclass
class SSIRSlotBase:
    """Shared plumbing for SSIR-consuming slots.

    Holds the compiled Stage 1 results keyed by sequence id, because the Stage 0
    contract passes a ``SecurityEventSequenceV1`` and the Stage 1 substrate is
    what turns that into transitions.
    """

    results: dict[str, ScenarioResult]
    input_schema: str = ACCEPTED_INPUT_SCHEMA
    output_schema: str = PRODUCED_OUTPUT_SCHEMA

    def _result_for(self, sequence: SecurityEventSequenceV1) -> ScenarioResult | None:
        return self.results.get(sequence.sequence_id)

    @staticmethod
    def _relevance(result: ScenarioResult) -> tuple[EvidenceRelevance, ...]:
        """Weight evidence by the responsibility of the transition it came from.

        This is where the causal spine reaches the investigator: the references
        that drove the verdict are the ones that raised security potential.
        """
        weighted: list[tuple[EvidenceRef, float]] = []
        total = sum(max(0.0, t.responsibility) for t in result.transitions)
        for transition in result.transitions:
            share = max(0.0, transition.responsibility) / total if total > 0 else 0.0
            for ref in transition.evidence[:1]:
                weighted.append((ref, share))
        if not weighted:
            return ()
        if total == 0:
            share = 1.0 / len(weighted)
            return tuple(EvidenceRelevance(ref=ref, weight=share) for ref, _ in weighted)
        return tuple(
            EvidenceRelevance(ref=ref, weight=min(1.0, weight)) for ref, weight in weighted
        )

    def _abstain(
        self, sequence: SecurityEventSequenceV1, reason_uncertainty: float = 1.0
    ) -> ThreatPredictionV1:
        return ThreatPredictionV1(
            prediction_id=f"{self.slot_name}-{sequence.sequence_id}",  # type: ignore[attr-defined]
            sequence_id=sequence.sequence_id,
            verdict=Verdict.INSUFFICIENT_EVIDENCE,
            confidence=0.0,
            novelty_score=0.0,
            uncertainty=reason_uncertainty,
            abstained=True,
            model_state_version=self.model_state_version,  # type: ignore[attr-defined]
            compute_path=ComputePath.CHEAP_TRANSITION,
        )


@dataclass
class StateCalculusSlot(SSIRSlotBase):
    """Symbolic family: reads ΔS and Φ, ignores the novelty tensor entirely.

    Deliberately blind to novelty. If this slot performs well, that is evidence
    the *state calculus* carries the signal — which is the Stage 1 hypothesis —
    rather than rarity doing the work.
    """

    slot_name: str = "s1-state-calculus"
    model_state_version: str = "s1-calculus.1.0.0"
    phi_threshold: float = DEFAULT_PHI_THRESHOLD

    def predict(self, sequence: SecurityEventSequenceV1) -> ThreatPredictionV1:
        result = self._result_for(sequence)
        if result is None or not result.transitions:
            return self._abstain(sequence)

        peak_phi = result.peak_phi
        committed = peak_phi >= self.phi_threshold
        confidence = (
            _squash(peak_phi, self.phi_threshold)
            if committed
            else 1.0 - _squash(peak_phi, self.phi_threshold)
        )
        # A window the calculus cannot interpret confidently abstains rather
        # than defaulting to benign.
        if result.peak_uncertainty >= 0.8:  # noqa: PLR2004
            return self._abstain(sequence, reason_uncertainty=result.peak_uncertainty)

        return ThreatPredictionV1(
            prediction_id=f"{self.slot_name}-{sequence.sequence_id}",
            sequence_id=sequence.sequence_id,
            verdict=Verdict.SUSPICIOUS if committed else Verdict.BENIGN,
            state_identifier=None,
            confidence=min(1.0, confidence),
            calibration_id=None,  # honest: no calibration map exists yet
            novelty_score=result.peak_novelty,
            uncertainty=result.peak_uncertainty,
            evidence_relevance=self._relevance(result),
            next_event=None,
            compute_path=(
                ComputePath.CHEAP_TRANSITION
                if not any(t.state_delta for t in result.transitions)
                else ComputePath.STATISTICAL
            ),
            compute_budget_units=float(len(result.transitions)),
            model_state_version=self.model_state_version,
        )


@dataclass
class NoveltyStatisticalSlot(SSIRSlotBase):
    """Statistical family: reads the novelty tensor and uncertainty, not Φ.

    The control for the Stage 1 claim that novelty alone is a poor detector —
    "do not equate rare with malicious" is an explicit non-goal. Expect this
    slot to fire on novel benign work. That is a result, not a bug.
    """

    slot_name: str = "s1-novelty-statistical"
    model_state_version: str = "s1-novelty.1.0.0"
    novelty_threshold: float = 0.7

    def predict(self, sequence: SecurityEventSequenceV1) -> ThreatPredictionV1:
        result = self._result_for(sequence)
        if result is None or not result.transitions:
            return self._abstain(sequence)

        peak_novelty = result.peak_novelty
        committed = peak_novelty >= self.novelty_threshold
        mean_surprise = sum(t.novelty.mean for t in result.transitions) / len(
            result.transitions
        )
        return ThreatPredictionV1(
            prediction_id=f"{self.slot_name}-{sequence.sequence_id}",
            sequence_id=sequence.sequence_id,
            verdict=Verdict.SUSPICIOUS if committed else Verdict.BENIGN,
            confidence=peak_novelty if committed else 1.0 - peak_novelty,
            calibration_id=None,
            novelty_score=peak_novelty,
            uncertainty=result.peak_uncertainty,
            evidence_relevance=self._relevance(result),
            next_event=NextEventExpectation(surprise_bits=mean_surprise * 8.0),
            compute_path=ComputePath.STATISTICAL,
            compute_budget_units=float(len(result.transitions)),
            model_state_version=self.model_state_version,
        )
