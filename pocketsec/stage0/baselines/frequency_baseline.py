"""H0 — the conventional baseline every proposed mechanism must beat.

A smoothed bigram model over event ``kind`` transitions. Deliberately boring:
no learned parameters beyond counts, no third-party dependency, fully
deterministic given a seed. Spec principle: "do not learn what can be
represented exactly by deterministic code" — so the hard baseline is the cheap
deterministic thing, and anything more expensive has to earn its place against
this on the same data and hardware.

It also exercises the novelty-energy instrumentation for real: a transition
already in the table resolves via ``CHEAP_TRANSITION``; an unseen one costs a
``STATISTICAL`` step. The resulting "resolved without inference" figure is
measured, not asserted.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from pocketsec.stage0.benchmark.dataset import LabelledSequence
from pocketsec.stage0.contracts.common import EvidenceRef
from pocketsec.stage0.contracts.model_slot import ACCEPTED_INPUT_SCHEMA, PRODUCED_OUTPUT_SCHEMA
from pocketsec.stage0.contracts.security_event_v1 import SecurityEventSequenceV1
from pocketsec.stage0.contracts.threat_prediction_v1 import (
    ComputePath,
    EvidenceRelevance,
    NextEventExpectation,
    ThreatPredictionV1,
    Verdict,
)

__all__ = ["FrequencyBaselineSlot", "SURPRISE_SCALE_BITS"]

BOUNDARY = "<START>"
LAPLACE_ALPHA = 1.0

#: Surprise (bits) mapped to a novelty score of 1.0. Fixed so novelty is
#: comparable across runs rather than rescaled per dataset.
SURPRISE_SCALE_BITS = 12.0

#: Minimum observed transitions before the model will commit to a verdict.
#: Below this it abstains rather than guessing from a near-empty table.
MIN_TRANSITIONS_TO_COMMIT = 8


@dataclass(frozen=True, slots=True)
class _Model:
    """Immutable fitted state: transition counts plus the observed vocabulary."""

    transitions: dict[tuple[str, str], int]
    context_totals: dict[str, int]
    vocabulary: frozenset[str]

    @property
    def transition_count(self) -> int:
        return sum(self.transitions.values())


class FrequencyBaselineSlot:
    """A conventional, deterministic bigram-surprise detector."""

    input_schema = ACCEPTED_INPUT_SCHEMA
    output_schema = PRODUCED_OUTPUT_SCHEMA

    def __init__(self, *, slot_name: str = "h0-frequency-baseline", threshold_bits: float = 4.0):
        self.slot_name = slot_name
        self.threshold_bits = threshold_bits
        self.model_state_version = "h0.0.0.0-unfitted"
        self._model = _Model({}, {}, frozenset())

    # --- fitting -------------------------------------------------------

    def fit(self, items: Iterable[LabelledSequence]) -> FrequencyBaselineSlot:
        """Fit on benign items only, then return self.

        Training on label 0 alone keeps this an anomaly baseline and avoids
        leaking attack labels into the transition table.
        """
        transitions: dict[tuple[str, str], int] = defaultdict(int)
        context_totals: dict[str, int] = defaultdict(int)
        vocabulary: set[str] = set()

        benign = 0
        for item in items:
            if item.label != 0:
                continue
            benign += 1
            for context, kind in self._bigrams(item.sequence):
                transitions[(context, kind)] += 1
                context_totals[context] += 1
                vocabulary.add(kind)

        self._model = _Model(dict(transitions), dict(context_totals), frozenset(vocabulary))
        self.model_state_version = (
            f"h0.1.0.0-b{benign}-t{self._model.transition_count}-v{len(vocabulary)}"
        )
        return self

    @staticmethod
    def _bigrams(sequence: SecurityEventSequenceV1) -> Iterable[tuple[str, str]]:
        context = BOUNDARY
        for event in sequence.events:
            yield context, event.kind
            context = event.kind

    # --- inference -----------------------------------------------------

    def predict(self, sequence: SecurityEventSequenceV1) -> ThreatPredictionV1:
        model = self._model
        surprises: list[float] = []
        all_transitions_known = True

        for context, kind in self._bigrams(sequence):
            count = model.transitions.get((context, kind), 0)
            if count == 0:
                all_transitions_known = False
            total = model.context_totals.get(context, 0)
            # Laplace smoothing over the observed vocabulary plus one slot for
            # anything never seen, so an unknown kind has defined probability.
            denominator = total + LAPLACE_ALPHA * (len(model.vocabulary) + 1)
            probability = (count + LAPLACE_ALPHA) / denominator
            surprises.append(-math.log2(probability))

        mean_surprise = sum(surprises) / len(surprises) if surprises else 0.0
        novelty = min(1.0, mean_surprise / SURPRISE_SCALE_BITS)
        compute_path = (
            ComputePath.CHEAP_TRANSITION if all_transitions_known else ComputePath.STATISTICAL
        )

        if model.transition_count < MIN_TRANSITIONS_TO_COMMIT:
            return self._abstain(sequence, novelty, mean_surprise, compute_path)
        return self._commit(sequence, novelty, mean_surprise, compute_path)

    def _commit(
        self,
        sequence: SecurityEventSequenceV1,
        novelty: float,
        mean_surprise: float,
        compute_path: ComputePath,
    ) -> ThreatPredictionV1:
        exceeded = mean_surprise >= self.threshold_bits
        verdict = Verdict.SUSPICIOUS if exceeded else Verdict.BENIGN
        # Confidence in the *detection*, matching the harness's score direction.
        confidence = novelty if exceeded else max(0.0, 1.0 - novelty)
        return ThreatPredictionV1(
            prediction_id=f"{self.slot_name}-{sequence.sequence_id}",
            sequence_id=sequence.sequence_id,
            verdict=verdict,
            state_identifier=None,
            confidence=confidence,
            # Honest: this model has no calibration map. Leaving this None makes
            # BenchmarkResult.calibrated False rather than faking calibration.
            calibration_id=None,
            novelty_score=novelty,
            uncertainty=novelty,
            abstained=False,
            evidence_relevance=_relevance(sequence),
            next_event=NextEventExpectation(surprise_bits=mean_surprise),
            compute_path=compute_path,
            compute_budget_units=float(len(sequence.events)),
            model_state_version=self.model_state_version,
        )

    def _abstain(
        self,
        sequence: SecurityEventSequenceV1,
        novelty: float,
        mean_surprise: float,
        compute_path: ComputePath,
    ) -> ThreatPredictionV1:
        return ThreatPredictionV1(
            prediction_id=f"{self.slot_name}-{sequence.sequence_id}",
            sequence_id=sequence.sequence_id,
            verdict=Verdict.INSUFFICIENT_EVIDENCE,
            confidence=0.0,
            novelty_score=novelty,
            uncertainty=1.0,
            abstained=True,
            evidence_relevance=_relevance(sequence),
            next_event=NextEventExpectation(surprise_bits=mean_surprise),
            compute_path=compute_path,
            compute_budget_units=float(len(sequence.events)),
            model_state_version=self.model_state_version,
        )


def _relevance(sequence: SecurityEventSequenceV1) -> tuple[EvidenceRelevance, ...]:
    """Uniform relevance over the window's evidence.

    The baseline has no attribution mechanism, so it says so by weighting
    evenly rather than inventing per-event importance.
    """
    refs: tuple[EvidenceRef, ...] = sequence.evidence
    if not refs:
        return ()
    weight = 1.0 / len(refs)
    return tuple(EvidenceRelevance(ref=ref, weight=weight) for ref in refs)
