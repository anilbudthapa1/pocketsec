"""The replaceable model slot — the frozen hub/model boundary (spec section 9).

The hub owns telemetry normalisation, deterministic rules, evidence, storage and
presentation. It talks to intelligence through exactly one interface, so a model
family can be swapped, demoted or removed without touching the product.

``NullModelSlot`` is not a placeholder to delete later: it is the proof that the
hub degrades to "no learned intelligence" and still produces well-formed,
honestly-abstaining output.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.security_event_v1 import (
    SECURITY_EVENT_SEQUENCE_V1_ID,
    SecurityEventSequenceV1,
)
from pocketsec.stage0.contracts.threat_prediction_v1 import (
    THREAT_PREDICTION_V1_ID,
    ComputePath,
    ThreatPredictionV1,
    Verdict,
)

__all__ = [
    "ACCEPTED_INPUT_SCHEMA",
    "ModelSlot",
    "NullModelSlot",
    "PRODUCED_OUTPUT_SCHEMA",
    "validate_slot",
]

ACCEPTED_INPUT_SCHEMA = SECURITY_EVENT_SEQUENCE_V1_ID
PRODUCED_OUTPUT_SCHEMA = THREAT_PREDICTION_V1_ID


@runtime_checkable
class ModelSlot(Protocol):
    """Everything PocketSec requires of an intelligence implementation."""

    #: Stable name for results and provenance, e.g. ``"h0-frequency-baseline"``.
    slot_name: str
    #: Version of the *learned state*, distinct from the code version.
    model_state_version: str
    #: Schema ids this slot was built against.
    input_schema: str
    output_schema: str

    def predict(self, sequence: SecurityEventSequenceV1) -> ThreatPredictionV1:
        """Score one bounded window. Must not mutate ``sequence``."""
        ...


def validate_slot(slot: ModelSlot) -> None:
    """Fail fast when a slot does not match the frozen boundary.

    The hub calls this before wiring a slot. A slot built against a different
    schema id is a wiring error, not something to coerce at runtime.
    """
    if not isinstance(slot, ModelSlot):
        raise ContractError(
            f"{type(slot).__name__} does not satisfy the ModelSlot protocol"
        )
    if slot.input_schema != ACCEPTED_INPUT_SCHEMA:
        raise ContractError(
            f"slot {slot.slot_name!r} accepts {slot.input_schema!r}, "
            f"hub emits {ACCEPTED_INPUT_SCHEMA!r}"
        )
    if slot.output_schema != PRODUCED_OUTPUT_SCHEMA:
        raise ContractError(
            f"slot {slot.slot_name!r} emits {slot.output_schema!r}, "
            f"hub consumes {PRODUCED_OUTPUT_SCHEMA!r}"
        )


class NullModelSlot:
    """A slot that always abstains.

    Used as the lower bound in every benchmark: any proposed mechanism has to
    beat "answer INSUFFICIENT_EVIDENCE forever" before it is worth its cost.
    """

    slot_name = "null-abstain"
    model_state_version = "null.1.0.0"
    input_schema = ACCEPTED_INPUT_SCHEMA
    output_schema = PRODUCED_OUTPUT_SCHEMA

    def predict(self, sequence: SecurityEventSequenceV1) -> ThreatPredictionV1:
        return ThreatPredictionV1(
            prediction_id=f"null-{sequence.sequence_id}",
            sequence_id=sequence.sequence_id,
            verdict=Verdict.INSUFFICIENT_EVIDENCE,
            confidence=0.0,
            novelty_score=0.0,
            uncertainty=1.0,
            abstained=True,
            model_state_version=self.model_state_version,
            compute_path=ComputePath.CHEAP_TRANSITION,
            compute_budget_units=0.0,
        )
