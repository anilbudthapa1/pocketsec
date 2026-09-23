"""D0.2 — versioned interface skeletons for the stable hub/model boundary."""

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef, SCHEMA_REGISTRY
from pocketsec.stage0.contracts.model_slot import ModelSlot, NullModelSlot, validate_slot
from pocketsec.stage0.contracts.security_event_v1 import (
    SECURITY_EVENT_SEQUENCE_V1_ID,
    SECURITY_EVENT_SEQUENCE_V1_VERSION,
    SecurityEventSequenceV1,
    SecurityEventV1,
)
from pocketsec.stage0.contracts.threat_prediction_v1 import (
    THREAT_PREDICTION_V1_ID,
    THREAT_PREDICTION_V1_VERSION,
    ComputePath,
    EvidenceRelevance,
    NextEventExpectation,
    ThreatPredictionV1,
    Verdict,
)

__all__ = [
    "ComputePath",
    "ContractError",
    "EvidenceRef",
    "EvidenceRelevance",
    "ModelSlot",
    "NextEventExpectation",
    "NullModelSlot",
    "SCHEMA_REGISTRY",
    "SECURITY_EVENT_SEQUENCE_V1_ID",
    "SECURITY_EVENT_SEQUENCE_V1_VERSION",
    "SecurityEventSequenceV1",
    "SecurityEventV1",
    "THREAT_PREDICTION_V1_ID",
    "THREAT_PREDICTION_V1_VERSION",
    "ThreatPredictionV1",
    "Verdict",
    "validate_slot",
]
