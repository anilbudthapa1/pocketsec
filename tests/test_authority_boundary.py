"""ADR-0003 — a model output structurally cannot carry response authority.

These tests are the enforcement mechanism for a MEMORY.md invariant: model
confidence never grants execution authority. They are deliberately written so
that weakening the invariant means deleting a test whose name says what it
protects.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from pocketsec.stage0.contracts.model_slot import NullModelSlot, validate_slot
from pocketsec.stage0.contracts.threat_prediction_v1 import (
    FORBIDDEN_AUTHORITY_FIELDS,
    ThreatPredictionV1,
    Verdict,
)
from pocketsec.stage0.gate import REPO_ROOT

SCHEMA_PATH = REPO_ROOT / "contracts" / "threat_prediction_v1.schema.json"


def _field_names() -> set[str]:
    return {field.name for field in dataclasses.fields(ThreatPredictionV1)}


def test_prediction_dataclass_has_no_authority_bearing_field() -> None:
    offending = {
        name
        for name in _field_names()
        for banned in FORBIDDEN_AUTHORITY_FIELDS
        if banned in name.lower()
    }
    assert not offending, (
        f"ThreatPredictionV1 gained authority-bearing field(s) {sorted(offending)}. "
        "Response authority belongs to Stage 5 under SENTINEL, never to a model output."
    )


def test_prediction_schema_has_no_authority_bearing_property() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    offending = {
        name
        for name in schema["properties"]
        for banned in FORBIDDEN_AUTHORITY_FIELDS
        if banned in name.lower()
    }
    assert not offending, f"schema gained authority-bearing propert(ies) {sorted(offending)}"


def test_prediction_schema_forbids_additional_properties() -> None:
    """Closed schema: an unknown field is a validation failure, not an extension."""
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["additionalProperties"] is False


def test_serialised_prediction_exposes_only_known_keys() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    prediction = NullModelSlot().predict(_sequence())
    assert set(prediction.to_dict()) <= set(schema["properties"])


def test_confidence_alone_never_marks_a_prediction_as_actionable() -> None:
    """There is no property that turns high confidence into permission."""
    prediction = ThreatPredictionV1(
        prediction_id="p1",
        sequence_id="seq-1",
        verdict=Verdict.MALICIOUS,
        confidence=1.0,
        novelty_score=1.0,
        uncertainty=0.0,
        model_state_version="m.1.0.0",
        compute_path="LEARNED_SOLVER",
    )
    payload = prediction.to_dict()
    assert not any(
        banned in key.lower() for key in payload for banned in FORBIDDEN_AUTHORITY_FIELDS
    )


# --- the hub survives with no model at all -----------------------------------


def _sequence():  # type: ignore[no-untyped-def]
    from conftest import make_sequence

    return make_sequence()


def test_null_slot_satisfies_the_boundary_and_always_abstains() -> None:
    slot = NullModelSlot()
    validate_slot(slot)
    prediction = slot.predict(_sequence())
    assert prediction.abstained is True
    assert prediction.verdict is Verdict.INSUFFICIENT_EVIDENCE
    assert prediction.is_committal is False


def test_a_slot_built_against_a_foreign_schema_is_refused() -> None:
    class ForeignSlot:
        slot_name = "foreign"
        model_state_version = "f.1.0.0"
        input_schema = "someone.else.events.v1"
        output_schema = "pocketsec.threat_prediction.v1"

        def predict(self, sequence):  # type: ignore[no-untyped-def]
            raise AssertionError("must never be called")

    with pytest.raises(Exception, match="accepts"):
        validate_slot(ForeignSlot())  # type: ignore[arg-type]


def test_predicting_does_not_mutate_the_input_window() -> None:
    sequence = _sequence()
    before = sequence.to_dict()
    NullModelSlot().predict(sequence)
    assert sequence.to_dict() == before


def test_schema_path_exists() -> None:
    assert SCHEMA_PATH.is_file(), f"missing {SCHEMA_PATH}"
    assert isinstance(REPO_ROOT, Path)
