"""Contract validation: failure paths, not only happy paths."""

from __future__ import annotations

import pytest
from conftest import make_event, make_sequence

from pocketsec.stage0.contracts.common import (
    ContractError,
    EvidenceRef,
    digest_of_bytes,
    register_schema,
)
from pocketsec.stage0.contracts.security_event_v1 import (
    MAX_SEQUENCE_CAPACITY,
    SecurityEventSequenceV1,
    SecurityEventV1,
)
from pocketsec.stage0.contracts.threat_prediction_v1 import (
    ComputePath,
    EvidenceRelevance,
    NextEventExpectation,
    ThreatPredictionV1,
    Verdict,
)

# --- evidence lineage --------------------------------------------------------


def test_evidence_ref_requires_a_content_digest() -> None:
    with pytest.raises(ContractError, match="sha256"):
        EvidenceRef(store="s", locator="l", digest="not-a-digest")


def test_evidence_ref_accepts_a_real_digest() -> None:
    ref = EvidenceRef(store="s", locator="l", digest=digest_of_bytes(b"x"))
    assert ref.digest.startswith("sha256:")


# --- event envelope ----------------------------------------------------------


@pytest.mark.parametrize(
    "field,value",
    [
        ("event_id", ""),
        ("host_id", "has space"),
        ("observed_at_ns", -1),
        ("monotonic_ns", -5),
        ("kind", ""),
    ],
)
def test_event_rejects_malformed_envelope_fields(field: str, value: object) -> None:
    kwargs: dict[str, object] = {
        "event_id": "e1",
        "host_id": "h1",
        "boot_id": "b1",
        "observed_at_ns": 1,
        "monotonic_ns": 1,
        "source": "src",
        "kind": "process.exec",
    }
    kwargs[field] = value
    with pytest.raises(ContractError):
        SecurityEventV1(**kwargs)  # type: ignore[arg-type]


def test_event_attributes_are_copied_not_aliased() -> None:
    """A contract object must never alias mutable caller state."""
    caller_owned = {"user": "root"}
    event = SecurityEventV1(
        event_id="e1",
        host_id="h1",
        boot_id="b1",
        observed_at_ns=1,
        monotonic_ns=1,
        source="src",
        kind="process.exec",
        attributes=caller_owned,
    )
    caller_owned["user"] = "attacker"
    assert event.attributes["user"] == "root"


def test_event_attributes_are_not_mutable_through_the_contract() -> None:
    event = make_event(0)
    with pytest.raises(TypeError):
        event.attributes["injected"] = "value"  # type: ignore[index]


def test_event_is_frozen() -> None:
    event = make_event(0)
    with pytest.raises((AttributeError, TypeError)):
        event.kind = "tampered"  # type: ignore[misc]


# --- sequence invariants -----------------------------------------------------


def test_sequence_rejects_empty_window() -> None:
    with pytest.raises(ContractError, match="must not be empty"):
        SecurityEventSequenceV1(sequence_id="s", host_id="h", events=())


def test_sequence_rejects_mixed_hosts() -> None:
    events = (make_event(0, host="host-a"), make_event(1, host="host-b"))
    with pytest.raises(ContractError, match="does not match"):
        SecurityEventSequenceV1(sequence_id="s", host_id="host-a", events=events)


def test_sequence_rejects_backwards_monotonic_time_within_a_boot() -> None:
    first, second = make_event(5), make_event(1)
    with pytest.raises(ContractError, match="backwards in monotonic time"):
        SecurityEventSequenceV1(sequence_id="s", host_id="host-a", events=(first, second))


def test_sequence_enforces_its_declared_window_capacity() -> None:
    """Bounded state is an invariant, so exceeding the bound is an error."""
    events = tuple(make_event(i) for i in range(5))
    with pytest.raises(ContractError, match="exceeding declared"):
        SecurityEventSequenceV1(
            sequence_id="s", host_id="host-a", events=events, window_capacity=3
        )


def test_sequence_capacity_cannot_exceed_the_global_bound() -> None:
    with pytest.raises(ContractError, match=r"within \[1, 4096\]"):
        make_sequence(window_capacity=MAX_SEQUENCE_CAPACITY + 1)


def test_truncation_is_explicit_so_a_bounded_buffer_is_not_a_silent_false_negative() -> None:
    sequence = make_sequence(truncated=True)
    assert sequence.truncated is True
    assert sequence.to_dict()["truncated"] is True


def test_sequence_round_trips_through_dict() -> None:
    original = make_sequence(("process.exec", "file.open", "net.connect"))
    restored = SecurityEventSequenceV1.from_dict(original.to_dict())
    assert restored == original


def test_sequence_from_dict_rejects_a_foreign_schema() -> None:
    payload = make_sequence().to_dict()
    payload["schema"] = "some.other.schema.v1"
    with pytest.raises(ContractError, match="expected schema"):
        SecurityEventSequenceV1.from_dict(payload)


def test_sequence_exposes_evidence_in_observation_order() -> None:
    sequence = make_sequence(("a.b", "c.d", "e.f"))
    assert len(sequence.evidence) == 3
    assert [ref.locator for ref in sequence.evidence] == ["e0", "e1", "e2"]


# --- prediction --------------------------------------------------------------


def _prediction(**overrides: object) -> ThreatPredictionV1:
    kwargs: dict[str, object] = {
        "prediction_id": "p1",
        "sequence_id": "seq-1",
        "verdict": Verdict.BENIGN,
        "confidence": 0.9,
        "novelty_score": 0.1,
        "uncertainty": 0.1,
        "model_state_version": "m.1.0.0",
        "compute_path": ComputePath.CHEAP_TRANSITION,
    }
    kwargs.update(overrides)
    return ThreatPredictionV1(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("field", ["confidence", "novelty_score", "uncertainty"])
@pytest.mark.parametrize("value", [-0.01, 1.01, float("nan"), float("inf")])
def test_prediction_rejects_out_of_range_scores(field: str, value: float) -> None:
    with pytest.raises(ContractError):
        _prediction(**{field: value})


def test_abstention_cannot_coexist_with_a_committal_verdict() -> None:
    with pytest.raises(ContractError, match="cannot also assert"):
        _prediction(verdict=Verdict.MALICIOUS, abstained=True)


def test_insufficient_evidence_requires_abstention() -> None:
    with pytest.raises(ContractError, match="requires abstained=True"):
        _prediction(verdict=Verdict.INSUFFICIENT_EVIDENCE, abstained=False, confidence=0.0)


@pytest.mark.parametrize(
    "verdict", [Verdict.UNKNOWN, Verdict.UNIDENTIFIABLE, Verdict.INSUFFICIENT_EVIDENCE]
)
def test_non_committal_verdicts_are_valid_answers(verdict: Verdict) -> None:
    """UNKNOWN/UNIDENTIFIABLE/INSUFFICIENT_EVIDENCE are answers, not errors."""
    prediction = _prediction(verdict=verdict, abstained=True, confidence=0.0, uncertainty=1.0)
    assert prediction.is_committal is False


def test_uncalibrated_confidence_is_reported_as_uncalibrated() -> None:
    """An unmeasured calibration must never be dressed up as a measured one."""
    assert _prediction(calibration_id=None).is_calibrated is False
    assert _prediction(calibration_id="platt.v1").is_calibrated is True


def test_evidence_relevance_weight_must_be_a_unit_interval() -> None:
    ref = EvidenceRef(store="s", locator="l", digest=digest_of_bytes(b"x"))
    with pytest.raises(ContractError):
        EvidenceRelevance(ref=ref, weight=1.5)


def test_next_event_distribution_cannot_exceed_total_probability_one() -> None:
    with pytest.raises(ContractError, match="exceeds 1.0"):
        NextEventExpectation(distribution={"a.b": 0.7, "c.d": 0.7})


def test_negative_surprise_is_rejected() -> None:
    with pytest.raises(ContractError, match="surprise_bits"):
        NextEventExpectation(surprise_bits=-1.0)


# --- schema registry ---------------------------------------------------------


def test_reregistering_a_schema_at_a_new_version_is_refused() -> None:
    """A breaking change takes a new schema id, never a version bump in place."""
    register_schema("pocketsec.test.registry.v1", "1.0.0")
    register_schema("pocketsec.test.registry.v1", "1.0.0")  # idempotent
    with pytest.raises(ContractError, match="requires a new schema id"):
        register_schema("pocketsec.test.registry.v1", "2.0.0")
