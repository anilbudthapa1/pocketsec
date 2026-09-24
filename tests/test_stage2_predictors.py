"""Stage 2 `predictors` — heads (D2.5), residuals (DTL-F09), cone and hazard (D2.8).

Three kinds of test live here.

1. **Contract tests.** A head with a shape mismatch or no recorded training run
   must not load. A cone whose probabilities do not sum to one must not exist.
   These assert the invariant at its tolerance, so loosening the tolerance breaks
   them — which is the point.
2. **Behaviour and failure paths.** The abstention path (an all-unknown cone) is
   reached, not merely reachable; bounds actually bound; adversarial input (NaN
   logits, ragged windows, negative bitmasks, inverted counts) is rejected.
3. **One measured comparison**, on a fixed `(corpus='ambiguous', count=240,
   seed=11)` split: Brier for `predict_future_cone` against `marginal_cone`, and
   Brier + ECE for `estimate_security_hazard` against `constant_hazard`. Both
   numbers are printed and **neither is asserted to win**. The architecture gate
   permits removal of the cone, and the measurement decides, not this file.

The `lattice` and `routing` packages are written in parallel with this one, so
the collaborators below are minimal local stand-ins implementing the published
signatures from `docs/stage-2-spec.md`. The code under test is this package's;
the stand-ins are the fixture. Anything measured through them is reported as
measured through them.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Iterator, Mapping, Sequence

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.ssir.relations import Relation, RelationFamily
from pocketsec.stage1.ssir.transition import TemporalContext
from pocketsec.stage1.state.security_state import (
    DIMENSIONS,
    Privilege,
    SecurityStateV1,
)
from pocketsec.stage2.dataset import build_dataset
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_WIDTH, EncodedTransition
from pocketsec.stage2.predictors.future_cone import (
    CONE_LABELS,
    MAX_BRANCHES,
    MAX_DEPTH,
    UNKNOWN_LABEL,
    ConeBranch,
    FutureCone,
    branch_label,
    marginal_cone,
    predict_future_cone,
)
from pocketsec.stage2.predictors.hazard import (
    HORIZONS,
    OUTCOME_DIMENSIONS,
    OUTCOMES,
    HazardEstimate,
    HazardReport,
    constant_hazard,
    estimate_security_hazard,
)
from pocketsec.stage2.predictors.heads import (
    HEAD_CLASSES,
    HEAD_IDS,
    TIME_BUCKETS,
    HeadPrediction,
    HeadWeights,
    PredictiveHeads,
    phi_bucket,
    pool_window,
    softmax,
)
from pocketsec.stage2.predictors.residual import (
    MULTI_LABEL_HEADS,
    OBJECT_PROPERTY_NAMES,
    SCORABLE_HEADS,
    class_names,
    score_prediction_residual,
)

EXPERIMENT_ID = "PS-S2-20260924-H1-predictors-0007"
DIMENSION_NAMES: tuple[str, ...] = tuple(DIMENSIONS)


# --- local stand-ins for the concurrently-built collaborators ----------------


class StubWindow:
    """Only `.features()` is consumed from `state.window.LineageWindow`."""

    def __init__(self, rows: Sequence[Sequence[float]]) -> None:
        self._rows = tuple(tuple(float(v) for v in row) for row in rows)

    def features(self) -> tuple[tuple[float, ...], ...]:
        return self._rows


@dataclass(frozen=True, slots=True)
class StubAtom:
    """`lattice.atom.BehaviourAtom`, reduced to what the cone reads."""

    atom_id: int
    state_summary: SecurityStateV1
    visit_count: int = 1
    delta_phi_mean: float = 0.0


class StubQuantizer:
    def __init__(self, atoms: Mapping[int, StubAtom]) -> None:
        self._atoms = dict(atoms)

    def get(self, atom_id: int) -> StubAtom | None:
        return self._atoms.get(atom_id)


class StubLattice:
    """`lattice.transitions.TransitionLattice`, reduced to the queried surface."""

    def __init__(self, *, alpha: float = 0.0) -> None:
        self._counts: dict[tuple[int, int, int], int] = {}
        self._alpha = alpha
        # Memoised so a timing of `predict_future_cone` measures the cone rather
        # than this fixture's O(edges) scan.
        self._cache: dict[tuple[int, int | None], dict[int, int]] = {}

    def observe(self, source: int, target: int, *, epoch_id: int) -> None:
        key = (epoch_id, source, target)
        self._counts[key] = self._counts.get(key, 0) + 1
        self._cache.clear()

    def _rows(self, source: int, epoch_id: int | None) -> dict[int, int]:
        cached = self._cache.get((source, epoch_id))
        if cached is not None:
            return cached
        rows: dict[int, int] = {}
        for (epoch, src, target), count in self._counts.items():
            if src != source or (epoch_id is not None and epoch != epoch_id):
                continue
            rows[target] = rows.get(target, 0) + count
        self._cache[(source, epoch_id)] = rows
        return rows

    def probability(
        self, source: int, target: int, *, epoch_id: int | None = None
    ) -> float:
        rows = self._rows(source, epoch_id)
        total = sum(rows.values())
        if not total:
            return 0.0
        return rows.get(target, 0) / total

    def successors(
        self, source: int, *, epoch_id: int | None = None, limit: int = 8
    ) -> tuple[tuple[int, float], ...]:
        rows = self._rows(source, epoch_id)
        total = sum(rows.values())
        if not total:
            return ()
        ranked = sorted(rows.items(), key=lambda item: (-item[1], item[0]))
        return tuple((target, count / total) for target, count in ranked[:limit])

    def sources(self) -> tuple[int, ...]:
        return tuple(sorted({src for _, src, _ in self._counts}))

    def source_counts(self) -> dict[int, float]:
        counts: dict[int, float] = {}
        for (_, src, _), count in self._counts.items():
            counts[src] = counts.get(src, 0.0) + count
        return counts


@dataclass
class RecordingLedger:
    """`router.accounting.WorkLedger`, reduced to `record`."""

    records: list[tuple[Any, bool, float, str]] = field(default_factory=list)

    def record(
        self, kind: Any, *, performed: bool, units: float, detail: str = ""
    ) -> None:
        self.records.append((kind, performed, units, detail))


# --- head builders -----------------------------------------------------------


def make_head(
    head_id: str,
    *,
    fill: float = 0.0,
    bias: Sequence[float] | None = None,
    experiment_id: str = EXPERIMENT_ID,
    classes: int | None = None,
    input_width: int = FEATURE_WIDTH,
    rows: Sequence[Sequence[float]] | None = None,
) -> HeadWeights:
    count = HEAD_CLASSES[head_id] if classes is None else classes
    weight_rows = (
        tuple(tuple(fill for _ in range(input_width)) for _ in range(count))
        if rows is None
        else tuple(tuple(float(v) for v in row) for row in rows)
    )
    return HeadWeights(
        head_id=head_id,
        input_width=input_width,
        classes=count,
        weights=weight_rows,
        bias=tuple(0.0 for _ in range(count)) if bias is None else tuple(bias),
        trained_experiment_id=experiment_id,
    )


def unit_window(value: float = 1.0) -> StubWindow:
    return StubWindow([[value] * FEATURE_WIDTH])


# --- D2.5: HeadWeights contract ---------------------------------------------


def test_head_weights_rejects_a_row_width_mismatch() -> None:
    with pytest.raises(ContractError, match="width"):
        make_head("relation", rows=[[0.0] * (FEATURE_WIDTH - 1)] * len(Relation))


def test_head_weights_rejects_a_row_count_mismatch() -> None:
    with pytest.raises(ContractError, match="weight rows"):
        make_head("relation", rows=[[0.0] * FEATURE_WIDTH] * (len(Relation) - 1))


def test_head_weights_rejects_a_bias_length_mismatch() -> None:
    with pytest.raises(ContractError, match="biases"):
        make_head("epoch", bias=[0.0])


def test_head_weights_rejects_an_empty_experiment_id() -> None:
    """A head with no recorded training run is rejectable by construction."""
    with pytest.raises(ContractError, match="trained_experiment_id"):
        make_head("epoch", experiment_id="   ")


def test_head_weights_rejects_a_stale_vocabulary() -> None:
    """A weights file trained against the wrong class count must not load."""
    with pytest.raises(ContractError, match="Stage 1 vocabulary"):
        make_head("relation", classes=len(Relation) + 1)


def test_head_weights_rejects_an_unknown_head_id() -> None:
    with pytest.raises(ContractError, match="unknown head id"):
        make_head("sentiment", classes=2)


def test_head_weights_rejects_a_width_that_is_not_the_encoder_width() -> None:
    with pytest.raises(ContractError, match="FEATURE_WIDTH"):
        make_head("epoch", input_width=FEATURE_WIDTH + 1)


# --- D2.5: vocabularies are derived, never written down ----------------------


def test_head_ids_are_the_eight_heads_of_spec_section_8() -> None:
    assert HEAD_IDS == (
        "relation",
        "object",
        "state_delta",
        "time",
        "causal",
        "epoch",
        "phi",
        "uncertainty",
    )
    assert len(HEAD_IDS) == 8
    assert set(HEAD_CLASSES) == set(HEAD_IDS)


def test_vocabulary_sizes_come_from_stage_1_not_from_literals() -> None:
    """If Stage 1 grows a relation or a dimension, these must move with it."""
    assert HEAD_CLASSES["relation"] == len(Relation)
    assert HEAD_CLASSES["causal"] == len(RelationFamily)
    assert HEAD_CLASSES["state_delta"] == len(DIMENSIONS)
    # Derived by asking Stage 1's own bucketer for its ceiling.
    assert HEAD_CLASSES["time"] == TemporalContext.bucket(1 << 62) + 1 == TIME_BUCKETS
    # And the object head's classes are the encoder's exposed property subset,
    # which is what `object_property_mask` bit indices actually address.
    assert HEAD_CLASSES["object"] == len(OBJECT_PROPERTY_NAMES)
    assert len(class_names("state_delta")) == len(DIMENSIONS)


# --- D2.5: softmax stability -------------------------------------------------


@pytest.mark.parametrize(
    "logits",
    [
        (0.0, 0.0, 0.0),
        (1e308, -1e308, 0.0),
        (-1e308, -1e308, -1e308),
        (710.0, 709.0),
        (-710.0, -1e6),
    ],
)
def test_softmax_is_a_distribution_at_extreme_logits(logits: tuple[float, ...]) -> None:
    probabilities = softmax(logits)
    assert all(0.0 <= p <= 1.0 for p in probabilities)
    assert all(math.isfinite(p) for p in probabilities)
    assert abs(sum(probabilities) - 1.0) < 1e-12


def test_softmax_refuses_nan_rather_than_reporting_confidence() -> None:
    with pytest.raises(ContractError, match="NaN"):
        softmax((0.0, float("nan")))


def test_softmax_splits_infinite_logits_instead_of_producing_nan() -> None:
    probabilities = softmax((math.inf, math.inf, 0.0))
    assert probabilities == (0.5, 0.5, 0.0)


def test_softmax_refuses_an_empty_logit_vector() -> None:
    with pytest.raises(ContractError):
        softmax(())


def test_pool_window_refuses_empty_and_ragged_windows() -> None:
    with pytest.raises(ContractError, match="empty window"):
        pool_window([])
    with pytest.raises(ContractError, match="ragged"):
        pool_window([[1.0, 2.0], [1.0]])


def test_pool_window_takes_the_max_over_time() -> None:
    """Max-over-time is the only pooling this project measured as justified."""
    assert pool_window([[0.0, 5.0], [3.0, 1.0]]) == (3.0, 5.0)


# --- D2.5: prediction --------------------------------------------------------


def test_predict_returns_one_distribution_per_loaded_head() -> None:
    heads = PredictiveHeads(
        {head_id: make_head(head_id) for head_id in ("relation", "epoch")}
    )
    predictions = heads.predict(unit_window())
    assert set(predictions) == {"relation", "epoch"}
    for head_id, prediction in predictions.items():
        assert len(prediction.probabilities) == HEAD_CLASSES[head_id]
        assert abs(sum(prediction.probabilities) - 1.0) < 1e-12
        assert prediction.entropy >= 0.0
        assert 0 <= prediction.argmax < HEAD_CLASSES[head_id]


def test_predict_refuses_an_empty_window() -> None:
    heads = PredictiveHeads({"epoch": make_head("epoch")})
    with pytest.raises(ContractError, match="empty window"):
        heads.predict(StubWindow([]))


def test_predict_refuses_a_window_of_the_wrong_width() -> None:
    heads = PredictiveHeads({"epoch": make_head("epoch")})
    with pytest.raises(ContractError, match="expects"):
        heads.predict(StubWindow([[1.0] * (FEATURE_WIDTH - 2)]))


def test_predictive_heads_refuses_an_empty_head_set() -> None:
    with pytest.raises(ContractError, match="at least one head"):
        PredictiveHeads({})


def test_predictive_heads_refuses_a_mislabelled_registration() -> None:
    with pytest.raises(ContractError, match="declares"):
        PredictiveHeads({"epoch": make_head("relation")})


def test_parameters_and_memory_are_computed_not_declared() -> None:
    heads = PredictiveHeads({"relation": make_head("relation")})
    assert heads.parameters() == len(Relation) * FEATURE_WIDTH + len(Relation)
    assert heads.memory_bytes() > heads.parameters() * 8


def test_from_json_round_trips_through_plain_data(tmp_path: Any) -> None:
    import json

    source = PredictiveHeads({"epoch": make_head("epoch", fill=0.25)})
    path = tmp_path / "heads.json"
    path.write_text(
        json.dumps({"heads": {"epoch": make_head("epoch", fill=0.25).to_dict()}}),
        encoding="utf-8",
    )
    loaded = PredictiveHeads.from_json(path)
    assert loaded.head_ids == source.head_ids
    assert loaded.parameters() == source.parameters()


def test_from_json_rejects_a_head_with_no_experiment_id(tmp_path: Any) -> None:
    import json

    payload = make_head("epoch").to_dict()
    payload["trained_experiment_id"] = ""
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"heads": {"epoch": payload}}), encoding="utf-8")
    with pytest.raises(ContractError, match="trained_experiment_id"):
        PredictiveHeads.from_json(path)


def test_a_nan_logit_is_refused_and_never_becomes_maximum_confidence() -> None:
    """Pins S2-AUTH-03.

    ``_sigmoid`` clamped with ``max(-700.0, min(700.0, logit))``, and
    ``min(700.0, nan)`` returns 700.0 in CPython — every comparison with NaN is
    False, so the two-argument form falls through to its first operand. A NaN
    logit therefore became sigmoid **1.0**, and ``predict_security_state_delta``
    thresholds on that, so the affected security dimension was reported as about
    to be raised on every event with nothing raising anywhere. ``softmax`` one
    method above already refused NaN logits for exactly this reason.
    """
    from pocketsec.stage2.predictors.heads import _sigmoid

    assert min(700.0, math.nan) == 700.0, "the CPython behaviour this pins"
    for bad in (math.nan, math.inf, -math.inf):
        with pytest.raises(ContractError, match="non-finite"):
            _sigmoid(bad)
    assert _sigmoid(0.0) == 0.5
    assert _sigmoid(800.0) == 1.0  # a merely saturated logit still clamps


def test_a_head_trained_to_divergence_is_refused_at_load(tmp_path: Any) -> None:
    """Pins S2-AUTH-03's load path.

    ``models/experimental/`` is a gitignored artefact store and ``from_json``
    reads it with a bare ``json.loads``, which accepts the non-standard bare
    ``NaN``/``Infinity`` literals. A head trained to divergence, a truncated
    download, or a file with one edited value used to load cleanly and then
    report every one of its dimensions as rising.
    """
    import json

    payload = make_head("state_delta").to_dict()
    payload["weights"][0][0] = float("nan")
    path = tmp_path / "diverged.json"
    path.write_text(
        json.dumps({"heads": {"state_delta": payload}}), encoding="utf-8"
    )
    with pytest.raises(ContractError, match="non-finite"):
        PredictiveHeads.from_json(path)

    # The bare `NaN` literal a corrupted file most plausibly carries.
    raw = json.dumps({"heads": {"state_delta": make_head("state_delta").to_dict()}})
    literal = tmp_path / "literal.json"
    literal.write_text(raw.replace('"bias": [0.0', '"bias": [NaN'), encoding="utf-8")
    with pytest.raises(ContractError, match="non-finite"):
        PredictiveHeads.from_json(literal)


def test_from_json_rejects_an_unparseable_experiment_id(tmp_path: Any) -> None:
    """A non-empty string is not a recorded training run (S2-AUTH-03)."""
    import json

    payload = make_head("epoch").to_dict()
    payload["trained_experiment_id"] = "x"
    path = tmp_path / "unparseable.json"
    path.write_text(json.dumps({"heads": {"epoch": payload}}), encoding="utf-8")
    with pytest.raises(ContractError, match="does not parse"):
        PredictiveHeads.from_json(path)


def test_from_json_rejects_a_malformed_file(tmp_path: Any) -> None:
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ContractError, match="cannot read"):
        PredictiveHeads.from_json(path)


# --- DTL-F06: predict_security_state_delta ----------------------------------


def _state_delta_heads(bias: Sequence[float]) -> PredictiveHeads:
    return PredictiveHeads({"state_delta": make_head("state_delta", bias=bias)})


def test_predicted_state_delta_only_names_real_dimensions() -> None:
    heads = _state_delta_heads([9.0] * len(DIMENSIONS))
    delta = heads.predict_security_state_delta(unit_window())
    assert delta.dimensions <= frozenset(DIMENSIONS)
    assert delta.dimensions == frozenset(DIMENSIONS)
    assert delta.bitmask() == (1 << len(DIMENSIONS)) - 1


def test_predicted_state_delta_can_be_empty() -> None:
    """Predicting "nothing moves" is the common, correct answer."""
    heads = _state_delta_heads([-9.0] * len(DIMENSIONS))
    delta = heads.predict_security_state_delta(unit_window())
    assert not delta
    assert delta.dimensions == frozenset()


def test_predicted_state_delta_is_per_dimension_not_argmax() -> None:
    """Two dimensions can be predicted at once; a softmax argmax cannot say that."""
    bias = [-9.0] * len(DIMENSIONS)
    bias[DIMENSION_NAMES.index("privilege")] = 9.0
    bias[DIMENSION_NAMES.index("credential")] = 9.0
    delta = _state_delta_heads(bias).predict_security_state_delta(unit_window())
    assert delta.dimensions == {"privilege", "credential"}


def test_predict_security_state_delta_requires_its_required_head() -> None:
    heads = PredictiveHeads({"relation": make_head("relation")})
    with pytest.raises(ContractError, match="DTL-F06 is REQUIRED"):
        heads.predict_security_state_delta(unit_window())


# --- DTL-F09: residuals and negative space ----------------------------------


def _encoded(
    *,
    relation: int = int(Relation.READ),
    state_delta_mask: int = 0,
    object_property_mask: int = 0,
    time_bucket: int = 0,
    delta_phi: float = 0.0,
) -> EncodedTransition:
    return EncodedTransition(
        features=tuple(0.0 for _ in range(FEATURE_WIDTH)),
        relation=relation,
        relation_family=0,
        state_delta_mask=state_delta_mask,
        time_bucket=time_bucket,
        delta_phi=delta_phi,
        object_property_mask=object_property_mask,
        epoch_id=0,
    )


def _prediction(head_id: str, probabilities: Sequence[float]) -> HeadPrediction:
    values = tuple(float(p) for p in probabilities)
    return HeadPrediction(
        head_id=head_id,
        probabilities=values,
        argmax=max(range(len(values)), key=values.__getitem__),
        entropy=-sum(p * math.log(p) for p in values if p > 0),
    )


def _peaked(head_id: str, index: int, mass: float) -> HeadPrediction:
    count = HEAD_CLASSES[head_id]
    rest = (1.0 - mass) / (count - 1)
    return _prediction(
        head_id, [mass if i == index else rest for i in range(count)]
    )


def test_residual_reports_an_expected_continuation_that_did_not_occur() -> None:
    """The negative-space half of spec section 23, on a constructed case."""
    expected = int(Relation.SEND)
    observed_relation = int(Relation.READ)
    predicted = {"relation": _peaked("relation", expected, 0.80)}
    residual = score_prediction_residual(
        predicted, _encoded(relation=observed_relation), expectation_floor=0.05
    )
    assert f"relation:{Relation.SEND.name.lower()}" in residual.absent_expected
    assert residual.absent_mass == pytest.approx(0.80, abs=1e-9)
    # The observed class was improbable, so the observed surprise is large.
    assert residual.observed_surprise > 2.0


def test_residual_reports_no_absent_expectation_when_the_expected_happened() -> None:
    observed = int(Relation.SEND)
    predicted = {"relation": _peaked("relation", observed, 0.80)}
    residual = score_prediction_residual(predicted, _encoded(relation=observed))
    assert residual.absent_expected == ()
    assert residual.absent_mass == 0.0
    assert residual.observed_surprise < 0.3


def test_residual_components_stay_separate_per_head() -> None:
    """Surprise is a geometry (spec section 9); collapsing it is forbidden."""
    predicted = {
        "relation": _peaked("relation", int(Relation.SEND), 0.9),
        "time": _peaked("time", 7, 0.9),
        "phi": _peaked("phi", 0, 0.9),
    }
    residual = score_prediction_residual(
        predicted, _encoded(relation=int(Relation.READ), time_bucket=7, delta_phi=0.0)
    )
    assert set(residual.components) == {"relation", "time", "phi"}
    # The time head was right and the relation head was wrong: the components
    # must not be equal, which is exactly what a single scalar would lose.
    assert residual.components["time"] < residual.components["relation"]
    assert residual.observed_surprise == pytest.approx(
        sum(residual.components.values())
    )
    assert residual.magnitude > 0.0


def test_residual_components_cannot_be_mutated_after_construction() -> None:
    residual = score_prediction_residual(
        {"relation": _peaked("relation", 0, 0.5)}, _encoded(relation=0)
    )
    snapshot = dict(residual.components)
    residual.components["relation"] = 999.0
    assert score_prediction_residual(
        {"relation": _peaked("relation", 0, 0.5)}, _encoded(relation=0)
    ).components == snapshot


def test_residual_scores_a_multi_label_head_without_an_infinite_surprise() -> None:
    """"Nothing was raised" is an observation, not an impossibility."""
    count = HEAD_CLASSES["state_delta"]
    predicted = {"state_delta": _prediction("state_delta", [1.0 / count] * count)}
    residual = score_prediction_residual(predicted, _encoded(state_delta_mask=0))
    assert math.isfinite(residual.observed_surprise)
    assert "state_delta" in MULTI_LABEL_HEADS


def test_residual_names_absent_state_dimensions_by_stage_1_name() -> None:
    index = DIMENSION_NAMES.index("credential")
    predicted = {"state_delta": _peaked("state_delta", index, 0.9)}
    residual = score_prediction_residual(predicted, _encoded(state_delta_mask=0))
    assert "state_delta:credential" in residual.absent_expected


def test_residual_skips_heads_with_no_observable_ground_truth() -> None:
    """An unsupervised head fits noise; it is not scored against a guess."""
    predicted = {
        "relation": _peaked("relation", 0, 0.5),
        "epoch": _peaked("epoch", 0, 0.9),
        "uncertainty": _peaked("uncertainty", 0, 0.9),
        "causal": _peaked("causal", 0, 0.9),
    }
    residual = score_prediction_residual(predicted, _encoded(relation=0))
    assert set(residual.components) == {"relation"}
    assert not {"epoch", "uncertainty", "causal"} & set(SCORABLE_HEADS)


def test_residual_refuses_when_no_scorable_head_was_supplied() -> None:
    with pytest.raises(ContractError, match="no scorable head"):
        score_prediction_residual({"epoch": _peaked("epoch", 0, 0.9)}, _encoded())


def test_residual_refuses_an_out_of_range_expectation_floor() -> None:
    with pytest.raises(ContractError, match="expectation_floor"):
        score_prediction_residual(
            {"relation": _peaked("relation", 0, 0.5)}, _encoded(), expectation_floor=0.0
        )


def test_residual_refuses_a_head_whose_width_does_not_match_the_vocabulary() -> None:
    bad = _prediction("relation", [0.5, 0.5])
    with pytest.raises(ContractError, match="vocabulary has"):
        score_prediction_residual({"relation": bad}, _encoded())


def test_residual_refuses_a_negative_bitmask() -> None:
    hostile = _encoded(state_delta_mask=-1)
    with pytest.raises(ContractError, match="negative bitmask"):
        score_prediction_residual(
            {"state_delta": _peaked("state_delta", 0, 0.5)}, hostile
        )


def test_phi_bucket_is_monotone_in_delta_phi() -> None:
    values = [-100.0, -1.0, -0.1, 0.0, 0.6, 1.5, 3.0, 100.0]
    buckets = [phi_bucket(v) for v in values]
    assert buckets == sorted(buckets)
    assert buckets[0] == 0
    assert buckets[-1] == HEAD_CLASSES["phi"] - 1


# --- DTL-F05: Future Cone bounds and mass conservation ----------------------


def _escalating_state(dimension: str, level: int) -> SecurityStateV1:
    enum_type = DIMENSIONS[dimension]
    return SecurityStateV1().raised_to(dimension, enum_type(level))


def _linear_fixture() -> tuple[StubLattice, StubQuantizer]:
    """0 -> 1 -> 2 -> 3, each step raising one more capability."""
    lattice = StubLattice()
    for source, target in ((0, 1), (1, 2), (2, 3)):
        lattice.observe(source, target, epoch_id=0)
    atoms = {
        0: StubAtom(0, SecurityStateV1()),
        1: StubAtom(1, _escalating_state("privilege", 1)),
        2: StubAtom(2, _escalating_state("credential", 2)),
        3: StubAtom(3, _escalating_state("persistence", 2)),
    }
    return lattice, StubQuantizer(atoms)


def _wide_fixture(width: int = 7) -> tuple[StubLattice, StubQuantizer]:
    """One source with `width` distinct successors — forces beam truncation."""
    lattice = StubLattice()
    atoms: dict[int, StubAtom] = {0: StubAtom(0, SecurityStateV1())}
    for target in range(1, width + 1):
        for _ in range(width + 1 - target):  # distinct counts, deterministic order
            lattice.observe(0, target, epoch_id=0)
        atoms[target] = StubAtom(target, _escalating_state("discovery", 1))
    return lattice, StubQuantizer(atoms)


def test_future_cone_refuses_probabilities_that_do_not_sum_to_one() -> None:
    branch = ConeBranch(
        label="normal_continuation",
        atom_path=(1,),
        probability=0.5,
        terminal_state=SecurityStateV1(),
        delta_phi=0.0,
        evidence=(),
    )
    with pytest.raises(ContractError, match="sum to 1.0"):
        FutureCone(branches=(branch,), unresolved_mass=0.3, depth=1, truncated=False)


def test_future_cone_tolerance_is_not_a_loophole() -> None:
    """Fails if anyone widens the 1e-9 mass tolerance."""
    branch = ConeBranch(
        label="normal_continuation",
        atom_path=(1,),
        probability=1.0,
        terminal_state=SecurityStateV1(),
        delta_phi=0.0,
        evidence=(),
    )
    FutureCone(branches=(branch,), unresolved_mass=5e-10, depth=1, truncated=False)
    with pytest.raises(ContractError, match="sum to 1.0"):
        FutureCone(branches=(branch,), unresolved_mass=1e-7, depth=1, truncated=False)


def test_future_cone_refuses_more_branches_than_the_bound() -> None:
    branches = tuple(
        ConeBranch(
            label="normal_continuation",
            atom_path=(index,),
            probability=1.0 / (MAX_BRANCHES + 1),
            terminal_state=SecurityStateV1(),
            delta_phi=0.0,
            evidence=(),
        )
        for index in range(MAX_BRANCHES + 1)
    )
    with pytest.raises(ContractError, match="MAX_BRANCHES"):
        FutureCone(branches=branches, unresolved_mass=0.0, depth=1, truncated=True)


def test_the_unknown_branch_can_never_be_a_named_branch() -> None:
    with pytest.raises(ContractError, match="unresolved_mass, never a named branch"):
        ConeBranch(
            label=UNKNOWN_LABEL,
            atom_path=(1,),
            probability=1.0,
            terminal_state=SecurityStateV1(),
            delta_phi=0.0,
            evidence=(),
        )


def test_cone_branch_refuses_a_path_deeper_than_max_depth() -> None:
    with pytest.raises(ContractError, match="MAX_DEPTH"):
        ConeBranch(
            label="normal_continuation",
            atom_path=tuple(range(MAX_DEPTH + 1)),
            probability=1.0,
            terminal_state=SecurityStateV1(),
            delta_phi=0.0,
            evidence=(),
        )


def test_predict_future_cone_respects_both_bounds_and_flags_truncation() -> None:
    lattice, quantizer = _wide_fixture()
    cone = predict_future_cone(
        lattice, quantizer, from_atom=0, state=SecurityStateV1(), epoch_id=0
    )
    assert len(cone.branches) <= MAX_BRANCHES
    assert cone.depth <= MAX_DEPTH
    assert cone.truncated is True
    assert cone.unresolved_mass > 0.0, "a truncated successor set must leave mass unknown"
    assert abs(cone.resolved_mass + cone.unresolved_mass - 1.0) < 1e-9


def test_predict_future_cone_refuses_bounds_above_the_declared_maxima() -> None:
    lattice, quantizer = _linear_fixture()
    with pytest.raises(ContractError, match="max_branches"):
        predict_future_cone(
            lattice,
            quantizer,
            from_atom=0,
            state=SecurityStateV1(),
            epoch_id=0,
            max_branches=MAX_BRANCHES + 1,
        )
    with pytest.raises(ContractError, match="max_depth"):
        predict_future_cone(
            lattice,
            quantizer,
            from_atom=0,
            state=SecurityStateV1(),
            epoch_id=0,
            max_depth=MAX_DEPTH + 1,
        )


def test_an_unknown_atom_yields_the_all_unknown_cone() -> None:
    """The abstention path is reached, not merely reachable. UNKNOWN is valid."""
    lattice, quantizer = _linear_fixture()
    cone = predict_future_cone(
        lattice, quantizer, from_atom=999, state=SecurityStateV1(), epoch_id=0
    )
    assert cone.branches == ()
    assert cone.unresolved_mass == pytest.approx(1.0)
    assert cone.most_consequential() is None
    assert cone.label_distribution()[UNKNOWN_LABEL] == pytest.approx(1.0)


def test_an_unknown_epoch_yields_the_all_unknown_cone() -> None:
    """Epoch-conditioned dynamics: a transition valid in one regime is not in another."""
    lattice, quantizer = _linear_fixture()
    cone = predict_future_cone(
        lattice, quantizer, from_atom=0, state=SecurityStateV1(), epoch_id=7
    )
    assert cone.unresolved_mass == pytest.approx(1.0)


def test_cone_terminal_states_are_monotone_within_a_branch() -> None:
    """SecurityStateV1 never loses capability walking forward (ADR-0005)."""
    lattice, quantizer = _linear_fixture()
    start = SecurityStateV1()
    cone = predict_future_cone(
        lattice, quantizer, from_atom=0, state=start, epoch_id=0
    )
    assert cone.branches
    for branch in cone.branches:
        for name in DIMENSIONS:
            assert branch.terminal_state.level(name) >= start.level(name)
        assert branch.delta_phi >= 0.0
        assert branch.label in CONE_LABELS
        assert branch.label != UNKNOWN_LABEL


def test_cone_never_lowers_a_capability_the_lineage_already_holds() -> None:
    lattice, quantizer = _linear_fixture()
    start = SecurityStateV1().raised_to("privilege", Privilege.ROOT)
    cone = predict_future_cone(
        lattice, quantizer, from_atom=0, state=start, epoch_id=0
    )
    for branch in cone.branches:
        assert branch.terminal_state.level("privilege") == int(Privilege.ROOT)


def test_most_consequential_picks_the_highest_phi_branch() -> None:
    lattice = StubLattice()
    lattice.observe(0, 1, epoch_id=0)
    lattice.observe(0, 2, epoch_id=0)
    atoms = {
        0: StubAtom(0, SecurityStateV1()),
        1: StubAtom(1, _escalating_state("discovery", 1)),
        2: StubAtom(2, _escalating_state("credential", 3)),
    }
    cone = predict_future_cone(
        lattice,
        StubQuantizer(atoms),
        from_atom=0,
        state=SecurityStateV1(),
        epoch_id=0,
    )
    best = cone.most_consequential()
    assert best is not None
    assert best.atom_path == (2,)
    assert best.label == "credential_egress"


def test_branch_label_names_the_most_consequential_dimension_raised() -> None:
    start = SecurityStateV1()
    assert branch_label(start, start) == "normal_continuation"
    assert (
        branch_label(start, _escalating_state("privilege", 2))
        == "administrative_escalation"
    )
    # Credential outranks privilege: the chain, not the escalation.
    both = _escalating_state("privilege", 2).raised_to(
        "credential", DIMENSIONS["credential"](2)
    )
    assert branch_label(start, both) == "credential_egress"


def test_cone_expansion_records_cone_expansion_work_and_nothing_else() -> None:
    lattice, quantizer = _linear_fixture()
    ledger = RecordingLedger()
    predict_future_cone(
        lattice,
        quantizer,
        from_atom=0,
        state=SecurityStateV1(),
        epoch_id=0,
        ledger=ledger,
    )
    assert len(ledger.records) == 1
    kind, performed, units, detail = ledger.records[0]
    assert str(kind) == "CONE_EXPANSION"
    assert performed is True, "work that ran must be reported as performed"
    assert units > 0.0
    assert "lookups" in detail


def test_cone_expansion_records_nothing_when_no_ledger_is_passed() -> None:
    lattice, quantizer = _linear_fixture()
    cone = predict_future_cone(
        lattice, quantizer, from_atom=0, state=SecurityStateV1(), epoch_id=0
    )
    assert cone.branches  # the call worked; it simply reported to nobody


# --- the simple control: marginal_cone --------------------------------------


def test_marginal_cone_refuses_to_guess_the_source_set() -> None:
    class Opaque:
        def successors(self, source: int, *, epoch_id: int | None = None, limit: int = 8):
            return ()

    with pytest.raises(ContractError, match="sources"):
        marginal_cone(Opaque(), epoch_id=0)


def test_marginal_cone_is_a_valid_distribution_and_ignores_the_current_atom() -> None:
    lattice, quantizer = _linear_fixture()
    control = marginal_cone(
        lattice,
        epoch_id=0,
        quantizer=quantizer,
        state=SecurityStateV1(),
        source_weights=lattice.source_counts(),
    )
    assert abs(control.resolved_mass + control.unresolved_mass - 1.0) < 1e-9
    assert len(control.branches) <= MAX_BRANCHES
    assert control.depth <= 1  # the marginal is one step by construction
    # It saw no starting atom, so every successor of every source contributes.
    assert {branch.atom_path[0] for branch in control.branches} == {1, 2, 3}


def test_marginal_cone_on_an_empty_lattice_is_all_unknown() -> None:
    control = marginal_cone(StubLattice(), epoch_id=0, sources=())
    assert control.branches == ()
    assert control.unresolved_mass == pytest.approx(1.0)


# --- DTL-F08: hazard --------------------------------------------------------


def test_hazard_probabilities_are_bounded_and_non_decreasing_in_horizon() -> None:
    lattice, quantizer = _linear_fixture()
    state = SecurityStateV1()
    cone = predict_future_cone(
        lattice, quantizer, from_atom=0, state=state, epoch_id=0
    )
    report = estimate_security_hazard(cone, lattice, state=state)
    for outcome in OUTCOMES:
        previous = -1.0
        for horizon in HORIZONS:
            estimate = report.for_outcome(outcome, horizon)
            assert estimate is not None
            assert 0.0 <= estimate.probability <= 1.0
            assert estimate.probability >= previous
            previous = estimate.probability


def test_hazard_is_not_calibrated_and_says_so() -> None:
    """Stage 1 ships calibration_id=None honestly; so does this, until D2.9."""
    lattice, quantizer = _linear_fixture()
    state = SecurityStateV1()
    cone = predict_future_cone(
        lattice, quantizer, from_atom=0, state=state, epoch_id=0
    )
    report = estimate_security_hazard(cone, lattice, state=state)
    assert all(estimate.calibration_id is None for estimate in report.estimates)
    assert report.calibrated() is False
    assert report.to_dict()["calibrated"] is False


def test_hazard_estimate_refuses_a_blank_calibration_id() -> None:
    with pytest.raises(ContractError, match="calibration_id"):
        HazardEstimate(
            outcome="egress",
            horizon=1,
            probability=0.5,
            evidence_count=1,
            calibration_id="  ",
        )


def test_hazard_estimate_refuses_an_impossible_probability() -> None:
    with pytest.raises(ContractError, match="outside"):
        HazardEstimate(
            outcome="egress", horizon=1, probability=1.5, evidence_count=1
        )


def test_hazard_estimate_refuses_an_unknown_outcome_or_a_zero_horizon() -> None:
    with pytest.raises(ContractError, match="unknown hazard outcome"):
        HazardEstimate(outcome="ransom", horizon=1, probability=0.1, evidence_count=0)
    with pytest.raises(ContractError, match="relevant event"):
        HazardEstimate(
            outcome="egress", horizon=0, probability=0.1, evidence_count=0
        )


def test_hazard_report_refuses_duplicate_buckets() -> None:
    estimate = HazardEstimate(
        outcome="egress", horizon=1, probability=0.1, evidence_count=0
    )
    with pytest.raises(ContractError, match="duplicate"):
        HazardReport(estimates=(estimate, estimate))


def test_an_all_unknown_cone_yields_zero_hazard_not_a_guess() -> None:
    lattice, quantizer = _linear_fixture()
    cone = predict_future_cone(
        lattice, quantizer, from_atom=999, state=SecurityStateV1(), epoch_id=0
    )
    report = estimate_security_hazard(cone, lattice, state=SecurityStateV1())
    for estimate in report.estimates:
        assert estimate.probability == 0.0
        assert estimate.evidence_count == 0


def test_hazard_ignores_a_capability_the_lineage_already_holds() -> None:
    """A lineage already at root cannot "raise privilege" again."""
    lattice, quantizer = _linear_fixture()
    already_root = SecurityStateV1().raised_to("privilege", Privilege.ROOT)
    cone = predict_future_cone(
        lattice, quantizer, from_atom=0, state=already_root, epoch_id=0
    )
    report = estimate_security_hazard(cone, lattice, state=already_root)
    estimate = report.for_outcome("privilege_raise", 16)
    assert estimate is not None
    assert estimate.probability == 0.0


def test_constant_hazard_distinguishes_never_observed_from_never_happened() -> None:
    report = constant_hazard(
        {("egress", 1): (0, 0), ("persistence", 1): (0, 40)}
    )
    never_observed = report.for_outcome("egress", 1)
    observed_zero = report.for_outcome("persistence", 1)
    assert never_observed is not None and never_observed.evidence_count == 0
    assert observed_zero is not None and observed_zero.evidence_count == 40
    assert never_observed.probability == observed_zero.probability == 0.0


def test_constant_hazard_refuses_inverted_counts() -> None:
    with pytest.raises(ContractError, match="occurrences"):
        constant_hazard({("egress", 1): (5, 2)})
    with pytest.raises(ContractError, match="negative"):
        constant_hazard({("egress", 1): (-1, 2)})


def test_estimate_security_hazard_refuses_an_empty_horizon_set() -> None:
    lattice, quantizer = _linear_fixture()
    cone = predict_future_cone(
        lattice, quantizer, from_atom=0, state=SecurityStateV1(), epoch_id=0
    )
    with pytest.raises(ContractError, match="at least one horizon"):
        estimate_security_hazard(cone, lattice, state=SecurityStateV1(), horizons=())


# --- the measured comparison (D2.8 / G2.6) ----------------------------------
#
# Fixed split, recorded in full: corpus='ambiguous', count=240, seed=11. Per
# `docs/stage-2-spec.md` section 0.1 a result quoted without all three is void.

MEASURE_CORPUS = "ambiguous"
MEASURE_COUNT = 240
MEASURE_SEED = 11
MAX_CONTEXTS = 3000
ECE_BINS = 10


MAX_FIXTURE_ATOMS = 256
OVERFLOW_ATOM = -2


class AtomIndex:
    """The `HashBucketQuantizer` rule of spec section 5, inlined as the fixture.

    ``atom_id`` is a deterministic bucket of
    ``(relation_family, state_delta_mask, object_property_mask)`` assigned in
    order of first appearance and bounded at ``MAX_FIXTURE_ATOMS``. Assignment
    is exact rather than a modular hash: folding two different
    ``state_delta_mask`` values into one atom would give every atom a saturated
    capability summary, and the cone would then be scored against a truth built
    from unsaturated per-step deltas — an apples-to-oranges comparison the cone
    could only lose. Measured on this corpus: 14 distinct triples, so nothing
    overflows.
    """

    def __init__(self) -> None:
        self._ids: dict[tuple[int, int, int], int] = {}

    def key(self, step: EncodedTransition) -> tuple[int, int, int]:
        return (
            step.relation_family,
            step.state_delta_mask,
            step.object_property_mask,
        )

    def of(self, step: EncodedTransition) -> int:
        key = self.key(step)
        existing = self._ids.get(key)
        if existing is not None:
            return existing
        if len(self._ids) >= MAX_FIXTURE_ATOMS:
            return OVERFLOW_ATOM
        self._ids[key] = len(self._ids)
        return self._ids[key]

    def __len__(self) -> int:
        return len(self._ids)


def _summary_of(step: EncodedTransition) -> SecurityStateV1:
    state = SecurityStateV1()
    for index, name in enumerate(DIMENSION_NAMES):
        if step.state_delta_mask & (1 << index):
            state = state.raised_to(name, DIMENSIONS[name](1))
    return state


def _mask_touches(step: EncodedTransition, dimension: str) -> bool:
    return bool(step.state_delta_mask & (1 << DIMENSION_NAMES.index(dimension)))


def _ece(labels: Sequence[int], confidences: Sequence[float]) -> float:
    """Expected calibration error. Local because `uncertainty/` (D2.9) is a
    sibling package built in the same wave; the `report` package uses the real
    one."""
    buckets: list[list[tuple[int, float]]] = [[] for _ in range(ECE_BINS)]
    for label, confidence in zip(labels, confidences, strict=True):
        index = min(ECE_BINS - 1, int(confidence * ECE_BINS))
        buckets[index].append((label, confidence))
    total = len(labels)
    error = 0.0
    for bucket in buckets:
        if not bucket:
            continue
        accuracy = sum(label for label, _ in bucket) / len(bucket)
        mean_confidence = sum(c for _, c in bucket) / len(bucket)
        error += len(bucket) / total * abs(accuracy - mean_confidence)
    return error


@dataclass(frozen=True, slots=True)
class _Context:
    atom: int
    state: SecurityStateV1
    epoch_id: int
    #: Label of what actually happened in the next single transition.
    observed_label: str
    #: Label of the state reached after the next MAX_DEPTH transitions, so a
    #: depth-3 cone can also be scored against a depth-3 truth rather than only
    #: against a one-step one.
    observed_label_deep: str
    outcomes: dict[tuple[str, int], int]


def _contexts(samples: Sequence[Any], index: AtomIndex) -> Iterator[_Context]:
    for sample in samples:
        state = SecurityStateV1()
        for position, step in enumerate(sample.steps[:-1]):
            state = SecurityStateV1.join(state, _summary_of(step))
            nxt = sample.steps[position + 1]
            terminal = SecurityStateV1.join(state, _summary_of(nxt))
            deep = terminal
            for later in sample.steps[position + 2 : position + 1 + MAX_DEPTH]:
                deep = SecurityStateV1.join(deep, _summary_of(later))
            outcomes: dict[tuple[str, int], int] = {}
            for outcome, dimension in OUTCOME_DIMENSIONS.items():
                for horizon in HORIZONS:
                    window = sample.steps[position + 1 : position + 1 + horizon]
                    outcomes[(outcome, horizon)] = int(
                        any(_mask_touches(s, dimension) for s in window)
                        and state.level(dimension) < len(DIMENSIONS[dimension]) - 1
                    )
            yield _Context(
                atom=index.of(step),
                state=state,
                epoch_id=step.epoch_id,
                observed_label=branch_label(state, terminal),
                observed_label_deep=branch_label(state, deep),
                outcomes=outcomes,
            )


@pytest.fixture(scope="module")
def measurement() -> dict[str, Any]:
    dataset = build_dataset(
        name="stage2-predictors-measure",
        count=MEASURE_COUNT,
        seed=MEASURE_SEED,
        corpus=MEASURE_CORPUS,
    )
    half = len(dataset.samples) // 2
    train, evaluate = dataset.samples[:half], dataset.samples[half:]

    lattice = StubLattice()
    index = AtomIndex()
    summaries: dict[int, SecurityStateV1] = {}
    train_outcomes: dict[tuple[str, int], list[int]] = {
        key: [] for key in ((o, h) for o in OUTCOMES for h in HORIZONS)
    }
    for sample in train:
        for position, step in enumerate(sample.steps):
            atom = index.of(step)
            summaries[atom] = SecurityStateV1.join(
                summaries.get(atom, SecurityStateV1()), _summary_of(step)
            )
            if position + 1 < len(sample.steps):
                lattice.observe(
                    atom, index.of(sample.steps[position + 1]), epoch_id=step.epoch_id
                )
    for context in _contexts(train, index):
        for key, value in context.outcomes.items():
            train_outcomes[key].append(value)

    quantizer = StubQuantizer(
        {atom: StubAtom(atom, summary) for atom, summary in summaries.items()}
    )
    contexts = []
    for context in _contexts(evaluate, index):
        contexts.append(context)
        if len(contexts) >= MAX_CONTEXTS:
            break
    return {
        "dataset": dataset,
        "lattice": lattice,
        "quantizer": quantizer,
        "contexts": contexts,
        "atoms": len(index),
        "source_counts": lattice.source_counts(),
        "control_counts": {
            key: (sum(values), len(values)) for key, values in train_outcomes.items()
        },
    }


def _multiclass_brier(distribution: Mapping[str, float], observed: str) -> float:
    return sum(
        (probability - (1.0 if label == observed else 0.0)) ** 2
        for label, probability in distribution.items()
    )


def test_measured_cone_brier_against_the_marginal_control(
    measurement: dict[str, Any], capsys: Any
) -> None:
    """MEASURED, not asserted: Brier for the cone vs the epoch-marginal control.

    No winner is asserted. Acceptance criterion 6 permits the cone's removal, and
    this number is the evidence that decides it (ADR-0116).
    """
    lattice = measurement["lattice"]
    quantizer = measurement["quantizer"]
    weights = measurement["source_counts"]
    contexts = measurement["contexts"]
    totals = dict.fromkeys(
        (
            "cone_brier",
            "cone_depth1_brier",
            "argmax_cone_brier",
            "marginal_brier",
            "cone_brier_deep_truth",
            "marginal_brier_deep_truth",
        ),
        0.0,
    )
    unresolved = 0.0
    for context in contexts:
        shared = {
            "from_atom": context.atom,
            "state": context.state,
            "epoch_id": context.epoch_id,
        }
        cone = predict_future_cone(lattice, quantizer, **shared)
        # Matched to the control on both bounds, so the only difference left is
        # the one under test: whether the current atom is conditioned on.
        shallow = predict_future_cone(
            lattice, quantizer, **shared, max_branches=MAX_BRANCHES, max_depth=1
        )
        # The 1-branch argmax cone named as a control in spec section 5.
        single = predict_future_cone(
            lattice, quantizer, **shared, max_branches=1, max_depth=1
        )
        control = marginal_cone(
            lattice,
            epoch_id=context.epoch_id,
            quantizer=quantizer,
            state=context.state,
            source_weights=weights,
        )
        unresolved += cone.unresolved_mass
        cone_dist = cone.label_distribution()
        control_dist = control.label_distribution()
        totals["cone_brier"] += _multiclass_brier(cone_dist, context.observed_label)
        totals["cone_depth1_brier"] += _multiclass_brier(
            shallow.label_distribution(), context.observed_label
        )
        totals["argmax_cone_brier"] += _multiclass_brier(
            single.label_distribution(), context.observed_label
        )
        totals["marginal_brier"] += _multiclass_brier(
            control_dist, context.observed_label
        )
        # A depth-3 cone scored against a depth-3 truth, so the full cone is not
        # penalised merely for answering a different question than the control.
        totals["cone_brier_deep_truth"] += _multiclass_brier(
            cone_dist, context.observed_label_deep
        )
        totals["marginal_brier_deep_truth"] += _multiclass_brier(
            control_dist, context.observed_label_deep
        )

    count = len(contexts)
    assert count > 0
    result: dict[str, Any] = {
        "corpus": MEASURE_CORPUS,
        "count": MEASURE_COUNT,
        "seed": MEASURE_SEED,
        "contexts": count,
        "atoms": measurement["atoms"],
        "labels": len(CONE_LABELS),
        "mean_cone_unresolved_mass": round(unresolved / count, 6),
        "synthetic_data": True,
    }
    result.update({key: round(value / count, 6) for key, value in totals.items()})
    with capsys.disabled():
        print(f"\nMEASURED cone vs marginal: {result}")
    # The only assertions are that every reported figure is a real Brier score
    # over a real distribution. No winner is asserted; see ADR-0116.
    for key in totals:
        assert 0.0 <= result[key] <= 2.0


def test_measured_hazard_against_the_constant_control(
    measurement: dict[str, Any], capsys: Any
) -> None:
    """MEASURED, not asserted: Brier + ECE for the cone hazard vs constant_hazard."""
    lattice = measurement["lattice"]
    quantizer = measurement["quantizer"]
    control = constant_hazard(measurement["control_counts"])
    contexts = measurement["contexts"]

    labels: list[int] = []
    cone_scores: list[float] = []
    control_scores: list[float] = []
    for context in contexts:
        cone = predict_future_cone(
            lattice,
            quantizer,
            from_atom=context.atom,
            state=context.state,
            epoch_id=context.epoch_id,
        )
        report = estimate_security_hazard(cone, lattice, state=context.state)
        for (outcome, horizon), observed in context.outcomes.items():
            estimate = report.for_outcome(outcome, horizon)
            baseline = control.for_outcome(outcome, horizon)
            assert estimate is not None and baseline is not None
            labels.append(observed)
            cone_scores.append(estimate.probability)
            control_scores.append(baseline.probability)

    def brier(scores: Sequence[float]) -> float:
        return sum(
            (s - y) ** 2 for s, y in zip(scores, labels, strict=True)
        ) / len(labels)

    result = {
        "corpus": MEASURE_CORPUS,
        "count": MEASURE_COUNT,
        "seed": MEASURE_SEED,
        "points": len(labels),
        "positive_rate": round(sum(labels) / len(labels), 6),
        "hazard_brier": round(brier(cone_scores), 6),
        "constant_brier": round(brier(control_scores), 6),
        "hazard_ece": round(_ece(labels, cone_scores), 6),
        "constant_ece": round(_ece(labels, control_scores), 6),
        "calibration_id": None,
        "synthetic_data": True,
    }
    with capsys.disabled():
        print(f"MEASURED hazard vs constant: {result}")
    assert 0.0 <= result["hazard_brier"] <= 1.0
    assert 0.0 <= result["constant_brier"] <= 1.0
    assert result["calibration_id"] is None


def _load_average() -> float | None:
    """One-minute load average, or None where the platform cannot report it.

    Recorded beside every wall-or-CPU timing: a microsecond figure taken on a
    contended host is indicative, and a reader has to be able to see that.
    """
    import os

    try:
        return round(os.getloadavg()[0], 2)
    except (AttributeError, OSError):  # pragma: no cover - platform dependent
        return None


def test_measured_runtime_cost_of_the_predictor_surface(
    measurement: dict[str, Any], capsys: Any
) -> None:
    """MEASURED resource cost of this package's runtime path.

    CPU time via `time.process_time()`, the same clock Stage 0's
    `ResourceSampler` uses (`resource_metrics.py:133`). Wall-clock would be
    meaningless here: this measurement ran at a one-minute load average recorded
    in the result, so a `perf_counter` figure would be measuring the host's
    contention, not this code.

    Reported, not asserted against a target. The Stage 0 Edge profile check is
    `report`'s and the gate's job (G2.11), and `parameters`/`memory_bytes` are the
    only two figures here that are load-independent.
    """
    import time

    heads = PredictiveHeads({head_id: make_head(head_id) for head_id in HEAD_IDS})
    window = StubWindow([[0.5] * FEATURE_WIDTH] * 64)
    for _ in range(20):  # warm the interpreter before timing anything
        heads.predict(window)

    start = time.process_time()
    for _ in range(200):
        heads.predict(window)
    head_us = (time.process_time() - start) / 200 * 1e6

    lattice = measurement["lattice"]
    quantizer = measurement["quantizer"]
    contexts = measurement["contexts"][:500]
    start = time.process_time()
    for context in contexts:
        predict_future_cone(
            lattice,
            quantizer,
            from_atom=context.atom,
            state=context.state,
            epoch_id=context.epoch_id,
        )
    cone_us = (time.process_time() - start) / len(contexts) * 1e6

    result = {
        "heads": len(HEAD_IDS),
        "parameters": heads.parameters(),
        "memory_bytes": heads.memory_bytes(),
        "window_steps": 64,
        "cpu_microseconds_per_full_head_predict": round(head_us, 2),
        "cpu_microseconds_per_cone_expansion": round(cone_us, 2),
        "load_average_1m_during_measurement": _load_average(),
        "synthetic_data": True,
    }
    with capsys.disabled():
        print(f"MEASURED predictor cost: {result}")
    # The only assertions are that the figures exist and that the parameter count
    # is the derived one, so a silently grown vocabulary is caught here too.
    assert heads.parameters() == sum(
        HEAD_CLASSES[h] * FEATURE_WIDTH + HEAD_CLASSES[h] for h in HEAD_IDS
    )
    assert result["memory_bytes"] > 0
    assert head_us > 0.0 and cone_us > 0.0
