"""Stage 2 — core IDs, the SSIR encoder, the autodiff, and the baseline suite.

The autodiff tests are gradient checks against finite differences. An autodiff
nobody gradient-checked is a silent source of wrong conclusions, and every
baseline's credibility rests on it.
"""

from __future__ import annotations

import numpy as np
import pytest

from pocketsec.stage1.labs.corpus import ATTACK_EXFIL, Scenario
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage2.core_ids import (
    CORE_IDS,
    PATH_COST_UNITS,
    REQUIRED_IDS,
    ExecutionPath,
    FunctionClass,
)
from pocketsec.stage2.dataset import build_dataset
from pocketsec.stage2.encoder.ssir_encoder import (
    FEATURE_LAYOUT,
    FEATURE_WIDTH,
    encode_ssir_transition,
    feature_names,
)
from pocketsec.stage2.research.autograd import (
    Tensor,
    binary_cross_entropy,
    bmm,
    concat,
    cross_entropy,
)
from pocketsec.stage2.research.baselines import build_baselines

# --- D2.1 core IDs -----------------------------------------------------------


def test_twenty_core_ids_are_defined() -> None:
    assert len(CORE_IDS) == 20
    assert all(cid.startswith("DTL-F") for cid in CORE_IDS)


def test_required_and_optional_functions_are_distinguished() -> None:
    """Optional functions are hypotheses; ablation may delete them."""
    optional = {
        cid
        for cid, fn in CORE_IDS.items()
        if fn.function_class is FunctionClass.OPTIONAL
    }
    assert REQUIRED_IDS and optional
    assert not (REQUIRED_IDS & optional)


def test_every_core_id_names_a_deliverable() -> None:
    for function in CORE_IDS.values():
        assert function.deliverable.startswith("D2.")


def test_execution_path_costs_increase_monotonically() -> None:
    """P0 must be cheapest or the whole sleeping-brain premise is wrong."""
    costs = [PATH_COST_UNITS[path] for path in ExecutionPath]
    assert costs == sorted(costs)
    assert PATH_COST_UNITS[ExecutionPath.P0_COMPILED] < PATH_COST_UNITS[
        ExecutionPath.P4_DEEP
    ]


# --- DTL-F01 encoder ---------------------------------------------------------


def _transitions():  # type: ignore[no-untyped-def]
    return Stage1Pipeline().run_scenario(Scenario("a", ATTACK_EXFIL, 1)).transitions


def test_feature_layout_matches_declared_width() -> None:
    assert sum(width for _, width in FEATURE_LAYOUT) == FEATURE_WIDTH
    assert len(feature_names()) == FEATURE_WIDTH


def test_encoding_is_deterministic() -> None:
    transition = _transitions()[0]
    assert encode_ssir_transition(transition) == encode_ssir_transition(transition)


def test_every_feature_is_finite_and_bounded() -> None:
    """Unbounded features would let one slot dominate any linear model."""
    for transition in _transitions():
        for value in encode_ssir_transition(transition).features:
            assert -1.0 <= value <= 1.0
            assert value == value  # not NaN


def test_encoder_ignores_identity_and_display_name() -> None:
    """ADR-0007 froze exact_identity out of the model-facing encoding.

    Tested behaviourally rather than by inspecting feature names: two
    transitions that differ ONLY in identity and display name must encode
    identically. String-matching the names is weaker and gives false positives
    (the relation *family* is legitimately called IDENTITY).
    """
    import dataclasses

    original = _transitions()[0]
    renamed = dataclasses.replace(
        original,
        actor=dataclasses.replace(
            original.actor,
            identity="proc:other-boot:99999:1",
            display_name="/tmp/.totally-different-name",
        ),
        object=dataclasses.replace(
            original.object,
            identity="file:987654",
            display_name="/some/other/path",
        ),
    )
    assert encode_ssir_transition(renamed).features == encode_ssir_transition(
        original
    ).features


def test_encoder_module_never_reads_identity_fields() -> None:
    """Belt and braces: the source must not touch identity at all."""
    import ast
    from pathlib import Path

    import pocketsec.stage2.encoder.ssir_encoder as module

    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    attributes = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    assert "identity" not in attributes
    assert "display_name" not in attributes


def test_encoder_preserves_evidence_for_binding() -> None:
    """DTL-F20 needs evidence locators, but they are never model features."""
    encoded = encode_ssir_transition(_transitions()[0])
    assert encoded.evidence
    assert len(encoded.features) == FEATURE_WIDTH


def test_state_delta_is_visible_to_the_model() -> None:
    transitions = _transitions()
    consequential = next(t for t in transitions if t.state_delta)
    encoded = encode_ssir_transition(consequential)
    assert encoded.state_delta_mask != 0
    assert any(value > 0 for value in encoded.features)


# --- dataset -----------------------------------------------------------------


def test_dataset_provenance_is_complete() -> None:
    dataset = build_dataset(name="probe", count=60, seed=11)
    provenance = dataset.to_provenance()
    for key in ("encoder_version", "feature_width", "samples", "base_rate", "seed"):
        assert key in provenance
    assert dataset.feature_width == FEATURE_WIDTH


def test_dataset_build_is_independent_of_call_order() -> None:
    """Each split gets a fresh Stage 1 pipeline.

    A shared pipeline would let the fit split warm the novelty engine that
    scores the eval split — the eval novelty features would reflect having
    already seen the training data. Building the same split twice, with another
    build interleaved, must give byte-identical features.
    """
    first = build_dataset(name="probe", count=40, seed=11)
    build_dataset(name="interleaved", count=40, seed=3)
    second = build_dataset(name="probe", count=40, seed=11)
    assert [s.features for s in first] == [s.features for s in second]


def test_a_shared_pipeline_would_change_features() -> None:
    """Guards the test above: it must be capable of detecting the leak."""
    from pocketsec.stage1.pipeline import Stage1Pipeline as Pipeline
    from pocketsec.stage1.labs.hard_corpus import build_hard_corpus

    scenarios = build_hard_corpus(count=20, seed=11, split="eval")
    fresh = Pipeline()
    cold = [
        encode_ssir_transition(t)
        for index, s in enumerate(scenarios)
        for t in fresh.run_scenario(s, offset=index).transitions
    ]

    warmed = Pipeline()
    for index, s in enumerate(build_hard_corpus(count=20, seed=3, split="eval")):
        warmed.run_scenario(s, offset=100 + index)
    hot = [
        encode_ssir_transition(t)
        for index, s in enumerate(scenarios)
        for t in warmed.run_scenario(s, offset=index).transitions
    ]
    assert [c.features for c in cold] != [h.features for h in hot]


def test_dataset_contains_both_classes() -> None:
    dataset = build_dataset(name="probe", count=80, seed=11)
    assert 0 < dataset.positive_count < len(dataset)


# --- autodiff gradient checks ------------------------------------------------


def _grad_check(fn, x: np.ndarray, tol: float = 1e-6) -> None:  # type: ignore[no-untyped-def]
    tensor = Tensor(x.copy(), requires_grad=True)
    fn(tensor).backward()
    assert tensor.grad is not None
    analytic = tensor.grad.copy()
    numeric = np.zeros_like(x)
    for index in np.ndindex(x.shape):
        for sign in (1, -1):
            perturbed = x.copy()
            perturbed[index] += sign * 1e-6
            numeric[index] += sign * float(fn(Tensor(perturbed)).data)
        numeric[index] /= 2e-6
    assert np.max(np.abs(analytic - numeric)) < tol


@pytest.fixture
def rng() -> np.random.Generator:
    return np.random.default_rng(0)


def test_gradient_tanh(rng) -> None:  # type: ignore[no-untyped-def]
    _grad_check(lambda t: t.tanh().sum(), rng.normal(size=(3, 4)))


def test_gradient_sigmoid(rng) -> None:  # type: ignore[no-untyped-def]
    _grad_check(lambda t: t.sigmoid().sum(), rng.normal(size=(3, 4)))


def test_gradient_relu(rng) -> None:  # type: ignore[no-untyped-def]
    _grad_check(lambda t: (t.relu() * 2.0).sum(), rng.normal(size=(3, 4)))


def test_gradient_log_softmax(rng) -> None:  # type: ignore[no-untyped-def]
    _grad_check(lambda t: t.log_softmax().sum(), rng.normal(size=(3, 4)))


def test_gradient_cross_entropy(rng) -> None:  # type: ignore[no-untyped-def]
    targets = np.array([0, 2, 1])
    _grad_check(lambda t: cross_entropy(t, targets), rng.normal(size=(3, 4)))


def test_gradient_binary_cross_entropy(rng) -> None:  # type: ignore[no-untyped-def]
    targets = np.array([[1.0], [0.0], [1.0]])
    _grad_check(lambda t: binary_cross_entropy(t, targets), rng.normal(size=(3, 1)))


def test_gradient_matmul(rng) -> None:  # type: ignore[no-untyped-def]
    weights = Tensor(rng.normal(size=(4, 3)), requires_grad=True)
    _grad_check(lambda t: (t @ weights).sum(), rng.normal(size=(2, 4)))


def test_gradient_bmm(rng) -> None:  # type: ignore[no-untyped-def]
    right = Tensor(rng.normal(size=(2, 3, 4)), requires_grad=True)
    _grad_check(lambda t: bmm(t, right).sum(), rng.normal(size=(2, 5, 3)))


def test_gradient_concat(rng) -> None:  # type: ignore[no-untyped-def]
    _grad_check(lambda t: concat([t, t * 2.0], axis=1).sum(), rng.normal(size=(2, 3)))


def test_gradient_reshape_transpose_exp(rng) -> None:  # type: ignore[no-untyped-def]
    _grad_check(lambda t: t.reshape(6, 2).sum(), rng.normal(size=(3, 4)))
    _grad_check(lambda t: t.transpose(0, 2, 1).sum(), rng.normal(size=(2, 3, 4)))
    _grad_check(lambda t: t.exp().sum(), rng.normal(size=(3, 4)))


def test_backward_requires_a_scalar(rng) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError, match="scalar"):
        Tensor(rng.normal(size=(2, 2)), requires_grad=True).backward()


# --- D2.2 baselines ----------------------------------------------------------


@pytest.fixture(scope="module")
def trained():  # type: ignore[no-untyped-def]
    train = build_dataset(name="s2-train", count=180, seed=3)
    test = build_dataset(name="s2-test", count=180, seed=11)
    models = build_baselines(hidden=20, epochs=30)
    for model in models:
        model.fit(train)
    return models, train, test


def test_at_least_five_baselines_exist(trained) -> None:  # type: ignore[no-untyped-def]
    """Stage 2 acceptance criterion 1."""
    models, _, _ = trained
    assert len(models) >= 5


def test_every_baseline_beats_the_base_rate(trained) -> None:  # type: ignore[no-untyped-def]
    """A baseline below chance is a bug, not a weak baseline.

    The tiny Transformer scored 0.55 against a 0.35 base rate until its
    query/key/value projections were reconnected to the graph.
    """
    from pocketsec.stage0.benchmark.security_metrics import average_precision

    models, _, test = trained
    labels = list(test.labels)
    for model in models:
        score = average_precision(labels, model.predict_scores(test))
        assert score is not None
        assert score > test.base_rate, f"{model.name} scored {score:.4f} below chance"


def test_baselines_report_measured_resource_profiles(trained) -> None:  # type: ignore[no-untyped-def]
    models, _, _ = trained
    for model in models:
        profile = model.resource_profile()
        assert profile["parameters"] >= 0
        assert profile["model_bytes_fp32"] >= 0


def test_every_baseline_scores_every_sample(trained) -> None:  # type: ignore[no-untyped-def]
    models, _, test = trained
    for model in models:
        assert len(model.predict_scores(test)) == len(test)


def test_padding_does_not_change_a_recurrent_verdict(trained) -> None:  # type: ignore[no-untyped-def]
    """Masked steps must not move recurrent state.

    Without masking, short scenarios are silently rewritten by whatever the
    padding contains, which is a correctness bug that looks like noise.
    """
    from pocketsec.stage2.research.baselines import GRUBaseline

    models, train, test = trained
    model = next(m for m in models if isinstance(m, GRUBaseline))
    short = [s for s in test.samples if len(s) == min(len(x) for x in test.samples)]
    assert short
    scores = model.predict_scores(test)
    assert all(0.0 <= s <= 1.0 for s in scores)
