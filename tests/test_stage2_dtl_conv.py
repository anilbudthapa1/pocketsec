"""DTL-C — the convolutional core (ADR-0009).

These tests pin the findings that drove the redesign, so none of them can
regress quietly. They are slow (each trains a model), which is the cost of
testing a claim about learning rather than a claim about plumbing.
"""

from __future__ import annotations

import numpy as np
import pytest

from pocketsec.stage0.benchmark.security_metrics import average_precision
from pocketsec.stage2.dataset import build_dataset
from pocketsec.stage2.research.autograd import (
    Tensor,
    normalised_bce,
    normalised_cross_entropy,
)
from pocketsec.stage2.research.baselines import TCNBaseline
from pocketsec.stage2.research.dtl_conv import DTLC_BLOCKS, DTLConvConfig, DTLConvModel

CORPUS = 90
EPOCHS = 20


@pytest.fixture(scope="module")
def splits():  # type: ignore[no-untyped-def]
    return (
        build_dataset(name="dtlc-train", count=CORPUS, seed=3, corpus="long"),
        build_dataset(name="dtlc-test", count=CORPUS, seed=11, corpus="long"),
    )


def _score(model, test) -> float:  # type: ignore[no-untyped-def]
    return average_precision(list(test.labels), model.predict_scores(test)) or 0.0


def _train(splits, **overrides):  # type: ignore[no-untyped-def]
    train, test = splits
    model = DTLConvModel(DTLConvConfig(latent=48, epochs=EPOCHS, **overrides))
    model.fit(train)
    return model, _score(model, test)


# --- loss normalisation ------------------------------------------------------


def test_normalised_losses_start_near_one() -> None:
    """Otherwise the loss weights encode vocabulary size, not priority.

    A 24-class head starts at ln(24)=3.18 and a binary head at ln(2)=0.69, so
    five unnormalised prediction heads starved the detection term to 16% of the
    gradient and its logits came out constant.
    """
    rng = np.random.default_rng(0)
    logits = Tensor(rng.normal(scale=0.01, size=(64, 24)))
    targets = rng.integers(0, 24, size=64)
    assert abs(float(normalised_cross_entropy(logits, targets, 24).data) - 1.0) < 0.05

    binary = Tensor(rng.normal(scale=0.01, size=(64, 1)))
    labels = rng.integers(0, 2, size=(64, 1)).astype(float)
    assert abs(float(normalised_bce(binary, labels).data) - 1.0) < 0.1


# --- the core findings -------------------------------------------------------


@pytest.mark.slow
def test_dtl_conv_matches_the_best_baseline(splits) -> None:  # type: ignore[no-untyped-def]
    """The whole point of the redesign: the recurrent core lost by 0.53."""
    train, test = splits
    _, dtlc = _train(splits)
    tcn = TCNBaseline(hidden=24, epochs=EPOCHS).fit(train)
    assert dtlc >= _score(tcn, test) - 0.02, (
        f"DTL-C {dtlc:.4f} vs TCN {_score(tcn, test):.4f}: the convolutional "
        "redesign must at least match the baseline it was built to answer"
    )


@pytest.mark.slow
def test_joint_heads_destroy_detection(splits) -> None:  # type: ignore[no-untyped-def]
    """ADR-0009's substantive finding, and why heads are detached.

    Training the predictive heads on the shared representation optimises the
    convolutional features for next-step prediction, which is dominated by
    frequent benign patterns, and that collapses the attack signal.
    """
    _, detached = _train(splits, detach_heads=True)
    _, joint = _train(splits, detach_heads=False)
    assert detached > joint + 0.3, (
        f"detached {detached:.4f} vs joint {joint:.4f}: joint training was "
        "measured to cost ~0.67 PR-AUC"
    )


@pytest.mark.slow
def test_joint_head_damage_is_not_a_weighting_problem(splits) -> None:  # type: ignore[no-untyped-def]
    """w_detect=8 with joint heads still failed, so re-weighting cannot fix it."""
    _, heavy_detect = _train(splits, detach_heads=False, w_detect=8.0)
    _, detached = _train(splits, detach_heads=True)
    assert detached > heavy_detect + 0.3


@pytest.mark.slow
def test_maxpool_is_the_load_bearing_component(splits) -> None:  # type: ignore[no-untyped-def]
    """Removing it collapses DTL-C to near the base rate.

    Max over time is what finds a short escalating chain anywhere inside a long
    benign session.
    """
    _, with_pool = _train(splits, use_maxpool=True)
    _, without_pool = _train(splits, use_maxpool=False)
    assert with_pool > without_pool + 0.3


# --- structure ---------------------------------------------------------------


def test_dilations_are_strictly_increasing() -> None:
    """Dilation *is* the timescale, so the ordering carries the meaning."""
    dilations = [dilation for _, _, dilation in DTLC_BLOCKS]
    assert dilations == sorted(dilations)
    assert dilations[0] == 1
    assert dilations[-1] >= 16


def test_block_shares_sum_to_the_latent_budget() -> None:
    config = DTLConvConfig(latent=48)
    assert sum(config.block_sizes().values()) == 48


def test_ablating_multiscale_keeps_the_capacity_budget() -> None:
    """A capacity-starved control would make multiscale look good for free."""
    config = DTLConvConfig(latent=48, use_multiscale=False)
    assert sum(config.block_sizes().values()) == 48
    assert list(config.dilations()) == ["fast"]


def test_dilated_windows_are_causal() -> None:
    """A non-causal window would leak the future into the prediction heads."""
    batch = np.arange(24, dtype=float).reshape(1, 8, 3)
    windows = DTLConvModel._dilated_windows(batch, dilation=2)
    # Step 0 can only see itself; earlier slots must be zero padding.
    assert np.all(windows[0, 0, :6] == 0.0)
    assert np.allclose(windows[0, 0, 6:], batch[0, 0])
    # Step 4 at dilation 2 sees steps 0, 2, 4.
    assert np.allclose(windows[0, 4, 0:3], batch[0, 0])
    assert np.allclose(windows[0, 4, 3:6], batch[0, 2])
    assert np.allclose(windows[0, 4, 6:9], batch[0, 4])


def test_resource_profile_reports_dilations(splits) -> None:  # type: ignore[no-untyped-def]
    train, _ = splits
    model = DTLConvModel(DTLConvConfig(latent=48, epochs=1)).fit(train)
    profile = model.resource_profile()
    assert profile["parameters"] > 0
    assert set(profile["dilations"]) == {name for name, _, _ in DTLC_BLOCKS}


def test_routing_reports_a_path_distribution(splits) -> None:  # type: ignore[no-untyped-def]
    train, test = splits
    model = DTLConvModel(DTLConvConfig(latent=48, epochs=1)).fit(train)
    routing = model.route(test)
    assert abs(sum(routing["path_fractions"].values()) - 1.0) < 1e-6
    assert routing["compute_units_per_event"] > 0


# --- the ambiguous corpus and what it enables --------------------------------


@pytest.fixture(scope="module")
def ambiguous():  # type: ignore[no-untyped-def]
    return (
        build_dataset(name="amb-train", count=90, seed=3, corpus="ambiguous"),
        build_dataset(name="amb-test", count=90, seed=11, corpus="ambiguous"),
    )


def test_ambiguous_corpus_interleaves_multiple_lineages(ambiguous) -> None:  # type: ignore[no-untyped-def]
    """Its whole purpose: no local window contains a coherent story."""
    from pocketsec.stage1.labs.ambiguous_corpus import build_ambiguous_corpus
    from pocketsec.stage1.pipeline import Stage1Pipeline

    pipeline = Stage1Pipeline()
    counts = []
    for index, scenario in enumerate(build_ambiguous_corpus(count=12, seed=11)):
        result = pipeline.run_scenario(scenario, offset=index)
        counts.append(len({t.actor.identity for t in result.transitions}))
    assert min(counts) >= 3, "sessions must interleave several concurrent actors"


def test_ambiguous_corpus_has_both_classes(ambiguous) -> None:  # type: ignore[no-untyped-def]
    _, test = ambiguous
    assert 0 < test.positive_count < len(test)


@pytest.mark.slow
def test_ambiguous_corpus_is_not_saturated(ambiguous) -> None:
    """The reason this corpus exists.

    Both earlier corpora saturate — the hard one ties five architectures at
    0.9992, the long one lets two reach 1.0000 — so neither can show that any
    component helps. A corpus that no model solves perfectly is what makes an
    ablation informative.
    """
    train, test = ambiguous
    tcn = TCNBaseline(hidden=24, epochs=EPOCHS).fit(train)
    assert _score(tcn, test) < 0.95, (
        "the local-burst shortcut is back: this corpus has no headroom and "
        "cannot justify any DTL component"
    )


@pytest.mark.slow
def test_router_and_surprise_are_removed_by_default() -> None:
    """Acceptance criterion 12, applied.

    Both measured harmful on the ambiguous corpus and neutral elsewhere, so
    neither has an ablation-supported reason to exist.
    """
    config = DTLConvConfig()
    assert config.use_router is False
    assert config.use_surprise is False
    assert config.use_multiscale is True
    assert config.use_maxpool is True


def test_actor_slot_is_a_grouping_key_not_an_identity() -> None:
    """Refines ADR-0007 rather than contradicting it.

    The slot is local to one session and assigned by order of first appearance,
    so it carries no name, no pid and no cross-session meaning. Two sessions
    with completely different processes both start at slot 0, so there is
    nothing to memorise.
    """
    first = build_dataset(name="a", count=8, seed=11, corpus="ambiguous")
    second = build_dataset(name="b", count=8, seed=3, corpus="ambiguous")
    for dataset in (first, second):
        for sample in dataset.samples:
            slots = sorted({step.actor_slot for step in sample.steps})
            assert slots[0] == 0, "slots must be session-local and start at 0"
            assert slots == list(range(len(slots))), "slots must be dense"


def test_ambiguous_corpus_is_aggregate_matched() -> None:
    """The label must not be inferable from operation counts.

    The first version leaked exactly this way: malicious sessions contained
    more injected events and a bag-of-features model could count them.
    """
    from collections import Counter

    from pocketsec.stage1.labs.ambiguous_corpus import build_ambiguous_corpus

    totals: dict[int, Counter[str]] = {0: Counter(), 1: Counter()}
    sessions = {0: 0, 1: 0}
    for scenario in build_ambiguous_corpus(count=90, seed=11):
        sessions[scenario.label] += 1
        for behaviour in scenario.behaviours:
            totals[scenario.label][behaviour.operation] += 1

    for operation in set(totals[0]) | set(totals[1]):
        benign = totals[0][operation] / max(sessions[0], 1)
        attack = totals[1][operation] / max(sessions[1], 1)
        assert abs(benign - attack) < max(1.5, 0.15 * max(benign, attack)), (
            f"operation {operation!r} differs across classes: "
            f"{benign:.2f} vs {attack:.2f} per session"
        )


@pytest.mark.slow
def test_lineage_pooling_helps_on_an_attribution_task(ambiguous) -> None:  # type: ignore[no-untyped-def]
    """The largest single improvement measured in Stage 2.

    A flat temporal pool cannot express "did any one lineage accumulate
    dangerous capability". Pooling within each lineage and taking the worst
    lineage asks that question directly.
    """
    _, with_pool = _train(ambiguous, use_lineage_pool=True)
    _, without_pool = _train(ambiguous, use_lineage_pool=False)
    assert with_pool > without_pool
