"""S2-E19 — the sleeping-brain benchmark, and ADR-0010's verdict.

Detection PR-AUC stopped discriminating after four corpora, so cost became the
deciding axis. These tests pin the measurement machinery and the conclusion it
produced.
"""

from __future__ import annotations

import pytest

from pocketsec.stage2.core_ids import PATH_COST_UNITS, ExecutionPath
from pocketsec.stage2.dataset import build_dataset
from pocketsec.stage2.research.baselines import MLPBaseline, TCNBaseline
from pocketsec.stage2.research.dtl_conv import DTLConvConfig, DTLConvModel
from pocketsec.stage2.research.sleeping_brain import (
    SleepingBrainPoint,
    sleeping_brain_report,
)


def test_cheap_path_share_counts_only_the_cheap_tiers() -> None:
    point = SleepingBrainPoint(
        name="probe",
        pr_auc=1.0,
        transitions=100,
        predict_seconds=0.1,
        parameters=0,
        path_fractions={
            ExecutionPath.P0_COMPILED.value: 0.5,
            ExecutionPath.P1_LATTICE.value: 0.2,
            ExecutionPath.P2_LOCAL.value: 0.1,
            ExecutionPath.P3_PREDICTIVE.value: 0.15,
            ExecutionPath.P4_DEEP.value: 0.05,
        },
        compute_units_per_event=1.0,
    )
    assert point.cheap_path_share == pytest.approx(0.8)
    assert point.microseconds_per_event == pytest.approx(1000.0)


def test_models_without_routing_report_no_path_share() -> None:
    point = SleepingBrainPoint("m", 1.0, 10, 0.01, 0, {}, None)
    assert point.cheap_path_share is None


def test_path_costs_are_ordered_cheapest_first() -> None:
    costs = [PATH_COST_UNITS[path] for path in ExecutionPath]
    assert costs == sorted(costs)


@pytest.mark.slow
def test_dtl_is_dominated_on_cost_at_equal_quality() -> None:
    """ADR-0010's decisive measurement.

    DTL reached detection parity with a plain TCN but at several times the
    per-event cost. Criterion 1 permits DTL to survive on wake rate rather than
    detection; this is the measurement that closed that door.
    """
    train = build_dataset(name="sb-train", count=90, seed=3, corpus="ambiguous")
    test = build_dataset(name="sb-test", count=90, seed=11, corpus="ambiguous")
    report = sleeping_brain_report(
        [
            TCNBaseline(hidden=24, epochs=20),
            DTLConvModel(DTLConvConfig(latent=48, epochs=20)),
        ],
        train,
        test,
    )
    by_name = {p["name"]: p for p in report["points"]}
    tcn, dtl = by_name["tcn"], by_name["dtl-conv"]
    assert dtl["pr_auc"] <= tcn["pr_auc"] + 0.01, "DTL never beat the TCN on detection"
    assert tcn["microseconds_per_event"] < dtl["microseconds_per_event"], (
        "the TCN was measured cheaper per event at equal quality; if that has "
        "changed, reopen ADR-0010"
    )


@pytest.mark.slow
def test_pareto_identifies_the_cheapest_model_at_best_quality() -> None:
    train = build_dataset(name="sb2-train", count=60, seed=3, corpus="ambiguous")
    test = build_dataset(name="sb2-test", count=60, seed=11, corpus="ambiguous")
    report = sleeping_brain_report(
        [TCNBaseline(hidden=24, epochs=15), MLPBaseline(hidden=24, epochs=15)],
        train,
        test,
    )
    pareto = report["pareto"]
    assert pareto["cheapest_at_best_quality"] in pareto["tied_at_best_quality"]
    assert pareto["verdict"]
