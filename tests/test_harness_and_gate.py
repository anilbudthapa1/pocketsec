"""D0.3 + D0.8 + acceptance gate — the end-to-end Stage 0 proof."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import make_sequence

from pocketsec.stage0.baselines.frequency_baseline import FrequencyBaselineSlot
from pocketsec.stage0.benchmark.dataset import DatasetError, SequenceDataset
from pocketsec.stage0.benchmark.fixtures import write_fixture
from pocketsec.stage0.benchmark.harness import BenchmarkCase, run_benchmark
from pocketsec.stage0.benchmark.profiles import PROFILES, check_profile
from pocketsec.stage0.benchmark.resource_metrics import ResourceMetrics, ResourceSampler
from pocketsec.stage0.cli import main
from pocketsec.stage0.contracts.model_slot import NullModelSlot
from pocketsec.stage0.gate import run_gate
from pocketsec.stage0.hypotheses import HYPOTHESES, unsupported_status_claims
from pocketsec.stage0.prior_art import PriorArtLedger
from pocketsec.stage0.repro.seeds import SeedSet
from pocketsec.stage0.smoke import SMOKE_EXPERIMENT_ID, run_smoke_benchmark

# --- dataset integrity -------------------------------------------------------


def test_dataset_refuses_a_checksum_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "d.jsonl"
    meta = write_fixture(path, split="eval", count=10, seed=1)
    with pytest.raises(DatasetError, match="checksum mismatch"):
        SequenceDataset.load_jsonl(
            path, name="d", version="v1", expected_sha256="f" * 64
        )
    # the true digest loads fine
    assert len(SequenceDataset.load_jsonl(
        path, name="d", version="v1", expected_sha256=meta["sha256"]
    )) == 10


def test_fixture_generation_is_deterministic(tmp_path: Path) -> None:
    first = write_fixture(tmp_path / "a.jsonl", split="eval", count=20, seed=99)
    second = write_fixture(tmp_path / "b.jsonl", split="eval", count=20, seed=99)
    assert first["sha256"] == second["sha256"]


def test_train_split_is_benign_only(tmp_path: Path) -> None:
    path = tmp_path / "train.jsonl"
    meta = write_fixture(path, split="train", count=30, seed=5)
    dataset = SequenceDataset.load_jsonl(
        path, name="t", version="v1", expected_sha256=meta["sha256"]
    )
    assert dataset.positive_count == 0


def test_unseen_technique_items_do_not_appear_in_training(tmp_path: Path) -> None:
    """Leakage-resistant by construction (fair-comparison rule 1)."""
    train_path, eval_path = tmp_path / "tr.jsonl", tmp_path / "ev.jsonl"
    tm = write_fixture(train_path, split="train", count=40, seed=1)
    em = write_fixture(eval_path, split="eval", count=40, seed=2)
    train = SequenceDataset.load_jsonl(
        train_path, name="t", version="v", expected_sha256=tm["sha256"]
    )
    evaluation = SequenceDataset.load_jsonl(
        eval_path, name="e", version="v", expected_sha256=em["sha256"]
    )

    train_kinds = {e.kind for item in train for e in item.sequence.events}
    unseen_kinds = {
        e.kind
        for item in evaluation
        if item.unseen_technique
        for e in item.sequence.events
    }
    assert unseen_kinds - train_kinds, "unseen-technique items must introduce novel kinds"


def test_missing_dataset_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(DatasetError, match="not found"):
        SequenceDataset.load_jsonl(tmp_path / "nope.jsonl", name="n", version="v")


def test_malformed_dataset_line_reports_its_line_number(tmp_path: Path) -> None:
    path = tmp_path / "bad.jsonl"
    path.write_text('{"label": 0}\n', encoding="utf-8")
    with pytest.raises(DatasetError, match=r":1:"):
        SequenceDataset.load_jsonl(path, name="n", version="v")


# --- baseline ----------------------------------------------------------------


def test_unfitted_baseline_abstains_rather_than_guessing() -> None:
    prediction = FrequencyBaselineSlot().predict(make_sequence())
    assert prediction.abstained is True


def test_baseline_reports_uncalibrated_confidence(tmp_path: Path) -> None:
    result = run_smoke_benchmark(tmp_path)
    assert result.calibrated is False, "H0 has no calibration map and must not claim one"


def test_baseline_distinguishes_cheap_from_statistical_paths(tmp_path: Path) -> None:
    result = run_smoke_benchmark(tmp_path)
    paths = result.novelty.path_counts
    assert paths.get("CHEAP_TRANSITION", 0) > 0
    assert paths.get("STATISTICAL", 0) > 0, "novelty economics must be measured, not assumed"
    assert result.novelty.resolved_without_inference == pytest.approx(1.0)


# --- harness -----------------------------------------------------------------


def test_smoke_benchmark_produces_a_complete_result(tmp_path: Path) -> None:
    result = run_smoke_benchmark(tmp_path)
    assert result.experiment_id == SMOKE_EXPERIMENT_ID
    assert result.synthetic_data is True, "fixture results must be labelled synthetic"
    assert result.security.sample_count > 0
    assert result.resources.events_processed > 0
    assert result.dataset["sha256"]
    assert result.environment.to_dict()["seeds"]["master"]
    payload = json.dumps(result.to_dict())  # must be JSON-serialisable for retention
    assert SMOKE_EXPERIMENT_ID in payload


def test_harness_is_deterministic_for_a_fixed_seed(tmp_path: Path) -> None:
    first = run_smoke_benchmark(tmp_path / "a")
    second = run_smoke_benchmark(tmp_path / "b")
    assert first.security.pr_auc == second.security.pr_auc
    assert first.novelty.path_counts == second.novelty.path_counts


def test_harness_rejects_a_malformed_experiment_id(tmp_path: Path) -> None:
    path = tmp_path / "d.jsonl"
    meta = write_fixture(path, split="eval", count=10, seed=1)
    dataset = SequenceDataset.load_jsonl(
        path, name="d", version="v", expected_sha256=meta["sha256"]
    )
    with pytest.raises(ValueError, match="malformed"):
        run_benchmark(
            NullModelSlot(),
            dataset,
            BenchmarkCase(case_id="c"),
            experiment_id="bad-id",
            seeds=SeedSet(1),
            synthetic_data=True,
        )


def test_null_slot_scores_zero_recall_as_the_floor(tmp_path: Path) -> None:
    """The lower bound every mechanism must beat."""
    path = tmp_path / "d.jsonl"
    meta = write_fixture(path, split="eval", count=20, seed=3)
    dataset = SequenceDataset.load_jsonl(
        path, name="d", version="v", expected_sha256=meta["sha256"]
    )
    result = run_benchmark(
        NullModelSlot(),
        dataset,
        BenchmarkCase(case_id="floor"),
        experiment_id="PS-S0-20260924-BASE-null-0001",
        seeds=SeedSet(1),
        synthetic_data=True,
    )
    assert result.security.abstention_rate == 1.0
    assert result.security.confusion.true_positives == 0


# --- resources and profiles --------------------------------------------------


def test_resource_sampler_measures_a_region() -> None:
    with ResourceSampler(interval_seconds=0.001) as sampler:
        _ = [object() for _ in range(10_000)]
    metrics = sampler.result(events_processed=10, startup_seconds=0.0)
    assert metrics.wall_seconds > 0
    assert metrics.events_per_second is not None
    assert metrics.cpu_seconds_per_event is not None


def test_unmeasured_target_is_not_a_met_target() -> None:
    """ProfileReport.within_target must be None, not True, when nothing measured."""
    blank = ResourceMetrics(
        idle_rss_bytes=None,
        peak_rss_bytes=None,
        peak_sampled_rss_bytes=None,
        pss_bytes=None,
        delta_rss_bytes=None,
        cpu_seconds=0.0,
        wall_seconds=0.0,
        events_processed=0,
        startup_seconds=None,
        sample_count=0,
        unavailable=("rss", "pss", "peak_rss"),
    )
    report = check_profile(blank, "edge")
    assert report.within_target is None
    assert "agent_rss" in report.unmeasured


def test_exceeding_a_profile_target_is_reported() -> None:
    heavy = ResourceMetrics(
        idle_rss_bytes=1,
        peak_rss_bytes=999 * 1024 * 1024,
        peak_sampled_rss_bytes=999 * 1024 * 1024,
        pss_bytes=1,
        delta_rss_bytes=0,
        cpu_seconds=0.1,
        wall_seconds=0.1,
        events_processed=1,
        startup_seconds=0.0,
        sample_count=1,
    )
    report = check_profile(heavy, "nano", model_bytes=0)
    assert report.within_target is False
    assert report.exceeded


def test_unknown_profile_is_refused() -> None:
    with pytest.raises(KeyError, match="unknown resource profile"):
        check_profile(
            ResourceMetrics(None, None, None, None, None, 0.0, 0.0, 0, None, 0), "huge"
        )


def test_the_three_spec_profiles_exist() -> None:
    assert set(PROFILES) == {"nano", "edge", "research_max"}


# --- hypotheses and prior art ------------------------------------------------


def test_no_hypothesis_claims_an_unevidenced_result() -> None:
    assert unsupported_status_claims() == []


def test_every_hypothesis_has_a_prior_art_entry() -> None:
    ledger = PriorArtLedger.load()
    assert ledger.missing_hypotheses() == []
    assert ledger.inconsistencies() == []
    assert set(ledger.entries) == set(HYPOTHESES)


def test_no_novelty_claim_is_currently_permitted() -> None:
    """Stage 0 non-goal: do not claim NERA is novel or superior."""
    ledger = PriorArtLedger.load()
    assert not any(entry.novelty_claim_permitted for entry in ledger.entries.values())


# --- the gate ----------------------------------------------------------------


def test_stage0_acceptance_gate_passes() -> None:
    report = run_gate()
    failures = [f"{c.id}: {c.detail}" for c in report.failures]
    assert report.passed, "Stage 0 gate failures:\n" + "\n".join(failures)
    assert len(report.checks) == 9


def test_gate_cli_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["gate"]) == 0
    assert "GATE: PASSED" in capsys.readouterr().out


def test_gate_cli_emits_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--json", "gate"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["passed"] is True
    assert len(payload["checks"]) == 9


def test_experiment_id_cli(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(
        [
            "experiment-id",
            "--stage",
            "1",
            "--hypothesis",
            "H2",
            "--slug",
            "ssir-ontology",
            "--sequence",
            "7",
            "--date",
            "20260101",
        ]
    )
    assert code == 0
    assert capsys.readouterr().out.strip() == "PS-S1-20260101-H2-ssir-ontology-0007"


def test_env_cli(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["env"]) == 0
    assert "python_version" in json.loads(capsys.readouterr().out)
