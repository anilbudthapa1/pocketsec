"""The Stage 0 smoke benchmark: H0 baseline, fixture data, full harness.

This is the concrete proof for acceptance clause 17.6 — "at least one
conventional baseline path can run through the benchmark harness, even if only
on a tiny fixture dataset". It is called by the gate, by CI, and by the tests.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from pocketsec.stage0.baselines.frequency_baseline import FrequencyBaselineSlot
from pocketsec.stage0.benchmark.dataset import SequenceDataset
from pocketsec.stage0.benchmark.fixtures import FIXTURE_VERSION, write_fixture
from pocketsec.stage0.benchmark.harness import BenchmarkCase, BenchmarkResult, run_benchmark
from pocketsec.stage0.repro.seeds import SeedSet

__all__ = ["SMOKE_CASE", "SMOKE_EXPERIMENT_ID", "run_smoke_benchmark"]

SMOKE_EXPERIMENT_ID = "PS-S0-20260924-H0-frequency-baseline-0000"
SMOKE_CASE = BenchmarkCase(
    case_id="stage0-smoke",
    threshold=0.5,
    fpr_budget=0.01,
    host_count=1,
    duration_seconds=86_400.0,
    resource_profile="edge",
)

TRAIN_COUNT = 80
EVAL_COUNT = 60
SEED = 20_260_924


def run_smoke_benchmark(workdir: Path | None = None) -> BenchmarkResult:
    """Generate fixtures, fit H0, and score it through the harness.

    The fixtures are regenerated into a temporary directory so the smoke run
    never depends on, or mutates, checked-in artifacts. Determinism comes from
    the seed, and the harness verifies the checksum it measured.
    """
    if workdir is not None:
        return _run(Path(workdir))
    with tempfile.TemporaryDirectory(prefix="pocketsec-smoke-") as tmp:
        return _run(Path(tmp))


def _run(root: Path) -> BenchmarkResult:
    train_path = root / "train.jsonl"
    eval_path = root / "eval.jsonl"
    train_meta = write_fixture(train_path, split="train", count=TRAIN_COUNT, seed=SEED)
    eval_meta = write_fixture(eval_path, split="eval", count=EVAL_COUNT, seed=SEED + 1)
    (root / "fixtures.meta.json").write_text(
        json.dumps({"train": train_meta, "eval": eval_meta}, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    train = SequenceDataset.load_jsonl(
        train_path,
        name="tiny-linux-events-train",
        version=FIXTURE_VERSION,
        expected_sha256=train_meta["sha256"],
    )
    evaluation = SequenceDataset.load_jsonl(
        eval_path,
        name="tiny-linux-events-eval",
        version=FIXTURE_VERSION,
        expected_sha256=eval_meta["sha256"],
    )

    slot = FrequencyBaselineSlot().fit(train)
    return run_benchmark(
        slot,
        evaluation,
        SMOKE_CASE,
        experiment_id=SMOKE_EXPERIMENT_ID,
        seeds=SeedSet(SEED),
        synthetic_data=True,
    )
