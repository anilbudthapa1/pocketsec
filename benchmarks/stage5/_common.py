"""Shared plumbing for the Stage 5 measurement scripts in this directory.

Why these scripts live here and not under ``pocketsec/stage5/``: each one needs a
capability the stage's own rules forbid inside the package, for good reasons —
naming the executor (T4), importing a Stage 4 module other than ``stage5_interface``
(T1), launching a process (P2), or loosening the Action Shadow ceiling for a
sensitivity sweep (a safety lever that must not ship in the privileged stage). They
use the package; the package never uses them.

Recording goes through Stage 0's instruments only: ``ResourceSampler`` for resource
cost, ``check_profile`` for the edge envelope, ``ExperimentRegistry.register`` for the
append-only ledger, and ``results/<experiment_id>.json`` for the payload (integration
plan §5.3 steps 4 and 5). ``run_benchmark`` itself is not used: it requires a
``ModelSlot`` mapping ``SecurityEventSequenceV1`` to ``ThreatPredictionV1``, and Stage 5
consumes a ``CBFResolutionV1`` plus a host and emits transaction receipts. Wrapping a
responder as a detector would invent an encoding and report a PR-AUC that measures it.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from pocketsec.stage0.benchmark.profiles import check_profile  # noqa: E402
from pocketsec.stage0.benchmark.resource_metrics import ResourceSampler  # noqa: E402
from pocketsec.stage0.experiments.registry import ExperimentRegistry  # noqa: E402

REGISTRY_PATH = REPO_ROOT / "experiments" / "registry.jsonl"
RESULTS_DIR = REPO_ROOT / "results"


def loadavg() -> list[float]:
    """``/proc/loadavg``'s three figures. Recorded beside every timing, always."""
    with open("/proc/loadavg", encoding="ascii") as handle:
        return [float(value) for value in handle.read().split()[:3]]


def executor_factory() -> Callable[[Any], Any]:
    """The gate's own real-executor factory. Only ``gate.py`` may name the class."""
    from pocketsec.stage5.gate import executor_for_rig

    return executor_for_rig


def primed(policy: Callable[[Any], Any]) -> Callable[[Any], Any]:
    """The gate's own priming: in-simulator LAB_SANDBOX drills fill the rig's memory."""
    from pocketsec.stage5.gate_runtime import prime_memory

    def run(rig: Any) -> Any:
        prime_memory(rig)
        return policy(rig)

    return run


def run_arm_measured(
    policy: Callable[[Any], Any], cases: Sequence[Any], *, arm: str
) -> dict[str, Any]:
    """One arm over one corpus, inside a Stage 0 ``ResourceSampler``."""
    from pocketsec.stage5.labs.baselines import run_arm

    with ResourceSampler() as sampler:
        outcome = run_arm(policy, cases, baseline_id=arm, build_executor=executor_factory())
    metrics = sampler.result(events_processed=len(cases), startup_seconds=None)
    return {
        **outcome.to_dict(),
        "cpu_seconds": metrics.cpu_seconds,
        "cpu_seconds_per_case": metrics.cpu_seconds_per_event,
        "wall_seconds": metrics.wall_seconds,
        "peak_sampled_rss_bytes": metrics.peak_sampled_rss_bytes,
        "edge_profile": check_profile(metrics, "edge").to_dict(),
    }


def record(
    *,
    experiment_id: str,
    title: str,
    slot_name: str,
    dataset_name: str,
    dataset_version: str,
    dataset_sha256: str,
    seeds: Mapping[str, int],
    notes: str,
    payload: Mapping[str, Any],
    command: str,
) -> None:
    """Write ``results/<id>.json`` and append one digest-chained ledger row.

    ``synthetic_data`` is ``True`` on every Stage 5 row: every corpus is a fixture and
    every host is ``SimulatedHost``. The registry refuses a reused id, so a second call
    for the same experiment fails loudly rather than overwriting history.
    """
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    result_path = RESULTS_DIR / f"{experiment_id}.json"
    body = {
        "experiment_id": experiment_id,
        "command": command,
        "synthetic_data": True,
        "simulated_host": True,
        "seeds": dict(seeds),
        "dataset": {"name": dataset_name, "version": dataset_version, "sha256": dataset_sha256},
        "payload": payload,
    }
    registry = ExperimentRegistry(REGISTRY_PATH)
    if registry.get(experiment_id) is not None:
        raise SystemExit(f"{experiment_id} is already registered; ids are never reused")
    result_path.write_text(json.dumps(body, indent=2, sort_keys=True, default=str) + "\n")
    registry.register(
        experiment_id=experiment_id,
        hypothesis="BASE",
        title=title,
        slot_name=slot_name,
        dataset_name=dataset_name,
        dataset_version=dataset_version,
        dataset_sha256=dataset_sha256,
        git_commit=None,
        seeds=dict(seeds),
        synthetic_data=True,
        notes=notes,
        result_path=str(result_path.relative_to(REPO_ROOT)),
    )
    print(f"recorded {experiment_id} -> {result_path.relative_to(REPO_ROOT)}")
