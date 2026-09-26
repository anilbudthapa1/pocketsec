"""Shared plumbing for the Stage 6 measurement scripts in this directory.

Why these scripts live here and not under ``pocketsec/stage6/``: several of them run
the Stage 6 learner under a *diagnostic* configuration the package must never ship
(a genesis threshold other than ``DEFAULT_THRESHOLD``, a denser corpus, a longer
horizon), and the stage's boundary rules forbid anything but ``gate*.py``/``cli.py``
from importing the gate rig. They use the package; the package never uses them.

Recording goes through Stage 0's instruments only: ``ResourceSampler`` for resource
cost, ``check_profile`` for the edge envelope, ``evaluate_scores`` /
``average_precision`` for security quality, ``ExperimentRegistry.register`` for the
append-only ledger and ``results/<experiment_id>.json`` for the payload (integration
plan §5.3). ``run_benchmark`` itself is not used: it requires a ``ModelSlot`` mapping
``SecurityEventSequenceV1`` to ``ThreatPredictionV1``, and a Stage 6 learner scores
Stage 1 *encoded steps* of a compiled session. Re-encoding raw events inside
``predict`` would run a second Stage 1 pipeline whose lineage state is carried
across sessions (MEMORY.md corpus trap), so the harness's own metric functions are
applied to the scores the learners produce on the compiled eval sessions instead.

Every row is ``synthetic_data=True``: every corpus is a fixture and every Stage 5
record the stage learns from is simulated.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from collections.abc import Iterator

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from pocketsec.stage0.experiments.registry import ExperimentRegistry

REGISTRY_PATH = REPO_ROOT / "experiments" / "registry.jsonl"
RESULTS_DIR = REPO_ROOT / "results"


def loadavg() -> list[float]:
    """``/proc/loadavg``'s three figures. Recorded beside every timing, always."""
    with open("/proc/loadavg", encoding="ascii") as handle:
        return [float(value) for value in handle.read().split()[:3]]


@contextmanager
def genesis_threshold(value: float | None) -> Iterator[None]:
    """DIAGNOSTIC ONLY: every ``genesis_state`` call made inside uses ``threshold=value``.

    ``semantic.genesis_state`` takes ``threshold`` as a keyword-only default, and every
    caller (the Stage 6 learner, every §7 baseline, the oracle) references the one
    function object, so patching its ``__kwdefaults__`` changes all learners together:
    the comparison between learners stays fair. ``None`` leaves the shipped default.
    The package constant ``DEFAULT_THRESHOLD`` is never edited.
    """
    from pocketsec.stage6.memory import semantic

    if value is None:
        yield
        return
    saved = dict(semantic.genesis_state.__kwdefaults__)
    semantic.genesis_state.__kwdefaults__["threshold"] = value
    try:
        yield
    finally:
        semantic.genesis_state.__kwdefaults__.clear()
        semantic.genesis_state.__kwdefaults__.update(saved)


def record(
    *,
    experiment_id: str,
    hypothesis: str,
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

    The registry refuses a reused id, so a second call for the same experiment fails
    loudly rather than overwriting history.
    """
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    result_path = RESULTS_DIR / f"{experiment_id}.json"
    registry = ExperimentRegistry(REGISTRY_PATH)
    if registry.get(experiment_id) is not None:
        raise SystemExit(f"{experiment_id} is already registered; ids are never reused")
    body = {
        "experiment_id": experiment_id,
        "command": command,
        "synthetic_data": True,
        "seeds": dict(seeds),
        "dataset": {"name": dataset_name, "version": dataset_version, "sha256": dataset_sha256},
        "payload": payload,
    }
    result_path.write_text(json.dumps(body, indent=2, sort_keys=True, default=str) + "\n")
    registry.register(
        experiment_id=experiment_id,
        hypothesis=hypothesis,
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


def corpus_digest(compiled: Any) -> str:
    """A digest over the compiled timeline's identity: version, seed, capsule ids, poison ids."""
    from pocketsec.stage0.contracts.common import digest_of_bytes

    ids = [e.capsule.capsule_id for m in compiled.months for e in m.events
           if e.capsule is not None]
    return digest_of_bytes(json.dumps(
        [compiled.version, compiled.seed, ids, sorted(compiled.poison_ids)]).encode("utf-8"))
