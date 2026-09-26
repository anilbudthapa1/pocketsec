"""Shared plumbing for the Stage 8 measurement scripts in this directory.

Why these scripts live here and not under ``pocketsec/stage8/``: the package never imports
them, and Stage 8's boundary rules (``pocketsec/stage8/gate_boundary.py``) are written for the
package, not for a measurement harness that also calls private helpers to build controls
(Stage 5/6/7 precedent: ``benchmarks/stage5``, ``benchmarks/stage6``, ``benchmarks/stage7``).

**How ``run_benchmark`` is used.** Detection results of a deployable Stage 8 artefact go
through ``pocketsec.stage0.benchmark.harness.run_benchmark``. The unit is a *set of reproduced
mechanisms* (optionally OR-ed with the Φ-oracle at its TRAIN FPR-budget threshold), wrapped as
one :class:`MechanismSetSlot`. The dataset is a split of the discovery corpus written as a
checksum-bound JSONL of Stage 0 sequences, one per episode, keyed by episode id, with one
``SecurityEventV1`` per encoded Stage 1 step, so ``event_count`` is the number of steps the
detector reads (Stage 1/7 precedent ``stage1/gate.py:_stub_sequence``). The slot looks the
episode's already-encoded steps up by id and never re-encodes raw events: a second Stage 1
pipeline would carry lineage state across sessions (MEMORY.md corpus trap).

Every figure is ``synthetic_data=True``: every corpus here is synthetic and the planted truth
shares an author with the engine (spec §9.1). Every detection figure is
``counterfactual_at_boundary``: Stage 6 adopts no Stage 8 discovery (B8-1, ADR-0076).
"""

from __future__ import annotations

import json
import os
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from pocketsec.stage0.benchmark.dataset import SequenceDataset, sha256_file  # noqa: E402
from pocketsec.stage0.benchmark.harness import BenchmarkCase, run_benchmark  # noqa: E402
from pocketsec.stage0.contracts.model_slot import (  # noqa: E402
    ACCEPTED_INPUT_SCHEMA,
    PRODUCED_OUTPUT_SCHEMA,
)
from pocketsec.stage0.contracts.security_event_v1 import (  # noqa: E402
    SecurityEventSequenceV1,
    SecurityEventV1,
)
from pocketsec.stage0.contracts.threat_prediction_v1 import (  # noqa: E402
    ComputePath,
    ThreatPredictionV1,
    Verdict,
)
from pocketsec.stage0.experiments.registry import ExperimentRegistry  # noqa: E402
from pocketsec.stage0.repro.seeds import SeedSet  # noqa: E402

REGISTRY_PATH = REPO_ROOT / "experiments" / "registry.jsonl"
RESULTS_DIR = REPO_ROOT / "results"
OUT_DIR = Path(os.environ.get("STAGE8_BENCH_OUT", REPO_ROOT / "results" / "stage8-bench"))
FPR_BUDGET = 0.01  # = residual.observatory.FPR_BUDGET, restated so a drift is visible


def loadavg() -> list[float]:
    """``/proc/loadavg``'s three figures. Recorded beside every timing, always."""
    with open("/proc/loadavg", encoding="ascii") as handle:
        return [float(value) for value in handle.read().split()[:3]]


def stamp(label: str) -> None:
    print(f"### {time.strftime('%H:%M:%S')} {label} loadavg {loadavg()}", flush=True)


def save(name: str, payload: Mapping[str, Any]) -> Path:
    """Write one script's raw output to ``OUT_DIR/<name>.json`` (git-ignored ``results/``)."""
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / f"{name}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
    print(f"wrote {path}")
    return path


# -- threshold helpers -----------------------------------------------------------------------


def threshold_at_fpr(scores: Sequence[float], labels: Sequence[int],
                     budget: float = FPR_BUDGET) -> float | None:
    """Lowest score threshold whose FPR on (scores, labels) is <= budget (fit-side choice)."""
    negatives = sorted((s for s, y in zip(scores, labels, strict=True) if y == 0), reverse=True)
    if not negatives:
        return None
    allowed = int(budget * len(negatives))       # false positives permitted
    # threshold strictly above the (allowed+1)-th highest negative score
    if allowed >= len(negatives):
        return min(scores)
    cut = negatives[allowed]
    above = [s for s in scores if s > cut]
    return min(above) if above else float("inf")


def rates(decisions: Sequence[bool], labels: Sequence[int]) -> dict[str, Any]:
    tp = sum(1 for d, y in zip(decisions, labels, strict=True) if d and y == 1)
    fp = sum(1 for d, y in zip(decisions, labels, strict=True) if d and y == 0)
    pos = sum(1 for y in labels if y == 1)
    neg = len(labels) - pos
    return {"tp": tp, "fp": fp, "positives": pos, "negatives": neg,
            "recall": tp / pos if pos else None, "fpr": fp / neg if neg else None}


# -- the harness slot ------------------------------------------------------------------------


def write_split_dataset(episodes: Sequence[Any], path: Path, *, name: str,
                        version: str) -> SequenceDataset:
    """One split as a checksum-bound Stage 0 JSONL: one sequence per episode, one event per step."""
    lines = []
    for e in episodes:
        sid = e.episode_id
        host = e.context.host_id
        events = tuple(
            SecurityEventV1(event_id=f"{sid}-e{i}", host_id=host, boot_id="boot-0001",
                            observed_at_ns=i + 1, monotonic_ns=i + 1,
                            source="stage8.discovery_corpus", kind="ssir.transition")
            for i in range(len(e.steps)))
        sequence = SecurityEventSequenceV1(sequence_id=sid, host_id=host, events=events)
        lines.append(json.dumps({"sequence": sequence.to_dict(), "label": int(e.label),
                                 "technique": e.context.family or None,
                                 "unseen_technique": False}, sort_keys=True))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return SequenceDataset.load_jsonl(path, name=name, version=version,
                                      expected_sha256=sha256_file(path))


@dataclass
class MechanismSetSlot:
    """A deployed Stage 8 artefact: a fixed set of grammar mechanisms, optionally OR-ed with
    the Φ-oracle at a fixed threshold. SUSPICIOUS at confidence 1.0 on a hit, else BENIGN at
    confidence 1.0 (detection score 0.0). No calibration exists."""

    slot_name: str
    mechanisms: Sequence[Any]
    episodes: Mapping[str, Any]            # sequence id -> Episode
    phi_threshold: float | None = None
    model_state_version: str = "stage8-mechanism-set.0"
    input_schema: str = ACCEPTED_INPUT_SCHEMA
    output_schema: str = PRODUCED_OUTPUT_SCHEMA
    fired: int = field(default=0)

    def predict(self, sequence: SecurityEventSequenceV1) -> ThreatPredictionV1:
        episode = self.episodes[sequence.sequence_id]
        hit = any(m.matches(episode.steps) for m in self.mechanisms)
        if not hit and self.phi_threshold is not None:
            hit = episode.phi_oracle_score() >= self.phi_threshold
        self.fired += hit
        return ThreatPredictionV1(
            prediction_id=f"{self.slot_name}-{sequence.sequence_id}",
            sequence_id=sequence.sequence_id,
            verdict=Verdict.SUSPICIOUS if hit else Verdict.BENIGN,
            state_identifier=None, confidence=1.0, calibration_id=None,
            novelty_score=0.0, uncertainty=0.0, evidence_relevance=(), next_event=None,
            compute_path=ComputePath.CHEAP_TRANSITION,
            compute_budget_units=float(len(self.mechanisms) * len(episode.steps)),
            model_state_version=self.model_state_version,
        )


def bench(slot: Any, dataset: SequenceDataset, experiment_id: str, seed: int,
          model_bytes: int | None = None) -> dict[str, Any]:
    """One ``run_benchmark`` call, reduced to the figures the findings quote."""
    case = BenchmarkCase(case_id="stage8-counterfactual-at-boundary", threshold=0.5,
                         fpr_budget=FPR_BUDGET, resource_profile="edge")
    before = loadavg()
    result = run_benchmark(slot, dataset, case, experiment_id=experiment_id,
                           seeds=SeedSet(master=seed), synthetic_data=True,
                           model_bytes=model_bytes)
    sec, res = result.security, result.resources
    c = sec.confusion
    return {
        "slot": slot.slot_name, "items": sec.sample_count, "positives": sec.positive_count,
        "tp": c.true_positives, "fp": c.false_positives, "fn": c.false_negatives,
        "tn": c.true_negatives,
        "recall_at_threshold": (c.true_positives / sec.positive_count
                                if sec.positive_count else None),
        "fpr_at_threshold": c.false_positive_rate,
        "recall_at_fpr_budget": sec.recall_at_fpr_budget, "pr_auc": sec.pr_auc,
        "events": dataset.event_count,
        "peak_rss_bytes": res.peak_rss_bytes, "cpu_seconds_per_event": res.cpu_seconds_per_event,
        "resources": res.to_dict(),
        "edge_profile": result.profile_report.to_dict(),
        "synthetic_data": result.synthetic_data, "dataset_sha256": result.dataset["sha256"],
        "loadavg_before": before, "loadavg_after": loadavg(),
    }


# -- the ledger (explicit act; never called by the gate) -------------------------------------


def record(*, experiment_id: str, hypothesis: str, title: str, slot_name: str,
           dataset_name: str, dataset_version: str, dataset_sha256: str,
           seeds: Mapping[str, int], notes: str, payload: Mapping[str, Any],
           command: str) -> None:
    """Write ``results/<id>.json`` and append one digest-chained ledger row."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    result_path = RESULTS_DIR / f"{experiment_id}.json"
    registry = ExperimentRegistry(REGISTRY_PATH)
    if registry.get(experiment_id) is not None:
        raise SystemExit(f"{experiment_id} is already registered; ids are never reused")
    body = {"experiment_id": experiment_id, "command": command, "synthetic_data": True,
            "seeds": dict(seeds),
            "dataset": {"name": dataset_name, "version": dataset_version,
                        "sha256": dataset_sha256},
            "payload": payload}
    result_path.write_text(json.dumps(body, indent=2, sort_keys=True, default=str) + "\n")
    registry.register(
        experiment_id=experiment_id, hypothesis=hypothesis, title=title, slot_name=slot_name,
        dataset_name=dataset_name, dataset_version=dataset_version,
        dataset_sha256=dataset_sha256, git_commit=None, seeds=dict(seeds),
        synthetic_data=True, notes=notes, result_path=str(result_path.relative_to(REPO_ROOT)))
    print(f"recorded {experiment_id} -> {result_path.relative_to(REPO_ROOT)}")


def corpus_digest(corpus: Any) -> str:
    """sha256 over the discovery corpus's identity: version, arm, seed, label seed, episode
    ids and labels per split (the CLI's ``_corpus_digest`` plus the labels)."""
    import hashlib

    ids = {split.value: sorted((e.episode_id, e.label) for e in episodes)
           for split, episodes in corpus.splits.items()}
    material = json.dumps([corpus.version, corpus.arm.value, corpus.seed, corpus.label_seed,
                           ids], sort_keys=True, default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(material).hexdigest()


def timed(fn: Callable[[], Any]) -> tuple[Any, float, float, list[float], list[float]]:
    """(value, wall s, CPU s, loadavg before, loadavg after)."""
    before = loadavg()
    wall0, cpu0 = time.perf_counter(), time.process_time()
    value = fn()
    return value, time.perf_counter() - wall0, time.process_time() - cpu0, before, loadavg()
