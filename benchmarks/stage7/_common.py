"""Shared plumbing for the Stage 7 measurement scripts in this directory.

Why these scripts live here and not under ``pocketsec/stage7/``: Stage 7's boundary rules
(``pocketsec/stage7/gate_boundary.py``) forbid a Stage 7 module from defining or wrapping the
Stage 0 harness, and only ``gate*.py``/``cli.py`` may import the gate. These scripts USE the
package; the package never imports them (Stage 5/6 precedent: ``benchmarks/stage5``,
``benchmarks/stage6``).

**How ``run_benchmark`` is used.** Detection results go through
``pocketsec.stage0.benchmark.harness.run_benchmark``. The unit Stage 7 changes is the set of
antibodies a receiver installs, so each aggregator's accepted set becomes one
:class:`AntibodySetSlot`, and the dataset is the receivers' held-out episodes written as a
checksum-bound JSONL of Stage 0 stub sequences (one per episode, keyed by id; Stage 1 gate
precedent ``stage1/gate.py:_stub_sequence``). The slot looks the episode's already-encoded
Stage 1 steps up by id and never re-encodes raw events, because a second Stage 1 pipeline
would carry lineage state across sessions (MEMORY.md corpus trap). The harness therefore
supplies the metrics, the resource sampler, the edge-profile check and the provenance; the
resource figures it reports are those of *scoring* with the installed set, not of the
collective protocol (the protocol's cost is measured by ``resources.py`` with the same
Stage 0 ``ResourceSampler``).

Every row is ``synthetic_data=True``: the fleet corpus is synthetic and the fleet is
simulated in-process.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping, Sequence
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
from pocketsec.stage7.antibody.forge import matches  # noqa: E402

REGISTRY_PATH = REPO_ROOT / "experiments" / "registry.jsonl"
RESULTS_DIR = REPO_ROOT / "results"
FPR_BUDGET = 0.01  # = byzantine_suite.FPR_BUDGET, restated so a drift is visible


def loadavg() -> list[float]:
    """``/proc/loadavg``'s three figures. Recorded beside every timing, always."""
    with open("/proc/loadavg", encoding="ascii") as handle:
        return [float(value) for value in handle.read().split()[:3]]


def episode_id(host_id: str, index: int) -> str:
    return f"s7-{host_id}-{index:03d}"


def write_heldout_dataset(corpus: Any, receivers: Sequence[str], path: Path) -> SequenceDataset:
    """The receivers' held-out episodes as a checksum-bound Stage 0 JSONL.

    Exactly the population ``byzantine_suite.detection`` scores: every held-out benign
    episode, and every held-out attack of a family the receiver never saw locally
    (``unseen_technique`` is therefore True on every positive).
    """
    lines = []
    for host_id in receivers:
        seen = corpus.host(host_id).families_local
        for e in corpus.for_host(host_id, history=False):
            if e.label == 1 and e.family in seen:
                continue
            sid = episode_id(host_id, e.index)
            sequence = SecurityEventSequenceV1(
                sequence_id=sid, host_id=host_id,
                events=(SecurityEventV1(event_id=f"{sid}-e0", host_id=host_id,
                                        boot_id="boot-0001", observed_at_ns=1, monotonic_ns=1,
                                        source="stage7.fleet_corpus", kind="stage7.episode"),),
            )
            lines.append(json.dumps({
                "sequence": sequence.to_dict(), "label": e.label,
                "technique": None if e.family is None else str(e.family),
                "unseen_technique": e.label == 1,
            }, sort_keys=True))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return SequenceDataset.load_jsonl(path, name="stage7-fleet-heldout",
                                      version=corpus.version,
                                      expected_sha256=sha256_file(path))


@dataclass
class AntibodySetSlot:
    """A receiver with a fixed set of installed antibody invariants (Stage 6 motif grammar).

    SUSPICIOUS at confidence 1.0 when any installed invariant matches the episode's encoded
    steps, else BENIGN at confidence 1.0 (detection score 0.0). No calibration exists.
    """

    slot_name: str
    installed: Mapping[str, Sequence[Any]]  # host id -> invariants
    episodes: Mapping[str, Any]  # sequence id -> FleetEpisode
    model_state_version: str = "stage7-antibody-set.0"
    input_schema: str = ACCEPTED_INPUT_SCHEMA
    output_schema: str = PRODUCED_OUTPUT_SCHEMA
    matched: int = field(default=0)

    def predict(self, sequence: SecurityEventSequenceV1) -> ThreatPredictionV1:
        episode = self.episodes[sequence.sequence_id]
        rules = self.installed.get(episode.host_id, ())
        hit = any(matches(rows, episode.steps) for rows in rules)
        self.matched += hit
        return ThreatPredictionV1(
            prediction_id=f"{self.slot_name}-{sequence.sequence_id}",
            sequence_id=sequence.sequence_id,
            verdict=Verdict.SUSPICIOUS if hit else Verdict.BENIGN,
            state_identifier=None, confidence=1.0, calibration_id=None,
            novelty_score=0.0, uncertainty=0.0, evidence_relevance=(), next_event=None,
            compute_path=ComputePath.CHEAP_TRANSITION,
            compute_budget_units=float(len(rules)),
            model_state_version=self.model_state_version,
        )


def bench(slot: AntibodySetSlot, dataset: SequenceDataset, experiment_id: str,
          seed: int) -> dict[str, Any]:
    """One ``run_benchmark`` call, reduced to the figures the findings quote."""
    case = BenchmarkCase(case_id="stage7-counterfactual-at-boundary", threshold=0.5,
                         fpr_budget=FPR_BUDGET, resource_profile="edge")
    result = run_benchmark(slot, dataset, case, experiment_id=experiment_id,
                           seeds=SeedSet(master=seed), synthetic_data=True)
    sec = result.security
    confusion = sec.confusion
    return {
        "slot": slot.slot_name,
        "items": sec.sample_count, "positives": sec.positive_count,
        "tp": confusion.true_positives, "fp": confusion.false_positives,
        "fn": confusion.false_negatives, "tn": confusion.true_negatives,
        "recall_at_fpr_budget": sec.recall_at_fpr_budget,
        "unseen_technique_recall": sec.unseen_technique_recall,
        "pr_auc": sec.pr_auc,
        "fp_rate": confusion.false_positive_rate,
        "peak_rss_bytes": result.resources.peak_rss_bytes,
        "cpu_seconds_per_event": result.resources.cpu_seconds_per_event,
        "edge_within_target": result.profile_report.within_target,
        "synthetic_data": result.synthetic_data,
        "dataset_sha256": result.dataset["sha256"],
    }


def record(*, experiment_id: str, hypothesis: str, title: str, slot_name: str,
           dataset_name: str, dataset_version: str, dataset_sha256: str,
           seeds: Mapping[str, int], notes: str, payload: Mapping[str, Any],
           command: str) -> None:
    """Write ``results/<id>.json`` and append one digest-chained ledger row (explicit act)."""
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
    """sha256 over the fleet corpus's identity: version, seed, and every episode's evidence."""
    import hashlib

    material = json.dumps([corpus.version, corpus.seed,
                           [(e.host_id, e.index, e.label, list(e.evidence_digests))
                            for e in corpus.episodes]], sort_keys=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(material).hexdigest()
