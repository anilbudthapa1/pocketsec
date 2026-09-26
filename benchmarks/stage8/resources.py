"""Resource cost and bounds, research side and endpoint side, under Stage 0's sampler.

1. Research side: one ``run_discovery`` (PLANTED seed 0) inside ``ResourceSampler``: idle RSS,
   sampled peak, incremental (peak - idle, floored at 0; lesson 8), CPU seconds, work units,
   CPU microseconds per work unit.
2. Bounds under flood: the gate's flood (10 000 external texts, 200 000 units) and a 10x flood
   (100 000 texts) under the DEFAULT 50 000 000-unit budget -- does a runaway hit a budget or
   a cap, or does it grow the host? Store sizes, refusals, incremental RSS.
3. Endpoint side, through ``run_benchmark`` on the REPLICATION split (240 episodes):
     PHI                 Φ-oracle at its TRAIN FPR-budget threshold;
     FORGE               the shipped compiled artefact(s), loaded with ``load_detector``;
     PHI_OR_FORGE        the deployed union;
     DIRECT_D2           LogisticProbe on pooled features, TRAIN+HOLDOUT labels, fit-side
                         FPR<=0.01 threshold (the equal-information control);
   plus the gate's own ``measure_endpoint_footprint``.
4. Endurance: ``run_endurance(cycles=12, seed=0)``.

Usage: ``PYTHONHASHSEED=0 python benchmarks/stage8/resources.py``
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field, replace

from _common import (
    OUT_DIR,
    MechanismSetSlot,
    bench,
    loadavg,
    save,
    stamp,
    threshold_at_fpr,
    write_split_dataset,
)

from pocketsec.stage0.benchmark.resource_metrics import ResourceSampler
from pocketsec.stage0.contracts.model_slot import ACCEPTED_INPUT_SCHEMA, PRODUCED_OUTPUT_SCHEMA
from pocketsec.stage0.contracts.threat_prediction_v1 import (
    ComputePath,
    ThreatPredictionV1,
    Verdict,
)
from pocketsec.stage1.guillotine.features import LogisticProbe
from pocketsec.stage8.episode import Split
from pocketsec.stage8.forge.representations import pooled_features
from pocketsec.stage8.forge.compiler import load_detector
from pocketsec.stage8.forge.tournament import _shipped, measure_endpoint_footprint
from pocketsec.stage8.gate import FLOOD_WORK_UNITS, flood_texts
from pocketsec.stage8.governor.budget import ResearchBudget
from pocketsec.stage8.labs.baselines import phi_oracle_baseline
from pocketsec.stage8.labs.discovery_corpus import CorpusArm, build_discovery_corpus
from pocketsec.stage8.labs.discovery_run import RunConfig, run_discovery, run_endurance
from pocketsec.stage6.resources import WorkMeter

EDGE_TARGET_BYTES = 100 * 1024 * 1024


def sampled(fn):
    sampler = ResourceSampler()
    l0 = loadavg()
    with sampler:
        value = fn()
    m = sampler.result(events_processed=1, startup_seconds=None)
    idle = m.idle_rss_bytes
    peaks = [v for v in (m.peak_sampled_rss_bytes,
                         None if idle is None or m.delta_rss_bytes is None
                         else idle + m.delta_rss_bytes) if v is not None]
    peak = max(peaks) if peaks else None
    return value, {"idle_rss_bytes": idle, "peak_sampled_rss_bytes": peak,
                   "incremental_rss_bytes": None if idle is None or peak is None
                   else max(0, peak - idle),
                   "cpu_seconds": m.cpu_seconds, "wall_seconds": m.wall_seconds,
                   "samples": m.sample_count, "loadavg": [l0, loadavg()]}


def run_summary(report) -> dict:
    return {"work_units": report.governor.spent, "budget_exhausted": report.budget_exhausted,
            "births": report.births, "registered": report.registered,
            "reproduced": len(report.reproduced), "packages": len(report.packages),
            "planted_recovered": [f for f, ok in report.planted_recovered if ok],
            "ledger": dict(report.ledger.stats()) if report.ledger else None,
            "lineage": dict(report.lineage.stats()) if report.lineage else None,
            "external_refused": sum(g.external_refused for g in report.generation),
            "governor_refusals": dict(report.governor.refusals_by_bound)}


@dataclass
class CompiledSlot:
    """The shipped FORGE artefacts, loaded from their bytes, optionally OR-ed with Φ."""

    slot_name: str
    detectors: list
    episodes: dict
    phi_threshold: float | None = None
    model_state_version: str = "stage8-forge-artefact.0"
    input_schema: str = ACCEPTED_INPUT_SCHEMA
    output_schema: str = PRODUCED_OUTPUT_SCHEMA
    meter: WorkMeter = field(default_factory=WorkMeter)

    def predict(self, sequence):
        episode = self.episodes[sequence.sequence_id]
        before = self.meter.spent
        hit = any(d.decide(episode, self.meter) for d in self.detectors)
        if not hit and self.phi_threshold is not None:
            hit = episode.phi_oracle_score() >= self.phi_threshold
        return ThreatPredictionV1(
            prediction_id=f"{self.slot_name}-{sequence.sequence_id}",
            sequence_id=sequence.sequence_id,
            verdict=Verdict.SUSPICIOUS if hit else Verdict.BENIGN, state_identifier=None,
            confidence=1.0, calibration_id=None, novelty_score=0.0, uncertainty=0.0,
            evidence_relevance=(), next_event=None, compute_path=ComputePath.CHEAP_TRANSITION,
            compute_budget_units=float(self.meter.spent - before),
            model_state_version=self.model_state_version)


@dataclass
class DirectSlot:
    slot_name: str
    probe: LogisticProbe
    cut: float
    episodes: dict
    model_state_version: str = "stage8-direct-d2.0"
    input_schema: str = ACCEPTED_INPUT_SCHEMA
    output_schema: str = PRODUCED_OUTPUT_SCHEMA

    def predict(self, sequence):
        episode = self.episodes[sequence.sequence_id]
        score = self.probe.predict([list(pooled_features(episode))])[0]
        hit = score >= self.cut
        return ThreatPredictionV1(
            prediction_id=f"{self.slot_name}-{sequence.sequence_id}",
            sequence_id=sequence.sequence_id,
            verdict=Verdict.SUSPICIOUS if hit else Verdict.BENIGN, state_identifier=None,
            confidence=1.0, calibration_id=None, novelty_score=0.0, uncertainty=0.0,
            evidence_relevance=(), next_event=None, compute_path=ComputePath.STATISTICAL,
            compute_budget_units=float(len(episode.steps)), model_state_version=self.model_state_version)


def main() -> None:
    out: dict = {}
    stamp("build PLANTED seed 0")
    corpus = build_discovery_corpus(arm=CorpusArm.PLANTED, seed=0)
    base = RunConfig(arm=CorpusArm.PLANTED, seed=0)

    stamp("1. research side: run_discovery under the sampler")
    report, cost = sampled(lambda: run_discovery(corpus, base))
    cost["cpu_us_per_work_unit"] = cost["cpu_seconds"] * 1e6 / report.governor.spent
    out["research"] = {**cost, **run_summary(report),
                       "edge_target_bytes": EDGE_TARGET_BYTES}
    print(f"  {out['research']}", flush=True)

    stamp("2a. gate flood: 10 000 texts, 200 000 units")
    flood, fcost = sampled(lambda: run_discovery(corpus, replace(
        base, budget=ResearchBudget(work_units=FLOOD_WORK_UNITS), external_texts=flood_texts())))
    out["flood_gate"] = {**fcost, **run_summary(flood)}
    print(f"  {out['flood_gate']}", flush=True)

    stamp("2b. 10x flood: 100 000 texts, default 50 000 000 units")
    big, bcost = sampled(lambda: run_discovery(corpus, replace(
        base, external_texts=flood_texts(100_000))))
    out["flood_10x_default_budget"] = {**bcost, **run_summary(big)}
    print(f"  {out['flood_10x_default_budget']}", flush=True)

    stamp("3. endpoint side through run_benchmark on REPLICATION")
    replication = corpus.episodes(Split.REPLICATION)
    by_id = {e.episode_id: e for e in replication}
    dataset = write_split_dataset(replication, OUT_DIR / "planted0-replication.jsonl",
                                  name="stage8-planted0-replication", version=corpus.version)
    phi = phi_oracle_baseline(corpus)
    shipped = _shipped(report.packages)
    # The selected entrant's measured artifact_bytes (the tournament's figure). An earlier
    # version of this line took len() of ``compiled_artifact``, a JSON mapping, and so recorded
    # its KEY COUNT (9) as bytes in results/stage8-bench/resources.json; that value is wrong.
    artefact_bytes = sum(
        next(e.artifact_bytes for e in p.detector_candidates.entrants
             if e.kind is p.selected_representation) or 0
        for p in report.packages if p.selected_representation is not None)
    fit = list(corpus.episodes(Split.TRAIN)) + list(corpus.episodes(Split.HOLDOUT))
    y_fit = [int(e.label) for e in fit]
    probe = LogisticProbe().fit([list(pooled_features(e)) for e in fit], y_fit)
    cut = threshold_at_fpr(probe.predict([list(pooled_features(e)) for e in fit]), y_fit)
    eid = "PS-S8-20260926-H4-endpoint-harness-0103"
    slots = [
        ("PHI", MechanismSetSlot("stage8-phi", [], by_id, phi_threshold=phi.threshold), None),
        ("FORGE", CompiledSlot("stage8-forge", [load_detector(d) for d in shipped], by_id),
         artefact_bytes),
        ("PHI_OR_FORGE", CompiledSlot("stage8-phi-or-forge",
                                      [load_detector(d) for d in shipped], by_id,
                                      phi_threshold=phi.threshold), artefact_bytes),
        ("DIRECT_D2", DirectSlot("stage8-direct-d2", probe, cut, by_id), None),
    ]
    out["endpoint"] = {"artefact_bytes": artefact_bytes,
                       "selected": [p.selected_representation.value if p.selected_representation
                                    else None for p in report.packages],
                       "slots": {}}
    for name, slot, model_bytes in slots:
        row = bench(slot, dataset, eid, seed=0, model_bytes=model_bytes)
        if isinstance(slot, CompiledSlot):
            row["work_units_per_episode"] = slot.meter.spent / len(replication)
        out["endpoint"]["slots"][name] = row
        print(f"  {name}: recall {row['recall_at_threshold']} fpr {row['fpr_at_threshold']} "
              f"pr_auc {row['pr_auc']} cpu s/event {row['cpu_seconds_per_event']} peak RSS "
              f"{row['peak_rss_bytes']} edge within {row['edge_profile'].get('within_target')} "
              f"load {row['loadavg_before']}", flush=True)
    footprint = measure_endpoint_footprint(report.packages, replication)
    out["endpoint"]["gate_footprint"] = asdict(footprint)
    print(f"  gate footprint {asdict(footprint)}", flush=True)
    save("resources", out)

    stamp("4. endurance 12 cycles")
    w0, c0, l0 = time.perf_counter(), time.process_time(), loadavg()
    endurance = run_endurance(cycles=12, seed=0)
    out["endurance"] = {**asdict(endurance), "wall_s": time.perf_counter() - w0,
                        "cpu_s": time.process_time() - c0, "loadavg": [l0, loadavg()]}
    e = out["endurance"]
    print(f"  endurance plateau_ok {e['plateau_ok']} problems {e['problems']} packages "
          f"{e['packages']} rss {e['rss_start']} -> {e['rss_peak']} sizes "
          f"{e['store_sizes']} evictions {e['evictions']} wall {e['wall_s']:.1f}s", flush=True)
    stamp("done")
    save("resources", out)


if __name__ == "__main__":
    main()
