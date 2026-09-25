"""``pocketsec-stage4`` — the Stage 4 operator entry point.

``gate``        run the twelve Stage 4 acceptance criteria (exits non-zero on failure)
``resolve``     replay the incident corpus through LUCID and print what it resolved
``baselines``   run all eight §7 baselines plus the mechanism and print the frontier
``ablation``    print the LucidConfig flag ablation, saturation guard first
``visibility``  fit and score the visibility model and print the held-out comparison
``flood``       run the adversarial branch flood and print every bound it reached
``sensing``     print what the discriminating-observation planner asked for, and refused
``resources``   measure Stage 4's incremental and peak RSS against the Stage 0 profile
``register``    append this gate run to experiments/registry.jsonl — **the only writer**

``register`` is a separate subcommand on purpose. Stage 3's gate appended a ``PS-S3-*``
row to the real append-only ledger every time it ran, so merely running the test suite
grew the permanent record (spec §2.7). Nothing else in this stage writes to it, and
G4.12 asserts the file is byte-identical across a gate run.

This is the only module in Stage 4 allowed to call ``print()``
(``tests/test_repository_structure.py``).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage1.observation.policy import AdaptiveObservationPolicy
from pocketsec.stage4 import gate_criteria as criteria
from pocketsec.stage4 import gate_probes as probes
from pocketsec.stage4.gate import (
    EXPERIMENT_ID,
    STAGE4_HYPOTHESIS,
    Stage4GateContext,
    run_gate,
)
from pocketsec.stage4.labs.baselines import pareto_frontier, run_baselines, saturation_guard
from pocketsec.stage4.labs.baseline_metrics import replay_corpus
from pocketsec.stage4.labs.experiments import blocked_experiments, run_ablation, saturation_check
from pocketsec.stage4.labs.incident_corpus import build_world_flood
from pocketsec.stage4.resources import loadavg, measure_stage4_resources

__all__ = ["main"]

_SUBCOMMANDS = (
    ("gate", "run the Stage 4 acceptance gate"),
    ("resolve", "replay the incident corpus through the LUCID engine"),
    ("baselines", "run the eight §7 baselines plus the mechanism"),
    ("ablation", "print the LucidConfig flag ablation"),
    ("visibility", "fit and score the visibility model on a held-out split"),
    ("flood", "run the adversarial branch flood and print every bound"),
    ("sensing", "print what the observation planner asked for and refused"),
    ("resources", "measure Stage 4 RSS against the Stage 0 Edge profile"),
    ("register", "append this gate run to the experiment ledger (the only writer)"),
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pocketsec-stage4", description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in _SUBCOMMANDS:
        sub.add_parser(name, help=help_text)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    handlers = {
        "gate": _gate,
        "resolve": _resolve,
        "baselines": _baselines,
        "ablation": _ablation,
        "visibility": _visibility,
        "flood": _flood,
        "sensing": _sensing,
        "resources": _resources,
        "register": _register,
    }
    return handlers[args.command](as_json=args.json)


def _gate(*, as_json: bool) -> int:
    report = run_gate()
    if as_json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print("PocketSec Stage 4 acceptance gate — CBF + LUCID\n")
        print(
            "This gate is EXPECTED TO FAIL and its failures are the stage's findings "
            "(docs/stage-4-spec.md §6.2). Read docs/stage-4-findings.md beside it.\n"
        )
        for check in report.checks:
            print(f"  [{'PASS' if check.passed else 'FAIL'}] {check.id}  {check.title}")
            print(f"         {check.detail}")
        print()
        print(
            "GATE: PASSED" if report.passed else f"GATE: FAILED ({len(report.failures)})"
        )
    return 0 if report.passed else 1


def _resolve(*, as_json: bool) -> int:
    ctx = Stage4GateContext.build()
    rows = [
        {
            "incident_id": run.case.incident_id,
            "truth_mechanism": run.case.truth.mechanism_id,
            "expected_state": run.case.expected_state,
            "state": run.resolution.verdict.state.value,
            "verdict": run.verdict.value,
            "leading_mechanism": run.resolution.verdict.leading_mechanism_id,
            "worlds": len(run.field.worlds),
            "confidence": round(run.confidence, 6),
            "claims": len(run.resolution.claim_graph.claims),
            "authoritative": len(run.resolution.claim_graph.authoritative),
            "gaps": len(run.resolution.gaps),
            "degraded": len(run.resolution.degraded),
        }
        for run in ctx.runs
    ]
    if as_json:
        print(json.dumps({"recall": ctx.recall.to_dict(), "incidents": rows}, indent=2))
        return 0
    print("LUCID resolution over the incident corpus (synthetic; NOT a detection result)\n")
    print(f"  {'incident':22}{'state':22}{'worlds':>7}{'conf':>8}{'claims':>8}{'auth':>6}")
    for row in rows:
        print(
            f"  {row['incident_id']:22}{row['state']:22}{row['worlds']:>7}"
            f"{row['confidence']:>8.4f}{row['claims']:>8}{row['authoritative']:>6}"
        )
    print(f"\n  world-set recall: {ctx.recall.to_dict()}")
    print(
        "  by_mechanism_id and by_equivalence are the spec's own two clauses; "
        "by_signal_coverage is the reading labs/baselines.py scores the frontier on, and "
        "B3_AlwaysOnRichTelemetry saturates it at 1.0 by construction."
    )
    return 0


def _baselines(*, as_json: bool) -> int:
    cases = criteria.corpus()
    split = criteria.measure_visibility_split(cases)
    outcomes = run_baselines(cases, seed=criteria.CORPUS_SEED, model=split.model)
    degenerate, why = saturation_guard(outcomes)
    frontier, dominated = pareto_frontier(outcomes)
    if as_json:
        print(
            json.dumps(
                {
                    "degenerate": degenerate,
                    "reason": why,
                    "frontier": list(frontier),
                    "dominated": list(dominated),
                    "outcomes": [outcome.to_dict() for outcome in outcomes],
                    "loadavg": list(loadavg()),
                },
                indent=2,
            )
        )
        return 0
    print("Stage 4 baselines (synthetic corpus; within-run ratios only)\n")
    print(f"  SATURATION GUARD: degenerate={degenerate} — {why}")
    if degenerate:
        print("  A DEGENERATE split records no comparison. The table below measures the split.\n")
    print(f"  {'baseline':30}{'recall':>9}{'unsup':>7}{'bytes':>9}{'cpu':>12}{'work':>9}")
    for outcome in outcomes:
        recall = "n/a" if outcome.world_set_recall is None else f"{outcome.world_set_recall:.4f}"
        print(
            f"  {outcome.baseline_id:30}{recall:>9}{outcome.unsupported_claim_count:>7}"
            f"{outcome.telemetry_bytes:>9}{outcome.cpu_units:>12.6f}{outcome.work_units:>9}"
        )
    print(f"\n  frontier  {list(frontier)}")
    print(f"  dominated {list(dominated)}")
    print(f"  loadavg   {loadavg()}")
    return 0


def _ablation(*, as_json: bool) -> int:
    cases = criteria.corpus()
    corpus_ok, corpus_why = saturation_check(cases)
    rows = run_ablation(cases, seed=criteria.CORPUS_SEED)
    blocked = blocked_experiments()
    if as_json:
        print(
            json.dumps(
                {
                    "corpus_degenerate": not corpus_ok,
                    "corpus_reason": corpus_why,
                    "rows": [row.to_dict() for row in rows],
                    "blocked": [spec.experiment_id for spec in blocked],
                },
                indent=2,
            )
        )
        return 0
    print("LucidConfig flag ablation (saturation guard first)\n")
    print(f"  corpus degenerate: {not corpus_ok} — {corpus_why}\n")
    print(f"  {'flag':28}{'core':10}{'with':>9}{'without':>9}{'delta':>9}  verdict")
    for row in rows:
        print(
            f"  {row.flag:28}{row.core_id:10}{row.with_value:>9.4f}"
            f"{row.without_value:>9.4f}{row.delta:>+9.4f}  {row.verdict}"
        )
    print(
        "\n  NOT_YET_JUSTIFIED is not REJECTED: on a corpus with no headroom, "
        "'no measured benefit' cannot demonstrate absence of benefit (ADR-0009)."
    )
    print(f"  blocked experiments: {[spec.experiment_id for spec in blocked]}")
    return 0


def _visibility(*, as_json: bool) -> int:
    split = criteria.measure_visibility_split(criteria.corpus())
    path = criteria.write_visibility_evidence(split)
    if as_json:
        print(json.dumps(json.loads(path.read_text(encoding="utf-8")), indent=2))
        return 0
    print("Visibility model: fitted on half the replays, scored on the other half\n")
    print(f"  provenance        {dict(split.provenance)}")
    print(f"  coverage          {split.coverage}")
    print(f"  compared pairs    {split.compared_pairs} (>= {criteria.HELD_OUT_MIN_OCCURRENCES} occurrences)")
    print(f"  outside +-{criteria.VISIBILITY_TOLERANCE}     {len(split.mismatches)} {split.mismatches[:3]}")
    print(f"  evidence written  {path.relative_to(REPO_ROOT)}")
    print(
        "\n  UNMEASURED: the telemetry-source clause. Every path here is a replay of a "
        "synthetic corpus through a simulated collector, so nothing here measures Linux "
        "sensor visibility. What would measure it: paired eBPF/auditd collection on a "
        "real host with ground-truth injected actions."
    )
    return 0


def _flood(*, as_json: bool) -> int:
    split = criteria.measure_visibility_split(criteria.corpus())
    flood = build_world_flood(count=criteria.FLOOD_COUNT, seed=criteria.FLOOD_SEED)
    sample, _runs = probes.flood_bounds(replay_corpus(flood), split.model)
    if as_json:
        print(json.dumps({**sample.to_dict(), "loadavg": list(loadavg())}, indent=2))
        return 0
    print(
        f"Adversarial branch flood: build_world_flood(count={criteria.FLOOD_COUNT}, "
        f"seed={criteria.FLOOD_SEED})\n"
    )
    for key, value in sample.to_dict().items():
        print(f"  {key:24} {value}")
    print(f"  {'loadavg':24} {loadavg()}")
    print(
        "\n  Bounds reached tells you whether this run exercised degradation AT the bound "
        "or only demonstrated the bound holding below it."
    )
    return 0


def _sensing(*, as_json: bool) -> int:
    ctx = Stage4GateContext.build()
    requested = 0
    reasons: dict[str, int] = {}
    for run in ctx.runs:
        plan = criteria.plan_for(
            run.field, model=ctx.visibility.model, observation=AdaptiveObservationPolicy()
        )
        requested += len(plan.requests)
        for _action, reason in plan.refused:
            key = reason.split(";")[0]
            reasons[key] = reasons.get(key, 0) + 1
    if as_json:
        print(json.dumps({"requested": requested, "refusals": reasons}, indent=2, sort_keys=True))
        return 0
    print("Discriminating-observation planner over the incident corpus\n")
    print(f"  requests issued  {requested} across {len(ctx.runs)} incidents")
    print("  refusals, by reason:")
    for reason, count in sorted(reasons.items(), key=lambda item: -item[1]):
        print(f"    {count:>5}  {reason}")
    print(
        "\n  A refusal naming a threshold is the planner deciding not to spend. A refusal "
        "naming a missing cost table or a missing observation policy is the wiring, and "
        "both were real defects found this session."
    )
    return 0


def _resources(*, as_json: bool) -> int:
    cases = criteria.corpus()
    split = criteria.measure_visibility_split(cases)
    replays = replay_corpus(cases)

    def work() -> int:
        runs, engine = criteria.drive_engine(
            replays, split.model, observation=AdaptiveObservationPolicy()
        )
        return sum(len(run.replay.result.transitions) for run in runs) or engine.work_units

    report = measure_stage4_resources(work, measured_by="pocketsec.stage4.cli:resources")
    if as_json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        return 0
    print("Stage 4 resource measurement (contended host; see docs/stage-4-spec.md §2.8)\n")
    for key, value in sorted(report.to_dict().items()):
        print(f"  {key:34} {value}")
    return 0


def _register(*, as_json: bool) -> int:
    """The ONLY writer to experiments/registry.jsonl, and only when asked.

    Stage 3's gate appended a row every time the test suite ran, which grew the permanent
    append-only record as a side effect of testing (spec §2.7). This subcommand exists so
    that registration is a decision an operator makes rather than a side effect.
    """
    from pocketsec.stage0.contracts.common import digest_of_bytes
    from pocketsec.stage0.experiments.registry import ExperimentRegistry
    from pocketsec.stage4.labs.incident_corpus import INCIDENT_CORPUS_VERSION
    from pocketsec.stage4.slot import CBF_SLOT_NAME

    report = run_gate()
    cases = criteria.corpus()
    registry = ExperimentRegistry(REPO_ROOT / "experiments" / "registry.jsonl")
    entry = registry.register(
        experiment_id=EXPERIMENT_ID,
        hypothesis=STAGE4_HYPOTHESIS,
        title="Stage 4 CBF+LUCID acceptance gate",
        slot_name=CBF_SLOT_NAME,
        dataset_name="stage4-incident-corpus",
        dataset_version=INCIDENT_CORPUS_VERSION,
        # The digest of the corpus this run actually scored, so a later reader can tell
        # whether a re-run saw the same cases (ADR-0127's provenance rule).
        dataset_sha256=digest_of_bytes(
            json.dumps([case.to_dict() for case in cases], sort_keys=True).encode("utf-8")
        ),
        git_commit=None,
        seeds={"corpus": criteria.CORPUS_SEED, "flood": criteria.FLOOD_SEED,
               "nonidentifiable": criteria.NONIDENT_SEED},
        synthetic_data=True,
        notes=(
            f"{len(report.checks) - len(report.failures)}/{len(report.checks)} criteria met; "
            f"failures {[check.id for check in report.failures]}"
        ),
    )
    if as_json:
        print(json.dumps({"registered": EXPERIMENT_ID, "entry": entry.to_dict()}, indent=2,
                         sort_keys=True, default=str))
        return 0
    print(f"registered {EXPERIMENT_ID} under hypothesis {STAGE4_HYPOTHESIS}")
    print(f"gate result: {'PASSED' if report.passed else f'FAILED ({len(report.failures)})'}")
    return 0 if report.passed else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
