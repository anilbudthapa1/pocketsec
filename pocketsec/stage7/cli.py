"""``pocketsec-stage7`` — the Stage 7 operator entry point.

``gate``          run the eleven Stage 7 acceptance criteria; exits non-zero on any failure
``suite``         the D7.9 Byzantine suite: every aggregator x arm x share, break points, ablation
``privacy``       membership / property inference (distilled vs raw control) and the DP curve
``campaign``      the distributed-campaign simulation against its common-cause arms
``partition``     offline equivalence, partition recovery, churn endurance and the scale run
``resources``     the FLOOD arm at 1000 simulated peers plus the scale run under Stage 0's sampler
``catalogue``     the 72 S7X experiments and their honest statuses; ``--run`` executes every runner
``experiments``   ``--register`` is the ONLY writer to ``experiments/registry.jsonl``

The fleet is simulated in-process and every corpus is synthetic, so nothing printed here is
a detection result; every detection gain is a ``counterfactual_at_boundary`` because Stage 6
admits no foreign capsule (B7-1). ``/proc/loadavg`` is printed beside every timing: timings on
this host are contended and only within-run ratios transfer. There is no command that
installs knowledge or touches a response path: Stage 7 has neither.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from dataclasses import asdict
from typing import Any

__all__ = ["main"]

_COMMANDS: tuple[tuple[str, str], ...] = (
    ("gate", "run the Stage 7 acceptance gate"),
    ("suite", "run the D7.9 Byzantine suite (all aggregators, arms and shares)"),
    ("privacy", "run the privacy attacks and the DP curve"),
    ("campaign", "run the distributed-campaign simulation"),
    ("partition", "run offline equivalence, partition recovery, churn and scale"),
    ("resources", "measure the FLOOD arm and the scale run under Stage 0's sampler"),
    ("catalogue", "list the 72 S7X experiments; --run executes every runner"),
    ("experiments", "--register runs the gate and appends it to experiments/registry.jsonl"),
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pocketsec-stage7", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--seed", type=int, default=0, help="simulation seed (default 0)")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in _COMMANDS:
        command = sub.add_parser(name, help=help_text)
        if name == "catalogue":
            command.add_argument("--run", action="store_true",
                                 help="execute every RUN row's runner (slow)")
        if name == "experiments":
            command.add_argument("--register", action="store_true",
                                 help="run the gate and append it (and its ablation rows)")
        if name == "partition":
            command.add_argument("--churn-rounds", type=int, default=None)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    handlers: dict[str, Callable[[argparse.Namespace], int]] = {
        "gate": _gate, "suite": _suite, "privacy": _privacy, "campaign": _campaign,
        "partition": _partition, "resources": _resources, "catalogue": _catalogue,
        "experiments": _experiments,
    }
    return handlers[args.command](args)


def _loadavg() -> str:
    from pocketsec.stage6.resources import loadavg

    return " ".join(f"{value:.2f}" for value in loadavg())


def _emit(payload: Any) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))


def _corpus() -> Any:
    from pocketsec.stage7.gate import CORPUS_SEED
    from pocketsec.stage7.labs.fleet_corpus import build_fleet_corpus

    return build_fleet_corpus(seed=CORPUS_SEED)


def _gate(args: argparse.Namespace) -> int:
    from pocketsec.stage7.gate import Stage7GateContext, run_gate, summary

    ctx = Stage7GateContext.build(seed=args.seed)
    report = run_gate(ctx)
    extra = summary(ctx)
    if args.json:
        _emit({**report.to_dict(), "gate": "stage-7", **extra})
        return 0 if report.passed else 1
    print("PocketSec Stage 7 acceptance gate (simulated fleet, synthetic corpus; "
          "see docs/stage-7-spec.md §6.1)\n")
    for check in report.checks:
        print(f"  [{'PASS' if check.passed else 'FAIL'}] {check.id}  {check.title}")
        print(f"         {check.detail}")
    if extra["errors"]:
        print("\n  build steps that raised (their checks FAIL with the reason):")
        for step, error in extra["errors"].items():
            print(f"    {step}: {error}")
    print("\n  timings (label, wall s, loadavg) — observations, never asserted:")
    for label, seconds, load in ctx.timings:
        print(f"    {label:<24} {seconds:>9.3f}  {load}")
    print(f"\nloadavg at end of run: {_loadavg()}")
    print(f"{len(report.checks) - len(report.failures)}/{len(report.checks)} criteria met")
    print("GATE: PASSED" if report.passed else f"GATE: FAILED ({len(report.failures)})")
    return 0 if report.passed else 1


def _suite(args: argparse.Namespace) -> int:
    from pocketsec.stage7.labs.byzantine_suite import run_byzantine_suite
    from pocketsec.stage7.labs.simulated_fleet import default_receivers

    corpus = _corpus()
    report = run_byzantine_suite(corpus, seed=args.seed, receivers=default_receivers(corpus))
    if args.json:
        _emit(asdict(report))
        return 0
    print("D7.9 Byzantine suite (counterfactual_at_boundary; synthetic; confounded)\n")
    for point in report.break_points:
        share = "none in sweep" if point.share is None else f"{point.share:.3f}"
        print(f"  break {point.arm:<24} {point.aggregator:<18} lv={point.lv!s:<5} {share}")
    for row in report.ablations:
        print(f"  ablation {row.core_id} {row.flag:<24} delta {row.delta} firing "
              f"{row.firing_count} {row.verdict}")
    for name, low, high in report.threshold_sensitivity:
        print(f"  sensitivity {name:<36} x0.5 {low:.3f}  x2 {high:.3f}")
    print(f"\n  loadavg {report.loadavg} (end: {_loadavg()})")
    return 0


def _privacy(args: argparse.Namespace) -> int:
    from pocketsec.stage7.labs import privacy_attacks as attacks

    corpus = _corpus()
    rows = [asdict(fn(corpus, representation=r, seed=args.seed))
            for fn in (attacks.membership_inference, attacks.property_inference)
            for r in attacks.REPRESENTATIONS]
    payload = {"attacks": rows, "dp_curve": attacks.dp_curve(corpus, seed=args.seed),
               "seeded_rng_is_not_private": True}
    if args.json:
        _emit(payload)
        return 0
    for row in rows:
        print(f"  {row['attack']:<22} {row['representation']:<18} advantage {row['advantage']} "
              f"chance {row['chance']} trials {row['trials']}")
    for epsilon, recall, advantage in payload["dp_curve"]:
        print(f"  dp epsilon {epsilon} novelty recall {recall} count-membership {advantage}")
    return 0


def _campaign(args: argparse.Namespace) -> int:
    from pocketsec.stage7.labs.campaign_sim import build_campaign_cases, run_campaign_sim

    report = run_campaign_sim(build_campaign_cases(seed=args.seed))
    if args.json:
        _emit(asdict(report))
        return 0
    for key, value in asdict(report).items():
        print(f"  {key:<28} {value}")
    return 0


def _partition(args: argparse.Namespace) -> int:
    from pocketsec.stage7.labs import partition
    from pocketsec.stage7.labs.simulated_fleet import default_receivers

    corpus = _corpus()
    churn = {} if args.churn_rounds is None else {"rounds": args.churn_rounds}
    payload = {
        "offline": [asdict(partition.run_offline_equivalence(corpus, receiver=h))
                    for h in default_receivers(corpus)],
        "recovery": asdict(partition.run_partition_recovery(corpus, seed=args.seed)),
        "churn": asdict(partition.run_churn_endurance(corpus, seed=args.seed, **churn)),
        "scale": [asdict(r) for r in partition.run_scale(seed=args.seed, corpus=corpus)],
        "loadavg": _loadavg(),
    }
    _emit(payload)
    return 0


def _resources(args: argparse.Namespace) -> int:
    from pocketsec.stage7.gate_evidence import flood_evidence
    from pocketsec.stage7.labs.partition import run_scale
    from pocketsec.stage7.labs.simulated_fleet import default_receivers

    corpus = _corpus()
    evidence = flood_evidence(corpus, default_receivers(corpus)[0], seed=args.seed,
                              scale=lambda: run_scale(seed=args.seed, corpus=corpus))
    _emit(asdict(evidence))
    return 0


def _catalogue(args: argparse.Namespace) -> int:
    from pocketsec.stage7.labs.seventy_two_experiments import (
        S7_EXPERIMENTS,
        ExperimentStatus,
        catalogue_problems,
    )

    results: dict[str, Any] = {}
    if args.run:  # every distinct runner, once: this is how each RUN row is exercised
        import importlib

        corpus = _corpus()
        for runner in sorted({e.runner for e in S7_EXPERIMENTS
                              if e.status is ExperimentStatus.RUN and e.runner}):
            module, _, name = runner.partition(":")
            results[runner] = getattr(importlib.import_module(module), name)(corpus,
                                                                             seed=args.seed)
    rows = [{"sid": e.sid, "status": e.status.value, "title": e.title, "runner": e.runner,
             "note": e.note} for e in S7_EXPERIMENTS]
    if args.json:
        _emit({"experiments": rows, "problems": list(catalogue_problems()), "results": results})
        return 0
    for row in rows:
        print(f"  {row['sid']} {row['status']:<24} {row['title']}")
    for runner, result in results.items():
        print(f"\n  {runner}\n    {json.dumps(result, default=str)[:2000]}")
    print(f"\n  catalogue problems: {list(catalogue_problems()) or 'none'}; loadavg {_loadavg()}")
    return 0


def _experiments(args: argparse.Namespace) -> int:
    if not args.register:
        print("Nothing was registered. `experiments --register` is the only ledger writer.")
        return 0
    return _register(args)


def _register(args: argparse.Namespace) -> int:
    """The ONLY writer to experiments/registry.jsonl, and only when asked (spec §2.5)."""
    from datetime import UTC, datetime

    from pocketsec.stage0.contracts.common import digest_of_bytes
    from pocketsec.stage0.experiments.ids import format_experiment_id
    from pocketsec.stage0.experiments.registry import ExperimentRegistry
    from pocketsec.stage7.gate import (
        ABLATION_HYPOTHESIS,
        EXPERIMENT_ID,
        REGISTRY_PATH,
        STAGE7_HYPOTHESIS,
        Stage7GateContext,
        run_gate,
    )

    ctx = Stage7GateContext.build(seed=args.seed)
    report = run_gate(ctx)
    registry = ExperimentRegistry(REGISTRY_PATH)
    corpus = digest_of_bytes(json.dumps([ctx.corpus.version, ctx.corpus.seed,
                                         sorted(ctx.corpus.raw_digests)]).encode("utf-8"))
    common: dict[str, Any] = {
        "slot_name": "stage7-collective-boundary", "dataset_name": "stage7-fleet-corpus",
        "dataset_version": ctx.corpus.version, "dataset_sha256": corpus, "git_commit": None,
        "seeds": {"gate": args.seed, "corpus": ctx.corpus.seed}, "synthetic_data": True}
    entries = [registry.register(
        experiment_id=EXPERIMENT_ID, hypothesis=STAGE7_HYPOTHESIS,
        title="Stage 7 ORPHEUS+HIVELOCK acceptance gate",
        notes=f"{len(report.checks) - len(report.failures)}/{len(report.checks)} criteria met; "
              f"failures {[c.id for c in report.failures]}", **common)]
    date = datetime.now(UTC).strftime("%Y%m%d")
    for index, row in enumerate(ctx.suite.ablations if ctx.suite else (), start=1):
        entries.append(registry.register(
            experiment_id=format_experiment_id(stage=7, hypothesis=ABLATION_HYPOTHESIS,
                                               slug="ablation", sequence=index, date=date),
            hypothesis=ABLATION_HYPOTHESIS, title=f"Stage 7 ablation {row.core_id} ({row.flag})",
            notes=json.dumps(asdict(row), sort_keys=True), **common))
    print(f"registered {len(entries)} entries: {[e.experiment_id for e in entries]}")
    print(f"gate result: {'PASSED' if report.passed else f'FAILED ({len(report.failures)})'}")
    return 0 if report.passed else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
