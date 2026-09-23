"""``pocketsec-stage1`` — the Stage 1 operator entry point.

``gate``          run the thirteen Stage 1 acceptance criteria
``adversarial``   run the eight adversarial representation tests
``guillotine``    print the measured representation Pareto frontier
``calibrate``     print the Φ calibration report
``replay``        replay the corpus and print pipeline statistics
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from pocketsec.stage1.gate import Stage1GateContext, run_gate
from pocketsec.stage1.guillotine.ablation import run_guillotine
from pocketsec.stage1.labs.adversarial import run_adversarial_suite
from pocketsec.stage1.state.potential import calibrate

__all__ = ["main"]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pocketsec-stage1", description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("gate", "run the Stage 1 acceptance gate"),
        ("adversarial", "run the adversarial representation suite"),
        ("guillotine", "print the representation Pareto frontier"),
        ("calibrate", "print the Φ calibration report"),
        ("replay", "replay the corpus and print pipeline statistics"),
    ):
        sub.add_parser(name, help=help_text)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    handlers = {
        "gate": _gate,
        "adversarial": _adversarial,
        "guillotine": _guillotine,
        "calibrate": _calibrate,
        "replay": _replay,
    }
    return handlers[args.command](as_json=args.json)


def _gate(*, as_json: bool) -> int:
    report = run_gate()
    if as_json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print("PocketSec Stage 1 acceptance gate\n")
        for check in report.checks:
            print(f"  [{'PASS' if check.passed else 'FAIL'}] {check.id}  {check.title}")
            print(f"         {check.detail}")
        print()
        print("GATE: PASSED" if report.passed else f"GATE: FAILED ({len(report.failures)})")
    return 0 if report.passed else 1


def _adversarial(*, as_json: bool) -> int:
    report = run_adversarial_suite()
    if as_json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print("Adversarial representation tests\n")
        for outcome in report.outcomes:
            print(f"  [{'PASS' if outcome.passed else 'FAIL'}] {outcome.name}")
            print(f"         {outcome.measurement}")
            print(f"         {outcome.detail}")
        print()
        print("SUITE: PASSED" if report.passed else f"SUITE: FAILED ({len(report.failures)})")
    return 0 if report.passed else 1


def _guillotine(*, as_json: bool) -> int:
    report = run_guillotine(Stage1GateContext.build().results)
    if as_json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        return 0
    print("Information Guillotine — measured representation frontier")
    print("(synthetic corpus; demonstrates the method, not a detection result)\n")
    print(f"  {'cut':<22} {'bytes':>6} {'PR-AUC':>8} {'recall@FP':>10}")
    for point in report.points:
        pr = "n/a" if point.pr_auc is None else f"{point.pr_auc:.4f}"
        rc = (
            "n/a"
            if point.recall_at_fpr_budget is None
            else f"{point.recall_at_fpr_budget:.4f}"
        )
        print(f"  {point.label:<22} {point.bytes_per_transition:>6.0f} {pr:>8} {rc:>10}")
    if report.knee:
        print(
            f"\n  knee: {report.knee.label} at {report.knee.bytes_per_transition:.0f} "
            f"bytes/transition, PR-AUC {report.knee.pr_auc}"
        )
    print(f"\n  {report.caveat}")
    return 0


def _calibrate(*, as_json: bool) -> int:
    ctx = Stage1GateContext.build()
    report = calibrate([(r.final_state, r.scenario.label) for r in ctx.results if r.transitions])
    if as_json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        return 0
    print("Φ calibration report (synthetic corpus)\n")
    for key, value in report.to_dict().items():
        print(f"  {key:<24} {value}")
    return 0


def _replay(*, as_json: bool) -> int:
    ctx = Stage1GateContext.build()
    payload = {
        "transitions": ctx.transitions,
        "scenarios": len(ctx.results),
        "peak_rss_bytes": ctx.peak_rss_bytes,
        "cpu_seconds": ctx.cpu_seconds,
        "pipeline": ctx.pipeline.report(),
    }
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    print(f"scenarios          {payload['scenarios']}")
    print(f"transitions        {payload['transitions']}")
    print(f"peak RSS           {payload['peak_rss_bytes']}")
    print(f"cpu seconds        {payload['cpu_seconds']:.4f}")
    report = ctx.pipeline.report()
    print(f"compiler           {report['compiler']}")
    print(f"novelty memory     {report['novelty_memory_bytes']} B")
    print(f"aggregation        {report['aggregation']}")
    print(f"observation        {report['observation']}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
