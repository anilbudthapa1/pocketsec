"""``pocketsec-stage0`` — the Stage 0 operator entry point.

Subcommands:

``gate``           run the Stage 0 acceptance gate (exit 1 on any failure)
``smoke``          run the H0 baseline through the harness and print the result
``experiment-id``  mint a well-formed immutable experiment id
``env``            print the reproducibility fingerprint for this machine
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from pocketsec.stage0.experiments.ids import format_experiment_id
from pocketsec.stage0.gate import run_gate
from pocketsec.stage0.repro.environment import EnvironmentFingerprint
from pocketsec.stage0.repro.seeds import SeedSet
from pocketsec.stage0.smoke import run_smoke_benchmark

__all__ = ["main"]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pocketsec-stage0", description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("gate", help="run the Stage 0 acceptance gate")
    sub.add_parser("smoke", help="run the H0 baseline through the benchmark harness")
    sub.add_parser("env", help="print the reproducibility environment fingerprint")

    ident = sub.add_parser("experiment-id", help="mint an immutable experiment id")
    ident.add_argument("--stage", type=int, required=True)
    ident.add_argument("--hypothesis", required=True, help="e.g. H0 or BASE")
    ident.add_argument("--slug", required=True, help="lowercase-kebab-case")
    ident.add_argument("--sequence", type=int, required=True)
    ident.add_argument("--date", default=None, help="YYYYMMDD (default: today, UTC)")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "gate":
        return _run_gate(as_json=args.json)
    if args.command == "smoke":
        return _run_smoke(as_json=args.json)
    if args.command == "env":
        fingerprint = EnvironmentFingerprint.capture(seeds=SeedSet.from_env())
        print(json.dumps(fingerprint.to_dict(), indent=2, sort_keys=True))
        return 0
    if args.command == "experiment-id":
        print(
            format_experiment_id(
                stage=args.stage,
                hypothesis=args.hypothesis,
                slug=args.slug,
                sequence=args.sequence,
                date=args.date,
            )
        )
        return 0
    return 2  # pragma: no cover - argparse enforces the choices


def _run_gate(*, as_json: bool) -> int:
    report = run_gate()
    if as_json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print("PocketSec Stage 0 acceptance gate\n")
        for check in report.checks:
            mark = "PASS" if check.passed else "FAIL"
            print(f"  [{mark}] {check.id}  {check.title}")
            print(f"         {check.detail}")
        print()
        print("GATE: PASSED" if report.passed else f"GATE: FAILED ({len(report.failures)})")
    return 0 if report.passed else 1


def _run_smoke(*, as_json: bool) -> int:
    result = run_smoke_benchmark()
    if as_json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return 0

    security, novelty, resources = result.security, result.novelty, result.resources
    print(f"experiment          {result.experiment_id}")
    print(f"slot                {result.slot_name} ({result.model_state_version})")
    print(f"dataset             {result.dataset['name']} @ {result.dataset['version']}")
    print(f"synthetic data      {result.synthetic_data}  (NOT a real-world result)")
    print(f"calibrated          {result.calibrated}")
    print(f"samples/positives   {security.sample_count} / {security.positive_count}")
    print(f"PR-AUC              {security.pr_auc}")
    print(f"recall @ FPR {security.fpr_budget}   {security.recall_at_fpr_budget}")
    print(f"FP per host-day     {security.false_positives_per_host_day}")
    print(f"abstention rate     {security.abstention_rate:.3f}")
    print(f"unseen-technique    {security.unseen_technique_recall}")
    print(f"resolved w/o infer  {novelty.resolved_without_inference:.3f}")
    print(f"compute paths       {novelty.path_counts}")
    print(f"peak RSS (sampled)  {resources.peak_sampled_rss_bytes}")
    print(f"cpu s / event       {resources.cpu_seconds_per_event}")
    print(f"profile             {result.profile_report.to_dict()}")
    for caveat in result.environment.caveats:
        print(f"caveat              {caveat}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
