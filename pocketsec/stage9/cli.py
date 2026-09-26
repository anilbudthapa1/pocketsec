"""``pocketsec-stage9`` — the Stage 9 operator entry point.

``gate``            run the ten Stage 9 acceptance criteria (``--save PATH`` keeps the report)
``expressibility``  can the genome language express the Φ-oracle and the Stage 2 scorers?
``boundary``        print every AST boundary predicate of G9.7 and G9.10(a)
``catalogue``       the 124-row S9X experiment programme: status counts, unresolvable runners
``search``          one search arm on the train split (``--strategy``, ``--seed``, ``--budget``)
``manifest``        build and verify the Stage 1-9 reproducibility manifest (no recompilation)
``register``        append a SAVED gate report to experiments/registry.jsonl (the ONLY writer)

Everything here is research on synthetic, project-authored corpora, so nothing printed is a
detection result. Work units are the primary cost; every wall-clock figure is host-contended
and printed beside ``/proc/loadavg``. There is no command that installs a genome or touches a
response path: Stage 9 has neither (ADR-0081).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any

__all__ = ["main"]

_COMMANDS: tuple[tuple[str, str], ...] = (
    ("gate", "run the Stage 9 acceptance gate"),
    ("expressibility", "check the genome language expresses the incumbents (count 60)"),
    ("boundary", "print the AST boundary predicates"),
    ("catalogue", "summarise the S9X experiment programme"),
    ("search", "run one search arm on the train split"),
    ("manifest", "build and verify the reproducibility manifest"),
    ("register", "register a saved gate report in experiments/registry.jsonl"),
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pocketsec-stage9",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in _COMMANDS:
        command = sub.add_parser(name, help=help_text)
        if name == "gate":
            command.add_argument(
                "--save",
                type=Path,
                default=None,
                help="also write the report JSON here (for `register`)",
            )
        if name == "search":
            command.add_argument(
                "--strategy", default="EXHAUSTIVE", choices=("EVOLUTIONARY", "RANDOM", "EXHAUSTIVE")
            )
            command.add_argument("--seed", type=int, default=101)
            command.add_argument("--budget", type=int, default=None)
        if name == "register":
            command.add_argument(
                "--report", type=Path, required=True, help="a report written by `gate --save`"
            )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    handlers: dict[str, Callable[[argparse.Namespace], int]] = {
        "gate": _gate,
        "expressibility": _expressibility,
        "boundary": _boundary,
        "catalogue": _catalogue,
        "search": _search,
        "manifest": _manifest,
        "register": _register,
    }
    return handlers[args.command](args)


def _loadavg() -> str:
    from pocketsec.stage6.resources import loadavg

    return " ".join(f"{value:.2f}" for value in loadavg())


def _emit(payload: Any) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))


def _gate(args: argparse.Namespace) -> int:
    from pocketsec.stage9.gate import build_context, report_for, summary

    print(f"loadavg before: {_loadavg()}", file=sys.stderr)
    ctx = build_context()
    report = report_for(ctx)
    payload = {**report.to_dict(), "gate": "stage-9", "summary": summary(ctx)}
    if args.save is not None:
        args.save.parent.mkdir(parents=True, exist_ok=True)
        args.save.write_text(
            json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
        )
    if args.json:
        _emit(payload)
        return 0 if report.passed else 1
    print("PocketSec Stage 9 acceptance gate (ONTOGENESIS)\n")
    for check in report.checks:
        print(f"  [{'PASS' if check.passed else 'FAIL'}] {check.id}  {check.title}")
        print(f"         {check.detail}")
    print("\nSteps (wall clock is host-contended; loadavg before -> after):")
    for row in payload["summary"]["steps"]:
        print(
            f"  {row['step']:<15} {row['seconds']:>9.2f} s  {row['loadavg_before']} -> "
            f"{row['loadavg_after']}"
        )
    for step, error in payload["summary"]["errors"].items():
        print(f"  ERROR {step}: {error}")
    _print_evidence(payload["summary"]["evidence"])
    print()
    print("GATE: PASSED" if report.passed else f"GATE: FAILED ({len(report.failures)})")
    return 0 if report.passed else 1


def _print_evidence(evidence: dict[str, Any]) -> None:
    """The search table and the null control: the figures the verdicts rest on."""
    print("\nSearch runs (train only; WU are the primary cost):")
    for runs in evidence["runs"].values():
        for r in runs:
            ap = r["winner_train_worst_case_ap"]
            print(
                f"  {r['run']:<34} {r['evaluations']:>4} evals {r['wu_spent']:>10} WU "
                f"{r['stop_reason']:<21} winner "
                f"{(r['winner_digest'] or 'NONE')[:19]:<19} train worst "
                f"{'None' if ap is None else f'{ap:.4f}'} phi-rediscovered "
                f"{r['rediscovered_phi']}"
            )
    for report in evidence["winner_reports"]:
        if report["genome_digest"]:
            print(
                f"  held-out {report['run']:<25} worst {report['heldout_worst_case_ap']:.4f}"
                f" clean {report['heldout_clean_ap']:.4f} gap {report['gap']:+.4f}"
            )
    control = evidence["shuffled_label_control"]
    if control is not None:
        print(
            f"\nShuffled-label control: {control['verdict']}, permutation p "
            f"{control['permutation_p_value']}, prior percentile {control['prior_percentile']}"
            f", held-out AP {control['heldout_ap']}"
        )


def _expressibility(args: argparse.Namespace) -> int:
    from pocketsec.stage9.genome.expressibility import check_expressibility
    from pocketsec.stage9.labs.splits import HELDOUT_SEED, SATURATED_COUNT, compile_variant

    variant = compile_variant(count=SATURATED_COUNT, seed=HELDOUT_SEED, keep_results=True)
    sessions = tuple(r.transitions for r in variant.results if r.transitions)
    rows = check_expressibility(variant.dataset, sessions=sessions)
    if args.json:
        _emit([asdict(row) for row in rows])
        return 0
    headline = [r for r in rows if not r.target.startswith("deterministic-scorer/")]
    scorers = [r for r in rows if r.target.startswith("deterministic-scorer/")]
    print(f"Expressibility on ambiguous count {SATURATED_COUNT} seed {HELDOUT_SEED}\n")
    for row in headline:
        print(
            f"  {row.target:<24} expressible={row.expressible} exact={row.exact} "
            f"rank_identical={row.rank_identical} max_err={row.max_abs_error}"
        )
        if row.reason:
            print(f"      {row.reason}")
    exact = sum(1 for r in scorers if r.exact)
    print(
        f"\n  deterministic scorers: {exact}/{len(scorers)} exact (window partition may differ;"
        " reported, not hidden)"
    )
    return 0


def _boundary(args: argparse.Namespace) -> int:
    from pocketsec.stage9.gate_criteria import bucket_readers
    from pocketsec.stage9.successor import boundary

    results = {
        name: getattr(boundary, name)()
        for name in (
            "direct_stage5_imports",
            "transitive_stage5_reach",
            "admit_call_sites",
            "admit_call_files",
            "stage6_writer_names",
            "stage6_allow_list_offenders",
            "authority_field_offenders",
            "dynamic_execution_offenders",
            "numpy_or_research_offenders",
            "earlier_stage_importers",
            "outside_importers_of_stage9",
        )
    }
    results["bucket_readers"] = bucket_readers()
    if args.json:
        _emit(results)
    else:
        for name, found in results.items():
            print(f"  {name:<32} {list(found) or 'none'}")
    clean = all(not v for k, v in results.items() if k != "admit_call_files")
    return 0 if clean else 1


def _catalogue(args: argparse.Namespace) -> int:
    from pocketsec.stage9.labs.one_twenty_experiments import (
        S9_EXPERIMENTS,
        resolve_runners,
        status_counts,
    )

    payload = {
        "rows": len(S9_EXPERIMENTS),
        "status": dict(status_counts()),
        "unresolvable_runners": list(resolve_runners()),
    }
    if args.json:
        _emit(payload)
    else:
        print(f"S9X programme: {payload['rows']} rows; {payload['status']}")
        print(f"unresolvable runners: {payload['unresolvable_runners'] or 'none'}")
    return 0 if not payload["unresolvable_runners"] else 1


def _search(args: argparse.Namespace) -> int:
    from pocketsec.stage9.argus.adversary import SCENARIO_ATTACKS
    from pocketsec.stage9.labs.splits import CLEAN, HEADROOM_COUNT, TRAIN_SEED, compile_variants
    from pocketsec.stage9.ontogenesis.fitness import EvaluationSuite
    from pocketsec.stage9.ontogenesis.search import (
        SEARCH_BUDGET_WU,
        SearchConfig,
        SearchStrategy,
        run_search,
    )

    ids = (CLEAN, *(a.attack_id for a in SCENARIO_ATTACKS))
    variants = compile_variants(count=HEADROOM_COUNT, seed=TRAIN_SEED, attack_ids=ids)
    train = EvaluationSuite(name="train", clean=variants[0], attacked=tuple(variants[1:]))
    config = SearchConfig(
        strategy=SearchStrategy(args.strategy),
        seed=args.seed,
        budget_wu=args.budget or SEARCH_BUDGET_WU,
    )
    run = run_search(config, train)
    winner = None if run.winner is None else run.records[run.winner].to_dict()
    payload = {
        "run": run.config.label,
        "evaluations": run.evaluations,
        "wu_spent": run.wu_spent,
        "stop_reason": run.stop_reason,
        "rediscovered_phi": run.rediscovered_phi,
        "winner_train_record": winner,
        "determinism_digest": run.determinism_digest,
        "wall_seconds_host_contended": round(run.wall_seconds, 2),
        "loadavg_before": run.loadavg_before,
        "loadavg_after": run.loadavg_after,
    }
    _emit(payload)
    return 0


def _manifest(args: argparse.Namespace) -> int:
    from pocketsec.stage0.repro.seeds import SeedSet
    from pocketsec.stage9.harness.reproducibility import build_manifest, verify_manifest

    manifest = build_manifest(
        seeds=SeedSet(master=20_260_926), split_digests={}, genome_digests=(), experiment_ids=()
    )
    problems = verify_manifest(manifest)
    _emit({"manifest": manifest.to_dict(), "problems": list(problems)})
    return 0 if not problems else 1


def _register(args: argparse.Namespace) -> int:
    """The ONLY writer to experiments/registry.jsonl, and only when asked (spec §2.5)."""
    from pocketsec.stage0.contracts.common import digest_of_bytes
    from pocketsec.stage0.experiments.registry import ExperimentRegistry
    from pocketsec.stage9.gate import EXPERIMENT_ID, REGISTRY_PATH, STAGE9_HYPOTHESIS
    from pocketsec.stage9.labs.splits import SPLITS_VERSION

    raw = args.report.read_bytes()
    report = json.loads(raw)
    if report.get("gate") != "stage-9" or report["summary"]["experiment_id"] != EXPERIMENT_ID:
        print(f"{args.report} is not a Stage 9 gate report for {EXPERIMENT_ID}")
        return 2
    if not report["summary"]["full_config"]:
        print("refused: a reduced (test) configuration is never the gate's verdict")
        return 2
    failures = [c["id"] for c in report["checks"] if not c["passed"]]
    entry = ExperimentRegistry(REGISTRY_PATH).register(
        experiment_id=EXPERIMENT_ID,
        hypothesis=STAGE9_HYPOTHESIS,
        title="Stage 9 ONTOGENESIS acceptance gate",
        slot_name="stage9-ontogenesis-search",
        dataset_name="ambiguous",
        dataset_version=SPLITS_VERSION,
        dataset_sha256=digest_of_bytes(
            json.dumps(report["summary"]["splits"], sort_keys=True).encode("utf-8")
        ),
        git_commit=None,
        seeds={"train": 3, "heldout": 11},
        synthetic_data=True,
        notes=f"{len(report['checks']) - len(failures)}/{len(report['checks'])} criteria met; "
        f"failures {failures}; report digest {digest_of_bytes(raw)}",
        result_path=str(args.report),
    )
    print(f"registered {entry.experiment_id}; gate {'PASSED' if not failures else 'FAILED'}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
