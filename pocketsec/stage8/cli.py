"""``pocketsec-stage8`` — the Stage 8 operator entry point.

``gate``          run the twelve Stage 8 acceptance criteria; exits non-zero on any failure
``discover``      one PROMETHEUS -> ORACLE -> FORGE run on the PLANTED/NULL/DROPOUT arm
``tournament``    the FORGE tournaments of one PLANTED run, every entrant and the selection
``null``          the null-corpus false-discovery rate, disciplined vs NAIVE
``baselines``     Φ-oracle residual gain, random / exhaustive search, the direct model
``oracle``        ORACLE selection policies (EIG_PER_COST, EIG_ONLY, RANDOM, CHEAPEST)
``endurance``     Stage 1 -> 8 -> lab Stage 6 cycles with one long-lived research state
``resources``     the endpoint footprint of every shipped artifact under Stage 0's sampler
``catalogue``     the 128 S8X experiments and their honest statuses
``experiments``   ``--register`` is the ONLY writer to ``experiments/registry.jsonl``

Every corpus is synthetic and its planted truth shares an author with the engine, so nothing
printed here is a detection result; every detection gain is a ``counterfactual_at_boundary``
because Stage 6 adopts no Stage 8 discovery (B8-1). ``/proc/loadavg`` is printed beside every
timing: timings on this host are contended and only within-run ratios transfer. There is no
command that installs a detector or touches a response path: Stage 8 has neither.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from dataclasses import asdict, replace
from typing import Any

__all__ = ["main"]

_COMMANDS: tuple[tuple[str, str], ...] = (
    ("gate", "run the Stage 8 acceptance gate"),
    ("discover", "one discovery run (PLANTED by default)"),
    ("tournament", "the FORGE tournaments of one PLANTED run"),
    ("null", "the null-corpus false-discovery rate, disciplined vs NAIVE"),
    ("baselines", "Φ-oracle gain, random/exhaustive search at equal budget, direct model"),
    ("oracle", "ORACLE selection policies, lab oracle off and on"),
    ("endurance", "long-lived Stage 1 -> 8 -> lab Stage 6 cycles"),
    ("resources", "endpoint footprint of every shipped artifact"),
    ("catalogue", "list the 128 S8X experiments and catalogue problems"),
    ("experiments", "--register runs the gate and appends it to experiments/registry.jsonl"),
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pocketsec-stage8", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--seed", type=int, default=0, help="run seed (default 0)")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in _COMMANDS:
        command = sub.add_parser(name, help=help_text)
        if name == "discover":
            command.add_argument("--arm", choices=("PLANTED", "NULL", "DROPOUT"),
                                 default="PLANTED")
            command.add_argument("--lab-oracle", action="store_true",
                                 help="authorise the lab oracle (lab_oracle_authored)")
        if name == "null":
            command.add_argument("--seeds", type=int, default=None)
        if name == "endurance":
            command.add_argument("--cycles", type=int, default=12)
        if name == "experiments":
            command.add_argument("--register", action="store_true",
                                 help="run the gate and append it (and its ablation rows)")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    handlers: dict[str, Callable[[argparse.Namespace], int]] = {
        "gate": _gate, "discover": _discover, "tournament": _tournament, "null": _null,
        "baselines": _baselines, "oracle": _oracle, "endurance": _endurance,
        "resources": _resources, "catalogue": _catalogue, "experiments": _experiments,
    }
    return handlers[args.command](args)


def _loadavg() -> str:
    from pocketsec.stage6.resources import loadavg

    return " ".join(f"{value:.2f}" for value in loadavg())


def _emit(payload: Any) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))


def _corpus(arm: str = "PLANTED", seed: int = 0) -> Any:
    from pocketsec.stage8.labs.discovery_corpus import CorpusArm, build_discovery_corpus

    return build_discovery_corpus(arm=CorpusArm(arm), seed=seed)


def _gate(args: argparse.Namespace) -> int:
    from pocketsec.stage8.gate import Stage8GateContext, run_gate, summary

    ctx = Stage8GateContext.build()
    report = run_gate(ctx)
    extra = summary(ctx)
    if args.json:
        _emit({**report.to_dict(), "gate": "stage-8", **extra})
        return 0 if report.passed else 1
    print("PocketSec Stage 8 acceptance gate (synthetic discovery corpus, author-confounded; "
          "see docs/stage-8-spec.md §6.1)\n")
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


def _run_summary(report: Any) -> dict[str, Any]:
    return {
        "arm": report.config.arm.value, "seed": report.config.seed,
        "births": report.births, "challenged_out": report.challenged_out,
        "registered": report.registered, "survived": len(report.survived),
        "falsified": report.falsified, "reproduced": len(report.reproduced),
        "packages": len(report.packages), "planted_recovered": dict(report.planted_recovered),
        "false_reproduced": report.false_reproduced, "trap": asdict(report.trap),
        "firings": [asdict(f) for f in report.firings],
        "outcomes": [list(o) for o in report.outcomes],
        "work_units": report.governor.spent, "budget_exhausted": report.budget_exhausted,
        "precondition_problems": list(report.precondition_problems),
        "wall_seconds": round(report.wall_seconds, 3), "loadavg": list(report.loadavg),
        "synthetic_data": report.synthetic_data,
    }


def _discover(args: argparse.Namespace) -> int:
    from pocketsec.stage8.labs.discovery_corpus import CorpusArm
    from pocketsec.stage8.labs.discovery_run import RunConfig, run_discovery

    config = RunConfig(arm=CorpusArm(args.arm), seed=args.seed, use_lab_oracle=args.lab_oracle)
    _emit(_run_summary(run_discovery(_corpus(args.arm, args.seed), config)))
    return 0


def _tournament(args: argparse.Namespace) -> int:
    from pocketsec.stage8.labs.discovery_corpus import CorpusArm
    from pocketsec.stage8.labs.discovery_run import RunConfig, run_discovery

    report = run_discovery(_corpus(seed=args.seed), RunConfig(arm=CorpusArm.PLANTED,
                                                               seed=args.seed))
    _emit({"tournaments": [p.detector_candidates.to_dict() for p in report.packages],
           "loadavg": _loadavg()})
    return 0


def _null(args: argparse.Namespace) -> int:
    from pocketsec.stage8.labs.baselines import NULL_SEEDS, run_null_fdr

    seeds = tuple(range(args.seeds if args.seeds is not None else NULL_SEEDS))
    _emit({**asdict(run_null_fdr(seeds=seeds, content_seed=args.seed)), "loadavg": _loadavg()})
    return 0


def _baselines(args: argparse.Namespace) -> int:
    from pocketsec.stage8.labs import baselines
    from pocketsec.stage8.labs.discovery_corpus import CorpusArm
    from pocketsec.stage8.labs.discovery_run import RunConfig, run_discovery

    corpus = _corpus(seed=args.seed)
    phi = baselines.phi_oracle_baseline(corpus)
    report = run_discovery(corpus, RunConfig(arm=CorpusArm.PLANTED, seed=args.seed))
    phi_row = asdict(replace(phi, replication_episodes=()))
    _emit({"phi_oracle": phi_row, "residual_gain": asdict(baselines.residual_gain(report, phi)),
           "search": asdict(baselines.compare_search(corpus, seed=args.seed)),
           "direct_model": asdict(baselines.direct_model_baseline(corpus)),
           "loadavg": _loadavg()})
    return 0


def _oracle(args: argparse.Namespace) -> int:
    from pocketsec.stage8.labs.baselines import oracle_comparison

    _emit({**asdict(oracle_comparison(_corpus(seed=args.seed), seeds=(args.seed,))),
           "loadavg": _loadavg()})
    return 0


def _endurance(args: argparse.Namespace) -> int:
    from pocketsec.stage8.labs.discovery_run import run_endurance

    _emit({**asdict(run_endurance(cycles=args.cycles, seed=args.seed)), "loadavg": _loadavg()})
    return 0


def _resources(args: argparse.Namespace) -> int:
    from pocketsec.stage8.episode import Split
    from pocketsec.stage8.forge.tournament import measure_endpoint_footprint
    from pocketsec.stage8.labs.discovery_corpus import CorpusArm
    from pocketsec.stage8.labs.discovery_run import RunConfig, run_discovery

    corpus = _corpus(seed=args.seed)
    report = run_discovery(corpus, RunConfig(arm=CorpusArm.PLANTED, seed=args.seed))
    footprint = measure_endpoint_footprint(report.packages, corpus.episodes(Split.REPLICATION))
    _emit({**asdict(footprint), "loadavg": _loadavg()})
    return 0


def _catalogue(args: argparse.Namespace) -> int:
    from pocketsec.stage8.labs.eighty_experiments import CATALOGUE, catalogue_problems

    rows = [{"id": r.experiment_id, "status": r.status.value, "deliverable": r.deliverable,
             "title": r.title, "runner": r.runner, "reason": r.reason} for r in CATALOGUE]
    problems = list(catalogue_problems())
    if args.json:
        _emit({"experiments": rows, "problems": problems})
        return 0
    for row in rows:
        print(f"  {row['id']} {row['status']:<17} {row['deliverable']:<6} {row['title']}")
    print(f"\n  catalogue problems: {problems or 'none'}; loadavg {_loadavg()}")
    return 0


def _experiments(args: argparse.Namespace) -> int:
    if not args.register:
        print("Nothing was registered. `experiments --register` is the only ledger writer.")
        return 0
    return _register(args)


def _corpus_digest(corpus: Any) -> str:
    from pocketsec.stage0.contracts.common import digest_of_bytes

    ids = {split.value: sorted(e.episode_id for e in episodes)
           for split, episodes in corpus.splits.items()}
    return digest_of_bytes(json.dumps([corpus.version, corpus.seed, ids],
                                      sort_keys=True).encode("utf-8"))


def _register(args: argparse.Namespace) -> int:
    """The ONLY writer to experiments/registry.jsonl, and only when asked (spec §2.5)."""
    from datetime import UTC, datetime

    from pocketsec.stage0.experiments.ids import format_experiment_id
    from pocketsec.stage0.experiments.registry import ExperimentRegistry
    from pocketsec.stage8.gate import (
        ABLATION_HYPOTHESIS,
        EXPERIMENT_ID,
        REGISTRY_PATH,
        STAGE8_HYPOTHESIS,
        Stage8GateContext,
        run_gate,
    )

    ctx = Stage8GateContext.build()
    report = run_gate(ctx)
    corpus = ctx.planted
    registry = ExperimentRegistry(REGISTRY_PATH)
    common: dict[str, Any] = {
        "slot_name": "stage8-discovery-boundary", "dataset_name": "stage8-discovery-corpus",
        "dataset_version": None if corpus is None else corpus.version,
        "dataset_sha256": None if corpus is None else _corpus_digest(corpus),
        "git_commit": None, "seeds": {"gate": 0, "corpus": 0}, "synthetic_data": True}
    entries = [registry.register(
        experiment_id=EXPERIMENT_ID, hypothesis=STAGE8_HYPOTHESIS,
        title="Stage 8 PROMETHEUS+ORACLE+FORGE acceptance gate",
        notes=f"{len(report.checks) - len(report.failures)}/{len(report.checks)} criteria met; "
              f"failures {[c.id for c in report.failures]}", **common)]
    date = datetime.now(UTC).strftime("%Y%m%d")
    for index, row in enumerate(ctx.ablation, start=1):
        entries.append(registry.register(
            experiment_id=format_experiment_id(stage=8, hypothesis=ABLATION_HYPOTHESIS,
                                               slug=row.experiment_slug, sequence=index,
                                               date=date),
            hypothesis=ABLATION_HYPOTHESIS, title=f"Stage 8 ablation {row.core_id} ({row.flag})",
            notes=json.dumps(asdict(row), sort_keys=True, default=str), **common))
    print(f"registered {len(entries)} entries: {[e.experiment_id for e in entries]}")
    print(f"gate result: {'PASSED' if report.passed else f'FAILED ({len(report.failures)})'}")
    return 0 if report.passed else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
