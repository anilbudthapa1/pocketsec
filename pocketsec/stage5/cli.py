"""``pocketsec-stage5`` — the Stage 5 operator entry point.

``gate``          run the fifteen Stage 5 acceptance criteria; exits non-zero on any failure
``baselines``     the nine §7 baselines plus the full planner, one corpus, one process
``ablation``      one measured row per OPTIONAL core id (never written to the real ledger)
``toctou``        the four target-substitution races against the real executor
``sentinel``      the 14 x 13 SENTINEL denial matrix
``resources``     §43's resource rows under Stage 0's sampler
``assurance``     the executor property table and its in-process mutation run
``experiments``   the fifty §41 experiments: which are runnable, which blocked and why

Every figure printed here comes from ``SimulatedHost``, a host model this wave wrote, and
is a property of that simulator. Rollback reliability against a real Linux host is
UNMEASURED. ``/proc/loadavg`` is printed beside every comparison, because timings on this
host are contended and only within-run ratios transfer.

There is no ``execute`` subcommand and there will not be one while the only host is
simulated: an operator-facing command that acts would be the natural-language-to-privilege
path this stage exists to close, and it would have nothing real to act on.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence

__all__ = ["main"]

_COMMANDS: tuple[tuple[str, str], ...] = (
    ("gate", "run the Stage 5 acceptance gate"),
    ("baselines", "run the nine baselines and the full planner on the shared corpus"),
    ("ablation", "measure one ablation row per OPTIONAL core id"),
    ("toctou", "run the four TOCTOU / PID-reuse races"),
    ("sentinel", "run the 14 x 13 SENTINEL denial matrix"),
    ("resources", "measure the Stage 5 resource rows"),
    ("assurance", "print the executor property table and run its mutations"),
    ("experiments", "list the fifty experiments and their dispositions"),
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pocketsec-stage5", description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in _COMMANDS:
        sub.add_parser(name, help=help_text)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    handlers: dict[str, Callable[..., int]] = {
        "gate": _gate,
        "baselines": _baselines,
        "ablation": _ablation,
        "toctou": _toctou,
        "sentinel": _sentinel,
        "resources": _resources,
        "assurance": _assurance,
        "experiments": _experiments,
    }
    return handlers[args.command](as_json=args.json)


def _loadavg() -> str:
    from pocketsec.stage5.resources import loadavg

    return " ".join(f"{value:.2f}" for value in loadavg())


def _gate(*, as_json: bool) -> int:
    from pocketsec.stage5.gate import run_gate

    report = run_gate()
    if as_json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print("PocketSec Stage 5 acceptance gate (simulated host; see ADR-0046)\n")
        for check in report.checks:
            print(f"  [{'PASS' if check.passed else 'FAIL'}] {check.id}  {check.title}")
            print(f"         {check.detail}")
        print()
        print(f"loadavg at end of run: {_loadavg()}")
        print("GATE: PASSED" if report.passed else f"GATE: FAILED ({len(report.failures)})")
    return 0 if report.passed else 1


def _baselines(*, as_json: bool) -> int:
    from pocketsec.stage5.gate import Stage5GateContext
    from pocketsec.stage5.labs.baselines import pareto_frontier_of
    from pocketsec.stage5.labs.fifty_experiments import saturation_check

    ctx = Stage5GateContext.build()
    degenerate, reason = saturation_check(ctx.outcomes)
    frontier = pareto_frontier_of(ctx.outcomes)
    if as_json:
        print(json.dumps({
            "outcomes": {arm: row.to_dict() for arm, row in ctx.outcomes.items()},
            "frontier": list(frontier), "degenerate": degenerate, "saturation": reason,
            "corpus_sha256": ctx.corpus_sha256, "loadavg": list(ctx.loadavg_at_build),
        }, indent=2, sort_keys=True))
        return 0
    print(f"Baselines on build_response_corpus(count=20, seed=11), corpus {ctx.corpus_sha256}")
    print("(simulated host; collateral is defined by harm tables authored with the planner)\n")
    print(f"  {'arm':<7}{'contained':>10}{'missed':>8}{'actions':>9}{'collat/1000':>13}"
          f"{'work units':>12}{'escalations':>13}{'denials':>9}")
    for arm, row in sorted(ctx.outcomes.items()):
        rate = row.collateral_per_1000()
        print(f"  {arm:<7}{row.incidents_contained:>10}{row.incidents_missed:>8}"
              f"{row.actions_taken:>9}{'None' if rate is None else f'{rate:.1f}':>13}"
              f"{row.work_units:>12}{row.human_escalations:>13}{row.sentinel_denials:>9}")
    print(f"\n  Pareto frontier: {list(frontier)}\n  saturation: {reason}")
    print(f"  loadavg {_loadavg()}")
    return 0


def _ablation(*, as_json: bool) -> int:
    from pocketsec.stage5.gate import Stage5GateContext
    from pocketsec.stage5.gate_measured import ablation_rows

    rows = ablation_rows(Stage5GateContext.build())
    if as_json:
        print(json.dumps({core: row.to_dict() for core, row in rows.items()}, indent=2,
                         sort_keys=True))
        return 0
    print("Ablation rows (full planner, one flag off; collateral_per_1000 at equal containment)\n")
    for core, row in sorted(rows.items()):
        print(f"  {core}  {row.flag:<30} with {row.with_value} ({row.with_contained}c)  "
              f"without {row.without_value} ({row.without_contained}c)  delta {row.delta}  "
              f"{row.verdict.value}")
    print(f"\n  loadavg {_loadavg()}")
    return 0


def _toctou(*, as_json: bool) -> int:
    from pocketsec.stage5.gate import executor_for_race
    from pocketsec.stage5.labs.toctou import toctou_suite

    races = toctou_suite(build_executor=executor_for_race)
    if as_json:
        print(json.dumps([race.to_dict() for race in races], indent=2, sort_keys=True))
    else:
        for race in races:
            print(f"  [{'REFUSED' if race.refused else 'ACTED'}] {race.variant:<20} "
                  f"{race.outcome.value:<18} apply calls {race.apply_calls}  substitute "
                  f"untouched {race.substitute_untouched}")
    return 0 if all(race.refused and race.apply_calls == 0 for race in races) else 1


def _sentinel(*, as_json: bool) -> int:
    from pocketsec.stage5.gate_construction import sentinel_matrix_denials

    passes, denials, cases, failures = sentinel_matrix_denials()
    payload = {"compliant_passes": passes, "denials": denials, "cases": cases,
               "failures": failures}
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"SENTINEL matrix: {denials} of {cases} required denials; compliant baselines "
              f"passing {passes}; failures {failures}")
    return 0 if denials == cases and not failures else 1


def _resources(*, as_json: bool) -> int:
    from pocketsec.stage5.gate import Stage5GateContext, executor_for_rig
    from pocketsec.stage5.resources import measure_stage5_resources

    report = measure_stage5_resources(Stage5GateContext.build().corpus,
                                      build_executor=executor_for_rig)
    if as_json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        return 0
    print("Stage 5 resources (Stage 0 ResourceSampler; process-wide peak is an upper bound)\n")
    for name, value in sorted(report.component_bytes.items()):
        print(f"  {name:<32} {'UNMEASURED' if value is None else f'{value} B'}")
    print(f"\n  incremental RSS {report.incremental_rss_bytes} B, peak {report.peak_rss_bytes} B, "
          f"within_target {report.within_target}\n  {report.detail}\n  loadavg {report.loadavg}")
    return 0


def _assurance(*, as_json: bool) -> int:
    from pocketsec.stage5.assurance import properties as assurance
    from pocketsec.stage5.gate_measured import check_assurance_table

    check = check_assurance_table()
    if as_json:
        print(json.dumps({"counts": dict(assurance.counts()), "check": check.to_dict(),
                          "properties": [row.to_dict() for row in assurance.EXECUTOR_PROPERTIES]},
                         indent=2, sort_keys=True))
        return 0 if check.passed else 1
    for row in assurance.EXECUTOR_PROPERTIES:
        evidence = row.construction or row.test_name or row.why_not
        print(f"  {row.property_id:<4}{row.kind.value:<24}{row.statement}\n{'':28}{evidence}")
    print(f"\n  {check.detail}")
    return 0 if check.passed else 1


def _experiments(*, as_json: bool) -> int:
    from pocketsec.stage5.labs.fifty_experiments import blocked_experiments, runnable_experiments

    runnable, blocked = runnable_experiments(), blocked_experiments()
    if as_json:
        print(json.dumps({"runnable": [row.to_dict() for row in runnable],
                          "blocked": [row.to_dict() for row in blocked]}, indent=2,
                         sort_keys=True))
        return 0
    print(f"Fifty experiments: {len(runnable)} runnable, {len(blocked)} blocked\n")
    for row in blocked:
        print(f"  BLOCKED {row.to_dict()}")
    print("\n  Registration into experiments/registry.jsonl is not performed here; the gate "
          "records ablations in a temporary ledger only (spec §2.7).")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
