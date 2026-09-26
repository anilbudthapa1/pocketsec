"""``pocketsec-stage6`` — the Stage 6 operator entry point.

``gate``          run the thirteen Stage 6 acceptance criteria; exits non-zero on any failure
``endurance``     every learner on the compiled 12-month timeline, one checkpoint per month
``poison``        the eleven poisoning arms x {Stage 6, NaiveFinetune, Stage2Only, accept-nothing}
``ablation``      one row per OPTIONAL mechanism against its simple control (never registered)
``resources``     the 12-month Stage 6 loop under Stage 0's sampler, in this process
``export``        a LearningRecordV1 (the Stage 7 handoff) from a 12-month Stage 6 run
``experiments``   the sixty S6X experiments; ``--register`` is the ONLY ledger writer

Every corpus is synthetic and every Stage 5 record the stage learns from is simulated, so
nothing printed here is a detection result. ``/proc/loadavg`` is printed beside every
timing, because timings on this host are contended and only within-run ratios transfer.

``experiments --register`` is the one command that appends to
``experiments/registry.jsonl``; the gate never does (spec §2.7). There is no command that
installs knowledge: trusted state changes only inside ``LearningPromotionController``.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from typing import Any

__all__ = ["main"]

_COMMANDS: tuple[tuple[str, str], ...] = (
    ("gate", "run the Stage 6 acceptance gate"),
    ("endurance", "run every learner on the compiled 12-month timeline"),
    ("poison", "run the eleven poisoning arms"),
    ("ablation", "measure one ablation row per OPTIONAL mechanism"),
    ("resources", "measure the 12-month Stage 6 loop under Stage 0's sampler"),
    ("export", "export a LearningRecordV1 from a 12-month Stage 6 run"),
    ("experiments", "list the sixty S6X experiments; --register appends to the ledger"),
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pocketsec-stage6", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in _COMMANDS:
        command = sub.add_parser(name, help=help_text)
        if name == "resources":
            command.add_argument("--sessions-per-month", type=int, default=None)
            command.add_argument("--seed", type=int, default=None)
        if name == "experiments":
            command.add_argument("--register", action="store_true",
                                 help="run the gate and append it (and its ablation rows) "
                                      "to experiments/registry.jsonl")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    handlers: dict[str, Callable[[argparse.Namespace], int]] = {
        "gate": _gate, "endurance": _endurance, "poison": _poison, "ablation": _ablation,
        "resources": _resources, "export": _export, "experiments": _experiments,
    }
    return handlers[args.command](args)


def _loadavg() -> str:
    from pocketsec.stage6.resources import loadavg

    return " ".join(f"{value:.2f}" for value in loadavg())


def _emit(payload: Any) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))


def _gate(args: argparse.Namespace) -> int:
    from pocketsec.stage6.gate import Stage6GateContext, run_gate

    ctx = Stage6GateContext.build()
    try:
        report = run_gate(ctx)
    finally:
        ctx.close()
    if args.json:
        _emit({**report.to_dict(), "gate": "stage-6", "timings": ctx.timings})
        return 0 if report.passed else 1
    print("PocketSec Stage 6 acceptance gate (synthetic corpora; see docs/stage-6-spec.md §6.1)\n")
    for check in report.checks:
        print(f"  [{'PASS' if check.passed else 'FAIL'}] {check.id}  {check.title}")
        print(f"         {check.detail}")
    print("\n  timings (label, wall s, loadavg) — observations, never asserted:")
    for label, seconds, load in ctx.timings:
        print(f"    {label:<34} {seconds:>9.3f}  {load}")
    print(f"\nloadavg at end of run: {_loadavg()}")
    print(f"{len(report.checks) - len(report.failures)}/{len(report.checks)} criteria met")
    print("GATE: PASSED" if report.passed else f"GATE: FAILED ({len(report.failures)})")
    return 0 if report.passed else 1


def _compiled() -> Any:
    from pocketsec.stage6.labs.endurance_corpus import (
        ENDURANCE_SEED,
        build_endurance_timeline,
        compile_timeline,
    )

    return compile_timeline(build_endurance_timeline(seed=ENDURANCE_SEED), seed=ENDURANCE_SEED)


def _endurance(args: argparse.Namespace) -> int:
    from pocketsec.stage6.gate import baseline_learners
    from pocketsec.stage6.labs.endurance import StageSixLearner, check_preconditions, run_endurance

    compiled = _compiled()
    pre = check_preconditions(compiled)
    learners = [*baseline_learners(compiled), StageSixLearner(compiled.genesis, seed=compiled.seed)]
    report = run_endurance(compiled, learners, pre)
    rows = []
    for learner in learners:
        points = report.for_learner(learner.name)
        last = points[-1]
        rows.append({"learner": learner.name, "fp_rate_final": last.fp_rate,
                     "acquisition": {p.month: dict(p.acquisition) for p in points},
                     "retention_final": dict(last.retention),
                     "promotions": sum(p.promotions for p in points),
                     "poisoned_promotions": sum(p.poisoned_promotions for p in points),
                     "detectors_removed": sum(p.detectors_removed for p in points),
                     "poison_removals": sum(p.poison_removals for p in points),
                     "work_units": last.cost.work_units, "stored_bytes": last.cost.stored_bytes})
    payload = {"preconditions": pre.verdict, "details": list(pre.details), "rows": rows,
               "observations": [list(o) for o in report.observations], "synthetic": True}
    if args.json:
        _emit(payload)
        return 0
    print(f"preconditions: {pre.verdict}")
    for detail in pre.details:
        print(f"  {detail}")
    for row in rows:
        print(f"  {row['learner']:<20} fp {row['fp_rate_final']} retention "
              f"{row['retention_final']} promotions {row['promotions']} poisoned additions "
              f"{row['poisoned_promotions']} detectors removed {row['detectors_removed']} "
              f"(right after a poison capsule {row['poison_removals']}) work "
              f"{row['work_units']} stored {row['stored_bytes']}")
    print(f"  loadavg {_loadavg()}")
    return 0


def _poison(args: argparse.Namespace) -> int:
    import tempfile
    from pathlib import Path

    from pocketsec.stage6.labs.endurance import run_poison_suite

    with tempfile.TemporaryDirectory(prefix="pocketsec-stage6-poison-") as root:
        report = run_poison_suite(fossil_root=Path(root))
    if args.json:
        from dataclasses import asdict

        _emit({"rows": [asdict(row) for row in report.rows],
               "arm_verdicts": dict(report.arm_verdicts), "synthetic": report.synthetic})
        return 0
    for row in report.rows:
        print(f"  {row.arm_id:<4} {row.learner:<15} x{row.multiplier:<3} offered "
              f"{row.poisoned_offered:<5} poisoned {row.poisoned_promotions} clean "
              f"{row.clean_promotions} ({row.clean_rate})")
    for arm, verdict in sorted(report.arm_verdicts.items()):
        print(f"  verdict {arm}: {verdict}")
    print(f"  loadavg {_loadavg()}")
    return 0


def _ablation(args: argparse.Namespace) -> int:
    from dataclasses import asdict

    from pocketsec.stage6.labs.endurance import run_ablation

    rows = run_ablation(_compiled())
    if args.json:
        _emit([asdict(row) for row in rows])
        return 0
    print("Ablation rows (full Stage 6 vs one flag replaced by its control; Rule C applies)\n")
    for row in rows:
        print(f"  {row.core_id:<22} {row.flag:<24} {row.metric:<22} full {row.full} ablated "
              f"{row.ablated} delta {row.delta} firing {row.firing_count} {row.verdict}")
    print(f"\n  loadavg {_loadavg()}")
    return 0


def _resources(args: argparse.Namespace) -> int:
    from pocketsec.stage6.gate_measured import resource_measurement

    kwargs = {key: value for key, value in (("sessions_per_month", args.sessions_per_month),
                                             ("seed", args.seed)) if value is not None}
    payload = resource_measurement(**kwargs)
    if args.json:
        _emit(payload)
        return 0
    print("Stage 6 resources (Stage 0 ResourceSampler; dev host, not a 2 GB device)\n")
    for key, value in sorted(payload.items()):
        print(f"  {key:<24} {value}")
    return 0


def _export(args: argparse.Namespace) -> int:
    from pocketsec.stage6.export.learning_record import export_learning_record
    from pocketsec.stage6.labs.endurance import StageSixLearner, run_endurance

    compiled = _compiled()
    learner = StageSixLearner(compiled.genesis, seed=compiled.seed)
    run_endurance(compiled, [learner])
    rows = [r.to_dict() for r in learner.controller.rollbacks()]
    record = export_learning_record(learner.trusted_state(), lineage=learner.lineage,
                                    fossils=learner.fossils, rollback_rows=rows, simulated=True)
    if args.json:
        _emit(record.to_dict())
    else:
        print(f"LearningRecordV1 {record.record_id} digest {record.digest()}")
        print(f"  trusted {record.trusted_digest}, items {len(record.items)}, fossils "
              f"{len(record.fossil_hashes)}, lineage intact {record.lineage_intact}, simulated "
              f"{record.simulated}")
    return 0


def _experiments(args: argparse.Namespace) -> int:
    from pocketsec.stage6.labs.sixty_experiments import SIXTY_EXPERIMENTS, unmeasured_experiments

    if args.register:
        return _register(as_json=args.json)
    unmeasured = unmeasured_experiments()
    if args.json:
        _emit({"experiments": [e.experiment_id for e in SIXTY_EXPERIMENTS],
               "unmeasured": [{"id": e.experiment_id, "limitation": e.limitation}
                              for e in unmeasured]})
        return 0
    print(f"Sixty experiments: {len(SIXTY_EXPERIMENTS) - len(unmeasured)} executable, "
          f"{len(unmeasured)} UNMEASURED\n")
    for experiment in SIXTY_EXPERIMENTS:
        print(f"  {experiment.experiment_id} {experiment.status.value:<10} {experiment.title}")
    print("\n  Nothing was registered. `experiments --register` is the only ledger writer.")
    return 0


def _register(*, as_json: bool) -> int:
    """The ONLY writer to experiments/registry.jsonl, and only when asked (spec §2.7)."""
    from dataclasses import asdict
    from datetime import UTC, datetime

    from pocketsec.stage0.contracts.common import digest_of_bytes
    from pocketsec.stage0.experiments.ids import format_experiment_id
    from pocketsec.stage0.experiments.registry import ExperimentRegistry
    from pocketsec.stage6.gate import (
        EXPERIMENT_ID,
        REGISTRY_PATH,
        STAGE6_HYPOTHESIS,
        Stage6GateContext,
        run_gate,
    )

    ctx = Stage6GateContext.build()
    try:
        report = run_gate(ctx)
    finally:
        ctx.close()
    registry = ExperimentRegistry(REGISTRY_PATH)
    corpus = digest_of_bytes(json.dumps([ctx.compiled.version, ctx.compiled.seed,
                                         sorted(ctx.compiled.poison_ids)]).encode("utf-8"))
    common: dict[str, Any] = {
        "slot_name": "stage6-learning-boundary", "dataset_name": "stage6-endurance",
        "dataset_version": ctx.compiled.version, "dataset_sha256": corpus, "git_commit": None,
        "seeds": {"endurance": ctx.seed}, "synthetic_data": True}
    entries = [registry.register(
        experiment_id=EXPERIMENT_ID, hypothesis=STAGE6_HYPOTHESIS,
        title="Stage 6 HELIOS+MNEMOSYNE acceptance gate",
        notes=f"{len(report.checks) - len(report.failures)}/{len(report.checks)} criteria met; "
              f"failures {[c.id for c in report.failures]}", **common)]
    date = datetime.now(UTC).strftime("%Y%m%d")
    for index, row in enumerate(ctx.ablation, start=1):
        entries.append(registry.register(
            experiment_id=format_experiment_id(stage=6, hypothesis="H8", slug="ablation",
                                               sequence=index, date=date),
            hypothesis="H8", title=f"Stage 6 ablation {row.core_id} ({row.flag})",
            notes=json.dumps(asdict(row), sort_keys=True), **common))
    if as_json:
        _emit({"registered": [e.experiment_id for e in entries]})
    else:
        print(f"registered {len(entries)} entries: {[e.experiment_id for e in entries]}")
        print(f"gate result: {'PASSED' if report.passed else f'FAILED ({len(report.failures)})'}")
    return 0 if report.passed else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
