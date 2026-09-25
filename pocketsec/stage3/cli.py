"""``pocketsec-stage3`` — the Stage 3 operator entry point.

``gate``         run the thirteen Stage 3 acceptance criteria
``baselines``    the five control baselines plus the cell path, in one run
``crystallize``  run CRYSTAL over the corpus's largest boundary regions
``melt``         the melting-locality experiment (G3.7, falsifier F2)
``pressure``     guided Boundary Pressure against random replay at the same cap
``threats``      the nine §39 threat cases, each with its control on and off
``resources``    Stage 3's §38 component budget, measured
``vmcost``       what verification costs inside ``CellVM.run``, and against a control
``handoff``      build and write the frozen Stage 4 interface

Every subcommand reports what it measured, including when the answer is that
nothing could be measured. ``--json`` emits the machine-readable form.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from pocketsec.stage1.ssir.relations import RelationFamily
from pocketsec.stage3.boundary.index import BoundaryIndex
from pocketsec.stage3.boundary.pressure import compare_strategies
from pocketsec.stage3.bytecode.cost import measure_vm_cost
from pocketsec.stage3.cells.field import KnowledgeField
from pocketsec.stage3.gate import (
    CORPUS_COUNT,
    EVAL_SEED,
    Stage3GateContext,
    crystallize_region,
    run_gate,
)
from pocketsec.stage3.gate_criteria import actor_predicate
from pocketsec.stage3.labs.boundary_evasion import run_threat_suite
from pocketsec.stage3.labs.crystal_corpus import build_crystal_corpus, session_frames
from pocketsec.stage3.labs.cell_path import phi_oracle_cell
from pocketsec.stage3.melting.partial import partial_melt
from pocketsec.stage3.oracles.counterexamples import CounterexampleStore
from pocketsec.stage3.resources import measure_stage3_resources
from pocketsec.stage3.stage4_interface import build_crystal_handoff, write_crystal_handoff

__all__ = ["main"]

_REGIONS_SHOWN = 8

#: Frames timed by ``vmcost``. Bounded, and large enough that per-frame overhead
#: dominates the loop rather than the loop dominating the measurement.
VMCOST_FRAMES = 512


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pocketsec-stage3", description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("gate", "run the Stage 3 acceptance gate"),
        ("baselines", "run the five control baselines and the cell path"),
        ("crystallize", "run CRYSTAL over the corpus's largest boundary regions"),
        ("melt", "the melting-locality experiment (G3.7)"),
        ("pressure", "guided Boundary Pressure vs random replay at the same cap"),
        ("threats", "the nine threat cases with their controls on and off"),
        ("resources", "Stage 3's measured component budget"),
        ("vmcost", "CellVM.run vs _execute vs a handwritten control"),
        ("handoff", "build and write the Stage 4 handoff"),
    ):
        sub.add_parser(name, help=help_text)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    handlers = {
        "gate": _gate,
        "baselines": _baselines,
        "crystallize": _crystallize,
        "melt": _melt,
        "pressure": _pressure,
        "threats": _threats,
        "resources": _resources,
        "vmcost": _vmcost,
        "handoff": _handoff,
    }
    return handlers[args.command](as_json=args.json)


def _gate(*, as_json: bool) -> int:
    report = run_gate()
    if as_json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print("PocketSec Stage 3 acceptance gate\n")
        for check in report.checks:
            print(f"  [{'PASS' if check.passed else 'FAIL'}] {check.id}  {check.title}")
            print(f"         {check.detail}")
        print()
        print(
            "GATE: PASSED"
            if report.passed
            else f"GATE: FAILED ({len(report.failures)} of {len(report.checks)})"
        )
    return 0 if report.passed else 1


def _baselines(*, as_json: bool) -> int:
    ctx = Stage3GateContext.build()
    table = ctx.baselines
    if as_json:
        print(json.dumps(table.to_dict(), indent=2, sort_keys=True))
        return 0
    print("Stage 3 baselines (synthetic drift corpus; demonstrates the method)\n")
    print(
        f"  corpus {table.corpus_version}, count {table.count}, fit seed {table.fit_seed}, "
        f"eval seed {table.eval_seed}, base rate {table.base_rate:.4f}, "
        f"loadavg {table.loadavg[0]:.2f}\n"
    )
    print(f"  {'id':<4} {'PR-AUC':>8} {'µs/event':>10} {'bytes':>8}  description")
    for row in table.rows:
        pr = "n/a" if row.pr_auc is None else f"{row.pr_auc:.4f}"
        us = (
            "UNMEASURED"
            if row.microseconds_per_event is None
            else f"{row.microseconds_per_event:.2f}"
        )
        print(f"  {row.baseline_id:<4} {pr:>8} {us:>10} {row.bytes_resident:>8}  {row.description}")
    if table.refused:
        print(f"\n  COMPARISON REFUSED: {table.refusal_reason}")
    print(
        "\n  Absolute microseconds are contended-host figures, not device measurements; "
        "only within-run ratios transfer."
    )
    return 0


def _crystallize(*, as_json: bool) -> int:
    ctx = Stage3GateContext.build()
    rows = []
    for rank in range(min(_REGIONS_SHOWN, len(ctx.regions()))):
        run = crystallize_region(
            ctx, KnowledgeField(), CounterexampleStore(cold_archive=None), rank=rank
        )
        rows.append(
            {
                "region_key": list(run.region_key),
                "outcome": run.outcome.value,
                "forms_tried": [form.value for form in run.candidates_tried],
                "selected": run.selected.program.form.value if run.selected else None,
                "microseconds_per_event": (
                    run.selected.microseconds_per_event if run.selected else None
                ),
                "cell_id": run.cell.cell_id if run.cell else None,
                "reason": run.reason,
            }
        )
    if as_json:
        print(json.dumps(rows, indent=2, sort_keys=True))
        return 0
    print("CRYSTAL over the drift corpus's largest boundary regions\n")
    for row in rows:
        print(f"  region {row['region_key']} -> {row['outcome']}")
        print(f"    forms tried: {row['forms_tried'] or 'none'}")
        print(f"    selected:    {row['selected']} at {row['microseconds_per_event']} µs/event")
        print(f"    reason:      {row['reason']}")
    print(
        "\n  A refusal here is the pipeline working: UNMEASURED is not cheap, and a benign "
        "answer on a HIGH-consequence frame is refused by Oracle B."
    )
    return 0


def _melt(*, as_json: bool) -> int:
    field, index = KnowledgeField(), BoundaryIndex()
    spanning = phi_oracle_cell(cell_id="cell-spanning")
    spanning = replace(
        spanning,
        boundary=replace(
            spanning.boundary,
            predicates=(
                actor_predicate(RelationFamily.FILESYSTEM),
                actor_predicate(RelationFamily.NETWORK),
            ),
        ),
    )
    field.insert(spanning)
    index.insert(spanning)
    for position, family in enumerate(
        (RelationFamily.IDENTITY, RelationFamily.AUTHORIZATION, RelationFamily.LOADING), start=1
    ):
        other = phi_oracle_cell(cell_id=f"cell-{position}")
        other = replace(
            other, boundary=replace(other.boundary, predicates=(actor_predicate(family),))
        )
        field.insert(other)
        index.insert(other)
    drifted = replace(
        spanning.boundary, predicates=(actor_predicate(RelationFamily.NETWORK),)
    )
    report = partial_melt(spanning, drifted, field=field, index=index)
    survivor = report.surviving_cell
    payload = {
        "reopened_keys": [list(key) for key in report.reopened_keys],
        "drifted_region_keys": [list(key) for key in drifted.keys()],
        # The four facts F2 turns on. `repair_locality` is printed last and labelled,
        # because it is 1.0 by construction — `partial_melt` touches two ids and the
        # field refuses rather than evicting — and a melt with its narrowing logic
        # deleted reports the same 1.0.
        "survivor_in_field_and_index": bool(
            survivor is not None
            and field.get(survivor.cell_id) is not None
            and index.keys_for(survivor.cell_id)
        ),
        "survivor_keys": (
            [] if survivor is None else [list(key) for key in survivor.boundary.keys()]
        ),
        "survivor_keys_are_a_proper_subset": bool(
            survivor is not None
            and set(survivor.boundary.keys()) < set(spanning.boundary.keys())
        ),
        "survivor_avoids_drifted_region": bool(
            survivor is not None and not survivor.boundary.intersects(drifted)
        ),
        "stale_cell_gone_from_field": field.get(spanning.cell_id) is None,
        "unrelated_cells_before": report.unrelated_cells_before,
        "unrelated_cells_retained": report.unrelated_cells_retained,
        "surviving_cell": survivor.cell_id if survivor else None,
        "reason": report.reason,
        "repair_locality_SANITY_CHECK_ONLY": report.repair_locality,
    }
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    print("Melting locality (G3.7, falsifier F2)\n")
    for key, value in payload.items():
        print(f"  {key:<26} {value}")
    print(
        "\n  repair_locality is a bystander sanity check, not the number that falsifies "
        "F2: it is 1.0 by construction. The survivor_* rows above are what can fail."
        "\n  The drift was authored by the corpus designer, so this is a mechanism "
        "demonstration and not a field claim."
    )
    return 0


def _pressure(*, as_json: bool) -> int:
    ctx = Stage3GateContext.build()
    cell = phi_oracle_cell()
    seeds = ctx.claimed_frames(cell, limit=8)
    guided, control, guided_only = compare_strategies(
        cell, oracle=ctx.oracle, budget=256, seed=EVAL_SEED, seeds=seeds
    )
    payload = {
        "guided": guided.to_dict(),
        "random_replay": control.to_dict(),
        "guided_only_classes": sorted(guided_only),
        "random_only_classes": sorted(
            control.counterexample_classes - guided.counterexample_classes
        ),
    }
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    print(
        "Boundary Pressure: guided vs random replay at the same budget CAP "
        "(G3.4, falsifier F3). The cap is shared; the spend is not — both probes_run "
        "figures are printed below.\n"
    )
    print(f"  guided        {guided.probes_run:>4} probes, {len(guided.counterexample_classes)} classes")
    print(f"  random replay {control.probes_run:>4} probes, {len(control.counterexample_classes)} classes")
    print(f"\n  found only by guided:        {payload['guided_only_classes'] or 'NONE'}")
    print(f"  found only by random replay: {payload['random_only_classes'] or 'NONE'}")
    return 0


def _threats(*, as_json: bool) -> int:
    report = run_threat_suite()
    if as_json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        return 0
    print("Stage 3 threat model (architecture §39), each case with its control on and off\n")
    for case in report.cases:
        mark = "OK " if case.meaningful else "!! "
        print(f"  [{mark}] {case.case_id}")
        print(f"         attack:  {case.attack}")
        print(f"         control: {case.control}")
        print(f"         stopped with control: {case.stopped_with_control}; "
              f"succeeded without it: {case.succeeded_without_control}")
        print(f"         {case.detail}")
    print(f"\n  complete: {report.complete}; unmitigated: {list(report.unmitigated) or 'none'}")
    return 0 if report.complete else 1


def _resources(*, as_json: bool) -> int:
    from pocketsec.stage3.gate_criteria import audit_state_bytes, cell_vm_bytes, zero_stress
    from pocketsec.stage3.promotion.audit import AuditSampler

    ctx = Stage3GateContext.build()
    cell = phi_oracle_cell()
    field, index = KnowledgeField(), BoundaryIndex()
    field.insert(cell)
    index.insert(cell)
    claimed = ctx.claimed_frames(cell)

    def work() -> int:
        for frame in claimed:
            hit = index.lookup(frame)
            if hit is not None:
                ctx.vm.run(hit.operator, frame)
        return len(claimed)

    report = measure_stage3_resources(
        work,
        measured_by="pocketsec.stage3.cli:resources",
        boundary_index=index,
        knowledge_cells=field,
        counterexample_hot=CounterexampleStore(cold_archive=None),
        cell_vm_bytes=cell_vm_bytes(ctx.vm),
        audit_state_bytes=audit_state_bytes(AuditSampler("cli-boot-salt"), zero_stress()),
    )
    if as_json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        return 0
    print("Stage 3 resource footprint (architecture §38)\n")
    print(f"  loadavg at measurement   {report.loadavg}")
    print(f"  incremental RSS          {report.incremental_rss_bytes} B")
    print(f"  peak sampled RSS         {report.peak_sampled_rss_bytes} B")
    for name, value in sorted(report.per_component_bytes.items()):
        print(f"  {name:<24} {value} B")
    print(f"  within budget            {report.within_budget}")
    if report.unmeasured:
        print(f"  UNMEASURED               {list(report.unmeasured)}")
    return 0


def _vmcost(*, as_json: bool) -> int:
    """The producer for the two ratios ADR-0021 and the findings document cite.

    Both figures were published from prose with no code in the repository behind
    them, and the findings document's own Corrections table said the fix was to
    land a producer or withdraw them. This is that producer, run over the same
    corpus frames the rest of the stage measures.
    """
    corpus = build_crystal_corpus(count=CORPUS_COUNT, seed=EVAL_SEED)
    frames = tuple(
        frame for session in corpus.sessions for frame in session_frames(session)
    )[:VMCOST_FRAMES]
    report = measure_vm_cost(
        frames, measured_by="pocketsec.stage3.cli:_vmcost"
    )
    payload = report.to_dict()
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    print("CellVM cost split, one run, best-of-" f"{report.repetitions}, {report.frames} frames")
    print(f"  loadavg {report.loadavg[0]:.2f}/{report.loadavg[1]:.2f}/{report.loadavg[2]:.2f}")
    for label, value in (
        ("CellVM.run", report.run_us),
        ("CellVM._execute", report.interpreter_us),
        ("handwritten control", report.handwritten_us),
    ):
        print(f"  {label:22s} {'UNMEASURED' if value is None else format(value, '.3f')} us/frame")
    for label, value in (
        ("run / _execute", report.run_over_interpreter),
        ("run / handwritten", report.run_over_handwritten),
    ):
        print(f"  {label:22s} {'UNMEASURED' if value is None else format(value, '.2f')}x")
    print(f"  control: {report.control_source}")
    print(
        "  Absolute microseconds are contended-host numbers, not device measurements; "
        "only the two ratios transfer."
    )
    return 0


def _handoff(*, as_json: bool) -> int:
    cell = phi_oracle_cell()
    field, index = KnowledgeField(), BoundaryIndex()
    field.insert(cell)
    index.insert(cell)
    handoff = build_crystal_handoff(field, index, handoff_id="stage3-crystal-0001")
    destination = Path("results") / "stage3-crystal-handoff.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = write_crystal_handoff(handoff, destination)
    if as_json:
        print(json.dumps({"path": str(destination), "digest": digest}, indent=2, sort_keys=True))
        return 0
    print(f"wrote {destination}\n  content digest {digest}")
    print(f"  {len(handoff.cells)} cell(s), {len(handoff.boundary_keys)} boundary key row(s)")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
