"""``pocketsec-stage2`` — the Stage 2 operator entry point.

``gate``      run the thirteen Stage 2 acceptance criteria (exits non-zero on failure)
``runtime``   replay the corpus through the stdlib path and print the work ledger
``resources`` measure the runtime path against the Stage 0 Edge profile
``frontier``  print the baseline-suite evidence the gate consumes
``handoff``   write the Stage 3 handoff and print its sha256 digest

Every command here is stdlib-only, because the endpoint runtime is. Fitting the
baseline suite and building the D2.14 report need numpy and therefore live
behind a separate entry point, ``python -m pocketsec.stage2.research.cli``: a
runtime module may not import research code (ADR-0008), and the gate is a
runtime module. It reads what research measured and refuses evidence from a
different split.

``gate`` is slow on purpose: it compiles two corpus splits through Stage 1 and
runs the drift corpus, the poison suite and the counterfactual probes. Measured
on this host it takes minutes, not seconds. A gate that skipped the measurement
to stay fast would not be a gate.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage2.gate import (
    GATE_CORPUS,
    GATE_COUNT,
    TEST_SEED,
    TRAIN_SEED,
    Stage2GateContext,
    run_gate,
)
from pocketsec.stage2.gate_criteria import phi_candidate

__all__ = ["main"]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pocketsec-stage2", description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("gate", "run the Stage 2 acceptance gate"),
        ("runtime", "replay the corpus through the stdlib path and print the work ledger"),
        ("resources", "measure the runtime path against the Stage 0 Edge profile"),
        ("frontier", "print the baseline-suite evidence the gate consumes"),
        ("handoff", "write the Stage 3 handoff and print its digest"),
    ):
        sub.add_parser(name, help=help_text)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    handlers = {
        "gate": _gate,
        "runtime": _runtime,
        "resources": _resources,
        "frontier": _frontier,
        "handoff": _handoff,
    }
    return handlers[args.command](as_json=args.json)


def _gate(*, as_json: bool) -> int:
    report = run_gate()
    if as_json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print("PocketSec Stage 2 acceptance gate")
        print(
            f"(synthetic corpus {GATE_CORPUS}, count={GATE_COUNT}, "
            f"train seed={TRAIN_SEED}, eval seed={TEST_SEED} — a Stage 2 figure "
            "quoted without all three is void)\n"
        )
        for check in report.checks:
            print(f"  [{'PASS' if check.passed else 'FAIL'}] {check.id}  {check.title}")
            print(f"         {check.detail}")
        print()
        print("GATE: PASSED" if report.passed else f"GATE: FAILED ({len(report.failures)})")
        if report.failures:
            print(
                "  Stage 2 is not gate-clean, and this is the recorded state of the "
                "stage rather than a regression: ADR-0113 exists because a stage may "
                "not be declared failed by prose."
            )
    return 0 if report.passed else 1


def _runtime(*, as_json: bool) -> int:
    ctx = Stage2GateContext.build()
    payload = {
        "corpus": ctx.test.to_provenance(),
        "cache_honoured": ctx.cached.to_dict(),
        "cache_ignored": ctx.uncached.to_dict(),
        "work_histogram": ctx.cached_ledger.histogram(),
        "path_fractions": ctx.cached_ledger.path_fractions(),
        "ledger_truncated": ctx.cached_ledger.truncated(),
        "lru_key_control_resident_fraction": ctx.lru_fraction,
    }
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    print("Stage 2 stdlib runtime path (synthetic corpus)\n")
    print(f"  events                 {ctx.cached.events}")
    print(f"  cache resolved         {ctx.cached.cache_resolved}")
    print(f"  deep inference         {ctx.cached.inferred}")
    print(f"  abstentions            {ctx.cached.abstentions}")
    print(f"  µs/event (cache on)    {ctx.cached.microseconds_per_event}")
    print(f"  µs/event (cache off)   {ctx.uncached.microseconds_per_event}")
    print(f"  proposed paths         {dict(ctx.cached.proposed_paths)}")
    print(f"  derived paths          {dict(ctx.cached.derived_paths)}")
    print(f"  LRU key control        {ctx.lru_fraction}")
    print(
        "\n  Proposed is what route_information_need would have claimed; derived is "
        "what the ledger proves ran. Only the second may be quoted as a saving "
        "(ADR-0114)."
    )
    return 0


def _resources(*, as_json: bool) -> int:
    ctx = Stage2GateContext.build()
    if as_json:
        print(json.dumps(ctx.resources, indent=2, sort_keys=True))
        return 0
    resources = ctx.resources
    print("Stage 2 runtime resource cost (this development host, not a 2 GB device)\n")
    for key in ("events", "within_target", "incremental_rss_bytes", "model_bytes"):
        print(f"  {key:<24} {resources.get(key, resources['pass'].get(key))}")
    print(f"  component bytes          {resources['component_bytes']}")
    print(f"  profile                  {resources['profile']}")
    print(f"  cache                    {resources['cache']}")
    return 0


def _frontier(*, as_json: bool) -> int:
    """Print the baseline-suite evidence the gate consumes, or say there is none.

    Measuring it needs the offline suite and therefore numpy (ADR-0008), which a
    runtime module may not import. This command reads what research wrote; it
    never fabricates a figure in its absence.
    """
    from pocketsec.stage2 import gate_evidence

    evidence, refusal = gate_evidence.load_frontier()
    if evidence is None:
        print(f"UNMEASURED: {refusal}", file=sys.stderr)
        return 1
    if as_json:
        print(json.dumps(evidence.to_dict(), indent=2, sort_keys=True))
        return 0
    print(f"Stage 2 baseline frontier ({gate_evidence.FRONTIER_PATH.name})\n")
    for name, value in sorted(evidence.scores.items()):
        print(f"  {name:<20} {value:.4f}")
    print(f"\n  base rate            {evidence.base_rate:.4f}")
    print(f"  degenerate           {evidence.degenerate} ({evidence.reason})")
    print(f"  cost frontier        {evidence.pareto.get('verdict', 'UNMEASURED')}")
    print(f"  measured by          {evidence.measured_by}")
    return 0


def _handoff(*, as_json: bool) -> int:
    from pocketsec.stage2.compile_candidates.exporter import export_candidates
    from pocketsec.stage2.compile_candidates.stage3_interface import build_handoff, write_handoff

    ctx = Stage2GateContext.build()
    # Anchored to the repository, not to the process CWD. Every other path in
    # this stage already is (`gate_evidence.FRONTIER_PATH`, `gate_criteria.ADR_DIR`,
    # `research/cli.py`), and both `export_candidates` and `write_handoff` call
    # `path.parent.mkdir(parents=True, exist_ok=True)` — so a CWD-relative
    # destination meant `pocketsec-stage2 handoff` created a `results/` tree
    # wherever it happened to be run, and wrote the Stage 3 handoff somewhere
    # Stage 3 would not look (S2-AUTH-11).
    destination = REPO_ROOT / "results" / "stage2-handoff.json"
    export = export_candidates(
        (phi_candidate(ctx),), destination.with_name("stage2-candidates.json")
    )
    handoff = build_handoff(export, handoff_id="stage2-handoff")
    digest = write_handoff(handoff, destination)
    payload = {
        "handoff": str(destination),
        "digest": digest,
        "candidates": len(handoff.candidates),
        "refused": [list(row) for row in export.refused],
        "encoder_version": handoff.encoder_version,
        "interface_version": handoff.interface_version,
    }
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    print("Stage 3 handoff\n")
    for key, value in payload.items():
        print(f"  {key:<20} {value}")
    if export.refused:
        print(
            "\n  A refused candidate is the export interface working: it carries no "
            "measurement the exporter could accept, and Stage 3 must never receive one."
        )
    return 0 if handoff.candidates else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
