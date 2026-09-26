"""The numbers behind the Stage 9 gate's ten verdicts, as one JSON-able record.

A check's ``detail`` says why it passed or failed; this module keeps the figures a reader
needs to audit that sentence: every search run's spend and stop reason, the shuffled-label
control, every mechanism verdict with its controls and firing count, every ARGUS finding,
every hardware measurement. ``pocketsec-stage9 gate --save`` writes it beside the checks, so
the findings document quotes one saved run rather than a second, unrecorded one.

Nothing here computes a measurement. It only reads what the build steps stored.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from pocketsec.stage9.gate_state import Stage9GateContext
from pocketsec.stage9.ontogenesis.search import SearchRun

__all__ = ["evidence"]


def _run(run: SearchRun) -> dict[str, Any]:
    winner = None if run.winner is None else run.records[run.winner]
    return {
        "run": run.config.label,
        "evaluations": run.evaluations,
        "cache_hits": run.cache_hits,
        "wu_spent": run.wu_spent,
        "budget_wu": run.config.budget_wu,
        "stop_reason": run.stop_reason,
        "winner_digest": None if winner is None else winner.genome_digest,
        "winner_train_worst_case_ap": None if winner is None else winner.worst_case_ap,
        "winner_from_variation": run.winner is not None
        and run.winner >= run.initial_records
        and run.config.strategy.value == "EVOLUTIONARY",
        "rediscovered_phi": run.rediscovered_phi,
        "population_evictions": run.population_evictions,
        "fossils_recorded": run.fossils_recorded,
        "fossils_avoided": run.fossils_avoided,
        "determinism_digest": run.determinism_digest,
        "operator_stats": [
            [s.operator.value, s.proposed, s.valid, s.improved_archive] for s in run.operator_stats
        ],
        "wall_seconds_host_contended": round(run.wall_seconds, 2),
        "loadavg": [run.loadavg_before, run.loadavg_after],
    }


def _references(ctx: Stage9GateContext) -> dict[str, Any]:
    return {
        "aps": ctx.reference_aps,
        "saturation": {
            k: {"degenerate": v.degenerate, "reason": v.reason} for k, v in ctx.saturation.items()
        },
        "hand": {
            name: {"train": ctx.hand_train[name].to_dict(), "heldout": record.to_dict()}
            for name, record in ctx.hand_heldout.items()
        },
        "contamination": None if ctx.contamination is None else ctx.contamination.to_dict(),
        "expressibility": [
            asdict(row)
            for row in ctx.expressibility
            if not row.target.startswith("deterministic-scorer/")
        ],
        "tcn_point": [
            None if ctx.tcn_point[0] is None else asdict(ctx.tcn_point[0]),
            ctx.tcn_point[1],
        ],
    }


def evidence(ctx: Stage9GateContext) -> dict[str, Any]:
    """Everything the checks read, flattened to JSON types (``default=str`` for the rest)."""
    return {
        "references": _references(ctx),
        "runs": {arm: [_run(run) for run in runs] for arm, runs in ctx.runs.items()},
        "winner_reports": [asdict(report) for report in ctx.reports],
        "strategy": None if ctx.strategy is None else asdict(ctx.strategy),
        "shuffled_label_control": None if ctx.shuffled is None else asdict(ctx.shuffled),
        "comparisons": {flag: asdict(c) for flag, c in sorted(ctx.comparisons.items())},
        "argus": [finding.to_dict() for finding in ctx.findings],
        "fittest_attrition": {label: a.to_dict() for label, a in ctx.attrition},
        "coarsenings": [asdict(c) for c in ctx.coarsenings],
        "candidates_examined": ctx.candidates_examined,
        "promotions": len(ctx.promotions),
        "laws": [law.status.value for law in ctx.laws],
        "catalog": []
        if ctx.catalog is None
        else [
            {
                "regime": e.regime.value,
                "genome": e.genome.digest,
                "heldout_worst_case_ap": e.heldout_worst_case_ap,
                "wu_per_event": e.wu_per_event,
            }
            for e in ctx.catalog.entries
        ],
        "transitions_into": ctx.transitions_into,
        "hardware": [m.to_dict() for m in ctx.measurements],
        "proxy": None if ctx.proxy is None else asdict(ctx.proxy),
        "successors": [
            {k: v for k, v in asdict(s).items() if k != "tampering"}
            | {"tampering": s.tampering.to_dict()}
            for s in ctx.successors
        ],
        "isolation": None if ctx.isolation is None else asdict(ctx.isolation),
        "lab_notes": ctx.lab_notes,
    }
