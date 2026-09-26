"""The Stage 9 acceptance gate (``docs/stage-9-spec.md`` §6), as an executable check.

Ten criteria, one per sentence of the phase file's §69, each evaluated by running the real
subsystems rather than inspecting a document. Like every earlier stage's gate this is code:
``pocketsec-stage9 gate`` exits non-zero if any criterion fails.

Four things about this gate are worth stating before anyone reads a result off it.

**It is expected to fail, and its failures are Stage 9's findings.** Spec §6.1 said so in
advance: G9.1 is blocked on Stage 8 (its criterion names "the strongest Stage-8 hand-designed
baseline", and Stage 8's named interface carries none Stage 9 may consume), and G9.4 needs a
2 GB reference machine this 16 GB host is not. Every other check that would pass on an empty
result is written to fail instead: a check over zero objects is VACUOUS and reported FAILED.

**One context, built once, and nothing selected on held-out data.** Train (ambiguous 240,
seed 3) and held-out (ambiguous 240, seed 11) are compiled clean plus the six ARGUS scenario
attacks; the searches see train only; held-out numbers are reported, never used to choose.
Count 60 is compiled only to show the saturation trap (ADR-0084).

**Nothing measured here is a detection result, and no timing is a device figure.** Every
corpus is synthetic and project-authored; the headroom split's label is the generator's own
attribution rule, which H1 and H2 restate (author confound, spec §9). ``/proc/loadavg`` is
recorded beside every step; work units are the primary cost.

This gate **never** appends to ``experiments/registry.jsonl`` (spec §2.5): G9.7 asserts the
ledger is byte-identical before and after the run. Registration is ``pocketsec-stage9
register``, a separate command.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pocketsec.stage0.gate import REPO_ROOT, GateReport
from pocketsec.stage6.resources import loadavg
from pocketsec.stage9 import gate_build as build
from pocketsec.stage9 import gate_criteria as criteria
from pocketsec.stage9 import gate_labs as labs
from pocketsec.stage9.gate_evidence import evidence
from pocketsec.stage9.gate_state import GateConfig, Stage9GateContext

__all__ = [
    "EXPERIMENT_ID",
    "REGISTRY_PATH",
    "STAGE9_HYPOTHESIS",
    "GateConfig",
    "Stage9GateContext",
    "build_context",
    "registry_digest",
    "report_for",
    "run_gate",
    "summary",
]

#: Spec §2.6 / ADR-0080: no H15 is minted; the search binds to H5 (state growth and
#: minimisation), CHRONOS rows to H6, baselines and controls to BASE.
STAGE9_HYPOTHESIS = "H5"
EXPERIMENT_ID = "PS-S9-20260926-H5-ontogenesis-gate-0001"
REGISTRY_PATH = REPO_ROOT / "experiments" / "registry.jsonl"

#: The build order. Each step reads what the earlier ones stored; a step whose inputs are
#: missing records why and stores nothing, so the checks that need it FAIL with the reason.
_STEPS: tuple[tuple[str, Callable[[Stage9GateContext], None]], ...] = (
    ("splits", build.compile_splits),
    ("audit", build.audit_splits),
    ("references", build.measure_references),
    ("expressibility", build.measure_expressibility),
    ("search", build.run_searches),
    ("comparisons", build.compare_searches),
    ("argus", labs.run_argus),
    ("physics", labs.run_physics),
    ("laws", labs.run_laws),
    ("abstractions", labs.run_abstractions),
    ("runtime", labs.run_runtime),
    ("hardware", labs.run_hardware),
    ("successor", labs.run_successors),
    ("isolation", labs.run_isolation),
)


def registry_digest(path: Path = REGISTRY_PATH) -> str | None:
    """sha256 of the real experiment ledger's bytes, or ``None`` when it does not exist."""
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_context(config: GateConfig | None = None) -> Stage9GateContext:
    """Run every step once, in order, timing each with loadavg before and after.

    A step that raises is recorded in ``errors`` and the build continues: one broken lab
    must fail the checks that read it, not hide the other nine criteria. A refused context
    (corpus audit or contamination failure, spec §6 step 2) skips every later step.
    """
    ctx = Stage9GateContext(config=config or GateConfig(), registry_before=registry_digest())
    for name, step in _STEPS:
        if ctx.refused and name not in ("splits", "audit"):
            ctx.errors[name] = f"skipped: the gate context refused to build ({ctx.refused})"
            continue
        _timed(ctx, name, step)
    ctx.registry_after = registry_digest()
    return ctx


def _timed(ctx: Stage9GateContext, name: str, step: Callable[[Stage9GateContext], None]) -> None:
    before, start = loadavg(), time.perf_counter()
    try:
        step(ctx)
    except Exception as exc:  # recorded, never swallowed: the reading checks fail with it
        ctx.errors[name] = f"{type(exc).__name__}: {exc}"
    ctx.timings.append((name, time.perf_counter() - start, before, loadavg()))


def report_for(ctx: Stage9GateContext) -> GateReport:
    """The ten checks read off an already-built context (the CLI prints both)."""
    return GateReport(checks=criteria.all_checks(ctx))


def run_gate(config: GateConfig | None = None) -> GateReport:
    """Evaluate all ten Stage 9 acceptance criteria on one freshly built context.

    ``config`` other than the default is for tests only: a reduced run exercises every code
    path and is never the gate's verdict (``pocketsec-stage9 gate`` always uses the default).
    """
    return report_for(build_context(config))


def summary(ctx: Stage9GateContext) -> dict[str, Any]:
    """Per-step wall clock with loadavg (host-contended, not a device figure) and errors."""
    return {
        "experiment_id": EXPERIMENT_ID,
        "full_config": ctx.config.full,
        "subject": ctx.subject_reason,
        "splits": {
            suite.name: suite.clean.content_digest
            for suite in (ctx.train, ctx.heldout)
            if suite is not None
        },
        "steps": [
            {
                "step": name,
                "seconds": round(seconds, 2),
                "loadavg_before": before,
                "loadavg_after": after,
            }
            for name, seconds, before, after in ctx.timings
        ],
        "errors": dict(sorted(ctx.errors.items())),
        "evidence": evidence(ctx),
    }
