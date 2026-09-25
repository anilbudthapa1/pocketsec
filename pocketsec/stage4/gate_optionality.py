"""G4.11 — "Stage 4 remains optional to core Stage 1-3 detection if it crashes".

This module is FOR the criterion the lead called a precondition for every other: if
Stage 4 cannot crash safely, nothing else about it matters. It measures it twice,
because the first version measured it once in the wrong place.

**The hook arm** (``hook_arm``) injects a fault into each of the ten ``Subsystem``
hooks of ``engine/integrator.run_attached_cognition``. That harness is real code and
still worth checking, but it is *not* the engine: the review ran G4.11 with every
``LucidEngine`` entry point replaced by a function that raised, and the gate still
reported PASS with zero escapes (S4-FC-01 / S4-MEAS-06).

**The engine arm** (``engine_arm``) is the fix. It drives the real ``LucidEngine`` —
``open_incident`` -> ``update`` per transition -> ``resolve`` -> ``close_incident``,
exactly as every other gate number is produced — with a fault monkeypatched into
the real function each step or resolution calls: tension, spawn, the claim compiler,
the observation planner, the shadow, the identifiability test, the shadow verdict
adjustment, gap pricing, the uncertainty read-out, confidence and the Stage 5
export. Each fault is armed for ONE incident only, and only after that incident's
first few calls, so it lands mid-incident; the other incidents are the control for
the per-incident degradation scoping (S4-REV-06). The patch is always undone in a
``finally``.

What counts as a failure, per fault point: an exception escaping any engine entry
point; the faulted incident's verdict (prediction or export) being committal; the
faulted incident carrying no degradation record; any OTHER incident carrying one;
or the Stage 1 results / Stage 2 verdicts the engine consumed changing digest while
it held them.
"""

from __future__ import annotations

import ast
import importlib
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.contracts.threat_prediction_v1 import NON_COMMITTAL_VERDICTS, Verdict
from pocketsec.stage0.gate import REPO_ROOT, GateCheck
from pocketsec.stage1.observation.policy import AdaptiveObservationPolicy
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage4 import gate_criteria as criteria
from pocketsec.stage4 import gate_probes as probes
from pocketsec.stage4.engine.degradation import FALLBACKS, DegradationLedger, Subsystem
from pocketsec.stage4.engine.integrator import integrate_evidence, run_attached_cognition
from pocketsec.stage4.engine.lucid import LucidConfig, LucidEngine
from pocketsec.stage4.labs.baseline_metrics import Replay
from pocketsec.stage4.labs.incident_corpus import IncidentCase
from pocketsec.stage4.visibility.model import VisibilityModel

__all__ = [
    "ENGINE_FAULT_POINTS",
    "EngineArmResult",
    "HookArmResult",
    "engine_arm",
    "hook_arm",
    "optionality_check",
    "t7_importers",
]

#: ``(label, module, attribute, calls_before_arming)``. Every attribute is the name
#: the ENGINE looks up at call time — a module-level name in ``lucid`` or
#: ``lucid_steps``, or the lazily imported planner in ``active_plan`` — so patching
#: it reaches the real call path rather than a copy. ``calls_before_arming`` > 0
#: makes the fault land mid-incident for per-transition calls; resolve-time calls
#: happen once, so they arm at once.
ENGINE_FAULT_POINTS: tuple[tuple[str, str, str, int], ...] = (
    ("tension", "pocketsec.stage4.engine.lucid_steps", "calculate_evidence_tension", 3),
    ("spawn", "pocketsec.stage4.engine.lucid_steps", "spawn_world", 3),
    ("shadow", "pocketsec.stage4.engine.lucid_steps", "estimate_sensor_shadow", 3),
    (
        "active_sensing_planner",
        "pocketsec.stage4.sensing.active_plan",
        "plan_discriminating_observation",
        3,
    ),
    ("claim_compiler", "pocketsec.stage4.engine.lucid_steps", "compile_typed_claim_graph", 0),
    ("identifiability", "pocketsec.stage4.engine.lucid", "test_identifiability", 0),
    ("shadow_verdict", "pocketsec.stage4.engine.lucid", "visibility_adjusted_verdict", 0),
    ("gap_pricing", "pocketsec.stage4.engine.lucid", "gaps_from", 0),
    ("uncertainty", "pocketsec.stage4.engine.lucid", "uncertainty_of", 0),
    ("confidence", "pocketsec.stage4.engine.lucid_steps", "visibility_adjusted_confidence", 0),
    (
        "stage5_export",
        "pocketsec.stage4.engine.lucid_bounds",
        "export_incident_world_record",
        0,
    ),
)

#: Which incident of the walk carries the fault. Not the first, so the incident
#: BEFORE it is a clean control for "a later fault does not reach back", and the
#: ones after it are the control for "an earlier fault does not reach forward".
FAULTED_INCIDENT: int = 1


class InjectedFault(RuntimeError):
    """The fault G4.11 injects. Its own type so an escape is unmistakable."""


@dataclass(frozen=True, slots=True)
class EngineArmResult:
    """What the engine arm found, per fault point, as lists of offences."""

    points: int
    incidents: int
    escaped: tuple[str, ...]
    committal: tuple[str, ...]
    unrecorded: tuple[str, ...]
    leaked: tuple[str, ...]
    digest_changed: tuple[str, ...]
    never_fired: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not (
            self.escaped
            or self.committal
            or self.unrecorded
            or self.leaked
            or self.digest_changed
            or self.never_fired
        )


@dataclass(frozen=True, slots=True)
class HookArmResult:
    """The integrator-hook arm: ten subsystems, the original G4.11 measurement."""

    incidents: int
    escaped: tuple[str, ...]
    digest_changed: tuple[str, ...]
    missing_record: tuple[str, ...]
    wrong_fallback: tuple[str, ...]
    committal: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not (
            self.escaped
            or self.digest_changed
            or self.missing_record
            or self.wrong_fallback
            or self.committal
        )


# --- the engine arm ----------------------------------------------------------


class _Fault:
    """A patched callable that raises once armed. Counts how often it fired."""

    def __init__(self, original: Callable[..., Any], calls_before: int) -> None:
        self.original = original
        self.calls_before = calls_before
        self.armed = False
        self.calls = 0
        self.fired = 0

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        if self.armed:
            self.calls += 1
            if self.calls > self.calls_before:
                self.fired += 1
                raise InjectedFault("G4.11 injected fault")
        return self.original(*args, **kwargs)


@contextmanager
def _patched(module_name: str, attribute: str, calls_before: int) -> Iterator[_Fault]:
    module = importlib.import_module(module_name)
    original = getattr(module, attribute)
    fault = _Fault(original, calls_before)
    setattr(module, attribute, fault)
    try:
        yield fault
    finally:
        setattr(module, attribute, original)


def _walk(
    engine: LucidEngine, replays: Sequence[Replay], fault: _Fault, label: str
) -> tuple[list[str], list[tuple[Any, Any]]]:
    """Drive every replay; arm ``fault`` for ``FAULTED_INCIDENT`` only."""
    escaped: list[str] = []
    outcomes: list[tuple[Any, Any]] = []
    for index, replay in enumerate(replays):
        fault.armed = index == FAULTED_INCIDENT
        fault.calls = 0
        transitions = replay.result.transitions
        epoch = transitions[0].epoch_id if transitions else 0
        try:
            field = engine.open_incident(replay.case.incident_id, epoch)
            spine = replay.pipeline.causal.spine()
            for transition in transitions:
                field = engine.update(field, transition, spine).field
            resolution = engine.resolve(field)
            export = engine.close_incident(field)
            outcomes.append((resolution, export))
        except (KeyboardInterrupt, SystemExit):  # pragma: no cover - never swallowed
            raise
        except BaseException as exc:  # noqa: BLE001 - the escape IS the measurement
            escaped.append(f"{label}@incident{index}: {type(exc).__name__}: {exc}")
            outcomes.append((None, None))
        finally:
            fault.armed = False
    return escaped, outcomes


def _judge(label: str, outcomes: Sequence[tuple[Any, Any]]) -> tuple[list[str], list[str], list[str]]:
    committal: list[str] = []
    unrecorded: list[str] = []
    leaked: list[str] = []
    for index, (resolution, export) in enumerate(outcomes):
        if resolution is None:
            continue
        if index == FAULTED_INCIDENT:
            # The export always follows the fault; the prediction only does when the
            # fault fired during update or resolve (an export fault fires after it).
            judged = [("export", export.verdict)]
            if resolution.degraded:
                judged.append(("prediction", resolution.prediction_verdict))
            for name, verdict in judged:
                if verdict is Verdict.BENIGN or verdict not in NON_COMMITTAL_VERDICTS:
                    committal.append(f"{label}: {name} verdict {verdict.value}")
            if not export.degradations:
                unrecorded.append(f"{label}: faulted incident carries no DegradationRecord")
        elif resolution.degraded or export.degradations:
            leaked.append(
                f"{label}: incident {index} carries {len(export.degradations)} degradation(s) "
                f"it did not have"
            )
    return committal, unrecorded, leaked


def engine_arm(
    replays: Sequence[Replay],
    model: VisibilityModel,
    *,
    config: LucidConfig | None = None,
) -> EngineArmResult:
    """Fault each real engine call site in turn; see the module docstring."""
    results = [replay.result for replay in replays]
    digest_before = criteria.stage1_digest(results)
    verdicts_before = criteria.stage2_verdicts(results)
    escaped: list[str] = []
    committal: list[str] = []
    unrecorded: list[str] = []
    leaked: list[str] = []
    never_fired: list[str] = []
    for label, module_name, attribute, calls_before in ENGINE_FAULT_POINTS:
        engine = LucidEngine(
            config=config if config is not None else LucidConfig(),
            visibility=model,
            observation=AdaptiveObservationPolicy(),
        )
        with _patched(module_name, attribute, calls_before) as fault:
            walk_escaped, outcomes = _walk(engine, replays, fault, label)
        escaped.extend(walk_escaped)
        if fault.fired == 0:
            never_fired.append(label)
        judged = _judge(label, outcomes)
        committal.extend(judged[0])
        unrecorded.extend(judged[1])
        leaked.extend(judged[2])
    digest_changed = []
    if criteria.stage1_digest(results) != digest_before:
        digest_changed.append("Stage 1 ScenarioResult digest")
    if criteria.stage2_verdicts(results) != verdicts_before:
        digest_changed.append("Stage 2 verdicts")
    return EngineArmResult(
        points=len(ENGINE_FAULT_POINTS),
        incidents=len(replays),
        escaped=tuple(escaped),
        committal=tuple(committal),
        unrecorded=tuple(unrecorded),
        leaked=tuple(leaked),
        digest_changed=tuple(digest_changed),
        never_fired=tuple(never_fired),
    )


# --- the hook arm (the original measurement) ---------------------------------


def hook_arm(cases: Sequence[IncidentCase], model: VisibilityModel) -> HookArmResult:
    """Ten integrator hooks, each faulted mid-incident. Moved here from ``gate.py``."""
    # ONE pipeline across the cases, exactly as ``_hook_walk`` runs them: the pipeline
    # carries lineage state across scenarios, so a fresh pipeline per case produces a
    # different (and here wrong) baseline digest.
    pipeline = Stage1Pipeline()
    baseline = [
        pipeline.run_scenario(case.scenario, sensor=criteria.DROPPED_SENSOR, offset=index)
        for index, case in enumerate(cases)
    ]
    baseline_digest = criteria.stage1_digest(baseline)
    baseline_verdicts = criteria.stage2_verdicts(baseline)
    hooks = probes.real_subsystem_hooks(model, observation=AdaptiveObservationPolicy())
    escaped: list[str] = []
    digest_changed: list[str] = []
    missing: list[str] = []
    wrong: list[str] = []
    committal: list[str] = []
    for subsystem in Subsystem:
        ledger = DegradationLedger()
        local, outcomes, run_escaped = _hook_walk(cases, hooks, subsystem, ledger)
        escaped.extend(run_escaped)
        if criteria.stage1_digest(local) != baseline_digest:
            digest_changed.append(f"{subsystem.value}: Stage 1 digest")
        if criteria.stage2_verdicts(local) != baseline_verdicts:
            digest_changed.append(f"{subsystem.value}: Stage 2 verdicts")
        records = [record for record in ledger.records() if record.subsystem is subsystem]
        if not records:
            missing.append(subsystem.value)
        elif any(record.fallback != FALLBACKS[subsystem] for record in records):
            wrong.append(subsystem.value)
        if any(record.at_sequence <= 0 for record in records):
            missing.append(f"{subsystem.value}: fault was not mid-incident")
        for outcome in outcomes:
            verdict = outcome.verdict
            if verdict is Verdict.BENIGN or (
                verdict is not None and verdict not in NON_COMMITTAL_VERDICTS
            ):
                committal.append(f"{subsystem.value}: {verdict.value}")
    return HookArmResult(
        incidents=len(cases),
        escaped=tuple(escaped),
        digest_changed=tuple(digest_changed),
        missing_record=tuple(missing),
        wrong_fallback=tuple(wrong),
        committal=tuple(committal),
    )


def _hook_walk(
    cases: Sequence[IncidentCase], hooks: Any, subsystem: Subsystem, ledger: DegradationLedger
) -> tuple[list[Any], list[Any], list[str]]:
    faulted = probes.with_fault(hooks, subsystem)
    pipeline = Stage1Pipeline()
    results: list[Any] = []
    outcomes: list[Any] = []
    escaped: list[str] = []
    for index, case in enumerate(cases):
        result = pipeline.run_scenario(case.scenario, sensor=criteria.DROPPED_SENSOR, offset=index)
        results.append(result)
        evidence = integrate_evidence(
            result,
            memory=pipeline.causal,
            incident_id=f"g411-{index:04d}",
            sensor=criteria.DROPPED_SENSOR,
        )
        try:
            outcomes.append(run_attached_cognition(evidence, hooks=faulted, ledger=ledger))
        except (KeyboardInterrupt, SystemExit):  # pragma: no cover - never swallowed
            raise
        except BaseException as exc:  # noqa: BLE001 - the escape IS the measurement
            escaped.append(f"{subsystem.value}: {type(exc).__name__}: {exc}")
    return results, outcomes, escaped


def t7_importers() -> list[str]:
    """Every ``path:lineno`` under Stage 1 or 2 that imports Stage 4 (T7).

    AST, not text: a docstring naming the boundary is not a violation of it. The
    resolver is imported rather than copied — S2-AUTH-01 was a hole that existed in the
    structural tests and in a seam check at once, and two copies is how it got closed
    in neither.
    """
    from pocketsec.stage2.gate_criteria import imported_modules

    offenders: list[str] = []
    for stage in ("stage1", "stage2"):
        root = REPO_ROOT / "pocketsec" / stage
        for path in sorted(root.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                for module in imported_modules(node, path):
                    if module == "pocketsec.stage4" or module.startswith("pocketsec.stage4."):
                        offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
    return offenders


def optionality_check(ctx: Any) -> GateCheck:
    """G4.11 — fault injection into the REAL engine, and into the integrator hooks.

    The isolation property, and the one the lead's instruction called a precondition for
    everything else. Until S4-FC-01 this check faulted only the integrator's hook
    harness, and passed with every ``LucidEngine`` entry point replaced by a function
    that raised — so it said nothing about the engine that produces every other gate
    number. ``gate_optionality.engine_arm`` drives that engine with a fault patched
    into each real call site; the hook arm is kept beside it.
    """
    subset = ctx.cases[:12]
    engine = engine_arm(ctx.replays[:12], ctx.visibility.model)
    hooks = hook_arm(subset, ctx.visibility.model)
    t7_offenders = t7_importers()
    passed = engine.passed and hooks.passed and not t7_offenders
    return GateCheck(
        "G4.11",
        "Stage 4 remains optional to core Stage 1-3 detection if it crashes",
        passed,
        f"ENGINE ARM — the real LucidEngine (open_incident -> update -> resolve -> "
        f"close_incident) over {engine.incidents} incidents, with a fault patched into each of "
        f"{engine.points} real call sites {[row[0] for row in ENGINE_FAULT_POINTS]}, "
        f"armed for incident #{FAULTED_INCIDENT} only and mid-incident for the "
        f"per-transition calls. Exceptions that escaped an engine entry point: "
        f"{len(engine.escaped)}" + (f" {list(engine.escaped[:3])}" if engine.escaped else "")
        + f"; faulted incident committal (prediction or Stage 5 export): {len(engine.committal)}"
        + (f" {list(engine.committal[:3])}" if engine.committal else "")
        + f"; faulted incident with no DegradationRecord: {len(engine.unrecorded)}"
        + (f" {list(engine.unrecorded[:3])}" if engine.unrecorded else "")
        + f"; OTHER incidents carrying a degradation they did not have (per-incident "
        f"scoping, S4-REV-06): {len(engine.leaked)}"
        + (f" {list(engine.leaked[:3])}" if engine.leaked else "")
        + f"; fault points that never fired (an arm that injects nothing proves nothing): "
        f"{list(engine.never_fired) or 'none'}; Stage 1 digest / Stage 2 verdicts of the "
        f"results the engine held changed: {list(engine.digest_changed) or 'no'}. "
        f"HOOK ARM — ten integrator subsystems x {hooks.incidents} incidents, each fault raised "
        f"at the incident's middle transition: escapes {len(hooks.escaped)}, Stage 1/2 changed "
        f"{list(hooks.digest_changed) or 'no'}, missing or wrong DegradationRecords "
        f"{list(hooks.missing_record) + list(hooks.wrong_fallback) or 'none'}, committal "
        f"verdicts {len(hooks.committal)}. T7, by AST over every module: modules under "
        f"pocketsec/stage1/ or pocketsec/stage2/ importing pocketsec.stage4: "
        f"{len(t7_offenders)}" + (f" {t7_offenders[:3]}" if t7_offenders else "")
        + f". THE NUMBER THAT DECIDED THIS: engine-arm escapes = {len(engine.escaped)} over "
        f"{engine.points} fault points. HONEST LIMIT: the engine arm faults the call sites "
        f"listed and no others, and the Stage 1 comparison can only detect Stage 4 MUTATING "
        f"what it was handed — Stage 4 runs after Stage 1 and T7 keeps Stages 1-2 from "
        f"importing it, so it cannot change their verdicts any other way.",
    )
