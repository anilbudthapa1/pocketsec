"""Stage 6 gate — the construction and controller criteria: G6.1, G6.6, G6.7, G6.8, G6.11.

These five are properties of how the stage is *built*: who may write trusted state, what
the writer refuses, what a report may carry across the Stage 5 seam, and whether a bad
promotion is reversed. Each is checked two ways at once, because either alone has failed
this project before: an AST scan over the source (a rule nobody can route around by
calling a different function), and a behavioural probe that drives the real subsystem with
a hostile input and watches ``mind.digest()``.

The AST scans re-implement the boundary rules of ``tests/test_stage6_boundary.py`` in
runtime code, because the gate may not import tests. They resolve imports without a copy
of ``stage2.gate_criteria.imported_modules`` (the allow-list forbids importing it here):
a relative import is itself reported, so every import not reported is absolute and its
``node.module`` is its true name (Stage 5's ``gate_construction`` precedent). Sealed names
are read from the constants their owner modules declare (``SEALED_NAMES``), so this file
never spells them — a gate that wrote them would be the breach it scans for.
"""

from __future__ import annotations

import ast
import dataclasses
import sys
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS, Verdict
from pocketsec.stage0.gate import REPO_ROOT, GateCheck
from pocketsec.stage5.stage6_interface import authority_violations, seam_violations
from pocketsec.stage6 import gate_rig as rig
from pocketsec.stage6.capsule import quarantine as gateway_module
from pocketsec.stage6.capsule.experience_capsule import reseal_capsule
from pocketsec.stage6.capsule.quarantine import QuarantineBucket, QuarantineVerdict
from pocketsec.stage6.chamber import evolution as chamber_module
from pocketsec.stage6.chamber.evolution import (
    MAX_CHAMBER_CAPSULES,
    CandidateKind,
    UnquarantinedInputError,
)
from pocketsec.stage6.conservation.gate import default_meter, offline_validation
from pocketsec.stage6.constitution.learning import (
    LifecycleState,
    require_transition,
    verify_constitution,
)
from pocketsec.stage6.export.learning_record import export_learning_record
from pocketsec.stage6.fossils.lineage import NodeKind
from pocketsec.stage6.labs.endurance import StageSixConfig, StageSixLearner
from pocketsec.stage6.labs.poison_suite import build_poison_arm
from pocketsec.stage6.memory.episodic import MAX_EPISODES, EpisodicMemory
from pocketsec.stage6.memory.semantic import LineageError, TrustedKnowledgeState
from pocketsec.stage6.promotion import controller as controller_module
from pocketsec.stage6.promotion.controller import RollbackTrigger
from pocketsec.stage6.shadow.canary import CanaryEvaluator
from pocketsec.stage6.shadow.mind import MIN_SHADOW_SESSIONS, ShadowMind

if TYPE_CHECKING:
    from pocketsec.stage6.gate import Stage6GateContext

__all__ = [
    "check_isolated_evaluation",
    "check_no_authority_path",
    "check_raw_telemetry_cannot_modify",
    "check_retraining_off_endpoint",
    "check_rollback_restores",
    "import_violations",
    "sealed_name_violations",
]

POCKETSEC_ROOT = REPO_ROOT / "pocketsec"
STAGE6_ROOT = POCKETSEC_ROOT / "stage6"
#: Spec §2.5 / ADR-0053, restated for runtime (the boundary test holds the same table).
_PERMITTED_STAGE2 = frozenset({
    "pocketsec.stage2.encoder.ssir_encoder", "pocketsec.stage2.adaptation.quarantine",
    "pocketsec.stage2.adaptation.promotion", "pocketsec.stage2.adaptation.epoch_guard"})
_PERMITTED_STAGE2_FROM_LABS = frozenset({
    "pocketsec.stage2.labs.drift_corpus", "pocketsec.stage2.labs.poison_suite"})
_PERMITTED = {"stage4": frozenset({"pocketsec.stage4.stage5_interface"}),
              "stage5": frozenset({"pocketsec.stage5.stage6_interface"})}
_FREE_STAGES = frozenset({"stage0", "stage1", "stage6"})
_T3_IMPORTER = ("capsule", "quarantine.py")
#: The integrator's harness at the stage root: it may import ``labs`` (spec §4.23).
HARNESS = frozenset({"gate.py", "gate_rig.py", "gate_construction.py", "gate_measured.py",
                     "cli.py"})
_SECOND_GATE_PARAMETERS = frozenset({"min_epochs", "delay_sequences"})
_WRITER_CLASS = "TrustedMind"


# --- the AST side ---------------------------------------------------------------------


def _modules(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imports(tree: ast.Module) -> Iterator[tuple[str, int]]:
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level:
            yield "<relative>", node.lineno
        elif isinstance(node, ast.ImportFrom):
            yield node.module or "", node.lineno
        elif isinstance(node, ast.Import):
            yield from ((alias.name, node.lineno) for alias in node.names)


def _import_reason(module: str, rel: tuple[str, ...]) -> str | None:
    """Why the Stage 6 file at ``rel`` may not import ``module`` (rules 1, 2, 3, 6)."""
    if module == "<relative>":
        return "relative import (unresolvable without the shared resolver)"
    parts = module.split(".")
    if parts[0] != "pocketsec":
        return None if parts[0] in sys.stdlib_module_names else "third-party import (ADR-0001)"
    if len(parts) >= 3 and parts[2].startswith("research"):
        return "research import (ADR-0008/ADR-0050)"
    stage = parts[1] if len(parts) > 1 else ""
    in_labs, harness = rel[0] == "labs", len(rel) == 1 and rel[0] in HARNESS
    if stage == "stage6" and len(parts) > 2 and parts[2] == "labs" and not (in_labs or harness):
        return "runtime imports labs (rule 6)"
    if stage in _FREE_STAGES:
        return None
    if stage == "stage2":
        allowed = _PERMITTED_STAGE2 | (_PERMITTED_STAGE2_FROM_LABS if in_labs else frozenset())
        return None if module in allowed else "stage2 outside the ADR-0051 allow-list"
    if stage in _PERMITTED:
        return None if module in _PERMITTED[stage] else f"{stage} outside the allow-list"
    if stage == "stage3":
        return "Stage 6 consumes nothing from Stage 3 (ADR-0053)"
    return None if rel == _T3_IMPORTER else f"{stage}: only capsule/quarantine.py (T3)"


def import_violations(root: Path | None = None) -> tuple[str, ...]:
    """Rules 1, 2, 3 and 6 over every Stage 6 module."""
    root = root or STAGE6_ROOT
    rows = []
    for path in _modules(root):
        rel = path.relative_to(root).parts
        for module, line in _imports(_tree(path)):
            if (reason := _import_reason(module, rel)) is not None:
                rows.append(f"{'/'.join(rel)}:{line} {module}: {reason}")
    return tuple(rows)


def _named(node: ast.AST) -> str | None:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.arg):
        return node.arg
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _owners() -> dict[str, Path]:
    """Sealed name -> the one file that may mention it, from each owner's own declaration."""
    owners: dict[str, Path] = {}
    modules: tuple[ModuleType, ...] = (controller_module, gateway_module, chamber_module)
    for module in modules:
        path = Path(str(module.__file__)).resolve()
        owners.update({name: path for name in module.SEALED_NAMES})
    return owners


def sealed_name_violations(root: Path | None = None) -> tuple[str, ...]:
    """Rules 4 and 5 over all of ``pocketsec/``: sealed names and ``TrustedMind(...)``."""
    root = root or POCKETSEC_ROOT
    owners = _owners()
    writer = owners[controller_module.SEALED_NAMES[0]]
    rows = []
    for path in _modules(root):
        resolved = path.resolve()
        for node in ast.walk(_tree(path)):
            name = _named(node)
            if name in owners and owners[name] != resolved:
                rows.append(f"{path.relative_to(root)}:{getattr(node, 'lineno', 0)} {name}")
            if (isinstance(node, ast.Call) and _named(node.func) == _WRITER_CLASS
                    and resolved != writer):
                rows.append(f"{path.relative_to(root)}:{node.lineno} {_WRITER_CLASS}(...)")
    return tuple(rows)


def second_gate_violations(root: Path | None = None) -> tuple[str, ...]:
    """Rule 11: no Stage 6 function takes Stage 2's epoch or delay parameters."""
    root = root or STAGE6_ROOT
    rows = []
    for path in _modules(root):
        for node in ast.walk(_tree(path)):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                a = node.args
                names = [x.arg for x in (*a.posonlyargs, *a.args, *a.kwonlyargs)]
                names += [x.arg for x in (a.vararg, a.kwarg) if x is not None]
                rows += [f"{path.name}:{node.lineno} {n}" for n in names
                         if n in _SECOND_GATE_PARAMETERS]
    return tuple(rows)


def _is_dataclass(node: ast.ClassDef) -> bool:
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if _named(target) == "dataclass":
            return True
    return False


def t5_violations(root: Path | None = None) -> tuple[str, ...]:
    """Rule 7: no ``@dataclass`` field under stage6 contains an authority word."""
    root = root or STAGE6_ROOT
    rows = []
    for path in _modules(root):
        for node in ast.walk(_tree(path)):
            if not isinstance(node, ast.ClassDef) or not _is_dataclass(node):
                continue
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    lowered = stmt.target.id.lower()
                    if any(word in lowered for word in FORBIDDEN_AUTHORITY_FIELDS):
                        rows.append(f"{path.name}:{stmt.lineno} {node.name}.{stmt.target.id}")
    return tuple(rows)


def upstream_dependents(root: Path | None = None) -> tuple[str, ...]:
    """Rule 8: no module of Stages 0-5 imports Stage 6 (so no Stage 5 path reaches it)."""
    root = root or POCKETSEC_ROOT
    rows = []
    for stage in range(6):
        for path in _modules(root / f"stage{stage}"):
            for module, line in _imports(_tree(path)):
                if module == "pocketsec.stage6" or module.startswith("pocketsec.stage6."):
                    rows.append(f"stage{stage}/{path.name}:{line} {module}")
    return tuple(rows)


# --- the behavioural side ---------------------------------------------------------------


def _refused(call: Callable[[], Any], *errors: type[BaseException]) -> tuple[bool, str]:
    try:
        call()
    except errors as exc:
        return True, f"{type(exc).__name__}"
    return False, "ACCEPTED"


def _first_verdicts(learner: StageSixLearner, ctx: Stage6GateContext, *,
                    trusted_candidates: int) -> list[QuarantineVerdict]:
    """Real verdicts minted by ``learner``'s own gateway on the compiled stream.

    Stops once at least one verdict exists and ``trusted_candidates`` of them are
    TRUSTED_CANDIDATE; returns what it has if the stream ends first.
    """
    found: list[QuarantineVerdict] = []
    for month in ctx.compiled.months:
        for event in month.events:
            if event.capsule is not None:
                found.append(learner.gateway.admit(event.capsule))
            elif event.decision is not None:
                learner.gateway.record_epoch_decision(event.decision)
            wanted = sum(v.bucket is QuarantineBucket.TRUSTED_CANDIDATE for v in found)
            if found and wanted >= trusted_candidates:
                return found
    return found


def _offer_single_source(learner: StageSixLearner, first: Any, change: Any) -> tuple[int, int]:
    """40 then (after ``change``) 200 offers of ``first``'s one lineage: (refused, admitted)."""
    per, refused, admitted = len(first.steps), 0, 0
    for phase, (epoch, count) in enumerate(((first.epoch_id, 40), (change.epoch_id, 200))):
        if phase == 1:
            learner.gateway.record_epoch_decision(change)
        steps = tuple(dataclasses.replace(step, epoch_id=epoch) for step in first.steps)
        for n in range(-(-count // per)):
            capsule = reseal_capsule(first, steps=steps, epoch_id=epoch,
                                     created_sequence=first.created_sequence + 1000 * phase + n)
            verdict = learner.gateway.admit(capsule)
            refused += gateway_module.REASON_SINGLE_SOURCE in verdict.reasons
            admitted += len(verdict.admissions)
    return refused, admitted


def _single_source_probe(ctx: Stage6GateContext) -> tuple[bool, str]:
    """Spec §0's probe, exactly: ONE lineage's staging steps, 40 offers, a corroborated
    change, 200 offers. Built from arm P1's first poisoned capsule, resealed so every copy
    keeps that one lineage (the arm itself mints a fresh lineage per session, which is a
    different attack — see docs/stage-6-findings.md). The control is the same stream with
    the independence check off (Stage 2's gate alone), reported so the attack is shown real."""
    scenario = build_poison_arm("P1", multiplier=1, seed=ctx.seed)
    change = next(e.decision for e in scenario.events if e.kind == "epoch" and e.decision)
    first = next(e.capsule for e in scenario.events if e.poisoned and e.capsule is not None)
    probe = StageSixLearner(scenario.genesis, seed=ctx.seed, name="gate-single-source-probe")
    control = StageSixLearner(scenario.genesis, seed=ctx.seed, name="gate-single-source-control",
                              config=StageSixConfig(independence_check=False))
    before = probe.trusted_digest()
    refused, admitted = _offer_single_source(probe, first, change)
    _, control_admitted = _offer_single_source(control, first, change)
    groups = len({step.source_group for step in first.steps})
    held = refused > 0 and admitted == 0 and probe.trusted_digest() == before
    return held, (f"spec §0 single-source probe ({groups} lineage, 240 step offers across a "
                  f"corroborated change) through admit: {refused} single_source refusals, "
                  f"{admitted} admissions (control, independence check off: "
                  f"{control_admitted} admissions)")


def _injections(ctx: Stage6GateContext) -> tuple[list[str], int]:
    """The six G6.1(b) injections against one real learner; returns (rows, digest changes)."""
    probe = StageSixLearner(ctx.compiled.genesis, seed=ctx.seed, name="gate-injection-probe")
    controller, before = probe.controller, probe.trusted_digest()
    verdict = _first_verdicts(probe, ctx, trusted_candidates=0)[0]
    raw = ctx.compiled.months[0].eval_steps[0][0].to_encoded()
    forged_verdict = dataclasses.replace(verdict, bucket=QuarantineBucket.TRUSTED_CANDIDATE,
                                         reasons=("gate-forged",))
    foreign = rig.LabChamber(probe.lineage).mint(controller.mind.current(), add=(rig.F1_MOTIF,))
    genesis = controller.mind.current()
    unlineaged = TrustedKnowledgeState(
        version=genesis.version + 1, parent_digest=genesis.digest(),
        active_context=genesis.active_context,
        items=(*genesis.items, *foreign.delta.added), rehearsal=())
    never = genesis.with_changes(threshold=0.9)
    probes: list[tuple[str, Callable[[], Any], tuple[type[BaseException], ...]]] = [
        ("EncodedTransition to controller.submit",
         lambda: controller.submit(raw, holdout=(), hostile=(), variant_seed=1),  # type: ignore[arg-type]
         (ContractError, TypeError)),
        ("hand-built TRUSTED_CANDIDATE verdict to chamber.spawn_evolution_candidate",
         lambda: probe.chamber.spawn_evolution_candidate(
             trusted=genesis, verdicts=[forged_verdict], admissions=[], half_lives=[],
             sequence=1), (UnquarantinedInputError,)),
        ("candidate minted by another chamber to controller.submit",
         lambda: controller.submit(foreign, holdout=(), hostile=(), variant_seed=1),
         (ContractError,)),
        ("state holding a lineage-less item loaded with the DAG",
         lambda: TrustedKnowledgeState.from_canonical_bytes(
             unlineaged.canonical_bytes(), lineage=probe.lineage), (LineageError,)),
        ("rollback to a digest this controller never fossilised",
         lambda: controller.rollback_learning(trigger=RollbackTrigger.OPERATOR_REQUEST,
                                              to_digest=never.digest()), (ContractError,)),
    ]
    rows = []
    for label, call, errors in probes:
        ok, how = _refused(call, *errors)
        rows.append(f"{'refused' if ok else 'ACCEPTED'} ({how}): {label}")
    held, detail = _single_source_probe(ctx)
    rows.append(f"{'refused' if held else 'ACCEPTED'}: {detail}")
    return rows, int(probe.trusted_digest() != before)


def _unrecorded_change(learner: StageSixLearner, before: str, rollbacks: int) -> int:
    """1 if trusted state moved during observe() with no rollback recording it, or the
    mind's cached digest no longer matches its state. Recomputed, never the cached digest:
    a write that bypassed the installer would leave the cache stale (review F1, medium)."""
    mind = learner.controller.mind
    now = mind.current().digest()
    moved = now != before and learner.controller.stats().rolled_back == rollbacks
    return int(moved or now != mind.digest())


def _drive(learner: StageSixLearner, ctx: Stage6GateContext,
           on_consolidate: Callable[[int], None],
           on_observe: Callable[[int], None] | None = None) -> None:
    from pocketsec.stage6.labs.endurance import simulated_snapshot

    for month in ctx.compiled.months:
        for event in month.events:
            if event.kind == "epoch" and event.decision and event.identity is not None:
                learner.on_epoch(event.decision, event.identity, sequence=event.sequence)
            elif event.capsule is not None:
                before = learner.controller.mind.current().digest()
                rollbacks = learner.controller.stats().rolled_back
                learner.observe(event.capsule, sequence=event.sequence)
                if on_observe is not None:
                    on_observe(_unrecorded_change(learner, before, rollbacks))
        last = month.events[-1].sequence if month.events else 0
        before = learner.trusted_digest()
        try:
            learner.consolidate(simulated_snapshot(pressure=month.pressure), sequence=last)
        except RuntimeError:
            on_consolidate(int(learner.trusted_digest() != before))


def _chamber_fault_probe(ctx: Stage6GateContext) -> tuple[int, int, int, int]:
    """G6.1(c): a fault raised inside the chamber, after it did its work, changes nothing.

    Also (d): across every observe() of the run, trusted state never moves unrecorded —
    (observe calls, unrecorded changes)."""
    learner = StageSixLearner(ctx.compiled.genesis, seed=ctx.seed, name="gate-fault-probe")
    real = learner.chamber.spawn_evolution_candidate
    faults: list[int] = []

    def exploding(**kwargs: Any) -> Any:
        real(**kwargs)
        raise RuntimeError("gate-injected fault inside the chamber")

    learner.chamber.spawn_evolution_candidate = exploding  # type: ignore[method-assign]
    observed: list[int] = []
    _drive(learner, ctx, faults.append, observed.append)
    return len(faults), sum(faults), len(observed), sum(observed)


def check_raw_telemetry_cannot_modify(ctx: Stage6GateContext) -> GateCheck:
    """G6.1 — raw telemetry cannot directly modify trusted cognition."""
    sealed, second = sealed_name_violations(), second_gate_violations()
    unbound = verify_constitution()
    rows, changed = _injections(ctx)
    faults, fault_changes, observes, silent = _chamber_fault_probe(ctx)
    refused = sum(row.startswith("refused") for row in rows)
    passed = (not sealed and not second and not unbound and refused == len(rows) == 6
              and changed == 0 and faults > 0 and fault_changes == 0
              and observes > 0 and silent == 0)
    return GateCheck(
        "G6.1", "Raw telemetry cannot directly modify trusted cognition", passed,
        f"(a) sealed-name/TrustedMind violations {list(sealed)}; second Stage 2 gate "
        f"{list(second)}; unresolvable law enforcers {list(unbound)}. (b) {refused}/6 "
        f"injections refused, digest changes {changed}: {'; '.join(rows)}. (c) faults "
        f"injected inside the chamber {faults} (0 = the fault never reached the chamber, "
        f"which fails), digest changes {fault_changes}. (d) observe() calls {observes}, "
        f"trusted-state changes no rollback recorded (recomputed digest) {silent}. The "
        "forged-decision call to the "
        "private installer is tests/test_stage6_promotion.py::"
        "test_private_installer_refuses_an_unminted_decision (rule 4 forbids naming it here)",
    )


# --- G6.6 -------------------------------------------------------------------------------


def _run_promotions_complete(learner: StageSixLearner) -> tuple[int, list[str]]:
    """Every TRUSTED decision in the log is preceded by OFFLINE_VALIDATED, SHADOW, CANARY."""
    decisions = learner.controller.decisions()
    problems, promoted = [], 0
    for index, decision in enumerate(decisions):
        if decision.to_state is not LifecycleState.TRUSTED or decision.candidate_id.startswith(
                "context:"):
            continue
        promoted += 1
        earlier = {d.to_state for d in decisions[:index] if d.candidate_id == decision.candidate_id}
        missing = {LifecycleState.OFFLINE_VALIDATED, LifecycleState.SHADOW,
                   LifecycleState.CANARY} - earlier
        if missing or decision.shadow_digest is None or decision.canary_digest is None:
            problems.append(f"{decision.candidate_id}: missing {sorted(s.value for s in missing)}")
    return promoted, problems


def _rig_isolation() -> tuple[list[str], int]:
    """Skips raise, a thin shadow is refused, a rejected or mutated candidate moves nothing."""
    world = rig.build_world()
    c, notes = world.controller, []
    state_a = rig.promote_f1_f3(world)
    holdout = [rig.skeleton("iso-h2", rig.f2_steps("iso-h2"), Verdict.MALICIOUS)]
    candidate = world.chamber.mint(state_a, add=(rig.F2_MOTIF,), holdout=holdout)
    ok, _ = _refused(lambda: require_transition(LifecycleState.CANDIDATE,
                                                LifecycleState.TRUSTED), ContractError)
    notes.append(f"require_transition(CANDIDATE, TRUSTED) raises: {ok}")
    offline = c.submit(candidate, holdout=holdout, hostile=(), variant_seed=7)
    notes.append(f"a clean F2 candidate -> {offline.to_state.value}")
    skip, _ = _refused(lambda: c.promote_trusted(candidate.candidate_id), ContractError)
    notes.append(f"OFFLINE_VALIDATED -> TRUSTED refused: {skip}")
    holdout.clear()  # mutating what the chamber was handed cannot reach trusted state
    distinct = candidate.proposed is not c.mind.current() and (
        candidate.proposed.digest() != c.mind.digest())
    notes.append(f"proposed is a distinct value: {distinct}")
    thin = offline if offline.to_state is not LifecycleState.OFFLINE_VALIDATED else c.run_shadow(
        candidate.candidate_id, rig.benign_traffic(MIN_SHADOW_SESSIONS - 1, "thin"))
    notes.append(f"shadow on {MIN_SHADOW_SESSIONS - 1} sessions -> {thin.to_state.value}")
    drop_f1 = world.chamber.mint(c.mind.current(), remove=(rig.detector_id(state_a,
                                 rig.F1_MOTIF),), kinds=frozenset({CandidateKind.CONSOLIDATION}))
    rejected = c.submit(drop_f1, holdout=(), hostile=(), variant_seed=7)
    notes.append(f"a G2-failing candidate -> {rejected.to_state.value}")
    passed = (ok and skip and distinct and offline.to_state is LifecycleState.OFFLINE_VALIDATED
              and thin.to_state is LifecycleState.REJECTED
              and rejected.to_state is LifecycleState.REJECTED)
    return notes, int(passed and c.mind.digest() == state_a.digest())


def check_isolated_evaluation(ctx: Stage6GateContext) -> GateCheck:
    """G6.6 — candidate models/cells are evaluated in isolation before influence."""
    promoted, problems = _run_promotions_complete(ctx.stage6)
    try:
        notes, rig_ok = _rig_isolation()
    except ContractError as exc:
        notes, rig_ok = [f"rig scenario aborted by {type(exc).__name__}: {exc}"], 0
    passed = not problems and rig_ok == 1
    return GateCheck(
        "G6.6", "Candidates are evaluated in isolation before influence", passed,
        f"12-month run: {promoted} promotions in the decision log, incomplete paths "
        f"{problems}; rig (lab chamber, real controller): {'; '.join(notes)}; digest "
        f"unchanged by every refusal: {bool(rig_ok)}",
    )


# --- G6.7 -------------------------------------------------------------------------------


def _screened(payloads: Iterable[tuple[str, dict[str, Any]]]) -> list[str]:
    return [f"{name}: {hit}" for name, payload in payloads
            for hit in (*authority_violations(payload, prefix=name),
                        *seam_violations(payload, prefix=name))]


def _forced_failures() -> tuple[list[str], list[tuple[str, dict[str, Any]]], list[float]]:
    world = rig.build_world()
    state_a = rig.promote_f1_f3(world)
    weaker = state_a.with_changes(remove=[rig.detector_id(state_a, rig.F1_MOTIF)])
    traffic = rig.shadow_traffic(4, tag="g67")
    shadow = ShadowMind(sample_every=1, work_budget=1).run_shadow_mind(weaker, state_a, traffic)
    canary = CanaryEvaluator(candidate=weaker, trusted=state_a, policy=rig.RIG_POLICY)
    margins = [o.emitted - o.trusted_score for o in world.canary_observations]
    for s in [*rig.benign_traffic(4, "g67c"), rig.session("g67f1", rig.f1_steps("g67f1"),
                                                           Verdict.MALICIOUS)]:
        observation = canary.observe(s)
        margins.append(observation.emitted - observation.trusted_score)
    report = canary.report()
    drop = world.chamber.mint(state_a, remove=(rig.detector_id(state_a, rig.F1_MOTIF),),
                              kinds=frozenset({CandidateKind.CONSOLIDATION}))
    verdict = offline_validation(drop, trusted=state_a, lineage=world.dag, fossils=world.store,
                                 holdout=(), hostile=(), variant_seed=1, meter=default_meter())
    record = export_learning_record(state_a, lineage=world.dag, fossils=world.store,
                                    rollback_rows=(), simulated=True)
    notes = [f"shadow work_budget=1 aborted={shadow.aborted} ({shadow.abort_reason})",
             f"canary on an F1-dropping state regressed={report.regressed}"]
    payloads = [("shadow", shadow.to_dict()), ("canary", report.to_dict()),
                ("conservation", verdict.to_dict()), ("learning_record", record.to_dict())]
    ok = shadow.aborted and report.regressed
    return (notes if ok else [*notes, "FORCED FAILURE DID NOT OCCUR"]), payloads, margins


def check_no_authority_path(ctx: Stage6GateContext) -> GateCheck:
    """G6.7 — shadow/canary failure cannot grant Stage 5 authority."""
    imports, t5, upstream = import_violations(), t5_violations(), upstream_dependents()
    try:
        notes, payloads, margins = _forced_failures()
    except ContractError as exc:
        notes, payloads, margins = [f"DID NOT OCCUR: rig aborted by {exc}"], [], []
    screened = _screened(payloads)
    run_margin = ctx.stage6.canary_min_margin
    margins += [] if run_margin is None else [run_margin]
    suppressed = [m for m in margins if m < 0]
    forced = not any("DID NOT OCCUR" in n for n in notes)
    passed = (not imports and not t5 and not upstream and forced and not screened
              and bool(margins) and not suppressed)
    return GateCheck(
        "G6.7", "Shadow/canary failure cannot grant Stage 5 authority", passed,
        f"(a) import rules 1/2/3/6 {list(imports)}; T5 fields {list(t5)}; Stages 0-5 "
        f"importing Stage 6 {list(upstream)}. (b) {'; '.join(notes)}; authority/seam hits in "
        f"shadow, canary, conservation and learning-record payloads {screened}. (c) canary "
        f"observations checked {len(margins)} (rig + 12-month run min margin {run_margin}); "
        f"emitted < trusted {len(suppressed)}. (d) covered by rule 8 above",
    )


# --- G6.8 -------------------------------------------------------------------------------


def _probation_rollback(world: rig.RigWorld) -> tuple[bool, str]:
    c = world.controller
    state_a = rig.promote_f1_f3(world)
    pre, pre_bytes = c.mind.digest(), world.store.payload(c.mind.digest())
    holdout = [rig.benign_holdout("g68hb"), rig.skeleton("g68h1", rig.f1_steps("g68h1"),
                                                         Verdict.MALICIOUS)]
    drop_f3 = world.chamber.mint(state_a, remove=(rig.detector_id(state_a, rig.F3_MOTIF),),
                                 holdout=holdout, kinds=frozenset({CandidateKind.CONSOLIDATION}))
    walked = rig.walk(world, drop_f3, holdout=holdout, shadow=rig.shadow_traffic(2, tag="g68"))
    promoted = walked[-1].to_state is LifecycleState.TRUSTED
    live = [*rig.benign_traffic(3, "g68p"), rig.session("g68f3", rig.f3_steps("g68f3"),
                                                        Verdict.MALICIOUS)]
    rollbacks = [r for s in live if (r := c.observe_probation(s)) is not None]
    kinds = {n.kind for n in world.dag.nodes()}
    ok = (promoted and len(rollbacks) == 1 and c.mind.digest() == pre
          and rollbacks[0].restored_bytes_identical is True
          and c.mind.current().canonical_bytes() == pre_bytes
          and {NodeKind.ROLLBACK, NodeKind.REJECTION} <= kinds)
    trigger = rollbacks[0].trigger.value if rollbacks else None
    return ok, (f"F3-dropping candidate passed offline+shadow+canary: {promoted}; automatic "
                f"rollbacks from observe_probation {len(rollbacks)} ({trigger}); digest == "
                f"pre-promotion {c.mind.digest() == pre}; restored_bytes_identical "
                f"{rollbacks[0].restored_bytes_identical if rollbacks else None}; ROLLBACK and "
                f"REJECTION nodes {({NodeKind.ROLLBACK, NodeKind.REJECTION} <= kinds)}")


def _corrupted_fossil_rollback(world: rig.RigWorld, directory: Path) -> tuple[bool, str]:
    c = world.controller
    base = c.mind.current()
    holdout = [rig.skeleton("g68h2", rig.f2_steps("g68h2"), Verdict.MALICIOUS)]
    walked = rig.walk(world, world.chamber.mint(base, add=(rig.F2_MOTIF,), holdout=holdout),
                      holdout=holdout, shadow=rig.shadow_traffic(0, tag="g68b"))
    if walked[-1].to_state is not LifecycleState.TRUSTED:
        return False, f"setup promotion did not reach TRUSTED ({walked[-1].to_state.value})"
    corrupted = base.digest()
    path = directory / f"{corrupted.split(':', 1)[1]}.fossil"
    path.write_bytes(b"\x00gate-corrupt" + path.read_bytes()[13:])
    rollback = c.rollback_learning(trigger=RollbackTrigger.OPERATOR_REQUEST)
    ok = (rollback.trigger is RollbackTrigger.FOSSIL_CORRUPTION
          and corrupted in rollback.skipped_fossils and rollback.restored_bytes_identical
          and c.mind.digest() == rollback.to_digest != corrupted
          and c.mind.current().canonical_bytes() == world.store.payload(rollback.to_digest))
    return ok, (f"corrupted newest fossil {corrupted[:19]}...: trigger "
                f"{rollback.trigger.value}, skipped {len(rollback.skipped_fossils)}, restored "
                f"{rollback.to_digest[:19]}... byte-identical {rollback.restored_bytes_identical}")


def _guarded(probe: Callable[..., tuple[bool, str]], *args: Any) -> tuple[bool, str]:
    """Run a rig scenario; a contract refusal mid-scenario is a FAILED probe, not a crash."""
    try:
        return probe(*args)
    except ContractError as exc:
        return False, f"scenario aborted by {type(exc).__name__}: {exc}"


def check_rollback_restores(ctx: Stage6GateContext) -> GateCheck:
    """G6.8 — learning rollback restores a known-good cognitive state."""
    directory = ctx.fresh_dir("g68-fossils")
    world = rig.build_world(directory)
    auto_ok, auto = _guarded(_probation_rollback, world)
    corrupt_ok, corrupt = (_guarded(_corrupted_fossil_rollback, world, directory) if auto_ok
                           else (False, "fossil-corruption probe not run: the first failed"))
    run_rollbacks = ctx.stage6.rollback_count
    return GateCheck(
        "G6.8", "Learning rollback restores a known-good cognitive state", auto_ok and corrupt_ok,
        f"rig (lab chamber, real controller and fossil store on disk): {auto}. {corrupt}. "
        f"12-month endurance run: {run_rollbacks} rollbacks",
    )


# --- G6.11 ------------------------------------------------------------------------------


def check_retraining_off_endpoint(ctx: Stage6GateContext) -> GateCheck:
    """G6.11 — full retraining/distillation remains off-endpoint unless measured otherwise."""
    labs = [row for row in import_violations() if "rule 6" in row]
    probe = StageSixLearner(ctx.compiled.genesis, seed=ctx.seed, name="gate-capacity-probe")
    issued = [v for v in _first_verdicts(probe, ctx, trusted_candidates=1)
              if v.bucket is QuarantineBucket.TRUSTED_CANDIDATE]
    if issued:
        over, how = _refused(lambda: probe.chamber.spawn_evolution_candidate(
            trusted=probe.controller.mind.current(), verdicts=issued[:1] * (
                MAX_CHAMBER_CAPSULES + 1), admissions=[], half_lives=[], sequence=1),
            ContractError)
    else:
        over, how = False, "no TRUSTED_CANDIDATE verdict on the stream to build the probe from"
    capped, _ = _refused(lambda: EpisodicMemory(capacity=MAX_EPISODES + 1), ValueError,
                         ContractError)
    full = ctx.learners["full-retrain"].cost()
    six = ctx.stage6.cost()
    ratio = (None if not six.work_units else round(full.work_units / six.work_units, 3),
             None if not six.stored_bytes else round(full.stored_bytes / six.stored_bytes, 3))
    return GateCheck(
        "G6.11", "Full retraining/distillation remains off-endpoint", not labs and over and capped,
        f"(a) runtime modules importing labs {labs}; spawn with {MAX_CHAMBER_CAPSULES + 1} "
        f"verdicts refused: {over} ({how}); EpisodicMemory above MAX_EPISODES refused: "
        f"{capped}. (b) measured, not asserted: FullRetrain work {full.work_units} / stored "
        f"{full.stored_bytes} B vs Stage 6 work {six.work_units} / stored {six.stored_bytes} B; "
        f"within-run ratios full/stage6 (work, stored) {ratio}. Every figure is from the "
        "synthetic 12-month timeline",
    )
