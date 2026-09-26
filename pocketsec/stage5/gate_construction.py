"""G5.1-G5.5: the construction criteria, each settled by running the thing it names.

These five are the criteria spec §6.1 says this wave can actually settle on synthetic
data, because they are properties of how the code is built rather than of how well a
plan turns out: the upstream seam is frozen, only typed operators reach privilege,
SENTINEL can deny everything by itself, no text or confidence grants authority, and
identity is re-read immediately before the host is touched. None of them is judged by
reading a document, and each one can be made to fail by a non-compliant input
(``tests/test_stage5_gate.py``).

The executor factories live in ``gate.py`` — the one module outside ``executor/`` and
``recovery/`` that may name ``TransactionalExecutor`` (ADR-0041) — and are imported
inside the functions that use them, so this module never names the class at all.
"""

from __future__ import annotations

import ast
import copy
import importlib
import inspect
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, get_type_hints

from pocketsec.stage0.contracts.common import SCHEMA_REGISTRY, ContractError
from pocketsec.stage0.gate import REPO_ROOT, GateCheck
from pocketsec.stage0.hypotheses import HYPOTHESES
from pocketsec.stage4.stage5_interface import IMPERATIVE_TOKENS, CBFResolutionV1
from pocketsec.stage5.authority.capability import (
    AuthorityGrant,
    Autonomy,
    GrantSource,
    autonomy_of,
    required_authority,
)
from pocketsec.stage5.constitution.invariants import (
    FROZEN_CONSTITUTION,
    AuthorityClass,
    ConstitutionalLaw,
    ResponseConstitution,
)
from pocketsec.stage5.core_ids import PINNED_UPSTREAM_SCHEMAS
from pocketsec.stage5.evidence.preservation_gate import (
    EvidencePreservationVerdict,
    PreservationDecision,
)
from pocketsec.stage5.executor.identity import ManualClock, identity_digest
from pocketsec.stage5.governor import STAGE5_BUDGET, ResourceGovernor
from pocketsec.stage5.labs import adversarial_load as fixtures
from pocketsec.stage5.operators.algebra import (
    DefensiveOperator,
    no_arbitrary_command_path,
)
from pocketsec.stage5.operators.catalog import CATALOG
from pocketsec.stage5.sentinel.kernel import CHECK_ORDER, Decision, DenyReason, SentinelKernel

if TYPE_CHECKING:  # pragma: no cover - annotations only; gate.py imports this module
    from pocketsec.stage5.gate import Stage5GateContext

__all__ = [
    "SEAM_SYMBOLS",
    "SENTINEL_MATRIX",
    "check_frozen_upstream",
    "check_identity_revalidated",
    "check_no_text_grants_authority",
    "check_sentinel_independent_denial",
    "check_typed_operators_only",
    "commit_call_order",
    "confidence_invariance",
    "key_space_agreement",
    "revalidation_adjacent",
    "sentinel_matrix_denials",
    "sentinel_switches",
    "stage5_import_violations",
]

STAGE5_ROOT = REPO_ROOT / "pocketsec" / "stage5"

#: Spec §3.0/§3.1: every upstream symbol Stage 5 consumes. ``imported_modules`` from
#: ``stage2.gate_criteria`` is deliberately absent — §3.1 says it is imported by the
#: boundary *test* only, and trust rule T1 forbids Stage 5 runtime (this gate included)
#: from importing Stage 2 at all. The count reported is whatever this table resolves.
SEAM_SYMBOLS: Mapping[str, tuple[str, ...]] = {
    "pocketsec.stage0.contracts.common": (
        "EvidenceRef", "ContractError", "register_schema", "digest_of_bytes",
        "require_identifier", "require_finite_unit_interval", "require_non_negative_int",
    ),
    "pocketsec.stage0.contracts.threat_prediction_v1": (
        "ThreatPredictionV1", "Verdict", "ComputePath", "FORBIDDEN_AUTHORITY_FIELDS",
    ),
    "pocketsec.stage0.gate": ("GateCheck", "GateReport", "REPO_ROOT"),
    "pocketsec.stage0.benchmark.resource_metrics": ("ResourceSampler", "ResourceMetrics"),
    "pocketsec.stage0.benchmark.profiles": ("check_profile", "ProfileReport", "PROFILES"),
    "pocketsec.stage0.benchmark.harness": ("run_benchmark", "BenchmarkCase", "BenchmarkResult"),
    "pocketsec.stage0.benchmark.dataset": ("SequenceDataset", "LabelledSequence"),
    "pocketsec.stage0.experiments.registry": ("ExperimentRegistry",),
    "pocketsec.stage0.experiments.ids": ("format_experiment_id",),
    "pocketsec.stage0.prior_art": ("PriorArtLedger",),
    "pocketsec.stage0.hypotheses": ("HYPOTHESES",),
    "pocketsec.stage1.state.security_state": ("SecurityStateV1", "StateDelta", "DIMENSIONS"),
    "pocketsec.stage1.state.potential": ("phi", "delta_phi", "PhiBreakdown"),
    "pocketsec.stage1.epoch.model": ("Epoch", "SystemIdentity", "EpochDecision"),
    "pocketsec.stage1.observation.policy": (
        "ObservationLevel", "MANDATORY_SIGNALS", "EscalationDecision",
    ),
    "pocketsec.stage1.telemetry.raw_event_v1": ("SensorPath",),
    "pocketsec.stage3.cells.schema": (
        "KnowledgeCellV1", "AssuranceLevel", "CellPhase", "HardConstraint", "ConstraintKind",
    ),
    "pocketsec.stage4.stage5_interface": (
        "CBFResolutionV1", "IncidentHypothesis", "InformationGap", "CBF_RESOLUTION_V1_ID",
        "MAX_HYPOTHESES_PER_RESOLUTION", "MAX_GAPS_PER_RESOLUTION", "seam_violations",
    ),
}

#: Modules whose import registers the five pinned upstream schemas.
_SCHEMA_OWNERS = (
    "pocketsec.stage0.contracts.security_event_v1",
    "pocketsec.stage0.contracts.threat_prediction_v1",
    "pocketsec.stage1.ssir.transition",
    "pocketsec.stage3.cells.schema",
    "pocketsec.stage4.stage5_interface",
)

_PERMITTED_STAGE4 = "pocketsec.stage4.stage5_interface"
_PERMITTED_STAGE3 = ("pocketsec.stage3.cells", "pocketsec.stage3.bytecode")
_FORBIDDEN_STAGES = tuple(f"pocketsec.stage{n}" for n in (2, 6, 7, 8, 9, 10, 11, 12))
_EXPECTED_HYPOTHESES = frozenset(f"H{index}" for index in range(9))


# --- G5.1 -----------------------------------------------------------------------------


def _missing_seam_symbols() -> tuple[int, list[str]]:
    resolved, missing = 0, []
    for module_name, names in SEAM_SYMBOLS.items():
        module = importlib.import_module(module_name)
        for name in names:
            if hasattr(module, name):
                resolved += 1
            else:
                missing.append(f"{module_name}.{name}")
    return resolved, missing


def _import_violation(module: str) -> str | None:
    root = module.split(".")[0]
    if root != "pocketsec" and root not in sys.stdlib_module_names:
        return "third-party import (ADR-0001/ADR-0040)"
    parts = module.split(".")
    if len(parts) >= 3 and parts[0] == "pocketsec" and parts[2] == "research":
        return "research import (ADR-0008/ADR-0040)"
    if module.startswith("pocketsec.stage4") and not module.startswith(_PERMITTED_STAGE4):
        return "Stage 4 import other than stage5_interface (ADR-0045)"
    if module.startswith("pocketsec.stage3") and not module.startswith(_PERMITTED_STAGE3):
        return "Stage 3 import outside cells/bytecode (T1)"
    if any(module == stage or module.startswith(stage + ".") for stage in _FORBIDDEN_STAGES):
        return "import of Stage 2 or a downstream stage (T1)"
    return None


def stage5_import_violations(root: Any = STAGE5_ROOT) -> tuple[str, ...]:
    """Every R1/R2/T1 import violation under ``root``, re-checked unconditionally.

    Resolution without a copy of ``stage2.gate_criteria.imported_modules`` (which T1
    forbids this gate from importing): a relative import is itself reported as a
    violation, so every import that is *not* reported is absolute and ``node.module``
    is its true name. Stage 5 has none today; this keeps the rule decidable if one lands.
    """
    rows: list[str] = []
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level:
                rows.append(f"{path.name}:{node.lineno}: relative import is unresolvable here")
                continue
            names = (
                [alias.name for alias in node.names] if isinstance(node, ast.Import)
                else [node.module or ""] if isinstance(node, ast.ImportFrom) else []
            )
            for name in names:
                reason = _import_violation(name)
                if reason is not None:
                    rows.append(f"{path.name}:{getattr(node, 'lineno', 0)}: {name}: {reason}")
    return tuple(rows)


def _schema_drift() -> list[str]:
    for owner in _SCHEMA_OWNERS:
        importlib.import_module(owner)
    return [
        f"{schema_id} pinned {version} registered {SCHEMA_REGISTRY.get(schema_id)}"
        for schema_id, version in PINNED_UPSTREAM_SCHEMAS.items()
        if SCHEMA_REGISTRY.get(schema_id) != version
    ]


def check_frozen_upstream(ctx: Stage5GateContext) -> GateCheck:
    """G5.1 — Stages 0-4 remain unchanged/frozen interfaces for Stage 5 evaluation."""
    from pocketsec.stage5.gate import registry_digest

    resolved, missing = _missing_seam_symbols()
    drift = _schema_drift()
    imports = stage5_import_violations()
    hypotheses_ok = set(HYPOTHESES) == _EXPECTED_HYPOTHESES
    ledger_ok = registry_digest() == ctx.registry_before
    passed = not missing and not drift and not imports and hypotheses_ok and ledger_ok
    return GateCheck(
        "G5.1",
        "Stages 0-4 remain frozen interfaces for Stage 5",
        passed,
        f"{resolved} of {resolved + len(missing)} seam symbols resolve (missing {missing}); "
        f"{len(PINNED_UPSTREAM_SCHEMAS) - len(drift)}/{len(PINNED_UPSTREAM_SCHEMAS)} pinned "
        f"schema versions match SCHEMA_REGISTRY {drift or ''}; {len(imports)} R1/R2/T1 import "
        f"violations under pocketsec/stage5 {list(imports)[:3]}; HYPOTHESES == H0..H8: "
        f"{hypotheses_ok}; experiments/registry.jsonl byte-identical since the run began: "
        f"{ledger_ok}. Stage 4's source is not diffed: another wave is editing it (§2.6)",
    )


# --- G5.2 -----------------------------------------------------------------------------


def _typed_entry_hint(executor_type: Any) -> bool:
    return get_type_hints(executor_type.execute).get("operator") is DefensiveOperator


def _forged_arguments(operator: DefensiveOperator) -> Sequence[tuple[str, object]]:
    forged_spec = replace(operator.spec)
    deep = copy.deepcopy(operator)
    return (
        ("str", operator.spec.operator_id),
        ("dict", {"operator_id": operator.spec.operator_id, "argv": ["kill", "-9", "1"]}),
        ("SimpleNamespace", SimpleNamespace(
            spec=operator.spec, target=operator.target, incident_id=operator.incident_id,
            ttl_seconds=operator.ttl_seconds, evidence_refs=(), argv=lambda: ("sh", "-c", "id"),
        )),
        ("forged OperatorSpec", forged_spec),
        ("DefensiveOperator with deep-copied spec", deep),
    )


def _refused_constructions(ctx: Stage5GateContext) -> tuple[int, int, list[str]]:
    """G5.2(b): five forged arguments at a real executor; each must raise before the host."""
    from pocketsec.stage5.gate import executor_for_rig
    from pocketsec.stage5.labs.baselines import build_rig

    rig = build_rig(ctx.corpus[0])
    candidate = next(c for c in rig.field.candidates if c.operator.spec.operator_class >= 2)
    operator = candidate.operator
    token = fixtures.mint_token(rig.tokens, operator, action_id="act.g52.forged")
    before = rig.host.apply_calls
    refused, leaked = 0, []
    for label, forged in _forged_arguments(operator):
        try:
            executor_for_rig(rig).execute(forged, token, resolution=rig.case.resolution)  # type: ignore[arg-type]
        except (ContractError, TypeError):
            refused += 1
            continue
        except Exception as exc:
            leaked.append(f"{label}:{type(exc).__name__}")
            continue
        leaked.append(label)
    return refused, rig.host.apply_calls - before, leaked


def _outside_catalog_refused() -> bool:
    """G5.2(c): an ``OperatorSpec`` built outside ``catalog.py`` cannot exist."""
    entry = next(iter(CATALOG.values()))
    try:
        replace(entry, catalog_token=object())
    except ContractError:
        return True
    return False


def check_typed_operators_only(ctx: Stage5GateContext) -> GateCheck:
    """G5.2 — only typed operators reach privilege."""
    from pocketsec.stage5.gate import TransactionalExecutor

    hinted = _typed_entry_hint(TransactionalExecutor)
    refused, applied, leaked = _refused_constructions(ctx)
    spec_refused = _outside_catalog_refused()
    shell = no_arbitrary_command_path(STAGE5_ROOT)
    passed = hinted and refused == 5 and applied == 0 and spec_refused and shell == ()
    return GateCheck(
        "G5.2",
        "Only typed operators reach privilege",
        passed,
        f"(a) get_type_hints(TransactionalExecutor.execute)['operator'] is DefensiveOperator: "
        f"{hinted}; (b) {refused} of 5 forged arguments (str, dict, SimpleNamespace with its "
        f"own argv, structurally equal OperatorSpec, deep-copied operator) raised at a real "
        f"executor, host.apply calls during them {applied}, leaked {leaked}; (c) "
        f"OperatorSpec outside catalog.py refused: {spec_refused}; (d) "
        f"no_arbitrary_command_path(pocketsec/stage5) rows: {len(shell)} {list(shell)[:2]}",
    )


# --- G5.3 -----------------------------------------------------------------------------


class _Case:
    """One compliant SENTINEL input with the planner maximally in favour (support 1.0)."""

    def __init__(self, operator_id: str) -> None:
        self.clock = ManualClock(1_000)
        self.kernel = fixtures.build_kernel(clock=self.clock)
        store = fixtures.build_token_store(clock=self.clock)
        self.snapshot = fixtures.build_snapshot()
        self.operator = fixtures.build_operator(operator_id)
        resolution = fixtures.build_resolution(supports=(1.0,), uncertainty=0.0)
        self.token = fixtures.mint_token(store, self.operator)
        self.evidence = fixtures.preserved_verdict(self.operator, resolution, self.snapshot)
        self.observed_identity = self.operator.target.identity
        self.journal_bytes = 0
        self.active_leases = 0
        self.recent_action_times: tuple[int, ...] = ()
        self.concurrent_operator_ids: frozenset[str] = frozenset()

    def arguments(self) -> dict[str, Any]:
        return {
            "operator": self.operator, "token": self.token, "evidence": self.evidence,
            "observed_identity": self.observed_identity, "snapshot": self.snapshot,
            "journal_bytes": self.journal_bytes, "active_leases": self.active_leases,
            "recent_action_times": self.recent_action_times,
            "concurrent_operator_ids": self.concurrent_operator_ids,
        }

    def verify(self) -> Any:
        args = self.arguments()
        return self.kernel.verify(args.pop("operator"), args.pop("token"), **args)


def _tamper(instance: Any, name: str, value: Any) -> None:
    """A frozen record handed to the kernel already corrupted; the kernel must refuse it."""
    object.__setattr__(instance, name, value)


def _zero_duration_invariants() -> Any:
    from pocketsec.stage5.constitution.schema import (
        InvariantKind,
        MissionInvariant,
        MissionInvariantSet,
    )

    return MissionInvariantSet((MissionInvariant(
        "MI-ZERO", InvariantKind.MAX_CONTAINMENT_DURATION, "", 0, "no lease may be held",
    ),))


def _swap_authority(case: _Case) -> None:
    other = AuthorityClass.A1 if case.token.authority is AuthorityClass.A0 else AuthorityClass.A0
    _tamper(case.token, "authority", other)


def _refused_evidence(case: _Case) -> None:
    case.evidence = EvidencePreservationVerdict(
        PreservationDecision.REFUSED_WOULD_DESTROY, case.evidence.bundle,
        ("process_memory",), (), None, "gate mutation",
    )


def _bundle_free_exception(case: _Case) -> None:
    case.evidence = EvidencePreservationVerdict(
        PreservationDecision.EXCEPTION_GRANTED, None, (), (), AuthorityClass.A5, "no bundle"
    )


#: Thirteen single-input mutations, one per DenyReason a check can reach. Each makes
#: exactly one SENTINEL input non-compliant while the planner is maximally in favour.
SENTINEL_MATRIX: tuple[tuple[DenyReason, Callable[[_Case], None]], ...] = (
    (DenyReason.SCHEMA, lambda c: setattr(c, "token", fixtures.token_shaped_impostor(c.token))),
    (DenyReason.SIGNATURE_VERSION, lambda c: _tamper(c.token, "schema_version", "0.0.1")),
    (DenyReason.CONSTITUTION, lambda c: _tamper(c.token, "authority", AuthorityClass.AX)),
    (DenyReason.AUTHORITY, _swap_authority),
    (DenyReason.SCOPE, lambda c: _tamper(c.token, "target_digest", "sha256:" + "0" * 64)),
    (DenyReason.TARGET_IDENTITY, lambda c: setattr(
        c, "observed_identity", fixtures.identity_for(start_time_ticks=123_456))),
    (DenyReason.PRECONDITION, lambda c: setattr(
        c, "snapshot", fixtures.build_snapshot(include_target=False))),
    (DenyReason.MISSION_INVARIANT, lambda c: setattr(c, "kernel", fixtures.build_kernel(
        clock=c.clock, invariants=_zero_duration_invariants()))),
    (DenyReason.EVIDENCE_PRESERVATION, _refused_evidence),
    (DenyReason.ROLLBACK_MISSING, _bundle_free_exception),
    (DenyReason.EXPIRY, lambda c: c.clock.advance(c.token.expiry - c.clock.now() + 1)),
    (DenyReason.RESOURCE_LIMIT, lambda c: setattr(
        c, "journal_bytes", STAGE5_BUDGET.max_rollback_journal_bytes + 1)),
    (DenyReason.FORBIDDEN_COMBINATION, lambda c: setattr(
        c, "concurrent_operator_ids", frozenset({c.operator.spec.operator_id}))),
)


def sentinel_matrix_denials() -> tuple[int, int, int, list[str]]:
    """``(compliant_passes, denials, cases, failures)`` over every operator x mutation."""
    passes, denials, failures = 0, 0, []
    for operator_id in sorted(CATALOG):
        if _Case(operator_id).verify().decision is Decision.PASS:
            passes += 1
        else:
            failures.append(f"{operator_id}/compliant-baseline-denied")
        for reason, mutate in SENTINEL_MATRIX:
            case = _Case(operator_id)
            mutate(case)
            verdict = case.verify()
            if verdict.decision is Decision.DENY and reason in verdict.reasons:
                denials += 1
            else:
                failures.append(f"{operator_id}/{reason.value}")
    return passes, denials, len(CATALOG) * len(SENTINEL_MATRIX), failures


def _independence_groups() -> dict[str, bool]:
    return {
        "no bypass name": _no_bypass_name(),
        "no module-level switch": sentinel_switches() == (),
        "None -> MISSING_INPUT": _none_inputs_deny(),
        "weaker constitution unconstructable": _weak_constitution_refused(),
        "raising check -> KERNEL_FAULT": _raising_checks_deny(),
    }


def _no_bypass_name() -> bool:
    import re

    pattern = re.compile(r"(?i)force|override|bypass|skip|disable|dry_?run|unsafe|trust_me")
    for path in sorted((STAGE5_ROOT / "sentinel").glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            name = getattr(node, "name", None) or getattr(node, "arg", None)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                name = node.id
            if isinstance(name, str) and pattern.search(name):
                return False
    return True


#: The files whose module state could switch SENTINEL off: the kernel, its monitors and
#: the evidence gate it reads (the F5 trusted surface).
_SENTINEL_SURFACE = ("sentinel/kernel.py", "sentinel/monitors.py",
                     "evidence/preservation_gate.py")


def sentinel_switches(paths: Sequence[Any] | None = None) -> tuple[str, ...]:
    """Every structural switch in the SENTINEL surface, whatever it is called (F4).

    The name regex above sees only the spellings it lists; a flag spelled ``ENFORCING``
    passed it. This rule is on shape instead: a module-level binding to ``True``,
    ``False`` or ``None``, a ``global`` statement (a function rebinding module state), or
    a read of ``globals()``, ``os.environ`` or ``getenv`` — the three ways module state or
    configuration can decide whether the kernel runs its checks.
    """
    rows: list[str] = []
    for path in paths if paths is not None else [STAGE5_ROOT / p for p in _SENTINEL_SURFACE]:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in tree.body:
            if _binds_a_switch(node):
                rows.append(f"{path.name}:{node.lineno}: module-level bool/None binding")
        for node in ast.walk(tree):
            if isinstance(node, ast.Global):
                rows.append(f"{path.name}:{node.lineno}: global {node.names}")
            name = node.id if isinstance(node, ast.Name) else getattr(node, "attr", None)
            if name in {"globals", "environ", "getenv"}:
                rows.append(f"{path.name}:{node.lineno}: reads {name}")
    return tuple(rows)


def _binds_a_switch(node: ast.stmt) -> bool:
    """A module-level ``NAME = True/False/None``: the shape of an on/off flag."""
    if not isinstance(node, (ast.Assign, ast.AnnAssign)):
        return False
    value = node.value
    return isinstance(value, ast.Constant) and any(
        value.value is constant for constant in (True, False, None)
    )


def _none_inputs_deny() -> bool:
    for argument in _Case("SUSPEND_PROCESS").arguments():
        case = _Case("SUSPEND_PROCESS")
        setattr(case, argument, None)
        verdict = case.verify()
        if verdict.decision is not Decision.DENY or DenyReason.MISSING_INPUT not in verdict.reasons:
            return False
    return True


def _weak_constitution_refused() -> bool:
    """A law dropped, or the autonomy ceiling raised to A5: neither may become an object."""
    attempts: tuple[tuple[tuple[ConstitutionalLaw, ...], AuthorityClass], ...] = (
        (tuple(ConstitutionalLaw)[:-1], FROZEN_CONSTITUTION.max_autonomous_authority),
        (tuple(ConstitutionalLaw), AuthorityClass.A5),
    )
    for laws, ceiling in attempts:
        try:
            ResponseConstitution(
                laws=laws, max_autonomous_authority=ceiling,
                prohibited_operator_classes=FROZEN_CONSTITUTION.prohibited_operator_classes,
                policy_version="1.0.0",
            )
        except ContractError:
            continue
        return False
    return True


def _raising_checks_deny() -> bool:
    def explode(self: SentinelKernel, request: Any) -> tuple[DenyReason, ...]:
        raise RuntimeError("gate-injected kernel fault")

    for name in CHECK_ORDER:
        attribute = f"_check_{name}"
        original = getattr(SentinelKernel, attribute)
        setattr(SentinelKernel, attribute, explode)
        try:
            verdict = _Case("SUSPEND_PROCESS").verify()
        finally:
            setattr(SentinelKernel, attribute, original)
        if verdict.decision is not Decision.DENY or DenyReason.KERNEL_FAULT not in verdict.reasons:
            return False
    return True


def check_sentinel_independent_denial() -> GateCheck:
    """G5.3 — SENTINEL can independently deny every action regardless of planner output."""
    passes, denials, cases, failures = sentinel_matrix_denials()
    groups = _independence_groups()
    keyword_only = {
        name for name, parameter in inspect.signature(SentinelKernel.__init__).parameters.items()
        if parameter.kind is inspect.Parameter.KEYWORD_ONLY
    }
    init_ok = keyword_only == {"constitution", "invariants", "clock"}
    passed = passes == len(CATALOG) and denials == cases and all(groups.values()) and init_ok
    return GateCheck(
        "G5.3",
        "SENTINEL independently denies every action regardless of planner output",
        passed,
        f"{denials} of {cases} required denials ({len(CATALOG)} operators x "
        f"{len(SENTINEL_MATRIX)} single-input mutations, planner at support 1.0 / "
        f"uncertainty 0.0); compliant baselines passing {passes}/{len(CATALOG)}; failures "
        f"{failures[:4]}; independence groups {groups}; __init__ keyword-only parameters "
        f"{sorted(keyword_only)}",
    )


# --- G5.4 -----------------------------------------------------------------------------

_HIGH, _LOW = 0.99, 0.01


def _with_leading_support(resolution: CBFResolutionV1, support: float) -> CBFResolutionV1:
    rows = [dict(row) for row in resolution.hypotheses]
    leading = max(range(len(rows)), key=lambda index: float(rows[index]["support"]))
    rows[leading]["support"] = support
    return replace(resolution, hypotheses=tuple(rows))


def _authority_signature(plan: Any) -> tuple[object, ...]:
    chosen = plan.chosen
    if chosen is None:
        return (None, None, None)
    contract = plan.human_contract
    return (
        chosen.authority,
        required_authority(chosen.operator.spec),
        None if contract is None else contract.approval_required,
    )


def _plan(case: Any, resolution: CBFResolutionV1) -> Any:
    from pocketsec.stage5.aegis.planner import AegisPlanner, PlannerConfig
    from pocketsec.stage5.cells.response_cells import ResponseCellField
    from pocketsec.stage5.executor.lease import DEFAULT_HYSTERESIS, HysteresisController
    from pocketsec.stage5.memory.effectiveness import EffectivenessMemory

    snapshot = case.host.snapshot()
    planner = AegisPlanner(
        config=PlannerConfig(), constitution=FROZEN_CONSTITUTION, invariants=case.invariants,
        governor=ResourceGovernor(), memory=EffectivenessMemory(), cells=ResponseCellField(),
        hysteresis=HysteresisController(policy=DEFAULT_HYSTERESIS, clock=ManualClock(snapshot.at)),
        harm=case.harm,
    )
    return planner.plan(resolution, snapshot, now=snapshot.at, active_leases=())


def _considered(plan: Any) -> tuple[Any, ...]:
    return (*plan.frontier, *([plan.chosen] if plan.chosen is not None else []))


def _proposed(plan: Any) -> dict[str, object]:
    return {c.operator.spec.operator_id: c.authority for c in _considered(plan)}


def confidence_invariance(cases: Sequence[Any]) -> dict[str, Any]:
    """G5.4(a) over each case emitted at leading support 0.99 and at 0.01.

    ``identical`` is the spec's literal count (chosen authority, required class and
    approval_required all equal). Two finer readings are reported beside it because the
    literal one conflates *what is proposed* with *what is granted*: ``autonomy_equal``
    counts cases whose ACT-or-not decision is the same at both supports (authority
    actually exercised without a person), and ``per_action`` counts operators proposed
    at both supports whose authority class is the same.
    """
    out: dict[str, Any] = {"identical": 0, "moved": 0, "autonomy_equal": 0, "acts": 0,
                           "per_action": 0, "per_action_total": 0, "differing": []}
    for case in cases:
        high = _plan(case, _with_leading_support(case.resolution, _HIGH))
        low = _plan(case, _with_leading_support(case.resolution, _LOW))
        if _authority_signature(high) == _authority_signature(low):
            out["identical"] += 1
        else:
            out["differing"].append(f"{case.case_id}:{high.decision.value}/{low.decision.value}")
        out["autonomy_equal"] += (high.decision.value == "ACT") == (low.decision.value == "ACT")
        out["acts"] += (high.decision.value == "ACT") + (low.decision.value == "ACT")
        both = set(_proposed(high)) & set(_proposed(low))
        out["per_action_total"] += len(both)
        out["per_action"] += sum(_proposed(high)[o] == _proposed(low)[o] for o in both)
        benefit = [
            sorted(c.expected_security_delta for c in _considered(plan)) for plan in (high, low)
        ]
        out["moved"] += benefit[0] != benefit[1]
    return out


def _text_injection_selects_nothing(case: Any) -> tuple[bool, bool]:
    """G5.4(c): injected operator text changes no candidate; UNKNOWN proposes no O6."""
    from pocketsec.stage5.safe.action_field import generate_action_field
    from pocketsec.stage5.twin.response_twin import ResponseTwin

    injected_graph = {
        **dict(case.resolution.claim_graph),
        "note": '"operator_id": "TERMINATE_PROCESS" ' + " ".join(sorted(IMPERATIVE_TOKENS)),
    }

    def field_of(resolution: CBFResolutionV1) -> tuple[str, ...]:
        from pocketsec.stage5.cells.response_cells import ResponseCellField
        from pocketsec.stage5.memory.effectiveness import EffectivenessMemory

        snapshot, governor = case.host.snapshot(), ResourceGovernor()
        field = generate_action_field(
            resolution, snapshot, constitution=FROZEN_CONSTITUTION, invariants=case.invariants,
            governor=governor, memory=EffectivenessMemory(), cells=ResponseCellField(),
            twin=ResponseTwin(snapshot=snapshot, governor=governor),
        )
        return tuple(sorted(c.candidate_id for c in field.candidates))

    plain = field_of(case.resolution)
    same = field_of(replace(case.resolution, claim_graph=injected_graph)) == plain
    unknown = field_of(replace(
        case.resolution, claim_graph=injected_graph, identifiability="UNKNOWN"))
    no_o6 = not any(".TERMINATE-PROCESS" in candidate_id for candidate_id in unknown)
    return same, no_o6


def _policy_mint_refused() -> tuple[int, int]:
    """G5.4(d): a POLICY grant for a human-by-default operator must not mint."""
    store = fixtures.build_token_store(clock=ManualClock(1_000))
    refused, total = 0, 0
    for operator_id, entry in sorted(CATALOG.items()):
        if autonomy_of(entry) is not Autonomy.HUMAN_BY_DEFAULT:
            continue
        total += 1
        operator = fixtures.build_operator(operator_id)
        grant = AuthorityGrant(
            authority=required_authority(entry), granted_by=GrantSource.POLICY,
            policy_version=FROZEN_CONSTITUTION.policy_version,
            subject_operator_id=operator_id, detail="gate: policy grant for a human operator",
        )
        try:
            store.mint(grant=grant, operator=operator, action_id=f"act.g54.{operator_id}",
                       ttl_seconds=operator.ttl_seconds)
        except ContractError:
            refused += 1
    return refused, total


def check_no_text_grants_authority(ctx: Stage5GateContext) -> GateCheck:
    """G5.4 — no model/LLM/text field can grant authority or construct privileged commands.

    Judged on the spec's literal clause (a): every case must reach an identical
    (authority, required class, approval_required) at both supports. The finer readings
    are reported, not substituted — if the literal clause fails, the check fails.
    """
    inv = confidence_invariance(ctx.corpus)
    sources = {member.value for member in GrantSource}
    sources_ok = sources == {"POLICY", "HUMAN"}
    injection = [_text_injection_selects_nothing(case) for case in ctx.corpus[:4]]
    text_ok = all(same and no_o6 for same, no_o6 in injection)
    refused, total = _policy_mint_refused()
    count = len(ctx.corpus)
    passed = (inv["identical"] == count and inv["moved"] > 0 and sources_ok and text_ok
              and total > 0 and refused == total)
    return GateCheck(
        "G5.4",
        "No model/LLM/text field grants authority or builds a privileged command",
        passed,
        f"(a) {inv['identical']} of {count} corpus cases reach an identical (authority, "
        f"required class, approval_required) at leading support 0.99 and 0.01; differing "
        f"(decision at 0.99/0.01) {inv['differing']}"
        f"; ACT-or-not identical {inv['autonomy_equal']}/{count} ({inv['acts']} ACT decisions "
        f"in {2 * count} plans, so this reading is vacuous here); per-operator authority "
        f"identical {inv['per_action']}/{inv['per_action_total']} operators proposed at both; "
        f"benefit estimate moved on {inv['moved']} (non-vacuity); (b) GrantSource = "
        f"{sorted(sources)}; (c) injected operator/imperative text changed no candidate and "
        f"proposed no O6 under UNKNOWN on {sum(a and b for a, b in injection)}/{len(injection)} "
        f"cases; (d) POLICY grant refused for {refused}/{total} HUMAN_BY_DEFAULT operators",
    )


# --- G5.5 -----------------------------------------------------------------------------


def _call_name(node: ast.Call) -> str:
    parts: list[str] = []
    current: ast.expr = node.func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def commit_call_order(source: str) -> list[str]:
    """Calls in ``TransactionalExecutor._commit``'s body, in source order."""
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "TransactionalExecutor":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == "_commit":
                    calls = [c for c in ast.walk(item) if isinstance(c, ast.Call)]
                    calls.sort(key=lambda c: (c.lineno, c.col_offset))
                    return [_call_name(c) for c in calls]
    return []


def revalidation_adjacent(calls: Sequence[str]) -> bool:
    """``revalidate`` is immediately followed by ``self._host.apply``: nothing between."""
    if "revalidate" not in calls or "self._host.apply" not in calls:
        return False
    first = calls.index("revalidate")
    return calls.index("self._host.apply") == first + 1


def _action_key_space(action: Any) -> set[str]:
    """Every string that names this action's target, from each of its producers."""
    receipt, rig = action.receipt, action.rig
    keys = {
        identity_digest(action.operator.target.identity),
        action.operator.target.identity.digest(),
        action.token.target_digest,
        receipt.target_digest,
        receipt.sentinel_verdict.target_digest,
    }
    keys.update(lease.target_digest for lease in rig.leases.leases_on(receipt.target_digest))
    keys.update(
        entry.target_digest for entry in rig.journal.entries()
        if entry.action_id == receipt.action_id
    )
    return keys


def key_space_agreement(actions: Sequence[Any], *, limit: int = 20) -> tuple[int, int]:
    """§4.9 Rule A over ``limit`` committed actions: ``(single_key_space, examined)``.

    Token, SENTINEL verdict, receipt, lease and journal must all name the target by the
    one ``identity_digest`` string; two strings here is two key spaces that can never join.
    """
    committed = [action for action in actions if action.receipt.committed()][:limit]
    return sum(len(_action_key_space(action)) == 1 for action in committed), len(committed)


def check_identity_revalidated(ctx: Stage5GateContext) -> GateCheck:
    """G5.5 — target identity is revalidated immediately before intervention."""
    from pocketsec.stage5.gate import executor_for_race
    from pocketsec.stage5.labs.toctou import toctou_suite

    source = (STAGE5_ROOT / "executor" / "transactional.py").read_text(encoding="utf-8")
    adjacent = revalidation_adjacent(commit_call_order(source))
    races = toctou_suite(build_executor=executor_for_race)
    refused = sum(race.refused for race in races)
    wrong_target = sum(race.apply_calls for race in races)
    untouched = all(race.substitute_untouched for race in races)
    equal, total = key_space_agreement(ctx.actions)
    passed = adjacent and refused == 4 and len(races) == 4 and wrong_target == 0 and untouched
    passed = passed and total > 0 and equal == total
    return GateCheck(
        "G5.5",
        "Target identity is revalidated immediately before intervention",
        passed,
        f"AST: revalidate immediately precedes self._host.apply in _commit: {adjacent}; "
        f"{refused} of {len(races)} TOCTOU races refused "
        f"({', '.join(f'{r.variant}={r.outcome.value}' for r in races)}); host.apply calls "
        f"during races {wrong_target}; substitute untouched {untouched}; identity_digest key "
        f"space equal across token/lease/receipt on {equal}/{total} committed corpus actions "
        "(simulated host; not a measurement of Linux pid recycling)",
    )
