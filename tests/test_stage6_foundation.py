"""Stage 6 foundation: the Learning Constitution, core ids, resource governor, S6X catalogue.

Each test is named for the invariant it protects. Several would fail if someone quietly
weakened the invariant — narrowed an anchor, added a lifecycle shortcut, let an
UNMEASURED RSS figure read as within the ceiling, or dropped an experiment's limitation.

**Symbols owned by other work packages** are resolved lazily. While those packages are
being built, a symbol may be unresolved *only* if its module is listed in
``PENDING_MODULES`` (and a law's test may be absent only if its file is in
``PENDING_TEST_FILES``). Those sets are the explicit hand-off to the integrator, who
removes each entry as its package lands; nothing here is skipped or xfailed. An entry no
table uses is itself a failure, so the sets cannot accumulate cover.
"""

from __future__ import annotations

import ast
import dataclasses
import importlib.util
import re
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest

import pocketsec.stage0.benchmark.resource_metrics as stage0_resource_metrics
import pocketsec.stage6.resources as resources
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage1.ssir.entities import SemanticProperty
from pocketsec.stage1.state.security_state import DIMENSIONS, StateDelta
from pocketsec.stage2.adaptation.quarantine import (
    ESCALATION_MASK,
    ESCALATION_PROPERTIES,
    _mask_from_properties,
)
from pocketsec.stage2.encoder.ssir_encoder import _property_mask
from pocketsec.stage6 import core_ids
from pocketsec.stage6.constitution import learning
from pocketsec.stage6.constitution.learning import (
    ALLOWED_TRANSITIONS,
    CONSERVATION_CHECK_NAMES,
    CONSERVATION_CHECKS,
    LEARNING_CONSTITUTION,
    MIN_INDEPENDENT_GROUPS,
    MIN_INDEPENDENT_LABEL_GROUPS,
    PROTECTED_ANCHORS,
    TERMINAL_STATES,
    TIMESCALES,
    ConservationTerm,
    LawBinding,
    LearningLaw,
    LifecycleState,
    ProtectedAnchor,
    Timescale,
    property_mask,
    raised_mask,
    require_transition,
    touches_protected,
    verify_constitution,
    verify_timescales,
)
from pocketsec.stage6.core_ids import (
    ABLATION_FLAGS,
    PINNED_SCHEMAS,
    STAGE6_FUNCTIONS,
    FunctionClass,
    optional_functions,
    pinned_schema_drift,
    resolve_symbols,
    symbol_problem,
)
from pocketsec.stage6.labs.sixty_experiments import (
    EXPERIMENTS_BY_ID,
    SIXTY_EXPERIMENTS,
    ExperimentStatus,
    Stage6Experiment,
    resolve_runners,
    unmeasured_experiments,
)
from pocketsec.stage6.resources import (
    STAGE6_INCREMENTAL_CEILING_BYTES,
    STORE_BUDGETS,
    ResourceSnapshot,
    Stage6ResourceReport,
    WorkBudgetExceeded,
    WorkMeter,
    measure_stage6_resources,
)

ARCHITECTURE = REPO_ROOT / "docs" / "architecture" / "sources" / "stage-06-helios-mnemosyne.md"
_S6 = "pocketsec.stage6."
_MIB = 1024 * 1024

# --- the integrator's hand-off: modules other packages have not landed yet ---

#: Stage 6 modules owned by other work packages. A symbol may be unresolved only if its
#: module is listed here. Every package has landed, so the integrator emptied both sets:
#: every symbol every table names must now resolve, and every law's test must exist.
PENDING_MODULES: frozenset[str] = frozenset()
#: Test files that must define the law tests named by LEARNING_CONSTITUTION.
PENDING_TEST_FILES: frozenset[str] = frozenset()


def _every_named_symbol() -> set[str]:
    symbols = {f.symbol for f in STAGE6_FUNCTIONS}
    symbols |= {b.enforced_by for b in LEARNING_CONSTITUTION}
    symbols |= {r for r in TIMESCALES.values() if core_ids.SYMBOL_PATTERN.fullmatch(r)}
    symbols |= {e.runner for e in SIXTY_EXPERIMENTS if e.runner is not None}
    return symbols


def _assert_only_pending(unresolved: tuple[str, ...]) -> None:
    """Every unresolved symbol lives in a module that is declared pending."""
    unexpected = sorted(s for s in unresolved if s.split(":", 1)[0] not in PENDING_MODULES)
    reasons = {s: symbol_problem(s) for s in unexpected}
    assert not unexpected, f"unresolved and not declared pending: {reasons}"


def test_pending_lists_name_only_modules_and_files_the_tables_use() -> None:
    """The hand-off lists cannot accumulate cover: each entry is used by some table."""
    modules = {symbol.split(":", 1)[0] for symbol in _every_named_symbol()}
    assert modules >= PENDING_MODULES, PENDING_MODULES - modules
    files = {b.tested_by.split("::", 1)[0] for b in LEARNING_CONSTITUTION}
    assert files >= PENDING_TEST_FILES, PENDING_TEST_FILES - files
    assert not (PENDING_MODULES & {_S6 + "core_ids", _S6 + "resources"})


# --- D6.1: the laws ------------------------------------------------------------


def test_every_law_binds_exactly_once_to_a_resolvable_format_symbol() -> None:
    assert [b.law for b in LEARNING_CONSTITUTION] == list(LearningLaw)
    assert len(LearningLaw) == 5
    for binding in LEARNING_CONSTITUTION:
        assert core_ids.SYMBOL_PATTERN.fullmatch(binding.enforced_by), binding
        assert learning.TESTED_BY_PATTERN.fullmatch(binding.tested_by), binding
        assert binding.statement.strip()


def test_law_enforcers_are_the_spec_table_symbols() -> None:
    """Spec D6.1: each law's enforcer is fixed, not a free choice of this package."""
    enforcers = {b.law: b.enforced_by for b in LEARNING_CONSTITUTION}
    assert enforcers == {
        LearningLaw.RAW_TELEMETRY_IS_NOT_TRAINING_DATA: (
            _S6 + "capsule.quarantine:QuarantineGateway.admit"
        ),
        LearningLaw.REPETITION_IS_NOT_TRUTH: _S6 + "provenance.trust:detect_evidence_dependence",
        LearningLaw.MODEL_SCORE_IS_NOT_KNOWLEDGE: _S6 + "conservation.gate:offline_validation",
        LearningLaw.NOVELTY_IS_NOT_PERMISSION_TO_ADAPT: (
            _S6 + "homeostasis.poisoning:detect_semantic_normalization_attack"
        ),
        LearningLaw.SUCCESS_IS_NOT_PERMISSION_TO_FORGET: (
            _S6 + "conservation.gate:offline_validation"
        ),
    }


def test_law_enforcers_resolve_or_are_declared_pending() -> None:
    _assert_only_pending(verify_constitution())


def _test_functions(test_id: str) -> set[str]:
    file_name = test_id.split("::")[0]
    path = REPO_ROOT / file_name
    if not path.exists():
        return set()
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}


def test_law_tests_exist_or_are_declared_pending() -> None:
    """A law whose test does not exist is proved by nothing."""
    missing = [
        b.tested_by
        for b in LEARNING_CONSTITUTION
        if b.tested_by.split("::")[1] not in _test_functions(b.tested_by)
        and b.tested_by.split("::")[0] not in PENDING_TEST_FILES
    ]
    assert not missing, f"laws naming a test that does not exist: {missing}"


def test_a_law_bound_to_a_missing_symbol_is_reported_not_passed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    good = LawBinding(
        LearningLaw.REPETITION_IS_NOT_TRUTH,
        _S6 + "core_ids:resolve_symbols",
        "tests/test_stage6_foundation.py::test_x",
        "resolves",
    )
    ghost = dataclasses.replace(good, enforced_by=_S6 + "core_ids:no_such_enforcer")
    monkeypatch.setattr(learning, "LEARNING_CONSTITUTION", (good,))
    assert verify_constitution() == ()
    monkeypatch.setattr(learning, "LEARNING_CONSTITUTION", (good, ghost))
    assert verify_constitution() == (ghost.enforced_by,)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("enforced_by", "capsule.quarantine:QuarantineGateway.admit"),
        ("enforced_by", "os:system"),
        ("enforced_by", "pocketsec.stage5.executor.transactional:TransactionalExecutor"),
        ("tested_by", "tests/test_stage5_gate.py::test_x"),
        ("tested_by", "tests/test_stage6_gateway.py"),
        ("statement", "   "),
    ],
)
def test_a_malformed_law_binding_is_refused(field: str, value: str) -> None:
    base = LEARNING_CONSTITUTION[0]
    with pytest.raises(ContractError):
        dataclasses.replace(base, **{field: value})  # type: ignore[arg-type]


def test_symbol_problem_never_imports_an_arbitrary_path() -> None:
    assert (symbol_problem("os:system") or "").startswith("malformed")
    non_callable = symbol_problem(_S6 + "core_ids:PINNED_SCHEMAS") or ""
    assert non_callable.startswith(_S6 + "core_ids:PINNED_SCHEMAS resolves to a non-callable")
    assert "no attribute" in (symbol_problem(_S6 + "core_ids:not_there") or "")
    assert (symbol_problem(_S6 + "no_such_module:f") or "").startswith("module not found")
    assert symbol_problem(_S6 + "core_ids:stage6_function") is None


def test_independence_minimums_are_the_spec_values() -> None:
    assert (MIN_INDEPENDENT_GROUPS, MIN_INDEPENDENT_LABEL_GROUPS) == (3, 2)


# --- D6.1: the conservation terms -----------------------------------------------


def test_every_conservation_term_binds_to_a_real_check_name() -> None:
    assert len(ConservationTerm) == 6 and len(CONSERVATION_CHECK_NAMES) == 9
    assert dict(CONSERVATION_CHECKS) == {
        ConservationTerm.NEW_UTILITY: ("G3_CURRENT_HOLDOUT",),
        ConservationTerm.HISTORICAL_SECURITY_LOSS: ("G2_HISTORICAL_REPLAY",),
        ConservationTerm.SAFETY_INVARIANT_LOSS: ("G5_ADVERSARIAL",),
        ConservationTerm.POISON_RISK: ("G5_ADVERSARIAL",),
        ConservationTerm.RESOURCE_GROWTH: ("G7_RESOURCE",),
        ConservationTerm.ROLLBACK_STATE_EXISTS: ("G9_ROLLBACK",),
    }


def test_conservation_check_names_match_the_gate_once_it_exists() -> None:
    """The join to the real enum. Pending only while ``conservation/gate.py`` is absent."""
    problems = learning.verify_conservation_terms()
    gate_exists = (REPO_ROOT / "pocketsec/stage6/conservation/gate.py").exists()
    if gate_exists:
        assert not [p for p in problems if p.startswith("ConservationCheck is")], problems
    assert all("module not found" in p or "raises on import" in p for p in problems), problems


# --- D6.1: the lifecycle machine ------------------------------------------------

_SPEC_EDGES = {
    ("QUARANTINED", "CANDIDATE"), ("QUARANTINED", "REJECTED"),
    ("CANDIDATE", "OFFLINE_VALIDATED"), ("CANDIDATE", "REJECTED"),
    ("OFFLINE_VALIDATED", "SHADOW"), ("OFFLINE_VALIDATED", "REJECTED"),
    ("SHADOW", "CANARY"), ("SHADOW", "REJECTED"),
    ("CANARY", "TRUSTED"), ("CANARY", "REJECTED"),
    ("TRUSTED", "DORMANT"), ("TRUSTED", "FOSSILIZED"), ("TRUSTED", "RETIRED"),
    ("TRUSTED", "ROLLED_BACK"),
    ("DORMANT", "TRUSTED"), ("DORMANT", "FOSSILIZED"), ("DORMANT", "RETIRED"),
    ("DORMANT", "ROLLED_BACK"),
    ("FOSSILIZED", "RETIRED"),
}  # fmt: skip


def test_the_lifecycle_has_exactly_the_eleven_states_of_architecture_42() -> None:
    assert [s.value for s in LifecycleState] == [
        "QUARANTINED", "CANDIDATE", "OFFLINE_VALIDATED", "SHADOW", "CANARY", "TRUSTED",
        "DORMANT", "FOSSILIZED", "RETIRED", "REJECTED", "ROLLED_BACK",
    ]  # fmt: skip
    assert all(state.name == state.value for state in LifecycleState)


def test_the_transition_table_is_exactly_the_spec_and_nothing_more() -> None:
    """All 121 ordered pairs: the allowed ones pass, every other one raises."""
    for current in LifecycleState:
        for target in LifecycleState:
            if (current.value, target.value) in _SPEC_EDGES:
                require_transition(current, target)
            else:
                with pytest.raises(ContractError):
                    require_transition(current, target)
    drawn = {(c.value, t.value) for c, targets in ALLOWED_TRANSITIONS.items() for t in targets}
    assert drawn == _SPEC_EDGES


def test_the_transition_table_forbids_candidate_to_trusted() -> None:
    """The shortcut past offline validation, shadow and canary does not exist."""
    with pytest.raises(ContractError, match="CANDIDATE -> TRUSTED"):
        require_transition(LifecycleState.CANDIDATE, LifecycleState.TRUSTED)
    for skip in (LifecycleState.SHADOW, LifecycleState.CANARY):
        with pytest.raises(ContractError):
            require_transition(LifecycleState.CANDIDATE, skip)
    with pytest.raises(ContractError):
        require_transition(LifecycleState.QUARANTINED, LifecycleState.TRUSTED)


def test_terminal_states_have_no_exit_and_rejection_is_never_undone() -> None:
    assert {
        LifecycleState.RETIRED,
        LifecycleState.REJECTED,
        LifecycleState.ROLLED_BACK,
    } == TERMINAL_STATES
    for state in TERMINAL_STATES:
        for target in LifecycleState:
            with pytest.raises(ContractError):
                require_transition(state, target)


def test_a_state_spelled_as_a_plain_string_is_refused() -> None:
    with pytest.raises(ContractError):
        require_transition("CANARY", LifecycleState.TRUSTED)  # type: ignore[arg-type]


# --- D6.1: timescales -----------------------------------------------------------


def test_no_two_timescales_share_a_learning_rule() -> None:
    assert set(TIMESCALES) == set(Timescale) and len(Timescale) == 6
    assert len(set(TIMESCALES.values())) == 6
    assert TIMESCALES[Timescale.STRUCTURAL].startswith("UNMEASURED")


def test_timescale_rules_resolve_or_are_declared_pending() -> None:
    _assert_only_pending(verify_timescales())


# --- D6.1: protected anchors ----------------------------------------------------


def test_anchors_are_a_superset_of_stage2_escalation_properties() -> None:
    covered = frozenset().union(*(a.properties for a in PROTECTED_ANCHORS))
    assert set(ESCALATION_PROPERTIES) <= covered
    assert property_mask(covered) & ESCALATION_MASK == ESCALATION_MASK


def test_the_anchor_table_is_the_spec_table() -> None:
    P = SemanticProperty
    table = {a.anchor_id: (a.properties, a.dimensions, a.structural) for a in PROTECTED_ANCHORS}
    assert table == {
        "privilege_boundary": (frozenset(), frozenset({"privilege"}), False),
        "credential_material": (
            frozenset({P.CREDENTIAL, P.CREDENTIAL_READER}), frozenset({"credential"}), False,
        ),
        "authorization_material": (frozenset({P.AUTHORIZATION_DATA}), frozenset(), False),
        "executable_trust": (frozenset(), frozenset({"execution", "trust"}), False),
        "persistence": (
            frozenset({P.PERSISTENCE, P.PERSISTENCE_WRITER}), frozenset({"persistence"}), False,
        ),
        "external_egress": (frozenset({P.EXTERNAL_ENDPOINT}), frozenset({"reachability"}), False),
        "evidence_integrity": (frozenset(), frozenset(), True),
        "response_authority": (frozenset(), frozenset(), True),
    }  # fmt: skip


def test_narrowing_the_anchors_below_stage2_fails_on_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Load a fresh, isolated copy of the module against a wider Stage 2 escalation set.

    TEMP_LOCATION is covered by no anchor, so widening Stage 2 by it is exactly the
    situation "Stage 6 is narrower than Stage 2" — and the module must refuse to load.
    The real module in ``sys.modules`` is never touched.
    """
    import pocketsec.stage2.adaptation.quarantine as stage2_quarantine

    widened = (*ESCALATION_PROPERTIES, SemanticProperty.TEMP_LOCATION)
    monkeypatch.setattr(stage2_quarantine, "ESCALATION_PROPERTIES", widened)
    spec = importlib.util.spec_from_file_location("isolated_learning_copy", learning.__file__)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves a class's module through sys.modules, so the isolated copy
    # is registered under its own name for the duration of this test only.
    monkeypatch.setitem(sys.modules, spec.name, module)
    with pytest.raises(ContractError, match="ESCALATION_PROPERTIES"):
        spec.loader.exec_module(module)


#: Every property the Stage 2 encoder can represent. ``NETWORK_CAPABLE`` is a Stage 1
#: property the encoder does not carry in its object group, so no mask can express it.
ENCODED_PROPERTIES = tuple(p for p in SemanticProperty if p is not SemanticProperty.NETWORK_CAPABLE)


def test_masks_match_stage2_escalation_mask_for_the_same_properties() -> None:
    assert property_mask(ESCALATION_PROPERTIES) == ESCALATION_MASK
    for prop in ENCODED_PROPERTIES:
        assert property_mask([prop]) == _mask_from_properties((prop,)) == _property_mask(
            frozenset({prop})
        ), prop
    assert property_mask(ENCODED_PROPERTIES) == (1 << len(ENCODED_PROPERTIES)) - 1


def test_a_property_the_encoder_cannot_represent_is_refused_not_masked_as_zero() -> None:
    """Lesson 2: a mask of 0 for an unrepresentable property would read as "touches nothing"."""
    with pytest.raises(ContractError, match="NETWORK_CAPABLE"):
        property_mask([SemanticProperty.NETWORK_CAPABLE])


def test_raised_mask_matches_stage1_state_delta_bitmask() -> None:
    """The state_delta_mask the encoder stores is ``StateDelta.bitmask()``; same bit order."""
    for dimension in DIMENSIONS:
        assert raised_mask([dimension]) == StateDelta(raised={dimension: (0, 1)}).bitmask()
    everything = StateDelta(raised={d: (0, 1) for d in DIMENSIONS}).bitmask()
    assert raised_mask(DIMENSIONS) == everything


def test_touches_protected_reports_the_anchor_a_step_hits() -> None:
    P = SemanticProperty
    assert touches_protected(property_mask([P.CREDENTIAL_READER]), 0) == ("credential_material",)
    assert touches_protected(0, raised_mask(["reachability", "privilege"])) == (
        "external_egress",
        "privilege_boundary",
    )
    assert touches_protected(property_mask([P.PERSISTENCE_WRITER]), raised_mask(["trust"])) == (
        "executable_trust",
        "persistence",
    )


def test_a_step_touching_no_protected_meaning_is_reported_as_none() -> None:
    P = SemanticProperty
    benign = property_mask([P.TEMP_LOCATION, P.USER_WRITABLE, P.SYSTEM_BINARY, P.INTERPRETER])
    assert touches_protected(benign, raised_mask(["discovery", "modification"])) == ()
    assert touches_protected(0, 0) == ()


def test_structural_anchors_never_match_a_step_and_carry_no_masks() -> None:
    every_bit = property_mask(ENCODED_PROPERTIES)
    hits = touches_protected(every_bit, raised_mask(DIMENSIONS))
    assert "evidence_integrity" not in hits and "response_authority" not in hits
    with pytest.raises(ContractError):
        ProtectedAnchor("x", frozenset({SemanticProperty.CREDENTIAL}), frozenset(), True, "r")
    with pytest.raises(ContractError):
        ProtectedAnchor("x", frozenset(), frozenset(), False, "r")


@pytest.mark.parametrize(
    ("objects", "raised"),
    [(-1, 0), (0, -1), (1 << 15, 0), (0, 1 << 9), (True, 0), (1.0, 0)],
)
def test_a_malformed_mask_is_refused_not_truncated(objects: object, raised: object) -> None:
    with pytest.raises(ContractError):
        touches_protected(objects, raised)  # type: ignore[arg-type]


def test_mask_builders_refuse_unknown_meanings() -> None:
    with pytest.raises(ContractError):
        raised_mask(["root"])
    with pytest.raises(ContractError):
        property_mask(["CREDENTIAL"])  # type: ignore[list-item]


# --- §4.22: core ids ------------------------------------------------------------


def _architecture_function_ids() -> dict[str, str]:
    text = ARCHITECTURE.read_text(encoding="utf-8")
    section = text.split("# 45. Stage 6 Functional IDs", 1)[1].split("# 46.", 1)[0]
    return dict(re.findall(r"^(S6-F\d{2})\n(\w+)$", section, flags=re.MULTILINE))


def test_there_are_26_core_ids_with_unique_ids_matching_architecture_45() -> None:
    assert len(STAGE6_FUNCTIONS) == 26
    assert [f.core_id for f in STAGE6_FUNCTIONS] == [f"HEL-F{n:02d}" for n in range(1, 27)]
    architecture = _architecture_function_ids()
    assert len(architecture) == 26
    assert {f.architecture_id: f.name for f in STAGE6_FUNCTIONS} == architecture


def test_required_and_optional_are_exactly_as_tabled() -> None:
    optional = {f.core_id: (f.ablation_flag, f.simple_control) for f in optional_functions()}
    assert optional == {
        "HEL-F07": ("half_life", "LRU"),
        "HEL-F08": ("plasticity_field", "uniform_mask"),
        "HEL-F10": ("competition", "NEWEST_WINS"),
        "HEL-F11": ("counterfactual_variants", "plain replay"),
        "HEL-F15": ("value_aware_rehearsal", "reservoir"),
        "HEL-F19": ("drift_discriminator", "corroborated change => legitimate"),
        "HEL-F21": ("resurrection", "relearn"),
        "HEL-F25": ("half_life", "LRU retire"),
    }
    ablated_required = {
        f.core_id for f in STAGE6_FUNCTIONS
        if f.function_class is FunctionClass.REQUIRED and f.ablation_flag is not None
    }  # fmt: skip
    assert ablated_required == {"HEL-F04", "HEL-F18"}
    assert {f.ablation_flag for f in STAGE6_FUNCTIONS if f.ablation_flag} == set(ABLATION_FLAGS)


def test_ablation_flags_are_stage_six_config_fields_once_it_exists() -> None:
    assert (REPO_ROOT / "pocketsec/stage6/labs/endurance.py").exists()
    from pocketsec.stage6.labs import endurance  # type: ignore[attr-defined]

    fields = {f.name for f in dataclasses.fields(endurance.StageSixConfig) if f.type == "bool"}
    assert fields == set(ABLATION_FLAGS)


@pytest.mark.parametrize(
    "overrides",
    [
        {"function_class": FunctionClass.OPTIONAL, "ablation_flag": None, "simple_control": None},
        {"ablation_flag": "half_life", "simple_control": None},
        {"ablation_flag": "made_up_flag", "simple_control": "x"},
        {"symbol": "capsule.quarantine:QuarantineGateway.admit"},
        {"architecture_id": "S6-F02"},
        {"core_id": "HEL-1"},
    ],
)
def test_a_core_row_that_could_never_be_ablated_or_resolved_is_refused(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ContractError):
        dataclasses.replace(STAGE6_FUNCTIONS[0], **overrides)  # type: ignore[arg-type]


def test_core_symbols_resolve_or_are_declared_pending() -> None:
    _assert_only_pending(resolve_symbols())


def test_the_five_pinned_upstream_schemas_have_not_drifted() -> None:
    assert dict(PINNED_SCHEMAS) == {
        "pocketsec.ssir_transition.v1": "1.0.0",
        "pocketsec.cbf_resolution.v1": "1.0.0",
        "pocketsec.response_record.v1": "1.0.0",
        "pocketsec.threat_prediction.v1": "1.0.0",
        "pocketsec.security_event_sequence.v1": "1.0.0",
    }
    assert pinned_schema_drift() == ()


def test_schema_drift_is_reported_when_a_pin_disagrees(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        core_ids, "PINNED_SCHEMAS", {**PINNED_SCHEMAS, "pocketsec.response_record.v1": "2.0.0"}
    )
    assert pinned_schema_drift() == (
        "pocketsec.response_record.v1: pinned 2.0.0, registered 1.0.0",
    )


def test_an_unknown_core_id_is_refused() -> None:
    assert core_ids.stage6_function("HEL-F17").name == "run_conservation_gate"
    with pytest.raises(ContractError):
        core_ids.stage6_function("HEL-F27")


# --- §4.22: resources -------------------------------------------------------------


def test_work_meter_raises_past_budget_and_charges_nothing_for_refused_work() -> None:
    meter = WorkMeter(budget=10)
    meter.charge(4)
    meter.charge(6)
    assert (meter.spent, meter.remaining) == (10, 0)
    with pytest.raises(WorkBudgetExceeded):
        meter.charge(1)
    assert meter.spent == 10
    zero = WorkMeter(budget=0)
    zero.charge(0)
    with pytest.raises(WorkBudgetExceeded):
        zero.charge()


def test_an_unbounded_meter_counts_but_never_refuses() -> None:
    meter = WorkMeter()
    for _ in range(1000):
        meter.charge(7)
    assert (meter.spent, meter.budget, meter.remaining) == (7000, None, None)


@pytest.mark.parametrize("units", [-1, 1.5, True, "3"])
def test_work_meter_refuses_nonsense_charges(units: object) -> None:
    meter = WorkMeter(budget=100)
    with pytest.raises(ContractError):
        meter.charge(units)  # type: ignore[arg-type]
    assert meter.spent == 0


@pytest.mark.parametrize("budget", [-1, 2.5, True])
def test_work_meter_refuses_a_nonsense_budget(budget: object) -> None:
    with pytest.raises(ContractError):
        WorkMeter(budget=budget)  # type: ignore[arg-type]


def test_store_budgets_are_the_five_rows_of_architecture_39() -> None:
    assert [(b.name, b.normal_bytes // _MIB, b.peak_bytes // _MIB) for b in STORE_BUDGETS] == [
        ("quarantine_metadata", 15, 25),
        ("episodic_hot_index", 15, 25),
        ("semantic_procedural_memory", 20, 30),
        ("lineage_fossil_metadata", 10, 15),
        ("consolidation_workspace", 15, 35),
    ]
    assert resources.STAGE6_NORMAL_INCREMENTAL_RSS_BYTES == 57671680 == 55 * _MIB
    assert STAGE6_INCREMENTAL_CEILING_BYTES == 104857600 == 100 * _MIB
    assert resources.STAGE6_DISK_BUDGET_BYTES == 500 * _MIB
    assert (
        resources.CONSOLIDATION_MAX_MEMORY_PRESSURE,
        resources.CONSOLIDATION_MAX_CPU_LOAD,
        resources.CONSOLIDATION_MAX_URGENCY,
        resources.CONSOLIDATION_MIN_DISK_FREE_BYTES,
    ) == (0.8, 0.8, 0.5, 64 * _MIB)


def test_measure_stage6_resources_returns_none_not_true_when_rss_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """UNMEASURED is never True: no RSS source means no ceiling verdict."""
    monkeypatch.setattr(stage0_resource_metrics, "read_rss_bytes", lambda: None)
    report = measure_stage6_resources(lambda: {"episodic_hot_index": 10}, events=3)
    assert report.incremental_rss_bytes is None
    assert report.within_ceiling is None
    assert "rss" in report.metrics.unavailable
    assert report.store_bytes == {"episodic_hot_index": 10}


def test_measure_stage6_resources_reports_a_real_verdict_when_rss_is_available() -> None:
    held: list[bytes] = []

    def work() -> Mapping[str, int]:
        held.extend(bytes(4096) for _ in range(2048))
        return {"quarantine_metadata": 16 * _MIB, "episodic_hot_index": 1, "shadow_window": 5}

    report = measure_stage6_resources(work, events=2048)
    assert report.incremental_rss_bytes is not None and report.incremental_rss_bytes >= 0
    ceiling = STAGE6_INCREMENTAL_CEILING_BYTES
    assert report.within_ceiling is (report.incremental_rss_bytes <= ceiling)
    assert report.over_budget() == ("quarantine_metadata",)
    assert report.over_budget(peak=True) == ()
    assert report.unbudgeted() == ("shadow_window",)
    assert report.metrics.events_processed == 2048
    assert len(report.loadavg) == 3


def test_the_report_refuses_a_verdict_its_figures_do_not_support() -> None:
    report = measure_stage6_resources(lambda: {}, events=0)
    with pytest.raises(ContractError):
        dataclasses.replace(report, incremental_rss_bytes=None, within_ceiling=True)
    with pytest.raises(ContractError):
        dataclasses.replace(report, incremental_rss_bytes=None, within_ceiling=False)
    with pytest.raises(ContractError):
        dataclasses.replace(
            report, incremental_rss_bytes=STAGE6_INCREMENTAL_CEILING_BYTES + 1, within_ceiling=True
        )
    over = dataclasses.replace(
        report, incremental_rss_bytes=STAGE6_INCREMENTAL_CEILING_BYTES + 1, within_ceiling=False
    )
    assert over.within_ceiling is False


@pytest.mark.parametrize("bad", [{"x": -1}, {"x": 1.5}, {"": 3}, {"x": True}])
def test_a_store_reporting_nonsense_bytes_is_refused(bad: Mapping[str, object]) -> None:
    with pytest.raises(ContractError):
        measure_stage6_resources(lambda: bad, events=0)  # type: ignore[arg-type,return-value]
    with pytest.raises(ContractError):
        measure_stage6_resources(lambda: {}, events=-1)


def test_a_failing_work_block_propagates_and_is_not_reported_as_measured() -> None:
    def work() -> Mapping[str, int]:
        raise RuntimeError("learning subsystem crashed")

    with pytest.raises(RuntimeError, match="crashed"):
        measure_stage6_resources(work, events=1)


def test_snapshot_capture_reads_this_host() -> None:
    snapshot = ResourceSnapshot.capture(incident_urgency=0.25)
    assert 0.0 <= snapshot.memory_pressure <= 1.0
    assert snapshot.cpu_load >= 0.0 and snapshot.disk_free_bytes >= 0
    assert snapshot.incident_urgency == 0.25


def test_an_unreadable_host_is_captured_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Unmeasured conditions defer consolidation instead of looking idle."""
    monkeypatch.setattr(resources, "MEMINFO_PATH", tmp_path / "no-meminfo")
    monkeypatch.setattr(resources, "LOADAVG_PATH", tmp_path / "no-loadavg")
    monkeypatch.setattr(resources, "THERMAL_ROOT", tmp_path / "no-thermal")
    snapshot = ResourceSnapshot.capture(disk_path=tmp_path / "no-such-dir")
    assert snapshot.unmeasured == ("cpu_load", "disk_free_bytes", "memory_pressure", "thermal_ok")
    assert snapshot.memory_pressure == 1.0 and snapshot.cpu_load == 1.0
    assert snapshot.disk_free_bytes == 0 and snapshot.thermal_ok is False
    assert resources.loadavg() == resources.LOADAVG_UNAVAILABLE


def _zone(root: Path, name: str, temp: int, trips: dict[str, int]) -> None:
    zone = root / name
    zone.mkdir(parents=True)
    (zone / "temp").write_text(f"{temp}\n", encoding="ascii")
    for index, (kind, value) in enumerate(trips.items()):
        (zone / f"trip_point_{index}_type").write_text(kind + "\n", encoding="ascii")
        (zone / f"trip_point_{index}_temp").write_text(f"{value}\n", encoding="ascii")


def test_thermal_policy_blocks_a_zone_near_its_critical_trip(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _zone(tmp_path, "thermal_zone0", 50000, {"critical": 100000})
    _zone(tmp_path, "thermal_zone1", 50, {"passive": -274000})  # placeholder: says nothing
    monkeypatch.setattr(resources, "THERMAL_ROOT", tmp_path)
    assert ResourceSnapshot.capture().thermal_ok is True
    _zone(tmp_path, "thermal_zone2", 96000, {"hot": 100000, "critical": 105000})
    snapshot = ResourceSnapshot.capture()
    assert snapshot.thermal_ok is False and "thermal_ok" not in snapshot.unmeasured


@pytest.mark.parametrize(
    "overrides",
    [
        {"memory_pressure": 1.5},
        {"cpu_load": -0.1},
        {"cpu_load": float("nan")},
        {"incident_urgency": 2.0},
        {"disk_free_bytes": -1},
        {"thermal_ok": 1},
        {"unmeasured": ("battery",)},
        {"unmeasured": ("thermal_ok",), "thermal_ok": True},
    ],
)
def test_a_snapshot_with_impossible_conditions_is_refused(overrides: dict[str, object]) -> None:
    base = {
        "memory_pressure": 0.1, "cpu_load": 0.1, "incident_urgency": 0.0,
        "disk_free_bytes": 1, "thermal_ok": True,
    }  # fmt: skip
    with pytest.raises(ContractError):
        ResourceSnapshot(**{**base, **overrides})  # type: ignore[arg-type]


# --- D6.20: the sixty-experiment catalogue --------------------------------------------


def _architecture_titles() -> dict[str, str]:
    line = next(
        text for text in ARCHITECTURE.read_text(encoding="utf-8").splitlines()
        if text.startswith("S6X-01")
    )  # fmt: skip
    parts = re.split(r"S6X-(\d{2})\s+", line)[1:]
    return {f"S6X-{parts[i]}": parts[i + 1].strip() for i in range(0, len(parts), 2)}


def test_sixty_rows_with_dense_ids_and_architecture_titles_verbatim() -> None:
    assert len(SIXTY_EXPERIMENTS) == 60 == len(EXPERIMENTS_BY_ID)
    assert [e.experiment_id for e in SIXTY_EXPERIMENTS] == [f"S6X-{n:02d}" for n in range(1, 61)]
    assert {e.experiment_id: e.title for e in SIXTY_EXPERIMENTS} == _architecture_titles()


def test_unmeasured_rows_are_exactly_the_parameter_free_three_and_carry_limitations() -> None:
    rows = unmeasured_experiments()
    assert [e.experiment_id for e in rows] == ["S6X-13", "S6X-14", "S6X-15"]
    for experiment in rows:
        assert experiment.runner is None
        assert "ADR-0050" in experiment.limitation and "parameter-free" in experiment.limitation


def test_split_rows_name_their_unmeasured_half() -> None:
    """A row that runs only half its title must say which half did not run."""
    for experiment_id, word in (("S6X-39", "neural"), ("S6X-52", "ONNX"), ("S6X-53", "ONNX")):
        row = EXPERIMENTS_BY_ID[experiment_id]
        assert row.status is ExperimentStatus.EXECUTABLE
        assert word in row.limitation and "UNMEASURED" in row.limitation
    assert "simulated=True" in EXPERIMENTS_BY_ID["S6X-60"].limitation
    assert "by construction" in EXPERIMENTS_BY_ID["S6X-21"].limitation
    assert "UNMEASURED" in EXPERIMENTS_BY_ID["S6X-31"].limitation


def test_every_executable_row_names_a_stage6_runner() -> None:
    for experiment in SIXTY_EXPERIMENTS:
        if experiment.status is ExperimentStatus.EXECUTABLE:
            assert experiment.runner and core_ids.SYMBOL_PATTERN.fullmatch(experiment.runner)
    assert EXPERIMENTS_BY_ID["S6X-58"].runner == _S6 + "labs.endurance:run_ablation"
    assert EXPERIMENTS_BY_ID["S6X-35"].runner == _S6 + "labs.endurance:run_poison_suite"


def test_runners_resolve_or_are_declared_pending() -> None:
    _assert_only_pending(resolve_runners())


@pytest.mark.parametrize(
    "overrides",
    [
        {"status": ExperimentStatus.UNMEASURED, "runner": None, "limitation": ""},
        {"status": ExperimentStatus.UNMEASURED},
        {"runner": None},
        {"runner": "labs.endurance:run_endurance"},
        {"experiment_id": "S6X-61"},
        {"deliverable": "D6.21"},
        {"title": " "},
    ],
)
def test_an_experiment_row_that_hides_why_it_cannot_run_is_refused(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ContractError):
        dataclasses.replace(EXPERIMENTS_BY_ID["S6X-01"], **overrides)  # type: ignore[arg-type]


def test_foundation_modules_hold_no_state_except_the_work_meter() -> None:
    """Bounds: the foundation is pure data. Any module-level mutable container is a leak."""
    mutable: list[str] = []
    for module in (core_ids, learning, resources):
        tree = ast.parse(Path(module.__file__ or "").read_text(encoding="utf-8"))
        imported = {
            alias.asname or alias.name
            for node in tree.body
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
        }
        for name, value in vars(module).items():
            if name.startswith("__") or name in imported:
                continue
            if isinstance(value, (list, dict, set, bytearray)):
                mutable.append(f"{module.__name__}.{name}")
    assert not mutable, mutable
    assert isinstance(Stage6Experiment.__slots__, tuple)
    assert isinstance(Stage6ResourceReport.__slots__, tuple)
