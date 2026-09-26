"""Stage 7 foundation: the Collective Constitution, the KnowledgeCapsuleV1 wire unit, core ids.

Each test is named for the invariant it protects, and most attack the boundary rather than
exercise it: an authority word injected at every depth, a payload one byte over the cap
that must never reach the parser, a raw path or user name smuggled into every string
field, a derived field forged, a type that asserts normality. Several would fail if
someone quietly weakened the invariant — for example by screening only top-level keys,
parsing before bounding, or coercing ``"3"`` into ``3``.

**Symbols owned by other work packages** are resolved lazily. While those packages are
built, a symbol may be unresolved *only* if its module is listed in ``PENDING_MODULES``
(and a law's test may be absent only if its file is in ``PENDING_TEST_FILES``). Those sets
are the explicit hand-off to the integrator, who empties them as packages land; nothing
here is skipped or xfailed. An entry no table uses is itself a failure, so the sets
cannot accumulate cover, and nothing this package owns may ever be pending.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import json
import re
from collections.abc import Callable, Mapping
from typing import Any

import pytest

# Imported for their side effect: they register learning_record.v1 and knowledge_package.v1.
import pocketsec.stage6.export.learning_record
import pocketsec.stage6.fleet.package  # noqa: F401
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS
from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage1.ssir.entities import SemanticProperty
from pocketsec.stage1.ssir.relations import Relation, RelationFamily
from pocketsec.stage2.encoder.ssir_encoder import _property_mask, feature_names
from pocketsec.stage6.capsule.experience_capsule import PrivacyClass
from pocketsec.stage6.memory.semantic import MAX_MOTIF_LENGTH, MotifStep, motif_pattern_key
from pocketsec.stage7 import core_ids
from pocketsec.stage7.capsule import knowledge_capsule as kc
from pocketsec.stage7.capsule.knowledge_capsule import (
    COUNTER_HYPOTHESIS_VALUES,
    MAX_EVIDENCE_COMMITMENTS,
    MAX_EXPIRY_HORIZON_ROUNDS,
    MAX_KNOWLEDGE_CAPSULE_BYTES,
    MAX_PARENT_CAPSULES,
    MAX_WINDOW_ROUNDS,
    MAX_WIRE_INT,
    ChainStage,
    EpochContext,
    FalsificationSummary,
    KnowledgeCapsuleV1,
    KnowledgeType,
    MotifRow,
    ObservabilityClaim,
    ProvenanceCommitment,
    RevocationGround,
    RoleClass,
    SourceContextSketch,
    Stance,
    ValidationSummary,
    VisibilityClass,
    authority_key_violations,
    derive_chain_stages,
    is_wire_string,
    motif_fingerprint,
    seal_capsule,
    wire_string_violations,
)
from pocketsec.stage7.constitution import collective
from pocketsec.stage7.constitution.collective import (
    COLLECTIVE_CONSTITUTION,
    COLLECTIVE_EXCHANGE_ENABLED,
    CollectiveLaw,
    LawBinding,
    law_test_problem,
    verify_collective_constitution,
)
from pocketsec.stage7.core_ids import (
    ABLATION_FLAGS,
    ARCHITECTURE_LAYERS,
    PINNED_SCHEMAS,
    STAGE7_FUNCTIONS,
    FunctionClass,
    optional_functions,
    pinned_schema_drift,
    resolve_symbols,
    stage7_function,
    symbol_problem,
)

_S7 = "pocketsec.stage7."
ARCHITECTURE = REPO_ROOT / "docs" / "architecture" / "sources" / "stage-07-orpheus-hivelock.md"
STAGE7 = REPO_ROOT / "pocketsec" / "stage7"
FOUNDATION_FILES = (
    STAGE7 / "core_ids.py",
    STAGE7 / "constitution" / "collective.py",
    STAGE7 / "capsule" / "knowledge_capsule.py",
)

# --- the integrator's hand-off: modules other packages have not landed yet -----------------

#: Stage 7 modules owned by OTHER work packages that a table here names. A symbol may be
#: unresolved only if its module is listed. The integrator empties this set.
#: Emptied by the integrator: every package has landed, so every symbol must now resolve.
PENDING_MODULES: frozenset[str] = frozenset()
#: Emptied by the integrator: every law's test file now exists and must define its test.
PENDING_TEST_FILES: frozenset[str] = frozenset()
#: What this package owns. Never pending: the foundation must resolve on its own.
OWN_MODULES = frozenset(
    {_S7 + "core_ids", _S7 + "constitution.collective", _S7 + "capsule.knowledge_capsule"}
)


def _every_named_module() -> set[str]:
    symbols = {f.symbol for f in STAGE7_FUNCTIONS}
    symbols |= {b.enforced_by for b in COLLECTIVE_CONSTITUTION}
    return {symbol.split(":", 1)[0] for symbol in symbols}


def test_pending_lists_name_only_what_the_tables_use_and_never_this_package() -> None:
    assert _every_named_module() >= PENDING_MODULES, PENDING_MODULES - _every_named_module()
    files = {b.tested_by.split("::", 1)[0] for b in COLLECTIVE_CONSTITUTION}
    assert files >= PENDING_TEST_FILES, PENDING_TEST_FILES - files
    assert not PENDING_MODULES & OWN_MODULES
    assert "tests/test_stage7_foundation.py" not in PENDING_TEST_FILES


# --- D7.1: the Collective Constitution -------------------------------------------------------

#: Spec D7.1's table, verbatim. Not a free choice of this package: eight packages agree on it.
SPEC_BINDINGS: Mapping[CollectiveLaw, tuple[str, str]] = {
    CollectiveLaw.NO_DIRECT_TRUSTED_WRITE: (
        "hivelock.stage6_bridge:Stage6Bridge.hand_over",
        "tests/test_stage7_boundary.py::test_no_stage7_module_names_a_stage6_writer",
    ),
    CollectiveLaw.NO_STAGE5_INVOCATION: (
        "capsule.knowledge_capsule:authority_key_violations",
        "tests/test_stage7_boundary.py::test_no_stage7_module_imports_stage5",
    ),
    CollectiveLaw.FOREIGN_IS_UNTRUSTED_EVEN_SIGNED: (
        "hivelock.ingress:HivelockIngress.receive",
        "tests/test_stage7_ingress.py::test_a_validly_signed_capsule_is_only_ever_pooled",
    ),
    CollectiveLaw.MAJORITY_IS_NOT_TRUTH: (
        "echo.inference:EchoEngine.infer",
        "tests/test_stage7_echo.py::test_identity_count_does_not_raise_mass_within_a_cluster",
    ),
    CollectiveLaw.NO_UNBOUNDED_IDENTITY_INFLUENCE: (
        "graph.dependence:DependenceGraph.observe",
        "tests/test_stage7_graph.py::test_sybils_sharing_a_root_are_one_cluster",
    ),
    CollectiveLaw.NO_RAW_HOST_DATA_EXPORT: (
        "privacy.distiller:residual_identifier_hits",
        "tests/test_stage7_privacy.py::test_no_raw_fleet_string_survives_export",
    ),
    CollectiveLaw.EVERY_IMPORT_REJECTABLE_EXPIRABLE_REVOCABLE: (
        "lineage.cross_host:RevocationPlane.submit",
        "tests/test_stage7_sovereignty.py::test_revocation_marks_exactly_the_descendants",
    ),
    CollectiveLaw.LOCAL_PROTECTION_SURVIVES_NETWORK_LOSS: (
        "orpheus.fabric:OrpheusFabric.run_round",
        "tests/test_stage7_sovereignty.py::"
        "test_local_detection_is_identical_with_the_fabric_absent_offline_or_crashing",
    ),
    CollectiveLaw.LOCAL_SOVEREIGNTY: (
        "echo.inference:EchoEngine.infer",
        "tests/test_stage7_sovereignty.py::test_a_unanimous_fleet_cannot_change_a_local_decision",
    ),
    CollectiveLaw.NO_FOREIGN_NORMALITY: (
        "capsule.knowledge_capsule:KnowledgeType",
        "tests/test_stage7_foundation.py::test_no_knowledge_type_can_assert_normality",
    ),
}


def test_constitution_binds_each_of_the_ten_laws_once_to_the_spec_pairs() -> None:
    assert len(CollectiveLaw) == 10
    assert [b.law for b in COLLECTIVE_CONSTITUTION] == list(CollectiveLaw)
    pairs = {b.law: (b.enforced_by, b.tested_by) for b in COLLECTIVE_CONSTITUTION}
    assert pairs == {law: (_S7 + e, t) for law, (e, t) in SPEC_BINDINGS.items()}
    assert all(b.statement.strip() for b in COLLECTIVE_CONSTITUTION)


def test_collective_exchange_is_off_by_default() -> None:
    assert COLLECTIVE_EXCHANGE_ENABLED is False


def test_constitution_resolves_except_for_declared_pending_packages() -> None:
    """Every problem names a pending module or file; the foundation's own laws resolve."""
    unexpected = []
    for problem in verify_collective_constitution():
        law, rest = problem.split(": ", 1)
        target = rest.split(" ", 2)[1]
        pending = (
            target.split(":", 1)[0] in PENDING_MODULES
            if rest.startswith("enforced_by")
            else target.split("::", 1)[0] in PENDING_TEST_FILES
        )
        if not pending or law == CollectiveLaw.NO_FOREIGN_NORMALITY:
            unexpected.append(problem)
    assert not unexpected, unexpected


def test_a_law_bound_to_a_missing_symbol_or_test_is_reported_not_passed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    good = LawBinding(
        CollectiveLaw.NO_FOREIGN_NORMALITY,
        _S7 + "capsule.knowledge_capsule:KnowledgeType",
        "tests/test_stage7_foundation.py::test_no_knowledge_type_can_assert_normality",
        "resolves",
    )
    ghost_symbol = dataclasses.replace(good, enforced_by=_S7 + "core_ids:no_such_enforcer")
    ghost_test = dataclasses.replace(good, tested_by="tests/test_stage7_foundation.py::test_nope")
    monkeypatch.setattr(collective, "COLLECTIVE_CONSTITUTION", (good,))
    assert verify_collective_constitution() == ()
    monkeypatch.setattr(collective, "COLLECTIVE_CONSTITUTION", (good, ghost_symbol, ghost_test))
    problems = verify_collective_constitution()
    assert len(problems) == 2
    assert "no attribute 'no_such_enforcer'" in problems[0]
    assert "defines no test 'test_nope'" in problems[1]


def test_a_test_named_only_in_a_docstring_or_string_does_not_exist(tmp_path: Any) -> None:
    """The ast parse is the point: mentioning a test name is not defining it."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_stage7_x.py").write_text(
        '"""test_claimed is proved elsewhere."""\nNAME = "test_claimed"\n'
        "def test_real() -> None:\n    pass\n"
    )
    assert law_test_problem("tests/test_stage7_x.py::test_real", root=tmp_path) is None
    problem = law_test_problem("tests/test_stage7_x.py::test_claimed", root=tmp_path)
    assert problem == "tests/test_stage7_x.py defines no test 'test_claimed'"
    missing = law_test_problem("tests/test_stage7_y.py::test_real", root=tmp_path)
    assert missing == "test file not found: tests/test_stage7_y.py"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("enforced_by", "capsule.knowledge_capsule:KnowledgeType"),
        ("enforced_by", "os:system"),
        ("enforced_by", "pocketsec.stage6.capsule.quarantine:QuarantineGateway.admit"),
        ("enforced_by", "pocketsec.stage5.executor.transactional:TransactionalExecutor"),
        ("tested_by", "tests/test_stage6_gateway.py::test_x"),
        ("tested_by", "tests/test_stage7_echo.py"),
        ("statement", "   "),
        ("law", "LOCAL_SOVEREIGNTY"),
    ],
)
def test_a_malformed_law_binding_is_refused(field: str, value: str) -> None:
    with pytest.raises(ContractError):
        dataclasses.replace(COLLECTIVE_CONSTITUTION[0], **{field: value})  # type: ignore[arg-type]


# --- §4.24: core ids --------------------------------------------------------------------------


def _architecture_layers() -> dict[str, str]:
    """Architecture §2's layer map, parsed from the source: ``7.N`` then the subsystem name."""
    text = ARCHITECTURE.read_text(encoding="utf-8")
    section = text.split("# 2. Stage 7 Layer Map", 1)[1].split("# 3.", 1)[0]
    return dict(re.findall(r"^(7\.\d{1,2})\n(.+)$", section, flags=re.MULTILINE))


def test_core_ids_cover_layers_7_0_to_7_21() -> None:
    assert [f.core_id for f in STAGE7_FUNCTIONS] == [f"ORPH-F{n:02d}" for n in range(1, 23)]
    assert [f.architecture_layer for f in STAGE7_FUNCTIONS] == [f"7.{n}" for n in range(22)]
    architecture = _architecture_layers()
    assert len(architecture) == 22
    assert dict(ARCHITECTURE_LAYERS) == architecture
    assert {f.architecture_layer: f.name for f in STAGE7_FUNCTIONS} == architecture


def test_core_symbols_are_the_spec_table() -> None:
    assert {f.core_id: f.symbol.removeprefix(_S7) for f in STAGE7_FUNCTIONS} == {
        "ORPH-F01": "constitution.collective:verify_collective_constitution",
        "ORPH-F02": "identity.integrity:Keyring.verify",
        "ORPH-F03": "capsule.compiler:compile_capsule",
        "ORPH-F04": "privacy.distiller:residual_identifier_hits",
        "ORPH-F05": "relevance.epistemic_distance:epistemic_distance",
        "ORPH-F06": "relevance.gravity:knowledge_gravity",
        "ORPH-F07": "hivelock.ingress:HivelockIngress.receive",
        "ORPH-F08": "graph.dependence:DependenceGraph.observe",
        "ORPH-F09": "echo.inference:EchoEngine.infer",
        "ORPH-F10": "antibody.forge:forge_antibody",
        "ORPH-F11": "reconstruct.partial_world:PartialWorldReconstructor.reconstruct",
        "ORPH-F12": "novelty.collective:CollectiveNoveltyEngine.evaluate",
        "ORPH-F13": "campaign.hypergraph:CampaignHypergraph.build_edges",
        "ORPH-F14": "falsifier.consensus:ConsensusFalsifier.falsify",
        "ORPH-F15": "lineage.cross_host:CrossHostLineageDAG.ancestry_complete",
        "ORPH-F16": "lineage.cross_host:RevocationPlane.submit",
        "ORPH-F17": "hivelock.stage6_bridge:Stage6Bridge.hand_over",
        "ORPH-F18": "aggregation.secure:aggregate_masked",
        "ORPH-F19": "privacy.ledger:PrivacyLedger.charge",
        "ORPH-F20": "governor.communication:CommunicationGovernor.admit_inbound",
        "ORPH-F21": "orpheus.fabric:OrpheusFabric.run_round",
        "ORPH-F22": "labs.byzantine_suite:run_byzantine_suite",
    }


def test_required_optional_and_every_control_are_exactly_as_tabled() -> None:
    optional = {f.core_id: dict(f.controls()) for f in optional_functions()}
    assert optional == {
        "ORPH-F05": {"epistemic_distance": "role equality"},
        "ORPH-F06": {"gravity": "validate every capsule"},
        "ORPH-F10": {"antibody_minimisation": "copied_rule"},
        "ORPH-F11": {"reconstruction": "no reconstruction"},
        "ORPH-F12": {"collective_novelty": "local novelty only"},
        "ORPH-F13": {"hypergraph": "pairwise co-occurrence"},
        "ORPH-F18": {"secure_aggregation": "plaintext sum"},
    }
    ablated_required = {
        f.core_id: dict(f.controls())
        for f in STAGE7_FUNCTIONS
        if f.function_class is FunctionClass.REQUIRED and f.ablation_flags
    }
    assert ablated_required == {
        "ORPH-F08": {"dependence_clustering": "declared roots only"},
        "ORPH-F09": {
            "cluster_cap": "uncapped identity sum",
            "contextual_trust": "constant prior",
            "falsification_weight": "1.0",
            "contest_mass": "ignore contests",
            "probation": "0 rounds",
        },
        "ORPH-F14": {"falsifier": "count_threshold_join"},
        "ORPH-F19": {"differential_privacy": "exact counts"},
    }
    used = [flag for f in STAGE7_FUNCTIONS for flag in f.ablation_flags]
    assert sorted(used) == sorted(ABLATION_FLAGS) and len(set(used)) == len(used)


@pytest.mark.parametrize(
    "overrides",
    [
        {"function_class": FunctionClass.OPTIONAL, "ablation_flags": (), "simple_control": ()},
        {"ablation_flags": ("gravity",), "simple_control": ()},
        {"ablation_flags": ("made_up_flag",), "simple_control": ("x",)},
        {"ablation_flags": ("gravity", "gravity"), "simple_control": ("x", "y")},
        {"ablation_flags": ("gravity",), "simple_control": ("  ",)},
        {"symbol": "capsule.compiler:compile_capsule"},
        {"symbol": "pocketsec.stage6.capsule.quarantine:QuarantineGateway.admit"},
        {"architecture_layer": "7.1"},
        {"name": "Something Else"},
        {"core_id": "ORPH-1"},
        {"function_class": "REQUIRED"},
    ],
)
def test_a_core_row_that_could_never_be_ablated_or_resolved_is_refused(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ContractError):
        dataclasses.replace(STAGE7_FUNCTIONS[0], **overrides)  # type: ignore[arg-type]


def test_core_symbols_resolve_except_for_declared_pending_packages() -> None:
    unexpected = [s for s in resolve_symbols() if s.split(":", 1)[0] not in PENDING_MODULES]
    assert not unexpected, {s: symbol_problem(s) for s in unexpected}
    assert symbol_problem(stage7_function("ORPH-F01").symbol) is None


def test_symbol_problem_never_imports_an_arbitrary_path() -> None:
    assert (symbol_problem("os:system") or "").startswith("malformed")
    assert (symbol_problem("pocketsec.stage5.cli:main") or "").startswith("malformed")
    assert "non-callable" in (symbol_problem(_S7 + "core_ids:PINNED_SCHEMAS") or "")
    assert "no attribute" in (symbol_problem(_S7 + "core_ids:not_there") or "")
    assert (symbol_problem(_S7 + "no_such_module:f") or "").startswith("module not found")


def test_the_three_pinned_stage6_schemas_have_not_drifted() -> None:
    assert dict(PINNED_SCHEMAS) == {
        "pocketsec.experience_capsule.v1": "1.0.0",
        "pocketsec.knowledge_package.v1": "1.0.0",
        "pocketsec.learning_record.v1": "1.0.0",
    }
    assert pinned_schema_drift() == ()


def test_schema_drift_is_reported_when_a_pin_disagrees(monkeypatch: pytest.MonkeyPatch) -> None:
    moved = {**PINNED_SCHEMAS, "pocketsec.knowledge_package.v1": "2.0.0"}
    monkeypatch.setattr(core_ids, "PINNED_SCHEMAS", moved)
    drift = pinned_schema_drift()
    assert len(drift) == 1
    assert drift[0].startswith("pocketsec.knowledge_package.v1: pinned 2.0.0, registered 1.0.0")


def test_an_unknown_core_id_is_refused() -> None:
    assert stage7_function("ORPH-F17").name == "Stage-6 Local Gate"
    with pytest.raises(ContractError):
        stage7_function("ORPH-F23")


# --- D7.2: capsule fixtures -------------------------------------------------------------------


def _hex(tag: str, width: int) -> str:
    return hashlib.sha256(tag.encode()).hexdigest()[:width]


def _bit(prop: SemanticProperty) -> int:
    return _property_mask(frozenset({prop}))


ROOT = "root-" + _hex("root-a", 16)
OBJECT_WIDTH = sum(1 for n in feature_names() if n.startswith("object."))
RAISED_WIDTH = sum(1 for n in feature_names() if n.startswith("raised."))
CRED_ROW = MotifRow(int(Relation.READ), _bit(SemanticProperty.CREDENTIAL), 0, 0)
EGRESS_ROW = MotifRow(int(Relation.CONNECT), _bit(SemanticProperty.EXTERNAL_ENDPOINT), 0, 0)
TARGET = "kc-" + _hex("target", 24)


def _fields(kind: KnowledgeType = KnowledgeType.ANTIBODY, **overrides: Any) -> dict[str, Any]:
    """Every non-derived field of a valid capsule of ``kind``; ``overrides`` win."""
    fields: dict[str, Any] = {
        "knowledge_type": kind,
        "stance": Stance.SUPPORT,
        "semantic_invariant": () if kind is KnowledgeType.REVOCATION else (CRED_ROW, EGRESS_ROW),
        "epoch_context": EpochContext("se-" + _hex("epoch", 16), VisibilityClass.FULL),
        "source_context_sketch": SourceContextSketch(RoleClass.WEB, (3, 2, 1, 0, 0, 1, 0, 0)),
        "validation_summary": ValidationSummary(12, 6, 0),
        "falsification_summary": FalsificationSummary(8, 2, ("H0_COINCIDENCE",)),
        "provenance_commitment": ProvenanceCommitment(
            "peer-" + _hex("peer", 16), ROOT, ("hc-" + _hex("e1", 32), "hc-" + _hex("e2", 32)),
            None,
        ),
        "independence_group": ROOT,
        "created_round": 5,
        "expiry_round": 20,
        "sequence": 3,
        "key_id": "key-" + _hex("key", 16),
    }
    if kind in (KnowledgeType.CAMPAIGN_FRAGMENT, KnowledgeType.NEGATIVE_EVIDENCE):
        fields["time_window"] = (2, 5)
    if kind is KnowledgeType.NEGATIVE_EVIDENCE:
        fields["observability"] = ObservabilityClaim(0.9, 1.0, 0.5)
    if kind is KnowledgeType.REVOCATION:
        fields["revocation_target"] = TARGET
        fields["revocation_ground"] = RevocationGround.SELF_RETRACTION
    fields.update(overrides)
    return fields


def _capsule(kind: KnowledgeType = KnowledgeType.ANTIBODY, **overrides: Any) -> KnowledgeCapsuleV1:
    return seal_capsule(**_fields(kind, **overrides))


def _signed(capsule: KnowledgeCapsuleV1) -> KnowledgeCapsuleV1:
    # A stand-in hex MAC: HMAC verification is identity.integrity's concern, not this schema's.
    mac = hashlib.sha256(capsule.unsigned_bytes()).hexdigest()
    return dataclasses.replace(capsule, signature=mac)


def _refused(payload: object) -> str:
    with pytest.raises(ContractError) as info:
        KnowledgeCapsuleV1.from_dict(payload)  # type: ignore[arg-type]
    return str(info.value)


def _nested_paths(payload: object, path: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    """Every path to a JSON object in ``payload``, the top level included."""
    found: list[tuple[Any, ...]] = []
    if isinstance(payload, dict):
        found.append(path)
        for key, value in payload.items():
            found.extend(_nested_paths(value, (*path, key)))
    elif isinstance(payload, list):
        for index, value in enumerate(payload):
            found.extend(_nested_paths(value, (*path, index)))
    return found


def _at(payload: Any, path: tuple[Any, ...]) -> Any:
    for step in path:
        payload = payload[step]
    return payload


# --- D7.2: what a capsule may assert ------------------------------------------------------------


def test_no_knowledge_type_can_assert_normality() -> None:
    """ADR-0063: a foreign peer may suggest what to fear, never what to trust."""
    assert {t.value for t in KnowledgeType} == {
        "ANTIBODY", "NOVELTY", "CAMPAIGN_FRAGMENT", "NEGATIVE_EVIDENCE", "REVOCATION",
    }  # fmt: skip
    normal = ("BENIGN", "NORMAL", "BASELINE", "TRUST", "ALLOW", "SAFE", "WHITELIST", "CLEAN")
    words = [t.value for t in KnowledgeType] + [s.value for s in Stance]
    assert not [w for w in words if any(n in w for n in normal)]
    assert {s.value for s in Stance} == {"SUPPORT", "CONTEST"}
    # Every refused spelling of normality, and the two types with no consumer (ADR-0062).
    payload = _capsule().to_dict()
    for name in ("BASELINE", "BENIGN", "NORMALITY", "DRIFT_NOTICE", "MODEL_DELTA", "antibody"):
        assert "unknown KnowledgeType" in _refused({**payload, "knowledge_type": name})
    # No key on the wire can carry a verdict or a label, and no string value can say BENIGN.
    keys = {str(p[-1]) for p in _nested_paths(payload) if p} | set(payload)
    assert not [k for k in keys if "verdict" in k or "label" in k or "baseline" in k]
    assert not is_wire_string("BENIGN") and not is_wire_string("UNKNOWN_BENIGN")
    # A contest is the only negative stance, and it exists on antibodies alone.
    for kind in set(KnowledgeType) - {KnowledgeType.ANTIBODY}:
        with pytest.raises(ContractError, match="CONTEST is an ANTIBODY stance only"):
            _capsule(kind, stance=Stance.CONTEST)
    assert _capsule(stance=Stance.CONTEST).stance is Stance.CONTEST


@pytest.mark.parametrize("kind", list(KnowledgeType))
def test_every_knowledge_type_round_trips_through_bytes_and_dict(kind: KnowledgeType) -> None:
    capsule = _capsule(kind)
    signed = _signed(capsule)
    for value in (capsule, signed):
        assert KnowledgeCapsuleV1.from_bytes(value.canonical_bytes()) == value
        assert KnowledgeCapsuleV1.from_dict(json.loads(value.canonical_bytes())) == value
        assert value.canonical_bytes().endswith(b"}\n")
        assert value.digest() == "sha256:" + hashlib.sha256(value.canonical_bytes()).hexdigest()
    # The signature covers everything but itself, and signing changes neither id nor MAC input.
    assert signed.capsule_id == capsule.capsule_id
    assert signed.unsigned_bytes() == capsule.unsigned_bytes()
    assert b'"signature"' not in capsule.unsigned_bytes()
    assert signed.digest() != capsule.digest()
    assert capsule.to_dict()["schema_id"] == "pocketsec.knowledge_capsule.v1"
    assert authority_key_violations(capsule.to_dict()) == ()
    assert wire_string_violations(capsule.to_dict()) == ()


def test_motif_rows_are_stage6_motif_steps_exactly() -> None:
    step = MotifStep(int(Relation.WRITE), _bit(SemanticProperty.PERSISTENCE), _bit(
        SemanticProperty.TEMP_LOCATION), 0b10000)
    row = MotifRow.from_motif_step(step)
    assert row.to_motif_step() == step
    assert row.to_payload() == step.to_payload()
    capsule = _capsule(semantic_invariant=(row,))
    assert capsule.to_dict()["semantic_invariant"] == [step.to_payload()]
    assert motif_pattern_key([row.to_motif_step()]).startswith("motif:")  # Stage 6 can key it
    with pytest.raises(ContractError):
        MotifRow.from_motif_step(row)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "values",
    [
        (len(Relation), 0, 0, 0),  # no such relation
        (0, 1 << OBJECT_WIDTH, 0, 0),  # a property bit the encoder cannot emit
        (0, 0, 1 << OBJECT_WIDTH, 0),
        (0, 0, 0, 1 << RAISED_WIDTH),  # a raised dimension the encoder cannot emit
        (0, 1, 1, 0),  # requires and forbids one property: never matches
        (0, -1, 0, 0),
        (True, 0, 0, 0),
        (0, 1.0, 0, 0),
    ],
)
def test_motif_rows_refuse_bits_the_encoder_cannot_emit(values: tuple[Any, ...]) -> None:
    with pytest.raises(ContractError):
        MotifRow(*values)


def test_row_bounds_are_the_encoder_widths() -> None:
    """Every bit the encoder can set is accepted; the first bit past its width is not."""
    top = MotifRow(len(Relation) - 1, (1 << OBJECT_WIDTH) - 1, 0, (1 << RAISED_WIDTH) - 1)
    everything = _property_mask(frozenset(SemanticProperty))  # the encoder's own mask builder
    assert top.require_properties == everything
    assert MotifRow(0, 0, everything, 0).forbid_properties == everything


def test_derive_chain_stages_follows_the_encoder_labels_and_the_spec_order() -> None:
    read, execute = int(Relation.READ), int(Relation.EXECUTE)
    raised = [n for n in feature_names() if n.startswith("raised.")]
    up = 1 << raised.index("raised.privilege")
    p = SemanticProperty
    cases = {
        MotifRow(read, _bit(p.CREDENTIAL_READER), 0, up): ChainStage.CREDENTIAL,
        MotifRow(execute, _bit(p.PERSISTENCE_WRITER), 0, up): ChainStage.ELEVATION,
        MotifRow(execute, _bit(p.PERSISTENCE), 0, 0): ChainStage.PERSISTENCE,
        MotifRow(execute, _bit(p.EXTERNAL_ENDPOINT), 0, 0): ChainStage.EGRESS,
        MotifRow(read, 0, 0, 0): ChainStage.ACCESS,
        MotifRow(int(Relation.CREATE), 0, 0, 0): ChainStage.ACCESS,  # same family as READ
        MotifRow(execute, 0, 0, 0): ChainStage.OTHER,
        # A forbidden credential is not a credential stage: only required bits count.
        MotifRow(execute, 0, _bit(SemanticProperty.CREDENTIAL), 0): ChainStage.OTHER,
    }  # fmt: skip
    for row, stage in cases.items():
        assert derive_chain_stages((row,)) == (stage,), row
    assert derive_chain_stages(()) == ()


def test_motif_fingerprint_is_bounded_and_order_sensitive() -> None:
    forward, backward = motif_fingerprint((CRED_ROW, EGRESS_ROW)), motif_fingerprint(
        (EGRESS_ROW, CRED_ROW)
    )
    assert re.fullmatch(r"mf-[0-9a-f]{16}", forward) and forward != backward
    for rows in ((), (CRED_ROW,) * (MAX_MOTIF_LENGTH + 1)):
        with pytest.raises(ContractError):
            motif_fingerprint(rows)


# --- D7.2: construction refuses -------------------------------------------------------------------


def test_oversize_bytes_refused_before_parse(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    real_loads = json.loads  # the module's json IS this json: keep the original first

    def watched_loads(text: str, **kwargs: Any) -> Any:
        calls.append(len(text))
        return real_loads(text, **kwargs)

    monkeypatch.setattr(json, "loads", watched_loads)
    for size in (MAX_KNOWLEDGE_CAPSULE_BYTES + 1, 10_240, 102_400, 1_048_576):
        with pytest.raises(ContractError, match="the cap is 4096"):
            KnowledgeCapsuleV1.from_bytes(b"{" + b" " * (size - 2) + b"}")
    assert calls == [], "an oversize payload reached the JSON parser"
    # Control: at exactly the cap the parser *is* reached, so the bound above is what fired.
    with pytest.raises(ContractError, match="unknown schema_id None"):
        KnowledgeCapsuleV1.from_bytes(b"{" + b" " * (MAX_KNOWLEDGE_CAPSULE_BYTES - 2) + b"}")
    assert calls == [MAX_KNOWLEDGE_CAPSULE_BYTES]


@pytest.mark.parametrize("word", sorted(FORBIDDEN_AUTHORITY_FIELDS))
def test_every_authority_key_refused_at_every_depth(word: str) -> None:
    payload = _capsule(KnowledgeType.NEGATIVE_EVIDENCE).to_dict()
    depths = _nested_paths(payload)
    assert len(depths) == 7  # top, five records, observability
    refused = 0
    for path in depths:
        for key in (word, f"x_{word.upper()}_y"):
            tampered = json.loads(json.dumps(payload))
            _at(tampered, path)[key] = 1
            assert "authority-named keys refused" in _refused(tampered), (path, key)
            refused += 1
    # Inside a list item, too: the screen walks arrays, not only objects.
    tampered = json.loads(json.dumps(payload))
    tampered["semantic_invariant"].append({word: 1})
    assert "authority-named keys refused" in _refused(tampered)
    assert refused == 2 * len(depths)


def test_authority_key_violations_names_every_offending_path() -> None:
    payload = {"a": {"Sudo_Mode": 1, "ok": [{"KILL": 2}]}, "execute_now": 3}
    assert authority_key_violations(payload) == (
        "capsule.a.Sudo_Mode", "capsule.a.ok[0].KILL", "capsule.execute_now",
    )  # fmt: skip
    assert authority_key_violations({"fine": [1, "sudo"]}) == ()  # values are not keys


def test_capsule_without_provenance_is_refused() -> None:
    good = _fields()["provenance_commitment"]
    peer, commitments = good.contributor, good.evidence_commitments
    too_many = tuple("hc-" + _hex(str(i), 32) for i in range(MAX_EVIDENCE_COMMITMENTS + 1))
    for args in (
        ("", ROOT, commitments, None),  # no contributor
        (peer, "", commitments, None),  # no root
        (peer, ROOT, (), None),  # zero commitments
        (peer, ROOT, ("sha256:" + "0" * 64,), None),  # a raw digest is not a commitment
        (peer, ROOT, commitments * 1 + (commitments[0],), None),  # a duplicate
        (peer, ROOT, too_many, None),
    ):
        with pytest.raises(ContractError):
            ProvenanceCommitment(*args)
    payload = _capsule().to_dict()
    del payload["provenance_commitment"]
    assert "missing keys ['provenance_commitment']" in _refused(payload)
    payload = _capsule().to_dict()
    payload["provenance_commitment"]["evidence_commitments"] = []
    assert "knowledge without provenance is refused" in _refused(payload)
    with pytest.raises(ContractError):
        _capsule(provenance_commitment=None)


def test_unknown_type_and_version_refused() -> None:
    payload = _capsule().to_dict()
    for key, value in (
        ("schema_id", "pocketsec.knowledge_capsule.v2"), ("schema_id", None),
        ("schema_version", "1.0.1"), ("schema_version", "2.0.0"), ("schema_version", 1),
        ("knowledge_type", "MODEL_DELTA"), ("knowledge_type", "DRIFT_NOTICE"),
        ("knowledge_type", 0),
    ):  # fmt: skip
        assert _refused({**payload, key: value})
    with pytest.raises(ContractError, match="unknown knowledge capsule version"):
        dataclasses.replace(_capsule(), schema_version="2.0.0")
    with pytest.raises(ContractError, match="must be a KnowledgeType"):
        dataclasses.replace(_capsule(), knowledge_type="ANTIBODY")  # type: ignore[arg-type]


def _reseal(payload: dict[str, Any]) -> dict[str, Any]:
    """Recompute ``capsule_id`` so only the tampered field is wrong."""
    payload["capsule_id"] = kc._capsule_id_of(payload)
    return payload


def test_derived_fields_must_match() -> None:
    payload = _capsule().to_dict()
    assert "capsule_id does not match" in _refused({**payload, "capsule_id": TARGET})
    # Any change to a covered field without re-deriving the id is refused.
    assert "capsule_id does not match" in _refused({**payload, "sequence": 4})
    forged = _reseal({**payload, "compact_feature_signature": "mf-" + "0" * 16})
    assert "compact_feature_signature does not match" in _refused(forged)
    forged = _reseal({**payload, "causal_motif": ["EGRESS", "CREDENTIAL"]})
    assert "causal_motif does not match" in _refused(forged)
    # Re-derived honestly, the same change is accepted: the checks are derivations, not freezes.
    assert KnowledgeCapsuleV1.from_dict(_reseal({**payload, "sequence": 4})).sequence == 4


@pytest.mark.parametrize(
    "raw",
    ["/etc/shadow", "alice", "10.0.0.5:22", "rm -rf /", "BENIGN", "kc-" + "A" * 24,
     "peer-" + "0" * 15, "password=hunter2", "cap-0123456789ab", "grp-0123456789abcdef"],
)  # fmt: skip
def test_non_wire_string_refused(raw: str) -> None:
    assert not is_wire_string(raw)
    payload = _capsule(KnowledgeType.CAMPAIGN_FRAGMENT).to_dict()
    targets: list[Callable[[dict[str, Any]], None]] = [
        lambda p: p["provenance_commitment"].update(contributor=raw),
        lambda p: p["epoch_context"].update(software_epoch=raw),
        lambda p: p["falsification_summary"].update(counter_hypotheses=[raw]),
        lambda p: p.update(attack_mappings=[raw]),
        lambda p: p.update(parent_capsules=[raw]),
        lambda p: p.update(key_id=raw),
        lambda p: p.update(signature=raw),
    ]
    for tamper in targets:
        tampered = json.loads(json.dumps(payload))
        tamper(tampered)
        assert wire_string_violations(tampered), raw
        _refused(_reseal(tampered))


def test_independence_group_is_the_declared_root_and_nothing_else() -> None:
    other = "root-" + _hex("root-b", 16)
    with pytest.raises(ContractError, match="independence_group must equal"):
        _capsule(independence_group=other)


@pytest.mark.parametrize(
    "privacy", [PrivacyClass.HOST_SENSITIVE, PrivacyClass.SECRET_BEARING, "PUBLIC_DERIVED"]
)
def test_only_public_derived_knowledge_is_a_capsule(privacy: object) -> None:
    with pytest.raises(ContractError, match="PUBLIC_DERIVED"):
        _capsule(privacy_class=privacy)


def test_attack_mappings_are_always_empty_in_v1() -> None:
    with pytest.raises(ContractError, match="attack_mappings must be empty"):
        _capsule(attack_mappings=("T1003",))
    with pytest.raises(ContractError):
        _capsule(attack_mappings="")  # a string is a Sequence; it is still refused


@pytest.mark.parametrize(
    ("kind", "field", "value"),
    [
        (KnowledgeType.ANTIBODY, "time_window", (1, 2)),
        (KnowledgeType.NOVELTY, "observability", ObservabilityClaim(1.0, 1.0, 1.0)),
        (KnowledgeType.CAMPAIGN_FRAGMENT, "observability", ObservabilityClaim(1.0, 1.0, 1.0)),
        (KnowledgeType.ANTIBODY, "revocation_target", TARGET),
        (KnowledgeType.NEGATIVE_EVIDENCE, "revocation_ground", RevocationGround.LOCAL_EVIDENCE),
        (KnowledgeType.CAMPAIGN_FRAGMENT, "time_window", None),  # required on its own type
        (KnowledgeType.NEGATIVE_EVIDENCE, "observability", None),
        (KnowledgeType.REVOCATION, "revocation_ground", None),
        (KnowledgeType.REVOCATION, "semantic_invariant", (CRED_ROW,)),
        (KnowledgeType.ANTIBODY, "semantic_invariant", ()),
        (KnowledgeType.ANTIBODY, "semantic_invariant", (CRED_ROW,) * (MAX_MOTIF_LENGTH + 1)),
    ],
)
def test_type_specific_fields_live_only_on_their_type(
    kind: KnowledgeType, field: str, value: object
) -> None:
    with pytest.raises(ContractError):
        _capsule(kind, **{field: value})


@pytest.mark.parametrize(
    "overrides",
    [
        {"expiry_round": 5},  # expiry == created
        {"expiry_round": 4},
        {"expiry_round": 5 + MAX_EXPIRY_HORIZON_ROUNDS + 1},
        {"time_window": (3, 3 + MAX_WINDOW_ROUNDS + 1)},
        {"time_window": (5, 4)},
        {"time_window": (1, 2, 3)},
        {"sequence": MAX_WIRE_INT + 1},  # two meanings on a double-parsing peer
        {"created_round": -1},
        {"sequence": True},
    ],
)
def test_windows_expiry_and_integers_beyond_their_caps_are_refused(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ContractError):
        _capsule(KnowledgeType.CAMPAIGN_FRAGMENT, **overrides)
    edge = _capsule(KnowledgeType.CAMPAIGN_FRAGMENT, expiry_round=5 + MAX_EXPIRY_HORIZON_ROUNDS,
                    time_window=(3, 3 + MAX_WINDOW_ROUNDS))  # fmt: skip
    assert edge.time_window == (3, 3 + MAX_WINDOW_ROUNDS)


def test_parents_are_bounded_distinct_never_self_and_required_for_a_derived_capsule() -> None:
    parents = tuple("kc-" + _hex(f"p{i}", 24) for i in range(MAX_PARENT_CAPSULES + 1))
    with pytest.raises(ContractError, match="cap is 8"):
        _capsule(parent_capsules=parents)
    with pytest.raises(ContractError, match="duplicate"):
        _capsule(parent_capsules=(parents[0], parents[0]))
    derived = dataclasses.replace(
        _fields()["provenance_commitment"], aggregation_decision="agg-" + _hex("decision", 32)
    )
    with pytest.raises(ContractError, match="cites its parents"):
        _capsule(provenance_commitment=derived)
    assert _capsule(provenance_commitment=derived, parent_capsules=parents[:2]).parent_capsules
    capsule = _capsule()
    with pytest.raises(ContractError, match="own parent"):
        dataclasses.replace(capsule, parent_capsules=(capsule.capsule_id,))


def test_strict_json_types_are_never_coerced() -> None:
    payload = _capsule(KnowledgeType.NEGATIVE_EVIDENCE).to_dict()
    tampers: list[Callable[[dict[str, Any]], None]] = [
        lambda p: p.update(sequence="3"),
        lambda p: p.update(sequence=3.0),
        lambda p: p.update(created_round=True),
        lambda p: p["observability"].update(sensor_health=1),  # a JSON int is not a float
        lambda p: p["validation_summary"].update(extra=0),  # an undeclared nested key
        lambda p: p["epoch_context"].pop("visibility"),  # a missing nested key
        lambda p: p["semantic_invariant"][0].append(0),  # a five-int row
        lambda p: p.update(time_window={"lo": 2, "hi": 5}),
        lambda p: p.update(stance="support"),  # enum values are case-exact
    ]
    for tamper in tampers:
        tampered = json.loads(json.dumps(payload))
        tamper(tampered)
        _refused(_reseal(tampered))


@pytest.mark.parametrize(
    "data",
    [
        b"[" * 2000 + b"]" * 2000,  # under the cap; nesting that exhausts the parser's stack
        b'{"a":1,"a":2}\n',  # duplicate keys: one byte string, two readings
        b'{"a":NaN}\n',
        b'{"a":1e999}\n',
        b"\xff\xfe{}",
        b"not json",
    ],
)
def test_ambiguous_or_malformed_bytes_are_refused(data: bytes) -> None:
    with pytest.raises(ContractError):
        KnowledgeCapsuleV1.from_bytes(data)


def test_only_the_canonical_encoding_is_accepted() -> None:
    capsule = _capsule()
    canonical = capsule.canonical_bytes()
    variants = (
        canonical.rstrip(b"\n"),
        json.dumps(capsule.to_dict(), indent=1).encode() + b"\n",
        json.dumps(capsule.to_dict(), sort_keys=False, separators=(",", ":")).encode() + b"\n",
    )
    for variant in variants:
        assert variant != canonical
        with pytest.raises(ContractError, match="not the canonical encoding"):
            KnowledgeCapsuleV1.from_bytes(variant)
    with pytest.raises(ContractError):
        KnowledgeCapsuleV1.from_bytes(bytearray(canonical))  # type: ignore[arg-type]


def test_a_self_referencing_payload_is_refused_not_looped_on() -> None:
    payload: dict[str, Any] = dict(_capsule().to_dict())
    payload["epoch_context"] = payload  # a cycle only a Python caller can build
    assert authority_key_violations(payload) == ()  # terminates
    _refused(payload)


def test_seal_derives_what_it_derives_and_refuses_it_from_a_caller() -> None:
    capsule = _capsule()
    assert capsule.signature == ""
    assert capsule.compact_feature_signature == motif_fingerprint(capsule.semantic_invariant)
    assert capsule.causal_motif == (ChainStage.CREDENTIAL, ChainStage.EGRESS)
    for derived in ("capsule_id", "compact_feature_signature", "causal_motif", "signature"):
        with pytest.raises(ContractError, match="may not be supplied"):
            seal_capsule(**_fields(), **{derived: getattr(capsule, derived)})
    with pytest.raises(ContractError, match="unknown fields"):
        seal_capsule(**_fields(), verdict="MALICIOUS")
    with pytest.raises(ContractError, match="missing field"):
        seal_capsule(**{k: v for k, v in _fields().items() if k != "key_id"})


def test_the_largest_legal_capsule_fits_the_byte_cap() -> None:
    """The cap refuses junk, not knowledge: a capsule with every bound at its maximum fits."""
    commitments = tuple("hc-" + _hex(f"e{i}", 32) for i in range(MAX_EVIDENCE_COMMITMENTS))
    half = 1 << (OBJECT_WIDTH - 1)
    widest = MotifRow(len(Relation) - 1, half - 1, half, (1 << RAISED_WIDTH) - 1)
    capsule = _signed(_capsule(
        KnowledgeType.NEGATIVE_EVIDENCE,
        semantic_invariant=(widest,) * MAX_MOTIF_LENGTH,
        validation_summary=ValidationSummary(MAX_WIRE_INT, MAX_WIRE_INT, 0),
        falsification_summary=FalsificationSummary(MAX_WIRE_INT, MAX_WIRE_INT,
                                                   COUNTER_HYPOTHESIS_VALUES),
        provenance_commitment=ProvenanceCommitment(
            "peer-" + _hex("peer", 16), ROOT, commitments, "agg-" + _hex("d", 32)),
        parent_capsules=tuple("kc-" + _hex(f"p{i}", 24) for i in range(MAX_PARENT_CAPSULES)),
        created_round=MAX_WIRE_INT - MAX_EXPIRY_HORIZON_ROUNDS, expiry_round=MAX_WIRE_INT,
        sequence=MAX_WIRE_INT, time_window=(MAX_WIRE_INT - MAX_WINDOW_ROUNDS, MAX_WIRE_INT),
        source_context_sketch=SourceContextSketch(RoleClass.DESKTOP, (3,) * len(RelationFamily)),
    ))  # fmt: skip
    size = len(capsule.canonical_bytes())
    assert size <= MAX_KNOWLEDGE_CAPSULE_BYTES
    assert KnowledgeCapsuleV1.from_bytes(capsule.canonical_bytes()) == capsule


def test_counter_hypotheses_are_the_falsifier_vocabulary() -> None:
    module = _S7 + "falsifier.consensus"
    problem = symbol_problem(module + ":CounterHypothesis")
    if problem is not None:  # not landed yet: allowed only while declared pending
        assert module in PENDING_MODULES, problem
        return
    from pocketsec.stage7.falsifier.consensus import CounterHypothesis

    assert tuple(h.value for h in CounterHypothesis) == COUNTER_HYPOTHESIS_VALUES


# --- structure: T5, the empty collective/ directory, empty subsystem packages ---------------


def _dataclass_fields(tree: ast.Module) -> list[str]:
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and any(
            "dataclass" in ast.unparse(d) for d in node.decorator_list
        ):
            names.extend(
                s.target.id for s in node.body
                if isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name)
            )  # fmt: skip
    return names


def test_t5_no_foundation_dataclass_field_names_an_authority_word() -> None:
    fields = [
        name for path in FOUNDATION_FILES
        for name in _dataclass_fields(ast.parse(path.read_text(encoding="utf-8")))
    ]  # fmt: skip
    assert len(fields) > 40  # the walk found the capsule's fields, not nothing
    assert not [f for f in fields if any(w in f.lower() for w in FORBIDDEN_AUTHORITY_FIELDS)]


def test_the_empty_collective_directory_is_gone_and_foundation_packages_hold_no_code() -> None:
    assert not (STAGE7 / "collective").exists()  # ADR-0121: an empty package dir is a defect
    for package in ("constitution", "capsule"):
        tree = ast.parse((STAGE7 / package / "__init__.py").read_text(encoding="utf-8"))
        body = tree.body[1:] if isinstance(tree.body[0], ast.Expr) else tree.body
        for node in body:
            is_future = isinstance(node, ast.ImportFrom) and node.module == "__future__"
            is_all = isinstance(node, (ast.Assign, ast.AnnAssign)) and "__all__" in ast.dump(node)
            assert is_future or is_all, ast.unparse(node)
