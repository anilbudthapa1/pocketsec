"""Stage 3 — AICT + CRYSTAL: reversible learned-to-executable security intelligence.

Stage 3 takes knowledge that Stage 2 proposed as a compile candidate, decides
whether it has *resolved* enough to be worth compiling, compiles it into a
bounded executable **Knowledge Cell**, and — the part that matters — keeps the
ability to take it back apart when the host stops behaving the way the cell was
validated on.

    Crystallisation answers: what has this host settled into?
    The validity boundary answers: where is that true?
    Melting answers: what do we give back when it stops being true?

**What this stage compiles is not what its architecture document assumed.**
There is no DTL. ADR-0010 rejected it on measured grounds, and the strongest
measured artefact in this repository is a zero-parameter rule — Stage 1's
Φ-oracle. So the first crystallisation target is that rule, handed over by
Stage 2 as a ``CandidateKind.DETERMINISTIC_SCORER`` (ADR-0118). Compiling
something that is already free is the honest test, not the trivial one: it asks
whether the Knowledge Cell machinery earns anything over the rule it wraps. The
measured answer for the Φ-oracle is recorded in ADR-0021 and
``docs/stage-3-findings.md``, and it is not the flattering one.

**Melting is the load-bearing claim, not crystallisation.** Anyone can compile a
model into a table; what would distinguish AICT is that localised drift reopens
one subregion without discarding unrelated crystallised knowledge. That is gate
criterion G3.7 and falsifier F2, and it is measured, not asserted.

**Nothing here is a detection result.** Every corpus in this repository is
synthetic. Stage 3 may validate its *mechanism* — verifier properties, boundary
semantics, melt and rollback, bytecode bounds, the composition algebra — and may
not claim a compression or detection result that transfers to real telemetry.

Dependency boundary (ADR-0001, ADR-0020): Stage 3 is stdlib-only, everywhere.
Unlike Stage 2 it ships **no** ``research`` subpackage and imports no
third-party module at all, because Oracle A is *data* — a frozen
``TeacherSnapshotV1`` produced offline — rather than a live forward pass, so the
runtime never needs a model object. ``tests/test_stage3_boundary.py`` enforces
both halves with an AST walk.

The names below are Stage 3's public surface. They resolve lazily through
``__getattr__``, exactly as Stage 2's do, so ``import pocketsec.stage3`` stays
cheap: a caller that wants one leaf module must not pay for the whole stage on a
2 GB host, and the subpackage ``__init__.py`` files stay empty as the
integration plan requires.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

#: Public name -> the leaf module that defines it. The map is the surface: a
#: name absent here is internal, whatever its module exports.
_SURFACE: dict[str, str] = {}


def _bind(module: str, *names: str) -> None:
    for name in names:
        _SURFACE[name] = module


_bind(
    "pocketsec.stage3.core_ids",
    "AICT_INTERFACE_ID",
    "AICT_INTERFACE_VERSION",
    "CORE_IDS",
    "CoreFunction",
    "FunctionClass",
    "OPTIONAL_IDS",
    "REQUIRED_IDS",
)
_bind(
    "pocketsec.stage3.theory",
    "IntelligenceDensity",
    "KnowledgePressure",
    "ResolutionState",
    "ResolutionThreshold",
    "SecurityConsequence",
    "THRESHOLDS",
    "consequence_of",
    "crystallization_allowed",
)
_bind(
    "pocketsec.stage3.cells.frame",
    "CellFrame",
    "boundary_key_of",
    "frame_digest",
)
_bind(
    "pocketsec.stage3.cells.masks",
    "PROPERTY_ORDER",
    "mask_properties",
    "property_mask",
)
_bind(
    "pocketsec.stage3.cells.invariant",
    "ConsequentSpec",
    "Invariant",
    "MAX_ANTECEDENT_TERMS",
    "PredicateRole",
    "SemanticPredicate",
)
_bind(
    "pocketsec.stage3.cells.operator",
    "MAX_CELL_STEPS",
    "OperatorForm",
    "OperatorProgram",
)
_bind(
    "pocketsec.stage3.cells.schema",
    "AssuranceLevel",
    "AuditPolicy",
    "CellPhase",
    "ConstraintKind",
    "HardConstraint",
    "KNOWLEDGE_CELL_V1_ID",
    "KNOWLEDGE_CELL_V1_VERSION",
    "KnowledgeCellV1",
)
_bind(
    "pocketsec.stage3.cells.field",
    "CellActivation",
    "CompositionOutcome",
    "CompositionVerdict",
    "FieldFull",
    "KnowledgeField",
    "MAX_CELLS",
    "MAX_FIELD_BYTES",
)
_bind("pocketsec.stage3.cells.fission", "FissionDomain", "FissionResult", "fission_cell")
_bind("pocketsec.stage3.cells.fusion", "fuse_cells")
_bind(
    "pocketsec.stage3.bytecode.isa",
    "CellISA",
    "Instruction",
    "MAX_INSTRUCTIONS",
    "MAX_STACK",
    "Op",
    "PCB_VERSION",
    "ValueType",
    "decode",
    "encode",
)
_bind(
    "pocketsec.stage3.bytecode.verifier",
    "ALL_PROVEN_PROPERTIES",
    "CellVerifier",
    "PROVEN_PROPERTIES",
    "STRUCTURAL_PROVEN_PROPERTIES",
    "TESTED_ONLY_PROPERTIES",
    "VerificationReport",
    "verify",
)
_bind("pocketsec.stage3.bytecode.vm", "CellResult", "CellVM")
_bind(
    "pocketsec.stage3.invariants.anti_unification",
    "anti_unify",
)
_bind("pocketsec.stage3.invariants.motifs", "TransitionMotif", "extract_motifs")
_bind(
    "pocketsec.stage3.invariants.discovery",
    "MAX_INVARIANTS",
    "MIN_LINEAGE_SUPPORT",
    "counterfactual_substitution",
    "cross_epoch_validate",
    "discover_invariants",
    "minimal_conditions",
    "predictive_equivalence_clusters",
)
_bind(
    "pocketsec.stage3.boundary.index",
    "BoundaryIndex",
    "BoundaryIndexFull",
    "BoundaryKey",
    "CellBoundary",
    "MAX_INDEX_BYTES",
    "MAX_INDEX_KEYS",
    "MAX_KEYS_PER_CELL",
)
_bind(
    "pocketsec.stage3.boundary.pressure",
    "BoundaryPressureReport",
    "BoundaryProbe",
    "Perturbation",
    "PressureStrategy",
    "apply_boundary_pressure",
    "compare_strategies",
    "random_replay_control",
)
_bind(
    "pocketsec.stage3.synthesis.operators",
    "SYNTHESISERS",
    "synthesize_bytecode",
    "synthesize_lookup_table",
)
_bind(
    "pocketsec.stage3.synthesis.selector",
    "OperatorCandidate",
    "measure_candidate",
    "pareto_frontier",
    "select_operator_form",
)
_bind(
    "pocketsec.stage3.crystal.pipeline",
    "CrystalConfig",
    "CrystalOutcome",
    "CrystalRun",
    "RegionSample",
    "crystallize",
)
_bind(
    "pocketsec.stage3.oracles.security_specs",
    "Violation",
    "check_hard_security_constraints",
)
_bind(
    "pocketsec.stage3.oracles.teacher",
    "TEACHER_SNAPSHOT_V1_ID",
    "TEACHER_SNAPSHOT_V1_VERSION",
    "TeacherOracle",
    "TeacherSnapshotV1",
    "build_phi_oracle_snapshot",
    "load_snapshot",
    "write_snapshot",
)
_bind(
    "pocketsec.stage3.oracles.dual_oracle",
    "DualOracleEvaluator",
    "DualOracleVerdict",
    "SecurityDivergence",
)
_bind(
    "pocketsec.stage3.oracles.counterexamples",
    "Counterexample",
    "CounterexampleStore",
    "MAX_HOT_BYTES",
    "MAX_HOT_COUNTEREXAMPLES",
)
_bind("pocketsec.stage3.promotion.shadow", "SHADOW_MIN_COVERAGE", "ShadowRun", "shadow_execute")
_bind(
    "pocketsec.stage3.promotion.assurance",
    "AssuranceState",
    "PromotionOutcome",
    "PromotionVerdict",
    "promote_cell",
)
_bind(
    "pocketsec.stage3.promotion.audit",
    "AuditReport",
    "AuditSampler",
    "MAX_AUDIT_RATE",
    "MIN_AUDIT_RATE",
    "audit_probability",
)
_bind(
    "pocketsec.stage3.promotion.decay",
    "ConfidenceAction",
    "DECAY_TERMS",
    "MIN_ASSURANCE_CONFIDENCE",
    "below_minimum",
    "decay_confidence",
    "decay_response",
)
_bind(
    "pocketsec.stage3.melting.stress",
    "CellStress",
    "FULL_MELT_THRESHOLD",
    "PARTIAL_MELT_THRESHOLD",
    "compute_cell_stress",
)
_bind("pocketsec.stage3.melting.partial", "partial_melt")
_bind("pocketsec.stage3.melting.full", "MeltKind", "MeltReport", "full_melt", "recrystallize")
_bind(
    "pocketsec.stage3.gc.controller",
    "CellUtility",
    "GCReport",
    "garbage_collect_knowledge",
)
_bind(
    "pocketsec.stage3.resources",
    "STAGE3_BUDGET",
    "STAGE3_NORMAL_INCREMENTAL_RSS_BYTES",
    "STAGE3_PEAK_INCREMENTAL_RSS_BYTES",
    "Stage3ResourceReport",
    "measure_stage3_resources",
)
_bind("pocketsec.stage3.slot", "CRYSTAL_SLOT_NAME", "CrystalSlot")
_bind(
    "pocketsec.stage3.stage4_interface",
    "CRYSTAL_HANDOFF_V1_ID",
    "CRYSTAL_HANDOFF_V1_VERSION",
    "CrystalHandoffV1",
    "build_crystal_handoff",
    "seam_violations",
    "write_crystal_handoff",
)
_bind("pocketsec.stage3.gate", "Stage3GateContext", "run_gate")

__all__ = sorted(_SURFACE)


def __getattr__(name: str) -> Any:
    """Resolve a public name to its leaf module on first access (PEP 562)."""
    module_name = _SURFACE.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module

    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return __all__


if TYPE_CHECKING:  # pragma: no cover - the lazy surface, spelled for type checkers
    from pocketsec.stage3.core_ids import (
        AICT_INTERFACE_ID,
        AICT_INTERFACE_VERSION,
        CORE_IDS,
        OPTIONAL_IDS,
        REQUIRED_IDS,
        CoreFunction,
        FunctionClass,
    )
    from pocketsec.stage3.gate import Stage3GateContext, run_gate
