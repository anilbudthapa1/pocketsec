"""Stage 4 — CBF + LUCID: self-questioning, evidence-conserving security cognition.

Stage 4 exists to prevent **confident single-world storytelling**. It holds
several competing explanations of the same telemetry at once, records what it
could not have seen, decides when the evidence cannot name one answer, and asks
for the specific observation that would separate the survivors.

    The Causal Belief Field answers: which explanations are still standing?
    The sensor shadow answers: where could we not have looked?
    The identifiability engine answers: can this evidence name one world at all?
    The typed claim graph answers: what may we actually say out loud?

**Stage 4 is an attachment, not a layer.** Stage 1-3 detection must keep working
when Stage 4 raises. That is an isolation property, it is a precondition for
everything else, and it was built first: ``engine/degradation.py`` guards every
subsystem, ``engine/integrator.py`` carries the attachment seam, and no module
under ``pocketsec/stage1/`` or ``pocketsec/stage2/`` may import this package
(``tests/test_stage4_boundary.py``, trust rule T7).

**The typed claim graph is the honesty mechanism, not documentation.** OBS / DER
/ INF / CF / EXT / UNK separation is enforced by construction — six distinct
frozen dataclasses whose ``__post_init__`` refuses to mix them — so "zero
unsupported authoritative claims" is a graph walk rather than a promise.

**``Verdict.UNIDENTIFIABLE`` is a success state.** A system that always names a
culprit is not doing causal reasoning. Stage 4 mints no parallel vocabulary: it
reuses Stage 1's ``UNKNOWN`` / ``UNIDENTIFIABLE`` / ``INSUFFICIENT_EVIDENCE``
(ADR-0032).

**Read the gate before believing anything about this stage.** ``run_gate()``
reports twelve criteria and it is *expected to fail*. G4.1's telemetry-source
clause is unmeasurable without a real Linux host; G4.10's baseline comparison
runs and comes out degenerate on every corpus available here. Those failures are
Stage 4's findings, recorded in ``docs/stage-4-findings.md``, not defects awaiting
a fix. A criterion restated until it passes would be the worst outcome available
(ADR-0113).

**Nothing measured here is a detection result.** Every corpus in this repository
is synthetic (ADR-0010), the corpus author and the mechanism author are the same
wave, and timings on this host are contended: figures are within-run ratios with
``/proc/loadavg`` beside them, never absolute microseconds.

Dependency boundary (ADR-0001, ADR-0030): Stage 4 is stdlib-only end to end. It
ships **no** ``research`` subpackage, imports no third-party module anywhere
including its tests, and imports nothing from ``pocketsec.stage3`` — the Stage 3
seam is plain JSON read by ``crystal/handoff.py``, because ADR-0021 is live and a
JSON reader survives a Stage 3 redesign where an import does not.

The names below are Stage 4's public surface. They resolve lazily through
``__getattr__``, exactly as Stage 2's and Stage 3's do, so ``import
pocketsec.stage4`` stays cheap: a caller that wants one leaf module must not pay
for the whole stage on a 2 GB host, and the subpackage ``__init__.py`` files stay
empty as the integration plan requires.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

#: Public name -> the leaf module that defines it. The map *is* the surface: a
#: name absent here is internal, whatever its own module exports.
_SURFACE: dict[str, str] = {}


def _bind(module: str, *names: str) -> None:
    for name in names:
        _SURFACE[name] = module


# --- the stage's own identity -------------------------------------------------

_bind(
    "pocketsec.stage4.core_ids",
    "ABLATION_FLAGS",
    "CBF_INTERFACE_ID",
    "CBF_INTERFACE_VERSION",
    "CORE_IDS",
    "CoreFunction",
    "FunctionClass",
    "OPTIONAL_IDS",
    "REQUIRED_IDS",
    "core_function",
)
_bind(
    "pocketsec.stage4.theory",
    "CBF_THEORY_VERSION",
    "DEFINITIONS",
    "Definition",
    "definition",
    "unbound_terms",
)

# --- the belief field --------------------------------------------------------

_bind(
    "pocketsec.stage4.worlds.world",
    "BeliefGeometry",
    "LatentSecurityState",
    "MAX_WORLD_BYTES",
    "SECURITY_WORLD_V1_ID",
    "SECURITY_WORLD_V1_VERSION",
    "SecurityWorldV1",
    "WorldSupport",
    "WorldSupportState",
    "authority_named_fields",
    "canonical_bytes",
)
_bind(
    "pocketsec.stage4.worlds.field",
    "CAUSAL_BELIEF_FIELD_V1_ID",
    "CAUSAL_BELIEF_FIELD_V1_VERSION",
    "CausalBeliefField",
    "MAX_WORLDS",
    "unknown_world",
)
_bind(
    "pocketsec.stage4.worlds.lifecycle",
    "BirthRefusal",
    "DeathCause",
    "EvidenceRegime",
    "FUSION_EQUIVALENCE_EPSILON",
    "MAX_FISSION_DEPTH",
    "Residual",
    "fission_world",
    "fuse_worlds",
    "kill_world",
    "prune_dominated_worlds",
    "residual_from_transition",
    "spawn_refusal",
    "spawn_world",
)
_bind(
    "pocketsec.stage4.worlds.tombstone",
    "MAX_TOMBSTONES",
    "TombstoneLedger",
    "WorldTombstone",
)
_bind(
    "pocketsec.stage4.graph.sparse_world_graph",
    "MAX_GRAPH_EDGES",
    "MAX_GRAPH_NODES",
    "SparseWorldGraph",
    "Truncation",
    "WorldGraphNode",
)
_bind(
    "pocketsec.stage4.graph.entropy_budget",
    "BUDGET_KINDS",
    "BudgetController",
    "EntropyBudget",
    "MAX_INCIDENT_BYTES",
)

# --- what could not be seen, and what contradicts what -----------------------

_bind(
    "pocketsec.stage4.visibility.model",
    "VISIBILITY_MODEL_V1_ID",
    "VISIBILITY_MODEL_V1_VERSION",
    "VisibilityModel",
    "VisibilityObservation",
    "best_visibility",
    "fit_visibility_model",
    "measure_visibility",
    "signals_of_transition",
)
_bind(
    "pocketsec.stage4.visibility.sensor_shadow",
    "SensorShadow",
    "ShadowRegion",
    "estimate_sensor_shadow",
    "verdict_committal_rank",
    "visibility_adjusted_confidence",
    "visibility_adjusted_verdict",
)
_bind(
    "pocketsec.stage4.tension.evidence_tension",
    "EvidenceTension",
    "TENSION_DEATH_THRESHOLD",
    "TensionTerm",
    "calculate_evidence_tension",
)
_bind(
    "pocketsec.stage4.tension.negative_evidence",
    "NegativeEvidenceVerdict",
    "classify_absence",
    "prediction_strength",
)

# --- counterfactual machinery ------------------------------------------------

_bind(
    "pocketsec.stage4.counterfactual.intervention",
    "Intervention",
    "InterventionKind",
    "InterventionResult",
    "MAX_COUNTERFACTUALS_PER_INCIDENT",
    "ResponsibilityFlux",
    "calculate_responsibility_flux",
    "counterfactual_intervene",
    "normalised_support",
)
_bind(
    "pocketsec.stage4.counterfactual.stress",
    "PerturbationKind",
    "StressMaterial",
    "StressResult",
    "stress_world_adversarially",
    "stresses_actually_run",
)
_bind(
    "pocketsec.stage4.counterfactual.questions",
    "Challenge",
    "QuestionKind",
    "SelfQuestioningVerdict",
    "materially_challenged",
    "self_question_world",
)
_bind(
    "pocketsec.stage4.cones.incident_cone",
    "CausalBranch",
    "IncidentFutureCone",
    "MAX_BRANCHES_PER_WORLD",
    "compose_cones",
    "pairwise_discriminating_signals",
    "predict_world_future_cone",
)

# --- can this evidence name one world, and what would separate them? ---------

_bind(
    "pocketsec.stage4.identifiability.resolution",
    "IDENTIFIABILITY_MARGIN",
    "IdentifiabilityState",
    "IdentifiabilityVerdict",
    "mechanism_polarity",
    "test_identifiability",
)
_bind(
    "pocketsec.stage4.identifiability.horizon",
    "HorizonOutcome",
    "ResolutionHorizon",
)
_bind(
    "pocketsec.stage4.evidence.sequential",
    "SequentialEvidence",
    "StopReason",
    "benign_null_likelihood_ratio",
    "start_benign_null_evidence",
)
_bind(
    "pocketsec.stage4.evidence.calibration",
    "CalibrationReport",
    "EpochCalibration",
    "MIN_CALIBRATION_SAMPLES",
)
_bind(
    "pocketsec.stage4.sensing.active_plan",
    "ObservationPlan",
    "ObservationRequest",
    "SENSOR_COSTS",
    "SensorAction",
    "SensorCost",
    "plan_discriminating_observation",
)
_bind(
    "pocketsec.stage4.sensing.simulate",
    "measure_sensor_costs",
    "signal_discrimination",
    "simulate_sensor_value",
)

# --- what may be said out loud -----------------------------------------------

_bind(
    "pocketsec.stage4.claims.typed_claim",
    "AUTHORITATIVE_KINDS",
    "ClaimKind",
    "CounterfactualClaim",
    "DerivedClaim",
    "ExternalClaim",
    "InferredClaim",
    "ObservedClaim",
    "TYPED_CLAIM_V1_ID",
    "TYPED_CLAIM_V1_VERSION",
    "TypedClaim",
    "UnknownClaim",
    "is_authoritative_kind",
    "kind_of",
)
_bind(
    "pocketsec.stage4.claims.graph",
    "ClaimGraph",
    "ClaimTruncation",
    "EMPTY_CLAIM_GRAPH",
    "LaunderingAttempt",
    "MAX_CLAIMS_PER_GRAPH",
)
_bind(
    "pocketsec.stage4.claims.compiler",
    "AmplificationRefusal",
    "CompiledClaim",
    "amplification_violations",
    "compile_typed_claim_graph",
)
_bind(
    "pocketsec.stage4.claims.verbalizer",
    "VERBALIZER_DEFAULT_ENABLED",
    "Verbalizer",
    "VerbalizerVerdict",
    "validate_verbalization",
    "verbalize_guarded",
)

# --- the loop, its failure surface, and its seams -----------------------------

_bind(
    "pocketsec.stage4.engine.degradation",
    "DEGRADED_VERDICT",
    "DegradationLedger",
    "DegradationRecord",
    "FALLBACKS",
    "Subsystem",
    "downgrade_verdict",
    "guarded",
    "record_for",
)
_bind(
    "pocketsec.stage4.engine.integrator",
    "ATTACHMENT_ORDER",
    "AttachmentOutcome",
    "IncidentEvidence",
    "SubsystemHook",
    "integrate_evidence",
    "run_attached_cognition",
)
_bind(
    "pocketsec.stage4.engine.lucid",
    "IncidentResolution",
    "LucidConfig",
    "LucidEngine",
    "MAX_OPEN_INCIDENTS",
    "UpdateOutcome",
)
_bind(
    "pocketsec.stage4.crystal.handoff",
    "CRYSTAL_HANDOFF_V1_ID",
    "CrystalKnowledge",
    "EMPTY_KNOWLEDGE",
    "load_or_empty",
    "read_crystal_knowledge",
)
_bind(
    "pocketsec.stage4.crystal.feedback",
    "CELL_STRESS_V1_ID",
    "CRYSTAL_CANDIDATE_V1_ID",
    "CellStressSignalV1",
    "CrystalCandidateSignalV1",
    "MIN_CONTRADICTIONS_FOR_STRESS",
    "ResolutionRecord",
    "propose_crystal_candidates",
    "stress_stage3_cell",
    "write_feedback",
)
_bind(
    "pocketsec.stage4.stage5_interface",
    "CBFResolutionV1",
    "CBF_RESOLUTION_V1_ID",
    "CBF_RESOLUTION_V1_VERSION",
    "InformationGap",
    "IncidentHypothesis",
    "export_incident_world_record",
    "write_resolution",
)
_bind("pocketsec.stage4.slot", "CBFSlot", "CBF_SLOT_NAME", "NullIncidentEngine")
_bind(
    "pocketsec.stage4.resources",
    "STAGE4_BUDGET",
    "STAGE4_NORMAL_INCREMENTAL_RSS_BYTES",
    "STAGE4_PEAK_CEILING_BYTES",
    "Stage4ResourceReport",
    "loadavg",
    "measure_stage4_resources",
)

# --- the gate, which is the only thing entitled to say how Stage 4 did -------

_bind(
    "pocketsec.stage4.gate",
    "EXPERIMENT_ID",
    "STAGE4_HYPOTHESIS",
    "STAGE4_SECONDARY",
    "Stage4GateContext",
    "run_gate",
)

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
    from pocketsec.stage4.core_ids import (
        CBF_INTERFACE_ID,
        CBF_INTERFACE_VERSION,
        CORE_IDS,
        OPTIONAL_IDS,
        REQUIRED_IDS,
        CoreFunction,
        FunctionClass,
    )
    from pocketsec.stage4.engine.lucid import LucidConfig, LucidEngine
    from pocketsec.stage4.gate import Stage4GateContext, run_gate
