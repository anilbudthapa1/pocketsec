"""Stage 2 — the DTL Intelligence Core (Dynamic Transition Lattice).

PocketSec's first real learning core. It consumes Stage 1 SSIR transitions, host
security state, behaviour epochs, causal state and uncertainty, and learns the
*dynamics* of a Linux host: what states exist, how they change, which futures
are plausible, what remains uncertain, and which learned transitions could
eventually execute without expensive inference.

> Do not make a tiny model imitate a giant model. Build the smallest adaptive
> machine that knows what security future to expect, knows when it does not
> know, and turns repeated understanding into structure that can eventually
> execute without the model.

**DTL is a research architecture, not a claim of novelty or superiority.** Every
component is compared against strong simple baselines and removed if it does not
improve the measured Pareto frontier (spec section 36).

Dependency boundary (ADR-0008): everything here is stdlib-only **except**
`pocketsec.stage2.research`, which is offline training and evaluation code and
may use numpy. The inference path must never import it.

The names below are Stage 2's public surface. They are resolved lazily through
``__getattr__``, so ``import pocketsec.stage2`` stays cheap: a caller that wants
one leaf module must not pay for the whole stage on a 2 GB host, and the
subpackage ``__init__.py`` files stay empty as the integration plan requires.
Everything reachable here is stdlib-only; ``research`` is deliberately absent.
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
    "pocketsec.stage2.core_ids",
    "CORE_IDS",
    "CoreFunction",
    "DTL_INTERFACE_ID",
    "DTL_INTERFACE_VERSION",
    "ExecutionPath",
    "FunctionClass",
    "PATH_COST_UNITS",
    "REQUIRED_IDS",
)
_bind(
    "pocketsec.stage2.encoder.ssir_encoder",
    "ENCODER_VERSION",
    "EncodedTransition",
    "FEATURE_WIDTH",
    "NEED_SIGNAL_INDICES",
    "encode_ssir_transition",
)
_bind("pocketsec.stage2.dataset", "Stage2Dataset", "Stage2Sample", "build_dataset")
_bind("pocketsec.stage2.state.window", "LineageWindow", "WindowStats", "WindowStore")
_bind(
    "pocketsec.stage2.router.accounting",
    "PathAccount",
    "WorkKind",
    "WorkLedger",
    "WorkRecord",
    "measured",
)
_bind(
    "pocketsec.stage2.router.policy",
    "NeedSignals",
    "ROUTER_DEFAULT_ENABLED",
    "route_information_need",
)
_bind("pocketsec.stage2.lattice.atom", "BehaviourAtom", "CompileStatus")
_bind(
    "pocketsec.stage2.lattice.quantizer",
    "BEHAVIOUR_QUANTIZER_ENABLED",
    "BehaviourQuantizer",
    "DEFAULT_QUANTIZER",
    "HashBucketQuantizer",
    "QuantizeResult",
)
_bind("pocketsec.stage2.lattice.transitions", "LatticeTransition", "TransitionLattice")
_bind(
    "pocketsec.stage2.lattice.equivalence",
    "EquivalenceVerdict",
    "jensen_shannon",
    "predictive_equivalence",
    "successor_distribution",
)
_bind(
    "pocketsec.stage2.lattice.restructure",
    "LatticeRestructurer",
    "MacroState",
    "RestructureReport",
)
_bind(
    "pocketsec.stage2.predictors.heads",
    "HEAD_IDS",
    "HeadPrediction",
    "HeadWeights",
    "PredictiveHeads",
)
_bind("pocketsec.stage2.predictors.residual", "Residual", "score_prediction_residual")
_bind(
    "pocketsec.stage2.predictors.future_cone",
    "ConeBranch",
    "FUTURE_CONE_DEFAULT_ENABLED",
    "FutureCone",
    "marginal_cone",
    "predict_future_cone",
)
_bind(
    "pocketsec.stage2.predictors.hazard",
    "HAZARD_DEFAULT_ENABLED",
    "HazardEstimate",
    "HazardReport",
    "constant_hazard",
    "estimate_security_hazard",
)
_bind(
    "pocketsec.stage2.uncertainty.calibration",
    "CalibrationReport",
    "IsotonicCalibrator",
    "ReliabilityBin",
    "brier_score",
    "expected_calibration_error",
)
_bind("pocketsec.stage2.uncertainty.conformal", "ConformalInterval", "SplitConformal")
_bind(
    "pocketsec.stage2.uncertainty.abstention",
    "EpistemicQuadrant",
    "UncertaintyEstimate",
    "UncertaintySource",
    "estimate_uncertainty",
    "one_minus_max",
)
_bind(
    "pocketsec.stage2.counterfactual.twin",
    "CounterfactualProbe",
    "Intervention",
    "ProbeBudget",
    "counterfactual_probe",
    "phi_only_probe",
    "probe_event",
)
_bind(
    "pocketsec.stage2.counterfactual.value_of_information",
    "InformationNeed",
    "InformationNeedTracker",
    "VoIReport",
    "request_observation_escalation",
    "uncertainty_only_requests",
)
_bind(
    "pocketsec.stage2.credit.ledger",
    "AttributionReport",
    "CausalCreditLedger",
    "CreditEntry",
    "naive_ancestry",
    "top_k_by_delta_phi",
)
_bind(
    "pocketsec.stage2.adaptation.epoch_guard",
    "AdaptationPolicy",
    "AdaptationRun",
    "DriftReport",
    "EpochMismatch",
    "SystemChangeSignal",
    "detect_epoch_mismatch",
    "drift_report",
    "run_adaptation",
)
_bind(
    "pocketsec.stage2.adaptation.quarantine",
    "AdaptationSample",
    "QuarantineBuffer",
    "QuarantineOutcome",
    "QuarantineVerdict",
)
_bind("pocketsec.stage2.adaptation.promotion", "PromotionController", "PromotionRecord")
_bind(
    "pocketsec.stage2.cache.transition_cache",
    "CacheStats",
    "CachedTransition",
    "TransitionCache",
    "transition_cache_key",
)
_bind(
    "pocketsec.stage2.cache.utility",
    "forget_low_utility_memory",
    "future_security_utility",
    "lru_control",
    "random_control",
)
_bind(
    "pocketsec.stage2.compile_candidates.candidate",
    "COMPILE_CANDIDATE_V1_ID",
    "COMPILE_CANDIDATE_V1_VERSION",
    "CandidateKind",
    "CandidateStability",
    "CompileCandidateV1",
    "MeasuredCost",
    "ValidityBoundary",
)
_bind(
    "pocketsec.stage2.compile_candidates.exporter",
    "ExportReport",
    "export_candidates",
    "propose_compile_candidate",
)
_bind(
    "pocketsec.stage2.compile_candidates.phi_oracle_candidate",
    "DeterministicScorerSpec",
    "PHI_ORACLE_SCORER",
    "phi_oracle_candidate",
)
_bind(
    "pocketsec.stage2.compile_candidates.stage3_interface",
    "EvidenceBoundPrediction",
    "STAGE3_HANDOFF_V1_ID",
    "STAGE3_HANDOFF_V1_VERSION",
    "Stage3Handoff",
    "build_handoff",
    "export_evidence_bound_prediction",
    "write_handoff",
)
_bind("pocketsec.stage2.gate", "Stage2GateContext", "run_gate")

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
    from pocketsec.stage2.core_ids import (
        CORE_IDS,
        DTL_INTERFACE_ID,
        DTL_INTERFACE_VERSION,
        PATH_COST_UNITS,
        REQUIRED_IDS,
        CoreFunction,
        ExecutionPath,
        FunctionClass,
    )
    from pocketsec.stage2.gate import Stage2GateContext, run_gate
