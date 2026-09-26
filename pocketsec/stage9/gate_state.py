"""The Stage 9 gate's run configuration and the one context every check reads.

Kept apart from :mod:`pocketsec.stage9.gate` so the build steps (``gate_build``,
``gate_labs``) and the checks (``gate_criteria``) can name the context without importing
the gate, which imports them. Nothing here computes anything: it is the shape of one run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pocketsec.stage1.pipeline import ScenarioResult
from pocketsec.stage2.dataset import Stage2Dataset
from pocketsec.stage9.argus.adversary import ArgusFinding, FittestAttrition
from pocketsec.stage9.genome.computational import ComputationalGenomeV1
from pocketsec.stage9.genome.expressibility import ExpressibilityResult
from pocketsec.stage9.harness.hardware_in_loop import HardwareMeasurement, ProxyCorrelation
from pocketsec.stage9.labs.splits import (
    HEADROOM_COUNT,
    HELDOUT_SEED,
    MAX_COMPILE_WORKERS,
    SATURATED_COUNT,
    TRAIN_SEED,
    CompiledVariant,
    SaturationCheck,
)
from pocketsec.stage9.ontogenesis.fitness import (
    ContaminationReport,
    EvaluationSuite,
    FitnessRecord,
)
from pocketsec.stage9.ontogenesis.search import (
    SEARCH_BUDGET_WU,
    SEARCH_SEEDS,
    SearchRun,
    ShuffledLabelControl,
    StrategyComparison,
    WinnerReport,
)
from pocketsec.stage9.spec.mssc import DetectorComparison, ObjectiveVector

__all__ = [
    "ARM_NAMES",
    "CoarseningEvidence",
    "GateConfig",
    "IsolationResult",
    "Stage9GateContext",
    "SuccessorEvidence",
    "Timing",
]

#: The three seed-matched ablation arms of spec §6 step 4, each switching on ONE flag.
ARM_NAMES: tuple[str, ...] = ("subtractive", "fossil_avoidance", "niches")

Timing = tuple[str, float, tuple[float, float, float], tuple[float, float, float]]


@dataclass(frozen=True, slots=True)
class GateConfig:
    """Run sizes. The defaults ARE the spec's gate (§6); ``pocketsec-stage9 gate`` always
    uses them. :meth:`small` exists only so tests can exercise every check's code path in
    minutes; its report is never the gate's verdict."""

    count: int = HEADROOM_COUNT
    saturated_count: int = SATURATED_COUNT
    train_seed: int = TRAIN_SEED
    heldout_seed: int = HELDOUT_SEED
    budget_wu: int = SEARCH_BUDGET_WU
    seeds: tuple[int, ...] = SEARCH_SEEDS
    workers: int = MAX_COMPILE_WORKERS
    drift_count: int = 120
    drift_seed: int = 11

    @classmethod
    def small(cls) -> GateConfig:
        return cls(
            count=12, saturated_count=12, budget_wu=900_000, seeds=(101,), workers=1, drift_count=12
        )

    @property
    def full(self) -> bool:
        return self == GateConfig()


@dataclass(frozen=True, slots=True)
class CoarseningEvidence:
    """G9.3: one abstraction, its semantic-conservation and counterfactual records."""

    name: str
    kind: str  # "coarse_graining" | "precision" | "minimal_state"
    decision_agreement: float | None
    ap_before: float | None
    ap_after: float | None
    bytes_before: int
    bytes_after: int
    pairs: int
    distinguished_before: int
    distinguished_after: int
    lost: int


@dataclass(frozen=True, slots=True)
class SuccessorEvidence:
    """G9.6: one winner taken through DAEDALUS, the package, the lab registry and the exit."""

    genome_digest: str
    successor_digest: str
    restored_digest: str
    restored_scores_digest: str
    parent_scores_digest: str
    tampering: ArgusFinding
    offered: int
    capsules_built: int
    verdicts: tuple[tuple[str, str, tuple[str, ...]], ...]
    unit_checks_passed: bool
    pcb_expressible: bool
    pcb_reason: str
    #: What the lab registry actually held (S9-R5 / S9-FC-05): a rollback proves something
    #: only if the installed genome differed from, and scored differently to, the parent,
    #: and the registry's ACTIVE genome after rollback is the parent.
    installed_digest: str = ""
    installed_scores_digest: str = ""
    parent_digest: str = ""
    active_after_install: str | None = None
    active_after_rollback: str | None = None

    @property
    def rollback_distinguishable(self) -> bool:
        """Could restoring the parent be told apart from leaving the successor installed?"""
        return (
            self.installed_digest != self.parent_digest
            and self.installed_scores_digest != self.parent_scores_digest
        )


@dataclass(frozen=True, slots=True)
class IsolationResult:
    """G9.10(b): the Φ-oracle's held-out AP computed with Stages 7-9 unimportable."""

    subprocess_ap: float | None
    in_process_ap: float | None
    base_rate: float | None
    returncode: int
    refused_imports: int  # the finder's firing count: >= 1 proves absence was enforced
    loaded: tuple[str, ...]  # Stage 7-9 modules found in the child's sys.modules; must be ()
    detail: str


@dataclass
class Stage9GateContext:
    """One build and one run of everything, so ten checks do not replay the searches."""

    config: GateConfig
    registry_before: str | None
    registry_after: str | None = None
    refused: str = ""
    #: (train variants, held-out variants) between the compile and audit steps only.
    raw_variants: tuple[tuple[CompiledVariant, ...], ...] = ()
    train: EvaluationSuite | None = None
    heldout: EvaluationSuite | None = None
    heldout_results: tuple[ScenarioResult, ...] = ()
    saturated: CompiledVariant | None = None
    saturated_sessions: tuple[Any, ...] = ()
    pairs: Stage2Dataset | None = None
    drift: Stage2Dataset | None = None
    audit_failures: tuple[str, ...] = ()
    contamination: ContaminationReport | None = None
    expressibility: tuple[ExpressibilityResult, ...] = ()
    saturation: dict[str, SaturationCheck] = field(default_factory=dict)
    reference_aps: dict[str, dict[str, float | None]] = field(default_factory=dict)
    hand: dict[str, ComputationalGenomeV1] = field(default_factory=dict)
    hand_train: dict[str, FitnessRecord] = field(default_factory=dict)
    hand_heldout: dict[str, FitnessRecord] = field(default_factory=dict)
    runs: dict[str, tuple[SearchRun, ...]] = field(default_factory=dict)
    shuffled: ShuffledLabelControl | None = None
    reports: tuple[WinnerReport, ...] = ()
    winners: dict[str, tuple[ComputationalGenomeV1, FitnessRecord, FitnessRecord]] = field(
        default_factory=dict
    )
    strategy: StrategyComparison | None = None
    comparisons: dict[str, DetectorComparison] = field(default_factory=dict)
    subject: ComputationalGenomeV1 | None = None
    subject_reason: str = ""
    findings: list[ArgusFinding] = field(default_factory=list)
    attrition: list[tuple[str, FittestAttrition]] = field(default_factory=list)
    coarsenings: list[CoarseningEvidence] = field(default_factory=list)
    lab_notes: dict[str, str] = field(default_factory=dict)
    candidates_examined: int = 0
    promotions: tuple[Any, ...] = ()
    laws: tuple[Any, ...] = ()
    catalog: Any = None
    regime_decisions: tuple[Any, ...] = ()
    transitions_into: dict[str, int] = field(default_factory=dict)
    survival_digest: str = ""
    measurements: list[HardwareMeasurement] = field(default_factory=list)
    proxy: ProxyCorrelation | None = None
    tcn_point: tuple[ObjectiveVector | None, str] = (None, "not measured")
    saturated_phi_ap: float | None = None
    successors: list[SuccessorEvidence] = field(default_factory=list)
    buckets_acted_on: int = 0
    isolation: IsolationResult | None = None
    errors: dict[str, str] = field(default_factory=dict)
    timings: list[Timing] = field(default_factory=list)
