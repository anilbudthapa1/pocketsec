"""D6.20 (catalogue half) — the sixty Stage 6 experiments, and which of them can run here.

Architecture §50 names sixty experiments. :data:`SIXTY_EXPERIMENTS` holds all sixty with
the titles verbatim and dense ids ``S6X-01 … S6X-60``. Each row is one of two things:

* ``EXECUTABLE`` — it names a ``runner``, the ``"module:function"`` whose execution
  produces the experiment's measured output. Harness-level rows name the endurance
  harness (``labs.endurance``); mechanism-level rows name the mechanism the gate's
  fixtures exercise. The runner is resolved lazily by :func:`resolve_runners`, because
  the endurance package builds in parallel with this one; a runner that does not
  resolve is reported, never assumed.
* ``UNMEASURED`` — no runner, and a non-empty ``limitation`` saying why. The spec fixes
  exactly three: S6X-13, S6X-14 and S6X-15 (EWC/SI regularisation, LwF distillation,
  adapter isolation) have **no object to act on** in a parameter-free symbolic learner
  (ADR-0050). They are reported as UNMEASURED, never as passed.

Several EXECUTABLE rows also carry a limitation, because running an experiment is not the
same as answering its title: the neural half of S6X-39 and the ONNX half of S6X-52/53 are
UNMEASURED while their symbolic/stdlib halves run; "real drift" (S6X-31, S6X-47) is a
harness-asserted ``SystemChangeSignal``; every Stage 5 record is ``simulated=True``; and the
motif representation cannot express timing, so S6X-21's timing perturbations cannot move a
motif match *by construction* — a result that looks like robustness and is not.

This module runs nothing, records nothing and never touches ``experiments/registry.jsonl``
(registration is the explicit ``pocketsec-stage6 experiments`` subcommand).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage6.core_ids import SYMBOL_PATTERN, symbol_problem

__all__ = [
    "EXPERIMENTS_BY_ID",
    "SIXTY_EXPERIMENTS",
    "ExperimentStatus",
    "Stage6Experiment",
    "resolve_runners",
    "unmeasured_experiments",
]


class ExperimentStatus(StrEnum):
    EXECUTABLE = "EXECUTABLE"
    UNMEASURED = "UNMEASURED"


_DELIVERABLE = re.compile(r"^D6\.(?:[1-9]|1\d|20)$")


@dataclass(frozen=True, slots=True)
class Stage6Experiment:
    """One row of architecture §50."""

    experiment_id: str
    title: str
    deliverable: str
    status: ExperimentStatus
    runner: str | None
    limitation: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"S6X-(0[1-9]|[1-5]\d|60)", self.experiment_id):
            raise ContractError(f"experiment id must be S6X-01..S6X-60, got {self.experiment_id!r}")
        if not self.title.strip():
            raise ContractError(f"{self.experiment_id}: empty title")
        if not _DELIVERABLE.fullmatch(self.deliverable):
            raise ContractError(f"{self.experiment_id}: deliverable {self.deliverable!r}")
        if self.status is ExperimentStatus.UNMEASURED:
            if self.runner is not None:
                raise ContractError(f"{self.experiment_id}: an UNMEASURED row names no runner")
            if not self.limitation.strip():
                raise ContractError(f"{self.experiment_id}: UNMEASURED must say why")
        elif self.runner is None or not SYMBOL_PATTERN.fullmatch(self.runner):
            raise ContractError(f"{self.experiment_id}: EXECUTABLE needs a module:function runner")


_S6 = "pocketsec.stage6."
_ENDURANCE = _S6 + "labs.endurance:run_endurance"
_POISON = _S6 + "labs.endurance:run_poison_suite"
_ABLATION = _S6 + "labs.endurance:run_ablation"
_REPLAY = _S6 + "rehearsal.counterfactual:generate_counterfactual_replay"
_SHADOW = _S6 + "shadow.mind:ShadowMind.run_shadow_mind"
_QUANT = _S6 + "export.quantized_candidates:evaluate_quantized"

_SYNTHETIC = "synthetic endurance timeline (spec §9.1); no real long-horizon telemetry"
_NOT_APPLICABLE = (
    "not applicable to a parameter-free learner (ADR-0050): Stage 6 ships no numpy and no "
    "research package, so there are no parameters to {what}"
)

# (title verbatim from architecture §50, deliverable, runner or None, limitation)
_ROWS: tuple[tuple[str, str, str | None, str], ...] = (
    ("experience capsule schema", "D6.2",
     _S6 + "capsule.experience_capsule:build_experience_capsule", ""),
    ("quarantine isolation", "D6.2", _S6 + "capsule.quarantine:QuarantineGateway.admit", ""),
    ("provenance scoring", "D6.3", _S6 + "provenance.trust:score_provenance",
     "source-class and label-origin weights are chosen parameters (spec §4.21), not calibrated"),
    ("duplicate/dependence detection", "D6.3",
     _S6 + "provenance.trust:detect_evidence_dependence",
     "independence groups are hashed lineages; causal-root grouping is not built (spec §9.2)"),
    ("episodic admission", "D6.4", _S6 + "memory.episodic:EpisodicMemory.admit_episode", ""),
    ("bounded reservoir baseline", "D6.20", _ENDURANCE, _SYNTHETIC),
    ("semantic episode compression", "D6.4", _S6 + "memory.episodic:skeleton_from_capsule", ""),
    ("epistemic half-life", "D6.5", _ABLATION, _SYNTHETIC),
    ("APF plasticity", "D6.6", _ABLATION, _SYNTHETIC),
    ("plasticity masks", "D6.6", _S6 + "plasticity.masks:generate_plasticity_mask", ""),
    ("naive fine-tune forgetting baseline", "D6.20", _ENDURANCE, _SYNTHETIC),
    ("replay baseline", "D6.20", _ENDURANCE, _SYNTHETIC),
    ("regularization baseline", "D6.20", None,
     _NOT_APPLICABLE.format(what="regularise (EWC/SI)")),
    ("distillation baseline", "D6.20", None,
     _NOT_APPLICABLE.format(what="distil and no teacher logits (LwF)")),
    ("adapter isolation baseline", "D6.20", None,
     _NOT_APPLICABLE.format(what="isolate and no base network to adapt")),
    ("prototype baseline", "D6.20", _ENDURANCE, _SYNTHETIC),
    ("knowledge competition", "D6.7", _ABLATION, _SYNTHETIC),
    ("counterfactual rehearsal", "D6.8", _ABLATION, _SYNTHETIC),
    ("semantic rename replay", "D6.8", _REPLAY, ""),
    ("telemetry-drop replay", "D6.8", _REPLAY, ""),
    ("timing perturbation replay", "D6.8", _REPLAY,
     "motifs cannot express timing (spec §4.0), so timing variants cannot change a motif "
     "match by construction; invariance here is not robustness"),
    ("knowledge fossil", "D6.9", _S6 + "fossils.store:FossilStore.create_fossil", ""),
    ("fossil integrity", "D6.9", _S6 + "fossils.store:FossilStore.load",
     "integrity by sha256 only; encryption at rest is not implemented (spec §9.2)"),
    ("lineage DAG", "D6.10", _S6 + "fossils.lineage:KnowledgeLineageDAG.update_lineage_dag", ""),
    ("candidate evolution chamber", "D6.11",
     _S6 + "chamber.evolution:EvolutionChamber.spawn_evolution_candidate",
     "candidate kinds are only those with an executor; no classifier/adapter/structural kind "
     "(ADR-0056)"),
    ("shadow mind", "D6.13", _SHADOW, ""),
    ("sampled shadow scheduling", "D6.13", _SHADOW, ""),
    ("conservation gate", "D6.14", _S6 + "conservation.gate:offline_validation",
     "every EPS_* bound is a chosen parameter (spec §4.21)"),
    ("canary promotion", "D6.17",
     _S6 + "promotion.controller:LearningPromotionController.promote_canary", ""),
    ("automatic learning rollback", "D6.17",
     _S6 + "promotion.controller:LearningPromotionController.observe_probation",
     "rollback depth is bounded by MAX_FOSSILS; older states are unrecoverable by design"),
    ("legitimate package-upgrade drift", "D6.16", _ENDURANCE,
     "the upgrade is a harness-asserted SystemChangeSignal; real package-upgrade drift is "
     "UNMEASURED (spec §6.1)"),
    ("new-service epoch", "D6.16",
     _S6 + "homeostasis.drift:KnowledgeContextRegistry.open_new_epoch", ""),
    ("recurring old epoch", "D6.16", _ENDURANCE, _SYNTHETIC),
    ("knowledge resurrection", "D6.16",
     _S6 + "homeostasis.drift:KnowledgeContextRegistry.resurrect_dormant_knowledge", ""),
    ("slow baseline poisoning", "D6.15", _POISON,
     "arms P2/P2b; the adversary is this wave's own and does not adapt to §4.21 parameters"),
    ("malicious repetition normalization", "D6.15", _POISON,
     "arms P1/P1b; the adversary is this wave's own and does not adapt to §4.21 parameters"),
    ("label poisoning", "D6.15", _POISON, "arm P3; analyst labels are simulated"),
    ("teacher label corruption", "D6.15", _POISON,
     "arm P3b; no teacher model exists, teacher labels are simulated with a declared error share"),
    ("trigger/backdoor candidate", "D6.15", _POISON,
     "symbolic trigger half only (arm P4c); the neural backdoor half is UNMEASURED because no "
     "neural candidate exists (ADR-0050)"),
    ("quarantine flooding", "D6.15", _POISON, "arm P6"),
    ("epoch manipulation", "D6.16", _POISON, "arm P5"),
    ("lineage tampering", "D6.10", _S6 + "fossils.lineage:KnowledgeLineageDAG.verify", ""),
    ("fossil corruption", "D6.9", _POISON, "arm P4b; corruption is injected by the harness"),
    ("model artifact tampering", "D6.14", _POISON,
     "arm P4a; the artifact is symbolic state bytes, not a model file"),
    ("semantic homeostasis", "D6.15",
     _S6 + "homeostasis.poisoning:detect_semantic_normalization_attack", ""),
    ("drift-vs-poison discriminator", "D6.16",
     _S6 + "homeostasis.drift:classify_drift_vs_poisoning", ""),
    ("false poison alarm under real drift", "D6.16", _ENDURANCE,
     "drift is synthetic (M02/M03 harness signals); a false-alarm rate under real drift is "
     "UNMEASURED"),
    ("resource-pressure consolidation", "D6.12", _ENDURANCE,
     "month M11's pressure is a constructed ResourceSnapshot, not a loaded host"),
    ("OOM shadow failure", "D6.13", _SHADOW,
     "simulated_oom: exhaustion of the shadow's work/byte budget, not a real out-of-memory kill"),
    ("month-scale memory growth simulation", "D6.20", _ENDURANCE, _SYNTHETIC),
    ("year-scale knowledge aging simulation", "D6.20", _ENDURANCE,
     "60 months repeat one synthetic year; the plateau shows caps binding, not real saturation"),
    ("INT8 candidate benchmark", "D6.18", _QUANT,
     "stdlib array quantisation of symbolic state only; ONNX export and ONNX Runtime INT8 are "
     "UNMEASURED (ADR-0050)"),
    ("INT4 candidate benchmark where applicable", "D6.18", _QUANT,
     "stdlib array quantisation of symbolic state only; ONNX Runtime INT4 is UNMEASURED "
     "(ADR-0050)"),
    ("offline teacher-assisted labeling", "D6.15",
     _S6 + "labs.poison_suite:simulated_teacher_labels",
     "no teacher model exists; labels are simulated_teacher_labels with a declared error share"),
    ("optional fleet signed package", "D6.19", _S6 + "fleet.package:verify_package",
     "fleet exchange is off by default; HMAC proves key membership, not host identity"),
    ("fleet duplicate/Sybil simulation", "D6.19", _S6 + "fleet.package:package_to_capsules",
     "simulated fleet; one fleet group is one independence group"),
    ("privacy leakage audit", "D6.2", _S6 + "capsule.experience_capsule:privacy_audit",
     "pattern screen over synthetic capsules; not a formal privacy guarantee"),
    ("full ablation", "D6.20", _ABLATION,
     "gated by preconditions E1-E5; synthetic data cannot pass G6.13 (spec §6.1)"),
    ("simpler-baseline falsification", "D6.20", _ENDURANCE, _SYNTHETIC),
    # The en dash is architecture §50's own character; the title is verbatim by contract.
    ("complete Stage1–6 endurance run", "D6.20", _ENDURANCE,  # noqa: RUF001
     "Stages 3-5 participate only through synthetic records built via their handoff types, "
     "not live; every Stage 5 record is simulated=True"),
)


def _experiment(index: int, row: tuple[str, str, str | None, str]) -> Stage6Experiment:
    title, deliverable, runner, limitation = row
    status = ExperimentStatus.UNMEASURED if runner is None else ExperimentStatus.EXECUTABLE
    return Stage6Experiment(f"S6X-{index:02d}", title, deliverable, status, runner, limitation)


SIXTY_EXPERIMENTS: tuple[Stage6Experiment, ...] = tuple(
    _experiment(index, row) for index, row in enumerate(_ROWS, start=1)
)

EXPERIMENTS_BY_ID: Mapping[str, Stage6Experiment] = MappingProxyType(
    {experiment.experiment_id: experiment for experiment in SIXTY_EXPERIMENTS}
)

if len(SIXTY_EXPERIMENTS) != 60 or len(EXPERIMENTS_BY_ID) != 60:
    raise ContractError("architecture §50 names exactly sixty experiments")


def unmeasured_experiments() -> tuple[Stage6Experiment, ...]:
    """Rows that cannot run in this repository, each with its limitation."""
    return tuple(e for e in SIXTY_EXPERIMENTS if e.status is ExperimentStatus.UNMEASURED)


def resolve_runners() -> tuple[str, ...]:
    """Distinct runner paths that fail to resolve; ``()`` means every runner exists."""
    runners = sorted({e.runner for e in SIXTY_EXPERIMENTS if e.runner is not None})
    return tuple(runner for runner in runners if symbol_problem(runner) is not None)
