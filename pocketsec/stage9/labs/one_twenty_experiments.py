"""D9.19 (ONTO-F19) — the Stage 9 falsification programme: every S9X experiment and who runs it.

Architecture §67 is headed "120-Experiment Stage 9 Program" but lists **124** ids, S9X-001 to
S9X-124. This catalogue keeps all 124 with their titles verbatim and does not renumber; the
header's "120" is the architecture's miscount, recorded here rather than silently corrected.

Each row says one of three things, and nothing in between:

* ``RUN_BY_GATE`` / ``RUN_BY_CLI`` — a ``"module:function"`` runner (relative to
  ``pocketsec.stage9``) that performs or decides the experiment. ``RUN_BY_GATE`` means the
  spec §6 gate context calls the runner or feeds its result to a gate check; the integrator
  owns the gate, and a row whose runner the gate does not call belongs in ``RUN_BY_CLI``.
  :func:`resolve_runners` imports every one lazily and ``()`` is the only passing answer, so a
  runner that names code that does not exist fails a test instead of reading as coverage.
* ``NOT_BUILT`` — nothing in Stage 9 performs it, with the reason.
* ``BLOCKED_*`` — it cannot be performed in this repository on this host: no real telemetry,
  no 2 GB reference target (this host has 16 GB), no Stage 8 phenotype to ablate against, or no
  second host. The reason names what is missing.

What it refuses to do. A row is never marked RUN because a related function exists: where the
runner covers only part of the title (a SIMULATED resource trace, a non-reference host), the
row's ``reason`` says which part. Runner resolution uses ``importlib`` — one of the three
declared dynamic-import exemptions (spec §2.2) — so this module imports no experiment code at
import time and cannot widen any other module's static import closure.
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from pocketsec.stage0.contracts.common import ContractError

__all__ = [
    "ARCHITECTURE_LISTED_IDS",
    "RUNNER_PACKAGE",
    "S9_EXPERIMENTS",
    "ExperimentStatus",
    "S9Experiment",
    "experiment",
    "resolve_runners",
    "status_counts",
]

#: The architecture's own count of listed ids (its header says 120).
ARCHITECTURE_LISTED_IDS: Final = 124
#: Runners are written relative to this package, as ARGUS's lifecycle runners are.
RUNNER_PACKAGE: Final = "pocketsec.stage9"

_ID_PATTERN = re.compile(r"S9X-\d{3}")
_RUNNER_PATTERN = re.compile(r"[a-z_]+(\.[a-z_0-9]+)+:[A-Za-z_][A-Za-z0-9_]*")


class ExperimentStatus(StrEnum):
    RUN_BY_GATE = "RUN_BY_GATE"
    RUN_BY_CLI = "RUN_BY_CLI"
    NOT_BUILT = "NOT_BUILT"
    BLOCKED_REAL_TELEMETRY = "BLOCKED_REAL_TELEMETRY"
    BLOCKED_NO_2GB_TARGET = "BLOCKED_NO_2GB_TARGET"
    BLOCKED_STAGE8 = "BLOCKED_STAGE8"
    BLOCKED_NO_SECOND_HOST = "BLOCKED_NO_SECOND_HOST"


_RUN_STATUSES = frozenset({ExperimentStatus.RUN_BY_GATE, ExperimentStatus.RUN_BY_CLI})


@dataclass(frozen=True, slots=True)
class S9Experiment:
    """One architecture §67 experiment: title verbatim, status, runner or the reason for none."""

    experiment_id: str
    title: str
    status: ExperimentStatus
    runner: str
    reason: str

    def __post_init__(self) -> None:
        if not _ID_PATTERN.fullmatch(self.experiment_id):
            raise ContractError(f"experiment id must be S9X-NNN, got {self.experiment_id!r}")
        if not self.title:
            raise ContractError(f"{self.experiment_id} needs its architecture title")
        if not isinstance(self.status, ExperimentStatus):
            raise ContractError(f"{self.experiment_id}: unknown status {self.status!r}")
        if self.status in _RUN_STATUSES:
            if not _RUNNER_PATTERN.fullmatch(self.runner):
                raise ContractError(
                    f"{self.experiment_id} is {self.status} but its runner {self.runner!r} is "
                    "not 'module:function'"
                )
        elif self.runner or not self.reason:
            raise ContractError(
                f"{self.experiment_id} is {self.status}: it carries no runner and needs a reason"
            )


_G, _C = ExperimentStatus.RUN_BY_GATE, ExperimentStatus.RUN_BY_CLI
_NB = ExperimentStatus.NOT_BUILT
_RT = ExperimentStatus.BLOCKED_REAL_TELEMETRY
_2G = ExperimentStatus.BLOCKED_NO_2GB_TARGET
_S8 = ExperimentStatus.BLOCKED_STAGE8
_SH = ExperimentStatus.BLOCKED_NO_SECOND_HOST

_SD = "laplace.state_discovery"
_REN = "renormalization.laboratory"
_SUITE, _CONS = "symmetry.suite", "symmetry.conservation"
_PHASE, _MSDL = "geometry.phase", "compression.msdl"
_CHRONOS, _LAWS = "chronos.forgetting_law", "laplace.law_discovery"
_SEARCH, _OBS = "ontogenesis.search", "observatory.convergence"
_ARGUS, _HOME = "argus.adversary", "runtime.homeostatic"

_TOPOLOGY = "the topological/relational state track (architecture §17) has no Stage 9 module"
_SIMULATED = "SIMULATED resource trace; nothing reads a real host's memory"
_MODE_2GB = "the regime is SIMULATED by runtime.homeostatic; a real mode needs the 2 GB target"
_NO_NUMPY = "no learned model exists in Stage 9: numpy is barred (ADR-0080)"

# (id, verbatim §67 title, status, runner, reason). Runner "" for every non-RUN row.
_ROWS: tuple[tuple[str, str, ExperimentStatus, str, str], ...] = (
    ("S9X-001", "state dimension sweep", _C, f"{_SD}:state_dimension_sweep", ""),
    ("S9X-002", "binary state", _G, f"{_SD}:precision_sweep", "1-bit point of the sweep"),
    ("S9X-003", "integer state", _G, f"{_SD}:precision_sweep", ""),
    ("S9X-004", "hybrid state", _G, f"{_SD}:precision_sweep", ""),
    ("S9X-005", "state sufficiency counterfactual", _C, f"{_SD}:state_sufficiency", ""),
    ("S9X-006", "state identifiability", _G, f"{_SD}:discover_minimal_state", ""),
    ("S9X-007", "primitive ablation", _G, "foundry.promotion:promotion_gate", ""),
    ("S9X-008", "primitive promotion", _G, "foundry.promotion:promotion_gate", ""),
    ("S9X-009", "primitive collision", _G, "foundry.promotion:reproduces_seed", ""),
    ("S9X-010", "compound reuse", _G, f"{_OBS}:convergence", ""),
    ("S9X-011", "algorithmic chemistry typing", _G, f"{_ARGUS}:tampered_genome",
     "typing is exercised by the refusals of tampered genomes"),
    ("S9X-012", "autocatalytic search isolation", _NB, "",
     "no autocatalytic search loop is built (architecture §10); programs are stored "
     "macro-expanded and validated against SEED_ALPHABET, a construction property"),
    ("S9X-013", "renormalization level 1", _G, f"{_REN}:run_renormalization", ""),
    ("S9X-014", "level 2", _G, f"{_REN}:run_renormalization", ""),
    ("S9X-015", "level 3", _G, f"{_REN}:run_renormalization", ""),
    ("S9X-016", "semantic conservation", _G, f"{_REN}:semantic_conservation", ""),
    ("S9X-017", "fixed-point convergence", _G, f"{_REN}:run_renormalization", ""),
    ("S9X-018", "fixed-point benign collision", _G, f"{_REN}:counterfactual_distinction", ""),
    ("S9X-019", "symmetry user rename", _G, f"{_SUITE}:invariance",
     "user and PID renaming are the same actor_slot permutation"),
    ("S9X-020", "PID symmetry", _G, f"{_SUITE}:invariance", ""),
    ("S9X-021", "path-class symmetry", _G, f"{_SUITE}:invariance", ""),
    ("S9X-022", "time-translation symmetry", _G, f"{_SUITE}:invariance", ""),
    ("S9X-023", "learned symmetry", _NB, "", "no symmetry learner is built (spec §4.11)"),
    ("S9X-024", "symmetry-breaking detector", _G, f"{_SUITE}:compare_symmetry_breaking", ""),
    ("S9X-025", "conservation symbolic search", _G, f"{_CONS}:conservation_search", ""),
    ("S9X-026", "conservation projection search", _G, f"{_CONS}:conservation_search", ""),
    ("S9X-027", "stable-statistic benign test", _G, f"{_CONS}:conservation_search", ""),
    ("S9X-028", "attack ΔQ test", _G, f"{_CONS}:conservation_search", ""),
    ("S9X-029", "Noether-inspired heuristic", _G, f"{_CONS}:compare_conservation", ""),
    ("S9X-030", "simple-statistic baseline", _G, f"{_CONS}:compare_conservation", ""),
    ("S9X-031", "graph motif baseline", _G, f"{_CONS}:compare_conservation", ""),
    ("S9X-032", "topological summary", _NB, "", _TOPOLOGY),
    ("S9X-033", "persistent feature test", _NB, "", _TOPOLOGY),
    ("S9X-034", "topology noise", _NB, "", _TOPOLOGY),
    ("S9X-035", "causal geometry", _G, "geometry.causal:compare_causal_geometry", ""),
    ("S9X-036", "geodesic anomaly", _G, "geometry.causal:compare_causal_geometry", ""),
    ("S9X-037", "phase parameter search", _G, f"{_PHASE}:compare_phase", ""),
    ("S9X-038", "change-point baseline", _G, f"{_PHASE}:compare_phase", ""),
    ("S9X-039", "precursor variance", _G, f"{_PHASE}:compare_phase", ""),
    ("S9X-040", "precursor autocorrelation", _G, f"{_PHASE}:compare_phase", ""),
    ("S9X-041", "precursor causal instability", _G, f"{_PHASE}:compare_phase",
     "transition rate and family entropy stand in for causal instability"),
    ("S9X-042", "false phase transition", _G, f"{_PHASE}:compare_phase", ""),
    ("S9X-043", "MSDL rule", _G, f"{_MSDL}:compare_msdl_selection", ""),
    ("S9X-044", "MSDL FSM", _G, f"{_MSDL}:compare_msdl_selection", ""),
    ("S9X-045", "MSDL learned model", _NB, "", _NO_NUMPY),
    ("S9X-046", "compressor surprise", _G, f"{_MSDL}:compare_surprise", ""),
    ("S9X-047", "probabilistic surprise", _G, f"{_MSDL}:compare_surprise", ""),
    ("S9X-048", "rare benign surprise", _G, f"{_MSDL}:compare_surprise", ""),
    ("S9X-049", "predictive compression", _G, f"{_MSDL}:compare_surprise", ""),
    ("S9X-050", "nuisance leakage", _C, f"{_MSDL}:nuisance_leakage", ""),
    ("S9X-051", "future-information proxy", _NB, "",
     "Stage 2 rejected the future cone on measured calibration (ADR-0116); not rebuilt"),
    ("S9X-052", "memory ring", _G, f"{_CHRONOS}:evaluate_families", ""),
    ("S9X-053", "memory decay", _G, f"{_CHRONOS}:evaluate_families", ""),
    ("S9X-054", "memory sketch", _G, f"{_CHRONOS}:evaluate_families", ""),
    ("S9X-055", "memory prototype", _G, f"{_CHRONOS}:evaluate_families", ""),
    ("S9X-056", "multiscale memory", _G, f"{_CHRONOS}:evaluate_families", ""),
    ("S9X-057", "forgetting value", _G, f"{_CHRONOS}:compare_forgetting", ""),
    ("S9X-058", "counterfactual deletion", _C, f"{_CHRONOS}:counterfactual_deletion", ""),
    ("S9X-059", "catastrophic deletion", _C, f"{_CHRONOS}:counterfactual_deletion", ""),
    ("S9X-060", "long-term fossil", _NB, "",
     "fossils live only inside one search run (bounded FossilStore); none persist across runs"),
    ("S9X-061", "gradient adaptation", _NB, "", _NO_NUMPY + "; no gradient learner"),
    ("S9X-062", "prototype adaptation", _G, f"{_LAWS}:compare_learning_laws", ""),
    ("S9X-063", "state split", _NB, "", "no state-splitting adaptation law is built"),
    ("S9X-064", "rule refinement", _G, f"{_LAWS}:compare_learning_laws",
     "threshold-refinement laws only"),
    ("S9X-065", "no-learning policy", _G, f"{_LAWS}:compare_learning_laws", ""),
    ("S9X-066", "learning-law search", _G, f"{_LAWS}:compare_learning_laws", ""),
    ("S9X-067", "host objective weights", _C, f"{_LAWS}:apply_host_objective", ""),
    ("S9X-068", "immutable constraint test", _C, f"{_LAWS}:apply_host_objective", ""),
    ("S9X-069", "DAEDALUS compile", _G, "daedalus.synthesizer:synthesize", ""),
    ("S9X-070", "typed genome validation", _G, f"{_ARGUS}:tampered_genome", ""),
    ("S9X-071", "GENESIS replace", _G, "genesis.variation:mutate", ""),
    ("S9X-072", "GENESIS merge", _G, "genesis.variation:mutate", ""),
    ("S9X-073", "GENESIS split", _G, "genesis.variation:mutate", ""),
    ("S9X-074", "GENESIS remove", _G, "genesis.variation:mutate", ""),
    ("S9X-075", "GENESIS specialize", _G, "genesis.variation:mutate", ""),
    ("S9X-076", "GENESIS backend move", _G, "genesis.variation:mutate",
     "MOVE is always refused (one backend exists), so it is expected INERT"),
    ("S9X-077", "subtractive evolution", _G, f"{_SEARCH}:compare_arm", ""),
    ("S9X-078", "component unique utility", _C, "genesis.variation:unique_utility", ""),
    ("S9X-079", "MAP-Elites baseline", _G, "gaia.qd_ecology:compare_qd", ""),
    ("S9X-080", "QD niche coverage", _G, "gaia.qd_ecology:single_architecture_dominance", ""),
    ("S9X-081", "speciation desktop/server", _RT, "",
     "desktop and server niches are measurable=False: single synthetic corpus with no host roles"),
    ("S9X-082", "low-memory species", _G, "genesis.speciation:speciate", ""),
    ("S9X-083", "sensor-limited species", _G, "genesis.speciation:speciate", ""),
    ("S9X-084", "morphogenesis", _G, "genesis.speciation:compare_morphogenesis", ""),
    ("S9X-085", "developmental rule search", _NB, "",
     "morphogenesis applies one fixed rule (best admissible pre-validated genome); no rule search"),
    ("S9X-086", "phenotype transition", _G, f"{_HOME}:drive", _SIMULATED),
    ("S9X-087", "homeostatic RAM", _G, f"{_HOME}:drive", _SIMULATED),
    ("S9X-088", "homeostatic CPU", _C, f"{_HOME}:drive", "SIMULATED; fires only on pressure_trace"),
    ("S9X-089", "queue pressure", _C, f"{_HOME}:drive", "SIMULATED; fires only on pressure_trace"),
    ("S9X-090", "cognitive regime hysteresis", _G, f"{_HOME}:compare_hysteresis", _SIMULATED),
    ("S9X-091", "marginal compute value", _NB, "",
     "the intelligence thermostat (architecture §41) is not built"),
    ("S9X-092", "analyst-attention cost", _RT, "", "no analyst workload telemetry exists"),
    ("S9X-093", "symbiosis search", _C, "gaia.qd_ecology:synergy", ""),
    ("S9X-094", "parasitism removal", _C, "gaia.qd_ecology:parasites", ""),
    ("S9X-095", "extinction", _G, f"{_SEARCH}:run_search", "fossils recorded within one run"),
    ("S9X-096", "fossil avoidance", _G, f"{_SEARCH}:compare_arm", ""),
    ("S9X-097", "independent evolution convergence", _G, f"{_OBS}:convergence", ""),
    ("S9X-098", "law promotion", _G, f"{_OBS}:law_gate",
     "cross_host is always None, so no law can be promoted"),
    ("S9X-099", "law decay", _C, f"{_OBS}:decay_confidence", ""),
    ("S9X-100", "meta-falsify sparsity", _C, f"{_OBS}:meta_falsify", ""),
    ("S9X-101", "meta-falsify causality", _C, f"{_OBS}:meta_falsify", ""),
    ("S9X-102", "meta-falsify specialization", _C, f"{_OBS}:meta_falsify", ""),
    ("S9X-103", "poisoning ARGUS", _G, f"{_ARGUS}:train_label_noise", ""),
    ("S9X-104", "evasion ARGUS", _G, f"{_ARGUS}:attack_findings", ""),
    ("S9X-105", "sensor-loss ARGUS", _G, f"{_ARGUS}:attack_findings", ""),
    ("S9X-106", "resource-starvation ARGUS", _G, f"{_ARGUS}:work_budget_starvation", ""),
    ("S9X-107", "search fitness hacking", _G, f"{_SEARCH}:run_shuffled_label_control", ""),
    ("S9X-108", "benchmark contamination", _G, "ontogenesis.fitness:contamination_attack", ""),
    ("S9X-109", "hardware-in-loop RSS", _2G, "",
     "measured by harness.hardware_in_loop on a 16 GB host; no 2 GB reference target exists"),
    ("S9X-110", "hardware-in-loop cycles", _2G, "",
     "no 2 GB reference target and no cycle-counter (perf) access"),
    ("S9X-111", "proxy-vs-real", _G, "harness.hardware_in_loop:proxy_vs_real",
     "on this non-reference, contended host"),
    ("S9X-112", "proof contract", _G, "successor.proof_carrying:build_successor", ""),
    ("S9X-113", "SMT FSM", _NB, "", "no SMT solver in a stdlib-only runtime (ADR-0001)"),
    ("S9X-114", "successor signature", _G, "successor.proof_carrying:tampered_successor",
     "integrity digests, not authenticity"),
    ("S9X-115", "40MB survival mode", _2G, "", _MODE_2GB),
    ("S9X-116", "100MB reflex mode", _2G, "", _MODE_2GB),
    ("S9X-117", "250MB adaptive mode", _2G, "", _MODE_2GB),
    ("S9X-118", "600MB full mode", _2G, "", _MODE_2GB),
    ("S9X-119", "self-repair substitute", _C, f"{_HOME}:self_repair_substitutions",
     "substitution only; the canary/monitor/rollback half of §57 is not built"),
    ("S9X-120", "foreign architecture transplant", _SH, "",
     "no foreign host or foreign architecture exists to transplant from"),
    ("S9X-121", "full Stage1\u20139 endurance", _RT, "",
     "endurance needs long-running real telemetry; only synthetic corpora exist"),
    ("S9X-122", "full ablation vs Stage8", _S8, "",
     "Stage 9 consumes nothing from Stage 8 in this wave (spec §2.4); G9.1 is BLOCKED_ON_STAGE8"),
    ("S9X-123", "MSSC final tournament", _G, f"{_SEARCH}:compare_strategies", ""),
    ("S9X-124", "independent reproduction", _SH, "",
     "harness.reproducibility:verify_manifest recompiles on this host only; no second host"),
)  # fmt: skip

S9_EXPERIMENTS: tuple[S9Experiment, ...] = tuple(S9Experiment(*row) for row in _ROWS)

# Import-time proof of the catalogue's shape: exactly the architecture's 124 ids, in order.
if tuple(e.experiment_id for e in S9_EXPERIMENTS) != tuple(
    f"S9X-{n:03d}" for n in range(1, ARCHITECTURE_LISTED_IDS + 1)
):
    raise ContractError("S9_EXPERIMENTS must list S9X-001..S9X-124 exactly once, in order")

_BY_ID: Mapping[str, S9Experiment] = MappingProxyType(
    {e.experiment_id: e for e in S9_EXPERIMENTS}
)


def experiment(experiment_id: str) -> S9Experiment:
    """Look a row up by id; an unknown id is a :class:`ContractError`."""
    try:
        return _BY_ID[experiment_id]
    except KeyError:
        raise ContractError(f"no experiment {experiment_id!r} in the §67 programme") from None


def _resolve(runner: str) -> str:
    """``""`` when ``runner`` names a callable; otherwise why it does not."""
    module_name, _, attribute = runner.partition(":")
    try:
        module = importlib.import_module(f"{RUNNER_PACKAGE}.{module_name}")
    except ImportError as exc:
        return f"module does not import ({type(exc).__name__}: {exc})"
    target = getattr(module, attribute, None)
    if target is None:
        return f"{module_name} has no attribute {attribute!r}"
    if not callable(target):
        return f"{runner} is not callable"
    return ""


def resolve_runners() -> tuple[str, ...]:
    """Every RUN row whose runner does not resolve, as ``"S9X-NNN module:function: why"``.

    ``()`` is the only passing answer.
    """
    problems: list[str] = []
    for row in S9_EXPERIMENTS:
        if row.status in _RUN_STATUSES:
            why = _resolve(row.runner)
            if why:
                problems.append(f"{row.experiment_id} {row.runner}: {why}")
    return tuple(problems)


def status_counts() -> Mapping[str, int]:
    """How many rows carry each status, every status present (zeros included)."""
    counts = dict.fromkeys((status.value for status in ExperimentStatus), 0)
    for row in S9_EXPERIMENTS:
        counts[row.status.value] += 1
    return MappingProxyType(counts)
