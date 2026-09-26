"""D8.19 — the S8X-001 … S8X-128 experiment catalogue: every row, its runner, its honest status.

Architecture §52 lists 80 experiments and §111 adds 48 (AION). A list is not a benchmark: this
catalogue binds each row to the function that MEASURES it (``runner``, a resolvable
``pocketsec.stage8.<module>:<qualname>``), or states in the row's ``reason`` why it is NOT_BUILT
(the capability does not exist, on purpose or for lack of an offline dependency) or BLOCKED
(B8-1: nothing Stage 8 hands over reaches Stage 6's TRUSTED_CANDIDATE, so the Stage 6 machinery
those rows probe never sees a Stage 8 candidate). Statuses are the spec's fixed table (§D8.19);
titles are the architecture's, verbatim, and :func:`catalogue_problems` compares them with the
architecture file itself.

What it refuses to do: a catalogue row is never evidence. ``MEASURED_IN_GATE`` means the gate
runs the named function; ``MEASURED_IN_CLI`` means ``pocketsec-stage8 experiments`` does. The
figures live in the findings, produced by running code, never here. Nothing in this module
writes the project's experiment registry. ``importlib`` is used only to resolve runner strings
(boundary rule 13 permits it in this file).
"""

from __future__ import annotations

import importlib
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from pocketsec.stage0.gate import REPO_ROOT

__all__ = [
    "ARCHITECTURE_FILE",
    "CATALOGUE",
    "CATALOGUE_SIZE",
    "CatalogueRow",
    "CatalogueStatus",
    "architecture_titles",
    "catalogue_problems",
    "resolve_runner",
]

CATALOGUE_SIZE = 128
ARCHITECTURE_FILE = (REPO_ROOT / "docs" / "architecture" / "sources"
                     / "stage-08-prometheus-oracle-forge.md")
_RUNNER = re.compile(r"^pocketsec\.stage8(?:\.[a-z_][a-z0-9_]*)+:"
                     r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_ARCH_ROW = re.compile(r"^S8X-(\d{2,3})\s+(\S.*?)\s*$")


class CatalogueStatus(StrEnum):
    MEASURED_IN_GATE = "MEASURED_IN_GATE"
    MEASURED_IN_CLI = "MEASURED_IN_CLI"
    NOT_BUILT = "NOT_BUILT"
    BLOCKED = "BLOCKED"


_MEASURED = frozenset({CatalogueStatus.MEASURED_IN_GATE, CatalogueStatus.MEASURED_IN_CLI})


@dataclass(frozen=True, slots=True)
class CatalogueRow:
    experiment_id: str            # "S8X-001" … "S8X-128"
    title: str                    # the architecture's §52 / §111 title, verbatim
    deliverable: str              # "D8.NN" or "AION"
    status: CatalogueStatus
    runner: str | None            # "pocketsec.stage8.<module>:<qualname>" for MEASURED rows
    reason: str                   # required unless MEASURED_*


_S = "pocketsec.stage8."
_G, _C, _N, _B = (CatalogueStatus.MEASURED_IN_GATE, CatalogueStatus.MEASURED_IN_CLI,
                  CatalogueStatus.NOT_BUILT, CatalogueStatus.BLOCKED)

_RUN = _S + "labs.discovery_run:run_discovery"
_ABL = _S + "labs.baselines:run_ablation"
_ORC = _S + "labs.baselines:oracle_comparison"
_CF = _S + "laboratory.counterfactual:apply_transform"
_MM = _S + "laboratory.metamorphic:run_metamorphic"
_DOP = _S + "doppelganger.engine:DoppelgangerEngine.challenge"
_CHC = _S + "challenger.adversarial:build_challenge_corpus"
_IDG = _S + "identifiability.gate:IdentifiabilityGate.assess"
_REP = _S + "reproducibility.gate:ReproducibilityGate.run"
_AUD = _S + "novelty.prior_art_audit:audit"
_CMP = _S + "forge.compiler:compile_all"
_FTP = _S + "forge.tournament:measure_endpoint_footprint"

_NO_CAUSAL_LIB = ("no offline causal-discovery library; a stdlib PC/FCI/GES/NOTEARS is out of "
                  "scope (spec §9)")
_B8_1 = ("B8-1 (ADR-0076): no Stage 8 hand-over reaches TRUSTED_CANDIDATE, and Stage 8 may not "
         "call Shadow Mind, the Conservation Gate or canary rollback")
_OBS = _S + "residual.observatory:ResidualObservatory.observe"
_GEN = _S + "prometheus.generators:"
_POP = _S + "ecology.population:"
_AION = "AION is architecture/representation invention, Stage 9's remit (ADR-0070)"

# (id, title verbatim, deliverable, status, runner, reason) — the spec's §D8.19 status table.
_ROWS: tuple[tuple[int, str, str, CatalogueStatus, str | None, str], ...] = (
    (1, "residual field construction", "D8.02", _G, _OBS, ""),
    (2, "residual decomposition", "D8.02", _G, _OBS, ""),
    (3, "priority calibration", "D8.02", _G, _ABL, ""),
    (4, "telemetry-failure residual", "D8.02", _G, _RUN, ""),
    (5, "hypothesis genome validation", "D8.03", _G, _S + "genome.hypothesis:HypothesisGenome", ""),
    (6, "mechanism grammar coverage", "D8.03", _C, _S + "genome.grammar:parse_mechanism", ""),
    (7, "symbolic generator", "D8.04", _G, _GEN + "SymbolicEnumerator.propose", ""),
    (8, "LLM generator", "D8.04", _N, None,
     "no LLM is built; ExternalProposalGenerator is its seam and is measured as S8X-053 "
     "(ADR-0074)"),
    (9, "analogy generator", "D8.04", _G, _GEN + "AnalogyGenerator.propose", ""),
    (10, "null/benign generator", "D8.04", _G, _GEN + "NullBenignGenerator.propose", ""),
    (11, "hypothesis diversity", "D8.04", _G, _S + "prometheus.engine:diversity_select", ""),
    (12, "bounded mutation", "D8.05", _G, _POP + "HypothesisPopulation.mutate", ""),
    (13, "hypothesis merge/split", "D8.05", _G, _POP + "HypothesisPopulation.merge", ""),
    (14, "MDL complexity", "D8.05", _G, _POP + "mdl_accepts", ""),
    (15, "Bayesian competition", "D8.06", _G, _S + "oracle.information_gain:update", ""),
    (16, "score competition", "D8.05", _G, _POP + "HypothesisPopulation.score", ""),
    (17, "prediction-before-observation", "D8.11", _G,
     _S + "ledger.theory:TheoryLedger.registered_before_tested", ""),
    (18, "hidden holdout integrity", "D8.18", _G,
     _S + "sandbox.integrity:HoldoutVault.evaluate", ""),
    (19, "historical replay", "D8.06", _G, _S + "oracle.planner:OraclePlanner.run", ""),
    (20, "time-split replay", "D8.12", _G, _REP, ""),
    (21, "host-split replay", "D8.12", _G, _REP, ""),
    (22, "family/campaign split", "D8.12", _G, _REP, ""),
    (23, "counterfactual rename", "D8.07", _C, _CF, ""),
    (24, "timing mutation", "D8.07", _C, _CF, ""),
    (25, "telemetry dropout", "D8.07", _C, _CF, ""),
    (26, "decoy insertion", "D8.07", _C, _CF, ""),
    (27, "causal-edge deletion", "D8.07", _G, _MM, ""),
    (28, "metamorphic invariant", "D8.07", _G, _MM, ""),
    (29, "benign doppelgänger admin", "D8.08", _G, _DOP, ""),
    (30, "software-update doppelgänger", "D8.08", _G, _DOP, ""),
    (31, "backup/orchestration doppelgänger", "D8.08", _G, _DOP, ""),
    (32, "adversarial challenger", "D8.09", _G, _S + "challenger.adversarial:challenge", ""),
    (33, "living-off-land substitution", "D8.09", _G, _CHC, ""),
    (34, "slow behavior", "D8.09", _G, _CHC, ""),
    (35, "event flood robustness", "D8.09", _G, _CHC, ""),
    (36, "shortcut trigger", "D8.09", _G, _S + "labs.discovery_run:probe_trap_at_holdout", ""),
    (37, "EIG experiment selection", "D8.06", _G, _ORC, ""),
    (38, "random experiment baseline", "D8.06", _G, _ORC, ""),
    (39, "cost-aware EIG", "D8.06", _G, _ORC, ""),
    (40, "stopping rule", "D8.06", _G, _S + "oracle.planner:OraclePlanner.run", ""),
    (41, "causal identifiability", "D8.10", _G, _IDG, ""),
    (42, "equivalence class", "D8.10", _G, _IDG, ""),
    (43, "unidentifiable abstention", "D8.10", _G, _IDG, ""),
    (44, "PC baseline", "D8.10", _N, None, _NO_CAUSAL_LIB),
    (45, "FCI baseline", "D8.10", _N, None, _NO_CAUSAL_LIB),
    (46, "GES/score baseline", "D8.10", _N, None, _NO_CAUSAL_LIB),
    (47, "NOTEARS-style baseline", "D8.10", _N, None, _NO_CAUSAL_LIB),
    (48, "sandbox isolation", "D8.18", _G, _S + "sandbox.boundary:ResearchSandbox.decide", ""),
    (49, "CALDERA known-technique lab", "D8.18", _N, None,
     "no emulator and no network in this repository; ISOLATED_EMULATION is refused (ADR-0075)"),
    (50, "sandbox kill switch", "D8.18", _G, _S + "governor.budget:ResearchGovernor.charge", ""),
    (51, "experiment tamper detection", "D8.18", _G, _S + "sandbox.integrity:verify_record", ""),
    (52, "hypothesis DoS", "D8.18", _G, _RUN, ""),
    (53, "prompt/log injection", "D8.04", _G, _GEN + "ExternalProposalGenerator.propose", ""),
    (54, "poisoned retrieval", "D8.09", _G, _S + "challenger.adversarial:poisoned_labels", ""),
    (55, "teacher self-confirmation", "D8.14", _N, None,
     "no teacher model: distillation from a large research model (§30) is not built"),
    (56, "negative-result memory", "D8.11", _G,
     _S + "ledger.negative_results:NegativeResultMemory.is_dead_end", ""),
    (57, "novelty ATT&CK mapping", "D8.13", _N, None,
     "no offline ATT&CK index and no network (D8.13)"),
    (58, "Sigma/YARA overlap audit", "D8.13", _N, None,
     "no offline Sigma or YARA index and no network (D8.13)"),
    (59, "known-combination classification", "D8.13", _G, _AUD, ""),
    (60, "potential-novelty review", "D8.13", _G, _AUD, ""),
    (61, "FORGE rule", "D8.14", _G, _CMP, ""),
    (62, "FORGE FSM", "D8.14", _G, _CMP, ""),
    (63, "FORGE Knowledge Cell", "D8.14", _N, None,
     "Stage 3's CellISA is single-frame and straight-line; the Knowledge Cell target is "
     "Stage 9's seam (ADR-0072)"),
    (64, "FORGE logistic model", "D8.14", _G, _CMP, ""),
    (65, "FORGE tree model", "D8.14", _G, _CMP, ""),
    (66, "FORGE tiny neural model", "D8.14", _N, None,
     "no research package and no numpy in Stage 8 (ADR-0070); neural targets not built (ADR-0072)"),
    (67, "representation tournament", "D8.15", _G, _S + "forge.tournament:run_tournament", ""),
    (68, "INT8 export", "D8.15", _N, None, "no quantised or ONNX export target (ADR-0072)"),
    (69, "compression ratio", "D8.15", _G, _S + "forge.tournament:discovery_compression_ratio", ""),
    (70, "edge latency", "D8.15", _G, _FTP, ""),
    (71, "edge RSS", "D8.15", _G, _FTP, ""),
    (72, "cross-epoch generalization", "D8.12", _G, _REP, ""),
    (73, "Stage6 quarantine", "D8.17", _G, _S + "adapters.stage6:Stage6Adapter.hand_over", ""),
    (74, "Shadow Mind discovery", "D8.17", _B, None, _B8_1),
    (75, "Conservation Gate rejection", "D8.17", _B, None, _B8_1),
    (76, "canary rollback", "D8.17", _B, None, _B8_1),
    (77, "Stage7 antibody export", "D8.17", _N, None,
     "outbound is Stage 6 -> Stage 7 (Stage 7 exports Stage 6 trusted records), never "
     "Stage 8 -> Stage 7 (ADR-0071)"),
    (78, "distributed residual discovery", "D8.17", _N, None,
     "Stage 7 capsules carry no episodes, so there is no distributed residual to observe (D8.17)"),
    (79, "full ablation", "D8.19", _G, _ABL, ""),
    (80, "full Stage1–8 endurance", "D8.20", _G, _S + "labs.discovery_run:run_endurance", ""),
)

_AION_TITLES: tuple[str, ...] = (
    "predictive bottleneck beta sweep", "causal quotient equivalence",
    "event algebra canonicalization",
    "motif hash collision impact", "HDC binary representation", "HDC low-bit representation",
    "sparse associative memory", "prototype poisoning", "FSM synthesis", "probabilistic transducer",
    "CEGIS detector synthesis", "CEGIS convergence budget", "differentiable-to-symbolic compile",
    "teacher shortcut removal", "partial evaluation", "host specialization",
    "feature ISA interpreter",
    "feature ISA AOT compile", "beam program search", "enumerative program search",
    "evolutionary program search", "architecture genome mutation", "Pareto frontier stability",
    "resource-Lagrangian search", "hardware-in-loop feedback", "proxy-vs-real resource correlation",
    "anytime inference", "adaptive depth routing", "microexpert routing", "expert poisoning",
    "structural sparsity ordering", "multi-resolution temporal memory", "event horizon compression",
    "semantic conservation tests", "mechanism entropy", "epistemic compute allocation",
    "confidence vector calibration", "contradiction tensor splitting", "open-world unknown",
    "uncertainty decomposition", "minimal witness", "counterfactual witness",
    "self-compression loop",
    "architecture fossil reuse", "proof-carrying package", "SMT/FSM verification",
    "MIR backend equivalence", "eBPF placement optimization",
)
# The three AION rows a deliverable already needs are built under that deliverable (spec §2.1).
_AION_MEASURED: dict[int, str] = {
    114: _S + "forge.tournament:conservation_checks",
    119: _OBS,
    125: _S + "forge.package:verify_package",
}


def _aion_rows() -> tuple[CatalogueRow, ...]:
    rows = []
    for offset, title in enumerate(_AION_TITLES):
        number = 81 + offset
        runner = _AION_MEASURED.get(number)
        rows.append(CatalogueRow(
            experiment_id=f"S8X-{number:03d}", title=title, deliverable="AION",
            status=_G if runner else _N, runner=runner, reason="" if runner else _AION))
    return tuple(rows)


CATALOGUE: tuple[CatalogueRow, ...] = tuple(
    CatalogueRow(experiment_id=f"S8X-{n:03d}", title=t, deliverable=d, status=s, runner=r,
                 reason=why)
    for n, t, d, s, r, why in _ROWS
) + _aion_rows()


def resolve_runner(runner: str) -> object:
    """Import ``module`` and walk ``qualname``; raises on anything that does not resolve."""
    if not _RUNNER.fullmatch(runner):
        raise ValueError(f"runner {runner!r} is not 'pocketsec.stage8.<module>:<qualname>'")
    module_name, _, qualname = runner.partition(":")
    target: object = importlib.import_module(module_name)
    for part in qualname.split("."):
        target = getattr(target, part)
    return target


def architecture_titles(path: Path = ARCHITECTURE_FILE) -> dict[str, str]:
    """``S8X-NNN`` -> title, read from the architecture file's §52 and §111 lists."""
    titles: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = _ARCH_ROW.match(line.strip())
        if match:
            titles[f"S8X-{int(match.group(1)):03d}"] = match.group(2)
    return titles


def _row_problems(row: CatalogueRow) -> list[str]:
    problems = []
    if row.status in _MEASURED:
        if not row.runner:
            problems.append(f"{row.experiment_id}: MEASURED row names no runner")
        else:
            try:
                resolve_runner(row.runner)
            except (ImportError, AttributeError, ValueError) as exc:
                problems.append(
                    f"{row.experiment_id}: runner {row.runner} does not resolve ({exc})")
    elif not row.reason.strip():
        problems.append(f"{row.experiment_id}: {row.status.value} row carries no reason")
    elif row.runner is not None:
        problems.append(f"{row.experiment_id}: {row.status.value} row must not name a runner")
    if row.deliverable != "AION" and not re.fullmatch(r"D8\.\d{2}", row.deliverable):
        problems.append(
            f"{row.experiment_id}: deliverable {row.deliverable!r} is not D8.NN or AION")
    return problems


def catalogue_problems(rows: tuple[CatalogueRow, ...] = CATALOGUE,
                       architecture: Path = ARCHITECTURE_FILE) -> tuple[str, ...]:
    """``()`` is the only pass: 128 unique ids, resolvable runners, reasons, verbatim titles."""
    problems: list[str] = []
    ids = [row.experiment_id for row in rows]
    expected = [f"S8X-{n:03d}" for n in range(1, CATALOGUE_SIZE + 1)]
    problems.extend(f"missing {i}" for i in expected if i not in ids)
    problems.extend(f"duplicate {i}" for i in sorted({i for i in ids if ids.count(i) > 1}))
    problems.extend(f"unexpected {i}" for i in ids if i not in expected)
    try:
        titles = architecture_titles(architecture)
    except OSError as exc:
        titles = {}
        problems.append(f"architecture file unreadable: {exc}")
    for row in rows:
        problems.extend(_row_problems(row))
        if titles and titles.get(row.experiment_id) != row.title:
            problems.append(f"{row.experiment_id}: title {row.title!r} is not the architecture's "
                            f"{titles.get(row.experiment_id)!r}")
    return tuple(problems)
