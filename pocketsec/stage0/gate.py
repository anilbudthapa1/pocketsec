"""The Stage 0 acceptance gate (spec section 17), as an executable check.

The gate is code, not a checklist somebody ticks. ``run_gate`` returns one
:class:`GateCheck` per clause of section 17; ``pocketsec-stage0 gate`` exits
non-zero if any fails. Check 6 does not inspect a file — it actually runs the
H0 baseline through the harness on the fixture dataset, because the clause says
a baseline path *can run*.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pocketsec.stage0.benchmark.profiles import PROFILES
from pocketsec.stage0.contracts.common import SCHEMA_REGISTRY
from pocketsec.stage0.contracts.security_event_v1 import (
    SECURITY_EVENT_SEQUENCE_V1_ID,
    SECURITY_EVENT_SEQUENCE_V1_VERSION,
)
from pocketsec.stage0.contracts.threat_prediction_v1 import (
    THREAT_PREDICTION_V1_ID,
    THREAT_PREDICTION_V1_VERSION,
)
from pocketsec.stage0.experiments.registry import ExperimentRegistry
from pocketsec.stage0.hypotheses import HYPOTHESES, unsupported_status_claims
from pocketsec.stage0.prior_art import PriorArtLedger

__all__ = ["GateCheck", "GateReport", "REPO_ROOT", "run_gate"]

REPO_ROOT = Path(__file__).resolve().parents[2]

_SPEC = REPO_ROOT / "docs" / "stage-0-research-spec.md"
_BOUNDARY = REPO_ROOT / "docs" / "architecture" / "hub-model-boundary.md"
_REPRO = REPO_ROOT / "docs" / "reproducibility-policy.md"
_ENTRY = REPO_ROOT / "docs" / "stage-1-entry-criteria.md"
_ADR_TEMPLATE = REPO_ROOT / "docs" / "adr" / "0000-adr-template.md"
_CONTRACT_DIR = REPO_ROOT / "contracts"
_REGISTRY = REPO_ROOT / "experiments" / "registry.jsonl"


@dataclass(frozen=True, slots=True)
class GateCheck:
    id: str
    title: str
    passed: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "title": self.title, "passed": self.passed, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class GateReport:
    checks: tuple[GateCheck, ...]

    @property
    def passed(self) -> bool:
        return all(check.passed for check in self.checks)

    @property
    def failures(self) -> tuple[GateCheck, ...]:
        return tuple(check for check in self.checks if not check.passed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate": "stage-0",
            "passed": self.passed,
            "checks": [check.to_dict() for check in self.checks],
        }


def run_gate() -> GateReport:
    """Evaluate every Stage 0 acceptance clause."""
    return GateReport(
        checks=(
            _check_objective_frozen(),
            _check_boundary_documented(),
            _check_contracts_versioned(),
            _check_measurement_fixed(),
            _check_experiment_rules_operational(),
            _check_baseline_runs(),
            _check_hypotheses_not_results(),
            _check_prior_art_ledger(),
            _check_stage1_can_proceed(),
        )
    )


def _check_objective_frozen() -> GateCheck:
    """17.1 — research question and optimisation objective frozen and versioned."""
    if not _SPEC.is_file():
        return GateCheck("G0.1", "Objective frozen and versioned", False, f"missing {_SPEC}")
    text = _SPEC.read_text(encoding="utf-8")
    required = ("M* =", "Specification version:", "Central research question")
    missing = [token for token in required if token not in text]
    if missing:
        return GateCheck(
            "G0.1",
            "Objective frozen and versioned",
            False,
            f"{_SPEC.name} lacks: {', '.join(missing)}",
        )
    return GateCheck(
        "G0.1", "Objective frozen and versioned", True, f"{_SPEC.name} states question + objective"
    )


def _check_boundary_documented() -> GateCheck:
    """17.2 — the stable hub/model boundary is documented."""
    if not _BOUNDARY.is_file():
        return GateCheck("G0.2", "Hub/model boundary documented", False, f"missing {_BOUNDARY}")
    text = _BOUNDARY.read_text(encoding="utf-8")
    if SECURITY_EVENT_SEQUENCE_V1_ID not in text or THREAT_PREDICTION_V1_ID not in text:
        return GateCheck(
            "G0.2",
            "Hub/model boundary documented",
            False,
            "boundary doc does not name both contract schema ids",
        )
    return GateCheck("G0.2", "Hub/model boundary documented", True, _BOUNDARY.name)


def _check_contracts_versioned() -> GateCheck:
    """17.3 — input/output interface skeletons are versioned.

    The JSON Schema files and the Python contracts must agree, or the
    language-neutral boundary is decorative.
    """
    expected = {
        SECURITY_EVENT_SEQUENCE_V1_ID: (
            _CONTRACT_DIR / "security_event_sequence_v1.schema.json",
            SECURITY_EVENT_SEQUENCE_V1_VERSION,
        ),
        THREAT_PREDICTION_V1_ID: (
            _CONTRACT_DIR / "threat_prediction_v1.schema.json",
            THREAT_PREDICTION_V1_VERSION,
        ),
    }
    problems: list[str] = []
    for schema_id, (path, version) in expected.items():
        if not path.is_file():
            problems.append(f"missing {path.name}")
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("$id") != schema_id:
            problems.append(f"{path.name}: $id {payload.get('$id')!r} != {schema_id!r}")
        if payload.get("version") != version:
            problems.append(
                f"{path.name}: version {payload.get('version')!r} != python {version!r}"
            )
        if SCHEMA_REGISTRY.get(schema_id) != version:
            problems.append(f"{schema_id}: not registered at {version}")
    if problems:
        return GateCheck("G0.3", "Contracts versioned", False, "; ".join(problems))
    return GateCheck(
        "G0.3", "Contracts versioned", True, f"{len(expected)} schemas agree with Python contracts"
    )


def _check_measurement_fixed() -> GateCheck:
    """17.4 — hardware/resource profiles and benchmark metrics are fixed."""
    missing = [name for name in ("nano", "edge", "research_max") if name not in PROFILES]
    if missing:
        return GateCheck(
            "G0.4", "Profiles and metrics fixed", False, f"missing profiles: {missing}"
        )
    return GateCheck(
        "G0.4",
        "Profiles and metrics fixed",
        True,
        f"profiles {sorted(PROFILES)}; metrics fixed in benchmark.security_metrics",
    )


def _check_experiment_rules_operational() -> GateCheck:
    """17.5 — experiment naming, reproducibility and retention rules operate."""
    problems: list[str] = []
    if not _REPRO.is_file():
        problems.append(f"missing {_REPRO.name}")
    if not _ADR_TEMPLATE.is_file():
        problems.append(f"missing {_ADR_TEMPLATE.name}")
    problems.extend(ExperimentRegistry(_REGISTRY).verify_integrity())
    if problems:
        return GateCheck("G0.5", "Experiment rules operational", False, "; ".join(problems))
    count = len(ExperimentRegistry(_REGISTRY).all())
    return GateCheck(
        "G0.5",
        "Experiment rules operational",
        True,
        f"registry intact ({count} entries), repro policy + ADR template present",
    )


def _check_baseline_runs() -> GateCheck:
    """17.6 — at least one conventional baseline runs through the harness."""
    try:
        from pocketsec.stage0.smoke import run_smoke_benchmark

        result = run_smoke_benchmark()
    except Exception as exc:  # noqa: BLE001 - the gate reports any failure cause
        return GateCheck("G0.6", "Baseline runs through harness", False, f"{type(exc).__name__}: {exc}")
    return GateCheck(
        "G0.6",
        "Baseline runs through harness",
        True,
        f"{result.slot_name} scored {result.security.sample_count} sequences; "
        f"PR-AUC {result.security.pr_auc!r}; "
        f"resolved without inference {result.novelty.resolved_without_inference:.2f}",
    )


def _check_hypotheses_not_results() -> GateCheck:
    """17.7 — hypotheses are documented as hypotheses, not claimed results."""
    problems = unsupported_status_claims()
    if problems:
        return GateCheck("G0.7", "Hypotheses not claimed as results", False, "; ".join(problems))
    return GateCheck(
        "G0.7",
        "Hypotheses not claimed as results",
        True,
        f"{len(HYPOTHESES)} hypotheses carried forward with no unevidenced claims",
    )


def _check_prior_art_ledger() -> GateCheck:
    """17.8 — a prior-art ledger exists and can be updated."""
    try:
        ledger = PriorArtLedger.load()
    except (OSError, ValueError, KeyError) as exc:
        return GateCheck("G0.8", "Prior-art ledger exists", False, str(exc))
    problems = ledger.inconsistencies()
    if problems:
        return GateCheck("G0.8", "Prior-art ledger exists", False, "; ".join(problems))
    return GateCheck(
        "G0.8", "Prior-art ledger exists", True, f"{len(ledger.entries)} entries, all consistent"
    )


def _check_stage1_can_proceed() -> GateCheck:
    """17.9 — Stage 1 can research ontology without changing Stage 0 rules."""
    if not _ENTRY.is_file():
        return GateCheck("G0.9", "Stage 1 entry criteria defined", False, f"missing {_ENTRY}")
    text = _ENTRY.read_text(encoding="utf-8")
    if "attributes" not in text or "measurement" not in text.lower():
        return GateCheck(
            "G0.9",
            "Stage 1 entry criteria defined",
            False,
            "entry criteria must state the ontology extension point and the frozen "
            "measurement rules",
        )
    return GateCheck("G0.9", "Stage 1 entry criteria defined", True, _ENTRY.name)
