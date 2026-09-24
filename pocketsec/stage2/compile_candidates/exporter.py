"""D2.13 — DTL-F17: propose and export compile candidates, refusing loudly.

This module is the gate between "Stage 2 noticed something" and "Stage 3 is
allowed to compile it". Its whole design principle is that a rejection is a
*recorded outcome*, never a silent drop: ``ExportReport.refused`` carries a
reason string per candidate, so a run that exports nothing still explains why.

Three refusals are non-negotiable, and each one corresponds to a way this
project has previously fooled itself:

* **UNSTABLE** — frequency is not corroboration (architecture spec §37). A
  pattern seen often inside a single epoch is one world's opinion.
* **EMPTY_BOUNDARY** — an artefact with no validity boundary is an unbounded
  claim, and Stage 3's melt-back safety story depends on the boundary existing.
* **UNMEASURED_COST** — ADR-0010's lesson. The router reported savings it never
  delivered; a candidate whose µs/event is ``None`` would let that happen again
  one stage further downstream. Note this refusal applies even to the
  zero-parameter Φ-oracle: the schema tolerates an untimed deterministic scorer,
  the exporter does not.

What this module refuses to do: it never truncates silently. Overflow past
``max_candidates`` is refused with a reason, because a cache or queue that drops
work invisibly is the exact failure the bounded-state invariant exists to stop.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef
from pocketsec.stage2.compile_candidates.candidate import (
    CandidateKind,
    CandidateStability,
    CompileCandidateV1,
    MeasuredCost,
    ValidityBoundary,
)
from pocketsec.stage2.compile_candidates.phi_oracle_candidate import DeterministicScorerSpec
from pocketsec.stage2.encoder.ssir_encoder import ENCODER_VERSION
from pocketsec.stage1.state.security_state import DIMENSIONS

__all__ = [
    "DEFAULT_MAX_CANDIDATES",
    "ExportReport",
    "REFUSAL_DUPLICATE_ID",
    "REFUSAL_EMPTY_BOUNDARY",
    "REFUSAL_OVERFLOW",
    "REFUSAL_UNMEASURED_COST",
    "REFUSAL_UNSTABLE",
    "export_candidates",
    "propose_compile_candidate",
]

DEFAULT_MAX_CANDIDATES = 256

REFUSAL_UNSTABLE = "UNSTABLE"
REFUSAL_EMPTY_BOUNDARY = "EMPTY_BOUNDARY"
REFUSAL_UNMEASURED_COST = "UNMEASURED_COST"
REFUSAL_DUPLICATE_ID = "DUPLICATE_ID"
REFUSAL_OVERFLOW = "EXCEEDS_MAX_CANDIDATES"


@dataclass(frozen=True, slots=True)
class ExportReport:
    """What was exported, what was refused and why, and how many bytes it cost."""

    candidates: tuple[CompileCandidateV1, ...]
    refused: tuple[tuple[str, str], ...]
    total_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "refused": [[candidate_id, reason] for candidate_id, reason in self.refused],
            "exported": len(self.candidates),
            "refused_count": len(self.refused),
            "total_bytes": self.total_bytes,
        }


def _epochs_of(counts: Mapping[int, int] | None) -> frozenset[int]:
    if not counts:
        return frozenset()
    return frozenset(int(epoch) for epoch in counts)


def _boundary(
    *,
    epochs: frozenset[int],
    max_uncertainty: float,
    min_evidence_count: int,
) -> ValidityBoundary:
    return ValidityBoundary(
        epochs=epochs,
        encoder_version=ENCODER_VERSION,
        state_dimensions=frozenset(DIMENSIONS),
        max_uncertainty=max_uncertainty,
        min_evidence_count=min_evidence_count,
    )


def _clamp_unit(value: float) -> float:
    """Squeeze an uncertainty into [0, 1], refusing what cannot be squeezed.

    `max(0.0, nan)` returns 0.0 in CPython, so clamping alone would turn a NaN
    uncertainty into the *most confident* value a candidate can carry — on a
    validity boundary Stage 3 reads (S2-AUTH-03). `cache/utility.py` already
    guards its own clamp this way.
    """
    numeric = float(value)
    if not math.isfinite(numeric):
        raise ContractError(
            f"uncertainty must be finite, got {value!r}; clamping it would record "
            "an undefined bound as the tightest one"
        )
    return min(1.0, max(0.0, numeric))


def propose_compile_candidate(
    *,
    atom: Any | None = None,
    transition: Any | None = None,
    scorer: DeterministicScorerSpec | None = None,
    cost: MeasuredCost,
    experiment_id: str,
    evidence: Sequence[EvidenceRef],
    stability: CandidateStability,
    min_evidence_count: int = 1,
    epochs: Sequence[int] = (0,),
) -> CompileCandidateV1:
    """DTL-F17. Turn one Stage 2 artefact into a candidate, or raise.

    Exactly one of ``atom`` / ``transition`` / ``scorer`` must be supplied: a
    candidate describes one compilable thing, and a payload mixing an atom
    prototype with a lattice edge would give Stage 3 two artefacts under one
    validity boundary.

    ``atom`` and ``transition`` are typed ``Any`` deliberately. They are consumed
    through their ``to_dict()`` and their epoch/uncertainty fields only, so this
    module holds no import from ``lattice`` and the seam stays plain data — the
    same reason Stage 3 gets JSON rather than classes.

    ``epochs`` applies to a scorer, which has no epoch counts of its own; an atom
    or an edge carries its observed epochs and those are used instead. Defaulting
    to the baseline epoch keeps the validity claim bounded — "valid in every
    epoch" is not a claim this function is allowed to make on a caller's behalf.
    """
    sources = (("atom", atom), ("transition", transition), ("scorer", scorer))
    supplied = [name for name, value in sources if value is not None]
    if len(supplied) != 1:
        raise ContractError(
            f"propose_compile_candidate needs exactly one of atom/transition/scorer, got {supplied}"
        )
    if scorer is not None:
        kind = CandidateKind.DETERMINISTIC_SCORER
        payload: dict[str, Any] = {"scorer": scorer.to_dict()}
        boundary = _boundary(
            epochs=frozenset(int(epoch) for epoch in epochs),
            max_uncertainty=1.0,
            min_evidence_count=min_evidence_count,
        )
        candidate_id = f"pocketsec.candidate.scorer.{scorer.scorer_id}"
    elif transition is not None:
        kind = CandidateKind.TRANSITION_TABLE
        payload = {"transition": transition.to_dict()}
        boundary = _boundary(
            epochs=_epochs_of(getattr(transition, "epoch_counts", None)),
            max_uncertainty=_clamp_unit(getattr(transition, "uncertainty_mean", 1.0)),
            min_evidence_count=min_evidence_count,
        )
        candidate_id = f"pocketsec.candidate.edge.{transition.source}-{transition.target}"
    else:
        kind = CandidateKind.NEURAL_REGION
        payload = {"atom": atom.to_dict()}
        envelope = getattr(atom, "uncertainty_envelope", (0.0, 1.0))
        boundary = _boundary(
            epochs=_epochs_of(getattr(atom, "epoch_counts", None)),
            max_uncertainty=_clamp_unit(envelope[1]),
            min_evidence_count=min_evidence_count,
        )
        candidate_id = f"pocketsec.candidate.atom.{atom.atom_id}"
    return CompileCandidateV1(
        candidate_id=candidate_id,
        kind=kind,
        boundary=boundary,
        evidence_lineage=tuple(evidence),
        cost=cost,
        experiment_id=experiment_id,
        payload=payload,
        stability=stability,
    )


def _refusal_for(candidate: CompileCandidateV1) -> str:
    """The single reason this candidate may not be exported, or ``""``."""
    if not candidate.stability.stable:
        return f"{REFUSAL_UNSTABLE}: {candidate.stability.instability_reason()}"
    if candidate.boundary.is_empty:
        return (
            f"{REFUSAL_EMPTY_BOUNDARY}: epochs={sorted(candidate.boundary.epochs)} "
            f"dimensions={len(candidate.boundary.state_dimensions)}"
        )
    if not candidate.cost.measured:
        return (
            f"{REFUSAL_UNMEASURED_COST}: microseconds_per_event is None "
            f"(measured_by={candidate.cost.measured_by})"
        )
    return ""


def export_candidates(
    candidates: Sequence[CompileCandidateV1],
    path: Path,
    *,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
) -> ExportReport:
    """Write the exportable candidates as canonical JSON and report every refusal.

    The written file is sorted-key JSON so two runs that export the same
    candidates produce byte-identical output, which is what makes the Stage 3
    handoff digest reproducible rather than merely present.
    """
    if max_candidates < 1:
        raise ContractError(f"max_candidates must be >= 1, got {max_candidates}")
    accepted: list[CompileCandidateV1] = []
    refused: list[tuple[str, str]] = []
    seen: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, CompileCandidateV1):
            raise ContractError(
                f"export_candidates takes CompileCandidateV1, got {type(candidate).__name__}"
            )
        if candidate.candidate_id in seen:
            refused.append((candidate.candidate_id, REFUSAL_DUPLICATE_ID))
            continue
        seen.add(candidate.candidate_id)
        reason = _refusal_for(candidate)
        if reason:
            refused.append((candidate.candidate_id, reason))
            continue
        if len(accepted) >= max_candidates:
            refused.append(
                (candidate.candidate_id, f"{REFUSAL_OVERFLOW}: cap {max_candidates} reached")
            )
            continue
        accepted.append(candidate)
    body = {
        "schema_id": "pocketsec.compile_candidate.v1",
        "candidates": [candidate.to_dict() for candidate in accepted],
    }
    payload = json.dumps(body, sort_keys=True, allow_nan=False, indent=2).encode("utf-8") + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return ExportReport(
        candidates=tuple(accepted), refused=tuple(refused), total_bytes=len(payload)
    )
