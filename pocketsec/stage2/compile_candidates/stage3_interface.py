"""D2.15 — the Stage 3 seam: DTL-F20 and the plain-data handoff.

Acceptance criterion 13 says stable candidates must be exportable to Stage 3
"without embedding DTL-specific assumptions into the PocketSec hub". This module
is where that is enforced rather than asserted: every nested member of a
``Stage3Handoff`` is a plain ``Mapping[str, Any]`` of JSON values, and
``to_dict()`` refuses to emit a payload whose keys name a Stage 2 class. Stage 3
reads JSON. It never imports a quantizer, a window, a lattice or a model object,
so a later Stage 2 redesign — and this stage has already been redesigned twice
(ADR-0009, ADR-0010) — cannot break Stage 3's compiler.

``EvidenceBoundPrediction`` is the other half of the seam: a prediction that
cannot be detached from the evidence it was made from. It carries a ``verdict``
from Stage 0's ``Verdict`` enum including ``UNKNOWN`` and ``UNIDENTIFIABLE``,
because abstention is an answer here, and it carries **no authority field** — no
action, no remediation, no privilege (ADR-0003). The constructor audits its own
field names against ``FORBIDDEN_AUTHORITY_FIELDS``, so adding such a field later
breaks construction rather than quietly shipping a response channel.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    EvidenceRef,
    digest_of_bytes,
    register_schema,
    require_identifier,
)
from pocketsec.stage0.contracts.threat_prediction_v1 import (
    FORBIDDEN_AUTHORITY_FIELDS,
    Verdict,
)
from pocketsec.stage2.compile_candidates.candidate import (
    CompileCandidateV1,
    forbidden_authority_keys,
    require_json_payload,
)
from pocketsec.stage2.compile_candidates.exporter import ExportReport
from pocketsec.stage2.core_ids import ExecutionPath
from pocketsec.stage2.encoder.ssir_encoder import ENCODER_VERSION
from pocketsec.stage2.uncertainty.abstention import UncertaintyEstimate

__all__ = [
    "FORBIDDEN_SEAM_TOKENS",
    "EvidenceBoundPrediction",
    "STAGE3_HANDOFF_V1_ID",
    "STAGE3_HANDOFF_V1_VERSION",
    "Stage3Handoff",
    "build_handoff",
    "export_evidence_bound_prediction",
    "seam_violations",
    "write_handoff",
]

STAGE3_HANDOFF_V1_ID = "pocketsec.stage3_handoff.v1"
STAGE3_HANDOFF_V1_VERSION = register_schema(STAGE3_HANDOFF_V1_ID, "1.0.0")

#: Class names Stage 3 must never see as a key. Compared against keys with
#: separators stripped, so ``behaviour_atom``, ``behaviourAtom`` and
#: ``BehaviourAtom`` are all caught. ``atom_id`` is *not* caught and should not
#: be: an integer id is plain data, a class name is a coupling.
FORBIDDEN_SEAM_TOKENS = frozenset(
    {
        "behaviouratom",
        "behaviourquantizer",
        "hashbucketquantizer",
        "transitionlattice",
        "latticetransition",
        "lineagewindow",
        "windowstore",
        "encodedtransition",
        "futurecone",
        "conebranch",
        "predictiveheads",
        "headweights",
        "dtlmodel",
        "dtlconvmodel",
        "tcnbaseline",
        "counterfactualprobe",
        "workledger",
        "tensor",
        "ndarray",
        "statedict",
    }
)


def seam_violations(payload: object, *, prefix: str = "handoff") -> tuple[str, ...]:
    """Return every key path whose name would leak a Stage 2 class across the seam."""
    found: list[str] = []
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            path = f"{prefix}.{key}"
            flattened = str(key).lower().replace("_", "").replace("-", "")
            if any(token in flattened for token in FORBIDDEN_SEAM_TOKENS):
                found.append(path)
            found.extend(seam_violations(value, prefix=path))
    elif isinstance(payload, (list, tuple)):
        for index, item in enumerate(payload):
            found.extend(seam_violations(item, prefix=f"{prefix}[{index}]"))
    return tuple(found)


@dataclass(frozen=True, slots=True)
class EvidenceBoundPrediction:
    """DTL-F20. A prediction that cannot be detached from the evidence behind it.

    ``score`` is a ranking quantity in [0, 1]; it grants nothing. A caller that
    wants an action must go through Stage 5's typed operators, which is why no
    field here names one.
    """

    score: float
    verdict: str
    uncertainty: UncertaintyEstimate
    evidence: tuple[EvidenceRef, ...]
    compute_path: ExecutionPath
    calibration_id: str | None
    candidate_id: str | None

    def __post_init__(self) -> None:
        offenders = [
            field.name
            for field in fields(self)
            if any(token in field.name.lower() for token in FORBIDDEN_AUTHORITY_FIELDS)
        ]
        if offenders:
            raise ContractError(
                f"EvidenceBoundPrediction declares response-authority fields {offenders}; "
                "a prediction carries no authority (ADR-0003)"
            )
        if not isinstance(self.score, float) or self.score != self.score:
            raise ContractError(
                f"EvidenceBoundPrediction.score must be a finite float, got {self.score!r}"
            )
        if not 0.0 <= self.score <= 1.0:
            raise ContractError(
                f"EvidenceBoundPrediction.score must be within [0, 1], got {self.score}"
            )
        if self.verdict not in {v.value for v in Verdict}:
            raise ContractError(
                f"EvidenceBoundPrediction.verdict must be a Stage 0 Verdict value, "
                f"got {self.verdict!r}"
            )
        if not isinstance(self.uncertainty, UncertaintyEstimate):
            raise ContractError(
                "EvidenceBoundPrediction.uncertainty must be an UncertaintyEstimate"
            )
        if not isinstance(self.compute_path, ExecutionPath):
            raise ContractError("EvidenceBoundPrediction.compute_path must be an ExecutionPath")
        if not isinstance(self.evidence, tuple) or not self.evidence:
            raise ContractError(
                "EvidenceBoundPrediction.evidence must be non-empty: a prediction with no "
                "evidence is exactly the thing this type exists to make unrepresentable"
            )
        for ref in self.evidence:
            if not isinstance(ref, EvidenceRef):
                raise ContractError(
                    f"EvidenceBoundPrediction.evidence entries must be EvidenceRef, "
                    f"got {type(ref).__name__}"
                )
        optional_ids = (
            ("calibration_id", self.calibration_id),
            ("candidate_id", self.candidate_id),
        )
        for name, value in optional_ids:
            if value is not None:
                require_identifier(value, f"EvidenceBoundPrediction.{name}")
        offending_sources = forbidden_authority_keys(
            dict(self.uncertainty.sources), prefix="uncertainty.sources"
        )
        if offending_sources:
            raise ContractError(
                f"EvidenceBoundPrediction.uncertainty.sources names authority fields "
                f"{list(offending_sources)}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "verdict": self.verdict,
            "uncertainty": self.uncertainty.to_dict(),
            "evidence": [ref.to_dict() for ref in self.evidence],
            "compute_path": self.compute_path.value,
            "calibration_id": self.calibration_id,
            "candidate_id": self.candidate_id,
        }


def export_evidence_bound_prediction(
    *,
    score: float,
    verdict: Verdict | str,
    uncertainty: UncertaintyEstimate,
    evidence: Sequence[EvidenceRef],
    compute_path: ExecutionPath,
    calibration_id: str | None = None,
    candidate_id: str | None = None,
) -> EvidenceBoundPrediction:
    """DTL-F20. Build a prediction bound to immutable Stage 1 evidence.

    ``calibration_id`` defaults to the estimate's own, which is ``None`` when the
    estimate was not calibrated. Stage 1 ships ``calibration_id=None`` honestly
    and so does this: a plausible-looking string here would be the exact lie the
    field exists to prevent.
    """
    resolved = calibration_id if calibration_id is not None else uncertainty.calibration_id
    verdict_value = verdict.value if isinstance(verdict, Verdict) else str(verdict)
    return EvidenceBoundPrediction(
        score=float(score),
        verdict=verdict_value,
        uncertainty=uncertainty,
        evidence=tuple(evidence),
        compute_path=compute_path,
        calibration_id=resolved,
        candidate_id=candidate_id,
    )


def _plain_rows(rows: Sequence[Mapping[str, Any]], *, field: str) -> tuple[Mapping[str, Any], ...]:
    """Normalise a tuple of plain-data rows, refusing classes and seam leaks."""
    normalised: list[Mapping[str, Any]] = []
    for index, row in enumerate(rows):
        where = f"{field}[{index}]"
        clean = require_json_payload(row, field=where)
        offenders = seam_violations(clean, prefix=where)
        if offenders:
            raise ContractError(
                f"{where} names Stage 2 classes {list(offenders)}; Stage 3 reads plain data"
            )
        normalised.append(clean)
    return tuple(normalised)


@dataclass(frozen=True, slots=True)
class Stage3Handoff:
    """Everything Stage 3 needs, and nothing DTL-specific."""

    handoff_id: str
    candidates: tuple[CompileCandidateV1, ...]
    atom_prototypes: tuple[Mapping[str, Any], ...]
    transition_statistics: tuple[Mapping[str, Any], ...]
    uncertainty_envelopes: tuple[Mapping[str, Any], ...]
    evidence_requirements: tuple[Mapping[str, Any], ...]
    encoder_version: str
    interface_version: str = STAGE3_HANDOFF_V1_VERSION

    def __post_init__(self) -> None:
        require_identifier(self.handoff_id, "Stage3Handoff.handoff_id")
        require_identifier(self.encoder_version, "Stage3Handoff.encoder_version")
        for candidate in self.candidates:
            if not isinstance(candidate, CompileCandidateV1):
                raise ContractError(
                    f"Stage3Handoff.candidates entries must be CompileCandidateV1, "
                    f"got {type(candidate).__name__}"
                )
            if candidate.boundary.encoder_version != self.encoder_version:
                raise ContractError(
                    f"candidate {candidate.candidate_id} was built under encoder "
                    f"{candidate.boundary.encoder_version!r}, handoff declares "
                    f"{self.encoder_version!r}; feature indices do not survive an encoder change"
                )
        for name in (
            "atom_prototypes",
            "transition_statistics",
            "uncertainty_envelopes",
            "evidence_requirements",
        ):
            object.__setattr__(
                self, name, _plain_rows(getattr(self, name), field=f"Stage3Handoff.{name}")
            )

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "interface_version": self.interface_version,
            "schema_id": STAGE3_HANDOFF_V1_ID,
            "handoff_id": self.handoff_id,
            "encoder_version": self.encoder_version,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "atom_prototypes": [dict(row) for row in self.atom_prototypes],
            "transition_statistics": [dict(row) for row in self.transition_statistics],
            "uncertainty_envelopes": [dict(row) for row in self.uncertainty_envelopes],
            "evidence_requirements": [dict(row) for row in self.evidence_requirements],
        }
        offenders = seam_violations(payload)
        if offenders:
            raise ContractError(
                f"Stage3Handoff.to_dict would leak Stage 2 class names {list(offenders)}"
            )
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Stage3Handoff:
        try:
            return cls(
                handoff_id=str(payload["handoff_id"]),
                candidates=tuple(
                    CompileCandidateV1.from_dict(row) for row in payload["candidates"]
                ),
                atom_prototypes=tuple(payload["atom_prototypes"]),
                transition_statistics=tuple(payload["transition_statistics"]),
                uncertainty_envelopes=tuple(payload["uncertainty_envelopes"]),
                evidence_requirements=tuple(payload["evidence_requirements"]),
                encoder_version=str(payload["encoder_version"]),
                interface_version=str(payload.get("interface_version", STAGE3_HANDOFF_V1_VERSION)),
            )
        except KeyError as exc:
            raise ContractError(f"Stage3Handoff missing field {exc.args[0]!r}") from exc


def build_handoff(report: ExportReport, *, handoff_id: str) -> Stage3Handoff:
    """Project an ``ExportReport`` into the plain-data shape Stage 3 consumes.

    Only *exported* candidates reach the handoff; a refused candidate is recorded
    in the report and never crosses the seam. The four projected tuples are
    derived from the candidates themselves rather than re-read from the lattice,
    so the handoff cannot describe an artefact it does not carry.
    """
    encoder_versions = {candidate.boundary.encoder_version for candidate in report.candidates}
    if len(encoder_versions) > 1:
        raise ContractError(
            f"cannot build one handoff across encoder versions {sorted(encoder_versions)}"
        )
    encoder_version = encoder_versions.pop() if encoder_versions else ENCODER_VERSION
    prototypes: list[Mapping[str, Any]] = []
    statistics: list[Mapping[str, Any]] = []
    envelopes: list[Mapping[str, Any]] = []
    requirements: list[Mapping[str, Any]] = []
    for candidate in report.candidates:
        payload = dict(candidate.payload)
        source = payload.get("atom")
        if isinstance(source, Mapping) and "prototype" in source:
            prototypes.append(
                {
                    "candidate_id": candidate.candidate_id,
                    "prototype": list(source["prototype"]),
                    "epochs": sorted(candidate.boundary.epochs),
                }
            )
        edge = payload.get("transition")
        if isinstance(edge, Mapping):
            statistics.append({"candidate_id": candidate.candidate_id, **dict(edge)})
        envelopes.append(
            {
                "candidate_id": candidate.candidate_id,
                "max_uncertainty": candidate.boundary.max_uncertainty,
                "unseen_input_behaviour": candidate.boundary.unseen_input_behaviour,
            }
        )
        requirements.append(
            {
                "candidate_id": candidate.candidate_id,
                "min_evidence_count": candidate.boundary.min_evidence_count,
                "evidence": [ref.to_dict() for ref in candidate.evidence_lineage],
            }
        )
    return Stage3Handoff(
        handoff_id=handoff_id,
        candidates=report.candidates,
        atom_prototypes=tuple(prototypes),
        transition_statistics=tuple(statistics),
        uncertainty_envelopes=tuple(envelopes),
        evidence_requirements=tuple(requirements),
        encoder_version=encoder_version,
    )


def write_handoff(handoff: Stage3Handoff, path: Path) -> str:
    """Write the handoff as canonical JSON and return its ``sha256:`` digest.

    Canonical (sorted keys, fixed separators, trailing newline) so the digest is
    reproducible: a Stage 3 run can prove the bytes it compiled are the bytes
    Stage 2 wrote, which is the same lineage guarantee ``EvidenceRef`` gives raw
    evidence.
    """
    payload = (
        json.dumps(handoff.to_dict(), sort_keys=True, allow_nan=False, indent=2).encode("utf-8")
        + b"\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return digest_of_bytes(payload)
