"""D2.13/D2.15 — ``CompileCandidateV1``: what Stage 2 is allowed to hand Stage 3.

Stage 3 crystallises what Stage 2 exports, so this schema is the narrowest and
most load-bearing seam in the project. It exists to make one sentence true by
construction rather than by review:

    **A candidate with no recorded measurement is rejectable by construction.**

Everything else follows from that. A candidate carries its validity boundary (so
Stage 3 knows when the compiled artefact stops being valid), its evidence
lineage (so a compiled rule can still be traced to the bytes that justified it),
its measured cost (so "cheaper" is a number, not an adjective) and the
experiment id that produced the measurement (so the number can be found in the
append-only registry).

What this module refuses to do:

* It refuses a candidate whose ``evidence_lineage`` is empty. An unattributable
  rule is not compilable — Stage 3 would have nothing to melt back to.
* It refuses an ``experiment_id`` that does not parse. A measurement with no
  provenance join key is indistinguishable from a guess.
* It refuses ``microseconds_per_event=None`` for anything but a zero-parameter
  deterministic scorer, whose honest cost may legitimately round to 0.0 µs but
  must still have been *measured*. ``None`` means UNMEASURED and never "fast".
* It refuses a payload key that names response authority (ADR-0003). A compiled
  artefact that could carry ``{"action": ...}`` would be a natural-language-free
  but still real path from model output to privilege.
* It refuses a payload that is not JSON — including NaN and Infinity, which
  ``json`` will happily emit and no other reader will accept. A candidate that
  cannot be written out is not a candidate.

The payload is normalised through JSON at construction, which is both the
serialisability check and what makes ``from_dict(to_dict(c)) == c`` exact: a
tuple in, a list out, on both sides of the seam.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    EvidenceRef,
    register_schema,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS
from pocketsec.stage0.experiments.ids import parse_experiment_id
from pocketsec.stage1.state.security_state import DIMENSIONS

__all__ = [
    "COMPILE_CANDIDATE_V1_ID",
    "COMPILE_CANDIDATE_V1_VERSION",
    "CandidateKind",
    "CandidateStability",
    "CompileCandidateV1",
    "MIN_STABILITY_OBSERVATIONS",
    "MeasuredCost",
    "UNSEEN_INPUT_ABSTAIN",
    "ValidityBoundary",
    "forbidden_authority_keys",
    "require_json_payload",
]

COMPILE_CANDIDATE_V1_ID = "pocketsec.compile_candidate.v1"
COMPILE_CANDIDATE_V1_VERSION = register_schema(COMPILE_CANDIDATE_V1_ID, "1.0.0")

#: The only accepted answer to "what does the compiled artefact do off its
#: validity boundary". "GUESS" is not a policy, it is a silent extrapolation,
#: and UNKNOWN is a valid PocketSec output (ADR-0003, MEMORY.md invariants).
UNSEEN_INPUT_ABSTAIN = "ABSTAIN"

#: Minimum observations before ``CandidateStability.stable`` can be true. Eight
#: matches the lattice's own ``min_evidence`` for a predictive-equivalence
#: verdict (spec §D2.7), so a candidate cannot be "stable" on less evidence than
#: it would take to merge two atoms.
MIN_STABILITY_OBSERVATIONS = 8


class CandidateKind(StrEnum):
    """What kind of thing Stage 3 is being asked to compile.

    ``DETERMINISTIC_SCORER`` is deliberately first and is not a special case of a
    neural region: the measured Φ-oracle reaches 0.7484 PR-AUC with **zero**
    parameters (MEMORY.md), and per integration plan §6.3 it is Stage 3's first
    crystallisation target. A format that could only carry learned weights would
    refute the compilation path before it began.
    """

    DETERMINISTIC_SCORER = "DETERMINISTIC_SCORER"
    TRANSITION_TABLE = "TRANSITION_TABLE"
    NEURAL_REGION = "NEURAL_REGION"


def forbidden_authority_keys(payload: object, *, prefix: str = "payload") -> tuple[str, ...]:
    """Return every key path whose name would smuggle response authority.

    Recursive because a nested ``{"meta": {"remediation": ...}}`` is exactly as
    dangerous as a top-level one, and a reviewer scanning the top level would
    miss it. Matching is substring-on-lowercase, so ``recommended_action`` is
    caught as well as ``action``.
    """
    found: list[str] = []
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            path = f"{prefix}.{key}"
            lowered = str(key).lower()
            if any(token in lowered for token in FORBIDDEN_AUTHORITY_FIELDS):
                found.append(path)
            found.extend(forbidden_authority_keys(value, prefix=path))
    elif isinstance(payload, (list, tuple)):
        for index, item in enumerate(payload):
            found.extend(forbidden_authority_keys(item, prefix=f"{prefix}[{index}]"))
    return tuple(found)


def require_json_payload(payload: Mapping[str, Any], *, field: str) -> Mapping[str, Any]:
    """Normalise a payload through JSON, or raise ``ContractError``.

    ``allow_nan=False`` is the point: ``json.dumps`` emits bare ``NaN`` by
    default, which every other JSON reader rejects, so a candidate carrying a
    NaN probability would serialise here and fail at the seam. Normalising (not
    merely validating) is what keeps ``from_dict(to_dict(c)) == c`` exact.
    """
    if not isinstance(payload, Mapping):
        raise ContractError(f"{field} must be a mapping, got {type(payload).__name__}")
    for key in payload:
        if not isinstance(key, str) or not key:
            raise ContractError(f"{field} keys must be non-empty strings, got {key!r}")
    try:
        encoded = json.dumps(dict(payload), allow_nan=False, sort_keys=True)
    except (TypeError, ValueError) as exc:
        raise ContractError(f"{field} must hold JSON data only: {exc}") from exc
    return MappingProxyType(json.loads(encoded))


@dataclass(frozen=True, slots=True)
class ValidityBoundary:
    """When the compiled artefact stops being allowed to answer.

    Stage 3's whole safety story is that a Knowledge Cell is *bounded* and melts
    back when it leaves its boundary. An empty boundary is therefore not a
    permissive boundary — it contains nothing, and the exporter refuses it.
    """

    epochs: frozenset[int]
    encoder_version: str
    state_dimensions: frozenset[str]
    max_uncertainty: float
    min_evidence_count: int
    unseen_input_behaviour: str = UNSEEN_INPUT_ABSTAIN

    def __post_init__(self) -> None:
        if not isinstance(self.epochs, frozenset) or any(
            not isinstance(e, int) or isinstance(e, bool) or e < 0 for e in self.epochs
        ):
            raise ContractError("ValidityBoundary.epochs must be a frozenset of epoch ids >= 0")
        require_identifier(self.encoder_version, "ValidityBoundary.encoder_version")
        unknown = set(self.state_dimensions) - set(DIMENSIONS)
        if not isinstance(self.state_dimensions, frozenset) or unknown:
            raise ContractError(
                f"ValidityBoundary.state_dimensions must be a subset of DIMENSIONS, "
                f"unknown: {sorted(unknown)}"
            )
        if not isinstance(self.max_uncertainty, float) or not 0.0 <= self.max_uncertainty <= 1.0:
            raise ContractError(
                f"ValidityBoundary.max_uncertainty must be a float in [0, 1], "
                f"got {self.max_uncertainty!r}"
            )
        require_non_negative_int(self.min_evidence_count, "ValidityBoundary.min_evidence_count")
        if self.min_evidence_count < 1:
            raise ContractError(
                "ValidityBoundary.min_evidence_count must be >= 1; a candidate that "
                "requires no evidence is not evidence-bound"
            )
        if self.unseen_input_behaviour != UNSEEN_INPUT_ABSTAIN:
            raise ContractError(
                f"ValidityBoundary.unseen_input_behaviour must be "
                f"{UNSEEN_INPUT_ABSTAIN!r}, never {self.unseen_input_behaviour!r}: "
                "guessing off the boundary is what a validity boundary exists to prevent"
            )

    @property
    def is_empty(self) -> bool:
        """A boundary with no epochs or no dimensions can never contain anything."""
        return not self.epochs or not self.state_dimensions

    def contains(self, *, epoch_id: int, encoder_version: str, uncertainty: float) -> bool:
        """Is this artefact still allowed to answer, here, now?

        A foreign ``encoder_version`` is a hard no: the compiled artefact reads
        feature slots by index, and Stage 1's field widths are still provisional
        (MEMORY.md), so the same index under a different encoder is a different
        question.
        """
        if epoch_id not in self.epochs:
            return False
        if encoder_version != self.encoder_version:
            return False
        return uncertainty <= self.max_uncertainty

    def to_dict(self) -> dict[str, Any]:
        return {
            "epochs": sorted(self.epochs),
            "encoder_version": self.encoder_version,
            "state_dimensions": sorted(self.state_dimensions),
            "max_uncertainty": self.max_uncertainty,
            "min_evidence_count": self.min_evidence_count,
            "unseen_input_behaviour": self.unseen_input_behaviour,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ValidityBoundary:
        try:
            return cls(
                epochs=frozenset(int(e) for e in payload["epochs"]),
                encoder_version=str(payload["encoder_version"]),
                state_dimensions=frozenset(str(d) for d in payload["state_dimensions"]),
                max_uncertainty=float(payload["max_uncertainty"]),
                min_evidence_count=int(payload["min_evidence_count"]),
                unseen_input_behaviour=str(payload["unseen_input_behaviour"]),
            )
        except KeyError as exc:
            raise ContractError(f"ValidityBoundary missing field {exc.args[0]!r}") from exc


@dataclass(frozen=True, slots=True)
class MeasuredCost:
    """What the artefact costs, and who measured it.

    ``measured_by`` is required because the project's honesty contract turns on
    one distinction: a number someone produced by running code, versus a number
    that looks plausible. A cost with no producing ``module:function`` is
    UNMEASURED, and this type will not hold it.
    """

    microseconds_per_event: float | None
    parameters: int
    bytes_on_disk: int
    peak_rss_bytes: int | None
    measured_by: str

    def __post_init__(self) -> None:
        if not isinstance(self.measured_by, str) or not self.measured_by.strip():
            raise ContractError(
                "MeasuredCost.measured_by must name the 'module:function' that produced "
                "the number; a cost with no producer is UNMEASURED, not zero"
            )
        producer = self.measured_by.split(":")
        if len(producer) != 2 or not all(part.strip() for part in producer):
            raise ContractError(
                f"MeasuredCost.measured_by must look like 'module:function', "
                f"got {self.measured_by!r}"
            )
        if self.microseconds_per_event is not None:
            # `math.isfinite`, not `x != x`: the NaN test alone accepted
            # `float("inf")`, `measured` then returned True and the exporter's
            # UNMEASURED_COST refusal never fired, so a candidate could travel to
            # Stage 3 claiming an infinite per-event cost as a measured one
            # (S2-10). The error message already said "finite".
            if (
                not isinstance(self.microseconds_per_event, float)
                or not math.isfinite(self.microseconds_per_event)
                or self.microseconds_per_event < 0.0
            ):
                raise ContractError(
                    f"MeasuredCost.microseconds_per_event must be None (UNMEASURED) or a "
                    f"finite float >= 0, got {self.microseconds_per_event!r}"
                )
        require_non_negative_int(self.parameters, "MeasuredCost.parameters")
        require_non_negative_int(self.bytes_on_disk, "MeasuredCost.bytes_on_disk")
        if self.peak_rss_bytes is not None:
            require_non_negative_int(self.peak_rss_bytes, "MeasuredCost.peak_rss_bytes")

    @property
    def measured(self) -> bool:
        """``False`` means UNMEASURED. It never means free."""
        return self.microseconds_per_event is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "microseconds_per_event": self.microseconds_per_event,
            "parameters": self.parameters,
            "bytes_on_disk": self.bytes_on_disk,
            "peak_rss_bytes": self.peak_rss_bytes,
            "measured_by": self.measured_by,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> MeasuredCost:
        try:
            micros = payload["microseconds_per_event"]
            rss = payload["peak_rss_bytes"]
            return cls(
                microseconds_per_event=None if micros is None else float(micros),
                parameters=int(payload["parameters"]),
                bytes_on_disk=int(payload["bytes_on_disk"]),
                peak_rss_bytes=None if rss is None else int(rss),
                measured_by=str(payload["measured_by"]),
            )
        except KeyError as exc:
            raise ContractError(f"MeasuredCost missing field {exc.args[0]!r}") from exc


@dataclass(frozen=True, slots=True)
class CandidateStability:
    """Evidence that the thing being compiled is the same thing twice.

    Frequency alone is explicitly insufficient (architecture spec §37): a
    pattern seen a thousand times inside one epoch has been corroborated by one
    world, not two. Hence ``distinct_epochs >= 2`` and zero drift invalidations.
    """

    observations: int
    distinct_epochs: int
    reruns_agreeing: int
    reruns_total: int
    drift_invalidations: int

    def __post_init__(self) -> None:
        for field in (
            "observations",
            "distinct_epochs",
            "reruns_agreeing",
            "reruns_total",
            "drift_invalidations",
        ):
            require_non_negative_int(getattr(self, field), f"CandidateStability.{field}")
        if self.reruns_agreeing > self.reruns_total:
            raise ContractError(
                f"CandidateStability.reruns_agreeing ({self.reruns_agreeing}) cannot exceed "
                f"reruns_total ({self.reruns_total})"
            )

    @property
    def stable(self) -> bool:
        return (
            self.observations >= MIN_STABILITY_OBSERVATIONS
            and self.distinct_epochs >= 2
            and self.reruns_total >= 1
            and self.reruns_agreeing == self.reruns_total
            and self.drift_invalidations == 0
        )

    def instability_reason(self) -> str:
        """Why ``stable`` is false, for the exporter's refusal string."""
        if self.observations < MIN_STABILITY_OBSERVATIONS:
            return f"observations {self.observations} < {MIN_STABILITY_OBSERVATIONS}"
        if self.distinct_epochs < 2:
            return f"distinct_epochs {self.distinct_epochs} < 2 (frequency is not corroboration)"
        if self.reruns_total < 1:
            return "no rerun recorded"
        if self.reruns_agreeing != self.reruns_total:
            return f"reruns disagree {self.reruns_agreeing}/{self.reruns_total}"
        if self.drift_invalidations:
            return f"drift invalidations {self.drift_invalidations}"
        return ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "observations": self.observations,
            "distinct_epochs": self.distinct_epochs,
            "reruns_agreeing": self.reruns_agreeing,
            "reruns_total": self.reruns_total,
            "drift_invalidations": self.drift_invalidations,
            "stable": self.stable,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> CandidateStability:
        try:
            return cls(
                observations=int(payload["observations"]),
                distinct_epochs=int(payload["distinct_epochs"]),
                reruns_agreeing=int(payload["reruns_agreeing"]),
                reruns_total=int(payload["reruns_total"]),
                drift_invalidations=int(payload["drift_invalidations"]),
            )
        except KeyError as exc:
            raise ContractError(f"CandidateStability missing field {exc.args[0]!r}") from exc


@dataclass(frozen=True, slots=True)
class CompileCandidateV1:
    """One thing Stage 2 proposes that Stage 3 compile into a Knowledge Cell."""

    candidate_id: str
    kind: CandidateKind
    boundary: ValidityBoundary
    evidence_lineage: tuple[EvidenceRef, ...]
    cost: MeasuredCost
    experiment_id: str
    payload: Mapping[str, Any]
    stability: CandidateStability
    schema_version: str = COMPILE_CANDIDATE_V1_VERSION

    def __post_init__(self) -> None:
        require_identifier(self.candidate_id, "CompileCandidateV1.candidate_id")
        if not isinstance(self.kind, CandidateKind):
            raise ContractError(
                f"CompileCandidateV1.kind must be a CandidateKind, got {self.kind!r}"
            )
        if not isinstance(self.boundary, ValidityBoundary):
            raise ContractError("CompileCandidateV1.boundary must be a ValidityBoundary")
        if not isinstance(self.cost, MeasuredCost):
            raise ContractError("CompileCandidateV1.cost must be a MeasuredCost")
        if not isinstance(self.stability, CandidateStability):
            raise ContractError("CompileCandidateV1.stability must be a CandidateStability")
        self._require_evidence()
        self._require_experiment()
        self._require_measured_cost()
        object.__setattr__(
            self, "payload", require_json_payload(self.payload, field="CompileCandidateV1.payload")
        )
        offenders = forbidden_authority_keys(self.payload)
        if offenders:
            raise ContractError(
                f"CompileCandidateV1.payload carries response-authority field names "
                f"{list(offenders)}; a compiled artefact may not name an action (ADR-0003)"
            )

    def _require_evidence(self) -> None:
        if not isinstance(self.evidence_lineage, tuple) or not self.evidence_lineage:
            raise ContractError(
                "CompileCandidateV1.evidence_lineage must be a non-empty tuple: an "
                "unattributable rule cannot be melted back to the bytes that justified it"
            )
        for ref in self.evidence_lineage:
            if not isinstance(ref, EvidenceRef):
                raise ContractError(
                    f"CompileCandidateV1.evidence_lineage entries must be EvidenceRef, "
                    f"got {type(ref).__name__}"
                )

    def _require_experiment(self) -> None:
        try:
            parse_experiment_id(self.experiment_id)
        except (TypeError, ValueError) as exc:
            raise ContractError(
                f"CompileCandidateV1.experiment_id must parse via stage0.experiments.ids: {exc}"
            ) from exc

    def _require_measured_cost(self) -> None:
        if self.cost.measured:
            return
        if self.kind is not CandidateKind.DETERMINISTIC_SCORER:
            raise ContractError(
                f"CompileCandidateV1 of kind {self.kind.value} has "
                "microseconds_per_event=None (UNMEASURED); only a zero-parameter "
                "DETERMINISTIC_SCORER may be proposed before it has been timed, and the "
                "exporter refuses even that"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "candidate_id": self.candidate_id,
            "kind": self.kind.value,
            "boundary": self.boundary.to_dict(),
            "evidence_lineage": [ref.to_dict() for ref in self.evidence_lineage],
            "cost": self.cost.to_dict(),
            "experiment_id": self.experiment_id,
            "payload": dict(self.payload),
            "stability": self.stability.to_dict(),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> CompileCandidateV1:
        try:
            return cls(
                candidate_id=str(payload["candidate_id"]),
                kind=CandidateKind(str(payload["kind"])),
                boundary=ValidityBoundary.from_dict(payload["boundary"]),
                evidence_lineage=tuple(
                    EvidenceRef.from_dict(ref) for ref in payload["evidence_lineage"]
                ),
                cost=MeasuredCost.from_dict(payload["cost"]),
                experiment_id=str(payload["experiment_id"]),
                payload=payload["payload"],
                stability=CandidateStability.from_dict(payload["stability"]),
                schema_version=str(payload.get("schema_version", COMPILE_CANDIDATE_V1_VERSION)),
            )
        except KeyError as exc:
            raise ContractError(f"CompileCandidateV1 missing field {exc.args[0]!r}") from exc
        except ValueError as exc:
            raise ContractError(f"CompileCandidateV1 could not be rebuilt: {exc}") from exc
