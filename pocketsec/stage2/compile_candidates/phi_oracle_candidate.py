"""D2.13/D2.15 — the Φ-oracle as a first-class zero-parameter compile candidate.

Integration plan §6.3 names the Φ-oracle as Stage 3's **first** crystallisation
target, and this module is the test of whether that is even expressible. The
question it answers is deliberately humiliating for the neural path:

    Can the compile format carry a rule that is already a rule?

If it cannot, the compilation story is refuted before a single neural region is
attempted — there would be nothing for Stage 3 to crystallise that is cheaper
than what Stage 1 already computes for free. Measured (MEMORY.md): the Φ-oracle
reaches **0.7484 PR-AUC with zero parameters and ~0 µs/event**, against a TCN at
6.6 µs/event. Roughly three quarters of the task is the representation.

A ``DeterministicScorerSpec`` is therefore *data*, not code: a feature index, an
aggregation name and a human-readable expression. Stage 3 can compile it without
importing Stage 2, which is exactly the seam rule this module exists to honour.

What this module refuses to do: it refuses to let a "zero-parameter" candidate
carry parameters, and it refuses to re-derive the Φ feature index from the
encoder layout at candidate-build time. The index is **pinned** to 73 and
cross-checked against the encoder at import, so a layout change breaks loudly
instead of silently scoring a different feature and reproducing 0.7484 by
accident.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef, require_identifier
from pocketsec.stage1.state.security_state import DIMENSIONS
from pocketsec.stage2.compile_candidates.candidate import (
    CandidateKind,
    CandidateStability,
    CompileCandidateV1,
    MeasuredCost,
    ValidityBoundary,
)
from pocketsec.stage2.encoder.ssir_encoder import (
    ENCODER_VERSION,
    FEATURE_WIDTH,
    NEED_SIGNAL_INDICES,
)

if TYPE_CHECKING:  # pragma: no cover - typing only, keeps the seam import-free
    from pocketsec.stage2.state.window import LineageWindow

__all__ = [
    "AGGREGATIONS",
    "DeterministicScorerSpec",
    "PHI_ORACLE_CANDIDATE_ID",
    "PHI_ORACLE_SCORER",
    "PHI_SIGN_FEATURE_INDEX",
    "PHI_SQUASHED_FEATURE_INDEX",
    "phi_oracle_candidate",
]

#: The squashed **absolute** ΔΦ slot: ``abs(phi) / (abs(phi) + 8.0)``
#: (``encoder/ssir_encoder.py:221``). Any reproduction of the 0.7484 PR-AUC
#: figure must use this exact definition — an unsquashed or signed ΔΦ is a
#: different scorer and will not reproduce it.
PHI_SQUASHED_FEATURE_INDEX = 73

#: The sign of the Φ movement lives here and is **deliberately not read**. The
#: oracle scores magnitude of security-relevant change, not direction: a large
#: drop in Φ is as consequential to look at as a large rise, and folding sign in
#: would make the scorer assert something about intent that the representation
#: does not carry.
PHI_SIGN_FEATURE_INDEX = 74

if NEED_SIGNAL_INDICES["delta_phi"] != PHI_SQUASHED_FEATURE_INDEX:  # pragma: no cover
    raise ContractError(
        f"the pinned Φ feature index {PHI_SQUASHED_FEATURE_INDEX} no longer matches the "
        f"encoder layout ({NEED_SIGNAL_INDICES['delta_phi']}). The 0.7484 measurement was "
        "taken against the old layout; re-measure before repinning."
    )

#: Aggregations a deterministic scorer may declare. Kept tiny on purpose: every
#: aggregation is something Stage 3 must be able to compile without a Stage 2
#: import, so each one is a commitment.
AGGREGATIONS = frozenset({"max_over_window", "mean_over_window", "last_in_window"})

PHI_ORACLE_CANDIDATE_ID = "pocketsec.candidate.phi-oracle-max-squashed-dphi"


@dataclass(frozen=True, slots=True)
class DeterministicScorerSpec:
    """A zero-parameter rule expressed as data Stage 3 can compile.

    No weights, no training, no model file. ``expression`` is carried so a human
    reading the exported JSON can see what will be compiled without running
    anything — the artefact explains itself or it is not auditable.
    """

    scorer_id: str
    feature_index: int
    aggregation: str
    threshold: float | None
    expression: str

    def __post_init__(self) -> None:
        require_identifier(self.scorer_id, "DeterministicScorerSpec.scorer_id")
        if (
            not isinstance(self.feature_index, int)
            or isinstance(self.feature_index, bool)
            or not 0 <= self.feature_index < FEATURE_WIDTH
        ):
            raise ContractError(
                f"DeterministicScorerSpec.feature_index must be within "
                f"[0, {FEATURE_WIDTH}), got {self.feature_index!r}"
            )
        if self.aggregation not in AGGREGATIONS:
            raise ContractError(
                f"DeterministicScorerSpec.aggregation must be one of "
                f"{sorted(AGGREGATIONS)}, got {self.aggregation!r}"
            )
        if self.threshold is not None and (
            not isinstance(self.threshold, float) or self.threshold != self.threshold
        ):
            raise ContractError(
                f"DeterministicScorerSpec.threshold must be None or a finite float, "
                f"got {self.threshold!r}"
            )
        if not isinstance(self.expression, str) or not self.expression.strip():
            raise ContractError("DeterministicScorerSpec.expression must be non-empty")

    def evaluate(self, window: LineageWindow) -> float:
        """Score one lineage window. Zero parameters, no state, no allocation beyond the slice.

        An empty window scores ``0.0``: no evidence is not a low score, it is no
        score, and the caller's abstention path — not this scorer — is what turns
        that into an UNKNOWN verdict.
        """
        rows = window.features()
        if not rows:
            return 0.0
        column = [float(row[self.feature_index]) for row in rows]
        if self.aggregation == "max_over_window":
            return max(column)
        if self.aggregation == "mean_over_window":
            return sum(column) / len(column)
        return column[-1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "scorer_id": self.scorer_id,
            "feature_index": self.feature_index,
            "aggregation": self.aggregation,
            "threshold": self.threshold,
            "expression": self.expression,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> DeterministicScorerSpec:
        try:
            threshold = payload["threshold"]
            return cls(
                scorer_id=str(payload["scorer_id"]),
                feature_index=int(payload["feature_index"]),
                aggregation=str(payload["aggregation"]),
                threshold=None if threshold is None else float(threshold),
                expression=str(payload["expression"]),
            )
        except KeyError as exc:
            raise ContractError(f"DeterministicScorerSpec missing field {exc.args[0]!r}") from exc


#: The scorer that measured 0.7484 PR-AUC with zero parameters. ``threshold`` is
#: ``None`` because the measurement is a *ranking* metric (PR-AUC); a threshold
#: would be an operating point, and Stage 0's harness picks that from an FP
#: budget rather than from a number written here.
PHI_ORACLE_SCORER = DeterministicScorerSpec(
    scorer_id="phi-oracle-max-squashed-dphi",
    feature_index=PHI_SQUASHED_FEATURE_INDEX,
    aggregation="max_over_window",
    threshold=None,
    expression=(
        "max over the lineage window of features[73], the squashed absolute "
        "|dPhi| = abs(phi)/(abs(phi)+8.0); the sign bit at features[74] is not read"
    ),
)


def phi_oracle_candidate(
    *,
    cost: MeasuredCost,
    experiment_id: str,
    evidence: Sequence[EvidenceRef],
    stability: CandidateStability,
    epochs: Sequence[int] = (0,),
    scorer: DeterministicScorerSpec = PHI_ORACLE_SCORER,
) -> CompileCandidateV1:
    """Build the Φ-oracle as a ``DETERMINISTIC_SCORER`` candidate.

    ``cost.parameters`` must be ``0``. The whole point of this candidate is that
    it has none, so a caller passing a parameter count has either measured the
    wrong thing or is smuggling a learned artefact in under a zero-parameter
    label. ``microseconds_per_event=0.0`` is accepted because ~0 µs is the
    measured figure; ``None`` is accepted by the schema but the exporter refuses
    it, so an untimed oracle never reaches Stage 3.

    ``epochs`` defaults to the baseline epoch alone. A deployment passes the
    epochs it actually observed the scorer hold over; defaulting to "all epochs"
    would be an unbounded validity claim, which is what ValidityBoundary exists
    to prevent.
    """
    if cost.parameters != 0:
        raise ContractError(
            f"the Φ-oracle is a zero-parameter scorer; cost.parameters={cost.parameters} "
            "means something learned is being exported under a deterministic label"
        )
    boundary = ValidityBoundary(
        epochs=frozenset(int(epoch) for epoch in epochs),
        encoder_version=ENCODER_VERSION,
        # ΔΦ is computed from the whole nine-dimension state lattice
        # (stage1/state/potential.py), so the scorer reads all of them even
        # though it only ever touches one feature slot.
        state_dimensions=frozenset(DIMENSIONS),
        # A deterministic function of Stage 1's representation has no
        # uncertainty-dependent validity: it is exactly as valid at U=1.0 as at
        # U=0.0, because it makes no claim the uncertainty could contradict.
        max_uncertainty=1.0,
        min_evidence_count=1,
    )
    return CompileCandidateV1(
        candidate_id=PHI_ORACLE_CANDIDATE_ID,
        kind=CandidateKind.DETERMINISTIC_SCORER,
        boundary=boundary,
        evidence_lineage=tuple(evidence),
        cost=cost,
        experiment_id=experiment_id,
        payload={
            "scorer": scorer.to_dict(),
            "feature_semantics": {
                "index_73": "squashed absolute |dPhi| = abs(phi)/(abs(phi)+8.0)",
                "index_74": "sign of dPhi, deliberately not read",
            },
            "provenance_note": (
                "zero-parameter scorer over Stage 1's representation; the reference "
                "PR-AUC figure is corpus-size dependent and must be quoted with "
                "(corpus, count, seed)"
            ),
        },
        stability=stability,
    )
