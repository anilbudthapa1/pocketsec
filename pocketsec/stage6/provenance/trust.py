"""D6.3 / HEL-F03, HEL-F04 — provenance scoring and the evidence-dependence check.

Why this module exists, in the architecture's own sentence (§7): *repeated
attacker-generated events from one compromised process should not become thousands of
independent votes for normality.* Stage 2's gate cannot see this — an
``AdaptationSample`` carries no source — and the spec's §0 probe measured the
consequence: one attacker lineage repeating an escalation-free step across two
corroborated epochs is promoted by Stage 2 alone. Stage 6 adds exactly one thing
Stage 2 lacks: it counts **independence groups**, not observations.

Two functions, both pure:

* :func:`score_provenance` — ``prior(source_class) x visibility x (1 - contamination)``.
  It says how much a capsule is worth as evidence; it never says whether the capsule
  is true, and it never admits or refuses anything (the gateway does).
* :func:`detect_evidence_dependence` — how many distinct groups a set of trust records
  really represents. A group is ONE vote however many capsules it contributed.

Every number in the three tables below is a **chosen parameter** (spec §4.21), not a
measurement; the findings list them under PARAMETERS. The ordering encodes a policy —
a lab's ground truth above a kernel sensor above an analyst above inference, a teacher
and a foreign host near the floor — and no experiment in this repository has
calibrated the magnitudes.

**Known weakness, stated rather than hidden.** For telemetry a group is the hashed
Stage 1 actor lineage. An attacker who forks many short-lived children mints many
groups; arm P1b ("fork-spray", §4.15) measures whether that defeats the check. This
module does not claim it does not.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING

from pocketsec.stage0.contracts.common import ContractError, require_finite_unit_interval
from pocketsec.stage6.capsule.experience_capsule import (
    ContaminationFlag,
    ExperienceCapsuleV1,
    LabelOrigin,
    SourceClass,
)

if TYPE_CHECKING:
    # The ledger imports this module for ProvenanceScore; the runtime import of
    # TrustRecord is local to detect_evidence_dependence to keep the pair acyclic.
    from pocketsec.stage6.provenance.ledger import TrustRecord

__all__ = [
    "FLAG_RISK",
    "LABEL_ORIGIN_WEIGHT",
    "MAX_DEPENDENCE_GROUPS_REPORTED",
    "MIN_PROVENANCE_SCORE",
    "SOURCE_CLASS_PRIOR",
    "DependenceReport",
    "ProvenanceScore",
    "detect_evidence_dependence",
    "score_provenance",
]

#: §4.21. Chosen parameter: below this the gateway buckets a capsule UNCERTAIN.
MIN_PROVENANCE_SCORE: float = 0.5
#: ``DependenceReport.groups`` lists at most this many; ``independent_groups`` counts all.
MAX_DEPENDENCE_GROUPS_REPORTED: int = 16

#: Chosen parameters (§4.21), not measurements.
SOURCE_CLASS_PRIOR: Mapping[SourceClass, float] = MappingProxyType(
    {
        SourceClass.LAB_GROUND_TRUTH: 1.0,
        SourceClass.KERNEL_SENSOR: 0.9,
        SourceClass.ANALYST: 0.8,
        SourceClass.DERIVED_INFERENCE: 0.5,
        SourceClass.EXTERNAL_DATASET: 0.5,
        SourceClass.TEACHER: 0.3,
        SourceClass.FOREIGN_HOST: 0.2,
    }
)

#: Chosen parameters (§4.21). Read by episodic memory's label-quality factor; the
#: provenance score itself deliberately does not use it (the §D6.3 formula has no label
#: term — a label's weight is a question about the label, not about the source).
LABEL_ORIGIN_WEIGHT: Mapping[LabelOrigin, float] = MappingProxyType(
    {
        LabelOrigin.GROUND_TRUTH: 1.0,
        LabelOrigin.ANALYST: 0.8,
        LabelOrigin.INFERENCE: 0.5,
        LabelOrigin.WEAK: 0.3,
        LabelOrigin.TEACHER: 0.3,
        LabelOrigin.NONE: 0.0,
    }
)

#: Chosen parameters (§D6.3). Contamination risk is the MAX over a capsule's flags, not
#: a sum: two mild flags are not one severe one, and a sum would let many harmless
#: annotations push an honest capsule to zero.
FLAG_RISK: Mapping[ContaminationFlag, float] = MappingProxyType(
    {
        ContaminationFlag.ATTACKER_CONTROLLED_SOURCE: 1.0,
        ContaminationFlag.FOREIGN_ORIGIN: 0.6,
        ContaminationFlag.UNCORROBORATED_EPOCH: 0.5,
        ContaminationFlag.DUPLICATE_EVIDENCE: 0.5,
        ContaminationFlag.SENSOR_DISAGREEMENT: 0.4,
        ContaminationFlag.OBSERVATION_INCOMPLETE: 0.3,
        ContaminationFlag.SIMULATED_RECORD: 0.2,
        ContaminationFlag.TRUNCATED: 0.2,
    }
)

# A table that silently misses an enum member would score that member by KeyError at
# runtime, or — worse, if someone "fixed" it with .get(..., 0.0) — as risk-free.
assert set(SOURCE_CLASS_PRIOR) == set(SourceClass), "every SourceClass needs a prior"
assert set(LABEL_ORIGIN_WEIGHT) == set(LabelOrigin), "every LabelOrigin needs a weight"
assert set(FLAG_RISK) == set(ContaminationFlag), "every ContaminationFlag needs a risk"


@dataclass(frozen=True, slots=True)
class ProvenanceScore:
    """How much a capsule is worth as evidence, and why. Not a verdict."""

    score: float
    contamination_risk: float
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        require_finite_unit_interval(self.score, "ProvenanceScore.score")
        require_finite_unit_interval(self.contamination_risk, "ProvenanceScore.contamination_risk")
        if not all(isinstance(reason, str) and reason for reason in self.reasons):
            raise ContractError("ProvenanceScore.reasons must be non-empty strings")
        object.__setattr__(self, "reasons", tuple(self.reasons))


def score_provenance(capsule: ExperienceCapsuleV1) -> ProvenanceScore:
    """HEL-F03. ``prior(source_class) x visibility x (1 - contamination_risk)``.

    Pure and total over valid capsules: every enum member has a table entry (asserted at
    import), and ``visibility`` is already validated to [0, 1] by the capsule.
    """
    if not isinstance(capsule, ExperienceCapsuleV1):
        raise ContractError(f"score_provenance reads capsules, got {type(capsule).__name__}")
    source = capsule.source_provenance.source_class
    prior = SOURCE_CLASS_PRIOR[source]
    flags = sorted(capsule.contamination_flags)
    risk = max((FLAG_RISK[flag] for flag in flags), default=0.0)
    score = prior * capsule.visibility * (1.0 - risk)
    reasons = [f"prior:{source.value}={prior}", f"visibility={capsule.visibility}"]
    reasons.extend(f"flag:{flag.value}={FLAG_RISK[flag]}" for flag in flags)
    if score < MIN_PROVENANCE_SCORE:
        reasons.append("below_min_provenance")
    return ProvenanceScore(score=score, contamination_risk=risk, reasons=tuple(reasons))


@dataclass(frozen=True, slots=True)
class DependenceReport:
    """How many independent votes a set of records is. ``largest_group_share`` (never
    "fraction" — T5) is the share of observations the most frequent group appears in."""

    observations: int
    independent_groups: int
    largest_group_share: float
    groups: tuple[tuple[str, int], ...]
    dependent: bool

    def __post_init__(self) -> None:
        for name in ("observations", "independent_groups"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ContractError(f"DependenceReport.{name} must be a non-negative int")
        require_finite_unit_interval(self.largest_group_share, "largest_group_share")
        if len(self.groups) > MAX_DEPENDENCE_GROUPS_REPORTED:
            raise ContractError(f"groups lists at most {MAX_DEPENDENCE_GROUPS_REPORTED}")
        object.__setattr__(self, "groups", tuple(tuple(pair) for pair in self.groups))


def _groups_of(record: TrustRecord) -> tuple[str, ...]:
    """Normality votes by acting lineage (``step_groups``); labels by asserting group.

    A record with steps is telemetry, and its votes are the lineages that produced the
    steps; a record without steps (a label, a resolution, a response) is one assertion,
    and its vote is the provenance ``independence_group``.
    """
    return record.step_groups if record.step_groups else (record.independence_group,)


def detect_evidence_dependence(
    records: Sequence[TrustRecord], *, min_groups: int
) -> DependenceReport:
    """HEL-F04. Count groups, not capsules: 240 capsules from one group are one vote.

    ``dependent`` is ``independent_groups < min_groups``. An empty input is dependent —
    no evidence is not independent evidence. ``groups`` is ordered by count descending
    then name and cut at ``MAX_DEPENDENCE_GROUPS_REPORTED``; the counts it reports are
    complete, only the listing is bounded.
    """
    from pocketsec.stage6.provenance.ledger import TrustRecord

    if isinstance(min_groups, bool) or not isinstance(min_groups, int) or min_groups < 1:
        raise ValueError(f"min_groups must be an int >= 1, got {min_groups!r}")
    counts: dict[str, int] = {}
    for record in records:
        if not isinstance(record, TrustRecord):
            raise ContractError(f"dependence is computed over TrustRecords, got {type(record)}")
        for group in _groups_of(record):
            counts[group] = counts.get(group, 0) + 1
    observations = len(records)
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    largest = ordered[0][1] / observations if ordered else 0.0
    return DependenceReport(
        observations=observations,
        independent_groups=len(counts),
        largest_group_share=min(1.0, largest),
        groups=tuple(ordered[:MAX_DEPENDENCE_GROUPS_REPORTED]),
        dependent=len(counts) < min_groups,
    )
