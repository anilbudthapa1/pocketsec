"""D8.17 (inbound) / PROM-F20 — Stage 7 antibodies as hypothesis *seeds*, never as evidence.

Architecture §9 lists "Stage-7 collective input: seed hypotheses from distributed evidence"
as one PROMETHEUS generator. This module is the only Stage 8 file that may import Stage 7,
and it imports exactly four names from ``stage7.capsule.knowledge_capsule``
(``KnowledgeCapsuleV1``, ``MotifRow``, ``KnowledgeType``, ``Stance``; spec §2.3, ADR-0071).

What it does: turn each ``ANTIBODY`` capsule with stance ``SUPPORT`` into a typed
:class:`Mechanism`. A Stage 7 antibody's invariant *is* a Stage 6 motif (``MotifRow`` is
``MotifStep`` as four integers, ADR-0062), so the conversion is exact and loses nothing:
one row becomes ``SINGLE``; two rows become ``PRECEDES`` — Stage 6's ``match_motif``
semantics (step *i* then step *j* > *i* of one actor), which the grammar's ``PRECEDES``
reproduces bit for bit.

What it refuses to do:

* **Treat a seed as evidence.** A seed is a hypothesis. It enters PROMETHEUS through
  ``Stage7SeedGenerator``, its genome is ``foreign=True``, and it then faces the whole
  discipline — preregistration, the vault, replication — like any other hypothesis. The
  capsule's self-reported validation and falsification summaries are never read.
* **Accept anything but a supporting antibody.** Every other ``KnowledgeType``, a
  ``CONTEST`` stance, a row count the grammar cannot express and a row the grammar refuses
  are ignored and **counted by reason**, never silently dropped.
* **Grow without bound.** At most ``MAX_STAGE7_SEEDS`` mechanisms; the rest are counted and
  ``truncated`` is set.
* **Send anything back.** There is no outbound path: Stage 7 exports Stage 6 *trusted*
  DETECTOR records only (ADR-0062), so a Stage 8 discovery reaches Stage 7, if ever, by way
  of Stage 6 — never from here (spec §3.2).

Distributed residuals (S8X-078) are not built: a Stage 7 capsule carries no episodes.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage7.capsule.knowledge_capsule import (
    KnowledgeCapsuleV1,
    KnowledgeType,
    MotifRow,
    Stance,
)
from pocketsec.stage8.genome.grammar import (
    GrammarError,
    Mechanism,
    MechanismRelation,
    StepPredicate,
)

__all__ = [
    "MAX_STAGE7_INPUT_CAPSULES",
    "MAX_STAGE7_SEEDS",
    "Stage7SeedReport",
    "seeds_from_capsules",
]

#: Spec §4.21. Chosen parameter, not a measurement.
MAX_STAGE7_SEEDS: int = 64
#: Capsules read per call. Past this the input itself is refused: an unbounded list of
#: foreign objects is not something a research loop should iterate on credit.
MAX_STAGE7_INPUT_CAPSULES: int = 4096

#: Ignore reasons, a closed vocabulary (the report is read by the gate, never parsed).
_REASON_TYPE = "knowledge_type:"
_REASON_CONTEST = "stance:CONTEST"
_REASON_ROWS = "rows:"
_REASON_GRAMMAR = "grammar_refused"
_REASON_DUPLICATE = "duplicate_mechanism"
_REASON_CAP = "seed_cap"


@dataclass(frozen=True, slots=True)
class Stage7SeedReport:
    """What the adapter turned into seeds, and why everything else was ignored."""

    mechanisms: tuple[Mechanism, ...]  # <= MAX_STAGE7_SEEDS
    source_capsule_ids: tuple[str, ...]  # parallel to mechanisms
    ignored_by_reason: tuple[tuple[str, int], ...]
    truncated: bool

    def __post_init__(self) -> None:
        if len(self.mechanisms) != len(self.source_capsule_ids):
            raise ContractError("each seed mechanism names exactly one source capsule")
        if len(self.mechanisms) > MAX_STAGE7_SEEDS:
            raise ContractError(f"at most {MAX_STAGE7_SEEDS} Stage 7 seeds")


def _predicate(row: MotifRow) -> StepPredicate:
    return StepPredicate(
        relation=row.relation,
        require_properties=row.require_properties,
        forbid_properties=row.forbid_properties,
        require_raised=row.require_raised,
    )


def _mechanism_of(capsule: KnowledgeCapsuleV1) -> Mechanism | str:
    """The seed mechanism, or the ignore reason."""
    if capsule.knowledge_type is not KnowledgeType.ANTIBODY:
        return _REASON_TYPE + capsule.knowledge_type.value
    if capsule.stance is not Stance.SUPPORT:
        return _REASON_CONTEST
    rows = capsule.semantic_invariant
    if len(rows) not in (1, 2):
        return f"{_REASON_ROWS}{len(rows)}"
    try:
        predicates = tuple(_predicate(row) for row in rows)
        relation = MechanismRelation.SINGLE if len(rows) == 1 else MechanismRelation.PRECEDES
        return Mechanism(relation, predicates)
    except GrammarError:
        # e.g. two identical rows: Stage 6 would match it, the grammar spells it REPEATED
        # and refuses the PRECEDES form. Counted, never repaired.
        return _REASON_GRAMMAR


def seeds_from_capsules(capsules: Sequence[KnowledgeCapsuleV1]) -> Stage7SeedReport:
    """Supporting ANTIBODY capsules as ``SINGLE`` / ``PRECEDES`` seeds; the rest counted."""
    batch = tuple(capsules)
    if len(batch) > MAX_STAGE7_INPUT_CAPSULES:
        raise ContractError(
            f"seeds_from_capsules reads at most {MAX_STAGE7_INPUT_CAPSULES} capsules, "
            f"got {len(batch)}"
        )
    if any(not isinstance(capsule, KnowledgeCapsuleV1) for capsule in batch):
        raise ContractError("seeds_from_capsules reads KnowledgeCapsuleV1 values only")
    mechanisms: list[Mechanism] = []
    sources: list[str] = []
    seen: set[str] = set()
    ignored: Counter[str] = Counter()
    for capsule in batch:
        outcome = _mechanism_of(capsule)
        if isinstance(outcome, str):
            ignored[outcome] += 1
            continue
        digest = outcome.digest()
        if digest in seen:
            ignored[_REASON_DUPLICATE] += 1
            continue
        if len(mechanisms) >= MAX_STAGE7_SEEDS:
            ignored[_REASON_CAP] += 1
            continue
        seen.add(digest)
        mechanisms.append(outcome)
        sources.append(capsule.capsule_id)
    return Stage7SeedReport(
        mechanisms=tuple(mechanisms),
        source_capsule_ids=tuple(sources),
        ignored_by_reason=tuple(sorted(ignored.items())),
        truncated=ignored[_REASON_CAP] > 0,
    )
