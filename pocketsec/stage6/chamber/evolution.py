"""HEL-F14 — the HELIOS evolution chamber: where candidate knowledge is built, never installed.

Architecture §17: all nontrivial learning happens in an isolated candidate
environment. In this repository that isolation is a matter of **values, not
sandboxes**: the chamber receives an immutable ``TrustedKnowledgeState``, builds a
*new* immutable state from it, and returns both inside an ``EvolutionCandidate``.
It holds no reference to ``TrustedMind`` and has no method that writes trusted
state; the only writer is ``promotion/controller.py`` (ADR-0052). An exception
anywhere in here therefore leaves the trusted digest exactly where it was
(architecture §41), because nothing here could have moved it.

What the chamber refuses, before doing any work:

* **Unquarantined input.** Every ``QuarantineVerdict`` must be one this host's
  gateway issued (``gateway.issued``) *and* bucketed ``TRUSTED_CANDIDATE``. One bad
  verdict refuses the whole call with ``UnquarantinedInputError`` — there is no
  partial candidate built from the verdicts that happened to be good. Admissions
  must be the very ``CandidateAdmission`` values those verdicts carry, and any
  capsule offered for procedural learning must be byte-identical (by content
  digest) to the capsule its verdict's ``TrustRecord`` names. A hand-built verdict,
  admission or capsule is raw telemetry wearing a costume, and is refused.
* **Full history.** More than ``max_capsules`` verdicts is a ``ContractError``: the
  chamber is a bounded workspace, not a retraining farm (G6.11).
* **Unbounded work.** Every scoring and motif evaluation charges a ``WorkMeter``
  budgeted at ``work_budget``; overrunning it raises ``WorkBudgetExceeded`` rather
  than returning a half-built candidate.

The chamber is the **only** minter of candidates, including MNEMOSYNE's
CONSOLIDATION candidates (through the issuer it binds into the consolidator) and
RESURRECTION candidates (``spawn_resurrection_candidate``): the controller accepts
nothing this chamber did not issue, and ``issued`` compares a fingerprint over the
proposed digest, so a candidate altered after issue is no longer issued (arm P4a).

Candidate kinds are exactly those with an executor (ADR-0056): no classifier,
adapter or structural kind exists here, because nothing could execute one.

``induce_motifs`` is **shared** with every §7 baseline learner, so two learners
differ only in the mechanism under test, never in how a motif is found.
"""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING

from pocketsec.stage0.contracts.common import ContractError, digest_of_bytes
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage2.adaptation.quarantine import (
    DEFAULT_CONSISTENCY_RADIUS,
    meaning_distance,
    pattern_key,
)
from pocketsec.stage6.capsule.experience_capsule import EncodedStep, ExperienceCapsuleV1
from pocketsec.stage6.capsule.quarantine import QuarantineBucket, QuarantineVerdict
from pocketsec.stage6.fossils.lineage import KnowledgeLineageDAG, LineageNode, NodeKind
from pocketsec.stage6.memory.competition import (
    CompetitionOutcome,
    CompetitionResult,
    compete_knowledge,
    newest_wins,
    overlaps,
)
from pocketsec.stage6.memory.episodic import EpisodeSkeleton, EpisodeTier
from pocketsec.stage6.memory.procedural import (
    ProcedureRecord,
    merge_procedure,
    procedure_key,
    procedure_observations,
)
from pocketsec.stage6.memory.semantic import (
    ALL_CONTEXTS,
    MAX_BASELINE_ITEMS,
    MAX_DETECTOR_ITEMS,
    MAX_ITEM_CAPSULE_REFS,
    MAX_ITEM_EPOCHS,
    MAX_PROCEDURE_ITEMS,
    MAX_REHEARSAL_EXEMPLARS,
    STATE_FLOAT_DECIMALS,
    ItemKind,
    ItemLineage,
    ItemValidation,
    KnowledgeItem,
    MotifStep,
    TrustedKnowledgeState,
    is_escalating,
    item_applies,
    match_motif,
    motif_pattern_key,
    score_session,
)
from pocketsec.stage6.plasticity.field import (
    PlasticityField,
    PlasticityTerms,
    baseline_terms,
    compute_plasticity_field,
    detector_terms,
    plasticity,
    procedure_terms,
    safe_share,
    threshold_terms,
)
from pocketsec.stage6.plasticity.masks import (
    PlasticityMask,
    field_only_freezes,
    generate_plasticity_mask,
    uniform_mask,
)
from pocketsec.stage6.rehearsal.counterfactual import ReplayVariant, generate_counterfactual_replay
from pocketsec.stage6.resources import WorkMeter

if TYPE_CHECKING:
    from pocketsec.stage6.capsule.quarantine import CandidateAdmission, QuarantineGateway
    from pocketsec.stage6.consolidator.mnemosyne import MnemosyneConsolidator
    from pocketsec.stage6.homeostasis.drift import ResurrectionProposal
    from pocketsec.stage6.memory.episodic import EpisodicMemory
    from pocketsec.stage6.memory.half_life import EpistemicHalfLife

__all__ = [
    "SEALED_NAMES",
    "FPR_BUDGET",
    "HOLDOUT_SHARE",
    "MAX_CHAMBER_CAPSULES",
    "MAX_CHAMBER_WORK_UNITS",
    "MAX_ISSUED_CANDIDATES",
    "MAX_MOTIF_CANDIDATES_PER_EPISODE",
    "MIN_DETECTOR_PRECISION",
    "CandidateKind",
    "ChamberStats",
    "EvolutionCandidate",
    "EvolutionChamber",
    "KnowledgeDelta",
    "MotifCandidate",
    "UnquarantinedInputError",
    "candidate_fingerprint",
    "holdout_member",
    "induce_motifs",
]

#: Verdicts one call may carry. The chamber never sees the full history (G6.11).
#: The minting names only this file may mention (boundary rule 5), declared by the owner
#: so the gate can scan for them without spelling them itself.
SEALED_NAMES: tuple[str, ...] = ("_issue_candidate", "_issued_candidates")
MAX_CHAMBER_CAPSULES: int = 128
#: Work units one call may spend (1 per item x step comparison, 1 per motif
#: evaluation per distinct episode).
MAX_CHAMBER_WORK_UNITS: int = 500_000
#: Seed motifs taken from one malicious episode, in position order.
MAX_MOTIF_CANDIDATES_PER_EPISODE: int = 16
#: A motif is kept only if its episode-level precision on training data reaches this.
MIN_DETECTOR_PRECISION: float = 0.9
#: Share of episodes (by ``sha256(episode_id)``) held out from induction. "Share",
#: never "fraction": the T5 screen refuses any field containing "action".
HOLDOUT_SHARE: float = 0.25
#: Issued candidate ids remembered for ``issued``; the oldest is forgotten and
#: counted, and a forgotten candidate is then refused by the controller (fails closed).
MAX_ISSUED_CANDIDATES: int = 256
#: The false-positive budget CALIBRATION fits the threshold to. Spec §4.21 places
#: this constant in ``labs/endurance.py``, which no runtime module may import
#: (boundary rule 6); it is defined here and the labs must import it from here.
FPR_BUDGET: float = 0.05


class UnquarantinedInputError(ContractError):
    """Input that did not come through this host's quarantine gateway."""


class CandidateKind(StrEnum):
    """ADR-0056: exactly the kinds that have an executor."""

    STATISTICAL = "STATISTICAL"  # BASELINE add/update from CandidateAdmissions
    SYMBOLIC = "SYMBOLIC"  # DETECTOR add/refine/remove
    CALIBRATION = "CALIBRATION"  # THRESHOLD change within mask.max_threshold_delta
    PROCEDURAL = "PROCEDURAL"  # PROCEDURE add/merge
    CONSOLIDATION = "CONSOLIDATION"  # produced by MNEMOSYNE
    RESURRECTION = "RESURRECTION"  # produced by homeostasis.drift


@dataclass(frozen=True, slots=True)
class KnowledgeDelta:
    """What a candidate changes, relative to its base state."""

    added: tuple[KnowledgeItem, ...] = ()
    removed: tuple[str, ...] = ()
    replaced: tuple[tuple[str, KnowledgeItem], ...] = ()
    threshold: float | None = None
    rehearsal_added: tuple[EpisodeSkeleton, ...] = ()
    rehearsal_removed: tuple[str, ...] = ()
    active_context: str | None = None
    #: Lineage of a changed threshold: the candidate, the benign episodes it was fitted
    #: against and their evidence (review F3). ``None`` iff ``threshold`` is ``None``.
    threshold_lineage: ItemLineage | None = None

    def is_empty(self) -> bool:
        return not (
            self.added
            or self.removed
            or self.replaced
            or self.threshold is not None
            or self.rehearsal_added
            or self.rehearsal_removed
            or self.active_context is not None
        )

    def item_mutations(self) -> int:
        return len(self.added) + len(self.removed) + len(self.replaced)

    def summary(self) -> dict[str, object]:
        """A lineage-free, canonical description: what the candidate id digests."""
        return {
            "added": sorted(item.item_id for item in self.added),
            "removed": sorted(self.removed),
            "replaced": sorted([old, new.item_id, new.status.value] for old, new in self.replaced),
            "threshold": None if self.threshold is None else round(self.threshold, 6),
            "rehearsal_added": sorted(e.episode_id for e in self.rehearsal_added),
            "rehearsal_removed": sorted(self.rehearsal_removed),
            "active_context": self.active_context,
        }


@dataclass(frozen=True, slots=True)
class MotifCandidate:
    """One induced motif and the training evidence for it.

    ``true_positives``/``false_positives`` are episode counts on the training
    split; they are carried (not re-derived from ``precision``) so the item weight
    ``(tp + 1) / (tp + fp + 2)`` is exact.
    """

    motif: tuple[MotifStep, ...]
    precision: float
    coverage: float
    support: tuple[str, ...]  # malicious training episode ids matched, sorted
    true_positives: int
    false_positives: int

    @property
    def weight(self) -> float:
        return (self.true_positives + 1) / (self.true_positives + self.false_positives + 2)


@dataclass(frozen=True, slots=True)
class EvolutionCandidate:
    """A proposed trusted state and everything needed to judge and trace it."""

    candidate_id: str  # "cand-" + digest(base_digest, delta)
    kinds: frozenset[CandidateKind]
    base_digest: str
    proposed: TrustedKnowledgeState
    delta: KnowledgeDelta
    verdict_ids: tuple[str, ...]
    capsule_ids: tuple[str, ...]
    mask: PlasticityMask
    competition: tuple[CompetitionResult, ...]
    holdout_episode_ids: tuple[str, ...]
    mask_refusals: int  # changes the mask forbade (plasticity firing count)
    work_units: int
    created_sequence: int

    def __post_init__(self) -> None:
        if not self.candidate_id.startswith("cand-"):
            raise ContractError("candidate_id must start with 'cand-'")
        if not self.kinds or not all(isinstance(k, CandidateKind) for k in self.kinds):
            raise ContractError("a candidate names at least one CandidateKind")
        if self.proposed.parent_digest != self.base_digest:
            raise ContractError("a candidate's proposed state must descend from its base digest")
        if self.mask_refusals < 0 or self.work_units < 0 or self.created_sequence < 0:
            raise ContractError("candidate counters are non-negative")


@dataclass(frozen=True, slots=True)
class ChamberStats:
    """Cumulative firing counts (Rule C) and bounds; counters never reset."""

    spawned: int = 0
    returned_none: int = 0
    issued_forgotten: int = 0
    mask_refusals: int = 0
    # HEL-F08 firing count: changes the uniform control would have KEPT that the field froze
    field_only_freezes: int = 0
    field_permission_differences: int = 0  # permissions withheld vs uniform, outcome or not
    field_displaced: int = 0  # uniform-kept changes the field outranked (priority, not freeze)
    competitions: int = 0
    competition_non_replace: int = (
        0  # HEL-F10 firing count: outcomes newest-wins would have replaced
    )
    capacity_refusals: int = 0
    utility_fallbacks: int = 0  # holdout had no episode of the class; training split used
    consolidation_candidates: int = 0
    issued_live: int = 0


@dataclass
class _Counters:
    """The mutable twin of ``ChamberStats`` (every field but ``issued_live``)."""

    spawned: int = 0
    returned_none: int = 0
    issued_forgotten: int = 0
    mask_refusals: int = 0
    field_only_freezes: int = 0
    field_permission_differences: int = 0
    field_displaced: int = 0
    competitions: int = 0
    competition_non_replace: int = 0
    capacity_refusals: int = 0
    utility_fallbacks: int = 0
    consolidation_candidates: int = 0


def holdout_member(episode_id: str, *, share: float = HOLDOUT_SHARE) -> bool:
    """Deterministic split: ``int(sha256(episode_id)[:8], 16) / 2**32 < share``."""
    head = hashlib.sha256(episode_id.encode("utf-8")).hexdigest()[:8]
    return int(head, 16) / 2**32 < share


def candidate_fingerprint(candidate: EvolutionCandidate) -> str:
    """Digest over everything a tamperer could swap after the chamber issued it."""
    payload = {
        "candidate_id": candidate.candidate_id,
        "base": candidate.base_digest,
        "proposed": candidate.proposed.digest(),
        "kinds": sorted(k.value for k in candidate.kinds),
        "delta": candidate.delta.summary(),
        "verdicts": list(candidate.verdict_ids),
        "capsules": list(candidate.capsule_ids),
        "sequence": candidate.created_sequence,
    }
    return digest_of_bytes(json.dumps(payload, sort_keys=True).encode("utf-8"))


# --- motif induction -----------------------------------------------------------


def _bits(mask: int) -> tuple[int, ...]:
    return tuple(1 << i for i in range(mask.bit_length()) if mask >> i & 1)


def _signature(episode: EpisodeSkeleton) -> tuple[tuple[int, int, int, int], ...]:
    # Everything match_motif reads: the actor grouping, order, relation and masks.
    return tuple(
        (s.actor_slot, s.relation, s.object_property_mask, s.state_delta_mask)
        for s in episode.steps
    )


@dataclass(frozen=True, slots=True)
class _Evaluation:
    tp: int
    fp: int
    malicious_ids: tuple[str, ...]
    benign_groups: tuple[int, ...]

    @property
    def precision(self) -> float:
        total = self.tp + self.fp
        return self.tp / total if total else 0.0


class _MotifEvaluator:
    """Episode-level tp/fp of a motif, cached, over structurally distinct episodes.

    Episodes with identical step signatures match identically, so each distinct
    signature is evaluated once and weighted by its multiplicity. The meter is
    charged for the work actually done: one unit per distinct episode evaluated.
    """

    def __init__(
        self,
        malicious: Sequence[EpisodeSkeleton],
        benign: Sequence[EpisodeSkeleton],
        meter: WorkMeter,
    ):
        self._malicious = self._group(malicious)
        self._benign = self._group(benign)
        self._meter = meter
        self._cache: dict[tuple[MotifStep, ...], _Evaluation] = {}

    @staticmethod
    def _group(
        episodes: Sequence[EpisodeSkeleton],
    ) -> list[tuple[EpisodeSkeleton, tuple[str, ...]]]:
        groups: dict[tuple[tuple[int, int, int, int], ...], list[EpisodeSkeleton]] = {}
        for episode in episodes:
            groups.setdefault(_signature(episode), []).append(episode)
        return [(members[0], tuple(e.episode_id for e in members)) for members in groups.values()]

    def benign_steps(self, groups: Iterable[int]) -> list[EpisodeSkeleton]:
        return [self._benign[g][0] for g in groups]

    def __call__(self, motif: tuple[MotifStep, ...]) -> _Evaluation:
        cached = self._cache.get(motif)
        if cached is not None:
            return cached
        self._meter.charge(len(self._malicious) + len(self._benign))
        malicious_ids: list[str] = []
        for representative, ids in self._malicious:
            if match_motif(motif, representative.steps):
                malicious_ids.extend(ids)
        benign_groups = [
            index for index, (rep, _) in enumerate(self._benign) if match_motif(motif, rep.steps)
        ]
        fp = sum(len(self._benign[g][1]) for g in benign_groups)
        result = _Evaluation(
            len(malicious_ids), fp, tuple(sorted(malicious_ids)), tuple(benign_groups)
        )
        self._cache[motif] = result
        return result


def _with_step(motif: tuple[MotifStep, ...], index: int, **changes: int) -> tuple[MotifStep, ...]:
    return (*motif[:index], replace(motif[index], **changes), *motif[index + 1 :])


def _drop_bits(
    motif: tuple[MotifStep, ...], evaluate: _MotifEvaluator, floor: float
) -> tuple[MotifStep, ...]:
    """Greedily generalise: drop each required bit whose loss keeps precision >= floor."""
    for index in range(len(motif)):
        for name in ("require_properties", "require_raised"):
            for bit in _bits(getattr(motif[index], name)):
                trial = _with_step(motif, index, **{name: getattr(motif[index], name) & ~bit})
                if evaluate(trial).precision >= floor:
                    motif = trial
    return motif


def _forbid_options(
    motif: tuple[MotifStep, ...], benign: Sequence[EpisodeSkeleton]
) -> list[tuple[int, int]]:
    """(step index, bit) pairs present on a benign step the motif step matches."""
    options: set[tuple[int, int]] = set()
    for index, part in enumerate(motif):
        for episode in benign:
            for step in episode.steps:
                if (
                    step.relation == part.relation
                    and step.object_property_mask & part.require_properties
                    == part.require_properties
                    and step.object_property_mask & part.forbid_properties == 0
                    and step.state_delta_mask & part.require_raised == part.require_raised
                ):
                    extra = step.object_property_mask & ~part.require_properties
                    options.update((index, bit) for bit in _bits(extra))
    return sorted(options)


def _add_forbid_bits(
    motif: tuple[MotifStep, ...], evaluate: _MotifEvaluator
) -> tuple[MotifStep, ...]:
    """While a benign twin still matches, forbid the bit that best separates it.

    Terminates: each round forbids a new bit and the bit space is finite.
    """
    current = evaluate(motif)
    while current.fp > 0:
        best: tuple[tuple[float, int], tuple[MotifStep, ...], _Evaluation] | None = None
        for index, bit in _forbid_options(motif, evaluate.benign_steps(current.benign_groups)):
            trial = _with_step(motif, index, forbid_properties=motif[index].forbid_properties | bit)
            result = evaluate(trial)
            key = (result.precision, result.tp)
            if best is None or key > best[0]:
                best = (key, trial, result)
        if best is None or best[2].precision <= current.precision:
            return motif
        motif, current = best[1], best[2]
    return motif


def _episode_seeds(episode: EpisodeSkeleton, limit: int) -> list[tuple[MotifStep, ...]]:
    """Singles and same-actor ordered pairs over escalating steps, in position order."""
    escalating = [step for step in episode.steps if is_escalating(step)]
    seeds: list[tuple[MotifStep, ...]] = []
    for i, first in enumerate(escalating):
        seeds.append((_specific(first),))
        seeds.extend(
            (_specific(first), _specific(second))
            for second in escalating[i + 1 :]
            if second.actor_slot == first.actor_slot
        )
        if len(seeds) >= limit:
            break
    return seeds[:limit]


def _specific(step: EncodedStep) -> MotifStep:
    return MotifStep(
        relation=step.relation,
        require_properties=step.object_property_mask,
        forbid_properties=0,
        require_raised=step.state_delta_mask,
    )


def induce_motifs(
    malicious: Sequence[EpisodeSkeleton],
    benign: Sequence[EpisodeSkeleton],
    *,
    max_per_episode: int = MAX_MOTIF_CANDIDATES_PER_EPISODE,
    min_precision: float = MIN_DETECTOR_PRECISION,
    meter: WorkMeter,
) -> tuple[MotifCandidate, ...]:
    """Specific-to-general motif induction, shared by the chamber and every baseline.

    Per malicious episode: every escalating single step and same-actor ordered
    pair, first ``max_per_episode`` by position. Each seed starts fully specific,
    is generalised by dropping required bits while precision on
    ``malicious + benign`` stays >= ``min_precision``, gains a forbid bit while a
    benign twin still matches, and is generalised once more. Only motifs at or
    above ``min_precision`` with at least one true positive survive. Output order
    is deterministic: episodes by id, seeds by position, first discovery wins.
    """
    if max_per_episode < 1:
        raise ContractError("max_per_episode must be >= 1")
    for episode in malicious:
        if episode.verdict is not Verdict.MALICIOUS:
            raise ContractError(f"episode {episode.episode_id} is not MALICIOUS-labelled")
    for episode in benign:
        if episode.verdict is not Verdict.BENIGN:
            raise ContractError(f"episode {episode.episode_id} is not BENIGN-labelled")
    ordered = sorted(malicious, key=lambda e: e.episode_id)
    evaluate = _MotifEvaluator(ordered, sorted(benign, key=lambda e: e.episode_id), meter)
    seeds: dict[tuple[MotifStep, ...], None] = {}
    for episode in ordered:
        for seed in _episode_seeds(episode, max_per_episode):
            seeds.setdefault(seed, None)
    found: dict[tuple[MotifStep, ...], MotifCandidate] = {}
    for seed in seeds:
        motif = _drop_bits(seed, evaluate, min_precision)
        motif = _drop_bits(_add_forbid_bits(motif, evaluate), evaluate, min_precision)
        result = evaluate(motif)
        if motif in found or result.tp == 0 or result.precision < min_precision:
            continue
        found[motif] = MotifCandidate(
            motif=motif,
            precision=result.precision,
            coverage=result.tp / len(ordered),
            support=result.malicious_ids,
            true_positives=result.tp,
            false_positives=result.fp,
        )
    return tuple(found.values())


# --- the chamber ------------------------------------------------------------------


class EvolutionChamber:
    """HEL-F14. Builds candidates from quarantined input; installs nothing.

    ``plasticity_field=False`` replaces the field with ``uniform_mask`` at the same
    budgets (HEL-F08's control); ``competition=False`` replaces
    ``compete_knowledge`` with ``newest_wins`` (HEL-F10's control).
    """

    def __init__(
        self,
        *,
        gateway: QuarantineGateway,
        episodic: EpisodicMemory,
        consolidator: MnemosyneConsolidator,
        max_capsules: int = MAX_CHAMBER_CAPSULES,
        work_budget: int = MAX_CHAMBER_WORK_UNITS,
        plasticity_field: bool = True,
        competition: bool = True,
    ) -> None:
        if not 1 <= max_capsules <= MAX_CHAMBER_CAPSULES:
            raise ContractError(f"max_capsules must be in [1, {MAX_CHAMBER_CAPSULES}]")
        if not 1 <= work_budget <= MAX_CHAMBER_WORK_UNITS:
            raise ContractError(f"work_budget must be in [1, {MAX_CHAMBER_WORK_UNITS}]")
        self._gateway = gateway
        self._episodic = episodic
        self._consolidator = consolidator
        self._max_capsules = max_capsules
        self._work_budget = work_budget
        self._plasticity_field = plasticity_field
        self._competition = competition
        self._issued_candidates: OrderedDict[str, str] = OrderedDict()
        self._counters = _Counters()
        consolidator.bind_candidate_issuer(self._issue_consolidation)

    # -- the sealed issued set ---------------------------------------------------

    def issued(self, candidate: EvolutionCandidate) -> bool:
        """True only for a candidate this chamber built, unaltered since."""
        if not isinstance(candidate, EvolutionCandidate):
            return False
        expected = self._issued_candidates.get(candidate.candidate_id)
        return expected is not None and expected == candidate_fingerprint(candidate)

    def _issue_candidate(self, candidate: EvolutionCandidate) -> EvolutionCandidate:
        self._issued_candidates[candidate.candidate_id] = candidate_fingerprint(candidate)
        self._issued_candidates.move_to_end(candidate.candidate_id)
        while len(self._issued_candidates) > MAX_ISSUED_CANDIDATES:
            self._issued_candidates.popitem(last=False)
            self._counters.issued_forgotten += 1
        return candidate

    def stats(self) -> ChamberStats:
        return ChamberStats(**vars(self._counters), issued_live=len(self._issued_candidates))

    def memory_bytes(self) -> int:
        # Each issued entry: a ~40-char id and a 71-char digest, plus dict overhead.
        return len(self._issued_candidates) * 256

    # -- input verification (step 1) --------------------------------------------------

    def _require_quarantined(
        self,
        verdicts: tuple[QuarantineVerdict, ...],
        admissions: tuple[CandidateAdmission, ...],
        capsules: tuple[ExperienceCapsuleV1, ...],
    ) -> None:
        for verdict in verdicts:
            if not isinstance(verdict, QuarantineVerdict) or not self._gateway.issued(verdict):
                raise UnquarantinedInputError("a verdict was not issued by this host's gateway")
            if verdict.bucket is not QuarantineBucket.TRUSTED_CANDIDATE:
                raise UnquarantinedInputError(
                    f"verdict {verdict.verdict_id} is {verdict.bucket.value}, not TRUSTED_CANDIDATE"
                )
            if not self._consolidator.lineage.has(verdict.verdict_id):
                raise UnquarantinedInputError(
                    f"verdict {verdict.verdict_id} has no VERDICT lineage node"
                )
        carried = {admission for verdict in verdicts for admission in verdict.admissions}
        for admission in admissions:
            if admission not in carried:
                raise UnquarantinedInputError(
                    "an admission is not carried by any verdict in this call"
                )
        digests = {verdict.capsule_id: verdict.trust.content_digest for verdict in verdicts}
        for capsule in capsules:
            if digests.get(capsule.capsule_id) != capsule.digest():
                raise UnquarantinedInputError(
                    f"capsule {capsule.capsule_id} differs from the one its verdict admitted"
                )

    # -- HEL-F14 ---------------------------------------------------------------------

    def spawn_evolution_candidate(
        self,
        *,
        trusted: TrustedKnowledgeState,
        verdicts: Sequence[QuarantineVerdict],
        admissions: Sequence[CandidateAdmission],
        half_lives: Sequence[EpistemicHalfLife],
        sequence: int,
        capsules: Sequence[ExperienceCapsuleV1] = (),
    ) -> EvolutionCandidate | None:
        """HEL-F14 — spec §D6.11 steps 1-11. ``None`` when nothing survives.

        ``capsules`` (an addition to the spec signature) carries RESPONSE_OUTCOME
        capsules for PROCEDURAL learning: a verdict holds no receipt rows, so
        without the capsule there is nothing to merge. Each is bound to its
        verdict by content digest in step 1.
        """
        verdict_list, capsule_list = tuple(verdicts), tuple(capsules)
        self._require_quarantined(verdict_list, tuple(admissions), capsule_list)
        if len(verdict_list) > self._max_capsules:
            raise ContractError(
                f"{len(verdict_list)} verdicts exceed the {self._max_capsules}-capsule workspace"
            )
        self._counters.spawned += 1
        run = _SpawnRun(
            self, trusted, verdict_list, sequence, {h.item_id: h.trust for h in half_lives}
        )
        candidate = run.build(tuple(admissions), capsule_list)
        if candidate is None:
            self._counters.returned_none += 1
            return None
        return self._issue_candidate(candidate)

    # -- MNEMOSYNE's only route to a candidate -------------------------------------

    def _issue_consolidation(
        self, *, trusted: TrustedKnowledgeState, delta: KnowledgeDelta, sequence: int, reason: str
    ) -> EvolutionCandidate | None:
        """Wrap a consolidation delta as a CONSOLIDATION candidate, after checking it.

        Consolidation maintains knowledge; it may not *create* any. So: a merged
        item must equal every parent in what it detects and cover exactly their
        contexts; a replaced item may change only its status; rehearsal exemplars
        must already be resident; the threshold and context are untouchable.
        Protected items are frozen by the same uniform mask every candidate gets.
        """
        _check_consolidation(trusted, delta, self._resident_episode_ids(trusted))
        mask = self._consolidation_mask(trusted, delta, sequence)
        candidate_id = _candidate_id(trusted, delta, sequence)
        added = tuple(_stamp(item, candidate_id) for item in delta.added)
        final = replace(delta, added=added)
        rehearsal = _rehearsal_after(trusted, final)
        proposed = trusted.with_changes(
            add=added, remove=final.removed, replace=final.replaced, rehearsal=rehearsal
        )
        lineage = self._consolidator.lineage
        parents = _consolidation_parents(trusted, final, self._episodic, lineage)
        if not parents:
            return None
        candidate = EvolutionCandidate(
            candidate_id=candidate_id,
            kinds=frozenset({CandidateKind.CONSOLIDATION}),
            base_digest=trusted.digest(),
            proposed=proposed,
            delta=final,
            verdict_ids=tuple(
                p
                for p in parents
                if (node := lineage.node(p)) is not None and node.kind is NodeKind.VERDICT
            ),
            capsule_ids=tuple(sorted({c for i in added for c in i.lineage.capsule_ids})),
            mask=mask,
            competition=(),
            holdout_episode_ids=(),
            mask_refusals=0,
            work_units=0,
            created_sequence=sequence,
        )
        _record_candidate(lineage, candidate, parents, reason)
        self._counters.consolidation_candidates += 1
        return self._issue_candidate(candidate)

    # -- RESURRECTION's only route to a candidate --------------------------------

    def spawn_resurrection_candidate(
        self, *, trusted: TrustedKnowledgeState, proposal: ResurrectionProposal, sequence: int
    ) -> EvolutionCandidate | None:
        """Wrap a HEL-F21 proposal as a RESURRECTION candidate, after re-verifying it.

        Every proposed item must be *exactly* an item held by the fossil it names,
        re-loaded here through the store's integrity check: a proposal cannot
        smuggle in knowledge no validated state ever held. Items already resident
        are skipped; at most the mask's mutation budget is taken per candidate and
        the rest is counted as postponed (call again for more).
        """
        held = {i.item_id: i for i in self._consolidator.fossils.load(proposal.fossil_hash).items}
        for item in proposal.items:
            if held.get(item.item_id) != item:
                raise UnquarantinedInputError(
                    f"{item.item_id} is not held by fossil {proposal.fossil_hash}"
                )
        resident = {i.item_id for i in trusted.items}
        wanted = sorted(
            (i for i in proposal.items if i.item_id not in resident), key=lambda i: i.item_id
        )
        mask = uniform_mask(
            [f"new:{i.item_id}" for i in wanted], protected=frozenset(), now_sequence=sequence
        )
        taken = wanted[: mask.max_item_mutations]
        self._counters.mask_refusals += len(wanted) - len(taken)
        lineage = self._consolidator.lineage
        parents = _resurrection_parents(lineage, proposal.fossil_hash, taken)
        if not taken or not parents:
            return None
        draft = KnowledgeDelta(added=tuple(taken))
        candidate_id = _candidate_id(trusted, draft, sequence)
        delta = KnowledgeDelta(added=tuple(_stamp(i, candidate_id) for i in taken))
        candidate = EvolutionCandidate(
            candidate_id=candidate_id,
            kinds=frozenset({CandidateKind.RESURRECTION}),
            base_digest=trusted.digest(),
            proposed=trusted.with_changes(add=delta.added),
            delta=delta,
            verdict_ids=(),
            capsule_ids=tuple(sorted({c for i in taken for c in i.lineage.capsule_ids})),
            mask=mask,
            competition=(),
            holdout_episode_ids=(),
            mask_refusals=len(wanted) - len(taken),
            work_units=0,
            created_sequence=sequence,
        )
        _record_candidate(lineage, candidate, parents, f"resurrect:{proposal.context_id}")
        return self._issue_candidate(candidate)

    def _consolidation_mask(
        self, trusted: TrustedKnowledgeState, delta: KnowledgeDelta, sequence: int
    ) -> PlasticityMask:
        """The uniform mask every consolidation gets; any refusal refuses the whole delta."""
        touched = [
            *(i.item_id for i in delta.added),
            *delta.removed,
            *(old for old, _ in delta.replaced),
        ]
        mask = uniform_mask(touched, protected=_protected_ids(trusted), now_sequence=sequence)
        refused = [cid for cid in touched if not mask.permits(cid, now_sequence=sequence)]
        if refused or delta.item_mutations() > mask.max_item_mutations:
            self._counters.mask_refusals += max(len(refused), 1)
            raise ContractError(f"consolidation delta exceeds its mask: refused {sorted(refused)}")
        return mask

    def _resident_episode_ids(self, trusted: TrustedKnowledgeState) -> frozenset[str]:
        resident = {e.episode_id for e in self._episodic.episodes(tier=EpisodeTier.LEARNING)}
        return frozenset(resident | {e.episode_id for e in trusted.rehearsal})


# --- helpers shared by spawn and consolidation --------------------------------------


def _resurrection_parents(
    lineage: KnowledgeLineageDAG, fossil_hash: str, taken: Sequence[KnowledgeItem]
) -> list[str]:
    """The FOSSIL node(s) holding the items, plus the candidates that first admitted them."""
    fossils = {
        n.node_id for n in lineage.nodes() if n.kind is NodeKind.FOSSIL and n.digest == fossil_hash
    }
    admitted = {i.lineage.candidate_id for i in taken if lineage.has(i.lineage.candidate_id)}
    return sorted(fossils | admitted)


def _protected_ids(trusted: TrustedKnowledgeState) -> frozenset[str]:
    return frozenset(item.item_id for item in trusted.items if item.protected)


def _candidate_id(trusted: TrustedKnowledgeState, delta: KnowledgeDelta, sequence: int) -> str:
    """``cand-`` + digest(base, delta, the draft proposed state).

    ``delta.summary()`` names items by id, and an item id does not cover its
    lineage or validation: two spawns at one sequence from different verdicts
    can add the same motif with different evidence, which are different proposed
    states. Digesting the draft state (items still carrying the pending lineage
    id) makes the id content-addressed without the circularity of digesting the
    final state, whose items name this very id. The sequence stays in because
    new items record it in their validation.
    """
    draft = trusted.with_changes(
        add=delta.added,
        remove=delta.removed,
        replace=delta.replaced,
        threshold=delta.threshold,
        threshold_lineage=delta.threshold_lineage,
        rehearsal=_rehearsal_after(trusted, delta),
    )
    payload = json.dumps(
        {
            "base": trusted.digest(),
            "delta": delta.summary(),
            "draft": draft.digest(),
            "sequence": sequence,
        },
        sort_keys=True,
    )
    return "cand-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def _stamp(item: KnowledgeItem, candidate_id: str) -> KnowledgeItem:
    """The same item (same id), its lineage naming the candidate that admits it."""
    return replace(item, lineage=replace(item.lineage, candidate_id=candidate_id))


def _rehearsal_after(
    trusted: TrustedKnowledgeState, delta: KnowledgeDelta
) -> tuple[EpisodeSkeleton, ...] | None:
    if not delta.rehearsal_added and not delta.rehearsal_removed:
        return None
    gone = set(delta.rehearsal_removed)
    kept = {e.episode_id: e for e in trusted.rehearsal if e.episode_id not in gone}
    for episode in delta.rehearsal_added:
        kept.setdefault(episode.episode_id, episode)
    return tuple(kept[key] for key in sorted(kept))


def _what(item: KnowledgeItem) -> tuple[object, ...]:
    return (
        item.kind,
        item.motif,
        item.anchor,
        item.pattern_key,
        item.weight,
        item.origin_verdict,
        item.procedure,
    )


def _check_consolidation(
    trusted: TrustedKnowledgeState, delta: KnowledgeDelta, resident: frozenset[str]
) -> None:
    by_id = {item.item_id: item for item in trusted.items}
    if delta.threshold is not None or delta.active_context is not None:
        raise ContractError("consolidation may not move the threshold or the active context")
    for item in delta.added:
        parents = [by_id.get(p) for p in item.lineage.parent_item_ids]
        if not parents or any(p is None for p in parents):
            raise ContractError(f"merged item {item.item_id} must name resident parents")
        if any(_what(p)[:4] != _what(item)[:4] for p in parents if p is not None):
            raise ContractError(f"merged item {item.item_id} detects something its parents do not")
        union = frozenset().union(*(p.context_ids for p in parents if p is not None))
        if item.context_ids != union:
            raise ContractError(
                f"merged item {item.item_id} must cover exactly its parents' contexts"
            )
    for old_id, new in delta.replaced:
        old = by_id.get(old_id)
        if old is None or old.item_id != new.item_id or _what(old) != _what(new):
            raise ContractError(f"consolidation may change only the status of {old_id}")
    for episode in delta.rehearsal_added:
        if episode.episode_id not in resident:
            raise ContractError(
                f"rehearsal exemplar {episode.episode_id} is not a resident episode"
            )


def _consolidation_parents(
    trusted: TrustedKnowledgeState,
    delta: KnowledgeDelta,
    episodic: EpisodicMemory,
    lineage: KnowledgeLineageDAG,
) -> tuple[str, ...]:
    by_id = {item.item_id: item for item in trusted.items}
    touched = [by_id[i] for i in delta.removed if i in by_id] + [
        by_id[o] for o, _ in delta.replaced if o in by_id
    ]
    for item in delta.added:
        touched.extend(by_id[p] for p in item.lineage.parent_item_ids if p in by_id)
    names = {item.lineage.candidate_id for item in touched}
    names |= {v for e in delta.rehearsal_added if (v := episodic.verdict_of(e.episode_id))}
    names |= {e.episode_id for e in delta.rehearsal_added}
    return tuple(sorted(n for n in names if lineage.has(n)))


def _record_candidate(
    lineage: KnowledgeLineageDAG, candidate: EvolutionCandidate, parents: Sequence[str], reason: str
) -> None:
    """Record the CANDIDATE node; an identical candidate (same base, same delta) is one node.

    The DAG is append-only, and the candidate id is content-addressed, so
    re-spawning the same proposal names the node that already exists. A node
    with that id but a different proposed digest would be a collision, refused.
    """
    existing = lineage.node(candidate.candidate_id)
    if existing is not None:
        if existing.digest != candidate.proposed.digest():
            raise ContractError(
                f"candidate id {candidate.candidate_id} collides with a different state"
            )
        return
    evidence = sorted({d for i in candidate.delta.added for d in i.lineage.evidence_digests})
    lineage.update_lineage_dag(
        node=LineageNode(
            node_id=candidate.candidate_id,
            kind=NodeKind.CANDIDATE,
            digest=candidate.proposed.digest(),
            created_sequence=candidate.created_sequence,
            detail=reason,
        ),
        parents=tuple(parents),
        reason=reason,
        evidence=tuple(evidence[:MAX_ITEM_CAPSULE_REFS]),
        parent_versions=(candidate.base_digest,),
        transformation="helios.chamber:" + ",".join(sorted(k.value for k in candidate.kinds)),
    )


# --- one spawn call's workspace -----------------------------------------------------

_LABELS = (Verdict.MALICIOUS, Verdict.BENIGN)


def _unique(episodes: Iterable[EpisodeSkeleton]) -> tuple[EpisodeSkeleton, ...]:
    return tuple({e.episode_id: e for e in episodes}.values())


@dataclass(frozen=True, slots=True)
class _Change:
    component_id: str
    kind: CandidateKind
    item: KnowledgeItem | None  # incoming item (add or replace); None for a removal
    old_ids: tuple[str, ...]  # replaced first, then removed
    order: int
    terms: PlasticityTerms
    exemplar: EpisodeSkeleton | None = None


class _SpawnRun:
    """One call's scratch space. It reads the trusted value and discards itself."""

    def __init__(
        self,
        chamber: EvolutionChamber,
        trusted: TrustedKnowledgeState,
        verdicts: tuple[QuarantineVerdict, ...],
        sequence: int,
        trust: Mapping[str, float],
    ) -> None:
        self.chamber, self.trusted, self.sequence, self.trust = chamber, trusted, sequence, trust
        self.meter = WorkMeter(budget=chamber._work_budget)
        self.by_capsule = {v.capsule_id: v for v in verdicts}
        # A label verdict speaks for the episode it targets: that episode joins the
        # batch, and its label's source counts toward the episode's independence.
        self.speakers: dict[str, list[QuarantineVerdict]] = {}
        for verdict in verdicts:
            for episode_id in {verdict.capsule_id, verdict.target_episode or verdict.capsule_id}:
                self.speakers.setdefault(episode_id, []).append(verdict)
        resident = chamber._episodic.episodes(tier=EpisodeTier.LEARNING)
        batch = [e for e in resident if e.episode_id in self.speakers and e.verdict in _LABELS]
        self.holdout = tuple(e for e in batch if holdout_member(e.episode_id))
        self.train = tuple(e for e in batch if not holdout_member(e.episode_id))
        rehearsal = tuple(e for e in trusted.rehearsal if e.verdict in _LABELS)
        others = [e for e in resident if e.episode_id not in self.speakers]
        self.benign_pool = _unique(
            e for e in (*self.train, *others, *rehearsal) if e.verdict is Verdict.BENIGN
        )
        self.replay = _unique((*rehearsal, *self.train))
        self.rehearsal = rehearsal
        self.threshold = trusted.threshold()
        self.protected = _protected_ids(trusted)
        self.changes: list[_Change] = []
        self.results: list[CompetitionResult] = []
        self.mask_refusals = 0
        self._alerts: dict[str, tuple[float, float]] = {}
        self._variants: tuple[ReplayVariant, ...] | None = None

    # -- scoring primitives (every call charges the one meter) --------------------

    def _score(self, episode: EpisodeSkeleton) -> tuple[float, float]:
        """(full score, detector-only score D) of the trusted state, cached per episode."""
        if episode.episode_id not in self._alerts:
            result = score_session(
                self.trusted, episode.steps, context_id=episode.context_id, meter=self.meter
            )
            weights = {item.item_id: item.weight for item in self.trusted.detectors()}
            detected = max((weights.get(h, 0.0) for h in result.detector_hits), default=0.0)
            self._alerts[episode.episode_id] = (result.score, detected)
        return self._alerts[episode.episode_id]

    def trusted_alerts(self, episode: EpisodeSkeleton) -> bool:
        """The trusted state alerts on ``episode`` (detector or unexplained-anomaly path)."""
        return self._score(episode)[0] >= self.threshold

    def trusted_detects(self, episode: EpisodeSkeleton) -> bool:
        """A resident DETECTOR alone reaches the threshold on ``episode``.

        Distinct from ``trusted_alerts`` on purpose: the unexplained term U is
        anomaly evidence, never a verdict (spec §4.0), so an episode that alerts
        only because nothing explains it has not been *detected*.
        """
        return self._score(episode)[1] >= self.threshold

    def matched(self, item: KnowledgeItem, episodes: Iterable[EpisodeSkeleton]) -> frozenset[str]:
        hits = set()
        for episode in episodes:
            self.meter.charge(max(1, len(episode.steps)))
            if item_applies(item, episode.context_id) and match_motif(item.motif, episode.steps):
                hits.add(episode.episode_id)
        return frozenset(hits)

    def variants(self) -> tuple[ReplayVariant, ...]:
        if self._variants is None:
            positives = [e for e in self.rehearsal if e.verdict is Verdict.MALICIOUS]
            self._variants = tuple(
                v for e in positives for v in generate_counterfactual_replay(e, seed=self.sequence)
            )
        return self._variants

    def groups(self, episode_ids: Iterable[str]) -> int:
        return len(
            {v.trust.independence_group for e in episode_ids for v in self.speakers.get(e, ())}
        )

    def poison(self, episode_ids: Iterable[str]) -> float:
        return max(
            (v.suspicion.summary() for e in episode_ids for v in self.speakers.get(e, ())),
            default=0.0,
        )

    def evidence(self, episode_ids: Sequence[str]) -> tuple[str, ...]:
        digests: dict[str, None] = {}
        for episode in (e for e in (*self.train, *self.holdout) if e.episode_id in episode_ids):
            for step in episode.steps:
                digests.update(dict.fromkeys(step.evidence))
        if not digests:  # no step evidence survived: the admitted capsule's own digest
            digests.update(
                dict.fromkeys(
                    v.trust.content_digest for e in episode_ids for v in self.speakers.get(e, ())
                )
            )
        return tuple(digests)[:MAX_ITEM_CAPSULE_REFS]

    def build(
        self, admissions: tuple[CandidateAdmission, ...], capsules: tuple[ExperienceCapsuleV1, ...]
    ) -> EvolutionCandidate | None:
        self.symbolic()
        self.statistical(admissions)
        self.procedural(capsules)
        return _assemble(self)

    # -- step 4: SYMBOLIC -------------------------------------------------------------

    def symbolic(self) -> None:
        malicious = [e for e in self.train if e.verdict is Verdict.MALICIOUS]
        if not malicious:
            return
        known = {item.item_id for item in self.trusted.items}
        detectors = self.trusted.detectors()
        resident_sets = [self.matched(d, self.replay) for d in detectors]
        for found in induce_motifs(malicious, self.benign_pool, meter=self.meter):
            item = self.detector_item(found)
            if item.item_id in known:
                continue
            rivals = [
                d for d in detectors if overlaps(item, d, replay=self.replay, meter=self.meter)
            ]
            outcome, targets = self.compete(item, rivals)
            if outcome is CompetitionOutcome.REJECT_NEW:
                continue
            own = self.matched(item, self.replay)
            old = next((d for d in detectors if d.item_id == targets[0]), None) if targets else None
            terms = detector_terms(
                targets[0] if targets else f"new:{item.pattern_key}",
                own_matches=own,
                resident_matches=resident_sets,
                groups=self.groups(found.support),
                stability=self.trust.get(old.item_id, 1.0) if old else 1.0,
                utility=self.detector_utility(item),
                sole_coverage=self.sole_coverage(old, detectors) if old else 0.0,
                true_positives=found.true_positives,
                false_positives=found.false_positives,
                poison=self.poison(found.support),
                occupied=len(detectors),
                capacity=MAX_DETECTOR_ITEMS,
            )
            exemplar = next((e for e in self.train if e.episode_id == found.support[0]), None)
            self.propose(terms, CandidateKind.SYMBOLIC, item, targets, exemplar)

    def detector_item(self, found: MotifCandidate) -> KnowledgeItem:
        support = found.support[:MAX_ITEM_CAPSULE_REFS]
        epochs = sorted({e.epoch_id for e in self.train if e.episode_id in support})[
            :MAX_ITEM_EPOCHS
        ]
        return KnowledgeItem.build(
            kind=ItemKind.DETECTOR,
            context_ids={ALL_CONTEXTS},
            pattern_key=motif_pattern_key(found.motif),
            weight=found.weight,
            origin_verdict=Verdict.MALICIOUS,
            lineage=ItemLineage(_PENDING, support, self.evidence(support), ()),
            validation=_fresh_validation(
                len(support), found.false_positives, self.sequence, epochs
            ),
            motif=found.motif,
        )

    def compete(
        self, item: KnowledgeItem, rivals: Sequence[KnowledgeItem]
    ) -> tuple[CompetitionOutcome, tuple[str, ...]]:
        """REJECT_NEW if any rival rejects; else REPLACE every rival that lost; else COEXIST."""
        rule = compete_knowledge if self.chamber._competition else newest_wins
        results = [
            rule(
                item,
                old,
                replay=self.replay,
                variants=self.variants(),
                threshold=self.threshold,
                meter=self.meter,
            )
            for old in rivals
        ]
        self.results.extend(results)
        self.chamber._counters.competitions += len(results)
        self.chamber._counters.competition_non_replace += sum(
            r.outcome is not CompetitionOutcome.REPLACE for r in results
        )
        if any(r.outcome is CompetitionOutcome.REJECT_NEW for r in results):
            return CompetitionOutcome.REJECT_NEW, ()
        targets = tuple(r.old_item_id for r in results if r.outcome is CompetitionOutcome.REPLACE)
        return (
            (CompetitionOutcome.REPLACE, targets) if targets else (CompetitionOutcome.COEXIST, ())
        )

    def detector_utility(self, item: KnowledgeItem) -> float:
        """Holdout MALICIOUS no resident detector catches and ``item`` does (training if none).

        Recall gain is measured on the detection path, not on ``score >= threshold``:
        with no BASELINE resident the unexplained term alone reaches the default
        threshold on every session, so "gain over what already alerts" was
        identically 0.0 on the endurance corpus (35 of 35 proposed detectors,
        measured) and the field froze all detector learning for a reason that
        has nothing to do with the detector. An anomaly alert is not a detection.
        """
        pool = [e for e in self.holdout if e.verdict is Verdict.MALICIOUS]
        if not pool:
            self.chamber._counters.utility_fallbacks += 1
            pool = [e for e in self.train if e.verdict is Verdict.MALICIOUS]
        caught = self.matched(item, pool) if item.weight >= self.threshold else frozenset()
        gained = [e for e in pool if e.episode_id in caught and not self.trusted_detects(e)]
        return safe_share(len(gained), len(pool))

    def sole_coverage(self, old: KnowledgeItem, detectors: Sequence[KnowledgeItem]) -> float:
        """R: share of rehearsal positives ``old`` alone covers among trusted detectors."""
        positives = [e for e in self.rehearsal if e.verdict is Verdict.MALICIOUS]
        mine = self.matched(old, positives)
        others: set[str] = set()
        for detector in detectors:
            if detector.item_id != old.item_id:
                others |= self.matched(detector, positives)
        return safe_share(len(mine - others), len(positives))

    # -- steps 5 and 6: STATISTICAL, PROCEDURAL -------------------------------------

    def statistical(self, admissions: tuple[CandidateAdmission, ...]) -> None:
        known = {item.item_id for item in self.trusted.items}
        baselines = self.trusted.baselines()
        for admission in admissions:
            item = KnowledgeItem.build(
                kind=ItemKind.BASELINE,
                context_ids={admission.context_id},
                pattern_key=admission.pattern_key,
                weight=DEFAULT_CONSISTENCY_RADIUS,
                origin_verdict=Verdict.BENIGN,
                lineage=ItemLineage(
                    _PENDING,
                    admission.capsule_ids[:MAX_ITEM_CAPSULE_REFS],
                    admission.evidence_digests[:MAX_ITEM_CAPSULE_REFS],
                    (),
                ),
                validation=_fresh_validation(len(admission.capsule_ids), 0, self.sequence, ()),
                anchor=admission.anchor,
            )
            if item.item_id in known:
                continue
            known.add(item.item_id)
            covered = any(
                _explains(b, admission.pattern_key, admission.anchor, admission.context_id)
                for b in baselines
            )
            terms = baseline_terms(
                f"new:{item.pattern_key}",
                covered=covered,
                groups=admission.independent_groups,
                utility=self.baseline_utility(item),
                poison=self.poison(admission.capsule_ids),
                occupied=len(baselines),
                capacity=MAX_BASELINE_ITEMS,
            )
            self.propose(terms, CandidateKind.STATISTICAL, item, ())

    def baseline_utility(self, item: KnowledgeItem) -> float:
        """Share of alerting BENIGN episodes (its context) in which it explains an unexplained step.

        An upper bound on the FP reduction: explaining one step lowers the
        unexplained share, which may or may not cross the threshold. Measuring the
        exact drop would require a state with the item added, which a full store
        cannot build before capacity planning.
        """
        pool = [
            e
            for e in self.holdout
            if e.verdict is Verdict.BENIGN and item_applies(item, e.context_id)
        ]
        if not pool:
            self.chamber._counters.utility_fallbacks += 1
            pool = [
                e
                for e in self.train
                if e.verdict is Verdict.BENIGN and item_applies(item, e.context_id)
            ]
        alerting = [e for e in pool if self.trusted_alerts(e)]
        helped = 0
        for episode in alerting:
            self.meter.charge(max(1, len(episode.steps)))
            helped += any(
                not is_escalating(step)
                and _explains(
                    item, pattern_key(step.to_encoded()), step.meaning(), episode.context_id
                )
                for step in episode.steps
            )
        return safe_share(helped, len(pool))

    def procedural(self, capsules: tuple[ExperienceCapsuleV1, ...]) -> None:
        merged: dict[str, tuple[ProcedureRecord, list[str]]] = {}
        for capsule in capsules:
            for record in procedure_observations(capsule):
                key = procedure_key(record.operator_id, record.context_id)
                prior = merged.get(key)
                merged[key] = (
                    merge_procedure(prior[0], record) if prior else record,
                    [*(prior[1] if prior else []), capsule.capsule_id],
                )
        existing = {item.pattern_key: item for item in self.trusted.procedures()}
        for key in sorted(merged):
            record, sources = merged[key]
            old = existing.get(key)
            if old is not None and old.procedure is not None:
                record = merge_procedure(old.procedure, record)
            sources = sources[:MAX_ITEM_CAPSULE_REFS]
            item = KnowledgeItem.build(
                kind=ItemKind.PROCEDURE,
                context_ids={record.context_id},
                pattern_key=key,
                weight=safe_share(
                    record.verified,
                    record.verified + record.unverified + record.rolled_back + record.failed,
                ),
                origin_verdict=Verdict.BENIGN,
                lineage=ItemLineage(
                    _PENDING, tuple(sources), self.evidence(sources), (old.item_id,) if old else ()
                ),
                validation=_fresh_validation(len(sources), record.failed, self.sequence, ()),
                procedure=record,
            )
            terms = procedure_terms(
                old.item_id if old else f"new:{key}",
                groups=self.groups(sources),
                stability=self.trust.get(old.item_id, 1.0) if old else 1.0,
                poison=self.poison(sources),
                occupied=len(existing),
                capacity=MAX_PROCEDURE_ITEMS,
            )
            self.propose(terms, CandidateKind.PROCEDURAL, item, (old.item_id,) if old else ())

    def propose(
        self,
        terms: PlasticityTerms,
        kind: CandidateKind,
        item: KnowledgeItem,
        old_ids: tuple[str, ...],
        exemplar: EpisodeSkeleton | None = None,
    ) -> None:
        if any(c.component_id == terms.component_id for c in self.changes):
            return  # one change per component; the first proposal (deterministic order) wins
        self.changes.append(
            _Change(terms.component_id, kind, item, old_ids, len(self.changes), terms, exemplar)
        )


_PENDING = "cand-pending"  # provisional lineage id, replaced by the real one in _assemble


def _fresh_validation(
    validations: int, contradictions: int, sequence: int, epochs: Iterable[int]
) -> ItemValidation:
    return ItemValidation(
        validations=validations,
        recurrence=0,
        contradictions=contradictions,
        first_sequence=sequence,
        last_matched_sequence=sequence,
        epochs_seen=frozenset(epochs),
    )


def _explains(baseline: KnowledgeItem, key: str, meaning: Sequence[float], context_id: str) -> bool:
    """The scorer's explanation rule: same Stage 2 pattern key, inside the radius."""
    return (
        baseline.kind is ItemKind.BASELINE
        and baseline.pattern_key == key
        and item_applies(baseline, context_id)
        and meaning_distance(tuple(meaning), tuple(baseline.anchor)) <= baseline.weight
    )


def _mask_for(
    run: _SpawnRun, components: Sequence[str], field: PlasticityField
) -> tuple[PlasticityMask, PlasticityMask]:
    """(the mask this run uses, the uniform control at identical budgets)."""
    control = uniform_mask(components, protected=run.protected, now_sequence=run.sequence)
    if not run.chamber._plasticity_field:
        return control, control
    return generate_plasticity_mask(
        field, protected=run.protected, now_sequence=run.sequence
    ), control


def _cost(changes: Iterable[_Change]) -> int:
    """Item mutations: one per change, plus one removal per extra replaced item."""
    return sum(1 + max(0, len(c.old_ids) - 1) for c in changes)


def _permitted(mask: PlasticityMask, change: _Change, sequence: int) -> bool:
    """The mask permits the component and every item it would replace or remove."""
    touched = (change.component_id, *change.old_ids)
    return all(mask.permits(cid, now_sequence=sequence) for cid in touched)


def _choose(
    changes: Sequence[_Change], mask: PlasticityMask, sequence: int, *, by_plasticity: bool
) -> tuple[list[_Change], int]:
    """Drop forbidden changes, keep the highest-priority ones within budget; (kept, refusals)."""
    permitted = [c for c in changes if _permitted(mask, c, sequence)]
    refusals = len(changes) - len(permitted)
    if by_plasticity:
        permitted.sort(key=lambda c: (-plasticity(c.terms), c.order))
    kept: list[_Change] = []
    for change in permitted:
        if _cost((*kept, change)) <= mask.max_item_mutations:
            kept.append(change)
        else:
            refusals += 1
    return kept, refusals


def _select(run: _SpawnRun, mask: PlasticityMask) -> list[_Change]:
    """Step 8, and HEL-F08's firing count at the level of the outcome.

    The firing count is the number of changes the uniform control *would have
    kept* (same budget, same order rule it uses) that the field froze. Counting
    every permission difference instead would credit the field with freezes the
    budget made moot: on the test fixture the field froze 6 proposals and the
    candidate was identical to the control's (measured), which is INERT.
    """
    field_on = run.chamber._plasticity_field
    kept, refusals = _choose(run.changes, mask, run.sequence, by_plasticity=field_on)
    run.mask_refusals += refusals
    if field_on:
        components = {cid for c in run.changes for cid in (c.component_id, *c.old_ids)}
        control = uniform_mask(components, protected=run.protected, now_sequence=run.sequence)
        uniform_kept, _ = _choose(run.changes, control, run.sequence, by_plasticity=False)
        # Budget cannot be the reason: uniform_kept already fits the identical budget.
        frozen = [c for c in uniform_kept if not _permitted(mask, c, run.sequence)]
        run.chamber._counters.field_only_freezes += len(frozen)
        # The field's other effect: its plasticity priority spends the budget on
        # different, permitted changes than the control's proposal order would.
        chosen = {c.order for c in kept}
        run.chamber._counters.field_displaced += sum(
            c.order not in chosen for c in uniform_kept if c not in frozen
        )
    return kept


def _make_room(
    run: _SpawnRun, kept: list[_Change], mask: PlasticityMask
) -> tuple[list[_Change], tuple[str, ...]]:
    """Step 9: ask MNEMOSYNE for evictions when a cap would be exceeded; never drop silently."""
    caps = {
        ItemKind.DETECTOR: MAX_DETECTOR_ITEMS,
        ItemKind.BASELINE: MAX_BASELINE_ITEMS,
        ItemKind.PROCEDURE: MAX_PROCEDURE_ITEMS,
    }
    counts = {kind: sum(item.kind is kind for item in run.trusted.items) for kind in caps}

    def needed(changes: Sequence[_Change]) -> dict[ItemKind, int]:
        after = dict(counts)
        for c in changes:
            if c.item is not None:
                after[c.item.kind] += 1 - len(c.old_ids)
        return {kind: after[kind] - caps[kind] for kind in caps if after[kind] > caps[kind]}

    want = needed(kept)
    if not want:
        return kept, ()
    touched = {oid for c in kept for oid in c.old_ids}
    room = run.chamber._consolidator.plan_room(run.trusted, want, now_sequence=run.sequence)
    by_id = {item.item_id: item for item in run.trusted.items}
    pool = [i for i in room.removed if i in by_id and i not in touched and i not in run.protected]
    while True:
        want = needed(kept)
        chosen = [
            i for kind, n in want.items() for i in [p for p in pool if by_id[p].kind is kind][:n]
        ]
        short = [kind for kind, n in want.items() if sum(by_id[p].kind is kind for p in pool) < n]
        over = _cost(kept) + len(chosen) > mask.max_item_mutations
        if not short and not over:
            return kept, tuple(chosen)
        victim = next(
            (
                c
                for c in reversed(kept)
                if c.item is not None and not c.old_ids and (not short or c.item.kind in short)
            ),
            None,
        )
        if victim is None:  # nothing left to refuse: keep only changes that need no room
            return [c for c in kept if c.old_ids], ()
        kept.remove(victim)
        if short:
            run.chamber._counters.capacity_refusals += 1
        else:
            run.mask_refusals += 1


def _calibrate(
    run: _SpawnRun, state: TrustedKnowledgeState
) -> tuple[float | None, PlasticityTerms | None, tuple[EpisodeSkeleton, ...]]:
    """Step 7: raise the threshold to meet FPR_BUDGET on rehearsal + TRAINING negatives.

    Raise-only by design: a lower threshold claims no FP reduction, so G3 would
    refuse it, and detection-side sensitivity is the detectors' job.

    Never on the holdout (review F5): G3 scores ``fp_reduction`` on the holdout, and a
    threshold fitted to those same episodes passes it by construction. The third value is
    the basis the threshold's lineage cites: the negatives the old threshold alerted on.
    """
    held_out = {e.episode_id for e in run.holdout}
    negatives = _unique(e for e in (*run.rehearsal, *run.train)
                        if e.verdict is Verdict.BENIGN and e.episode_id not in held_out)
    if not negatives:
        return None, None, ()
    scored = [
        (score_session(state, e.steps, context_id=e.context_id, meter=run.meter).score, e)
        for e in negatives
    ]
    scores = sorted((score for score, _ in scored), reverse=True)
    current = state.threshold()
    allowed = int(FPR_BUDGET * len(scores))
    if sum(s >= current for s in scores) <= allowed:
        return None, None, ()
    basis = tuple(sorted((e for score, e in scored if score >= current),
                         key=lambda e: e.episode_id))[:MAX_ITEM_CAPSULE_REFS]
    target = min(1.0, round(scores[allowed], STATE_FLOAT_DECIMALS) + 10.0**-STATE_FLOAT_DECIMALS)
    positives = [e for e in run.rehearsal if e.verdict is Verdict.MALICIOUS]
    lost = sum(
        current <= s < target
        for s in (
            score_session(state, e.steps, context_id=e.context_id, meter=run.meter).score
            for e in positives
        )
    )
    terms = threshold_terms(
        fp_before=sum(s >= current for s in scores),
        fp_after=sum(s >= target for s in scores),
        negatives=len(scores),
        positives_lost=lost,
        positives=len(positives),
    )
    return target, terms, basis


def _threshold_basis(
    basis: Sequence[EpisodeSkeleton],
) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    """(capsule ids, evidence digests) a learned threshold cites; ``None`` = no provenance."""
    evidence = tuple(dict.fromkeys(d for e in basis for s in e.steps for d in s.evidence))
    if not basis or not evidence:
        return None
    return tuple(e.episode_id for e in basis), evidence[:MAX_ITEM_CAPSULE_REFS]


def _final_mask(
    run: _SpawnRun,
    components: Sequence[str],
    evictions: Sequence[str],
    threshold_terms: PlasticityTerms | None,
) -> tuple[PlasticityMask, PlasticityMask]:
    """(the mask the candidate carries, the uniform control): every proposed
    component, the evictions made for them (adaptable unless frozen), and the
    threshold; counts every permission the field withheld that uniform granted."""
    extra = [threshold_terms] if threshold_terms else []
    field = compute_plasticity_field([*(c.terms for c in run.changes), *extra])
    everything = [*components, *evictions, *(t.component_id for t in extra)]
    mask, control = _mask_for(run, everything, field)
    mask = replace(mask, adaptable=mask.adaptable | (frozenset(evictions) - mask.frozen_core))
    run.chamber._counters.field_permission_differences += field_only_freezes(
        mask, control, everything, now_sequence=run.sequence
    )
    return mask, control


def _clip_threshold(
    run: _SpawnRun, target: float | None, mask: PlasticityMask, control: PlasticityMask
) -> float | None:
    """The calibrated threshold the mask allows, or ``None``; a refusal is counted."""
    if target is None:
        return None
    budget = mask.threshold_budget(now_sequence=run.sequence)
    if budget > 0.0:
        return min(target, run.threshold + budget)
    run.mask_refusals += 1
    # The calibration the control would have made and the field refused.
    run.chamber._counters.field_only_freezes += int(
        run.chamber._plasticity_field and control.threshold_budget(now_sequence=run.sequence) > 0.0
    )
    return None


def _assemble(run: _SpawnRun) -> EvolutionCandidate | None:
    """Steps 8-11: mask, capacity, calibration, the proposed value, its lineage node."""
    components = [c.component_id for c in run.changes] + [o for c in run.changes for o in c.old_ids]
    mask, _ = _mask_for(run, components, compute_plasticity_field([c.terms for c in run.changes]))
    kept, evictions = _make_room(run, _select(run, mask), mask)
    target, threshold_terms, basis = _calibrate(
        run, _stage(run.trusted, kept, evictions, _PENDING))
    provenance = _threshold_basis(basis)
    if provenance is None:  # a threshold that cannot name its evidence is not learned
        target, threshold_terms = None, None
    mask, control = _final_mask(run, components, evictions, threshold_terms)
    threshold = _clip_threshold(run, target, mask, control)
    run.chamber._counters.mask_refusals += run.mask_refusals
    if not kept and not evictions and threshold is None:
        return None
    exemplars = [c.exemplar for c in kept if c.exemplar is not None]
    room = max(0, MAX_REHEARSAL_EXEMPLARS - len(run.trusted.rehearsal))
    draft = _delta(kept, evictions, threshold, exemplars[:room], _PENDING, provenance)
    candidate_id = _candidate_id(run.trusted, draft, run.sequence)
    delta = _delta(kept, evictions, threshold, exemplars[:room], candidate_id, provenance)
    proposed = run.trusted.with_changes(
        add=delta.added,
        remove=delta.removed,
        replace=delta.replaced,
        threshold=delta.threshold,
        threshold_lineage=delta.threshold_lineage,
        rehearsal=_rehearsal_after(run.trusted, delta),
    )
    kinds = {c.kind for c in kept} | (
        {CandidateKind.CALIBRATION} if threshold is not None else set()
    )
    verdict_ids = tuple(sorted(v.verdict_id for v in run.by_capsule.values()))
    candidate = EvolutionCandidate(
        candidate_id=candidate_id,
        kinds=frozenset(kinds),
        base_digest=run.trusted.digest(),
        proposed=proposed,
        delta=delta,
        verdict_ids=verdict_ids,
        capsule_ids=tuple(sorted(run.by_capsule)),
        mask=mask,
        competition=tuple(run.results),
        holdout_episode_ids=tuple(sorted(e.episode_id for e in run.holdout)),
        mask_refusals=run.mask_refusals,
        work_units=run.meter.spent,
        created_sequence=run.sequence,
    )
    _record_candidate(
        run.chamber._consolidator.lineage, candidate, verdict_ids, "spawn_evolution_candidate"
    )
    return candidate


def _stage(
    trusted: TrustedKnowledgeState,
    kept: Sequence[_Change],
    evictions: Sequence[str],
    candidate_id: str,
) -> TrustedKnowledgeState:
    """The item changes applied, threshold untouched: what calibration is fitted on."""
    delta = _delta(kept, evictions, None, (), candidate_id)
    return trusted.with_changes(add=delta.added, remove=delta.removed, replace=delta.replaced)


def _delta(
    kept: Sequence[_Change],
    evictions: Sequence[str],
    threshold: float | None,
    exemplars: Sequence[EpisodeSkeleton],
    candidate_id: str,
    threshold_basis: tuple[tuple[str, ...], tuple[str, ...]] | None = None,
) -> KnowledgeDelta:
    added: list[KnowledgeItem] = []
    replaced: list[tuple[str, KnowledgeItem]] = []
    removed: list[str] = list(evictions)
    for change in kept:
        if change.item is None:
            removed.extend(change.old_ids)
            continue
        item = _stamp(change.item, candidate_id)
        if change.old_ids:
            item = replace(
                item,
                lineage=replace(item.lineage, parent_item_ids=tuple(sorted(set(change.old_ids)))),
            )
            replaced.append((change.old_ids[0], item))
            removed.extend(change.old_ids[1:])
        else:
            added.append(item)
    lineage = None
    if threshold is not None:
        if threshold_basis is None:
            raise ContractError("a threshold change needs the basis its lineage cites")
        lineage = ItemLineage(candidate_id, threshold_basis[0], threshold_basis[1], ())
    return KnowledgeDelta(
        added=tuple(added),
        removed=tuple(dict.fromkeys(removed)),
        replaced=tuple(replaced),
        threshold=threshold,
        rehearsal_added=_unique(exemplars),
        threshold_lineage=lineage,
    )
