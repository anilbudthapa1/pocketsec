"""HEL-F15 / HEL-F25 — MNEMOSYNE: memory maintenance that proposes, never installs.

Architecture §18 lists what consolidation does (deduplicate, merge, split, age,
fossilise, retire, select rehearsal exemplars, schedule). Every one of those that
would change **trusted** state is returned as a ``CONSOLIDATION`` candidate built
by the chamber, and reaches the trusted state only through the conservation gate,
shadow, canary and the one controller like any other candidate. This module has
no reference to ``TrustedMind`` and no path that writes trusted state.

What it refuses to do:

* **Retire without a fossil.** Removal is irreversible in the live state, so an
  item is retired only after a ``RETIREMENT`` fossil is created *and* re-loaded
  from the store with the item inside it. A fossil store that cannot take the
  fossil means no retirement, counted — never a removal on faith.
* **Touch protected items.** Protected items are never melted, retired, merged
  or evicted; the chamber's mask would refuse it anyway, and this module does
  not propose it.
* **Block detection.** When ``consolidation_allowed`` is false (architecture §40)
  the call returns ``deferred=True`` with the reasons, queues bounded metadata,
  and does no expensive work. Scoring never waits on consolidation.
* **Split.** ``ItemValidation`` carries no per-context statistic, so context
  divergence cannot be observed; ``split`` is always empty and reported INERT
  rather than simulated.
* **Merge episodes.** ``EpisodicMemory`` exposes no merge or removal operation, so
  semantically equivalent episodes are *counted* (``deduplicated``) and excluded
  from rehearsal selection, not deleted.

Simple controls (Rule C): ``half_life=False`` ranks by least-recently-matched and
retires at the unmodulated half-life's age cutoff (LRU); ``value_aware_rehearsal=False``
selects exemplars by reservoir sampling at the **same** byte budget (ADR-0128
precedent). Firing counts are in ``stats()``.
"""

from __future__ import annotations

import json
import math
import random
from collections import deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace

from pocketsec.stage0.contracts.common import ContractError, digest_of_bytes
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage6.chamber.evolution import EvolutionCandidate, KnowledgeDelta
from pocketsec.stage6.fossils.lineage import KnowledgeLineageDAG
from pocketsec.stage6.fossils.store import FossilReason, FossilStore
from pocketsec.stage6.memory.episodic import EpisodeSkeleton, EpisodeTier, EpisodicMemory
from pocketsec.stage6.memory.half_life import (
    HALF_LIFE_H0,
    RETIRE_TRUST_FLOOR,
    EpistemicHalfLife,
    trust_ranking,
)
from pocketsec.stage6.memory.semantic import (
    ALL_CONTEXTS,
    MAX_BASELINE_ITEMS,
    MAX_DETECTOR_ITEMS,
    MAX_ITEM_CAPSULE_REFS,
    MAX_ITEM_EPOCHS,
    MAX_PROCEDURE_ITEMS,
    MAX_REHEARSAL_EXEMPLARS,
    ItemKind,
    ItemLineage,
    ItemStatus,
    ItemValidation,
    KnowledgeItem,
    TrustedKnowledgeState,
    match_motif,
    score_session,
)
from pocketsec.stage6.plasticity.masks import MAX_ITEM_MUTATIONS
from pocketsec.stage6.resources import (
    CONSOLIDATION_MAX_CPU_LOAD,
    CONSOLIDATION_MAX_MEMORY_PRESSURE,
    CONSOLIDATION_MAX_URGENCY,
    CONSOLIDATION_MIN_DISK_FREE_BYTES,
    ResourceSnapshot,
    WorkMeter,
)

__all__ = [
    "CONSOLIDATION_PERIOD",
    "DEFAULT_REHEARSAL_BUDGET_BYTES",
    "MAX_DEFERRED_RECORDS",
    "MAX_DORMANT_SEQUENCES",
    "Consolidation",
    "ConsolidatorStats",
    "DeferredRecord",
    "MnemosyneConsolidator",
    "consolidation_allowed",
]

#: Offered capsules between consolidation runs.
CONSOLIDATION_PERIOD: int = 64
#: A DORMANT item must have gone unmatched this long before it may be retired.
MAX_DORMANT_SEQUENCES: int = 8192
#: Rehearsal byte budget when the caller names none. Chosen: the middle point of
#: the endurance sweep ``REPLAY_BUDGETS_BYTES`` (spec §4.21); not measured.
DEFAULT_REHEARSAL_BUDGET_BYTES: int = 65536
#: Deferred-consolidation metadata kept; the oldest is dropped and counted.
MAX_DEFERRED_RECORDS: int = 64

_CAPS: Mapping[ItemKind, int] = {
    ItemKind.DETECTOR: MAX_DETECTOR_ITEMS,
    ItemKind.BASELINE: MAX_BASELINE_ITEMS,
    ItemKind.PROCEDURE: MAX_PROCEDURE_ITEMS,
}
#: The age at which an *unmodulated* half-life (H = H0) falls below the retire
#: floor: the LRU control uses this one cutoff for every item.
_LRU_AGE_CUTOFF: float = HALF_LIFE_H0 * math.log2(1.0 / RETIRE_TRUST_FLOOR)

Issuer = Callable[..., EvolutionCandidate | None]


def consolidation_allowed(snapshot: ResourceSnapshot) -> tuple[bool, tuple[str, ...]]:
    """Architecture §40: every condition must hold; the reasons name each that fails."""
    reasons: list[str] = [f"unmeasured:{name}" for name in snapshot.unmeasured]
    if snapshot.memory_pressure >= CONSOLIDATION_MAX_MEMORY_PRESSURE:
        reasons.append(
            f"memory_pressure {snapshot.memory_pressure:.3f} >= {CONSOLIDATION_MAX_MEMORY_PRESSURE}"
        )
    if snapshot.cpu_load >= CONSOLIDATION_MAX_CPU_LOAD:
        reasons.append(f"cpu_load {snapshot.cpu_load:.3f} >= {CONSOLIDATION_MAX_CPU_LOAD}")
    if snapshot.incident_urgency >= CONSOLIDATION_MAX_URGENCY:
        reasons.append(
            f"incident_urgency {snapshot.incident_urgency:.3f} >= {CONSOLIDATION_MAX_URGENCY}"
        )
    if snapshot.disk_free_bytes < CONSOLIDATION_MIN_DISK_FREE_BYTES:
        reasons.append(
            f"disk_free_bytes {snapshot.disk_free_bytes} < {CONSOLIDATION_MIN_DISK_FREE_BYTES}"
        )
    if not snapshot.thermal_ok:
        reasons.append("thermal policy refuses")
    return not reasons, tuple(reasons)


@dataclass(frozen=True, slots=True)
class Consolidation:
    """Architecture §18, every bullet a field. Trusted changes are only in ``candidate``."""

    candidate: EvolutionCandidate | None
    deduplicated: int  # equivalent episodes excluded from rehearsal selection (untrusted side)
    merged: tuple[tuple[str, str], ...]  # detector/baseline pairs merged (in the candidate)
    split: tuple[str, ...]  # always (): no per-context statistic exists to detect divergence
    aged: tuple[EpistemicHalfLife, ...]
    dormant_evicted: tuple[
        str, ...
    ]  # dormant-context items fossilised then removed (in the candidate)
    retired: tuple[str, ...]
    rehearsal_selected: tuple[str, ...]
    fossil_due: bool
    deferred: bool
    deferred_reasons: tuple[str, ...]
    work_units: int


@dataclass(frozen=True, slots=True)
class DeferredRecord:
    """The bounded metadata a deferred consolidation leaves behind."""

    sequence: int
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ConsolidatorStats:
    runs: int
    not_due: int
    deferred: int
    deferred_dropped: int
    candidates: int
    retire_refused_no_fossil: int
    half_life_decisions_differing_from_lru: int  # HEL-F07/F25 firing count
    rehearsal_differing_from_reservoir: int  # HEL-F15 firing count
    mutations_postponed: int  # over the per-candidate mask budget, left for the next run


@dataclass
class _Counters:
    runs: int = 0
    not_due: int = 0
    deferred: int = 0
    deferred_dropped: int = 0
    candidates: int = 0
    retire_refused_no_fossil: int = 0
    half_life_decisions_differing_from_lru: int = 0
    rehearsal_differing_from_reservoir: int = 0
    mutations_postponed: int = 0


def _signature(episode: EpisodeSkeleton) -> tuple[object, ...]:
    """Semantic equivalence for deduplication: verdict plus every step's meaning bits."""
    steps = tuple(
        (s.actor_slot, s.relation, s.object_property_mask, s.state_delta_mask)
        for s in episode.steps
    )
    return (episode.verdict, episode.context_id, steps)


def _applies_now(item: KnowledgeItem, active_context: str) -> bool:
    return item.status is ItemStatus.ACTIVE and (
        ALL_CONTEXTS in item.context_ids or active_context in item.context_ids
    )


class MnemosyneConsolidator:
    """HEL-F15. Proposes CONSOLIDATION candidates through the chamber it is bound to."""

    def __init__(
        self,
        *,
        fossils: FossilStore,
        lineage: KnowledgeLineageDAG,
        value_aware_rehearsal: bool = True,
        half_life: bool = True,
        period: int = CONSOLIDATION_PERIOD,
        rehearsal_budget_bytes: int = DEFAULT_REHEARSAL_BUDGET_BYTES,
        seed: int = 0,
    ) -> None:
        if period < 1 or rehearsal_budget_bytes < 0:
            raise ContractError("period must be >= 1 and the rehearsal budget non-negative")
        self._fossils = fossils
        self._lineage = lineage
        self._value_aware = value_aware_rehearsal
        self._half_life = half_life
        self._period = period
        self._rehearsal_budget = rehearsal_budget_bytes
        self._seed = seed
        self._issuer: Issuer | None = None
        self._next_due = 0
        self._deferred: deque[DeferredRecord] = deque(maxlen=MAX_DEFERRED_RECORDS)
        self._counters = _Counters()

    @property
    def lineage(self) -> KnowledgeLineageDAG:
        return self._lineage

    @property
    def fossils(self) -> FossilStore:
        return self._fossils

    def bind_candidate_issuer(self, issuer: Issuer) -> None:
        """Called once by ``EvolutionChamber.__init__``; a second bind is refused."""
        if self._issuer is not None:
            raise ContractError("the consolidator is already bound to a chamber")
        self._issuer = issuer

    def stats(self) -> ConsolidatorStats:
        return ConsolidatorStats(**vars(self._counters))

    def deferred_records(self) -> tuple[DeferredRecord, ...]:
        return tuple(self._deferred)

    def memory_bytes(self) -> int:
        return sum(64 + sum(len(r) for r in record.reasons) for record in self._deferred)

    # -- HEL-F15 ----------------------------------------------------------------------

    def consolidate_memory(
        self,
        *,
        trusted: TrustedKnowledgeState,
        episodic: EpisodicMemory,
        snapshot: ResourceSnapshot,
        now_sequence: int,
        epochs_since_match: Mapping[str, int],
    ) -> Consolidation:
        """One maintenance pass, or a deferral. The result's candidate is a proposal only."""
        gated = self._gate(now_sequence, snapshot)
        if gated is not None:
            return gated
        meter = WorkMeter()
        aged = trust_ranking(
            trusted.items, now_sequence=now_sequence, epochs_since_match=epochs_since_match
        )
        lifecycle = self.melt_or_retire_knowledge(trusted, rankings=aged, now_sequence=now_sequence)
        merges, merged_pairs = _merge_proposals(trusted)
        dormant = self._dormant_evictions(trusted, now_sequence)
        selected, deduplicated = self._select(episodic, trusted, self._rehearsal_budget, meter)
        current = {e.episode_id for e in trusted.rehearsal}
        chosen = {e.episode_id for e in selected}
        delta = self._bounded_delta(
            (*lifecycle.removed, *dormant),
            lifecycle.replaced,
            merges.added,
            (
                tuple(e for e in selected if e.episode_id not in current),
                tuple(sorted(current - chosen)),
            ),
        )
        removed = set(delta.removed)
        return Consolidation(
            candidate=self._propose(trusted, delta, now_sequence),
            deduplicated=deduplicated,
            merged=tuple(p for p in merged_pairs if p[0] in removed),
            split=(),
            aged=aged,
            dormant_evicted=tuple(i for i in dormant if i in removed),
            retired=tuple(i for i in lifecycle.removed if i in removed),
            rehearsal_selected=tuple(sorted(chosen)),
            fossil_due=self._fossils.get(trusted.digest()) is None,
            deferred=False,
            deferred_reasons=(),
            work_units=meter.spent,
        )

    def _gate(self, now_sequence: int, snapshot: ResourceSnapshot) -> Consolidation | None:
        """Not due, or deferred by §40 (bounded metadata queued); ``None`` means run now."""
        if now_sequence < self._next_due:
            self._counters.not_due += 1
            return _empty(deferred=False, reasons=(f"not_due:{self._next_due}",))
        allowed, reasons = consolidation_allowed(snapshot)
        if not allowed:
            self._counters.deferred += 1
            if len(self._deferred) == self._deferred.maxlen:
                self._counters.deferred_dropped += 1
            self._deferred.append(DeferredRecord(now_sequence, reasons))
            return _empty(deferred=True, reasons=reasons)
        self._counters.runs += 1
        self._next_due = now_sequence + self._period
        return None

    def _propose(
        self, trusted: TrustedKnowledgeState, delta: KnowledgeDelta, now_sequence: int
    ) -> EvolutionCandidate | None:
        """Hand a non-empty delta to the bound chamber; this module never applies it."""
        if delta.is_empty():
            return None
        if self._issuer is None:
            raise ContractError(
                "the consolidator has no chamber bound; it cannot propose trusted changes"
            )
        candidate = self._issuer(
            trusted=trusted, delta=delta, sequence=now_sequence, reason="consolidate_memory"
        )
        self._counters.candidates += candidate is not None
        return candidate

    def _bounded_delta(
        self,
        removals: Sequence[str],
        melts: Sequence[tuple[str, KnowledgeItem]],
        merges: Sequence[KnowledgeItem],
        rehearsal: tuple[tuple[EpisodeSkeleton, ...], tuple[str, ...]],
    ) -> KnowledgeDelta:
        """Keep the per-candidate mutation budget; the rest waits for the next run (counted).

        Priority: retirements and evictions, then melts, then merges (a merge
        costs one addition plus a removal per parent, and is the least urgent).
        """
        budget = MAX_ITEM_MUTATIONS
        removed = list(dict.fromkeys(removals))[:budget]
        budget -= len(removed)
        replaced = [(old, new) for old, new in melts if old not in removed][:budget]
        budget -= len(replaced)
        added: list[KnowledgeItem] = []
        busy = set(removed) | {old for old, _ in replaced}
        for item in merges:
            parents = item.lineage.parent_item_ids
            if 1 + len(parents) <= budget and not busy & set(parents):
                added.append(item)
                removed.extend(parents)
                busy |= set(parents)
                budget -= 1 + len(parents)
        wanted = len(set(removals)) + len(melts) + len(merges)
        kept_removals = len(removed) - sum(len(i.lineage.parent_item_ids) for i in added)
        self._counters.mutations_postponed += wanted - kept_removals - len(replaced) - len(added)
        return KnowledgeDelta(
            added=tuple(added),
            removed=tuple(removed),
            replaced=tuple(replaced),
            rehearsal_added=rehearsal[0],
            rehearsal_removed=rehearsal[1],
        )

    # -- HEL-F25 ----------------------------------------------------------------------

    def melt_or_retire_knowledge(
        self,
        trusted: TrustedKnowledgeState,
        *,
        rankings: Sequence[EpistemicHalfLife],
        now_sequence: int,
    ) -> KnowledgeDelta:
        """Melt ACTIVE -> DORMANT below the trust floor; retire DORMANT only behind a fossil."""
        by_id = {item.item_id: item for item in trusted.items}
        melts: list[tuple[str, KnowledgeItem]] = []
        retires: list[str] = []
        for ranked in sorted(rankings, key=lambda h: (h.trust, h.item_id)):
            item = by_id.get(ranked.item_id)
            if item is None or item.protected or item.kind is ItemKind.THRESHOLD:
                continue
            decision = self._lifecycle(item, ranked, modulated=self._half_life)
            if decision != self._lifecycle(item, ranked, modulated=not self._half_life):
                self._counters.half_life_decisions_differing_from_lru += 1
            if decision == "melt":
                melts.append((item.item_id, replace(item, status=ItemStatus.DORMANT)))
            elif decision == "retire":
                retires.append(item.item_id)
        if retires and not self._fossil_holds(
            trusted, retires, FossilReason.RETIREMENT, now_sequence
        ):
            self._counters.retire_refused_no_fossil += len(retires)
            retires = []
        return KnowledgeDelta(removed=tuple(retires), replaced=tuple(melts))

    @staticmethod
    def _lifecycle(item: KnowledgeItem, ranked: EpistemicHalfLife, *, modulated: bool) -> str:
        """ "melt", "retire" or "keep" under the half-life (modulated) or the LRU control."""
        weak = ranked.trust < RETIRE_TRUST_FLOOR if modulated else ranked.age > _LRU_AGE_CUTOFF
        if not weak:
            return "keep"
        if item.status is ItemStatus.ACTIVE:
            return "melt"
        return "retire" if ranked.age > MAX_DORMANT_SEQUENCES else "keep"

    # -- rehearsal selection -------------------------------------------------------------

    def select_rehearsal_exemplars(
        self, episodic: EpisodicMemory, *, trusted: TrustedKnowledgeState, budget_bytes: int
    ) -> tuple[EpisodeSkeleton, ...]:
        """Value-aware selection (or reservoir sampling as the control) at ``budget_bytes``."""
        selected, _ = self._select(episodic, trusted, budget_bytes, WorkMeter())
        return selected

    def _select(
        self,
        episodic: EpisodicMemory,
        trusted: TrustedKnowledgeState,
        budget_bytes: int,
        meter: WorkMeter,
    ) -> tuple[tuple[EpisodeSkeleton, ...], int]:
        pool = _pool(episodic, trusted)
        reservoir = _reservoir(pool, budget_bytes, self._seed)
        if not self._value_aware:
            return reservoir, 0
        chosen, deduplicated = _value_aware(pool, trusted, budget_bytes, meter)
        ids = {e.episode_id for e in reservoir}
        self._counters.rehearsal_differing_from_reservoir += sum(
            e.episode_id not in ids for e in chosen
        )
        return chosen, deduplicated

    # -- capacity -------------------------------------------------------------------

    def plan_room(
        self,
        trusted: TrustedKnowledgeState,
        needed: Mapping[ItemKind, int],
        *,
        now_sequence: int | None = None,
    ) -> KnowledgeDelta:
        """Evictions that make room: dormant-context items first, then lowest trust (or LRU).

        Every proposed victim is held by a verified fossil before it is named;
        if no fossil can hold them, nothing is proposed (the caller then refuses
        its additions, counted) — never an unfossilised eviction.
        """
        now = (
            now_sequence
            if now_sequence is not None
            else max((i.validation.last_matched_sequence for i in trusted.items), default=0)
        )
        trust = {
            h.item_id: h.trust
            for h in trust_ranking(trusted.items, now_sequence=now, epochs_since_match={})
        }
        victims: list[str] = []
        all_dormant = True
        for kind in sorted(needed, key=lambda k: k.value):
            count = needed[kind]
            if count <= 0:
                continue
            pool = [
                i
                for i in trusted.items
                if i.kind is kind and not i.protected and kind is not ItemKind.THRESHOLD
            ]
            chosen = _victims(pool, trusted.active_context, count, trust, modulated=self._half_life)
            control = _victims(pool, trusted.active_context, count, trust, modulated=False)
            if self._half_life:
                self._counters.half_life_decisions_differing_from_lru += len(
                    set(chosen) - set(control)
                )
            all_dormant &= all(
                not _applies_now(i, trusted.active_context) for i in pool if i.item_id in chosen
            )
            victims.extend(chosen)
        if not victims:
            return KnowledgeDelta()
        reason = FossilReason.CONTEXT_DORMANCY if all_dormant else FossilReason.CONSOLIDATION
        if not self._fossil_holds(trusted, victims, reason, now):
            return KnowledgeDelta()
        return KnowledgeDelta(removed=tuple(victims))

    def _dormant_evictions(
        self, trusted: TrustedKnowledgeState, now_sequence: int
    ) -> tuple[str, ...]:
        """At a full store, fossilise-and-remove one dormant-context item to keep headroom."""
        full = {
            kind: 1
            for kind, cap in _CAPS.items()
            if sum(i.kind is kind for i in trusted.items) >= cap
        }
        if not full:
            return ()
        by_id = {item.item_id: item for item in trusted.items}
        delta = self.plan_room(trusted, full, now_sequence=now_sequence)
        return tuple(i for i in delta.removed if not _applies_now(by_id[i], trusted.active_context))

    def _fossil_holds(
        self,
        trusted: TrustedKnowledgeState,
        item_ids: Iterable[str],
        reason: FossilReason,
        sequence: int,
    ) -> bool:
        """Create (or find) a fossil of ``trusted``; prove by re-loading that it holds the items."""
        digest = trusted.digest()
        try:
            if self._fossils.get(digest) is None:
                self._fossils.create_fossil(
                    trusted,
                    reason=reason,
                    fingerprint=_fingerprint(trusted),
                    epoch_range=_epoch_range(trusted),
                    sequence=sequence,
                )
            held = {item.item_id for item in self._fossils.load(digest).items}
        except (ContractError, OSError, ValueError, KeyError):
            return False
        return set(item_ids) <= held


# --- pure helpers ------------------------------------------------------------------------


def _empty(*, deferred: bool, reasons: tuple[str, ...]) -> Consolidation:
    return Consolidation(
        candidate=None,
        deduplicated=0,
        merged=(),
        split=(),
        aged=(),
        dormant_evicted=(),
        retired=(),
        rehearsal_selected=(),
        fossil_due=False,
        deferred=deferred,
        deferred_reasons=reasons,
        work_units=0,
    )


def _victims(
    pool: Sequence[KnowledgeItem],
    active: str,
    count: int,
    trust: Mapping[str, float],
    *,
    modulated: bool,
) -> list[str]:
    def order(item: KnowledgeItem) -> tuple[float, str]:
        key = (
            trust.get(item.item_id, 1.0)
            if modulated
            else float(item.validation.last_matched_sequence)
        )
        return (key, item.item_id)

    dormant = sorted((i for i in pool if not _applies_now(i, active)), key=order)
    live = sorted((i for i in pool if _applies_now(i, active)), key=order)
    return [i.item_id for i in (*dormant, *live)][:count]


def _fingerprint(trusted: TrustedKnowledgeState) -> str:
    """Digest of the rehearsal replay result at fossilisation time."""
    scores = [
        [e.episode_id, round(score_session(trusted, e.steps, context_id=e.context_id).score, 6)]
        for e in trusted.rehearsal
    ]
    return digest_of_bytes(json.dumps(scores, sort_keys=True).encode("utf-8"))


def _epoch_range(trusted: TrustedKnowledgeState) -> tuple[int, int]:
    epochs = {e.epoch_id for e in trusted.rehearsal}
    for item in trusted.items:
        epochs |= set(item.validation.epochs_seen)
    return (min(epochs), max(epochs)) if epochs else (0, 0)


def _merge_proposals(
    trusted: TrustedKnowledgeState,
) -> tuple[KnowledgeDelta, tuple[tuple[str, str], ...]]:
    """Unprotected DETECTOR/BASELINE items identical but for context: merge one pair per group."""
    groups: dict[tuple[object, ...], list[KnowledgeItem]] = {}
    for item in trusted.items:
        if item.protected or item.status is not ItemStatus.ACTIVE:
            continue
        if item.kind in (ItemKind.DETECTOR, ItemKind.BASELINE):
            groups.setdefault((item.kind, item.motif, item.anchor, item.pattern_key), []).append(
                item
            )
    added: list[KnowledgeItem] = []
    pairs: list[tuple[str, str]] = []
    for members in groups.values():
        if len(members) < 2:
            continue
        left, right = sorted(members, key=lambda i: i.item_id)[:2]
        added.append(_merged(left, right))
        pairs.append((left.item_id, right.item_id))
    removed = tuple(i for pair in pairs for i in pair)
    return KnowledgeDelta(added=tuple(added), removed=removed), tuple(pairs)


def _merged(left: KnowledgeItem, right: KnowledgeItem) -> KnowledgeItem:
    """One item over both contexts. A detector keeps the higher weight (no alert is
    lost); a baseline keeps the tighter radius (nothing new is explained)."""
    weight = (
        max(left.weight, right.weight)
        if left.kind is ItemKind.DETECTOR
        else min(left.weight, right.weight)
    )
    a, b = left.validation, right.validation
    return KnowledgeItem.build(
        kind=left.kind,
        context_ids=left.context_ids | right.context_ids,
        pattern_key=left.pattern_key,
        weight=weight,
        origin_verdict=left.origin_verdict,
        lineage=ItemLineage(
            "cand-pending",
            tuple(dict.fromkeys((*left.lineage.capsule_ids, *right.lineage.capsule_ids)))[
                :MAX_ITEM_CAPSULE_REFS
            ],
            tuple(dict.fromkeys((*left.lineage.evidence_digests, *right.lineage.evidence_digests)))[
                :MAX_ITEM_CAPSULE_REFS
            ],
            (left.item_id, right.item_id),
        ),
        validation=ItemValidation(
            validations=a.validations + b.validations,
            recurrence=a.recurrence + b.recurrence,
            contradictions=a.contradictions + b.contradictions,
            first_sequence=min(a.first_sequence, b.first_sequence),
            last_matched_sequence=max(a.last_matched_sequence, b.last_matched_sequence),
            epochs_seen=frozenset(sorted(a.epochs_seen | b.epochs_seen)[-MAX_ITEM_EPOCHS:]),
        ),
        motif=left.motif,
        anchor=left.anchor,
    )


def _pool(episodic: EpisodicMemory, trusted: TrustedKnowledgeState) -> tuple[EpisodeSkeleton, ...]:
    """Current exemplars plus resident learning episodes, labelled only, by id."""
    labelled = (Verdict.MALICIOUS, Verdict.BENIGN)
    merged = {e.episode_id: e for e in trusted.rehearsal if e.verdict in labelled}
    for episode in episodic.episodes(tier=EpisodeTier.LEARNING):
        if episode.verdict in labelled:
            merged.setdefault(episode.episode_id, episode)
    return tuple(merged[key] for key in sorted(merged))


def _reservoir(
    pool: Sequence[EpisodeSkeleton], budget_bytes: int, seed: int
) -> tuple[EpisodeSkeleton, ...]:
    """The control: a uniformly random subset (seeded shuffle), filled to the same byte budget."""
    order = list(pool)
    random.Random(seed).shuffle(order)
    chosen: list[EpisodeSkeleton] = []
    used = 0
    for episode in order:
        size = episode.byte_size()
        if len(chosen) < MAX_REHEARSAL_EXEMPLARS and used + size <= budget_bytes:
            chosen.append(episode)
            used += size
    return tuple(sorted(chosen, key=lambda e: e.episode_id))


class _Picker:
    """Greedy exemplar selection under a byte budget, skipping semantic duplicates."""

    def __init__(self, budget_bytes: int) -> None:
        self.budget = budget_bytes
        self.chosen: dict[str, EpisodeSkeleton] = {}
        self.signatures: set[tuple[object, ...]] = set()
        self.used = 0
        self.deduplicated = 0

    def take(self, episode: EpisodeSkeleton) -> bool:
        if episode.episode_id in self.chosen or len(self.chosen) >= MAX_REHEARSAL_EXEMPLARS:
            return False
        signature = _signature(episode)
        if signature in self.signatures:
            self.deduplicated += 1
            return False
        if self.used + episode.byte_size() > self.budget:
            return False
        self.chosen[episode.episode_id] = episode
        self.signatures.add(signature)
        self.used += episode.byte_size()
        return True

    def first_of(self, episodes: Iterable[EpisodeSkeleton]) -> None:
        for episode in episodes:
            if self.take(episode):
                return


def _value_aware(
    pool: Sequence[EpisodeSkeleton],
    trusted: TrustedKnowledgeState,
    budget_bytes: int,
    meter: WorkMeter,
) -> tuple[tuple[EpisodeSkeleton, ...], int]:
    """>= 1 positive per active detector, a hard benign per context, then by value."""
    picker = _Picker(budget_bytes)
    positives = [e for e in pool if e.verdict is Verdict.MALICIOUS]
    active = (d for d in trusted.detectors() if d.status is ItemStatus.ACTIVE)
    for detector in sorted(active, key=lambda d: (not d.protected, d.item_id)):
        meter.charge(max(1, len(positives)))
        matches = [e for e in positives if match_motif(detector.motif, e.steps)]
        if not any(e.episode_id in picker.chosen for e in matches):
            picker.first_of(sorted(matches, key=lambda e: (e.byte_size(), e.episode_id)))
    baseline_contexts = {c for b in trusted.baselines() for c in b.context_ids}
    threshold = trusted.threshold()
    for context in sorted(({trusted.active_context} | baseline_contexts) - {ALL_CONTEXTS}):
        benign = [e for e in pool if e.verdict is Verdict.BENIGN and e.context_id == context]

        # Hard negatives first: the benign episodes the trusted state scores
        # closest to (or above) the threshold are the ones a regression would flip.
        def hardness(episode: EpisodeSkeleton, context: str = context) -> tuple[float, str]:
            score = score_session(trusted, episode.steps, context_id=context, meter=meter).score
            return (-min(score, threshold), episode.episode_id)

        picker.first_of(sorted(benign, key=hardness))
    by_value = sorted(
        pool,
        key=lambda e: (
            not e.anchors_touched,
            e.verdict is not Verdict.MALICIOUS,
            e.byte_size(),
            e.episode_id,
        ),
    )
    for episode in by_value:
        picker.take(episode)
    return tuple(picker.chosen[key] for key in sorted(picker.chosen)), picker.deduplicated
