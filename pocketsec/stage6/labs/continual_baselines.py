"""§7 — the dumbest continual learners that could work, so Stage 6 has something to lose to.

Stage 6's anti-forgetting and anti-poisoning machinery is justified only against
the simplest learners that do the same job. Every class here is one of the spec
§7 baselines, stdlib and symbolic (ADR-0050), and every one uses the **same**
representation and the same two primitives as the Stage 6 learner:
``chamber.evolution.induce_motifs`` to learn detectors and
``memory.semantic.score_session`` to score. Two learners can therefore differ
only in the *mechanism* under test — never in what they can express.

What these learners refuse to be:

* **Trusted.** Each holds a plain ``TrustedKnowledgeState`` *value* in its own
  attribute. None touches ``TrustedMind`` or the promotion controller; nothing
  here can change the endpoint's trusted cognition. They are lab controls, and
  ``labs/`` is never imported by a runtime module (boundary rule 6).
* **Clever.** ``NaiveFinetune`` believes every label the moment it arrives,
  treats unlabelled traffic as normal, moves its baseline anchors to the latest
  sample, refits its threshold on the last window, evicts detectors first-in
  first-out and treats *every* identity change as a new epoch. That is the
  point: it is the forgetting and poisoning lower bound (E3, G6.9).
* **Unbounded, except where the spec says so.** ``FullRetrain`` keeps every
  labelled episode forever — it is the cost ceiling Stage 6 must beat (G6.11)
  and exists only in the lab.

Two methods beyond the spec's ``Learner`` protocol are declared here because
the harness cannot measure without them: ``threshold()`` (the operating point,
so an FP rate can be read at the learner's own threshold) and
``trusted_state()`` (so promotions are counted from item lineage, one rule for
every learner). Both read; neither writes.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections import OrderedDict, deque
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.epoch.model import EpochDecision, SystemIdentity
from pocketsec.stage1.ssir.entities import SemanticProperty
from pocketsec.stage1.ssir.relations import Relation
from pocketsec.stage1.state.security_state import SecurityStateV1
from pocketsec.stage2.adaptation.promotion import PromotionController
from pocketsec.stage2.adaptation.quarantine import (
    DEFAULT_CONSISTENCY_RADIUS,
    AdaptationSample,
    QuarantineBuffer,
    meaning_vector,
    pattern_key,
)
from pocketsec.stage2.encoder.ssir_encoder import EncodedTransition
from pocketsec.stage6.capsule.experience_capsule import (
    CapsuleKind,
    EncodedStep,
    ExperienceCapsuleV1,
    LabelOrigin,
)
from pocketsec.stage6.chamber.evolution import FPR_BUDGET, MotifCandidate, induce_motifs
from pocketsec.stage6.constitution.learning import property_mask, raised_mask
from pocketsec.stage6.memory.episodic import EpisodeSkeleton, motif_signature, skeleton_from_capsule
from pocketsec.stage6.memory.semantic import (
    ALL_CONTEXTS,
    MAX_DETECTOR_ITEMS,
    MAX_ITEM_CAPSULE_REFS,
    ItemKind,
    ItemLineage,
    ItemValidation,
    KnowledgeItem,
    MotifStep,
    TrustedKnowledgeState,
    canonical_float,
    context_id_for,
    genesis_state,
    is_escalating,
    motif_pattern_key,
    score_session,
)
from pocketsec.stage6.resources import ResourceSnapshot, WorkMeter

__all__ = [
    "BENIGN_WINDOW",
    "PENDING_EPISODES",
    "AcceptNothing",
    "CalibrationOnly",
    "FullRetrain",
    "Learner",
    "LearnerCost",
    "NaiveFinetune",
    "NeverUpdate",
    "ORACLE_DEFINITION",
    "ORACLE_MOTIFS",
    "PrototypeCentroid",
    "ReservoirReplay",
    "Stage2Only",
    "oracle_detectors",
]

#: Episodes remembered so a later label can name them. Oldest forgotten first;
#: a label for a forgotten episode is counted as an orphan, never guessed at.
PENDING_EPISODES: int = 256
#: The "last window" NaiveFinetune refits its threshold on and draws its benign
#: induction pool from.
BENIGN_WINDOW: int = 64
_THRESHOLD_STEP = 1e-6


@dataclass(frozen=True, slots=True)
class LearnerCost:
    """Work units spent, bytes of retained history, bytes of the learned state."""

    work_units: int
    stored_bytes: int
    trusted_bytes: int


class Learner(Protocol):
    """What the endurance harness drives. Every learner gets byte-identical input."""

    name: str

    def observe(self, capsule: ExperienceCapsuleV1, *, sequence: int) -> None: ...
    def on_epoch(
        self, decision: EpochDecision, identity: SystemIdentity, *, sequence: int
    ) -> None: ...
    def consolidate(self, snapshot: ResourceSnapshot, *, sequence: int) -> None: ...
    def score(self, steps: Sequence[EncodedStep], *, context_id: str) -> float: ...
    def cost(self) -> LearnerCost: ...
    def trusted_digest(self) -> str: ...
    def threshold(self) -> float: ...
    def trusted_state(self) -> TrustedKnowledgeState: ...


def _bounded(ids: Iterable[str]) -> tuple[str, ...]:
    """Distinct, order-kept, newest ``MAX_ITEM_CAPSULE_REFS`` (the item cap)."""
    return tuple(dict.fromkeys(ids))[-MAX_ITEM_CAPSULE_REFS:]


def _evidence(skeletons: Iterable[EpisodeSkeleton]) -> tuple[str, ...]:
    return _bounded(d for s in skeletons for step in s.steps for d in step.evidence)


class _SymbolicLearner:
    """Shared plumbing: a genesis value, a bounded episode book, a benign window.

    Subclasses choose the mechanism: when labels update detectors, how capacity
    is enforced, whether normality is learned, whether the threshold moves.
    """

    naive_normality = True
    refit_threshold = True
    contradict_on_benign = True
    calibrate_when_frozen = False

    def __init__(self, identity: SystemIdentity, *, name: str,
                 detector_capacity: int = MAX_DETECTOR_ITEMS) -> None:
        if not 1 <= detector_capacity <= MAX_DETECTOR_ITEMS:
            raise ValueError(f"detector_capacity must be in [1, {MAX_DETECTOR_ITEMS}]")
        self.name = name
        self.detector_capacity = detector_capacity
        self._state = genesis_state(identity=identity)
        self._context = context_id_for(identity)
        self._meter = WorkMeter()
        self._episodes: OrderedDict[str, ExperienceCapsuleV1] = OrderedDict()
        self._benign: deque[EpisodeSkeleton] = deque(maxlen=BENIGN_WINDOW)
        self._fifo: deque[str] = deque()
        self._frozen = False
        self._minted = 0
        self.counters: dict[str, int] = {"orphan_labels": 0, "evicted": 0, "contexts_opened": 0,
                                         "uncorroborated_contexts": 0, "refused_updates": 0,
                                         "reservoir_swaps_refused": 0}

    # -- protocol ------------------------------------------------------------------

    def observe(self, capsule: ExperienceCapsuleV1, *, sequence: int) -> None:
        if capsule.kind is CapsuleKind.TRANSITION_EPISODE:
            self._remember(capsule)
            if capsule.label is None:
                self._unlabelled(capsule, sequence=sequence)
            else:
                self._labelled(capsule, capsule.label.verdict, capsule.label.origin, (), sequence)
        elif capsule.kind is CapsuleKind.LABEL_ASSERTION and capsule.label is not None:
            target = self._episodes.get(capsule.label.target_capsule_id)
            if target is None:
                self.counters["orphan_labels"] += 1
                return
            self._labelled(
                target, capsule.label.verdict, capsule.label.origin, (capsule.capsule_id,), sequence
            )
        elif capsule.kind is CapsuleKind.FOREIGN_PACKAGE and capsule.steps:
            self._unlabelled(capsule, sequence=sequence)

    def on_epoch(self, decision: EpochDecision, identity: SystemIdentity, *, sequence: int) -> None:
        if not decision.transitioned:
            return
        self._switch(identity)

    def consolidate(self, snapshot: ResourceSnapshot, *, sequence: int) -> None:
        return None

    def score(self, steps: Sequence[EncodedStep], *, context_id: str) -> float:
        return score_session(self._state, steps, context_id=context_id, meter=self._meter).score

    def cost(self) -> LearnerCost:
        history = sum(len(c.canonical_bytes()) for c in self._episodes.values())
        history += sum(s.byte_size() for s in self._benign) + self._extra_bytes()
        return LearnerCost(self._meter.spent, history, self._state.byte_size())

    def trusted_digest(self) -> str:
        return self._state.digest()

    def threshold(self) -> float:
        return self._state.threshold()

    def trusted_state(self) -> TrustedKnowledgeState:
        return self._state

    # -- mechanism hooks -------------------------------------------------------------

    def _extra_bytes(self) -> int:
        return 0

    def _unlabelled(self, capsule: ExperienceCapsuleV1, *, sequence: int) -> None:
        """Unlabelled traffic is normal — the naive assumption, stated rather than hidden."""
        self._benign.append(
            skeleton_from_capsule(capsule, verdict=Verdict.BENIGN, label_origin=LabelOrigin.NONE)
        )
        if self.naive_normality and not self._frozen:
            self._learn_normality(capsule.steps, (capsule.capsule_id,), sequence)

    def _labelled(self, episode: ExperienceCapsuleV1, verdict: Verdict, origin: LabelOrigin,
                  label_ids: tuple[str, ...], sequence: int) -> None:
        if verdict not in (Verdict.MALICIOUS, Verdict.BENIGN):
            return
        skeleton = skeleton_from_capsule(episode, verdict=verdict, label_origin=origin)
        ids = (episode.capsule_id, *label_ids)
        # The episode was assumed benign when it arrived unlabelled; a label now
        # overrides that assumption, or the episode would be its own false positive.
        self._forget_assumed(episode.capsule_id)
        if verdict is Verdict.BENIGN:
            self._benign.append(skeleton)
            if self._frozen:
                self._after_update()
                return
            if self.contradict_on_benign:
                self._contradict(skeleton)
            if self.naive_normality:
                self._learn_normality(episode.steps, ids, sequence)
        elif not self._frozen:
            self._learn_malicious(skeleton, ids, sequence)
        self._after_update()

    def _learn_malicious(
        self, skeleton: EpisodeSkeleton, ids: tuple[str, ...], sequence: int
    ) -> None:
        found = induce_motifs([skeleton], list(self._benign), meter=self._meter)
        self._add_detectors(found, [skeleton], ids, sequence)

    def _after_update(self) -> None:
        if self.refit_threshold and (not self._frozen or self.calibrate_when_frozen):
            self._refit()

    # -- shared primitives -------------------------------------------------------------

    def _forget_assumed(self, episode_id: str) -> None:
        if any(s.episode_id == episode_id for s in self._benign):
            kept = [s for s in self._benign if s.episode_id != episode_id]
            self._benign.clear()
            self._benign.extend(kept)

    def _remember(self, capsule: ExperienceCapsuleV1) -> None:
        self._episodes[capsule.capsule_id] = capsule
        while len(self._episodes) > PENDING_EPISODES:
            self._episodes.popitem(last=False)

    def _switch(self, identity: SystemIdentity) -> None:
        context = context_id_for(identity)
        if context != self._context:
            self._context = context
            self.counters["contexts_opened"] += 1
            self._state = self._state.with_changes(active_context=context)

    def _detector(self, found: MotifCandidate, skeletons: Sequence[EpisodeSkeleton],
                  ids: tuple[str, ...], sequence: int) -> KnowledgeItem:
        self._minted += 1
        return KnowledgeItem.build(
            kind=ItemKind.DETECTOR, context_ids=(ALL_CONTEXTS,),
            pattern_key=motif_pattern_key(found.motif),
            weight=canonical_float(found.weight), origin_verdict=Verdict.MALICIOUS,
            lineage=ItemLineage(f"{self.name}:{self._minted}", _bounded((*found.support, *ids)),
                                _evidence(skeletons) or ids[:1], ()),
            validation=ItemValidation.fresh(sequence=sequence), motif=found.motif,
        )

    def _add_detectors(self, found: Sequence[MotifCandidate], skeletons: Sequence[EpisodeSkeleton],
                       ids: tuple[str, ...], sequence: int) -> None:
        """Add every new motif; at capacity evict first-in first-out (counted)."""
        state = self._state
        known = {item.item_id for item in state.items}
        for motif in found:
            item = self._detector(motif, skeletons, ids, sequence)
            if item.item_id in known:
                continue
            remove: list[str] = []
            while len(state.detectors()) - len(remove) >= self.detector_capacity and self._fifo:
                remove.append(self._fifo.popleft())
                self.counters["evicted"] += 1
            state = state.with_changes(add=(item,), remove=tuple(remove))
            self._fifo.append(item.item_id)
            known.add(item.item_id)
        self._state = state

    def _contradict(self, benign: EpisodeSkeleton) -> None:
        """A BENIGN label on an episode a detector fires on drops that detector. Immediately."""
        hits = score_session(
            self._state, benign.steps, context_id=benign.context_id, meter=self._meter
        )
        if hits.detector_hits:
            self._state = self._state.with_changes(remove=hits.detector_hits)
            for item_id in hits.detector_hits:
                if item_id in self._fifo:
                    self._fifo.remove(item_id)

    def _learn_normality(
        self, steps: Sequence[EncodedStep], ids: tuple[str, ...], sequence: int
    ) -> None:
        """Every non-escalating step becomes its pattern's anchor: latest sample wins."""
        latest: dict[str, EncodedStep] = {}
        for step in steps:
            self._meter.charge(1)
            if not is_escalating(step):
                latest[pattern_key(step.to_encoded())] = step
        state = self._state
        for key, step in latest.items():
            old = [i for i in state.baselines()
                   if i.pattern_key == key and self._context in i.context_ids]
            prior = old[0].lineage.capsule_ids if old else ()
            item = self._baseline(
                key, step.meaning(), _bounded((*prior, *ids)), step.evidence or ids[:1], sequence
            )
            if old and old[0].item_id == item.item_id:
                continue
            if old:
                state = state.with_changes(replace=((old[0].item_id, item),))
            else:
                state = state.with_changes(add=(item,))
        self._state = state

    def _baseline(self, key: str, anchor: Sequence[float], ids: tuple[str, ...],
                  evidence: Sequence[str], sequence: int) -> KnowledgeItem:
        self._minted += 1
        return KnowledgeItem.build(
            kind=ItemKind.BASELINE, context_ids=(self._context,), pattern_key=key,
            weight=DEFAULT_CONSISTENCY_RADIUS, origin_verdict=Verdict.BENIGN,
            lineage=ItemLineage(f"{self.name}:{self._minted}", ids, _bounded(evidence), ()),
            validation=ItemValidation.fresh(sequence=sequence), anchor=anchor,
        )

    def _refit(self) -> None:
        """Threshold at the FPR budget over the last benign window (never silently > 1)."""
        if not self._benign:
            return
        scores = sorted(
            (score_session(self._state, s.steps, context_id=s.context_id, meter=self._meter).score
             for s in self._benign),
            reverse=True,
        )
        allowed = int(FPR_BUDGET * len(scores))
        target = canonical_float(min(1.0, scores[allowed] + _THRESHOLD_STEP))
        if target != self._state.threshold():
            self._state = self._state.with_changes(threshold=target)


class NaiveFinetune(_SymbolicLearner):
    """The forgetting and poisoning lower bound: no gate at all, FIFO at capacity.

    It also treats **every** identity change as an epoch, corroborated or not —
    the property arm P5 (epoch manipulation) exists to punish.
    """

    def __init__(
        self, identity: SystemIdentity, *, detector_capacity: int = MAX_DETECTOR_ITEMS
    ) -> None:
        super().__init__(identity, name="naive-finetune", detector_capacity=detector_capacity)

    def on_epoch(self, decision: EpochDecision, identity: SystemIdentity, *, sequence: int) -> None:
        if not decision.changed_components:
            return
        if not decision.transitioned:
            self.counters["uncorroborated_contexts"] += 1
        self._switch(identity)


class NeverUpdate(_SymbolicLearner):
    """Learns during its first epoch (M01) exactly as NaiveFinetune, then never again."""

    def __init__(self, identity: SystemIdentity, *, detector_capacity: int = MAX_DETECTOR_ITEMS,
                 name: str = "never-update") -> None:
        super().__init__(identity, name=name, detector_capacity=detector_capacity)

    def on_epoch(self, decision: EpochDecision, identity: SystemIdentity, *, sequence: int) -> None:
        if decision.transitioned:
            self._frozen = True
            self._switch(identity)


class CalibrationOnly(NeverUpdate):
    """NeverUpdate's frozen M01 structure, with the threshold refitted forever.

    ``NEVER_UPDATE + CALIBRATION_ONLY`` is the combination spec §1.1 predicts the
    anti-forgetting stack will not beat; it adds no item after M01.
    """

    calibrate_when_frozen = True

    def __init__(
        self, identity: SystemIdentity, *, detector_capacity: int = MAX_DETECTOR_ITEMS
    ) -> None:
        super().__init__(identity, detector_capacity=detector_capacity, name="calibration-only")

    def _unlabelled(self, capsule: ExperienceCapsuleV1, *, sequence: int) -> None:
        super()._unlabelled(capsule, sequence=sequence)
        if self._frozen:
            self._refit()


class ReservoirReplay(_SymbolicLearner):
    """Naive learning, gated by replay: an update is kept iff replay recall does not drop.

    The replay buffer is reservoir-sampled labelled skeletons under a **byte**
    budget — the same budget Stage 6's rehearsal gets, so value-aware selection
    is compared at equal bytes (the ADR-0128 lesson).
    """

    def __init__(self, identity: SystemIdentity, *, budget_bytes: int,
                 detector_capacity: int = MAX_DETECTOR_ITEMS, seed: int = 0) -> None:
        super().__init__(
            identity, name=f"reservoir-{budget_bytes}", detector_capacity=detector_capacity
        )
        if budget_bytes < 1:
            raise ValueError("budget_bytes must be positive")
        self.budget_bytes = budget_bytes
        self._rng = random.Random(seed)
        self._reservoir: list[EpisodeSkeleton] = []
        self._seen = 0

    def _extra_bytes(self) -> int:
        return sum(s.byte_size() for s in self._reservoir)

    def _sample(self, skeleton: EpisodeSkeleton) -> None:
        """Reservoir sampling under a byte budget: a swap that would overflow it is refused."""
        self._seen += 1
        held = sum(s.byte_size() for s in self._reservoir)
        if held + skeleton.byte_size() <= self.budget_bytes:
            self._reservoir.append(skeleton)
            return
        slot = self._rng.randrange(self._seen)
        if slot >= len(self._reservoir):
            return
        if held - self._reservoir[slot].byte_size() + skeleton.byte_size() > self.budget_bytes:
            self.counters["reservoir_swaps_refused"] += 1
            return
        self._reservoir[slot] = skeleton

    def _replay_recall(self, state: TrustedKnowledgeState) -> float | None:
        positives = [s for s in self._reservoir if s.verdict is Verdict.MALICIOUS]
        if not positives:
            return None
        hits = sum(score_session(state, s.steps, context_id=s.context_id, meter=self._meter).score
                   >= state.threshold() for s in positives)
        return hits / len(positives)

    def _labelled(self, episode: ExperienceCapsuleV1, verdict: Verdict, origin: LabelOrigin,
                  label_ids: tuple[str, ...], sequence: int) -> None:
        before_state, before_fifo = self._state, deque(self._fifo)
        before = self._replay_recall(before_state)
        super()._labelled(episode, verdict, origin, label_ids, sequence)
        after = self._replay_recall(self._state)
        if before is not None and after is not None and after < before:
            self._state, self._fifo = before_state, before_fifo
            self.counters["refused_updates"] += 1
        if verdict in (Verdict.MALICIOUS, Verdict.BENIGN):
            self._sample(skeleton_from_capsule(episode, verdict=verdict, label_origin=origin))


class FullRetrain(_SymbolicLearner):
    """Keeps every labelled episode forever and rebuilds every detector each consolidation.

    Lab only: its history store is unbounded by design, which is what G6.11
    measures it on. Detectors are chosen by greedy coverage up to capacity and
    induced against the labelled BENIGN history (never the unlabelled window):
    this is the strong, expensive ceiling, not a second naive learner.
    """

    def __init__(
        self, identity: SystemIdentity, *, detector_capacity: int = MAX_DETECTOR_ITEMS
    ) -> None:
        super().__init__(identity, name="full-retrain", detector_capacity=detector_capacity)
        self._history: list[EpisodeSkeleton] = []
        self._history_ids: list[str] = []

    def _extra_bytes(self) -> int:
        return sum(s.byte_size() for s in self._history)

    def _learn_malicious(
        self, skeleton: EpisodeSkeleton, ids: tuple[str, ...], sequence: int
    ) -> None:
        self._history.append(skeleton)
        self._history_ids.extend(ids)

    def _labelled(self, episode: ExperienceCapsuleV1, verdict: Verdict, origin: LabelOrigin,
                  label_ids: tuple[str, ...], sequence: int) -> None:
        if verdict is Verdict.BENIGN:
            self._history.append(
                skeleton_from_capsule(episode, verdict=verdict, label_origin=origin)
            )
        super()._labelled(episode, verdict, origin, label_ids, sequence)

    def consolidate(self, snapshot: ResourceSnapshot, *, sequence: int) -> None:
        malicious = [s for s in self._history if s.verdict is Verdict.MALICIOUS]
        if not malicious:
            return
        # Negatives are the labelled BENIGN history only. The unlabelled window is
        # for threshold calibration: an unlabelled recurrence of an old attack
        # (M08) is not evidence that the attack is benign, and a rebuild that
        # believed it would delete its own F1 detector (measured, before this rule).
        benign = [s for s in self._history if s.verdict is Verdict.BENIGN]
        found = induce_motifs(malicious, benign, meter=self._meter)
        chosen, covered = [], set()
        for motif in sorted(found, key=lambda m: (-len(set(m.support) - covered), -m.precision)):
            if len(chosen) >= self.detector_capacity or not set(motif.support) - covered:
                continue
            chosen.append(motif)
            covered |= set(motif.support)
        self._state = self._state.with_changes(
            remove=tuple(i.item_id for i in self._state.detectors())
        )
        self._fifo.clear()
        self._add_detectors(chosen, malicious, _bounded(self._history_ids), sequence)
        self._refit()


class PrototypeCentroid(_SymbolicLearner):
    """One motif per MALICIOUS cluster (keyed by motif signature); no competition, no gate."""

    refit_threshold = False
    contradict_on_benign = False

    def __init__(
        self, identity: SystemIdentity, *, detector_capacity: int = MAX_DETECTOR_ITEMS
    ) -> None:
        super().__init__(identity, name="prototype-centroid", detector_capacity=detector_capacity)
        self._clusters: set[frozenset[tuple[int, int, int]]] = set()

    def _learn_malicious(
        self, skeleton: EpisodeSkeleton, ids: tuple[str, ...], sequence: int
    ) -> None:
        signature = motif_signature(skeleton.steps)
        if signature in self._clusters:
            return
        self._clusters.add(signature)
        found = induce_motifs([skeleton], list(self._benign), meter=self._meter)
        if found:
            best = max(found, key=lambda m: (m.coverage, m.precision, -len(m.motif)))
            self._add_detectors([best], [skeleton], ids, sequence)


class AcceptNothing(_SymbolicLearner):
    """Never changes its state. The control that makes "0 poisoned promotions" mean something."""

    naive_normality = False
    refit_threshold = False
    contradict_on_benign = False

    def __init__(self, identity: SystemIdentity) -> None:
        super().__init__(identity, name="accept-nothing")
        self._frozen = True


class _BaselineWriter:
    """Stage 2's ``TrustedQuantizer``, writing BASELINE items straight into the owner's state.

    This is the Stage2Only control's entire difference from Stage 6: Stage 2's
    controller output is installed at once — no independence check, no shadow,
    no canary, no rollback.
    """

    def __init__(self, owner: Stage2Only) -> None:
        self._owner = owner

    def quantize_behaviour_atom(self, encoded: EncodedTransition, *, state: SecurityStateV1,
                                epoch_id: int, sequence: int) -> Any:
        return self._owner._install_baseline(encoded, sequence)

    def get(self, atom_id: int) -> None:
        return None


class Stage2Only(_SymbolicLearner):
    """Stage 2's buffer + controller straight into its own state; detectors as NaiveFinetune."""

    naive_normality = False

    def __init__(
        self, identity: SystemIdentity, *, detector_capacity: int = MAX_DETECTOR_ITEMS
    ) -> None:
        super().__init__(identity, name="stage2-only", detector_capacity=detector_capacity)
        self._buffer = QuarantineBuffer()
        self._controller = PromotionController()
        self._writer = _BaselineWriter(self)
        self._pending_ids: tuple[str, ...] = ()
        self._pending_evidence: tuple[str, ...] = ()
        self._step_sequence = 0

    def on_epoch(self, decision: EpochDecision, identity: SystemIdentity, *, sequence: int) -> None:
        self._buffer.record_epoch_decision(decision)
        self._controller.record_epoch_decision(decision)
        super().on_epoch(decision, identity, sequence=sequence)

    def _unlabelled(self, capsule: ExperienceCapsuleV1, *, sequence: int) -> None:
        super()._unlabelled(capsule, sequence=sequence)
        self._offer(capsule.steps, (capsule.capsule_id,))

    def _labelled(self, episode: ExperienceCapsuleV1, verdict: Verdict, origin: LabelOrigin,
                  label_ids: tuple[str, ...], sequence: int) -> None:
        super()._labelled(episode, verdict, origin, label_ids, sequence)
        if verdict is Verdict.BENIGN:
            self._offer(episode.steps, (episode.capsule_id, *label_ids))

    def _offer(self, steps: Sequence[EncodedStep], ids: tuple[str, ...]) -> None:
        self._pending_ids = ids
        for step in steps:
            self._pending_evidence = step.evidence
            self._meter.charge(1)
            self._step_sequence += 1
            sample = AdaptationSample(
                encoded=step.to_encoded(), state=SecurityStateV1(), epoch_id=step.epoch_id,
                delta_phi=step.delta_phi, uncertainty=step.uncertainty, evidence=step.evidence,
                received_at_sequence=self._step_sequence, causal_signature=step.causal_signature,
                parent_signature=step.parent_signature,
            )
            verdict = self._buffer.quarantine_adaptation_sample(sample)
            self._controller.promote(verdict, sample, quantizer=self._writer, lattice=None)

    def _install_baseline(self, encoded: EncodedTransition, sequence: int) -> int:
        key = pattern_key(encoded)
        old = [i for i in self._state.baselines()
               if i.pattern_key == key and self._context in i.context_ids]
        item = self._baseline(key, meaning_vector(encoded), self._pending_ids,
                              self._pending_evidence or self._pending_ids[:1], sequence)
        if old:
            if old[0].item_id != item.item_id:
                self._state = self._state.with_changes(replace=((old[0].item_id, item),))
        else:
            self._state = self._state.with_changes(add=(item,))
        return len(self._state.items)


# --- E1: the ground-truth motif set -------------------------------------------------

_P = SemanticProperty


def _step(relation: Relation, *, require: Sequence[SemanticProperty] = (),
          forbid: Sequence[SemanticProperty] = (), raised: Sequence[str] = ()) -> MotifStep:
    return MotifStep(
        int(relation), property_mask(require), property_mask(forbid), raised_mask(raised)
    )


#: Names the corpus definition the oracle motifs are written from (their lineage).
ORACLE_DEFINITION = "stage6-endurance-v0.1.0:oracle"

#: The motifs a perfect learner would hold, written from the corpus definition.
#: If these cannot reach EXPRESSIBLE_RECALL, the representation cannot express the
#: task and every learner result is BLOCKED (lesson 2).
ORACLE_MOTIFS: dict[str, tuple[MotifStep, ...]] = {
    "F1": (_step(Relation.READ, require=(_P.CREDENTIAL,), forbid=(_P.TEMP_LOCATION,)),
           _step(Relation.SEND, require=(_P.EXTERNAL_ENDPOINT,))),
    "F2": (_step(Relation.IMPERSONATE, raised=("privilege",)),
           _step(Relation.WRITE, require=(_P.PERSISTENCE,), forbid=(_P.TEMP_LOCATION,))),
    "F3": (_step(Relation.WRITE, require=(_P.TEMP_LOCATION,)),
           _step(Relation.SEND, require=(_P.EXTERNAL_ENDPOINT,))),
}


def _definition_digest(family: str, motif: Sequence[MotifStep]) -> str:
    payload = json.dumps(
        [ORACLE_DEFINITION, family, [s.to_payload() for s in motif]], sort_keys=True
    )
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def oracle_detectors(timeline: Sequence[Any]) -> TrustedKnowledgeState:
    """E1 only: ground-truth motifs as a lab value. Never loaded into a TrustedMind.

    ``timeline`` supplies the identity (its first month's). Semantic memory
    refuses any non-threshold item that claims genesis lineage, so each oracle
    item cites what it really comes from: the corpus *definition*, addressed by
    the sha256 of ``(ORACLE_DEFINITION, family, motif)``. No telemetry evidence
    backs it, which is exactly why this value may only ever be a lab probe.
    """
    if not timeline:
        raise ValueError("oracle_detectors needs a non-empty timeline")
    state = genesis_state(identity=timeline[0].identity)
    items = [
        KnowledgeItem.build(
            kind=ItemKind.DETECTOR, context_ids=(ALL_CONTEXTS,),
            pattern_key=motif_pattern_key(motif),
            weight=1.0, origin_verdict=Verdict.MALICIOUS,
            lineage=ItemLineage(f"lab:oracle:{family}", (f"lab:definition:{family}",),
                                (_definition_digest(family, motif),), ()),
            validation=ItemValidation.fresh(sequence=0), motif=motif,
        )
        for family, motif in ORACLE_MOTIFS.items()
    ]
    return state.with_changes(add=items)
