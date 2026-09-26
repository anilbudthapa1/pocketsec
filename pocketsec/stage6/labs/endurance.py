"""D6.20 — the endurance, poisoning and ablation harness: every learner, identical input.

This is where Stage 6's claims are measured instead of asserted. Three rules make
the numbers mean something:

* **One compile.** ``compile_timeline`` runs ``Stage1Pipeline`` once per timeline;
  every learner then receives the *same* capsule objects in the same order. A
  difference between two learners is the mechanism, never the input.
* **Preconditions before retention.** ``check_preconditions`` (spec §4.20, E1–E5)
  runs first. A corpus the representation cannot express is BLOCKED; one a
  zero-learning control already solves is DEGENERATE; neither yields a number.
* **Rule C.** Every ablation row carries a firing count; a mechanism that never
  changed an outcome is INERT and its delta is not evidence.

``StageSixLearner`` wires the real subsystems — gateway -> episodic -> chamber ->
consolidator -> controller — and refuses to be clever about it: a candidate is
submitted, shadowed, canaried, promoted and put on probation through the one
controller, in that order. Shadow and canary replay a bounded ring of recently
observed sessions (a synthetic month holds 16 sessions; the §4.21 windows need
128 shadow / 64 canary sessions), so they are filled by *replaying observed
traffic*, never by inventing it. Probation is different: it watches only live
sessions that arrive after the promotion, so a regression the replay could not
show still rolls back automatically. Until the ring holds a full shadow window
the learner promotes nothing — at 16 sessions a month that is eight months, a
measured consequence of the chosen constants, reported, not tuned away.

``compile_timeline`` is defined beside the corpus (``endurance_corpus``) and
re-exported here, where the spec places it.

Nothing here appends to ``experiments/registry.jsonl`` (the integrator's
``experiments`` command does). Cost is ``WorkMeter`` units; wall clock is an
observation recorded beside ``/proc/loadavg`` and never asserted. Every report is
``synthetic=True``.
"""

from __future__ import annotations

import statistics
import time
from collections import Counter, OrderedDict, deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from pocketsec.stage0.benchmark.security_metrics import average_precision, recall_at_max_fpr
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.epoch.model import EpochDecision, SystemIdentity
from pocketsec.stage6.capsule.experience_capsule import (
    CapsuleKind,
    EncodedStep,
    ExperienceCapsuleV1,
    LabelOrigin,
)
from pocketsec.stage6.capsule.quarantine import (
    MAX_ISSUED_VERDICTS,
    QuarantineBucket,
    QuarantineGateway,
    QuarantineVerdict,
)
from pocketsec.stage6.chamber.evolution import (
    FPR_BUDGET,
    MAX_CHAMBER_CAPSULES,
    MAX_ISSUED_CANDIDATES,
    EvolutionCandidate,
    EvolutionChamber,
)
from pocketsec.stage6.conservation.gate import EPS_FP_RATE, EPS_SECURITY
from pocketsec.stage6.consolidator.mnemosyne import (
    DEFAULT_REHEARSAL_BUDGET_BYTES,
    MnemosyneConsolidator,
)
from pocketsec.stage6.constitution.learning import LifecycleState
from pocketsec.stage6.fossils.lineage import MAX_LINEAGE_NODES, KnowledgeLineageDAG
from pocketsec.stage6.fossils.store import MAX_FOSSIL_BYTES, MAX_FOSSILS, FossilStore
from pocketsec.stage6.homeostasis.drift import (
    DRIFT_ALIGN_WINDOW,
    MAX_KNOWLEDGE_CONTEXTS,
    DriftClass,
    KnowledgeContextRegistry,
    classify_drift_vs_poisoning,
    drift_signals,
)
from pocketsec.stage6.labs.continual_baselines import (
    Learner,
    LearnerCost,
    NaiveFinetune,
    NeverUpdate,
    oracle_detectors,
)
from pocketsec.stage6.labs.endurance_corpus import (
    ENDURANCE_SEED,
    FAMILIES,
    CompiledMonth,
    CompiledTimeline,
    StreamEvent,
    compile_timeline,
    simulated_snapshot,
)
from pocketsec.stage6.labs.poison_suite import (
    POISON_MULTIPLIERS,
    PoisonReport,
    PoisonRow,
    run_poison_suite,
)
from pocketsec.stage6.memory.episodic import (
    MAX_EPISODES,
    MAX_HOSTILE_EPISODES,
    EpisodeTier,
    EpisodicMemory,
    episode_value,
    skeleton_from_capsule,
)
from pocketsec.stage6.memory.half_life import trust_ranking
from pocketsec.stage6.memory.semantic import (
    MAX_BASELINE_ITEMS,
    MAX_DETECTOR_ITEMS,
    MAX_PROCEDURE_ITEMS,
    MAX_TRUSTED_STATE_BYTES,
    TrustedKnowledgeState,
    genesis_state,
    is_escalating,
    score_session,
)
from pocketsec.stage6.promotion.controller import (
    MAX_DECISION_LOG,
    LearningPromotionController,
    PromotionDecision,
)
from pocketsec.stage6.provenance.ledger import MAX_TRUST_RECORDS, ProvenanceLedger
from pocketsec.stage6.resources import (
    CONSOLIDATION_WORKSPACE_BUDGET_BYTES,
    EPISODIC_BUDGET_BYTES,
    LINEAGE_FOSSIL_META_BUDGET_BYTES,
    QUARANTINE_META_BUDGET_BYTES,
    ResourceSnapshot,
    WorkBudgetExceeded,
    WorkMeter,
    loadavg,
)
from pocketsec.stage6.shadow.canary import CANARY_WINDOW_SESSIONS
from pocketsec.stage6.shadow.mind import (
    MIN_SHADOW_SESSIONS,
    STEP_BYTES_ESTIMATE,
    ShadowMind,
    ShadowSession,
)

__all__ = [
    "ACQUISITION_NEED_MAX",
    "CAPACITY_SWEEP",
    "EXPRESSIBLE_RECALL",
    "FORGETTING_MIN_DROP",
    "FPR_BUDGET",
    "POISON_MULTIPLIERS",
    "REPLAY_BUDGETS_BYTES",
    "REPLAY_RING_SESSIONS",
    "SATURATION_AP",
    "STORE_CAPS",
    "STORE_GROUPS",
    "VERDICTS",
    "VOCABULARY_LEAK_MAX",
    "AblationRow",
    "CompiledMonth",
    "CompiledTimeline",
    "EnduranceReport",
    "MonthCheckpoint",
    "PoisonReport",
    "PoisonRow",
    "PreconditionReport",
    "StageSixConfig",
    "StageSixLearner",
    "StreamEvent",
    "check_preconditions",
    "compile_timeline",
    "run_ablation",
    "run_endurance",
    "run_poison_suite",
    "simulated_snapshot",
    "store_violations",
]

CAPACITY_SWEEP: tuple[int, ...] = (4, 8, 64)
REPLAY_BUDGETS_BYTES: tuple[int, ...] = (16384, 65536, 262144)
EXPRESSIBLE_RECALL = 0.9
SATURATION_AP = 0.9
FORGETTING_MIN_DROP = 0.10
ACQUISITION_NEED_MAX = 0.5
VOCABULARY_LEAK_MAX = 0.05
#: Recently observed sessions shadow/canary/probation may replay. Bounded.
REPLAY_RING_SESSIONS: int = 256
_PENDING_EPISODES = 256
_MAX_PROMOTIONS_PER_CYCLE = 4
#: store -> (byte cap, count cap) for every bounded store ``StageSixLearner.stores``
#: reports. Byte caps are the §39 budgets (or the subsystem's own tighter cap);
#: ``None`` = the store has no such cap. Bounded-growth checks read only this table.
STORE_CAPS: Mapping[str, tuple[int | None, int | None]] = {
    "gateway": (QUARANTINE_META_BUDGET_BYTES, MAX_ISSUED_VERDICTS),
    "ledger": (QUARANTINE_META_BUDGET_BYTES, MAX_TRUST_RECORDS),
    "episodic": (EPISODIC_BUDGET_BYTES, MAX_EPISODES + MAX_HOSTILE_EPISODES),
    "lineage": (LINEAGE_FOSSIL_META_BUDGET_BYTES, MAX_LINEAGE_NODES),
    "fossils": (MAX_FOSSIL_BYTES, MAX_FOSSILS),
    "controller": (None, MAX_DECISION_LOG),
    "chamber": (None, MAX_ISSUED_CANDIDATES),
    "consolidator": (CONSOLIDATION_WORKSPACE_BUDGET_BYTES, None),
    "contexts": (None, MAX_KNOWLEDGE_CONTEXTS),
    "replay_ring": (None, REPLAY_RING_SESSIONS),
    # The episode book labels resolve against (review S6-R5: held but never reported).
    "episode_book": (None, _PENDING_EPISODES),
    "trusted": (
        MAX_TRUSTED_STATE_BYTES,
        MAX_DETECTOR_ITEMS + MAX_BASELINE_ITEMS + MAX_PROCEDURE_ITEMS + 1,
    ),
}
#: Stores that share ONE §39 budget: each alone is capped at the whole budget above, so the
#: sum must be checked too — two 15 MiB caps admitted 30 MiB of quarantine metadata, over the
#: §39 peak of 25 MiB (review S6-R9).
STORE_GROUPS: Mapping[str, tuple[tuple[str, ...], int]] = {
    "quarantine_metadata": (("gateway", "ledger", "episode_book"), QUARANTINE_META_BUDGET_BYTES),
}
VERDICTS = ("JUSTIFIED", "NOT_YET_JUSTIFIED", "HARMFUL", "INERT", "DEGENERATE", "UNMEASURED")


# --- the Stage 6 learner --------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class StageSixConfig:
    independence_check: bool = True
    homeostasis: bool = True
    plasticity_field: bool = True
    half_life: bool = True
    competition: bool = True
    counterfactual_variants: bool = True
    value_aware_rehearsal: bool = True
    drift_discriminator: bool = True
    resurrection: bool = True
    detector_capacity: int = MAX_DETECTOR_ITEMS
    rehearsal_budget_bytes: int = DEFAULT_REHEARSAL_BUDGET_BYTES


class StageSixLearner:
    """The real pipeline behind ``Learner``; trusted state moves only through the controller.

    Two knobs cannot be honoured by the subsystems as built, and the constructor
    says so instead of pretending: ``detector_capacity`` other than
    ``MAX_DETECTOR_ITEMS`` (the chamber and consolidator read the module cap) and
    ``counterfactual_variants=False`` (the controller runs the conservation gate
    itself, with no G4 switch). Both raise ``ValueError``.
    """

    def __init__(
        self,
        identity: SystemIdentity,
        *,
        config: StageSixConfig = StageSixConfig(),
        fossil_dir: Path | None = None,
        name: str = "stage6",
        seed: int = ENDURANCE_SEED,
    ) -> None:
        if config.detector_capacity != MAX_DETECTOR_ITEMS:
            raise ValueError(
                "StageSixLearner cannot honour detector_capacity != MAX_DETECTOR_ITEMS: the "
                "chamber and consolidator expose no capacity parameter (reported blocker)"
            )
        if not config.counterfactual_variants:
            raise ValueError(
                "StageSixLearner cannot switch G4 off: the controller runs offline_validation "
                "itself with no counterfactual flag (reported blocker)"
            )
        self.name, self.config, self._seed, self.fossil_dir = name, config, seed, fossil_dir
        self.lineage = KnowledgeLineageDAG()
        self.fossils = FossilStore(directory=fossil_dir)
        self.ledger = ProvenanceLedger()
        self.gateway = QuarantineGateway(ledger=self.ledger, lineage=self.lineage,
                                         independence_check=config.independence_check,
                                         homeostasis=config.homeostasis)
        self.episodic = EpisodicMemory()
        self.consolidator = MnemosyneConsolidator(
            fossils=self.fossils,
            lineage=self.lineage,
            value_aware_rehearsal=config.value_aware_rehearsal,
            half_life=config.half_life,
            rehearsal_budget_bytes=config.rehearsal_budget_bytes,
            seed=seed,
        )
        self.chamber = EvolutionChamber(
            gateway=self.gateway,
            episodic=self.episodic,
            consolidator=self.consolidator,
            plasticity_field=config.plasticity_field,
            competition=config.competition,
        )
        self.shadow = ShadowMind()
        self.registry = KnowledgeContextRegistry(identity=identity, epoch_id=0, sequence=0)
        self.controller = LearningPromotionController(
            genesis=genesis_state(identity=identity), fossils=self.fossils, lineage=self.lineage,
            gateway=self.gateway, chamber=self.chamber, shadow=self.shadow)
        self._meter = WorkMeter()
        self._book: OrderedDict[str, ExperienceCapsuleV1] = OrderedDict()
        self._ring: deque[ShadowSession] = deque(maxlen=REPLAY_RING_SESSIONS)
        self._labels: deque[QuarantineVerdict] = deque(maxlen=MAX_CHAMBER_CAPSULES // 2)
        self._normality: deque[QuarantineVerdict] = deque(maxlen=MAX_CHAMBER_CAPSULES // 2)
        self._responses: deque[tuple[QuarantineVerdict, ExperienceCapsuleV1]] = deque(maxlen=16)
        self._drift: tuple[EpochDecision, int, list[QuarantineVerdict]] | None = None
        #: The last DRIFT_ALIGN_WINDOW verdicts, so a drift window holds verdicts from BEFORE
        #: its pivot as well as after. Without them every key in the window was "changed"
        #: and HEL-F19 classed every corroborated change POISON_SUSPECT (review F1).
        self._recent: deque[QuarantineVerdict] = deque(maxlen=DRIFT_ALIGN_WINDOW)
        self._held: list[QuarantineVerdict] = []
        self._epoch = 0
        self._last_gateway_sequence = 0
        self._candidate_work = 0
        self.lab_tamper: Callable[[EvolutionCandidate], EvolutionCandidate] | None = None
        self.counters: Counter[str] = Counter()
        self.canary_min_margin: float | None = None
        self._probation_next: str | None = None
        #: The last few refusal messages, bounded: a counter says *that* the
        #: subsystems refused, this says *why*, so a refusal is never silent.
        self.refusals: deque[str] = deque(maxlen=16)

    # -- protocol ---------------------------------------------------------------------

    def observe(self, capsule: ExperienceCapsuleV1, *, sequence: int) -> None:
        verdict = self.gateway.admit(capsule)
        self._last_gateway_sequence = verdict.sequence
        self.counters[f"bucket:{verdict.bucket.value}"] += 1
        self._recent.append(verdict)
        if self._drift is not None:
            _, pivot, window = self._drift
            window.append(verdict)
            if sum(v.sequence > pivot for v in window) >= DRIFT_ALIGN_WINDOW:
                self._close_drift()
        if capsule.kind is CapsuleKind.TRANSITION_EPISODE:
            self._flush_probation()
            self._book[capsule.capsule_id] = capsule
            while len(self._book) > _PENDING_EPISODES:
                self._book.popitem(last=False)
                self.counters["book_evicted"] += 1
            self._ring.append(
                ShadowSession(capsule.capsule_id, capsule.steps, capsule.context_id, None)
            )
            self._probation_next = capsule.capsule_id
            self.counters["ring_seen"] += 1
        if verdict.bucket is QuarantineBucket.HOSTILE_SUSPECT:
            self._admit_hostile(capsule, verdict)
        elif verdict.bucket is QuarantineBucket.TRUSTED_CANDIDATE:
            self._accept(capsule, verdict)

    def on_epoch(self, decision: EpochDecision, identity: SystemIdentity, *, sequence: int) -> None:
        self.gateway.record_epoch_decision(decision)
        transition = self.registry.open_new_epoch(
            decision,
            identity=identity,
            sequence=sequence,
            trusted=self.controller.mind.current(),
            fossils=self.fossils,
        )
        if not decision.transitioned:
            self.counters["epoch_refused_uncorroborated"] += 1
            return
        self._epoch = decision.epoch_id
        self._close_drift()
        # Bounded: <= DRIFT_ALIGN_WINDOW verdicts before the pivot, as many after.
        self._drift = (decision, self._last_gateway_sequence, list(self._recent))
        if transition is None:
            return
        if transition.resurrect is not None and not self.config.resurrection:
            transition = replace(transition, resurrect=None)
            self.counters["resurrection_suppressed"] += 1
        try:
            self.controller.apply_context_transition(transition)
            self.registry.activate(transition.current, sequence=sequence)
            self.counters["context_transitions"] += 1
        except ContractError as exc:
            self.counters["context_transition_refused"] += 1
            self.refusals.append(f"context_transition: {exc}")
            return
        if transition.resurrect is not None:
            candidate = self.chamber.spawn_resurrection_candidate(
                trusted=self.controller.mind.current(),
                proposal=transition.resurrect,
                sequence=sequence,
            )
            if candidate is not None and self._promote(candidate, sequence):
                self.counters["resurrections_promoted"] += 1

    def consolidate(self, snapshot: ResourceSnapshot, *, sequence: int) -> None:
        self._flush_probation()
        self._close_drift()
        self._learn(sequence)
        trusted = self.controller.mind.current()
        result = self.consolidator.consolidate_memory(
            trusted=trusted,
            episodic=self.episodic,
            snapshot=snapshot,
            now_sequence=sequence,
            epochs_since_match=self._epochs_since_match(trusted),
        )
        self.counters["consolidation_deferred"] += int(result.deferred)
        if result.candidate is not None and len(self._ring) >= self._shadow_minimum():
            self._promote(result.candidate, sequence)
        elif result.candidate is not None:  # built, recorded and issued, then not submitted
            self.counters["consolidation_candidate_dropped_short_ring"] += 1
        if self.lineage.stats().nodes > MAX_LINEAGE_NODES // 2:
            # Through the controller, never a raw DAG collect: only the controller knows the
            # pinned rollback target's items, and a raw collect given the current items
            # alone strands that target during probation (integration seam fix; pinned by
            # test_a_raw_dag_collect_strands_the_target_and_rollback_names_it).
            self.counters["lineage_folded"] += self.controller.collect_lineage()

    def score(self, steps: Sequence[EncodedStep], *, context_id: str) -> float:
        return self.controller.mind.score(steps, context_id=context_id, meter=self._meter).score

    def cost(self) -> LearnerCost:
        stored = sum(size for size, _, _ in self.stores().values())
        return LearnerCost(self._meter.spent + self._candidate_work, stored,
                           self.controller.mind.current().byte_size())

    def trusted_digest(self) -> str:
        return self.controller.mind.digest()

    def threshold(self) -> float:
        return self.controller.mind.current().threshold()

    def trusted_state(self) -> TrustedKnowledgeState:
        return self.controller.mind.current()

    def stores(self) -> dict[str, tuple[int, int, int]]:
        """name -> (bytes, count, evictions) for every bounded store this learner owns."""
        episodic, fossils = self.episodic.stats(), self.fossils.stats()
        lineage, controller = self.lineage.stats(), self.controller.stats()
        chamber, consolidator = self.chamber.stats(), self.consolidator.stats()
        gateway, trusted = self.gateway.stats(), self.controller.mind.current()
        ring_bytes = sum(len(s.steps) * STEP_BYTES_ESTIMATE for s in self._ring)
        ring_evicted = max(0, self.counters["ring_seen"] - len(self._ring))
        return {
            "gateway": (
                self.gateway.memory_bytes(),
                gateway.get("issued"),
                gateway.get("issued_forgotten") + gateway.get("episodes_forgotten"),
            ),
            "ledger": (
                self.ledger.memory_bytes(), self.ledger.stats().records, self.ledger.evicted()
            ),
            "episodic": (
                episodic.memory_bytes,
                episodic.learning_episodes + episodic.hostile_episodes,
                episodic.evictions + episodic.hostile_evictions,
            ),
            "lineage": (lineage.memory_bytes, lineage.nodes, lineage.folded_total),
            "fossils": (fossils.memory_bytes, fossils.fossils, fossils.evictions),
            "controller": (
                self.controller.memory_bytes(),
                controller.decisions_logged,
                controller.decisions_dropped,
            ),
            "chamber": (
                self.chamber.memory_bytes(), chamber.issued_live, chamber.issued_forgotten
            ),
            "consolidator": (
                self.consolidator.memory_bytes(), consolidator.runs, consolidator.deferred_dropped
            ),
            "contexts": (
                self.registry.memory_bytes(), len(self.registry.contexts()), self.registry.dropped
            ),
            "replay_ring": (ring_bytes, len(self._ring), ring_evicted),
            "episode_book": (
                sum(len(c.canonical_bytes()) for c in self._book.values()), len(self._book),
                self.counters["book_evicted"],
            ),
            "trusted": (trusted.byte_size(), len(trusted.items), 0),
        }

    @property
    def rollback_count(self) -> int:
        return self.controller.stats().rolled_back

    # -- quarantine-side bookkeeping ----------------------------------------------------

    def _accept(self, capsule: ExperienceCapsuleV1, verdict: QuarantineVerdict) -> None:
        if capsule.kind in (
            CapsuleKind.LABEL_ASSERTION, CapsuleKind.WORLD_RESOLUTION
        ) and capsule.label:
            target = self._book.get(verdict.target_episode or capsule.label.target_capsule_id)
            if target is None:
                self.counters["label_target_forgotten"] += 1
                return
            self._admit_episode(
                target, verdict, capsule.label.verdict, capsule.label.origin, EpisodeTier.LEARNING
            )
            self._label_ring(target.capsule_id, capsule.label.verdict)
            self._push(self._labels, verdict, "label_verdicts_dropped")
        elif verdict.admissions:
            if self._drift is not None:
                # bounded: the drift window closes at DRIFT_ALIGN_WINDOW verdicts
                self._held.append(verdict)
            else:
                self._push(self._normality, verdict, "normality_verdicts_dropped")
        elif capsule.kind is CapsuleKind.RESPONSE_OUTCOME:
            self._push(self._responses, (verdict, capsule), "response_verdicts_dropped")

    def _push(self, queue: deque, item: object, counter: str) -> None:
        """Append to a bounded learning queue; an entry pushed out is counted, never silent."""
        if queue.maxlen is not None and len(queue) >= queue.maxlen:
            self.counters[counter] += 1
        queue.append(item)

    def _admit_hostile(self, capsule: ExperienceCapsuleV1, verdict: QuarantineVerdict) -> None:
        target = capsule if capsule.kind is CapsuleKind.TRANSITION_EPISODE else self._book.get(
            verdict.target_episode
        )
        if target is not None and target.steps:
            self._admit_episode(
                target, verdict, Verdict.UNKNOWN, LabelOrigin.NONE, EpisodeTier.HOSTILE
            )

    def _admit_episode(
        self,
        target: ExperienceCapsuleV1,
        verdict: QuarantineVerdict,
        label: Verdict,
        origin: LabelOrigin,
        tier: EpisodeTier,
    ) -> None:
        skeleton = skeleton_from_capsule(target, verdict=label, label_origin=origin)
        trust = self.ledger.get(target.capsule_id) or verdict.trust
        value = episode_value(
            skeleton,
            trust=trust,
            suspicion_summary=verdict.suspicion.summary(),
            resident=self.episodic.episodes(),
            trusted=self.controller.mind.current(),
        )
        record = self.episodic.admit_episode(
            skeleton, value=value, verdict_id=verdict.verdict_id, tier=tier
        )
        self.counters[
            f"episodic_{tier.value.lower()}_{'admitted' if record.admitted else 'refused'}"
        ] += 1

    def _flush_probation(self) -> None:
        """Feed the last *live* session — its labels have arrived by now — to probation.

        Probation watches traffic that arrives after the promotion, never the
        replayed ring the shadow already saw: a regression the shadow could not
        see (G2's rehearsal gap, G6.8) is exactly what live traffic surfaces, and
        a surfaced regression rolls back here, automatically, not in a report.
        """
        episode_id, self._probation_next = self._probation_next, None
        if episode_id is None or not self.controller.stats().probation_active:
            return
        session = next((s for s in reversed(self._ring) if s.session_id == episode_id), None)
        if session is None:
            return
        self.counters["probation_observed"] += 1
        if self.controller.observe_probation(session) is not None:
            self.counters["probation_rollbacks"] += 1

    def _label_ring(self, episode_id: str, label: Verdict) -> None:
        for index, session in enumerate(self._ring):
            if session.session_id == episode_id:
                self._ring[index] = replace(session, label=label)

    def _close_drift(self) -> None:
        """HEL-F19 at work: classify the post-change window; drop poison-suspect admissions."""
        if self._drift is None:
            return
        decision, pivot, window = self._drift
        self._drift = None
        verdict = classify_drift_vs_poisoning(
            drift_signals(window, decision=decision, decision_sequence=pivot)
        )
        self.counters[f"drift:{verdict.drift_class.value}"] += 1
        if verdict.drift_class is not DriftClass.LEGITIMATE_DRIFT:
            self.counters["drift_differs_from_rule"] += 1
        if self.config.drift_discriminator and verdict.drift_class is DriftClass.POISON_SUSPECT:
            self.counters["drift_dropped_admissions"] += len(self._held)
        else:
            for held in self._held:
                self._push(self._normality, held, "normality_verdicts_dropped")
        self._held = []

    def _epochs_since_match(self, trusted: TrustedKnowledgeState) -> dict[str, int]:
        return {item.item_id: max(0, self._epoch - max(item.validation.epochs_seen, default=0))
                for item in trusted.items}

    def _shadow_minimum(self) -> int:
        return MIN_SHADOW_SESSIONS * self.shadow.sample_every

    # -- the one path to trusted state ----------------------------------------------------

    def _learn(self, sequence: int) -> None:
        if not (self._labels or self._normality or self._responses):
            return
        if len(self._ring) < self._shadow_minimum():
            self.counters["learning_deferred_short_ring"] += 1
            return
        if self.controller.stats().probation_active:
            self.counters["learning_deferred_probation"] += 1
            return
        verdicts = [*self._labels, *self._normality, *(v for v, _ in self._responses)][
            :MAX_CHAMBER_CAPSULES
        ]
        admissions = [a for v in verdicts for a in v.admissions]
        capsules = [c for _, c in self._responses]
        for _ in range(_MAX_PROMOTIONS_PER_CYCLE):
            trusted = self.controller.mind.current()
            halves = trust_ranking(trusted.items, now_sequence=sequence,
                                   epochs_since_match=self._epochs_since_match(trusted))
            try:
                candidate = self.chamber.spawn_evolution_candidate(
                    trusted=trusted, verdicts=verdicts, admissions=admissions, half_lives=halves,
                    sequence=sequence, capsules=capsules)
            except (ContractError, WorkBudgetExceeded) as exc:
                self.counters["spawn_refused"] += 1
                self.refusals.append(f"spawn: {exc}")
                break
            if candidate is None or not self._promote(candidate, sequence):
                break
            if self.controller.stats().probation_active:
                # A promotion opened probation, so a further candidate would be spawned,
                # lineage-recorded and issued only to be refused unseen (review S6-R8).
                break
        self._labels.clear()
        self._normality.clear()
        self._responses.clear()

    def _promote(self, candidate: EvolutionCandidate, sequence: int) -> bool:
        """submit -> shadow -> canary -> trusted -> probation. False at the first refusal.

        One canary or probation at a time (the controller's rule): while a promoted
        state is still on probation nothing new is submitted, and the waiting is
        counted rather than hidden.
        """
        if self.controller.stats().probation_active:
            self.counters["deferred_probation_active"] += 1
            return False
        if self.lab_tamper is not None:
            candidate = self.lab_tamper(candidate)
        self._candidate_work += candidate.work_units
        holdout_ids = set(candidate.holdout_episode_ids)
        holdout = [e for e in self.episodic.episodes() if e.episode_id in holdout_ids]
        try:
            decision = self.controller.submit(
                candidate,
                holdout=holdout,
                hostile=self.episodic.episodes(tier=EpisodeTier.HOSTILE),
                variant_seed=self._seed + sequence,
            )
        except ContractError as exc:
            self.counters["submit_refused"] += 1
            self.refusals.append(f"submit: {exc}")
            return False
        if _rejected(decision) or _rejected(
            self.controller.run_shadow(candidate.candidate_id, list(self._ring))
        ):
            self.counters["rejected_offline_or_shadow"] += 1
            return False
        self.controller.promote_canary(candidate.candidate_id)
        for session in list(self._ring)[-CANARY_WINDOW_SESSIONS:]:
            outcome = self.controller.observe_canary(session)
            if isinstance(outcome, PromotionDecision):
                self.counters["rejected_canary"] += 1
                return False
            margin = outcome.emitted - outcome.trusted_score
            self.canary_min_margin = margin if self.canary_min_margin is None else min(
                self.canary_min_margin, margin
            )
        if _rejected(self.controller.promote_trusted(candidate.candidate_id)):
            # Enough canary sessions, too few benign-labelled ones (review S6-AUTH-03).
            self.counters["rejected_canary_unlabelled"] += 1
            return False
        self.counters["promoted"] += 1
        return True  # probation now runs on live traffic (_flush_probation)


def _rejected(decision: PromotionDecision) -> bool:
    return decision.to_state is LifecycleState.REJECTED


# --- endurance ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MonthCheckpoint:
    month: int
    learner: str
    acquisition: Mapping[str, float | None]
    retention: Mapping[str, float | None]
    fp_rate: float | None
    store_bytes: Mapping[str, int]
    store_counts: Mapping[str, int]
    evictions: Mapping[str, int]
    promotions: int
    rollbacks: int
    poisoned_promotions: int
    clean_promotions: int
    cost: LearnerCost
    scores: tuple[float, ...] = ()
    #: Detector items that left trusted state this month, and the subset that left in the
    #: update right after a poison capsule was observed (review F2: a label-flip's effect is
    #: a removal, which an additions-only count cannot see). Removals at consolidation are
    #: in ``detectors_removed`` but are not attributed to poison: that attribution is
    #: UNMEASURED here.
    detectors_removed: int = 0
    poison_removals: int = 0


@dataclass(frozen=True, slots=True)
class PreconditionReport:
    expressible: bool | None
    saturated: bool | None
    forgetting_pressure: bool | None
    acquisition_need: bool | None
    vocabulary_leak: bool | None
    details: tuple[str, ...]

    @property
    def verdict(self) -> str:
        """BLOCKED / DEGENERATE / UNMEASURED / OK — never a number when violated."""
        if self.expressible is False:
            return "BLOCKED"
        if (self.saturated or self.vocabulary_leak or self.forgetting_pressure is False
                or self.acquisition_need is False):
            return "DEGENERATE"
        if None in (
            self.expressible,
            self.saturated,
            self.forgetting_pressure,
            self.acquisition_need,
            self.vocabulary_leak,
        ):
            return "UNMEASURED"
        return "OK"


@dataclass(frozen=True, slots=True)
class EnduranceReport:
    timeline_version: str
    seed: int
    checkpoints: tuple[MonthCheckpoint, ...]
    preconditions: PreconditionReport | None
    synthetic: bool = True
    observations: tuple[tuple[str, float, tuple[float, float, float]], ...] = ()

    def for_learner(self, name: str) -> tuple[MonthCheckpoint, ...]:
        return tuple(c for c in self.checkpoints if c.learner == name)


def store_violations(checkpoint: MonthCheckpoint) -> tuple[str, ...]:
    """Every store whose bytes or count exceed ``STORE_CAPS`` at this checkpoint; () = bounded.

    A store the learner reports but the table does not name is itself a
    violation: an uncapped store is exactly what this check exists to catch.
    """
    problems: list[str] = []
    for name, size in checkpoint.store_bytes.items():
        if name not in STORE_CAPS:
            problems.append(f"{name}: no cap declared")
            continue
        byte_cap, count_cap = STORE_CAPS[name]
        count = checkpoint.store_counts.get(name, 0)
        if byte_cap is not None and size > byte_cap:
            problems.append(f"{name}: {size} bytes > {byte_cap}")
        if count_cap is not None and count > count_cap:
            problems.append(f"{name}: {count} items > {count_cap}")
    for group, (members, budget) in STORE_GROUPS.items():
        total = sum(checkpoint.store_bytes.get(m, 0) for m in members)
        if total > budget:
            problems.append(f"{group} ({'+'.join(members)}): {total} bytes > {budget}")
    return tuple(problems)


class _Tracker:
    """Counts promotions from item lineage — the same rule for every learner.

    A promotion is a new (item id, weight) pair, so a re-weighted item — above all the
    THRESHOLD, whose id never changes — counts (review F3). It is *poisoned* when its lineage
    cites a poison capsule. Detector removals are counted too, and attributed to poison when
    they happen in the update right after a poison capsule (review F2).
    """

    def __init__(self, learner: Learner, poison: frozenset[str]) -> None:
        self.learner, self.poison = learner, poison
        self.state = learner.trusted_state()
        self.promoted = self.poisoned = self.removed = self.poison_removed = 0

    def update(self, *, after_poison: bool = False) -> None:
        state = self.learner.trusted_state()
        if state is self.state:
            return
        known = {(item.item_id, item.weight) for item in self.state.items}
        for item in state.items:
            if (item.item_id, item.weight) not in known:
                self.promoted += 1
                self.poisoned += bool(self.poison.intersection(item.lineage.capsule_ids))
        kept = {item.item_id for item in state.detectors()}
        gone = sum(item.item_id not in kept for item in self.state.detectors())
        self.removed += gone
        self.poison_removed += gone if after_poison else 0
        self.state = state

    def take(self) -> tuple[int, int, int, int]:
        taken = (self.promoted, self.poisoned, self.removed, self.poison_removed)
        self.promoted = self.poisoned = self.removed = self.poison_removed = 0
        return taken


def _recall(scores: Sequence[float], families: Sequence[str | None], family: str) -> float | None:
    labels = [1 if f == family else 0 for f in families if f == family or f not in FAMILIES]
    kept = [s for s, f in zip(scores, families, strict=True) if f == family or f not in FAMILIES]
    return recall_at_max_fpr(labels, kept, FPR_BUDGET)[0]


def _checkpoint(learner: Learner, month: CompiledMonth, seen: set[str], tracker: _Tracker,
                rollbacks: int) -> MonthCheckpoint:
    scores = tuple(learner.score(steps, context_id=month.context_id) for steps in month.eval_steps)
    recalls = {f: _recall(scores, month.eval_families, f) if f in month.eval_families else None
               for f in FAMILIES}
    acquisition = {f: recalls[f] if f in month.labelled_families else None for f in FAMILIES}
    retention = {
        f: recalls[f] if f in seen and f not in month.labelled_families else None for f in FAMILIES
    }
    benign = [s for s, f in zip(scores, month.eval_families, strict=True) if f not in FAMILIES]
    threshold = learner.threshold()
    stores = getattr(learner, "stores", lambda: {})()
    promoted, poisoned, removed, poison_removed = tracker.take()
    return MonthCheckpoint(
        month=month.month,
        learner=learner.name,
        acquisition=acquisition,
        retention=retention,
        fp_rate=sum(s >= threshold for s in benign) / len(benign) if benign else None,
        store_bytes={k: v[0] for k, v in stores.items()},
        store_counts={k: v[1] for k, v in stores.items()},
        evictions={k: v[2] for k, v in stores.items()},
        promotions=promoted,
        rollbacks=rollbacks,
        poisoned_promotions=poisoned,
        clean_promotions=promoted - poisoned,
        cost=learner.cost(),
        scores=scores,
        detectors_removed=removed,
        poison_removals=poison_removed,
    )


def run_endurance(compiled: CompiledTimeline, learners: Sequence[Learner],
                  preconditions: PreconditionReport | None = None) -> EnduranceReport:
    """Drive every learner over the identical stream; checkpoint each at every month end."""
    checkpoints: list[MonthCheckpoint] = []
    observations = []
    for learner in learners:
        started = time.perf_counter()
        tracker = _Tracker(learner, compiled.poison_ids)
        seen: set[str] = set()
        for month in compiled.months:
            for event in month.events:
                if event.kind == "epoch" and event.decision and event.identity is not None:
                    learner.on_epoch(event.decision, event.identity, sequence=event.sequence)
                elif event.capsule is not None:
                    learner.observe(event.capsule, sequence=event.sequence)
                tracker.update(after_poison=event.capsule is not None
                               and event.capsule.capsule_id in compiled.poison_ids)
            last = month.events[-1].sequence if month.events else 0
            learner.consolidate(simulated_snapshot(pressure=month.pressure), sequence=last)
            tracker.update()
            seen.update(month.labelled_families)
            checkpoints.append(
                _checkpoint(learner, month, seen, tracker, getattr(learner, "rollback_count", 0))
            )
        observations.append((learner.name, round(time.perf_counter() - started, 3), loadavg()))
    return EnduranceReport(compiled.version, compiled.seed, tuple(checkpoints), preconditions,
                           observations=tuple(observations))


# --- preconditions E1-E5 ---------------------------------------------------------------


def _eval_pool(compiled: CompiledTimeline) -> tuple[
    list[tuple[EncodedStep, ...]], list[str | None], list[str]
]:
    steps = [s for m in compiled.months for s in m.eval_steps]
    families = [f for m in compiled.months for f in m.eval_families]
    contexts = [m.context_id for m in compiled.months for _ in m.eval_steps]
    return steps, families, contexts


def _lineage_dphi(steps: Sequence[EncodedStep]) -> float:
    totals: Counter[str] = Counter()
    for step in steps:
        totals[step.source_group] += max(0.0, step.delta_phi)
    return max(totals.values(), default=0.0)


def _bag_loo(steps: Sequence[tuple[EncodedStep, ...]], labels: Sequence[int]) -> list[float]:
    """Order-free control, leave-one-out: the positive rate of the OTHER sessions with this bag."""
    bags = [tuple(sorted(Counter(s.relation for s in session).items())) for session in steps]
    total, positive = Counter(bags), Counter(b for b, y in zip(bags, labels, strict=True) if y)
    prior = sum(labels) / len(labels)
    return [
        (positive[b] - y + prior) / (total[b] - 1 + 1) for b, y in zip(bags, labels, strict=True)
    ]


def _final(report: EnduranceReport, learner: str, family: str, kind: str) -> float | None:
    for checkpoint in reversed(report.for_learner(learner)):
        value = getattr(checkpoint, kind).get(family)
        if value is not None:
            return value
    return None


def check_preconditions(compiled: CompiledTimeline) -> PreconditionReport:
    """E1-E5 exactly as spec §4.20. Any violation makes the verdict BLOCKED or DEGENERATE."""
    steps, families, contexts = _eval_pool(compiled)
    labels = [1 if f in FAMILIES else 0 for f in families]
    details: list[str] = []
    oracle = oracle_detectors([_GenesisPlan(compiled.genesis)])
    oracle_scores = [
        score_session(oracle, s, context_id=c).score for s, c in zip(steps, contexts, strict=True)
    ]
    recalls = {f: _recall(oracle_scores, families, f) for f in FAMILIES if f in families}
    expressible = None if not recalls else all(
        r is not None and r >= EXPRESSIBLE_RECALL for r in recalls.values()
    )
    details.append(f"E1 oracle recall at FPR {FPR_BUDGET}: {recalls}")
    never, naive = NeverUpdate(compiled.genesis), NaiveFinetune(
        compiled.genesis, detector_capacity=CAPACITY_SWEEP[0]
    )
    report = run_endurance(compiled, [never, naive])
    never_scores = [s for c in report.for_learner(never.name) for s in c.scores]
    aps = {
        "lineage_dphi": average_precision(labels, [_lineage_dphi(s) for s in steps]),
        "any_escalation": average_precision(
            labels, [float(any(is_escalating(x) for x in s)) for s in steps]
        ),
        "never_update": average_precision(labels, never_scores),
    }
    measured = [v for v in aps.values() if v is not None]
    saturated = None if len(measured) < len(aps) else any(v > SATURATION_AP for v in measured)
    details.append(f"E2 control AP (saturated iff any > {SATURATION_AP}): {aps}")
    never_f1, naive_f1 = _final(report, never.name, "F1", "retention"), _final(
        report, naive.name, "F1", "retention"
    )
    pressure = (None if never_f1 is None or naive_f1 is None
                else naive_f1 <= never_f1 - FORGETTING_MIN_DROP)
    trace = [(c.month, c.retention.get("F1")) for c in report.for_learner(naive.name)]
    never_trace = [(c.month, c.retention.get("F1")) for c in report.for_learner(never.name)]
    details.append(f"E3 F1 retention at the last month, naive (capacity {CAPACITY_SWEEP[0]}) "
                   f"{naive_f1} vs "
                   f"never-update {never_f1}; per-month naive {trace}; never-update {never_trace}")
    acq = {f: _final(report, never.name, f, "acquisition") for f in ("F2", "F3")}
    acquired = [v for v in acq.values() if v is not None]
    need = None if len(acquired) < len(acq) else all(v <= ACQUISITION_NEED_MAX for v in acquired)
    details.append(f"E4 never-update acquisition (need iff all <= {ACQUISITION_NEED_MAX}): {acq}")
    bag_ap = average_precision(labels, _bag_loo(steps, labels)) if any(labels) else None
    base = sum(labels) / len(labels) if labels else None
    leak = None if bag_ap is None or base is None else abs(bag_ap - base) > VOCABULARY_LEAK_MAX
    details.append(f"E5 leave-one-out bag-of-relations AP {bag_ap} vs base rate {base}")
    return PreconditionReport(expressible, saturated, pressure, need, leak, tuple(details))


@dataclass(frozen=True, slots=True)
class _GenesisPlan:
    identity: SystemIdentity


# --- ablation ------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AblationRow:
    core_id: str
    flag: str
    control: str
    metric: str
    full: float | None
    ablated: float | None
    delta: float | None
    firing_count: int
    verdict: str


def _metric(report: EnduranceReport, learner: str, metric: str) -> float | None:
    points = report.for_learner(learner)
    if not points:
        return None
    if metric == "retention_F1":
        return _final(report, learner, "F1", "retention")
    if metric == "mean_recall":
        last = points[-1]
        values = [v for f in FAMILIES for v in (last.acquisition.get(f), last.retention.get(f))
                  if v is not None]
        return statistics.fmean(values) if values else None
    if metric == "fp_rate":
        return points[-1].fp_rate
    if metric == "poisoned_promotions":
        return float(sum(c.poisoned_promotions for c in points))
    return _months_to_adapt(points, int(metric.rsplit("M", 1)[-1]))


def _months_to_adapt(points: Sequence[MonthCheckpoint], after: int) -> float | None:
    before = next((c.fp_rate for c in points if c.month == after - 1), None)
    if before is None:
        return None
    for c in points:
        if c.month >= after and c.fp_rate is not None and c.fp_rate <= before + EPS_FP_RATE:
            return float(c.month - after)
    return None


#: (core id, flag, control, metric, lower-is-better, firing counter)
_ABLATIONS: tuple[tuple[str, str, str, str, bool, Callable[[StageSixLearner], int]], ...] = (
    ("HEL-F07", "half_life", "LRU order", "retention_F1", False,
     lambda s: s.consolidator.stats().half_life_decisions_differing_from_lru),
    ("HEL-F08", "plasticity_field", "uniform_mask", "mean_recall", False,
     lambda s: s.chamber.stats().field_only_freezes),
    ("HEL-F10", "competition", "NEWEST_WINS", "fp_rate", True,
     lambda s: s.chamber.stats().competition_non_replace),
    ("HEL-F15", "value_aware_rehearsal", "reservoir at equal bytes", "retention_F1", False,
     lambda s: s.consolidator.stats().rehearsal_differing_from_reservoir),
    ("HEL-F19", "drift_discriminator", "corroborated => legitimate", "poisoned_promotions", True,
     lambda s: s.counters["drift_differs_from_rule"]),
    ("HEL-F21", "resurrection", "relearn", "months_to_adapt_M6", True,
     lambda s: s.registry.resurrections),
    ("HEL-F25", "half_life", "LRU retire", "retention_F1", False,
     lambda s: s.consolidator.stats().half_life_decisions_differing_from_lru),
    ("gateway:independence", "independence_check", "off", "poisoned_promotions", True,
     lambda s: s.gateway.stats().get("single_source_refusals")),
    ("gateway:homeostasis", "homeostasis", "Stage 2 ESCALATION_PROPERTIES only",
     "poisoned_promotions", True,
     lambda s: s.gateway.stats().get("beyond_stage2")
     + s.gateway.stats().get("normalization_findings")),
)


def _verdict(delta: float | None, firing: int, precondition: str, metric: str) -> str:
    if firing == 0:
        return "INERT"
    if precondition == "BLOCKED" and metric in ("retention_F1", "mean_recall"):
        return "UNMEASURED"
    if precondition == "DEGENERATE" and metric in ("retention_F1", "mean_recall"):
        return "DEGENERATE"
    if delta is None:
        return "UNMEASURED"
    if delta > EPS_SECURITY:
        return "JUSTIFIED"
    return "HARMFUL" if delta < -EPS_SECURITY else "NOT_YET_JUSTIFIED"


def run_ablation(
    compiled: CompiledTimeline, *, preconditions: PreconditionReport | None = None
) -> tuple[AblationRow, ...]:
    """Full Stage 6 vs Stage 6 with one flag replaced by its §7 control, per OPTIONAL mechanism."""
    status = (preconditions or check_preconditions(compiled)).verdict
    full = StageSixLearner(compiled.genesis, seed=compiled.seed)
    full_report = run_endurance(compiled, [full])
    # The controller runs G4 itself with no switch (reported blocker): HEL-F11 is UNMEASURED.
    rows = [AblationRow("HEL-F11", "counterfactual_variants", "plain replay (G2 only)",
                        "poisoned_or_regressing", None, None, None, 0, "UNMEASURED")]
    reports: dict[str, EnduranceReport] = {}
    for core_id, flag, control, metric, lower, firing in _ABLATIONS:
        if flag not in reports:
            ablated = StageSixLearner(
                compiled.genesis,
                config=replace(StageSixConfig(), **{flag: False}),
                seed=compiled.seed,
                name=f"stage6-no-{flag}",
            )
            reports[flag] = run_endurance(compiled, [ablated])
        report = reports[flag]
        a = _metric(full_report, full.name, metric)
        b = _metric(report, report.checkpoints[0].learner if report.checkpoints else "", metric)
        delta = None if a is None or b is None else (b - a if lower else a - b)
        count = int(firing(full))
        rows.append(
            AblationRow(
                core_id, flag, control, metric, a, b, delta, count, _verdict(
                    delta, count, status, metric
                )
            )
        )
    return tuple(rows)
