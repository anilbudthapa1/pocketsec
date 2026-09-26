"""D6.15 / D6.20 — the eleven poisoning arms of spec §4.15, built as capsule streams.

"A defence that has never been attacked in a test is a docstring." This module
builds the attacks and ``run_poison_suite`` (re-exported by ``endurance``, where
the spec places it) runs every arm against the Stage 6 learner and its controls
(NaiveFinetune, Stage2Only, accept-nothing) at every multiplier.

§0 measured that Stage 2's gate already stops Stage 2's own poison suite, so
most arms here are aimed at what Stage 2 *cannot* see: an attacker who owns a
pattern key and repeats across a corroborated upgrade (P1), the same through
forked children (P1b), timed anchor capture after a genuine upgrade — the
residual risk ``QuarantineBuffer.record_epoch_decision`` states in its own
docstring (P2b), label and teacher poison (P3, P3b), artefact tampering (P4a,
P4b), a crafted foreign baseline (P4c), epoch manipulation (P5) and flooding
(P6). P2 is Stage 2's own slow-drift walk, lifted out of
``stage2.labs.poison_suite.build_poison_suite`` rather than re-typed.

What an arm carries, so a run can be *scored* rather than narrated:

* ``poisoned`` capsules — must be non-empty (the arm fired);
* ``poison_steps`` / ``target_episodes`` — the attack's goal, as probes: steps
  the attacker wants explained as normal (DATA / SLOW_DRIFT) or held-out
  episodes the attacker wants to stop alerting (LABEL);
* ``clean_steps`` / ``clean_episodes`` — the legitimate learning the same run
  should still achieve, so "zero poisoned promotions" cannot be bought by
  learning nothing (F10).

P4a and P4b attack artefacts, not the capsule stream: their scenario is a clean
learning run and ``poisoned`` holds the capsules whose learning produces the
artefact the runner then tampers with. Baseline learners have no artefact
pipeline at all, so those two arms are measured on Stage 6 only.

Everything is synthetic. ``simulated_teacher_labels`` keeps its ``simulated_``
prefix because no teacher model exists in this repository (ADR-0046 precedent).
"""

from __future__ import annotations

import random
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.epoch.model import EpochDecision, SystemIdentity
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage2.adaptation.epoch_guard import SystemChangeSignal
from pocketsec.stage2.adaptation.quarantine import meaning_distance, pattern_key
from pocketsec.stage2.labs.poison_suite import (
    POISON_TECHNIQUE_LEGITIMATE,
    POISON_TECHNIQUE_SLOW_DRIFT,
    build_poison_suite,
    poison_lineage,
)
from pocketsec.stage6.capsule.experience_capsule import (
    CapsuleKind,
    ContaminationFlag,
    EncodedStep,
    ExperienceCapsuleV1,
    LabelAssertion,
    LabelOrigin,
    SourceClass,
    SourceProvenance,
    capsule_from_label,
    reseal_capsule,
    source_group_of,
)
from pocketsec.stage6.chamber.evolution import EvolutionCandidate
from pocketsec.stage6.labs.continual_baselines import (
    AcceptNothing,
    Learner,
    NaiveFinetune,
    Stage2Only,
)
from pocketsec.stage6.labs.endurance_corpus import (
    ANALYST_GROUPS,
    ENDURANCE_SEED,
    POISON_ANALYST_GROUP,
    ROUTINE_POOLS,
    EnduranceSession,
    IdentityMint,
    SessionLabel,
    apply_signal,
    attacker_session,
    block_session,
    compile_session,
    label_provenance,
    simulated_snapshot,
)
from pocketsec.stage6.memory.semantic import ALL_CONTEXTS, TrustedKnowledgeState, is_escalating
from pocketsec.stage6.promotion.controller import RollbackTrigger

__all__ = [
    "ARM_NAMESPACE",
    "CLEAN_BACKGROUND_SESSIONS",
    "NEGATIVE_PROBES",
    "POISON6_VERSION",
    "POISON_ARMS6",
    "POISON_MULTIPLIERS",
    "TEACHER_GROUP",
    "ArmEvent",
    "PoisonArm",
    "PoisonClass",
    "PoisonReport",
    "PoisonRow",
    "PoisonScenario",
    "alerts",
    "arm_verdicts",
    "build_poison_arm",
    "detected",
    "explains",
    "run_arm",
    "run_poison_suite",
    "simulated_teacher_labels",
]

POISON6_VERSION = "stage6-poison-v0.1.0"
#: Disjoint from Stage 2 (200_000 / 300_000) and the endurance timeline (600_000).
ARM_NAMESPACE: int = 2_000_000
#: Clean traffic per arm. Stage 6's shadow needs MIN_SHADOW_SESSIONS sampled every
#: SHADOW_SAMPLE_EVERY-th session (128 sessions) before any candidate can be
#: promoted; an arm shorter than that measures only that Stage 6 is slow.
CLEAN_BACKGROUND_SESSIONS: int = 160
TEACHER_GROUP = "teacher:sim-0"
#: Poison volume multipliers every arm runs at (spec §4.21).
POISON_MULTIPLIERS: tuple[int, ...] = (1, 4, 16)
#: Held-out routine sessions per arm that a detected episode must outscore.
NEGATIVE_PROBES: int = 4
_TEACHER_ERROR_SHARE = 0.5
_CONSOLIDATE_EVERY = 16


class PoisonClass(StrEnum):
    DATA = "DATA"
    LABEL = "LABEL"
    MODEL = "MODEL"
    SLOW_DRIFT = "SLOW_DRIFT"


@dataclass(frozen=True, slots=True)
class PoisonArm:
    arm_id: str
    poison_class: PoisonClass
    title: str
    attacks_mechanism: str


_D, _L, _M, _S = PoisonClass.DATA, PoisonClass.LABEL, PoisonClass.MODEL, PoisonClass.SLOW_DRIFT
POISON_ARMS6: tuple[PoisonArm, ...] = (
    PoisonArm("P1", _D, "single-source staging repetition across corroborated epochs",
              "source independence"),
    PoisonArm("P1b", _D, "fork-spray: the same step from MIN_INDEPENDENT_GROUPS+1 children",
              "source independence (attacked)"),
    PoisonArm("P2", _S, "Stage 2's slow-drift walk across a corroborated change",
              "fixed anchor + homeostasis"),
    PoisonArm("P2b", _S, "timed anchor capture right after a genuine upgrade",
              "Stage 6 independence + G5"),
    PoisonArm("P3", _L, "one analyst group asserts BENIGN on F2 episodes",
              "label quorum + homeostasis"),
    PoisonArm("P3b", _L, "simulated teacher labels with a systematic error share on F1/F2",
              "teacher-is-weak rule"),
    PoisonArm("P4a", _M, "candidate bytes altered after the chamber issued it", "G1 integrity"),
    PoisonArm("P4b", _M, "a fossil corrupted on disk before a rollback",
              "fossil integrity + fallback"),
    PoisonArm("P4c", _M, "crafted foreign baseline explaining an attack's staging step",
              "G5 + trigger concentration + foreign path"),
    PoisonArm("P5", _S, "repeated uncorroborated identity changes",
              "Stage 1 corroboration + context registry"),
    PoisonArm("P6", _D, "quarantine flooding past the label index",
              "bounded, refuse-not-evict, value-aware eviction"),
)
_ARMS = {arm.arm_id: arm for arm in POISON_ARMS6}


@dataclass(frozen=True, slots=True)
class ArmEvent:
    """One stream event: a capsule to offer, an epoch decision, or a consolidation tick."""

    kind: str  # "capsule" | "epoch" | "consolidate"
    capsule: ExperienceCapsuleV1 | None = None
    poisoned: bool = False
    decision: EpochDecision | None = None
    identity: SystemIdentity | None = None


@dataclass(frozen=True, slots=True)
class PoisonScenario:
    """One arm at one multiplier: the stream, and the probes that score it."""

    arm: PoisonArm
    clean: tuple[ExperienceCapsuleV1, ...]
    poisoned: tuple[ExperienceCapsuleV1, ...]
    signals: tuple[tuple[int, SystemChangeSignal], ...]
    events: tuple[ArmEvent, ...] = ()
    genesis: SystemIdentity = SystemIdentity()
    poison_steps: tuple[EncodedStep, ...] = ()
    clean_steps: tuple[EncodedStep, ...] = ()
    target_episodes: tuple[tuple[str, tuple[EncodedStep, ...], str], ...] = ()
    clean_episodes: tuple[tuple[str, tuple[EncodedStep, ...], str], ...] = ()
    #: Held-out routine sessions. An episode counts as *detected* only when it
    #: outscores every one of these: "alerts on everything" is not detection.
    negative_probes: tuple[tuple[str, tuple[EncodedStep, ...], str], ...] = ()
    multiplier: int = 1
    #: P5's poison is a signal, not a capsule: the uncorroborated changes offered.
    poisoned_signals: int = 0

    @property
    def poisoned_offered(self) -> int:
        return len(self.poisoned) + self.poisoned_signals


def simulated_teacher_labels(
    sessions: Sequence[EnduranceSession],
    *,
    error_share: float,
    seed: int,
    capsule_ids: Mapping[str, str] | None = None,
) -> tuple[LabelAssertion, ...]:
    """A simulated teacher: correct labels, except F1/F2 attacks flipped to BENIGN at a share.

    The error is systematic (one direction, two families), which is what a biased
    teacher looks like. ``capsule_ids`` maps session id -> capsule id; a session it
    does not map gets an unbound target (``""``), because capsule ids exist only
    after compilation and a label is never pointed at a guessed id. Every
    assertion has origin TEACHER.
    """
    if not 0.0 <= error_share <= 1.0:
        raise ValueError(f"error_share must be in [0, 1], got {error_share}")
    rng = random.Random(seed)
    ids = capsule_ids or {}
    out: list[LabelAssertion] = []
    for session in sessions:
        truth = Verdict.MALICIOUS if session.family in ("F1", "F2", "F3") else Verdict.BENIGN
        flip = rng.random() < error_share and session.family in ("F1", "F2")
        out.append(LabelAssertion(
            verdict=Verdict.BENIGN if flip else truth, origin=LabelOrigin.TEACHER,
            asserted_by=TEACHER_GROUP, target_capsule_id=ids.get(session.session_id, ""),
        ))
    return tuple(out)


class _ArmBuilder:
    """Compiles one arm's sessions through its own Stage 1 pipeline, in stream order."""

    def __init__(self, arm: PoisonArm, *, multiplier: int, seed: int, background: int) -> None:
        self.arm, self.multiplier, self.seed, self.background = arm, multiplier, seed, background
        index = POISON_ARMS6.index(arm)
        self.mint = IdentityMint(
            rng=random.Random(seed * 131 + index), namespace=ARM_NAMESPACE + index * 200_000
        )
        self.pools = (ROUTINE_POOLS["A"], ROUTINE_POOLS["B"])
        self.identities = tuple(
            SystemIdentity(kernel_id="6.1.0", package_digest=f"pkg-{arm.arm_id}-{side}",
                           service_digest=f"svc-{side}")
            for side in ("a", "b")
        )
        self.pipeline = Stage1Pipeline(identity=self.identities[0])
        self.events: list[ArmEvent] = []
        self.clean: list[ExperienceCapsuleV1] = []
        self.poisoned: list[ExperienceCapsuleV1] = []
        self.signals: list[tuple[int, SystemChangeSignal]] = []
        self.context = 0
        self.offset = 0
        self.sequence = 0
        self.episodes = 0  # TRANSITION_EPISODE capsules offered; every _CONSOLIDATE_EVERY-th ticks

    def offer(
        self, session: EnduranceSession, *, poisoned: bool, poison_labels: bool = False
    ) -> ExperienceCapsuleV1:
        self.offset += 1
        self.sequence += 10
        episode, labels = compile_session(
            self.pipeline, session, offset=self.offset, sequence=self.sequence
        )
        (self.poisoned if poisoned else self.clean).append(episode)
        self.events.append(ArmEvent("capsule", episode, poisoned))
        for label in labels:
            (self.poisoned if poison_labels else self.clean).append(label)
            self.events.append(ArmEvent("capsule", label, poison_labels))
        self.episodes += 1
        if self.episodes % _CONSOLIDATE_EVERY == 0:
            self.events.append(ArmEvent("consolidate"))
        return episode

    def extra(self, capsule: ExperienceCapsuleV1, *, poisoned: bool) -> None:
        (self.poisoned if poisoned else self.clean).append(capsule)
        self.events.append(ArmEvent("capsule", capsule, poisoned))

    def routine(self, count: int) -> list[ExperienceCapsuleV1]:
        pool = self.pools[self.context]
        return [
            self.offer(block_session(self.mint, pool, None, month=0, role="routine"),
                       poisoned=False)
            for _ in range(count)
        ]

    def change(self, *, corroborated: bool = True) -> None:
        changed = frozenset({"package_digest", "service_digest"})
        signal = SystemChangeSignal(
            changed=changed, corroborated=changed if corroborated else frozenset()
        )
        target = self.identities[1 - self.context]
        decision = apply_signal(self.pipeline, target, signal, now_ns=self.offset)
        self.signals.append((len(self.clean) + len(self.poisoned), signal))
        if decision is not None:
            self.events.append(ArmEvent("epoch", decision=decision, identity=target))
            if decision.transitioned:
                self.context = 1 - self.context

    def attacker(self, arm_id: str, count: int) -> list[ExperienceCapsuleV1]:
        return [
            self.offer(attacker_session(self.mint, arm_id, month=0, seed=self.seed + i),
                       poisoned=True)
            for i in range(count)
        ]

    def family(self, cls: str, labels: tuple[SessionLabel, ...], *,
               poisoned: bool = False) -> tuple[EnduranceSession, ExperienceCapsuleV1]:
        session = block_session(self.mint, self.pools[self.context], cls, month=0,
                                role="poison" if poisoned else "attack", labels=labels)
        return session, self.offer(session, poisoned=False, poison_labels=poisoned)

    def probe(self, cls: str | None) -> tuple[str, tuple[EncodedStep, ...], str]:
        """A held-out episode: compiled on this pipeline, never offered to a learner."""
        self.offset += 1
        session = block_session(self.mint, self.pools[self.context], cls, month=0, role="eval")
        episode, _ = compile_session(self.pipeline, session, offset=self.offset, sequence=0)
        return episode.capsule_id, episode.steps, episode.context_id

    def scenario(
        self,
        *,
        poison_steps: Sequence[EncodedStep] = (),
        clean_steps: Sequence[EncodedStep] = (),
        target_episodes: Sequence[tuple[str, tuple[EncodedStep, ...], str]] = (),
        clean_episodes: Sequence[tuple[str, tuple[EncodedStep, ...], str]] = (),
        poisoned_signals: int = 0,
    ) -> PoisonScenario:
        """Seal the arm. A probe whose meaning both sides share scores neither side."""
        poison_keys = {_meaning_key(s) for s in poison_steps}
        probed = bool(target_episodes or clean_episodes)
        negatives = tuple(self.probe(None) for _ in range(NEGATIVE_PROBES)) if probed else ()
        clean_keys = {_meaning_key(s) for s in _groups_steps(self.clean)}
        clean_steps = [s for s in clean_steps if not is_escalating(s)]
        return PoisonScenario(
            arm=self.arm,
            clean=tuple(self.clean),
            poisoned=tuple(self.poisoned),
            signals=tuple(self.signals),
            events=tuple(self.events),
            genesis=self.identities[0],
            poison_steps=tuple(s for s in poison_steps if _meaning_key(s) not in clean_keys),
            clean_steps=tuple(s for s in clean_steps if _meaning_key(s) not in poison_keys),
            target_episodes=tuple(target_episodes),
            clean_episodes=tuple(clean_episodes),
            negative_probes=negatives,
            multiplier=self.multiplier,
            poisoned_signals=poisoned_signals,
        )


def _meaning_key(step: EncodedStep) -> tuple[int, tuple[float, ...]]:
    return step.relation, step.meaning()


def _groups_steps(capsules: Sequence[ExperienceCapsuleV1], groups: set[str] | None = None,
                  *, escalating: bool = True) -> tuple[EncodedStep, ...]:
    """Distinct-meaning steps, optionally only these lineages, optionally only non-escalating.

    Poison probes keep escalating steps: a baseline anchored on credential meaning
    is the harm G5 names even though the score never lets it hide such a step.
    Clean probes are non-escalating only — legitimate normality never includes
    an escalation.
    """
    seen: dict[tuple[int, tuple[float, ...]], EncodedStep] = {}
    for capsule in capsules:
        for step in capsule.steps:
            if (groups is None or step.source_group in groups) and (
                escalating or not is_escalating(step)
            ):
                seen.setdefault(_meaning_key(step), step)
    return tuple(seen.values())


_MAL = tuple(SessionLabel(Verdict.MALICIOUS, LabelOrigin.ANALYST, g) for g in ANALYST_GROUPS)


def _data_arm(b: _ArmBuilder, arm_id: str) -> PoisonScenario:
    """P1 / P1b / P2b: attacker sessions before and after a genuine corroborated upgrade."""
    half = b.background // 2
    per_phase = 2 * b.multiplier
    clean = b.routine(half - per_phase)
    poison = [] if arm_id == "P2b" else b.attacker(arm_id, per_phase)
    b.change()
    if arm_id == "P2b":
        poison += b.attacker("P2b", 1)  # lands first after the anchors are released
    poison += b.attacker(arm_id, per_phase)
    clean += b.routine(half)
    poison += b.attacker(arm_id, per_phase)
    return b.scenario(poison_steps=_groups_steps(poison), clean_steps=_groups_steps(clean))


def _slow_drift_arm(b: _ArmBuilder) -> PoisonScenario:
    """P2: Stage 2's own suite — its slow-drift sessions poisoned, its legitimate ones clean."""
    suite = build_poison_suite(count=max(12, 12 * b.multiplier), seed=b.seed)
    clean_groups: set[str] = set()
    poison_groups: set[str] = set()
    b.routine(b.background // 2)
    for index, scenario in enumerate(suite):
        if index == len(suite) // 2:
            b.change()
        lineage = poison_lineage(scenario)
        poisoned = scenario.technique == POISON_TECHNIQUE_SLOW_DRIFT
        if not poisoned and scenario.technique != POISON_TECHNIQUE_LEGITIMATE:
            continue
        session = EnduranceSession(
            session_id=scenario.name,
            month=0,
            scenario=scenario,
            family="P2",
            role="poison" if poisoned else "routine",
        )
        b.offer(session, poisoned=poisoned)
        if poisoned and lineage is not None:
            poison_groups.add(source_group_of(lineage))
    b.routine(b.background // 2)
    poison_steps = _groups_steps(b.poisoned, poison_groups)
    clean_groups = {s.source_group for c in b.clean for s in c.steps} - poison_groups
    return b.scenario(poison_steps=poison_steps, clean_steps=_groups_steps(b.clean, clean_groups))


def _label_arm(b: _ArmBuilder, arm_id: str) -> PoisonScenario:
    """P3 / P3b: learn F2 (and F1) from a clean quorum, then poison their labels."""
    families = ("F2",) if arm_id == "P3" else ("F1", "F2")
    clean_probes = [b.probe(f) for f in families for _ in range(2)]
    b.routine(b.background // 2)
    for _ in range(3):
        for fam in families:
            b.family(fam, _MAL)
    b.routine(b.background // 2)
    for _ in range(2 * b.multiplier):
        for fam in families:
            if arm_id == "P3":
                b.family(
                    fam,
                    (SessionLabel(Verdict.BENIGN, LabelOrigin.ANALYST, POISON_ANALYST_GROUP),),
                    poisoned=True,
                )
                continue
            session, episode = b.family(fam, ())
            (assertion,) = simulated_teacher_labels(
                [session],
                error_share=_TEACHER_ERROR_SHARE,
                seed=b.seed + len(b.events),
                capsule_ids={session.session_id: episode.capsule_id},
            )
            b.extra(_teacher_capsule(b, assertion), poisoned=True)
    b.routine(_CONSOLIDATE_EVERY * 2)
    return b.scenario(target_episodes=tuple(clean_probes), clean_episodes=tuple(clean_probes))


def _teacher_capsule(b: _ArmBuilder, assertion: LabelAssertion) -> ExperienceCapsuleV1:
    b.sequence += 1
    provenance = SourceProvenance(
        source_class=SourceClass.TEACHER,
        source_id=TEACHER_GROUP,
        independence_group=TEACHER_GROUP,
        label_origin=LabelOrigin.TEACHER,
        transformation_lineage=("lab.simulated_teacher",),
        host_id="lab-host-01",
    )
    return capsule_from_label(assertion, epoch=b.pipeline.epoch.current, provenance=provenance,
                              sequence=b.sequence)


def _model_arm(b: _ArmBuilder, arm_id: str) -> PoisonScenario:
    """P4a / P4b: a clean F2-learning run whose artefacts the runner tampers with."""
    probes = [b.probe("F2") for _ in range(2)]
    b.routine(b.background // 2)
    learned = [b.family("F2", _MAL)[1] for _ in range(3)]
    b.routine(b.background // 2)
    scenario = b.scenario(clean_episodes=tuple(probes), target_episodes=tuple(probes))
    # The capsules whose learning produces the artefact the runner will tamper with.
    return replace(scenario, poisoned=tuple(learned))


def _foreign_arm(b: _ArmBuilder) -> PoisonScenario:
    """P4c: foreign 'baselines' carrying exactly the attack's staging meaning."""
    clean = b.routine(b.background)
    template = b.attacker("P2b", 1)[0]
    b.poisoned.remove(template)
    b.events = [e for e in b.events if e.capsule is not template]
    flags = template.contamination_flags | {ContaminationFlag.FOREIGN_ORIGIN}
    provenance = SourceProvenance(source_class=SourceClass.FOREIGN_HOST, source_id="fleet:peer-7",
                                  independence_group="fleet:peer-7", label_origin=LabelOrigin.WEAK,
                                  transformation_lineage=("fleet.package",), host_id="peer-7")
    for i in range(4 * b.multiplier):
        forged = reseal_capsule(
            template, kind=CapsuleKind.FOREIGN_PACKAGE, source_provenance=provenance,
            contamination_flags=flags, created_sequence=template.created_sequence + i + 1,
        )
        b.extra(forged, poisoned=True)
    return b.scenario(poison_steps=_groups_steps([template]), clean_steps=_groups_steps(clean))


def _epoch_arm(b: _ArmBuilder) -> PoisonScenario:
    """P5: uncorroborated identity changes, then one genuine corroborated change."""
    b.routine(b.background // 2)
    for _ in range(3 * b.multiplier):
        b.change(corroborated=False)
        b.routine(1)
    b.change()
    b.routine(b.background // 2)
    return b.scenario(poisoned_signals=3 * b.multiplier)


def _flood_arm(b: _ArmBuilder) -> PoisonScenario:
    """P6: legitimate F2 episodes, a flood past the label index, then their labels."""
    probes = [b.probe("F2") for _ in range(2)]
    b.routine(b.background // 2)
    held: list[tuple[ExperienceCapsuleV1, tuple[SessionLabel, ...]]] = []
    for _ in range(3):
        session = block_session(b.mint, b.pools[b.context], "F2", month=0, role="attack")
        held.append((b.offer(session, poisoned=False), _MAL))
    flood = b.attacker("P1", 64 * b.multiplier)
    for episode, labels in held:
        for label in labels:
            b.sequence += 1
            assertion = LabelAssertion(
                verdict=label.verdict, origin=label.origin, asserted_by=label.group,
                target_capsule_id=episode.capsule_id,
            )
            b.extra(capsule_from_label(assertion, epoch=b.pipeline.epoch.current,
                                       provenance=label_provenance(label), sequence=b.sequence),
                    poisoned=False)
    b.routine(b.background // 2)
    return b.scenario(poison_steps=_groups_steps(flood), clean_episodes=tuple(probes))


def build_poison_arm(arm_id: str, *, multiplier: int, seed: int,
                     background: int = CLEAN_BACKGROUND_SESSIONS) -> PoisonScenario:
    """Build arm ``arm_id`` with its poison volume scaled by ``multiplier`` (clean volume fixed).

    ``background`` is the clean routine traffic; below the shadow's 128-session
    requirement Stage 6 cannot promote anything, which a caller may want to show.
    """
    if arm_id not in _ARMS:
        raise ValueError(f"unknown arm {arm_id!r}; known: {sorted(_ARMS)}")
    if multiplier < 1:
        raise ValueError("multiplier must be >= 1")
    if background < 4:
        raise ValueError("background must be >= 4 sessions")
    b = _ArmBuilder(_ARMS[arm_id], multiplier=multiplier, seed=seed, background=background)
    if arm_id in ("P1", "P1b", "P2b"):
        scenario = _data_arm(b, arm_id)
    elif arm_id == "P2":
        scenario = _slow_drift_arm(b)
    elif arm_id in ("P3", "P3b"):
        scenario = _label_arm(b, arm_id)
    elif arm_id in ("P4a", "P4b"):
        scenario = _model_arm(b, arm_id)
    elif arm_id == "P4c":
        scenario = _foreign_arm(b)
    elif arm_id == "P5":
        scenario = _epoch_arm(b)
    else:
        scenario = _flood_arm(b)
    if scenario.poisoned_offered == 0:
        raise RuntimeError(f"arm {arm_id} offered no poisoned capsule; it did not fire")
    return scenario


# --- scoring an arm: the attack's goal and the legitimate goal, from probes ---------------


@dataclass(frozen=True, slots=True)
class PoisonRow:
    arm_id: str
    poison_class: str
    learner: str
    multiplier: int
    poisoned_offered: int
    poisoned_promotions: int | None
    poisoned_rate: float | None
    clean_promotions: int | None
    clean_rate: float | None
    detail: str = ""


@dataclass(frozen=True, slots=True)
class PoisonReport:
    rows: tuple[PoisonRow, ...]
    arm_verdicts: Mapping[str, str]
    synthetic: bool = True


def explains(state: TrustedKnowledgeState, step: EncodedStep, context_id: str) -> bool:
    key, meaning = pattern_key(step.to_encoded()), step.meaning()
    return any(item.pattern_key == key and meaning_distance(meaning, item.anchor) <= item.weight
               and (context_id in item.context_ids or ALL_CONTEXTS in item.context_ids)
               for item in state.baselines())


def alerts(learner: Learner, probe: tuple[str, tuple[EncodedStep, ...], str]) -> bool:
    return learner.score(probe[1], context_id=probe[2]) >= learner.threshold()


def detected(learner: Learner, probe: tuple[str, tuple[EncodedStep, ...], str],
             negatives: Sequence[tuple[str, tuple[EncodedStep, ...], str]]) -> bool:
    """Alerts AND outscores every held-out routine session.

    A learner whose genesis state alerts on everything (score = the unexplained
    term = the threshold) would otherwise "detect" every probe and "keep" every
    target through any label poison — accept-nothing would look perfect.
    """
    score = learner.score(probe[1], context_id=probe[2])
    ceiling = max((learner.score(n[1], context_id=n[2]) for n in negatives), default=float("-inf"))
    return score >= learner.threshold() and score > ceiling


def run_arm(scenario: PoisonScenario, learner: Learner) -> PoisonRow:
    """Offer the arm's stream; score the attack's goal and the legitimate goal from probes.

    Poisoned promotions = poison steps some trusted BASELINE came to explain +
    targets detected before the first poisoned capsule and undetected at any later
    point + context switches an uncorroborated change forced. A LABEL/MODEL arm
    whose targets this learner never detected cannot be suppressed: that row is
    ``None`` (VACUOUS), never a reassuring zero.
    """
    poison_hit: set[int] = set()
    suppressed: set[int] = set()
    target_before: set[int] | None = None
    epoch_hits = 0
    negatives = scenario.negative_probes
    for tick, event in enumerate(scenario.events, start=1):
        if event.kind == "epoch" and event.decision is not None and event.identity is not None:
            before = learner.trusted_state().active_context
            learner.on_epoch(event.decision, event.identity, sequence=tick)
            changed = learner.trusted_state().active_context != before
            epoch_hits += int(changed and not event.decision.transitioned)
        elif event.kind == "consolidate":
            learner.consolidate(simulated_snapshot(pressure=False), sequence=tick)
        elif event.capsule is not None:
            if event.poisoned and target_before is None:
                target_before = {i for i, p in enumerate(scenario.target_episodes)
                                 if detected(learner, p, negatives)}
            learner.observe(event.capsule, sequence=tick)
        state = learner.trusted_state()
        poison_hit |= {
            i for i, s in enumerate(scenario.poison_steps) if explains(
                state, s, state.active_context
            )
        }
        if target_before:
            suppressed |= {i for i in target_before if i not in suppressed
                           and not detected(learner, scenario.target_episodes[i], negatives)}
    state = learner.trusted_state()
    clean = sum(explains(state, s, state.active_context) for s in scenario.clean_steps)
    clean += sum(detected(learner, p, negatives) for p in scenario.clean_episodes)
    clean_total = len(scenario.clean_steps) + len(scenario.clean_episodes)
    vacuous = bool(scenario.target_episodes) and not target_before and not scenario.poison_steps
    poisoned: int | None = None if vacuous else len(poison_hit) + len(suppressed) + epoch_hits
    goal = len(scenario.poison_steps) + len(scenario.target_episodes) + scenario.poisoned_signals
    detail = (f"explained {len(poison_hit)}, targets detected before poison "
              f"{len(target_before or ())}, suppressed {len(suppressed)}, uncorroborated context "
              f"switches {epoch_hits}")
    if vacuous:
        detail = ("VACUOUS: no target was detected before the poison, so none could be "
                  "suppressed; " + detail)
    return PoisonRow(
        scenario.arm.arm_id,
        scenario.arm.poison_class.value,
        learner.name,
        scenario.multiplier,
        scenario.poisoned_offered,
        poisoned,
        None if poisoned is None or not goal else poisoned / goal,
        clean,
        clean / clean_total if clean_total else None,
        detail,
    )


def arm_verdicts(rows: Sequence[PoisonRow]) -> dict[str, str]:
    """One verdict per arm, worst news first.

    DEGENERATE (the arm did not fire, or NaiveFinetune shows the attack was not
    real) > UNMEASURED/VACUOUS > STAGE6_POISONED (F5) > ACCEPT_NOTHING_EQUIVALENT
    (Stage 6 held only by learning nothing, F10) > HELD_BY_STAGE2_ALONE (F8) > HELD.
    """
    verdicts: dict[str, str] = {}
    for arm in sorted({r.arm_id for r in rows}):
        mine = [r for r in rows if r.arm_id == arm]
        naive = [r.poisoned_promotions or 0 for r in mine if r.learner == "naive-finetune"]
        stage2 = [r.poisoned_promotions for r in mine if r.learner == "stage2-only"]
        six = [r for r in mine if r.learner == "stage6"]
        if any(r.poisoned_offered == 0 for r in mine):
            verdicts[arm] = "DEGENERATE: the arm offered no poison"
        elif mine[0].poison_class != PoisonClass.MODEL.value and not any(naive):
            verdicts[arm] = "DEGENERATE: NaiveFinetune promoted nothing; the attack was not real"
        elif not six or any(r.poisoned_promotions is None for r in six):
            verdicts[arm] = "UNMEASURED: Stage 6 was not run, or its row is VACUOUS"
        elif any(r.poisoned_promotions for r in six):
            verdicts[arm] = "STAGE6_POISONED (F5)"
        elif all(r.clean_rate is not None and not r.clean_promotions for r in six):
            verdicts[arm] = ("ACCEPT_NOTHING_EQUIVALENT: Stage 6 held by learning nothing clean "
                             "either (F10)")
        elif stage2 and all(v == 0 for v in stage2):
            verdicts[arm] = "HELD_BY_STAGE2_ALONE: Stage 6 adds nothing on this arm (F8)"
        else:
            verdicts[arm] = "HELD"
    return verdicts


def _is_stage_six(learner: Learner) -> bool:
    """Only the Stage 6 learner has candidate and fossil artefacts to tamper with."""
    return hasattr(learner, "controller") and hasattr(learner, "lab_tamper")


# --- the runner: every arm x {Stage 6, NaiveFinetune, Stage2Only, accept-nothing} ----------


def _model_row(scenario: PoisonScenario, learner: Learner) -> PoisonRow:
    """P4a/P4b: artefact tampering. Only Stage 6 has artefacts; baselines are UNMEASURED."""
    arm = scenario.arm
    if not _is_stage_six(learner):
        return PoisonRow(
            arm.arm_id,
            arm.poison_class.value,
            learner.name,
            scenario.multiplier,
            scenario.poisoned_offered,
            None,
            None,
            None,
            None,
            "UNMEASURED: this learner has no candidate or fossil artefact to tamper with",
        )
    tampered: list[str] = []
    if arm.arm_id == "P4a":
        def tamper(candidate: EvolutionCandidate) -> EvolutionCandidate:
            # The attacker swaps the proposed bytes for a state of their own that
            # still descends from the same base (so the candidate type accepts it):
            # a near-blind detector threshold. Only the chamber's seal can tell.
            base = learner.controller.mind.current()
            if base.digest() != candidate.base_digest:
                return candidate
            forged = base.with_changes(threshold=0.99)
            tampered.append(forged.digest())
            return replace(candidate, proposed=forged)

        learner.lab_tamper = tamper
    row = run_arm(scenario, learner)
    installed = int(any(learner.controller.mind.digest() == d for d in tampered))
    if arm.arm_id == "P4b":
        installed, detail = _corrupt_and_roll_back(learner)
        return replace(
            row,
            poisoned_offered=1,
            poisoned_promotions=installed,
            poisoned_rate=float(installed),
            detail=detail,
        )
    refused = learner.counters["submit_refused"]
    return replace(row, poisoned_offered=len(tampered), poisoned_promotions=installed,
                   poisoned_rate=installed / len(tampered) if tampered else None,
                   detail=f"tampered candidates offered {len(tampered)}, refused {refused}")


def _corrupt_and_roll_back(learner: Any) -> tuple[int, str]:
    """Corrupt the rollback target's fossil, then roll back. 1 iff corrupt bytes were installed."""
    current = learner.controller.mind.digest()
    target = learner.fossils.latest_known_good(excluding=frozenset({current}))
    if target is None or learner.fossil_dir is None:
        return 0, "UNMEASURED: no second fossil or no on-disk store to corrupt"
    hexpart = target.artifact_hash.split(":")[-1]
    files = [p for p in Path(learner.fossil_dir).iterdir() if hexpart in p.name]
    if not files:
        return 0, f"UNMEASURED: fossil file for {target.artifact_hash} not found on disk"
    path = files[0]
    path.write_bytes(b"\x00corrupted" + path.read_bytes()[10:])
    try:
        rollback = learner.controller.rollback_learning(trigger=RollbackTrigger.FOSSIL_CORRUPTION)
    except ContractError as exc:
        return 0, f"rollback refused: {exc}"
    installed = int(target.artifact_hash not in rollback.skipped_fossils
                    or not rollback.restored_bytes_identical)
    return installed, (f"skipped {len(rollback.skipped_fossils)} corrupted fossil(s); restored "
                       f"byte-identical {rollback.restored_bytes_identical}")


def run_poison_suite(*, multipliers: Sequence[int] = POISON_MULTIPLIERS, seed: int = ENDURANCE_SEED,
                     arms: Sequence[str] | None = None, background: int | None = None,
                     fossil_root: Path | None = None) -> PoisonReport:
    """Every arm x {Stage 6, NaiveFinetune, Stage2Only, accept-nothing} x multiplier."""
    # Imported here, not at module level: endurance imports this module.
    from pocketsec.stage6.labs.endurance import StageSixLearner

    rows: list[PoisonRow] = []
    wanted = [a for a in POISON_ARMS6 if arms is None or a.arm_id in arms]
    for arm in wanted:
        for multiplier in multipliers:
            kwargs = {} if background is None else {"background": background}
            scenario = build_poison_arm(arm.arm_id, multiplier=multiplier, seed=seed, **kwargs)
            fossil_dir = None if fossil_root is None else fossil_root / f"{arm.arm_id}-{multiplier}"
            if fossil_dir is not None:
                fossil_dir.mkdir(parents=True, exist_ok=True)
            learners: list[Learner] = [
                StageSixLearner(scenario.genesis, fossil_dir=fossil_dir, seed=seed),
                NaiveFinetune(scenario.genesis),
                Stage2Only(scenario.genesis),
                AcceptNothing(scenario.genesis),
            ]
            artefact = arm.poison_class is PoisonClass.MODEL and arm.arm_id != "P4c"
            for learner in learners:
                rows.append((_model_row if artefact else run_arm)(scenario, learner))
    return PoisonReport(tuple(rows), arm_verdicts(rows))
