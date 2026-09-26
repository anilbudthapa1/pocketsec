"""The gate's controller rig: a lab chamber and hand-sized F1/F3 fixtures for G6.3/6/7/8.

**What this is for.** Four gate criteria are about the *controller* — the one trusted
writer — rather than about what the learner happens to learn: that a candidate which
forgets a historical detection is refused (G6.3's firing proof), that no state can be
skipped (G6.6), that shadow and canary payloads carry no authority (G6.7), and that a
candidate which passes offline but regresses live is rolled back automatically and
byte-identically (G6.8). On the endurance corpus the real Stage 6 learner promotes
almost nothing (docs/stage-6-findings.md), so waiting for the corpus to produce these
situations would leave the checks vacuous. This rig produces them on purpose.

**What it is not.** :class:`LabChamber` mints real :class:`EvolutionCandidate` values,
with the real ``candidate_fingerprint`` and real lineage nodes, and registers what it
minted, so the controller's ``chamber.issued`` refusal is exercised exactly as it is for
the real chamber. It does **not** run the real chamber's induction: G6.3/6/7/8 here say
nothing about what ``EvolutionChamber`` would propose. The real chamber is exercised by
G6.1 (it refuses unissued verdicts) and by the endurance run.

The rig's genesis threshold is :data:`RIG_THRESHOLD` (0.6), strictly above
``UNEXPLAINED_WEIGHT`` (0.5), so that only detectors alert in these fixtures. At the
spec's ``DEFAULT_THRESHOLD`` (0.5) every session with an unexplained step alerts
through ``U`` alone, a detector's removal cannot change any alert, and G6.8's regression
could not exist — that is the finding recorded against the constants, not something the
rig hides.

This module is harness, not runtime: only ``gate*.py`` and ``cli.py`` may import it
(``tests/test_stage6_boundary.py``), and nothing in it is reachable from the endpoint.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.epoch.model import SystemIdentity
from pocketsec.stage1.ssir.entities import SemanticProperty
from pocketsec.stage1.ssir.relations import Relation
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_LAYOUT, FEATURE_WIDTH, GROUP_OFFSETS
from pocketsec.stage6.capsule.experience_capsule import EncodedStep, LabelOrigin
from pocketsec.stage6.capsule.quarantine import QuarantineGateway
from pocketsec.stage6.chamber.evolution import (
    CandidateKind,
    EvolutionCandidate,
    KnowledgeDelta,
    candidate_fingerprint,
)
from pocketsec.stage6.constitution.learning import (
    LifecycleState,
    property_mask,
    touches_protected,
)
from pocketsec.stage6.fossils.lineage import KnowledgeLineageDAG, LineageNode, NodeKind
from pocketsec.stage6.fossils.store import FossilStore
from pocketsec.stage6.memory.episodic import EpisodeSkeleton
from pocketsec.stage6.memory.semantic import (
    ALL_CONTEXTS,
    ItemKind,
    ItemLineage,
    ItemValidation,
    KnowledgeItem,
    MotifStep,
    TrustedKnowledgeState,
    context_id_for,
    genesis_state,
    motif_pattern_key,
)
from pocketsec.stage6.plasticity.masks import uniform_mask
from pocketsec.stage6.promotion.controller import LearningPromotionController, PromotionDecision
from pocketsec.stage6.provenance.ledger import ProvenanceLedger
from pocketsec.stage6.shadow.canary import CanaryObservation, CanaryPolicy
from pocketsec.stage6.shadow.mind import MIN_SHADOW_SESSIONS, ShadowMind, ShadowSession

__all__ = [
    "F1_MOTIF",
    "F2_MOTIF",
    "F3_MOTIF",
    "RIG_POLICY",
    "RIG_THRESHOLD",
    "LabChamber",
    "RigWorld",
    "benign_holdout",
    "benign_traffic",
    "build_world",
    "detector_id",
    "f1_steps",
    "f2_steps",
    "f3_steps",
    "promote_f1_f3",
    "session",
    "shadow_traffic",
    "skeleton",
    "walk",
]

IDENTITY = SystemIdentity(kernel_id="k-gate-rig")
CTX = context_id_for(IDENTITY)
RIG_THRESHOLD = 0.6
#: Canary and probation windows shortened so the rig finishes in milliseconds. The
#: controller's logic is window-length independent; the §4.21 lengths are not re-measured.
RIG_POLICY = CanaryPolicy(window_sessions=8, probation_sessions=16)
_CRED = property_mask([SemanticProperty.CREDENTIAL])
_EGRESS = property_mask([SemanticProperty.EXTERNAL_ENDPOINT])
_PERSIST = property_mask([SemanticProperty.PERSISTENCE])
_AUTHZ = property_mask([SemanticProperty.AUTHORIZATION_DATA])
_OBJ = GROUP_OFFSETS["object_semantics"]
_ACTOR = GROUP_OFFSETS["actor_semantics"]
_ACTOR_WIDTH = dict(FEATURE_LAYOUT)["actor_semantics"]
_GATEWAY_ROOT = "rig-gateway-root"

F1_MOTIF = (MotifStep(int(Relation.READ), _CRED, 0, 0),
            MotifStep(int(Relation.SEND), _EGRESS, 0, 0))
F2_MOTIF = (MotifStep(int(Relation.READ), _AUTHZ, 0, 0),)
F3_MOTIF = (MotifStep(int(Relation.WRITE), _PERSIST, 0, 0),)


def _hex(label: str, width: int) -> str:
    return hashlib.sha256(label.encode()).hexdigest()[:width]


def _digest(label: str) -> str:
    return "sha256:" + _hex(label, 64)


def _cap_id(label: str) -> str:
    return "cap-" + _hex(label, 24)


def _step(relation: Relation, *, props: int = 0, actor: int = 0, actor_class: int = 0,
          group: str = "a") -> EncodedStep:
    features = [0.0] * FEATURE_WIDTH
    features[GROUP_OFFSETS["relation_onehot"] + int(relation)] = 1.0
    for bit in range(dict(FEATURE_LAYOUT)["object_semantics"]):
        if props >> bit & 1:
            features[_OBJ + bit] = 1.0
    features[_ACTOR + actor_class % _ACTOR_WIDTH] = 1.0
    return EncodedStep(
        features=tuple(features), relation=int(relation), relation_family=0, state_delta_mask=0,
        time_bucket=0, delta_phi=0.0, object_property_mask=props, epoch_id=1, actor_slot=actor,
        uncertainty=0.0, source_group="grp-" + _hex(group, 16), causal_signature="",
        parent_signature="", evidence=(_digest(f"ev-{relation}-{actor}-{props}-{group}"),),
    )


def f1_steps(tag: str) -> list[EncodedStep]:
    """Credential read then external send by one actor, plus a bystander."""
    return [_step(Relation.READ, props=_CRED, group=tag),
            _step(Relation.SEND, props=_EGRESS, group=tag),
            _step(Relation.READ, actor=1, actor_class=3, group=tag + "b")]


def f2_steps(tag: str) -> list[EncodedStep]:
    """An authorisation-data read."""
    return [_step(Relation.READ, props=_AUTHZ, group=tag)]


def f3_steps(tag: str) -> list[EncodedStep]:
    """A persistence write, plus a bystander."""
    return [_step(Relation.WRITE, props=_PERSIST, group=tag),
            _step(Relation.READ, actor=1, actor_class=2, group=tag + "b")]


def _benign_steps(tag: str) -> list[EncodedStep]:
    return [_step(Relation.READ, actor_class=1, group=tag),
            _step(Relation.WRITE, actor=1, actor_class=2, group=tag + "y")]


def skeleton(label: str, steps: Sequence[EncodedStep], verdict: Verdict) -> EpisodeSkeleton:
    return EpisodeSkeleton(
        episode_id=_cap_id(label), steps=tuple(steps), verdict=verdict,
        label_origin=LabelOrigin.GROUND_TRUTH, epoch_id=1, context_id=CTX,
        visibility_mask=(1 << len(steps)) - 1, truncated=False,
        anchors_touched=tuple(sorted({
            a for s in steps for a in touches_protected(s.object_property_mask, s.state_delta_mask)
        })),
    )


def session(label: str, steps: Sequence[EncodedStep], verdict: Verdict | None) -> ShadowSession:
    return ShadowSession(session_id=f"s-{label}", steps=tuple(steps), context_id=CTX, label=verdict)


def benign_traffic(count: int, tag: str) -> list[ShadowSession]:
    return [session(f"{tag}{i}", _benign_steps(f"{tag}{i}"), Verdict.BENIGN) for i in range(count)]


def shadow_traffic(malicious: int, *, tag: str) -> list[ShadowSession]:
    """``MIN_SHADOW_SESSIONS`` labelled sessions: benign, then ``malicious`` F1 sessions."""
    rows = benign_traffic(MIN_SHADOW_SESSIONS - malicious, tag)
    rows += [session(f"{tag}m{i}", f1_steps(f"{tag}m{i}"), Verdict.MALICIOUS)
             for i in range(malicious)]
    return rows


def _detector(motif: tuple[MotifStep, ...], candidate_id: str, capsule: str) -> KnowledgeItem:
    return KnowledgeItem.build(
        kind=ItemKind.DETECTOR, context_ids=(ALL_CONTEXTS,), pattern_key=motif_pattern_key(motif),
        weight=0.9, origin_verdict=Verdict.MALICIOUS,
        lineage=ItemLineage(candidate_id, (_cap_id(capsule),), (_digest(capsule),), ()),
        validation=ItemValidation.fresh(sequence=1), motif=motif,
    )


def detector_id(state: TrustedKnowledgeState, motif: tuple[MotifStep, ...]) -> str:
    return next(i.item_id for i in state.detectors() if i.motif == motif)


class LabChamber:
    """Mints real ``EvolutionCandidate`` values with real fingerprints and lineage nodes."""

    def __init__(self, dag: KnowledgeLineageDAG) -> None:
        self._dag = dag
        self._issued: dict[str, str] = {}
        self._count = 0

    def issued(self, candidate: EvolutionCandidate) -> bool:
        return self._issued.get(candidate.candidate_id) == candidate_fingerprint(candidate)

    def _admit(self, capsule: str) -> str:
        """CAPSULE + VERDICT nodes under a rig root, as the gateway records them."""
        if not self._dag.has(_GATEWAY_ROOT):
            self._dag.update_lineage_dag(
                node=LineageNode(_GATEWAY_ROOT, NodeKind.GENESIS, _digest(_GATEWAY_ROOT), 0, ""),
                parents=(), reason="gateway_root")
        if not self._dag.has(capsule):
            self._dag.update_lineage_dag(
                node=LineageNode(capsule, NodeKind.CAPSULE, _digest(capsule), 1, ""),
                parents=(_GATEWAY_ROOT,), reason="capsule_offered", evidence=(_digest(capsule),))
            self._dag.update_lineage_dag(
                node=LineageNode(f"ver-{capsule}", NodeKind.VERDICT, _digest("v" + capsule), 1,
                                 ""), parents=(capsule,), reason="quarantine_verdict")
        return f"ver-{capsule}"

    def mint(self, trusted: TrustedKnowledgeState, *, add: Sequence[tuple[MotifStep, ...]] = (),
             remove: Sequence[str] = (), rehearsal: Sequence[EpisodeSkeleton] = (),
             holdout: Sequence[EpisodeSkeleton] = (), register: bool = True,
             kinds: frozenset[CandidateKind] = frozenset({CandidateKind.SYMBOLIC}),
             ) -> EvolutionCandidate:
        self._count += 1
        label = f"rig{self._count}-{trusted.digest()[7:15]}"
        cid = "cand-" + _hex(label, 32)
        verdicts = [self._admit(_cap_id(f"{label}-{i}")) for i, _ in enumerate(add)]
        verdicts = verdicts or [self._admit(_cap_id(label))]
        items = tuple(_detector(motif, cid, f"{label}-{i}") for i, motif in enumerate(add))
        verdicts += [self._admit(e.episode_id) for e in (*rehearsal, *holdout)]
        kept = {e.episode_id: e for e in trusted.rehearsal}
        kept.update({e.episode_id: e for e in rehearsal})
        proposed = trusted.with_changes(
            add=items, remove=remove,
            rehearsal=tuple(kept[k] for k in sorted(kept)) if rehearsal else None)
        candidate = EvolutionCandidate(
            candidate_id=cid, kinds=kinds, base_digest=trusted.digest(), proposed=proposed,
            delta=KnowledgeDelta(added=items, removed=tuple(remove),
                                 rehearsal_added=tuple(rehearsal)),
            verdict_ids=tuple(sorted(set(verdicts))), capsule_ids=(),
            mask=uniform_mask([i.item_id for i in items], protected=frozenset(), now_sequence=0),
            competition=(), holdout_episode_ids=tuple(sorted(e.episode_id for e in holdout)),
            mask_refusals=0, work_units=0, created_sequence=self._count,
        )
        self._dag.update_lineage_dag(
            node=LineageNode(cid, NodeKind.CANDIDATE, proposed.digest(), self._count, "rig"),
            parents=tuple(sorted(set(verdicts))), reason="spawn_evolution_candidate")
        if register:
            self._issued[cid] = candidate_fingerprint(candidate)
        return candidate


@dataclass
class RigWorld:
    controller: LearningPromotionController
    chamber: LabChamber
    dag: KnowledgeLineageDAG
    store: FossilStore
    canary_observations: list[CanaryObservation]


def build_world(directory: Path | None = None, *, shadow: ShadowMind | None = None) -> RigWorld:
    dag = KnowledgeLineageDAG()
    store = FossilStore(directory=directory)
    chamber = LabChamber(dag)
    controller = LearningPromotionController(
        genesis=genesis_state(identity=IDENTITY, threshold=RIG_THRESHOLD), fossils=store,
        lineage=dag, gateway=QuarantineGateway(ledger=ProvenanceLedger(), lineage=dag),
        chamber=chamber,  # type: ignore[arg-type]  # duck-typed: the controller reads .issued
        shadow=shadow or ShadowMind(sample_every=1), policy=RIG_POLICY)
    return RigWorld(controller, chamber, dag, store, [])


def walk(world: RigWorld, candidate: EvolutionCandidate, *, holdout: Sequence[EpisodeSkeleton],
         shadow: Sequence[ShadowSession]) -> tuple[PromotionDecision, ...]:
    """submit -> shadow -> canary -> trusted; stops at the first REJECTED decision."""
    c = world.controller
    offline = c.submit(candidate, holdout=holdout, hostile=(), variant_seed=7)
    if offline.to_state is LifecycleState.REJECTED:
        return (offline,)
    shadowed = c.run_shadow(candidate.candidate_id, shadow)
    decisions = [offline, shadowed]
    if shadowed.to_state is LifecycleState.REJECTED:
        return tuple(decisions)
    decisions.append(c.promote_canary(candidate.candidate_id))
    for s in benign_traffic(RIG_POLICY.window_sessions, "can" + candidate.candidate_id[5:11]):
        outcome = c.observe_canary(s)
        if isinstance(outcome, PromotionDecision):
            return (*decisions, outcome)
        world.canary_observations.append(outcome)
    decisions.append(c.promote_trusted(candidate.candidate_id))
    return tuple(decisions)


def promote_f1_f3(world: RigWorld) -> TrustedKnowledgeState:
    """Trusted F1 + F3 detectors; the rehearsal set holds F1 and benign exemplars, NO F3."""
    holdout = [skeleton("h1", f1_steps("h1"), Verdict.MALICIOUS),
               skeleton("h3", f3_steps("h3"), Verdict.MALICIOUS),
               skeleton("hb", _benign_steps("hb"), Verdict.BENIGN)]
    rehearsal = [skeleton("r1", f1_steps("r1"), Verdict.MALICIOUS),
                 skeleton("rb", _benign_steps("rb"), Verdict.BENIGN)]
    candidate = world.chamber.mint(world.controller.mind.current(), add=(F1_MOTIF, F3_MOTIF),
                                   rehearsal=rehearsal, holdout=holdout)
    walk(world, candidate, holdout=holdout, shadow=shadow_traffic(3, tag="sa"))
    for s in benign_traffic(RIG_POLICY.probation_sessions, "pa"):
        world.controller.observe_probation(s)
    return world.controller.mind.current()


def benign_holdout(tag: str) -> EpisodeSkeleton:
    return skeleton(tag, _benign_steps(tag), Verdict.BENIGN)
