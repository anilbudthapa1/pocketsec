"""Stage 6 package `promotion`: conservation gate, Shadow Mind, canary, the one trusted writer.

These tests attack the boundary rather than admire it. Every injection path the spec names
(raw telemetry, a hand-built or altered candidate, a forged or replayed decision handed to
the private installer, an unknown rollback digest) is driven and must leave
``mind.digest()`` unchanged. The G6.8 scenario is built in miniature: a candidate that
passes every offline gate because the rehearsal set has no F3 exemplar, regresses F3 live,
and is rolled back *automatically* to a byte-identical fossil. A corrupted fossil on disk
is skipped and named. Every report payload passes Stage 5's own authority and seam screens.

The chamber here is a stub that mints candidates with the real ``EvolutionCandidate`` type,
the real ``candidate_fingerprint`` and real lineage nodes, so the controller's refusal of
anything the chamber did not issue is exercised on the real check; one test also uses the
real ``EvolutionChamber`` to show a candidate it never built is refused.
"""

from __future__ import annotations

import dataclasses
import hashlib
from collections.abc import Sequence
from pathlib import Path

import pytest

from pocketsec.stage0.contracts.common import ContractError, digest_of_bytes
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.epoch.model import EpochDecision, EpochTransitionReason, SystemIdentity
from pocketsec.stage1.ssir.entities import SemanticProperty
from pocketsec.stage1.ssir.relations import Relation
from pocketsec.stage2.adaptation.quarantine import DEFAULT_CONSISTENCY_RADIUS, pattern_key
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_LAYOUT, FEATURE_WIDTH, GROUP_OFFSETS
from pocketsec.stage5.stage6_interface import authority_violations, seam_violations
from pocketsec.stage6.capsule.experience_capsule import EncodedStep, LabelOrigin
from pocketsec.stage6.capsule.quarantine import QuarantineGateway
from pocketsec.stage6.chamber.evolution import (
    CandidateKind,
    EvolutionCandidate,
    EvolutionChamber,
    KnowledgeDelta,
    candidate_fingerprint,
)
from pocketsec.stage6.conservation import gate as cg
from pocketsec.stage6.consolidator.mnemosyne import MnemosyneConsolidator
from pocketsec.stage6.constitution.learning import (
    LifecycleState,
    property_mask,
    require_transition,
    touches_protected,
)
from pocketsec.stage6.fossils.lineage import (
    KnowledgeLineageDAG,
    LineageCapacityError,
    LineageNode,
    NodeKind,
)
from pocketsec.stage6.fossils.store import MAX_FOSSILS, FossilReason, FossilStore
from pocketsec.stage6.homeostasis.drift import EpochTransition, KnowledgeContextRegistry
from pocketsec.stage6.memory.episodic import EpisodeSkeleton, EpisodicMemory
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
from pocketsec.stage6.promotion import controller as pc
from pocketsec.stage6.promotion.controller import (
    MAX_DECISION_LOG,
    MAX_PENDING_CANDIDATES,
    LearningPromotionController,
    PromotionDecision,
    RollbackTrigger,
)
from pocketsec.stage6.provenance.ledger import ProvenanceLedger
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage6.shadow.canary import (
    CanaryEvaluator,
    CanaryPolicy,
    canary_sampled,
    emitted_score,
)
from pocketsec.stage6.shadow.mind import (
    ABORT_BYTE_BUDGET,
    ABORT_WORK_BUDGET,
    MIN_SHADOW_SESSIONS,
    ShadowMind,
    ShadowSession,
)

IDENTITY = SystemIdentity(kernel_id="k-promotion")
CTX = context_id_for(IDENTITY)
CTX2 = context_id_for(SystemIdentity(kernel_id="k-upgraded"))
CRED = property_mask([SemanticProperty.CREDENTIAL])
EGRESS = property_mask([SemanticProperty.EXTERNAL_ENDPOINT])
PERSIST = property_mask([SemanticProperty.PERSISTENCE])
AUTHZ = property_mask([SemanticProperty.AUTHORIZATION_DATA])
THRESHOLD = 0.6  # above UNEXPLAINED_WEIGHT, so only detectors can alert in these fixtures
FAST = CanaryPolicy(window_sessions=8, probation_sessions=16)
_OBJ = GROUP_OFFSETS["object_semantics"]
_ACTOR = GROUP_OFFSETS["actor_semantics"]
_ACTOR_WIDTH = dict(FEATURE_LAYOUT)["actor_semantics"]

F1_MOTIF = (MotifStep(int(Relation.READ), CRED, 0, 0), MotifStep(int(Relation.SEND), EGRESS, 0, 0))
F2_MOTIF = (MotifStep(int(Relation.READ), AUTHZ, 0, 0),)
F3_MOTIF = (MotifStep(int(Relation.WRITE), PERSIST, 0, 0),)
GENESIS = genesis_state(identity=IDENTITY, threshold=THRESHOLD)
GATEWAY_ROOT = "stub-gateway-root"


# --- fixtures built from the real Stage 6 types ---------------------------------------------


def _hex(label: str, width: int) -> str:
    return hashlib.sha256(label.encode()).hexdigest()[:width]


def _digest(label: str) -> str:
    return "sha256:" + _hex(label, 64)


def cap_id(label: str) -> str:
    return "cap-" + _hex(label, 24)


def step(relation: Relation, *, props: int = 0, actor: int = 0, actor_class: int = 0,
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


def f1_steps(tag: str = "x") -> list[EncodedStep]:
    return [step(Relation.READ, props=CRED, group=tag),
            step(Relation.SEND, props=EGRESS, group=tag),
            step(Relation.READ, actor=1, actor_class=3, group=tag + "b")]


def f3_steps(tag: str = "x") -> list[EncodedStep]:
    return [step(Relation.WRITE, props=PERSIST, group=tag),
            step(Relation.READ, actor=1, actor_class=2, group=tag + "b")]


def benign_steps(tag: str = "x") -> list[EncodedStep]:
    return [step(Relation.READ, actor_class=1, group=tag),
            step(Relation.WRITE, actor=1, actor_class=2, group=tag + "y")]


def skeleton(label: str, steps: Sequence[EncodedStep], verdict: Verdict,
             context: str = CTX) -> EpisodeSkeleton:
    return EpisodeSkeleton(
        episode_id=cap_id(label), steps=tuple(steps), verdict=verdict,
        label_origin=LabelOrigin.GROUND_TRUTH, epoch_id=1, context_id=context,
        visibility_mask=(1 << len(steps)) - 1, truncated=False,
        anchors_touched=tuple(sorted({
            a for s in steps for a in touches_protected(s.object_property_mask, s.state_delta_mask)
        })),
    )


def session(label: str, steps: Sequence[EncodedStep], verdict: Verdict | None) -> ShadowSession:
    return ShadowSession(session_id=f"s-{label}", steps=tuple(steps), context_id=CTX, label=verdict)


def detector(motif: tuple[MotifStep, ...], candidate_id: str, capsule: str) -> KnowledgeItem:
    return KnowledgeItem.build(
        kind=ItemKind.DETECTOR, context_ids=(ALL_CONTEXTS,), pattern_key=motif_pattern_key(motif),
        weight=0.9, origin_verdict=Verdict.MALICIOUS,
        lineage=ItemLineage(candidate_id, (cap_id(capsule),), (_digest(capsule),), ()),
        validation=ItemValidation.fresh(sequence=1), motif=motif,
    )


def baseline_for(example: EncodedStep, candidate_id: str, capsule: str) -> KnowledgeItem:
    return KnowledgeItem.build(
        kind=ItemKind.BASELINE, context_ids=(CTX,), pattern_key=pattern_key(example.to_encoded()),
        weight=DEFAULT_CONSISTENCY_RADIUS, origin_verdict=Verdict.BENIGN,
        lineage=ItemLineage(candidate_id, (cap_id(capsule),), (_digest(capsule),), ()),
        validation=ItemValidation.fresh(sequence=1), anchor=example.meaning(),
    )


class StubChamber:
    """Mints candidates the way the chamber does: real type, fingerprint and lineage nodes."""

    def __init__(self, dag: KnowledgeLineageDAG) -> None:
        self._dag = dag
        self._issued: dict[str, str] = {}
        self._count = 0

    def issued(self, candidate: EvolutionCandidate) -> bool:
        return self._issued.get(candidate.candidate_id) == candidate_fingerprint(candidate)

    def admit(self, label: str) -> str:
        return self.admit_id(cap_id(label))

    def admit_id(self, capsule: str) -> str:
        """CAPSULE + VERDICT nodes under a gateway root of their own, as the gateway records them.

        The root must NOT be the controller's ``genesis`` node: the genesis THRESHOLD item's
        candidate id is ``genesis``, so hanging capsules there would make every node a
        descendant of a live item and lineage collection a silent no-op.
        """
        label = capsule
        if not self._dag.has(GATEWAY_ROOT):
            self._dag.update_lineage_dag(
                node=LineageNode(GATEWAY_ROOT, NodeKind.GENESIS, _digest(GATEWAY_ROOT), 0, ""),
                parents=(), reason="gateway_root")
        if not self._dag.has(capsule):
            self._dag.update_lineage_dag(
                node=LineageNode(capsule, NodeKind.CAPSULE, _digest(label), 1, ""),
                parents=(GATEWAY_ROOT,), reason="capsule_offered", evidence=(_digest(label),))
            self._dag.update_lineage_dag(
                node=LineageNode(f"ver-{capsule}", NodeKind.VERDICT, _digest("v" + label), 1, ""),
                parents=(capsule,), reason="quarantine_verdict")
        return f"ver-{capsule}"

    def mint(self, trusted: TrustedKnowledgeState, *, add: Sequence[tuple] = (),
             remove: Sequence[str] = (), rehearsal: Sequence[EpisodeSkeleton] = (),
             kinds: frozenset[CandidateKind] = frozenset({CandidateKind.SYMBOLIC}),
             holdout: Sequence[EpisodeSkeleton] = (), register: bool = True) -> EvolutionCandidate:
        self._count += 1
        label = f"cand{self._count}-{trusted.digest()[7:15]}"
        cid = "cand-" + _hex(label, 32)
        verdicts = [self.admit(f"{label}-{i}") for i, _ in enumerate(add)] or [self.admit(label)]
        items = tuple(detector(motif, cid, f"{label}-{i}") for i, motif in enumerate(add))
        for episode in (*rehearsal, *holdout):
            verdicts.append(self.admit_id(episode.episode_id))
        delta = KnowledgeDelta(added=items, removed=tuple(remove), rehearsal_added=tuple(rehearsal))
        kept = {e.episode_id: e for e in trusted.rehearsal}
        kept.update({e.episode_id: e for e in rehearsal})
        proposed = trusted.with_changes(add=items, remove=remove,
                                        rehearsal=tuple(kept[k] for k in sorted(kept)) if rehearsal
                                        else None)
        candidate = EvolutionCandidate(
            candidate_id=cid, kinds=kinds, base_digest=trusted.digest(), proposed=proposed,
            delta=delta, verdict_ids=tuple(sorted(set(verdicts))), capsule_ids=(),
            mask=uniform_mask([i.item_id for i in items], protected=frozenset(), now_sequence=0),
            competition=(), holdout_episode_ids=tuple(sorted(e.episode_id for e in holdout)),
            mask_refusals=0, work_units=0, created_sequence=self._count,
        )
        self._dag.update_lineage_dag(
            node=LineageNode(cid, NodeKind.CANDIDATE, proposed.digest(), self._count, "stub"),
            parents=tuple(sorted(set(verdicts))), reason="spawn_evolution_candidate")
        if register:
            self._issued[cid] = candidate_fingerprint(candidate)
        return candidate


@dataclasses.dataclass
class World:
    controller: LearningPromotionController
    chamber: StubChamber
    dag: KnowledgeLineageDAG
    store: FossilStore


def build(directory: Path | None = None, *, shadow: ShadowMind | None = None,
          policy: CanaryPolicy = FAST, max_nodes: int | None = None) -> World:
    dag = KnowledgeLineageDAG() if max_nodes is None else KnowledgeLineageDAG(max_nodes=max_nodes)
    store = FossilStore(directory=directory)
    chamber = StubChamber(dag)
    controller = LearningPromotionController(
        genesis=GENESIS, fossils=store, lineage=dag,
        gateway=QuarantineGateway(ledger=ProvenanceLedger(), lineage=dag),
        chamber=chamber,  # type: ignore[arg-type]
        shadow=shadow or ShadowMind(sample_every=1), policy=policy)
    return World(controller, chamber, dag, store)


def shadow_traffic(malicious: int = 0, *, family=f1_steps, tag: str = "sh") -> list[ShadowSession]:
    rows = [session(f"{tag}{i}", benign_steps(f"{tag}{i}"), Verdict.BENIGN)
            for i in range(MIN_SHADOW_SESSIONS - malicious)]
    rows += [session(f"{tag}m{i}", family(f"{tag}m{i}"), Verdict.MALICIOUS)
             for i in range(malicious)]
    return rows


def benign_traffic(count: int, tag: str) -> list[ShadowSession]:
    return [session(f"{tag}{i}", benign_steps(f"{tag}{i}"), Verdict.BENIGN) for i in range(count)]


def walk(world: World, candidate: EvolutionCandidate, *, holdout=(), shadow=None,
         canary=None) -> PromotionDecision:
    """submit -> shadow -> canary -> trusted, asserting each stage passed."""
    c = world.controller
    assert c.submit(candidate, holdout=holdout, hostile=(), variant_seed=7).to_state is (
        LifecycleState.OFFLINE_VALIDATED)
    assert c.run_shadow(candidate.candidate_id, shadow or shadow_traffic()).to_state is (
        LifecycleState.SHADOW)
    c.promote_canary(candidate.candidate_id)
    for s in canary or benign_traffic(FAST.window_sessions, "can" + candidate.candidate_id[5:9]):
        assert not isinstance(c.observe_canary(s), PromotionDecision)
    return c.promote_trusted(candidate.candidate_id)


def candidate_a(world: World) -> tuple[EvolutionCandidate, list[EpisodeSkeleton]]:
    """F1 + F3 detectors; rehearsal holds F1 and benign exemplars but NO F3 exemplar."""
    holdout = [skeleton("h1", f1_steps("h1"), Verdict.MALICIOUS),
               skeleton("h3", f3_steps("h3"), Verdict.MALICIOUS),
               skeleton("hb", benign_steps("hb"), Verdict.BENIGN)]
    rehearsal = [skeleton("r1", f1_steps("r1"), Verdict.MALICIOUS),
                 skeleton("rb", benign_steps("rb"), Verdict.BENIGN)]
    candidate = world.chamber.mint(world.controller.mind.current(), add=(F1_MOTIF, F3_MOTIF),
                                   rehearsal=rehearsal, holdout=holdout)
    return candidate, holdout


def promoted_a(world: World, *, finish_probation: bool = True) -> TrustedKnowledgeState:
    candidate, holdout = candidate_a(world)
    walk(world, candidate, holdout=holdout, shadow=shadow_traffic(3))
    if finish_probation:
        for s in benign_traffic(FAST.probation_sessions, "pa"):
            assert world.controller.observe_probation(s) is None
    return world.controller.mind.current()


def f3_detector_id(state: TrustedKnowledgeState) -> str:
    return next(i.item_id for i in state.detectors() if i.motif == F3_MOTIF)


def f1_detector_id(state: TrustedKnowledgeState) -> str:
    return next(i.item_id for i in state.detectors() if i.motif == F1_MOTIF)


# --- the single writer ---------------------------------------------------------------------


def test_the_trusted_mind_refuses_attribute_writes_even_through_sealed_names() -> None:
    """S6-AUTH-04: SEALED_NAMES is public, so setattr(mind, SEALED_NAMES[1], state) wrote
    trusted state without spelling the name the boundary scan looks for."""
    world = build()
    mind = world.controller.mind
    before = mind.digest()
    evil = GENESIS.with_changes(threshold=0.99)
    for name in (pc.SEALED_NAMES[1], "_trusted_digest"):
        with pytest.raises(ContractError, match="only by its installer"):
            setattr(mind, name, evil if name == pc.SEALED_NAMES[1] else evil.digest())
    assert mind.digest() == before == mind.current().digest()


def test_private_installer_refuses_an_unminted_decision() -> None:
    world = build()
    mind = world.controller.mind
    before = mind.digest()
    evil = GENESIS.with_changes(threshold=0.99)  # lineage-valid: only the decision is missing
    forged = PromotionDecision(
        decision_id="dec-" + "0" * 32, candidate_id="cand-" + "0" * 32,
        from_state=LifecycleState.CANARY, to_state=LifecycleState.TRUSTED,
        conservation_digest=None, shadow_digest=None, canary_digest=None,
        trusted_before=before, trusted_after=evil.digest(), reason="forged", sequence=1)
    with pytest.raises(ContractError, match="not minted"):
        mind._install_trusted(evil, decision=forged)
    # A decision minted by ANOTHER controller for its own mind is refused here (token-bound).
    other = build().controller
    minted = other._issue_decision("cand-x", LifecycleState.CANARY, LifecycleState.TRUSTED,
                                   "t", before, evil.digest(), install=True)
    with pytest.raises(ContractError, match="not minted"):
        mind._install_trusted(evil, decision=minted)
    # A decision minted for THIS mind but for a different target state is refused.
    mine = world.controller._issue_decision("cand-y", LifecycleState.CANARY,
                                            LifecycleState.TRUSTED, "t", before, _digest("other"),
                                            install=True)
    with pytest.raises(ContractError, match="different before/after"):
        mind._install_trusted(evil, decision=mine)
    # And once consumed (even by a refusal) it cannot be replayed.
    with pytest.raises(ContractError, match="not minted"):
        mind._install_trusted(evil, decision=mine)
    assert mind.digest() == before


def test_real_install_decisions_cannot_be_replayed() -> None:
    world = build()
    promoted_a(world)
    installed = [d for d in world.controller.decisions() if d.to_state is LifecycleState.TRUSTED]
    assert len(installed) == 1
    digest = world.controller.mind.digest()
    with pytest.raises(ContractError, match="not minted"):
        world.controller.mind._install_trusted(GENESIS, decision=installed[0])
    assert world.controller.mind.digest() == digest


def test_raw_telemetry_hand_built_candidates_and_unknown_rollbacks_are_refused() -> None:
    world = build()
    c = world.controller
    before = c.mind.digest()
    with pytest.raises(ContractError):
        c.submit(step(Relation.READ, props=CRED).to_encoded(), holdout=(), hostile=(),  # type: ignore[arg-type]
                 variant_seed=1)
    unissued = world.chamber.mint(c.mind.current(), add=(F1_MOTIF,), register=False)
    with pytest.raises(ContractError, match="not issued"):
        c.submit(unissued, holdout=(), hostile=(), variant_seed=1)
    never = GENESIS.with_changes(threshold=0.9)
    with pytest.raises(ContractError, match="not a fossil"):
        c.rollback_learning(trigger=RollbackTrigger.OPERATOR_REQUEST, to_digest=never.digest())
    assert c.mind.digest() == before
    assert c.rollbacks() == () and c.stats().submissions_refused == 1


def test_real_chamber_refuses_a_candidate_it_did_not_build() -> None:
    dag = KnowledgeLineageDAG()
    store = FossilStore()
    gateway = QuarantineGateway(ledger=ProvenanceLedger(), lineage=dag)
    chamber = EvolutionChamber(gateway=gateway, episodic=EpisodicMemory(),
                               consolidator=MnemosyneConsolidator(fossils=store, lineage=dag))
    controller = LearningPromotionController(genesis=GENESIS, fossils=store, lineage=dag,
                                             gateway=gateway, chamber=chamber, shadow=ShadowMind())
    forged = StubChamber(dag).mint(controller.mind.current(), add=(F1_MOTIF,))
    before = controller.mind.digest()
    with pytest.raises(ContractError, match="not issued"):
        controller.submit(forged, holdout=(), hostile=(), variant_seed=1)
    assert controller.mind.digest() == before


def test_a_candidate_altered_after_issue_is_refused_and_g1_catches_it_too() -> None:
    world = build()
    trusted = world.controller.mind.current()
    candidate = world.chamber.mint(trusted, add=(F1_MOTIF,))
    swapped = trusted.with_changes(threshold=0.1)  # descends from the base, so it constructs
    tampered = dataclasses.replace(candidate, proposed=swapped)
    with pytest.raises(ContractError, match="not issued"):
        world.controller.submit(tampered, holdout=(), hostile=(), variant_seed=1)
    verdict = cg.offline_validation(tampered, trusted=trusted, lineage=world.dag,
                                    fossils=world.store, holdout=(), hostile=(), variant_seed=1,
                                    meter=WorkMeter())
    g1 = verdict.result(cg.ConservationCheck.G1_INTEGRITY)
    assert not g1.passed and "not base + delta" in g1.detail
    assert world.controller.mind.digest() == trusted.digest()


def test_skipping_a_lifecycle_state_raises() -> None:
    with pytest.raises(ContractError):
        require_transition(LifecycleState.CANDIDATE, LifecycleState.TRUSTED)
    world = build()
    candidate, holdout = candidate_a(world)
    c = world.controller
    with pytest.raises(ContractError, match="unknown candidate"):
        c.promote_trusted(candidate.candidate_id)
    c.submit(candidate, holdout=holdout, hostile=(), variant_seed=7)
    with pytest.raises(ContractError, match="cannot be skipped"):
        c.promote_trusted(candidate.candidate_id)
    with pytest.raises(ContractError, match="cannot be skipped"):
        c.promote_canary(candidate.candidate_id)
    assert c.mind.digest() == GENESIS.digest()


def test_a_failing_candidate_leaves_the_digest_unchanged_and_is_recorded() -> None:
    world = build()
    state_a = promoted_a(world)
    drop_f1 = world.chamber.mint(state_a, remove=(f1_detector_id(state_a),),
                                 kinds=frozenset({CandidateKind.CONSOLIDATION}))
    decision = world.controller.submit(drop_f1, holdout=(), hostile=(), variant_seed=7)
    assert decision.to_state is LifecycleState.REJECTED
    assert world.controller.mind.digest() == state_a.digest()
    assert world.controller.lifecycle(drop_f1.candidate_id) is LifecycleState.REJECTED
    rejections = [n for n in world.dag.nodes() if n.kind is NodeKind.REJECTION]
    assert len(rejections) == 1 and drop_f1.candidate_id in rejections[0].node_id
    # G2 is the check that fired: F1's protected exemplar would be newly missed.
    edge = world.dag.edge(drop_f1.candidate_id, f"conservation-{drop_f1.candidate_id}")
    assert edge is not None and "G2_HISTORICAL_REPLAY" in edge.gate_result
    assert "G8_SHADOW" not in edge.gate_result  # pending G8 is not an offline failure
    with pytest.raises(ContractError):
        world.controller.run_shadow(drop_f1.candidate_id, shadow_traffic())


# --- G6.8 in miniature: pass offline, regress live, roll back automatically ---------------


def test_probation_regression_rolls_back_automatically_to_the_identical_fossil() -> None:
    world = build()
    c = world.controller
    state_a = promoted_a(world)
    pre_digest = c.mind.digest()
    pre_bytes = world.store.payload(pre_digest)
    # The rehearsal set has no F3 exemplar, so dropping the F3 detector passes every
    # offline gate — the rehearsal-gap limit G2 cannot see past.
    holdout = [skeleton("hb2", benign_steps("hb2"), Verdict.BENIGN),
               skeleton("h12", f1_steps("h12"), Verdict.MALICIOUS)]
    drop_f3 = world.chamber.mint(state_a, remove=(f3_detector_id(state_a),), holdout=holdout,
                                 kinds=frozenset({CandidateKind.CONSOLIDATION}))
    walk(world, drop_f3, holdout=holdout, shadow=shadow_traffic(2, tag="b"))
    assert c.mind.digest() == drop_f3.proposed.digest() != pre_digest
    rollbacks = []
    probation = [*benign_traffic(3, "pb"), session("f3", f3_steps("f3"), Verdict.MALICIOUS)]
    for i, s in enumerate(probation):
        result = c.observe_probation(s)
        if result is not None:
            rollbacks.append((i, result))
    assert len(rollbacks) == 1 and rollbacks[0][0] == 3  # the F3 session, not a benign one
    rollback = rollbacks[0][1]
    assert rollback.trigger is RollbackTrigger.PROBATION_REGRESSION
    assert rollback.to_digest == pre_digest == c.mind.digest()
    assert rollback.restored_bytes_identical is True
    assert c.mind.current().canonical_bytes() == pre_bytes
    assert rollback.skipped_fossils == () and rollback.evidence
    kinds = [n.kind for n in world.dag.nodes()]
    assert kinds.count(NodeKind.ROLLBACK) == 1
    assert any(n.kind is NodeKind.REJECTION and drop_f3.candidate_id in n.node_id
               for n in world.dag.nodes())
    assert c.lifecycle(drop_f3.candidate_id) is LifecycleState.ROLLED_BACK
    # Nothing about the failed candidate was deleted: its fossil and PROMOTION node remain.
    assert world.store.get(drop_f3.proposed.digest()) is not None
    assert world.dag.has(f"promotion-{drop_f3.candidate_id}")
    assert c.observe_probation(session("after", f3_steps("after"), Verdict.MALICIOUS)) is None
    assert world.dag.verify() == ()


def _regressed_and_rolled_back(world: World) -> tuple[TrustedKnowledgeState, str]:
    """state_a promoted; a candidate dropping F3 promoted, then rolled back by probation."""
    c = world.controller
    state_a = promoted_a(world)
    holdout = [skeleton("hb2", benign_steps("hb2"), Verdict.BENIGN),
               skeleton("h12", f1_steps("h12"), Verdict.MALICIOUS)]
    drop_f3 = world.chamber.mint(state_a, remove=(f3_detector_id(state_a),), holdout=holdout,
                                 kinds=frozenset({CandidateKind.CONSOLIDATION}))
    walk(world, drop_f3, holdout=holdout, shadow=shadow_traffic(2, tag="b"))
    rollback = c.observe_probation(session("f3r", f3_steps("f3r"), Verdict.MALICIOUS))
    assert rollback is not None and c.mind.digest() == state_a.digest()
    return state_a, drop_f3.proposed.digest()


def test_an_operator_cannot_re_trust_a_state_probation_rolled_back() -> None:
    """S6-AUTH-02: rollback_learning(to_digest=<the regressed state>) used to re-install it
    with no gate and no probation, blame the good candidate and blacklist the good state."""
    world = build()
    c = world.controller
    state_a, regressed = _regressed_and_rolled_back(world)
    installer = [d for d in c.decisions() if d.to_state is LifecycleState.TRUSTED][0]
    assert world.store.get(regressed) is not None  # still held: rollback deletes nothing
    with pytest.raises(ContractError, match="rolled back or rejected"):
        c.rollback_learning(trigger=RollbackTrigger.OPERATOR_REQUEST, to_digest=regressed)
    assert c.mind.digest() == state_a.digest()
    assert any(i.motif == F3_MOTIF for i in c.mind.current().detectors())
    assert c.lifecycle(installer.candidate_id) is LifecycleState.TRUSTED  # not mis-blamed
    automatic = c.rollback_learning(trigger=RollbackTrigger.OPERATOR_REQUEST)
    assert automatic.to_digest == GENESIS.digest()  # the good state was never blacklisted


def test_an_explicit_rollback_target_is_restored_exactly_after_a_lineage_fold() -> None:
    """S6-R1 / honesty F2: after collect_lineage an operator rollback to an intact, held
    fossil used to install a *different* state and record FOSSIL_CORRUPTION. Collection now
    keeps every retained fossil's lineage, so the named digest is restored byte-identically."""
    world = build()
    c = world.controller
    _state_a, state_b = _probation_over_a_removal(world)
    for s in benign_traffic(FAST.probation_sessions, "fold"):
        assert c.observe_probation(s) is None  # state_b is no longer the pinned target
    assert state_b.digest() not in {f.artifact_hash for f in world.store.fossils() if f.pinned}
    assert c.collect_lineage() > 0
    rollback = c.rollback_learning(trigger=RollbackTrigger.OPERATOR_REQUEST,
                                   to_digest=state_b.digest())
    assert rollback.to_digest == state_b.digest() == c.mind.digest()
    assert rollback.trigger is RollbackTrigger.OPERATOR_REQUEST and rollback.skipped_fossils == ()
    assert c.mind.current().canonical_bytes() == world.store.payload(state_b.digest())


def test_an_unverifiable_explicit_target_is_refused_never_substituted() -> None:
    """S6-R1 / honesty F2: if the named fossil cannot be verified the call raises and the
    trusted state is unchanged; no other fossil is installed in its place."""
    world = build()
    c = world.controller
    _state_a, state_b = _probation_over_a_removal(world)
    for s in benign_traffic(FAST.probation_sessions, "raw"):
        assert c.observe_probation(s) is None
    # A raw DAG collect (not the controller's) strands state_b's F2 lineage.
    assert world.dag.collect(live_items=c.mind.current().items, pinned_fossils=()) > 0
    current = c.mind.digest()
    with pytest.raises(ContractError, match="no other fossil was substituted"):
        c.rollback_learning(trigger=RollbackTrigger.OPERATOR_REQUEST, to_digest=state_b.digest())
    assert c.mind.digest() == current and c.stats().rolled_back == 0


def test_unlabelled_canary_traffic_cannot_promote_a_candidate_that_drops_a_detection() -> None:
    """S6-AUTH-03: a canary of unlabelled F3 attacks used to promote a candidate that drops
    the F3 detector (regressions were counted only on labelled sessions)."""
    world = build()
    c = world.controller
    state_a = promoted_a(world)
    holdout = [skeleton("hb3", benign_steps("hb3"), Verdict.BENIGN),
               skeleton("h13", f1_steps("h13"), Verdict.MALICIOUS)]
    drop_f3 = world.chamber.mint(state_a, remove=(f3_detector_id(state_a),), holdout=holdout,
                                 kinds=frozenset({CandidateKind.CONSOLIDATION}))
    assert c.submit(drop_f3, holdout=holdout, hostile=(), variant_seed=7).to_state is (
        LifecycleState.OFFLINE_VALIDATED)
    assert c.run_shadow(drop_f3.candidate_id, shadow_traffic(2, tag="u")).to_state is (
        LifecycleState.SHADOW)
    c.promote_canary(drop_f3.candidate_id)
    outcome = c.observe_canary(session("u0", f3_steps("u0"), None))
    assert isinstance(outcome, PromotionDecision) and outcome.to_state is LifecycleState.REJECTED
    assert "protected_regressions" in outcome.reason
    assert c.mind.digest() == state_a.digest()


def test_an_unlabelled_canary_window_is_incomplete_and_the_candidate_is_rejected() -> None:
    """S6-AUTH-03: a window of unlabelled sessions is not evidence; it is rejected, not passed."""
    world = build()
    c = world.controller
    candidate, holdout = candidate_a(world)
    assert c.submit(candidate, holdout=holdout, hostile=(), variant_seed=7).to_state is (
        LifecycleState.OFFLINE_VALIDATED)
    c.run_shadow(candidate.candidate_id, shadow_traffic(3))
    c.promote_canary(candidate.candidate_id)
    for i in range(FAST.window_sessions):
        c.observe_canary(session(f"n{i}", benign_steps(f"n{i}"), None))
    decision = c.promote_trusted(candidate.candidate_id)
    assert decision.to_state is LifecycleState.REJECTED and "canary_unlabelled" in decision.reason
    assert c.mind.digest() == GENESIS.digest()


def test_unlabelled_probation_neither_passes_nor_hides_a_dropped_detection() -> None:
    """S6-AUTH-03: probation used to end as passed after N unlabelled sessions, even while
    the promoted state missed every unlabelled attack the prior state caught."""
    world = build()
    c = world.controller
    state_a = promoted_a(world, finish_probation=False)
    for i in range(2 * FAST.probation_sessions):
        assert c.observe_probation(session(f"q{i}", benign_steps(f"q{i}"), None)) is None
    assert c.stats().probation_active  # unlabelled traffic never ends it
    assert c.observe_probation(session("qb", benign_steps("qb"), Verdict.BENIGN)) is None
    assert not c.stats().probation_active  # one benign label: now it can be judged
    holdout = [skeleton("hb4", benign_steps("hb4"), Verdict.BENIGN),
               skeleton("h14", f1_steps("h14"), Verdict.MALICIOUS)]
    drop_f3 = world.chamber.mint(state_a, remove=(f3_detector_id(state_a),), holdout=holdout,
                                 kinds=frozenset({CandidateKind.CONSOLIDATION}))
    walk(world, drop_f3, holdout=holdout, shadow=shadow_traffic(2, tag="p"))
    rollback = c.observe_probation(session("pf3", f3_steps("pf3"), None))
    assert rollback is not None and rollback.trigger is RollbackTrigger.PROBATION_REGRESSION
    assert c.mind.digest() == state_a.digest()


def test_an_attack_during_a_non_regressing_probation_does_not_roll_back() -> None:
    """Review F3 (medium): a probation that rolled back on ANY malicious session passed every
    test, because every probe's attack was also a regression. This is the negative control:
    the promoted state still catches the attack, so nothing may roll back."""
    world = build()
    c = world.controller
    promoted_a(world, finish_probation=False)
    for tag, steps in (("ok1", f1_steps("ok1")), ("ok3", f3_steps("ok3"))):
        assert c.observe_probation(session(tag, steps, Verdict.MALICIOUS)) is None
    assert c.stats().rolled_back == 0 and c.stats().probation_active


def test_corrupted_newest_fossil_is_skipped_as_fossil_corruption(tmp_path: Path) -> None:
    world = build(tmp_path)
    c = world.controller
    state_a = promoted_a(world)
    authz = world.chamber.mint(state_a, add=(F2_MOTIF,),
                               holdout=[skeleton("h2", [step(Relation.READ, props=AUTHZ)],
                                                 Verdict.MALICIOUS)])
    walk(world, authz, holdout=[skeleton("h2", [step(Relation.READ, props=AUTHZ)],
                                         Verdict.MALICIOUS)])
    assert c.stats().probation_active
    corrupted = state_a.digest()  # the newest fossil that is not the current state
    path = tmp_path / f"{corrupted.split(':', 1)[1]}.fossil"
    path.write_bytes(b"\x00not-zlib" + path.read_bytes()[9:])
    rollback = c.rollback_learning(trigger=RollbackTrigger.OPERATOR_REQUEST)
    assert rollback.trigger is RollbackTrigger.FOSSIL_CORRUPTION
    assert rollback.skipped_fossils == (corrupted,)
    assert rollback.to_digest == GENESIS.digest() == c.mind.digest()
    assert rollback.restored_bytes_identical
    assert c.mind.current().canonical_bytes() == world.store.payload(GENESIS.digest())
    node = next(n for n in world.dag.nodes() if n.kind is NodeKind.ROLLBACK)
    assert "requested=OPERATOR_REQUEST" in node.detail


def _probation_over_a_removal(world: World) -> tuple[TrustedKnowledgeState, TrustedKnowledgeState]:
    """state_a -> state_b (adds F2, probation finished) -> state_c (drops F2, IN probation).

    state_b's F2 item comes from a candidate none of whose items survive into state_c, so
    the only thing keeping that candidate's lineage alive is state_b being a pinned fossil.
    """
    c = world.controller
    state_a = promoted_a(world)
    holdout = [skeleton("h2", [step(Relation.READ, props=AUTHZ)], Verdict.MALICIOUS)]
    walk(world, world.chamber.mint(state_a, add=(F2_MOTIF,), holdout=holdout), holdout=holdout)
    for s in benign_traffic(FAST.probation_sessions, "pb"):
        assert c.observe_probation(s) is None
    state_b = c.mind.current()
    # Dead lineage for collection to fold: a candidate G2 rejects (it drops protected F1).
    doomed = world.chamber.mint(state_b, remove=(f1_detector_id(state_b),),
                                kinds=frozenset({CandidateKind.CONSOLIDATION}))
    assert c.submit(doomed, holdout=(), hostile=(),
                    variant_seed=7).to_state is LifecycleState.REJECTED
    f2 = tuple(i.item_id for i in state_b.detectors() if i.motif == F2_MOTIF)
    walk(world, world.chamber.mint(state_b, remove=f2,
                                   kinds=frozenset({CandidateKind.CONSOLIDATION})))
    assert c.stats().probation_active
    return state_a, state_b


def test_controller_collection_never_strands_the_pinned_rollback_target() -> None:
    world = build()
    _state_a, state_b = _probation_over_a_removal(world)
    folded = world.controller.collect_lineage()
    assert folded > 0  # collection really ran; a no-op would prove nothing
    rollback = world.controller.rollback_learning(trigger=RollbackTrigger.OPERATOR_REQUEST)
    assert rollback.skipped_fossils == ()
    assert rollback.to_digest == state_b.digest() == world.controller.mind.digest()
    assert rollback.trigger is RollbackTrigger.OPERATOR_REQUEST and rollback.restored_bytes_identical
    assert world.dag.verify() == ()


def test_a_raw_dag_collect_strands_the_target_and_rollback_names_it() -> None:
    """The hazard collect_lineage exists for, pinned down so it cannot drift silently.

    A raw ``KnowledgeLineageDAG.collect`` given only the current items folds the lineage of
    the probation target's dropped item. Rollback then cannot load it: it skips and names
    it, records LINEAGE_UNVERIFIABLE (the bytes are intact — calling a lineage fold
    FOSSIL_CORRUPTION was a mislabel, review S6-R1), and restores the next verified state
    byte-identically rather than failing or installing an unverifiable state.
    """
    world = build()
    c = world.controller
    state_a, state_b = _probation_over_a_removal(world)
    pinned = [f.artifact_hash for f in world.store.fossils() if f.pinned]
    assert world.dag.collect(live_items=c.mind.current().items, pinned_fossils=pinned) > 0
    rollback = c.rollback_learning(trigger=RollbackTrigger.OPERATOR_REQUEST)
    assert state_b.digest() in rollback.skipped_fossils
    assert rollback.trigger is RollbackTrigger.LINEAGE_UNVERIFIABLE
    assert rollback.to_digest == c.mind.digest() != state_b.digest()
    assert rollback.to_digest in (state_a.digest(), GENESIS.digest())
    assert rollback.restored_bytes_identical and world.dag.verify() == ()


def test_controller_collection_keeps_in_flight_candidates_and_bounds_the_dag() -> None:
    world = build()
    c = world.controller
    _probation_over_a_removal(world)
    for s in benign_traffic(FAST.probation_sessions, "pc"):
        assert c.observe_probation(s) is None
    holdout = [skeleton("h2b", [step(Relation.READ, props=AUTHZ)], Verdict.MALICIOUS)]
    in_flight = world.chamber.mint(c.mind.current(), add=(F2_MOTIF,), holdout=holdout)
    assert c.submit(in_flight, holdout=holdout, hostile=(),
                    variant_seed=7).to_state is LifecycleState.OFFLINE_VALIDATED
    before = len(world.dag.nodes())
    folded = c.collect_lineage()
    assert folded > 0 and len(world.dag.nodes()) < before
    # The in-flight candidate still walks to TRUSTED on the lineage that survived.
    assert c.run_shadow(in_flight.candidate_id, shadow_traffic(3)).to_state is LifecycleState.SHADOW
    c.promote_canary(in_flight.candidate_id)
    for s in benign_traffic(FAST.window_sessions, "cz"):
        c.observe_canary(s)
    assert c.promote_trusted(in_flight.candidate_id).to_state is LifecycleState.TRUSTED
    assert all(world.dag.lineage_complete(i) for i in c.mind.current().items)
    assert world.dag.verify() == ()


def test_a_full_lineage_dag_cannot_keep_a_regressed_state_trusted() -> None:
    world = build(max_nodes=400)
    c = world.controller
    _state_a, state_b = _probation_over_a_removal(world)
    regressed = c.mind.digest()
    filled = 0
    with pytest.raises(LineageCapacityError):  # fill with dead lineage until the DAG refuses
        while True:
            world.chamber.admit(f"junk-{filled}")
            filled += 1
    assert filled > 0 and world.dag.stats().refused >= 1
    # The promoted state dropped F2 (a protected authorization read): one F2 session in
    # probation is a protected regression, and the AUTOMATIC rollback must still happen.
    rollback = c.observe_probation(
        session("f2", [step(Relation.READ, props=AUTHZ, group="f2")], Verdict.MALICIOUS))
    assert rollback is not None and rollback.trigger is RollbackTrigger.PROBATION_REGRESSION
    assert rollback.to_digest == state_b.digest() == c.mind.digest() != regressed
    assert rollback.restored_bytes_identical and rollback.skipped_fossils == ()
    assert world.dag.stats().collections >= 1
    assert any(n.kind is NodeKind.ROLLBACK for n in world.dag.nodes())
    assert world.dag.verify() == ()


def test_state_digest_is_the_fossil_hash() -> None:
    world = build()
    c = world.controller
    genesis_fossil = world.store.get(c.mind.digest())
    assert genesis_fossil is not None and genesis_fossil.pinned
    assert genesis_fossil.creation_reason is FossilReason.GENESIS
    candidate, holdout = candidate_a(world)
    assert candidate.base_digest == c.mind.digest()
    walk(world, candidate, holdout=holdout, shadow=shadow_traffic(3))
    current = world.store.get(c.mind.digest())
    assert current is not None and current.artifact_hash == c.mind.digest() and current.pinned
    assert digest_of_bytes(world.store.payload(c.mind.digest())) == c.mind.digest()
    rollback = c.rollback_learning(trigger=RollbackTrigger.OPERATOR_REQUEST)
    assert rollback.to_digest == c.mind.digest() == GENESIS.digest()
    assert world.store.get(rollback.to_digest) is not None


# --- shadow and canary ---------------------------------------------------------------------


def test_shadow_over_budget_aborts_and_g8_fails() -> None:
    state_a = build()
    trusted = state_a.controller.mind.current()
    candidate, holdout = candidate_a(state_a)
    report = ShadowMind(work_budget=1).run_shadow_mind(candidate.proposed, trusted,
                                                       shadow_traffic())
    assert report.aborted and report.abort_reason == ABORT_WORK_BUDGET
    assert report.sessions_sampled == 0 and report.disagreement_rate is None
    bytes_report = ShadowMind(byte_budget=16).run_shadow_mind(candidate.proposed, trusted,
                                                              shadow_traffic())
    assert bytes_report.aborted and bytes_report.abort_reason == ABORT_BYTE_BUDGET
    verdict = cg.offline_validation(candidate, trusted=trusted, lineage=state_a.dag,
                                    fossils=state_a.store, holdout=holdout, hostile=(),
                                    variant_seed=7, meter=WorkMeter())
    assert verdict.offline_passed() and not verdict.complete
    completed = cg.complete_with_shadow(verdict, report)
    assert completed.complete and not completed.passed
    assert completed.failed_checks() == ("G8_SHADOW",)
    # Through the controller: REJECTED, digest unchanged.
    world = build(shadow=ShadowMind(sample_every=1, work_budget=1))
    candidate, holdout = candidate_a(world)
    world.controller.submit(candidate, holdout=holdout, hostile=(), variant_seed=7)
    decision = world.controller.run_shadow(candidate.candidate_id, shadow_traffic(3))
    assert decision.to_state is LifecycleState.REJECTED
    assert world.controller.mind.digest() == GENESIS.digest()


def test_shadow_sampling_is_deterministic_and_none_is_not_zero() -> None:
    world = build()
    candidate, _ = candidate_a(world)
    trusted = world.controller.mind.current()
    empty = ShadowMind().run_shadow_mind(candidate.proposed, trusted, [])
    assert empty.sessions_sampled == 0 and empty.disagreement_rate is None
    assert empty.calibration_delta is None and empty.poisoning_sensitivity is None
    assert not cg._shadow_result(empty).passed
    rows = shadow_traffic(4)
    first = ShadowMind(sample_every=4).run_shadow_mind(candidate.proposed, trusted, rows)
    again = ShadowMind(sample_every=4).run_shadow_mind(candidate.proposed, trusted, rows)
    assert first == again and first.sessions_seen == 32 and first.sessions_sampled == 8
    full = ShadowMind(sample_every=1).run_shadow_mind(
        candidate.proposed, trusted, rows,
        hostile=[skeleton("hx", f1_steps("hx"), Verdict.MALICIOUS)])
    assert full.misses_caught == 4 and full.regressions == 0 and full.fp_change == 0
    assert full.disagreement_rate == pytest.approx(4 / 32)
    assert full.calibration_delta is not None and full.calibration_delta < 0
    assert full.poisoning_sensitivity == 1.0


def test_canary_emits_at_least_trusted_on_every_observation() -> None:
    world = build()
    state_a = promoted_a(world)
    rows = (benign_traffic(20, "e") + [session(f"f1-{i}", f1_steps(f"f{i}"), Verdict.MALICIOUS)
                                       for i in range(20)])
    sampled = 0
    for candidate, trusted in ((GENESIS, state_a), (state_a, GENESIS)):
        evaluator = CanaryEvaluator(candidate=candidate, trusted=trusted,
                                    policy=CanaryPolicy(share=0.5))
        for s in rows:
            observation = evaluator.observe(s)
            assert observation.emitted >= observation.trusted_score
            sampled += observation.sampled
            if observation.sampled:
                assert observation.emitted == max(observation.trusted_score,
                                                  observation.candidate_score)
            else:
                assert observation.emitted == observation.trusted_score
    assert 0 < sampled < 2 * len(rows)  # both branches of emitted_score were exercised
    assert emitted_score(0.9, 0.1, sampled=True) == 0.9
    assert canary_sampled("abc", share=0.3) == canary_sampled("abc", share=0.3)
    for bad in (0.0, 1.5):
        with pytest.raises(ContractError):
            CanaryPolicy(share=bad)


def test_canary_regression_rejects_at_once_and_trusted_is_untouched() -> None:
    world = build()
    c = world.controller
    state_a = promoted_a(world)
    holdout = [skeleton("hb3", benign_steps("hb3"), Verdict.BENIGN)]
    drop_f3 = world.chamber.mint(state_a, remove=(f3_detector_id(state_a),), holdout=holdout,
                                 kinds=frozenset({CandidateKind.CONSOLIDATION}))
    c.submit(drop_f3, holdout=holdout, hostile=(), variant_seed=7)
    c.run_shadow(drop_f3.candidate_id, shadow_traffic())
    c.promote_canary(drop_f3.candidate_id)
    assert not isinstance(c.observe_canary(session("cb", benign_steps("cb"), Verdict.BENIGN)),
                          PromotionDecision)
    result = c.observe_canary(session("cf3", f3_steps("cf3"), Verdict.MALICIOUS))
    assert isinstance(result, PromotionDecision) and result.to_state is LifecycleState.REJECTED
    assert "protected_regressions" in result.reason
    assert c.mind.digest() == state_a.digest() and c.rollbacks() == ()
    assert not c.stats().canary_active
    with pytest.raises(ContractError):
        c.promote_trusted(drop_f3.candidate_id)


def test_promote_trusted_refuses_an_incomplete_canary_window() -> None:
    world = build()
    c = world.controller
    candidate, holdout = candidate_a(world)
    c.submit(candidate, holdout=holdout, hostile=(), variant_seed=7)
    c.run_shadow(candidate.candidate_id, shadow_traffic(3))
    c.promote_canary(candidate.candidate_id)
    c.observe_canary(session("one", benign_steps("one"), Verdict.BENIGN))
    with pytest.raises(ContractError, match="incomplete"):
        c.promote_trusted(candidate.candidate_id)
    assert c.mind.digest() == GENESIS.digest()


# --- the conservation gate -------------------------------------------------------------------


def test_offline_verdict_has_nine_checks_in_order_with_g8_pending() -> None:
    world = build()
    candidate, holdout = candidate_a(world)
    trusted = world.controller.mind.current()
    verdict = cg.offline_validation(candidate, trusted=trusted, lineage=world.dag,
                                    fossils=world.store, holdout=holdout, hostile=(),
                                    variant_seed=7, meter=WorkMeter())
    assert [r.check for r in verdict.results] == list(cg.ConservationCheck)
    assert not verdict.complete and not verdict.passed and verdict.offline_passed()
    g8 = verdict.result(cg.ConservationCheck.G8_SHADOW)
    assert not g8.passed and g8.measured is None and "PENDING" in g8.detail
    assert verdict.result(cg.ConservationCheck.G3_CURRENT_HOLDOUT).measured == pytest.approx(1.0)
    assert "VACUOUS" in verdict.result(cg.ConservationCheck.G2_HISTORICAL_REPLAY).detail
    with pytest.raises(ContractError):
        dataclasses.replace(verdict, passed=True)
    other = ShadowMind().run_shadow_mind(GENESIS, GENESIS, [])
    with pytest.raises(ContractError, match="different candidate"):
        cg.complete_with_shadow(verdict, other)


def test_g3_refuses_unmeasurable_utility_and_ignores_unnamed_holdout() -> None:
    world = build()
    trusted = world.controller.mind.current()
    named = [skeleton("hb9", benign_steps("hb9"), Verdict.BENIGN)]
    candidate = world.chamber.mint(trusted, add=(F1_MOTIF,), holdout=named)
    # The caller slips in a malicious episode the candidate did not name as holdout.
    smuggled = [skeleton("train", f1_steps("train"), Verdict.MALICIOUS)]
    verdict = cg.offline_validation(candidate, trusted=trusted, lineage=world.dag,
                                    fossils=world.store, holdout=[*named, *smuggled], hostile=(),
                                    variant_seed=7, meter=WorkMeter())
    g3 = verdict.result(cg.ConservationCheck.G3_CURRENT_HOLDOUT)
    assert not g3.passed and g3.measured is None and "UNMEASURED" in g3.detail
    assert "holdout used 1/2" in g3.detail


def test_g5_refuses_hostile_drops_and_protected_normalisation() -> None:
    world = build()
    state_a = promoted_a(world)
    hostile = [skeleton("hostile", f1_steps("hostile"), Verdict.MALICIOUS)]
    drop_f1 = world.chamber.mint(state_a, remove=(f1_detector_id(state_a),),
                                 kinds=frozenset({CandidateKind.CONSOLIDATION}))
    verdict = cg.offline_validation(drop_f1, trusted=state_a, lineage=world.dag,
                                    fossils=world.store, holdout=(), hostile=hostile,
                                    variant_seed=7, meter=WorkMeter())
    g5 = verdict.result(cg.ConservationCheck.G5_ADVERSARIAL)
    assert not g5.passed and "dropped below threshold 1" in g5.detail
    # A BASELINE anchored on credential meaning normalises a protected anchor.
    label = "poison-baseline"
    world.chamber.admit(label)
    poison = baseline_for(step(Relation.READ, props=CRED), "cand-" + _hex(label, 32), label)
    assert poison.protected
    proposed = state_a.with_changes(add=(poison,))
    candidate = EvolutionCandidate(
        candidate_id="cand-" + _hex(label, 32), kinds=frozenset({CandidateKind.STATISTICAL}),
        base_digest=state_a.digest(), proposed=proposed, delta=KnowledgeDelta(added=(poison,)),
        verdict_ids=(), capsule_ids=(),
        mask=uniform_mask([], protected=frozenset(), now_sequence=0),
        competition=(), holdout_episode_ids=(), mask_refusals=0, work_units=0, created_sequence=1)
    verdict = cg.offline_validation(candidate, trusted=state_a, lineage=world.dag,
                                    fossils=world.store, holdout=(), hostile=(), variant_seed=7,
                                    meter=WorkMeter())
    g5 = verdict.result(cg.ConservationCheck.G5_ADVERSARIAL)
    assert not g5.passed and poison.item_id in g5.detail


def test_g1_refuses_items_whose_capsules_the_gateway_never_admitted() -> None:
    world = build()
    trusted = world.controller.mind.current()
    candidate = world.chamber.mint(trusted, add=(F1_MOTIF,))
    ghost = "cand-" + _hex("ghost", 32)
    item = detector(F1_MOTIF, ghost, "never-admitted")
    forged = dataclasses.replace(candidate, proposed=trusted.with_changes(add=(item,)),
                                 delta=KnowledgeDelta(added=(item,)))
    verdict = cg.offline_validation(forged, trusted=trusted, lineage=world.dag,
                                    fossils=world.store, holdout=(), hostile=(), variant_seed=7,
                                    meter=WorkMeter())
    g1 = verdict.result(cg.ConservationCheck.G1_INTEGRITY)
    assert not g1.passed and "without lineage" in g1.detail and g1.measured < 1.0


def test_exhausted_validation_budget_fails_every_remaining_check_closed() -> None:
    world = build()
    state_a = promoted_a(world)
    candidate = world.chamber.mint(state_a, add=(F2_MOTIF,))
    verdict = cg.offline_validation(candidate, trusted=state_a, lineage=world.dag,
                                    fossils=world.store, holdout=(), hostile=(), variant_seed=7,
                                    meter=WorkMeter(budget=3))
    assert not verdict.offline_passed()
    assert all("work budget exhausted" in r.detail for r in verdict.results[1:7])


# --- payload screens, bounds, context transitions ---------------------------------------------


def test_every_payload_passes_stage5_authority_and_seam_screens() -> None:
    world = build()
    state_a = promoted_a(world)
    drop_f3 = world.chamber.mint(state_a, remove=(f3_detector_id(state_a),),
                                 kinds=frozenset({CandidateKind.CONSOLIDATION}))
    walk(world, drop_f3, shadow=shadow_traffic(1, tag="z"))
    world.controller.observe_probation(session("pf3", f3_steps("pf3"), Verdict.MALICIOUS))
    evaluator = CanaryEvaluator(candidate=GENESIS, trusted=state_a, policy=FAST)
    evaluator.observe(session("q", f1_steps("q"), Verdict.MALICIOUS))
    shadow = ShadowMind(work_budget=1).run_shadow_mind(state_a, GENESIS, shadow_traffic())
    verdict = cg.offline_validation(drop_f3, trusted=state_a, lineage=world.dag,
                                    fossils=world.store, holdout=(), hostile=(), variant_seed=7,
                                    meter=WorkMeter())
    payloads = [shadow.to_dict(), evaluator.report().to_dict(), verdict.to_dict(),
                *(r.to_dict() for r in world.controller.rollbacks()),
                *(d.to_dict() for d in world.controller.decisions())]
    assert evaluator.report().regressed and shadow.aborted and world.controller.rollbacks()
    for payload in payloads:
        assert authority_violations(payload) == () and seam_violations(payload) == ()


def test_decision_log_and_candidate_records_are_bounded() -> None:
    world = build()
    c = world.controller
    stale_base = GENESIS.with_changes(threshold=0.7)
    total = MAX_DECISION_LOG + 6
    for _ in range(total):
        candidate = world.chamber.mint(stale_base, add=(F1_MOTIF,))
        assert c.submit(candidate, holdout=(), hostile=(), variant_seed=1).reason == "stale_base"
    stats = c.stats()
    assert stats.decisions_logged == MAX_DECISION_LOG
    assert stats.decisions_dropped == total - MAX_DECISION_LOG
    assert stats.candidates_tracked <= pc.MAX_CANDIDATE_RECORDS and stats.rejected == total
    assert c.mind.digest() == GENESIS.digest()


def test_a_long_horizon_plateaus_every_store_the_controller_touches() -> None:
    """70 promote-then-rollback cycles: every log, record set, pin set and the DAG plateau."""
    world = build()
    c = world.controller
    base = promoted_a(world)
    holdout = [skeleton("h2", [step(Relation.READ, props=AUTHZ)], Verdict.MALICIOUS)]
    cycles, samples, collected = pc.MAX_ROLLBACK_LOG + 6, {}, []
    for cycle in range(cycles):
        walk(world, world.chamber.mint(c.mind.current(), add=(F2_MOTIF,), holdout=holdout),
             holdout=holdout, shadow=shadow_traffic(tag=f"lh{cycle}"),
             canary=benign_traffic(FAST.window_sessions, f"lc{cycle}"))
        rollback = c.rollback_learning(trigger=RollbackTrigger.OPERATOR_REQUEST)
        assert rollback.to_digest == base.digest() and rollback.restored_bytes_identical
        if cycle % 10 == 9:
            c.collect_lineage()
            collected.append(len(world.dag.nodes()))
        if cycle >= cycles - 5:
            samples[cycle] = (c.memory_bytes(), len(world.dag.nodes()))
    stats = c.stats()
    assert stats.rollbacks_logged == pc.MAX_ROLLBACK_LOG and stats.rollbacks_dropped == 6
    assert stats.decisions_logged == MAX_DECISION_LOG and stats.decisions_dropped > 0
    assert stats.candidates_tracked == pc.MAX_CANDIDATE_RECORDS
    assert len(world.store.fossils()) <= MAX_FOSSILS and world.store.evictions() > 0
    assert sum(f.pinned for f in world.store.fossils()) <= 3
    memory = [m for m, _ in samples.values()]
    assert max(memory) - min(memory) <= 0.02 * max(memory)  # plateau, not growth
    c.collect_lineage()
    # Collection keeps the lineage of every RETAINED fossil (review S6-R1: rollback may target
    # any of them), so live history is bounded by the fossil store — about ten nodes per
    # fossil here — and plateaus once the store is full, instead of by a collection period.
    assert len(world.dag.nodes()) <= 10 * (MAX_FOSSILS + 1)
    assert collected[-1] == collected[-2] == collected[-3], collected  # plateau, not growth
    assert all(world.dag.lineage_complete(i) for i in c.mind.current().items)
    assert world.dag.verify() == ()


def test_in_flight_candidates_are_capped_by_refusal_not_eviction() -> None:
    world = build()
    c = world.controller
    held = []
    for _ in range(MAX_PENDING_CANDIDATES):
        candidate, holdout = candidate_a(world)
        assert c.submit(candidate, holdout=holdout, hostile=(),
                        variant_seed=7).to_state is LifecycleState.OFFLINE_VALIDATED
        held.append(candidate.candidate_id)
    extra, holdout = candidate_a(world)
    with pytest.raises(ContractError, match="in flight"):
        c.submit(extra, holdout=holdout, hostile=(), variant_seed=7)
    assert all(c.lifecycle(cid) is LifecycleState.OFFLINE_VALIDATED for cid in held)


def _minted_transition(world: World) -> EpochTransition:
    """A context change the way the learner gets one: from Stage 1's corroborated decision."""
    registry = KnowledgeContextRegistry(identity=IDENTITY, epoch_id=0, sequence=0)
    decision = EpochDecision(epoch_id=1, reason=EpochTransitionReason.SYSTEM_CHANGE_CORROBORATED,
                             changed_components=frozenset({"kernel_id"}), corroborated=True,
                             detail="test")
    transition = registry.open_new_epoch(decision, identity=SystemIdentity(kernel_id="k-upgraded"),
                                         sequence=1, trusted=world.controller.mind.current(),
                                         fossils=world.store)
    assert transition is not None and transition.current == CTX2
    return transition


def test_context_transition_changes_only_the_active_context() -> None:
    world = build()
    c = world.controller
    state_a = promoted_a(world)
    item_change = EpochTransition(previous=CTX, current=CTX2, resurrect=None,
                                  proposal=KnowledgeDelta(active_context=CTX2,
                                                          removed=(f1_detector_id(state_a),)))
    with pytest.raises(ContractError, match="chamber"):
        c.apply_context_transition(item_change)
    decision = c.apply_context_transition(_minted_transition(world))
    assert decision.to_state is LifecycleState.DORMANT
    assert c.mind.current().active_context == CTX2
    assert c.mind.current().items == state_a.items
    fossil = world.store.get(c.mind.digest())
    assert fossil is not None and fossil.creation_reason is FossilReason.CONTEXT_DORMANCY
    rollback = c.rollback_learning(trigger=RollbackTrigger.OPERATOR_REQUEST,
                                   to_digest=state_a.digest())
    assert c.mind.digest() == state_a.digest() and rollback.restored_bytes_identical


def test_context_transition_is_refused_during_probation() -> None:
    world = build()
    promoted_a(world, finish_probation=False)
    with pytest.raises(ContractError, match="probation"):
        world.controller.apply_context_transition(_minted_transition(world))


def test_a_hand_built_context_transition_is_refused() -> None:
    """S6-AUTH-05: a transition not minted by open_new_epoch skips Stage 1's corroboration
    refusal, so it must not move trusted active_context — not to a real context, and not to
    one that does not exist (which used to install a pinned CONTEXT_DORMANCY fossil)."""
    world = build()
    c = world.controller
    before = c.mind.digest()
    for target in (CTX2, "ctx-" + "0" * 16):
        forged = EpochTransition(previous=CTX, current=target, resurrect=None,
                                 proposal=KnowledgeDelta(active_context=target))
        with pytest.raises(ContractError, match="not minted"):
            c.apply_context_transition(forged)
    stale = EpochTransition(previous="ctx-" + "1" * 16, current=CTX2, resurrect=None,
                            proposal=KnowledgeDelta(active_context=CTX2))
    with pytest.raises(ContractError, match="previous context"):
        c.apply_context_transition(stale)
    assert c.mind.digest() == before and c.stats().context_transitions == 0
    minted = _minted_transition(world)
    assert c.apply_context_transition(minted).to_state is LifecycleState.DORMANT
    with pytest.raises(ContractError):  # single use: a replay is refused
        c.apply_context_transition(minted)


def test_every_promotion_has_its_four_parents_and_lineage_is_complete() -> None:
    world = build()
    promoted_a(world)
    promotions = [n for n in world.dag.nodes()
                  if n.kind is NodeKind.PROMOTION and n.node_id != pc.GENESIS_PROMOTION_NODE]
    assert len(promotions) == 1
    kinds = {world.dag.node(p).kind for p in world.dag.parents(promotions[0].node_id)}
    assert kinds == {NodeKind.CANDIDATE, NodeKind.CONSERVATION, NodeKind.SHADOW, NodeKind.CANARY}
    assert all(world.dag.lineage_complete(i) for i in world.controller.mind.current().items)
    assert world.dag.verify() == ()
    transitions = [(d.from_state, d.to_state) for d in world.controller.decisions()]
    assert transitions == [
        (LifecycleState.CANDIDATE, LifecycleState.OFFLINE_VALIDATED),
        (LifecycleState.OFFLINE_VALIDATED, LifecycleState.SHADOW),
        (LifecycleState.SHADOW, LifecycleState.CANARY),
        (LifecycleState.CANARY, LifecycleState.TRUSTED),
    ]


# --- the constitution's law tests (LEARNING_CONSTITUTION binds these names) -----------------


def test_a_candidate_is_not_promoted_on_score_alone() -> None:
    """MODEL_SCORE_IS_NOT_KNOWLEDGE: passing offline validation is not trust.

    A candidate that clears every offline check still cannot reach TRUSTED without its
    shadow run and a complete canary window; each shortcut raises and the trusted digest
    does not move until the full path has been walked.
    """
    world = build()
    c = world.controller
    candidate, holdout = candidate_a(world)
    before = c.mind.digest()
    decision = c.submit(candidate, holdout=holdout, hostile=(), variant_seed=7)
    assert decision.to_state is LifecycleState.OFFLINE_VALIDATED
    for shortcut in (c.promote_trusted, c.promote_canary):
        with pytest.raises(ContractError, match="cannot be skipped"):
            shortcut(candidate.candidate_id)
    assert c.run_shadow(candidate.candidate_id, shadow_traffic(3)).to_state is (
        LifecycleState.SHADOW)
    with pytest.raises(ContractError, match="cannot be skipped"):
        c.promote_trusted(candidate.candidate_id)
    c.promote_canary(candidate.candidate_id)
    with pytest.raises(ContractError, match="incomplete or regressed"):
        c.promote_trusted(candidate.candidate_id)
    assert c.mind.digest() == before


def test_a_candidate_that_forgets_a_historical_detection_is_refused() -> None:
    """SUCCESS_IS_NOT_PERMISSION_TO_FORGET: dropping the F1 detector is refused by G2."""
    world = build()
    state_a = promoted_a(world)
    forget = world.chamber.mint(state_a, remove=(f1_detector_id(state_a),),
                                kinds=frozenset({CandidateKind.CONSOLIDATION}))
    decision = world.controller.submit(forget, holdout=(), hostile=(), variant_seed=7)
    assert decision.to_state is LifecycleState.REJECTED
    edge = world.dag.edge(forget.candidate_id, f"conservation-{forget.candidate_id}")
    assert edge is not None and "G2_HISTORICAL_REPLAY" in edge.gate_result
    assert world.controller.mind.digest() == state_a.digest()
