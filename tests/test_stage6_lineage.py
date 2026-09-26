"""Stage 6 package `lineage`: fossils, the lineage DAG, counterfactual rehearsal, quantised
export and the Stage 7 learning record (D6.8, D6.9, D6.10, D6.18, HEL-F26).

These tests exercise behaviour and failure paths: a corrupted fossil is refused and skipped,
a pinned fossil survives eviction, the DAG refuses forged lineage and detects a one-field
tamper, collection never folds live lineage, score-invariant variants really leave every
score unchanged, a quantised variant is rejected when it moves alerts, and the learning
record passes Stage 5's screens and carries no capsule id.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path

import pytest

from pocketsec.stage0.contracts.common import ContractError, digest_of_bytes
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.epoch.model import SystemIdentity
from pocketsec.stage1.ssir.entities import SemanticProperty
from pocketsec.stage1.ssir.relations import Relation
from pocketsec.stage2.adaptation.quarantine import DEFAULT_CONSISTENCY_RADIUS, pattern_key
from pocketsec.stage2.encoder import ssir_encoder
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_LAYOUT, FEATURE_WIDTH, GROUP_OFFSETS
from pocketsec.stage5.stage6_interface import authority_violations, seam_violations
from pocketsec.stage6.capsule.experience_capsule import EncodedStep, LabelOrigin
from pocketsec.stage6.constitution.learning import property_mask, raised_mask, touches_protected
from pocketsec.stage6.export import learning_record as lr
from pocketsec.stage6.export import quantized_candidates as qc
from pocketsec.stage6.fossils.lineage import (
    MAX_TOMBSTONE_IDS,
    KnowledgeLineageDAG,
    LineageCapacityError,
    LineageNode,
    NodeKind,
)
from pocketsec.stage6.fossils.store import (
    MAX_PINNED_FOSSILS,
    MAX_TOMBSTONES,
    FossilCapacityError,
    FossilIntegrityError,
    FossilReason,
    FossilStore,
    UnknownFossilError,
)
from pocketsec.stage6.memory.episodic import EpisodeSkeleton
from pocketsec.stage6.memory.semantic import (
    ALL_CONTEXTS,
    ItemKind,
    ItemLineage,
    ItemValidation,
    KnowledgeItem,
    LineageError,
    MotifStep,
    TrustedKnowledgeState,
    context_id_for,
    genesis_state,
    motif_pattern_key,
    score_session,
)
from pocketsec.stage6.rehearsal.counterfactual import (
    CAN_LOWER_RECALL_KINDS,
    MAX_TIME_BUCKET,
    MAX_VARIANTS_PER_EPISODE,
    SCORE_INVARIANT_KINDS,
    VariantKind,
    generate_counterfactual_replay,
)

IDENTITY = SystemIdentity(kernel_id="k-test")
CTX = context_id_for(IDENTITY)
CRED = property_mask([SemanticProperty.CREDENTIAL])
EGRESS = property_mask([SemanticProperty.EXTERNAL_ENDPOINT])
PRIV = raised_mask(["privilege"])
_OBJ = GROUP_OFFSETS["object_semantics"]
_RAISED = GROUP_OFFSETS["state_delta_raised"]
_TEMPORAL = GROUP_OFFSETS["temporal"]
_ACTOR = GROUP_OFFSETS["actor_semantics"]
_ACTOR_WIDTH = dict(FEATURE_LAYOUT)["actor_semantics"]


def _hex(label: str, width: int) -> str:
    return hashlib.sha256(label.encode()).hexdigest()[:width]


def _digest(label: str) -> str:
    return "sha256:" + _hex(label, 64)


def cap_id(label: str) -> str:
    return "cap-" + _hex(label, 24)


def step(relation: Relation, *, props: int = 0, raised: int = 0, actor: int = 0,
         bucket: int = 3, actor_class: int = 0, group: str = "a") -> EncodedStep:
    features = [0.0] * FEATURE_WIDTH
    features[GROUP_OFFSETS["relation_onehot"] + int(relation)] = 1.0
    for bit in range(dict(FEATURE_LAYOUT)["object_semantics"]):
        if props >> bit & 1:
            features[_OBJ + bit] = 1.0
    for bit in range(dict(FEATURE_LAYOUT)["state_delta_raised"]):
        if raised >> bit & 1:
            features[_RAISED + bit] = 1.0
    if actor_class:
        features[_ACTOR + actor_class % _ACTOR_WIDTH] = 1.0
    features[_TEMPORAL] = round(bucket / MAX_TIME_BUCKET, 6)
    return EncodedStep(
        features=tuple(features), relation=int(relation), relation_family=0,
        state_delta_mask=raised, time_bucket=bucket, delta_phi=0.0, object_property_mask=props,
        epoch_id=1, actor_slot=actor,
        uncertainty=0.0, source_group="grp-" + _hex(group, 16), causal_signature="",
        parent_signature="", evidence=(_digest(f"ev-{relation}-{actor}-{props}"),),
    )


def skeleton(label: str, steps: list[EncodedStep], verdict: Verdict) -> EpisodeSkeleton:
    return EpisodeSkeleton(
        episode_id=cap_id(label), steps=tuple(steps), verdict=verdict,
        label_origin=LabelOrigin.GROUND_TRUTH, epoch_id=1, context_id=CTX,
        visibility_mask=(1 << len(steps)) - 1, truncated=False,
        anchors_touched=tuple(sorted({
            a for s in steps for a in touches_protected(s.object_property_mask, s.state_delta_mask)
        })),
    )


EXFIL_MOTIF = (
    MotifStep(int(Relation.READ), CRED, 0, 0),
    MotifStep(int(Relation.SEND), EGRESS, 0, 0),
)


def detector(motif=EXFIL_MOTIF, *, candidate: str = "cand-a", capsule: str = "c1",
             weight: float = 0.9) -> KnowledgeItem:
    return KnowledgeItem.build(
        kind=ItemKind.DETECTOR, context_ids=(ALL_CONTEXTS,), pattern_key=motif_pattern_key(motif),
        weight=weight, origin_verdict=Verdict.MALICIOUS,
        lineage=ItemLineage(candidate, (cap_id(capsule),), (_digest(capsule),), ()),
        validation=ItemValidation.fresh(sequence=1), motif=motif,
    )


def baseline(example: EncodedStep, *, candidate: str = "cand-b",
             capsule: str = "c2") -> KnowledgeItem:
    return KnowledgeItem.build(
        kind=ItemKind.BASELINE, context_ids=(CTX,), pattern_key=pattern_key(example.to_encoded()),
        weight=DEFAULT_CONSISTENCY_RADIUS, origin_verdict=Verdict.BENIGN,
        lineage=ItemLineage(candidate, (cap_id(capsule),), (_digest(capsule),), ()),
        validation=ItemValidation.fresh(sequence=1), anchor=example.meaning(),
    )


def learned_state(*items: KnowledgeItem, threshold: float | None = None) -> TrustedKnowledgeState:
    return genesis_state(identity=IDENTITY).with_changes(add=items, threshold=threshold)


def exfil_session() -> list[EncodedStep]:
    return [step(Relation.READ, props=CRED), step(Relation.SEND, props=EGRESS),
            step(Relation.READ, actor=1, actor_class=3, group="b")]


def benign_session(label: str = "x") -> list[EncodedStep]:
    return [step(Relation.READ, actor=0, actor_class=1, group=label),
            step(Relation.WRITE, actor=1, actor_class=2, group=label + "y")]


def node(node_id: str, kind: NodeKind, *, seq: int = 1) -> LineageNode:
    return LineageNode(node_id, kind, _digest(f"{kind}:{node_id}"), seq, "")


def record_chain(dag: KnowledgeLineageDAG, capsule: str, candidate: str, *, seq: int = 1,
                 promote: bool = True) -> None:
    """GENESIS -> CAPSULE -> VERDICT -> CANDIDATE -> PROMOTION, as gateway and controller do."""
    if not dag.has("genesis-node"):
        dag.update_lineage_dag(node=node("genesis-node", NodeKind.GENESIS, seq=0), parents=(),
                               reason="genesis")
    cid, vid = cap_id(capsule), f"ver-{capsule}"
    dag.update_lineage_dag(node=node(cid, NodeKind.CAPSULE, seq=seq), parents=("genesis-node",),
                           reason="admitted", evidence=(_digest(capsule),))
    dag.update_lineage_dag(node=node(vid, NodeKind.VERDICT, seq=seq), parents=(cid,),
                           reason="TRUSTED_CANDIDATE")
    dag.update_lineage_dag(node=node(candidate, NodeKind.CANDIDATE, seq=seq), parents=(vid,),
                           reason="spawned", transformation="SYMBOLIC")
    if promote:
        dag.update_lineage_dag(node=node(f"prom-{candidate}", NodeKind.PROMOTION, seq=seq),
                               parents=(candidate,), reason="promoted",
                               tests=(_digest(f"cons{candidate}"),),
                               parent_versions=(_digest("s0"),))


def fossilise(store: FossilStore, state: TrustedKnowledgeState, seq: int, *, pin: bool = False,
              reason: FossilReason = FossilReason.PROMOTION):
    return store.create_fossil(state, reason=reason, fingerprint=_digest("fp"), epoch_range=(0, 1),
                               sequence=seq, pin=pin)


# --- D6.9 fossils ----------------------------------------------------------------------------


def test_state_digest_is_the_fossil_hash() -> None:
    """Rule A: artifact_hash IS TrustedKnowledgeState.digest() of the uncompressed bytes."""
    state = learned_state(detector())
    store = FossilStore()
    fossil = fossilise(store, state, 5)
    assert fossil.artifact_hash == state.digest() == digest_of_bytes(state.canonical_bytes())
    assert store.payload(fossil.artifact_hash) == state.canonical_bytes()
    assert fossil.compressed_bytes < len(state.canonical_bytes())
    restored = store.load(fossil.artifact_hash)
    assert restored.canonical_bytes() == state.canonical_bytes()
    assert fossil.parent_hashes == (state.parent_digest,)
    assert fossil.capabilities_preserved == tuple(i.item_id for i in state.detectors())
    assert dict(fossil.versions).keys() == {"state", "capsule_schema", "encoder"}


def test_byte_flipped_fossil_file_raises_and_is_skipped(tmp_path: Path) -> None:
    store = FossilStore(directory=tmp_path)
    older = learned_state(detector())
    newer = older.with_changes(threshold=0.6)
    good = fossilise(store, older, 1, reason=FossilReason.PRE_PROMOTION)
    bad = fossilise(store, newer, 2)
    assert store.latest_known_good() == bad
    path = tmp_path / (bad.artifact_hash.split(":")[1] + ".fossil")
    raw = bytearray(path.read_bytes())
    raw[len(raw) // 2] ^= 0x01
    path.write_bytes(bytes(raw))
    with pytest.raises(FossilIntegrityError):
        store.load(bad.artifact_hash)
    with pytest.raises(FossilIntegrityError):
        store.payload(bad.artifact_hash)
    assert store.latest_known_good() == good  # the corrupted fossil is skipped, never returned
    assert store.latest_known_good(excluding=frozenset({good.artifact_hash})) is None
    assert store.stats().integrity_failures >= 3


def test_missing_or_truncated_fossil_file_raises(tmp_path: Path) -> None:
    store = FossilStore(directory=tmp_path)
    fossil = fossilise(store, learned_state(), 0, reason=FossilReason.GENESIS)
    path = tmp_path / (fossil.artifact_hash.split(":")[1] + ".fossil")
    path.write_bytes(path.read_bytes()[:10])
    with pytest.raises(FossilIntegrityError):
        store.load(fossil.artifact_hash)
    path.unlink()
    with pytest.raises(FossilIntegrityError):
        store.load(fossil.artifact_hash)


def _chain_of_states(count: int) -> list[TrustedKnowledgeState]:
    states = [genesis_state(identity=IDENTITY)]
    for _ in range(count - 1):
        states.append(states[-1].with_changes(threshold=0.5))
    return states


def test_pinned_fossils_are_never_evicted_and_tombstones_are_recorded() -> None:
    store = FossilStore(max_fossils=3)
    states = _chain_of_states(8)
    pinned = fossilise(store, states[0], 0, pin=True, reason=FossilReason.GENESIS)
    for seq, state in enumerate(states[1:], start=1):
        fossilise(store, state, seq)
    held = {f.artifact_hash for f in store.fossils()}
    assert pinned.artifact_hash in held and len(held) == 3
    assert store.evictions() == 5 == len(store.tombstones())
    evicted = states[1].digest()
    tomb = store.tombstone_for(evicted)
    assert tomb is not None and tomb.parent_hashes == (states[0].digest(),)
    with pytest.raises(UnknownFossilError, match="evicted"):
        store.load(evicted)  # rollback depth is bounded, and the store says so


def test_pin_cap_and_refusal_to_evict_pinned() -> None:
    store = FossilStore(max_fossils=MAX_PINNED_FOSSILS)
    states = _chain_of_states(MAX_PINNED_FOSSILS + 2)
    for seq, state in enumerate(states[:MAX_PINNED_FOSSILS]):
        fossilise(store, state, seq, pin=True)
    # Full of pinned fossils: the newcomer is refused rather than a rollback target evicted.
    with pytest.raises(FossilCapacityError):
        fossilise(store, states[-2], 9)
    with pytest.raises(FossilCapacityError):  # and a fifth pin is refused outright
        fossilise(store, states[-2], 9, pin=True)
    store.unpin(states[0].digest())
    fossilise(store, states[-2], 9)
    assert store.get(states[0].digest()) is None  # the one unpinned fossil was the victim
    assert all(store.get(s.digest()) is not None for s in states[1:MAX_PINNED_FOSSILS])
    store.pin(states[-2].digest())  # four pinned again, the store is full of rollback targets
    with pytest.raises(FossilCapacityError):
        fossilise(store, states[-1], 10)
    assert store.stats().pinned == MAX_PINNED_FOSSILS


def test_fossil_load_refuses_items_without_complete_lineage() -> None:
    state = learned_state(detector(candidate="cand-ghost"))
    store = FossilStore()
    fossil = fossilise(store, state, 1)
    with pytest.raises(LineageError):
        store.load(fossil.artifact_hash, lineage=KnowledgeLineageDAG())
    dag = KnowledgeLineageDAG()
    record_chain(dag, "c1", "cand-ghost")
    assert store.load(fossil.artifact_hash, lineage=dag).digest() == state.digest()


def test_fossil_store_plateaus_over_a_long_horizon() -> None:
    """Long-horizon growth: fossils cap at 32, tombstones at 256, memory_bytes plateaus."""
    store = FossilStore()
    state = genesis_state(identity=IDENTITY)
    samples: dict[int, int] = {}
    for seq in range(1, 601):
        state = state.with_changes(threshold=0.5)
        fossilise(store, state, seq)
        samples[seq] = store.memory_bytes()
    stats = store.stats()
    assert stats.fossils == 32 and stats.tombstones == MAX_TOMBSTONES
    assert stats.evictions == 600 - 32 and stats.tombstones_dropped == 600 - 32 - MAX_TOMBSTONES
    assert samples[600] <= samples[400] * 1.01  # plateau, not growth


# --- D6.10 lineage DAG -----------------------------------------------------------------------


def test_dag_refuses_forged_or_malformed_lineage() -> None:
    dag = KnowledgeLineageDAG()
    record_chain(dag, "c1", "cand-a")
    node = LineageNode("n-x", NodeKind.CANDIDATE, _digest("x"), 1, "")
    with pytest.raises(LineageError, match="unknown parent"):
        dag.update_lineage_dag(node=node, parents=("nope",), reason="r")
    with pytest.raises(LineageError, match="only GENESIS"):
        dag.update_lineage_dag(node=node, parents=(), reason="r")
    with pytest.raises(LineageError, match="cycle"):
        dag.update_lineage_dag(node=node, parents=("n-x",), reason="r")
    with pytest.raises(LineageError, match="duplicate"):
        dag.update_lineage_dag(node=LineageNode("cand-a", NodeKind.CANDIDATE, _digest("y"), 1, ""),
                               parents=("genesis-node",), reason="r")
    with pytest.raises(LineageError, match="collect"):
        dag.update_lineage_dag(node=LineageNode("t", NodeKind.TOMBSTONE, _digest("t"), 1, ""),
                               parents=("genesis-node",), reason="r")
    with pytest.raises(LineageError, match="gate_result"):
        dag.update_lineage_dag(node=node, parents=("cand-a",), reason="r", gate_result="MAYBE")
    with pytest.raises(LineageError):
        dag.update_lineage_dag(node=LineageNode("g2", NodeKind.GENESIS, _digest("g2"), 0, ""),
                               parents=("cand-a",), reason="r")
    assert dag.stats().refused == 7 and not dag.has("n-x")


def test_verify_catches_a_one_field_tamper() -> None:
    dag = KnowledgeLineageDAG()
    record_chain(dag, "c1", "cand-a")
    assert dag.verify() == ()
    edge = dag.edge("cand-a", "prom-cand-a")
    for field, value in (("reason", "benign"), ("evidence", (_digest("z"),)), ("tests", ()),
                         ("parent_versions", ()), ("transformation", "x"),
                         ("gate_result", "FAIL:G2")):
        tampered = KnowledgeLineageDAG()
        record_chain(tampered, "c1", "cand-a")
        tampered._edges[("cand-a", "prom-cand-a")] = dataclasses.replace(edge, **{field: value})
        assert tampered.verify() == ("cand-a->prom-cand-a",), field
    # A node digest swapped underneath its edges is caught through both edges bound to it.
    dag._nodes["cand-a"] = dataclasses.replace(dag._nodes["cand-a"], digest=_digest("forged"))
    assert set(dag.verify()) == {"ver-c1->cand-a", "cand-a->prom-cand-a"}


def test_lineage_complete_requires_promotion_capsule_and_verdict() -> None:
    dag = KnowledgeLineageDAG()
    record_chain(dag, "c1", "cand-a")
    record_chain(dag, "c2", "cand-unpromoted", promote=False)
    assert dag.lineage_complete(detector(candidate="cand-a", capsule="c1"))
    assert not dag.lineage_complete(detector(candidate="cand-unpromoted", capsule="c2"))
    assert not dag.lineage_complete(detector(candidate="cand-a", capsule="never-admitted"))
    assert not dag.lineage_complete(detector(candidate="cand-missing", capsule="c1"))
    # A capsule node with no VERDICT child was never judged by the gateway.
    dag.update_lineage_dag(node=LineageNode(cap_id("c3"), NodeKind.CAPSULE, _digest("c3"), 2, ""),
                           parents=("genesis-node",), reason="admitted")
    assert not dag.lineage_complete(detector(candidate="cand-a", capsule="c3"))
    # Genesis is not a way to skip provenance: only the genesis THRESHOLD passes.
    genesis_threshold = genesis_state(identity=IDENTITY).items[0]
    assert dag.lineage_complete(genesis_threshold)
    assert not dag.lineage_complete(detector(candidate="genesis", capsule="c1"))
    state = learned_state(detector(candidate="cand-a", capsule="c1"))
    assert TrustedKnowledgeState.from_canonical_bytes(state.canonical_bytes(), lineage=dag) == state


def test_collect_never_folds_live_lineage_and_folds_dead_lineage() -> None:
    dag = KnowledgeLineageDAG()
    record_chain(dag, "c1", "cand-live")
    record_chain(dag, "c2", "cand-dead", seq=2)
    record_chain(dag, "c3", "cand-pinned", seq=3)
    fossil_node = LineageNode("fos-1", NodeKind.FOSSIL, _digest("state-pinned"), 3, "")
    dag.update_lineage_dag(node=fossil_node,
                           parents=("prom-cand-pinned",), reason="fossilised")
    live = detector(candidate="cand-live", capsule="c1")
    folded = dag.collect(live_items=[live], pinned_fossils=[_digest("state-pinned")])
    assert folded == 4  # capsule, verdict, candidate and promotion of the dead chain
    assert dag.lineage_complete(live)
    assert not dag.has("cand-dead") and dag.has("cand-pinned") and dag.has(cap_id("c3"))
    assert cap_id("c2") in dag.tombstone_ids()
    assert dag.verify() == ()
    assert dag.collect(live_items=[live], pinned_fossils=[_digest("state-pinned")]) == 0
    # A tombstoned capsule still counts for an item that cites it (e.g. restored from a fossil) …
    record_chain(dag, "c4", "cand-restored", seq=4)
    restored = dataclasses.replace(
        detector(candidate="cand-restored", capsule="c4"),
        lineage=ItemLineage("cand-restored", (cap_id("c4"), cap_id("c2")), (_digest("c4"),), ()),
    )
    assert dag.lineage_complete(restored)
    # … but a capsule id the DAG never saw does not.
    unseen = ItemLineage("cand-restored", (cap_id("zz"),), (_digest("z"),), ())
    forged = dataclasses.replace(restored, lineage=unseen)
    assert not dag.lineage_complete(forged)


def test_tombstone_id_set_is_bounded_and_counts_what_it_drops() -> None:
    dag = KnowledgeLineageDAG()
    for index in range(MAX_TOMBSTONE_IDS // 2 + 10):
        record_chain(dag, f"d{index}", f"cand-d{index}", seq=index)
    dag.collect(live_items=[], pinned_fossils=[])
    stats = dag.stats()
    assert stats.tombstone_ids == MAX_TOMBSTONE_IDS
    assert stats.tombstone_ids_dropped == stats.folded_total - MAX_TOMBSTONE_IDS > 0
    assert cap_id("d0") in dag.tombstone_ids()  # capsule ids are kept first


def test_dag_capacity_refuses_then_collect_makes_room() -> None:
    dag = KnowledgeLineageDAG(max_nodes=6, max_edges=16)
    record_chain(dag, "c1", "cand-a")  # 5 nodes
    with pytest.raises(LineageCapacityError):
        record_chain(dag, "c2", "cand-b")  # the capsule fits, its verdict does not
    assert dag.stats().nodes == 6 and dag.stats().refused == 1
    live = detector(candidate="cand-a", capsule="c1")
    assert dag.collect(live_items=[live], pinned_fossils=[]) == 1  # only the orphaned capsule
    assert dag.lineage_complete(live)
    assert dag.collect(live_items=[], pinned_fossils=[]) == 4
    record_chain(dag, "c3", "cand-c")
    assert dag.stats().nodes <= 6
    assert not dag.lineage_complete(live)  # what nobody kept live is gone, and fails closed


def test_dag_plateaus_over_a_long_horizon() -> None:
    """5000 promotions, collecting every 50 with the newest 8 items live: nodes plateau."""
    dag = KnowledgeLineageDAG()
    live: list[KnowledgeItem] = []
    peak_late = peak_early = 0
    for index in range(5000):
        record_chain(dag, f"h{index}", f"cand-h{index}", seq=index)
        live = (live + [detector(candidate=f"cand-h{index}", capsule=f"h{index}")])[-8:]
        if index % 50 == 49:
            dag.collect(live_items=live, pinned_fossils=[])
            assert all(dag.lineage_complete(item) for item in live)
        nodes = dag.stats().nodes
        if index < 2500:
            peak_early = max(peak_early, nodes)
        else:
            peak_late = max(peak_late, nodes)
    assert peak_late <= peak_early < 300
    assert dag.verify() == ()


def test_ancestors_respects_max_depth() -> None:
    dag = KnowledgeLineageDAG()
    record_chain(dag, "c1", "cand-a")
    assert dag.ancestors("prom-cand-a") == ("cand-a", "ver-c1", cap_id("c1"), "genesis-node")
    assert dag.ancestors("prom-cand-a", max_depth=2) == ("cand-a", "ver-c1")


# --- D6.8 counterfactual rehearsal -----------------------------------------------------------


def _scores(state: TrustedKnowledgeState, steps) -> tuple[float, tuple[str, ...], float]:
    result = score_session(state, steps, context_id=CTX)
    return result.score, result.detector_hits, result.unexplained


def test_variants_are_deterministic_and_bounded() -> None:
    sk = skeleton("s1", exfil_session(), Verdict.MALICIOUS)
    decoys = [skeleton("d1", benign_session(), Verdict.BENIGN)]
    first = generate_counterfactual_replay(sk, seed=7, decoys=decoys, motifs=[EXFIL_MOTIF])
    assert first == generate_counterfactual_replay(sk, seed=7, decoys=decoys, motifs=[EXFIL_MOTIF])
    assert len(first) == MAX_VARIANTS_PER_EPISODE and {v.kind for v in first} == set(VariantKind)
    other = generate_counterfactual_replay(sk, seed=8, decoys=decoys, motifs=[EXFIL_MOTIF])
    assert [v.steps for v in other] != [v.steps for v in first]
    assert len(generate_counterfactual_replay(sk, seed=7, max_variants=2)) == 2
    with pytest.raises(ValueError):
        generate_counterfactual_replay(sk, seed=7, max_variants=MAX_VARIANTS_PER_EPISODE + 1)
    with pytest.raises(ValueError, match="BENIGN"):
        generate_counterfactual_replay(sk, seed=7, decoys=[sk])
    lone = skeleton("s2", [step(Relation.READ, props=CRED)], Verdict.MALICIOUS)
    kinds = {v.kind for v in generate_counterfactual_replay(lone, seed=1)}
    assert VariantKind.SUBSTITUTE_PROCESS_CLASS not in kinds
    assert VariantKind.INJECT_DECOYS not in kinds


def test_score_invariant_kinds_leave_every_score_unchanged() -> None:
    """RENAME, ALTER_TIMING and SUBSTITUTE are INERT by construction: every score identical."""
    state = learned_state(detector(), baseline(step(Relation.READ, actor_class=1)))
    sessions = [skeleton("m", exfil_session(), Verdict.MALICIOUS),
                skeleton("b", benign_session(), Verdict.BENIGN)]
    checked = 0
    for sk in sessions:
        for seed in range(12):
            kinds = sorted(SCORE_INVARIANT_KINDS)
            for variant in generate_counterfactual_replay(sk, seed=seed, kinds=kinds):
                assert _scores(state, variant.steps) == _scores(state, sk.steps), variant.kind
                assert variant.semantics_preserved and variant.expected_verdict is sk.verdict
                checked += 1
    assert checked == 2 * 12 * 3
    (renamed,) = generate_counterfactual_replay(sessions[0], seed=0,
                                                kinds=[VariantKind.RENAME_ACTORS])
    assert [s.actor_slot for s in renamed.steps] != [s.actor_slot for s in sessions[0].steps]


def test_substitute_touches_only_actor_semantics() -> None:
    sk = skeleton("m", exfil_session(), Verdict.MALICIOUS)
    (variant,) = generate_counterfactual_replay(sk, seed=3,
                                                kinds=[VariantKind.SUBSTITUTE_PROCESS_CLASS])
    for before, after in zip(sk.steps, variant.steps, strict=True):
        assert before.meaning() == after.meaning()
        assert before.object_property_mask == after.object_property_mask
        assert before.state_delta_mask == after.state_delta_mask
        outside = [i for i in range(FEATURE_WIDTH) if not _ACTOR <= i < _ACTOR + _ACTOR_WIDTH]
        assert all(before.features[i] == after.features[i] for i in outside)
    assert any(b.features != a.features for b, a in zip(sk.steps, variant.steps, strict=True))


def test_decoys_can_only_raise_a_score() -> None:
    state = learned_state(detector(), baseline(step(Relation.READ, actor_class=1)))
    decoys = [skeleton(f"d{i}", benign_session(f"z{i}"), Verdict.BENIGN) for i in range(3)]
    raised = 0
    explained = [step(Relation.READ, actor_class=1)]  # U = 0 until a decoy actor arrives
    cases = (("m", exfil_session(), Verdict.MALICIOUS), ("b", explained, Verdict.BENIGN))
    for label, steps, verdict in cases:
        sk = skeleton(label, steps, verdict)
        for seed in range(10):
            (variant,) = generate_counterfactual_replay(sk, seed=seed, decoys=decoys,
                                                        kinds=[VariantKind.INJECT_DECOYS])
            fresh = {s.actor_slot for s in variant.steps} - {s.actor_slot for s in sk.steps}
            assert fresh and len(variant.steps) > len(sk.steps)
            after, before = _scores(state, variant.steps)[0], _scores(state, sk.steps)[0]
            assert after >= before
            raised += after > before
    assert raised > 0  # it does move the false-positive side


def test_drop_telemetry_is_the_kind_that_can_lower_recall() -> None:
    assert CAN_LOWER_RECALL_KINDS == {VariantKind.DROP_TELEMETRY}
    state = learned_state(detector())
    threshold = state.threshold()
    # A redundant bystander step exists: the drop picks it, semantics are preserved.
    padded = skeleton("m", exfil_session(), Verdict.MALICIOUS)
    drop = [VariantKind.DROP_TELEMETRY]
    (kept,) = generate_counterfactual_replay(padded, seed=0, kinds=drop, motifs=[EXFIL_MOTIF])
    assert kept.semantics_preserved and kept.expected_verdict is Verdict.MALICIOUS
    assert score_session(state, kept.steps, context_id=CTX).score >= threshold
    assert kept.visibility_mask == padded.visibility_mask & ~(1 << 2)
    # Only the motif's own two steps: every drop breaks the only matching motif.
    bare = skeleton("m2", exfil_session()[:2], Verdict.MALICIOUS)
    (lost,) = generate_counterfactual_replay(bare, seed=0, kinds=drop, motifs=[EXFIL_MOTIF])
    assert not lost.semantics_preserved and lost.expected_verdict is Verdict.UNKNOWN
    assert score_session(state, lost.steps, context_id=CTX).score < threshold
    assert bin(lost.visibility_mask).count("1") == 1


def test_drop_without_motif_knowledge_fails_closed_on_meaningful_steps() -> None:
    # Both steps touch protected anchors.
    bare = skeleton("m3", exfil_session()[:2], Verdict.MALICIOUS)
    (variant,) = generate_counterfactual_replay(bare, seed=4, kinds=[VariantKind.DROP_TELEMETRY])
    assert not variant.semantics_preserved and variant.expected_verdict is Verdict.UNKNOWN
    benign = skeleton("b3", benign_session(), Verdict.BENIGN)
    (kept,) = generate_counterfactual_replay(benign, seed=4, kinds=[VariantKind.DROP_TELEMETRY])
    assert kept.semantics_preserved and kept.expected_verdict is Verdict.BENIGN


def test_time_bucket_ceiling_matches_the_encoder() -> None:
    assert MAX_TIME_BUCKET == ssir_encoder._MAX_TIME_BUCKET
    sk = skeleton("t", exfil_session(), Verdict.MALICIOUS)
    (variant,) = generate_counterfactual_replay(sk, seed=5, kinds=[VariantKind.ALTER_TIMING])
    for s in variant.steps:
        assert s.features[_TEMPORAL] == round(s.time_bucket / MAX_TIME_BUCKET, 6)
        assert s.features[_TEMPORAL + 2] == (1.0 if s.time_bucket <= 1 else 0.0)


# --- D6.18 quantised export ------------------------------------------------------------------


def _quant_state(threshold: float = 0.5) -> TrustedKnowledgeState:
    return learned_state(
        detector(weight=0.9), baseline(step(Relation.READ, actor_class=1)),
        baseline(step(Relation.WRITE, props=property_mask([SemanticProperty.TEMP_LOCATION])),
                 capsule="c3"),
        threshold=threshold,
    )


def test_quantize_round_trip_is_within_half_a_step() -> None:
    state = _quant_state()
    for bits in qc.QUANT_BITS:
        quantized = qc.quantize_state(state, bits=bits)
        restored = qc.dequantize_state(quantized, template=state)
        before = [v for i in qc._float_items(state) for v in qc._floats_of(i)]
        after_map = qc._dequantized_items(quantized, state)
        after = [v for i in qc._float_items(state) for v in qc._floats_of(after_map[i.item_id])]
        assert len(before) == len(after) == quantized.float_count
        pairs = zip(before, after, strict=True)
        assert all(abs(a - b) <= quantized.scale / 2 + 1e-6 for a, b in pairs)
        assert restored.version == state.version and len(restored.items) == len(state.items)
    int4 = qc.quantize_state(state, bits=4)
    assert len(int4.payload) == (int4.float_count + 1) // 2  # two codes per byte
    with pytest.raises(ContractError):
        qc.quantize_state(state, bits=16)
    with pytest.raises(ContractError, match="template"):
        qc.dequantize_state(qc.quantize_state(state, bits=8), template=learned_state())


def _replay() -> list[EpisodeSkeleton]:
    return [
        skeleton("q-m", exfil_session(), Verdict.MALICIOUS),
        skeleton("q-u", [step(Relation.CONNECT, actor=0)], Verdict.MALICIOUS),  # caught by U alone
        skeleton("q-b", [step(Relation.READ, actor_class=1)], Verdict.BENIGN),
        skeleton("q-b2", benign_session(), Verdict.BENIGN),
    ]


def test_int8_at_the_default_threshold_is_not_lossless_and_is_rejected() -> None:
    """MEASURED refutation of the spec's advance claim that INT8 is lossless here.

    One symmetric scale over anchors, weights and threshold (peak 1.0) cannot represent
    0.5: it becomes 64/127 = 0.50394, just above UNEXPLAINED_WEIGHT = 0.5, so every alert
    carried by the unexplained term alone is lost. The bound catches it.
    """
    state = _quant_state()
    assert state.threshold() == 0.5
    for bits in qc.QUANT_BITS:
        result = qc.evaluate_quantized(state, bits=bits, replay=_replay(), context_id=CTX)
        assert not result.accepted and "recall drop" in result.reason, bits
        assert result.recall_fp == 1.0 and result.recall_q == 0.5


def test_int8_off_the_half_step_is_lossless_and_accepted() -> None:
    state = _quant_state(threshold=0.4)
    int8 = qc.evaluate_quantized(state, bits=8, replay=_replay(), context_id=CTX)
    assert int8.accepted, int8.reason
    assert int8.recall_q == int8.recall_fp == 1.0 and int8.fp_rate_q == int8.fp_rate_fp
    assert int8.consistency_agreement == 1.0
    assert int8.quantized_bytes < int8.fp_bytes


def test_an_unmeasurable_variant_is_never_accepted() -> None:
    state = _quant_state()
    only_positives = [sk for sk in _replay() if sk.verdict is Verdict.MALICIOUS]
    result = qc.evaluate_quantized(state, bits=8, replay=only_positives, context_id=CTX)
    assert not result.accepted and result.reason.startswith("UNMEASURED")
    assert result.fp_rate_fp is None
    no_baselines = learned_state(detector())
    result = qc.evaluate_quantized(no_baselines, bits=8, replay=_replay(), context_id=CTX)
    assert result.consistency_agreement is None and not result.accepted


def test_fp_rate_bound_agrees_with_the_conservation_gate() -> None:
    try:
        from pocketsec.stage6.conservation.gate import EPS_FP_RATE as GATE_EPS_FP_RATE
    except ImportError:
        GATE_EPS_FP_RATE = 0.01  # §4.21's value, until the promotion package lands
    assert qc.EPS_FP_RATE == GATE_EPS_FP_RATE


# --- HEL-F26 learning record -----------------------------------------------------------------


def _exportable() -> tuple[TrustedKnowledgeState, KnowledgeLineageDAG, FossilStore]:
    dag = KnowledgeLineageDAG()
    record_chain(dag, "c1", "cand-a")
    record_chain(dag, "c2", "cand-b", seq=2)
    state = learned_state(detector(candidate="cand-a", capsule="c1"),
                          baseline(step(Relation.READ, actor_class=1), candidate="cand-b",
                                   capsule="c2"))
    store = FossilStore()
    fossilise(store, state, 3, pin=True)
    return state, dag, store


def export(state, dag, store, rows=(), simulated=True) -> lr.LearningRecordV1:
    return lr.export_learning_record(state, lineage=dag, fossils=store, rollback_rows=list(rows),
                                     simulated=simulated)


ROLLBACK = {"rollback_id": "rb-1", "trigger": "CANARY_REGRESSION", "candidate_id": "cand-x",
            "from_digest": _digest("a"), "to_digest": _digest("b"),
            "restored_bytes_identical": True,
            "skipped_fossils": [], "evidence": [cap_id("leak")], "sequence": 9}


def test_learning_record_passes_stage5_screens_and_carries_no_capsule_ids() -> None:
    state, dag, store = _exportable()
    record = export(state, dag, store, [ROLLBACK])
    payload = record.to_dict()
    assert seam_violations(payload) == () and authority_violations(payload) == ()
    text = json.dumps(payload)
    for item in state.items:
        for capsule_id in item.lineage.capsule_ids:
            assert capsule_id not in text
        for digest in item.lineage.evidence_digests:
            assert digest not in text
    assert "grp-" not in text and cap_id("leak") not in text
    assert payload["privacy_class"] == lr.PUBLIC_DERIVED and payload["lineage_intact"] is True
    assert payload["trusted_digest"] == state.digest() and payload["simulated"] is True
    assert payload["fossil_hashes"] == [state.digest()]
    assert set(payload["rollback_rows"][0]) == set(lr.ROLLBACK_ROW_KEYS)
    assert {row["evidence_count"] for row in payload["items"] if row["kind"] != "THRESHOLD"} == {1}
    assert all("anchor" not in row for row in payload["items"])
    assert record.digest() == export(state, dag, store, [ROLLBACK]).digest()


def test_learning_record_refuses_unlineaged_items_and_malformed_rows() -> None:
    state, dag, store = _exportable()
    ghost = detector(motif=(EXFIL_MOTIF[0],), candidate="cand-ghost", capsule="c9")
    orphan = state.with_changes(add=[ghost])
    with pytest.raises(ContractError, match="lineage"):
        export(orphan, dag, store)
    with pytest.raises(ContractError, match="lacks"):
        export(state, dag, store, [{"trigger": "X"}])
    with pytest.raises(ContractError):
        export(state, dag, store, simulated=None)
    edge = dag.edge("cand-a", "prom-cand-a")
    dag._edges[("cand-a", "prom-cand-a")] = dataclasses.replace(edge, reason="x")
    record = export(state, dag, store, simulated=False)
    assert record.lineage_intact is False and record.simulated is False


def test_learning_record_to_dict_refuses_authority_seam_and_host_ids() -> None:
    state, dag, store = _exportable()
    good = export(state, dag, store)
    for bad_row in ({"action_taken": 1}, {"sentinel_verdict": "x"}, {"note": cap_id("c1")},
                    {"group": "grp-" + _hex("g", 16)}):
        forged = dataclasses.replace(good, items=good.items + (bad_row,))
        with pytest.raises(ContractError):
            forged.to_dict()
    with pytest.raises(ContractError, match="PUBLIC_DERIVED"):
        dataclasses.replace(good, privacy_class="HOST_SENSITIVE")
    with pytest.raises(ContractError, match="simulated"):
        dataclasses.replace(good, simulated=1)


# --- review F3 / S6-AUTH-08: a learned threshold is not a genesis item -----------------------


def test_a_changed_threshold_claiming_genesis_fails_lineage_once_genesis_is_bound() -> None:
    """F3: the THRESHOLD keeps its id when re-weighted, and lineage_complete used to accept
    any THRESHOLD claiming genesis — so a threshold raised to blind every detector loaded
    as trusted with no evidence and no promotion named. The genesis weight is now bound."""
    genesis = genesis_state(identity=IDENTITY)
    raised = genesis.with_changes(threshold=0.99)
    item = next(i for i in raised.items if i.kind is ItemKind.THRESHOLD)
    dag = KnowledgeLineageDAG()
    assert dag.lineage_complete(item)  # unbound: the old, permissive behaviour
    dag.bind_genesis_threshold(genesis.threshold())
    assert not dag.lineage_complete(item)
    with pytest.raises(LineageError):
        TrustedKnowledgeState.from_canonical_bytes(raised.canonical_bytes(), lineage=dag)
    assert TrustedKnowledgeState.from_canonical_bytes(genesis.canonical_bytes(), lineage=dag)
    with pytest.raises(LineageError):  # a learned threshold cannot name genesis either
        genesis.with_changes(threshold=0.7, threshold_lineage=ItemLineage("genesis", (), (), ()))


# --- review S6-AUTH-06 / F5: "admitted" means the gateway did not refuse it -----------------


def test_an_item_citing_a_discarded_or_hostile_capsule_is_not_lineage_complete() -> None:
    """S6-AUTH-06: any VERDICT child used to count as admission, including the DISCARD and
    HOSTILE_SUSPECT verdicts the gateway writes for capsules it refused."""
    for bucket, admitted in (("DISCARD", False), ("HOSTILE_SUSPECT", False),
                             ("UNCERTAIN", True)):
        dag = KnowledgeLineageDAG()
        dag.update_lineage_dag(node=node("genesis-node", NodeKind.GENESIS, seq=0), parents=(),
                               reason="genesis")
        cid = cap_id(f"refused-{bucket}")
        dag.update_lineage_dag(node=node(cid, NodeKind.CAPSULE), parents=("genesis-node",),
                               reason="capsule_offered")
        dag.update_lineage_dag(node=node(f"ver-{bucket}", NodeKind.VERDICT), parents=(cid,),
                               reason="quarantine_verdict", gate_result=f"FAIL:{bucket}")
        dag.update_lineage_dag(node=node("cand-x", NodeKind.CANDIDATE), parents=(f"ver-{bucket}",),
                               reason="spawned")
        dag.update_lineage_dag(node=node("prom-x", NodeKind.PROMOTION), parents=("cand-x",),
                               reason="promoted")
        item = detector(candidate="cand-x", capsule=f"refused-{bucket}")
        assert dag.capsule_admitted(cid) is admitted, bucket
        assert dag.lineage_complete(item) is admitted, bucket


def test_a_folded_non_capsule_id_is_not_an_admitted_capsule() -> None:
    """F5 (medium): after a fold any folded id counted as an admitted capsule — a CANDIDATE
    or REJECTION id cited as a capsule passed lineage_complete."""
    dag = KnowledgeLineageDAG()
    record_chain(dag, "kept", "cand-live")
    record_chain(dag, "gone", "cand-dead", seq=2)
    live = detector(candidate="cand-live", capsule="kept")
    assert dag.collect(live_items=(live,), pinned_fossils=()) > 0
    assert "cand-dead" in dag.tombstone_ids()
    assert dag.capsule_admitted(cap_id("gone"))  # a folded, admitted capsule still counts
    assert not dag.capsule_admitted("cand-dead")  # a folded CANDIDATE never did
