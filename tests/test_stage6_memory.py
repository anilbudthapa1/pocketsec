"""Behaviour and failure-path tests for the Stage 6 `memory` package (D6.4, D6.5).

Every test here is about something the trusted-state model must **refuse**,
**bound** or **keep identical**, because Stage 6 is where learning is allowed to
change trusted state and a quietly weakened invariant here is a poisoning path:

* rollback identity — ``from_canonical_bytes(x.canonical_bytes())`` is byte-identical;
* lineage — an item without evidence is refused at load time, and "genesis" is not a
  bypass for a detector;
* bounds — a cap raises ``CapacityError`` instead of dropping, and a long simulated
  horizon of episodic admissions plateaus;
* the score — a same-actor conjunction, ``U`` capped at 0.5, escalating steps never
  "unexplained", and baselines of another context dormant by construction;
* Rule A — baseline keys are Stage 2's ``pattern_key`` and context keys come from one
  function, with the producing capsule module on the other side of the join.
"""

from __future__ import annotations

import dataclasses
import json
import random
from types import SimpleNamespace

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.epoch.model import Epoch, SystemIdentity
from pocketsec.stage1.ssir.entities import SemanticProperty as P
from pocketsec.stage1.ssir.relations import Relation
from pocketsec.stage2.adaptation import quarantine as stage2_quarantine
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_WIDTH, GROUP_OFFSETS
from pocketsec.stage6.capsule.experience_capsule import EncodedStep, LabelOrigin
from pocketsec.stage6.constitution.learning import property_mask, raised_mask, touches_protected
from pocketsec.stage6.memory import semantic
from pocketsec.stage6.memory.episodic import (
    MAX_EVICTION_LOG,
    MAX_SKELETON_STEPS,
    EpisodeSkeleton,
    EpisodeTier,
    EpisodeValue,
    EpisodicMemory,
    skeleton_from_capsule,
)
from pocketsec.stage6.memory.half_life import (
    HALF_LIFE_H0,
    HalfLifeInputs,
    below_retire_floor,
    half_life,
    lru_ranking,
    trust_ranking,
    update_epistemic_half_life,
)
from pocketsec.stage6.memory.procedural import (
    ProceduralMemory,
    ProcedureRecord,
    merge_procedure,
    procedure_key,
    procedure_observations,
)
from pocketsec.stage6.memory.semantic import (
    ALL_CONTEXTS,
    MAX_DETECTOR_ITEMS,
    UNEXPLAINED_WEIGHT,
    CapacityError,
    ItemKind,
    ItemLineage,
    ItemStatus,
    ItemValidation,
    KnowledgeItem,
    LineageError,
    MotifStep,
    SemanticMemory,
    TrustedKnowledgeState,
    context_id_for,
    genesis_state,
    match_motif,
    motif_pattern_key,
    score_session,
)
from pocketsec.stage6.resources import WorkBudgetExceeded, WorkMeter

DIGEST = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
IDENTITY = SystemIdentity(kernel_id="6.1.0-test")
OTHER_IDENTITY = SystemIdentity(kernel_id="6.2.0-test")
CTX = context_id_for(IDENTITY)
OTHER_CTX = context_id_for(OTHER_IDENTITY)
CRED = property_mask([P.CREDENTIAL])
EXT = property_mask([P.EXTERNAL_ENDPOINT])


# --- fixtures ----------------------------------------------------------------


def _step(
    relation: Relation,
    props: tuple[P, ...] = (),
    raised: tuple[str, ...] = (),
    *,
    actor: int = 0,
    epoch: int = 0,
    incomplete: bool = False,
) -> EncodedStep:
    """An EncodedStep whose features agree with its masks, as the encoder's would."""
    pmask, rmask = property_mask(props), raised_mask(raised)
    features = [0.0] * FEATURE_WIDTH
    features[GROUP_OFFSETS["relation_onehot"] + int(relation)] = 1.0
    for bit in range(16):
        if pmask >> bit & 1:
            features[GROUP_OFFSETS["object_semantics"] + bit] = 1.0
        if rmask >> bit & 1:
            features[GROUP_OFFSETS["state_delta_raised"] + bit] = 1.0
    if incomplete:
        features[GROUP_OFFSETS["uncertainty"] + 1] = 1.0
    return EncodedStep(
        features=tuple(features),
        relation=int(relation),
        relation_family=0,
        state_delta_mask=rmask,
        time_bucket=0,
        delta_phi=0.0,
        object_property_mask=pmask,
        epoch_id=epoch,
        actor_slot=actor,
        uncertainty=0.0,
        source_group=f"grp-{actor:016x}",
        causal_signature="",
        parent_signature="",
        evidence=(DIGEST,),
    )


def _lineage(candidate: str = "cand-1") -> ItemLineage:
    return ItemLineage(candidate, ("cap-0001",), (DIGEST,), ())


def _detector(
    motif: tuple[MotifStep, ...], *, weight: float = 0.9, contexts=(ALL_CONTEXTS,)
) -> KnowledgeItem:
    return KnowledgeItem.build(
        kind=ItemKind.DETECTOR,
        context_ids=contexts,
        motif=motif,
        pattern_key=motif_pattern_key(motif),
        weight=weight,
        origin_verdict=Verdict.MALICIOUS,
        lineage=_lineage(),
        validation=ItemValidation.fresh(sequence=1, epoch_id=0),
    )


def _baseline(
    step: EncodedStep, *, contexts=(CTX,), status=ItemStatus.ACTIVE, radius: float = 1.0
) -> KnowledgeItem:
    return KnowledgeItem.build(
        kind=ItemKind.BASELINE,
        context_ids=contexts,
        anchor=step.meaning(),
        pattern_key=stage2_quarantine.pattern_key(step.to_encoded()),
        weight=radius,
        origin_verdict=Verdict.BENIGN,
        lineage=_lineage("cand-b"),
        status=status,
        validation=ItemValidation.fresh(sequence=1, epoch_id=0),
    )


def _procedure_item(record: ProcedureRecord) -> KnowledgeItem:
    return KnowledgeItem.build(
        kind=ItemKind.PROCEDURE,
        context_ids=(record.context_id,),
        pattern_key=procedure_key(record.operator_id, record.context_id),
        weight=1.0,
        origin_verdict=Verdict.BENIGN,
        lineage=_lineage("cand-p"),
        procedure=record,
        validation=ItemValidation.fresh(sequence=1),
    )


EXFIL = (
    MotifStep(int(Relation.READ), CRED, 0, 0),
    MotifStep(int(Relation.SEND), EXT, 0, 0),
)


def _skeleton(
    episode_id: str, steps: tuple[EncodedStep, ...], *, verdict=Verdict.MALICIOUS
) -> EpisodeSkeleton:
    return EpisodeSkeleton(
        episode_id=episode_id,
        steps=steps,
        verdict=verdict,
        label_origin=LabelOrigin.GROUND_TRUTH,
        epoch_id=0,
        context_id=CTX,
        visibility_mask=(1 << len(steps)) - 1,
        anchors_touched=tuple(
            sorted(
                {
                    a
                    for s in steps
                    for a in touches_protected(s.object_property_mask, s.state_delta_mask)
                }
            )
        ),
        truncated=False,
    )


def _value(v: float) -> EpisodeValue:
    return EpisodeValue(1.0, 1.0, 1.0, 1.0, 1.0, 0.1, 0.0, 0.0, v)


def _rich_state() -> TrustedKnowledgeState:
    record = ProcedureRecord("op-observe", 0, CTX, 3, 1, 0, 0, True, (DIGEST,))
    benign = _step(Relation.READ, (P.SYSTEM_BINARY,))
    return genesis_state(identity=IDENTITY, threshold=0.123456789).with_changes(
        add=[
            _detector(EXFIL, weight=0.912345678),
            _baseline(benign, radius=0.3333333333),
            _procedure_item(record),
        ],
        rehearsal=[
            _skeleton(
                "cap-0001",
                (
                    _step(Relation.READ, (P.CREDENTIAL,)),
                    _step(Relation.SEND, (P.EXTERNAL_ENDPOINT,)),
                ),
            )
        ],
    )


# --- canonical bytes and rollback identity ----------------------------------


def test_canonical_bytes_round_trip_is_byte_identical() -> None:
    state = _rich_state()
    data = state.canonical_bytes()
    loaded = TrustedKnowledgeState.from_canonical_bytes(data)
    assert loaded.canonical_bytes() == data
    assert loaded.digest() == state.digest()
    assert loaded == state  # floats were canonicalised at construction, not only on disk
    # A second generation is stable too: rollback of a rollback restores the same bytes.
    assert (
        TrustedKnowledgeState.from_canonical_bytes(loaded.canonical_bytes()).canonical_bytes()
        == data
    )


def test_non_canonical_or_tampered_bytes_are_refused() -> None:
    data = _rich_state().canonical_bytes()
    pretty = (json.dumps(json.loads(data), indent=1, sort_keys=True) + "\n").encode()
    with pytest.raises(ContractError, match="not canonical"):
        TrustedKnowledgeState.from_canonical_bytes(pretty)
    payload = json.loads(data)
    by_kind = {raw["kind"]: raw for raw in payload["items"]}
    by_kind["THRESHOLD"]["weight"] = 0.01  # forged without changing the item's id
    forged = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    # Weight is not part of identity, so this loads as a DIFFERENT state with a different digest.
    assert TrustedKnowledgeState.from_canonical_bytes(forged).digest() != _rich_state().digest()
    # Same id, different (valid) content: a WRITE baseline wearing a READ baseline's id.
    by_kind["BASELINE"]["pattern_key"] = stage2_quarantine.pattern_key(
        _step(Relation.WRITE).to_encoded()
    )
    with pytest.raises(ContractError, match="content-addressed"):
        TrustedKnowledgeState.from_canonical_bytes(
            (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )
    with pytest.raises(ContractError):
        TrustedKnowledgeState.from_canonical_bytes(b"\xff\xfe not json")


def test_with_changes_chains_parent_digest_and_never_mutates() -> None:
    base = genesis_state(identity=IDENTITY)
    before = base.canonical_bytes()
    child = base.with_changes(add=[_detector(EXFIL)])
    assert child.version == base.version + 1
    assert child.parent_digest == base.digest()
    assert base.canonical_bytes() == before
    assert child.with_changes(threshold=0.7).threshold() == 0.7
    with pytest.raises(ContractError, match="unknown item"):
        child.with_changes(remove=["k-does-not-exist"])
    with pytest.raises(ContractError, match="already present"):
        child.with_changes(add=[_detector(EXFIL)])


# --- lineage ------------------------------------------------------------------


def test_lineage_less_item_is_refused_at_load_time() -> None:
    orphan = dataclasses.replace(_detector(EXFIL), lineage=ItemLineage("cand-x", (), (), ()))
    base = genesis_state(identity=IDENTITY)
    # Constructing the value is allowed (the gate's load probe builds exactly this) ...
    state = TrustedKnowledgeState(1, base.digest(), CTX, (*base.items, orphan), ())
    # ... but it can never be loaded as trusted state, and never added through with_changes.
    with pytest.raises(LineageError):
        TrustedKnowledgeState.from_canonical_bytes(state.canonical_bytes())
    with pytest.raises(LineageError):
        base.with_changes(add=[orphan])
    no_evidence = dataclasses.replace(orphan, lineage=ItemLineage("cand-x", ("cap-1",), (), ()))
    with pytest.raises(LineageError):
        base.with_changes(add=[no_evidence])


def test_genesis_is_not_a_lineage_bypass_for_learned_items() -> None:
    fake = dataclasses.replace(_detector(EXFIL), lineage=ItemLineage("genesis", (), (), ()))
    base = genesis_state(identity=IDENTITY)
    state = TrustedKnowledgeState(1, base.digest(), CTX, (*base.items, fake), ())
    with pytest.raises(LineageError, match="genesis"):
        TrustedKnowledgeState.from_canonical_bytes(state.canonical_bytes())
    # The genesis threshold itself does load.
    assert TrustedKnowledgeState.from_canonical_bytes(base.canonical_bytes()) == base


def test_lineage_checker_is_consulted_for_every_item() -> None:
    state = _rich_state()
    seen: list[str] = []

    class Checker:
        def __init__(self, verdict: bool) -> None:
            self.verdict = verdict

        def lineage_complete(self, item: KnowledgeItem) -> bool:
            seen.append(item.item_id)
            return self.verdict or item.kind is ItemKind.THRESHOLD

    assert (
        TrustedKnowledgeState.from_canonical_bytes(state.canonical_bytes(), lineage=Checker(True))
        == state
    )
    assert sorted(seen) == sorted(item.item_id for item in state.items)
    with pytest.raises(LineageError, match="complete lineage"):
        TrustedKnowledgeState.from_canonical_bytes(state.canonical_bytes(), lineage=Checker(False))


# --- identity and protection ---------------------------------------------------


def test_item_ids_are_content_addressed_and_protection_cannot_be_dropped() -> None:
    detector = _detector(EXFIL)
    assert detector.item_id.startswith("k-") and detector.protected
    with pytest.raises(ContractError, match="content-addressed"):
        dataclasses.replace(detector, item_id="k-" + "0" * 32)
    with pytest.raises(ContractError, match="protected"):
        dataclasses.replace(detector, protected=False)
    # Re-weighting or making dormant is the same item; changing the motif is not.
    assert (
        dataclasses.replace(detector, weight=0.5, status=ItemStatus.DORMANT).item_id
        == detector.item_id
    )
    assert _detector(EXFIL[:1]).item_id != detector.item_id


def test_origin_verdict_is_a_verdict_never_a_family_name() -> None:
    with pytest.raises(ContractError, match="Verdict"):
        dataclasses.replace(_detector(EXFIL), origin_verdict="credential_theft")
    with pytest.raises(ContractError):
        dataclasses.replace(_detector(EXFIL), origin_verdict=Verdict.BENIGN)


def test_raw_telemetry_is_not_trusted_state() -> None:
    base = genesis_state(identity=IDENTITY)
    raw = _step(Relation.READ, (P.CREDENTIAL,)).to_encoded()
    with pytest.raises(ContractError, match="only KnowledgeItem"):
        base.with_changes(add=[raw])  # type: ignore[list-item]
    with pytest.raises(ContractError, match="EpisodeSkeleton"):
        base.with_changes(rehearsal=[_step(Relation.READ)])  # type: ignore[list-item]
    with pytest.raises(ContractError, match="KnowledgeItem"):
        TrustedKnowledgeState(1, None, CTX, (*base.items, raw), ())  # type: ignore[arg-type]
    digest = base.digest()
    score_session(base, [_step(Relation.READ)], context_id=CTX)
    assert base.digest() == digest  # scoring reads; it never writes


# --- bounds ---------------------------------------------------------------------


def test_capacity_error_instead_of_silent_drop() -> None:
    detectors = [
        _detector((MotifStep(int(Relation.READ), CRED | (1 << (4 + i % 8)), 0, i // 8),))
        for i in range(MAX_DETECTOR_ITEMS + 1)
    ]
    assert len({d.item_id for d in detectors}) == MAX_DETECTOR_ITEMS + 1
    base = genesis_state(identity=IDENTITY)
    full = base.with_changes(add=detectors[:MAX_DETECTOR_ITEMS])
    assert len(full.detectors()) == MAX_DETECTOR_ITEMS
    with pytest.raises(CapacityError):
        full.with_changes(add=detectors[MAX_DETECTOR_ITEMS:])
    assert len(full.detectors()) == MAX_DETECTOR_ITEMS  # nothing dropped, nothing added


def test_state_byte_cap_and_rehearsal_cap_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    base = genesis_state(identity=IDENTITY)
    monkeypatch.setattr(semantic, "MAX_TRUSTED_STATE_BYTES", base.byte_size() + 10)
    with pytest.raises(CapacityError, match="bytes"):
        base.with_changes(add=[_detector(EXFIL)])
    monkeypatch.undo()
    monkeypatch.setattr(semantic, "MAX_REHEARSAL_EXEMPLARS", 1)
    two = [_skeleton(f"cap-{i}", (_step(Relation.READ),)) for i in range(2)]
    with pytest.raises(CapacityError, match="rehearsal"):
        base.with_changes(rehearsal=two)


# --- the score -----------------------------------------------------------------


def test_motif_is_a_same_actor_ordered_conjunction() -> None:
    read = _step(Relation.READ, (P.CREDENTIAL,), actor=0)
    send_same = _step(Relation.SEND, (P.EXTERNAL_ENDPOINT,), actor=0)
    send_other = _step(Relation.SEND, (P.EXTERNAL_ENDPOINT,), actor=1)
    assert match_motif(EXFIL, [read, send_same])
    assert not match_motif(EXFIL, [read, send_other])  # spread across two actors
    assert not match_motif(EXFIL, [send_same, read])  # wrong order
    both = MotifStep(int(Relation.READ), CRED, 0, 0)
    assert not match_motif((both, both), [read])  # one step cannot be i and j
    assert match_motif((both, both), [read, read])
    with pytest.raises(ContractError):
        match_motif((), [read])
    state = genesis_state(identity=IDENTITY).with_changes(add=[_detector(EXFIL)])
    assert score_session(state, [read, send_other], context_id=CTX).detector_hits == ()
    hit = score_session(state, [read, send_same], context_id=CTX)
    assert hit.score == pytest.approx(0.9) and len(hit.detector_hits) == 1


def test_unexplained_is_capped_and_escalating_steps_never_count() -> None:
    state = genesis_state(identity=IDENTITY)
    novel = [_step(Relation.WRITE, (P.TEMP_LOCATION,), actor=a) for a in range(3)]
    result = score_session(state, novel, context_id=CTX)
    assert result.unexplained == UNEXPLAINED_WEIGHT == result.score == 0.5
    escalating = [
        _step(Relation.READ, (P.CREDENTIAL,)),  # touches a protected anchor
        _step(Relation.EXECUTE, (), ("discovery",)),  # raises a non-protected dimension
    ]
    assert score_session(state, escalating, context_id=CTX).unexplained == 0.0
    # One actor half explained: its share is 0.5, so U = 0.25; the max over actors wins.
    known = _step(Relation.READ, (P.SYSTEM_BINARY,), actor=0)
    with_base = state.with_changes(add=[_baseline(known)])
    mixed = [known, _step(Relation.WRITE, (P.TEMP_LOCATION,), actor=0)]
    assert score_session(with_base, mixed, context_id=CTX).unexplained == pytest.approx(0.25)
    assert score_session(with_base, [known], context_id=CTX).score == 0.0
    assert score_session(state, [], context_id=CTX).score == 0.0


def test_dormant_context_baselines_do_not_apply() -> None:
    known = _step(Relation.READ, (P.SYSTEM_BINARY,))
    state = genesis_state(identity=IDENTITY).with_changes(add=[_baseline(known, contexts=(CTX,))])
    assert score_session(state, [known], context_id=CTX).unexplained == 0.0
    assert score_session(state, [known], context_id=OTHER_CTX).unexplained == 0.5
    assert SemanticMemory(state).baselines(OTHER_CTX) == ()
    dormant = genesis_state(identity=IDENTITY).with_changes(
        add=[_baseline(known, contexts=(ALL_CONTEXTS,), status=ItemStatus.DORMANT)]
    )
    assert score_session(dormant, [known], context_id=CTX).unexplained == 0.5
    everywhere = genesis_state(identity=IDENTITY).with_changes(
        add=[_baseline(known, contexts=(ALL_CONTEXTS,))]
    )
    assert score_session(everywhere, [known], context_id=OTHER_CTX).unexplained == 0.0


def test_score_charges_one_unit_per_item_step_comparison() -> None:
    known = _step(Relation.READ, (P.SYSTEM_BINARY,))
    state = genesis_state(identity=IDENTITY).with_changes(add=[_detector(EXFIL), _baseline(known)])
    steps = [known, known, _step(Relation.READ, (P.CREDENTIAL,))]  # 2 non-escalating
    meter = WorkMeter()
    result = score_session(state, steps, context_id=CTX, meter=meter)
    assert result.work_units == meter.spent == 1 * 3 + 1 * 2
    with pytest.raises(WorkBudgetExceeded):
        score_session(state, steps, context_id=CTX, meter=WorkMeter(budget=2))


# --- Rule A --------------------------------------------------------------------


def test_baseline_key_is_stage2_pattern_key() -> None:
    assert semantic.pattern_key is stage2_quarantine.pattern_key
    step = _step(Relation.READ, (P.SYSTEM_BINARY,))
    item = _baseline(step)
    assert item.pattern_key == stage2_quarantine.pattern_key(step.to_encoded())
    assert SemanticMemory(genesis_state(identity=IDENTITY).with_changes(add=[item])).lookup(
        item.pattern_key
    ) == (item,)
    produced = {stage2_quarantine.pattern_key(_step(r).to_encoded()) for r in Relation}
    assert produced == semantic.STAGE2_BASELINE_KEYS
    # A baseline keyed in any other key space would explain nothing, so it cannot exist.
    with pytest.raises(ContractError, match="not a Stage 2 pattern_key"):
        KnowledgeItem.build(
            kind=ItemKind.BASELINE,
            context_ids=(CTX,),
            anchor=step.meaning(),
            pattern_key=f"rel-{step.relation}",
            weight=1.0,
            origin_verdict=Verdict.BENIGN,
            lineage=_lineage(),
            validation=ItemValidation.fresh(sequence=1),
        )
    # And a baseline for another relation never explains this step, even at distance zero.
    elsewhere = dataclasses.replace(step, relation=int(Relation.WRITE))
    state = genesis_state(identity=IDENTITY).with_changes(add=[_baseline(elsewhere)])
    assert score_session(state, [step], context_id=CTX).unexplained == 0.5


def test_context_key_is_one_function() -> None:
    assert context_id_for(IDENTITY) == "ctx-" + IDENTITY.key()
    assert genesis_state(identity=IDENTITY).active_context == CTX
    epoch = Epoch(epoch_id=3, identity=IDENTITY, key=IDENTITY.key(), opened_at_ns=0)
    from pocketsec.stage6.capsule import experience_capsule as capsule_mod

    provenance = capsule_mod.SourceProvenance(
        capsule_mod.SourceClass.ANALYST,
        "analyst-1",
        "analyst:1",
        LabelOrigin.ANALYST,
        ("analyst",),
        "host-1",
    )
    label = capsule_mod.LabelAssertion(
        Verdict.MALICIOUS, LabelOrigin.ANALYST, "analyst:1", "cap-" + "0" * 24
    )
    capsule = capsule_mod.capsule_from_label(label, epoch=epoch, provenance=provenance, sequence=1)
    assert capsule.context_id == context_id_for(IDENTITY)
    with pytest.raises(ContractError):
        context_id_for(IDENTITY.key())  # type: ignore[arg-type]
    with pytest.raises(ContractError, match="context_id_for"):
        _baseline(_step(Relation.READ), contexts=(IDENTITY.key(),))


# --- episodic memory -------------------------------------------------------------


def test_value_aware_eviction_refuses_a_lower_value_newcomer_and_records_evictions() -> None:
    memory = EpisodicMemory(capacity=2)
    steps = (_step(Relation.READ),)
    assert memory.admit_episode(
        _skeleton("cap-a", steps), value=_value(1.0), verdict_id="v-a"
    ).admitted
    assert memory.admit_episode(
        _skeleton("cap-b", steps), value=_value(2.0), verdict_id="v-b"
    ).admitted
    low = memory.admit_episode(_skeleton("cap-c", steps), value=_value(0.5), verdict_id="v-c")
    tie = memory.admit_episode(_skeleton("cap-d", steps), value=_value(1.0), verdict_id="v-d")
    assert not low.admitted and not tie.admitted and low.reason == "lower_value_than_resident"
    assert [s.episode_id for s in memory.episodes()] == ["cap-a", "cap-b"]
    assert memory.evictions() == 0
    high = memory.admit_episode(_skeleton("cap-e", steps), value=_value(3.0), verdict_id="v-e")
    assert high.admitted and high.evicted == ("cap-a",)  # the MIN-value victim, not the oldest
    assert memory.verdict_of("cap-a") is None and memory.verdict_of("cap-e") == "v-e"
    record = memory.eviction_log()[-1]
    assert (record.episode_id, record.verdict_id, record.replaced_by) == ("cap-a", "v-a", "cap-e")
    stats = memory.stats()
    assert (stats.admitted, stats.refused, stats.evictions) == (3, 2, 1)


def test_eviction_log_is_bounded_and_counters_never_reset() -> None:
    memory = EpisodicMemory(capacity=1)
    steps = (_step(Relation.READ),)
    total = MAX_EVICTION_LOG + 40
    for i in range(total + 1):
        memory.admit_episode(
            _skeleton(f"cap-{i}", steps), value=_value(float(i + 1)), verdict_id=f"v-{i}"
        )
    assert memory.evictions() == total
    assert len(memory.eviction_log()) == MAX_EVICTION_LOG
    assert memory.stats().eviction_log_dropped == total - MAX_EVICTION_LOG


def test_hostile_tier_is_evidence_never_learning_material() -> None:
    memory = EpisodicMemory(capacity=4, hostile_capacity=2)
    steps = (_step(Relation.READ),)
    for i in range(3):
        memory.admit_episode(
            _skeleton(f"cap-h{i}", steps),
            value=_value(9.0),
            verdict_id=f"v-{i}",
            tier=EpisodeTier.HOSTILE,
        )
    assert memory.episodes() == ()
    assert [s.episode_id for s in memory.episodes(tier=EpisodeTier.HOSTILE)] == ["cap-h1", "cap-h2"]
    assert (
        memory.stats().hostile_evictions == 1
        and memory.eviction_log()[-1].reason == "oldest_evidence"
    )
    dup = memory.admit_episode(_skeleton("cap-h2", steps), value=_value(9.0), verdict_id="v-x")
    assert not dup.admitted and dup.reason == "duplicate_episode"


def test_byte_budget_evicts_by_value_and_bounds_cannot_be_raised() -> None:
    steps = (_step(Relation.READ),)
    size = _skeleton("cap-0", steps).byte_size()
    memory = EpisodicMemory(capacity=100, byte_budget=size * 2 + 1)
    for i, v in enumerate((5.0, 1.0, 3.0)):
        memory.admit_episode(_skeleton(f"cap-{i}", steps), value=_value(v), verdict_id=f"v-{i}")
    assert {s.episode_id for s in memory.episodes()} == {"cap-0", "cap-2"}
    assert memory.learning_bytes() <= size * 2 + 1
    with pytest.raises(ContractError, match="cannot be raised"):
        EpisodicMemory(capacity=10_000)


def test_long_horizon_episodic_growth_plateaus() -> None:
    rng = random.Random(11)
    memory = EpisodicMemory(capacity=64, byte_budget=64 * 1024)
    checkpoints: list[int] = []
    for i in range(6000):
        steps = tuple(
            _step(Relation(rng.randrange(0, 12)), actor=rng.randrange(0, 3))
            for _ in range(rng.randrange(1, 6))
        )
        memory.admit_episode(
            _skeleton(f"cap-{i}", steps), value=_value(rng.random()), verdict_id=f"v-{i}"
        )
        if i % 500 == 499:
            checkpoints.append(memory.memory_bytes())
    stats = memory.stats()
    assert stats.learning_episodes <= 64 and stats.learning_bytes <= 64 * 1024
    assert stats.evictions > 0 and stats.refused > 0  # both policies actually fired
    late = checkpoints[len(checkpoints) // 2 :]
    assert max(late) <= 64 * 1024 + MAX_EVICTION_LOG * 200  # bounded by budget + bounded log
    assert max(late) - min(late) < 0.1 * max(late)  # plateau, not growth


def test_skeleton_keeps_escalating_and_first_steps_and_truncates_explicitly() -> None:
    steps = (
        _step(Relation.READ, (P.SYSTEM_BINARY,), actor=0),
        _step(Relation.READ, (P.SYSTEM_BINARY,), actor=0),  # same (actor, key): dropped
        _step(Relation.READ, (P.CREDENTIAL,), actor=0),  # escalating: kept
        _step(Relation.READ, (P.SYSTEM_BINARY,), actor=1, incomplete=True),  # new actor: kept
    )
    capsule = SimpleNamespace(
        capsule_id="cap-0007", steps=steps, epoch_id=2, context_id=CTX, truncated=False
    )
    skeleton = skeleton_from_capsule(
        capsule, verdict=Verdict.MALICIOUS, label_origin=LabelOrigin.ANALYST
    )  # type: ignore[arg-type]
    assert skeleton.steps == (steps[0], steps[2], steps[3]) and not skeleton.truncated
    assert skeleton.visibility_mask == 0b011  # the last kept step was not observed
    assert skeleton.anchors_touched == ("credential_material",)
    many = tuple(
        _step(Relation.EXECUTE, (), ("execution",), actor=i % 7)
        for i in range(MAX_SKELETON_STEPS + 8)
    )
    wide = SimpleNamespace(
        capsule_id="cap-0008", steps=many, epoch_id=0, context_id=CTX, truncated=False
    )
    cut = skeleton_from_capsule(wide, verdict=Verdict.MALICIOUS, label_origin=LabelOrigin.ANALYST)  # type: ignore[arg-type]
    assert cut.truncated and len(cut.steps) <= MAX_SKELETON_STEPS
    assert EpisodeSkeleton.from_payload(cut.to_payload()) == cut
    with pytest.raises(CapacityError):
        _skeleton("cap-9", many)


def test_episode_value_factors() -> None:
    from pocketsec.stage6.memory.episodic import episode_value

    trust = SimpleNamespace(provenance_score=0.9)
    exfil = (_step(Relation.READ, (P.CREDENTIAL,)), _step(Relation.SEND, (P.EXTERNAL_ENDPOINT,)))
    state = genesis_state(identity=IDENTITY).with_changes(add=[_detector(EXFIL)])
    fresh = episode_value(
        _skeleton("cap-1", exfil), trust=trust, suspicion_summary=0.0, resident=(), trusted=state
    )  # type: ignore[arg-type]
    assert (
        fresh.security_information == 1.0
        and fresh.novelty == 1.0
        and fresh.future_replay_value == 1.0
    )
    resident = (_skeleton("cap-2", exfil), _skeleton("cap-3", exfil))
    stale = episode_value(
        _skeleton("cap-1", exfil),
        trust=trust,
        suspicion_summary=0.0,
        resident=resident,
        trusted=state,
    )  # type: ignore[arg-type]
    assert (
        stale.redundancy == 1.0 and stale.future_replay_value == 0.5 and stale.value < fresh.value
    )
    risky = episode_value(
        _skeleton("cap-1", exfil), trust=trust, suspicion_summary=0.9, resident=(), trusted=state
    )  # type: ignore[arg-type]
    assert risky.value < fresh.value
    unlabelled = dataclasses.replace(_skeleton("cap-1", exfil), label_origin=LabelOrigin.NONE)
    assert (
        episode_value(
            unlabelled, trust=trust, suspicion_summary=0.0, resident=(), trusted=state
        ).value
        == 0.0
    )  # type: ignore[arg-type]


# --- procedural memory -------------------------------------------------------------


def _response_capsule(rows: list[dict], *, flags=frozenset()) -> SimpleNamespace:
    from pocketsec.stage6.capsule.experience_capsule import CapsuleKind

    return SimpleNamespace(
        kind=CapsuleKind.RESPONSE_OUTCOME,
        contamination_flags=flags,
        procedure_rows=tuple(rows),
        evidence_refs=(DIGEST,),
        context_id=CTX,
    )


def test_procedure_observations_count_only_verified_as_verified() -> None:
    rows = [
        {
            "operator_id": "op-a",
            "operator_class": 2,
            "outcome": "COMMITTED_VERIFIED",
            "simulated": False,
        },
        {
            "operator_id": "op-a",
            "operator_class": 2,
            "outcome": "COMMITTED_UNVERIFIED",
            "simulated": False,
        },
        {
            "operator_id": "op-a",
            "operator_class": 2,
            "outcome": "ROLLED_BACK",
            "rollback_attempted": True,
            "rollback_succeeded": True,
            "simulated": False,
        },
        {
            "operator_id": "op-a",
            "operator_class": 2,
            "outcome": "ROLLBACK_FAILED",
            "rollback_attempted": True,
            "rollback_succeeded": False,
            "simulated": False,
        },
        {
            "operator_id": "op-a",
            "operator_class": 2,
            "outcome": "REFUSED_SENTINEL",
            "simulated": False,
        },
        {
            "operator_id": "op-a",
            "operator_class": 2,
            "outcome": "SOMETHING_NEW",
            "simulated": False,
        },
        {
            "operator_id": "op-b",
            "operator_class": 0,
            "outcome": "COMMITTED_VERIFIED",
            "evidence_bundle_digest": DIGEST_B,
        },  # does not say whether simulated
    ]
    records = {r.operator_id: r for r in procedure_observations(_response_capsule(rows))}  # type: ignore[arg-type]
    a, b = records["op-a"], records["op-b"]
    assert (a.verified, a.unverified, a.rolled_back, a.failed) == (1, 2, 1, 1)  # refusal ignored
    assert not a.simulated and b.simulated  # a silent row is simulated
    assert b.evidence_digests == (DIGEST, DIGEST_B)
    flagged = _response_capsule(rows[:1], flags=frozenset({"SIMULATED_RECORD"}))
    from pocketsec.stage6.capsule.experience_capsule import ContaminationFlag

    flagged.contamination_flags = frozenset({ContaminationFlag.SIMULATED_RECORD})
    assert procedure_observations(flagged)[0].simulated  # type: ignore[arg-type]
    assert merge_procedure(a, dataclasses.replace(a, simulated=True)).simulated  # sticky
    not_response = SimpleNamespace(kind="TRANSITION_EPISODE")
    assert procedure_observations(not_response) == ()  # type: ignore[arg-type]


def test_procedural_memory_is_a_context_bound_lookup_that_counts() -> None:
    record = ProcedureRecord("op-observe", 0, CTX, 3, 0, 0, 0, True, (DIGEST,))
    state = genesis_state(identity=IDENTITY).with_changes(add=[_procedure_item(record)])
    memory = ProceduralMemory(state)
    assert memory.lookup("op-observe", context_id=CTX) == record
    assert memory.lookup("op-observe", context_id=OTHER_CTX) is None
    assert (memory.lookups, memory.hits) == (2, 1)
    # Procedural knowledge changes no detection outcome.
    steps = [_step(Relation.READ, (P.SYSTEM_BINARY,))]
    assert score_session(state, steps, context_id=CTX) == score_session(
        genesis_state(identity=IDENTITY), steps, context_id=CTX
    )
    with pytest.raises(ContractError):
        ProcedureRecord(
            "op", 0, CTX, 0, 0, 0, 0, True, tuple(f"sha256:{i:064x}" for i in range(17))
        )


# --- epistemic half-life -------------------------------------------------------------


def _aged(item: KnowledgeItem, **changes: int) -> KnowledgeItem:
    return dataclasses.replace(item, validation=dataclasses.replace(item.validation, **changes))


def test_half_life_grows_with_recurrence_and_shrinks_with_contradiction() -> None:
    base = _detector(EXFIL)
    plain = update_epistemic_half_life(base, now_sequence=1, epochs_since_match=0)
    recurring = update_epistemic_half_life(
        _aged(base, recurrence=9, validations=4), now_sequence=1, epochs_since_match=0
    )
    contradicted = update_epistemic_half_life(
        _aged(base, contradictions=5), now_sequence=1, epochs_since_match=0
    )
    assert plain.half_life == HALF_LIFE_H0
    assert recurring.half_life > plain.half_life > contradicted.half_life
    drifted = update_epistemic_half_life(base, now_sequence=1, epochs_since_match=3)
    assert drifted.half_life < plain.half_life
    baseline = update_epistemic_half_life(
        _baseline(_step(Relation.READ)), now_sequence=1, epochs_since_match=0
    )
    assert baseline.half_life < plain.half_life  # context-bound knowledge is drift-sensitive
    assert plain.trust == 1.0
    at_h = update_epistemic_half_life(
        base, now_sequence=1 + int(HALF_LIFE_H0), epochs_since_match=0
    )
    assert at_h.trust == pytest.approx(0.5)
    with pytest.raises(ContractError, match="negative age"):
        update_epistemic_half_life(base, now_sequence=0, epochs_since_match=0)
    with pytest.raises(ContractError):
        half_life(HalfLifeInputs(1.5, 0.0, 0.0, 0.0, 0.0))


def test_trust_ranking_can_disagree_with_the_lru_control() -> None:
    old_validated = _aged(
        _detector(EXFIL), validations=50, recurrence=50, last_matched_sequence=100
    )
    fresh_contradicted = _aged(
        _baseline(_step(Relation.READ)), contradictions=50, last_matched_sequence=2000
    )
    items = [old_validated, fresh_contradicted]
    ranking = trust_ranking(
        items, now_sequence=9000, epochs_since_match={fresh_contradicted.item_id: 4}
    )
    assert lru_ranking(items)[0] == old_validated.item_id
    assert ranking[0].item_id == fresh_contradicted.item_id  # half-life picks a different victim
    assert [r.trust for r in ranking] == sorted(r.trust for r in ranking)
    assert below_retire_floor(ranking) == (fresh_contradicted.item_id,)


def test_no_memory_dataclass_field_names_authority() -> None:
    """T5, local copy: this package's own tests fail if a field names authority."""
    from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS
    from pocketsec.stage6.memory import episodic, half_life, procedural

    offenders = [
        f"{module.__name__}.{obj.__name__}.{field.name}"
        for module in (semantic, episodic, procedural, half_life)
        for obj in vars(module).values()
        if isinstance(obj, type)
        and dataclasses.is_dataclass(obj)
        and obj.__module__ == module.__name__
        for field in dataclasses.fields(obj)
        if any(token in field.name.lower() for token in FORBIDDEN_AUTHORITY_FIELDS)
    ]
    assert offenders == []
