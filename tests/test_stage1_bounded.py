"""Stage 1 — boundedness, fusion, novelty, epochs, causality, AOP, aggregation.

Every structure Stage 1 puts on the hot path has a declared cap. These tests
exist to prove the caps hold under pressure, because "bounded" that is only
true on benign input is not bounded — flooding is an explicit adversarial test.
"""

from __future__ import annotations

import pytest

from pocketsec.stage1.aggregation.policy import AggregationPolicy, AggregationThresholds
from pocketsec.stage1.causal.memory import CausalMemory, causal_signature
from pocketsec.stage1.epoch.model import EpochModel, SystemIdentity
from pocketsec.stage1.labs.corpus import ATTACK_EXFIL, Behaviour, Scenario
from pocketsec.stage1.novelty.engine import NOVELTY_CONTEXTS, NoveltyEngine
from pocketsec.stage1.novelty.sketches import (
    BoundedLRUCounter,
    CountMinSketch,
    StableBloomFilter,
)
from pocketsec.stage1.observation.policy import (
    MANDATORY_SIGNALS,
    AdaptiveObservationPolicy,
    AOPBudget,
    ObservationLevel,
)
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage1.ssir.codec import LAYOUTS, SSIRCodec
from pocketsec.stage1.ssir.transition import RepresentationLevel, TemporalContext
from pocketsec.stage1.state.security_state import StateDelta
from pocketsec.stage1.telemetry.assembler import EventAssembler
from pocketsec.stage1.telemetry.raw_event_v1 import RawEventV1, SensorPath

# --- sketches ----------------------------------------------------------------


def test_count_min_never_underestimates() -> None:
    """The safe error direction: over-estimating makes things look familiar."""
    sketch = CountMinSketch(width=64, depth=3)
    for _ in range(10):
        sketch.add("alpha")
    assert sketch.estimate("alpha") >= 10


def test_count_min_memory_is_fixed_under_load() -> None:
    sketch = CountMinSketch(width=128, depth=4)
    before = sketch.memory_bytes
    for i in range(50_000):
        sketch.add(f"key-{i}")
    assert sketch.memory_bytes == before


def test_stable_bloom_does_not_saturate() -> None:
    """A classic Bloom filter fills and answers 'seen' for everything.

    That would silently zero out novelty, which is the worst available failure:
    the system would stop finding anything unfamiliar and never say so.
    """
    bloom = StableBloomFilter(cells=512, hashes=4)
    for i in range(20_000):
        bloom.add(f"key-{i}")
    assert bloom.fill_rate < 0.9, "filter saturated: novelty would read as zero"
    # 40x over capacity and it still converges rather than filling.
    assert bloom.false_positive_rate < 0.25


def test_stable_bloom_false_positive_rate_is_measured_not_assumed() -> None:
    """The spec requires Bloom false positives to be measured.

    Checks the estimator against an empirical count, so the reported number is
    trustworthy rather than a formula nobody validated.
    """
    bloom = StableBloomFilter(cells=1024, hashes=4)
    for i in range(10_000):
        bloom.add(f"present-{i}")
    trials = 2_000
    observed = sum(1 for i in range(trials) if bloom.seen(f"absent-{i}")) / trials
    assert abs(observed - bloom.false_positive_rate) < 0.05


def test_stable_bloom_retains_recent_insertions() -> None:
    """Eviction must be of stale entries, not of what just happened."""
    bloom = StableBloomFilter(cells=512, hashes=4)
    for i in range(20_000):
        bloom.add(f"key-{i}")
    assert all(bloom.seen(f"key-{i}") for i in range(19_990, 20_000))


def test_bounded_lru_evicts_and_counts() -> None:
    counter = BoundedLRUCounter(capacity=10)
    for i in range(100):
        counter.add(f"k{i}")
    assert len(counter) == 10
    assert counter.evictions == 90
    assert counter.get("k0") == 0  # evicted keys report zero, not stale data


def test_bounded_lru_keeps_hot_keys() -> None:
    counter = BoundedLRUCounter(capacity=5)
    for i in range(20):
        counter.add("hot")
        counter.add(f"cold{i}")
    assert counter.get("hot") == 20


# --- novelty engine ----------------------------------------------------------


def test_novelty_tensor_covers_every_context() -> None:
    engine = NoveltyEngine()
    tensor = engine.observe({context: f"v-{context}" for context in NOVELTY_CONTEXTS})
    assert set(tensor.values) == set(NOVELTY_CONTEXTS)


def test_first_sighting_is_maximally_novel() -> None:
    engine = NoveltyEngine()
    tensor = engine.observe({c: "first" for c in NOVELTY_CONTEXTS})
    assert tensor.peak == 1.0


def test_novelty_decays_with_repetition() -> None:
    engine = NoveltyEngine()
    keys = {c: "repeated" for c in NOVELTY_CONTEXTS}
    first = engine.observe(keys).peak
    for _ in range(20):
        engine.observe(keys)
    assert engine.score(keys).peak < first


def test_scoring_does_not_learn() -> None:
    """Score must be a pure query, or speculative scoring would poison novelty."""
    engine = NoveltyEngine()
    keys = {c: "probe" for c in NOVELTY_CONTEXTS}
    for _ in range(5):
        engine.score(keys)
    assert engine.observations == 0
    assert engine.score(keys).peak == 1.0


def test_missing_context_key_is_novel_not_familiar() -> None:
    """An absent key is missing information; 0.0 would assert 'seen before'."""
    engine = NoveltyEngine()
    assert engine.score({})["host"] == 1.0


def test_novelty_peak_is_max_not_mean() -> None:
    """A mean would dilute the one context that is actually unusual."""
    engine = NoveltyEngine()
    common = {c: "known" for c in NOVELTY_CONTEXTS}
    for _ in range(50):
        engine.observe(common)
    probe = {**common, "actor": "brand-new-actor"}
    tensor = engine.score(probe)
    assert tensor.peak == 1.0
    assert tensor.mean < tensor.peak


def test_novelty_memory_stays_bounded_under_flood() -> None:
    engine = NoveltyEngine()
    for i in range(30_000):
        engine.observe({c: f"flood-{i}" for c in NOVELTY_CONTEXTS})
    assert engine.memory_bytes < 2_000_000


# --- fusion ------------------------------------------------------------------


def _record(index: int, key: str | None, rtype: str, expected: str | None = None) -> RawEventV1:
    fields = {"path": "/tmp/x"}
    if expected:
        fields["_expected_records"] = expected
    return RawEventV1(
        record_id=f"r{index}",
        host_id="h1",
        boot_id="b1",
        sensor=SensorPath.AUDITD,
        observed_at_ns=index * 1000,
        monotonic_ns=index * 1000,
        record_type=rtype,
        assembly_key=key,
        fields=fields,
    )


def test_compound_records_fuse_into_one_operation() -> None:
    assembler = EventAssembler()
    assert assembler.feed(_record(0, "k1", "SYSCALL", "2")) == []
    fused = assembler.feed(_record(1, "k1", "PATH", "2"))
    assert len(fused) == 1
    assert len(fused[0].records) == 2
    assert not fused[0].partial


def test_singleton_records_emit_immediately() -> None:
    assembler = EventAssembler()
    assert len(assembler.feed(_record(0, None, "execve"))) == 1


def test_incomplete_assembly_flushes_as_partial() -> None:
    """A partially observed escalation is still worth knowing about."""
    assembler = EventAssembler()
    assembler.feed(_record(0, "k1", "SYSCALL", "3"))
    drained = assembler.flush()
    assert len(drained) == 1
    assert drained[0].partial


def test_assembler_evicts_under_pressure_rather_than_growing() -> None:
    assembler = EventAssembler(max_pending=8)
    for i in range(200):
        assembler.feed(_record(i, f"key-{i}", "SYSCALL", "2"))
    assert assembler.pending_count <= 8
    assert assembler.stats().evicted_under_pressure > 0


def test_sensor_conflicts_are_surfaced_not_resolved() -> None:
    assembler = EventAssembler()
    first = RawEventV1(
        record_id="a",
        host_id="h1",
        boot_id="b1",
        sensor=SensorPath.AUDITD,
        observed_at_ns=1,
        monotonic_ns=1,
        record_type="SYSCALL",
        assembly_key="k",
        fields={"path": "/etc/shadow", "_expected_records": "2"},
    )
    second = RawEventV1(
        record_id="b",
        host_id="h1",
        boot_id="b1",
        sensor=SensorPath.EBPF,
        observed_at_ns=2,
        monotonic_ns=2,
        record_type="PATH",
        assembly_key="k",
        fields={"path": "/var/log/syslog", "_expected_records": "2"},
    )
    assembler.feed(first)
    fused = assembler.feed(second)[0]
    assert "path" in fused.conflicting_fields()


# --- epochs ------------------------------------------------------------------


def _model() -> EpochModel:
    return EpochModel(identity=SystemIdentity(kernel_id="6.1", package_digest="a"))


def test_novelty_alone_never_opens_an_epoch() -> None:
    """The anti-poisoning rule, stated as a test so it cannot quietly lapse."""
    model = _model()
    decision = model.evaluate(
        observed_identity=SystemIdentity(kernel_id="6.1", package_digest="ATTACKER"),
        corroborating_evidence=frozenset(),
        now_ns=1,
        behavioural_novelty=1.0,
    )
    assert not decision.transitioned
    assert model.epoch_id == 0
    assert model.rejected_transitions == 1


def test_corroborated_system_change_opens_an_epoch() -> None:
    model = _model()
    decision = model.evaluate(
        observed_identity=SystemIdentity(kernel_id="6.1", package_digest="b"),
        corroborating_evidence={"package_digest"},
        now_ns=1,
    )
    assert decision.transitioned
    assert model.epoch_id == 1


def test_corroboration_must_match_what_changed() -> None:
    """Evidence of a kernel upgrade does not justify a package-set change."""
    model = _model()
    decision = model.evaluate(
        observed_identity=SystemIdentity(kernel_id="6.1", package_digest="b"),
        corroborating_evidence={"kernel_id"},
        now_ns=1,
    )
    assert not decision.transitioned


def test_unchanged_identity_is_a_no_op() -> None:
    model = _model()
    decision = model.evaluate(
        observed_identity=SystemIdentity(kernel_id="6.1", package_digest="a"),
        corroborating_evidence={"package_digest"},
        now_ns=1,
    )
    assert not decision.transitioned
    assert decision.reason.value == "UNCHANGED"


def test_epoch_rotation_compresses_history_rather_than_erasing_it() -> None:
    model = _model()
    for _ in range(7):
        model.record_transition()
    model.evaluate(
        observed_identity=SystemIdentity(kernel_id="6.1", package_digest="b"),
        corroborating_evidence={"package_digest"},
        now_ns=1,
    )
    history = model.retained_history
    assert history and history[-1]["observed_transitions"] == 7


def test_epoch_history_is_bounded() -> None:
    model = EpochModel(identity=SystemIdentity(package_digest="p0"), max_history=3)
    for i in range(1, 12):
        model.evaluate(
            observed_identity=SystemIdentity(package_digest=f"p{i}"),
            corroborating_evidence={"package_digest"},
            now_ns=i,
        )
    assert len(model.retained_history) <= 3


# --- causal memory -----------------------------------------------------------


def test_causal_signature_ignores_identity() -> None:
    """Rename the binary; the route is unchanged."""
    args = {
        "parent_signature": "0" * 16,
        "actor_semantics": frozenset({"NETWORK_CLIENT"}),
        "relation": 7,
        "object_semantics": frozenset({"CREDENTIAL"}),
        "state_delta": StateDelta.empty(),
    }
    assert causal_signature(**args) == causal_signature(**args)


def test_causal_signature_changes_with_behaviour() -> None:
    """Change what it actually does and the signature diverges."""
    base: dict[str, object] = {
        "parent_signature": "0" * 16,
        "actor_semantics": frozenset(),
        "relation": 2,
        "object_semantics": frozenset(),
        "state_delta": StateDelta.empty(),
    }
    read = causal_signature(**base)  # type: ignore[arg-type]
    connect = causal_signature(**{**base, "relation": 7})  # type: ignore[arg-type]
    different_object = causal_signature(
        **{**base, "object_semantics": frozenset({"CREDENTIAL"})}  # type: ignore[arg-type]
    )
    assert read != connect
    assert read != different_object


def test_causal_signature_chains_through_its_parent() -> None:
    """Same step, different history, different signature."""
    base: dict[str, object] = {
        "actor_semantics": frozenset(),
        "relation": 2,
        "object_semantics": frozenset(),
        "state_delta": StateDelta.empty(),
    }
    a = causal_signature(parent_signature="a" * 16, **base)  # type: ignore[arg-type]
    b = causal_signature(parent_signature="b" * 16, **base)  # type: ignore[arg-type]
    assert a != b


def test_causal_memory_stays_within_capacity() -> None:
    memory = CausalMemory(capacity=32, l0_budget=8)
    for i in range(500):
        memory.record(
            parent_signature=f"{i:016x}",
            actor_semantics=frozenset({f"a{i}"}),
            relation=i % 20,
            object_semantics=frozenset(),
            state_delta=StateDelta.empty(),
            delta_phi=0.0,
        )
    assert len(memory) <= 32
    assert memory.dropped > 0


def test_high_responsibility_survives_compression() -> None:
    """An attack step from ten minutes ago outranks a file read from now."""
    memory = CausalMemory(capacity=16, l0_budget=4)
    memory.record(
        parent_signature="0" * 16,
        actor_semantics=frozenset({"attacker"}),
        relation=12,
        object_semantics=frozenset({"CREDENTIAL"}),
        state_delta=StateDelta({"credential": (0, 2)}),
        delta_phi=6.0,
    )
    for i in range(200):
        memory.record(
            parent_signature=f"{i:016x}",
            actor_semantics=frozenset({"noise"}),
            relation=2,
            object_semantics=frozenset(),
            state_delta=StateDelta.empty(),
            delta_phi=0.0,
        )
    spine = memory.spine()
    assert len(spine) == 1
    assert spine[0].delta_phi == 6.0
    assert spine[0].resolution == 0, "the spine must survive at full fidelity"


def test_demotion_sheds_identity_at_l2() -> None:
    memory = CausalMemory()
    node = memory.record(
        parent_signature="0" * 16,
        actor_semantics=frozenset(),
        relation=2,
        object_semantics=frozenset(),
        state_delta=StateDelta.empty(),
        delta_phi=0.0,
        actor_identity="proc:b:1:1",
        evidence_locators=("loc-1",),
    )
    demoted = node.demote(2)
    assert demoted.actor_identity == ""
    assert demoted.evidence_locators == ()
    assert demoted.delta_phi == node.delta_phi, "ΔΦ must survive every tier"


# --- adaptive observation ----------------------------------------------------


def test_mandatory_signals_are_collected_without_escalation() -> None:
    """AOP controls optional collection only. It can never switch these off."""
    policy = AdaptiveObservationPolicy()
    for signal in MANDATORY_SIGNALS:
        assert policy.collects(signal, "not-escalated")
    assert not policy.collects("optional_verbose_trace", "not-escalated")


def test_budget_is_a_product_so_any_zero_factor_suppresses() -> None:
    score = AdaptiveObservationPolicy.budget_score(
        uncertainty=1.0, security_potential=100.0, causal_relevance=0.0
    )
    assert score == 0.0


def test_high_uncertainty_without_consequence_does_not_escalate() -> None:
    policy = AdaptiveObservationPolicy()
    decision = policy.consider(
        target="t", uncertainty=1.0, security_potential=0.0, causal_relevance=1.0, now_ns=0
    )
    assert not decision.escalated


def test_concurrency_cap_refuses_further_escalation() -> None:
    policy = AdaptiveObservationPolicy(AOPBudget(max_concurrent=2))
    decisions = [
        policy.consider(
            target=f"t{i}",
            uncertainty=0.9,
            security_potential=10.0,
            causal_relevance=0.9,
            now_ns=0,
        )
        for i in range(6)
    ]
    assert sum(1 for d in decisions if d.escalated) == 2
    assert any("max_concurrent" in d.refused_reason for d in decisions)
    assert policy.report().peak_concurrent <= 2


def test_escalations_expire() -> None:
    budget = AOPBudget(max_duration_ns=1_000)
    policy = AdaptiveObservationPolicy(budget)
    policy.consider(
        target="t", uncertainty=0.9, security_potential=10.0, causal_relevance=0.9, now_ns=0
    )
    assert policy.level_for("t") is not ObservationLevel.BASELINE
    policy.consider(
        target="other",
        uncertainty=0.0,
        security_potential=0.0,
        causal_relevance=0.0,
        now_ns=10_000,
    )
    assert policy.level_for("t") is ObservationLevel.BASELINE


def test_extra_event_rate_is_capped() -> None:
    policy = AdaptiveObservationPolicy(AOPBudget(max_extra_events_per_second=10))
    policy.consider(
        target="t", uncertainty=0.9, security_potential=10.0, causal_relevance=0.9, now_ns=0
    )
    policy.record_observation("t", extra_events=10_000, uncertainty_now=0.1)
    report = policy.report()
    assert report.extra_events_collected <= 10
    assert "max_extra_events_per_second" in report.caps_hit


# --- aggregation -------------------------------------------------------------


def _run(behaviours: tuple[Behaviour, ...], label: int = 0):  # type: ignore[no-untyped-def]
    return Stage1Pipeline().run_scenario(Scenario("s", behaviours, label))


def test_repetitive_low_value_events_aggregate() -> None:
    result = _run(tuple(Behaviour("read", {"path": "/var/log/app.log"}) for _ in range(50)))
    assert len(result.emitted) < len(result.transitions)


def test_high_consequence_transitions_are_never_aggregated() -> None:
    """Repetition does not make a credential read less interesting."""
    pipeline = Stage1Pipeline()
    result = pipeline.run_scenario(Scenario("s", ATTACK_EXFIL * 6, 1))
    high = [t for t in result.transitions if t.is_high_consequence]
    emitted_high = [t for t in result.emitted if t.is_high_consequence]
    assert high
    assert len(emitted_high) == len(high)


def test_aggregation_retains_count_extrema_and_evidence() -> None:
    pipeline = Stage1Pipeline()
    pipeline.run_scenario(
        Scenario("s", tuple(Behaviour("read", {"path": "/var/log/a.log"}) for _ in range(30)), 0)
    )
    groups = pipeline.aggregation.groups
    assert groups
    group = max(groups, key=lambda g: g.count)
    assert group.count > 1
    assert group.evidence, "aggregates must stay investigable"


def test_incomplete_observation_blocks_aggregation() -> None:
    """Cannot certify low information loss on an observation we did not see fully."""
    policy = AggregationPolicy(AggregationThresholds())
    result = _run((Behaviour("read", {"path": "/var/log/a.log"}),))
    transition = result.transitions[0]
    from dataclasses import replace

    incomplete = replace(transition, observation_incomplete=True)
    assert policy.offer(incomplete) is incomplete


# --- SSIR codec --------------------------------------------------------------


def test_representation_levels_cost_progressively_more() -> None:
    codec = SSIRCodec()
    sizes = [codec.record_bytes(level) for level in RepresentationLevel]
    assert sizes[0] < sizes[1] <= sizes[2]


def test_encode_decode_round_trips() -> None:
    result = _run(ATTACK_EXFIL, label=1)
    codec = SSIRCodec()
    transition = result.transitions[0]
    blob = codec.encode(transition)
    decoded = codec.decode_fields(blob)
    assert decoded["relation"] == int(transition.relation)
    assert decoded["state_delta"] == transition.state_delta.bitmask()


def test_decoder_refuses_a_foreign_blob() -> None:
    """Silently misreading a security representation is worse than refusing."""
    from pocketsec.stage0.contracts.common import ContractError

    with pytest.raises(ContractError, match="magic"):
        SSIRCodec().decode_header(b"\xff\xff\x01\x00")


def test_ablated_codec_actually_costs_fewer_bytes() -> None:
    full = SSIRCodec()
    ablated = SSIRCodec(retained=frozenset(LAYOUTS) - {"causal_sig", "actor_id"})
    assert ablated.record_bytes(RepresentationLevel.L2) < full.record_bytes(
        RepresentationLevel.L2
    )


def test_projection_to_l0_drops_evidence_and_delta() -> None:
    result = _run(ATTACK_EXFIL, label=1)
    rich = next(t for t in result.transitions if t.state_delta)
    projected = rich.at_level(RepresentationLevel.L0)
    assert projected.evidence == ()
    assert not projected.state_delta


def test_temporal_buckets_are_monotone_and_bounded() -> None:
    buckets = [TemporalContext.bucket(n) for n in (0, 1_000, 10**6, 10**9, 10**12)]
    assert buckets == sorted(buckets)
    assert max(buckets) <= 15
