"""Stage 7 package ``echo``: aggregator families (D7.9), ECHO (D7.10), antibody forge (D7.11).

Behaviour and failure paths, not construction: the sovereignty rules are attacked with
whole-fleet support, the cap is attacked with many identities in one cluster, every ECHO
ablation switch is shown to change an outcome on a crafted case (and to change nothing on a
case it should not touch), and the forge is run on real Stage 1 episodes encoded through
Stage 2 into Stage 6 ``EncodedStep`` values.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import replace

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.labs.corpus import (
    ATTACK_EXFIL,
    ATTACK_PERSISTENCE,
    ATTACK_UNSEEN_ESCAPE,
    ATTACK_UNSEEN_MEMORY,
    BENIGN_PATTERNS,
    BENIGN_PRIVILEGED,
    Behaviour,
    Scenario,
)
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_LAYOUT, GROUP_OFFSETS
from pocketsec.stage6.capsule.experience_capsule import EncodedStep, PrivacyClass
from pocketsec.stage6.memory.semantic import match_motif
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage7.aggregation import robust
from pocketsec.stage7.aggregation.robust import (
    Aggregator,
    StanceMatrix,
    aggregate,
    plus_local_validation,
    stance_matrix,
)
from pocketsec.stage7.antibody import forge
from pocketsec.stage7.antibody.forge import (
    BenignRing,
    LocalIncident,
    LocalValidation,
    LocalValidator,
    copied_rule,
    forge_antibody,
    matches,
    mutate_incident,
    prototype_steps,
)
from pocketsec.stage7.capsule.knowledge_capsule import (
    EpochContext,
    FalsificationSummary,
    KnowledgeType,
    MotifRow,
    ProvenanceCommitment,
    RoleClass,
    SourceContextSketch,
    Stance,
    ValidationSummary,
    VisibilityClass,
    motif_fingerprint,
    seal_capsule,
)
from pocketsec.stage7.echo import inference
from pocketsec.stage7.echo.inference import (
    MECHANISMS,
    EchoConfig,
    EchoEngine,
    EchoStatus,
)
from pocketsec.stage7.hivelock.ingress import MAX_POOL_CAPSULES, PooledCapsule
from pocketsec.stage7.relevance.epistemic_distance import LocalContext
from pocketsec.stage7.trust.contextual import TRUST_PRIOR, ContextualTrust

ALL_RELATIONS = frozenset(range(24))
SE = "se-" + "0" * 16
SETUID_THEN_SEND = (MotifRow(13, 0, 0, 1), MotifRow(10, 128, 0, 0))
READ_CREDENTIAL = (MotifRow(2, 1, 0, 4),)
NO_PROBATION = EchoConfig(probation=False)

# --- Stage 1 -> Stage 2 -> Stage 6 episodes ------------------------------------------------


def _episode(
    chain: tuple[Behaviour, ...], offset: int, *, slot: int = 0
) -> tuple[EncodedStep, ...]:
    # Session-unique offsets: Stage 1 carries lineage state across scenarios (MEMORY trap).
    result = Stage1Pipeline().run_scenario(Scenario(f"s{offset}", chain, 0), offset=offset)
    return tuple(EncodedStep.from_transition(t, actor_slot=slot) for t in result.transitions)


def _interleave(a: tuple[EncodedStep, ...], b: tuple[EncodedStep, ...]) -> tuple[EncodedStep, ...]:
    merged: list[EncodedStep] = []
    for index in range(max(len(a), len(b))):
        merged.extend(a[index : index + 1])
        merged.extend(b[index : index + 1])
    return tuple(merged)


def _incident(name: str, steps: tuple[EncodedStep, ...]) -> LocalIncident:
    digests = tuple(dict.fromkeys(d for step in steps for d in step.evidence))[:8]
    return LocalIncident(name, steps, digests)


ATTACKS = {
    "exfil": ATTACK_EXFIL,
    "persist": ATTACK_PERSISTENCE,
    "memory": ATTACK_UNSEEN_MEMORY,
    "escape": ATTACK_UNSEEN_ESCAPE,
}


@pytest.fixture(scope="module")
def fleet() -> dict[str, object]:
    """A small simulated fleet: 3 hosts, each with a benign ring and one incident per family.

    Host 0 and 1 are WEB-like (no privileged admin work); host 2 is ADMIN-like and its ring
    holds BENIGN_PRIVILEGED, the benign behaviour that shares setuid + systemd with
    ATTACK_PERSISTENCE (the non-IID collision the fleet corpus is built on).
    """
    hosts = []
    for host in range(3):
        base = (host + 1) * 100_000
        ring = BenignRing()
        for index, pattern in enumerate(BENIGN_PATTERNS):
            ring.add(_episode(pattern, base + index * 1000))
        if host == 2:
            ring.add(_episode(BENIGN_PRIVILEGED, base + 90_000))
        incidents = {}
        for index, (name, chain) in enumerate(ATTACKS.items()):
            attack = _episode(chain, base + 50_000 + index * 1000, slot=0)
            cover = _episode(BENIGN_PATTERNS[index % 5], base + 70_000 + index * 1000, slot=1)
            incidents[name] = _incident(f"h{host}-{name}", _interleave(attack, cover))
        hosts.append({"ring": ring, "incidents": incidents})
    return {"hosts": hosts}


# --- capsules and the engine ---------------------------------------------------------------


def _peer(n: int) -> str:
    return f"peer-{n:016x}"


def _root(n: int) -> str:
    return f"root-{n:016x}"


def _pooled(
    rows: tuple[MotifRow, ...],
    peer: int,
    *,
    stance: Stance = Stance.SUPPORT,
    root: int | None = None,
    relevance: float = 1.0,
    tried: int = 0,
    survived: int = 0,
    sequence: int = 1,
) -> PooledCapsule:
    declared = _root(peer if root is None else root)
    capsule = seal_capsule(
        knowledge_type=KnowledgeType.ANTIBODY,
        stance=stance,
        semantic_invariant=rows,
        attack_mappings=(),
        epoch_context=EpochContext(SE, VisibilityClass.FULL),
        source_context_sketch=SourceContextSketch(RoleClass.WEB, (0,) * 8),
        validation_summary=ValidationSummary(4, 1, 0),
        falsification_summary=FalsificationSummary(tried, survived, ()),
        provenance_commitment=ProvenanceCommitment(
            _peer(peer), declared, ("hc-" + "c" * 32,), None
        ),
        independence_group=declared,
        privacy_class=PrivacyClass.PUBLIC_DERIVED,
        created_round=0,
        expiry_round=32,
        sequence=sequence,
        parent_capsules=(),
        time_window=None,
        observability=None,
        revocation_target=None,
        revocation_ground=None,
        key_id=f"key-{peer:016x}",
    )
    raw = "sha256:" + hashlib.sha256(capsule.capsule_id.encode()).hexdigest()
    return PooledCapsule(
        capsule=capsule,
        raw_digest=raw,
        peer_id=_peer(peer),
        cluster_id="cl-" + f"{peer:016x}",
        relevance=relevance,
        gravity=0.5,
        received_round=0,
    )


class StubTrust:
    """A fixed reliability per cluster (default 1.0) that records every ``record`` call."""

    def __init__(self, reliability: float = 1.0) -> None:
        self.value = reliability
        self.calls: list[tuple[str, str, bool, int]] = []

    def reliability(self, cluster_id: str, task: str, *, round_index: int) -> float:
        return self.value

    def record(self, cluster_id: str, task: str, *, confirmed: bool, round_index: int) -> None:
        self.calls.append((cluster_id, task, confirmed, round_index))


def _engine(
    *,
    config: EchoConfig = NO_PROBATION,
    ring: tuple[tuple[EncodedStep, ...], ...] = (),
    incidents: tuple[LocalIncident, ...] = (),
    local_keys: frozenset[str] = frozenset(),
    clusters: dict[str, str] | None = None,
    trust: object | None = None,
    observable: frozenset[int] = ALL_RELATIONS,
    meter: WorkMeter | None = None,
) -> EchoEngine:
    benign = BenignRing()
    for episode in ring:
        benign.add(episode)
    validator = LocalValidator(benign=benign, incidents=incidents, observable_relations=observable)
    local = LocalContext(
        role=RoleClass.WEB,
        software_epoch=SE,
        visibility=VisibilityClass.FULL,
        family_profile=(0,) * 8,
        local_keys=local_keys,
        observable_relations=observable,
    )
    mapping = clusters or {}
    return EchoEngine(
        local=local,
        validator=validator,
        trust=trust if trust is not None else StubTrust(),  # type: ignore[arg-type]
        cluster_of=lambda p: mapping.get(p, "cl-" + p[-16:]),
        config=config,
        meter=meter,
    )


def _decide(engine: EchoEngine, round_index: int = 0) -> inference.EchoDecision:
    result = engine.infer(round_index=round_index)
    assert len(result.decisions) == 1
    return result.decisions[0]


def _firing(engine: EchoEngine, round_index: int = 0) -> dict[str, int]:
    return dict(engine.infer(round_index=round_index).firing)


# === ECHO: sovereignty, independence, direction ===========================================


def test_identity_count_does_not_raise_mass_within_a_cluster() -> None:
    """MAJORITY_IS_NOT_TRUTH. One cluster with 1 identity and with 40 has the same mass."""
    one = _engine(clusters={_peer(0): "cl-sybil"})
    one.offer([_pooled(SETUID_THEN_SEND, 0)])
    many_ids = {_peer(n): "cl-sybil" for n in range(40)}
    many = _engine(clusters=many_ids)
    many.offer([_pooled(SETUID_THEN_SEND, n) for n in range(40)])  # 40 declared roots
    lone, crowd = _decide(one), _decide(many)
    assert crowd.support_mass == pytest.approx(lone.support_mass) == pytest.approx(0.5)
    assert crowd.support_clusters == lone.support_clusters == 1
    assert crowd.status is lone.status is EchoStatus.INSUFFICIENT
    assert crowd.evidence[0].identities == 40
    # The control would fail this test: an uncapped identity sum is bought by identities.
    uncapped = _engine(config=EchoConfig(probation=False, cluster_cap=False), clusters=many_ids)
    uncapped.offer([_pooled(SETUID_THEN_SEND, n) for n in range(40)])
    assert _decide(uncapped).support_mass == pytest.approx(20.0)
    assert _decide(uncapped, 1).status is EchoStatus.ELIGIBLE


def test_local_fp_challenges_whatever_the_support(fleet: dict[str, object]) -> None:
    benign = fleet["hosts"][2]["ring"].episodes()  # type: ignore[index]
    privileged = next(e for e in benign if e[0].relation == 13)
    fp_rows = (MotifRow(13, 0, 0, 1),)  # setuid raising privilege: matches admin's own work
    assert matches(fp_rows, privileged)
    engine = _engine(ring=benign)
    engine.offer([_pooled(fp_rows, n) for n in range(64)])  # 64 independent roots agree
    for round_index in range(4):
        decision = _decide(engine, round_index)
        assert decision.status is EchoStatus.CHALLENGED
        assert decision.local_validation is LocalValidation.LOCAL_FP
        assert decision.reasons == ("local_fp",)
        assert decision.support_mass >= 30  # the support is overwhelming, and irrelevant
    assert _firing(engine, 4)["local_validation"] == 1


def test_local_origin_key_is_never_redecided() -> None:
    key = motif_fingerprint(SETUID_THEN_SEND)
    engine = _engine(local_keys=frozenset({key}))
    engine.offer([_pooled(SETUID_THEN_SEND, n) for n in range(32)])
    engine.offer([_pooled(SETUID_THEN_SEND, 100 + n, stance=Stance.CONTEST) for n in range(32)])
    engine.mark_suspect([key])
    for round_index in range(3):
        decision = _decide(engine, round_index)
        assert decision.status is EchoStatus.REFUSED
        assert decision.reasons == ("local_origin",)
    # No ablation switch reaches the rule: with every mechanism off it is still REFUSED.
    off = EchoConfig(**dict.fromkeys(MECHANISMS, False))
    bare = _engine(config=off, local_keys=frozenset({key}))
    bare.offer([_pooled(SETUID_THEN_SEND, n) for n in range(32)])
    assert _decide(bare).status is EchoStatus.REFUSED


def test_contests_reduce_but_never_create() -> None:
    trust = StubTrust()
    engine = _engine(trust=trust)
    engine.offer([_pooled(SETUID_THEN_SEND, n, stance=Stance.CONTEST) for n in range(64)])
    only_contests = _decide(engine)
    assert only_contests.status is EchoStatus.INSUFFICIENT
    assert only_contests.support_mass == 0.0 and only_contests.contest_mass > 0
    assert trust.calls == []  # a contest never refutes anyone
    # Monotone: over every (supporters, contesters) mix, adding contests never makes ELIGIBLE,
    # never changes the support side, and does reduce some ELIGIBLE key to INSUFFICIENT.
    reduced = 0
    for supporters in range(0, 5):
        base = _engine()
        base.offer([_pooled(SETUID_THEN_SEND, n) for n in range(supporters)])
        before = base.infer(round_index=0).decisions
        for contesters in range(1, 5):
            mixed = _engine()
            mixed.offer([_pooled(SETUID_THEN_SEND, n) for n in range(supporters)])
            mixed.offer(
                [
                    _pooled(SETUID_THEN_SEND, 50 + n, stance=Stance.CONTEST)
                    for n in range(contesters)
                ]
            )
            after = _decide(mixed)
            if after.status is EchoStatus.ELIGIBLE:
                assert before and before[0].status is EchoStatus.ELIGIBLE
            if before:
                assert after.support_mass == pytest.approx(before[0].support_mass)
                reduced += (
                    before[0].status is EchoStatus.ELIGIBLE
                    and after.status is not EchoStatus.ELIGIBLE
                )
    assert reduced > 0


def test_probation_delays_eligibility() -> None:
    engine = _engine(config=EchoConfig())  # probation on, 2 rounds
    engine.offer([_pooled(SETUID_THEN_SEND, n) for n in range(2)])
    statuses = [_decide(engine, r) for r in range(3)]
    assert [d.status for d in statuses] == [EchoStatus.INSUFFICIENT] * 2 + [EchoStatus.ELIGIBLE]
    assert [d.eligible_rounds for d in statuses] == [1, 2, 3]
    assert statuses[0].reasons == ("probation",)
    # Re-inferring a counted round does not advance probation; a missed round restarts it.
    assert _decide(engine, 2).eligible_rounds == 3
    assert _decide(engine, 5).status is EchoStatus.INSUFFICIENT
    # The timing-collusion defence: contests that arrive during probation stop it.
    late = _engine(config=EchoConfig())
    late.offer([_pooled(SETUID_THEN_SEND, n) for n in range(2)])
    _decide(late, 0)
    late.offer([_pooled(SETUID_THEN_SEND, 90 + n, stance=Stance.CONTEST) for n in range(3)])
    assert [_decide(late, r).status for r in (1, 2, 3)] == [EchoStatus.INSUFFICIENT] * 3
    # Probation off: the same evidence is ELIGIBLE at once.
    eager = _engine(config=EchoConfig(probation=False))
    eager.offer([_pooled(SETUID_THEN_SEND, n) for n in range(2)])
    assert _decide(eager).status is EchoStatus.ELIGIBLE


def _flag_case(name: str, fleet: dict[str, object], config: EchoConfig) -> EchoEngine:
    rows = SETUID_THEN_SEND
    if name in ("cluster_cap", "dependence_clustering"):
        # Three identities declaring three roots, which the dependence graph merged.
        engine = _engine(config=config, clusters={_peer(n): "cl-one" for n in range(3)})
        engine.offer([_pooled(rows, n) for n in range(3)])
    elif name == "contextual_trust":
        engine = _engine(config=config, trust=StubTrust(0.1))
        engine.offer([_pooled(rows, n) for n in range(4)])
    elif name == "epistemic_distance":
        engine = _engine(config=config)
        engine.offer([_pooled(rows, n, relevance=0.1) for n in range(2)])
    elif name == "falsification_weight":
        engine = _engine(config=config)
        engine.offer([_pooled(rows, n, tried=16, survived=0) for n in range(2)])
    elif name == "contest_mass":
        engine = _engine(config=config)
        engine.offer([_pooled(rows, n) for n in range(2)])
        engine.offer([_pooled(rows, 10 + n, stance=Stance.CONTEST) for n in range(3)])
    elif name == "local_validation":
        ring = fleet["hosts"][2]["ring"].episodes()  # type: ignore[index]
        engine = _engine(config=config, ring=ring)
        engine.offer([_pooled((MotifRow(13, 0, 0, 1),), n) for n in range(2)])
    else:
        engine = _engine(config=config)
        engine.offer([_pooled(rows, n) for n in range(2)])
    return engine


@pytest.mark.parametrize("name", MECHANISMS)
def test_every_config_flag_changes_something_on_a_crafted_case(
    name: str, fleet: dict[str, object]
) -> None:
    on = EchoConfig(probation=name == "probation")
    off = replace(on, **{name: False})
    firing = _firing(_flag_case(name, fleet, on))
    assert firing[name] == 1, (name, firing)
    # The firing count agrees with an independent run under the ablated config.
    with_it = _decide(_flag_case(name, fleet, on)).status
    without = _decide(_flag_case(name, fleet, off)).status
    assert with_it is not without
    assert name not in dict(_flag_case(name, fleet, off).infer(round_index=0).firing)
    # Control: a case the mechanism has no reason to touch does not fire it.
    plain = _engine(config=on)
    count = 1 if name == "probation" else 6  # probation: stay below the floor both ways
    plain.offer([_pooled((MotifRow(10, 128, 0, 0),), n) for n in range(count)])
    assert _firing(plain)[name] == 0


def test_every_decision_is_recorded_with_bounded_evidence() -> None:
    engine = _engine()
    engine.offer([_pooled(SETUID_THEN_SEND, n) for n in range(20)])
    decision = _decide(engine)
    assert re.fullmatch(r"agg-[0-9a-f]{32}", decision.decision_id)
    assert len(decision.evidence) == inference.MAX_CLUSTERS_PER_DECISION and decision.truncated
    assert decision.support_clusters == 20  # the mass counts every cluster, shown or not
    assert decision.decision_id == _decide(engine).decision_id  # deterministic
    crowded = _engine(clusters={_peer(n): "cl-one" for n in range(12)})
    crowded.offer([_pooled(SETUID_THEN_SEND, n) for n in range(12)])
    row = _decide(crowded).evidence[0]
    assert len(row.capsule_ids) == inference.MAX_CAPSULE_IDS_PER_ROW and _decide(crowded).truncated


def test_offer_bounds_refuse_newcomers_and_count(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = _engine()
    cap = inference.MAX_CONTRIBUTIONS_PER_KEY
    assert engine.offer([_pooled(SETUID_THEN_SEND, n) for n in range(cap + 5)]) == cap
    assert engine.contributions_refused() == 5
    assert engine.offer([_pooled(SETUID_THEN_SEND, 0)]) == 0  # the same capsule again
    # An established peer's newer word replaces its older one without a new slot.
    assert engine.offer([_pooled(SETUID_THEN_SEND, 0, stance=Stance.CONTEST, sequence=2)]) == 1
    assert _decide(engine).contest_clusters == 1
    monkeypatch.setattr(inference, "MAX_KEYS_TRACKED", 2)
    small = _engine()
    small.offer([_pooled((MotifRow(r, 0, 0, 0),), 0) for r in (1, 2, 3, 7)])
    result = small.infer(round_index=0)
    assert (result.keys_tracked, result.keys_refused) == (2, 2)
    assert small.memory_bytes() > 0


def test_suspect_and_reinstatement_restart_probation() -> None:
    key = motif_fingerprint(SETUID_THEN_SEND)
    engine = _engine()
    engine.offer([_pooled(SETUID_THEN_SEND, n) for n in range(2)])
    assert _decide(engine, 0).status is EchoStatus.ELIGIBLE
    engine.mark_suspect([key])
    assert _decide(engine, 1).status is EchoStatus.SUSPECT
    engine.clear_suspect([key])
    assert _decide(engine, 2).status is EchoStatus.ELIGIBLE  # probation off in this config
    patient = _engine(config=EchoConfig())
    patient.offer([_pooled(SETUID_THEN_SEND, n) for n in range(2)])
    for r in range(3):
        _decide(patient, r)
    patient.mark_suspect([key])
    _decide(patient, 3)
    patient.clear_suspect([key])
    assert _decide(patient, 4).status is EchoStatus.INSUFFICIENT  # re-earns eligibility


def test_trust_moves_only_on_local_evidence(fleet: dict[str, object]) -> None:
    trust = ContextualTrust()
    host = fleet["hosts"][0]  # type: ignore[index]
    incident = host["incidents"]["exfil"]
    engine = _engine(trust=trust, incidents=(incident,))
    rows = SETUID_THEN_SEND
    assert matches(rows, incident.steps)
    engine.offer([_pooled(rows, n) for n in range(2)])
    engine.offer([_pooled(rows, 9, stance=Stance.CONTEST)])
    decision = _decide(engine, 1)
    assert decision.local_validation is LocalValidation.LOCAL_CONFIRMED
    assert "local_confirmed" in decision.reasons
    task = "-".join(str(stage) for stage in _pooled(rows, 0).capsule.causal_motif)
    confirmed = trust.reliability("cl-" + _peer(0)[-16:], task, round_index=1)
    assert confirmed > TRUST_PRIOR
    engine.record_outcome(motif_fingerprint(rows), confirmed=False, round_index=2)
    assert trust.reliability("cl-" + _peer(0)[-16:], task, round_index=2) < confirmed
    assert trust.reliability("cl-" + _peer(9)[-16:], task, round_index=2) == TRUST_PRIOR
    with pytest.raises(ContractError):
        engine.record_outcome("mf-" + "0" * 16, confirmed=True, round_index=2)


def test_not_observable_and_meter_charging() -> None:
    meter = WorkMeter()
    engine = _engine(observable=frozenset({13}), meter=meter)
    engine.offer([_pooled(SETUID_THEN_SEND, n) for n in range(3)])
    decision = _decide(engine)
    assert decision.status is EchoStatus.INSUFFICIENT and decision.reasons == ("not_observable",)
    assert meter.spent > 0
    with pytest.raises(ContractError):
        EchoConfig(probation_rounds=-1)
    with pytest.raises(ContractError):
        engine.infer(round_index=-1)


# === aggregator families =======================================================================


def _matrix(
    rows: dict[str, tuple[int, ...]], keys: tuple[str, ...], roots: dict[str, str] | None = None
) -> StanceMatrix:
    ids = tuple(rows)
    return StanceMatrix(
        ids,
        keys,
        tuple(rows[i] for i in ids),
        tuple((roots or {}).get(i, "root-" + i) for i in ids),
    )


def test_median_trimmed_krum_bulyan_semantics() -> None:
    keys = ("k1", "k2")
    honest = {f"h{n}": (1, 0) for n in range(5)}
    byz = {"z0": (-1, 1), "z1": (-1, 1)}
    m = _matrix({**honest, **byz}, keys)  # n = 7, f = max(1, floor(0.2*7)) = 1
    krum = aggregate(m, Aggregator.KRUM)
    assert krum.accepted == ("k1",) and len(krum.excluded_identities) == 6
    multi = aggregate(m, Aggregator.MULTI_KRUM)  # m = n - f = 6: one Byzantine row gets in
    assert multi.accepted == ("k1", "k2") and multi.excluded_identities == ("z1",)
    bulyan = aggregate(m, Aggregator.BULYAN)  # 5 honest selected, trim 1 each end
    assert bulyan.accepted == ("k1",) and set(bulyan.excluded_identities) == {"z0", "z1"}
    # Median over VOTERS: k2's only voters are the two Byzantine rows, so it is accepted —
    # the silent honest majority does not vote. Krum/Bulyan, over full vectors, refuse it.
    assert aggregate(m, Aggregator.MEDIAN).accepted == ("k1", "k2")
    # Refused preconditions: nothing accepted, the reason named.
    small = _matrix({f"h{n}": (1, 0) for n in range(4)}, keys)
    refused = aggregate(small, Aggregator.KRUM)
    assert refused.accepted == () and refused.refused_reason and "2f" in refused.refused_reason
    six = _matrix({f"h{n}": (1, 0) for n in range(6)}, keys)
    assert aggregate(six, Aggregator.KRUM).refused_reason is None
    assert aggregate(six, Aggregator.BULYAN).refused_reason.startswith("bulyan")  # type: ignore[union-attr]
    # Vote families over VOTERS only.
    votes = _matrix({"a": (1, 1), "b": (1, -1), "c": (-1, 0), "d": (-1, 0), "e": (-1, 0)}, keys)
    assert aggregate(votes, Aggregator.MEDIAN).accepted == ()  # k1 [1,1,-1,-1,-1]; k2 [1,-1] -> 0
    assert aggregate(votes, Aggregator.TRIMMED_MEAN).accepted == ()  # trimmed k1 = -1/3
    lone = _matrix({"a": (1, 0), "b": (0, 1), "c": (0, 1)}, keys)
    assert aggregate(lone, Aggregator.MAJORITY).accepted == ("k2",)  # k1 lacks quorum 2
    assert aggregate(lone, Aggregator.MEAN).accepted == ("k2",)
    assert aggregate(lone, Aggregator.MEDIAN).accepted == ("k1", "k2")  # no quorum clause
    assert aggregate(lone, Aggregator.TRIMMED_MEAN, trim=0.4).accepted == ("k1", "k2")
    # The Sybil contrast: 10 identities of one adversary outvote 3 honest roots.
    sybil = _matrix(
        {**{f"s{n}": (1,) for n in range(10)}, **{f"h{n}": (-1,) for n in range(3)}}, ("p",)
    )
    for method in (
        Aggregator.MAJORITY,
        Aggregator.MEAN,
        Aggregator.MEDIAN,
        Aggregator.TRIMMED_MEAN,
    ):
        assert aggregate(sybil, method).accepted == ("p",), method
    clusters = {**{f"s{n}": "cl-adv" for n in range(10)}, **{f"h{n}": f"cl-h{n}" for n in range(3)}}
    assert (
        aggregate(
            sybil, Aggregator.ROOT_QUORUM, clusters=clusters, local_ok=lambda k: True
        ).accepted
        == ()
    )
    with pytest.raises(ContractError):
        aggregate(m, Aggregator.ECHO)
    with pytest.raises(ContractError):
        aggregate(m, Aggregator.MEDIAN, trim=0.5)


def test_validation_filter_and_root_quorum() -> None:
    keys = ("good", "fp", "contested")
    m = _matrix(
        {"a": (1, 1, 1), "b": (0, 1, -1), "c": (0, 0, -1), "d": (1, 0, 1)},
        keys,
        roots={"a": "root-feed"},
    )
    ok = {"good": True, "fp": False, "contested": True}
    local_ok = ok.__getitem__
    vf = aggregate(m, Aggregator.VALIDATION_FILTER, local_ok=local_ok)
    assert vf.accepted == ("good", "contested")  # any single SUPPORT that passes locally
    clusters = {"a": "cl-1", "b": "cl-2", "c": "cl-3", "d": "cl-4"}
    rq = aggregate(m, Aggregator.ROOT_QUORUM, clusters=clusters, local_ok=local_ok)
    assert rq.accepted == ("good",)  # contested: 2 supporting vs 2 contesting clusters
    merged = {**clusters, "d": "cl-1"}  # a and d are one cluster: only one supporter left
    assert aggregate(m, Aggregator.ROOT_QUORUM, clusters=merged, local_ok=local_ok).accepted == ()
    declared = aggregate(m, Aggregator.ROOT_QUORUM, local_ok=local_ok)  # roots as clusters
    assert declared.accepted == ("good",)
    with pytest.raises(ContractError):
        aggregate(m, Aggregator.ROOT_QUORUM, clusters={"a": "cl-1"}, local_ok=local_ok)
    with pytest.raises(ContractError):
        aggregate(m, Aggregator.VALIDATION_FILTER)
    feed = aggregate(m, Aggregator.CENTRAL_FEED, feed_root="root-feed", local_ok=local_ok)
    assert feed.accepted == ("good", "contested")
    assert aggregate(m, Aggregator.NO_SHARING).accepted == ()
    lv = plus_local_validation(aggregate(m, Aggregator.MAJORITY), local_ok)
    assert "fp" not in lv.accepted


def test_stance_matrix_reads_the_pool_by_identity() -> None:
    assert robust.MAX_MATRIX_IDENTITIES == MAX_POOL_CAPSULES
    pool = [
        _pooled(SETUID_THEN_SEND, 0),
        _pooled(SETUID_THEN_SEND, 0, stance=Stance.CONTEST, sequence=2),  # latest word wins
        _pooled(SETUID_THEN_SEND, 1, root=7),
        _pooled(READ_CREDENTIAL, 1, sequence=3),
    ]
    m = stance_matrix(pool)
    assert m.identities == (_peer(0), _peer(1))
    key = motif_fingerprint(SETUID_THEN_SEND)
    column = m.column(m.keys.index(key))
    assert column == (-1, 1) and m.roots == (_root(0), _root(7))
    with pytest.raises(ContractError):
        StanceMatrix(("a",), ("k",), ((2,),), ("r",))


# === the forge ================================================================================


def test_forged_antibody_matches_incident_not_benign_ring(fleet: dict[str, object]) -> None:
    forged = 0
    for host in fleet["hosts"]:  # type: ignore[union-attr]
        ring: BenignRing = host["ring"]
        for incident in host["incidents"].values():
            antibody = forge_antibody(incident, benign=ring, seed=3)
            if antibody is None:
                continue
            forged += 1
            assert matches(antibody.invariant, incident.steps)
            assert not any(matches(antibody.invariant, e) for e in ring.episodes())
            validator = LocalValidator(
                benign=ring, incidents=(incident,), observable_relations=ALL_RELATIONS
            )
            assert validator.validate(antibody.invariant) is LocalValidation.LOCAL_CONFIRMED
            assert antibody.antibody_key == motif_fingerprint(antibody.invariant)
            _, doppelgangers = mutate_incident(incident, seed=3, benign=ring)
            assert not any(matches(antibody.invariant, d) for d in doppelgangers)
    assert forged >= 9  # exfil, memory and escape on every host


def _size(antibody: forge.KnowledgeAntibody) -> tuple[int, int]:
    """(rows, asserted bits): what a receiver must match, and what it can over-fit on."""
    rows = antibody.invariant
    bits = sum(r.require_properties.bit_count() + r.require_raised.bit_count() for r in rows)
    return len(rows), bits


def test_minimised_is_no_larger_than_copied_rule(fleet: dict[str, object]) -> None:
    strictly_smaller = 0
    for host in fleet["hosts"]:  # type: ignore[union-attr]
        for incident in host["incidents"].values():
            minimised = forge_antibody(incident, benign=host["ring"], seed=1)
            plain = forge_antibody(incident, benign=host["ring"], seed=1, minimise=False)
            copied = copied_rule(incident)
            assert copied is not None and copied.minimised is False
            if minimised is None:
                assert plain is None
                continue
            assert plain is not None
            assert _size(minimised) <= _size(plain) <= _size(copied)
            strictly_smaller += _size(minimised) < _size(copied)
    assert strictly_smaller > 0  # minimisation fires on this corpus


def test_forge_returns_none_without_a_discriminative_core(fleet: dict[str, object]) -> None:
    admin = fleet["hosts"][2]  # type: ignore[index]
    persist = admin["incidents"]["persist"]
    # setuid -> execve(systemctl) is the only doppelganger-proof pair, and the admin's own
    # apt work performs it: no stable discriminative core on this host.
    assert forge_antibody(persist, benign=admin["ring"], seed=0) is None
    assert copied_rule(persist) is not None  # the control would ship it anyway
    benign_twin = _incident("twin", admin["ring"].episodes()[0])
    assert forge_antibody(benign_twin, benign=admin["ring"]) is None
    quiet = _incident(
        "quiet", (replace(benign_twin.steps[1], object_property_mask=0, state_delta_mask=0),)
    )
    assert forge_antibody(quiet, benign=BenignRing()) is None and copied_rule(quiet) is None


def test_prototype_steps_round_trip_through_match_motif(fleet: dict[str, object]) -> None:
    widths = dict(FEATURE_LAYOUT)
    allowed = set()
    for group in (
        "relation_onehot",
        "relation_family_onehot",
        "object_semantics",
        "state_delta_raised",
    ):
        allowed |= set(range(GROUP_OFFSETS[group], GROUP_OFFSETS[group] + widths[group]))
    checked = 0
    for host in fleet["hosts"]:  # type: ignore[union-attr]
        for incident in host["incidents"].values():
            for antibody in (forge_antibody(incident, benign=host["ring"]), copied_rule(incident)):
                if antibody is None:
                    continue
                steps = prototype_steps(antibody.invariant, source_group="grp-" + "a" * 16)
                motif = tuple(row.to_motif_step() for row in antibody.invariant)
                assert match_motif(motif, steps) and matches(antibody.invariant, steps)
                for row, step in zip(antibody.invariant, steps, strict=True):
                    assert step.object_property_mask == row.require_properties
                    assert step.state_delta_mask == row.require_raised and step.actor_slot == 0
                    assert all(v == 0.0 for i, v in enumerate(step.features) if i not in allowed)
                    assert (step.time_bucket, step.delta_phi, step.uncertainty, step.evidence) == (
                        0,
                        0.0,
                        0.0,
                        (),
                    )
                checked += 1
    assert checked >= 20
    with pytest.raises(ContractError):
        prototype_steps((MotifRow(99, 0, 0, 0),), source_group="grp-" + "a" * 16)
    with pytest.raises(ContractError):
        prototype_steps((MotifRow(1, 1 << 20, 0, 0),), source_group="grp-" + "a" * 16)


def test_mutations_are_deterministic_and_preserve_the_attack(fleet: dict[str, object]) -> None:
    host = fleet["hosts"][0]  # type: ignore[index]
    incident = host["incidents"]["exfil"]
    first = mutate_incident(incident, seed=5, benign=host["ring"])
    assert first == mutate_incident(incident, seed=5, benign=host["ring"])
    assert first != mutate_incident(incident, seed=6, benign=host["ring"])
    preserving, doppelgangers = first
    assert len(preserving) == len(doppelgangers) == forge.MUTATIONS_PER_INCIDENT
    copied = copied_rule(incident)
    assert copied is not None
    assert all(matches(copied.invariant, p) for p in preserving)
    assert not any(matches(copied.invariant, d) for d in doppelgangers)  # first/last always split
    single = _incident("single", (incident.steps[0],))
    assert mutate_incident(single, seed=0)[1] == ()  # nothing to split: no doppelganger


def test_local_stores_are_bounded_and_validated(fleet: dict[str, object]) -> None:
    ring = BenignRing(capacity=3)
    episode = fleet["hosts"][0]["ring"].episodes()[0]  # type: ignore[index]
    for _ in range(5):
        ring.add(episode)
    assert len(ring.episodes()) == 3 and ring.evictions() == 2 and ring.memory_bytes() > 0
    with pytest.raises(ContractError):
        ring.add(())
    with pytest.raises(ContractError):
        LocalIncident("x", episode, ("sha256:nothex",))
    with pytest.raises(ContractError):
        matches((), episode)
    with pytest.raises(ContractError):
        matches((MotifRow(1, 0, 0, 0),) * 3, episode)
    validator = LocalValidator(benign=ring, incidents=(), observable_relations=frozenset({2}))
    assert validator.validate((MotifRow(1, 0, 0, 0),)) is LocalValidation.NOT_OBSERVABLE
    meter = WorkMeter()
    lenient = LocalValidator(
        benign=ring, incidents=(), observable_relations=ALL_RELATIONS, fp_ceiling=5, meter=meter
    )
    assert lenient.validate((MotifRow(episode[0].relation, 0, 0, 0),)) is LocalValidation.PASS
    assert meter.spent > 0
    assert (
        LocalValidator(benign=ring, incidents=(), observable_relations=ALL_RELATIONS).validate(
            (MotifRow(episode[0].relation, 0, 0, 0),)
        )
        is LocalValidation.LOCAL_FP
    )
