"""Stage 7 review regressions: one test per confirmed finding, each named in its docstring.

Every test here FAILED on the code the review ran against and passes after the fix. Each is an
attack or a failure path, not a construction check, and each carries the positive control that
proves the defended path still works (lesson 1): a defence that also stopped honest knowledge
would pass an attack test for the wrong reason.

Helpers come from the two suites that already build ECHO engines and fabrics
(``test_stage7_echo`` and ``test_stage7_sovereignty``) so the regressions run on exactly the
objects the rest of the Stage 7 suite trusts.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import test_stage7_echo as et
import test_stage7_sovereignty as sv

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage6.capsule.experience_capsule import PrivacyClass
from pocketsec.stage7.antibody.forge import LocalValidation, LocalValidator
from pocketsec.stage7.capsule.knowledge_capsule import (
    EpochContext,
    FalsificationSummary,
    KnowledgeCapsuleV1,
    KnowledgeType,
    MotifRow,
    ProvenanceCommitment,
    RevocationGround,
    RoleClass,
    SourceContextSketch,
    Stance,
    ValidationSummary,
    VisibilityClass,
    motif_fingerprint,
    seal_capsule,
)
from pocketsec.stage7.echo import inference
from pocketsec.stage7.echo.inference import EchoConfig, EchoEngine, EchoStatus
from pocketsec.stage7.hivelock.ingress import VALIDATION_FLOOR, IngressOutcome, PooledCapsule
from pocketsec.stage7.identity.integrity import Keyring
from pocketsec.stage7.labs.fleet_corpus import FleetCorpus, build_fleet_corpus
from pocketsec.stage7.relevance.epistemic_distance import LocalContext
from pocketsec.stage7.relevance.gravity import knowledge_gravity

SETUID_THEN_SEND = et.SETUID_THEN_SEND
NO_PROBATION = et.NO_PROBATION


def _pooled(peer: int, *, rows: tuple[MotifRow, ...] = SETUID_THEN_SEND,
            stance: Stance = Stance.SUPPORT, created: int = 0,
            expiry: int | None = None) -> PooledCapsule:
    """``test_stage7_echo._pooled`` with a chosen creation and expiry round."""
    capsule = seal_capsule(
        knowledge_type=KnowledgeType.ANTIBODY, stance=stance, semantic_invariant=rows,
        attack_mappings=(), epoch_context=EpochContext(et.SE, VisibilityClass.FULL),
        source_context_sketch=SourceContextSketch(RoleClass.WEB, (0,) * 8),
        validation_summary=ValidationSummary(4, 1, 0),
        falsification_summary=FalsificationSummary(0, 0, ()),
        provenance_commitment=ProvenanceCommitment(
            et._peer(peer), et._root(peer), ("hc-" + "c" * 32,), None
        ),
        independence_group=et._root(peer), privacy_class=PrivacyClass.PUBLIC_DERIVED,
        created_round=created, expiry_round=created + 32 if expiry is None else expiry,
        sequence=1, parent_capsules=(), time_window=None, observability=None,
        revocation_target=None, revocation_ground=None, key_id=f"key-{peer:016x}",
    )
    return PooledCapsule(capsule=capsule, raw_digest="sha256:" + "a" * 64,
                         peer_id=et._peer(peer), cluster_id="cl-" + f"{peer:016x}",
                         relevance=1.0, gravity=0.5, received_round=created)


def _id(item: KnowledgeCapsuleV1) -> str:
    return KnowledgeCapsuleV1.from_bytes(sv.wire(item)).capsule_id


# === S7-R1: retraction before eligibility =======================================================


def test_retraction_before_eligibility_removes_the_contribution() -> None:
    """S7-R1. Every supporter self-retracts DURING probation: the key must never become
    ELIGIBLE and nothing reaches Stage 6. Before the fix ECHO kept the full mass (no decision
    node existed yet to mark SUSPECT) and bridged revoked evidence two rounds later."""
    host = sv.build_host()
    supports = [sv.capsule(n, sequence=1) for n in sv.FLEET[:12]]
    for item in supports:
        sv.send(host, item)
    host.fabric.run_round()
    assert sv.statuses(host)[sv.PASS_KEY] is EchoStatus.INSUFFICIENT  # on probation
    for n, item in zip(sv.FLEET[:12], supports, strict=True):
        retraction = sv.capsule(n, sequence=2, kind=KnowledgeType.REVOCATION, target=_id(item),
                                ground=RevocationGround.SELF_RETRACTION, created=1)
        assert sv.send(host, retraction).outcome is IngressOutcome.ROUTED_REVOCATION
    reports = [host.fabric.run_round() for _ in range(4)]
    assert sum(dict(r.revocations).get("accepted", 0) for r in reports) == 12
    assert sv.statuses(host)[sv.PASS_KEY] is EchoStatus.INSUFFICIENT
    assert host.fabric.bridged_keys() == () and host.bridge.created() == 0
    assert host.fabric.last_inference().contributions_excluded == 12  # type: ignore[union-attr]
    # Positive control: the same support, unretracted, is bridged (eligible_pass_host asserts it).
    assert sv.eligible_pass_host().fabric.bridged_keys() == (sv.PASS_KEY,)


def test_reinstated_contribution_counts_again() -> None:
    """S7-R1 (reversibility). Exclusion is read from lineage state every round, so undoing
    the revocation restores the contribution rather than losing it."""
    live = {"kc": True}
    engine = EchoEngine(local=_local(), validator=_validator(), trust=et.StubTrust(),
                        cluster_of=lambda p: "cl-" + p[-16:], config=NO_PROBATION,
                        contribution_live=lambda cid: live.get(cid, True))
    pooled = [_pooled(n) for n in range(2)]
    engine.offer(pooled)
    assert engine.infer(round_index=0).decisions[0].status is EchoStatus.ELIGIBLE
    live[pooled[0].capsule.capsule_id] = False
    assert engine.infer(round_index=1).decisions[0].status is EchoStatus.INSUFFICIENT
    live[pooled[0].capsule.capsule_id] = True
    assert engine.infer(round_index=2).decisions[0].status is EchoStatus.ELIGIBLE


def _local(local_keys: frozenset[str] = frozenset()) -> LocalContext:
    return LocalContext(role=RoleClass.WEB, software_epoch=et.SE, visibility=VisibilityClass.FULL,
                        family_profile=(0,) * 8, local_keys=local_keys,
                        observable_relations=et.ALL_RELATIONS)


def _validator() -> LocalValidator:
    from pocketsec.stage7.antibody.forge import BenignRing
    return LocalValidator(benign=BenignRing(), incidents=(), observable_relations=et.ALL_RELATIONS)


# === S7-R2 / R7-3: slot squatting ================================================================


def test_sybil_slot_squatters_cannot_lock_out_contests() -> None:
    """S7-R2 / R7-3. 80 supporting identities over 5 clusters fill every contribution slot
    first; 12 honest contests from 12 independent clusters must still be weighed. Before the
    fix all 12 contests were refused at offer() and the key went ELIGIBLE uncontested."""
    clusters = {et._peer(n): f"cl-squat{n % 5}" for n in range(80)}
    engine = et._engine(clusters=clusters)
    engine.offer([et._pooled(SETUID_THEN_SEND, n) for n in range(80)])
    accepted = engine.offer([et._pooled(SETUID_THEN_SEND, 500 + n, stance=Stance.CONTEST)
                             for n in range(12)])
    assert accepted == 12
    decision = et._decide(engine)
    assert decision.contest_clusters == 12 and decision.support_clusters == 5
    assert decision.status is EchoStatus.INSUFFICIENT and decision.reasons == ("contested",)
    assert engine.bound_counters()["contributions_evicted"] == 12
    # The squatting bought nothing: the support mass equals 5 lone identities'.
    lone = et._engine()
    lone.offer([et._pooled(SETUID_THEN_SEND, n) for n in range(5)])
    assert decision.support_mass == pytest.approx(et._decide(lone).support_mass)
    # Control: independent identities are never evicted to make room (all groups of 1).
    fair = et._engine()
    cap = inference.MAX_CONTRIBUTIONS_PER_KEY
    fair.offer([et._pooled(SETUID_THEN_SEND, n) for n in range(cap)])
    assert fair.offer([et._pooled(SETUID_THEN_SEND, 900, stance=Stance.CONTEST)]) == 0
    assert fair.bound_counters()["contributions_evicted"] == 0


# === S7-R3: relay farming =========================================================================


def test_relaying_the_hosts_own_knowledge_farms_no_trust() -> None:
    """S7-R3. Peers relay back an antibody the host already holds (local_origin): it is
    LOCAL_CONFIRMED here, yet it must confirm nobody. Before the fix each relaying cluster
    gained a trust confirmation for free."""
    validator, _ = sv._local_validator()
    assert validator.validate(sv.LOCAL_ROWS) is LocalValidation.LOCAL_CONFIRMED
    for local_keys, expected_calls in ((frozenset({sv.LOCAL_KEY}), 0), (frozenset(), 2)):
        trust = et.StubTrust()
        engine = EchoEngine(local=_local(local_keys), validator=validator, trust=trust,
                            cluster_of=lambda p: "cl-" + p[-16:], config=NO_PROBATION)
        engine.offer([_pooled(n, rows=sv.LOCAL_ROWS) for n in range(2)])
        decision = engine.infer(round_index=0).decisions[0]
        assert "local_confirmed" in decision.reasons
        assert len(trust.calls) == expected_calls  # 2 = control: foreign knowledge confirmed
        if local_keys:
            assert decision.status is EchoStatus.REFUSED


# === S7-R4 / S7-AUTH-08: sovereignty over knowledge published after start-up ======================


def test_an_antibody_published_after_startup_is_sovereign() -> None:
    """S7-R4 / S7-AUTH-08. PASS_KEY is not in LocalContext.local_keys; the host publishes it
    after construction. A foreign CONTEST on it must be refused local_sovereignty and foreign
    SUPPORT must be REFUSED local_origin, never bridged back as foreign knowledge."""
    host = sv.build_host()
    assert sv.PASS_KEY not in host.components.local.local_keys
    assert len(host.fabric.publish([sv.capsule(sv.LOCAL_HOST, sequence=1)])) == 1
    contest = sv.send(host, sv.capsule(5, sequence=2, stance=Stance.CONTEST))
    assert contest.outcome is IngressOutcome.REFUSED
    assert any("local_sovereignty" in r for r in contest.reasons)
    for n in sv.FLEET[:12]:
        sv.send(host, sv.capsule(n, sequence=1))
    for _ in range(4):
        host.fabric.run_round()
    assert sv.statuses(host)[sv.PASS_KEY] is EchoStatus.REFUSED
    assert host.fabric.bridged_keys() == () and host.bridge.created() == 0


# === S7-AUTH-01 / R7-1: expiry ====================================================================


def test_expired_contributions_stop_counting_and_close_the_key() -> None:
    """S7-AUTH-01 / R7-1. Two unclustered identities 500 rounds apart (never co-timed): the
    first capsule expired at round 32 and must not add to the second. Before the fix the key
    went ELIGIBLE at round 502 citing a capsule 470 rounds past its expiry."""
    engine = et._engine(config=EchoConfig())
    engine.offer([_pooled(1, created=0)])
    engine.infer(round_index=0)
    engine.offer([_pooled(2, created=500)])
    for round_index in (500, 501, 502, 503):
        decision = engine.infer(round_index=round_index).decisions[0]
        assert decision.status is EchoStatus.INSUFFICIENT
        assert decision.support_clusters == 1
    result = engine.infer(round_index=532)  # the second capsule expires too
    assert result.decisions == () and result.keys_tracked == 0 and result.keys_expired == 1
    # Control: the same pair, both alive, is ELIGIBLE after probation.
    alive = et._engine(config=EchoConfig())
    alive.offer([_pooled(1, created=500), _pooled(2, created=500)])
    assert [alive.infer(round_index=r).decisions[0].status for r in (500, 501, 502)][-1] \
        is EchoStatus.ELIGIBLE


def test_revoked_signing_keys_stop_counting_in_echo() -> None:
    """R7-1. Keys revoked while their antibody sits in probation: ECHO must not reach
    ELIGIBLE on the revoked keys' pre-revocation contributions, and nothing is bridged."""
    host = sv.build_host()
    for n in sv.FLEET[:12]:
        sv.send(host, sv.capsule(n, sequence=1))
    host.fabric.run_round()
    for n in sv.FLEET[:12]:
        host.components.keyring.revoke(sv.key_id(n), round_index=1)
    host.fabric.repin_keyring()  # the deliberate local act after an authorised key change
    for _ in range(4):
        host.fabric.run_round()
    assert sv.statuses(host)[sv.PASS_KEY] is EchoStatus.INSUFFICIENT
    assert host.bridge.created() == 0


# === S7-AUTH-02 / R7-3: distinct-key flood ========================================================


def _junk_rows(i: int) -> tuple[MotifRow, ...]:
    return (MotifRow(i % 20, (i // 20) % 64, 0, 0), MotifRow(10, 128, 0, (i // 1280) % 2))


def test_one_key_holder_cannot_own_the_key_table() -> None:
    """S7-AUTH-02 / R7-3. One peer streams 1034 distinct keys, then 20 honest peers offer a
    new antibody: it must be tracked and decided. Before the fix the flood filled all 1024
    slots forever and every honest key was refused."""
    engine = et._engine()
    flood = [_pooled(999, rows=_junk_rows(i), expiry=64) for i in range(1034)]
    engine.offer(flood)
    counters = engine.bound_counters()
    assert counters["keys_quota_refused"] == 1034 - inference.MAX_KEYS_PER_OPENER
    assert engine.offer([_pooled(n, expiry=64) for n in range(20)]) == 20
    keys = {d.antibody_key for d in engine.infer(round_index=10).decisions}
    assert motif_fingerprint(SETUID_THEN_SEND) in keys
    # And the flood is not permanent: its capsules expire and the table empties.
    assert engine.infer(round_index=64).keys_tracked == 0


# === R7-2: one decision node per evidence change, not per round ===================================


def test_an_unchanged_eligible_key_is_one_lineage_node() -> None:
    """R7-2. An ELIGIBLE key held for 40 rounds must not add a lineage node per round, and a
    later local revocation of a supporting capsule must still name the Stage 6 capsules the
    bridge admitted. Before the fix every round appended a new ECHO_DECISION."""
    host = sv.eligible_pass_host()
    lineage = host.components.lineage
    size = len(lineage)
    for _ in range(40):
        host.fabric.run_round()
    assert sv.statuses(host)[sv.PASS_KEY] is EchoStatus.ELIGIBLE
    assert len(lineage) == size
    supported = _id(sv.capsule(sv.FLEET[0], sequence=1))
    revocation = host.fabric.revocations.revoke_locally(supported, round_index=41)
    admitted = {cid for r in host.bridge.receipts() for cid in r.stage6_capsule_ids}
    assert revocation.accepted and not revocation.affected_truncated
    assert admitted and set(revocation.stage6_capsule_ids) == admitted


# === R7-4: the keyring reclaims dead records ======================================================


def test_keyring_reclaims_dead_records_but_never_reuses_an_id() -> None:
    """R7-4. A full ring could never rotate or replace a key again, because REVOKED and
    expired-ROTATED records counted against the cap forever."""
    ring = Keyring(capacity=4)
    ring.register(sv.key_id(0), sv.key_bytes(0), owner=sv.peer_id(0), round_index=0)
    for i in range(1, 6):  # five rotations, each after the previous grace has passed
        ring.rotate(sv.key_id(i - 1), sv.key_id(i), sv.key_bytes(i), round_index=i * 20)
    ring.revoke(sv.key_id(5), round_index=200)
    ring.register(sv.key_id(6), sv.key_bytes(6), owner=sv.peer_id(0), round_index=200)
    assert len(ring) <= 4 and ring.reclaimed() >= 3
    with pytest.raises(ContractError):  # no resurrection of a reclaimed id
        ring.register(sv.key_id(0), sv.key_bytes(0), owner=sv.peer_id(0), round_index=201)
    signer = Keyring()
    signer.register(sv.key_id(0), sv.key_bytes(0), owner=sv.peer_id(0), round_index=0)
    old = sv.capsule(0, sequence=1)
    signed = signer.sign(old, key_id=old.key_id)
    assert signer.verify(signed, round_index=1).valid
    assert ring.verify(signed, round_index=201).reason == "unknown_key"  # reclaimed: refused
    # A ring of LIVE keys still refuses: nothing live is ever evicted.
    live = Keyring(capacity=2)
    for i in range(2):
        live.register(sv.key_id(i), sv.key_bytes(i), owner=sv.peer_id(i), round_index=0)
    with pytest.raises(ContractError):
        live.register(sv.key_id(9), sv.key_bytes(9), owner=sv.peer_id(9), round_index=0)


# === R7-5: gravity does not count dependence twice ================================================


def test_a_merged_honest_cluster_still_reaches_echo() -> None:
    """R7-5. 24 peers declaring one root are merged into one cluster. Gravity used to divide
    by the cluster size, pushing every capsule below VALIDATION_FLOOR to METADATA_ONLY, so
    the cluster lost even the one capped term ECHO promises it."""
    host = sv.build_host()
    peers = sv.FLEET[:24]
    verdicts = [host.fabric.deliver(sv.wire(_shared_root_capsule(n)), sender=sv.peer_id(n))
                for n in peers]
    graph = host.components.graph
    assert len({graph.cluster_of(sv.peer_id(n)) for n in peers}) == 1
    assert [v.outcome for v in verdicts[-4:]] == [IngressOutcome.POOLED] * 4
    assert IngressOutcome.METADATA_ONLY not in {v.outcome for v in verdicts}
    # The pre-fix wiring (independence = 1 / 24) would have dropped the same capsule.
    item = _shared_root_capsule(peers[-1])
    old = knowledge_gravity(item, distance=host.fabric._distance(item), independence=1 / 24,
                            suspicion=0.0, local=host.components.local, round_index=0)
    assert old.value < VALIDATION_FLOOR
    # And the switch ADR-0069 needs exists as configuration.
    off = sv.build_host()
    assert off.components.gravity_enabled is True and off.fabric.ingress._gravity_enabled is True


def _shared_root_capsule(n: int) -> KnowledgeCapsuleV1:
    base = sv.capsule(n, sequence=1)
    return seal_capsule(
        knowledge_type=base.knowledge_type, stance=base.stance,
        semantic_invariant=base.semantic_invariant, attack_mappings=(),
        epoch_context=base.epoch_context, source_context_sketch=base.source_context_sketch,
        validation_summary=base.validation_summary,
        falsification_summary=base.falsification_summary,
        provenance_commitment=ProvenanceCommitment(
            contributor=sv.peer_id(n), provenance_root=sv.root_id(1),
            evidence_commitments=base.provenance_commitment.evidence_commitments,
            aggregation_decision=None,
        ),
        independence_group=sv.root_id(1), privacy_class=PrivacyClass.PUBLIC_DERIVED,
        created_round=0, expiry_round=48, sequence=1, parent_capsules=(), time_window=None,
        observability=None, revocation_target=None, revocation_ground=None, key_id=sv.key_id(n),
    )


# === lab and gate measurements ====================================================================


@pytest.fixture(scope="module")
def small_corpus() -> FleetCorpus:
    return build_fleet_corpus(hosts=8, episodes_per_host=16, seed=7)


def test_offline_equivalence_sees_a_fabric_that_damages_the_validator(
    small_corpus: FleetCorpus, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F2. A fabric that wipes the host's LocalValidator after every round must make G7.3's
    digests differ. Before the fix the digest read only the benign ring, so this sabotage
    still reported identical=True (and G7.3 PASS)."""
    from pocketsec.stage7.labs import partition
    from pocketsec.stage7.labs.simulated_fleet import default_receivers
    from pocketsec.stage7.orpheus.fabric import OrpheusFabric

    receiver = default_receivers(small_corpus)[1]
    honest = partition.run_offline_equivalence(small_corpus, receiver=receiver, rounds=3,
                                               flood_identities=4)
    assert honest.identical  # control: an honest fabric leaves every digest equal
    original = OrpheusFabric.run_round

    def sabotaged(self):  # type: ignore[no-untyped-def]
        report = original(self)
        validator = self._c.validator
        validator._incidents, validator._observable, validator._ceiling = (), frozenset(), 10**9
        return report

    monkeypatch.setattr(OrpheusFabric, "run_round", sabotaged)
    damaged = partition.run_offline_equivalence(small_corpus, receiver=receiver, rounds=3,
                                                flood_identities=4)
    assert not damaged.identical
    assert damaged.digest_absent == honest.digest_absent != damaged.digest_offline


def test_threshold_sensitivity_sees_a_moved_handoff_round(small_corpus: FleetCorpus) -> None:
    """S7-R7. ECHO_PROBATION_ROUNDS changes WHEN a key first becomes ELIGIBLE (the one round
    the fabric bridges it) and whether latent poison ever does. The old flip metric compared
    only the last status and reported 0; the trace metric must see the change."""
    from dataclasses import replace

    from pocketsec.stage7.labs import byzantine_suite as bs
    from pocketsec.stage7.labs.partition import replay_with, simulate
    from pocketsec.stage7.labs.simulated_fleet import AdversaryArm, default_receivers

    spec = bs._spec_for(AdversaryArm.BYZANTINE_LATENT_POISON, 0.2, 12, 0,
                        tuple(default_receivers(small_corpus)[:2]))
    run = simulate(small_corpus, spec)
    other = replay_with(run, config=replace(EchoConfig(), probation_rounds=1))
    assert bs._flip_share(bs._statuses(run), bs._statuses(other)) == 0.0  # what it used to see
    assert bs._flip_share(bs._decision_trace(run), bs._decision_trace(other)) > 0.0


def test_property_inference_is_exhaustive_with_its_own_chance(small_corpus: FleetCorpus) -> None:
    """F8. Every host is predicted exactly once (n = hosts with a vector, not 200 resamples),
    each representation carries its own chance, and the result does not depend on the seed."""
    from pocketsec.stage7.labs import privacy_attacks

    for representation in privacy_attacks.REPRESENTATIONS:
        runs = [privacy_attacks.property_inference(small_corpus, representation=representation,
                                                   trials=200, seed=s) for s in (0, 1, 2)]
        assert len({(m.trials, m.advantage, m.chance) for m in runs}) == 1
        m = runs[0]
        assert 0 < m.trials <= len(small_corpus.hosts)  # hosts, not resamples
        accuracy = m.advantage + m.chance  # type: ignore[operator]
        assert accuracy * m.trials == pytest.approx(round(accuracy * m.trials))


def test_collective_novelty_is_inert_on_the_fabric_path(small_corpus: FleetCorpus) -> None:
    """F4. Honest fabric traffic carries no NOVELTY capsule, so collective novelty (and the DP
    release that serves it) fire 0 times on the fabric path, whatever the toy probe shows."""
    from pocketsec.stage7.labs import privacy_attacks
    from pocketsec.stage7.labs.byzantine_suite import ablation_row
    from pocketsec.stage7.labs.partition import simulate
    from pocketsec.stage7.labs.simulated_fleet import AdversaryArm, FleetSpec, default_receivers

    run = simulate(small_corpus, FleetSpec(arm=AdversaryArm.NONE, rounds=6,
                                           receivers=tuple(default_receivers(small_corpus)[:2])))
    fabric = privacy_attacks.fabric_novelty_firing(run.receivers.values())
    assert fabric == 0
    metric, full, control, toy_firing, lower = privacy_attacks.novelty_ablation(small_corpus)
    assert toy_firing > 0  # the toy fires; the fleet does not
    row = ablation_row("ORPH-F12", "collective_novelty", "local novelty only", metric, full,
                       control, fabric, lower_is_better=lower)
    assert row.verdict == "INERT"


# === the AST boundary: dynamic imports and a shadowed ReplayGuard =================================


_DYNAMIC_LEAKS = (
    "import importlib\ndef f(n):\n    return importlib.import_module('pocketsec.stage' + n)\n",
    "def f():\n    return __import__('pocketsec.stage5.executor')\n",
    "def f(src):\n    exec(src)\n",
    "def f(src):\n    return eval(src)\n",
    "from importlib import import_module\ndef f():\n    return import_module('x')\n",
    "import pickle\n",
)


@pytest.mark.parametrize("source", _DYNAMIC_LEAKS)
def test_rule_12_catches_dynamic_imports_and_code_execution(source: str, tmp_path: Path) -> None:
    """S7-AUTH-03 / F1. Every one of these reaches a module the static import rules cannot
    see; before rule 12 all of them passed rules 3, 5, 6 and 8 in a runtime module."""
    from pocketsec.stage7.gate_boundary import dynamic_code, imports_stage5, targets

    package = tmp_path / "pocketsec" / "stage7" / "echo"
    package.mkdir(parents=True)
    path = package / "leak.py"
    path.write_text(source, encoding="utf-8")
    assert not any(imports_stage5(t) for t in targets(path))  # invisible to rule 3
    assert dynamic_code(path)


def test_rule_12_holds_on_the_real_tree_and_exempts_only_declared_sites(tmp_path: Path) -> None:
    """S7-AUTH-03. The real tree has 0 offenders; the same call in an undeclared function of
    an exempted file is still caught, and ``re.compile`` is not a code-execution call."""
    from pocketsec.stage7.gate_boundary import dynamic_code, rule_offenders

    assert rule_offenders(12) == ()
    package = tmp_path / "pocketsec" / "stage7"
    package.mkdir(parents=True)
    path = package / "core_ids.py"
    path.write_text("import importlib, re\nP = re.compile('x')\n"
                    "def _import_problem(m):\n    return importlib.import_module(m)\n"
                    "def other(m):\n    return importlib.import_module(m)\n", encoding="utf-8")
    assert [line for _, line in dynamic_code(path)] == [6]


def test_a_shadowed_replay_guard_exempts_no_admit_call(tmp_path: Path) -> None:
    """F1. A local function NAMED ReplayGuard returning the quarantine gateway used to make
    ``guard.admit(...)`` look like a fresh replay guard (a static second door into Stage 6)."""
    from pocketsec.stage7.gate_boundary import admit_calls

    package = tmp_path / "pocketsec" / "stage7" / "echo"
    package.mkdir(parents=True)
    shadow = package / "leak.py"
    shadow.write_text("def ReplayGuard():\n    return GATEWAY\n"
                      "def f(c):\n    guard = ReplayGuard()\n    return guard.admit(c)\n",
                      encoding="utf-8")
    alias = package / "alias.py"
    alias.write_text("from x import Gateway as ReplayGuard\n"
                     "def f(c):\n    guard = ReplayGuard()\n    return guard.admit(c)\n",
                     encoding="utf-8")
    genuine = package / "genuine.py"
    genuine.write_text("from pocketsec.stage7.identity.integrity import ReplayGuard\n"
                       "def f(c):\n    guard = ReplayGuard()\n    return guard.admit(c)\n",
                       encoding="utf-8")
    assert admit_calls(shadow) and admit_calls(alias)
    assert admit_calls(genuine) == []  # control: the real guard is still exempt


# === R7-4 (consequence): churn now measures a LIVE receiver =======================================


def test_churn_keyring_no_longer_refuses_and_the_plateau_rule_still_sees_a_leak(
    small_corpus: FleetCorpus,
) -> None:
    """R7-4. Under churn the keyring used to fill for good, refuse every newcomer and so
    'plateau' by refusing. With dead keys reclaimed it refuses none. The plateau rule had to
    tolerate a live store's fluctuation; it must still flag a store that keeps growing."""
    from pocketsec.stage7.labs import partition

    report = partition.run_churn_endurance(small_corpus, rounds=45, churn_share=0.5,
                                           peer_capacity=24, publish_p=0.5)
    assert dict(report.evictions)["keyring_refused"] == 0
    assert report.peers_seen > 24
    leak = [{"s": r} for r in range(45)]  # +1 per round: a leak
    flat = [{"s": 10 + (r * 7) % 5} for r in range(45)]  # bounded and fluctuating
    assert partition.unplateaued(leak, ["s"], rounds=45)
    assert partition.unplateaued(flat, ["s"], rounds=45) == ()
