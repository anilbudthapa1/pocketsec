"""Stage 7 package ``adversary``: the simulated fleet, the Byzantine suite, privacy attacks,
partition/churn/scale labs and the 72-experiment catalogue.

A defence never attacked in a test is a docstring, so these tests attack: every adversary arm
must actually put its attack on the wire, the identity-counting baselines must actually be
bought by Sybils (or the Sybil arm is not real), the raw-steps privacy control must actually
leak (or the attack is not real), and every bound must actually be hit. Configurations are
tiny (8 hosts, <= 4 rounds); the full sweep belongs to the gate and the CLI.
"""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import replace
from pathlib import Path

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage7.aggregation.robust import Aggregator, stance_matrix
from pocketsec.stage7.echo.inference import EchoConfig, EchoStatus
from pocketsec.stage7.labs import byzantine_suite as suite
from pocketsec.stage7.labs import partition, privacy_attacks
from pocketsec.stage7.labs import seventy_two_experiments as catalogue
from pocketsec.stage7.labs.fleet_corpus import FleetCorpus, Precondition, build_fleet_corpus
from pocketsec.stage7.labs.simulated_fleet import (
    AdversaryArm,
    FleetSpec,
    SimulatedFleet,
    adversary_root_count,
    default_receivers,
)

ROOT = Path(__file__).resolve().parents[1]
LABS = ROOT / "pocketsec" / "stage7" / "labs"
REGISTRY = ROOT / "experiments" / "registry.jsonl"


@pytest.fixture(scope="module")
def corpus() -> FleetCorpus:
    return build_fleet_corpus(hosts=8, episodes_per_host=16, seed=7)


@pytest.fixture(scope="module")
def pair(corpus: FleetCorpus) -> tuple[str, ...]:
    """The late-benign ADMIN host (latent-poison target) and a WEB host."""
    return default_receivers(corpus)[:2]


def _traffic(corpus: FleetCorpus, spec: FleetSpec) -> list:
    fleet = SimulatedFleet(corpus, spec)
    return [d for r in range(spec.rounds) for d in fleet.round_traffic(r, visible_keys={})]


# --- the simulated fleet -------------------------------------------------------------------------

_POISON_ARMS = {
    AdversaryArm.SYBIL_DECLARED_ROOT, AdversaryArm.SYBIL_FORGED_ROOTS, AdversaryArm.SYBIL_ADAPTIVE,
    AdversaryArm.BYZANTINE_POISON, AdversaryArm.BYZANTINE_LATENT_POISON, AdversaryArm.SLOW_POISON,
    AdversaryArm.COLLUSION_TIMING, AdversaryArm.FLOOD, AdversaryArm.UNANIMOUS_FLEET,
}


@pytest.mark.parametrize("arm", [a for a in AdversaryArm if a is not AdversaryArm.NONE])
def test_each_arm_fires(corpus: FleetCorpus, pair: tuple[str, ...], arm: AdversaryArm) -> None:
    """Every arm puts its attack on the wire; the poison arms actually offer poison."""
    rounds = 8 if arm is AdversaryArm.SLOW_POISON else 3  # slow poison turns after its warm-up
    spec = FleetSpec(arm=arm, adversary_share=0.2, sybils_per_root=4, rounds=rounds,
                     receivers=pair)
    deliveries = _traffic(corpus, spec)
    adversarial = [d for d in deliveries if d.adversarial]
    assert adversarial, f"{arm} offered nothing adversarial"
    if arm in _POISON_ARMS:
        assert any(d.poison_key for d in adversarial), f"{arm} never offered its poison"
    assert all(len(d.data) > 0 and d.receiver in pair for d in deliveries)


def test_the_arm_none_is_honest_only(corpus: FleetCorpus, pair: tuple[str, ...]) -> None:
    deliveries = _traffic(corpus, FleetSpec(arm=AdversaryArm.NONE, rounds=3, receivers=pair))
    assert deliveries and not any(d.adversarial or d.poison_key for d in deliveries)


def test_fleet_spec_rejects_invalid_input() -> None:
    for bad in ({"adversary_share": 1.0}, {"adversary_share": -0.1}, {"rounds": 0},
                {"sybils_per_root": 0}, {"seed": -1}, {"adversary_share": True}):
        with pytest.raises(ContractError):
            FleetSpec(arm=AdversaryArm.NONE, **bad)  # type: ignore[arg-type]
    with pytest.raises(ContractError):
        FleetSpec(arm="NONE")  # type: ignore[arg-type]


def test_fleet_refuses_unknown_receivers(corpus: FleetCorpus) -> None:
    with pytest.raises(ContractError):
        SimulatedFleet(corpus, FleetSpec(arm=AdversaryArm.NONE, receivers=("h999",)))


def test_adversary_root_share_is_the_requested_share() -> None:
    assert adversary_root_count(16, 0.0) == 0
    for share in (0.1, 0.2, 0.5):
        roots = adversary_root_count(16, share)
        assert abs(roots / (roots + 16) - share) <= 0.05


def test_honest_traffic_is_deterministic_per_seed(corpus: FleetCorpus,
                                                  pair: tuple[str, ...]) -> None:
    """The cross-run cache must not change a single byte; a different seed must."""
    spec = FleetSpec(arm=AdversaryArm.NONE, rounds=2, receivers=pair)
    first = [d.data for d in _traffic(corpus, spec)]
    again = [d.data for d in _traffic(corpus, spec)]
    other = [d.data for d in _traffic(corpus, replace(spec, seed=1))]
    assert first == again and first != other


def test_sybil_identities_share_one_true_root(corpus: FleetCorpus, pair: tuple[str, ...]) -> None:
    for arm in (AdversaryArm.SYBIL_DECLARED_ROOT, AdversaryArm.SYBIL_FORGED_ROOTS):
        fleet = SimulatedFleet(corpus, FleetSpec(arm=arm, sybils_per_root=6, receivers=pair))
        truth = fleet.ground_truth()
        assert len(truth.adversary_peers) == 6 and truth.adversary_roots == 1
        assert len({truth.true_root_of[p] for p in truth.adversary_peers}) == 1


# --- the suite: identical pools, the Sybil attack is real, the cap bounds ECHO -------------------


@pytest.fixture(scope="module")
def latent_run(corpus: FleetCorpus, pair: tuple[str, ...]) -> partition.SuiteRun:
    spec = FleetSpec(arm=AdversaryArm.BYZANTINE_LATENT_POISON, adversary_share=0.3, rounds=3,
                     receivers=pair)
    return partition.simulate(corpus, spec)


def test_all_aggregators_see_identical_pools(latent_run: partition.SuiteRun) -> None:
    """Every aggregator is scored on the very pool the fabric pooled (lesson 4)."""
    rows = suite.evaluate_run(latent_run)
    assert {r.aggregator for r in rows} == {a.value for a in Aggregator}
    assert len({(r.poison_offered, r.true_offered) for r in rows}) == 1
    assert rows[0].poison_offered > 0 and rows[0].true_offered > 0
    replayed = partition.replay_with(latent_run, config=EchoConfig(contest_mass=False))
    for host, receiver in latent_run.receivers.items():
        pooled = [p.capsule.capsule_id for p in receiver.pooled]
        assert pooled == [p.capsule.capsule_id for p in replayed.receivers[host].pooled]
        matrix = stance_matrix([p for p in receiver.pooled
                                if p.capsule.knowledge_type.value == "ANTIBODY"])
        assert set(matrix.identities) <= {p.peer_id for p in receiver.pooled}


def test_local_validation_blindness_is_real_for_latent_poison(
        latent_run: partition.SuiteRun) -> None:
    """VALIDATION_FILTER accepts the latent poison (local replay is blind by construction):
    the arm tests aggregation, not local validation."""
    rows = {(r.aggregator, r.lv): r for r in suite.evaluate_run(latent_run)}
    assert rows[("VALIDATION_FILTER", False)].poison_accepted > 0
    echo, vf = rows[("ECHO", False)], rows[("VALIDATION_FILTER", False)]
    assert echo.poison_accepted <= vf.poison_accepted


def _sybil_run(corpus: FleetCorpus, pair: tuple[str, ...], sybils: int) -> partition.SuiteRun:
    spec = FleetSpec(arm=AdversaryArm.SYBIL_DECLARED_ROOT, sybils_per_root=sybils, rounds=3,
                     receivers=pair)
    return partition.simulate(corpus, spec)


def _poison_support(run: partition.SuiteRun) -> float:
    """The highest ECHO support mass any poison key reached at any receiver and round."""
    return max((d.support_mass for r in run.receivers.values() for inf in r.inferences
                for d in inf.decisions if d.antibody_key in run.truth.poison_keys), default=0.0)


def test_majority_amplification_grows_with_sybils(corpus: FleetCorpus,
                                                  pair: tuple[str, ...]) -> None:
    """The attack is real: an identity-counting vote is bought by minting identities."""
    one, many = _sybil_run(corpus, pair, 1), _sybil_run(corpus, pair, 8)
    small = {r.aggregator: r for r in suite.evaluate_run(one) if not r.lv}
    large = {r.aggregator: r for r in suite.evaluate_run(many) if not r.lv}
    assert large["MAJORITY"].poison_accepted > small["MAJORITY"].poison_accepted
    assert large["MAJORITY"].amplification is not None
    assert large["MAJORITY"].amplification > 1.5
    assert large["MAJORITY"].amplification > (small["MAJORITY"].amplification or 0.0)


def test_declared_root_sybil_amplification_is_bounded_for_echo(corpus: FleetCorpus,
                                                               pair: tuple[str, ...]) -> None:
    """Identity count inside one declared root never raises ECHO's mass (the per-cluster cap);
    this would fail if the cap or the SAME_ROOT merge were silently weakened."""
    one, many = _sybil_run(corpus, pair, 1), _sybil_run(corpus, pair, 8)
    assert _poison_support(many) <= _poison_support(one) + 1e-9
    echo = next(r for r in suite.evaluate_run(many) if r.aggregator == "ECHO")
    assert echo.poison_accepted == 0
    assert echo.amplification is None or echo.amplification <= 1.05
    control = partition.replay_with(many, config=EchoConfig(cluster_cap=False,
                                                            dependence_clustering=False))
    assert _poison_support(control) >= _poison_support(many)


def test_break_point_definition() -> None:
    def row(share: float, offered: int, accepted: int, method: str = "MEDIAN") -> suite.SuiteRow:
        return suite.SuiteRow("BYZANTINE_POISON", method, False, share, 1, offered, accepted,
                              0, 0, None, None, None, None, 0)
    rows = [row(0.0, 4, 0), row(0.1, 4, 1), row(0.2, 4, 2), row(0.3, 4, 4),
            row(0.1, 0, 0, "ECHO"), row(0.2, 4, 1, "ECHO")]
    points = {p.aggregator: p.share for p in suite.break_points(rows)}
    assert points["MEDIAN"] == 0.2  # the SMALLEST share at acceptance >= BREAK_LEVEL
    assert points["ECHO"] is None  # never broken in the sweep; no poison offered is not broken
    assert suite.break_points(list(reversed(rows))) == suite.break_points(rows)


def test_zero_firing_is_reported_inert() -> None:
    inert = suite.ablation_row("ORPH-F09", "x", "off", "m", 0.9, 0.1, 0, lower_is_better=True)
    assert inert.verdict == "INERT" and inert.delta == pytest.approx(0.8)
    good = suite.ablation_row("ORPH-F09", "x", "off", "m", 0.1, 0.9, 3, lower_is_better=True)
    bad = suite.ablation_row("ORPH-F09", "x", "off", "m", 0.9, 0.1, 3, lower_is_better=True)
    flat = suite.ablation_row("ORPH-F09", "x", "off", "m", 0.5, 0.52, 3, lower_is_better=True)
    unknown = suite.ablation_row("ORPH-F09", "x", "off", "m", None, 0.5, 3, lower_is_better=True)
    verdicts = (good.verdict, bad.verdict, flat.verdict)
    assert verdicts == ("JUSTIFIED", "HARMFUL", "NOT_YET_JUSTIFIED")
    assert unknown.delta is None and unknown.verdict == "NOT_YET_JUSTIFIED"


def test_suite_refuses_a_blocked_precondition(corpus: FleetCorpus,
                                              monkeypatch: pytest.MonkeyPatch) -> None:
    blocked = (Precondition("P3", "BLOCKED", "representation cannot express the task"),)
    monkeypatch.setattr(suite, "fleet_preconditions", lambda _c: blocked)
    with pytest.raises(ContractError, match="BLOCKED"):
        suite.run_byzantine_suite(corpus, arms=(AdversaryArm.NONE,), ablations=False,
                                  sensitivity=False)


def test_suite_never_writes_the_registry(corpus: FleetCorpus, pair: tuple[str, ...]) -> None:
    before = hashlib.sha256(REGISTRY.read_bytes()).hexdigest() if REGISTRY.exists() else None
    report = suite.run_byzantine_suite(
        corpus, arms=(AdversaryArm.NONE, AdversaryArm.BYZANTINE_POISON), shares=(0.2,),
        rounds=2, receivers=pair, with_stage6=True, ablations=False, sensitivity=False)
    after = hashlib.sha256(REGISTRY.read_bytes()).hexdigest() if REGISTRY.exists() else None
    assert before == after
    assert report.synthetic is True and len(report.loadavg) == 3 and report.rows
    for path in LABS.glob("*.py"):  # no lab can even name the registry writer
        names = {n.id for n in ast.walk(ast.parse(path.read_text())) if isinstance(n, ast.Name)}
        assert "ExperimentRegistry" not in names, path.name


def test_unanimous_fleet_changes_no_local_decision(corpus: FleetCorpus,
                                                   pair: tuple[str, ...]) -> None:
    """The whole fleet (64 independent roots) agrees against each host; nothing local moves."""
    run = partition.simulate(corpus, FleetSpec(arm=AdversaryArm.UNANIMOUS_FLEET, rounds=3,
                                               receivers=pair), with_stage6=True)
    assert run.offered["adversarial:REFUSED:SCHEMA"] > 0  # the authority payloads
    for host, receiver in run.receivers.items():
        local = receiver.components.local.local_keys
        statuses = {d.antibody_key: d.status for inf in receiver.inferences for d in inf.decisions}
        assert all(statuses.get(k, EchoStatus.REFUSED) is EchoStatus.REFUSED for k in local)
        assert not any(statuses.get(k) is EchoStatus.ELIGIBLE for k in run.truth.poison_keys)
        assert receiver.components.bridge is not None
        assert receiver.components.bridge.created() == receiver.components.bridge.admitted() == 0
        assert not (set(receiver.fabric.bridged_keys()) & (local | run.truth.poison_keys)), host


@pytest.mark.parametrize("arm, stage", [
    (AdversaryArm.AUTHORITY_INJECTION, "SCHEMA"), (AdversaryArm.LINEAGE_TAMPER, "PROVENANCE"),
    (AdversaryArm.REPLAY, None), (AdversaryArm.FLOOD, "SIZE_RATE"),
])
def test_protocol_attacks_are_refused(corpus: FleetCorpus, pair: tuple[str, ...],
                                      arm: AdversaryArm, stage: str | None) -> None:
    run = partition.simulate(corpus, FleetSpec(arm=arm, sybils_per_root=4, rounds=3,
                                               receivers=pair))
    adversarial = {k: n for k, n in run.offered.items() if k.startswith("adversarial:")}
    assert sum(adversarial.values()) > 0
    if arm is not AdversaryArm.FLOOD:  # a flood's first copy of each capsule is well-formed
        assert not any(":POOLED:" in k for k in adversarial), adversarial
    if stage is not None:
        assert any(k.endswith(f":{stage}") and ":REFUSED:" in k for k in adversarial), adversarial


def test_false_revocations_change_no_state(corpus: FleetCorpus, pair: tuple[str, ...]) -> None:
    run = partition.simulate(corpus, FleetSpec(arm=AdversaryArm.FALSE_REVOCATION, rounds=3,
                                               receivers=pair))
    for receiver in run.receivers.values():
        counts = receiver.fabric.revocations.counts()
        assert sum(counts.values()) > 0
        assert counts.get("accepted", 0) == counts.get("accepted_truncated", 0) == 0


# --- privacy attacks --------------------------------------------------------------------


def test_canary_scan_finds_planted_canary(corpus: FleetCorpus) -> None:
    fleet = SimulatedFleet(corpus, FleetSpec(arm=AdversaryArm.NONE))
    clean = [c.canonical_bytes() for h in corpus.hosts for c in fleet.local_capsules(h.host_id)]
    assert clean and privacy_attacks.canary_scan(corpus, clean) == (0, ())
    canary = next(s for s in sorted(corpus.raw_strings) if s.startswith("cnry-"))
    digest = sorted(corpus.raw_digests)[0]
    hits, names = privacy_attacks.canary_scan(corpus, [*clean, f"x{canary}y{digest}".encode()])
    assert hits >= 2 and canary in names and digest in names


def test_raw_control_attack_beats_chance(corpus: FleetCorpus) -> None:
    """The membership attack is real: it breaks the raw-steps control, not the capsule."""
    raw = privacy_attacks.membership_inference(corpus, representation="raw_steps_control",
                                               trials=120)
    distilled = privacy_attacks.membership_inference(corpus, representation="distilled",
                                                     trials=120)
    assert raw.advantage is not None and raw.advantage >= 0.1
    assert distilled.advantage is not None and distilled.advantage < raw.advantage
    assert raw.synthetic and distilled.synthetic and raw.trials > 0


def test_property_inference_reports_a_measured_advantage(corpus: FleetCorpus) -> None:
    for representation in privacy_attacks.REPRESENTATIONS:
        m = privacy_attacks.property_inference(corpus, representation=representation, trials=40)
        assert m.chance is not None and 0.5 <= m.chance < 1.0
        assert m.advantage is not None and -1.0 <= m.advantage <= 1.0 - m.chance


def test_privacy_attacks_refuse_bad_input(corpus: FleetCorpus) -> None:
    with pytest.raises(ContractError):
        privacy_attacks.membership_inference(corpus, representation="features")
    with pytest.raises(ContractError):
        privacy_attacks.property_inference(corpus, representation="distilled", trials=0)


def test_dp_curve_is_measured_not_asserted(corpus: FleetCorpus) -> None:
    curve = privacy_attacks.dp_curve(corpus, seed=3)
    assert len(curve) >= 4 and curve[-1][0] is None
    exact = curve[-1]
    assert exact[1] == 1.0 and exact[2] == 1.0  # exact counts: full utility, full leakage
    noisy = [point for point in curve if point[0] is not None]
    assert all(p[2] is not None and p[2] < 1.0 for p in noisy)
    assert noisy[0][2] < noisy[-1][2]  # more noise, less count-membership advantage


# --- partition, churn, scale ------------------------------------------------------------


def test_offline_equivalence_digests_match(corpus: FleetCorpus) -> None:
    result = partition.run_offline_equivalence(corpus, receiver=default_receivers(corpus)[1],
                                               rounds=3, flood_identities=4)
    assert result.identical
    assert result.digest_absent == result.digest_offline == result.digest_crashing
    assert result.digest_disabled == result.digest_corrupt_keyring == result.digest_absent
    assert result.corrupt_reached_disabled
    assert result.crashing_failures > 0 and result.offline_dropped > 0  # the faults fired


def test_partition_recovery_refuses_stale_replayed_and_expired(corpus: FleetCorpus) -> None:
    report = partition.run_partition_recovery(corpus, partition_rounds=3)
    assert report.dropped_while_partitioned > 0
    assert report.replay_refused > 0 and report.expired_refused > 0
    assert report.recovered_rounds is not None


def test_churn_stores_plateau(corpus: FleetCorpus) -> None:
    report = partition.run_churn_endurance(corpus, rounds=45, churn_share=0.5, peer_capacity=24,
                                           publish_p=0.5)
    assert report.plateau_ok
    assert report.peers_seen > 24  # churn really exceeded every peer-sized cap
    for store, peak, cap in report.store_peaks:
        assert peak <= cap, store
    evictions = dict(report.evictions)
    hit = evictions["keyring_refused"] + evictions["peers_refused"] + evictions["peers_evicted"]
    assert hit > 0
    with pytest.raises(ContractError):
        partition.run_churn_endurance(corpus, rounds=2)


def test_scale_hits_peer_bound(corpus: FleetCorpus) -> None:
    rows = partition.run_scale(peer_counts=(12, 60), corpus=corpus, peer_capacity=32)
    small, large = rows
    assert small.refused_peers == 0 and small.table_size <= 12 + len(corpus.hosts)
    assert large.refused_peers > 0 and large.table_size <= 32  # a flood hits the bound
    assert large.work_units > small.work_units > 0 and large.memory_bytes > 0


# --- the catalogue ------------------------------------------------------------------------------


def _architecture_titles() -> list[str]:
    text = (ROOT / "docs" / "architecture" / "sources" / "stage-07-orpheus-hivelock.md").read_text()
    return [m.group(2) for m in re.finditer(r"^S7X-(\d\d)  (.+)$", text, flags=re.MULTILINE)]


def test_catalogue_has_72_rows_and_is_consistent(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = catalogue.S7_EXPERIMENTS
    assert len(rows) == 72 and catalogue.catalogue_problems() == ()
    assert [r.title for r in rows] == _architecture_titles()
    fixed = {r.sid: r.status.value for r in rows if r.status is not catalogue.ExperimentStatus.RUN}
    assert fixed == {"S7X-48": "REFUSED_BY_CONSTRUCTION", "S7X-49": "REFUSED_BY_CONSTRUCTION",
                     "S7X-62": "REFUSED_BY_CONSTRUCTION", "S7X-69": "UNMEASURED"}
    assert all("VACUOUS" in r.note for r in rows if r.sid in {"S7X-66", "S7X-67", "S7X-68"})
    broken = (replace(rows[0], runner=f"{catalogue.__name__}:no_such_runner"), *rows[1:47],
              replace(rows[47], note=" "),
              replace(rows[48], status=catalogue.ExperimentStatus.RUN), *rows[49:])
    monkeypatch.setattr(catalogue, "S7_EXPERIMENTS", broken)
    problems = catalogue.catalogue_problems()
    assert any("S7X-01" in p and "resolve" in p for p in problems)  # a runner that is not there
    assert any("S7X-48" in p and "note" in p for p in problems)  # a refusal without a reason
    assert any("S7X-49" in p and "contradicts" in p for p in problems)  # a status drifted
    monkeypatch.setattr(catalogue, "S7_EXPERIMENTS", rows[:71])
    assert any("expected 72 rows" in p for p in catalogue.catalogue_problems())


def test_cheap_catalogue_runners_run(corpus: FleetCorpus) -> None:
    protocol = catalogue.run_capsule_protocol(corpus)
    assert protocol["round_trip_equal"] and protocol["unknown_version_refused"]
    assert protocol["unknown_type_refused"] and protocol["forged_signature"] == "bad_signature"
    assert protocol["valid_signature"] == "ok" and protocol["replay"] == "duplicate_capsule"
    secure = catalogue.run_secure_aggregation(corpus)
    assert secure["exact"] and secure["dropout_aborted"]
    assert secure["malicious_edit_detected"] is False  # declared: the masked sum cannot see it
    sizes = catalogue.run_capsule_sizes(corpus)
    assert sizes["100kb_refused"] and sizes["capsule_bytes"] <= sizes["limit"]
    budget = catalogue.run_budget_exhaustion(corpus)
    assert budget["admitted_at_eps_0_5"] > 0 and budget["refusals"] >= 1
