"""D7.19 — the 72-experiment adversarial benchmark: every row, its runner, its honest status.

Architecture §48 lists 72 experiments. A list is not a benchmark: this catalogue binds each
row to a RUNNER that executes it on the simulated fleet corpus, or states — in the row's own
note — why it is REFUSED_BY_CONSTRUCTION (the capability it probes does not exist on purpose)
or UNMEASURED (the evidence it needs does not exist). Statuses are the spec's fixed table
(§D7.19); titles are verbatim from §48 and a test compares them with the architecture file.

Every runner has one signature, ``runner(corpus, *, seed=0) -> dict[str, object]``, and returns
only figures it computed in that call. Several rows share a runner when one measurement answers
them; the row's note names the field that answers it. Runners never write
``experiments/registry.jsonl``: registration is an explicit CLI act (lesson 7). Timing figures
are within-run ratios with ``/proc/loadavg`` beside them, never device measurements.

Three RUN rows are VACUOUS today and say so: S7X-66/67/68 probe Stage 6's Shadow Mind,
Conservation Gate and canary rollback on a *foreign* candidate, and Stage 6 puts no foreign
capsule in TRUSTED_CANDIDATE (M0.2, B7-1); their runner reports the bridge's Stage 6 buckets,
which is the only honest figure available at Stage 7's boundary.
"""

from __future__ import annotations

import importlib
import json
import time
import zlib
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from enum import StrEnum

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage6.resources import loadavg
from pocketsec.stage7.aggregation.robust import Aggregator
from pocketsec.stage7.aggregation.secure import MaskedVector, aggregate_masked, mask_vector
from pocketsec.stage7.antibody.forge import LocalValidation, matches, prototype_steps
from pocketsec.stage7.capsule.knowledge_capsule import (
    MAX_KNOWLEDGE_CAPSULE_BYTES,
    KnowledgeCapsuleV1,
)
from pocketsec.stage7.identity.integrity import Keyring, ReplayGuard
from pocketsec.stage7.labs import byzantine_suite as suite
from pocketsec.stage7.labs import privacy_attacks as privacy
from pocketsec.stage7.labs.campaign_sim import build_campaign_cases, run_campaign_sim
from pocketsec.stage7.labs.fleet_corpus import FleetCorpus
from pocketsec.stage7.labs.partition import (
    CHURN_ROUNDS,
    run_churn_endurance,
    run_offline_equivalence,
    run_partition_recovery,
    run_scale,
    simulate,
)
from pocketsec.stage7.labs.simulated_fleet import (
    AdversaryArm,
    FleetSpec,
    SimulatedFleet,
    honest_antibodies,
    simulated_key_provisioning,
)
from pocketsec.stage7.lineage.cross_host import (
    CrossHostLineageDAG,
    LineageRecord,
    LinkState,
    NodeRole,
    RevocationPlane,
)
from pocketsec.stage7.privacy.ledger import PrivacyBudgetExhausted, PrivacyLedger

__all__ = [
    "S7_EXPERIMENTS",
    "ExperimentStatus",
    "S7Experiment",
    "catalogue_problems",
    "run_antibody",
    "run_baselines",
    "run_budget_exhaustion",
    "run_campaign",
    "run_capsule_protocol",
    "run_capsule_sizes",
    "run_churn",
    "run_crypto_and_compression",
    "run_dp",
    "run_flood_and_pressure",
    "run_full_ablation",
    "run_novelty",
    "run_partition",
    "run_privacy_distillation",
    "run_relevance",
    "run_revocation",
    "run_scale_rows",
    "run_secure_aggregation",
    "run_stage6_handoff",
    "run_sybil",
]

Result = dict[str, object]
_M = "pocketsec.stage7.labs.seventy_two_experiments"


class ExperimentStatus(StrEnum):
    RUN = "RUN"
    REFUSED_BY_CONSTRUCTION = "REFUSED_BY_CONSTRUCTION"
    UNMEASURED = "UNMEASURED"


@dataclass(frozen=True, slots=True)
class S7Experiment:
    sid: str
    title: str
    deliverable: str
    runner: str | None  # "module:qualname", uniform signature (corpus, *, seed) -> dict
    status: ExperimentStatus
    note: str


# --- runners --------------------------------------------------------------------------------


def _fleet(corpus: FleetCorpus, seed: int) -> SimulatedFleet:
    return SimulatedFleet(corpus, FleetSpec(arm=AdversaryArm.NONE, seed=seed))


def _signed_sample(fleet: SimulatedFleet) -> tuple[KnowledgeCapsuleV1, Keyring]:
    """One honest host's own capsule, signed with the key provisioned for the first receiver."""
    receiver = fleet.receivers[0]
    source = next(h.host_id for h in fleet.corpus.hosts
                  if h.host_id != receiver and fleet.local_capsules(h.host_id))
    capsule = fleet.local_capsules(source)[0]
    ring = Keyring()
    for key_id, key, owner in fleet.key_directory(receiver):
        if key_id == capsule.key_id:
            ring.register(key_id, key, owner=owner, round_index=0)
    return ring.sign(capsule, key_id=capsule.key_id), ring


def _refused(build: Callable[[], object]) -> bool:
    try:
        build()
    except (ContractError, ValueError, TypeError, KeyError):
        return True
    return False


def run_capsule_protocol(corpus: FleetCorpus, *, seed: int = 0) -> Result:
    """S7X-01/04: round-trip, unknown version/type refused, forged signature and replay caught."""
    signed, ring = _signed_sample(_fleet(corpus, seed))
    data = signed.canonical_bytes()
    payload = json.loads(data)
    guard = ReplayGuard()
    guard.admit(signed)
    forged = KnowledgeCapsuleV1.from_dict({**payload, "signature": "0" * 64})
    return {
        "round_trip_equal": KnowledgeCapsuleV1.from_bytes(data) == signed,
        "unknown_version_refused": _refused(
            lambda: KnowledgeCapsuleV1.from_dict({**payload, "schema_version": "9.9.9"})),
        "unknown_type_refused": _refused(
            lambda: KnowledgeCapsuleV1.from_dict({**payload, "knowledge_type": "MODEL_DELTA"})),
        "valid_signature": ring.verify(signed, round_index=0).reason,
        "forged_signature": ring.verify(forged, round_index=0).reason,
        "replay": guard.check(signed, round_index=0),
        "bytes": len(data),
    }


def run_privacy_distillation(corpus: FleetCorpus, *, seed: int = 0) -> Result:
    """S7X-02/03/50/51: canary scan of every export, invariance, membership and property."""
    fleet = _fleet(corpus, seed)
    exported = [c.canonical_bytes() for h in corpus.hosts for c in fleet.local_capsules(h.host_id)]
    raw = [json.dumps([s.to_dict() for s in i.incident.steps]).encode()
           for i in honest_antibodies(corpus)]
    items = honest_antibodies(corpus)
    return {
        "exported_capsules": len(exported),
        "canary_hits_distilled": privacy.canary_scan(corpus, exported)[0],
        "canary_hits_raw_steps_control": privacy.canary_scan(corpus, raw)[0],
        "invariant_matches_source_incident": sum(matches(i.antibody.invariant, i.incident.steps)
                                                 for i in items),
        "invariant_matches_prototype": sum(matches(i.antibody.invariant, prototype_steps(
            i.antibody.invariant, source_group="grp-" + "0" * 16)) for i in items),
        "antibodies": len(items),
        **{f"{m.attack}:{m.representation}": m.advantage
           for rep in privacy.REPRESENTATIONS
           for m in (privacy.membership_inference(corpus, representation=rep, seed=seed),
                     privacy.property_inference(corpus, representation=rep, seed=seed))},
    }


def run_relevance(corpus: FleetCorpus, *, seed: int = 0) -> Result:
    """S7X-05/06/21/22/23/24: per-receiver-role ECHO acceptance of true foreign keys, the
    receiver FP from what it accepted, and gravity triage counts, on the NONE arm."""
    run = simulate(corpus, FleetSpec(arm=AdversaryArm.NONE, seed=seed))
    accepted = suite.accepted_keys(run, Aggregator.ECHO)
    out: Result = {"true_acceptance": suite.echo_metric(run, "true_acceptance")}
    for host_id, receiver in run.receivers.items():
        role = corpus.host(host_id).role.value
        recall, fp = suite.detection(replace(run, receivers={host_id: receiver}), accepted)
        out[f"{role}:{host_id}:recall"] = recall
        out[f"{role}:{host_id}:fp_rate"] = fp
        out[f"{role}:{host_id}:triaged"] = receiver.verdicts["METADATA_ONLY"]
    return out


def _suite_result(report: suite.ByzantineReport, aggregators: frozenset[str]) -> Result:
    return {
        "rows": [asdict(r) for r in report.rows if r.aggregator in aggregators],
        "break_points": [asdict(b) for b in report.break_points if b.aggregator in aggregators],
        "firing": dict(report.firing), "loadavg": report.loadavg, "synthetic": report.synthetic,
    }


def run_sybil(corpus: FleetCorpus, *, seed: int = 0) -> Result:
    """S7X-07..11: the three Sybil arms at 1, 8 and 32 identities; amplification, merges."""
    report = suite.run_byzantine_suite(corpus, arms=sorted(suite.SYBIL_ARMS),
                                       sybil_counts=(1, 8, 32),
                                       seed=seed, with_stage6=False, ablations=False,
                                       sensitivity=False)
    return _suite_result(report, frozenset({"ECHO", "MAJORITY", "MEAN", "MEDIAN", "ROOT_QUORUM"}))


def run_baselines(corpus: FleetCorpus, *, seed: int = 0) -> Result:
    """S7X-12..18/28/42/43/72: every aggregator (+LV) on identical pools, Byzantine arms."""
    arms = (AdversaryArm.NONE, AdversaryArm.BYZANTINE_POISON, AdversaryArm.BYZANTINE_LATENT_POISON,
            AdversaryArm.BYZANTINE_SUPPRESS, AdversaryArm.SLOW_POISON,
            AdversaryArm.COLLUSION_TIMING)
    report = suite.run_byzantine_suite(corpus, arms=arms, shares=(0.0, 0.2, 0.4), seed=seed,
                                       with_stage6=False, ablations=False, sensitivity=False)
    result = _suite_result(report, frozenset(a.value for a in Aggregator))
    result["time_to_detect"] = dict(report.time_to_detect)
    return result


def run_secure_aggregation(corpus: FleetCorpus, *, seed: int = 0) -> Result:
    """S7X-19/20/47: exact masked sum, dropout abort, a malicious aggregator's edit."""
    names = [f"p{i}" for i in range(4)]
    keys = simulated_key_provisioning(names, names, seed=seed)
    values = {n: [i + 1, 2 * i] for i, n in enumerate(names)}
    vectors = [mask_vector(values[n], participant=n, round_index=0,
                           pair_keys={m: keys[(min(n, m), max(n, m))] for m in names if m != n})
               for n in names]
    exact = aggregate_masked(vectors, expected=frozenset(names), round_index=0)
    dropout = aggregate_masked(vectors[:-1], expected=frozenset(names), round_index=0)
    edited = [*vectors[:-1], MaskedVector(vectors[-1].participant, 0,
                                          ((vectors[-1].values[0] + 1) % 2**32,
                                           *vectors[-1].values[1:]))]
    tampered = aggregate_masked(edited, expected=frozenset(names), round_index=0)
    truth = [sum(v[i] for v in values.values()) for i in range(2)]
    probe = privacy.secure_sum_ablation(corpus, seed=seed)
    return {"exact": exact.total == tuple(truth), "dropout_aborted": dropout.aborted,
            "malicious_edit_detected": tampered.aborted or tampered.total == tuple(truth),
            "sybil_inflation_secure": probe[1], "sybil_inflation_clamped": probe[2]}


def run_antibody(corpus: FleetCorpus, *, seed: int = 0) -> Result:
    """S7X-25..28: forge yield, mutation survival, local validation at every receiver."""
    items = honest_antibodies(corpus)
    run = simulate(corpus, FleetSpec(arm=AdversaryArm.BYZANTINE_LATENT_POISON, adversary_share=0.2,
                                     seed=seed, rounds=2))
    verdicts: dict[str, int] = {}
    for receiver in run.receivers.values():
        for item in items:
            outcome = receiver.components.validator.validate(item.antibody.invariant).value
            verdicts[outcome] = verdicts.get(outcome, 0) + 1
    poison = {k: [r.components.validator.validate(run.fleet.invariant_of(k) or ()).value
                  for r in run.receivers.values()] for k in run.truth.poison_keys}
    return {"antibodies": len(items), "minimised": sum(i.antibody.minimised for i in items),
            "mutations_tried": sum(i.antibody.falsification.mutations_tried for i in items),
            "mutations_survived": sum(i.antibody.falsification.mutations_survived for i in items),
            "local_validation": verdicts, "latent_poison_validation": poison,
            "latent_poison_is_blind": all(v == LocalValidation.PASS.value
                                          for vs in poison.values() for v in vs[:1])}


def run_campaign(corpus: FleetCorpus, *, seed: int = 0) -> Result:
    """S7X-29..36/40/41: every campaign arm through the reconstructor and falsifier."""
    report = run_campaign_sim(build_campaign_cases(seed=seed))
    return asdict(report)


def run_novelty(corpus: FleetCorpus, *, seed: int = 0) -> Result:
    """S7X-37/38/39: collective vs local-only novelty on routine and truly novel patterns."""
    metric, full, control, firing, _ = privacy.novelty_ablation(corpus, seed=seed)
    return {"metric": metric, "collective": full, "local_only": control, "firing": firing}


def run_revocation(corpus: FleetCorpus, *, seed: int = 0) -> Result:
    """S7X-44/45: the FALSE_REVOCATION arm changes nothing; a self-retraction marks exactly
    the descendants and reinstatement restores the digest byte for byte."""
    run = simulate(corpus, FleetSpec(arm=AdversaryArm.FALSE_REVOCATION, seed=seed, rounds=4))
    counts = {h: dict(r.fabric.revocations.counts()) for h, r in run.receivers.items()}
    dag = CrossHostLineageDAG()
    for node, parents in (("kc-" + "a" * 24, ()), ("kc-" + "b" * 24, ("kc-" + "a" * 24,)),
                          ("kc-" + "c" * 24, ("kc-" + "b" * 24,)), ("kc-" + "d" * 24, ())):
        dag.add(LineageRecord(node, NodeRole.FOREIGN_CAPSULE, parents, LinkState.LIVE, 0, ""))
    plane = RevocationPlane(dag=dag, owner_of_key=lambda _k: None, contributor_of=lambda _c: None,
                            local_keys=frozenset, echo_suspect=lambda _keys, _s: None)
    before = dag.state_digest()
    local = plane.revoke_locally("kc-" + "a" * 24, round_index=1)
    restored = plane.reinstate(local.revocation_id)
    return {"false_revocation_outcomes": counts, "affected": sorted(local.affected),
            "non_descendant_untouched": "kc-" + "d" * 24 not in local.affected,
            "reinstated_digest_equal": restored and dag.state_digest() == before,
            "ground": local.ground.value}


def run_budget_exhaustion(corpus: FleetCorpus, *, seed: int = 0) -> Result:
    """S7X-52: releases the default ledger admits in one window before it refuses."""
    ledger, admitted = PrivacyLedger(), 0
    try:
        while admitted < 100_000:
            ledger.charge("novelty_counts", recipient_scope="simulated", round_index=0, epsilon=0.5)
            admitted += 1
    except PrivacyBudgetExhausted:
        pass
    return {"admitted_at_eps_0_5": admitted, "refusals": ledger.refusals()}


def run_dp(corpus: FleetCorpus, *, seed: int = 0) -> Result:
    """S7X-53: the epsilon / novelty-recall / count-membership-advantage curve."""
    return {"curve": [list(point) for point in privacy.dp_curve(corpus, seed=seed)],
            "seeded_rng_voids_guarantee": True}


def run_flood_and_pressure(corpus: FleetCorpus, *, seed: int = 0) -> Result:
    """S7X-54/55: a flood hits the per-peer, round and table bounds; graph pressure at scale."""
    run = simulate(corpus, FleetSpec(arm=AdversaryArm.FLOOD, sybils_per_root=64, seed=seed,
                                     rounds=3))
    stores = {h: dict(r.fabric.memory_bytes()) for h, r in run.receivers.items()}
    return {"offered": dict(run.offered), "store_bytes": stores,
            "scale": [asdict(r) for r in run_scale(peer_counts=(1000,), corpus=corpus, seed=seed)]}


def run_partition(corpus: FleetCorpus, *, seed: int = 0) -> Result:
    """S7X-56/57/58: partition + stale recovery, and local equivalence while offline."""
    receiver = SimulatedFleet(corpus, FleetSpec(arm=AdversaryArm.NONE)).receivers[0]
    return {"partition": asdict(run_partition_recovery(corpus, seed=seed)),
            "offline": asdict(run_offline_equivalence(corpus, receiver=receiver))}


def run_scale_rows(corpus: FleetCorpus, *, seed: int = 0) -> Result:
    """S7X-59/60: 1 000 and 10 000 simulated peers at one receiver (not a network)."""
    return {"rows": [asdict(r) for r in run_scale(peer_counts=(1000, 10000), corpus=corpus,
                                                   seed=seed)]}


def _timed(fn: Callable[[], object], repeat: int) -> float:
    start = time.perf_counter()
    for _ in range(repeat):
        fn()
    return (time.perf_counter() - start) / repeat


def run_capsule_sizes(corpus: FleetCorpus, *, seed: int = 0) -> Result:
    """S7X-61/62: the 1 KB class parses; 10 KB+ classes are refused before parsing.
    Wall-time RATIO only (refusal / parse), with loadavg beside it."""
    signed, _ = _signed_sample(_fleet(corpus, seed))
    data = signed.canonical_bytes()
    big = b"{" + b" " * 100_000 + b"}"
    parse = _timed(lambda: KnowledgeCapsuleV1.from_bytes(data), 50)
    refuse = _timed(lambda: _refused(lambda: KnowledgeCapsuleV1.from_bytes(big)), 50)
    return {"capsule_bytes": len(data), "limit": MAX_KNOWLEDGE_CAPSULE_BYTES,
            "100kb_refused": _refused(lambda: KnowledgeCapsuleV1.from_bytes(big)),
            "refusal_to_parse_time_ratio": refuse / parse if parse else None, "loadavg": loadavg()}


def run_crypto_and_compression(corpus: FleetCorpus, *, seed: int = 0) -> Result:
    """S7X-63/64: HMAC sign+verify vs parse (time RATIO, loadavg beside); zlib size ratio."""
    signed, ring = _signed_sample(_fleet(corpus, seed))
    data = signed.canonical_bytes()
    crypto = _timed(lambda: ring.verify(ring.sign(signed, key_id=signed.key_id), round_index=0), 50)
    parse = _timed(lambda: KnowledgeCapsuleV1.from_bytes(data), 50)
    return {"hmac_to_parse_time_ratio": crypto / parse if parse else None,
            "zlib_ratio": len(zlib.compress(data, 9)) / len(data), "loadavg": loadavg(),
            "ed25519": None, "zstd": None}


def run_stage6_handoff(corpus: FleetCorpus, *, seed: int = 0) -> Result:
    """S7X-65..68: what Stage 6 did with every bridged capsule (verbatim buckets)."""
    run = simulate(corpus, FleetSpec(arm=AdversaryArm.NONE, seed=seed), with_stage6=True)
    firing = suite.run_firing(run)
    return {"bridge_created": firing["bridge_created"],
            "bridge_admitted": firing["bridge_admitted"],
            "stage6_buckets": {k: v for k, v in firing.items() if k.startswith("stage6:")},
            "trusted_candidates": sum(r.stage6_trusted_candidates for r in suite.evaluate_run(run)
                                      if r.aggregator == "ECHO")}


def run_churn(corpus: FleetCorpus, *, seed: int = 0) -> Result:
    """S7X-70: CHURN_ROUNDS of 10% per-round churn; every store's peak against its cap."""
    return asdict(run_churn_endurance(corpus, rounds=CHURN_ROUNDS, seed=seed))


def run_full_ablation(corpus: FleetCorpus, *, seed: int = 0) -> Result:
    """S7X-71: one AblationRow per spec §7 flag, with firing counts."""
    return {"ablations": [asdict(r) for r in suite.run_ablation(corpus, seed=seed)]}


# --- the catalogue ------------------------------------------------------------------------------

_R = ExperimentStatus.RUN
_X = ExperimentStatus.REFUSED_BY_CONSTRUCTION
_U = ExperimentStatus.UNMEASURED
_VACUOUS = ("VACUOUS today: Stage 6 puts no foreign capsule in TRUSTED_CANDIDATE (M0.2, B7-1), "
            "so no foreign candidate reaches {}; the runner reports the bridge's Stage 6 buckets")

#: (number, title verbatim from architecture §48, deliverable, runner, status, note)
_ROWS: tuple[tuple[int, str, str, str | None, ExperimentStatus, str], ...] = (
    (1, "capsule schema/versioning", "D7.2", "run_capsule_protocol", _R,
     "round trip; unknown version/type refused"),
    (2, "privacy distillation", "D7.3", "run_privacy_distillation", _R, "canary_hits_distilled"),
    (3, "semantic invariance after redaction", "D7.3", "run_privacy_distillation", _R,
     "invariant_matches_source_incident / invariant_matches_prototype"),
    (4, "signature/replay protection", "D7.4", "run_capsule_protocol", _R,
     "forged_signature, replay"),
    (5, "epistemic distance calibration", "D7.5", "run_relevance", _R, "per-role recall and FP"),
    (6, "knowledge gravity calibration", "D7.6", "run_relevance", _R,
     "per-receiver triaged counts"),
    (7, "dependence graph", "D7.8", "run_sybil", _R, "firing graph_merge:*"),
    (8, "duplicate evidence discount", "D7.8", "run_sybil", _R,
     "SYBIL_DECLARED_ROOT amplification"),
    (9, "Sybil identity burst", "D7.8", "run_sybil", _R, "SYBIL_FORGED_ROOTS rows"),
    (10, "Sybil slow growth", "D7.8", "run_sybil", _R, "SYBIL_ADAPTIVE rows (staggered births)"),
    (11, "colluding peer cluster", "D7.8", "run_sybil", _R, "break points per aggregator"),
    (12, "honest rare-role clients", "D7.9", "run_baselines", _R,
     "NONE rows at the ADMIN receiver"),
    (13, "median baseline", "D7.9", "run_baselines", _R, "MEDIAN rows"),
    (14, "trimmed mean baseline", "D7.9", "run_baselines", _R, "TRIMMED_MEAN rows"),
    (15, "Krum-family baseline", "D7.9", "run_baselines", _R, "KRUM / MULTI_KRUM rows"),
    (16, "Bulyan-family baseline", "D7.9", "run_baselines", _R, "BULYAN rows"),
    (17, "validation-filter baseline", "D7.9", "run_baselines", _R, "VALIDATION_FILTER rows"),
    (18, "ECHO aggregation", "D7.10", "run_baselines", _R, "ECHO rows (the fabric's ELIGIBLE set)"),
    (19, "secure aggregation prototype", "D7.17", "run_secure_aggregation", _R, "exact"),
    (20, "secure aggregation dropout", "D7.17", "run_secure_aggregation", _R,
     "dropout aborts; recovery NOT built"),
    (21, "non-IID web/desktop/server split", "D7.5", "run_relevance", _R, "per-role rows"),
    (22, "role-conditioned aggregation", "D7.5", "run_relevance", _R, "true_acceptance by role"),
    (23, "cross-epoch transfer", "D7.5", "run_relevance", _R,
     "roles carry distinct images in the corpus: cross-role is also cross-epoch"),
    (24, "bad cross-role transfer", "D7.5", "run_relevance", _R, "per-receiver fp_rate"),
    (25, "antibody extraction", "D7.11", "run_antibody", _R, "antibodies, minimised"),
    (26, "antibody counterfactual mutation", "D7.11", "run_antibody", _R, "mutations_survived"),
    (27, "antibody local validation", "D7.11", "run_antibody", _R, "local_validation"),
    (28, "poisoned antibody", "D7.11", "run_antibody", _R, "latent_poison_validation"),
    (29, "partial-world reconstruction 2 hosts", "D7.12", "run_campaign", _R, "TRUE_CAMPAIGN_2"),
    (30, "4 hosts", "D7.12", "run_campaign", _R, "TRUE_CAMPAIGN_4"),
    (31, "10 hosts", "D7.12", "run_campaign", _R, "TRUE_CAMPAIGN_10"),
    (32, "benign coincidence falsification", "D7.15", "run_campaign", _R, "H0 rejections"),
    (33, "shared software-update false campaign", "D7.15", "run_campaign", _R, "H1 rejections"),
    (34, "campaign hypergraph", "D7.13", "run_campaign", _R, "false_campaign_rate"),
    (35, "temporal uncertainty", "D7.13", "run_campaign", _R, "TEMPORAL_UNCERTAINTY"),
    (36, "negative evidence visibility", "D7.15", "run_campaign", _R, "suppression_delay_rounds"),
    (37, "collective novelty", "D7.14", "run_novelty", _R, "collective"),
    (38, "rare benign population event", "D7.14", "run_novelty", _R, "false-novel rate"),
    (39, "unknown attack campaign", "D7.14", "run_novelty", _R, "novel recall in metric"),
    (40, "campaign suppression", "D7.15", "run_campaign", _R, "suppressed_never_detected"),
    (41, "consensus falsifier", "D7.15", "run_campaign", _R, "rejections_by_hypothesis"),
    (42, "majority-poison scenario", "D7.9", "run_baselines", _R, "BYZANTINE_POISON at 0.4"),
    (43, "high-quality minority scenario", "D7.9", "run_baselines", _R,
     "true acceptance at share 0.4 (honest minority of roots stays correct)"),
    (44, "false revocation", "D7.16", "run_revocation", _R, "false_revocation_outcomes"),
    (45, "revocation descendant tracing", "D7.16", "run_revocation", _R, "affected, reinstated"),
    (46, "lineage tamper", "D7.7", "run_capsule_protocol", _R,
     "the LINEAGE_TAMPER arm in the suite; this runner covers the protocol refusals"),
    (47, "malicious aggregator", "D7.17", "run_secure_aggregation", _R,
     "a malicious aggregator in the secure sum alters the total -> detected only if a "
     "participant cross-checks; measured as undetected (declared)"),
    (48, "model replacement", "D7.2", None, _X, "no MODEL_DELTA knowledge type (ADR-0062)"),
    (49, "backdoor adapter", "D7.2", None, _X, "no MODEL_DELTA knowledge type (ADR-0062)"),
    (50, "membership inference", "D7.3", "run_privacy_distillation", _R, "membership_inference:*"),
    (51, "property inference", "D7.3", "run_privacy_distillation", _R, "property_inference:*"),
    (52, "privacy budget exhaustion", "D7.3", "run_budget_exhaustion", _R, "admitted_at_eps_0_5"),
    (53, "DP utility/privacy curve", "D7.3", "run_dp", _R, "DP curve on population counts"),
    (54, "capsule flood", "D7.18", "run_flood_and_pressure", _R, "offered refusals by stage"),
    (55, "graph OOM pressure", "D7.8", "run_flood_and_pressure", _R, "scale, store_bytes"),
    (56, "network partition", "D7.18", "run_partition", _R, "simulated partition, not a network"),
    (57, "stale peer recovery", "D7.18", "run_partition", _R, "stale/replay/expired refused"),
    (58, "offline operation", "D7.18", "run_partition", _R, "offline digests identical"),
    (59, "1k peer simulation", "D7.18", "run_scale_rows", _R,
     "simulated peers at the ingress; not a network"),
    (60, "10k peer simulation", "D7.18", "run_scale_rows", _R,
     "simulated peers at the ingress; not a network"),
    (61, "1 KB capsule benchmark", "D7.2", "run_capsule_sizes", _R, "1 KB class"),
    (62, "100 KB capsule benchmark", "D7.2", "run_capsule_sizes", _X,
     "> MAX_KNOWLEDGE_CAPSULE_BYTES; refused before parsing; refusal cost measured"),
    (63, "crypto CPU benchmark", "D7.4", "run_crypto_and_compression", _R,
     "HMAC-SHA256 only; Ed25519 UNMEASURED"),
    (64, "compression benchmark", "D7.18", "run_crypto_and_compression", _R,
     "zlib as a stdlib stand-in; zstd UNMEASURED"),
    (65, "Stage6 import gate", "D7.7", "run_stage6_handoff", _R, "stage6_buckets"),
    (66, "Shadow Mind foreign candidate", "D7.7", "run_stage6_handoff", _R,
     _VACUOUS.format("Shadow Mind")),
    (67, "Conservation Gate rejection", "D7.7", "run_stage6_handoff", _R,
     _VACUOUS.format("the Conservation Gate")),
    (68, "canary rollback", "D7.7", "run_stage6_handoff", _R, _VACUOUS.format("canary rollback")),
    (69, "full Stage1–7 endurance", "D7.20", None, _U,  # noqa: RUF001 - verbatim §48
     "a full Stage 1-7 endurance on real telemetry does not exist; the synthetic churn run "
     "is S7X-70"),
    (70, "month-scale peer churn", "D7.20", "run_churn", _R, "plateau_ok, store_peaks"),
    (71, "full ablation", "D7.9", "run_full_ablation", _R, "one AblationRow per flag"),
    (72, "falsification vs FedAvg/playbook feed", "D7.9", "run_baselines", _R,
     "against FedAvg (= MEAN) and the central feed; FedProx/personalised FL are UNMEASURED "
     "(no parameters)"),
)

S7_EXPERIMENTS: tuple[S7Experiment, ...] = tuple(
    S7Experiment(sid=f"S7X-{n:02d}", title=title, deliverable=deliverable,
                 runner=f"{_M}:{runner}" if runner else None, status=status, note=note)
    for n, title, deliverable, runner, status, note in _ROWS
)

#: The spec's fixed non-RUN statuses (§D7.19); every other row is RUN.
_FIXED = {48: _X, 49: _X, 62: _X, 69: _U}


def _resolve(target: str) -> object:
    module, _, qualname = target.partition(":")
    obj: object = importlib.import_module(module)
    for part in qualname.split("."):
        obj = getattr(obj, part)
    return obj


def catalogue_problems() -> tuple[str, ...]:
    """Every inconsistency in the catalogue; () means consistent.

    Exactly 72 rows S7X-01..72 in order; the spec's fixed statuses; every RUN row names a
    runner that resolves to a callable in ``pocketsec.stage7``; every non-RUN row carries a
    note. (Whether the gate or CLI exercises each runner is checked by the integrator.)
    """
    problems = []
    if len(S7_EXPERIMENTS) != 72:
        problems.append(f"expected 72 rows, found {len(S7_EXPERIMENTS)}")
    for index, row in enumerate(S7_EXPERIMENTS, start=1):
        if row.sid != f"S7X-{index:02d}":
            problems.append(f"row {index} has sid {row.sid}")
        if row.status is not _FIXED.get(index, _R):
            problems.append(f"{row.sid}: status {row.status} contradicts the spec table")
        if row.status is not _R and not row.note.strip():
            problems.append(f"{row.sid}: a {row.status} row needs a note")
        if row.status is _R:
            if not row.runner or not row.runner.startswith("pocketsec.stage7."):
                problems.append(f"{row.sid}: RUN row without a stage 7 runner")
                continue
            try:
                if not callable(_resolve(row.runner)):
                    problems.append(f"{row.sid}: runner {row.runner} is not callable")
            except (ImportError, AttributeError) as error:
                problems.append(f"{row.sid}: runner {row.runner} does not resolve ({error})")
    return tuple(problems)
