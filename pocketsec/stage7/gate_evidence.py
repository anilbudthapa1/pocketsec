"""The Stage 7 gate's evidence: each builder RUNS real subsystems once and records what it saw.

The eleven checks (``gate_construction``, ``gate_measured``) judge; this module only runs and
records, so a check never replays an expensive simulation and never reads a document to
decide a mechanism question. Every builder works on the simulated fleet corpus through the
real ``OrpheusFabric`` (HIVELOCK ingress, dependence graph, ECHO, revocation plane, campaign
engines) and, where the criterion is about the Stage 6 boundary, a real ``Stage6Bridge`` into
a real lab ``QuarantineGateway``. Nothing here writes ``experiments/registry.jsonl``.

Two things are stated rather than hidden. **The fleet is simulated in-process** — real
latency, partitions and Sybil populations are UNMEASURED. **The adversary, the defences and
the ground truth share an author** (lesson 6), so robustness figures are mechanism figures.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, fields, replace

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage7.capsule.compiler import ExportContext, compile_capsule
from pocketsec.stage7.capsule.knowledge_capsule import (
    COUNTER_HYPOTHESIS_VALUES,
    MAX_EVIDENCE_COMMITMENTS,
    FalsificationSummary,
    KnowledgeCapsuleV1,
    KnowledgeType,
    MotifRow,
    ObservabilityClaim,
    RevocationGround,
    RoleClass,
    Stance,
    ValidationSummary,
    seal_capsule,
)
from pocketsec.stage7.aggregation.robust import Aggregator
from pocketsec.stage7.antibody.forge import LocalValidation
from pocketsec.stage7.echo.inference import EchoStatus
from pocketsec.stage7.governor.communication import Stage7ResourceReport, measure_stage7_resources
from pocketsec.stage7.hivelock.ingress import IngressOutcome, IngressStage, IngressVerdict
from pocketsec.stage7.identity.integrity import Keyring
from pocketsec.stage7.labs.byzantine_suite import accepted_keys, detection
from pocketsec.stage7.labs.fleet_corpus import FleetCorpus, oracle_motif
from pocketsec.stage7.labs.partition import (
    ScaleRow,
    SimulatedReceiver,
    SuiteRun,
    simulate,
    simulated_receiver,
    store_caps,
    store_counts,
)
from pocketsec.stage7.labs.simulated_fleet import (
    UNANIMOUS_PEERS,
    AdversaryArm,
    Delivery,
    FleetSpec,
    SimulatedFleet,
)
from pocketsec.stage7.lineage.cross_host import LinkState, NodeRole
from pocketsec.stage7.privacy.ledger import PrivacyLedger
from pocketsec.stage7.trust.contextual import TRUST_PRIOR, task_key

__all__ = [
    "FLOOD_IDENTITIES",
    "FLOOD_ROUNDS",
    "UNANIMOUS_ROUNDS",
    "FloodEvidence",
    "NonIidEvidence",
    "RevocationEvidence",
    "RunObservation",
    "UnanimousEvidence",
    "capsule_samples",
    "false_revocation_evidence",
    "flood_evidence",
    "non_iid_evidence",
    "observe_run",
    "revocation_evidence",
    "unanimous_evidence",
]

#: Chosen gate sizes, not measurements. The spec fixes 1000 flood peers (G7.10) and 64
#: unanimous peers (G7.1(c), ``UNANIMOUS_PEERS``); the round counts are the smallest that
#: let every rule fire more than once.
FLOOD_IDENTITIES: int = 1000
FLOOD_ROUNDS: int = 4
UNANIMOUS_ROUNDS: int = 4
_SAMPLE_SECRET = hashlib.sha256(b"stage7-gate-sample-host").digest()
_VERDICT_KIND = "VERDICT"  # Stage 6 NodeKind value; the enum itself is not on the allow-list


# --- one suite run, observed (G7.1(b), G7.8, G7.11's no-sharing FP) ------------------------------


@dataclass(frozen=True, slots=True)
class RunObservation:
    """What one suite run's receivers did at the Stage 6 boundary, summed over receivers."""

    arm: str
    share: float
    sybils: int
    created: int  # ExperienceCapsuleV1 values the bridges built
    admitted: int  # values the bridges passed to gateway.admit
    gateway_offered: int  # what the lab gateways say they were offered
    mismatched: tuple[str, ...]  # receivers where created, admitted and offered disagree
    buckets: tuple[tuple[str, int], ...]
    trusted_candidates: int
    eligible: int  # distinct ELIGIBLE decision ids
    eligible_incomplete: int  # of those, cross-host ancestry not complete
    bridged: int  # Stage 6 capsules named in bridge receipts
    bridged_lineage_missing: int  # of those, no local node or no VERDICT child
    base_recall: float | None  # NO_SHARING, counterfactual_at_boundary
    base_fp: float | None


def _stage6_lineage_ok(receiver: SimulatedReceiver, capsule_id: str, verdict_id: str) -> bool:
    dag = receiver.stage6_dag
    if dag is None or not dag.has(capsule_id) or verdict_id not in dag.children(capsule_id):
        return False
    node = dag.node(verdict_id)
    return node is not None and getattr(node.kind, "value", node.kind) == _VERDICT_KIND


def _bridge_counts(host_id: str, receiver: SimulatedReceiver, tally: Counter[str],
                   buckets: Counter[str], mismatched: list[str]) -> None:
    bridge = receiver.components.bridge
    if bridge is None:
        return
    offered = receiver.gateway.stats().get("offered") if receiver.gateway is not None else 0
    created, admitted = bridge.created(), bridge.admitted()
    tally.update({"created": created, "admitted": admitted, "offered": offered})
    if not created == admitted == offered:
        mismatched.append(f"{host_id}: created {created} admitted {admitted} offered {offered}")
    buckets.update(bridge.buckets())
    for receipt in bridge.receipts():
        tally["trusted"] += receipt.trusted_candidates
        for capsule_id, verdict_id in zip(receipt.stage6_capsule_ids, receipt.verdict_ids,
                                          strict=True):
            tally["bridged"] += 1
            tally["missing"] += not _stage6_lineage_ok(receiver, capsule_id, verdict_id)


def observe_run(run: SuiteRun) -> RunObservation:
    """Summarise one run at the Stage 6 boundary and the cross-host lineage."""
    tally: Counter[str] = Counter()
    buckets: Counter[str] = Counter()
    mismatched: list[str] = []
    for host_id, receiver in sorted(run.receivers.items()):
        _bridge_counts(host_id, receiver, tally, buckets, mismatched)
        ids = {d.decision_id for inference in receiver.inferences
               for d in inference.decisions if d.status is EchoStatus.ELIGIBLE}
        tally["eligible"] += len(ids)
        tally["incomplete"] += sum(
            not receiver.components.lineage.ancestry_complete(i) for i in ids)
    base_recall, base_fp = detection(run, None)
    spec = run.spec
    return RunObservation(
        arm=spec.arm.value, share=float(spec.adversary_share), sybils=spec.sybils_per_root,
        created=tally["created"], admitted=tally["admitted"], gateway_offered=tally["offered"],
        mismatched=tuple(mismatched), buckets=tuple(sorted(buckets.items())),
        trusted_candidates=tally["trusted"], eligible=tally["eligible"],
        eligible_incomplete=tally["incomplete"], bridged=tally["bridged"],
        bridged_lineage_missing=tally["missing"], base_recall=base_recall, base_fp=base_fp,
    )


# --- G7.5: non-IID honest hosts on the suite's NONE run ---------------------------------------


@dataclass(frozen=True, slots=True)
class NonIidEvidence:
    """Rare-role (ADMIN) honest knowledge vs majority-role, on arm NONE (no adversary)."""

    rare_offered: int  # (receiver, key): same-role honest antibodies that pass local validation
    rare_eligible: int
    majority_offered: int
    majority_eligible: int
    honest_pairs: int  # honest peer pairs of different true roots seen at a receiver
    false_merges: int  # of those, placed in one dependence cluster
    rare_trust_pairs: int  # (cluster, task) pairs of rare-role honest contributions
    rare_trust_violations: int  # below TRUST_PRIOR with no recorded refutation
    krum_excluded: tuple[tuple[str, float | None], ...]  # method -> rare key exclusion share


def _same_role_keys(run: SuiteRun, host_id: str, receiver: SimulatedReceiver) -> set[str]:
    role = run.fleet.corpus.host(host_id).role
    local = receiver.components.local.local_keys
    ok = {LocalValidation.PASS, LocalValidation.LOCAL_CONFIRMED}
    return {
        p.capsule.compact_feature_signature for p in receiver.pooled
        if p.peer_id not in run.truth.adversary_peers
        and p.capsule.knowledge_type is KnowledgeType.ANTIBODY
        and p.capsule.stance is Stance.SUPPORT
        and p.capsule.source_context_sketch.role is role
        and p.capsule.compact_feature_signature not in local
        and receiver.components.validator.validate(p.capsule.semantic_invariant) in ok
    }


def _false_merges(run: SuiteRun, receiver: SimulatedReceiver) -> tuple[int, int]:
    roots = run.truth.true_root_of
    peers = sorted({p.peer_id for p in receiver.pooled
                    if p.peer_id not in run.truth.adversary_peers and p.peer_id in roots})
    cluster = {peer: receiver.components.graph.cluster_of(peer) for peer in peers}
    pairs = merged = 0
    for i, a in enumerate(peers):
        for b in peers[i + 1:]:
            if roots[a] != roots[b]:
                pairs += 1
                merged += cluster[a] == cluster[b]
    return pairs, merged


def _rare_trust(run: SuiteRun, receiver: SimulatedReceiver, rare: RoleClass) -> tuple[int, int]:
    trust, graph = receiver.components.trust, receiver.components.graph
    last = run.spec.rounds - 1
    seen: set[tuple[str, str]] = set()
    violations = 0
    for p in receiver.pooled:
        if p.peer_id in run.truth.adversary_peers or p.capsule.source_context_sketch.role is not rare:
            continue
        if not p.capsule.causal_motif:
            continue
        pair = (graph.cluster_of(p.peer_id), task_key(p.capsule.causal_motif))
        if pair in seen:
            continue
        seen.add(pair)
        state = trust.state(*pair)
        low = trust.reliability(*pair, round_index=last) < TRUST_PRIOR
        violations += low and (state is None or state.refutations == 0)
    return len(seen), violations


def _krum_exclusion(run: SuiteRun, rare_keys: Mapping[str, set[str]]) -> tuple[tuple[str, float | None], ...]:
    out = []
    offered = sum(len(k) for k in rare_keys.values())
    for method in (Aggregator.KRUM, Aggregator.MULTI_KRUM, Aggregator.BULYAN):
        accepted = accepted_keys(run, method)
        kept = sum(len(keys & accepted.get(h, {}).keys()) for h, keys in rare_keys.items())
        out.append((method.value, None if offered == 0 else 1.0 - kept / offered))
    return tuple(out)


def non_iid_evidence(run: SuiteRun, *, rare: RoleClass = RoleClass.ADMIN) -> NonIidEvidence:
    tally: Counter[str] = Counter()
    rare_keys: dict[str, set[str]] = {}
    for host_id, receiver in run.receivers.items():
        keys = _same_role_keys(run, host_id, receiver)
        eligible = {d.antibody_key for inf in receiver.inferences for d in inf.decisions
                    if d.status is EchoStatus.ELIGIBLE}
        side = "rare" if run.fleet.corpus.host(host_id).role is rare else "majority"
        tally[f"{side}_offered"] += len(keys)
        tally[f"{side}_eligible"] += len(keys & eligible)
        if side == "rare":
            rare_keys[host_id] = keys
        pairs, merged = _false_merges(run, receiver)
        tally.update({"pairs": pairs, "merged": merged})
        checked, violations = _rare_trust(run, receiver, rare)
        tally.update({"trust_pairs": checked, "trust_violations": violations})
    return NonIidEvidence(
        rare_offered=tally["rare_offered"], rare_eligible=tally["rare_eligible"],
        majority_offered=tally["majority_offered"], majority_eligible=tally["majority_eligible"],
        honest_pairs=tally["pairs"], false_merges=tally["merged"],
        rare_trust_pairs=tally["trust_pairs"], rare_trust_violations=tally["trust_violations"],
        krum_excluded=_krum_exclusion(run, rare_keys),
    )


# --- G7.1(c): the unanimous fleet ------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class UnanimousEvidence:
    """64 independent-root peers all agreeing against each receiver, every delivery judged."""

    receivers: int
    sent: tuple[tuple[str, int], ...]  # kind -> deliveries (revoke/support_fp/contest/authority)
    held: tuple[tuple[str, int], ...]  # kind -> deliveries the rule held as required
    min_senders: int  # fewest distinct adversarial senders any receiver saw
    fp_exercised: int  # receivers sent (ii): SUPPORT for a rule that FPs locally
    fp_challenged: int  # of those: ended CHALLENGED, never ELIGIBLE, never bridged
    local_intact: int  # receivers whose local capsule stayed LIVE and local keys unmoved
    revocations_accepted: int
    bridged: int
    buckets: tuple[tuple[str, int], ...]


def _kind_of(delivery: Delivery) -> str:
    try:
        capsule = KnowledgeCapsuleV1.from_bytes(delivery.data)
    except (ContractError, ValueError, TypeError, KeyError, RecursionError):
        return "authority"  # the arm's only unparseable payload is the authority-keyed one
    if capsule.knowledge_type is KnowledgeType.REVOCATION:
        return "revoke"
    if capsule.stance is Stance.CONTEST:
        return "contest"
    return "support_fp" if delivery.poison_key is not None else "other"


def _held(kind: str, verdict: IngressVerdict | None) -> bool:
    """Did ingress do what G7.1(c) requires for this kind? ``None`` (dropped) never counts."""
    if verdict is None:
        return False
    refused = verdict.outcome is IngressOutcome.REFUSED
    if kind == "revoke":
        return refused and any("local_sovereignty" in r for r in verdict.reasons)
    if kind == "contest":
        return refused
    if kind == "authority":
        return refused and verdict.stage_reached is IngressStage.SCHEMA
    return True  # SUPPORT is allowed to pool; ECHO must then challenge it


def _local_intact(run: SuiteRun, host_id: str, receiver: SimulatedReceiver) -> bool:
    lineage, local = receiver.components.lineage, receiver.components.local.local_keys
    for capsule in run.fleet.local_capsules(host_id)[:1]:
        record = lineage.get(capsule.capsule_id)
        if record is None or record.role is not NodeRole.LOCAL_CAPSULE:
            return False
        if record.state is not LinkState.LIVE:
            return False
    statuses = {d.antibody_key: d.status for inf in receiver.inferences for d in inf.decisions}
    moved = [k for k in local if statuses.get(k, EchoStatus.REFUSED) is not EchoStatus.REFUSED]
    return not moved and not set(receiver.fabric.bridged_keys()) & local


def _fp_challenged(receiver: SimulatedReceiver, keys: frozenset[str]) -> bool:
    history = [(d.antibody_key, d.status) for inf in receiver.inferences for d in inf.decisions
               if d.antibody_key in keys]
    last = dict(history)
    never_eligible = all(status is not EchoStatus.ELIGIBLE for _, status in history)
    unbridged = not set(receiver.fabric.bridged_keys()) & keys
    return bool(last) and never_eligible and unbridged and all(
        last[k] is EchoStatus.CHALLENGED for k in keys if k in last)


def unanimous_evidence(corpus: FleetCorpus, receivers: tuple[str, ...], *,
                       seed: int) -> UnanimousEvidence:
    """Run UNANIMOUS_FLEET through the real fabric and Stage 6 bridge; judge every delivery."""
    sent: Counter[str] = Counter()
    held: Counter[str] = Counter()
    senders: dict[str, set[str]] = {h: set() for h in receivers}
    fp_keys: dict[str, set[str]] = {h: set() for h in receivers}

    def judge(delivery: Delivery, verdict: IngressVerdict | None) -> None:
        kind = _kind_of(delivery)
        sent[kind] += 1
        held[kind] += _held(kind, verdict)
        senders[delivery.receiver].add(delivery.sender)
        if kind == "support_fp" and delivery.poison_key is not None:
            fp_keys[delivery.receiver].add(delivery.poison_key)

    spec = FleetSpec(arm=AdversaryArm.UNANIMOUS_FLEET, rounds=UNANIMOUS_ROUNDS, seed=seed,
                     receivers=receivers)
    run = simulate(corpus, spec, with_stage6=True, on_verdict=judge)
    buckets: Counter[str] = Counter()
    challenged = intact = accepted = bridged = 0
    for host_id, receiver in run.receivers.items():
        keys = frozenset(fp_keys[host_id])
        challenged += bool(keys) and _fp_challenged(receiver, keys)
        intact += _local_intact(run, host_id, receiver)
        counts = receiver.fabric.revocations.counts()
        accepted += counts.get("accepted", 0) + counts.get("accepted_truncated", 0)
        if receiver.components.bridge is not None:
            bridged += receiver.components.bridge.admitted()
            buckets.update(receiver.components.bridge.buckets())
    return UnanimousEvidence(
        receivers=len(run.receivers), sent=tuple(sorted(sent.items())),
        held=tuple(sorted(held.items())),
        min_senders=min((len(s) for s in senders.values()), default=0),
        fp_exercised=sum(1 for k in fp_keys.values() if k), fp_challenged=challenged,
        local_intact=intact, revocations_accepted=accepted, bridged=bridged,
        buckets=tuple(sorted(buckets.items())),
    )


# --- one sample capsule per knowledge type (G7.2 fuzz, G7.7(b) field table) -------------------


def _sample_context(corpus: FleetCorpus, host_id: str) -> ExportContext:
    host = corpus.host(host_id)
    counts = Counter(s.relation_family for e in corpus.for_host(host_id, history=True)
                     for s in e.steps)
    return ExportContext(
        host_secret=_SAMPLE_SECRET, identity=host.identity, role=host.role,
        provenance_root="root-" + hashlib.sha256(b"gate-root").hexdigest()[:16],
        key_id="key-" + hashlib.sha256(b"gate-key").hexdigest()[:16], visibility_share=0.95,
        family_counts=dict(counts), fleet_scope="stage7-gate",
    )


def _type_fields(kind: KnowledgeType) -> dict[str, object]:
    extra: dict[str, object] = {}
    if kind in (KnowledgeType.CAMPAIGN_FRAGMENT, KnowledgeType.NEGATIVE_EVIDENCE):
        extra["time_window"] = (1, 3)
    if kind is KnowledgeType.NEGATIVE_EVIDENCE:
        extra["observability"] = ObservabilityClaim(0.9, 1.0, 0.5)
    if kind is KnowledgeType.REVOCATION:
        extra["revocation_target"] = "kc-" + hashlib.sha256(b"gate-target").hexdigest()[:24]
        extra["revocation_ground"] = RevocationGround.SELF_RETRACTION
    return extra


def capsule_samples(corpus: FleetCorpus) -> dict[KnowledgeType, KnowledgeCapsuleV1]:
    """One capsule of every knowledge type, built by the real compiler from a corpus incident."""
    incident = next((e for e in corpus.episodes if e.label == 1 and e.history
                     and oracle_motif(e.steps) is not None), None)
    if incident is None:
        raise ContractError("the corpus holds no history incident with an expressible motif")
    motif = oracle_motif(incident.steps) or ()
    invariant = tuple(MotifRow.from_motif_step(step) for step in motif)
    ledger = PrivacyLedger()
    samples: dict[KnowledgeType, KnowledgeCapsuleV1] = {}
    for sequence, kind in enumerate(KnowledgeType, start=1):
        samples[kind] = compile_capsule(
            knowledge_type=kind, invariant=() if kind is KnowledgeType.REVOCATION else invariant,
            evidence_digests=incident.evidence_digests[:MAX_EVIDENCE_COMMITMENTS],
            validation=ValidationSummary(episodes_replayed=12, true_matches=3, false_matches=0),
            falsification=FalsificationSummary(
                mutations_tried=8, mutations_survived=8,
                counter_hypotheses=COUNTER_HYPOTHESIS_VALUES[:2]),
            context=_sample_context(corpus, incident.host_id), ledger=ledger,
            created_round=2, sequence=sequence, **_type_fields(kind),  # type: ignore[arg-type]
        )
    return samples


# --- G7.9: a targeted, reversible self-retraction on a suite-built lineage ---------------------


@dataclass(frozen=True, slots=True)
class RevocationEvidence:
    target: str | None  # a foreign capsule with >= 2 generations of descendants
    accepted: bool
    reason: str
    affected_exact: bool  # affected == (target, *descendants) and every one now SUSPECT
    non_descendants_changed: int
    echo_keys_expected: tuple[str, ...]  # ECHO_DECISION keys under the target
    echo_keys_newly_suspect: tuple[str, ...]
    stage6_expected: tuple[str, ...]  # Stage 6 capsule ids of the STAGE6_LINKs beneath
    stage6_reported: tuple[str, ...]
    digest_restored: bool
    signature_valid: bool
    false_submitted: int = 0
    false_accepted: int = 0
    false_state_changes: int = 0
    note: str = ""


def _target(receiver: SimulatedReceiver) -> str | None:
    """A LIVE foreign capsule whose descendants hold a decision AND a Stage 6 link beneath it."""
    lineage, bridge = receiver.components.lineage, receiver.components.bridge
    for receipt in bridge.receipts() if bridge is not None else ():
        decision = lineage.get(receipt.decision_id)
        for parent in decision.parents if decision is not None else ():
            record = lineage.get(parent)
            if record is None or record.role is not NodeRole.FOREIGN_CAPSULE:
                continue
            below = [lineage.get(n) for n in lineage.descendants(parent)[0]]
            if record.state is LinkState.LIVE and any(
                    r is not None and r.role is NodeRole.STAGE6_LINK for r in below):
                return parent
    return None


def _self_retraction(run: SuiteRun, receiver: SimulatedReceiver,
                     target: str) -> tuple[KnowledgeCapsuleV1, str] | None:
    """The target's contributor retracting it: sealed, then signed with its own key."""
    pooled = next((p for p in receiver.pooled if p.capsule.capsule_id == target), None)
    if pooled is None:
        return None
    base = pooled.capsule
    keys = {k: (key, owner) for k, key, owner in run.fleet.key_directory(receiver.host_id)}
    if base.key_id not in keys:
        return None
    key, owner = keys[base.key_id]
    derived = {"capsule_id", "signature", "compact_feature_signature", "causal_motif",
               "schema_version"}
    payload = {f.name: getattr(base, f.name) for f in fields(base) if f.name not in derived}
    now = receiver.fabric.round_index
    payload.update(knowledge_type=KnowledgeType.REVOCATION, stance=Stance.SUPPORT,
                   semantic_invariant=(), parent_capsules=(),
                   provenance_commitment=replace(base.provenance_commitment,
                                                 aggregation_decision=None),
                   time_window=None, observability=None, revocation_target=target,
                   revocation_ground=RevocationGround.SELF_RETRACTION,
                   created_round=now, expiry_round=now + 1, sequence=base.sequence + 10**6)
    signer = Keyring(capacity=1)
    signer.register(base.key_id, key, owner=owner, round_index=0)
    return signer.sign(seal_capsule(**payload), key_id=base.key_id), owner


def _statuses(receiver: SimulatedReceiver) -> dict[str, EchoStatus]:
    return {d.antibody_key: d.status for d in receiver.inferences[-1].decisions} \
        if receiver.inferences else {}


def revocation_evidence(run: SuiteRun) -> RevocationEvidence:
    """Submit a real signed self-retraction to a receiver's real RevocationPlane, then undo it."""
    for receiver in run.receivers.values():
        target = _target(receiver)
        retraction = _self_retraction(run, receiver, target) if target else None
        if target is not None and retraction is not None:
            return _retract_and_reinstate(receiver, target, *retraction)
    return RevocationEvidence(None, False, "no_target", False, 0, (), (), (), (), False, False,
                              note="no foreign capsule with a decision and a Stage 6 link "
                                   "beneath it was built by the run")


def _retract_and_reinstate(receiver: SimulatedReceiver, target: str,
                           capsule: KnowledgeCapsuleV1, owner: str) -> RevocationEvidence:
    fabric, lineage = receiver.fabric, receiver.components.lineage
    signature = receiver.components.keyring.verify(capsule, round_index=fabric.round_index)
    before = {n: lineage.get(n).state for n in lineage.node_ids()}  # type: ignore[union-attr]
    descendants = lineage.descendants(target)[0]
    below = [r for n in descendants if (r := lineage.get(n)) is not None]
    echo_keys = tuple(sorted({r.detail for r in below if r.role is NodeRole.ECHO_DECISION}))
    stage6 = tuple(sorted({c for r in below if (c := r.stage6_capsule_id()) is not None}))
    statuses_before = _statuses(receiver)
    revocation = fabric.revocations.submit(capsule, sender_peer=owner,
                                           round_index=fabric.round_index)
    after = {n: lineage.get(n).state for n in lineage.node_ids()}  # type: ignore[union-attr]
    affected = set(revocation.affected)
    exact = (revocation.affected == (target, *descendants)
             and all(after[n] is LinkState.SUSPECT for n in affected if n in after))
    changed = sum(after.get(n) != s for n, s in before.items() if n not in affected)
    fabric.echo.infer(round_index=fabric.round_index)
    now = _statuses(receiver)
    newly = tuple(sorted(k for k, s in now.items() if s is EchoStatus.SUSPECT
                         and statuses_before.get(k) is not EchoStatus.SUSPECT))
    restored = fabric.revocations.reinstate(revocation.revocation_id)
    restored = restored and lineage.state_digest() == revocation.prior_digest
    return RevocationEvidence(
        target=target, accepted=revocation.accepted, reason=revocation.reason,
        affected_exact=exact, non_descendants_changed=changed, echo_keys_expected=echo_keys,
        echo_keys_newly_suspect=newly, stage6_expected=stage6,
        stage6_reported=tuple(sorted(revocation.stage6_capsule_ids)),
        digest_restored=restored, signature_valid=signature.valid,
        note=f"{len(descendants)} descendants; submitted to the fabric's own RevocationPlane "
             f"after the run (the ingress path is the FALSE_REVOCATION arm's)",
    )


def false_revocation_evidence(corpus: FleetCorpus, receivers: tuple[str, ...], *,
                              seed: int) -> tuple[int, int, int]:
    """FALSE_REVOCATION through the fabric: (revocations judged, accepted, nodes not LIVE)."""
    run = simulate(corpus, FleetSpec(arm=AdversaryArm.FALSE_REVOCATION, rounds=UNANIMOUS_ROUNDS,
                                     seed=seed, receivers=receivers))
    judged = accepted = changed = 0
    for receiver in run.receivers.values():
        counts = receiver.fabric.revocations.counts()
        judged += sum(counts.values())
        accepted += counts.get("accepted", 0) + counts.get("accepted_truncated", 0)
        lineage = receiver.components.lineage
        changed += sum(lineage.get(n).state is not LinkState.LIVE  # type: ignore[union-attr]
                       for n in lineage.node_ids())
    return judged, accepted, changed


# --- G7.10: the flood, the scale run and the resource envelope ---------------------------------


@dataclass(frozen=True, slots=True)
class FloodEvidence:
    resources: Stage7ResourceReport
    rounds: int
    identities: int
    over_cap: tuple[str, ...]  # "store@round count>cap" — must be empty
    at_cap: tuple[str, ...]  # stores that reached their cap during the flood (reported)
    keys_offered: int  # keys the flood fleet provisioned at the receiver (keyring cap: 1024)
    pressure: tuple[tuple[str, int], ...]  # eviction/refusal counters per store
    governor_refused: tuple[tuple[str, int], ...]
    outbound_over: tuple[str, ...]  # rounds whose outbound bytes exceeded the mode's cap
    deliveries: int
    scale: tuple[ScaleRow, ...] = field(default=())


def _pressure(receiver: SimulatedReceiver) -> dict[str, int]:
    """Eviction + refusal counters, keyed like :func:`store_caps` (replay's two stores share
    one guard, and so one counter)."""
    c = receiver.components
    replay = sum(c.replay.evictions())
    pool = sum(n for k, n in receiver.fabric.ingress.stats().items() if "pool_full" in k)
    return {"peers": c.peers.evictions() + c.peers.refused(), "keyring": receiver.keyring_refused,
            "graph": c.graph.evictions(), "replay_keys": replay, "replay_seen": replay,
            "trust": c.trust.evictions(), "lineage": c.lineage.evictions(), "pool": pool,
            "echo_keys": receiver.fabric.echo.keys_refused(), "novelty": c.novelty.evictions()}


@dataclass(slots=True)
class _FloodRun:
    """What the flood loop saw, filled inside the measured block."""

    receiver: SimulatedReceiver | None = None
    over: list[str] = field(default_factory=list)
    at_cap: set[str] = field(default_factory=set)
    outbound: list[str] = field(default_factory=list)
    deliveries: int = 0
    keys_offered: int = 0


def _flood_rounds(corpus: FleetCorpus, receiver_id: str, seed: int, identities: int,
                  seen: _FloodRun) -> Mapping[str, int]:
    spec = FleetSpec(arm=AdversaryArm.FLOOD, sybils_per_root=identities,
                     rounds=FLOOD_ROUNDS, seed=seed, receivers=(receiver_id,))
    fleet = SimulatedFleet(corpus, spec)
    receiver = seen.receiver = simulated_receiver(corpus, fleet, receiver_id)
    seen.keys_offered = len(fleet.key_directory(receiver_id))
    caps = store_caps()
    for r in range(FLOOD_ROUNDS):
        for d in fleet.round_traffic(r, visible_keys={}):
            receiver.fabric.deliver(d.data, sender=d.sender)
            seen.deliveries += 1
        budget = receiver.components.governor.budget()
        if budget.outbound_used > budget.outbound_cap:
            seen.outbound.append(f"round {r}: {budget.outbound_used}>{budget.outbound_cap}")
        receiver.fabric.run_round()
        tracked = receiver.inferences[-1].keys_tracked if receiver.inferences else 0
        for store, count in store_counts(receiver, tracked).items():
            if count > caps[store]:
                seen.over.append(f"{store}@{r} {count}>{caps[store]}")
            if count >= caps[store]:
                seen.at_cap.add(store)
    return receiver.fabric.memory_bytes()


def flood_evidence(corpus: FleetCorpus, receiver_id: str, *, seed: int,
                   scale: Callable[[], tuple[ScaleRow, ...]],
                   identities: int = FLOOD_IDENTITIES) -> FloodEvidence:
    """The FLOOD arm at ``identities`` (1000) simulated peers, then ``scale`` (the 10 000-peer
    run), under Stage 0's sampler. RSS is a dev-host in-process figure, never a device one."""
    seen = _FloodRun()
    rows: list[ScaleRow] = []

    def block() -> Mapping[str, int]:
        stores = dict(_flood_rounds(corpus, receiver_id, seed, identities, seen))
        rows.extend(scale())
        return stores

    report = measure_stage7_resources(block)
    receiver = seen.receiver
    if receiver is None:  # pragma: no cover - the block always builds it before returning
        raise ContractError("the flood block built no receiver")
    return FloodEvidence(
        resources=report, rounds=FLOOD_ROUNDS, identities=identities, over_cap=tuple(seen.over),
        at_cap=tuple(sorted(seen.at_cap)), keys_offered=seen.keys_offered, pressure=tuple(sorted(_pressure(receiver).items())),
        governor_refused=receiver.components.governor.budget().refused,
        outbound_over=tuple(seen.outbound), deliveries=seen.deliveries, scale=tuple(rows),
    )

