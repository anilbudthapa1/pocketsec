"""§4.22 — privacy attacks: leakage is MEASURED by attacking the export, never assumed absent.

"Raw telemetry stays local" is not a privacy result. What leaves the host is the field table
of ``privacy/distiller.py`` (ADR-0065): semantic bitmasks, coarse context, pseudonyms and keyed
commitments. This module attacks exactly that, beside the control a naive sharing design
would ship — Stage 6's own fleet-item format, raw ``EncodedStep`` records
(``raw_steps_control``) — so each figure has a baseline it must beat:

* :func:`canary_scan` searches exported bytes for every raw corpus string and every Stage 1
  evidence digest (the canaries are planted by ``labs/fleet_corpus.py``);
* :func:`membership_inference` asks "was THIS incident one the source exported?" given the
  source's export — by invariant match (distilled) or exact feature-sequence match (raw);
* :func:`property_inference` infers an UNDISCLOSED host property — does the host run the
  local database service, Stage 1 benign pattern [4] — by nearest centroid over the disclosed
  ``family_profile`` (distilled) or over raw feature vectors (control);
* :func:`dp_curve` measures the geometric mechanism on population counts (the ONLY release
  DP is claimed for): collective-novelty recall on true distributed novelty, and a
  count-membership attacker's advantage, per epsilon.

An advantage is ``TPR - FPR`` (membership) or ``accuracy - chance`` (property). ``None``
means NOT COMPUTED (e.g. no member/non-member pair exists), never 0.0. Every measurement
is synthetic (``synthetic=True``) and uses a SEEDED RNG, which voids the DP guarantee for the
run itself: the curve measures the mechanism's utility/leakage shape, not a deployment.

Also here, as probes for ``byzantine_suite.run_ablation``: collective novelty against
local-only novelty, secure (masked) summing against a plaintext per-cluster clamp, and DP
against exact counts. Each returns ``(metric, full, control, firing, lower_is_better)``.
"""

from __future__ import annotations

import json
import random
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.labs.corpus import BENIGN_PATTERNS
from pocketsec.stage7.aggregation.secure import aggregate_masked, mask_vector
from pocketsec.stage7.antibody.forge import matches
from pocketsec.stage7.capsule.knowledge_capsule import (
    ChainStage,
    KnowledgeCapsuleV1,
    KnowledgeType,
    RoleClass,
    VisibilityClass,
)
from pocketsec.stage7.graph.dependence import DependenceGraph
from pocketsec.stage7.identity.peer import PeerIdentity
from pocketsec.stage7.labs.fleet_corpus import (
    ROLE_BENIGN,
    AttackFamily,
    FleetCorpus,
    FleetEpisode,
    raw_scan_set,
)
from pocketsec.stage7.labs.simulated_fleet import (
    AdversaryArm,
    FleetSpec,
    HonestAntibody,
    SimulatedFleet,
    honest_antibodies,
    simulated_key_provisioning,
)
from pocketsec.stage7.novelty.collective import CollectiveNoveltyEngine, NoveltyStatus
from pocketsec.stage7.privacy.distiller import MAX_CANARY_REPORT, canary_hit_count, canary_hits
from pocketsec.stage7.privacy.ledger import PrivacyLedger, release_counts
from pocketsec.stage7.relevance.epistemic_distance import LocalContext

__all__ = [
    "DP_EPSILONS",
    "REPRESENTATIONS",
    "LeakageMeasurement",
    "canary_scan",
    "dp_ablation",
    "dp_curve",
    "membership_inference",
    "novelty_ablation",
    "property_inference",
    "secure_sum_ablation",
]

REPRESENTATIONS: tuple[str, ...] = ("distilled", "raw_steps_control")
DP_EPSILONS: tuple[float | None, ...] = (0.1, 0.5, 1.0, 2.0, None)
_NOVEL_PATTERNS = 4  # chosen: true distributed-novelty patterns per dp_curve trial
_COMMON_PATTERNS = 4  # chosen: routine-in-population patterns per trial
_DP_TRIALS = 16
_WINDOW = 16  # = NOVELTY_WINDOW_ROUNDS; reports fill one whole window
_SE_OLD = "se-" + "0" * 16  # an image first seen long before the window: not "fresh" (H1)
_ESCALATING = (ChainStage.CREDENTIAL, ChainStage.EGRESS)
_DB_PATTERN = BENIGN_PATTERNS[4]  # "local chatter": the undisclosed property under attack


@dataclass(frozen=True, slots=True)
class LeakageMeasurement:
    attack: str
    representation: str  # "distilled" | "raw_steps_control"
    trials: int
    advantage: float | None  # TPR - FPR, or accuracy - chance; None = NOT COMPUTED
    chance: float | None
    synthetic: bool = True


def _check(representation: str, trials: int) -> None:
    if representation not in REPRESENTATIONS:
        raise ContractError(
            f"representation must be one of {REPRESENTATIONS}, got {representation!r}")
    if isinstance(trials, bool) or not isinstance(trials, int) or trials < 1:
        raise ContractError(f"trials must be a positive int, got {trials!r}")


# --- canary scan -----------------------------------------------------------------------------


def canary_scan(corpus: FleetCorpus, exported: Sequence[bytes]) -> tuple[int, tuple[str, ...]]:
    """(hits, first names): every raw corpus string and Stage 1 digest, searched in the bytes.

    ``hits`` counts (blob, canary) occurrences; names are capped at ``MAX_CANARY_REPORT``.
    One joined pass first: most exports are clean and the per-blob pass is then skipped.
    """
    scan = sorted(raw_scan_set(corpus))
    blobs = [bytes(b) for b in exported]
    if not blobs or canary_hit_count(b"\x00".join(blobs), scan) == 0:
        return 0, ()
    hits, names = 0, list[str]()
    for blob in blobs:
        hits += canary_hit_count(blob, scan)
        for name in canary_hits(blob, scan):
            if name not in names and len(names) < MAX_CANARY_REPORT:
                names.append(name)
    return hits, tuple(names)


# --- membership inference ----------------------------------------------------------------------


def _incidents_by_family(corpus: FleetCorpus) -> dict[AttackFamily, list[FleetEpisode]]:
    grouped: dict[AttackFamily, list[FleetEpisode]] = {}
    for episode in corpus.episodes:
        if episode.label == 1 and episode.family is not None:
            grouped.setdefault(episode.family, []).append(episode)
    return grouped


def _features(steps: Sequence[object]) -> tuple[tuple[float, ...], ...]:
    return tuple(tuple(s.features) for s in steps)  # type: ignore[attr-defined]


def _raw_item(steps: Sequence[object]) -> bytes:
    """Stage 6's fleet item: the raw EncodedStep dicts (the control a naive design ships)."""
    rows = [s.to_dict() for s in steps]  # type: ignore[attr-defined]
    return json.dumps(rows, sort_keys=True).encode()


def _is_member_guess(representation: str, candidate: FleetEpisode, export: Sequence[bytes]) -> bool:
    if representation == "distilled":  # the attacker reads each capsule's invariant
        return any(matches(KnowledgeCapsuleV1.from_bytes(blob).semantic_invariant, candidate.steps)
                   for blob in export)
    target = _features(candidate.steps)  # nearest feature match: distance 0 means "seen"
    return any(tuple(tuple(s["features"]) for s in json.loads(blob)) == target for blob in export)


def _exports(corpus: FleetCorpus, representation: str) -> dict[str, list[bytes]]:
    """host -> exported blobs: its distilled capsules, or the raw steps of the same incidents."""
    fleet = SimulatedFleet(corpus, FleetSpec(arm=AdversaryArm.NONE))
    exports: dict[str, list[bytes]] = {}
    for item in honest_antibodies(corpus):
        if representation == "distilled":
            capsules = fleet.local_capsules(item.host_id)
            blob = next(c.canonical_bytes() for c in capsules
                        if c.compact_feature_signature == item.antibody.antibody_key)
        else:
            blob = _raw_item(item.incident.steps)
        exports.setdefault(item.host_id, []).append(blob)
    return exports


def membership_inference(corpus: FleetCorpus, *, representation: str, trials: int = 200,
                         seed: int = 0) -> LeakageMeasurement:
    """Was this candidate incident one the source host exported? Advantage = TPR - FPR.

    Members are the incidents a host forged its exported antibodies from; non-members are
    other incidents OF THE SAME FAMILY (so the attack cannot win on family alone).
    """
    _check(representation, trials)
    items: list[HonestAntibody] = list(honest_antibodies(corpus))
    by_family = _incidents_by_family(corpus)
    exported_ids = {(i.host_id, i.incident.incident_id) for i in items}
    exports = _exports(corpus, representation)
    rng, tp, fp, pos, neg = random.Random(f"membership:{seed}"), 0, 0, 0, 0
    for _ in range(trials):
        item = items[rng.randrange(len(items))] if items else None
        if item is None:
            break
        if rng.random() < 0.5:
            candidate = next(e for e in corpus.episodes if e.host_id == item.host_id
                             and f"{e.host_id}-e{e.index:03d}" == item.incident.incident_id)
            pos += 1
            tp += _is_member_guess(representation, candidate, exports[item.host_id])
            continue
        pool = [e for e in by_family.get(item.family, [])
                if (item.host_id, f"{e.host_id}-e{e.index:03d}") not in exported_ids]
        if pool:
            neg += 1
            fp += _is_member_guess(representation, pool[rng.randrange(len(pool))],
                                   exports[item.host_id])
    advantage = tp / pos - fp / neg if pos and neg else None
    return LeakageMeasurement("membership_inference", representation, pos + neg, advantage, 0.0)


# --- property inference ------------------------------------------------------------------------


def _host_vector(corpus: FleetCorpus, host_id: str, representation: str,
                 fleet: SimulatedFleet) -> tuple[float, ...] | None:
    if representation == "distilled":  # only what the wire discloses: the quantised profile
        capsules = fleet.local_capsules(host_id)
        if not capsules:
            return None
        return tuple(float(v) for v in capsules[0].source_context_sketch.family_profile)
    steps = [s for e in corpus.for_host(host_id, history=True) for s in e.steps]
    if not steps:
        return None
    width = len(steps[0].features)
    return tuple(sum(s.features[i] for s in steps) / len(steps) for i in range(width))


def _nearest(vector: tuple[float, ...], centroids: dict[bool, tuple[float, ...]]) -> bool:
    return min(sorted(centroids), key=lambda k: sum(abs(a - b) for a, b in zip(vector, centroids[k],
                                                                             strict=True)))


def _centroids(samples: Sequence[tuple[tuple[float, ...], bool]]) -> dict[bool, tuple[float, ...]]:
    out = {}
    for label in (False, True):
        members = [v for v, y in samples if y is label]
        if members:
            out[label] = tuple(sum(col) / len(members) for col in zip(*members, strict=True))
    return out


def property_inference(corpus: FleetCorpus, *, representation: str, trials: int = 200,
                       seed: int = 0) -> LeakageMeasurement:
    """Infer whether a host runs the local database service (pattern [4]), never disclosed.

    EXHAUSTIVE leave-one-host-out nearest centroid over ``family_profile`` (distilled) or the
    mean raw feature vector of the host's history steps (control): every host is predicted
    exactly once, so ``trials`` in the result is the number of hosts n, and chance is THIS
    representation's own majority-class share (a host with no export has no vector, so the
    two rows can have different n and different chance). Review finding F8: the earlier
    "200 trials" were with-replacement resamples of these n deterministic predictions, i.e.
    resampling noise over ~22 hosts. ``trials`` and ``seed`` are accepted and ignored: the
    measurement is deterministic.
    """
    _check(representation, trials)
    fleet = SimulatedFleet(corpus, FleetSpec(arm=AdversaryArm.NONE))
    samples = [(v, _DB_PATTERN in ROLE_BENIGN[h.role]) for h in corpus.hosts
               if (v := _host_vector(corpus, h.host_id, representation, fleet)) is not None]
    labels = Counter(y for _, y in samples)
    if len(labels) < 2:
        return LeakageMeasurement("property_inference", representation, 0, None, None)
    chance = max(labels.values()) / len(samples)
    correct = 0
    for index in range(len(samples)):
        centroids = _centroids(samples[:index] + samples[index + 1:])
        if len(centroids) < 2:
            return LeakageMeasurement("property_inference", representation, 0, None, chance)
        correct += _nearest(samples[index][0], centroids) is samples[index][1]
    return LeakageMeasurement("property_inference", representation, len(samples),
                              correct / len(samples) - chance, chance)


# --- the DP curve on population counts (the only DP claim, ADR-0065) -------------------------


def _local(role: RoleClass) -> LocalContext:
    return LocalContext(role=role, software_epoch=_SE_OLD, visibility=VisibilityClass.FULL,
                        family_profile=(0,) * 8, local_keys=frozenset(),
                        observable_relations=frozenset())


def _novelty_trial(epsilon: float | None, rng: random.Random, *,
                   enabled: bool = True) -> dict[str, NoveltyStatus]:
    """One window: novel patterns seen by 2 hosts in the population, common ones by 3 per round.

    Each pattern is reported by two clusters every round; the per-round population count is
    released through ``release_counts`` (exact or geometric noise). The ledger is sized for the
    window's releases: the default budget would refuse them, which S7X-52 measures separately.
    """
    engine = CollectiveNoveltyEngine(local=_local(RoleClass.WEB), enabled=enabled)
    engine.note_epoch(_SE_OLD, 0)
    novel = [f"mf-novel{i:011x}" for i in range(_NOVEL_PATTERNS)]
    common = [f"mf-common{i:010x}" for i in range(_COMMON_PATTERNS)]
    sightings = {p: set(rng.sample(range(_WINDOW), 2)) for p in novel}
    ledger = PrivacyLedger(epsilon_budget=(epsilon or 0.0) * _WINDOW + 1.0,
                           window_rounds=_WINDOW * 4)
    start = _WINDOW  # the window [16, 31]: the image was first seen at round 0
    for offset in range(_WINDOW):
        r = start + offset
        for pattern in (*novel, *common):
            for cluster in ("cl-" + "a" * 16, "cl-" + "b" * 16):
                engine.observe_report(pattern, stages=_ESCALATING, cluster_id=cluster,
                                      software_epoch=_SE_OLD, round_index=r)
        counts = {p: int(offset in sightings[p]) for p in novel} | {p: 3 for p in common}
        released = release_counts(counts, epsilon=epsilon, ledger=ledger,
                                  recipient_scope="simulated-population", round_index=r, rng=rng)
        engine.observe_population(released, role=RoleClass.WEB, round_index=r)
    return {n.pattern_key: n.status for n in engine.evaluate(round_index=start + _WINDOW - 1)}


def _recall_and_false(statuses: Sequence[dict[str, NoveltyStatus]]) -> tuple[float, float]:
    novel = [s[k] for s in statuses for k in s if k.startswith("mf-novel")]
    common = [s[k] for s in statuses for k in s if k.startswith("mf-common")]
    flagged = NoveltyStatus.COLLECTIVELY_NOVEL
    return (sum(x is flagged for x in novel) / len(novel) if novel else 0.0,
            sum(x is flagged for x in common) / len(common) if common else 0.0)


def _count_membership_advantage(epsilon: float | None, rng: random.Random,
                                trials: int = 400) -> float:
    """Attacker knows the count without the target (c0) and sees one release y; guesses
    'member' iff y > c0. Advantage = TPR - FPR (1.0 for exact counts)."""
    ledger = PrivacyLedger(epsilon_budget=(epsilon or 0.0) * trials + 1.0, max_releases=trials + 1,
                           window_rounds=trials + 1)
    tp = fp = pos = neg = 0
    for trial in range(trials):
        member = trial % 2 == 0
        c0 = 5
        released = release_counts({"mf-" + "c" * 16: c0 + int(member)}, epsilon=epsilon,
                                  ledger=ledger, recipient_scope="simulated-attack",
                                  round_index=trial, rng=rng)
        guess = released["mf-" + "c" * 16] > c0
        pos, neg = pos + member, neg + (not member)
        tp, fp = tp + (guess and member), fp + (guess and not member)
    return tp / pos - fp / neg


def dp_curve(corpus: FleetCorpus, *, epsilons: Sequence[float | None] = DP_EPSILONS,
             seed: int = 0) -> tuple[tuple[float | None, float | None, float | None], ...]:
    """(epsilon, collective-novelty recall on true distributed novelty, count-membership
    advantage). ``None`` epsilon is the exact-count control. SEEDED: not itself private."""
    if not isinstance(corpus, FleetCorpus):
        raise ContractError("dp_curve needs a FleetCorpus")
    curve = []
    for epsilon in epsilons:
        rng = random.Random(f"dp:{seed}:{epsilon}")
        recall, _ = _recall_and_false([_novelty_trial(epsilon, rng) for _ in range(_DP_TRIALS)])
        curve.append((epsilon, recall, _count_membership_advantage(epsilon, rng)))
    return tuple(curve)


# --- ablation probes: (metric, full, control, firing, lower_is_better) -------------------------

Probe = tuple[str, float | None, float | None, int, bool]


def fabric_novelty_firing(receivers: Iterable[object]) -> int:
    """How often collective novelty can act on the FABRIC path of a real run: NOVELTY capsules
    pooled by the receivers. (No runtime code calls ``observe_population`` either.) Review
    finding F4: the probes below never touch the fabric, so their firing is not this one."""
    return sum(
        p.capsule.knowledge_type is KnowledgeType.NOVELTY  # type: ignore[attr-defined]
        for r in receivers for p in r.pooled  # type: ignore[attr-defined]
    )


def novelty_ablation(corpus: FleetCorpus, *, seed: int = 0) -> Probe:
    """S7X-38 vs S7X-39: false-novel rate on patterns routine in the population (lower is
    better), collective vs local-only novelty. Firing = statuses that differ.

    A TOY CONSTRUCTION (F4): ``corpus`` is unused; 4 novel and 4 common hand-authored patterns
    are all first sighted inside the window, so the local-only control flags every common
    pattern by definition. It shows the mechanism can fire, not that it fires on the fleet."""
    rng_full, rng_ctrl = random.Random(f"nov:{seed}"), random.Random(f"nov:{seed}")
    full = [_novelty_trial(None, rng_full) for _ in range(_DP_TRIALS)]
    control = [_novelty_trial(None, rng_ctrl, enabled=False) for _ in range(_DP_TRIALS)]
    firing = sum(a[k] is not b.get(k) for a, b in zip(full, control, strict=True) for k in a)
    (recall_f, false_f), (recall_c, false_c) = _recall_and_false(full), _recall_and_false(control)
    metric = (f"false-novel rate on population-routine patterns (novel recall {recall_f:.3f} "
              f"collective vs {recall_c:.3f} local-only)")
    return metric, false_f, false_c, firing, True


def dp_ablation(corpus: FleetCorpus, *, seed: int = 0) -> Probe:
    """Geometric noise at epsilon 1.0 vs exact counts: count-membership advantage (lower is
    better), with the utility cost in the metric text. Firing = statuses the noise changed.

    A TOY CONSTRUCTION on the same corpus-free window as :func:`novelty_ablation` (F4), and a
    TRADE-OFF, not a win: the advantage falls because noise is added (monotone in the knob,
    lesson 4) while novel recall collapses; the metric text carries both."""
    rng = random.Random(f"dpab:{seed}")
    noisy = [_novelty_trial(1.0, random.Random(f"dpab:{seed}:{t}")) for t in range(_DP_TRIALS)]
    exact = [_novelty_trial(None, random.Random(f"dpab:{seed}:{t}")) for t in range(_DP_TRIALS)]
    firing = sum(a[k] is not b.get(k) for a, b in zip(noisy, exact, strict=True) for k in a)
    recall_n, recall_e = _recall_and_false(noisy)[0], _recall_and_false(exact)[0]
    metric = (f"count-membership advantage at eps=1.0 (novel recall {recall_n:.3f} vs "
              f"{recall_e:.3f} exact)")
    return (metric, _count_membership_advantage(1.0, rng), _count_membership_advantage(None, rng),
            firing, True)


def secure_sum_ablation(corpus: FleetCorpus, *, seed: int = 0, sybils: int = 16) -> Probe:
    """Novelty-count inflation under SYBIL_FORGED_ROOTS: masked sum vs plaintext + clamp.

    Participants are round-0 senders of a real SYBIL_FORGED_ROOTS fleet; their dependence
    clusters come from a real ``DependenceGraph``. Two honest hosts saw the pattern; every
    Sybil claims it. The masked sum hides per-participant vectors, so no cluster clamp is
    possible: inflation = total / true count. Lower is better. Firing = rounds summed.
    """
    fleet = SimulatedFleet(corpus, FleetSpec(arm=AdversaryArm.SYBIL_FORGED_ROOTS,
                                             sybils_per_root=sybils, rounds=1, seed=seed))
    receiver, graph = fleet.receivers[0], DependenceGraph()
    senders: dict[str, str] = {}
    for delivery in fleet.round_traffic(0, visible_keys={}):
        if delivery.receiver != receiver:
            continue
        capsule = KnowledgeCapsuleV1.from_bytes(delivery.data)
        commitment = capsule.provenance_commitment
        peer = PeerIdentity(commitment.contributor, capsule.key_id, commitment.provenance_root,
                            capsule.source_context_sketch.role, 0, 0)
        senders[commitment.contributor] = graph.observe(capsule, peer, round_index=0)
    adversaries = fleet.ground_truth().adversary_peers
    honest = sorted(p for p in senders if p not in adversaries)[:2]
    claims = {p: int(p in honest or p in adversaries) for p in senders}
    true_total = sum(claims[p] for p in honest)
    keys = simulated_key_provisioning(sorted(senders), sorted(senders), seed=seed)
    vectors = [mask_vector([claims[p]], participant=p, round_index=0,
                           pair_keys={q: keys[(min(p, q), max(p, q))] for q in senders if q != p})
               for p in sorted(senders)]
    result = aggregate_masked(vectors, expected=frozenset(senders), round_index=0)
    clamped = sum(min(1, sum(claims[p] for p in senders if graph.cluster_of(p) == c))
                  for c in {graph.cluster_of(p) for p in senders})
    secure_total = result.total[0] if result.total is not None else None
    full = secure_total / true_total if secure_total is not None and true_total else None
    control = clamped / true_total if true_total else None
    return ("novelty-count inflation (total / true) under SYBIL_FORGED_ROOTS",
            full, control, 0 if result.aborted else 1, True)
