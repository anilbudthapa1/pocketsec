"""D7.9 runner — the Byzantine evidence suite: every aggregator, every arm, identical pools.

A robustness claim is only a comparison if every mechanism saw the same input (lesson 4).
For each (arm, adversary share or Sybil count) this runner generates the simulated fleet's
traffic ONCE, ingests it once per receiver through a real ``OrpheusFabric`` (HIVELOCK ingress,
dependence graph, ECHO, revocation plane, campaign engines and, with ``with_stage6``, a real
``Stage6Bridge`` into the lab Stage 6 gateway), and then evaluates EVERY identity aggregator
of ``aggregation.robust`` — plain and "+LV" — on the very pool that fabric pooled. ECHO's
figure is the fabric's own ELIGIBLE set, never a re-implementation of it.

**Measurement boundary (spec §0).** Stage 6 admits no foreign capsule today (M0.2, B7-1), so
acceptance is measured at Stage 7's own output: a key is *accepted* by an aggregator at a
receiver in the first round it is in that aggregator's accepted set (the fabric bridges a key
once; an accepted key is acted on once). Detection figures are
``counterfactual_at_boundary``: each receiver's held-out episodes are scored by Stage 6's
``match_motif`` over its local antibodies (NO_SHARING) and over local + accepted, and recall
comes from Stage 0's ``recall_at_max_fpr`` at :data:`FPR_BUDGET`. Recall is over held-out
attacks of the families the receiver never saw locally; FP rate over all held-out benign.

**Two lab observation taps, declared.** The fabric exposes no per-round inference or pool
accessor, so :func:`simulated_receiver` wraps ``fabric.echo.infer`` and
``fabric.ingress.drain_pool`` on the instance: each tap returns exactly what it wrapped and
keeps a bounded copy. Nothing is altered; no runtime module is aware of it.

**Refusals.** The suite refuses to run past a BLOCKED fleet precondition (P1-P4), and it never
writes ``experiments/registry.jsonl``: registration is an explicit CLI act. Everything here is
synthetic and simulated, and the defences, the attacks and the ground truth share an author
(lesson 6): these are construction and mechanism figures, not deployment evidence.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace

from pocketsec.stage0.benchmark.security_metrics import confusion_at_threshold, recall_at_max_fpr
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage6.resources import loadavg
from pocketsec.stage7.aggregation.robust import (
    Aggregator,
    aggregate,
    plus_local_validation,
    stance_matrix,
)
from pocketsec.stage7.antibody.forge import (
    BenignRing,
    KnowledgeAntibody,
    LocalIncident,
    LocalValidation,
    matches,
)
from pocketsec.stage7.capsule.knowledge_capsule import KnowledgeType, MotifRow, Stance
from pocketsec.stage7.echo.inference import EchoConfig, EchoStatus
from pocketsec.stage7.hivelock.ingress import IngressOutcome, PooledCapsule
from pocketsec.stage7.labs.fleet_corpus import (
    FleetCorpus,
    FleetEpisode,
    Precondition,
    fleet_preconditions,
)
from pocketsec.stage7.labs.partition import (
    SimulatedReceiver,
    SuiteRun,
    _validator,
    replay_with,
    simulate,
)
from pocketsec.stage7.labs.simulated_fleet import (
    SUITE_ROUNDS,
    AdversaryArm,
    FleetGroundTruth,
    FleetSpec,
)
from pocketsec.stage7.trust.contextual import TRUST_PRIOR

__all__ = [
    "BREAK_LEVEL",
    "DETECTION_GAIN_MIN",
    "FEED_LAG_ROUNDS",
    "FPR_BUDGET",
    "SHARES",
    "SUITE_ARMS",
    "SYBIL_ARMS",
    "SYBIL_COUNTS",
    "AblationRow",
    "BreakPoint",
    "ByzantineReport",
    "SuiteRow",
    "ablation_row",
    "accepted_keys",
    "break_points",
    "detection",
    "echo_metric",
    "evaluate_run",
    "run_ablation",
    "run_byzantine_suite",
    "run_firing",
    "siem_oracle",
    "threshold_sensitivity",
]

# --- parameters: chosen, not measured (spec §4.23) -----------------------------------------
FPR_BUDGET: float = 0.01
SHARES: tuple[float, ...] = (0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6)
SYBIL_COUNTS: tuple[int, ...] = (1, 2, 4, 8, 16, 32, 64, 128)
BREAK_LEVEL: float = 0.5
DETECTION_GAIN_MIN: float = 0.10
FEED_LAG_ROUNDS: int = 4

SYBIL_ARMS = frozenset({
    AdversaryArm.SYBIL_DECLARED_ROOT, AdversaryArm.SYBIL_FORGED_ROOTS,
    AdversaryArm.SYBIL_ADAPTIVE,
})
SUITE_ARMS: tuple[AdversaryArm, ...] = (
    AdversaryArm.NONE, *sorted(SYBIL_ARMS), AdversaryArm.BYZANTINE_POISON,
    AdversaryArm.BYZANTINE_LATENT_POISON, AdversaryArm.BYZANTINE_SUPPRESS,
    AdversaryArm.SLOW_POISON, AdversaryArm.COLLUSION_TIMING,
)
_SWEEP_ONCE = frozenset({  # arms with no share knob: one run at the arm's own layout
    AdversaryArm.NONE, AdversaryArm.UNANIMOUS_FLEET, AdversaryArm.FLOOD, AdversaryArm.REPLAY,
    AdversaryArm.FALSE_REVOCATION, AdversaryArm.LINEAGE_TAMPER, AdversaryArm.AUTHORITY_INJECTION,
})
_IDENTITY_METHODS: tuple[Aggregator, ...] = tuple(a for a in Aggregator if a is not Aggregator.ECHO)
_OK = frozenset({LocalValidation.PASS, LocalValidation.LOCAL_CONFIRMED})


@dataclass(frozen=True, slots=True)
class SuiteRow:
    arm: str
    aggregator: str
    lv: bool
    adversary_share: float  # root share; for Sybil arms the adversary's IDENTITY share
    sybils_per_root: int
    poison_offered: int  # (receiver, poison key) pairs supported in the pool
    poison_accepted: int
    true_offered: int  # (receiver, true foreign key) pairs supported in the pool
    true_accepted: int
    recall_no_sharing: float | None  # counterfactual_at_boundary
    recall_collective: float | None  # counterfactual_at_boundary
    fp_rate_collective: float | None
    amplification: float | None
    stage6_trusted_candidates: int


@dataclass(frozen=True, slots=True)
class BreakPoint:
    arm: str
    aggregator: str
    lv: bool
    share: float | None  # smallest share with poison acceptance >= BREAK_LEVEL; None = none


@dataclass(frozen=True, slots=True)
class AblationRow:
    core_id: str
    flag: str
    control: str
    metric: str
    full_value: float | None
    control_value: float | None
    delta: float | None
    firing_count: int
    verdict: str  # JUSTIFIED | NOT_YET_JUSTIFIED | HARMFUL | INERT


@dataclass(frozen=True, slots=True)
class ByzantineReport:
    rows: tuple[SuiteRow, ...]
    break_points: tuple[BreakPoint, ...]
    ablations: tuple[AblationRow, ...]
    threshold_sensitivity: tuple[tuple[str, float, float], ...]  # (param, flip x0.5, flip x2)
    firing: tuple[tuple[str, int], ...]
    preconditions: tuple[Precondition, ...]
    loadavg: tuple[float, float, float]
    synthetic: bool = True
    time_to_detect: tuple[tuple[str, float | None], ...] = ()  # arm NONE, rounds, per method


# --- acceptance per method ------------------------------------------------------------------------


def _antibody_pool(receiver: SimulatedReceiver, round_index: int) -> list[PooledCapsule]:
    return [p for p in receiver.pooled
            if p.received_round <= round_index and p.capsule.expiry_round > round_index
            and p.capsule.knowledge_type is KnowledgeType.ANTIBODY]


def _invariants(receiver: SimulatedReceiver) -> dict[str, tuple[MotifRow, ...]]:
    return {p.capsule.compact_feature_signature: p.capsule.semantic_invariant
            for p in receiver.pooled if p.capsule.knowledge_type is KnowledgeType.ANTIBODY}


def _local_ok(receiver: SimulatedReceiver) -> Callable[[str], bool]:
    rows, cache = _invariants(receiver), dict[str, bool]()

    def ok(key: str) -> bool:
        if key not in cache:
            invariant = rows.get(key)
            cache[key] = invariant is not None and (
                receiver.components.validator.validate(invariant) in _OK)
        return cache[key]
    return ok


def _feed_root(receiver: SimulatedReceiver, truth: FleetGroundTruth) -> str | None:
    """The honest declared root supporting the most distinct keys: the 'curated feed'."""
    support: dict[str, set[str]] = {}
    for p in receiver.pooled:
        if p.peer_id not in truth.adversary_peers and p.capsule.stance is Stance.SUPPORT:
            root = p.capsule.provenance_commitment.provenance_root
            support.setdefault(root, set()).add(p.capsule.compact_feature_signature)
    return max(sorted(support), key=lambda r: len(support[r])) if support else None


def accepted_keys(run: SuiteRun, method: Aggregator, *,
                  lv: bool = False) -> dict[str, dict[str, int]]:
    """receiver -> antibody key -> the first round ``method`` accepted it."""
    result: dict[str, dict[str, int]] = {}
    for host_id, receiver in run.receivers.items():
        first: dict[str, int] = {}
        if method is Aggregator.ECHO:
            for inference in receiver.inferences:
                for decision in inference.decisions:
                    if decision.status is EchoStatus.ELIGIBLE:
                        first.setdefault(decision.antibody_key, inference.round_index)
            result[host_id] = first
            continue
        local_ok = _local_ok(receiver)
        clusters = {p.peer_id: receiver.components.graph.cluster_of(p.peer_id)
                    for p in receiver.pooled}
        feed = _feed_root(receiver, run.truth)
        for round_index in range(run.spec.rounds):
            lag = FEED_LAG_ROUNDS if method is Aggregator.CENTRAL_FEED else 0
            seen = round_index - lag
            pool = _antibody_pool(receiver, seen) if seen >= 0 else []
            if not pool:
                continue
            outcome = aggregate(stance_matrix(pool), method, clusters=clusters, local_ok=local_ok,
                                feed_root=feed)
            if lv:
                outcome = plus_local_validation(outcome, local_ok)
            for key in outcome.accepted:
                first.setdefault(key, round_index)
        result[host_id] = first
    return result


# --- metrics -----------------------------------------------------------------------------------


def _supported(receiver: SimulatedReceiver) -> dict[str, int]:
    """key -> first round a SUPPORT for it was pooled at this receiver."""
    first: dict[str, int] = {}
    for p in receiver.pooled:
        capsule = p.capsule
        if capsule.knowledge_type is KnowledgeType.ANTIBODY and capsule.stance is Stance.SUPPORT:
            first.setdefault(p.capsule.compact_feature_signature, p.received_round)
    return first


def _true_keys(truth: FleetGroundTruth) -> frozenset[str]:
    return frozenset(k for keys in truth.true_keys_by_family.values() for k in keys)


def detection(run: SuiteRun, accepted: Mapping[str, Iterable[str]] | None
              ) -> tuple[float | None, float | None]:
    """(recall at FPR_BUDGET on locally-unseen families, FP rate), micro over receivers.

    ``accepted`` None scores local antibodies only (NO_SHARING). counterfactual_at_boundary.
    """
    labels: list[int] = []
    scores: list[float] = []
    corpus = run.fleet.corpus
    for host_id, receiver in run.receivers.items():
        local = [a.antibody.invariant for a in run.fleet.local_antibodies(host_id)]
        rows = _invariants(receiver)
        foreign = [rows[k] for k in (accepted or {}).get(host_id, ()) if k in rows]
        seen = corpus.host(host_id).families_local
        for episode in corpus.for_host(host_id, history=False):
            if episode.label == 1 and episode.family in seen:
                continue  # detection gain is about families this host never saw
            labels.append(episode.label)
            scores.append(1.0 if _scores(episode, local + foreign) else 0.0)
    recall, _ = recall_at_max_fpr(labels, scores, FPR_BUDGET) if labels else (None, None)
    confusion = confusion_at_threshold(labels, scores, 1.0) if labels else None
    return recall, (confusion.false_positive_rate if confusion else None)


def _scores(episode: FleetEpisode, invariants: Sequence[tuple[MotifRow, ...]]) -> bool:
    return any(matches(rows, episode.steps) for rows in invariants)


def _amplification(run: SuiteRun, method: Aggregator,
                   accepted: Mapping[str, Mapping[str, int]]) -> float | None:
    """(adversary share of accepted support mass) / (adversary share of TRUE roots)."""
    truth = run.truth
    total_roots = truth.adversary_roots + truth.honest_roots
    if truth.adversary_roots == 0 or total_roots == 0:
        return None
    adversary = total = 0.0
    for host_id, receiver in run.receivers.items():
        keys = accepted.get(host_id, {})
        if method is Aggregator.ECHO:
            peer_of = {p.capsule.capsule_id: p.peer_id for p in receiver.pooled}
            for inference in receiver.inferences:
                for decision in inference.decisions:
                    if keys.get(decision.antibody_key) != inference.round_index:
                        continue  # the mass at the moment of first acceptance only
                    for row in decision.evidence:
                        if row.stance is Stance.SUPPORT and row.capsule_ids:
                            bad = sum(peer_of.get(c) in truth.adversary_peers
                                      for c in row.capsule_ids)
                            adversary += row.mass * bad / len(row.capsule_ids)
                            total += row.mass
            continue
        voters = {(p.peer_id, p.capsule.compact_feature_signature) for p in _antibody_pool(
            receiver, run.spec.rounds - 1) if p.capsule.stance is Stance.SUPPORT}
        for peer, key in voters:
            if key in keys:
                total += 1.0
                adversary += peer in truth.adversary_peers
    if total == 0.0:
        return None
    return (adversary / total) / (truth.adversary_roots / total_roots)


def _share_of(run: SuiteRun) -> float:
    if run.spec.arm in SYBIL_ARMS:
        adversaries = len(run.truth.adversary_peers)
        honest = len(run.truth.true_root_of) - adversaries
        return adversaries / (adversaries + honest) if adversaries + honest else 0.0
    return float(run.spec.adversary_share)


def _trusted_candidates(run: SuiteRun) -> int:
    return sum(r.trusted_candidates for rx in run.receivers.values()
               if rx.components.bridge is not None for r in rx.components.bridge.receipts())


def evaluate_run(run: SuiteRun) -> tuple[SuiteRow, ...]:
    """Every method (+LV) on this run's identical pools, plus ECHO's own ELIGIBLE set."""
    poison, true = run.truth.poison_keys, _true_keys(run.truth)
    supported = {h: _supported(r) for h, r in run.receivers.items()}
    local = {h: {a.antibody.antibody_key for a in run.fleet.local_antibodies(h)}
             for h in run.receivers}
    base_recall, _ = detection(run, None)
    share, rows = _share_of(run), []
    plans = [(m, lv) for m in _IDENTITY_METHODS for lv in (False, True)]
    plans.append((Aggregator.ECHO, False))
    for method, lv in plans:
        accepted = accepted_keys(run, method, lv=lv)
        counts = Counter[str]()
        for host_id, offered in supported.items():
            foreign_true = (true & offered.keys()) - local[host_id]
            counts["po"] += len(poison & offered.keys())
            counts["pa"] += len(poison & accepted[host_id].keys())
            counts["to"] += len(foreign_true)
            counts["ta"] += len(foreign_true & accepted[host_id].keys())
        recall, fp = detection(run, accepted)
        rows.append(SuiteRow(
            arm=run.spec.arm.value, aggregator=method.value, lv=lv, adversary_share=share,
            sybils_per_root=run.spec.sybils_per_root, poison_offered=counts["po"],
            poison_accepted=counts["pa"], true_offered=counts["to"], true_accepted=counts["ta"],
            recall_no_sharing=base_recall, recall_collective=recall, fp_rate_collective=fp,
            amplification=_amplification(run, method, accepted),
            stage6_trusted_candidates=_trusted_candidates(run) if method is Aggregator.ECHO else 0,
        ))
    return tuple(rows)


def run_firing(run: SuiteRun) -> Counter[str]:
    """How often each mechanism changed an outcome in this run (lesson 1: 0 = INERT)."""
    firing: Counter[str] = Counter()
    for receiver in run.receivers.values():
        for inference in receiver.inferences:
            firing.update({f"echo:{name}": count for name, count in inference.firing})
        for kind, count in receiver.components.graph.merges_by_kind().items():
            firing[f"graph_merge:{kind.value}"] += count
        firing["gravity_triaged"] += receiver.verdicts[IngressOutcome.METADATA_ONLY.value]
        bridge = receiver.components.bridge
        if bridge is not None:
            firing["bridge_created"] += bridge.created()
            firing["bridge_admitted"] += bridge.admitted()
            firing.update({f"stage6:{b}": n for b, n in bridge.buckets().items()})
    return firing


def break_points(rows: Sequence[SuiteRow]) -> tuple[BreakPoint, ...]:
    """Per (arm, aggregator, lv): the smallest share whose poison acceptance >= BREAK_LEVEL."""
    groups: dict[tuple[str, str, bool], list[SuiteRow]] = {}
    for row in rows:
        groups.setdefault((row.arm, row.aggregator, row.lv), []).append(row)
    points = []
    for (arm, method, lv), members in sorted(groups.items()):
        broken = [r.adversary_share for r in sorted(members, key=lambda r: r.adversary_share)
                  if r.poison_offered > 0 and r.poison_accepted / r.poison_offered >= BREAK_LEVEL]
        points.append(BreakPoint(arm, method, lv, broken[0] if broken else None))
    return tuple(points)


def _time_to_detect(run: SuiteRun) -> tuple[tuple[str, float | None], ...]:
    """Mean rounds from a true key's first pooled SUPPORT to acceptance, per method."""
    true, out = _true_keys(run.truth), []
    for method in (Aggregator.ECHO, *_IDENTITY_METHODS):
        accepted, delays = accepted_keys(run, method), []
        for host_id, receiver in run.receivers.items():
            offered = _supported(receiver)
            delays += [accepted[host_id][k] - offered[k] for k in accepted[host_id]
                       if k in true and k in offered]
        out.append((method.value, sum(delays) / len(delays) if delays else None))
    return tuple(out)


def _refuse_blocked(preconditions: Sequence[Precondition]) -> None:
    blocked = [p for p in preconditions if p.status == "BLOCKED"]
    if blocked:
        raise ContractError("the suite refuses to run past a BLOCKED precondition: "
                            + "; ".join(f"{p.name}: {p.detail}" for p in blocked))


def _specs(arm: AdversaryArm, shares: Sequence[float], sybil_counts: Sequence[int], rounds: int,
           seed: int, receivers: tuple[str, ...]) -> list[FleetSpec]:
    if arm in SYBIL_ARMS:
        return [FleetSpec(arm=arm, sybils_per_root=s, rounds=rounds, seed=seed, receivers=receivers)
                for s in sybil_counts]
    shares = (0.0,) if arm in _SWEEP_ONCE else shares
    return [FleetSpec(arm=arm, adversary_share=x, rounds=rounds, seed=seed, receivers=receivers)
            for x in shares]


def run_byzantine_suite(corpus: FleetCorpus, *, arms: Sequence[AdversaryArm] = SUITE_ARMS,
                        shares: Sequence[float] = SHARES,
                        sybil_counts: Sequence[int] = SYBIL_COUNTS,
                        rounds: int = SUITE_ROUNDS, seed: int = 0, with_stage6: bool = True,
                        receivers: tuple[str, ...] = (), ablations: bool = True,
                        sensitivity: bool = True,
                        observe: Callable[[SuiteRun], None] | None = None) -> ByzantineReport:
    """The D7.9 suite. Refuses to run past a BLOCKED precondition; writes no registry.

    ``observe`` (gate/lab only) sees each run once, after it is evaluated, so a caller can
    inspect bridges and lineage without the suite holding every run in memory."""
    preconditions = fleet_preconditions(corpus)
    _refuse_blocked(preconditions)
    rows: list[SuiteRow] = []
    firing: Counter[str] = Counter()
    ttd: tuple[tuple[str, float | None], ...] = ()
    for arm in arms:
        for spec in _specs(arm, shares, sybil_counts, rounds, seed, receivers):
            run = simulate(corpus, spec, with_stage6=with_stage6)
            rows.extend(evaluate_run(run))
            firing.update(run_firing(run))
            if observe is not None:
                observe(run)
            if arm is AdversaryArm.NONE:
                ttd = _time_to_detect(run)
    return ByzantineReport(
        rows=tuple(rows), break_points=break_points(rows),
        ablations=run_ablation(corpus, seed=seed, rounds=rounds, receivers=receivers)
        if ablations else (),
        threshold_sensitivity=threshold_sensitivity(corpus, seed=seed, rounds=rounds,
                                                    receivers=receivers) if sensitivity else (),
        firing=tuple(sorted(firing.items())), preconditions=preconditions, loadavg=loadavg(),
        time_to_detect=ttd,
    )


# --- ablation (spec §7 per-mechanism table) -----------------------------------------------------

#: (core id, flag, control, arm, x, EchoConfig change, metric). Every metric: lower is better,
#: except true_acceptance.
_ECHO_ABLATIONS: tuple[tuple[str, str, str, AdversaryArm, float, dict[str, bool], str], ...] = (
    ("ORPH-F08", "dependence_clustering", "declared roots only", AdversaryArm.SYBIL_FORGED_ROOTS,
     16, {"dependence_clustering": False}, "amplification"),
    ("ORPH-F09", "cluster_cap", "uncapped identity sum", AdversaryArm.SYBIL_DECLARED_ROOT, 16,
     {"cluster_cap": False}, "amplification"),
    ("ORPH-F09", "contextual_trust", "constant prior", AdversaryArm.SLOW_POISON, 0.2,
     {"contextual_trust": False}, "poison_acceptance"),
    ("ORPH-F09", "falsification_weight", "1.0", AdversaryArm.BYZANTINE_LATENT_POISON, 0.2,
     {"falsification_weight": False}, "poison_acceptance"),
    ("ORPH-F09", "contest_mass", "ignore contests", AdversaryArm.BYZANTINE_LATENT_POISON, 0.2,
     {"contest_mass": False}, "poison_acceptance"),
    ("ORPH-F09", "probation", "0 rounds", AdversaryArm.COLLUSION_TIMING, 0.2,
     {"probation": False}, "poison_acceptance"),
    ("ORPH-F09", "local_validation", "no local replay", AdversaryArm.BYZANTINE_POISON, 0.2,
     {"local_validation": False}, "poison_acceptance"),
    ("ORPH-F05", "epistemic_distance", "role equality", AdversaryArm.NONE, 0.0,
     {"epistemic_distance": False}, "true_acceptance"),
)


def _spec_for(arm: AdversaryArm, x: float, rounds: int, seed: int,
              receivers: tuple[str, ...]) -> FleetSpec:
    if arm in SYBIL_ARMS:
        return FleetSpec(arm=arm, sybils_per_root=int(x), rounds=rounds, seed=seed,
                         receivers=receivers)
    return FleetSpec(arm=arm, adversary_share=x, rounds=rounds, seed=seed, receivers=receivers)


def echo_metric(run: SuiteRun, metric: str) -> float | None:
    """ECHO's amplification, or its accepted/offered rate on poison or true foreign keys."""
    accepted = accepted_keys(run, Aggregator.ECHO)
    if metric == "amplification":
        return _amplification(run, Aggregator.ECHO, accepted)
    keys = run.truth.poison_keys if metric == "poison_acceptance" else _true_keys(run.truth)
    offered = hits = 0
    for host_id, receiver in run.receivers.items():
        mine = {a.antibody.antibody_key for a in run.fleet.local_antibodies(host_id)}
        present = (keys & _supported(receiver).keys()) - mine
        offered += len(present)
        hits += len(present & accepted[host_id].keys())
    return hits / offered if offered else None


def _verdict(full: float | None, control: float | None, firing: int, *,
             lower_is_better: bool) -> tuple[float | None, str]:
    if full is None or control is None:
        return None, "INERT" if firing == 0 else "NOT_YET_JUSTIFIED"
    delta = full - control
    if firing == 0:
        return delta, "INERT"
    gain = -delta if lower_is_better else delta
    return delta, "JUSTIFIED" if gain > 0.05 else "HARMFUL" if gain < -0.05 else "NOT_YET_JUSTIFIED"


def ablation_row(core: str, flag: str, control: str, metric: str, full: float | None,
                 control_value: float | None, firing: int, *, lower_is_better: bool) -> AblationRow:
    delta, verdict = _verdict(full, control_value, firing, lower_is_better=lower_is_better)
    return AblationRow(core, flag, control, metric, full, control_value, delta, firing, verdict)


class _RunCache:
    """Full-configuration runs shared by the ablation and the sensitivity sweep."""

    def __init__(self, corpus: FleetCorpus, *, rounds: int, seed: int,
                 receivers: tuple[str, ...]) -> None:
        self.corpus, self.rounds, self.seed, self.receivers = corpus, rounds, seed, receivers
        self._runs: dict[tuple[AdversaryArm, float], SuiteRun] = {}

    def full(self, arm: AdversaryArm, x: float) -> SuiteRun:
        if (arm, x) not in self._runs:
            spec = _spec_for(arm, x, self.rounds, self.seed, self.receivers)
            self._runs[(arm, x)] = simulate(self.corpus, spec)
        return self._runs[(arm, x)]


def _decisions_changed(full: SuiteRun, control: SuiteRun) -> int:
    """(receiver, key) pairs whose final ECHO status or acceptance differs from the control
    run on the SAME traffic: Rule C's "changed an outcome relative to its control"."""
    a, b = accepted_keys(full, Aggregator.ECHO), accepted_keys(control, Aggregator.ECHO)
    before, after = _statuses(full), _statuses(control)
    flipped = sum(before.get(k) != after.get(k) for k in set(before) | set(after))
    return flipped + sum(len(set(a[h]) ^ set(b.get(h, {}))) for h in a)


def _echo_ablations(cache: _RunCache) -> list[AblationRow]:
    """ECHO flags: full vs one-flag-off on identical recorded traffic.

    Firing is the count of decisions that differ between the two runs (ECHO's own per-round
    counter ignores probation history, so it can read 0 while the control run differs), and
    for dependence clustering the behavioural merges (the spec's "merges by kind").
    """
    rows = []
    for core, flag, control, arm, x, change, metric in _ECHO_ABLATIONS:
        full_run = cache.full(arm, x)
        control_run = replay_with(full_run, config=replace(EchoConfig(), **change))
        if flag == "dependence_clustering":
            firing = sum(n for k, n in run_firing(full_run).items()
                         if k.startswith("graph_merge:") and k != "graph_merge:SAME_ROOT")
        else:
            firing = _decisions_changed(full_run, control_run)
        rows.append(ablation_row(core, flag, control, f"ECHO {metric} on {arm.value}@{x}",
                                 echo_metric(full_run, metric), echo_metric(control_run, metric),
                                 firing, lower_is_better=metric != "true_acceptance"))
    return rows


def _gravity_row(cache: _RunCache) -> AblationRow:
    """Counterfactual: the fabric has no gravity switch, so 'validate everything' is bounded
    by the true keys whose every contribution was triaged (they alone could be lost)."""
    run = cache.full(AdversaryArm.NONE, 0.0)
    true, lost = _true_keys(run.truth), 0
    for receiver in run.receivers.values():
        lost += len((receiver.triaged_keys & true) - _supported(receiver).keys())
    firing = sum(r.verdicts[IngressOutcome.METADATA_ONLY.value] for r in run.receivers.values())
    return ablation_row("ORPH-F06", "gravity", "validate every capsule (counterfactual bound)",
                "true keys lost to triage (lower is better)", float(lost), 0.0, firing,
                lower_is_better=True)


def _auc(pairs: Sequence[tuple[float, bool]]) -> float | None:
    """Mann-Whitney AUC of a score predicting a boolean; ties count one half."""
    pos = [s for s, useful in pairs if useful]
    neg = [s for s, useful in pairs if not useful]
    if not pos or not neg:
        return None
    wins = sum(1.0 if p > n else 0.5 if p == n else 0.0 for p in pos for n in neg)
    return wins / (len(pos) * len(neg))


def _distance_auc_row(cache: _RunCache) -> AblationRow:
    """F6: AUC of -D_E predicting local usefulness (TP > 0 and FP = 0 on the held-out)."""
    from pocketsec.stage7.relevance.epistemic_distance import (
        epistemic_distance,
    )
    run = cache.full(AdversaryArm.NONE, 0.0)
    full: list[tuple[float, bool]] = []
    control: list[tuple[float, bool]] = []
    changed = 0
    for host_id, receiver in run.receivers.items():
        local = receiver.components.local
        heldout = run.fleet.corpus.for_host(host_id, history=False)
        for p in {p.capsule.capsule_id: p for p in receiver.pooled
                  if p.capsule.knowledge_type is KnowledgeType.ANTIBODY}.values():
            rows = p.capsule.semantic_invariant
            tp = sum(1 for e in heldout if e.label == 1 and matches(rows, e.steps))
            fp = sum(1 for e in heldout if e.label == 0 and matches(rows, e.steps))
            args = (p.capsule.source_context_sketch, p.capsule.epoch_context, local)
            d_full = epistemic_distance(*args).total
            d_ctrl = epistemic_distance(*args, enabled=False).total
            changed += d_full != d_ctrl
            full.append((-d_full, tp > 0 and fp == 0))
            control.append((-d_ctrl, tp > 0 and fp == 0))
    return ablation_row("ORPH-F05", "epistemic_distance_auc", "role equality",
                "AUC(-D_E predicts local usefulness) on NONE", _auc(full), _auc(control),
                changed, lower_is_better=False)


def _transfer_recall(corpus: FleetCorpus, receivers: Sequence[str],
                     rule: Callable[[LocalIncident], KnowledgeAntibody | None]) -> float | None:
    """Recall at FPR_BUDGET when each receiver installs ``rule`` of every OTHER host's incidents
    that passes its own local validation. counterfactual_at_boundary."""
    from pocketsec.stage7.labs.simulated_fleet import honest_antibodies
    labels: list[int] = []
    scores: list[float] = []
    items = honest_antibodies(corpus)
    for host_id in receivers:
        validator = _validator(corpus, host_id)
        rules = [r.invariant for i in items if i.host_id != host_id
                 and (r := rule(i.incident)) is not None
                 and validator.validate(r.invariant) in _OK]
        seen = corpus.host(host_id).families_local
        for e in corpus.for_host(host_id, history=False):
            if not (e.label == 1 and e.family in seen):
                labels.append(e.label)
                scores.append(1.0 if _scores(e, rules) else 0.0)
    return recall_at_max_fpr(labels, scores, FPR_BUDGET)[0] if labels else None


def _minimisation_row(corpus: FleetCorpus, receivers: Sequence[str]) -> AblationRow:
    from pocketsec.stage7.antibody.forge import copied_rule
    from pocketsec.stage7.labs.simulated_fleet import honest_antibodies
    items = honest_antibodies(corpus)
    minimised = {i.incident.incident_id: i.antibody for i in items}
    firing = sum(1 for i in items if (c := copied_rule(i.incident)) is None
                 or c.invariant != i.antibody.invariant)
    full = _transfer_recall(corpus, receivers, lambda inc: minimised.get(inc.incident_id))
    control = _transfer_recall(corpus, receivers, copied_rule)
    return ablation_row("ORPH-F10", "antibody_minimisation", "copied_rule",
                "receiver recall@FPR_BUDGET on unseen families", full, control, firing,
                lower_is_better=False)


def _campaign_rows(seed: int) -> list[AblationRow]:
    from pocketsec.stage7.labs.campaign_sim import (
        build_campaign_cases,
        run_campaign_case,
        run_campaign_sim,
    )
    cases = build_campaign_cases(seed=seed, per_arm=4)
    full = run_campaign_sim(cases)
    flat = run_campaign_sim(cases, hypergraph=False)
    rejected = sum(n for _, n in full.rejections_by_hypothesis)
    changed = sum(1 for c in cases if (run_campaign_case(c).detected_after_rounds is None)
                  != (run_campaign_case(c, hypergraph=False).detected_after_rounds is None))
    detected = sum(1 for c in cases if c.is_campaign
                   and run_campaign_case(c).detected_after_rounds is not None)
    return [
        ablation_row("ORPH-F11", "reconstruction", "no reconstruction", "true campaign recall",
             full.true_recall, 0.0, detected, lower_is_better=False),
        ablation_row("ORPH-F13", "hypergraph", "pairwise co-occurrence", "false campaign rate",
             full.false_campaign_rate, flat.false_campaign_rate, changed, lower_is_better=True),
        ablation_row("ORPH-F14", "falsifier", "count_threshold_join", "false campaign rate",
             full.false_campaign_rate, full.control_false_campaign_rate, rejected,
             lower_is_better=True),
    ]


def run_ablation(corpus: FleetCorpus, *, seed: int = 0, rounds: int = SUITE_ROUNDS,
                 receivers: tuple[str, ...] = ()) -> tuple[AblationRow, ...]:
    """One AblationRow per spec §7 flag. Firing 0 -> INERT, never 'measured'."""
    from pocketsec.stage7.labs import privacy_attacks
    _refuse_blocked(fleet_preconditions(corpus))
    cache = _RunCache(corpus, rounds=rounds, seed=seed, receivers=receivers)
    rows = _echo_ablations(cache)
    rows += [_gravity_row(cache), _distance_auc_row(cache),
             _minimisation_row(corpus,
                               receivers or cache.full(AdversaryArm.NONE, 0.0).fleet.receivers)]
    rows += _campaign_rows(seed)
    # F4: novelty and DP probes are corpus-free toys; judge them by their FABRIC-path firing.
    fabric = privacy_attacks.fabric_novelty_firing(cache.full(AdversaryArm.NONE, 0.0)
                                                   .receivers.values())
    for core, flag, control, probe in (
        ("ORPH-F12", "collective_novelty", "local novelty only", privacy_attacks.novelty_ablation),
        ("ORPH-F18", "secure_aggregation", "plaintext sum + per-root clamp",
         privacy_attacks.secure_sum_ablation),
        ("ORPH-F19", "differential_privacy", "exact counts", privacy_attacks.dp_ablation),
    ):
        metric, full, control_value, firing, lower = probe(corpus, seed=seed)
        if flag != "secure_aggregation":
            metric = f"TOY, corpus unused: {metric}; toy firing {firing}, fabric firing {fabric}"
            firing = fabric
        rows.append(ablation_row(core, flag, control, metric, full, control_value, firing,
                         lower_is_better=lower))
    return tuple(rows)


# --- threshold sensitivity (lesson 5) -------------------------------------------------------------

_SENSITIVITY_ARMS: tuple[tuple[AdversaryArm, float], ...] = (
    (AdversaryArm.NONE, 0.0), (AdversaryArm.BYZANTINE_LATENT_POISON, 0.2),
)


def _statuses(run: SuiteRun) -> dict[tuple[str, str], str]:
    """(receiver, key) -> the last ECHO status of that key."""
    final: dict[tuple[str, str], str] = {}
    for host_id, receiver in run.receivers.items():
        for inference in receiver.inferences:
            for decision in inference.decisions:
                final[(host_id, decision.antibody_key)] = decision.status.value
    return final


def _decision_trace(run: SuiteRun) -> dict[tuple[str, str], tuple[str, int | None]]:
    """(receiver, key) -> (last status, first ELIGIBLE round). The fabric bridges a key ONCE,
    at its first ELIGIBLE round, so a knob that moves only that (probation) is a flip (S7-R7)."""
    final = _statuses(run)
    first = accepted_keys(run, Aggregator.ECHO)
    return {k: (status, first.get(k[0], {}).get(k[1])) for k, status in final.items()}


def _flip_share(base: Mapping[tuple[str, str], object],
                other: Mapping[tuple[str, str], object]) -> float:
    keys = set(base) | set(other)
    return sum(base.get(k) != other.get(k) for k in keys) / len(keys) if keys else 0.0


def threshold_sensitivity(corpus: FleetCorpus, *, seed: int = 0, rounds: int = SUITE_ROUNDS,
                          receivers: tuple[str, ...] = ()) -> tuple[tuple[str, float, float], ...]:
    """Share of ECHO decisions that flip at x0.5 and x2 (+-1 for the integer probation).
    A decision flips when its final status OR its first-ELIGIBLE round differs (S7-R7).

    VALIDATION_FLOOR is not an ECHO parameter and the fabric has no switch for it: its figure
    is the share of the ingress's TRIAGE decisions that flip, from the recorded gravities.
    """
    cache = _RunCache(corpus, rounds=rounds, seed=seed, receivers=receivers)
    base_runs = [cache.full(arm, x) for arm, x in _SENSITIVITY_ARMS]
    base = [_decision_trace(r) for r in base_runs]
    default = EchoConfig()
    knobs: tuple[tuple[str, Callable[[float], dict[str, object]]], ...] = (
        ("MASS_FLOOR", lambda f: {"config": replace(default, mass_floor=default.mass_floor * f)}),
        ("CLUSTER_CAP", lambda f: {"config": replace(default, cap=default.cap * f)}),
        ("CONTEST_RATIO", lambda f: {"config": replace(default,
                                                        contest_ratio=default.contest_ratio * f)}),
        ("RELEVANCE_FLOOR", lambda f: {"config": replace(
            default, relevance_floor=default.relevance_floor * f)}),
        ("ECHO_PROBATION_ROUNDS", lambda f: {"config": replace(
            default, probation_rounds=max(0, default.probation_rounds + (1 if f > 1 else -1)))}),
        ("TRUST_PRIOR", lambda f: {"trust_prior": TRUST_PRIOR * f}),
    )
    out = []
    for name, change in knobs:
        flips = []
        for factor in (0.5, 2.0):
            variants = [_decision_trace(replay_with(r, **change(factor)))  # type: ignore[arg-type]
                        for r in base_runs]
            both = {(str(i), *k): v for i, b in enumerate(base) for k, v in b.items()}
            other = {(str(i), *k): v for i, b in enumerate(variants) for k, v in b.items()}
            flips.append(_flip_share(both, other))  # type: ignore[arg-type]
        out.append((name, flips[0], flips[1]))
    out.append(("VALIDATION_FLOOR (triage decisions)", *_triage_flips(base_runs)))
    return tuple(out)


def _triage_flips(runs: Sequence[SuiteRun]) -> tuple[float, float]:
    from pocketsec.stage7.hivelock.ingress import VALIDATION_FLOOR
    triage = [t for run in runs for r in run.receivers.values() for t in r.triage]
    if not triage:
        return 0.0, 0.0
    shares = []
    for factor in (0.5, 2.0):
        floor = VALIDATION_FLOOR * factor
        shares.append(sum((g >= floor) != pooled for g, pooled in triage) / len(triage))
    return shares[0], shares[1]


def siem_oracle(corpus: FleetCorpus, *, receiver: str) -> tuple[float | None, int]:
    """The raw-log SIEM upper bound: the receiver forges from EVERY host's raw labelled history.

    Returns (recall at FPR_BUDGET on its locally-unseen families, raw strings and digests
    exposed). Exposure is scanned over the raw ``EncodedStep`` records such a feed ships
    (Stage 6's fleet-item format); a real SIEM also ships the raw event fields, which the
    corpus does not retain, so the figure is a LOWER bound on exposure.
    """
    import json

    from pocketsec.stage7.antibody.forge import forge_antibody
    from pocketsec.stage7.labs.privacy_attacks import canary_scan
    ring = BenignRing(capacity=max(1, len(corpus.episodes)))
    shipped: list[bytes] = []
    for e in corpus.episodes:
        if e.history:
            if e.label == 0:
                ring.add(e.steps)
            if e.host_id != receiver:
                shipped.append(json.dumps([s.to_dict() for s in e.steps], sort_keys=True).encode())
    rules = [a.invariant for e in corpus.episodes if e.history and e.label == 1
             and (a := forge_antibody(LocalIncident(f"siem-{e.host_id}-{e.index}", e.steps,
                                                    e.evidence_digests[:8]), benign=ring))]
    labels: list[int] = []
    scores: list[float] = []
    seen = corpus.host(receiver).families_local
    for e in corpus.for_host(receiver, history=False):
        if not (e.label == 1 and e.family in seen):
            labels.append(e.label)
            scores.append(1.0 if _scores(e, rules) else 0.0)
    recall = recall_at_max_fpr(labels, scores, FPR_BUDGET)[0] if labels else None
    return recall, canary_scan(corpus, shipped)[0]
