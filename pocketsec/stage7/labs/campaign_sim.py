"""D7.19 (campaign part) — simulated distributed campaigns and their benign common-cause twins.

**Synthetic, simulated, and confounded — read this first.** There is no real fleet. Each
:class:`CampaignCase` is a hand-built set of :class:`Fragment` and :class:`NegativeClaim`
values (no Stage 1 run is needed: a fragment is already the distilled, pseudonymous record
a ``CAMPAIGN_FRAGMENT`` capsule would carry). **The arms and the falsifier's tests share an
author.** Each benign common-cause arm is built so that exactly its intended hypothesis
applies (and :data:`BENIGN_ARM_HYPOTHESIS` names it), so "the falsifier rejects every benign
arm" shows the *mechanism fires as designed*, not that real common causes look like these.
A real shared update, admin job or telemetry fault that differs from its arm here is simply
not in this simulation. Every figure this module produces carries ``synthetic=True``.

The ten arms (spec D7.19):

* ``TRUE_CAMPAIGN_{2,4,10}``: one campaign across 2, 4 or 10 hosts in distinct dependence
  clusters, walking CREDENTIAL → ELEVATION → PERSISTENCE → EGRESS a round or two apart, on
  established software images, FULL/PARTIAL visibility, random roles.
* ``BENIGN_COINCIDENCE`` (H0): common stages only (ACCESS, PERSISTENCE, EGRESS) whose base
  rates make the co-occurrence unsurprising.
* ``SHARED_SOFTWARE_UPDATE`` (H1): every fragment on one software epoch first seen inside the
  window; distinct roles; rare stages.
* ``ADMIN_AUTOMATION`` (H2): one role (ADMIN), identical window starts, rare stages.
* ``TELEMETRY_ARTIFACT`` (H3): every fragment at LOW visibility.
* ``COLLUDING_FABRICATION`` (H4): fragments stamped with distinct clusters that the
  dependence view later merges into one (even cases, ``cluster_merges``), or whose
  identities were born in one burst (odd cases, ``burst_capsules``).
* ``SUPPRESSION``: a real 4-host campaign in two phases plus negative claims from three
  unmerged Sybil clusters. Even cases suppress only the first phase (the campaign resumes
  later: measured as delay); odd cases claim every window the case spans, so the veto
  never lifts. The spec's "a suppression attack can at most delay" holds only against the
  first kind; the odd cases measure the second, reported as ``suppressed_never_detected``.
* ``TEMPORAL_UNCERTAINTY``: a real 4-host campaign with wide (3-6 round) jittered windows.

The benign arms H1-H4 use the rare stages CREDENTIAL, ELEVATION and PERSISTENCE only, so
every qualifying world contains both rare stages and H0 is rejected in each of them; that is
what "exactly its hypothesis applies" requires.

**The run.** One case at a time, round by round from ``start_round``: a fragment arrives when
its window closes (``hi``), every negative claim is in force from ``start_round`` (a
suppressor may claim ahead of the windows it names), and the reconstructor runs every
round. A case is *detected* at the first round a
SUPPORTED world exists. The control is :func:`count_threshold_join` with
``window = JOIN_WINDOW_ROUNDS`` and ``k = MIN_WORLD_STAGES`` (as many fragments and clusters
as the reconstructor needs stages: the stricter, fairer setting for the control).

Parameters (chosen, not measured): :data:`SIM_STAGE_BASE_RATES` (per host per round),
:data:`SIM_RELEVANT_HOSTS`, the arm shapes above. H0's outcome on every arm is decided by
these rates; they were chosen with the arms in view (the confound again).
"""

from __future__ import annotations

import hashlib
import random
import statistics
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from pocketsec.stage0.contracts.common import ContractError, require_non_negative_int
from pocketsec.stage7.campaign.hypergraph import JOIN_WINDOW_ROUNDS, CampaignHypergraph, Fragment
from pocketsec.stage7.capsule.knowledge_capsule import ChainStage, RoleClass, VisibilityClass
from pocketsec.stage7.falsifier.consensus import (
    ConsensusFalsifier,
    CounterHypothesis,
    NegativeClaim,
)
from pocketsec.stage7.reconstruct.partial_world import (
    MIN_WORLD_STAGES,
    PartialWorld,
    PartialWorldReconstructor,
    WorldStatus,
    count_threshold_join,
)

__all__ = [
    "BENIGN_ARM_HYPOTHESIS",
    "CAMPAIGN_ARMS",
    "CAMPAIGN_SIM_VERSION",
    "SIM_RELEVANT_HOSTS",
    "SIM_STAGE_BASE_RATES",
    "CampaignArm",
    "CampaignCase",
    "CampaignCaseOutcome",
    "CampaignSimReport",
    "build_campaign_cases",
    "run_campaign_case",
    "run_campaign_sim",
]

CAMPAIGN_SIM_VERSION = "stage7-campaign-sim-v0.1.0"

#: Per host per round. Chosen, not measured (and chosen with the arms in view).
SIM_STAGE_BASE_RATES: Mapping[ChainStage, float] = {
    ChainStage.ACCESS: 0.05,
    ChainStage.CREDENTIAL: 0.0005,
    ChainStage.ELEVATION: 0.0005,
    ChainStage.PERSISTENCE: 0.02,
    ChainStage.EGRESS: 0.05,
}
SIM_RELEVANT_HOSTS: int = 16
_EPOCH_AGE_ROUNDS = 30
_TAIL_ROUNDS = JOIN_WINDOW_ROUNDS + 2
_SUPPRESSOR_CLUSTERS = 3
_SUPPRESSOR_WEIGHT = 0.9
_PHASE_GAP_ROUNDS = 10

_CHAIN: tuple[ChainStage, ...] = (
    ChainStage.CREDENTIAL, ChainStage.ELEVATION, ChainStage.PERSISTENCE, ChainStage.EGRESS,
)
_RARE_BENIGN: tuple[ChainStage, ...] = (
    ChainStage.CREDENTIAL, ChainStage.ELEVATION, ChainStage.PERSISTENCE,
)
_COMMON: tuple[ChainStage, ...] = (ChainStage.ACCESS, ChainStage.PERSISTENCE, ChainStage.EGRESS)
_ROLES: tuple[RoleClass, ...] = (RoleClass.WEB, RoleClass.DEV, RoleClass.DESKTOP, RoleClass.ADMIN)


class CampaignArm(StrEnum):
    TRUE_CAMPAIGN_2 = "TRUE_CAMPAIGN_2"
    TRUE_CAMPAIGN_4 = "TRUE_CAMPAIGN_4"
    TRUE_CAMPAIGN_10 = "TRUE_CAMPAIGN_10"
    BENIGN_COINCIDENCE = "BENIGN_COINCIDENCE"
    SHARED_SOFTWARE_UPDATE = "SHARED_SOFTWARE_UPDATE"
    ADMIN_AUTOMATION = "ADMIN_AUTOMATION"
    TELEMETRY_ARTIFACT = "TELEMETRY_ARTIFACT"
    COLLUDING_FABRICATION = "COLLUDING_FABRICATION"
    SUPPRESSION = "SUPPRESSION"
    TEMPORAL_UNCERTAINTY = "TEMPORAL_UNCERTAINTY"


#: The arms whose cases are real campaigns (``is_campaign``).
CAMPAIGN_ARMS: frozenset[CampaignArm] = frozenset(
    {
        CampaignArm.TRUE_CAMPAIGN_2, CampaignArm.TRUE_CAMPAIGN_4, CampaignArm.TRUE_CAMPAIGN_10,
        CampaignArm.SUPPRESSION, CampaignArm.TEMPORAL_UNCERTAINTY,
    }
)
#: The one hypothesis each non-campaign arm is built to trigger.
BENIGN_ARM_HYPOTHESIS: Mapping[CampaignArm, CounterHypothesis] = {
    CampaignArm.BENIGN_COINCIDENCE: CounterHypothesis.H0_COINCIDENCE,
    CampaignArm.SHARED_SOFTWARE_UPDATE: CounterHypothesis.H1_SHARED_UPDATE,
    CampaignArm.ADMIN_AUTOMATION: CounterHypothesis.H2_ADMIN_AUTOMATION,
    CampaignArm.TELEMETRY_ARTIFACT: CounterHypothesis.H3_TELEMETRY_ARTIFACT,
    CampaignArm.COLLUDING_FABRICATION: CounterHypothesis.H4_COLLUDING_PEERS,
}


@dataclass(frozen=True, slots=True)
class CampaignCase:
    """One simulated case. The last three fields are additive to the spec (see module docstring).

    ``epoch_history``: ``(software_epoch, first_seen_round)`` for images established before the
    case (the H1 test needs history). ``cluster_merges``: ``(stamped, resolved)`` cluster ids
    the dependence view merged after contribution (H4). ``burst_capsules``: capsule ids whose
    contributing identities were born in one burst (H4).
    """

    arm: CampaignArm
    fragments: tuple[Fragment, ...]
    negative: tuple[NegativeClaim, ...]
    is_campaign: bool
    start_round: int
    epoch_history: tuple[tuple[str, int], ...] = ()
    cluster_merges: tuple[tuple[str, str], ...] = ()
    burst_capsules: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.arm, CampaignArm):
            raise ContractError(f"CampaignCase.arm invalid: {self.arm!r}")
        if not self.fragments:
            raise ContractError("CampaignCase.fragments must not be empty")
        if self.is_campaign != (self.arm in CAMPAIGN_ARMS):
            raise ContractError(f"is_campaign disagrees with arm {self.arm}")
        require_non_negative_int(self.start_round, "CampaignCase.start_round")


@dataclass(frozen=True, slots=True)
class CampaignCaseOutcome:
    """What one case produced: the first SUPPORTED round (relative to start) and every world."""

    arm: CampaignArm
    is_campaign: bool
    detected_after_rounds: int | None
    worlds: tuple[PartialWorld, ...]
    control_groups: int


@dataclass(frozen=True, slots=True)
class CampaignSimReport:
    true_recall: float | None
    false_campaign_rate: float | None
    control_false_campaign_rate: float | None
    time_to_detect_rounds: tuple[tuple[str, int | None], ...]
    rejections_by_hypothesis: tuple[tuple[str, int], ...]
    suppression_delay_rounds: float | None
    synthetic: bool = True
    #: Additive to the spec: SUPPRESSION cases detected without the negative claims but
    #: never with them (the veto did not lift inside the horizon).
    suppressed_never_detected: int = 0


# --- case construction ---------------------------------------------------------------


class _Ids:
    """Deterministic, seed-derived ids in the wire shapes (``kc-``, ``cl-``, ``se-``)."""

    def __init__(self, seed: int, arm: CampaignArm, index: int) -> None:
        self._prefix = f"{CAMPAIGN_SIM_VERSION}|{seed}|{arm.value}|{index}"

    def _hex(self, label: str, width: int) -> str:
        return hashlib.sha256(f"{self._prefix}|{label}".encode()).hexdigest()[:width]

    def capsule(self, label: str) -> str:
        return "kc-" + self._hex(f"capsule:{label}", 24)

    def cluster(self, label: str) -> str:
        return "cl-" + self._hex(f"cluster:{label}", 16)

    def epoch(self, label: str) -> str:
        return "se-" + self._hex(f"epoch:{label}", 16)


@dataclass(frozen=True, slots=True)
class _Shape:
    """How one arm lays out its hosts; every knob is a construction choice."""

    hosts: int
    stages_of: Callable[[int], tuple[int, ...]]
    stage_set: tuple[ChainStage, ...]
    width: tuple[int, int]
    jitter: int
    synced: bool = False
    distinct_roles: bool = False
    role: RoleClass | None = None
    visibility: tuple[VisibilityClass, ...] = (VisibilityClass.FULL, VisibilityClass.PARTIAL)
    fresh_epoch: bool = False
    rarity: tuple[float, float] = (0.6, 1.0)


def _lay_out(rng: random.Random, ids: _Ids, shape: _Shape, start: int, *,
             phase: int = 0, offset: int = 0) -> tuple[list[Fragment], list[tuple[str, int]]]:
    established = [ids.epoch(f"established:{n}") for n in range(3)]
    history = [(epoch, max(0, start - _EPOCH_AGE_ROUNDS)) for epoch in established]
    fresh = ids.epoch("fresh")
    roles = list(_ROLES)
    rng.shuffle(roles)
    fragments: list[Fragment] = []
    for host in range(shape.hosts):
        if shape.role is not None:
            role = shape.role
        elif shape.distinct_roles:
            role = roles[host % len(roles)]
        else:
            role = rng.choice(_ROLES)
        epoch = fresh if shape.fresh_epoch else rng.choice(established)
        for stage_index in shape.stages_of(host):
            step = 0 if shape.synced else stage_index + rng.randint(0, shape.jitter)
            lo = start + offset + step
            fragments.append(Fragment(
                capsule_id=ids.capsule(f"{phase}:{host}:{stage_index}"),
                cluster_id=ids.cluster(f"host:{host}"),
                role=role,
                stage=shape.stage_set[stage_index % len(shape.stage_set)],
                window=(lo, lo + rng.randint(*shape.width)),
                software_epoch=epoch,
                visibility=rng.choice(shape.visibility),
                rarity=round(rng.uniform(*shape.rarity), 3),
            ))
    return fragments, history


def _campaign_stages(hosts: int) -> Callable[[int], tuple[int, ...]]:
    if hosts == 2:  # two hosts must still cover the whole chain between them
        return lambda host: (0, 2) if host == 0 else (1, 3)
    return lambda host: (host % len(_CHAIN),)


def _true_shape(hosts: int, *, width: tuple[int, int] = (1, 2), jitter: int = 1) -> _Shape:
    return _Shape(hosts=hosts, stages_of=_campaign_stages(hosts), stage_set=_CHAIN,
                  width=width, jitter=jitter)


def _rare(host: int) -> tuple[int, ...]:
    return (host % len(_RARE_BENIGN),)


def _benign_shape(arm: CampaignArm, hosts: int) -> _Shape:
    rare = _rare
    if arm is CampaignArm.BENIGN_COINCIDENCE:
        return _Shape(hosts=hosts, stages_of=lambda host: (host % len(_COMMON),), stage_set=_COMMON,
                      width=(1, 2), jitter=1, distinct_roles=True,
                      visibility=(VisibilityClass.FULL,), rarity=(0.1, 0.5))
    if arm is CampaignArm.SHARED_SOFTWARE_UPDATE:
        return _Shape(hosts=hosts, stages_of=rare, stage_set=_RARE_BENIGN, width=(1, 3), jitter=0,
                      synced=True, distinct_roles=True, visibility=(VisibilityClass.FULL,),
                      fresh_epoch=True, rarity=(0.5, 0.9))
    if arm is CampaignArm.ADMIN_AUTOMATION:
        return _Shape(hosts=hosts, stages_of=rare, stage_set=_RARE_BENIGN, width=(1, 3), jitter=0,
                      synced=True, role=RoleClass.ADMIN, visibility=(VisibilityClass.FULL,),
                      rarity=(0.5, 0.9))
    if arm is CampaignArm.TELEMETRY_ARTIFACT:
        return _Shape(hosts=hosts, stages_of=rare, stage_set=_RARE_BENIGN, width=(1, 2), jitter=1,
                      distinct_roles=True, visibility=(VisibilityClass.LOW,), rarity=(0.5, 0.9))
    if arm is CampaignArm.COLLUDING_FABRICATION:
        return _Shape(hosts=hosts, stages_of=rare, stage_set=_RARE_BENIGN, width=(1, 2), jitter=1,
                      distinct_roles=True, visibility=(VisibilityClass.FULL,), rarity=(0.7, 1.0))
    raise ContractError(f"{arm} is not a benign arm")


def _suppression_claims(ids: _Ids, start: int, span: int) -> tuple[NegativeClaim, ...]:
    claims: list[NegativeClaim] = []
    for suppressor in range(_SUPPRESSOR_CLUSTERS):
        cluster = ids.cluster(f"suppressor:{suppressor}")
        for lo in range(start, start + span, 16):
            for stage in _CHAIN:
                claims.append(NegativeClaim(
                    capsule_id=ids.capsule(f"neg:{suppressor}:{lo}:{stage.value}"),
                    cluster_id=cluster, stage=stage,
                    window=(lo, min(lo + 16, start + span)), weight=_SUPPRESSOR_WEIGHT,
                ))
    return tuple(claims)


def _case(arm: CampaignArm, *, seed: int, index: int) -> CampaignCase:
    rng = random.Random(f"{CAMPAIGN_SIM_VERSION}|{seed}|{arm.value}|{index}")
    ids = _Ids(seed, arm, index)
    start = 40 + 8 * index
    negative: tuple[NegativeClaim, ...] = ()
    merges: tuple[tuple[str, str], ...] = ()
    burst: tuple[str, ...] = ()
    hosts_of = {CampaignArm.TRUE_CAMPAIGN_2: 2, CampaignArm.TRUE_CAMPAIGN_4: 4,
                CampaignArm.TRUE_CAMPAIGN_10: 10}
    if arm in hosts_of:
        fragments, history = _lay_out(rng, ids, _true_shape(hosts_of[arm]), start)
    elif arm is CampaignArm.TEMPORAL_UNCERTAINTY:
        fragments, history = _lay_out(rng, ids, _true_shape(4, width=(3, 6), jitter=2), start)
    elif arm is CampaignArm.SUPPRESSION:
        fragments, history = _lay_out(rng, ids, _true_shape(4), start)
        later, _ = _lay_out(rng, ids, _true_shape(4), start, phase=1, offset=_PHASE_GAP_ROUNDS)
        fragments += later
        span = 8 if index % 2 == 0 else _PHASE_GAP_ROUNDS + 16
        negative = _suppression_claims(ids, start, span)
    else:
        fragments, history = _lay_out(rng, ids, _benign_shape(arm, rng.randint(3, 4)), start)
        if arm is CampaignArm.COLLUDING_FABRICATION:
            if index % 2 == 0:
                merged = ids.cluster("merged")
                merges = tuple(sorted({(item.cluster_id, merged) for item in fragments}))
            else:
                burst = tuple(sorted(item.capsule_id for item in fragments))
    return CampaignCase(
        arm=arm, fragments=tuple(fragments), negative=negative, is_campaign=arm in CAMPAIGN_ARMS,
        start_round=start, epoch_history=tuple(history), cluster_merges=merges,
        burst_capsules=burst,
    )


def build_campaign_cases(*, seed: int, per_arm: int = 8) -> tuple[CampaignCase, ...]:
    """``per_arm`` cases for each of the ten arms, deterministic in ``seed``."""
    require_non_negative_int(seed, "seed")
    if require_non_negative_int(per_arm, "per_arm") < 1:
        raise ContractError("per_arm must be >= 1")
    return tuple(
        _case(arm, seed=seed, index=index) for arm in CampaignArm for index in range(per_arm)
    )


# --- running -------------------------------------------------------------------------


def _burst_rule(burst: frozenset[str]) -> Callable[[Sequence[str]], bool]:
    """Lab rule: a world is burst-born when a strict majority of its capsules are."""
    def birth_burst(capsule_ids: Sequence[str]) -> bool:
        return 2 * sum(1 for item in capsule_ids if item in burst) > len(capsule_ids)
    return birth_burst


def run_campaign_case(case: CampaignCase, *, falsify: bool = True, hypergraph: bool = True,
                      use_negative: bool = True) -> CampaignCaseOutcome:
    """Replay one case round by round through a fresh hypergraph and reconstructor."""
    graph = CampaignHypergraph(enabled=hypergraph)
    for epoch, first in case.epoch_history:
        graph.note_epoch(epoch, first)
    merges = dict(case.cluster_merges)
    reconstructor = PartialWorldReconstructor(
        hypergraph=graph,
        falsifier=ConsensusFalsifier(stage_base_rates=SIM_STAGE_BASE_RATES,
                                     relevant_hosts=SIM_RELEVANT_HOSTS),
        falsify=falsify,
        resolve_cluster=lambda cluster: merges.get(cluster, cluster),
        birth_burst=_burst_rule(frozenset(case.burst_capsules)),
    )
    claims = case.negative if use_negative else ()
    pending = sorted(case.fragments, key=lambda item: (item.window[1], item.capsule_id))
    last = max([item.window[1] for item in case.fragments] + [item.window[1] for item in claims])
    detected: int | None = None
    worlds: tuple[PartialWorld, ...] = ()
    for round_index in range(case.start_round, last + _TAIL_ROUNDS + 1):
        while pending and pending[0].window[1] <= round_index:
            graph.add_fragment(pending.pop(0))
        worlds = reconstructor.reconstruct(round_index=round_index, negative=claims)
        if detected is None and any(world.status is WorldStatus.SUPPORTED for world in worlds):
            detected = round_index - case.start_round
    groups = count_threshold_join(case.fragments, window=JOIN_WINDOW_ROUNDS, k=MIN_WORLD_STAGES)
    return CampaignCaseOutcome(arm=case.arm, is_campaign=case.is_campaign,
                               detected_after_rounds=detected, worlds=worlds,
                               control_groups=len(groups))


def _rate(hits: int, total: int) -> float | None:
    return None if total == 0 else hits / total


def _suppression_delay(cases: Sequence[CampaignCase], outcomes: Sequence[CampaignCaseOutcome], *,
                       falsify: bool, hypergraph: bool) -> tuple[float | None, int]:
    delays: list[int] = []
    never = 0
    for case, outcome in zip(cases, outcomes, strict=True):
        if case.arm is not CampaignArm.SUPPRESSION:
            continue
        free = run_campaign_case(case, falsify=falsify, hypergraph=hypergraph, use_negative=False)
        if free.detected_after_rounds is None:
            continue
        if outcome.detected_after_rounds is None:
            never += 1
        else:
            delays.append(outcome.detected_after_rounds - free.detected_after_rounds)
    return (statistics.fmean(delays) if delays else None), never


def run_campaign_sim(cases: Sequence[CampaignCase], *, falsify: bool = True,
                     hypergraph: bool = True) -> CampaignSimReport:
    """Every case through the reconstructor; recall, false-campaign rates, delays. Synthetic."""
    outcomes = [run_campaign_case(case, falsify=falsify, hypergraph=hypergraph) for case in cases]
    campaigns = [item for item in outcomes if item.is_campaign]
    benign = [item for item in outcomes if not item.is_campaign]
    ttd: list[tuple[str, int | None]] = []
    for arm in CampaignArm:
        found = [item.detected_after_rounds for item in outcomes
                 if item.arm is arm and item.detected_after_rounds is not None]
        ttd.append((arm.value, statistics.median_low(found) if found else None))
    rejections = {hypothesis.value: 0 for hypothesis in CounterHypothesis}
    for outcome in outcomes:
        for world in outcome.worlds:
            if world.status in (WorldStatus.REJECTED_COMMON_CAUSE, WorldStatus.REJECTED_COLLUSION):
                explanation = world.falsification.explanation if world.falsification else None
                if explanation is None:
                    raise ContractError(f"{world.world_id} is REJECTED without an explanation")
                rejections[explanation.value] += 1
    delay, never = _suppression_delay(cases, outcomes, falsify=falsify, hypergraph=hypergraph)
    true_found = sum(1 for item in campaigns if item.detected_after_rounds is not None)
    false_found = sum(1 for item in benign if item.detected_after_rounds is not None)
    return CampaignSimReport(
        true_recall=_rate(true_found, len(campaigns)),
        false_campaign_rate=_rate(false_found, len(benign)),
        control_false_campaign_rate=_rate(sum(1 for item in benign if item.control_groups > 0),
                                          len(benign)),
        time_to_detect_rounds=tuple(ttd),
        rejections_by_hypothesis=tuple(rejections.items()),
        suppression_delay_rounds=delay,
        synthetic=True,
        suppressed_never_detected=never,
    )
