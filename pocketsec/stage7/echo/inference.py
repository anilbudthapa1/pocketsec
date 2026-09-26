"""ORPH-F09 / D7.10 — ECHO: collective inference that counts independent evidence, not votes.

ECHO decides, per antibody key and per receiving host, whether pooled foreign knowledge is
ELIGIBLE to be handed to Stage 6's quarantine AS A CANDIDATE. It exists because every
identity-counting aggregator (``aggregation/robust.py``) is bought by whoever mints the most
identities, and because no amount of agreement elsewhere is evidence about THIS host.

The decision (spec D7.10, bound in this order):

1. A key this host already holds as LOCAL-origin knowledge is REFUSED ``local_origin``: local
   knowledge is never re-decided by foreign evidence. A key under revocation is SUSPECT.
   Neither rule has an ablation switch.
2. The receiver's own ``LocalValidator`` replays the motif. ``LOCAL_FP`` makes the key
   CHALLENGED whatever the support: local evidence dominates, with no override (LOCAL
   SOVEREIGNTY). ``NOT_OBSERVABLE`` is INSUFFICIENT: unjudgeable here is not clean here.
3. Contributions are grouped by dependence cluster. Each (cluster, stance) contributes
   ``min(cap, reliability x relevance x falsification)``: ONE term per cluster, so the number
   of identities inside a cluster never raises its mass (MAJORITY_IS_NOT_TRUTH, §36). A
   cluster below the relevance floor contributes 0 (§25: split by epistemic context before
   averaging). Contests use falsification 1.0 and can only REDUCE eligibility; there is no
   foreign "benign" stance that creates anything (ADR-0063).
4. ELIGIBLE iff support mass >= the floor and >= contest_ratio x contest mass, held for more
   than ``probation_rounds`` consecutive rounds, so late contests get time to arrive (the
   timing-collusion defence). Otherwise INSUFFICIENT, naming the failing clause.
5. ``LOCAL_CONFIRMED`` never changes the status. It is recorded as a trust confirmation for
   the supporting clusters: local evidence is the only thing that ever confirms. A key that
   was REFUSED (``local_origin``) or is SUSPECT confirms nobody: relaying this host's own
   knowledge back to it carries no new evidence and must not farm trust (S7-R3).

**Only usable contributions count, every round (S7-R1, S7-AUTH-01, R7-1).** A contribution
whose capsule has expired is dropped from the table (and a key left with none is closed). A
contribution whose lineage node is no longer LIVE (retracted or revoked, whatever the order
relative to eligibility) or whose signing key no longer verifies (revoked, or rotated past
its grace) is excluded from that round's mass and from the evidence rows, and comes back if
the revocation is reinstated. Both predicates are injected by the fabric; the defaults (no
predicate) treat everything as usable, which is what a bare engine in a unit test means.
The sovereignty set is also injected (``local_keys``), so a key this host PUBLISHED after
start-up is as sovereign as one it held at construction (S7-R4).

What ECHO refuses to do: it never promotes, never writes trusted state and never touches
Stage 5. ELIGIBLE means "may be offered to ``QuarantineGateway.admit``", nothing more.
Every mechanism is an ``EchoConfig`` ablation switch, and every ``infer`` call reports, per
enabled mechanism, how many decisions would have differed with that mechanism off, computed
from the same inputs in the same call (lesson 1: a mechanism that never fires is INERT).
``local_validation=False`` exists only as that ablation; it disables step 2 and is never a
deployment setting.

Bounded: at most ``MAX_KEYS_TRACKED`` keys, of which one dependence cluster may OPEN at most
``MAX_KEYS_PER_OPENER`` (so a single key-holder cannot own the table, S7-AUTH-02/R7-3), and a
key closes when its last contribution expires (so a flood is never permanent). At most
``MAX_CONTRIBUTIONS_PER_KEY`` contributions per key. When a key's slots are full a newcomer
is not simply refused: a surplus identity is evicted (counted) from the largest
(cluster, stance) group if that group is at least two larger than the newcomer's own group.
Identities inside one cluster add no mass, so without this rule they would still buy slots
and lock out every later CONTEST (S7-R2). A newcomer whose group is already as well
represented is refused and counted. Evidence rows per decision are truncated at
``MAX_CLUSTERS_PER_DECISION`` with a flag.
"""

from __future__ import annotations

import hashlib
import json
import math
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import TYPE_CHECKING

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage7.antibody.forge import LocalValidation, LocalValidator
from pocketsec.stage7.capsule.knowledge_capsule import (
    KnowledgeCapsuleV1,
    KnowledgeType,
    MotifRow,
    Stance,
)
from pocketsec.stage7.trust.contextual import TRUST_PRIOR

if TYPE_CHECKING:
    from pocketsec.stage7.hivelock.ingress import PooledCapsule
    from pocketsec.stage7.relevance.epistemic_distance import LocalContext
    from pocketsec.stage7.trust.contextual import ContextualTrust

__all__ = [
    "CLUSTER_CAP",
    "CONTEST_RATIO",
    "DEFAULT_ECHO_CONFIG",
    "ECHO_PROBATION_ROUNDS",
    "MASS_FLOOR",
    "MAX_CAPSULE_IDS_PER_ROW",
    "MAX_CLUSTERS_PER_DECISION",
    "MAX_CONTRIBUTIONS_PER_KEY",
    "MAX_KEYS_PER_OPENER",
    "MAX_KEYS_TRACKED",
    "MECHANISMS",
    "RELEVANCE_FLOOR",
    "ClusterEvidence",
    "EchoConfig",
    "EchoDecision",
    "EchoEngine",
    "EchoInference",
    "EchoStatus",
]

#: Per-cluster mass cap. Chosen, not measured.
CLUSTER_CAP: float = 1.0
#: Support mass needed for eligibility. Chosen, not measured.
MASS_FLOOR: float = 1.0
#: Support must be at least this multiple of contest mass. Chosen, not measured.
CONTEST_RATIO: float = 1.0
#: A cluster whose best relevance is below this contributes 0. Chosen, not measured.
RELEVANCE_FLOOR: float = 0.2
#: Rounds the mass clauses must hold BEFORE the round that makes a key ELIGIBLE.
ECHO_PROBATION_ROUNDS: int = 2
MAX_KEYS_TRACKED: int = 1024
#: Keys one dependence cluster may have OPENED and still open. Chosen, not measured.
MAX_KEYS_PER_OPENER: int = 128
MAX_CONTRIBUTIONS_PER_KEY: int = 64
MAX_CLUSTERS_PER_DECISION: int = 16
#: ``ClusterEvidence.capsule_ids`` holds at most this many ids (spec: ``<= 8``).
MAX_CAPSULE_IDS_PER_ROW: int = 8
#: The ablation switches, in report order. Each is a boolean field of ``EchoConfig``.
MECHANISMS: tuple[str, ...] = (
    "cluster_cap",
    "dependence_clustering",
    "contextual_trust",
    "epistemic_distance",
    "falsification_weight",
    "contest_mass",
    "local_validation",
    "probation",
)
_FLOAT_DECIMALS = 9
_DECISION_HEX = 32


class EchoStatus(StrEnum):
    ELIGIBLE = "ELIGIBLE"  # may be handed to Stage 6 — as a candidate, never as trusted
    INSUFFICIENT = "INSUFFICIENT"  # not enough independent evidence — a valid, common answer
    CHALLENGED = "CHALLENGED"  # local evidence contradicts it (local FP); local dominates
    SUSPECT = "SUSPECT"  # an ancestor is revoked (D7.16)
    REFUSED = "REFUSED"  # a local-origin key decided from outside (sovereignty)


@dataclass(frozen=True, slots=True)
class ClusterEvidence:
    cluster_id: str
    stance: Stance
    identities: int
    capsule_ids: tuple[str, ...]
    reliability: float
    relevance: float
    falsification: float
    mass: float

    def to_payload(self) -> list[object]:
        return [
            self.cluster_id,
            str(self.stance),
            self.identities,
            list(self.capsule_ids),
            *(
                round(v, _FLOAT_DECIMALS)
                for v in (self.reliability, self.relevance, self.falsification, self.mass)
            ),
        ]


@dataclass(frozen=True, slots=True)
class EchoDecision:
    decision_id: str
    antibody_key: str
    invariant: tuple[MotifRow, ...]
    status: EchoStatus
    local_validation: LocalValidation
    support_mass: float
    contest_mass: float
    support_clusters: int
    contest_clusters: int
    eligible_rounds: int  # consecutive rounds the mass clauses held (the probation streak)
    evidence: tuple[ClusterEvidence, ...]
    truncated: bool
    reasons: tuple[str, ...]
    round_index: int


@dataclass(frozen=True, slots=True)
class EchoConfig:
    """Every boolean is an ablation switch (core_ids ORPH-F09); the floats are parameters."""

    cluster_cap: bool = True
    dependence_clustering: bool = True
    contextual_trust: bool = True
    epistemic_distance: bool = True
    falsification_weight: bool = True
    contest_mass: bool = True
    local_validation: bool = True
    probation: bool = True
    cap: float = CLUSTER_CAP
    mass_floor: float = MASS_FLOOR
    contest_ratio: float = CONTEST_RATIO
    relevance_floor: float = RELEVANCE_FLOOR
    probation_rounds: int = ECHO_PROBATION_ROUNDS

    def __post_init__(self) -> None:
        for name in MECHANISMS:
            if not isinstance(getattr(self, name), bool):
                raise ContractError(f"EchoConfig.{name} must be a bool")
        for name in ("cap", "mass_floor", "contest_ratio", "relevance_floor"):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value < 0
            ):
                raise ContractError(f"EchoConfig.{name} must be a finite non-negative number")
        if self.cap <= 0:
            raise ContractError("EchoConfig.cap must be > 0")
        if self.relevance_floor > 1.0:
            raise ContractError("EchoConfig.relevance_floor must be <= 1")
        rounds = self.probation_rounds
        if isinstance(rounds, bool) or not isinstance(rounds, int) or rounds < 0:
            raise ContractError("EchoConfig.probation_rounds must be a non-negative int")


#: The deployed configuration: every mechanism on (frozen, so safe as a shared default).
DEFAULT_ECHO_CONFIG: EchoConfig = EchoConfig()


@dataclass(frozen=True, slots=True)
class EchoInference:
    round_index: int
    decisions: tuple[EchoDecision, ...]
    keys_tracked: int
    keys_refused: int
    firing: tuple[tuple[str, int], ...]  # per enabled mechanism: decisions differing when it is off
    contributions_excluded: int = 0  # this round: held but not LIVE / signing key not usable
    keys_expired: int = 0  # cumulative: keys closed because every contribution expired


# --- internal state -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Contribution:
    peer_id: str
    capsule_id: str
    stance: Stance
    root: str
    relevance: float
    falsification: float
    key_id: str
    expiry_round: int


@dataclass(slots=True)
class _KeyEntry:
    invariant: tuple[MotifRow, ...]
    task: str
    opener: str  # the cluster that opened the key: charged against MAX_KEYS_PER_OPENER
    contributions: dict[str, _Contribution] = field(default_factory=dict)
    streak: int = 0
    last_met_round: int | None = None
    confirmed_clusters: set[str] = field(default_factory=set)


@dataclass(frozen=True, slots=True)
class _Outcome:
    status: EchoStatus
    reasons: tuple[str, ...]
    support_mass: float
    contest_mass: float
    support_clusters: int
    contest_clusters: int
    rows: tuple[ClusterEvidence, ...]
    streak: int
    met: bool


def _unit(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ContractError(f"{name} must be a finite number, got {value!r}")
    if not 0.0 <= value <= 1.0:
        raise ContractError(f"{name} must be in [0, 1], got {value!r}")
    return float(value)


def _survival(tried: int, survived: int) -> float:
    """``(survived + 1) / (tried + 2)``: SELF-REPORTED by the contributor, clipped to [0, 1]."""
    tried = max(0, int(tried))
    survived = min(max(0, int(survived)), tried)
    return (survived + 1) / (tried + 2)


def _contribution(pooled: PooledCapsule) -> _Contribution:
    capsule = pooled.capsule
    return _Contribution(
        peer_id=pooled.peer_id,
        capsule_id=capsule.capsule_id,
        stance=Stance(capsule.stance),
        root=capsule.provenance_commitment.provenance_root,
        relevance=_unit(pooled.relevance, "PooledCapsule.relevance"),
        falsification=_survival(
            capsule.falsification_summary.mutations_tried,
            capsule.falsification_summary.mutations_survived,
        ),
        key_id=capsule.key_id,
        expiry_round=capsule.expiry_round,
    )


def _decision_id(key: str, status: EchoStatus, rows: Sequence[ClusterEvidence]) -> str:
    """Stable while (key, status, evidence grouping) is unchanged (R7-2).

    Neither the round nor the drifting floats (trust decays every round) enter the id, so an
    unchanged ELIGIBLE key is ONE lineage node, not one per round: per-round ids flooded the
    descendant walk of every supporting capsule and hid the STAGE6_LINKs a revocation names.
    """
    material = [
        key,
        str(status),
        [[row.cluster_id, str(row.stance), row.identities, list(row.capsule_ids)] for row in rows],
    ]
    text = json.dumps(material, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return "agg-" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:_DECISION_HEX]


class EchoEngine:
    """Per-receiver ECHO. State: the per-key contribution table, probation streaks, suspects."""

    def __init__(
        self,
        *,
        local: LocalContext,
        validator: LocalValidator,
        trust: ContextualTrust,
        cluster_of: Callable[[str], str],
        config: EchoConfig = DEFAULT_ECHO_CONFIG,
        meter: WorkMeter | None = None,
        local_keys: Callable[[], Iterable[str]] | None = None,
        contribution_live: Callable[[str], bool] | None = None,
        key_active: Callable[[str, int], bool] | None = None,
    ) -> None:
        """``local_keys``: the LIVE sovereignty view (default: the frozen ``local.local_keys``).
        ``contribution_live``: capsule id -> its lineage node is LIVE. ``key_active``:
        (key id, round) -> the signing key still verifies. None means "always"."""
        if not isinstance(validator, LocalValidator):
            raise ContractError("EchoEngine needs a LocalValidator")
        if not isinstance(config, EchoConfig):
            raise ContractError("EchoEngine needs an EchoConfig")
        self._local = local
        self._validator = validator
        self._trust = trust
        self._cluster_of = cluster_of
        self._config = config
        self._meter = meter
        self._local_keys = local_keys if local_keys is not None else lambda: local.local_keys
        self._live = contribution_live
        self._key_active = key_active
        self._table: dict[str, _KeyEntry] = {}
        self._opened: dict[str, int] = {}  # opener cluster -> keys it opened that are still open
        self._suspect: dict[str, None] = {}
        self._keys_refused = 0
        self._quota_refused = 0
        self._keys_expired = 0
        self._contributions_refused = 0
        self._contributions_evicted = 0
        self._contributions_expired = 0
        self._suspect_refused = 0
        self._suspect_evictions = 0

    # -- intake ---------------------------------------------------------------------------

    def offer(self, pooled: Sequence[PooledCapsule]) -> int:
        """Record ANTIBODY contributions; returns how many were accepted into the table.

        One contribution per (key, peer): a peer's newer capsule replaces its older one, so
        re-sending never buys a second slot. A new key past the table cap or its opener's
        quota is refused, counted; a full key makes room only by evicting a surplus identity
        of an over-represented (cluster, stance) group, else refuses the newcomer, counted.
        """
        accepted = 0
        for item in pooled:
            capsule = item.capsule
            if capsule.knowledge_type != KnowledgeType.ANTIBODY:
                continue
            contribution = _contribution(item)
            key = capsule.compact_feature_signature
            entry = self._table.get(key)
            if entry is None:
                entry = self._open(key, capsule, contribution)
                if entry is None:
                    continue
            held = entry.contributions.get(item.peer_id)
            if held is not None and held.capsule_id == capsule.capsule_id:
                continue
            full = held is None and len(entry.contributions) >= MAX_CONTRIBUTIONS_PER_KEY
            if full and not self._make_room(entry, contribution):
                self._contributions_refused += 1
                continue
            entry.contributions[item.peer_id] = contribution
            accepted += 1
        return accepted

    def _open(
        self, key: str, capsule: KnowledgeCapsuleV1, first: _Contribution
    ) -> _KeyEntry | None:
        if len(self._table) >= MAX_KEYS_TRACKED:
            self._keys_refused += 1
            return None
        opener = self._group(first, self._config, {})
        if self._opened.get(opener, 0) >= MAX_KEYS_PER_OPENER:
            self._keys_refused += 1
            self._quota_refused += 1
            return None
        self._opened[opener] = self._opened.get(opener, 0) + 1
        task = "-".join(str(stage) for stage in capsule.causal_motif)
        entry = self._table[key] = _KeyEntry(tuple(capsule.semantic_invariant), task, opener)
        return entry

    def _close(self, key: str) -> None:
        entry = self._table.pop(key)
        left = self._opened.get(entry.opener, 0) - 1
        if left > 0:
            self._opened[entry.opener] = left
        else:
            self._opened.pop(entry.opener, None)

    def _make_room(self, entry: _KeyEntry, newcomer: _Contribution) -> bool:
        """Evict one surplus identity from the largest (cluster, stance) group, iff that group
        is at least two larger than the newcomer's own (so the eviction strictly improves the
        representation of independent groups). The victim is the member with the lowest
        relevance x survival, so the group's capped term (its best member) is unchanged."""
        cache: dict[str, str] = {}
        groups: dict[tuple[str, str], list[str]] = {}
        for peer_id, held in entry.contributions.items():
            group = (self._group(held, self._config, cache), str(held.stance))
            groups.setdefault(group, []).append(peer_id)
        own = (self._group(newcomer, self._config, cache), str(newcomer.stance))
        mine = len(groups.get(own, ()))
        _, members = max(groups.items(), key=lambda kv: (len(kv[1]), kv[0]))
        if len(members) <= mine + 1:
            return False
        victim = min(members, key=lambda p: (
            entry.contributions[p].relevance * entry.contributions[p].falsification,
            entry.contributions[p].capsule_id,
        ))
        del entry.contributions[victim]
        self._contributions_evicted += 1
        return True

    def mark_suspect(self, antibody_keys: Iterable[str]) -> None:
        """From the RevocationPlane. A tracked key's mark always fits (it may evict the oldest
        mark for an UNtracked key, counted); an untracked key's mark past the cap is refused."""
        for key in antibody_keys:
            if key in self._suspect:
                continue
            if len(self._suspect) < MAX_KEYS_TRACKED:
                self._suspect[key] = None
                continue
            victim = next((k for k in self._suspect if k not in self._table), None)
            if key in self._table and victim is not None:
                del self._suspect[victim]
                self._suspect_evictions += 1
                self._suspect[key] = None
            else:
                self._suspect_refused += 1

    def clear_suspect(self, antibody_keys: Iterable[str]) -> None:
        """Reinstatement. The probation streak restarts: a reinstated key re-earns eligibility."""
        for key in antibody_keys:
            if key not in self._suspect:
                continue
            del self._suspect[key]
            entry = self._table.get(key)
            if entry is not None:
                entry.streak = 0
                entry.last_met_round = None

    # -- the decision ---------------------------------------------------------------------

    def infer(self, *, round_index: int) -> EchoInference:
        if isinstance(round_index, bool) or not isinstance(round_index, int) or round_index < 0:
            raise ContractError(f"round_index must be a non-negative int, got {round_index!r}")
        self._expire(round_index)
        clusters: dict[str, str] = {}
        reliability: dict[tuple[str, str], float] = {}
        local_keys = frozenset(self._local_keys())
        enabled = tuple(name for name in MECHANISMS if getattr(self._config, name))
        firing = dict.fromkeys(enabled, 0)
        ablated = {name: replace(self._config, **{name: False}) for name in enabled}
        decisions = []
        outcomes: dict[str, tuple[_Outcome, LocalValidation, tuple[_Contribution, ...]]] = {}
        excluded = 0
        for key in sorted(self._table):
            entry = self._table[key]
            usable = self._usable(entry, round_index)
            excluded += len(entry.contributions) - len(usable)
            lv = self._validator.validate(entry.invariant)
            ctx = _Context(self, clusters, reliability, round_index, local_keys)
            outcome = _evaluate(key, entry, usable, lv, self._config, ctx)
            for name in enabled:
                counter = _evaluate(key, entry, usable, lv, ablated[name], ctx)
                if counter.status is not outcome.status:
                    firing[name] += 1
            outcomes[key] = (outcome, lv, usable)
            decisions.append(_decision(key, entry, outcome, lv, round_index))
        self._commit(outcomes, round_index)
        return EchoInference(
            round_index=round_index,
            decisions=tuple(decisions),
            keys_tracked=len(self._table),
            keys_refused=self._keys_refused,
            firing=tuple((name, firing[name]) for name in enabled),
            contributions_excluded=excluded,
            keys_expired=self._keys_expired,
        )

    def _expire(self, round_index: int) -> None:
        """Drop every contribution whose capsule has expired; close a key left with none.
        Rounds only move forward, so an expired contribution can never count again."""
        for key in tuple(self._table):
            entry = self._table[key]
            dead = [p for p, c in entry.contributions.items() if c.expiry_round <= round_index]
            for peer_id in dead:
                del entry.contributions[peer_id]
            self._contributions_expired += len(dead)
            if not entry.contributions:
                self._close(key)
                self._keys_expired += 1

    def _usable(self, entry: _KeyEntry, round_index: int) -> tuple[_Contribution, ...]:
        """The contributions that may carry mass this round (LIVE lineage, verifying key)."""
        live, active = self._live, self._key_active
        return tuple(
            c
            for c in entry.contributions.values()
            if (live is None or live(c.capsule_id) is True)
            and (active is None or active(c.key_id, round_index) is True)
        )

    def _commit(
        self,
        outcomes: Mapping[str, tuple[_Outcome, LocalValidation, tuple[_Contribution, ...]]],
        round_index: int,
    ) -> None:
        """Advance streaks, then record LOCAL_CONFIRMED as trust confirmations (once per
        key and cluster). Done after every decision so the counterfactuals saw one state.
        A REFUSED (local-origin) or SUSPECT key confirms nobody (S7-R3)."""
        for key, (outcome, lv, usable) in outcomes.items():
            entry = self._table[key]
            entry.streak = outcome.streak
            entry.last_met_round = round_index if outcome.met else None
            if lv is not LocalValidation.LOCAL_CONFIRMED or not self._config.local_validation:
                continue
            if outcome.status in (EchoStatus.REFUSED, EchoStatus.SUSPECT):
                continue
            for cluster in self._supporting_clusters(usable):
                if cluster not in entry.confirmed_clusters:
                    entry.confirmed_clusters.add(cluster)
                    self._trust.record(cluster, entry.task, confirmed=True, round_index=round_index)

    def record_outcome(self, antibody_key: str, *, confirmed: bool, round_index: int) -> None:
        """A local observation after eligibility -> ContextualTrust.record per supporting cluster.

        This, and LOCAL_CONFIRMED in ``infer``, are the only inputs to trust: a contest never
        refutes anyone (G7.5(c)). NOTE (S7-R5): no Stage 7 runtime path calls this yet, so
        the refutation half of the asymmetric update is unreachable in the fabric.
        """
        entry = self._table.get(antibody_key)
        if entry is None:
            raise ContractError(f"record_outcome for an untracked key {antibody_key!r}")
        if not isinstance(confirmed, bool):
            raise ContractError("record_outcome needs confirmed: bool")
        for cluster in self._supporting_clusters(self._usable(entry, round_index)):
            self._trust.record(cluster, entry.task, confirmed=confirmed, round_index=round_index)

    def _supporting_clusters(self, usable: Sequence[_Contribution]) -> tuple[str, ...]:
        found = {self._group(c, self._config, {}) for c in usable if c.stance is Stance.SUPPORT}
        return tuple(sorted(found))

    def _group(self, contribution: _Contribution, config: EchoConfig, cache: dict[str, str]) -> str:
        if not config.dependence_clustering:
            return contribution.root  # the control: declared roots trusted as independence
        cluster = cache.get(contribution.peer_id)
        if cluster is None:
            cluster = self._cluster_of(contribution.peer_id)
            if not isinstance(cluster, str) or not cluster:
                raise ContractError(f"cluster_of returned {cluster!r} for {contribution.peer_id!r}")
            cache[contribution.peer_id] = cluster
        return cluster

    # -- accounting -----------------------------------------------------------------------

    @property
    def config(self) -> EchoConfig:
        return self._config

    def keys_refused(self) -> int:
        return self._keys_refused

    def contributions_refused(self) -> int:
        return self._contributions_refused

    def bound_counters(self) -> Mapping[str, int]:
        """Every bound's refusals and evictions, cumulative (a flood must show up here)."""
        return {
            "keys_refused": self._keys_refused,
            "keys_quota_refused": self._quota_refused,
            "keys_expired": self._keys_expired,
            "contributions_refused": self._contributions_refused,
            "contributions_evicted": self._contributions_evicted,
            "contributions_expired": self._contributions_expired,
        }

    def suspect_counters(self) -> tuple[int, int]:
        """(marks refused, marks evicted) of the bounded suspect set."""
        return self._suspect_refused, self._suspect_evictions

    def memory_bytes(self) -> int:
        """An estimate: strings plus a fixed overhead per entry, contribution and mark."""
        total = sys.getsizeof(self._table) + sys.getsizeof(self._suspect)
        total += sys.getsizeof(self._opened) + sum(sys.getsizeof(k) + 32 for k in self._opened)
        for key, entry in self._table.items():
            total += (
                sys.getsizeof(key) + sys.getsizeof(entry.task) + 160 + 64 * len(entry.invariant)
            )
            total += sum(sys.getsizeof(c) for c in entry.confirmed_clusters)
            for peer, item in entry.contributions.items():
                total += sys.getsizeof(peer) + sys.getsizeof(item.capsule_id)
                total += sys.getsizeof(item.root) + sys.getsizeof(item.key_id) + 136
        total += sum(sys.getsizeof(key) for key in self._suspect)
        return total


# --- the pure per-key evaluation (shared by the decision and its counterfactuals) --------


class _Context:
    """Per-infer caches, so a counterfactual reads exactly the inputs the decision read."""

    __slots__ = ("clusters", "engine", "local_keys", "reliability", "round_index")

    def __init__(
        self,
        engine: EchoEngine,
        clusters: dict[str, str],
        reliability: dict[tuple[str, str], float],
        round_index: int,
        local_keys: frozenset[str],
    ) -> None:
        self.engine = engine
        self.clusters = clusters
        self.reliability = reliability
        self.round_index = round_index
        self.local_keys = local_keys

    def group(self, contribution: _Contribution, config: EchoConfig) -> str:
        return self.engine._group(contribution, config, self.clusters)

    def trust(self, cluster: str, task: str, config: EchoConfig) -> float:
        if not config.contextual_trust:
            return TRUST_PRIOR
        cached = self.reliability.get((cluster, task))
        if cached is None:
            cached = self.engine._trust.reliability(cluster, task, round_index=self.round_index)
            cached = _unit(cached, "ContextualTrust.reliability")
            self.reliability[(cluster, task)] = cached
        return cached

    def charge(self, units: int) -> None:
        if self.engine._meter is not None and units > 0:
            self.engine._meter.charge(units)


def _row(
    cluster: str, stance: Stance, members: Sequence[_Contribution], trust: float, config: EchoConfig
) -> ClusterEvidence:
    use_relevance = config.epistemic_distance
    weigh = config.falsification_weight and stance is Stance.SUPPORT
    relevances = [c.relevance if use_relevance else 1.0 for c in members]
    survivals = [c.falsification if weigh else 1.0 for c in members]
    relevance, survival = max(relevances), max(survivals)
    floor = config.relevance_floor if use_relevance else 0.0
    if config.cluster_cap:
        # ONE term per cluster: the identity count inside it never raises its mass.
        mass = 0.0 if relevance < floor else min(config.cap, trust * relevance * survival)
    else:
        # The CONTROL: an uncapped identity sum, exactly what a Sybil cluster would buy.
        mass = sum(trust * r * s for r, s in zip(relevances, survivals, strict=True) if r >= floor)
    if stance is Stance.CONTEST and not config.contest_mass:
        mass = 0.0
    ids = tuple(sorted(c.capsule_id for c in members))
    return ClusterEvidence(cluster, stance, len(members), ids, trust, relevance, survival, mass)


def _rows(
    entry: _KeyEntry, usable: Sequence[_Contribution], config: EchoConfig, ctx: _Context
) -> tuple[ClusterEvidence, ...]:
    buckets: dict[tuple[str, Stance], list[_Contribution]] = {}
    for item in usable:
        buckets.setdefault((ctx.group(item, config), item.stance), []).append(item)
    ctx.charge(len(usable))
    rows = [
        _row(cluster, stance, members, ctx.trust(cluster, entry.task, config), config)
        for (cluster, stance), members in buckets.items()
    ]
    rows.sort(key=lambda r: (-r.mass, r.cluster_id, str(r.stance)))
    return tuple(rows)


def _streak(entry: _KeyEntry, round_index: int) -> int:
    if entry.last_met_round == round_index:
        return entry.streak  # re-inferring a round already counted does not advance probation
    if entry.last_met_round is not None and entry.last_met_round == round_index - 1:
        return entry.streak + 1
    return 1


def _gate(
    key: str, lv: LocalValidation, config: EchoConfig, ctx: _Context
) -> tuple[EchoStatus, str] | None:
    engine = ctx.engine
    if key in ctx.local_keys:
        return EchoStatus.REFUSED, "local_origin"
    if key in engine._suspect:
        return EchoStatus.SUSPECT, "suspect"
    if config.local_validation and lv is LocalValidation.LOCAL_FP:
        return EchoStatus.CHALLENGED, "local_fp"
    if config.local_validation and lv is LocalValidation.NOT_OBSERVABLE:
        return EchoStatus.INSUFFICIENT, "not_observable"
    return None


def _evaluate(
    key: str,
    entry: _KeyEntry,
    usable: Sequence[_Contribution],
    lv: LocalValidation,
    config: EchoConfig,
    ctx: _Context,
) -> _Outcome:
    rows = _rows(entry, usable, config, ctx)
    support = sum(r.mass for r in rows if r.stance is Stance.SUPPORT)
    contest = sum(r.mass for r in rows if r.stance is Stance.CONTEST)
    counts = (
        sum(1 for r in rows if r.stance is Stance.SUPPORT and r.mass > 0),
        sum(1 for r in rows if r.stance is Stance.CONTEST and r.mass > 0),
    )
    gated = _gate(key, lv, config, ctx)
    met = (
        gated is None and support >= config.mass_floor and support >= config.contest_ratio * contest
    )
    streak = _streak(entry, ctx.round_index) if met else 0
    if gated is not None:
        status, reason = gated
    elif support < config.mass_floor:
        status, reason = EchoStatus.INSUFFICIENT, "below_mass_floor"
    elif not met:
        status, reason = EchoStatus.INSUFFICIENT, "contested"
    elif streak <= (config.probation_rounds if config.probation else 0):
        status, reason = EchoStatus.INSUFFICIENT, "probation"
    else:
        status, reason = EchoStatus.ELIGIBLE, "eligible"
    reasons = (reason, "local_confirmed") if lv is LocalValidation.LOCAL_CONFIRMED else (reason,)
    return _Outcome(status, reasons, support, contest, counts[0], counts[1], rows, streak, met)


def _decision(
    key: str, entry: _KeyEntry, outcome: _Outcome, lv: LocalValidation, round_index: int
) -> EchoDecision:
    rows = outcome.rows
    truncated = len(rows) > MAX_CLUSTERS_PER_DECISION
    shown = []
    for row in rows[:MAX_CLUSTERS_PER_DECISION]:
        if len(row.capsule_ids) > MAX_CAPSULE_IDS_PER_ROW:
            truncated = True
            row = replace(row, capsule_ids=row.capsule_ids[:MAX_CAPSULE_IDS_PER_ROW])
        shown.append(row)
    evidence = tuple(shown)
    return EchoDecision(
        decision_id=_decision_id(key, outcome.status, evidence),
        antibody_key=key,
        invariant=entry.invariant,
        status=outcome.status,
        local_validation=lv,
        support_mass=outcome.support_mass,
        contest_mass=outcome.contest_mass,
        support_clusters=outcome.support_clusters,
        contest_clusters=outcome.contest_clusters,
        eligible_rounds=outcome.streak,
        evidence=evidence,
        truncated=truncated,
        reasons=outcome.reasons,
        round_index=round_index,
    )
