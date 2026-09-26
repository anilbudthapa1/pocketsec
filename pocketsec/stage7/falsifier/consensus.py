"""D7.15 / ORPH-F14 — the consensus falsifier: every collective campaign belief meets its rivals.

Architecture §18: "every strong collective belief gets an adversarial counter-hypothesis ...
this prevents consensus from hardening merely because it is popular." A candidate partial
world (D7.12) is a set of cross-host fragments that *could* be one campaign. Before anyone
calls it one, six hypotheses are tested, always all six and always in this order:

* **H0 coincidence.** For each stage of the world, the Poisson upper tail of seeing at least
  that many fragments of that stage in the world's window, given ``rate(stage) *
  relevant_hosts * window length``; the stages are treated as independent, so ``p`` is the
  product of the per-stage tails. REJECTED iff ``p < COINCIDENCE_P``. A stage without a base
  rate leaves H0 UNEVALUATED (and therefore the world unsupported) rather than guessing one.
  Rates are per host per round and are the caller's chosen parameters, not measurements.
* **H1 shared software update.** SURVIVES iff every fragment carries one ``software_epoch``
  and that epoch first appeared inside the world's window. Without epoch history the test is
  UNEVALUATED unless the epochs already differ (then it is REJECTED without history).
  **Known residual, measured.** "Inside the window" is exact, so a world built only from a
  rollout's *later* hosts starts after the epoch first appeared and H1 rejects it. Shifting
  the ``SHARED_SOFTWARE_UPDATE`` arm's fragments into a staggered rollout (fragment *i*
  moved ``k*i`` rounds later, 8 cases per seed, run in the build session) turned cases into
  SUPPORTED false campaigns: seed 0 → 0/1/2/0/0 of 8 at k = 1/2/3/5/8, seed 1 → 0/2/1/0/0.
  At k >= 5 the fragments no longer join at all. The lab arm itself is a simultaneous
  rollout; a staggered one is not simulated as an arm, so G7.6 does not see this residual.
* **H2 common admin automation.** SURVIVES iff every fragment comes from one role and the
  window starts agree within ``ADMIN_SYNC_TOLERANCE_ROUNDS``. **Deviation from the spec,
  stated:** the spec also requires "one declared root". A :class:`Fragment` carries no root,
  and the dependence graph merges equal declared roots unconditionally (``SAME_ROOT``), so a
  world whose fragments share one root is one cluster and never reaches the falsifier (the
  hypergraph and reconstructor need two clusters). With the clause H2 could never fire. It
  is dropped; this makes H2 fire *more* often (more worlds explained as benign), the
  conservative direction, at the cost that a same-role worm with a synchronised start is
  explained as automation.
* **H3 telemetry artefact.** SURVIVES iff a strict majority of fragments are
  ``VisibilityClass.LOW``.
* **H4 colluding peers.** SURVIVES iff the fragments' clusters, **re-resolved now** through
  ``resolve_cluster``, number fewer than ``MIN_WORLD_CLUSTERS`` (the dependence graph may have
  merged identities after they contributed), or ``birth_burst`` says the contributors were
  born together. ``birth_burst`` receives the contributing capsule ids; the caller maps them
  to peers.
* **H5 real campaign.** SURVIVES iff H0-H4 are all REJECTED.

The ``explanation``: H5 iff H0-H4 are all REJECTED; ``None`` (UNIDENTIFIABLE, a valid answer)
when two or more benign hypotheses (H0-H3) survive, because none of these boolean tests
ranks one benign cause above another; otherwise the first survivor in enum order; ``None``
when nothing survives but something was UNEVALUATED. :class:`ConsensusFalsification`
re-derives the explanation from its tests on construction and refuses a mismatch, so no
caller can label a world H5 while a rival survives.

**Negative evidence (§19).** ``negative_evidence_weight`` is the product
``expected_observability * sensor_health * temporal_coverage * host_relevance``, and exactly
``0`` when the peer could not observe (``expected_observability == 0``): absence proves
nothing where nobody was looking. Claims count against a world only when their stage is one
of its stages and their window overlaps its window. They are summed per re-resolved cluster
and each cluster is capped at ``NEG_CLUSTER_CAP``, so one cluster of Sybils cannot veto by
volume. The reconstructor moves a world to UNRESOLVED when the total reaches
``NEG_EVIDENCE_FLOOR``; negative evidence **never deletes** a world.

**Not built, declared.** §18's "request/seek the cheapest privacy-safe observations that
distinguish the worlds" needs a peer query protocol the simulated fleet does not have; a
vocabulary of observation requests would have no consumer (lesson 3). It is UNMEASURED.

**Confound, declared.** The tests and the lab's common-cause arms (``labs/campaign_sim.py``)
share an author; a benign cause this module does not model is not rejected by it, it is
simply absent from its world (spec §9).

Everything here is advisory. The module never emits a verdict or a ``ThreatPredictionV1`` and
never hands anything to Stage 6.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_finite_unit_interval,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage7.campaign.hypergraph import Fragment
from pocketsec.stage7.capsule.knowledge_capsule import (
    MAX_WINDOW_ROUNDS,
    ChainStage,
    ObservabilityClaim,
    VisibilityClass,
)

if TYPE_CHECKING:  # the reconstructor imports this module; annotation only, no cycle at runtime
    from pocketsec.stage7.reconstruct.partial_world import PartialWorld

__all__ = [
    "ADMIN_SYNC_TOLERANCE_ROUNDS",
    "BENIGN_HYPOTHESES",
    "COINCIDENCE_P",
    "MIN_WORLD_CLUSTERS",
    "NEG_CLUSTER_CAP",
    "NEG_EVIDENCE_FLOOR",
    "ConsensusFalsification",
    "ConsensusFalsifier",
    "CounterHypothesis",
    "HypothesisStatus",
    "HypothesisTest",
    "NegativeClaim",
    "explanation_of",
    "negative_evidence_weight",
    "poisson_upper_tail",
]

#: §4.23. Chosen parameters, not measurements.
COINCIDENCE_P: float = 0.01
ADMIN_SYNC_TOLERANCE_ROUNDS: int = 0
NEG_CLUSTER_CAP: float = 1.0
NEG_EVIDENCE_FLOOR: float = 1.5
#: §4.23 places this in ``reconstruct/partial_world.py``, which re-exports it; it is defined
#: here because the reconstructor imports the falsifier and H4 needs the same number.
MIN_WORLD_CLUSTERS: int = 2


class CounterHypothesis(StrEnum):
    H0_COINCIDENCE = "H0_COINCIDENCE"
    H1_SHARED_UPDATE = "H1_SHARED_UPDATE"
    H2_ADMIN_AUTOMATION = "H2_ADMIN_AUTOMATION"
    H3_TELEMETRY_ARTIFACT = "H3_TELEMETRY_ARTIFACT"
    H4_COLLUDING_PEERS = "H4_COLLUDING_PEERS"
    H5_REAL_CAMPAIGN = "H5_REAL_CAMPAIGN"


#: The benign common causes. H4 is adversarial, H5 is the claim itself.
BENIGN_HYPOTHESES: frozenset[CounterHypothesis] = frozenset(
    {
        CounterHypothesis.H0_COINCIDENCE,
        CounterHypothesis.H1_SHARED_UPDATE,
        CounterHypothesis.H2_ADMIN_AUTOMATION,
        CounterHypothesis.H3_TELEMETRY_ARTIFACT,
    }
)
_RIVALS: tuple[CounterHypothesis, ...] = tuple(CounterHypothesis)[:5]


class HypothesisStatus(StrEnum):
    REJECTED = "REJECTED"
    SURVIVES = "SURVIVES"
    UNEVALUATED = "UNEVALUATED"


@dataclass(frozen=True, slots=True)
class HypothesisTest:
    hypothesis: CounterHypothesis
    status: HypothesisStatus
    statistic: float | None
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.hypothesis, CounterHypothesis):
            raise ContractError(f"HypothesisTest.hypothesis invalid: {self.hypothesis!r}")
        if not isinstance(self.status, HypothesisStatus):
            raise ContractError(f"HypothesisTest.status invalid: {self.status!r}")
        if self.statistic is not None and not math.isfinite(self.statistic):
            raise ContractError(f"HypothesisTest.statistic must be finite, got {self.statistic!r}")
        if not isinstance(self.reason, str) or not self.reason:
            raise ContractError("HypothesisTest.reason must be a non-empty string")


@dataclass(frozen=True, slots=True)
class NegativeClaim:
    """One peer's "I could have seen this stage in this window and did not" (§19)."""

    capsule_id: str
    cluster_id: str
    stage: ChainStage
    window: tuple[int, int]
    weight: float

    def __post_init__(self) -> None:
        require_identifier(self.capsule_id, "NegativeClaim.capsule_id")
        require_identifier(self.cluster_id, "NegativeClaim.cluster_id")
        if not isinstance(self.stage, ChainStage):
            raise ContractError(f"NegativeClaim.stage must be a ChainStage, got {self.stage!r}")
        if not isinstance(self.window, tuple) or len(self.window) != 2:
            raise ContractError(f"NegativeClaim.window must be (lo, hi), got {self.window!r}")
        lo = require_non_negative_int(self.window[0], "NegativeClaim.window[0]")
        hi = require_non_negative_int(self.window[1], "NegativeClaim.window[1]")
        if lo > hi or hi - lo > MAX_WINDOW_ROUNDS:
            raise ContractError(f"NegativeClaim.window invalid: {self.window!r}")
        require_finite_unit_interval(self.weight, "NegativeClaim.weight")


def explanation_of(tests: Sequence[HypothesisTest]) -> CounterHypothesis | None:
    """The one rule that turns six test results into an explanation (module docstring)."""
    rivals = tests[:5]
    if all(test.status is HypothesisStatus.REJECTED for test in rivals):
        return CounterHypothesis.H5_REAL_CAMPAIGN
    survivors = [test.hypothesis for test in rivals if test.status is HypothesisStatus.SURVIVES]
    if sum(1 for hypothesis in survivors if hypothesis in BENIGN_HYPOTHESES) >= 2:
        return None
    return survivors[0] if survivors else None


@dataclass(frozen=True, slots=True)
class ConsensusFalsification:
    world_id: str
    tests: tuple[HypothesisTest, ...]
    explanation: CounterHypothesis | None
    negative_weight: float

    def __post_init__(self) -> None:
        require_identifier(self.world_id, "ConsensusFalsification.world_id")
        if tuple(test.hypothesis for test in self.tests) != tuple(CounterHypothesis):
            raise ContractError("ConsensusFalsification needs exactly six tests, in enum order")
        if self.explanation != explanation_of(self.tests):
            raise ContractError(
                f"explanation {self.explanation} does not follow from the tests "
                f"(expected {explanation_of(self.tests)})"
            )
        if not math.isfinite(self.negative_weight) or self.negative_weight < 0.0:
            raise ContractError(
                f"negative_weight must be finite and >= 0, got {self.negative_weight!r}"
            )


def negative_evidence_weight(claim: ObservabilityClaim, *, host_relevance: float) -> float:
    """§19's product; exactly ``0`` for a peer that could not observe."""
    expected = require_finite_unit_interval(claim.expected_observability, "expected_observability")
    health = require_finite_unit_interval(claim.sensor_health, "sensor_health")
    coverage = require_finite_unit_interval(claim.temporal_coverage, "temporal_coverage")
    relevance = require_finite_unit_interval(host_relevance, "host_relevance")
    if expected == 0.0:
        return 0.0
    return expected * health * coverage * relevance


def poisson_upper_tail(rate: float, count: int) -> float:
    """``P(X >= count)`` for ``X ~ Poisson(rate)``, stdlib ``math`` only."""
    if not math.isfinite(rate) or rate < 0.0:
        raise ContractError(f"Poisson rate must be finite and >= 0, got {rate!r}")
    require_non_negative_int(count, "count")
    if count == 0:
        return 1.0
    if rate == 0.0:
        return 0.0
    term = math.exp(-rate)
    cumulative = term
    for k in range(1, count):
        term *= rate / k
        cumulative += term
    return min(1.0, max(0.0, 1.0 - cumulative))


def _test(hypothesis: CounterHypothesis, status: HypothesisStatus, statistic: float | None,
          reason: str) -> HypothesisTest:
    return HypothesisTest(hypothesis=hypothesis, status=status, statistic=statistic, reason=reason)


def _overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] <= b[1] and b[0] <= a[1]


class ConsensusFalsifier:
    """Runs H0-H5 against one candidate world. ``enabled=False`` evaluates nothing (ablation)."""

    def __init__(
        self,
        *,
        stage_base_rates: Mapping[ChainStage, float],
        relevant_hosts: int,
        enabled: bool = True,
    ) -> None:
        rates: dict[ChainStage, float] = {}
        for stage, rate in stage_base_rates.items():
            if not isinstance(stage, ChainStage):
                raise ContractError(f"stage_base_rates key must be a ChainStage, got {stage!r}")
            rates[stage] = require_finite_unit_interval(rate, f"stage_base_rates[{stage}]")
        if require_non_negative_int(relevant_hosts, "relevant_hosts") < 1:
            raise ContractError("relevant_hosts must be >= 1")
        self._rates = rates
        self._hosts = relevant_hosts
        self._enabled = bool(enabled)

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _h0(self, world: PartialWorld, fragments: Sequence[Fragment]) -> HypothesisTest:
        hypothesis = CounterHypothesis.H0_COINCIDENCE
        length = world.window[1] - world.window[0] + 1
        p_value = 1.0
        for stage in world.stages:
            if stage not in self._rates:
                return _test(
                    hypothesis, HypothesisStatus.UNEVALUATED, None, f"no_base_rate:{stage}"
                )
            observed = sum(1 for item in fragments if item.stage is stage)
            p_value *= poisson_upper_tail(self._rates[stage] * self._hosts * length, observed)
        status = HypothesisStatus.REJECTED if p_value < COINCIDENCE_P else HypothesisStatus.SURVIVES
        return _test(hypothesis, status, p_value, f"poisson_p={p_value:.3g}")

    @staticmethod
    def _h1(world: PartialWorld, fragments: Sequence[Fragment],
            epoch_first_seen: Callable[[str], int | None] | None) -> HypothesisTest:
        hypothesis = CounterHypothesis.H1_SHARED_UPDATE
        epochs = {item.software_epoch for item in fragments}
        if len(epochs) > 1:
            return _test(hypothesis, HypothesisStatus.REJECTED, float(len(epochs)), "epochs_differ")
        if epoch_first_seen is None:
            return _test(hypothesis, HypothesisStatus.UNEVALUATED, None, "no_epoch_history")
        first = epoch_first_seen(next(iter(epochs)))
        if first is None:
            return _test(hypothesis, HypothesisStatus.UNEVALUATED, None, "epoch_never_noted")
        fresh = world.window[0] <= first <= world.window[1]
        status = HypothesisStatus.SURVIVES if fresh else HypothesisStatus.REJECTED
        reason = "fresh_epoch" if fresh else "established_epoch"
        return _test(hypothesis, status, float(first), reason)

    @staticmethod
    def _h2(fragments: Sequence[Fragment]) -> HypothesisTest:
        hypothesis = CounterHypothesis.H2_ADMIN_AUTOMATION
        roles = {item.role for item in fragments}
        starts = [item.window[0] for item in fragments]
        spread = max(starts) - min(starts)
        synced = len(roles) == 1 and spread <= ADMIN_SYNC_TOLERANCE_ROUNDS
        status = HypothesisStatus.SURVIVES if synced else HypothesisStatus.REJECTED
        reason = "one_role_synchronised" if synced else f"roles={len(roles)},start_spread={spread}"
        return _test(hypothesis, status, float(spread), reason)

    @staticmethod
    def _h3(fragments: Sequence[Fragment]) -> HypothesisTest:
        hypothesis = CounterHypothesis.H3_TELEMETRY_ARTIFACT
        low = sum(1 for item in fragments if item.visibility is VisibilityClass.LOW)
        share = low / len(fragments)
        majority = 2 * low > len(fragments)
        status = HypothesisStatus.SURVIVES if majority else HypothesisStatus.REJECTED
        return _test(hypothesis, status, share, f"low_visibility_share={share:.3f}")

    @staticmethod
    def _h4(fragments: Sequence[Fragment], resolve: Callable[[str], str],
            birth_burst: Callable[[Sequence[str]], bool]) -> HypothesisTest:
        hypothesis = CounterHypothesis.H4_COLLUDING_PEERS
        clusters = {resolve(item.cluster_id) for item in fragments}
        burst = bool(birth_burst(tuple(item.capsule_id for item in fragments)))
        count = float(len(clusters))
        if len(clusters) < MIN_WORLD_CLUSTERS:
            return _test(hypothesis, HypothesisStatus.SURVIVES, count, "single_cluster")
        if burst:
            return _test(hypothesis, HypothesisStatus.SURVIVES, count, "birth_burst")
        return _test(hypothesis, HypothesisStatus.REJECTED, count, "independent_clusters")

    @staticmethod
    def negative_weight(world: PartialWorld, negative: Sequence[NegativeClaim],
                        resolve: Callable[[str], str]) -> float:
        """Σ over re-resolved clusters of ``min(NEG_CLUSTER_CAP, Σ relevant claim weights)``."""
        per_cluster: dict[str, float] = {}
        stages = set(world.stages)
        for claim in negative:
            if not isinstance(claim, NegativeClaim):
                raise ContractError(f"negative must hold NegativeClaim, got {type(claim).__name__}")
            if claim.stage in stages and _overlaps(claim.window, world.window):
                cluster = resolve(claim.cluster_id)
                per_cluster[cluster] = per_cluster.get(cluster, 0.0) + claim.weight
        return sum(min(NEG_CLUSTER_CAP, weight) for weight in per_cluster.values())

    def falsify(
        self,
        world: PartialWorld,
        fragments: Sequence[Fragment],
        *,
        negative: Sequence[NegativeClaim] = (),
        birth_burst: Callable[[Sequence[str]], bool],
        resolve_cluster: Callable[[str], str] | None = None,
        epoch_first_seen: Callable[[str], int | None] | None = None,
    ) -> ConsensusFalsification:
        """All six tests against ``world``; the explanation follows :func:`explanation_of`."""
        if not fragments:
            raise ContractError("falsify needs the world's fragments")
        if {item.capsule_id for item in fragments} != set(world.fragment_ids):
            raise ContractError("fragments do not match the world's fragment ids")
        resolve: Callable[[str], str] = resolve_cluster if resolve_cluster is not None else str
        weight = self.negative_weight(world, negative, resolve)
        if not self._enabled:
            tests = tuple(
                _test(hypothesis, HypothesisStatus.UNEVALUATED, None, "falsifier_disabled")
                for hypothesis in CounterHypothesis
            )
            return ConsensusFalsification(world.world_id, tests, None, weight)
        rivals = (
            self._h0(world, fragments),
            self._h1(world, fragments, epoch_first_seen),
            self._h2(fragments),
            self._h3(fragments),
            self._h4(fragments, resolve, birth_burst),
        )
        if all(test.status is HypothesisStatus.REJECTED for test in rivals):
            status, reason = HypothesisStatus.SURVIVES, "all_rivals_rejected"
        elif any(test.status is HypothesisStatus.SURVIVES for test in rivals):
            status, reason = HypothesisStatus.REJECTED, "a_rival_survives"
        else:
            status, reason = HypothesisStatus.UNEVALUATED, "a_rival_unevaluated"
        h5 = _test(CounterHypothesis.H5_REAL_CAMPAIGN, status, None, reason)
        tests = (*rivals, h5)
        return ConsensusFalsification(world.world_id, tests, explanation_of(tests), weight)
