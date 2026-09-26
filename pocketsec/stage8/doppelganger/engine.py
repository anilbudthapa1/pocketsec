"""D8.8 / PROM-F12 — the Benign Doppelgänger Engine: can a benign workload do the same thing?

A MALICIOUS-direction theory is only worth holding if the benign world does not already do
what it describes. Administration scripts, software updates, backups, package managers,
monitoring agents, developer tooling and orchestration all read credentials, connect out,
write to temporary locations and run what they wrote. This engine asks a
:class:`DoppelgangerSource` for label-0 sessions of each of those seven families and measures
how many of them the theory would match. A theory that matches its benign doppelgängers is
not separated from them, and the run records that as a ``DOPPELGANGER_SEPARATION`` refutation.

**A kill here is the engine working, not failing.** Planted mechanism PM2
(``REPEATED(CONNECT+EXTERNAL_ENDPOINT, 4)``) cannot be told apart from a monitoring agent that
reports home four or more times: the grammar has no actor properties (ADR-0072), so the only
honest outcome is that PM2 does not separate from ``MONITORING_AGENT`` (spec §4 D8.8).

What it refuses to do:

- It never challenges a BENIGN-direction genome: those *are* the benign explanations, and
  asking whether benign work resembles benign work measures nothing (:meth:`challenge`
  returns ``()`` and counts the skip).
- It never accepts a doppelgänger that is not label 0, nor one drawn from a held-out split
  (HOLDOUT / REPLICATION are evaluated once, inside the vault, and nowhere else).
- :meth:`separates` is never True over nothing: no results, or a family with no episodes
  tested, is not evidence of separation.
- It holds no research state beyond counters, writes no ledger entry and grants nothing. The
  caller records the outcome as a ``CHALLENGE_RESULT``.

Cost: every predicate test is paid through the run's :class:`ResearchGovernor` meter and
attributed to the ``doppelganger`` component, so a flood of challenges hits the budget.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol, runtime_checkable

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage8.episode import Episode, Split
from pocketsec.stage8.genome.grammar import StepPredicate
from pocketsec.stage8.genome.hypothesis import Direction, HypothesisGenome
from pocketsec.stage8.governor.budget import ResearchGovernor

__all__ = [
    "DOPPELGANGER_COMPONENT",
    "DOPPELGANGER_PER_FAMILY",
    "MAX_DOPPELGANGER_PER_FAMILY",
    "MAX_STRONGEST_EPISODES",
    "BenignDoppelganger",
    "DoppelgangerEngine",
    "DoppelgangerFamily",
    "DoppelgangerSource",
]

#: Spec §4.21. Chosen, not measured.
DOPPELGANGER_PER_FAMILY: int = 16
#: A hard ceiling on ``per_family``: 7 families x 256 episodes x 64 steps keeps one challenge
#: bounded even when a caller asks for "more". Chosen, not measured.
MAX_DOPPELGANGER_PER_FAMILY: int = 256
#: The strongest counterexamples a result names (spec: <= 4).
MAX_STRONGEST_EPISODES: int = 4
DOPPELGANGER_COMPONENT: str = "doppelganger"

#: Held-out splits are evaluated once, in the vault; a doppelgänger drawn from one would be
#: a second, unregistered look at them.
_VAULT_SPLITS: frozenset[Split] = frozenset({Split.HOLDOUT, Split.REPLICATION})


class DoppelgangerFamily(StrEnum):
    """The seven benign workloads a MALICIOUS theory must be separated from (architecture §19)."""

    ADMIN_SCRIPT = "ADMIN_SCRIPT"
    SOFTWARE_UPDATE = "SOFTWARE_UPDATE"
    BACKUP = "BACKUP"
    PACKAGE_MANAGER = "PACKAGE_MANAGER"
    MONITORING_AGENT = "MONITORING_AGENT"
    DEVELOPER_TOOLING = "DEVELOPER_TOOLING"
    ORCHESTRATION = "ORCHESTRATION"


@runtime_checkable
class DoppelgangerSource(Protocol):
    """Where benign alternatives come from. ``labs.discovery_corpus.CorpusDoppelgangers``
    implements it; every episode it returns is label 0 by lab construction."""

    def benign_alternatives(
        self, family: DoppelgangerFamily, *, count: int, seed: int
    ) -> tuple[Episode, ...]: ...


@dataclass(frozen=True, slots=True)
class BenignDoppelganger:
    """How one theory fared against one benign family. Plain data; decides nothing."""

    hypothesis_id: str
    family: DoppelgangerFamily
    episodes_tested: int
    matched: int
    matched_share: float
    partial_matches: int  # matched >= one necessary predicate but not the mechanism
    strongest_episode_ids: tuple[str, ...]  # <= 4: full matches first, then partial

    def __post_init__(self) -> None:
        if not isinstance(self.hypothesis_id, str) or not self.hypothesis_id:
            raise ContractError("BenignDoppelganger.hypothesis_id must be a non-empty string")
        if not isinstance(self.family, DoppelgangerFamily):
            raise ContractError(f"family must be a DoppelgangerFamily, got {self.family!r}")
        for name in ("episodes_tested", "matched", "partial_matches"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ContractError(f"BenignDoppelganger.{name} must be an int >= 0")
        if self.matched + self.partial_matches > self.episodes_tested:
            raise ContractError("full plus partial matches cannot exceed the episodes tested")
        expected = self.matched / self.episodes_tested if self.episodes_tested else 0.0
        if self.matched_share != expected:
            raise ContractError(f"matched_share must be matched / tested = {expected}")
        ids = tuple(self.strongest_episode_ids)
        if len(ids) > MAX_STRONGEST_EPISODES or len(set(ids)) != len(ids):
            raise ContractError(
                f"strongest_episode_ids holds <= {MAX_STRONGEST_EPISODES} distinct ids")
        object.__setattr__(self, "strongest_episode_ids", ids)


class DoppelgangerEngine:
    """Challenge a MALICIOUS theory with every benign family; report, never decide trust."""

    __slots__ = ("_governor", "_n", "_per_family", "_seed", "_source")

    def __init__(
        self,
        source: DoppelgangerSource,
        *,
        governor: ResearchGovernor,
        per_family: int = DOPPELGANGER_PER_FAMILY,
        seed: int = 0,
    ) -> None:
        if not isinstance(source, DoppelgangerSource):
            raise ContractError("DoppelgangerEngine needs a source with benign_alternatives()")
        if not isinstance(governor, ResearchGovernor):
            raise ContractError("DoppelgangerEngine needs the run's ResearchGovernor")
        if (isinstance(per_family, bool) or not isinstance(per_family, int)
                or not 1 <= per_family <= MAX_DOPPELGANGER_PER_FAMILY):
            raise ContractError(f"per_family must be an int in 1..{MAX_DOPPELGANGER_PER_FAMILY}")
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise ContractError(f"seed must be an int, got {seed!r}")
        self._source = source
        self._governor = governor
        self._per_family = per_family
        self._seed = seed
        self._n: Counter[str] = Counter()

    def challenge(self, genome: HypothesisGenome) -> tuple[BenignDoppelganger, ...]:
        """One :class:`BenignDoppelganger` per family, in enum order. ``()`` for BENIGN genomes."""
        if not isinstance(genome, HypothesisGenome):
            raise ContractError(f"challenge needs a HypothesisGenome, got {type(genome).__name__}")
        if genome.direction is not Direction.MALICIOUS:
            self._n["benign_direction_skipped"] += 1
            return ()
        self._n["challenges"] += 1
        return tuple(
            self._challenge_family(genome, family, self._seed + index)
            for index, family in enumerate(DoppelgangerFamily)
        )

    def separates(self, results: Sequence[BenignDoppelganger], *, threshold: float) -> bool:
        """True iff every family was tested and none matched a share above ``threshold``."""
        if isinstance(threshold, bool) or not isinstance(threshold, int | float):
            raise ContractError(f"threshold must be a number, got {threshold!r}")
        if not 0.0 <= float(threshold) <= 1.0:
            raise ContractError(f"threshold must be in [0, 1], got {threshold}")
        results = tuple(results)
        if any(not isinstance(item, BenignDoppelganger) for item in results):
            raise ContractError("separates takes BenignDoppelganger results only")
        if len({item.hypothesis_id for item in results}) > 1:
            raise ContractError("separates judges one hypothesis at a time")
        # Never True on nothing: an untested family is not a family we are separated from.
        if not results or any(item.episodes_tested == 0 for item in results):
            self._n["separation_unmeasured"] += 1
            return False
        failing = [item for item in results if item.matched_share > threshold]
        if failing:
            self._n["separation_failed"] += 1
            self._n["families_failed"] += len(failing)
            return False
        self._n["separation_passed"] += 1
        return True

    def stats(self) -> Mapping[str, int]:
        return MappingProxyType(dict(self._n))

    def _challenge_family(
        self, genome: HypothesisGenome, family: DoppelgangerFamily, seed: int
    ) -> BenignDoppelganger:
        episodes = self._draw(family, seed)
        necessary = genome.necessary_conditions
        full: list[str] = []
        partial: list[str] = []
        meter = self._governor.meter
        for episode in episodes:
            before = meter.spent
            fired = genome.decides(episode, meter=meter)
            # Name what decides() paid through the meter now, before the partial scan
            # charges the governor directly: the two must not be attributed twice.
            self._governor.account(DOPPELGANGER_COMPONENT, meter.spent - before)
            if fired:
                full.append(episode.episode_id)
            elif self._partially_matches(necessary, episode):
                partial.append(episode.episode_id)
        self._n["episodes_tested"] += len(episodes)
        self._n["full_matches"] += len(full)
        tested = len(episodes)
        return BenignDoppelganger(
            hypothesis_id=genome.hypothesis_id,
            family=family,
            episodes_tested=tested,
            matched=len(full),
            matched_share=len(full) / tested if tested else 0.0,
            partial_matches=len(partial),
            strongest_episode_ids=tuple((full + partial)[:MAX_STRONGEST_EPISODES]),
        )

    def _draw(self, family: DoppelgangerFamily, seed: int) -> tuple[Episode, ...]:
        episodes = self._source.benign_alternatives(family, count=self._per_family, seed=seed)
        if not isinstance(episodes, tuple):
            raise ContractError("a DoppelgangerSource returns a tuple of episodes")
        if len(episodes) > self._per_family:
            # More than asked for is a broken source, not a bonus: refusing keeps the bound.
            raise ContractError(
                f"source returned {len(episodes)} {family} episodes; {self._per_family} were asked"
            )
        for episode in episodes:
            if not isinstance(episode, Episode):
                raise ContractError(f"doppelgängers must be Episodes, got {type(episode).__name__}")
            if episode.label != 0:
                raise ContractError(
                    f"doppelgänger {episode.episode_id} of {family} is not label 0 "
                    f"(label={episode.label!r}): a benign alternative must be benign"
                )
            if episode.split in _VAULT_SPLITS:
                raise ContractError(
                    f"doppelgänger {episode.episode_id} comes from the held-out "
                    f"{episode.split} split"
                )
        return episodes

    def _partially_matches(self, necessary: Sequence[StepPredicate], episode: Episode) -> bool:
        for predicate in necessary:
            # Paid before the scan, as WorkMeter intends: a refused charge does no unpaid work.
            # An early hit therefore over-pays by at most one episode's steps.
            self._governor.charge(DOPPELGANGER_COMPONENT, len(episode.steps))
            if any(predicate.matches(step) for step in episode.steps):
                return True
        return False
