"""D8.10 / PROM-F14 — the Causal Identifiability Gate: could the data have told these apart?

A theory that fits is not yet a theory that was *identified*. If a rival mechanism makes the
same decision on every episode we can observe, the data cannot say which one is at work, and
Stage 8 must answer ``UNIDENTIFIABLE`` rather than pick the one its generator happened to
propose. The worked case (spec §4 D8.10): planted PM1 is ``PRECEDES(a, b)``; in the natural
corpus ``a`` always precedes ``b``, so ``CO_OCCURS(a, b)`` agrees with it everywhere and the
two form an equivalence class. Only a ``REORDER`` intervention, labelled by the lab oracle,
separates them — and only when interventions are permitted.

The rules, applied in this order, first hit wins (each maps to a Stage 0 :class:`Verdict`
answer, never a new one):

1. fewer than ``min_evidence`` labelled observed episodes the candidate matches →
   ``INSUFFICIENT_EVIDENCE`` (``Verdict.INSUFFICIENT_EVIDENCE``);
2. a rival that no offered episode distinguishes from the candidate →
   ``EQUIVALENCE_CLASS`` / ``NO_DISTINGUISHING_EPISODE``;
3. a rival distinguishable only by interventions that are not permitted →
   ``UNIDENTIFIABLE`` / ``ONLY_UNDER_INTERVENTION``;
4. a rival distinguishable only on episodes with an incomplete step →
   ``UNIDENTIFIABLE`` / ``ONLY_UNDER_INCOMPLETE_OBSERVATION``;
5. a rival that agrees with the labels strictly more often where the two disagree →
   ``UNIDENTIFIABLE`` / ``RIVAL_PREFERRED``;
6. at least ``min_distinguishing`` complete, labelled distinguishing episodes against every
   rival → ``IDENTIFIED``; otherwise ``UNIDENTIFIABLE`` / ``INSUFFICIENT_EVIDENCE``.

**Rule 2 reads every offered episode, permitted or not** (a documented reading of the spec):
if rule 2 counted only permitted interventions, a rival separable only by forbidden
interventions would always land in rule 2 and rule 3 could never fire. An equivalence class
here means *nothing offered* separates the two.

What it refuses to do:

- It never counts an unlabelled episode, and never counts an episode with an incomplete step
  towards identification (rules 5–6 read complete observations only): a sensor gap is not
  evidence for either mechanism.
- It refuses held-out episodes (HOLDOUT / REPLICATION are read once, in the vault), refuses
  a CHALLENGE episode passed as an *observation* (an intervention smuggled in as observation
  would defeat rule 3), and refuses an intervention that is not a CHALLENGE episode.
- With no rival supplied it does not claim identification: identified against nothing is
  not identified (rule 6 answers ``INSUFFICIENT_EVIDENCE``).
- It writes nothing. The caller records the verdict (``TheoryLedger.record_identifiability``)
  and carries it unchanged into any package.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage8.episode import Episode, Split
from pocketsec.stage8.forge.package import IdentifiabilityClass
from pocketsec.stage8.genome.hypothesis import MAX_COMPETITORS, Direction, HypothesisGenome

__all__ = [
    "MAX_ASSESSED_EPISODES",
    "MIN_DISTINGUISHING_EPISODES",
    "MIN_EVIDENCE_EPISODES",
    "REASONS",
    "IdentifiabilityGate",
    "IdentifiabilityVerdict",
]

#: Spec §4.21. Chosen, not measured.
MIN_DISTINGUISHING_EPISODES: int = 3
MIN_EVIDENCE_EPISODES: int = 10
#: One assessment reads at most this many episodes (observed plus interventions): twice the
#: vault's MAX_HOLDOUT_EPISODES. Chosen, not measured.
MAX_ASSESSED_EPISODES: int = 4096

IDENTIFIED = "IDENTIFIED"
NO_DISTINGUISHING_EPISODE = "NO_DISTINGUISHING_EPISODE"
ONLY_UNDER_INTERVENTION = "ONLY_UNDER_INTERVENTION"
ONLY_UNDER_INCOMPLETE_OBSERVATION = "ONLY_UNDER_INCOMPLETE_OBSERVATION"
RIVAL_PREFERRED = "RIVAL_PREFERRED"
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
#: The closed reason vocabulary, in rule order.
REASONS: tuple[str, ...] = (
    INSUFFICIENT_EVIDENCE,
    NO_DISTINGUISHING_EPISODE,
    ONLY_UNDER_INTERVENTION,
    ONLY_UNDER_INCOMPLETE_OBSERVATION,
    RIVAL_PREFERRED,
    IDENTIFIED,
)

_OBSERVABLE_SPLITS: frozenset[Split] = frozenset(
    {Split.TRAIN, Split.LAB_POOL, Split.INDEPENDENT}
)


@dataclass(frozen=True, slots=True)
class IdentifiabilityVerdict:
    """What the data can and cannot separate. ``verdict`` is None iff IDENTIFIED."""

    hypothesis_id: str
    klass: IdentifiabilityClass
    members: tuple[str, ...]  # the class (<= MAX_COMPETITORS), candidate first
    distinguishing_episodes: int
    reason: str
    verdict: Verdict | None

    def __post_init__(self) -> None:
        if not isinstance(self.klass, IdentifiabilityClass):
            raise ContractError(f"klass must be an IdentifiabilityClass, got {self.klass!r}")
        if self.reason not in REASONS:
            raise ContractError(f"reason must be one of {REASONS}, got {self.reason!r}")
        members = tuple(self.members)
        if not members or members[0] != self.hypothesis_id:
            raise ContractError("members must start with the candidate's hypothesis id")
        if len(members) > MAX_COMPETITORS or len(set(members)) != len(members):
            raise ContractError(f"members holds <= {MAX_COMPETITORS} distinct ids")
        count = self.distinguishing_episodes
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ContractError("distinguishing_episodes must be an int >= 0")
        identified = self.klass is IdentifiabilityClass.IDENTIFIED
        if identified != (self.reason == IDENTIFIED) or identified != (self.verdict is None):
            raise ContractError("IDENTIFIED, reason IDENTIFIED and verdict None go together")
        # Non-IDENTIFIED answers map onto Stage 0's own answers, never onto a new verdict.
        expected = (None if identified else Verdict.INSUFFICIENT_EVIDENCE
                    if self.reason == INSUFFICIENT_EVIDENCE else Verdict.UNIDENTIFIABLE)
        if self.verdict is not expected:
            raise ContractError(
                f"reason {self.reason} maps to verdict {expected}, got {self.verdict}")
        object.__setattr__(self, "members", members)


@dataclass(frozen=True, slots=True)
class _RivalEvidence:
    """Per rival: where the two mechanisms decide differently, by kind of episode."""

    rival_id: str
    observed: int  # labelled observed disagreements
    permitted_interventions: int  # labelled intervention disagreements, counted iff permitted
    forbidden_interventions: int  # labelled intervention disagreements, not permitted
    complete: int  # counted disagreements with every step observed
    candidate_right: int  # of the complete ones, the candidate agrees with the label
    rival_right: int


class IdentifiabilityGate:
    """Decide what the evidence can separate; answer UNIDENTIFIABLE rather than guess."""

    __slots__ = ("_interventions_permitted", "_min_distinguishing", "_min_evidence", "_n")

    def __init__(
        self,
        *,
        interventions_permitted: bool,
        min_distinguishing: int = MIN_DISTINGUISHING_EPISODES,
        min_evidence: int = MIN_EVIDENCE_EPISODES,
    ) -> None:
        if not isinstance(interventions_permitted, bool):
            raise ContractError("interventions_permitted must be a bool")
        for name, value in (("min_distinguishing", min_distinguishing),
                            ("min_evidence", min_evidence)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ContractError(f"{name} must be an int >= 1, got {value!r}")
        self._interventions_permitted = interventions_permitted
        self._min_distinguishing = min_distinguishing
        self._min_evidence = min_evidence
        self._n: Counter[str] = Counter()

    def assess(
        self,
        candidate: HypothesisGenome,
        rivals: Sequence[HypothesisGenome],
        observed: Sequence[Episode],
        interventions: Sequence[Episode] = (),
    ) -> IdentifiabilityVerdict:
        """Apply the six rules in order; the first that fires is the answer."""
        rivals = self._check_genomes(candidate, rivals)
        observed, interventions = self._check_episodes(observed, interventions)
        self._n["assessed"] += 1
        evidence = sum(1 for ep in observed if ep.label is not None and candidate.decides(ep))
        if evidence < self._min_evidence:
            return self._verdict(candidate, (), evidence, INSUFFICIENT_EVIDENCE)
        table = [self._evidence(candidate, rival, observed, interventions) for rival in rivals]
        equivalent = [row for row in table if row.observed + row.permitted_interventions
                      + row.forbidden_interventions == 0]
        if equivalent:
            return self._verdict(candidate, tuple(r.rival_id for r in equivalent), 0,
                                 NO_DISTINGUISHING_EPISODE)
        for row in table:
            if row.observed + row.permitted_interventions == 0:  # so forbidden_interventions > 0
                return self._verdict(candidate, (row.rival_id,), row.forbidden_interventions,
                                     ONLY_UNDER_INTERVENTION)
        for row in table:
            if row.complete == 0:
                counted = row.observed + row.permitted_interventions
                return self._verdict(candidate, (row.rival_id,), counted,
                                     ONLY_UNDER_INCOMPLETE_OBSERVATION)
        for row in table:
            if row.rival_right > row.candidate_right:
                return self._verdict(candidate, (row.rival_id,), row.complete, RIVAL_PREFERRED)
        weakest = min((row.complete for row in table), default=0)
        if table and weakest >= self._min_distinguishing:
            return self._verdict(candidate, (), weakest, IDENTIFIED)
        return self._verdict(candidate, (), weakest, INSUFFICIENT_EVIDENCE)

    def stats(self) -> Mapping[str, int]:
        """Firing counts: assessments and one counter per reason reached."""
        return MappingProxyType(dict(self._n))

    def _evidence(
        self,
        candidate: HypothesisGenome,
        rival: HypothesisGenome,
        observed: Sequence[Episode],
        interventions: Sequence[Episode],
    ) -> _RivalEvidence:
        counts: Counter[str] = Counter()
        for source, episodes in (("observed", observed), ("intervention", interventions)):
            for episode in episodes:
                if episode.label is None:
                    continue  # an unlabelled disagreement says nothing about which is right
                mine, theirs = candidate.decides(episode), rival.decides(episode)
                if mine == theirs:
                    continue
                if source == "observed":
                    counts["observed"] += 1
                elif not self._interventions_permitted:
                    counts["forbidden"] += 1
                    continue  # never read further: a forbidden intervention decides nothing
                else:
                    counts["permitted"] += 1
                if any(step.observation_incomplete for step in episode.steps):
                    continue
                counts["complete"] += 1
                truth = episode.label == _POSITIVE[candidate.direction]
                counts["candidate_right" if mine == truth else "rival_right"] += 1
        return _RivalEvidence(
            rival_id=rival.hypothesis_id,
            observed=counts["observed"],
            permitted_interventions=counts["permitted"],
            forbidden_interventions=counts["forbidden"],
            complete=counts["complete"],
            candidate_right=counts["candidate_right"],
            rival_right=counts["rival_right"],
        )

    def _verdict(
        self, candidate: HypothesisGenome, rival_ids: tuple[str, ...], count: int, reason: str
    ) -> IdentifiabilityVerdict:
        self._n[reason] += 1
        if reason == IDENTIFIED:
            klass, verdict = IdentifiabilityClass.IDENTIFIED, None
        elif reason == NO_DISTINGUISHING_EPISODE:
            klass, verdict = IdentifiabilityClass.EQUIVALENCE_CLASS, Verdict.UNIDENTIFIABLE
        elif reason == INSUFFICIENT_EVIDENCE:
            klass, verdict = IdentifiabilityClass.UNIDENTIFIABLE, Verdict.INSUFFICIENT_EVIDENCE
        else:
            klass, verdict = IdentifiabilityClass.UNIDENTIFIABLE, Verdict.UNIDENTIFIABLE
        members = (candidate.hypothesis_id, *rival_ids)[:MAX_COMPETITORS]
        return IdentifiabilityVerdict(
            hypothesis_id=candidate.hypothesis_id,
            klass=klass,
            members=members,
            distinguishing_episodes=count,
            reason=reason,
            verdict=verdict,
        )

    @staticmethod
    def _check_genomes(
        candidate: HypothesisGenome, rivals: Sequence[HypothesisGenome]
    ) -> tuple[HypothesisGenome, ...]:
        if not isinstance(candidate, HypothesisGenome):
            raise ContractError(
                f"candidate must be a HypothesisGenome, got {type(candidate).__name__}")
        rivals = tuple(rivals)
        if len(rivals) > MAX_COMPETITORS:
            raise ContractError(
                f"at most {MAX_COMPETITORS} rivals per assessment, got {len(rivals)}")
        ids = [candidate.hypothesis_id]
        for rival in rivals:
            if not isinstance(rival, HypothesisGenome):
                raise ContractError(f"rivals must be HypothesisGenomes, got {type(rival).__name__}")
            if rival.direction is not candidate.direction:
                raise ContractError("a rival predicts the same direction as the candidate")
            ids.append(rival.hypothesis_id)
        if len(set(ids)) != len(ids):
            raise ContractError("the candidate and its rivals must be distinct hypotheses")
        return rivals

    @staticmethod
    def _check_episodes(
        observed: Sequence[Episode], interventions: Sequence[Episode]
    ) -> tuple[tuple[Episode, ...], tuple[Episode, ...]]:
        observed, interventions = tuple(observed), tuple(interventions)
        if len(observed) + len(interventions) > MAX_ASSESSED_EPISODES:
            raise ContractError(f"an assessment reads at most {MAX_ASSESSED_EPISODES} episodes")
        for episode in (*observed, *interventions):
            if not isinstance(episode, Episode):
                raise ContractError(f"episodes must be Episodes, got {type(episode).__name__}")
        for episode in observed:
            if episode.split not in _OBSERVABLE_SPLITS:
                raise ContractError(
                    f"observed episode {episode.episode_id} is {episode.split}: observations are "
                    "TRAIN, LAB_POOL or INDEPENDENT (held-out splits live in the vault, and a "
                    "CHALLENGE episode is an intervention)"
                )
        for episode in interventions:
            if episode.split is not Split.CHALLENGE:
                raise ContractError(
                    f"intervention {episode.episode_id} is {episode.split}, not a CHALLENGE episode"
                )
        return observed, interventions


#: The label a match predicts, per direction.
_POSITIVE: Mapping[Direction, int] = MappingProxyType({Direction.MALICIOUS: 1, Direction.BENIGN: 0})
