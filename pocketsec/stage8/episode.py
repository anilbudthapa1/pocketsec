"""D8.3 (unit) — ``Episode``: the one unit of observation every Stage 8 package reads.

Stage 8 is a research loop, and a research loop that lets each of its eight packages
invent its own view of "a session" measures eight different things and calls them one.
This module is therefore the single observation unit: one Stage 1 ``ScenarioResult``
turned into a tuple of Stage 6 ``EncodedStep`` values, plus a lab label, a
:class:`Split` and lab metadata. Generators, the vault, the laboratory, FORGE and every
baseline read exactly this.

Why Stage 6's step type and not a new one: the only way a Stage 8 discovery ever reaches
an endpoint is as Stage 6 evidence capsules (spec §0 M0.2, ADR-0071). If an episode's
steps and the capsule's steps could differ, a mechanism measured here would be judged on
different data there. :func:`episode_from_result` therefore uses Stage 6's actor-slot
rule exactly (order of first appearance of ``transition.actor.identity``) and
``EncodedStep.from_transition`` — Stage 2's encoder, never a second one — and a test
asserts the steps equal ``capsule_from_scenario(result, ...).steps``.

What this module refuses, by construction:

* **Ground truth by the side door.** :func:`episode_from_result` never reads
  ``result.scenario``. The lab label arrives only as the explicit ``label`` argument,
  so two results that differ only in their scenario produce identical steps and ids.
* **Forged content addresses.** ``episode_id`` is ``"ep-"`` plus 24 hex of the sha256
  of the canonical steps *only*. Label, split and context are excluded on purpose: the
  same session placed in two splits keeps one id, which is what leakage detection keys
  on. An id that does not match the steps is refused.
* **Silent loss.** More than ``MAX_EPISODE_STEPS`` transitions are cut to the cap and
  ``truncated=True`` records it. The cap is Stage 6's own constant, imported, never
  redefined, so the two can never drift apart.
* **Metadata as a feature.** :class:`EpisodeContext` is lab bookkeeping (host, lab epoch,
  family, corpus). No method here turns it into a model input.

:class:`FitCounts` is the one confusion count used by the genome, the vault, FORGE and
the baselines. Its rates are ``None`` when undefined — never a plausible-looking 0.0.

This module decides nothing, holds no state and has no authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum

from pocketsec.stage0.contracts.common import ContractError, require_identifier
from pocketsec.stage1.pipeline import ScenarioResult
from pocketsec.stage2.compile_candidates.phi_oracle_candidate import PHI_SQUASHED_FEATURE_INDEX
from pocketsec.stage6.capsule.experience_capsule import (
    MAX_EVIDENCE_REFS_PER_CAPSULE,
    MAX_STEPS_PER_CAPSULE,
    EncodedStep,
)
from pocketsec.stage6.resources import WorkMeter

__all__ = [
    "EPISODE_ID_PATTERN",
    "EPISODE_VERSION",
    "MAX_CONTEXT_TEXT",
    "MAX_EPISODE_EVIDENCE",
    "MAX_EPISODE_STEPS",
    "Episode",
    "EpisodeContext",
    "FitCounts",
    "Split",
    "episode_from_result",
    "episode_id_for",
    "fit_counts",
]

EPISODE_VERSION = "stage8-episode.1.0.0"

# §4.21: Stage 6's caps, imported. Redefining them here would let an episode hold steps a
# capsule built from the same session cannot, and the one door would then drop them.
MAX_EPISODE_STEPS: int = MAX_STEPS_PER_CAPSULE
MAX_EPISODE_EVIDENCE: int = MAX_EVIDENCE_REFS_PER_CAPSULE
#: Longest ``family`` / ``corpus`` string an ``EpisodeContext`` accepts. Chosen.
MAX_CONTEXT_TEXT: int = 64

EPISODE_ID_PATTERN = re.compile(r"^ep-[0-9a-f]{24}$")
_CONTEXT_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]*$")


class Split(StrEnum):
    #: The only split PROMETHEUS, the observatory and the population may read.
    TRAIN = "TRAIN"
    #: Evaluated once, inside the vault, as one Bonferroni family.
    HOLDOUT = "HOLDOUT"
    #: Host-, time- and family-separated; evaluated once, in a second vault.
    REPLICATION = "REPLICATION"
    #: ORACLE's experiment pool.
    LAB_POOL = "LAB_POOL"
    #: Stage 1 benign sessions: the false-positive control.
    INDEPENDENT = "INDEPENDENT"
    #: Derived episodes (laboratory transforms, challenges, doppelgängers).
    CHALLENGE = "CHALLENGE"


@dataclass(frozen=True, slots=True)
class EpisodeContext:
    """Lab metadata about where an episode came from. NEVER a model feature.

    ``epoch_id`` is the lab split epoch (time separation), not the steps' own Stage 1
    ``epoch_id``; the two are different clocks and are kept apart by name.
    """

    host_id: str
    epoch_id: int
    family: str  # lab family name; "" when unknown
    corpus: str  # the generator's <NAME>_VERSION
    synthetic: bool

    def __post_init__(self) -> None:
        require_identifier(self.host_id, "EpisodeContext.host_id")
        if not isinstance(self.epoch_id, int) or isinstance(self.epoch_id, bool):
            raise ContractError(f"EpisodeContext.epoch_id must be an int, got {self.epoch_id!r}")
        if self.epoch_id < 0:
            raise ContractError(f"EpisodeContext.epoch_id must be >= 0, got {self.epoch_id}")
        if self.family != "":
            _require_context_text(self.family, "EpisodeContext.family")
        _require_context_text(self.corpus, "EpisodeContext.corpus")
        if not isinstance(self.synthetic, bool):
            raise ContractError("EpisodeContext.synthetic must be a bool")


def _require_context_text(value: object, field: str) -> None:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_CONTEXT_TEXT
        or not _CONTEXT_TEXT.fullmatch(value)
    ):
        raise ContractError(f"{field} must be a 1-{MAX_CONTEXT_TEXT} char code, got {value!r}")


def episode_id_for(steps: Sequence[EncodedStep]) -> str:
    """``"ep-"`` + 24 hex of the sha256 of the canonical steps — and of nothing else.

    Public because every package that derives an episode (laboratory transforms,
    challenges) must address it the same way; two derivations of one id are how two
    key spaces are born.
    """
    rows = [step.to_dict() for step in steps]
    text = json.dumps(rows, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return "ep-" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:24]


@dataclass(frozen=True, slots=True)
class Episode:
    """One session as Stage 6 steps, with a lab label, a split and lab metadata."""

    episode_id: str  # "ep-" + sha256(canonical steps)[:24]; "" derives; mismatch refused
    steps: tuple[EncodedStep, ...]  # 1 … MAX_EPISODE_STEPS
    label: int | None  # 0 / 1 lab ground truth, or None
    split: Split
    context: EpisodeContext
    truncated: bool  # True iff the source had > MAX_EPISODE_STEPS transitions

    def __post_init__(self) -> None:
        if not isinstance(self.steps, (tuple, list)):
            raise ContractError("Episode.steps must be a tuple of EncodedStep")
        steps = tuple(self.steps)
        if not 1 <= len(steps) <= MAX_EPISODE_STEPS:
            raise ContractError(f"an episode holds 1..{MAX_EPISODE_STEPS} steps, got {len(steps)}")
        if any(not isinstance(step, EncodedStep) for step in steps):
            raise ContractError("Episode.steps must hold EncodedStep values only")
        object.__setattr__(self, "steps", steps)
        label = self.label
        if label is not None and (type(label) is not int or label not in (0, 1)):
            raise ContractError(f"Episode.label must be 0, 1 or None, got {self.label!r}")
        if not isinstance(self.split, Split):
            raise ContractError(f"Episode.split must be a Split, got {self.split!r}")
        if not isinstance(self.context, EpisodeContext):
            raise ContractError("Episode.context must be an EpisodeContext")
        if not isinstance(self.truncated, bool):
            raise ContractError("Episode.truncated must be a bool")
        derived = episode_id_for(steps)
        if self.episode_id == "":
            object.__setattr__(self, "episode_id", derived)
        elif self.episode_id != derived:
            raise ContractError(
                f"episode_id {self.episode_id!r} does not match its steps ({derived})"
            )

    def phi_oracle_score(self) -> float:
        """Baseline (1): the Φ-oracle is ``max(step.features[73])`` over the episode."""
        if not self.steps:
            return 0.0
        return max(step.features[PHI_SQUASHED_FEATURE_INDEX] for step in self.steps)

    def evidence_digests(self) -> tuple[str, ...]:
        """Distinct evidence digests in step order, at most ``MAX_EPISODE_EVIDENCE``.

        A summary, like the capsule's ``evidence_refs``: every digest still travels on
        its own step, so cutting the summary loses nothing.
        """
        every = dict.fromkeys(digest for step in self.steps for digest in step.evidence)
        return tuple(every)[:MAX_EPISODE_EVIDENCE]

    def actors(self) -> frozenset[int]:
        return frozenset(step.actor_slot for step in self.steps)

    def with_split(self, split: Split, *, label: int | None) -> Episode:
        """The same steps under another split and label (derived episodes only).

        The id is unchanged by design: it is a content address of the steps, so a
        derived episode that reuses a held-out session is still recognisable as it.
        """
        return replace(self, split=split, label=label)


@dataclass(frozen=True, slots=True)
class FitCounts:
    """The one confusion count. Rates are ``None`` when their denominator is 0."""

    matched: int
    true_matches: int
    false_matches: int
    positives: int
    negatives: int

    def __post_init__(self) -> None:
        for name in ("matched", "true_matches", "false_matches", "positives", "negatives"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ContractError(f"FitCounts.{name} must be a non-negative int, got {value!r}")
        if self.true_matches + self.false_matches != self.matched:
            raise ContractError("FitCounts: true_matches + false_matches must equal matched")
        if self.true_matches > self.positives or self.false_matches > self.negatives:
            raise ContractError("FitCounts: more matches than labelled episodes of that class")

    @property
    def precision(self) -> float | None:
        return None if self.matched == 0 else self.true_matches / self.matched

    @property
    def recall(self) -> float | None:
        return None if self.positives == 0 else self.true_matches / self.positives

    @property
    def f1(self) -> float | None:
        precision, recall = self.precision, self.recall
        if precision is None or recall is None:
            return None
        if precision + recall == 0.0:
            return 0.0
        return 2.0 * precision * recall / (precision + recall)

    @property
    def false_positive_rate(self) -> float | None:
        return None if self.negatives == 0 else self.false_matches / self.negatives


def episode_from_result(
    result: ScenarioResult, *, split: Split, context: EpisodeContext, label: int | None
) -> Episode:
    """One ``ScenarioResult`` as an ``Episode``. Never reads ``result.scenario``.

    Stage 6's slot rule, exactly: ``actor_slot`` is the order of first appearance of
    ``transition.actor.identity`` among the transitions kept.
    """
    if not isinstance(result, ScenarioResult):
        raise ContractError(f"episode_from_result needs a ScenarioResult, got {type(result)}")
    transitions = result.transitions
    if not transitions:
        raise ContractError("a scenario with no transitions is not an episode")
    slots: dict[str, int] = {}
    steps: list[EncodedStep] = []
    for transition in transitions[:MAX_EPISODE_STEPS]:
        slot = slots.setdefault(transition.actor.identity, len(slots))
        steps.append(EncodedStep.from_transition(transition, actor_slot=slot))
    return Episode(
        episode_id="",
        steps=tuple(steps),
        label=label,
        split=split,
        context=context,
        truncated=len(transitions) > MAX_EPISODE_STEPS,
    )


def fit_counts(
    decide: Callable[[Episode], bool],
    episodes: Sequence[Episode],
    *,
    meter: WorkMeter | None = None,
) -> FitCounts:
    """Confusion counts of ``decide`` over the labelled episodes.

    Unlabelled episodes are skipped and counted nowhere: a count that silently treated
    "no label" as "benign" would report false positives the lab never asserted.
    ``meter`` is charged one unit per labelled episode (the count update); the work
    ``decide`` itself does is charged by ``decide``.
    """
    matched = true_matches = positives = negatives = 0
    for episode in episodes:
        if episode.label is None:
            continue
        if meter is not None:
            meter.charge(1)
        fired = bool(decide(episode))
        if episode.label == 1:
            positives += 1
            true_matches += fired
        else:
            negatives += 1
        matched += fired
    return FitCounts(
        matched=matched,
        true_matches=true_matches,
        false_matches=matched - true_matches,
        positives=positives,
        negatives=negatives,
    )
