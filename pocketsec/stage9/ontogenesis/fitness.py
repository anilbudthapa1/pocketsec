"""Worst-case fitness: how every Stage 9 genome is scored, charged and cached (spec §4.6).

Fitness is the one number the search optimises, so it is the one number most worth
attacking (architecture §51, "fitness hacking"). Three decisions here close the
obvious hacks, and each is recorded in ADR-0083:

* **Worst case, not average.** ``worst_case_ap`` is the *minimum* AP over the clean
  variant and every ARGUS scenario attack in the suite. A genome that is excellent on
  clean data and collapses under one label-preserving perturbation scores its collapse.
  An average would let five easy attacks pay for one fatal one.
* **Abstention is not a free pass.** A genome may abstain on a session (score
  ``None``); for ranking an abstention counts as ``0.0`` — the least suspicious score —
  and the number of abstentions is recorded. Abstaining on every hard session
  therefore cannot raise AP.
* **Work is paid for before it is done.** Every evaluation charges the caller's
  ``stage6.resources.WorkMeter`` through the phenotype, which charges *before*
  running. When the budget runs out ``WorkBudgetExceeded`` propagates: ``evaluate``
  never returns a record for a partially scored suite.

The cache is bounded (``MAX_CACHE_ENTRIES``, LRU) and counts hits, misses and
evictions; a hit costs 0 WU, which is the only way a re-evaluation can be free. Its key
binds the labels *and* every variant's content digest, so a shuffled-label control or a
contaminated suite can never be answered from the real suite's entry.

What this module refuses to do: it never scores a variant that failed the corpus audit
(an ``EvaluationSuite`` will not hold one), never averages over attacks, never treats an
unmeasured AP as a number (a variant without positives makes the worst case ``None``),
and never lets held-out sessions sit inside a training suite unnoticed
(``contamination_check``).
"""

from __future__ import annotations

import hashlib
import json
import random
from collections import OrderedDict
from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.benchmark.security_metrics import average_precision
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage2.dataset import Stage2Dataset
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage9.genome.computational import ComputationalGenomeV1
from pocketsec.stage9.labs.splits import (
    CLEAN,
    CompiledVariant,
    dataset_digest,
    session_content_digest,
)
from pocketsec.stage9.spec.mssc import ObjectiveVector

if TYPE_CHECKING:  # pragma: no cover - typing only; the adversary imports this module
    from pocketsec.stage9.argus.adversary import ArgusFinding

__all__ = [
    "ABSTAINED_RANK_SCORE",
    "CONTAMINATION_COPIES",
    "MAX_CACHE_ENTRIES",
    "ContaminationReport",
    "EvaluationCache",
    "EvaluationSuite",
    "FitnessRecord",
    "contamination_attack",
    "contamination_check",
    "evaluate",
    "score_ap",
    "scores_digest",
    "session_scores",
]

#: Chosen, not measured (spec §4.21).
MAX_CACHE_ENTRIES = 4096
#: The score an abstention ranks as: the least suspicious possible, so abstaining can
#: never move a session up the ranking.
ABSTAINED_RANK_SCORE = 0.0
#: Held-out sessions the contamination attack copies into train (spec §4.6).
CONTAMINATION_COPIES = 20


# --- scoring helpers ----------------------------------------------------------------------


def score_ap(labels: Sequence[int], scores: Sequence[float | None]) -> tuple[float | None, int]:
    """(AP with abstentions ranked as 0.0, number of abstentions). AP is stage0's."""
    ranked = [ABSTAINED_RANK_SCORE if score is None else float(score) for score in scores]
    abstained = sum(1 for score in scores if score is None)
    return average_precision(labels, ranked), abstained


def scores_digest(scores: Sequence[float | None]) -> str:
    """sha256 of a score vector, exact floats, ``None`` kept distinct from 0.0."""
    payload = json.dumps([None if score is None else float(score) for score in scores])
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def session_scores(
    genome: ComputationalGenomeV1, dataset: Stage2Dataset, *, meter: WorkMeter | None = None
) -> tuple[float | None, ...]:
    """One score per session (``None`` = abstained), charged to ``meter`` if given."""
    runs = genome.phenotype().run_dataset(dataset, meter=meter)
    return tuple(run.score for run in runs)


# --- the suite ----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EvaluationSuite:
    """A clean variant plus its attacked variants: what one fitness number is taken over."""

    name: str
    clean: CompiledVariant
    attacked: tuple[CompiledVariant, ...]
    labels_override: tuple[int, ...] | None = None  # shuffled-label / label-noise controls

    def __post_init__(self) -> None:
        if not self.name:
            raise ContractError("an EvaluationSuite needs a name")
        if self.clean.key.attack_id != CLEAN:
            raise ContractError(f"the clean variant is {self.clean.key.attack_id!r}, not clean")
        ids = [variant.key.attack_id for variant in self.attacked]
        if CLEAN in ids or len(set(ids)) != len(ids):
            raise ContractError(f"attacked variant ids must be unique and not clean: {ids}")
        base = (self.clean.key.corpus, self.clean.key.count, self.clean.key.seed)
        for variant in self.variants:
            if (variant.key.corpus, variant.key.count, variant.key.seed) != base:
                raise ContractError(f"{variant.key} is not a variant of the split {base}")
            if variant.audit_failures:
                raise ContractError(
                    f"variant {variant.key.attack_id!r} failed the corpus audit: "
                    + "; ".join(variant.audit_failures)
                )
        self._check_override()

    def _check_override(self) -> None:
        if self.labels_override is None:
            return
        if len(self.labels_override) != len(self.clean.dataset):
            raise ContractError(
                f"labels_override has {len(self.labels_override)} labels for "
                f"{len(self.clean.dataset)} sessions"
            )
        if any(label not in (0, 1) for label in self.labels_override):
            raise ContractError("labels_override may hold only 0 and 1")

    @property
    def variants(self) -> tuple[CompiledVariant, ...]:
        """Clean first, then the attacks in suite order."""
        return (self.clean, *self.attacked)

    @property
    def labels(self) -> tuple[int, ...]:
        """The clean variant's labels, or the override when this is a control suite."""
        if self.labels_override is not None:
            return self.labels_override
        return self.clean.dataset.labels

    @property
    def base_rate(self) -> float:
        labels = self.labels
        return sum(labels) / len(labels) if labels else 0.0

    @property
    def events_total(self) -> int:
        return sum(variant.dataset.transition_count for variant in self.variants)

    @property
    def labels_digest(self) -> str:
        """Binds the labels AND every variant's content digest (the cache key's third part)."""
        payload = json.dumps(
            {"labels": list(self.labels), "variants": [v.content_digest for v in self.variants]}
        )
        return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def labels_for(self, variant: CompiledVariant) -> tuple[int, ...]:
        """Labels aligned to ``variant``'s sessions (override mapped by sample id)."""
        if self.labels_override is None:
            return variant.dataset.labels
        if variant is self.clean:
            return self.labels_override
        by_id: dict[str, int] = {}
        for sample, label in zip(self.clean.dataset.samples, self.labels_override, strict=True):
            by_id.setdefault(sample.sample_id, label)
        missing = [s.sample_id for s in variant.dataset.samples if s.sample_id not in by_id]
        if missing:
            raise ContractError(f"variant sessions absent from the clean split: {missing[:3]}")
        return tuple(by_id[sample.sample_id] for sample in variant.dataset.samples)

    def with_shuffled_labels(self, seed: int) -> EvaluationSuite:
        """The same sessions under a random permutation of the labels (base rate kept)."""
        shuffled = list(self.labels)
        random.Random(seed).shuffle(shuffled)
        return replace(self, labels_override=tuple(shuffled))

    def with_label_noise(self, rate: float, seed: int) -> EvaluationSuite:
        """Flip exactly ``round(rate * n)`` labels, chosen without replacement."""
        if not 0.0 <= rate <= 1.0:
            raise ContractError(f"label-noise rate must be in [0, 1], got {rate}")
        labels = list(self.labels)
        flips = round(rate * len(labels))
        for index in random.Random(seed).sample(range(len(labels)), k=flips):
            labels[index] = 1 - labels[index]
        return replace(self, labels_override=tuple(labels))


# --- the record ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FitnessRecord:
    """One genome on one suite. Every figure was measured or is ``None``."""

    genome_digest: str
    suite: str
    clean_ap: float | None
    variant_aps: tuple[tuple[str, float | None], ...]  # clean first, then attacks
    worst_case_ap: float | None
    worst_variant: str
    wu_per_event: int
    state_bytes: int
    description_length_bits: float
    work_units_spent: int
    constant_output: bool
    lineage_evictions: int  # summed over every variant evaluated
    scores_digest: str  # sha256 of the clean score vector
    #: Sessions (over every variant) on which the genome abstained and was ranked 0.0.
    #: Added beyond spec §4.6's field list, which says abstentions are "counted" but
    #: names no field to count them in.
    abstained_sessions: int = 0
    #: Sessions (over every variant) longer than ``MAX_SESSION_EVENTS``: each abstained
    #: unprocessed and is also counted in ``abstained_sessions``. Carried so a bound that
    #: was hit reaches fitness and the gate instead of dying inside one SessionRun (S9-FC-02).
    truncated_sessions: int = 0

    def objective(self) -> ObjectiveVector:
        """The MSSC objective: worst-case AP up, WU/event down, state bytes down."""
        return ObjectiveVector(
            worst_case_ap=self.worst_case_ap,
            wu_per_event=self.wu_per_event,
            state_bytes=self.state_bytes,
            description_length_bits=self.description_length_bits,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "genome_digest": self.genome_digest,
            "suite": self.suite,
            "clean_ap": self.clean_ap,
            "variant_aps": [[name, ap] for name, ap in self.variant_aps],
            "worst_case_ap": self.worst_case_ap,
            "worst_variant": self.worst_variant,
            "wu_per_event": self.wu_per_event,
            "state_bytes": self.state_bytes,
            "description_length_bits": self.description_length_bits,
            "work_units_spent": self.work_units_spent,
            "constant_output": self.constant_output,
            "lineage_evictions": self.lineage_evictions,
            "scores_digest": self.scores_digest,
            "abstained_sessions": self.abstained_sessions,
            "truncated_sessions": self.truncated_sessions,
        }


CacheKey = tuple[str, str, str]


class EvaluationCache:
    """A bounded LRU of fitness records keyed (genome digest, suite name, labels digest)."""

    __slots__ = ("_capacity", "_entries", "_evictions", "_hits", "_misses")

    def __init__(self, capacity: int = MAX_CACHE_ENTRIES) -> None:
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
            raise ContractError(f"cache capacity must be a positive int, got {capacity!r}")
        self._capacity = capacity
        self._entries: OrderedDict[CacheKey, FitnessRecord] = OrderedDict()
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def capacity(self) -> int:
        return self._capacity

    def get(self, key: CacheKey) -> FitnessRecord | None:
        record = self._entries.get(key)
        if record is None:
            self._misses += 1
            return None
        self._entries.move_to_end(key)
        self._hits += 1
        return record

    def put(self, key: CacheKey, record: FitnessRecord) -> None:
        if key in self._entries:
            self._entries.move_to_end(key)
        elif len(self._entries) >= self._capacity:
            self._entries.popitem(last=False)
            self._evictions += 1
        self._entries[key] = record

    @property
    def hits(self) -> int:
        return self._hits

    @property
    def misses(self) -> int:
        return self._misses

    @property
    def evictions(self) -> int:
        return self._evictions


# --- evaluation ---------------------------------------------------------------------------


def _worst(variant_aps: Sequence[tuple[str, float | None]]) -> tuple[float | None, str]:
    """The minimum AP and its variant; an unmeasured variant makes the worst case unmeasured."""
    for name, ap in variant_aps:
        if ap is None:
            return None, name
    name, ap = min(variant_aps, key=lambda pair: pair[1] if pair[1] is not None else 0.0)
    return ap, name


@dataclass(frozen=True, slots=True)
class _SuiteRun:
    variant_aps: tuple[tuple[str, float | None], ...]
    clean_scores: tuple[float | None, ...]
    lineage_evictions: int
    abstained: int
    truncated: int = 0


def _run_suite(
    genome: ComputationalGenomeV1, suite: EvaluationSuite, meter: WorkMeter
) -> _SuiteRun:
    """Every variant, charged to ``meter``; an exhausted budget raises out of here."""
    phenotype = genome.phenotype()
    variant_aps: list[tuple[str, float | None]] = []
    evictions = abstained = truncated = 0
    clean_scores: tuple[float | None, ...] = ()
    for variant in suite.variants:
        runs = phenotype.run_dataset(variant.dataset, meter=meter)
        scores = tuple(run.score for run in runs)
        ap, variant_abstained = score_ap(suite.labels_for(variant), scores)
        variant_aps.append((variant.key.attack_id, ap))
        evictions += sum(run.lineage_evictions for run in runs)
        truncated += sum(1 for run in runs if run.truncated_events)
        abstained += variant_abstained
        if variant is suite.clean:
            clean_scores = scores
    return _SuiteRun(tuple(variant_aps), clean_scores, evictions, abstained, truncated)


def evaluate(
    genome: ComputationalGenomeV1,
    suite: EvaluationSuite,
    *,
    meter: WorkMeter,
    cache: EvaluationCache | None = None,
) -> FitnessRecord:
    """Score ``genome`` on every variant of ``suite``; fitness is the worst case.

    A cache hit returns the stored record and charges 0 WU. Otherwise every session of
    every variant is charged to ``meter`` before it runs; ``WorkBudgetExceeded``
    propagates and no record is produced (or cached).
    """
    key: CacheKey = (genome.digest, suite.name, suite.labels_digest)
    if cache is not None:
        cached = cache.get(key)
        if cached is not None:
            return cached
    spent_before = meter.spent
    run = _run_suite(genome, suite, meter)
    worst, worst_variant = _worst(run.variant_aps)
    ranked_clean = {ABSTAINED_RANK_SCORE if s is None else float(s) for s in run.clean_scores}
    bounds = genome.bounds
    record = FitnessRecord(
        genome_digest=genome.digest,
        suite=suite.name,
        clean_ap=run.variant_aps[0][1],
        variant_aps=run.variant_aps,
        worst_case_ap=worst,
        worst_variant=worst_variant,
        wu_per_event=bounds.update_wu_per_event,
        state_bytes=bounds.session_state_bytes_max,
        description_length_bits=genome.description_length_bits(),
        work_units_spent=meter.spent - spent_before,
        constant_output=len(ranked_clean) <= 1,
        lineage_evictions=run.lineage_evictions,
        scores_digest=scores_digest(run.clean_scores),
        abstained_sessions=run.abstained,
        truncated_sessions=run.truncated,
    )
    if cache is not None:
        cache.put(key, record)
    return record


# --- contamination ------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ContaminationReport:
    """Overlap between a training suite and a held-out suite. Any overlap refuses."""

    overlapping_sample_ids: int  # ids qualified by (corpus, count, seed)
    overlapping_content: int  # sessions whose content digest (id excluded) matches
    refused: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "overlapping_sample_ids": self.overlapping_sample_ids,
            "overlapping_content": self.overlapping_content,
            "refused": self.refused,
        }


def _qualified_ids(variant: CompiledVariant) -> set[str]:
    key = variant.key
    return {f"{key.corpus}/{key.count}/{key.seed}/{s.sample_id}" for s in variant.dataset}


def contamination_check(train: EvaluationSuite, heldout: EvaluationSuite) -> ContaminationReport:
    """Refuse when any held-out session is also a training session.

    Ids are qualified by the split key, because the generator reuses ``amb-eval-NNNN``
    at every seed; content is compared id-free, because a copied session can be renamed.
    """
    shared_ids = _qualified_ids(train.clean) & _qualified_ids(heldout.clean)
    train_content = {session_content_digest(s) for s in train.clean.dataset.samples}
    shared_content = sum(
        1 for s in heldout.clean.dataset.samples if session_content_digest(s) in train_content
    )
    return ContaminationReport(
        overlapping_sample_ids=len(shared_ids),
        overlapping_content=shared_content,
        refused=bool(shared_ids) or shared_content > 0,
    )


def _contaminated(train: EvaluationSuite, heldout: EvaluationSuite) -> EvaluationSuite:
    copies = heldout.clean.dataset.samples[:CONTAMINATION_COPIES]
    dataset = replace(
        train.clean.dataset,
        name=f"{train.clean.dataset.name}+contaminated",
        samples=(*train.clean.dataset.samples, *copies),
    )
    clean = replace(train.clean, dataset=dataset, content_digest=dataset_digest(dataset))
    override = None
    if train.labels_override is not None:
        override = (*train.labels_override, *(sample.label for sample in copies))
    return EvaluationSuite(
        name=f"{train.name}+contaminated",
        clean=clean,
        attacked=train.attacked,
        labels_override=override,
    )


def contamination_attack(train: EvaluationSuite, heldout: EvaluationSuite) -> ArgusFinding:
    """ARGUS ``benchmark_contamination`` [SEARCH]: copy 20 held-out sessions into train.

    A DEFENCE: ``contamination_check`` must refuse the contaminated pair (fired = 1 of 1).
    """
    from pocketsec.stage9.argus.adversary import ArgusFinding, ArgusSurface  # cycle-free

    before = contamination_check(train, heldout)
    after = contamination_check(_contaminated(train, heldout), heldout)
    copies = min(CONTAMINATION_COPIES, len(heldout.clean.dataset))
    return ArgusFinding(
        attack_id="benchmark_contamination",
        surface=ArgusSurface.SEARCH,
        kind="DEFENCE",
        fired=1 if after.refused else 0,
        inert=not after.refused,
        total=1,
        metric_before=float(before.overlapping_content),
        metric_after=float(after.overlapping_content),
        detail=(
            f"copied {copies} held-out sessions into train; check refused={after.refused} "
            f"(content overlap {before.overlapping_content} -> {after.overlapping_content}, "
            f"qualified-id overlap {before.overlapping_sample_ids} -> "
            f"{after.overlapping_sample_ids}); the uncontaminated pair was "
            f"{'already refused' if before.refused else 'clean'}"
        ),
        measured_by="ontogenesis.fitness:contamination_attack",
    )
