"""ADR-0028 — Stage 3's corpus is Stage 2's drift corpus, replayed with its epoch signals.

This module builds **no corpus**. It composes three things that already exist:

* ``pocketsec.stage2.labs.drift_corpus.build_drift_corpus`` — three routine
  phases, two corroborated system changes and one uncorroborated change that must
  not open an epoch;
* ``pocketsec.stage1.pipeline.Stage1Pipeline`` — the only corpus walk in this
  repository (integration plan §3.1);
* ``pocketsec.stage2.gate_measures.DRIFT_EPOCH_SIGNALS`` — the out-of-band
  ``SystemChangeSignal`` for each change, so **behaviour never opens an epoch**.

The reason it exists at all is G2.13. Stage 2's exporter refuses the Φ-oracle
candidate because ``CandidateStability`` requires two distinct epochs and the
detection corpus has one. The fix is **not** to lower that requirement —
"frequency is not corroboration" is the anti-poisoning invariant (ADR-0007) and
weakening it to unblock a later stage is the exact failure this repository exists
to refuse. The fix is a corpus that genuinely has three epochs, which
``build_drift_corpus`` already is; all that was missing was somebody driving the
signals through ``EpochModel``. That is the twenty lines in
:func:`build_crystal_corpus`.

No fifth ``Scenario`` type is defined here, and no second corpus builder.

Three corpus properties are asserted **before anything is fitted**, because each
has already cost this project a result:

* :func:`session_identity_owners` — ``Stage1Pipeline`` carries lineage state
  across scenarios, so a corpus that reuses process identities saturates every
  lineage's privilege by the second session and erases its own signal. That
  produced a retracted +0.042 "improvement" out of label noise.
* :func:`median_peak_delta_phi` — if the median per-session peak ΔΦ is 0.00 for
  either class, there is no state-calculus signal to compile and every structural
  result measured on the corpus is noise.
* :func:`pooled_order_free_scores` — if a bag-of-operations model beats the base
  rate, the corpus leaks its label through operation vocabulary and no
  order-sensitive mechanism measured on it means anything.
"""

from __future__ import annotations

import math
import statistics
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.benchmark.security_metrics import average_precision
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.epoch.model import EpochDecision, SystemIdentity
from pocketsec.stage1.labs.corpus import Scenario
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage1.ssir.entities import Entity
from pocketsec.stage1.ssir.relations import RelationFamily, family_of
from pocketsec.stage1.ssir.transition import SSIRTransitionV1
from pocketsec.stage1.state.security_state import DIMENSIONS, SecurityStateV1
from pocketsec.stage1.state.potential import phi
from pocketsec.stage2.encoder.ssir_encoder import ENCODER_VERSION
from pocketsec.stage2.gate_measures import DRIFT_EPOCH_SIGNALS
from pocketsec.stage2.labs.drift_corpus import DRIFT_VERSION, build_drift_corpus, malicious_lineage
from pocketsec.stage3.cells.frame import CellFrame
from pocketsec.stage3.cells.masks import property_mask

__all__ = [
    "CRYSTAL_CORPUS_VERSION",
    "CrystalCorpus",
    "CrystalSession",
    "DEFAULT_CORPUS_COUNT",
    "DEFAULT_CORPUS_SEED",
    "build_crystal_corpus",
    "epoch_reasons",
    "median_peak_delta_phi",
    "operation_counts",
    "pooled_order_free_scores",
    "session_frames",
    "session_identity_owners",
    "vocabulary_leak",
]

#: Bumped whenever the composition changes — the drift builder, the signals, or
#: the frame projection. A snapshot or a baseline table carrying a different
#: version is a different corpus and is not comparable.
CRYSTAL_CORPUS_VERSION = f"stage3-crystal-corpus-v0.1.0+{DRIFT_VERSION}"

#: Stage 2's own drift fixtures use these (``tests/test_stage2_adaptation.py``).
#: Reusing them means a Stage 3 corpus property that fails here would have failed
#: there too, rather than being an artefact of a size we picked.
DEFAULT_CORPUS_COUNT = 60
DEFAULT_CORPUS_SEED = 11


@dataclass(frozen=True, slots=True)
class CrystalSession:
    """One scenario, replayed, with the epoch it ran in."""

    scenario: Scenario
    transitions: tuple[SSIRTransitionV1, ...]
    label: int
    technique: str | None
    epoch_id: int
    attack_lineage: str | None

    @property
    def peak_delta_phi(self) -> float:
        return max((abs(t.delta_phi) for t in self.transitions), default=0.0)


@dataclass(frozen=True, slots=True)
class CrystalCorpus:
    """The replayed drift corpus, with the epoch decisions that produced it."""

    version: str
    count: int
    seed: int
    split: str
    sessions: tuple[CrystalSession, ...]
    epoch_decisions: tuple[EpochDecision, ...]
    encoder_version: str

    @property
    def transitions(self) -> tuple[SSIRTransitionV1, ...]:
        return tuple(t for session in self.sessions for t in session.transitions)

    @property
    def distinct_epochs(self) -> int:
        """What ``CandidateStability`` counts. Two is the bar G2.13 sets."""
        return len({t.epoch_id for t in self.transitions})

    @property
    def corroborated_transitions(self) -> int:
        return sum(1 for decision in self.epoch_decisions if decision.transitioned)

    @property
    def labels(self) -> tuple[int, ...]:
        return tuple(session.label for session in self.sessions)

    @property
    def base_rate(self) -> float:
        labels = self.labels
        return sum(labels) / len(labels) if labels else 0.0

    def to_provenance(self) -> dict[str, Any]:
        return {
            "corpus_version": self.version,
            "count": self.count,
            "seed": self.seed,
            "split": self.split,
            "sessions": len(self.sessions),
            "transitions": len(self.transitions),
            "distinct_epochs": self.distinct_epochs,
            "corroborated_epoch_transitions": self.corroborated_transitions,
            "base_rate": self.base_rate,
            "encoder_version": self.encoder_version,
        }


def _observed_identity(
    current: SystemIdentity, changed: frozenset[str], epoch_id: int
) -> SystemIdentity:
    """What the host looks like after the change the corpus declared.

    The suffix is the *next* epoch id so two changes to the same component are
    distinguishable; without it a second package change would leave the identity
    unchanged and ``EpochModel`` would correctly report ``UNCHANGED``.
    """
    return SystemIdentity(
        **{
            name: (
                f"{getattr(current, name)}+{epoch_id + 1}"
                if name in changed
                else getattr(current, name)
            )
            for name in current.to_dict()
        }
    )


def build_crystal_corpus(
    *,
    count: int = DEFAULT_CORPUS_COUNT,
    seed: int = DEFAULT_CORPUS_SEED,
    split: str = "eval",
) -> CrystalCorpus:
    """Replay the drift corpus through one pipeline, driving its epoch signals.

    **One** pipeline for the whole corpus, deliberately: this is one host over
    time, and the epoch model's history is the thing under test. Stage 2's
    ``compile_split`` uses a pipeline per split for the opposite and equally
    deliberate reason — there, a shared pipeline would let the fitting split warm
    the novelty engine that scores the evaluation split.

    The signal is offered **after** the scenario that carries it has run, matching
    ``run_adaptation`` (``stage2/adaptation/epoch_guard.py``): the change is
    observed, then corroborated, then the next session runs in the new epoch.
    """
    if count < 8:
        raise ContractError(
            f"count={count} cannot hold three phases and two changes; "
            "the drift corpus places its changes at 25% and 50%"
        )
    scenarios = build_drift_corpus(count=count, seed=seed, split=split)
    pipeline = Stage1Pipeline()
    sessions: list[CrystalSession] = []
    decisions: list[EpochDecision] = []
    for index, scenario in enumerate(scenarios):
        result = pipeline.run_scenario(scenario, offset=index)
        sessions.append(
            CrystalSession(
                scenario=scenario,
                transitions=result.transitions,
                label=scenario.label,
                technique=scenario.technique,
                epoch_id=pipeline.epoch.epoch_id,
                attack_lineage=malicious_lineage(scenario),
            )
        )
        signal = DRIFT_EPOCH_SIGNALS.get(scenario.technique or "")
        if signal is None:
            continue
        decision = pipeline.epoch.evaluate(
            observed_identity=_observed_identity(
                pipeline.epoch.current.identity, signal.changed, pipeline.epoch.epoch_id
            ),
            corroborating_evidence=signal.corroborated,
            now_ns=(index + 1) * 1_000_000_000,
            # Passed at its floor: nothing in this harness routes behaviour into
            # an epoch decision, and the parameter makes that absence visible.
            behavioural_novelty=0.0,
        )
        decisions.append(decision)
    return CrystalCorpus(
        version=CRYSTAL_CORPUS_VERSION,
        count=count,
        seed=seed,
        split=split,
        sessions=tuple(sessions),
        epoch_decisions=tuple(decisions),
        encoder_version=ENCODER_VERSION,
    )


# --- frame projection ---------------------------------------------------------


def _fold(state: SecurityStateV1, transition: SSIRTransitionV1) -> SecurityStateV1:
    """Re-apply one transition's ΔS. Stage 1 owns the calculus; nothing new is invented."""
    for name, (_before, after) in transition.state_delta.raised.items():
        state = state.raised_to(name, DIMENSIONS[name](after))
    return state


def _asserted(entity: Entity) -> int:
    return property_mask(entity.semantics.asserted)


def session_frames(session: CrystalSession) -> tuple[CellFrame, ...]:
    """Project one replayed session into the only thing a cell may read.

    Identities are dropped here and never recovered: the frame carries property
    masks, not names (ADR-0006/0007). The window counts are per relation family
    within the session, which is bounded by Stage 1's vocabulary rather than by
    the session's length.
    """
    frames: list[CellFrame] = []
    state = SecurityStateV1()
    window: Counter[int] = Counter()
    for transition in session.transitions:
        before = state
        state = _fold(state, transition)
        window[int(family_of(transition.relation))] += 1
        frames.append(
            CellFrame(
                state=before,
                delta=transition.state_delta,
                actor_properties=_asserted(transition.actor),
                object_properties=_asserted(transition.object),
                relation_family=RelationFamily(family_of(transition.relation)),
                phi=phi(before).total,
                delta_phi=transition.delta_phi,
                uncertainty=transition.uncertainty,
                epoch_id=transition.epoch_id,
                window_counts=dict(window),
                evidence=transition.evidence,
                encoder_version=ENCODER_VERSION,
            )
        )
    return tuple(frames)


# --- the three mandatory corpus properties ------------------------------------


def session_identity_owners(
    scenarios: Sequence[Scenario],
) -> dict[tuple[str, str], set[str]]:
    """Which sessions each ``(pid, start_time)`` appears in.

    Any identity owned by more than one session is the retracted-result trap:
    ``Stage1Pipeline`` carries lineage state across scenarios, so a reused
    identity accumulates capability the corpus never described.
    """
    owners: dict[tuple[str, str], set[str]] = {}
    for scenario in scenarios:
        for behaviour in scenario.behaviours:
            identity = (str(behaviour.fields["pid"]), str(behaviour.fields["start_time"]))
            owners.setdefault(identity, set()).add(scenario.name)
    return owners


def median_peak_delta_phi(corpus: CrystalCorpus) -> dict[int, float]:
    """Median per-session peak |ΔΦ|, per class.

    Peak per session, not mean per transition: most transitions move Φ by zero in
    any corpus, so a per-transition median is 0.00 by construction and would say
    nothing about whether the corpus carries signal. This is the definition
    ``tests/test_stage2_adaptation.py`` already uses, reused so the two cannot
    disagree about what "the corpus has signal" means.
    """
    per_class: dict[int, list[float]] = {}
    for session in corpus.sessions:
        per_class.setdefault(session.label, []).append(session.peak_delta_phi)
    return {label: statistics.median(values) for label, values in per_class.items() if values}


def operation_counts(scenarios: Sequence[Scenario]) -> dict[int, Counter[str]]:
    """Per-class operation histograms — the vocabulary a counting model would see."""
    totals: dict[int, Counter[str]] = {}
    for scenario in scenarios:
        bucket = totals.setdefault(scenario.label, Counter())
        for behaviour in scenario.behaviours:
            bucket[behaviour.operation] += 1
    return totals


def pooled_order_free_scores(scenarios: Sequence[Scenario]) -> list[float]:
    """Multinomial naive Bayes over per-session operation counts.

    Order-free by construction and fitted on the very data it scores — the most
    generous baseline of its kind. If it beats the base rate, the corpus leaks its
    label through vocabulary and no order-sensitive Stage 3 result measured on it
    would mean anything.
    """
    vocabulary = sorted({b.operation for s in scenarios for b in s.behaviours})
    if not vocabulary:
        return [0.0 for _ in scenarios]
    totals = operation_counts(scenarios)
    labels = sorted(totals)
    sizes = {label: sum(totals[label].values()) for label in labels}
    log_p = {
        label: {
            operation: math.log(
                (totals[label][operation] + 1.0) / (sizes[label] + len(vocabulary))
            )
            for operation in vocabulary
        }
        for label in labels
    }
    scores: list[float] = []
    for scenario in scenarios:
        counts = Counter(b.operation for b in scenario.behaviours)
        per_label = {
            label: sum(counts[op] * log_p[label][op] for op in counts if op in log_p[label])
            for label in labels
        }
        positive = per_label.get(1, 0.0)
        negative = per_label.get(0, 0.0)
        scores.append(positive - negative)
    return scores


def vocabulary_leak(corpus: CrystalCorpus) -> tuple[float, float]:
    """``(pooled PR-AUC, base rate)``. The gap is what the corpus leaks."""
    scenarios = tuple(session.scenario for session in corpus.sessions)
    labels = [session.label for session in corpus.sessions]
    pooled = average_precision(labels, pooled_order_free_scores(scenarios)) or 0.0
    return pooled, corpus.base_rate


def epoch_reasons(corpus: CrystalCorpus) -> Mapping[str, int]:
    """How many epoch decisions of each reason the replay produced."""
    counts: Counter[str] = Counter()
    for decision in corpus.epoch_decisions:
        counts[decision.reason.value] += 1
    return dict(counts)
