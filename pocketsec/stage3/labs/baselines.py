"""D3.15 — the five controls that decide whether Stage 3 survives, in one run.

These are the **dumbest things that could work**, and they are the comparison,
not a formality. Stage 2 already found that an atom/epoch-keyed cache *loses* to
a plain LRU keyed on ``(relation_family, state_delta_mask)`` (PROGRESS.md, G2.10:
0.9966 vs 0.9977). Expect the same family of result here.

===  ==================  ==========================================================
id   baseline            what it is
===  ==================  ==========================================================
B1   PlainLookupTable    ``dict[BoundaryKey, float]`` — no invariant, no boundary, no VM
B2   DepthLimitedTree    depth<=4 Gini tree on ``EncodedTransition`` features, stdlib
B3   PhiOracleUnchanged  ``DeterministicScorerSpec`` at feature 73, invoked directly
B4   FrozenTeacherLRU    Stage 2's ``TransitionCache`` + ``lru_control``, serving a snapshot
B5   NoStage3            the Stage 1 Φ path plus a drift detector
S3   CellPathBaseline    **not a control** — the Stage 3 runtime path, measured alongside
===  ==================  ==========================================================

**B3 is the real bar.** It is a zero-parameter rule that costs roughly 0.1
microseconds per event (cited from ``planning/MEMORY.md``, not measured here). If
a ``KnowledgeCellV1`` reproducing it costs more microseconds *or* more bytes at
identical scores, that is falsifier F1: a measured rejection of the cell format
for this class of knowledge, and it must be reported as one rather than explained
away.

Everything runs in **one process, one run**, so every comparison is a within-run
ratio. Absolute microseconds are recorded beside ``/proc/loadavg`` and are never
presented as device measurements: this host is shared, and a Stage 2 gate run
measured a 7x wall-clock inflation at load 23-67 versus load 8-12.

**A control below the base rate is a bug, not a result.** If any of the five
fails to beat the corpus base rate the table is ``REFUSED`` with the offenders
named, because a comparison against a broken control tells you nothing.

The table also carries an ``S3`` row — the cell path from
``labs/cell_path.py``. That row is the **mechanism**, not a control, so it does
**not** gate the report: if S3 lands at or below chance that is a result about
Stage 3, and refusing to report it would hide the most important thing measured.

:class:`TeacherErrorCase` and :func:`teacher_error_cases` are re-exported here
from ``labs/teacher_error.py``, where gate criterion G3.5's three constructed
teacher errors and their teacher-only control live.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.benchmark.security_metrics import evaluate_scores
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage2.cache.transition_cache import (
    CORE_INFERENCE_UNITS,
    CachedTransition,
    TransitionCache,
    transition_cache_key,
)
from pocketsec.stage2.cache.utility import lru_control
from pocketsec.stage2.compile_candidates.phi_oracle_candidate import (
    PHI_ORACLE_SCORER,
    PHI_SQUASHED_FEATURE_INDEX,
)
from pocketsec.stage2.encoder.ssir_encoder import (
    ENCODER_VERSION,
    FEATURE_WIDTH,
    encode_ssir_transition,
)
from pocketsec.stage2.gate_measures import lineage_windows
from pocketsec.stage3.cells.frame import CellFrame, boundary_key_of
from pocketsec.stage3.cells.masks import BoundaryKey
from pocketsec.stage3.labs.crystal_corpus import CrystalCorpus, CrystalSession, session_frames
from pocketsec.stage3.labs.cell_path import CellPathBaseline, phi_oracle_cell
from pocketsec.stage3.labs.teacher_error import TeacherErrorCase, teacher_error_cases
from pocketsec.stage3.oracles.teacher import (
    TeacherOracle,
    TeacherSnapshotV1,
    phi_oracle_score,
)
from pocketsec.stage3.resources import loadavg

__all__ = [
    "AT_CHANCE_PR_AUC_BAND",
    "BASELINE_IDS",
    "BaselineRow",
    "BaselineTable",
    "CellPathBaseline",
    "DepthLimitedTree",
    "FrozenTeacherLRU",
    "NoStage3",
    "PhiOracleUnchanged",
    "PlainLookupTable",
    "TeacherErrorCase",
    "measure_microseconds",
    "measure_microseconds_with_spread",
    "model_bytes",
    "phi_oracle_cell",
    "run_baselines",
    "teacher_error_cases",
]

BASELINE_IDS: tuple[str, ...] = ("B1", "B2", "B3", "B4", "B5")


#: Timing repetitions. Best-of-N, never the mean: the minimum is the figure least
#: polluted by unrelated load, and this host is shared. Same convention as
#: ``pocketsec/stage2/gate_criteria.py:scorer_microseconds``.
TIMING_REPETITIONS = 5

#: Threshold and budget passed to ``evaluate_scores``. Fixed across every row so
#: the confusion matrices are comparable; PR-AUC itself is threshold-free.
#: Half-width of the band in which a PR-AUC is *indistinguishable from chance*.
#: ``labs/ablation.SATURATION_PR_AUC_BAND`` is this same number, imported from
#: here, because one band cannot mean "the split cannot tell models apart" in one
#: module and nothing at all in the other.
AT_CHANCE_PR_AUC_BAND = 0.01

SCORE_THRESHOLD = 0.5
FPR_BUDGET = 0.01

#: Per-row disclosure of what its timing actually covers. Every row is timed
#: end-to-end from a ``CrystalSession`` to a score, including whatever per-session
#: structure it has to build; that is consistent across rows and is the figure a
#: host would pay, but it means no row's microseconds are the cost of its scoring
#: rule alone.
_NOTES: Mapping[str, str] = {
    "B3": (
        "timing covers lineage-window construction as well as the scorer; the "
        "~0.1 us/event figure cited for the Φ-oracle in planning/MEMORY.md is the "
        "scorer alone and is NOT what this row measures"
    ),
    "B5": "scores are B3's by construction; only drift behaviour differs",
    "S3": (
        "not a baseline — the mechanism the baselines control for. Its scores are "
        "clamp01(ΔΦ), not the Φ-oracle's squashed score: the PCB ISA has no "
        "division opcode, so F1's 'identical scores' precondition is not met"
    ),
}


def model_bytes(payload: object) -> int:
    """Resident bytes of a model's own data, as canonical JSON.

    Measured from the bytes rather than estimated from a parameter count, for the
    same reason ``OperatorProgram.size_bytes`` is: G3.9 compares bytes across
    models with different shapes, and an estimate would be comparing two
    estimators rather than two models.
    """
    canonical = json.dumps(
        payload, sort_keys=True, allow_nan=False, separators=(",", ":")
    )
    return len(canonical.encode("utf-8"))


def measure_microseconds(
    scorer: Callable[[CrystalSession], float],
    sessions: Sequence[CrystalSession],
    *,
    repetitions: int = TIMING_REPETITIONS,
) -> tuple[float | None, int]:
    """Best-of-N microseconds per *transition*, and the event count it covers.

    Per transition rather than per session, because "events" is the unit every
    other cost figure in this repository uses and a per-session figure would
    silently reward a corpus with longer sessions.

    Returns ``(None, 0)`` when there is nothing to time. ``None`` is UNMEASURED
    and is never rendered as a small number.
    """
    best, events, _spread = measure_microseconds_with_spread(
        scorer, sessions, repetitions=repetitions
    )
    return best, events


def measure_microseconds_with_spread(
    scorer: Callable[[CrystalSession], float],
    sessions: Sequence[CrystalSession],
    *,
    repetitions: int = TIMING_REPETITIONS,
) -> tuple[float | None, int, tuple[float, float] | None]:
    """Best-of-N, the event count, and the ``(min, max)`` over the repetitions.

    The spread exists because a single best-of-N sample with no dispersion beside
    it invites a reader to treat a ratio built from two such samples as a
    measurement with an error bar of zero. It has none: this host is contended,
    and the repetitions of one timing already differ. Reported, not smoothed.
    """
    events = sum(len(session.transitions) for session in sessions)
    if not sessions or events == 0:
        return None, 0, None
    samples: list[float] = []
    for _ in range(max(1, repetitions)):
        started = time.perf_counter()
        for session in sessions:
            scorer(session)
        samples.append(time.perf_counter() - started)
    if not samples:  # unreachable while repetitions >= 1; fails closed, never zero
        return None, events, None
    per_event = [sample / events * 1e6 for sample in samples]
    return min(per_event), events, (min(per_event), max(per_event))


# --- B1: a plain lookup table -------------------------------------------------


class PlainLookupTable:
    """B1. ``dict[BoundaryKey, float]`` on the quantised representation.

    No invariant, no validity boundary, no VM, no assurance state — and, crucially,
    **no melt path**: when the key's meaning changes, the only repair is to throw
    the whole table away. That absence is what the Knowledge Field has to be worth
    its extra bytes for. Equal coverage at more bytes is falsifier F7.
    """

    baseline_id = "B1"
    description = "dict[BoundaryKey, float] on the quantised representation"

    def __init__(self) -> None:
        self._table: dict[BoundaryKey, float] = {}

    def fit(self, corpus: CrystalCorpus) -> PlainLookupTable:
        positives: dict[BoundaryKey, int] = {}
        totals: dict[BoundaryKey, int] = {}
        for session in corpus.sessions:
            for frame in session_frames(session):
                key = boundary_key_of(frame)
                totals[key] = totals.get(key, 0) + 1
                positives[key] = positives.get(key, 0) + session.label
        self._table = {key: positives[key] / totals[key] for key in totals}
        return self

    def score(self, session: CrystalSession) -> float:
        return max(
            (self._table.get(boundary_key_of(frame), 0.0) for frame in session_frames(session)),
            default=0.0,
        )

    def size_bytes(self) -> int:
        return model_bytes({f"{k[0]}:{k[1]}:{k[2]}": v for k, v in self._table.items()})


# --- B2: a depth-limited Gini tree -------------------------------------------


@dataclass(frozen=True, slots=True)
class _Node:
    """A tree node. ``feature is None`` marks a leaf."""

    feature: int | None
    threshold: float
    left: _Node | None
    right: _Node | None
    value: float


class DepthLimitedTree:
    """B2. Depth <= 4 Gini tree over per-session ``EncodedTransition`` features.

    Pure stdlib, no numpy — ADR-0020 forbids a third-party import anywhere in
    Stage 3, and a depth-4 tree over a few dozen sessions does not need one.

    Its job is to make the multi-operator synthesiser (D3.7) earn its place: if
    the selector's chosen operator does not reach this tree's cost *and* bytes at
    equal equivalence, the seven non-``DECISION_DAG`` synthesisers are
    NOT_YET_JUSTIFIED and must be reported as such — which is not the same as
    REJECTED.
    """

    baseline_id = "B2"
    description = "depth<=4 Gini tree on EncodedTransition features"

    def __init__(self, *, max_depth: int = 4, min_samples: int = 4) -> None:
        if not 1 <= max_depth <= 4:
            raise ContractError("DepthLimitedTree.max_depth is bounded to [1, 4] by D3.15")
        self._max_depth = max_depth
        self._min_samples = min_samples
        self._root: _Node | None = None
        self._nodes = 0

    @staticmethod
    def features(session: CrystalSession) -> tuple[float, ...]:
        """Per-session vector: element-wise max over the session's transitions.

        Max rather than mean: the corpus's signal is "did any single lineage
        accumulate dangerous capability", and a mean over a long benign session
        would average exactly that away.
        """
        rows = [encode_ssir_transition(t).features for t in session.transitions]
        if not rows:
            return tuple(0.0 for _ in range(FEATURE_WIDTH))
        return tuple(max(row[i] for row in rows) for i in range(FEATURE_WIDTH))

    def fit(self, corpus: CrystalCorpus) -> DepthLimitedTree:
        samples = [(self.features(s), s.label) for s in corpus.sessions]
        self._nodes = 0
        self._root = self._grow(samples, depth=0)
        return self

    def _grow(self, samples: Sequence[tuple[tuple[float, ...], int]], *, depth: int) -> _Node:
        labels = [label for _features, label in samples]
        mean = sum(labels) / len(labels) if labels else 0.0
        self._nodes += 1
        if depth >= self._max_depth or len(samples) < self._min_samples or mean in (0.0, 1.0):
            return _Node(None, 0.0, None, None, mean)
        split = self._best_split(samples)
        if split is None:
            return _Node(None, 0.0, None, None, mean)
        feature, threshold = split
        left = [s for s in samples if s[0][feature] <= threshold]
        right = [s for s in samples if s[0][feature] > threshold]
        if not left or not right:
            return _Node(None, 0.0, None, None, mean)
        return _Node(
            feature,
            threshold,
            self._grow(left, depth=depth + 1),
            self._grow(right, depth=depth + 1),
            mean,
        )

    def _best_split(
        self, samples: Sequence[tuple[tuple[float, ...], int]]
    ) -> tuple[int, float] | None:
        best: tuple[float, int, float] | None = None
        for feature in range(FEATURE_WIDTH):
            values = sorted({row[feature] for row, _label in samples})
            if len(values) < 2:
                continue
            for low, high in zip(values, values[1:], strict=False):
                threshold = (low + high) / 2.0
                impurity = _weighted_gini(samples, feature, threshold)
                if best is None or impurity < best[0]:
                    best = (impurity, feature, threshold)
        return None if best is None else (best[1], best[2])

    def score(self, session: CrystalSession) -> float:
        node = self._root
        if node is None:
            return 0.0
        row = self.features(session)
        while node.feature is not None:
            child = node.left if row[node.feature] <= node.threshold else node.right
            if child is None:
                break
            node = child
        return float(node.value)

    def size_bytes(self) -> int:
        return model_bytes(_node_to_dict(self._root))


def _weighted_gini(
    samples: Sequence[tuple[tuple[float, ...], int]], feature: int, threshold: float
) -> float:
    left = [label for row, label in samples if row[feature] <= threshold]
    right = [label for row, label in samples if row[feature] > threshold]
    total = len(samples)
    return sum(len(part) / total * _gini(part) for part in (left, right) if part)


def _gini(labels: Sequence[int]) -> float:
    if not labels:
        return 0.0
    p = sum(labels) / len(labels)
    return 2.0 * p * (1.0 - p)


def _node_to_dict(node: _Node | None) -> Any:
    if node is None:
        return None
    if node.feature is None:
        return {"value": round(node.value, 6)}
    return {
        "feature": node.feature,
        "threshold": round(node.threshold, 6),
        "left": _node_to_dict(node.left),
        "right": _node_to_dict(node.right),
    }


# --- B3: the Φ-oracle, unchanged ---------------------------------------------


class PhiOracleUnchanged:
    """B3. ``DeterministicScorerSpec`` at ``PHI_SQUASHED_FEATURE_INDEX``, invoked directly.

    Zero parameters, no fitting, no cell machinery at all. This is the bar
    (G3.9, falsifier F1) and it is genuinely hard to beat: there is nothing here
    to make cheaper.
    """

    baseline_id = "B3"
    description = (
        f"DeterministicScorerSpec at feature {PHI_SQUASHED_FEATURE_INDEX}, no cell machinery"
    )

    def __init__(self) -> None:
        self._scorer = PHI_ORACLE_SCORER
        if self._scorer.feature_index != PHI_SQUASHED_FEATURE_INDEX:
            raise ContractError(
                f"PHI_ORACLE_SCORER reads feature {self._scorer.feature_index}, not "
                f"{PHI_SQUASHED_FEATURE_INDEX}; B3 must be the exported candidate, not a copy"
            )

    def fit(self, corpus: CrystalCorpus) -> PhiOracleUnchanged:
        """No-op. Kept so the suite can treat every baseline identically."""
        return self

    def score(self, session: CrystalSession) -> float:
        windows = lineage_windows(session.transitions)
        return max((self._scorer.evaluate(window) for window in windows), default=0.0)

    def size_bytes(self) -> int:
        return model_bytes(self._scorer.to_dict())


# --- B4: a frozen teacher behind Stage 2's existing LRU -----------------------


class FrozenTeacherLRU:
    """B4. Stage 2's ``TransitionCache`` with ``lru_control``, serving a frozen snapshot.

    The cache is **Stage 2's**, not a second implementation: the recency structure
    is already written, already bounded and already counts its own evictions.

    The key is ``(relation_family, epoch_id, state_delta_mask)``. Stage 3 does not
    consume Behaviour Atoms (integration plan §6.5 forbids it), so the relation
    family stands in for ``atom_id``. That makes the key *coarser* than a frame,
    which is the whole interest of the control: a hit can serve a score computed
    for a different frame, and how often that costs accuracy is measured rather
    than assumed.

    Hits are served through ``TransitionCache.lookup_transition_cache`` so that
    reads mark recency and ``lru_control`` evicts least-recently-*used* rather
    than least-recently-stored. It used to call ``TransitionCache.get``, which
    reads "without touching recency" by its own docstring, so the control named
    for an LRU measured a FIFO; the figures published before this repair were
    honest measurements of the wrong policy.

    **Give it a ``snapshot``.** ``fit(corpus, snapshot=None)`` leaves
    ``TeacherOracle(None)``, so every miss falls back to a fresh Φ-oracle
    evaluation and the control exercises neither the frozen teacher nor its bytes.
    A B4 row measured that way says nothing about caching a frozen teacher, which
    is what the mandated control is for.
    """

    baseline_id = "B4"
    description = "Stage 2 TransitionCache + lru_control over a frozen teacher snapshot"

    def __init__(self, *, keep: int = 256, model_version: str = "phi-oracle-teacher") -> None:
        self._cache = TransitionCache(
            model_version=model_version, encoder_version=ENCODER_VERSION
        )
        self._keep = keep
        self._snapshot: TeacherSnapshotV1 | None = None
        self._oracle = TeacherOracle(None)
        self._hits = 0
        self._misses = 0
        self._evicted = 0
        self._sequence = 0

    def fit(
        self, corpus: CrystalCorpus, *, snapshot: TeacherSnapshotV1 | None = None
    ) -> FrozenTeacherLRU:
        self._snapshot = snapshot
        self._oracle = TeacherOracle(snapshot)
        return self

    def _serve(self, frame: CellFrame) -> float:
        self._sequence += 1
        key = transition_cache_key(
            atom_id=int(frame.relation_family),
            epoch_id=frame.epoch_id,
            state_delta_mask=frame.delta.bitmask(),
        )
        # ``lookup_transition_cache``, not ``get``: ``get`` reads "without
        # touching recency" by its own docstring, so ``lru_control`` never saw a
        # read and evicted on store age — the recorded B4 figures were a FIFO
        # cache's, under an LRU name. Stage 2's ``recency_order`` repair made this
        # the one-line fix it was documented to be.
        entry = self._cache.lookup_transition_cache(
            atom_id=int(frame.relation_family),
            epoch_id=frame.epoch_id,
            state_delta_mask=frame.delta.bitmask(),
        )
        if entry is not None:
            self._hits += 1
            return float(entry.predicted_phi)
        self._misses += 1
        # A miss consults the frozen teacher. ``None`` is the teacher's honest
        # UNKNOWN, and the miss then costs a fresh Φ-oracle evaluation — which is
        # the whole expense this cache exists to avoid, so it is counted, not hidden.
        remembered = self._oracle.consult(frame)
        score = phi_oracle_score(frame.delta_phi) if remembered is None else float(remembered)
        self._cache.store(
            CachedTransition(
                key=key,
                atom_id=int(frame.relation_family),
                epoch_id=frame.epoch_id,
                model_version=self._cache.model_version,
                encoder_version=self._cache.encoder_version,
                predicted_delta=frame.delta,
                predicted_phi=score,
                uncertainty=frame.uncertainty,
                hits=0,
                utility=score,
                last_sequence=self._sequence,
            )
        )
        self._evicted += len(lru_control(self._cache, keep=self._keep))
        return score

    def score(self, session: CrystalSession) -> float:
        return max((self._serve(frame) for frame in session_frames(session)), default=0.0)

    def size_bytes(self) -> int:
        return self._cache.memory_bytes() + (
            0 if self._snapshot is None else model_bytes(dict(self._snapshot.responses))
        )

    def stats(self) -> dict[str, Any]:
        return {
            "hits": self._hits,
            "misses": self._misses,
            "evicted": self._evicted,
            "entries": len(self._cache),
            "core_inference_units_per_miss": CORE_INFERENCE_UNITS,
        }


# --- B5: no Stage 3 at all ----------------------------------------------------


class NoStage3:
    """B5. The Stage 1 Φ path plus a drift detector — the §35 "No Stage 3" row.

    Its scores are B3's **by construction**, and that is stated rather than
    hidden: the only thing B5 adds is what happens on drift. It invalidates
    everything on a corroborated epoch change, so its repair locality is 0.0 by
    construction. Stage 3's only defensible advantage is *localised* repair; if a
    measured ``MeltReport.repair_locality`` does not exceed this 0.0, the stage
    reduces to distillation plus cache invalidation (falsifier F2).
    """

    baseline_id = "B5"
    description = "Stage 1 Φ path plus a drift detector; invalidates everything on drift"

    def __init__(self) -> None:
        self._phi = PhiOracleUnchanged()
        self._epoch: int | None = None
        self.invalidations = 0

    #: There is no localised repair here. Not "unmeasured" — zero, by construction.
    repair_locality = 0.0

    def fit(self, corpus: CrystalCorpus) -> NoStage3:
        return self

    def score(self, session: CrystalSession) -> float:
        if self._epoch is not None and session.epoch_id != self._epoch:
            self.invalidations += 1
        self._epoch = session.epoch_id
        return self._phi.score(session)

    def size_bytes(self) -> int:
        return self._phi.size_bytes()


# --- the table ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BaselineRow:
    """One baseline, measured. Every optional figure is ``None`` when unmeasured."""

    baseline_id: str
    description: str
    pr_auc: float | None
    microseconds_per_event: float | None
    bytes_resident: int
    events: int
    sessions: int
    beats_base_rate: bool | None
    #: ``(min, max)`` µs/event over the timing repetitions, or ``None`` when
    #: unmeasured. ``microseconds_per_event`` is the min; this says how far the
    #: slowest repetition was from it, so a ratio built from two rows can be
    #: reported with the band its own inputs admit instead of as a point.
    microseconds_spread: tuple[float, float] | None = None
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_id": self.baseline_id,
            "description": self.description,
            "pr_auc": self.pr_auc,
            "microseconds_per_event": self.microseconds_per_event,
            "bytes_resident": self.bytes_resident,
            "events": self.events,
            "sessions": self.sessions,
            "beats_base_rate": self.beats_base_rate,
            "microseconds_spread": (
                None if self.microseconds_spread is None else list(self.microseconds_spread)
            ),
            "notes": self.notes,
        }


@dataclass(frozen=True, slots=True)
class BaselineTable:
    """The whole comparison, or the refusal to report one."""

    corpus_version: str
    fit_seed: int
    eval_seed: int
    count: int
    base_rate: float
    rows: tuple[BaselineRow, ...]
    loadavg: tuple[float, float, float]
    measured_by: str
    refused: bool
    refusal_reason: str
    #: Control ids whose PR-AUC is within :data:`AT_CHANCE_PR_AUC_BAND` of the base
    #: rate. Reported rather than folded into ``refused``: a control at chance is a
    #: result about that control, and it is not evidence that the control works.
    at_chance: tuple[str, ...] = ()

    @property
    def by_id(self) -> Mapping[str, BaselineRow]:
        return {row.baseline_id: row for row in self.rows}

    def ratio(self, numerator: str, denominator: str, *, metric: str) -> float | None:
        """Within-run ratio of two rows on one metric. ``None`` if either is unmeasured.

        The only comparison that transfers off this host. An absolute microsecond
        figure from a contended machine is not a device measurement and this
        module will not offer one as if it were.
        """
        left = getattr(self.by_id[numerator], metric)
        right = getattr(self.by_id[denominator], metric)
        if left is None or right is None or not right:
            return None
        return float(left) / float(right)

    def to_dict(self) -> dict[str, Any]:
        return {
            "corpus_version": self.corpus_version,
            "fit_seed": self.fit_seed,
            "eval_seed": self.eval_seed,
            "count": self.count,
            "base_rate": self.base_rate,
            "loadavg": list(self.loadavg),
            "measured_by": self.measured_by,
            "refused": self.refused,
            "refusal_reason": self.refusal_reason,
            "at_chance": list(self.at_chance),
            "rows": [row.to_dict() for row in self.rows],
            "note": (
                "Absolute microseconds are not device measurements: this host is "
                "shared and the load average is recorded beside them. Only within-run "
                "ratios transfer."
            ),
        }


def _pr_auc(labels: Sequence[int], scores: Sequence[float], *, events: int) -> float | None:
    """PR-AUC through Stage 0's evaluator only. There is no second metric path."""
    metrics = evaluate_scores(
        labels,
        scores,
        threshold=SCORE_THRESHOLD,
        fpr_budget=FPR_BUDGET,
        latencies_ns=(),
        abstentions=0,
        host_count=1,
        duration_seconds=max(1.0, float(events)),
    )
    return metrics.pr_auc


def _beats_base_rate(pr_auc: float | None, base_rate: float) -> bool | None:
    """Tri-state: True above chance, False below, ``None`` indistinguishable.

    ``None`` is AT_CHANCE, and it is not the same claim as "beats the base rate".
    A bare ``pr_auc > base_rate`` called B4 a working control on a margin of
    +0.0086 — inside :data:`AT_CHANCE_PR_AUC_BAND`, the very band this stage uses
    to declare a split unable to tell models apart. Sweeping the corpus size on
    the gate's own builder put that margin on either side of zero, so the sign of
    a difference that small is not a result.

    ``None`` also already means UNMEASURED for a missing PR-AUC, and the two
    readings agree: neither is evidence that the control works.
    """
    if pr_auc is None:
        return None
    margin = pr_auc - base_rate
    if abs(margin) <= AT_CHANCE_PR_AUC_BAND:
        return None
    return margin > 0.0


def _row(
    model: Any, corpus: CrystalCorpus, *, notes: str = ""
) -> BaselineRow:
    labels = list(corpus.labels)
    scores = [model.score(session) for session in corpus.sessions]
    micros, events, spread = measure_microseconds_with_spread(model.score, corpus.sessions)
    pr_auc = _pr_auc(labels, scores, events=events)
    beats = _beats_base_rate(pr_auc, corpus.base_rate)
    return BaselineRow(
        baseline_id=model.baseline_id,
        description=model.description,
        pr_auc=pr_auc,
        microseconds_per_event=micros,
        bytes_resident=model.size_bytes(),
        events=events,
        sessions=len(corpus.sessions),
        beats_base_rate=beats,
        microseconds_spread=spread,
        notes=notes,
    )


def run_baselines(
    *,
    fit: CrystalCorpus,
    evaluation: CrystalCorpus,
    snapshot: TeacherSnapshotV1 | None = None,
    include_cell_path: bool = True,
    measured_by: str = "pocketsec.stage3.labs.baselines:run_baselines",
) -> BaselineTable:
    """Fit on one split, score another, and report one table — in one run.

    Two splits from the same builder at different seeds, each with its own
    ``Stage1Pipeline``. Fitting and scoring the same sessions would let every
    baseline memorise the corpus and would make the comparison a measurement of
    nothing.

    Refuses to report when any row fails to beat the base rate.
    """
    if fit.seed == evaluation.seed:
        raise ContractError(
            "the fit and evaluation splits share a seed; a baseline fitted on the "
            "sessions it scores is measuring its own memory"
        )
    models: list[Any] = [
        PlainLookupTable().fit(fit),
        DepthLimitedTree().fit(fit),
        PhiOracleUnchanged().fit(fit),
        FrozenTeacherLRU().fit(fit, snapshot=snapshot),
        NoStage3().fit(fit),
    ]
    if include_cell_path:
        models.append(CellPathBaseline().fit(fit))
    rows = tuple(
        _row(
            model,
            evaluation,
            notes=_NOTES.get(model.baseline_id, ""),
        )
        for model in models
    )
    # Only the five CONTROLS gate the report. A control below chance is a bug in
    # the control and makes every comparison meaningless. S3 is the mechanism
    # under test: if it lands at or below chance that is a RESULT about Stage 3,
    # and refusing to report it would hide the most important thing measured.
    offenders = [
        row.baseline_id
        for row in rows
        if row.baseline_id in BASELINE_IDS and row.beats_base_rate is False
    ]
    at_chance = [
        row.baseline_id
        for row in rows
        if row.baseline_id in BASELINE_IDS and row.beats_base_rate is None
    ]
    # Refused only for a control measurably *below* chance, which is a bug in the
    # control. A control indistinguishable from chance is a RESULT about that
    # control and is reported, with the fact stated: refusing the whole table on a
    # margin inside AT_CHANCE_PR_AUC_BAND would make the reportability of every
    # comparison turn on the sign of a difference too small to have one.
    refused = bool(offenders)
    reason = (
        ""
        if not refused
        else (
            f"baselines {offenders} score measurably below the base rate "
            f"{evaluation.base_rate:.4f}; a control below chance is a bug and the "
            "comparison is refused, not reported"
        )
    )

    return BaselineTable(
        corpus_version=evaluation.version,
        fit_seed=fit.seed,
        eval_seed=evaluation.seed,
        count=evaluation.count,
        base_rate=evaluation.base_rate,
        rows=rows,
        loadavg=loadavg(),
        measured_by=measured_by,
        refused=refused,
        refusal_reason=reason,
        at_chance=tuple(at_chance),
    )
