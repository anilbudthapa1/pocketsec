"""Transition motif extraction — architecture §9, part of D3.3.

A *motif* is a short, repeated shape in one causal lineage's transition
sequence: which relation families fired, which security dimensions they raised,
and how hard Φ moved. It is the candidate skeleton an invariant is built on.

What this module is **for** is answering "does this shape recur, and across how
many *independent* witnesses?" without ever letting a chatty lineage vote a
thousand times.

What it **refuses** to do:

* **It refuses to count events as witnesses.** ``TransitionMotif.lineages`` is
  the number of distinct causal lineages the motif was seen in, and
  ``min_support`` filters on that, never on ``support``. A loop that repeats the
  same three steps five hundred times inside one process is one observation of
  the shape, not five hundred. "Frequency is not corroboration" (ADR-0007) is
  the anti-poisoning invariant this stage inherits.
* **It refuses to silently drop motifs.** The motif table is bounded by
  :data:`MAX_MOTIFS`. :func:`extract_motifs` raises
  :class:`MotifBudgetExceeded` when the corpus produces more distinct motifs
  than the budget; :func:`extract_motifs_bounded` returns the same work with an
  explicit ``truncated`` flag and the count that was discarded. There is no
  third option where the answer quietly shrinks.

ΔΦ is recorded as a *band index*, never as the float. An exact float makes every
step unique, every motif a singleton, and the whole count meaningless — the same
reason ``TemporalContext`` buckets its gaps instead of storing nanoseconds.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.ssir.relations import RelationFamily, family_of
from pocketsec.stage1.ssir.transition import SSIRTransitionV1

__all__ = [
    "MAX_LINEAGES",
    "MAX_MOTIFS",
    "MAX_MOTIF_LENGTH",
    "MAX_TRANSITIONS_PER_LINEAGE",
    "MotifBudgetExceeded",
    "MotifExtraction",
    "MotifStep",
    "PHI_BAND_EDGES",
    "SessionLike",
    "TransitionMotif",
    "extract_motifs",
    "extract_motifs_bounded",
    "lineage_key",
    "lineage_transitions",
    "motif_step",
    "phi_band",
]

#: Longest window slid over a lineage. Four steps is the §9 motif horizon; a
#: longer window turns every attack chain into its own singleton motif.
MAX_MOTIF_LENGTH = 4

#: Hard cap on distinct motifs held at once. Endpoint state is bounded (2 GB
#: host target); an unbounded motif table is the "knowledge explosion" failure.
MAX_MOTIFS = 4096

#: Hard cap on lineages walked in one extraction.
MAX_LINEAGES = 4096

#: Hard cap on transitions retained per lineage.
MAX_TRANSITIONS_PER_LINEAGE = 4096

#: ΔΦ band edges. Five bands: <=0, small, moderate, large, extreme. Pinned,
#: because the band index travels inside a motif key.
PHI_BAND_EDGES: tuple[float, ...] = (0.0, 0.5, 2.0, 6.0)

#: (relation family, StateDelta bitmask, ΔΦ band index).
MotifStep = tuple[RelationFamily, int, int]


class MotifBudgetExceeded(ContractError):
    """Raised when a corpus produces more distinct motifs than the budget.

    A contract error rather than a truncation, because a caller that asked for
    the motif table and got a silently shortened one would draw conclusions
    from a sample it does not know is a sample.
    """


@runtime_checkable
class SessionLike(Protocol):
    """The only shape this package needs from a corpus replay.

    ``pocketsec.stage1.pipeline.ScenarioResult`` satisfies it structurally, so
    Stage 3 reads the existing Stage 1 corpus walk and defines no second one.
    """

    @property
    def transitions(self) -> tuple[SSIRTransitionV1, ...]: ...


@dataclass(frozen=True, slots=True)
class TransitionMotif:
    """One repeated shape, with its two very different counts."""

    steps: tuple[MotifStep, ...]
    #: Total occurrences across the corpus. Diagnostic only.
    support: int
    #: Distinct causal lineages the motif occurred in. This is the witness count.
    lineages: int

    def __post_init__(self) -> None:
        if not self.steps:
            raise ContractError("TransitionMotif.steps must be non-empty")
        if len(self.steps) > MAX_MOTIF_LENGTH:
            raise ContractError(
                f"motif length {len(self.steps)} exceeds MAX_MOTIF_LENGTH={MAX_MOTIF_LENGTH}"
            )
        if self.lineages < 1 or self.support < self.lineages:
            raise ContractError(
                f"motif counts incoherent: support={self.support} lineages={self.lineages}"
            )

    @property
    def length(self) -> int:
        return len(self.steps)

    def key(self) -> tuple[tuple[int, int, int], ...]:
        """A deterministic, JSON-safe identity for this shape."""
        return tuple((int(family), mask, band) for family, mask, band in self.steps)


@dataclass(frozen=True, slots=True)
class MotifExtraction:
    """A motif table that knows whether it is complete."""

    motifs: tuple[TransitionMotif, ...]
    #: True when ``distinct_seen`` exceeded the budget and the table was cut.
    truncated: bool
    #: Distinct motifs the corpus produced, before the budget was applied.
    distinct_seen: int
    #: Distinct motifs dropped by the budget. Zero when ``truncated`` is False.
    discarded: int
    #: Lineages skipped because ``MAX_LINEAGES`` was reached.
    lineages_skipped: int
    #: Transitions dropped because ``MAX_TRANSITIONS_PER_LINEAGE`` was reached.
    transitions_dropped: int


def phi_band(delta: float) -> int:
    """Map a ΔΦ to a band index in ``[0, len(PHI_BAND_EDGES)]``."""
    band = 0
    for edge in PHI_BAND_EDGES:
        if delta > edge:
            band += 1
    return band


def motif_step(transition: SSIRTransitionV1) -> MotifStep:
    """The identity-free shape of one transition."""
    return (
        family_of(transition.relation),
        transition.state_delta.bitmask(),
        phi_band(transition.delta_phi),
    )


def lineage_key(transition: SSIRTransitionV1) -> str:
    """Which causal lineage a transition belongs to.

    The actor's exact identity, which is what Stage 1's semantic compiler keys
    lineage state on (``semantic_compiler._lineage_key``). Using it here is not
    a semantic read: counting *independent witnesses* is exactly the question an
    identity answers, and the generalisation step
    (``anti_unification.anti_unify``) never sees it.
    """
    return transition.actor.identity


def lineage_transitions(
    sessions: Sequence[SessionLike],
    *,
    max_lineages: int = MAX_LINEAGES,
    max_per_lineage: int = MAX_TRANSITIONS_PER_LINEAGE,
) -> tuple[dict[str, tuple[SSIRTransitionV1, ...]], int, int]:
    """Group a corpus replay into per-lineage transition sequences.

    Returns ``(lineages, lineages_skipped, transitions_dropped)``. Both bounds
    are reported rather than applied in silence.
    """
    grouped: dict[str, list[SSIRTransitionV1]] = {}
    skipped: set[str] = set()
    dropped = 0
    for session in sessions:
        for transition in session.transitions:
            key = lineage_key(transition)
            bucket = grouped.get(key)
            if bucket is None:
                if len(grouped) >= max_lineages:
                    skipped.add(key)
                    continue
                bucket = []
                grouped[key] = bucket
            if len(bucket) >= max_per_lineage:
                dropped += 1
                continue
            bucket.append(transition)
    return ({key: tuple(value) for key, value in grouped.items()}, len(skipped), dropped)


def _count_windows(
    lineages: Mapping[str, tuple[SSIRTransitionV1, ...]], k: int
) -> tuple[Counter[tuple[MotifStep, ...]], dict[tuple[MotifStep, ...], set[str]]]:
    """Count every length-``k`` window, tracking which lineages produced it."""
    occurrences: Counter[tuple[MotifStep, ...]] = Counter()
    witnesses: dict[tuple[MotifStep, ...], set[str]] = {}
    for key, transitions in lineages.items():
        if len(transitions) < k:
            continue
        steps = [motif_step(transition) for transition in transitions]
        for start in range(len(steps) - k + 1):
            window = tuple(steps[start : start + k])
            occurrences[window] += 1
            witnesses.setdefault(window, set()).add(key)
    return occurrences, witnesses


def _sort_key(motif: TransitionMotif) -> tuple[int, int, int, tuple[tuple[int, int, int], ...]]:
    """Deterministic ranking: witnesses first, then occurrences, then shape."""
    return (-motif.lineages, -motif.support, motif.length, motif.key())


def extract_motifs_bounded(
    sessions: Sequence[SessionLike],
    *,
    k: int,
    min_support: int,
    max_motifs: int = MAX_MOTIFS,
) -> MotifExtraction:
    """Extract length-``k`` motifs, reporting truncation explicitly.

    ``min_support`` is compared against ``TransitionMotif.lineages`` — distinct
    causal lineages — and never against the occurrence count.
    """
    if not 1 <= k <= MAX_MOTIF_LENGTH:
        raise ContractError(f"k must be in [1, {MAX_MOTIF_LENGTH}], got {k!r}")
    if min_support < 1:
        raise ContractError(f"min_support must be >= 1, got {min_support!r}")
    if not 1 <= max_motifs <= MAX_MOTIFS:
        raise ContractError(f"max_motifs must be in [1, {MAX_MOTIFS}], got {max_motifs!r}")

    lineages, skipped, dropped = lineage_transitions(sessions)
    occurrences, witnesses = _count_windows(lineages, k)
    surviving = [
        TransitionMotif(steps=window, support=count, lineages=len(witnesses[window]))
        for window, count in occurrences.items()
        if len(witnesses[window]) >= min_support
    ]
    surviving.sort(key=_sort_key)
    distinct_seen = len(surviving)
    truncated = distinct_seen > max_motifs
    return MotifExtraction(
        motifs=tuple(surviving[:max_motifs]),
        truncated=truncated,
        distinct_seen=distinct_seen,
        discarded=distinct_seen - min(distinct_seen, max_motifs),
        lineages_skipped=skipped,
        transitions_dropped=dropped,
    )


def extract_motifs(
    sessions: Sequence[SessionLike],
    *,
    k: int,
    min_support: int,
    max_motifs: int = MAX_MOTIFS,
) -> tuple[TransitionMotif, ...]:
    """Extract length-``k`` motifs, or refuse if the budget cannot hold them.

    The spec-facing signature. It returns a complete table or nothing at all:
    callers that can cope with a partial table call
    :func:`extract_motifs_bounded` and read its ``truncated`` flag.
    """
    extraction = extract_motifs_bounded(
        sessions, k=k, min_support=min_support, max_motifs=max_motifs
    )
    if extraction.truncated:
        raise MotifBudgetExceeded(
            f"{extraction.distinct_seen} distinct motifs exceed max_motifs={max_motifs}; "
            f"{extraction.discarded} would be discarded — use extract_motifs_bounded "
            "to accept a truncated table knowingly"
        )
    return extraction.motifs
