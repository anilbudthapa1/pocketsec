"""D9.7 (ONTO-F07, second half) — Conservation search and its Noether-inspired pairing.

Architecture §15 looks for compact quantities ``Q`` that stay inside a benign envelope while
a lineage does ordinary work, and jump when it does something security-relevant:
``|Q(s_{t+1}) - Q(s_t)| >> envelope``. §16 then tries a *heuristic* borrowed from Noether:
where the detector is invariant under a transformation, look for a statistic that is
conserved. Noether's theorem is **not** asserted to hold for Linux telemetry; this module
only tests whether the heuristic finds a quantity whose violation predicts the label better
than the dumb things (§7): the Φ-oracle (a simple statistic, S9X-030) and H2 (the per-lineage
graph-motif rule, S9X-031).

Every candidate quantity is a real per-lineage genome, built with ``build_genome`` in the
same typed language the search uses, so its cost and bounds are the language's, not a
side-channel Python function. The per-step ``ΔQ`` is read by running that genome on each
prefix of each lineage's own event sub-sequence (at most :data:`MAX_LINEAGE_PREFIX` steps per
lineage; beyond that steps are counted in ``truncated_steps`` and never scored).

What this module refuses to do. The envelope is fitted on **train benign** steps only, the
quantity is selected on **train** AP, and only then is its held-out AP compared with the
controls — a quantity picked on held-out data would be a fitted threshold wearing a
physics name. :data:`CONSERVATION_DEFAULT_ENABLED` ships ``False``.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache

from pocketsec.stage2.dataset import Stage2Dataset, Stage2Sample
from pocketsec.stage2.encoder.ssir_encoder import (
    GROUP_OFFSETS,
    NEED_SIGNAL_INDICES,
    EncodedTransition,
)
from pocketsec.stage9.chemistry.phenotype import SessionAggregation
from pocketsec.stage9.chemistry.typed_ir import (
    InputSource,
    IRNode,
    IRProgram,
    IRType,
    NodeKind,
    ProgramPhase,
    RegisterSpec,
)
from pocketsec.stage9.genome.computational import ComputationalGenomeV1, build_genome
from pocketsec.stage9.genome.expressibility import hand_designed_genomes
from pocketsec.stage9.ontogenesis.fitness import session_scores
from pocketsec.stage9.renormalization.laboratory import (
    ScoredDetector,
    compare_detectors,
    phi_oracle_scores,
    ranked_ap,
    unmeasured_comparison,
)
from pocketsec.stage9.spec.mssc import DetectorComparison
from pocketsec.stage9.symmetry.suite import SymmetryTest, Transformation, invariance

__all__ = [
    "CONSERVATION_DEFAULT_ENABLED",
    "ENVELOPE_QUANTILE",
    "MAX_LINEAGE_PREFIX",
    "ConservationTest",
    "ConservedQuantity",
    "candidate_quantities",
    "compare_conservation",
    "conservation_search",
    "envelope_of",
    "step_deltas",
]

#: Off until a measured JUSTIFIED verdict is cited in the findings and its ADR (spec §4.22).
CONSERVATION_DEFAULT_ENABLED: bool = False
#: The benign envelope is this quantile of per-step ``|ΔQ|`` on train benign steps (§4.11).
ENVELOPE_QUANTILE = 0.99
#: Per-lineage prefix bound: ``ΔQ`` costs O(L²) interpreter events for a lineage of L steps,
#: so a lineage's steps beyond this are counted as truncated, never scored. Chosen.
MAX_LINEAGE_PREFIX = 64

_NOVELTY_PEAK = NEED_SIGNAL_INDICES["novelty_peak"]


@dataclass(frozen=True, slots=True)
class ConservedQuantity:
    """A named per-lineage statistic ``Q``, written as a genome in the search language."""

    name: str
    genome: ComputationalGenomeV1


def _reg(index: int, type_: IRType) -> IRNode:
    return IRNode(kind=NodeKind.REG, type=type_, index=index)


def _input(source: InputSource, type_: IRType, index: int = 0) -> IRNode:
    return IRNode(kind=NodeKind.INPUT, type=type_, source=source, index=index)


def _apply(primitive: str, type_: IRType, *args: int) -> IRNode:
    return IRNode(kind=NodeKind.APPLY, type=type_, primitive=primitive, args=args)


def _const(value: float | int, type_: IRType) -> IRNode:
    return IRNode(kind=NodeKind.CONST, type=type_, value=value)


def _single(
    name: str, update: Sequence[IRNode], register: IRType, *, popcount: bool
) -> ConservedQuantity:
    """One register whose new value is the update's last node; readout REG [→ POPCOUNT]."""
    readout = [_reg(0, register)]
    if popcount:
        readout.append(_apply("POPCOUNT", IRType.FLOAT, 0))
    genome = build_genome(
        registers=(RegisterSpec(type=register, init=0.0 if register is IRType.FLOAT else 0),),
        update=IRProgram(ProgramPhase.UPDATE, tuple(update), (len(update) - 1,)),
        readout=IRProgram(ProgramPhase.READOUT, tuple(readout), (len(readout) - 1,)),
        aggregation=SessionAggregation.MAX,
    )
    return ConservedQuantity(name=name, genome=genome)


def _projection(group: str) -> ConservedQuantity:
    """Per-lineage mean of the group's first slot: a SUM register and a COUNT register."""
    f = IRType.FLOAT
    update = (
        _reg(0, f), _input(InputSource.FEATURE, f, GROUP_OFFSETS[group]), _apply("ADD", f, 0, 1),
        _reg(1, f), _const(1.0, f), _apply("ADD", f, 3, 4),
    )
    readout = (_reg(0, f), _reg(1, f), _apply("DIV", f, 0, 1))
    genome = build_genome(
        registers=(RegisterSpec(type=f, init=0.0), RegisterSpec(type=f, init=0.0)),
        update=IRProgram(ProgramPhase.UPDATE, update, (2, 5)),
        readout=IRProgram(ProgramPhase.READOUT, readout, (2,)),
        aggregation=SessionAggregation.MAX,
    )
    return ConservedQuantity(name=f"projection/{group}", genome=genome)


@lru_cache(maxsize=1)
def candidate_quantities() -> tuple[ConservedQuantity, ...]:
    """4 symbolic quantities, then one projection per feature group (13), in offset order."""
    f, i = IRType.FLOAT, IRType.INT
    symbolic = (
        _single(
            "popcount(or-state-delta-mask)",
            (_reg(0, i), _input(InputSource.STATE_DELTA_MASK, i), _apply("OR", i, 0, 1)),
            i, popcount=True,
        ),
        _single(
            "sum(delta-phi)",
            (_reg(0, f), _input(InputSource.DELTA_PHI, f), _apply("ADD", f, 0, 1)),
            f, popcount=False,
        ),
        _single(
            "distinct(relation-family)",
            (_reg(0, i), _const(1, i), _input(InputSource.RELATION_FAMILY, i),
             _apply("SHIFT", i, 1, 2), _apply("OR", i, 0, 3)),
            i, popcount=True,
        ),
        _single(
            "max(novelty-peak)",
            (_reg(0, f), _input(InputSource.FEATURE, f, _NOVELTY_PEAK), _apply("MAX", f, 0, 1)),
            f, popcount=False,
        ),
    )
    groups = sorted(GROUP_OFFSETS, key=lambda group: GROUP_OFFSETS[group])
    return symbolic + tuple(_projection(group) for group in groups)


def envelope_of(values: Sequence[float], *, quantile: float = ENVELOPE_QUANTILE) -> float | None:
    """Nearest-rank quantile: the smallest value with at least ``quantile`` of values <= it."""
    if not 0.0 < quantile <= 1.0:
        raise ValueError(f"quantile must be within (0, 1], got {quantile!r}")
    ordered = sorted(values)
    if not ordered:
        return None
    return ordered[max(0, math.ceil(quantile * len(ordered)) - 1)]


@dataclass(frozen=True, slots=True)
class _Prefixes:
    """Every lineage prefix of every session, as one dataset, plus where each belongs."""

    dataset: Stage2Dataset
    owner: tuple[tuple[int, int], ...]  # (session index, lineage slot) per prefix
    truncated_steps: int


def _lineage_prefixes(dataset: Stage2Dataset) -> _Prefixes:
    samples: list[Stage2Sample] = []
    owner: list[tuple[int, int]] = []
    truncated = 0
    for index, sample in enumerate(dataset.samples):
        lineages: dict[int, list[EncodedTransition]] = {}
        for step in sample.steps:
            lineages.setdefault(step.actor_slot, []).append(step)
        for slot, steps in lineages.items():
            truncated += max(0, len(steps) - MAX_LINEAGE_PREFIX)
            for length in range(1, min(len(steps), MAX_LINEAGE_PREFIX) + 1):
                samples.append(
                    Stage2Sample(
                        sample_id=f"{sample.sample_id}/L{slot}/{length}",
                        steps=tuple(steps[:length]), label=sample.label,
                        technique=sample.technique, unseen_technique=sample.unseen_technique,
                        final_phi=sample.final_phi,
                    )
                )
                owner.append((index, slot))
    prefix_set = Stage2Dataset(
        name=f"{dataset.name}/lineage-prefixes", seed=dataset.seed, corpus=dataset.corpus,
        encoder_version=dataset.encoder_version, feature_width=dataset.feature_width,
        samples=tuple(samples),
    )
    return _Prefixes(prefix_set, tuple(owner), truncated)


def step_deltas(
    quantity: ConservedQuantity, dataset: Stage2Dataset, *, prefixes: _Prefixes | None = None
) -> tuple[tuple[float, ...], ...]:
    """Per session, every scored lineage step's ``|ΔQ|`` (``Q`` before a lineage's first step is 0).

    Every register starts at 0 and every readout maps the all-zero state to 0, so ``Q_0 = 0``
    holds for all 17 candidates; an abstained prefix reads as 0.0.
    """
    prefixes = prefixes if prefixes is not None else _lineage_prefixes(dataset)
    scores = session_scores(quantity.genome, prefixes.dataset)
    deltas: list[list[float]] = [[] for _ in dataset.samples]
    previous: dict[tuple[int, int], float] = {}
    for key, score in zip(prefixes.owner, scores, strict=True):
        value = 0.0 if score is None else float(score)
        deltas[key[0]].append(abs(value - previous.get(key, 0.0)))
        previous[key] = value
    return tuple(tuple(row) for row in deltas)


@dataclass(frozen=True, slots=True)
class ConservationTest:
    """One quantity's benign envelope, its violation rates and its detector quality.

    ``ap`` is held-out AP of the session score ``max |ΔQ| / envelope``; ``train_ap`` is the
    same on train and is the only figure used to *select* a quantity. The score vectors are
    kept so :func:`compare_conservation` can count decisions without recomputing them.
    """

    quantity: str
    envelope: float | None
    benign_violation_rate: float | None
    malicious_violation_rate: float | None
    ap: float | None
    noether_pair: str | None
    train_ap: float | None = None
    train_scores: tuple[float, ...] = ()
    heldout_scores: tuple[float, ...] = ()
    truncated_steps: int = 0


def _session_scores(deltas: Sequence[Sequence[float]], envelope: float | None) -> tuple[float, ...]:
    peaks = [max(row, default=0.0) for row in deltas]
    if envelope is None or envelope <= 0.0:
        return tuple(peaks)  # a zero envelope leaves the ranking of max |ΔQ| unchanged
    return tuple(peak / envelope for peak in peaks)


def _violation_rate(
    deltas: Sequence[Sequence[float]], labels: Sequence[int], label: int, envelope: float | None
) -> float | None:
    rows = [row for row, lab in zip(deltas, labels, strict=True) if lab == label]
    if envelope is None or not rows:
        return None
    return sum(1 for row in rows if any(d > envelope for d in row)) / len(rows)


def _noether_pair(
    quantity: ConservedQuantity,
    invariant: Sequence[Transformation],
    heldout: Stage2Dataset,
    transformed: Mapping[Transformation, Stage2Dataset] | None,
) -> str | None:
    """The invariant transformations this quantity is paired with (the heuristic's premise).

    With transformed splits supplied, a transformation pairs only if the quantity's own
    session value is invariant under it too; without them the pairing is the detector's
    invariance alone, and the string says the quantity's side was not measured.
    """
    if not invariant:
        return None
    if transformed is None:
        return ",".join(t.value for t in invariant) + " (quantity invariance not measured)"
    kept = [
        t.value for t in invariant
        if t in transformed and invariance(quantity.genome, heldout, transformed[t], t).invariant
    ]
    return ",".join(kept) if kept else None


def _test_quantity(
    quantity: ConservedQuantity,
    splits: tuple[Stage2Dataset, Stage2Dataset],
    prefixes: tuple[_Prefixes, _Prefixes],
    pair: str | None,
) -> ConservationTest:
    train, heldout = splits
    train_deltas = step_deltas(quantity, train, prefixes=prefixes[0])
    heldout_deltas = step_deltas(quantity, heldout, prefixes=prefixes[1])
    benign_steps = [
        d for row, lab in zip(train_deltas, train.labels, strict=True) if lab == 0 for d in row
    ]
    envelope = envelope_of(benign_steps)
    train_scores = _session_scores(train_deltas, envelope)
    heldout_scores = _session_scores(heldout_deltas, envelope)
    return ConservationTest(
        quantity=quantity.name, envelope=envelope,
        benign_violation_rate=_violation_rate(heldout_deltas, heldout.labels, 0, envelope),
        malicious_violation_rate=_violation_rate(heldout_deltas, heldout.labels, 1, envelope),
        ap=ranked_ap(heldout.labels, heldout_scores), noether_pair=pair,
        train_ap=ranked_ap(train.labels, train_scores), train_scores=train_scores,
        heldout_scores=heldout_scores,
        truncated_steps=prefixes[0].truncated_steps + prefixes[1].truncated_steps,
    )


def conservation_search(
    train: Stage2Dataset,
    heldout: Stage2Dataset,
    invariants: Sequence[SymmetryTest],
    *,
    transformed_heldout: Mapping[Transformation, Stage2Dataset] | None = None,
) -> tuple[ConservationTest, ...]:
    """Test all 17 candidate quantities; pair each with the detector's invariant transformations.

    ``invariants`` are :class:`SymmetryTest` records; only those with ``invariant is True``
    seed the heuristic (``None`` = unmeasured never counts as invariant).
    """
    invariant = [Transformation(t.transformation) for t in invariants if t.invariant is True]
    prefixes = (_lineage_prefixes(train), _lineage_prefixes(heldout))
    return tuple(
        _test_quantity(
            quantity, (train, heldout), prefixes,
            _noether_pair(quantity, invariant, heldout, transformed_heldout),
        )
        for quantity in candidate_quantities()
    )


def compare_conservation(
    tests: Sequence[ConservationTest],
    heldout: Stage2Dataset,
    *,
    train: Stage2Dataset | None = None,
) -> DetectorComparison:
    """The train-selected quantity vs the Φ-oracle and H2, on held-out AP.

    The quantity with the best **train** AP is chosen; its held-out AP is the value.
    JUSTIFIED iff it beats ``max(Φ-oracle, H2) + 0.02``. Pass ``train`` so ``fired``'s
    thresholds are train-fitted. No test, or no test with a train AP, is UNMEASURED.
    """
    mechanism = f"{__name__}:CONSERVATION_DEFAULT_ENABLED"
    metric = "heldout_ap(max |dQ| / benign envelope)"
    names = ("phi-oracle", "H2")
    usable = [t for t in tests if t.train_ap is not None and len(t.heldout_scores) == len(heldout)]
    if not usable:
        return unmeasured_comparison(
            mechanism, metric, names, "no conservation test with a train AP aligned to held-out"
        )
    best = max(usable, key=lambda t: t.train_ap or 0.0)
    h2 = hand_designed_genomes()["H2"]
    candidate = ScoredDetector(
        f"conservation/{best.quantity}", best.heldout_scores,
        best.train_scores if train is not None else None,
    )
    controls = (
        ScoredDetector(
            names[0], phi_oracle_scores(heldout),
            phi_oracle_scores(train) if train is not None else None,
        ),
        ScoredDetector(
            names[1], session_scores(h2, heldout),
            session_scores(h2, train) if train is not None else None,
        ),
    )
    return compare_detectors(
        mechanism, metric, candidate, controls, heldout_labels=heldout.labels,
        train_labels=train.labels if train is not None else None,
        detail=f"selected {best.quantity} on train AP {best.train_ap:.4f} "
        f"(envelope {best.envelope}); Noether pair: {best.noether_pair}.",
    )
