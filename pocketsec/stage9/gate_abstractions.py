"""G9.3's evidence: every abstraction Stage 9 makes, with both of its tests.

"Every abstraction has semantic-conservation and counterfactual tests" (phase file §69). The
abstractions are exactly spec §6's list: every :class:`CoarseGraining` level, every
``precision_sweep`` level below 64 bits, and the minimal state LAPLACE discovers. Each is
measured the same way, through the two generic functions of the renormalization laboratory:

* ``semantic_conservation``: held-out decisions before and after, at ONE threshold fitted on
  the original representation's TRAIN benign scores (spec §4.10; never refitted per level);
* ``counterfactual_distinction``: the attribution pairs (a malicious session and its twin
  with the same operations spread across actors) still told apart after the abstraction.

A coarse-graining abstracts the *input* (the genome is unchanged, the data is coarsened); a
precision level and the minimal state abstract the *genome* (the data is unchanged).
"""

from __future__ import annotations

from dataclasses import replace

from pocketsec.stage2.dataset import Stage2Dataset
from pocketsec.stage9.gate_build import need
from pocketsec.stage9.gate_state import CoarseningEvidence, Stage9GateContext
from pocketsec.stage9.genome.computational import ComputationalGenomeV1
from pocketsec.stage9.laplace.state_discovery import (
    discover_minimal_state,
    packed_state_bytes,
    precision_sweep,
)
from pocketsec.stage9.ontogenesis.fitness import session_scores
from pocketsec.stage9.renormalization.laboratory import (
    CoarseGraining,
    coarse_grain,
    counterfactual_distinction,
    feature_bytes,
    semantic_conservation,
)

__all__ = ["measure_abstractions"]

#: Levels at or above this are the unabstracted representation, not an abstraction.
_FULL_PRECISION = 64
_Scores = tuple[float | None, ...]
_Base = tuple[_Scores, _Scores, _Scores]


def _benign(dataset: Stage2Dataset) -> Stage2Dataset:
    return replace(dataset, samples=tuple(s for s in dataset.samples if s.label == 0))


def _evidence(
    name: str,
    kind: str,
    *,
    base: _Base,
    after: tuple[_Scores, _Scores],
    labels: tuple[int, ...],
    bytes_before: int,
    bytes_after: int,
) -> CoarseningEvidence:
    train_benign, held_before, pairs_before = base
    held_after, pairs_after = after
    kept = semantic_conservation(
        name,
        train_scores_before=train_benign,
        scores_before=held_before,
        scores_after=held_after,
        labels=labels,
        bytes_before=bytes_before,
        bytes_after=bytes_after,
    )
    twin = counterfactual_distinction(
        name, pair_scores_before=pairs_before, pair_scores_after=pairs_after
    )
    return CoarseningEvidence(
        name=name,
        kind=kind,
        decision_agreement=kept.decision_agreement,
        ap_before=kept.ap_before,
        ap_after=kept.ap_after,
        bytes_before=kept.bytes_before,
        bytes_after=kept.bytes_after,
        pairs=twin.pairs,
        distinguished_before=twin.distinguished_before,
        distinguished_after=twin.distinguished_after,
        lost=twin.lost,
    )


def _coarse(
    genome: ComputationalGenomeV1, base: _Base, held: Stage2Dataset, pairs: Stage2Dataset
) -> list[CoarseningEvidence]:
    """The INPUT abstractions: the genome is unchanged, the data is coarsened."""
    return [
        _evidence(
            f"coarse:{level.value}",
            "coarse_graining",
            base=base,
            after=(
                session_scores(genome, coarse_grain(held, level)),
                session_scores(genome, coarse_grain(pairs, level)),
            ),
            labels=held.labels,
            bytes_before=feature_bytes(None),
            bytes_after=feature_bytes(level),
        )
        for level in CoarseGraining
    ]


def _precision(
    genome: ComputationalGenomeV1, base: _Base, held: Stage2Dataset, pairs: Stage2Dataset
) -> list[CoarseningEvidence]:
    """The GENOME abstractions by precision: every level below the unabstracted 64 bits."""
    before = packed_state_bytes(genome)
    return [
        _evidence(
            f"precision:{point.bits}",
            "precision",
            base=base,
            after=_genome_scores(point.genome, held, pairs),
            labels=held.labels,
            bytes_before=before,
            bytes_after=point.state_bytes,
        )
        for point in precision_sweep(genome, held)
        if point.bits < _FULL_PRECISION
    ]


def measure_abstractions(ctx: Stage9GateContext) -> list[CoarseningEvidence]:
    """Coarse-grainings, precision levels < 64 bits and the minimal state, on the subject."""
    genome = need(ctx.subject, "the subject genome")
    train, heldout = need(ctx.train, "train"), need(ctx.heldout, "heldout")
    held, pairs = heldout.clean.dataset, need(ctx.pairs, "the attribution pairs")
    base = (
        session_scores(genome, _benign(train.clean.dataset)),
        session_scores(genome, held),
        session_scores(genome, pairs),
    )
    minimal = discover_minimal_state(genome, train, heldout).minimal_genome
    return [
        *_coarse(genome, base, held, pairs),
        *_precision(genome, base, held, pairs),
        _evidence(
            "minimal_state",
            "minimal_state",
            base=base,
            after=_genome_scores(minimal, held, pairs),
            labels=held.labels,
            bytes_before=genome.bounds.session_state_bytes_max,
            bytes_after=minimal.bounds.session_state_bytes_max,
        ),
    ]


def _genome_scores(
    genome: ComputationalGenomeV1, held: Stage2Dataset, pairs: Stage2Dataset
) -> tuple[_Scores, _Scores]:
    return session_scores(genome, held), session_scores(genome, pairs)
