"""D9.7 (ONTO-F07, first half) — the Symmetry suite: invariance tests and symmetry-breaking.

Architecture §13 asks which variations a detector should *ignore*: renaming a user or PID,
substituting a path class, translating time, reordering benign interleavings. A detector
whose score moves under such a transformation is reading a nuisance, and ARGUS can exploit
it. :func:`invariance` measures that directly, session by session, on compiled splits.

§14 then proposes the inverse: *symmetry-breaking* ``B_G(x)`` — how much a session's score
moves under the transformations — as an anomaly signal. The architecture itself says the
method "survives only if it adds value beyond simpler rarity and graph-motif baselines", so
:func:`compare_symmetry_breaking` pits it against the Stage 1 novelty peak (``features[83]``)
and the Φ-oracle and ships :data:`SYMMETRY_BREAKING_DEFAULT_ENABLED` ``False``.

What this module refuses to do. It never reports a transformation it cannot perform as
invariant: host-identity permutation needs a second host, interpreter substitution needs
interpreter alternatives the corpus does not have, and a *learned* symmetry needs a learner
nobody built (S9X-023). Those return ``invariant=None`` with the reason — UNMEASURED, which
is never read as "invariant". The transformed splits for path class, time translation and
benign reorder are ARGUS's label-preserving scenario attacks, compiled by the caller through
``labs.splits``; this module does not re-author them.
"""

from __future__ import annotations

import dataclasses
import random
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from pocketsec.stage2.dataset import Stage2Dataset, Stage2Sample
from pocketsec.stage2.encoder.ssir_encoder import NEED_SIGNAL_INDICES
from pocketsec.stage9.genome.computational import ComputationalGenomeV1
from pocketsec.stage9.ontogenesis.fitness import session_scores
from pocketsec.stage9.renormalization.laboratory import (
    ScoredDetector,
    compare_detectors,
    phi_oracle_scores,
    unmeasured_comparison,
)
from pocketsec.stage9.spec.mssc import DetectorComparison

__all__ = [
    "ARGUS_VARIANT_OF",
    "INVARIANCE_TOLERANCE",
    "NOVELTY_PEAK_INDEX",
    "SYMMETRY_BREAKING_DEFAULT_ENABLED",
    "UNMEASURED_TRANSFORMATIONS",
    "SymmetryTest",
    "Transformation",
    "compare_symmetry_breaking",
    "invariance",
    "novelty_peak_scores",
    "permute_actor_slots",
    "symmetry_breaking_scores",
]

#: Off until a measured JUSTIFIED verdict is cited in the findings and its ADR (spec §4.22).
SYMMETRY_BREAKING_DEFAULT_ENABLED: bool = False

#: A score "changed" when it moved by more than this. Scores are deterministic, so any
#: real movement is far above float noise.
INVARIANCE_TOLERANCE = 1e-12

#: Stage 1's novelty peak slot — the rarity control. Derived from the layout, not pinned.
NOVELTY_PEAK_INDEX: int = NEED_SIGNAL_INDICES["novelty_peak"]


class Transformation(StrEnum):
    """The candidate symmetry group ``G`` of architecture §13, bound to what can be run."""

    ACTOR_SLOT_PERMUTATION = "ACTOR_SLOT_PERMUTATION"
    PATH_CLASS = "PATH_CLASS"
    TIME_TRANSLATION = "TIME_TRANSLATION"
    BENIGN_REORDER = "BENIGN_REORDER"
    HOST_IDENTITY = "HOST_IDENTITY"
    INTERPRETER_SUBSTITUTION = "INTERPRETER_SUBSTITUTION"
    LEARNED = "LEARNED"


#: Which ARGUS scenario attack realises each measurable transformation (``argus.adversary``).
ARGUS_VARIANT_OF: dict[Transformation, str] = {
    Transformation.PATH_CLASS: "rename_binaries",
    Transformation.TIME_TRANSLATION: "timing_stretch",
    Transformation.BENIGN_REORDER: "reorder_across_actors",
}

#: Transformations that cannot be performed on this corpus, with the reason each is refused.
UNMEASURED_TRANSFORMATIONS: dict[Transformation, str] = {
    Transformation.HOST_IDENTITY: "single synthetic host: there is no second host to permute",
    Transformation.INTERPRETER_SUBSTITUTION: (
        "the corpus holds no equivalent-interpreter alternatives to substitute"
    ),
    Transformation.LEARNED: "no symmetry learner is built (S9X-023)",
}


@dataclass(frozen=True, slots=True)
class SymmetryTest:
    """Whether a genome's session scores survive one transformation.

    ``invariant`` is ``None`` when the transformation was not measured; ``reason`` then says
    why. A session missing from the transformed split counts as changed (the transformation
    removed it, which is not invariance).
    """

    transformation: str
    sessions: int
    score_changed: int
    max_abs_delta: float | None
    invariant: bool | None
    reason: str = ""


def _unmeasured(transformation: Transformation, reason: str) -> SymmetryTest:
    return SymmetryTest(
        transformation=transformation.value, sessions=0, score_changed=0, max_abs_delta=None,
        invariant=None, reason=f"UNMEASURED: {reason}",
    )


def _aligned_deltas(
    clean: Stage2Dataset,
    clean_scores: Sequence[float | None],
    transformed: Stage2Dataset,
    transformed_scores: Sequence[float | None],
) -> tuple[list[float | None], int]:
    """Per clean session, ``|delta|`` against its transformed twin (``None`` if missing)."""
    by_id = {
        sample.sample_id: score
        for sample, score in zip(transformed.samples, transformed_scores, strict=True)
    }
    deltas: list[float | None] = []
    missing = 0
    for sample, score in zip(clean.samples, clean_scores, strict=True):
        if sample.sample_id not in by_id:
            deltas.append(None)
            missing += 1
            continue
        other = by_id[sample.sample_id]
        deltas.append(abs((score or 0.0) - (other or 0.0)))
    return deltas, missing


def invariance(
    genome: ComputationalGenomeV1,
    clean: Stage2Dataset,
    transformed: Stage2Dataset | None,
    transformation: Transformation,
) -> SymmetryTest:
    """Does ``genome`` score every session identically before and after ``transformation``?"""
    transformation = Transformation(transformation)
    if transformation in UNMEASURED_TRANSFORMATIONS:
        return _unmeasured(transformation, UNMEASURED_TRANSFORMATIONS[transformation])
    if transformed is None:
        return _unmeasured(transformation, "no transformed split was supplied")
    if not clean.samples:
        return _unmeasured(transformation, "the clean split is empty")
    deltas, missing = _aligned_deltas(
        clean, session_scores(genome, clean), transformed, session_scores(genome, transformed)
    )
    present = [delta for delta in deltas if delta is not None]
    changed = missing + sum(1 for delta in present if delta > INVARIANCE_TOLERANCE)
    return SymmetryTest(
        transformation=transformation.value, sessions=len(clean.samples), score_changed=changed,
        max_abs_delta=max(present) if present else None, invariant=changed == 0,
        reason=f"{missing} session(s) absent from the transformed split" if missing else "",
    )


def _permuted_sample(sample: Stage2Sample, seed: int) -> Stage2Sample:
    slots = sorted({step.actor_slot for step in sample.steps})
    # A string seed goes through sha512 in ``random.seed``: stable under PYTHONHASHSEED.
    shuffled = list(slots)
    random.Random(f"{seed}:{sample.sample_id}").shuffle(shuffled)
    mapping = dict(zip(slots, shuffled, strict=True))
    steps = tuple(
        dataclasses.replace(step, actor_slot=mapping[step.actor_slot]) for step in sample.steps
    )
    return dataclasses.replace(sample, steps=steps)


def permute_actor_slots(dataset: Stage2Dataset, *, seed: int) -> Stage2Dataset:
    """Rename lineages inside each session (user/PID renaming); nothing else moves.

    ``actor_slot`` is a session-local grouping key, so a permutation is exactly a relabelling
    of who is who. Event order, features and labels are untouched.
    """
    samples = tuple(_permuted_sample(sample, seed) for sample in dataset.samples)
    return dataclasses.replace(dataset, name=f"{dataset.name}/slot-permuted", samples=samples)


def symmetry_breaking_scores(
    genome: ComputationalGenomeV1,
    clean: Stage2Dataset,
    variants: Sequence[Stage2Dataset],
) -> tuple[float, ...]:
    """``B_G(x) = mean_g |score(x) - score(g(x))|`` per clean session (architecture §14).

    A variant missing a session contributes nothing to that session's mean; a session
    missing from every variant scores 0.0 (no evidence of breaking).
    """
    clean_scores = session_scores(genome, clean)
    totals = [0.0] * len(clean.samples)
    counts = [0] * len(clean.samples)
    for variant in variants:
        deltas, _ = _aligned_deltas(clean, clean_scores, variant, session_scores(genome, variant))
        for index, delta in enumerate(deltas):
            if delta is not None:
                totals[index] += delta
                counts[index] += 1
    return tuple(
        total / count if count else 0.0 for total, count in zip(totals, counts, strict=True)
    )


def novelty_peak_scores(dataset: Stage2Dataset) -> tuple[float, ...]:
    """The rarity control: each session's maximum Stage 1 novelty peak (``features[83]``)."""
    return tuple(
        max((step.features[NOVELTY_PEAK_INDEX] for step in sample.steps), default=0.0)
        for sample in dataset.samples
    )


def compare_symmetry_breaking(
    genome: ComputationalGenomeV1,
    heldout_clean: Stage2Dataset,
    heldout_variants: Sequence[Stage2Dataset],
    *,
    train_clean: Stage2Dataset | None = None,
    train_variants: Sequence[Stage2Dataset] = (),
) -> DetectorComparison:
    """Symmetry-breaking vs rarity (``max features[83]``) and the Φ-oracle, on held-out AP.

    JUSTIFIED iff ``AP(B_G) >= max(controls) + 0.02``. Pass ``train_clean`` (and its variants)
    so the decision thresholds behind ``fired`` are fitted on train; without it they are
    fitted on held-out benign, and the detail says so. No variant means UNMEASURED.
    """
    mechanism = f"{__name__}:SYMMETRY_BREAKING_DEFAULT_ENABLED"
    metric = "heldout_ap(symmetry_breaking)"
    if not heldout_variants:
        return unmeasured_comparison(
            mechanism, metric, ("rarity-novelty-peak", "phi-oracle"),
            "no transformed held-out variant was supplied",
        )
    use_train = train_clean is not None and bool(train_variants)
    candidate = ScoredDetector(
        "symmetry-breaking",
        symmetry_breaking_scores(genome, heldout_clean, heldout_variants),
        symmetry_breaking_scores(genome, train_clean, train_variants)
        if use_train and train_clean is not None else None,
    )
    controls = (
        ScoredDetector(
            "rarity-novelty-peak", novelty_peak_scores(heldout_clean),
            novelty_peak_scores(train_clean) if use_train and train_clean is not None else None,
        ),
        ScoredDetector(
            "phi-oracle", phi_oracle_scores(heldout_clean),
            phi_oracle_scores(train_clean) if use_train and train_clean is not None else None,
        ),
    )
    return compare_detectors(
        mechanism, metric, candidate, controls, heldout_labels=heldout_clean.labels,
        train_labels=train_clean.labels if use_train and train_clean is not None else None,
        detail=f"{len(heldout_variants)} held-out variant(s).",
    )
