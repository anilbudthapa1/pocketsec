"""D9.6 (ONTO-F06) — the Security Renormalization laboratory, and the decision arithmetic.

The architecture (§11-§12) asks whether raw security detail can be replaced by a coarser
representation *without changing the security decision* and *without erasing a counterfactual
distinction*. That is the only sense in which an abstraction is admissible here: fewer bytes
that make the same calls and still tell a malicious session from its benign doppelgänger.

This module exists for three reasons:

* **The ladder.** Four coarse-grainings ``R1..R4`` (:class:`CoarseGraining`) applied to a
  compiled :class:`~pocketsec.stage2.dataset.Stage2Dataset`. A coarse-graining zeroes whole
  feature groups (``GROUP_OFFSETS``) **and** the integer fields those groups mirror, because a
  genome reads ``EncodedTransition`` fields directly and an abstraction that left
  ``relation`` readable while zeroing its one-hot would coarse-grain nothing.
* **The generic tests (G9.3).** :func:`semantic_conservation` and
  :func:`counterfactual_distinction` take score vectors, so the gate applies them to *every*
  abstraction — these levels, precision levels, a minimal-state genome — through one rule.
* **One threshold rule for the whole physics layer.** Every ``compare_*`` in
  ``symmetry``, ``geometry`` and ``compression`` imports :func:`compare_detectors` from here.
  Lesson 5 (an uncalibrated threshold is a parameter) is answered once: every decision uses an
  FPR budget of 0.05 fitted on **train benign** scores, and every verdict uses the same
  ``+0.02`` margin over the strongest control.

What this module refuses to do. It never re-implements the Φ-oracle: the control is always
``phi_oracle_genome()`` run through ``ontogenesis.fitness.session_scores``. It never selects a
level on held-out data. And an attribution counterfactual changes **only** who did what —
the operation multiset, order and timing are byte-identical — so a lost distinction is a
property of the abstraction, not of a second difference smuggled into the twin.
"""

from __future__ import annotations

import dataclasses
import hashlib
import math
import random
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from pocketsec.stage0.benchmark.security_metrics import average_precision
from pocketsec.stage1.labs.corpus import Behaviour, Scenario
from pocketsec.stage2.dataset import Stage2Dataset, Stage2Sample
from pocketsec.stage2.encoder.ssir_encoder import (
    FEATURE_WIDTH,
    GROUP_OFFSETS,
    EncodedTransition,
)
from pocketsec.stage9.genome.computational import ComputationalGenomeV1
from pocketsec.stage9.genome.expressibility import phi_oracle_genome
from pocketsec.stage9.ontogenesis.fitness import session_scores
from pocketsec.stage9.spec.mssc import DetectorComparison, MechanismVerdict

__all__ = [
    "AP_TOLERANCE",
    "BYTES_REDUCTION_MIN",
    "CHAIN_GAP_NS",
    "FEATURE_SLOT_BYTES",
    "FIXED_POINT_MAX_ITERATIONS",
    "FPR_BUDGET",
    "RANDOM_DROP_DRAWS",
    "RENORMALIZATION_DEFAULT_ENABLED",
    "VERDICT_MARGIN",
    "CoarseGraining",
    "CounterfactualDistinction",
    "RenormalizationResult",
    "ScoredDetector",
    "SemanticConservation",
    "attribution_counterfactuals",
    "coarse_grain",
    "compare_detectors",
    "counterfactual_distinction",
    "dataset_feature_bytes",
    "decide",
    "feature_bytes",
    "fpr_threshold",
    "group_widths",
    "phi_oracle_scores",
    "ranked_ap",
    "run_renormalization",
    "semantic_conservation",
    "unmeasured_comparison",
    "verdict_against",
    "zero_groups",
]

#: Off until a measured JUSTIFIED verdict is cited in the findings and its ADR (spec §4.22).
RENORMALIZATION_DEFAULT_ENABLED: bool = False

#: FPR budget for every decision threshold in the physics layer (spec §4.21). Chosen.
FPR_BUDGET = 0.05
#: A mechanism must beat the strongest control by this much AP (spec §4.21). Chosen.
VERDICT_MARGIN = 0.02
#: A level "keeps" quality when held-out AP stays within this of raw (spec §4.10). Chosen.
AP_TOLERANCE = 0.01
#: A level must save at least this share of feature bytes to count (spec §4.10). Chosen.
BYTES_REDUCTION_MIN = 0.30
#: Stage 3's ``SLOT_BYTES = 8`` precedent: a feature slot is one 8-byte value.
FEATURE_SLOT_BYTES = 8
#: The fixed-point search applies a level at most this many times (spec §4.10).
FIXED_POINT_MAX_ITERATIONS = 4
#: The random-drop control is the median AP over this many equal-byte draws: one draw of a
#: random group set is a lottery ticket, not a control. Chosen.
RANDOM_DROP_DRAWS = 5
#: Chain stages carry gaps of 5-40 minutes; routine behaviour gaps are 2-90 s
#: (``ambiguous_corpus.py:237``/``:257``). 300 s separates them with room on both sides.
CHAIN_GAP_NS = 300 * 1_000_000_000
#: Twins get fresh pids from here, far above the corpus's ``100_000 + session*100`` range:
#: Stage 1 carries lineage state across scenarios, so a twin reusing its original's pids
#: would inherit the original's capability and erase its own signal (MEMORY.md corpus trap).
_TWIN_PID_BASE = 900_000_000
_SCORE_EQUAL_TOLERANCE = 1e-12
#: AP differences are compared with this slack so that 0.68 - 0.70 (= -0.0199999...) is the
#: -0.02 it means: a decimal margin must not be decided by binary rounding.
_MARGIN_EPSILON = 1e-9


# --- Decision arithmetic shared by every physics comparison -----------------------------------


def _as_ranked(scores: Sequence[float | None]) -> tuple[float, ...]:
    """An abstained score (``None``) ranks as 0.0, as in ``ontogenesis.fitness.evaluate``."""
    return tuple(0.0 if score is None else float(score) for score in scores)


def ranked_ap(labels: Sequence[int], scores: Sequence[float | None]) -> float | None:
    """Stage 0's average precision, or ``None`` when one class is absent (never a free 1.0)."""
    if len(labels) != len(scores):
        raise ValueError(f"{len(labels)} labels against {len(scores)} scores")
    if len(set(labels)) < 2:
        return None
    return average_precision(labels, _as_ranked(scores))


def fpr_threshold(
    benign_scores: Sequence[float | None], *, budget: float = FPR_BUDGET
) -> float | None:
    """The threshold ``t`` such that *at most* ``budget`` of these benign scores exceed it.

    A session is called positive when its score is **strictly above** ``t``. ``t`` is the
    ``(floor(budget*n) + 1)``-th largest benign score, so at most ``floor(budget*n)`` benign
    scores lie above it — ties never push the false-positive count over the budget.
    ``None`` when there is no benign score to fit on.
    """
    if not 0.0 <= budget < 1.0:
        raise ValueError(f"FPR budget must be within [0, 1), got {budget!r}")
    ranked = sorted(_as_ranked(benign_scores), reverse=True)
    if not ranked:
        return None
    allowed = math.floor(budget * len(ranked))
    return ranked[min(allowed, len(ranked) - 1)]


def decide(scores: Sequence[float | None], threshold: float | None) -> tuple[bool, ...]:
    """Decisions at ``threshold``; with no threshold every decision is negative (abstain)."""
    if threshold is None:
        return tuple(False for _ in scores)
    return tuple(score > threshold for score in _as_ranked(scores))


def _benign(scores: Sequence[float | None], labels: Sequence[int]) -> tuple[float | None, ...]:
    return tuple(score for score, label in zip(scores, labels, strict=True) if label == 0)


def verdict_against(
    value: float | None,
    controls: Sequence[tuple[str, float | None]],
    *,
    margin: float = VERDICT_MARGIN,
) -> tuple[MechanismVerdict, str]:
    """JUSTIFIED iff ``value >= max(controls) + margin``; REJECTED iff ``<= max - margin``.

    An unmeasured control could be the strongest one, so any ``None`` makes the whole
    comparison UNMEASURED rather than quietly comparing against the controls that exist.
    """
    if value is None:
        return MechanismVerdict.UNMEASURED, "the mechanism's metric is unmeasured"
    if not controls:
        return MechanismVerdict.UNMEASURED, "no control was measured"
    missing = [name for name, control in controls if control is None]
    if missing:
        return MechanismVerdict.UNMEASURED, f"unmeasured control(s): {', '.join(missing)}"
    best_name, best = max(controls, key=lambda pair: float(pair[1] or 0.0))
    assert best is not None  # narrowed above; kept for the type checker
    delta = value - best
    text = f"value {value:.4f} vs strongest control {best_name} {best:.4f} (delta {delta:+.4f})"
    if delta >= margin - _MARGIN_EPSILON:
        return MechanismVerdict.JUSTIFIED, text
    if delta <= -margin + _MARGIN_EPSILON:
        return MechanismVerdict.REJECTED, text
    return MechanismVerdict.NOT_YET_JUSTIFIED, text


def phi_oracle_scores(dataset: Stage2Dataset) -> tuple[float | None, ...]:
    """The Φ-oracle control: the canonical genome through the one evaluator, never re-written."""
    return session_scores(phi_oracle_genome(), dataset)


@dataclass(frozen=True, slots=True)
class ScoredDetector:
    """One detector's session scores on train (for its threshold) and held-out (for its AP)."""

    name: str
    heldout_scores: tuple[float | None, ...]
    train_scores: tuple[float | None, ...] | None = None


def _decisions_of(
    detector: ScoredDetector, train_labels: Sequence[int] | None, heldout_labels: Sequence[int]
) -> tuple[tuple[bool, ...], str]:
    if detector.train_scores is not None and train_labels is not None:
        threshold = fpr_threshold(_benign(detector.train_scores, train_labels))
        basis = "train benign"
    else:
        threshold = fpr_threshold(_benign(detector.heldout_scores, heldout_labels))
        basis = "HELD-OUT benign (no train scores supplied)"
    return decide(detector.heldout_scores, threshold), basis


def _degenerate_reason(labels: Sequence[int], *sizes: int) -> str:
    if not labels:
        return "the held-out split is empty"
    if any(size != len(labels) for size in sizes):
        return "score vectors are not aligned with the held-out labels"
    if len(set(labels)) < 2:
        return "the held-out split has a single class, so AP is not computable"
    return ""


def unmeasured_comparison(
    mechanism: str, metric: str, control_names: Sequence[str], reason: str
) -> DetectorComparison:
    """The record for a comparison that could not be run: UNMEASURED, fired 0, the reason."""
    return DetectorComparison(
        mechanism=mechanism, metric=metric, value=None,
        controls=tuple((name, None) for name in control_names),
        verdict=MechanismVerdict.UNMEASURED, fired=0, detail=f"UNMEASURED: {reason}",
    )


def compare_detectors(
    mechanism: str,
    metric: str,
    candidate: ScoredDetector,
    controls: Sequence[ScoredDetector],
    *,
    heldout_labels: Sequence[int],
    train_labels: Sequence[int] | None = None,
    detail: str = "",
) -> DetectorComparison:
    """The one comparison record every physics detector returns (G9.9 reads it).

    ``value`` is the candidate's held-out AP and each control's held-out AP is listed.
    ``fired`` counts held-out sessions whose decision under the candidate differs from the
    decision under the **strongest** control, each at its own FPR-0.05 threshold fitted on
    train benign scores. ``fired == 0`` means the mechanism never changed a call: INERT.
    A degenerate input returns UNMEASURED with the reason; it never raises.
    """
    sizes = (len(candidate.heldout_scores), *(len(c.heldout_scores) for c in controls))
    reason = _degenerate_reason(heldout_labels, *sizes)
    if reason:
        return unmeasured_comparison(
            mechanism, metric, [control.name for control in controls], f"{reason}. {detail}"
        )
    value = ranked_ap(heldout_labels, candidate.heldout_scores)
    measured = tuple(
        (control.name, ranked_ap(heldout_labels, control.heldout_scores)) for control in controls
    )
    verdict, text = verdict_against(value, measured)
    fired, basis = 0, "no control"
    if controls:
        strongest = max(zip(controls, measured, strict=True), key=lambda p: p[1][1] or 0.0)[0]
        mine, basis = _decisions_of(candidate, train_labels, heldout_labels)
        theirs, _ = _decisions_of(strongest, train_labels, heldout_labels)
        fired = sum(1 for a, b in zip(mine, theirs, strict=True) if a != b)
    inert = " INERT (no decision differs from the strongest control)." if fired == 0 else ""
    if verdict is MechanismVerdict.JUSTIFIED and fired == 0:
        # A better AP that never changes a call is not the mechanism's doing (mssc contract).
        verdict = MechanismVerdict.NOT_YET_JUSTIFIED
    return DetectorComparison(
        mechanism=mechanism, metric=metric, value=value, controls=measured, verdict=verdict,
        fired=fired,
        detail=f"{text}; thresholds at FPR {FPR_BUDGET} fitted on {basis}.{inert} {detail}".strip(),
    )


# --- The coarse-graining ladder ---------------------------------------------------------------


class CoarseGraining(StrEnum):
    """The renormalization ladder ``R_k`` (architecture §11), concrete on the Stage 2 encoding."""

    R1_DROP_NOVELTY_TEMPORAL = "R1_DROP_NOVELTY_TEMPORAL"
    R2_RELATION_TO_FAMILY = "R2_RELATION_TO_FAMILY"
    R3_STATE_ONLY = "R3_STATE_ONLY"
    R4_LINEAGE_EPISODE = "R4_LINEAGE_EPISODE"


def group_widths() -> dict[str, int]:
    """Each feature group's width, derived from ``GROUP_OFFSETS`` and ``FEATURE_WIDTH``.

    Derived rather than imported from ``FEATURE_LAYOUT`` because the §2.3 allow-list names
    ``GROUP_OFFSETS`` and not the layout; the test cross-checks the two agree.
    """
    ordered = sorted(GROUP_OFFSETS.items(), key=lambda pair: pair[1])
    widths: dict[str, int] = {}
    for position, (group, start) in enumerate(ordered):
        end = ordered[position + 1][1] if position + 1 < len(ordered) else FEATURE_WIDTH
        widths[group] = end - start
    return widths


_WIDTHS = group_widths()  # computed once: _zero_step runs per event

#: The integer fields that mirror a feature group. Zeroing a group zeroes its field too,
#: because genomes read these fields as ``InputSource`` values.
_GROUP_FIELDS: dict[str, tuple[str, object]] = {
    "relation_onehot": ("relation", 0),
    "relation_family_onehot": ("relation_family", 0),
    "object_semantics": ("object_property_mask", 0),
    "state_delta_raised": ("state_delta_mask", 0),
    "delta_phi": ("delta_phi", 0.0),
    "temporal": ("time_bucket", 0),
}
_STATE_GROUPS = frozenset({"state_delta_raised", "state_delta_scalars", "delta_phi"})


def _dropped_groups(level: CoarseGraining) -> frozenset[str]:
    if level is CoarseGraining.R1_DROP_NOVELTY_TEMPORAL:
        return frozenset({"novelty_tensor", "novelty_scalars", "temporal"})
    if level is CoarseGraining.R2_RELATION_TO_FAMILY:
        return frozenset({"relation_onehot"})
    if level is CoarseGraining.R3_STATE_ONLY:
        return frozenset(GROUP_OFFSETS) - _STATE_GROUPS
    return frozenset()  # R4 keeps every slot; it removes events instead


def feature_bytes(level: CoarseGraining | None) -> int:
    """Bytes of non-zeroed feature slots **per event** (``None`` = the raw representation)."""
    if level is None:
        return FEATURE_WIDTH * FEATURE_SLOT_BYTES
    widths = group_widths()
    dropped = sum(widths[group] for group in _dropped_groups(CoarseGraining(level)))
    return (FEATURE_WIDTH - dropped) * FEATURE_SLOT_BYTES


def _zero_step(step: EncodedTransition, groups: frozenset[str]) -> EncodedTransition:
    widths = _WIDTHS
    features = list(step.features)
    changes: dict[str, object] = {}
    for group in groups:
        start = GROUP_OFFSETS[group]
        features[start : start + widths[group]] = [0.0] * widths[group]
        if group in _GROUP_FIELDS:
            name, zero = _GROUP_FIELDS[group]
            changes[name] = zero
    return dataclasses.replace(step, features=tuple(features), **changes)  # type: ignore[arg-type]


def _with_steps(sample: Stage2Sample, steps: tuple[EncodedTransition, ...]) -> Stage2Sample:
    return dataclasses.replace(sample, steps=steps)


def zero_groups(dataset: Stage2Dataset, groups: frozenset[str], *, name: str) -> Stage2Dataset:
    """Zero every named feature group (and its mirrored field) in every step; ids/labels kept."""
    unknown = sorted(groups - set(GROUP_OFFSETS))
    if unknown:
        raise ValueError(f"unknown feature groups {unknown}")
    samples = tuple(
        _with_steps(sample, tuple(_zero_step(step, groups) for step in sample.steps))
        for sample in dataset.samples
    )
    return dataclasses.replace(dataset, name=name, samples=samples)


def _lineage_summary(steps: Sequence[EncodedTransition], slot: int) -> EncodedTransition:
    """One step per lineage: OR of masks, sum of ΔΦ, element-wise max of features.

    Categorical fields that have no meaningful aggregate (relation, family, time bucket,
    epoch) take the lineage's most recent value. Evidence locators are the union, in order,
    so the summary still points at every raw event it replaced.
    """
    last = steps[-1]
    mask = obj_mask = 0
    evidence: dict[str, None] = {}
    for step in steps:
        mask |= step.state_delta_mask
        obj_mask |= step.object_property_mask
        evidence.update(dict.fromkeys(step.evidence))
    return EncodedTransition(
        features=tuple(max(column) for column in zip(*(s.features for s in steps), strict=True)),
        relation=last.relation, relation_family=last.relation_family, state_delta_mask=mask,
        time_bucket=last.time_bucket, delta_phi=sum(step.delta_phi for step in steps),
        object_property_mask=obj_mask, epoch_id=last.epoch_id, actor_slot=slot,
        evidence=tuple(evidence),
    )


def _episode_sample(sample: Stage2Sample) -> Stage2Sample:
    by_slot: dict[int, list[EncodedTransition]] = {}
    for step in sample.steps:
        by_slot.setdefault(step.actor_slot, []).append(step)
    return _with_steps(
        sample, tuple(_lineage_summary(steps, slot) for slot, steps in by_slot.items())
    )


def coarse_grain(dataset: Stage2Dataset, level: CoarseGraining) -> Stage2Dataset:
    """Apply one level of the ladder. Sample ids, labels and order are always preserved."""
    level = CoarseGraining(level)
    name = f"{dataset.name}/{level.value}"
    if level is CoarseGraining.R4_LINEAGE_EPISODE:
        samples = tuple(_episode_sample(sample) for sample in dataset.samples)
        return dataclasses.replace(dataset, name=name, samples=samples)
    return zero_groups(dataset, _dropped_groups(level), name=name)


def dataset_feature_bytes(dataset: Stage2Dataset, level: CoarseGraining | None) -> int:
    """Total feature bytes a split occupies at ``level`` (R4 saves bytes by removing events)."""
    return feature_bytes(level) * dataset.transition_count


def _sample_digest(sample: Stage2Sample) -> str:
    hasher = hashlib.sha256(sample.sample_id.encode())
    for step in sample.steps:
        hasher.update(
            repr((step.actor_slot, step.relation, step.relation_family, step.state_delta_mask,
                  step.time_bucket, round(step.delta_phi, 9), step.object_property_mask,
                  tuple(round(value, 9) for value in step.features))).encode()
        )
    return hasher.hexdigest()


def _dataset_digest(dataset: Stage2Dataset) -> str:
    hasher = hashlib.sha256()
    for sample in dataset.samples:
        hasher.update(_sample_digest(sample).encode())
    return "sha256:" + hasher.hexdigest()


# --- The generic G9.3 tests -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SemanticConservation:
    """Did an abstraction keep the security *decisions*, and at what byte cost?

    ``decision_agreement`` is the share of sessions whose call is unchanged, both calls made
    at the FPR-0.05 threshold fitted on the ORIGINAL representation's train benign scores.
    ``None`` when there is no train benign score to fit that threshold on (UNMEASURED).
    """

    level: str
    decision_agreement: float | None
    ap_before: float | None
    ap_after: float | None
    bytes_before: int
    bytes_after: int
    decisions_changed: int = 0


def semantic_conservation(
    label: str,
    *,
    train_scores_before: Sequence[float | None],
    scores_before: Sequence[float | None],
    scores_after: Sequence[float | None],
    labels: Sequence[int],
    bytes_before: int,
    bytes_after: int,
) -> SemanticConservation:
    """Generic: works for ANY abstraction (a coarse-graining, a precision level, a minimal state).

    ``train_scores_before`` are the original representation's scores on **train benign**
    sessions; the threshold is fitted on them once and applied, unchanged, to both vectors.
    """
    if not len(scores_before) == len(scores_after) == len(labels):
        raise ValueError("scores_before, scores_after and labels must be aligned")
    threshold = fpr_threshold(train_scores_before)
    before = decide(scores_before, threshold)
    after = decide(scores_after, threshold)
    changed = sum(1 for a, b in zip(before, after, strict=True) if a != b)
    agreement = None if threshold is None or not labels else 1.0 - changed / len(labels)
    return SemanticConservation(
        level=label, decision_agreement=agreement,
        ap_before=ranked_ap(labels, scores_before), ap_after=ranked_ap(labels, scores_after),
        bytes_before=bytes_before, bytes_after=bytes_after,
        decisions_changed=changed if threshold is not None else 0,
    )


@dataclass(frozen=True, slots=True)
class CounterfactualDistinction:
    """How many malicious-vs-twin pairs an abstraction still tells apart.

    ``lost`` counts pairs distinguished before and not after: the abstraction erased that
    counterfactual. An abstraction "keeps every distinction" iff ``lost == 0``.
    """

    level: str
    pairs: int
    distinguished_before: int
    distinguished_after: int
    lost: int = 0


def _distinguished(scores: Sequence[float | None]) -> tuple[bool, ...]:
    ranked = _as_ranked(scores)
    return tuple(
        ranked[2 * i] - ranked[2 * i + 1] > _SCORE_EQUAL_TOLERANCE for i in range(len(ranked) // 2)
    )


def counterfactual_distinction(
    label: str,
    *,
    pair_scores_before: Sequence[float | None],
    pair_scores_after: Sequence[float | None],
) -> CounterfactualDistinction:
    """Pairs are interleaved: index ``2i`` is malicious, ``2i+1`` its attribution twin.

    Distinguished means ``score(2i) > score(2i+1)`` — the abstraction still ranks the
    single-lineage chain above the same chain spread across actors.
    """
    if len(pair_scores_before) != len(pair_scores_after):
        raise ValueError("before and after pair scores must be aligned")
    if len(pair_scores_before) % 2:
        raise ValueError("pair scores must be interleaved (malicious, twin), so even in length")
    before = _distinguished(pair_scores_before)
    after = _distinguished(pair_scores_after)
    return CounterfactualDistinction(
        level=label, pairs=len(before),
        distinguished_before=sum(before), distinguished_after=sum(after),
        lost=sum(1 for b, a in zip(before, after, strict=True) if b and not a),
    )


def _actor_key(behaviour: Behaviour) -> tuple[str, str] | None:
    pid = behaviour.fields.get("pid")
    start = behaviour.fields.get("start_time")
    return None if pid is None or start is None else (pid, start)


def _is_chain_stage(behaviour: Behaviour) -> bool:
    try:
        return int(behaviour.fields.get("_gap_ns", "0")) >= CHAIN_GAP_NS
    except ValueError:
        return False


def _twin(scenario: Scenario, pair_index: int, rng: random.Random) -> Scenario | None:
    """The same stream with each chain stage re-attributed to a distinct *other* actor."""
    actors = list(dict.fromkeys(k for b in scenario.behaviours if (k := _actor_key(b))))
    stages = [i for i, b in enumerate(scenario.behaviours) if _is_chain_stage(b)]
    owners = {_actor_key(scenario.behaviours[i]) for i in stages}
    others = [actor for actor in actors if actor not in owners]
    if not stages or None in owners or len(others) < len(stages):
        return None
    new_owner = dict(zip(stages, rng.sample(others, k=len(stages)), strict=True))
    fresh = {actor: str(_TWIN_PID_BASE + pair_index * 10_000 + k) for k, actor in enumerate(actors)}
    behaviours: list[Behaviour] = []
    for index, behaviour in enumerate(scenario.behaviours):
        actor = new_owner.get(index, _actor_key(behaviour))
        if actor is None:
            behaviours.append(behaviour)
            continue
        behaviours.append(behaviour.with_fields(pid=fresh[actor], start_time=actor[1]))
    return Scenario(
        name=f"{scenario.name}-twin", behaviours=tuple(behaviours), label=0, technique=None,
        unseen_technique=False,
    )


def attribution_counterfactuals(
    scenarios: Sequence[Scenario], *, seed: int
) -> tuple[tuple[Scenario, Scenario], ...]:
    """For each malicious scenario, its benign twin: the SAME chain, spread across actors.

    Only attribution changes: every behaviour keeps its operation, fields, position and gap;
    chain stages (``_gap_ns >= 300 s``) move to distinct other actors of the same session, and
    every actor is renamed to a fresh, session-unique pid so Stage 1 cannot carry the
    original's lineage state into the twin. A scenario with fewer other actors than chain
    stages has no valid twin and is skipped — the caller sees it as a shorter tuple.
    Compile ``[m0, t0, m1, t1, ...]`` to get the interleaved pair dataset.
    """
    rng = random.Random(seed * 1_000_003 + 9)
    pairs: list[tuple[Scenario, Scenario]] = []
    for scenario in scenarios:
        if scenario.label != 1:
            continue
        twin = _twin(scenario, len(pairs), rng)
        if twin is not None:
            pairs.append((scenario, twin))
    return tuple(pairs)


# --- The laboratory run -----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RenormalizationResult:
    """Every level's conservation and counterfactual record, the control, and the verdict.

    ``fired`` counts held-out sessions whose representation the chosen level actually
    changed; 0 means the level only zeroed slots that were already zero (INERT). How many
    sessions' *genome scores* it changed is a separate figure, reported in ``detail``.
    """

    genome_digest: str
    conservation: tuple[SemanticConservation, ...]
    counterfactual: tuple[CounterfactualDistinction, ...]
    fixed_point_level: str | None
    fixed_point_iterations: int
    random_drop_control_ap: float | None
    fired: int
    verdict: MechanismVerdict
    detail: str


def _random_drop_groups(share: float, rng: random.Random) -> frozenset[str]:
    """Random whole groups until at least ``share`` of the slots are dropped (equal bytes)."""
    widths = group_widths()
    order = sorted(GROUP_OFFSETS)
    rng.shuffle(order)
    dropped: set[str] = set()
    slots = 0
    for group in order:
        if slots >= share * FEATURE_WIDTH:
            break
        dropped.add(group)
        slots += widths[group]
    return frozenset(dropped)


def _qualifies(cons: SemanticConservation, cf: CounterfactualDistinction) -> bool:
    if cons.ap_before is None or cons.ap_after is None or cons.bytes_before <= 0:
        return False
    return (
        cons.ap_after >= cons.ap_before - AP_TOLERANCE
        and cons.bytes_after <= (1.0 - BYTES_REDUCTION_MIN) * cons.bytes_before
        and cf.pairs > 0
        and cf.lost == 0
    )


def _fixed_point(dataset: Stage2Dataset, level: CoarseGraining) -> tuple[int, bool]:
    """Apply ``level`` until the dataset digest stops changing, at most 4 applications."""
    current, digest = dataset, _dataset_digest(dataset)
    for iteration in range(1, FIXED_POINT_MAX_ITERATIONS + 1):
        current = coarse_grain(current, level)
        new_digest = _dataset_digest(current)
        if new_digest == digest:
            return iteration, True
        digest = new_digest
    return FIXED_POINT_MAX_ITERATIONS, False


def _level_records(
    genome: ComputationalGenomeV1,
    datasets: tuple[Stage2Dataset, Stage2Dataset],
    raw: tuple[tuple[float | None, ...], tuple[float | None, ...], tuple[float | None, ...]],
) -> tuple[tuple[SemanticConservation, CounterfactualDistinction], ...]:
    heldout, pairs = datasets
    train_benign, heldout_raw, pairs_raw = raw
    records = []
    for level in CoarseGraining:
        coarse = coarse_grain(heldout, level)
        cons = semantic_conservation(
            level.value, train_scores_before=train_benign, scores_before=heldout_raw,
            scores_after=session_scores(genome, coarse), labels=heldout.labels,
            bytes_before=dataset_feature_bytes(heldout, None),
            bytes_after=dataset_feature_bytes(coarse, level),
        )
        cf = counterfactual_distinction(
            level.value, pair_scores_before=pairs_raw,
            pair_scores_after=session_scores(genome, coarse_grain(pairs, level)),
        )
        records.append((cons, cf))
    return tuple(records)


def _renormalization_verdict(
    chosen: tuple[SemanticConservation, CounterfactualDistinction] | None,
    qualifies: bool,
    control_ap: float | None,
) -> tuple[MechanismVerdict, str]:
    if chosen is None or chosen[0].ap_before is None or chosen[1].pairs == 0:
        return MechanismVerdict.UNMEASURED, "raw held-out AP or the pair set is unmeasurable"
    if not qualifies:
        return MechanismVerdict.REJECTED, (
            f"no level keeps held-out AP within {AP_TOLERANCE} of raw with >= "
            f"{BYTES_REDUCTION_MIN:.0%} fewer bytes and every counterfactual distinction"
        )
    verdict, text = verdict_against(chosen[0].ap_after, (("random-group-drop", control_ap),))
    if verdict is MechanismVerdict.REJECTED:
        verdict = MechanismVerdict.NOT_YET_JUSTIFIED  # it conserves; it just is not special
    return verdict, f"{chosen[0].level} conserves; vs equal-byte random drop: {text}"


@dataclass(frozen=True, slots=True)
class _ChosenLevel:
    control_ap: float | None
    iterations: int
    stable: bool
    representation_changed: int
    scores_changed: int


def _measure_chosen(
    genome: ComputationalGenomeV1,
    heldout: Stage2Dataset,
    chosen: SemanticConservation,
    heldout_raw: Sequence[float | None],
    seed: int,
) -> _ChosenLevel:
    """The equal-byte random-drop control (median of several draws), fixed point, firing."""
    level = CoarseGraining(chosen.level)
    share = 1.0 - chosen.bytes_after / max(chosen.bytes_before, 1)
    control_aps = []
    for draw in range(RANDOM_DROP_DRAWS):
        dropped = _random_drop_groups(share, random.Random(seed * 1_000_003 + 6 + draw))
        control = zero_groups(heldout, dropped, name=f"{heldout.name}/random-drop-{draw}")
        control_aps.append(ranked_ap(heldout.labels, session_scores(genome, control)))
    measured = sorted(ap for ap in control_aps if ap is not None)
    iterations, stable = _fixed_point(heldout, level)
    coarse = coarse_grain(heldout, level)
    after = session_scores(genome, coarse)
    return _ChosenLevel(
        control_ap=measured[len(measured) // 2] if len(measured) == len(control_aps) else None,
        iterations=iterations, stable=stable,
        representation_changed=sum(
            1 for a, b in zip(heldout.samples, coarse.samples, strict=True)
            if _sample_digest(a) != _sample_digest(b)
        ),
        scores_changed=sum(
            1 for a, b in zip(_as_ranked(heldout_raw), _as_ranked(after), strict=True)
            if abs(a - b) > _SCORE_EQUAL_TOLERANCE
        ),
    )


def run_renormalization(
    genome: ComputationalGenomeV1,
    train: Stage2Dataset,
    heldout: Stage2Dataset,
    pairs: Stage2Dataset,
    *,
    seed: int,
) -> RenormalizationResult:
    """Every level on held-out, the equal-byte random-drop control, a fixed point, a verdict.

    JUSTIFIED iff some level keeps held-out AP >= raw - 0.01 with >= 30% fewer feature bytes,
    keeps every counterfactual distinction, AND beats the random-drop control (the median of
    :data:`RANDOM_DROP_DRAWS` equal-byte draws) by >= 0.02. The decision threshold is fitted
    on the raw representation's train benign scores. The level chosen is the qualifying one
    with the fewest bytes (or, if none qualifies, the cheapest measurable one, for the report).
    Degenerate inputs (a single class, no pairs) return UNMEASURED; nothing raises.
    """
    raw = (
        _benign(session_scores(genome, train), train.labels),
        session_scores(genome, heldout),
        session_scores(genome, pairs),
    )
    records = _level_records(genome, (heldout, pairs), raw)
    passing = [record for record in records if _qualifies(*record)]
    pool = passing or [record for record in records if record[0].ap_after is not None]
    chosen = min(pool, key=lambda r: r[0].bytes_after) if pool else None
    measured = _measure_chosen(genome, heldout, chosen[0], raw[1], seed) if chosen else None
    verdict, text = _renormalization_verdict(
        chosen, bool(passing), measured.control_ap if measured else None
    )
    fired = measured.representation_changed if measured else 0
    if verdict is MechanismVerdict.JUSTIFIED and fired == 0:
        verdict = MechanismVerdict.NOT_YET_JUSTIFIED  # an unchanged input saved nothing
    lines = "; ".join(
        f"{c.level}: AP {c.ap_before}->{c.ap_after}, bytes {c.bytes_before}->{c.bytes_after}, "
        f"lost {cf.lost}/{cf.pairs}" for c, cf in records
    )
    firing = (
        f"chosen level changed the representation of {fired} and the genome score of "
        f"{measured.scores_changed} held-out session(s){' (INERT)' if not fired else ''}. "
        if measured else ""
    )
    return RenormalizationResult(
        genome_digest=genome.digest, conservation=tuple(r[0] for r in records),
        counterfactual=tuple(r[1] for r in records),
        fixed_point_level=chosen[0].level if chosen and measured and measured.stable else None,
        fixed_point_iterations=measured.iterations if measured else 0,
        random_drop_control_ap=measured.control_ap if measured else None, fired=fired,
        verdict=verdict, detail=f"{text}. {firing}{lines}",
    )
