"""D9.2 (second half): can the genome language express the incumbents? Checked first.

Stage 3's bytecode could not carry the Φ-oracle because it had no division and no MAX
(M0.10). A language that cannot express the incumbent cannot find a cheaper equivalent
of it, and every search result over such a language is uninterpretable. This module is
therefore run *before* any search, and it answers with measurements, not assertions:

* :func:`phi_oracle_genome` writes Stage 2's zero-parameter Φ-oracle as a 3-node,
  3-WU/event genome, and :func:`check_expressibility` compares its scores with two
  independent references - ``max(step.features[73])`` per session, and Stage 2's own
  ``PHI_ORACLE_SCORER.evaluate`` over ``stage2.gate_measures.lineage_windows``, max over
  windows. Exact means within 1e-12 on every session.
* :func:`phi_oracle_raw_genome` recomputes the squash ``x / (x + 8)`` from raw ΔΦ, which
  is the one place the language needs ``DIV``.
* All 96 x 3 Stage 2 ``DeterministicScorerSpec`` rules are written as genomes. The
  ``max`` rows must be exact. ``mean`` and ``last`` are defined by Stage 2 per causal-root
  :class:`LineageWindow`, while genome lineages are keyed by ``actor_slot``; where those
  two partitions of a session differ the row reports ``exact=False`` with the reason.
  That is a difference of definitions, reported rather than hidden.
* :func:`reduced_tcn_genome` proves the TCN *operator family* (projection, kernel-3
  causal convolution through a ring register, ReLU, max-over-time, linear readout) is
  expressible, against a plain-Python reference. The full Stage 2 TCN is not
  expressible within the IR's bounds; :data:`STAGE2_TCN_BOUND_NOTE` gives the arithmetic.
* The two hand-designed per-lineage baselines H1 and H2 (spec §7) and the order-free
  saturation control are defined here, once, so the search and the gate compare against
  the same objects. H1/H2 were written by the author of the spec after reading the
  corpus generator: they are author-confounded, and are baselines precisely for that
  reason (lesson 6).

What this module refuses to do: it never tunes anything, never reads a label and never
decides a verdict. ``exact`` is a comparison of two score vectors, nothing more.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from itertools import pairwise
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage2.compile_candidates.phi_oracle_candidate import (
    AGGREGATIONS,
    PHI_ORACLE_SCORER,
    PHI_SQUASHED_FEATURE_INDEX,
    DeterministicScorerSpec,
)
from pocketsec.stage2.dataset import Stage2Dataset, Stage2Sample
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_WIDTH
from pocketsec.stage2.gate_measures import lineage_windows
from pocketsec.stage9.chemistry.phenotype import SessionAggregation
from pocketsec.stage9.chemistry.typed_ir import (
    MAX_CONSTANTS,
    MAX_LINEAGES,
    MAX_PROGRAM_NODES,
    InputSource,
    IRNode,
    IRProgram,
    IRType,
    NodeKind,
    ProgramPhase,
    RegisterSpec,
)
from pocketsec.stage9.genome.computational import ComputationalGenomeV1, build_genome

__all__ = [
    "EXACT_TOLERANCE",
    "REDUCED_TCN_DEFAULT_FEATURES",
    "REDUCED_TCN_DEFAULT_WEIGHTS",
    "REDUCED_TCN_MAX_FEATURES",
    "STAGE2_TCN_BOUND_NOTE",
    "STAGE2_TCN_PARAMETERS",
    "ExpressibilityResult",
    "check_expressibility",
    "deterministic_scorer_genome",
    "deterministic_scorer_specs",
    "hand_designed_genomes",
    "order_free_control_genome",
    "phi_oracle_genome",
    "phi_oracle_raw_genome",
    "rank_identical",
    "reduced_tcn_genome",
    "reduced_tcn_reference",
]

#: "Exact" means every session's score is within this of the reference.
EXACT_TOLERANCE = 1e-12

#: The reduced TCN reads at most this many feature slots (spec §4.2).
REDUCED_TCN_MAX_FEATURES = 4

#: A fixed, hand-chosen probe for the reduced-TCN exactness row. It is NOT trained and
#: carries no quality claim: the row tests that the genome computes what its reference
#: computes, for weights that exercise every term (non-zero taps, a bias that makes ReLU
#: clip, a signed readout). Layout: see :func:`reduced_tcn_genome`.
REDUCED_TCN_DEFAULT_FEATURES: tuple[int, ...] = (73, 83, 85, 90)
REDUCED_TCN_DEFAULT_WEIGHTS: tuple[float, ...] = (
    0.9, -0.4, 0.3, 0.2,  # pointwise projection, one per feature
    0.5, 0.3, -0.2,  # temporal taps: t, t-1, t-2
    -0.05,  # conv bias
    1.5, 0.1,  # readout scale and offset
)  # fmt: skip

#: Stage 2's TCN (``stage2/research/baselines.py`` ``TCNBaseline``, ``hidden=24`` in
#: ``stage2_report.py``, width = ``FEATURE_WIDTH``): conv ``kernel*width x hidden`` +
#: bias ``hidden`` + readout ``hidden`` + readout bias 1.
STAGE2_TCN_PARAMETERS = 3 * FEATURE_WIDTH * 24 + 24 + 24 + 1

STAGE2_TCN_BOUND_NOTE: str = (
    f"NOT a measurement: arithmetic from constants. The full Stage 2 TCN (kernel 3, "
    f"width {FEATURE_WIDTH}, hidden 24) has 3*{FEATURE_WIDTH}*24 + 24 + 24 + 1 = "
    f"{STAGE2_TCN_PARAMETERS} weights, each of which would be a CONST node; the IR caps a "
    f"program at MAX_CONSTANTS={MAX_CONSTANTS} constants and MAX_PROGRAM_NODES="
    f"{MAX_PROGRAM_NODES} nodes, so it is not expressible within bounds. It also pools "
    "over the whole session, whereas a genome's state is per actor_slot lineage. The "
    "operator family is expressible (see reduced-tcn); the Stage 2 instance is not."
)


@dataclass(frozen=True, slots=True)
class ExpressibilityResult:
    """One target's verdict. ``None`` fields mean "not measured", never "fine"."""

    target: str
    expressible: bool
    #: Scores equal the reference within 1e-12 on every session.
    exact: bool | None
    rank_identical: bool | None
    sessions: int
    max_abs_error: float | None
    genome_digest: str | None
    #: Non-empty when not expressible or not exact.
    reason: str


# --- node builders -----------------------------------------------------------


def _reg(index: int, value_type: IRType = IRType.FLOAT, lag: int = 0) -> IRNode:
    return IRNode(kind=NodeKind.REG, type=value_type, index=index, lag=lag)


def _input(source: InputSource, value_type: IRType, index: int = 0) -> IRNode:
    return IRNode(kind=NodeKind.INPUT, type=value_type, source=source, index=index)


def _feature(index: int) -> IRNode:
    return _input(InputSource.FEATURE, IRType.FLOAT, index)


def _const(value: float) -> IRNode:
    return IRNode(kind=NodeKind.CONST, type=IRType.FLOAT, value=float(value))


def _apply(primitive: str, value_type: IRType, *args: int) -> IRNode:
    return IRNode(kind=NodeKind.APPLY, type=value_type, primitive=primitive, args=args)


def _update(nodes: Sequence[IRNode], outputs: Sequence[int]) -> IRProgram:
    return IRProgram(phase=ProgramPhase.UPDATE, nodes=tuple(nodes), outputs=tuple(outputs))


def _readout(nodes: Sequence[IRNode]) -> IRProgram:
    return IRProgram(phase=ProgramPhase.READOUT, nodes=tuple(nodes), outputs=(len(nodes) - 1,))


_FLOAT_REGISTER = RegisterSpec(type=IRType.FLOAT)
_READ_R0 = _readout((_reg(0),))


# --- the incumbents as genomes -----------------------------------------------


def phi_oracle_genome() -> ComputationalGenomeV1:
    """Stage 2's Φ-oracle: per-lineage ``max(features[73])``, MAX over lineages.

    Update ``(REG r0, INPUT FEATURE[73], APPLY MAX(0, 1))`` is the canonical node order
    ``search.enumerate_exhaustive`` also uses, so the two produce the same digest. Session
    MAX of per-lineage MAX is the session max, which is what the oracle scores.
    """
    update = _update(
        (_reg(0), _feature(PHI_SQUASHED_FEATURE_INDEX), _apply("MAX", IRType.FLOAT, 0, 1)),
        (2,),
    )
    return build_genome(
        registers=(_FLOAT_REGISTER,),
        update=update,
        readout=_READ_R0,
        aggregation=SessionAggregation.MAX,
    )


def phi_oracle_raw_genome() -> ComputationalGenomeV1:
    """The same oracle from raw ΔΦ: ``r0' = MAX(r0, ABS(DELTA_PHI))``, readout
    ``DIV(r0, ADD(r0, 8.0))``. The squash is monotone, so max-then-squash equals
    squash-then-max; this is the row that needs ``DIV`` (M0.4)."""
    update = _update(
        (
            _reg(0),
            _input(InputSource.DELTA_PHI, IRType.FLOAT),
            _apply("ABS", IRType.FLOAT, 1),
            _apply("MAX", IRType.FLOAT, 0, 2),
        ),
        (3,),
    )
    readout = _readout(
        (
            _reg(0),
            _const(8.0),
            _apply("ADD", IRType.FLOAT, 0, 1),
            _apply("DIV", IRType.FLOAT, 0, 2),
        )
    )
    return build_genome(
        registers=(_FLOAT_REGISTER,),
        update=update,
        readout=readout,
        aggregation=SessionAggregation.MAX,
    )


def deterministic_scorer_genome(spec: DeterministicScorerSpec) -> ComputationalGenomeV1:
    """A Stage 2 ``DeterministicScorerSpec`` as a genome, MAX over lineages.

    ``max_over_window`` -> a MAX register; ``mean_over_window`` -> SUM and COUNT
    registers, readout DIV; ``last_in_window`` -> a register overwritten each event.
    """
    feature = _feature(spec.feature_index)
    if spec.aggregation == "max_over_window":
        update = _update((_reg(0), feature, _apply("MAX", IRType.FLOAT, 0, 1)), (2,))
        registers: tuple[RegisterSpec, ...] = (_FLOAT_REGISTER,)
        readout = _READ_R0
    elif spec.aggregation == "mean_over_window":
        update = _update(
            (
                _reg(0),
                feature,
                _apply("ADD", IRType.FLOAT, 0, 1),
                _reg(1),
                _const(1.0),
                _apply("ADD", IRType.FLOAT, 3, 4),
            ),
            (2, 5),
        )
        registers = (_FLOAT_REGISTER, _FLOAT_REGISTER)
        readout = _readout((_reg(0), _reg(1), _apply("DIV", IRType.FLOAT, 0, 1)))
    elif spec.aggregation == "last_in_window":
        update = _update((feature,), (0,))
        registers = (_FLOAT_REGISTER,)
        readout = _READ_R0
    else:  # DeterministicScorerSpec already refuses this; kept so a new one fails loudly
        raise ContractError(f"no genome form for aggregation {spec.aggregation!r}")
    return build_genome(
        registers=registers, update=update, readout=readout, aggregation=SessionAggregation.MAX
    )


def deterministic_scorer_specs() -> tuple[DeterministicScorerSpec, ...]:
    """All ``FEATURE_WIDTH x len(AGGREGATIONS)`` Stage 2 deterministic scorers, sorted."""
    return tuple(
        DeterministicScorerSpec(
            scorer_id=f"s9-expr-{feature}-{aggregation}",
            feature_index=feature,
            aggregation=aggregation,
            threshold=None,
            expression=f"{aggregation} of features[{feature}]",
        )
        for feature in range(FEATURE_WIDTH)
        for aggregation in sorted(AGGREGATIONS)
    )


def order_free_control_genome() -> ComputationalGenomeV1:
    """SUM over lineages of per-lineage sums of ``POPCOUNT(STATE_DELTA_MASK)``.

    It ignores both event order and which lineage acted: the saturation control. If it
    ties the best genome on a split, that split cannot rank attribution-aware mechanisms.
    """
    update = _update(
        (
            _reg(0),
            _input(InputSource.STATE_DELTA_MASK, IRType.INT),
            _apply("POPCOUNT", IRType.FLOAT, 1),
            _apply("ADD", IRType.FLOAT, 0, 2),
        ),
        (3,),
    )
    return build_genome(
        registers=(_FLOAT_REGISTER,),
        update=update,
        readout=_READ_R0,
        aggregation=SessionAggregation.SUM,
    )


def _h1_genome() -> ComputationalGenomeV1:
    update = _update(
        (
            _reg(0),
            _input(InputSource.DELTA_PHI, IRType.FLOAT),
            _const(0.0),
            _apply("MAX", IRType.FLOAT, 1, 2),
            _apply("ADD", IRType.FLOAT, 0, 3),
        ),
        (4,),
    )
    return build_genome(
        registers=(_FLOAT_REGISTER,),
        update=update,
        readout=_READ_R0,
        aggregation=SessionAggregation.MAX,
    )


def _h2_genome() -> ComputationalGenomeV1:
    update = _update(
        (
            _reg(0, IRType.INT),
            _input(InputSource.STATE_DELTA_MASK, IRType.INT),
            _apply("OR", IRType.INT, 0, 1),
        ),
        (2,),
    )
    readout = _readout((_reg(0, IRType.INT), _apply("POPCOUNT", IRType.FLOAT, 0)))
    return build_genome(
        registers=(RegisterSpec(type=IRType.INT),),
        update=update,
        readout=readout,
        aggregation=SessionAggregation.MAX,
    )


def hand_designed_genomes() -> Mapping[str, ComputationalGenomeV1]:
    """H1: per-lineage Σ max(ΔΦ, 0), MAX. H2: per-lineage popcount(OR of the state-delta
    mask), MAX, in the exhaustive space's canonical order so H2 is in it by digest."""
    return MappingProxyType({"H1": _h1_genome(), "H2": _h2_genome()})


# --- the reduced TCN ---------------------------------------------------------


def _check_tcn_arguments(
    weights: Sequence[float], features: Sequence[int]
) -> tuple[tuple[float, ...], tuple[int, ...]]:
    feature_tuple = tuple(features)
    if not 1 <= len(feature_tuple) <= REDUCED_TCN_MAX_FEATURES:
        raise ContractError(
            f"the reduced TCN reads 1..{REDUCED_TCN_MAX_FEATURES} features, "
            f"got {len(feature_tuple)}"
        )
    for feature in feature_tuple:
        if isinstance(feature, bool) or not isinstance(feature, int):
            raise ContractError(f"feature indices must be ints, got {feature!r}")
        if not 0 <= feature < FEATURE_WIDTH:
            raise ContractError(f"feature index {feature} outside [0, {FEATURE_WIDTH})")
    weight_tuple = tuple(float(weight) for weight in weights)
    if len(weight_tuple) != len(feature_tuple) + 6:
        raise ContractError(
            f"the reduced TCN takes len(features) + 6 = {len(feature_tuple) + 6} weights, "
            f"got {len(weight_tuple)}"
        )
    if not all(math.isfinite(weight) for weight in weight_tuple):
        raise ContractError("reduced TCN weights must be finite")
    return weight_tuple, feature_tuple


def _tcn_update(weights: tuple[float, ...], features: tuple[int, ...]) -> IRProgram:
    nodes: list[IRNode] = []

    def add(node: IRNode) -> int:
        nodes.append(node)
        return len(nodes) - 1

    width = len(features)
    projection = -1
    for position, feature in enumerate(features):
        x = add(_feature(feature))
        term = add(_apply("MUL", IRType.FLOAT, add(_const(weights[position])), x))
        projection = term if projection < 0 else add(_apply("ADD", IRType.FLOAT, projection, term))
    taps = (projection, add(_reg(0, lag=0)), add(_reg(0, lag=1)))
    total = -1
    for tap_index, source in enumerate(taps):
        term = add(_apply("MUL", IRType.FLOAT, add(_const(weights[width + tap_index])), source))
        total = term if total < 0 else add(_apply("ADD", IRType.FLOAT, total, term))
    biased = add(_apply("ADD", IRType.FLOAT, total, add(_const(weights[width + 3]))))
    relu = add(_apply("MAX", IRType.FLOAT, biased, add(_const(0.0))))
    pooled = add(_apply("MAX", IRType.FLOAT, add(_reg(1)), relu))
    return _update(nodes, (projection, pooled))


def reduced_tcn_genome(weights: Sequence[float], features: Sequence[int]) -> ComputationalGenomeV1:
    """One channel, <= 4 input features, kernel 3, ReLU, max-over-time, linear readout.

    ``weights`` = ``[v_0..v_{F-1}, k_0, k_1, k_2, b, a, c]``: the pointwise projection
    ``z_t = Σ v_i x_{t,i}`` is written into a RING(3) register ``r0``, so ``z_{t-1}`` and
    ``z_{t-2}`` are ``REG r0 lag 0`` and ``lag 1``; ``h_t = ReLU(k_0 z_t + k_1 z_{t-1} +
    k_2 z_{t-2} + b)`` = ``MAX(x, 0)``; ``r1`` keeps ``max_t h_t``; the readout is
    ``a * r1 + c``. Zero initial ring values are the causal zero padding. State is per
    ``actor_slot`` lineage and lineages are combined by MAX (see the bound note).
    """
    weight_tuple, feature_tuple = _check_tcn_arguments(weights, features)
    width = len(feature_tuple)
    readout = _readout(
        (
            _reg(1),
            _const(weight_tuple[width + 4]),
            _apply("MUL", IRType.FLOAT, 1, 0),
            _const(weight_tuple[width + 5]),
            _apply("ADD", IRType.FLOAT, 2, 3),
        )
    )
    return build_genome(
        registers=(RegisterSpec(type=IRType.FLOAT, ring=3), _FLOAT_REGISTER),
        update=_tcn_update(weight_tuple, feature_tuple),
        readout=readout,
        aggregation=SessionAggregation.MAX,
    )


def _tcn_lineage_score(
    steps: Sequence[Any], weights: tuple[float, ...], features: tuple[int, ...]
) -> float:
    width = len(features)
    previous, before_previous, pooled = 0.0, 0.0, 0.0
    for step in steps:
        projection = weights[0] * step.features[features[0]]
        for position in range(1, width):
            projection = projection + weights[position] * step.features[features[position]]
        total = weights[width] * projection + weights[width + 1] * previous
        total = total + weights[width + 2] * before_previous
        activation = max(total + weights[width + 3], 0.0)
        pooled = max(pooled, activation)
        previous, before_previous = projection, previous
    return weights[width + 4] * pooled + weights[width + 5]


def reduced_tcn_reference(
    sample: Stage2Sample, weights: Sequence[float], features: Sequence[int]
) -> float:
    """Plain-Python reference for :func:`reduced_tcn_genome`, in the same operation order.

    It groups steps by ``actor_slot`` and never evicts, so it is the genome's semantics
    only for sessions with at most ``MAX_LINEAGES`` lineages; the check reports how many
    sessions exceed that.
    """
    weight_tuple, feature_tuple = _check_tcn_arguments(weights, features)
    lineages = _by_lineage(sample)
    if not lineages:
        raise ContractError(f"sample {sample.sample_id} has no steps")
    return max(_tcn_lineage_score(steps, weight_tuple, feature_tuple) for steps in lineages)


# --- references and comparison -----------------------------------------------


def _by_lineage(sample: Stage2Sample) -> list[list[Any]]:
    """Steps grouped by ``actor_slot``, groups in first-appearance order."""
    groups: dict[int, list[Any]] = {}
    for step in sample.steps:
        groups.setdefault(step.actor_slot, []).append(step)
    return list(groups.values())


def _popcount(mask: int) -> float:
    return float(bin(mask & 0xFFFFFFFFFFFFFFFF).count("1"))


def _h1_reference(sample: Stage2Sample) -> float:
    totals = []
    for steps in _by_lineage(sample):
        total = 0.0
        for step in steps:
            total = total + max(step.delta_phi, 0.0)
        totals.append(total)
    return max(totals)


def _h2_reference(sample: Stage2Sample) -> float:
    masks = []
    for steps in _by_lineage(sample):
        mask = 0
        for step in steps:
            mask |= step.state_delta_mask
        masks.append(_popcount(mask))
    return max(masks)


def _order_free_reference(sample: Stage2Sample) -> float:
    total = 0.0
    for steps in _by_lineage(sample):
        lineage_total = 0.0
        for step in steps:
            lineage_total = lineage_total + _popcount(step.state_delta_mask)
        total = total + lineage_total
    return total


def _session_max(feature: int) -> Callable[[Stage2Sample], float]:
    return lambda sample: max(step.features[feature] for step in sample.steps)


def rank_identical(a: Sequence[float], b: Sequence[float]) -> bool:
    """True iff every pair of sessions is ordered (and tied) the same way by ``a`` and ``b``."""
    if len(a) != len(b):
        return False
    order = sorted(range(len(a)), key=lambda i: (b[i], a[i]))
    for left, right in pairwise(order):
        if (b[left] == b[right]) != (a[left] == a[right]) or a[left] > a[right]:
            return False
    return True


@dataclass(frozen=True, slots=True)
class _Comparison:
    exact: bool
    rank_identical: bool
    max_abs_error: float
    first_mismatch: str


def _compare(
    scores: Sequence[float | None], reference: Sequence[float], samples: Sequence[Stage2Sample]
) -> _Comparison:
    """Compare a genome's session scores with a reference; an abstention is a mismatch."""
    errors = [
        math.inf if score is None else abs(score - expected)
        for score, expected in zip(scores, reference, strict=True)
    ]
    worst = max(errors, default=0.0)
    mismatch = next((i for i, error in enumerate(errors) if error > EXACT_TOLERANCE), None)
    first = "" if mismatch is None else samples[mismatch].sample_id
    usable = all(score is not None for score in scores)
    ranked = usable and rank_identical([float(s) for s in scores if s is not None], reference)
    return _Comparison(worst <= EXACT_TOLERANCE, ranked, worst, first)


def _genome_scores(
    genome: ComputationalGenomeV1, dataset: Stage2Dataset
) -> tuple[float | None, ...]:
    return tuple(run.score for run in genome.phenotype().run_dataset(dataset))


def _result(
    target: str,
    genome: ComputationalGenomeV1,
    scores: Sequence[float | None],
    references: Sequence[tuple[str, Sequence[float] | None]],
    samples: Sequence[Stage2Sample],
) -> ExpressibilityResult:
    """Combine one or more references; a missing reference makes ``exact`` unmeasured."""
    comparisons = [
        (name, None if reference is None else _compare(scores, reference, samples))
        for name, reference in references
    ]
    missing = [name for name, comparison in comparisons if comparison is None]
    measured = [(name, c) for name, c in comparisons if c is not None]
    reasons = [f"reference {name} unmeasured (needs SSIR sessions)" for name in missing]
    reasons += [
        f"{name}: max |error| {c.max_abs_error:.3g}, first mismatch {c.first_mismatch}"
        for name, c in measured
        if not c.exact
    ]
    all_exact = all(c.exact for _, c in measured)
    all_ranked = all(c.rank_identical for _, c in measured)
    return ExpressibilityResult(
        target=target,
        expressible=True,
        exact=None if missing and all_exact else all_exact,
        rank_identical=None if missing and all_ranked else all_ranked,
        sessions=len(samples),
        max_abs_error=max((c.max_abs_error for _, c in measured), default=None),
        genome_digest=genome.digest,
        reason="; ".join(reasons),
    )


def _window_rows(
    sessions: Sequence[Sequence[Any]] | None, samples: Sequence[Stage2Sample]
) -> list[tuple[Any, ...]] | None:
    """Stage 2's lineage windows per session, or ``None`` when no SSIR was supplied."""
    if sessions is None:
        return None
    if len(sessions) != len(samples):
        raise ContractError(
            f"{len(sessions)} SSIR sessions for {len(samples)} samples: not index-aligned"
        )
    for session, sample in zip(sessions, samples, strict=True):
        if len(session) != len(sample.steps):
            raise ContractError(f"session for {sample.sample_id} has a different length")
    return [lineage_windows(session) for session in sessions]


def _window_reference(
    spec: DeterministicScorerSpec, windows: list[tuple[Any, ...]] | None
) -> list[float] | None:
    if windows is None:
        return None
    return [max(spec.evaluate(window) for window in session) for session in windows]


def _phi_rows(
    dataset: Stage2Dataset, windows: list[tuple[Any, ...]] | None
) -> list[ExpressibilityResult]:
    samples = dataset.samples
    references: list[tuple[str, Sequence[float] | None]] = [
        ("max(features[73]) per session",
         [_session_max(PHI_SQUASHED_FEATURE_INDEX)(s) for s in samples]),
        ("PHI_ORACLE_SCORER over lineage_windows", _window_reference(PHI_ORACLE_SCORER, windows)),
    ]  # fmt: skip
    rows = []
    for target, genome in (
        ("phi-oracle-squashed", phi_oracle_genome()),
        ("phi-oracle-raw", phi_oracle_raw_genome()),
    ):
        rows.append(_result(target, genome, _genome_scores(genome, dataset), references, samples))
    return rows


def _scorer_rows(
    dataset: Stage2Dataset, windows: list[tuple[Any, ...]] | None
) -> list[ExpressibilityResult]:
    rows = []
    for spec in deterministic_scorer_specs():
        genome = deterministic_scorer_genome(spec)
        result = _result(
            f"deterministic-scorer/{spec.feature_index}/{spec.aggregation}",
            genome,
            _genome_scores(genome, dataset),
            (("DeterministicScorerSpec over lineage_windows", _window_reference(spec, windows)),),
            dataset.samples,
        )
        if result.exact is False and spec.aggregation != "max_over_window":
            result = _annotate(result, "Stage 2 windows are causal-root lineages capped at "
                               "MAX_WINDOW; genome lineages are actor_slot")  # fmt: skip
        rows.append(result)
    return rows


def _annotate(result: ExpressibilityResult, note: str) -> ExpressibilityResult:
    return ExpressibilityResult(
        target=result.target,
        expressible=result.expressible,
        exact=result.exact,
        rank_identical=result.rank_identical,
        sessions=result.sessions,
        max_abs_error=result.max_abs_error,
        genome_digest=result.genome_digest,
        reason=f"{result.reason}; {note}" if result.reason else note,
    )


def _plain_rows(dataset: Stage2Dataset) -> list[ExpressibilityResult]:
    samples = dataset.samples
    crowded = sum(1 for s in samples if len({step.actor_slot for step in s.steps}) > MAX_LINEAGES)
    hand = hand_designed_genomes()
    tcn = reduced_tcn_genome(REDUCED_TCN_DEFAULT_WEIGHTS, REDUCED_TCN_DEFAULT_FEATURES)
    cases: tuple[tuple[str, ComputationalGenomeV1, Callable[[Stage2Sample], float]], ...] = (
        ("reduced-tcn", tcn, lambda s: reduced_tcn_reference(
            s, REDUCED_TCN_DEFAULT_WEIGHTS, REDUCED_TCN_DEFAULT_FEATURES)),
        ("order-free-control", order_free_control_genome(), _order_free_reference),
        ("H1", hand["H1"], _h1_reference),
        ("H2", hand["H2"], _h2_reference),
    )  # fmt: skip
    rows = []
    for target, genome, reference in cases:
        result = _result(
            target,
            genome,
            _genome_scores(genome, dataset),
            (("plain-Python per-actor_slot reference", [reference(s) for s in samples]),),
            samples,
        )
        if crowded and result.exact is False:
            result = _annotate(result, f"{crowded} sessions exceed MAX_LINEAGES={MAX_LINEAGES}")
        rows.append(result)
    return rows


def check_expressibility(
    dataset: Stage2Dataset, *, sessions: Sequence[Sequence[Any]] | None = None
) -> tuple[ExpressibilityResult, ...]:
    """Run every expressibility target over ``dataset``.

    ``sessions`` are the SSIR sessions ``dataset`` was encoded from, index-aligned (a
    ``stage2.gate_measures.CompiledSplit`` gives both, as ``.dataset`` and ``.sessions``).
    They are needed for every reference defined over Stage 2's ``lineage_windows``;
    without them those references are reported unmeasured and the affected rows have
    ``exact=None`` - never ``True``.
    """
    if not dataset.samples:
        raise ContractError("check_expressibility needs a non-empty dataset")
    windows = _window_rows(sessions, dataset.samples)
    rows = _phi_rows(dataset, windows) + _scorer_rows(dataset, windows) + _plain_rows(dataset)
    rows.append(
        ExpressibilityResult(
            target="stage2-tcn-full",
            expressible=False,
            exact=None,
            rank_identical=None,
            sessions=len(dataset.samples),
            max_abs_error=None,
            genome_digest=None,
            reason=STAGE2_TCN_BOUND_NOTE,
        )
    )
    return tuple(rows)
