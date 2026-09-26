"""D9.9 (ONTO-F09) — Minimum Security Description Length and predictive-compression surprise.

Architecture §22 proposes selecting a security program by one scalar,
``MSDL(P, E) = L(P) + L(E|P) + λ_rt·Runtime + λ_fp·FalsePositives + λ_adv·Fragility``: the
bits to state the theory, the bits the evidence still costs given it, and priced penalties.
§23-§24 propose *surprise* — how badly a model of normal behaviour compresses a session —
as a detector. Both are attractive and both are exactly the kind of mechanism this project
has learned to distrust until measured (lesson 4, ADR-0010), so each is compared with the
simple thing it would replace:

* **MSDL selection** vs the **Pareto choice** the search already makes (max train
  worst-case AP within the WU cap). The spec makes cost an objective, never a weighted sum
  (ADR-0083); MSDL is that weighted sum, so it exists here only as a measured alternative.
* **Surprise** (zlib with a benign dictionary, S9X-046; a smoothed per-lineage bigram code,
  S9X-047) vs the Stage 1 novelty peak and the Φ-oracle.

``L(E|P)`` is the code length of the train labels under a 1-D logistic on the genome's score,
fitted by :data:`LOGISTIC_STEPS` deterministic gradient steps in plain Python — no numpy
(ADR-0080), no randomness. Kolmogorov complexity is not claimed to be measured; zlib is a
computable proxy and nothing more.

What this module refuses to do. It never fits on held-out data; it records the true number
of candidates MSDL was computed for (bounded by :data:`MSDL_MAX_CANDIDATES`); and when the
train split is not supplied it returns UNMEASURED rather than fitting the logistic on the
split it is judged on. Both flags ship ``False``.
"""

from __future__ import annotations

import math
import statistics
import zlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from pocketsec.stage1.ssir.relations import RelationFamily
from pocketsec.stage2.dataset import Stage2Dataset, Stage2Sample
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage9.genome.computational import ComputationalGenomeV1
from pocketsec.stage9.ontogenesis.fitness import (
    EvaluationSuite,
    FitnessRecord,
    evaluate,
    session_scores,
)
from pocketsec.stage9.renormalization.laboratory import (
    ScoredDetector,
    compare_detectors,
    decide,
    fpr_threshold,
    phi_oracle_scores,
    ranked_ap,
    unmeasured_comparison,
    verdict_against,
)
from pocketsec.stage9.spec.mssc import DEFAULT_CONSTRAINTS, DetectorComparison, MechanismVerdict
from pocketsec.stage9.symmetry.suite import novelty_peak_scores

if TYPE_CHECKING:  # pragma: no cover - typing only; search is a sibling package
    from pocketsec.stage9.ontogenesis.search import SearchRun

__all__ = [
    "LAMBDA_ADV",
    "LAMBDA_FP",
    "LAMBDA_RUNTIME",
    "LOGISTIC_STEPS",
    "MSDL_MAX_CANDIDATES",
    "MSDL_SELECTION_DEFAULT_ENABLED",
    "SURPRISE_DEFAULT_ENABLED",
    "WU_SAVING_MIN",
    "ZDICT_MAX_BYTES",
    "MSDLScore",
    "build_bigrams",
    "build_zdict",
    "compare_msdl_selection",
    "compare_surprise",
    "compressor_surprise",
    "fit_logistic",
    "msdl",
    "nuisance_leakage",
    "probabilistic_surprise",
    "session_tokens",
]

#: Off until a measured JUSTIFIED verdict is cited in the findings and its ADR (spec §4.22).
MSDL_SELECTION_DEFAULT_ENABLED: bool = False
SURPRISE_DEFAULT_ENABLED: bool = False
#: Bits charged per unit of each penalty (spec §4.13). Chosen, not fitted.
LAMBDA_RUNTIME = 1.0
LAMBDA_FP = 8.0
LAMBDA_ADV = 100.0
#: The benign zlib dictionary never exceeds this (zlib's own window is 32 KiB).
ZDICT_MAX_BYTES = 32768
#: Deterministic gradient steps for the 1-D logistic (spec §4.13).
LOGISTIC_STEPS = 200
_LOGISTIC_RATE = 0.5
_PROBABILITY_FLOOR = 1e-12
#: MSDL is computed for at most this many candidates per run (train worst-case AP order).
MSDL_MAX_CANDIDATES = 64
#: "Equal AP at >= 10% less WU" also justifies MSDL selection (spec §7). Chosen.
WU_SAVING_MIN = 0.10
#: "Equal AP" allows binary rounding only, not a quality loss.
_EQUAL_AP_TOLERANCE = 1e-9
_FAMILIES = len(RelationFamily)


@dataclass(frozen=True, slots=True)
class MSDLScore:
    """Every MSDL term for one genome, in bits; ``total`` is ``None`` if any term is."""

    genome_digest: str
    program_bits: float
    residual_bits: float | None
    runtime_term: float
    fp_term: float | None
    adversarial_term: float | None
    total: float | None


def _sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    e = math.exp(x)
    return e / (1.0 + e)


def fit_logistic(
    scores: Sequence[float], labels: Sequence[int], *, steps: int = LOGISTIC_STEPS
) -> tuple[float, float, float, float]:
    """``(a, b, mean, scale)`` of ``p = sigmoid(a*(s-mean)/scale + b)`` by full-batch descent.

    Standardising first makes one fixed learning rate work for any score range; starting at
    zero and iterating a fixed number of times makes the fit bit-identical run to run.
    """
    if len(scores) != len(labels) or not scores:
        raise ValueError("fit_logistic needs aligned, non-empty scores and labels")
    mean = sum(scores) / len(scores)
    scale = statistics.pstdev(scores) or 1.0
    z = [(s - mean) / scale for s in scores]
    a = b = 0.0
    for _ in range(steps):
        grad_a = grad_b = 0.0
        for zi, yi in zip(z, labels, strict=True):
            error = _sigmoid(a * zi + b) - yi
            grad_a += error * zi
            grad_b += error
        a -= _LOGISTIC_RATE * grad_a / len(z)
        b -= _LOGISTIC_RATE * grad_b / len(z)
    return a, b, mean, scale


def _residual_bits(scores: Sequence[float], labels: Sequence[int]) -> float:
    a, b, mean, scale = fit_logistic(scores, labels)
    bits = 0.0
    for score, label in zip(scores, labels, strict=True):
        p = _sigmoid(a * (score - mean) / scale + b)
        p = min(max(p if label == 1 else 1.0 - p, _PROBABILITY_FLOOR), 1.0)
        bits -= math.log2(p)
    return bits


def msdl(genome: ComputationalGenomeV1, fitness: FitnessRecord, train: Stage2Dataset) -> MSDLScore:
    """``L(P) + L(E|P) + λ_rt·WU/event + λ_fp·FP + λ_adv·(clean - worst-case AP)``, on train.

    ``FP`` counts train benign sessions above the FPR-0.05 threshold fitted on those same
    train benign scores. An empty train split leaves the residual and FP terms ``None``.
    """
    scores = tuple(0.0 if s is None else float(s) for s in session_scores(genome, train))
    labels = train.labels
    residual = _residual_bits(scores, labels) if scores else None
    benign = [s for s, lab in zip(scores, labels, strict=True) if lab == 0]
    threshold = fpr_threshold(benign)
    fp_term = None if threshold is None else LAMBDA_FP * sum(decide(benign, threshold))
    fragile = (
        None if fitness.clean_ap is None or fitness.worst_case_ap is None
        else max(0.0, fitness.clean_ap - fitness.worst_case_ap)
    )
    adversarial = None if fragile is None else LAMBDA_ADV * fragile
    program = genome.description_length_bits()
    runtime = LAMBDA_RUNTIME * fitness.wu_per_event
    parts = (residual, fp_term, adversarial)
    total = (
        None if any(p is None for p in parts) else program + runtime + sum(p or 0.0 for p in parts)
    )
    return MSDLScore(
        genome_digest=genome.digest, program_bits=program, residual_bits=residual,
        runtime_term=runtime, fp_term=fp_term, adversarial_term=adversarial, total=total,
    )


def _candidates(run: SearchRun) -> list[tuple[ComputationalGenomeV1, FitnessRecord]]:
    """Genomes within the WU cap with a measured worst case, best first (the Pareto order)."""
    cap = DEFAULT_CONSTRAINTS.wu_per_event_max
    pool = [
        (genome, record)
        for genome, record in zip(run.genomes, run.records, strict=True)
        if record.worst_case_ap is not None and record.wu_per_event <= cap
    ]
    pool.sort(key=lambda p: (-(p[1].worst_case_ap or 0.0), p[1].wu_per_event, p[1].state_bytes,
                             p[1].genome_digest))
    return pool[:MSDL_MAX_CANDIDATES]


@dataclass(frozen=True, slots=True)
class _Choice:
    pareto_digest: str
    msdl_digest: str
    pareto_ap: float | None
    msdl_ap: float | None
    pareto_wu: int
    msdl_wu: int


def _heldout_worst(
    genome: ComputationalGenomeV1, heldout: EvaluationSuite, memo: dict[str, float | None]
) -> float | None:
    if genome.digest not in memo:
        memo[genome.digest] = evaluate(genome, heldout, meter=WorkMeter()).worst_case_ap
    return memo[genome.digest]


def _choose(
    run: SearchRun, train: Stage2Dataset, heldout: EvaluationSuite, memo: dict[str, float | None]
) -> _Choice | None:
    pool = _candidates(run)
    scored = [(msdl(g, r, train).total, g, r) for g, r in pool]
    ranked = [(total, g, r) for total, g, r in scored if total is not None]
    if not pool or not ranked:
        return None
    pareto_genome, pareto_record = pool[0]
    _, msdl_genome, msdl_record = min(ranked, key=lambda t: (t[0], t[2].genome_digest))
    return _Choice(
        pareto_digest=pareto_genome.digest, msdl_digest=msdl_genome.digest,
        pareto_ap=_heldout_worst(pareto_genome, heldout, memo),
        msdl_ap=_heldout_worst(msdl_genome, heldout, memo),
        pareto_wu=pareto_record.wu_per_event, msdl_wu=msdl_record.wu_per_event,
    )


def _msdl_verdict(
    choices: Sequence[_Choice],
) -> tuple[MechanismVerdict, float | None, float | None, str]:
    msdl_aps = [c.msdl_ap for c in choices if c.msdl_ap is not None]
    pareto_aps = [c.pareto_ap for c in choices if c.pareto_ap is not None]
    if len(msdl_aps) != len(choices) or len(pareto_aps) != len(choices):
        return MechanismVerdict.UNMEASURED, None, None, "a chosen genome has no held-out AP"
    value, control = statistics.median(msdl_aps), statistics.median(pareto_aps)
    wu_msdl = statistics.median(c.msdl_wu for c in choices)
    wu_pareto = statistics.median(c.pareto_wu for c in choices)
    verdict, text = verdict_against(value, (("pareto-choice", control),))
    text = f"{text}; median WU/event {wu_msdl} vs {wu_pareto}"
    # The second route (spec §7): no AP lost, and at least 10% cheaper per event.
    if (
        verdict is not MechanismVerdict.JUSTIFIED
        and value >= control - _EQUAL_AP_TOLERANCE
        and wu_msdl <= (1.0 - WU_SAVING_MIN) * wu_pareto
    ):
        verdict = MechanismVerdict.JUSTIFIED
    return verdict, value, control, text


def compare_msdl_selection(
    runs: Sequence[SearchRun],
    heldout: EvaluationSuite,
    *,
    train: Stage2Dataset | None = None,
) -> DetectorComparison:
    """Per run, the MSDL argmin vs the Pareto choice, both scored on held-out worst-case AP.

    JUSTIFIED iff MSDL's median is ``>= +0.02`` over Pareto's, or equal at ``>= 10%`` less
    WU/event. ``fired`` = runs where MSDL chose a different genome. ``train`` (the split the
    search fitted on, clean) is required for ``L(E|P)``; without it the result is UNMEASURED.
    """
    mechanism = f"{__name__}:MSDL_SELECTION_DEFAULT_ENABLED"
    metric = "median heldout worst_case_ap of the chosen genome"
    if train is None:
        return unmeasured_comparison(
            mechanism, metric, ("pareto-choice",),
            "MSDL's residual term needs the train split; pass train=",
        )
    memo: dict[str, float | None] = {}
    choices = [c for run in runs if (c := _choose(run, train, heldout, memo)) is not None]
    if not choices:
        return unmeasured_comparison(
            mechanism, metric, ("pareto-choice",), "no run has a candidate within the WU cap"
        )
    verdict, value, control, text = _msdl_verdict(choices)
    fired = sum(1 for c in choices if c.msdl_digest != c.pareto_digest)
    if verdict is MechanismVerdict.JUSTIFIED and fired == 0:
        verdict = MechanismVerdict.NOT_YET_JUSTIFIED
    return DetectorComparison(
        mechanism=mechanism, metric=metric, value=value, controls=(("pareto-choice", control),),
        verdict=verdict, fired=fired,
        detail=f"{text}; {len(choices)}/{len(runs)} run(s) had candidates (<= "
        f"{MSDL_MAX_CANDIDATES} each); MSDL chose differently in {fired}."
        + (" INERT." if fired == 0 else ""),
    )


# --------------------------------------------------------------------------------------
# Surprise: algorithmic (zlib) and probabilistic (bigram code)
# --------------------------------------------------------------------------------------


def session_tokens(sample: Stage2Sample) -> bytes:
    """Five bytes per event: lineage slot, relation, family, state-delta mask (low, high).

    Evidence locators and identity never enter; ``actor_slot`` is a session-local key.
    """
    out = bytearray()
    for step in sample.steps:
        mask = step.state_delta_mask
        out += bytes((step.actor_slot & 0xFF, step.relation & 0xFF, step.relation_family & 0xFF,
                      mask & 0xFF, (mask >> 8) & 0xFF))
    return bytes(out)


def build_zdict(train_benign: Sequence[Stage2Sample]) -> bytes:
    """The most recent :data:`ZDICT_MAX_BYTES` of benign token streams (zlib favours the tail)."""
    buffer = bytearray()
    for sample in train_benign:
        buffer += session_tokens(sample)
        if len(buffer) > 2 * ZDICT_MAX_BYTES:
            del buffer[: len(buffer) - ZDICT_MAX_BYTES]
    return bytes(buffer[-ZDICT_MAX_BYTES:])


def compressor_surprise(sample: Stage2Sample, zdict: bytes) -> float:
    """Compressed bits per event of the session under zlib primed with the benign dictionary."""
    if len(zdict) > ZDICT_MAX_BYTES:
        raise ValueError(f"zdict of {len(zdict)} bytes exceeds {ZDICT_MAX_BYTES}")
    compressor = zlib.compressobj(9, zdict=zdict) if zdict else zlib.compressobj(9)
    payload = compressor.compress(session_tokens(sample)) + compressor.flush()
    return 8.0 * len(payload) / max(1, len(sample.steps))


def _lineage_bigrams(sample: Stage2Sample) -> list[tuple[int, int]]:
    """``(previous family, family)`` pairs within each lineage (predecessor = same actor)."""
    last: dict[int, int] = {}
    pairs = []
    for step in sample.steps:
        if step.actor_slot in last:
            pairs.append((last[step.actor_slot], step.relation_family))
        last[step.actor_slot] = step.relation_family
    return pairs


def build_bigrams(train_benign: Sequence[Stage2Sample]) -> dict[tuple[int, int], int]:
    """Counts of within-lineage family transitions over train benign sessions."""
    counts: dict[tuple[int, int], int] = {}
    for sample in train_benign:
        for pair in _lineage_bigrams(sample):
            counts[pair] = counts.get(pair, 0) + 1
    return counts


def probabilistic_surprise(sample: Stage2Sample, bigrams: Mapping[tuple[int, int], int]) -> float:
    """Mean ``-log2 P(family | previous family of the same lineage)``, Laplace-smoothed.

    A session with no within-lineage transition carries no evidence and scores 0.0.
    """
    rows: dict[int, int] = {}
    for (previous, _), count in bigrams.items():
        rows[previous] = rows.get(previous, 0) + count
    pairs = _lineage_bigrams(sample)
    if not pairs:
        return 0.0
    bits = sum(
        -math.log2((bigrams.get(pair, 0) + 1) / (rows.get(pair[0], 0) + _FAMILIES))
        for pair in pairs
    )
    return bits / len(pairs)


def nuisance_leakage(genome: ComputationalGenomeV1, dataset: Stage2Dataset) -> float | None:
    """AP of the genome's score for the nuisance "session longer than the median" (S9X-050).

    High leakage means the score partly measures session length. ``None`` when every session
    is on one side of the median (no nuisance label to predict).
    """
    if not dataset.samples:
        return None
    median = statistics.median(len(sample) for sample in dataset.samples)
    nuisance = tuple(1 if len(sample) > median else 0 for sample in dataset.samples)
    return ranked_ap(nuisance, session_scores(genome, dataset))


def compare_surprise(train: Stage2Dataset, heldout: Stage2Dataset) -> DetectorComparison:
    """The train-selected surprise (zlib or bigram) vs novelty peak and the Φ-oracle.

    JUSTIFIED iff its held-out AP ``>= max(controls) + 0.02``. No train benign session
    means no model of normal: UNMEASURED; nothing raises.
    """
    mechanism = f"{__name__}:SURPRISE_DEFAULT_ENABLED"
    metric = "heldout_ap(surprise)"
    names = ("novelty-peak", "phi-oracle")
    benign = [s for s in train.samples if s.label == 0]
    if not benign:
        return unmeasured_comparison(mechanism, metric, names, "no train benign session")
    zdict, bigrams = build_zdict(benign), build_bigrams(benign)
    arms: tuple[tuple[str, Callable[[Stage2Sample], float]], ...] = (
        ("compressor-surprise", lambda s: compressor_surprise(s, zdict)),
        ("probabilistic-surprise", lambda s: probabilistic_surprise(s, bigrams)),
    )
    scored = [
        ScoredDetector(
            name, tuple(fn(s) for s in heldout.samples), tuple(fn(s) for s in train.samples)
        )
        for name, fn in arms
    ]
    train_aps = [ranked_ap(train.labels, d.train_scores or ()) for d in scored]
    best = max(range(len(scored)), key=lambda i: (train_aps[i] is not None, train_aps[i] or 0.0))
    controls = (
        ScoredDetector(names[0], novelty_peak_scores(heldout), novelty_peak_scores(train)),
        ScoredDetector(names[1], phi_oracle_scores(heldout), phi_oracle_scores(train)),
    )
    return compare_detectors(
        mechanism, metric, scored[best], controls, heldout_labels=heldout.labels,
        train_labels=train.labels,
        detail=f"selected {scored[best].name} on train AP {train_aps[best]} "
        f"(train APs: {dict(zip((a[0] for a in arms), train_aps, strict=True))}); zdict "
        f"{len(zdict)} bytes.",
    )
