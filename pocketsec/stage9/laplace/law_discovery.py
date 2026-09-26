"""D9.3 (law half) — LAPLACE law discovery: does any adaptation law beat not learning?

The architecture (§29) treats the learning law ``θ_(t+1) = F(θ_t, error, novelty, ...)`` as
something to *discover*, with "no learning" as one candidate among several. Stage 9's genome
language deliberately has one learning law, ``NONE`` (lesson 3: never define a catalogue
richer than its consumer), so adaptation is studied OUTSIDE the genome, on the one thing a
deployed scorer can adapt without new code: its decision threshold.

Four laws stream over a session sequence in scenario order, each deciding ``score >=
threshold`` BEFORE it sees that session's label, then receiving the label as delayed
analyst feedback (never a peek):

* ``NO_LEARNING`` — the control: the threshold fitted on the calibration prefix, frozen.
* ``THRESHOLD_QUANTILE`` — the threshold re-fitted at FPR :data:`FPR_BUDGET` over a window of
  the last :data:`ADAPTATION_WINDOW` benign-feedback scores.
* ``EWMA_THRESHOLD`` — ``mean + z * sd`` of an exponentially weighted benign score estimate.
* ``PROTOTYPE_INSERT`` — every false positive inserts its score as a benign prototype (window
  :data:`ADAPTATION_WINDOW`); a later score within :data:`PROTOTYPE_RADIUS` of one is not
  alerted.

The measurement (:func:`compare_learning_laws`) runs on Stage 2's drift corpus, the one corpus
built to move under a scorer's feet. The first :data:`CALIBRATION_SHARE` of sessions — the
routine phase before the first change — is the TRAIN prefix: every law's initial threshold is
fitted there at FPR :data:`FPR_BUDGET`, and no rate is reported over it.

:func:`apply_host_objective` is the S9X-068 immutable-constraint test (architecture §30):
host-specific trade-off weights may exist, but no weight may relax a constitutional bound.
It returns the constraints UNCHANGED and raises on any attempt to loosen one.

What this module refuses to do: it never lets a law see a label before deciding on that
session, it never reports a rate over the calibration prefix, and it never marks a law
JUSTIFIED on a lower false-positive rate bought with lower recall.
"""

from __future__ import annotations

import math
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass, fields
from enum import StrEnum

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage2.dataset import Stage2Dataset
from pocketsec.stage2.encoder.ssir_encoder import ENCODER_VERSION
from pocketsec.stage2.labs.drift_corpus import DRIFT_VERSION, build_drift_corpus
from pocketsec.stage9.genome.computational import ComputationalGenomeV1
from pocketsec.stage9.labs.splits import CLEAN, CompiledVariant, SplitKey, compile_scenarios
from pocketsec.stage9.laplace.state_discovery import DECISION_FPR_BUDGET, fit_threshold
from pocketsec.stage9.ontogenesis.fitness import session_scores
from pocketsec.stage9.renormalization.laboratory import fpr_threshold
from pocketsec.stage9.spec.mssc import (
    DEFAULT_CONSTRAINTS,
    DetectorComparison,
    MechanismVerdict,
    MSSCConstraints,
)

__all__ = [
    "ADAPTATION_WINDOW",
    "CALIBRATION_SHARE",
    "DEFAULT_HALF_LIFE_EVENTS",
    "EWMA_ALPHA",
    "EWMA_Z",
    "FPR_BUDGET",
    "FP_MARGIN",
    "LEARNING_LAW_SEARCH_DEFAULT_ENABLED",
    "PROTOTYPE_RADIUS",
    "AdaptationLaw",
    "DiscoveredLaw",
    "HostObjective",
    "LawKind",
    "LawOutcome",
    "apply_host_objective",
    "compare_learning_laws",
    "compile_drift_corpus",
    "evaluate_adaptation",
    "law_from_comparison",
]

#: Ships False. Only the integrator may set it True, after a measured JUSTIFIED verdict.
LEARNING_LAW_SEARCH_DEFAULT_ENABLED: bool = False

#: Every adaptive law's memory is bounded to this many scores (chosen).
ADAPTATION_WINDOW = 256
FPR_BUDGET = DECISION_FPR_BUDGET
#: Share of the stream used only to fit the initial threshold (the drift corpus's
#: pre-change routine phase is its first 25%). Chosen.
CALIBRATION_SHARE = 0.25
#: EWMA weight and one-sided normal z for a 5% tail. Chosen, not fitted.
EWMA_ALPHA = 0.05
EWMA_Z = 1.645
#: A score this close to a benign prototype is suppressed. Chosen.
PROTOTYPE_RADIUS = 1e-3
#: JUSTIFIED needs FP at least this much lower than the control at recall >= control's.
FP_MARGIN = 0.02
#: ln(2) / 0.01 rounded: the half-life that ``decay_confidence``'s default lambda implies.
DEFAULT_HALF_LIFE_EVENTS = 69

_MECHANISM = "pocketsec.stage9.laplace.law_discovery:LEARNING_LAW_SEARCH_DEFAULT_ENABLED"
#: ``labs.splits`` spells an unattacked variant's attack version this way.
_NO_ATTACK_VERSION = "none"


class AdaptationLaw(StrEnum):
    NO_LEARNING = "NO_LEARNING"
    THRESHOLD_QUANTILE = "THRESHOLD_QUANTILE"
    EWMA_THRESHOLD = "EWMA_THRESHOLD"
    PROTOTYPE_INSERT = "PROTOTYPE_INSERT"


class LawKind(StrEnum):
    STATE = "STATE"
    TRANSITION = "TRANSITION"
    ADAPTATION = "ADAPTATION"


@dataclass(frozen=True, slots=True)
class LawOutcome:
    """One law's rates over the post-calibration stream; ``updates_applied`` is its firing
    count (threshold changes or prototype insertions)."""

    law: str
    benign_fp_rate: float | None  # None when no benign session follows the prefix
    recall: float | None  # None when no malicious session follows the prefix
    updates_applied: int


@dataclass(frozen=True, slots=True)
class DiscoveredLaw:
    """A law that survived its comparison. Confidence starts at 1.0 and is decayed by
    :func:`pocketsec.stage9.observatory.convergence.decay_confidence`; it is a bookkeeping
    quantity, not a probability."""

    name: str
    kind: LawKind
    statement: str
    experiment_id: str | None
    confidence: float
    half_life_events: int
    failure_domain: str


# --- the laws ----------------------------------------------------------------------------------


def _ranked(score: float | None) -> float:
    return 0.0 if score is None else float(score)


class _Law:
    """A threshold that may move after each piece of feedback."""

    def __init__(self, law: AdaptationLaw, threshold: float, prefix_benign: Sequence[float]):
        self.law = law
        self.threshold = threshold
        self.updates = 0
        self._window: deque[float] = deque(prefix_benign, maxlen=ADAPTATION_WINDOW)
        self._prototypes: deque[float] = deque(maxlen=ADAPTATION_WINDOW)
        mean = sum(prefix_benign) / len(prefix_benign) if prefix_benign else 0.0
        var = (
            sum((x - mean) ** 2 for x in prefix_benign) / len(prefix_benign)
            if prefix_benign
            else 0.0
        )
        self._mean, self._var = mean, var

    def decide(self, score: float) -> bool:
        if score < self.threshold:
            return False
        return not any(abs(score - p) <= PROTOTYPE_RADIUS for p in self._prototypes)

    def feedback(self, score: float, label: int, alerted: bool) -> None:
        if self.law is AdaptationLaw.NO_LEARNING or label != 0:
            return
        if self.law is AdaptationLaw.PROTOTYPE_INSERT:
            if alerted:
                self._prototypes.append(score)
                self.updates += 1
            return
        new = self._next_threshold(score)
        if new != self.threshold:
            self.threshold = new
            self.updates += 1

    def _next_threshold(self, score: float) -> float:
        if self.law is AdaptationLaw.THRESHOLD_QUANTILE:
            self._window.append(score)
            return _benign_quantile_threshold(self._window)
        delta = score - self._mean
        self._mean += EWMA_ALPHA * delta
        self._var = (1.0 - EWMA_ALPHA) * (self._var + EWMA_ALPHA * delta * delta)
        return self._mean + EWMA_Z * math.sqrt(self._var)


def _benign_quantile_threshold(benign: Sequence[float]) -> float:
    """The lowest threshold at which at most ``FPR_BUDGET`` of ``benign`` would alert.

    The ONE benign-FPR cut of Stage 9 is ``renormalization.laboratory.fpr_threshold`` (alert
    when ``score > t``); this module alerts on ``score >= threshold``, so it returns the next
    float above ``t``, which is the same decision (integrator seam fix: one implementation).
    """
    cut = fpr_threshold(benign, budget=FPR_BUDGET)
    if cut is None:
        raise ContractError("no benign score to fit a threshold on")
    return math.nextafter(cut, math.inf)


def _calibration_size(count: int) -> int:
    return max(1, int(count * CALIBRATION_SHARE))


def _check_stream(scores: Sequence[float | None], labels: Sequence[int]) -> None:
    if len(scores) != len(labels):
        raise ContractError(f"{len(scores)} scores but {len(labels)} labels")
    if any(label not in (0, 1) for label in labels):
        raise ContractError("labels must be 0 or 1")
    if len(scores) < 2:
        raise ContractError("an adaptation stream needs a calibration prefix and a remainder")


def _initial_threshold(prefix_scores: Sequence[float], prefix_labels: Sequence[int]) -> float:
    if 0 in prefix_labels and 1 in prefix_labels:
        return fit_threshold(prefix_labels, prefix_scores)
    benign = [s for s, label in zip(prefix_scores, prefix_labels, strict=True) if label == 0]
    if not benign:
        raise ContractError("the calibration prefix holds no benign session to fit on")
    return _benign_quantile_threshold(benign)


def _run_law(
    law: AdaptationLaw,
    scores: Sequence[float | None],
    labels: Sequence[int],
    initial_threshold: float | None,
) -> tuple[LawOutcome, tuple[bool, ...]]:
    """Stream one law; returns its outcome and its post-prefix decisions."""
    _check_stream(scores, labels)
    ranked = [_ranked(s) for s in scores]
    split = _calibration_size(len(ranked))
    prefix, prefix_labels = ranked[:split], list(labels[:split])
    threshold = (
        _initial_threshold(prefix, prefix_labels)
        if initial_threshold is None
        else initial_threshold
    )
    benign_prefix = [s for s, label in zip(prefix, prefix_labels, strict=True) if label == 0]
    state = _Law(law, threshold, benign_prefix)
    made: list[bool] = []
    for score, label in zip(ranked[split:], labels[split:], strict=True):
        alerted = state.decide(score)  # decided BEFORE the label is seen
        made.append(alerted)
        state.feedback(score, label, alerted)
    rest = list(labels[split:])
    benign = sum(1 for label in rest if label == 0)
    malicious = len(rest) - benign
    fp = sum(1 for a, label in zip(made, rest, strict=True) if a and label == 0)
    tp = sum(1 for a, label in zip(made, rest, strict=True) if a and label == 1)
    outcome = LawOutcome(
        law=law.value,
        benign_fp_rate=None if benign == 0 else fp / benign,
        recall=None if malicious == 0 else tp / malicious,
        updates_applied=state.updates,
    )
    return outcome, tuple(made)


def evaluate_adaptation(
    law: AdaptationLaw,
    scores: Sequence[float | None],
    labels: Sequence[int],
    *,
    initial_threshold: float | None = None,
) -> LawOutcome:
    """Stream ``law`` over ``scores`` in order (bounded window :data:`ADAPTATION_WINDOW`).

    The first :data:`CALIBRATION_SHARE` of the stream fits the initial threshold (or
    ``initial_threshold`` is used as given) and is excluded from the reported rates.
    """
    return _run_law(AdaptationLaw(law), scores, labels, initial_threshold)[0]


# --- the comparison ------------------------------------------------------------------------------


def compile_drift_corpus(*, count: int = 120, seed: int = 11) -> CompiledVariant:
    """Stage 2's drift corpus at (count, seed), compiled once through ``labs.splits``.

    Public because the promotion gate's cross-epoch step needs the same compiled corpus
    that :func:`compare_learning_laws` measures on, and only this module may import the
    drift builder (spec §2.3). One compile, shared, cannot disagree with itself.
    """
    key = SplitKey(
        corpus="drift",
        count=count,
        seed=seed,
        attack_id=CLEAN,
        corpus_version=DRIFT_VERSION,
        encoder_version=ENCODER_VERSION,
        attack_version=_NO_ATTACK_VERSION,
    )
    return compile_scenarios(build_drift_corpus(count=count, seed=seed), key=key)


def _drift_scores(
    genome: ComputationalGenomeV1, count: int, seed: int, drift: Stage2Dataset | None
) -> tuple[tuple[float | None, ...], tuple[int, ...]]:
    dataset = compile_drift_corpus(count=count, seed=seed).dataset if drift is None else drift
    return session_scores(genome, dataset), dataset.labels


def _qualifies(outcome: LawOutcome, control: LawOutcome) -> bool:
    assert control.benign_fp_rate is not None and control.recall is not None
    return (
        outcome.benign_fp_rate is not None
        and outcome.recall is not None
        and outcome.recall >= control.recall
        and outcome.benign_fp_rate <= control.benign_fp_rate - FP_MARGIN
    )


def _dominated_by_control(outcome: LawOutcome, control: LawOutcome) -> bool:
    assert control.benign_fp_rate is not None and control.recall is not None
    if outcome.benign_fp_rate is None or outcome.recall is None:
        return False
    no_better = (
        outcome.benign_fp_rate >= control.benign_fp_rate and outcome.recall <= control.recall
    )
    worse = outcome.benign_fp_rate > control.benign_fp_rate or outcome.recall < control.recall
    return no_better and worse


def _best_adaptive(
    runs: dict[AdaptationLaw, tuple[LawOutcome, tuple[bool, ...]]],
    qualifying: list[AdaptationLaw],
) -> AdaptationLaw | None:
    """The qualifying law with the lowest FP, else the lowest-FP measured adaptive law."""
    pool = qualifying or [
        law
        for law in AdaptationLaw
        if law is not AdaptationLaw.NO_LEARNING and runs[law][0].benign_fp_rate is not None
    ]
    if not pool:
        return None
    return min(pool, key=lambda law: (runs[law][0].benign_fp_rate or 0.0, law.value))


def _recall_note(
    runs: dict[AdaptationLaw, tuple[LawOutcome, tuple[bool, ...]]], control: LawOutcome
) -> str:
    """Flag a law that beats the control on recall at no FP cost.

    The §4.14 rule scores FP only, so when the control already sits at FP 0 no law can be
    JUSTIFIED however much recall it recovers. That blind spot is reported, not re-ruled.
    """
    assert control.benign_fp_rate is not None and control.recall is not None
    gains = [
        law.value
        for law, (outcome, _made) in runs.items()
        if outcome.benign_fp_rate is not None
        and outcome.recall is not None
        and outcome.benign_fp_rate <= control.benign_fp_rate
        and outcome.recall >= control.recall + FP_MARGIN
    ]
    return f"RECALL_GAIN_NOT_SCORED_BY_RULE {gains}; " if gains else ""


def compare_learning_laws(
    genome: ComputationalGenomeV1,
    *,
    count: int = 120,
    seed: int = 11,
    drift: Stage2Dataset | None = None,
) -> DetectorComparison:
    """Every adaptation law against NO_LEARNING on the drift corpus (spec §4.14, §7).

    JUSTIFIED iff some law's benign FP rate is >= :data:`FP_MARGIN` lower at recall >= the
    control's; REJECTED iff every adaptive law is dominated by the control. ``fired`` counts
    post-prefix sessions the best adaptive law decided differently from the control.
    ``drift`` is :func:`compile_drift_corpus` (count, seed) already compiled by the caller;
    without it the corpus is compiled here.
    """
    scores, labels = _drift_scores(genome, count, seed, drift)
    runs = {law: _run_law(law, scores, labels, None) for law in AdaptationLaw}
    control, control_made = runs[AdaptationLaw.NO_LEARNING]
    adaptive: list[AdaptationLaw] = [
        law for law in AdaptationLaw if law is not AdaptationLaw.NO_LEARNING
    ]
    summary = "; ".join(
        f"{law.value}: fp={runs[law][0].benign_fp_rate} recall={runs[law][0].recall} "
        f"updates={runs[law][0].updates_applied}"
        for law in AdaptationLaw
    )
    metric = f"benign FP rate after calibration, drift corpus count {count} seed {seed}"
    controls = (("NO_LEARNING", control.benign_fp_rate),)
    if control.benign_fp_rate is None or control.recall is None:
        return DetectorComparison(
            _MECHANISM, metric, None, controls, MechanismVerdict.UNMEASURED, 0,
            f"control rates not computable; {summary}",
        )  # fmt: skip
    qualifying = [law for law in adaptive if _qualifies(runs[law][0], control)]
    best = _best_adaptive(runs, qualifying)
    if best is None:
        return DetectorComparison(
            _MECHANISM, metric, None, controls, MechanismVerdict.UNMEASURED, 0,
            f"no adaptive law produced a rate; {summary}",
        )  # fmt: skip
    fired = sum(1 for a, b in zip(runs[best][1], control_made, strict=True) if a != b)
    if qualifying and fired > 0:
        verdict = MechanismVerdict.JUSTIFIED
    elif all(_dominated_by_control(runs[law][0], control) for law in adaptive):
        verdict = MechanismVerdict.REJECTED
    else:
        verdict = MechanismVerdict.NOT_YET_JUSTIFIED
    return DetectorComparison(
        mechanism=_MECHANISM,
        metric=metric,
        value=runs[best][0].benign_fp_rate,
        controls=controls,
        verdict=verdict,
        fired=fired,
        detail=_recall_note(runs, control) + f"best adaptive law {best.value}; {summary}",
    )


def law_from_comparison(
    comparison: DetectorComparison,
    *,
    name: str,
    kind: LawKind,
    statement: str,
    failure_domain: str,
    experiment_id: str | None = None,
) -> DiscoveredLaw | None:
    """A :class:`DiscoveredLaw` for a JUSTIFIED comparison, else ``None``.

    Only a measured JUSTIFIED verdict produces a law; every other verdict produces nothing,
    so a law can never be created by omission.
    """
    if comparison.verdict is not MechanismVerdict.JUSTIFIED:
        return None
    if not failure_domain.strip():
        raise ContractError("a discovered law must state its failure domain (architecture §47)")
    return DiscoveredLaw(
        name=name,
        kind=kind,
        statement=statement,
        experiment_id=experiment_id,
        confidence=1.0,
        half_life_events=DEFAULT_HALF_LIFE_EVENTS,
        failure_domain=failure_domain,
    )


# --- S9X-068: host objectives never relax a constraint --------------------------------------------


@dataclass(frozen=True, slots=True)
class HostObjective:
    """Architecture §30's host trade-off weights (FN, FP, latency, RAM)."""

    fn_weight: float
    fp_weight: float
    latency_weight: float
    ram_weight: float


def _check_weights(objective: HostObjective) -> None:
    weights = [getattr(objective, f.name) for f in fields(objective)]
    for f, value in zip(fields(objective), weights, strict=True):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ContractError(f"HostObjective.{f.name} must be a number, got {value!r}")
        if not math.isfinite(value) or value < 0:
            raise ContractError(
                f"HostObjective.{f.name}={value!r}: a negative or non-finite weight rewards "
                "the outcome it should penalise, which relaxes a constraint by the back door"
            )
    if not any(weights):
        raise ContractError("a HostObjective with every weight zero weighs nothing")


def _relaxations(constraints: MSSCConstraints, constitution: MSSCConstraints) -> list[str]:
    loosened = []
    if constraints.q_min_margin < constitution.q_min_margin:
        loosened.append("q_min_margin")
    if constraints.r_min < constitution.r_min:
        loosened.append("r_min")
    if constraints.ram_bytes_max > constitution.ram_bytes_max:
        loosened.append("ram_bytes_max")
    if constraints.wu_per_event_max > constitution.wu_per_event_max:
        loosened.append("wu_per_event_max")
    if constitution.k_min is not None and (
        constraints.k_min is None or constraints.k_min < constitution.k_min
    ):
        loosened.append("k_min")
    return loosened


def apply_host_objective(
    objective: HostObjective,
    constraints: MSSCConstraints,
    *,
    constitution: MSSCConstraints = DEFAULT_CONSTRAINTS,
) -> MSSCConstraints:
    """Return ``constraints`` UNCHANGED (the same object); raise ContractError on relaxation.

    Host weights may re-rank candidates that already satisfy the constraints; they never
    touch the constraints themselves. ``constraints`` looser than ``constitution`` on any
    field, or a weight that is negative/non-finite, is an attempt to relax (S9X-068).
    """
    _check_weights(objective)
    loosened = _relaxations(constraints, constitution)
    if loosened:
        raise ContractError(
            f"host objective refused: it would relax the constitutional {', '.join(loosened)}"
        )
    return constraints
