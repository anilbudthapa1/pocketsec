"""D8.6 / PROM-F09 — the experiment value engine: an explicit posterior and exact expected information gain.

ORACLE (architecture §14–§15) chooses the experiment that most separates the surviving
hypotheses. "Most separates" is made a number here: the expected reduction in the entropy of a
posterior over hypotheses, ``EIG(X) = H(P) − Σ_y P(y) · H(P | y)``.

How the likelihood is defined (§41: "likelihood approximations documented"):

- Each hypothesis predicts a label vector over the design's episodes (1 = malicious).
- An observation ``y`` has likelihood ``L(y | h) = Π_i (1 − ε if ŷ_h,i = y_i else ε)`` with
  ε = :data:`LIKELIHOOD_NOISE`: one wrong label costs a hypothesis a factor of ε/(1−ε), never
  its whole mass, because the lab's labels and a theory's reading of a step are both imperfect.
- The outcome space is the set of *distinct predicted vectors*, not all 2^n vectors. It is
  enumerated exactly, and the outcome probabilities are renormalised over it so the expectation
  is a proper average. When every hypothesis predicts the same vector there is one outcome, the
  posterior cannot move, and EIG is exactly 0 — the "observationally equivalent" case that
  §43 turns into a stopping rule.
- Likelihoods are combined in log space so a 64-episode design cannot underflow to 0/0.

What it refuses to do:

- **No hidden prior.** Every :class:`Posterior` carries ``prior_version``; the only prior this
  wave builds is ``uniform-v1``.
- **A missing label is not evidence.** ``None`` in ``observed`` contributes no factor; it never
  counts as agreement with anyone.
- **Adversarial evidence never enters.** This module sees label vectors, not episodes; the
  planner hands it labels only from LAB_POOL recordings, label-preserving lab transforms or the
  authorised lab oracle, and refuses CHALLENGE episodes at its door (§41 "adversarially generated
  evidence down-weighted": here, weighted zero by construction).
- **The posterior decides nothing.** It orders experiments and prunes hypotheses before
  registration; only the holdout vault decides survival.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from pocketsec.stage0.contracts.common import ContractError

__all__ = [
    "LIKELIHOOD_NOISE",
    "POSTERIOR_SUM_TOLERANCE",
    "PRIOR_VERSION",
    "Posterior",
    "entropy_bits",
    "expected_information_gain",
    "log_likelihood",
    "uniform_prior",
    "update",
]

#: §4.21. Chosen parameters, not measurements.
LIKELIHOOD_NOISE: float = 0.05
PRIOR_VERSION: str = "uniform-v1"
#: How far a posterior's probabilities may sum from 1.0 before construction refuses it.
POSTERIOR_SUM_TOLERANCE: float = 1e-9

_LOG_AGREE = math.log(1.0 - LIKELIHOOD_NOISE)
_LOG_DISAGREE = math.log(LIKELIHOOD_NOISE)


@dataclass(frozen=True, slots=True)
class Posterior:
    """A normalised distribution over hypothesis ids, and the prior it started from."""

    hypothesis_ids: tuple[str, ...]
    probabilities: tuple[float, ...]
    prior_version: str = PRIOR_VERSION

    def __post_init__(self) -> None:
        ids, probabilities = self.hypothesis_ids, self.probabilities
        if not isinstance(ids, tuple) or not isinstance(probabilities, tuple):
            raise ContractError("Posterior.hypothesis_ids and probabilities must be tuples")
        if not ids or len(ids) != len(probabilities):
            raise ContractError("a Posterior needs >= 1 hypothesis and one probability each")
        if any(not isinstance(item, str) or not item for item in ids) or len(set(ids)) != len(ids):
            raise ContractError("Posterior.hypothesis_ids must be distinct non-empty strings")
        for value in probabilities:
            if isinstance(value, bool) or not isinstance(value, float):
                raise ContractError(f"Posterior probabilities must be floats, got {value!r}")
            if not math.isfinite(value) or value < 0.0:
                raise ContractError(f"Posterior probabilities must be finite and >= 0, got {value}")
        if abs(math.fsum(probabilities) - 1.0) > POSTERIOR_SUM_TOLERANCE:
            raise ContractError(f"Posterior probabilities sum to {math.fsum(probabilities)}, not 1")
        if not isinstance(self.prior_version, str) or not self.prior_version:
            raise ContractError("Posterior.prior_version must name the prior explicitly")

    def probability(self, hypothesis_id: str) -> float:
        try:
            return self.probabilities[self.hypothesis_ids.index(hypothesis_id)]
        except ValueError:
            raise ContractError(f"{hypothesis_id!r} is not in this posterior") from None

    def leading(self) -> str | None:
        """The unique most probable id, or ``None`` on a tie at the top (no invented winner)."""
        best = max(self.probabilities)
        top = [hid for hid, p in zip(self.hypothesis_ids, self.probabilities) if p == best]
        return top[0] if len(top) == 1 else None

    def restricted(self, keep: Sequence[str]) -> Posterior:
        """The posterior conditioned on ``keep`` (renormalised); used after pruning."""
        wanted = set(keep)
        pairs = [(h, p) for h, p in zip(self.hypothesis_ids, self.probabilities) if h in wanted]
        total = math.fsum(p for _, p in pairs)
        if not pairs or total <= 0.0:
            raise ContractError("restricting a posterior must keep some probability mass")
        return Posterior(
            hypothesis_ids=tuple(h for h, _ in pairs),
            probabilities=_normalised([p / total for _, p in pairs]),
            prior_version=self.prior_version,
        )


def _normalised(values: Sequence[float]) -> tuple[float, ...]:
    total = math.fsum(values)
    return tuple(float(value / total) for value in values)


def _from_log_weights(log_weights: Sequence[float]) -> tuple[float, ...]:
    peak = max(log_weights)
    return _normalised([math.exp(value - peak) for value in log_weights])


def uniform_prior(hypothesis_ids: Sequence[str]) -> Posterior:
    """The ``uniform-v1`` prior: every hypothesis equally likely before any experiment."""
    ids = tuple(hypothesis_ids)
    if not ids:
        raise ContractError("uniform_prior needs >= 1 hypothesis")
    return Posterior(hypothesis_ids=ids, probabilities=_normalised([1.0] * len(ids)))


def entropy_bits(posterior: Posterior) -> float:
    """Shannon entropy of ``posterior`` in bits (0 · log 0 = 0)."""
    return _entropy(posterior.probabilities)


def _entropy(probabilities: Sequence[float]) -> float:
    return max(0.0, -math.fsum(p * math.log2(p) for p in probabilities if p > 0.0))


def _check_predictions(
    posterior: Posterior, predictions: Mapping[str, tuple[int, ...]]
) -> tuple[tuple[int, ...], ...]:
    """Each posterior id's vector, in posterior order; all the same length, every value 0/1."""
    vectors: list[tuple[int, ...]] = []
    for hypothesis_id in posterior.hypothesis_ids:
        if hypothesis_id not in predictions:
            raise ContractError(f"no prediction for hypothesis {hypothesis_id!r}")
        vector = predictions[hypothesis_id]
        if not isinstance(vector, tuple) or any(
            isinstance(value, bool) or value not in (0, 1) for value in vector
        ):
            raise ContractError(f"prediction for {hypothesis_id!r} must be a tuple of 0/1 ints")
        vectors.append(vector)
    if len({len(vector) for vector in vectors}) != 1:
        raise ContractError("every hypothesis must predict the same number of episodes")
    return tuple(vectors)


def log_likelihood(predicted: tuple[int, ...], observed: Sequence[int | None]) -> float:
    """``log L(observed | predicted)``; a ``None`` observation contributes no factor."""
    if len(predicted) != len(observed):
        raise ContractError("observed and predicted vectors differ in length")
    total = 0.0
    for guess, seen in zip(predicted, observed):
        if seen is None:
            continue
        if isinstance(seen, bool) or seen not in (0, 1):
            raise ContractError(f"an observed label must be 0, 1 or None, got {seen!r}")
        total += _LOG_AGREE if guess == seen else _LOG_DISAGREE
    return total


def expected_information_gain(
    posterior: Posterior, predictions: Mapping[str, tuple[int, ...]]
) -> float:
    """Exact EIG in bits over the distinct predicted outcome vectors (module docstring)."""
    vectors = _check_predictions(posterior, predictions)
    outcomes = tuple(dict.fromkeys(vectors))
    if len(outcomes) == 1:
        return 0.0  # every hypothesis predicts the same thing: nothing can be learned here
    log_prior = [math.log(p) if p > 0.0 else -math.inf for p in posterior.probabilities]
    joint: list[list[float]] = []  # joint[o][h] = log P(h) + log L(y_o | h)
    for outcome in outcomes:
        joint.append([lp + log_likelihood(vector, outcome) for lp, vector in zip(log_prior, vectors)])
    evidence = [_logsumexp(row) for row in joint]  # log P(y_o), unnormalised over the outcome set
    outcome_weights = _from_log_weights(evidence)
    expected_after = math.fsum(
        weight * _entropy(_from_log_weights(row)) for weight, row in zip(outcome_weights, joint)
    )
    return max(0.0, entropy_bits(posterior) - expected_after)


def _logsumexp(values: Sequence[float]) -> float:
    peak = max(values)
    if peak == -math.inf:
        return -math.inf
    return peak + math.log(math.fsum(math.exp(value - peak) for value in values))


def update(
    posterior: Posterior,
    predictions: Mapping[str, tuple[int, ...]],
    observed: tuple[int | None, ...],
) -> Posterior:
    """Bayes' rule with the module's likelihood; ``None`` labels leave the posterior unmoved."""
    vectors = _check_predictions(posterior, predictions)
    if not isinstance(observed, tuple) or len(observed) != len(vectors[0]):
        raise ContractError("observed must be a tuple as long as each predicted vector")
    log_weights = [
        (math.log(p) if p > 0.0 else -math.inf) + log_likelihood(vector, observed)
        for p, vector in zip(posterior.probabilities, vectors)
    ]
    return Posterior(
        hypothesis_ids=posterior.hypothesis_ids,
        probabilities=_from_log_weights(log_weights),
        prior_version=posterior.prior_version,
    )
