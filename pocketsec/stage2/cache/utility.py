"""D2.13 — DTL-F15: forget by future security utility, not by age.

Architecture spec §20 argues that a security system should retain what will
matter, not what happened recently:

    Retain(m) ∝ FutureSecurityUtility(m) × CausalResponsibility(m) × UncertaintyReduction(m)

That is a hypothesis, and this module implements it **next to its controls** so
it can be refuted. ``lru_control`` is the standard answer and ``random_control``
is the dumbest thing that could work; if utility-based forgetting does not beat
them on hit rate at equal capacity, the honest recommendation is LRU and this
mechanism should be deleted.

The measured answer is in ``tests/test_stage2_export.py``
(``test_utility_forgetting_measured_against_lru_and_random``) and in ADR-0118:
utility-based forgetting wins **only** when future reuse correlates with security
consequence, and loses to LRU when reuse is recency-driven. Whether a real Linux
host looks like the first trace or the second is not something synthetic data can
settle, so the default recommendation stays LRU.

What this module refuses to do: it refuses to let a zero factor erase an entry
that is demonstrably being reused. Credit and uncertainty-reduction inputs are
floored, because a product of three terms means one unmeasured input (credit
defaults to 0.0 when the ledger has not attributed anything yet) would silently
forget the hottest entry in the cache.
"""

from __future__ import annotations

import random

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage2.cache.transition_cache import CachedTransition, TransitionCache

__all__ = [
    "UTILITY_FLOOR",
    "forget_low_utility_memory",
    "future_security_utility",
    "lru_control",
    "random_control",
]

#: Floor applied to the causal-responsibility and uncertainty-reduction factors.
#: Not a fudge: a strictly multiplicative rule treats "not yet attributed" as
#: "worthless", which is the same conflation Stage 1's uncertainty model already
#: had to unlearn — an absent measurement is not a zero measurement.
UTILITY_FLOOR = 0.01


def _clamp_unit(value: float, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError(f"{field} must be a number, got {value!r}")
    numeric = float(value)
    if numeric != numeric:
        raise ContractError(f"{field} must be finite, got {value!r}")
    return min(1.0, max(0.0, numeric))


def future_security_utility(
    entry: CachedTransition, *, credit: float, uncertainty_reduction: float
) -> float:
    """Retain(m) for one cached transition. Higher means keep.

    Three factors, each measured elsewhere:

    * **Future security utility** — reuse (``hits``) times consequence
      (``|predicted_phi|`` plus the ΔS magnitude). An entry that is asked for
      often *and* predicts a capability change is worth more than one that is
      merely hot.
    * **Causal responsibility** — ``credit``, from the Causal Credit Ledger.
    * **Uncertainty reduction** — how much answering from this entry narrows the
      prediction, from the uncertainty module.

    Neither of the last two is available inside the cache, which is why they are
    arguments: the cache does not get to invent its own importance.
    """
    if not isinstance(entry, CachedTransition):
        raise ContractError(
            f"future_security_utility expects a CachedTransition, got {type(entry).__name__}"
        )
    reuse = 1.0 + float(entry.hits)
    consequence = 1.0 + abs(float(entry.predicted_phi)) + float(entry.predicted_delta.magnitude)
    responsibility = max(_clamp_unit(credit, field="credit"), UTILITY_FLOOR)
    reduction = max(
        _clamp_unit(uncertainty_reduction, field="uncertainty_reduction"), UTILITY_FLOOR
    )
    return reuse * consequence * responsibility * reduction


def _require_keep(cache: TransitionCache, keep: int) -> int:
    if not isinstance(cache, TransitionCache):
        raise ContractError(f"expected a TransitionCache, got {type(cache).__name__}")
    if not isinstance(keep, int) or isinstance(keep, bool) or keep < 0:
        raise ContractError(f"keep must be an int >= 0, got {keep!r}")
    return max(0, len(cache) - keep)


def forget_low_utility_memory(cache: TransitionCache, *, keep: int) -> tuple[str, ...]:
    """DTL-F15. Evict the lowest-utility entries until ``keep`` remain.

    Ties break on ``hits`` then ``last_sequence`` then ``key``, so the outcome is
    reproducible: a forgetting policy whose result depends on dict ordering cannot
    be compared against a control.
    """
    surplus = _require_keep(cache, keep)
    if surplus == 0:
        return ()
    ordered = sorted(
        cache.entries(),
        key=lambda entry: (entry.utility, entry.hits, entry.last_sequence, entry.key),
    )
    victims = tuple(entry.key for entry in ordered[:surplus])
    cache.drop_many(victims)
    return victims


def lru_control(cache: TransitionCache, *, keep: int) -> tuple[str, ...]:
    """THE SIMPLE CONTROL: evict the least-recently-*used*.

    Ordering comes from ``TransitionCache.recency_order()``, which is bumped on
    every hit. It used to sort on ``CachedTransition.last_sequence``, which is
    only ever written at store time — so the control this module is judged
    against was FIFO, not LRU, for any workload that re-reads entries rather
    than re-storing them (S2-03). A control that is not what it says it is
    cannot settle whether DTL-F15 earns its place.
    """
    surplus = _require_keep(cache, keep)
    if surplus == 0:
        return ()
    victims = cache.recency_order()[:surplus]
    cache.drop_many(victims)
    return victims


def random_control(cache: TransitionCache, *, keep: int, seed: int) -> tuple[str, ...]:
    """The dumbest control: uniform random eviction, seeded for reproducibility."""
    surplus = _require_keep(cache, keep)
    if surplus == 0:
        return ()
    keys = sorted(entry.key for entry in cache.entries())
    victims = tuple(random.Random(seed).sample(keys, surplus))
    cache.drop_many(victims)
    return victims
