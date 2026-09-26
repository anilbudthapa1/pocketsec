"""D7.3 / ORPH-F19 — the Privacy Ledger: every release is charged before it exists.

Architecture §29 asks that privacy cost be accounted, not asserted. This module keeps
that account for one host: what representation was released, to which scope, how often,
under what differential-privacy parameter, and what the labs' inference attacks measured
against it. A release that would exceed the budget raises
:class:`PrivacyBudgetExhausted` *before* anything is produced — the compiler and
:func:`release_counts` both call :meth:`PrivacyLedger.charge` first, so an exhausted
budget means no bytes, not bytes plus an apology.

**The exact differential-privacy claim (spec D7.3, ADR-0065), and nothing more.**
DP is claimed ONLY for the per-round population count release that feeds collective
novelty (D7.14): :func:`release_counts` with a numeric ``epsilon`` adds two-sided
geometric (discrete Laplace) noise of scale ``1/epsilon`` to each count, which is pure
ε-DP per released count under a per-host, per-pattern contribution clamp of 1 (the
caller's clamp; this module cannot see individual hosts), with basic composition across
releases enforced by this ledger's budget. Stated precisely so it cannot be over-read:

* the guarantee is per pattern count; a host that contributes to ``m`` patterns in one
  release loses ``m·ε`` for that release, and the ledger charges ``ε`` once per release
  (the spec's accounting), so it under-counts such a host by a factor ``m``;
* it is not formally verified; timing side channels are UNMEASURED;
* **a seeded ``random.Random`` voids it.** The default RNG is ``secrets.SystemRandom()``;
  labs pass a seeded RNG for reproducibility, and any figure produced that way is a
  utility measurement, NOT a private release;
* ``epsilon=None`` is the exact-count control and carries no DP claim (``dp_epsilon`` is
  ``None`` on its ledger entry);
* **no DP is claimed for knowledge capsules.** Their privacy is generalisation plus keyed
  commitments (:mod:`pocketsec.stage7.privacy.distiller`), measured by attack in the labs.
  Capsule releases are charged here with ``epsilon=None``: they consume the release
  budget, never the ε budget.

The budget is enforced over a **sliding** window of ``window_rounds`` rounds (a tumbling
window would admit twice the budget across a boundary), and **globally across scopes**:
recipients in different scopes may collude, so composition is over everything this host
released. Rounds only move forward; an earlier round is refused, or a caller could
replay an old round to fall outside the window. Ledger *entries* are a bounded report
(FIFO eviction, counted); the budget is enforced from a separate release log bounded by
``max_releases``, so evicting a report row never frees budget.
"""

from __future__ import annotations

import math
import random
import secrets
from collections import OrderedDict, deque
from collections.abc import Mapping
from dataclasses import dataclass, replace

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage6.capsule.experience_capsule import PrivacyClass
from pocketsec.stage7.capsule.knowledge_capsule import KnowledgeType

__all__ = [
    "DP_CLAIM",
    "EPSILON_BUDGET",
    "MAX_COUNTS_PER_RELEASE",
    "MAX_INFERENCE_TESTS",
    "MAX_LEDGER_ENTRIES",
    "MAX_RELEASES_PER_WINDOW",
    "NOVELTY_COUNTS",
    "PRIVACY_WINDOW_ROUNDS",
    "PrivacyBudgetExhausted",
    "PrivacyLedger",
    "PrivacyLedgerEntry",
    "geometric_noise",
    "release_counts",
]

# §4.23 — chosen parameters, not measurements.
EPSILON_BUDGET: float = 4.0
PRIVACY_WINDOW_ROUNDS: int = 64
MAX_RELEASES_PER_WINDOW: int = 256
MAX_LEDGER_ENTRIES: int = 256
#: Not in §4.23; chosen. Inference-test rows kept per entry (spec: <= 8), and patterns per
#: count release (matches the novelty engine's MAX_NOVELTY_PATTERNS).
MAX_INFERENCE_TESTS: int = 8
MAX_COUNTS_PER_RELEASE: int = 1024

#: The one non-capsule representation this ledger charges.
NOVELTY_COUNTS: str = "novelty_counts"
_REPRESENTATIONS = frozenset({*(t.value for t in KnowledgeType), NOVELTY_COUNTS})
#: Float slack on the ε budget comparison, so four releases at 1.0 fit a budget of 4.0.
_BUDGET_SLACK: float = 1e-9
_SENSITIVITY_ORDER = (
    PrivacyClass.PUBLIC_DERIVED, PrivacyClass.HOST_SENSITIVE, PrivacyClass.SECRET_BEARING,
)

DP_CLAIM: str = (
    "Pure epsilon-DP per released population count (two-sided geometric noise, scale "
    "1/epsilon) under a per-host per-pattern contribution clamp of 1, with basic "
    "composition across releases enforced by the ledger's sliding-window budget. Only "
    "novelty count releases; never knowledge capsules. A host contributing to m patterns "
    "in one release loses m*epsilon, which the ledger (charging epsilon once per release) "
    "does not account. Not formally verified; timing side channels UNMEASURED; a seeded "
    "RNG voids the guarantee."
)


class PrivacyBudgetExhausted(RuntimeError):
    """A release was refused because the ε budget or the release budget is spent."""


@dataclass(frozen=True, slots=True)
class PrivacyLedgerEntry:
    """One reported row: a representation released to a scope within one window."""

    representation_type: str
    sensitivity_class: PrivacyClass
    recipient_scope: str
    release_count: int
    dp_epsilon: float | None
    dp_delta: float | None
    inference_test_results: tuple[tuple[str, float], ...]
    expiry_round: int

    def __post_init__(self) -> None:
        if self.representation_type not in _REPRESENTATIONS:
            raise ContractError(f"unknown representation {self.representation_type!r}")
        if not isinstance(self.sensitivity_class, PrivacyClass):
            raise ContractError("sensitivity_class must be a PrivacyClass")
        require_identifier(self.recipient_scope, "recipient_scope")
        require_non_negative_int(self.release_count, "release_count")
        require_non_negative_int(self.expiry_round, "expiry_round")
        if self.dp_epsilon is not None and not _positive_finite(self.dp_epsilon):
            raise ContractError("dp_epsilon must be None or a finite positive float")
        if self.dp_delta is not None:
            raise ContractError("dp_delta is always None: the geometric mechanism is pure-epsilon")
        if len(self.inference_test_results) > MAX_INFERENCE_TESTS:
            raise ContractError(f"at most {MAX_INFERENCE_TESTS} inference tests per entry")


def _positive_finite(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return math.isfinite(value) and value > 0


def _require_epsilon(epsilon: object) -> float | None:
    if epsilon is None:
        return None
    if not _positive_finite(epsilon):
        raise ContractError(f"epsilon must be None or a finite positive number, got {epsilon!r}")
    return float(epsilon)  # type: ignore[arg-type]


class PrivacyLedger:
    """Bounded per-host privacy account. Budget over a sliding window, global across scopes."""

    def __init__(
        self,
        *,
        capacity: int = MAX_LEDGER_ENTRIES,
        epsilon_budget: float = EPSILON_BUDGET,
        window_rounds: int = PRIVACY_WINDOW_ROUNDS,
        max_releases: int = MAX_RELEASES_PER_WINDOW,
    ) -> None:
        for name, value in (("capacity", capacity), ("window_rounds", window_rounds),
                            ("max_releases", max_releases)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ContractError(f"{name} must be a positive int, got {value!r}")
        if not _positive_finite(epsilon_budget):
            raise ContractError(f"epsilon_budget must be finite and positive, got {epsilon_budget!r}")
        self.capacity = capacity
        self.epsilon_budget = float(epsilon_budget)
        self.window_rounds = window_rounds
        self.max_releases = max_releases
        self._entries: OrderedDict[tuple[str, str, int], PrivacyLedgerEntry] = OrderedDict()
        # (round_index, epsilon or 0.0); never longer than max_releases, by the refusal below.
        self._log: deque[tuple[int, float]] = deque()
        self._last_round = 0
        self._evictions = 0
        self._dropped_tests = 0
        self._refusals = 0

    # --- accounting --------------------------------------------------------------

    def _prune(self, round_index: int) -> None:
        horizon = round_index - self.window_rounds
        while self._log and self._log[0][0] <= horizon:
            self._log.popleft()

    def spent(self, round_index: int) -> tuple[int, float]:
        """(releases, ε) charged within the window ending at ``round_index``."""
        horizon = round_index - self.window_rounds
        live = [eps for rnd, eps in self._log if horizon < rnd <= round_index]
        return len(live), math.fsum(live)

    def _refuse(self, reason: str) -> PrivacyBudgetExhausted:
        self._refusals += 1
        return PrivacyBudgetExhausted(reason)

    def charge(
        self,
        representation_type: str,
        *,
        recipient_scope: str,
        round_index: int,
        epsilon: float | None = None,
    ) -> PrivacyLedgerEntry:
        """Record one release, or raise :class:`PrivacyBudgetExhausted` and record nothing."""
        if representation_type not in _REPRESENTATIONS:
            raise ContractError(f"unknown representation {representation_type!r}")
        require_identifier(recipient_scope, "recipient_scope")
        require_non_negative_int(round_index, "round_index")
        eps = _require_epsilon(epsilon)
        if round_index < self._last_round:
            raise ContractError(
                f"round {round_index} is before the last charged round {self._last_round}; "
                "rounds only move forward"
            )
        self._prune(round_index)
        if len(self._log) >= self.max_releases:
            raise self._refuse(
                f"release budget exhausted: {len(self._log)} releases in the last "
                f"{self.window_rounds} rounds (cap {self.max_releases})"
            )
        spent = math.fsum(e for _, e in self._log)
        if eps is not None and spent + eps > self.epsilon_budget + _BUDGET_SLACK:
            raise self._refuse(
                f"epsilon budget exhausted: {spent:.6g} spent + {eps:.6g} requested > "
                f"{self.epsilon_budget:.6g} over {self.window_rounds} rounds"
            )
        self._last_round = round_index
        self._log.append((round_index, eps if eps is not None else 0.0))
        return self._record(representation_type, recipient_scope, round_index, eps)

    def _record(self, rep: str, scope: str, round_index: int, eps: float | None) -> PrivacyLedgerEntry:
        window = round_index // self.window_rounds
        key = (rep, scope, window)
        klass = _release_class(rep, eps)
        prior = self._entries.get(key)
        if prior is None:
            entry = PrivacyLedgerEntry(
                representation_type=rep, sensitivity_class=klass, recipient_scope=scope,
                release_count=1, dp_epsilon=eps, dp_delta=None, inference_test_results=(),
                expiry_round=(window + 1) * self.window_rounds,
            )
        else:
            # One exact release voids the DP claim for the whole entry: dp_epsilon records
            # a guarantee, and a window that also released exact counts has none.
            dp = None if eps is None or prior.dp_epsilon is None else prior.dp_epsilon + eps
            entry = replace(
                prior, release_count=prior.release_count + 1, dp_epsilon=dp,
                sensitivity_class=_more_sensitive(prior.sensitivity_class, klass),
            )
        self._entries[key] = entry
        while len(self._entries) > self.capacity:
            self._entries.popitem(last=False)
            self._evictions += 1
        return entry

    def record_inference_test(
        self, representation_type: str, *, recipient_scope: str, name: str, advantage: float
    ) -> None:
        """Attach a lab attack's measured advantage to the latest matching entry.

        Refuses a test of a representation never released to that scope. Keeps the latest
        ``MAX_INFERENCE_TESTS`` rows per entry and counts the ones it drops.
        """
        require_identifier(name, "inference test name")
        if isinstance(advantage, bool) or not isinstance(advantage, (int, float)) or not (
            math.isfinite(advantage) and -1.0 <= advantage <= 1.0
        ):
            raise ContractError(f"advantage must be a finite number in [-1, 1], got {advantage!r}")
        keys = [k for k in self._entries if k[0] == representation_type and k[1] == recipient_scope]
        if not keys:
            raise ContractError(
                f"no release of {representation_type!r} to {recipient_scope!r} is on the ledger"
            )
        key = max(keys, key=lambda k: k[2])
        entry = self._entries[key]
        rows = (*entry.inference_test_results, (name, float(advantage)))
        if len(rows) > MAX_INFERENCE_TESTS:
            self._dropped_tests += len(rows) - MAX_INFERENCE_TESTS
            rows = rows[-MAX_INFERENCE_TESTS:]
        self._entries[key] = replace(entry, inference_test_results=rows)

    # --- inspection ----------------------------------------------------------------

    def entries(self) -> tuple[PrivacyLedgerEntry, ...]:
        return tuple(self._entries.values())

    def evictions(self) -> int:
        return self._evictions

    def refusals(self) -> int:
        """Releases refused for budget, over the ledger's lifetime."""
        return self._refusals

    def dropped_inference_tests(self) -> int:
        return self._dropped_tests

    def memory_bytes(self) -> int:
        """Structural estimate: entry slots, their strings and test rows, plus the log."""
        entries = sum(
            160 + len(e.representation_type) + len(e.recipient_scope)
            + sum(48 + len(name) for name, _ in e.inference_test_results)
            for e in self._entries.values()
        )
        return entries + 32 * len(self._log)


def _release_class(rep: str, eps: float | None) -> PrivacyClass:
    # An exact population count describes what this host saw; only its noised form, or a
    # distilled capsule, is PUBLIC_DERIVED.
    if rep == NOVELTY_COUNTS and eps is None:
        return PrivacyClass.HOST_SENSITIVE
    return PrivacyClass.PUBLIC_DERIVED


def _more_sensitive(a: PrivacyClass, b: PrivacyClass) -> PrivacyClass:
    return a if _SENSITIVITY_ORDER.index(a) >= _SENSITIVITY_ORDER.index(b) else b


# --- the mechanism ----------------------------------------------------------------------


def _one_sided(rng: random.Random, log_alpha: float) -> int:
    # Inverse CDF of Geometric(1 - alpha) on {0, 1, ...}: P(G >= k) = alpha**k.
    u = 1.0 - rng.random()  # (0, 1]: log is finite
    return int(math.floor(math.log(u) / log_alpha))


def geometric_noise(
    epsilon: float, *, sensitivity: int = 1, rng: random.Random | None = None
) -> int:
    """Two-sided geometric (discrete Laplace) noise: P(k) ∝ exp(-epsilon·|k|/sensitivity).

    Integer output, so there is no float-snapping channel of the kind that breaks
    textbook floating Laplace. ``rng`` defaults to ``secrets.SystemRandom()``; a seeded
    ``random.Random`` makes the output reproducible and therefore NOT private.
    """
    eps = _require_epsilon(epsilon)
    if eps is None:
        raise ContractError("geometric_noise needs a numeric epsilon")
    if isinstance(sensitivity, bool) or not isinstance(sensitivity, int) or sensitivity < 1:
        raise ContractError(f"sensitivity must be a positive int, got {sensitivity!r}")
    source = rng if rng is not None else secrets.SystemRandom()
    alpha = math.exp(-eps / sensitivity)
    if alpha <= 0.0:
        return 0  # epsilon so large that every draw is 0 at float precision
    log_alpha = math.log(alpha)
    return _one_sided(source, log_alpha) - _one_sided(source, log_alpha)


def release_counts(
    counts: Mapping[str, int],
    *,
    epsilon: float | None,
    ledger: PrivacyLedger,
    recipient_scope: str,
    round_index: int,
    rng: random.Random | None = None,
) -> dict[str, int]:
    """Release per-pattern population counts, charging the ledger first (once per release).

    ``epsilon=None`` returns the exact counts (the control; no DP claim). Otherwise each
    count gets independent geometric noise at sensitivity 1 and is clamped at 0; the
    clamp is post-processing and does not weaken the guarantee, at the cost of a small
    upward bias near zero. The per-host 0/1 contribution clamp is the CALLER's duty.
    """
    if not isinstance(ledger, PrivacyLedger):
        raise ContractError("release_counts needs a PrivacyLedger")
    if not isinstance(counts, Mapping) or len(counts) > MAX_COUNTS_PER_RELEASE:
        raise ContractError(f"counts must be a mapping of <= {MAX_COUNTS_PER_RELEASE} patterns")
    exact: dict[str, int] = {}
    for key, value in counts.items():
        if not isinstance(key, str) or not key:
            raise ContractError(f"count keys must be non-empty strings, got {key!r}")
        exact[key] = require_non_negative_int(value, f"counts[{key!r}]")
    eps = _require_epsilon(epsilon)
    ledger.charge(NOVELTY_COUNTS, recipient_scope=recipient_scope, round_index=round_index,
                  epsilon=eps)
    if eps is None:
        return exact
    source = rng if rng is not None else secrets.SystemRandom()
    return {key: max(0, value + geometric_noise(eps, rng=source)) for key, value in exact.items()}
