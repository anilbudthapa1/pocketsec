"""D8.18 / PROM-F23 — the Research Integrity Plane: content addressing and the held-out vault.

A discovery engine that can see its test data is not being tested. This module is where
Stage 8 keeps held-out data *out of reach* and turns a preregistered test into a result
exactly once.

**The vault** (:class:`HoldoutVault`). One vault per held-out split (HOLDOUT, and a second
one for REPLICATION). It holds its episodes in a single private attribute,
``_vault_episodes``, and **exposes no method that returns an episode, a step or a label**
(boundary rule 14 checks that the name appears nowhere else in Stage 8). The only way
information leaves is a :class:`~pocketsec.stage8.ledger.theory.TestOutcome` for a
hypothesis the ledger already holds a PREREGISTER for, written through
``TheoryLedger.record_result``. The discipline:

1. ``seal_batch`` accepts only registrations that are PREREGISTER entries in the ledger for
   *this* split and *this* :func:`split_digest`, whose ``batch_size`` equals the batch
   length (so ``alpha / batch_size`` is the Bonferroni correction for the family actually
   tested), no more than ``max_registrations_per_batch``, and no batch past ``max_batches``
   (one per split by default: a split looked at twice is no longer held out).
2. ``evaluate`` runs once per ticket. For each registration it counts matches with
   ``genome.decides`` (direction-aware: a BENIGN genome predicts enrichment of *negatives*),
   computes the exact one-sided binomial p-value at the split's base rate, applies every
   refutation rule the genome declared for that split at ``alpha / batch_size``, writes the
   outcome, and (HOLDOUT only) sets SURVIVED / FALSIFIED. REPLICATION outcomes leave the
   status to the reproducibility gate, which also weighs invariance, imbalance and
   independent false positives before REPRODUCED.
3. A ticket whose evaluation is cut off by the work budget is still consumed: the data was
   read, so it cannot be read again for a better answer.

A rule the vault cannot evaluate refutes (reason ``<kind>:not_evaluable``): a preregistered
criterion that was not applied cannot be said to have been survived.

**Content addressing and records.** :func:`content_digest` is ``sha256:`` over canonical
JSON; :func:`split_digest` binds a split's episode ids *and labels* (a relabelled split is a
different split); :func:`detect_split_leakage` names every episode id present in two
splits; :func:`sign_record` / :func:`verify_record` are HMAC-SHA256 over canonical bytes
with a per-run key. **HMAC proves possession of the key, not identity** (ADR-0064
precedent): this is local integrity only — the record was not altered after signing on this
host — and anyone holding the seed can derive the key.

:func:`binomial_upper_tail` is exact (``math.comb``, summed in log space so that
``C(2048, 1024)`` does not overflow a float), never a normal approximation.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import sys
from collections import Counter, deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, NoReturn

from pocketsec.stage0.contracts.common import ContractError, digest_of_bytes
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage8.episode import Episode, FitCounts, Split
from pocketsec.stage8.genome.hypothesis import (
    Direction,
    FalsifierKind,
    HypothesisGenome,
)
from pocketsec.stage8.governor.budget import ResearchBudget, ResearchGovernor
from pocketsec.stage8.ledger.theory import (
    HELD_OUT_SPLITS,
    PreRegistration,
    TestOutcome,
    TheoryLedger,
    TheoryStatus,
    canonical_bytes,
)

__all__ = [
    "ALPHA",
    "MAX_HOLDOUT_BATCHES_PER_SPLIT",
    "MAX_HOLDOUT_EPISODES",
    "MAX_VAULT_LOG",
    "MIN_SIGNING_KEY_BYTES",
    "SIGNATURE_PREFIX",
    "BatchTicket",
    "HoldoutVault",
    "LeakageFinding",
    "VaultAccess",
    "VaultError",
    "binomial_upper_tail",
    "content_digest",
    "detect_split_leakage",
    "run_key",
    "sign_record",
    "split_digest",
    "verify_record",
]

#: Spec §4.21. Chosen, not measured.
ALPHA: float = 0.05
MAX_HOLDOUT_BATCHES_PER_SPLIT: int = 1
MAX_HOLDOUT_EPISODES: int = 2048
MAX_VAULT_LOG: int = 1024
#: Shorter keys make the HMAC a checksum; 16 bytes is the floor, not a recommendation.
MIN_SIGNING_KEY_BYTES: int = 16
SIGNATURE_PREFIX: str = "hmac-sha256:"

_VAULT_COMPONENT = "vault"
_HOLDOUT_RULES: frozenset[FalsifierKind] = frozenset({
    FalsifierKind.HOLDOUT_ENRICHMENT,
    FalsifierKind.HOLDOUT_FALSE_POSITIVES,
    FalsifierKind.HOLDOUT_RECALL,
})


class VaultError(ContractError):
    """A vault request refused: wrong split, unregistered, oversized, exhausted or replayed."""


# --- content addressing, leakage, signed records ----------------------------------------------


def content_digest(payload: Any) -> str:
    """``sha256:`` over the canonical JSON of plain data (sorted keys, ASCII, no NaN)."""
    return digest_of_bytes(canonical_bytes(payload))


def split_digest(episodes: Sequence[Episode]) -> str:
    """Bind a split: its sorted ``(episode_id, label)`` pairs and the splits it claims.

    Labels are included deliberately: the same ids relabelled after a preregistration are a
    different test, and must not satisfy a registration made against the original.
    """
    pairs = sorted((episode.episode_id, episode.label) for episode in episodes)
    splits = sorted({episode.split.value for episode in episodes})
    return content_digest({"episodes": pairs, "splits": splits})


@dataclass(frozen=True, slots=True)
class LeakageFinding:
    episode_id: str
    splits: tuple[Split, ...]


def detect_split_leakage(splits: Mapping[Split, Sequence[Episode]]) -> tuple[LeakageFinding, ...]:
    """Every episode id present under two or more split keys, sorted by id.

    Episode ids are content-derived and exclude label, split and context (``episode.py``), so
    the same session placed in two splits is caught even if its label or split field differ.
    """
    seen: dict[str, set[Split]] = {}
    for split, episodes in splits.items():
        for episode in episodes:
            seen.setdefault(episode.episode_id, set()).add(split)
    return tuple(
        LeakageFinding(episode_id, tuple(sorted(found, key=lambda s: s.value)))
        for episode_id, found in sorted(seen.items())
        if len(found) > 1
    )


def run_key(seed: int) -> bytes:
    """The per-run signing key derived from the run seed. Local integrity only (ADR-0064)."""
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ContractError(f"run_key takes an int seed, got {seed!r}")
    return hashlib.sha256(f"pocketsec-stage8-run-key|{seed}".encode("ascii")).digest()


def _require_key(key: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) < MIN_SIGNING_KEY_BYTES:
        raise ContractError(f"a signing key is bytes of length >= {MIN_SIGNING_KEY_BYTES}")
    return key


def sign_record(payload: Mapping[str, Any], *, key: bytes) -> str:
    """HMAC-SHA256 over ``payload``'s canonical bytes: integrity on this host, not identity."""
    if not isinstance(payload, Mapping):
        raise ContractError("sign_record takes a mapping")
    tag = hmac.new(_require_key(key), canonical_bytes(payload), hashlib.sha256).hexdigest()
    return SIGNATURE_PREFIX + tag


def verify_record(payload: Mapping[str, Any], signature: str, *, key: bytes) -> bool:
    """Constant-time check that ``signature`` is this key's HMAC of ``payload``."""
    _require_key(key)
    if not isinstance(signature, str) or not signature.startswith(SIGNATURE_PREFIX):
        return False
    try:
        expected = sign_record(payload, key=key)
    except ContractError:
        return False
    return hmac.compare_digest(expected, signature)


# --- the exact test -------------------------------------------------------------------------------


def binomial_upper_tail(k: int, n: int, p: float) -> float:
    """``P(X >= k)`` for ``X ~ Binomial(n, p)``, exactly (up to float rounding of each term).

    Each term ``C(n, i) p^i (1-p)^(n-i)`` is formed in log space from the exact integer
    ``math.comb(n, i)`` (``math.log`` accepts arbitrarily large ints), so no term overflows,
    and the terms are summed with ``math.fsum``.
    """
    for label, value in (("k", k), ("n", n)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ContractError(f"binomial_upper_tail: {label} must be an int, got {value!r}")
    if not 0 <= n <= MAX_HOLDOUT_EPISODES:
        raise ContractError(f"binomial_upper_tail: n must be within [0, {MAX_HOLDOUT_EPISODES}]")
    if isinstance(p, bool) or not isinstance(p, (int, float)) or not (
        math.isfinite(p) and 0.0 <= p <= 1.0
    ):
        raise ContractError(f"binomial_upper_tail: p must be within [0, 1], got {p!r}")
    if k <= 0:
        return 1.0
    if k > n:
        return 0.0
    if p == 0.0:
        return 0.0
    if p == 1.0:
        return 1.0
    log_p, log_q = math.log(p), math.log1p(-p)
    terms = [
        math.exp(math.log(math.comb(n, i)) + i * log_p + (n - i) * log_q)
        for i in range(k, n + 1)
    ]
    return min(1.0, max(0.0, math.fsum(terms)))


# --- the vault ----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BatchTicket:
    """One sealed Bonferroni family: which registrations, on which split, of what size."""

    ticket_id: str
    split: Split
    registration_ids: tuple[str, ...]
    batch_size: int


@dataclass(frozen=True, slots=True)
class VaultAccess:
    """One vault request, allowed or refused. ``refused`` is a fixed code or ``None``."""

    sequence: int
    ticket_id: str
    outcomes: int
    refused: str | None


@dataclass(frozen=True, slots=True)
class _Tally:
    """A registration's counts and cost, computed before anything is written."""

    registration: PreRegistration
    genome: HypothesisGenome
    counts: FitCounts
    units: int


class HoldoutVault:
    """One held-out split, evaluated once per sealed batch, answering only through the ledger."""

    def __init__(
        self,
        episodes: Sequence[Episode],
        *,
        split: Split,
        ledger: TheoryLedger,
        max_batches: int = MAX_HOLDOUT_BATCHES_PER_SPLIT,
        alpha: float = ALPHA,
        governor: ResearchGovernor | None = None,
    ) -> None:
        if not isinstance(split, Split) or split not in HELD_OUT_SPLITS:
            raise VaultError(f"a vault holds HOLDOUT or REPLICATION, got {split!r}")
        if not isinstance(ledger, TheoryLedger):
            raise VaultError("a vault writes through a TheoryLedger")
        if isinstance(max_batches, bool) or not isinstance(max_batches, int) or max_batches < 1:
            raise VaultError(f"max_batches must be an int >= 1, got {max_batches!r}")
        if isinstance(alpha, bool) or not isinstance(alpha, (int, float)) or not 0.0 < alpha <= 0.5:
            raise VaultError(f"alpha must be within (0, 0.5], got {alpha!r}")
        if governor is not None and not isinstance(governor, ResearchGovernor):
            raise VaultError("governor must be a ResearchGovernor or None")
        held = tuple(episodes)
        self._check_episodes(held, split)
        # The one place held-out episodes live (boundary rule 14). Nothing returns it.
        self._vault_episodes: tuple[Episode, ...] = held
        self._split = split
        self._ledger = ledger
        self._max_batches = max_batches
        self._alpha = float(alpha)
        self._governor = governor
        self._digest = split_digest(held)
        self._pending: dict[str, BatchTicket] = {}
        self._consumed: set[str] = set()
        self._log: deque[VaultAccess] = deque(maxlen=MAX_VAULT_LOG)
        self._sequence = 0
        self._n: Counter[str] = Counter()

    @staticmethod
    def _check_episodes(held: tuple[Episode, ...], split: Split) -> None:
        if not held:
            raise VaultError("a vault needs at least one episode")
        if len(held) > MAX_HOLDOUT_EPISODES:
            raise VaultError(f"{len(held)} episodes exceed the cap of {MAX_HOLDOUT_EPISODES}")
        if any(not isinstance(e, Episode) for e in held):
            raise VaultError("a vault holds Episode values only")
        if any(e.split is not split for e in held):
            raise VaultError(f"every vault episode must be {split.value}; the input mixes splits")
        if any(e.label not in (0, 1) for e in held):
            raise VaultError("every vault episode must carry a 0/1 lab label")
        if len({e.episode_id for e in held}) != len(held):
            raise VaultError("a vault episode appears twice; it would be counted twice")
        if len({e.label for e in held}) < 2:
            raise VaultError("a one-class split cannot test a detection claim")

    # --- public surface: sizes, digests, tickets, outcomes. Never an episode. -------------

    @property
    def split(self) -> Split:
        return self._split

    def size(self) -> int:
        return len(self._vault_episodes)

    def split_digest(self) -> str:
        return self._digest

    def seal_batch(self, registrations: Sequence[PreRegistration]) -> BatchTicket:
        batch = tuple(registrations)
        if not batch:
            self._refuse("empty_batch", "a batch needs at least one registration")
        if not self._admit_batch_size(len(batch)):
            self._refuse("batch_too_large", f"{len(batch)} registrations exceed the per-batch cap")
        if len(self._pending) + len(self._consumed) >= self._max_batches:
            self._refuse("batches_exhausted", f"{self._split.value}: {self._max_batches} batch(es)")
        if len({r.hypothesis_id for r in batch if isinstance(r, PreRegistration)}) != len(batch):
            self._refuse("duplicate_hypothesis", "a hypothesis appears twice in one batch")
        for registration in batch:
            self._check_registration(registration, len(batch))
        ids = tuple(r.registration_id for r in batch)
        index = len(self._pending) + len(self._consumed)
        ticket_id = "tk-" + content_digest({
            "split": self._split.value, "split_digest": self._digest,
            "registrations": list(ids), "index": index,
        })[7:31]
        ticket = BatchTicket(ticket_id, self._split, ids, len(batch))
        self._pending[ticket_id] = ticket
        self._n["batches_sealed"] += 1
        self._log_access(ticket_id, 0, None)
        return ticket

    def evaluate(self, ticket: BatchTicket) -> tuple[TestOutcome, ...]:
        ticket_id = ticket.ticket_id if isinstance(ticket, BatchTicket) else ""
        if ticket_id in self._consumed:
            self._refuse("ticket_already_evaluated", f"{ticket_id} was evaluated", ticket_id)
        if self._pending.get(ticket_id) != ticket:
            self._refuse("unknown_ticket", "this vault did not seal that ticket", ticket_id)
        # Consumed before any episode is read: a budget cut-off cannot buy a second look.
        del self._pending[ticket_id]
        self._consumed.add(ticket_id)
        tallies = [self._tally(self._require_registered(rid)) for rid in ticket.registration_ids]
        outcomes = tuple(self._outcome(tally) for tally in tallies)
        for tally, outcome in zip(tallies, outcomes, strict=True):
            self._ledger.record_result(outcome, work_units=tally.units)
            if self._split is Split.HOLDOUT:
                status = TheoryStatus.SURVIVED if outcome.survived else TheoryStatus.FALSIFIED
                self._ledger.set_status(outcome.hypothesis_id, status, reason="vault:holdout")
            self._n["survived" if outcome.survived else "falsified"] += 1
        self._n["batches_evaluated"] += 1
        self._n["outcomes_written"] += len(outcomes)
        self._log_access(ticket_id, len(outcomes), None)
        return outcomes

    def access_log(self) -> tuple[VaultAccess, ...]:
        return tuple(self._log)

    def stats(self) -> Mapping[str, int]:
        counters = dict(self._n)
        counters["size"] = len(self._vault_episodes)
        counters["max_batches"] = self._max_batches
        return MappingProxyType(counters)

    def memory_bytes(self) -> int:
        """A shallow estimate: episodes, their step tuples and feature vectors, and the log."""
        held = 0
        for episode in self._vault_episodes:
            held += sys.getsizeof(episode) + sys.getsizeof(episode.steps)
            for step in episode.steps:
                held += sys.getsizeof(step) + sys.getsizeof(getattr(step, "features", ()))
        return held + sys.getsizeof(self._log) + len(self._log) * 96 + sys.getsizeof(self._n)

    # --- internals ----------------------------------------------------------------------------

    def _refuse(self, code: str, message: str, ticket_id: str = "") -> NoReturn:
        self._n[f"refused_{code}"] += 1
        self._log_access(ticket_id, 0, code)
        raise VaultError(message)

    def _log_access(self, ticket_id: str, outcomes: int, refused: str | None) -> None:
        if len(self._log) == self._log.maxlen:
            self._n["access_log_evicted"] += 1
        self._log.append(VaultAccess(self._sequence, ticket_id, outcomes, refused))
        self._sequence += 1

    def _admit_batch_size(self, size: int) -> bool:
        if self._governor is not None:
            return self._governor.admit("max_registrations_per_batch", size - 1)
        return size <= ResearchBudget().max_registrations_per_batch

    def _check_registration(self, registration: PreRegistration, size: int) -> None:
        if not isinstance(registration, PreRegistration):
            self._refuse("not_a_registration", "seal_batch takes PreRegistration values")
        if registration.split is not self._split or registration.split_digest != self._digest:
            self._refuse("wrong_split", f"{registration.registration_id}: another split")
        if registration.batch_size != size:
            self._refuse(
                "batch_size_mismatch",
                f"{registration.registration_id}: m={registration.batch_size}, batch of {size}",
            )
        if self._ledger.preregistration(registration.registration_id) != registration:
            self._refuse("unregistered", f"{registration.registration_id}: no PREREGISTER")
        if self._ledger.outcome(registration.registration_id) is not None:
            self._refuse("already_tested", f"{registration.registration_id} already has a result")

    def _require_registered(self, registration_id: str) -> PreRegistration:
        registration = self._ledger.preregistration(registration_id)
        if registration is None:
            self._refuse("unregistered", f"{registration_id} left the ledger before evaluation")
        return registration

    def _tally(self, registration: PreRegistration) -> _Tally:
        genome = self._ledger.genome(registration.hypothesis_id)
        target = 0 if genome.direction is Direction.BENIGN else 1
        meter = self._governor.meter if self._governor is not None else WorkMeter()
        before = meter.spent
        matched = true_matches = positives = 0
        try:
            for episode in self._vault_episodes:
                is_target = episode.label == target
                positives += is_target
                if genome.decides(episode, meter=meter):
                    matched += 1
                    true_matches += is_target
        finally:
            units = meter.spent - before
            if self._governor is not None:
                self._governor.account(_VAULT_COMPONENT, units)
        counts = FitCounts(
            matched=matched, true_matches=true_matches, false_matches=matched - true_matches,
            positives=positives, negatives=len(self._vault_episodes) - positives,
        )
        return _Tally(registration, genome, counts, units)

    def _outcome(self, tally: _Tally) -> TestOutcome:
        counts, registration = tally.counts, tally.registration
        base_rate = counts.positives / (counts.positives + counts.negatives)
        p_value = binomial_upper_tail(counts.true_matches, counts.matched, base_rate)
        reasons = _refutations(
            tally.genome, self._split, counts, p_value,
            family_alpha=min(registration.alpha, self._alpha), batch_size=registration.batch_size,
        )
        return TestOutcome(
            registration_id=registration.registration_id,
            hypothesis_id=registration.hypothesis_id, split=self._split, counts=counts,
            p_value=p_value, survived=not reasons, reasons=reasons,
        )


def _rule_fires(
    kind: FalsifierKind, threshold: float, counts: FitCounts, p_value: float, corrected_alpha: float
) -> bool:
    """One HOLDOUT rule on direction-relative counts. An undefined rate refutes."""
    if kind is FalsifierKind.HOLDOUT_ENRICHMENT:
        return p_value > corrected_alpha
    if kind is FalsifierKind.HOLDOUT_FALSE_POSITIVES:
        rate = counts.false_positive_rate
        return rate is None or rate > threshold
    recall = counts.recall
    return recall is None or recall < threshold


def _refutations(
    genome: HypothesisGenome, split: Split, counts: FitCounts, p_value: float, *,
    family_alpha: float, batch_size: int,
) -> tuple[str, ...]:
    """Every registered rule for ``split`` that fires, as fixed reason codes."""
    declared = [f for f in genome.falsification_tests if f.split is split]
    if not declared:
        return ("no_registered_rule",)
    holdout_rules = {f.kind: f for f in genome.falsification_tests if f.kind in _HOLDOUT_RULES}
    reasons: list[str] = []
    for falsifier in declared:
        checks: list[tuple[FalsifierKind, float, float | None]]
        if split is Split.HOLDOUT and falsifier.kind in _HOLDOUT_RULES:
            prefix, checks = "", [(falsifier.kind, falsifier.threshold, falsifier.alpha)]
        elif split is Split.REPLICATION and falsifier.kind is FalsifierKind.REPLICATION:
            # "The three HOLDOUT rules, re-run on REPLICATION in its own batch" (spec D8.3):
            # enrichment at the REPLICATION falsifier's alpha, the two rate rules at the
            # thresholds the genome registered for HOLDOUT.
            prefix = "replication:"
            checks = [(FalsifierKind.HOLDOUT_ENRICHMENT, falsifier.threshold, falsifier.alpha)]
            checks += [
                (kind, holdout_rules[kind].threshold, None)
                for kind in (FalsifierKind.HOLDOUT_FALSE_POSITIVES, FalsifierKind.HOLDOUT_RECALL)
                if kind in holdout_rules
            ]
        else:
            reasons.append(f"{falsifier.kind.value}:not_evaluable")
            continue
        for kind, threshold, alpha in checks:
            corrected = (family_alpha if alpha is None else min(family_alpha, alpha)) / batch_size
            if _rule_fires(kind, threshold, counts, p_value, corrected):
                reasons.append(f"{prefix}{kind.value}")
    return tuple(dict.fromkeys(reasons))
