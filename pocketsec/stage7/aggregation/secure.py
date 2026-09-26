"""D7.17 / ORPH-F18 — optional pairwise-masking secure sum, OFF by default.

**What it is (ADR-0066).** Bonawitz et al.'s *masking layer only*: every pair of
participants shares a key; for each round each pair derives the same pseudo-random vector
(HMAC-SHA256 in counter mode); the participant with the lower id adds it and the one with
the higher id subtracts it, modulo :data:`MODULUS`. Every mask cancels in the sum, so an
aggregator that receives all masked vectors learns **the total and nothing else** about any
single participant's vector — under the assumption that the pair keys are secret.

**What it protects.** Each host's count vector (the per-round population counts that feed
collective novelty, D7.14) from an **honest-but-curious** aggregator that follows the
protocol and only looks at what it receives.

**What it does NOT do — each a deliberate, declared gap, not an oversight:**

* **No key agreement.** Stdlib has no Diffie-Hellman or X25519, and hand-rolling one is out
  of scope. Pair keys are *simulated and pre-provisioned* by the caller; whoever provisions
  them can unmask everyone. Real key agreement is UNMEASURED.
* **No authentication.** A masked vector names its participant; nothing proves it. A
  participant may submit any values it likes, and the sum hides which one lied.
* **No dropout tolerance.** Shamir-based mask recovery is not built. A missing participant
  leaves its pairwise masks uncancelled, so :func:`aggregate_masked` **aborts the round and
  returns no total at all** (§43 "abort round; no partial unsafe update"): a partial sum
  would be uniformly random garbage presented as a count.
* **No malicious-aggregator detection.** An aggregator that alters the total is caught only
  if a participant cross-checks it out of band (S7X-47 measures it as undetected).
* **It prevents exactly the per-client inspection Byzantine filtering needs.** Under masking
  the receiver cannot clamp, cluster or drop a single Sybil's inflated counts. That is the
  trade-off the suite measures (secure sum vs plaintext sum with per-cluster clamping); it
  is the reason this module is off by default and why no privacy guarantee is claimed beyond
  "the aggregator sees only the sum, under the simulated key assumption".

The sum is exact modulo 2**32: callers keep per-coordinate totals below :data:`MODULUS`
(counts of at most :data:`MAX_PARTICIPANTS` hosts are far below it).

Stdlib only (``hmac``, ``hashlib``). No network, no execution primitive.
"""

from __future__ import annotations

import hashlib
import hmac
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_identifier,
    require_non_negative_int,
)

__all__ = [
    "MAX_PARTICIPANTS",
    "MAX_VECTOR_LEN",
    "MIN_PAIR_KEY_BYTES",
    "MODULUS",
    "SECURE_AGGREGATION_ENABLED",
    "MaskedVector",
    "SecureRoundResult",
    "aggregate_masked",
    "mask_vector",
    "memory_bytes_of",
    "pairwise_mask",
]

#: §28 / ADR-0066: off by default. No runtime path in Stage 7 calls this module; only the
#: labs (D7.14 population counts, S7X-19/20/47) exercise it, explicitly.
SECURE_AGGREGATION_ENABLED: bool = False
MODULUS: int = 2**32
#: §4.23. Chosen parameters, not measurements.
MAX_PARTICIPANTS: int = 256
MAX_VECTOR_LEN: int = 1024
#: A 128-bit floor on pair keys, matching Stage 6's MIN_KEY_BYTES; chosen.
MIN_PAIR_KEY_BYTES: int = 16

_WORD_BYTES = 4  # one coordinate of a 2**32 modulus
_WORDS_PER_BLOCK = hashlib.sha256().digest_size // _WORD_BYTES


@dataclass(frozen=True, slots=True)
class MaskedVector:
    """What one participant sends the aggregator: its vector plus every pairwise mask."""

    participant: str
    round_index: int
    values: tuple[int, ...]

    def __post_init__(self) -> None:
        require_identifier(self.participant, "MaskedVector.participant")
        require_non_negative_int(self.round_index, "MaskedVector.round_index")
        values = tuple(self.values)
        if not 1 <= len(values) <= MAX_VECTOR_LEN:
            raise ContractError(f"a masked vector holds 1..{MAX_VECTOR_LEN} coordinates")
        if not _all_words(values):
            raise ContractError(f"masked coordinates are ints in [0, {MODULUS})")
        object.__setattr__(self, "values", values)


@dataclass(frozen=True, slots=True)
class SecureRoundResult:
    """The round's outcome. ``total is None`` exactly when the round aborted."""

    round_index: int
    participants: tuple[str, ...]
    total: tuple[int, ...] | None
    aborted: bool
    reason: str
    bytes_exchanged: int

    def __post_init__(self) -> None:
        if self.aborted != (self.total is None):
            raise ContractError("an aborted round carries no total, and only an aborted one")


def _all_words(values: Sequence[object]) -> bool:
    return all(
        not isinstance(v, bool) and isinstance(v, int) and 0 <= v < MODULUS for v in values
    )


def _require_key(key: object) -> bytes:
    if not isinstance(key, bytes) or len(key) < MIN_PAIR_KEY_BYTES:
        raise ContractError(f"a pair key must be bytes of at least {MIN_PAIR_KEY_BYTES}")
    return key


def pairwise_mask(pair_key: bytes, *, round_index: int, length: int) -> tuple[int, ...]:
    """HMAC-SHA256 counter-mode PRG: ``length`` words in ``[0, MODULUS)`` for this round.

    Both members of a pair derive the identical vector; a new round gives a fresh mask, so a
    mask is never reused across rounds (reuse would let the aggregator difference two rounds).
    """
    key = _require_key(pair_key)
    require_non_negative_int(round_index, "round_index")
    if isinstance(length, bool) or not isinstance(length, int) or not 1 <= length <= MAX_VECTOR_LEN:
        raise ContractError(f"length must be an int in 1..{MAX_VECTOR_LEN}")
    words: list[int] = []
    counter = 0
    while len(words) < length:
        block = hmac.new(
            key, f"stage7-secure-sum|{round_index}|{counter}".encode("ascii"), hashlib.sha256
        ).digest()
        words.extend(
            int.from_bytes(block[i * _WORD_BYTES : (i + 1) * _WORD_BYTES], "big")
            for i in range(_WORDS_PER_BLOCK)
        )
        counter += 1
    return tuple(words[:length])


def mask_vector(
    values: Sequence[int], *, participant: str, pair_keys: Mapping[str, bytes], round_index: int
) -> MaskedVector:
    """``values`` plus the mask shared with every higher id, minus every lower id, mod 2**32.

    ``pair_keys`` maps each OTHER participant to the key this participant shares with it.
    """
    require_identifier(participant, "participant")
    vector = tuple(values)
    if not 1 <= len(vector) <= MAX_VECTOR_LEN:
        raise ContractError(f"a vector holds 1..{MAX_VECTOR_LEN} coordinates")
    if not _all_words(vector):
        raise ContractError(f"values are ints in [0, {MODULUS})")
    if participant in pair_keys:
        raise ContractError("a participant shares no pair key with itself")
    if len(pair_keys) + 1 > MAX_PARTICIPANTS:
        raise ContractError(f"at most {MAX_PARTICIPANTS} participants")
    masked = list(vector)
    for other, key in sorted(pair_keys.items()):
        require_identifier(other, "pair_keys[]")
        mask = pairwise_mask(key, round_index=round_index, length=len(vector))
        sign = 1 if other > participant else -1
        masked = [(m + sign * k) % MODULUS for m, k in zip(masked, mask, strict=True)]
    return MaskedVector(participant=participant, round_index=round_index, values=tuple(masked))


def _abort(
    round_index: int, participants: tuple[str, ...], reason: str, size: int
) -> SecureRoundResult:
    return SecureRoundResult(
        round_index=round_index, participants=participants, total=None, aborted=True,
        reason=reason, bytes_exchanged=size,
    )


def _refusal(
    vectors: Sequence[MaskedVector], expected: frozenset[str], round_index: int
) -> str | None:
    if not expected or len(expected) > MAX_PARTICIPANTS:
        return "bad_participant_set"
    names = [v.participant for v in vectors]
    if len(set(names)) != len(names):
        return "duplicate_participant"
    if set(names) - expected:
        return "unexpected_participant"
    if expected - set(names):
        return "missing_participant"  # dropout: masks do not cancel, and recovery is not built
    if any(v.round_index != round_index for v in vectors):
        return "wrong_round"
    if len({len(v.values) for v in vectors}) != 1:
        return "length_mismatch"
    return None


def aggregate_masked(
    vectors: Sequence[MaskedVector], *, expected: frozenset[str], round_index: int
) -> SecureRoundResult:
    """The coordinate-wise sum mod 2**32 of exactly the ``expected`` participants' vectors.

    ANY deviation — a missing participant (dropout), an unexpected or duplicate one, a vector
    from another round, a length mismatch — ABORTS the round with ``total=None``. There is
    never a partial total.
    """
    require_non_negative_int(round_index, "round_index")
    received = tuple(vectors)
    if not all(isinstance(v, MaskedVector) for v in received):
        raise ContractError("aggregate_masked sums MaskedVector values")
    names = tuple(sorted(v.participant for v in received))
    size = sum(_WORD_BYTES * len(v.values) for v in received)
    reason = _refusal(received, frozenset(expected), round_index)
    if reason is not None:
        return _abort(round_index, names, reason, size)
    total = [0] * len(received[0].values)
    for vector in received:
        total = [(t + v) % MODULUS for t, v in zip(total, vector.values, strict=True)]
    return SecureRoundResult(
        round_index=round_index, participants=names, total=tuple(total), aborted=False,
        reason="ok", bytes_exchanged=size,
    )


def memory_bytes_of(vectors: Sequence[MaskedVector]) -> int:
    """An upper-bound estimate of a round's buffered vectors (for resource accounting)."""
    return sum(sys.getsizeof(v) + sys.getsizeof(v.values) + 36 * len(v.values) for v in vectors)
