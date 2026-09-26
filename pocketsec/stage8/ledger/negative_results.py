"""D8.11 / PROM-F15 — negative-result memory: what Stage 8 already learned does not work.

A discovery engine without a memory of its failures re-proposes them: the same refuted
mechanism reappears under a new residual cluster, a new scope or a new generator, costs a
fresh preregistration slot and dilutes the next Bonferroni family. This store keeps one
compact :class:`NegativeResult` per refuted or retired mechanism so PROMETHEUS can skip a
known dead end *before* it spends budget on it (``PrometheusEngine`` calls
:meth:`NegativeResultMemory.is_dead_end`, and every hit is counted so an ablation can show
whether the memory ever changed an outcome — a store that is never hit is INERT).

**Exact, not fuzzy, and per direction.** A reading is a dead end only if its
``Mechanism.digest()`` *and* its ``Direction`` equal a remembered one. A near neighbour of a
refuted mechanism is a *different* hypothesis and may be true; skipping it by similarity would
be the engine deciding a scientific question with no test. So is the other reading of the same
mechanism: a refuted MALICIOUS:M says nothing about BENIGN:M (the engine keeps both on purpose),
so memory is keyed by ``(digest, direction)`` and a refutation never silences the null-benign
reading the architecture requires to be tested.

**A dead end is never overwritten by a retirement.** A later FOSSILIZED or
INSUFFICIENT_EVIDENCE record for the same reading does not replace a refuted one: that would
erase the refutation (the ledger folds records at its cap, so a sibling's eviction would
otherwise resurrect a refuted mechanism). The newer record is counted
(``dead_end_kept``) and dropped.

**Refuted is not the same as retired.** Everything terminal and non-REPRODUCED is
remembered (the ledger folds such records here), but only the three *refuted* statuses —
``CHALLENGED_OUT``, ``FALSIFIED``, ``NOT_REPRODUCED`` — make a mechanism a dead end.
``INSUFFICIENT_EVIDENCE`` means the data could not decide, and ``FOSSILIZED`` means the
ecology evicted the hypothesis for room, not that anything refuted it; treating either as
a dead end would turn "unknown" into "false", which DL-06 forbids.

**Bounded.** At most ``capacity`` results. When full, the least recently *hit* result is
evicted (a result nobody re-proposes is the cheapest to forget) and the eviction is
counted. The store holds ids and digests only — never an episode, a step or a label.

This module also holds the ledger package's canonical JSON encoding (:func:`canonical_bytes`)
and its reason-code vocabulary, because ``theory`` imports this module and not the reverse.
"""

from __future__ import annotations

import json
import math
import re
import sys
from collections import Counter, OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError, require_non_negative_int
from pocketsec.stage8.genome.grammar import Mechanism
from pocketsec.stage8.genome.hypothesis import Direction, FalsifierKind

if TYPE_CHECKING:
    from pocketsec.stage8.ledger.theory import TheoryStatus

__all__ = [
    "DEAD_END_STATUS_NAMES",
    "EPISODE_ID",
    "MAX_COUNTEREXAMPLES",
    "MAX_NEGATIVE_RESULTS",
    "REASON_CODE",
    "NegativeResult",
    "NegativeResultMemory",
    "canonical_bytes",
    "freeze_plain",
    "plain_data",
]

#: Spec §4.21. Chosen, not measured.
MAX_NEGATIVE_RESULTS: int = 1024
MAX_COUNTEREXAMPLES: int = 4

#: The statuses that *refute* a mechanism. Named, not imported, because ``theory`` imports
#: this module; ``NegativeResult`` checks the status against ``TheoryStatus`` at runtime.
DEAD_END_STATUS_NAMES: frozenset[str] = frozenset(
    {"CHALLENGED_OUT", "FALSIFIED", "NOT_REPRODUCED"}
)
_REMEMBERED_STATUS_NAMES: frozenset[str] = DEAD_END_STATUS_NAMES | {
    "INSUFFICIENT_EVIDENCE",
    "FOSSILIZED",
}

#: A fixed-vocabulary reason code: no spaces, no free text. Shared with the ledger so a
#: caller cannot smuggle a raw proposal string into durable state as a "reason" (G8.2).
REASON_CODE = re.compile(r"^[A-Za-z0-9_.:\-+=<>/]{1,96}$")
_MECHANISM_ID = re.compile(r"^mech-[0-9a-f]{16}$")
_HYPOTHESIS_ID = re.compile(r"^hyp-[0-9a-f]{24}$")
EPISODE_ID = re.compile(r"^ep-[0-9a-f]{24}$")


# --- canonical encoding, shared by the ledger package (theory imports this module) ----


def plain_data(value: Any) -> Any:
    """A JSON-ready copy of ``value``; refuses anything that is not plain data."""
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ContractError(f"canonical data must be finite, got {value!r}")
        return value
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ContractError(f"canonical mapping keys must be str, got {key!r}")
            out[key] = plain_data(item)
        return out
    if isinstance(value, (list, tuple)):
        return [plain_data(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(plain_data(item) for item in value)
    raise ContractError(f"not canonical plain data: {type(value).__name__}")


def canonical_bytes(payload: Any) -> bytes:
    """Sorted-key, separator-free, ASCII JSON: the one encoding every Stage 8 digest uses here."""
    return json.dumps(
        plain_data(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def freeze_plain(value: Any) -> Any:
    """Deep-freeze plain data so a retained payload cannot be edited through an alias."""
    if isinstance(value, dict):
        return MappingProxyType({key: freeze_plain(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(freeze_plain(item) for item in value)
    return value



@dataclass(frozen=True, slots=True)
class NegativeResult:
    """One retired hypothesis, reduced to what the engine needs to avoid repeating it."""

    mechanism_digest: str
    hypothesis_id: str
    status: TheoryStatus
    refutation: FalsifierKind | None
    reason: str
    counterexample_ids: tuple[str, ...]
    recorded_sequence: int
    #: The reading that was refuted or retired. A mechanism refuted as MALICIOUS is not
    #: refuted as BENIGN; memory is keyed by ``(mechanism_digest, direction)`` (F4).
    direction: Direction

    def __post_init__(self) -> None:
        from pocketsec.stage8.ledger.theory import TheoryStatus  # deferred: theory imports us

        if not isinstance(self.mechanism_digest, str) or not _MECHANISM_ID.fullmatch(
            self.mechanism_digest
        ):
            raise ContractError(f"not a mechanism digest: {self.mechanism_digest!r}")
        if not isinstance(self.hypothesis_id, str) or not _HYPOTHESIS_ID.fullmatch(
            self.hypothesis_id
        ):
            raise ContractError(f"hypothesis_id must be 'hyp-'+24 hex, got {self.hypothesis_id!r}")
        if not isinstance(self.status, TheoryStatus):
            raise ContractError(f"status must be a TheoryStatus, got {self.status!r}")
        if self.status.name not in _REMEMBERED_STATUS_NAMES:
            raise ContractError(
                f"only terminal non-REPRODUCED theories are remembered, got {self.status.name}"
            )
        if self.refutation is not None and not isinstance(self.refutation, FalsifierKind):
            raise ContractError(f"refutation must be a FalsifierKind or None: {self.refutation!r}")
        if not isinstance(self.reason, str) or not REASON_CODE.fullmatch(self.reason):
            raise ContractError(f"reason must be a fixed-vocabulary code, got {self.reason!r}")
        object.__setattr__(self, "counterexample_ids", tuple(self.counterexample_ids))
        if len(self.counterexample_ids) > MAX_COUNTEREXAMPLES:
            raise ContractError(f"at most {MAX_COUNTEREXAMPLES} counterexample ids")
        for episode_id in self.counterexample_ids:
            if not isinstance(episode_id, str) or not EPISODE_ID.fullmatch(episode_id):
                raise ContractError(f"counterexample ids are episode ids, got {episode_id!r}")
        require_non_negative_int(self.recorded_sequence, "NegativeResult.recorded_sequence")
        if not isinstance(self.direction, Direction):
            raise ContractError(f"direction must be a Direction, got {self.direction!r}")

    @property
    def key(self) -> tuple[str, Direction]:
        """The memory key: one reading of one mechanism."""
        return self.mechanism_digest, self.direction

    @property
    def dead_end(self) -> bool:
        """True iff the status refutes the mechanism (not merely retires it)."""
        return self.status.name in DEAD_END_STATUS_NAMES


class NegativeResultMemory:
    """A bounded, LRU-by-hit map from (mechanism digest, direction) to its negative result."""

    __slots__ = ("_by_key", "_by_hypothesis", "_capacity", "_n")

    def __init__(self, *, capacity: int = MAX_NEGATIVE_RESULTS) -> None:
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
            raise ContractError(f"capacity must be an int >= 1, got {capacity!r}")
        self._capacity = capacity
        self._by_key: OrderedDict[tuple[str, Direction], NegativeResult] = OrderedDict()
        self._by_hypothesis: dict[str, tuple[str, Direction]] = {}
        self._n: Counter[str] = Counter()

    @property
    def capacity(self) -> int:
        return self._capacity

    def remember(self, result: NegativeResult) -> None:
        """Store ``result``; a newer result for the same reading replaces the older one, except
        that a retirement (not a dead end) never replaces a refutation (a dead end)."""
        if not isinstance(result, NegativeResult):
            raise ContractError(f"remember takes a NegativeResult, got {type(result).__name__}")
        key = result.key
        previous = self._by_key.get(key)
        if previous is not None and previous.dead_end and not result.dead_end:
            # F5: a sibling retired for room must not erase the refutation of its mechanism.
            self._n["dead_end_kept"] += 1
            return
        if previous is not None:
            del self._by_key[key]
            self._by_hypothesis.pop(previous.hypothesis_id, None)
            self._n["replaced"] += 1
        elif len(self._by_key) >= self._capacity:
            _, evicted = self._by_key.popitem(last=False)
            self._by_hypothesis.pop(evicted.hypothesis_id, None)
            self._n["evicted"] += 1
        self._by_key[key] = result
        self._by_hypothesis[result.hypothesis_id] = key
        self._n["remembered"] += 1

    def is_dead_end(self, mechanism: Mechanism, direction: Direction) -> bool:
        """Whether this reading of ``mechanism`` was already refuted. A hit refreshes its recency
        and is counted. The other direction's refutation is not consulted (F4)."""
        if not isinstance(mechanism, Mechanism):
            raise ContractError(f"is_dead_end takes a Mechanism, got {type(mechanism).__name__}")
        if not isinstance(direction, Direction):
            raise ContractError(f"is_dead_end needs a Direction, got {direction!r}")
        self._n["lookups"] += 1
        key = (mechanism.digest(), direction)
        result = self._by_key.get(key)
        if result is None:
            return False
        self._by_key.move_to_end(key)
        if not result.dead_end:
            self._n["retired_not_dead_end"] += 1
            return False
        self._n["hits"] += 1
        return True

    def result_for_hypothesis(self, hypothesis_id: str) -> NegativeResult | None:
        """The remembered result of one hypothesis id, without counting a hit."""
        key = self._by_hypothesis.get(hypothesis_id)
        return None if key is None else self._by_key[key]

    def results(self) -> tuple[NegativeResult, ...]:
        """Oldest-hit first."""
        return tuple(self._by_key.values())

    def __len__(self) -> int:
        return len(self._by_key)

    def stats(self) -> Mapping[str, int]:
        counters = dict(self._n)
        counters["size"] = len(self._by_key)
        counters["capacity"] = self._capacity
        return MappingProxyType(counters)

    def memory_bytes(self) -> int:
        per = sum(
            sys.getsizeof(result) + sys.getsizeof(result.mechanism_digest)
            + sys.getsizeof(result.hypothesis_id) + sys.getsizeof(result.reason)
            + sum(sys.getsizeof(item) + 8 for item in result.counterexample_ids)
            for result in self._by_key.values()
        )
        return (
            per + sys.getsizeof(self._by_key) + sys.getsizeof(self._by_hypothesis)
            + sys.getsizeof(self._n)
        )
