"""D5.15 — local effectiveness memory: what actually works *on this host*.

Architecture §27: ``EffectStats(context, operator)`` over ``n``, verified security
effect, no-effect, collateral, rollback success, time-to-effect and the residual
distribution, conditioned on the **epoch**. §28 gives the reason it is local: an
external defensive ontology standardises vocabulary and MITRE itself says D3FEND
does not characterise countermeasure effectiveness, so effectiveness has to be
measured here or not claimed at all.

What this module refuses to do:

- **It refuses to learn what §31 forbids.** :meth:`EffectivenessMemory.observe`
  raises on a receipt whose operator class is not in
  :data:`ALLOWED_LEARNING` for the declared source. It does not drop the row
  quietly: "PocketSec does not learn high-impact responses by trial-and-error on
  production systems" has to be a stack trace, not a log line nobody reads.
- **It refuses to report a rate it cannot support.** Every rate returns ``None``
  below :data:`MIN_SAMPLES_FOR_RATE`, and ``None`` is not zero and not a pass:
  G5.7 treats ``None`` as blocking autonomy. A rate over three samples is a
  number that feels like evidence and is not.
- **It refuses to merge across epochs.** The epoch is *inside* the key, so
  "safe last epoch" cannot be carried across a corroborated system change by
  accident. That is structural, not a policy someone can forget.
- **It refuses to grow.** ``MAX_EFFECTIVENESS_RECORDS`` bounds the table, each
  eviction writes a truncation row, and the ring of time samples is bounded too.

**Rule A — one key function.** :func:`context_key` is the *only* way a context
string is produced, and :func:`split_context_key` is its inverse. Stage 2 lost a
whole result to a join between two key spaces that could never match (S2-FC-01)
and Stage 3 shipped the same class of defect, so the planner's read key and this
module's write key are the same call, and a test asserts it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage5.executor.residual import MATERIAL_RESIDUAL
from pocketsec.stage5.executor.verify import VerificationOutcome
from pocketsec.stage5.operators.algebra import OperatorClass, TargetKind
from pocketsec.stage5.operators.catalog import spec

if TYPE_CHECKING:  # pragma: no cover - annotations only
    from pocketsec.stage5.executor.transactional import TransactionReceipt

__all__ = [
    "ALLOWED_LEARNING",
    "AUTONOMOUS_ROLLBACK_THRESHOLD",
    "CONTEXT_KEY_SEPARATOR",
    "EXECUTED_OUTCOME_NAMES",
    "MAX_EFFECTIVENESS_RECORDS",
    "MAX_TIME_SAMPLES",
    "MAX_TRUNCATION_RECORDS",
    "MIN_SAMPLES_FOR_RATE",
    "RESIDUAL_BUCKETS",
    "ContextKey",
    "EffectivenessMemory",
    "EffectivenessRecord",
    "EffectivenessTruncation",
    "LearningSource",
    "context_key",
    "residual_bucket",
    "split_context_key",
]

#: Bounded endpoint state. 256 (context, operator) pairs is roughly nine epochs
#: of the fourteen-entry catalog against two mechanisms; past that, the oldest
#: pair is evicted **and recorded**.
MAX_EFFECTIVENESS_RECORDS: int = 256
#: Below this, every rate is ``None``. A chosen parameter.
MIN_SAMPLES_FOR_RATE: int = 8
#: The residual histogram's width. Five buckets over [0, 1].
RESIDUAL_BUCKETS: int = 5
#: The time-to-effect ring. Bounded because this is endpoint state.
MAX_TIME_SAMPLES: int = 16
#: The truncation log is itself bounded; ``evictions()`` keeps the total count so
#: the number never silently caps.
MAX_TRUNCATION_RECORDS: int = 64
#: The rollback reliability an operator must show before it may act
#: autonomously. **Chosen**, not measured: the measured figure against a real
#: Linux host is UNMEASURED (§6.1, ADR-0046), and what this module can report is
#: ``simulated_rollback_success`` — a property of the simulator.
AUTONOMOUS_ROLLBACK_THRESHOLD: float = 0.98

#: ``require_identifier``'s pattern admits ``[A-Za-z0-9._:-]`` and nothing else,
#: so ``|`` cannot occur inside a validated mechanism id and splitting on it is
#: unambiguous. That is why the separator may be a single character.
CONTEXT_KEY_SEPARATOR: str = "|"

#: ``Outcome`` member names that mean the action reached the host. Mirrored
#: rather than imported: ``executor/transactional.py`` sits at the top of the
#: privileged import graph and this module must not pull it in to count a row.
#: A refused or escalated receipt is evidence about the *gate*, not about the
#: operator's effect, so it is counted by ``not_executed()`` instead of diluting
#: ``n``.
EXECUTED_OUTCOME_NAMES: frozenset[str] = frozenset(
    {
        "COMMITTED_VERIFIED",
        "COMMITTED_UNVERIFIED",
        "ROLLED_BACK",
        "ROLLBACK_FAILED",
    }
)


class LearningSource(StrEnum):
    """§31's table, as an enum rather than prose."""

    OFFLINE_REPLAY = "OFFLINE_REPLAY"
    LAB_SANDBOX = "LAB_SANDBOX"
    PRODUCTION_OBSERVATION = "PRODUCTION_OBSERVATION"
    HUMAN_APPROVED_ACTION = "HUMAN_APPROVED_ACTION"
    AUTONOMOUS_LOW_IMPACT = "AUTONOMOUS_LOW_IMPACT"


_ALL_CLASSES: frozenset[OperatorClass] = frozenset(OperatorClass)

#: §31, read as code. The two rows that matter are ``PRODUCTION_OBSERVATION``
#: (effect estimation without disruptive exploration — so O0 and O1 only) and
#: ``AUTONOMOUS_LOW_IMPACT`` (only inside the validated SAFE envelope — so up to
#: O3, which is where ``MAX_AUTONOMOUS_AUTHORITY = A2`` runs out).
ALLOWED_LEARNING: Mapping[LearningSource, frozenset[OperatorClass]] = MappingProxyType(
    {
        LearningSource.OFFLINE_REPLAY: _ALL_CLASSES,
        LearningSource.LAB_SANDBOX: frozenset(
            {
                OperatorClass.O0_OBSERVE,
                OperatorClass.O1_PRESERVE,
                OperatorClass.O2_REVERSIBLE_RESTRICT,
                OperatorClass.O3_SUSPEND,
                OperatorClass.O4_LOCAL_REVOKE,
                OperatorClass.O5_SERVICE_CONTAINMENT,
                OperatorClass.O6_DISRUPTIVE,
            }
        ),
        LearningSource.PRODUCTION_OBSERVATION: frozenset(
            {OperatorClass.O0_OBSERVE, OperatorClass.O1_PRESERVE}
        ),
        LearningSource.HUMAN_APPROVED_ACTION: _ALL_CLASSES,
        LearningSource.AUTONOMOUS_LOW_IMPACT: frozenset(
            {
                OperatorClass.O0_OBSERVE,
                OperatorClass.O1_PRESERVE,
                OperatorClass.O2_REVERSIBLE_RESTRICT,
                OperatorClass.O3_SUSPEND,
            }
        ),
    }
)

assert set(ALLOWED_LEARNING) == set(LearningSource), (
    "ALLOWED_LEARNING must be total over LearningSource: an unmapped source "
    "would fall through to a KeyError at the one place §31 is enforced"
)


def context_key(*, epoch_id: int, mechanism_id: str, target_kind: TargetKind) -> str:
    """THE key. The planner reads with it and the memory writes with it.

    The epoch is the first component so that a lexicographic scan groups by
    epoch, and it is *in* the key so no code path can average an operator's
    behaviour across a system change.
    """
    require_non_negative_int(epoch_id, "context_key.epoch_id")
    require_identifier(mechanism_id, "context_key.mechanism_id")
    if not isinstance(target_kind, TargetKind):
        raise ContractError(
            f"context_key.target_kind must be a TargetKind, got {target_kind!r}"
        )
    return CONTEXT_KEY_SEPARATOR.join(
        (str(epoch_id), mechanism_id, target_kind.value)
    )


@dataclass(frozen=True, slots=True)
class ContextKey:
    """The parsed form of a context key."""

    epoch_id: int
    mechanism_id: str
    target_kind: TargetKind


def split_context_key(key: str) -> ContextKey:
    """The inverse of :func:`context_key`, and the only sanctioned parse.

    It lives beside the producer so the two cannot drift: a second parser
    somewhere else is how two key spaces are born.
    """
    parts = key.split(CONTEXT_KEY_SEPARATOR)
    if len(parts) != 3:
        raise ContractError(f"not a context key: {key!r}")
    epoch_text, mechanism_id, kind_text = parts
    if not epoch_text.isdigit():
        raise ContractError(f"context key {key!r} has a non-numeric epoch")
    try:
        target_kind = TargetKind(kind_text)
    except ValueError as exc:
        raise ContractError(
            f"context key {key!r} names an unknown target kind {kind_text!r}"
        ) from exc
    return ContextKey(
        epoch_id=int(epoch_text),
        mechanism_id=require_identifier(mechanism_id, "context key mechanism_id"),
        target_kind=target_kind,
    )


def residual_bucket(distance: float) -> int:
    """Index a residual distance into :data:`RESIDUAL_BUCKETS` buckets."""
    if distance < 0.0 or distance > 1.0:
        raise ContractError(f"residual distance must be in [0, 1], got {distance!r}")
    return min(int(distance * RESIDUAL_BUCKETS), RESIDUAL_BUCKETS - 1)


@dataclass(frozen=True, slots=True)
class EffectivenessRecord:
    """§27's ``EffectStats``, field for field, for one (context, operator) pair."""

    context: str
    operator_id: str
    epoch_id: int
    n: int = 0
    verified_security_effect: int = 0
    no_effect: int = 0
    collateral: int = 0
    rollback_attempts: int = 0
    rollback_successes: int = 0
    time_to_effect_units: tuple[int, ...] = ()
    residual_buckets: tuple[int, ...] = (0,) * RESIDUAL_BUCKETS

    def __post_init__(self) -> None:
        parsed = split_context_key(self.context)
        if parsed.epoch_id != self.epoch_id:
            raise ContractError(
                f"EffectivenessRecord.context {self.context!r} names epoch "
                f"{parsed.epoch_id} but the record says {self.epoch_id}; a record "
                "whose key and payload disagree is the S2-FC-01 defect"
            )
        require_identifier(self.operator_id, "EffectivenessRecord.operator_id")
        if len(self.residual_buckets) != RESIDUAL_BUCKETS:
            raise ContractError(
                f"EffectivenessRecord.residual_buckets must have length "
                f"{RESIDUAL_BUCKETS}, got {len(self.residual_buckets)}"
            )
        if len(self.time_to_effect_units) > MAX_TIME_SAMPLES:
            raise ContractError(
                "EffectivenessRecord.time_to_effect_units exceeds "
                f"MAX_TIME_SAMPLES={MAX_TIME_SAMPLES}"
            )
        if self.rollback_successes > self.rollback_attempts:
            raise ContractError(
                "EffectivenessRecord cannot have more rollback successes than attempts"
            )

    def effect_rate(self) -> float | None:
        """``None`` below :data:`MIN_SAMPLES_FOR_RATE`. ``None`` is not zero."""
        if self.n < MIN_SAMPLES_FOR_RATE:
            return None
        return self.verified_security_effect / self.n

    def collateral_rate(self) -> float | None:
        if self.n < MIN_SAMPLES_FOR_RATE:
            return None
        return self.collateral / self.n

    def simulated_rollback_success(self) -> float | None:
        """Named for what it is: a rate measured inside the simulated host.

        The name carries the caveat into every table it appears in (ADR-0046).
        """
        if self.rollback_attempts < MIN_SAMPLES_FOR_RATE:
            return None
        return self.rollback_successes / self.rollback_attempts

    def to_dict(self) -> dict[str, Any]:
        return {
            "context": self.context,
            "operator_id": self.operator_id,
            "epoch_id": self.epoch_id,
            "n": self.n,
            "verified_security_effect": self.verified_security_effect,
            "no_effect": self.no_effect,
            "collateral": self.collateral,
            "rollback_attempts": self.rollback_attempts,
            "rollback_successes": self.rollback_successes,
            "time_to_effect_units": list(self.time_to_effect_units),
            "residual_buckets": list(self.residual_buckets),
            "effect_rate": self.effect_rate(),
            "collateral_rate": self.collateral_rate(),
            "simulated_rollback_success": self.simulated_rollback_success(),
            "min_samples_for_rate": MIN_SAMPLES_FOR_RATE,
        }


@dataclass(frozen=True, slots=True)
class EffectivenessTruncation:
    """One eviction, recorded. Truncation is explicit or it is data loss."""

    what: str
    identifier: str
    reason: str
    samples_dropped: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "what": self.what,
            "identifier": self.identifier,
            "reason": self.reason,
            "samples_dropped": self.samples_dropped,
        }


def _bump(buckets: tuple[int, ...], index: int) -> tuple[int, ...]:
    values = list(buckets)
    values[index] += 1
    return tuple(values)


def _ring(samples: tuple[int, ...], value: int) -> tuple[int, ...]:
    return (*samples, value)[-MAX_TIME_SAMPLES:]


class EffectivenessMemory:
    """Bounded, epoch-conditioned, LRU-evicting statistics over receipts."""

    def __init__(self, *, max_records: int = MAX_EFFECTIVENESS_RECORDS) -> None:
        if max_records < 1:
            raise ContractError("EffectivenessMemory.max_records must be >= 1")
        self._max_records = max_records
        self._records: dict[tuple[str, str], EffectivenessRecord] = {}
        self._truncations: list[EffectivenessTruncation] = []
        self._evictions = 0
        self._not_executed = 0

    def observe(
        self,
        receipt: TransactionReceipt,
        *,
        source: LearningSource,
        mechanism_id: str,
    ) -> None:
        """Fold one receipt in, or raise because §31 forbids learning it.

        The raise is the point. A silently dropped row would leave the memory
        looking well-populated while the one rule that keeps disruptive
        exploration off production hosts had been violated.
        """
        if not isinstance(source, LearningSource):
            raise ContractError(f"observe.source must be a LearningSource, got {source!r}")
        allowed = ALLOWED_LEARNING[source]
        if receipt.operator_class not in allowed:
            raise ContractError(
                f"§31 forbids learning {receipt.operator_class.name} from "
                f"{source.value}: allowed classes are "
                f"{sorted(cls.name for cls in allowed)}"
            )
        target_kind = spec(receipt.operator_id).target_kind
        context = context_key(
            epoch_id=receipt.epoch_id,
            mechanism_id=mechanism_id,
            target_kind=target_kind,
        )
        if receipt.outcome.name not in EXECUTED_OUTCOME_NAMES:
            self._not_executed += 1
            return
        key = (context, receipt.operator_id)
        current = self._records.pop(key, None) or EffectivenessRecord(
            context=context,
            operator_id=receipt.operator_id,
            epoch_id=receipt.epoch_id,
        )
        self._records[key] = _fold(current, receipt)
        self._evict_while_over_bound()

    def record(self, *, context: str, operator_id: str) -> EffectivenessRecord | None:
        """The planner's read. Touching a record refreshes its LRU position."""
        key = (context, operator_id)
        found = self._records.pop(key, None)
        if found is None:
            return None
        self._records[key] = found
        return found

    def rollback_reliability(
        self, *, operator_id: str, epoch_id: int
    ) -> float | None:
        """``None`` below :data:`MIN_SAMPLES_FOR_RATE` **attempts**, and ``None``
        blocks autonomy rather than defaulting to a pass."""
        attempts = 0
        successes = 0
        for record in self._records.values():
            if record.operator_id != operator_id or record.epoch_id != epoch_id:
                continue
            attempts += record.rollback_attempts
            successes += record.rollback_successes
        if attempts < MIN_SAMPLES_FOR_RATE:
            return None
        return successes / attempts

    def meets_threshold(
        self, *, operator_id: str, epoch_id: int, threshold: float
    ) -> bool | None:
        reliability = self.rollback_reliability(
            operator_id=operator_id, epoch_id=epoch_id
        )
        if reliability is None:
            return None
        return reliability >= threshold

    def evictions(self) -> int:
        return self._evictions

    def not_executed(self) -> int:
        """Receipts that never reached the host. Visible, not discarded."""
        return self._not_executed

    def truncations(self) -> tuple[EffectivenessTruncation, ...]:
        return tuple(self._truncations)

    def rows(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(
            MappingProxyType(record.to_dict()) for record in self._records.values()
        )

    def _evict_while_over_bound(self) -> None:
        while len(self._records) > self._max_records:
            key, evicted = next(iter(self._records.items()))
            del self._records[key]
            self._evictions += 1
            self._note_truncation(evicted)

    def _note_truncation(self, evicted: EffectivenessRecord) -> None:
        if len(self._truncations) >= MAX_TRUNCATION_RECORDS:
            self._truncations.pop(0)
        self._truncations.append(
            EffectivenessTruncation(
                what="effectiveness_record",
                identifier=f"{evicted.context}#{evicted.operator_id}",
                reason=f"max_records={self._max_records} reached; least recently used",
                samples_dropped=evicted.n,
            )
        )


def _fold(record: EffectivenessRecord, receipt: TransactionReceipt) -> EffectivenessRecord:
    """Apply one receipt to a record, returning a new record.

    ``UNVERIFIABLE`` counts in ``n`` and in neither ``verified_security_effect``
    nor ``no_effect``: an action nobody could verify is not evidence that it
    worked and not evidence that it failed (ADR-0004).
    """
    verification = receipt.verification
    residual = receipt.residual
    collateral = verification is VerificationOutcome.DIVERGENT or (
        residual is not None and residual.distance >= MATERIAL_RESIDUAL
    )
    buckets = record.residual_buckets
    if residual is not None:
        buckets = _bump(buckets, residual_bucket(residual.distance))
    return replace(
        record,
        n=record.n + 1,
        verified_security_effect=record.verified_security_effect
        + int(verification is VerificationOutcome.EFFECTIVE),
        no_effect=record.no_effect
        + int(verification is VerificationOutcome.INEFFECTIVE),
        collateral=record.collateral + int(collateral),
        rollback_attempts=record.rollback_attempts + int(receipt.rollback_attempted),
        rollback_successes=record.rollback_successes
        + int(receipt.rollback_succeeded is True),
        # Work units, not milliseconds: this host's load average swung 8→67
        # between two runs of one gate, so a millisecond sample would be a
        # measurement of the other wave's test run (§2.8).
        time_to_effect_units=_ring(record.time_to_effect_units, receipt.work_units),
        residual_buckets=buckets,
    )
