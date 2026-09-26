"""D5.11 — the bounded, digest-chained rollback journal.

The journal is the reason a containment action is *reversible* rather than
merely *reversible in principle*. It holds, for every in-flight and recently
finished action, the pre-action state needed to undo it, plus a tamper-evident
record of which phase of the transaction happened when.

**Why it refuses instead of evicting.** Every other bounded structure in this
project evicts its oldest entry when it fills. This one must not: evicting the
rollback state of an action whose lease is still live turns a reversible
intervention into a permanent one, which is precisely the failure architecture
§18 exists to prevent. So :meth:`RollbackJournal.full` is forward-looking — it
answers "can a whole new action still fit" — and :meth:`RollbackJournal.append`
raises rather than making room. The executor maps that refusal to
``Outcome.REFUSED_JOURNAL_FULL``: the system stops acting before it starts acting
irreversibly. Every refusal is recorded as a :class:`JournalTruncation`, because
a bound that silently drops work is indistinguishable from a bug.

**Why the chain is walked over recomputed digests.** ``ExperimentRegistry.
verify_integrity`` learned this the hard way: verifying against the *stored*
digests lets a single-row edit slip through with only a local mismatch.
:meth:`RollbackJournal.verify_chain` recomputes each entry's digest and feeds the
recomputed value forward, so editing any entry invalidates every link after it.
This is tamper-*evident*, not tamper-proof — someone who consistently rewrites
every later entry can still forge history, and detecting that needs an external
anchor this repository does not have.

**Refuse, but never refuse the undo, and never fill for good.** Two defects made
the refusal permanent (findings F2, S5-SEC-03, both reproduced before the fix):
the lease sweeper's undo is a *new* action and was refused like any other once
the journal filled, and nothing ever reclaimed an entry, so about 170 finished
actions filled a default journal for the rest of the process's life. So (1) a
*restoration* transaction may use a reserve of :data:`UNDO_RESERVE_ACTIONS`
transactions that ordinary actions may not touch, and (2) when a new action does
not fit, :meth:`RollbackJournal.append` first compacts the chain's head: the
leading entries of actions that reached FINALIZE and hold no rollback state are
dropped, the last dropped digest becomes the chain anchor, and the compaction is
counted and recorded as a :class:`JournalTruncation`. Rollback state a live lease
may still need is never compacted: an action that holds state stops the
compaction at itself.

**What this module refuses to do.** It does not know what a lease is, it does not
decide whether an action may proceed, and it never touches a host. ``release()``
enforces only the half of its precondition it can see — that the action reached
its terminal phase; the "no live lease references this action" half is enforced by
``TransactionalExecutor._finalize``, which is the only caller that can see both.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    digest_of_bytes,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage5.executor.identity import identity_digest

if TYPE_CHECKING:  # pragma: no cover - typing only; importing at runtime would
    # close a cycle, because transactional.py imports this module for its
    # ``journal`` parameter. See TERMINAL_PHASE_NAME for how the one runtime fact
    # this module needs about Phase is kept from drifting.
    from pocketsec.stage5.executor.transactional import Phase
    from pocketsec.stage5.operators.algebra import DefensiveOperator

__all__ = [
    "GENESIS_DIGEST",
    "MAX_JOURNAL_BYTES",
    "MAX_JOURNAL_ENTRIES",
    "MAX_PHASES_PER_ACTION",
    "MAX_TRUNCATION_RECORDS",
    "MIN_FREE_BYTES_FOR_ACTION",
    "ROLLBACK_STATE_KEY",
    "UNDO_RESERVE_ACTIONS",
    "UNDO_RESERVE_BYTES_PER_ACTION",
    "TERMINAL_PHASE_NAME",
    "JournalEntry",
    "JournalFull",
    "JournalTruncation",
    "RollbackJournal",
]

#: §4.9. 256 KiB of endpoint state, and the governor carries the same number as
#: ``max_rollback_journal_bytes`` so the two cannot disagree about the budget.
MAX_JOURNAL_BYTES: int = 262144
MAX_JOURNAL_ENTRIES: int = 512

#: One entry per transaction phase. Pinned to ``len(Phase)`` by
#: ``test_the_journal_constants_do_not_drift_from_phase``.
MAX_PHASES_PER_ACTION: int = 5

#: ``Phase.FINALIZE.value``, held as a name rather than an import so this module
#: does not close an import cycle with ``transactional.py``. The same test above
#: asserts the two agree, so the pair cannot drift apart silently.
TERMINAL_PHASE_NAME: str = "FINALIZE"

#: The key under which ``PreActionBundle.to_dict()`` carries the state needed to
#: undo the action. The journal extracts it by this key and nothing else; a
#: bundle without it yields no rollback state, which SENTINEL's
#: ``ROLLBACK_STATE_CAPTURED`` precondition then refuses.
ROLLBACK_STATE_KEY: str = "rollback_state"

#: The truncation ledger is endpoint state too, so it is bounded like everything
#: else. A flood of refused actions would otherwise grow an unbounded list of
#: records *about* the bound that stopped them — measured: a 4000-action flood
#: against a default journal produced 3873 refusals, and therefore 3873 rows.
#: Overflow is counted rather than kept, and :meth:`RollbackJournal.truncations_dropped`
#: reports the count so the loss is still explicit.
MAX_TRUNCATION_RECORDS: int = 64

#: Headroom a new action must have before :meth:`RollbackJournal.full` says yes.
#: A journal that accepts PREPARE and then cannot fit ROLLBACK has recorded an
#: action it cannot undo, so the reserve is checked up front.
MIN_FREE_BYTES_FOR_ACTION: int = 4096

#: Undo transactions a full journal must still be able to hold. Four is the lease
#: capacity (``MAX_CONCURRENT_LEASES``): at most that many changes can be awaiting an
#: undo at once, so at most that many undo transactions can be owed.
UNDO_RESERVE_ACTIONS: int = 4
#: Bytes set aside per owed undo. A CHOSEN bound, equal to the per-action headroom
#: :data:`MIN_FREE_BYTES_FOR_ACTION`; the test that pins the reserve measures one real
#: restoration transaction against it rather than trusting this comment.
UNDO_RESERVE_BYTES_PER_ACTION: int = 4096

GENESIS_DIGEST: str = "sha256:" + "0" * 64


class JournalFull(ContractError):
    """Raised when a new action will not fit. A refusal, never an eviction."""


@dataclass(frozen=True, slots=True)
class JournalEntry:
    """One immutable phase record, chained to the one before it."""

    action_id: str
    phase: Phase
    at: int
    operator_id: str
    target_digest: str
    payload_digest: str
    previous_digest: str
    entry_digest: str

    def content_payload(self) -> dict[str, Any]:
        """The canonical, digest-covered content. ``entry_digest`` is excluded
        because it is the digest *of* this payload."""
        return {
            "action_id": self.action_id,
            "phase": str(self.phase),
            "at": self.at,
            "operator_id": self.operator_id,
            "target_digest": self.target_digest,
            "payload_digest": self.payload_digest,
            "previous_digest": self.previous_digest,
        }

    def compute_digest(self) -> str:
        canonical = json.dumps(self.content_payload(), sort_keys=True, separators=(",", ":"))
        return digest_of_bytes(canonical.encode("utf-8"))

    def to_dict(self) -> dict[str, Any]:
        return {**self.content_payload(), "entry_digest": self.entry_digest}


@dataclass(frozen=True, slots=True)
class JournalTruncation:
    """One thing the journal declined to hold, and why. Truncation is explicit."""

    what: str
    identifier: str
    reason: str
    bytes_dropped: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "what": self.what,
            "identifier": self.identifier,
            "reason": self.reason,
            "bytes_dropped": self.bytes_dropped,
        }


def _canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    """Sorted-key JSON. ``default=str`` keeps an unexpected value from turning a
    journal append — which is on the privileged path — into a TypeError."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


class RollbackJournal:
    """Append-only, digest-chained, bounded, and it refuses rather than forgets."""

    __slots__ = (
        "_anchor",
        "_bytes",
        "_compacted",
        "_entries",
        "_max_bytes",
        "_max_entries",
        "_reserve_bytes",
        "_reserve_entries",
        "_rollback_bytes",
        "_rollback_state",
        "_seen_actions",
        "_truncations",
        "_truncations_dropped",
    )

    def __init__(
        self, *, max_bytes: int = MAX_JOURNAL_BYTES, max_entries: int = MAX_JOURNAL_ENTRIES
    ) -> None:
        if max_bytes < MIN_FREE_BYTES_FOR_ACTION or max_entries < MAX_PHASES_PER_ACTION:
            raise ContractError(
                "a journal too small for one action cannot hold a reversible "
                f"intervention: max_bytes={max_bytes}, max_entries={max_entries}"
            )
        self._entries: list[JournalEntry] = []
        self._max_bytes = max_bytes
        self._max_entries = max_entries
        self._bytes = 0
        self._rollback_bytes = 0
        self._rollback_state: dict[str, Mapping[str, Any]] = {}
        self._seen_actions: set[str] = set()
        self._truncations: list[JournalTruncation] = []
        self._truncations_dropped = 0
        #: The digest the oldest retained entry chains to: genesis until a compaction.
        self._anchor = GENESIS_DIGEST
        self._compacted = 0
        # The undo reserve, shrunk for a journal too small to hold it beside one action,
        # so a minimum-size journal still admits its first action.
        self._reserve_entries = min(
            UNDO_RESERVE_ACTIONS * MAX_PHASES_PER_ACTION, max_entries - MAX_PHASES_PER_ACTION
        )
        self._reserve_bytes = min(
            UNDO_RESERVE_ACTIONS * UNDO_RESERVE_BYTES_PER_ACTION,
            max_bytes - MIN_FREE_BYTES_FOR_ACTION,
        )

    # --- writing -----------------------------------------------------------

    def append(
        self,
        *,
        action_id: str,
        phase: Phase,
        at: int,
        operator: DefensiveOperator,
        payload: Mapping[str, Any],
        restoration: bool = False,
    ) -> JournalEntry:
        """Record one phase of one action.

        A *new* action is refused when the journal cannot hold a whole
        transaction, after compacting whatever finished history it can; phases of
        an action already under way are always accepted, because abandoning an
        action half-recorded is worse than overshooting the soft budget by one
        entry — the overshoot is bounded by :data:`MIN_FREE_BYTES_FOR_ACTION`,
        which is why that reserve exists. ``restoration=True`` (an undo) may use the
        undo reserve that ordinary actions leave free.
        """
        require_identifier(action_id, "action_id")
        require_non_negative_int(at, "at")
        is_new = action_id not in self._seen_actions
        if is_new and self.full(restoration=restoration):
            self.compact()
        if is_new and self.full(restoration=restoration):
            self._record_truncation(
                JournalTruncation(
                    what="action",
                    identifier=action_id,
                    reason="JOURNAL_FULL: refused a new action rather than evicting "
                    "rollback state a live lease may need",
                    bytes_dropped=len(_canonical_bytes(payload)),
                )
            )
            raise JournalFull(
                f"journal is full ({self._bytes} bytes / {len(self._entries)} entries); "
                f"action {action_id!r} refused"
            )
        payload_bytes = _canonical_bytes(payload)
        entry = JournalEntry(
            action_id=action_id,
            phase=phase,
            at=at,
            operator_id=operator.spec.operator_id,
            target_digest=identity_digest(operator.target.identity),
            payload_digest=digest_of_bytes(payload_bytes),
            previous_digest=self._entries[-1].entry_digest if self._entries else self._anchor,
            entry_digest="",
        )
        sealed = replace(entry, entry_digest=entry.compute_digest())
        self._entries.append(sealed)
        self._seen_actions.add(action_id)
        self._bytes += len(_canonical_bytes(sealed.to_dict()))
        self._record_rollback_state(action_id, payload)
        return sealed

    def _record_truncation(self, truncation: JournalTruncation) -> None:
        """Keep the first :data:`MAX_TRUNCATION_RECORDS`, count the rest.

        The first refusals are the diagnostic ones; the thousandth adds nothing a
        counter does not. Keeping the head rather than the tail means the record of
        *why* the bound was first reached is never pushed out by the flood.
        """
        if len(self._truncations) < MAX_TRUNCATION_RECORDS:
            self._truncations.append(truncation)
            return
        self._truncations_dropped += 1

    def _record_rollback_state(self, action_id: str, payload: Mapping[str, Any]) -> None:
        """Keep the undo state the first time an action declares it.

        First write wins: a later phase must not be able to overwrite the
        pre-action state with post-action state, which would make the recorded
        rollback a no-op.
        """
        state = payload.get(ROLLBACK_STATE_KEY)
        if not isinstance(state, Mapping) or action_id in self._rollback_state:
            return
        frozen = dict(state)
        self._rollback_state[action_id] = frozen
        self._rollback_bytes += len(_canonical_bytes(frozen))

    def compact(self) -> int:
        """Drop the chain's settled head; return how many entries went.

        Settled: the action reached FINALIZE and holds no rollback state. Only a
        leading run is dropped, so the retained chain still verifies from one anchor;
        an action that still holds undo state (a live lease may need it) ends the run.
        """
        settled = self._settled_actions()
        dropped = 0
        for entry in self._entries:
            if entry.action_id not in settled:
                break
            dropped += 1
        if dropped == 0:
            return 0
        head, self._entries = self._entries[:dropped], self._entries[dropped:]
        self._anchor = head[-1].entry_digest
        freed = sum(len(_canonical_bytes(entry.to_dict())) for entry in head)
        self._bytes -= freed
        self._seen_actions -= {entry.action_id for entry in head}
        self._compacted += dropped
        self._record_truncation(
            JournalTruncation(
                what="compaction",
                identifier=self._anchor,
                reason=f"COMPACTED: {dropped} entries of finalised, released actions; "
                "the retained chain now verifies from this anchor",
                bytes_dropped=freed,
            )
        )
        return dropped

    def _settled_actions(self) -> frozenset[str]:
        last: dict[str, str] = {}
        for entry in self._entries:
            last[entry.action_id] = str(entry.phase)
        return frozenset(
            action_id
            for action_id, phase in last.items()
            if phase == TERMINAL_PHASE_NAME and action_id not in self._rollback_state
        )

    def finalised_actions(self) -> frozenset[str]:
        """Actions whose last recorded phase is FINALIZE, whether or not state is held."""
        last: dict[str, str] = {}
        for entry in self._entries:
            last[entry.action_id] = str(entry.phase)
        return frozenset(a for a, phase in last.items() if phase == TERMINAL_PHASE_NAME)

    def release(self, action_id: str) -> None:
        """Drop an action's rollback state once it can no longer be needed.

        Refuses unless the action reached its terminal phase. The other half of
        the precondition — that no live lease still references the action — is
        enforced by the executor, which is the only caller that can see the lease
        registry. Releasing an unfinished action is how a journal turns a
        reversible intervention into a permanent one by accident.
        """
        require_identifier(action_id, "action_id")
        phases = [entry.phase for entry in self._entries if entry.action_id == action_id]
        if not phases:
            raise ContractError(f"unknown action {action_id!r}")
        if str(phases[-1]) != TERMINAL_PHASE_NAME:
            raise ContractError(
                f"action {action_id!r} is at {str(phases[-1])!r}, not {TERMINAL_PHASE_NAME}; "
                "rollback state is not releasable before the transaction finalises"
            )
        state = self._rollback_state.pop(action_id, None)
        if state is not None:
            self._rollback_bytes -= len(_canonical_bytes(state))

    # --- reading -----------------------------------------------------------

    def rollback_state(self, action_id: str) -> Mapping[str, Any] | None:
        return self._rollback_state.get(action_id)

    def bytes_used(self) -> int:
        return self._bytes + self._rollback_bytes

    def full(self, *, restoration: bool = False) -> bool:
        """Forward-looking: can a whole new transaction still fit?

        An ordinary action must also leave the undo reserve free; a restoration may
        use it. Without the reserve, the undo that ends a containment was the one
        transaction a full journal was guaranteed to refuse (F2).
        """
        reserve_entries = 0 if restoration else self._reserve_entries
        reserve_bytes = 0 if restoration else self._reserve_bytes
        return (
            len(self._entries) + MAX_PHASES_PER_ACTION + reserve_entries > self._max_entries
            or self.bytes_used() + MIN_FREE_BYTES_FOR_ACTION + reserve_bytes > self._max_bytes
        )

    def compacted_entries(self) -> int:
        """Entries dropped by compaction since construction. Explicit, never silent."""
        return self._compacted

    def entries(self) -> tuple[JournalEntry, ...]:
        return tuple(self._entries)

    def phases_of(self, action_id: str) -> tuple[Phase, ...]:
        return tuple(entry.phase for entry in self._entries if entry.action_id == action_id)

    def truncations(self) -> tuple[JournalTruncation, ...]:
        return tuple(self._truncations)

    def truncations_dropped(self) -> int:
        """Refusals that happened after the truncation ledger filled. Non-zero means
        the count is the record and the individual rows are gone."""
        return self._truncations_dropped

    def verify_chain(self) -> tuple[str, ...]:
        """Return the problems found; ``()`` is the property.

        The walk feeds **recomputed** digests forward. Verifying against stored
        digests would report only a local mismatch for an edited row and leave
        every later link looking intact.
        """
        problems: list[str] = []
        previous = self._anchor
        for index, entry in enumerate(self._entries):
            label = f"entry {index} ({entry.action_id}/{entry.phase!s})"
            if entry.previous_digest != previous:
                problems.append(
                    f"{label}: chain break - expected previous digest {previous}, "
                    f"found {entry.previous_digest}"
                )
            recomputed = entry.compute_digest()
            if entry.entry_digest != recomputed:
                problems.append(f"{label}: content was modified after it was recorded")
            previous = recomputed
        return tuple(problems)
