"""D6.16 — Drift / Epoch / Recurrence: legitimate change versus poisoning, and knowledge contexts.

A host changes. A package upgrade legitimately moves what "normal" means, and an
attacker would like nothing better than to be mistaken for one. This module answers
two questions and refuses to answer a third.

**Is this change drift or poisoning?** ``classify_drift_vs_poisoning`` (HEL-F19)
reads the six signals of architecture §22 and lets **no single signal decide**: a
corroborated epoch change is not enough on its own (the attacker can time their
first sample to land right after a genuine upgrade — Stage 2's stated residual
risk, arm P2b), and neither is breadth or timing. LEGITIMATE_DRIFT needs trusted
provenance AND stable semantics AND independent corroboration AND no failed
rollback test; anything that attacks semantics or arrives uncorroborated from too
few groups is POISON_SUSPECT; the rest is UNDETERMINED, which is a valid answer.

**Which knowledge applies now?** A ``KnowledgeContext`` groups the Stage 1 epochs
that share one ``SystemIdentity.key()``. It is NOT a second ``Epoch``: Stage 1
decides epochs, and a return to an earlier identity opens a *new* ``epoch_id`` with
the *same* key — which is exactly what makes a returning context recognisable.
``open_new_epoch`` (HEL-F20) marks the old context DORMANT, fossilises its state,
and returns a **proposal**; ``resurrect_dormant_knowledge`` (HEL-F21) reloads a
returning context's evicted items from its integrity-verified dormancy fossil as a
RESURRECTION proposal.

**Minted, not built.** ``open_new_epoch`` records every transition it returns in a
module-private, bounded, single-use registry; the controller installs an active-context
change only for a transition it can consume from there (review S6-AUTH-05). A hand-built
``EpochTransition`` would otherwise skip Stage 1's corroboration refusal entirely.

**What it refuses to do:** write trusted state. Every output here is a proposal the
controller installs through conservation (and, for resurrection, shadow and canary).
An uncorroborated ``EpochDecision`` changes nothing at all (arm P5: contexts opened
and items retired by uncorroborated changes must be 0). Resurrection that never had
to reload anything is reported INERT by its caller, not as working.

Stdlib only.
"""

from __future__ import annotations

import secrets
import sys
from collections import OrderedDict
from collections.abc import Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING

from pocketsec.stage0.contracts.common import ContractError, digest_of_bytes
from pocketsec.stage1.epoch.model import EpochDecision, SystemIdentity
from pocketsec.stage2.adaptation.quarantine import MAX_EPOCHS_PER_PATTERN
from pocketsec.stage6.capsule.quarantine import QuarantineBucket, QuarantineVerdict
from pocketsec.stage6.constitution.learning import MIN_INDEPENDENT_GROUPS
from pocketsec.stage6.fossils.store import FossilIntegrityError, FossilReason, FossilStore
from pocketsec.stage6.memory.semantic import KnowledgeItem, TrustedKnowledgeState, context_id_for

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pocketsec.stage6.chamber.evolution import KnowledgeDelta

__all__ = [
    "DRIFT_ALIGN_WINDOW",
    "MAX_KNOWLEDGE_CONTEXTS",
    "ContextStatus",
    "DriftClass",
    "DriftSignals",
    "DriftVerdict",
    "EpochTransition",
    "KnowledgeContext",
    "KnowledgeContextRegistry",
    "ResurrectionProposal",
    "classify_drift_vs_poisoning",
    "consume_issued_transition",
    "drift_signals",
]

#: Chosen parameters (spec §4.21), not measurements.
MAX_KNOWLEDGE_CONTEXTS: int = 16
DRIFT_ALIGN_WINDOW: int = 64
#: Minted, not-yet-installed transitions held at once (not in §4.21; a transition is
#: consumed by the next install, so a handful covers every legitimate caller).
_MAX_ISSUED_TRANSITIONS = 16
#: (previous, current, proposal) of every transition ``open_new_epoch`` returned and nobody
#: installed yet. Module-private; single use; oldest forgotten first.
_issued_transitions: OrderedDict[tuple[str, str, str, KnowledgeDelta], None] = OrderedDict()


def _mint(transition: EpochTransition) -> EpochTransition:
    minted = replace(transition, mint=secrets.token_hex(16))
    _issued_transitions[_mint_key(minted)] = None
    while len(_issued_transitions) > _MAX_ISSUED_TRANSITIONS:
        _issued_transitions.popitem(last=False)
    return minted


def _mint_key(transition: EpochTransition) -> tuple[str, str, str, KnowledgeDelta]:
    return (transition.mint, transition.previous, transition.current, transition.proposal)


def consume_issued_transition(transition: object) -> bool:
    """True, once, for a transition ``open_new_epoch`` minted; False for anything else.

    Keyed on (mint token, previous, current, proposal), not on ``resurrect``: resurrection
    is a separate candidate through the chamber, so a caller may drop it
    (``replace(t, resurrect=None)``) without making the context change any less minted.
    """
    if not isinstance(transition, EpochTransition) or not transition.mint:
        return False
    key = _mint_key(transition)
    try:
        minted = key in _issued_transitions
    except TypeError:  # an unhashable hand-built proposal was never minted
        return False
    if not minted:
        return False
    del _issued_transitions[key]
    return True


class DriftClass(StrEnum):
    LEGITIMATE_DRIFT = "LEGITIMATE_DRIFT"
    POISON_SUSPECT = "POISON_SUSPECT"
    UNDETERMINED = "UNDETERMINED"


@dataclass(frozen=True, slots=True)
class DriftSignals:
    """Architecture §22, one field per row."""

    provenance_trusted_change: bool
    breadth: float
    timing_aligned: bool
    independent_corroboration: int
    semantics_stable: bool
    rollback_test_passed: bool | None = None


@dataclass(frozen=True, slots=True)
class DriftVerdict:
    drift_class: DriftClass
    signals: DriftSignals
    reasons: tuple[str, ...]


def drift_signals(
    window: Sequence[QuarantineVerdict],
    *,
    decision: EpochDecision | None,
    decision_sequence: int | None,
) -> DriftSignals:
    """Measure the §22 signals over a window of gateway verdicts around a change.

    A pattern key is *changed* when it first appears after ``decision_sequence``
    (or anywhere in the window when there is no decision). ``rollback_test_passed``
    is ``None``: only the conservation gate can fill it, and it is never guessed.
    ``semantics_stable`` is False when a changed pattern touches a protected anchor
    or any verdict carrying one was held hostile. ``breadth`` and ``timing_aligned``
    are measured and reported; the spec's classifier deliberately does not decide on
    them, because a timed attacker controls both.
    """
    trusted_change = decision is not None and decision.transitioned and decision.corroborated
    pivot = decision_sequence if decision_sequence is not None else -1
    before = {k for v in window if v.sequence <= pivot for k in v.pattern_keys}
    after = [v for v in window if v.sequence > pivot]
    changed = {k for v in after for k in v.pattern_keys} - before
    observed = before | {k for v in after for k in v.pattern_keys}
    carriers = [v for v in after if changed.intersection(v.pattern_keys)]
    first = min((v.sequence for v in carriers), default=None)
    return DriftSignals(
        provenance_trusted_change=trusted_change,
        breadth=len(changed) / len(observed) if observed else 0.0,
        timing_aligned=(
            trusted_change and first is not None and first - pivot <= DRIFT_ALIGN_WINDOW
        ),
        independent_corroboration=len({g for v in carriers for g in v.trust.step_groups}),
        semantics_stable=not any(_unstable(v, changed) for v in carriers),
        rollback_test_passed=None,
    )


def _unstable(verdict: QuarantineVerdict, changed: set[str]) -> bool:
    """A changed pattern that touches protected meaning, or a verdict held hostile."""
    return (
        verdict.bucket is QuarantineBucket.HOSTILE_SUSPECT
        or verdict.normalization is not None
        or verdict.suspicion.protected_conflict
        or bool(changed.intersection(verdict.protected_keys))
    )


def classify_drift_vs_poisoning(signals: DriftSignals) -> DriftVerdict:
    """HEL-F19, exactly as spec §D6.16. No single signal decides either way."""
    reasons: list[str] = []
    corroborated = signals.independent_corroboration >= MIN_INDEPENDENT_GROUPS
    if not signals.semantics_stable:
        reasons.append("semantics_unstable")
    if not signals.provenance_trusted_change and not corroborated:
        reasons.append("uncorroborated_change_from_too_few_groups")
    if signals.rollback_test_passed is False:
        reasons.append("rollback_test_failed")
    if reasons:
        return DriftVerdict(DriftClass.POISON_SUSPECT, signals, tuple(reasons))
    if signals.provenance_trusted_change and signals.semantics_stable and corroborated:
        reason = ("corroborated_stable_independent",)
        return DriftVerdict(DriftClass.LEGITIMATE_DRIFT, signals, reason)
    missing = []
    if not signals.provenance_trusted_change:
        missing.append("no_trusted_system_change")
    if not corroborated:
        missing.append("too_few_independent_groups")
    return DriftVerdict(DriftClass.UNDETERMINED, signals, tuple(missing))


# --- knowledge contexts ------------------------------------------------------


class ContextStatus(StrEnum):
    ACTIVE = "ACTIVE"
    PROVISIONAL = "PROVISIONAL"
    DORMANT = "DORMANT"


@dataclass(frozen=True, slots=True)
class KnowledgeContext:
    """A group of Stage 1 epochs sharing one ``SystemIdentity.key()``; NOT a second Epoch."""

    context_id: str
    identity: SystemIdentity
    epoch_ids: tuple[int, ...]
    status: ContextStatus
    opened_sequence: int
    last_active_sequence: int
    dormancy_fossil: str | None


@dataclass(frozen=True, slots=True)
class ResurrectionProposal:
    """Items a returning context lost to eviction, reloaded from its verified dormancy fossil."""

    context_id: str
    fossil_hash: str
    items: tuple[KnowledgeItem, ...]


@dataclass(frozen=True, slots=True)
class EpochTransition:
    """A proposal. The controller installs ``proposal``; nothing here is trusted yet.

    ``mint`` is the random token ``open_new_epoch`` stamped on it; ``""`` on anything built
    by hand, which the controller refuses (review S6-AUTH-05).
    """

    previous: str
    current: str
    resurrect: ResurrectionProposal | None
    proposal: KnowledgeDelta
    mint: str = ""


class KnowledgeContextRegistry:
    """Bounded map of knowledge contexts; the oldest DORMANT is dropped first (its fossil stays).

    When every slot is held by a non-dormant context the newcomer is refused and
    counted: dropping a context that is still active or provisional would forget
    knowledge that has not been fossilised.
    """

    def __init__(
        self,
        *,
        identity: SystemIdentity | None = None,
        epoch_id: int = 0,
        sequence: int = 0,
        capacity: int = MAX_KNOWLEDGE_CONTEXTS,
    ) -> None:
        if capacity < 2:
            raise ValueError("a context registry needs room for the old context and the new one")
        self._capacity = capacity
        self._contexts: OrderedDict[str, KnowledgeContext] = OrderedDict()
        self.refused_uncorroborated = 0
        self.refused_full = 0
        self.dropped = 0
        self.resurrections = 0
        self.unloadable_fossils = 0
        if identity is not None:
            cid = context_id_for(identity)
            self._contexts[cid] = KnowledgeContext(
                cid, identity, (epoch_id,), ContextStatus.ACTIVE, sequence, sequence, None
            )

    def open_new_epoch(
        self,
        decision: EpochDecision,
        *,
        identity: SystemIdentity,
        sequence: int,
        trusted: TrustedKnowledgeState,
        fossils: FossilStore,
    ) -> EpochTransition | None:
        """HEL-F20. ``None`` unless ``decision.transitioned``; otherwise a proposal only."""
        if not decision.transitioned or not decision.corroborated:
            self.refused_uncorroborated += 1
            return None
        current = context_id_for(identity)
        previous = trusted.active_context
        if current == previous:
            return None
        known = self._contexts.get(current)
        if known is None and not self._room_for_one():
            self.refused_full += 1
            return None
        self._retire_live(keep=current, trusted=trusted, fossils=fossils, sequence=sequence)
        epochs = _append_epoch(known.epoch_ids if known else (), decision.epoch_id)
        self._contexts[current] = KnowledgeContext(
            current, identity, epochs, ContextStatus.PROVISIONAL,
            known.opened_sequence if known else sequence, sequence,
            known.dormancy_fossil if known else None,
        )
        self._contexts.move_to_end(current)
        resurrect = None
        if known is not None and known.status is ContextStatus.DORMANT:
            resurrect = self.resurrect_dormant_knowledge(identity, trusted=trusted, fossils=fossils)
        return _mint(EpochTransition(previous, current, resurrect, _context_delta(current)))

    def activate(self, context_id: str, *, sequence: int) -> None:
        """Mark a PROVISIONAL context ACTIVE once the controller installed its transition."""
        context = self._contexts.get(context_id)
        if context is None or context.status is not ContextStatus.PROVISIONAL:
            return
        self._contexts[context_id] = replace(
            context, status=ContextStatus.ACTIVE, last_active_sequence=sequence
        )

    def resurrect_dormant_knowledge(
        self, identity: SystemIdentity, *, trusted: TrustedKnowledgeState, fossils: FossilStore
    ) -> ResurrectionProposal | None:
        """HEL-F21. Reload a returning context's *evicted* items from its dormancy fossil.

        ``None`` when the context is unknown, was never fossilised, lost nothing (its
        items are still resident — resurrection is INERT, not working), or its
        fossil fails integrity or was evicted (counted; relearning is the fallback,
        never a corrupted reload).
        """
        cid = context_id_for(identity)
        context = self._contexts.get(cid)
        if context is None or context.dormancy_fossil is None:
            return None
        try:
            archived = fossils.load(context.dormancy_fossil)
        except (FossilIntegrityError, ContractError, KeyError):
            self.unloadable_fossils += 1
            return None
        resident = {item.item_id for item in trusted.items}
        lost = tuple(
            item
            for item in archived.items
            if cid in item.context_ids and item.item_id not in resident
        )
        if not lost:
            return None
        self.resurrections += 1
        return ResurrectionProposal(context_id=cid, fossil_hash=context.dormancy_fossil, items=lost)

    def contexts(self) -> tuple[KnowledgeContext, ...]:
        return tuple(self._contexts.values())

    def get(self, context_id: str) -> KnowledgeContext | None:
        return self._contexts.get(context_id)

    def memory_bytes(self) -> int:
        return sum(
            sys.getsizeof(cid) + 8 * len(c.epoch_ids) + 512 for cid, c in self._contexts.items()
        )

    # --- internals -------------------------------------------------------

    def _room_for_one(self) -> bool:
        if len(self._contexts) < self._capacity:
            return True
        oldest = next(
            (cid for cid, c in self._contexts.items() if c.status is ContextStatus.DORMANT), None
        )
        if oldest is None:
            return False
        del self._contexts[oldest]
        self.dropped += 1
        return True

    def _retire_live(
        self, *, keep: str, trusted: TrustedKnowledgeState, fossils: FossilStore, sequence: int
    ) -> None:
        """Every live context but ``keep`` -> DORMANT, with a CONTEXT_DORMANCY fossil.

        The fossil holds the trusted state the context ran under, so its items survive
        any later eviction. Its fingerprint is a digest of (context, state digest), not
        a replay result: no replay has run here and the field says what it is.
        """
        for cid, context in list(self._contexts.items()):
            if cid == keep or context.status is ContextStatus.DORMANT:
                continue
            fossil = fossils.create_fossil(
                trusted,
                reason=FossilReason.CONTEXT_DORMANCY,
                fingerprint=digest_of_bytes(f"dormancy:{cid}:{trusted.digest()}".encode("utf-8")),
                epoch_range=(min(context.epoch_ids), max(context.epoch_ids)),
                sequence=sequence,
            )
            self._contexts[cid] = replace(
                context, status=ContextStatus.DORMANT, last_active_sequence=sequence,
                dormancy_fossil=fossil.artifact_hash,
            )


def _append_epoch(epochs: tuple[int, ...], epoch_id: int) -> tuple[int, ...]:
    merged = tuple(dict.fromkeys((*epochs, epoch_id)))
    return merged[-MAX_EPOCHS_PER_PATTERN:]


def _context_delta(active_context: str) -> KnowledgeDelta:
    # Imported here, not at module level: the chamber imports the gateway, and the
    # gateway's package must not import the chamber back at import time.
    from pocketsec.stage6.chamber.evolution import KnowledgeDelta

    return KnowledgeDelta(
        added=(), removed=(), replaced=(), threshold=None,
        rehearsal_added=(), rehearsal_removed=(), active_context=active_context,
    )
