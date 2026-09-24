"""The only path by which a quarantined sample may change trusted cognition.

Everything else in Stage 2 reads. This module writes — and it is deliberately the
narrowest module in the stage, because a second write path would make every
guarantee in ``quarantine.py`` decorative. Nothing else may call
``quantize_behaviour_atom`` or ``TransitionLattice.observe`` with a sample that
came from telemetry.

What it refuses to do, and why:

* **It refuses frequency.** A pattern seen ten thousand times in one epoch is a
  pattern seen once, ten thousand times. Spec §37 says a compile candidate never
  becomes trusted on frequency alone, and this is where that is enforced: the
  epoch requirement is re-checked here, independently of the quarantine's own
  verdict, so a weakened buffer cannot let a single-epoch pattern through.
* **It refuses evidence.** A sample the quarantine retained as evidence is never
  promotable, whatever else is true about it. Evidence is an input to
  investigation, never to normality.
* **It refuses immediacy.** The first time a candidate becomes eligible it is
  *queued*, not written. It is promoted only if the behaviour is still happening
  after the delay, so a burst cannot buy trust, and a candidate that stops
  recurring expires unpromoted. The queue is bounded and its drops are counted.
* **It records every refusal with a reason.** A refusal with no reason is
  indistinguishable from a bug, and the refusal log is the only evidence that the
  gate did anything at all.

``quantizer`` and ``lattice`` arrive as parameters rather than as imports. That is
not decoupling for its own sake: the trust boundary is *here*, so this module must
work against whatever trusted store the runtime is using, and a test must be able
to hand it a store it can inspect.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

from pocketsec.stage1.epoch.model import EpochDecision
from pocketsec.stage1.state.security_state import SecurityStateV1
from pocketsec.stage2.adaptation.quarantine import (
    BASELINE_EPOCH_ID,
    AdaptationSample,
    QuarantineOutcome,
    QuarantineVerdict,
)
from pocketsec.stage2.encoder.ssir_encoder import EncodedTransition

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pocketsec.stage2.lattice.atom import BehaviourAtom

__all__ = [
    "DelayedCandidate",
    "MAX_DELAYED_PROMOTIONS",
    "MAX_PROMOTED_SIGNATURES",
    "MAX_REFUSAL_LOG",
    "PROMOTION_DELAY_SEQUENCES",
    "PromotionController",
    "PromotionRecord",
    "PromotionStats",
    "REFUSE_DELAY_QUEUE_FULL",
    "REFUSE_EVIDENCE",
    "REFUSE_FREQUENCY_ALONE",
    "REFUSE_INSUFFICIENT_OBSERVATIONS",
    "REFUSE_NOT_ELIGIBLE",
    "REFUSE_REFUSED_UPSTREAM",
    "TrustedLattice",
    "TrustedQuantizer",
]

#: Candidates waiting out their delay. Bounded: an attacker who can mint new
#: behaviour signatures must not be able to grow endpoint state through this queue.
MAX_DELAYED_PROMOTIONS: int = 64

#: Refusals retained for inspection. Bounded, oldest dropped, drops counted.
MAX_REFUSAL_LOG: int = 128

#: Transitions a candidate waits before it may be written. Counted in offered
#: samples, not wall time: the endpoint's clock is not the attacker's constraint,
#: its event stream is.
PROMOTION_DELAY_SEQUENCES: int = 64

#: Promoted causal signatures remembered, so the adjacency check is bounded
#: endpoint state. Oldest forgotten first; forgetting costs a lattice edge,
#: never correctness — a missing count is honest, a fabricated one is not.
MAX_PROMOTED_SIGNATURES: int = 256

REFUSE_NOT_ELIGIBLE = "not_eligible"
REFUSE_EVIDENCE = "retained_as_evidence"
REFUSE_REFUSED_UPSTREAM = "refused_by_quarantine"
REFUSE_FREQUENCY_ALONE = "frequency_alone"
REFUSE_INSUFFICIENT_OBSERVATIONS = "insufficient_observations"
REFUSE_DELAY_QUEUE_FULL = "delay_queue_full"


class TrustedQuantizer(Protocol):
    """The trusted atom store, as ``lattice/quantizer.py`` provides it."""

    def quantize_behaviour_atom(
        self,
        encoded: EncodedTransition,
        *,
        state: SecurityStateV1,
        epoch_id: int,
        sequence: int,
    ) -> Any: ...

    def get(self, atom_id: int) -> BehaviourAtom | None: ...


class TrustedLattice(Protocol):
    """The trusted transition store, as ``lattice/transitions.py`` provides it."""

    def observe(
        self,
        source: int,
        target: int,
        *,
        epoch_id: int,
        delta_phi: float,
        uncertainty: float,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class PromotionRecord:
    """What the promotion gate did, and on what grounds."""

    outcome: QuarantineOutcome
    key: str
    atom_id: int | None
    reason: str
    checks_failed: tuple[str, ...]
    epochs_observed: int
    observations: int
    sequence: int
    release_at: int | None = None

    @property
    def promoted(self) -> bool:
        return self.outcome is QuarantineOutcome.PROMOTED

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "key": self.key,
            "atom_id": self.atom_id,
            "reason": self.reason,
            "checks_failed": list(self.checks_failed),
            "epochs_observed": self.epochs_observed,
            "observations": self.observations,
            "sequence": self.sequence,
            "release_at": self.release_at,
        }


@dataclass(frozen=True, slots=True)
class PromotionStats:
    """Measured behaviour of the gate. Every field is a count, not a claim."""

    offered: int
    promoted: int
    refused: int
    delayed: int
    delayed_pending: int
    delayed_dropped: int
    delayed_expired: int
    refusals_dropped: int
    corroborated_epochs: int
    trusted_atoms: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "offered": self.offered,
            "promoted": self.promoted,
            "refused": self.refused,
            "delayed": self.delayed,
            "delayed_pending": self.delayed_pending,
            "delayed_dropped": self.delayed_dropped,
            "delayed_expired": self.delayed_expired,
            "refusals_dropped": self.refusals_dropped,
            "corroborated_epochs": self.corroborated_epochs,
            "trusted_atoms": self.trusted_atoms,
        }


@dataclass(frozen=True, slots=True)
class DelayedCandidate:
    """A candidate serving its waiting period."""

    key: str
    queued_at: int
    release_at: int
    expires_at: int


class PromotionController:
    """Gated, delayed, reason-recording promotion of quarantined samples."""

    def __init__(
        self,
        *,
        min_epochs: int = 2,
        min_observations: int = 8,
        max_delayed: int = MAX_DELAYED_PROMOTIONS,
        delay_sequences: int = PROMOTION_DELAY_SEQUENCES,
    ) -> None:
        if min_epochs < 2:
            raise ValueError(
                "min_epochs below 2 lets one regime corroborate itself, which is "
                "promotion on frequency alone wearing a different name"
            )
        self.min_epochs = min_epochs
        self.min_observations = min_observations
        self.max_delayed = max(1, max_delayed)
        self.delay_sequences = max(1, delay_sequences)
        self._delayed: OrderedDict[str, DelayedCandidate] = OrderedDict()
        self._refusals: deque[PromotionRecord] = deque()
        self._corroborated: set[int] = {BASELINE_EPOCH_ID}
        self._trusted_atoms: dict[str, int] = {}
        #: causal_signature -> (atom_id, epoch_id) for transitions this
        #: controller promoted. A single `_last_atom` across every lineage is
        #: what made the fabricated edge possible (S2-AUTH-05); an unbounded map
        #: would be endpoint state that grows with the attacker's event rate.
        self._promoted_signatures: OrderedDict[str, tuple[int, int]] = OrderedDict()
        self._signatures_forgotten = 0
        self._offered = 0
        self._promoted = 0
        self._refused = 0
        self._delayed_count = 0
        self._delayed_dropped = 0
        self._delayed_expired = 0
        self._refusals_dropped = 0

    # --- epochs ----------------------------------------------------------

    def record_epoch_decision(self, decision: EpochDecision) -> bool:
        """Register a corroborated epoch. Uncorroborated decisions change nothing."""
        if not decision.corroborated or not decision.changed_components:
            return False
        self._corroborated.add(decision.epoch_id)
        return True

    @property
    def corroborated_epochs(self) -> frozenset[int]:
        return frozenset(self._corroborated)

    # --- the gate --------------------------------------------------------

    def promote(
        self,
        verdict: QuarantineVerdict,
        sample: AdaptationSample,
        *,
        quantizer: TrustedQuantizer,
        lattice: TrustedLattice | None,
    ) -> PromotionRecord:
        """Promote, delay, or refuse. The only write path into trusted state."""
        self._offered += 1
        now = sample.received_at_sequence
        self._expire(now)

        blocked = self._blocking_reason(verdict, sample)
        if blocked is not None:
            return self._refuse(verdict, now, blocked)

        waiting = self._delayed.get(verdict.key)
        if waiting is None:
            return self._delay(verdict, now)
        if now < waiting.release_at:
            return PromotionRecord(
                outcome=QuarantineOutcome.HELD,
                key=verdict.key,
                atom_id=None,
                reason="serving_delay",
                checks_failed=(),
                epochs_observed=verdict.epochs_observed,
                observations=verdict.observations,
                sequence=now,
                release_at=waiting.release_at,
            )

        del self._delayed[verdict.key]
        return self._write(verdict, sample, quantizer=quantizer, lattice=lattice)

    def _blocking_reason(
        self, verdict: QuarantineVerdict, sample: AdaptationSample
    ) -> str | None:
        """Every reason a sample may not be written, checked independently.

        The epoch and observation counts are re-checked here rather than trusted
        from ``verdict.checks_failed``. A quarantine buffer that was weakened —
        by a config change, a refactor, or a caller passing its own thresholds —
        must not be able to authorise a write on its own say-so.
        """
        if verdict.outcome is QuarantineOutcome.RETAINED_AS_EVIDENCE:
            return REFUSE_EVIDENCE
        if verdict.outcome is QuarantineOutcome.REFUSED:
            return REFUSE_REFUSED_UPSTREAM
        if verdict.outcome is not QuarantineOutcome.HELD:
            return REFUSE_NOT_ELIGIBLE
        if verdict.epochs_observed < self.min_epochs:
            return REFUSE_FREQUENCY_ALONE
        if verdict.observations < self.min_observations:
            return REFUSE_INSUFFICIENT_OBSERVATIONS
        if verdict.checks_failed:
            return REFUSE_NOT_ELIGIBLE
        if sample.epoch_id not in self._corroborated:
            return REFUSE_FREQUENCY_ALONE
        return None

    def _delay(self, verdict: QuarantineVerdict, now: int) -> PromotionRecord:
        if len(self._delayed) >= self.max_delayed:
            self._delayed_dropped += 1
            return self._refuse(verdict, now, REFUSE_DELAY_QUEUE_FULL)
        release_at = now + self.delay_sequences
        self._delayed[verdict.key] = DelayedCandidate(
            key=verdict.key,
            queued_at=now,
            release_at=release_at,
            expires_at=release_at + self.delay_sequences,
        )
        self._delayed_count += 1
        return PromotionRecord(
            outcome=QuarantineOutcome.HELD,
            key=verdict.key,
            atom_id=None,
            reason="queued_for_delay",
            checks_failed=(),
            epochs_observed=verdict.epochs_observed,
            observations=verdict.observations,
            sequence=now,
            release_at=release_at,
        )

    def _write(
        self,
        verdict: QuarantineVerdict,
        sample: AdaptationSample,
        *,
        quantizer: TrustedQuantizer,
        lattice: TrustedLattice | None,
    ) -> PromotionRecord:
        result = quantizer.quantize_behaviour_atom(
            sample.encoded,
            state=sample.state,
            epoch_id=sample.epoch_id,
            sequence=sample.received_at_sequence,
        )
        atom_id = int(getattr(result, "atom_id", result))
        previous = self._previous_in_lineage(sample)
        if lattice is not None and previous is not None:
            # An edge is written ONLY when this sample's `parent_signature`
            # names a transition this controller itself promoted, in this same
            # epoch. That is Stage 1's own causal link, not an inference.
            #
            # This used to be `if self._last_atom is not None`, where
            # `_last_atom` was simply the previously *promoted* atom — from any
            # behaviour signature, any lineage, any epoch, any distance in the
            # event stream — stamped with the TARGET's epoch_id. Over a long run
            # every promotion chained to the previous one, so the trusted lattice
            # accumulated a synthetic path through atom space whose `count` and
            # `epoch_counts` were indistinguishable from observed evidence. Those
            # are exactly the fields `exporter.propose_compile_candidate` reads
            # to build a candidate's `ValidityBoundary.epochs`, so a fabricated
            # edge produced a compile candidate whose "observed in epochs {...}"
            # claim was unbacked — inside the one module that documents itself as
            # the sole trust-boundary write path (S2-AUTH-05).
            #
            # A missing edge is honest. A fabricated one is not.
            lattice.observe(
                previous,
                atom_id,
                epoch_id=sample.epoch_id,
                delta_phi=sample.delta_phi,
                uncertainty=sample.uncertainty,
            )
        self._remember(sample, atom_id)
        self._trusted_atoms[verdict.key] = atom_id
        self._promoted += 1
        return PromotionRecord(
            outcome=QuarantineOutcome.PROMOTED,
            key=verdict.key,
            atom_id=atom_id,
            reason=(
                f"{verdict.observations} observations across "
                f"{verdict.epochs_observed} corroborated epochs, delay served"
            ),
            checks_failed=(),
            epochs_observed=verdict.epochs_observed,
            observations=verdict.observations,
            sequence=sample.received_at_sequence,
        )

    def _previous_in_lineage(self, sample: AdaptationSample) -> int | None:
        """The atom this sample's transition genuinely followed, or ``None``.

        Adjacency is exact, not inferred: the edge is written only when the
        sample's ``parent_signature`` names a transition this controller itself
        promoted, in the same epoch. Stage 1 computed that link; nothing here
        guesses it. Every other case — an unknown signature, a parent that was
        never promoted, a parent promoted under a different epoch — returns
        ``None``, and a ``None`` writes nothing.
        """
        if not sample.parent_signature:
            return None
        remembered = self._promoted_signatures.get(sample.parent_signature)
        if remembered is None:
            return None
        atom_id, epoch_id = remembered
        return atom_id if epoch_id == sample.epoch_id else None

    def _remember(self, sample: AdaptationSample, atom_id: int) -> None:
        """Record which atom this transition was promoted as. Bounded state."""
        if not sample.causal_signature:
            return
        self._promoted_signatures[sample.causal_signature] = (atom_id, sample.epoch_id)
        self._promoted_signatures.move_to_end(sample.causal_signature)
        while len(self._promoted_signatures) > MAX_PROMOTED_SIGNATURES:
            self._promoted_signatures.popitem(last=False)
            self._signatures_forgotten += 1

    def _refuse(
        self, verdict: QuarantineVerdict, now: int, reason: str
    ) -> PromotionRecord:
        record = PromotionRecord(
            outcome=QuarantineOutcome.REFUSED,
            key=verdict.key,
            atom_id=None,
            reason=reason,
            checks_failed=verdict.checks_failed,
            epochs_observed=verdict.epochs_observed,
            observations=verdict.observations,
            sequence=now,
        )
        self._refused += 1
        self._refusals.append(record)
        while len(self._refusals) > MAX_REFUSAL_LOG:
            self._refusals.popleft()
            self._refusals_dropped += 1
        return record

    def _expire(self, now: int) -> None:
        """Drop candidates that stopped recurring before their delay matured.

        Waiting is only meaningful if it can fail. A candidate whose behaviour
        vanished is not trusted by default; it is forgotten.
        """
        stale = [key for key, entry in self._delayed.items() if now > entry.expires_at]
        for key in stale:
            del self._delayed[key]
            self._delayed_expired += 1

    # --- reporting -------------------------------------------------------

    def delayed_promotion(self) -> tuple[DelayedCandidate, ...]:
        """The bounded waiting queue, oldest first."""
        return tuple(self._delayed.values())

    def refusals(self) -> tuple[PromotionRecord, ...]:
        return tuple(self._refusals)

    def trusted_atom_ids(self) -> tuple[int, ...]:
        return tuple(sorted(set(self._trusted_atoms.values())))

    def stats(self) -> PromotionStats:
        return PromotionStats(
            offered=self._offered,
            promoted=self._promoted,
            refused=self._refused,
            delayed=self._delayed_count,
            delayed_pending=len(self._delayed),
            delayed_dropped=self._delayed_dropped,
            delayed_expired=self._delayed_expired,
            refusals_dropped=self._refusals_dropped,
            corroborated_epochs=len(self._corroborated),
            trusted_atoms=len(set(self._trusted_atoms.values())),
        )
