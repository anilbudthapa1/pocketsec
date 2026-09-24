"""DTL-F19 — ``quarantine_adaptation_sample``: the anti-poisoning boundary.

Stage 2 is allowed to learn. It is **not** allowed to learn directly from raw
telemetry, because an attacker supplies raw telemetry. The invariant this module
exists to hold is the one `planning/MEMORY.md` states without qualification:

> Raw telemetry never directly rewrites trusted long-term cognition.

So every candidate update is held here first, checked, and either kept waiting,
refused, or — if it is high-consequence — **retained as evidence**. Retention is
the important word. A poisoning attempt is security-relevant information about
the host; discarding it would destroy the signal and leave no trace that someone
tried. Nothing in this module normalises a sample by silence.

Three checks, each aimed at a different attack on the learning loop:

**risk.** A sample that raises security capability, carries credential /
authorisation / persistence / external-endpoint meaning its pattern did not, or
arrives with high ΔΦ or high uncertainty, is not adaptation material at all. It is
evidence. This is where the escalation rule lives, and it is absolute: an
escalating sample can never become the anchor for anything, which is what stops
an attacker from *defining* normality with their first packet.

**consistency.** A sample must agree with the pattern it would update, measured
against that pattern's **anchor** — the first escalation-free sample seen for the
behaviour signature in the current epoch, released only by a corroborated system
change (``record_epoch_decision``). Anchoring on a running mean is the classic
mistake: a slow-drift attacker moves the mean a little at a time and every single
step looks consistent with the step before it. Against a fixed anchor the walk
accumulates distance and is refused. Only the security *meaning* of a sample
enters this distance (semantics and state delta); novelty and timing are transient
and would make an honest pattern look inconsistent for no reason.

**epoch.** A pattern must be corroborated across ``min_epochs`` distinct epochs
before it is eligible. Frequency is not corroboration — see
``promotion.PromotionController``, which refuses it again on the way out.

Bounds, and why the two policies differ:

* **Pending patterns refuse new entries when full.** Under a flood of novel
  behaviour signatures, evicting a waiting pattern to admit the attacker's newest
  one is exactly the wrong failure; the attacker would evict the legitimate
  adaptation queue at will. Refusing the newcomer fails closed.
* **Retained evidence drops the oldest when full**, because an investigation needs
  the most recent evidence. Nothing is lost that was not already durable: a
  retained record holds Stage 1 **evidence locators**, and the evidence itself
  lives in Stage 1's immutable store, so truncating here truncates the candidate
  queue and never the evidence trail.

Both drop counts are exposed by ``dropped()``; neither is silent. Stdlib only.
"""

from __future__ import annotations

import sys
from collections import deque
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from pocketsec.stage1.epoch.model import EpochDecision
from pocketsec.stage1.ssir.entities import SemanticProperty
from pocketsec.stage1.state.security_state import SecurityStateV1
from pocketsec.stage2.encoder.ssir_encoder import (
    FEATURE_LAYOUT,
    GROUP_OFFSETS,
    EncodedTransition,
    feature_names,
)

__all__ = [
    "AdaptationSample",
    "BASELINE_EPOCH_ID",
    "CHECK_CONSISTENCY",
    "CHECK_EPOCH",
    "CHECK_OBSERVATIONS",
    "CHECK_RISK",
    "DEFAULT_CONSISTENCY_RADIUS",
    "DEFAULT_MAX_UNCERTAINTY",
    "ESCALATION_MASK",
    "ESCALATION_PROPERTIES",
    "MAX_EPOCHS_PER_PATTERN",
    "MAX_QUARANTINE",
    "MEANING_GROUPS",
    "QuarantineBuffer",
    "QuarantineOutcome",
    "QuarantineStats",
    "QuarantineVerdict",
    "RetainedEvidence",
    "meaning_distance",
    "meaning_vector",
    "pattern_key",
]

MAX_QUARANTINE: int = 512

#: Epochs recorded per pending pattern. Matches the lattice's per-atom bound so a
#: pattern cannot accumulate unbounded epoch history while it waits.
MAX_EPOCHS_PER_PATTERN: int = 8

#: Epoch 0 is the system as it was found: an installed baseline, not a regime a
#: behaviour opened. Later epochs are corroborated only by an ``EpochDecision``
#: whose ``corroborated`` flag is set, which behavioural novelty can never
#: produce (``stage1/epoch/model.py``).
BASELINE_EPOCH_ID: int = 0

CHECK_RISK = "risk"
CHECK_CONSISTENCY = "consistency"
CHECK_EPOCH = "epoch"
CHECK_OBSERVATIONS = "observations"

#: Object properties whose appearance is an *escalation* of what a pattern means.
#: Deliberately narrow: TEMP_LOCATION or SYSTEM_BINARY describe where an object
#: lives, while these four describe security consequence.
ESCALATION_PROPERTIES: tuple[SemanticProperty, ...] = (
    SemanticProperty.CREDENTIAL,
    SemanticProperty.AUTHORIZATION_DATA,
    SemanticProperty.PERSISTENCE,
    SemanticProperty.EXTERNAL_ENDPOINT,
)

#: Feature groups that carry a transition's *meaning*. Novelty, timing,
#: uncertainty and causal features are excluded on purpose: they move for reasons
#: unrelated to what the behaviour is, and including them would make an honest
#: repeated pattern drift away from its own anchor.
MEANING_GROUPS: tuple[str, ...] = (
    "object_semantics",
    "state_delta_raised",
    "state_delta_scalars",
)

#: Squared-L2 radius in meaning space. MEASURED, not chosen: on the poison suite
#: (count=60, seed=11) every routine sample and every legitimate adaptation sample
#: sits at distance 0.000 from its anchor (n=888 and n=312, median and max both
#: 0.000), while the high-frequency arm sits at 2.000 (n=56) and the slow-drift
#: arm reaches 2.000. A radius of 1.0 separates them with a full bit of margin on
#: each side: one differing non-security property is tolerated, two are not.
DEFAULT_CONSISTENCY_RADIUS: float = 1.0

#: Above this, a sample is too poorly understood to be learned from. Stage 1's
#: AOP escalates at 0.5, so a sample the observation policy would already want to
#: investigate is not adaptation material.
DEFAULT_MAX_UNCERTAINTY: float = 0.5


def _mask_from_properties(properties: tuple[SemanticProperty, ...]) -> int:
    """Bit positions of ``properties`` inside ``object_property_mask``.

    Derived from the encoder's public ``feature_names()`` rather than hardcoded:
    the mask's bit order is the encoder's object-semantics group order, and a
    magic index into a frozen layout silently points at the wrong property the
    moment the layout grows.
    """
    names = feature_names()
    offset = GROUP_OFFSETS["object_semantics"]
    width = dict(FEATURE_LAYOUT)["object_semantics"]
    group = names[offset : offset + width]
    mask = 0
    for prop in properties:
        label = f"object.{prop.value}"
        if label not in group:  # pragma: no cover - guarded by a test
            raise AssertionError(
                f"{label!r} is not in the encoder's object-semantics group; the "
                "escalation mask can no longer be derived from the layout"
            )
        mask |= 1 << group.index(label)
    return mask


ESCALATION_MASK: int = _mask_from_properties(ESCALATION_PROPERTIES)


#: Resolved (start, stop) slices for ``MEANING_GROUPS``, computed once. The whole
#: gate measures 16.5-19.8 µs per offered sample across runs on this host (2040
#: samples of the drift corpus), and run-to-run variance is wider than the saving
#: from hoisting these, so no improvement is claimed for it — only that rebuilding
#: them per call is pure overhead on a path that runs once per transition.
_MEANING_SLICES: tuple[tuple[int, int], ...] = tuple(
    (GROUP_OFFSETS[group], GROUP_OFFSETS[group] + dict(FEATURE_LAYOUT)[group])
    for group in MEANING_GROUPS
)


def meaning_vector(encoded: EncodedTransition) -> tuple[float, ...]:
    """The subvector of ``features`` that says what the transition *means*."""
    features = encoded.features
    values: list[float] = []
    for start, stop in _MEANING_SLICES:
        values.extend(features[start:stop])
    return tuple(values)


def meaning_distance(left: tuple[float, ...], right: tuple[float, ...]) -> float:
    """Squared L2 over meaning space, matching ``BehaviourAtom.distance``."""
    return sum((a - b) * (a - b) for a, b in zip(left, right, strict=True))


def pattern_key(encoded: EncodedTransition) -> str:
    """The behaviour signature a sample would update.

    Deliberately coarser than the sample: grouping on the relation alone is what
    makes a walk *visible*. If the key included the object's semantics then each
    step of a slow drift would land on a fresh key with a fresh anchor and agree
    with itself perfectly, which is how this check gets quietly defeated.
    """
    return f"relation:{encoded.relation}"


class QuarantineOutcome(StrEnum):
    """What happened to a candidate adaptation sample."""

    HELD = "HELD"
    PROMOTED = "PROMOTED"
    REFUSED = "REFUSED"
    RETAINED_AS_EVIDENCE = "RETAINED_AS_EVIDENCE"


@dataclass(frozen=True, slots=True)
class AdaptationSample:
    """One candidate update, as offered by the runtime path.

    It carries no label and no verdict. The quarantine must be decidable from
    what the endpoint can actually see; a field naming the ground truth would
    make every measurement here meaningless.
    """

    encoded: EncodedTransition
    state: SecurityStateV1
    epoch_id: int
    delta_phi: float
    uncertainty: float
    evidence: tuple[str, ...]
    received_at_sequence: int
    #: Stage 1's causal signature for this transition, and its parent's. Not
    #: identity and not a label: they are the chain links Stage 1 already
    #: computes, and ``promotion.py`` uses them for one thing only — deciding
    #: whether one promoted atom genuinely *followed* another before writing a
    #: lattice edge between them. Empty means UNKNOWN, and UNKNOWN means no edge
    #: is written rather than an invented one (S2-AUTH-05). Neither field is
    #: ever consulted when deciding whether to promote.
    causal_signature: str = ""
    parent_signature: str = ""


@dataclass(frozen=True, slots=True)
class RetainedEvidence:
    """A compact, durable record of a sample that was not learned from.

    Holds Stage 1 evidence **locators**, never content: evidence is referenced by
    digest and lives in Stage 1's immutable store (a Stage 0 invariant). Keeping
    96 floats per record here instead would put the endpoint's memory bound at
    the mercy of the attacker's event rate.
    """

    key: str
    reason: str
    epoch_id: int
    delta_phi: float
    uncertainty: float
    object_property_mask: int
    state_delta_mask: int
    evidence: tuple[str, ...]
    received_at_sequence: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "reason": self.reason,
            "epoch_id": self.epoch_id,
            "delta_phi": round(self.delta_phi, 4),
            "uncertainty": round(self.uncertainty, 4),
            "object_property_mask": self.object_property_mask,
            "state_delta_mask": self.state_delta_mask,
            "evidence": list(self.evidence),
            "received_at_sequence": self.received_at_sequence,
        }


@dataclass(frozen=True, slots=True)
class QuarantineVerdict:
    """Why a sample is waiting, refused, or held as evidence."""

    outcome: QuarantineOutcome
    checks_passed: tuple[str, ...]
    checks_failed: tuple[str, ...]
    epochs_observed: int
    detail: str
    key: str = ""
    observations: int = 0
    distance: float | None = None

    @property
    def eligible(self) -> bool:
        """True only when every check passed and the sample is still HELD."""
        return self.outcome is QuarantineOutcome.HELD and not self.checks_failed

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "checks_passed": list(self.checks_passed),
            "checks_failed": list(self.checks_failed),
            "epochs_observed": self.epochs_observed,
            "observations": self.observations,
            "distance": None if self.distance is None else round(self.distance, 4),
            "key": self.key,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class QuarantineStats:
    """Everything the resource harness and the gate need to check the bounds."""

    pending_patterns: int
    retained_evidence: int
    dropped_patterns: int
    dropped_evidence: int
    refused: int
    eligible: int
    reanchored: int
    corroborated_epochs: int
    memory_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "pending_patterns": self.pending_patterns,
            "retained_evidence": self.retained_evidence,
            "dropped_patterns": self.dropped_patterns,
            "dropped_evidence": self.dropped_evidence,
            "refused": self.refused,
            "eligible": self.eligible,
            "reanchored": self.reanchored,
            "corroborated_epochs": self.corroborated_epochs,
            "memory_bytes": self.memory_bytes,
        }


@dataclass
class _PendingPattern:
    """A behaviour signature waiting for enough corroboration to be trusted."""

    key: str
    #: ``None`` means released by a corroborated epoch change: the next
    #: escalation-free sample re-anchors the pattern.
    anchor: tuple[float, ...] | None
    observations: int = 0
    epochs: set[int] = field(default_factory=set)
    first_sequence: int = 0
    last_sequence: int = 0

    def memory_bytes(self) -> int:
        return (
            len(self.anchor or ()) * 8
            + len(self.epochs) * 8
            + sys.getsizeof(self.key)
            + 64  # counters and dataclass slots, upper bound
        )


class QuarantineBuffer:
    """Bounded holding area between raw telemetry and trusted cognition."""

    def __init__(
        self,
        *,
        capacity: int = MAX_QUARANTINE,
        min_epochs: int = 2,
        min_observations: int = 8,
        max_delta_phi: float = 2.0,
        max_uncertainty: float = DEFAULT_MAX_UNCERTAINTY,
        consistency_radius: float = DEFAULT_CONSISTENCY_RADIUS,
    ) -> None:
        if capacity < 2:
            raise ValueError("capacity must leave room for a pattern and its evidence")
        if min_epochs < 2:
            raise ValueError(
                "min_epochs below 2 would let a single regime corroborate itself, "
                "which is the poisoning path this buffer exists to close"
            )
        self.capacity = capacity
        self.min_epochs = min_epochs
        self.min_observations = min_observations
        self.max_delta_phi = max_delta_phi
        self.max_uncertainty = max_uncertainty
        self.consistency_radius = consistency_radius
        # Half the budget to waiting patterns, half to retained evidence, so the
        # total record count is bounded by `capacity` and the memory claim holds
        # whichever way the traffic leans.
        self._max_patterns = max(1, capacity // 2)
        self._max_evidence = max(1, capacity - self._max_patterns)
        self._pending: dict[str, _PendingPattern] = {}
        self._evidence: deque[RetainedEvidence] = deque()
        self._corroborated: set[int] = {BASELINE_EPOCH_ID}
        self._reanchored = 0
        self._dropped_patterns = 0
        self._dropped_evidence = 0
        self._refused = 0
        self._eligible = 0

    # --- epochs ----------------------------------------------------------

    def record_epoch_decision(self, decision: EpochDecision) -> bool:
        """Register an epoch as corroborated, or refuse to — and re-anchor.

        Mirrors Stage 1 exactly and adds nothing: an epoch counts only when the
        decision says a system component actually changed *and* an independent
        source corroborated it. Behavioural novelty reaches this method as a
        decision with ``corroborated=False`` and is ignored, which is the whole
        anti-poisoning mechanism.

        A corroborated change also **releases the anchors**. It has to: after a
        legitimate package upgrade the new version may write to a different kind
        of place or execute through a different mechanism, and an anchor frozen on
        the old meaning would refuse the new normality forever. This is the one
        and only way an anchor is ever released, which is why it is safe —
        behaviour cannot reach it.

        Observation and epoch counts survive. Resetting those as well would make a
        pattern unpromotable after every change, since promotion needs two
        distinct corroborated epochs and a reset pattern has one.

        Residual risk, stated rather than hidden: the first escalation-free sample
        after a corroborated change defines the new anchor, so an attacker who can
        time a non-escalating pattern to land immediately after a genuine upgrade
        can influence it. The escalation rule still bars anything carrying
        credential, authorisation, persistence or external meaning, and the delay
        and epoch requirements still apply.
        """
        if not decision.corroborated or not decision.changed_components:
            return False
        self._corroborated.add(decision.epoch_id)
        for pattern in self._pending.values():
            pattern.anchor = None
        self._reanchored += 1
        return True

    @property
    def corroborated_epochs(self) -> frozenset[int]:
        return frozenset(self._corroborated)

    # --- the gate --------------------------------------------------------

    def quarantine_adaptation_sample(self, sample: AdaptationSample) -> QuarantineVerdict:
        """DTL-F19. Decide what may happen to one candidate update.

        Three outcomes and no fourth: kept as evidence, refused, or held waiting.
        Nothing is promoted here — that is ``promotion.PromotionController``, on
        purpose, so that the only write path into trusted state is a module of its
        own.
        """
        key = pattern_key(sample.encoded)
        risk = self._risk_reason(sample)
        if risk is not None:
            return self._as_evidence(sample, key=key, risk=risk)

        pattern = self._pending.get(key)
        if pattern is None:
            if len(self._pending) >= self._max_patterns:
                return self._full(key)
            pattern = _PendingPattern(
                key=key,
                anchor=meaning_vector(sample.encoded),
                first_sequence=sample.received_at_sequence,
            )
            self._pending[key] = pattern
            distance = 0.0
        elif pattern.anchor is None:
            pattern.anchor = meaning_vector(sample.encoded)
            distance = 0.0
        else:
            distance = meaning_distance(pattern.anchor, meaning_vector(sample.encoded))
            if distance > self.consistency_radius:
                return self._inconsistent(sample, pattern=pattern, distance=distance)

        self._observe(pattern, sample)
        return self._eligibility(pattern, distance)

    def _as_evidence(
        self, sample: AdaptationSample, *, key: str, risk: str
    ) -> QuarantineVerdict:
        self._retain(sample, key=key, reason=risk)
        return QuarantineVerdict(
            outcome=QuarantineOutcome.RETAINED_AS_EVIDENCE,
            checks_passed=(),
            checks_failed=(CHECK_RISK,),
            epochs_observed=self._epochs_observed(key),
            detail=(
                f"{risk}; retained as evidence rather than learned from. A "
                "high-consequence sample is information about the host, not a "
                "description of its normality."
            ),
            key=key,
        )

    def _full(self, key: str) -> QuarantineVerdict:
        self._dropped_patterns += 1
        self._refused += 1
        return QuarantineVerdict(
            outcome=QuarantineOutcome.REFUSED,
            checks_passed=(CHECK_RISK,),
            checks_failed=(CHECK_CONSISTENCY,),
            epochs_observed=0,
            detail=(
                f"quarantine full at {self._max_patterns} pending patterns; refusing "
                "the new signature rather than evicting a waiting one, so a flood "
                "cannot displace legitimate adaptation"
            ),
            key=key,
        )

    def _inconsistent(
        self, sample: AdaptationSample, *, pattern: _PendingPattern, distance: float
    ) -> QuarantineVerdict:
        self._refused += 1
        self._retain(sample, key=pattern.key, reason="inconsistent_with_anchor")
        return QuarantineVerdict(
            outcome=QuarantineOutcome.REFUSED,
            checks_passed=(CHECK_RISK,),
            checks_failed=(CHECK_CONSISTENCY,),
            epochs_observed=len(pattern.epochs),
            detail=(
                f"meaning distance {distance:.3f} exceeds radius "
                f"{self.consistency_radius:.3f} from the pattern's anchor; an "
                "adaptation sample may refine a trusted behaviour, never walk it "
                "somewhere new"
            ),
            key=pattern.key,
            observations=pattern.observations,
            distance=distance,
        )

    # --- internals -------------------------------------------------------

    def _risk_reason(self, sample: AdaptationSample) -> str | None:
        """The one reason this sample is evidence rather than training data."""
        encoded = sample.encoded
        if encoded.object_property_mask & ESCALATION_MASK:
            return "object carries credential/authorisation/persistence/external meaning"
        if encoded.state_delta_mask:
            return "sample raised a security capability"
        if sample.delta_phi > self.max_delta_phi:
            return f"delta_phi {sample.delta_phi:.3f} above {self.max_delta_phi:.3f}"
        if sample.uncertainty > self.max_uncertainty:
            return f"uncertainty {sample.uncertainty:.3f} above {self.max_uncertainty:.3f}"
        return None

    def _observe(self, pattern: _PendingPattern, sample: AdaptationSample) -> None:
        pattern.observations += 1
        pattern.last_sequence = sample.received_at_sequence
        if sample.epoch_id in self._corroborated and len(pattern.epochs) < MAX_EPOCHS_PER_PATTERN:
            pattern.epochs.add(sample.epoch_id)

    def _eligibility(self, pattern: _PendingPattern, distance: float) -> QuarantineVerdict:
        epochs = len(pattern.epochs)
        passed = [CHECK_RISK, CHECK_CONSISTENCY]
        failed: list[str] = []
        if epochs >= self.min_epochs:
            passed.append(CHECK_EPOCH)
        else:
            failed.append(CHECK_EPOCH)
        if pattern.observations >= self.min_observations:
            passed.append(CHECK_OBSERVATIONS)
        else:
            failed.append(CHECK_OBSERVATIONS)
        if not failed:
            self._eligible += 1
            detail = (
                f"{pattern.observations} observations across {epochs} corroborated "
                "epochs; eligible, and still not promoted — promotion is a separate "
                "gated step"
            )
        else:
            detail = (
                f"held: {pattern.observations}/{self.min_observations} observations, "
                f"{epochs}/{self.min_epochs} corroborated epochs"
            )
        return QuarantineVerdict(
            outcome=QuarantineOutcome.HELD,
            checks_passed=tuple(passed),
            checks_failed=tuple(failed),
            epochs_observed=epochs,
            detail=detail,
            key=pattern.key,
            observations=pattern.observations,
            distance=distance,
        )

    def _epochs_observed(self, key: str) -> int:
        pattern = self._pending.get(key)
        return 0 if pattern is None else len(pattern.epochs)

    def _retain(self, sample: AdaptationSample, *, key: str, reason: str) -> None:
        record = RetainedEvidence(
            key=key,
            reason=reason,
            epoch_id=sample.epoch_id,
            delta_phi=sample.delta_phi,
            uncertainty=sample.uncertainty,
            object_property_mask=sample.encoded.object_property_mask,
            state_delta_mask=sample.encoded.state_delta_mask,
            evidence=sample.evidence,
            received_at_sequence=sample.received_at_sequence,
        )
        self._evidence.append(record)
        while len(self._evidence) > self._max_evidence:
            self._evidence.popleft()
            self._dropped_evidence += 1

    # --- reporting -------------------------------------------------------

    def dropped(self) -> int:
        """Records the buffer refused to store because it was full."""
        return self._dropped_patterns + self._dropped_evidence

    def evidence(self) -> tuple[RetainedEvidence, ...]:
        return tuple(self._evidence)

    def pending(self) -> tuple[str, ...]:
        return tuple(sorted(self._pending))

    def observations(self, key: str) -> int:
        pattern = self._pending.get(key)
        return 0 if pattern is None else pattern.observations

    def memory_bytes(self) -> int:
        """Upper bound on stored bytes, ignoring interpreter overhead."""
        patterns = sum(pattern.memory_bytes() for pattern in self._pending.values())
        evidence = sum(
            sys.getsizeof(record.key) + sum(sys.getsizeof(e) for e in record.evidence) + 96
            for record in self._evidence
        )
        return patterns + evidence

    def stats(self) -> QuarantineStats:
        return QuarantineStats(
            pending_patterns=len(self._pending),
            retained_evidence=len(self._evidence),
            dropped_patterns=self._dropped_patterns,
            dropped_evidence=self._dropped_evidence,
            refused=self._refused,
            eligible=self._eligible,
            reanchored=self._reanchored,
            corroborated_epochs=len(self._corroborated),
            memory_bytes=self.memory_bytes(),
        )
