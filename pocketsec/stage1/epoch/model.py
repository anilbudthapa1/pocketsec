"""D1.7 — the Behaviour Epoch Model (spec section 13).

Normal behaviour changes after legitimate system changes. A permanent baseline
either alerts forever after every ``apt upgrade``, or is retrained so eagerly
that an attacker can walk it somewhere useful. So normality is scoped to a
**behavioural epoch**, keyed on system identity rather than on behaviour.

The critical rule, and the reason this module is small and strict:

> Epoch changes require corroborating system-change evidence and cannot be
> triggered solely by behavioural novelty. (spec section 28)

That single constraint is the anti-poisoning mechanism. An attacker who can mint
a new epoch by acting strange gets a fresh baseline in which their behaviour is
normal. Here, novelty alone never mints an epoch: something must have actually
changed about the system — a kernel, a package set, a service set, a policy.
"""

from __future__ import annotations

import hashlib
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

__all__ = [
    "EPOCH_KEY_COMPONENTS",
    "EpochDecision",
    "EpochModel",
    "EpochTransitionReason",
    "SystemIdentity",
]

#: Components of the epoch key. Each is a fact about the *system*, verifiable
#: independently of any behaviour PocketSec observed.
EPOCH_KEY_COMPONENTS = (
    "kernel_id",
    "package_digest",
    "service_digest",
    "container_id",
    "policy_digest",
    "user_role_digest",
)


class EpochTransitionReason(StrEnum):
    INITIAL = "INITIAL"
    SYSTEM_CHANGE_CORROBORATED = "SYSTEM_CHANGE_CORROBORATED"
    REJECTED_NO_CORROBORATION = "REJECTED_NO_CORROBORATION"
    UNCHANGED = "UNCHANGED"


@dataclass(frozen=True, slots=True)
class SystemIdentity:
    """A snapshot of what the system *is*, independent of what it did."""

    kernel_id: str = ""
    package_digest: str = ""
    service_digest: str = ""
    container_id: str = ""
    policy_digest: str = ""
    user_role_digest: str = ""

    def key(self) -> str:
        material = "|".join(getattr(self, name) for name in EPOCH_KEY_COMPONENTS)
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]

    def changed_components(self, other: SystemIdentity) -> frozenset[str]:
        return frozenset(
            name
            for name in EPOCH_KEY_COMPONENTS
            if getattr(self, name) != getattr(other, name)
        )

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in EPOCH_KEY_COMPONENTS}


@dataclass(frozen=True, slots=True)
class EpochDecision:
    """The outcome of evaluating a candidate epoch change, with its reasoning."""

    epoch_id: int
    reason: EpochTransitionReason
    changed_components: frozenset[str]
    corroborated: bool
    detail: str

    @property
    def transitioned(self) -> bool:
        return self.reason is EpochTransitionReason.SYSTEM_CHANGE_CORROBORATED

    def to_dict(self) -> dict[str, Any]:
        return {
            "epoch_id": self.epoch_id,
            "reason": self.reason.value,
            "changed_components": sorted(self.changed_components),
            "corroborated": self.corroborated,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class Epoch:
    """One behavioural regime."""

    epoch_id: int
    identity: SystemIdentity
    key: str
    opened_at_ns: int
    #: Transitions observed while this epoch was current. Retained, compressed,
    #: across rotation — history is never simply reset (acceptance criterion 5).
    observed_transitions: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "epoch_id": self.epoch_id,
            "key": self.key,
            "opened_at_ns": self.opened_at_ns,
            "observed_transitions": self.observed_transitions,
            "identity": self.identity.to_dict(),
        }


@dataclass
class _EpochSummary:
    """Compressed retained history for a closed epoch."""

    epoch_id: int
    key: str
    observed_transitions: int
    closed_at_ns: int


class EpochModel:
    """Poisoning-resistant epoch tracking with a bounded history."""

    def __init__(self, *, identity: SystemIdentity, now_ns: int = 0, max_history: int = 16):
        self._next_id = 1
        self._current = Epoch(
            epoch_id=0, identity=identity, key=identity.key(), opened_at_ns=now_ns
        )
        self._history: OrderedDict[int, _EpochSummary] = OrderedDict()
        self._max_history = max_history
        self._rejected = 0

    @property
    def current(self) -> Epoch:
        return self._current

    @property
    def epoch_id(self) -> int:
        return self._current.epoch_id

    @property
    def rejected_transitions(self) -> int:
        """Candidate epoch changes refused for lack of corroboration."""
        return self._rejected

    def record_transition(self) -> None:
        self._current = Epoch(
            epoch_id=self._current.epoch_id,
            identity=self._current.identity,
            key=self._current.key,
            opened_at_ns=self._current.opened_at_ns,
            observed_transitions=self._current.observed_transitions + 1,
        )

    def evaluate(
        self,
        *,
        observed_identity: SystemIdentity,
        corroborating_evidence: frozenset[str] | set[str],
        now_ns: int,
        behavioural_novelty: float = 0.0,
    ) -> EpochDecision:
        """Decide whether to open a new epoch.

        ``behavioural_novelty`` is accepted and then *deliberately ignored* for
        the transition decision. It is a parameter so callers cannot quietly
        route novelty in through another door, and so the signature documents
        the rule: novelty never mints an epoch.

        ``corroborating_evidence`` names the system-change components an
        independent source confirms (a package-manager transaction, a kernel
        boot, a config-management run). A key change with no corroboration is a
        poisoning attempt until proven otherwise.
        """
        changed = self._current.identity.changed_components(observed_identity)

        if not changed:
            return EpochDecision(
                epoch_id=self._current.epoch_id,
                reason=EpochTransitionReason.UNCHANGED,
                changed_components=frozenset(),
                corroborated=False,
                detail="system identity unchanged",
            )

        corroborated = changed & frozenset(corroborating_evidence)
        if not corroborated:
            self._rejected += 1
            return EpochDecision(
                epoch_id=self._current.epoch_id,
                reason=EpochTransitionReason.REJECTED_NO_CORROBORATION,
                changed_components=changed,
                corroborated=False,
                detail=(
                    f"system identity changed in {sorted(changed)} with no corroborating "
                    "system-change evidence; staying in the current epoch. Behavioural "
                    "novelty alone cannot open an epoch."
                ),
            )

        return self._open(observed_identity, changed, corroborated, now_ns)

    def _open(
        self,
        identity: SystemIdentity,
        changed: frozenset[str],
        corroborated: frozenset[str],
        now_ns: int,
    ) -> EpochDecision:
        self._history[self._current.epoch_id] = _EpochSummary(
            epoch_id=self._current.epoch_id,
            key=self._current.key,
            observed_transitions=self._current.observed_transitions,
            closed_at_ns=now_ns,
        )
        while len(self._history) > self._max_history:
            self._history.popitem(last=False)

        epoch_id = self._next_id
        self._next_id += 1
        self._current = Epoch(
            epoch_id=epoch_id, identity=identity, key=identity.key(), opened_at_ns=now_ns
        )
        return EpochDecision(
            epoch_id=epoch_id,
            reason=EpochTransitionReason.SYSTEM_CHANGE_CORROBORATED,
            changed_components=changed,
            corroborated=True,
            detail=(
                f"corroborated system change in {sorted(corroborated)}; opened epoch "
                f"{epoch_id}. Prior epoch retained in compressed history."
            ),
        )

    @property
    def retained_history(self) -> tuple[dict[str, Any], ...]:
        """Compressed prior epochs. Rotation compresses; it does not erase."""
        return tuple(
            {
                "epoch_id": summary.epoch_id,
                "key": summary.key,
                "observed_transitions": summary.observed_transitions,
                "closed_at_ns": summary.closed_at_ns,
            }
            for summary in self._history.values()
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "current": self._current.to_dict(),
            "retained_history": list(self.retained_history),
            "rejected_transitions": self._rejected,
        }
