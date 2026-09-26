"""D8.18 / PROM-F21 — the Safety Sandbox: which experiments Stage 8 may run, and on what.

Architecture §3 (DL-09): "Real-system active experiments require explicit isolated lab
authorization; production defaults to observation/replay only." This module is the one
place that answer is given. Every experiment ORACLE designs is put to
:meth:`ResearchSandbox.decide` first, and every decision — allowed or refused — is audited.

**Six classes are safe and ALLOWED without clearance** (``SAFE_EXPERIMENT_CLASSES``):
historical replay, counterfactual mutation, telemetry dropout, metamorphic transforms,
benign alternatives and synthetic event worlds. Each only *reads* recorded or synthetic
``Episode`` values inside this process; none touches a host.

**``ISOLATED_EMULATION`` is never allowed in this repository.** It needs a
:class:`LabClearance` for that class, that scope, not expired — and an emulator. There is no
emulator (``EMULATOR_AVAILABLE = False``, ADR-0075), so the answer with a *valid* clearance
is ``REFUSED_NO_EMULATOR``. The refusal is unconditional in code, not read from the flag:
flipping a constant must not be enough to start running things; adding an emulator would
need its own module, boundary review and ADR. "All active emulation is isolated and
authorised" is therefore true because none exists, and the gate checks the refusal path
*fires* rather than accepting that vacuous truth (G8.3).

**There is no production-intervention class** (ADR-0075): ``ExperimentClass`` has none, and
``verify_discovery_constitution`` fails if one is added.

The clearance's field is ``clearance_id``, not an "authorization" field: T5 forbids
authority words in Stage 8 dataclass fields, and a clearance grants nothing — it is one of
several preconditions of an answer that is currently always "no".

Bounded: the audit is a ring of ``audit_capacity`` decisions, evictions counted.
"""

from __future__ import annotations

import re
import sys
from collections import Counter, deque
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage8.constitution.discovery import SAFE_EXPERIMENT_CLASSES
from pocketsec.stage8.genome.hypothesis import ExperimentClass

__all__ = [
    "EMULATOR_AVAILABLE",
    "MAX_SANDBOX_AUDIT",
    "LabClearance",
    "ResearchSandbox",
    "SandboxDecision",
    "SandboxOutcome",
]

#: Spec §4.21. Chosen, not measured.
MAX_SANDBOX_AUDIT: int = 4096
#: There is no emulator in this repository (ADR-0075). Declared, and never consulted to allow.
EMULATOR_AVAILABLE: bool = False

_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


class SandboxOutcome(StrEnum):
    ALLOWED = "ALLOWED"
    REFUSED_NO_CLEARANCE = "REFUSED_NO_CLEARANCE"
    REFUSED_NO_EMULATOR = "REFUSED_NO_EMULATOR"
    REFUSED_EXPIRED = "REFUSED_EXPIRED"
    REFUSED_SCOPE = "REFUSED_SCOPE"


@dataclass(frozen=True, slots=True)
class LabClearance:
    """A lab's statement that one experiment class may run on one scope until a sequence."""

    clearance_id: str
    experiment_class: ExperimentClass
    scope_digest: str
    expires_sequence: int
    issued_by: str

    def __post_init__(self) -> None:
        require_identifier(self.clearance_id, "LabClearance.clearance_id")
        if not isinstance(self.experiment_class, ExperimentClass):
            raise ContractError(f"not an ExperimentClass: {self.experiment_class!r}")
        if not isinstance(self.scope_digest, str) or not _SHA256.fullmatch(self.scope_digest):
            raise ContractError("LabClearance.scope_digest must be 'sha256:' + 64 hex")
        require_non_negative_int(self.expires_sequence, "LabClearance.expires_sequence")
        require_identifier(self.issued_by, "LabClearance.issued_by")


@dataclass(frozen=True, slots=True)
class SandboxDecision:
    experiment_class: ExperimentClass
    outcome: SandboxOutcome
    sequence: int
    reason: str

    @property
    def allowed(self) -> bool:
        return self.outcome is SandboxOutcome.ALLOWED


class ResearchSandbox:
    """Decides, and audits, whether an experiment class may run. Holds no episode."""

    __slots__ = ("_audit", "_n")

    def __init__(self, *, audit_capacity: int = MAX_SANDBOX_AUDIT) -> None:
        capacity = audit_capacity
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
            raise ContractError(f"audit_capacity must be an int >= 1, got {audit_capacity!r}")
        self._audit: deque[SandboxDecision] = deque(maxlen=audit_capacity)
        self._n: Counter[str] = Counter()

    def decide(
        self,
        experiment_class: ExperimentClass,
        *,
        clearance: LabClearance | None,
        scope_digest: str,
        sequence: int,
    ) -> SandboxDecision:
        if not isinstance(experiment_class, ExperimentClass):
            raise ContractError(f"decide takes an ExperimentClass, got {experiment_class!r}")
        if clearance is not None and not isinstance(clearance, LabClearance):
            raise ContractError("clearance must be a LabClearance or None")
        if not isinstance(scope_digest, str) or not scope_digest:
            raise ContractError("scope_digest must be a non-empty string")
        require_non_negative_int(sequence, "sequence")
        outcome, reason = self._judge(experiment_class, clearance, scope_digest, sequence)
        decision = SandboxDecision(experiment_class, outcome, sequence, reason)
        if len(self._audit) == self._audit.maxlen:
            self._n["audit_evicted"] += 1
        self._audit.append(decision)
        self._n["decisions"] += 1
        self._n[outcome.value] += 1
        return decision

    @staticmethod
    def _judge(
        experiment_class: ExperimentClass,
        clearance: LabClearance | None,
        scope_digest: str,
        sequence: int,
    ) -> tuple[SandboxOutcome, str]:
        if experiment_class in SAFE_EXPERIMENT_CLASSES:
            return SandboxOutcome.ALLOWED, f"safe_class:{experiment_class.value}"
        if clearance is None:
            return SandboxOutcome.REFUSED_NO_CLEARANCE, "no_clearance"
        if clearance.experiment_class is not experiment_class:
            return SandboxOutcome.REFUSED_NO_CLEARANCE, "clearance_for_another_class"
        if sequence >= clearance.expires_sequence:
            return SandboxOutcome.REFUSED_EXPIRED, "clearance_expired"
        if clearance.scope_digest != scope_digest:
            return SandboxOutcome.REFUSED_SCOPE, "clearance_for_another_scope"
        # Every precondition a lab can supply holds; the one it cannot does not. Unconditional
        # on purpose: see the module docstring.
        return SandboxOutcome.REFUSED_NO_EMULATOR, "no_emulator_in_repository"

    def audit(self) -> tuple[SandboxDecision, ...]:
        return tuple(self._audit)

    def stats(self) -> Mapping[str, int]:
        counters = dict(self._n)
        counters["audit_retained"] = len(self._audit)
        return MappingProxyType(counters)

    def memory_bytes(self) -> int:
        per = sum(sys.getsizeof(d) + sys.getsizeof(d.reason) for d in self._audit)
        return per + sys.getsizeof(self._audit) + sys.getsizeof(self._n)
