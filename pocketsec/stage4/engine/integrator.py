"""D4.17 — the evidence integrator, and the seam Stage 4's cognition attaches to.

Two jobs, both about the boundary rather than about reasoning:

1. :func:`integrate_evidence` builds :class:`IncidentEvidence` — *everything*
   Stage 4 receives, and the only way it receives it. One bounded, immutable
   object means a Stage 4 subsystem cannot reach back into the Stage 1 pipeline,
   the causal memory or the sensor path while it works, so a crash in the
   cognition has nothing live to corrupt. That is what makes the isolation
   property of G4.11 structural instead of hopeful.
2. :func:`run_attached_cognition` runs the ten subsystems of
   :class:`~pocketsec.stage4.engine.degradation.Subsystem` as *hooks*, each call
   wrapped in ``guarded``. The LUCID engine (D4.2) supplies the real hooks; this
   module never imports them, which is why the crash-isolation gate can be
   measured before the cognition exists and why a subsystem can be removed after
   its ablation says it should be.

``predictions`` holds ``ThreatPredictionV1`` rows and they are read **as evidence
only**. A verdict is an input, never an authorisation (ADR-0003): nothing in this
module or downstream of it may treat a Stage 2/3 ``MALICIOUS`` as permission to do
anything, and there is no field here in which such permission could be written
(trust rule T5, ``FORBIDDEN_AUTHORITY_FIELDS``).

A failed subsystem is **disabled for the rest of the incident** rather than
retried per transition. That is §45's semantics — the fallback replaces the
subsystem, it does not race it — and it is what makes "exactly one
``DegradationRecord`` per failure" true rather than a bound on a retry loop.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_non_negative_int,
)
from pocketsec.stage0.contracts.threat_prediction_v1 import ThreatPredictionV1, Verdict
from pocketsec.stage1.causal.memory import CausalMemory, CausalNode
from pocketsec.stage1.pipeline import ScenarioResult
from pocketsec.stage1.ssir.transition import SSIRTransitionV1
from pocketsec.stage1.state.security_state import SecurityStateV1
from pocketsec.stage1.telemetry.raw_event_v1 import SensorPath
from pocketsec.stage4.crystal.handoff import EMPTY_KNOWLEDGE, CrystalKnowledge
from pocketsec.stage4.engine.degradation import (
    DegradationLedger,
    Subsystem,
    downgrade_verdict,
    guarded,
)
from pocketsec.stage4.worlds.world import authority_named_fields

__all__ = [
    "ATTACHMENT_ORDER",
    "AttachmentOutcome",
    "IncidentEvidence",
    "MAX_PREDICTIONS_PER_INCIDENT",
    "MAX_SPINE_NODES",
    "MAX_TRANSITIONS_PER_INCIDENT",
    "SPINE_MIN_RESPONSIBILITY",
    "SubsystemHook",
    "integrate_evidence",
    "run_attached_cognition",
]

#: Matches Stage 0's bounded window (``MAX_SEQUENCE_CAPACITY``), so an incident
#: cannot be larger than the window the evidence arrived in.
MAX_TRANSITIONS_PER_INCIDENT: int = 4096

#: ``CausalMemory``'s own default capacity. Stated here so the bound survives a
#: caller that raised the memory's capacity.
MAX_SPINE_NODES: int = 512

#: Stage 2/3 rows are evidence, and a handful of them per incident is evidence;
#: thousands would be a queue.
MAX_PREDICTIONS_PER_INCIDENT: int = 64

#: ``CausalMemory.spine``'s documented default: transitions that actually raised Φ.
SPINE_MIN_RESPONSIBILITY: float = 0.01

#: The order subsystems are offered each transition. Deterministic because a
#: degraded run has to be reproducible: the same fault at the same transition must
#: produce the same record on every run.
ATTACHMENT_ORDER: tuple[Subsystem, ...] = tuple(Subsystem)

#: What the LUCID engine supplies per subsystem. The transition is passed so a
#: failure can be recorded ``at_sequence`` rather than at "somewhere in this
#: incident", and so a subsystem sees evidence incrementally, which is what
#: sequential evidence and active sensing need.
SubsystemHook = Callable[["IncidentEvidence", SSIRTransitionV1], object]


@dataclass(frozen=True, slots=True)
class IncidentEvidence:
    """Everything Stage 4 receives, and the only way it receives it."""

    incident_id: str
    epoch_id: int
    transitions: tuple[SSIRTransitionV1, ...]
    spine: tuple[CausalNode, ...]
    host_state: SecurityStateV1
    #: Read as evidence only, never as authority (ADR-0003).
    predictions: tuple[ThreatPredictionV1, ...]
    knowledge: CrystalKnowledge
    sensor: SensorPath
    #: True when any bound above dropped evidence. Explicit, because a bounded
    #: buffer that truncates silently becomes a false negative.
    truncated: bool

    def __post_init__(self) -> None:
        # T5 / ADR-0003, audited on construction rather than left to review: this
        # is the object every Stage 4 subsystem receives, so a field named after a
        # response is the one place authority could enter the cognition. The
        # helper is Stage 4's single implementation (§2.4) — a second copy is how
        # S2-AUTH-01 stayed open in two checkers at once.
        offenders = authority_named_fields(type(self))
        if offenders:
            raise ContractError(
                f"IncidentEvidence names response authority in {list(offenders)}; "
                "a verdict is an input to Stage 4, never an authorisation"
            )
        if not isinstance(self.incident_id, str) or not self.incident_id:
            raise ContractError("IncidentEvidence.incident_id must be a non-empty string")
        require_non_negative_int(self.epoch_id, "IncidentEvidence.epoch_id")
        object.__setattr__(self, "transitions", tuple(self.transitions))
        object.__setattr__(self, "spine", tuple(self.spine))
        object.__setattr__(self, "predictions", tuple(self.predictions))
        object.__setattr__(self, "sensor", SensorPath(self.sensor))
        self._validate_bounds()
        if not isinstance(self.host_state, SecurityStateV1):
            raise ContractError("IncidentEvidence.host_state must be a SecurityStateV1")
        if not isinstance(self.knowledge, CrystalKnowledge):
            raise ContractError("IncidentEvidence.knowledge must be a CrystalKnowledge")
        if not isinstance(self.truncated, bool):
            raise ContractError("IncidentEvidence.truncated must be a bool")

    def _validate_bounds(self) -> None:
        """Refuse an over-long incident rather than trimming it here.

        Trimming belongs to :func:`integrate_evidence`, which also sets
        ``truncated``. A constructor that silently trimmed would make a truncated
        incident indistinguishable from a short one.
        """
        if len(self.transitions) > MAX_TRANSITIONS_PER_INCIDENT:
            raise ContractError(
                f"IncidentEvidence holds {len(self.transitions)} transitions, "
                f"cap is {MAX_TRANSITIONS_PER_INCIDENT}"
            )
        if len(self.spine) > MAX_SPINE_NODES:
            raise ContractError(
                f"IncidentEvidence holds {len(self.spine)} spine nodes, cap is {MAX_SPINE_NODES}"
            )
        if len(self.predictions) > MAX_PREDICTIONS_PER_INCIDENT:
            raise ContractError(
                f"IncidentEvidence holds {len(self.predictions)} predictions, "
                f"cap is {MAX_PREDICTIONS_PER_INCIDENT}"
            )
        for index, transition in enumerate(self.transitions):
            if not isinstance(transition, SSIRTransitionV1):
                raise ContractError(f"IncidentEvidence.transitions[{index}] must be SSIR")
        for index, node in enumerate(self.spine):
            if not isinstance(node, CausalNode):
                raise ContractError(f"IncidentEvidence.spine[{index}] must be a CausalNode")
        for index, prediction in enumerate(self.predictions):
            if not isinstance(prediction, ThreatPredictionV1):
                raise ContractError(
                    f"IncidentEvidence.predictions[{index}] must be a ThreatPredictionV1"
                )

    @property
    def middle_sequence(self) -> int:
        """The sequence number half way through the incident.

        Used by fault injection to raise *mid-incident*: a subsystem that only
        ever fails on the first transition proves nothing about a system that has
        already built state.
        """
        if not self.transitions:
            return 0
        return self.transitions[len(self.transitions) // 2].sequence

    @property
    def observation_incomplete_count(self) -> int:
        """How many transitions arrived with fused observation incomplete.

        The direct input to the sensor shadow (D4.3), surfaced here so that model
        does not walk the transitions again for a count.
        """
        return sum(1 for item in self.transitions if item.observation_incomplete)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "epoch_id": self.epoch_id,
            "transitions": len(self.transitions),
            "spine": len(self.spine),
            "host_state": self.host_state.to_dict(),
            "predictions": len(self.predictions),
            "knowledge": self.knowledge.to_dict(),
            "sensor": self.sensor.value,
            "truncated": self.truncated,
            "observation_incomplete": self.observation_incomplete_count,
        }


def integrate_evidence(
    result: ScenarioResult,
    *,
    memory: CausalMemory,
    knowledge: CrystalKnowledge = EMPTY_KNOWLEDGE,
    predictions: Sequence[ThreatPredictionV1] = (),
    incident_id: str,
    sensor: SensorPath,
) -> IncidentEvidence:
    """Project one Stage 1 scenario plus its causal spine into incident evidence.

    The spine comes from :meth:`CausalMemory.spine` at
    :data:`SPINE_MIN_RESPONSIBILITY` (``memory.py:256``) rather than from a second
    traversal here: worlds are hypotheses over *that* spine, and a Stage 4 copy of
    the responsibility rule would be a second definition of responsibility.

    Truncation keeps the **most recent** evidence, matching Stage 0's bounded
    window, where ``truncated`` means "the window dropped what happened before
    this". It is reported, never silent.
    """
    if not isinstance(result, ScenarioResult):
        raise ContractError("integrate_evidence takes a Stage 1 ScenarioResult")
    if not isinstance(memory, CausalMemory):
        raise ContractError("integrate_evidence takes a Stage 1 CausalMemory")
    transitions = tuple(result.transitions)
    spine = memory.spine(min_responsibility=SPINE_MIN_RESPONSIBILITY)
    rows = tuple(predictions)
    truncated = (
        len(transitions) > MAX_TRANSITIONS_PER_INCIDENT
        or len(spine) > MAX_SPINE_NODES
        or len(rows) > MAX_PREDICTIONS_PER_INCIDENT
    )
    return IncidentEvidence(
        incident_id=incident_id,
        epoch_id=transitions[-1].epoch_id if transitions else 0,
        transitions=transitions[-MAX_TRANSITIONS_PER_INCIDENT:],
        spine=spine[-MAX_SPINE_NODES:],
        host_state=result.final_state,
        predictions=rows[-MAX_PREDICTIONS_PER_INCIDENT:],
        knowledge=knowledge,
        sensor=sensor,
        truncated=truncated,
    )


@dataclass(frozen=True, slots=True)
class AttachmentOutcome:
    """What the attached cognition produced, and what it lost on the way."""

    incident_id: str
    #: Last non-``None`` result per subsystem that is still live.
    results: Mapping[Subsystem, object]
    #: Subsystems disabled by a failure, in the order they failed.
    disabled: tuple[Subsystem, ...]
    #: Hook invocations actually made. Bounded by transitions x live subsystems.
    calls: int
    resolved: bool
    verdict: Verdict

    @property
    def degraded(self) -> bool:
        return bool(self.disabled)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "subsystems_reporting": sorted(key.value for key in self.results),
            "disabled": [item.value for item in self.disabled],
            "calls": self.calls,
            "resolved": self.resolved,
            "verdict": self.verdict.value,
        }


def run_attached_cognition(
    evidence: IncidentEvidence,
    *,
    hooks: Mapping[Subsystem, SubsystemHook],
    ledger: DegradationLedger,
) -> AttachmentOutcome:
    """Offer each transition to each live subsystem, every call guarded.

    The contract this function exists to keep: **no hook failure raises.**
    Whatever a hook does — ``RuntimeError``, ``MemoryError``, ``RecursionError``,
    a bare ``BaseException`` — the caller gets an :class:`AttachmentOutcome` back
    and the Stage 1–3 code that called it continues. A hook that fails is recorded
    once and then disabled, and the verdict passes through
    :func:`~pocketsec.stage4.engine.degradation.downgrade_verdict`, so a run with
    a hole in it can never come back ``BENIGN``. A malformed *hooks mapping* is a
    different thing — a wiring error, raised eagerly before any evidence is
    touched, exactly as ``validate_slot`` refuses a mis-wired slot.

    ``CLAIM_COMPILER`` is the subsystem that resolves: an incident that never
    reached the claim compiler has no authoritative claims and is therefore
    unresolved by definition (D4.13), whatever the other nine computed.
    """
    for key in hooks:
        try:
            known = Subsystem(key) in ATTACHMENT_ORDER
        except ValueError:
            known = False
        if not known:
            raise ContractError(f"unknown Stage 4 subsystem {key!r}")
    live = [item for item in ATTACHMENT_ORDER if item in hooks]
    disabled: list[Subsystem] = []
    results: dict[Subsystem, object] = {}
    calls = 0

    for transition in evidence.transitions:
        for subsystem in tuple(live):
            calls += 1
            scope = _offer(subsystem, hooks[subsystem], evidence, transition, ledger)
            if scope.failed:
                live.remove(subsystem)
                disabled.append(subsystem)
                results.pop(subsystem, None)
                continue
            if scope.result is not None:
                results[subsystem] = scope.result

    verdict, resolved = _attachment_verdict(results, disabled=tuple(disabled))
    return AttachmentOutcome(
        incident_id=evidence.incident_id,
        results=MappingProxyType(dict(results)),
        disabled=tuple(disabled),
        calls=calls,
        resolved=resolved,
        verdict=verdict,
    )


def _offer(
    subsystem: Subsystem,
    hook: SubsystemHook,
    evidence: IncidentEvidence,
    transition: SSIRTransitionV1,
    ledger: DegradationLedger,
) -> guarded:
    """One guarded hook call, returned as its scope so the caller can read both.

    ``evidence_preserved=True`` because the hook is handed an immutable
    :class:`IncidentEvidence` and owns none of it: a crash cannot take the
    evidence references with it, which is what makes the incident reconstructable
    (§45's last rule).
    """
    scope = guarded(
        subsystem,
        ledger,
        at_sequence=transition.sequence,
        fallback=None,
        evidence_preserved=True,
    )
    with scope:
        scope.result = hook(evidence, transition)
    return scope


def _attachment_verdict(
    results: Mapping[Subsystem, object], *, disabled: tuple[Subsystem, ...]
) -> tuple[Verdict, bool]:
    """Decide the attachment's verdict, and whether the incident was resolved.

    Two non-committal outcomes that must not be conflated: ``UNIDENTIFIABLE``
    means the claim compiler produced no resolution, and
    :data:`~pocketsec.stage4.engine.degradation.DEGRADED_VERDICT` means it
    produced one that the reasoning around it no longer supports. Reporting both
    as one value would hide which of the two happened, and only one of them is a
    Stage 4 defect.
    """
    proposed = results.get(Subsystem.CLAIM_COMPILER)
    compiled = isinstance(proposed, Verdict) and Subsystem.CLAIM_COMPILER not in disabled
    verdict = downgrade_verdict(
        proposed if compiled and isinstance(proposed, Verdict) else Verdict.UNIDENTIFIABLE,
        degraded=bool(disabled),
    )
    return verdict, compiled and verdict is proposed
