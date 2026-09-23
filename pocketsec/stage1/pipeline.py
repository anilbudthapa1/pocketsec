"""The Stage 1 pipeline: telemetry in, SSIR + host state out.

Wires the subsystems into the order the spec's block diagram describes, and is
the single place a scenario is turned into transitions. Everything downstream —
the gate, the guillotine, the adversarial harness, the Stage 2 fixtures — runs
through here, so they are all measuring the same system.

    raw records -> assembler -> semantic compiler -> causal memory
                                     |                    |
                                     +-> epoch model      +-> AOP
                                     |
                                     +-> aggregation -> emitted SSIR
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pocketsec.stage1.aggregation.policy import AggregationPolicy
from pocketsec.stage1.causal.memory import CausalMemory
from pocketsec.stage1.compiler.semantic_compiler import SemanticCompiler
from pocketsec.stage1.epoch.model import EpochModel, SystemIdentity
from pocketsec.stage1.labs.corpus import Scenario, emit
from pocketsec.stage1.novelty.engine import NoveltyEngine
from pocketsec.stage1.observation.policy import AdaptiveObservationPolicy
from pocketsec.stage1.ssir.transition import SSIRTransitionV1
from pocketsec.stage1.state.potential import phi
from pocketsec.stage1.state.security_state import SecurityStateV1
from pocketsec.stage1.telemetry.assembler import EventAssembler
from pocketsec.stage1.telemetry.raw_event_v1 import SensorPath

__all__ = ["ScenarioResult", "Stage1Pipeline"]


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    """Everything one scenario produced."""

    scenario: Scenario
    transitions: tuple[SSIRTransitionV1, ...]
    emitted: tuple[SSIRTransitionV1, ...]
    final_state: SecurityStateV1
    peak_phi: float
    peak_novelty: float
    peak_uncertainty: float
    unresolved: int

    @property
    def semantic_keys(self) -> tuple[Any, ...]:
        """The sensor-independent semantics, for equivalence comparison."""
        return tuple(t.semantic_key() for t in self.transitions)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario.to_dict(),
            "transitions": len(self.transitions),
            "emitted": len(self.emitted),
            "final_state": self.final_state.to_dict(),
            "peak_phi": round(self.peak_phi, 4),
            "peak_novelty": round(self.peak_novelty, 4),
            "peak_uncertainty": round(self.peak_uncertainty, 4),
            "unresolved": self.unresolved,
        }


@dataclass
class Stage1Pipeline:
    """One host's Stage 1 substrate."""

    host_id: str = "lab-host-01"
    identity: SystemIdentity = field(
        default_factory=lambda: SystemIdentity(
            kernel_id="6.1.0", package_digest="pkg-a", service_digest="svc-a"
        )
    )
    novelty: NoveltyEngine = field(default_factory=NoveltyEngine)
    causal: CausalMemory = field(default_factory=CausalMemory)
    aggregation: AggregationPolicy = field(default_factory=AggregationPolicy)
    observation: AdaptiveObservationPolicy = field(
        default_factory=AdaptiveObservationPolicy
    )

    def __post_init__(self) -> None:
        self.epoch = EpochModel(identity=self.identity)
        self.compiler = SemanticCompiler(host_id=self.host_id, novelty=self.novelty)
        self._lineage_responsibility: dict[str, float] = {}

    def run_scenario(
        self, scenario: Scenario, *, sensor: SensorPath = SensorPath.EBPF, offset: int = 0
    ) -> ScenarioResult:
        """Replay one scenario through a given sensor path.

        Each scenario gets a fresh assembler and a fresh lineage: scenarios are
        independent actors, and leaking state between them would manufacture
        capability accumulation the corpus never described.
        """
        assembler = EventAssembler()
        transitions: list[SSIRTransitionV1] = []
        emitted: list[SSIRTransitionV1] = []
        unresolved = 0
        pid = str(1000 + offset)

        events = []
        for index, behaviour in enumerate(scenario.behaviours):
            for record in emit(
                behaviour,
                sensor=sensor,
                index=offset * 100 + index,
                host_id=self.host_id,
                pid=pid,
            ):
                events.extend(assembler.feed(record))
        events.extend(assembler.flush())

        for event in events:
            transition = self.compiler.compile(event, epoch_id=self.epoch.epoch_id)
            if transition is None:
                unresolved += 1
                continue
            self.epoch.record_transition()
            transitions.append(transition)
            self._record_causal(transition)
            self._consider_observation(transition)
            if self.aggregation.offer(transition) is not None:
                emitted.append(transition)

        lineage = f"proc:boot-0001:{pid}:7"
        final = self.compiler.lineage_state(lineage)
        return ScenarioResult(
            scenario=scenario,
            transitions=tuple(transitions),
            emitted=tuple(emitted),
            final_state=final,
            peak_phi=phi(final).total,
            peak_novelty=max((t.novelty.peak for t in transitions), default=0.0),
            peak_uncertainty=max((t.uncertainty for t in transitions), default=0.0),
            unresolved=unresolved,
        )

    def _record_causal(self, transition: SSIRTransitionV1) -> None:
        self.causal.record(
            parent_signature=transition.parent_signature,
            actor_semantics=frozenset(p.value for p in transition.actor.semantics.asserted),
            relation=int(transition.relation),
            object_semantics=frozenset(p.value for p in transition.object.semantics.asserted),
            state_delta=transition.state_delta,
            delta_phi=transition.delta_phi,
            actor_identity=transition.actor.identity,
            evidence_locators=tuple(ref.locator for ref in transition.evidence[:2]),
        )

    def _consider_observation(self, transition: SSIRTransitionV1) -> None:
        # Causal relevance is a property of the LINEAGE, not of this single
        # transition. Reusing this transition's ΔΦ here would put security
        # potential into the product twice and make the third factor decorative.
        lineage = transition.actor.identity
        cumulative = self._lineage_responsibility.get(lineage, 0.0) + max(
            0.0, transition.delta_phi
        )
        self._lineage_responsibility[lineage] = cumulative
        relevance = cumulative / (1.0 + cumulative)

        decision = self.observation.consider(
            target=lineage,
            uncertainty=transition.uncertainty,
            security_potential=max(0.0, transition.delta_phi),
            causal_relevance=relevance,
            now_ns=transition.sequence * 1_000_000,
        )
        if decision.escalated:
            # Escalation buys richer semantics on the actor, which in this
            # prototype resolves a measurable slice of semantic uncertainty.
            self.observation.record_observation(
                transition.actor.identity,
                extra_events=4,
                uncertainty_now=max(0.05, transition.uncertainty * 0.5),
            )

    def report(self) -> dict[str, Any]:
        return {
            "host_id": self.host_id,
            "compiler": self.compiler.stats().to_dict(),
            "novelty_memory_bytes": self.novelty.memory_bytes,
            "causal": self.causal.to_dict(),
            "aggregation": self.aggregation.report().to_dict(),
            "observation": self.observation.report().to_dict(),
            "epoch": self.epoch.to_dict(),
            "registry": self.compiler.registry.to_dict(),
        }
