"""D1.3 — the semantic compiler (spec section 16).

    Linux sources -> Raw Event Assembler -> Semantic Compiler
                                              /   |   |   \\
                                        Entity Relation State Evidence
                                              \\   |   |   /
                                                SSIR transition
                                              /            \\
                              Host Security State        Evidence Store

**This module is the compatibility boundary.** Different sensors describing
equivalent behaviour must converge on equivalent SSIR transitions — that is
acceptance criterion 1, and it is why the compiler reads from the fused
``EvidenceEvent``'s merged fields rather than from any one sensor's record shape.

Semantics are earned by behaviour. The compiler assigns capability properties
from what an entity *did* (opened a socket, spawned a child, read a credential),
never from what it is called. Renaming ``curl`` to ``/tmp/x91`` changes the
display name and nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pocketsec.stage1.compiler.entity_registry import EntityRegistry
from pocketsec.stage1.compiler.rules import (
    OPERATION_RULES,
    OperationRule,
    classify_operation,
)
from pocketsec.stage1.novelty.engine import NoveltyEngine
from pocketsec.stage1.ssir.entities import Entity, SemanticProperty
from pocketsec.stage1.ssir.transition import (
    RepresentationLevel,
    SSIRTransitionV1,
    TemporalContext,
)
from pocketsec.stage1.state.potential import phi
from pocketsec.stage1.state.security_state import SecurityStateV1, StateDelta
from pocketsec.stage1.telemetry.raw_event_v1 import EvidenceEvent

__all__ = ["CompilerStats", "SemanticCompiler"]

#: Uncertainty floor added when fusion was incomplete or sensors disagreed.
#: Incomplete observation must raise uncertainty, never default to benign or
#: malicious (hard requirement, spec section 28).
PARTIAL_OBSERVATION_UNCERTAINTY = 0.35
CONFLICT_UNCERTAINTY = 0.25


@dataclass(frozen=True, slots=True)
class CompilerStats:
    compiled: int = 0
    unresolved_relation: int = 0
    partial_observations: int = 0
    sensor_conflicts: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "compiled": self.compiled,
            "unresolved_relation": self.unresolved_relation,
            "partial_observations": self.partial_observations,
            "sensor_conflicts": self.sensor_conflicts,
        }


class SemanticCompiler:
    """Compiles fused telemetry into SSIR transitions and host state.

    Holds the per-host mutable substrate — entity registry, novelty engine,
    lineage states, causal memory — because compilation is inherently stateful:
    "what is now true" depends on everything that came before.
    """

    def __init__(
        self,
        *,
        host_id: str,
        novelty: NoveltyEngine | None = None,
        registry: EntityRegistry | None = None,
        max_lineages: int = 256,
    ) -> None:
        self.host_id = host_id
        self.novelty = novelty or NoveltyEngine()
        self.registry = registry or EntityRegistry()
        self._max_lineages = max_lineages
        self._lineage_state: dict[str, SecurityStateV1] = {}
        self._lineage_signature: dict[str, str] = {}
        self._last_seen_ns: dict[str, int] = {}
        self._last_host_ns = 0
        self._sequence = 0
        self._compiled = 0
        self._unresolved = 0
        self._partial = 0
        self._conflicts = 0

    # --- public API -----------------------------------------------------

    def stats(self) -> CompilerStats:
        return CompilerStats(
            compiled=self._compiled,
            unresolved_relation=self._unresolved,
            partial_observations=self._partial,
            sensor_conflicts=self._conflicts,
        )

    def host_state(self) -> SecurityStateV1:
        """The host aggregate: the lattice join over all live lineages."""
        state = SecurityStateV1()
        for lineage_state in self._lineage_state.values():
            state = SecurityStateV1.join(state, lineage_state)
        return state

    def lineage_state(self, lineage: str) -> SecurityStateV1:
        return self._lineage_state.get(lineage, SecurityStateV1())

    def compile(
        self, event: EvidenceEvent, *, epoch_id: int = 0
    ) -> SSIRTransitionV1 | None:
        """Compile one fused operation into an SSIR transition.

        Returns ``None`` when the operation carries no recognisable machine
        relation. Returning None rather than inventing a relation matters: an
        unrecognised operation is missing information, and fabricating a
        relation would put that fabrication into the model's training data.
        """
        rule = classify_operation(event)
        if rule is None:
            self._unresolved += 1
            return None

        fields = event.merged_fields()
        actor, obj = self._resolve_entities(event, rule, fields)
        actor = self._apply_behavioural_semantics(actor, rule)

        lineage = self._lineage_key(actor)
        before = self.lineage_state(lineage)
        after = self._apply_state_operators(before, rule, obj)
        delta = StateDelta.between(before, after)
        self._store_lineage_state(lineage, after)

        novelty = self.novelty.observe(self._novelty_keys(actor, obj, rule, fields))
        uncertainty = self._uncertainty(event, actor, obj)
        temporal = self._temporal(actor, event)

        self._sequence += 1
        transition = self._build(
            event=event,
            rule=rule,
            actor=actor,
            obj=obj,
            before=before,
            after=after,
            delta=delta,
            novelty=novelty,
            uncertainty=uncertainty,
            temporal=temporal,
            lineage=lineage,
            epoch_id=epoch_id,
        )
        self._compiled += 1
        return transition

    # --- internals ------------------------------------------------------

    def _resolve_entities(
        self, event: EvidenceEvent, rule: OperationRule, fields: dict[str, str]
    ) -> tuple[Entity, Entity]:
        actor = self.registry.resolve_actor(event, fields)
        obj = self.registry.resolve_object(event, rule, fields)
        return actor, obj

    def _apply_behavioural_semantics(self, actor: Entity, rule: OperationRule) -> Entity:
        """Grant the actor the capabilities this operation demonstrates.

        This is progressive semantic resolution (spec section 10): /tmp/x91
        becomes NETWORK_CLIENT because it connected, not because of its path.
        """
        updated = actor
        for prop in rule.actor_properties:
            updated = updated.observe(prop, support=rule.property_support)
        if updated is actor:
            # No new capability demonstrated, but we still watched it act.
            # That is evidence: an actor seen behaving consistently is better
            # characterised than one seen once, and its uncertainty should fall.
            updated = actor.with_semantics(actor.semantics.note_observation())
        self.registry.update(updated)
        return updated

    @staticmethod
    def _apply_state_operators(
        state: SecurityStateV1, rule: OperationRule, obj: Entity
    ) -> SecurityStateV1:
        """Apply the rule's lattice operators, conditioned on object semantics."""
        updated = state
        for dimension, level in rule.raises:
            updated = updated.raised_to(dimension, level)
        for prop, dimension, level in rule.conditional_raises:
            if obj.semantics.holds(prop):
                updated = updated.raised_to(dimension, level)
        return updated

    def _lineage_key(self, actor: Entity) -> str:
        return actor.identity

    def _store_lineage_state(self, lineage: str, state: SecurityStateV1) -> None:
        """Record lineage state under a hard cap.

        Evicting the *lowest-Φ* lineage rather than the oldest keeps an active
        attack chain resident while a noisy build process churns through slots.
        """
        self._lineage_state[lineage] = state
        while len(self._lineage_state) > self._max_lineages:
            victim = min(self._lineage_state, key=lambda k: phi(self._lineage_state[k]).total)
            self._lineage_state.pop(victim)
            self._lineage_signature.pop(victim, None)

    @staticmethod
    def _novelty_keys(
        actor: Entity, obj: Entity, rule: OperationRule, fields: dict[str, str]
    ) -> dict[str, str]:
        """Build the per-context novelty keys.

        Keys are built from *semantics* wherever possible, so novelty tracks
        behaviour rather than memorising identity strings.
        """
        actor_sem = ",".join(sorted(p.value for p in actor.semantics.asserted)) or "none"
        object_sem = ",".join(sorted(p.value for p in obj.semantics.asserted)) or "none"
        relation = rule.relation.name
        return {
            "host": f"{relation}:{actor_sem}:{object_sem}",
            "user": f"{fields.get('uid', '?')}:{relation}",
            "actor": f"{actor.identity}:{relation}",
            "parent_child": f"{fields.get('ppid', '?')}->{fields.get('pid', '?')}",
            "object": f"{obj.kind.name}:{object_sem}",
            "relation": relation,
            "time": f"{relation}:{fields.get('hour', '?')}",
            "causal": f"{actor_sem}|{relation}|{object_sem}",
        }

    def _uncertainty(self, event: EvidenceEvent, actor: Entity, obj: Entity) -> float:
        """U — combined semantic and observational uncertainty.

        Semantic uncertainty comes from the entities; observational uncertainty
        from incomplete fusion and sensor disagreement. They compound, and the
        result is never zero.
        """
        semantic = max(actor.uncertainty, obj.uncertainty)
        observational = 0.0
        if event.partial:
            observational += PARTIAL_OBSERVATION_UNCERTAINTY
            self._partial += 1
        if event.conflicting_fields():
            observational += CONFLICT_UNCERTAINTY
            self._conflicts += 1
        return min(1.0, semantic * 0.5 + observational + 0.05)

    def _temporal(self, actor: Entity, event: EvidenceEvent) -> TemporalContext:
        now = event.monotonic_ns
        since_actor = now - self._last_seen_ns.get(actor.identity, now)
        since_host = now - (self._last_host_ns or now)
        self._last_seen_ns[actor.identity] = now
        self._last_host_ns = now
        # Bound the per-actor timing table alongside the lineage cap.
        if len(self._last_seen_ns) > self._max_lineages * 2:
            self._last_seen_ns.pop(next(iter(self._last_seen_ns)))
        return TemporalContext(
            since_actor_bucket=TemporalContext.bucket(since_actor),
            since_host_bucket=TemporalContext.bucket(since_host),
        )

    def _build(
        self,
        *,
        event: EvidenceEvent,
        rule: OperationRule,
        actor: Entity,
        obj: Entity,
        before: SecurityStateV1,
        after: SecurityStateV1,
        delta: StateDelta,
        novelty: Any,
        uncertainty: float,
        temporal: TemporalContext,
        lineage: str,
        epoch_id: int,
    ) -> SSIRTransitionV1:
        from pocketsec.stage1.causal.memory import causal_signature

        parent = self._lineage_signature.get(lineage, "0" * 16)
        signature = causal_signature(
            parent_signature=parent,
            actor_semantics=frozenset(p.value for p in actor.semantics.asserted),
            relation=int(rule.relation),
            object_semantics=frozenset(p.value for p in obj.semantics.asserted),
            state_delta=delta,
        )
        self._lineage_signature[lineage] = signature

        delta_phi_value = phi(after).total - phi(before).total
        return SSIRTransitionV1(
            actor=actor,
            relation=rule.relation,
            object=obj,
            state_delta=delta,
            uncertainty=uncertainty,
            novelty=novelty,
            causal_signature=signature,
            parent_signature=parent,
            responsibility=max(0.0, delta_phi_value),
            temporal=temporal,
            evidence=event.evidence_refs,
            epoch_id=epoch_id,
            sequence=self._sequence,
            level=_choose_level(delta, novelty.peak, uncertainty),
            delta_phi=delta_phi_value,
            observation_incomplete=event.partial or bool(event.conflicting_fields()),
        )


def _choose_level(
    delta: StateDelta, novelty_peak: float, uncertainty: float
) -> RepresentationLevel:
    """Policy-driven representation escalation (spec section 18).

    Richness increases when novelty, security potential or uncertainty justify
    the cost. A state change always earns at least L2 — a capability gain is
    exactly what an investigator will come back for.
    """
    if delta and delta.magnitude >= 2:
        return RepresentationLevel.L3
    if delta:
        return RepresentationLevel.L2
    if novelty_peak >= 0.8 or uncertainty >= 0.6:  # noqa: PLR2004
        return RepresentationLevel.L2
    if novelty_peak >= 0.4:  # noqa: PLR2004
        return RepresentationLevel.L1
    return RepresentationLevel.L0


assert SemanticProperty  # re-exported for rule modules
assert OPERATION_RULES
