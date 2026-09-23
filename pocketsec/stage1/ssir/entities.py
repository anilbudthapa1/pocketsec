"""D1.3 (part) — the entity model: identity, semantics, evidence.

    Entity = (ExactIdentity, SemanticState, EvidencePointer)

Three layers, kept deliberately separate because three different consumers need
them: runtime correlation needs the exact identity, intelligence needs the
semantic state, and an investigator needs the evidence.

The load-bearing design choice is that **semantics are earned by behaviour, not
granted by name**. A binary called ``/usr/bin/curl`` gets no network semantics
for being called that; it gets them by opening a socket. This is what makes the
renamed-tool and unseen-binary adversarial tests (spec section 22) meaningful
rather than a test of string matching.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef

__all__ = [
    "Entity",
    "EntityKind",
    "SemanticBelief",
    "SemanticProperty",
    "UNKNOWN_ENTITY_KIND",
]


class EntityKind(IntEnum):
    """The initial entity universe (spec section 8).

    These are starting hypotheses, not a frozen taxonomy: Stage 1 experiments
    may merge or split them. ``UNKNOWN`` is deliberately value 0 and a
    first-class citizen — the system must never require a fixed vocabulary of
    executable names.
    """

    UNKNOWN = 0
    PROCESS = 1
    THREAD = 2
    USER = 3
    SESSION = 4
    FILE = 5
    DIRECTORY = 6
    SOCKET = 7
    ENDPOINT = 8
    SERVICE = 9
    PACKAGE = 10
    DEVICE = 11
    CONTAINER = 12
    NAMESPACE = 13
    CREDENTIAL = 14
    KERNEL_OBJECT = 15


UNKNOWN_ENTITY_KIND = EntityKind.UNKNOWN


class SemanticProperty(StrEnum):
    """Orthogonal semantic properties.

    Orthogonality is the point (spec section 8): a FILE can simultaneously be
    CREDENTIAL, PERSISTENCE, ROOT_OWNED and AUTHORIZATION_DATA. Modelling these
    as a single mutually-exclusive class would throw away exactly the
    combinations that carry security meaning.
    """

    # Capability properties, acquired by observed behaviour.
    INTERPRETER = "INTERPRETER"
    NETWORK_CAPABLE = "NETWORK_CAPABLE"
    NETWORK_CLIENT = "NETWORK_CLIENT"
    NETWORK_SERVER = "NETWORK_SERVER"
    PROCESS_SPAWNER = "PROCESS_SPAWNER"
    CREDENTIAL_READER = "CREDENTIAL_READER"
    PRIVILEGE_CHANGER = "PRIVILEGE_CHANGER"
    PERSISTENCE_WRITER = "PERSISTENCE_WRITER"

    # Object properties, derived from host metadata rather than behaviour.
    CREDENTIAL = "CREDENTIAL"
    AUTHORIZATION_DATA = "AUTHORIZATION_DATA"
    PERSISTENCE = "PERSISTENCE"
    ROOT_OWNED = "ROOT_OWNED"
    USER_WRITABLE = "USER_WRITABLE"
    SYSTEM_BINARY = "SYSTEM_BINARY"
    TEMP_LOCATION = "TEMP_LOCATION"
    EXTERNAL_ENDPOINT = "EXTERNAL_ENDPOINT"


#: Properties a process earns only by acting. Never assigned from a name or
#: path, so renaming a binary cannot transfer them.
BEHAVIOURAL_PROPERTIES = frozenset(
    {
        SemanticProperty.INTERPRETER,
        SemanticProperty.NETWORK_CAPABLE,
        SemanticProperty.NETWORK_CLIENT,
        SemanticProperty.NETWORK_SERVER,
        SemanticProperty.PROCESS_SPAWNER,
        SemanticProperty.CREDENTIAL_READER,
        SemanticProperty.PRIVILEGE_CHANGER,
        SemanticProperty.PERSISTENCE_WRITER,
    }
)

#: Neutral prior for a property with no evidence either way. Explicitly 0.5 and
#: not 0.0: "we have not seen it" is uncertainty, not absence.
NEUTRAL_BELIEF = 0.5

#: Belief at or above which a property is treated as held.
ASSERT_THRESHOLD = 0.75


@dataclass(frozen=True, slots=True)
class SemanticBelief:
    """Probabilistic semantics for one entity (spec section 10).

    Beliefs stay explicitly uncertain while evidence is incomplete. An unknown
    binary is ``UNKNOWN`` with high uncertainty — never defaulted to benign and
    never defaulted to malicious (hard requirement, spec section 28).
    """

    kind: EntityKind = EntityKind.UNKNOWN
    properties: dict[SemanticProperty, float] = field(default_factory=dict)
    #: Count of behavioural observations folded in. Drives uncertainty decay.
    observations: int = 0

    def __post_init__(self) -> None:
        for prop, value in self.properties.items():
            if not isinstance(prop, SemanticProperty):
                raise ContractError(f"unknown semantic property {prop!r}")
            if not 0.0 <= value <= 1.0:
                raise ContractError(f"belief for {prop} must be in [0, 1], got {value!r}")
        object.__setattr__(self, "properties", MappingProxyType(dict(self.properties)))

    def belief(self, prop: SemanticProperty) -> float:
        return self.properties.get(prop, NEUTRAL_BELIEF)

    def holds(self, prop: SemanticProperty) -> bool:
        return self.belief(prop) >= ASSERT_THRESHOLD

    @property
    def asserted(self) -> frozenset[SemanticProperty]:
        return frozenset(prop for prop in self.properties if self.holds(prop))

    @property
    def uncertainty(self) -> float:
        """Semantic uncertainty in [0, 1].

        Two sources compound: an UNKNOWN kind, and beliefs sitting near the
        neutral prior. Uncertainty falls as behaviour accumulates, but never to
        zero — the semantic compiler is inferring, not observing ground truth.
        """
        kind_penalty = 0.5 if self.kind is EntityKind.UNKNOWN else 0.0
        if self.properties:
            # Distance from the neutral prior, averaged: 0 when every belief is
            # decided, 1 when every belief is a coin flip.
            indecision = sum(
                1.0 - 2.0 * abs(value - NEUTRAL_BELIEF) for value in self.properties.values()
            ) / len(self.properties)
        else:
            indecision = 1.0
        evidence_relief = 1.0 / (1.0 + self.observations)
        raw = kind_penalty + (1.0 - kind_penalty) * indecision * evidence_relief
        return max(0.05, min(1.0, raw))

    def observe(self, prop: SemanticProperty, *, support: float) -> SemanticBelief:
        """Fold one behavioural observation into the belief, immutably.

        A bounded multiplicative update: repeated evidence moves belief toward
        1.0 with diminishing returns and can never reach certainty. Capping
        below 1.0 keeps ``uncertainty`` honest about inference remaining
        inference.
        """
        if not 0.0 <= support <= 1.0:
            raise ContractError(f"support must be in [0, 1], got {support!r}")
        current = self.belief(prop)
        updated = min(0.99, current + support * (1.0 - current))
        merged = {**dict(self.properties), prop: updated}
        return SemanticBelief(
            kind=self.kind, properties=merged, observations=self.observations + 1
        )

    def classify(
        self,
        *,
        present: frozenset[SemanticProperty],
        evaluated: frozenset[SemanticProperty],
    ) -> SemanticBelief:
        """Record a metadata classification, **including its negative results**.

        Absence from ``properties`` means "never considered", which is genuine
        ignorance. A property that was evaluated and found absent is different:
        that is evidence, and recording it as a low belief rather than omitting
        it is what stops an ordinary log file from looking as uncertain as an
        unclassified one.

        Conflating the two made routine reads carry high uncertainty, which in
        turn suppressed aggregation and drove needless observation escalation.
        """
        updated = dict(self.properties)
        for prop in evaluated:
            if prop in present:
                updated[prop] = 0.95
            else:
                updated.setdefault(prop, 0.05)
        return SemanticBelief(
            kind=self.kind, properties=updated, observations=self.observations + 1
        )

    def note_observation(self) -> SemanticBelief:
        """Record that this entity was observed acting, earning no new property.

        Watching an entity behave is evidence even when it demonstrates nothing
        new: a process seen doing eight file reads and nothing else is better
        characterised than one seen once. This is progressive semantic
        resolution (spec section 10) in its quietest form.
        """
        return replace(self, observations=self.observations + 1)

    def with_kind(self, kind: EntityKind) -> SemanticBelief:
        return replace(self, kind=kind)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.name,
            "properties": {prop.value: round(value, 4) for prop, value in self.properties.items()},
            "asserted": sorted(prop.value for prop in self.asserted),
            "observations": self.observations,
            "uncertainty": round(self.uncertainty, 4),
        }


@dataclass(frozen=True, slots=True)
class Entity:
    """One entity across all three layers."""

    #: Layer 1 — stable identity for runtime correlation. For a process this is
    #: boot+pid+start-time (pid alone is reused); for a file, an inode-aware
    #: key. Never the display name.
    identity: str
    #: Layer 2 — what intelligence consumes.
    semantics: SemanticBelief = field(default_factory=SemanticBelief)
    #: Layer 3 — what an investigator consumes. Referenced, never inlined.
    evidence: tuple[EvidenceRef, ...] = ()
    #: Human-facing label (path, command line). Retained for investigation and
    #: deliberately excluded from the model-facing SSIR encoding: Stage 1
    #: non-goal forbids making executable names mandatory model vocabulary.
    display_name: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.identity, str) or not self.identity:
            raise ContractError("Entity.identity must be a non-empty string")
        if not isinstance(self.semantics, SemanticBelief):
            raise ContractError("Entity.semantics must be a SemanticBelief")
        object.__setattr__(self, "evidence", tuple(self.evidence))

    @property
    def kind(self) -> EntityKind:
        return self.semantics.kind

    @property
    def uncertainty(self) -> float:
        return self.semantics.uncertainty

    def observe(self, prop: SemanticProperty, *, support: float) -> Entity:
        return replace(self, semantics=self.semantics.observe(prop, support=support))

    def with_semantics(self, semantics: SemanticBelief) -> Entity:
        return replace(self, semantics=semantics)

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity,
            "display_name": self.display_name,
            "semantics": self.semantics.to_dict(),
            "evidence": [ref.to_dict() for ref in self.evidence],
        }
