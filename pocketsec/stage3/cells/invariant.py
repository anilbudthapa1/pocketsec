"""D3.3 types — Behavioural Invariants over Stage 1 *semantics*, never identities.

An invariant is the generalised relationship a Knowledge Cell is compiled from:
"an actor holding these semantic properties, in this relation family, raises
these security dimensions". The architecture's own example is the point —

    nginx  -> interpreter -> credential access
    apache -> interpreter -> credential access
    custom -> interpreter -> credential access
    =>  NETWORK_SERVER + PROCESS_SPAWNER -> CHILD_INTERPRETER -> CREDENTIAL

— the three executable names are what anti-unification is supposed to throw
away. ``SemanticPredicate`` therefore refuses to *hold* an identity at all: its
``__post_init__`` audits its own field names for ``name``, ``identity`` and
``path`` and raises if one appears. That is a structural guarantee against a
future contributor adding ``process_name: str`` "just for debugging" and turning
a semantic invariant into a signature (ADR-0006, ADR-0007).

The types live here, in ``foundation``, rather than beside the discovery engine,
so that ``invariants/discovery.py`` and ``cells/schema.py`` can both depend on
them without a circular import.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    EvidenceRef,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage1.ssir.entities import Entity, EntityKind, SemanticProperty
from pocketsec.stage1.ssir.relations import Relation, RelationFamily, family_of
from pocketsec.stage1.state.security_state import DIMENSIONS
from pocketsec.stage3.theory import SecurityConsequence

__all__ = [
    "FORBIDDEN_PREDICATE_FIELD_TOKENS",
    "Invariant",
    "MAX_ANTECEDENT_TERMS",
    "MAX_EVIDENCE_KINDS",
    "PredicateRole",
    "SemanticPredicate",
    "ConsequentSpec",
]

#: A conjunction of more than four semantic terms stops being an invariant and
#: starts being a memorised trace; it also blows up boundary key expansion.
MAX_ANTECEDENT_TERMS = 4

#: Bound on the evidence-kind requirement set, so a consequent cannot demand an
#: unbounded list of signals the collector would have to satisfy per event.
MAX_EVIDENCE_KINDS = 16

#: Field-name fragments that would smuggle an identity into a semantic
#: predicate. Substring-matched on the lowered field name, so ``process_name``
#: and ``exe_path`` are caught as well as ``name`` and ``path``.
FORBIDDEN_PREDICATE_FIELD_TOKENS = frozenset({"name", "identity", "path"})


class PredicateRole(StrEnum):
    """Which side of the relation a predicate constrains."""

    ACTOR = "ACTOR"
    OBJECT = "OBJECT"


@dataclass(frozen=True, slots=True)
class SemanticPredicate:
    """One semantic condition on an actor or object.

    Both a required and a forbidden set, because "INTERPRETER and not
    SYSTEM_BINARY" is a different hypothesis from "INTERPRETER", and collapsing
    them would make the invariant broader than the evidence supports.
    """

    role: PredicateRole
    required_properties: frozenset[SemanticProperty]
    forbidden_properties: frozenset[SemanticProperty]
    relation_family: RelationFamily | None
    entity_kind: EntityKind | None

    def __post_init__(self) -> None:
        _audit_field_names(type(self))
        if not isinstance(self.role, PredicateRole):
            raise ContractError(
                f"SemanticPredicate.role must be a PredicateRole, got {self.role!r}"
            )
        required = _require_property_set(self.required_properties, "required_properties")
        forbidden = _require_property_set(self.forbidden_properties, "forbidden_properties")
        overlap = required & forbidden
        if overlap:
            raise ContractError(
                f"SemanticPredicate requires and forbids {sorted(p.value for p in overlap)}; "
                "a predicate that can never match is not a hypothesis, it is a bug"
            )
        if self.relation_family is not None and not isinstance(
            self.relation_family, RelationFamily
        ):
            raise ContractError(
                "SemanticPredicate.relation_family must be a RelationFamily or None"
            )
        if self.entity_kind is not None and not isinstance(self.entity_kind, EntityKind):
            raise ContractError("SemanticPredicate.entity_kind must be an EntityKind or None")

    def matches(self, entity: Entity, relation: Relation) -> bool:
        """Does this entity, in this relation, satisfy the predicate?

        Reads ``entity.semantics.asserted`` — the properties whose belief crossed
        Stage 1's assert threshold. Beliefs below it are *uncertain*, not absent,
        and a compiled cell must not treat uncertainty as a negative answer.
        """
        if not isinstance(entity, Entity):
            raise ContractError(f"SemanticPredicate.matches expects an Entity, got {entity!r}")
        if not isinstance(relation, Relation):
            raise ContractError(f"SemanticPredicate.matches expects a Relation, got {relation!r}")
        if self.entity_kind is not None and entity.kind is not self.entity_kind:
            return False
        if self.relation_family is not None and family_of(relation) is not self.relation_family:
            return False
        asserted = entity.semantics.asserted
        if not self.required_properties <= asserted:
            return False
        return not (self.forbidden_properties & asserted)

    def generality(self) -> int:
        """How many properties this predicate leaves unconstrained.

        Higher is more general. Used by discovery to prefer the *most specific*
        shared generalisation: a predicate constraining nothing matches the whole
        host and would silently extrapolate.
        """
        return len(SemanticProperty) - len(self.required_properties) - len(
            self.forbidden_properties
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role.value,
            "required_properties": sorted(p.value for p in self.required_properties),
            "forbidden_properties": sorted(p.value for p in self.forbidden_properties),
            "relation_family": None
            if self.relation_family is None
            else int(self.relation_family),
            "entity_kind": None if self.entity_kind is None else int(self.entity_kind),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> SemanticPredicate:
        try:
            family = payload["relation_family"]
            kind = payload["entity_kind"]
            return cls(
                role=PredicateRole(str(payload["role"])),
                required_properties=frozenset(
                    SemanticProperty(str(p)) for p in payload["required_properties"]
                ),
                forbidden_properties=frozenset(
                    SemanticProperty(str(p)) for p in payload["forbidden_properties"]
                ),
                relation_family=None if family is None else RelationFamily(int(family)),
                entity_kind=None if kind is None else EntityKind(int(kind)),
            )
        except KeyError as exc:
            raise ContractError(f"SemanticPredicate missing field {exc.args[0]!r}") from exc
        except ValueError as exc:
            raise ContractError(f"SemanticPredicate could not be rebuilt: {exc}") from exc


@dataclass(frozen=True, slots=True)
class ConsequentSpec:
    """What the antecedent is claimed to imply, in Stage 1's own vocabulary."""

    required_dimensions: frozenset[str]
    min_delta_phi: float
    required_evidence_kinds: frozenset[str]
    consequence: SecurityConsequence

    def __post_init__(self) -> None:
        if not isinstance(self.required_dimensions, frozenset):
            raise ContractError("ConsequentSpec.required_dimensions must be a frozenset")
        unknown = set(self.required_dimensions) - set(DIMENSIONS)
        if unknown:
            raise ContractError(
                f"ConsequentSpec.required_dimensions must be a subset of DIMENSIONS, "
                f"unknown: {sorted(unknown)}"
            )
        if not self.required_dimensions:
            raise ContractError(
                "ConsequentSpec.required_dimensions must be non-empty: an invariant that "
                "predicts no security-state change predicts nothing worth compiling"
            )
        if (
            isinstance(self.min_delta_phi, bool)
            or not isinstance(self.min_delta_phi, (int, float))
            or self.min_delta_phi != self.min_delta_phi
        ):
            raise ContractError(
                f"ConsequentSpec.min_delta_phi must be a finite number, got {self.min_delta_phi!r}"
            )
        if not isinstance(self.required_evidence_kinds, frozenset):
            raise ContractError("ConsequentSpec.required_evidence_kinds must be a frozenset")
        if len(self.required_evidence_kinds) > MAX_EVIDENCE_KINDS:
            raise ContractError(
                f"ConsequentSpec.required_evidence_kinds holds "
                f"{len(self.required_evidence_kinds)} kinds, above {MAX_EVIDENCE_KINDS}"
            )
        for kind in self.required_evidence_kinds:
            require_identifier(kind, "ConsequentSpec.required_evidence_kinds entry")
        if not isinstance(self.consequence, SecurityConsequence):
            raise ContractError("ConsequentSpec.consequence must be a SecurityConsequence")

    def to_dict(self) -> dict[str, Any]:
        return {
            "required_dimensions": sorted(self.required_dimensions),
            "min_delta_phi": float(self.min_delta_phi),
            "required_evidence_kinds": sorted(self.required_evidence_kinds),
            "consequence": int(self.consequence),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ConsequentSpec:
        try:
            return cls(
                required_dimensions=frozenset(str(d) for d in payload["required_dimensions"]),
                min_delta_phi=float(payload["min_delta_phi"]),
                required_evidence_kinds=frozenset(
                    str(k) for k in payload["required_evidence_kinds"]
                ),
                consequence=SecurityConsequence(int(payload["consequence"])),
            )
        except KeyError as exc:
            raise ContractError(f"ConsequentSpec missing field {exc.args[0]!r}") from exc
        except ValueError as exc:
            raise ContractError(f"ConsequentSpec could not be rebuilt: {exc}") from exc


@dataclass(frozen=True, slots=True)
class Invariant:
    """A falsifiable relationship between semantics and security outcome (§8).

    ``support`` counts **distinct causal lineages**, never events. A pattern seen
    a thousand times inside one lineage has one witness, and treating repetition
    as corroboration is precisely the anti-poisoning failure ADR-0007 closed.

    ``falsifier`` is mandatory and non-empty: the architecture requires an
    invariant to remain a hypothesis until something could refute it. A relation
    with no stated refutation is not an invariant, it is a belief.
    """

    invariant_id: str
    antecedent: tuple[SemanticPredicate, ...]
    consequent: ConsequentSpec
    support: int
    contradictions: int
    identities_collapsed: int
    epochs: frozenset[int]
    falsifier: str
    evidence: tuple[EvidenceRef, ...]

    def __post_init__(self) -> None:
        require_identifier(self.invariant_id, "Invariant.invariant_id")
        self._require_antecedent()
        if not isinstance(self.consequent, ConsequentSpec):
            raise ContractError("Invariant.consequent must be a ConsequentSpec")
        require_non_negative_int(self.support, "Invariant.support")
        require_non_negative_int(self.contradictions, "Invariant.contradictions")
        require_non_negative_int(self.identities_collapsed, "Invariant.identities_collapsed")
        if not isinstance(self.epochs, frozenset) or not self.epochs:
            raise ContractError(
                "Invariant.epochs must be a non-empty frozenset: an invariant that holds "
                "in no epoch holds nowhere"
            )
        for epoch in self.epochs:
            require_non_negative_int(epoch, "Invariant.epochs entry")
        if not isinstance(self.falsifier, str) or not self.falsifier.strip():
            raise ContractError(
                "Invariant.falsifier must be a non-empty string naming the observation "
                "that would refute this relationship; an unfalsifiable rule is not an invariant"
            )
        self._require_evidence()

    def _require_antecedent(self) -> None:
        if not isinstance(self.antecedent, tuple) or not self.antecedent:
            raise ContractError(
                "Invariant.antecedent must hold at least one SemanticPredicate: an "
                "invariant with no condition fires on every event on the host"
            )
        if len(self.antecedent) > MAX_ANTECEDENT_TERMS:
            raise ContractError(
                f"Invariant.antecedent holds {len(self.antecedent)} terms, above "
                f"MAX_ANTECEDENT_TERMS={MAX_ANTECEDENT_TERMS}; beyond that it is a "
                "memorised trace, not a generalisation"
            )
        for predicate in self.antecedent:
            if not isinstance(predicate, SemanticPredicate):
                raise ContractError(
                    f"Invariant.antecedent entries must be SemanticPredicate, "
                    f"got {type(predicate).__name__}"
                )

    def _require_evidence(self) -> None:
        if not isinstance(self.evidence, tuple) or not self.evidence:
            raise ContractError(
                "Invariant.evidence must be a non-empty tuple: an unattributable "
                "invariant cannot be melted back to the bytes that justified it"
            )
        for ref in self.evidence:
            if not isinstance(ref, EvidenceRef):
                raise ContractError(
                    f"Invariant.evidence entries must be EvidenceRef, got {type(ref).__name__}"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "invariant_id": self.invariant_id,
            "antecedent": [predicate.to_dict() for predicate in self.antecedent],
            "consequent": self.consequent.to_dict(),
            "support": self.support,
            "contradictions": self.contradictions,
            "identities_collapsed": self.identities_collapsed,
            "epochs": sorted(self.epochs),
            "falsifier": self.falsifier,
            "evidence": [ref.to_dict() for ref in self.evidence],
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Invariant:
        try:
            return cls(
                invariant_id=str(payload["invariant_id"]),
                antecedent=tuple(
                    SemanticPredicate.from_dict(item) for item in payload["antecedent"]
                ),
                consequent=ConsequentSpec.from_dict(payload["consequent"]),
                support=int(payload["support"]),
                contradictions=int(payload["contradictions"]),
                identities_collapsed=int(payload["identities_collapsed"]),
                epochs=frozenset(int(e) for e in payload["epochs"]),
                falsifier=str(payload["falsifier"]),
                evidence=tuple(EvidenceRef.from_dict(ref) for ref in payload["evidence"]),
            )
        except KeyError as exc:
            raise ContractError(f"Invariant missing field {exc.args[0]!r}") from exc
        except ValueError as exc:
            raise ContractError(f"Invariant could not be rebuilt: {exc}") from exc


def _require_property_set(value: object, field: str) -> frozenset[SemanticProperty]:
    if not isinstance(value, frozenset):
        raise ContractError(
            f"SemanticPredicate.{field} must be a frozenset, got {type(value).__name__}"
        )
    for prop in value:
        if not isinstance(prop, SemanticProperty):
            raise ContractError(
                f"SemanticPredicate.{field} entries must be SemanticProperty, got {prop!r}"
            )
    return value


def _audit_field_names(cls: type) -> None:
    """Refuse a predicate type that gained an identity-shaped field.

    Runs on every construction rather than once at import because that is what
    makes it a contract rather than a lint: a subclass or a patched dataclass
    cannot slip past it.
    """
    offenders = [
        field_name
        for field_name in getattr(cls, "__dataclass_fields__", {})
        if any(token in field_name.lower() for token in FORBIDDEN_PREDICATE_FIELD_TOKENS)
    ]
    if offenders:
        raise ContractError(
            f"{cls.__name__} declares identity-shaped fields {offenders}; semantics are "
            "earned by behaviour and names are evidence, never model vocabulary "
            "(ADR-0006, ADR-0007)"
        )
