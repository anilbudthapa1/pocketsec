"""Semantic anti-unification — architecture §9, part of D3.3.

Anti-unification is the operation that turns three observations of *particular*
processes into one claim about a *class* of processes::

    nginx           -> interpreter child -> credential read
    apache          -> interpreter child -> credential read
    custom-service  -> interpreter child -> credential read
    ------------------------------------------------------------------
    NETWORK_SERVER  -> INTERPRETER       -> CREDENTIAL_READER

What this module is **for** is producing the most specific predicate that still
covers every observed entity, so a Knowledge Cell generalises over identities
without generalising over semantics.

What it **refuses** to do:

* **It never reads a name.** ``Entity.display_name`` and ``Entity.identity`` are
  not accessed anywhere in this module, and that is a structural property, not a
  convention: ADR-0006/0007 make names evidence and never semantics, and a
  generaliser that peeked at a path would hand the renamed-binary adversarial
  case a free pass. ``tests/test_stage3_invariants.py`` replaces both attributes
  with raising descriptors and calls :func:`anti_unify` to hold this honest.
* **It never returns a predicate with no required property.** A predicate whose
  ``required_properties`` are empty matches every entity on the host, so a cell
  carrying it would silently extrapolate over the whole machine — exactly the
  §10 failure ("a rule without a boundary is unsafe"). That floor is
  :data:`GENERALISATION_FLOOR` and the refusal is ``None``, an abstention, not a
  weaker predicate.

The property ordering is **imported**, never redefined here: ``PROPERTY_ORDER``
and ``property_mask`` are a wire commitment shared with the boundary index's
``BoundaryKey``, and a second ordering in this module would make two masks that
look alike mean different things.
"""

from __future__ import annotations

from collections.abc import Sequence

from pocketsec.stage1.ssir.entities import (
    ASSERT_THRESHOLD,
    Entity,
    EntityKind,
    SemanticBelief,
    SemanticProperty,
)
from pocketsec.stage1.ssir.relations import RelationFamily
from pocketsec.stage3.cells.invariant import PredicateRole, SemanticPredicate
from pocketsec.stage3.cells.masks import PROPERTY_ORDER, property_mask

__all__ = [
    "GENERALISATION_FLOOR",
    "PROPERTY_ORDER",
    "REFUTE_THRESHOLD",
    "anti_unify",
    "property_mask",
    "refuted_properties",
    "semantic_class",
    "shared_asserted",
    "shared_refuted",
]

#: The minimum number of required properties an emitted predicate must carry.
#: One, not zero: zero is the universal predicate and is never a generalisation.
GENERALISATION_FLOOR = 1

#: Belief at or below which a property counts as *evaluated and found absent*.
#: The mirror of ``ASSERT_THRESHOLD``. Absence from ``SemanticBelief.properties``
#: is ignorance and is NOT refutation — conflating the two is the Stage 1
#: uncertainty trap recorded in MEMORY.md, and it would let a never-classified
#: entity acquire forbidden properties it was never tested for.
REFUTE_THRESHOLD = 1.0 - ASSERT_THRESHOLD


def _semantics(entity: Entity) -> SemanticBelief:
    """The only attribute of an ``Entity`` this module is allowed to touch."""
    return entity.semantics


def refuted_properties(belief: SemanticBelief) -> frozenset[SemanticProperty]:
    """Properties this belief holds *negative* evidence about."""
    return frozenset(
        prop for prop, value in belief.properties.items() if value <= REFUTE_THRESHOLD
    )


def shared_asserted(entities: Sequence[Entity]) -> frozenset[SemanticProperty]:
    """The properties every entity asserts.

    A streaming intersection, so an unbounded entity sequence costs O(1) state:
    the working set can only shrink, and it short-circuits once it is empty.
    """
    if not entities:
        return frozenset()
    shared = set(_semantics(entities[0]).asserted)
    for entity in entities[1:]:
        if not shared:
            break
        shared &= _semantics(entity).asserted
    return frozenset(shared)


def shared_refuted(entities: Sequence[Entity]) -> frozenset[SemanticProperty]:
    """The properties every entity was *evaluated for* and found to lack."""
    if not entities:
        return frozenset()
    shared = set(refuted_properties(_semantics(entities[0])))
    for entity in entities[1:]:
        if not shared:
            break
        shared &= refuted_properties(_semantics(entity))
    return frozenset(shared)


def _shared_kind(entities: Sequence[Entity]) -> EntityKind | None:
    """The one ``EntityKind`` shared by every entity, or ``None``.

    ``UNKNOWN`` never becomes a shared kind: it is the absence of a
    classification, so pinning a predicate to it would narrow the boundary on
    the strength of ignorance.
    """
    kinds = {_semantics(entity).kind for entity in entities}
    if len(kinds) != 1:
        return None
    kind = next(iter(kinds))
    return None if kind is EntityKind.UNKNOWN else kind


def semantic_class(entity: Entity) -> tuple[int, int]:
    """The equivalence class used for counterfactual actor substitution.

    Two entities are *semantically equivalent* when they share a kind and an
    asserted-property mask. Nothing identity-shaped participates, which is what
    makes "swap a semantically equivalent actor" a real counterfactual rather
    than a string edit.
    """
    belief = _semantics(entity)
    return (int(belief.kind), property_mask(belief.asserted))


def anti_unify(
    entities: Sequence[Entity],
    role: PredicateRole,
    relation_family: RelationFamily | None,
) -> SemanticPredicate | None:
    """Least general generalisation of ``entities``, or ``None``.

    Returns the most specific :class:`SemanticPredicate` that still matches every
    entity in ``entities``: their shared asserted properties as ``required``,
    their shared *refuted* properties as ``forbidden``, and their shared kind
    when they have one.

    Returns ``None`` — an explicit abstention — when the generalisation floor is
    not met. Callers must treat ``None`` as "these entities have nothing in
    common worth claiming", never as an empty predicate.
    """
    if not entities:
        return None
    required = shared_asserted(entities)
    if len(required) < GENERALISATION_FLOOR:
        return None
    # A property cannot be both required and forbidden; ``SemanticPredicate``
    # raises on the intersection, so the subtraction is the caller-side contract
    # and not a silent repair — required evidence outranks refuting evidence
    # because ASSERT_THRESHOLD is the stricter bar.
    forbidden = shared_refuted(entities) - required
    return SemanticPredicate(
        role=role,
        required_properties=required,
        forbidden_properties=forbidden,
        relation_family=relation_family,
        entity_kind=_shared_kind(entities),
    )
