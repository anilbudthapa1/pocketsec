"""D8.3 / PROM-F07 — the Mechanism Grammar: the closed language a Stage 8 theory is said in.

A discovery engine that can say anything can claim anything. Stage 8's hypotheses are
therefore drawn from a small, closed grammar whose **every member has an evaluator**
(ADR-0072): a :class:`Mechanism` is one of five per-actor relations over one or two
:class:`StepPredicate` values, and a predicate is exactly Stage 6's detector test — a
bitmask test of ``(relation, require_properties, forbid_properties, require_raised)``
against a step's own encoder masks. ``StepPredicate.matches`` is ``MotifStep.matches``
bit for bit, and ``PRECEDES`` is Stage 6's ``match_motif`` (a test compares both over
random steps), so a mechanism measured here means the same thing to Stage 6's matcher.

The whole grammar, per actor slot:

=========================  ==========================================================
``SINGLE``                  some step matches ``a``
``SINGLE`` + ``REPEATED(k)`` some actor has at least ``k`` steps matching ``a``
``PRECEDES``                some actor has step ``i`` matching ``a`` and a later ``j``
                            matching ``b`` (``b`` is checked before ``a`` arms, as Stage 6)
``CO_OCCURS``               some actor has two distinct steps matching ``a`` and ``b``
``WITHOUT``                 some actor has a step matching ``a`` and none matching ``b``
=========================  ==========================================================

What the grammar refuses, and why:

* **Causal verbs** (``enables``, ``causes``, ``suppresses``, ``requires``) and the
  modifiers ``rare``/``epoch-specific``/``user-specific``/``visibility-dependent``/
  ``collective``: on observational replay each is indistinguishable from a member
  above, or has no evaluator in the step type (ADR-0072). A word with no evaluator
  would let a theory claim something no test can check.
* **Two spellings of one function.** ``CO_OCCURS`` is symmetric, so its two steps are
  stored in one canonical order. A two-step relation over one predicate twice is
  refused: ``PRECEDES(p,p)`` and ``CO_OCCURS(p,p)`` are ``REPEATED(p,2)``, and
  ``WITHOUT(a,b)`` where every ``a`` step is also a ``b`` step can never fire.
* **Mechanisms the DSL cannot spell.** A mechanism whose DSL form exceeds
  ``MAX_DSL_BYTES`` does not construct, so ``parse_mechanism(m.to_dsl()) == m`` holds
  for every member (a test found 260-byte members before this rule existed).
* **Free text as state.** :meth:`Mechanism.render` produces English on demand and is
  never parsed back. The only text the grammar reads is its own strict DSL
  (:func:`parse_mechanism`): ASCII, at most ``MAX_DSL_BYTES``, names spelled exactly as
  ``Relation``, the encoder's 15 object properties and ``DIMENSIONS`` spell them, no
  whitespace, and :class:`GrammarError` for anything else. Untrusted proposals (an
  offline LLM, an analyst) enter only through this parser, and are refused, never
  repaired (ADR-0074).

Cost is work units: :meth:`Mechanism.matches` charges the caller's ``WorkMeter`` one unit
per predicate test of one step, before doing it, so a budgeted search stops at its
budget rather than after it.

This module decides nothing about trust and has no authority. It does not execute,
emit or describe any procedure: a mechanism is a test over recorded steps.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.ssir.entities import SemanticProperty
from pocketsec.stage1.ssir.relations import Relation, RelationFamily, family_of
from pocketsec.stage1.state.security_state import DIMENSIONS
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_LAYOUT, feature_names
from pocketsec.stage6.capsule.experience_capsule import EncodedStep
from pocketsec.stage6.memory.semantic import MAX_MOTIF_LENGTH, MotifStep
from pocketsec.stage6.resources import WorkMeter

__all__ = [
    "DIMENSION_NAMES",
    "FEATURE_NAMES",
    "GRAMMAR_VERSION",
    "MAX_DSL_BYTES",
    "MAX_MECHANISM_STEPS",
    "MAX_REPEAT",
    "PROPERTY_BITS",
    "PROPERTY_NAMES",
    "RAISED_BITS",
    "RELATION_NAMES",
    "GrammarError",
    "Mechanism",
    "MechanismRelation",
    "Modifier",
    "StepPredicate",
    "TriggerClass",
    "mechanism_from_canonical",
    "parse_mechanism",
]

GRAMMAR_VERSION = "stage8-mechanism-grammar.1.0.0"

_LAYOUT = dict(FEATURE_LAYOUT)
#: Width of the encoder's ``object_semantics`` group: the bits ``object_property_mask``
#: can carry. Derived at import so a grown encoder cannot leave the grammar behind.
PROPERTY_BITS: int = _LAYOUT["object_semantics"]
#: One bit per ``DIMENSIONS`` entry, the ``state_delta_mask`` bit order.
RAISED_BITS: int = len(DIMENSIONS)
#: Stage 6's motif length (2), imported: the grammar is never richer in chain length than
#: the detector grammar it may one day be compiled into.
MAX_MECHANISM_STEPS: int = MAX_MOTIF_LENGTH
MAX_REPEAT: int = 8
MAX_DSL_BYTES: int = 256

#: Every slot name of the encoder, re-exported so ``forge/package.py`` can check
#: ``required_features`` without importing Stage 2 itself (it may import genome/* only).
FEATURE_NAMES: tuple[str, ...] = feature_names()
#: The encoder's object properties in ``object_property_mask`` bit order, read from the
#: encoder's own slot names (its property tuple is private to Stage 2).
PROPERTY_NAMES: tuple[str, ...] = tuple(
    SemanticProperty(name.split(".", 1)[1]).name
    for name in FEATURE_NAMES
    if name.startswith("object.")
)
DIMENSION_NAMES: tuple[str, ...] = tuple(DIMENSIONS)
RELATION_NAMES: tuple[str, ...] = tuple(relation.name for relation in Relation)

if len(PROPERTY_NAMES) != PROPERTY_BITS or _LAYOUT["state_delta_raised"] != RAISED_BITS:
    raise ContractError("the grammar's bit widths no longer match the Stage 2 encoder layout")
if tuple(Relation.__members__) != RELATION_NAMES:
    raise ContractError("Relation values must be dense 0..n-1 for the grammar")

_PROPERTY_INDEX: Mapping[str, int] = MappingProxyType(
    {name: index for index, name in enumerate(PROPERTY_NAMES)}
)
_DIMENSION_INDEX: Mapping[str, int] = MappingProxyType(
    {name: index for index, name in enumerate(DIMENSION_NAMES)}
)
_PRIVILEGE_BIT = 1 << _DIMENSION_INDEX["privilege"]
_PERSISTENCE_RAISED_BIT = 1 << _DIMENSION_INDEX["persistence"]
_PERSISTENCE_PROPERTY_BIT = 1 << _PROPERTY_INDEX["PERSISTENCE"]


class GrammarError(ContractError):
    """A mechanism or DSL text the grammar does not contain."""


class TriggerClass(StrEnum):
    """What a predicate is about. Rendering only: no decision reads it."""

    EXECUTION = "EXECUTION"
    AUTH = "AUTH"
    PRIVILEGE = "PRIVILEGE"
    FILE = "FILE"
    NETWORK = "NETWORK"
    PERSISTENCE = "PERSISTENCE"
    IDENTITY = "IDENTITY"
    CONFIGURATION = "CONFIGURATION"


class MechanismRelation(StrEnum):
    SINGLE = "SINGLE"
    PRECEDES = "PRECEDES"
    CO_OCCURS = "CO_OCCURS"
    WITHOUT = "WITHOUT"


class Modifier(StrEnum):
    NONE = "NONE"
    REPEATED = "REPEATED"


def _require_mask(value: object, field: str, width: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < (1 << width):
        raise GrammarError(f"{field} must be an int in [0, 2**{width}), got {value!r}")
    return value


def _bit_names(mask: int, names: Sequence[str]) -> tuple[str, ...]:
    return tuple(name for index, name in enumerate(names) if mask >> index & 1)


@dataclass(frozen=True, slots=True)
class StepPredicate:
    """One bitmask test of one step: Stage 6's ``MotifStep``, with the widths checked."""

    relation: int  # a Relation value, 0 … 23
    require_properties: int  # object_property_mask bits, < 2**PROPERTY_BITS
    forbid_properties: int  # disjoint from require_properties
    require_raised: int  # state_delta_mask bits, < 2**RAISED_BITS

    def __post_init__(self) -> None:
        relation = self.relation
        if not isinstance(relation, int) or isinstance(relation, bool):
            raise GrammarError(f"StepPredicate.relation must be an int, got {relation!r}")
        if not 0 <= relation < len(Relation):
            raise GrammarError(f"StepPredicate.relation {relation} is not a Relation value")
        # A Relation member is an int subclass; store the plain int so equality, hashing
        # and canonical JSON never depend on which of the two the caller passed.
        object.__setattr__(self, "relation", int(relation))
        _require_mask(self.require_properties, "require_properties", PROPERTY_BITS)
        _require_mask(self.forbid_properties, "forbid_properties", PROPERTY_BITS)
        _require_mask(self.require_raised, "require_raised", RAISED_BITS)
        if self.require_properties & self.forbid_properties:
            raise GrammarError("a predicate requiring and forbidding one property never matches")

    def matches(self, step: EncodedStep) -> bool:
        """``MotifStep.matches`` semantics, bit for bit (tested against it)."""
        props = step.object_property_mask
        return (
            step.relation == self.relation
            and (props & self.require_properties) == self.require_properties
            and (props & self.forbid_properties) == 0
            and (step.state_delta_mask & self.require_raised) == self.require_raised
        )

    def implies(self, other: StepPredicate) -> bool:
        """True when every step matching ``self`` also matches ``other``."""
        return (
            self.relation == other.relation
            and other.require_properties & ~self.require_properties == 0
            and other.forbid_properties & ~self.forbid_properties == 0
            and other.require_raised & ~self.require_raised == 0
        )

    def to_motif_step(self) -> MotifStep:
        return MotifStep(
            relation=self.relation,
            require_properties=self.require_properties,
            forbid_properties=self.forbid_properties,
            require_raised=self.require_raised,
        )

    def payload(self) -> tuple[int, int, int, int]:
        return (self.relation, self.require_properties, self.forbid_properties,
                self.require_raised)

    def bits(self) -> int:
        """Popcounts of the three masks: how much this predicate asserts."""
        return (
            self.require_properties.bit_count()
            + self.forbid_properties.bit_count()
            + self.require_raised.bit_count()
        )

    def trigger_class(self) -> TriggerClass:
        """Spec §4 D8.3 rendering rules, in order. Never read by a decision."""
        relation = Relation(self.relation)
        family = family_of(relation)
        if self.require_raised & _PRIVILEGE_BIT or family is RelationFamily.AUTHORIZATION:
            return TriggerClass.PRIVILEGE
        if relation is Relation.AUTHENTICATE:
            return TriggerClass.AUTH
        if relation is Relation.IMPERSONATE:
            return TriggerClass.IDENTITY
        if (self.require_raised & _PERSISTENCE_RAISED_BIT
                or self.require_properties & _PERSISTENCE_PROPERTY_BIT):
            return TriggerClass.PERSISTENCE
        if family in (RelationFamily.EXECUTION, RelationFamily.LOADING):
            return TriggerClass.EXECUTION
        if family is RelationFamily.FILESYSTEM:
            return TriggerClass.FILE
        if family is RelationFamily.NETWORK:
            return TriggerClass.NETWORK
        return TriggerClass.CONFIGURATION  # CONTROL / PACKAGING: every family is covered

    def to_dsl(self) -> str:
        return (
            RELATION_NAMES[self.relation]
            + "".join("+" + name for name in _bit_names(self.require_properties, PROPERTY_NAMES))
            + "".join("-" + name for name in _bit_names(self.forbid_properties, PROPERTY_NAMES))
            + "".join("^" + name for name in _bit_names(self.require_raised, DIMENSION_NAMES))
        )

    def render(self) -> str:
        text = RELATION_NAMES[self.relation]
        required = _bit_names(self.require_properties, PROPERTY_NAMES)
        forbidden = _bit_names(self.forbid_properties, PROPERTY_NAMES)
        raised = _bit_names(self.require_raised, DIMENSION_NAMES)
        if required:
            text += " on an object that is " + " and ".join(required)
        if forbidden:
            text += (" and not " if required else " on an object that is not ") + " or ".join(
                forbidden
            )
        if raised:
            text += ", raising " + " and ".join(raised)
        return text


_Charge = Callable[[int], None]


def _no_charge(units: int) -> None:
    del units


def _by_actor(steps: Sequence[EncodedStep]) -> dict[int, list[EncodedStep]]:
    """Steps grouped by actor slot, in order of first appearance, step order kept."""
    groups: dict[int, list[EncodedStep]] = {}
    for step in steps:
        groups.setdefault(step.actor_slot, []).append(step)
    return groups


@dataclass(frozen=True, slots=True)
class Mechanism:
    """A typed, closed-grammar predicate over one episode's steps, per actor slot."""

    relation: MechanismRelation
    steps: tuple[StepPredicate, ...]  # 1 for SINGLE, 2 otherwise
    modifier: Modifier = Modifier.NONE
    repeat_min: int = 1  # REPEATED: 2 … MAX_REPEAT and relation SINGLE; NONE: exactly 1

    def __post_init__(self) -> None:
        if not isinstance(self.relation, MechanismRelation):
            raise GrammarError(f"relation must be a MechanismRelation, got {self.relation!r}")
        if not isinstance(self.modifier, Modifier):
            raise GrammarError(f"Mechanism.modifier must be a Modifier, got {self.modifier!r}")
        if not isinstance(self.steps, (tuple, list)):
            raise GrammarError("Mechanism.steps must be a tuple of StepPredicate")
        steps = tuple(self.steps)
        if any(not isinstance(step, StepPredicate) for step in steps):
            raise GrammarError("Mechanism.steps must hold StepPredicate values only")
        expected = 1 if self.relation is MechanismRelation.SINGLE else MAX_MECHANISM_STEPS
        if len(steps) != expected:
            raise GrammarError(f"{self.relation.value} takes {expected} step(s), got {len(steps)}")
        if len(steps) == 2:
            steps = self._two_step_form(steps)
        object.__setattr__(self, "steps", steps)
        self._check_modifier()
        if len(self.to_dsl()) > MAX_DSL_BYTES:
            # The DSL is the grammar's only external form. A mechanism it cannot spell
            # could never round-trip, so it is not in the grammar (it asserts > ~20 bits
            # per step; no generator here proposes one).
            raise GrammarError(f"mechanism DSL exceeds {MAX_DSL_BYTES} bytes")

    def _two_step_form(self, steps: tuple[StepPredicate, ...]) -> tuple[StepPredicate, ...]:
        first, second = steps
        if first == second:
            raise GrammarError(
                f"{self.relation.value} over one predicate twice is REPEATED(p,2) "
                "(or, for WITHOUT, never fires); one function has one spelling"
            )
        if self.relation is MechanismRelation.WITHOUT and first.implies(second):
            raise GrammarError("WITHOUT(a,b) where every a step is a b step can never fire")
        if self.relation is MechanismRelation.CO_OCCURS and second.payload() < first.payload():
            return (second, first)  # symmetric: one canonical order, one digest
        return steps

    def _check_modifier(self) -> None:
        count = self.repeat_min
        if not isinstance(count, int) or isinstance(count, bool):
            raise GrammarError(f"Mechanism.repeat_min must be an int, got {count!r}")
        if self.modifier is Modifier.NONE:
            if count != 1:
                raise GrammarError("repeat_min must be 1 unless the modifier is REPEATED")
            return
        if self.relation is not MechanismRelation.SINGLE:
            raise GrammarError("REPEATED applies to SINGLE only")
        if not 2 <= count <= MAX_REPEAT:
            raise GrammarError(f"REPEATED needs 2 <= k <= {MAX_REPEAT}, got {count}")

    # --- evaluation ------------------------------------------------------------------

    def _actor_fires(self, steps: Sequence[EncodedStep], charge: _Charge) -> bool:
        """The grammar table, for the steps of ONE actor. Charges before each test."""
        a = self.steps[0]
        if self.relation is MechanismRelation.SINGLE:
            need, seen = self.repeat_min, 0
            for step in steps:
                charge(1)
                if a.matches(step):
                    seen += 1
                    if seen >= need:
                        return True
            return False
        b = self.steps[1]
        if self.relation is MechanismRelation.PRECEDES:
            armed = False
            for step in steps:
                # b before a, as match_motif: one step satisfying both halves is not i < j.
                if armed:
                    charge(1)
                    if b.matches(step):
                        return True
                charge(1)
                armed = armed or a.matches(step)
            return False
        if self.relation is MechanismRelation.CO_OCCURS:
            seen_a = seen_b = False
            for step in steps:
                charge(2)
                is_a, is_b = a.matches(step), b.matches(step)
                # A pair of distinct steps: the later one meets an earlier one.
                if (is_a and seen_b) or (is_b and seen_a):
                    return True
                seen_a, seen_b = seen_a or is_a, seen_b or is_b
            return False
        has_a = False  # WITHOUT: needs the whole actor, because absence is global
        for step in steps:
            charge(2)
            if b.matches(step):
                return False
            has_a = has_a or a.matches(step)
        return has_a

    def firing_actors(
        self, steps: Sequence[EncodedStep], *, meter: WorkMeter | None = None
    ) -> frozenset[int]:
        """Every actor slot for which the mechanism fires (no early exit across actors)."""
        charge = _no_charge if meter is None else meter.charge
        return frozenset(
            slot for slot, own in _by_actor(steps).items() if self._actor_fires(own, charge)
        )

    def matches(self, steps: Sequence[EncodedStep], *, meter: WorkMeter | None = None) -> bool:
        """True when some actor satisfies the mechanism; stops at the first such actor."""
        charge = _no_charge if meter is None else meter.charge
        return any(self._actor_fires(own, charge) for own in _by_actor(steps).values())

    # --- description -----------------------------------------------------------------

    def description_length_bits(self) -> int:
        """``2 + Σ(5 + 4·popcounts) + (3 if REPEATED)``: the MDL term (DL-07)."""
        per_step = sum(5 + 4 * step.bits() for step in self.steps)
        return 2 + per_step + (3 if self.modifier is Modifier.REPEATED else 0)

    def canonical(self) -> dict[str, Any]:
        return {
            "grammar": GRAMMAR_VERSION,
            "relation": self.relation.value,
            "modifier": self.modifier.value,
            "repeat_min": self.repeat_min,
            "steps": [list(step.payload()) for step in self.steps],
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.canonical(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    def digest(self) -> str:
        return "mech-" + hashlib.sha256(self.canonical_bytes()).hexdigest()[:16]

    def render(self) -> str:
        """English, for people. Never parsed back and never stored as state."""
        a = self.steps[0].render()
        lead = f"[{self.steps[0].trigger_class().value}] one actor "
        if self.relation is MechanismRelation.SINGLE:
            if self.modifier is Modifier.REPEATED:
                return lead + f"performs {a} at least {self.repeat_min} times"
            return lead + f"performs {a}"
        b = self.steps[1].render()
        if self.relation is MechanismRelation.PRECEDES:
            return lead + f"performs {a}, and later {b}"
        if self.relation is MechanismRelation.CO_OCCURS:
            return lead + f"performs both {a} and {b}, in either order"
        return lead + f"performs {a}, and never {b}"

    def to_dsl(self) -> str:
        """The DSL form; ``parse_mechanism(m.to_dsl()) == m``."""
        if self.modifier is Modifier.REPEATED:
            return f"REPEATED({self.steps[0].to_dsl()},{self.repeat_min})"
        return f"{self.relation.value}({','.join(step.to_dsl() for step in self.steps)})"


# --- the strict DSL ------------------------------------------------------------------

_OUTER = re.compile(r"^(SINGLE|PRECEDES|CO_OCCURS|WITHOUT|REPEATED)\(([^()]*)\)$")
_PREDICATE = re.compile(
    r"^([A-Z]+)((?:\+[A-Z_]+)*)((?:-[A-Z_]+)*)((?:\^[a-z]+)*)$"
)
_COUNT = re.compile(r"^[1-9][0-9]?$")
_RELATION_INDEX: Mapping[str, int] = MappingProxyType(
    {name: index for index, name in enumerate(RELATION_NAMES)}
)


def _names_to_mask(group: str, sep: str, index: Mapping[str, int], what: str) -> int:
    if not group:
        return 0
    names = group[1:].split(sep)
    if len(set(names)) != len(names):
        raise GrammarError(f"duplicate {what} in {group!r}")
    mask = 0
    for name in names:
        if name not in index:
            raise GrammarError(f"unknown {what} {name!r}")
        mask |= 1 << index[name]
    return mask


def _parse_predicate(text: str) -> StepPredicate:
    match = _PREDICATE.fullmatch(text)
    if match is None:
        raise GrammarError(f"not a predicate: {text!r}")
    relation, required, forbidden, raised = match.groups()
    if relation not in _RELATION_INDEX:
        raise GrammarError(f"unknown relation {relation!r}")
    return StepPredicate(
        relation=_RELATION_INDEX[relation],
        require_properties=_names_to_mask(required, "+", _PROPERTY_INDEX, "property"),
        forbid_properties=_names_to_mask(forbidden, "-", _PROPERTY_INDEX, "property"),
        require_raised=_names_to_mask(raised, "^", _DIMENSION_INDEX, "dimension"),
    )


def parse_mechanism(text: str) -> Mechanism:
    """The one reader of mechanism text. Strict: anything else is a ``GrammarError``.

    ``SINGLE(p)``, ``PRECEDES(p,p)``, ``CO_OCCURS(p,p)``, ``WITHOUT(p,p)``,
    ``REPEATED(p,k)``; ``p := RELATION ("+" PROPERTY)* ("-" PROPERTY)* ("^" dimension)*``.
    No whitespace anywhere, ASCII only, at most ``MAX_DSL_BYTES`` bytes. Text that does
    not parse is refused, never repaired: a repaired proposal is a theory nobody wrote.
    """
    if not isinstance(text, str):
        raise GrammarError(f"mechanism text must be a str, got {type(text).__name__}")
    if not text.isascii():
        raise GrammarError("mechanism text must be ASCII")
    if len(text.encode("ascii")) > MAX_DSL_BYTES:
        raise GrammarError(f"mechanism text exceeds {MAX_DSL_BYTES} bytes")
    match = _OUTER.fullmatch(text)
    if match is None:
        raise GrammarError(f"not a mechanism: {text[:64]!r}")
    head, body = match.groups()
    parts = body.split(",")
    if head == "SINGLE":
        if len(parts) != 1:
            raise GrammarError("SINGLE takes one predicate")
        return Mechanism(MechanismRelation.SINGLE, (_parse_predicate(parts[0]),))
    if len(parts) != 2:
        raise GrammarError(f"{head} takes two arguments")
    if head == "REPEATED":
        if not _COUNT.fullmatch(parts[1]):
            raise GrammarError(f"REPEATED count must be a plain integer, got {parts[1]!r}")
        return Mechanism(MechanismRelation.SINGLE, (_parse_predicate(parts[0]),),
                         Modifier.REPEATED, int(parts[1]))
    steps = (_parse_predicate(parts[0]), _parse_predicate(parts[1]))
    return Mechanism(MechanismRelation(head), steps)


def mechanism_from_canonical(payload: Mapping[str, Any]) -> Mechanism:
    """The inverse of :meth:`Mechanism.canonical`, strict about keys, types and version."""
    if not isinstance(payload, Mapping):
        raise GrammarError("a mechanism payload must be a mapping")
    expected = {"grammar", "relation", "modifier", "repeat_min", "steps"}
    if set(payload) != expected:
        raise GrammarError(f"mechanism payload keys must be exactly {sorted(expected)}")
    if payload["grammar"] != GRAMMAR_VERSION:
        raise GrammarError(f"mechanism grammar {payload['grammar']!r} is not {GRAMMAR_VERSION}")
    steps = payload["steps"]
    if not isinstance(steps, (list, tuple)) or not 1 <= len(steps) <= MAX_MECHANISM_STEPS:
        raise GrammarError("mechanism steps must be a list of 1..2 predicates")
    predicates: list[StepPredicate] = []
    for row in steps:
        if not isinstance(row, (list, tuple)) or len(row) != 4:
            raise GrammarError("a predicate payload is [relation, require, forbid, raised]")
        predicates.append(StepPredicate(*row))
    try:
        relation = MechanismRelation(payload["relation"])
        modifier = Modifier(payload["modifier"])
    except ValueError as exc:
        raise GrammarError(str(exc)) from None
    mechanism = Mechanism(relation, tuple(predicates), modifier, payload["repeat_min"])
    if mechanism.canonical() != {**payload, "steps": [list(row) for row in steps]}:
        raise GrammarError("mechanism payload is not in canonical form")
    return mechanism
