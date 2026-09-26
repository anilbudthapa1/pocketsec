"""D9.2: the Computational Genome, ``pocketsec.computational_genome.v1``.

The architecture (§4) describes a genome as fourteen "laws". Fourteen free-form laws
would be a search space in which nothing terminates by construction and nothing can be
compared. This module binds the fourteen names to one typed object instead: a set of
per-lineage registers, an UPDATE program that rewrites them once per event, a READOUT
program that turns them into one score per lineage, and a session aggregation. Every
program is a typed DAG in the Stage 9 IR (``chemistry/typed_ir.py``), so every genome
that can be constructed terminates in a static number of work units and allocates a
static number of bytes. :data:`ARCHITECTURE_FIELD_BINDING` shows where each of the
fourteen names went; a law with no executor is a one-member enum (lesson 3: never
define a catalogue richer than its consumer).

Why the object refuses what it refuses:

* **Ill-typed genomes are unconstructible.** ``__post_init__`` validates both programs
  against :data:`SEED_ALPHABET` and raises :class:`IRError` on any defect. A genome
  cannot exist in an unvalidated state, so no consumer has to remember to validate.
* **Macros are always stored expanded.** A promoted primitive changes what the search
  proposes and what description length it pays, never what the runtime executes. That
  is why validation is against the *seed* alphabet: a stored genome that still names a
  macro fails ``UNKNOWN_PRIMITIVE``.
* **Declared bounds may not understate.** The integration plan requires every genome to
  carry ``declared_max_state_bytes`` and ``declared_max_steps_per_event``. A declared
  figure below the statically computed bound is refused (``DECLARED_BOUND_UNDERSTATED``):
  a genome that lies about its own cost is the supply-chain attack ARGUS tests.
* **The digest is content, not lineage.** ``digest`` hashes canonical JSON of everything
  except ``parent_digests`` and ``mutation``, so the same computation reached by two
  search paths has one identity. :meth:`from_dict` refuses a payload whose digest does
  not match its content. A digest is integrity, never authenticity (ADR-0088).

What the genome refuses to be: a deployed component. It carries no authority, names no
operator and writes nothing; its only exits are evaluation inside Stage 9 and Stage 6's
quarantine boundary (ADR-0081).
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import ContractError, digest_of_bytes, register_schema
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_WIDTH
from pocketsec.stage9.chemistry.phenotype import Phenotype, SessionAggregation
from pocketsec.stage9.chemistry.typed_ir import (
    MAX_LINEAGES,
    MAX_LOOKUP_ENTRIES,
    InputSource,
    IRError,
    IRNode,
    IRProgram,
    IRType,
    NodeKind,
    ProgramPhase,
    RegisterSpec,
    StaticBounds,
    static_bounds,
    validate_program,
)
from pocketsec.stage9.foundry.primitives import SEED_ALPHABET, PrimitiveAlphabet

__all__ = [
    "ARCHITECTURE_FIELD_BINDING",
    "COMPUTATIONAL_GENOME_V1_ID",
    "COMPUTATIONAL_GENOME_V1_VERSION",
    "GENOME_KEYS",
    "MAX_PARENT_DIGESTS",
    "ComputationalGenomeV1",
    "DeploymentBackend",
    "EvidenceSemantics",
    "LearningLaw",
    "RoutingLaw",
    "build_genome",
    "resolve_field",
]

COMPUTATIONAL_GENOME_V1_ID = "pocketsec.computational_genome.v1"
COMPUTATIONAL_GENOME_V1_VERSION = register_schema(COMPUTATIONAL_GENOME_V1_ID, "1.0.0")

#: Lineage is recorded, not unbounded: a child names at most this many parents.
MAX_PARENT_DIGESTS = 4

#: Nested macro bodies are walked at most this deep when recording ``macro_uses``. The
#: alphabet already refuses cycles and caps depth; this guard keeps the walk bounded even
#: if a malformed alphabet were handed in.
_MACRO_WALK_DEPTH = 8

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class LearningLaw(StrEnum):
    #: The only member with an executor. Adaptation laws are studied outside the genome
    #: (``laplace/law_discovery.py``); a member without an executor would be a promise.
    NONE = "NONE"


class RoutingLaw(StrEnum):
    #: Every event runs the whole UPDATE program. There is no router to evolve.
    SINGLE_PATH = "SINGLE_PATH"


class DeploymentBackend(StrEnum):
    #: The stdlib interpreter. PCB lowering is a DAEDALUS finding, not a backend (M0.10).
    USERSPACE_STDLIB = "USERSPACE_STDLIB"


class EvidenceSemantics(StrEnum):
    #: A score cites the evidence locators of the events that moved the winning lineage.
    WINNING_LINEAGE_LOCATORS = "WINNING_LINEAGE_LOCATORS"


_ENUM_FIELDS: tuple[tuple[str, type[StrEnum]], ...] = (
    ("aggregation", SessionAggregation),
    ("learning_law", LearningLaw),
    ("routing_law", RoutingLaw),
    ("backend", DeploymentBackend),
    ("evidence_semantics", EvidenceSemantics),
)

#: The exact top-level keys of :meth:`ComputationalGenomeV1.to_dict`.
GENOME_KEYS: frozenset[str] = frozenset(
    {
        "schema",
        "schema_version",
        "registers",
        "update",
        "readout",
        "aggregation",
        "lookup_table",
        "declared_max_state_bytes",
        "declared_max_steps_per_event",
        "min_events_for_score",
        "learning_law",
        "routing_law",
        "backend",
        "evidence_semantics",
        "macro_uses",
        "parent_digests",
        "mutation",
        "digest",
    }
)
_NODE_KEYS = frozenset({"kind", "type", "primitive", "args", "source", "index", "lag", "value"})
_PROGRAM_KEYS = frozenset({"phase", "nodes", "outputs"})
_REGISTER_KEYS = frozenset({"type", "ring", "precision_bits", "init"})
#: Excluded from the digest: the same computation reached twice has one identity.
_LINEAGE_KEYS = frozenset({"parent_digests", "mutation", "digest"})


# --- canonical payloads ------------------------------------------------------


def _typed_value(value: object, value_type: IRType) -> object:
    """Normalise a FLOAT-typed int to float so ``init=0`` and ``init=0.0`` hash alike.

    Only this one lossless widening is applied; any other type confusion is left for
    the IR validator to refuse rather than being papered over here.
    """
    if value_type is IRType.FLOAT and isinstance(value, int) and not isinstance(value, bool):
        return float(value)
    return value


def _node_payload(node: IRNode) -> dict[str, Any]:
    return {
        "kind": node.kind.value,
        "type": node.type.value,
        "primitive": node.primitive,
        "args": list(node.args),
        "source": None if node.source is None else node.source.value,
        "index": node.index,
        "lag": node.lag,
        "value": _typed_value(node.value, node.type),
    }


def _program_payload(program: IRProgram) -> dict[str, Any]:
    return {
        "phase": program.phase.value,
        "nodes": [_node_payload(node) for node in program.nodes],
        "outputs": list(program.outputs),
    }


def _register_payload(register: RegisterSpec) -> dict[str, Any]:
    return {
        "type": register.type.value,
        "ring": register.ring,
        "precision_bits": register.precision_bits,
        "init": _typed_value(register.init, register.type),
    }


def _canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return text.encode("utf-8")


def _exact_keys(payload: object, expected: frozenset[str], what: str) -> Mapping[str, Any]:
    if not isinstance(payload, Mapping):
        raise ContractError(f"{what} must be a mapping, got {type(payload).__name__}")
    keys = set(payload)
    if keys != expected:
        missing, extra = sorted(expected - keys), sorted(keys - expected)
        raise ContractError(f"{what} keys differ: missing {missing}, unexpected {extra}")
    return payload


def _plain_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractError(f"{field} must be an int, got {type(value).__name__}")
    return value


def _node_from(payload: object) -> IRNode:
    data = _exact_keys(payload, _NODE_KEYS, "IR node")
    source = data["source"]
    return IRNode(
        kind=NodeKind(data["kind"]),
        type=IRType(data["type"]),
        primitive=str(data["primitive"]),
        args=tuple(_plain_int(arg, "IR node arg") for arg in data["args"]),
        source=None if source is None else InputSource(source),
        index=_plain_int(data["index"], "IR node index"),
        lag=_plain_int(data["lag"], "IR node lag"),
        value=data["value"],
    )


def _program_from(payload: object) -> IRProgram:
    data = _exact_keys(payload, _PROGRAM_KEYS, "IR program")
    return IRProgram(
        phase=ProgramPhase(data["phase"]),
        nodes=tuple(_node_from(node) for node in data["nodes"]),
        outputs=tuple(_plain_int(output, "IR program output") for output in data["outputs"]),
    )


def _register_from(payload: object) -> RegisterSpec:
    data = _exact_keys(payload, _REGISTER_KEYS, "register")
    return RegisterSpec(
        type=IRType(data["type"]),
        ring=_plain_int(data["ring"], "register ring"),
        precision_bits=_plain_int(data["precision_bits"], "register precision_bits"),
        init=data["init"],
    )


# --- the genome --------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ComputationalGenomeV1:
    """A typed, bounded, per-lineage security computation. See the module docstring."""

    registers: tuple[RegisterSpec, ...]
    #: Phase UPDATE; ``outputs[r]`` is the new value of register ``r``.
    update: IRProgram
    #: Phase READOUT; exactly one FLOAT output per lineage.
    readout: IRProgram
    aggregation: SessionAggregation
    #: At most ``MAX_LOOKUP_ENTRIES``, consumed by the LOOKUP primitive.
    lookup_table: tuple[float, ...]
    declared_max_state_bytes: int
    declared_max_steps_per_event: int
    #: Fewer events than this and the phenotype abstains (score ``None``), never guesses.
    min_events_for_score: int = 1
    learning_law: LearningLaw = LearningLaw.NONE
    routing_law: RoutingLaw = RoutingLaw.SINGLE_PATH
    backend: DeploymentBackend = DeploymentBackend.USERSPACE_STDLIB
    evidence_semantics: EvidenceSemantics = EvidenceSemantics.WINNING_LINEAGE_LOCATORS
    #: Promoted macro names used, one entry per use; the programs hold them EXPANDED.
    macro_uses: tuple[str, ...] = ()
    #: Lineage, at most ``MAX_PARENT_DIGESTS``; excluded from :attr:`digest`.
    parent_digests: tuple[str, ...] = ()
    #: The variation operator that produced it; excluded from :attr:`digest`.
    mutation: str = ""
    schema_version: str = COMPUTATIONAL_GENOME_V1_VERSION

    def __post_init__(self) -> None:
        self._check_shapes()
        self._check_enums()
        self._check_lookup_table()
        validate_program(self.update, self.registers, SEED_ALPHABET)
        validate_program(self.readout, self.registers, SEED_ALPHABET)
        self._check_declared_bounds(
            static_bounds(self.update, self.readout, self.registers, SEED_ALPHABET)
        )
        self._check_lineage()

    def _check_shapes(self) -> None:
        if self.schema_version != COMPUTATIONAL_GENOME_V1_VERSION:
            raise ContractError(
                f"{COMPUTATIONAL_GENOME_V1_ID} is registered at "
                f"{COMPUTATIONAL_GENOME_V1_VERSION}, got {self.schema_version!r}"
            )
        if not isinstance(self.registers, tuple) or not all(
            isinstance(register, RegisterSpec) for register in self.registers
        ):
            raise ContractError("registers must be a tuple of RegisterSpec")
        for name, phase in (("update", ProgramPhase.UPDATE), ("readout", ProgramPhase.READOUT)):
            program = getattr(self, name)
            if not isinstance(program, IRProgram) or program.phase is not phase:
                raise ContractError(f"{name} must be an IRProgram of phase {phase.value}")
        if _plain_int(self.min_events_for_score, "min_events_for_score") < 1:
            raise ContractError("min_events_for_score must be >= 1")

    def _check_enums(self) -> None:
        # A raw string equal to a member is refused too: from_dict converts, and nothing
        # else should be building genomes from untyped text.
        for name, enum_type in _ENUM_FIELDS:
            if not isinstance(getattr(self, name), enum_type):
                raise ContractError(f"{name} must be a {enum_type.__name__} member")

    def _check_lookup_table(self) -> None:
        if not isinstance(self.lookup_table, tuple):
            raise ContractError("lookup_table must be a tuple of floats")
        if len(self.lookup_table) > MAX_LOOKUP_ENTRIES:
            raise IRError(
                "LOOKUP_BOUND",
                f"lookup_table holds {len(self.lookup_table)} entries, cap {MAX_LOOKUP_ENTRIES}",
            )
        for entry in self.lookup_table:
            if isinstance(entry, bool) or not isinstance(entry, (int, float)):
                raise ContractError("lookup_table entries must be numbers")
            if not math.isfinite(entry):
                raise ContractError("lookup_table entries must be finite")

    def _check_declared_bounds(self, bounds: StaticBounds) -> None:
        declared = (
            ("declared_max_state_bytes", bounds.session_state_bytes_max),
            ("declared_max_steps_per_event", bounds.max_steps_per_event),
        )
        for name, computed in declared:
            value = _plain_int(getattr(self, name), name)
            if value < computed:
                raise IRError(
                    "DECLARED_BOUND_UNDERSTATED",
                    f"{name}={value} is below the computed static bound {computed}",
                )

    def _check_lineage(self) -> None:
        for name in ("macro_uses", "parent_digests"):
            value = getattr(self, name)
            if not isinstance(value, tuple) or not all(
                isinstance(item, str) and item for item in value
            ):
                raise ContractError(f"{name} must be a tuple of non-empty strings")
        if len(self.parent_digests) > MAX_PARENT_DIGESTS:
            raise ContractError(
                f"parent_digests holds {len(self.parent_digests)}, cap {MAX_PARENT_DIGESTS}"
            )
        if any(not _DIGEST_RE.fullmatch(parent) for parent in self.parent_digests):
            raise ContractError("parent_digests entries must be sha256:<64 hex>")
        if not isinstance(self.mutation, str):
            raise ContractError("mutation must be a string")

    # --- derived views -------------------------------------------------------

    @property
    def digest(self) -> str:
        """``sha256:`` of canonical JSON, lineage fields (parents, mutation) excluded."""
        return _genome_digest(self)

    @property
    def bounds(self) -> StaticBounds:
        return _genome_bounds(self)

    @property
    def observation_map(self) -> frozenset[tuple[InputSource, int]]:
        """Every ``(InputSource, index)`` the UPDATE program reads. READOUT reads none."""
        return validate_program(self.update, self.registers, SEED_ALPHABET).inputs_read

    @property
    def alphabet_digest(self) -> str:
        """The alphabet every stored genome is validated against: always the seed one."""
        return SEED_ALPHABET.digest

    @property
    def lineage_eviction_policy(self) -> str:
        """The fixed forgetting policy the phenotype applies to whole lineages."""
        return f"LRU_BY_LAST_UPDATE:max_lineages={MAX_LINEAGES}"

    def description_length_bits(self, alphabet: PrimitiveAlphabet | None = None) -> float:
        """Deterministic description length in bits (spec §4.2 formula).

        A genome that used promoted macros is credited ``(macro_nodes - 1) x
        mean_node_bits`` per use, which needs the alphabet that defined the macro. It is
        refused without one rather than silently reported uncredited.
        """
        return _description_length(self, alphabet)

    def phenotype(self) -> Phenotype:
        """The executable form. Built fresh each call; it holds per-session state only."""
        return Phenotype(
            update=self.update,
            readout=self.readout,
            registers=self.registers,
            aggregation=self.aggregation,
            lookup_table=self.lookup_table,
            min_events_for_score=self.min_events_for_score,
            alphabet=SEED_ALPHABET,
        )

    # --- serialisation -------------------------------------------------------

    def _content_payload(self) -> dict[str, Any]:
        return {
            "schema": COMPUTATIONAL_GENOME_V1_ID,
            "schema_version": self.schema_version,
            "registers": [_register_payload(register) for register in self.registers],
            "update": _program_payload(self.update),
            "readout": _program_payload(self.readout),
            "aggregation": self.aggregation.value,
            "lookup_table": [float(entry) for entry in self.lookup_table],
            "declared_max_state_bytes": self.declared_max_state_bytes,
            "declared_max_steps_per_event": self.declared_max_steps_per_event,
            "min_events_for_score": self.min_events_for_score,
            "learning_law": self.learning_law.value,
            "routing_law": self.routing_law.value,
            "backend": self.backend.value,
            "evidence_semantics": self.evidence_semantics.value,
            "macro_uses": list(self.macro_uses),
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self._content_payload()
        payload["parent_digests"] = list(self.parent_digests)
        payload["mutation"] = self.mutation
        payload["digest"] = self.digest
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ComputationalGenomeV1:
        """Rebuild and re-validate; refuse unknown keys and a digest that does not match."""
        data = _exact_keys(payload, GENOME_KEYS, COMPUTATIONAL_GENOME_V1_ID)
        if data["schema"] != COMPUTATIONAL_GENOME_V1_ID:
            raise ContractError(f"not a {COMPUTATIONAL_GENOME_V1_ID} payload: {data['schema']!r}")
        try:
            genome = cls(**_constructor_arguments(data))
        except ContractError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise ContractError(f"malformed {COMPUTATIONAL_GENOME_V1_ID} payload: {exc}") from exc
        if data["digest"] != genome.digest:
            raise ContractError(
                f"digest mismatch: payload says {data['digest']!r}, content is {genome.digest}"
            )
        return genome


def _constructor_arguments(data: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "registers": tuple(_register_from(register) for register in data["registers"]),
        "update": _program_from(data["update"]),
        "readout": _program_from(data["readout"]),
        "aggregation": SessionAggregation(data["aggregation"]),
        "lookup_table": tuple(data["lookup_table"]),
        "declared_max_state_bytes": data["declared_max_state_bytes"],
        "declared_max_steps_per_event": data["declared_max_steps_per_event"],
        "min_events_for_score": data["min_events_for_score"],
        "learning_law": LearningLaw(data["learning_law"]),
        "routing_law": RoutingLaw(data["routing_law"]),
        "backend": DeploymentBackend(data["backend"]),
        "evidence_semantics": EvidenceSemantics(data["evidence_semantics"]),
        "macro_uses": tuple(data["macro_uses"]),
        "parent_digests": tuple(data["parent_digests"]),
        "mutation": data["mutation"],
        "schema_version": data["schema_version"],
    }


# Bounded memo tables: the search asks for the same genome's digest and bounds many
# times. Equal genomes have equal content, so sharing an entry between them is exact.
@lru_cache(maxsize=4096)
def _genome_digest(genome: ComputationalGenomeV1) -> str:
    return digest_of_bytes(_canonical_bytes(genome._content_payload()))


@lru_cache(maxsize=4096)
def _genome_bounds(genome: ComputationalGenomeV1) -> StaticBounds:
    return static_bounds(genome.update, genome.readout, genome.registers, SEED_ALPHABET)


# --- description length ------------------------------------------------------


def _node_bits(node: IRNode, position: int, registers: Sequence[RegisterSpec]) -> float:
    bits = math.log2(len(NodeKind))
    if node.kind is NodeKind.APPLY:
        bits += math.log2(len(SEED_ALPHABET.names()))
        bits += sum(math.log2(max(2, position)) for _ in node.args)
    elif node.kind is NodeKind.INPUT:
        bits += math.log2(len(InputSource))
        if node.source is InputSource.FEATURE:
            bits += math.log2(FEATURE_WIDTH)
    elif node.kind is NodeKind.CONST:
        bits += 32.0
    elif node.kind is NodeKind.REG:
        ring = registers[node.index].ring
        bits += math.log2(max(2, len(registers))) + math.log2(max(2, ring))
    return bits


def _macro_node_count(name: str, alphabet: PrimitiveAlphabet | None) -> int:
    if alphabet is None:
        raise ContractError(
            f"genome uses macro {name!r}; its description length needs the alphabet "
            "that defines it"
        )
    macro = alphabet.get(name).macro
    if macro is None:
        raise IRError("UNKNOWN_PRIMITIVE", f"{name!r} is not a macro in the given alphabet")
    return len(macro.nodes)


def _description_length(
    genome: ComputationalGenomeV1, alphabet: PrimitiveAlphabet | None
) -> float:
    node_bits = [
        _node_bits(node, position, genome.registers)
        for program in (genome.update, genome.readout)
        for position, node in enumerate(program.nodes)
    ]
    total = sum(node_bits)
    total += 8.0 * len(genome.registers)  # 2 type bits + 6 precision bits per register
    total += math.log2(3)  # one of three aggregations
    total += 32.0 * len(genome.lookup_table)
    # A macro use is credited at this genome's average node price (nodes only, not the
    # register/aggregation/table overhead); the total is clamped so it cannot go negative.
    mean_node_bits = sum(node_bits) / len(node_bits) if node_bits else 0.0
    for name in genome.macro_uses:
        total -= (_macro_node_count(name, alphabet) - 1) * mean_node_bits
    return max(0.0, total)


# --- construction ------------------------------------------------------------


def _macro_uses_in(
    nodes: Sequence[IRNode], alphabet: PrimitiveAlphabet, depth: int = 0
) -> list[str]:
    """Every macro use in ``nodes``, including uses nested inside macro bodies."""
    if depth > _MACRO_WALK_DEPTH:
        raise IRError("MACRO_DEPTH", f"macro nesting exceeds {_MACRO_WALK_DEPTH}")
    uses: list[str] = []
    for node in nodes:
        if node.kind is not NodeKind.APPLY:
            continue
        macro = alphabet.get(node.primitive).macro
        if macro is not None:
            uses.append(node.primitive)
            uses.extend(_macro_uses_in(macro.nodes, alphabet, depth + 1))
    return uses


def build_genome(
    *,
    registers: Sequence[RegisterSpec],
    update: IRProgram,
    readout: IRProgram,
    aggregation: SessionAggregation,
    lookup_table: Sequence[float] = (),
    alphabet: PrimitiveAlphabet = SEED_ALPHABET,
    min_events_for_score: int = 1,
    parent_digests: Sequence[str] = (),
    mutation: str = "",
) -> ComputationalGenomeV1:
    """The one constructor search and hand-written genomes share.

    Expands every macro through ``alphabet``, records each use in ``macro_uses``, and
    sets both declared bounds *exactly* to the computed static bounds, so a genome built
    here never over-declares either (an over-declared bound is legal but wastes budget).
    """
    register_tuple = tuple(registers)
    uses = tuple(
        _macro_uses_in(update.nodes, alphabet) + _macro_uses_in(readout.nodes, alphabet)
    )
    expanded_update = alphabet.expand(update)
    expanded_readout = alphabet.expand(readout)
    validate_program(expanded_update, register_tuple, SEED_ALPHABET)
    validate_program(expanded_readout, register_tuple, SEED_ALPHABET)
    bounds = static_bounds(expanded_update, expanded_readout, register_tuple, SEED_ALPHABET)
    return ComputationalGenomeV1(
        registers=register_tuple,
        update=expanded_update,
        readout=expanded_readout,
        aggregation=aggregation,
        lookup_table=tuple(float(entry) for entry in lookup_table),
        declared_max_state_bytes=bounds.session_state_bytes_max,
        declared_max_steps_per_event=bounds.max_steps_per_event,
        min_events_for_score=min_events_for_score,
        macro_uses=uses,
        parent_digests=tuple(parent_digests),
        mutation=mutation,
    )


# --- the architecture's fourteen fields --------------------------------------

#: Architecture §4's fourteen genome fields -> the attribute(s)/property(ies) that bind
#: them, joined by ``+``. Every name resolves on a genome (tested). The two laws whose
#: only member is fixed (learning, routing) are bound to one-member enums on purpose.
ARCHITECTURE_FIELD_BINDING: Mapping[str, str] = MappingProxyType(
    {
        "state_space": "registers",
        "observation_map": "observation_map",
        "primitive_alphabet": "macro_uses+alphabet_digest",
        "transition_law": "update",
        "memory_law": "registers+update",
        "forgetting_law": "update+lineage_eviction_policy",
        "learning_law": "learning_law",
        "uncertainty_law": "min_events_for_score",
        "readout_law": "readout+aggregation",
        "routing_law": "routing_law",
        "resource_control_law": "declared_max_state_bytes+declared_max_steps_per_event",
        "compression_law": "registers",
        "evidence_semantics": "evidence_semantics",
        "deployment_backend": "backend",
    }
)


def resolve_field(genome: ComputationalGenomeV1, architecture_field: str) -> tuple[Any, ...]:
    """The values bound to one architecture field; ``ContractError`` for an unknown one."""
    binding = ARCHITECTURE_FIELD_BINDING.get(architecture_field)
    if binding is None:
        raise ContractError(f"architecture §4 has no genome field {architecture_field!r}")
    return tuple(getattr(genome, attribute) for attribute in binding.split("+"))
