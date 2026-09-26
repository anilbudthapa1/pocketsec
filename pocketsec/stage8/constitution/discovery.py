"""D8.1 / PROM-F01 — the Discovery Constitution: nine laws, each bound to what enforces it.

Architecture §3 states nine laws for Stage 8. A law that is only a sentence is a promise;
this module turns each into a :class:`DiscoveryLaw` whose ``enforced_by`` names the code (or
the boundary test) that makes it true, and :func:`verify_discovery_constitution` checks —
at runtime, against the tree as it is — that every one of those names still resolves and
that the properties the laws rest on still hold. ``()`` is the only passing answer.

What the verifier checks:

1. **Every binding resolves.** ``"pocketsec.stage8.<module>:<qualname>"`` is imported with
   :mod:`importlib` *lazily, by string* — eight packages build in parallel and several of
   the named modules import this one, so an eager import would be a cycle. ``"tests/<file>.py"``
   (optionally ``::<test>``) must exist and, when named, define that test (read with
   :mod:`ast`, never executed).
2. **Defensive only (DL-01).** No member name or value of the six closed vocabularies —
   ``RepresentationKind``, ``ExperimentClass``, ``ChallengeKind``, ``TransformKind``,
   ``GeneratorKind``, ``FalsifierKind`` — matches :data:`OFFENSIVE_TOKENS`. Adversarial work
   in Stage 8 perturbs *synthetic telemetry* to test defences; a vocabulary that could name
   an exploit, payload or implant would be the first step to producing one.
3. **No production intervention (DL-02, DL-09, ADR-0075).** ``ExperimentClass`` equals
   :data:`SAFE_EXPERIMENT_CLASSES` plus ``ISOLATED_EMULATION`` exactly. The safe set is
   *listed*, not derived as "everything but emulation", so a new member cannot become safe by
   default: it fails this check until someone decides what it is.
4. **Falsifiable or refused (DL-05).** A valid control genome is built first (so the refusal
   below is known to be about falsifiers, not about some other malformed field); then the same
   genome with no falsifiers, and with each mandatory falsifier missing, must raise
   ``ContractError``.
5. **UNKNOWN is an answer (DL-06).** ``Verdict.UNIDENTIFIABLE`` and
   ``Verdict.INSUFFICIENT_EVIDENCE`` exist.

This module decides nothing at runtime, holds no state and grants nothing.
"""

from __future__ import annotations

import ast
import importlib
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage8.genome.hypothesis import ExperimentClass

__all__ = [
    "CLOSED_VOCABULARIES",
    "DISCOVERY_LAWS",
    "OFFENSIVE_TOKENS",
    "SAFE_EXPERIMENT_CLASSES",
    "DiscoveryLaw",
    "resolve_binding",
    "verify_discovery_constitution",
]

#: Words that name offensive capability. Screened against every closed-vocabulary member.
OFFENSIVE_TOKENS: re.Pattern[str] = re.compile(
    r"(?i)(exploit|payload|shellcode|malware|implant|backdoor|ransom|keylog|rootkit|weaponi[sz])"
)

#: Listed explicitly (see the module docstring, check 3). Each only reads recorded or
#: synthetic episodes in-process.
SAFE_EXPERIMENT_CLASSES: frozenset[ExperimentClass] = frozenset({
    ExperimentClass.HISTORICAL_REPLAY,
    ExperimentClass.COUNTERFACTUAL_MUTATION,
    ExperimentClass.TELEMETRY_DROPOUT,
    ExperimentClass.METAMORPHIC_TRANSFORM,
    ExperimentClass.BENIGN_ALTERNATIVE,
    ExperimentClass.SYNTHETIC_EVENT_WORLD,
})

#: (module, enum name) of the six closed vocabularies, resolved lazily.
CLOSED_VOCABULARIES: tuple[tuple[str, str], ...] = (
    ("pocketsec.stage8.forge.package", "RepresentationKind"),
    ("pocketsec.stage8.genome.hypothesis", "ExperimentClass"),
    ("pocketsec.stage8.challenger.adversarial", "ChallengeKind"),
    ("pocketsec.stage8.laboratory.counterfactual", "TransformKind"),
    ("pocketsec.stage8.genome.hypothesis", "GeneratorKind"),
    ("pocketsec.stage8.genome.hypothesis", "FalsifierKind"),
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SYMBOL = re.compile(
    r"^pocketsec\.stage[0-8](?:\.[a-z_][a-z0-9_]*)+:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$"
)
_TEST_REF = re.compile(r"^tests/test_stage8_[a-z0-9_]+\.py(?:::[A-Za-z_]\w*)?$")
_BOUNDARY = "tests/test_stage8_boundary.py"
_HYPOTHESIS = "pocketsec.stage8.genome.hypothesis"


@dataclass(frozen=True, slots=True)
class DiscoveryLaw:
    """One architecture §3 law, verbatim, and the names that make it true."""

    law_id: str
    text: str
    enforced_by: tuple[str, ...]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"DL-0[1-9]", self.law_id):
            raise ContractError(f"law_id must be DL-01 … DL-09, got {self.law_id!r}")
        if not self.text or not self.enforced_by:
            raise ContractError(f"{self.law_id}: a law needs its text and at least one enforcer")
        for ref in self.enforced_by:
            if not (_SYMBOL.fullmatch(ref) or _TEST_REF.fullmatch(ref)):
                raise ContractError(f"{self.law_id}: {ref!r} is not a symbol or a test path")


DISCOVERY_LAWS: tuple[DiscoveryLaw, ...] = (
    DiscoveryLaw(
        "DL-01", "Stage 8 is defensive research, not an autonomous offensive agent.",
        (
            "pocketsec.stage8.constitution.discovery:OFFENSIVE_TOKENS",
            "pocketsec.stage8.constitution.discovery:CLOSED_VOCABULARIES",
            _BOUNDARY,
        ),
    ),
    DiscoveryLaw(
        "DL-02", "No hypothesis grants permission to execute an action on external systems.",
        (
            "pocketsec.stage0.contracts.threat_prediction_v1:FORBIDDEN_AUTHORITY_FIELDS",
            f"{_HYPOTHESIS}:ExperimentClass",
            "pocketsec.stage8.constitution.discovery:SAFE_EXPERIMENT_CLASSES",
            _BOUNDARY,
        ),
    ),
    DiscoveryLaw(
        "DL-03",
        "No generated procedure may bypass Stage 5 authority or Stage 6 learning gates.",
        ("pocketsec.stage8.adapters.stage6:Stage6Adapter", _BOUNDARY),
    ),
    DiscoveryLaw(
        "DL-04", "An LLM may propose theories but cannot define ground truth.",
        (
            "pocketsec.stage8.prometheus.generators:ExternalProposalGenerator",
            f"{_HYPOTHESIS}:GenomeProvenance",
        ),
    ),
    DiscoveryLaw(
        "DL-05", "Every accepted theory must state observations that could falsify it.",
        (
            f"{_HYPOTHESIS}:HypothesisGenome",
            f"{_HYPOTHESIS}:MANDATORY_FALSIFIERS",
            "pocketsec.stage8.ledger.theory:TheoryLedger.preregister",
            "pocketsec.stage8.sandbox.integrity:HoldoutVault",
        ),
    ),
    DiscoveryLaw(
        "DL-06", "UNKNOWN/UNIDENTIFIABLE is a valid scientific result.",
        (
            "pocketsec.stage8.identifiability.gate:IdentifiabilityGate",
            "pocketsec.stage0.contracts.threat_prediction_v1:Verdict.UNIDENTIFIABLE",
        ),
    ),
    DiscoveryLaw(
        "DL-07",
        "Complexity is penalized; simpler mechanisms are preferred when explanatory power is "
        "equivalent.",
        (
            "pocketsec.stage8.genome.grammar:Mechanism.description_length_bits",
            "pocketsec.stage8.ecology.population:HypothesisPopulation",
        ),
    ),
    DiscoveryLaw(
        "DL-08",
        "Discoveries are not trusted until they survive Stage 6 quarantine, shadow and "
        "conservation testing.",
        ("pocketsec.stage8.adapters.stage6:Stage6Adapter", _BOUNDARY),
    ),
    DiscoveryLaw(
        "DL-09",
        "Real-system active experiments require explicit isolated lab authorization; "
        "production defaults to observation/replay only.",
        (
            "pocketsec.stage8.sandbox.boundary:ResearchSandbox",
            "pocketsec.stage8.sandbox.boundary:EMULATOR_AVAILABLE",
        ),
    ),
)


def resolve_binding(ref: str) -> str | None:
    """``None`` if ``ref`` resolves, else the problem. Never raises."""
    if _TEST_REF.fullmatch(ref):
        return _resolve_test(ref)
    module_name, _, qualname = ref.partition(":")
    try:
        target: Any = importlib.import_module(module_name)
    except Exception as error:  # an unimportable module is a finding, not a crash
        return f"{ref}: module does not import ({type(error).__name__}: {error})"
    for part in qualname.split("."):
        if not hasattr(target, part):
            return f"{ref}: {part!r} is not defined"
        target = getattr(target, part)
    return None


def _resolve_test(ref: str) -> str | None:
    path_text, _, test_name = ref.partition("::")
    path = _REPO_ROOT / path_text
    if not path.is_file():
        return f"{ref}: the test file does not exist"
    if not test_name:
        return None
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError) as error:
        return f"{ref}: the test file does not parse ({error})"
    defined = {
        node.name for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    return None if test_name in defined else f"{ref}: no test named {test_name!r}"


def _vocabulary_problems() -> list[str]:
    problems: list[str] = []
    for module_name, enum_name in CLOSED_VOCABULARIES:
        ref = f"{module_name}:{enum_name}"
        missing = resolve_binding(ref)
        if missing is not None:
            problems.append(missing)
            continue
        vocabulary = getattr(importlib.import_module(module_name), enum_name)
        if not (isinstance(vocabulary, type) and issubclass(vocabulary, Enum)):
            problems.append(f"{ref} is not a closed enum")
            continue
        for member in vocabulary:
            if OFFENSIVE_TOKENS.search(member.name) or OFFENSIVE_TOKENS.search(str(member.value)):
                problems.append(f"{ref}.{member.name} names offensive capability (DL-01)")
    return problems


def _experiment_class_problems() -> list[str]:
    try:
        live = importlib.import_module(_HYPOTHESIS).ExperimentClass
        emulation = live.ISOLATED_EMULATION
    except (ImportError, AttributeError) as error:
        return [f"ExperimentClass has no ISOLATED_EMULATION member ({error})"]
    problems: list[str] = []
    if emulation in SAFE_EXPERIMENT_CLASSES:
        problems.append("ISOLATED_EMULATION is listed as a safe experiment class")
    extra = {member.name for member in live} - {m.name for m in SAFE_EXPERIMENT_CLASSES} - {
        emulation.name
    }
    if extra:
        problems.append(
            f"ExperimentClass members {sorted(extra)} are neither listed safe nor emulation; "
            "a production-intervention class needs an ADR, not a default (ADR-0075)"
        )
    missing = {m.name for m in SAFE_EXPERIMENT_CLASSES} - {member.name for member in live}
    if missing:
        problems.append(f"SAFE_EXPERIMENT_CLASSES names removed members {sorted(missing)}")
    return problems


def _control_genome_kwargs(hypothesis: Any) -> dict[str, Any]:
    """Arguments for ``genome_for`` that build one valid, minimal genome."""
    grammar = importlib.import_module("pocketsec.stage8.genome.grammar")
    relations = importlib.import_module("pocketsec.stage1.ssir.relations")
    predicate = grammar.StepPredicate(
        relation=int(relations.Relation.EXECUTE), require_properties=0, forbid_properties=0,
        require_raised=0,
    )
    return {
        "mechanism": grammar.Mechanism(
            relation=grammar.MechanismRelation.SINGLE, steps=(predicate,)
        ),
        "direction": hypothesis.Direction.MALICIOUS,
        "scope": hypothesis.ObservationScope(
            residual_cluster_ids=(),
            residual_types=frozenset({hypothesis.ResidualType.OBSERVATION}),
            episode_ids=(),
        ),
        "provenance": hypothesis.GenomeProvenance(
            generator=hypothesis.GeneratorKind.SYMBOLIC_ENUMERATOR,
            source_digest="sha256:" + "0" * 64, foreign=False, seed=0,
        ),
    }


def _falsifier_problems() -> list[str]:
    """DL-05 by construction: the control builds, and every falsifier-deficient twin is refused."""
    try:
        hypothesis = importlib.import_module(_HYPOTHESIS)
        kwargs = _control_genome_kwargs(hypothesis)
        control = hypothesis.genome_for(**kwargs)
    except Exception as error:  # the check cannot run; that is itself a failure
        return [f"cannot build the valid control genome ({type(error).__name__}: {error})"]
    full = tuple(control.falsification_tests)
    deficient: list[tuple[str, tuple[Any, ...]]] = [("no falsifiers", ())]
    for kind in sorted(hypothesis.MANDATORY_FALSIFIERS, key=lambda k: k.name):
        deficient.append((f"missing {kind.name}", tuple(f for f in full if f.kind is not kind)))
    problems: list[str] = []
    for label, falsifiers in deficient:
        try:
            hypothesis.genome_for(**kwargs, falsifiers=falsifiers)
        except ContractError:
            continue
        except Exception as error:
            problems.append(f"a genome with {label} raised {type(error).__name__}")
            continue
        problems.append(f"a genome with {label} was accepted (DL-05)")
    return problems


def _verdict_problems() -> list[str]:
    module = importlib.import_module("pocketsec.stage0.contracts.threat_prediction_v1")
    return [
        f"Verdict.{name} is missing (DL-06)"
        for name in ("UNIDENTIFIABLE", "INSUFFICIENT_EVIDENCE")
        if not hasattr(module.Verdict, name)
    ]


def verify_discovery_constitution() -> tuple[str, ...]:
    """Every problem with the nine laws' bindings and the properties they rest on."""
    problems: list[str] = []
    if tuple(law.law_id for law in DISCOVERY_LAWS) != tuple(f"DL-0{i}" for i in range(1, 10)):
        problems.append("DISCOVERY_LAWS must be exactly DL-01 … DL-09, in order")
    for law in DISCOVERY_LAWS:
        for ref in law.enforced_by:
            problem = resolve_binding(ref)
            if problem is not None:
                problems.append(f"{law.law_id}: {problem}")
    problems.extend(_vocabulary_problems())
    problems.extend(_experiment_class_problems())
    problems.extend(_falsifier_problems())
    problems.extend(_verdict_problems())
    return tuple(problems)
