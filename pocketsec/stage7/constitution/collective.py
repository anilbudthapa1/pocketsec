"""D7.1 — the Collective Constitution: the hard laws for foreign knowledge, bound to code.

Stage 7 is where knowledge from other hosts arrives. Architecture §3 states eight laws for
it in prose; the project lead added two (local sovereignty, and no foreign normality —
ADR-0063). A law in prose is enforced by nothing, so this module turns each one into a
:class:`LawBinding` that names

* the one symbol that enforces it (``pocketsec.stage7.<module>:<qualname>``), and
* the one test whose name says it (``tests/test_stage7_<key>.py::test_<name>``).

The pairs are fixed by spec §4 D7.1 so the eight work packages agree on them; this module
does not choose them. :func:`verify_collective_constitution` resolves every enforcer with
:mod:`importlib` and parses every test file with :mod:`ast` **at call time, never at
import**, because the enforcing modules are built by other packages in parallel. A
non-empty answer fails gate check G7.1: a law bound to a symbol that does not exist, or
proved by a test that does not exist, is a docstring.

:data:`COLLECTIVE_EXCHANGE_ENABLED` is ``False`` (architecture §28: Stage 7 is an
accelerator, not a dependency). Turning collective exchange on is a deployment decision,
not a code path anyone reaches by accident.

This module holds no state, admits nothing, trusts nothing and grants nothing. It refuses
only malformed bindings, on construction.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage7.core_ids import SYMBOL_PATTERN, symbol_problem

__all__ = [
    "COLLECTIVE_CONSTITUTION",
    "COLLECTIVE_EXCHANGE_ENABLED",
    "TESTED_BY_PATTERN",
    "CollectiveLaw",
    "LawBinding",
    "law_test_problem",
    "verify_collective_constitution",
]

#: Architecture §28. Off by default; ADR-0060 records who may turn it on.
COLLECTIVE_EXCHANGE_ENABLED: bool = False

#: ``tests/test_stage7_<package>.py::test_<name>`` — a law names a test in this stage.
TESTED_BY_PATTERN = re.compile(r"^tests/test_stage7_[a-z0-9_]+\.py::test_[a-z0-9_]+$")

_S7 = "pocketsec.stage7."


class CollectiveLaw(StrEnum):
    """Architecture §3's eight laws, plus the lead's two (spec D7.1)."""

    NO_DIRECT_TRUSTED_WRITE = "NO_DIRECT_TRUSTED_WRITE"
    NO_STAGE5_INVOCATION = "NO_STAGE5_INVOCATION"
    FOREIGN_IS_UNTRUSTED_EVEN_SIGNED = "FOREIGN_IS_UNTRUSTED_EVEN_SIGNED"
    MAJORITY_IS_NOT_TRUTH = "MAJORITY_IS_NOT_TRUTH"
    NO_UNBOUNDED_IDENTITY_INFLUENCE = "NO_UNBOUNDED_IDENTITY_INFLUENCE"
    NO_RAW_HOST_DATA_EXPORT = "NO_RAW_HOST_DATA_EXPORT"
    EVERY_IMPORT_REJECTABLE_EXPIRABLE_REVOCABLE = "EVERY_IMPORT_REJECTABLE_EXPIRABLE_REVOCABLE"
    LOCAL_PROTECTION_SURVIVES_NETWORK_LOSS = "LOCAL_PROTECTION_SURVIVES_NETWORK_LOSS"
    #: No collective outcome changes a local decision without local evidence.
    LOCAL_SOVEREIGNTY = "LOCAL_SOVEREIGNTY"
    #: ADR-0063: a foreign peer may suggest what to fear, never what to trust.
    NO_FOREIGN_NORMALITY = "NO_FOREIGN_NORMALITY"


@dataclass(frozen=True, slots=True)
class LawBinding:
    """One law, the symbol that enforces it, and the test that proves the symbol does."""

    law: CollectiveLaw
    enforced_by: str
    tested_by: str
    statement: str

    def __post_init__(self) -> None:
        if not isinstance(self.law, CollectiveLaw):
            raise ContractError(f"LawBinding.law must be a CollectiveLaw, got {self.law!r}")
        if not isinstance(self.enforced_by, str) or not SYMBOL_PATTERN.fullmatch(
            self.enforced_by
        ):
            raise ContractError(
                f"{self.law}: enforced_by {self.enforced_by!r} is not pocketsec.stage7.<m>:<q>"
            )
        if not isinstance(self.tested_by, str) or not TESTED_BY_PATTERN.fullmatch(
            self.tested_by
        ):
            raise ContractError(f"{self.law}: tested_by {self.tested_by!r} is not a test id")
        if not isinstance(self.statement, str) or not self.statement.strip():
            raise ContractError(f"{self.law}: a law with no statement binds nothing")


def _bind(law: CollectiveLaw, enforced_by: str, tested_by: str, statement: str) -> LawBinding:
    return LawBinding(law, _S7 + enforced_by, "tests/" + tested_by, statement)


_L = CollectiveLaw

#: Spec D7.1's table, one binding per law, in law order. The enforcer/test pairs are the
#: spec's verbatim; only the statements are this module's wording of architecture §3.
COLLECTIVE_CONSTITUTION: tuple[LawBinding, ...] = (
    _bind(
        _L.NO_DIRECT_TRUSTED_WRITE,
        "hivelock.stage6_bridge:Stage6Bridge.hand_over",
        "test_stage7_boundary.py::test_no_stage7_module_names_a_stage6_writer",
        "Stage 7 never modifies trusted Stage 1-6 cognition: foreign knowledge leaves Stage 7 "
        "only as ExperienceCapsuleV1 values handed to Stage 6's QuarantineGateway.admit.",
    ),
    _bind(
        _L.NO_STAGE5_INVOCATION,
        "capsule.knowledge_capsule:authority_key_violations",
        "test_stage7_boundary.py::test_no_stage7_module_imports_stage5",
        "Stage 7 never invokes Stage 5: no Stage 7 module imports Stage 5, and no capsule "
        "carries an authority-named key at any depth.",
    ),
    _bind(
        _L.FOREIGN_IS_UNTRUSTED_EVEN_SIGNED,
        "hivelock.ingress:HivelockIngress.receive",
        "test_stage7_ingress.py::test_a_validly_signed_capsule_is_only_ever_pooled",
        "Every foreign object is untrusted input even when validly signed: the best a "
        "capsule can reach at ingress is POOLED.",
    ),
    _bind(
        _L.MAJORITY_IS_NOT_TRUTH,
        "echo.inference:EchoEngine.infer",
        "test_stage7_echo.py::test_identity_count_does_not_raise_mass_within_a_cluster",
        "A majority is never ground truth: more identities in one dependence cluster add no "
        "support mass.",
    ),
    _bind(
        _L.NO_UNBOUNDED_IDENTITY_INFLUENCE,
        "graph.dependence:DependenceGraph.observe",
        "test_stage7_graph.py::test_sybils_sharing_a_root_are_one_cluster",
        "One physical or administrative source cannot gain unbounded influence by spawning "
        "identities: identities sharing a root are one cluster.",
    ),
    _bind(
        _L.NO_RAW_HOST_DATA_EXPORT,
        "privacy.distiller:residual_identifier_hits",
        "test_stage7_privacy.py::test_no_raw_fleet_string_survives_export",
        "Raw command history, credentials, sensitive filenames and raw telemetry never "
        "leave the host: any string outside the closed wire vocabulary refuses export.",
    ),
    _bind(
        _L.EVERY_IMPORT_REJECTABLE_EXPIRABLE_REVOCABLE,
        "lineage.cross_host:RevocationPlane.submit",
        "test_stage7_sovereignty.py::test_revocation_marks_exactly_the_descendants",
        "Every imported object is locally rejectable, expirable and revocable, and "
        "revocation is targeted at exactly its descendants.",
    ),
    _bind(
        _L.LOCAL_PROTECTION_SURVIVES_NETWORK_LOSS,
        "orpheus.fabric:OrpheusFabric.run_round",
        "test_stage7_sovereignty.py::"
        "test_local_detection_is_identical_with_the_fabric_absent_offline_or_crashing",
        "Loss of the Stage 7 network never reduces local Stage 1-6 protection: local "
        "outputs are identical with the fabric absent, offline or crashing.",
    ),
    _bind(
        _L.LOCAL_SOVEREIGNTY,
        "echo.inference:EchoEngine.infer",
        "test_stage7_sovereignty.py::test_a_unanimous_fleet_cannot_change_a_local_decision",
        "No collective outcome, however unanimous, overrides a local denial, grants "
        "authority, or changes a local decision without local evidence.",
    ),
    _bind(
        _L.NO_FOREIGN_NORMALITY,
        "capsule.knowledge_capsule:KnowledgeType",
        "test_stage7_foundation.py::test_no_knowledge_type_can_assert_normality",
        "A foreign peer may suggest what to fear, never what to trust: no knowledge type "
        "carries normality, a baseline or a benign verdict.",
    ),
)

# Import-time invariant, raised rather than asserted so ``-O`` cannot strip it.
if [binding.law for binding in COLLECTIVE_CONSTITUTION] != list(CollectiveLaw):
    raise ContractError("COLLECTIVE_CONSTITUTION must bind every CollectiveLaw exactly once")


def _defined_tests(path: Path) -> frozenset[str]:
    """Names of the test functions ``path`` defines, read with ``ast`` (never imported).

    Parsing rather than importing matters twice over: importing a test module would run
    its imports (another package's half-built module), and a name mentioned only in a
    docstring or comment must not count as a test that exists.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return frozenset(
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )


def law_test_problem(tested_by: str, *, root: Path = REPO_ROOT) -> str | None:
    """Why the test ``tested_by`` names does not exist, or ``None`` when it does."""
    if not isinstance(tested_by, str) or not TESTED_BY_PATTERN.fullmatch(tested_by):
        return "malformed: not tests/test_stage7_<key>.py::test_<name>"
    file_name, function = tested_by.split("::", 1)
    path = root / file_name
    if not path.is_file():
        return f"test file not found: {file_name}"
    try:
        defined = _defined_tests(path)
    except SyntaxError as exc:
        return f"test file does not parse: {file_name}: {exc.msg}"
    if function not in defined:
        return f"{file_name} defines no test {function!r}"
    return None


def verify_collective_constitution(*, root: Path = REPO_ROOT) -> tuple[str, ...]:
    """Every reason a law is not bound to code; ``()`` means every law resolves.

    One string per problem, prefixed with the law: an ``enforced_by`` that does not
    resolve to a callable, or a ``tested_by`` whose file is missing or defines no such
    test. Nothing is imported until this is called.
    """
    problems: list[str] = []
    for binding in COLLECTIVE_CONSTITUTION:
        enforcer = symbol_problem(binding.enforced_by)
        if enforcer is not None:
            problems.append(f"{binding.law}: enforced_by {binding.enforced_by}: {enforcer}")
        test = law_test_problem(binding.tested_by, root=root)
        if test is not None:
            problems.append(f"{binding.law}: tested_by {binding.tested_by}: {test}")
    return tuple(problems)
