"""Stage 6's dependency and single-writer boundary (spec §5.1, ADR-0001/0050/0051/0052/0053/0121).

``tests/test_repository_structure.py`` implements the import rules for Stages 0-2 and
hard-codes ``pocketsec/stage2/research/``; another wave may be editing it, so Stage 6
gets its own copy of the *technique* here and leaves that file untouched. Stage 6 is the
stage where learning may change trusted state, so its import graph and its writer set
are a security boundary, not a tidiness preference.

The eleven rules of spec §5.1:

1. **R1 / ADR-0001.** Every module under ``pocketsec/stage6/`` imports only stdlib roots
   or ``pocketsec``.
2. **R2 / ADR-0008 + ADR-0050.** No ``pocketsec.stage*.research*`` import, and
   ``pocketsec/stage6/research/`` does not exist.
3. **Upstream allow-list (§2.5, ADR-0053).** Stage 2: four runtime modules (plus two lab
   modules, from ``stage6/labs/`` only); Stage 3: nothing; Stage 4: ``stage5_interface``;
   Stage 5: ``stage6_interface``; Stages 7-12: only from ``capsule/quarantine.py`` (T3).
4. **Single writer (ADR-0052).** Across all of ``pocketsec/``, ``_install_trusted`` and
   ``_trusted_state`` — as a name, an attribute, a ``def`` or a string — and any
   ``TrustedMind(...)`` construction appear only in ``promotion/controller.py``.
5. **Gateway seal.** ``_issue_verdict``/``_issued_verdicts`` only in
   ``capsule/quarantine.py``; ``_issue_candidate``/``_issued_candidates`` only in
   ``chamber/evolution.py``; ``_issue_decision``/``_issued_decisions`` only in
   ``promotion/controller.py``.
6. **Runtime never imports labs.**
7. **T5.** No annotated field of a ``@dataclass`` under ``pocketsec/stage6/`` contains a
   ``FORBIDDEN_AUTHORITY_FIELDS`` member, lowercased. No exemption list. Enum members are
   unannotated assignments and are not fields.
8. **No earlier stage imports Stage 6.**
9. **No second harness, ledger, contracts or corpus type.**
10. **No empty package (ADR-0121)**, and ``helios/``, ``learning/``, ``mnemosyne/``,
    ``quarantine/`` do not exist.
11. **No second Stage 2 gate:** no Stage 6 function takes ``min_epochs`` or
    ``delay_sequences`` as a parameter (ADR-0051).

Every check walks the AST, never the text: several modules *name* the boundary in a
docstring, and naming it is not crossing it. The import resolver is **imported** from
``pocketsec.stage2.gate_criteria``, never copied — S2-AUTH-01 was a hole open in two
checkers at once, and two copies is how it stayed open in both.

**Every package has landed.** The integrator emptied :data:`PENDING_EMPTY_DIRECTORIES`
(``memory/`` is a package now), so the no-empty-package rule holds with no concession.

**The gate and the CLI are the harness, not the runtime.** Spec §4.23 requires
``gate.py`` to run the endurance timeline, the poison suite and the ablation, all of
which live in ``labs/``; rule 6 therefore exempts exactly the integrator's harness
modules at the stage root (:data:`HARNESS_MODULES`, Stage 4/5 precedent), and a
compensating rule forbids every other Stage 6 module — and every other stage — from
importing them, so the labs cannot reach the runtime through the gate.
"""

from __future__ import annotations

import ast
import sys
from functools import cache
from pathlib import Path

import pytest

from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS
from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage2.gate_criteria import imported_modules

POCKETSEC_ROOT = REPO_ROOT / "pocketsec"
STAGE6_ROOT = POCKETSEC_ROOT / "stage6"

#: Stage 2 runtime modules Stage 6 composes (ADR-0051); exact module paths, because a
#: package import (``from pocketsec.stage2.encoder import x``) could reach anything its
#: ``__init__`` re-exports.
PERMITTED_STAGE2 = frozenset(
    {
        "pocketsec.stage2.encoder.ssir_encoder",
        "pocketsec.stage2.adaptation.quarantine",
        "pocketsec.stage2.adaptation.promotion",
        "pocketsec.stage2.adaptation.epoch_guard",
    }
)
#: Stage 2 corpus builders the Stage 6 labs reuse instead of writing a second builder.
PERMITTED_STAGE2_FROM_LABS = frozenset(
    {"pocketsec.stage2.labs.drift_corpus", "pocketsec.stage2.labs.poison_suite"}
)
PERMITTED_STAGE4 = frozenset({"pocketsec.stage4.stage5_interface"})
PERMITTED_STAGE5 = frozenset({"pocketsec.stage5.stage6_interface"})
DOWNSTREAM_STAGES = frozenset({f"stage{n}" for n in range(7, 13)})
FREELY_IMPORTABLE_STAGES = frozenset({"stage0", "stage1", "stage6"})

#: T3: the one Stage 6 module that may ever import Stages 7-12.
T3_IMPORTER = ("stage6", "capsule", "quarantine.py")

#: Name -> the one file (relative to ``pocketsec/``) that may mention it (rules 4 and 5).
SEALED_NAMES: dict[str, tuple[str, ...]] = {
    "_install_trusted": ("stage6", "promotion", "controller.py"),
    "_trusted_state": ("stage6", "promotion", "controller.py"),
    "_issue_verdict": ("stage6", "capsule", "quarantine.py"),
    "_issued_verdicts": ("stage6", "capsule", "quarantine.py"),
    "_issue_candidate": ("stage6", "chamber", "evolution.py"),
    "_issued_candidates": ("stage6", "chamber", "evolution.py"),
    "_issue_decision": ("stage6", "promotion", "controller.py"),
    "_issued_decisions": ("stage6", "promotion", "controller.py"),
}
WRITER_CLASS = "TrustedMind"
WRITER_FILE = ("stage6", "promotion", "controller.py")
SINGLE_WRITER_NAMES = frozenset({"_install_trusted", "_trusted_state"})

FORBIDDEN_STAGE6_DIRECTORIES = ("contracts", "benchmark", "experiments", "research")
#: ADR-0121 precedent: empty, not packages, named after nothing in the §2.1 layout.
DELETED_STAGE6_DIRECTORIES = ("helios", "learning", "mnemosyne", "quarantine")
#: Directories the spec assigns to a package that has not filled them yet. Tolerated
#: ONLY while empty. Every package has landed, so the integrator emptied it.
PENDING_EMPTY_DIRECTORIES: frozenset[str] = frozenset()
#: The integrator's harness at the stage root (spec §4.23): they may import ``labs``
#: because the gate must run the endurance and poison labs; nothing may import them.
HARNESS_MODULES = frozenset({"gate.py", "gate_rig.py", "gate_construction.py",
                             "gate_measured.py", "cli.py"})
FORBIDDEN_DEFINITIONS = frozenset({"run_benchmark", "ExperimentRegistry", "Scenario", "Behaviour"})
SECOND_GATE_PARAMETERS = frozenset({"min_epochs", "delay_sequences"})


def _modules(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


@cache
def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _resolved(path: Path) -> list[tuple[str, int]]:
    """Every module the file imports, as an ABSOLUTE dotted path, with its line."""
    return [
        (module, getattr(node, "lineno", 0))
        for node in ast.walk(_parse(path))
        for module in imported_modules(node, path)
    ]


def _rel(path: Path) -> tuple[str, ...]:
    """The path's parts below its innermost ``pocketsec`` directory (works for fixtures)."""
    parts = path.resolve().parts
    root = len(parts) - 1 - parts[::-1].index("pocketsec")
    return parts[root + 1 :]


def _label(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return "/".join(_rel(path))


def _is_research(module: str) -> bool:
    parts = module.split(".")
    return (
        len(parts) >= 3
        and parts[0] == "pocketsec"
        and parts[1].startswith("stage")
        and parts[2].startswith("research")
    )


def _allow_list_violation(module: str, rel: tuple[str, ...]) -> str | None:
    """Why ``module`` may not be imported by the Stage 6 file at ``rel`` (rule 3)."""
    parts = module.split(".")
    if parts[0] != "pocketsec" or len(parts) < 2:
        return None
    stage = parts[1]
    in_labs = len(rel) > 2 and rel[1] == "labs"
    if stage in FREELY_IMPORTABLE_STAGES:
        return None
    if stage == "stage2":
        allowed = PERMITTED_STAGE2 | (PERMITTED_STAGE2_FROM_LABS if in_labs else frozenset())
        return None if module in allowed else "stage2 outside the ADR-0051 allow-list"
    if stage == "stage3":
        return "Stage 6 consumes nothing from Stage 3 (ADR-0053)"
    if stage == "stage4":
        return None if module in PERMITTED_STAGE4 else "stage4 other than stage5_interface"
    if stage == "stage5":
        return None if module in PERMITTED_STAGE5 else "stage5 other than stage6_interface"
    if stage in DOWNSTREAM_STAGES:
        return None if rel == T3_IMPORTER else "T3: only capsule/quarantine.py may import 7-12"
    return f"unknown stage {stage!r}"


def _imports_labs(module: str) -> bool:
    return module == "pocketsec.stage6.labs" or module.startswith("pocketsec.stage6.labs.")


def _sealed_hits(path: Path) -> list[tuple[str, int]]:
    """Every mention of a sealed name, and every ``TrustedMind`` construction or alias."""
    hits: list[tuple[str, int]] = []
    for node in ast.walk(_parse(path)):
        name: str | None = None
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            name = node.name
        elif isinstance(node, ast.Name):
            name = node.id
        elif isinstance(node, ast.Attribute):
            name = node.attr
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            name = node.value
        elif isinstance(node, ast.arg):
            name = node.arg
        if name in SEALED_NAMES:
            hits.append((name, getattr(node, "lineno", 0)))
        if isinstance(node, ast.Call) and _callee(node.func) == WRITER_CLASS:
            hits.append((f"{WRITER_CLASS}(...)", node.lineno))
        if isinstance(node, ast.ImportFrom) and any(
            alias.name == WRITER_CLASS and alias.asname for alias in node.names
        ):
            hits.append((f"{WRITER_CLASS} imported under an alias", node.lineno))
    return hits


def _callee(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _owner_of(hit: str) -> tuple[str, ...]:
    return SEALED_NAMES.get(hit, WRITER_FILE)


def _is_dataclass(node: ast.ClassDef) -> bool:
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if _callee(target) == "dataclass":
            return True
    return False


def _t5_offenders(path: Path) -> list[tuple[str, int]]:
    """Annotated fields of ``@dataclass`` classes whose name contains an authority word."""
    found: list[tuple[str, int]] = []
    for node in ast.walk(_parse(path)):
        if not isinstance(node, ast.ClassDef) or not _is_dataclass(node):
            continue
        for statement in node.body:
            if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                lowered = statement.target.id.lower()
                if any(word in lowered for word in FORBIDDEN_AUTHORITY_FIELDS):
                    found.append((f"{node.name}.{statement.target.id}", statement.lineno))
    return found


def _second_gate_parameters(path: Path) -> list[tuple[str, int]]:
    found: list[tuple[str, int]] = []
    for node in ast.walk(_parse(path)):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        arguments = node.args
        every = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
        every += [a for a in (arguments.vararg, arguments.kwarg) if a is not None]
        found += [(a.arg, node.lineno) for a in every if a.arg in SECOND_GATE_PARAMETERS]
    return found


def _defined_names(path: Path) -> list[tuple[str, int]]:
    found: list[tuple[str, int]] = []
    for node in ast.walk(_parse(path)):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            found.append((node.name, node.lineno))
    return found


def test_stage6_has_modules_at_all() -> None:
    """Guard against every rule below passing vacuously on an empty stage."""
    assert _modules(STAGE6_ROOT), "pocketsec/stage6/ holds no Python modules"


def test_the_import_resolver_is_the_shared_one_not_a_copy() -> None:
    assert imported_modules.__module__ == "pocketsec.stage2.gate_criteria"


# --- rule 1 ------------------------------------------------------------------


def test_stage6_has_no_third_party_imports() -> None:
    """ADR-0001: a deferred import inside a function is caught exactly like a top-level one."""
    allowed = set(sys.stdlib_module_names) | {"pocketsec"}
    offenders = {
        _label(path): external
        for path in _modules(STAGE6_ROOT)
        if (external := {module.split(".")[0] for module, _ in _resolved(path)} - allowed)
    }
    assert not offenders, f"third-party imports in Stage 6: {offenders}"


# --- rule 2 ------------------------------------------------------------------


def test_stage6_never_imports_research_code_and_ships_no_research_package() -> None:
    """ADR-0050: RESEARCH_PREFIX is still Stage 2's literal, so numpy here fails ADR-0001."""
    assert not (STAGE6_ROOT / "research").exists()
    offenders = [
        f"{_label(path)}:{lineno} -> {module}"
        for path in _modules(STAGE6_ROOT)
        for module, lineno in _resolved(path)
        if _is_research(module)
    ]
    assert not offenders, f"Stage 6 modules importing research code: {offenders}"


# --- rule 3 ------------------------------------------------------------------


def test_stage6_imports_upstream_only_through_the_allow_list() -> None:
    """ADR-0053: every upstream seam is a named module, and Stage 3 is not one."""
    offenders = [
        f"{_label(path)}:{lineno} -> {module} ({reason})"
        for path in _modules(STAGE6_ROOT)
        for module, lineno in _resolved(path)
        if (reason := _allow_list_violation(module, _rel(path))) is not None
    ]
    assert not offenders, f"Stage 6 imports outside the allow-list: {offenders}"


def test_the_allow_list_permits_exactly_the_seams_it_must() -> None:
    """Both directions are the rule: a predicate refusing everything would pass vacuously."""
    runtime = ("stage6", "capsule", "experience_capsule.py")
    labs = ("stage6", "labs", "endurance.py")
    for module in (*PERMITTED_STAGE2, *PERMITTED_STAGE4, *PERMITTED_STAGE5):
        assert _allow_list_violation(module, runtime) is None, module
    for module in PERMITTED_STAGE2_FROM_LABS:
        assert _allow_list_violation(module, labs) is None, module
        assert _allow_list_violation(module, runtime) is not None, module
    assert _allow_list_violation("pocketsec.stage7.hivelock", T3_IMPORTER) is None
    for refused in (
        "pocketsec.stage2.gate_criteria",
        "pocketsec.stage2.encoder",
        "pocketsec.stage3.cells.schema",
        "pocketsec.stage4.worlds.world",
        "pocketsec.stage5.executor.transactional",
        "pocketsec.stage7.hivelock",
        "pocketsec.stage12.constellation",
    ):
        assert _allow_list_violation(refused, runtime) is not None, refused


# --- rules 4 and 5 -----------------------------------------------------------


def test_trusted_state_has_exactly_one_writer_across_the_repository() -> None:
    """ADR-0052: the only code that can change trusted state lives in one file.

    Scanned over all of ``pocketsec/`` rather than Stage 6, because a Stage 7 module
    that named the installer would be the same breach from further away. A string
    equal to a sealed name counts, so ``getattr(controller, "_install_trusted")`` is
    caught too.
    """
    offenders = [
        f"{_label(path)}:{lineno} {hit}"
        for path in _modules(POCKETSEC_ROOT)
        for hit, lineno in _sealed_hits(path)
        if (hit in SINGLE_WRITER_NAMES or hit.startswith(WRITER_CLASS))
        and _rel(path) != WRITER_FILE
    ]
    assert not offenders, f"trusted-state writer named outside {WRITER_FILE}: {offenders}"


def test_minting_names_appear_only_in_the_module_that_mints() -> None:
    """Gateway seal: a verdict, a candidate or a decision is minted in exactly one place."""
    offenders = [
        f"{_label(path)}:{lineno} {hit}"
        for path in _modules(POCKETSEC_ROOT)
        for hit, lineno in _sealed_hits(path)
        if hit in SEALED_NAMES and _rel(path) != SEALED_NAMES[hit]
    ]
    assert not offenders, f"minting names outside their owner: {offenders}"


# --- rule 6 ------------------------------------------------------------------


def _is_harness(rel: tuple[str, ...]) -> bool:
    return len(rel) == 2 and rel[0] == "stage6" and rel[1] in HARNESS_MODULES


def _imports_harness(module: str) -> bool:
    return module in {f"pocketsec.stage6.{name[:-3]}" for name in HARNESS_MODULES}


def test_the_runtime_never_imports_the_labs() -> None:
    """A runtime path that can reach a poisoning arm is a path an experiment can steer."""
    offenders = [
        f"{_label(path)}:{lineno} -> {module}"
        for path in _modules(STAGE6_ROOT)
        if _rel(path)[1] != "labs" and not _is_harness(_rel(path))
        for module, lineno in _resolved(path)
        if _imports_labs(module)
    ]
    assert not offenders, f"Stage 6 runtime importing labs: {offenders}"


def test_nothing_but_the_harness_imports_the_gate_or_the_cli() -> None:
    """The compensating rule for the harness exemption above, over all of ``pocketsec/``:
    a runtime or lab module that imported ``gate``/``cli`` would reach ``labs`` through it."""
    offenders = [
        f"{_label(path)}:{lineno} -> {module}"
        for path in _modules(POCKETSEC_ROOT)
        if not _is_harness(_rel(path))
        for module, lineno in _resolved(path)
        if _imports_harness(module)
    ]
    assert not offenders, f"modules importing the Stage 6 harness: {offenders}"
    assert _is_harness(("stage6", "gate.py")) and not _is_harness(("stage6", "labs", "gate.py"))
    assert _imports_harness("pocketsec.stage6.gate") and not _imports_harness(
        "pocketsec.stage6.labs.endurance")


# --- rule 7 ------------------------------------------------------------------


def test_no_stage6_dataclass_field_carries_an_authority_word() -> None:
    """T5, with no exemption list: ``fraction``, ``transaction``, ``compaction`` all fail."""
    offenders = [
        f"{_label(path)}:{lineno} {field}"
        for path in _modules(STAGE6_ROOT)
        for field, lineno in _t5_offenders(path)
    ]
    assert not offenders, f"authority-named dataclass fields under stage6/: {offenders}"


# --- rule 8 ------------------------------------------------------------------


def test_no_earlier_stage_depends_on_stage6() -> None:
    offenders = [
        f"{_label(path)}:{lineno} -> {module}"
        for stage in range(6)
        for path in _modules(POCKETSEC_ROOT / f"stage{stage}")
        for module, lineno in _resolved(path)
        if module == "pocketsec.stage6" or module.startswith("pocketsec.stage6.")
    ]
    assert not offenders, f"Stages 0-5 importing Stage 6: {offenders}"


# --- rule 9 ------------------------------------------------------------------


@pytest.mark.parametrize("name", FORBIDDEN_STAGE6_DIRECTORIES)
def test_stage6_holds_no_second_contracts_harness_or_ledger_directory(name: str) -> None:
    found = [_label(p) for p in STAGE6_ROOT.rglob(name) if p.is_dir()]
    assert not found, f"forbidden directories under stage6/: {found}"


def test_stage6_defines_no_second_harness_ledger_or_corpus_type() -> None:
    offenders = [
        f"{_label(path)}:{lineno} {name}"
        for path in _modules(STAGE6_ROOT)
        for name, lineno in _defined_names(path)
        if name in FORBIDDEN_DEFINITIONS
    ]
    assert not offenders, f"Stage 6 redefines a Stage 0/1 type: {offenders}"


# --- rule 10 -----------------------------------------------------------------


@pytest.mark.parametrize("name", DELETED_STAGE6_DIRECTORIES)
def test_the_deleted_empty_directories_do_not_return(name: str) -> None:
    assert not (STAGE6_ROOT / name).exists(), f"pocketsec/stage6/{name}/ came back (ADR-0121)"


def test_no_stage6_package_is_empty_and_no_directory_is_an_orphan() -> None:
    """ADR-0121: a package exports a public class or function, or it does not exist."""
    packages = sorted(p.parent for p in STAGE6_ROOT.rglob("__init__.py"))
    assert packages, "no Stage 6 package has an __init__.py; this rule would pass vacuously"
    empty = [
        _label(directory)
        for directory in packages
        if not [
            name
            for path in _modules(directory)
            if path.name != "__init__.py"
            for name, _ in _defined_names(path)
            if not name.startswith("_")
        ]
    ]
    assert not empty, f"Stage 6 packages exporting nothing: {empty}"
    orphans = [
        _label(directory)
        for directory in sorted(STAGE6_ROOT.rglob("*"))
        if directory.is_dir()
        and directory.name != "__pycache__"
        and not (directory / "__init__.py").exists()
        and not (directory.name in PENDING_EMPTY_DIRECTORIES and not any(directory.iterdir()))
    ]
    assert not orphans, f"directories under stage6/ that are not packages: {orphans}"


# --- rule 11 -----------------------------------------------------------------


def test_stage6_defines_no_second_epoch_or_delay_gate() -> None:
    """ADR-0051: Stage 6 composes Stage 2's buffer and controller; it does not rebuild them."""
    offenders = [
        f"{_label(path)}:{lineno} {name}"
        for path in _modules(STAGE6_ROOT)
        for name, lineno in _second_gate_parameters(path)
    ]
    assert not offenders, f"a second Stage 2 gate under stage6/: {offenders}"


# --- the committed negative fixtures -----------------------------------------

#: The relative imports that were invisible to two checkers at once (S2-AUTH-01), plus
#: one absolute third-party import. ``(package the file sits in, source, rule)``.
BOUNDARY_VIOLATIONS = (
    (("pocketsec", "stage6"), "from ..stage2.research import x", "research"),
    (("pocketsec", "stage6"), "from ..stage2.research import x", "allow_list"),
    (("pocketsec", "stage6"), "from . import research", "research"),
    (("pocketsec", "stage6", "capsule"), "from ..research import solver", "research"),
    (("pocketsec", "stage6", "memory"), "from ...stage3.cells import schema", "allow_list"),
    (("pocketsec", "stage6", "memory"), "from ...stage5.executor import journal", "allow_list"),
    (("pocketsec", "stage6", "shadow"), "from ...stage7 import hivelock", "allow_list"),
    (("pocketsec", "stage6", "memory"), "from ..labs import endurance", "labs"),
    (("pocketsec", "stage6", "promotion"), "from ..labs.poison_suite import arm", "labs"),
    (("pocketsec", "stage6", "chamber"), "import numpy", "third_party"),
)


@pytest.mark.parametrize(("where", "source", "rule"), BOUNDARY_VIOLATIONS)
def test_a_boundary_violation_is_caught_whatever_its_import_form(
    where: tuple[str, ...], source: str, rule: str, tmp_path: Path
) -> None:
    """The fixture file sits at a real position in a ``pocketsec`` tree, so each relative
    level resolves as it would in the package; then the rules' own predicates judge it."""
    package = tmp_path.joinpath(*where)
    package.mkdir(parents=True)
    offender = package / "leak.py"
    offender.write_text(source + "\n", encoding="utf-8")
    resolved = [module for module, _ in _resolved(offender)]
    assert resolved, f"{source} resolved to no module at all"
    rel = _rel(offender)
    if rule == "research":
        assert all(_is_research(module) for module in resolved), resolved
    elif rule == "allow_list":
        assert all(_allow_list_violation(module, rel) for module in resolved), resolved
    elif rule == "labs":
        assert rel[1] != "labs" and all(_imports_labs(module) for module in resolved), resolved
    else:
        stdlib = set(sys.stdlib_module_names) | {"pocketsec"}
        assert all(module.split(".")[0] not in stdlib for module in resolved), resolved


def test_the_negative_fixture_covers_every_form_named_by_the_spec() -> None:
    sources = {source for _, source, _ in BOUNDARY_VIOLATIONS}
    assert {
        "from ..stage2.research import x",
        "from . import research",
        "from ...stage3.cells import schema",
        "from ..labs import endurance",
    } <= sources
    assert {rule for _, _, rule in BOUNDARY_VIOLATIONS} == {
        "research",
        "allow_list",
        "labs",
        "third_party",
    }


def _write(tmp_path: Path, where: tuple[str, ...], source: str) -> Path:
    package = tmp_path.joinpath("pocketsec", *where[:-1])
    package.mkdir(parents=True, exist_ok=True)
    path = package / where[-1]
    path.write_text(source, encoding="utf-8")
    return path


def test_the_single_writer_rule_catches_every_way_to_name_the_installer(tmp_path: Path) -> None:
    offender = _write(
        tmp_path,
        ("stage6", "chamber", "evolution.py"),
        "from pocketsec.stage6.promotion.controller import TrustedMind as Mind\n"
        "def sneak(controller, state):\n"
        "    controller._install_trusted(state)\n"
        "    getattr(controller, '_trusted_state')\n"
        "    return TrustedMind(state)\n",
    )
    hits = {hit for hit, _ in _sealed_hits(offender)}
    assert {"_install_trusted", "_trusted_state", "TrustedMind(...)"} <= hits, hits
    assert "TrustedMind imported under an alias" in hits
    owner = _write(tmp_path, WRITER_FILE, "def _install_trusted(self):\n    return TrustedMind()\n")
    assert all(_owner_of(hit) == _rel(owner) for hit, _ in _sealed_hits(owner))


def test_the_gateway_seal_catches_a_forged_verdict_minter(tmp_path: Path) -> None:
    offender = _write(
        tmp_path,
        ("stage6", "chamber", "evolution.py"),
        "def forge(gateway):\n    gateway._issued_verdicts.add('v-1')\n",
    )
    hits = [(hit, SEALED_NAMES[hit]) for hit, _ in _sealed_hits(offender)]
    assert hits == [("_issued_verdicts", ("stage6", "capsule", "quarantine.py"))]
    assert _rel(offender) != SEALED_NAMES["_issued_verdicts"]


def test_the_t5_screen_bites_on_words_nobody_reads_as_authority(tmp_path: Path) -> None:
    offender = _write(
        tmp_path,
        ("stage6", "memory", "stats.py"),
        "from dataclasses import dataclass\nimport dataclasses\nfrom enum import StrEnum\n"
        "@dataclass(frozen=True, slots=True)\n"
        "class Stats:\n    retained_fraction: float\n    transaction_id: str\n    ok: bool\n"
        "@dataclasses.dataclass\n"
        "class Compaction:\n    compaction_bytes: int\n    was_blocked: bool\n"
        "class LifecycleState(StrEnum):\n    QUARANTINED = 'QUARANTINED'\n"
        "class NotADataclass:\n    action: str\n",
    )
    assert {field for field, _ in _t5_offenders(offender)} == {
        "Stats.retained_fraction",
        "Stats.transaction_id",
        "Compaction.compaction_bytes",
        "Compaction.was_blocked",
    }


def test_the_second_gate_rule_catches_every_parameter_position(tmp_path: Path) -> None:
    offender = _write(
        tmp_path,
        ("stage6", "capsule", "quarantine.py"),
        "def a(min_epochs): ...\n"
        "def b(*, delay_sequences=64): ...\n"
        "def ok(buffer):\n    return buffer(min_epochs=2)\n",
    )
    assert sorted(name for name, _ in _second_gate_parameters(offender)) == [
        "delay_sequences",
        "min_epochs",
    ]


def test_each_owner_declares_exactly_the_sealed_names_this_file_assigns_it() -> None:
    """The gate scans for sealed names by reading each owner's ``SEALED_NAMES`` (so the gate
    never spells them). That declaration must agree with this file's table, or the gate and
    this test would be enforcing two different seals."""
    from pocketsec.stage6.capsule import quarantine
    from pocketsec.stage6.chamber import evolution
    from pocketsec.stage6.promotion import controller

    declared = {
        name: ("stage6", *Path(module.__file__).parts[-2:])
        for module in (controller, quarantine, evolution)
        for name in module.SEALED_NAMES
    }
    assert declared == SEALED_NAMES
