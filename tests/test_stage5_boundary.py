"""Stage 5's dependency-boundary check (ADR-0001, ADR-0040, ADR-0045, ADR-0121, T1, T4).

``tests/test_repository_structure.py`` implements these rules for Stages 0-2 and
hard-codes ``pocketsec/stage2/research/``. Widening those literals is an edit to a
file another wave may be editing, so Stage 5 gets its own copy of the *technique*
here and **leaves that file untouched**. ``tests/test_stage3_boundary.py`` and
``tests/test_stage4_boundary.py`` did the same for their stages; this is the
Stage 5 sibling, and it matters more than either: Stage 5 is the only stage that
touches privilege, so its import graph is a security boundary rather than a
tidiness preference.

The nine rules of spec §5.1:

1. **R1 / ADR-0001.** Every module under ``pocketsec/stage5/`` imports only roots
   in ``sys.stdlib_module_names`` or ``pocketsec``.
2. **R2 / ADR-0008 + ADR-0040.** No module imports any ``pocketsec.stage*.research*``
   and ``pocketsec/stage5/research/`` does not exist — permanently, because a
   numpy import here is a supply-chain path into the executor.
3. **T1 / ADR-0045.** The only ``pocketsec.stage4.*`` module imported anywhere is
   ``pocketsec.stage4.stage5_interface``; no ``pocketsec.stage2.*``; no
   ``pocketsec.stage6``…``stage12``; nothing under ``stage3`` except
   ``stage3.cells`` and ``stage3.bytecode``.
4. **T4.** ``get_type_hints(TransactionalExecutor.execute)["operator"]`` is exactly
   ``DefensiveOperator``, and only ``executor/``, ``recovery/`` and the single file
   ``gate.py`` import the executor (ADR-0041: spec G5.2(a) requires the gate to read
   the executor's type hints, which §5.1 rule 4 as written forbade). Nothing but
   ``cli.py`` and the ``gate_*`` modules may import ``gate.py``, so the permission
   cannot leak into runtime.
5. **P2 / no-shell.** ``no_arbitrary_command_path(stage5) == ()``.
6. **§35 — the planner is unprivileged.** Nothing under ``aegis/``, ``safe/``,
   ``twin/`` or ``cells/`` imports ``authority.tokens``, ``executor.transactional``,
   ``executor.journal`` or the name ``SimulatedHost``.
7. **SENTINEL is independent.** Nothing under ``sentinel/`` imports ``aegis/``,
   ``safe/``, ``twin/``, ``memory/`` or ``cells/``, and ``sentinel/`` defines no
   name matching ``force|override|bypass|skip|disable|dry_run|unsafe|trust_me``.
8. **No second contracts package, ledger or harness.**
9. **No empty package (ADR-0121)**, and ``pocketsec/stage5/response/`` does not exist.

Every check walks the AST, never the text: several Stage 5 modules *name* the
boundary in a docstring, and naming it is not crossing it.

The import resolver is **imported**, not copied. S2-AUTH-01 was a hole that existed
in the structural tests and in the G2.13 seam check at once, and two copies is
exactly how it got closed in neither. A test may import Stage 2 for it; runtime
may not, which rule 3 enforces.

**Rules 4 and 5 depend on modules other work packages own.** Where the subject
does not exist yet the rule skips with the module name in the reason — never
``xfail``, never a bare pass. The guard is a module-existence check, so the rule
becomes a hard assertion the moment the module lands, and ``pocketsec-stage5 gate``
re-checks all nine unconditionally.
"""

from __future__ import annotations

import ast
import re
import sys
from importlib.util import find_spec
from pathlib import Path

import pytest

from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage2.gate_criteria import imported_modules

STAGE5_ROOT = REPO_ROOT / "pocketsec" / "stage5"

#: Directories the Stage 5 layout (spec §2.1) excludes by name. ``research`` is
#: ADR-0040 and is permanent. ``contracts``/``benchmark``/``experiments`` would be
#: a second contract registry, a second measurement harness and a second
#: experiment ledger; Stage 5 uses Stage 0's. ``response`` existed empty on disk
#: before this wave: importable by accident as a namespace package, invisible to
#: every structural test, and named after a component the layout puts elsewhere.
FORBIDDEN_STAGE5_DIRECTORIES = ("research", "contracts", "benchmark", "experiments", "response")

#: The one Stage 4 module Stage 5 may import (spec §2.5, ADR-0045).
PERMITTED_STAGE4_MODULE = "pocketsec.stage4.stage5_interface"

#: The only Stage 3 subpackages Stage 5 may import (trust rule T1).
PERMITTED_STAGE3_PREFIXES = ("pocketsec.stage3.cells", "pocketsec.stage3.bytecode")

#: Stages Stage 5 may not import at all: Stage 2 is rejected machinery behind a
#: research boundary, and Stages 6-12 are downstream of Stage 5 by construction.
FORBIDDEN_STAGES = (
    "stage2",
    "stage6",
    "stage7",
    "stage8",
    "stage9",
    "stage10",
    "stage11",
    "stage12",
)

#: Packages that plan but must never be able to act (§35).
UNPRIVILEGED_PACKAGES = ("aegis", "safe", "twin", "cells")

#: Modules and names a planning package may not touch. ``HostSnapshot`` and the
#: row types are deliberately absent: they are read-only data, and a planner that
#: cannot see host state cannot plan.
PRIVILEGED_IMPORTS = (
    "pocketsec.stage5.authority.tokens",
    "pocketsec.stage5.executor.transactional",
    "pocketsec.stage5.executor.journal",
)

#: Packages SENTINEL may not import. A verifier that shares state or a code path
#: with the thing it verifies is not independent (§4).
SENTINEL_FORBIDDEN_PACKAGES = ("aegis", "safe", "twin", "memory", "cells")

#: Names whose existence anywhere under ``sentinel/`` would be a bypass surface.
BYPASS_NAME_RE = re.compile(r"(?i)force|override|bypass|skip|disable|dry_?run|unsafe|trust_me")

#: A second experiment ledger or benchmark harness, by name.
FORBIDDEN_SYMBOLS = ("run_benchmark", "ExperimentRegistry")


def _modules(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _resolved(path: Path) -> list[tuple[str, int]]:
    """Every module the file imports, as an ABSOLUTE dotted path, with its line."""
    return [
        (module, node.lineno)
        for node in ast.walk(_parse(path))
        for module in imported_modules(node, path)
    ]


def _label(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _module_exists(dotted: str) -> bool:
    """Whether a module another work package owns has landed yet."""
    try:
        return find_spec(dotted) is not None
    except (ImportError, ValueError):
        return False


def _requires(dotted: str, owner: str) -> None:
    """Skip a rule whose *subject* another work package has not finished.

    Two distinct situations, both reported rather than passed:

    * the module does not exist yet — the rule has nothing to check;
    * the module exists but raises on import — the rule cannot be evaluated, and
      the exception text goes in the skip reason.

    A skip here is **not** a pass. ``pocketsec-stage5 gate`` re-checks all nine
    rules unconditionally on the assembled stage, so a Stage 5 that does not
    import is a failed gate whatever this file says. The guard exists because
    packages build in parallel, not to make a rule optional.
    """
    if not _module_exists(dotted):
        pytest.skip(f"{dotted} ({owner}) does not exist yet")
    try:
        __import__(dotted)
    except Exception as exc:
        pytest.skip(f"{dotted} ({owner}) does not import yet: {type(exc).__name__}: {exc}")


def _imports_the_executor(path: Path) -> list[int]:
    """Lines where this file imports the name ``TransactionalExecutor``.

    The rule is about the *name* (spec §5.1 rule 4), so importing
    ``TransactionReceipt`` from the same module is not a violation: a receipt is a
    record, and reading one confers nothing.
    """
    lines: list[int] = []
    for node in ast.walk(_parse(path)):
        modules = imported_modules(node, path)
        if "pocketsec.stage5.executor.transactional" not in modules:
            continue
        if isinstance(node, ast.Import) or (isinstance(node, ast.ImportFrom) and any(
            alias.name == "TransactionalExecutor" for alias in node.names
        )):
            lines.append(node.lineno)
    return lines


def _is_research(module: str) -> bool:
    parts = module.split(".")
    return len(parts) >= 3 and parts[0] == "pocketsec" and parts[2] == "research"


def _crosses_t1(module: str) -> bool:
    """Whether this import breaks trust rule T1 as spec §2.5 narrows it."""
    if module == "pocketsec.stage4" or module.startswith("pocketsec.stage4."):
        return module != PERMITTED_STAGE4_MODULE and not module.startswith(
            PERMITTED_STAGE4_MODULE + "."
        )
    if module == "pocketsec.stage3" or module.startswith("pocketsec.stage3."):
        return not module.startswith(PERMITTED_STAGE3_PREFIXES)
    return any(
        module == f"pocketsec.{stage}" or module.startswith(f"pocketsec.{stage}.")
        for stage in FORBIDDEN_STAGES
    )


def _defined_names(path: Path) -> list[tuple[str, int]]:
    """Every module-level and class-level name this file defines."""
    found: list[tuple[str, int]] = []
    for node in ast.walk(_parse(path)):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            found.append((node.name, node.lineno))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            found.append((node.target.id, node.lineno))
        elif isinstance(node, ast.Assign):
            found.extend(
                (target.id, node.lineno) for target in node.targets if isinstance(target, ast.Name)
            )
    return found


def test_stage5_has_modules_at_all() -> None:
    """Guard against every rule below passing vacuously on an empty package."""
    assert _modules(STAGE5_ROOT), "pocketsec/stage5/ holds no Python modules"


# --- rule 1 ------------------------------------------------------------------


def test_stage5_has_no_third_party_imports() -> None:
    """ADR-0001: the endpoint runtime depends on the stdlib alone.

    Stage 5 is where this stops being about install footprint. The executor's
    trusted computing base is small precisely because nothing outside the stdlib
    is in it, and the AST walk sees a deferred import inside a function exactly as
    it sees a module-scope one.
    """
    allowed = set(sys.stdlib_module_names) | {"pocketsec"}
    offenders: dict[str, set[str]] = {}
    for path in _modules(STAGE5_ROOT):
        external = {module.split(".")[0] for module, _ in _resolved(path)} - allowed
        if external:
            offenders[_label(path)] = external
    assert not offenders, f"third-party imports in Stage 5: {offenders}"


# --- rule 2 ------------------------------------------------------------------


def test_stage5_never_imports_research_code() -> None:
    """ADR-0040: Stage 5 ships no research package and reaches no other stage's.

    Written against ``pocketsec.stage<N>.research`` rather than Stage 2's literal
    path, so a Stage 5 module cannot reach numpy through a future stage's research
    package either.
    """
    offenders = [
        f"{_label(path)}:{lineno} -> {module}"
        for path in _modules(STAGE5_ROOT)
        for module, lineno in _resolved(path)
        if _is_research(module)
    ]
    assert not offenders, f"Stage 5 modules importing research code: {offenders}"


# --- rule 3 ------------------------------------------------------------------


def test_stage5_imports_stage4_through_exactly_one_module() -> None:
    """T1 / ADR-0045 / spec §2.5.

    ``CBFResolutionV1.to_dict()`` performs Stage 4's own refusals — laundered
    claim kinds, dangling citations, class-name leakage — so consuming the typed
    objects directly would route around checks Stage 4 built for Stage 5's
    benefit. And another wave is building Stage 4 in this tree right now: eleven
    module imports would be eleven chances to be broken mid-build.
    """
    offenders = [
        f"{_label(path)}:{lineno} -> {module}"
        for path in _modules(STAGE5_ROOT)
        for module, lineno in _resolved(path)
        if _crosses_t1(module)
    ]
    assert not offenders, f"Stage 5 modules crossing the T1 import boundary: {offenders}"


# --- rule 4 ------------------------------------------------------------------


def test_the_executor_entry_point_accepts_exactly_defensive_operator() -> None:
    """T4 / property P1: one type reaches privilege, and it is not a union.

    ``str``, ``object``, ``Any``, ``DefensiveOperator | Mapping`` and a string
    annotation that never resolves are all failures. This is the assertion that
    makes "only typed operators reach privilege" a fact about the signature rather
    than a claim in a docstring.
    """
    _requires("pocketsec.stage5.executor.transactional", "package 4")
    _requires("pocketsec.stage5.operators.algebra", "package 2")
    from typing import get_type_hints

    from pocketsec.stage5.executor.transactional import TransactionalExecutor
    from pocketsec.stage5.operators.algebra import DefensiveOperator

    hints = get_type_hints(TransactionalExecutor.execute)
    assert hints["operator"] is DefensiveOperator, hints["operator"]


#: The one file outside ``executor/`` and ``recovery/`` that may name the executor.
#: ADR-0041: spec G5.2(a) makes the gate read ``get_type_hints(TransactionalExecutor
#: .execute)``, so rule 4 as first written made the stage's own gate unbuildable. The
#: exemption is a single *file*, not a directory, and ``labs/`` stays forbidden — the
#: labs are handed executors through factories and cannot assemble one.
GATE_MODULE = STAGE5_ROOT / "gate.py"

#: Modules that may import ``pocketsec.stage5.gate``. The gate's factories are the
#: only executor constructors outside the two privileged directories, so the gate
#: itself must not become a library the runtime can reach.
GATE_IMPORTERS = frozenset({"cli.py"})


def test_only_the_executor_and_recovery_import_the_executor() -> None:
    """T4's second half: the privileged class is not reachable from planning code.

    Scanned by file position rather than by import graph, so it holds before the
    executor exists and does not depend on any module importing cleanly.
    """
    permitted = (STAGE5_ROOT / "executor", STAGE5_ROOT / "recovery")
    offenders = [
        f"{_label(path)}:{lineno}"
        for path in _modules(STAGE5_ROOT)
        if not any(parent in path.parents for parent in permitted) and path != GATE_MODULE
        for lineno in _imports_the_executor(path)
    ]
    assert not offenders, (
        "spec §5.1 rule 4 (as amended by ADR-0041) permits TransactionalExecutor imports "
        f"under executor/, recovery/ and the single file gate.py only; found {offenders}"
    )


def test_the_executor_exemption_is_one_file_and_it_is_not_a_library() -> None:
    """The compensating half of ADR-0041's amendment to rule 4.

    Nothing under ``pocketsec/stage5/`` imports ``pocketsec.stage5.gate`` except
    ``cli.py`` and the ``gate_*`` check modules, which may import it only inside a
    function (they are imported *by* it, so a module-level import would be a cycle,
    and a function-level one keeps the dependency visible to this scan).
    """
    offenders: list[str] = []
    for path in _modules(STAGE5_ROOT):
        if path == GATE_MODULE:
            continue
        for module, lineno in _resolved(path):
            if module != "pocketsec.stage5.gate":
                continue
            if path.name in GATE_IMPORTERS and path.parent == STAGE5_ROOT:
                continue
            if path.name.startswith("gate_") and path.parent == STAGE5_ROOT:
                continue
            offenders.append(f"{_label(path)}:{lineno}")
    assert not offenders, f"only cli.py and gate_*.py may import the gate; found {offenders}"


# --- rule 5 ------------------------------------------------------------------


def test_no_arbitrary_command_path_exists_under_stage5() -> None:
    """P2: the AST proof that no natural-language-to-shell path exists.

    The implementation lives in ``operators/algebra.py`` so that the gate and this
    test share one copy — two copies is how S2-AUTH-01 stayed open in neither.
    """
    _requires("pocketsec.stage5.operators.algebra", "package 2")
    from pocketsec.stage5.operators.algebra import no_arbitrary_command_path

    assert no_arbitrary_command_path(STAGE5_ROOT) == ()


#: Stdlib modules through which a string could become a process. Checked here at
#: *import* level, which is decidable without ``operators/algebra.py`` and catches
#: the most likely form of the violation before package 2 lands. The authoritative
#: proof is the test above; this is not a second implementation of it.
SHELL_CAPABLE_ROOTS = (
    "subprocess", "pty", "multiprocessing", "ctypes", "shlex",
    # Finding S5-SEC-09: os's own back ends, asyncio's create_subprocess_shell, and the
    # other foreign-function and launcher roots the list above missed.
    "posix", "nt", "_posixsubprocess", "asyncio", "cffi", "runpy", "pexpect",
)


def test_no_stage5_module_imports_a_shell_capable_module() -> None:
    """The import-level half of P2, which can run today."""
    offenders = [
        f"{_label(path)}:{lineno} -> {module}"
        for path in _modules(STAGE5_ROOT)
        for module, lineno in _resolved(path)
        if module.split(".")[0] in SHELL_CAPABLE_ROOTS
    ]
    assert not offenders, f"Stage 5 modules importing a shell-capable module: {offenders}"


# --- rule 6 ------------------------------------------------------------------


@pytest.mark.parametrize("package", UNPRIVILEGED_PACKAGES)
def test_the_planner_cannot_reach_privilege(package: str) -> None:
    """§35: AEGIS proposes; it does not mint, journal or apply.

    The planner is the part of Stage 5 an attacker can influence, through the
    evidence and the incident hypotheses it reads. Keeping the token store and the
    executor out of its import graph is what stops influence becoming privilege.
    """
    offenders = [
        f"{_label(path)}:{lineno} -> {module}"
        for path in _modules(STAGE5_ROOT / package)
        for module, lineno in _resolved(path)
        if module in PRIVILEGED_IMPORTS
    ]
    offenders += [
        f"{_label(path)}:{lineno} defines or names SimulatedHost"
        for path in _modules(STAGE5_ROOT / package)
        for name, lineno in _defined_names(path)
        if name == "SimulatedHost"
    ]
    assert not offenders, f"{package}/ reaches privilege: {offenders}"


def test_the_planner_rule_catches_its_own_violation(tmp_path: Path) -> None:
    """A rule that cannot catch its own negative fixture is enforcing nothing.

    Rule 6 scans packages that some work packages have not written yet, so without
    this the test would pass on an empty directory and look like a guarantee.
    """
    package = tmp_path.joinpath("pocketsec", "stage5", "aegis")
    package.mkdir(parents=True)
    offender = package / "planner.py"
    offender.write_text("from pocketsec.stage5.authority.tokens import TokenStore\n", "utf-8")
    assert [m for m, _ in _resolved(offender) if m in PRIVILEGED_IMPORTS]

    relative = package / "shortcut.py"
    relative.write_text("from ..authority.tokens import TokenStore\n", encoding="utf-8")
    assert [m for m, _ in _resolved(relative) if m in PRIVILEGED_IMPORTS], (
        "a relative reach into the token store must resolve to an absolute path"
    )


# --- rule 7 ------------------------------------------------------------------


def test_sentinel_imports_nothing_it_verifies() -> None:
    """§4: AEGIS cannot bypass SENTINEL, and SENTINEL shares no state with it."""
    forbidden = tuple(f"pocketsec.stage5.{name}" for name in SENTINEL_FORBIDDEN_PACKAGES)
    offenders = [
        f"{_label(path)}:{lineno} -> {module}"
        for path in _modules(STAGE5_ROOT / "sentinel")
        for module, lineno in _resolved(path)
        if module.startswith(forbidden)
    ]
    assert not offenders, f"sentinel/ imports what it verifies: {offenders}"


def test_sentinel_defines_no_bypass_name() -> None:
    """A kernel with a ``force`` kwarg or a ``dry_run`` flag is not a kernel.

    Names, from the AST, not text: a docstring that says "there is no bypass" is
    not a bypass. The regex is deliberately broad — a name that merely *sounds*
    like an escape hatch has to be renamed, because the next reader will use it.
    """
    offenders = [
        f"{_label(path)}:{lineno} {name}"
        for path in _modules(STAGE5_ROOT / "sentinel")
        for name, lineno in _defined_names(path)
        if BYPASS_NAME_RE.search(name)
    ]
    assert not offenders, f"bypass-shaped names under sentinel/: {offenders}"


def test_the_bypass_name_rule_catches_its_own_violation(tmp_path: Path) -> None:
    """The negative fixture for rule 7, for the same reason as rule 6's."""
    package = tmp_path.joinpath("pocketsec", "stage5", "sentinel")
    package.mkdir(parents=True)
    offender = package / "kernel.py"
    offender.write_text(
        "class SentinelKernel:\n"
        "    def verify(self, *, force: bool = False) -> None: ...\n"
        "DRY_RUN = True\n"
        "def _override() -> None: ...\n",
        encoding="utf-8",
    )
    caught = [name for name, _ in _defined_names(offender) if BYPASS_NAME_RE.search(name)]
    assert set(caught) == {"DRY_RUN", "_override"}, caught
    assert not BYPASS_NAME_RE.search("SentinelKernel")


# --- rule 8 ------------------------------------------------------------------


@pytest.mark.parametrize("name", FORBIDDEN_STAGE5_DIRECTORIES)
def test_stage5_does_not_hold_a_forbidden_directory(name: str) -> None:
    """``research/`` is ADR-0040; the rest would be a second Stage 0."""
    assert not (STAGE5_ROOT / name).exists(), (
        f"pocketsec/stage5/{name}/ exists; the Stage 5 layout excludes it and an empty "
        "package directory is a defect, not a placeholder (ADR-0121)"
    )


@pytest.mark.parametrize("symbol", FORBIDDEN_SYMBOLS)
def test_stage5_defines_no_second_harness_or_ledger(symbol: str) -> None:
    """One measurement path and one append-only ledger, both Stage 0's."""
    offenders = [
        f"{_label(path)}:{lineno}"
        for path in _modules(STAGE5_ROOT)
        for name, lineno in _defined_names(path)
        if name == symbol
    ]
    assert not offenders, f"Stage 5 defines its own {symbol}: {offenders}"


# --- rule 9 ------------------------------------------------------------------


def _packages() -> list[Path]:
    return sorted(
        directory
        for directory in STAGE5_ROOT.rglob("*")
        if directory.is_dir() and (directory / "__init__.py").exists()
    )


def test_no_stage5_package_is_empty() -> None:
    """ADR-0121: create the package in the same change that fills it.

    ``__init__.py`` files stay empty by convention (consumers import the leaf
    module), so the check scans the *directory* for a class or function, exactly as
    ``test_stage2_subpackage_exports_something`` does.
    """
    packages = _packages()
    assert packages, "no Stage 5 package has an __init__.py; this rule would pass vacuously"
    empty: list[str] = []
    for directory in packages:
        symbols = [
            name
            for path in _modules(directory)
            if path.name != "__init__.py"
            for name, _ in _defined_names(path)
            if not name.startswith("_")
        ]
        if not symbols:
            empty.append(_label(directory))
    assert not empty, f"Stage 5 packages exporting nothing: {empty}"


# --- the committed negative fixture for rules 1-3 and 5 ----------------------

#: A Stage 5 module reaching where it must not, the way a future author most
#: plausibly would: from inside the package, with a *relative* import. Committed
#: as a fixture rather than described, because that is exactly the shape that was
#: invisible to two checkers at once (S2-AUTH-01): ``from .research import x``
#: gives ``node.module == "research"``, which matched neither
#: ``pocketsec.stage2.research`` nor ``".research"``, and ``from . import
#: research`` gives ``node.module is None``, which the ``and node.module`` guard
#: dropped outright. CI stayed green while numpy could reach the endpoint runtime.
#:
#: Each row is ``(package the offending module sits in, the import, the rule it breaks)``.
RELATIVE_BOUNDARY_VIOLATIONS = (
    (("pocketsec", "stage5"), "from . import research", "research"),
    (("pocketsec", "stage5"), "from .research import solver", "research"),
    (("pocketsec", "stage5", "aegis"), "from ..research import solver", "research"),
    (("pocketsec", "stage5", "aegis"), "from .. import research", "research"),
    (("pocketsec", "stage5"), "from ..stage2 import gate_criteria", "t1"),
    (("pocketsec", "stage5", "safe"), "from ...stage4.worlds import world", "t1"),
    (("pocketsec", "stage5", "safe"), "from ...stage2.encoder import ssir", "t1"),
    (("pocketsec", "stage5", "aegis"), "from ...stage3.invariants import discovery", "t1"),
    (("pocketsec", "stage5", "executor"), "from ...stage6 import helios", "t1"),
    (("pocketsec", "stage5", "host"), "import subprocess", "shell"),
    (("pocketsec", "stage5", "host"), "from shlex import quote", "shell"),
)


@pytest.mark.parametrize(("where", "source", "rule"), RELATIVE_BOUNDARY_VIOLATIONS)
def test_a_relative_boundary_violation_is_resolved_to_an_absolute_path(
    where: tuple[str, ...], source: str, rule: str, tmp_path: Path
) -> None:
    """Every rule above must see a relative import, not skip it.

    The offending file is written at a real position inside a ``pocketsec`` tree so
    the relative level resolves the way it would in the package itself, then the
    *same* predicates the rules use are applied to it.
    """
    package = tmp_path.joinpath(*where)
    package.mkdir(parents=True)
    offender = package / "leak.py"
    offender.write_text(source + "\n", encoding="utf-8")

    resolved = [module for module, _ in _resolved(offender)]
    assert resolved, f"{source} resolved to no module at all"

    if rule == "research":
        assert all(_is_research(module) for module in resolved), resolved
        assert all(module.split(".")[0] == "pocketsec" for module in resolved), resolved
    elif rule == "t1":
        assert all(_crosses_t1(module) for module in resolved), resolved
    else:
        assert all(module.split(".")[0] in SHELL_CAPABLE_ROOTS for module in resolved), resolved


def test_the_negative_fixture_covers_every_import_form_and_rule() -> None:
    """The fixture is only as good as its coverage, so the coverage is asserted."""
    sources = [source for _, source, _ in RELATIVE_BOUNDARY_VIOLATIONS]
    assert any(s.startswith("from . import ") for s in sources)
    assert any(s.startswith("from .. import ") for s in sources)
    assert any(s.startswith("from .research") for s in sources)
    assert any(s.startswith("from ...") for s in sources)
    assert any(s.startswith("import ") for s in sources)
    assert {rule for _, _, rule in RELATIVE_BOUNDARY_VIOLATIONS} == {"research", "t1", "shell"}


def test_the_t1_predicate_permits_exactly_the_two_seams_it_must() -> None:
    """The permitted half of T1, asserted so the rule cannot be vacuously strict.

    A predicate that refused *everything* would pass every test above while making
    the Stage 4 seam and the Stage 3 cell reuse impossible. Both directions are
    the rule.
    """
    assert not _crosses_t1(PERMITTED_STAGE4_MODULE)
    assert not _crosses_t1("pocketsec.stage3.cells.schema")
    assert not _crosses_t1("pocketsec.stage3.bytecode.isa")
    assert not _crosses_t1("pocketsec.stage0.contracts.common")
    assert not _crosses_t1("pocketsec.stage1.state.potential")
    assert not _crosses_t1("pocketsec.stage5.operators.catalog")
    assert _crosses_t1("pocketsec.stage4")
    assert _crosses_t1("pocketsec.stage4.worlds.world")
    assert _crosses_t1("pocketsec.stage3")
    assert _crosses_t1("pocketsec.stage3.invariants.discovery")
    assert _crosses_t1("pocketsec.stage2.gate_criteria")
    assert _crosses_t1("pocketsec.stage12.constellation")


#: Modules the privileged half must never have loaded: the gate apparatus and the D3FEND
#: adapter. ``d3fend.py`` imports ``stage0.gate`` for its snapshot path.
PRIVILEGED_PROCESS_FORBIDDEN = (
    "pocketsec.stage0.gate",
    "pocketsec.stage0.experiments.registry",
    "pocketsec.stage0.prior_art",
    "pocketsec.stage5.operators.d3fend",
)


def test_the_privileged_import_graph_loads_no_gate_and_no_d3fend_adapter() -> None:
    """Finding S5-SEC-11, measured in a fresh interpreter rather than read off the AST.

    ``OperatorSpec.__post_init__`` imported ``operators/d3fend`` for two names, and that
    module imports ``stage0.gate``, so importing the executor, SENTINEL and the catalog
    loaded the experiment registry and the prior-art ledger into the privileged process.
    The AST test above excluded ``operators/`` and could not see it.
    """
    import subprocess

    probe = (
        "import sys\n"
        "import pocketsec.stage5.executor.transactional\n"
        "import pocketsec.stage5.sentinel.kernel\n"
        "from pocketsec.stage5.operators.catalog import CATALOG\n"
        "from pocketsec.stage5.labs.adversarial_load import build_operator\n"
        "build_operator('SUSPEND_PROCESS')\n"
        f"print(sorted(m for m in {PRIVILEGED_PROCESS_FORBIDDEN!r} if m in sys.modules))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], cwd=REPO_ROOT, capture_output=True, text=True,
        timeout=120, check=True, env={"PYTHONPATH": str(REPO_ROOT), "PYTHONHASHSEED": "0"},
    )
    assert result.stdout.strip() == "[]", result.stdout + result.stderr


def _token_store_keys(root: Path) -> list[str]:
    """Every ``TokenStore(key=...)`` under ``root`` whose key is not drawn from ``secrets``."""
    rows: list[str] = []
    for path in sorted(root.rglob("*.py")):
        for node in ast.walk(_parse(path)):
            if not (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "TokenStore"):
                continue
            for keyword in node.keywords:
                if keyword.arg != "key":
                    continue
                value = keyword.value
                drawn = (isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)
                         and ast.unparse(value.func) == "secrets.token_bytes")
                passed_in = isinstance(value, ast.Name)
                if not (drawn or passed_in):
                    rows.append(f"{path.name}:{node.lineno}: key={ast.unparse(value)}")
    return rows


def test_no_token_store_key_is_a_constant_or_derived_from_public_data(tmp_path: Path) -> None:
    """Finding S5-SEC-12: a key-shaped constant and a key hashed from a public fault profile.

    ``labs/toctou.py`` states the policy — "there is no key constant in this repository" —
    and two Stage 5 modules broke it. Every store is now keyed by ``secrets.token_bytes`` or
    by a key its caller passes in; a planted constant and a planted derived key are caught.
    """
    assert _token_store_keys(STAGE5_ROOT) == []
    planted = tmp_path / "planted.py"
    planted.write_text(
        "a = TokenStore(key=b'fixture-key-0123456789ab', signer='s', clock=c)\n"
        "b = TokenStore(key=digest_of_bytes(repr(f).encode()).encode(), signer='s', clock=c)\n",
        encoding="utf-8",
    )
    assert len(_token_store_keys(tmp_path)) == 2
