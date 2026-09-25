"""Stage 3's dependency-boundary check (ADR-0001, ADR-0008, ADR-0020, ADR-0121).

``tests/test_repository_structure.py`` implements these rules for Stages 0-2 and
hard-codes ``pocketsec/stage2/research/`` in two places. Widening those literals
is an edit to a file another wave may be editing, so Stage 3 gets its own copy of
the technique here and leaves that file untouched.

The rules below are what make ADR-0020 ("Stage 3 ships no ``research/`` package
and no numpy") enforceable rather than aspirational. Under
``test_repository_structure.py``'s current literals, a ``pocketsec/stage3/research/``
directory would be classified as *runtime*, so a numpy import inside it would
already fail — but only by accident of a hard-coded prefix. Rule 3 states the
decision explicitly so it survives the day that prefix is widened.

Every check uses ``ast``, not text search: a docstring that *names* the boundary
is not a crossing of it, and several modules in this package name it deliberately.
"""

from __future__ import annotations

import ast
import builtins
import sys
from pathlib import Path

import pytest

from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS
from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage2.gate_criteria import imported_modules

STAGE3_ROOT = REPO_ROOT / "pocketsec" / "stage3"

#: Directories under ``pocketsec/stage3/`` that the integration plan's layout
#: (§1.2) assigns to a work package. ``compiler/`` is deliberately absent: the
#: layout gives compilation to ``synthesis/``, and the empty ``compiler/``
#: directory that predates this wave is the ADR-0121 anti-pattern.
FORBIDDEN_STAGE3_DIRECTORIES = ("research", "compiler")


def _stage3_modules() -> list[Path]:
    if not STAGE3_ROOT.is_dir():  # pragma: no cover - the package is the subject
        return []
    return sorted(
        path
        for path in STAGE3_ROOT.rglob("*.py")
        if "__pycache__" not in path.parts
    )


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imported_roots(tree: ast.Module, path: Path) -> set[str]:
    """Root package of every import, relative ones resolved to absolute first.

    `node.level == 0` used to filter relative imports out entirely, so a
    relative reach out of Stage 3 contributed no root at all (S2-AUTH-01). The
    resolver is imported rather than copied, so the repair cannot be applied in
    one checker and missed in another.
    """
    roots: set[str] = set()
    for node in ast.walk(tree):
        roots.update(module.split(".")[0] for module in imported_modules(node, path))
    return roots


def _imported_modules(tree: ast.Module, path: Path) -> list[tuple[str, int]]:
    """Every imported module as an ABSOLUTE dotted path, with its line number."""
    modules: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        modules.extend(
            (module, node.lineno) for module in imported_modules(node, path)
        )
    return modules


def test_stage3_has_modules_at_all() -> None:
    """Guard against every rule below passing vacuously on an empty package."""
    assert _stage3_modules(), "pocketsec/stage3/ holds no Python modules"


def test_stage3_has_no_third_party_imports() -> None:
    """ADR-0001: the endpoint runtime depends on the stdlib alone."""
    allowed = set(sys.stdlib_module_names) | {"pocketsec"}
    offenders: dict[str, set[str]] = {}
    for path in _stage3_modules():
        external = _imported_roots(_parse(path), path) - allowed
        if external:
            offenders[str(path.relative_to(REPO_ROOT))] = external
    assert not offenders, f"third-party imports in Stage 3: {offenders}"


def test_stage3_never_imports_research_code() -> None:
    """ADR-0008: the research boundary is one-directional, for every stage.

    Written against ``pocketsec.stage<N>.research`` rather than Stage 2's literal
    path, so a Stage 3 module cannot reach numpy through a *future* stage's
    research package either.
    """
    offenders: list[str] = []
    for path in _stage3_modules():
        for module, lineno in _imported_modules(_parse(path), path):
            parts = module.split(".")
            if len(parts) >= 3 and parts[0] == "pocketsec" and parts[2] == "research":
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{lineno} -> {module}")
    assert not offenders, f"Stage 3 modules importing research code: {offenders}"


@pytest.mark.parametrize("name", FORBIDDEN_STAGE3_DIRECTORIES)
def test_stage3_does_not_hold_a_forbidden_directory(name: str) -> None:
    """``research/`` is ADR-0020; ``compiler/`` is not in the layout (ADR-0121)."""
    assert not (STAGE3_ROOT / name).exists(), (
        f"pocketsec/stage3/{name}/ exists; it is excluded by the Stage 3 layout "
        "and an empty package directory is a defect"
    )


def test_every_stage3_package_exports_something() -> None:
    """An empty package is a defect, not a placeholder (ADR-0121).

    The check scans the package *directory*, not ``__init__.py``: the integration
    plan requires those to stay empty and consumers to import the leaf module.
    What must not exist is a package directory with no class or function in it.
    """
    empty: list[str] = []
    for directory in sorted(STAGE3_ROOT.iterdir()):
        if not directory.is_dir() or directory.name.startswith("__"):
            continue
        symbols = [
            node.name
            for path in sorted(directory.rglob("*.py"))
            if "__pycache__" not in path.parts
            for node in _parse(path).body
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            and not node.name.startswith("_")
        ]
        if not symbols:
            empty.append(str(directory.relative_to(REPO_ROOT)))
    assert not empty, f"Stage 3 package directories exporting no class or function: {empty}"


def test_no_stage3_directory_is_an_orphan() -> None:
    """A directory under Stage 3 is either a package or absent (ADR-0121).

    A directory with no ``__init__.py`` is importable by accident under namespace
    packages, invisible to structural tests, and a standing invitation to put
    code in the wrong place.
    """
    orphans = [
        str(path.relative_to(REPO_ROOT))
        for path in sorted(STAGE3_ROOT.iterdir())
        if path.is_dir() and not path.name.startswith("__") and not (path / "__init__.py").exists()
    ]
    assert not orphans, f"directories under stage3 that are not packages: {orphans}"


def test_stage3_has_exactly_one_cell_frame_type_and_one_frame_digest() -> None:
    """A second ``CellFrame`` is a second wire format wearing the same name.

    ``frame_digest`` is the join key between a ``CellFrame`` and the frozen
    ``TeacherSnapshotV1`` (Oracle A, D3.8). Two implementations that disagree do
    not fail loudly — every ``TeacherOracle.consult`` misses, returns ``None``,
    and the dual oracle reports ``TEACHER_UNAVAILABLE``, so G3.5 silently
    becomes unmeasurable rather than failing.

    The canonical home is ``cells/frame.py`` and cannot be ``bytecode/vm.py``:
    ``cells/boundary.py`` needs ``CellFrame`` for ``contains``, and the work
    package order (spec §5) has ``bytecode`` depending on ``foundation``, not the
    reverse. So ``bytecode/vm.py`` and ``oracles/teacher.py`` must import and
    re-export these, not redefine them.
    """
    from pocketsec.stage3.bytecode import vm
    from pocketsec.stage3.cells import frame as canonical
    from pocketsec.stage3.oracles import teacher

    assert vm.CellFrame is canonical.CellFrame, (
        "pocketsec/stage3/bytecode/vm.py defines its own CellFrame instead of "
        "re-exporting pocketsec.stage3.cells.frame.CellFrame; two dataclasses with "
        "identical fields are still unequal to each other"
    )
    assert teacher.frame_digest is canonical.frame_digest, (
        "pocketsec/stage3/oracles/teacher.py defines its own frame_digest instead of "
        "re-exporting pocketsec.stage3.cells.frame.frame_digest; a teacher snapshot "
        "written with one and read with the other joins on nothing"
    )


def test_stage3_has_exactly_one_cell_boundary_type() -> None:
    """A second ``CellBoundary`` is a second validity language wearing one name.

    Two definitions existed at the end of the build wave — ``cells/boundary.py``
    and ``boundary/index.py`` — and they disagreed about what a boundary covers.
    ``cells/boundary.py`` expanded the delta component over every *subset* of
    ``state_dimensions``, which put the empty-delta mask in every boundary and
    made any two boundaries sharing a family and an actor mask impossible to
    separate. Under it a key-disjoint proper subregion was inexpressible, so
    ``partial_melt`` could not narrow anything and G3.7 — the stage's
    load-bearing criterion — could not be run at all.

    ``boundary/index.py`` is canonical: it is where spec §2.1 and §3.2 put the
    type, and it folds the declared dimensions into one union delta mask, which
    is what makes a proper subregion expressible.
    """
    from pocketsec.stage3.boundary import index as canonical
    from pocketsec.stage3.cells import schema

    assert not (STAGE3_ROOT / "cells" / "boundary.py").exists(), (
        "pocketsec/stage3/cells/boundary.py is back; CellBoundary is defined in "
        "pocketsec/stage3/boundary/index.py and nowhere else"
    )
    assert schema.CellBoundary is canonical.CellBoundary, (
        "KnowledgeCellV1 is annotated against a different CellBoundary than the one "
        "BoundaryIndex.insert expands; a cell built with one would be isinstance-rejected "
        "by the other"
    )


def test_the_bytecode_isa_imports_its_shared_constants_from_foundation() -> None:
    """One spelling of ``const.``, one value for the step cap.

    ``cells/operator.py`` enforces that a BYTECODE program's table holds nothing
    but the constant and set pools, and ``bytecode/isa.py`` reads those pools
    back out. If the two spell the prefixes differently the pool loads *empty*
    while every type check still passes, so ``LOAD_CONST`` fails its range check
    against length 0 and the enumerative synthesiser cannot emit a literal —
    which is exactly the defect this identity check was added to prevent
    recurring.
    """
    from pocketsec.stage3.bytecode import isa
    from pocketsec.stage3.cells import operator

    assert isa.CONSTANT_KEY_PREFIX is operator.CONSTANT_KEY_PREFIX
    assert isa.SET_KEY_PREFIX is operator.SET_KEY_PREFIX
    assert isa.MAX_INSTRUCTIONS == operator.MAX_CELL_STEPS


def test_stage3_declares_only_adrs_inside_its_reserved_block() -> None:
    """Stage 3 owns 0020-0029 and may use no number outside it.

    Checked against the filenames rather than against prose, because a wave that
    spent another wave's number would not discover it until both had shipped.
    """
    stage3_adrs = sorted(
        path.name
        for path in (REPO_ROOT / "docs" / "adr").glob("00[0-9][0-9]-*.md")
        if 20 <= int(path.name[:4]) <= 29
    )
    assert stage3_adrs, "Stage 3 wrote no ADR in its reserved block"
    numbers = {int(name[:4]) for name in stage3_adrs}
    assert numbers <= set(range(20, 30)), f"ADR outside Stage 3's block: {sorted(numbers)}"


def test_no_debug_prints_outside_the_stage3_cli() -> None:
    """print() belongs in the CLI presentation layer, nowhere else."""
    offenders: list[str] = []
    for path in _stage3_modules():
        if path.name == "cli.py":
            continue
        for node in ast.walk(_parse(path)):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "print"
            ):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
    assert not offenders, f"stray print() calls in Stage 3: {offenders}"


def test_no_stage3_dataclass_field_names_response_authority() -> None:
    """Import rule T5 / ADR-0003: no model output carries response authority.

    Matched on annotated assignments inside a class body, which is what a
    dataclass field is, so a *local variable* named ``blocked`` is not confused
    with a field named ``block``. Substring-matched on the lowered name, so
    ``recommended_action`` is caught as well as ``action``.

    **There is no exemption list here, deliberately.** The moment this check
    acquires one, every future collision is resolved by appending to it rather
    than by renaming, and the rule stops being a rule. A false-looking positive
    is resolved by changing the field name, not by narrowing the test.

    One collision was found and **resolved by renaming**, which is the precedent
    this docstring exists to set: ``docs/stage-3-spec.md`` D3.6 mandates
    ``CellResult.steps_executed``, whose name contains the ``execute`` token.
    The field is a past-tense instruction counter and grants nothing, so the
    honest reading is that the rule is broader than the harm — but a rule with
    one exemption has none, and ``steps_taken`` reads identically at no cost.
    The field is therefore ``CellResult.steps_taken`` throughout Stage 3, and
    the spec's field name is the one thing this wave deviated from there.
    """
    offenders: list[str] = []
    for path in _stage3_modules():
        for node in ast.walk(_parse(path)):
            if not isinstance(node, ast.ClassDef):
                continue
            for statement in node.body:
                if not isinstance(statement, ast.AnnAssign) or not isinstance(
                    statement.target, ast.Name
                ):
                    continue
                lowered = statement.target.id.lower()
                if any(token in lowered for token in FORBIDDEN_AUTHORITY_FIELDS):
                    offenders.append(
                        f"{path.relative_to(REPO_ROOT)}:{statement.lineno} "
                        f"{node.name}.{statement.target.id}"
                    )
    assert not offenders, f"Stage 3 fields naming response authority: {offenders}"


def test_every_stage3_module_parses_and_declares_future_annotations() -> None:
    """A cheap smoke check, plus the repository's ``from __future__`` convention.

    Scoped to modules that actually define something. The integration plan
    (§2.1) requires every Stage 3 ``__init__.py`` to stay empty so consumers
    import the leaf module, and an empty package marker has no annotations to
    postpone; demanding the import there would be a convention enforcing itself
    against the layout that defines it.
    """
    missing: list[str] = []
    for path in _stage3_modules():
        tree = _parse(path)
        defines_code = any(
            isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            for node in tree.body
        )
        if not defines_code:
            continue
        has_future = any(
            isinstance(node, ast.ImportFrom)
            and node.module == "__future__"
            and any(alias.name == "annotations" for alias in node.names)
            for node in tree.body
        )
        if not has_future:
            missing.append(str(path.relative_to(REPO_ROOT)))
    assert not missing, f"Stage 3 modules without `from __future__ import annotations`: {missing}"


# --- rule 5: an annotation must name something the module actually binds ------


def _bound_names(tree: ast.Module) -> set[str]:
    """Every name this module binds anywhere, including under ``TYPE_CHECKING``.

    Deliberately generous — a name bound inside a function still counts — because
    the failure this rule catches is a *missing* binding, and a generous collector
    keeps the rule free of false positives while still catching it.
    """
    bound: set[str] = set(dir(builtins))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                bound.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ClassDef):
            bound.add(node.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            bound.add(node.name)
            bound.update(arg.arg for arg in node.args.args)
            bound.update(arg.arg for arg in node.args.posonlyargs)
            bound.update(arg.arg for arg in node.args.kwonlyargs)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound.add(node.id)
        elif isinstance(node, ast.alias):  # pragma: no cover - covered above
            bound.add(node.asname or node.name.split(".")[0])
    return bound


def _annotation_names(tree: ast.Module) -> set[tuple[str, int]]:
    """``(name, lineno)`` for every bare name an annotation refers to."""
    found: set[tuple[str, int]] = set()
    annotations: list[ast.expr] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and node.annotation is not None:
            annotations.append(node.annotation)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.returns is not None:
                annotations.append(node.returns)
            for arg in (
                *node.args.args,
                *node.args.posonlyargs,
                *node.args.kwonlyargs,
                node.args.vararg,
                node.args.kwarg,
            ):
                if arg is not None and arg.annotation is not None:
                    annotations.append(arg.annotation)
    for annotation in annotations:
        for inner in ast.walk(annotation):
            if isinstance(inner, ast.Name):
                found.add((inner.id, inner.lineno))
            elif isinstance(inner, ast.Attribute):
                root = inner
                while isinstance(root, ast.Attribute):
                    root = root.value  # type: ignore[assignment]
                if isinstance(root, ast.Name):
                    found.add((root.id, root.lineno))
    return found


def test_every_stage3_annotation_names_something_the_module_binds() -> None:
    """Pins S3-12: ``CellBoundary.from_dict`` annotated ``Mapping``, never imported.

    ``from __future__ import annotations`` defers evaluation, so the method worked
    and nothing failed — until something introspected the annotation, at which
    point it raises NameError. An annotation naming a type the module does not
    bind is a lie about the signature that the interpreter happens not to check.
    """
    offenders: list[str] = []
    for path in _stage3_modules():
        tree = _parse(path)
        bound = _bound_names(tree)
        for name, lineno in sorted(_annotation_names(tree)):
            if name not in bound:
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{lineno} -> {name}")
    assert not offenders, f"Stage 3 annotations naming unbound types: {offenders}"
