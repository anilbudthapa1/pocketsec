"""D0.8 — repository structure and CI smoke checks (ADR-0001, ADR-0002)."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

from pocketsec.stage0.gate import REPO_ROOT

# One implementation of import resolution for every boundary checker in this
# repository, imported rather than copied: S2-AUTH-01 was a hole that existed in
# the structural tests AND in the G2.13 seam check, and two copies is how it got
# closed in neither.
from pocketsec.stage2.gate_criteria import imported_modules, research_imports

# Every directory the Stage 0 spec's recommended skeleton calls for.
SPEC_DIRECTORIES = (
    "docs",
    "docs/architecture",
    "docs/adr",
    "docs/prior-art",
    "contracts",
    "benchmarks",
    "experiments",
    "results",
    "datasets",
    "baselines",
    "models",
    "models/experimental",
    "models/compiled",
    "runtime",
    "training",
    "pocketsec",
    "tests",
)

SPEC_DELIVERABLE_FILES = (
    "docs/stage-0-research-spec.md",
    "docs/architecture/hub-model-boundary.md",
    "docs/adr/0000-adr-template.md",
    "docs/reproducibility-policy.md",
    "docs/prior-art/ledger.json",
    "docs/stage-1-entry-criteria.md",
    "docs/stage-1-ssir-spec.md",
    "docs/stage-2-entry-criteria.md",
    "docs/adr/0005-lineage-scoped-security-state.md",
    "docs/adr/0006-semantics-are-earned-by-behaviour.md",
    "contracts/security_event_sequence_v1.schema.json",
    "contracts/threat_prediction_v1.schema.json",
    "pyproject.toml",
    ".github/workflows/ci.yml",
)


@pytest.mark.parametrize("relative", SPEC_DIRECTORIES)
def test_spec_directory_exists(relative: str) -> None:
    assert (REPO_ROOT / relative).is_dir(), f"missing spec directory {relative}"


@pytest.mark.parametrize("relative", SPEC_DELIVERABLE_FILES)
def test_stage0_deliverable_exists(relative: str) -> None:
    assert (REPO_ROOT / relative).is_file(), f"missing deliverable {relative}"


def test_no_importable_module_lives_outside_the_package() -> None:
    """ADR-0002: all code lives in pocketsec/; top level holds artifacts."""
    stray = [
        path.relative_to(REPO_ROOT)
        for path in REPO_ROOT.glob("*/*.py")
        if not str(path.relative_to(REPO_ROOT)).startswith(("pocketsec/", "tests/"))
    ]
    assert not stray, f"Python modules outside the package: {stray}"


#: Offline research code, exempt from the stdlib-only rule (ADR-0008).
RESEARCH_PREFIX = "pocketsec/stage2/research/"

#: Every stage whose runtime packages must stay stdlib-only and research-free.
#: A stage added here without its packages listed below would pass vacuously.
RUNTIME_STAGES = ("stage0", "stage1", "stage2")

#: Stage 2's runtime subpackages, named rather than globbed. Integration plan
#: section 1.1 calls an empty package a defect, and the eleven that shipped empty
#: are exactly what this list exists to keep filled.
STAGE2_RUNTIME_PACKAGES = (
    "adaptation",
    "cache",
    "compile_candidates",
    "counterfactual",
    "credit",
    "encoder",
    "labs",
    "lattice",
    "predictors",
    "router",
    "state",
    "uncertainty",
)


def _runtime_modules() -> list[Path]:
    """Every module that could run on an endpoint (i.e. not offline research)."""
    return sorted(
        path
        for path in (REPO_ROOT / "pocketsec").rglob("*.py")
        if not str(path.relative_to(REPO_ROOT)).startswith(RESEARCH_PREFIX)
    )


def _research_modules() -> list[Path]:
    return sorted((REPO_ROOT / "pocketsec" / "stage2" / "research").rglob("*.py"))


def test_runtime_never_imports_research_code() -> None:
    """ADR-0008: the boundary is one-directional.

    Research may depend on the runtime. The runtime must never depend on
    research, or numpy would reach the endpoint through the back door.
    """
    offenders = _research_importers(_runtime_modules())
    assert not offenders, f"runtime modules importing research code: {offenders}"


def _research_importers(paths: list[Path]) -> list[str]:
    """Every ``path:lineno`` that imports research code, relative imports included."""
    offenders: list[str] = []
    for path in paths:
        # AST, not text search: a docstring that *names* the boundary is not a
        # violation of it.
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            modules = imported_modules(node, path)
            if any(m.startswith("pocketsec.stage2.research") for m in modules):
                offenders.append(f"{_label(path)}:{node.lineno}")
    return offenders


def _label(path: Path) -> str:
    """Repo-relative when it can be, absolute otherwise (a tmp_path fixture)."""
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


#: A runtime module reaching research the way a future author most plausibly
#: would — from inside the same package, with a relative import. Committed as a
#: fixture rather than described, so the hole cannot reopen unnoticed.
RELATIVE_RESEARCH_IMPORTS = (
    # (package the offending module sits in, the import it writes)
    (("pocketsec", "stage2"), "from .research import dtl"),
    (("pocketsec", "stage2"), "from . import research"),
    (("pocketsec", "stage2"), "from .research.dtl import DTLConvModel"),
    (("pocketsec", "stage2", "compile_candidates"), "from ..research import dtl"),
    (("pocketsec", "stage2", "compile_candidates"), "from .. import research"),
    (
        ("pocketsec", "stage2", "lattice"),
        "from ..research.baselines import fit_baselines",
    ),
)


@pytest.mark.parametrize(("where", "source"), RELATIVE_RESEARCH_IMPORTS)
def test_a_relative_research_import_is_caught_by_both_checkers(
    where: tuple[str, ...], source: str, tmp_path: Path
) -> None:
    """Pins S2-AUTH-01. The boundary was absolute-import-only in both directions.

    ``from .research import dtl`` gives ``node.module == "research"``, which
    matched neither ``pocketsec.stage2.research`` (the structural test) nor
    ``".research" in module`` (the G2.13 seam check); ``from . import research``
    gives ``node.module is None``, which the ``and node.module`` guard dropped
    outright. CI stayed green, ``pocketsec-stage2 gate`` reported 0 research
    imports, and numpy could reach the endpoint runtime with nothing able to see
    it — while ``planning/MEMORY.md`` and the interfaces document both asserted
    the boundary was "enforced in both directions by tests".

    The file is written at a real position inside ``pocketsec/stage2`` so the
    relative level resolves the way it would in the package itself.
    """
    package = tmp_path.joinpath(*where)
    package.mkdir(parents=True)
    offender = package / "leak.py"
    offender.write_text(source + "\n", encoding="utf-8")

    resolved = [
        module
        for node in ast.walk(ast.parse(source))
        for module in imported_modules(node, offender)
    ]
    assert resolved, source
    assert all(m.startswith("pocketsec.stage2.research") for m in resolved), resolved

    # The structural checker, which is what CI runs.
    assert _research_importers([offender]), f"{source} slipped past the structural test"

    # And the G2.13 seam check, which scans a whole package.
    assert research_imports(package), f"{source} slipped past research_imports"


def test_research_package_is_the_only_numpy_user() -> None:
    """The exemption must stay narrow and be visible."""
    using_numpy = [
        str(path.relative_to(REPO_ROOT))
        for path in _research_modules()
        if "import numpy" in path.read_text(encoding="utf-8")
    ]
    assert using_numpy, "the research exemption exists to be used; nothing uses it"


def test_runtime_has_no_third_party_imports() -> None:
    """ADR-0001: the endpoint runtime depends on the stdlib alone."""
    allowed = set(sys.stdlib_module_names) | {"pocketsec"}
    offenders: dict[str, set[str]] = {}

    for path in _runtime_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        roots: set[str] = set()
        for node in ast.walk(tree):
            # Relative imports are resolved to absolute paths rather than
            # skipped: `node.level == 0` used to filter every one of them out,
            # so a relative reach into research — which transitively imports
            # numpy — contributed no root at all (S2-AUTH-01).
            roots.update(module.split(".")[0] for module in imported_modules(node, path))
        external = roots - allowed
        if external:
            offenders[_label(path)] = external

    assert not offenders, f"third-party imports in runtime code: {offenders}"


def test_pyproject_declares_no_runtime_dependencies() -> None:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "dependencies = []" in text


def test_every_runtime_module_parses() -> None:
    """A cheap CI smoke check that nothing is syntactically broken."""
    for path in _runtime_modules():
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_no_debug_prints_outside_the_cli() -> None:
    """print() belongs in the CLI presentation layer, nowhere else."""
    offenders: list[str] = []
    for path in _runtime_modules():
        if path.name == "cli.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "print"
            ):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
    assert not offenders, f"stray print() calls: {offenders}"


@pytest.mark.parametrize("package", STAGE2_RUNTIME_PACKAGES)
def test_stage2_subpackage_exports_something(package: str) -> None:
    """An empty package is a defect, not a placeholder (integration plan §1.1).

    The check scans the package *directory*, not ``__init__.py``: the integration
    plan requires those to stay empty and consumers to import from the leaf
    module, exactly as ``encoder/`` already does. What must not exist is a
    package directory with no class or function in it at all.
    """
    directory = REPO_ROOT / "pocketsec" / "stage2" / package
    assert directory.is_dir(), f"missing Stage 2 package {package}"
    symbols: list[str] = []
    for path in sorted(directory.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        symbols.extend(
            node.name
            for node in tree.body
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            and not node.name.startswith("_")
        )
    assert symbols, f"pocketsec/stage2/{package}/ exports no class or function"


def test_no_stage_directory_is_an_orphan() -> None:
    """A directory under a stage is either a package or absent (ADR-0121).

    ``stage2/{atoms,dtl,prediction}/`` existed with no ``__init__.py`` and no
    content: importable by accident under namespace packages, invisible to every
    structural test, and a standing invitation to put code in the wrong place.
    """
    orphans = [
        str(path.relative_to(REPO_ROOT))
        for stage in RUNTIME_STAGES
        for path in sorted((REPO_ROOT / "pocketsec" / stage).iterdir())
        if path.is_dir()
        and not path.name.startswith("__")
        and not (path / "__init__.py").exists()
    ]
    assert not orphans, f"directories under a stage that are not packages: {orphans}"


def test_every_runtime_stage_is_covered_by_the_import_rules() -> None:
    """The stdlib-only and no-research rules must actually reach Stage 2.

    ``_runtime_modules()`` globs the whole package, so a new stage is covered
    automatically — but only if it is on disk under ``pocketsec/``. This pins the
    three stages that exist, so deleting one silently would be caught.
    """
    modules = {str(path.relative_to(REPO_ROOT)) for path in _runtime_modules()}
    for stage in RUNTIME_STAGES:
        covered = [name for name in modules if name.startswith(f"pocketsec/{stage}/")]
        assert covered, f"no runtime module of {stage} is checked by the import rules"
    stage2 = [name for name in modules if name.startswith("pocketsec/stage2/")]
    assert not [name for name in stage2 if name.startswith(RESEARCH_PREFIX)]
    for package in STAGE2_RUNTIME_PACKAGES:
        assert any(
            name.startswith(f"pocketsec/stage2/{package}/") for name in stage2
        ), f"pocketsec/stage2/{package}/ is not reached by the runtime import checks"


def test_stage2_gate_and_cli_exist_and_are_stdlib_only() -> None:
    """Stage 2 had no gate and no CLI; both are runtime modules like any other.

    ``docs/adr/0113`` records why this is a test and not a note: a stage may not
    be declared passed *or* failed by prose, and the gate that makes the claim
    has to be code the stdlib-only rule already covers.
    """
    for name in ("gate.py", "cli.py"):
        assert (REPO_ROOT / "pocketsec" / "stage2" / name).is_file(), f"missing stage2/{name}"
    from pocketsec.stage2.cli import main
    from pocketsec.stage2.gate import Stage2GateContext, run_gate

    assert callable(main) and callable(run_gate) and Stage2GateContext is not None


def test_pyproject_declares_the_stage2_entry_point_and_numpy_as_dev_only() -> None:
    """numpy is a research dependency (ADR-0008), so it belongs in the dev extra.

    Integration plan §5.6: the test suite imports numpy while ``pyproject.toml``
    declared it nowhere, so the CI ``test`` job as written could not pass.
    """
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'pocketsec-stage2 = "pocketsec.stage2.cli:main"' in text
    assert "numpy" in text.split("[project.optional-dependencies]", 1)[1].split("[", 1)[0]
    assert "numpy" not in text.split("dependencies = [", 1)[1].split("]", 1)[0]
