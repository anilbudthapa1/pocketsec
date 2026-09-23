"""D0.8 — repository structure and CI smoke checks (ADR-0001, ADR-0002)."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

from pocketsec.stage0.gate import REPO_ROOT

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
    offenders: list[str] = []
    for path in _runtime_modules():
        # AST, not text search: a docstring that *names* the boundary is not a
        # violation of it.
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules = [node.module]
            if any(m.startswith("pocketsec.stage2.research") for m in modules):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
    assert not offenders, f"runtime modules importing research code: {offenders}"


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
            if isinstance(node, ast.Import):
                roots.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                roots.add(node.module.split(".")[0])
        external = roots - allowed
        if external:
            offenders[str(path.relative_to(REPO_ROOT))] = external

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
