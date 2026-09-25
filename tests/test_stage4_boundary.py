"""Stage 4's dependency-boundary check (ADR-0001, ADR-0008, ADR-0030, ADR-0121, T5, T7).

``tests/test_repository_structure.py`` implements these rules for Stages 0-2 and
hard-codes ``pocketsec/stage2/research/`` in two places. Widening those literals is an
edit to a file another wave may be editing, so Stage 4 gets its own copy of the
technique here and **leaves that file untouched**. ``tests/test_stage3_boundary.py``
did the same for Stage 3; this is the Stage 4 sibling.

The five rules of spec §5:

1. Every module under ``pocketsec/stage4/`` imports only roots in
   ``sys.stdlib_module_names`` or ``pocketsec`` (ADR-0001, R1).
2. No module under ``pocketsec/stage4/`` imports any ``pocketsec.stage*.research*``
   (ADR-0008, R2), and ``pocketsec/stage4/research/`` does not exist (ADR-0030).
3. No module under ``pocketsec/stage4/`` imports ``pocketsec.stage3`` (spec §2.5). The
   Stage 3 seam is plain JSON, read by ``crystal/handoff.py``, because ADR-0021 is live
   and a JSON reader survives a Stage 3 redesign where an import does not.
4. No module under ``pocketsec/stage1/`` or ``pocketsec/stage2/`` imports
   ``pocketsec.stage4`` (T7). This is how "Stage 4 remains optional to core Stage 1-3
   detection" is made structural rather than hopeful.
5. No dataclass field under ``pocketsec/stage4/`` has a lowered name containing a
   ``FORBIDDEN_AUTHORITY_FIELDS`` token (T5, ADR-0003), and
   ``pocketsec/stage4/{causal,cbf,lucid}/`` do not exist (ADR-0121).

Every check walks the AST, never the text: several modules in this package *name* the
boundary in a docstring, and naming it is not crossing it.

The import resolver is **imported**, not copied. S2-AUTH-01 was a hole that existed in
the structural tests and in the G2.13 seam check at once, and two copies is exactly how
it got closed in neither.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS
from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage2.gate_criteria import imported_modules

STAGE4_ROOT = REPO_ROOT / "pocketsec" / "stage4"

#: Directories under ``pocketsec/stage4/`` that the layout excludes. ``research`` is
#: ADR-0030 (bounded-K world enumeration is combinatorial, not numerical, and must run
#: on the endpoint). ``causal``, ``cbf`` and ``lucid`` existed empty before this wave:
#: importable by accident as namespace packages, invisible to every structural test,
#: and named after components the layout puts elsewhere. That is the ADR-0121
#: anti-pattern, and this test forbids their return by name.
FORBIDDEN_STAGE4_DIRECTORIES = ("research", "causal", "cbf", "lucid")

#: Stages that may never import Stage 4 (T7).
DOWNSTREAM_FORBIDDEN_STAGES = ("stage1", "stage2")


def _modules(root: Path) -> list[Path]:
    if not root.is_dir():  # pragma: no cover - the package is the subject
        return []
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _resolved(path: Path) -> list[tuple[str, int]]:
    """Every module the file imports, as an ABSOLUTE dotted path, with its line."""
    tree = _parse(path)
    return [
        (module, node.lineno)
        for node in ast.walk(tree)
        for module in imported_modules(node, path)
    ]


def _label(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def test_stage4_has_modules_at_all() -> None:
    """Guard against every rule below passing vacuously on an empty package."""
    assert _modules(STAGE4_ROOT), "pocketsec/stage4/ holds no Python modules"


# --- rule 1 ------------------------------------------------------------------


def test_stage4_has_no_third_party_imports() -> None:
    """ADR-0001 / ADR-0030: Stage 4 is stdlib-only end to end.

    A gate is a runtime module and the CI ``gate`` job installs the package bare, so a
    third-party import anywhere in Stage 4 — including deferred inside a function, which
    the AST walk sees — breaks the gate rather than the tests.
    """
    allowed = set(sys.stdlib_module_names) | {"pocketsec"}
    offenders: dict[str, set[str]] = {}
    for path in _modules(STAGE4_ROOT):
        external = {module.split(".")[0] for module, _ in _resolved(path)} - allowed
        if external:
            offenders[_label(path)] = external
    assert not offenders, f"third-party imports in Stage 4: {offenders}"


# --- rule 2 ------------------------------------------------------------------


def test_stage4_never_imports_research_code() -> None:
    """ADR-0008: the research boundary is one-directional, for every stage.

    Written against ``pocketsec.stage<N>.research`` rather than Stage 2's literal path,
    so a Stage 4 module cannot reach numpy through a *future* stage's research package
    either.
    """
    offenders = [
        f"{_label(path)}:{lineno} -> {module}"
        for path in _modules(STAGE4_ROOT)
        for module, lineno in _resolved(path)
        if _is_research(module)
    ]
    assert not offenders, f"Stage 4 modules importing research code: {offenders}"


def _is_research(module: str) -> bool:
    parts = module.split(".")
    return len(parts) >= 3 and parts[0] == "pocketsec" and parts[2] == "research"


# --- rule 3 ------------------------------------------------------------------


def test_stage4_never_imports_stage3() -> None:
    """Spec §2.5: Stage 4's only contact with Stage 3 is a JSON file.

    ADR-0021 is live — Stage 3's cell format may be withdrawn — and
    ``CrystalHandoffV1.to_dict()`` already refuses to emit a payload naming a Stage 3
    class. A JSON reader survives that redesign; an import does not.
    """
    offenders = [
        f"{_label(path)}:{lineno} -> {module}"
        for path in _modules(STAGE4_ROOT)
        for module, lineno in _resolved(path)
        if module == "pocketsec.stage3" or module.startswith("pocketsec.stage3.")
    ]
    assert not offenders, f"Stage 4 modules importing Stage 3: {offenders}"


# --- rule 4 ------------------------------------------------------------------


@pytest.mark.parametrize("stage", DOWNSTREAM_FORBIDDEN_STAGES)
def test_no_earlier_stage_imports_stage4(stage: str) -> None:
    """T7: detection must not be able to depend on cognition.

    Acceptance criterion 11 is "Stage 4 remains optional to core Stage 1-3 detection if
    it crashes". The fault-injection half lives in ``tests/test_stage4_optionality.py``;
    this is the structural half, and it is the cheaper of the two to keep true.
    """
    root = REPO_ROOT / "pocketsec" / stage
    assert root.is_dir(), f"pocketsec/{stage}/ is missing"
    offenders = [
        f"{_label(path)}:{lineno} -> {module}"
        for path in _modules(root)
        for module, lineno in _resolved(path)
        if module == "pocketsec.stage4" or module.startswith("pocketsec.stage4.")
    ]
    assert not offenders, f"{stage} modules importing Stage 4: {offenders}"


# --- rule 5 ------------------------------------------------------------------


@pytest.mark.parametrize("name", FORBIDDEN_STAGE4_DIRECTORIES)
def test_stage4_does_not_hold_a_forbidden_directory(name: str) -> None:
    """``research/`` is ADR-0030; the other three are ADR-0121's empty-package defect."""
    assert not (STAGE4_ROOT / name).exists(), (
        f"pocketsec/stage4/{name}/ exists; it is excluded by the Stage 4 layout and an "
        "empty package directory is a defect, not a placeholder"
    )


def test_no_stage4_dataclass_field_names_response_authority() -> None:
    """T5 / ADR-0003: no Stage 4 output carries response authority.

    This bites Stage 4 harder than any other stage — the architecture's own §9 writes
    ``do(block privilege transition)`` and both ``block`` and ``privilege`` are
    forbidden tokens. Spec §2.4 fixes the renamings so eight engineers do not invent
    eight of them.

    Matched on annotated assignments inside a class body, which is what a dataclass
    field is, so a *local variable* named ``blocked`` is not confused with a field named
    ``block``. Substring-matched on the lowered name, so ``recommended_action`` is
    caught as well as ``action``.

    **There is no exemption list here, deliberately.** The moment this check acquires
    one, every future collision is resolved by appending to it rather than by renaming,
    and the rule stops being a rule. Stage 3 set the precedent: its spec mandated
    ``CellResult.steps_executed``, the field granted nothing, and it was renamed to
    ``steps_taken`` anyway.
    """
    offenders: list[str] = []
    for path in _modules(STAGE4_ROOT):
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
                        f"{_label(path)}:{statement.lineno} {node.name}.{statement.target.id}"
                    )
    assert not offenders, f"Stage 4 fields naming response authority: {offenders}"


# --- the committed negative fixture for rules 1-4 ----------------------------

#: A Stage 4 module reaching where it must not, the way a future author most plausibly
#: would: from inside the package, with a *relative* import. Committed as a fixture
#: rather than described, because that is exactly the shape that was invisible to two
#: checkers at once (S2-AUTH-01): ``from .research import x`` gives
#: ``node.module == "research"``, which matched neither ``pocketsec.stage2.research`` nor
#: ``".research"``, and ``from . import research`` gives ``node.module is None``, which
#: the ``and node.module`` guard dropped outright. CI stayed green while numpy could
#: reach the endpoint runtime.
#:
#: Each row is ``(package the offending module sits in, the import, the rule it breaks)``.
RELATIVE_BOUNDARY_VIOLATIONS = (
    (("pocketsec", "stage4"), "from . import research", "research"),
    (("pocketsec", "stage4"), "from .research import solver", "research"),
    (("pocketsec", "stage4"), "from .research.solver import fit", "research"),
    (("pocketsec", "stage4", "worlds"), "from ..research import solver", "research"),
    (("pocketsec", "stage4", "worlds"), "from .. import research", "research"),
    (("pocketsec", "stage4"), "from ..stage3 import stage4_interface", "stage3"),
    (("pocketsec", "stage4", "crystal"), "from ...stage3.cells import schema", "stage3"),
    (("pocketsec", "stage4", "crystal"), "from ...stage3 import gate", "stage3"),
    (("pocketsec", "stage1", "state"), "from ...stage4.worlds import field", "stage4"),
    (("pocketsec", "stage2", "labs"), "from ...stage4 import theory", "stage4"),
)


@pytest.mark.parametrize(("where", "source", "rule"), RELATIVE_BOUNDARY_VIOLATIONS)
def test_a_relative_boundary_violation_is_resolved_to_an_absolute_path(
    where: tuple[str, ...], source: str, rule: str, tmp_path: Path
) -> None:
    """Every rule above must see a relative import, not skip it.

    The offending file is written at a real position inside a ``pocketsec`` tree so the
    relative level resolves the way it would in the package itself, then the *same*
    predicates the rules use are applied to it. A rule that cannot catch its own
    negative fixture is not enforcing anything.
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
    elif rule == "stage3":
        assert all(module.startswith("pocketsec.stage3") for module in resolved), resolved
    else:
        assert all(module.startswith("pocketsec.stage4") for module in resolved), resolved


def test_the_negative_fixture_covers_every_import_form_and_rule() -> None:
    """The fixture is only as good as its coverage, so the coverage is asserted.

    Both spellings that hid S2-AUTH-01 must be present — ``from . import x`` (no
    ``node.module``) and ``from .x import y`` (a relative ``node.module``) — and all
    three of the import rules that a relative import could evade.
    """
    sources = [source for _, source, _ in RELATIVE_BOUNDARY_VIOLATIONS]
    assert any(s.startswith("from . import ") for s in sources)
    assert any(s.startswith("from .. import ") for s in sources)
    assert any(s.startswith("from .research") for s in sources)
    assert any(s.startswith("from ...") for s in sources)
    assert {rule for _, _, rule in RELATIVE_BOUNDARY_VIOLATIONS} == {
        "research",
        "stage3",
        "stage4",
    }
