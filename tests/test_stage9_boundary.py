"""Stage 9's authority boundary (spec §2.2, §2.3; ADR-0081), proven on the real tree and
attacked with negative fixtures.

One test per predicate in ``pocketsec/stage9/successor/boundary.py`` asserts ``()`` on the
real tree; each rule is then shown to FIRE on a fixture written to ``tmp_path`` at a real
package position (``tmp_path/pocketsec/stage9/...``), so a rule that silently stopped
matching would fail here rather than pass vacuously.

This file never touches ``tests/test_repository_structure.py`` (the lead's rule): Stage 9's
dependency boundary lives here. It spells Stage 6's sealed writer names, which is legal
because Stage 6's own boundary test only scans ``pocketsec/``.
"""

from __future__ import annotations

import ast
import hashlib
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from pocketsec.stage2.gate_criteria import imported_modules
from pocketsec.stage9.successor import boundary as b

Predicate = Callable[[], tuple[str, ...]]


def _fixture(tmp_path: Path, relative: str, source: str) -> Path:
    """Write ``source`` at ``tmp_path/pocketsec/<relative>`` with package ``__init__``s."""
    path = tmp_path / "pocketsec" / relative
    for parent in [path.parent, *path.parent.parents]:
        if parent == tmp_path:
            break
        parent.mkdir(parents=True, exist_ok=True)
        (parent / "__init__.py").touch()
    path.write_text(source, encoding="utf-8")
    return path


# --- the tree is real, so no rule passes vacuously -----------------------------------------------


def test_the_stage9_tree_the_rules_scan_is_not_empty() -> None:
    labels = {str(p.relative_to(b.POCKETSEC_ROOT)) for p in b.stage9_modules()}
    assert "stage9/successor/stage6_exit.py" in labels
    assert "stage9/successor/boundary.py" in labels
    assert len(labels) > 20


# --- one test per predicate on the real tree -----------------------------------------------------


@pytest.mark.parametrize("predicate", [
    b.direct_stage5_imports,
    b.transitive_stage5_reach,
    b.stage6_allow_list_offenders,
    b.admit_call_sites,
    b.stage6_writer_names,
    b.authority_field_offenders,
    b.dynamic_execution_offenders,
    b.numpy_or_research_offenders,
    b.earlier_stage_importers,
    b.outside_importers_of_stage9,
], ids=lambda f: f.__name__)
def test_every_boundary_rule_holds_on_the_real_tree(predicate: Predicate) -> None:
    assert predicate() == ()


def test_admit_is_called_in_exactly_one_stage9_file_the_exit() -> None:
    assert b.admit_call_files() == ("pocketsec/stage9/successor/stage6_exit.py",)


def test_the_exit_residual_is_real_and_goes_through_the_capsule_package() -> None:
    """Rule 2 is not vacuous: without the capsule stop, the exit DOES reach Stage 5 (M0.9),
    and the first path it finds runs through pocketsec.stage6.capsule."""
    exit_path = b.STAGE9_ROOT / "successor" / "stage6_exit.py"
    chain = b._stage5_path(exit_path, b.POCKETSEC_ROOT, stop=lambda _m: False)
    assert chain is not None and chain[-1].startswith("pocketsec.stage5")
    assert any(m.startswith("pocketsec.stage6.capsule") for m in chain)


def test_sealed_names_are_read_from_stage6_source_and_the_writer_digest_is_pinned() -> None:
    assert b.sealed_names() >= {
        "_install_trusted", "_trusted_state", "_issue_verdict", "_issued_verdicts",
        "_issue_candidate", "_issued_candidates", "_issue_decision", "_issued_decisions",
    }
    assert hashlib.sha256(b"_install_trusted").hexdigest() in b.WRITER_NAME_DIGESTS


# --- negative fixtures: every rule fires ------------------------------------------------------


def test_a_relative_stage5_import_is_caught(tmp_path: Path) -> None:
    leak = _fixture(tmp_path, "stage9/argus/leak.py",
                    "from ...stage5.operators import catalog\n")
    assert len(b.direct_stage5_imports([leak])) == 1
    absolute = _fixture(tmp_path, "stage9/gaia/leak.py", "from pocketsec import stage5\n")
    assert len(b.direct_stage5_imports([absolute])) == 1


def test_a_function_level_route_to_stage5_is_caught_by_the_closure(tmp_path: Path) -> None:
    leak = _fixture(tmp_path, "stage9/genesis/leak.py",
                    "def later():\n"
                    "    from pocketsec.stage6.capsule.quarantine import QuarantineGateway\n"
                    "    return QuarantineGateway\n")
    (offender,) = b.transitive_stage5_reach([leak])
    assert "reaches Stage 5" in offender and "pocketsec.stage6.capsule" in offender


def test_the_exit_may_not_reach_stage5_except_through_the_capsule_package(
        tmp_path: Path) -> None:
    through = _fixture(tmp_path, "stage9/successor/stage6_exit.py",
                       "from pocketsec.stage6.capsule.quarantine import QuarantineGateway\n")
    assert b.transitive_stage5_reach([through]) == ()
    bypass = _fixture(tmp_path / "second", "stage9/successor/stage6_exit.py",
                      "import pocketsec.stage5.operators.catalog\n")
    (offender,) = b.transitive_stage5_reach([bypass])
    assert "bypassing pocketsec.stage6.capsule" in offender


def test_a_quarantine_gateway_from_import_outside_the_exit_is_caught(tmp_path: Path) -> None:
    leak = _fixture(tmp_path, "stage9/ontogenesis/leak.py",
                    "from pocketsec.stage6.capsule.quarantine import QuarantineGateway\n")
    assert len(b.stage6_allow_list_offenders([leak])) == 1
    assert len(b.admit_call_sites([leak])) == 1
    harness = _fixture(tmp_path, "stage9/gate_lab.py",
                       "from pocketsec.stage6.capsule.quarantine import QuarantineGateway\n"
                       "from pocketsec.stage6.memory.semantic import genesis_state\n")
    assert b.stage6_allow_list_offenders([harness]) == ()
    assert b.admit_call_sites([harness]) == ()


@pytest.mark.parametrize(("relative", "source"), [
    ("stage9/runtime/leak.py", "from pocketsec.stage6.memory.semantic import genesis_state\n"),
    ("stage9/runtime/leak.py", "import pocketsec.stage2.dataset\n"),
    ("stage9/runtime/leak.py", "from pocketsec.stage2 import dataset\n"),
    ("stage9/runtime/leak.py", "from pocketsec.stage2.gate_measures import compile_split\n"),
    ("stage9/runtime/leak.py", "from pocketsec.stage4.cbf import worlds\n"),
    ("stage9/runtime/leak.py", "from pocketsec.stage7.echo import x\n"),
    ("stage9/labs/leak.py", "from pocketsec.stage3.bytecode.isa import Op\n"),
])
def test_the_allow_list_refuses_off_list_modules_names_and_files(
        tmp_path: Path, relative: str, source: str) -> None:
    assert len(b.stage6_allow_list_offenders([_fixture(tmp_path, relative, source)])) == 1


def test_the_allow_list_admits_what_the_spec_grants(tmp_path: Path) -> None:
    ok = _fixture(tmp_path, "stage9/daedalus/synthesizer.py",
                  "from pocketsec.stage3.bytecode.isa import Op\n"
                  "from pocketsec.stage6.resources import WorkMeter\n"
                  "from pocketsec.stage1.pipeline import ScenarioResult\n")
    assert b.stage6_allow_list_offenders([ok]) == ()


@pytest.mark.parametrize("source", [
    "def f(g, c):\n    return g.admit(c)\n",
    "def f(g, c):\n    return getattr(g, 'admit')(c)\n",
])
def test_an_admit_call_outside_the_exit_is_caught(tmp_path: Path, source: str) -> None:
    leak = _fixture(tmp_path, "stage9/labs/leak.py", source)
    assert len(b.admit_call_sites([leak])) == 1
    harness = _fixture(tmp_path, "stage9/gate.py", source)
    assert len(b.admit_call_sites([harness])) == 1  # the harness may build, never call


@pytest.mark.parametrize("source", [
    "from pocketsec.stage6.promotion.controller import TrustedMind\n",
    "from pocketsec.stage6.fossils.store import x\n",
    "def f(mind, s):\n    mind._install_trusted(s)\n",
    "NAME = '_issued_verdicts'\n",
])
def test_a_stage6_writer_named_anywhere_is_caught(tmp_path: Path, source: str) -> None:
    leak = _fixture(tmp_path, "stage9/chronos/leak.py", source)
    assert len(b.stage6_writer_names([leak])) >= 1


def test_the_writer_rule_refuses_to_pass_when_it_can_read_no_sealed_names(
        tmp_path: Path) -> None:
    clean = _fixture(tmp_path, "stage9/chronos/clean.py", "X = 1\n")
    empty_stage6 = tmp_path / "pocketsec" / "stage6"
    empty_stage6.mkdir(parents=True, exist_ok=True)
    (offender,) = b.stage6_writer_names([clean], stage6_root=empty_stage6)
    assert "vacuously" in offender


@pytest.mark.parametrize("source", [
    "from dataclasses import dataclass\n@dataclass\nclass Hint:\n    suggested_action: str\n",
    "class QuarantineHelper:\n    pass\n",
    "class P:\n    privilege_level: int\n",
    "class R:\n    cpu_fraction: float\n",  # "fraction" holds "action"
])
def test_an_authority_named_class_or_field_is_caught(tmp_path: Path, source: str) -> None:
    leak = _fixture(tmp_path, "stage9/spec/leak.py", source)
    assert len(b.authority_field_offenders([leak])) == 1


@pytest.mark.parametrize(("relative", "source"), [
    ("stage9/geometry/leak.py", "x = eval('1')\n"),
    ("stage9/geometry/leak.py", "exec('x = 1')\n"),
    ("stage9/geometry/leak.py", "c = compile('1', 'f', 'eval')\n"),
    ("stage9/geometry/leak.py", "m = __import__('os')\n"),
    ("stage9/geometry/leak.py", "import importlib\nm = importlib.import_module('x')\n"),
    ("stage9/geometry/leak.py", "import pickle\n"),
    ("stage9/geometry/leak.py", "import marshal\n"),
    ("stage9/geometry/leak.py", "import socket\n"),
    ("stage9/geometry/leak.py", "import os\nos.system('true')\n"),
    ("stage9/geometry/leak.py", "import subprocess\n"),
    ("stage9/cli.py", "import subprocess\n"),
    ("stage9/geometry/leak.py", "from concurrent.futures import ProcessPoolExecutor\n"),
    # S9-AUTH-01: aliases and literal-name lookups used to pass the rule, and with it the
    # Stage 5 closure proof, which cannot see a dynamic import.
    ("stage9/geometry/leak.py", "from importlib import import_module as load\nm = load('x')\n"),
    ("stage9/geometry/leak.py", "import builtins as b\nb.eval('1')\n"),
    ("stage9/geometry/leak.py", "import builtins\nf = getattr(builtins, 'eval')\n"),
    ("stage9/geometry/leak.py", "import builtins\nf = vars(builtins)['exec']\n"),
    ("stage9/geometry/leak.py", "import runpy\n"),
    ("stage9/geometry/leak.py", "import multiprocessing\n"),
])
def test_dynamic_execution_is_caught(tmp_path: Path, relative: str, source: str) -> None:
    assert len(b.dynamic_execution_offenders([_fixture(tmp_path, relative, source)])) >= 1


@pytest.mark.parametrize(("relative", "source"), [
    ("stage9/core_ids.py", "import importlib\nm = importlib.import_module('x')\n"),
    ("stage9/labs/one_twenty_experiments.py", "from importlib import import_module\n"
                                              "m = import_module('x')\n"),
    ("stage9/gate_isolation.py", "import subprocess\n"),
    ("stage9/labs/splits.py", "from concurrent.futures import ProcessPoolExecutor\n"),
    ("stage9/geometry/fine.py", "import re\nP = re.compile('x')\n"),
])
def test_the_three_declared_exemptions_and_re_compile_are_not_offenders(
        tmp_path: Path, relative: str, source: str) -> None:
    assert b.dynamic_execution_offenders([_fixture(tmp_path, relative, source)]) == ()


def test_numpy_a_research_import_and_a_research_directory_are_caught(tmp_path: Path) -> None:
    numpy = _fixture(tmp_path, "stage9/compression/leak.py", "import numpy as np\n")
    research = _fixture(tmp_path, "stage9/compression/leak2.py",
                        "from pocketsec.stage2.research import dtl\n")
    root = tmp_path / "pocketsec" / "stage9"
    assert len(b.numpy_or_research_offenders([numpy, research], stage9_root=root)) == 2
    (root / "research").mkdir()
    assert len(b.numpy_or_research_offenders([], stage9_root=root)) == 1


def test_an_earlier_stage_importing_stage9_is_caught(tmp_path: Path) -> None:
    _fixture(tmp_path, "stage2/leak.py", "from pocketsec.stage9.genome import computational\n")
    _fixture(tmp_path, "stage1/leak.py", "import pocketsec.stage8\n")
    assert len(b.earlier_stage_importers(tmp_path / "pocketsec")) == 2


def test_t3_lets_only_the_quarantine_import_only_the_successor(tmp_path: Path) -> None:
    _fixture(tmp_path, "stage6/capsule/quarantine.py",
             "from pocketsec.stage9.successor import proof_carrying\n")
    root = tmp_path / "pocketsec"
    assert b.earlier_stage_importers(root) == ()
    assert b.outside_importers_of_stage9(root) == ()
    # A fresh root: the AST cache is keyed by path, so a rewritten file would not be re-read.
    other = tmp_path / "other"
    _fixture(other, "stage6/capsule/quarantine.py",
             "from pocketsec.stage9.genome import computational\n")
    assert len(b.earlier_stage_importers(other / "pocketsec")) == 1


def test_an_importer_of_stage9_outside_stage9_is_caught(tmp_path: Path) -> None:
    _fixture(tmp_path, "stage10/leak.py", "from pocketsec.stage9.successor import boundary\n")
    _fixture(tmp_path, "stage9/fine.py", "from pocketsec.stage9.successor import boundary\n")
    (offender,) = b.outside_importers_of_stage9(tmp_path / "pocketsec")
    assert "stage10/leak.py" in offender


# --- the dependency boundary (ADR-0001, ADR-0008, ADR-0080), the shared AST technique ----------
#
# ``tests/test_repository_structure.py`` enforces ADR-0001/0008 for Stages 0-2 only and may not be
# edited by this wave. These tests apply its exact technique - an AST walk resolved through
# ``stage2.gate_criteria.imported_modules`` so relative imports count - to every Stage 9 file.

_STDLIB = frozenset(sys.stdlib_module_names) | {"pocketsec"}


def _third_party_roots(paths: tuple[Path, ...]) -> dict[str, set[str]]:
    offenders: dict[str, set[str]] = {}
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        roots = {m.split(".")[0] for node in ast.walk(tree) for m in imported_modules(node, path)}
        if external := roots - _STDLIB:
            offenders[str(path)] = external
    return offenders


def _research_importers(paths: tuple[Path, ...]) -> list[str]:
    found: list[str] = []
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if any(".research" in f".{m}." or m.split(".")[-1] == "research"
                   for m in imported_modules(node, path)):
                found.append(f"{path}:{node.lineno}")
    return found


def test_stage9_imports_no_third_party_module() -> None:
    """ADR-0001: every Stage 9 file, runtime subpackages and harness alike, is stdlib-only."""
    assert _third_party_roots(b.stage9_modules()) == {}


def test_stage9_imports_no_research_package_of_any_stage() -> None:
    """ADR-0008/0080: Stage 9 ships no research/ and imports none (stage2.research included)."""
    assert _research_importers(b.stage9_modules()) == []
    assert not (b.STAGE9_ROOT / "research").exists()


@pytest.mark.parametrize("source", [
    "import numpy as np\n",
    "from requests import get\n",
    "def f():\n    import torch\n",
])
def test_a_third_party_import_in_stage9_is_caught(tmp_path: Path, source: str) -> None:
    leak = _fixture(tmp_path, "stage9/genome/leak.py", source)
    assert list(_third_party_roots((leak,))) == [str(leak)]


@pytest.mark.parametrize("source", [
    "from pocketsec.stage2.research import dtl\n",
    "from ..research import search\n",
    "from . import research\n",
])
def test_a_research_import_in_stage9_is_caught_relative_ones_included(
        tmp_path: Path, source: str) -> None:
    leak = _fixture(tmp_path, "stage9/ontogenesis/leak.py", source)
    assert len(_research_importers((leak,))) == 1


# --- the lazy public surface (pocketsec/stage9/__init__.py) -------------------------------------


def test_importing_stage9_imports_no_stage9_module_and_no_stage5() -> None:
    """The ``__init__`` is a lazy surface: importing the package loads nothing else."""
    probe = ("import sys, pocketsec.stage9; print(sorted(m for m in sys.modules if "
             "m.startswith(('pocketsec.stage9.', 'pocketsec.stage5', 'pocketsec.stage6'))))")
    out = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True,
                         check=True, cwd=b.REPO_ROOT)
    assert out.stdout.strip() == "[]"


def test_the_public_surface_resolves_and_excludes_the_door_the_gate_and_the_labs() -> None:
    import pocketsec.stage9 as stage9

    assert len(stage9.__all__) >= 19
    for name in stage9.__all__:
        assert getattr(stage9, name) is not None, name
    modules = set(stage9._SURFACE.values())
    assert not any(m.endswith(("stage6_exit", ".gate", ".cli")) or ".gate_" in m or ".labs." in m
                   for m in modules), modules
    assert "Stage6Exit" not in stage9.__all__
    with pytest.raises(AttributeError):
        _ = stage9.Stage6Exit
