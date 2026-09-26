"""Stage 7's dependency and authority boundary (spec §5.1, ADR-0001/0060/0061/0063/0121).

Stage 7 is where foreign knowledge arrives, so its import graph IS the security boundary:
the only way from a peer's bytes to local trusted state must be Stage 6's quarantine,
reached through exactly one module (``hivelock/stage6_bridge.py``), and nothing in Stage 7
may be able to name Stage 5 or a Stage 6 writer. These rules are checked here, for Stage 7
only. ``tests/test_repository_structure.py`` and ``tests/test_stage6_boundary.py`` belong to
other waves: their *technique* is reused and the files are left untouched.

The thirteen rules of spec §5.1:

1. **R1 / ADR-0001.** Only stdlib roots or ``pocketsec``, including deferred imports.
2. **R2.** No ``pocketsec.stage*.research*`` import; ``pocketsec/stage7/research/`` absent.
3. **T2.** No import of ``pocketsec.stage5`` in any form (relative, deferred,
   ``from pocketsec import stage5``).
4. **Stage 3/4: nothing. Stage 2: only ``encoder.ssir_encoder``.**
5. **The Stage 6 allow-list of §2.3** at the granularity of module, imported NAME and
   importing FILE. A whole-module ``import pocketsec.stage6.x`` is refused everywhere, since
   names cannot be checked through it.
6. **Stage 6 writer names** appear nowhere in Stage 7 as a Name, Attribute, def, arg,
   import alias or string constant.
7. **The one door.** A called ``.admit`` appears only in ``hivelock/stage6_bridge.py``.
8. **No execution or network primitive.**
9. **T5.** No ``@dataclass`` field whose lowercased name contains an authority word.
10. **Runtime never imports labs**; nothing outside the integrator's harness imports it.
11. **T7.** No module under ``pocketsec/stage0`` … ``stage6`` imports Stage 7.
12. **No second harness, ledger, contracts or corpus type.**
13. **No empty package (ADR-0121)**, and ``collective/`` does not return.

**Two declared exemptions, rule 7 (a deviation from the spec's literal text, reported).** The
spec names ``ReplayGuard.admit`` (D7.4) *and* says a called ``.admit`` appears only in the
bridge; the two cannot both hold, because ``hivelock/ingress.py`` must call the replay guard's
``admit`` to record a capsule it has checked, and a lab replaying S7X-04 must do the same.
AST cannot see types, so each exemption covers only a receiver that is *provably* a replay
guard: (a) ``self._replay.admit(...)`` in ``hivelock/ingress.py`` alone, and (b) a local name
bound exactly once, directly, to ``ReplayGuard(...)`` in the same function. Any other
receiver (a parameter, an attribute, a name rebound to anything else), any other file, and
any ``getattr(x, "admit")`` is an offender. The stronger guarantee is rule 5: no module but
the bridge (and the labs) can even import ``QuarantineGateway``.

Every check walks the AST, never the text: docstrings *name* the boundary, and naming it is
not crossing it. The import resolver is **imported** from ``pocketsec.stage2.gate_criteria``,
never copied (S2-AUTH-01).

**The predicates live in** ``pocketsec/stage7/gate_boundary.py`` **(integrator).** G7.1(a) and
G7.2 evaluate these rules in-gate, and two copies of one checker is how S2-AUTH-01 stayed
open in both; so the gate and this file share one implementation, and the negative fixtures
below attack the very predicates the gate runs. The harness files alone may import the
shared resolver (the one name §2.3 did not give them; reported, see that module).
"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

import pytest

from pocketsec.stage2.gate_criteria import imported_modules
from pocketsec.stage7.gate_boundary import (
    BRIDGE,
    DELETED_DIRECTORIES,
    EARLIER_STAGES,
    FORBIDDEN_DEFINITIONS,
    FORBIDDEN_DIRECTORIES,
    POCKETSEC_ROOT,
    STAGE2_ALLOWED,
    STAGE6_WRITER_DIGESTS,
    STAGE7_ROOT,
    T3_IMPORTER,
    Target,
    admit_calls,
    execution_primitives,
    imports_harness,
    imports_labs,
    imports_stage5,
    is_research,
    is_writer_name,
    rule_offenders,
    t5_offenders,
    third_party,
    upstream_violation,
    writer_hits,
)
from pocketsec.stage7.gate_boundary import imported_modules as gate_resolver
from pocketsec.stage7.gate_boundary import in_labs as _in_labs
from pocketsec.stage7.gate_boundary import is_harness as _is_harness
from pocketsec.stage7.gate_boundary import is_stage as _is_stage
from pocketsec.stage7.gate_boundary import label as _label
from pocketsec.stage7.gate_boundary import modules_under as _modules
from pocketsec.stage7.gate_boundary import parse as _parse
from pocketsec.stage7.gate_boundary import rel as _rel
from pocketsec.stage7.gate_boundary import targets as _targets


#: Spec §5.1 rule 6, spelled out HERE (tests/ is outside pocketsec/, where Stage 6's own
#: boundary test forbids these names as string constants); the checker holds their digests.
STAGE6_WRITER_NAMES = frozenset({
    "LearningPromotionController", "TrustedMind", "EvolutionChamber", "ShadowMind",
    "CanaryEvaluator", "_install_trusted", "_trusted_state", "with_changes", "promote_trusted",
    "rollback_learning", "_issue_verdict", "_issued_verdicts",
})


def _stage7_files() -> list[Path]:
    files = _modules(STAGE7_ROOT)
    assert files, "pocketsec/stage7/ holds no modules: every rule would pass vacuously"
    return files


def _offenders(check, files: list[Path]) -> list[str]:  # type: ignore[no-untyped-def]
    return [f"{_label(p)}:{line} {what}" for p in files for what, line in check(p)]


# --- sanity ---------------------------------------------------------------------------------------


def test_the_import_resolver_is_the_shared_one_not_a_copy() -> None:
    assert imported_modules.__module__ == "pocketsec.stage2.gate_criteria"
    assert gate_resolver is imported_modules  # the gate's checker resolves with the same one


@pytest.mark.parametrize("rule", [1, 2, 3, 5, 6, 7, 8, 9, 10, 11])
def test_the_gate_evaluates_the_same_rules_and_finds_no_offender(rule: int) -> None:
    """The in-gate evaluation (G7.1(a), G7.2) over the real tree agrees with this file."""
    assert rule_offenders(rule) == ()


# --- rules 1 and 2 --------------------------------------------------------------------------------


def test_stage7_has_no_third_party_imports() -> None:
    offenders = [
        f"{_label(p)}:{t.lineno} {t.module}"
        for p in _stage7_files() for t in _targets(p) if third_party(t)
    ]
    assert not offenders, f"third-party imports in Stage 7 (ADR-0001): {offenders}"


def test_stage7_never_imports_research_code_and_ships_no_research_package() -> None:
    assert not (STAGE7_ROOT / "research").exists()
    offenders = [
        f"{_label(p)}:{t.lineno} {t.module}"
        for p in _stage7_files() for t in _targets(p) if is_research(t)
    ]
    assert not offenders, f"Stage 7 importing research code: {offenders}"


# --- rule 3 ---------------------------------------------------------------------------------------


def test_no_stage7_module_imports_stage5() -> None:
    """T2: Stage 5 is the only stage that touches privilege; Stage 7 cannot even name it."""
    offenders = [
        f"{_label(p)}:{t.lineno} {'.'.join(filter(None, (t.module, t.name)))}"
        for p in _stage7_files() for t in _targets(p) if imports_stage5(t)
    ]
    assert not offenders, f"Stage 7 importing Stage 5: {offenders}"


# --- rules 4 and 5 --------------------------------------------------------------------------------


def test_stage7_imports_upstream_only_through_the_allow_list() -> None:
    offenders = [
        f"{_label(p)}:{t.lineno} {t.module}:{t.name} ({reason})"
        for p in _stage7_files() for t in _targets(p)
        if (reason := upstream_violation(t, _rel(p))) is not None
    ]
    assert not offenders, f"Stage 7 imports outside the §2.3 allow-list: {offenders}"


def test_the_allow_list_permits_exactly_the_seams_it_must() -> None:
    """Both directions: a predicate refusing everything would pass the rule vacuously."""
    runtime = ("stage7", "echo", "inference.py")
    bridge = ("stage7", "hivelock", "stage6_bridge.py")
    labs = ("stage7", "labs", "simulated_fleet.py")
    harness = ("stage7", "gate_measured.py")
    allowed = [
        (Target("pocketsec.stage6.memory.semantic", "match_motif", 1), runtime),
        (Target("pocketsec.stage6.resources", "WorkMeter", 1), runtime),
        (Target(STAGE2_ALLOWED, "FEATURE_WIDTH", 1), runtime),
        (Target("pocketsec.stage2.encoder", "ssir_encoder", 1), runtime),
        (Target("pocketsec.stage6.fleet.package", "package_to_capsules", 1), bridge),
        (Target("pocketsec.stage6.capsule.quarantine", "QuarantineGateway", 1), labs),
        (Target("pocketsec.stage6.memory.semantic", "genesis_state", 1), harness),
        (Target("pocketsec.stage2.gate_criteria", "imported_modules", 1), harness),
    ]
    for target, rel in allowed:
        assert upstream_violation(target, rel) is None, (target, rel)
    refused = [
        (Target("pocketsec.stage6.memory.semantic", "genesis_state", 1), runtime),
        (Target("pocketsec.stage6.memory.semantic", None, 1), labs),  # whole-module import
        (Target("pocketsec.stage6.fleet.package", "package_to_capsules", 1), runtime),
        (Target("pocketsec.stage6.capsule.quarantine", "QuarantineGateway", 1), runtime),
        (Target("pocketsec.stage6.promotion.controller", "LearningPromotionController", 1), labs),
        (Target("pocketsec.stage6.capsule", "quarantine", 1), bridge),
        (Target("pocketsec.stage2.gate_criteria", "imported_modules", 1), runtime),
        (Target("pocketsec.stage2.gate_criteria", "imported_modules", 1), labs),
        (Target("pocketsec.stage2.gate_criteria", "research_imports", 1), harness),
        (Target("pocketsec.stage3.cells.schema", "Cell", 1), labs),
        (Target("pocketsec.stage4.worlds", "world", 1), runtime),
        (Target("pocketsec", "stage6", 1), runtime),
    ]
    for target, rel in refused:
        assert upstream_violation(target, rel) is not None, (target, rel)


# --- rule 6 ---------------------------------------------------------------------------------------


def test_no_stage7_module_names_a_stage6_writer() -> None:
    """NO_DIRECT_TRUSTED_WRITE: Stage 7 cannot reach a writer it cannot name, including by
    ``getattr(x, "<name>")`` (a string constant equal to the name counts)."""
    offenders = _offenders(writer_hits, _stage7_files())
    assert not offenders, f"Stage 7 names a Stage 6 writer: {offenders}"


# --- rule 7 ---------------------------------------------------------------------------------------


def test_the_bridge_is_the_one_door_to_admit() -> None:
    offenders = _offenders(admit_calls, _stage7_files())
    assert not offenders, f"a called .admit outside {BRIDGE}: {offenders}"
    bridge = STAGE7_ROOT / BRIDGE
    bridge_calls = [
        n for n in ast.walk(_parse(bridge))
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "admit"
    ]
    assert len(bridge_calls) == 1, "the bridge must call gateway.admit exactly once, in one place"


# --- rule 8 ---------------------------------------------------------------------------------------


def test_stage7_has_no_execution_or_network_primitive() -> None:
    offenders = _offenders(execution_primitives, _stage7_files())
    assert not offenders, f"execution/network primitives in Stage 7: {offenders}"


# --- rule 9 ---------------------------------------------------------------------------------------


def test_no_stage7_dataclass_field_carries_an_authority_word() -> None:
    offenders = _offenders(t5_offenders, _stage7_files())
    assert not offenders, f"T5 offenders in Stage 7: {offenders}"


# --- rule 10 --------------------------------------------------------------------------------------


def test_the_runtime_never_imports_the_labs_or_the_harness() -> None:
    labs_offenders = [
        f"{_label(p)}:{t.lineno} {t.module}"
        for p in _stage7_files()
        if not _in_labs(_rel(p)) and not _is_harness(_rel(p))
        for t in _targets(p) if imports_labs(t)
    ]
    assert not labs_offenders, f"Stage 7 runtime importing labs: {labs_offenders}"
    harness_offenders = [
        f"{_label(p)}:{t.lineno} {t.module}"
        for p in _modules(POCKETSEC_ROOT)
        if not _is_harness(_rel(p))
        for t in _targets(p) if imports_harness(t)
    ]
    assert not harness_offenders, f"modules importing the Stage 7 harness: {harness_offenders}"


# --- rule 11 --------------------------------------------------------------------------------------


def test_no_earlier_stage_depends_on_stage7() -> None:
    """T7: local detection (Stages 0-6) cannot depend on the collective fabric. T3 permits
    exactly one importer, Stage 6's ``capsule/quarantine.py``, and today it imports nothing."""
    offenders = [
        f"{_label(p)}:{t.lineno} {t.module}"
        for stage in EARLIER_STAGES
        for p in _modules(POCKETSEC_ROOT / stage)
        for t in _targets(p)
        if any(_is_stage(c, "stage7") for c in t.candidates())
    ]
    assert not offenders, f"earlier stages importing Stage 7: {offenders}"
    quarantine = POCKETSEC_ROOT.joinpath(*T3_IMPORTER)
    assert quarantine.exists(), "T3's one permitted importer moved; re-check the permission"


# --- rules 12 and 13 ------------------------------------------------------------------------------


@pytest.mark.parametrize("name", FORBIDDEN_DIRECTORIES)
def test_stage7_holds_no_second_contracts_harness_or_ledger_directory(name: str) -> None:
    assert not [p for p in STAGE7_ROOT.rglob(name) if p.is_dir()], f"stage7/**/{name}/ exists"


def test_stage7_defines_no_second_harness_ledger_or_corpus_type() -> None:
    offenders = [
        f"{_label(p)}:{node.lineno} {node.name}"
        for p in _stage7_files()
        for node in ast.walk(_parse(p))
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in FORBIDDEN_DEFINITIONS
    ]
    assert not offenders, f"a second harness/ledger/corpus/gateway type in Stage 7: {offenders}"


def test_no_stage7_package_is_empty_and_collective_is_gone() -> None:
    for name in DELETED_DIRECTORIES:
        assert not (STAGE7_ROOT / name).exists(), f"pocketsec/stage7/{name}/ came back (ADR-0121)"
    packages = sorted(
        p.parent for p in STAGE7_ROOT.rglob("__init__.py") if "__pycache__" not in p.parts
    )
    assert packages, "no Stage 7 package has an __init__.py; this rule would pass vacuously"
    empty = [
        _label(directory) for directory in packages
        if not [
            node.name
            for path in _modules(directory) if path.name != "__init__.py"
            for node in ast.walk(_parse(path))
            if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and not node.name.startswith("_")
        ]
    ]
    assert not empty, f"Stage 7 packages exporting nothing: {empty}"
    orphans = [
        _label(d) for d in sorted(STAGE7_ROOT.rglob("*"))
        if d.is_dir() and d.name != "__pycache__" and not (d / "__init__.py").exists()
    ]
    assert not orphans, f"directories under stage7/ that are not packages: {orphans}"


# --- the committed negative fixtures --------------------------------------------------------------

#: ``(file position under pocketsec/, source, rule)``. Each file sits at a real position so
#: every relative level resolves as it would in the package.
_HL, _ECHO, _GRAPH = ("stage7", "hivelock"), ("stage7", "echo"), ("stage7", "graph")
NEGATIVE_FIXTURES = (
    (("stage7", "leak.py"), "from ..stage5 import x\n", "stage5"),
    (("stage7", "leak.py"), "from pocketsec import stage5\n", "stage5"),
    ((*_HL, "leak.py"), "def f():\n    import pocketsec.stage5.executor\n", "stage5"),
    (("stage7", "leak.py"), "from . import research\n", "research"),
    (("stage7", "echo", "leak.py"), "from ..research import solver\n", "research"),
    ((*_HL, "leak.py"), "from ...stage6.promotion import controller\n", "allow_list"),
    ((*_ECHO, "leak.py"), "from pocketsec.stage6.memory.semantic import genesis_state\n",
     "allow_list"),
    (("stage7", "echo", "leak.py"), "import pocketsec.stage6.memory.semantic\n", "allow_list"),
    ((*_ECHO, "leak.py"), "from pocketsec.stage6.fleet.package import package_to_capsules\n",
     "allow_list"),
    (("stage7", "echo", "leak.py"), "from ...stage3.cells import schema\n", "allow_list"),
    ((*_GRAPH, "leak.py"), "def f(x):\n    return getattr(x, '_install_trusted')\n", "writer"),
    ((*_GRAPH, "leak.py"), "from pocketsec.stage6.shadow.mind import ShadowMind as M\n", "writer"),
    (("stage7", "echo", "leak.py"), "def f(gateway, c):\n    return gateway.admit(c)\n", "admit"),
    ((*_HL, "ingress.py"), "def f(self, c):\n    return self._gateway.admit(c)\n", "admit"),
    (("stage7", "echo", "leak.py"), "def f(g, c):\n    return getattr(g, 'admit')(c)\n", "admit"),
    ((*_ECHO, "leak.py"), "def f(gateway, c):\n    guard = ReplayGuard()\n    guard = gateway\n"
     "    return guard.admit(c)\n", "admit"),
    ((*_ECHO, "leak.py"), "def f(guard, c):\n    return guard.admit(c)\n", "admit"),
    ((*_ECHO, "leak.py"), "def f(c):\n    g = QuarantineGateway()\n    return g.admit(c)\n",
     "admit"),
    (("stage7", "echo", "leak.py"), "import subprocess\n", "execution"),
    ((*_ECHO, "leak.py"), "import os\ndef f():\n    os.execv('/bin/sh', [])\n", "execution"),
    (("stage7", "echo", "leak.py"), "from urllib.request import urlopen\n", "execution"),
    (("stage7", "echo", "leak.py"),
     "from dataclasses import dataclass\n@dataclass\nclass R:\n    redaction_count: int\n", "t5"),
    (("stage7", "echo", "leak.py"), "from ..labs import simulated_fleet\n", "labs"),
    (("stage7", "echo", "leak.py"), "from pocketsec.stage7 import labs\n", "labs"),
    (("stage7", "echo", "leak.py"), "import numpy\n", "third_party"),
)


def _write(tmp_path: Path, where: tuple[str, ...], source: str) -> Path:
    package = tmp_path.joinpath("pocketsec", *where[:-1])
    package.mkdir(parents=True, exist_ok=True)
    path = package / where[-1]
    path.write_text(source, encoding="utf-8")
    return path


def _caught(rule: str, path: Path) -> bool:
    targets = _targets(path)
    rel = _rel(path)
    checks = {
        "stage5": lambda: any(imports_stage5(t) for t in targets),
        "research": lambda: any(is_research(t) for t in targets),
        "allow_list": lambda: any(upstream_violation(t, rel) for t in targets),
        "writer": lambda: bool(writer_hits(path)),
        "admit": lambda: bool(admit_calls(path)),
        "execution": lambda: bool(execution_primitives(path)),
        "t5": lambda: bool(t5_offenders(path)),
        "labs": lambda: not _in_labs(rel) and any(imports_labs(t) for t in targets),
        "third_party": lambda: any(third_party(t) for t in targets),
    }
    return checks[rule]()


@pytest.mark.parametrize(("where", "source", "rule"), NEGATIVE_FIXTURES)
def test_a_boundary_violation_is_caught_whatever_its_form(
    where: tuple[str, ...], source: str, rule: str, tmp_path: Path
) -> None:
    assert _caught(rule, _write(tmp_path, where, source)), (rule, source)


def test_the_negative_fixture_covers_every_form_named_by_the_spec() -> None:
    sources = {source for _, source, _ in NEGATIVE_FIXTURES}
    assert "from ..stage5 import x\n" in sources
    assert "from . import research\n" in sources
    assert "from ...stage6.promotion import controller\n" in sources
    assert any("getattr(x, '_install_trusted')" in s for s in sources)
    assert {rule for *_, rule in NEGATIVE_FIXTURES} == {
        "stage5", "research", "allow_list", "writer", "admit", "execution", "t5", "labs",
        "third_party",
    }


def test_the_admit_exemption_is_exactly_one_receiver_in_one_file(tmp_path: Path) -> None:
    ingress = _write(tmp_path, ("stage7", "hivelock", "ingress.py"),
                     "def f(self, c):\n    self._replay.admit(c)\n")
    elsewhere = _write(tmp_path, ("stage7", "echo", "replay.py"),
                       "def f(self, c):\n    self._replay.admit(c)\n")
    assert admit_calls(ingress) == [] and admit_calls(elsewhere) != []
    fresh = _write(tmp_path, ("stage7", "labs", "replay_lab.py"),
                   "def f(c):\n    guard = ReplayGuard()\n    guard.admit(c)\n")
    assert admit_calls(fresh) == []
    bridge = _write(tmp_path, ("stage7", "hivelock", "stage6_bridge.py"),
                    "def f(self, c):\n    return self._gateway.admit(c)\n")
    assert admit_calls(bridge) == []


def test_the_checker_matches_exactly_the_spec_writer_names() -> None:
    """The checker holds digests (Stage 6's own rule forbids spelling the names under
    pocketsec/); they must be exactly the spec's twelve names, no more, no fewer."""
    assert {hashlib.sha256(n.encode()).hexdigest() for n in STAGE6_WRITER_NAMES} == \
        STAGE6_WRITER_DIGESTS
    assert all(is_writer_name(n) for n in STAGE6_WRITER_NAMES)
    assert not any(is_writer_name(n) for n in ("TrustedMind_", "trustedmind", "install_trusted"))


def test_the_writer_rule_ignores_docstrings_that_name_the_boundary(tmp_path: Path) -> None:
    """Naming the boundary in prose is not crossing it; an exact string constant is."""
    prose = _write(tmp_path, ("stage7", "echo", "prose.py"),
                   '"""Never calls TrustedMind or _install_trusted."""\n')
    assert writer_hits(prose) == []
