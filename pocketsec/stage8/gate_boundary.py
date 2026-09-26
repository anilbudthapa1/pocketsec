"""Stage 8's boundary rules (spec §5.1) as predicates the gate RUNS and the tests PROVE.

Stage 8 is a research loop with NO production authority. Its only exit is a typed candidate
handed to Stage 6's quarantine through exactly one module (``adapters/stage6.py``); nothing in
Stage 8 may name Stage 5, a Stage 6 writer, or run a process or a socket. G8.9 and G8.10 must
evaluate these rules in-gate (spec §6) and ``tests/test_stage8_boundary.py`` must prove each
rule catches every form of violation with committed negative fixtures. Two copies of one
checker is how S2-AUTH-01 stayed open in both, so there is ONE copy: this module (the Stage 7
precedent, ``stage7/gate_boundary.py``). The test file imports these predicates and attacks
them; the gate calls :func:`rule_offenders`. The one import resolver is IMPORTED from
``pocketsec.stage2.gate_criteria``, never copied.

**Two declared deviations from the spec's literal text** (recorded in ADR-0071):

* *Rule 7.* The spec defines ``ResearchGovernor.admit(bound, current)`` (D8.18) *and* says a
  called ``.admit`` appears only in the adapter; both cannot hold (``prometheus/generators.py``
  and ``sandbox/integrity.py`` call the governor's). AST cannot see types, so the exemption is
  by CALL SHAPE only: exactly two positional arguments, no keywords, the first a string literal
  naming a ``ResearchBudget`` bound. Stage 6's ``admit(capsule)`` raises ``ContractError`` for a
  string, so a call of that shape can never admit anything; rule 5 already keeps
  ``QuarantineGateway`` unimportable outside the adapter and the labs.
* *Rule 4.* The harness (``gate.py``, ``gate_*.py``, ``cli.py``) may import exactly the shared
  resolver ``pocketsec.stage2.gate_criteria:imported_modules``. The runtime still may not.

**Rules 6 and 14 compare digests, not names.** Stage 6's own repository-wide boundary test
forbids its writer names as string constants anywhere under ``pocketsec/`` outside their owner,
and rule 14 forbids the vault's private attribute name anywhere but the vault, so this checker
holds sha256 digests; the test file (outside ``pocketsec/``) spells the names and pins the
digests to them.

Every check walks the AST, never the text: docstrings *name* the boundary, and naming it is
not crossing it.
"""

from __future__ import annotations

import ast
import hashlib
import sys
from collections.abc import Callable
from dataclasses import dataclass
from functools import cache
from pathlib import Path

from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS
from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage2.gate_criteria import imported_modules
from pocketsec.stage8.governor.budget import ResearchBudget

__all__ = [
    "ADAPTER",
    "ANY",
    "BOUNDARY_RULES",
    "DYNAMIC_IMPORT_FILES",
    "EARLIER_STAGES",
    "FORBIDDEN_BUILTIN_CALLS",
    "FORBIDDEN_DEFINITIONS",
    "FORBIDDEN_DIRECTORIES",
    "FORBIDDEN_MODULE_ROOTS",
    "GOVERNOR_BOUNDS",
    "HARNESS_RESOLVER",
    "LABS",
    "POCKETSEC_ROOT",
    "STAGE2_ALLOW",
    "STAGE6_WRITER_DIGESTS",
    "STAGE7_ADAPTER",
    "STAGE8_ROOT",
    "T3_IMPORTER",
    "UPSTREAM_ALLOW",
    "VAULT_ATTRIBUTE_DIGEST",
    "VAULT_FILE",
    "Target",
    "admit_calls",
    "definition_hits",
    "dynamic_imports",
    "execution_primitives",
    "here",
    "imported_modules",
    "imports_harness",
    "imports_labs",
    "imports_stage5",
    "in_labs",
    "is_harness",
    "is_research",
    "is_stage",
    "is_vault_attribute",
    "is_writer_name",
    "label",
    "modules_under",
    "parse",
    "registry_hits",
    "rel",
    "rule_offenders",
    "stage8_files",
    "t5_offenders",
    "targets",
    "third_party",
    "upstream_violation",
    "vault_hits",
    "writer_hits",
]

POCKETSEC_ROOT = REPO_ROOT / "pocketsec"
STAGE8_ROOT = POCKETSEC_ROOT / "stage8"
EARLIER_STAGES = tuple(f"stage{n}" for n in range(8))
#: T3's one permitted earlier-stage importer of Stage 8; it imports nothing from it today.
T3_IMPORTER = POCKETSEC_ROOT / "stage6" / "capsule" / "quarantine.py"

ANY, LABS = "*", "labs/"
ADAPTER, STAGE7_ADAPTER = "adapters/stage6.py", "adapters/stage7.py"

#: §2.3 rows for Stage 2: module -> the only names any Stage 8 file may import from it.
STAGE2_ALLOW: dict[str, frozenset[str]] = {
    "pocketsec.stage2.encoder.ssir_encoder": frozenset({
        "EncodedTransition", "FEATURE_LAYOUT", "FEATURE_WIDTH", "GROUP_OFFSETS",
        "feature_names"}),
    "pocketsec.stage2.compile_candidates.phi_oracle_candidate": frozenset({
        "PHI_SQUASHED_FEATURE_INDEX", "PHI_ORACLE_SCORER"}),
}
#: The harness's one extra name (deviation 2): the shared resolver.
HARNESS_RESOLVER = ("pocketsec.stage2.gate_criteria", "imported_modules")

#: §2.3 rows for Stages 6 and 7: module -> ((names, files that may import them), ...).
UPSTREAM_ALLOW: dict[str, tuple[tuple[frozenset[str], frozenset[str]], ...]] = {
    "pocketsec.stage6.capsule.experience_capsule": (
        (frozenset({"EncodedStep", "ExperienceCapsuleV1", "MAX_STEPS_PER_CAPSULE",
                    "MAX_EVIDENCE_REFS_PER_CAPSULE", "source_group_of"}), frozenset({ANY})),
        (frozenset({"capsule_from_scenario", "SourceProvenance", "SourceClass", "LabelOrigin",
                    "LabelAssertion", "ContaminationFlag", "reseal_capsule", "PrivacyClass"}),
         frozenset({ADAPTER})),
    ),
    "pocketsec.stage6.memory.semantic": (
        (frozenset({"MotifStep", "match_motif", "motif_pattern_key", "MAX_MOTIF_LENGTH",
                    "is_escalating"}), frozenset({ANY})),
        (frozenset({"genesis_state"}), frozenset({LABS})),
    ),
    "pocketsec.stage6.capsule.quarantine": (
        (frozenset({"QuarantineGateway", "QuarantineVerdict", "QuarantineBucket"}),
         frozenset({ADAPTER, LABS})),
    ),
    "pocketsec.stage6.provenance.trust": ((frozenset({"score_provenance"}),
                                           frozenset({ADAPTER})),),
    "pocketsec.stage6.fossils.lineage": ((frozenset({"KnowledgeLineageDAG"}),
                                          frozenset({LABS})),),
    "pocketsec.stage6.provenance.ledger": ((frozenset({"ProvenanceLedger"}),
                                            frozenset({LABS})),),
    "pocketsec.stage6.resources": (
        (frozenset({"WorkMeter", "WorkBudgetExceeded", "loadavg"}), frozenset({ANY})),
    ),
    "pocketsec.stage7.capsule.knowledge_capsule": (
        (frozenset({"KnowledgeCapsuleV1", "MotifRow", "KnowledgeType", "Stance"}),
         frozenset({STAGE7_ADAPTER})),
    ),
}

#: Rule 6's fourteen Stage 6 writer names, as sha256 hex digests (see the module docstring).
STAGE6_WRITER_DIGESTS = frozenset({
    "ceb17b3db2a86b632593998b544fee78f243d90518f8902f2c2886424bc4e8a6",
    "81cae441cd0ba64a69a51765cac77e9e44a6a0bbac74ce4cc3765a5d0fcccbfd",
    "9c198dece758750642756507730abb76653149d5ba7019a605e04b9f4becc97d",
    "7b7a02d528f6bd2c1a342835e6299a52fe19ad2fd96347ad56051bbc6e88c263",
    "ce90b637ec1d039cad1447a7267d3dbf4a98458b5c16991df78880d75e49cc97",
    "72e8f748a1a1ed082db3310a0cf10e2b0741d55b101c4f83134fa3ab37e8a726",
    "439d62ddc6d74bbcd5f5bcd99dab7cbf0a62e0f68ddfde319a3096fa430cbcb8",
    "e72588cfe2c483222566076e1e3dc8d55d6c7557bda304f06b976ee98fce8cf9",
    "a170e643ce3fbdface29b498e6552a0d3e0068e509781e75ca230a9a7c3330bd",
    "01f6bda31a568151a260fcfc34b19836c3919f99aaa363e229d61539ab092bb1",
    "1c5ddcff8ffbd5ac1e70f0ab53213bc21a1c377e40682e9de81199ab2964bb82",
    "3cd73638e6416deafa22a2d241505661af3dbf36b0da91167dbb29708ae7b43a",
    "39626750017ba4c02c9de8004d0651ad083313dfb04161235b73b342d2940dd2",
    "cb04ef7ca0f24d6440eff133db0a4d61ffebacde18ada6f6826850de403f095b",
})
#: Rule 14: the vault's private attribute name, as a digest (see the module docstring).
VAULT_ATTRIBUTE_DIGEST = "cfd330a6f15404374ab25cb49bc1e862b3b8fa5d5be0ccf7b3929302f4e88a6e"
VAULT_FILE = "sandbox/integrity.py"

FORBIDDEN_MODULE_ROOTS = frozenset({
    "socket", "ssl", "http", "urllib", "ftplib", "smtplib", "socketserver", "select",
    "selectors", "asyncio", "subprocess", "multiprocessing", "ctypes", "pty", "xmlrpc",
    "telnetlib", "pickle", "marshal", "shelve",
})
FORBIDDEN_BUILTIN_CALLS = frozenset({"eval", "exec", "compile", "__import__"})
FORBIDDEN_DIRECTORIES = ("contracts", "benchmark", "experiments", "hypotheses", "research")
FORBIDDEN_DEFINITIONS = frozenset({
    "run_benchmark", "ExperimentRegistry", "Scenario", "Behaviour", "SequenceDataset",
    "QuarantineGateway", "PromotionController",
})
DYNAMIC_IMPORT_FILES = frozenset({
    "core_ids.py", "constitution/discovery.py", "labs/eighty_experiments.py"})
#: The rule-7 exemption (deviation 1): a governor bound name as a literal first argument.
GOVERNOR_BOUNDS = frozenset(ResearchBudget.bound_names())
_REGISTRY_FILE = "registry.jsonl"


# --- the AST machinery (shared by every rule) -------------------------------------------


@dataclass(frozen=True, slots=True)
class Target:
    """One thing a file imports: the resolved module and, for ``from M import n``, the name."""

    module: str
    name: str | None
    lineno: int

    def candidates(self) -> tuple[str, ...]:
        return (self.module,) if self.name is None else (self.module, f"{self.module}.{self.name}")


def modules_under(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts) \
        if root.is_dir() else []


@cache
def parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def rel(path: Path) -> tuple[str, ...]:
    """Parts below the innermost ``pocketsec`` directory (works for tmp fixtures too)."""
    parts = path.resolve().parts
    root = len(parts) - 1 - parts[::-1].index("pocketsec")
    return parts[root + 1:]


def here(path: Path) -> str:
    """``forge/compiler.py`` for ``pocketsec/stage8/forge/compiler.py``."""
    return "/".join(rel(path)[1:])


def label(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return "/".join(rel(path))


def targets(path: Path) -> list[Target]:
    found: list[Target] = []
    for node in ast.walk(parse(path)):
        modules = imported_modules(node, path)
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            found += [Target(modules[0], alias.name, node.lineno) for alias in node.names]
        else:
            found += [Target(m, None, getattr(node, "lineno", 0)) for m in modules]
    return found


def is_stage(module: str, stage: str) -> bool:
    return module == f"pocketsec.{stage}" or module.startswith(f"pocketsec.{stage}.")


def is_harness(parts: tuple[str, ...]) -> bool:
    return len(parts) == 2 and parts[0] == "stage8" and (
        parts[1] in {"gate.py", "cli.py"} or (parts[1].startswith("gate_")
                                              and parts[1].endswith(".py")))


def in_labs(parts: tuple[str, ...]) -> bool:
    return len(parts) > 2 and parts[0] == "stage8" and parts[1] == "labs"


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def is_writer_name(name: str) -> bool:
    """Whether ``name`` is one of rule 6's Stage 6 writer names (compared by digest)."""
    return _digest(name) in STAGE6_WRITER_DIGESTS


def is_vault_attribute(name: str) -> bool:
    return _digest(name) == VAULT_ATTRIBUTE_DIGEST


# --- the rule predicates (pure; the negative fixtures attack each one) ------------------


def third_party(t: Target) -> bool:
    return t.module.split(".")[0] not in set(sys.stdlib_module_names) | {"pocketsec"}


def is_research(t: Target) -> bool:
    """R2, the spec's ``pocketsec.stage*.research*``: a research package in the resolved
    module path (at any depth), or a stage-level ``research*`` name imported from
    ``pocketsec.stageN``, or a name that is exactly ``research``. An imported FUNCTION whose
    name merely starts with "research" (``research_state_bytes_of``) is not a package."""
    parts = t.module.split(".")
    if len(parts) < 2 or parts[0] != "pocketsec" or not parts[1].startswith("stage"):
        return False
    if any(p.startswith("research") for p in parts[2:]):
        return True
    name = t.name or ""
    return name == "research" or (len(parts) == 2 and name.startswith("research"))


def imports_stage5(t: Target) -> bool:
    return any(is_stage(c, "stage5") for c in t.candidates())


def upstream_violation(t: Target, parts: tuple[str, ...]) -> str | None:
    """Rules 4 and 5: why this Stage 8 file may not import this target (None = allowed)."""
    module, name = t.module, t.name
    if module == "pocketsec" and name is not None:
        return None if name in {"stage0", "stage1", "stage8"} else f"package import of {name}"
    if any(is_stage(module, s) for s in ("stage3", "stage4", "stage5")):
        return "Stage 8 consumes nothing from Stages 3, 4 and 5"
    if is_stage(module, "stage2"):
        if is_harness(parts) and (module, name) == HARNESS_RESOLVER:
            return None
        names = STAGE2_ALLOW.get(module)
        if names is None or name is None or name not in names:
            return "Stage 2 beyond the two §2.3 modules and names"
        return None
    if is_stage(module, "stage6") or is_stage(module, "stage7"):
        return _upstream_name_violation(module, name, parts)
    return None


def _upstream_name_violation(module: str, name: str | None, parts: tuple[str, ...]) -> str | None:
    if name is None:
        return "whole-module import: names cannot be checked through it"
    rules = UPSTREAM_ALLOW.get(module)
    if rules is None:
        return f"{module} is not on the §2.3 allow-list"
    where = "/".join(parts[1:])
    for names, files in rules:
        if name not in names:
            continue
        if ANY in files or where in files or ((in_labs(parts) or is_harness(parts))
                                              and LABS in files):
            return None
        return f"{module}:{name} is not permitted in {where}"
    return f"{module}:{name} is not an allow-listed name"


def _node_names(node: ast.AST) -> list[str]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        return [node.attr]
    if isinstance(node, ast.arg):
        return [node.arg]
    if isinstance(node, ast.alias):
        return [node.name.split(".")[-1], node.asname or ""]
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    return []


def writer_hits(path: Path) -> list[tuple[str, int]]:
    """Rule 6: a Stage 6 writer name as a def, Name, Attribute, arg, alias or string."""
    return [(n, getattr(node, "lineno", 0)) for node in ast.walk(parse(path))
            for n in _node_names(node) if n and is_writer_name(n)]


def _governor_shaped(call: ast.Call) -> bool:
    """Deviation 1: ``x.admit("<ResearchBudget bound>", current)`` and nothing else."""
    return (len(call.args) == 2 and not call.keywords
            and isinstance(call.args[0], ast.Constant) and call.args[0].value in GOVERNOR_BOUNDS)


def admit_calls(path: Path) -> list[tuple[str, int]]:
    """Rule 7: every called ``.admit`` outside the adapter, and every ``getattr(x, "admit")``."""
    found: list[tuple[str, int]] = []
    for node in ast.walk(parse(path)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "admit" and \
                here(path) != ADAPTER and not _governor_shaped(node):
            found.append((ast.unparse(func), node.lineno))
        if isinstance(func, ast.Name) and func.id == "getattr" and any(
                isinstance(a, ast.Constant) and a.value == "admit" for a in node.args):
            found.append(("getattr(..., 'admit')", node.lineno))
    return found


def _os_forbidden(name: str) -> bool:
    return name in {"system", "popen"} or name.startswith(("exec", "spawn"))


def execution_primitives(path: Path) -> list[tuple[str, int]]:
    """Rule 8: a network/process/deserialiser module, an ``os`` launcher, or eval/exec."""
    found = [(t.module, t.lineno) for t in targets(path)
             if t.module.split(".")[0] in FORBIDDEN_MODULE_ROOTS
             or (t.module == "os" and t.name is not None and _os_forbidden(t.name))]
    for node in ast.walk(parse(path)):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) \
                and node.value.id == "os" and _os_forbidden(node.attr):
            found.append((f"os.{node.attr}", node.lineno))
        if isinstance(node, ast.Call):
            func = node.func
            called = func.id if isinstance(func, ast.Name) else (
                func.attr if isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name) and func.value.id == "builtins" else None)
            if called in FORBIDDEN_BUILTIN_CALLS:
                found.append((f"{called}()", node.lineno))
    return found


def _is_dataclass(node: ast.ClassDef) -> bool:
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = target.id if isinstance(target, ast.Name) else getattr(target, "attr", None)
        if name == "dataclass":
            return True
    return False


def t5_offenders(path: Path) -> list[tuple[str, int]]:
    """Rule 9: an annotated dataclass field whose lowercased name holds an authority word."""
    found: list[tuple[str, int]] = []
    for node in ast.walk(parse(path)):
        if not isinstance(node, ast.ClassDef) or not _is_dataclass(node):
            continue
        for statement in node.body:
            if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                lowered = statement.target.id.lower()
                if any(word in lowered for word in FORBIDDEN_AUTHORITY_FIELDS):
                    found.append((f"{node.name}.{statement.target.id}", statement.lineno))
    return found


def imports_labs(t: Target) -> bool:
    return any(is_stage(c, "stage8.labs") for c in t.candidates())


def imports_harness(t: Target) -> bool:
    for candidate in t.candidates():
        parts = candidate.split(".")
        if len(parts) == 3 and parts[:2] == ["pocketsec", "stage8"] and (
                parts[2] in {"gate", "cli"} or parts[2].startswith("gate_")):
            return True
    return False


def dynamic_imports(path: Path) -> list[tuple[str, int]]:
    """Rule 13: ``import_module`` calls (any receiver) outside the three permitted files."""
    if here(path) in DYNAMIC_IMPORT_FILES:
        return []
    found = [(t.module, t.lineno) for t in targets(path)
             if t.module == "importlib" and t.name == "import_module"]
    for node in ast.walk(parse(path)):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if name == "import_module":
                found.append(("import_module()", node.lineno))
    return found


def vault_hits(path: Path) -> list[tuple[str, int]]:
    """Rule 14: the vault's private attribute named anywhere but the vault's own module."""
    if here(path) == VAULT_FILE:
        return []
    hits = []
    for node in ast.walk(parse(path)):
        value = (node.attr if isinstance(node, ast.Attribute) else node.id
                 if isinstance(node, ast.Name) else node.value
                 if isinstance(node, ast.Constant) else node.arg
                 if isinstance(node, ast.arg) else None)
        if isinstance(value, str) and is_vault_attribute(value):
            hits.append(("<vault attribute>", getattr(node, "lineno", 0)))
    return hits


def _prose(tree: ast.AST) -> set[int]:
    """ids of string constants that are bare expression statements (docstrings, prose)."""
    return {id(node.value) for node in ast.walk(tree)
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)}


def registry_hits(path: Path) -> list[tuple[str, int]]:
    """Rule 12: the experiment ledger's file name, as a VALUE, outside the harness.
    A docstring naming the file is not a path anything can open."""
    if is_harness(rel(path)):
        return []
    tree = parse(path)
    prose = _prose(tree)
    return [(_REGISTRY_FILE, n.lineno) for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
            and _REGISTRY_FILE in n.value and id(n) not in prose]


def definition_hits(path: Path) -> list[tuple[str, int]]:
    """Rule 12: a second harness, ledger, corpus or gateway type defined under Stage 8."""
    return [(n.name, n.lineno) for n in ast.walk(parse(path))
            if isinstance(n, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            and n.name in FORBIDDEN_DEFINITIONS]


# --- the real tree ------------------------------------------------------------------------


def stage8_files() -> list[Path]:
    return modules_under(STAGE8_ROOT)


def _per_target(check: Callable[[Target, Path], str | None],
                files: list[Path]) -> tuple[str, ...]:
    return tuple(f"{label(p)}:{t.lineno} {'.'.join(filter(None, (t.module, t.name)))} ({why})"
                 for p in files for t in targets(p) if (why := check(t, p)))


def _per_node(check: Callable[[Path], list[tuple[str, int]]],
              files: list[Path]) -> tuple[str, ...]:
    return tuple(f"{label(p)}:{line} {what}" for p in files for what, line in check(p))


def _rule_research() -> tuple[str, ...]:
    found = _per_target(lambda t, _p: "research" if is_research(t) else None, stage8_files())
    exists = (STAGE8_ROOT / "research").exists()
    return found + (("pocketsec/stage8/research/ exists",) if exists else ())


def _rule_one_door() -> tuple[str, ...]:
    found = _per_node(admit_calls, stage8_files())
    adapter = STAGE8_ROOT / ADAPTER
    calls = [n for n in ast.walk(parse(adapter))
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "admit"] if adapter.is_file() else []
    if len(calls) != 1:
        found += (f"{ADAPTER} calls .admit {len(calls)} times, not exactly once",)
    return found


def _rule_labs_and_harness() -> tuple[str, ...]:
    runtime = [p for p in stage8_files() if not in_labs(rel(p)) and not is_harness(rel(p))]
    labs = _per_target(lambda t, _p: "runtime imports labs" if imports_labs(t) else None,
                       runtime)
    outside = [p for p in modules_under(POCKETSEC_ROOT) if not is_harness(rel(p))]
    harness = _per_target(lambda t, _p: "imports the harness" if imports_harness(t) else None,
                          outside)
    return labs + harness


def _rule_earlier_stages() -> tuple[str, ...]:
    earlier = [p for stage in EARLIER_STAGES for p in modules_under(POCKETSEC_ROOT / stage)]
    found = _per_target(lambda t, _p: "earlier stage imports Stage 8"
                        if any(is_stage(c, "stage8") for c in t.candidates()) else None, earlier)
    if not T3_IMPORTER.is_file():
        found += ("T3's one permitted importer moved; re-check the permission",)
    return found


def _rule_second_harness() -> tuple[str, ...]:
    dirs = tuple(f"pocketsec/stage8/**/{name}/ exists" for name in FORBIDDEN_DIRECTORIES
                 if any(p.is_dir() for p in STAGE8_ROOT.rglob(name)))
    return (dirs + _per_node(definition_hits, stage8_files())
            + _per_node(registry_hits, stage8_files()))


def _public_definitions(directory: Path) -> list[str]:
    return [node.name for path in modules_under(directory) if path.name != "__init__.py"
            for node in ast.walk(parse(path))
            if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and not node.name.startswith("_")]


def _rule_no_empty_package() -> tuple[str, ...]:
    found = [f"pocketsec/stage8/{name}/ came back" for name in ("experiments", "hypotheses")
             if (STAGE8_ROOT / name).exists()]
    if not (STAGE8_ROOT / "__init__.py").is_file():
        found.append("pocketsec/stage8/__init__.py is missing")
    packages = sorted(p.parent for p in STAGE8_ROOT.rglob("__init__.py")
                      if "__pycache__" not in p.parts)
    found += [f"{label(d)} exports nothing (ADR-0121)" for d in packages
              if d != STAGE8_ROOT and not _public_definitions(d)]
    found += [f"{label(d)} is a directory but not a package" for d in sorted(STAGE8_ROOT.rglob("*"))
              if d.is_dir() and d.name != "__pycache__" and not (d / "__init__.py").exists()]
    return tuple(found)


def _files(check: Callable[[Path], list[tuple[str, int]]]) -> Callable[[], tuple[str, ...]]:
    return lambda: _per_node(check, stage8_files())


def _imports(check: Callable[[Target, Path], str | None]) -> Callable[[], tuple[str, ...]]:
    return lambda: _per_target(check, stage8_files())


#: Rule number -> (title, whole-tree evaluator). Rule 16 is behavioural and lives in the gate.
BOUNDARY_RULES: dict[int, tuple[str, Callable[[], tuple[str, ...]]]] = {
    1: ("R1 no third-party import", _imports(
        lambda t, _p: "third party" if third_party(t) else None)),
    2: ("R2 no research import or package", _rule_research),
    3: ("T2 no Stage 5 import", _imports(lambda t, _p: "stage5" if imports_stage5(t) else None)),
    4: ("Stage 2/3/4 only through §2.3", _imports(
        lambda t, p: why if (why := upstream_violation(t, rel(p))) and not
        (is_stage(t.module, "stage6") or is_stage(t.module, "stage7")) else None)),
    5: ("Stage 6/7 allow-list", _imports(
        lambda t, p: upstream_violation(t, rel(p))
        if is_stage(t.module, "stage6") or is_stage(t.module, "stage7") else None)),
    6: ("no Stage 6 writer name", _files(writer_hits)),
    7: ("the one door to admit", _rule_one_door),
    8: ("no execution/network primitive", _files(execution_primitives)),
    9: ("T5 no authority-named dataclass field", _files(t5_offenders)),
    10: ("runtime never imports labs or harness", _rule_labs_and_harness),
    11: ("nothing earlier imports Stage 8", _rule_earlier_stages),
    12: ("no second harness, ledger, corpus type or registry path", _rule_second_harness),
    13: ("dynamic imports only in the three named files", _files(dynamic_imports)),
    14: ("the vault attribute only in the vault", _files(vault_hits)),
    15: ("no empty package (ADR-0121)", _rule_no_empty_package),
}


def rule_offenders(rule: int) -> tuple[str, ...]:
    """Every offender of one §5.1 rule over the real tree. A tree with no Stage 8 module
    cannot be judged, and says so rather than reporting zero offenders."""
    if not stage8_files():
        return ("pocketsec/stage8/ holds no modules: the rule would pass vacuously",)
    return BOUNDARY_RULES[rule][1]()
