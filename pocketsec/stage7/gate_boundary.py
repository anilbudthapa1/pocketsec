"""Stage 7's boundary rules (spec §5.1) as predicates the gate RUNS and the tests PROVE.

Stage 7 is where foreign knowledge arrives, so its import graph is the security boundary:
the only way from a peer's bytes to local trusted state is Stage 6's quarantine, reached
through exactly one module (``hivelock/stage6_bridge.py``), and nothing in Stage 7 may be
able to name Stage 5 or a Stage 6 writer. G7.1(a) and G7.2 must evaluate these rules
in-gate (spec §6), and ``tests/test_stage7_boundary.py`` must prove each rule catches every
form of violation with committed negative fixtures. Two copies of one checker is how
S2-AUTH-01 stayed open in both, so there is ONE copy: this module. The test file imports
these predicates and attacks them; the gate calls :func:`rule_offenders`.

**One declared permission for the harness (reported deviation from §2.3).** The shared
import resolver ``pocketsec.stage2.gate_criteria.imported_modules`` must be imported, never
copied (S2-AUTH-01), yet §2.3 gives the harness only the ``labs/`` allowances. The gate
cannot evaluate rule 5 without resolving relative imports, so the harness files (``gate.py``,
``gate_*.py``, ``cli.py``) — and only they — may import exactly that one name. The runtime
still may not (rule 4), and rule 10 keeps every runtime module from importing the harness.

**Two declared exemptions to rule 7** (a deviation from the spec's literal text): the spec
names ``ReplayGuard.admit`` (D7.4) *and* says a called ``.admit`` appears only in the bridge;
both cannot hold. AST cannot see types, so each exemption covers only a receiver that is
provably a replay guard: (a) ``self._replay.admit(...)`` in ``hivelock/ingress.py`` alone,
and (b) a local name bound exactly once, directly, to ``ReplayGuard(...)`` in the same
function. Anything else — a parameter, an attribute, a rebound name, another file,
``getattr(x, "admit")`` — is an offender.

**Rule 6 compares digests, not names.** Stage 6's own repository-wide boundary test forbids
its writer names as string constants anywhere under ``pocketsec/`` outside their owner, so
this checker holds their sha256 digests; the test file (outside ``pocketsec/``) spells the
names and pins the digests to them.

**Rule 12 (review findings S7-AUTH-03 / F1): no dynamic import or code execution.** Rules 3,
5, 6 and 8 see only ``Import``/``ImportFrom`` nodes and literal names, so
``importlib.import_module(<composed string>)``, ``__import__``, ``eval``, ``exec``,
``compile`` and a deserialiser (``pickle``/``marshal``/``shelve``) would reach Stage 5 or a
Stage 6 writer invisibly. Rule 12 flags every such call or import in every Stage 7 file,
except the declared (file, function) sites in ``DYNAMIC_IMPORT_EXEMPTIONS``, each of which
imports only a name it validated against a pocketsec.stage7 pattern or table. What AST still
cannot see (``getattr`` on a module object reached some other way) stays a residual. Rule
7's fresh-``ReplayGuard`` exemption no longer applies in a file that REBINDS the name
``ReplayGuard`` (a local def, class, parameter, assignment or foreign import alias): shadowing
the name used to exempt any ``.admit`` call (F1).

Every check walks the AST, never the text: docstrings *name* the boundary, and naming it is
not crossing it.
"""

from __future__ import annotations

import ast
import hashlib
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from functools import cache
from pathlib import Path

from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS
from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage2.gate_criteria import imported_modules

__all__ = [
    "ADMIT_EXEMPTION",
    "DYNAMIC_IMPORT_EXEMPTIONS",
    "ANY",
    "BOUNDARY_RULES",
    "BRIDGE",
    "DELETED_DIRECTORIES",
    "EARLIER_STAGES",
    "FORBIDDEN_DEFINITIONS",
    "FORBIDDEN_DIRECTORIES",
    "FORBIDDEN_MODULE_ROOTS",
    "HARNESS_RESOLVER",
    "LABS",
    "POCKETSEC_ROOT",
    "STAGE2_ALLOWED",
    "STAGE6_ALLOW",
    "STAGE6_WRITER_DIGESTS",
    "STAGE7_ROOT",
    "T3_IMPORTER",
    "Target",
    "admit_calls",
    "execution_primitives",
    "imported_modules",
    "imports_harness",
    "imports_labs",
    "imports_stage5",
    "in_labs",
    "is_harness",
    "is_research",
    "is_stage",
    "is_writer_name",
    "dynamic_code",
    "label",
    "modules_under",
    "parse",
    "rel",
    "rule_offenders",
    "stage7_files",
    "t5_offenders",
    "targets",
    "third_party",
    "upstream_violation",
    "writer_hits",
]

POCKETSEC_ROOT = REPO_ROOT / "pocketsec"
STAGE7_ROOT = POCKETSEC_ROOT / "stage7"
EARLIER_STAGES = tuple(f"stage{n}" for n in range(7))

ANY = "*"
LABS = "labs/"
BRIDGE = "hivelock/stage6_bridge.py"

#: §2.3, verbatim: module -> ((names, files that may import them), ...). ``ANY`` = any Stage 7
#: file; ``LABS`` = any file under ``labs/``. The integrator's harness gets the labs allowances.
STAGE6_ALLOW: dict[str, tuple[tuple[frozenset[str], frozenset[str]], ...]] = {
    "pocketsec.stage6.capsule.experience_capsule": (
        (frozenset({"EncodedStep", "ExperienceCapsuleV1", "PrivacyClass", "SECRET_PATTERN",
                    "source_group_of"}), frozenset({ANY})),
    ),
    "pocketsec.stage6.memory.semantic": (
        (frozenset({"MotifStep", "match_motif", "motif_pattern_key", "MAX_MOTIF_LENGTH",
                    "context_id_for"}), frozenset({ANY})),
        (frozenset({"genesis_state"}), frozenset({LABS})),
    ),
    "pocketsec.stage6.export.learning_record": (
        (frozenset({"LearningRecordV1"}), frozenset({"capsule/compiler.py"})),
    ),
    "pocketsec.stage6.fleet.package": (
        (frozenset({"KnowledgePackageV1", "KNOWLEDGE_PACKAGE_V1_VERSION", "sign_package",
                    "verify_package", "package_to_capsules"}), frozenset({BRIDGE})),
        (frozenset({"MIN_KEY_BYTES"}), frozenset({"identity/integrity.py", BRIDGE})),
    ),
    "pocketsec.stage6.capsule.quarantine": (
        (frozenset({"QuarantineGateway", "QuarantineVerdict", "QuarantineBucket"}),
         frozenset({BRIDGE, LABS})),
    ),
    "pocketsec.stage6.fossils.lineage": (
        (frozenset({"KnowledgeLineageDAG"}), frozenset({BRIDGE, LABS})),
    ),
    "pocketsec.stage6.provenance.ledger": ((frozenset({"ProvenanceLedger"}), frozenset({LABS})),),
    "pocketsec.stage6.resources": (
        (frozenset({"WorkMeter", "WorkBudgetExceeded", "loadavg"}), frozenset({ANY})),
    ),
}
STAGE2_ALLOWED = "pocketsec.stage2.encoder.ssir_encoder"
#: The harness's one extra name (module docstring): the shared resolver, never a copy.
HARNESS_RESOLVER = ("pocketsec.stage2.gate_criteria", "imported_modules")
#: Rule 6's twelve Stage 6 writer names, as sha256 hex digests. Digests, not names: Stage 6's
#: own boundary test forbids those names as string constants anywhere under pocketsec/ outside
#: their owner, so a checker that spelled them would itself offend. Membership by digest is
#: exact; tests/test_stage7_boundary.py (outside pocketsec/) pins this set to the spec's names.
STAGE6_WRITER_DIGESTS = frozenset({
    "01f6bda31a568151a260fcfc34b19836c3919f99aaa363e229d61539ab092bb1",
    "1c5ddcff8ffbd5ac1e70f0ab53213bc21a1c377e40682e9de81199ab2964bb82",
    "39626750017ba4c02c9de8004d0651ad083313dfb04161235b73b342d2940dd2",
    "3cd73638e6416deafa22a2d241505661af3dbf36b0da91167dbb29708ae7b43a",
    "439d62ddc6d74bbcd5f5bcd99dab7cbf0a62e0f68ddfde319a3096fa430cbcb8",
    "7b7a02d528f6bd2c1a342835e6299a52fe19ad2fd96347ad56051bbc6e88c263",
    "81cae441cd0ba64a69a51765cac77e9e44a6a0bbac74ce4cc3765a5d0fcccbfd",
    "a170e643ce3fbdface29b498e6552a0d3e0068e509781e75ca230a9a7c3330bd",
    "cb04ef7ca0f24d6440eff133db0a4d61ffebacde18ada6f6826850de403f095b",
    "ce90b637ec1d039cad1447a7267d3dbf4a98458b5c16991df78880d75e49cc97",
    "ceb17b3db2a86b632593998b544fee78f243d90518f8902f2c2886424bc4e8a6",
    "e72588cfe2c483222566076e1e3dc8d55d6c7557bda304f06b976ee98fce8cf9",
})
FORBIDDEN_MODULE_ROOTS = frozenset({
    "socket", "ssl", "http", "urllib", "ftplib", "smtplib", "socketserver", "select",
    "selectors", "asyncio", "subprocess", "multiprocessing", "ctypes", "pty", "xmlrpc",
    "telnetlib",
})
FORBIDDEN_OS_CALLS = frozenset({"system", "popen"})
FORBIDDEN_OS_PREFIXES = ("exec", "spawn")
FORBIDDEN_DIRECTORIES = ("contracts", "benchmark", "experiments", "research")
FORBIDDEN_DEFINITIONS = frozenset({
    "run_benchmark", "ExperimentRegistry", "Scenario", "Behaviour", "QuarantineGateway",
    "PromotionController",
})
DELETED_DIRECTORIES = ("collective",)
#: The one exemption to rule 7 (see the module docstring): (file, receiver attribute).
ADMIT_EXEMPTION = ("hivelock/ingress.py", "_replay")
#: T3: the one earlier-stage module ever permitted to import Stage 7 (and today it does not).
T3_IMPORTER = ("stage6", "capsule", "quarantine.py")


@dataclass(frozen=True, slots=True)
class Target:
    """One thing a file imports: the resolved module and, for ``from M import n``, the name."""

    module: str
    name: str | None
    lineno: int

    def candidates(self) -> tuple[str, ...]:
        """Every dotted path this import could bind: ``M`` and ``M.n``."""
        return (self.module,) if self.name is None else (self.module, f"{self.module}.{self.name}")


def modules_under(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


@cache
def parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def rel(path: Path) -> tuple[str, ...]:
    """The path's parts below its innermost ``pocketsec`` directory (works for fixtures)."""
    parts = path.resolve().parts
    root = len(parts) - 1 - parts[::-1].index("pocketsec")
    return parts[root + 1 :]


def _stage7_rel(path: Path) -> str:
    """``hivelock/ingress.py`` for ``pocketsec/stage7/hivelock/ingress.py``."""
    return "/".join(rel(path)[1:])


def label(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return "/".join(rel(path))


def targets(path: Path) -> list[Target]:
    """Every import of the file, resolved by the shared resolver, at name granularity."""
    found: list[Target] = []
    for node in ast.walk(parse(path)):
        modules = imported_modules(node, path)
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            found += [Target(modules[0], alias.name, node.lineno) for alias in node.names]
        else:  # `import a.b` or `from . import x` (the resolver already made x a module)
            found += [Target(module, None, getattr(node, "lineno", 0)) for module in modules]
    return found


def is_harness(rel_parts: tuple[str, ...]) -> bool:
    return len(rel_parts) == 2 and rel_parts[0] == "stage7" and (
        rel_parts[1] in {"gate.py", "cli.py"}
        or (rel_parts[1].startswith("gate_") and rel_parts[1].endswith(".py"))
    )


def in_labs(rel_parts: tuple[str, ...]) -> bool:
    return len(rel_parts) > 2 and rel_parts[1] == "labs"


def is_stage(module: str, stage: str) -> bool:
    return module == f"pocketsec.{stage}" or module.startswith(f"pocketsec.{stage}.")


# --- the rule predicates (pure; the test's negative fixtures exercise each one) ----------------


def third_party(target: Target) -> bool:
    return target.module.split(".")[0] not in set(sys.stdlib_module_names) | {"pocketsec"}


def is_research(target: Target) -> bool:
    for candidate in target.candidates():
        parts = candidate.split(".")
        if len(parts) >= 3 and parts[0] == "pocketsec" and parts[1].startswith("stage") and \
                any(p.startswith("research") for p in parts[2:]):
            return True
    return False


def imports_stage5(target: Target) -> bool:
    return any(is_stage(c, "stage5") for c in target.candidates())


def upstream_violation(target: Target, rel_parts: tuple[str, ...]) -> str | None:
    """Rules 4 and 5: why this Stage 7 file may not import this target (None = allowed)."""
    module, name = target.module, target.name
    if module == "pocketsec" and name is not None:  # `from pocketsec import stageN`
        return None if name in {"stage0", "stage1"} else f"package import of pocketsec.{name}"
    if any(is_stage(module, s) for s in ("stage3", "stage4")):
        return "Stage 7 consumes nothing from Stages 3 and 4"
    if is_stage(module, "stage2"):
        full = f"{module}.{name}" if name else module
        if STAGE2_ALLOWED in (module, full):
            return None
        if is_harness(rel_parts) and (module, name) == HARNESS_RESOLVER:
            return None
        return "stage2 other than encoder.ssir_encoder"
    if is_stage(module, "stage6"):
        return _stage6_violation(module, name, rel_parts)
    return None


def _stage6_violation(module: str, name: str | None, rel_parts: tuple[str, ...]) -> str | None:
    if name is None:
        return "whole-module Stage 6 import: names cannot be checked through it"
    rules = STAGE6_ALLOW.get(module)
    if rules is None:
        return f"{module} is not on the Stage 6 allow-list"
    here = "/".join(rel_parts[1:])
    harness = is_harness(rel_parts)
    for names, files in rules:
        if name not in names:
            continue
        if ANY in files or here in files or ((in_labs(rel_parts) or harness) and LABS in files):
            return None
        return f"{module}:{name} is not permitted in {here}"
    return f"{module}:{name} is not an allow-listed name"


@cache
def is_writer_name(name: str) -> bool:
    """Whether ``name`` is one of rule 6's Stage 6 writer names (compared by digest)."""
    return hashlib.sha256(name.encode("utf-8")).hexdigest() in STAGE6_WRITER_DIGESTS


def writer_hits(path: Path) -> list[tuple[str, int]]:
    """Rule 6: every mention of a Stage 6 writer name, in any form that can reach it."""
    hits: list[tuple[str, int]] = []
    for node in ast.walk(parse(path)):
        names: list[str] = []
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names = [node.name]
        elif isinstance(node, ast.Name):
            names = [node.id]
        elif isinstance(node, ast.Attribute):
            names = [node.attr]
        elif isinstance(node, ast.arg):
            names = [node.arg]
        elif isinstance(node, ast.alias):
            names = [node.name.split(".")[-1], node.asname or ""]
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            names = [node.value]
        hits += [(n, getattr(node, "lineno", 0)) for n in names if n and is_writer_name(n)]
    return hits


def _local_replay_guards(function: ast.AST) -> frozenset[str]:
    """Names provably bound to a fresh ``ReplayGuard(...)`` in this function: assigned
    exactly once, and only from a direct ``ReplayGuard`` constructor call."""
    bindings: dict[str, list[bool]] = {}
    for node in ast.walk(function):
        assigned: list[ast.expr | None] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            assigned, value = list(node.targets), node.value
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            assigned, value = [node.target], node.value
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            assigned = [node.target]
        elif isinstance(node, ast.withitem):
            assigned = [node.optional_vars]
        for target in assigned:
            for name in ast.walk(target) if target is not None else ():
                if isinstance(name, ast.Name):
                    fresh = (
                        isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                        and value.func.id == "ReplayGuard" and target is name
                    )
                    bindings.setdefault(name.id, []).append(fresh)
    return frozenset(name for name, marks in bindings.items() if marks == [True])


def _replay_guard_rebound(tree: ast.AST) -> bool:
    """Whether the module binds the NAME ``ReplayGuard`` to anything but the real class."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == "ReplayGuard":
                return True
        elif isinstance(node, ast.arg) and node.arg == "ReplayGuard":
            return True
        elif isinstance(node, ast.Name) and node.id == "ReplayGuard" and \
                isinstance(node.ctx, (ast.Store, ast.Del)):
            return True
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                bound = alias.asname or alias.name
                genuine = alias.name == "ReplayGuard" and (node.module or "").endswith(
                    "identity.integrity")
                if bound == "ReplayGuard" and not genuine:
                    return True
    return False


def admit_calls(path: Path) -> list[tuple[str, int]]:
    """Rule 7: every called ``.admit`` and every ``getattr(x, "admit")`` in the file, except
    the two receivers that are provably a ``ReplayGuard`` (see the module docstring)."""
    here = _stage7_rel(path)
    found: list[tuple[str, int]] = []
    tree = parse(path)
    scopes = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    # One binding analysis per scope (was one per node: quadratic). Scopes arrive outer
    # first, so a nested function's own analysis wins for its calls, as before.
    guards: dict[int, frozenset[str]] = {}
    rebound = _replay_guard_rebound(tree)
    for scope in scopes:
        bound = frozenset() if rebound else _local_replay_guards(scope)
        guards.update({id(call): bound for call in ast.walk(scope)})
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "admit":
            receiver = func.value
            ingress_guard = (
                (here, getattr(receiver, "attr", None)) == ADMIT_EXEMPTION
                and isinstance(receiver, ast.Attribute)
                and isinstance(receiver.value, ast.Name) and receiver.value.id == "self"
            )
            fresh_guard = isinstance(receiver, ast.Name) and receiver.id in guards.get(
                id(node), frozenset()
            )
            if here != BRIDGE and not ingress_guard and not fresh_guard:
                found.append((ast.unparse(func), node.lineno))
        if isinstance(func, ast.Name) and func.id == "getattr" and any(
            isinstance(a, ast.Constant) and a.value == "admit" for a in node.args
        ):
            found.append(("getattr(..., 'admit')", node.lineno))
    return found


def execution_primitives(path: Path) -> list[tuple[str, int]]:
    """Rule 8: network/execution modules, and ``os.system``/``popen``/``exec*``/``spawn*``."""
    found = [
        (t.module, t.lineno) for t in targets(path)
        if t.module.split(".")[0] in FORBIDDEN_MODULE_ROOTS
        or (t.module == "os" and t.name is not None and _os_forbidden(t.name))
    ]
    for node in ast.walk(parse(path)):
        if (
            isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
            and node.value.id == "os" and _os_forbidden(node.attr)
        ):
            found.append((f"os.{node.attr}", node.lineno))
    return found


#: (stage7-relative file, enclosing function) -> why its dynamic import is bounded.
DYNAMIC_IMPORT_EXEMPTIONS: dict[tuple[str, str], str] = {
    ("__init__.py", "__getattr__"): "imports only a module named in the literal _SURFACE table",
    ("core_ids.py", "_import_problem"): "only after SYMBOL_PATTERN (pocketsec.stage7 only)",
    ("cli.py", "_catalogue"): "harness: only runners named in the literal S7 catalogue",
    ("labs/seventy_two_experiments.py", "_resolve"): "lab: only the literal S7 catalogue",
}
_DYNAMIC_CALLS = frozenset({"__import__", "eval", "exec", "compile", "import_module"})
_DESERIALISERS = frozenset({"pickle", "marshal", "shelve"})


def dynamic_code(path: Path) -> list[tuple[str, int]]:
    """Rule 12: dynamic imports, code execution and deserialisers, outside the exemptions."""
    here = _stage7_rel(path)
    tree = parse(path)
    enclosing: dict[int, str] = {}
    for scope in ast.walk(tree):  # outer scopes first: a nested def overrides its parent
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            enclosing.update({id(n): scope.name for n in ast.walk(scope)})
    found = [(t.module, t.lineno) for t in targets(path)
             if t.module.split(".")[0] in _DESERIALISERS]
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else None
        if isinstance(func, ast.Attribute) and func.attr in {"import_module", "__import__"}:
            name = func.attr
        if name in _DYNAMIC_CALLS and (here, enclosing.get(id(node), "")) \
                not in DYNAMIC_IMPORT_EXEMPTIONS:
            found.append((ast.unparse(func), node.lineno))
    return found


def _os_forbidden(name: str) -> bool:
    return name in FORBIDDEN_OS_CALLS or name.startswith(FORBIDDEN_OS_PREFIXES)


def _is_dataclass(node: ast.ClassDef) -> bool:
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = target.id if isinstance(target, ast.Name) else getattr(target, "attr", None)
        if name == "dataclass":
            return True
    return False


def t5_offenders(path: Path) -> list[tuple[str, int]]:
    """Rule 9: every annotated ``@dataclass`` field whose lowercased name holds an authority
    word (``redaction`` holds ``action``). No exemption list."""
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


def imports_labs(target: Target) -> bool:
    return any(is_stage(c, "stage7.labs") for c in target.candidates())


def imports_harness(target: Target) -> bool:
    for candidate in target.candidates():
        parts = candidate.split(".")
        if len(parts) == 3 and parts[:2] == ["pocketsec", "stage7"] and (
            parts[2] in {"gate", "cli"} or parts[2].startswith("gate_")
        ):
            return True
    return False


def stage7_files() -> list[Path]:
    return modules_under(STAGE7_ROOT)


# --- whole-tree offenders, one list per rule (what the gate evaluates) --------------------------


def _per_target(check: Callable[[Target, Path], str | None],
                files: Iterable[Path]) -> tuple[str, ...]:
    return tuple(
        f"{label(p)}:{t.lineno} {'.'.join(filter(None, (t.module, t.name)))} ({why})"
        for p in files for t in targets(p) if (why := check(t, p)) is not None
    )


def _per_node(check: Callable[[Path], list[tuple[str, int]]],
              files: Iterable[Path]) -> tuple[str, ...]:
    return tuple(f"{label(p)}:{line} {what}" for p in files for what, line in check(p))


def _rule_labs_and_harness() -> tuple[str, ...]:
    runtime = [p for p in stage7_files() if not in_labs(rel(p)) and not is_harness(rel(p))]
    labs = _per_target(lambda t, _p: "runtime imports labs" if imports_labs(t) else None, runtime)
    outside = [p for p in modules_under(POCKETSEC_ROOT) if not is_harness(rel(p))]
    harness = _per_target(lambda t, _p: "imports the harness" if imports_harness(t) else None,
                          outside)
    return labs + harness


def _rule_t7() -> tuple[str, ...]:
    earlier = [p for stage in EARLIER_STAGES for p in modules_under(POCKETSEC_ROOT / stage)]
    return _per_target(
        lambda t, _p: "earlier stage imports Stage 7"
        if any(is_stage(c, "stage7") for c in t.candidates()) else None, earlier)


#: Rule number -> (title, whole-tree evaluator). ``rule_offenders`` runs them.
BOUNDARY_RULES: dict[int, tuple[str, Callable[[], tuple[str, ...]]]] = {
    1: ("R1 no third-party import", lambda: _per_target(
        lambda t, _p: "third party" if third_party(t) else None, stage7_files())),
    2: ("R2 no research import", lambda: _per_target(
        lambda t, _p: "research" if is_research(t) else None, stage7_files())),
    3: ("T2 no Stage 5 import", lambda: _per_target(
        lambda t, _p: "stage5" if imports_stage5(t) else None, stage7_files())),
    5: ("Stage 2/3/4/6 allow-list", lambda: _per_target(
        lambda t, p: upstream_violation(t, rel(p)), stage7_files())),
    6: ("no Stage 6 writer name", lambda: _per_node(writer_hits, stage7_files())),
    7: ("the one door to admit", lambda: _per_node(admit_calls, stage7_files())),
    8: ("no execution/network primitive",
        lambda: _per_node(execution_primitives, stage7_files())),
    9: ("T5 no authority-named dataclass field",
        lambda: _per_node(t5_offenders, stage7_files())),
    10: ("runtime never imports labs or harness", _rule_labs_and_harness),
    11: ("T7 no earlier stage imports Stage 7", _rule_t7),
    12: ("no dynamic import or code execution", lambda: _per_node(dynamic_code, stage7_files())),
}


def rule_offenders(rule: int) -> tuple[str, ...]:
    """Every offender of one §5.1 rule over the real tree. A tree with no Stage 7 module
    cannot be judged, and says so rather than reporting zero offenders."""
    if not stage7_files():
        return ("pocketsec/stage7/ holds no modules: the rule would pass vacuously",)
    return BOUNDARY_RULES[rule][1]()
