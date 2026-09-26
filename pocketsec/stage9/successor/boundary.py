"""Stage 9's authority boundary (spec §2.2, §2.3; ADR-0081) as AST predicates.

Search has no production authority. That is only true if it is *checked*, so every rule is
a pure function over the source tree that returns a tuple of offenders, where ``()`` is the
only pass. ``tests/test_stage9_boundary.py`` asserts each on the real tree and attacks each
with negative fixtures; gate checks G9.7 and G9.10 call the same functions. There is one
copy of every rule: this module.

"No Stage 9 module reaches Stage 5" cannot be proven by a whole-package closure, because
the one exit to Stage 6 loads 27 Stage 5 modules (M0.9). It is proven in three parts:

1. **Direct** (:func:`direct_stage5_imports`): no Stage 9 import names ``pocketsec.stage5``.
   Relative imports are resolved by ``stage2.gate_criteria.imported_modules`` (imported,
   never copied: two copies of a resolver is how S2-AUTH-01 stayed open in both).
2. **Closure** (:func:`transitive_stage5_reach`): a static import closure over
   ``pocketsec/``, following module-level AND function-level imports and the parent
   packages every import executes. No Stage 9 module except the exit and the harness
   (``gate*.py``, ``cli.py``) may reach Stage 5; for those, every path to Stage 5 must pass
   through ``pocketsec.stage6.capsule.*`` (the declared residual).
3. **One door** (:func:`admit_call_sites`, :func:`stage6_writer_names`): only
   ``successor/stage6_exit.py`` calls ``.admit`` or imports ``QuarantineGateway`` outside
   the harness, and no Stage 9 file names a Stage 6 writer.

Stage 6's own boundary test forbids its sealed writer names as string constants anywhere
under ``pocketsec/`` outside their owners, so this module never spells them: it reads each
Stage 6 module's ``SEALED_NAMES`` by AST, and holds the one name the spec lists outside
``SEALED_NAMES`` as a sha256 digest (the test file, outside ``pocketsec/``, pins it).

Two declared deviations from the §2.3 table, both reported: the harness may import
``Epoch`` (it must build one to call ``Stage6Exit.hand_over``), and ``admit_call_sites``
lets the harness import ``QuarantineGateway`` because §2.3 grants it for lab-gateway
construction while rule 3's prose says "only the exit"; the harness still may not call
``.admit``.

What AST cannot see stays a residual: ``getattr`` on a module object obtained some other
way, anything built from a composed string after the dynamic-execution rule's exemptions,
and (rule 3) an ``admit`` method bound first and called later, fetched through
``operator.methodcaller`` or ``vars(type(gw))["admit"]``, or a bucket read other than a
``.bucket`` attribute (S9-AUTH-02: declared, not detected). Aliased dynamic callables,
``builtins`` aliases, and a dynamic callable fetched by a literal name through ``getattr``
or a subscript ARE caught (S9-AUTH-01), and ``runpy``/``multiprocessing`` are banned. Every check walks the AST, never the text: docstrings name the boundary, and
naming it is not crossing it.
"""

from __future__ import annotations

import ast
import hashlib
from collections import deque
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from functools import cache
from pathlib import Path

from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS
from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage2.gate_criteria import imported_modules

__all__ = [
    "ANY",
    "EXIT_MODULE",
    "HARNESS",
    "POCKETSEC_ROOT",
    "STAGE6_ROOT",
    "STAGE9_ALLOW",
    "STAGE9_ROOT",
    "T3_ALLOWED",
    "WRITER_MODULES",
    "WRITER_NAME_DIGESTS",
    "Target",
    "admit_call_files",
    "admit_call_sites",
    "authority_field_offenders",
    "direct_stage5_imports",
    "dynamic_execution_offenders",
    "earlier_stage_importers",
    "numpy_or_research_offenders",
    "outside_importers_of_stage9",
    "sealed_names",
    "stage6_allow_list_offenders",
    "stage6_writer_names",
    "stage9_modules",
    "targets",
    "transitive_stage5_reach",
]

POCKETSEC_ROOT = REPO_ROOT / "pocketsec"
STAGE9_ROOT = POCKETSEC_ROOT / "stage9"
STAGE6_ROOT = POCKETSEC_ROOT / "stage6"

ANY = "*"
HARNESS = "<harness>"
EXIT_MODULE = "successor/stage6_exit.py"

_STAGE1 = "pocketsec.stage1."
_STAGE2 = "pocketsec.stage2."
_STAGE6 = "pocketsec.stage6."
_SYN = "daedalus/synthesizer.py"

#: Spec §2.3, verbatim at (module, names, importing files) granularity. ``ANY`` = any Stage 9
#: file; ``HARNESS`` = ``gate.py``, ``gate_*.py``, ``cli.py`` at the stage root. Stage 0 and
#: Stage 9 itself are free; every other stage module not listed here is refused.
STAGE9_ALLOW: dict[str, tuple[tuple[frozenset[str], frozenset[str]], ...]] = {
    _STAGE1 + "labs.corpus": (
        (frozenset({"Behaviour", "Scenario", "CORPUS_VERSION"}), frozenset({ANY})),
    ),
    _STAGE1 + "labs.ambiguous_corpus": (
        (frozenset({"build_ambiguous_corpus", "AMBIGUOUS_VERSION"}), frozenset({ANY})),
    ),
    _STAGE1 + "pipeline": ((frozenset({"Stage1Pipeline", "ScenarioResult"}), frozenset({ANY})),),
    _STAGE1 + "state.security_state": ((frozenset({"DIMENSIONS"}), frozenset({ANY})),),
    _STAGE1 + "ssir.relations": ((frozenset({"RelationFamily"}), frozenset({ANY})),),
    _STAGE1 + "novelty.sketches": (
        (frozenset({"CountMinSketch"}), frozenset({"chronos/forgetting_law.py"})),
    ),
    # Deviation: the harness needs an Epoch to call Stage6Exit.hand_over.
    _STAGE1 + "epoch.model": (
        (frozenset({"Epoch"}), frozenset({EXIT_MODULE, HARNESS})),
        # Integrator (ADR-0081): an Epoch and genesis_state both need the identity they bind.
        (frozenset({"SystemIdentity"}), frozenset({HARNESS})),
    ),
    _STAGE2 + "dataset": (
        (frozenset({"Stage2Dataset", "Stage2Sample"}), frozenset({ANY})),
        (frozenset({"_encode"}), frozenset({"labs/splits.py"})),
    ),
    _STAGE2 + "encoder.ssir_encoder": (
        (
            frozenset(
                {
                    "EncodedTransition",
                    "FEATURE_WIDTH",
                    "GROUP_OFFSETS",
                    "ENCODER_VERSION",
                    "NEED_SIGNAL_INDICES",
                }
            ),
            frozenset({ANY}),
        ),
    ),
    _STAGE2 + "core_ids": ((frozenset({"FunctionClass"}), frozenset({"core_ids.py"})),),
    _STAGE2 + "compile_candidates.phi_oracle_candidate": (
        (
            frozenset(
                {
                    "PHI_ORACLE_SCORER",
                    "PHI_SQUASHED_FEATURE_INDEX",
                    "DeterministicScorerSpec",
                    "AGGREGATIONS",
                }
            ),
            frozenset({ANY}),
        ),
    ),
    _STAGE2 + "compile_candidates.candidate": (
        (frozenset({"forbidden_authority_keys"}), frozenset({"successor/proof_carrying.py"})),
    ),
    _STAGE2 + "gate_measures": (
        (frozenset({"lineage_windows"}), frozenset({"genome/expressibility.py"})),
    ),
    _STAGE2 + "gate_evidence": (
        (
            frozenset({"load_frontier", "FrontierEvidence"}),
            frozenset({HARNESS, "harness/hardware_in_loop.py"}),
        ),
    ),
    _STAGE2 + "gate_criteria": (
        (frozenset({"imported_modules"}), frozenset({"successor/boundary.py"})),
    ),
    _STAGE2 + "labs.drift_corpus": (
        (
            frozenset({"build_drift_corpus", "DRIFT_VERSION"}),
            frozenset({"laplace/law_discovery.py", "harness/reproducibility.py"}),
        ),
    ),
    "pocketsec.stage3.labs.ablation": (
        (frozenset({"saturation_guard"}), frozenset({"labs/splits.py"})),
    ),
    "pocketsec.stage3.cells.operator": (
        (frozenset({"OperatorProgram", "OperatorForm"}), frozenset({_SYN})),
    ),
    "pocketsec.stage3.bytecode.verifier": ((frozenset({"verify"}), frozenset({_SYN})),),
    "pocketsec.stage3.bytecode.isa": ((frozenset({"Op"}), frozenset({_SYN})),),
    _STAGE6 + "resources": (
        (frozenset({"WorkMeter", "WorkBudgetExceeded", "loadavg"}), frozenset({ANY})),
    ),
    _STAGE6 + "capsule.experience_capsule": (
        (
            frozenset(
                {
                    "capsule_from_scenario",
                    "SourceProvenance",
                    "SourceClass",
                    "LabelOrigin",
                    "ExperienceCapsuleV1",
                }
            ),
            frozenset({EXIT_MODULE}),
        ),
    ),
    _STAGE6 + "capsule.quarantine": (
        (
            frozenset({"QuarantineGateway", "QuarantineVerdict", "QuarantineBucket"}),
            frozenset({EXIT_MODULE, HARNESS}),
        ),
    ),
    _STAGE6 + "provenance.ledger": ((frozenset({"ProvenanceLedger"}), frozenset({HARNESS})),),
    _STAGE6 + "fossils.lineage": ((frozenset({"KnowledgeLineageDAG"}), frozenset({HARNESS})),),
    _STAGE6 + "memory.semantic": ((frozenset({"genesis_state"}), frozenset({HARNESS})),),
}
_GOVERNED_STAGES = tuple(f"stage{n}" for n in range(1, 13) if n != 9)

#: Stage 6 writer modules (spec §2.3 rule 3). A Stage 9 import of any of them is an offender.
WRITER_MODULES: tuple[str, ...] = (
    _STAGE6 + "promotion",
    _STAGE6 + "chamber",
    _STAGE6 + "shadow",
    _STAGE6 + "consolidator",
    _STAGE6 + "fossils.store",
)
#: The single-writer method the spec lists by name, as a sha256 digest (module docstring).
WRITER_NAME_DIGESTS = frozenset(
    {
        "e72588cfe2c483222566076e1e3dc8d55d6c7557bda304f06b976ee98fce8cf9",
    }
)
#: Integration plan T3: the one earlier-stage module that may import these (it does not today).
T3_IMPORTER = ("stage6", "capsule", "quarantine.py")
T3_ALLOWED = ("pocketsec.stage7", "pocketsec.stage8.forge", "pocketsec.stage9.successor")

_DYNAMIC_CALLS = frozenset({"eval", "exec", "compile", "__import__", "import_module"})
_BANNED_MODULE_ROOTS = frozenset(
    {"pickle", "marshal", "shelve", "subprocess", "socket", "runpy", "multiprocessing"}
)
_OS_CALLS = frozenset({"system", "popen"})
_POOL = "ProcessPoolExecutor"
#: (stage9-relative file, what) -> why it is bounded (spec §2.2's declared exemptions).
_IMPORT_MODULE_EXEMPT = frozenset(
    {
        "core_ids.py",
        "labs/one_twenty_experiments.py",
        # Integrator (ADR-0080): the lazy public surface, the stage6/stage7 ``__init__`` shape.
        "__init__.py",
    }
)
_POOL_EXEMPT = frozenset({"labs/splits.py"})


@dataclass(frozen=True, slots=True)
class Target:
    """One thing a file imports: the resolved module and, for ``from M import n``, the name."""

    module: str
    name: str | None
    lineno: int

    def candidates(self) -> tuple[str, ...]:
        return (self.module,) if self.name is None else (self.module, f"{self.module}.{self.name}")

    def spelled(self) -> str:
        return self.module if self.name is None else f"{self.module}:{self.name}"


# --- tree helpers ------------------------------------------------------------------------------


def _python_files(root: Path) -> tuple[Path, ...]:
    if not root.is_dir():
        return ()
    return tuple(sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts))


def stage9_modules(root: Path = STAGE9_ROOT) -> tuple[Path, ...]:
    """Every Stage 9 source file, sorted."""
    return _python_files(root)


@cache
def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _rel(path: Path) -> tuple[str, ...]:
    """The path's parts below its innermost ``pocketsec`` directory (works for fixtures)."""
    parts = path.resolve().parts
    root = len(parts) - 1 - parts[::-1].index("pocketsec")
    return parts[root + 1 :]


def _stage9_rel(path: Path) -> str:
    return "/".join(_rel(path)[1:])


def _label(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return "pocketsec/" + "/".join(_rel(path))


def _module_name(path: Path) -> str:
    parts = ["pocketsec", *_rel(path)]
    parts[-1] = parts[-1][:-3]
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def _is_harness(path: Path) -> bool:
    parts = _rel(path)
    return (
        len(parts) == 2
        and parts[0] == "stage9"
        and (
            parts[1] in {"gate.py", "cli.py"}
            or (parts[1].startswith("gate_") and parts[1].endswith(".py"))
        )
    )


def _is_gate(path: Path) -> bool:
    return _is_harness(path) and _rel(path)[1] != "cli.py"


def _is_stage(module: str, stage: str) -> bool:
    return module == f"pocketsec.{stage}" or module.startswith(f"pocketsec.{stage}.")


@cache
def targets(path: Path) -> tuple[Target, ...]:
    """Every import in the file (any depth), resolved by the shared resolver."""
    found: list[Target] = []
    for node in ast.walk(_parse(path)):
        modules = imported_modules(node, path)
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            found += [Target(modules[0], alias.name, node.lineno) for alias in node.names]
        else:  # `import a.b`, or `from . import x` (the resolver made x a module)
            found += [Target(m, None, getattr(node, "lineno", 0)) for m in modules]
    return tuple(found)


def _files(files: Iterable[Path] | None) -> tuple[Path, ...]:
    return stage9_modules() if files is None else tuple(files)


def _per_target(
    check: Callable[[Target, Path], str | None], files: Iterable[Path]
) -> tuple[str, ...]:
    return tuple(
        f"{_label(p)}:{t.lineno} {t.spelled()} ({why})"
        for p in files
        for t in targets(p)
        if (why := check(t, p)) is not None
    )


# --- rule 1: direct Stage 5 imports ------------------------------------------------------------


def direct_stage5_imports(files: Iterable[Path] | None = None) -> tuple[str, ...]:
    """Rule 1 (integration plan T2): no Stage 9 import names ``pocketsec.stage5``."""
    return _per_target(
        lambda t, _p: "stage5" if any(_is_stage(c, "stage5") for c in t.candidates()) else None,
        _files(files),
    )


# --- rule 2: the static import closure ---------------------------------------------------------


@cache
def _module_file(module: str, root: Path) -> Path | None:
    parts = module.split(".")
    if parts[0] != "pocketsec":
        return None
    base = root.joinpath(*parts[1:])
    if (base / "__init__.py").is_file():
        return base / "__init__.py"
    if base.with_suffix(".py").is_file():
        return base.with_suffix(".py")
    return None


def _with_parents(module: str) -> list[str]:
    parts = module.split(".")
    return [".".join(parts[: i + 1]) for i in range(len(parts))]


@cache
def _edges(path: Path, root: Path) -> tuple[str, ...]:
    """Modules executed by importing ``path``: each import target and its parent packages."""
    found: dict[str, None] = {}
    for target in targets(path):
        for candidate in target.candidates():
            if not candidate.startswith("pocketsec"):
                continue
            if _module_file(candidate, root) is None and not _is_stage(candidate, "stage5"):
                continue
            found.update(dict.fromkeys(_with_parents(candidate)))
    return tuple(m for m in found if _module_file(m, root) is not None or _is_stage(m, "stage5"))


def _stage5_path(start: Path, root: Path, *, stop: Callable[[str], bool]) -> list[str] | None:
    """The first import chain from ``start`` to a Stage 5 module, or None."""
    origin = _module_name(start)
    parents: dict[str, str | None] = {origin: None}
    queue: deque[tuple[str, Path | None]] = deque([(origin, start)])
    for package in _with_parents(origin)[:-1]:
        parents.setdefault(package, origin)
        queue.append((package, _module_file(package, root)))
    while queue:
        module, path = queue.popleft()
        if _is_stage(module, "stage5"):
            chain = [module]
            while (previous := parents[chain[-1]]) is not None:
                chain.append(previous)
            return chain[::-1]
        if path is None or (module != origin and stop(module)):
            continue
        for nxt in _edges(path, root):
            if nxt not in parents:
                parents[nxt] = module
                queue.append((nxt, _module_file(nxt, root)))
    return None


def transitive_stage5_reach(
    files: Iterable[Path] | None = None, *, root: Path = POCKETSEC_ROOT
) -> tuple[str, ...]:
    """Rule 2: no Stage 9 module's static import closure contains Stage 5, except that the
    exit and the harness may reach it only THROUGH ``pocketsec.stage6.capsule.*``."""
    offenders: list[str] = []
    for path in _files(files):
        residual = _stage9_rel(path) == EXIT_MODULE or _is_harness(path)
        stop = (lambda m: _is_stage(m, "stage6.capsule")) if residual else (lambda _m: False)
        chain = _stage5_path(path, root, stop=stop)
        if chain is not None:
            where = "bypassing pocketsec.stage6.capsule" if residual else "reaches Stage 5"
            offenders.append(f"{_label(path)} {where}: {' -> '.join(chain)}")
    return tuple(offenders)


# --- the §2.3 allow-list -----------------------------------------------------------------------


def _allowed_here(files: frozenset[str], path: Path) -> bool:
    return ANY in files or _stage9_rel(path) in files or (HARNESS in files and _is_harness(path))


def _upstream_violation(target: Target, path: Path) -> str | None:
    module, name = target.module, target.name
    if module == "pocketsec":
        if name is None or name in {"stage0", "stage9"}:
            return None
        return f"package import of pocketsec.{name}: names cannot be checked through it"
    stage = next((s for s in _GOVERNED_STAGES if _is_stage(module, s)), None)
    if stage is None:
        return None
    rules = STAGE9_ALLOW.get(module)
    if rules is None:
        return f"{module} is not on the §2.3 allow-list"
    if name is None:
        return "whole-module import: names cannot be checked through it"
    for names, files in rules:
        if name in names:
            return (
                None
                if _allowed_here(files, path)
                else f"{name} is not permitted in {_stage9_rel(path)}"
            )
    return f"{name} is not an allow-listed name of {module}"


def stage6_allow_list_offenders(files: Iterable[Path] | None = None) -> tuple[str, ...]:
    """Spec §2.3: every upstream import checked at module + name + importing-file granularity.

    Covers the whole table (Stages 1-4, 6, 7, 8, 10-12 as well as Stage 6), because a
    Stage 6 door is only as narrow as the rest of the wall around it.
    """
    return _per_target(_upstream_violation, _files(files))


# --- rule 3: the one door, and no Stage 6 writer -----------------------------------------------


def _admit_calls(path: Path) -> list[tuple[str, int]]:
    found: list[tuple[str, int]] = []
    for node in ast.walk(_parse(path)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "admit":
            found.append((ast.unparse(func), node.lineno))
        elif (
            isinstance(func, ast.Name)
            and func.id == "getattr"
            and any(isinstance(a, ast.Constant) and a.value == "admit" for a in node.args)
        ):
            found.append(("getattr(..., 'admit')", node.lineno))
    return found


def admit_call_files(files: Iterable[Path] | None = None) -> tuple[str, ...]:
    """Every Stage 9 file containing an ``.admit`` call; the gate asserts it is the exit."""
    return tuple(_label(p) for p in _files(files) if _admit_calls(p))


def admit_call_sites(files: Iterable[Path] | None = None) -> tuple[str, ...]:
    """Rule 3: ``.admit`` calls outside the exit, and ``QuarantineGateway`` imports outside
    the exit and the harness (which §2.3 lets construct a lab gateway, never call it)."""
    offenders: list[str] = []
    for path in _files(files):
        if _stage9_rel(path) == EXIT_MODULE:
            continue
        offenders += [f"{_label(path)}:{line} {what}" for what, line in _admit_calls(path)]
        if _is_harness(path):
            continue
        offenders += [
            f"{_label(path)}:{t.lineno} imports QuarantineGateway"
            for t in targets(path)
            if t.name == "QuarantineGateway" or (t.module.endswith(".QuarantineGateway"))
        ]
    return tuple(offenders)


@cache
def sealed_names(stage6_root: Path = STAGE6_ROOT) -> frozenset[str]:
    """Every string in a module-level ``SEALED_NAMES = (...)`` of a Stage 6 module, by AST."""
    names: set[str] = set()
    for path in _python_files(stage6_root):
        for node in _parse(path).body:
            target, value = _assignment(node)
            if target == "SEALED_NAMES" and isinstance(value, (ast.Tuple, ast.List)):
                names.update(
                    e.value
                    for e in value.elts
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)
                )
    return frozenset(names)


def _assignment(node: ast.stmt) -> tuple[str | None, ast.expr | None]:
    if (
        isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
    ):
        return node.targets[0].id, node.value
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return node.target.id, node.value
    return None, None


def _mentions(node: ast.AST) -> list[str]:
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


def _is_writer_name(name: str, sealed: frozenset[str]) -> bool:
    return name in sealed or hashlib.sha256(name.encode("utf-8")).hexdigest() in WRITER_NAME_DIGESTS


def stage6_writer_names(
    files: Iterable[Path] | None = None, *, stage6_root: Path = STAGE6_ROOT
) -> tuple[str, ...]:
    """Rule 3: no Stage 9 file imports a Stage 6 writer module or mentions a sealed name."""
    sealed = sealed_names(stage6_root)
    if not sealed:
        return (f"no SEALED_NAMES found under {stage6_root}: the rule would pass vacuously",)
    offenders = list(
        _per_target(
            lambda t, _p: (
                "Stage 6 writer module"
                if any(
                    _is_stage(c, m.removeprefix("pocketsec."))
                    for c in t.candidates()
                    for m in WRITER_MODULES
                )
                else None
            ),
            _files(files),
        )
    )
    for path in _files(files):
        offenders += [
            f"{_label(path)}:{getattr(node, 'lineno', 0)} names a Stage 6 writer"
            for node in ast.walk(_parse(path))
            if any(n and _is_writer_name(n, sealed) for n in _mentions(node))
        ]
    return tuple(offenders)


# --- T5: authority-named classes and fields ----------------------------------------------------


def _authority_word(name: str) -> str | None:
    lowered = name.lower()
    return next((w for w in FORBIDDEN_AUTHORITY_FIELDS if w in lowered), None)


def authority_field_offenders(files: Iterable[Path] | None = None) -> tuple[str, ...]:
    """T5: no class name, and no annotated class field, holds an authority word."""
    offenders: list[str] = []
    for path in _files(files):
        for node in ast.walk(_parse(path)):
            if not isinstance(node, ast.ClassDef):
                continue
            if (word := _authority_word(node.name)) is not None:
                offenders.append(f"{_label(path)}:{node.lineno} class {node.name} ({word})")
            for stmt in node.body:
                if (
                    isinstance(stmt, ast.AnnAssign)
                    and isinstance(stmt.target, ast.Name)
                    and (word := _authority_word(stmt.target.id)) is not None
                ):
                    offenders.append(
                        f"{_label(path)}:{stmt.lineno} field {node.name}.{stmt.target.id} ({word})"
                    )
    return tuple(offenders)


# --- §2.2: dynamic execution -------------------------------------------------------------------


def _aliases(tree: ast.AST) -> tuple[dict[str, str], frozenset[str]]:
    """Local names bound to a dynamic-execution callable, and names bound to ``builtins``.

    Without this, ``from importlib import import_module as load`` then ``load(...)``, or
    ``import builtins as b`` then ``b.eval(...)``, passed the rule (S9-AUTH-01), and with it
    the Stage 5 closure proof that relies on the rule to see dynamic imports.
    """
    callables: dict[str, str] = {}
    modules: set[str] = {"builtins"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name in _DYNAMIC_CALLS:
                    callables[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.Import):
            modules.update(a.asname for a in node.names if a.name == "builtins" and a.asname)
    return callables, frozenset(modules)


def _call_name(func: ast.expr, callables: dict[str, str], modules: frozenset[str]) -> str | None:
    if isinstance(func, ast.Name):
        return callables.get(func.id, func.id)
    if isinstance(func, ast.Attribute) and (
        func.attr in {"import_module", "__import__"}
        or (isinstance(func.value, ast.Name) and func.value.id in modules)
    ):
        return func.attr
    return None


def _spelled_lookup(node: ast.AST) -> str | None:
    """``getattr(x, "eval")`` or ``vars(builtins)["eval"]``: a dynamic callable fetched by
    a LITERAL name. A composed string stays the declared residual."""
    key: ast.expr | None = None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and \
            node.func.id == "getattr" and len(node.args) >= 2:
        key = node.args[1]
    elif isinstance(node, ast.Subscript):
        key = node.slice
    if isinstance(key, ast.Constant) and key.value in _DYNAMIC_CALLS:
        return str(key.value)
    return None


def _dynamic_calls(path: Path) -> list[tuple[str, int]]:
    here = _stage9_rel(path)
    tree = _parse(path)
    callables, modules = _aliases(tree)
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        name = _call_name(node.func, callables, modules) if isinstance(node, ast.Call) else None
        name = name if name in _DYNAMIC_CALLS else _spelled_lookup(node)
        if name is not None and not (name == "import_module" and here in _IMPORT_MODULE_EXEMPT):
            found.append((f"{name}(...)", getattr(node, "lineno", 0)))
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "os"
            and (node.attr in _OS_CALLS or node.attr.startswith(("exec", "spawn")))
        ):
            found.append((f"os.{node.attr}", node.lineno))
        if _names_pool(node) and here not in _POOL_EXEMPT:
            found.append((_POOL, getattr(node, "lineno", 0)))
    return found


def _names_pool(node: ast.AST) -> bool:
    """A reference to the process pool (not a string that spells it, like this module's)."""
    if isinstance(node, ast.Name):
        return node.id == _POOL
    if isinstance(node, ast.Attribute):
        return node.attr == _POOL
    return isinstance(node, ast.alias) and _POOL in (node.name.split(".")[-1], node.asname)


def _banned_import(target: Target, path: Path) -> str | None:
    root = target.module.split(".")[0]
    if root in _BANNED_MODULE_ROOTS and not (root == "subprocess" and _is_gate(path)):
        return f"{root} is banned in Stage 9"
    if (
        target.module == "os"
        and target.name is not None
        and (target.name in _OS_CALLS or target.name.startswith(("exec", "spawn")))
    ):
        return "os process primitive"
    return None


def dynamic_execution_offenders(files: Iterable[Path] | None = None) -> tuple[str, ...]:
    """§2.2: eval/exec/compile/__import__/import_module (also aliased, or fetched by a literal
    name), pickle, marshal, subprocess, socket, runpy, multiprocessing, os.system and
    ProcessPoolExecutor, outside the three declared exemptions."""
    chosen = _files(files)
    calls = tuple(f"{_label(p)}:{line} {what}" for p in chosen for what, line in _dynamic_calls(p))
    return calls + _per_target(_banned_import, chosen)


# --- ADR-0008 / ADR-0080: no numpy, no research package ----------------------------------------


def _research(target: Target) -> bool:
    for candidate in target.candidates():
        parts = candidate.split(".")
        if (
            len(parts) >= 3
            and parts[0] == "pocketsec"
            and parts[1].startswith("stage")
            and any(p.startswith("research") for p in parts[2:])
        ):
            return True
    return False


def numpy_or_research_offenders(
    files: Iterable[Path] | None = None, *, stage9_root: Path = STAGE9_ROOT
) -> tuple[str, ...]:
    """No numpy import anywhere in Stage 9, no research import, no stage9/research dir."""
    offenders = list(
        _per_target(
            lambda t, _p: (
                "numpy"
                if t.module.split(".")[0] == "numpy"
                else ("research module" if _research(t) else None)
            ),
            _files(files),
        )
    )
    if (stage9_root / "research").exists():
        offenders.append(f"{_label(stage9_root / 'research' / '__init__.py')} directory exists")
    return tuple(offenders)


# --- T7 / T3: who may import Stage 9 -----------------------------------------------------------


def _t3_exempt(path: Path, target: Target) -> bool:
    return _rel(path) == T3_IMPORTER and all(
        any(c == a or c.startswith(a + ".") for a in T3_ALLOWED)
        for c in target.candidates()
        if any(_is_stage(c, s) for s in ("stage7", "stage8", "stage9"))
    )


def _importers(files: Sequence[Path], stages: Sequence[str], why: str) -> tuple[str, ...]:
    return _per_target(
        lambda t, p: (
            why
            if any(_is_stage(c, s) for c in t.candidates() for s in stages) and not _t3_exempt(p, t)
            else None
        ),
        files,
    )


def earlier_stage_importers(root: Path = POCKETSEC_ROOT) -> tuple[str, ...]:
    """T7: nothing in Stages 0-6 imports Stage 7, 8 or 9 (T3's one quarantine exemption)."""
    earlier = [p for n in range(7) for p in _python_files(root / f"stage{n}")]
    return _importers(earlier, ("stage7", "stage8", "stage9"), "earlier stage imports 7/8/9")


def outside_importers_of_stage9(root: Path = POCKETSEC_ROOT) -> tuple[str, ...]:
    """T3: nothing under ``pocketsec/`` outside Stage 9 imports Stage 9 (same exemption)."""
    outside = [p for p in _python_files(root) if not (_rel(p) and _rel(p)[0] == "stage9")]
    return _importers(outside, ("stage9",), "imports Stage 9 from outside it")
