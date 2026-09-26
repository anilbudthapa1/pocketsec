"""P2's static scan: no natural-language-to-shell path under a package root.

This is the check the gate (G5.2 clause d), ``tests/test_stage5_boundary.py`` rule 5 and
the operators tests share. It used to live at the bottom of ``operators/algebra.py``; it
moved here when finding S5-SEC-09 extended it, because ``algebra.py`` was already past the
repository's module-size limit and the scanner has nothing to do with the operator types.
``algebra.py`` re-exports every public name, so no caller changed.

**What it finds** (each reported as ``path:lineno:reason``): an import of a launcher root
(:data:`FORBIDDEN_IMPORT_ROOTS`, relative imports resolved, because a relative import was
invisible to two checkers at once in Stage 2, S2-AUTH-01); a process-starting attribute of
``os``/``posix``/``nt`` (:data:`FORBIDDEN_OS_ATTRIBUTES`) under **any alias** — read, not
only called, because ``launch = o.system`` is the same capability one line earlier;
``getattr`` on such an alias, which is how the attribute name is hidden from the rule above;
``eval``/``exec``/``compile``/``__import__``; ``import_module`` with a literal naming a
launcher root; ``shell=True``; and a formatted string flowing into :func:`assemble_argv` or
into a name holding an argument vector.

**What it cannot find, and why P2 is TESTED rather than proven.** The scan is static. A
call ``importlib.import_module(name)`` whose ``name`` is computed at run time can reach any
module, and four Stage 5 modules use exactly that for lazy exports and binding resolution
(``__init__.py``, ``theory.py``, ``gate_construction.py``, ``assurance/properties.py``).
No static scan decides where such a call leads, so absence of a launcher is a tested
property of today's source, not a construction (finding S5-SEC-09).
"""

from __future__ import annotations

import ast
from pathlib import Path

__all__ = [
    "ARGV_NAME_TOKENS",
    "FORBIDDEN_CALL_NAMES",
    "FORBIDDEN_IMPORT_ROOTS",
    "FORBIDDEN_OS_ATTRIBUTES",
    "PROCESS_MODULES",
    "no_arbitrary_command_path",
]

#: Import roots that put a shell, a pty, a foreign-function call or a second process one
#: call away. ``posix``/``nt`` are ``os``'s own back ends; ``asyncio`` carries
#: ``create_subprocess_shell``; ``ctypes``/``cffi`` reach libc's ``system``.
FORBIDDEN_IMPORT_ROOTS: frozenset[str] = frozenset(
    {
        "subprocess", "pty", "ptyprocess", "commands", "posix", "nt", "_posixsubprocess",
        "ctypes", "cffi", "multiprocessing", "asyncio", "shlex", "runpy", "code", "codeop",
        "pexpect", "sh", "plumbum", "concurrent",
    }
)
#: Modules whose attributes below start a process. ``os`` itself is permitted — Stage 5
#: reads the load average through it — so the rule is on the attribute, under any alias.
PROCESS_MODULES: frozenset[str] = frozenset({"os", "posix", "nt"})
#: Attributes of :data:`PROCESS_MODULES` that execute, replace or fork the process.
FORBIDDEN_OS_ATTRIBUTES: frozenset[str] = frozenset(
    {
        "system", "popen", "execl", "execle", "execlp", "execlpe", "execv", "execve",
        "execvp", "execvpe", "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv",
        "spawnve", "spawnvp", "spawnvpe", "posix_spawn", "posix_spawnp", "fork", "forkpty",
        "startfile",
    }
)
#: Builtins that turn data into code, or a string into a module.
FORBIDDEN_CALL_NAMES: frozenset[str] = frozenset({"eval", "exec", "compile", "__import__"})
#: A name that holds an argument vector. A formatted string flowing into one of these is
#: command construction whatever it is called.
ARGV_NAME_TOKENS: tuple[str, ...] = ("argv", "cmd", "command")


def no_arbitrary_command_path(package_root: Path) -> tuple[str, ...]:
    """Every launcher path the static scan can see under ``package_root``. ``()`` is P2."""
    rows: list[str] = []
    for path in sorted(package_root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        label = _relative_label(path, package_root)
        aliases = _process_module_aliases(tree)
        for node in ast.walk(tree):
            for reason in _node_violations(node, aliases):
                rows.append(f"{label}:{getattr(node, 'lineno', 0)}:{reason}")
    return tuple(sorted(rows))


def _relative_label(path: Path, package_root: Path) -> str:
    try:
        return str(path.relative_to(package_root.parent))
    except ValueError:  # a tmp_path fixture outside the package
        return str(path)


def _process_module_aliases(tree: ast.AST) -> frozenset[str]:
    """Every local name bound to ``os``/``posix``/``nt`` in this file, however spelled.

    ``import os as o`` binds ``o``; ``import os.path`` binds ``os``. Reading only the
    literal name ``os`` is the lexical gap finding S5-SEC-09 reproduced.
    """
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Import):
            continue
        for alias in node.names:
            root = alias.name.split(".")[0]
            if root in PROCESS_MODULES:
                names.add(alias.asname or root)
    return frozenset(names)


def _node_violations(node: ast.AST, aliases: frozenset[str]) -> tuple[str, ...]:
    reasons: list[str] = []
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        reasons.extend(_import_violations(node))
    if isinstance(node, ast.Attribute) and _is_process_attribute(node, aliases):
        reasons.append(f"reads {node.attr} of a process module")
    if isinstance(node, ast.Name) and node.id == "__import__":
        reasons.append("names __import__")
    if isinstance(node, ast.Call):
        reasons.extend(_call_violations(node, aliases))
    if isinstance(node, ast.Assign):
        for target in node.targets:
            name = _simple_name(target)
            if name and _is_argv_name(name) and _holds_formatted_string(node.value):
                reasons.append(f"formatted string assigned to {name}")
    return tuple(reasons)


def _import_violations(node: ast.Import | ast.ImportFrom) -> tuple[str, ...]:
    reasons = [f"imports {module}" for module in _imported_roots(node)
               if module in FORBIDDEN_IMPORT_ROOTS]
    if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[-1] in PROCESS_MODULES:
        reasons.extend(f"imports os.{alias.name}" for alias in node.names
                       if alias.name in FORBIDDEN_OS_ATTRIBUTES)
    return tuple(reasons)


def _is_process_attribute(node: ast.Attribute, aliases: frozenset[str]) -> bool:
    return (
        isinstance(node.value, ast.Name)
        and (node.value.id in aliases or node.value.id in PROCESS_MODULES)
        and node.attr in FORBIDDEN_OS_ATTRIBUTES
    )


def _call_violations(node: ast.Call, aliases: frozenset[str]) -> tuple[str, ...]:
    reasons: list[str] = []
    func = node.func
    if isinstance(func, ast.Name) and func.id in FORBIDDEN_CALL_NAMES:
        reasons.append(f"calls {func.id}")
    if isinstance(func, ast.Attribute) and _is_process_attribute(func, aliases):
        reasons.append(f"calls os.{func.attr}")
    if _simple_name(func) == "getattr" and node.args and _names_process_module(
        node.args[0], aliases
    ):
        reasons.append("getattr on a process module hides the attribute it reads")
    if _simple_name(func) == "import_module" and node.args and _literal_forbidden(node.args[0]):
        reasons.append("imports a launcher root through import_module")
    if isinstance(func, ast.Attribute) and func.attr == "join":
        for argument in node.args:
            name = _simple_name(argument)
            if name and _is_argv_name(name):
                reasons.append(f"joins {name} into one string")
    reasons.extend(_keyword_violations(node))
    if _simple_name(func) == "assemble_argv":
        for argument in node.args:
            if _holds_formatted_string(argument):
                reasons.append("formatted string flows into assemble_argv")
    return tuple(reasons)


def _keyword_violations(node: ast.Call) -> tuple[str, ...]:
    reasons: list[str] = []
    for keyword in node.keywords:
        if (keyword.arg == "shell" and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True):
            reasons.append("passes shell=True")
        if keyword.arg and _is_argv_name(keyword.arg) and _holds_formatted_string(keyword.value):
            reasons.append(f"formatted string passed as {keyword.arg}")
    return tuple(reasons)


def _names_process_module(node: ast.expr, aliases: frozenset[str]) -> bool:
    return isinstance(node, ast.Name) and (node.id in aliases or node.id in PROCESS_MODULES)


def _literal_forbidden(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.split(".")[0] in FORBIDDEN_IMPORT_ROOTS
    )


def _simple_name(node: ast.expr) -> str | None:
    """The bare name of a ``Name`` or the attribute of an ``Attribute``, else ``None``."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_argv_name(name: str) -> bool:
    lowered = name.lower()
    return any(token in lowered for token in ARGV_NAME_TOKENS)


def _holds_formatted_string(node: ast.expr | None) -> bool:
    """True when ``node`` is, or contains, a string built by formatting."""
    if node is None:
        return False
    for inner in ast.walk(node):
        if isinstance(inner, ast.JoinedStr):
            return True
        if isinstance(inner, ast.BinOp) and isinstance(inner.op, ast.Mod):
            return True
        if isinstance(inner, ast.Call) and _simple_name(inner.func) == "format":
            return True
    return False


def _imported_roots(node: ast.Import | ast.ImportFrom) -> tuple[str, ...]:
    """Every root package an import node names, relative imports included."""
    if isinstance(node, ast.Import):
        return tuple(alias.name.split(".")[0] for alias in node.names)
    aliases = tuple(alias.name.split(".")[0] for alias in node.names)
    if not node.module:
        # `from . import subprocess`: the names ARE the modules.
        return aliases
    # A relative `from ..util import subprocess` may be importing a *module* named on the
    # alias, so both ends of the dotted module and the alias names all count. Stage 2 lost
    # a whole boundary to reading only `node.module` (S2-AUTH-01).
    parts = node.module.split(".")
    if node.level > 0:
        return (parts[0], parts[-1], *aliases)
    return (parts[0], parts[-1])
