"""Stage 9 core functional ids ``ONTO-F01 … ONTO-F20`` and one lazy symbol resolver.

One id per Phase 9 deliverable (D9.1 … D9.20), in the shape Stage 2's ``DTL-F*``,
Stage 6's ``HEL-F*`` and Stage 7's ``ORPH-F*`` sets already use: the hub, the gate and
Stage 10 depend on *functions*, not on ONTOGENESIS. Every earlier stage rejected most of
its own machinery on measurement (ADR-0010 rejected Stage 2's core). If the search, the
physics-inspired laboratories or the ecology lose to their simple controls, the rest of
the system keeps working against these ids and degrades to what survives.

Each row is **REQUIRED** (the stage's boundary or its measurement substrate cannot work
without it) or **OPTIONAL** (a mechanism a measured ablation may delete). A row names its
ablation flags as ``"pocketsec.stage9.<module>:<NAME>_DEFAULT_ENABLED"`` strings and,
position for position, the simple control each flag switches to. An OPTIONAL row with no
flag could never be removed, and is refused at import. Every flag ships ``False``; only
the integrator may set one ``True``, after a measured JUSTIFIED verdict (spec §4.22).
Gate G9.9 reads :func:`optional_flags` and joins each triple to the ``DetectorComparison``
its owning ``compare_*`` returned.

**Symbols are resolved lazily.** Eight work packages build in parallel, so most of the
modules named here do not exist when this one is imported. This module imports none of
them; :func:`resolve_symbols` walks the table with :mod:`importlib` on demand, and ``()``
is the only passing answer. Only strings matching :data:`SYMBOL_PATTERN` or
:data:`FLAG_PATTERN` are ever imported - never an arbitrary dotted path, and never a
module outside ``pocketsec.stage9``. This is one of the three declared ``importlib``
exemptions (spec §2.2).

This module decides nothing at runtime, holds no state and carries no authority.
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage2.core_ids import FunctionClass

__all__ = [
    "FLAG_PATTERN",
    "STAGE9_FUNCTIONS",
    "SYMBOL_PATTERN",
    "FunctionClass",
    "Stage9Function",
    "flag_problem",
    "flag_value",
    "optional_flags",
    "resolve_symbols",
    "stage9_function",
    "symbol_problem",
]

#: ``pocketsec.stage9.<module path>:<Name>``: Stage 9 names only its own symbols here, so
#: a rename elsewhere cannot become a silent Stage 9 regression.
SYMBOL_PATTERN = re.compile(r"^pocketsec\.stage9(?:\.[a-z_][a-z0-9_]*)+:[A-Za-z_][A-Za-z0-9_]*$")

#: An ablation flag: a module-level boolean constant named ``*_DEFAULT_ENABLED``.
FLAG_PATTERN = re.compile(
    r"^pocketsec\.stage9(?:\.[a-z_][a-z0-9_]*)+:[A-Z][A-Z0-9_]*_DEFAULT_ENABLED$"
)

_CORE_ID = re.compile(r"^ONTO-F(\d{2})$")


@dataclass(frozen=True, slots=True)
class Stage9Function:
    """One row of spec §4.22. ``controls[i]`` is what ``ablation_flags[i]`` switches to."""

    core_id: str
    name: str
    deliverable: str
    function_class: FunctionClass
    symbol: str
    ablation_flags: tuple[str, ...]
    controls: tuple[str, ...]

    def __post_init__(self) -> None:
        match = _CORE_ID.fullmatch(self.core_id)
        if match is None:
            raise ContractError(f"core_id must look like ONTO-F01, got {self.core_id!r}")
        if self.deliverable != f"D9.{int(match.group(1))}":
            raise ContractError(f"{self.core_id} must bind D9.{int(match.group(1))}")
        if not isinstance(self.name, str) or not self.name.strip():
            raise ContractError(f"{self.core_id}: name must be non-empty")
        if not isinstance(self.function_class, FunctionClass):
            raise ContractError(f"{self.core_id}: function_class must be a FunctionClass")
        if not SYMBOL_PATTERN.fullmatch(self.symbol):
            raise ContractError(f"{self.core_id}: symbol {self.symbol!r} is not module:Name")
        self._check_ablation()

    def _check_ablation(self) -> None:
        flags, controls = self.ablation_flags, self.controls
        if not isinstance(flags, tuple) or not isinstance(controls, tuple):
            raise ContractError(f"{self.core_id}: ablation_flags and controls are tuples")
        if len(flags) != len(controls):
            raise ContractError(f"{self.core_id}: every ablation flag names its control")
        if len(set(flags)) != len(flags):
            raise ContractError(f"{self.core_id}: an ablation flag is listed twice")
        for flag in flags:
            if not isinstance(flag, str) or not FLAG_PATTERN.fullmatch(flag):
                raise ContractError(f"{self.core_id}: {flag!r} is not module:*_DEFAULT_ENABLED")
        if any(not isinstance(c, str) or not c.strip() for c in controls):
            raise ContractError(f"{self.core_id}: a control must be named, not blank")
        if self.function_class is FunctionClass.OPTIONAL and not flags:
            raise ContractError(
                f"{self.core_id} is OPTIONAL with no ablation flag: it could never be removed"
            )


_P = "pocketsec.stage9."
_REQUIRED = FunctionClass.REQUIRED
_OPTIONAL = FunctionClass.OPTIONAL


def _row(
    number: int,
    name: str,
    symbol: str,
    function_class: FunctionClass = _REQUIRED,
    ablation: tuple[tuple[str, str], ...] = (),
) -> Stage9Function:
    """One table row; ``symbol`` and flags are relative to ``pocketsec.stage9``."""
    return Stage9Function(
        core_id=f"ONTO-F{number:02d}",
        name=name,
        deliverable=f"D9.{number}",
        function_class=function_class,
        symbol=_P + symbol,
        ablation_flags=tuple(_P + flag for flag, _ in ablation),
        controls=tuple(control for _, control in ablation),
    )


#: Spec §4.22. Names are the Phase 9 checklist's; symbols are the spec §4 entry points.
STAGE9_FUNCTIONS: tuple[Stage9Function, ...] = (
    _row(1, "MSSC formal research specification", "spec.mssc:check_constraints"),
    _row(2, "Computational Genome schema", "genome.computational:ComputationalGenomeV1"),
    _row(3, "LAPLACE state/law discovery engine", "laplace.state_discovery:discover_minimal_state",
         _OPTIONAL,
         (("laplace.law_discovery:LEARNING_LAW_SEARCH_DEFAULT_ENABLED", "NO_LEARNING"),)),
    _row(4, "Primitive Foundry + promotion gate", "foundry.promotion:promotion_gate", _OPTIONAL,
         (("foundry.promotion:PRIMITIVE_FOUNDRY_DEFAULT_ENABLED", "seed alphabet"),)),
    _row(5, "Algorithmic Chemistry typed IR", "chemistry.typed_ir:validate_program"),
    _row(6, "Security Renormalization laboratory", "renormalization.laboratory:run_renormalization",
         _OPTIONAL, (("renormalization.laboratory:RENORMALIZATION_DEFAULT_ENABLED",
                      "raw representation + equal-byte random group drop"),)),
    _row(7, "Symmetry/Conservation research suite", "symmetry.suite:invariance", _OPTIONAL, (
        ("symmetry.suite:SYMMETRY_BREAKING_DEFAULT_ENABLED", "rarity (max features[83]), Φ-oracle"),
        ("symmetry.conservation:CONSERVATION_DEFAULT_ENABLED", "Φ-oracle, H2"),
    )),
    _row(8, "Causal Geometry/Phase Observatory benchmarks", "geometry.causal:mechanism_distance",
         _OPTIONAL, (
             ("geometry.causal:CAUSAL_GEOMETRY_DEFAULT_ENABLED", "pooled-feature kNN, Φ-oracle"),
             ("geometry.phase:PHASE_OBSERVATORY_DEFAULT_ENABLED", "CUSUM on ΔΦ, Φ-oracle"),
         )),
    _row(9, "MSDL/Predictive Compression suite", "compression.msdl:msdl", _OPTIONAL, (
        ("compression.msdl:MSDL_SELECTION_DEFAULT_ENABLED", "Pareto choice"),
        ("compression.msdl:SURPRISE_DEFAULT_ENABLED", "Stage 1 novelty peak, Φ-oracle"),
    )),
    _row(10, "CHRONOS memory/forgetting-law engine", "chronos.forgetting_law:evaluate_families",
         _OPTIONAL, (("chronos.forgetting_law:LEARNED_FORGETTING_DEFAULT_ENABLED", "EXACT_RING"),)),
    _row(11, "DAEDALUS system synthesizer", "daedalus.synthesizer:synthesize"),
    _row(12, "GENESIS variation/speciation engine", "genesis.variation:mutate", _OPTIONAL, (
        ("ontogenesis.search:EVOLUTIONARY_SEARCH_DEFAULT_ENABLED",
         "random search + exhaustive enumeration at equal budget"),
        ("ontogenesis.search:SUBTRACTIVE_BIAS_DEFAULT_ENABLED", "no forced deletion"),
        ("genesis.speciation:MORPHOGENESIS_DEFAULT_ENABLED", "one universal phenotype"),
    )),
    _row(13, "GAIA QD ecology", "gaia.qd_ecology:QualityDiversityArchive", _OPTIONAL, (
        ("gaia.qd_ecology:QD_ARCHIVE_DEFAULT_ENABLED", "single-cell elitist archive"),
        ("gaia.qd_ecology:FOSSIL_AVOIDANCE_DEFAULT_ENABLED", "no fossil avoidance"),
    )),
    _row(14, "ARGUS architecture adversary", "argus.adversary:attack_findings"),
    # REQUIRED: degradation must expose lost coverage (G9.5). Hysteresis is the OPTIONAL part.
    _row(15, "Homeostatic Runtime controller", "runtime.homeostatic:HomeostaticController",
         ablation=(("runtime.homeostatic:HYSTERESIS_DEFAULT_ENABLED", "no hysteresis"),)),
    _row(16, "Convergence/Law Observatory", "observatory.convergence:convergence"),
    _row(17, "Proof-Carrying Successor Package", "successor.proof_carrying:build_successor"),
    _row(18, "Hardware-in-loop benchmark harness", "harness.hardware_in_loop:measure_phenotype"),
    _row(19, "120-experiment falsification program", "labs.one_twenty_experiments:resolve_runners"),
    _row(20, "Final MSSC thesis report + Stage 1-9 reproducibility package",
         "harness.reproducibility:build_manifest"),
)  # fmt: skip

_BY_ID: Mapping[str, Stage9Function] = MappingProxyType(
    {function.core_id: function for function in STAGE9_FUNCTIONS}
)

# Import-time invariants, raised rather than asserted so ``-O`` cannot strip them.
if [f.core_id for f in STAGE9_FUNCTIONS] != [f"ONTO-F{n:02d}" for n in range(1, 21)]:
    raise ContractError("STAGE9_FUNCTIONS must hold ONTO-F01..ONTO-F20 exactly once, in order")
_ALL_FLAGS = [flag for f in STAGE9_FUNCTIONS for flag in f.ablation_flags]
if len(set(_ALL_FLAGS)) != len(_ALL_FLAGS):
    raise ContractError("an ablation flag is owned by more than one row")


def stage9_function(core_id: str) -> Stage9Function:
    """The row for ``core_id``; a ``ContractError`` for an id the spec never named."""
    try:
        return _BY_ID[core_id]
    except KeyError:
        raise ContractError(f"unknown Stage 9 core id {core_id!r}") from None


def optional_flags() -> tuple[tuple[str, str, str], ...]:
    """Every ``(core_id, "module:CONSTANT", control)`` triple, in table order (G9.9 reads it).

    It includes the flag on the REQUIRED row ONTO-F15: a required component's optional
    mechanism must justify itself exactly like an optional component.
    """
    return tuple(
        (function.core_id, flag, control)
        for function in STAGE9_FUNCTIONS
        for flag, control in zip(function.ablation_flags, function.controls, strict=True)
    )


def _resolve(reference: str, pattern: re.Pattern[str]) -> tuple[object | None, str | None]:
    """Import ``module`` and walk to ``Name``; the object, or why it could not be reached."""
    if not isinstance(reference, str) or not pattern.fullmatch(reference):
        return None, f"malformed: {reference!r} is not pocketsec.stage9.<module>:<Name>"
    module_name, name = reference.split(":", 1)
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        return None, f"module not found: {exc.name}"
    except Exception as exc:  # another package's module raising on import is a finding
        return None, f"module raises on import: {type(exc).__name__}: {exc}"
    if not hasattr(module, name):
        return None, f"{module_name} has no attribute {name!r}"
    return getattr(module, name), None


def symbol_problem(symbol: str) -> str | None:
    """Why ``symbol`` does not resolve to a callable (function or class), or ``None``."""
    target, problem = _resolve(symbol, SYMBOL_PATTERN)
    if problem is not None:
        return problem
    if not callable(target):
        return f"{symbol} resolves to a non-callable {type(target).__name__}"
    return None


def flag_problem(flag: str) -> str | None:
    """Why ``flag`` does not resolve to a module-level ``bool``, or ``None``."""
    target, problem = _resolve(flag, FLAG_PATTERN)
    if problem is not None:
        return problem
    if not isinstance(target, bool):
        return f"{flag} is a {type(target).__name__}, not a bool"
    return None


def flag_value(flag: str) -> bool | None:
    """The CURRENT value of ``flag``'s module constant, read from code (G9.9), or ``None``
    when it does not resolve to a ``bool`` (``flag_problem`` says why)."""
    target, problem = _resolve(flag, FLAG_PATTERN)
    if problem is not None or not isinstance(target, bool):
        return None
    return target


def resolve_symbols() -> tuple[str, ...]:
    """Every symbol or flag in :data:`STAGE9_FUNCTIONS` that fails to resolve.

    ``()`` is the only passing answer. Each entry is ``"<reference>: <reason>"``.
    """
    problems: list[str] = []
    for function in STAGE9_FUNCTIONS:
        problem = symbol_problem(function.symbol)
        if problem is not None:
            problems.append(f"{function.symbol}: {problem}")
        for flag in function.ablation_flags:
            flag_reason = flag_problem(flag)
            if flag_reason is not None:
                problems.append(f"{flag}: {flag_reason}")
    return tuple(problems)
