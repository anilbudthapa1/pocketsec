"""Stage 8 core functional ids and one lazy symbol resolver.

Twenty-five stable ids, ``PROM-F01 … PROM-F25``, one per architecture layer 8.0-8.24
(spec §4.22). They serve the purpose Stage 6's ``HEL-F*`` and Stage 7's ``ORPH-F*`` sets
serve: the gate and the ablation runner depend on *functions*, not on PROMETHEUS, ORACLE
or FORGE. Every stage so far has rejected most of its own machinery on measurement; if
the priority field, the ecology or ORACLE's information gain lose to their simple
controls, the discovery loop keeps working against the same ids and degrades to whatever
survives.

Each id is **REQUIRED** (the falsification discipline or the no-authority boundary cannot
run without it) or **OPTIONAL** (a mechanism a measured ablation may delete). A row
carries its ablation flags and, position for position, the simple control each flag
switches to. An OPTIONAL row with no flag could never be removed and is refused on
construction; a REQUIRED row may carry flags too (the PROMETHEUS generators,
``negative_memory``, the vault's ``holdout_discipline`` and ``bonferroni``), because a
required defence that never fires is still a finding.

**Symbols are resolved lazily.** Every row names the ``"module:qualname"`` that
implements it, and this module imports none of them: eight work packages build in
parallel and most of those modules do not exist when this one is written.
:func:`resolve_symbols` walks the table with :mod:`importlib` on demand; ``()`` is the
only passing answer. PROM-F25 names a ``labs`` symbol: it is only ever *resolved* here,
by string, for the gate — no runtime module binds a ``labs`` name through this table.
Only a string matching :data:`SYMBOL_PATTERN` (``pocketsec.stage8.…``) is ever imported.

This module decides nothing at runtime, holds no state and has no authority.
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from pocketsec.stage0.contracts.common import ContractError

__all__ = [
    "ABLATION_FLAGS",
    "ARCHITECTURE_LAYERS",
    "STAGE8_FUNCTIONS",
    "SYMBOL_PATTERN",
    "FunctionClass",
    "Stage8Function",
    "optional_functions",
    "resolve_symbols",
    "stage8_function",
    "symbol_problem",
]

#: ``pocketsec.stage8.<module path>:<Qualified.name>``. Stage 8 names only its own
#: symbols here; a row pointing into another stage would make that stage's rename a
#: silent Stage 8 regression.
SYMBOL_PATTERN = re.compile(
    r"^pocketsec\.stage8(?:\.[a-z_][a-z0-9_]*)+:[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$"
)

#: Every ablation flag §4.22 names, in table order. Held as data so the ablation runner
#: can be joined to it: a flag with no ablation row is an unablated mechanism.
ABLATION_FLAGS: tuple[str, ...] = (
    "priority_field",
    "residual_motif",
    "analogy",
    "null_benign",
    "stage7_seed",
    "external_proposal",
    "diversity",
    "mutation",
    "mdl",
    "score_full",
    "oracle",
    "cost_aware",
    "eig",
    "doppelganger_screen",
    "negative_memory",
    "holdout_discipline",
    "bonferroni",
)

#: Architecture §2's layer map, verbatim: layer id -> subsystem name.
ARCHITECTURE_LAYERS: Mapping[str, str] = MappingProxyType(
    {
        "8.0": "Discovery Constitution",
        "8.1": "Residual Observatory",
        "8.2": "Discovery Priority Field",
        "8.3": "Hypothesis Genome",
        "8.4": "PROMETHEUS",
        "8.5": "Hypothesis Ecology",
        "8.6": "Mechanism Grammar",
        "8.7": "ORACLE",
        "8.8": "Experiment Value Engine",
        "8.9": "Counterfactual Laboratory",
        "8.10": "Metamorphic Laboratory",
        "8.11": "Benign Doppelgänger Engine",
        "8.12": "Adversarial Challenger",
        "8.13": "Causal Identifiability Gate",
        "8.14": "Theory Ledger",
        "8.15": "Discovery Reproducibility Gate",
        "8.16": "FORGE",
        "8.17": "Representation Tournament",
        "8.18": "Discovery Compression Ratio",
        "8.19": "Stage 6 Admission Bridge",
        "8.20": "Safety Sandbox",
        "8.21": "Research Resource Governor",
        "8.22": "Research Integrity Plane",
        "8.23": "Novelty/Originality Audit",
        "8.24": "Assurance/Falsification",
    }
)


class FunctionClass(StrEnum):
    #: The falsification discipline or the no-authority boundary cannot run without this.
    REQUIRED = "REQUIRED"
    #: Experimental. Must justify itself by ablation against its simple control, or go.
    OPTIONAL = "OPTIONAL"


@dataclass(frozen=True, slots=True)
class Stage8Function:
    """One row of spec §4.22. ``controls[i]`` is what ``ablation_flags[i]`` switches to."""

    core_id: str
    layer: str
    title: str
    function_class: FunctionClass
    symbol: str
    ablation_flags: tuple[str, ...]
    controls: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.core_id, str) or not re.fullmatch(r"PROM-F\d{2}", self.core_id):
            raise ContractError(f"core_id must look like PROM-F01, got {self.core_id!r}")
        expected_layer = f"8.{int(self.core_id[-2:]) - 1}"
        if self.layer != expected_layer:
            raise ContractError(f"{self.core_id} is layer {expected_layer}, not {self.layer!r}")
        if ARCHITECTURE_LAYERS.get(self.layer) != self.title:
            raise ContractError(f"{self.core_id}: {self.title!r} is not layer {expected_layer}")
        if not isinstance(self.symbol, str) or not SYMBOL_PATTERN.fullmatch(self.symbol):
            raise ContractError(f"{self.core_id}: symbol {self.symbol!r} is not module:qualname")
        if not isinstance(self.function_class, FunctionClass):
            raise ContractError(f"{self.core_id}: function_class must be a FunctionClass")
        self._check_ablation()

    def _check_ablation(self) -> None:
        flags, controls = self.ablation_flags, self.controls
        if not isinstance(flags, tuple) or not isinstance(controls, tuple):
            raise ContractError(f"{self.core_id}: flags and controls are tuples")
        if len(flags) != len(controls):
            raise ContractError(f"{self.core_id}: every ablation flag names its control")
        if len(set(flags)) != len(flags):
            raise ContractError(f"{self.core_id}: an ablation flag is listed twice")
        unknown = [flag for flag in flags if flag not in ABLATION_FLAGS]
        if unknown:
            raise ContractError(f"{self.core_id}: unknown ablation flag {unknown[0]!r}")
        if any(not isinstance(c, str) or not c.strip() for c in controls):
            raise ContractError(f"{self.core_id}: a control must be named, not blank")
        if self.function_class is FunctionClass.OPTIONAL and not flags:
            raise ContractError(f"{self.core_id} is OPTIONAL with no flag: never removable")

    def control_map(self) -> Mapping[str, str]:
        """``ablation flag -> control`` for this row."""
        return MappingProxyType(dict(zip(self.ablation_flags, self.controls, strict=True)))


def _row(
    number: int,
    symbol: str,
    function_class: FunctionClass = FunctionClass.REQUIRED,
    ablation: tuple[tuple[str, str], ...] = (),
) -> Stage8Function:
    """Build one table row; ``symbol`` is relative to ``pocketsec.stage8``."""
    layer = f"8.{number - 1}"
    return Stage8Function(
        core_id=f"PROM-F{number:02d}",
        layer=layer,
        title=ARCHITECTURE_LAYERS[layer],
        function_class=function_class,
        symbol=f"pocketsec.stage8.{symbol}",
        ablation_flags=tuple(flag for flag, _ in ablation),
        controls=tuple(control for _, control in ablation),
    )


_OPTIONAL = FunctionClass.OPTIONAL
_GENERATOR_OFF = "generator off"

#: Spec §4.22, verbatim. The REQUIRED/OPTIONAL split and every control are the spec's.
STAGE8_FUNCTIONS: tuple[Stage8Function, ...] = (
    _row(1, "constitution.discovery:verify_discovery_constitution"),
    _row(2, "residual.observatory:ResidualObservatory"),
    _row(3, "residual.priority_field:prioritise", _OPTIONAL, (("priority_field", "SIZE_ONLY"),)),
    _row(4, "genome.hypothesis:HypothesisGenome"),
    _row(
        5,
        "prometheus.engine:PrometheusEngine",
        ablation=(
            ("residual_motif", _GENERATOR_OFF),
            ("analogy", _GENERATOR_OFF),
            ("null_benign", _GENERATOR_OFF),
            ("stage7_seed", _GENERATOR_OFF),
            ("external_proposal", _GENERATOR_OFF),
            ("diversity", "top-k"),
        ),
    ),
    _row(
        6,
        "ecology.population:HypothesisPopulation",
        _OPTIONAL,
        (("mutation", "off"), ("mdl", "off"), ("score_full", "FIT_ONLY")),
    ),
    _row(7, "genome.grammar:Mechanism"),
    _row(8, "oracle.planner:OraclePlanner", _OPTIONAL,
         (("oracle", "off (register top-k by score)"),)),
    _row(9, "oracle.information_gain:expected_information_gain", _OPTIONAL,
         (("cost_aware", "EIG_ONLY"), ("eig", "RANDOM, CHEAPEST"))),
    _row(10, "laboratory.counterfactual:apply_transform"),
    _row(11, "laboratory.metamorphic:run_metamorphic"),
    _row(12, "doppelganger.engine:DoppelgangerEngine", _OPTIONAL,
         (("doppelganger_screen", "off"),)),
    _row(13, "challenger.adversarial:challenge"),
    _row(14, "identifiability.gate:IdentifiabilityGate"),
    _row(15, "ledger.theory:TheoryLedger", ablation=(("negative_memory", "off"),)),
    _row(16, "reproducibility.gate:ReproducibilityGate"),
    _row(17, "forge.compiler:compile_all"),
    _row(18, "forge.tournament:run_tournament"),
    _row(19, "forge.tournament:discovery_compression_ratio"),
    _row(20, "adapters.stage6:Stage6Adapter"),
    _row(21, "sandbox.boundary:ResearchSandbox"),
    _row(22, "governor.budget:ResearchGovernor"),
    # REQUIRED: the vault is the discipline. NAIVE is a control run to show what the
    # discipline prevents, never a mode the loop may run in.
    _row(23, "sandbox.integrity:HoldoutVault",
         ablation=(("holdout_discipline", "NAIVE (control only)"),
                   ("bonferroni", "NAIVE (control only)"))),
    _row(24, "novelty.prior_art_audit:audit"),
    _row(25, "labs.baselines:run_ablation"),
)  # fmt: skip

_BY_ID: Mapping[str, Stage8Function] = MappingProxyType(
    {function.core_id: function for function in STAGE8_FUNCTIONS}
)

# Import-time invariants, raised rather than asserted so ``-O`` cannot strip them.
if len(_BY_ID) != len(STAGE8_FUNCTIONS) or len(STAGE8_FUNCTIONS) != len(ARCHITECTURE_LAYERS):
    raise ContractError("STAGE8_FUNCTIONS must hold exactly one distinct id per layer 8.0-8.24")
if [f.layer for f in STAGE8_FUNCTIONS] != list(ARCHITECTURE_LAYERS):
    raise ContractError("STAGE8_FUNCTIONS must cover layers 8.0-8.24 in order")
if sorted(flag for f in STAGE8_FUNCTIONS for flag in f.ablation_flags) != sorted(ABLATION_FLAGS):
    raise ContractError("every ABLATION_FLAGS entry is used by exactly one row")


def stage8_function(core_id: str) -> Stage8Function:
    """The row for ``core_id``; a ``ContractError`` for an id the spec never named."""
    try:
        return _BY_ID[core_id]
    except KeyError:
        raise ContractError(f"unknown Stage 8 core id {core_id!r}") from None


def optional_functions() -> tuple[Stage8Function, ...]:
    """Every row a measured ablation may delete, in table order."""
    return tuple(f for f in STAGE8_FUNCTIONS if f.function_class is FunctionClass.OPTIONAL)


def symbol_problem(symbol: str) -> str | None:
    """Why ``symbol`` does not resolve, or ``None`` when it does.

    Importing the module is the test: a module that exists but raises on import is as
    unusable as one that does not exist, so the exception text becomes the reason rather
    than propagating. Only a string matching :data:`SYMBOL_PATTERN` is looked up — never
    an arbitrary dotted path, and never anything outside ``pocketsec.stage8``.
    """
    if not isinstance(symbol, str) or not SYMBOL_PATTERN.fullmatch(symbol):
        return "malformed: not pocketsec.stage8.<module>:<qualname>"
    module_name, qualname = symbol.split(":", 1)
    try:
        target: object = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        return f"module not found: {exc.name}"
    except Exception as exc:  # another package's module raising on import
        return f"module raises on import: {type(exc).__name__}: {exc}"
    for part in qualname.split("."):
        if not hasattr(target, part):
            return f"{module_name} has no attribute {qualname!r}"
        target = getattr(target, part)
    if not callable(target):
        return f"{symbol} resolves to a non-callable {type(target).__name__}"
    return None


def resolve_symbols() -> tuple[str, ...]:
    """Symbols of :data:`STAGE8_FUNCTIONS` that fail to resolve; ``()`` = all resolve."""
    return tuple(f.symbol for f in STAGE8_FUNCTIONS if symbol_problem(f.symbol) is not None)
