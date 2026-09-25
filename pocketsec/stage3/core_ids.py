"""D3.1 (part) — AICT core functional IDs and the versioned Stage 3 interface.

Twenty stable functional IDs, mapped one-to-one onto the architecture's
``CRY-F01 … CRY-F20`` (architecture §31). Their purpose is the same as Stage 2's
``DTL-F*`` set and the Stage 0 model slot's: the hub depends on *functions*, not
on CRYSTAL. If the Knowledge Cell machinery is measured to be worthless and
deleted in Stage 4 — which is a live possibility, because the first
crystallisation target is a zero-parameter Φ-oracle that is already free — the
hub keeps working against the same ids, degrading to whatever remains.

Each id declares whether it is **required** (Stage 3 cannot present a cell at
all without it) or **optional** (an experimental mechanism that ablation may
delete). Acceptance criterion G3.11 enumerates every ``OPTIONAL`` id here and
demands a registered experiment id with a *measured* delta for each one. Nothing
is marked OPTIONAL that this wave is not prepared to ablate, and an OPTIONAL
mechanism with no measured delta is ``NOT_YET_JUSTIFIED`` — never "kept because
it is there".
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import register_schema

__all__ = [
    "AICT_INTERFACE_ID",
    "AICT_INTERFACE_VERSION",
    "CORE_IDS",
    "CoreFunction",
    "FunctionClass",
    "OPTIONAL_IDS",
    "REQUIRED_IDS",
]

AICT_INTERFACE_ID = "pocketsec.aict_interface.v1"
AICT_INTERFACE_VERSION = register_schema(AICT_INTERFACE_ID, "1.0.0")


class FunctionClass(StrEnum):
    #: Stage 3 cannot produce or retire a Knowledge Cell without this.
    REQUIRED = "REQUIRED"
    #: Experimental. Must justify itself by ablation (G3.11) or be removed.
    OPTIONAL = "OPTIONAL"


@dataclass(frozen=True, slots=True)
class CoreFunction:
    """One functional id the hub may depend on, independent of its implementation."""

    core_id: str
    #: The architecture's own id for the same function (§31). Kept explicitly so
    #: the renaming CRY-F -> AICT-F stays auditable rather than implied.
    architecture_id: str
    name: str
    purpose: str
    function_class: FunctionClass
    #: Deliverable that implements it.
    deliverable: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "core_id": self.core_id,
            "architecture_id": self.architecture_id,
            "name": self.name,
            "purpose": self.purpose,
            "class": self.function_class.value,
            "deliverable": self.deliverable,
        }


_FUNCTIONS = (
    CoreFunction(
        "AICT-F01",
        "CRY-F01",
        "mine_candidate_regions",
        "Select behavioural regions worth attempting to compile",
        FunctionClass.REQUIRED,
        "D3.2",
    ),
    CoreFunction(
        "AICT-F02",
        "CRY-F02",
        "discover_invariant",
        "Generalise observed relationships over Stage 1 semantics, never identities",
        FunctionClass.REQUIRED,
        "D3.3",
    ),
    CoreFunction(
        "AICT-F03",
        "CRY-F03",
        "infer_boundary",
        "Infer the region in which a candidate invariant is allowed to answer",
        FunctionClass.REQUIRED,
        "D3.4",
    ),
    CoreFunction(
        "AICT-F04",
        "CRY-F04",
        "apply_boundary_pressure",
        "Guided perturbation search for counterexamples near a boundary",
        # OPTIONAL: G3.4 compares it against a same-budget random replay control
        # and removes the guided search outright if it finds no extra
        # counterexample class.
        FunctionClass.OPTIONAL,
        "D3.4",
    ),
    CoreFunction(
        "AICT-F05",
        "CRY-F05",
        "synthesize_operator",
        "Fit a bounded executable operator to a region, one form at a time",
        # OPTIONAL: the eight-form synthesiser set is the hypothesis. Baseline B2
        # is a depth-limited tree; if DECISION_DAG always wins, the other seven
        # synthesisers are NOT_YET_JUSTIFIED and must say so.
        FunctionClass.OPTIONAL,
        "D3.7",
    ),
    CoreFunction(
        "AICT-F06",
        "CRY-F06",
        "select_operator_form",
        "Choose the cheapest candidate form satisfying security equivalence",
        FunctionClass.OPTIONAL,
        "D3.7",
    ),
    CoreFunction(
        "AICT-F07",
        "CRY-F07",
        "evaluate_security_equivalence",
        "Dual-oracle decision on whether a cell may replace the learned path",
        FunctionClass.REQUIRED,
        "D3.8",
    ),
    CoreFunction(
        "AICT-F08",
        "CRY-F08",
        "check_hard_security_constraints",
        "Refuse a cell that suppresses evidence, lowers Phi or downgrades consequence",
        FunctionClass.REQUIRED,
        "D3.8",
    ),
    CoreFunction(
        "AICT-F09",
        "CRY-F09",
        "create_counterexample",
        "Record a frame on which the cell and the oracles disagreed",
        FunctionClass.REQUIRED,
        "D3.9",
    ),
    CoreFunction(
        "AICT-F10",
        "CRY-F10",
        "fission_cell",
        "Split a cell whose boundary accumulated incompatible behaviour",
        FunctionClass.REQUIRED,
        "D3.10",
    ),
    CoreFunction(
        "AICT-F11",
        "CRY-F11",
        "fuse_cells",
        "Merge cells with equivalent security-relevant behaviour",
        # OPTIONAL: fusion is a compression convenience. Stage 2 already measured
        # that an atom/epoch-keyed cache LOSES to a plain LRU; a merge mechanism
        # must show a measured delta or go.
        FunctionClass.OPTIONAL,
        "D3.10",
    ),
    CoreFunction(
        "AICT-F12",
        "CRY-F12",
        "shadow_execute",
        "Run a cell beside the learned path without authority over the answer",
        FunctionClass.REQUIRED,
        "D3.11",
    ),
    CoreFunction(
        "AICT-F13",
        "CRY-F13",
        "promote_cell",
        "Move a cell to the cheap authoritative path under an assurance level",
        FunctionClass.REQUIRED,
        "D3.11",
    ),
    CoreFunction(
        "AICT-F14",
        "CRY-F14",
        "audit_cell",
        "Sample a promoted cell against the oracles at an unpredictable rate",
        FunctionClass.REQUIRED,
        "D3.12",
    ),
    CoreFunction(
        "AICT-F15",
        "CRY-F15",
        "compute_cell_stress",
        "Accumulate disagreement, drift and decay pressure on one cell",
        # OPTIONAL: a stress scalar is one way to trigger melting; "melt on the
        # first corroborated epoch mismatch" is the simpler control it must beat.
        FunctionClass.OPTIONAL,
        "D3.13",
    ),
    CoreFunction(
        "AICT-F16",
        "CRY-F16",
        "partial_melt",
        "Reopen one subregion of a cell without discarding the rest",
        FunctionClass.REQUIRED,
        "D3.13",
    ),
    CoreFunction(
        "AICT-F17",
        "CRY-F17",
        "full_melt",
        "Retire a cell entirely and return its region to the learned path",
        FunctionClass.REQUIRED,
        "D3.13",
    ),
    CoreFunction(
        "AICT-F18",
        "CRY-F18",
        "recrystallize",
        "Re-compile a melted region once it has resolved again",
        FunctionClass.REQUIRED,
        "D3.13",
    ),
    CoreFunction(
        "AICT-F19",
        "CRY-F19",
        "garbage_collect_knowledge",
        "Forget cells by measured future utility rather than by age",
        # OPTIONAL: the bounded field already refuses to exceed MAX_CELLS, so GC
        # is an optimisation, not a safety property. It must earn its complexity.
        FunctionClass.OPTIONAL,
        "D3.14",
    ),
    CoreFunction(
        "AICT-F20",
        "CRY-F20",
        "export_assurance_record",
        "Emit what was proven, what was only tested, and the evidence for both",
        FunctionClass.REQUIRED,
        "D3.16",
    ),
)

CORE_IDS = MappingProxyType({function.core_id: function for function in _FUNCTIONS})

#: Functions Stage 3 genuinely cannot lose. Everything else is a hypothesis.
REQUIRED_IDS = frozenset(
    fn.core_id for fn in _FUNCTIONS if fn.function_class is FunctionClass.REQUIRED
)

#: The ablation surface. G3.11 reads exactly this set and demands a registered
#: experiment id with a measured delta for every member.
OPTIONAL_IDS = frozenset(
    fn.core_id for fn in _FUNCTIONS if fn.function_class is FunctionClass.OPTIONAL
)

assert len(CORE_IDS) == 20, "the architecture defines exactly twenty core functional IDs"
assert len(REQUIRED_IDS) + len(OPTIONAL_IDS) == 20, "every id is required or optional, never both"
assert {fn.architecture_id for fn in _FUNCTIONS} == {
    f"CRY-F{index:02d}" for index in range(1, 21)
}, "the AICT ids must map one-to-one onto the architecture's CRY-F ids"
