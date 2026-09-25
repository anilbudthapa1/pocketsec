"""D4.19 — Stage 4 core functional IDs and the versioned CBF interface.

Twenty stable functional ids, mapped one-to-one onto the architecture's
``LUC-F01 … LUC-F20`` (architecture §36). Their purpose is the same as Stage 2's
``DTL-F*`` and Stage 3's ``AICT-F*`` sets: the hub depends on *functions*, not on
LUCID. Stage 4 is an attachment, not a layer — if the multi-world machinery is
measured to lose to a single-world MAP control (§7 B1, ADR-0036 is pre-assigned
to say so whichever way it falls), the hub keeps working against the same ids and
degrades to whatever survives.

Each id declares whether it is **REQUIRED** (Stage 4 cannot maintain a belief
field at all without it) or **OPTIONAL** (an experimental mechanism a measured
ablation may delete). An OPTIONAL id names the ``LucidConfig`` flag that removes
it, so "remove this mechanism" is a flag the gate can set rather than a code
edit nobody dares make. G4.10 enumerates exactly :data:`OPTIONAL_IDS` and demands
a registered experiment id with a *measured* delta for every member; an OPTIONAL
function with no measured delta is ``NOT_YET_JUSTIFIED``, never "kept because it
is there".

This module refuses to decide anything at runtime. It holds no thresholds, reads
no files and has no authority: it is the audit table that keeps the rename
``LUC-F*`` → ``CBF-F*`` traceable.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import ContractError, register_schema

__all__ = [
    "ABLATION_FLAGS",
    "CBF_INTERFACE_ID",
    "CBF_INTERFACE_VERSION",
    "CORE_IDS",
    "CoreFunction",
    "FunctionClass",
    "OPTIONAL_IDS",
    "REQUIRED_IDS",
    "core_function",
]

CBF_INTERFACE_ID = "pocketsec.cbf_interface.v1"
CBF_INTERFACE_VERSION = register_schema(CBF_INTERFACE_ID, "1.0.0")


class FunctionClass(StrEnum):
    #: Stage 4 cannot maintain or resolve a belief field without this.
    REQUIRED = "REQUIRED"
    #: Experimental. Must justify itself by measured ablation (G4.10) or go.
    OPTIONAL = "OPTIONAL"


@dataclass(frozen=True, slots=True)
class CoreFunction:
    """One functional id the hub may depend on, independent of its implementation."""

    core_id: str
    #: The architecture's own id for the same function (§36). Kept explicitly so
    #: the renaming LUC-F -> CBF-F stays auditable rather than implied.
    architecture_id: str
    name: str
    purpose: str
    function_class: FunctionClass
    #: Deliverable that implements it.
    deliverable: str
    #: The LucidConfig flag whose removal deletes this mechanism. Empty for a
    #: REQUIRED id: there is no flag, because there is no option.
    ablation_flag: str = ""

    def __post_init__(self) -> None:
        required = self.function_class is FunctionClass.REQUIRED
        if required and self.ablation_flag:
            raise ContractError(f"{self.core_id} is REQUIRED and may not name an ablation flag")
        if not required and not self.ablation_flag:
            raise ContractError(
                f"{self.core_id} is OPTIONAL and must name the flag that removes it; "
                "an optional mechanism with no off switch cannot be ablated"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "core_id": self.core_id,
            "architecture_id": self.architecture_id,
            "name": self.name,
            "purpose": self.purpose,
            "class": self.function_class.value,
            "deliverable": self.deliverable,
            "ablation_flag": self.ablation_flag,
        }


_REQUIRED = FunctionClass.REQUIRED
_OPTIONAL = FunctionClass.OPTIONAL

# Flag names, spelled once. Two ids sharing a flag are one mechanism with two
# entry points (fission without fusion is an unbounded world count), and the
# table says so by reusing the constant rather than repeating a string.
_FISSION_FUSION = "enable_fission_fusion"
_SEQUENTIAL = "enable_sequential_evidence"
_COUNTERFACTUAL = "enable_counterfactual"
_ACTIVE_SENSING = "enable_active_sensing"
_SELF_QUESTIONING = "enable_self_questioning"
_STRESS = "enable_stress"
_CELL_FEEDBACK = "enable_cell_feedback"


_FUNCTIONS = (
    CoreFunction(
        "CBF-F01",
        "LUC-F01",
        "update_causal_belief_field",
        "Fold one transition into the field: support, tension, births, deaths",
        _REQUIRED,
        "D4.2",
    ),
    CoreFunction(
        "CBF-F02",
        "LUC-F02",
        "spawn_world",
        "Create a bounded world only for a security-relevant unexplained residual",
        _REQUIRED,
        "D4.5",
    ),
    CoreFunction(
        "CBF-F03",
        "LUC-F03",
        "kill_world",
        "Retire a world on contradiction or sustained tension, leaving a tombstone",
        _REQUIRED,
        "D4.5",
    ),
    CoreFunction(
        "CBF-F04",
        "LUC-F04",
        "fission_world",
        "Split a world that predicts two incompatible evidence regimes",
        # OPTIONAL: adaptive complexity is the hypothesis, and Stage 3 already
        # measured that its own fusion convenience did not earn its keep.
        _OPTIONAL,
        "D4.5",
        _FISSION_FUSION,
    ),
    CoreFunction(
        "CBF-F05",
        "LUC-F05",
        "fuse_worlds",
        "Merge two observationally and security equivalent worlds into one",
        _OPTIONAL,
        "D4.5",
        _FISSION_FUSION,
    ),
    CoreFunction(
        "CBF-F06",
        "LUC-F06",
        "estimate_sensor_shadow",
        "Record what the active collection policy could not have observed",
        _REQUIRED,
        "D4.3",
    ),
    CoreFunction(
        "CBF-F07",
        "LUC-F07",
        "calculate_evidence_tension",
        "Measure a world against reality, not only the evidence that supports it",
        _REQUIRED,
        "D4.4",
    ),
    CoreFunction(
        "CBF-F08",
        "LUC-F08",
        "update_sequential_evidence",
        "Accumulate anytime-valid evidence for worlds that unfold slowly",
        # OPTIONAL: an e-process is a statistical guarantee with preconditions
        # this repository's synthetic corpora cannot establish. It must beat a
        # plain running log-odds or be deleted.
        _OPTIONAL,
        "D4.10",
        _SEQUENTIAL,
    ),
    CoreFunction(
        "CBF-F09",
        "LUC-F09",
        "counterfactual_intervene",
        "Perturb one event inside a world model and measure the predicted change",
        # OPTIONAL: Stage 2's counterfactual credit was REJECTED (ADR-0122) as
        # more concise than naive ancestry but at lower recall. Same bar here.
        _OPTIONAL,
        "D4.6",
        _COUNTERFACTUAL,
    ),
    CoreFunction(
        "CBF-F10",
        "LUC-F10",
        "calculate_responsibility_flux",
        "Let causal responsibility move between events as evidence arrives",
        _OPTIONAL,
        "D4.6",
        _COUNTERFACTUAL,
    ),
    CoreFunction(
        "CBF-F11",
        "LUC-F11",
        "predict_world_future_cone",
        "Enumerate the bounded security-relevant futures a world implies",
        # REQUIRED despite Stage 2's cone rejection (ADR-0116): D4.9 cannot
        # score a candidate observation without the futures it would separate.
        _REQUIRED,
        "D4.7",
    ),
    CoreFunction(
        "CBF-F12",
        "LUC-F12",
        "test_identifiability",
        "Decide whether the evidence can name one world, and refuse when it cannot",
        _REQUIRED,
        "D4.8",
    ),
    CoreFunction(
        "CBF-F13",
        "LUC-F13",
        "plan_discriminating_observation",
        "Rank candidate observations by what they would separate, not by volume",
        _OPTIONAL,
        "D4.9",
        _ACTIVE_SENSING,
    ),
    CoreFunction(
        "CBF-F14",
        "LUC-F14",
        "simulate_sensor_value",
        "Refuse to spend telemetry budget when outcomes barely differ across worlds",
        _OPTIONAL,
        "D4.9",
        _ACTIVE_SENSING,
    ),
    CoreFunction(
        "CBF-F15",
        "LUC-F15",
        "self_question_world",
        "Run the §24 challenges against a high-consequence world as typed tests",
        _OPTIONAL,
        "D4.11",
        _SELF_QUESTIONING,
    ),
    CoreFunction(
        "CBF-F16",
        "LUC-F16",
        "stress_world_adversarially",
        "Attack a conclusion with semantics-preserving perturbations before resolving",
        _OPTIONAL,
        "D4.11",
        _STRESS,
    ),
    CoreFunction(
        "CBF-F17",
        "LUC-F17",
        "prune_dominated_worlds",
        "Reduce world count without losing a materially different alternative",
        _REQUIRED,
        "D4.5",
    ),
    CoreFunction(
        "CBF-F18",
        "LUC-F18",
        "compile_typed_claim_graph",
        "Compile human-readable claims from typed evidence, never freely",
        _REQUIRED,
        "D4.13",
    ),
    CoreFunction(
        "CBF-F19",
        "LUC-F19",
        "stress_stage3_cell",
        "Send contradiction pressure back at a Knowledge Cell that claims benign",
        # OPTIONAL: no stage may be permanently unquestionable (§27), but the
        # reverse channel is also the one that can destabilise trusted cells.
        _OPTIONAL,
        "D4.14",
        _CELL_FEEDBACK,
    ),
    CoreFunction(
        "CBF-F20",
        "LUC-F20",
        "export_incident_world_record",
        "Hand Stage 5 the surviving field, its lineage and its information gaps",
        # D4.1 (continued) specifies stage5_interface.CBFResolutionV1; ADR-0039
        # records the plain-JSON seam decision.
        _REQUIRED,
        "D4.1",
    ),
)

CORE_IDS = MappingProxyType({function.core_id: function for function in _FUNCTIONS})

#: Functions Stage 4 genuinely cannot lose. Everything else is a hypothesis.
#: A tuple, in architecture order, because G4.10 reports them in order and a
#: frozenset would make the report's ordering an accident of hashing.
REQUIRED_IDS = tuple(fn.core_id for fn in _FUNCTIONS if fn.function_class is _REQUIRED)

#: The ablation surface. G4.10 reads exactly this and demands a registered
#: experiment id with a measured delta for every member.
OPTIONAL_IDS = tuple(fn.core_id for fn in _FUNCTIONS if fn.function_class is _OPTIONAL)

#: core_id -> the LucidConfig flag that removes it. OPTIONAL ids only, so a
#: caller iterating this mapping cannot accidentally "ablate" a required
#: function by reading an empty flag name as a valid one.
ABLATION_FLAGS = MappingProxyType(
    {fn.core_id: fn.ablation_flag for fn in _FUNCTIONS if fn.function_class is _OPTIONAL}
)


def core_function(core_id: str) -> CoreFunction:
    """Look one id up, failing loudly rather than returning ``None``."""
    try:
        return CORE_IDS[core_id]
    except KeyError as exc:
        raise KeyError(f"unknown Stage 4 core id {core_id!r}") from exc


assert len(CORE_IDS) == 20, "the architecture defines exactly twenty core functional IDs"
assert len(REQUIRED_IDS) + len(OPTIONAL_IDS) == 20, "every id is required or optional, never both"
assert {fn.architecture_id for fn in _FUNCTIONS} == {
    f"LUC-F{index:02d}" for index in range(1, 21)
}, "the CBF ids must map one-to-one onto the architecture's LUC-F ids"
assert [fn.core_id for fn in _FUNCTIONS] == [
    f"CBF-F{index:02d}" for index in range(1, 21)
], "the table keeps the architecture's own order; G4.10 reports against the index"
