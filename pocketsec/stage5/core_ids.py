"""Stage 5 core functional IDs and the versioned SAFE interface.

Twenty-four stable functional ids, mapped one-to-one onto architecture §38's
``S5-F01 … S5-F24``. Their purpose is the same as Stage 2's ``DTL-F*``, Stage 3's
``AICT-F*`` and Stage 4's ``CBF-F*`` sets: the hub depends on *functions*, not on
SAFE, AEGIS or SENTINEL. If the Counterfactual Response Twin and the Intervention
Cone lose to a fixed playbook — which is the honest expectation, given Stage 2
returned zero justified learned mechanisms and Stage 3 rejected its own
compilation vehicle — the response loop keeps working against the same ids and
degrades to whatever survives.

Each id declares whether it is **REQUIRED** (the response loop cannot run without
it) or **OPTIONAL** (an experimental mechanism a measured ablation may delete). An
OPTIONAL id must name the ``PlannerConfig`` flag that removes it, and
``CoreFunction.__post_init__`` refuses the two inconsistent cases: an optional
mechanism with no off switch cannot be ablated, and a required function with a
flag is a switch somebody will eventually turn off.

``REQUIRED`` is a claim about the loop, not about measured value. F17
(``rollback_transaction``) and F19 (``plan_safe_recovery``) are REQUIRED even
though their real-host reliability is **UNMEASURED** and cannot be measured in
this repository: an executor with no rollback path is not a safer executor, it is
an unbounded one.

This module decides nothing at runtime. It holds no thresholds, reads no files and
has no authority: it is the audit table that keeps the rename ``S5-F*`` →
``SAFE-F*`` traceable, plus the five upstream schema versions Stage 5 pins.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import ContractError, register_schema

__all__ = [
    "ABLATION_FLAGS",
    "CORE_IDS",
    "OPTIONAL_IDS",
    "PINNED_UPSTREAM_SCHEMAS",
    "REQUIRED_IDS",
    "SAFE_INTERFACE_ID",
    "SAFE_INTERFACE_VERSION",
    "CoreFunction",
    "FunctionClass",
    "core_function",
]

SAFE_INTERFACE_ID = "pocketsec.safe_interface.v1"
SAFE_INTERFACE_VERSION = register_schema(SAFE_INTERFACE_ID, "1.0.0")

#: The upstream schema versions Stage 5 is built against, pinned as data so G5.1
#: ("Stages 0–4 remain unchanged/frozen interfaces for Stage 5 evaluation") can
#: *join* this table to ``SCHEMA_REGISTRY`` rather than assert that some types
#: exist. All five were read from the registry at 1.0.0 in this session; if an
#: upstream wave bumps one, the join fails and the gate says which id moved.
PINNED_UPSTREAM_SCHEMAS: Mapping[str, str] = MappingProxyType(
    {
        "pocketsec.security_event_sequence.v1": "1.0.0",
        "pocketsec.threat_prediction.v1": "1.0.0",
        "pocketsec.ssir_transition.v1": "1.0.0",
        "pocketsec.knowledge_cell.v1": "1.0.0",
        "pocketsec.cbf_resolution.v1": "1.0.0",
    }
)


class FunctionClass(StrEnum):
    #: The response loop cannot run without this.
    REQUIRED = "REQUIRED"
    #: Experimental. Must justify itself by measured ablation (G5.14) or go.
    OPTIONAL = "OPTIONAL"


@dataclass(frozen=True, slots=True)
class CoreFunction:
    """One functional id the hub may depend on, independent of its implementation."""

    core_id: str
    #: The architecture's own id for the same function (§38). Kept explicitly so
    #: the renaming S5-F -> SAFE-F stays auditable rather than implied.
    architecture_id: str
    name: str
    purpose: str
    function_class: FunctionClass
    #: Deliverable that implements it.
    deliverable: str
    #: The ``PlannerConfig`` flag whose removal deletes this mechanism. Empty for a
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
# entry points — crystallising and melting a response cell are the same switch —
# and the table says so by reusing the constant rather than repeating a string.
_TWIN = "enable_twin"
_CONE = "enable_cone"
_SHADOW = "enable_shadow_gate"
_REGRET = "enable_regret"
_PARETO = "enable_pareto"
_RESIDUAL = "enable_residual"
_HYSTERESIS = "enable_hysteresis"
_EFFECTIVENESS = "enable_effectiveness_memory"
_CELLS = "enable_response_cells"
_D3FEND = "enable_d3fend"


_FUNCTIONS = (
    CoreFunction(
        "SAFE-F01",
        "S5-F01",
        "generate_safe_action_field",
        "Enumerate the bounded candidate set; never open-ended planning",
        _REQUIRED,
        "D5.2",
    ),
    CoreFunction(
        "SAFE-F02",
        "S5-F02",
        "bind_target_identity",
        "Bind an action to a process identity, because a pid is not an identity",
        _REQUIRED,
        "D5.11",
    ),
    CoreFunction(
        "SAFE-F03",
        "S5-F03",
        "check_response_identifiability",
        "Refuse a candidate that harms a hypothesis the evidence has not ruled out",
        _REQUIRED,
        "D5.2",
    ),
    CoreFunction(
        "SAFE-F04",
        "S5-F04",
        "build_counterfactual_twin",
        "Predict the host's response to the action before taking it",
        # OPTIONAL: the twin is the most expensive thing Stage 5 does and the
        # fixed playbook (§7 B2) does not have one. If it does not reduce
        # measured collateral it is not justified.
        _OPTIONAL,
        "D5.7",
        _TWIN,
    ),
    CoreFunction(
        "SAFE-F05",
        "S5-F05",
        "build_intervention_cone",
        "Enumerate bounded adversary adaptations to the intervention",
        _OPTIONAL,
        "D5.8",
        _CONE,
    ),
    CoreFunction(
        "SAFE-F06",
        "S5-F06",
        "estimate_action_shadow",
        "Count what the action's model does not cover, and gate autonomy on it",
        _OPTIONAL,
        "D5.8",
        _SHADOW,
    ),
    CoreFunction(
        "SAFE-F07",
        "S5-F07",
        "calculate_action_regret",
        "Loss against the best admissible action in hindsight, per world",
        _OPTIONAL,
        "D5.9",
        _REGRET,
    ),
    CoreFunction(
        "SAFE-F08",
        "S5-F08",
        "construct_pareto_frontier",
        "Remove dominated actions before any scalar utility is computed",
        _OPTIONAL,
        "D5.9",
        _PARETO,
    ),
    CoreFunction(
        "SAFE-F09",
        "S5-F09",
        "check_mission_invariants",
        "Refuse an action that breaks a protected §24 invariant",
        _REQUIRED,
        "D5.1",
    ),
    CoreFunction(
        "SAFE-F10",
        "S5-F10",
        "preserve_evidence",
        "Build the pre-action bundle BEFORE the action, or refuse the action",
        _REQUIRED,
        "D5.10",
    ),
    CoreFunction(
        "SAFE-F11",
        "S5-F11",
        "sentinel_verify",
        "Independently deny any action, whatever the planner concluded",
        _REQUIRED,
        "D5.4",
    ),
    CoreFunction(
        "SAFE-F12",
        "S5-F12",
        "issue_capability_token",
        "Mint one narrow, expiring, single-use capability per action",
        _REQUIRED,
        "D5.6",
    ),
    CoreFunction(
        "SAFE-F13",
        "S5-F13",
        "prepare_transaction",
        "Revalidate identity, re-check preconditions, capture rollback state",
        _REQUIRED,
        "D5.11",
    ),
    CoreFunction(
        "SAFE-F14",
        "S5-F14",
        "commit_typed_action",
        "Apply exactly one typed operator through the privileged seam",
        _REQUIRED,
        "D5.11",
    ),
    CoreFunction(
        "SAFE-F15",
        "S5-F15",
        "verify_postconditions",
        "An action that cannot be verified is not a completed action",
        _REQUIRED,
        "D5.13",
    ),
    CoreFunction(
        "SAFE-F16",
        "S5-F16",
        "calculate_intervention_residual",
        "Distance between the predicted and the observed post-action host",
        # OPTIONAL: the residual is the only thing that could calibrate the
        # Action Shadow, and if it does not rank-correlate with it, F06 cannot
        # gate autonomy either (falsifier F3).
        _OPTIONAL,
        "D5.13",
        _RESIDUAL,
    ),
    CoreFunction(
        "SAFE-F17",
        "S5-F17",
        "rollback_transaction",
        "Restore the pre-action state; reliability against a real host is UNMEASURED",
        _REQUIRED,
        "D5.11",
    ),
    CoreFunction(
        "SAFE-F18",
        "S5-F18",
        "manage_action_lease",
        "Expire containment by design, with hysteresis against thrashing",
        _OPTIONAL,
        "D5.12",
        _HYSTERESIS,
    ),
    CoreFunction(
        "SAFE-F19",
        "S5-F19",
        "plan_safe_recovery",
        "Return the host to a safe state after containment",
        _REQUIRED,
        "D5.14",
    ),
    CoreFunction(
        "SAFE-F20",
        "S5-F20",
        "update_effectiveness_memory",
        "Remember what worked locally, per epoch, bounded and epoch-conditioned",
        _OPTIONAL,
        "D5.15",
        _EFFECTIVENESS,
    ),
    CoreFunction(
        "SAFE-F21",
        "S5-F21",
        "crystallize_response_cell",
        "Compile a repeatedly-verified response into an executable cell",
        _OPTIONAL,
        "D5.17",
        _CELLS,
    ),
    CoreFunction(
        "SAFE-F22",
        "S5-F22",
        "melt_response_cell",
        "Reverse the compilation when the epoch or the evidence moves",
        _OPTIONAL,
        "D5.17",
        _CELLS,
    ),
    CoreFunction(
        "SAFE-F23",
        "S5-F23",
        "map_d3fend_knowledge",
        "Map operators to published D3FEND ids, or UNMAPPED — never a guessed id",
        _OPTIONAL,
        "D5.16",
        _D3FEND,
    ),
    CoreFunction(
        "SAFE-F24",
        "S5-F24",
        "export_response_record",
        "Hand Stage 6 one plain-JSON record that states whether the host was simulated",
        # The exported type is specified by spec §3.3 rather than by a D5.* row;
        # naming the section is honest, naming a deliverable that does not contain
        # it would not be.
        _REQUIRED,
        "spec §3.3",
    ),
)

CORE_IDS = MappingProxyType({function.core_id: function for function in _FUNCTIONS})

#: Functions Stage 5 genuinely cannot lose. Everything else is a hypothesis.
#: A tuple, in architecture order, because G5.14 reports them in order and a
#: frozenset would make the report's ordering an accident of hashing.
REQUIRED_IDS = tuple(fn.core_id for fn in _FUNCTIONS if fn.function_class is _REQUIRED)

#: The ablation surface. G5.14 reads exactly this and demands an ``AblationRow``
#: with a *measured* non-``None`` delta for every member — it joins on core id and
#: reads each row's verdict, because Stage 2's equivalent check was a bare row
#: count and could not have come out differently (S2-AUTH-09).
OPTIONAL_IDS = tuple(fn.core_id for fn in _FUNCTIONS if fn.function_class is _OPTIONAL)

#: core_id -> the ``PlannerConfig`` flag that removes it. OPTIONAL ids only, so a
#: caller iterating this mapping cannot accidentally "ablate" a required function
#: by reading an empty flag name as a valid one.
ABLATION_FLAGS = MappingProxyType(
    {fn.core_id: fn.ablation_flag for fn in _FUNCTIONS if fn.function_class is _OPTIONAL}
)


def core_function(core_id: str) -> CoreFunction:
    """Look one id up, failing loudly rather than returning ``None``."""
    try:
        return CORE_IDS[core_id]
    except KeyError as exc:
        raise KeyError(f"unknown Stage 5 core id {core_id!r}") from exc


assert len(CORE_IDS) == 24, "architecture §38 defines exactly twenty-four core functional IDs"
assert len(REQUIRED_IDS) + len(OPTIONAL_IDS) == 24, "every id is required or optional, never both"
assert {fn.architecture_id for fn in _FUNCTIONS} == {
    f"S5-F{index:02d}" for index in range(1, 25)
}, "the SAFE ids must map one-to-one onto the architecture's S5-F ids"
assert [fn.core_id for fn in _FUNCTIONS] == [
    f"SAFE-F{index:02d}" for index in range(1, 25)
], "the table keeps the architecture's own order; G5.14 reports against the index"
assert len(PINNED_UPSTREAM_SCHEMAS) == 5, "spec §3.1 pins five upstream schema ids"
