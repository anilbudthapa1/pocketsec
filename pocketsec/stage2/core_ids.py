"""D2.1 — DTL core functional IDs and the versioned Stage 2 interface.

Twenty stable functional IDs (spec section 29). Their purpose is the same as the
Stage 0 model slot's: the hub depends on *functions*, not on DTL. If DTL is
replaced wholesale in Stage 3 — or deleted — the hub keeps working against the
same IDs, degrading to whatever remains.

Each ID declares whether it is **required** (the hub cannot function without it)
or **optional** (an experimental mechanism that ablation may delete). An
optional function that survives must have an ablation-supported reason to exist,
which is Stage 2 acceptance criterion 12.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import register_schema

__all__ = [
    "CORE_IDS",
    "DTL_INTERFACE_ID",
    "DTL_INTERFACE_VERSION",
    "CoreFunction",
    "ExecutionPath",
    "FunctionClass",
]

DTL_INTERFACE_ID = "pocketsec.dtl_interface.v1"
DTL_INTERFACE_VERSION = register_schema(DTL_INTERFACE_ID, "1.0.0")


class FunctionClass(StrEnum):
    #: The hub cannot operate without this.
    REQUIRED = "REQUIRED"
    #: Experimental. Must justify itself by ablation or be removed.
    OPTIONAL = "OPTIONAL"


class ExecutionPath(StrEnum):
    """The Need-to-Compute ladder (spec section 6).

    The headline Stage 2 metric is not inference latency but the **distribution
    of events across these paths** — the sleeping-brain benchmark. A system that
    answers 95% of events at P0/P1 has eliminated expensive inference, which is
    the whole PocketSec thesis.
    """

    P0_COMPILED = "P0_COMPILED"  # compiled/cached exact transition
    P1_LATTICE = "P1_LATTICE"  # prototype/lattice lookup
    P2_LOCAL = "P2_LOCAL"  # small local state update
    P3_PREDICTIVE = "P3_PREDICTIVE"  # multi-block predictive inference
    P4_DEEP = "P4_DEEP"  # counterfactual/deep analysis + AOP request


#: Relative cost weights for the execution paths, used to report a single
#: comparable "compute units per event" figure. Calibrated from measured CPU
#: time in `research.sleeping_brain`, not assumed.
PATH_COST_UNITS: dict[ExecutionPath, float] = {
    ExecutionPath.P0_COMPILED: 1.0,
    ExecutionPath.P1_LATTICE: 2.0,
    ExecutionPath.P2_LOCAL: 8.0,
    ExecutionPath.P3_PREDICTIVE: 40.0,
    ExecutionPath.P4_DEEP: 200.0,
}


@dataclass(frozen=True, slots=True)
class CoreFunction:
    core_id: str
    name: str
    purpose: str
    function_class: FunctionClass
    #: Deliverable that implements it.
    deliverable: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "core_id": self.core_id,
            "name": self.name,
            "purpose": self.purpose,
            "class": self.function_class.value,
            "deliverable": self.deliverable,
        }


_FUNCTIONS = (
    CoreFunction(
        "DTL-F01",
        "encode_ssir_transition",
        "Turn one SSIR transition into a fixed feature vector",
        FunctionClass.REQUIRED,
        "D2.3",
    ),
    CoreFunction(
        "DTL-F02",
        "route_information_need",
        "Decide which state blocks and execution path an event needs",
        FunctionClass.REQUIRED,
        "D2.4",
    ),
    CoreFunction(
        "DTL-F03",
        "update_multiscale_state",
        "Update the factorised latent state, waking only the gated blocks",
        FunctionClass.REQUIRED,
        "D2.3",
    ),
    CoreFunction(
        "DTL-F04",
        "quantize_behaviour_atom",
        "Quantise continuous state into a reusable discrete prototype",
        FunctionClass.OPTIONAL,
        "D2.6",
    ),
    CoreFunction(
        "DTL-F05",
        "predict_future_cone",
        "Bounded distribution over plausible security continuations",
        FunctionClass.OPTIONAL,
        "D2.8",
    ),
    CoreFunction(
        "DTL-F06",
        "predict_security_state_delta",
        "Predict the next security capability change",
        FunctionClass.REQUIRED,
        "D2.5",
    ),
    CoreFunction(
        "DTL-F07",
        "estimate_uncertainty",
        "Calibrated confidence supporting abstention",
        FunctionClass.REQUIRED,
        "D2.9",
    ),
    CoreFunction(
        "DTL-F08",
        "estimate_security_hazard",
        "Multi-horizon hazard for bounded security outcomes",
        FunctionClass.OPTIONAL,
        "D2.8",
    ),
    CoreFunction(
        "DTL-F09",
        "score_prediction_residual",
        "Structured surprise over observed and expected-but-absent events",
        FunctionClass.OPTIONAL,
        "D2.5",
    ),
    CoreFunction(
        "DTL-F10",
        "assign_causal_credit",
        "Bounded ledger of transitions that moved predicted security state",
        FunctionClass.OPTIONAL,
        "D2.10",
    ),
    CoreFunction(
        "DTL-F11",
        "counterfactual_probe",
        "Compare observed trajectory against masked alternatives",
        FunctionClass.OPTIONAL,
        "D2.10",
    ),
    CoreFunction(
        "DTL-F12",
        "request_observation_escalation",
        "Value-of-information request into the Stage 1 AOP",
        FunctionClass.OPTIONAL,
        "D2.11",
    ),
    CoreFunction(
        "DTL-F13",
        "merge_equivalent_atoms",
        "Merge atoms with equivalent security-relevant futures",
        FunctionClass.OPTIONAL,
        "D2.7",
    ),
    CoreFunction(
        "DTL-F14",
        "split_heterogeneous_atom",
        "Split an atom that accumulated incompatible futures",
        FunctionClass.OPTIONAL,
        "D2.7",
    ),
    CoreFunction(
        "DTL-F15",
        "forget_low_utility_memory",
        "Forget by predicted future utility rather than by age",
        FunctionClass.OPTIONAL,
        "D2.13",
    ),
    CoreFunction(
        "DTL-F16",
        "lookup_transition_cache",
        "P0 exact-transition cache lookup",
        FunctionClass.OPTIONAL,
        "D2.13",
    ),
    CoreFunction(
        "DTL-F17",
        "propose_compile_candidate",
        "Nominate a stable transition for Stage 3 compilation",
        FunctionClass.OPTIONAL,
        "D2.13",
    ),
    CoreFunction(
        "DTL-F18",
        "detect_epoch_mismatch",
        "Flag behaviour that does not fit the current regime",
        FunctionClass.REQUIRED,
        "D2.12",
    ),
    CoreFunction(
        "DTL-F19",
        "quarantine_adaptation_sample",
        "Hold new experience out of trusted state until validated",
        FunctionClass.REQUIRED,
        "D2.12",
    ),
    CoreFunction(
        "DTL-F20",
        "export_evidence_bound_prediction",
        "Emit a prediction bound to immutable Stage 1 evidence IDs",
        FunctionClass.REQUIRED,
        "D2.15",
    ),
)

CORE_IDS = MappingProxyType({function.core_id: function for function in _FUNCTIONS})

#: Functions the hub genuinely cannot lose. Everything else is a hypothesis.
REQUIRED_IDS = frozenset(
    fn.core_id for fn in _FUNCTIONS if fn.function_class is FunctionClass.REQUIRED
)

assert len(CORE_IDS) == 20, "the spec defines exactly twenty core functional IDs"
