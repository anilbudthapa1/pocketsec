"""DTL-F02 — ``route_information_need``, the deterministic need-score policy.

This is the policy that *proposes* an execution path. It does not decide what is
reported: `router/accounting.py` derives the reported path from work that
genuinely ran. Keeping the two apart is the whole of ADR-0114 — a policy that
could write its own path into the ledger would reproduce the ADR-0010 defect on
its first commit, so this module imports nothing from `accounting` and there is a
test pinning that.

Two measured facts bound what this module is allowed to be:

* **The router is harmful.** −0.115 PR-AUC on the ambiguous corpus
  (`planning/MEMORY.md`, ADR-0010), and it saved no real compute. So
  ``ROUTER_DEFAULT_ENABLED`` is ``False``. The policy is retained because a
  negative result is a result worth keeping runnable, not because it is expected
  to earn its place back.
* **There is no ground truth for "which path should this event have taken".** An
  earlier learned execution-path head had no supervision and fitted noise
  (`planning/MEMORY.md`, benchmarking trap 6). This module is therefore
  deliberately *not* a learned head: the weights and thresholds are fixed,
  auditable and copied verbatim from the policy already measured in
  `research/dtl.py::path_histogram`, so the negative result stays comparable.

Stdlib only: this runs on the endpoint.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage2.core_ids import ExecutionPath
from pocketsec.stage2.encoder.ssir_encoder import (
    NEED_SIGNAL_INDICES,
    EncodedTransition,
)

__all__ = [
    "NEED_SIGNAL_ORDER",
    "NEED_WEIGHTS",
    "PATH_THRESHOLDS",
    "ROUTER_DEFAULT_ENABLED",
    "NeedSignals",
    "need_score",
    "route_information_need",
]

#: Measured HARMFUL: −0.115 PR-AUC on the ambiguous corpus, while reporting 100 %
#: cheap-path resolution that the ledger has since shown to have been notional
#: (ADR-0010). Off by default under Stage 2 acceptance criterion 12; re-enabling
#: it requires a measurement that reverses that number, not a preference.
ROUTER_DEFAULT_ENABLED: bool = False

#: Field order of `NeedSignals`, matching the five `NEED_SIGNAL_INDICES` keys.
NEED_SIGNAL_ORDER: tuple[str, ...] = (
    "novelty_peak",
    "delta_phi",
    "uncertainty",
    "responsibility",
    "state_delta_magnitude",
)

#: Verbatim from `research/dtl.py::path_histogram`. Changing a weight changes the
#: mechanism whose −0.115 is on record, so the two must stay identical or the
#: negative result stops applying to the code that ships.
NEED_WEIGHTS: dict[str, float] = {
    "novelty_peak": 0.35,
    "delta_phi": 0.25,
    "uncertainty": 0.20,
    "responsibility": 0.15,
    "state_delta_magnitude": 0.05,
}

#: (exclusive upper bound, path), ascending. Above the last bound, P4.
PATH_THRESHOLDS: tuple[tuple[float, ExecutionPath], ...] = (
    (0.15, ExecutionPath.P0_COMPILED),
    (0.30, ExecutionPath.P1_LATTICE),
    (0.50, ExecutionPath.P2_LOCAL),
    (0.70, ExecutionPath.P3_PREDICTIVE),
)

#: The feature slots this policy reads, as documented in the Stage 2 spec. They
#: are *checked* against the encoder's derived layout rather than used directly:
#: the encoder's own comment is that a magic index into a frozen layout silently
#: points at the wrong feature the moment the layout grows, and a router quietly
#: scoring the wrong five slots is a failure mode with no symptom.
DOCUMENTED_NEED_INDICES: dict[str, int] = {
    "novelty_peak": 83,
    "delta_phi": 73,
    "uncertainty": 85,
    "responsibility": 90,
    "state_delta_magnitude": 71,
}

if NEED_SIGNAL_INDICES != DOCUMENTED_NEED_INDICES:  # pragma: no cover - import guard
    raise ContractError(
        "the encoder feature layout moved: NEED_SIGNAL_INDICES is "
        f"{NEED_SIGNAL_INDICES} but this policy documents {DOCUMENTED_NEED_INDICES}. "
        "Refusing to score five unknown slots."
    )


@dataclass(frozen=True, slots=True)
class NeedSignals:
    """The five signals the need score is allowed to see.

    Novelty, Φ and uncertainty arrive as three separate fields and stay separate
    — collapsing them into one score is forbidden (ADR-0006 lineage, Stage 1
    invariant). The weighting below combines them for a *routing* decision only,
    which is not a detection score and carries no authority (ADR-0003).
    """

    novelty_peak: float
    delta_phi: float
    uncertainty: float
    responsibility: float
    state_delta_magnitude: float

    def __post_init__(self) -> None:
        for field_name in NEED_SIGNAL_ORDER:
            value = getattr(self, field_name)
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise ContractError(f"{field_name} must be a real number, got {value!r}")
            value = float(value)
            if not math.isfinite(value):
                raise ContractError(f"{field_name} must be finite, got {value!r}")
            if value < 0.0:
                raise ContractError(
                    f"{field_name} must be >= 0, got {value!r}; the encoder emits "
                    "normalised non-negative slots and a negative value means the "
                    "caller read the wrong feature"
                )
            object.__setattr__(self, field_name, value)

    @classmethod
    def from_encoded(cls, encoded: EncodedTransition) -> NeedSignals:
        """Read the five need slots out of an encoded transition."""
        features = encoded.features
        width = len(features)
        for name, index in NEED_SIGNAL_INDICES.items():
            if index >= width:
                raise ContractError(
                    f"need signal {name} lives at index {index} but the encoded "
                    f"transition has only {width} features"
                )
        return cls(
            **{name: features[NEED_SIGNAL_INDICES[name]] for name in NEED_SIGNAL_ORDER}
        )

    def to_dict(self) -> dict[str, Any]:
        return {name: round(getattr(self, name), 6) for name in NEED_SIGNAL_ORDER}


def need_score(signals: NeedSignals) -> float:
    """The weighted need score. Deterministic, auditable, not learned."""
    return sum(
        NEED_WEIGHTS[name] * getattr(signals, name) for name in NEED_SIGNAL_ORDER
    )


def route_information_need(signals: NeedSignals) -> ExecutionPath:
    """DTL-F02. The path this policy *proposes* for an event.

    A proposal only. `WorkLedger.close()` derives the path that gets reported from
    the work that actually ran, so agreeing with this function is never evidence
    that compute was saved — which is exactly the mistake ADR-0010 recorded.
    """
    score = need_score(signals)
    for upper, path in PATH_THRESHOLDS:
        if score < upper:
            return path
    return ExecutionPath.P4_DEEP
