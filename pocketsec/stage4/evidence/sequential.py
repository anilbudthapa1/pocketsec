"""Sequential evidence accumulation for slowly-unfolding worlds (architecture §31).

Sparse persistence and slow credential misuse do not arrive in one burst, so a world's
support has to be updatable observation by observation without a fixed sample size.
This module keeps an e-process-inspired accumulator for that.

What this module refuses to do is more important than what it does. §31's own wording is
"anytime-valid evidence **where assumptions permit**, without pretending all model scores
satisfy statistical guarantees". Here that becomes a boolean a reader can check:
``anytime_valid`` is ``False`` unless the evidence was accumulated against the one null
this module can actually construct — a fixed benign-mechanism emission model over the
closed Stage 4 signal vocabulary. Every other accumulator carries a truthful
``null_description`` and ``anytime_valid=False``, and its e-value is bookkeeping, not a
statistical guarantee. ``__post_init__`` refuses to let a caller set the flag without the
matching null, so the honesty is structural rather than documented.

Arithmetic is pure Python ``float`` (ADR-0030: no numpy anywhere in Stage 4) and the
e-value is clipped at ``E_VALUE_CEILING`` so a long benign run cannot produce an
unbounded number that then overflows a report.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import ContractError, require_identifier

__all__ = [
    "BENIGN_NULL_DESCRIPTION",
    "E_VALUE_CEILING",
    "FORBIDDEN_EMISSION_PROBABILITY",
    "MAX_EVIDENCE_STEPS",
    "NULL_EMISSION_PROBABILITY",
    "SIGNAL_VOCABULARY",
    "STOP_CONTRADICTION_THRESHOLD",
    "STOP_SUPPORT_THRESHOLD",
    "SILENT_EMISSION_PROBABILITY",
    "WORLD_EMISSION_PROBABILITY",
    "SequentialEvidence",
    "StopReason",
    "benign_null_likelihood_ratio",
    "model_score_evidence",
    "start_benign_null_evidence",
]

#: Observations one world's accumulator may absorb. A bound, not a hint: an unbounded
#: accumulator is unbounded endpoint state.
MAX_EVIDENCE_STEPS: int = 256

#: E-values are clipped here. Beyond ~1e6 the number carries no extra decision content
#: and unclipped products overflow to ``inf``, which is not a reportable figure.
E_VALUE_CEILING: float = 1e6

#: E-value at which support is called sufficient. A chosen parameter (spec §9.11):
#: 20 is the conventional "strong evidence" reading of an e-value, reported as a
#: parameter and never as a measurement.
STOP_SUPPORT_THRESHOLD: float = 20.0

#: E-value at which the world is called contradicted.
STOP_CONTRADICTION_THRESHOLD: float = 0.05

#: The closed signal vocabulary the constructible null is defined over. Kept as a
#: literal frozenset rather than imported from the cone module so that this module's
#: null does not silently change meaning when another package extends its vocabulary —
#: a null that moves is not a null.
SIGNAL_VOCABULARY: frozenset[str] = frozenset(
    {
        "authentication",
        "privilege_change",
        "credential_access",
        "persistence_write",
        "module_load",
        "boundary_crossing",
        "file_staging",
        "session_teardown",
    }
)

#: Emission probability under the null: the fixed benign-mechanism model emits each
#: vocabulary signal independently at this rate. A declared parameter of the null, and
#: the null is only meaningful because it is *fixed* — it is never fitted to the data
#: it is then tested against.
NULL_EMISSION_PROBABILITY: float = 0.25

#: Probability a world emits a signal it expects.
WORLD_EMISSION_PROBABILITY: float = 0.9

#: Probability a world emits a signal it forbids. Not zero: a zero here would make one
#: observation infinitely decisive and a single mislabelled event fatal.
FORBIDDEN_EMISSION_PROBABILITY: float = 0.02

#: Probability a world emits a signal it neither expects nor forbids.
SILENT_EMISSION_PROBABILITY: float = 0.25

#: The one null this module can construct. ``anytime_valid=True`` is permitted for this
#: description and no other.
BENIGN_NULL_DESCRIPTION: str = (
    "fixed benign-mechanism emission model: each of the 8 closed Stage 4 vocabulary "
    "signals is emitted independently with probability 0.25, parameters fixed before "
    "observation and never fitted to the incident under test"
)

_EMISSION_BY_ROLE: Mapping[str, float] = MappingProxyType(
    {
        "expected": WORLD_EMISSION_PROBABILITY,
        "forbidden": FORBIDDEN_EMISSION_PROBABILITY,
        "silent": SILENT_EMISSION_PROBABILITY,
    }
)


class StopReason(StrEnum):
    """§31's four stopping conditions, plus the state of not having stopped."""

    SUFFICIENT_SUPPORT = "SUFFICIENT_SUPPORT"
    SUFFICIENT_CONTRADICTION = "SUFFICIENT_CONTRADICTION"
    HORIZON_REACHED = "HORIZON_REACHED"
    NON_IDENTIFIABLE = "NON_IDENTIFIABLE"
    STILL_RUNNING = "STILL_RUNNING"


@dataclass(frozen=True, slots=True)
class SequentialEvidence:
    """An e-process-inspired accumulator (§31). Not a p-value, and it does not claim to be."""

    world_id: str
    e_value: float
    steps: int
    #: What the null actually is, in words, or the guarantee is void. Required non-empty.
    null_description: str
    #: ``True`` only for ``BENIGN_NULL_DESCRIPTION``; see the module docstring.
    anytime_valid: bool = False
    stop_reason: StopReason = StopReason.STILL_RUNNING

    def __post_init__(self) -> None:
        require_identifier(self.world_id, "SequentialEvidence.world_id")
        object.__setattr__(self, "stop_reason", StopReason(self.stop_reason))
        value = float(self.e_value)
        if value != value or value in (math.inf, -math.inf) or value < 0.0:
            raise ContractError(
                f"SequentialEvidence.e_value must be finite and >= 0, got {self.e_value!r}"
            )
        if value > E_VALUE_CEILING:
            raise ContractError(
                f"SequentialEvidence.e_value {value!r} exceeds E_VALUE_CEILING "
                f"{E_VALUE_CEILING}; clip at construction, do not report past the bound"
            )
        object.__setattr__(self, "e_value", value)
        if not isinstance(self.steps, int) or isinstance(self.steps, bool) or self.steps < 0:
            raise ContractError(f"SequentialEvidence.steps must be >= 0, got {self.steps!r}")
        if self.steps > MAX_EVIDENCE_STEPS:
            raise ContractError(
                f"SequentialEvidence.steps {self.steps} exceeds MAX_EVIDENCE_STEPS "
                f"{MAX_EVIDENCE_STEPS}"
            )
        if not isinstance(self.null_description, str) or not self.null_description.strip():
            raise ContractError(
                "SequentialEvidence.null_description is required and non-empty; an "
                "e-value whose null nobody stated is not evidence of anything"
            )
        if not isinstance(self.anytime_valid, bool):
            raise ContractError("SequentialEvidence.anytime_valid must be a bool")
        if self.anytime_valid and self.null_description != BENIGN_NULL_DESCRIPTION:
            raise ContractError(
                "anytime_valid=True is permitted only for the one null this module can "
                "construct (BENIGN_NULL_DESCRIPTION); a model score does not become "
                "anytime-valid by being labelled so"
            )

    # --- CBF-F08 --------------------------------------------------------

    def update(self, likelihood_ratio: float) -> SequentialEvidence:
        """Absorb one observation's likelihood ratio and return a new accumulator.

        Refuses to update an accumulator that has already stopped. Continuing past a
        stop would silently invalidate whatever the stop meant, and returning ``self``
        unchanged would hide the caller's bug — an accumulator that quietly ignores
        evidence looks exactly like one that saw none.
        """
        if self.stop_reason is not StopReason.STILL_RUNNING:
            raise ContractError(
                f"SequentialEvidence for {self.world_id!r} already stopped with "
                f"{self.stop_reason.value}; start a new accumulator instead of "
                "extending a stopped one"
            )
        ratio = float(likelihood_ratio)
        if ratio != ratio or ratio in (math.inf, -math.inf) or ratio <= 0.0:
            raise ContractError(
                f"likelihood_ratio must be finite and > 0, got {likelihood_ratio!r}"
            )
        e_value = min(self.e_value * ratio, E_VALUE_CEILING)
        steps = self.steps + 1
        return replace(
            self,
            e_value=e_value,
            steps=steps,
            stop_reason=_stop_reason(e_value, steps),
        )

    def stopped(self, reason: StopReason) -> SequentialEvidence:
        """Stop this accumulator for an externally-decided reason.

        ``NON_IDENTIFIABLE`` is the reason this method exists: non-identifiability is
        established by the identifiability engine over the whole field, not by any one
        world's e-value, and that decision has to be recordable here.
        """
        reason = StopReason(reason)
        if reason is StopReason.STILL_RUNNING:
            raise ContractError("stopped() needs a real stop reason, not STILL_RUNNING")
        return replace(self, stop_reason=reason)

    @property
    def is_running(self) -> bool:
        return self.stop_reason is StopReason.STILL_RUNNING

    @property
    def log_e_value(self) -> float:
        """``log(e_value)``, or ``-inf`` at zero. Reported for readability only."""
        return math.log(self.e_value) if self.e_value > 0.0 else -math.inf

    def to_dict(self) -> dict[str, Any]:
        return {
            "world_id": self.world_id,
            "e_value": round(self.e_value, 6),
            "steps": self.steps,
            "null_description": self.null_description,
            "anytime_valid": self.anytime_valid,
            "stop_reason": self.stop_reason.value,
        }


def _stop_reason(e_value: float, steps: int) -> StopReason:
    """Order matters: the horizon is checked first so a bound cannot be overrun by a
    late burst of support."""
    if steps >= MAX_EVIDENCE_STEPS:
        return StopReason.HORIZON_REACHED
    if e_value >= STOP_SUPPORT_THRESHOLD:
        return StopReason.SUFFICIENT_SUPPORT
    if e_value <= STOP_CONTRADICTION_THRESHOLD:
        return StopReason.SUFFICIENT_CONTRADICTION
    return StopReason.STILL_RUNNING


# --- the two constructors ---------------------------------------------------


def start_benign_null_evidence(world_id: str) -> SequentialEvidence:
    """An accumulator against the one constructible null. ``anytime_valid=True``."""
    return SequentialEvidence(
        world_id=world_id,
        e_value=1.0,
        steps=0,
        null_description=BENIGN_NULL_DESCRIPTION,
        anytime_valid=True,
    )


def model_score_evidence(world_id: str, *, null_description: str) -> SequentialEvidence:
    """An accumulator against a null this module cannot construct.

    ``anytime_valid`` stays ``False``. The caller must still say what the null is, so
    that a reader can see exactly which unverified assumption the number rests on.
    """
    if null_description == BENIGN_NULL_DESCRIPTION:
        raise ContractError(
            "use start_benign_null_evidence() for the constructible null; routing it "
            "through model_score_evidence() would understate the guarantee"
        )
    return SequentialEvidence(
        world_id=world_id,
        e_value=1.0,
        steps=0,
        null_description=null_description,
        anytime_valid=False,
    )


# --- the likelihood ratio of the constructible null -------------------------


def _emission_role(signal: str, *, expected: frozenset[str], forbidden: frozenset[str]) -> str:
    if signal in forbidden:
        # Forbidden beats expected. A world that both expects and forbids a signal is
        # refused upstream by SecurityWorldV1, but if one ever reaches here the
        # conservative reading is the one that does not inflate support.
        return "forbidden"
    if signal in expected:
        return "expected"
    return "silent"


def benign_null_likelihood_ratio(
    observed: Iterable[str],
    *,
    expected: frozenset[str],
    forbidden: frozenset[str],
    vocabulary: frozenset[str] = SIGNAL_VOCABULARY,
) -> float:
    """P(observed | world) / P(observed | fixed benign null), over the closed vocabulary.

    Both numerator and denominator are products of independent Bernoulli terms over the
    *whole* vocabulary, so a signal's **absence** counts as evidence exactly as its
    presence does. That is the point of pairing this with the visibility model: absence
    is only evidence where the signal was observable, and the caller is responsible for
    passing an ``observed`` set drawn from signals that were actually collectable.
    """
    seen = frozenset(str(s) for s in observed)
    unknown = seen - vocabulary
    if unknown:
        raise ContractError(
            f"observed signals outside the null's closed vocabulary: {sorted(unknown)!r}; "
            "the null is defined over a fixed vocabulary and extending it silently "
            "would void the guarantee"
        )
    numerator = 0.0
    denominator = 0.0
    for signal in sorted(vocabulary):
        p = _EMISSION_BY_ROLE[_emission_role(signal, expected=expected, forbidden=forbidden)]
        q = NULL_EMISSION_PROBABILITY
        present = signal in seen
        numerator += math.log(p if present else 1.0 - p)
        denominator += math.log(q if present else 1.0 - q)
    return math.exp(numerator - denominator)
