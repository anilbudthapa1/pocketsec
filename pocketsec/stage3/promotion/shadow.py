"""D3.11 (part) — shadow execution: running a candidate cell beside the oracle.

Architecture §26. A candidate runs on live frames *without its answers being
used*, and every frame is compared against the dual oracle. The whole module is
read-only with respect to the field and the index: :func:`shadow_execute`
returns a record and changes nothing, so a shadow run can never be the thing
that promotes a cell.

The part worth getting right is what "long enough" means. §26 says shadow
duration is consequence-dependent and is measured in **boundary coverage and
diversity of transitions**, not in a fixed event count. An event count alone is
gameable by a quiet host: ten thousand identical heartbeat frames prove a cell
works on one key and nothing else. :data:`SHADOW_MIN_COVERAGE` therefore pairs a
frame floor with a distinct-boundary-key floor, and
:data:`SHADOW_MIN_TRANSITIONS` adds the diversity term §26 names separately.
All three rise strictly with consequence.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage3.boundary.pressure import AXIS_ORDER, BoundaryProbe
from pocketsec.stage3.oracles.teacher import frame_digest
from pocketsec.stage3.theory import SecurityConsequence

if TYPE_CHECKING:  # pragma: no cover - import-time cost, not behaviour
    from pocketsec.stage3.boundary.index import BoundaryKey
    from pocketsec.stage3.bytecode.vm import CellFrame, CellVM
    from pocketsec.stage3.cells.schema import KnowledgeCellV1
    from pocketsec.stage3.oracles.dual_oracle import DualOracleEvaluator

__all__ = [
    "PHI_BAND_WIDTH",
    "SHADOW_MIN_COVERAGE",
    "SHADOW_MIN_TRANSITIONS",
    "ShadowRun",
    "shadow_execute",
    "transition_signature",
]

#: ``(minimum frames, minimum distinct boundary keys)`` per consequence. Both
#: terms are required: frames alone can be produced by a quiet host, and keys
#: alone can be produced by a short burst of variety.
SHADOW_MIN_COVERAGE: Mapping[SecurityConsequence, tuple[int, int]] = MappingProxyType(
    {
        SecurityConsequence.ROUTINE: (32, 2),
        SecurityConsequence.ELEVATED: (64, 4),
        SecurityConsequence.HIGH: (128, 8),
        SecurityConsequence.CRITICAL: (256, 16),
    }
)

#: §26's "diversity of transitions", kept as its own closed mapping because a
#: transition signature is not a boundary key: two frames can share a key and
#: differ in Φ band, and a cell that only ever saw one band has not been
#: exercised over its own Φ range.
SHADOW_MIN_TRANSITIONS: Mapping[SecurityConsequence, int] = MappingProxyType(
    {
        SecurityConsequence.ROUTINE: 2,
        SecurityConsequence.ELEVATED: 3,
        SecurityConsequence.HIGH: 5,
        SecurityConsequence.CRITICAL: 8,
    }
)

#: Φ band width for the transition signature. Φ is unbounded above, so the band
#: index saturates rather than growing without bound — an unbounded signature
#: alphabet would make "distinct transitions" trivially satisfiable.
PHI_BAND_WIDTH = 0.5

#: Beyond this many bands every higher Φ counts as the same band.
MAX_PHI_BANDS = 16


def transition_signature(frame: CellFrame) -> tuple[int, int, int]:
    """``(relation family, state-delta bitmask, Φ band)`` — §9's motif step shape.

    Deliberately the same triple ``invariants/motifs.py`` uses for a motif step,
    so "diversity of transitions" here means the same thing it means there.
    """
    band = int(max(0.0, float(frame.phi)) / PHI_BAND_WIDTH)
    return (
        int(frame.relation_family),
        frame.delta.bitmask(),
        band if band < MAX_PHI_BANDS else MAX_PHI_BANDS,
    )


def _boundary_key(frame: CellFrame) -> BoundaryKey:
    """The index key this frame falls under, computed without an index."""
    return (int(frame.relation_family), frame.actor_properties, frame.delta.bitmask())


@dataclass(frozen=True, slots=True)
class ShadowRun:
    """What a shadow deployment observed. A record, never an authorisation."""

    frames_seen: int
    distinct_boundary_keys: int
    distinct_transitions: int
    agreements: int
    divergences: tuple[BoundaryProbe, ...]
    consequence: SecurityConsequence
    coverage_met: bool
    reason: str

    def __post_init__(self) -> None:
        for name in (
            "frames_seen",
            "distinct_boundary_keys",
            "distinct_transitions",
            "agreements",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ContractError(f"ShadowRun.{name} must be a non-negative int, got {value!r}")
        if self.agreements > self.frames_seen:
            raise ContractError(
                f"ShadowRun reports {self.agreements} agreements over {self.frames_seen} "
                "frames; the two were counted over different populations"
            )
        if not isinstance(self.consequence, SecurityConsequence):
            raise ContractError("ShadowRun.consequence must be a SecurityConsequence")
        if not isinstance(self.divergences, tuple):
            raise ContractError("ShadowRun.divergences must be a tuple")
        if not isinstance(self.coverage_met, bool):
            raise ContractError("ShadowRun.coverage_met must be a bool")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ContractError(
                "ShadowRun.reason must say what was or was not covered; an unexplained "
                "coverage verdict cannot be reviewed"
            )

    @property
    def abstentions(self) -> int:
        """Frames where the cell declined and the oracle raised nothing.

        Neither an agreement nor a divergence: the cell had no opinion, which is
        a legal outcome and must not be counted as either kind of evidence.
        """
        return self.frames_seen - self.agreements - len(self.divergences)

    def to_dict(self) -> dict[str, Any]:
        return {
            "frames_seen": self.frames_seen,
            "distinct_boundary_keys": self.distinct_boundary_keys,
            "distinct_transitions": self.distinct_transitions,
            "agreements": self.agreements,
            "divergence_count": len(self.divergences),
            "abstentions": self.abstentions,
            "consequence": int(self.consequence),
            "coverage_met": self.coverage_met,
            "reason": self.reason,
        }


def _coverage_verdict(
    consequence: SecurityConsequence, frames: int, keys: int, transitions: int
) -> tuple[bool, str]:
    """Check the three §26 floors and name every one that was missed."""
    min_frames, min_keys = SHADOW_MIN_COVERAGE[consequence]
    min_transitions = SHADOW_MIN_TRANSITIONS[consequence]
    missing: list[str] = []
    if frames < min_frames:
        missing.append(f"frames {frames} < {min_frames}")
    if keys < min_keys:
        missing.append(f"boundary_keys {keys} < {min_keys}")
    if transitions < min_transitions:
        missing.append(f"transitions {transitions} < {min_transitions}")
    if missing:
        return False, f"COVERAGE_SHORT[{consequence.name}]: " + "; ".join(missing)
    return True, f"COVERAGE_MET[{consequence.name}]"


def shadow_execute(
    cell: KnowledgeCellV1,
    frames: Sequence[CellFrame],
    *,
    oracle: DualOracleEvaluator,
    vm: CellVM,
) -> ShadowRun:
    """Run ``cell`` beside the oracle over ``frames`` and log the equivalence.

    Changes nothing — not the field, not the index, not the cell. The VM result
    is computed and discarded precisely so the answers cannot reach a caller by
    accident: a shadow run that could be mistaken for a live one would put an
    unpromoted cell on the cheap path.

    Every divergence is recorded as a :class:`BoundaryProbe` with
    ``steps_from_seed == 0``, because these frames were **observed, not
    perturbed**. The ``perturbation`` field is part of that type's shape and
    carries no claim here; ``AXIS_ORDER[0]`` is used as the null axis and the
    zero step count is what distinguishes a shadow divergence from a pressure
    probe.
    """
    if cell.operator is None:  # pragma: no cover - schema forbids it; defence in depth
        raise ContractError("shadow_execute needs a cell with an operator")
    consequence = cell.invariant.consequent.consequence
    keys: set[BoundaryKey] = set()
    transitions: set[tuple[int, int, int]] = set()
    agreements = 0
    divergences: list[BoundaryProbe] = []
    seen = 0
    for frame in frames:
        seen += 1
        keys.add(_boundary_key(frame))
        transitions.add(transition_signature(frame))
        result = vm.run(cell.operator, frame)
        verdict = oracle.evaluate(cell, (frame,))
        if not verdict.passed:
            divergences.append(
                BoundaryProbe(
                    frame=frame,
                    perturbation=AXIS_ORDER[0],
                    steps_from_seed=0,
                    seed_digest=frame_digest(frame),
                )
            )
        elif not result.abstained:
            agreements += 1
    met, reason = _coverage_verdict(consequence, seen, len(keys), len(transitions))
    return ShadowRun(
        frames_seen=seen,
        distinct_boundary_keys=len(keys),
        distinct_transitions=len(transitions),
        agreements=agreements,
        divergences=tuple(divergences),
        consequence=consequence,
        coverage_met=met,
        reason=reason,
    )


def _assert_coverage_rises_with_consequence() -> None:
    levels = sorted(SecurityConsequence)
    if set(SHADOW_MIN_COVERAGE) != set(levels) or set(SHADOW_MIN_TRANSITIONS) != set(levels):
        raise ContractError(
            "shadow coverage mappings must be closed over SecurityConsequence; a missing "
            "level would let a CRITICAL candidate promote on ROUTINE evidence"
        )
    previous: tuple[int, int, int] | None = None
    for level in levels:
        frames, index_keys = SHADOW_MIN_COVERAGE[level]
        current = (frames, index_keys, SHADOW_MIN_TRANSITIONS[level])
        if any(value < 1 for value in current):
            raise ContractError(f"shadow coverage floors for {level.name} must all be >= 1")
        if previous is not None and any(
            later <= earlier for earlier, later in zip(previous, current, strict=True)
        ):
            raise ContractError(
                f"shadow coverage must rise strictly with consequence: {level.name} "
                f"{current} does not exceed {previous} on every term"
            )
        previous = current


_assert_coverage_rises_with_consequence()
