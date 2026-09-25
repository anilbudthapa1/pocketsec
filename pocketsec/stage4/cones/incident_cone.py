"""D4.7 — incident-level counterfactual future cones (architecture §15).

A world is only useful if it predicts something. This module turns each surviving
world into a bounded set of security-relevant futures — persistence, credential
access, data staging, session end — and then reports the **differences** between two
worlds' predictions. That difference is the mechanism's entire content: §4 says the
useful intelligence lives in where the worlds disagree, so
:meth:`IncidentFutureCone.discriminating_signals` is the primitive the sensor planner
(D4.9) plans against, and anything more elaborate has to beat a symmetric difference
over predicted signal sets before it earns its place.

What this module refuses to do:

- It is **not** built on ``pocketsec/stage2/predictors/future_cone.py``. That module is
  default-off and measured worse than its own marginal control (ADR-0116: cone Brier
  1.566994 against marginal 1.850148, cited from PROGRESS.md, not measured here).
  Reusing a rejected predictor to satisfy a deliverable would be the worst kind of
  reuse.
- It never grows an unbounded tree. ``MAX_BRANCHES_PER_WORLD`` × ``MAX_CONE_DEPTH`` are
  hard, and a branch dropped for either bound or for being inconsequential is counted
  in ``truncated_branches``. A silent drop is a defect.
- It never invents a signal name. The vocabulary is closed
  (:data:`CONE_SIGNAL_VOCABULARY`) and rooted in Stage 1's ``MANDATORY_SIGNALS``, so a
  cone's prediction can actually be checked against telemetry.
- It never treats a refuted branch as a truncation. ``collapse()`` removes branches the
  observation contradicts; that is evidence arriving, not information being lost, and
  conflating the two would make ``truncated_branches`` meaningless.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.observation.policy import MANDATORY_SIGNALS
from pocketsec.stage1.state.potential import phi
from pocketsec.stage1.state.security_state import DIMENSIONS, SecurityStateV1

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pocketsec.stage4.worlds.field import CausalBeliefField
    from pocketsec.stage4.worlds.world import SecurityWorldV1

__all__ = [
    "BRANCH_LABELS",
    "CONE_SIGNAL_VOCABULARY",
    "MAX_BRANCHES_PER_WORLD",
    "MAX_CONE_DEPTH",
    "MIN_BRANCH_CONSEQUENCE",
    "CausalBranch",
    "IncidentFutureCone",
    "compose_cones",
    "pairwise_discriminating_signals",
    "predict_world_future_cone",
]

#: §15 keeps "only bounded security-relevant futures". Four per world, depth three.
MAX_BRANCHES_PER_WORLD: int = 4
MAX_CONE_DEPTH: int = 3
#: A branch whose reached state carries less Φ than this is not worth predicting.
MIN_BRANCH_CONSEQUENCE: float = 0.1

#: Two signal names beyond ``MANDATORY_SIGNALS`` that the four §15 branches need.
#: Declared here so the vocabulary stays closed and auditable.
_EXTRA_SIGNALS: frozenset[str] = frozenset({"file_staging", "session_teardown"})
CONE_SIGNAL_VOCABULARY: frozenset[str] = MANDATORY_SIGNALS | _EXTRA_SIGNALS

#: label -> (predicted signals, forbidden signals, dimensions this future would raise).
#: §15's own four branches for a compromised session, plus the benign terminator.
_BRANCH_SPECS: Mapping[str, tuple[frozenset[str], frozenset[str], frozenset[str]]] = {
    "persistence": (
        frozenset({"persistence_write", "module_load"}),
        frozenset({"session_teardown"}),
        frozenset({"persistence", "execution"}),
    ),
    "credential_access": (
        frozenset({"credential_access", "authentication"}),
        frozenset({"session_teardown"}),
        frozenset({"credential", "trust"}),
    ),
    "data_staging": (
        frozenset({"file_staging", "boundary_crossing"}),
        frozenset({"session_teardown"}),
        frozenset({"reachability", "discovery"}),
    ),
    "session_end": (
        frozenset({"session_teardown"}),
        frozenset({"persistence_write", "credential_access", "file_staging"}),
        frozenset(),
    ),
}

BRANCH_LABELS: tuple[str, ...] = tuple(_BRANCH_SPECS)

#: What a branch plausibly leads to next, for depth > 1. Deliberately sparse: a
#: successor is only listed where the architecture's own example chains them.
_SUCCESSORS: Mapping[str, str] = {
    "credential_access": "data_staging",
    "persistence": "credential_access",
    "data_staging": "session_end",
}


@dataclass(frozen=True, slots=True)
class CausalBranch:
    """One bounded security-relevant future of one world."""

    branch_id: str
    label: str
    predicted_signals: frozenset[str]
    forbidden_signals: frozenset[str]
    raises_dimensions: frozenset[str]
    consequence: float
    depth: int

    def __post_init__(self) -> None:
        if self.label not in _BRANCH_SPECS:
            raise ContractError(f"unknown branch label {self.label!r}")
        if not 1 <= self.depth <= MAX_CONE_DEPTH:
            raise ContractError(f"branch depth must be 1..{MAX_CONE_DEPTH}, got {self.depth}")
        unknown = (self.predicted_signals | self.forbidden_signals) - CONE_SIGNAL_VOCABULARY
        if unknown:
            raise ContractError(f"branch signals outside the closed vocabulary: {sorted(unknown)}")
        if self.predicted_signals & self.forbidden_signals:
            raise ContractError(
                "a branch may not predict and forbid the same signal: "
                f"{sorted(self.predicted_signals & self.forbidden_signals)}"
            )
        bad = self.raises_dimensions - frozenset(DIMENSIONS)
        if bad:
            raise ContractError(f"branch raises unknown dimensions: {sorted(bad)}")

    def contradicted_by(self, observed: frozenset[str]) -> bool:
        return bool(observed & self.forbidden_signals)

    def to_dict(self) -> dict[str, Any]:
        return {
            "branch_id": self.branch_id,
            "label": self.label,
            "predicted_signals": sorted(self.predicted_signals),
            "forbidden_signals": sorted(self.forbidden_signals),
            "raises_dimensions": sorted(self.raises_dimensions),
            "consequence": round(self.consequence, 4),
            "depth": self.depth,
        }


@dataclass(frozen=True, slots=True)
class IncidentFutureCone:
    """One world's bounded future cone, with its losses counted."""

    world_id: str
    branches: tuple[CausalBranch, ...]
    truncated_branches: int = 0

    def __post_init__(self) -> None:
        if len(self.branches) > MAX_BRANCHES_PER_WORLD:
            raise ContractError(
                f"a cone holds at most {MAX_BRANCHES_PER_WORLD} branches, "
                f"got {len(self.branches)}"
            )
        if self.truncated_branches < 0:
            raise ContractError("truncated_branches must be non-negative")
        ids = [branch.branch_id for branch in self.branches]
        if len(set(ids)) != len(ids):
            raise ContractError("duplicate branch_id in a cone")

    def predicted_signals(self) -> frozenset[str]:
        out: frozenset[str] = frozenset()
        for branch in self.branches:
            out |= branch.predicted_signals
        return out

    def discriminating_signals(self, other: IncidentFutureCone) -> frozenset[str]:
        """The signals that would tell these two worlds apart.

        A symmetric difference over predicted signal sets, and therefore symmetric by
        construction: ``a.discriminating_signals(b) == b.discriminating_signals(a)``.
        An empty result is the honest report that **no observation in this vocabulary
        separates these two worlds** — which is exactly the input
        ``test_identifiability`` needs to return ``UNIDENTIFIABLE`` rather than naming
        the more alarming world.
        """
        return self.predicted_signals() ^ other.predicted_signals()

    def collapse(self, observed: frozenset[str]) -> IncidentFutureCone:
        """Prune the branches this observation contradicts (§15).

        ``truncated_branches`` is deliberately unchanged: a refuted branch is a
        successful prediction being tested, not a bound being hit.
        """
        kept = tuple(b for b in self.branches if not b.contradicted_by(observed))
        if len(kept) == len(self.branches):
            return self
        return IncidentFutureCone(
            world_id=self.world_id,
            branches=kept,
            truncated_branches=self.truncated_branches,
        )

    def max_consequence(self) -> float:
        return max((b.consequence for b in self.branches), default=0.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "world_id": self.world_id,
            "branches": [b.to_dict() for b in self.branches],
            "truncated_branches": self.truncated_branches,
        }


def _reached_state(state: SecurityStateV1, dimensions: Iterable[str]) -> SecurityStateV1:
    """Raise each dimension one lattice step, capped at its top member.

    One step, not to the ceiling: a future cone predicts the next move, and predicting
    maximal compromise for every branch would make every consequence identical and the
    ordering meaningless.
    """
    reached = state
    for dimension in dimensions:
        enum_type = DIMENSIONS[dimension]
        ceiling = max(int(member) for member in enum_type)
        target = min(reached.level(dimension) + 1, ceiling)
        reached = reached.raised_to(dimension, enum_type(target))
    return reached


def _relevant(world: SecurityWorldV1, label: str,
              predicted: frozenset[str], raises: frozenset[str]) -> bool:
    """Is this future worth maintaining for this world?

    ``session_end`` is always a candidate — every session can end, and keeping the
    benign terminator is what stops a cone from only ever predicting escalation.
    """
    if label == "session_end":
        return True
    if predicted & frozenset(world.expected_evidence):
        return True
    return bool(raises & frozenset(world.latent_state.asserted_dimensions))


def _candidate_branches(world: SecurityWorldV1, depth: int) -> list[CausalBranch]:
    base = world.latent_state.state
    out: list[CausalBranch] = []
    for label, (predicted, forbidden, raises) in _BRANCH_SPECS.items():
        if not _relevant(world, label, predicted, raises):
            continue
        chain_signals, chain_raises, chain_label = predicted, raises, label
        for level in range(1, depth + 1):
            out.append(
                CausalBranch(
                    branch_id=f"{world.world_id}:{label}:{level}",
                    label=label,
                    predicted_signals=chain_signals,
                    forbidden_signals=forbidden,
                    raises_dimensions=chain_raises,
                    consequence=phi(_reached_state(base, chain_raises)).total,
                    depth=level,
                )
            )
            successor = _SUCCESSORS.get(chain_label)
            if successor is None:
                break
            next_predicted, next_forbidden, next_raises = _BRANCH_SPECS[successor]
            if next_predicted & forbidden or next_forbidden & chain_signals:
                # Chaining would make the branch predict and forbid the same signal.
                break
            chain_signals = chain_signals | next_predicted
            chain_raises = chain_raises | next_raises
            chain_label = successor
    return out


def predict_world_future_cone(
    world: SecurityWorldV1, *, depth: int = MAX_CONE_DEPTH
) -> IncidentFutureCone:
    """CBF-F11 — the bounded future cone of one world.

    Branches are ordered by descending consequence so that the bound, when it bites,
    drops the *least* consequential future. Every branch dropped — for consequence or
    for the bound — is counted in ``truncated_branches``.
    """
    if not 1 <= depth <= MAX_CONE_DEPTH:
        raise ContractError(f"depth must be 1..{MAX_CONE_DEPTH}, got {depth}")
    candidates = _candidate_branches(world, depth)
    consequential = [b for b in candidates if b.consequence >= MIN_BRANCH_CONSEQUENCE]
    dropped = len(candidates) - len(consequential)
    consequential.sort(key=lambda b: (-b.consequence, b.depth, b.label))
    kept = tuple(consequential[:MAX_BRANCHES_PER_WORLD])
    return IncidentFutureCone(
        world_id=world.world_id,
        branches=kept,
        truncated_branches=dropped + max(0, len(consequential) - len(kept)),
    )


def compose_cones(
    field: CausalBeliefField, *, depth: int = MAX_CONE_DEPTH
) -> Mapping[str, IncidentFutureCone]:
    """Incident-level composition: one cone per surviving world (§15).

    Bounded by ``MAX_BRANCHES_PER_WORLD`` × the field's own world cap, which is why
    this cannot be a denial-of-service surface even under a branch flood.
    """
    return {world.world_id: predict_world_future_cone(world, depth=depth) for world in field.worlds}


def pairwise_discriminating_signals(
    cones: Mapping[str, IncidentFutureCone] | Sequence[IncidentFutureCone],
) -> Mapping[tuple[str, str], frozenset[str]]:
    """Every pair's discriminating signal set, world ids sorted within each key.

    This is what D4.9 reads: an empty set for a pair means no observation in the
    vocabulary separates those two worlds, and a planner that spends telemetry on that
    pair anyway is spending for nothing (§17's first rule).
    """
    items = tuple(cones.values()) if isinstance(cones, Mapping) else tuple(cones)
    out: dict[tuple[str, str], frozenset[str]] = {}
    for index, left in enumerate(items):
        for right in items[index + 1 :]:
            key = (left.world_id, right.world_id)
            if key[0] > key[1]:
                key = (key[1], key[0])
            out[key] = left.discriminating_signals(right)
    return out
