"""D2.8 / DTL-F05 — the bounded Future Cone (spec section 7).

Spec section 7 is explicit that this is **not** a generative simulator of
arbitrary Linux activity. It is a compact, deliberately shallow distribution over
a handful of security-relevant continuations, capped at ``MAX_BRANCHES`` wide and
``MAX_DEPTH`` deep, whose purpose is to estimate continuation risk and to say
which branch is worth observing.

Two properties are load-bearing and neither is negotiable:

* **The unresolved branch is explicit and never folded away.** ``unresolved_mass``
  holds every probability the lattice could not name: the tail the beam dropped,
  and the mass the successor distribution itself left unassigned. Redistributing
  it over the named branches would manufacture confidence out of ignorance, and
  UNKNOWN is a valid PocketSec output.
* **Mass is conserved exactly.** ``sum(branch probabilities) + unresolved_mass``
  must equal 1.0 within 1e-9 or construction fails. A cone that does not sum to
  one is not a distribution and every Brier score taken from it would be void.

``marginal_cone`` is the control this mechanism has to beat. It is the
epoch-marginal continuation distribution with the current atom removed, and if
the conditioned cone cannot beat it on Brier, the cone does not earn its place —
which acceptance criterion 6 explicitly permits (see ADR-0116).

Terminal states are built with ``SecurityStateV1.raised_to``, so a branch is
monotone by construction: a lineage never loses capability while walking forward,
because you do not un-read a credential.

**MEASURED VERDICT — the cone is rejected and default off (ADR-0116).** On
``corpus='ambiguous'``, ``count=240``, ``seed=11``, 3000 contexts: Brier
**1.458259** at the specified bounds against ``marginal_cone``'s **0.175982**, and
**1.484908** against **0.301033** when both are scored on a depth-3 truth.
Collapsed to depth 1 the cone reaches 0.169505 — inside the corpus noise. Mean
unresolved mass 0.848074: the cone spends 85 % of its confidence saying it does
not know. So this module refuses to contribute to a detection score, a verdict,
an escalation or a compile candidate. It remains in the tree because
``marginal_cone`` is the control that produced the rejection, and deleting a
mechanism together with its own falsifier destroys the evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Iterable, Mapping, Sequence

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.state.potential import phi
from pocketsec.stage1.state.security_state import DIMENSIONS, SecurityStateV1
from pocketsec.stage2.core_ids import PATH_COST_UNITS, ExecutionPath
from pocketsec.stage2.router.accounting import WorkKind

if TYPE_CHECKING:  # pragma: no cover - typing only
    # `lattice/` is consumed through its published method surfaces only, so the
    # coupling stays structural and a caller may substitute its own lattice.
    # `WorkKind` above is a StrEnum of work *labels*: importing it does not pull
    # in a router, which is what ADR-0114 keeps separate from the accounting.
    from pocketsec.stage2.lattice.quantizer import BehaviourQuantizer
    from pocketsec.stage2.lattice.transitions import TransitionLattice
    from pocketsec.stage2.router.accounting import WorkLedger

__all__ = [
    "CONE_LABELS",
    "FUTURE_CONE_DEFAULT_ENABLED",
    "MAX_BRANCHES",
    "MAX_DEPTH",
    "UNKNOWN_LABEL",
    "ConeBranch",
    "FutureCone",
    "branch_label",
    "marginal_cone",
    "predict_future_cone",
]

#: ADR-0116 rejected DTL-F05 on measured calibration: the cone scores Brier
#: 1.458259 against `marginal_cone`'s 0.175982, and collapsed to depth 1 its
#: 0.006477 margin is inside the corpus noise. The ADR says "both are default
#: off"; this constant is that sentence in code, because a gate may not read a
#: decision out of a document. Nothing here consults it — a caller that would
#: let a cone reach a verdict, a score or a compile candidate must check it.
FUTURE_CONE_DEFAULT_ENABLED: bool = False

#: Spec section 7: "deliberately shallow and bounded".
MAX_BRANCHES: int = 4
MAX_DEPTH: int = 3

#: The explicit unknown branch. Never a named continuation.
UNKNOWN_LABEL: str = "unknown"

#: Every label a branch can carry, in descending consequence. A fixed label
#: space is what makes the cone and its marginal control scorable against each
#: other: a Brier over two different label sets compares nothing.
CONE_LABELS: tuple[str, ...] = (
    "credential_egress",
    "administrative_escalation",
    "persistence_install",
    "discovery_sweep",
    "boundary_crossing",
    "normal_continuation",
    UNKNOWN_LABEL,
)

#: Label rules in priority order: (label, the dimensions that trigger it).
#: Priority is by consequence, so a branch that raises both privilege and
#: credential is reported as the credential chain rather than as an escalation.
_LABEL_RULES: tuple[tuple[str, frozenset[str]], ...] = (
    ("credential_egress", frozenset({"credential"})),
    ("administrative_escalation", frozenset({"privilege", "execution"})),
    ("persistence_install", frozenset({"persistence"})),
    ("discovery_sweep", frozenset({"discovery"})),
    (
        "boundary_crossing",
        frozenset({"reachability", "isolation", "trust", "modification"}),
    ),
)

_MASS_TOLERANCE: float = 1e-9

#: The cone's cost is lattice lookups, so that is what it reports: one
#: `P1_LATTICE` unit per successor query actually issued. The ledger only ever
#: sees work that ran (ADR-0114).
_LOOKUP_UNITS: float = PATH_COST_UNITS[ExecutionPath.P1_LATTICE]


def branch_label(previous: SecurityStateV1, terminal: SecurityStateV1) -> str:
    """Name a continuation from the dimensions it raised."""
    raised = terminal.delta_from(previous).dimensions
    if not raised:
        return "normal_continuation"
    for label, triggers in _LABEL_RULES:
        if raised & triggers:
            return label
    return "normal_continuation"  # pragma: no cover - rules cover all 9 dimensions


def _apply_atom_state(
    state: SecurityStateV1, summary: SecurityStateV1
) -> SecurityStateV1:
    """Raise ``state`` to the capability level an atom's summary implies."""
    result = state
    for name, enum_type in DIMENSIONS.items():
        level = summary.level(name)
        if level > result.level(name):
            result = result.raised_to(name, enum_type(level))
    return result


@dataclass(frozen=True, slots=True)
class ConeBranch:
    """One named continuation. ``atom_path`` holds *future* atoms only."""

    label: str
    atom_path: tuple[int, ...]
    probability: float
    terminal_state: SecurityStateV1
    delta_phi: float
    #: Lattice provenance (atom and edge references), not Stage 0 evidence
    #: digests: a cone over prototypes has no raw evidence of its own. The
    #: exporter re-binds these to `EvidenceRef` through Stage 1's transitions.
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.label not in CONE_LABELS:
            raise ContractError(f"unknown cone label {self.label!r}")
        if self.label == UNKNOWN_LABEL:
            raise ContractError(
                "the unknown branch is unresolved_mass, never a named branch"
            )
        if len(self.atom_path) > MAX_DEPTH:
            raise ContractError(
                f"atom_path depth {len(self.atom_path)} exceeds MAX_DEPTH {MAX_DEPTH}"
            )
        if not 0.0 <= self.probability <= 1.0:
            raise ContractError(f"branch probability {self.probability} outside [0, 1]")

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "atom_path": list(self.atom_path),
            "probability": round(self.probability, 6),
            "terminal_state": self.terminal_state.to_dict(),
            "delta_phi": round(self.delta_phi, 4),
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True, slots=True)
class FutureCone:
    """A bounded continuation distribution with an explicit unknown branch."""

    branches: tuple[ConeBranch, ...]
    unresolved_mass: float
    depth: int
    truncated: bool

    def __post_init__(self) -> None:
        if len(self.branches) > MAX_BRANCHES:
            raise ContractError(
                f"{len(self.branches)} branches exceeds MAX_BRANCHES {MAX_BRANCHES}"
            )
        if self.depth > MAX_DEPTH or self.depth < 0:
            raise ContractError(f"cone depth {self.depth} outside [0, {MAX_DEPTH}]")
        if not 0.0 <= self.unresolved_mass <= 1.0:
            raise ContractError(
                f"unresolved_mass {self.unresolved_mass} outside [0, 1]"
            )
        total = sum(branch.probability for branch in self.branches)
        total += self.unresolved_mass
        if abs(total - 1.0) > _MASS_TOLERANCE:
            raise ContractError(
                "cone probabilities plus unresolved mass must sum to 1.0, got "
                f"{total!r}"
            )

    @property
    def resolved_mass(self) -> float:
        return sum(branch.probability for branch in self.branches)

    def most_consequential(self) -> ConeBranch | None:
        """The branch whose terminal state carries the highest Φ, or None."""
        if not self.branches:
            return None
        return max(
            self.branches,
            key=lambda branch: (phi(branch.terminal_state).total, branch.atom_path),
        )

    def label_distribution(self) -> dict[str, float]:
        """Probability per label, with ``unknown`` carrying unresolved mass.

        This is the form a Brier score is taken over, and the reason
        ``unresolved_mass`` has to be a real class: scoring it away would give
        the cone credit for a confidence it never had.
        """
        distribution = {label: 0.0 for label in CONE_LABELS}
        for branch in self.branches:
            distribution[branch.label] += branch.probability
        distribution[UNKNOWN_LABEL] += self.unresolved_mass
        return distribution

    def to_dict(self) -> dict[str, Any]:
        return {
            "branches": [branch.to_dict() for branch in self.branches],
            "unresolved_mass": round(self.unresolved_mass, 6),
            "depth": self.depth,
            "truncated": self.truncated,
        }


@dataclass(frozen=True, slots=True)
class _Partial:
    """An in-progress path. ``path[0]`` is the starting atom."""

    path: tuple[int, ...]
    probability: float
    state: SecurityStateV1
    evidence: tuple[str, ...]


def _successor_step(
    lattice: TransitionLattice,
    quantizer: BehaviourQuantizer,
    partial: _Partial,
    *,
    epoch_id: int,
    limit: int,
) -> tuple[list[_Partial], float, bool]:
    """Expand one partial path.

    Returns ``(children, unnamed mass, hit_limit)``. ``hit_limit`` is True when the
    lattice returned exactly as many successors as were asked for, which means the
    successor set was itself clipped before the beam ever saw it — a truncation the
    cone must report rather than silently inherit.
    """
    source = partial.path[-1]
    raw = tuple(lattice.successors(source, epoch_id=epoch_id, limit=limit))
    hit_limit = len(raw) >= limit
    successors = [
        (target, probability) for target, probability in raw if probability > 0.0
    ]
    if not successors:
        return [], 0.0, hit_limit
    named = sum(probability for _, probability in successors)
    children: list[_Partial] = []
    for target, probability in successors:
        atom = quantizer.get(target)
        state = (
            partial.state
            if atom is None
            else _apply_atom_state(partial.state, atom.state_summary)
        )
        children.append(
            _Partial(
                path=partial.path + (target,),
                probability=partial.probability * probability,
                state=state,
                evidence=partial.evidence
                + (f"lattice-edge:{source}->{target}@epoch{epoch_id}",),
            )
        )
    unnamed = partial.probability * max(0.0, 1.0 - named)
    return children, unnamed, hit_limit


def _finalise(
    partials: Sequence[_Partial],
    *,
    origin: SecurityStateV1,
    accounted_unresolved: float,
    truncated: bool,
    max_branches: int,
) -> FutureCone:
    """Cap the beam, build branches, and close the mass budget exactly."""
    ordered = sorted(partials, key=lambda p: (-p.probability, p.path))
    kept = ordered[:max_branches]
    dropped = ordered[max_branches:]
    if dropped:
        truncated = True
        accounted_unresolved += sum(p.probability for p in dropped)
    origin_phi = phi(origin).total
    branches = tuple(
        ConeBranch(
            label=branch_label(origin, p.state),
            atom_path=p.path[1:],
            probability=p.probability,
            terminal_state=p.state,
            delta_phi=phi(p.state).total - origin_phi,
            evidence=p.evidence,
        )
        for p in kept
    )
    # Close on the exact residual so the sum is 1.0 to the bit, then check the
    # tracked budget agrees. A mismatch is a mass-conservation bug in the beam,
    # and it must fail loudly rather than be absorbed.
    residual = 1.0 - sum(branch.probability for branch in branches)
    if abs(residual - accounted_unresolved) > 1e-6:
        raise ContractError(
            "future cone lost probability mass: tracked "
            f"{accounted_unresolved!r}, residual {residual!r}"
        )
    return FutureCone(
        branches=branches,
        unresolved_mass=max(0.0, residual),
        depth=max((len(branch.atom_path) for branch in branches), default=0),
        truncated=truncated,
    )


def _record_expansion(ledger: WorkLedger | None, lookups: int) -> None:
    """Report the lookups that genuinely ran (ADR-0114)."""
    if ledger is None:
        return
    ledger.record(
        WorkKind.CONE_EXPANSION,
        performed=True,
        units=_LOOKUP_UNITS * lookups,
        detail=f"lattice successor lookups={lookups}",
    )


@dataclass(slots=True)
class _Beam:
    """Mutable accumulator for one expansion, so the mass budget lives in one
    place instead of being threaded through five return values."""

    frontier: list[_Partial]
    terminal: list[_Partial] = field(default_factory=list)
    unresolved: float = 0.0
    truncated: bool = False
    lookups: int = 0


def _expand_one_level(
    beam: _Beam,
    lattice: TransitionLattice,
    quantizer: BehaviourQuantizer,
    *,
    epoch_id: int,
    limit: int,
) -> bool:
    """Advance the beam one step. Returns False when nothing can expand further."""
    candidates: list[_Partial] = []
    for partial in beam.frontier:
        beam.lookups += 1
        children, unnamed, hit_limit = _successor_step(
            lattice, quantizer, partial, epoch_id=epoch_id, limit=limit
        )
        beam.unresolved += unnamed
        beam.truncated = beam.truncated or hit_limit
        if children:
            candidates.extend(children)
        elif len(partial.path) > 1:
            # A path that already walked an observed edge is a real branch: it
            # describes the states reached, not a claim that activity stops.
            beam.terminal.append(partial)
        else:
            # A *starting* atom with no known successor is different — nothing
            # was observed at all, so its mass belongs to the unknown branch
            # rather than to a "normal_continuation" the lattice never supported.
            beam.unresolved += partial.probability
    if not candidates:
        beam.frontier = []
        return False
    ordered = sorted(candidates, key=lambda p: (-p.probability, p.path))
    beam.frontier = ordered[:limit]
    if len(ordered) > limit:
        beam.truncated = True
        beam.unresolved += sum(p.probability for p in ordered[limit:])
    return True


def predict_future_cone(
    lattice: TransitionLattice,
    quantizer: BehaviourQuantizer,
    *,
    from_atom: int,
    state: SecurityStateV1,
    epoch_id: int,
    max_branches: int = MAX_BRANCHES,
    max_depth: int = MAX_DEPTH,
    ledger: WorkLedger | None = None,
) -> FutureCone:
    """DTL-F05 — beam-expand the lattice into a bounded cone of continuations.

    An atom the lattice has never seen a successor for yields the all-unknown
    cone: no branches, ``unresolved_mass == 1.0``. That is the abstention path,
    and it is a correct answer rather than a failure.
    """
    if not 1 <= max_branches <= MAX_BRANCHES:
        raise ContractError(
            f"max_branches must be in [1, {MAX_BRANCHES}], got {max_branches}"
        )
    if not 1 <= max_depth <= MAX_DEPTH:
        raise ContractError(f"max_depth must be in [1, {MAX_DEPTH}], got {max_depth}")

    beam = _Beam(frontier=[_Partial((from_atom,), 1.0, state, ())])
    for _ in range(max_depth):
        if not _expand_one_level(
            beam, lattice, quantizer, epoch_id=epoch_id, limit=max_branches
        ):
            break

    _record_expansion(ledger, beam.lookups)
    return _finalise(
        beam.terminal + beam.frontier,
        origin=state,
        accounted_unresolved=beam.unresolved,
        truncated=beam.truncated,
        max_branches=max_branches,
    )


def _discover_sources(lattice: TransitionLattice) -> tuple[int, ...]:
    accessor = getattr(lattice, "sources", None)
    if accessor is None or not callable(accessor):
        raise ContractError(
            "marginal_cone cannot enumerate the lattice: pass sources=... "
            "explicitly, or give TransitionLattice a sources() accessor"
        )
    return tuple(accessor())


def _marginal_partial(
    target: int,
    value: float,
    *,
    origin: SecurityStateV1,
    quantizer: BehaviourQuantizer | None,
    epoch_id: int,
) -> _Partial:
    """One marginal branch. ``path[0] == -1`` marks "no starting atom"."""
    atom = None if quantizer is None else quantizer.get(target)
    return _Partial(
        path=(-1, target),
        probability=min(1.0, value),
        state=origin if atom is None else _apply_atom_state(origin, atom.state_summary),
        evidence=(f"lattice-marginal:{target}@epoch{epoch_id}",),
    )


def marginal_cone(
    lattice: TransitionLattice,
    *,
    epoch_id: int,
    quantizer: BehaviourQuantizer | None = None,
    state: SecurityStateV1 | None = None,
    sources: Iterable[int] | None = None,
    source_weights: Mapping[int, float] | None = None,
    max_branches: int = MAX_BRANCHES,
) -> FutureCone:
    """THE SIMPLE CONTROL — the epoch-marginal continuation, current atom removed.

    Everything the conditioned cone gets, this gets too, except the one thing
    under test: which atom the lineage is standing on. ``state`` and
    ``quantizer`` are accepted precisely so the control is not weakened into a
    straw man — a marginal with no atom summaries would label every branch
    ``normal_continuation`` and lose on Brier for the wrong reason.

    ``source_weights`` lets a caller supply visit counts, making this a
    count-weighted marginal. Without them sources are weighted uniformly, which
    is the weaker control; a cone that cannot beat even that has no case.
    """
    origin = SecurityStateV1() if state is None else state
    source_ids = (
        _discover_sources(lattice) if sources is None else tuple(sources)
    )
    weights = {
        source: (1.0 if source_weights is None else float(source_weights.get(source, 0.0)))
        for source in source_ids
    }
    total_weight = sum(weights.values())
    if total_weight <= 0.0:
        return FutureCone(branches=(), unresolved_mass=1.0, depth=0, truncated=False)

    mass: dict[int, float] = {}
    for source, weight in weights.items():
        if weight <= 0.0:
            continue
        for target, probability in lattice.successors(
            source, epoch_id=epoch_id, limit=max_branches
        ):
            if probability > 0.0:
                mass[target] = mass.get(target, 0.0) + weight * probability / total_weight

    partials = [
        _marginal_partial(
            target, value, origin=origin, quantizer=quantizer, epoch_id=epoch_id
        )
        for target, value in mass.items()
    ]
    named = sum(p.probability for p in partials)
    if named > 1.0:  # pragma: no cover - guarded by the per-source normalisation
        raise ContractError(f"marginal mass {named} exceeds 1.0")
    ordered = sorted(partials, key=lambda p: (-p.probability, p.path))
    kept = ordered[:max_branches]
    truncated = len(ordered) > max_branches
    return _finalise(
        kept,
        origin=origin,
        accounted_unresolved=1.0 - sum(p.probability for p in kept),
        truncated=truncated,
        max_branches=max_branches,
    )
