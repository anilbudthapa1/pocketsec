"""DTL-F11 — the Counterfactual Twin (architecture spec section 16).

    Observed:        session -> sudo -> interpreter -> credential read -> egress
    Counterfactual:  session -> [sudo removed] -> interpreter -> ?
    Responsibility(sudo) = divergence between predicted security futures

That equation is implemented literally here: a probe masks, neutralises or
delays one transition inside a bounded lineage window, re-derives the predicted
future from the *same* learned lattice, and reports the Jensen-Shannon
divergence between the two futures. Nothing else counts as responsibility.

What this module refuses to do, and why:

* **It never mutates the live quantizer or lattice.** A probe that quantizes its
  own counterfactual would teach the model the trajectory it invented — a
  corpus leak with no external symptom. Both objects are handed in wrapped in
  :class:`ReadOnlyGuard`, which is **deny-by-default**: only the names in
  :data:`LATTICE_READS` and :data:`QUANTIZER_READS` forward, so every mutator
  that exists now (``observe``, ``set_status``, ``remove_edge``, ``reinsert``,
  ``quantize_behaviour_atom``, ``fission_atom``) and every one added later
  raises instead of silently succeeding. Atom assignment during a probe is
  read-only nearest-prototype lookup.
* **It never exceeds its compute budget silently, and it never reports work it
  did do as skipped.** ``MAX_PROBES_PER_EVENT`` and ``MAX_PROBE_DEPTH`` are
  hard. Exhaustion is reported on the probe (``budget_exhausted``) and marked in
  ``evidence``; a refused probe carries the observed future on both sides, so
  its divergence is a real 0.0 rather than an unmeasured number dressed up as
  one, and :mod:`pocketsec.stage2.credit.ledger` refuses to award credit for it.
  On the ledger, a refusal costs ``0.0`` units — the observed cone was expanded
  before the budget was consulted and is charged as its own performed
  ``CONE_EXPANSION``, and only the counterfactual half is genuinely skipped.
* **It is attribution and evidence selection, not generative reasoning**
  (architecture spec section 16). The only alternatives considered are the three
  :class:`Intervention` members applied to transitions that were actually
  observed.

Divergence is computed over branch **labels**, never over atom ids: a lattice
that relabels the same predicted future with different prototype ids must
register zero divergence, because nothing about the security future changed.

Stdlib only. The lattice, quantizer and cone are consumed through their
documented call shapes rather than imported as concrete types, so a caller may
substitute the zero-parameter control for any of them. Two leaf symbols *are*
imported: :data:`WorkKind`, so a probe's ledger record cannot degrade to a bare
string, and :func:`jensen_shannon`, because one divergence measure in Stage 2 is
one definition of divergence (integrator seam fix, this wave).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Callable, Iterable, Protocol, Sequence

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.state.security_state import DIMENSIONS, SecurityStateV1
from pocketsec.stage2.core_ids import PATH_COST_UNITS, ExecutionPath
from pocketsec.stage2.encoder.ssir_encoder import (
    FEATURE_LAYOUT,
    GROUP_OFFSETS,
    EncodedTransition,
)
from pocketsec.stage2.lattice.equivalence import jensen_shannon
from pocketsec.stage2.router.accounting import WorkKind

if TYPE_CHECKING:  # pragma: no cover - typing only, never imported at runtime
    from pocketsec.stage2.state.window import LineageWindow

__all__ = [
    "DELAY_NOOP_EVIDENCE",
    "MAX_PROBES_PER_EVENT",
    "MAX_PROBE_DEPTH",
    "CONE_EXPANSION_UNITS",
    "LATTICE_READS",
    "PHI_PRIOR_SCALE",
    "PROBE_COST_UNITS",
    "QUANTIZER_READS",
    "PROBE_REFUSED_EVIDENCE",
    "PROBE_TRUNCATED_EVIDENCE",
    "UNRESOLVED_LABEL",
    "BranchView",
    "ConeView",
    "CounterfactualProbe",
    "Intervention",
    "PhiBranch",
    "PhiCone",
    "ProbeBudget",
    "ReadOnlyGuard",
    "counterfactual_probe",
    "expected_delta_phi",
    "jensen_shannon",
    "label_distribution",
    "phi_only_probe",
    "probe_event",
]

#: Probes allowed per observed event. Counterfactual analysis is the most
#: expensive path in Stage 2 (P4_DEEP), so it is rationed rather than trusted.
MAX_PROBES_PER_EVENT: int = 4
#: Transitions a single probe may replay. The window may be longer; the excess
#: is reported as truncation, never replayed anyway.
MAX_PROBE_DEPTH: int = 8

#: Cost of one probe in PATH_COST_UNITS terms. NOTE: PATH_COST_UNITS is itself
#: uncalibrated (Stage 2 spec honest limit 9), so this is a policy weight for
#: the work ledger, not a measured microsecond figure.
PROBE_COST_UNITS: float = PATH_COST_UNITS[ExecutionPath.P4_DEEP]

#: Cost of expanding ONE cone. A probe always expands the observed future, and
#: expands the counterfactual one only if the budget granted it, so the two are
#: charged separately: a refused probe genuinely spent the first and genuinely
#: did not spend the second (S2-01).
CONE_EXPANSION_UNITS: float = PATH_COST_UNITS[ExecutionPath.P3_PREDICTIVE]

#: Prior ΔΦ scale for the Φ-only control's cone. Quoted from the encoder's own
#: ΔΦ squash scale (``ssir_encoder._PHI_SCALE``) so the control lives on the same
#: scale the representation already uses, rather than on a new invented one.
PHI_PRIOR_SCALE: float = 8.0

#: Pseudo-label carrying a cone's explicit unknown mass into the divergence.
#: Folding it away would make an ambiguous future look like a confident one.
UNRESOLVED_LABEL: str = "__unresolved__"

#: The only lattice reads a probe is allowed to make. Deny-by-default: anything
#: absent here — ``observe``, ``set_status``, ``remove_edge``, ``reinsert`` —
#: raises rather than forwarding (S2-AUTH-04).
LATTICE_READS: tuple[str, ...] = (
    "alpha",
    "bucket_count",
    "edge",
    "edges",
    "evictions",
    "known_targets",
    "log_loss",
    "max_transitions",
    "memory_bytes",
    "perplexity",
    "probability",
    "sources",
    "successors",
    "to_dict",
    "unseen_mass",
    "vocabulary_floor",
)

#: The only quantizer reads a probe is allowed to make. ``quantize_behaviour_atom``
#: and ``fission_atom`` are absent, which is the point.
QUANTIZER_READS: tuple[str, ...] = (
    "atoms",
    "buckets",
    "get",
    "max_atoms",
    "memory_bytes",
    "radius",
    "stats",
    "to_dict",
)

#: Evidence markers. These are a named contract with the credit ledger, which
#: must be able to tell "measured no change" from "did not measure".
PROBE_REFUSED_EVIDENCE: str = "probe_refused:per_event_budget"
PROBE_TRUNCATED_EVIDENCE: str = "probe_truncated:max_probe_depth"
DELAY_NOOP_EVIDENCE: str = "probe_noop:delay_at_window_end"

_DIMENSION_NAMES: tuple[str, ...] = tuple(DIMENSIONS)
#: Feature groups a benign substitution must neutralise, derived from the frozen
#: encoder layout rather than hardcoded indices.
_CONSEQUENCE_GROUPS: tuple[str, ...] = (
    "state_delta_raised",
    "state_delta_scalars",
    "delta_phi",
)
_GROUP_WIDTHS: dict[str, int] = dict(FEATURE_LAYOUT)


class Intervention(StrEnum):
    """The only three alternatives a probe is allowed to imagine."""

    #: Remove the transition from the replay entirely.
    MASK = "MASK"
    #: Keep the transition but strip its security consequence.
    SUBSTITUTE_BENIGN = "SUBSTITUTE_BENIGN"
    #: Keep the transition but move it to the end of the bounded horizon.
    DELAY = "DELAY"


class BranchView(Protocol):
    """The part of a D2.8 ``ConeBranch`` this module reads."""

    label: str
    probability: float
    delta_phi: float


class ConeView(Protocol):
    """The part of a D2.8 ``FutureCone`` this module reads.

    Declared structurally so the zero-parameter control can supply its own
    :class:`PhiCone` without importing — or duplicating — the neural cone.
    """

    branches: tuple[BranchView, ...]
    unresolved_mass: float


@dataclass(frozen=True, slots=True)
class PhiBranch:
    """One branch of the zero-parameter control's cone."""

    label: str
    probability: float
    delta_phi: float
    atom_path: tuple[int, ...] = ()
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PhiCone:
    """A predicted future built from Stage 1's ΔΦ alone — zero parameters.

    Not a ``FutureCone``: no lattice, no atoms, no learned probabilities. It
    exists so the Φ-only control can be compared against the model-based twin
    with the *same* divergence measure, which is the only way the comparison
    means anything.
    """

    branches: tuple[PhiBranch, ...]
    unresolved_mass: float
    depth: int
    truncated: bool

    def most_consequential(self) -> PhiBranch | None:
        if not self.branches:
            return None
        return max(self.branches, key=lambda b: (b.delta_phi, b.probability))

    def to_dict(self) -> dict[str, Any]:
        return {
            "branches": [
                {
                    "label": b.label,
                    "probability": round(b.probability, 4),
                    "delta_phi": round(b.delta_phi, 4),
                }
                for b in self.branches
            ],
            "unresolved_mass": round(self.unresolved_mass, 4),
            "depth": self.depth,
            "truncated": self.truncated,
        }


@dataclass(frozen=True, slots=True)
class CounterfactualProbe:
    """One masked/substituted/delayed transition and what it cost the future."""

    target_signature: str
    intervention: Intervention
    observed_cone: ConeView
    counterfactual_cone: ConeView
    divergence: float
    delta_phi_shift: float
    budget_exhausted: bool
    evidence: tuple[str, ...]

    @property
    def measured(self) -> bool:
        """False when the probe was refused, so nothing was actually compared."""
        return PROBE_REFUSED_EVIDENCE not in self.evidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_signature": self.target_signature,
            "intervention": self.intervention.value,
            "divergence": round(self.divergence, 6),
            "delta_phi_shift": round(self.delta_phi_shift, 4),
            "budget_exhausted": self.budget_exhausted,
            "measured": self.measured,
            "evidence": list(self.evidence),
            "observed_labels": {
                k: round(v, 4) for k, v in label_distribution(self.observed_cone).items()
            },
            "counterfactual_labels": {
                k: round(v, 4)
                for k, v in label_distribution(self.counterfactual_cone).items()
            },
        }


class ReadOnlyGuard:
    """A deny-by-default read-only view. Only ``readable`` names forward.

    The point is not politeness. A probe that quantizes its counterfactual into
    the live quantizer, or writes its invented edge into the live lattice, is a
    corpus leak that produces plausible numbers forever. Making the mutator
    raise turns that class of bug into an immediate, loud failure.

    This is an **allowlist**, not a blocklist, and that is the whole of the fix
    for S2-AUTH-04. The blocklist version named one mutator per object
    (``observe`` for the lattice, ``quantize_behaviour_atom`` for the quantizer)
    while ``set_status``, ``remove_edge``, ``reinsert`` and ``fission_atom``
    forwarded straight through. ``reinsert`` in particular takes a whole
    ``LatticeTransition``, so counts, epoch histories and compile status could be
    fabricated during a probe — including ``CompileStatus.EXECUTABLE``, which
    ``lattice/atom.py`` documents as the one status Stage 2 never promotes itself
    to (ADR-0003). A blocklist has to be right about every mutator that exists
    now and every one added later; an allowlist only has to be right about the
    reads this module performs.
    """

    __slots__ = ("_target", "_readable")

    def __init__(self, target: Any, *, readable: Sequence[str]) -> None:
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_readable", frozenset(readable))

    def __getattr__(self, name: str) -> Any:
        if name not in object.__getattribute__(self, "_readable"):
            raise ContractError(
                f"{name!r} is not on this probe's read-only allowlist and is "
                "refused during a counterfactual probe; a probe may not train on, "
                "restructure or relabel the live model"
            )
        return getattr(object.__getattribute__(self, "_target"), name)

    def __setattr__(self, name: str, value: Any) -> None:
        raise ContractError("a counterfactual probe may not write to the live model")

    def unwrap(self) -> Any:
        return object.__getattribute__(self, "_target")


class ProbeBudget:
    """Rations probes per event and per session; refusal is recorded, not raised.

    A caller driving :func:`counterfactual_probe` directly must call
    :meth:`begin_event` when a new event arrives, or the per-event counter never
    resets and the budget degenerates into a session-wide cap of
    ``max_per_event``. :func:`probe_event` does this for you, which is why it is
    the intended entry point.
    """

    __slots__ = ("max_per_event", "max_total", "_event_key", "_event_spent", "_total")

    def __init__(
        self, *, max_per_event: int = MAX_PROBES_PER_EVENT, max_total: int = 64
    ) -> None:
        if max_per_event < 1 or max_total < 1:
            raise ContractError("probe budgets must be >= 1")
        self.max_per_event = max_per_event
        self.max_total = max_total
        self._event_key = ""
        self._event_spent = 0
        self._total = 0

    def begin_event(self, event_key: str) -> None:
        self._event_key = event_key
        self._event_spent = 0

    def try_spend(self) -> bool:
        if self._event_spent >= self.max_per_event or self._total >= self.max_total:
            return False
        self._event_spent += 1
        self._total += 1
        return True

    @property
    def spent(self) -> int:
        return self._total

    @property
    def spent_this_event(self) -> int:
        return self._event_spent


ConeExpander = Callable[..., ConeView]


# --- divergence ---------------------------------------------------------------


def label_distribution(cone: ConeView | None) -> dict[str, float]:
    """A cone as a probability distribution over branch **labels**.

    Labels, not atom paths: two cones that predict the same security futures by
    different prototype routes are the same prediction, and a divergence measure
    that disagreed would be measuring the quantizer's naming, not the future.
    """
    if cone is None:
        return {UNRESOLVED_LABEL: 1.0}
    mass: dict[str, float] = {}
    for branch in cone.branches:
        probability = float(branch.probability)
        if probability < 0.0:
            raise ContractError(f"branch {branch.label!r} has negative probability")
        mass[branch.label] = mass.get(branch.label, 0.0) + probability
    unresolved = float(getattr(cone, "unresolved_mass", 0.0))
    if unresolved < 0.0:
        raise ContractError("cone unresolved_mass must be >= 0")
    if unresolved > 0.0:
        mass[UNRESOLVED_LABEL] = mass.get(UNRESOLVED_LABEL, 0.0) + unresolved
    total = sum(mass.values())
    if total <= 0.0:
        return {UNRESOLVED_LABEL: 1.0}
    return {label: value / total for label, value in mass.items()}


def expected_delta_phi(cone: ConeView | None) -> float:
    """Probability-weighted ΔΦ of a predicted future."""
    if cone is None:
        return 0.0
    return sum(float(b.probability) * float(b.delta_phi) for b in cone.branches)


# --- replay ------------------------------------------------------------------


def _raise_masked(state: SecurityStateV1, mask: int) -> SecurityStateV1:
    """Raise every dimension named by a state-delta bitmask to its first level.

    The window carries encoded transitions, not Stage 1 lineage states, so the
    probe reconstructs a state consistent with each step's ``state_delta_mask``.
    The reconstruction loses *how far* a dimension was raised — an
    approximation, recorded as one. It is applied identically to the observed
    and counterfactual replays, which is what keeps the comparison fair.
    """
    if not mask:
        return state
    for index, name in enumerate(_DIMENSION_NAMES):
        if mask & (1 << index):
            state = state.raised_to(name, DIMENSIONS[name](1))
    return state


def _fold_state(
    steps: Iterable[EncodedTransition], *, base: SecurityStateV1 | None = None
) -> SecurityStateV1:
    """Fold a run of transitions into one reconstructed state.

    The masks are OR-ed before any state is built. ``raised_to`` at level 1 is
    monotone and idempotent, so OR-ing first is exactly equivalent to raising
    step by step, and it turns O(steps x dimensions) dataclass copies into at
    most nine — which matters because this runs on the probe's hot path.
    """
    mask = 0
    for step in steps:
        mask |= step.state_delta_mask
    return _raise_masked(base if base is not None else SecurityStateV1(), mask)


def _benign_substitute(step: EncodedTransition) -> EncodedTransition:
    """The same operation with its security consequence removed."""
    features = list(step.features)
    for group in _CONSEQUENCE_GROUPS:
        start = GROUP_OFFSETS[group]
        width = _GROUP_WIDTHS[group]
        for index in range(start, start + width):
            features[index] = 0.0
    return replace(
        step, features=tuple(features), state_delta_mask=0, delta_phi=0.0
    )


def _intervene(
    suffix: tuple[EncodedTransition, ...], intervention: Intervention
) -> tuple[tuple[EncodedTransition, ...], tuple[str, ...]]:
    """Apply the intervention to a suffix whose first element is the target."""
    if intervention is Intervention.MASK:
        return suffix[1:], ()
    if intervention is Intervention.SUBSTITUTE_BENIGN:
        return (_benign_substitute(suffix[0]), *suffix[1:]), ()
    if len(suffix) == 1:
        # Delaying the last transition inside the horizon changes nothing that
        # this probe can observe. Say so rather than reporting a measured zero.
        return suffix, (DELAY_NOOP_EVIDENCE,)
    return (*suffix[1:], suffix[0]), ()


def _nearest_atom(quantizer: Any, features: Sequence[float]) -> int | None:
    """Read-only prototype assignment. ``None`` is a valid answer (UNKNOWN).

    Deliberately not ``quantize_behaviour_atom``: that call learns, and a probe
    must not learn. An empty lattice yields ``None``, which the cone expander is
    expected to treat as "no atom", not as atom 0.
    """
    best: int | None = None
    best_distance = math.inf
    for atom in quantizer.atoms():
        distance = atom.distance(features)
        if distance < best_distance:
            best_distance = distance
            best = atom.atom_id
    return best


def _target_signature(window: Any, step: EncodedTransition, index: int) -> str:
    """A deterministic locator for the probed transition.

    ``EncodedTransition`` carries no causal signature, so the probe names its
    target by lineage and position. The authoritative signature reaches the
    credit ledger on the ``CausalNode``; this string is provenance for the probe
    itself, never an identity the ledger trusts.
    """
    lineage = getattr(window, "lineage_key", "")
    return f"{lineage}:{index}:r{step.relation}:m{step.state_delta_mask}"


def _default_expander(lattice: Any, quantizer: Any, **kwargs: Any) -> ConeView:
    try:
        from pocketsec.stage2.predictors.future_cone import predict_future_cone
    except ImportError as exc:  # pragma: no cover - depends on D2.8 presence
        raise ContractError(
            "counterfactual_probe needs D2.8 predict_future_cone; "
            "pass cone_expander=... to supply a different future model"
        ) from exc
    return predict_future_cone(lattice, quantizer, **kwargs)


def _record_work(
    ledger: Any,
    *,
    kind: WorkKind = WorkKind.COUNTERFACTUAL,
    performed: bool,
    units: float,
    detail: str,
) -> None:
    """Record one unit of probe work on D2.4's ledger, if one was supplied.

    ``units`` must be ``0.0`` whenever ``performed`` is False: ``WorkRecord``
    refuses anything else, because "units I avoided" is the exact shape of a
    phantom saving (ADR-0114 rule 3). An earlier version of this module recorded
    the *intended* cost on the budget-refusal path, which made that path raise
    ``ContractError`` against a real ledger and left the safety branch
    unreachable (S2-01).
    """
    if ledger is None:
        return
    ledger.record(kind, performed=performed, units=units, detail=detail)


# --- probes ------------------------------------------------------------------


def counterfactual_probe(
    window: LineageWindow,
    quantizer: Any,
    lattice: Any,
    *,
    target_index: int,
    intervention: Intervention = Intervention.MASK,
    ledger: Any | None = None,
    budget: ProbeBudget | None = None,
    cone_expander: ConeExpander | None = None,
) -> CounterfactualProbe:
    """DTL-F11. Responsibility as divergence between predicted futures.

    The live ``quantizer`` and ``lattice`` are wrapped read-only for the whole
    call; the probe reads prototypes and transition statistics and writes
    nothing. See the module docstring for why that is not negotiable.
    """
    steps = _window_steps(window, target_index)
    target = steps[target_index]
    signature = _target_signature(window, target, target_index)
    expand = cone_expander or _default_expander
    guarded_quantizer = ReadOnlyGuard(quantizer, readable=QUANTIZER_READS)
    guarded_lattice = ReadOnlyGuard(lattice, readable=LATTICE_READS)

    end = min(len(steps), target_index + MAX_PROBE_DEPTH)
    truncated = end < len(steps)
    prefix_state = _fold_state(steps[:target_index])
    observed_suffix = steps[target_index:end]
    observed_cone = _expand(
        expand, guarded_lattice, guarded_quantizer, observed_suffix, prefix_state
    )
    # Charged before the budget is consulted because it was spent before the
    # budget was consulted. Recording it inside the granted branch alone would
    # let a refused probe report that work which genuinely ran did not run.
    _record_work(
        ledger,
        kind=WorkKind.CONE_EXPANSION,
        performed=True,
        units=CONE_EXPANSION_UNITS,
        detail=f"observed:{signature}",
    )

    if budget is not None and not budget.try_spend():
        # No COUNTERFACTUAL record is written here, and that is deliberate.
        #
        # The old code wrote `performed=False, units=PROBE_COST_UNITS`, which
        # `WorkRecord.__post_init__` refuses outright (ADR-0114 rule 3), so this
        # branch raised instead of returning and the safety path was unreachable
        # against a real ledger (S2-01). The obvious repair — `units=0.0` — is
        # also wrong here: `MAX_PROBES_PER_EVENT` is 4, so an ordinary event
        # performs some counterfactuals and refuses others, and a skipped
        # COUNTERFACTUAL beside a performed one is exactly the contradiction
        # `assert_no_phantom_savings()` raises on. An honest caller must not be
        # able to trip that assertion.
        #
        # So the ledger records work, and a probe that did not run is not work.
        # Nothing is claimed as skipped, so nothing here can become a phantom
        # saving. The refusal itself is reported where the credit ledger reads
        # it: `budget_exhausted` and `PROBE_REFUSED_EVIDENCE` on the probe.
        return _refused_probe(signature, intervention, observed_cone, target)

    counterfactual_suffix, markers = _intervene(observed_suffix, intervention)
    counterfactual_cone = _expand(
        expand, guarded_lattice, guarded_quantizer, counterfactual_suffix, prefix_state
    )
    _record_work(
        ledger,
        performed=True,
        units=PROBE_COST_UNITS,
        detail=f"{intervention.value}:{signature}",
    )
    return _measured_probe(
        signature,
        intervention,
        observed_cone,
        counterfactual_cone,
        evidence=(*target.evidence, *markers),
        truncated=truncated,
    )


def _window_steps(window: Any, target_index: int) -> tuple[EncodedTransition, ...]:
    steps = tuple(window.steps)
    if not steps:
        raise ContractError("a probe needs a non-empty lineage window")
    if not 0 <= target_index < len(steps):
        raise ContractError(
            f"target_index {target_index} outside window of {len(steps)} steps"
        )
    return steps


def _refused_probe(
    signature: str,
    intervention: Intervention,
    observed_cone: ConeView,
    target: EncodedTransition,
) -> CounterfactualProbe:
    """A probe the budget refused: both sides are the observed future.

    The divergence is therefore a genuine 0.0 for a comparison that never ran,
    and ``PROBE_REFUSED_EVIDENCE`` is what stops the credit ledger reading that
    zero as a measurement.
    """
    return CounterfactualProbe(
        target_signature=signature,
        intervention=intervention,
        observed_cone=observed_cone,
        counterfactual_cone=observed_cone,
        divergence=0.0,
        delta_phi_shift=0.0,
        budget_exhausted=True,
        evidence=(*target.evidence, PROBE_REFUSED_EVIDENCE),
    )


def _measured_probe(
    signature: str,
    intervention: Intervention,
    observed_cone: ConeView,
    counterfactual_cone: ConeView,
    *,
    evidence: tuple[str, ...],
    truncated: bool,
) -> CounterfactualProbe:
    if truncated:
        evidence = (*evidence, PROBE_TRUNCATED_EVIDENCE)
    return CounterfactualProbe(
        target_signature=signature,
        intervention=intervention,
        observed_cone=observed_cone,
        counterfactual_cone=counterfactual_cone,
        divergence=jensen_shannon(
            label_distribution(observed_cone), label_distribution(counterfactual_cone)
        ),
        delta_phi_shift=expected_delta_phi(counterfactual_cone)
        - expected_delta_phi(observed_cone),
        budget_exhausted=truncated,
        evidence=evidence,
    )


def _expand(
    expand: ConeExpander,
    lattice: Any,
    quantizer: Any,
    suffix: tuple[EncodedTransition, ...],
    prefix_state: SecurityStateV1,
) -> ConeView:
    """Expand the future implied by one replay, read-only.

    An empty replay, or a quantizer with no prototype to anchor on, has no
    predicted future at all. That is reported as a fully unresolved cone rather
    than by handing ``None`` to the cone model as if it were atom 0.
    """
    if not suffix:
        return PhiCone(branches=(), unresolved_mass=1.0, depth=0, truncated=False)
    from_atom = _nearest_atom(quantizer, suffix[-1].features)
    if from_atom is None:
        return PhiCone(branches=(), unresolved_mass=1.0, depth=len(suffix), truncated=False)
    return expand(
        lattice,
        quantizer,
        from_atom=from_atom,
        state=_fold_state(suffix, base=prefix_state),
        epoch_id=suffix[-1].epoch_id,
    )


def phi_only_probe(
    window: LineageWindow, *, target_index: int
) -> CounterfactualProbe:
    """THE SIMPLE CONTROL: replay without the transition, score with ΔΦ alone.

    Zero parameters, no lattice, no atoms, no cone model — only the ΔΦ Stage 1
    already computed for each transition. Stage 1's Φ-oracle reaches 0.7484
    PR-AUC with zero parameters, so this control is a serious candidate to beat
    the model-based twin outright, and the comparison is reported either way.
    """
    steps = _window_steps(window, target_index)
    end = min(len(steps), target_index + MAX_PROBE_DEPTH)
    truncated = end < len(steps)
    observed = steps[target_index:end]
    return _measured_probe(
        _target_signature(window, steps[target_index], target_index),
        Intervention.MASK,
        _phi_cone(observed, truncated=truncated),
        _phi_cone(observed[1:], truncated=truncated),
        evidence=steps[target_index].evidence,
        truncated=truncated,
    )


def _phi_cone(
    steps: tuple[EncodedTransition, ...], *, truncated: bool
) -> PhiCone:
    """Escalating vs receding vs unknown, weighted by ΔΦ *magnitude*.

    The prior scale keeps the unknown branch honest: a lineage that has moved Φ
    very little is mostly unknown, and confidence is earned only by observed
    movement. It also makes the control magnitude-sensitive — normalising rising
    against falling alone would report an identical future whether a lineage
    gained 0.5 or 50.0 of potential, which would make the Φ-only control blind
    to exactly the transitions it exists to attribute.
    """
    rising = sum(step.delta_phi for step in steps if step.delta_phi > 0.0)
    falling = sum(-step.delta_phi for step in steps if step.delta_phi < 0.0)
    total = rising + falling + PHI_PRIOR_SCALE
    return PhiCone(
        branches=(
            PhiBranch("phi_escalating", rising / total, rising),
            PhiBranch("phi_receding", falling / total, -falling),
        ),
        unresolved_mass=PHI_PRIOR_SCALE / total,
        depth=len(steps),
        truncated=truncated,
    )


def probe_event(
    window: LineageWindow,
    quantizer: Any,
    lattice: Any,
    *,
    target_indices: Sequence[int],
    event_key: str = "",
    intervention: Intervention = Intervention.MASK,
    ledger: Any | None = None,
    budget: ProbeBudget | None = None,
    cone_expander: ConeExpander | None = None,
) -> tuple[CounterfactualProbe, ...]:
    """Probe several transitions under one event budget.

    This is the unit ``MAX_PROBES_PER_EVENT`` actually bounds: probing is driven
    by an arriving event, and the cap only means something if something counts
    probes across the targets that event proposed.
    """
    probe_budget = budget or ProbeBudget()
    probe_budget.begin_event(event_key)
    return tuple(
        counterfactual_probe(
            window,
            quantizer,
            lattice,
            target_index=index,
            intervention=intervention,
            ledger=ledger,
            budget=probe_budget,
            cone_expander=cone_expander,
        )
        for index in target_indices
    )
