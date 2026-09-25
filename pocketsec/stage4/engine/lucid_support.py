"""D4.2's arithmetic and bookkeeping, split out so ``engine/lucid.py`` stays the loop.

The spec bounds ``engine/lucid.py`` at 600 lines and the repository bounds every
module at ~800. The LUCID loop plus its unit tables plus its field-surgery helpers
does not fit, so the helpers live here: the work-unit cost tables, the evidence
lineage bookkeeping, the ΔΦ→credit map, the death-cause rule, the cone-derived
fission regimes, and the gap projection. Nothing here holds state and nothing here
raises past its own contract — the guarding is the caller's job.

Three of these carry a defect this module was written to stop repeating, and each
says so where it lives: :func:`bounded_credit` (an unbounded ΔΦ silently refused by
``WorldGraphNode``), :func:`regimes_for` (a fission child that predicted and forbade
the same signal), and :func:`attach_evidence` (a claim graph that was empty for
every incident, which would have made G4.8 pass by producing nothing).
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import replace
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import EvidenceRef
from pocketsec.stage1.observation.policy import MANDATORY_SIGNALS
from pocketsec.stage4.engine.degradation import DegradationLedger
from pocketsec.stage4.graph.entropy_budget import BudgetController, EntropyBudget
from pocketsec.stage4.graph.sparse_world_graph import (
    SparseWorldGraph,
    Truncation,
    append_truncations,
)
from pocketsec.stage4.identifiability.resolution import (
    IdentifiabilityState,
    IdentifiabilityVerdict,
)
from pocketsec.stage4.stage5_interface import InformationGap
from pocketsec.stage4.visibility.model import signals_of_transition
from pocketsec.stage4.tension.evidence_tension import (
    TENSION_DEATH_THRESHOLD,
    TENSION_SUSTAIN_STEPS,
    EvidenceTension,
)
from pocketsec.stage4.worlds.lifecycle import DeathCause, EvidenceRegime
from pocketsec.stage4.worlds.tombstone import TombstoneLedger
from pocketsec.stage4.worlds.world import SecurityWorldV1

__all__ = [
    "BUDGET_KIND_FOR",
    "INERT_FLAGS",
    "IncidentState",
    "MAX_FIELD_EVIDENCE_REFS",
    "MAX_SHADOW_EVIDENCE_TRANSITIONS",
    "MAX_WORLD_EVIDENCE_REFS",
    "WORK_UNITS",
    "attach_evidence",
    "bounded_credit",
    "death_cause",
    "gaps_from",
    "regimes_for",
    "retain_evidence",
    "retain_shadow_evidence",
    "uncertainty_of",
    "unknown_verdict",
    "with_truncations",
]

#: Deterministic cost of each loop step, in reasoning units, charged per *item*
#: the step considers (per world, per pair, per spine node) so a bigger field
#: costs more — the property the bound exists to constrain. Deterministic because
#: §2.8 forbids a wall-clock bound on this contended host: a Stage 2 gate read the
#: same two passes as 7x slower at load 23-67 than at load 8-12, so an ablation
#: priced in milliseconds would measure the host.
WORK_UNITS: Mapping[str, int] = MappingProxyType(
    {
        "integrate": 1,
        "visibility": 2,
        "tension": 3,
        "kill": 1,
        "fission_fusion": 2,
        "spawn": 2,
        "prune": 1,
        "sequential_evidence": 2,
        "active_sensing": 4,
        "free_energy": 3,
        "counterfactual": 5,
        "self_questioning": 4,
        "stress": 4,
        "cell_feedback": 2,
        "verbalizer": 2,
        "identifiability": 2,
        "claims": 3,
    }
)

#: Which ``BUDGET_KINDS`` bucket each step charges. ``graph/entropy_budget.py``
#: owns a closed vocabulary — correctly, since a typo there makes a spend report
#: unreadable — so the engine maps onto it rather than inventing a kind. Three
#: mappings are approximations and are named as such: ``free_energy`` charges
#: ``sensor_plan`` because §18's objective exists to rank observations;
#: ``self_questioning`` and ``stress`` charge ``counterfactual`` because D4.11 is
#: built on the intervention machinery and shares its §29 cap; ``cell_feedback``
#: charges ``claim_compile`` because it reads the compiled graph and nothing else.
BUDGET_KIND_FOR: Mapping[str, str] = MappingProxyType(
    {
        "integrate": "evidence_integration",
        "visibility": "visibility_update",
        "tension": "tension",
        "kill": "world_death",
        "fission_fusion": "fission",
        "spawn": "world_birth",
        "prune": "dominance_pruning",
        "sequential_evidence": "sequential_evidence",
        "active_sensing": "sensor_plan",
        "free_energy": "sensor_plan",
        "counterfactual": "counterfactual",
        "self_questioning": "counterfactual",
        "stress": "counterfactual",
        "cell_feedback": "claim_compile",
        "verbalizer": "verbalizer",
        "identifiability": "identifiability",
        "claims": "claim_compile",
    }
)

#: Flags whose mechanism cannot reach the verdict, the world set or the claims BY
#: CONSTRUCTION, with the reason. An ablation of one of these can only ever measure
#: 0.0, whatever the corpus, so reporting it as "NOT_YET_JUSTIFIED — get a better
#: corpus" would misattribute a structural zero to the data (S4-FC-08). Wiring one
#: into belief or verdict is how it leaves this table.
INERT_FLAGS: Mapping[str, str] = MappingProxyType(
    {
        "enable_free_energy": "adds work units; the §18 term is reported, never read",
        "enable_sequential_evidence": "writes IncidentState.sequential, which nothing reads",
        "enable_verbalizer": "runs the guard with verbalizer=None and discards the result",
        "enable_counterfactual": "calculate_responsibility_flux's result is discarded",
        "enable_self_questioning": "self_question_world's result is discarded",
        "enable_stress": "adds work units and calls nothing",
        "enable_cell_feedback": "adds work units and calls nothing",
    }
)


#: Evidence references the field retains for the Stage 5 lineage, and the smaller
#: number one world carries. The world bound is tighter because ``MAX_WORLD_BYTES``
#: is 8192 and a reference costs ~100 bytes serialised, so overflowing it makes the
#: world unconstructable rather than merely large. Both overflows record a
#: ``Truncation``: the digests stay in the field even when a world sheds them.
MAX_FIELD_EVIDENCE_REFS: int = 64
MAX_WORLD_EVIDENCE_REFS: int = 8

#: Stage 1 ``observation_incomplete`` transitions an incident keeps for the shadow.
#: Only transitions that contribute a signal the shadow has not yet seen are kept at
#: all (see :func:`retain_shadow_evidence`), so the practical bound is the closed
#: signal vocabulary; this cap is the hard one behind it, and hitting it records a
#: ``Truncation``. It replaces an unbounded ``list`` of every transition the incident
#: ever saw, which the visibility step rescanned on every update — per-update cost
#: grew linearly and memory without limit (S4-REV-01, S4-SEC-01, S4-RES-01).
MAX_SHADOW_EVIDENCE_TRANSITIONS: int = 64


def with_truncations(field: Any, items: Sequence[Truncation]) -> Any:
    """Append losses to a field, deduplicated and bounded. Always recorded.

    Routed through :func:`append_truncations` so the log grows with *distinct
    losses*, not with transitions: an unchanged spine re-reported the same refused
    edges on every step and the log reached 13895 records over one long incident (the
    review's measurement on the pre-fix code, cited rather than re-run here).
    """
    if not items:
        return field
    return replace(field, truncations=append_truncations(field.truncations, items))


def retain_shadow_evidence(state: Any, transition: Any) -> tuple[Truncation, ...]:
    """Keep ``transition`` for the shadow only if it can change the shadow.

    ``sensor_shadow._incomplete_regions`` reads only ``observation_incomplete``
    transitions and keeps the **first** transition per non-mandatory signal, so a
    transition that brings no new such signal cannot change its output. Keeping
    only the ones that do gives the identical shadow from a set bounded by the
    signal vocabulary — the same answer, without holding the incident's history.
    """
    if not transition.observation_incomplete:
        return ()
    fresh = {
        signal
        for signal in signals_of_transition(transition)
        if signal not in MANDATORY_SIGNALS and signal not in state.shadow_signals
    }
    if not fresh:
        return ()
    if len(state.shadow_evidence) >= MAX_SHADOW_EVIDENCE_TRANSITIONS:
        return tuple(
            Truncation(
                what="shadow_region",
                identifier=signal,
                reason=f"max_shadow_evidence_transitions:{MAX_SHADOW_EVIDENCE_TRANSITIONS}",
                consequence_lost=0.0,
            )
            for signal in sorted(fresh)
        )
    state.shadow_signals |= fresh
    state.shadow_evidence.append(transition)
    return ()


def retain_evidence(
    field: Any, refs: Sequence[EvidenceRef]
) -> tuple[Any, tuple[Truncation, ...]]:
    """Add a transition's evidence to the incident lineage, within the bound.

    Deduplicated by digest: one raw event can back several transitions, and a
    lineage that counted it twice would overstate how much independent evidence
    the incident rests on.
    """
    seen = {ref.digest for ref in field.evidence_refs}
    kept = list(field.evidence_refs)
    losses: list[Truncation] = []
    for ref in refs:
        if ref.digest in seen:
            continue
        if len(kept) >= MAX_FIELD_EVIDENCE_REFS:
            losses.append(
                Truncation(
                    what="claim",
                    identifier=ref.digest,
                    reason=f"max_field_evidence_refs:{MAX_FIELD_EVIDENCE_REFS}",
                    consequence_lost=0.0,
                )
            )
            continue
        seen.add(ref.digest)
        kept.append(ref)
    if len(kept) == len(field.evidence_refs) and not losses:
        return field, ()
    return replace(field, evidence_refs=tuple(kept)), tuple(losses)


def attach_evidence(field: Any, world_id: str, refs: Sequence[EvidenceRef]) -> Any:
    """Give a newborn world the evidence its residual came from.

    Without this the world has no ``evidence_refs``, the claim compiler emits no
    ``ObservedClaim``, and every incident's authoritative output is empty — so
    G4.8 would pass by producing nothing. A criterion that cannot fail is not a
    criterion (the Stage 2 lesson), so the world born from a transition cites that
    transition's evidence.
    """
    world = field.world(world_id)
    if world is None or not refs:
        return field
    updated = replace(world, evidence_refs=tuple(refs)[:MAX_WORLD_EVIDENCE_REFS])
    return field.with_worlds(
        tuple(updated if item.world_id == world_id else item for item in field.worlds)
    )


def bounded_credit(delta_phi: float) -> float:
    """Map ΔΦ onto [0, 1] monotonically for ``WorldGraphNode.causal_credit``.

    ``x / (1 + x)`` rather than a clamp: ΔΦ is unbounded above (Stage 1's measured
    benign/malicious separation is 0.62 / 9.46) and a clamp would make every
    consequential node indistinguishable at exactly the end of the range where
    retention decisions are made. **A bounded rank, not a probability** — reading
    it as one would be the ``BeliefGeometry`` mistake §11 exists to prevent.
    """
    value = max(0.0, float(delta_phi))
    return value / (1.0 + value)


def death_cause(tension: EvidenceTension | None) -> DeathCause | None:
    """Which §13 cause, if any, this world's tension has established.

    A hard contradiction kills at once; ordinary tension must be *sustained* for
    ``TENSION_SUSTAIN_STEPS``, because one surprising transition is how a true
    world looks at the moment the attack turns.
    """
    if tension is None:
        return None
    if tension.hard_contradictions:
        return DeathCause.HARD_CONTRADICTION
    sustained = tension.sustained_steps >= TENSION_SUSTAIN_STEPS
    if sustained and tension.total >= TENSION_DEATH_THRESHOLD:
        return DeathCause.SUSTAINED_TENSION
    return None


def regimes_for(world: SecurityWorldV1) -> tuple[EvidenceRegime, EvidenceRegime] | None:
    """Two incompatible continuations of one world, taken from its own future cone.

    Drawn from the cone's **branches**, not from the world's already-expected set.
    Splitting the expected set was this module's first attempt and it is
    unconstructable: ``fission_world`` unions the parent's whole expected set into
    each child, so a regime forbidding a signal the parent expects yields a child
    that predicts and forbids the same thing — which ``SecurityWorldV1`` correctly
    refuses as unfalsifiable. The degradation ledger found it, which is the point
    of having one.

    ``None`` whenever the cone offers no genuinely disjoint pair: a fission into
    compatible regimes is one world with a wide prediction wearing two names.
    """
    from pocketsec.stage4.cones.incident_cone import predict_world_future_cone

    cone = predict_world_future_cone(world)
    taken = world.expected_evidence | world.forbidden_evidence
    candidates = [
        (branch.label, frozenset(branch.predicted_signals) - taken, branch.consequence)
        for branch in cone.branches
    ]
    candidates = sorted(
        (row for row in candidates if row[1]), key=lambda row: (-row[2], row[0])
    )
    for index, (left_label, left, left_cost) in enumerate(candidates):
        for right_label, right, right_cost in candidates[index + 1 :]:
            if left & right:
                continue
            return (
                EvidenceRegime(
                    label=f"cone-{left_label}", expected=left, forbidden=right,
                    consequence=left_cost,
                ),
                EvidenceRegime(
                    label=f"cone-{right_label}", expected=right, forbidden=left,
                    consequence=right_cost,
                ),
            )
    return None


def gaps_from(verdict: IdentifiabilityVerdict, plan: Any) -> tuple[InformationGap, ...]:
    """Turn the discriminating observations into questions for Stage 5.

    A gap needs at least two worlds to separate, so a single-survivor field
    produces none: there is nothing to discriminate and inventing a gap would be a
    fabricated recommendation. ``UNIDENTIFIABLE`` also produces none, by
    construction, because its ``discriminating_observations`` is empty — that is
    the difference between "cannot decide" and "have not looked".
    """
    worlds = tuple(
        item
        for item in dict.fromkeys((verdict.leading_world_id, *verdict.material_alternatives))
        if item
    )
    if len(worlds) < 2:
        return ()
    affordable = bool(getattr(plan, "requests", ())) and verdict.affordable
    return tuple(
        InformationGap(
            signal=signal,
            why_it_matters=(
                f"observing {signal} separates {len(worlds)} surviving explanations; "
                f"identifiability is {verdict.state.value}"
            ),
            would_discriminate=worlds,
            affordable=affordable,
        )
        for signal in verdict.discriminating_observations
    )


def uncertainty_of(field: Any) -> float:
    """The leading world's uncertainty, or 1.0 for an empty field.

    An empty field is maximally uncertain rather than certain of nothing; the
    opposite convention would let "no worlds" read as "no doubt".
    """
    if not field.worlds:
        return 1.0
    leaders = field.leaders(n=1)
    return float(leaders[0].uncertainty) if leaders else 1.0


def unknown_verdict(previous: IdentifiabilityVerdict | None) -> IdentifiabilityVerdict:
    """The honest verdict when identifiability itself failed to run.

    ``UNKNOWN``, not ``INSUFFICIENT_EVIDENCE``: the evidence may have been
    sufficient and it is the *reasoning* that did not complete. Conflating the two
    would misreport a crash as a gap in telemetry. An already-abstaining verdict is
    returned unchanged, because ``UNIDENTIFIABLE`` is an answer.
    """
    if previous is not None and previous.abstains():
        return previous
    return IdentifiabilityVerdict(
        state=IdentifiabilityState.UNKNOWN,
        leading_world_id=None,
        support_margin=0.0,
        material_alternatives=(),
        discriminating_observations=(),
        affordable=False,
        shadow_penalty=0.0,
        detail="identifiability subsystem degraded; no world was ranked",
    )


class IncidentState:
    """Per-incident reasoning state. Bounded, and dropped by ``close_incident``.

    Public because the loop (``engine/lucid.py``) and the steps
    (``engine/lucid_steps.py``) both thread it, and a shared mutable owned by
    neither would be worse than a named type owned by both.
    """

    __slots__ = (
        "budget",
        "graph",
        "last_signals",
        "ledger",
        "observed",
        "pending_escalations",
        "refused_updates",
        "residual",
        "resolutions",
        "sequential",
        "shadow_evidence",
        "shadow_signals",
        "tension",
        "tombstones",
        "transition_count",
    )

    def __init__(self, budget: EntropyBudget) -> None:
        self.budget = BudgetController(budget=budget)
        self.graph = SparseWorldGraph()
        # This incident's own failures. The engine's ledger is the roll-up; a
        # verdict is downgraded, and a Stage 5 export lists degradations, from THIS
        # ledger only. One engine-lifetime ledger made a single fault in incident 0
        # downgrade and mis-attribute every later incident (S4-REV-06 / S4-FC-09).
        self.ledger = DegradationLedger()
        self.observed: set[str] = set()
        # The previous transition's residual, carried because ``Residual``
        # accumulates persistence: ``MIN_RESIDUAL_FOR_BIRTH`` plus
        # ``RESIDUAL_PERSISTENCE_STEPS`` is a two-step gate, so an engine that
        # recomputed the residual from scratch each transition would pin
        # ``persistent_steps`` at 1 and **no world could ever be born**. That was a
        # real defect in this package's first draft, found by the degradation
        # ledger rather than by reading the code.
        self.residual: Any = None
        self.resolutions: list[str] = []
        self.sequential: dict[str, Any] = {}
        # The CURRENT transition's signals. The e-process multiplies in one
        # likelihood ratio per transition over that transition's own observation;
        # re-applying the incident's cumulative set every transition counted the same
        # evidence N times while the accumulator claimed anytime validity (S4-REV-02).
        self.last_signals: frozenset[str] = frozenset()
        # Escalations Stage 1's AOP granted during the current update, charged to
        # the §29 budget and the §20 horizon by the engine after the steps run.
        self.pending_escalations = 0
        # Transitions that arrived after the horizon closed. Non-zero means the
        # verdict was reached without reading them, so it cannot stay committal.
        self.refused_updates = 0
        # Only shadow-changing observation_incomplete transitions, bounded by
        # MAX_SHADOW_EVIDENCE_TRANSITIONS; the rest of the history is not held.
        self.shadow_evidence: list[Any] = []
        self.shadow_signals: set[str] = set()
        self.tension: dict[str, EvidenceTension] = {}
        self.tombstones = TombstoneLedger()
        self.transition_count = 0

    def memory_bytes(self) -> int:
        """Bytes this incident's reasoning state holds, for the resource budget.

        Counts what the old accounting left out — the retained shadow evidence — so
        the report can no longer stay flat while real state grows.
        """
        total = self.graph.memory_bytes() + self.tombstones.memory_bytes()
        total += self.ledger.memory_bytes()
        total += 64 * (
            len(self.observed)
            + len(self.tension)
            + len(self.sequential)
            + len(self.shadow_signals)
        )
        total += sum(_transition_bytes(item) for item in self.shadow_evidence)
        return total


def _transition_bytes(transition: Any) -> int:
    """Serialised size of one retained transition. Measured, not a constant."""
    to_dict = getattr(transition, "to_dict", None)
    if not callable(to_dict):
        return 1024
    return len(json.dumps(to_dict(), sort_keys=True, default=str))
