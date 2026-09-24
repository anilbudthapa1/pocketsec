"""DTL-F18 — ``detect_epoch_mismatch``, and the drift measurement around it.

Normal behaviour changes after a legitimate system change, so a Behaviour Atom
learned before an ``apt upgrade`` may simply no longer describe the host. Stage 1
solved the dangerous half of this problem and Stage 2 must not undo it:

> Epoch changes require corroborating system-change evidence and cannot be
> triggered solely by behavioural novelty. (``stage1/epoch/model.py``)

An attacker who can mint an epoch by acting strange gets a fresh baseline in which
their behaviour is normal. This module therefore **reads** Stage 1's
``EpochDecision`` and never forms an opinion of its own: there is no code path here
from novelty, ΔΦ, surprise, or atom distance to "the regime changed". The only
question it answers is whether an atom's own epoch accounting covers the epoch the
host is currently in, and whether an *independently corroborated* change explains
the difference.

The rest of the module measures what adaptation actually costs and what it
actually refuses, through the real pipeline:

* ``run_adaptation`` drives a corpus through Stage 1, the quarantine and the
  promotion gate, under one of three policies. Two of those policies are the
  controls — **accept everything** and **accept nothing** — because a quarantine
  that is never compared against them is an assertion rather than a measurement.
  Accept-everything shows what gets normalised without a gate; accept-nothing shows
  that refusing everything is safe *and useless*, which is the only way a
  measured improvement from the real gate means anything.
* ``drift_report`` reduces a run to the four numbers acceptance criterion 8 asks
  for. ``transitions_to_recover`` is ``int | None`` and is **None** when recovery
  did not happen inside the corpus. Not a large number, not a sentinel: unmeasured
  is not measured.

Stdlib only.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pocketsec.stage1.epoch.model import Epoch, EpochDecision, EpochModel, SystemIdentity
from pocketsec.stage1.labs.corpus import Scenario
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage1.ssir.transition import SSIRTransitionV1
from pocketsec.stage1.state.security_state import DIMENSIONS, SecurityStateV1
from pocketsec.stage2.adaptation.promotion import (
    PromotionController,
    PromotionRecord,
    TrustedLattice,
    TrustedQuantizer,
)
from pocketsec.stage2.adaptation.quarantine import (
    ESCALATION_MASK,
    AdaptationSample,
    QuarantineBuffer,
    QuarantineOutcome,
)
from pocketsec.stage2.encoder.ssir_encoder import encode_ssir_transition

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pocketsec.stage2.lattice.atom import BehaviourAtom

__all__ = [
    "AdaptationPolicy",
    "AdaptationRun",
    "DriftReport",
    "EpochMismatch",
    "SystemChangeSignal",
    "detect_epoch_mismatch",
    "drift_report",
    "run_adaptation",
]


@dataclass(frozen=True, slots=True)
class EpochMismatch:
    """Whether an atom still describes the epoch the host is in."""

    atom_id: int
    current_epoch: int
    valid_epochs: frozenset[int]
    mismatch: bool
    #: True only when Stage 1 recorded a corroborated change *into this epoch*.
    #: Behavioural novelty can never set this, which is the whole mechanism.
    corroborated_system_change: bool
    detail: str

    @property
    def may_invalidate(self) -> bool:
        """An atom may be invalidated only by a corroborated system change.

        Without this, an attacker who makes an atom look stale — by behaving
        oddly enough that the current epoch stops matching — could force the
        system to discard learned structure at will, which is denial of service
        against the machine's own memory.
        """
        return self.mismatch and self.corroborated_system_change

    def to_dict(self) -> dict[str, Any]:
        return {
            "atom_id": self.atom_id,
            "current_epoch": self.current_epoch,
            "valid_epochs": sorted(self.valid_epochs),
            "mismatch": self.mismatch,
            "corroborated_system_change": self.corroborated_system_change,
            "may_invalidate": self.may_invalidate,
            "detail": self.detail,
        }


def detect_epoch_mismatch(
    atom: BehaviourAtom, *, epoch: Epoch, decision: EpochDecision | None
) -> EpochMismatch:
    """DTL-F18. Compare an atom's epoch accounting against the current epoch.

    ``decision`` is Stage 1's verdict on the most recent candidate epoch change.
    It is read for two fields only — ``corroborated`` and ``changed_components`` —
    and it must name *this* epoch: a corroboration for an earlier epoch is a stale
    receipt, and replaying one would be a way to buy invalidation cheaply.

    The atom's validity comes from the atom's own ``epoch_valid``; nothing here
    infers a regime change from behaviour.
    """
    current = epoch.epoch_id
    valid_epochs = frozenset(atom.epoch_counts)
    mismatch = not atom.epoch_valid(current)
    corroborated = (
        decision is not None
        and decision.corroborated
        and bool(decision.changed_components)
        and decision.epoch_id == current
    )

    if not mismatch:
        detail = f"atom {atom.atom_id} was observed in epoch {current}"
    elif corroborated:
        detail = (
            f"atom {atom.atom_id} is valid in {sorted(valid_epochs)} but the host is "
            f"in epoch {current}, opened by a corroborated change in "
            f"{sorted(decision.changed_components) if decision else []}"
        )
    else:
        detail = (
            f"atom {atom.atom_id} is valid in {sorted(valid_epochs)} and the host is "
            f"in epoch {current} with no corroborated system change; the atom stays "
            "valid. Behavioural novelty alone never invalidates learned structure."
        )
    return EpochMismatch(
        atom_id=atom.atom_id,
        current_epoch=current,
        valid_epochs=valid_epochs,
        mismatch=mismatch,
        corroborated_system_change=corroborated,
        detail=detail,
    )


@dataclass(frozen=True, slots=True)
class DriftReport:
    """Acceptance criterion 8, as four measured numbers."""

    #: Transitions between the MOST RECENT corroborated change and the first
    #: trusted atom that is epoch-valid in the new epoch — that is, how long the
    #: host went without a trusted pattern describing its current regime.
    #: ``None`` when recovery did not happen inside the corpus, or when no
    #: corroborated change happened at all: never a guess, and never a large
    #: number standing in for "did not happen".
    transitions_to_recover: int | None
    #: Trusted atoms the most recent corroborated change invalidated. Counted at
    #: the change, and only where ``EpochMismatch.may_invalidate`` holds.
    atoms_invalidated: int
    #: Of those, how many were promoted again afterwards — structure the change
    #: did not destroy.
    atoms_reused_after_change: int
    #: Promotions carrying escalating meaning: a credential / authorisation /
    #: persistence / external object, or a raised security capability. MUST be 0.
    malicious_patterns_normalised: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "transitions_to_recover": self.transitions_to_recover,
            "atoms_invalidated": self.atoms_invalidated,
            "atoms_reused_after_change": self.atoms_reused_after_change,
            "malicious_patterns_normalised": self.malicious_patterns_normalised,
        }


class AdaptationPolicy(StrEnum):
    """The real gate and its two controls."""

    QUARANTINED = "QUARANTINED"
    #: No gate at all: every sample rewrites trusted state. The control that shows
    #: what the gate is worth, by showing what happens without it.
    ACCEPT_EVERYTHING = "ACCEPT_EVERYTHING"
    #: Refuse every promotion. Safe, and useless: nothing is ever normalised and
    #: nothing ever recovers. Without this control, "malicious_patterns_normalised
    #: == 0" would be satisfied by doing nothing.
    ACCEPT_NOTHING = "ACCEPT_NOTHING"


@dataclass(frozen=True, slots=True)
class SystemChangeSignal:
    """An out-of-band system change, as an independent source would report it.

    ``changed`` is what the host looks like now; ``corroborated`` is what a
    package-manager transaction, a kernel boot record or a config-management run
    actually confirms. They are separate fields because the interesting case is a
    change with no corroboration, which must be refused.
    """

    changed: frozenset[str]
    corroborated: frozenset[str]


@dataclass(frozen=True, slots=True)
class AdaptationRun:
    """Everything one pass over a corpus measured. Counts only, no claims."""

    policy: AdaptationPolicy
    scenarios: int
    samples: int
    escalating_samples: int
    outcomes: dict[str, int]
    promotions: int
    escalating_promotions: int
    attack_lineage_promotions: int
    promoted_keys: tuple[str, ...]
    epoch_decisions: tuple[dict[str, Any], ...]
    final_epoch: int
    samples_after_change: int | None
    transitions_to_recover: int | None
    atoms_invalidated: int
    atoms_invalidated_total: int
    atoms_reused_after_change: int
    quarantine: dict[str, Any]
    promotion: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy.value,
            "scenarios": self.scenarios,
            "samples": self.samples,
            "escalating_samples": self.escalating_samples,
            "outcomes": dict(self.outcomes),
            "promotions": self.promotions,
            "escalating_promotions": self.escalating_promotions,
            "attack_lineage_promotions": self.attack_lineage_promotions,
            "promoted_keys": list(self.promoted_keys),
            "epoch_decisions": list(self.epoch_decisions),
            "final_epoch": self.final_epoch,
            "samples_after_change": self.samples_after_change,
            "transitions_to_recover": self.transitions_to_recover,
            "atoms_invalidated": self.atoms_invalidated,
            "atoms_invalidated_total": self.atoms_invalidated_total,
            "atoms_reused_after_change": self.atoms_reused_after_change,
            "quarantine": self.quarantine,
            "promotion": self.promotion,
        }


def drift_report(run: AdaptationRun) -> DriftReport:
    """Reduce a run to acceptance criterion 8's four numbers."""
    return DriftReport(
        transitions_to_recover=run.transitions_to_recover,
        atoms_invalidated=run.atoms_invalidated,
        atoms_reused_after_change=run.atoms_reused_after_change,
        malicious_patterns_normalised=run.escalating_promotions,
    )


@dataclass
class _RunState:
    """Mutable bookkeeping for one pass. Nothing here influences a decision."""

    counter: int = 0
    escalating_samples: int = 0
    promotions: int = 0
    escalating_promotions: int = 0
    attack_lineage_promotions: int = 0
    atoms_invalidated: int = 0
    invalidated_total: int = 0
    atoms_reused: int = 0
    change_at: int | None = None
    recovered_at: int | None = None
    trusted_before_change: frozenset[int] = frozenset()
    reused_atoms: set[int] = field(default_factory=set)
    outcomes: dict[str, int] = field(default_factory=dict)
    promoted_keys: list[str] = field(default_factory=list)
    decisions: list[dict[str, Any]] = field(default_factory=list)


def _escalating(sample: AdaptationSample) -> bool:
    """Does this sample carry security consequence?

    The same rule the quarantine's risk check uses, restated here for accounting.
    Stage 1 refuses to *aggregate* a capability-raising transition; Stage 2 refuses
    to *learn from* one. Both refusals follow from the same fact: a transition that
    moved the security state is information about an event, not a description of
    normality.
    """
    return bool(sample.encoded.object_property_mask & ESCALATION_MASK) or bool(
        sample.encoded.state_delta_mask
    )


def _lineage_states(
    transitions: Sequence[SSIRTransitionV1],
) -> Iterator[tuple[SSIRTransitionV1, SecurityStateV1]]:
    """Replay each lineage's state exactly, from its own raised dimensions.

    Stage 1's state is monotone within a lineage, so applying each transition's
    ``raised`` dimensions in order reconstructs the state at that transition
    rather than the scenario's final state — which would attribute capability the
    lineage did not yet hold.
    """
    states: dict[str, SecurityStateV1] = {}
    for transition in transitions:
        identity = transition.actor.identity
        state = states.get(identity, SecurityStateV1())
        for dimension, (_before, after) in transition.state_delta.raised.items():
            state = state.raised_to(dimension, DIMENSIONS[dimension](after))
        states[identity] = state
        yield transition, state


def _apply_signal(
    model: EpochModel, signal: SystemChangeSignal, *, now_ns: int
) -> EpochDecision:
    """Offer Stage 1 a candidate system change and take its answer."""
    current = model.current.identity
    observed = SystemIdentity(
        **{
            name: (f"{getattr(current, name)}+{model.epoch_id + 1}" if name in signal.changed
                   else getattr(current, name))
            for name in current.to_dict()
        }
    )
    # behavioural_novelty is passed at its floor on purpose: this harness has no
    # route by which behaviour could influence an epoch, and the parameter exists
    # so that absence is visible rather than implied.
    return model.evaluate(
        observed_identity=observed,
        corroborating_evidence=signal.corroborated,
        now_ns=now_ns,
        behavioural_novelty=0.0,
    )


def _count_invalidations(
    controller: PromotionController,
    quantizer: TrustedQuantizer,
    epoch: Epoch,
    decision: EpochDecision,
) -> int:
    """How many trusted atoms the corroborated change invalidated (DTL-F18)."""
    invalidated = 0
    for atom_id in controller.trusted_atom_ids():
        atom = quantizer.get(atom_id)
        if atom is None:
            continue
        if detect_epoch_mismatch(atom, epoch=epoch, decision=decision).may_invalidate:
            invalidated += 1
    return invalidated


def run_adaptation(
    scenarios: Sequence[Scenario],
    *,
    quantizer: TrustedQuantizer,
    epoch_signals: Mapping[str, SystemChangeSignal],
    lattice: TrustedLattice | None = None,
    policy: AdaptationPolicy = AdaptationPolicy.QUARANTINED,
    buffer: QuarantineBuffer | None = None,
    controller: PromotionController | None = None,
    attack_lineage: Callable[[Scenario], str | None] | None = None,
    identity: SystemIdentity | None = None,
) -> AdaptationRun:
    """Drive a corpus through Stage 1, the quarantine and the promotion gate.

    ``epoch_signals`` maps a scenario's ``technique`` to the out-of-band system
    change that accompanies it. The corpus says *when* a change happened; this
    harness says what a change *is*; neither lets behaviour open an epoch.

    ``attack_lineage`` is the corpus's own ground truth, used for accounting after
    the fact and never consulted by a decision. ``AdaptationSample`` carries no
    label precisely so that this cannot be cheated.
    """
    pipeline = Stage1Pipeline()
    buffer = buffer if buffer is not None else QuarantineBuffer()
    controller = controller if controller is not None else PromotionController()
    model = EpochModel(
        identity=identity
        if identity is not None
        else SystemIdentity(kernel_id="6.1.0", package_digest="pkg-a", service_digest="svc-a")
    )
    state = _RunState()

    for index, scenario in enumerate(scenarios):
        result = pipeline.run_scenario(scenario, offset=index)
        signal = epoch_signals.get(scenario.technique or "")
        decision = (
            None
            if signal is None
            else _offer_system_change(
                signal,
                model=model,
                buffer=buffer,
                controller=controller,
                quantizer=quantizer,
                state=state,
                now_ns=(index + 1) * 1_000_000_000,
            )
        )
        owner = attack_lineage(scenario) if attack_lineage is not None else None
        _run_scenario_samples(
            result.transitions,
            owner=owner,
            epoch=model.current,
            state=state,
            policy=policy,
            buffer=buffer,
            controller=controller,
            quantizer=quantizer,
            lattice=lattice,
            decision=decision,
        )

    return _assemble(
        state,
        policy=policy,
        scenarios=len(scenarios),
        model=model,
        buffer=buffer,
        controller=controller,
    )


def _offer_system_change(
    signal: SystemChangeSignal,
    *,
    model: EpochModel,
    buffer: QuarantineBuffer,
    controller: PromotionController,
    quantizer: TrustedQuantizer,
    state: _RunState,
    now_ns: int,
) -> EpochDecision:
    """Put one candidate system change to Stage 1 and apply whatever it decided."""
    decision = _apply_signal(model, signal, now_ns=now_ns)
    buffer.record_epoch_decision(decision)
    controller.record_epoch_decision(decision)
    state.decisions.append(decision.to_dict())
    if not decision.transitioned:
        return decision
    # Every drift number is relative to the MOST RECENT corroborated change, so
    # the counters reset here. Accumulating across several changes would mix one
    # regime's recovery with another's and can report a recovery that happened
    # before the change it is attributed to — measured as
    # transitions_to_recover=-747 on the first version of this harness.
    state.trusted_before_change = frozenset(controller.trusted_atom_ids())
    state.atoms_invalidated = _count_invalidations(
        controller, quantizer, model.current, decision
    )
    state.invalidated_total += state.atoms_invalidated
    state.change_at = state.counter
    state.recovered_at = None
    state.reused_atoms.clear()
    return decision


def _assemble(
    state: _RunState,
    *,
    policy: AdaptationPolicy,
    scenarios: int,
    model: EpochModel,
    buffer: QuarantineBuffer,
    controller: PromotionController,
) -> AdaptationRun:
    after = None if state.change_at is None else state.counter - state.change_at
    recover = (
        None
        if state.change_at is None or state.recovered_at is None
        else state.recovered_at - state.change_at
    )
    return AdaptationRun(
        policy=policy,
        scenarios=scenarios,
        samples=state.counter,
        escalating_samples=state.escalating_samples,
        outcomes=dict(sorted(state.outcomes.items())),
        promotions=state.promotions,
        escalating_promotions=state.escalating_promotions,
        attack_lineage_promotions=state.attack_lineage_promotions,
        promoted_keys=tuple(sorted(set(state.promoted_keys))),
        epoch_decisions=tuple(state.decisions),
        final_epoch=model.epoch_id,
        samples_after_change=after,
        transitions_to_recover=recover,
        atoms_invalidated=state.atoms_invalidated,
        atoms_invalidated_total=state.invalidated_total,
        atoms_reused_after_change=len(state.reused_atoms),
        quarantine=buffer.stats().to_dict(),
        promotion=controller.stats().to_dict(),
    )


def _run_scenario_samples(
    transitions: Sequence[SSIRTransitionV1],
    *,
    owner: str | None,
    epoch: Epoch,
    state: _RunState,
    policy: AdaptationPolicy,
    buffer: QuarantineBuffer,
    controller: PromotionController,
    quantizer: TrustedQuantizer,
    lattice: TrustedLattice | None,
    decision: EpochDecision | None,
) -> None:
    for transition, lineage_state in _lineage_states(transitions):
        state.counter += 1
        sample = AdaptationSample(
            encoded=encode_ssir_transition(transition),
            state=lineage_state,
            epoch_id=epoch.epoch_id,
            delta_phi=transition.delta_phi,
            uncertainty=transition.uncertainty,
            evidence=tuple(ref.locator for ref in transition.evidence),
            received_at_sequence=state.counter,
            # The causal chain links Stage 1 already computed. Promotion needs
            # them to tell a genuinely observed transition from two unrelated
            # promotions before it writes a lattice edge (S2-AUTH-05).
            causal_signature=transition.causal_signature,
            parent_signature=transition.parent_signature,
        )
        if _escalating(sample):
            state.escalating_samples += 1
        record = _offer(
            sample,
            policy=policy,
            buffer=buffer,
            controller=controller,
            quantizer=quantizer,
            lattice=lattice,
        )
        label = f"{policy.value}:{record.outcome.value}:{record.reason}"
        state.outcomes[label] = state.outcomes.get(label, 0) + 1
        if record.promoted:
            _account_promotion(
                state,
                record=record,
                sample=sample,
                actor=transition.actor.identity,
                owner=owner,
                epoch=epoch,
                quantizer=quantizer,
                decision=decision,
            )


def _offer(
    sample: AdaptationSample,
    *,
    policy: AdaptationPolicy,
    buffer: QuarantineBuffer,
    controller: PromotionController,
    quantizer: TrustedQuantizer,
    lattice: TrustedLattice | None,
) -> PromotionRecord:
    """Apply one policy to one sample and report what happened."""
    if policy is AdaptationPolicy.ACCEPT_EVERYTHING:
        # The control: no quarantine, no gate, no delay. Exactly the mechanism
        # the invariant forbids, run so its cost can be measured instead of
        # asserted.
        result = quantizer.quantize_behaviour_atom(
            sample.encoded,
            state=sample.state,
            epoch_id=sample.epoch_id,
            sequence=sample.received_at_sequence,
        )
        return PromotionRecord(
            outcome=QuarantineOutcome.PROMOTED,
            key="accept-everything",
            atom_id=int(getattr(result, "atom_id", result)),
            reason="no_gate",
            checks_failed=(),
            epochs_observed=0,
            observations=0,
            sequence=sample.received_at_sequence,
        )

    verdict = buffer.quarantine_adaptation_sample(sample)
    if policy is AdaptationPolicy.ACCEPT_NOTHING:
        return PromotionRecord(
            outcome=QuarantineOutcome.REFUSED,
            key=verdict.key,
            atom_id=None,
            reason="accept_nothing_control",
            checks_failed=verdict.checks_failed,
            epochs_observed=verdict.epochs_observed,
            observations=verdict.observations,
            sequence=sample.received_at_sequence,
        )
    return controller.promote(verdict, sample, quantizer=quantizer, lattice=lattice)


def _account_promotion(
    state: _RunState,
    *,
    record: PromotionRecord,
    sample: AdaptationSample,
    actor: str,
    owner: str | None,
    epoch: Epoch,
    quantizer: TrustedQuantizer,
    decision: EpochDecision | None,
) -> None:
    """Count a write. Ground truth is used here and nowhere else.

    ``actor`` arrives as a separate argument because the encoding deliberately
    carries no identity (ADR-0007): a sample cannot be traced to a lineage from
    inside the decision path, only from outside it, in accounting like this.
    """
    state.promotions += 1
    state.promoted_keys.append(record.key)
    if _escalating(sample):
        state.escalating_promotions += 1
    if owner is not None and actor == owner:
        state.attack_lineage_promotions += 1
    atom_id = record.atom_id
    if atom_id is None:
        return
    if atom_id in state.trusted_before_change:
        state.reused_atoms.add(atom_id)
    if state.change_at is None or state.recovered_at is not None:
        return
    atom = quantizer.get(atom_id)
    if atom is not None and not detect_epoch_mismatch(
        atom, epoch=epoch, decision=decision
    ).mismatch:
        state.recovered_at = state.counter
