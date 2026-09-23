"""Stage 1 — entity semantics, relation algebra, state calculus and Φ."""

from __future__ import annotations

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.ssir.entities import (
    ASSERT_THRESHOLD,
    NEUTRAL_BELIEF,
    Entity,
    EntityKind,
    SemanticBelief,
    SemanticProperty,
)
from pocketsec.stage1.ssir.relations import RELATION_FAMILIES, Relation
from pocketsec.stage1.state.potential import (
    BASE_WEIGHTS,
    INTERACTIONS,
    calibrate,
    delta_phi,
    phi,
)
from pocketsec.stage1.state.security_state import (
    DIMENSIONS,
    CredentialExposure,
    Persistence,
    Privilege,
    Reachability,
    SecurityStateV1,
    StateDelta,
)

# --- entity semantics --------------------------------------------------------


def test_unknown_entity_is_first_class() -> None:
    """The system must not require a fixed vocabulary of executable names."""
    belief = SemanticBelief()
    assert belief.kind is EntityKind.UNKNOWN
    assert belief.uncertainty > 0.5


def test_unseen_property_sits_at_the_neutral_prior() -> None:
    """Never observed is uncertainty, not absence."""
    assert SemanticBelief().belief(SemanticProperty.INTERPRETER) == NEUTRAL_BELIEF


def test_belief_rises_with_evidence_but_never_reaches_certainty() -> None:
    belief = SemanticBelief(kind=EntityKind.PROCESS)
    for _ in range(50):
        belief = belief.observe(SemanticProperty.NETWORK_CLIENT, support=0.6)
    assert belief.holds(SemanticProperty.NETWORK_CLIENT)
    assert belief.belief(SemanticProperty.NETWORK_CLIENT) < 1.0, (
        "inference must stay inference; certainty would make uncertainty dishonest"
    )


def test_uncertainty_falls_as_observations_accumulate() -> None:
    sparse = SemanticBelief(kind=EntityKind.PROCESS)
    observed = sparse
    for _ in range(10):
        observed = observed.note_observation()
    assert observed.uncertainty < sparse.uncertainty


def test_classification_records_negative_results() -> None:
    """A property evaluated and not found is evidence, not silence."""
    evaluated = frozenset({SemanticProperty.CREDENTIAL, SemanticProperty.PERSISTENCE})
    belief = SemanticBelief(kind=EntityKind.FILE).classify(
        present=frozenset(), evaluated=evaluated
    )
    assert belief.belief(SemanticProperty.CREDENTIAL) < 0.5
    assert not belief.holds(SemanticProperty.CREDENTIAL)
    # And it is much more certain than an unclassified file.
    assert belief.uncertainty < SemanticBelief(kind=EntityKind.FILE).uncertainty


def test_properties_are_orthogonal() -> None:
    """A FILE can be CREDENTIAL and PERSISTENCE and ROOT_OWNED at once."""
    belief = SemanticBelief(kind=EntityKind.FILE)
    for prop in (
        SemanticProperty.CREDENTIAL,
        SemanticProperty.PERSISTENCE,
        SemanticProperty.ROOT_OWNED,
    ):
        belief = belief.observe(prop, support=0.95)
    assert len(belief.asserted) == 3


def test_belief_rejects_out_of_range_support() -> None:
    with pytest.raises(ContractError):
        SemanticBelief().observe(SemanticProperty.INTERPRETER, support=1.5)


def test_entity_requires_an_identity() -> None:
    with pytest.raises(ContractError, match="identity"):
        Entity(identity="")


def test_assert_threshold_is_above_the_neutral_prior() -> None:
    assert ASSERT_THRESHOLD > NEUTRAL_BELIEF


# --- relation algebra --------------------------------------------------------


def test_every_relation_has_a_family() -> None:
    assert set(RELATION_FAMILIES) == set(Relation)


def test_relations_fit_a_uint8() -> None:
    assert max(Relation) < 256


# --- state calculus ----------------------------------------------------------


def test_state_raises_are_monotone_within_a_lineage() -> None:
    """You do not un-read a credential."""
    state = SecurityStateV1().raised_to("credential", CredentialExposure.EXTRACTED)
    lowered = state.raised_to("credential", CredentialExposure.METADATA)
    assert lowered.credential is CredentialExposure.EXTRACTED


def test_raising_to_the_same_level_is_identity() -> None:
    state = SecurityStateV1().raised_to("privilege", Privilege.ROOT)
    assert state.raised_to("privilege", Privilege.ROOT) is state


def test_unknown_dimension_is_refused() -> None:
    with pytest.raises(ContractError, match="unknown state dimension"):
        SecurityStateV1().raised_to("telepathy", Privilege.ROOT)


def test_join_is_order_independent() -> None:
    a = SecurityStateV1().raised_to("privilege", Privilege.ROOT)
    b = SecurityStateV1().raised_to("credential", CredentialExposure.EXTRACTED)
    assert SecurityStateV1.join(a, b) == SecurityStateV1.join(b, a)


def test_delta_reports_only_raised_dimensions() -> None:
    before = SecurityStateV1()
    after = before.raised_to("privilege", Privilege.ELEVATED)
    delta = StateDelta.between(before, after)
    assert delta.dimensions == {"privilege"}
    assert delta.magnitude == 1
    assert bool(delta)


def test_no_change_yields_an_empty_delta() -> None:
    state = SecurityStateV1()
    assert not StateDelta.between(state, state)


def test_delta_bitmask_fits_a_uint16() -> None:
    every = SecurityStateV1()
    for name, enum_type in DIMENSIONS.items():
        every = every.raised_to(name, list(enum_type)[-1])
    assert StateDelta.between(SecurityStateV1(), every).bitmask() < 1 << 16


# --- security potential ------------------------------------------------------


def test_phi_of_the_initial_state_is_zero() -> None:
    assert phi(SecurityStateV1()).total == 0.0


def test_composition_exceeds_the_sum_of_parts() -> None:
    """The Stage 1 hypothesis: combination matters more than severity summing."""
    privilege = SecurityStateV1().raised_to("privilege", Privilege.ROOT)
    credential = SecurityStateV1().raised_to("credential", CredentialExposure.READABLE)
    combined = privilege.raised_to("credential", CredentialExposure.READABLE)

    assert phi(combined).total > phi(privilege).total + phi(credential).total
    assert "privileged_credential_access" in phi(combined).active_interactions


def test_exfiltration_triad_fires_only_when_complete() -> None:
    state = (
        SecurityStateV1()
        .raised_to("privilege", Privilege.ELEVATED)
        .raised_to("credential", CredentialExposure.READABLE)
    )
    assert "exfiltration_triad" not in phi(state).active_interactions
    complete = state.raised_to("reachability", Reachability.EXTERNAL)
    assert "exfiltration_triad" in phi(complete).active_interactions


def test_privilege_alone_is_not_dangerous() -> None:
    """A legitimate admin has high privilege and should stay low potential.

    This is the test that keeps Φ from degenerating into a privilege detector.
    """
    admin = SecurityStateV1().raised_to("privilege", Privilege.ROOT)
    assert phi(admin).total < 4.0
    assert phi(admin).active_interactions == ()


def test_delta_phi_is_the_movement() -> None:
    before = SecurityStateV1().raised_to("privilege", Privilege.ELEVATED)
    after = before.raised_to("credential", CredentialExposure.READABLE)
    assert delta_phi(before, after) == pytest.approx(
        phi(after).total - phi(before).total
    )


def test_phi_breakdown_explains_itself() -> None:
    """Φ is never a bare number: an unexplainable score is an arbitrary weight."""
    state = (
        SecurityStateV1()
        .raised_to("privilege", Privilege.ROOT)
        .raised_to("credential", CredentialExposure.EXTRACTED)
        .raised_to("reachability", Reachability.EXTERNAL)
    )
    breakdown = phi(state)
    assert breakdown.base_terms
    assert breakdown.active_interactions
    assert breakdown.total == pytest.approx(breakdown.base + breakdown.interaction_total)


def test_every_interaction_has_a_documented_rationale() -> None:
    for interaction in INTERACTIONS:
        assert interaction.rationale.strip(), f"{interaction.name} lacks a rationale"
        assert interaction.weight > 0


def test_every_dimension_has_a_base_weight() -> None:
    assert set(BASE_WEIGHTS) == set(DIMENSIONS)


def test_calibration_measures_composition_gain() -> None:
    benign = SecurityStateV1().raised_to("privilege", Privilege.ROOT)
    attack = (
        SecurityStateV1()
        .raised_to("privilege", Privilege.ROOT)
        .raised_to("credential", CredentialExposure.EXTRACTED)
        .raised_to("reachability", Reachability.EXTERNAL)
    )
    report = calibrate([(benign, 0), (attack, 1)])
    assert report.composition_gain > 0, (
        "interaction terms should widen benign/malicious separation beyond an "
        "additive severity sum"
    )


def test_calibration_reports_insufficient_labels_honestly() -> None:
    report = calibrate([(SecurityStateV1(), 0)])
    assert "insufficient labels" in report.notes
    assert report.composition_gain == 0.0


def test_persistence_needs_privilege_to_be_a_strong_signal() -> None:
    persistence = SecurityStateV1().raised_to("persistence", Persistence.SERVICE)
    assert "privileged_persistence" not in phi(persistence).active_interactions
    with_privilege = persistence.raised_to("privilege", Privilege.ROOT)
    assert "privileged_persistence" in phi(with_privilege).active_interactions
