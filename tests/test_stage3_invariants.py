"""D3.3 — behavioural invariant discovery: behaviour and failure paths.

These tests exist to keep three claims honest, because each of them is easy to
weaken by accident and expensive to get wrong:

1. anti-unification generalises over **semantics** and cannot see a name;
2. support counts **distinct causal lineages**, never events;
3. bounds truncate **explicitly**, and abstention is reachable.

Every fixture is built by hand rather than replayed from a corpus, so the counts
under test are counts this file states, not counts a generator happened to
produce. One integration test at the end runs the same engine over the real
Stage 1 pipeline to show it survives contact with actual transitions.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

import pytest

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef
from pocketsec.stage1.labs.corpus import build_corpus
from pocketsec.stage1.novelty.engine import NOVELTY_CONTEXTS, NoveltyTensor
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage1.ssir.entities import (
    Entity,
    EntityKind,
    SemanticBelief,
    SemanticProperty,
)
from pocketsec.stage1.ssir.relations import Relation, RelationFamily
from pocketsec.stage1.ssir.transition import SSIRTransitionV1, TemporalContext
from pocketsec.stage1.state.security_state import StateDelta
from pocketsec.stage3.cells.invariant import (
    ConsequentSpec,
    Invariant,
    PredicateRole,
    SemanticPredicate,
)
from pocketsec.stage3.invariants.anti_unification import (
    GENERALISATION_FLOOR,
    PROPERTY_ORDER,
    anti_unify,
    property_mask,
    semantic_class,
    shared_asserted,
)
from pocketsec.stage3.invariants.discovery import (
    MAX_CLUSTERS,
    MAX_INVARIANTS,
    counterfactual_substitution,
    cross_epoch_validate,
    discover_invariants,
    epoch_accident_reason,
    evaluate_invariant,
    is_explicitly_epoch_bound,
    minimal_conditions,
    observed_epochs,
    predictive_equivalence_clusters,
)
from pocketsec.stage3.invariants.motifs import (
    MAX_MOTIFS,
    MAX_MOTIF_LENGTH,
    MotifBudgetExceeded,
    extract_motifs,
    extract_motifs_bounded,
    phi_band,
)
from pocketsec.stage3.theory import SecurityConsequence

# --- fixtures -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FakeSession:
    """The minimal shape ``SessionLike`` asks for."""

    transitions: tuple[SSIRTransitionV1, ...]


def evidence(locator: str) -> EvidenceRef:
    digest = hashlib.sha256(locator.encode("utf-8")).hexdigest()
    return EvidenceRef(store="ebpf", locator=locator, digest=f"sha256:{digest}")


def belief(
    kind: EntityKind,
    asserted: Iterable[SemanticProperty] = (),
    refuted: Iterable[SemanticProperty] = (),
) -> SemanticBelief:
    properties: dict[SemanticProperty, float] = {prop: 0.95 for prop in asserted}
    for prop in refuted:
        properties.setdefault(prop, 0.05)
    return SemanticBelief(kind=kind, properties=properties, observations=4)


def entity(
    identity: str,
    kind: EntityKind,
    asserted: Iterable[SemanticProperty] = (),
    refuted: Iterable[SemanticProperty] = (),
    display_name: str = "",
) -> Entity:
    return Entity(
        identity=identity,
        semantics=belief(kind, asserted, refuted),
        evidence=(evidence(f"entity/{identity}"),),
        display_name=display_name or identity,
    )


def transition(
    actor: Entity,
    relation: Relation,
    obj: Entity,
    *,
    raised: Mapping[str, tuple[int, int]],
    delta_phi: float,
    epoch: int = 0,
    sequence: int = 0,
    refs: tuple[EvidenceRef, ...] = (),
) -> SSIRTransitionV1:
    return SSIRTransitionV1(
        actor=actor,
        relation=relation,
        object=obj,
        state_delta=StateDelta(raised=dict(raised)),
        uncertainty=0.2,
        novelty=NoveltyTensor(values=dict.fromkeys(NOVELTY_CONTEXTS, 0.1)),
        causal_signature=f"{actor.identity}:{sequence}",
        parent_signature=f"{actor.identity}:{max(sequence - 1, 0)}",
        responsibility=0.5,
        temporal=TemporalContext(),
        evidence=refs if refs else (evidence(f"{actor.identity}/{sequence}"),),
        epoch_id=epoch,
        sequence=sequence,
        delta_phi=delta_phi,
    )


SERVICE_PROPERTIES = (SemanticProperty.NETWORK_SERVER, SemanticProperty.PROCESS_SPAWNER)
CREDENTIAL_FILE = (SemanticProperty.CREDENTIAL, SemanticProperty.ROOT_OWNED)


def credential_read_lineage(
    identity: str,
    *,
    repeats: int,
    epoch: int = 0,
    refs: tuple[EvidenceRef, ...] = (),
) -> tuple[SSIRTransitionV1, ...]:
    """One lineage reading a credential file ``repeats`` times over."""
    actor = entity(identity, EntityKind.PROCESS, SERVICE_PROPERTIES)
    obj = entity(f"{identity}/secrets", EntityKind.FILE, CREDENTIAL_FILE)
    return tuple(
        transition(
            actor,
            Relation.READ,
            obj,
            raised={"credential": (0, 2)},
            delta_phi=1.5,
            epoch=epoch,
            sequence=index,
            refs=refs,
        )
        for index in range(repeats)
    )


# --- anti-unification ---------------------------------------------------------


def test_anti_unify_refuses_a_predicate_with_no_required_property() -> None:
    """The generalisation floor is the whole point: no floor, no boundary."""
    entities = [
        entity("a", EntityKind.PROCESS, [SemanticProperty.INTERPRETER]),
        entity("b", EntityKind.PROCESS, [SemanticProperty.NETWORK_CLIENT]),
    ]
    assert shared_asserted(entities) == frozenset()
    assert anti_unify(entities, PredicateRole.ACTOR, RelationFamily.FILESYSTEM) is None
    assert GENERALISATION_FLOOR == 1


def test_anti_unify_never_reads_display_name_or_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Structural, not conventional: the attributes are made to explode."""

    def explode(_self: Entity) -> str:
        raise AssertionError("anti_unify read an identity-shaped attribute")

    entities = [
        entity("nginx-1", EntityKind.PROCESS, SERVICE_PROPERTIES, display_name="/usr/sbin/nginx"),
        entity("httpd-2", EntityKind.PROCESS, SERVICE_PROPERTIES, display_name="/usr/sbin/httpd"),
    ]
    monkeypatch.setattr(Entity, "display_name", property(explode), raising=False)
    monkeypatch.setattr(Entity, "identity", property(explode), raising=False)

    with pytest.raises(AssertionError):
        _ = entities[0].display_name  # the trap is armed

    predicate = anti_unify(entities, PredicateRole.ACTOR, RelationFamily.NETWORK)
    assert predicate is not None
    assert predicate.required_properties == frozenset(SERVICE_PROPERTIES)
    assert semantic_class(entities[0]) == semantic_class(entities[1])


def test_anti_unify_keeps_the_most_specific_shared_generalisation() -> None:
    shared = (SemanticProperty.INTERPRETER, SemanticProperty.NETWORK_CLIENT)
    entities = [
        entity("a", EntityKind.PROCESS, (*shared, SemanticProperty.ROOT_OWNED)),
        entity("b", EntityKind.PROCESS, (*shared, SemanticProperty.TEMP_LOCATION)),
    ]
    predicate = anti_unify(entities, PredicateRole.ACTOR, RelationFamily.NETWORK)
    assert predicate is not None
    assert predicate.required_properties == frozenset(shared)
    assert predicate.entity_kind is EntityKind.PROCESS
    # ROOT_OWNED is asserted by exactly one entity, so it is neither required
    # nor forbidden: disagreement is not negative evidence.
    assert SemanticProperty.ROOT_OWNED not in predicate.forbidden_properties


def test_anti_unify_forbids_only_properties_every_entity_was_evaluated_for() -> None:
    entities = [
        entity(
            "a",
            EntityKind.PROCESS,
            [SemanticProperty.INTERPRETER],
            refuted=[SemanticProperty.PRIVILEGE_CHANGER],
        ),
        entity(
            "b",
            EntityKind.PROCESS,
            [SemanticProperty.INTERPRETER],
            refuted=[SemanticProperty.PRIVILEGE_CHANGER, SemanticProperty.ROOT_OWNED],
        ),
    ]
    predicate = anti_unify(entities, PredicateRole.ACTOR, None)
    assert predicate is not None
    assert predicate.forbidden_properties == frozenset({SemanticProperty.PRIVILEGE_CHANGER})
    # Never seen is not refuted: ROOT_OWNED was only evaluated on one entity.
    assert SemanticProperty.ROOT_OWNED not in predicate.forbidden_properties
    assert not (predicate.required_properties & predicate.forbidden_properties)


def test_anti_unify_abstains_on_an_empty_sequence() -> None:
    assert anti_unify([], PredicateRole.OBJECT, None) is None


def test_anti_unify_does_not_pin_a_kind_it_does_not_know() -> None:
    entities = [
        entity("a", EntityKind.UNKNOWN, [SemanticProperty.INTERPRETER]),
        entity("b", EntityKind.UNKNOWN, [SemanticProperty.INTERPRETER]),
    ]
    predicate = anti_unify(entities, PredicateRole.ACTOR, None)
    assert predicate is not None
    assert predicate.entity_kind is None


def test_property_mask_ordering_is_imported_not_redefined() -> None:
    """A second ordering would make two identical-looking masks disagree."""
    from pocketsec.stage3.cells import masks

    assert PROPERTY_ORDER is masks.PROPERTY_ORDER
    assert property_mask(SERVICE_PROPERTIES) == masks.property_mask(SERVICE_PROPERTIES)


# --- motifs -------------------------------------------------------------------


def test_extract_motifs_counts_lineages_not_events() -> None:
    """Fifty repeats inside one process are one witness, not fifty."""
    sessions = [FakeSession(credential_read_lineage("proc:loop", repeats=51))]
    motifs = extract_motifs(sessions, k=2, min_support=1)
    assert len(motifs) == 1
    assert motifs[0].support == 50
    assert motifs[0].lineages == 1
    # And the filter is on witnesses, so a support of two erases it entirely.
    assert extract_motifs(sessions, k=2, min_support=2) == ()


def test_extract_motifs_truncates_explicitly_rather_than_silently() -> None:
    """The bounded form flags truncation; the plain form refuses outright."""
    sessions = [
        FakeSession(
            tuple(
                transition(
                    entity(f"proc:{index}", EntityKind.PROCESS, SERVICE_PROPERTIES),
                    Relation.READ,
                    entity(f"obj:{index}", EntityKind.FILE, CREDENTIAL_FILE),
                    raised={"credential": (0, min(index % 3 + 1, 2))},
                    delta_phi=float(index),
                    sequence=index,
                )
                for index in range(8)
            )
        )
    ]
    bounded = extract_motifs_bounded(sessions, k=1, min_support=1, max_motifs=2)
    assert bounded.truncated is True
    assert len(bounded.motifs) == 2
    assert bounded.discarded == bounded.distinct_seen - 2 > 0
    with pytest.raises(MotifBudgetExceeded):
        extract_motifs(sessions, k=1, min_support=1, max_motifs=2)


def test_extract_motifs_rejects_out_of_range_arguments() -> None:
    sessions = [FakeSession(credential_read_lineage("proc:a", repeats=4))]
    with pytest.raises(ContractError):
        extract_motifs(sessions, k=MAX_MOTIF_LENGTH + 1, min_support=1)
    with pytest.raises(ContractError):
        extract_motifs(sessions, k=1, min_support=0)
    with pytest.raises(ContractError):
        extract_motifs(sessions, k=1, min_support=1, max_motifs=MAX_MOTIFS + 1)


def test_phi_band_is_monotone_and_bounded() -> None:
    bands = [phi_band(value) for value in (-3.0, 0.0, 0.25, 1.0, 4.0, 99.0)]
    assert bands == sorted(bands)
    assert bands[0] == 0 and bands[-1] == 4


# --- discovery ----------------------------------------------------------------


def credential_corpus(*, lineages: int, repeats: int, epoch: int = 0) -> list[FakeSession]:
    return [
        FakeSession(credential_read_lineage(f"proc:{index}", repeats=repeats, epoch=epoch))
        for index in range(lineages)
    ]


def test_invariant_support_counts_lineages_and_not_events() -> None:
    """One lineage repeating a motif fifty times has support 1, not 50.

    This is the test that fails if anyone swaps the witness count for an
    occurrence count to make support look healthier.
    """
    sessions = credential_corpus(lineages=1, repeats=51)
    occurrences = extract_motifs(sessions, k=2, min_support=1)[0].support
    assert occurrences == 50

    invariants = discover_invariants(sessions, min_support=1)
    assert invariants, "a single well-evidenced lineage should still yield a hypothesis"
    assert {inv.support for inv in invariants} == {1}
    assert all(inv.identities_collapsed == 1 for inv in invariants)


def test_min_support_refuses_a_single_loud_lineage() -> None:
    sessions = credential_corpus(lineages=1, repeats=51)
    assert discover_invariants(sessions, min_support=4) == ()
    assert discover_invariants(credential_corpus(lineages=4, repeats=3), min_support=4)


def test_every_emitted_invariant_is_falsifiable_and_evidenced() -> None:
    invariants = discover_invariants(credential_corpus(lineages=5, repeats=3), min_support=4)
    assert invariants
    for invariant in invariants:
        assert invariant.falsifier.strip()
        assert "does not raise" in invariant.falsifier
        assert invariant.evidence
        assert invariant.epochs
        assert 1 <= len(invariant.antecedent) <= 4


def test_discovery_abstains_when_the_corpus_carries_no_evidence_lineage() -> None:
    """No evidence is an abstention, not a weaker invariant.

    Evidence is referenced, never invented (Stage 0 invariant), so a corpus
    whose transitions lost their references at projection yields nothing.
    """
    evidenced = credential_corpus(lineages=5, repeats=3)
    assert discover_invariants(evidenced, min_support=4), "control: the corpus does yield some"

    stripped = [
        FakeSession(tuple(_without_evidence(t) for t in session.transitions))
        for session in evidenced
    ]
    assert discover_invariants(stripped, min_support=4) == ()


def _without_evidence(source: SSIRTransitionV1) -> SSIRTransitionV1:
    from dataclasses import replace

    return replace(source, evidence=())


def test_discover_invariants_rejects_out_of_range_bounds() -> None:
    sessions = credential_corpus(lineages=4, repeats=3)
    with pytest.raises(ContractError):
        discover_invariants(sessions, min_support=0)
    with pytest.raises(ContractError):
        discover_invariants(sessions, max_invariants=0)
    with pytest.raises(ContractError):
        discover_invariants(sessions, max_invariants=MAX_INVARIANTS + 1)


def test_discover_invariants_respects_its_cap() -> None:
    sessions = credential_corpus(lineages=6, repeats=4)
    assert len(discover_invariants(sessions, min_support=4, max_invariants=1)) <= 1


def test_contradictions_are_counted_not_discarded() -> None:
    """A matching window that fails the consequent must show up in the count."""
    satisfying = credential_corpus(lineages=5, repeats=3)
    counterexample_actor = entity("proc:quiet", EntityKind.PROCESS, SERVICE_PROPERTIES)
    counterexample_object = entity("proc:quiet/secrets", EntityKind.FILE, CREDENTIAL_FILE)
    contradicting = FakeSession(
        (
            transition(
                counterexample_actor,
                Relation.READ,
                counterexample_object,
                raised={"discovery": (0, 1)},
                delta_phi=0.1,
                sequence=0,
            ),
        )
    )
    invariants = discover_invariants([*satisfying, contradicting], min_support=4)
    assert invariants
    fit = evaluate_invariant(invariants[0], [*satisfying, contradicting])
    assert fit.support >= 4
    assert fit.contradictions >= 1


# --- minimal conditions -------------------------------------------------------


def test_minimal_conditions_never_returns_a_changed_consequent() -> None:
    sessions = credential_corpus(lineages=5, repeats=3)
    invariants = discover_invariants(sessions, min_support=4)
    assert invariants
    for invariant in invariants:
        reduced = minimal_conditions(invariant, sessions)
        assert reduced.consequent == invariant.consequent
        assert 1 <= len(reduced.antecedent) <= len(invariant.antecedent)
        assert reduced.falsifier.strip()
        assert reduced.evidence == invariant.evidence


def test_minimal_conditions_keeps_at_least_one_condition() -> None:
    """A zero-term antecedent would fire on every event on the host."""
    sessions = credential_corpus(lineages=5, repeats=3)
    invariant = discover_invariants(sessions, min_support=4)[0]
    reduced = minimal_conditions(invariant, sessions)
    assert len(reduced.antecedent) >= 1


def test_minimal_conditions_refuses_to_minimise_against_an_unexercised_corpus() -> None:
    """Zero matching windows make every removal look free. It is not."""
    unrelated = FakeSession(
        (
            transition(
                entity("proc:idle", EntityKind.PROCESS, [SemanticProperty.INTERPRETER]),
                Relation.SIGNAL,
                entity("proc:idle/target", EntityKind.PROCESS),
                raised={"execution": (0, 1)},
                delta_phi=0.0,
            ),
        )
    )
    padded = actor_dependent_invariant()
    assert minimal_conditions(padded, [unrelated]) is padded


def test_minimal_conditions_drops_a_term_that_carries_nothing() -> None:
    """An object term that every matching window satisfies is removable."""
    sessions = credential_corpus(lineages=5, repeats=3)
    invariant = discover_invariants(sessions, min_support=4)[0]
    padded = Invariant(
        invariant_id="inv:padded-case",
        antecedent=(
            *invariant.antecedent,
            SemanticPredicate(
                role=PredicateRole.OBJECT,
                required_properties=frozenset({SemanticProperty.CREDENTIAL}),
                forbidden_properties=frozenset(),
                relation_family=None,
                entity_kind=None,
            ),
        )[:4],
        consequent=invariant.consequent,
        support=invariant.support,
        contradictions=invariant.contradictions,
        identities_collapsed=invariant.identities_collapsed,
        epochs=invariant.epochs,
        falsifier=invariant.falsifier,
        evidence=invariant.evidence,
    )
    reduced = minimal_conditions(padded, sessions)
    assert len(reduced.antecedent) < len(padded.antecedent)
    assert reduced.consequent == padded.consequent


# --- counterfactual substitution ----------------------------------------------


def actor_dependent_invariant() -> Invariant:
    return Invariant(
        invariant_id="inv:actor-dependent",
        antecedent=(
            SemanticPredicate(
                role=PredicateRole.ACTOR,
                required_properties=frozenset(SERVICE_PROPERTIES),
                forbidden_properties=frozenset(),
                relation_family=RelationFamily.FILESYSTEM,
                entity_kind=EntityKind.PROCESS,
            ),
        ),
        consequent=ConsequentSpec(
            required_dimensions=frozenset({"credential"}),
            min_delta_phi=0.0,
            required_evidence_kinds=frozenset(),
            consequence=SecurityConsequence.ROUTINE,
        ),
        support=2,
        contradictions=0,
        identities_collapsed=2,
        epochs=frozenset({0}),
        falsifier="a service-semantics actor reading without raising credential",
        evidence=(evidence("case/actor-dependent"),),
    )


def test_counterfactual_substitution_reports_instability_from_actor_identity() -> None:
    """Same semantics, different name, different outcome ⇒ unstable."""
    alpha = FakeSession(credential_read_lineage("proc:alpha", repeats=2))
    beta_actor = entity("proc:beta", EntityKind.PROCESS, SERVICE_PROPERTIES)
    beta_object = entity("proc:beta/notes", EntityKind.FILE, CREDENTIAL_FILE)
    beta = FakeSession(
        tuple(
            transition(
                beta_actor,
                Relation.READ,
                beta_object,
                raised={"discovery": (0, 1)},
                delta_phi=0.1,
                sequence=index,
            )
            for index in range(2)
        )
    )
    assert semantic_class(alpha.transitions[0].actor) == semantic_class(beta_actor)

    stable, broken = counterfactual_substitution(
        actor_dependent_invariant(), [alpha, beta], seed=7
    )
    assert stable is False
    assert broken
    assert all("proc:alpha" in item and "proc:beta" in item for item in broken)


def test_counterfactual_substitution_is_stable_when_semantics_decide() -> None:
    sessions = credential_corpus(lineages=4, repeats=2)
    stable, broken = counterfactual_substitution(
        actor_dependent_invariant(), sessions, seed=7
    )
    assert stable is True
    assert broken == ()


def test_counterfactual_substitution_is_deterministic_for_a_seed() -> None:
    alpha = FakeSession(credential_read_lineage("proc:alpha", repeats=2))
    beta_actor = entity("proc:beta", EntityKind.PROCESS, SERVICE_PROPERTIES)
    beta = FakeSession(
        (
            transition(
                beta_actor,
                Relation.READ,
                entity("proc:beta/notes", EntityKind.FILE, CREDENTIAL_FILE),
                raised={"discovery": (0, 1)},
                delta_phi=0.1,
            ),
        )
    )
    first = counterfactual_substitution(actor_dependent_invariant(), [alpha, beta], seed=11)
    second = counterfactual_substitution(actor_dependent_invariant(), [alpha, beta], seed=11)
    assert first == second


# --- cross-epoch validation ---------------------------------------------------


def test_cross_epoch_validate_returns_the_epoch_set_and_flags_an_accident() -> None:
    from dataclasses import replace

    holding = credential_corpus(lineages=4, repeats=2, epoch=0)
    drifted_actor = entity("proc:drift", EntityKind.PROCESS, SERVICE_PROPERTIES)
    drifted = FakeSession(
        (
            transition(
                drifted_actor,
                Relation.READ,
                entity("proc:drift/notes", EntityKind.FILE, CREDENTIAL_FILE),
                raised={"discovery": (0, 1)},
                delta_phi=0.1,
                epoch=1,
            ),
        )
    )
    sessions = [*holding, drifted]
    overclaiming = replace(actor_dependent_invariant(), epochs=frozenset({0, 1}))

    assert observed_epochs(sessions) == frozenset({0, 1})
    assert cross_epoch_validate(overclaiming, sessions) == frozenset({0})
    assert is_explicitly_epoch_bound(overclaiming, sessions) is False

    reason = epoch_accident_reason(overclaiming, sessions)
    assert reason is not None
    assert "holds only in epoch 0" in reason
    assert "claiming epochs [0, 1]" in reason


def test_a_single_epoch_invariant_is_flagged_even_when_it_labels_itself() -> None:
    """Self-labelling cannot launder narrowness.

    ``discover_invariants`` fills ``epochs`` from the same measurement, so if a
    matching ``epochs`` field silenced the flag, every discovered single-epoch
    relationship would pass §9 unexamined. This test fails the moment that
    escape hatch is reopened.
    """
    from dataclasses import replace

    holding = credential_corpus(lineages=4, repeats=2, epoch=0)
    drifted = FakeSession(
        (
            transition(
                entity("proc:drift", EntityKind.PROCESS, SERVICE_PROPERTIES),
                Relation.READ,
                entity("proc:drift/notes", EntityKind.FILE, CREDENTIAL_FILE),
                raised={"discovery": (0, 1)},
                delta_phi=0.1,
                epoch=1,
            ),
        )
    )
    sessions = [*holding, drifted]
    bound = replace(actor_dependent_invariant(), epochs=frozenset({0}))
    assert cross_epoch_validate(bound, sessions) == frozenset({0})
    assert is_explicitly_epoch_bound(bound, sessions) is True
    reason = epoch_accident_reason(bound, sessions)
    assert reason is not None
    assert "already bound to that epoch" in reason


def test_cross_epoch_validate_reports_an_invariant_that_holds_nowhere() -> None:
    failing = FakeSession(
        (
            transition(
                entity("proc:none", EntityKind.PROCESS, SERVICE_PROPERTIES),
                Relation.READ,
                entity("proc:none/notes", EntityKind.FILE, CREDENTIAL_FILE),
                raised={"discovery": (0, 1)},
                delta_phi=0.1,
            ),
        )
    )
    invariant = actor_dependent_invariant()
    assert cross_epoch_validate(invariant, [failing]) == frozenset()
    reason = epoch_accident_reason(invariant, [failing])
    assert reason is not None and "no observed epoch" in reason


# --- predictive equivalence ---------------------------------------------------


def test_predictive_equivalence_groups_equivalent_futures() -> None:
    same_future = credential_corpus(lineages=2, repeats=2)
    other_actor = entity("proc:other", EntityKind.PROCESS, SERVICE_PROPERTIES)
    other = FakeSession(
        (
            transition(
                other_actor,
                Relation.CONNECT,
                entity("endpoint:1", EntityKind.ENDPOINT, [SemanticProperty.EXTERNAL_ENDPOINT]),
                raised={"reachability": (0, 2)},
                delta_phi=0.4,
            ),
        )
    )
    clusters = predictive_equivalence_clusters([*same_future, other])
    assert len(clusters) == 2
    assert clusters[0] == frozenset({"proc:0", "proc:1"})
    assert clusters[1] == frozenset({"proc:other"})


def test_predictive_equivalence_truncates_to_the_requested_bound() -> None:
    sessions = credential_corpus(lineages=3, repeats=1)
    assert len(predictive_equivalence_clusters(sessions, max_clusters=1)) == 1
    with pytest.raises(ContractError):
        predictive_equivalence_clusters(sessions, max_clusters=0)
    with pytest.raises(ContractError):
        predictive_equivalence_clusters(sessions, max_clusters=MAX_CLUSTERS + 1)


# --- integration with the real Stage 1 pipeline -------------------------------


def stage1_sessions(*, count: int, seed: int) -> Sequence[object]:
    pipeline = Stage1Pipeline()
    scenarios = build_corpus(count=count, seed=seed, split="eval")
    return [
        pipeline.run_scenario(scenario, offset=index)
        for index, scenario in enumerate(scenarios)
    ]


def test_discovery_survives_the_real_stage1_pipeline() -> None:
    """Whatever it finds on real transitions must still satisfy the contract."""
    sessions = stage1_sessions(count=24, seed=3)
    assert any(session.transitions for session in sessions)  # type: ignore[attr-defined]

    invariants = discover_invariants(sessions, min_support=2)  # type: ignore[arg-type]
    for invariant in invariants:
        assert invariant.falsifier.strip()
        assert invariant.evidence
        assert invariant.support >= 2
        assert invariant.epochs
        reduced = minimal_conditions(invariant, sessions)  # type: ignore[arg-type]
        assert reduced.consequent == invariant.consequent
    assert len(invariants) <= MAX_INVARIANTS
