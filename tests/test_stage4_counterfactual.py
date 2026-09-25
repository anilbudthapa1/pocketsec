"""Behaviour and failure-path tests for Stage 4's counterfactual package (D4.6, D4.7, D4.11).

Every test here is about something going *wrong* if the mechanism is weakened: a key
space drifting, a bound not bounding, an untested conclusion reported as survived, a
dropped sensor making the system more confident, an unfalsifiable world passing
unremarked.

**On the test doubles.** ``pocketsec/stage4/worlds/{world,field}.py``,
``visibility/sensor_shadow.py`` and ``claims/graph.py`` are owned by the `foundation`,
`visibility` and `claims` packages and are being written concurrently — at the time this
file was written ``find pocketsec/stage4 -type f`` listed only the counterfactual
package. The doubles below implement exactly the surface `docs/stage-4-spec.md` §4
documents for those types and nothing more, which is also the surface the production
modules here are allowed to touch. They are test doubles, not weakened assertions: no
assertion in this file is softened because of them, and the production modules import
those types only under ``TYPE_CHECKING``, so they keep working unchanged when the real
ones land.

The causal spine is **not** a double. ``CausalMemory`` and ``CausalNode`` are the real
Stage 1 types, because the join between an intervention target and a spine signature is
the single thing this file most needs to be real (S2-FC-01).
"""

from __future__ import annotations

import ast
import dataclasses
import math
import pathlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS
from pocketsec.stage1.causal.memory import GENESIS_SIGNATURE, CausalMemory, CausalNode
from pocketsec.stage1.state.potential import phi
from pocketsec.stage1.state.security_state import (
    DIMENSIONS,
    CredentialExposure,
    Persistence,
    Privilege,
    SecurityStateV1,
    StateDelta,
)
from pocketsec.stage4.cones import incident_cone as cone_module
from pocketsec.stage4.cones.incident_cone import (
    MAX_BRANCHES_PER_WORLD,
    MAX_CONE_DEPTH,
    MIN_BRANCH_CONSEQUENCE,
    CausalBranch,
    IncidentFutureCone,
    compose_cones,
    pairwise_discriminating_signals,
    predict_world_future_cone,
)
from pocketsec.stage4.counterfactual import intervention as intervention_module
from pocketsec.stage4.counterfactual import questions as questions_module
from pocketsec.stage4.counterfactual import stress as stress_module
from pocketsec.stage4.counterfactual.intervention import (
    MAX_COUNTERFACTUALS_PER_INCIDENT,
    MAX_FLUX_HISTORY,
    MAX_INTERVENTION_DEPTH,
    NOVELTY_BORN_MECHANISM,
    Intervention,
    InterventionKind,
    ResponsibilityFlux,
    calculate_responsibility_flux,
    counterfactual_intervene,
    enumerate_interventions,
    sweep_interventions,
)
from pocketsec.stage4.counterfactual.questions import (
    MAX_QUESTIONS_PER_WORLD,
    Challenge,
    QuestionKind,
    SelfQuestioningVerdict,
    judge_self_questioning,
    materially_challenged,
    self_question_world,
)
from pocketsec.stage4.counterfactual.stress import (
    COLLAPSE_DROP,
    MAX_STRESS_PERTURBATIONS,
    NO_MATERIAL,
    PerturbationKind,
    StressMaterial,
    stress_world_adversarially,
    stresses_actually_run,
)

# --- test doubles for the concurrently-written foundation types ----------------


class _Geometry(StrEnum):
    UNNORMALISED_WEIGHT = "UNNORMALISED_WEIGHT"


@dataclass(frozen=True, slots=True)
class _Support:
    """``WorldSupport``'s documented surface: a value with its geometry attached."""

    value: float
    geometry: _Geometry = _Geometry.UNNORMALISED_WEIGHT

    def combine(self, log_likelihood_ratio: float) -> _Support:
        return _Support(value=self.value * math.exp(log_likelihood_ratio),
                        geometry=self.geometry)

    def as_probability(self) -> float | None:
        return None


@dataclass(frozen=True, slots=True)
class _Latent:
    state: SecurityStateV1
    asserted_dimensions: frozenset[str]
    consequence: float


@dataclass(frozen=True, slots=True)
class _World:
    world_id: str
    mechanism_id: str
    latent_state: _Latent
    support: _Support
    expected_evidence: frozenset[str] = frozenset()
    forbidden_evidence: frozenset[str] = frozenset()
    contradictions: tuple[str, ...] = ()
    tension: Any = None
    uncertainty: float = 0.2
    visibility_requirements: frozenset[str] = frozenset()
    spine_signatures: tuple[str, ...] = ()
    born_at_sequence: int = 0
    fission_depth: int = 0


@dataclass(frozen=True, slots=True)
class _Field:
    incident_id: str
    epoch_id: int
    worlds: tuple[_World, ...]
    at_sequence: int = 0

    def world(self, world_id: str) -> _World | None:
        for world in self.worlds:
            if world.world_id == world_id:
                return world
        return None

    def with_worlds(self, worlds: Sequence[_World]) -> _Field:
        return replace(self, worlds=tuple(worlds))

    def support_vector(self) -> Mapping[str, float]:
        return {world.world_id: world.support.value for world in self.worlds}

    def support_distance(self, other: _Field) -> float:
        return intervention_module.jensen_shannon(self.support_vector(),
                                                  other.support_vector())

    def leaders(self, *, n: int = 2) -> tuple[_World, ...]:
        return tuple(sorted(self.worlds, key=lambda w: -w.support.value))[:n]


@dataclass(frozen=True, slots=True)
class _Shadow:
    blind: frozenset[str] = frozenset()

    def covers(self, signal: str) -> bool:
        return signal in self.blind

    def confidence_penalty(self) -> float:
        return min(1.0, 0.1 * len(self.blind))


@dataclass(frozen=True, slots=True)
class _Claim:
    claim_id: str
    kind: str
    subject: str
    premises: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class _Graph:
    claims: Mapping[str, _Claim]
    authoritative: frozenset[str] = frozenset()
    rooted: frozenset[str] = frozenset()

    def traces_to_observation(self, claim_id: str) -> bool:
        return claim_id in self.rooted


# --- fixtures -----------------------------------------------------------------


def _compromised_state() -> SecurityStateV1:
    state = SecurityStateV1().raised_to("privilege", Privilege.ROOT)
    return state.raised_to("credential", CredentialExposure.READABLE)


def _spine(count: int = 3) -> tuple[CausalNode, ...]:
    """A real Stage 1 causal spine. Signatures come from ``causal_signature``."""
    memory = CausalMemory(capacity=64, l0_budget=32)
    parent = GENESIS_SIGNATURE
    for index in range(count):
        node = memory.record(
            parent_signature=parent,
            actor_semantics=frozenset({f"role_{index}"}),
            relation=index + 1,
            object_semantics=frozenset({"credential_material"}),
            state_delta=StateDelta(raised={"credential": (0, 1)}),
            delta_phi=1.0 + index,
            actor_identity=f"/usr/bin/tool{index}",
            evidence_locators=(f"evt:{index}",),
        )
        parent = node.signature
    return memory.spine()


def _two_world_field(spine: Sequence[CausalNode]) -> _Field:
    signatures = tuple(node.signature for node in spine)
    compromised = _World(
        world_id="W1",
        mechanism_id="compromised_admin_session",
        latent_state=_Latent(
            state=_compromised_state(),
            asserted_dimensions=frozenset({"privilege", "credential"}),
            consequence=phi(_compromised_state()).total,
        ),
        support=_Support(value=0.6),
        expected_evidence=frozenset({"credential_access", "privilege_change"}),
        forbidden_evidence=frozenset({"session_teardown"}),
        spine_signatures=signatures,
    )
    benign = _World(
        world_id="W2",
        mechanism_id="approved_admin_change",
        latent_state=_Latent(
            state=SecurityStateV1(),
            asserted_dimensions=frozenset(),
            consequence=phi(SecurityStateV1()).total,
        ),
        support=_Support(value=0.4),
        expected_evidence=frozenset({"authentication"}),
        spine_signatures=(),
    )
    return _Field(incident_id="INC-1", epoch_id=7, worlds=(compromised, benign), at_sequence=12)


# --- D4.6: the key space, which is the defect this module exists to avoid ------


def test_intervention_refuses_a_positional_locator_as_a_target() -> None:
    """S2-FC-01: a locator key space must fail at construction, not join against nothing."""
    for bad in ("lineage:3:r2:m1", "W1", "", "abc", "0" * 17, "A" * 16, "0" * 15 + "g"):
        with pytest.raises(ContractError):
            Intervention(kind=InterventionKind.REMOVE_EVENT, target_signature=bad)


def test_intervention_refuses_a_target_absent_from_the_spine() -> None:
    spine = _spine()
    field = _two_world_field(spine)
    absent = "f" * 16
    assert absent not in {node.signature for node in spine}
    with pytest.raises(ContractError, match="not a spine"):
        counterfactual_intervene(
            field,
            Intervention(kind=InterventionKind.REMOVE_EVENT, target_signature=absent),
            spine=spine,
        )


def test_every_intervention_run_joins_against_a_real_spine_signature_by_count() -> None:
    """The count, not the plausibility: S2-FC-01 reported a measurement over zero calls."""
    spine = _spine(4)
    field = _two_world_field(spine)
    signatures = {node.signature for node in spine}
    assert signatures, "the spine must be non-empty or this test proves nothing"

    calls: list[str] = []
    real = intervention_module.counterfactual_intervene

    def counting(field_: Any, intervention: Intervention, **kwargs: Any) -> Any:
        calls.append(intervention.target_signature)
        return real(field_, intervention, **kwargs)

    interventions = enumerate_interventions(field, spine)
    results = tuple(counting(field, i, spine=spine) for i in interventions)

    assert len(calls) == len(interventions) > 0
    assert sum(1 for signature in calls if signature in signatures) == len(calls)
    assert all(r.work_units > 0 for r in results)


def test_suppress_escalation_requires_a_real_dimension_and_no_other_kind_may_carry_one() -> None:
    signature = _spine()[0].signature
    with pytest.raises(ContractError, match="DIMENSIONS"):
        Intervention(kind=InterventionKind.SUPPRESS_ESCALATION, target_signature=signature)
    with pytest.raises(ContractError, match="DIMENSIONS"):
        Intervention(
            kind=InterventionKind.SUPPRESS_ESCALATION,
            target_signature=signature,
            suppressed_dimension="not_a_dimension",
        )
    with pytest.raises(ContractError, match="must not carry suppressed_dimension"):
        Intervention(
            kind=InterventionKind.REMOVE_EVENT,
            target_signature=signature,
            suppressed_dimension="privilege",
        )
    ok = Intervention(
        kind=InterventionKind.SUPPRESS_ESCALATION,
        target_signature=signature,
        suppressed_dimension="privilege",
    )
    assert ok.suppressed_dimension in DIMENSIONS


def test_replace_actor_class_requires_a_replacement_and_others_refuse_one() -> None:
    signature = _spine()[0].signature
    with pytest.raises(ContractError, match="replacement_class"):
        Intervention(kind=InterventionKind.REPLACE_ACTOR_CLASS, target_signature=signature)
    with pytest.raises(ContractError, match="must not carry replacement_class"):
        Intervention(
            kind=InterventionKind.DELAY_STEP,
            target_signature=signature,
            replacement_class="service_account",
        )


def test_no_stage4_counterfactual_dataclass_field_names_an_authority_token() -> None:
    """Trust rule T5, enforced inside this package rather than hoped for.

    Architecture §9 writes ``do(block privilege transition)`` and §16 writes
    "privilege/risk cost". Both wordings are forbidden field names. This test is the one
    that goes red if someone undoes the rename.
    """
    modules = (intervention_module, stress_module, questions_module, cone_module)
    checked = 0
    for module in modules:
        for name in dir(module):
            obj = getattr(module, name)
            if not dataclasses.is_dataclass(obj) or not isinstance(obj, type):
                continue
            if obj.__module__ != module.__name__:
                continue
            checked += 1
            for field_name in obj.__dataclass_fields__:
                lowered = field_name.lower()
                for token in FORBIDDEN_AUTHORITY_FIELDS:
                    assert token not in lowered, f"{obj.__name__}.{field_name} names {token!r}"
    assert checked >= 6, f"expected to audit the package's dataclasses, saw {checked}"


# --- D4.6: what the interventions actually do ---------------------------------


def test_remove_event_lowers_the_dependent_world_and_moves_the_field() -> None:
    spine = _spine()
    field = _two_world_field(spine)
    result = counterfactual_intervene(
        field,
        Intervention(kind=InterventionKind.REMOVE_EVENT, target_signature=spine[-1].signature),
        spine=spine,
    )
    assert result.support_shift["W1"] < 0.0
    assert result.support_shift["W2"] > 0.0
    assert result.field_distance > 0.0
    assert result.moved_the_field()
    # The dependent world is the alarming one, so removing its cause must lower the
    # expected consequence, never raise it.
    assert result.outcome_shift < 0.0


def test_delay_step_is_the_null_probe_and_moves_nothing_at_all() -> None:
    """Causal signatures exclude timing, so a semantics-preserving delay must be exact."""
    spine = _spine()
    field = _two_world_field(spine)
    result = counterfactual_intervene(
        field,
        Intervention(kind=InterventionKind.DELAY_STEP, target_signature=spine[0].signature),
        spine=spine,
    )
    assert result.field_distance == 0.0
    assert result.evidence_shift == 0.0
    assert set(result.support_shift.values()) == {0.0}


def test_remove_novelty_touches_only_the_world_born_from_novelty() -> None:
    """Novelty is not maliciousness: an evidence-backed world may not lean on novelty."""
    spine = _spine()
    field = _two_world_field(spine)
    evidence_only = counterfactual_intervene(
        field,
        Intervention(kind=InterventionKind.REMOVE_NOVELTY, target_signature=spine[0].signature),
        spine=spine,
    )
    assert evidence_only.field_distance == 0.0

    unknown = _World(
        world_id="W0",
        mechanism_id=NOVELTY_BORN_MECHANISM,
        latent_state=_Latent(SecurityStateV1(), frozenset(), 0.0),
        support=_Support(value=0.5),
        expected_evidence=frozenset({"module_load"}),
        spine_signatures=tuple(node.signature for node in spine),
    )
    with_unknown = field.with_worlds((*field.worlds, unknown))
    result = counterfactual_intervene(
        with_unknown,
        Intervention(kind=InterventionKind.REMOVE_NOVELTY, target_signature=spine[0].signature),
        spine=spine,
    )
    assert result.support_shift["W0"] < 0.0
    assert result.support_shift["W1"] > 0.0
    assert result.field_distance > 0.0


def test_suppress_escalation_only_bites_a_world_that_asserts_that_dimension() -> None:
    spine = _spine()
    field = _two_world_field(spine)
    # The spine raises `credential`, and only W1 asserts it.
    credential = counterfactual_intervene(
        field,
        Intervention(
            kind=InterventionKind.SUPPRESS_ESCALATION,
            target_signature=spine[-1].signature,
            suppressed_dimension="credential",
        ),
        spine=spine,
    )
    assert credential.support_shift["W1"] < 0.0
    # `persistence` was never raised by any spine node, so suppressing it is a no-op.
    untouched = counterfactual_intervene(
        field,
        Intervention(
            kind=InterventionKind.SUPPRESS_ESCALATION,
            target_signature=spine[-1].signature,
            suppressed_dimension="persistence",
        ),
        spine=spine,
    )
    assert untouched.field_distance == 0.0


# --- D4.6: the bounds actually bound -----------------------------------------


def test_intervention_depth_beyond_one_is_refused() -> None:
    spine = _spine()
    field = _two_world_field(spine)
    intervention = Intervention(
        kind=InterventionKind.REMOVE_EVENT, target_signature=spine[0].signature
    )
    assert MAX_INTERVENTION_DEPTH == 1
    for bad_depth in (0, 2, 17):
        with pytest.raises(ContractError, match="depth"):
            counterfactual_intervene(field, intervention, spine=spine, depth=bad_depth)


def test_sweep_refuses_more_than_the_per_incident_counterfactual_bound() -> None:
    spine = _spine()
    field = _two_world_field(spine)
    one = Intervention(kind=InterventionKind.REMOVE_EVENT, target_signature=spine[0].signature)
    batch = (one,) * (MAX_COUNTERFACTUALS_PER_INCIDENT + 1)
    with pytest.raises(ContractError, match=str(MAX_COUNTERFACTUALS_PER_INCIDENT)):
        sweep_interventions(field, batch, spine=spine)
    assert len(sweep_interventions(field, batch[:4], spine=spine)) == 4


def test_enumerate_interventions_is_bounded_deterministic_and_spine_keyed() -> None:
    spine = _spine(12)
    field = _two_world_field(spine)
    first = enumerate_interventions(field, spine)
    assert first == enumerate_interventions(field, spine)
    assert len(first) <= MAX_COUNTERFACTUALS_PER_INCIDENT
    signatures = {node.signature for node in spine}
    assert all(i.target_signature in signatures for i in first)
    assert len(enumerate_interventions(field, spine, limit=3)) == 3
    with pytest.raises(ContractError):
        enumerate_interventions(field, spine, limit=-1)


def test_intervention_module_holds_no_retained_counterfactual_workspace() -> None:
    """§44: the workspace is per-call. A module-level cache would also be unbounded."""
    # AST over the module's own source, so an imported mapping such as Stage 1's
    # DIMENSIONS is not mistaken for state this module keeps.
    tree = ast.parse(pathlib.Path(str(intervention_module.__file__)).read_text(encoding="utf-8"))
    mutable = (ast.Dict, ast.List, ast.Set, ast.DictComp, ast.ListComp, ast.SetComp)
    offenders = [
        target.id
        for node in tree.body
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, mutable)
        for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
        if isinstance(target, ast.Name) and target.id != "__all__"
    ]
    assert offenders == [], f"mutable module-level state in intervention.py: {offenders}"

    spine = _spine()
    field = _two_world_field(spine)
    intervention = Intervention(
        kind=InterventionKind.REMOVE_EVENT, target_signature=spine[0].signature
    )
    baseline = counterfactual_intervene(field, intervention, spine=spine)
    for _ in range(50):
        repeat = counterfactual_intervene(field, intervention, spine=spine)
        assert repeat == baseline


# --- D4.6: responsibility flux (§10) ------------------------------------------


def test_responsibility_flux_is_computed_for_every_spine_node_and_is_bounded() -> None:
    spine = _spine(40)
    field = _two_world_field(spine)
    fluxes = calculate_responsibility_flux(field, spine, at_sequence=1)
    assert len(fluxes) == min(len(spine), MAX_COUNTERFACTUALS_PER_INCIDENT)
    signatures = {node.signature for node in spine}
    assert all(f.node_signature in signatures for f in fluxes)
    assert all(f.flux >= 0.0 for f in fluxes)


def test_responsibility_actually_moves_between_events_as_evidence_arrives() -> None:
    """§10's claim, as an inequality: a frozen spine would make ``moved()`` zero."""
    spine = _spine()
    field = _two_world_field(spine)
    first = calculate_responsibility_flux(field, spine, at_sequence=1)

    # Evidence arrives: the benign world gains support, so removing a node that the
    # compromised world depends on now moves the field by a different amount.
    shifted = field.with_worlds(
        tuple(
            replace(world, support=_Support(value=0.95)) if world.world_id == "W2" else world
            for world in field.worlds
        )
    )
    second = calculate_responsibility_flux(shifted, spine, at_sequence=2, previous=first)

    assert {f.node_signature for f in first} == {f.node_signature for f in second}
    assert any(f.moved() != 0.0 for f in second), "responsibility never moved: flux is frozen"
    assert all(f.history and f.history[-1][0] == 1 for f in second)


def test_flux_history_is_bounded_to_max_flux_history_and_keeps_the_newest() -> None:
    flux = ResponsibilityFlux(node_signature="a" * 16, flux=0.0, at_sequence=0)
    for step in range(1, 40):
        flux = flux.with_sample(step, step / 100.0)
    assert len(flux.history) == MAX_FLUX_HISTORY
    assert flux.at_sequence == 39
    assert [sequence for sequence, _ in flux.history] == list(range(31, 39))
    with pytest.raises(ContractError, match="bounded"):
        ResponsibilityFlux(
            node_signature="a" * 16,
            flux=0.0,
            at_sequence=1,
            history=tuple((i, 0.0) for i in range(MAX_FLUX_HISTORY + 1)),
        )


def test_flux_refuses_a_node_signature_that_is_not_a_causal_signature() -> None:
    with pytest.raises(ContractError):
        ResponsibilityFlux(node_signature="lineage:0:r1:m1", flux=0.1, at_sequence=0)
    with pytest.raises(ContractError):
        calculate_responsibility_flux(
            _two_world_field(_spine()), _spine(), at_sequence=-1
        )


# --- D4.11: adversarial belief stress (§25) -----------------------------------


def _material(spine: Sequence[CausalNode], **overrides: Any) -> StressMaterial:
    base: dict[str, Any] = {
        "observed_signals": frozenset({"credential_access", "privilege_change"}),
        "spine": tuple(spine),
    }
    base.update(overrides)
    return StressMaterial(**base)


def test_exactly_eight_perturbations_and_eight_questions_exist() -> None:
    assert len(list(PerturbationKind)) == MAX_STRESS_PERTURBATIONS == 8
    assert len(list(QuestionKind)) == MAX_QUESTIONS_PER_WORLD == 8


def test_rename_leaves_the_support_vector_bit_identical() -> None:
    """Equality, not similarity. ``causal_signature`` excludes identities by design."""
    spine = _spine()
    field = _two_world_field(spine)
    renames = {node.actor_identity: f"/opt/{node.signature}" for node in spine}
    rows = stress_world_adversarially(
        field,
        "W1",
        corpus_hook=lambda kind: (
            _material(spine, identity_renames=renames)
            if kind is PerturbationKind.RENAME_SEMANTIC_PRESERVING
            else None
        ),
    )
    row = next(r for r in rows if r.kind is PerturbationKind.RENAME_SEMANTIC_PRESERVING)
    assert row.exercised()
    assert row.support_shift == 0.0
    assert row.conclusion_survived is True
    assert row.spurious_detected is False
    assert "bit_identical=True" in row.detail


def test_ioc_swap_delay_and_epoch_shift_are_all_bit_identical() -> None:
    spine = _spine()
    field = _two_world_field(spine)
    material = _material(
        spine,
        ioc_equivalents={"evt:0": "evt:unseen-0"},
        delay_steps=900,
        epoch_shift=3,
    )
    rows = stress_world_adversarially(field, "W1", corpus_hook=lambda kind: material)
    for kind in (
        PerturbationKind.REPLACE_IOC_WITH_EQUIVALENT,
        PerturbationKind.DELAY_LOW_AND_SLOW,
        PerturbationKind.PERTURB_EPOCH_CONTEXT,
    ):
        row = next(r for r in rows if r.kind is kind)
        assert row.exercised(), kind
        assert row.support_shift == 0.0, kind
        assert row.spurious_detected is False, kind


def test_remove_critical_event_collapses_the_spurious_world_not_the_true_one() -> None:
    """G4.6's core: a world resting on one decoy must collapse where a chain does not."""
    spine = _spine(3)
    decoy = CausalNode(
        signature="d" * 16,
        parent_signature=GENESIS_SIGNATURE,
        sequence=99,
        relation=9,
        state_delta_mask=1 << list(DIMENSIONS).index("credential"),
        delta_phi=9.0,
        actor_identity="/tmp/decoy",
    )
    true_world = _two_world_field(spine).world("W1")
    assert true_world is not None
    spurious = _World(
        world_id="WS",
        mechanism_id="decoy_driven_explanation",
        latent_state=_Latent(
            _compromised_state(), frozenset({"credential"}), phi(_compromised_state()).total
        ),
        support=_Support(value=0.6),
        expected_evidence=frozenset({"credential_access"}),
        spine_signatures=(decoy.signature,),
    )
    field = _Field(
        incident_id="INC-SPUR", epoch_id=1, worlds=(true_world, spurious), at_sequence=5
    )
    full_spine = (*spine, decoy)

    spurious_row = stress_world_adversarially(
        field,
        "WS",
        corpus_hook=lambda kind: (
            _material(full_spine, critical_signature=decoy.signature)
            if kind is PerturbationKind.REMOVE_CRITICAL_EVENT
            else None
        ),
    )[1]
    true_row = stress_world_adversarially(
        field,
        "W1",
        corpus_hook=lambda kind: (
            _material(full_spine, critical_signature=spine[-1].signature)
            if kind is PerturbationKind.REMOVE_CRITICAL_EVENT
            else None
        ),
    )[1]

    assert spurious_row.kind is PerturbationKind.REMOVE_CRITICAL_EVENT
    assert spurious_row.spurious_detected is True
    assert spurious_row.conclusion_survived is False
    assert spurious_row.support_shift <= -COLLAPSE_DROP
    assert true_row.spurious_detected is False
    assert true_row.conclusion_survived is True
    assert true_row.support_shift > spurious_row.support_shift


def test_decoy_ancestry_is_detected_when_a_world_leans_on_it() -> None:
    spine = _spine(3)
    decoy = CausalNode(
        signature="e" * 16,
        parent_signature=GENESIS_SIGNATURE,
        sequence=50,
        relation=4,
        state_delta_mask=1 << list(DIMENSIONS).index("credential"),
        delta_phi=12.0,
    )
    leaning = _World(
        world_id="WD",
        mechanism_id="decoy_leaning",
        latent_state=_Latent(
            _compromised_state(), frozenset({"credential"}), phi(_compromised_state()).total
        ),
        support=_Support(value=0.7),
        expected_evidence=frozenset({"credential_access"}),
        spine_signatures=(decoy.signature,),
    )
    other = _two_world_field(spine).world("W2")
    assert other is not None
    field = _Field(incident_id="INC-D", epoch_id=1, worlds=(leaning, other))
    rows = stress_world_adversarially(
        field,
        "WD",
        corpus_hook=lambda kind: (
            _material(spine, decoy=decoy)
            if kind is PerturbationKind.INJECT_DECOY_ANCESTRY
            else None
        ),
    )
    row = next(r for r in rows if r.kind is PerturbationKind.INJECT_DECOY_ANCESTRY)
    assert row.spurious_detected is True


def test_a_support_rise_under_dropped_telemetry_is_flagged_spurious() -> None:
    """Falsifier F4 in miniature: less evidence may never make a conclusion stronger."""
    spine = _spine()
    field = _two_world_field(spine)
    forbidding = replace(
        field.worlds[1], forbidden_evidence=frozenset({"credential_access"})
    )
    field = field.with_worlds((field.worlds[0], forbidding))
    rows = stress_world_adversarially(
        field,
        "W2",
        corpus_hook=lambda kind: (
            _material(spine, dropped_signals=frozenset({"credential_access"}))
            if kind is PerturbationKind.DROP_TELEMETRY
            else None
        ),
    )
    row = next(r for r in rows if r.kind is PerturbationKind.DROP_TELEMETRY)
    assert row.support_shift > 0.0
    assert row.spurious_detected is True


def test_benign_context_that_collapses_a_conclusion_is_reported() -> None:
    spine = _spine()
    field = _two_world_field(spine)
    rows = stress_world_adversarially(
        field,
        "W1",
        corpus_hook=lambda kind: (
            _material(spine, benign_signals=frozenset({"session_teardown"}))
            if kind is PerturbationKind.INSERT_BENIGN_CONTEXT
            else None
        ),
    )
    row = next(r for r in rows if r.kind is PerturbationKind.INSERT_BENIGN_CONTEXT)
    # W1 forbids session_teardown, so plausible benign context collapses it entirely.
    assert row.spurious_detected is True
    assert row.conclusion_survived is False


def test_absent_material_is_never_reported_as_a_surviving_conclusion() -> None:
    """Eight untested 'survived' rows would be the most flattering possible lie."""
    spine = _spine()
    field = _two_world_field(spine)
    rows = stress_world_adversarially(field, "W1", corpus_hook=lambda kind: None)
    assert len(rows) == MAX_STRESS_PERTURBATIONS
    assert stresses_actually_run(rows) == 0
    for row in rows:
        assert row.detail.startswith(NO_MATERIAL)
        assert row.conclusion_survived is False
        assert row.spurious_detected is False
        assert row.support_shift == 0.0


def test_stress_refuses_an_unknown_world_and_a_wrong_hook_return() -> None:
    spine = _spine()
    field = _two_world_field(spine)
    with pytest.raises(ContractError, match="not in incident"):
        stress_world_adversarially(field, "nope", corpus_hook=lambda kind: None)
    with pytest.raises(ContractError, match="StressMaterial"):
        stress_world_adversarially(  # type: ignore[arg-type,return-value]
            field, "W1", corpus_hook=lambda kind: "material"
        )
    with pytest.raises(ContractError, match="delay_steps"):
        StressMaterial(delay_steps=-1)


def test_implied_signals_read_only_state_deltas() -> None:
    """The invariant that makes the four semantics-preserving stresses non-tautological."""
    spine = _spine()
    renamed = tuple(
        replace(node, actor_identity="/other/name", sequence=node.sequence + 500)
        for node in spine
    )
    assert stress_module.implied_signals(spine) == stress_module.implied_signals(renamed)
    assert "credential_access" in stress_module.implied_signals(spine)


# --- D4.11: the self-questioning engine (§24) --------------------------------


def test_self_question_world_returns_all_eight_questions_in_enum_order() -> None:
    spine = _spine()
    field = _two_world_field(spine)
    challenges = self_question_world(
        field, "W1", shadow=_Shadow(), graph=None, observed=frozenset(), spine=spine
    )
    assert len(challenges) == MAX_QUESTIONS_PER_WORLD
    assert tuple(c.kind for c in challenges) == tuple(QuestionKind)


def test_an_unfalsifiable_world_is_a_material_finding() -> None:
    state = SecurityStateV1()
    lonely = _World(
        world_id="WU",
        mechanism_id="unfalsifiable",
        latent_state=_Latent(state, frozenset(), 0.0),
        support=_Support(value=1.0),
        expected_evidence=frozenset({"authentication"}),
        forbidden_evidence=frozenset(),
    )
    field = _Field(incident_id="INC-U", epoch_id=1, worlds=(lonely,))
    challenges = self_question_world(field, "WU", shadow=_Shadow(), graph=None)
    falsify = challenges[0]
    assert falsify.kind is QuestionKind.WHAT_WOULD_FALSIFY
    assert falsify.material is True
    assert "would falsify" in falsify.finding


def test_a_shadowed_absence_is_not_material_but_an_observable_absence_is() -> None:
    """§8's trap: absence only counts where the signal could have been seen."""
    spine = _spine()
    field = _two_world_field(spine)
    blind = self_question_world(
        field,
        "W1",
        shadow=_Shadow(blind=frozenset({"credential_access", "privilege_change"})),
        graph=None,
        observed=frozenset(),
        spine=spine,
    )[4]
    visible = self_question_world(
        field, "W1", shadow=_Shadow(), graph=None, observed=frozenset(), spine=spine
    )[4]
    assert blind.kind is visible.kind is QuestionKind.WHAT_EXPECTED_EVIDENCE_IS_ABSENT
    assert blind.material is False
    assert visible.material is True


def test_an_authoritative_claim_resting_on_a_blind_spot_is_material() -> None:
    spine = _spine()
    field = _two_world_field(spine)
    graph = _Graph(
        claims={
            "C1": _Claim("C1", "OBS", "credential_access"),
            "C2": _Claim("C2", "DER", "privilege_change"),
        },
        authoritative=frozenset({"C1"}),
        rooted=frozenset({"C1", "C2"}),
    )
    shadow = _Shadow(blind=frozenset({"credential_access"}))
    blindness = self_question_world(
        field, "W1", shadow=shadow, graph=graph, observed=frozenset(), spine=spine
    )[2]
    assert blindness.material is True
    assert blindness.claim_ids_affected == ("C1",)

    safe = self_question_world(
        field, "W1", shadow=_Shadow(blind=frozenset({"module_load"})), graph=graph, spine=spine
    )[2]
    assert safe.material is False
    assert safe.claim_ids_affected == ()


def test_an_external_mapping_with_no_observation_under_it_is_material() -> None:
    spine = _spine()
    field = _two_world_field(spine)
    graph = _Graph(
        claims={"X1": _Claim("X1", "EXT", "credential"), "O1": _Claim("O1", "OBS", "credential")},
        authoritative=frozenset({"O1"}),
        rooted=frozenset({"O1"}),
    )
    external = self_question_world(
        field, "W1", shadow=_Shadow(), graph=graph, spine=spine
    )[7]
    assert external.material is True
    assert external.claim_ids_affected == ("X1",)


def test_responsibility_concentration_fires_on_a_single_event_world() -> None:
    spine = _spine(1)
    field = _two_world_field(spine)
    concentrated = self_question_world(
        field, "W1", shadow=_Shadow(), graph=None, spine=spine
    )[3]
    assert concentrated.kind is QuestionKind.WHICH_EVENT_CARRIES_TOO_MUCH
    assert concentrated.answered is True
    assert concentrated.material is True


def test_unanswerable_questions_are_never_material_and_never_counted() -> None:
    spine = _spine()
    field = _two_world_field(spine)
    challenges = self_question_world(field, "W1", shadow=_Shadow(), graph=None, spine=())
    unanswered = tuple(c for c in challenges if not c.answered)
    assert unanswered, "with no spine and no graph some questions must be unanswerable"
    assert all(not c.material for c in unanswered)
    assert all(c.answered for c in materially_challenged(challenges))
    with pytest.raises(ContractError, match="cannot be material"):
        Challenge(
            kind=QuestionKind.WHAT_WOULD_FALSIFY, answered=False, finding="x", material=True
        )


def test_finding_nothing_is_not_yet_justified_and_never_rejected() -> None:
    """F8's distinction, in code: ADR-0009's lesson about a corpus with no headroom."""
    barren = [
        [
            Challenge(kind=kind, answered=True, finding="nothing", material=False)
            for kind in QuestionKind
        ]
        for _ in range(5)
    ]
    verdict, counts = judge_self_questioning(barren)
    assert verdict is SelfQuestioningVerdict.NOT_YET_JUSTIFIED
    assert counts["_answered"] == 40
    assert set(verdict.__class__) == {
        SelfQuestioningVerdict.MATERIAL,
        SelfQuestioningVerdict.NOT_YET_JUSTIFIED,
    }, "no REJECTED verdict may exist here"

    barren[0][0] = Challenge(
        kind=QuestionKind.WHAT_WOULD_FALSIFY, answered=True, finding="!", material=True
    )
    verdict, counts = judge_self_questioning(barren)
    assert verdict is SelfQuestioningVerdict.MATERIAL
    assert counts[QuestionKind.WHAT_WOULD_FALSIFY.value] == 1


def test_self_question_world_refuses_an_unknown_world() -> None:
    field = _two_world_field(_spine())
    with pytest.raises(ContractError, match="not in incident"):
        self_question_world(field, "missing", shadow=None, graph=None)


# --- D4.7: incident future cones (§15) ---------------------------------------


def test_discriminating_signals_is_a_symmetric_difference() -> None:
    spine = _spine()
    field = _two_world_field(spine)
    cones = compose_cones(field)
    left, right = cones["W1"], cones["W2"]
    assert left.discriminating_signals(right) == right.discriminating_signals(left)
    expected = left.predicted_signals() ^ right.predicted_signals()
    assert left.discriminating_signals(right) == expected
    assert expected, "two differently-stated worlds must predict something different"


def test_two_identical_worlds_offer_no_discriminating_observation() -> None:
    """The input non-identifiability needs: no observation separates the pair."""
    spine = _spine()
    world = _two_world_field(spine).world("W1")
    assert world is not None
    twin = replace(world, world_id="W1b", mechanism_id="compromised_admin_session_b")
    field = _Field(incident_id="INC-NI", epoch_id=1, worlds=(world, twin))
    cones = compose_cones(field)
    assert cones["W1"].discriminating_signals(cones["W1b"]) == frozenset()
    pairs = pairwise_discriminating_signals(cones)
    assert pairs[("W1", "W1b")] == frozenset()


def test_cone_is_bounded_and_counts_every_branch_it_drops() -> None:
    spine = _spine()
    world = _two_world_field(spine).world("W1")
    assert world is not None
    rich = replace(
        world,
        expected_evidence=frozenset(
            {"credential_access", "persistence_write", "file_staging", "authentication"}
        ),
        latent_state=_Latent(
            _compromised_state().raised_to("persistence", Persistence.SERVICE),
            frozenset({"privilege", "credential", "persistence", "reachability"}),
            phi(_compromised_state()).total,
        ),
    )
    full = predict_world_future_cone(rich, depth=MAX_CONE_DEPTH)
    assert len(full.branches) <= MAX_BRANCHES_PER_WORLD
    assert full.truncated_branches > 0, "a rich world must exceed the branch bound"
    assert all(b.depth <= MAX_CONE_DEPTH for b in full.branches)
    # Truncation drops the least consequential branch, never the most.
    assert full.branches[0].consequence == full.max_consequence()
    with pytest.raises(ContractError, match="depth"):
        predict_world_future_cone(rich, depth=MAX_CONE_DEPTH + 1)


def test_inconsequential_branches_are_dropped_and_counted() -> None:
    benign = _World(
        world_id="WB",
        mechanism_id="legitimate_automation",
        latent_state=_Latent(SecurityStateV1(), frozenset(), 0.0),
        support=_Support(value=1.0),
        expected_evidence=frozenset({"authentication"}),
    )
    cone = predict_world_future_cone(benign)
    assert all(b.consequence >= MIN_BRANCH_CONSEQUENCE for b in cone.branches)
    assert cone.truncated_branches >= 1, "session_end on a benign world carries no consequence"
    assert "session_end" not in {b.label for b in cone.branches}


def test_collapse_prunes_contradicted_branches_and_is_not_a_truncation() -> None:
    spine = _spine()
    world = _two_world_field(spine).world("W1")
    assert world is not None
    cone = predict_world_future_cone(world)
    assert cone.branches
    collapsed = cone.collapse(frozenset({"session_teardown"}))
    assert len(collapsed.branches) < len(cone.branches)
    assert collapsed.truncated_branches == cone.truncated_branches
    assert cone.collapse(frozenset({"nothing_relevant"})) is cone


def test_branch_refuses_an_invented_signal_a_bad_depth_and_a_self_contradiction() -> None:
    with pytest.raises(ContractError, match="closed vocabulary"):
        CausalBranch(
            branch_id="b",
            label="persistence",
            predicted_signals=frozenset({"made_up_signal"}),
            forbidden_signals=frozenset(),
            raises_dimensions=frozenset({"persistence"}),
            consequence=1.0,
            depth=1,
        )
    with pytest.raises(ContractError, match="depth"):
        CausalBranch(
            branch_id="b",
            label="persistence",
            predicted_signals=frozenset({"persistence_write"}),
            forbidden_signals=frozenset(),
            raises_dimensions=frozenset({"persistence"}),
            consequence=1.0,
            depth=MAX_CONE_DEPTH + 1,
        )
    with pytest.raises(ContractError, match="unknown dimensions"):
        CausalBranch(
            branch_id="b",
            label="persistence",
            predicted_signals=frozenset({"persistence_write"}),
            forbidden_signals=frozenset(),
            raises_dimensions=frozenset({"not_a_dimension"}),
            consequence=1.0,
            depth=1,
        )
    with pytest.raises(ContractError, match="unknown branch label"):
        CausalBranch(
            branch_id="b",
            label="exfiltration",
            predicted_signals=frozenset({"persistence_write"}),
            forbidden_signals=frozenset(),
            raises_dimensions=frozenset(),
            consequence=1.0,
            depth=1,
        )


def test_cone_refuses_more_branches_than_the_bound_and_duplicate_ids() -> None:
    branch = CausalBranch(
        branch_id="b1",
        label="persistence",
        predicted_signals=frozenset({"persistence_write"}),
        forbidden_signals=frozenset(),
        raises_dimensions=frozenset({"persistence"}),
        consequence=1.0,
        depth=1,
    )
    with pytest.raises(ContractError, match="at most"):
        IncidentFutureCone(world_id="W", branches=(branch,) * (MAX_BRANCHES_PER_WORLD + 1))
    with pytest.raises(ContractError, match="duplicate"):
        IncidentFutureCone(world_id="W", branches=(branch, branch))
    with pytest.raises(ContractError, match="non-negative"):
        IncidentFutureCone(world_id="W", branches=(branch,), truncated_branches=-1)


def test_compose_cones_covers_every_world_and_stays_within_the_incident_bound() -> None:
    spine = _spine()
    field = _two_world_field(spine)
    extra = tuple(
        replace(field.worlds[0], world_id=f"W{i}", mechanism_id=f"mech_{i}")
        for i in range(3, 9)
    )
    wide = field.with_worlds((*field.worlds, *extra))
    cones = compose_cones(wide)
    assert set(cones) == {w.world_id for w in wide.worlds}
    total = sum(len(c.branches) for c in cones.values())
    assert total <= MAX_BRANCHES_PER_WORLD * len(wide.worlds)


# --- a measured, within-run ratio (§2.8: never an absolute figure) ------------


def test_counterfactual_work_units_are_linear_in_both_worlds_and_spine() -> None:
    """The cost model, measured in the same run as its own control.

    Work units are the contract (§2.8): wall clock on this host is contended enough that
    a 7x inflation has already been observed between two runs of the same gate. The
    spine term exists because a measured run showed a 48-node spine costing 2.664x the
    wall clock of a 6-node spine while a world-only charge stayed flat — a budget blind
    to that is one an attacker starves by growing the spine.
    """
    spine = _spine(6)
    single = _two_world_field(spine)
    single = single.with_worlds((single.worlds[0],))
    wide = _two_world_field(spine)
    wide = wide.with_worlds(
        (
            *wide.worlds,
            *(
                replace(wide.worlds[0], world_id=f"Wx{i}", mechanism_id=f"mech_x{i}")
                for i in range(6)
            ),
        )
    )
    target = Intervention(
        kind=InterventionKind.REMOVE_EVENT, target_signature=spine[0].signature
    )
    one = counterfactual_intervene(single, target, spine=spine)
    many = counterfactual_intervene(wide, target, spine=spine)
    assert len(wide.worlds) == 8 and len(single.worlds) == 1 and len(spine) == 6
    # base 2 + K + |spine|: 9 units at K=1, 16 at K=8, so +1 unit per extra world.
    assert one.work_units == 9
    assert many.work_units == 16
    assert many.work_units - one.work_units == len(wide.worlds) - len(single.worlds)

    long_spine = _spine(48)
    long_field = _two_world_field(long_spine)
    long_field = long_field.with_worlds((long_field.worlds[0],))
    longer = counterfactual_intervene(
        long_field,
        Intervention(
            kind=InterventionKind.REMOVE_EVENT, target_signature=long_spine[0].signature
        ),
        spine=long_spine,
    )
    assert longer.work_units - one.work_units == len(long_spine) - len(spine)
