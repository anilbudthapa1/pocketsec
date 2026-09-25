"""Stage 4 work package 1 — D4.1, D4.19 and D4.18's base corpus.

These tests are about *refusals*, not construction. Every mechanism in this package
exists to make an illegal state unconstructable, so the tests that matter are the ones
that try to construct one:

* a world that asserts a capability its own latent state does not hold (§21);
* a world whose support is read as a probability when its geometry is a log-odds (§11);
* a field holding two worlds with one mechanism, which is a fusion that did not happen;
* a dataclass field naming response authority (T5) — over **every** forbidden token, so
  an exemption list cannot be slipped in later;
* a corpus whose classes differ in vocabulary, which would hand a counting model a free
  perfect score.

Four corpus tests are mandatory because each has already cost this project a published
wrong answer: session-unique identities, non-zero per-class median ΔΦ asserted *before*
any mechanism is measured, no vocabulary signal, and a world flood whose ground truth is
still recoverable.
"""

from __future__ import annotations

import dataclasses
import math
from collections import Counter
from dataclasses import dataclass

import pytest

from pocketsec.stage0.benchmark.security_metrics import average_precision
from pocketsec.stage0.contracts.common import ContractError, EvidenceRef, SCHEMA_REGISTRY
from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS
from pocketsec.stage1.compiler.entity_registry import (
    AUTHORIZATION_PATHS,
    CREDENTIAL_PATHS,
    PERSISTENCE_PATHS,
)
from pocketsec.stage1.observation.policy import MANDATORY_SIGNALS
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage1.state.potential import phi
from pocketsec.stage1.state.security_state import (
    DIMENSIONS,
    CredentialExposure,
    Privilege,
    Reachability,
    SecurityStateV1,
)
from pocketsec.stage4.core_ids import (
    ABLATION_FLAGS,
    CBF_INTERFACE_ID,
    CBF_INTERFACE_VERSION,
    CORE_IDS,
    OPTIONAL_IDS,
    REQUIRED_IDS,
    CoreFunction,
    FunctionClass,
    core_function,
)
from pocketsec.stage4.labs.incident_corpus import (
    EXPECTED_STATES,
    FAMILY_BANDS,
    INCIDENT_CORPUS_VERSION,
    MECHANISM_BY_LABEL,
    RENAME_MAP,
    SPURIOUS_MECHANISM_ID,
    WORLD_LABELS,
    GroundTruthWorld,
    IncidentCase,
    build_decoy_variants,
    build_incident_corpus,
    build_low_and_slow_variants,
    build_rename_variants,
    build_shared_prefix_pairs,
    build_world_flood,
    chain_owner_identity,
    decoy_cases,
    identity_keys,
    identity_namespace,
    median_peak_delta_phi,
    operation_counts,
    operation_share_gap,
    pooled_order_free_scores,
    reidentify,
)
from pocketsec.stage4.theory import (
    CBF_THEORY_VERSION,
    DEFINITIONS,
    MAX_DEFINITIONS,
    Definition,
    definition,
    resolve_binding,
    unbound_terms,
)
from pocketsec.stage4.worlds.field import (
    CAUSAL_BELIEF_FIELD_V1_ID,
    MAX_WORLDS,
    MAX_WORLDS_CEILING,
    UNKNOWN_MECHANISM_ID,
    CausalBeliefField,
    unknown_world,
)
from pocketsec.stage4.worlds.world import (
    MAX_EXPECTED_SIGNALS,
    MAX_FORBIDDEN_SIGNALS,
    MAX_LOG_ODDS,
    MAX_WORLD_BYTES,
    MAX_WORLD_FISSION_DEPTH,
    SECURITY_WORLD_V1_ID,
    BeliefGeometry,
    LatentSecurityState,
    SecurityWorldV1,
    WorldSupport,
    WorldSupportState,
    authority_named_fields,
)

# --- shared builders ---------------------------------------------------------

ADMIN_STATE = SecurityStateV1(privilege=Privilege.ROOT)
EXFIL_STATE = SecurityStateV1(
    privilege=Privilege.ROOT,
    credential=CredentialExposure.READABLE,
    reachability=Reachability.EXTERNAL,
)


def make_world(
    world_id: str = "w-1",
    *,
    mechanism_id: str = "approved_administration",
    state: SecurityStateV1 = ADMIN_STATE,
    asserted: frozenset[str] = frozenset({"privilege"}),
    expected: frozenset[str] = frozenset({"authentication"}),
    forbidden: frozenset[str] = frozenset({"module_load"}),
    support: WorldSupport | None = None,
    **overrides: object,
) -> SecurityWorldV1:
    fields: dict[str, object] = {
        "world_id": world_id,
        "mechanism_id": mechanism_id,
        "latent_state": LatentSecurityState.from_state(state, asserted),
        "support": support or WorldSupport(BeliefGeometry.LOG_ODDS, 0.0),
        "support_state": WorldSupportState.PROVISIONAL,
        "expected_evidence": expected,
        "forbidden_evidence": forbidden,
        "contradictions": (),
        "tension": None,
        "uncertainty": 0.4,
        "visibility_requirements": frozenset({"authentication"}),
        "spine_signatures": ("sig-a",),
        "evidence_refs": (),
        "born_at_sequence": 0,
    }
    fields.update(overrides)
    return SecurityWorldV1(**fields)  # type: ignore[arg-type]


def make_field(*worlds: SecurityWorldV1, **overrides: object) -> CausalBeliefField:
    return CausalBeliefField(
        incident_id="inc-0001", epoch_id=0, worlds=worlds, **overrides  # type: ignore[arg-type]
    )


# === D4.19 — core functional ids =============================================


def test_the_cbf_interface_schema_is_registered() -> None:
    assert SCHEMA_REGISTRY[CBF_INTERFACE_ID] == CBF_INTERFACE_VERSION == "1.0.0"


def test_twenty_ids_map_one_to_one_onto_the_architectures_luc_ids_in_order() -> None:
    assert [fn.core_id for fn in CORE_IDS.values()] == [f"CBF-F{i:02d}" for i in range(1, 21)]
    assert [fn.architecture_id for fn in CORE_IDS.values()] == [
        f"LUC-F{i:02d}" for i in range(1, 21)
    ]


def test_every_id_is_required_or_optional_and_never_both() -> None:
    assert set(REQUIRED_IDS) | set(OPTIONAL_IDS) == set(CORE_IDS)
    assert not set(REQUIRED_IDS) & set(OPTIONAL_IDS)
    assert len(REQUIRED_IDS) + len(OPTIONAL_IDS) == 20


def test_the_optional_set_is_the_spec_table_verbatim() -> None:
    """The D4.19 table enumerates **ten** OPTIONAL ids; its prose says nine.

    Pinned here rather than resolved by judgement. The table is the enumeration and the
    architect's instruction was to take it verbatim, so the count is ten: F04/F05
    (fission-fusion), F08 (sequential evidence), F09/F10 (counterfactual), F13/F14
    (active sensing), F15/F16 (self-question and stress), F19 (cell feedback). If a
    later wave reconciles the prose, this test is the record of what was built.
    """
    assert set(OPTIONAL_IDS) == {
        "CBF-F04",
        "CBF-F05",
        "CBF-F08",
        "CBF-F09",
        "CBF-F10",
        "CBF-F13",
        "CBF-F14",
        "CBF-F15",
        "CBF-F16",
        "CBF-F19",
    }
    assert len(OPTIONAL_IDS) == 10


def test_every_optional_id_names_the_flag_that_removes_it() -> None:
    """G4.10 sets a flag; it does not edit code. A flagless optional cannot be ablated."""
    assert set(ABLATION_FLAGS) == set(OPTIONAL_IDS)
    assert all(ABLATION_FLAGS[core_id] for core_id in OPTIONAL_IDS)
    assert ABLATION_FLAGS["CBF-F04"] == ABLATION_FLAGS["CBF-F05"] == "enable_fission_fusion"
    assert ABLATION_FLAGS["CBF-F09"] == ABLATION_FLAGS["CBF-F10"] == "enable_counterfactual"


def test_a_required_id_carries_no_flag_and_an_optional_one_must() -> None:
    for core_id in REQUIRED_IDS:
        assert CORE_IDS[core_id].ablation_flag == ""
    with pytest.raises(ContractError, match="may not name an ablation flag"):
        CoreFunction("X", "LUC-F01", "n", "p", FunctionClass.REQUIRED, "D4.2", "enable_x")
    with pytest.raises(ContractError, match="must name the flag that removes it"):
        CoreFunction("X", "LUC-F01", "n", "p", FunctionClass.OPTIONAL, "D4.2", "")


def test_every_id_names_a_real_deliverable_and_lookup_fails_loudly() -> None:
    for fn in CORE_IDS.values():
        assert fn.deliverable.startswith("D4.") and fn.deliverable[3:].isdigit()
        assert fn.name and fn.purpose
    assert core_function("CBF-F12").name == "test_identifiability"
    with pytest.raises(KeyError, match="unknown Stage 4 core id"):
        core_function("CBF-F99")


# === D4.1 — the theory table ==================================================


def test_the_definition_table_is_bounded_and_covers_at_least_twenty_constructs() -> None:
    assert CBF_THEORY_VERSION == "stage4-cbf-theory-v1.0.0"
    assert 20 <= len(DEFINITIONS) <= MAX_DEFINITIONS
    assert len({d.term for d in DEFINITIONS}) == len(DEFINITIONS)
    assert all(d.architecture_section.startswith("§") for d in DEFINITIONS)


def test_a_definition_without_a_falsifier_is_refused() -> None:
    """§51: a new name is not proof of novelty, so a construct with no falsifier is a label."""
    with pytest.raises(ContractError, match="names no falsifier"):
        Definition("t", "§7", "f", "pocketsec.stage4.theory.DEFINITIONS", "m", "")
    with pytest.raises(ContractError, match="bound_to must be non-empty"):
        Definition("t", "§7", "f", "", "m", "would refute it")


def test_definition_lookup_fails_loudly_on_an_unknown_term() -> None:
    assert definition("evidence_tension").architecture_section == "§7"
    with pytest.raises(ContractError, match="no Stage 4 definition for term"):
        definition("evidence_vibes")


def test_resolve_binding_walks_modules_and_attributes_and_raises_when_absent() -> None:
    """``unbound_terms`` must *resolve*, not read a list someone maintained by hand."""
    assert resolve_binding("pocketsec.stage4.worlds.field.CausalBeliefField") is CausalBeliefField
    assert (
        resolve_binding("pocketsec.stage4.worlds.world.WorldSupport.as_probability")
        is WorldSupport.as_probability
    )
    # ``pocketsec.stage4`` is importable, so a missing submodule surfaces as an
    # AttributeError on the package rather than an ImportError. ``unbound_terms`` must
    # therefore catch both, and this pins the pair it catches.
    with pytest.raises((ImportError, AttributeError)):
        resolve_binding("pocketsec.stage4.nowhere.Nothing")
    with pytest.raises(AttributeError):
        resolve_binding("pocketsec.stage4.theory.NoSuchSymbol")
    with pytest.raises(ImportError):
        resolve_binding("notapackage.Nothing")


def test_every_definition_bound_to_this_package_already_resolves() -> None:
    """G4.7 asserts ``unbound_terms() == ()`` at the end of the wave.

    Package 1 can only assert the half it owns: nothing this package is responsible for
    may be unbound, and every term reported as unbound must genuinely fail to resolve.
    """
    missing = unbound_terms()
    owned = {"causal_belief_field", "latent_security_state", "belief_geometry"}
    stranded = sorted(owned & set(missing))
    assert not stranded, f"foundation definitions unbound: {stranded}"
    for term in missing:
        with pytest.raises((ImportError, AttributeError)):
            resolve_binding(definition(term).bound_to)


# === D4.1 (continued) — WorldSupport and belief geometry ======================


def test_only_a_calibrated_probability_reads_back_as_a_probability() -> None:
    """§11's whole point: a log-odds, an e-value and an interval are not probabilities."""
    assert WorldSupport(BeliefGeometry.CALIBRATED_PROBABILITY, 0.75).as_probability() == 0.75
    assert WorldSupport(BeliefGeometry.LOG_ODDS, 2.0).as_probability() is None
    assert WorldSupport(BeliefGeometry.E_VALUE, 20.0).as_probability() is None
    assert (
        WorldSupport(BeliefGeometry.EVIDENCE_INTERVAL, 0.0, (-1.0, 1.0)).as_probability() is None
    )


def test_support_refuses_a_half_declared_representation() -> None:
    with pytest.raises(ContractError, match="must carry its interval"):
        WorldSupport(BeliefGeometry.EVIDENCE_INTERVAL, 0.0)
    with pytest.raises(ContractError, match="may not carry an interval"):
        WorldSupport(BeliefGeometry.LOG_ODDS, 0.0, (-1.0, 1.0))
    with pytest.raises(ContractError, match="outside its interval"):
        WorldSupport(BeliefGeometry.EVIDENCE_INTERVAL, 5.0, (-1.0, 1.0))
    with pytest.raises(ContractError, match="e-value is strictly positive"):
        WorldSupport(BeliefGeometry.E_VALUE, 0.0)
    with pytest.raises(ContractError, match="within"):
        WorldSupport(BeliefGeometry.CALIBRATED_PROBABILITY, 1.5)
    with pytest.raises(ContractError, match="must be finite"):
        WorldSupport(BeliefGeometry.LOG_ODDS, float("inf"))


def test_combine_stays_inside_its_geometry_and_is_bounded() -> None:
    log_odds = WorldSupport(BeliefGeometry.LOG_ODDS, 1.0).combine(2.0)
    assert log_odds.geometry is BeliefGeometry.LOG_ODDS
    assert log_odds.value == pytest.approx(3.0)

    probability = WorldSupport(BeliefGeometry.CALIBRATED_PROBABILITY, 0.5).combine(math.log(3.0))
    assert probability.as_probability() == pytest.approx(0.75)

    e_value = WorldSupport(BeliefGeometry.E_VALUE, 2.0).combine(math.log(5.0))
    assert e_value.value == pytest.approx(10.0)

    interval = WorldSupport(BeliefGeometry.EVIDENCE_INTERVAL, 0.0, (-1.0, 1.0)).combine(2.0)
    assert interval.interval == pytest.approx((1.0, 3.0))

    # An unbounded accumulator is how a flood turns support into inf and every
    # comparison into nan. The clamp is the bound, and it is monotone up to it.
    saturated = WorldSupport(BeliefGeometry.LOG_ODDS, MAX_LOG_ODDS).combine(1000.0)
    assert saturated.value == MAX_LOG_ODDS
    assert math.isfinite(WorldSupport(BeliefGeometry.E_VALUE, 1e5).combine(500.0).value)


# === D4.1 (continued) — LatentSecurityState and semantic conservation =========


def test_a_world_may_not_assert_a_capability_its_latent_state_does_not_hold() -> None:
    """§21 made mechanical: abstraction is allowed, factual amplification is not."""
    with pytest.raises(ContractError, match="does not hold them"):
        LatentSecurityState.from_state(ADMIN_STATE, {"credential"})
    with pytest.raises(ContractError, match="not in DIMENSIONS"):
        LatentSecurityState.from_state(ADMIN_STATE, {"vibes"})


def test_a_world_may_not_overstate_its_own_consequence() -> None:
    """A fabricated Φ would let a world win a leadership comparison it did not earn."""
    honest = phi(EXFIL_STATE).total
    assert LatentSecurityState(EXFIL_STATE, frozenset({"credential"}), honest).consequence == honest
    with pytest.raises(ContractError, match="does not equal phi"):
        LatentSecurityState(EXFIL_STATE, frozenset({"credential"}), honest + 5.0)


def test_raises_reports_only_what_the_world_committed_to() -> None:
    latent = LatentSecurityState.from_state(EXFIL_STATE, {"credential", "reachability"})
    assert latent.raises("credential") and latent.raises("reachability")
    assert not latent.raises("privilege")  # held by the state, but not asserted


# === D4.1 (continued) — SecurityWorldV1 refusals ==============================


def test_the_security_world_schema_is_registered() -> None:
    assert SCHEMA_REGISTRY[SECURITY_WORLD_V1_ID] == "1.0.0"
    assert SCHEMA_REGISTRY[CAUSAL_BELIEF_FIELD_V1_ID] == "1.0.0"


def test_a_world_that_both_predicts_and_forbids_a_signal_is_refused() -> None:
    """Such a world cannot be falsified by that signal, so it is unkillable."""
    with pytest.raises(ContractError, match="unkillable"):
        make_world(
            expected=frozenset({"credential_access"}),
            forbidden=frozenset({"credential_access"}),
        )


def test_a_world_refuses_out_of_range_uncertainty_and_oversized_signal_sets() -> None:
    with pytest.raises(ContractError, match="within"):
        make_world(uncertainty=1.5)
    with pytest.raises(ContractError, match="within"):
        make_world(uncertainty=-0.1)
    with pytest.raises(ContractError, match="bound is 32"):
        make_world(expected=frozenset(f"sig-{i}" for i in range(MAX_EXPECTED_SIGNALS + 1)))
    with pytest.raises(ContractError, match="bound is 16"):
        make_world(forbidden=frozenset(f"bad-{i}" for i in range(MAX_FORBIDDEN_SIGNALS + 1)))


def test_a_world_refuses_unbounded_fission_depth() -> None:
    assert make_world(fission_depth=MAX_WORLD_FISSION_DEPTH).fission_depth == 2
    with pytest.raises(ContractError, match="denial of service"):
        make_world(fission_depth=MAX_WORLD_FISSION_DEPTH + 1)


def test_the_constructor_side_fission_bound_equals_the_lifecycle_constant() -> None:
    """Two constants for one rule must not be allowed to drift apart.

    ``worlds/lifecycle.py`` owns ``MAX_FISSION_DEPTH`` and importing it from
    ``world.py`` would close a cycle, so the bound is duplicated under a second name.
    This test is what keeps the duplication honest; it begins asserting as soon as the
    lifecycle package exists.
    """
    try:
        from pocketsec.stage4.worlds.lifecycle import MAX_FISSION_DEPTH
    except ImportError:  # pragma: no cover - lifecycle is a later work package
        assert MAX_WORLD_FISSION_DEPTH == 2
        return
    assert MAX_WORLD_FISSION_DEPTH == MAX_FISSION_DEPTH


def test_a_world_that_serialises_past_the_byte_bound_is_refused() -> None:
    """§44 requires KB-scale worlds, measured on what would actually be persisted."""
    small = make_world()
    assert 0 < small.state_bytes() <= MAX_WORLD_BYTES
    assert small.state_bytes() == make_world().state_bytes()  # deterministic
    fat = tuple(
        EvidenceRef("store", f"locator-{i:04d}", "sha256:" + f"{i:064x}") for i in range(64)
    )
    with pytest.raises(ContractError, match="KB-scale"):
        make_world(evidence_refs=fat, spine_signatures=tuple(f"sig-{i:040d}" for i in range(64)))


def test_predicts_forbids_and_observational_equivalence_ignore_support() -> None:
    """§14 fuses on *observables*: same predictions plus same consequence is one hypothesis."""
    left = make_world("a", mechanism_id="m-a")
    right = make_world(
        "b", mechanism_id="m-b", support=WorldSupport(BeliefGeometry.LOG_ODDS, 9.0)
    )
    assert left.predicts("authentication") and left.forbids("module_load")
    assert not left.predicts("credential_access")
    assert left.observationally_equivalent(right, epsilon=0.0)
    different = make_world("c", mechanism_id="m-c", expected=frozenset({"persistence_write"}))
    assert not left.observationally_equivalent(different, epsilon=10.0)
    with pytest.raises(ContractError, match="epsilon must be non-negative"):
        left.observationally_equivalent(right, epsilon=-0.1)


def test_consequence_separates_worlds_only_outside_epsilon() -> None:
    admin = make_world("a", mechanism_id="m-a")
    exfil = make_world(
        "b", mechanism_id="m-b", state=EXFIL_STATE, asserted=frozenset({"privilege"})
    )
    gap = abs(admin.latent_state.consequence - exfil.latent_state.consequence)
    assert gap > 0.0
    assert not admin.observationally_equivalent(exfil, epsilon=gap / 2)
    assert admin.observationally_equivalent(exfil, epsilon=gap)


# === T5 — the authority audit, with no exemption list ========================


@pytest.mark.parametrize("token", sorted(FORBIDDEN_AUTHORITY_FIELDS))
def test_every_forbidden_token_is_caught_in_a_field_name(token: str) -> None:
    """The invariant-weakening test.

    If anyone adds an exemption list to ``authority_named_fields``, or narrows the token
    set, one of these parametrised cases stops raising. The architecture's own §9 writes
    ``do(block privilege transition)``, so the pressure to add an exemption is real and
    this is what resists it.
    """

    @dataclass(frozen=True, slots=True)
    class Tempting:
        world_id: str
        # Constructed field name, e.g. "recommended_privilege_hint".
        __annotations__[f"recommended_{token}_hint"] = str

    assert authority_named_fields(Tempting) == (f"recommended_{token}_hint",)


def test_the_shipped_foundation_types_name_no_authority() -> None:
    for cls in (SecurityWorldV1, LatentSecurityState, WorldSupport, CausalBeliefField):
        assert authority_named_fields(cls) == ()


def test_a_world_subclass_naming_authority_is_refused_at_construction() -> None:
    """The audit runs in ``__post_init__``, so subclassing cannot bypass it.

    It is also the **first** refusal, before any value is validated: a type that names
    authority must be rejected before anything else about it is discussed.
    """

    @dataclass(frozen=True, slots=True)
    class LoudWorld(SecurityWorldV1):
        recommended_action: str = ""

    honest = make_world()
    kwargs = {f.name: getattr(honest, f.name) for f in dataclasses.fields(SecurityWorldV1)}
    assert authority_named_fields(LoudWorld) == ("recommended_action",)
    with pytest.raises(ContractError, match="carries no authority"):
        LoudWorld(**kwargs)


# === D4.1 (continued) — CausalBeliefField ====================================


def test_the_field_is_bounded_by_construction() -> None:
    assert MAX_WORLDS == 8 and MAX_WORLDS_CEILING == 16
    worlds = tuple(make_world(f"w-{i}", mechanism_id=f"m-{i}") for i in range(MAX_WORLDS + 1))
    with pytest.raises(ContractError, match="must prune and record a Truncation"):
        make_field(*worlds)
    with pytest.raises(ContractError, match="exceeds the explicit ceiling"):
        make_field(max_worlds=MAX_WORLDS_CEILING + 1)
    with pytest.raises(ContractError, match="at least 1"):
        make_field(max_worlds=0)


def test_the_field_refuses_duplicate_ids_and_duplicate_mechanisms() -> None:
    with pytest.raises(ContractError, match="duplicate world_ids"):
        make_field(make_world("w", mechanism_id="m-a"), make_world("w", mechanism_id="m-b"))
    with pytest.raises(ContractError, match="fusion that did not happen"):
        make_field(make_world("w-1", mechanism_id="m"), make_world("w-2", mechanism_id="m"))


def test_the_support_vector_refuses_to_compare_incomparable_geometries() -> None:
    """An e-value of 3.0 and a log-odds of 3.0 are not comparable magnitudes (§11)."""
    mixed = make_field(
        make_world("a", mechanism_id="m-a", support=WorldSupport(BeliefGeometry.LOG_ODDS, 3.0)),
        make_world("b", mechanism_id="m-b", support=WorldSupport(BeliefGeometry.E_VALUE, 3.0)),
    )
    with pytest.raises(ContractError, match="mixes belief geometries"):
        mixed.support_vector()


def test_the_support_vector_is_a_share_and_never_a_probability_claim() -> None:
    field = make_field(
        make_world("a", mechanism_id="m-a", support=WorldSupport(BeliefGeometry.LOG_ODDS, 1.0)),
        make_world("b", mechanism_id="m-b", support=WorldSupport(BeliefGeometry.LOG_ODDS, 0.0)),
    )
    shares = field.support_vector()
    assert math.fsum(shares.values()) == pytest.approx(1.0)
    assert shares["a"] > shares["b"]
    # The share is derived; the support itself still refuses to be a probability.
    assert all(w.support.as_probability() is None for w in field.worlds)
    assert make_field().support_vector() == {}


def test_support_distance_is_a_bounded_symmetric_divergence() -> None:
    one = make_field(make_world("a", mechanism_id="m-a"))
    two = make_field(make_world("b", mechanism_id="m-b"))
    assert one.support_distance(one) == pytest.approx(0.0)
    # Disjoint world ids put the two fields' mass on different outcomes entirely.
    assert one.support_distance(two) == pytest.approx(1.0)
    assert one.support_distance(two) == pytest.approx(two.support_distance(one))
    empty = make_field()
    assert empty.support_distance(empty) == 0.0
    # Going from no hypothesis to a hypothesis is the largest move there is; 0.0 here
    # would tell the sensor planner that spawning the first world was worthless.
    assert one.support_distance(empty) == 1.0

    shifted = one.with_worlds(
        (
            make_world("a", mechanism_id="m-a"),
            make_world("b", mechanism_id="m-b", support=WorldSupport(BeliefGeometry.LOG_ODDS, 1.0)),
        )
    )
    moved = one.support_distance(shifted)
    assert 0.0 < moved < 1.0


def test_leaders_are_deterministic_and_tie_break_on_world_id() -> None:
    field = make_field(
        make_world("z", mechanism_id="m-z"),
        make_world("a", mechanism_id="m-a"),
        make_world("m", mechanism_id="m-m", support=WorldSupport(BeliefGeometry.LOG_ODDS, 5.0)),
    )
    assert [w.world_id for w in field.leaders(n=3)] == ["m", "a", "z"]
    assert field.leaders(n=0) == ()
    with pytest.raises(ContractError, match="non-negative"):
        field.leaders(n=-1)


def test_the_field_is_immutable_and_with_worlds_returns_a_new_one() -> None:
    """``support_distance`` needs the predecessor, so a mutated field has no history."""
    original = make_field(make_world("a", mechanism_id="m-a"))
    replaced = original.with_worlds((make_world("b", mechanism_id="m-b"),))
    assert replaced is not original
    assert [w.world_id for w in original.worlds] == ["a"]
    with pytest.raises(dataclasses.FrozenInstanceError):
        original.worlds = ()  # type: ignore[misc]


def test_the_unknown_world_asserts_nothing_and_predicts_nothing() -> None:
    """§12: novelty is not maliciousness, so the UNKNOWN world is the weakest claim."""
    world = unknown_world("inc-0001", at_sequence=7)
    assert world.mechanism_id == UNKNOWN_MECHANISM_ID
    assert world.latent_state.asserted_dimensions == frozenset()
    assert world.latent_state.consequence == 0.0
    assert world.expected_evidence == world.forbidden_evidence == frozenset()
    assert world.support_state is WorldSupportState.UNRESOLVED
    assert world.uncertainty == 1.0
    assert world.support.as_probability() is None
    field = make_field(world)
    assert field.unknown_world() is world
    assert make_field(make_world()).unknown_world() is None
    with pytest.raises(ContractError):
        unknown_world("inc-0001", at_sequence=-1)


def test_the_field_serialises_its_optional_members_through_their_own_contract() -> None:
    """Forward dependencies are structural types; a member that does not satisfy one says so."""

    @dataclass(frozen=True, slots=True)
    class Trunc:
        what: str
        identifier: str
        reason: str
        consequence_lost: float

    field = make_field(
        make_world(), truncations=(Trunc("world", "w-9", "budget_exhausted", 1.25),)
    )
    payload = field.to_dict()
    assert payload["truncations"] == [
        {
            "what": "world",
            "identifier": "w-9",
            "reason": "budget_exhausted",
            "consequence_lost": 1.25,
        }
    ]
    assert payload["sensor_shadow"] is None  # None means NOT YET COMPUTED, never zero
    assert field.state_bytes() > 0

    broken = make_field(make_world(), truncations=(object(),))  # type: ignore[arg-type]
    with pytest.raises(ContractError, match="does not satisfy TruncationLike"):
        broken.to_dict()


def test_a_field_lookup_misses_honestly() -> None:
    field = make_field(make_world("a", mechanism_id="m-a"))
    assert field.world("a") is not None
    assert field.world("nope") is None


# === D4.18 — the base corpus =================================================

CORPUS_COUNT = 60
CORPUS_SEED = 11
#: The vocabulary guard runs at a larger count than the ΔΦ guard because PR-AUC on 20
#: positives is noisy: the same construction reads +0.06 at count=60 seed=11 and -0.01 at
#: seed=23. 240 cases is where the measured gap stops depending on the draw.
VOCABULARY_COUNT = 240
#: Share difference tolerated per operation. Measured at 0.0074 for the base corpus.
MAX_SHARE_GAP = 0.02
#: The mandated band around the base rate for an order-free control.
ORDER_FREE_BAND = 0.05


@pytest.fixture(scope="module")
def corpus() -> tuple[IncidentCase, ...]:
    return build_incident_corpus(count=CORPUS_COUNT, seed=CORPUS_SEED)


def test_the_corpus_version_names_the_corpus_it_is_built_on() -> None:
    assert INCIDENT_CORPUS_VERSION == "stage4-incident-v0.1.0+stage1-ambiguous-v0.1.0"


def test_the_corpus_is_deterministic_under_its_seed(corpus: tuple[IncidentCase, ...]) -> None:
    again = build_incident_corpus(count=CORPUS_COUNT, seed=CORPUS_SEED)
    assert [c.to_dict() for c in corpus] == [c.to_dict() for c in again]
    other = build_incident_corpus(count=CORPUS_COUNT, seed=CORPUS_SEED + 1)
    assert [c.incident_id for c in other] != [c.incident_id for c in corpus]


def test_every_case_carries_a_known_world_and_a_testable_alternative_set(
    corpus: tuple[IncidentCase, ...],
) -> None:
    labels = {c.truth.world_label for c in corpus}
    assert labels == set(WORLD_LABELS), f"the corpus omits {set(WORLD_LABELS) - labels}"
    for case in corpus:
        assert case.truth.mechanism_id == MECHANISM_BY_LABEL[case.truth.world_label]
        assert case.expected_state in EXPECTED_STATES
        assert case.material_alternatives
        assert case.truth.mechanism_id not in case.material_alternatives
        signal = case.truth.discriminating_signal
        assert signal is None or signal in MANDATORY_SIGNALS


def test_the_novel_world_asserts_nothing_and_expects_unknown(
    corpus: tuple[IncidentCase, ...],
) -> None:
    """A mechanism the system cannot name resolves to UNKNOWN, not to SUSPICIOUS."""
    novel = [c for c in corpus if c.truth.world_label == "novel_unresolved"]
    assert novel
    for case in novel:
        assert case.truth.raises_dimensions == frozenset()
        assert case.truth.discriminating_signal is None
        assert case.expected_state == "UNKNOWN"


# --- mandatory corpus test 1: session-unique identities -----------------------


def test_incident_corpus_uses_session_unique_identities(
    corpus: tuple[IncidentCase, ...],
) -> None:
    """Reused identities erase the corpus's own signal before any model sees it.

    ``Stage1Pipeline`` carries lineage state across scenarios, so a shared
    ``(pid, start_time)`` lets capability accumulate between sessions. That defect drove
    the median per-lineage peak ΔΦ to 0.00 for both classes and retracted a +0.042
    result.
    """
    seen: dict[tuple[str, str], str] = {}
    for case in corpus:
        keys = identity_keys(case)
        assert keys, f"{case.incident_id} names no process identity at all"
        for key in keys:
            assert key not in seen, f"{key} shared by {seen[key]} and {case.incident_id}"
            seen[key] = case.incident_id


def test_every_corpus_family_lives_in_its_own_identity_band(
    corpus: tuple[IncidentCase, ...],
) -> None:
    """Families are replayed together, so their bands must not overlap either."""
    base = corpus[0]
    families = [
        corpus,
        build_world_flood(count=8, seed=23),
        build_rename_variants(base, seed=3),
        build_low_and_slow_variants(base, seed=3),
        build_decoy_variants(base, seed=3),
        [member for pair in build_shared_prefix_pairs(count=4, seed=5) for member in pair],
    ]
    seen: dict[tuple[str, str], str] = {}
    for family in families:
        for case in family:
            for key in identity_keys(case):
                assert key not in seen, f"{key} shared by {seen[key]} and {case.incident_id}"
                seen[key] = case.incident_id
    assert len(FAMILY_BANDS) == len(set(FAMILY_BANDS.values()))


def test_identity_namespacing_refuses_to_invent_a_band() -> None:
    assert identity_namespace("base", 0) != identity_namespace("flood", 0)
    with pytest.raises(ContractError, match="add a band to FAMILY_BANDS"):
        identity_namespace("improvised", 0)
    with pytest.raises(ContractError, match="outside the band size"):
        identity_namespace("base", 10**9)


def test_reidentify_preserves_structure_and_ssir_semantics(
    corpus: tuple[IncidentCase, ...],
) -> None:
    """Only identity *values* move: distinct actors stay distinct, semantics are untouched."""
    case = corpus[0]
    moved = reidentify(case.scenario, namespace=identity_namespace("rename", 99_000))
    assert len(moved.behaviours) == len(case.scenario.behaviours)
    assert [b.operation for b in moved.behaviours] == [
        b.operation for b in case.scenario.behaviours
    ]
    original_actors = {b.fields["pid"] for b in case.scenario.behaviours}
    moved_actors = {b.fields["pid"] for b in moved.behaviours}
    assert len(original_actors) == len(moved_actors)
    assert not original_actors & moved_actors
    assert (
        Stage1Pipeline().run_scenario(case.scenario).semantic_keys
        == Stage1Pipeline().run_scenario(moved).semantic_keys
    )


# --- mandatory corpus test 2: non-zero median ΔΦ per class --------------------


def test_incident_corpus_median_delta_phi_is_nonzero_per_class(
    corpus: tuple[IncidentCase, ...],
) -> None:
    """Asserted **before** any mechanism is measured on this corpus.

    A median of 0.00 for either class means the state calculus saw nothing move, and any
    later result over the corpus would be measuring the defect rather than the mechanism.
    """
    medians = median_peak_delta_phi(corpus)
    assert set(medians) == {0, 1}, medians
    for label, median in medians.items():
        assert median > 0.0, f"class {label} has median peak ΔΦ {median}"


# --- mandatory corpus test 3: no vocabulary signal ---------------------------


def test_incident_corpus_carries_no_vocabulary_signal(
    corpus: tuple[IncidentCase, ...],
) -> None:
    """Two corpora already leaked this way, and each handed a counting model a free score.

    Three checks: the operation *vocabulary* is identical across classes, no operation's
    share differs by more than ``MAX_SHARE_GAP``, and a leave-one-out order-free control
    stays within ``ORDER_FREE_BAND`` of the base rate.
    """
    counts = operation_counts(corpus)
    assert set(counts) == {0, 1}
    assert set(counts[0]) == set(counts[1]), "one class emits an operation the other never does"
    assert operation_share_gap(corpus) <= MAX_SHARE_GAP

    wide = build_incident_corpus(count=VOCABULARY_COUNT, seed=CORPUS_SEED)
    labels = [case.label for case in wide]
    base_rate = sum(labels) / len(labels)
    pooled = average_precision(labels, pooled_order_free_scores(wide))
    assert pooled is not None
    assert pooled - base_rate <= ORDER_FREE_BAND, (
        f"an order-free bag-of-operations control reaches {pooled:.4f} against a base rate "
        f"of {base_rate:.4f}; the label is readable from the operation histogram"
    )


def test_the_order_free_control_is_actually_order_free() -> None:
    """A control that could see order would not be measuring what this test claims."""
    cases = build_incident_corpus(count=12, seed=5)
    shuffled = tuple(
        dataclasses.replace(
            case,
            scenario=dataclasses.replace(
                case.scenario, behaviours=tuple(reversed(case.scenario.behaviours))
            ),
        )
        for case in cases
    )
    assert pooled_order_free_scores(cases) == pooled_order_free_scores(shuffled)


# --- mandatory corpus test 4: the flood keeps a recoverable ground truth ------


def test_world_flood_does_not_saturate() -> None:
    """A flood in which the true world is unrecoverable tests nothing about bounds.

    Every session must still contain exactly one actor holding the *complete* capability
    chain, and that actor must be the recorded ``chain_identity``. Every other actor
    holds a partial chain, which is what makes the field want to branch.
    """
    flood = build_world_flood(count=40, seed=23)
    assert len(flood) == 40
    for case in flood:
        by_actor: dict[str, set[str]] = {}
        for behaviour in case.scenario.behaviours:
            by_actor.setdefault(behaviour.fields["pid"], set()).add(behaviour.operation)
        complete = {
            actor
            for actor, operations in by_actor.items()
            if {"setuid", "read", "connect", "send"} <= operations
        }
        assert len(complete) == 1, f"{case.incident_id} has {len(complete)} complete chains"
        assert case.chain_identity is not None
        assert complete == {case.chain_identity[0]}
        assert len(by_actor) > 1, "a flood with one actor cannot make the field branch"


def test_the_flood_is_a_branch_flood_and_not_merely_a_long_session() -> None:
    """Many candidate residuals, each from a different lineage: that is the DoS shape."""
    case = build_world_flood(count=1, seed=23)[0]
    raising = {
        behaviour.fields["pid"]
        for behaviour in case.scenario.behaviours
        if behaviour.operation in {"setuid", "read", "connect"}
    }
    assert len(raising) >= MAX_WORLDS, (
        f"only {len(raising)} lineages produce a capability residual; the flood cannot "
        f"push the field past MAX_WORLDS={MAX_WORLDS}"
    )


# --- §39 rows: the variant families ------------------------------------------


def test_shared_prefix_pairs_share_their_evidence_and_differ_only_in_attribution() -> None:
    """§39 row 1, asserted on SSIR semantics rather than on the construction."""
    pairs = build_shared_prefix_pairs(count=5, seed=7)
    assert len(pairs) == 5
    for malicious, benign in pairs:
        assert malicious.label == 1 and benign.label == 0
        assert malicious.shared_prefix_length == benign.shared_prefix_length > 0
        assert Counter(b.operation for b in malicious.scenario.behaviours) == Counter(
            b.operation for b in benign.scenario.behaviours
        )
        keys_m = Stage1Pipeline().run_scenario(malicious.scenario).semantic_keys
        keys_b = Stage1Pipeline().run_scenario(benign.scenario).semantic_keys
        prefix = malicious.shared_prefix_length
        assert keys_m[:prefix] == keys_b[:prefix], "the shared prefix is not actually shared"
        assert keys_m != keys_b, "the continuations must differ, or the pair tests nothing"


def test_rename_variants_preserve_object_class_and_ssir_semantics(
    corpus: tuple[IncidentCase, ...],
) -> None:
    """§39 row 2. Class preservation is checked against Stage 1's own metadata tables."""
    for old, new in RENAME_MAP.items():
        assert _path_class(old) == _path_class(new), f"{old} -> {new} changes object class"
    for case in corpus[:8]:
        variant = build_rename_variants(case, seed=5)[0]
        assert not identity_keys(variant) & identity_keys(case)
        assert (
            Stage1Pipeline().run_scenario(case.scenario).semantic_keys
            == Stage1Pipeline().run_scenario(variant.scenario).semantic_keys
        ), f"{case.incident_id}: a semantics-preserving rename changed the SSIR keys"


def _path_class(value: str) -> str:
    """Stage 1's host-metadata class for a path or address, by its own tables."""
    if not value.startswith("/"):
        return "external" if not value.startswith(("127.", "10.", "192.168.", "172.1")) else "local"
    if any(marker in value for marker in CREDENTIAL_PATHS):
        return "credential"
    if any(value.startswith(marker) or marker in value for marker in PERSISTENCE_PATHS):
        return "persistence"
    if any(marker in value for marker in AUTHORIZATION_PATHS):
        return "authorization"
    if value.startswith(("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/")):
        return "system_binary"
    return "ordinary"


def test_low_and_slow_variants_stretch_time_and_nothing_else(
    corpus: tuple[IncidentCase, ...],
) -> None:
    """§39 row 5: the operation multiset is identical, so the timing is the only change."""
    case = corpus[1]
    variants = build_low_and_slow_variants(case, seed=5)
    assert len(variants) == 2
    original_gaps = [int(b.fields["_gap_ns"]) for b in case.scenario.behaviours]
    for variant, factor in zip(variants, (60, 1440), strict=True):
        assert Counter(b.operation for b in variant.scenario.behaviours) == Counter(
            b.operation for b in case.scenario.behaviours
        )
        assert [int(b.fields["_gap_ns"]) for b in variant.scenario.behaviours] == [
            gap * factor for gap in original_gaps
        ]


def test_five_base_cases_carry_a_predefined_spurious_explanation(
    corpus: tuple[IncidentCase, ...],
) -> None:
    """G4.6 needs exactly five decoy-bearing cases, provably off the true chain."""
    carriers = decoy_cases(corpus)
    assert len(carriers) == 5
    assert {c.label for c in carriers} == {0, 1}, "decoys must straddle both classes"
    for case in carriers:
        assert case.spurious_mechanism_id == SPURIOUS_MECHANISM_ID
        assert case.decoy_identity is not None
        assert case.chain_identity is not None
        assert case.decoy_identity != case.chain_identity
        decoy_operations = [
            behaviour.operation
            for behaviour in case.scenario.behaviours
            if behaviour.fields["pid"] == case.decoy_identity[0]
        ]
        # The decoy actor does nothing but the decoy: that is "off the true chain".
        assert decoy_operations == ["setuid", "read", "write"]


def test_the_decoy_ancestor_actually_raises_security_potential(
    corpus: tuple[IncidentCase, ...],
) -> None:
    """A decoy with low ΔΦ would not be a *spurious* explanation, just noise."""
    case = decoy_cases(corpus)[0]
    result = Stage1Pipeline().run_scenario(case.scenario)
    decoy_pid = case.decoy_identity[0] if case.decoy_identity else ""
    decoy_delta = [
        transition.delta_phi
        for transition in result.transitions
        if decoy_pid in transition.actor.identity
    ]
    assert decoy_delta, "the decoy produced no transitions at all"
    assert max(decoy_delta) > 0.0
    assert math.fsum(decoy_delta) > 0.0


def test_decoy_variants_never_point_their_decoy_at_the_chain_owner(
    corpus: tuple[IncidentCase, ...],
) -> None:
    """The refusal that caught a real bug: recomputing the decoy after a reband.

    ``chain_owner_identity`` returns the first ``setuid`` performer, and an injected
    decoy's own ``setuid`` can precede the true chain's. Deriving the decoy identity
    from the rebanded scenario therefore pointed it at the chain owner, and
    ``IncidentCase`` refuses that rather than shipping an untestable case.
    """
    for case in corpus[:4]:
        for variant in build_decoy_variants(case, seed=5):
            assert variant.decoy_identity is not None
            assert variant.decoy_identity != variant.chain_identity
            assert variant.spurious_mechanism_id == SPURIOUS_MECHANISM_ID
    honest = corpus[0]
    owner = chain_owner_identity(honest.scenario)
    assert owner is not None
    with pytest.raises(ContractError, match="decoy identity IS the chain owner"):
        dataclasses.replace(
            honest,
            spurious_mechanism_id=SPURIOUS_MECHANISM_ID,
            decoy_identity=owner,
            chain_identity=owner,
        )


# --- corpus type refusals -----------------------------------------------------


def test_ground_truth_refuses_a_mislabelled_mechanism() -> None:
    with pytest.raises(ContractError, match="unknown world label"):
        GroundTruthWorld("imaginary_world", "m", frozenset(), None)
    with pytest.raises(ContractError, match="means"):
        GroundTruthWorld("approved_admin", "compromised_admin_session", frozenset(), None)
    with pytest.raises(ContractError, match="not in DIMENSIONS"):
        GroundTruthWorld(
            "approved_admin", "approved_administration", frozenset({"vibes"}), None
        )


def test_incident_case_refuses_an_unusable_expectation(
    corpus: tuple[IncidentCase, ...],
) -> None:
    case = corpus[0]
    with pytest.raises(ContractError, match="not an IdentifiabilityState value"):
        dataclasses.replace(case, expected_state="PROBABLY_BAD")
    with pytest.raises(ContractError, match="among its own material alternatives"):
        dataclasses.replace(case, material_alternatives=(case.truth.mechanism_id,))
    with pytest.raises(ContractError, match="no decoy identity"):
        dataclasses.replace(
            case, spurious_mechanism_id=SPURIOUS_MECHANISM_ID, decoy_identity=None
        )
    with pytest.raises(ContractError, match="prefix longer than the scenario"):
        dataclasses.replace(case, shared_prefix_length=10**6)


def test_the_corpus_expectation_vocabulary_matches_the_identifiability_enum() -> None:
    """``expected_state`` is a ``str`` because the enum lives in a later work package.

    The moment ``identifiability/resolution.py`` exists, the two vocabularies must be
    identical — otherwise a case could declare an expectation the engine cannot produce.
    Until then the four literal names are what binds.
    """
    assert EXPECTED_STATES == {
        "IDENTIFIED",
        "UNIDENTIFIABLE",
        "INSUFFICIENT_EVIDENCE",
        "UNKNOWN",
    }
    try:
        from pocketsec.stage4.identifiability.resolution import IdentifiabilityState
    except ImportError:  # pragma: no cover - resolution is a later work package
        return
    assert {state.value for state in IdentifiabilityState} == EXPECTED_STATES


# === measured bytes ==========================================================


def test_measured_world_and_field_bytes_sit_inside_the_architectures_kb_scale() -> None:
    """A recorded, contention-free measurement: bytes, not microseconds.

    Timing on this host is contended — a Stage 2 gate run reported a 7x inflation at
    load 23-67 versus load 8-12 — so the only resource figure this package asserts is a
    deterministic serialised size. The numbers are reported in the completion output.
    """
    world = make_world(
        expected=frozenset(f"signal-{i}" for i in range(MAX_EXPECTED_SIGNALS)),
        forbidden=frozenset(f"never-{i}" for i in range(MAX_FORBIDDEN_SIGNALS)),
        spine_signatures=tuple(f"sig-{i:016x}" for i in range(16)),
        evidence_refs=tuple(
            EvidenceRef("lab", f"loc-{i}", "sha256:" + f"{i:064x}") for i in range(4)
        ),
    )
    assert world.state_bytes() <= MAX_WORLD_BYTES
    full = make_field(
        *(
            make_world(f"w-{i}", mechanism_id=f"m-{i}", expected=frozenset({f"sig-{i}"}))
            for i in range(MAX_WORLDS)
        )
    )
    # §29's max_memory_bytes is 8 MiB for a whole incident; a saturated world set must
    # be orders of magnitude below it or nothing else fits.
    assert full.state_bytes() < 8 * 1024 * 1024 // 64
