"""D4.13 / D4.15 — the typed claim graph, the compiler and the verbalizer guard.

These tests exist to keep one promise mechanical: *the authoritative output
contains zero unsupported factual claims* (G4.8). Every test here is either an
attempt to launder an inference into an observation, a bound being pushed past,
or a demonstration that an abstention path is actually reachable.

Four of them fail if someone silently weakens the invariant, and each was checked
by actually weakening it and watching the test go red:

* ``..._catches_an_injected_authoritative_inference`` and
  ``..._re_checks_digests_rather_than_trusting_the_constructor`` bypass
  ``__post_init__``, proving the G4.8 walk is independent of the constructor;
* ``test_authoritative_kinds_is_the_only_place_the_policy_lives`` pins the two
  policy constants, so widening them to make something pass is a failing change;
* ``..._is_still_refused_by_the_object_class_rule`` pins §21's second arm.

Every fixture is built by hand, so the counts under test are counts this file
states rather than counts a generator happened to produce.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import get_args

import pytest

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef, digest_of_bytes
from pocketsec.stage1.observation.policy import MANDATORY_SIGNALS
from pocketsec.stage1.state.security_state import DIMENSIONS
from pocketsec.stage1.telemetry.raw_event_v1 import SensorPath
from pocketsec.stage4.claims.compiler import (
    AMPLIFICATION_RULES,
    FORBIDDEN_AMPLIFICATIONS,
    MAX_COMPILED_CLAIMS,
    MAX_COMPILED_SECTION,
    AmplificationRefusal,
    CompiledClaim,
    amplification_violations,
    compile_typed_claim_graph,
    insert_conserved,
    normalise_claim_token,
    observed_object_classes,
    permitted_inferences,
)
from pocketsec.stage4.claims.graph import (
    EMPTY_CLAIM_GRAPH,
    MAX_CLAIM_DEPTH,
    MAX_CLAIMS_PER_GRAPH,
    MAX_TRUNCATION_RECORDS,
    ClaimGraph,
    ClaimTruncation,
    LaunderingAttempt,
)
from pocketsec.stage4.claims.typed_claim import (
    AUTHORITATIVE_KINDS,
    DERIVABLE_FROM,
    MAX_CLAIM_TEXT,
    MAX_PREMISES_PER_CLAIM,
    ClaimKind,
    CounterfactualClaim,
    DerivedClaim,
    ExternalClaim,
    InferredClaim,
    ObservedClaim,
    TypedClaim,
    UnknownClaim,
    is_authoritative_kind,
    kind_of,
    sensor_of_evidence,
)
from pocketsec.stage4.claims.verbalizer import (
    MAX_VERBALIZED_TEXT,
    VERBALIZER_DEFAULT_ENABLED,
    CompiledClaim as VerbalizerCompiledClaim,
    VerbalizerVerdict,
    validate_verbalization,
    verbalize_guarded,
)

# --- helpers -----------------------------------------------------------------


def ref(locator: str, *, sensor: str = "ebpf") -> EvidenceRef:
    return EvidenceRef(
        store=f"raw.{sensor}", locator=locator, digest=digest_of_bytes(locator.encode())
    )


def observed(
    claim_id: str = "obs-1",
    *,
    subject: str = "credential_access",
    text: str = "ebpf recorded a read of an object classified CREDENTIAL_MATERIAL",
    at_sequence: int = 17,
) -> ObservedClaim:
    return ObservedClaim(
        claim_id=claim_id,
        subject=subject,
        text=text,
        evidence=(ref(claim_id),),
        sensor=SensorPath.EBPF,
        at_sequence=at_sequence,
    )


def derived(claim_id: str, premises: tuple[str, ...], *, text: str = "spine holds") -> DerivedClaim:
    return DerivedClaim(
        claim_id=claim_id,
        subject="credential",
        text=text,
        premises=premises,
        rule_id="cbf.spine",
    )


def inferred(claim_id: str, premises: tuple[str, ...], *, text: str) -> InferredClaim:
    return InferredClaim(
        claim_id=claim_id,
        subject="world:w-1",
        text=text,
        premises=premises,
        world_id="w-1",
        support=0.61,
    )


@dataclass(frozen=True, slots=True)
class StubIntervention:
    """Minimal ``InterventionLike``: package 6 owns the real one."""

    kind: str
    target_signature: str


@dataclass(frozen=True, slots=True)
class StubWorld:
    world_id: str
    mechanism_id: str
    forbidden_evidence: frozenset[str]
    evidence_refs: tuple[EvidenceRef, ...]


@dataclass(frozen=True, slots=True)
class StubField:
    incident_id: str
    at_sequence: int
    worlds: tuple[StubWorld, ...]
    support: Mapping[str, float]

    def support_vector(self) -> Mapping[str, float]:
        return self.support


@dataclass(frozen=True, slots=True)
class StubRegion:
    signal: str
    reason: str


@dataclass(frozen=True, slots=True)
class StubShadow:
    regions: tuple[StubRegion, ...]
    penalty: float = 0.25

    def confidence_penalty(self) -> float:
        return self.penalty


@dataclass(frozen=True, slots=True)
class StubVerdict:
    discriminating_observations: tuple[str, ...] = ()


def build_field(world_count: int = 2, *, evidence_per_world: int = 2) -> StubField:
    worlds = tuple(
        StubWorld(
            world_id=f"w-{index}",
            mechanism_id="compromised_admin_session" if index % 2 else "benign_backup_job",
            forbidden_evidence=frozenset({"evidence:w-0-e0"}),
            evidence_refs=tuple(ref(f"w-{index}-e{j}") for j in range(evidence_per_world)),
        )
        for index in range(world_count)
    )
    return StubField(
        incident_id="inc-1",
        at_sequence=42,
        worlds=worlds,
        support={world.world_id: 1.0 / (index + 2) for index, world in enumerate(worlds)},
    )


class StubVerbalizer:
    """A paraphraser that returns whatever the test told it to return."""

    def __init__(self, text: str) -> None:
        self.text = text

    def verbalize(self, compiled: CompiledClaim) -> str:
        return self.text


class RaisingVerbalizer:
    def verbalize(self, compiled: CompiledClaim) -> str:
        raise RuntimeError("model went away")


# --- the epistemic type system ------------------------------------------------


def test_the_union_has_exactly_six_members_covering_every_claim_kind() -> None:
    members = get_args(TypedClaim)
    assert len(members) == 6
    assert {kind_of(member) for member in members} == set(ClaimKind)
    assert len(set(members)) == 6


def test_authoritative_kinds_is_the_only_place_the_policy_lives() -> None:
    # Widening either constant to make something pass must be a failing change.
    assert AUTHORITATIVE_KINDS == frozenset({ClaimKind.OBS, ClaimKind.DER})
    assert DERIVABLE_FROM == frozenset({ClaimKind.OBS, ClaimKind.DER})
    assert is_authoritative_kind(observed())
    assert not is_authoritative_kind(inferred("i", ("obs-1",), text="possible x"))


def test_kind_is_a_property_of_the_class_not_a_constructor_argument() -> None:
    with pytest.raises(TypeError):
        ObservedClaim(  # type: ignore[call-arg]
            claim_id="obs-x", subject="s", text="t", kind="OBS",
            evidence=(ref("e"),), sensor=SensorPath.EBPF, at_sequence=0,
        )


def test_a_claim_may_not_announce_a_kind_its_class_does_not_hold() -> None:
    with pytest.raises(ContractError, match="carries marker"):
        observed(text="[INF] possible credential access")


# --- the seven laundering attempts (D4.13) ------------------------------------


def test_laundering_a_observed_claim_with_no_evidence() -> None:
    with pytest.raises(ContractError, match="at least one EvidenceRef"):
        ObservedClaim(
            claim_id="obs-a", subject="credential_access", text="a read happened",
            evidence=(), sensor=SensorPath.EBPF, at_sequence=3,
        )


def test_laundering_b_inference_text_with_a_malformed_digest() -> None:
    with pytest.raises(ContractError, match="sha256"):
        ObservedClaim(
            claim_id="obs-b", subject="credential", text="possible credential access",
            evidence=(EvidenceRef(store="raw.ebpf", locator="e1", digest="sha256:deadbeef"),),
            sensor=SensorPath.EBPF, at_sequence=3,
        )


def test_laundering_c_derived_claim_resting_on_an_inference() -> None:
    graph = EMPTY_CLAIM_GRAPH.insert(observed(), authoritative=True)
    graph = graph.insert(inferred("inf-1", ("obs-1",), text="possible credential access"))
    with pytest.raises(LaunderingAttempt, match="must root in OBS"):
        graph.insert(derived("der-1", ("inf-1",)))


def test_laundering_d_inserting_an_inference_as_authoritative() -> None:
    graph = EMPTY_CLAIM_GRAPH.insert(observed(), authoritative=True)
    claim = inferred("inf-1", ("obs-1",), text="possible credential access")
    with pytest.raises(LaunderingAttempt, match="may never be authoritative"):
        graph.insert(claim, authoritative=True)


def test_laundering_e_a_derived_cycle() -> None:
    first = derived("der-a", ("der-b",))
    second = derived("der-b", ("der-a",))
    with pytest.raises(LaunderingAttempt, match="cycle"):
        ClaimGraph(claims={"der-a": first, "der-b": second})


def test_laundering_f_external_claim_without_a_source_version() -> None:
    with pytest.raises(ContractError, match="source_version"):
        ExternalClaim(
            claim_id="ext-1", subject="credential", text="maps to an analytic",
            knowledge_source="attack", source_version="", rationale="object class matches",
        )
    # A *valid* external claim is still refused authority: naming is not deciding.
    valid = ExternalClaim(
        claim_id="ext-1", subject="credential", text="maps to a credential-access analytic",
        knowledge_source="attack", source_version="v18.1",
        rationale="the observed read matches the analytic's object class",
    )
    with pytest.raises(LaunderingAttempt, match="may never be authoritative"):
        EMPTY_CLAIM_GRAPH.insert(valid, authoritative=True)


def test_laundering_g_obs_der_inf_der_with_the_second_der_authoritative() -> None:
    graph = EMPTY_CLAIM_GRAPH.insert(observed(), authoritative=True)
    graph = graph.insert(derived("der-1", ("obs-1",)), authoritative=True)
    graph = graph.insert(inferred("inf-1", ("der-1",), text="possible credential access"))
    with pytest.raises(LaunderingAttempt, match="must root in OBS"):
        graph.insert(derived("der-2", ("inf-1",)), authoritative=True)


def test_a_premise_absent_from_the_graph_is_dangling_support() -> None:
    with pytest.raises(LaunderingAttempt, match="not .*in the graph"):
        EMPTY_CLAIM_GRAPH.insert(derived("der-1", ("obs-missing",)))


# --- G4.8: the walk ----------------------------------------------------------


def test_unsupported_authoritative_is_empty_for_a_chain_rooted_in_observations() -> None:
    graph = EMPTY_CLAIM_GRAPH.insert(observed("obs-1"), authoritative=True)
    graph = graph.insert(observed("obs-2", at_sequence=18), authoritative=True)
    graph = graph.insert(derived("der-1", ("obs-1", "obs-2")), authoritative=True)
    graph = graph.insert(derived("der-2", ("der-1",)), authoritative=True)
    assert graph.unsupported_authoritative() == ()
    assert graph.traces_to_observation("der-2")
    assert {claim.claim_id for claim in graph.roots_of("der-2")} == {"obs-1", "obs-2"}


def test_unsupported_authoritative_catches_an_injected_authoritative_inference() -> None:
    """The detector must not depend on the constructor that normally refuses this.

    A future author who weakens ``_validate_structure`` has to make this test fail
    to do it, which is the point of writing G4.8 as a walk rather than a rule.
    """
    graph = EMPTY_CLAIM_GRAPH.insert(observed(), authoritative=True)
    graph = graph.insert(inferred("inf-1", ("obs-1",), text="possible credential access"))
    object.__setattr__(graph, "authoritative", frozenset({"obs-1", "inf-1"}))
    assert graph.unsupported_authoritative() == ("inf-1",)


def test_unsupported_authoritative_catches_a_chain_rooted_in_external_knowledge() -> None:
    external = ExternalClaim(
        claim_id="ext-1", subject="credential", text="an external analytic names this family",
        knowledge_source="sigma", source_version="2026-09", rationale="object class matches",
    )
    graph = EMPTY_CLAIM_GRAPH.insert(external)
    injected = derived("der-1", ("ext-1",))
    object.__setattr__(graph, "claims", {**graph.claims, "der-1": injected})
    object.__setattr__(graph, "authoritative", frozenset({"der-1"}))
    assert graph.unsupported_authoritative() == ("der-1",)
    assert not graph.traces_to_observation("der-1")


def test_the_g48_walk_re_checks_digests_rather_than_trusting_the_constructor() -> None:
    """A tampered digest must fail the walk even though construction accepted it.

    ``ObservedClaim`` validates its digest, but G4.8 is a property of the graph
    that gets exported. If the walk trusted the constructor, mutating the evidence
    afterwards — or arriving through any future second path — would produce an
    authoritative claim resting on bytes nobody can verify.
    """
    graph = EMPTY_CLAIM_GRAPH.insert(observed("obs-1"), authoritative=True)
    graph = graph.insert(derived("der-1", ("obs-1",)), authoritative=True)
    assert graph.unsupported_authoritative() == ()
    tampered = EvidenceRef.__new__(EvidenceRef)
    object.__setattr__(tampered, "store", "raw.ebpf")
    object.__setattr__(tampered, "locator", "obs-1")
    object.__setattr__(tampered, "digest", "sha256:not-a-real-digest")
    object.__setattr__(graph.claims["obs-1"], "evidence", (tampered,))
    assert graph.unsupported_authoritative() == ("der-1", "obs-1")


def test_kinds_present_counts_every_kind_that_was_exercised() -> None:
    graph = EMPTY_CLAIM_GRAPH.insert(observed(), authoritative=True)
    graph = graph.insert(derived("der-1", ("obs-1",)), authoritative=True)
    graph = graph.insert(inferred("inf-1", ("der-1",), text="possible credential access"))
    graph = graph.insert(
        UnknownClaim(
            claim_id="unk-1",
            subject="module_load",
            text="module_load was not observable",
            reason="shadowed",
            shadow_region="module_load",
        )
    )
    counts = graph.kinds_present()
    assert counts[ClaimKind.OBS] == 1
    assert counts[ClaimKind.DER] == 1
    assert counts[ClaimKind.INF] == 1
    assert counts[ClaimKind.UNK] == 1
    assert ClaimKind.CF not in counts


# --- bounds ------------------------------------------------------------------


def test_bound_hit_records_a_truncation_and_drops_nothing_silently() -> None:
    graph = EMPTY_CLAIM_GRAPH
    for index in range(MAX_CLAIMS_PER_GRAPH):
        graph = graph.insert(observed(f"obs-{index}", at_sequence=index), authoritative=True)
    assert len(graph.claims) == MAX_CLAIMS_PER_GRAPH
    refused = observed("obs-overflow", at_sequence=999)
    after = graph.insert(refused, authoritative=True)
    assert len(after.claims) == MAX_CLAIMS_PER_GRAPH
    assert "obs-overflow" not in after.claims
    assert len(after.truncated) == 1
    record = after.truncated[0]
    # The refused claim is *named*, so the loss is auditable rather than a count.
    assert record.identifier == "obs-overflow"
    assert record.reason == f"max_claims_per_graph:{MAX_CLAIMS_PER_GRAPH}"
    assert after.unsupported_authoritative() == ()


def test_the_truncation_log_is_itself_bounded_and_counts_what_it_coalesced() -> None:
    graph = EMPTY_CLAIM_GRAPH
    for index in range(MAX_CLAIMS_PER_GRAPH):
        graph = graph.insert(observed(f"obs-{index}", at_sequence=index))
    for index in range(MAX_TRUNCATION_RECORDS + 10):
        graph = graph.insert(observed(f"spill-{index}", at_sequence=index))
    assert len(graph.truncated) == MAX_TRUNCATION_RECORDS
    overflow = graph.truncated[-1]
    assert overflow.identifier == "truncation_log_overflow"
    assert overflow.consequence_lost == 11.0


def test_depth_is_bounded_by_construction() -> None:
    graph = EMPTY_CLAIM_GRAPH.insert(observed("obs-0", at_sequence=0), authoritative=True)
    previous = "obs-0"
    for depth in range(1, MAX_CLAIM_DEPTH + 1):
        graph = graph.insert(derived(f"der-{depth}", (previous,)), authoritative=True)
        previous = f"der-{depth}"
    assert graph.depth() == MAX_CLAIM_DEPTH
    with pytest.raises(LaunderingAttempt, match="MAX_CLAIM_DEPTH|depth"):
        graph.insert(derived("der-over", (previous,)))


def test_claim_text_and_premise_count_are_bounded() -> None:
    with pytest.raises(ContractError, match=f"<= {MAX_CLAIM_TEXT}"):
        observed(text="x" * (MAX_CLAIM_TEXT + 1))
    with pytest.raises(ContractError, match=f"<= {MAX_PREMISES_PER_CLAIM}"):
        derived("der-1", tuple(f"obs-{i}" for i in range(MAX_PREMISES_PER_CLAIM + 1)))


def test_a_claim_may_not_be_its_own_premise() -> None:
    with pytest.raises(ContractError, match="own id"):
        derived("der-1", ("der-1",))


# --- per-kind refusals -------------------------------------------------------


def test_derived_claim_refuses_inline_evidence_and_empty_premises() -> None:
    with pytest.raises(ContractError, match="requires premises"):
        DerivedClaim(claim_id="der-1", subject="s", text="t", premises=(), rule_id="r")
    with pytest.raises(ContractError, match="must not inline evidence"):
        DerivedClaim(
            claim_id="der-1", subject="s", text="t", premises=("obs-1",),
            evidence=(ref("e"),), rule_id="r",
        )


def test_inferred_claim_refuses_support_outside_the_unit_interval() -> None:
    kw = {"claim_id": "inf-1", "subject": "s", "text": "possible x"}
    for bad in (-0.01, 1.01, float("nan")):
        with pytest.raises(ContractError):
            InferredClaim(**kw, premises=("obs-1",), world_id="w-1", support=bad)
    with pytest.raises(ContractError, match="world_id"):
        InferredClaim(**kw, world_id="", support=0.5)


def test_counterfactual_claim_refuses_an_intervention_with_no_target() -> None:
    good = CounterfactualClaim(
        claim_id="cf-1",
        subject="credential",
        text="removing the read collapses this world",
        premises=(),
        intervention=StubIntervention(kind="REMOVE_EVENT", target_signature="sig-17"),
        outcome_shift=-0.4,
    )
    assert kind_of(good) is ClaimKind.CF
    kw = {"subject": "credential", "text": "removing it", "outcome_shift": 0.0}
    with pytest.raises(ContractError, match="target_signature"):
        CounterfactualClaim(
            claim_id="cf-2",
            intervention=StubIntervention(kind="REMOVE_EVENT", target_signature=""),
            **kw,
        )
    with pytest.raises(ContractError, match="kind and target_signature"):
        CounterfactualClaim(claim_id="cf-3", intervention=object(), **kw)  # type: ignore[arg-type]


def test_unknown_claim_refuses_evidence_premises_and_an_unlisted_reason() -> None:
    kw = {"claim_id": "unk-1", "subject": "s", "text": "t"}
    with pytest.raises(ContractError, match="no evidence"):
        UnknownClaim(**kw, evidence=(ref("e"),), reason="shadowed")
    with pytest.raises(ContractError, match="no premises"):
        UnknownClaim(**kw, premises=("obs-1",), reason="shadowed")
    with pytest.raises(ContractError, match="reason must be one of"):
        UnknownClaim(**kw, reason="because_i_said_so")


def test_external_claim_refuses_an_unlisted_source_and_an_empty_rationale() -> None:
    kw = {"claim_id": "ext-1", "subject": "s", "text": "t", "source_version": "1"}
    with pytest.raises(ContractError, match="knowledge_source"):
        ExternalClaim(**kw, knowledge_source="vendor_blog", rationale="r")
    with pytest.raises(ContractError, match="rationale"):
        ExternalClaim(**kw, knowledge_source="local", rationale="   ")


def test_sensor_is_recovered_from_the_evidence_store_or_is_none() -> None:
    assert sensor_of_evidence(ref("e", sensor="auditd")) is SensorPath.AUDITD
    unnamed = EvidenceRef(store="archive", locator="e", digest=digest_of_bytes(b"e"))
    assert sensor_of_evidence(unnamed) is None


# --- semantic conservation (§21) ---------------------------------------------


def test_section_21_exact_case_possible_access_permitted_stolen_refused() -> None:
    """Evidence: read object classified CREDENTIAL_MATERIAL.

    Permitted: ``[INF] possible credential access``. Refused: ``password stolen``.
    """
    obs = observed("obs-1", subject="CREDENTIAL_MATERIAL")
    graph = EMPTY_CLAIM_GRAPH.insert(obs, authoritative=True)
    graph = insert_conserved(graph, derived("der-1", ("obs-1",)), authoritative=True)
    graph = insert_conserved(
        graph, inferred("inf-ok", ("der-1",), text="[INF] possible credential access")
    )
    assert "inf-ok" in graph.claims
    with pytest.raises(AmplificationRefusal):
        insert_conserved(graph, inferred("inf-bad", ("der-1",), text="[INF] password stolen"))


def test_an_over_strong_hedged_claim_is_still_refused_by_the_object_class_rule() -> None:
    obs = observed("obs-1", subject="CREDENTIAL_MATERIAL")
    graph = EMPTY_CLAIM_GRAPH.insert(obs, authoritative=True)
    graph = insert_conserved(graph, derived("der-1", ("obs-1",)), authoritative=True)
    with pytest.raises(AmplificationRefusal, match="possible_credential_access"):
        insert_conserved(
            graph, inferred("inf-bad", ("der-1",), text="possible credential exfiltration")
        )


def test_amplification_rules_never_license_a_completed_compromise() -> None:
    for object_class, permitted in AMPLIFICATION_RULES.items():
        assert permitted, f"{object_class} must license something or be removed"
        for allowed in permitted:
            assert allowed.startswith("possible_"), f"{object_class} -> {allowed}"
            assert not any(verb in allowed for verb in FORBIDDEN_AMPLIFICATIONS)
    assert permitted_inferences("CREDENTIAL_MATERIAL") == frozenset({"possible_credential_access"})
    assert permitted_inferences("NOT_A_CLASS") == frozenset()


def test_an_unknown_claim_may_name_an_unobserved_amplification() -> None:
    # §23's own example unknown is "direct exfiltration evidence". Naming a hole is
    # the opposite of amplifying, so UNK is exempt from the verb arm.
    unknown = UnknownClaim(
        claim_id="unk-1",
        subject="exfiltration",
        text="no direct evidence that data was exfiltrated was observable",
        reason="not_observed",
    )
    assert amplification_violations([unknown]) == ()


def test_a_derived_claim_may_not_assert_a_completed_compromise() -> None:
    graph = EMPTY_CLAIM_GRAPH.insert(observed("obs-1"), authoritative=True)
    asserted = derived("der-1", ("obs-1",), text="the account was compromised")
    with pytest.raises(AmplificationRefusal):
        insert_conserved(graph, asserted, authoritative=True)


def test_observed_object_classes_reads_subject_and_uppercase_tokens() -> None:
    claim = observed("obs-1", subject="credential_access")
    assert observed_object_classes([claim]) == frozenset({"CREDENTIAL_MATERIAL"})
    assert normalise_claim_token("[DER] Parent-child relation") == "parent_child_relation"


# --- the compiler ------------------------------------------------------------


def test_compile_produces_obs_inf_unk_and_zero_unsupported_authoritative() -> None:
    """S4-FC-02 / S4-REV-09 changed this test's contract, and in the stricter direction.

    It used to require a DER, and the only DER the compiler emitted was the per-world
    "N observation(s) form the causal spine of <world>" — world attribution, which is
    the hypothesis, marked authoritative. The compiler now emits none, so the
    assertion is that NO DER appears, alongside OBS, INF and UNK.
    """
    field = build_field(world_count=2)
    shadow = StubShadow(regions=(StubRegion(signal="module_load", reason="sensor_path_dropped"),))
    graph, compiled = compile_typed_claim_graph(field, shadow=shadow, verdict=StubVerdict())
    kinds = graph.kinds_present()
    for kind in (ClaimKind.OBS, ClaimKind.INF, ClaimKind.UNK):
        assert kinds.get(kind, 0) >= 1, kind
    assert kinds.get(ClaimKind.DER, 0) == 0
    assert graph.unsupported_authoritative() == ()
    assert amplification_violations(list(graph.claims.values())) == ()
    for claim_id in graph.authoritative:
        assert kind_of(graph.claims[claim_id]) in AUTHORITATIVE_KINDS
    assert len(compiled) == 2
    assert all(kind_of(item.headline) is ClaimKind.INF for item in compiled)


def test_compile_is_deterministic_and_ranks_by_support() -> None:
    field = build_field(world_count=3)
    first = compile_typed_claim_graph(field, shadow=None, verdict=StubVerdict())
    second = compile_typed_claim_graph(field, shadow=None, verdict=StubVerdict())
    assert json.dumps(first[0].to_dict(), sort_keys=True) == json.dumps(
        second[0].to_dict(), sort_keys=True
    )
    assert [item.render() for item in first[1]] == [item.render() for item in second[1]]
    headline_worlds = [item.headline.claim_id for item in first[1]]
    assert headline_worlds == ["inf.w-0", "inf.w-1", "inf.w-2"]


def test_compile_bounds_the_number_of_compiled_claims_and_records_the_loss() -> None:
    field = build_field(world_count=MAX_COMPILED_CLAIMS + 3)
    graph, compiled = compile_typed_claim_graph(field, shadow=None, verdict=StubVerdict())
    assert len(compiled) == MAX_COMPILED_CLAIMS
    reasons = [record.reason for record in graph.truncated]
    assert f"max_compiled_claims:{MAX_COMPILED_CLAIMS}" in reasons


def test_compile_refuses_to_fabricate_a_sensor_for_unattributable_evidence() -> None:
    world = StubWorld(
        world_id="w-0",
        mechanism_id="benign_backup_job",
        forbidden_evidence=frozenset(),
        evidence_refs=(EvidenceRef(store="archive", locator="e0", digest=digest_of_bytes(b"e0")),),
    )
    field = StubField(incident_id="inc-2", at_sequence=1, worlds=(world,), support={"w-0": 1.0})
    graph, compiled = compile_typed_claim_graph(field, shadow=None, verdict=StubVerdict())
    assert compiled == ()
    assert graph.kinds_present().get(ClaimKind.OBS, 0) == 0
    assert any("evidence_store_names_no_sensor" in r.reason for r in graph.truncated)


def test_a_single_world_field_does_not_manufacture_an_identifiability_unknown() -> None:
    graph, compiled = compile_typed_claim_graph(
        build_field(world_count=1), shadow=None, verdict=StubVerdict()
    )
    assert graph.kinds_present().get(ClaimKind.UNK, 0) == 0
    assert compiled[0].unknown == ()
    assert compiled[0].render().endswith("unknown:\n  (none recorded)")


def test_the_unknown_path_is_reachable_and_bounded() -> None:
    regions = tuple(
        StubRegion(signal=f"signal_{index}", reason="no_visibility_evidence")
        for index in range(MAX_COMPILED_SECTION + 4)
    )
    field = build_field(world_count=2)
    graph, compiled = compile_typed_claim_graph(
        field, shadow=StubShadow(regions=regions), verdict=StubVerdict()
    )
    # MAX_COMPILED_SECTION shadow regions plus the one identifiability unknown that
    # only a field with competing worlds is allowed to carry.
    assert graph.kinds_present()[ClaimKind.UNK] == MAX_COMPILED_SECTION + 1
    assert len(compiled[0].unknown) == MAX_COMPILED_SECTION
    assert any(f"max_compiled_section:{MAX_COMPILED_SECTION}" in r.reason for r in graph.truncated)


def test_render_follows_the_section_23_template() -> None:
    field = build_field(world_count=1)
    _, compiled = compile_typed_claim_graph(
        field,
        shadow=StubShadow(regions=(StubRegion(signal="module_load", reason="below_level"),)),
        verdict=StubVerdict(),
    )
    text = compiled[0].render()
    lines = text.splitlines()
    assert lines[0].startswith("[INF] ")
    assert "because:" in lines
    assert "unknown:" in lines
    assert "  [UNK] module_load was not observable (below_level)" in lines


def test_render_says_none_recorded_rather_than_nothing_is_unknown() -> None:
    compiled = CompiledClaim(headline=observed("obs-1"))
    assert compiled.render().endswith("unknown:\n  (none recorded)")


def test_compiled_claim_refuses_an_unknown_in_the_wrong_section() -> None:
    unknown = UnknownClaim(claim_id="unk-1", subject="s", text="t", reason="shadowed")
    with pytest.raises(ContractError, match="belongs in CompiledClaim.unknown"):
        CompiledClaim(headline=observed("obs-1"), because=(unknown,))
    with pytest.raises(ContractError, match="must not repeat"):
        CompiledClaim(headline=observed("obs-1"), because=(observed("obs-1"),))


def test_claim_graph_to_dict_is_json_safe_and_names_no_stage4_class() -> None:
    field = build_field(world_count=2)
    graph, _ = compile_typed_claim_graph(field, shadow=None, verdict=StubVerdict())
    payload = json.dumps(graph.to_dict(), sort_keys=True)
    for token in ("ClaimGraph", "ObservedClaim", "DerivedClaim", "InferredClaim", "CausalBelief"):
        assert token not in payload
    assert json.loads(payload)["unsupported_authoritative"] == []


# --- the verbalizer guard (D4.15) --------------------------------------------


def compiled_fixture() -> CompiledClaim:
    field = build_field(world_count=1)
    _, compiled = compile_typed_claim_graph(
        field,
        shadow=StubShadow(regions=(StubRegion(signal="module_load", reason="below_level"),)),
        verdict=StubVerdict(),
    )
    return compiled[0]


def test_no_language_model_ships_by_default() -> None:
    assert VERBALIZER_DEFAULT_ENABLED is False
    assert VerbalizerCompiledClaim is CompiledClaim
    verdict = verbalize_guarded(compiled_fixture(), None)
    assert verdict.accepted is False
    assert verdict.fell_back is True
    assert verdict.rejected_reason == "verbalizer_disabled"
    assert verdict.text == compiled_fixture().render()


def test_a_faithful_paraphrase_is_accepted() -> None:
    compiled = compiled_fixture()
    produced = "One explanation remains open; module_load was not observable."
    verdict = validate_verbalization(compiled, produced)
    assert verdict.accepted is True, verdict.rejected_reason
    assert verdict.fell_back is False
    assert verdict.text == produced


def test_violation_a_forbidden_amplification_is_rejected() -> None:
    compiled = compiled_fixture()
    verdict = verbalize_guarded(compiled, StubVerbalizer("The admin password was stolen."))
    assert verdict.accepted is False
    assert verdict.rejected_reason == "forbidden_amplification"
    assert verdict.unsupported_propositions == ("stolen",)
    assert verdict.text == compiled.render()
    assert verdict.fell_back is True


def test_violation_b_an_unsupported_security_term_is_rejected() -> None:
    compiled = compiled_fixture()
    introduced = "persistence" if "persistence" not in compiled.render().lower() else "isolation"
    assert introduced in set(DIMENSIONS) | set(MANDATORY_SIGNALS)
    verdict = verbalize_guarded(compiled, StubVerbalizer(f"The {introduced} dimension rose."))
    assert verdict.accepted is False
    assert verdict.rejected_reason == "unsupported_security_term"
    assert introduced in verdict.unsupported_propositions


def test_violation_c_an_invented_quantity_is_rejected() -> None:
    compiled = compiled_fixture()
    verdict = verbalize_guarded(compiled, StubVerbalizer("Seen across 9731 events."))
    assert verdict.accepted is False
    assert verdict.rejected_reason == "invented_quantity"
    assert verdict.unsupported_propositions == ("9731",)


def test_violation_d_negating_an_unknown_is_rejected_but_restating_it_is_not() -> None:
    compiled = compiled_fixture()
    assert compiled.unknown, "fixture must carry an unknown for this test to mean anything"
    resolved = verbalize_guarded(compiled, StubVerbalizer("No module_load ever happened here."))
    assert resolved.accepted is False
    assert resolved.rejected_reason == "negated_unknown"
    assert resolved.unsupported_propositions == (compiled.unknown[0].claim_id,)

    restated = verbalize_guarded(
        compiled, StubVerbalizer("No module_load was observed; visibility was reduced.")
    )
    assert restated.accepted is True, restated.rejected_reason


def test_a_raising_verbalizer_never_reaches_the_caller() -> None:
    compiled = compiled_fixture()
    verdict = verbalize_guarded(compiled, RaisingVerbalizer())
    assert verdict.accepted is False
    assert verdict.rejected_reason == "verbalizer_raised:RuntimeError"
    assert verdict.text == compiled.render()


def test_empty_and_oversized_verbalizations_are_rejected() -> None:
    compiled = compiled_fixture()
    assert validate_verbalization(compiled, "   ").rejected_reason == "empty_verbalization"
    long_text = "safe words " * (MAX_VERBALIZED_TEXT // 5)
    assert validate_verbalization(compiled, long_text).rejected_reason.startswith("text_too_long")


def test_verbalizer_verdict_refuses_a_self_contradicting_record() -> None:
    with pytest.raises(ContractError, match="rejected_reason"):
        VerbalizerVerdict(accepted=True, text="x", rejected_reason="why")
    with pytest.raises(ContractError, match="must name its reason"):
        VerbalizerVerdict(accepted=False, text="x")
    with pytest.raises(ContractError, match="did not fall back"):
        VerbalizerVerdict(accepted=True, text="x", fell_back=True)


# --- resource behaviour ------------------------------------------------------


def test_a_full_graph_stays_small_enough_to_export() -> None:
    """A bound is only useful if the bounded thing is actually affordable."""
    graph = EMPTY_CLAIM_GRAPH
    for index in range(MAX_CLAIMS_PER_GRAPH):
        graph = graph.insert(observed(f"obs-{index}", at_sequence=index), authoritative=True)
    payload = json.dumps(graph.to_dict(), sort_keys=True).encode("utf-8")
    assert len(graph.claims) == MAX_CLAIMS_PER_GRAPH
    # Measured at 91_100 B on the run that wrote this test (load average 14.34);
    # the assertion is the order of magnitude, not the byte count, so a
    # representation change is caught without breaking on a wording edit.
    assert len(payload) < 256 * 1024
    assert graph.unsupported_authoritative() == ()


def test_claim_truncation_refuses_an_unnamed_loss() -> None:
    """``consequence_lost`` is now passed explicitly, and that is the point of the change.

    The integrator collapsed ``ClaimTruncation`` into
    ``graph/sparse_world_graph.Truncation`` — the two were verified field-for-field
    identical and ``Truncation`` is the stricter of the pair. It has no ``= 0.0`` default,
    because a loss recorded without saying how much was lost is the thing the record
    exists to prevent. The two refusals asserted here are unchanged.
    """
    with pytest.raises(ContractError, match="identifier"):
        ClaimTruncation(what="claim", identifier="", reason="because", consequence_lost=0.0)
    with pytest.raises(ContractError, match="reason"):
        ClaimTruncation(what="claim", identifier="c-1", reason="", consequence_lost=0.0)


def test_the_claim_truncation_record_is_the_world_graph_truncation_record() -> None:
    """One type, not two identical ones. S2-AUTH-01's lesson, applied to a data record.

    Two field-for-field identical records in different packages is how a validation hole
    gets closed in one of them and not the other. ``Truncation`` also validates ``what``
    against the closed ``TRUNCATION_KINDS`` vocabulary, which the claims-local copy did
    not, so the collapse is strictly stronger.
    """
    from pocketsec.stage4.graph.sparse_world_graph import TRUNCATION_KINDS, Truncation

    assert ClaimTruncation is Truncation
    assert "claim" in TRUNCATION_KINDS
    with pytest.raises(ContractError, match="TRUNCATION_KINDS|what must be"):
        ClaimTruncation(
            what="not_a_truncation_kind", identifier="c-1", reason="because",
            consequence_lost=0.0,
        )
