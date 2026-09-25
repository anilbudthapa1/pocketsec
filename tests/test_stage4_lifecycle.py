"""Stage 4 package 5 — world lifecycle, tombstones, sparse graph, entropy budget.

These tests exist to make three properties mechanically checkable rather than
promised:

1.  **The bounds bound while the field is being flooded.** A bound demonstrated at
    rest is not demonstrated. An attacker who can make the system branch without
    limit has a denial of service, so ``test_world_flood_*`` asserts world count,
    graph size, work units and incident bytes at *every step* of an adversarial
    flood, and asserts the ground-truth world survives it.
2.  **Every loss is recorded.** A silent drop is a defect. For every world, node
    and edge that a bound removed, there is exactly one ``Truncation`` naming it
    and its ``consequence_lost``.
3.  **Novelty is not maliciousness.** ``BirthRefusal.NOT_SECURITY_RELEVANT`` fires
    on a real benign Stage 1 corpus, and the benign spawn rate is measured rather
    than asserted (F3).

``worlds/world.py``, ``worlds/field.py`` and ``visibility/`` are written by other
packages in the same wave. This file therefore exercises the lifecycle against
**doubles built strictly to the published field lists and method semantics** of
those types (spec §D4.1-continued, §D4.3), so the lifecycle's own logic is tested
today and the doubles can be deleted when the real types land. Where the real
module is importable, the test asserts the double and the constant agree
(``test_mirrored_constants_match_their_owning_modules``).
"""

from __future__ import annotations

import dataclasses
import importlib
import math
import random
from dataclasses import dataclass, field as dataclass_field
from typing import Any

import pytest

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef, digest_of_bytes
from pocketsec.stage1.labs.corpus import build_corpus
from pocketsec.stage1.observation.policy import MANDATORY_SIGNALS
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage1.state.security_state import DIMENSIONS
from pocketsec.stage4.graph.entropy_budget import (
    BUDGET_KINDS,
    DEFAULT_MAX_REASONING_UNITS,
    MAX_INCIDENT_BYTES,
    BudgetController,
    EntropyBudget,
)
from pocketsec.stage4.graph.sparse_world_graph import (
    MAX_GRAPH_EDGES,
    MAX_GRAPH_NODES,
    RETENTION_THRESHOLD,
    TRUNCATION_KINDS,
    SparseWorldGraph,
    Truncation,
    WorldGraphNode,
    total_consequence_lost,
)
from pocketsec.stage4.worlds.lifecycle import (
    DIMENSION_SIGNALS,
    FUSION_EQUIVALENCE_EPSILON,
    MAX_FISSION_DEPTH,
    MIN_RESIDUAL_FOR_BIRTH,
    RESIDUAL_PERSISTENCE_STEPS,
    BirthRefusal,
    DeathCause,
    DominanceTest,
    EvidenceRegime,
    Residual,
    dominance_report,
    dominance_test,
    fission_world,
    fuse_worlds,
    kill_world,
    prune_dominated_worlds,
    residual_from_transition,
    spawn_refusal,
    spawn_world,
)
from pocketsec.stage4.worlds.tombstone import (
    MAX_TOMBSTONES,
    TombstoneLedger,
    WorldTombstone,
)

# --------------------------------------------------------------------------
# Doubles for the concurrently-built foundation types.
# --------------------------------------------------------------------------

MAX_WORLD_BYTES = 8192


@dataclass(frozen=True, slots=True)
class FakeSupport:
    value: float = 0.5

    def as_probability(self) -> float | None:
        return self.value if 0.0 <= self.value <= 1.0 else None


@dataclass(frozen=True, slots=True)
class FakeLatent:
    asserted_dimensions: frozenset[str] = frozenset()
    consequence: float = 0.0

    def __post_init__(self) -> None:
        unknown = set(self.asserted_dimensions) - set(DIMENSIONS)
        if unknown:
            raise ContractError(f"unknown dimensions {sorted(unknown)}")

    def raises(self, dimension: str) -> bool:
        return dimension in self.asserted_dimensions


@dataclass(frozen=True, slots=True)
class FakeWorld:
    """``SecurityWorldV1`` as the spec publishes it, minus the members the
    lifecycle never touches (``support_state``, ``tension``, ``schema_version``)."""

    world_id: str
    mechanism_id: str
    latent_state: FakeLatent = dataclass_field(default_factory=FakeLatent)
    support: FakeSupport = dataclass_field(default_factory=FakeSupport)
    expected_evidence: frozenset[str] = frozenset()
    forbidden_evidence: frozenset[str] = frozenset()
    contradictions: tuple[str, ...] = ()
    uncertainty: float = 0.5
    visibility_requirements: frozenset[str] = frozenset()
    spine_signatures: tuple[str, ...] = ()
    evidence_refs: tuple[EvidenceRef, ...] = ()
    born_at_sequence: int = 0
    fission_depth: int = 0

    def __post_init__(self) -> None:
        clash = self.expected_evidence & self.forbidden_evidence
        if clash:
            raise ContractError(f"world expects and forbids {sorted(clash)}")
        if self.fission_depth > MAX_FISSION_DEPTH:
            raise ContractError("fission_depth beyond MAX_FISSION_DEPTH")
        if self.state_bytes() > MAX_WORLD_BYTES:
            raise ContractError("world exceeds MAX_WORLD_BYTES")

    def predicts(self, signal: str) -> bool:
        return signal in self.expected_evidence

    def forbids(self, signal: str) -> bool:
        return signal in self.forbidden_evidence

    def observationally_equivalent(self, other: FakeWorld, *, epsilon: float) -> bool:
        return (
            self.expected_evidence == other.expected_evidence
            and self.forbidden_evidence == other.forbidden_evidence
            and abs(self.support.value - other.support.value) <= epsilon
        )

    def state_bytes(self) -> int:
        signals = self.expected_evidence | self.forbidden_evidence | self.visibility_requirements
        return (
            64
            + len(self.world_id)
            + len(self.mechanism_id)
            + sum(len(s) for s in signals)
            + sum(len(c) for c in self.contradictions)
            + sum(len(s) for s in self.spine_signatures)
            + 72 * len(self.evidence_refs)
        )


@dataclass(frozen=True, slots=True)
class FakeField:
    """``CausalBeliefField`` as the spec publishes it, with its two refusals."""

    incident_id: str
    epoch_id: int = 1
    worlds: tuple[FakeWorld, ...] = ()
    max_worlds: int = 8
    graph: SparseWorldGraph | None = None
    truncations: tuple[Truncation, ...] = ()
    at_sequence: int = 0

    def __post_init__(self) -> None:
        if len(self.worlds) > self.max_worlds:
            raise ContractError(f"{len(self.worlds)} worlds exceeds max_worlds={self.max_worlds}")
        ids = [w.world_id for w in self.worlds]
        if len(set(ids)) != len(ids):
            raise ContractError("duplicate world_id")
        mechanisms = [w.mechanism_id for w in self.worlds]
        if len(set(mechanisms)) != len(mechanisms):
            raise ContractError("duplicate mechanism_id: a fusion that did not happen")

    def world(self, world_id: str) -> FakeWorld | None:
        for candidate in self.worlds:
            if candidate.world_id == world_id:
                return candidate
        return None

    def with_worlds(self, worlds: Any) -> FakeField:
        return dataclasses.replace(self, worlds=tuple(worlds))

    def state_bytes(self) -> int:
        graph_bytes = self.graph.memory_bytes() if self.graph is not None else 0
        return (
            len(self.incident_id)
            + sum(w.state_bytes() for w in self.worlds)
            + graph_bytes
            + 96 * len(self.truncations)
        )


@dataclass(frozen=True, slots=True)
class FakeShadow:
    blind: frozenset[str] = frozenset()

    def covers(self, signal: str) -> bool:
        return signal in self.blind

    def confidence_penalty(self) -> float:
        return min(1.0, 0.1 * len(self.blind))


def fake_unknown_world(incident_id: str, *, at_sequence: int) -> FakeWorld:
    """Stands in for ``worlds.field.unknown_world``: novelty is not
    maliciousness, so the UNKNOWN world asserts no dimension."""
    return FakeWorld(
        world_id=f"unknown-{at_sequence}",
        mechanism_id="unresolved_novel_mechanism",
        latent_state=FakeLatent(),
        support=FakeSupport(0.1),
        born_at_sequence=at_sequence,
    )


def digest(text: str) -> str:
    return digest_of_bytes(text.encode("utf-8"))


def evidence(text: str) -> EvidenceRef:
    return EvidenceRef(store="lab", locator=f"/lab/{text}", digest=digest(text))


def world(
    world_id: str,
    mechanism_id: str,
    *,
    expected: frozenset[str] = frozenset(),
    forbidden: frozenset[str] = frozenset(),
    support: float = 0.5,
    consequence: float = 0.0,
    dims: frozenset[str] = frozenset(),
    contradictions: tuple[str, ...] = (),
    refs: tuple[EvidenceRef, ...] = (),
) -> FakeWorld:
    return FakeWorld(
        world_id=world_id,
        mechanism_id=mechanism_id,
        latent_state=FakeLatent(asserted_dimensions=dims, consequence=consequence),
        support=FakeSupport(support),
        expected_evidence=expected,
        forbidden_evidence=forbidden,
        contradictions=contradictions,
        evidence_refs=refs,
    )


def residual(
    signals: frozenset[str],
    *,
    magnitude: float = 1.0,
    steps: int = RESIDUAL_PERSISTENCE_STEPS,
    visibility_explained: bool = False,
    consequence: float = 4.0,
) -> Residual:
    return Residual(
        signals=signals,
        magnitude=magnitude,
        persistent_steps=steps,
        visibility_explained=visibility_explained,
        consequence=consequence,
    )


CRITICAL = frozenset({"privilege_change"})

#: Constants ``graph/entropy_budget.py`` mirrors because importing their owning
#: module would close a cycle. Every name here is UNCHECKED until that module
#: exists, and the mirror test refuses any name not declared here.
MIRRORS_PENDING_THEIR_OWNER = frozenset(
    {
        "pocketsec.stage4.worlds.field.MAX_WORLDS",
        "pocketsec.stage4.counterfactual.intervention.MAX_COUNTERFACTUALS_PER_INCIDENT",
        "pocketsec.stage4.identifiability.horizon.DEFAULT_HORIZON_WORK_UNITS",
        "pocketsec.stage4.identifiability.horizon.DEFAULT_HORIZON_ESCALATIONS",
    }
)


# --------------------------------------------------------------------------
# Constants and vocabulary
# --------------------------------------------------------------------------


def test_constants_match_the_stage4_constant_table() -> None:
    assert (MIN_RESIDUAL_FOR_BIRTH, RESIDUAL_PERSISTENCE_STEPS) == (0.25, 2)
    assert (MAX_FISSION_DEPTH, FUSION_EQUIVALENCE_EPSILON) == (2, 0.05)
    assert (MAX_GRAPH_NODES, MAX_GRAPH_EDGES, RETENTION_THRESHOLD) == (512, 1024, 0.05)
    assert MAX_TOMBSTONES == 32
    assert DEFAULT_MAX_REASONING_UNITS == 4096
    assert MAX_INCIDENT_BYTES == 8 * 1024 * 1024


def test_dimension_signal_map_covers_every_dimension_and_mandatory_signal() -> None:
    """If Stage 1 adds a dimension or a mandatory signal, this must be updated.

    Would fail if someone added a tenth dimension and left the map alone — the
    silent consequence being residuals that can never name that dimension.
    """
    assert set(DIMENSION_SIGNALS) == set(DIMENSIONS)
    assert MANDATORY_SIGNALS <= set(DIMENSION_SIGNALS.values())
    non_mandatory = set(DIMENSION_SIGNALS.values()) - MANDATORY_SIGNALS
    assert non_mandatory == {"reachability", "modification", "discovery"}


def test_birth_and_death_vocabularies_are_exactly_the_specified_members() -> None:
    assert {m.value for m in BirthRefusal} == {
        "RESIDUAL_TOO_SMALL",
        "NOT_PERSISTENT",
        "VISIBILITY_ARTIFACT",
        "EXPLAINED_BY_EXISTING",
        "FIELD_AT_CAPACITY",
        "NOT_SECURITY_RELEVANT",
    }
    assert {m.value for m in DeathCause} == {
        "HARD_CONTRADICTION",
        "SUSTAINED_TENSION",
        "DOMINATED",
        "EPOCH_INVALIDATION",
        "ASSURANCE_BELOW_THRESHOLD",
        "BUDGET_TRUNCATION",
    }


def test_no_stage4_dataclass_field_carries_an_authority_token() -> None:
    """Trust rule T5, for this package's own types.

    This is the test that fires if someone "fixes" ``retired_at_sequence`` back to
    the spec's ``killed_at_sequence``: ``kill`` is a FORBIDDEN_AUTHORITY_FIELDS
    token and the field name would smuggle response authority into a Stage 4
    record.
    """
    from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS

    owned = (
        Truncation,
        WorldGraphNode,
        EntropyBudget,
        WorldTombstone,
        Residual,
        EvidenceRegime,
        DominanceTest,
    )
    offenders = [
        f"{cls.__name__}.{name}"
        for cls in owned
        for name in cls.__dataclass_fields__
        if any(token in name.lower() for token in FORBIDDEN_AUTHORITY_FIELDS)
    ]
    assert offenders == []


def test_mirrored_constants_match_their_owning_modules() -> None:
    """``entropy_budget`` re-declares constants it cannot import without a cycle.

    Skipping is not an option, so this checks each owning module only if it exists
    and reports what it could not check.
    """
    unchecked: list[str] = []
    for module_name, attr, mirrored in (
        ("pocketsec.stage4.worlds.field", "MAX_WORLDS", EntropyBudget().max_worlds),
        (
            "pocketsec.stage4.counterfactual.intervention",
            "MAX_COUNTERFACTUALS_PER_INCIDENT",
            EntropyBudget().max_counterfactuals,
        ),
        (
            "pocketsec.stage4.identifiability.horizon",
            "DEFAULT_HORIZON_WORK_UNITS",
            EntropyBudget().max_reasoning_units,
        ),
        (
            "pocketsec.stage4.identifiability.horizon",
            "DEFAULT_HORIZON_ESCALATIONS",
            EntropyBudget().max_sensor_escalations,
        ),
    ):
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            unchecked.append(f"{module_name}.{attr}")
            continue
        assert getattr(module, attr) == mirrored, f"{module_name}.{attr} drifted from the mirror"
    # Recorded, not silently passed: an unchecked mirror is an unmeasured claim,
    # and the declared list is what stops a typo'd module path skipping forever.
    assert set(unchecked) <= MIRRORS_PENDING_THEIR_OWNER, (
        f"unexpected unchecked mirrors: {sorted(set(unchecked) - MIRRORS_PENDING_THEIR_OWNER)}"
    )


# --------------------------------------------------------------------------
# Residual construction and refusal
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"magnitude": 1.5},
        {"magnitude": float("nan")},
        {"steps": -1},
        {"consequence": -0.1},
        {"signals": frozenset({""})},
    ],
)
def test_residual_refuses_invalid_fields(kwargs: dict[str, Any]) -> None:
    base: dict[str, Any] = {
        "signals": frozenset({"privilege_change"}),
        "magnitude": 0.5,
        "steps": 2,
        "consequence": 1.0,
    }
    base.update(kwargs)
    with pytest.raises(ContractError):
        residual(
            base["signals"],
            magnitude=base["magnitude"],
            steps=base["steps"],
            consequence=base["consequence"],
        )


def test_residual_refuses_more_signals_than_a_world_may_expect() -> None:
    with pytest.raises(ContractError):
        residual(frozenset(f"signal-{i}" for i in range(33)))


def test_every_birth_refusal_is_reachable() -> None:
    """All six members fire. An unreachable refusal is an unfalsifiable gate."""
    empty = FakeField(incident_id="inc-1")
    fired: dict[BirthRefusal, bool] = {}

    fired[BirthRefusal.NOT_SECURITY_RELEVANT] = (
        spawn_refusal(empty, residual(frozenset({"reachability"})))
        is BirthRefusal.NOT_SECURITY_RELEVANT
    )
    fired[BirthRefusal.RESIDUAL_TOO_SMALL] = (
        spawn_refusal(empty, residual(CRITICAL, magnitude=0.1))
        is BirthRefusal.RESIDUAL_TOO_SMALL
    )
    fired[BirthRefusal.NOT_PERSISTENT] = (
        spawn_refusal(empty, residual(CRITICAL, steps=1)) is BirthRefusal.NOT_PERSISTENT
    )
    fired[BirthRefusal.VISIBILITY_ARTIFACT] = (
        spawn_refusal(empty, residual(CRITICAL), shadow=FakeShadow(blind=CRITICAL))
        is BirthRefusal.VISIBILITY_ARTIFACT
    )
    explained = FakeField(
        incident_id="inc-1",
        worlds=(world("w1", "known_admin", expected=CRITICAL),),
    )
    fired[BirthRefusal.EXPLAINED_BY_EXISTING] = (
        spawn_refusal(explained, residual(CRITICAL)) is BirthRefusal.EXPLAINED_BY_EXISTING
    )
    full = FakeField(
        incident_id="inc-1",
        max_worlds=2,
        worlds=(world("w1", "m1"), world("w2", "m2")),
    )
    fired[BirthRefusal.FIELD_AT_CAPACITY] = (
        spawn_refusal(full, residual(CRITICAL)) is BirthRefusal.FIELD_AT_CAPACITY
    )

    assert set(fired) == set(BirthRefusal)
    assert all(fired.values()), {k.value: v for k, v in fired.items()}


def test_relevance_is_checked_before_size_so_benign_novelty_is_named_correctly() -> None:
    """A big, persistent, benign residual must report NOT_SECURITY_RELEVANT.

    Reporting RESIDUAL_TOO_SMALL here would hide the one refusal that proves
    §12's gate discriminates consequence from novelty (F3).
    """
    loud_but_benign = residual(frozenset({"reachability", "modification"}), magnitude=1.0)
    assert (
        spawn_refusal(FakeField(incident_id="inc-1"), loud_but_benign)
        is BirthRefusal.NOT_SECURITY_RELEVANT
    )


def test_a_world_that_forbids_the_residual_does_not_explain_it() -> None:
    """A contradicting world should be dying, not absorbing the residual."""
    contradictor = world("w1", "m1", expected=frozenset({"module_load"}), forbidden=CRITICAL)
    field = FakeField(incident_id="inc-1", worlds=(contradictor,))
    assert spawn_refusal(field, residual(CRITICAL)) is None


def test_spawn_creates_one_world_and_leaves_the_predecessor_untouched() -> None:
    before = FakeField(incident_id="inc-1")
    after, world_id, refusal = spawn_world(
        before,
        residual(CRITICAL),
        shadow=FakeShadow(),
        epoch_id=1,
        world_factory=fake_unknown_world,
    )
    assert refusal is None and world_id is not None
    assert len(before.worlds) == 0, "the field must be immutable"
    spawned = after.world(world_id)
    assert spawned is not None
    assert spawned.expected_evidence == CRITICAL
    assert spawned.mechanism_id == "unresolved_novel_mechanism"
    assert spawned.latent_state.asserted_dimensions == frozenset(), (
        "an UNKNOWN world asserts nothing: novelty is not maliciousness"
    )


def test_spawn_refuses_an_epoch_mismatch_loudly() -> None:
    """An epoch change invalidates worlds (§13); it never silently rebases them."""
    with pytest.raises(ContractError):
        spawn_world(
            FakeField(incident_id="inc-1", epoch_id=1),
            residual(CRITICAL),
            shadow=None,
            epoch_id=2,
            world_factory=fake_unknown_world,
        )


def test_second_spawn_gets_a_distinct_mechanism_id() -> None:
    field = FakeField(incident_id="inc-1")
    field, first, _ = spawn_world(
        field, residual(CRITICAL), shadow=None, epoch_id=1, world_factory=fake_unknown_world
    )
    field = dataclasses.replace(field, at_sequence=5)
    field, second, refusal = spawn_world(
        field,
        residual(frozenset({"credential_access"})),
        shadow=None,
        epoch_id=1,
        world_factory=fake_unknown_world,
    )
    assert refusal is None and second is not None and second != first
    mechanisms = {w.mechanism_id for w in field.worlds}
    assert len(mechanisms) == 2


# --------------------------------------------------------------------------
# Residuals from real Stage 1 transitions, and F3
# --------------------------------------------------------------------------


def _spawn_rate(
    *, split: str, count: int, seed: int
) -> tuple[int, int, set[BirthRefusal]]:
    """Drive the birth gate from a real Stage 1 replay.

    Each scenario gets its own ``offset`` because ``Stage1Pipeline`` carries
    lineage state across scenarios: reusing identities would saturate privilege
    and manufacture consequence the corpus never described (MEMORY.md).
    """
    pipeline = Stage1Pipeline()
    field = FakeField(incident_id=f"{split}-inc", max_worlds=8)
    transitions = 0
    spawns = 0
    refusals: set[BirthRefusal] = set()
    for index, scenario in enumerate(build_corpus(count=count, seed=seed, split=split)):
        result = pipeline.run_scenario(scenario, offset=index)
        previous: Residual | None = None
        for transition in result.transitions:
            transitions += 1
            field = dataclasses.replace(field, at_sequence=transitions)
            current = residual_from_transition(transition, field.worlds, previous=previous)
            previous = current
            field, world_id, refusal = spawn_world(
                field,
                current,
                shadow=None,
                epoch_id=field.epoch_id,
                world_factory=fake_unknown_world,
            )
            if refusal is not None:
                refusals.add(refusal)
            if world_id is not None:
                spawns += 1
    return transitions, spawns, refusals


@pytest.mark.parametrize(("count", "seed"), [(30, 5), (60, 11)])
def test_benign_corpus_does_not_explode_into_hypotheses(count: int, seed: int) -> None:
    """F3: spawn count must stay at or below one world per 100 transitions, and
    ``NOT_SECURITY_RELEVANT`` must actually fire. A gate that never refuses is
    not a gate."""
    transitions, spawns, refusals = _spawn_rate(split="train", count=count, seed=seed)
    assert transitions >= 60, "corpus too small to say anything"
    assert BirthRefusal.NOT_SECURITY_RELEVANT in refusals
    rate = spawns / (transitions / 100.0)
    assert rate <= 1.0, f"{spawns} spawns over {transitions} benign transitions ({rate:.2f}/100)"


def test_the_birth_gate_is_not_a_blanket_refusal() -> None:
    """The other half of F3, and the more important half.

    A gate that refuses everything trivially satisfies the benign spawn rate and
    proves nothing. The attack-bearing split must spawn strictly more worlds than
    the benign one over a comparable number of transitions. If this ever fails,
    the benign result above is worthless, not reassuring.
    """
    benign_t, benign_spawns, _ = _spawn_rate(split="train", count=30, seed=5)
    attack_t, attack_spawns, _ = _spawn_rate(split="eval", count=30, seed=5)
    assert abs(attack_t - benign_t) < benign_t * 0.25, "splits not comparable in length"
    assert benign_spawns == 0
    assert attack_spawns > benign_spawns, (
        f"gate spawned {attack_spawns} on eval vs {benign_spawns} on train: "
        "a gate that never fires is not a gate"
    )


def test_residual_from_transition_marks_a_shadowed_residual_as_a_visibility_artifact() -> None:
    pipeline = Stage1Pipeline()
    scenario = build_corpus(count=1, seed=5, split="train")[0]
    result = pipeline.run_scenario(scenario)
    raising = [t for t in result.transitions if t.state_delta]
    assert raising, "corpus produced no state change to build a residual from"
    signals = frozenset(
        DIMENSION_SIGNALS[d] for d in raising[0].state_delta.dimensions if d in DIMENSION_SIGNALS
    )
    blind = residual_from_transition(raising[0], (), shadow=FakeShadow(blind=signals))
    seeing = residual_from_transition(raising[0], (), shadow=FakeShadow())
    assert blind.visibility_explained is True
    assert seeing.visibility_explained is False
    assert blind.signals == seeing.signals == signals


# --------------------------------------------------------------------------
# Death and tombstones
# --------------------------------------------------------------------------


def test_kill_world_keeps_the_evidence_digests_needed_to_rebuild_it() -> None:
    refs = (evidence("a"), evidence("b"))
    field = FakeField(
        incident_id="inc-1",
        worlds=(world("w1", "m1", refs=refs, consequence=3.0),),
        at_sequence=7,
    )
    after, stone = kill_world(field, "w1", DeathCause.DOMINATED, "dominated by w2")
    assert after.worlds == ()
    assert stone.retired_at_sequence == 7
    assert stone.evidence_digests == tuple(sorted(r.digest for r in refs))
    assert stone.reopenable is True
    assert stone.consequence == pytest.approx(3.0)


def test_an_evidential_death_is_not_reopenable() -> None:
    field = FakeField(incident_id="inc-1", worlds=(world("w1", "m1"),))
    _, stone = kill_world(field, "w1", DeathCause.HARD_CONTRADICTION, "forbidden signal observed")
    assert stone.reopenable is False


def test_kill_world_refuses_an_unknown_world() -> None:
    with pytest.raises(ContractError):
        kill_world(FakeField(incident_id="inc-1"), "ghost", DeathCause.DOMINATED, "x")


def test_tombstone_refuses_a_bad_cause_and_a_bad_digest() -> None:
    good = dict(
        world_id="w1",
        mechanism_id="m1",
        cause=DeathCause.DOMINATED,
        detail="d",
        retired_at_sequence=0,
        support_at_death=0.1,
        reopenable=True,
        evidence_digests=(),
    )
    with pytest.raises(ContractError):
        WorldTombstone(**{**good, "cause": "NOT_A_CAUSE"})
    with pytest.raises(ContractError):
        WorldTombstone(**{**good, "evidence_digests": ("deadbeef",)})


def test_oscillation_is_refused_on_the_spawn_kill_spawn_loop() -> None:
    """spawn -> kill -> spawn must not be allowed to cycle.

    An evidential death closes the mechanism immediately; a resource death buys
    one reopening and no more.
    """
    ledger = TombstoneLedger()
    field = FakeField(incident_id="inc-1")
    field, world_id, refusal = spawn_world(
        field,
        residual(CRITICAL),
        shadow=None,
        epoch_id=1,
        tombstones=ledger,
        world_factory=fake_unknown_world,
    )
    assert refusal is None and world_id is not None
    field, stone = kill_world(field, world_id, DeathCause.HARD_CONTRADICTION, "refuted")
    ledger.record(stone)
    assert ledger.oscillating(stone.mechanism_id) is True
    _, second, refusal = spawn_world(
        field,
        residual(CRITICAL),
        shadow=None,
        epoch_id=1,
        tombstones=ledger,
        world_factory=fake_unknown_world,
    )
    assert second is None
    assert refusal is BirthRefusal.EXPLAINED_BY_EXISTING


def test_a_resource_death_allows_exactly_one_reopening() -> None:
    ledger = TombstoneLedger()
    stone = WorldTombstone(
        world_id="w1",
        mechanism_id="m1",
        cause=DeathCause.BUDGET_TRUNCATION,
        detail="budget",
        retired_at_sequence=1,
        support_at_death=0.4,
        reopenable=True,
        evidence_digests=(digest("a"),),
    )
    ledger.record(stone)
    assert ledger.oscillating("m1") is False
    reopened = ledger.reopen("m1")
    assert reopened is not None and reopened.world_id == "w1"
    assert ledger.reopen("m1") is None, "a tombstone is a one-shot licence to rebuild"
    ledger.record(dataclasses.replace(stone, world_id="w2", retired_at_sequence=9))
    assert ledger.oscillating("m1") is True, "dying twice for resource reasons is oscillation"


def test_tombstone_eviction_is_oldest_lowest_consequence_and_never_drops_a_digest() -> None:
    ledger = TombstoneLedger(max_tombstones=4)
    losses: list[Truncation] = []
    for index in range(10):
        losses.extend(
            ledger.record(
                WorldTombstone(
                    world_id=f"w{index}",
                    mechanism_id=f"m{index}",
                    cause=DeathCause.DOMINATED,
                    detail="d",
                    retired_at_sequence=index,
                    support_at_death=0.1,
                    reopenable=True,
                    evidence_digests=(digest(f"ev-{index}"),),
                    consequence=float(index),
                )
            )
        )
    assert len(ledger) == 4
    # Six evictions, each recorded exactly once, and each naming the lowest
    # remaining consequence at the time.
    assert [t.identifier for t in losses] == [f"w{i}" for i in range(6)]
    assert all(t.what == "tombstone" for t in losses)
    assert total_consequence_lost(losses) == pytest.approx(sum(range(6)))
    # Every digest ever recorded survives eviction of its narrative record.
    assert ledger.digests() == frozenset(digest(f"ev-{i}") for i in range(10))
    assert ledger.deaths("m0") == 1, "the death count outlives the evicted record"
    assert ledger.oscillating("m0") is False


def test_a_refutation_survives_tombstone_eviction() -> None:
    """Would fail if ``oscillating`` went back to scanning only resident records.

    The evicted record is the one an attacker wants gone: if a refutation expires
    with its tombstone, the spawn -> kill -> spawn loop restarts for free.
    """
    ledger = TombstoneLedger(max_tombstones=2)
    refuted = WorldTombstone(
        world_id="w0",
        mechanism_id="m_refuted",
        cause=DeathCause.HARD_CONTRADICTION,
        detail="forbidden signal observed",
        retired_at_sequence=0,
        support_at_death=0.1,
        reopenable=False,
        evidence_digests=(digest("ev-0"),),
        consequence=0.0,
    )
    ledger.record(refuted)
    for index in (1, 2, 3):
        ledger.record(
            dataclasses.replace(
                refuted,
                world_id=f"w{index}",
                mechanism_id=f"m{index}",
                cause=DeathCause.DOMINATED,
                reopenable=True,
                consequence=5.0,
            )
        )
    assert ledger.tombstones() and all(
        stone.mechanism_id != "m_refuted" for stone in ledger.tombstones()
    ), "the refuted record must have been evicted for this test to mean anything"
    assert ledger.refuted("m_refuted") is True
    assert ledger.oscillating("m_refuted") is True


def test_mechanism_tracking_is_bounded_and_refuses_new_rather_than_forgetting_old() -> None:
    from pocketsec.stage4.worlds.tombstone import MAX_TRACKED_MECHANISMS

    ledger = TombstoneLedger()
    losses: list[Truncation] = []
    for index in range(MAX_TRACKED_MECHANISMS + 5):
        losses.extend(
            ledger.record(
                WorldTombstone(
                    world_id=f"w{index}",
                    mechanism_id=f"m{index}",
                    cause=DeathCause.HARD_CONTRADICTION,
                    detail="d",
                    retired_at_sequence=index,
                    support_at_death=0.1,
                    reopenable=False,
                    evidence_digests=(digest(f"ev-{index}"),),
                )
            )
        )
    report = ledger.report()
    assert report["tracked_mechanisms"] == MAX_TRACKED_MECHANISMS
    assert report["untracked_mechanisms"] == 5
    untracked = [t for t in losses if "mechanism_tracking_capacity" in t.reason]
    assert len(untracked) == 5, "an unarmed oscillation guard is an explicit loss"
    assert ledger.refuted("m0") is True, "the earliest refutation is never forgotten"


def test_tombstone_ledger_memory_is_bounded_and_measured() -> None:
    ledger = TombstoneLedger()
    for index in range(MAX_TOMBSTONES * 3):
        ledger.record(
            WorldTombstone(
                world_id=f"w{index}",
                mechanism_id=f"m{index}",
                cause=DeathCause.DOMINATED,
                detail="d",
                retired_at_sequence=index,
                support_at_death=0.1,
                reopenable=True,
                evidence_digests=(digest(f"ev-{index}"),),
                consequence=float(index % 7),
            )
        )
    assert len(ledger) == MAX_TOMBSTONES
    report = ledger.report()
    assert report["retained_digests"] == MAX_TOMBSTONES * 3
    assert 0 < report["memory_bytes"] < MAX_INCIDENT_BYTES


# --------------------------------------------------------------------------
# Fission and fusion
# --------------------------------------------------------------------------


def _regimes() -> tuple[EvidenceRegime, EvidenceRegime]:
    left = EvidenceRegime(
        label="interactive",
        expected=frozenset({"authentication"}),
        forbidden=frozenset({"module_load"}),
        consequence=2.0,
    )
    right = EvidenceRegime(
        label="implanted",
        expected=frozenset({"module_load"}),
        forbidden=frozenset({"authentication"}),
        consequence=5.0,
    )
    return left, right


def test_fission_splits_only_on_incompatible_regimes() -> None:
    parent = world("w1", "ambiguous_admin", expected=CRITICAL)
    field = FakeField(incident_id="inc-1", worlds=(parent,))
    left, right = _regimes()

    same = EvidenceRegime(label="a", expected=frozenset({"authentication"}), forbidden=frozenset())
    other = EvidenceRegime(label="b", expected=frozenset({"module_load"}), forbidden=frozenset())
    unchanged, pair = fission_world(field, "w1", (same, other))
    assert pair is None and unchanged.worlds == field.worlds

    split, pair = fission_world(field, "w1", (left, right))
    assert pair is not None
    assert {w.world_id for w in split.worlds} == set(pair)
    assert all(w.fission_depth == 1 for w in split.worlds)
    assert {w.mechanism_id for w in split.worlds} == {
        "ambiguous_admin.interactive",
        "ambiguous_admin.implanted",
    }
    for child in split.worlds:
        assert child.expected_evidence & child.forbidden_evidence == frozenset()
        assert child.support.value == parent.support.value, "support is not redistributed"


def test_fission_beyond_max_depth_records_the_branch_it_lost() -> None:
    deep = dataclasses.replace(
        world("w1", "m1", expected=CRITICAL), fission_depth=MAX_FISSION_DEPTH
    )
    field = FakeField(incident_id="inc-1", worlds=(deep,))
    after, pair = fission_world(field, "w1", _regimes())
    assert pair is None
    assert len(after.truncations) == 1
    (lost,) = after.truncations
    assert lost.what == "branch"
    assert "MAX_FISSION_DEPTH" in lost.reason
    assert lost.consequence_lost == pytest.approx(5.0)


def test_fission_at_capacity_records_the_branch_it_lost() -> None:
    worlds = tuple(world(f"w{i}", f"m{i}", expected=CRITICAL) for i in range(3))
    field = FakeField(incident_id="inc-1", max_worlds=3, worlds=worlds)
    after, pair = fission_world(field, "w0", _regimes())
    assert pair is None
    assert [t.what for t in after.truncations] == ["branch"]
    assert "field_at_capacity" in after.truncations[0].reason


def test_fusion_merges_equivalent_worlds_without_recording_a_loss() -> None:
    left = world("w1", "m1", expected=CRITICAL, support=0.60, refs=(evidence("a"),))
    right = world("w2", "m2", expected=CRITICAL, support=0.62, refs=(evidence("b"),))
    field = FakeField(incident_id="inc-1", worlds=(left, right))
    after, fused_id = fuse_worlds(field, "w1", "w2")
    assert fused_id == "w2", "the better-supported world survives"
    assert len(after.worlds) == 1
    fused = after.world(fused_id)
    assert fused is not None
    assert {r.digest for r in fused.evidence_refs} == {evidence("a").digest, evidence("b").digest}
    assert after.truncations == (), (
        "fusion loses nothing: the survivor explains everything the absorbed world did"
    )


def test_fusion_refuses_worlds_that_are_not_observationally_equivalent() -> None:
    left = world("w1", "m1", expected=CRITICAL, support=0.1)
    right = world("w2", "m2", expected=CRITICAL, support=0.9)
    field = FakeField(incident_id="inc-1", worlds=(left, right))
    after, fused_id = fuse_worlds(field, "w1", "w2")
    assert fused_id is None and after.worlds == field.worlds
    assert abs(0.9 - 0.1) > FUSION_EQUIVALENCE_EPSILON


def test_fusion_refuses_a_missing_or_self_pair() -> None:
    field = FakeField(incident_id="inc-1", worlds=(world("w1", "m1"),))
    with pytest.raises(ContractError):
        fuse_worlds(field, "w1", "w1")
    with pytest.raises(ContractError):
        fuse_worlds(field, "w1", "ghost")


# --------------------------------------------------------------------------
# Dominance pruning and the hard veto
# --------------------------------------------------------------------------


def test_dominance_reports_all_five_clauses_separately() -> None:
    winner = world("w1", "m1", expected=CRITICAL, consequence=2.0)
    loser = world(
        "w2",
        "m2",
        expected=CRITICAL,
        contradictions=("saw forbidden module_load",),
        consequence=1.0,
    )
    test = dominance_test(winner, loser)
    assert test.to_dict() == {
        "explains_critical_evidence": True,
        "no_more_contradictions": True,
        "no_more_unsupported_assumptions": True,
        "within_representation_budget": True,
        "no_unique_critical_future_lost": True,
    }
    assert test.dominates() is True
    assert test.vetoed() is False
    rows = dominance_report(FakeField(incident_id="inc-1", worlds=(winner, loser)))
    assert len(rows) == 2, "every ordered pair is reported, so a pruning is auditable"


def test_the_fifth_clause_vetoes_a_pruning_that_would_lose_the_exfiltration_world() -> None:
    """§30's hard veto, as the case it exists for.

    ``w_exfil`` is worse on every other clause — fewer explanations, more
    contradictions, larger representation — and it is the only world predicting
    ``exfiltration``. A pruning that removed it would not have reduced
    complexity; it would have lost the answer.
    """
    simple = world(
        "w_simple",
        "approved_admin",
        expected=CRITICAL,
        consequence=0.5,
        support=0.8,
    )
    exfil = world(
        "w_exfil",
        "compromised_session",
        expected=CRITICAL | frozenset({"exfiltration"}),
        contradictions=("one unexplained gap",),
        consequence=9.0,
        support=0.2,
    )
    field = FakeField(incident_id="inc-1", worlds=(simple, exfil))

    naive = dominance_test(
        simple,
        exfil,
        futures={"w_simple": frozenset(), "w_exfil": frozenset()},
    )
    assert naive.dominates() is True, "without the veto, the exfil world is dominated"

    guarded = dominance_test(simple, exfil)
    assert guarded.no_unique_critical_future_lost is False
    assert guarded.vetoed() is True, "the other four clauses passed; only the veto refused"
    assert guarded.dominates() is False

    after, pruned = prune_dominated_worlds(field)
    assert pruned == ()
    assert {w.world_id for w in after.worlds} == {"w_simple", "w_exfil"}
    assert after.truncations == ()


def test_dominance_pruning_removes_a_genuinely_redundant_world_and_records_it() -> None:
    keeper = world("w1", "m1", expected=CRITICAL, consequence=4.0)
    redundant = world(
        "w2",
        "m2",
        expected=CRITICAL,
        consequence=0.5,
        contradictions=("saw forbidden module_load", "missing expected authentication"),
    )
    field = FakeField(incident_id="inc-1", worlds=(keeper, redundant))
    after, pruned = prune_dominated_worlds(field)
    assert pruned == ("w2",)
    assert [w.world_id for w in after.worlds] == ["w1"]
    assert len(after.truncations) == 1
    (loss,) = after.truncations
    assert (loss.what, loss.identifier, loss.consequence_lost) == ("world", "w2", 0.5)
    assert loss.reason == "dominated_by:w1"


def test_pruning_never_empties_the_field() -> None:
    twins = (world("w1", "m1", expected=CRITICAL), world("w2", "m2", expected=CRITICAL))
    field = FakeField(incident_id="inc-1", worlds=twins)
    after, pruned = prune_dominated_worlds(field)
    assert len(after.worlds) >= 1
    assert len(pruned) <= 1


# --------------------------------------------------------------------------
# Sparse world graph
# --------------------------------------------------------------------------


def node(
    signature: str,
    *,
    credit: float = 0.0,
    contradiction: float = 0.0,
    discrimination: float = 0.0,
    mandatory: bool = False,
) -> WorldGraphNode:
    return WorldGraphNode(
        signature=signature,
        causal_credit=credit,
        contradiction_value=contradiction,
        discrimination_value=discrimination,
        mandatory=mandatory,
        state_delta_mask=1,
    )


@pytest.mark.parametrize(
    ("kwargs", "retained"),
    [
        ({}, False),
        ({"credit": RETENTION_THRESHOLD}, False),
        ({"credit": RETENTION_THRESHOLD + 0.01}, True),
        ({"contradiction": 0.9}, True),
        ({"discrimination": 0.9}, True),
        ({"mandatory": True}, True),
    ],
)
def test_node_retention_implements_the_four_clause_rule(
    kwargs: dict[str, Any], retained: bool
) -> None:
    assert node("sig", **kwargs).retained() is retained


def test_a_mandatory_node_is_retained_and_never_evicted() -> None:
    """Stage 1's AOP may never stop collecting a mandatory signal, so the graph
    may never forget one either."""
    graph = SparseWorldGraph(max_nodes=2)
    assert graph.add(node("m", mandatory=True)) == ()
    assert graph.add(node("m2", mandatory=True)) == ()
    losses = graph.add(node("strong", credit=1.0))
    assert [t.reason for t in losses] == ["node_capacity_all_resident_nodes_mandatory"]
    assert {n.signature for n in graph.nodes()} == {"m", "m2"}
    assert graph.prune() == (), "pruning never touches a mandatory node"


def test_a_non_retained_node_is_refused_with_exactly_one_truncation() -> None:
    graph = SparseWorldGraph()
    losses = graph.add(node("noise"))
    assert len(losses) == 1
    assert losses[0].what == "graph_node"
    assert losses[0].reason == "below_retention_threshold"
    assert len(graph) == 0


def test_node_capacity_evicts_the_weakest_and_records_exactly_one_loss() -> None:
    graph = SparseWorldGraph(max_nodes=3)
    for index, credit in enumerate((0.2, 0.9, 0.5)):
        assert graph.add(node(f"n{index}", credit=credit)) == ()
    losses = graph.add(node("newcomer", credit=0.8))
    assert [(t.what, t.identifier) for t in losses] == [("graph_node", "n0")]
    assert {n.signature for n in graph.nodes()} == {"n1", "n2", "newcomer"}
    weaker = graph.add(node("weakling", credit=0.06))
    assert [t.reason for t in weaker] == ["node_capacity_incoming_weaker_than_resident"]


def test_edges_are_bounded_and_every_refusal_is_recorded() -> None:
    graph = SparseWorldGraph(max_nodes=8, max_edges=2)
    for index in range(4):
        graph.add(node(f"n{index}", credit=0.5 + index / 10))
    assert graph.link("n0", "n1") == ()
    assert graph.link("n1", "n2") == ()
    evicted = graph.link("n2", "n3")
    assert [t.what for t in evicted] == ["graph_edge"]
    assert len(graph.edges()) == 2
    assert [t.reason for t in graph.link("n0", "ghost")] == ["endpoint_absent:ghost"]
    assert [t.reason for t in graph.link("n0", "n0")] == ["self_loop_refused"]


def test_dropping_a_node_records_every_edge_it_took_with_it() -> None:
    graph = SparseWorldGraph(max_nodes=3)
    graph.add(node("hub", credit=0.5))
    graph.add(node("a", credit=0.9))
    graph.add(node("b", credit=0.9))
    graph.link("hub", "a")
    graph.link("hub", "b")
    losses = graph.add(node("newcomer", credit=0.95))
    kinds = [t.what for t in losses]
    assert kinds == ["graph_node", "graph_edge", "graph_edge"], (
        "a cascaded edge loss is still a loss and gets its own record"
    )
    assert graph.edges() == ()


def test_graph_nodes_key_on_a_real_stage1_causal_signature() -> None:
    """The graph is keyed on ``CausalNode.signature``, built from semantics, so
    renaming a binary does not move a node. Grounded on the real spine rather
    than on hand-written strings."""
    pipeline = Stage1Pipeline()
    for index, scenario in enumerate(build_corpus(count=6, seed=3, split="eval")):
        pipeline.run_scenario(scenario, offset=index)
    spine = pipeline.causal.spine()
    assert spine, "Stage 1 produced no causal spine to key on"
    graph = SparseWorldGraph()
    losses: list[Truncation] = []
    for causal_node in spine:
        losses.extend(
            graph.add(
                WorldGraphNode(
                    signature=causal_node.signature,
                    causal_credit=min(1.0, abs(causal_node.delta_phi) / 10.0),
                    contradiction_value=0.0,
                    discrimination_value=0.0,
                    mandatory=False,
                    state_delta_mask=causal_node.state_delta_mask,
                )
            )
        )
    assert len(graph) + len([t for t in losses if t.what == "graph_node"]) == len(spine)
    assert {n.signature for n in graph.nodes()} <= {n.signature for n in spine}


def test_graph_memory_bytes_grows_with_what_is_actually_stored() -> None:
    graph = SparseWorldGraph()
    empty = graph.memory_bytes()
    for index in range(50):
        graph.add(node(f"signature-{index:04d}", credit=0.5))
    filled = graph.memory_bytes()
    assert filled > empty
    for index in range(49):
        graph.link(f"signature-{index:04d}", f"signature-{index + 1:04d}")
    assert graph.memory_bytes() > filled


# --------------------------------------------------------------------------
# Entropy budget
# --------------------------------------------------------------------------


def test_budget_refuses_an_impossible_configuration() -> None:
    with pytest.raises(ContractError):
        EntropyBudget(max_worlds=0)
    with pytest.raises(ContractError):
        EntropyBudget(max_edges=MAX_GRAPH_EDGES + 1)
    with pytest.raises(ContractError):
        EntropyBudget(max_memory_bytes=MAX_INCIDENT_BYTES + 1)
    with pytest.raises(ContractError):
        EntropyBudget(max_reasoning_ms=0.0)


def test_charging_saturates_at_the_cap_so_the_bound_holds_by_construction() -> None:
    controller = BudgetController(EntropyBudget(max_reasoning_units=10))
    controller.charge("world_birth", 6)
    controller.charge("tension", 9)
    report = controller.spend_report()
    assert report["reasoning_units"] == 10
    assert report["refused_units"] == 5, "the overrun is recorded, not forgotten"
    assert report["kind.world_birth"] == 6 and report["kind.tension"] == 4
    assert controller.exhausted() is True


def test_charge_refuses_an_unknown_kind_and_a_negative_amount() -> None:
    controller = BudgetController()
    with pytest.raises(ContractError):
        controller.charge("not_a_kind", 1)
    with pytest.raises(ContractError):
        controller.charge("tension", -1)
    assert "tension" in BUDGET_KINDS


def test_counterfactual_and_escalation_bounds_are_separate_from_work_units() -> None:
    controller = BudgetController(EntropyBudget(max_counterfactuals=2, max_sensor_escalations=1))
    controller.charge("counterfactual", 1)
    assert controller.exhausted() is False
    controller.charge("sensor_escalation", 1)
    assert controller.exhausted() is True
    assert controller.spend_report()["sensor_escalations"] == 1


def test_wall_clock_is_observed_only_and_unset_means_unmeasured() -> None:
    """§2.8: this host's load swung 1.88 -> 3.04 in twenty idle minutes, so a
    millisecond bound would make G4.9 a coin flip."""
    controller = BudgetController(EntropyBudget(max_reasoning_units=10))
    assert controller.advisory_ms_exceeded() is None, "unset is None, never False"
    controller.observe(5_000_000_000)
    assert controller.exhausted() is False, "wall clock must never exhaust the budget"
    advisory = BudgetController(EntropyBudget(max_reasoning_ms=1.0))
    advisory.observe(5_000_000)
    assert advisory.advisory_ms_exceeded() is True
    assert advisory.exhausted() is False


def test_timed_scope_charges_work_and_observes_elapsed_time_even_on_failure() -> None:
    controller = BudgetController(EntropyBudget(max_reasoning_units=100))
    with pytest.raises(RuntimeError):
        with controller.timed("tension", 3):
            raise RuntimeError("mid-incident failure")
    report = controller.spend_report()
    assert report["reasoning_units"] == 3
    assert report["observed_ms"] >= 0


def test_safe_prune_never_removes_the_last_non_benign_world() -> None:
    """§45: OOM pressure prunes low-consequence dominated worlds first and never
    converts uncertainty into benign."""
    benign_a = world("w_b1", "routine_backup", expected=CRITICAL, consequence=0.0)
    benign_b = world("w_b2", "routine_indexer", expected=CRITICAL, consequence=0.0)
    worrying = world(
        "w_bad",
        "compromised_session",
        expected=CRITICAL,
        consequence=7.0,
        dims=frozenset({"privilege"}),
    )
    # The field is legal at its own cap; the controller's BUDGET is what is
    # exceeded, which is the real §45 situation (memory pressure, not a bad field).
    field = FakeField(incident_id="inc-1", worlds=(benign_a, benign_b, worrying))
    controller = BudgetController(EntropyBudget(max_worlds=1))
    after, losses = controller.safe_prune(field)
    surviving = {w.world_id for w in after.worlds}
    assert "w_bad" in surviving, "the last non-benign world is never pruned"
    assert len(after.worlds) < len(field.worlds), "safe pruning still made progress"
    assert {t.identifier for t in losses} == set(
        w.world_id for w in field.worlds
    ) - surviving
    assert all(t.reason == "budget_truncation_low_consequence_dominated" for t in losses)


def test_safe_prune_refuses_rather_than_resolving_an_unresolved_field_as_benign() -> None:
    """The most dangerous line of code available to this module, pinned.

    A field holding one worrying world and one benign one, over its byte budget,
    must come back still holding the worrying world — even at the cost of staying
    over budget.
    """
    worrying = world(
        "w_bad", "exfil", expected=CRITICAL, consequence=9.0, dims=frozenset({"credential"})
    )
    benign = world("w_ok", "backup", expected=CRITICAL, consequence=0.0)
    field = FakeField(incident_id="inc-1", worlds=(worrying, benign))
    controller = BudgetController(EntropyBudget(max_worlds=1))
    after, losses = controller.safe_prune(field)
    assert "w_bad" in {w.world_id for w in after.worlds}
    assert len(after.worlds) == 1
    assert [t.identifier for t in losses] == ["w_ok"]


def test_safe_prune_leaves_a_within_budget_field_alone() -> None:
    field = FakeField(incident_id="inc-1", worlds=(world("w1", "m1"),))
    after, losses = BudgetController().safe_prune(field)
    assert after is field and losses == ()


# --------------------------------------------------------------------------
# The flood: bounds under adversarial load
# --------------------------------------------------------------------------

#: The world the flood must not wash away. Its mechanism and its unique predicted
#: future are what make "the ground truth survived" a real assertion rather than a
#: restatement of the bound.
GROUND_TRUTH_ID = "w_ground_truth"
GROUND_TRUTH_FUTURE = "exfiltration"


def _ground_truth_world() -> FakeWorld:
    return world(
        GROUND_TRUTH_ID,
        "stolen_credential_exfil",
        expected=frozenset({"credential_access", GROUND_TRUTH_FUTURE}),
        consequence=9.5,
        support=0.3,
        dims=frozenset({"credential"}),
    )


def _flood_residuals(count: int, *, seed: int) -> list[Residual]:
    """An adversarial branch flood: every residual is security-critical,
    persistent, fully unexplained and cheap to produce."""
    rng = random.Random(seed)
    critical = sorted(MANDATORY_SIGNALS)
    out: list[Residual] = []
    for index in range(count):
        signals = frozenset(
            {rng.choice(critical), f"flood_signal_{index:04d}", f"flood_alt_{index % 7}"}
        )
        out.append(
            residual(
                signals,
                magnitude=1.0,
                steps=RESIDUAL_PERSISTENCE_STEPS + 1,
                consequence=rng.uniform(0.5, 3.0),
            )
        )
    return out


def _run_flood(count: int = 700, *, seed: int = 23) -> dict[str, Any]:
    """Drive the whole lifecycle under flood, checking every bound at every step."""
    graph = SparseWorldGraph()
    budget = EntropyBudget(max_worlds=8, max_reasoning_units=512)
    controller = BudgetController(budget)
    ledger = TombstoneLedger()
    field = FakeField(
        incident_id="flood-inc",
        max_worlds=budget.max_worlds,
        worlds=(_ground_truth_world(),),
        graph=graph,
    )
    futures = {GROUND_TRUTH_ID: frozenset({GROUND_TRUTH_FUTURE})}
    refusals: dict[str, int] = {}
    removed: list[str] = []
    graph_losses: list[Truncation] = []
    spawned = 0

    for step, res in enumerate(_flood_residuals(count, seed=seed), start=1):
        field = dataclasses.replace(field, at_sequence=step)
        controller.charge("evidence_integration", 1)
        graph_losses.extend(_flood_graph_step(graph, step))

        field, world_id, refusal = spawn_world(
            field,
            res,
            shadow=None,
            epoch_id=field.epoch_id,
            tombstones=ledger,
            world_factory=fake_unknown_world,
        )
        if refusal is not None:
            refusals[refusal.value] = refusals.get(refusal.value, 0) + 1
        else:
            spawned += 1
            controller.charge("world_birth", 2)
        # Measured after the spawn: a world born and pruned in the same step is
        # still a world that was removed, and it must still be accounted for.
        present = {w.world_id for w in field.worlds}
        field, pruned = prune_dominated_worlds(field, futures=_futures_for(field, futures))
        controller.charge("dominance_pruning", 1)
        field, _ = controller.safe_prune(field)
        removed.extend(present - {w.world_id for w in field.worlds})

        _assert_bounds(field, graph, controller, budget, step)

    return _flood_result(field, graph, controller, refusals, removed, graph_losses, spawned, count)


def _flood_result(
    field: FakeField,
    graph: SparseWorldGraph,
    controller: BudgetController,
    refusals: dict[str, int],
    removed: list[str],
    graph_losses: list[Truncation],
    spawned: int,
    count: int,
) -> dict[str, Any]:
    return {
        "field": field,
        "graph": graph,
        "controller": controller,
        "refusals": refusals,
        "removed": removed,
        "graph_losses": tuple(graph_losses),
        "spawned": spawned,
        "steps": count,
    }


#: Flooded worlds carrying this signal are given a unique critical future, which
#: makes them UNPRUNABLE under §30's veto. That is the adversary's best move: an
#: attacker who can manufacture worlds the safety clause protects fills the field
#: and starves it. The flood must still stay inside every bound, and the ground
#: truth must still survive.
UNPRUNABLE_FLOOD_SIGNAL = "flood_alt_0"


def _flood_graph_step(graph: SparseWorldGraph, step: int) -> tuple[Truncation, ...]:
    """One step of graph pressure: a fresh node, chained to its predecessor."""
    losses = list(
        graph.add(
            node(f"sig-{step:05d}", credit=0.1 + (step % 9) / 10.0, mandatory=step % 50 == 0)
        )
    )
    if step > 1:
        losses.extend(graph.link(f"sig-{step - 1:05d}", f"sig-{step:05d}"))
    return tuple(losses)


def _futures_for(
    field: FakeField, seeded: dict[str, frozenset[str]]
) -> dict[str, frozenset[str]]:
    """The critical futures each world predicts, as the future cone would supply."""
    mapping: dict[str, frozenset[str]] = {}
    for candidate in field.worlds:
        if UNPRUNABLE_FLOOD_SIGNAL in candidate.expected_evidence:
            mapping[candidate.world_id] = frozenset({f"future.{candidate.world_id}"})
        else:
            mapping[candidate.world_id] = frozenset()
    mapping.update(seeded)
    return mapping


def _assert_bounds(
    field: FakeField,
    graph: SparseWorldGraph,
    controller: BudgetController,
    budget: EntropyBudget,
    step: int,
) -> None:
    assert len(field.worlds) <= budget.max_worlds, f"world bound broke at step {step}"
    assert len(graph) <= MAX_GRAPH_NODES, f"node bound broke at step {step}"
    assert len(graph.edges()) <= MAX_GRAPH_EDGES, f"edge bound broke at step {step}"
    spend = controller.spend_report()
    assert spend["reasoning_units"] <= budget.max_reasoning_units, f"work bound broke at {step}"
    assert field.state_bytes() <= MAX_INCIDENT_BYTES, f"byte bound broke at step {step}"


def test_world_flood_holds_every_bound_while_the_field_is_being_flooded() -> None:
    result = _run_flood()
    field: FakeField = result["field"]
    graph: SparseWorldGraph = result["graph"]
    assert result["steps"] == 700
    assert len(graph) == MAX_GRAPH_NODES, "the flood must actually reach the node bound"
    assert result["refusals"].get("FIELD_AT_CAPACITY", 0) > 0, (
        "the flood must actually press against the world bound"
    )
    assert result["controller"].spend_report()["reasoning_units"] == 512
    assert field.state_bytes() <= MAX_INCIDENT_BYTES


def test_the_ground_truth_world_survives_the_flood() -> None:
    """A bound that discards the true world has not bounded anything useful."""
    result = _run_flood()
    field: FakeField = result["field"]
    assert GROUND_TRUTH_ID in {w.world_id for w in field.worlds}
    truth = field.world(GROUND_TRUTH_ID)
    assert truth is not None and truth.predicts(GROUND_TRUTH_FUTURE)


def test_every_world_the_flood_removed_produced_exactly_one_truncation() -> None:
    result = _run_flood()
    field: FakeField = result["field"]
    removed: list[str] = result["removed"]
    world_losses = [t for t in field.truncations if t.what == "world"]
    assert sorted(removed) == sorted(t.identifier for t in world_losses)
    assert len(removed) == len(set(removed)), "a world cannot be lost twice"
    assert all(t.reason for t in world_losses)
    assert all(math.isfinite(t.consequence_lost) for t in world_losses)
    assert GROUND_TRUTH_ID not in removed


def test_every_graph_loss_in_the_flood_is_named_and_accounted() -> None:
    result = _run_flood()
    graph: SparseWorldGraph = result["graph"]
    losses: tuple[Truncation, ...] = result["graph_losses"]
    node_attempts = result["steps"]
    accepted = len(graph)
    refused_or_evicted = [t for t in losses if t.what == "graph_node"]
    assert accepted + len(refused_or_evicted) == node_attempts, (
        "every node offered is either resident or accounted for by one Truncation"
    )
    assert all(t.what in TRUNCATION_KINDS for t in losses)
    assert total_consequence_lost(losses) >= 0.0


def test_flooding_the_budget_never_lets_the_counter_pass_its_cap() -> None:
    """Would fail if someone replaced the saturating charge with a plain add."""
    controller = BudgetController(EntropyBudget(max_reasoning_units=64))
    for _ in range(1000):
        controller.charge("tension", 3)
        assert controller.spend_report()["reasoning_units"] <= 64
    assert controller.spend_report()["refused_units"] == 3000 - 64


def test_flood_is_deterministic_under_its_seed() -> None:
    first, second = _run_flood(count=120, seed=7), _run_flood(count=120, seed=7)
    assert first["removed"] == second["removed"]
    assert first["refusals"] == second["refusals"]
    assert first["controller"].spend_report() == second["controller"].spend_report()

# --------------------------------------------------------------------------
# The same lifecycle, against the real foundation types
# --------------------------------------------------------------------------


def _real_foundation() -> tuple[Any, Any] | None:
    """``(CausalBeliefField, unknown_world)`` when package 1 has landed, else None.

    Guarded rather than imported at module scope: this package is built in the
    same wave as ``worlds/field.py``, and a hard import would make the lifecycle's
    own tests unrunnable while that module is in flight. The guard is recorded in
    the assertion below so a permanently-unreached branch cannot hide.
    """
    try:
        from pocketsec.stage4.worlds.field import CausalBeliefField, unknown_world
    except ImportError:
        return None
    return CausalBeliefField, unknown_world


def test_the_real_foundation_types_are_exercised_or_the_gap_is_named() -> None:
    real = _real_foundation()
    assert real is not None, (
        "pocketsec.stage4.worlds.field is absent: the lifecycle was verified only "
        "against doubles built to the published field list"
    )


def test_lifecycle_round_trip_on_a_real_causal_belief_field() -> None:
    real = _real_foundation()
    assert real is not None
    field_cls, unknown = real
    field = field_cls(incident_id="real-inc", epoch_id=1, worlds=())

    field, first, refusal = spawn_world(
        field, residual(CRITICAL), shadow=None, epoch_id=1
    )
    assert refusal is None and first is not None
    field = dataclasses.replace(field, at_sequence=3)
    field, second, refusal = spawn_world(
        field, residual(frozenset({"credential_access"})), shadow=None, epoch_id=1
    )
    assert refusal is None and second is not None

    split, pair = fission_world(field, first, _regimes())
    assert pair is not None and len(split.worlds) == 3

    clone = dataclasses.replace(
        field.world(first), world_id="w-real-clone", mechanism_id="real_clone_mechanism"
    )
    with_clone = field.with_worlds((*field.worlds, clone))
    fused_field, fused_id = fuse_worlds(with_clone, first, "w-real-clone")
    assert fused_id is not None

    after, stone = kill_world(fused_field, fused_id, DeathCause.SUSTAINED_TENSION, "tension")
    assert stone.reopenable is False
    assert TombstoneLedger().record(stone) == ()

    # Disjoint predictions: §30's veto must protect both worlds.
    kept, pruned = prune_dominated_worlds(field)
    assert pruned == () and len(kept.worlds) == 2


def test_real_field_flood_holds_every_bound_and_keeps_the_ground_truth() -> None:
    """The flood again, on the real field, which enforces its own invariants."""
    real = _real_foundation()
    assert real is not None
    field_cls, unknown = real
    graph = SparseWorldGraph()
    budget = EntropyBudget(max_worlds=8, max_reasoning_units=512)
    controller = BudgetController(budget)
    ledger = TombstoneLedger()
    field = field_cls(incident_id="real-flood", epoch_id=1, worlds=(), graph=graph)
    truth_residual = residual(
        frozenset({"credential_access", GROUND_TRUTH_FUTURE}), consequence=9.5
    )
    field, truth_id, refusal = spawn_world(field, truth_residual, shadow=None, epoch_id=1)
    assert refusal is None and truth_id is not None

    removed: list[str] = []
    refusals: dict[str, int] = {}
    for step, res in enumerate(_flood_residuals(400, seed=29), start=2):
        field = dataclasses.replace(field, at_sequence=step)
        controller.charge("evidence_integration", 1)
        _flood_graph_step(graph, step)
        field, _, refused = spawn_world(
            field, res, shadow=None, epoch_id=1, tombstones=ledger
        )
        if refused is not None:
            refusals[refused.value] = refusals.get(refused.value, 0) + 1
        present = {w.world_id for w in field.worlds}
        field, _ = prune_dominated_worlds(field)
        field, _ = controller.safe_prune(field)
        removed.extend(present - {w.world_id for w in field.worlds})
        assert len(field.worlds) <= budget.max_worlds
        assert len(graph) <= MAX_GRAPH_NODES and len(graph.edges()) <= MAX_GRAPH_EDGES
        assert controller.spend_report()["reasoning_units"] <= budget.max_reasoning_units
        assert field.state_bytes() <= MAX_INCIDENT_BYTES

    assert truth_id in {w.world_id for w in field.worlds}, "the real field lost the ground truth"
    world_losses = [t.identifier for t in field.truncations if t.what == "world"]
    assert sorted(removed) == sorted(world_losses)
    assert truth_id not in removed
    # Non-vacuity: with no future-cone mapping supplied, §30's default over-protects,
    # so nothing is prunable and the bound has to hold by refusing births instead.
    # If FIELD_AT_CAPACITY never fires, this test proved nothing about the bound.
    assert refusals.get(BirthRefusal.FIELD_AT_CAPACITY.value, 0) > 0
    assert len(field.worlds) == budget.max_worlds
