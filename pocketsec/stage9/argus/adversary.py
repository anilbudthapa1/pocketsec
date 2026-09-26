"""D9.14 — ARGUS, the architecture adversary (spec §4.6, architecture §50).

A genome that survives search has only been shown to fit the data it was scored on.
ARGUS exists to try to destroy it, on every surface architecture §50 names, and to
report *how often each attack actually changed something*. Two kinds of attack:

* **Scenario attacks** (``SCENARIO_ATTACKS``) are label-preserving transforms applied
  to Stage 1 scenarios *before* compilation: renamed binaries, reordered or duplicated
  events, stretched timing, dropped sensor events, a flood of fresh lineages. They are
  the fitness attack set — ``ontogenesis.fitness`` takes the worst case over them, so an
  attack here is part of what the search optimises against, not an afterthought.
* **Lifecycle attacks** (``LIFECYCLE_ATTACKS``) target the rest of the lifecycle:
  corrupted constants, a mid-session state reset, work-budget starvation, tampered
  genomes, noisy training labels, contaminated benchmarks, shuffled-label search,
  hypothesis explosion, tampered successors and a session padded past the event bound.
  Six run here; four live beside the mechanism they attack and are named by a ``"module:function"`` runner string that
  the gate resolves — this module never imports them.

Every result is an ``ArgusFinding`` with a firing count. A MEASUREMENT fires when an
outcome changed (a session score, a rank); one that changed nothing is INERT and does
not count toward lifecycle coverage — measured before this module was written, two of
the four cheap scenario attacks change no score of either reference scorer (spec M0.7),
and saying so is the point. A DEFENCE fires when a refusal was raised and must fire on
*every* trial; a tampering that was not refused is a failed defence, never a pass.

What this module refuses to do: no attack changes a label, a session name or a
technique; no attack reuses an actor identity across sessions (the corpus trap the
lineage flood could otherwise walk straight into); and no finding claims a surface is
covered when its attack changed nothing. The attacks are authored by the same wave as
the genomes and the corpus they perturb (lesson 6), so a survived attack is evidence
about *these* perturbations only.
"""

from __future__ import annotations

import hashlib
import random
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.labs.corpus import Behaviour, Scenario
from pocketsec.stage2.dataset import Stage2Dataset
from pocketsec.stage6.resources import WorkBudgetExceeded, WorkMeter
from pocketsec.stage9.argus.attrition import FittestAttrition, fittest_die_under_attack
from pocketsec.stage9.argus.findings import (
    DEFENCE,
    MEASUREMENT,
    SURFACE_TESTS,
    ArgusFinding,
    ArgusSurface,
    coverage,
)
from pocketsec.stage9.argus.tampering import tampered_genome
from pocketsec.stage9.chemistry.phenotype import Phenotype, SessionInterventions
from pocketsec.stage9.chemistry.typed_ir import (
    MAX_SESSION_EVENTS,
    IRNode,
    IRProgram,
    IRType,
    NodeKind,
)
from pocketsec.stage9.genome.computational import ComputationalGenomeV1
from pocketsec.stage9.ontogenesis.fitness import (
    EvaluationSuite,
    FitnessRecord,
    evaluate,
    score_ap,
)

if TYPE_CHECKING:  # pragma: no cover - typing only; splits imports this module lazily
    from pocketsec.stage9.labs.splits import CompiledVariant

__all__ = [
    "ARGUS_VERSION",
    "FLOOD_ACTORS",
    "LIFECYCLE_ATTACKS",
    "NOISE_RERANK_TOP",
    "SCENARIO_ATTACKS",
    "SURFACE_TESTS",
    "ArgusAttack",
    "ArgusFinding",
    "ArgusSurface",
    "FittestAttrition",
    "LifecycleAttack",
    "ScenarioAttack",
    "attack_by_id",
    "attack_findings",
    "constant_corruption",
    "coverage",
    "fittest_die_under_attack",
    "session_cap_padding",
    "state_reset_midsession",
    "tampered_genome",
    "train_label_noise",
    "work_budget_starvation",
]

ARGUS_VERSION = "stage9-argus.1.0.0"

#: Fresh actors the lineage flood inserts per session: 4x ``MAX_LINEAGES`` (16), so the
#: phenotype's lineage table must evict. Chosen, not measured.
FLOOD_ACTORS = 64
#: Genomes re-ranked by ``train_label_noise`` (spec §4.6).
NOISE_RERANK_TOP = 16
#: Two scores closer than this are "unchanged". Chosen: far below any AP-relevant gap,
#: far above float noise from a different evaluation order.
SCORE_CHANGE_TOLERANCE = 1e-12

_SECOND_NS = 1_000_000_000
_INT_MASK = (1 << 64) - 1
_MEASUREMENT = MEASUREMENT
_DEFENCE = DEFENCE


# --- scenario attacks ---------------------------------------------------------------------

Transform = Callable[[Scenario, random.Random], tuple[Behaviour, ...]]


@dataclass(frozen=True, slots=True)
class ScenarioAttack:
    """A label-preserving transform applied to scenarios BEFORE Stage 1 compiles them."""

    attack_id: str
    surface: ArgusSurface
    description: str
    salt: int
    transform: Transform = field(compare=False, repr=False)

    def apply(self, scenarios: Sequence[Scenario], *, seed: int) -> tuple[Scenario, ...]:
        """Transform every scenario; name, label, technique and novelty flag preserved."""
        rng = random.Random(seed * 1_000_003 + self.salt)
        return tuple(
            Scenario(
                name=scenario.name,
                behaviours=self.transform(scenario, rng),
                label=scenario.label,
                technique=scenario.technique,
                unseen_technique=scenario.unseen_technique,
            )
            for scenario in scenarios
        )


def _renamed_path(path: str) -> str:
    # A digest of the path, not an rng draw: the same binary gets the same new name in
    # every session, so the rename is consistent, as a real renamed binary would be.
    return "/opt/x/" + hashlib.sha256(f"s9-rename:{path}".encode()).hexdigest()[:8]


def rename_binaries(scenario: Scenario, rng: random.Random) -> tuple[Behaviour, ...]:
    """Every execve ``path`` becomes ``/opt/x/<8 hex>``, consistently per original path."""
    del rng  # deterministic by construction
    return tuple(
        b.with_fields(path=_renamed_path(b.fields["path"]))
        if b.operation == "execve" and "path" in b.fields
        else b
        for b in scenario.behaviours
    )


def reorder_across_actors(scenario: Scenario, rng: random.Random) -> tuple[Behaviour, ...]:
    """Swap adjacent behaviours of different pids with p=0.3 (a swapped pair is not reused)."""
    stream = list(scenario.behaviours)
    index = 0
    while index < len(stream) - 1:
        first, second = stream[index], stream[index + 1]
        if first.fields.get("pid") != second.fields.get("pid") and rng.random() < 0.3:
            stream[index], stream[index + 1] = second, first
            index += 2
        else:
            index += 1
    return tuple(stream)


def benign_duplicate_flood(scenario: Scenario, rng: random.Random) -> tuple[Behaviour, ...]:
    """Duplicate each behaviour in place with p=0.1 (same actor, same object)."""
    stream: list[Behaviour] = []
    for behaviour in scenario.behaviours:
        stream.append(behaviour)
        if rng.random() < 0.1:
            stream.append(behaviour.with_fields())
    return tuple(stream)


def timing_stretch(scenario: Scenario, rng: random.Random) -> tuple[Behaviour, ...]:
    """Multiply each ``_gap_ns`` by U(0.2, 5.0), floored at 1 ns."""
    stream: list[Behaviour] = []
    for behaviour in scenario.behaviours:
        gap = behaviour.fields.get("_gap_ns")
        if gap is None:
            stream.append(behaviour)
            continue
        stretched = max(1, int(int(gap) * rng.uniform(0.2, 5.0)))
        stream.append(behaviour.with_fields(_gap_ns=str(stretched)))
    return tuple(stream)


def sensor_drop_10(scenario: Scenario, rng: random.Random) -> tuple[Behaviour, ...]:
    """Drop each behaviour with p=0.1: partial sensor loss."""
    return tuple(b for b in scenario.behaviours if rng.random() >= 0.1)


def _flood_actor(scenario_name: str, k: int) -> tuple[str, str]:
    # pid AND start_time come from a digest of (session name, k), so a flood actor is
    # unique to its session: identities_reused_across_sessions stays 0 (corpus trap).
    digest = hashlib.sha256(f"{scenario_name}\x00{k}".encode()).hexdigest()
    return str(2_000_000 + int(digest[:8], 16)), str(10_000 + int(digest[8:16], 16))


def lineage_table_flood(scenario: Scenario, rng: random.Random) -> tuple[Behaviour, ...]:
    """Insert 64 single-read behaviours from 64 fresh actors at random positions."""
    stream = list(scenario.behaviours)
    for k in range(FLOOD_ACTORS):
        pid, start_time = _flood_actor(scenario.name, k)
        flood = Behaviour(
            "read",
            {
                "path": "/tmp/s9-flood",
                "pid": pid,
                "start_time": start_time,
                "_gap_ns": str(rng.randrange(2, 90) * _SECOND_NS),
            },
        )
        stream.insert(rng.randrange(0, len(stream) + 1), flood)
    return tuple(stream)


#: The fitness attack set, in spec order. Transforms are module-level functions so an
#: attack can be named across a process boundary.
# fmt: off
SCENARIO_ATTACKS: tuple[ScenarioAttack, ...] = (
    ScenarioAttack("rename_binaries", ArgusSurface.INPUT,
                   "execve path -> /opt/x/<8 hex>, consistent per original path",
                   1, rename_binaries),
    ScenarioAttack("reorder_across_actors", ArgusSurface.INPUT,
                   "swap adjacent behaviours of different pids, p=0.3", 2, reorder_across_actors),
    ScenarioAttack("benign_duplicate_flood", ArgusSurface.INPUT,
                   "duplicate a behaviour in place, p=0.1", 3, benign_duplicate_flood),
    ScenarioAttack("timing_stretch", ArgusSurface.SENSORS,
                   "_gap_ns * U(0.2, 5.0), floored at 1", 4, timing_stretch),
    ScenarioAttack("sensor_drop_10", ArgusSurface.SENSORS,
                   "drop each behaviour with p=0.1", 5, sensor_drop_10),
    ScenarioAttack("lineage_table_flood", ArgusSurface.STATE,
                   "insert 64 single reads of /tmp/s9-flood from 64 session-unique actors",
                   6, lineage_table_flood),
)
# fmt: on


def attack_by_id(attack_id: str) -> ScenarioAttack:
    """The scenario attack named ``attack_id``; an unknown id is refused."""
    for attack in SCENARIO_ATTACKS:
        if attack.attack_id == attack_id:
            return attack
    known = [attack.attack_id for attack in SCENARIO_ATTACKS]
    raise ContractError(f"unknown ARGUS scenario attack {attack_id!r}; known: {known}")


# --- lifecycle attacks --------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LifecycleAttack:
    """An attack on the lifecycle, run by ``runner`` (relative to ``pocketsec.stage9``)."""

    attack_id: str
    surface: ArgusSurface
    description: str
    runner: str  # "module:function", resolved by the gate, never imported here


# fmt: off
LIFECYCLE_ATTACKS: tuple[LifecycleAttack, ...] = (
    LifecycleAttack("constant_corruption", ArgusSurface.MODEL,
                    "+/-10% on every CONST and lookup entry",
                    "argus.adversary:constant_corruption"),
    LifecycleAttack("state_reset_midsession", ArgusSurface.STATE,
                    "clear all lineage state at events // 2",
                    "argus.adversary:state_reset_midsession"),
    LifecycleAttack("work_budget_starvation", ArgusSurface.RESOURCE,
                    "half the WU a session needs; must raise, never a partial score",
                    "argus.adversary:work_budget_starvation"),
    LifecycleAttack("session_cap_padding", ArgusSurface.INPUT,
                    "prepend MAX_SESSION_EVENTS copies of each session's first event; the "
                    "session must abstain, never score the padded prefix (S9-FC-02)",
                    "argus.adversary:session_cap_padding"),
    LifecycleAttack("tampered_genome", ArgusSurface.SUPPLY_CHAIN,
                    "3 tamperings of a genome artefact; each must be refused",
                    "argus.adversary:tampered_genome"),
    LifecycleAttack("benchmark_contamination", ArgusSurface.SEARCH,
                    "copy 20 held-out sessions into train; the check must refuse",
                    "ontogenesis.fitness:contamination_attack"),
    LifecycleAttack("train_label_noise", ArgusSurface.DATA,
                    "re-rank the top 16 under 5% flipped train labels",
                    "argus.adversary:train_label_noise"),
    LifecycleAttack("shuffled_label_search", ArgusSurface.SEARCH,
                    "search on shuffled labels must find nothing above chance",
                    "ontogenesis.search:run_shuffled_label_control"),
    LifecycleAttack("hypothesis_explosion", ArgusSurface.SEARCH,
                    "flood the QD archive with candidates; bounds must hold",
                    "gaia.qd_ecology:hypothesis_explosion"),
    LifecycleAttack("tampered_successor", ArgusSurface.SUPPLY_CHAIN,
                    "tampered successor packages must be refused",
                    "successor.proof_carrying:tampered_successor"),
)
# fmt: on

ArgusAttack = ScenarioAttack | LifecycleAttack


def _changed(before: float | None, after: float | None) -> bool:
    if before is None or after is None:
        return (before is None) != (after is None)
    return abs(before - after) > SCORE_CHANGE_TOLERANCE


def _score_map(
    phenotype: Phenotype, dataset: Stage2Dataset, *, reset_half: bool = False
) -> dict[str, float | None]:
    scores: dict[str, float | None] = {}
    for sample in dataset.samples:
        interventions = (
            SessionInterventions(reset_at=len(sample.steps) // 2)
            if reset_half
            else SessionInterventions()
        )
        scores[sample.sample_id] = phenotype.run_session(
            sample.steps, interventions=interventions
        ).score
    return scores


def _ap(dataset: Stage2Dataset, scores: Mapping[str, float | None]) -> float | None:
    return score_ap(dataset.labels, [scores[s.sample_id] for s in dataset.samples])[0]


def _fired(before: Mapping[str, float | None], after: Mapping[str, float | None]) -> int:
    """Sessions whose score changed; a session missing from ``after`` counts as changed."""
    return sum(
        1
        for sample_id, score in before.items()
        if sample_id not in after or _changed(score, after[sample_id])
    )


def attack_findings(
    genome: ComputationalGenomeV1, clean: CompiledVariant, variants: Sequence[CompiledVariant]
) -> tuple[ArgusFinding, ...]:
    """One MEASUREMENT per attacked variant: how many session scores the attack moved."""
    phenotype = genome.phenotype()
    before = _score_map(phenotype, clean.dataset)
    ap_before = _ap(clean.dataset, before)
    findings = []
    for variant in variants:
        attack = attack_by_id(variant.key.attack_id)
        after = _score_map(phenotype, variant.dataset)
        fired = _fired(before, after)
        missing = sum(1 for sample_id in before if sample_id not in after)
        findings.append(
            ArgusFinding(
                attack_id=attack.attack_id,
                surface=attack.surface,
                kind=_MEASUREMENT,
                fired=fired,
                total=len(before),
                inert=fired == 0,
                metric_before=ap_before,
                metric_after=_ap(variant.dataset, after),
                detail=(
                    f"{fired}/{len(before)} session scores changed ({missing} sessions "
                    f"missing from the variant); genome {genome.digest}"
                ),
                measured_by="argus.adversary:attack_findings",
            )
        )
    return tuple(findings)


def _corrupt_value(node: IRNode, factor: float) -> IRNode | None:
    """``node`` with its constant scaled by ``factor``, or ``None`` if it cannot scale."""
    if node.kind is not NodeKind.CONST or isinstance(node.value, bool) or node.value is None:
        return None
    if node.type is IRType.INT:
        scaled_int = round(int(node.value) * factor) & _INT_MASK
        return replace(node, value=scaled_int) if scaled_int != node.value else None
    return replace(node, value=float(node.value) * factor)


def _corrupt_program(program: IRProgram, rng: random.Random) -> tuple[IRProgram, int]:
    nodes: list[IRNode] = []
    corrupted = 0
    for node in program.nodes:
        scaled = _corrupt_value(node, 1.0 + rng.choice((-0.1, 0.1)))
        nodes.append(node if scaled is None else scaled)
        corrupted += scaled is not None
    return replace(program, nodes=tuple(nodes)), corrupted


def constant_corruption(
    genome: ComputationalGenomeV1, dataset: Stage2Dataset, *, seed: int
) -> ArgusFinding:
    """[MODEL] Scale every CONST and lookup entry by 1 +/- 10%; count moved scores.

    A BOOL constant cannot be scaled and is left alone; an INT constant is scaled and
    re-masked. A genome with no constant is INERT here by construction, and says so.
    """
    rng = random.Random(seed)
    update, in_update = _corrupt_program(genome.update, rng)
    readout, in_readout = _corrupt_program(genome.readout, rng)
    table = tuple(v * (1.0 + rng.choice((-0.1, 0.1))) for v in genome.lookup_table)
    corrupted = in_update + in_readout + len(table)
    before = _score_map(genome.phenotype(), dataset)
    after = before
    if corrupted:
        mutant = replace(genome, update=update, readout=readout, lookup_table=table)
        after = _score_map(mutant.phenotype(), dataset)
    fired = _fired(before, after)
    return ArgusFinding(
        attack_id="constant_corruption",
        surface=ArgusSurface.MODEL,
        kind=_MEASUREMENT,
        fired=fired,
        total=len(before),
        inert=fired == 0,
        metric_before=_ap(dataset, before),
        metric_after=_ap(dataset, after),
        detail=(
            f"{corrupted} constants scaled by 1 +/- 10% (seed {seed}); {fired}/{len(before)} "
            "session scores changed" + ("" if corrupted else "; no constant: INERT")
        ),
        measured_by="argus.adversary:constant_corruption",
    )


def state_reset_midsession(genome: ComputationalGenomeV1, dataset: Stage2Dataset) -> ArgusFinding:
    """[STATE] Clear all lineage state at ``events // 2``; count moved scores."""
    phenotype = genome.phenotype()
    before = _score_map(phenotype, dataset)
    after = _score_map(phenotype, dataset, reset_half=True)
    fired = _fired(before, after)
    return ArgusFinding(
        attack_id="state_reset_midsession",
        surface=ArgusSurface.STATE,
        kind=_MEASUREMENT,
        fired=fired,
        total=len(before),
        inert=fired == 0,
        metric_before=_ap(dataset, before),
        metric_after=_ap(dataset, after),
        detail=f"reset at events // 2: {fired}/{len(before)} session scores changed",
        measured_by="argus.adversary:state_reset_midsession",
    )


def work_budget_starvation(genome: ComputationalGenomeV1, dataset: Stage2Dataset) -> ArgusFinding:
    """[RESOURCE] Give each session half the WU it needs. A DEFENCE.

    It must raise ``WorkBudgetExceeded`` every time; a returned ``SessionRun`` under half
    the budget would be a partial score, which is the failure this attack exists to catch.
    """
    phenotype = genome.phenotype()
    raised = partial = overspent = 0
    for sample in dataset.samples:
        probe = WorkMeter()
        phenotype.run_session(sample.steps, meter=probe)
        starved = WorkMeter(budget=probe.spent // 2)
        try:
            phenotype.run_session(sample.steps, meter=starved)
        except WorkBudgetExceeded:
            raised += 1
        else:
            partial += 1
        overspent += starved.spent > (starved.budget or 0)
    return ArgusFinding(
        attack_id="work_budget_starvation",
        surface=ArgusSurface.RESOURCE,
        kind=_DEFENCE,
        fired=raised,
        total=len(dataset.samples),
        inert=raised == 0,
        metric_before=None,
        metric_after=float(partial),
        detail=(
            f"{raised} WorkBudgetExceeded raised, {partial} partial scores produced, "
            f"{overspent} meters past budget, over {len(dataset.samples)} sessions"
        ),
        measured_by="argus.adversary:work_budget_starvation",
    )


def session_cap_padding(genome: ComputationalGenomeV1, dataset: Stage2Dataset) -> ArgusFinding:
    """[INPUT] Prepend ``MAX_SESSION_EVENTS`` copies of each session's first event. A DEFENCE.

    This is the evasion S9-FC-02 measured: a phenotype that scores only the first
    ``MAX_SESSION_EVENTS`` events sees nothing but the padding and returns an ordinary,
    confident score. The defence holds on a session iff the padded run ABSTAINS with its
    overflow counted. Holding it does not restore detection: every padded session ranks as
    0.0, so ``metric_after`` is the AP an attacker who can emit 4096 events forces. What the
    defence buys is UNKNOWN instead of a benign-looking number. Head padding is not a
    fitness attack: it would pin every genome's worst case at the same chance level, one
    attack silently deciding every outcome (lesson 5).
    """
    phenotype = genome.phenotype()
    clean = _score_map(phenotype, dataset)
    padded: dict[str, float | None] = {}
    abstained = 0
    for sample in dataset.samples:
        steps = tuple(sample.steps)
        pad = (steps[0],) * MAX_SESSION_EVENTS if steps else ()
        run = phenotype.run_session(pad + steps)
        padded[sample.sample_id] = run.score
        abstained += run.score is None and run.truncated_events > 0
    return ArgusFinding(
        attack_id="session_cap_padding",
        surface=ArgusSurface.INPUT,
        kind=_DEFENCE,
        fired=abstained,
        total=len(dataset.samples),
        inert=abstained == 0,
        metric_before=_ap(dataset, clean),
        metric_after=_ap(dataset, padded),
        detail=(
            f"{abstained}/{len(dataset.samples)} sessions padded with {MAX_SESSION_EVENTS} "
            "copies of their first event abstained (overflow counted); any other outcome is a "
            "confident score from a prefix the attacker chose. Abstention is UNKNOWN, not "
            "detection: AP with padded sessions ranked 0.0 is metric_after"
        ),
        measured_by="argus.adversary:session_cap_padding",
    )


# --- label noise and attrition ------------------------------------------------------------


def _rank_key(pair: tuple[str, float | None]) -> tuple[float, str]:
    digest, worst = pair
    return (-(worst if worst is not None else float("-inf")), digest)


def train_label_noise(
    records_top: Sequence[tuple[ComputationalGenomeV1, FitnessRecord]],
    train: EvaluationSuite,
    *,
    rate: float = 0.05,
    seed: int,
) -> ArgusFinding:
    """[DATA] Re-rank the top 16 under ``rate`` flipped train labels; count rank moves.

    The records must have been measured on ``train`` itself; re-ranking genomes scored
    on another suite would compare two different questions.
    """
    for genome, record in records_top:
        if record.genome_digest != genome.digest or record.suite != train.name:
            raise ContractError(
                f"record {record.genome_digest} on {record.suite!r} does not belong to "
                f"genome {genome.digest} on {train.name!r}"
            )
    ranked = sorted(
        ((g.digest, r.worst_case_ap, g) for g, r in records_top),
        key=lambda item: _rank_key((item[0], item[1])),
    )[:NOISE_RERANK_TOP]
    noisy = train.with_label_noise(rate, seed)
    meter = WorkMeter()
    noisy_worst = {digest: evaluate(g, noisy, meter=meter).worst_case_ap for digest, _, g in ranked}
    before_order = [digest for digest, _, _ in ranked]
    after_order = sorted(before_order, key=lambda d: _rank_key((d, noisy_worst[d])))
    moved = sum(1 for a, b in zip(before_order, after_order, strict=True) if a != b)
    winner_changed = bool(before_order) and before_order[0] != after_order[0]
    return ArgusFinding(
        attack_id="train_label_noise",
        surface=ArgusSurface.DATA,
        kind=_MEASUREMENT,
        fired=moved,
        total=len(before_order),
        inert=moved == 0,
        metric_before=ranked[0][1] if ranked else None,
        metric_after=noisy_worst[after_order[0]] if after_order else None,
        detail=(
            f"{moved}/{len(before_order)} genomes changed rank under {rate:.0%} flipped "
            f"train labels (seed {seed}); winner changed: {winner_changed}; "
            f"{meter.spent} WU spent"
        ),
        measured_by="argus.adversary:train_label_noise",
    )
